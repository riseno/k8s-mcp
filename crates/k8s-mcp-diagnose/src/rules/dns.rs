//! DNS (PROPOSAL §9.2). Two entry points:
//! - [`check`] (`diagnose_pod`, v0.1): resolution errors in the pod's own logs;
//! - [`check_cluster`] (`diagnose_dns`, v0.2): the whole path, in the order a lookup takes it:
//!   the pod's NetworkPolicies, CoreDNS, the kube-dns Service, then the app's logs and ndots.
//!
//! Log patterns are only medium-confidence evidence, so the log finding is `high`/`medium`: it
//! never outranks a definitive root cause (always `critical`), such as the crash loop whose
//! logs show the same lines. A NetworkPolicy is judged conservatively: any egress rule that
//! could reach port 53 counts as allowing DNS, so the rule never claims a block it cannot prove.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use k8s_mcp_core::finding::{Confidence, Finding, RuleMeta, Severity, Source};
use k8s_mcp_core::text::truncate;
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::api::networking::v1::{NetworkPolicy, NetworkPolicyPeer, NetworkPolicyPort};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use regex::Regex;
use serde_json::json;

use super::{
    dns_name, docs, logs_args, phase, pod_condition, pod_ready, pod_ref, re, resource_args,
    selector_matches,
};
use crate::evidence::{ContainerLog, DnsEvidence, PodEvidence};

/// Rules emitted by this module.
pub const RULES: &[RuleMeta] = &[
    RuleMeta {
        id: "dns.app_resolution_errors",
        title: "The application logs DNS resolution failures",
        docs: docs::DNS,
    },
    RuleMeta {
        id: "dns.netpol_blocks_egress",
        title: "A NetworkPolicy blocks DNS (port 53) egress",
        docs: docs::NETWORK_POLICY,
    },
    RuleMeta {
        id: "dns.coredns_unhealthy",
        title: "The cluster DNS pods (CoreDNS) are not healthy",
        docs: docs::DNS,
    },
    RuleMeta {
        id: "dns.no_endpoints",
        title: "The kube-dns Service has no ready endpoints",
        docs: docs::DNS,
    },
    RuleMeta {
        id: "dns.ndots_hint",
        title: "External names go through the cluster search domains first (ndots)",
        docs: docs::POD_DNS,
    },
];

static DNS_ERROR: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)no such host|temporary failure in name resolution|name or service not known|server misbehaving|servfail|getaddrinfo (enotfound|eai_again)|unknownhostexception|could not resolve host|:53\b.*i/o timeout",
    )
});
/// CoreDNS's loop plugin: `[FATAL] plugin/loop: Loop (127.0.0.1:55953 -> :53) detected for zone "."`.
static LOOP: LazyLock<Regex> = LazyLock::new(|| re(r"plugin/loop: Loop .* detected"));
/// CoreDNS failing to reach its upstreams: `[ERROR] plugin/errors: 2 example.com. A: read udp ...: i/o timeout`.
static UPSTREAM: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"\[ERROR\] plugin/errors: .*(i/o timeout|connection refused|no route to host|network is unreachable)",
    )
});
/// Hostnames in log lines (lower-cased before matching).
static HOST: LazyLock<Regex> =
    LazyLock::new(|| re(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62})\b"));

/// Default `ndots` for ClusterFirst pods.
const DEFAULT_NDOTS: usize = 5;
const SHOWN: usize = 3;

/// `diagnose_pod`: resolution errors in the pod's logs.
pub fn check(ev: &PodEvidence, out: &mut Vec<Finding>) {
    resolution_errors(&ev.pod, &ev.logs, out);
}

/// `diagnose_dns`: every layer of the pod's (or the namespace's) DNS path.
pub fn check_cluster(ev: &DnsEvidence, out: &mut Vec<Finding>) {
    network_policies(ev, out);
    let dns_ready = coredns(ev, out);
    endpoints(ev, dns_ready, out);
    if let Some(pod) = &ev.pod {
        resolution_errors(pod, &ev.pod_logs, out);
        ndots(pod, &ev.pod_logs, out);
    }
}

fn resolution_errors(pod: &Pod, logs: &[ContainerLog], out: &mut Vec<Finding>) {
    for log in logs {
        let hits: Vec<&String> = log.lines.iter().filter(|l| DNS_ERROR.is_match(l)).collect();
        let Some(last) = hits.len().checked_sub(1) else {
            continue;
        };
        let name = &log.container;
        let (pod_name, ns) = pod_ref(pod);
        let mut f = Finding::new("dns.app_resolution_errors", Severity::High, Confidence::Medium, format!("container {name:?} logs DNS resolution failures"))
            .explain(format!("{} of the last {} log lines report that a hostname could not be resolved. The application cannot reach the services it depends on by name.", hits.len(), log.lines.len()))
            .fix("Find the layer that fails: the hostname itself (typo, missing Service, wrong namespace: use `<service>.<namespace>.svc.cluster.local`), the pod's dnsPolicy/dnsConfig, a NetworkPolicy blocking egress to port 53, then CoreDNS health. diagnose_dns checks all of them.")
            .docs(docs::DNS)
            .next("get_logs", logs_args(pod, name, log.previous), "read the failing lookups in context")
            .next("diagnose_dns", json!({"pod": pod_name, "namespace": ns}), "check every layer of the pod's DNS path");
        for line in &hits[last.saturating_sub(2)..] {
            f = f.evidence(Source::Log, truncate(line, 300));
        }
        out.push(f);
    }
}

/// Policies of type Egress (explicit, or implied by an `egress` section).
fn restricts_egress(np: &NetworkPolicy) -> bool {
    np.spec.as_ref().is_some_and(|s| match &s.policy_types {
        Some(types) => types.iter().any(|t| t == "Egress"),
        None => s.egress.is_some(),
    })
}

/// Port 53 is allowed when the rule lists no ports, or a port range or `dns*` name covering it.
fn ports_allow_53(ports: Option<&Vec<NetworkPolicyPort>>) -> bool {
    ports.is_none_or(|ports| {
        ports.is_empty()
            || ports.iter().any(|p| match &p.port {
                None => true,
                Some(IntOrString::Int(n)) => {
                    *n == 53 || p.end_port.is_some_and(|end| *n <= 53 && 53 <= end)
                }
                Some(IntOrString::String(name)) => name.starts_with("dns"),
            })
    })
}

/// Whether a rule's peers could include the DNS pods: any destination, any namespace selector
/// or IP block (node-local DNS, upstream servers), or pods in kube-system itself.
fn peers_may_reach_dns(to: Option<&Vec<NetworkPolicyPeer>>, ns: &str) -> bool {
    to.is_none_or(|peers| {
        peers.is_empty()
            || peers.iter().any(|p| {
                p.ip_block.is_some() || p.namespace_selector.is_some() || ns == "kube-system"
            })
    })
}

fn network_policies(ev: &DnsEvidence, out: &mut Vec<Finding>) {
    let Some(policies) = &ev.network_policies else {
        return;
    };
    let no_labels = BTreeMap::new();
    let labels = ev
        .pod
        .as_ref()
        .and_then(|p| p.metadata.labels.as_ref())
        .unwrap_or(&no_labels);
    let selecting: Vec<&NetworkPolicy> = policies
        .iter()
        .filter(|np| restricts_egress(np))
        .filter(|np| {
            np.spec.as_ref().is_some_and(|s| {
                // An absent podSelector selects every pod, like an empty one.
                s.pod_selector
                    .as_ref()
                    .is_none_or(|sel| selector_matches(sel, Some(labels)))
            })
        })
        .collect();
    let allows = |np: &&NetworkPolicy| {
        np.spec
            .iter()
            .flat_map(|s| s.egress.iter().flatten())
            .any(|rule| {
                ports_allow_53(rule.ports.as_ref())
                    && peers_may_reach_dns(rule.to.as_ref(), &ev.namespace)
            })
    };
    if selecting.is_empty() || selecting.iter().any(allows) {
        return;
    }
    let names: Vec<&str> = selecting
        .iter()
        .filter_map(|np| np.metadata.name.as_deref())
        .collect();
    let subject = ev.pod.as_ref().map_or_else(
        || format!("every pod in {}", ev.namespace),
        |p| format!("pod {}", pod_ref(p).0),
    );
    let mut f = Finding::new(
        "dns.netpol_blocks_egress",
        Severity::Critical,
        Confidence::High,
        format!("NetworkPolicy {} blocks DNS for {subject}", names.join(", ")),
    )
    .explain(format!("The policies select {subject} and restrict its egress, and none of their egress rules allows UDP or TCP port 53 towards the cluster DNS, so every name lookup times out."))
    .docs(docs::NETWORK_POLICY)
    .fix("Add an egress rule allowing DNS to one of these policies: `to: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: kube-system}}, podSelector: {matchLabels: {k8s-app: kube-dns}}}]` with `ports: [{protocol: UDP, port: 53}, {protocol: TCP, port: 53}]`.");
    for np in &selecting {
        let rules = np
            .spec
            .iter()
            .flat_map(|s| s.egress.iter().flatten())
            .count();
        f = f.evidence(
            Source::Spec,
            format!(
                "NetworkPolicy {} restricts egress with {rules} rule(s), none reaching port 53",
                np.metadata.name.as_deref().unwrap_or("")
            ),
        );
    }
    if let Some(first) = names.first() {
        f = f.next(
            "get_resource",
            resource_args("NetworkPolicy", first, &ev.namespace),
            "see the policy's egress rules",
        );
    }
    out.push(f);
}

/// Report unhealthy CoreDNS; returns how many DNS pods are Ready (`None` if unknown).
fn coredns(ev: &DnsEvidence, out: &mut Vec<Finding>) -> Option<usize> {
    let pods = ev.dns_pods.as_ref()?;
    let ready = pods.iter().filter(|p| pod_ready(p)).count();
    let lines = || ev.dns_logs.iter().flat_map(|l| &l.lines);
    let loops: Vec<&String> = lines().filter(|l| LOOP.is_match(l)).collect();
    if pods.is_empty() {
        out.push(
            Finding::new(
                "dns.coredns_unhealthy",
                Severity::Critical,
                Confidence::High,
                "No cluster DNS pods (k8s-app=kube-dns) run in kube-system",
            )
            .explain("Pods resolve names through the kube-dns Service, and nothing serves it, so every lookup fails.")
            .docs(docs::DNS)
            .fix("Restore the cluster DNS add-on (CoreDNS): check its Deployment in kube-system, or re-enable the managed add-on for this cluster."),
        );
        return Some(0);
    }
    if ready < pods.len() || !loops.is_empty() {
        let title = if loops.is_empty() {
            format!("{ready} of {} CoreDNS pods are Ready", pods.len())
        } else {
            "CoreDNS detected a forwarding loop".to_owned()
        };
        let mut f = Finding::new(
            "dns.coredns_unhealthy",
            if ready == 0 { Severity::Critical } else { Severity::High },
            Confidence::High,
            title,
        )
        .explain("The CoreDNS pods answer every cluster lookup; the ones that are not Ready get no traffic, and with none Ready all lookups fail.")
        .docs(docs::DNS);
        f = if loops.is_empty() {
            f.fix("Find out why the CoreDNS pods are not Ready (diagnose_pod on one): crash loops, OOM kills, or a broken Corefile in the coredns ConfigMap.")
        } else {
            f.fix("CoreDNS forwards to itself: the node's /etc/resolv.conf points at a local stub (often 127.0.0.53 from systemd-resolved). Point the kubelet's resolvConf at the real upstream file (/run/systemd/resolve/resolv.conf), or forward CoreDNS to explicit upstream servers in its Corefile.")
        };
        for p in pods.iter().filter(|p| !pod_ready(p)).take(SHOWN) {
            let ready = pod_condition(p, "Ready")
                .and_then(|c| c.reason.as_deref())
                .unwrap_or("not Ready");
            f = f.evidence(
                Source::Status,
                format!("pod {}: {}, {ready}", pod_ref(p).0, phase(p)),
            );
        }
        for line in loops.iter().take(1) {
            f = f.evidence(Source::Log, truncate(line, 300));
        }
        if let Some(p) = pods.iter().find(|p| !pod_ready(p)) {
            f = f.next(
                "diagnose_pod",
                json!({"name": pod_ref(p).0, "namespace": "kube-system"}),
                "root-cause the CoreDNS pod",
            );
        }
        out.push(f);
        return Some(ready);
    }
    let upstream: Vec<&String> = lines().filter(|l| UPSTREAM.is_match(l)).collect();
    if !upstream.is_empty() {
        let mut f = Finding::new(
            "dns.coredns_unhealthy",
            Severity::High,
            Confidence::Medium,
            "CoreDNS cannot reach its upstream resolvers",
        )
        .explain("CoreDNS answers cluster names itself but forwards everything else upstream; those forwards time out or are refused, so external names fail to resolve.")
        .docs(docs::DNS)
        .fix("Check the upstream servers CoreDNS forwards to (the forward plugin in the coredns ConfigMap, or the nodes' /etc/resolv.conf), and that egress to them on port 53 is allowed (cloud firewall rules, NetworkPolicies in kube-system).");
        for line in upstream.iter().rev().take(2) {
            f = f.evidence(Source::Log, truncate(line, 300));
        }
        out.push(f);
    }
    Some(ready)
}

fn endpoints(ev: &DnsEvidence, dns_ready: Option<usize>, out: &mut Vec<Finding>) {
    let f = match &ev.dns_service {
        Some(None) => Finding::new(
            "dns.no_endpoints",
            Severity::Critical,
            Confidence::High,
            "The kube-dns Service does not exist in kube-system",
        )
        .explain("Pods' /etc/resolv.conf points at the kube-dns Service's ClusterIP; without the Service nothing answers there."),
        // Unready CoreDNS pods already explain the missing endpoints.
        Some(Some(_)) if ev.dns_ready_endpoints == Some(0) && dns_ready != Some(0) => Finding::new(
            "dns.no_endpoints",
            Severity::Critical,
            Confidence::High,
            "The kube-dns Service has no ready endpoints",
        )
        .explain("The Service exists but routes to no DNS pod, so lookups to its ClusterIP time out. When CoreDNS pods are Ready, the Service selector no longer matches their labels.")
        .evidence(Source::Related, "EndpointSlices of kube-dns: 0 ready endpoints")
        .next("diagnose_service", json!({"name": "kube-dns", "namespace": "kube-system"}), "compare the Service selector with the CoreDNS pod labels"),
        _ => return,
    };
    out.push(f.docs(docs::DNS).fix("Restore the kube-dns Service so it selects the CoreDNS pods (k8s-app=kube-dns) on UDP and TCP port 53; managed clusters recreate it when the DNS add-on is repaired."));
}

/// External names (with a dot, fewer dots than ndots, not cluster names) in DNS-error lines.
fn ndots(pod: &Pod, logs: &[ContainerLog], out: &mut Vec<Finding>) {
    let Some(spec) = &pod.spec else {
        return;
    };
    if !matches!(
        spec.dns_policy.as_deref().unwrap_or("ClusterFirst"),
        "ClusterFirst" | "ClusterFirstWithHostNet"
    ) {
        return;
    }
    let ndots = spec
        .dns_config
        .iter()
        .flat_map(|c| c.options.iter().flatten())
        .find(|o| o.name.as_deref() == Some("ndots"))
        .and_then(|o| o.value.as_deref()?.parse().ok())
        .unwrap_or(DEFAULT_NDOTS);
    let cluster = |h: &str| {
        [".local", ".svc", ".cluster.local", ".internal"]
            .iter()
            .any(|s| h.ends_with(s))
    };
    let mut hosts: Vec<String> = logs
        .iter()
        .flat_map(|l| &l.lines)
        .filter(|l| DNS_ERROR.is_match(l))
        .flat_map(|l| {
            HOST.find_iter(&l.to_ascii_lowercase())
                .map(|m| m.as_str().to_owned())
                .collect::<Vec<_>>()
        })
        .filter(|h| dns_name(h) && !cluster(h) && h.matches('.').count() < ndots)
        .filter(|h| {
            !h.split('.')
                .all(|part| part.bytes().all(|b| b.is_ascii_digit()))
        })
        .collect();
    hosts.sort();
    hosts.dedup();
    let Some(example) = hosts.first() else {
        return;
    };
    let (name, _) = pod_ref(pod);
    out.push(
        Finding::new(
            "dns.ndots_hint",
            Severity::Low,
            Confidence::Medium,
            format!("pod {name} looks up external names such as {example} through the cluster search domains (ndots {ndots})"),
        )
        .explain(format!("A name with fewer than {ndots} dots is first tried with every search domain (<namespace>.svc.cluster.local, svc.cluster.local, ...), which multiplies lookups; under load the extra lookups add latency and timeouts."))
        .docs(docs::POD_DNS)
        .evidence(Source::Spec, format!("dnsPolicy {}, ndots {ndots}", spec.dns_policy.as_deref().unwrap_or("ClusterFirst")))
        .fix("Use fully qualified names with a trailing dot (api.example.com.), or set `dnsConfig: {options: [{name: ndots, value: \"2\"}]}` on the pod."),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{dns_fixture, pod_fixture};

    fn cluster(fixture: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        check_cluster(&dns_fixture(fixture), &mut out);
        out
    }

    fn cluster_ids(fixture: &str) -> Vec<String> {
        cluster(fixture).into_iter().map(|f| f.id).collect()
    }

    #[test]
    fn egress_policy_without_dns_blocks_lookups() {
        let out = cluster("dns/netpol-blocks.yaml");
        let f = &out[0];
        assert_eq!(
            (f.id.as_str(), f.severity),
            ("dns.netpol_blocks_egress", Severity::Critical)
        );
        assert_eq!(
            f.title,
            "NetworkPolicy api-egress blocks DNS for pod api-6d5f4-xk2p9"
        );
        assert_eq!(
            f.evidence[0].text,
            "NetworkPolicy api-egress restricts egress with 1 rule(s), none reaching port 53"
        );
        assert!(out.iter().any(|f| f.id == "dns.app_resolution_errors"));
        assert!(
            !out.iter().any(|f| f.id == "dns.ndots_hint"),
            "cluster names are not hinted"
        );
    }

    #[test]
    fn a_policy_allowing_dns_is_enough() {
        assert!(cluster_ids("dns/netpol-allows-dns.yaml").is_empty());
        // Without a pod, only policies selecting every pod count; api-egress selects app=api.
        let mut ev = dns_fixture("dns/netpol-blocks.yaml");
        ev.pod = None;
        ev.pod_logs.clear();
        let mut out = Vec::new();
        check_cluster(&ev, &mut out);
        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn coredns_loop_is_critical_and_explains_the_missing_endpoints() {
        let out = cluster("dns/coredns-loop.yaml");
        assert_eq!(out.len(), 1, "{out:?}");
        let f = &out[0];
        assert_eq!(
            (f.id.as_str(), f.severity),
            ("dns.coredns_unhealthy", Severity::Critical)
        );
        assert_eq!(f.title, "CoreDNS detected a forwarding loop");
        assert!(
            f.evidence
                .iter()
                .any(|e| e.source == Source::Log && e.text.contains("plugin/loop"))
        );
        assert_eq!(f.next[0].tool, "diagnose_pod");
    }

    #[test]
    fn ready_coredns_without_endpoints_points_at_the_service() {
        assert_eq!(cluster_ids("dns/no-endpoints.yaml"), ["dns.no_endpoints"]);
        let mut ev = dns_fixture("dns/no-endpoints.yaml");
        ev.dns_service = Some(None);
        let mut out = Vec::new();
        check_cluster(&ev, &mut out);
        assert_eq!(
            out[0].title,
            "The kube-dns Service does not exist in kube-system"
        );
    }

    #[test]
    fn upstream_timeouts_and_external_names() {
        let out = cluster("dns/upstream-timeout.yaml");
        let ids: Vec<&str> = out.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "dns.coredns_unhealthy",
                "dns.app_resolution_errors",
                "dns.ndots_hint"
            ]
        );
        assert_eq!(out[0].confidence, Confidence::Medium);
        assert_eq!(out[2].severity, Severity::Low);
        assert!(out[2].title.contains("api.example.com"), "{}", out[2].title);
    }

    #[test]
    fn healthy_dns_and_unreadable_evidence_have_no_findings() {
        assert!(cluster_ids("dns/healthy.yaml").is_empty());
        let unknown = DnsEvidence {
            namespace: "shop".into(),
            ..DnsEvidence::default()
        };
        let mut out = Vec::new();
        check_cluster(&unknown, &mut out);
        assert!(out.is_empty(), "{out:?}");
    }

    fn run(fixture: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        check(&pod_fixture(fixture), &mut out);
        out
    }

    #[test]
    fn resolution_errors_are_quoted() {
        let out = run("pods/dns-errors.yaml");
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::High, Confidence::Medium)
        );
        let logs: Vec<_> = f
            .evidence
            .iter()
            .filter(|e| e.source == Source::Log)
            .collect();
        assert_eq!(logs.len(), 3, "last three matching lines");
        assert!(logs[2].text.contains("ENOTFOUND"));
    }

    #[test]
    fn patterns() {
        for hit in [
            "dial tcp: lookup db.shop.svc.cluster.local on 10.96.0.10:53: no such host",
            "socket.gaierror: [Errno -3] Temporary failure in name resolution",
            "java.net.UnknownHostException: payments",
            "read udp 10.244.0.5:41234->10.96.0.10:53: i/o timeout",
        ] {
            assert!(DNS_ERROR.is_match(hit), "{hit}");
        }
        for miss in [
            "dial tcp 10.0.0.5:5432: i/o timeout",
            "user not found",
            "connection refused",
        ] {
            assert!(!DNS_ERROR.is_match(miss), "{miss}");
        }
    }

    #[test]
    fn logs_without_dns_errors_are_ignored() {
        for f in [
            "pods/crashloop-exit1.yaml",
            "pods/healthy.yaml",
            "pods/oomkilled.yaml",
        ] {
            assert!(run(f).is_empty(), "{f}");
        }
    }
}
