//! DNS resolution errors in the pod's own logs (PROPOSAL §9.2, the v0.1 log-pattern rule).
//!
//! Log patterns are only medium-confidence evidence, so the finding is `high`/`medium`: it
//! never outranks a definitive root cause (always `critical`), such as the crash loop whose
//! logs show the same lines. Cluster-side DNS checks (CoreDNS health, NetworkPolicies) arrive
//! with `diagnose_dns` in v0.2.

use std::sync::LazyLock;

use k8s_mcp_core::finding::{Confidence, Finding, RuleMeta, Severity, Source};
use k8s_mcp_core::text::truncate;
use regex::Regex;
use serde_json::json;

use super::{docs, logs_args, re};
use crate::evidence::PodEvidence;

/// Rules emitted by this module.
pub const RULES: &[RuleMeta] = &[RuleMeta {
    id: "dns.app_resolution_errors",
    title: "The application logs DNS resolution failures",
    docs: docs::DNS,
}];

static DNS_ERROR: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)no such host|temporary failure in name resolution|name or service not known|server misbehaving|servfail|getaddrinfo (enotfound|eai_again)|unknownhostexception|could not resolve host|:53\b.*i/o timeout",
    )
});

/// Check every container log tail.
pub fn check(ev: &PodEvidence, out: &mut Vec<Finding>) {
    for log in &ev.logs {
        let hits: Vec<&String> = log.lines.iter().filter(|l| DNS_ERROR.is_match(l)).collect();
        let Some(last) = hits.len().checked_sub(1) else {
            continue;
        };
        let name = &log.container;
        let mut f = Finding::new("dns.app_resolution_errors", Severity::High, Confidence::Medium, format!("container {name:?} logs DNS resolution failures"))
            .explain(format!("{} of the last {} log lines report that a hostname could not be resolved. The application cannot reach the services it depends on by name.", hits.len(), log.lines.len()))
            .fix("Find the layer that fails: the hostname itself (typo, missing Service, wrong namespace: use `<service>.<namespace>.svc.cluster.local`), the pod's dnsPolicy/dnsConfig, a NetworkPolicy blocking egress to port 53 in kube-system, then CoreDNS health. A dedicated diagnose_dns tool arrives in v0.2.")
            .docs(docs::DNS)
            .next("get_logs", logs_args(&ev.pod, name, log.previous), "read the failing lookups in context")
            .next("list_resources", json!({"kind": "Pod", "namespace": "kube-system", "label_selector": "k8s-app=kube-dns"}), "check that the cluster DNS pods are running and ready");
        for line in &hits[last.saturating_sub(2)..] {
            f = f.evidence(Source::Log, truncate(line, 300));
        }
        out.push(f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::pod_fixture;

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
