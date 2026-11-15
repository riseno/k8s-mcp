//! Services (PROPOSAL §9.2, v0.2): the selector, the port mapping, pod readiness and load
//! balancer provisioning. Readiness comes from the pods the selector matches, which is what
//! the EndpointSlice controller uses.
//!
//! A numeric `targetPort` that no container declares is only medium confidence: declaring
//! `containerPort` is optional, and apps often listen on ports they do not declare.

use std::collections::BTreeMap;

use k8s_mcp_core::finding::{Confidence, Finding, RuleMeta, Severity, Source};
use k8s_mcp_core::text::age;
use k8s_openapi::api::core::v1::{Pod, ServicePort, ServiceSpec};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use serde_json::json;

use super::{docs, msg, phase, pod_condition, pod_ready, pod_ref, reason, resource_args};
use crate::evidence::ServiceEvidence;

/// Rules emitted by this module.
pub const RULES: &[RuleMeta] = &[
    RuleMeta {
        id: "svc.no_matching_pods",
        title: "The Service selector matches no pods",
        docs: docs::DEBUG_SERVICE,
    },
    RuleMeta {
        id: "svc.target_port_mismatch",
        title: "The Service targetPort is not a port its pods expose",
        docs: docs::DEBUG_SERVICE,
    },
    RuleMeta {
        id: "svc.no_ready_endpoints",
        title: "None of the Service's pods are Ready, so it has no endpoints",
        docs: docs::DEBUG_SERVICE,
    },
    RuleMeta {
        id: "svc.lb_pending",
        title: "The LoadBalancer Service has no external address",
        docs: docs::LOAD_BALANCER,
    },
];

/// How long a LoadBalancer may take to get an address before it is reported.
const LB_GRACE_SECS: i64 = 120;
/// Pods quoted as evidence.
const SHOWN: usize = 3;

/// Check one Service.
pub fn check(ev: &ServiceEvidence, out: &mut Vec<Finding>) {
    let Some(spec) = &ev.service.spec else {
        return;
    };
    if spec.type_.as_deref() == Some("ExternalName") {
        return;
    }
    let name = ev.service.metadata.name.as_deref().unwrap_or("");
    let ns = ev
        .service
        .metadata
        .namespace
        .as_deref()
        .unwrap_or("default");
    // No selector: endpoints are managed by hand or by another controller.
    let (Some(selector), Some(pods)) = (spec.selector.as_ref().filter(|s| !s.is_empty()), &ev.pods)
    else {
        load_balancer(ev, spec, name, ns, out);
        return;
    };
    let live: Vec<&Pod> = pods
        .iter()
        .filter(|p| !matches!(phase(p), "Succeeded" | "Failed"))
        .collect();
    let matched: Vec<&Pod> = live
        .iter()
        .copied()
        .filter(|p| selects(selector, p))
        .collect();
    if matched.is_empty() {
        out.push(no_matching_pods(name, ns, selector, &live));
    } else {
        for port in spec.ports.iter().flatten() {
            if let Some(f) = target_port(name, ns, port, &matched) {
                out.push(f);
            }
        }
        if !spec.publish_not_ready_addresses.unwrap_or(false)
            && !matched.iter().any(|p| pod_ready(p))
        {
            out.push(no_ready_endpoints(name, ns, &matched));
        }
    }
    load_balancer(ev, spec, name, ns, out);
}

/// True when the pod carries every label of the Service selector.
pub fn selects(selector: &BTreeMap<String, String>, pod: &Pod) -> bool {
    let labels = pod.metadata.labels.as_ref();
    selector
        .iter()
        .all(|(k, v)| labels.and_then(|l| l.get(k)) == Some(v))
}

fn fmt_labels(labels: &BTreeMap<String, String>) -> String {
    labels
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn no_matching_pods(
    name: &str,
    ns: &str,
    selector: &BTreeMap<String, String>,
    live: &[&Pod],
) -> Finding {
    let sel = fmt_labels(selector);
    let mut f = Finding::new(
        "svc.no_matching_pods",
        Severity::Critical,
        Confidence::High,
        format!("Service {name} selects no pods ({sel})"),
    )
    .explain(format!(
        "The selector matches none of the {} running pods in namespace {ns}, so the Service has no endpoints and every connection to it fails.",
        live.len()
    ))
    .evidence(Source::Spec, format!("selector: {sel}"));
    // Near misses: pods that carry any of the selector's keys, closest first.
    let mut near: Vec<(&Pod, Vec<String>)> = live
        .iter()
        .filter_map(|p| {
            let labels = p.metadata.labels.as_ref()?;
            if !selector.keys().any(|k| labels.contains_key(k)) {
                return None;
            }
            let diffs = selector
                .iter()
                .filter_map(|(k, v)| match labels.get(k) {
                    Some(have) if have == v => None,
                    Some(have) => Some(format!("{k}={have} (selector wants {k}={v})")),
                    None => Some(format!("no label {k} (selector wants {k}={v})")),
                })
                .collect();
            Some((*p, diffs))
        })
        .collect();
    near.sort_by_key(|(p, d)| (d.len(), pod_ref(p).0.to_owned()));
    if near.is_empty() {
        f = f.evidence(
            Source::Related,
            format!("no pod in {ns} carries any of the selector's labels"),
        );
    }
    for (p, diffs) in near.iter().take(SHOWN) {
        f = f.evidence(
            Source::Related,
            format!("pod {} has {}", pod_ref(p).0, diffs.join(", ")),
        );
    }
    f.docs(docs::DEBUG_SERVICE)
        .fix("Make the Service selector and the pod template labels agree: compare `selector` in the Service with the labels on the pods it should reach (`kubectl get pods --show-labels`). Change whichever side is wrong; pod labels come from the workload's pod template.")
        .next(
            "list_resources",
            json!({"kind": "Pod", "namespace": ns}),
            "see the pods in the namespace",
        )
        .next(
            "get_resource",
            resource_args("Service", name, ns),
            "see the Service selector and ports",
        )
}

/// True when a container of the pod declares the port's targetPort (by name or number).
pub fn exposes(pod: &Pod, port: &ServicePort) -> bool {
    pod.spec
        .iter()
        .flat_map(|s| &s.containers)
        .flat_map(|c| c.ports.iter().flatten())
        .any(|cp| match &port.target_port {
            Some(IntOrString::String(name)) => cp.name.as_deref() == Some(name.as_str()),
            Some(IntOrString::Int(n)) => cp.container_port == *n,
            None => cp.container_port == port.port,
        })
}

/// Every declared container port as (name, number, protocol), sorted and de-duplicated.
fn container_ports(pods: &[&Pod]) -> Vec<(Option<String>, i32, String)> {
    let mut ports: Vec<(Option<String>, i32, String)> = pods
        .iter()
        .filter_map(|p| p.spec.as_ref())
        .flat_map(|s| &s.containers)
        .flat_map(|c| c.ports.iter().flatten())
        .map(|p| {
            (
                p.name.clone(),
                p.container_port,
                p.protocol.clone().unwrap_or_else(|| "TCP".into()),
            )
        })
        .collect();
    ports.sort();
    ports.dedup();
    ports
}

fn target_port(name: &str, ns: &str, port: &ServicePort, pods: &[&Pod]) -> Option<Finding> {
    if pods.iter().any(|p| exposes(p, port)) {
        return None;
    }
    let declared = container_ports(pods);
    let shown = declared
        .iter()
        .map(|(n, p, proto)| match n {
            Some(n) => format!("{n} {p}/{proto}"),
            None => format!("{p}/{proto}"),
        })
        .collect::<Vec<_>>()
        .join(", ");
    let protocol = port.protocol.as_deref().unwrap_or("TCP");
    let label = port
        .name
        .as_deref()
        .map_or_else(|| port.port.to_string(), |n| format!("{n} ({})", port.port));
    let (target, confidence, severity, why) = match &port.target_port {
        Some(IntOrString::String(t)) => (
                format!("{t:?}"),
                Confidence::High,
                Severity::Critical,
                "A named targetPort must match a named containerPort on each pod; no selected pod has one with this name, so the port has no endpoints.".to_owned(),
            ),
        target => {
            let n = match target {
                Some(IntOrString::Int(n)) => *n,
                _ => port.port,
            };
            // Undeclared ports are allowed: only judge pods that declare some.
            if declared.is_empty() {
                return None;
            }
            (
                n.to_string(),
                Confidence::Medium,
                Severity::High,
                "The selected pods declare other container ports. If the app listens only on those, connections to the Service are refused (declared ports are informational, so check what the app really listens on).".to_owned(),
            )
        }
    };
    Some(
        Finding::new(
            "svc.target_port_mismatch",
            severity,
            confidence,
            format!("Service {name} port {label} targets port {target}, which its pods do not expose"),
        )
        .explain(why)
        .evidence(
            Source::Spec,
            format!("port {label}/{protocol} -> targetPort {target}"),
        )
        .evidence(
            Source::Spec,
            format!("pod {} declares: {shown}", pod_ref(pods[0]).0),
        )
        .docs(docs::DEBUG_SERVICE)
        .fix("Point targetPort at the port the container listens on (by number, or by the containerPort name), or add that port to the pod template.")
        .next(
            "get_resource",
            resource_args("Service", name, ns),
            "see the Service ports",
        ),
    )
}

fn no_ready_endpoints(name: &str, ns: &str, matched: &[&Pod]) -> Finding {
    let mut f = Finding::new(
        "svc.no_ready_endpoints",
        Severity::Critical,
        Confidence::High,
        format!(
            "Service {name} has no ready endpoints: none of its {} pods are Ready",
            matched.len()
        ),
    )
    .explain("Services only route to Ready pods. Every pod the selector matches is failing its readiness probe or still starting, so connections to the Service are refused or time out.");
    for p in matched.iter().take(SHOWN) {
        let ready = pod_condition(p, "Ready").map_or_else(
            || "no Ready condition".to_owned(),
            |c| match &c.reason {
                Some(r) => format!("Ready={} ({r})", c.status),
                None => format!("Ready={}", c.status),
            },
        );
        f = f.evidence(
            Source::Status,
            format!("pod {}: {}, {ready}", pod_ref(p).0, phase(p)),
        );
    }
    let first = pod_ref(matched[0]).0;
    f.docs(docs::DEBUG_SERVICE)
        .fix("Fix the pods first: diagnose_pod tells why they are not Ready. A readiness probe that fails while the app works usually checks the wrong port or path.")
        .next(
            "diagnose_pod",
            json!({"name": first, "namespace": ns}),
            "find out why the pod is not Ready",
        )
}

fn load_balancer(
    ev: &ServiceEvidence,
    spec: &ServiceSpec,
    name: &str,
    ns: &str,
    out: &mut Vec<Finding>,
) {
    if spec.type_.as_deref() != Some("LoadBalancer") {
        return;
    }
    let has_address = ev
        .service
        .status
        .as_ref()
        .and_then(|s| s.load_balancer.as_ref())
        .and_then(|lb| lb.ingress.as_ref())
        .is_some_and(|i| !i.is_empty());
    let Some(created) = ev.service.metadata.creation_timestamp.as_ref().map(|t| t.0) else {
        return;
    };
    if has_address || ev.now.duration_since(created).as_secs() < LB_GRACE_SECS {
        return;
    }
    let failures: Vec<_> = ev
        .events
        .iter()
        .filter(|e| e.type_.as_deref() == Some("Warning"))
        .collect();
    let mut f = Finding::new(
        "svc.lb_pending",
        Severity::High,
        if failures.is_empty() {
            Confidence::Medium
        } else {
            Confidence::High
        },
        format!(
            "LoadBalancer Service {name} has no external address after {}",
            age(ev.now, created)
        ),
    );
    if failures.is_empty() {
        f = f
            .explain("No load balancer has been provisioned and no controller reported an error. Clusters without a load-balancer controller (kind, bare metal without MetalLB, k3s with ServiceLB disabled) never fill in the address.")
            .fix("Install a load-balancer controller (the cloud controller manager, MetalLB, or k3s ServiceLB), or set loadBalancerClass to one that exists; otherwise use a ClusterIP Service behind an Ingress or Gateway.");
    } else {
        f = f
            .explain("The controller that provisions load balancers reported errors for this Service.")
            .fix("Fix the cause in the events (cloud quota, subnet or security-group tags, an annotation the controller rejects), then wait for the controller to retry.");
        for e in failures.iter().take(2) {
            f = f.evidence(Source::Event, format!("{}: {}", reason(e), msg(e)));
        }
    }
    out.push(f.docs(docs::LOAD_BALANCER).next(
        "list_events",
        json!({"namespace": ns, "involved_kind": "Service", "involved_name": name, "types": ["Warning", "Normal"]}),
        "see the load balancer provisioning events",
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::service_fixture;

    fn ids(fixture: &str) -> Vec<String> {
        let mut out = Vec::new();
        check(&service_fixture(fixture), &mut out);
        out.into_iter().map(|f| f.id).collect()
    }

    fn finding(fixture: &str, id: &str) -> Finding {
        let mut out = Vec::new();
        check(&service_fixture(fixture), &mut out);
        out.into_iter().find(|f| f.id == id).unwrap()
    }

    fn texts(f: &Finding) -> Vec<&str> {
        f.evidence.iter().map(|e| e.text.as_str()).collect()
    }

    #[test]
    fn selector_mismatch_shows_the_label_diff() {
        assert_eq!(
            ids("services/selector-mismatch.yaml"),
            ["svc.no_matching_pods"]
        );
        let f = finding("services/selector-mismatch.yaml", "svc.no_matching_pods");
        assert_eq!(f.severity, Severity::Critical);
        assert!(
            texts(&f).contains(&"pod web-6f7d9-abcde has app=web-v2 (selector wants app=web)"),
            "{:?}",
            texts(&f)
        );
        assert!(
            !texts(&f).iter().any(|t| t.contains("batch-runner")),
            "{:?}",
            texts(&f)
        );
    }

    /// The common case: one selector key whose value differs.
    #[test]
    fn single_key_selector_mismatch_still_shows_the_diff() {
        let mut ev = service_fixture("services/selector-mismatch.yaml");
        ev.service.spec.as_mut().unwrap().selector =
            Some([("app".to_owned(), "web".to_owned())].into());
        let mut out = Vec::new();
        check(&ev, &mut out);
        assert!(
            texts(&out[0]).contains(&"pod web-6f7d9-abcde has app=web-v2 (selector wants app=web)"),
            "{:?}",
            texts(&out[0])
        );
    }

    #[test]
    fn named_target_port_missing_is_critical() {
        let f = finding(
            "services/target-port-name-missing.yaml",
            "svc.target_port_mismatch",
        );
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::Critical, Confidence::High)
        );
        assert!(
            texts(&f).contains(&"pod api-7c9d8-k2j4h declares: web 8080/TCP"),
            "{:?}",
            texts(&f)
        );
    }

    #[test]
    fn numeric_target_port_mismatch_is_medium_confidence() {
        assert_eq!(
            ids("services/target-port-number-mismatch.yaml"),
            ["svc.target_port_mismatch"]
        );
        let f = finding(
            "services/target-port-number-mismatch.yaml",
            "svc.target_port_mismatch",
        );
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::High, Confidence::Medium)
        );
        assert!(f.title.contains("targets port 8080"), "{}", f.title);
    }

    #[test]
    fn unready_pods_mean_no_endpoints() {
        assert_eq!(
            ids("services/no-ready-endpoints.yaml"),
            ["svc.no_ready_endpoints"]
        );
        let f = finding("services/no-ready-endpoints.yaml", "svc.no_ready_endpoints");
        assert!(
            texts(&f).contains(&"pod cart-5b6c7-qwert: Running, Ready=False (ContainersNotReady)"),
            "{:?}",
            texts(&f)
        );
        assert_eq!(f.next[0].tool, "diagnose_pod");
    }

    #[test]
    fn pending_load_balancer_without_controller_is_medium() {
        assert_eq!(ids("services/lb-pending.yaml"), ["svc.lb_pending"]);
        let f = finding("services/lb-pending.yaml", "svc.lb_pending");
        assert_eq!(f.confidence, Confidence::Medium);
        assert!(f.title.ends_with("after 10m"), "{}", f.title);
    }

    #[test]
    fn healthy_and_special_services_have_no_findings() {
        assert!(ids("services/healthy.yaml").is_empty());
        let mut ev = service_fixture("services/selector-mismatch.yaml");
        // Unreadable pods, no selector, ExternalName: nothing to judge.
        let mut unreadable = ev.clone();
        unreadable.pods = None;
        let mut manual = ev.clone();
        manual.service.spec.as_mut().unwrap().selector = None;
        ev.service.spec.as_mut().unwrap().type_ = Some("ExternalName".into());
        for e in [unreadable, manual, ev] {
            let mut out = Vec::new();
            check(&e, &mut out);
            assert!(out.is_empty(), "{out:?}");
        }
    }

    #[test]
    fn lb_failure_events_raise_confidence() {
        let mut ev = service_fixture("services/lb-pending.yaml");
        ev.events.push(serde_json::from_value(json!({
            "metadata": {"name": "e1", "namespace": "shop"},
            "involvedObject": {"kind": "Service", "name": "shop-lb", "namespace": "shop"},
            "type": "Warning", "reason": "SyncLoadBalancerFailed",
            "message": "Error syncing load balancer: failed to ensure load balancer: quota exceeded"
        })).unwrap());
        let mut out = Vec::new();
        check(&ev, &mut out);
        assert_eq!(out[0].confidence, Confidence::High);
        assert_eq!(out[0].evidence[0].source, Source::Event);
    }
}
