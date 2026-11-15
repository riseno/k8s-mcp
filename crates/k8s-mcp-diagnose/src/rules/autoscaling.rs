//! Autoscaling (PROPOSAL §8.1 `autoscaling_status`, v0.2): why the cluster does not add nodes
//! (Karpenter NodePools and NodeClaims, the Cluster Autoscaler) and why workloads do not scale
//! (HorizontalPodAutoscalers).
//!
//! Karpenter objects arrive as JSON (no typed API in k8s-openapi) and the Cluster Autoscaler
//! status as its parsed YAML (`cluster-autoscaler-status`, CA 1.30+ format).

use k8s_mcp_core::finding::{Confidence, Finding, RuleMeta, Severity, Source};
use k8s_mcp_core::quantity::{bytes, cpu_millis};
use k8s_mcp_core::text::{age, truncate};
use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;
use serde_json::{Value, json};

use super::{docs, msg, resource_args};
use crate::evidence::AutoscalingEvidence;

/// Rules emitted by this module.
pub const RULES: &[RuleMeta] = &[
    RuleMeta {
        id: "autoscaling.karpenter.limit_reached",
        title: "A Karpenter NodePool has reached its resource limits",
        docs: docs::KARPENTER_NODEPOOL,
    },
    RuleMeta {
        id: "autoscaling.karpenter.nodeclaim_not_launched",
        title: "A Karpenter NodeClaim failed to launch or to join the cluster",
        docs: docs::KARPENTER_NODEPOOL,
    },
    RuleMeta {
        id: "autoscaling.ca.not_triggered",
        title: "The Cluster Autoscaler would not scale up for pending pods",
        docs: docs::CLUSTER_AUTOSCALER,
    },
    RuleMeta {
        id: "autoscaling.ca.unhealthy",
        title: "The Cluster Autoscaler reports an unhealthy cluster or node group",
        docs: docs::CLUSTER_AUTOSCALER,
    },
    RuleMeta {
        id: "autoscaling.hpa.not_scaling",
        title: "A HorizontalPodAutoscaler cannot compute or apply a scale",
        docs: docs::HPA,
    },
    RuleMeta {
        id: "autoscaling.hpa.at_max",
        title: "A HorizontalPodAutoscaler is pinned at maxReplicas",
        docs: docs::HPA,
    },
];

/// A NodeClaim may take this long to launch, and to register, before it is reported.
const LAUNCH_GRACE_SECS: i64 = 300;
const REGISTER_GRACE_SECS: i64 = 900;

/// Check every autoscaler.
pub fn check(ev: &AutoscalingEvidence, out: &mut Vec<Finding>) {
    for np in ev.nodepools.iter().flatten() {
        nodepool_limits(np, out);
    }
    for nc in &ev.nodeclaims {
        nodeclaim(ev, nc, out);
    }
    not_triggered(ev, out);
    if let Some(status) = &ev.ca_status {
        ca_health(status, out);
    }
    for hpa in ev.hpas.iter().flatten() {
        hpa_conditions(hpa, out);
    }
}

fn name_of(o: &Value) -> &str {
    o["metadata"]["name"].as_str().unwrap_or("")
}

/// `used >= limit`, comparing CPU in millicores (decimal suffixes like `1k` too) and
/// everything else as plain quantities.
fn at_limit(resource: &str, used: &str, limit: &str) -> bool {
    let parse = |q: &str| {
        if resource == "cpu" {
            cpu_millis(q).or_else(|| bytes(q).map(|v| v * 1000))
        } else {
            bytes(q)
        }
    };
    matches!((parse(used), parse(limit)), (Some(u), Some(l)) if u >= l)
}

fn nodepool_limits(np: &Value, out: &mut Vec<Finding>) {
    let Some(limits) = np["spec"]["limits"].as_object() else {
        return;
    };
    let used = &np["status"]["resources"];
    let reached: Vec<String> = limits
        .iter()
        .filter_map(|(r, limit)| {
            let (u, l) = (used[r].as_str()?, limit.as_str()?);
            at_limit(r, u, l).then(|| format!("{r} {u} of {l}"))
        })
        .collect();
    if reached.is_empty() {
        return;
    }
    let name = name_of(np);
    out.push(
        Finding::new(
            "autoscaling.karpenter.limit_reached",
            Severity::High,
            Confidence::High,
            format!("Karpenter NodePool {name} has reached its limits ({})", reached.join(", ")),
        )
        .explain("Karpenter launches no more nodes for a NodePool once the capacity it already provisioned reaches spec.limits, so pending pods that only this NodePool can take stay Pending.")
        .evidence(Source::Status, format!("NodePool {name}: {}", reached.join(", ")))
        .docs(docs::KARPENTER_NODEPOOL)
        .fix("Raise (or remove) spec.limits on the NodePool if the extra capacity is intended, add another NodePool the pods can use, or reduce what is running (scale down idle workloads, consolidate).")
        .next("get_resource", json!({"kind": "NodePool", "name": name}), "see the NodePool limits and status"),
    );
}

fn condition<'a>(o: &'a Value, type_: &str) -> Option<&'a Value> {
    o["status"]["conditions"]
        .as_array()?
        .iter()
        .find(|c| c["type"] == type_)
}

fn describe(c: &Value) -> String {
    format!(
        "condition {}={} reason={}: {}",
        c["type"].as_str().unwrap_or(""),
        c["status"].as_str().unwrap_or(""),
        c["reason"].as_str().unwrap_or("-"),
        truncate(c["message"].as_str().unwrap_or(""), 300)
    )
}

fn nodeclaim(ev: &AutoscalingEvidence, nc: &Value, out: &mut Vec<Finding>) {
    let Some(created) = nc["metadata"]["creationTimestamp"]
        .as_str()
        .and_then(|t| t.parse::<jiff::Timestamp>().ok())
    else {
        return;
    };
    let secs = ev.now.duration_since(created).as_secs();
    let is_false = |c: Option<&Value>| c.is_some_and(|c| c["status"] == "False");
    let launched = condition(nc, "Launched");
    let registered = condition(nc, "Registered");
    let (title, cond, explain) = if is_false(launched) && secs >= LAUNCH_GRACE_SECS {
        (
            "failed to launch",
            launched,
            "Karpenter could not create the instance for this NodeClaim, typically because no offered instance type has capacity, a quota or permission error, or a NodeClass (subnet, security group, AMI) problem.",
        )
    } else if launched.is_some_and(|c| c["status"] == "True")
        && !registered.is_some_and(|c| c["status"] == "True")
        && secs >= REGISTER_GRACE_SECS
    {
        (
            "launched but never joined the cluster",
            registered,
            "The instance exists but its kubelet never registered a Node: the node cannot reach the API server, or its bootstrap (user data, node role and access entry, AMI) is broken.",
        )
    } else {
        return;
    };
    let name = name_of(nc);
    let pool = nc["metadata"]["labels"]["karpenter.sh/nodepool"]
        .as_str()
        .unwrap_or("?");
    let mut f = Finding::new(
        "autoscaling.karpenter.nodeclaim_not_launched",
        Severity::High,
        Confidence::High,
        format!("Karpenter NodeClaim {name} (NodePool {pool}) {title}"),
    )
    .explain(explain)
    .evidence(Source::Status, format!("NodeClaim {name} created {} ago", age(ev.now, created)))
    .docs(docs::KARPENTER_NODEPOOL)
    .fix("Read the NodeClaim's conditions and the Karpenter controller logs: fix the NodeClass (subnets, security groups, AMI selector, instance profile), widen the NodePool's instance-type requirements, or resolve the cloud quota or permission error they name.")
    .next("get_resource", json!({"kind": "NodeClaim", "name": name}), "see the NodeClaim's conditions");
    if let Some(c) = cond {
        f = f.evidence(Source::Status, describe(c));
    }
    out.push(f);
}

fn not_triggered(ev: &AutoscalingEvidence, out: &mut Vec<Finding>) {
    let events: Vec<_> = ev
        .events
        .iter()
        .filter(|e| e.reason.as_deref() == Some("NotTriggerScaleUp"))
        .collect();
    if events.is_empty() {
        return;
    }
    let pods: std::collections::BTreeSet<&str> = events
        .iter()
        .filter_map(|e| e.involved_object.name.as_deref())
        .collect();
    let all = events.iter().map(|e| msg(e)).collect::<Vec<_>>().join(" ");
    // Directions chosen from what CA reported; the message itself stays in the evidence.
    let mut fixes = Vec::new();
    if all.contains("max node group size reached") {
        fixes.push("raise the maximum size of the node groups at their limit");
    }
    if all.contains("node affinity/selector") || all.contains("untolerated taint") {
        fixes.push("make a node group's labels and taints match the pods' nodeSelector, affinity and tolerations (CA judges from the group's node template)");
    }
    if all.contains("Insufficient") {
        fixes.push("add a node group whose instance type is large enough for the pods' requests");
    }
    if fixes.is_empty() {
        fixes.push("read the reasons in the events: each names why a node group was not a fit");
    }
    let mut f = Finding::new(
        "autoscaling.ca.not_triggered",
        Severity::High,
        Confidence::High,
        format!(
            "The Cluster Autoscaler did not scale up for {} pending pod(s)",
            pods.len()
        ),
    )
    .explain("The Cluster Autoscaler simulated adding a node from every node group and none would let these pods schedule, so it added nothing.")
    .docs(docs::CLUSTER_AUTOSCALER)
    .fix(format!("To let it scale up: {}.", fixes.join("; ")));
    for e in events.iter().take(2) {
        f = f.evidence(
            Source::Event,
            format!(
                "pod {}: {}",
                e.involved_object.name.as_deref().unwrap_or(""),
                msg(e)
            ),
        );
    }
    if let Some(e) = events.first()
        && let (Some(name), Some(ns)) = (
            e.involved_object.name.as_deref(),
            e.involved_object.namespace.as_deref(),
        )
    {
        f = f.next(
            "diagnose_pod",
            json!({"name": name, "namespace": ns}),
            "see why the pod does not fit the existing nodes",
        );
    }
    out.push(f);
}

fn ca_health(status: &Value, out: &mut Vec<Finding>) {
    let unhealthy = |s: &Value| {
        s["health"]["status"]
            .as_str()
            .is_some_and(|h| h != "Healthy")
    };
    let mut problems = Vec::new();
    if unhealthy(&status["clusterWide"]) {
        let counts = &status["clusterWide"]["health"]["nodeCounts"];
        problems.push(format!(
            "cluster-wide health {} (registered {}, ready {}, unregistered {})",
            status["clusterWide"]["health"]["status"]
                .as_str()
                .unwrap_or("?"),
            counts["registered"]["total"],
            counts["registered"]["ready"],
            counts["unregistered"]
        ));
    }
    for g in status["nodeGroups"].as_array().into_iter().flatten() {
        let name = g["name"].as_str().unwrap_or("?");
        if unhealthy(g) {
            problems.push(format!(
                "node group {name} health {}",
                g["health"]["status"].as_str().unwrap_or("?")
            ));
        }
        if g["scaleUp"]["status"] == "Backoff" {
            problems.push(format!(
                "node group {name} scale-up in backoff: {} {}",
                g["scaleUp"]["backoffInfo"]["errorCode"]
                    .as_str()
                    .unwrap_or(""),
                truncate(
                    g["scaleUp"]["backoffInfo"]["errorMessage"]
                        .as_str()
                        .unwrap_or(""),
                    300
                )
            ));
        }
    }
    if problems.is_empty() {
        return;
    }
    let mut f = Finding::new(
        "autoscaling.ca.unhealthy",
        Severity::High,
        Confidence::High,
        format!("The Cluster Autoscaler reports {}", if problems.len() == 1 { "a problem" } else { "problems" }),
    )
    .explain("When the cluster or a node group is unhealthy (too many unready or unregistered nodes) or scale-up is backing off after errors, the Cluster Autoscaler stops or slows scaling.")
    .docs(docs::CLUSTER_AUTOSCALER)
    .fix("Fix the nodes that are not ready or not registering (diagnose_node), or the cloud error behind the backoff (quota, instance availability, launch template), then CA resumes on its own.");
    for p in problems.iter().take(3) {
        f = f.evidence(Source::Status, p.clone());
    }
    out.push(f.next(
        "get_resource",
        resource_args("ConfigMap", "cluster-autoscaler-status", "kube-system"),
        "read the full Cluster Autoscaler status",
    ));
}

fn hpa_conditions(hpa: &HorizontalPodAutoscaler, out: &mut Vec<Finding>) {
    let name = hpa.metadata.name.as_deref().unwrap_or("");
    let ns = hpa.metadata.namespace.as_deref().unwrap_or("default");
    let target = hpa.spec.as_ref().map_or_else(String::new, |s| {
        format!("{}/{}", s.scale_target_ref.kind, s.scale_target_ref.name)
    });
    let conditions = hpa
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .map(Vec::as_slice)
        .unwrap_or_default();
    let quote = |c: &k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscalerCondition| {
        format!(
            "condition {}={} reason={}: {}",
            c.type_,
            c.status,
            c.reason.as_deref().unwrap_or("-"),
            truncate(c.message.as_deref().unwrap_or(""), 300)
        )
    };
    let next = |f: Finding| {
        f.docs(docs::HPA).next(
            "get_resource",
            resource_args("HorizontalPodAutoscaler", name, ns),
            "see the HPA's metrics and conditions",
        )
    };
    if let Some(c) = conditions.iter().find(|c| {
        matches!(c.type_.as_str(), "ScalingActive" | "AbleToScale") && c.status == "False"
    }) {
        out.push(next(
            Finding::new(
                "autoscaling.hpa.not_scaling",
                Severity::High,
                Confidence::High,
                format!("HPA {name} ({ns}) cannot scale {target}"),
            )
            .explain("The HPA cannot read its metrics or the target's scale, so the replica count stays where it is whatever the load.")
            .evidence(Source::Status, quote(c))
            .fix("For metric errors: check that metrics-server (or the custom/external metrics adapter) is running and that the target's containers set resource requests for the metric; for scale errors: check the scaleTargetRef kind and name."),
        ));
        return;
    }
    let (Some(spec), Some(status)) = (&hpa.spec, &hpa.status) else {
        return;
    };
    if let Some(c) = conditions.iter().find(|c| {
        c.type_ == "ScalingLimited"
            && c.status == "True"
            && c.reason.as_deref() == Some("TooManyReplicas")
    }) && status.current_replicas.unwrap_or(0) >= spec.max_replicas
    {
        out.push(next(
            Finding::new(
                "autoscaling.hpa.at_max",
                Severity::Medium,
                Confidence::High,
                format!("HPA {name} ({ns}) keeps {target} at maxReplicas ({})", spec.max_replicas),
            )
            .explain("The metrics ask for more replicas than maxReplicas allows, so the workload runs at its ceiling and may be overloaded.")
            .evidence(Source::Status, quote(c))
            .fix("Raise maxReplicas if the cluster has room (and the nodes can scale), or make each replica handle more (resources, efficiency)."),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::autoscaling_fixture;

    fn run(fixture: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        check(&autoscaling_fixture(fixture), &mut out);
        out
    }

    fn ids(fixture: &str) -> Vec<String> {
        run(fixture).into_iter().map(|f| f.id).collect()
    }

    /// v0.2 acceptance criterion 5.
    #[test]
    fn karpenter_nodepool_at_its_limit() {
        let out = run("autoscaling/karpenter-limit.yaml");
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].id, "autoscaling.karpenter.limit_reached");
        assert_eq!(
            out[0].title,
            "Karpenter NodePool general has reached its limits (cpu 1000 of 1k)"
        );
    }

    /// v0.2 acceptance criterion 5.
    #[test]
    fn cluster_autoscaler_not_trigger_scale_up() {
        let out = run("autoscaling/ca-not-triggered.yaml");
        let f = out
            .iter()
            .find(|f| f.id == "autoscaling.ca.not_triggered")
            .unwrap();
        assert_eq!(
            f.title,
            "The Cluster Autoscaler did not scale up for 2 pending pod(s)"
        );
        assert!(f.fix.contains("raise the maximum size"), "{}", f.fix);
        assert!(
            !f.fix.contains("pod didn't trigger"),
            "event text stays out of the fix"
        );
        assert_eq!(f.evidence[0].source, Source::Event);
        assert_eq!(f.next[0].tool, "diagnose_pod");
    }

    #[test]
    fn nodeclaims_that_never_launch_or_join() {
        let out = run("autoscaling/karpenter-nodeclaims.yaml");
        let titles: Vec<&str> = out.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(
            titles,
            [
                "Karpenter NodeClaim general-x7k2p (NodePool general) failed to launch",
                "Karpenter NodeClaim general-q9w8e (NodePool general) launched but never joined the cluster",
            ],
            "the young NodeClaim is not reported"
        );
    }

    #[test]
    fn cluster_autoscaler_backoff_and_unhealthy_groups() {
        let out = run("autoscaling/ca-unhealthy.yaml");
        assert_eq!(out.len(), 1);
        let texts: Vec<&str> = out[0].evidence.iter().map(|e| e.text.as_str()).collect();
        assert!(
            texts
                .iter()
                .any(|t| t.starts_with("node group ng-spot scale-up in backoff: OutOfResource")),
            "{texts:?}"
        );
    }

    #[test]
    fn hpas_without_metrics_or_at_their_ceiling() {
        assert_eq!(
            ids("autoscaling/hpa.yaml"),
            ["autoscaling.hpa.not_scaling", "autoscaling.hpa.at_max"]
        );
    }

    #[test]
    fn healthy_autoscalers_have_no_findings() {
        assert!(ids("autoscaling/healthy.yaml").is_empty());
        let mut out = Vec::new();
        check(&AutoscalingEvidence::default(), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn quantities_compare_by_value() {
        assert!(at_limit("cpu", "1000", "1k"));
        assert!(at_limit("cpu", "2", "2000m"));
        assert!(!at_limit("cpu", "999", "1k"));
        assert!(at_limit("memory", "4Gi", "4096Mi"));
        assert!(!at_limit("memory", "3Gi", "4Gi"));
        assert!(!at_limit("memory", "bogus", "4Gi"));
    }
}
