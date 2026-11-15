//! Pods stuck terminating and evicted pods (PROPOSAL §9.2).
//!
//! `metadata.deletionTimestamp` is the deletion request time plus the grace period, so a
//! pod still present 5 minutes after it is stuck. Force-delete guidance is text only: v0.1
//! has no write tools.

use k8s_mcp_core::finding::{Confidence, Finding, RuleMeta, Severity, Source};
use k8s_mcp_core::text::{age, truncate};
use serde_json::json;

use super::{docs, secs_since};
use crate::evidence::PodEvidence;

/// Rules emitted by this module.
pub const RULES: &[RuleMeta] = &[
    RuleMeta {
        id: "pod.terminating.stuck",
        title: "Pod is stuck terminating long past its grace period",
        docs: docs::FINALIZERS,
    },
    RuleMeta {
        id: "pod.evicted",
        title: "Pod was evicted by the kubelet because of node resource pressure",
        docs: docs::EVICTION,
    },
];

/// Grace beyond `deletionTimestamp` before a terminating pod counts as stuck.
const STUCK_AFTER_SECS: i64 = 300;

/// Check deletion and eviction state.
pub fn check(ev: &PodEvidence, out: &mut Vec<Finding>) {
    let node = ev.pod.spec.as_ref().and_then(|s| s.node_name.as_deref());
    let diagnose_node = |f: Finding, why: &str| match node {
        Some(n) => f.next("diagnose_node", json!({ "name": n }), why),
        None => f,
    };

    if let Some(deleted) = ev.pod.metadata.deletion_timestamp.as_ref().map(|t| t.0)
        && secs_since(ev.now, deleted) > STUCK_AFTER_SECS
    {
        let finalizers = ev.pod.metadata.finalizers.as_deref().unwrap_or_default();
        let node_down = ev.node.as_ref().is_some_and(|n| {
            n.status
                .as_ref()
                .and_then(|s| s.conditions.as_ref())
                .into_iter()
                .flatten()
                .any(|c| c.type_ == "Ready" && c.status != "True")
        });
        let (cause, fix) = if !finalizers.is_empty() {
            (
                "Finalizers are still set: the API server only removes the pod once every finalizer's controller has finished and cleared its entry.",
                "Find the controller that owns each finalizer and fix it (it is usually down or erroring). As a last resort remove the finalizers: `kubectl patch pod <pod> --type merge -p '{\"metadata\":{\"finalizers\":null}}'`.",
            )
        } else if node_down {
            (
                "The pod's node is not Ready, so no kubelet confirms that the containers stopped and the API object stays.",
                "Bring the node back, or remove the object with `kubectl delete pod <pod> --grace-period=0 --force`. The containers may still run if the node returns; StatefulSet pods then risk running twice.",
            )
        } else {
            (
                "The kubelet has not confirmed that the containers stopped. A process that ignores SIGTERM is killed after the grace period, so a longer wait points at the container runtime or a volume unmount that hangs.",
                "Check the node (diagnose_node) for runtime or volume errors. If the node is healthy and the pod still hangs, `kubectl delete pod <pod> --grace-period=0 --force` removes the object.",
            )
        };
        let mut f = Finding::new(
            "pod.terminating.stuck",
            Severity::High,
            Confidence::High,
            format!(
                "pod is stuck terminating {} past its grace period",
                age(ev.now, deleted)
            ),
        )
        .explain(format!(
            "The pod was deleted but has not gone away. {cause}"
        ))
        .evidence(
            Source::Status,
            format!("metadata.deletionTimestamp {} ago", age(ev.now, deleted)),
        )
        .fix(fix)
        .docs(docs::FINALIZERS);
        if !finalizers.is_empty() {
            f = f.evidence(
                Source::Spec,
                format!(
                    "metadata.finalizers: {}",
                    truncate(&finalizers.join(", "), 300)
                ),
            );
        }
        if node_down {
            f = f.evidence(
                Source::Related,
                format!("node {} is not Ready", node.unwrap_or("")),
            );
        }
        out.push(diagnose_node(f, "check whether the node is healthy"));
    }

    let status = ev.pod.status.as_ref();
    if status.and_then(|s| s.reason.as_deref()) == Some("Evicted") {
        let message = status.and_then(|s| s.message.as_deref()).unwrap_or("");
        let lower = message.to_ascii_lowercase();
        let (what, fix) = if lower.contains("memory") {
            (
                "memory",
                "Set memory requests close to real usage: under memory pressure the kubelet evicts pods using the most memory above their request first. Then check why the node ran low (diagnose_node, `top`).",
            )
        } else if lower.contains("ephemeral-storage")
            || lower.contains("disk")
            || lower.contains("nodefs")
            || lower.contains("imagefs")
        {
            (
                "disk",
                "Set ephemeral-storage requests and limits, and look for growing emptyDir volumes, container logs or files written into the container filesystem. Then check the node's disk (diagnose_node).",
            )
        } else if lower.contains("pid") {
            (
                "PID",
                "Find the process leak (a fork loop or threads never reaped) and set a pod PID limit on the kubelet if needed. Then check the node (diagnose_node).",
            )
        } else {
            (
                "resource",
                "Read the eviction message for the resource and its threshold, then check the node (diagnose_node).",
            )
        };
        let f = Finding::new("pod.evicted", Severity::High, Confidence::High, format!("pod was evicted by the kubelet ({what} pressure on its node)"))
            .explain("The kubelet stopped the pod to reclaim a resource the node was running out of. Its controller (if any) creates a replacement; the evicted pod object stays until deleted.")
            .evidence(Source::Status, format!("status.reason=Evicted: {}", truncate(message, 300)))
            .fix(format!("{fix} Delete the evicted pod object once understood."))
            .docs(docs::EVICTION);
        out.push(diagnose_node(f, "see the node's pressure conditions"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::pod_fixture;

    fn run(ev: &PodEvidence) -> Vec<Finding> {
        let mut out = Vec::new();
        check(ev, &mut out);
        out
    }

    #[test]
    fn stuck_with_finalizer_on_dead_node() {
        let out = run(&pod_fixture("pods/terminating-stuck.yaml"));
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.id, "pod.terminating.stuck");
        assert!(f.title.contains("25m"), "{}", f.title);
        assert!(f.fix.contains("finalizers"));
        assert!(
            f.evidence
                .iter()
                .any(|e| e.text == "node node-2 is not Ready")
        );
        assert_eq!(f.next[0].tool, "diagnose_node");
    }

    #[test]
    fn recently_deleted_pod_is_not_stuck() {
        let mut ev = pod_fixture("pods/terminating-stuck.yaml");
        ev.now = "2026-11-14T11:37:00Z".parse().unwrap();
        assert!(run(&ev).is_empty());
    }

    #[test]
    fn eviction_names_the_resource() {
        let out = run(&pod_fixture("pods/evicted.yaml"));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "pod.evicted");
        assert!(out[0].title.contains("memory pressure"), "{}", out[0].title);
    }

    #[test]
    fn live_pods_are_ignored() {
        for f in ["pods/healthy.yaml", "pods/crashloop-exit1.yaml"] {
            assert!(run(&pod_fixture(f)).is_empty(), "{f}");
        }
    }
}
