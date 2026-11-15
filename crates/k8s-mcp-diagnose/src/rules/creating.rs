//! Pods stuck in ContainerCreating (PROPOSAL §9.2): volume attach/mount failures, CNI/IP
//! allocation failures and other sandbox errors. FailedMount events naming a missing
//! ConfigMap, Secret, key or ServiceAccount are left to [`super::config`].

use std::sync::LazyLock;

use k8s_mcp_core::finding::{Confidence, Finding, RuleMeta, Severity, Source};
use k8s_mcp_core::text::age;
use k8s_openapi::api::core::v1::Event;
use regex::Regex;
use serde_json::json;

use super::config::parse_issue;
use super::{
    all_containers, docs, events_with, latest, msg, phase, pod_events_args, pod_ref, quote_event,
    re, resource_args, rule_docs, secs_since, waiting_reason,
};
use crate::evidence::PodEvidence;

/// Rules emitted by this module.
pub const RULES: &[RuleMeta] = &[
    RuleMeta {
        id: "pod.creating.volume",
        title: "A volume cannot be attached or mounted, so the pod cannot start",
        docs: docs::PV,
    },
    RuleMeta {
        id: "pod.creating.cni",
        title: "The network plugin cannot set up the pod's network (CNI / IP exhaustion)",
        docs: docs::NETWORK,
    },
    RuleMeta {
        id: "pod.creating.sandbox",
        title: "The pod sandbox cannot be created (container runtime problem)",
        docs: docs::DEBUG_PODS,
    },
];

/// ContainerCreating for longer than this, with no explaining event, is reported.
const STUCK_AFTER_SECS: i64 = 300;

/// Event reasons for volume attach/mount failures.
const VOLUME: [&str; 3] = ["FailedAttachVolume", "FailedMount", "FailedMapVolume"];

static CNI: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)setup network|set up network|cni|assign an ip|ip address|ipam|networkplugin|network plugin",
    )
});

/// Check a scheduled pod whose containers are still being created.
pub fn check(ev: &PodEvidence, out: &mut Vec<Finding>) {
    // No container (init or main) has got past creation yet.
    let creating = all_containers(&ev.pod).iter().all(|(_, st)| {
        st.is_none_or(|s| {
            matches!(
                waiting_reason(s),
                Some("ContainerCreating" | "PodInitializing")
            )
        })
    });
    let Some(node) = ev.pod.spec.as_ref().and_then(|s| s.node_name.as_deref()) else {
        return;
    };
    if phase(&ev.pod) != "Pending" || !creating {
        return;
    }
    // A missing ConfigMap/Secret behind a FailedMount is config's finding.
    if events_with(&ev.events, &["FailedMount"]).any(|e| parse_issue(msg(e)).is_some()) {
        return;
    }
    let (_, ns) = pod_ref(&ev.pod);
    let node_next = |f: Finding, why: &str| f.next("diagnose_node", json!({ "name": node }), why);

    let volume: Vec<&Event> = events_with(&ev.events, &VOLUME).collect();
    if !volume.is_empty() {
        let multi = volume.iter().any(|e| msg(e).contains("Multi-Attach"));
        let (title, fix) = if multi {
            (
                "a ReadWriteOnce volume is still attached to another node (Multi-Attach)",
                "The volume is still attached to the node of the previous pod. It detaches once that pod is gone (check for a pod stuck terminating on the old node); the attach/detach controller force-detaches after about 6 minutes if that node is down. Use a Deployment strategy of Recreate (or a StatefulSet) for RWO volumes.",
            )
        } else {
            (
                "a volume cannot be attached or mounted",
                "FailedAttachVolume points at the attach step (cloud permissions, per-node attach limits, a zone mismatch); FailedMount at the node (filesystem errors, an unreachable NFS server, a CSI node plugin not running on the node). Check the PVC and the CSI driver pods; a dedicated diagnose_pvc tool arrives in v0.2.",
            )
        };
        let mut f = Finding::new(
            "pod.creating.volume",
            Severity::Critical,
            Confidence::High,
            title,
        )
        .explain(
            "The kubelet cannot start the containers until every volume is attached and mounted.",
        )
        .fix(fix)
        .docs(rule_docs(RULES, "pod.creating.volume"));
        for r in VOLUME {
            if let Some(e) = latest(events_with(&ev.events, &[r])) {
                f = f.evidence(Source::Event, quote_event(e, ev.now));
            }
        }
        for claim in ev
            .pod
            .spec
            .iter()
            .flat_map(|s| s.volumes.iter().flatten())
            .filter_map(|v| v.persistent_volume_claim.as_ref())
        {
            let name = &claim.claim_name;
            f = f
                .evidence(Source::Spec, format!("volume uses PVC {name}"))
                .next(
                    "get_resource",
                    resource_args("PersistentVolumeClaim", name, ns),
                    &format!("see PVC {name}'s binding and events"),
                );
        }
        out.push(node_next(f, "check the node's CSI plugin and attach state"));
        return;
    }

    let sandbox: Vec<&Event> = events_with(&ev.events, &["FailedCreatePodSandBox"]).collect();
    if let Some(e) = latest(sandbox.iter().copied()) {
        let f = if CNI.is_match(msg(e)) {
            Finding::new("pod.creating.cni", Severity::Critical, Confidence::High, "the network plugin cannot give the pod an IP / network")
                .explain("The container runtime asked the CNI plugin to set up the pod's network and it failed, so the sandbox (and every container) cannot start.")
                .fix("On EKS with the VPC CNI, `failed to assign an IP address` means the subnet or the node's ENIs are out of IPs: enable prefix delegation, add subnets or use larger instances. On AKS with Azure CNI the subnet is exhausted. Otherwise check the CNI DaemonSet pod on this node (aws-node, calico-node, cilium, kindnet...) for errors.")
                .docs(rule_docs(RULES, "pod.creating.cni"))
        } else {
            Finding::new("pod.creating.sandbox", Severity::Critical, Confidence::High, "the container runtime cannot create the pod sandbox")
                .explain("Creating the pod sandbox (the pause container and its namespaces) failed, so no container can start. This is a node-level problem, not an application one.")
                .fix("Check the node: container runtime health, disk space, cgroup errors and the runtime's own logs. Cordon and replace the node if the runtime is broken.")
                .docs(rule_docs(RULES, "pod.creating.sandbox"))
        };
        out.push(node_next(
            f.evidence(Source::Event, quote_event(e, ev.now)),
            "check the node's runtime and network plugin",
        ));
        return;
    }

    // Still creating with no explaining event: only worth reporting if it has been a while
    // and no image is still being pulled.
    let since = ev
        .pod
        .status
        .as_ref()
        .and_then(|s| s.start_time.as_ref())
        .or(ev.pod.metadata.creation_timestamp.as_ref())
        .map(|t| t.0);
    let pulling = events_with(&ev.events, &["Pulling"]).next().is_some()
        && events_with(&ev.events, &["Pulled"]).next().is_none();
    if let Some(since) = since
        && secs_since(ev.now, since) > STUCK_AFTER_SECS
        && !pulling
    {
        let f = Finding::new("pod.creating.sandbox", Severity::Critical, Confidence::Low, format!("pod has been in ContainerCreating for {} with no error event", age(ev.now, since)))
            .explain("The pod is on a node but its containers have not been created, and no event explains why. The kubelet or container runtime on the node is likely unhealthy or overloaded.")
            .evidence(Source::Status, format!("containers waiting in ContainerCreating since {} ago", age(ev.now, since)))
            .fix("Check the node (diagnose_node): kubelet and runtime health, disk and PID pressure. If other pods on the node are stuck too, cordon and replace it.")
            .docs(rule_docs(RULES, "pod.creating.sandbox"))
            .next("list_events", pod_events_args(&ev.pod), "look for events the summary missed");
        out.push(node_next(f, "check the kubelet and runtime on the node"));
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

    fn ids(fixture: &str) -> Vec<String> {
        run(&pod_fixture(fixture))
            .into_iter()
            .map(|f| f.id)
            .collect()
    }

    #[test]
    fn multi_attach_is_volume() {
        let out = run(&pod_fixture("pods/creating-volume.yaml"));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "pod.creating.volume");
        assert!(out[0].title.contains("Multi-Attach"));
        assert!(
            out[0]
                .evidence
                .iter()
                .any(|e| e.text == "volume uses PVC data")
        );
    }

    #[test]
    fn ip_exhaustion_is_cni() {
        assert_eq!(ids("pods/creating-cni.yaml"), ["pod.creating.cni"]);
    }

    #[test]
    fn other_sandbox_errors_and_silent_stalls() {
        let mut ev = pod_fixture("pods/creating-cni.yaml");
        ev.events[0].message = Some("Failed to create pod sandbox: rpc error: code = DeadlineExceeded desc = context deadline exceeded".into());
        let out = run(&ev);
        assert_eq!(
            (out[0].id.as_str(), out[0].confidence),
            ("pod.creating.sandbox", Confidence::High)
        );

        ev.events.clear();
        let out = run(&ev);
        assert_eq!(
            (out[0].id.as_str(), out[0].confidence),
            ("pod.creating.sandbox", Confidence::Low)
        );

        ev.now = "2026-11-14T11:51:00Z".parse().unwrap();
        assert!(run(&ev).is_empty(), "not stuck yet");
    }

    #[test]
    fn config_mount_errors_and_other_states_are_ignored() {
        for f in [
            "pods/config-missing-secret-volume.yaml",
            "pods/config-missing-serviceaccount.yaml",
            "pods/healthy.yaml",
            "pods/image-not-found.yaml",
            "pods/pending-pvc-unbound.yaml",
        ] {
            assert!(ids(f).is_empty(), "{f}");
        }
    }
}
