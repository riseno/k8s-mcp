//! Pending, unscheduled pods (PROPOSAL §9.2), from the scheduler's `FailedScheduling`
//! message (parsed by [`crate::parse::failed_scheduling`]) or the `PodScheduled=False`
//! condition.
//!
//! One finding per cause, the cause that rejected the most nodes first. `pod.pending.quota`
//! is emitted by [`super::rollout`], because a quota stops the pod from being created at all.

use std::cmp::Reverse;
use std::collections::BTreeSet;

use k8s_mcp_core::finding::{Confidence, Finding, RuleMeta, Severity, Source};
use k8s_mcp_core::text::truncate;
use k8s_openapi::api::core::v1::Node;
use serde_json::json;

use super::{
    allocatable, dns_name, docs, events_with, fmt_quantity, latest, msg, node_name, phase,
    pod_condition, pod_events_args, pod_ref, pod_requests, quote_event, resource_args, rule_docs,
    secs_since,
};
use crate::evidence::{PodEvidence, RefKind};
use crate::parse::{SchedulingReason, failed_scheduling};

/// Rules emitted by this module.
pub const RULES: &[RuleMeta] = &[
    RuleMeta {
        id: "pod.pending.insufficient_resources",
        title: "No node has enough free CPU/memory/other resources for the pod",
        docs: docs::RESOURCES,
    },
    RuleMeta {
        id: "pod.pending.taints",
        title: "Nodes carry taints the pod does not tolerate (or are cordoned)",
        docs: docs::TAINTS,
    },
    RuleMeta {
        id: "pod.pending.node_selector_affinity",
        title: "No node matches the pod's nodeSelector or affinity rules",
        docs: docs::AFFINITY,
    },
    RuleMeta {
        id: "pod.pending.topology_spread",
        title: "Topology spread constraints cannot be satisfied",
        docs: docs::TOPOLOGY,
    },
    RuleMeta {
        id: "pod.pending.pvc_unbound",
        title: "A PersistentVolumeClaim used by the pod is not bound",
        docs: docs::PV,
    },
    RuleMeta {
        id: "pod.pending.volume_node_affinity",
        title: "The pod's volumes are pinned to nodes (zones) it cannot use",
        docs: docs::PV,
    },
    RuleMeta {
        id: "pod.pending.too_many_pods",
        title: "Nodes have reached their maximum pod count",
        docs: docs::RESOURCES,
    },
    RuleMeta {
        id: "pod.pending.no_scheduler",
        title: "No scheduler has picked up the pod",
        docs: docs::AFFINITY,
    },
    RuleMeta {
        id: "pod.pending.unschedulable",
        title: "The scheduler cannot place the pod (unclassified reason)",
        docs: docs::AFFINITY,
    },
];

/// How long an untouched pod may wait before `pod.pending.no_scheduler` fires.
const NO_SCHEDULER_AFTER_SECS: i64 = 120;
/// At most this many nodes are quoted per finding.
const MAX_NODES: usize = 5;

/// Check an unscheduled Pending pod.
pub fn check(ev: &PodEvidence, out: &mut Vec<Finding>) {
    let scheduled = ev
        .pod
        .spec
        .as_ref()
        .and_then(|s| s.node_name.as_ref())
        .is_some();
    if phase(&ev.pod) != "Pending" || scheduled {
        return;
    }
    let event = latest(events_with(&ev.events, &["FailedScheduling"]));
    let cond = pod_condition(&ev.pod, "PodScheduled").filter(|c| c.status == "False");
    let (message, quoted) = match (event, cond) {
        (Some(e), _) => (msg(e), (Source::Event, quote_event(e, ev.now))),
        (None, Some(c)) => {
            let m = c.message.as_deref().unwrap_or("");
            let text = format!(
                "condition PodScheduled=False reason={}: {}",
                c.reason.as_deref().unwrap_or("-"),
                truncate(m, 300)
            );
            (m, (Source::Status, text))
        }
        (None, None) => {
            no_scheduler(ev, out);
            return;
        }
    };

    let parsed = failed_scheduling(message);
    let total = parsed.as_ref().and_then(|p| p.nodes);
    let mut causes: Vec<(&str, u32)> = Vec::new();
    let mut short: BTreeSet<&str> = BTreeSet::new();
    for (n, r) in parsed.iter().flat_map(|p| &p.reasons) {
        let id = match r {
            SchedulingReason::Insufficient(res) => {
                short.insert(res);
                "pod.pending.insufficient_resources"
            }
            SchedulingReason::TooManyPods => "pod.pending.too_many_pods",
            SchedulingReason::Taint | SchedulingReason::Cordoned => "pod.pending.taints",
            SchedulingReason::Affinity => "pod.pending.node_selector_affinity",
            SchedulingReason::TopologySpread => "pod.pending.topology_spread",
            SchedulingReason::UnboundPvc => "pod.pending.pvc_unbound",
            SchedulingReason::VolumeNodeAffinity => "pod.pending.volume_node_affinity",
            SchedulingReason::Other => continue,
        };
        // Pod-level reasons (no count) block every node.
        let n = n.unwrap_or(u32::MAX);
        match causes.iter_mut().find(|(i, _)| *i == id) {
            Some((_, c)) => *c = c.saturating_add(n),
            None => causes.push((id, n)),
        }
    }
    causes.sort_by_key(|(_, n)| Reverse(*n));

    if causes.is_empty() {
        out.push(
            Finding::new("pod.pending.unschedulable", Severity::Critical, Confidence::Medium, "the scheduler cannot place the pod")
                .explain("The scheduler tried every node and rejected them all, for a reason this engine does not classify. The scheduler's message names the failing filter.")
                .evidence(quoted.0, quoted.1)
                .fix("Read the scheduler message: common unclassified causes are host ports already in use, per-node volume attach limits, scheduling gates and scheduler plugin errors. Adjust the pod or the nodes accordingly.")
                .docs(rule_docs(RULES, "pod.pending.unschedulable"))
                .next("list_events", pod_events_args(&ev.pod), "see the scheduler's attempts"),
        );
        return;
    }
    for (id, n) in causes {
        let mut f = cause(ev, id, &short);
        if n != u32::MAX {
            let of = total.map(|t| format!(" of {t}")).unwrap_or_default();
            f.explanation = format!("{} This rejected {n}{of} node(s).", f.explanation);
        }
        out.push(
            f.evidence(quoted.0, quoted.1.clone())
                .docs(rule_docs(RULES, id)),
        );
    }
}

/// Finding for one scheduling cause (evidence from the spec and the node list).
fn cause(ev: &PodEvidence, id: &str, short: &BTreeSet<&str>) -> Finding {
    let nodes = ev.nodes.as_deref();
    let base = |title: String, explanation: &str, fix: &str| {
        Finding::new(id, Severity::Critical, Confidence::High, title)
            .explain(explanation)
            .fix(fix)
    };
    let mut f = match id {
        "pod.pending.insufficient_resources" => return insufficient(ev, short),
        "pod.pending.too_many_pods" => {
            let mut f = base(
                "nodes have reached their maximum pod count".into(),
                "Every candidate node already runs as many pods as its kubelet allows (allocatable `pods`).",
                "Add nodes, or raise the kubelet's maxPods. On EKS with the VPC CNI the limit follows the instance's ENI/IP capacity: enable prefix delegation or use larger instances.",
            );
            for n in nodes.into_iter().flatten().take(MAX_NODES) {
                if let Some(p) = allocatable(n).get("pods") {
                    f = f.evidence(
                        Source::Related,
                        format!("node {} allows {p} pods", node_name(n)),
                    );
                }
            }
            f
        }
        "pod.pending.taints" => taints(
            ev,
            base(
                "nodes are tainted or cordoned and the pod tolerates none of them".into(),
                "Nodes with a NoSchedule/NoExecute taint only accept pods that tolerate it, and cordoned nodes accept no new pods.",
                "Add a matching toleration to the pod only if it should run on those nodes, remove the taint (`kubectl taint nodes <node> <key>-`), or uncordon the node (`kubectl uncordon <node>`). A control-plane taint as the only reason means there are no worker nodes.",
            ),
        ),
        "pod.pending.node_selector_affinity" => selectors(
            ev,
            base(
                "no node matches the pod's nodeSelector or affinity rules".into(),
                "The pod may only run on nodes with specific labels (nodeSelector or required node affinity), or next to/away from other pods (pod affinity/anti-affinity), and no node qualifies.",
                "Label a node to match (`kubectl label node <node> <key>=<value>`) or fix the selector/affinity in the pod template. Pod anti-affinity needs at least as many eligible nodes as replicas.",
            ),
        ),
        "pod.pending.topology_spread" => spread(
            ev,
            base(
                "topology spread constraints cannot be satisfied".into(),
                "A constraint with whenUnsatisfiable: DoNotSchedule would exceed maxSkew in every eligible domain, usually because there are too few zones/nodes or some nodes lack the topologyKey label.",
                "Add nodes in more domains, raise maxSkew, or use whenUnsatisfiable: ScheduleAnyway. Nodes without the topologyKey label are not eligible at all.",
            ),
        ),
        "pod.pending.pvc_unbound" => claims(
            ev,
            base(
                "the pod waits for a PersistentVolumeClaim that is not bound".into(),
                "The pod uses a PVC that has no volume yet (or does not exist), and the scheduler will not place a pod whose immediate-binding claims are unbound.",
                "Check the PVC with diagnose_pvc: its StorageClass must exist and have a working provisioner, or a matching PV must exist for static provisioning.",
            ),
        ),
        _ => {
            let mut f = claims(
                ev,
                base(
                    "the pod's volumes are pinned to nodes (zones) it cannot use".into(),
                    "A bound PersistentVolume has node affinity (typically a zone) and no node in that zone can take the pod.",
                    "Use a StorageClass with volumeBindingMode: WaitForFirstConsumer so volumes are created where the pod lands, or add nodes in the volume's zone. The PV's nodeAffinity shows its zone.",
                ),
            );
            let zones: BTreeSet<&str> = nodes
                .into_iter()
                .flatten()
                .filter_map(|n| label(n, "topology.kubernetes.io/zone"))
                .collect();
            if !zones.is_empty() {
                f = f.evidence(
                    Source::Related,
                    format!(
                        "node zones: {}",
                        zones.into_iter().collect::<Vec<_>>().join(", ")
                    ),
                );
            }
            f
        }
    };
    if nodes.is_none() {
        f = f.evidence(Source::Unavailable, "the node list could not be read");
    }
    f.next(
        "list_events",
        pod_events_args(&ev.pod),
        "see the scheduler's attempts",
    )
}

fn insufficient(ev: &PodEvidence, short: &BTreeSet<&str>) -> Finding {
    let requests = pod_requests(&ev.pod);
    let mut named = Vec::new();
    let mut never = Vec::new();
    let mut evidence = Vec::new();
    // Only resources the pod actually requests: their names come from the spec, not the message.
    for (res, &want) in requests.iter().filter(|(r, _)| short.contains(r.as_str())) {
        named.push(res.as_str());
        evidence.push((
            Source::Spec,
            format!("pod requests {res}={}", fmt_quantity(res, want)),
        ));
        let Some(nodes) = ev.nodes.as_deref() else {
            continue;
        };
        let best = nodes
            .iter()
            .map(|n| (allocatable(n).get(res).copied().unwrap_or(0), node_name(n)))
            .max_by_key(|(v, _)| *v);
        match best {
            Some((max, node)) => {
                evidence.push((
                    Source::Related,
                    format!(
                        "largest allocatable {res} is {} (node {node})",
                        fmt_quantity(res, max)
                    ),
                ));
                if want > max {
                    never.push(res.as_str());
                }
            }
            None => evidence.push((Source::Related, "the cluster has no nodes".to_owned())),
        }
    }
    let what = if named.is_empty() {
        "resources".to_owned()
    } else {
        named.join("/")
    };
    let mut f = if never.is_empty() {
        Finding::new("pod.pending.insufficient_resources", Severity::Critical, Confidence::High, format!("no node has enough free {what} for the pod"))
            .explain("Nodes that could hold the pod are full: requests of the pods already there leave too little room. The pod is placed once capacity frees up or a node is added.")
            .fix("Free capacity (right-size or scale down other workloads; compare requests with real usage via `top`), add nodes, or check why the cluster autoscaler/Karpenter is not adding them (its events and NodePool limits; an autoscaling_status tool arrives in v0.2). Lowering this pod's requests also works if they are oversized.")
    } else {
        let never = never.join("/");
        Finding::new("pod.pending.insufficient_resources", Severity::Critical, Confidence::High, format!("pod requests more {never} than any node can offer: it can never fit"))
            .explain("The pod's request exceeds the allocatable capacity of the largest node, so no amount of waiting or evicting will place it. Allocatable is below the machine size because of system reservations.")
            .fix(format!("Lower resources.requests.{never} below the largest node's allocatable, or add a node type large enough. An autoscaler only helps if one of its node groups offers such machines (an autoscaling_status tool arrives in v0.2)."))
    };
    for (s, t) in evidence {
        f = f.evidence(s, t);
    }
    if ev.nodes.is_none() {
        f = f.evidence(
            Source::Unavailable,
            "the node list could not be read, so it is unknown whether the pod could ever fit",
        );
    }
    f.next(
        "top",
        json!({"target": "nodes"}),
        "see how full each node is",
    )
}

fn taints(ev: &PodEvidence, mut f: Finding) -> Finding {
    for n in ev.nodes.iter().flatten().take(MAX_NODES) {
        let spec = n.spec.as_ref();
        if spec.and_then(|s| s.unschedulable) == Some(true) {
            f = f.evidence(
                Source::Related,
                format!("node {} is cordoned (spec.unschedulable)", node_name(n)),
            );
        }
        let list: Vec<String> = spec
            .and_then(|s| s.taints.as_ref())
            .into_iter()
            .flatten()
            .filter(|t| t.effect != "PreferNoSchedule")
            .map(|t| match t.value.as_deref().filter(|v| !v.is_empty()) {
                Some(v) => format!("{}={v}:{}", t.key, t.effect),
                None => format!("{}:{}", t.key, t.effect),
            })
            .collect();
        if !list.is_empty() {
            f = f.evidence(
                Source::Related,
                format!("node {} taints: {}", node_name(n), list.join(", ")),
            );
        }
    }
    let tolerations: Vec<String> = ev
        .pod
        .spec
        .as_ref()
        .and_then(|s| s.tolerations.as_ref())
        .into_iter()
        .flatten()
        .map(|t| {
            let key = t.key.as_deref().unwrap_or("*");
            let value = t
                .value
                .as_deref()
                .map(|v| format!("={v}"))
                .unwrap_or_default();
            format!("{key}{value}:{}", t.effect.as_deref().unwrap_or("*"))
        })
        .collect();
    let tolerations = if tolerations.is_empty() {
        "none".to_owned()
    } else {
        tolerations.join(", ")
    };
    f.evidence(
        Source::Spec,
        format!("pod tolerations: {}", truncate(&tolerations, 300)),
    )
}

fn selectors(ev: &PodEvidence, mut f: Finding) -> Finding {
    let spec = ev.pod.spec.as_ref();
    let nodes = ev.nodes.as_deref();
    for (k, v) in spec
        .and_then(|s| s.node_selector.as_ref())
        .into_iter()
        .flatten()
    {
        f = f.evidence(Source::Spec, format!("nodeSelector {k}={v}"));
        if let Some(nodes) = nodes {
            let matching = nodes
                .iter()
                .filter(|n| label(n, k) == Some(v.as_str()))
                .count();
            f = f.evidence(
                Source::Related,
                format!("{matching} of {} node(s) have label {k}={v}", nodes.len()),
            );
        }
    }
    let affinity = spec.and_then(|s| s.affinity.as_ref());
    if affinity
        .and_then(|a| a.node_affinity.as_ref())
        .is_some_and(|n| {
            n.required_during_scheduling_ignored_during_execution
                .is_some()
        })
    {
        f = f.evidence(Source::Spec, "required node affinity is set");
    }
    if affinity.is_some_and(|a| a.pod_affinity.is_some() || a.pod_anti_affinity.is_some()) {
        f = f.evidence(Source::Spec, "pod affinity/anti-affinity rules are set");
    }
    f
}

fn spread(ev: &PodEvidence, mut f: Finding) -> Finding {
    let constraints = ev
        .pod
        .spec
        .as_ref()
        .and_then(|s| s.topology_spread_constraints.as_ref())
        .into_iter()
        .flatten()
        .filter(|c| c.when_unsatisfiable == "DoNotSchedule");
    for c in constraints {
        let key = &c.topology_key;
        f = f.evidence(Source::Spec, format!("topologySpreadConstraint topologyKey={key} maxSkew={} whenUnsatisfiable=DoNotSchedule", c.max_skew));
        if let Some(nodes) = ev.nodes.as_deref() {
            let domains: BTreeSet<&str> = nodes.iter().filter_map(|n| label(n, key)).collect();
            let missing = nodes.iter().filter(|n| label(n, key).is_none()).count();
            f = f.evidence(
                Source::Related,
                format!(
                    "nodes span {} value(s) of {key}; {missing} node(s) lack the label",
                    domains.len()
                ),
            );
        }
    }
    f
}

fn claims(ev: &PodEvidence, mut f: Finding) -> Finding {
    let (_, ns) = pod_ref(&ev.pod);
    let names: Vec<&str> = ev
        .pod
        .spec
        .iter()
        .flat_map(|s| s.volumes.iter().flatten())
        .filter_map(|v| v.persistent_volume_claim.as_ref())
        .map(|c| c.claim_name.as_str())
        .collect();
    if let [only] = names.as_slice() {
        f.title = format!("{} ({only:?})", f.title);
    }
    for name in names {
        if let Some(pvc) = ev
            .pvcs
            .iter()
            .find(|p| p.metadata.name.as_deref() == Some(name))
        {
            let phase = pvc
                .status
                .as_ref()
                .and_then(|s| s.phase.as_deref())
                .unwrap_or("Unknown");
            let class = pvc
                .spec
                .as_ref()
                .and_then(|s| s.storage_class_name.as_deref())
                .unwrap_or("(default)");
            f = f
                .evidence(
                    Source::Related,
                    format!("PVC {name} phase={phase} storageClassName={class}"),
                )
                .next(
                    "diagnose_pvc",
                    json!({"name": name, "namespace": ns}),
                    &format!("root-cause PVC {name}"),
                );
            continue;
        } else if ev.refs.iter().any(|r| {
            r.kind == RefKind::PersistentVolumeClaim && r.name == name && r.exists == Some(false)
        }) {
            f = f.evidence(Source::Related, format!("PVC {name} does not exist"));
        }
        f = f.next(
            "get_resource",
            resource_args("PersistentVolumeClaim", name, ns),
            &format!("see PVC {name}'s status and provisioning events"),
        );
    }
    f
}

fn label<'a>(n: &'a Node, key: &str) -> Option<&'a str> {
    n.metadata.labels.as_ref()?.get(key).map(String::as_str)
}

/// A Pending pod no scheduler has touched (no events, no PodScheduled condition).
fn no_scheduler(ev: &PodEvidence, out: &mut Vec<Finding>) {
    let created = ev.pod.metadata.creation_timestamp.as_ref().map(|t| t.0);
    if created.is_none_or(|t| secs_since(ev.now, t) < NO_SCHEDULER_AFTER_SECS) {
        return;
    }
    let scheduler = ev
        .pod
        .spec
        .as_ref()
        .and_then(|s| s.scheduler_name.as_deref())
        .unwrap_or("default-scheduler");
    let mut f = if scheduler == "default-scheduler" {
        Finding::new("pod.pending.no_scheduler", Severity::Critical, Confidence::Low, "no scheduler has picked up the pod (is kube-scheduler running?)")
            .explain("The pod has no node, no scheduling events and no PodScheduled condition, so the default scheduler never considered it. On self-managed clusters kube-scheduler may be down or unable to reach the API server.")
            .fix("Check the kube-scheduler pods in kube-system (managed clusters run it for you: check the provider's control-plane health).")
            .next("list_resources", json!({"kind": "Pod", "namespace": "kube-system", "label_selector": "component=kube-scheduler"}), "check that kube-scheduler is running")
    } else {
        let shown = if dns_name(scheduler) {
            format!("{scheduler:?}")
        } else {
            "set in spec.schedulerName".to_owned()
        };
        Finding::new("pod.pending.no_scheduler", Severity::Critical, Confidence::Medium, format!("no scheduler named {shown} has picked up the pod"))
            .explain("The pod asks for a non-default scheduler, and nothing has scheduled it or reported why. That scheduler is probably not installed, not running, or uses a different name.")
            .fix("Install/start that scheduler, fix spec.schedulerName, or remove it to use the default scheduler.")
    };
    f = f.evidence(
        Source::Spec,
        format!("spec.schedulerName={}", truncate(scheduler, 100)),
    );
    if ev.unavailable.iter().any(|u| u.what.contains("events")) {
        f.confidence = Confidence::Low;
        f = f.evidence(Source::Unavailable, "pod events could not be read");
    }
    out.push(f.docs(rule_docs(RULES, "pod.pending.no_scheduler")));
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

    fn ids(ev: &PodEvidence) -> Vec<String> {
        run(ev).into_iter().map(|f| f.id).collect()
    }

    #[test]
    fn huge_cpu_request_can_never_fit() {
        let out = run(&pod_fixture("pods/pending-insufficient-cpu.yaml"));
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.id, "pod.pending.insufficient_resources");
        assert!(
            f.title.contains("can never fit") && f.title.contains("cpu"),
            "{}",
            f.title
        );
        let texts: Vec<_> = f.evidence.iter().map(|e| e.text.as_str()).collect();
        assert!(texts.contains(&"pod requests cpu=64"), "{texts:?}");
        assert!(
            texts
                .iter()
                .any(|t| t.starts_with("largest allocatable cpu is 4 (node")),
            "{texts:?}"
        );
        assert!(f.next.iter().all(|n| n.tool != "autoscaling_status"));
    }

    #[test]
    fn request_that_fits_a_node_is_not_never_fit() {
        let mut ev = pod_fixture("pods/pending-insufficient-cpu.yaml");
        let c = &mut ev.pod.spec.as_mut().unwrap().containers[0];
        c.resources
            .as_mut()
            .unwrap()
            .requests
            .as_mut()
            .unwrap()
            .insert(
                "cpu".into(),
                k8s_openapi::apimachinery::pkg::api::resource::Quantity("2".into()),
            );
        let f = &run(&ev)[0];
        assert!(
            f.title.starts_with("no node has enough free cpu"),
            "{}",
            f.title
        );
    }

    #[test]
    fn node_selector_mismatch_counts_matching_nodes() {
        let out = run(&pod_fixture("pods/pending-node-selector.yaml"));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "pod.pending.node_selector_affinity");
        assert!(
            out[0]
                .evidence
                .iter()
                .any(|e| e.text == "0 of 1 node(s) have label disktype=ssd")
        );
    }

    #[test]
    fn unbound_pvc_names_the_claim() {
        let ev = pod_fixture("pods/pending-pvc-unbound.yaml");
        let out = run(&ev);
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.id, "pod.pending.pvc_unbound");
        assert!(f.title.contains("\"data\""), "{}", f.title);
        assert!(
            f.evidence
                .iter()
                .any(|e| e.text == "PVC data phase=Pending storageClassName=does-not-exist")
        );
        // Same result from the PodScheduled condition alone.
        let mut ev = ev;
        ev.events.clear();
        let f = &run(&ev)[0];
        assert_eq!(f.id, "pod.pending.pvc_unbound");
        assert_eq!(f.evidence.last().unwrap().source, Source::Status);
    }

    #[test]
    fn mixed_reasons_rank_by_node_count() {
        let ev = pod_fixture("pods/pending-taint.yaml");
        assert_eq!(
            ids(&ev),
            ["pod.pending.insufficient_resources", "pod.pending.taints"]
        );
        let taint = &run(&ev)[1];
        assert!(
            taint
                .evidence
                .iter()
                .any(|e| e.text == "node cp-1 taints: node-role.kubernetes.io/master:NoSchedule")
        );
        assert!(
            taint
                .evidence
                .iter()
                .any(|e| e.text == "pod tolerations: none")
        );
    }

    #[test]
    fn other_scheduler_messages() {
        let base = pod_fixture("pods/pending-node-selector.yaml");
        let cases = [
            (
                "0/3 nodes are available: 3 node(s) didn't match pod topology spread constraints.",
                "pod.pending.topology_spread",
            ),
            (
                "0/3 nodes are available: 3 node(s) had volume node affinity conflict.",
                "pod.pending.volume_node_affinity",
            ),
            (
                "0/2 nodes are available: 2 Too many pods.",
                "pod.pending.too_many_pods",
            ),
            (
                "0/2 nodes are available: 2 node(s) didn't have free ports for the requested pod ports.",
                "pod.pending.unschedulable",
            ),
        ];
        for (message, want) in cases {
            let mut ev = base.clone();
            ev.events[0].message = Some(message.into());
            assert_eq!(ids(&ev), [want], "{message}");
        }
    }

    #[test]
    fn custom_scheduler_that_never_runs() {
        let out = run(&pod_fixture("pods/pending-no-scheduler.yaml"));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "pod.pending.no_scheduler");
        assert!(
            out[0].title.contains("\"batch-scheduler\""),
            "{}",
            out[0].title
        );
    }

    #[test]
    fn scheduled_or_young_pods_are_ignored() {
        for f in [
            "pods/healthy.yaml",
            "pods/image-not-found.yaml",
            "pods/config-missing-configmap.yaml",
        ] {
            assert!(run(&pod_fixture(f)).is_empty(), "{f}");
        }
        let mut ev = pod_fixture("pods/pending-no-scheduler.yaml");
        ev.pod.metadata.creation_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(ev.now));
        assert!(run(&ev).is_empty());
    }
}
