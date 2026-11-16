//! Node rules (PROPOSAL §9.2): readiness, pressure conditions, pod network, kubelet version
//! skew, cordon, overcommitted requests, system OOM events, and node-problem-detector (or
//! vendor agent) conditions.
//!
//! Non-standard conditions produce ids `node.npd.<condition_type_snake_case>` (for example
//! `node.npd.kernel_deadlock`), catalogued once as `node.npd.condition`. A condition type
//! ending in `Ready` (the EKS node monitoring agent style, e.g. `StorageReady`) is a problem
//! when not True; any other non-standard condition is a problem when True.

use k8s_mcp_core::finding::{Confidence, Evidence, Finding, RuleMeta, Severity, Source};
use k8s_mcp_core::text::{age, truncate};
use k8s_openapi::api::core::v1::NodeCondition;
use serde_json::json;

use super::{
    allocatable, count, docs, events_with, fmt_quantity, latest, node_name, parse_version, phase,
    pod_requests, quote_event,
};
use crate::evidence::NodeEvidence;

/// Rules emitted by this module.
pub const RULES: &[RuleMeta] = &[
    RuleMeta {
        id: "node.not_ready",
        title: "Node is NotReady or has stopped reporting",
        docs: docs::NODES,
    },
    RuleMeta {
        id: "node.pressure.memory",
        title: "Node is under memory pressure (the kubelet evicts pods)",
        docs: docs::EVICTION,
    },
    RuleMeta {
        id: "node.pressure.disk",
        title: "Node is under disk pressure (the kubelet evicts pods)",
        docs: docs::EVICTION,
    },
    RuleMeta {
        id: "node.pressure.pid",
        title: "Node is running out of process IDs",
        docs: docs::EVICTION,
    },
    RuleMeta {
        id: "node.network_unavailable",
        title: "Node's pod network is not configured",
        docs: docs::NETWORK,
    },
    RuleMeta {
        id: "node.version_skew",
        title: "Kubelet version is outside (or at the edge of) the supported skew",
        docs: docs::SKEW,
    },
    RuleMeta {
        id: "node.cordoned",
        title: "Node is cordoned: no new pods are scheduled there",
        docs: docs::NODES,
    },
    RuleMeta {
        id: "node.overcommitted",
        title: "Pod requests on the node exceed its allocatable resources",
        docs: docs::RESOURCES,
    },
    RuleMeta {
        id: "node.oom.system",
        title: "Node ran out of memory at the system level (SystemOOM)",
        docs: docs::MEMORY,
    },
    RuleMeta {
        id: "node.npd.condition",
        title: "Node reports a node-problem-detector or vendor problem condition (ids are node.npd.<condition_type>)",
        docs: docs::NODES,
    },
];

/// Conditions every kubelet reports; anything else is node-problem-detector or a vendor agent.
const STANDARD: &[&str] = &[
    "Ready",
    "MemoryPressure",
    "DiskPressure",
    "PIDPressure",
    "NetworkUnavailable",
];

/// node-problem-detector conditions that mean the node is unreliable (upstream NPD monitors).
const NPD_FAULTS: &[&str] = &[
    "KernelDeadlock",
    "ReadonlyFilesystem",
    "FrequentKubeletRestart",
    "FrequentDockerRestart",
    "FrequentContainerdRestart",
    "CorruptDockerOverlay2",
    "FrequentUnregisterNetDevice",
    "KubeletUnhealthy",
    "ContainerRuntimeUnhealthy",
];

/// Vendor conditions that record configuration and stay `True` on healthy nodes (GKE). Not
/// documented by the vendor: classified from their messages (riseno/k8s-mcp#5).
const INFORMATIONAL: &[&str] = &["SysctlChanged", "KubeletConfigChanged"];

/// Run every node check.
pub fn check(ev: &NodeEvidence, out: &mut Vec<Finding>) {
    let name = node_name(&ev.node);
    let conditions = ev
        .node
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_deref())
        .unwrap_or_default();
    for c in conditions {
        let t = c.type_.as_str();
        let healthy_when_true = t == "Ready" || (t.ends_with("Ready") && !STANDARD.contains(&t));
        if (c.status == "True") == healthy_when_true || INFORMATIONAL.contains(&t) {
            continue;
        }
        let f = match c.type_.as_str() {
            "Ready" => not_ready(ev, name, c),
            "MemoryPressure" => pressure(name, "node.pressure.memory", "memory", "The kubelet is evicting pods to reclaim memory. Find the biggest consumers (`top`), set memory requests close to real usage so the scheduler stops overpacking the node, and reserve memory for the system (kube-reserved/system-reserved)."),
            "DiskPressure" => pressure(name, "node.pressure.disk", "disk", "Free disk space: unused images (image garbage collection), container logs and emptyDir volumes. Give pods ephemeral-storage requests and limits, and grow the node's disk if it is simply too small."),
            "PIDPressure" => pressure(name, "node.pressure.pid", "process ID", "A process is leaking processes or threads. Find it on the node (`ps -eLf | wc -l` per container) and set a pod PID limit (kubelet podPidsLimit)."),
            "NetworkUnavailable" => Finding::new("node.network_unavailable", Severity::Critical, Confidence::High, format!("node {name} has no working pod network"))
                .explain("NetworkUnavailable=True means the network plugin (or the cloud's route controller) has not set up pod networking on this node, so pods there cannot communicate.")
                .fix("Check the CNI DaemonSet pod on this node (aws-node, calico-node, cilium, kube-flannel, kindnet...) and its logs; on route-based clusters check that the cloud route for the node's pod CIDR was created.")
                .docs(docs::NETWORK),
            _ => npd(name, c),
        };
        // Only conditions known to hurt pods may claim the node's pods are affected.
        let affects_pods = STANDARD.contains(&t) || NPD_FAULTS.contains(&t);
        out.push(with_pods(
            ev,
            f.evidence(Source::Status, describe(c, ev)),
            affects_pods,
        ));
    }
    if let Some(e) = latest(events_with(&ev.events, &["EvictionThresholdMet"]))
        && let Some(f) = out.iter_mut().find(|f| f.id.starts_with("node.pressure."))
    {
        f.evidence.push(Evidence {
            source: Source::Event,
            text: quote_event(e, ev.now),
        });
    }
    if ev.node.spec.as_ref().and_then(|s| s.unschedulable) == Some(true) {
        out.push(
            Finding::new("node.cordoned", Severity::Medium, Confidence::High, format!("node {name} is cordoned: no new pods are scheduled there"))
                .explain("spec.unschedulable is set (kubectl cordon or drain). Running pods stay, but the node adds no capacity for new ones.")
                .evidence(Source::Spec, "spec.unschedulable=true")
                .fix(format!("If maintenance is over, `kubectl uncordon {name}`. A cordon left behind by a failed drain or an unfinished autoscaler scale-down is a common cause of lost capacity."))
                .docs(docs::NODES),
        );
    }
    version_skew(ev, name, out);
    overcommitted(ev, name, out);
    let oom: Vec<_> = events_with(&ev.events, &["SystemOOM", "OOMKilling"]).collect();
    if let Some(e) = latest(oom.iter().copied()) {
        let n: i32 = oom.iter().map(|e| count(e)).sum();
        out.push(
            Finding::new("node.oom.system", Severity::High, Confidence::High, format!("node {name} ran out of memory at the system level ({n} OOM events)"))
                .explain("The kernel OOM killer fired on the node itself, outside a container's own limit. Pods without memory limits, or a node whose requests are far below real use, are the usual cause and victims.")
                .evidence(Source::Event, quote_event(e, ev.now))
                .fix("Set memory requests and limits on every pod scheduled here (pods without limits can take the whole node), keep requests close to real usage, and reserve memory for the system (system-reserved, eviction thresholds) so the kubelet evicts before the kernel kills.")
                .docs(docs::MEMORY)
                .next("top", json!({"target": "pods", "sort_by": "memory"}), "find the pods using the most memory"),
        );
    }
}

/// `condition Ready=Unknown reason=NodeStatusUnknown: ... (since 12m)`.
fn describe(c: &NodeCondition, ev: &NodeEvidence) -> String {
    let since = c
        .last_transition_time
        .as_ref()
        .map(|t| format!(" (since {} ago)", age(ev.now, t.0)))
        .unwrap_or_default();
    format!(
        "condition {}={} reason={}: {}{since}",
        c.type_,
        c.status,
        c.reason.as_deref().unwrap_or("-"),
        truncate(c.message.as_deref().unwrap_or(""), 300)
    )
}

/// Add the number of pods on the node and a `list_resources` call for them.
fn with_pods(ev: &NodeEvidence, f: Finding, affects_pods: bool) -> Finding {
    let name = node_name(&ev.node);
    let f = match &ev.pods {
        Some(pods) => {
            let live = pods
                .iter()
                .filter(|p| !matches!(phase(p), "Succeeded" | "Failed"))
                .count();
            let text = if affects_pods {
                format!("{live} pod(s) on this node are affected")
            } else {
                format!("{live} pod(s) run on this node")
            };
            f.evidence(Source::Related, text)
        }
        None => f,
    };
    f.next(
        "list_resources",
        json!({"kind": "Pod", "all_namespaces": true, "field_selector": format!("spec.nodeName={name}")}),
        "see the pods on this node",
    )
}

fn not_ready(ev: &NodeEvidence, name: &str, c: &NodeCondition) -> Finding {
    let unknown = c.status == "Unknown";
    let mut f = if unknown {
        Finding::new("node.not_ready", Severity::Critical, Confidence::High, format!("node {name} has stopped reporting (Ready=Unknown)"))
            .explain("The control plane has not heard from the node's kubelet within the grace period: the machine may be down or partitioned, or the kubelet crashed. Pods on it are evicted once their not-ready/unreachable toleration (default 5 minutes) runs out.")
            .fix("Check the machine in the cloud console or hypervisor (stopped, terminated, network-partitioned); on the node, check `systemctl status kubelet` and `journalctl -u kubelet`. Replace the node if it does not come back.")
    } else {
        Finding::new("node.not_ready", Severity::Critical, Confidence::High, format!("node {name} is NotReady"))
            .explain("The kubelet reports the node unhealthy, commonly because the container runtime is down, the network plugin is not ready, or the runtime's pod lifecycle checks (PLEG) are failing. The condition message says which.")
            .fix("Read the condition message, then on the node check `systemctl status kubelet containerd` and `journalctl -u kubelet`. If the network plugin is not ready, check the CNI DaemonSet pod on this node.")
    };
    if let Some(hb) = c.last_heartbeat_time.as_ref() {
        f = f.evidence(
            Source::Status,
            format!("last heartbeat {} ago", age(ev.now, hb.0)),
        );
    }
    let mut taints: Vec<&str> = ev
        .node
        .spec
        .as_ref()
        .and_then(|s| s.taints.as_ref())
        .into_iter()
        .flatten()
        .map(|t| t.key.as_str())
        .filter(|k| k.starts_with("node.kubernetes.io/"))
        .collect();
    taints.dedup(); // NoSchedule and NoExecute entries share a key
    if !taints.is_empty() {
        f = f.evidence(Source::Spec, format!("taints: {}", taints.join(", ")));
    }
    for e in events_with(
        &ev.events,
        &["NodeNotReady", "Rebooted", "NodeHasInsufficientMemory"],
    )
    .take(3)
    {
        f = f.evidence(Source::Event, quote_event(e, ev.now));
    }
    f.docs(docs::NODES).next(
        "list_events",
        json!({"involved_kind": "Node", "involved_name": name}),
        "see the node's recent events",
    )
}

fn pressure(name: &str, id: &str, what: &str, fix: &str) -> Finding {
    Finding::new(id, Severity::High, Confidence::High, format!("node {name} is under {what} pressure"))
        .explain(format!("The kubelet's {what} eviction threshold is crossed: it taints the node so no new pods land there and evicts pods to reclaim {what}."))
        .fix(fix)
        .docs(docs::EVICTION)
        .next("top", json!({"target": "nodes"}), "compare usage across nodes")
}

fn npd(name: &str, c: &NodeCondition) -> Finding {
    let id = format!("node.npd.{}", snake(&c.type_));
    let shown = if c.type_.chars().all(|ch| ch.is_ascii_alphanumeric()) {
        c.type_.clone()
    } else {
        snake(&c.type_)
    };
    if NPD_FAULTS.contains(&c.type_.as_str()) {
        return Finding::new(&id, Severity::High, Confidence::High, format!("node {name} reports problem condition {shown}"))
            .explain("node-problem-detector set this condition: kernel deadlocks, read-only filesystems and repeated kubelet or runtime restarts usually leave the node unreliable.")
            .fix(format!("Read the condition message and the node's system logs. If the problem persists, drain the node (`kubectl drain {name} --ignore-daemonsets`) and replace or reboot it."))
            .docs(docs::NODES);
    }
    Finding::new(&id, Severity::Medium, Confidence::Medium, format!("node {name} reports condition {shown}"))
        .explain("A node agent (node-problem-detector or a vendor agent) set a condition this rule set does not know. Vendors also use conditions to record configuration, so it is not necessarily a fault.")
        .fix("Read the condition message (get_resource kind=Node). Act only if it describes a fault; do not drain a node because of this condition alone.")
        .docs(docs::NODES)
}

/// `KernelDeadlock` -> `kernel_deadlock`; anything but ASCII letters and digits is dropped.
fn snake(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars().filter(char::is_ascii_alphanumeric) {
        if ch.is_ascii_uppercase() && !out.is_empty() && !out.ends_with('_') {
            out.push('_');
        }
        out.push(ch.to_ascii_lowercase());
    }
    if out.is_empty() {
        "unknown".to_owned()
    } else {
        out
    }
}

/// Kubelet minor vs API server minor, per the version skew policy: a kubelet may be up to 3
/// minors older than the API server (2 before 1.28) and never newer.
fn version_skew(ev: &NodeEvidence, name: &str, out: &mut Vec<Finding>) {
    let Some((smaj, smin)) = ev.server_version else {
        return;
    };
    let Some(kubelet) = ev
        .node
        .status
        .as_ref()
        .and_then(|s| s.node_info.as_ref())
        .map(|i| i.kubelet_version.as_str())
    else {
        return;
    };
    let Some((kmaj, kmin)) = parse_version(kubelet) else {
        return;
    };
    let max_skew = if smin >= 28 { 3 } else { 2 };
    let behind = i64::from(smin) - i64::from(kmin);
    let (severity, problem) = if kmaj != smaj || kmin > smin {
        (
            Severity::High,
            "newer than the API server, which is unsupported".to_owned(),
        )
    } else if behind > max_skew {
        (
            Severity::High,
            format!(
                "{behind} minor versions behind the API server, beyond the supported {max_skew}"
            ),
        )
    } else if behind == max_skew {
        (
            Severity::Low,
            format!(
                "{behind} minor versions behind the API server: the oldest supported, so it blocks the next control plane upgrade"
            ),
        )
    } else {
        return;
    };
    out.push(
        Finding::new("node.version_skew", severity, Confidence::High, format!("kubelet v{kmaj}.{kmin} on node {name} is {problem}"))
            .explain(format!("The API server runs v{smaj}.{smin}. Kubelets may be up to {max_skew} minor versions older than the API server and never newer; outside that range behaviour is untested and features break."))
            .evidence(Source::Status, format!("status.nodeInfo.kubeletVersion={}", truncate(kubelet, 50)))
            .evidence(Source::Related, format!("API server v{smaj}.{smin}"))
            .fix("Upgrade the node by replacing it from an updated node pool or node group (or upgrade the kubelet in place), keeping it no newer than the control plane.")
            .docs(docs::SKEW),
    );
}

/// `v1.29.4-eks-1234` -> (1, 29).
/// Sum of requests of the node's live pods vs allocatable, for CPU and memory.
fn overcommitted(ev: &NodeEvidence, name: &str, out: &mut Vec<Finding>) {
    let Some(pods) = &ev.pods else { return };
    let alloc = allocatable(&ev.node);
    let mut lines = Vec::new();
    let mut over = Vec::new();
    for res in ["cpu", "memory"] {
        let Some(&cap) = alloc.get(res) else { continue };
        let used: i64 = pods
            .iter()
            .filter(|p| !matches!(phase(p), "Succeeded" | "Failed"))
            .filter_map(|p| pod_requests(p).get(res).copied())
            .sum();
        if cap > 0 && used > cap {
            over.push(res);
            lines.push(format!(
                "{res} requested {} of {} allocatable ({}%)",
                fmt_quantity(res, used),
                fmt_quantity(res, cap),
                used * 100 / cap
            ));
        }
    }
    if over.is_empty() {
        return;
    }
    let mut f = Finding::new("node.overcommitted", Severity::High, Confidence::High, format!("pod requests on node {name} exceed its allocatable {}", over.join(" and ")))
        .explain("The scheduler never places pods beyond allocatable, so either allocatable shrank (changed system/kube reservations, a smaller instance) or pods were bound without the scheduler (static pods, spec.nodeName). The kubelet may reject or evict pods to recover.")
        .fix("Move workloads off the node (drain it or delete the pods bound to it directly) or restore its allocatable capacity.")
        .docs(docs::RESOURCES);
    for l in lines {
        f = f.evidence(Source::Related, l);
    }
    out.push(f);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::node_fixture;

    fn run(ev: &NodeEvidence) -> Vec<Finding> {
        let mut out = Vec::new();
        check(ev, &mut out);
        out
    }

    fn ids(ev: &NodeEvidence) -> Vec<String> {
        run(ev).into_iter().map(|f| f.id).collect()
    }

    #[test]
    fn unknown_ready_is_not_ready_with_affected_pods() {
        let out = run(&node_fixture("nodes/not-ready.yaml"));
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(
            (f.id.as_str(), f.severity),
            ("node.not_ready", Severity::Critical)
        );
        assert!(f.title.contains("stopped reporting"));
        let texts: Vec<_> = f.evidence.iter().map(|e| e.text.as_str()).collect();
        assert!(
            texts.contains(&"2 pod(s) on this node are affected"),
            "{texts:?}"
        );
        assert!(
            texts.contains(&"taints: node.kubernetes.io/unreachable"),
            "{texts:?}"
        );
    }

    #[test]
    fn pressure_oom_and_problem_conditions() {
        let ev = node_fixture("nodes/pressure-oom.yaml");
        assert_eq!(
            ids(&ev),
            [
                "node.pressure.memory",
                "node.npd.kernel_deadlock",
                "node.npd.storage_ready",
                "node.oom.system"
            ]
        );
        let out = run(&ev);
        assert!(
            out[0]
                .evidence
                .iter()
                .any(|e| e.source == Source::Event && e.text.contains("EvictionThresholdMet"))
        );
        assert!(out[3].title.contains("(3 OOM events)"), "{}", out[3].title);
    }

    #[test]
    fn gke_config_conditions_are_ignored_and_unknown_ones_are_medium_without_drain_advice() {
        let out = run(&node_fixture("nodes/gke-config-conditions.yaml"));
        let got: Vec<_> = out.iter().map(|f| (f.id.as_str(), f.severity)).collect();
        assert_eq!(
            got,
            [("node.npd.vendor_maintenance_scheduled", Severity::Medium)]
        );
        assert!(!out[0].fix.contains("drain the node"), "{}", out[0].fix);
    }

    /// riseno/k8s-mcp#32: only conditions known to hurt pods claim the pods are affected.
    #[test]
    fn unknown_conditions_do_not_claim_pods_are_affected() {
        let mut ev = node_fixture("nodes/healthy.yaml");
        let conditions = ev
            .node
            .status
            .as_mut()
            .unwrap()
            .conditions
            .as_mut()
            .unwrap();
        let mut c = conditions[0].clone();
        c.type_ = "VendorWidgetProblem".into();
        c.status = "True".into();
        conditions.push(c);
        let out = run(&ev);
        let f = out
            .iter()
            .find(|f| f.id == "node.npd.vendor_widget_problem")
            .unwrap();
        let texts: Vec<&str> = f.evidence.iter().map(|e| e.text.as_str()).collect();
        assert!(
            texts.iter().any(|t| t.ends_with("pod(s) run on this node")),
            "{texts:?}"
        );
        assert!(!texts.iter().any(|t| t.contains("affected")), "{texts:?}");
    }

    #[test]
    fn known_npd_fault_is_high_with_drain_advice() {
        let out = run(&node_fixture("nodes/pressure-oom.yaml"));
        let f = out
            .iter()
            .find(|f| f.id == "node.npd.kernel_deadlock")
            .unwrap();
        assert_eq!(f.severity, Severity::High);
        assert!(f.fix.contains("kubectl drain"), "{}", f.fix);
    }

    #[test]
    fn cordoned_old_kubelet_overcommitted_without_network() {
        let out = run(&node_fixture("nodes/cordoned-skew.yaml"));
        let got: Vec<_> = out.iter().map(|f| (f.id.as_str(), f.severity)).collect();
        assert_eq!(
            got,
            [
                ("node.network_unavailable", Severity::Critical),
                ("node.cordoned", Severity::Medium),
                ("node.version_skew", Severity::High),
                ("node.overcommitted", Severity::High)
            ]
        );
        assert!(
            out[2].title.contains("v1.29") && out[2].title.contains("4 minor versions behind"),
            "{}",
            out[2].title
        );
        assert!(
            out[3]
                .evidence
                .iter()
                .any(|e| e.text == "cpu requested 5 of 4 allocatable (125%)")
        );
    }

    #[test]
    fn version_skew_policy() {
        let mut ev = node_fixture("nodes/healthy.yaml");
        let cases = [
            ("v1.33.1", (1, 33), None),
            ("v1.31.0", (1, 33), None),
            ("v1.30.2-eks-a1b2c3", (1, 33), Some(Severity::Low)),
            ("v1.34.0", (1, 33), Some(Severity::High)),
            ("v1.25.9", (1, 27), Some(Severity::Low)),
            ("v1.24.0", (1, 27), Some(Severity::High)),
        ];
        for (kubelet, server, want) in cases {
            ev.node
                .status
                .as_mut()
                .unwrap()
                .node_info
                .as_mut()
                .unwrap()
                .kubelet_version = kubelet.into();
            ev.server_version = Some(server);
            let got = run(&ev)
                .into_iter()
                .find(|f| f.id == "node.version_skew")
                .map(|f| f.severity);
            assert_eq!(got, want, "{kubelet} vs {server:?}");
        }
    }

    #[test]
    fn healthy_node_has_no_findings() {
        assert!(run(&node_fixture("nodes/healthy.yaml")).is_empty());
    }

    #[test]
    fn snake_case_condition_ids() {
        assert_eq!(snake("KernelDeadlock"), "kernel_deadlock");
        assert_eq!(snake("ReadonlyFilesystem"), "readonly_filesystem");
        assert_eq!(
            snake("Frequent-Kubelet Restart!"),
            "frequent_kubelet_restart"
        );
        assert_eq!(snake("--"), "unknown");
    }
}
