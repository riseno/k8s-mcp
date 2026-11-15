//! Tolerant parsers for Kubernetes event messages.
//!
//! Messages are untrusted text: parsers only classify them; the rules decide what (if
//! anything) may be echoed outside `Event`/`Status` evidence.

use std::sync::LazyLock;

use regex::Regex;

use crate::rules::re;

/// Why some nodes rejected a pod, from one item of a `FailedScheduling` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchedulingReason {
    /// `Insufficient cpu`, `Insufficient nvidia.com/gpu`: the resource name as written.
    Insufficient(String),
    /// `Too many pods` (the node's pod limit is reached).
    TooManyPods,
    /// `had untolerated taint {k: v}` or the older `had taint {k: v}, that the pod didn't tolerate`.
    Taint,
    /// `node(s) were unschedulable` (cordoned).
    Cordoned,
    /// `didn't match Pod's node affinity/selector`, `didn't match node selector`, and pod
    /// (anti-)affinity rules.
    Affinity,
    /// `didn't match pod topology spread constraints`.
    TopologySpread,
    /// `pod has unbound immediate PersistentVolumeClaims`, `persistentvolumeclaim "x" not found`,
    /// `didn't find available persistent volumes to bind`, VolumeBinding PreBind errors.
    UnboundPvc,
    /// `had volume node affinity conflict`.
    VolumeNodeAffinity,
    /// Anything else (free ports, volume limits, plugin errors).
    Other,
}

/// A parsed `FailedScheduling` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedScheduling {
    /// Nodes considered (`0/5 nodes are available` gives 5), if stated.
    pub nodes: Option<u32>,
    /// Each reason with the number of nodes it applies to (`None` for pod-level reasons).
    pub reasons: Vec<(Option<u32>, SchedulingReason)>,
}

static HEADER: LazyLock<Regex> = LazyLock::new(|| re(r"^\s*\d+/(\d+) nodes are available:?\s*"));
static SPLIT: LazyLock<Regex> = LazyLock::new(|| re(r",\s+(\d+\s)"));
static COUNTED: LazyLock<Regex> = LazyLock::new(|| re(r"^(\d+)\s+(.*)$"));

/// Parse a `FailedScheduling` message such as
/// `0/5 nodes are available: 2 Insufficient cpu, 3 node(s) had untolerated taint {dedicated: gpu}. preemption: ...`.
/// The preemption part is ignored. Returns `None` for an empty message.
pub fn failed_scheduling(message: &str) -> Option<FailedScheduling> {
    let main = message
        .find("preemption:")
        .map_or(message, |i| &message[..i]);
    let (nodes, rest) = match HEADER.captures(main) {
        Some(c) => (c[1].parse().ok(), &main[c.get(0)?.end()..]),
        None if main.trim_start().starts_with("no nodes available") => (Some(0), ""),
        None => (None, main),
    };
    let rest = rest.trim().trim_end_matches('.').trim();
    if rest.is_empty() && nodes.is_none() {
        return None;
    }
    let mut items = Vec::new();
    let mut start = 0;
    for c in SPLIT.captures_iter(rest) {
        items.push(&rest[start..c.get(0)?.start()]);
        start = c.get(1)?.start();
    }
    items.push(&rest[start..]);
    let reasons = items
        .into_iter()
        .map(|item| item.trim().trim_end_matches('.'))
        .filter(|item| !item.is_empty())
        .map(|item| match COUNTED.captures(item) {
            Some(c) => (c[1].parse().ok(), classify(&c[2])),
            None => (None, classify(item)),
        })
        .collect();
    Some(FailedScheduling { nodes, reasons })
}

fn classify(text: &str) -> SchedulingReason {
    let t = text.to_ascii_lowercase();
    let has = |s: &str| t.contains(s);
    if let Some(r) = t.strip_prefix("insufficient ") {
        SchedulingReason::Insufficient(r.trim().to_owned())
    } else if has("too many pods") {
        SchedulingReason::TooManyPods
    } else if has("volume node affinity") {
        SchedulingReason::VolumeNodeAffinity
    } else if has("taint") {
        SchedulingReason::Taint
    } else if has("were unschedulable") {
        SchedulingReason::Cordoned
    } else if has("topology spread") {
        SchedulingReason::TopologySpread
    } else if has("affinity") || has("node selector") {
        SchedulingReason::Affinity
    } else if has("persistentvolumeclaim")
        || has("persistent volumes to bind")
        || has("volumebinding")
    {
        SchedulingReason::UnboundPvc
    } else {
        SchedulingReason::Other
    }
}

#[cfg(test)]
mod tests {
    use super::SchedulingReason::*;
    use super::*;

    fn parse(m: &str) -> (Option<u32>, Vec<(Option<u32>, SchedulingReason)>) {
        let p = failed_scheduling(m).unwrap();
        (p.nodes, p.reasons)
    }

    #[test]
    fn current_format_with_preemption() {
        assert_eq!(
            parse(
                "0/5 nodes are available: 2 Insufficient cpu, 3 node(s) had untolerated taint {dedicated: gpu}. preemption: 0/5 nodes are available: 5 Preemption is not helpful for scheduling."
            ),
            (
                Some(5),
                vec![(Some(2), Insufficient("cpu".into())), (Some(3), Taint)]
            )
        );
    }

    #[test]
    fn older_taint_format_keeps_its_comma() {
        assert_eq!(
            parse(
                "0/3 nodes are available: 1 node(s) had taint {node-role.kubernetes.io/master: }, that the pod didn't tolerate, 2 Insufficient memory."
            ),
            (
                Some(3),
                vec![(Some(1), Taint), (Some(2), Insufficient("memory".into()))]
            )
        );
    }

    #[test]
    fn single_reasons() {
        let one = |m: &str| parse(m).1;
        assert_eq!(
            one(
                "0/1 nodes are available: 1 Insufficient cpu. preemption: 0/1 nodes are available: 1 No preemption victims found for incoming pod."
            ),
            [(Some(1), Insufficient("cpu".into()))]
        );
        assert_eq!(
            one("0/1 nodes are available: 1 node(s) didn't match Pod's node affinity/selector."),
            [(Some(1), Affinity)]
        );
        assert_eq!(
            one("0/3 nodes are available: 3 node(s) didn't match node selector."),
            [(Some(3), Affinity)]
        );
        assert_eq!(
            one("0/1 nodes are available: pod has unbound immediate PersistentVolumeClaims."),
            [(None, UnboundPvc)]
        );
        assert_eq!(
            one(
                "0/1 nodes are available: persistentvolumeclaim \"data\" not found. preemption: 0/1 nodes are available: 1 Preemption is not helpful for scheduling.."
            ),
            [(None, UnboundPvc)]
        );
        assert_eq!(
            one("0/3 nodes are available: 3 node(s) had volume node affinity conflict."),
            [(Some(3), VolumeNodeAffinity)]
        );
        assert_eq!(
            one("0/3 nodes are available: 3 node(s) didn't match pod topology spread constraints."),
            [(Some(3), TopologySpread)]
        );
        assert_eq!(
            one("0/2 nodes are available: 2 Too many pods."),
            [(Some(2), TooManyPods)]
        );
        assert_eq!(
            one(
                "0/4 nodes are available: 4 node(s) didn't satisfy existing pods anti-affinity rules."
            ),
            [(Some(4), Affinity)]
        );
        assert_eq!(
            one(
                "0/2 nodes are available: 2 node(s) didn't have free ports for the requested pod ports."
            ),
            [(Some(2), Other)]
        );
    }

    #[test]
    fn mixed_cordon_taint_and_gpu() {
        assert_eq!(
            parse(
                "0/6 nodes are available: 1 node(s) were unschedulable, 2 node(s) had untolerated taint {node-role.kubernetes.io/control-plane: }, 3 Insufficient nvidia.com/gpu. preemption: 0/6 nodes are available: 3 No preemption victims found for incoming pod, 3 Preemption is not helpful for scheduling."
            ),
            (
                Some(6),
                vec![
                    (Some(1), Cordoned),
                    (Some(2), Taint),
                    (Some(3), Insufficient("nvidia.com/gpu".into()))
                ]
            )
        );
    }

    #[test]
    fn no_nodes_and_unstructured_messages() {
        assert_eq!(
            parse("no nodes available to schedule pods"),
            (Some(0), vec![])
        );
        assert_eq!(
            parse(
                "running PreBind plugin \"VolumeBinding\": binding volumes: timed out waiting for the condition"
            ),
            (None, vec![(None, UnboundPvc)])
        );
        assert!(failed_scheduling("").is_none());
    }
}
