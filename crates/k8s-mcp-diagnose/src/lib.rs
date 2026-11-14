#![forbid(unsafe_code)]
//! The pure k8s-mcp rule engine: evidence in, ranked findings out. **No I/O.**
//!
//! Tools gather an evidence bundle ([`PodEvidence`], [`WorkloadEvidence`],
//! [`NodeEvidence`]) and call [`diagnose_pod`], [`diagnose_workload`] or
//! [`diagnose_node`]. Rules live in [`rules`], one module per area.

pub mod evidence;
pub mod parse;
pub mod rules;
#[cfg(test)]
mod test_support;

pub use evidence::*;
use k8s_mcp_core::finding::{Finding, ObjectRef, RuleMeta, Source, dedup, rank};

/// Root-cause a pod. Rules run root causes first, so ties in severity/confidence keep that
/// order after ranking.
pub fn diagnose_pod(ev: &PodEvidence) -> Vec<Finding> {
    let mut out = Vec::new();
    rules::terminating::check(ev, &mut out);
    rules::config::check(ev, &mut out);
    rules::image::check(ev, &mut out);
    rules::pending::check(ev, &mut out);
    rules::creating::check(ev, &mut out);
    rules::init::check(ev, &mut out);
    rules::oom::check(ev, &mut out);
    rules::probe::check(ev, &mut out);
    rules::crashloop::check(ev, &mut out);
    rules::dns::check(ev, &mut out);
    rank(&mut out);
    dedup(&mut out);
    out
}

/// Root-cause a workload: pod findings for representative pods (merged across pods),
/// then workload-level findings (rollout, quota, admission, jobs).
pub fn diagnose_workload(ev: &WorkloadEvidence) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    for p in &ev.pods {
        let (name, ns) = rules::pod_ref(&p.pod);
        let obj = ObjectRef::new("Pod", Some(ns), name);
        for f in diagnose_pod(p) {
            match out.iter_mut().find(|o| o.id == f.id) {
                Some(existing) => existing.evidence.push(k8s_mcp_core::finding::Evidence {
                    source: Source::Related,
                    text: format!("same finding on pod {name}"),
                }),
                None => out.push(f.object(obj.clone())),
            }
        }
    }
    rules::rollout::check(ev, &mut out);
    rank(&mut out);
    dedup(&mut out);
    out
}

/// Root-cause a node.
pub fn diagnose_node(ev: &NodeEvidence) -> Vec<Finding> {
    let mut out = Vec::new();
    rules::node::check(ev, &mut out);
    rank(&mut out);
    dedup(&mut out);
    out
}

/// Every rule id this engine can emit, with title and docs link.
pub fn catalogue() -> Vec<RuleMeta> {
    let mut all: Vec<RuleMeta> = [
        rules::terminating::RULES,
        rules::config::RULES,
        rules::image::RULES,
        rules::pending::RULES,
        rules::creating::RULES,
        rules::init::RULES,
        rules::oom::RULES,
        rules::probe::RULES,
        rules::crashloop::RULES,
        rules::dns::RULES,
        rules::rollout::RULES,
        rules::node::RULES,
    ]
    .concat();
    all.sort_by_key(|r| r.id);
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_ids_are_unique_and_dotted() {
        let all = catalogue();
        let mut ids: Vec<_> = all.iter().map(|r| r.id).collect();
        ids.dedup();
        assert_eq!(ids.len(), all.len(), "duplicate rule ids");
        for id in ids {
            assert!(
                id.contains('.')
                    && id
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c == '.' || c == '_'),
                "bad id {id}"
            );
        }
    }
}
