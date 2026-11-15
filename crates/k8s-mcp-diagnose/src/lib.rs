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

/// Root-cause a Service: selector, port mapping, readiness and load balancer.
pub fn diagnose_service(ev: &ServiceEvidence) -> Vec<Finding> {
    let mut out = Vec::new();
    rules::service::check(ev, &mut out);
    rank(&mut out);
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
        rules::service::RULES,
    ]
    .concat();
    all.sort_by_key(|r| r.id);
    all
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{node_fixture, pod_fixture, service_fixture, workload_fixture};

    /// Every fixture under `dir`, sorted, as `dir/<file>` names.
    fn fixtures(dir: &str) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(k8s_mcp_testkit::path(dir))
            .unwrap()
            .map(|e| format!("{dir}/{}", e.unwrap().file_name().to_string_lossy()))
            .filter(|n| {
                std::path::Path::new(n)
                    .extension()
                    .is_some_and(|e| e == "yaml")
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn every_emitted_id_is_catalogued() {
        let known: Vec<&str> = catalogue().iter().map(|r| r.id).collect();
        let check = |fixture: &str, findings: Vec<Finding>| {
            for f in findings {
                let ok = known.contains(&f.id.as_str())
                    || f.id.strip_prefix("node.npd.").is_some_and(|rest| {
                        !rest.is_empty()
                            && rest
                                .chars()
                                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                    });
                assert!(ok, "{fixture}: uncatalogued id {}", f.id);
                assert!(
                    !f.title.is_empty() && f.docs.is_some(),
                    "{fixture}: {} lacks title/docs",
                    f.id
                );
            }
        };
        let (pods, workloads, nodes) = (fixtures("pods"), fixtures("workloads"), fixtures("nodes"));
        assert!(!pods.is_empty() && !workloads.is_empty() && !nodes.is_empty());
        for f in &pods {
            check(f, diagnose_pod(&pod_fixture(f)));
        }
        for f in &workloads {
            check(f, diagnose_workload(&workload_fixture(f)));
        }
        for f in &nodes {
            check(f, diagnose_node(&node_fixture(f)));
        }
        let services = fixtures("services");
        assert!(!services.is_empty());
        for f in &services {
            check(f, diagnose_service(&service_fixture(f)));
        }
    }

    /// The eval scenarios (PROPOSAL §13): the root cause must rank first, forbidden ids must
    /// not appear at all.
    #[test]
    fn eval_scenarios_rank_root_cause_first() {
        let cases: &[(&str, &str, &[&str])] = &[
            (
                "pods/image-not-found.yaml",
                "pod.image.not_found",
                &["pod.image.auth"],
            ),
            (
                "pods/image-auth.yaml",
                "pod.image.auth",
                &["pod.image.not_found"],
            ),
            (
                "pods/crashloop-exit127.yaml",
                "pod.crashloop.command_not_found",
                &[],
            ),
            ("pods/crashloop-exit1.yaml", "pod.crashloop.app_error", &[]),
            (
                "pods/oom-memory-hog.yaml",
                "pod.oom.container",
                &["pod.crashloop.sigkill"],
            ),
            (
                "pods/probe-port-mismatch.yaml",
                "pod.probe.port_mismatch",
                &["pod.crashloop.exit_zero"],
            ),
            (
                "pods/probe-readiness-404.yaml",
                "pod.probe.readiness_failing",
                &[],
            ),
            (
                "pods/config-missing-configmap.yaml",
                "pod.config.missing_configmap",
                &[],
            ),
            (
                "pods/config-missing-key.yaml",
                "pod.config.missing_key",
                &["pod.config.missing_secret"],
            ),
            (
                "pods/pending-insufficient-cpu.yaml",
                "pod.pending.insufficient_resources",
                &[],
            ),
            (
                "pods/pending-node-selector.yaml",
                "pod.pending.node_selector_affinity",
                &[],
            ),
            (
                "pods/pending-pvc-unbound.yaml",
                "pod.pending.pvc_unbound",
                &[],
            ),
            ("pods/crashloop-exit0.yaml", "pod.crashloop.exit_zero", &[]),
            (
                "workloads/quota-exceeded.yaml",
                "pod.pending.quota",
                &["workload.create_failed"],
            ),
            // Beyond the eval set: symptoms and log hints never outrank the root cause.
            ("pods/dns-errors.yaml", "pod.crashloop.app_error", &[]),
            ("workloads/rollout-stuck.yaml", "pod.image.not_found", &[]),
            ("workloads/job-backoff.yaml", "job.backoff_limit", &[]),
        ];
        for (fixture, primary, forbidden) in cases {
            let findings = if fixture.starts_with("workloads/") {
                diagnose_workload(&workload_fixture(fixture))
            } else {
                diagnose_pod(&pod_fixture(fixture))
            };
            let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
            assert_eq!(ids.first(), Some(primary), "{fixture}: {ids:?}");
            for bad in *forbidden {
                assert!(!ids.contains(bad), "{fixture}: forbidden {bad} in {ids:?}");
            }
        }
    }

    #[test]
    fn dns_hint_ranks_below_the_crash() {
        let ids: Vec<String> = diagnose_pod(&pod_fixture("pods/dns-errors.yaml"))
            .into_iter()
            .map(|f| f.id)
            .collect();
        assert_eq!(
            ids,
            ["pod.crashloop.app_error", "dns.app_resolution_errors"]
        );
    }

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
