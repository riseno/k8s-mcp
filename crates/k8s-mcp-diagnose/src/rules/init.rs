//! Init containers (PROPOSAL §9.2): `Init:CrashLoopBackOff` / `Init:Error`, sub-classified
//! like a main container by [`super::crashloop::classify`], and init containers that run so
//! long the app never starts. OOMKilled init containers are left to [`super::oom`]
//! (`classify` returns `None` for them).

use k8s_mcp_core::finding::{Confidence, Finding, RuleMeta, Severity, Source};
use k8s_mcp_core::text::{age, truncate};

use super::crashloop::{classify, is_crashlooping};
use super::{docs, init_containers, last_termination, logs_args, secs_since};
use crate::evidence::PodEvidence;

/// Rules emitted by this module.
pub const RULES: &[RuleMeta] = &[
    RuleMeta {
        id: "pod.init.failing",
        title: "An init container keeps failing, so the app containers never start",
        docs: docs::INIT,
    },
    RuleMeta {
        id: "pod.init.waiting",
        title: "An init container has been running for a long time, blocking pod start",
        docs: docs::INIT,
    },
];

/// An init container running longer than this is reported as `pod.init.waiting`.
const WAITING_AFTER_SECS: i64 = 300;

/// Check every init container.
pub fn check(ev: &PodEvidence, out: &mut Vec<Finding>) {
    for (c, st) in init_containers(&ev.pod) {
        let Some(st) = st else { continue };
        let state = st.state.as_ref();
        let failed = last_termination(st).is_some_and(|t| t.exit_code != 0);
        if failed && (is_crashlooping(st) || state.is_some_and(|s| s.terminated.is_some())) {
            if let Some(mut f) = classify(ev, c, st) {
                f.id = "pod.init.failing".into();
                f.title = format!("init container blocks pod start: {}", f.title);
                f.explanation = format!(
                    "Init containers must all succeed before the app containers start. {}",
                    f.explanation
                );
                f.docs = Some(docs::INIT.into());
                out.push(f);
            }
            continue;
        }
        let sidecar = c.restart_policy.as_deref() == Some("Always");
        let Some(started) = state
            .and_then(|s| s.running.as_ref())
            .and_then(|r| r.started_at.as_ref())
            .map(|t| t.0)
        else {
            continue;
        };
        if sidecar || secs_since(ev.now, started) < WAITING_AFTER_SECS {
            continue;
        }
        let ran = age(ev.now, started);
        let mut f = Finding::new("pod.init.waiting", Severity::High, Confidence::Medium, format!("init container {:?} has been running for {ran}; the app containers cannot start", c.name))
            .explain("Init containers run to completion one at a time. This one is still running, which usually means it waits for a dependency (a database, a Service, DNS) or is stuck in a slow job such as a migration.")
            .evidence(Source::Status, format!("init container {:?} running since {ran} ago", c.name))
            .fix("Read its logs to see what it waits for and check that dependency exists and is reachable. Give wait loops a timeout so a missing dependency surfaces as an error instead of a silent hang.")
            .docs(docs::INIT)
            .next("get_logs", logs_args(&ev.pod, &c.name, false), "see what the init container is waiting for");
        if let Some(log) = ev.logs.iter().find(|l| l.container == c.name) {
            let start = log.lines.len().saturating_sub(3);
            for line in &log.lines[start..] {
                f = f.evidence(Source::Log, truncate(line, 300));
            }
        }
        out.push(f);
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
    fn crashing_init_container_is_sub_classified() {
        let out = run(&pod_fixture("pods/init-crashloop.yaml"));
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.id, "pod.init.failing");
        assert!(
            f.title.contains("\"migrate\"") && f.title.contains("exits with code 1"),
            "{}",
            f.title
        );
        assert!(
            f.evidence
                .iter()
                .any(|e| e.source == Source::Log && e.text.contains("relation"))
        );
    }

    #[test]
    fn oomkilled_init_container_is_left_to_oom() {
        let mut ev = pod_fixture("pods/init-crashloop.yaml");
        let st = &mut ev
            .pod
            .status
            .as_mut()
            .unwrap()
            .init_container_statuses
            .as_mut()
            .unwrap()[0];
        let t = st.last_state.as_mut().unwrap().terminated.as_mut().unwrap();
        t.reason = Some("OOMKilled".into());
        t.exit_code = 137;
        assert!(run(&ev).is_empty());
    }

    #[test]
    fn long_running_init_container_is_waiting() {
        let out = run(&pod_fixture("pods/init-waiting.yaml"));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "pod.init.waiting");
        assert!(
            out[0]
                .evidence
                .iter()
                .any(|e| e.source == Source::Log && e.text.contains("waiting for db"))
        );
    }

    #[test]
    fn pods_without_init_trouble_are_ignored() {
        for f in ["pods/healthy.yaml", "pods/crashloop-exit1.yaml"] {
            assert!(run(&pod_fixture(f)).is_empty(), "{f}");
        }
        let mut ev = pod_fixture("pods/init-waiting.yaml");
        ev.now = "2026-11-14T11:41:00Z".parse().unwrap();
        assert!(
            run(&ev).is_empty(),
            "a young init container is not waiting yet"
        );
    }
}
