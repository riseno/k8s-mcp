//! OOMKilled containers, with JVM/Node.js heap-flag checks (PROPOSAL §9.2).
//! Node-level OOM (`node.oom.system`) lives in [`super::node`].

use std::sync::LazyLock;

use k8s_mcp_core::finding::{Confidence, Finding, RuleMeta, Severity, Source};
use k8s_mcp_core::quantity::{bytes, fmt_bytes};
use k8s_openapi::api::core::v1::Container;
use regex::Regex;
use serde_json::json;

use super::{all_containers, describe_termination, docs, last_termination, logs_args, pod_ref};
use crate::evidence::PodEvidence;

/// Rules emitted by this module.
pub const RULES: &[RuleMeta] = &[RuleMeta {
    id: "pod.oom.container",
    title: "Container was OOMKilled: it exceeded its memory limit",
    docs: docs::MEMORY,
}];

#[allow(clippy::unwrap_used)] // constant patterns
static XMX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"-Xmx(\d+)([kKmMgG]?)\b").unwrap());
#[allow(clippy::unwrap_used)]
static NODE_HEAP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"--max-old-space-size=(\d+)").unwrap());

/// Check main and init containers.
pub fn check(ev: &PodEvidence, out: &mut Vec<Finding>) {
    for (c, st) in all_containers(&ev.pod) {
        let Some(st) = st else { continue };
        let Some(t) = last_termination(st) else {
            continue;
        };
        if t.reason.as_deref() != Some("OOMKilled") {
            continue;
        }
        let limit = memory_limit(c);
        let title = match limit {
            Some(l) => format!(
                "container {:?} was OOMKilled: it exceeded its {} memory limit",
                c.name,
                fmt_bytes(l)
            ),
            None => format!("container {:?} was OOMKilled (no memory limit set)", c.name),
        };
        let mut f = Finding::new("pod.oom.container", Severity::Critical, Confidence::High, title)
            .explain("The kernel OOM killer stopped the container because it used more memory than allowed (exit 137, reason OOMKilled). It will keep crashing until memory use and the limit agree.")
            .evidence(Source::Status, format!("lastState.terminated {}", describe_termination(t, ev.now)))
            .evidence(Source::Status, format!("restartCount={}", st.restart_count))
            .docs(docs::MEMORY);
        let mut fix = String::new();
        match limit {
            Some(l) => {
                f = f.evidence(
                    Source::Spec,
                    format!("resources.limits.memory={}", fmt_bytes(l)),
                );
                if let Some((flag, src, heap)) = heap_flag(c)
                    && heap * 10 >= l * 9
                {
                    f = f.evidence(
                        Source::Spec,
                        format!(
                            "heap flag {flag} in {src} is {} of the {} limit",
                            if heap >= l { "above" } else { "close to" },
                            fmt_bytes(l)
                        ),
                    );
                    fix = format!(
                        "Set the heap well below the limit (for JVMs prefer -XX:MaxRAMPercentage=75 instead of {flag}), or raise resources.limits.memory to at least {}.",
                        fmt_bytes(heap * 3 / 2)
                    );
                }
                if fix.is_empty() {
                    fix = format!(
                        "Raise resources.limits.memory above the container's real peak (currently {}), or fix the memory leak. Compare usage with `top`.",
                        fmt_bytes(l)
                    );
                }
            }
            None => {
                fix = "Set resources.requests.memory and resources.limits.memory from observed usage so the scheduler can place the pod and the kill becomes predictable.".into();
            }
        }
        let (pod, ns) = pod_ref(&ev.pod);
        out.push(
            f.fix(fix)
                .next(
                    "get_logs",
                    logs_args(&ev.pod, &c.name, true),
                    "see what the process was doing before the kill",
                )
                .next(
                    "top",
                    json!({"target": "pods", "namespace": ns}),
                    &format!("compare {pod}'s memory use with its limit"),
                ),
        );
    }
}

/// Memory limit of a container in bytes.
pub fn memory_limit(c: &Container) -> Option<i64> {
    c.resources
        .as_ref()?
        .limits
        .as_ref()?
        .get("memory")
        .and_then(|q| bytes(&q.0))
}

/// First heap flag in args, command or env literals: (flag text, where, bytes).
fn heap_flag(c: &Container) -> Option<(String, String, i64)> {
    let sources = c
        .command
        .iter()
        .flatten()
        .chain(c.args.iter().flatten())
        .map(|s| (s.as_str(), "args".to_owned()))
        .chain(
            c.env
                .iter()
                .flatten()
                .filter_map(|e| e.value.as_deref().map(|v| (v, format!("env {}", e.name)))),
        );
    for (text, src) in sources {
        if let Some(m) = XMX.captures(text) {
            let n: i64 = m[1].parse().ok()?;
            let mult = match &m[2] {
                "k" | "K" => 1 << 10,
                "m" | "M" => 1 << 20,
                "g" | "G" => 1 << 30,
                _ => 1,
            };
            return Some((m[0].to_owned(), src, n * mult));
        }
        if let Some(m) = NODE_HEAP.captures(text) {
            let n: i64 = m[1].parse().ok()?;
            return Some((m[0].to_owned(), src, n << 20));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::pod_fixture;

    #[test]
    fn oomkilled_with_jvm_flag_above_limit() {
        let ev = pod_fixture("pods/oomkilled.yaml");
        let mut out = Vec::new();
        check(&ev, &mut out);
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.id, "pod.oom.container");
        assert!(f.title.contains("128Mi"), "{}", f.title);
        assert!(
            f.evidence
                .iter()
                .any(|e| e.text.contains("-Xmx256m in env JAVA_OPTS is above"))
        );
        assert!(f.fix.contains("MaxRAMPercentage"));
    }

    #[test]
    fn non_oom_crash_is_ignored() {
        let mut out = Vec::new();
        check(&pod_fixture("pods/crashloop-exit1.yaml"), &mut out);
        assert!(out.is_empty());
    }
}
