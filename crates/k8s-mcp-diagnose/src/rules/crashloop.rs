//! CrashLoopBackOff, sub-classified by the last termination (PROPOSAL §9.2).
//!
//! OOMKilled terminations are left to [`super::oom`] and probe-driven restarts to
//! [`super::probe`], so each crash has exactly one root-cause finding.

use k8s_mcp_core::finding::{Confidence, Finding, RuleMeta, Severity, Source};
use k8s_openapi::api::core::v1::{Container, ContainerStatus};

use super::{
    containers, describe_termination, docs, error_lines, events_with, last_termination, logs_args,
    probe_killed, quote_event, restart_policy, rule_docs, waiting_reason,
};
use crate::evidence::PodEvidence;

/// Rules emitted by this module.
pub const RULES: &[RuleMeta] = &[
    RuleMeta {
        id: "pod.crashloop.dependency_unreachable",
        title: "Container crash-loops because a service it connects to refuses or drops the connection (from its logs)",
        docs: docs::DEBUG_PODS,
    },
    RuleMeta {
        id: "pod.crashloop.app_error",
        title: "Container crash-loops because the application exits with an error (exit 1/2)",
        docs: docs::DEBUG_PODS,
    },
    RuleMeta {
        id: "pod.crashloop.command_not_found",
        title: "Container crash-loops because its command was not found (exit 127)",
        docs: docs::DEBUG_PODS,
    },
    RuleMeta {
        id: "pod.crashloop.not_executable",
        title: "Container crash-loops because its command is not executable (exit 126)",
        docs: docs::DEBUG_PODS,
    },
    RuleMeta {
        id: "pod.crashloop.sigkill",
        title: "Container is being SIGKILLed (exit 137) without an OOM kill",
        docs: docs::LIFECYCLE,
    },
    RuleMeta {
        id: "pod.crashloop.sigterm",
        title: "Container exits on SIGTERM (exit 143)",
        docs: docs::LIFECYCLE,
    },
    RuleMeta {
        id: "pod.crashloop.exit_zero",
        title: "Container exits successfully (exit 0) but the restart policy is Always",
        docs: docs::LIFECYCLE,
    },
    RuleMeta {
        id: "pod.crashloop.other",
        title: "Container crash-loops with an unusual exit code",
        docs: docs::DEBUG_PODS,
    },
];

/// What a crashed container's log says about the cause, when it says it clearly.
enum LogCause {
    /// A wrapper failed to start the real program.
    CommandNotFound,
    /// A connection the application needs was refused or timed out (`host:port` if shown).
    Unreachable(Option<String>),
}

#[allow(clippy::unwrap_used)] // constant patterns
static SPAWN: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r#"(?i)failed to spawn|executable file not found|exec: "[^"]*": no such file or directory|: command not found"#).unwrap()
});
#[allow(clippy::unwrap_used)]
static UNREACHABLE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"(?i)connection refused|econnrefused|connection timed out|no route to host|network is unreachable|errno 111").unwrap()
});
/// `host:port` with a hostname or IP (letters or dots required, so `12:30` times don't match).
#[allow(clippy::unwrap_used)]
static HOST_PORT: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"\b((?:[A-Za-z0-9-]+\.)*[A-Za-z0-9-]+):(\d{2,5})\b").unwrap()
});

/// Read the last lines of the crashed instance's log for a cause the exit code can't show.
fn log_cause(ev: &PodEvidence, container: &str) -> Option<LogCause> {
    let log = ev.logs.iter().find(|l| l.container == container)?;
    let tail = &log.lines[log.lines.len().saturating_sub(30)..];
    if tail.iter().any(|l| SPAWN.is_match(l)) {
        return Some(LogCause::CommandNotFound);
    }
    // DNS failures belong to dns.app_resolution_errors.
    let line = tail
        .iter()
        .rev()
        .find(|l| UNREACHABLE.is_match(l) && !l.contains("no such host"))?;
    let target = HOST_PORT
        .captures_iter(line)
        .find(|c| c[1].contains('.') || c[1].chars().any(|ch| ch.is_ascii_alphabetic()))
        .map(|c| format!("{}:{}", c[1].to_ascii_lowercase(), &c[2]))
        .filter(|t| super::dns_name(t.split(':').next().unwrap_or("")));
    Some(LogCause::Unreachable(target))
}

/// Check every main container.
pub fn check(ev: &PodEvidence, out: &mut Vec<Finding>) {
    for (c, st) in containers(&ev.pod) {
        if let Some(st) = st
            && is_crashlooping(st)
        {
            out.extend(classify(ev, c, st));
        }
    }
}

/// True if the container is in (or heading into) CrashLoopBackOff.
pub fn is_crashlooping(st: &ContainerStatus) -> bool {
    waiting_reason(st) == Some("CrashLoopBackOff")
        || (st.restart_count >= 3 && last_termination(st).is_some())
}

/// Classify a crashing container by its last termination. Returns `None` when another rule
/// owns the root cause (OOMKilled, probe-driven restarts).
pub fn classify(ev: &PodEvidence, c: &Container, st: &ContainerStatus) -> Option<Finding> {
    let t = last_termination(st)?;
    let term_reason = t.reason.as_deref().unwrap_or("");
    if super::oom::oom_kind(ev, c, t).is_some() || probe_killed(&ev.events, &c.name) {
        return None;
    }
    let message = t.message.as_deref().unwrap_or("");
    let code = t.exit_code;
    let name = &c.name;
    let start_error = matches!(term_reason, "StartError" | "ContainerCannotRun");

    let (id, title, explanation, fix, confidence) = if code == 127
        || (start_error
            && (message.contains("executable file not found")
                || message.contains("no such file or directory")))
    {
        (
            "pod.crashloop.command_not_found",
            format!("container {name:?} crash-loops: its command was not found"),
            "The container's entrypoint or a command it runs does not exist in the image (exit code 127, or the runtime could not find the executable). The process never really starts.".to_owned(),
            format!("Check `command`/`args` of container {name:?} against the image: run the image locally (`docker run --entrypoint sh <image>`) and confirm the binary path. Fix typos, use an absolute path, or use an image that contains the tool."),
            Confidence::High,
        )
    } else if code == 126 || (start_error && message.contains("permission denied")) {
        (
            "pod.crashloop.not_executable",
            format!("container {name:?} crash-loops: its command is not executable"),
            "The command exists but cannot be executed (exit 126): missing execute permission, a script without a valid shebang, or a binary built for another architecture.".to_owned(),
            "Make the entrypoint executable (`chmod +x` in the Dockerfile), check the shebang line, and make sure the image architecture matches the node (`kubernetes.io/arch`).".to_owned(),
            Confidence::High,
        )
    } else if code == 137 {
        (
            "pod.crashloop.sigkill",
            format!("container {name:?} is being killed with SIGKILL (exit 137), not by the OOM killer"),
            "Exit 137 means the process received SIGKILL. Without an OOMKilled reason this is usually the kubelet killing a container that ignored SIGTERM (after a liveness failure or during shutdown), an eviction, a preemption, or a node-level OOM kill.".to_owned(),
            "Check recent events for Killing/Evicted/Preempting, compare memory use with limits (`top`), and make the process handle SIGTERM so it exits within terminationGracePeriodSeconds.".to_owned(),
            Confidence::Medium,
        )
    } else if code == 143 {
        (
            "pod.crashloop.sigterm",
            format!("container {name:?} exits on SIGTERM (exit 143)"),
            "Exit 143 means the process stopped on SIGTERM. Something keeps asking the container to stop: often probe failures, a rollout, or the process itself sending TERM to its own group.".to_owned(),
            "Look at events for Killing and Unhealthy messages and at the previous logs around shutdown. If probes are failing, fix the probe or the endpoint it checks.".to_owned(),
            Confidence::Medium,
        )
    } else if code == 0 {
        if restart_policy(&ev.pod) != "Always" {
            return None;
        }
        (
            "pod.crashloop.exit_zero",
            format!("container {name:?} exits successfully but is restarted (restartPolicy Always)"),
            "The main process finishes with exit code 0, so the kubelet restarts it and eventually backs off. Long-running containers must keep a foreground process; one-shot tasks belong in a Job.".to_owned(),
            "Run the server in the foreground (for example `nginx -g 'daemon off;'`, no `&` or daemon mode), fix a command that only prints and exits, or move one-shot work to a Job/CronJob.".to_owned(),
            Confidence::High,
        )
    } else if let Some(cause) = log_cause(ev, name) {
        match cause {
            LogCause::CommandNotFound => (
                "pod.crashloop.command_not_found",
                format!("container {name:?} crash-loops: a command it runs was not found"),
                "The logs show a program failing to start another executable (for example a `uv run` or shell wrapper reporting `Failed to spawn` or `executable file not found`). The wrapper then exits with its own code.".to_owned(),
                format!("Check that the command container {name:?} runs exists in the image (installed, on PATH, right name), or fix `command`/`args`."),
                Confidence::Medium,
            ),
            LogCause::Unreachable(target) => (
                "pod.crashloop.dependency_unreachable",
                match &target {
                    Some(t) => format!("container {name:?} crash-loops: it cannot connect to {t}"),
                    None => format!("container {name:?} crash-loops: a service it connects to is unreachable"),
                },
                "The application exits because a connection it needs at startup is refused or times out. The dependency is down, not listening yet, or the address is wrong (for example localhost inside a container, where nothing else listens).".to_owned(),
                "Make sure the dependency is running and reachable from the pod (its Service, port and endpoints; NetworkPolicy), point the application at the right host and port, or make it retry instead of exiting while the dependency starts.".to_owned(),
                Confidence::Medium,
            ),
        }
    } else if code == 1 || code == 2 {
        (
            "pod.crashloop.app_error",
            format!("container {name:?} crash-loops: the application exits with code {code}"),
            "The application starts and then exits with an error. The cause is in its own output: look at the last lines before the crash.".to_owned(),
            "Read the previous instance's logs (below / get_logs previous=true) and fix the error they report: commonly missing configuration, an unreachable dependency, or a bad flag.".to_owned(),
            Confidence::High,
        )
    } else {
        let signal = if code > 128 {
            format!(" (signal {})", code - 128)
        } else {
            String::new()
        };
        (
            "pod.crashloop.other",
            format!("container {name:?} crash-loops with exit code {code}{signal}"),
            "The container keeps exiting with an application-specific exit code. Its logs usually explain why.".to_owned(),
            "Read the previous logs and look up the exit code in the application's documentation.".to_owned(),
            Confidence::Medium,
        )
    };

    let mut f = Finding::new(id, Severity::Critical, confidence, title)
        .explain(explanation)
        .evidence(
            Source::Status,
            format!("lastState.terminated {}", describe_termination(t, ev.now)),
        )
        .evidence(Source::Status, format!("restartCount={}", st.restart_count))
        .fix(fix)
        .docs(rule_docs(RULES, id))
        .next(
            "get_logs",
            logs_args(&ev.pod, name, true),
            "see the full output of the crashed instance",
        );
    if !message.is_empty() {
        f = f.evidence(
            Source::Status,
            format!(
                "lastState.terminated.message: {}",
                k8s_mcp_core::text::truncate(message, 300)
            ),
        );
    }
    if id == "pod.crashloop.command_not_found" || id == "pod.crashloop.not_executable" {
        let cmd: Vec<&str> = c
            .command
            .iter()
            .flatten()
            .chain(c.args.iter().flatten())
            .map(String::as_str)
            .collect();
        if !cmd.is_empty() {
            f = f.evidence(
                Source::Spec,
                format!(
                    "command/args: {}",
                    k8s_mcp_core::text::truncate(&cmd.join(" "), 200)
                ),
            );
        }
    }
    if let Some(log) = ev.logs.iter().find(|l| l.container == *name) {
        for line in error_lines(&log.lines, 3) {
            f = f.evidence(Source::Log, line);
        }
    } else if ev.unavailable.iter().any(|u| u.what.contains("logs")) {
        f.confidence = f.confidence.lower();
        f = f.evidence(Source::Unavailable, "container logs could not be read");
    }
    if let Some(e) = events_with(&ev.events, &["BackOff"]).next() {
        f = f.evidence(Source::Event, quote_event(e, ev.now));
    }
    Some(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::pod_fixture;

    fn ids(fixture: &str) -> Vec<String> {
        let ev = pod_fixture(fixture);
        let mut out = Vec::new();
        check(&ev, &mut out);
        out.into_iter().map(|f| f.id).collect()
    }

    #[test]
    fn app_error_quotes_log_lines() {
        let ev = pod_fixture("pods/crashloop-exit1.yaml");
        let mut out = Vec::new();
        check(&ev, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "pod.crashloop.app_error");
        assert!(
            out[0]
                .evidence
                .iter()
                .any(|e| e.source == Source::Log && e.text.contains("Exception"))
        );
    }

    #[test]
    fn refused_connection_in_logs_is_dependency_unreachable() {
        let ev = pod_fixture("pods/crashloop-dependency-refused.yaml");
        let mut out = Vec::new();
        check(&ev, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "pod.crashloop.dependency_unreachable");
        assert_eq!(out[0].confidence, Confidence::Medium);
        assert!(out[0].title.contains("localhost:6379"), "{}", out[0].title);
    }

    #[test]
    fn wrapper_failing_to_spawn_is_command_not_found() {
        assert_eq!(
            ids("pods/crashloop-uv-spawn.yaml"),
            ["pod.crashloop.command_not_found"]
        );
    }

    #[test]
    fn plain_app_errors_are_not_reclassified_from_logs() {
        // Mentions a host:port but no refused connection.
        assert_eq!(
            ids("pods/crashloop-exit1.yaml"),
            ["pod.crashloop.app_error"]
        );
    }

    #[test]
    fn exit_127_is_command_not_found() {
        assert_eq!(
            ids("pods/crashloop-exit127.yaml"),
            ["pod.crashloop.command_not_found"]
        );
    }

    #[test]
    fn exit_zero_with_always() {
        assert_eq!(
            ids("pods/crashloop-exit0.yaml"),
            ["pod.crashloop.exit_zero"]
        );
    }

    #[test]
    fn oomkilled_is_left_to_oom_rule() {
        assert!(ids("pods/oomkilled.yaml").is_empty());
    }

    #[test]
    fn healthy_pod_has_no_findings() {
        assert!(ids("pods/healthy.yaml").is_empty());
    }
}
