//! Probe failures (PROPOSAL §9.2): kubelet `Unhealthy` events (`Liveness probe failed: ...`)
//! and `Killing` events (`Container x failed liveness probe, will be restarted`), checked
//! against the probe spec.
//!
//! One root-cause finding per failing probe, in this order: a port no `containerPort`
//! declares (`port_mismatch`), deadline errors with a 1s timeout (`timeout_too_low`), a
//! startup probe whose budget runs out (`startup_too_short`), else
//! `liveness_failing`/`readiness_failing`. Probes that get the container killed are critical,
//! so they outrank the crash loop the kills cause ([`super::crashloop`] also defers).

use std::sync::LazyLock;

use k8s_mcp_core::finding::{Confidence, Finding, RuleMeta, Severity, Source};
use k8s_openapi::api::core::v1::{Container, ContainerStatus, Event, Probe};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use regex::Regex;

use super::{
    about_container, containers, docs, latest, logs_args, msg, pod_events_args, quote_event, re,
    reason, rule_docs,
};
use crate::evidence::PodEvidence;

/// Rules emitted by this module.
pub const RULES: &[RuleMeta] = &[
    RuleMeta {
        id: "pod.probe.liveness_failing",
        title: "Liveness probe is failing and the kubelet restarts the container",
        docs: docs::PROBES,
    },
    RuleMeta {
        id: "pod.probe.readiness_failing",
        title: "Readiness probe is failing: the pod receives no Service traffic",
        docs: docs::PROBES,
    },
    RuleMeta {
        id: "pod.probe.startup_too_short",
        title: "The app needs longer to start than its probes allow",
        docs: docs::PROBES,
    },
    RuleMeta {
        id: "pod.probe.port_mismatch",
        title: "Probe checks a port the container does not expose",
        docs: docs::PROBES,
    },
    RuleMeta {
        id: "pod.probe.timeout_too_low",
        title: "Probe times out because timeoutSeconds is too low",
        docs: docs::PROBES,
    },
];

static TIMEOUT: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)context deadline exceeded|client\.timeout exceeded|timed out|timeout: failed to connect|i/o timeout",
    )
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Startup,
    Liveness,
    Readiness,
}

impl Kind {
    /// Lower-case name, as in `failed liveness probe`.
    fn name(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Liveness => "liveness",
            Self::Readiness => "readiness",
        }
    }

    /// Event message prefix, as in `Liveness probe failed: ...`.
    fn prefix(self) -> &'static str {
        match self {
            Self::Startup => "Startup probe",
            Self::Liveness => "Liveness probe",
            Self::Readiness => "Readiness probe",
        }
    }

    fn probe(self, c: &Container) -> Option<&Probe> {
        match self {
            Self::Startup => c.startup_probe.as_ref(),
            Self::Liveness => c.liveness_probe.as_ref(),
            Self::Readiness => c.readiness_probe.as_ref(),
        }
    }
}

/// Check every probe of every main container.
pub fn check(ev: &PodEvidence, out: &mut Vec<Finding>) {
    for (c, st) in containers(&ev.pod) {
        let Some(st) = st else { continue };
        for kind in [Kind::Startup, Kind::Liveness, Kind::Readiness] {
            if let Some(probe) = kind.probe(c) {
                failing(ev, c, st, kind, probe, out);
            }
        }
    }
}

/// Emit the root-cause finding for one probe, if its events show it failing.
fn failing(
    ev: &PodEvidence,
    c: &Container,
    st: &ContainerStatus,
    kind: Kind,
    probe: &Probe,
    out: &mut Vec<Finding>,
) {
    let ours = |e: &&Event| about_container(e, &c.name);
    let fails: Vec<&Event> = ev
        .events
        .iter()
        .filter(ours)
        .filter(|e| reason(e) == "Unhealthy" && msg(e).starts_with(kind.prefix()))
        .collect();
    let kill = ev.events.iter().filter(ours).find(|e| {
        reason(e) == "Killing" && msg(e).contains(&format!("failed {} probe", kind.name()))
    });
    let recovered = kind == Kind::Readiness && st.ready;
    if (fails.is_empty() && kill.is_none()) || recovered {
        return;
    }
    let name = &c.name;
    let k = kind.name();
    let text: String = fails.iter().map(|e| msg(e)).collect::<Vec<_>>().join("\n");
    let refused = text.contains("connection refused");
    let declared: Vec<String> = c
        .ports
        .iter()
        .flatten()
        .map(|p| match &p.name {
            Some(n) => format!("{} ({n})", p.container_port),
            None => p.container_port.to_string(),
        })
        .collect();
    let declared_text = if declared.is_empty() {
        "none".to_owned()
    } else {
        declared.join(", ")
    };
    let timeout = probe.timeout_seconds.unwrap_or(1);
    let budget = probe.initial_delay_seconds.unwrap_or(0)
        + probe.failure_threshold.unwrap_or(3) * probe.period_seconds.unwrap_or(10);
    let effect = if kind == Kind::Readiness {
        "the pod is never Ready, so its Services send it no traffic"
    } else {
        "the kubelet restarts the container every time the failure threshold is reached"
    };

    let (id, title, explanation, fix) = if let Some(port) = mismatched_port(c, probe) {
        (
            "pod.probe.port_mismatch",
            format!(
                "{k} probe of container {name:?} checks port {port}, which the container does not expose"
            ),
            format!(
                "The probe targets port {port}, but the container declares containerPort(s): {declared_text}. Nothing answers there, so the probe can never succeed and {effect}."
            ),
            format!(
                "Point the probe at the port the app listens on (declared: {declared_text}), preferably by name, or fix containerPort if the app really listens on {port}."
            ),
        )
    } else if timeout <= 1 && TIMEOUT.is_match(&text) {
        (
            "pod.probe.timeout_too_low",
            format!("{k} probe of container {name:?} times out after {timeout}s"),
            format!("The endpoint answers more slowly than timeoutSeconds={timeout} (the default), so the kubelet counts each slow answer as a failure and {effect}."),
            "Raise timeoutSeconds (for example to 5) and make the probe endpoint cheap: it should not call databases or other dependencies.".to_owned(),
        )
    } else if kind == Kind::Startup {
        (
            "pod.probe.startup_too_short",
            format!("startup probe of container {name:?} gives the app only {budget}s to start"),
            format!("The startup probe allows initialDelaySeconds + failureThreshold × periodSeconds = {budget}s, and the app is not healthy within that time, so {effect}."),
            "Raise failureThreshold (or periodSeconds) so the budget covers the slowest observed start, and keep liveness strict. If the app never becomes healthy, its logs show whether it is failing rather than slow.".to_owned(),
        )
    } else if kind == Kind::Liveness {
        (
            "pod.probe.liveness_failing",
            format!("liveness probe of container {name:?} is failing and the kubelet restarts it"),
            format!("The liveness probe ({}) keeps failing, so {effect}. The crash loop that follows is a symptom.", action(probe)),
            "Check the probed endpoint from inside the pod. Keep liveness shallow (process health only, never dependencies) and give slow starters a startupProbe instead of a long initialDelaySeconds.".to_owned(),
        )
    } else {
        (
            "pod.probe.readiness_failing",
            format!("readiness probe of container {name:?} is failing: the pod receives no traffic"),
            format!("The readiness probe ({}) keeps failing, so {effect}.", action(probe)),
            "Check the probed endpoint: an HTTP status of 400 or more means the path or app state is wrong (404: wrong path). Readiness may check dependencies, but then a dependency outage removes every pod from its Service.".to_owned(),
        )
    };

    let severity = if kind == Kind::Readiness {
        Severity::High
    } else if kill.is_some() || st.restart_count > 0 {
        Severity::Critical
    } else {
        Severity::High
    };
    let mut f = Finding::new(id, severity, Confidence::High, title)
        .explain(explanation)
        .evidence(
            Source::Spec,
            format!(
                "{k}Probe {} timeoutSeconds={timeout} periodSeconds={} failureThreshold={} initialDelaySeconds={}",
                action(probe),
                probe.period_seconds.unwrap_or(10),
                probe.failure_threshold.unwrap_or(3),
                probe.initial_delay_seconds.unwrap_or(0)
            ),
        )
        .fix(fix)
        .docs(rule_docs(RULES, id));
    if id == "pod.probe.port_mismatch" {
        f = f.evidence(Source::Spec, format!("containerPorts: {declared_text}"));
    }
    if let Some(e) = latest(fails.iter().copied()) {
        f = f.evidence(Source::Event, quote_event(e, ev.now));
    }
    if let Some(e) = kill {
        f = f.evidence(Source::Event, quote_event(e, ev.now));
    }
    f = f
        .evidence(
            Source::Status,
            format!("ready={} restartCount={}", st.ready, st.restart_count),
        )
        .next(
            "get_logs",
            logs_args(&ev.pod, name, st.restart_count > 0),
            "see what the app logs while the probe fails",
        )
        .next(
            "list_events",
            pod_events_args(&ev.pod),
            "see the probe failures in order",
        );
    out.push(f);

    // A refused connection with no startup probe may just be a slow start: say so, as a hint.
    if id == "pod.probe.liveness_failing" && refused && c.startup_probe.is_none() {
        out.push(
            Finding::new("pod.probe.startup_too_short", Severity::Medium, Confidence::Low, format!("container {name:?} may be killed before it finishes starting"))
                .explain(format!("The liveness probe sees `connection refused` and there is no startupProbe, so an app that takes longer than {budget}s to open its port is killed before it is up."))
                .fix("If the app is slow to start, add a startupProbe with the same check and a generous failureThreshold; if it never opens the port, fix the port or the app.")
                .docs(docs::PROBES),
        );
    }
}

/// The probe's port if no `containerPort` matches it: a number when the container declares
/// ports, or a name when no port has that name.
fn mismatched_port(c: &Container, probe: &Probe) -> Option<String> {
    let port = probe
        .http_get
        .as_ref()
        .map(|h| h.port.clone())
        .or_else(|| probe.tcp_socket.as_ref().map(|t| t.port.clone()))
        .or_else(|| probe.grpc.as_ref().map(|g| IntOrString::Int(g.port)))?;
    let ports = c.ports.as_deref().unwrap_or_default();
    match port {
        IntOrString::Int(n) => (!ports.is_empty() && !ports.iter().any(|p| p.container_port == n))
            .then(|| n.to_string()),
        IntOrString::String(name) => (!ports
            .iter()
            .any(|p| p.name.as_deref() == Some(name.as_str())))
        .then_some(name),
    }
}

/// Short description of the probe action, e.g. `httpGet :8080/healthz`.
fn action(probe: &Probe) -> String {
    let port = |p: &IntOrString| match p {
        IntOrString::Int(n) => n.to_string(),
        IntOrString::String(s) => s.clone(),
    };
    if let Some(h) = &probe.http_get {
        format!(
            "httpGet :{}{}",
            port(&h.port),
            h.path.as_deref().unwrap_or("/")
        )
    } else if let Some(t) = &probe.tcp_socket {
        format!("tcpSocket :{}", port(&t.port))
    } else if let Some(g) = &probe.grpc {
        format!("grpc :{}", g.port)
    } else {
        "exec".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::pod_fixture;

    fn run(fixture: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        check(&pod_fixture(fixture), &mut out);
        out
    }

    fn ids(fixture: &str) -> Vec<String> {
        run(fixture).into_iter().map(|f| f.id).collect()
    }

    #[test]
    fn liveness_on_undeclared_port_is_port_mismatch_only() {
        let out = run("pods/probe-port-mismatch.yaml");
        assert_eq!(out.len(), 1, "no separate liveness_failing finding");
        let f = &out[0];
        assert_eq!(
            (f.id.as_str(), f.severity),
            ("pod.probe.port_mismatch", Severity::Critical)
        );
        assert!(f.title.contains("port 8080"), "{}", f.title);
        assert!(
            f.evidence
                .iter()
                .any(|e| e.text == "containerPorts: 80 (http)")
        );
    }

    #[test]
    fn readiness_404_is_readiness_failing() {
        let out = run("pods/probe-readiness-404.yaml");
        assert_eq!(out.len(), 1);
        assert_eq!(
            (out[0].id.as_str(), out[0].severity),
            ("pod.probe.readiness_failing", Severity::High)
        );
        assert!(
            out[0]
                .evidence
                .iter()
                .any(|e| e.source == Source::Event && e.text.contains("statuscode: 404"))
        );
    }

    #[test]
    fn recovered_readiness_is_ignored() {
        let mut ev = pod_fixture("pods/probe-readiness-404.yaml");
        ev.pod
            .status
            .as_mut()
            .unwrap()
            .container_statuses
            .as_mut()
            .unwrap()[0]
            .ready = true;
        let mut out = Vec::new();
        check(&ev, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn deadline_with_default_timeout_is_timeout_too_low() {
        assert_eq!(
            ids("pods/probe-timeout.yaml"),
            ["pod.probe.timeout_too_low"]
        );
    }

    #[test]
    fn startup_probe_budget_exhausted() {
        let out = run("pods/probe-startup.yaml");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "pod.probe.startup_too_short");
        assert!(out[0].title.contains("only 30s"), "{}", out[0].title);
    }

    #[test]
    fn refused_liveness_without_ports_adds_slow_start_hint() {
        let out = run("pods/probe-liveness-refused.yaml");
        let got: Vec<_> = out.iter().map(|f| (f.id.as_str(), f.severity)).collect();
        assert_eq!(
            got,
            [
                ("pod.probe.liveness_failing", Severity::Critical),
                ("pod.probe.startup_too_short", Severity::Medium)
            ]
        );
    }

    #[test]
    fn pods_without_probe_events_are_ignored() {
        for f in [
            "pods/healthy.yaml",
            "pods/crashloop-exit1.yaml",
            "pods/image-not-found.yaml",
        ] {
            assert!(ids(f).is_empty(), "{f}");
        }
    }
}
