//! Configuration errors (PROPOSAL §9.2): missing ConfigMaps, Secrets, keys and
//! ServiceAccounts, unresolvable env references, and runtime container-creation failures.
//!
//! Signals: `waiting.reason` CreateContainerConfigError / CreateContainerError /
//! RunContainerError with its message, kubelet `Failed`/`FailedMount` events, and the
//! existence checks in `ev.refs`. [`parse_issue`] is shared with [`super::creating`] (so a
//! FailedMount caused by a missing ConfigMap is reported once, here) and with
//! [`super::rollout`] (ReplicaSet `FailedCreate` for a missing ServiceAccount).

use std::sync::LazyLock;

use k8s_mcp_core::finding::{Confidence, Finding, RuleMeta, Severity, Source};
use k8s_mcp_core::text::truncate;
use k8s_openapi::api::core::v1::{Container, Pod};
use regex::Regex;
use serde_json::json;

use super::{
    all_containers, dns_name, docs, events_with, msg, pod_events_args, pod_ref, quote_event,
    resource_args, rule_docs, service_account_name, waiting_message, waiting_reason,
};
use crate::evidence::{PodEvidence, RefKind};

/// Rules emitted by this module.
pub const RULES: &[RuleMeta] = &[
    RuleMeta {
        id: "pod.config.missing_configmap",
        title: "A ConfigMap referenced by the pod does not exist",
        docs: docs::CONFIGMAP,
    },
    RuleMeta {
        id: "pod.config.missing_secret",
        title: "A Secret referenced by the pod does not exist",
        docs: docs::SECRET,
    },
    RuleMeta {
        id: "pod.config.missing_key",
        title: "A key referenced from a ConfigMap or Secret does not exist",
        docs: docs::CONFIGMAP,
    },
    RuleMeta {
        id: "pod.config.invalid_env_ref",
        title: "An environment variable reference cannot be resolved",
        docs: docs::CONFIGMAP,
    },
    RuleMeta {
        id: "pod.config.mount_failed",
        title: "Container cannot start because a volume mount failed",
        docs: docs::DEBUG_PODS,
    },
    RuleMeta {
        id: "pod.config.missing_serviceaccount",
        title: "The pod's ServiceAccount does not exist",
        docs: docs::SERVICE_ACCOUNT,
    },
    RuleMeta {
        id: "pod.config.create_container_error",
        title: "The container runtime could not create or start the container",
        docs: docs::DEBUG_PODS,
    },
];

/// A configuration problem named by a kubelet or API server message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Issue {
    /// A ConfigMap, Secret or ServiceAccount that does not exist (name passed [`dns_name`]).
    Missing(RefKind, String),
    /// A key missing from a ConfigMap or Secret. The object name and key are `None` when the
    /// message did not carry a safe value.
    MissingKey(RefKind, Option<String>, Option<String>),
    /// An env var `fieldRef`/`resourceFieldRef` the kubelet could not resolve.
    InvalidEnvRef,
}

#[allow(clippy::unwrap_used)] // constant patterns
static KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"couldn't find key (\S+) in (ConfigMap|Secret) [^/\s]+/([^\s:,]+)").unwrap()
});
#[allow(clippy::unwrap_used)]
static VOLUME_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(configmap|secret) references non-existent (?:config|secret) key: (\S+)").unwrap()
});
#[allow(clippy::unwrap_used)]
static MISSING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(configmap|secret|serviceaccount)s? "([^"]+)" not found"#).unwrap()
});
#[allow(clippy::unwrap_used)]
static ENV_REF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)unsupported fieldpath|field label not supported|container resource").unwrap()
});
#[allow(clippy::unwrap_used)]
static MOUNT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)subpath|mount|not a directory|read-only file system").unwrap()
});

/// Classify a kubelet/API message into a configuration [`Issue`].
pub fn parse_issue(message: &str) -> Option<Issue> {
    let kind = |k: &str| {
        if k.eq_ignore_ascii_case("secret") {
            RefKind::Secret
        } else if k.eq_ignore_ascii_case("serviceaccount") {
            RefKind::ServiceAccount
        } else {
            RefKind::ConfigMap
        }
    };
    let safe_name = |s: &str| dns_name(s).then(|| s.to_owned());
    if let Some(c) = KEY.captures(message) {
        return Some(Issue::MissingKey(
            kind(&c[2]),
            safe_name(&c[3]),
            config_key(&c[1]).then(|| c[1].to_owned()),
        ));
    }
    if let Some(c) = VOLUME_KEY.captures(message) {
        return Some(Issue::MissingKey(
            kind(&c[1]),
            None,
            config_key(&c[2]).then(|| c[2].to_owned()),
        ));
    }
    if let Some(c) = MISSING.captures(message) {
        return safe_name(&c[2]).map(|n| Issue::Missing(kind(&c[1]), n));
    }
    ENV_REF.is_match(message).then_some(Issue::InvalidEnvRef)
}

/// True if `s` is a valid ConfigMap/Secret key (`[-._a-zA-Z0-9]+`), so safe to echo.
fn config_key(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
}

fn kind_name(k: RefKind) -> &'static str {
    match k {
        RefKind::ConfigMap => "ConfigMap",
        RefKind::Secret => "Secret",
        RefKind::PersistentVolumeClaim => "PersistentVolumeClaim",
        RefKind::ServiceAccount => "ServiceAccount",
    }
}

/// Check container states, events and reference existence.
pub fn check(ev: &PodEvidence, out: &mut Vec<Finding>) {
    let mut found: Vec<(Issue, Finding)> = Vec::new();
    for (c, st) in all_containers(&ev.pod) {
        let Some(st) = st else { continue };
        let Some(r @ ("CreateContainerConfigError" | "CreateContainerError" | "RunContainerError")) =
            waiting_reason(st)
        else {
            continue;
        };
        let message = waiting_message(st).unwrap_or("");
        let status = format!(
            "container {:?} waiting: {r}: {}",
            c.name,
            truncate(message, 300)
        );
        match parse_issue(message) {
            Some(issue) => add(ev, &mut found, issue, Source::Status, status),
            None => out.push(runtime_error(ev, c, status, message)),
        }
    }
    for e in events_with(&ev.events, &["Failed", "FailedMount"]) {
        if let Some(issue) = parse_issue(msg(e)) {
            add(ev, &mut found, issue, Source::Event, quote_event(e, ev.now));
        }
    }
    for r in ev.refs.iter().filter(|r| r.exists == Some(false)) {
        let issue = Issue::Missing(r.kind, r.name.clone());
        if r.kind == RefKind::PersistentVolumeClaim || found.iter().any(|(i, _)| *i == issue) {
            continue;
        }
        let refs = references(&ev.pod, r.kind, &r.name);
        let required = if r.kind == RefKind::ServiceAccount {
            service_account_name(&ev.pod) == r.name
        } else {
            !refs.is_empty() && refs.iter().all(|x| !x.optional)
        };
        if required {
            let mut f = issue_finding(&issue, pod_ref(&ev.pod).1);
            f.severity = Severity::High;
            f.confidence = Confidence::Medium;
            f.title = format!("{} (the pod fails at its next start)", f.title);
            f.explanation.push_str(" The pod is not failing yet because the reference is only resolved when a container starts or a volume is refreshed.");
            out.push(with_spec_evidence(ev, &issue, f));
        }
    }
    out.extend(found.into_iter().map(|(_, f)| f));
    for e in events_with(&ev.events, &["InvalidEnvironmentVariableNames"]) {
        out.push(
            Finding::new("pod.config.invalid_env_ref", Severity::Medium, Confidence::High, "some envFrom keys were skipped: they are not valid environment variable names")
                .explain("The kubelet imports every key of an envFrom ConfigMap/Secret as an environment variable, and silently skips keys that are not valid variable names. The application may be missing settings it expects.")
                .evidence(Source::Event, quote_event(e, ev.now))
                .fix("Rename the keys to valid variable names (letters, digits, `_`), set an envFrom `prefix`, or mount the ConfigMap/Secret as a volume and read the files instead.")
                .docs(docs::CONFIGMAP),
        );
    }
}

/// Merge `trigger` into the finding for `issue`, creating it on first sight.
fn add(
    ev: &PodEvidence,
    found: &mut Vec<(Issue, Finding)>,
    issue: Issue,
    source: Source,
    trigger: String,
) {
    if let Some((_, f)) = found.iter_mut().find(|(i, _)| *i == issue) {
        f.evidence.push(k8s_mcp_core::finding::Evidence {
            source,
            text: trigger,
        });
        return;
    }
    let f = issue_finding(&issue, pod_ref(&ev.pod).1).evidence(source, trigger);
    let f = with_spec_evidence(ev, &issue, f);
    found.push((issue, f));
}

/// Add the pod-spec locations referencing the object and its existence check.
fn with_spec_evidence(ev: &PodEvidence, issue: &Issue, mut f: Finding) -> Finding {
    let (kind, name, key) = match issue {
        Issue::Missing(k, n) => (*k, Some(n), None),
        Issue::MissingKey(k, n, key) => (*k, n.as_ref(), key.as_ref()),
        Issue::InvalidEnvRef => return f,
    };
    if kind == RefKind::ServiceAccount {
        return f.evidence(
            Source::Spec,
            format!("spec.serviceAccountName={}", service_account_name(&ev.pod)),
        );
    }
    let refs = match name {
        Some(n) => references(&ev.pod, kind, n),
        None => Vec::new(),
    };
    for r in refs
        .iter()
        .filter(|r| key.is_none_or(|k| r.keys.is_empty() || r.keys.contains(k)))
    {
        f = f.evidence(
            Source::Spec,
            format!(
                "referenced by {}{}",
                r.place,
                if r.optional { " (optional)" } else { "" }
            ),
        );
    }
    let Some(name) = name else { return f };
    let Some(check) = ev.refs.iter().find(|r| r.kind == kind && r.name == *name) else {
        return f;
    };
    let k = kind_name(kind);
    match (check.exists, &check.keys) {
        (Some(false), _) => f.evidence(Source::Related, format!("{k} {name} does not exist")),
        (Some(true), Some(keys)) if key.is_some() => f.evidence(
            Source::Related,
            format!("{k} {name} exists with keys: {}", keys.join(", ")),
        ),
        (Some(true), _) if matches!(issue, Issue::Missing(..)) => {
            f.confidence = f.confidence.lower();
            f.evidence(
                Source::Related,
                format!("{k} {name} exists now; the kubelet retries, so the error should clear"),
            )
        }
        (None, _) => {
            f.confidence = f.confidence.lower();
            f.evidence(
                Source::Unavailable,
                format!("could not check whether {k} {name} exists"),
            )
        }
        _ => f,
    }
}

/// The base finding for an [`Issue`] in namespace `ns` (critical; callers add evidence).
pub fn issue_finding(issue: &Issue, ns: &str) -> Finding {
    let missing = |id: &str, k: &str, name: &str| {
        Finding::new(id, Severity::Critical, Confidence::High, format!("{k} {name:?} does not exist"))
            .explain(format!("The pod references {k} {name:?} in namespace {ns}, but it does not exist, so the kubelet cannot start the containers (or mount the volume) that need it. The pod stays stuck until it is created."))
            .fix(format!("Create {k} {name} in namespace {ns} (or fix the name in the references listed below). If the pod can run without it, mark the reference `optional: true`."))
            .docs(rule_docs(RULES, id))
            .next("list_resources", json!({"kind": k, "namespace": ns}), &format!("see which {k}s exist (typo in the name?)"))
    };
    match issue {
        Issue::Missing(RefKind::Secret, n) => missing("pod.config.missing_secret", "Secret", n),
        Issue::Missing(RefKind::ServiceAccount, n) => Finding::new("pod.config.missing_serviceaccount", Severity::Critical, Confidence::High, format!("ServiceAccount {n:?} does not exist"))
            .explain(format!("The pod runs as ServiceAccount {n:?} in namespace {ns}, which does not exist. New pods are rejected at admission and existing pods cannot refresh their API token."))
            .fix(format!("Create it (`kubectl create serviceaccount {n} -n {ns}`) or set spec.serviceAccountName to an existing ServiceAccount."))
            .docs(docs::SERVICE_ACCOUNT)
            .next("list_resources", json!({"kind": "ServiceAccount", "namespace": ns}), "see which ServiceAccounts exist"),
        Issue::Missing(_, n) => missing("pod.config.missing_configmap", "ConfigMap", n),
        Issue::MissingKey(kind, name, key) => {
            let k = kind_name(*kind);
            let key_text = key.as_deref().map_or_else(|| "a referenced key".to_owned(), |key| format!("key {key:?}"));
            let obj = name.as_deref().map_or_else(|| format!("its {k}"), |n| format!("{k} {n:?}"));
            let mut f = Finding::new("pod.config.missing_key", Severity::Critical, Confidence::High, format!("{key_text} is missing from {obj}"))
                .explain(format!("The {k} exists, but the pod references a key it does not contain, so the kubelet refuses to start the container (env keyRef) or to mount the volume (items)."))
                .fix(format!("Add {key_text} to {obj}, or fix the key name in the reference. If the value is not required, set `optional: true` on the keyRef."))
                .docs(if *kind == RefKind::Secret { docs::SECRET } else { docs::CONFIGMAP });
            if let Some(n) = name {
                f = f.next("get_resource", resource_args(k, n, ns), &format!("list the keys {k} {n} actually has (values are never shown)"));
            }
            f
        }
        Issue::InvalidEnvRef => Finding::new("pod.config.invalid_env_ref", Severity::Critical, Confidence::High, "an env var fieldRef/resourceFieldRef cannot be resolved")
            .explain("A `valueFrom.fieldRef` or `resourceFieldRef` names a field or resource the kubelet cannot resolve, so the container is not created.")
            .fix("Use a supported fieldPath (metadata.name, metadata.namespace, metadata.labels['k'], status.podIP, spec.nodeName, ...) or a resource of the same container (limits.cpu, requests.memory, ...).")
            .docs(docs::CONFIGMAP),
    }
}

/// A runtime failure that is not a missing object: mount problems or other create errors.
fn runtime_error(ev: &PodEvidence, c: &Container, status: String, message: &str) -> Finding {
    let name = &c.name;
    let lower = message.to_ascii_lowercase();
    let (id, title, explanation, fix) = if MOUNT.is_match(message) {
        (
            "pod.config.mount_failed",
            format!("container {name:?} cannot start: a volume mount failed"),
            "The runtime could not set up one of the container's volume mounts, so the container is never created.",
            "Check the container's volumeMounts: a `subPath` must exist in the volume, a file cannot be mounted over a directory (or the reverse), and a read-only volume cannot back a path the image writes to.",
        )
    } else {
        let fix = if lower.contains("exec format error") {
            "The image was built for another CPU architecture than the node. Publish a multi-arch image, or pin the pod to matching nodes with nodeSelector `kubernetes.io/arch`."
        } else if lower.contains("runasnonroot") || lower.contains("run as root") {
            "securityContext.runAsNonRoot is true but the image runs as root. Set `securityContext.runAsUser` to a non-zero UID, or use an image whose USER is non-root."
        } else if lower.contains("executable file not found")
            || lower.contains("no such file or directory")
        {
            "The command does not exist in the image. Check `command`/`args` against the image (`docker run --entrypoint sh <image>`) and use the right path."
        } else if lower.contains("already in use") {
            "A stale container with the same name still exists in the runtime; this usually clears on retry. If it persists, inspect the node's container runtime (diagnose_node)."
        } else {
            "Read the runtime message below; it names the failing step. Common causes are a bad command, a security context the image cannot satisfy, and device or mount options the node does not support."
        };
        (
            "pod.config.create_container_error",
            format!("container {name:?} cannot be created by the container runtime"),
            "The kubelet asked the container runtime to create or start the container and it failed before the process ran.",
            fix,
        )
    };
    Finding::new(id, Severity::Critical, Confidence::High, title)
        .explain(explanation)
        .evidence(Source::Status, status)
        .fix(fix)
        .docs(rule_docs(RULES, id))
        .next(
            "list_events",
            pod_events_args(&ev.pod),
            "see the runtime errors in order",
        )
}

/// A pod-spec location that references a ConfigMap or Secret.
struct Reference {
    place: String,
    keys: Vec<String>,
    optional: bool,
}

/// Every place in the pod spec that references ConfigMap or Secret `name`.
fn references(pod: &Pod, kind: RefKind, name: &str) -> Vec<Reference> {
    let mut out = Vec::new();
    let Some(spec) = pod.spec.as_ref() else {
        return out;
    };
    let mut push = |place: String, keys: Vec<String>, optional: Option<bool>| {
        out.push(Reference {
            place,
            keys,
            optional: optional.unwrap_or(false),
        });
    };
    for c in spec
        .init_containers
        .iter()
        .flatten()
        .chain(&spec.containers)
    {
        for e in c.env.iter().flatten() {
            let from = e.value_from.as_ref();
            let sel = match kind {
                RefKind::ConfigMap => from
                    .and_then(|v| v.config_map_key_ref.as_ref())
                    .map(|s| (&s.name, &s.key, s.optional)),
                RefKind::Secret => from
                    .and_then(|v| v.secret_key_ref.as_ref())
                    .map(|s| (&s.name, &s.key, s.optional)),
                _ => None,
            };
            if let Some((n, key, optional)) = sel
                && n == name
            {
                push(
                    format!("container {:?} env {} (key {key})", c.name, e.name),
                    vec![key.clone()],
                    optional,
                );
            }
        }
        for e in c.env_from.iter().flatten() {
            let sel = match kind {
                RefKind::ConfigMap => e.config_map_ref.as_ref().map(|s| (&s.name, s.optional)),
                RefKind::Secret => e.secret_ref.as_ref().map(|s| (&s.name, s.optional)),
                _ => None,
            };
            if let Some((n, optional)) = sel
                && n == name
            {
                push(format!("container {:?} envFrom", c.name), vec![], optional);
            }
        }
    }
    for v in spec.volumes.iter().flatten() {
        let direct = match kind {
            RefKind::ConfigMap => v
                .config_map
                .as_ref()
                .map(|s| (s.name.as_str(), &s.items, s.optional, "")),
            RefKind::Secret => v.secret.as_ref().map(|s| {
                let n = s.secret_name.as_deref().unwrap_or("");
                (n, &s.items, s.optional, "")
            }),
            _ => None,
        };
        let projected = v
            .projected
            .iter()
            .flat_map(|p| p.sources.iter().flatten())
            .filter_map(|p| match kind {
                RefKind::ConfigMap => p
                    .config_map
                    .as_ref()
                    .map(|s| (s.name.as_str(), &s.items, s.optional, " (projected)")),
                RefKind::Secret => p
                    .secret
                    .as_ref()
                    .map(|s| (s.name.as_str(), &s.items, s.optional, " (projected)")),
                _ => None,
            });
        for (n, items, optional, how) in direct.into_iter().chain(projected) {
            if n == name {
                let keys = items.iter().flatten().map(|k| k.key.clone()).collect();
                push(format!("volume {:?}{how}", v.name), keys, optional);
            }
        }
    }
    out
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
    fn parses_kubelet_messages() {
        let cm = |n: &str| Some(Issue::Missing(RefKind::ConfigMap, n.into()));
        assert_eq!(
            parse_issue("configmap \"app-config\" not found"),
            cm("app-config")
        );
        assert_eq!(
            parse_issue("Error: configmaps \"app-config\" not found"),
            cm("app-config")
        );
        assert_eq!(
            parse_issue("couldn't find key password in Secret eval-x/db-creds"),
            Some(Issue::MissingKey(
                RefKind::Secret,
                Some("db-creds".into()),
                Some("password".into())
            ))
        );
        assert_eq!(
            parse_issue(
                "MountVolume.SetUp failed for volume \"cfg\" : configmap references non-existent config key: app.yaml"
            ),
            Some(Issue::MissingKey(
                RefKind::ConfigMap,
                None,
                Some("app.yaml".into())
            ))
        );
        assert_eq!(
            parse_issue("failed to fetch token: serviceaccounts \"build-bot\" not found"),
            Some(Issue::Missing(RefKind::ServiceAccount, "build-bot".into()))
        );
        // Names that are not DNS names are never echoed.
        assert_eq!(parse_issue("secret \"Bad Name!\" not found"), None);
        assert_eq!(parse_issue("Back-off pulling image"), None);
    }

    #[test]
    fn missing_configmap_names_object_and_reference() {
        let out = run("pods/config-missing-configmap.yaml");
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.id, "pod.config.missing_configmap");
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.title.contains("\"app-config\""), "{}", f.title);
        assert!(
            f.evidence
                .iter()
                .any(|e| e.source == Source::Spec && e.text.contains("env APP_MODE (key mode)"))
        );
        assert!(f.evidence.iter().any(|e| e.source == Source::Event));
        assert!(
            f.evidence
                .iter()
                .any(|e| e.text == "ConfigMap app-config does not exist")
        );
    }

    #[test]
    fn missing_key_lists_existing_keys() {
        let out = run("pods/config-missing-key.yaml");
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.id, "pod.config.missing_key");
        assert!(
            f.title.contains("\"password\"") && f.title.contains("\"db-creds\""),
            "{}",
            f.title
        );
        assert!(
            f.evidence
                .iter()
                .any(|e| e.text.contains("exists with keys: username"))
        );
        assert_eq!(f.next[0].tool, "get_resource");
    }

    #[test]
    fn missing_secret_volume_from_failed_mount() {
        assert_eq!(
            ids("pods/config-missing-secret-volume.yaml"),
            ["pod.config.missing_secret"]
        );
    }

    #[test]
    fn missing_serviceaccount() {
        assert_eq!(
            ids("pods/config-missing-serviceaccount.yaml"),
            ["pod.config.missing_serviceaccount"]
        );
    }

    #[test]
    fn run_as_root_is_create_container_error() {
        let out = run("pods/config-run-as-root.yaml");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "pod.config.create_container_error");
        assert!(out[0].fix.contains("runAsUser"));
    }

    #[test]
    fn subpath_failure_is_mount_failed() {
        assert_eq!(ids("pods/config-subpath.yaml"), ["pod.config.mount_failed"]);
    }

    #[test]
    fn skipped_env_keys_are_invalid_env_ref() {
        let out = run("pods/config-invalid-env.yaml");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "pod.config.invalid_env_ref");
        assert_eq!(out[0].severity, Severity::Medium);
    }

    #[test]
    fn deleted_required_configmap_is_latent() {
        let out = run("pods/config-latent-missing.yaml");
        assert_eq!(out.len(), 1, "optional reference must not be reported");
        assert_eq!(out[0].id, "pod.config.missing_configmap");
        assert_eq!(out[0].severity, Severity::High);
        assert!(out[0].title.contains("\"feature-flags\""));
    }

    #[test]
    fn unrelated_pods_have_no_config_findings() {
        for f in [
            "pods/healthy.yaml",
            "pods/crashloop-exit1.yaml",
            "pods/image-not-found.yaml",
        ] {
            assert!(ids(f).is_empty(), "{f}");
        }
    }
}
