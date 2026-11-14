//! Image pull failures (PROPOSAL §9.2), classified from the kubelet's pull error.
//!
//! Patterns are tried in a fixed order: invalid name, platform, rate limit, auth, not found,
//! network. Auth comes before not-found because Docker Hub answers a private (or missing)
//! repository with `pull access denied, repository does not exist or may require
//! authorization`, while a missing tag (`nginx:doesnotexist`) ends in a plain `: not found`.

use std::sync::LazyLock;

use k8s_mcp_core::finding::{Confidence, Finding, RuleMeta, Severity, Source};
use k8s_mcp_core::text::truncate;
use k8s_openapi::api::core::v1::{Container, ContainerStatus, Event};
use regex::Regex;
use serde_json::json;

use super::{
    about_container, all_containers, docs, events_with, last_seen, msg, pod_events_args, pod_ref,
    quote_event, resource_args, rule_docs, service_account_name, waiting_message, waiting_reason,
};
use crate::evidence::{PodEvidence, RefKind};

/// Rules emitted by this module.
pub const RULES: &[RuleMeta] = &[
    RuleMeta {
        id: "pod.image.not_found",
        title: "Image tag or repository does not exist",
        docs: docs::IMAGES,
    },
    RuleMeta {
        id: "pod.image.auth",
        title: "Registry refused the pull: missing or invalid credentials",
        docs: docs::PULL_SECRET,
    },
    RuleMeta {
        id: "pod.image.network",
        title: "Node cannot reach the image registry",
        docs: docs::IMAGES,
    },
    RuleMeta {
        id: "pod.image.rate_limited",
        title: "Registry rate-limited the image pull",
        docs: docs::IMAGES,
    },
    RuleMeta {
        id: "pod.image.invalid_name",
        title: "Image reference is not valid",
        docs: docs::IMAGES,
    },
    RuleMeta {
        id: "pod.image.platform",
        title: "Image has no build for the node's OS/architecture",
        docs: docs::IMAGES,
    },
    RuleMeta {
        id: "pod.image.pull_failed",
        title: "Image cannot be pulled (unclassified pull error)",
        docs: docs::IMAGES,
    },
];

/// Waiting reasons that mean the image is not available.
const PULL_REASONS: &[&str] = &[
    "ErrImagePull",
    "ImagePullBackOff",
    "InvalidImageName",
    "ErrImageNeverPull",
    "RegistryUnavailable",
    "ErrRegistryUnavailable",
    "ImageInspectError",
];

fn re(pattern: &str) -> Regex {
    #[allow(clippy::unwrap_used)] // constant patterns, covered by tests
    Regex::new(pattern).unwrap()
}

/// (rule id, pattern), in match order.
static PATTERNS: LazyLock<Vec<(&str, Regex)>> = LazyLock::new(|| {
    vec![
        (
            "pod.image.invalid_name",
            re(r"(?i)invalid reference format|couldn't parse image"),
        ),
        (
            "pod.image.platform",
            re(r"(?i)no match for platform|no matching manifest for"),
        ),
        (
            "pod.image.rate_limited",
            re(r"(?i)toomanyrequests|too many requests|\b429\b|rate limit"),
        ),
        (
            "pod.image.auth",
            re(
                r"(?i)unauthorized|\b40[13]\b|denied|authentication required|authorization failed|no basic auth credentials|failed to authorize|forbidden",
            ),
        ),
        (
            "pod.image.not_found",
            re(r"(?i)not found|manifest unknown|name unknown|repository does not exist"),
        ),
        (
            "pod.image.network",
            re(
                r"(?i)no such host|i/o timeout|connection refused|tls handshake|x509|network is unreachable|connection reset|dial tcp",
            ),
        ),
    ]
});

/// Classify a pull error message; `None` if no pattern matches.
pub fn classify(message: &str) -> Option<&'static str> {
    PATTERNS
        .iter()
        .find(|(_, re)| re.is_match(message))
        .map(|(id, _)| *id)
}

/// Check every init and main container waiting on its image.
pub fn check(ev: &PodEvidence, out: &mut Vec<Finding>) {
    for (c, st) in all_containers(&ev.pod) {
        if let Some(st) = st
            && waiting_reason(st).is_some_and(|r| PULL_REASONS.contains(&r))
        {
            out.push(finding(ev, c, st));
        }
    }
}

fn finding(ev: &PodEvidence, c: &Container, st: &ContainerStatus) -> Finding {
    let waiting = waiting_reason(st).unwrap_or("");
    let waiting_msg = waiting_message(st).unwrap_or("");
    let mut failed: Vec<&Event> = events_with(
        &ev.events,
        &["Failed", "InspectFailed", "ErrImageNeverPull"],
    )
    .filter(|e| about_container(e, &c.name))
    .collect();
    failed.sort_by_key(|e| std::cmp::Reverse(last_seen(e)));
    // The newest message that classifies wins; the waiting message may only say "Back-off".
    let classified = failed
        .iter()
        .map(|e| (classify(msg(e)), Some(*e)))
        .chain([(classify(waiting_msg), None)])
        .find(|(id, _)| id.is_some());
    let (id, event) = match (waiting, classified) {
        ("InvalidImageName", _) => ("pod.image.invalid_name", None),
        (_, Some((Some(id), e))) => (id, e),
        _ => ("pod.image.pull_failed", None),
    };
    let event = event.or_else(|| failed.first().copied());

    let image = c.image.as_deref().unwrap_or("");
    let shown = if safe_image(image) {
        format!("image {image:?}")
    } else {
        format!("the image of container {:?}", c.name)
    };
    let host = if safe_image(image) {
        registry_host(image)
    } else {
        "the registry"
    };
    let (title, explanation, fix) = match id {
        "pod.image.not_found" => (
            format!("{shown} not found: the tag or repository does not exist"),
            "The registry answered that this image reference does not exist. Usually the tag is misspelled, was never pushed, or was deleted.".to_owned(),
            format!("Check that the tag exists in {host} (`docker manifest inspect <image>` or the registry UI), fix typos in the repository or tag, and prefer immutable tags or digests."),
        ),
        "pod.image.auth" => (
            format!("registry {host} refused to serve {shown}: missing or invalid credentials"),
            "The registry requires authentication for this image and the node had no valid credentials for it. Credentials come from imagePullSecrets on the pod or its ServiceAccount, or from the node's cloud identity.".to_owned(),
            format!("Create a docker-registry Secret for {host} (`kubectl create secret docker-registry regcred --docker-server={host} --docker-username=... --docker-password=... -n {ns}`) and list it in spec.imagePullSecrets or on ServiceAccount {sa}. If a Secret is already referenced, check it exists, is for {host}, and its credentials are valid. Cloud registries: ECR needs the node role to allow ecr:GetAuthorizationToken and ecr:BatchGetImage; Artifact Registry needs roles/artifactregistry.reader for the node service account; ACR needs `az aks update --attach-acr`.", ns = pod_ref(&ev.pod).1, sa = service_account_name(&ev.pod)),
        ),
        "pod.image.network" => (
            format!("node cannot reach {host} to pull {shown}"),
            "The pull failed at the network level (DNS, TCP or TLS) before the registry could answer. The image itself may be fine.".to_owned(),
            format!("From the node, check DNS resolution of {host} and HTTPS egress to it (NAT gateway, proxy, firewall, private endpoint). A registry with a private CA must be trusted by the node's container runtime."),
        ),
        "pod.image.rate_limited" => (
            format!("registry {host} rate-limited pulls of {shown}"),
            "The registry rejected the pull with a rate limit (HTTP 429 / toomanyrequests). Docker Hub limits anonymous pulls per source IP, so whole clusters behind one NAT hit it quickly.".to_owned(),
            "Authenticate pulls (an imagePullSecret for Docker Hub raises the limit), use a registry mirror or pull-through cache (ECR, Artifact Registry and ACR all offer one), or copy the image into your own registry. imagePullPolicy IfNotPresent avoids needless re-pulls.".to_owned(),
        ),
        "pod.image.invalid_name" => (
            format!("{shown} is not a valid image reference"),
            "The kubelet could not parse the image reference, so it never contacted a registry.".to_owned(),
            "Use `[registry/]repository[:tag]` or `repository@sha256:<digest>`: lowercase repository, no URL scheme (`https://`), no spaces or trailing characters.".to_owned(),
        ),
        "pod.image.platform" => (
            format!("{shown} has no build for the node's OS/architecture"),
            "The image exists but its manifest list has no entry for the node's platform (for example arm64 nodes and an amd64-only image).".to_owned(),
            "Publish a multi-arch image (`docker buildx build --platform linux/amd64,linux/arm64`), or pin the pod to matching nodes with nodeSelector `kubernetes.io/arch`.".to_owned(),
        ),
        _ => (
            format!("{shown} cannot be pulled"),
            "The kubelet cannot get the image, and the error did not match a known cause.".to_owned(),
            "Read the pull error quoted below. For ErrImageNeverPull the image must be preloaded on the node or imagePullPolicy changed from Never.".to_owned(),
        ),
    };

    let confidence = if id == "pod.image.pull_failed" {
        Confidence::Medium
    } else {
        Confidence::High
    };
    let mut f = Finding::new(id, Severity::Critical, confidence, title)
        .explain(explanation)
        .evidence(
            Source::Status,
            format!(
                "container {:?} waiting: {waiting}: {}",
                c.name,
                truncate(waiting_msg, 300)
            ),
        )
        .evidence(Source::Spec, format!("image: {}", truncate(image, 200)))
        .fix(fix)
        .docs(rule_docs(RULES, id))
        .next(
            "list_events",
            pod_events_args(&ev.pod),
            "see every pull attempt and its error",
        );
    if let Some(e) = event {
        f = f.evidence(Source::Event, quote_event(e, ev.now));
    }
    if id == "pod.image.auth" {
        f = pull_secret_evidence(ev, f);
    }
    let node = ev.node.as_ref().and_then(|n| n.metadata.name.as_deref());
    if matches!(id, "pod.image.network" | "pod.image.platform")
        && let Some(node) = node
    {
        f = f.next(
            "diagnose_node",
            json!({ "name": node }),
            "check the node's network and platform",
        );
    }
    if id == "pod.image.platform"
        && let Some(arch) = ev
            .node
            .as_ref()
            .and_then(|n| n.metadata.labels.as_ref()?.get("kubernetes.io/arch"))
    {
        f = f.evidence(
            Source::Related,
            format!("node {} has kubernetes.io/arch={arch}", node.unwrap_or("")),
        );
    }
    f
}

/// Say which imagePullSecrets the pod and its ServiceAccount carry, and whether they exist.
fn pull_secret_evidence(ev: &PodEvidence, mut f: Finding) -> Finding {
    let (_, ns) = pod_ref(&ev.pod);
    let sa = service_account_name(&ev.pod);
    let pod_secrets: Vec<&str> = ev
        .pod
        .spec
        .as_ref()
        .and_then(|s| s.image_pull_secrets.as_ref())
        .into_iter()
        .flatten()
        .map(|r| r.name.as_str())
        .collect();
    let list = |v: &[&str]| {
        if v.is_empty() {
            "none".to_owned()
        } else {
            v.join(", ")
        }
    };
    f = f.evidence(
        Source::Spec,
        format!("pod spec.imagePullSecrets: {}", list(&pod_secrets)),
    );
    let mut all = pod_secrets;
    if let Some(account) = &ev.service_account {
        let sa_secrets: Vec<&str> = account
            .image_pull_secrets
            .iter()
            .flatten()
            .map(|r| r.name.as_str())
            .collect();
        f = f.evidence(
            Source::Related,
            format!(
                "ServiceAccount {sa} imagePullSecrets: {}",
                list(&sa_secrets)
            ),
        );
        all.extend(sa_secrets);
    } else {
        f.confidence = f.confidence.lower();
        f = f.evidence(
            Source::Unavailable,
            format!("ServiceAccount {sa} could not be read (its imagePullSecrets are unknown)"),
        );
    }
    all.sort_unstable();
    all.dedup();
    for name in all {
        let check = ev
            .refs
            .iter()
            .find(|r| r.kind == RefKind::Secret && r.name == name);
        f = match check.map(|r| r.exists) {
            Some(Some(true)) => f.evidence(Source::Related, format!("Secret {name} exists")),
            Some(Some(false)) => {
                f.evidence(Source::Related, format!("Secret {name} does not exist"))
            }
            Some(None) => f.evidence(
                Source::Unavailable,
                format!("could not check whether Secret {name} exists"),
            ),
            None => f,
        };
    }
    for e in events_with(&ev.events, &["FailedToRetrieveImagePullSecret"]) {
        f = f.evidence(Source::Event, quote_event(e, ev.now));
    }
    f.next(
        "get_resource",
        resource_args("ServiceAccount", sa, ns),
        "check the ServiceAccount's imagePullSecrets",
    )
}

/// True if an image reference only uses reference characters, so it is safe to echo.
fn safe_image(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'/' | b':' | b'@')
        })
}

/// Registry host of an image reference (`docker.io` when none is given).
fn registry_host(image: &str) -> &str {
    match image.split_once('/') {
        Some((first, _)) if first.contains(['.', ':']) || first == "localhost" => first,
        _ => "docker.io",
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
    fn missing_tag_is_not_found() {
        let out = run(&pod_fixture("pods/image-not-found.yaml"));
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.id, "pod.image.not_found");
        assert!(f.title.contains("\"nginx:doesnotexist\""), "{}", f.title);
        assert!(
            f.evidence
                .iter()
                .any(|e| e.source == Source::Event && e.text.contains("not found"))
        );
    }

    #[test]
    fn private_image_without_pull_secret_is_auth() {
        let out = run(&pod_fixture("pods/image-auth.yaml"));
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.id, "pod.image.auth");
        assert!(f.title.contains("ghcr.io"), "{}", f.title);
        let texts: Vec<_> = f.evidence.iter().map(|e| e.text.as_str()).collect();
        assert!(
            texts.contains(&"pod spec.imagePullSecrets: none"),
            "{texts:?}"
        );
        assert!(
            texts.contains(&"ServiceAccount default imagePullSecrets: none"),
            "{texts:?}"
        );
    }

    #[test]
    fn pull_messages_classify_in_order() {
        let cases = [
            (
                "docker.io/library/nginx:doesnotexist: not found",
                "pod.image.not_found",
            ),
            (
                "failed to resolve reference \"docker.io/acme/private:1.0\": pull access denied, repository does not exist or may require authorization: server message: insufficient_scope: authorization failed",
                "pod.image.auth",
            ),
            (
                "failed to fetch anonymous token: unexpected status from GET request to https://ghcr.io/token: 401 Unauthorized",
                "pod.image.auth",
            ),
            (
                "toomanyrequests: You have reached your pull rate limit.",
                "pod.image.rate_limited",
            ),
            (
                "dial tcp: lookup registry.internal on 10.96.0.10:53: no such host",
                "pod.image.network",
            ),
            (
                "no match for platform in manifest: not found",
                "pod.image.platform",
            ),
            (
                "Failed to apply default image tag \"Nginx\": couldn't parse image reference \"Nginx\": invalid reference format",
                "pod.image.invalid_name",
            ),
            ("manifest unknown: manifest unknown", "pod.image.not_found"),
        ];
        let base = pod_fixture("pods/image-not-found.yaml");
        for (message, want) in cases {
            let mut ev = base.clone();
            ev.events[0].message = Some(message.into());
            assert_eq!(run(&ev)[0].id, want, "{message}");
        }
        assert_eq!(classify("Back-off pulling image \"x\""), None);
    }

    #[test]
    fn unclassified_and_invalid_name_reasons() {
        let mut ev = pod_fixture("pods/image-not-found.yaml");
        ev.events.clear();
        let f = &run(&ev)[0];
        assert_eq!(
            (f.id.as_str(), f.confidence),
            ("pod.image.pull_failed", Confidence::Medium)
        );

        let st = &mut ev
            .pod
            .status
            .as_mut()
            .unwrap()
            .container_statuses
            .as_mut()
            .unwrap()[0];
        st.state.as_mut().unwrap().waiting.as_mut().unwrap().reason =
            Some("InvalidImageName".into());
        assert_eq!(run(&ev)[0].id, "pod.image.invalid_name");
    }

    #[test]
    fn non_pull_states_are_ignored() {
        for f in [
            "pods/healthy.yaml",
            "pods/config-missing-configmap.yaml",
            "pods/crashloop-exit1.yaml",
        ] {
            assert!(run(&pod_fixture(f)).is_empty(), "{f}");
        }
    }

    #[test]
    fn registry_hosts() {
        assert_eq!(registry_host("nginx:1.27"), "docker.io");
        assert_eq!(registry_host("acme/app:1"), "docker.io");
        assert_eq!(registry_host("ghcr.io/acme/app:1"), "ghcr.io");
        assert_eq!(registry_host("localhost:5000/app"), "localhost:5000");
    }
}
