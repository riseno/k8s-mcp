//! `gke_identity_check`: GKE Workload Identity for a Kubernetes ServiceAccount. The
//! Kubernetes side (the `iam.gke.io/gcp-service-account` annotation) always runs; the cloud
//! side (the cluster's workload pool, node pool metadata modes, the Google service account and
//! its `roles/iam.workloadIdentityUser` binding) runs when credentials allow. Pure: the caller
//! fetches the facts.

use k8s_mcp_core::finding::{Confidence, Finding, RuleMeta, Severity, Source};
use k8s_mcp_provider::{IdentityCheck, IdentityReport, Report, WorkloadIdentity};
use serde_json::json;

/// The ServiceAccount annotation naming the Google service account.
pub const GSA_ANNOTATION: &str = "iam.gke.io/gcp-service-account";
/// The role that lets a Kubernetes ServiceAccount impersonate a Google service account.
pub const WI_USER_ROLE: &str = "roles/iam.workloadIdentityUser";

const DOCS_WI: &str = "https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity";

/// Rules emitted by the identity check.
pub const RULES: &[RuleMeta] = &[
    RuleMeta {
        id: "gke.wi.pool_missing",
        title: "Workload Identity is not enabled on the cluster",
        docs: DOCS_WI,
    },
    RuleMeta {
        id: "gke.wi.metadata_mode",
        title: "Node pools do not run the GKE metadata server",
        docs: DOCS_WI,
    },
    RuleMeta {
        id: "gke.wi.gsa_missing",
        title: "The annotated Google service account does not exist",
        docs: DOCS_WI,
    },
    RuleMeta {
        id: "gke.wi.gsa_disabled",
        title: "The annotated Google service account is disabled",
        docs: DOCS_WI,
    },
    RuleMeta {
        id: "gke.wi.binding_missing",
        title: "The Google service account does not grant workloadIdentityUser to the ServiceAccount",
        docs: DOCS_WI,
    },
];

/// The annotated Google service account.
#[derive(Debug, Clone, Default)]
pub struct GsaFacts {
    /// Email from the annotation.
    pub email: String,
    /// Whether it exists.
    pub exists: bool,
    /// Whether it is disabled.
    pub disabled: bool,
    /// Members of its `roles/iam.workloadIdentityUser` bindings.
    pub wi_users: Vec<String>,
}

/// What the Google Cloud APIs say.
#[derive(Debug, Clone, Default)]
pub struct CloudFacts {
    /// The cluster's workload pool (`<project>.svc.id.goog`); empty when Workload Identity is off.
    pub workload_pool: String,
    /// Autopilot clusters always run the GKE metadata server.
    pub autopilot: bool,
    /// Node pools and their workload metadata mode (`GKE_METADATA`, `GCE_METADATA`, or
    /// `MODE_UNSPECIFIED`, which follows the cluster's setting).
    pub node_pool_modes: Vec<(String, String)>,
    /// The annotated GSA, when there is an annotation.
    pub gsa: Option<GsaFacts>,
}

fn check(
    side: &'static str,
    check: &str,
    result: &'static str,
    detail: impl Into<String>,
) -> IdentityCheck {
    IdentityCheck {
        side,
        check: check.into(),
        result,
        detail: detail.into(),
    }
}

/// Turn the facts into checks and findings. `cloud` is `Err(reason)` when Google Cloud could
/// not be asked.
pub fn evaluate(
    k8s: &WorkloadIdentity,
    cloud: Result<&CloudFacts, &str>,
) -> Report<IdentityReport> {
    let meta = &k8s.service_account.metadata;
    let sa = meta.name.as_deref().unwrap_or("");
    let ns = meta.namespace.as_deref().unwrap_or("default");
    let subject = format!("ServiceAccount {ns}/{sa}");
    let gsa = meta
        .annotations
        .as_ref()
        .and_then(|a| a.get(GSA_ANNOTATION))
        .cloned();
    let mut checks = vec![match &gsa {
        Some(email) => check("kubernetes", "GSA annotation", "ok", email.clone()),
        None => check(
            "kubernetes",
            "GSA annotation",
            "not configured",
            format!("no {GSA_ANNOTATION} annotation"),
        ),
    }];
    let mut findings = Vec::new();
    let facts = match cloud {
        Ok(f) => f,
        Err(reason) => {
            return (
                IdentityReport {
                    checks,
                    cloud_checks: format!("skipped: {reason}"),
                },
                findings,
            );
        }
    };
    let pool = facts.workload_pool.as_str();
    checks.push(check(
        "gcp",
        "Workload Identity pool",
        match (pool.is_empty(), gsa.is_some()) {
            (false, _) => "ok",
            (true, true) => "fail",
            (true, false) => "not configured",
        },
        if pool.is_empty() {
            "Workload Identity is disabled on the cluster".to_owned()
        } else {
            pool.to_owned()
        },
    ));
    let Some(email) = gsa else {
        return (
            IdentityReport {
                checks,
                cloud_checks: "done".into(),
            },
            findings,
        );
    };
    if pool.is_empty() {
        findings.push(
            Finding::new("gke.wi.pool_missing", Severity::Critical, Confidence::High, format!("{subject} is annotated for Workload Identity, but the cluster has no workload pool"))
                .explain("Without a workload pool the GKE metadata server does not exchange Kubernetes tokens for Google credentials, so pods get the node's service account (or nothing).")
                .evidence(Source::Spec, format!("{GSA_ANNOTATION}: {email}"))
                .evidence(Source::Related, "cluster workloadIdentityConfig.workloadPool is empty")
                .docs(DOCS_WI)
                .fix("Enable Workload Identity on the cluster (`gcloud container clusters update <name> --workload-pool=<project>.svc.id.goog`) and on its node pools (GKE_METADATA)."),
        );
    }
    let wrong_mode: Vec<String> = facts
        .node_pool_modes
        .iter()
        .filter(|(_, mode)| mode == "GCE_METADATA")
        .map(|(name, _)| name.clone())
        .collect();
    checks.push(check(
        "gcp",
        "node pools run the GKE metadata server",
        if facts.autopilot || wrong_mode.is_empty() {
            "ok"
        } else {
            "fail"
        },
        if facts.autopilot {
            "Autopilot".to_owned()
        } else if wrong_mode.is_empty() {
            format!(
                "none of {} node pool(s) in GCE_METADATA",
                facts.node_pool_modes.len()
            )
        } else {
            format!("GCE_METADATA: {}", wrong_mode.join(", "))
        },
    ));
    if !facts.autopilot && !wrong_mode.is_empty() && !pool.is_empty() {
        findings.push(
            Finding::new("gke.wi.metadata_mode", Severity::High, Confidence::High, format!("{} node pool(s) do not run the GKE metadata server, so pods there cannot use Workload Identity", wrong_mode.len()))
                .explain("Pods get Workload Identity credentials from the GKE metadata server, which runs only on node pools with workload metadata mode GKE_METADATA. Pods scheduled elsewhere see the node's service account instead.")
                .evidence(Source::Related, format!("node pools in GCE_METADATA mode: {}", wrong_mode.join(", ")))
                .docs(DOCS_WI)
                .fix("Set `--workload-metadata=GKE_METADATA` on those node pools (it recreates their nodes), or keep the workloads off them with a nodeSelector."),
        );
    }
    let gsa_facts = facts.gsa.as_ref();
    let exists = gsa_facts.is_some_and(|g| g.exists);
    checks.push(check(
        "gcp",
        "GSA exists",
        if exists { "ok" } else { "fail" },
        email.clone(),
    ));
    if !exists {
        findings.push(
            Finding::new("gke.wi.gsa_missing", Severity::Critical, Confidence::High, format!("Google service account {email} in the annotation of {subject} does not exist"))
                .explain("The GKE metadata server cannot impersonate a service account that does not exist, so the pods' Google API calls fail.")
                .evidence(Source::Spec, format!("{GSA_ANNOTATION}: {email}"))
                .docs(DOCS_WI)
                .fix("Create the service account (and grant it the roles the workload needs), or correct the annotation.")
                .next("get_resource", json!({"kind": "ServiceAccount", "name": sa, "namespace": ns}), "check the annotation"),
        );
        return (
            IdentityReport {
                checks,
                cloud_checks: "done".into(),
            },
            findings,
        );
    }
    let g = gsa_facts.cloned().unwrap_or_default();
    if g.disabled {
        checks.push(check("gcp", "GSA enabled", "fail", "disabled"));
        findings.push(
            Finding::new("gke.wi.gsa_disabled", Severity::High, Confidence::High, format!("Google service account {email} used by {subject} is disabled"))
                .explain("A disabled service account cannot issue tokens, so every Google API call of the pods fails with an authentication error.")
                .evidence(Source::Related, format!("{email}: disabled"))
                .docs(DOCS_WI)
                .fix("Enable the service account (`gcloud iam service-accounts enable <email>`) or point the annotation at another one."),
        );
    }
    let member = format!("serviceAccount:{pool}[{ns}/{sa}]");
    let bound = g.wi_users.contains(&member);
    checks.push(check(
        "gcp",
        "workloadIdentityUser granted to the ServiceAccount",
        if bound { "ok" } else { "fail" },
        if bound {
            member.clone()
        } else {
            format!("{WI_USER_ROLE} on {email} does not list {member}")
        },
    ));
    if !bound && !pool.is_empty() {
        findings.push(
            Finding::new("gke.wi.binding_missing", Severity::Critical, Confidence::High, format!("{email} does not let {subject} impersonate it"))
                .explain(format!("The GKE metadata server exchanges the pod's token only if the Google service account's IAM policy grants {WI_USER_ROLE} to the Kubernetes ServiceAccount; otherwise the pods get PERMISSION_DENIED on every Google API call."))
                .evidence(Source::Related, format!("{WI_USER_ROLE} members: {}", if g.wi_users.is_empty() { "none".to_owned() } else { g.wi_users.iter().take(5).cloned().collect::<Vec<_>>().join(", ") }))
                .docs(DOCS_WI)
                .fix(format!("Grant it: `gcloud iam service-accounts add-iam-policy-binding {email} --role {WI_USER_ROLE} --member \"{member}\"`.")),
        );
    }
    (
        IdentityReport {
            checks,
            cloud_checks: "done".into(),
        },
        findings,
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn sa(annotated: bool) -> WorkloadIdentity {
        let mut v = json!({"metadata": {"name": "api", "namespace": "shop"}});
        if annotated {
            v["metadata"]["annotations"] =
                json!({GSA_ANNOTATION: "api@acme.iam.gserviceaccount.com"});
        }
        WorkloadIdentity {
            service_account: serde_json::from_value(v).unwrap(),
            pods: Vec::new(),
            agent_ready: None,
        }
    }

    fn facts() -> CloudFacts {
        CloudFacts {
            workload_pool: "acme.svc.id.goog".into(),
            autopilot: false,
            node_pool_modes: vec![("general".into(), "GKE_METADATA".into())],
            gsa: Some(GsaFacts {
                email: "api@acme.iam.gserviceaccount.com".into(),
                exists: true,
                disabled: false,
                wi_users: vec!["serviceAccount:acme.svc.id.goog[shop/api]".into()],
            }),
        }
    }

    fn ids(r: &Report<IdentityReport>) -> Vec<&str> {
        r.1.iter().map(|f| f.id.as_str()).collect()
    }

    #[test]
    fn a_complete_setup_passes() {
        let r = evaluate(&sa(true), Ok(&facts()));
        assert!(r.1.is_empty(), "{:?}", r.1);
        assert!(
            r.0.checks.iter().all(|c| c.result == "ok"),
            "{:?}",
            r.0.checks
        );
    }

    /// v0.3 AC 2 (GKE): missing workloadIdentityUser binding, node pool not GKE_METADATA,
    /// cluster without a workload pool.
    #[test]
    fn identity_failure_cases() {
        let mut f = facts();
        f.gsa.as_mut().unwrap().wi_users =
            vec!["serviceAccount:acme.svc.id.goog[shop/worker]".into()];
        assert_eq!(
            ids(&evaluate(&sa(true), Ok(&f))),
            ["gke.wi.binding_missing"]
        );

        let mut f = facts();
        f.node_pool_modes
            .push(("legacy".into(), "GCE_METADATA".into()));
        let r = evaluate(&sa(true), Ok(&f));
        assert_eq!(ids(&r), ["gke.wi.metadata_mode"]);
        assert!(r.1[0].evidence[0].text.ends_with(": legacy"));
        f.autopilot = true;
        assert!(
            evaluate(&sa(true), Ok(&f)).1.is_empty(),
            "Autopilot always runs it"
        );

        let mut f = facts();
        f.workload_pool.clear();
        assert_eq!(ids(&evaluate(&sa(true), Ok(&f))), ["gke.wi.pool_missing"]);
    }

    #[test]
    fn missing_or_disabled_gsa() {
        let mut f = facts();
        f.gsa.as_mut().unwrap().exists = false;
        assert_eq!(ids(&evaluate(&sa(true), Ok(&f))), ["gke.wi.gsa_missing"]);
        let mut f = facts();
        f.gsa.as_mut().unwrap().disabled = true;
        assert_eq!(ids(&evaluate(&sa(true), Ok(&f))), ["gke.wi.gsa_disabled"]);
    }

    #[test]
    fn unannotated_and_without_credentials() {
        let r = evaluate(&sa(false), Ok(&facts()));
        assert!(r.1.is_empty());
        assert_eq!(r.0.checks[0].result, "not configured");
        let r = evaluate(&sa(true), Err("no Google Cloud credentials"));
        assert_eq!(r.0.cloud_checks, "skipped: no Google Cloud credentials");
        assert_eq!(r.0.checks.len(), 1);
    }
}
