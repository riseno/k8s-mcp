//! `aks_identity_check`: Azure Workload Identity for a Kubernetes ServiceAccount. The
//! Kubernetes side (the client-id annotation, the pods' `azure.workload.identity/use` label and
//! the injected environment) always runs; the Azure side (the cluster's OIDC issuer and
//! workload identity, the managed identity with that client id and its federated credentials)
//! runs when credentials allow. Pure: the caller fetches the facts.

use k8s_mcp_core::finding::{Confidence, Finding, RuleMeta, Severity, Source};
use k8s_mcp_provider::{IdentityCheck, IdentityReport, Report, WorkloadIdentity};
use k8s_openapi::api::core::v1::Pod;
use serde_json::json;

/// The ServiceAccount annotation naming the Entra application or managed identity.
pub const CLIENT_ID_ANNOTATION: &str = "azure.workload.identity/client-id";
/// The pod label that makes the webhook inject the credentials.
pub const USE_LABEL: &str = "azure.workload.identity/use";
/// The audience Azure expects in federated tokens.
pub const AUDIENCE: &str = "api://AzureADTokenExchange";

const DOCS_WI: &str = "https://learn.microsoft.com/azure/aks/workload-identity-overview";

/// Rules emitted by the identity check.
pub const RULES: &[RuleMeta] = &[
    RuleMeta {
        id: "aks.wi.oidc_issuer_disabled",
        title: "The cluster's OIDC issuer is disabled",
        docs: DOCS_WI,
    },
    RuleMeta {
        id: "aks.wi.not_enabled",
        title: "Workload identity is not enabled on the cluster",
        docs: DOCS_WI,
    },
    RuleMeta {
        id: "aks.wi.pod_label_missing",
        title: "Pods lack the azure.workload.identity/use label",
        docs: DOCS_WI,
    },
    RuleMeta {
        id: "aks.wi.env_not_injected",
        title: "Pods did not get the workload identity environment injected",
        docs: DOCS_WI,
    },
    RuleMeta {
        id: "aks.wi.identity_not_found",
        title: "No user-assigned managed identity has the annotated client id",
        docs: DOCS_WI,
    },
    RuleMeta {
        id: "aks.wi.federated_credential_missing",
        title: "The managed identity has no federated credential for this cluster",
        docs: DOCS_WI,
    },
    RuleMeta {
        id: "aks.wi.federated_credential_mismatch",
        title: "The federated credential does not name this ServiceAccount",
        docs: DOCS_WI,
    },
];

/// One federated identity credential.
#[derive(Debug, Clone, Default)]
pub struct FederatedCredential {
    /// Its name.
    pub name: String,
    /// Token issuer it trusts.
    pub issuer: String,
    /// Subject it trusts.
    pub subject: String,
    /// Audiences it accepts.
    pub audiences: Vec<String>,
}

/// The user-assigned managed identity with the annotated client id.
#[derive(Debug, Clone, Default)]
pub struct ManagedIdentity {
    /// Its name.
    pub name: String,
    /// Its federated identity credentials.
    pub federated: Vec<FederatedCredential>,
}

/// What the Azure APIs say.
#[derive(Debug, Clone, Default)]
pub struct CloudFacts {
    /// The cluster's OIDC issuer URL; `None` when the issuer is disabled.
    pub oidc_issuer: Option<String>,
    /// `securityProfile.workloadIdentity.enabled` (the mutating webhook).
    pub workload_identity: bool,
    /// The identity with the annotated client id; `None` when none was found.
    pub identity: Option<ManagedIdentity>,
    /// Where the identity was looked for (for the not-found message).
    pub searched: String,
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

fn has_env(p: &Pod, var: &str) -> bool {
    p.spec
        .iter()
        .flat_map(|s| &s.containers)
        .flat_map(|c| c.env.iter().flatten())
        .any(|e| e.name == var)
}

fn pod_name(p: &Pod) -> &str {
    p.metadata.name.as_deref().unwrap_or("")
}

fn same_issuer(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

/// Turn the facts into checks and findings. `cloud` is `Err(reason)` when Azure could not be
/// asked.
pub fn evaluate(
    k8s: &WorkloadIdentity,
    cloud: Result<&CloudFacts, &str>,
) -> Report<IdentityReport> {
    let meta = &k8s.service_account.metadata;
    let sa = meta.name.as_deref().unwrap_or("");
    let ns = meta.namespace.as_deref().unwrap_or("default");
    let subject = format!("ServiceAccount {ns}/{sa}");
    let expected_subject = format!("system:serviceaccount:{ns}:{sa}");
    let client_id = meta
        .annotations
        .as_ref()
        .and_then(|a| a.get(CLIENT_ID_ANNOTATION))
        .cloned();
    let mut checks = vec![match &client_id {
        Some(id) => check("kubernetes", "client-id annotation", "ok", id.clone()),
        None => check(
            "kubernetes",
            "client-id annotation",
            "not configured",
            format!("no {CLIENT_ID_ANNOTATION} annotation"),
        ),
    }];
    let mut findings = Vec::new();
    if client_id.is_some() && !k8s.pods.is_empty() {
        let unlabeled: Vec<&str> = k8s
            .pods
            .iter()
            .filter(|p| {
                p.metadata
                    .labels
                    .as_ref()
                    .and_then(|l| l.get(USE_LABEL))
                    .map(String::as_str)
                    != Some("true")
            })
            .map(pod_name)
            .collect();
        checks.push(check(
            "kubernetes",
            "pods labeled azure.workload.identity/use=true",
            if unlabeled.is_empty() { "ok" } else { "fail" },
            format!(
                "{}/{} pods labeled",
                k8s.pods.len() - unlabeled.len(),
                k8s.pods.len()
            ),
        ));
        if !unlabeled.is_empty() {
            findings.push(
                Finding::new("aks.wi.pod_label_missing", Severity::High, Confidence::High, format!("{} pod(s) of {subject} lack the {USE_LABEL}: \"true\" label", unlabeled.len()))
                    .explain("The workload identity webhook only injects the federated token and AZURE_* variables into pods with this label, so these pods have no Azure credentials.")
                    .evidence(Source::Spec, format!("pods without the label: {}", unlabeled.iter().take(5).copied().collect::<Vec<_>>().join(", ")))
                    .docs(DOCS_WI)
                    .fix(format!("Add `{USE_LABEL}: \"true\"` to the pod template's labels (not the Deployment's) and roll the workload.")),
            );
        }
        let not_injected: Vec<&str> = k8s
            .pods
            .iter()
            .filter(|p| {
                p.metadata
                    .labels
                    .as_ref()
                    .and_then(|l| l.get(USE_LABEL))
                    .map(String::as_str)
                    == Some("true")
            })
            .filter(|p| !has_env(p, "AZURE_FEDERATED_TOKEN_FILE"))
            .map(pod_name)
            .collect();
        if !not_injected.is_empty() {
            checks.push(check(
                "kubernetes",
                "workload identity env injected",
                "fail",
                format!(
                    "{} labeled pod(s) without AZURE_FEDERATED_TOKEN_FILE",
                    not_injected.len()
                ),
            ));
            findings.push(
                Finding::new("aks.wi.env_not_injected", Severity::High, Confidence::High, format!("{} labeled pod(s) of {subject} did not get the workload identity environment", not_injected.len()))
                    .explain("The webhook injects AZURE_CLIENT_ID, AZURE_TENANT_ID and AZURE_FEDERATED_TOKEN_FILE when a pod is created. Pods created before the label or annotation was added, or while workload identity was off, lack them.")
                    .evidence(Source::Spec, format!("pods without AZURE_FEDERATED_TOKEN_FILE: {}", not_injected.iter().take(5).copied().collect::<Vec<_>>().join(", ")))
                    .docs(DOCS_WI)
                    .fix("Make sure workload identity is enabled on the cluster, then restart the pods (`kubectl rollout restart` on their workload)."),
            );
        }
    }
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
    let annotated = client_id.is_some();
    checks.push(check(
        "azure",
        "OIDC issuer enabled",
        match (&facts.oidc_issuer, annotated) {
            (Some(_), _) => "ok",
            (None, true) => "fail",
            (None, false) => "not configured",
        },
        facts
            .oidc_issuer
            .clone()
            .unwrap_or_else(|| "disabled".into()),
    ));
    checks.push(check(
        "azure",
        "workload identity enabled",
        match (facts.workload_identity, annotated) {
            (true, _) => "ok",
            (false, true) => "fail",
            (false, false) => "not configured",
        },
        if facts.workload_identity {
            "enabled"
        } else {
            "disabled"
        },
    ));
    let Some(client_id) = client_id else {
        return (
            IdentityReport {
                checks,
                cloud_checks: "done".into(),
            },
            findings,
        );
    };
    if facts.oidc_issuer.is_none() {
        findings.push(
            Finding::new("aks.wi.oidc_issuer_disabled", Severity::Critical, Confidence::High, format!("{subject} uses workload identity, but the cluster's OIDC issuer is disabled"))
                .explain("Entra ID validates the pod's federated token against the cluster's OIDC issuer; without it no token exchange succeeds.")
                .evidence(Source::Related, "oidcIssuerProfile.enabled: false")
                .docs(DOCS_WI)
                .fix("Enable it: `az aks update --enable-oidc-issuer`, then create the federated credentials with the new issuer URL."),
        );
    }
    if !facts.workload_identity {
        findings.push(
            Finding::new("aks.wi.not_enabled", Severity::Critical, Confidence::High, format!("{subject} uses workload identity, but workload identity is not enabled on the cluster"))
                .explain("Without the workload identity add-on, no webhook injects the federated token and AZURE_* variables into pods.")
                .evidence(Source::Related, "securityProfile.workloadIdentity.enabled: false")
                .docs(DOCS_WI)
                .fix("Enable it: `az aks update --enable-workload-identity`, then restart the workloads."),
        );
    }
    let Some(identity) = &facts.identity else {
        checks.push(check(
            "azure",
            "managed identity with the client id",
            "fail",
            format!("none found in {}", facts.searched),
        ));
        findings.push(
            Finding::new("aks.wi.identity_not_found", Severity::Medium, Confidence::Low, format!("No user-assigned managed identity with client id {client_id} was found"))
                .explain(format!("k8s-mcp looked in {}. The client id may belong to an identity in another subscription, or to an Entra application registration, whose federated credentials are managed in Entra ID; otherwise the annotation is wrong and token exchange fails.", facts.searched))
                .evidence(Source::Spec, format!("{CLIENT_ID_ANNOTATION}: {client_id}"))
                .docs(DOCS_WI)
                .fix("Check the client id (`az identity show` or the app registration), and that its federated credential names this cluster's issuer and the ServiceAccount.")
                .next("get_resource", json!({"kind": "ServiceAccount", "name": sa, "namespace": ns}), "check the annotation"),
        );
        return (
            IdentityReport {
                checks,
                cloud_checks: "done".into(),
            },
            findings,
        );
    };
    checks.push(check(
        "azure",
        "managed identity with the client id",
        "ok",
        identity.name.clone(),
    ));
    let Some(issuer) = &facts.oidc_issuer else {
        return (
            IdentityReport {
                checks,
                cloud_checks: "done".into(),
            },
            findings,
        );
    };
    let for_cluster: Vec<&FederatedCredential> = identity
        .federated
        .iter()
        .filter(|f| same_issuer(&f.issuer, issuer))
        .collect();
    let matching = for_cluster
        .iter()
        .find(|f| f.subject == expected_subject && f.audiences.iter().any(|a| a == AUDIENCE));
    checks.push(check(
        "azure",
        "federated credential for the cluster issuer and ServiceAccount",
        if matching.is_some() { "ok" } else { "fail" },
        matching.map_or_else(
            || format!("{} credential(s) for this issuer, none for {expected_subject} with audience {AUDIENCE}", for_cluster.len()),
            |f| f.name.clone(),
        ),
    ));
    if matching.is_none() {
        let f = if for_cluster.is_empty() {
            Finding::new("aks.wi.federated_credential_missing", Severity::Critical, Confidence::High, format!("Managed identity {} has no federated credential for this cluster", identity.name))
                .explain("Entra ID exchanges a pod's token only for an identity whose federated credential trusts the cluster's OIDC issuer; none of this identity's credentials does, so the pods get AADSTS70021 errors.")
                .evidence(Source::Related, format!("{} federated credential(s), none with issuer {issuer}", identity.federated.len()))
        } else {
            let mut f = Finding::new("aks.wi.federated_credential_mismatch", Severity::Critical, Confidence::High, format!("The federated credentials of {} do not name {subject}", identity.name))
                .explain(format!("A credential trusts this cluster's issuer, but Entra ID also requires its subject to be exactly {expected_subject} and its audience to include {AUDIENCE}; otherwise the token exchange fails with AADSTS70021 (no matching federated identity record)."));
            for c in for_cluster.iter().take(5) {
                f = f.evidence(
                    Source::Related,
                    format!(
                        "{}: subject {}, audiences {}",
                        c.name,
                        c.subject,
                        c.audiences.join(",")
                    ),
                );
            }
            f
        };
        findings.push(
            f.docs(DOCS_WI).fix(format!(
                "Create (or correct) the federated credential: `az identity federated-credential create --identity-name {} --resource-group <rg> --name <name> --issuer {issuer} --subject {expected_subject} --audience {AUDIENCE}`.",
                identity.name
            )),
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

    const ISSUER: &str = "https://westeurope.oic.prod-aks.azure.com/tenant/guid/";

    fn sa(annotated: bool, labeled: bool, injected: bool) -> WorkloadIdentity {
        let mut v = json!({"metadata": {"name": "api", "namespace": "shop"}});
        if annotated {
            v["metadata"]["annotations"] =
                json!({CLIENT_ID_ANNOTATION: "11111111-2222-3333-4444-555555555555"});
        }
        let mut pod =
            json!({"metadata": {"name": "api-1"}, "spec": {"containers": [{"name": "app"}]}});
        if labeled {
            pod["metadata"]["labels"] = json!({USE_LABEL: "true"});
        }
        if injected {
            pod["spec"]["containers"][0]["env"] = json!([{"name": "AZURE_FEDERATED_TOKEN_FILE", "value": "/var/run/secrets/azure/tokens/azure-identity-token"}]);
        }
        WorkloadIdentity {
            service_account: serde_json::from_value(v).unwrap(),
            pods: vec![serde_json::from_value(pod).unwrap()],
            agent_ready: None,
        }
    }

    fn facts() -> CloudFacts {
        CloudFacts {
            oidc_issuer: Some(ISSUER.into()),
            workload_identity: true,
            identity: Some(ManagedIdentity {
                name: "shop-api".into(),
                federated: vec![FederatedCredential {
                    name: "shop-api-aks".into(),
                    issuer: ISSUER.trim_end_matches('/').into(),
                    subject: "system:serviceaccount:shop:api".into(),
                    audiences: vec![AUDIENCE.into()],
                }],
            }),
            searched: "subscription s".into(),
        }
    }

    fn ids(r: &Report<IdentityReport>) -> Vec<&str> {
        r.1.iter().map(|f| f.id.as_str()).collect()
    }

    #[test]
    fn a_complete_setup_passes() {
        let r = evaluate(&sa(true, true, true), Ok(&facts()));
        assert!(r.1.is_empty(), "{:?}", r.1);
        assert!(
            r.0.checks.iter().all(|c| c.result == "ok"),
            "{:?}",
            r.0.checks
        );
    }

    /// v0.3 AC 2 (AKS): missing federated credential, wrong subject, pod label missing, OIDC
    /// issuer disabled.
    #[test]
    fn identity_failure_cases() {
        let mut f = facts();
        f.identity.as_mut().unwrap().federated.clear();
        assert_eq!(
            ids(&evaluate(&sa(true, true, true), Ok(&f))),
            ["aks.wi.federated_credential_missing"]
        );

        let mut f = facts();
        f.identity.as_mut().unwrap().federated[0].subject =
            "system:serviceaccount:shop:worker".into();
        let r = evaluate(&sa(true, true, true), Ok(&f));
        assert_eq!(ids(&r), ["aks.wi.federated_credential_mismatch"]);
        assert!(
            r.1[0].evidence[0]
                .text
                .contains("system:serviceaccount:shop:worker")
        );

        assert_eq!(
            ids(&evaluate(&sa(true, false, false), Ok(&facts()))),
            ["aks.wi.pod_label_missing"]
        );

        let mut f = facts();
        f.oidc_issuer = None;
        assert_eq!(
            ids(&evaluate(&sa(true, true, true), Ok(&f))),
            ["aks.wi.oidc_issuer_disabled"]
        );
    }

    #[test]
    fn other_cases() {
        assert_eq!(
            ids(&evaluate(&sa(true, true, false), Ok(&facts()))),
            ["aks.wi.env_not_injected"]
        );
        let mut f = facts();
        f.workload_identity = false;
        assert_eq!(
            ids(&evaluate(&sa(true, true, true), Ok(&f))),
            ["aks.wi.not_enabled"]
        );
        let mut f = facts();
        f.identity = None;
        let r = evaluate(&sa(true, true, true), Ok(&f));
        assert_eq!(ids(&r), ["aks.wi.identity_not_found"]);
        assert_eq!(r.1[0].confidence, Confidence::Low);
        let r = evaluate(&sa(false, false, false), Ok(&facts()));
        assert!(r.1.is_empty() && r.0.checks[0].result == "not configured");
        // Without credentials the Kubernetes side still runs.
        let r = evaluate(&sa(true, false, false), Err("no Azure credentials"));
        assert_eq!(ids(&r), ["aks.wi.pod_label_missing"]);
        assert_eq!(r.0.cloud_checks, "skipped: no Azure credentials");
    }
}
