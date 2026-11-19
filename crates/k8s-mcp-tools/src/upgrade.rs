//! `upgrade_readiness`: is the cluster ready for the next control-plane minor? Gathers the
//! deprecated-API metric, CRDs, objects written with deprecated versions, nodes, PDBs and
//! workloads, plus the provider's upgrade checks when a provider toolset is registered.

use k8s_mcp_core::envelope::Section;
use k8s_mcp_core::finding::rank;
use k8s_mcp_core::{Error, Result};
use k8s_mcp_diagnose::rules::parse_version;
use k8s_mcp_diagnose::rules::upgrade::{
    checklist, deprecated_crd_versions, requested_deprecated_apis, scan_targets, split_served,
    stale_writes, tally,
};
use k8s_mcp_diagnose::{DeprecatedApi, StaleWrite, Unavailable, UpgradeEvidence};
use k8s_openapi::api::apps::v1::{Deployment, StatefulSet};
use k8s_openapi::api::core::v1::Node;
use k8s_openapi::api::policy::v1::PodDisruptionBudget;
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, ApiResource, DynamicObject, ListParams};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use crate::common::{Scope, ensure_namespace, envelope, list_scoped, scope, soft};
use crate::read::add_notes;
use crate::{Ctx, Envelope};

/// Objects read per deprecated API when looking for stale writes.
const SCAN_LIMIT: u32 = 500;

/// Inputs for `upgrade_readiness`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpgradeReadinessInput {
    /// Kubernetes version to upgrade the control plane to, such as `1.35` (default: the next
    /// minor after the current one).
    pub target_version: Option<String>,
    /// Only check this namespace's PodDisruptionBudgets, workloads and objects (the control
    /// plane, nodes and the API server's deprecated-API metric are cluster-wide). Default: all
    /// allowed namespaces.
    pub namespace: Option<String>,
    /// Kubeconfig context.
    pub context: Option<String>,
}

/// Objects last written with the deprecated APIs in `targets`, read through each group's
/// preferred version (never the deprecated one, which would count as a deprecated request).
async fn scan(
    ctx: &Ctx,
    sc: &Scope,
    targets: &[DeprecatedApi],
    un: &mut Vec<Unavailable>,
) -> Vec<StaleWrite> {
    let mut out = Vec::new();
    if targets.is_empty() {
        return out;
    }
    let resources = match crate::discovery::resources(ctx, &sc.target).await {
        Ok(r) => r,
        Err(e) => {
            un.push(Unavailable {
                what: "objects written with deprecated API versions".into(),
                reason: e.to_string(),
            });
            return out;
        }
    };
    for t in targets {
        let what = format!("{} objects (for {} writes)", t.resource, t.group_version());
        let Some(info) = resources
            .iter()
            .find(|r| r.group == t.group && r.plural == t.resource)
        else {
            continue; // not served any more
        };
        if info.version == t.version {
            un.push(Unavailable { what, reason: format!("{} is the preferred version of its group, so reading the objects would request it; only the metric covers it", t.group_version()) });
            continue;
        }
        let ar = ApiResource {
            group: info.group.clone(),
            version: info.version.clone(),
            api_version: info.api_version(),
            kind: info.kind.clone(),
            plural: info.plural.clone(),
        };
        let lp = ListParams::default().limit(SCAN_LIMIT);
        match Api::<DynamicObject>::all_with(sc.target.client.clone(), &ar)
            .list_metadata(&lp)
            .await
        {
            Ok(list) => {
                if list
                    .metadata
                    .continue_
                    .as_deref()
                    .is_some_and(|c| !c.is_empty())
                {
                    un.push(Unavailable {
                        what: what.clone(),
                        reason: format!("only the first {SCAN_LIMIT} were scanned"),
                    });
                }
                for o in &list.items {
                    let ns = o.metadata.namespace.as_deref();
                    let outside = match (&sc.namespace, ns) {
                        (Some(only), Some(ns)) => only != ns,
                        (Some(_), None) => true, // cluster-scoped objects are not in the namespace
                        (None, Some(ns)) => !ctx.policy.namespace_allowed(ns),
                        (None, None) => false,
                    };
                    if outside {
                        continue;
                    }
                    out.extend(stale_writes(t, &info.kind, &o.metadata));
                }
            }
            Err(e) => {
                let err = Error::kube(format!("list {}", info.plural), &e);
                // Issue #68: in-cluster, name the chart value that grants it.
                let reason = if err.is_forbidden()
                    && sc.target.context == k8s_mcp_core::cluster::IN_CLUSTER
                {
                    format!(
                        "the server's ClusterRole cannot list {plural}; add `{{apiGroups: [{group}], resources: [{plural}], verbs: [list]}}` to the chart's rbac.extraRules",
                        plural = info.plural,
                        group = if info.group.is_empty() {
                            "\"\""
                        } else {
                            info.group.as_str()
                        }
                    )
                } else {
                    err.to_string()
                };
                un.push(Unavailable { what, reason });
            }
        }
    }
    out.sort();
    out
}

/// Provider upgrade data: `(cloud, support_ends, section lines, findings, checklist row)`.
type ProviderSection = (
    String,
    Option<i64>,
    Vec<String>,
    Vec<k8s_mcp_core::finding::Finding>,
    (String, &'static str, String),
);

/// The registered provider's upgrade data (a cluster has one cloud).
#[cfg(any(
    feature = "provider-eks",
    feature = "provider-gke",
    feature = "provider-aks"
))]
async fn provider(
    ctx: &Ctx,
    sc: &Scope,
    target: &str,
    un: &mut Vec<Unavailable>,
) -> Option<ProviderSection> {
    use k8s_mcp_core::provider::ProviderId;
    let id = ctx.providers.first().copied()?;
    let result = match id {
        #[cfg(feature = "provider-eks")]
        ProviderId::Eks => crate::eks::upgrade(ctx, sc, target).await,
        #[cfg(feature = "provider-gke")]
        ProviderId::Gke => crate::gke::upgrade(ctx, sc, target).await,
        #[cfg(feature = "provider-aks")]
        ProviderId::Aks => crate::aks::upgrade(ctx, sc, target).await,
        #[allow(unreachable_patterns)] // every provider compiled in
        _ => return None,
    };
    let cloud = id.as_str().to_uppercase();
    match result {
        Ok((info, findings)) => {
            let failing = info
                .checks
                .iter()
                .filter(|c| matches!(c.status.as_str(), "error" | "warning"))
                .count();
            let row = (
                format!("{cloud} upgrade checks"),
                if failing == 0 { "ok" } else { "warn" },
                format!("{} checked, {failing} failing", info.checks.len()),
            );
            let lines = k8s_mcp_provider::upgrade_lines(id, &info);
            Some((cloud, info.support_ends, lines, findings, row))
        }
        Err(e) => {
            un.push(Unavailable {
                what: format!("{cloud} upgrade checks"),
                reason: e.to_string(),
            });
            None
        }
    }
}

#[cfg(not(any(
    feature = "provider-eks",
    feature = "provider-gke",
    feature = "provider-aks"
)))]
#[allow(clippy::unused_async)] // same signature as the provider build
async fn provider(
    _: &Ctx,
    _: &Scope,
    _: &str,
    _: &mut Vec<Unavailable>,
) -> Option<ProviderSection> {
    None
}

/// Check what stands between the cluster and the next control-plane minor.
pub async fn upgrade_readiness(ctx: &Ctx, input: UpgradeReadinessInput) -> Result<Envelope> {
    let sc = scope(
        ctx,
        input.context.as_deref(),
        input.namespace.as_deref(),
        input.namespace.is_none(),
    )
    .await?;
    // A mistyped namespace must not read as "nothing found" (#67).
    if input.namespace.is_some() {
        ensure_namespace(&sc).await?;
    }
    let client = sc.target.client.clone();
    let info = client
        .apiserver_version()
        .await
        .map_err(|e| Error::kube("read the API server version", &e))?;
    let (_, current) =
        parse_version(&format!("{}.{}", info.major, info.minor)).ok_or_else(|| {
            Error::Api(format!(
                "cannot parse the API server version {}.{}",
                info.major, info.minor
            ))
        })?;
    let target = match &input.target_version {
        Some(t) => {
            let (major, minor) = parse_version(t)
                .filter(|(major, _)| *major == 1)
                .ok_or_else(|| {
                    Error::InvalidInput(format!("target_version {t:?} must look like 1.35"))
                })?;
            if minor <= current {
                return Err(Error::InvalidInput(format!(
                    "target_version {major}.{minor} is not newer than the control plane's 1.{current}"
                )));
            }
            minor
        }
        None => current + 1,
    };
    let mut un = Vec::new();
    let metrics = http::Request::get("/metrics")
        .body(Vec::new())
        .map_err(|e| Error::Api(format!("build the /metrics request: {e}")))?;
    let requested = match client.request_text(metrics).await {
        Ok(text) => Some(requested_deprecated_apis(&text)),
        Err(e) => {
            un.push(Unavailable {
                what: "the API server's apiserver_requested_deprecated_apis metric".into(),
                reason: format!("{}; deprecated APIs are checked from objects only (grant get on the /metrics non-resource URL)", Error::kube("get /metrics", &e)),
            });
            None
        }
    };
    // Issue #65: the gauge keeps entries for group/versions no longer served (a deleted CRD)
    // until the API server restarts. Without discovery, nothing is dropped.
    let (requested, unserved) = match (requested, client.list_api_groups().await) {
        (Some(r), Ok(groups)) => {
            let served: Vec<String> = std::iter::once("v1".to_owned())
                .chain(
                    groups
                        .groups
                        .into_iter()
                        .flat_map(|g| g.versions.into_iter().map(|v| v.group_version)),
                )
                .collect();
            let (r, u) = split_served(r, &served);
            (Some(r), u)
        }
        (r, _) => (r, Vec::new()),
    };
    let crds = soft(
        Api::<CustomResourceDefinition>::all(client.clone())
            .list(&ListParams::default())
            .await
            .map(|l| l.items)
            .map_err(|e| Error::kube("list CustomResourceDefinitions", &e)),
        "CustomResourceDefinitions",
        &mut un,
    )?
    .unwrap_or_default();
    let crd_versions = deprecated_crd_versions(&crds);
    let targets = scan_targets(
        current,
        target,
        requested.as_deref().unwrap_or_default(),
        &crd_versions,
    );
    let stale = scan(ctx, &sc, &targets, &mut un).await;
    let nodes = soft(
        Api::<Node>::all(client.clone())
            .list(&ListParams::default())
            .await
            .map(|l| l.items)
            .map_err(|e| Error::kube("list nodes", &e)),
        "nodes",
        &mut un,
    )?;
    let lp = ListParams::default();
    let pdbs = soft(
        list_scoped::<PodDisruptionBudget>(ctx, &sc, &lp, "poddisruptionbudgets", &mut un).await,
        "PodDisruptionBudgets",
        &mut un,
    )?;
    let deployments = soft(
        list_scoped::<Deployment>(ctx, &sc, &lp, "deployments", &mut un).await,
        "Deployments",
        &mut un,
    )?;
    let statefulsets = soft(
        list_scoped::<StatefulSet>(ctx, &sc, &lp, "statefulsets", &mut un).await,
        "StatefulSets",
        &mut un,
    )?;
    let cloud = provider(ctx, &sc, &format!("1.{target}"), &mut un).await;

    let ev = UpgradeEvidence {
        current,
        target,
        requested,
        unserved,
        deprecated_crd_versions: crd_versions,
        stale_writes: stale,
        nodes,
        pdbs,
        deployments,
        statefulsets,
        support_ends: cloud
            .as_ref()
            .and_then(|(name, ends, ..)| ends.map(|e| (name.clone(), e))),
        unavailable: un,
        now: ctx.now(),
    };
    let mut findings = k8s_mcp_diagnose::diagnose_upgrade(&ev);
    let mut rows: Vec<(String, &'static str, String)> = checklist(&ev, &findings)
        .into_iter()
        .map(|(c, s, d)| (c.to_owned(), s, d))
        .collect();
    let (blocked, mut review) = tally(&ev);
    let mut sections = Vec::new();
    if let Some((name, _, lines, provider_findings, row)) = cloud {
        findings.extend(provider_findings);
        rank(&mut findings);
        if row.1 == "warn" {
            review.push(format!("{} ({})", row.0, row.2));
        }
        rows.push(row);
        sections.push(Section {
            title: format!("PROVIDER ({name})"),
            lines,
            untrusted: None,
        });
    }
    // Objects, not checklist rows (#66): "blocked by 4 PodDisruptionBudgets".
    let list = |items: &[String]| match items.split_last() {
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
        None => String::new(),
    };
    let head = format!(
        "Upgrade 1.{current} → 1.{target}: {}{}",
        if blocked.is_empty() {
            "nothing blocks it".to_owned()
        } else {
            format!("blocked by {}", list(&blocked))
        },
        if review.is_empty() {
            String::new()
        } else {
            format!("; review {}", list(&review))
        }
    );
    let mut e = envelope(
        &sc,
        match findings.first() {
            Some(f) => format!("{head}. Top finding: {}.", f.title),
            None => format!("{head}; no problems found by the diagnosis rules."),
        },
    );
    e.columns = vec!["check", "status", "detail"];
    e.items = rows
        .into_iter()
        .map(|(check, status, detail)| json!({"check": check, "status": status, "detail": detail}))
        .collect();
    e.sections = sections;
    e.findings = findings;
    add_notes(&mut e, &ev.unavailable);
    Ok(e)
}
