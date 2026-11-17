//! API discovery (cached per context for 5 minutes) and kind resolution.

use std::sync::Arc;
use std::time::Duration;

use k8s_mcp_core::cluster::{ResourceInfo, Target};
use k8s_mcp_core::{Error, Result};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::APIResourceList;
use kube::discovery::ApiResource;

use crate::Ctx;

/// Budget for one API group's resource list. Broken aggregated APIs (common on managed
/// clusters, e.g. custom or external metrics adapters) accept the request and never answer.
const GROUP_TIMEOUT: Duration = Duration::from_secs(5);

/// All resources served by the cluster (preferred version of each group), cached. Groups are
/// fetched concurrently; a group that fails or exceeds [`GROUP_TIMEOUT`] is skipped.
pub async fn resources(ctx: &Ctx, target: &Target) -> Result<Arc<Vec<ResourceInfo>>> {
    if let Some(r) = ctx.clusters.cached_discovery(&target.context) {
        return Ok(r);
    }
    let client = &target.client;
    let mut out = Vec::new();
    let core = client
        .list_core_api_resources("v1")
        .await
        .map_err(|e| Error::kube("discover core API resources", &e))?;
    push_list(&mut out, "", &core);
    let groups = client
        .list_api_groups()
        .await
        .map_err(|e| Error::kube("discover API groups", &e))?;
    let mut tasks = tokio::task::JoinSet::new();
    for g in groups.groups {
        let Some(pref) = g.preferred_version.or_else(|| g.versions.first().cloned()) else {
            continue;
        };
        let client = client.clone();
        tasks.spawn(async move {
            let res = tokio::time::timeout(
                GROUP_TIMEOUT,
                client.list_api_group_resources(&pref.group_version),
            )
            .await;
            (g.name, pref.group_version, res)
        });
    }
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((name, _, Ok(Ok(list)))) => push_list(&mut out, &name, &list),
            Ok((_, gv, Ok(Err(e)))) => {
                tracing::debug!(group = %gv, error = %e, "skipping API group");
            }
            Ok((_, gv, Err(_))) => {
                tracing::debug!(group = %gv, "skipping API group: no answer within 5s");
            }
            Err(e) => tracing::debug!(error = %e, "discovery task failed"),
        }
    }
    out.sort_by(|a, b| a.group.cmp(&b.group).then(a.kind.cmp(&b.kind)));
    let out = Arc::new(out);
    ctx.clusters.store_discovery(&target.context, out.clone());
    Ok(out)
}

fn push_list(out: &mut Vec<ResourceInfo>, group: &str, list: &APIResourceList) {
    let version = list
        .group_version
        .rsplit('/')
        .next()
        .unwrap_or(&list.group_version);
    for r in &list.resources {
        if r.name.contains('/') {
            continue; // subresources
        }
        out.push(ResourceInfo {
            group: group.to_owned(),
            version: version.to_owned(),
            kind: r.kind.clone(),
            plural: r.name.clone(),
            namespaced: r.namespaced,
            short_names: r.short_names.clone().unwrap_or_default(),
            verbs: r.verbs.clone(),
        });
    }
}

/// A resolved kind, plus other API groups serving the same name when the request was ambiguous.
pub struct Resolved {
    /// The chosen resource.
    pub info: ResourceInfo,
    /// Other groups serving the same kind name (empty when `api_version` or a group was given).
    pub alternatives: Vec<ResourceInfo>,
}

impl Resolved {
    /// "Kind X is also served by …" for the summary, when there are alternatives.
    pub fn note(&self) -> Option<String> {
        (!self.alternatives.is_empty()).then(|| {
            format!(
                " Kind {} is also served by {}; pass api_version to choose.",
                self.info.kind,
                self.alternatives
                    .iter()
                    .map(ResourceInfo::api_version)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
    }
}

/// Resolve a user-supplied kind (`Deployment`, `deployments`, `deploy`, a CRD kind, or kubectl's
/// `plural.group` / `Kind.group`) and optional `api_version`. Refreshes discovery once on a miss.
pub async fn resolve(
    ctx: &Ctx,
    target: &Target,
    kind: &str,
    api_version: Option<&str>,
) -> Result<Resolved> {
    for attempt in 0..2 {
        let all = resources(ctx, target).await?;
        if let Some(r) = find(&all, kind, api_version) {
            return Ok(r);
        }
        if attempt == 0 {
            ctx.clusters.forget_discovery(&target.context);
        }
    }
    Err(Error::NotFound(format!(
        "kind {kind:?}{} is not served by this cluster. Call api_resources to see available kinds (CRDs included).",
        api_version.map(|v| format!(" in {v}")).unwrap_or_default()
    )))
}

fn find(all: &[ResourceInfo], kind: &str, api_version: Option<&str>) -> Option<Resolved> {
    // kubectl's `plural.group` / `Kind.group`, when the suffix is a served group.
    let (name, group) = match kind.split_once('.') {
        Some((n, g)) if api_version.is_none() && all.iter().any(|r| r.group == g) => (n, Some(g)),
        _ => (kind, None),
    };
    let k = name.to_ascii_lowercase();
    let mut matches: Vec<&ResourceInfo> = all
        .iter()
        .filter(|r| r.kind.to_ascii_lowercase() == k || r.plural == k || r.short_names.contains(&k))
        .filter(|r| api_version.is_none_or(|v| r.api_version() == v || r.group == v))
        .filter(|r| group.is_none_or(|g| r.group == g))
        .collect();
    // Prefer the core group and well-known groups over CRDs that reuse a kind name; then by
    // group name, so the choice does not depend on discovery order.
    let rank = |r: &ResourceInfo| match r.group.as_str() {
        "" => 0,
        "apps" | "batch" | "networking.k8s.io" | "policy" | "storage.k8s.io" | "autoscaling" => 1,
        g if g.ends_with(".k8s.io") => 2,
        _ => 3,
    };
    matches.sort_by(|a, b| (rank(a), &a.group).cmp(&(rank(b), &b.group)));
    let info = (*matches.first()?).clone();
    let alternatives = if api_version.is_none() && group.is_none() {
        // Same kind only: metrics.k8s.io serves `pods` and `nodes`, as PodMetrics and NodeMetrics.
        matches[1..]
            .iter()
            .filter(|r| r.group != info.group && r.kind == info.kind)
            .map(|r| (*r).clone())
            .collect()
    } else {
        Vec::new()
    };
    Some(Resolved { info, alternatives })
}

/// Convert to a kube `ApiResource` for dynamic calls.
pub fn api_resource(r: &ResourceInfo) -> ApiResource {
    ApiResource {
        group: r.group.clone(),
        version: r.version.clone(),
        api_version: r.api_version(),
        kind: r.kind.clone(),
        plural: r.plural.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(group: &str, kind: &str, plural: &str, short: &[&str]) -> ResourceInfo {
        ResourceInfo {
            group: group.into(),
            version: "v1".into(),
            kind: kind.into(),
            plural: plural.into(),
            namespaced: true,
            short_names: short.iter().map(|s| (*s).to_owned()).collect(),
            verbs: vec![],
        }
    }

    #[test]
    fn finds_by_kind_plural_or_short_name_preferring_builtin_groups() {
        let all = vec![
            r("apps", "Deployment", "deployments", &["deploy"]),
            r("example.com", "Deployment", "deployments", &[]),
            r("", "Pod", "pods", &["po"]),
        ];
        for q in ["Deployment", "deployments", "deploy", "DEPLOYMENT"] {
            assert_eq!(find(&all, q, None).unwrap().info.group, "apps");
        }
        assert_eq!(
            find(&all, "deployment", Some("example.com/v1"))
                .unwrap()
                .info
                .group,
            "example.com"
        );
        assert_eq!(find(&all, "po", None).unwrap().info.kind, "Pod");
        assert!(find(&all, "nope", None).is_none());
    }

    /// riseno/k8s-mcp#27: ambiguous kinds name the other groups; kubectl's group forms work.
    #[test]
    fn ambiguous_kinds_and_group_qualified_names() {
        let all = vec![
            r("bh.example.com", "Widget", "widgets", &[]),
            r("other.example.com", "Widget", "widgets", &[]),
        ];
        let w = find(&all, "Widget", None).unwrap();
        assert_eq!(w.info.group, "bh.example.com");
        assert_eq!(w.alternatives.len(), 1);
        assert!(
            w.note().unwrap().contains("other.example.com/v1"),
            "{:?}",
            w.note()
        );
        // riseno/k8s-mcp#77: a shared plural with another kind is not an alternative.
        let all = vec![
            r("", "Pod", "pods", &["po"]),
            r("metrics.k8s.io", "PodMetrics", "pods", &[]),
            r("", "Node", "nodes", &["no"]),
            r("metrics.k8s.io", "NodeMetrics", "nodes", &[]),
        ];
        for q in ["pods", "nodes", "Pod", "po"] {
            let core = find(&all, q, None).unwrap();
            assert_eq!(core.info.group, "", "{q}");
            assert!(core.note().is_none(), "{q}: {:?}", core.note());
        }
        let all = vec![
            r("bh.example.com", "Widget", "widgets", &[]),
            r("other.example.com", "Widget", "widgets", &[]),
        ];
        for q in ["widgets.other.example.com", "Widget.other.example.com"] {
            let w = find(&all, q, None).unwrap();
            assert_eq!(w.info.group, "other.example.com", "{q}");
            assert!(w.alternatives.is_empty());
        }
    }
}
