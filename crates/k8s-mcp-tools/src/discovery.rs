//! API discovery (cached per context for 5 minutes) and kind resolution.

use std::sync::Arc;

use k8s_mcp_core::cluster::{ResourceInfo, Target};
use k8s_mcp_core::{Error, Result};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::APIResourceList;
use kube::discovery::ApiResource;

use crate::Ctx;

/// All resources served by the cluster (preferred version of each group), cached.
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
    for g in groups.groups {
        let Some(pref) = g.preferred_version.or_else(|| g.versions.first().cloned()) else {
            continue;
        };
        match client.list_api_group_resources(&pref.group_version).await {
            Ok(list) => push_list(&mut out, &g.name, &list),
            // Aggregated APIs (e.g. a broken metrics-server) can fail on their own.
            Err(e) => {
                tracing::debug!(group = %pref.group_version, error = %e, "skipping API group");
            }
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

/// Resolve a user-supplied kind (`Deployment`, `deployments`, `deploy`, `NodePool`) and
/// optional `api_version` to a resource. Refreshes discovery once on a miss.
pub async fn resolve(
    ctx: &Ctx,
    target: &Target,
    kind: &str,
    api_version: Option<&str>,
) -> Result<ResourceInfo> {
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

fn find(all: &[ResourceInfo], kind: &str, api_version: Option<&str>) -> Option<ResourceInfo> {
    let k = kind.to_ascii_lowercase();
    let matches = |r: &&ResourceInfo| {
        (r.kind.to_ascii_lowercase() == k || r.plural == k || r.short_names.contains(&k))
            && api_version.is_none_or(|v| r.api_version() == v || r.group == v)
    };
    // Prefer the core group and well-known groups over CRDs that reuse a kind name.
    all.iter()
        .filter(matches)
        .min_by_key(|r| match r.group.as_str() {
            "" => 0,
            "apps" | "batch" | "networking.k8s.io" | "policy" | "storage.k8s.io"
            | "autoscaling" => 1,
            g if g.ends_with(".k8s.io") => 2,
            _ => 3,
        })
        .cloned()
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
            assert_eq!(find(&all, q, None).unwrap().group, "apps");
        }
        assert_eq!(
            find(&all, "deployment", Some("example.com/v1"))
                .unwrap()
                .group,
            "example.com"
        );
        assert_eq!(find(&all, "po", None).unwrap().kind, "Pod");
        assert!(find(&all, "nope", None).is_none());
    }
}
