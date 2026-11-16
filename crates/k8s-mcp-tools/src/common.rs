//! Shared plumbing: context/namespace scoping under policy, policy-filtered listing,
//! event lookup, label selectors and object cleaning.

use std::fmt::Debug;

use jiff::{SignedDuration, Timestamp};
use k8s_mcp_core::cluster::Target;
use k8s_mcp_core::envelope::Envelope;
use k8s_mcp_core::{Error, Result};
use k8s_mcp_diagnose::Unavailable;
use k8s_mcp_diagnose::rules::last_seen;
use k8s_openapi::api::core::v1::Event;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use kube::Resource;
use kube::api::{Api, ListParams, PartialObjectMeta};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::Ctx;

/// A resolved context plus namespace (`None` = all allowed namespaces).
pub struct Scope {
    /// The context and its client.
    pub target: Target,
    /// Namespace, or `None` for all allowed namespaces.
    pub namespace: Option<String>,
}

/// Reject names that are not valid Kubernetes object names (DNS-1123 subdomain, or a
/// path-segment-safe name for kinds like RBAC that allow `:`).
pub fn check_name(what: &str, name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 253
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b':' | b'@'))
        && !name.contains("..");
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidInput(format!(
            "{what} {name:?} is not a valid Kubernetes name (letters, digits, '-', '.', '_', ':' or '@', at most 253 characters)"
        )))
    }
}

/// Namespaces are RFC 1123 labels: lowercase letters, digits and '-', at most 63 characters.
pub fn check_namespace_name(ns: &str) -> Result<()> {
    let ok = !ns.is_empty()
        && ns.len() <= 63
        && ns
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !ns.starts_with('-')
        && !ns.ends_with('-');
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidInput(format!(
            "namespace {ns:?} is not a valid namespace name (lowercase letters, digits and '-', at most 63 characters); list_resources kind=namespaces shows the namespaces"
        )))
    }
}

/// A numeric input within `1..=max`, or `default`. Out-of-range values are an error, not
/// silently clamped, so the caller learns its request was not what ran.
pub fn bounded<T: Copy + PartialOrd + From<u8> + std::fmt::Display>(
    name: &str,
    value: Option<T>,
    default: T,
    max: T,
) -> Result<T> {
    match value {
        None => Ok(default),
        Some(v) if v >= T::from(1) && v <= max => Ok(v),
        Some(v) => Err(Error::InvalidInput(format!(
            "{name} must be between 1 and {max}, got {v}"
        ))),
    }
}

/// After an empty namespaced result: fail with "namespace does not exist" when that is why.
/// Other lookup errors (for example Forbidden under namespace-scoped RBAC) are ignored.
pub async fn ensure_namespace(scope: &Scope) -> Result<()> {
    let Some(ns) = &scope.namespace else {
        return Ok(());
    };
    match Api::<k8s_openapi::api::core::v1::Namespace>::all(scope.target.client.clone())
        .get_opt(ns)
        .await
    {
        Ok(None) => Err(Error::NotFound(format!(
            "namespace {ns:?} does not exist in context {}; list_resources kind=namespaces shows the namespaces",
            scope.target.context
        ))),
        _ => Ok(()),
    }
}

/// Resolve context and namespace, enforcing the context allow-list and namespace policy.
pub async fn scope(
    ctx: &Ctx,
    context: Option<&str>,
    namespace: Option<&str>,
    all_namespaces: bool,
) -> Result<Scope> {
    let target = ctx.clusters.target(context, &ctx.policy).await?;
    if all_namespaces && namespace.is_none() {
        return Ok(Scope {
            target,
            namespace: None,
        });
    }
    let ns = namespace.map_or_else(|| target.namespace.clone(), str::to_owned);
    check_namespace_name(&ns)?;
    ctx.policy.check_namespace(&ns)?;
    Ok(Scope {
        target,
        namespace: Some(ns),
    })
}

/// Start an envelope stamped with the scope's context and namespace.
pub fn envelope(scope: &Scope, summary: impl Into<String>) -> Envelope {
    let mut e = Envelope::new(summary);
    e.context = Some(scope.target.context.clone());
    e.namespace.clone_from(&scope.namespace);
    e
}

/// Namespace of a typed object.
pub fn ns_of<K: Resource>(o: &K) -> &str {
    o.meta().namespace.as_deref().unwrap_or("")
}

/// List objects in the scope. Cluster-wide lists are filtered through the namespace
/// policy; if RBAC forbids listing cluster-wide, fall back to each allowed literal
/// namespace (plus the context's default) and report the fallback in `notes`.
pub async fn list_scoped<K>(
    ctx: &Ctx,
    scope: &Scope,
    lp: &ListParams,
    what: &str,
    notes: &mut Vec<Unavailable>,
) -> Result<Vec<K>>
where
    K: Resource<Scope = k8s_openapi::NamespaceResourceScope> + Clone + DeserializeOwned + Debug,
    <K as Resource>::DynamicType: Default,
{
    list_scoped_with(ctx, scope, what, notes, |api: Api<K>| {
        let lp = lp.clone();
        async move { api.list(&lp).await.map(|l| l.items) }
    })
    .await
}

/// [`list_scoped`], metadata only: no object bodies (Secret data, ConfigMap values) are read.
pub async fn list_meta_scoped<K>(
    ctx: &Ctx,
    scope: &Scope,
    lp: &ListParams,
    what: &str,
    notes: &mut Vec<Unavailable>,
) -> Result<Vec<PartialObjectMeta<K>>>
where
    K: Resource<Scope = k8s_openapi::NamespaceResourceScope> + Clone + DeserializeOwned + Debug,
    <K as Resource>::DynamicType: Default,
{
    list_scoped_with(ctx, scope, what, notes, |api: Api<K>| {
        let lp = lp.clone();
        async move { api.list_metadata(&lp).await.map(|l| l.items) }
    })
    .await
}

/// The policy filtering and RBAC fallback shared by the list helpers. (A plain closure
/// returning a `Send` future: `AsyncFn` futures cannot be proven `Send` for rmcp handlers.)
async fn list_scoped_with<K, T, F, Fut>(
    ctx: &Ctx,
    scope: &Scope,
    what: &str,
    notes: &mut Vec<Unavailable>,
    list: F,
) -> Result<Vec<T>>
where
    T: Resource,
    F: Fn(Api<K>) -> Fut,
    Fut: std::future::Future<Output = kube::Result<Vec<T>>> + Send,
    K: Resource<Scope = k8s_openapi::NamespaceResourceScope> + Clone + DeserializeOwned + Debug,
    <K as Resource>::DynamicType: Default,
{
    let client = scope.target.client.clone();
    if let Some(ns) = &scope.namespace {
        return list(Api::namespaced(client, ns))
            .await
            .map_err(|e| Error::kube(format!("list {what} in namespace {ns}"), &e));
    }
    match list(Api::all(client.clone())).await {
        Ok(items) => Ok(items
            .into_iter()
            .filter(|o| ctx.policy.namespace_allowed(ns_of(o)))
            .collect()),
        Err(e) => {
            let err = Error::kube(format!("list {what} in all namespaces"), &e);
            if !err.is_forbidden() {
                return Err(err);
            }
            let namespaces = fallback_namespaces(ctx, scope, what, notes);
            let mut out = Vec::new();
            for ns in namespaces {
                match list(Api::namespaced(client.clone(), &ns)).await {
                    Ok(items) => out.extend(items),
                    Err(e) => notes.push(Unavailable {
                        what: format!("{what} in namespace {ns}"),
                        reason: Error::kube(format!("list {what} in namespace {ns}"), &e)
                            .to_string(),
                    }),
                }
            }
            Ok(out)
        }
    }
}

/// Namespaces to list one by one when RBAC forbids a cluster-wide list: the allow-list's
/// literal names plus the context's namespace. Records the fallback in `notes`.
pub fn fallback_namespaces(
    ctx: &Ctx,
    scope: &Scope,
    what: &str,
    notes: &mut Vec<Unavailable>,
) -> Vec<String> {
    let mut namespaces = ctx.policy.literal_namespaces();
    if ctx.policy.namespace_allowed(&scope.target.namespace)
        && !namespaces.contains(&scope.target.namespace)
    {
        namespaces.push(scope.target.namespace.clone());
    }
    notes.push(Unavailable {
        what: format!("cluster-wide list of {what}"),
        reason: format!(
            "forbidden by RBAC; listed namespaces {} instead",
            namespaces.join(", ")
        ),
    });
    namespaces
}

/// Fetch something, turning failures into an [`Unavailable`] note instead of an error.
pub fn soft<T>(res: Result<T>, what: &str, notes: &mut Vec<Unavailable>) -> Option<T> {
    match res {
        Ok(v) => Some(v),
        Err(e) => {
            notes.push(Unavailable {
                what: what.to_owned(),
                reason: e.to_string(),
            });
            None
        }
    }
}

/// Events about one object in the last `window` (default 1h), newest first.
pub async fn events_for(
    target: &Target,
    namespace: &str,
    kind: &str,
    name: &str,
    now: Timestamp,
) -> Result<Vec<Event>> {
    let api: Api<Event> = if namespace.is_empty() {
        Api::all(target.client.clone())
    } else {
        Api::namespaced(target.client.clone(), namespace)
    };
    let lp = ListParams::default().fields(&format!(
        "involvedObject.kind={kind},involvedObject.name={name}"
    ));
    let mut events = api
        .list(&lp)
        .await
        .map_err(|e| Error::kube(format!("list events for {kind} {name}"), &e))?
        .items;
    retain_recent(&mut events, now, SignedDuration::from_hours(1));
    Ok(events)
}

/// Keep events seen within `window` of `now`, newest first.
pub fn retain_recent(events: &mut Vec<Event>, now: Timestamp, window: SignedDuration) {
    let cutoff = now.checked_sub(window).unwrap_or(now);
    events.retain(|e| last_seen(e).is_none_or(|t| t >= cutoff));
    events.sort_by_key(|e| std::cmp::Reverse(last_seen(e)));
}

/// Convert a LabelSelector into the string form used by list calls.
pub fn selector_string(sel: &LabelSelector) -> String {
    let mut parts: Vec<String> = sel
        .match_labels
        .iter()
        .flatten()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    for e in sel.match_expressions.iter().flatten() {
        let values = e.values.clone().unwrap_or_default().join(",");
        parts.push(match e.operator.as_str() {
            "In" => format!("{} in ({values})", e.key),
            "NotIn" => format!("{} notin ({values})", e.key),
            "Exists" => e.key.clone(),
            "DoesNotExist" => format!("!{}", e.key),
            _ => continue,
        });
    }
    parts.join(",")
}

pub use k8s_mcp_diagnose::rules::selector_matches;

/// Strip noise and redact an object for display (PROPOSAL §7.7 rule 2, §12.3).
pub fn clean(ctx: &Ctx, kind: &str, mut v: Value) -> Value {
    if let Some(meta) = v.get_mut("metadata").and_then(Value::as_object_mut) {
        meta.remove("managedFields");
        meta.remove("selfLink");
        if let Some(ann) = meta.get_mut("annotations").and_then(Value::as_object_mut) {
            ann.remove("kubectl.kubernetes.io/last-applied-configuration");
            ctx.redactor.map(ann);
        }
        if let Some(owners) = meta
            .get_mut("ownerReferences")
            .and_then(Value::as_array_mut)
        {
            for o in owners.iter_mut().filter_map(Value::as_object_mut) {
                o.remove("uid");
            }
        }
    }
    match kind {
        "Secret" => k8s_mcp_core::redact::sanitize_secret(&mut v),
        "ConfigMap" => {
            if let Some(data) = v.get_mut("data").and_then(Value::as_object_mut) {
                for (k, val) in data.iter_mut() {
                    if let Value::String(s) = val {
                        *s = ctx.redactor.config_value(k, s);
                    }
                }
            }
            if let Some(bin) = v.get_mut("binaryData").and_then(Value::as_object_mut) {
                for val in bin.values_mut() {
                    let n = val.as_str().map_or(0, |s| s.len() * 3 / 4);
                    *val = Value::String(format!("<{n} bytes>"));
                }
            }
        }
        _ => {}
    }
    redact_env(ctx, &mut v);
    strip_probe_times(&mut v);
    ctx.redactor.json(&mut v);
    v
}

/// Mask literal env values with sensitive names anywhere in the object (pod specs,
/// templates, job templates).
fn redact_env(ctx: &Ctx, v: &mut Value) {
    match v {
        Value::Object(m) => {
            if let Some(Value::Array(env)) = m.get_mut("env") {
                for e in env.iter_mut().filter_map(Value::as_object_mut) {
                    let name = e
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned();
                    if let Some(Value::String(val)) = e.get_mut("value") {
                        *val = ctx.redactor.named(&name, val);
                    }
                }
            }
            m.values_mut().for_each(|v| redact_env(ctx, v));
        }
        Value::Array(a) => a.iter_mut().for_each(|v| redact_env(ctx, v)),
        _ => {}
    }
}

fn strip_probe_times(v: &mut Value) {
    if let Some(conds) = v
        .pointer_mut("/status/conditions")
        .and_then(Value::as_array_mut)
    {
        for c in conds.iter_mut().filter_map(Value::as_object_mut) {
            c.remove("lastProbeTime");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_validated() {
        assert!(check_name("pod", "web-6d4cf56db6-abcde").is_ok());
        assert!(check_name("pod", "system:node:a").is_ok());
        assert!(check_name("pod", "../etc").is_err());
        assert!(check_name("pod", "a b").is_err());
        assert!(check_name("pod", "").is_err());
    }

    #[test]
    fn selectors_render() {
        let sel: LabelSelector = serde_json::from_value(serde_json::json!({
            "matchLabels": {"app": "web"},
            "matchExpressions": [{"key": "tier", "operator": "In", "values": ["a", "b"]}, {"key": "x", "operator": "Exists"}]
        }))
        .unwrap();
        assert_eq!(selector_string(&sel), "app=web,tier in (a,b),x");
    }
}
