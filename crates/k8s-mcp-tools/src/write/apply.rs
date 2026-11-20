//! `apply_manifest`: server-side apply of YAML documents, field manager `k8s-mcp`, never
//! forced, so another manager's fields are reported as conflicts instead of taken over.

use k8s_mcp_core::finding::NextCall;
use k8s_mcp_core::{Error, Result};
use kube::api::{Api, DynamicObject, Patch};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use super::node::check_node_write;
use super::{Change, check_confirm, run, state};
use crate::common::{check_name, check_namespace_name, clean, scope};
use crate::discovery::{api_resource, resolve};
use crate::{Ctx, Envelope};

/// Largest manifest accepted, in bytes.
const MAX_MANIFEST: usize = 256 * 1024;
/// Most objects in one manifest.
const MAX_OBJECTS: usize = 20;
/// Diff lines shown per object.
const MAX_LINES: usize = 40;

/// What `apply_manifest` refuses (v0.4 decision 2): Secrets would carry their values through
/// the server and the audit log; the API groups below are the shortest paths to cluster-admin
/// (RBAC, admission control, CRDs, aggregated APIs), refused whole so new kinds are covered.
const REFUSED_KINDS: &[(&str, &str)] = &[("", "Secret")];
const REFUSED_GROUPS: &[&str] = &[
    "rbac.authorization.k8s.io",
    "admissionregistration.k8s.io",
    "apiextensions.k8s.io",
    "apiregistration.k8s.io",
];

/// Inputs for `apply_manifest`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyManifestInput {
    /// One or more YAML (or JSON) documents, separated by `---`.
    pub manifest: String,
    /// Namespace for namespaced objects that name none (default: the context's namespace).
    pub namespace: Option<String>,
    /// Kubeconfig context.
    pub context: Option<String>,
    /// `true` (default): a server-side dry-run apply that returns each object's diff and a
    /// `confirm_token`. `false`: apply; needs that `confirm_token`.
    pub dry_run: Option<bool>,
    /// The token from the plan, with `dry_run: false`.
    pub confirm_token: Option<String>,
}

/// One document, resolved and checked.
struct Object {
    api: Api<DynamicObject>,
    kind: String,
    /// `namespace/name`, or `name` for a cluster-scoped object.
    id: String,
    name: String,
    body: Value,
    /// The live object, cleaned for display (`None`: it does not exist yet).
    live: Option<Value>,
    /// The live object's [`state`] for the confirm token.
    live_state: Option<String>,
}

/// Server-side apply a manifest.
pub async fn apply_manifest(ctx: &Ctx, input: ApplyManifestInput) -> Result<Envelope> {
    check_confirm(
        "apply_manifest",
        input.dry_run,
        input.confirm_token.as_deref(),
    )?;
    if input.manifest.len() > MAX_MANIFEST {
        return Err(Error::InvalidInput(format!(
            "the manifest is {} bytes; apply_manifest takes at most {MAX_MANIFEST}. Split it into smaller applies.",
            input.manifest.len()
        )));
    }
    let docs: Vec<Value> = serde_saphyr::from_multiple::<Value>(&input.manifest)
        .map_err(|e| Error::InvalidInput(format!("the manifest is not valid YAML: {e}")))?
        .into_iter()
        .filter(|d| !d.is_null())
        .collect();
    if docs.is_empty() || docs.len() > MAX_OBJECTS {
        return Err(Error::InvalidInput(format!(
            "the manifest has {} objects; apply_manifest takes 1 to {MAX_OBJECTS}",
            docs.len()
        )));
    }
    let sc = scope(
        ctx,
        input.context.as_deref(),
        input.namespace.as_deref(),
        false,
    )
    .await?;
    let default_ns = sc.namespace.clone().unwrap_or_default();
    let mut objects = Vec::new();
    for doc in docs {
        objects.push(prepare(ctx, &sc.target, &default_ns, doc).await?);
    }
    let args = json!({"manifest": input.manifest, "namespace": default_ns});
    let targets: Vec<(String, Option<String>)> = objects
        .iter()
        .map(|o| (format!("{}/{}", o.kind, o.id), o.live_state.clone()))
        .collect();
    let objects = &objects;
    run(
        ctx,
        &sc,
        "apply_manifest",
        args,
        &targets,
        (input.dry_run, input.confirm_token.as_deref()),
        |mode| async move {
            let mut lines = Vec::new();
            let mut applied = Vec::new();
            for o in objects {
                let result = o
                    .api
                    .patch(&o.name, &mode.apply(), &Patch::Apply(&o.body))
                    .await
                    .map_err(|e| {
                        let done = if applied.is_empty() {
                            String::new()
                        } else {
                            format!(" (already applied: {})", applied.join(", "))
                        };
                        Error::kube(format!("apply {} {}{done}", o.kind, o.id), &e)
                    })?;
                applied.push(format!("{} {}", o.kind, o.id));
                let after = clean(
                    ctx,
                    &o.kind,
                    serde_json::to_value(&result).unwrap_or_default(),
                );
                let mut diff = Vec::new();
                match &o.live {
                    None => lines.push(format!("create {} {}", o.kind, o.id)),
                    Some(live) => {
                        diff_values(live, &after, "", &mut diff);
                        lines.push(if diff.is_empty() {
                            format!("{} {}: unchanged", o.kind, o.id)
                        } else {
                            format!("update {} {}:", o.kind, o.id)
                        });
                    }
                }
                let more = diff.len().saturating_sub(MAX_LINES);
                lines.extend(diff.into_iter().take(MAX_LINES).map(|l| format!("  {l}")));
                if more > 0 {
                    lines.push(format!("  … {more} more changed fields"));
                }
            }
            Ok(Change {
                summary: format!(
                    "server-side apply of {} object(s): {}",
                    objects.len(),
                    applied.join(", ")
                ),
                lines,
                next: objects
                    .iter()
                    .take(3)
                    .map(|o| {
                        let mut a = json!({"kind": o.kind, "name": o.name});
                        if let Some((ns, _)) = o.id.split_once('/') {
                            a["namespace"] = json!(ns);
                        }
                        NextCall::new("get_resource", a, "see the applied object")
                    })
                    .collect(),
            })
        },
    )
    .await
}

/// Resolve one document's kind, check it may be applied, and read the live object.
async fn prepare(
    ctx: &Ctx,
    target: &k8s_mcp_core::cluster::Target,
    default_ns: &str,
    mut doc: Value,
) -> Result<Object> {
    let (Some(api_version), Some(kind)) = (
        doc.get("apiVersion")
            .and_then(Value::as_str)
            .map(str::to_owned),
        doc.get("kind").and_then(Value::as_str).map(str::to_owned),
    ) else {
        return Err(Error::InvalidInput(
            "every document needs apiVersion and kind".into(),
        ));
    };
    if kind == "List" {
        return Err(Error::InvalidInput(
            "a List is not applied as such: pass its items as separate documents".into(),
        ));
    }
    let name = doc
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            Error::InvalidInput(format!(
                "{kind} needs metadata.name (generateName cannot be applied)"
            ))
        })?;
    check_name(&kind, &name)?;
    let info = resolve(ctx, target, &kind, Some(&api_version)).await?.info;
    if REFUSED_KINDS.contains(&(info.group.as_str(), info.kind.as_str()))
        || REFUSED_GROUPS.contains(&info.group.as_str())
    {
        return Err(Error::Forbidden(format!(
            "apply_manifest does not apply {} objects ({kind} {name}): {}. Use kubectl for this change.",
            info.kind,
            if info.kind == "Secret" {
                "their values would pass through k8s-mcp and its audit log"
            } else {
                "RBAC, admission control, CRDs and aggregated APIs can grant or bypass any permission"
            }
        )));
    }
    let meta = doc
        .get_mut("metadata")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| Error::InvalidInput(format!("{kind} {name} has no metadata")))?;
    // Fields the server owns: server-side apply rejects managedFields, and the manifest's
    // resourceVersion is replaced by the live one below.
    for f in [
        "managedFields",
        "resourceVersion",
        "uid",
        "creationTimestamp",
        "generation",
    ] {
        meta.remove(f);
    }
    let client = target.writer.clone();
    let ar = api_resource(&info);
    let (api, id): (Api<DynamicObject>, String) = if info.namespaced {
        let ns = meta
            .get("namespace")
            .and_then(Value::as_str)
            .map_or_else(|| default_ns.to_owned(), str::to_owned);
        check_namespace_name(&ns)?;
        ctx.policy.check_write_namespace(&ns)?;
        meta.insert("namespace".into(), json!(ns));
        (
            Api::namespaced_with(client, &ns, &ar),
            format!("{ns}/{name}"),
        )
    } else {
        check_node_write(ctx, "apply_manifest")?;
        if info.kind == "Namespace" {
            ctx.policy.check_write_namespace(&name)?;
        }
        meta.remove("namespace");
        (Api::all_with(client, &ar), name.clone())
    };
    if let Some(obj) = doc.as_object_mut() {
        obj.remove("status");
    }
    let live = api
        .get_opt(&name)
        .await
        .map_err(|e| Error::kube(format!("get {kind} {id}"), &e))?;
    let rv = live
        .as_ref()
        .and_then(|l| l.metadata.resource_version.clone());
    let live_state = live.as_ref().map(state);
    // The live resourceVersion (the one the confirm token is checked against) makes the apply
    // conditional: an object changed after this read gets a conflict instead of the apply.
    if let (Some(rv), Some(meta)) = (&rv, doc.get_mut("metadata").and_then(Value::as_object_mut)) {
        meta.insert("resourceVersion".into(), json!(rv));
    }
    let live = live.map(|l| {
        clean(
            ctx,
            &info.kind,
            serde_json::to_value(&l).unwrap_or_default(),
        )
    });
    Ok(Object {
        api,
        kind: info.kind,
        id,
        name,
        body: doc,
        live,
        live_state,
    })
}

/// Server-maintained fields that change on every write.
fn ignored(path: &str) -> bool {
    path == "status"
        || path.starts_with("status.")
        || matches!(
            path,
            "metadata.resourceVersion"
                | "metadata.generation"
                | "metadata.uid"
                | "metadata.creationTimestamp"
        )
}

/// Field-level differences, `path: before → after`, `+path: value` and `-path: value`.
fn diff_values(old: &Value, new: &Value, path: &str, out: &mut Vec<String>) {
    if ignored(path) {
        return;
    }
    let at = |k: &str| {
        if path.is_empty() {
            k.to_owned()
        } else {
            format!("{path}.{k}")
        }
    };
    match (old, new) {
        (Value::Object(a), Value::Object(b)) => {
            let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                match (a.get(k), b.get(k)) {
                    (Some(x), Some(y)) => diff_values(x, y, &at(k), out),
                    (None, Some(y)) if !ignored(&at(k)) => {
                        out.push(format!("+{}: {}", at(k), short(y)));
                    }
                    (Some(x), None) if !ignored(&at(k)) => {
                        out.push(format!("-{}: {}", at(k), short(x)));
                    }
                    _ => {}
                }
            }
        }
        (Value::Array(a), Value::Array(b)) if a.len() == b.len() => {
            for (i, (x, y)) in a.iter().zip(b).enumerate() {
                diff_values(x, y, &format!("{path}[{i}]"), out);
            }
        }
        (x, y) if x != y => out.push(format!("{path}: {} → {}", short(x), short(y))),
        _ => {}
    }
}

fn short(v: &Value) -> String {
    k8s_mcp_core::text::truncate(&v.to_string(), 120)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diffs_name_fields_and_skip_server_fields() {
        let old = json!({"metadata": {"resourceVersion": "1", "labels": {"a": "1", "gone": "x"}},
            "spec": {"replicas": 2, "ports": [80, 443]}, "status": {"ready": 1}});
        let new = json!({"metadata": {"resourceVersion": "2", "labels": {"a": "2", "b": "y"}},
            "spec": {"replicas": 3, "ports": [80]}, "status": {"ready": 3}});
        let mut out = Vec::new();
        diff_values(&old, &new, "", &mut out);
        assert_eq!(
            out,
            [
                "metadata.labels.a: \"1\" → \"2\"",
                "+metadata.labels.b: \"y\"",
                "-metadata.labels.gone: \"x\"",
                "spec.ports: [80,443] → [80]",
                "spec.replicas: 2 → 3",
            ]
        );
    }

    /// A YAML alias bomb ("billion laughs") within the size cap is rejected, not expanded.
    #[test]
    fn alias_bombs_are_refused() {
        let lines: Vec<String> = ('a'..='i')
            .zip('b'..='j')
            .map(|(prev, name)| {
                format!(
                    "{name}: &{name} [{}]",
                    vec![format!("*{prev}"); 10].join(", ")
                )
            })
            .collect();
        let bomb = format!(
            "a: &a [x, x, x, x, x, x, x, x, x, x]\n{}\n",
            lines.join("\n")
        );
        assert!(bomb.len() < MAX_MANIFEST);
        let started = std::time::Instant::now();
        assert!(serde_saphyr::from_multiple::<Value>(&bomb).is_err());
        // The parser's budget stops it after a few hundred ms in a debug build; expanding the
        // 10^10 nodes would take hours.
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    proptest::proptest! {
        /// Fuzzing (v1.0 security review): any manifest text parses or fails cleanly.
        #[test]
        fn any_manifest_text_parses_or_fails_cleanly(text in "(?s).{0,400}") {
            let _ = serde_saphyr::from_multiple::<Value>(&text);
        }
    }
}
