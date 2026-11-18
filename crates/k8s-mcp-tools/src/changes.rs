//! What changed: `rollout_history` (one workload's revisions with diffs) and `recent_changes`
//! (rollouts, created/updated objects and Helm releases in a time window).
//!
//! Diffs never show env values (names only), and change-cause annotations are redacted:
//! both can carry credentials. Object changes come from metadata-only lists, so Secret and
//! ConfigMap bodies are never read.

use std::collections::BTreeMap;

use jiff::{SignedDuration, Timestamp};
use k8s_mcp_core::envelope::Section;
use k8s_mcp_core::text::{age, parse_duration};
use k8s_mcp_core::{Error, Result};
use k8s_mcp_diagnose::Unavailable;
use k8s_openapi::api::apps::v1::{
    ControllerRevision, DaemonSet, Deployment, ReplicaSet, StatefulSet,
};
use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;
use k8s_openapi::api::batch::v1::CronJob;
use k8s_openapi::api::core::v1::{
    ConfigMap, Container, PersistentVolumeClaim, PodSpec, PodTemplateSpec, Secret, Service,
};
use k8s_openapi::api::networking::v1::{Ingress, NetworkPolicy};
use k8s_openapi::api::policy::v1::PodDisruptionBudget;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, ListParams, PartialObjectMeta};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::common::{
    check_name, ensure_namespace, envelope, list_meta_scoped, list_scoped, scope, soft,
};
use crate::diagnose::{owned, workload_kind};
use crate::read::add_notes;
use crate::{Ctx, Envelope};

/// Revisions listed by `rollout_history`.
const MAX_REVISIONS: usize = 10;
/// Rows listed by `recent_changes`.
const MAX_CHANGES: usize = 50;
/// Diff lines shown per change in `recent_changes`.
const DIFF_SUMMARY: usize = 3;
/// Longest `since` accepted.
const MAX_SINCE: SignedDuration = SignedDuration::from_hours(7 * 24);

/// One revision of a workload's pod template.
pub(crate) struct Revision {
    pub(crate) number: i64,
    created: Option<Timestamp>,
    pub(crate) template: PodTemplateSpec,
    change_cause: Option<String>,
    /// `ready/desired` for a ReplicaSet.
    replicas: Option<String>,
}

fn revision_of_rs(rs: &ReplicaSet) -> Option<Revision> {
    let ann = rs.metadata.annotations.as_ref();
    Some(Revision {
        number: ann?
            .get("deployment.kubernetes.io/revision")?
            .parse()
            .ok()?,
        created: created(&rs.metadata),
        template: rs.spec.as_ref()?.template.clone()?,
        change_cause: ann.and_then(|a| a.get("kubernetes.io/change-cause").cloned()),
        replicas: rs.spec.as_ref().map(|s| {
            format!(
                "{}/{}",
                rs.status
                    .as_ref()
                    .and_then(|s| s.ready_replicas)
                    .unwrap_or(0),
                s.replicas.unwrap_or(1)
            )
        }),
    })
}

fn revision_of_cr(cr: &ControllerRevision) -> Option<Revision> {
    let data = cr.data.as_ref()?;
    Some(Revision {
        number: cr.revision,
        created: created(&cr.metadata),
        template: serde_json::from_value(data.0["spec"]["template"].clone()).ok()?,
        change_cause: cr
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get("kubernetes.io/change-cause").cloned()),
        replicas: None,
    })
}

fn created(meta: &ObjectMeta) -> Option<Timestamp> {
    meta.creation_timestamp.as_ref().map(|t| t.0)
}

/// The revisions of a Deployment, StatefulSet or DaemonSet, newest first. Fails with
/// NotFound when the workload does not exist (an empty list would read as "never rolled out").
pub(crate) async fn revisions(
    client: &kube::Client,
    ns: &str,
    kind: &str,
    name: &str,
) -> Result<Vec<Revision>> {
    let exists = match kind {
        "Deployment" => Api::<Deployment>::namespaced(client.clone(), ns)
            .get(name)
            .await
            .map(drop),
        "StatefulSet" => Api::<StatefulSet>::namespaced(client.clone(), ns)
            .get(name)
            .await
            .map(drop),
        "DaemonSet" => Api::<DaemonSet>::namespaced(client.clone(), ns)
            .get(name)
            .await
            .map(drop),
        _ => Ok(()),
    };
    exists.map_err(|e| Error::kube(format!("get {kind} {name} in namespace {ns}"), &e))?;
    let mut revs: Vec<Revision> = match kind {
        "Deployment" => owned::<ReplicaSet>(client, ns, kind, name)
            .await?
            .iter()
            .filter_map(revision_of_rs)
            .collect(),
        "StatefulSet" | "DaemonSet" => owned::<ControllerRevision>(client, ns, kind, name)
            .await?
            .iter()
            .filter_map(revision_of_cr)
            .collect(),
        other => {
            return Err(Error::InvalidInput(format!(
                "{other} has no rollout revisions: use Deployment, StatefulSet or DaemonSet"
            )));
        }
    };
    revs.sort_by_key(|r| std::cmp::Reverse(r.number));
    Ok(revs)
}

fn images(t: &PodTemplateSpec) -> String {
    t.spec
        .iter()
        .flat_map(|s| &s.containers)
        .filter_map(|c| c.image.as_deref())
        .collect::<Vec<_>>()
        .join(",")
}

/// What changed between two pod templates, one line per change. Env values are never shown.
pub(crate) fn template_diff(old: &PodTemplateSpec, new: &PodTemplateSpec) -> Vec<String> {
    let empty = PodSpec::default();
    let (os, ns) = (
        old.spec.as_ref().unwrap_or(&empty),
        new.spec.as_ref().unwrap_or(&empty),
    );
    let by_name = |s: &PodSpec| -> BTreeMap<String, Container> {
        s.init_containers
            .iter()
            .flatten()
            .chain(&s.containers)
            .map(|c| (c.name.clone(), c.clone()))
            .collect()
    };
    let (oc, nc) = (by_name(os), by_name(ns));
    let mut out = Vec::new();
    for name in oc.keys().filter(|k| !nc.contains_key(*k)) {
        out.push(format!("container {name} removed"));
    }
    for (name, c) in &nc {
        let Some(o) = oc.get(name) else {
            out.push(format!(
                "container {name} added (image {})",
                c.image.as_deref().unwrap_or("?")
            ));
            continue;
        };
        container_diff(name, o, c, &mut out);
    }
    let changed = |what: &str, a: &Value, b: &Value, out: &mut Vec<String>| {
        if a != b {
            out.push(format!("{what} changed"));
        }
    };
    changed(
        "serviceAccountName",
        &json!(os.service_account_name),
        &json!(ns.service_account_name),
        &mut out,
    );
    changed(
        "nodeSelector",
        &json!(os.node_selector),
        &json!(ns.node_selector),
        &mut out,
    );
    changed(
        "affinity",
        &json!(os.affinity),
        &json!(ns.affinity),
        &mut out,
    );
    changed(
        "tolerations",
        &json!(os.tolerations),
        &json!(ns.tolerations),
        &mut out,
    );
    let vols = |s: &PodSpec| -> Vec<String> {
        s.volumes.iter().flatten().map(|v| v.name.clone()).collect()
    };
    let (ov, nv) = (vols(os), vols(ns));
    for v in nv.iter().filter(|v| !ov.contains(v)) {
        out.push(format!("volume {v} added"));
    }
    for v in ov.iter().filter(|v| !nv.contains(v)) {
        out.push(format!("volume {v} removed"));
    }
    let restarted = |t: &PodTemplateSpec| {
        t.metadata
            .as_ref()
            .and_then(|m| m.annotations.as_ref())
            .and_then(|a| a.get("kubectl.kubernetes.io/restartedAt").cloned())
    };
    if restarted(old) != restarted(new) && restarted(new).is_some() {
        out.push("restarted (kubectl rollout restart)".into());
    }
    if out.is_empty() {
        out.push("no pod template change".into());
    }
    out
}

fn container_diff(name: &str, o: &Container, c: &Container, out: &mut Vec<String>) {
    if o.image != c.image {
        out.push(format!(
            "container {name}: image {} -> {}",
            o.image.as_deref().unwrap_or("?"),
            c.image.as_deref().unwrap_or("?")
        ));
    }
    if o.command != c.command {
        out.push(format!("container {name}: command changed"));
    }
    if o.args != c.args {
        out.push(format!("container {name}: args changed"));
    }
    // Names only: values (and valueFrom references) may be credentials.
    let env = |c: &Container| -> BTreeMap<String, Value> {
        c.env
            .iter()
            .flatten()
            .map(|e| (e.name.clone(), json!([e.value, e.value_from])))
            .collect()
    };
    let (oe, ne) = (env(o), env(c));
    let names = |pred: &dyn Fn(&String) -> bool, keys: &BTreeMap<String, Value>| -> Vec<String> {
        keys.keys().filter(|k| pred(k)).cloned().collect()
    };
    for (what, list) in [
        ("added", names(&|k| !oe.contains_key(k), &ne)),
        ("removed", names(&|k| !ne.contains_key(k), &oe)),
        (
            "changed",
            names(&|k| ne.get(k).is_some_and(|n| oe.get(k) != Some(n)), &oe),
        ),
    ] {
        if !list.is_empty() {
            out.push(format!("container {name}: env {what}: {}", list.join(", ")));
        }
    }
    if o.env_from != c.env_from {
        out.push(format!("container {name}: envFrom changed"));
    }
    let resources = |c: &Container| -> BTreeMap<String, String> {
        let r = c.resources.clone().unwrap_or_default();
        let mut m = BTreeMap::new();
        for (kind, list) in [("requests", r.requests), ("limits", r.limits)] {
            for (k, q) in list.unwrap_or_default() {
                m.insert(format!("{kind}.{k}"), q.0);
            }
        }
        m
    };
    let (or, nr) = (resources(o), resources(c));
    let keys: std::collections::BTreeSet<&String> = or.keys().chain(nr.keys()).collect();
    for k in keys {
        let (a, b) = (or.get(k), nr.get(k));
        if a != b {
            out.push(format!(
                "container {name}: {k} {} -> {}",
                a.map_or("none", String::as_str),
                b.map_or("none", String::as_str)
            ));
        }
    }
    if json!(o.ports) != json!(c.ports) {
        out.push(format!("container {name}: ports changed"));
    }
    for (probe, a, b) in [
        ("livenessProbe", &o.liveness_probe, &c.liveness_probe),
        ("readinessProbe", &o.readiness_probe, &c.readiness_probe),
        ("startupProbe", &o.startup_probe, &c.startup_probe),
    ] {
        if a != b {
            out.push(format!("container {name}: {probe} changed"));
        }
    }
}

// ---------------------------------------------------------------------------------------
// rollout_history

/// Inputs for `rollout_history`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RolloutHistoryInput {
    /// Deployment, StatefulSet or DaemonSet.
    pub kind: String,
    /// Workload name.
    pub name: String,
    /// Two revision numbers to diff (default: the newest two).
    pub compare: Option<Vec<i64>>,
    /// Namespace (default: the context's namespace).
    pub namespace: Option<String>,
    /// Kubeconfig context.
    pub context: Option<String>,
}

/// A workload's revisions (images, change-cause, age) and the diff of two of them.
pub async fn rollout_history(ctx: &Ctx, input: RolloutHistoryInput) -> Result<Envelope> {
    check_name("name", &input.name)?;
    let kind = workload_kind(&input.kind)?;
    if let Some(c) = &input.compare
        && c.len() != 2
    {
        return Err(Error::InvalidInput(format!(
            "compare takes exactly two revision numbers, got {}",
            c.len()
        )));
    }
    let sc = scope(
        ctx,
        input.context.as_deref(),
        input.namespace.as_deref(),
        false,
    )
    .await?;
    let ns = sc.namespace.clone().unwrap_or_default();
    let now = ctx.now();
    let revs = revisions(&sc.target.client, &ns, kind, &input.name).await?;
    let find = |n: i64| revs.iter().find(|r| r.number == n);
    let pair = match input.compare.as_deref() {
        Some([a, b]) => {
            let (a, b) = (*a.min(b), *a.max(b));
            let missing = [a, b].into_iter().find(|n| find(*n).is_none());
            if let Some(n) = missing {
                return Err(Error::NotFound(format!(
                    "{kind} {} has no revision {n}; available: {}",
                    input.name,
                    revs.iter()
                        .map(|r| r.number.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
            find(a).zip(find(b))
        }
        _ => revs.get(1).zip(revs.first()),
    };
    let head = format!("{kind} {} ({ns}): {} revisions", input.name, revs.len());
    let summary = match (revs.first(), pair) {
        (None, _) => format!(
            "{head}; it has never been rolled out (no ReplicaSet or ControllerRevision found)."
        ),
        (Some(cur), Some((old, new))) => format!(
            "{head}, current {} ({}), created {} ago. Revision {} -> {}: {}.",
            cur.number,
            images(&cur.template),
            cur.created.map_or_else(|| "?".into(), |t| age(now, t)),
            old.number,
            new.number,
            template_diff(&old.template, &new.template)
                .iter()
                .take(DIFF_SUMMARY)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        ),
        (Some(cur), None) => format!(
            "{head}, current {} ({}).",
            cur.number,
            images(&cur.template)
        ),
    };
    let mut e = envelope(&sc, summary);
    e.columns = vec!["revision", "age", "images", "replicas", "change_cause"];
    e.items = revs
        .iter()
        .take(MAX_REVISIONS)
        .map(|r| {
            json!({
                "revision": r.number,
                "age": r.created.map(|t| age(now, t)),
                "images": images(&r.template),
                "replicas": r.replicas,
                "change_cause": r.change_cause.as_deref().map(|c| ctx.redactor.text(c).into_owned()),
            })
        })
        .collect();
    if revs.len() > MAX_REVISIONS {
        e.truncated = true;
        e.omitted.items = revs.len() - MAX_REVISIONS;
    }
    if let Some((old, new)) = pair {
        e.sections.push(Section {
            title: format!("DIFF revision {} -> {}", old.number, new.number),
            lines: template_diff(&old.template, &new.template),
            untrusted: None,
        });
    }
    e.untrusted_fields = vec!["items[*].change_cause".into()];
    Ok(e)
}

// ---------------------------------------------------------------------------------------
// recent_changes

/// Inputs for `recent_changes`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecentChangesInput {
    /// Limit to one namespace (default: all allowed namespaces).
    pub namespace: Option<String>,
    /// Time window, e.g. `30m`, `2h`, `1d` (default `2h`, at most 7d).
    pub since: Option<String>,
    /// Only this workload, as `kind/name` (needs `namespace` or the context's namespace).
    pub workload: Option<String>,
    /// Kubeconfig context.
    pub context: Option<String>,
}

/// One row of `recent_changes`.
struct Change {
    at: Timestamp,
    kind: String,
    namespace: String,
    name: String,
    what: String,
}

/// Rollout rows from revisions newer than `cutoff`, each diffed against the one before.
fn rollout_changes(
    kind: &str,
    ns: &str,
    name: &str,
    revs: &[Revision],
    cutoff: Timestamp,
) -> Vec<Change> {
    revs.iter()
        .enumerate()
        .filter(|(_, r)| r.number > 1 && r.created.is_some_and(|t| t >= cutoff))
        .filter_map(|(i, r)| {
            let prev = revs.get(i + 1)?;
            Some(Change {
                at: r.created?,
                kind: kind.to_owned(),
                namespace: ns.to_owned(),
                name: name.to_owned(),
                what: format!(
                    "rolled out revision {}: {}",
                    r.number,
                    template_diff(&prev.template, &r.template)
                        .iter()
                        .take(DIFF_SUMMARY)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            })
        })
        .collect()
}

/// `created`, or the newest spec/metadata update with its field manager (status updates and
/// the controller manager's own bookkeeping are ignored).
fn object_change(meta: &ObjectMeta, cutoff: Timestamp) -> Option<(Timestamp, String)> {
    if let Some(t) = created(meta)
        && t >= cutoff
    {
        return Some((t, "created".into()));
    }
    meta.managed_fields
        .iter()
        .flatten()
        .filter(|m| m.subresource.as_deref() != Some("status"))
        .filter(|m| {
            m.manager.as_deref() != Some("kube-controller-manager")
                || m.subresource.as_deref() == Some("scale")
        })
        .filter_map(|m| Some((m.time.as_ref()?.0, m)))
        .filter(|(t, _)| *t >= cutoff)
        .max_by_key(|(t, _)| *t)
        .map(|(t, m)| {
            let by = m.manager.as_deref().unwrap_or("unknown");
            let how = match m.subresource.as_deref() {
                Some("scale") => " (scale)".to_owned(),
                _ => String::new(),
            };
            (t, format!("updated by {by}{how}"))
        })
}

/// Objects that only record controller state, which would drown real changes.
fn is_noise(kind: &str, meta: &ObjectMeta) -> bool {
    // ponytail: name/annotation heuristics; replace with a manager allow-list if they miss.
    kind == "ConfigMap"
        && (matches!(
            meta.name.as_deref(),
            // Written by the CA every few seconds / created in every namespace by Kubernetes.
            Some("cluster-autoscaler-status" | "kube-root-ca.crt")
        ) || meta
            .annotations
            .as_ref()
            .is_some_and(|a| a.contains_key("control-plane.alpha.kubernetes.io/leader")))
}

/// Recent rollouts, created or updated objects, and Helm releases.
pub async fn recent_changes(ctx: &Ctx, input: RecentChangesInput) -> Result<Envelope> {
    let since = match &input.since {
        Some(s) => parse_duration(s).map_err(Error::InvalidInput)?,
        None => SignedDuration::from_hours(2),
    };
    if since > MAX_SINCE || since <= SignedDuration::ZERO {
        return Err(Error::InvalidInput(
            "since must be between 1s and 7d".into(),
        ));
    }
    let workload = match &input.workload {
        Some(w) => {
            let (k, n) = w.split_once('/').ok_or_else(|| {
                Error::InvalidInput(format!(
                    "workload {w:?} must be kind/name, e.g. deployment/web"
                ))
            })?;
            check_name("workload name", n)?;
            Some((workload_kind(k)?, n.to_owned()))
        }
        None => None,
    };
    let all_ns = input.namespace.is_none() && workload.is_none();
    let sc = scope(
        ctx,
        input.context.as_deref(),
        input.namespace.as_deref(),
        all_ns,
    )
    .await?;
    // A mistyped namespace must not read as "nothing found" (#67).
    if input.namespace.is_some() {
        ensure_namespace(&sc).await?;
    }
    let now = ctx.now();
    let cutoff = now.checked_sub(since).unwrap_or(now);
    let client = sc.target.client.clone();
    let mut un: Vec<Unavailable> = Vec::new();
    let mut changes: Vec<Change> = Vec::new();

    if let Some((kind, name)) = &workload {
        let ns = sc.namespace.clone().unwrap_or_default();
        let revs = revisions(&client, &ns, kind, name).await?;
        changes.extend(rollout_changes(kind, &ns, name, &revs, cutoff));
    } else {
        // Deployment rollouts: ReplicaSets grouped by their owner.
        let mut by_owner: BTreeMap<(String, String), Vec<Revision>> = BTreeMap::new();
        for rs in soft(
            list_scoped::<ReplicaSet>(ctx, &sc, &ListParams::default(), "replicasets", &mut un)
                .await,
            "ReplicaSets",
            &mut un,
        )?
        .into_iter()
        .flatten()
        {
            let owner = rs
                .metadata
                .owner_references
                .iter()
                .flatten()
                .find(|o| o.kind == "Deployment")
                .map(|o| o.name.clone());
            if let (Some(owner), Some(rev)) = (owner, revision_of_rs(&rs)) {
                by_owner
                    .entry((rs.metadata.namespace.clone().unwrap_or_default(), owner))
                    .or_default()
                    .push(rev);
            }
        }
        for ((ns, name), mut revs) in by_owner {
            revs.sort_by_key(|r| std::cmp::Reverse(r.number));
            changes.extend(rollout_changes("Deployment", &ns, &name, &revs, cutoff));
        }
        // StatefulSet and DaemonSet rollouts: ControllerRevisions.
        let mut by_owner: BTreeMap<(String, String, String), Vec<Revision>> = BTreeMap::new();
        for cr in soft(
            list_scoped::<ControllerRevision>(
                ctx,
                &sc,
                &ListParams::default(),
                "controllerrevisions",
                &mut un,
            )
            .await,
            "ControllerRevisions",
            &mut un,
        )?
        .into_iter()
        .flatten()
        {
            let owner = cr
                .metadata
                .owner_references
                .iter()
                .flatten()
                .find(|o| matches!(o.kind.as_str(), "StatefulSet" | "DaemonSet"))
                .map(|o| (o.kind.clone(), o.name.clone()));
            if let (Some((kind, owner)), Some(rev)) = (owner, revision_of_cr(&cr)) {
                by_owner
                    .entry((
                        cr.metadata.namespace.clone().unwrap_or_default(),
                        kind,
                        owner,
                    ))
                    .or_default()
                    .push(rev);
            }
        }
        for ((ns, kind, name), mut revs) in by_owner {
            revs.sort_by_key(|r| std::cmp::Reverse(r.number));
            changes.extend(rollout_changes(&kind, &ns, &name, &revs, cutoff));
        }
        // Created or updated objects, metadata only.
        macro_rules! objects {
            ($($ty:ty => $kind:literal),* $(,)?) => {$(
                let metas: Vec<PartialObjectMeta<$ty>> = soft(list_meta_scoped::<$ty>(ctx, &sc, &ListParams::default(), $kind, &mut un).await, $kind, &mut un)?.unwrap_or_default();
                for m in metas.iter().filter(|m| !is_noise($kind, &m.metadata)) {
                    // Helm's release records are reported as releases below.
                    if $kind == "Secret" && m.metadata.labels.as_ref().is_some_and(|l| l.get("owner").is_some_and(|o| o == "helm")) {
                        continue;
                    }
                    if let Some((at, change)) = object_change(&m.metadata, cutoff) {
                        changes.push(Change { at, kind: $kind.into(), namespace: m.metadata.namespace.clone().unwrap_or_default(), name: m.metadata.name.clone().unwrap_or_default(), what: change });
                    }
                }
            )*};
        }
        objects!(
            Deployment => "Deployment", StatefulSet => "StatefulSet", DaemonSet => "DaemonSet", CronJob => "CronJob",
            Service => "Service", Ingress => "Ingress", NetworkPolicy => "NetworkPolicy", ConfigMap => "ConfigMap",
            Secret => "Secret", PersistentVolumeClaim => "PersistentVolumeClaim",
            HorizontalPodAutoscaler => "HorizontalPodAutoscaler", PodDisruptionBudget => "PodDisruptionBudget",
        );
        // Helm releases: Helm 3 stores each revision as a Secret labeled owner=helm.
        let releases: Vec<PartialObjectMeta<Secret>> = soft(
            list_meta_scoped::<Secret>(
                ctx,
                &sc,
                &ListParams::default().labels("owner=helm"),
                "Helm release records",
                &mut un,
            )
            .await,
            "Helm release records",
            &mut un,
        )?
        .unwrap_or_default();
        for r in releases {
            let (Some(at), Some(labels)) = (created(&r.metadata), r.metadata.labels.as_ref())
            else {
                continue;
            };
            if at < cutoff {
                continue;
            }
            let label = |k: &str| labels.get(k).map_or("?", String::as_str);
            changes.push(Change {
                at,
                kind: "HelmRelease".into(),
                namespace: r.metadata.namespace.clone().unwrap_or_default(),
                name: label("name").to_owned(),
                what: format!("revision {} ({})", label("version"), label("status")),
            });
        }
    }
    // A rollout also updates its workload: keep the rollout row only.
    let rolled: Vec<(String, String, String)> = changes
        .iter()
        .filter(|c| c.what.starts_with("rolled out"))
        .map(|c| (c.kind.clone(), c.namespace.clone(), c.name.clone()))
        .collect();
    changes.retain(|c| {
        c.what.starts_with("rolled out")
            || !rolled.contains(&(c.kind.clone(), c.namespace.clone(), c.name.clone()))
    });
    changes.sort_by(|a, b| {
        b.at.cmp(&a.at)
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.name.cmp(&b.name))
    });

    let total = changes.len();
    let count = |pred: &dyn Fn(&Change) -> bool| changes.iter().filter(|c| pred(c)).count();
    let rollouts = count(&|c| c.what.starts_with("rolled out"));
    let helm = count(&|c| c.kind == "HelmRelease");
    let window = input.since.clone().unwrap_or_else(|| "2h".into());
    let summary = match changes.first() {
        None => format!("No changes in the last {window}."),
        Some(c) => format!(
            "{total} changes in the last {window} ({rollouts} rollouts, {helm} Helm releases, {} objects created or updated). Newest, {} ago: {} {}/{} {}.",
            total - rollouts - helm,
            age(now, c.at),
            c.kind,
            c.namespace,
            c.name,
            c.what
        ),
    };
    let mut e = envelope(&sc, summary);
    e.columns = vec!["age", "kind", "name", "change"];
    e.items = changes
        .iter()
        .take(MAX_CHANGES)
        .map(|c| {
            json!({
                "age": age(now, c.at),
                "kind": c.kind,
                "name": if c.namespace.is_empty() { c.name.clone() } else { format!("{}/{}", c.namespace, c.name) },
                "change": c.what,
            })
        })
        .collect();
    if total > MAX_CHANGES {
        e.truncated = true;
        e.omitted.items = total - MAX_CHANGES;
    }
    add_notes(&mut e, &un);
    Ok(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template(v: Value) -> PodTemplateSpec {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn diffs_name_env_keys_but_never_values() {
        let old = template(
            json!({"spec": {"containers": [{"name": "app", "image": "api:1.4",
            "env": [{"name": "DB_PASSWORD", "value": "hunter2"}, {"name": "MODE", "value": "a"}],
            "resources": {"limits": {"memory": "256Mi"}}}]}}),
        );
        let new = template(
            json!({"metadata": {"annotations": {"kubectl.kubernetes.io/restartedAt": "2026-11-14T11:00:00Z"}},
            "spec": {"containers": [{"name": "app", "image": "api:1.5",
            "env": [{"name": "DB_PASSWORD", "value": "s3cr3t"}, {"name": "NEW", "value": "x"}],
            "resources": {"limits": {"memory": "512Mi"}}}], "volumes": [{"name": "cache", "emptyDir": {}}]}}),
        );
        let diff = template_diff(&old, &new);
        assert_eq!(
            diff,
            [
                "container app: image api:1.4 -> api:1.5",
                "container app: env added: NEW",
                "container app: env removed: MODE",
                "container app: env changed: DB_PASSWORD",
                "container app: limits.memory 256Mi -> 512Mi",
                "volume cache added",
                "restarted (kubectl rollout restart)",
            ]
        );
        let all = diff.join(" ");
        assert!(!all.contains("hunter2") && !all.contains("s3cr3t"), "{all}");
        assert_eq!(template_diff(&old, &old), ["no pod template change"]);
    }

    #[test]
    fn object_changes_ignore_status_and_controller_bookkeeping() {
        let cutoff: Timestamp = "2026-11-14T10:00:00Z".parse().unwrap();
        let meta: ObjectMeta = serde_json::from_value(json!({
            "creationTimestamp": "2026-11-01T00:00:00Z",
            "managedFields": [
                {"manager": "kubectl-client-side-apply", "operation": "Update", "time": "2026-11-14T11:00:00Z"},
                {"manager": "kube-controller-manager", "operation": "Update", "time": "2026-11-14T11:30:00Z"},
                {"manager": "kubelet", "operation": "Update", "subresource": "status", "time": "2026-11-14T11:50:00Z"}
            ]
        }))
        .unwrap();
        assert_eq!(
            object_change(&meta, cutoff).unwrap().1,
            "updated by kubectl-client-side-apply"
        );
        let old: ObjectMeta =
            serde_json::from_value(json!({"creationTimestamp": "2026-11-01T00:00:00Z"})).unwrap();
        assert!(object_change(&old, cutoff).is_none());
    }
}
