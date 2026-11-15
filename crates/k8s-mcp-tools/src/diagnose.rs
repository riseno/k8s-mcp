//! Headline tools: evidence gathering for `diagnose_pod`, `diagnose_workload`,
//! `diagnose_node` and `find_problems` (PROPOSAL §8.2, §9.1).
//!
//! Gathering is bounded: one log fetch per container, a 1-hour event window, at most
//! [`MAX_REFS`] reference checks and [`MAX_PODS`] representative pods per workload.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use jiff::SignedDuration;
use k8s_mcp_core::envelope::Section;
use k8s_mcp_core::finding::{Finding, ObjectRef, Severity, dedup, group_same_cause, rank};
use k8s_mcp_core::text::{dedup_lines, is_marker_line, strip_ansi};
use k8s_mcp_core::{Error, Result};
use k8s_mcp_diagnose::{
    ContainerLog, NodeEvidence, PodEvidence, RefCheck, RefKind, ServiceEvidence, Unavailable,
    Workload, WorkloadEvidence,
};
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;
use k8s_openapi::api::batch::v1::{CronJob, Job};
use k8s_openapi::api::core::v1::{
    ConfigMap, Event, Node, PersistentVolumeClaim, Pod, ResourceQuota, Secret, Service,
    ServiceAccount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use kube::Resource;
use kube::api::{Api, ListParams, LogParams};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use crate::common::{
    Scope, check_name, ensure_namespace, envelope, events_for, list_scoped, retain_recent, scope,
    selector_matches, selector_string, soft,
};
use crate::read::{add_notes, events_section};
use crate::rows::{node_row, pod_row, pod_status, unhealthy};
use crate::{Ctx, Envelope};

/// Max referenced objects checked per pod.
const MAX_REFS: usize = 20;
/// Max representative pods diagnosed per workload.
const MAX_PODS: usize = 3;

// ---------------------------------------------------------------------------------------
// diagnose_pod

/// Inputs for `diagnose_pod`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiagnosePodInput {
    /// Pod name.
    pub name: String,
    /// Namespace (default: the context's namespace).
    pub namespace: Option<String>,
    /// Read container logs as evidence (default true).
    pub include_logs: Option<bool>,
    /// Log lines per container (default 100, max 500).
    pub log_tail: Option<i64>,
    /// Kubeconfig context.
    pub context: Option<String>,
}

/// Root-cause one pod.
pub async fn diagnose_pod(ctx: &Ctx, input: DiagnosePodInput) -> Result<Envelope> {
    check_name("pod", &input.name)?;
    let sc = scope(
        ctx,
        input.context.as_deref(),
        input.namespace.as_deref(),
        false,
    )
    .await?;
    let ns = sc.namespace.clone().unwrap_or_default();
    let pod = Api::<Pod>::namespaced(sc.target.client.clone(), &ns)
        .get(&input.name)
        .await
        .map_err(|e| Error::kube(format!("get pod {} in namespace {ns}", input.name), &e))?;
    let tail = input.log_tail.unwrap_or(100).clamp(1, 500);
    let ev = gather_pod(
        ctx,
        &sc,
        pod,
        input.include_logs.unwrap_or(true).then_some(tail),
        None,
    )
    .await;
    let findings = k8s_mcp_diagnose::diagnose_pod(&ev);
    Ok(render_pod(ctx, &sc, &ev, findings))
}

/// Gather evidence for one pod. `events` may be passed in when already listed.
async fn gather_pod(
    ctx: &Ctx,
    sc: &Scope,
    pod: Pod,
    log_tail: Option<i64>,
    events: Option<Vec<Event>>,
) -> PodEvidence {
    let now = ctx.now();
    let client = sc.target.client.clone();
    let name = pod.metadata.name.clone().unwrap_or_default();
    let ns = pod.metadata.namespace.clone().unwrap_or_default();
    let mut un = Vec::new();

    let events = match events {
        Some(e) => e,
        None => soft(
            events_for(&sc.target, &ns, "Pod", &name, now).await,
            "pod events",
            &mut un,
        )
        .unwrap_or_default(),
    };
    let node_name = pod.spec.as_ref().and_then(|s| s.node_name.clone());
    let node = match &node_name {
        Some(n) => soft(
            Api::<Node>::all(client.clone())
                .get(n)
                .await
                .map_err(|e| Error::kube(format!("get node {n}"), &e)),
            "node",
            &mut un,
        ),
        None => None,
    };
    let pending = pod.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Pending")
        && node_name.is_none();
    let nodes = if pending {
        soft(
            Api::<Node>::all(client.clone())
                .list(&ListParams::default())
                .await
                .map(|l| l.items)
                .map_err(|e| Error::kube("list nodes", &e)),
            "nodes (for scheduling checks)",
            &mut un,
        )
    } else {
        None
    };

    let mut refs = Vec::new();
    // Values of the Secrets the pod uses, kept only to mask them in its logs (never output).
    let mut secret_values: Vec<String> = Vec::new();
    let mut pvcs = Vec::new();
    let mut service_account = None;
    for (kind, ref_name) in collect_refs(&pod).into_iter().take(MAX_REFS) {
        let (exists, keys) = match kind {
            RefKind::ConfigMap => match Api::<ConfigMap>::namespaced(client.clone(), &ns)
                .get_opt(&ref_name)
                .await
            {
                Ok(Some(cm)) => (
                    Some(true),
                    Some(
                        cm.data
                            .unwrap_or_default()
                            .into_keys()
                            .chain(cm.binary_data.unwrap_or_default().into_keys())
                            .collect(),
                    ),
                ),
                Ok(None) => (Some(false), None),
                Err(e) => note(&mut un, &format!("ConfigMap {ref_name}"), &e),
            },
            // Only key names are kept; values are dropped immediately.
            RefKind::Secret => match Api::<Secret>::namespaced(client.clone(), &ns)
                .get_opt(&ref_name)
                .await
            {
                Ok(Some(s)) => {
                    secret_values.extend(values_of(&s));
                    (
                        Some(true),
                        Some(
                            s.data
                                .unwrap_or_default()
                                .into_keys()
                                .chain(s.string_data.unwrap_or_default().into_keys())
                                .collect(),
                        ),
                    )
                }
                Ok(None) => (Some(false), None),
                Err(e) => note(&mut un, &format!("Secret {ref_name} (existence only)"), &e),
            },
            RefKind::PersistentVolumeClaim => {
                match Api::<PersistentVolumeClaim>::namespaced(client.clone(), &ns)
                    .get_opt(&ref_name)
                    .await
                {
                    Ok(Some(p)) => {
                        pvcs.push(p);
                        (Some(true), None)
                    }
                    Ok(None) => (Some(false), None),
                    Err(e) => note(&mut un, &format!("PersistentVolumeClaim {ref_name}"), &e),
                }
            }
            RefKind::ServiceAccount => match Api::<ServiceAccount>::namespaced(client.clone(), &ns)
                .get_opt(&ref_name)
                .await
            {
                Ok(Some(sa)) => {
                    service_account = Some(sa);
                    (Some(true), None)
                }
                Ok(None) => (Some(false), None),
                Err(e) => note(&mut un, &format!("ServiceAccount {ref_name}"), &e),
            },
        };
        refs.push(RefCheck {
            kind,
            name: ref_name,
            exists,
            keys,
        });
    }

    let mut logs = Vec::new();
    if let Some(tail) = log_tail {
        let api: Api<Pod> = Api::namespaced(client.clone(), &ns);
        // (container, read previous instance?) for containers that have run at least once.
        let wanted: Vec<(String, bool)> = pod
            .status
            .iter()
            .flat_map(|s| {
                s.init_container_statuses
                    .iter()
                    .flatten()
                    .chain(s.container_statuses.iter().flatten())
            })
            .filter_map(|st| {
                let restarted = st.restart_count > 0
                    && st
                        .last_state
                        .as_ref()
                        .and_then(|s| s.terminated.as_ref())
                        .is_some();
                let terminated_now = st.state.as_ref().is_some_and(|s| s.terminated.is_some());
                let running = st.state.as_ref().is_some_and(|s| s.running.is_some());
                // A container that just crashed sits in `terminated` for a while; its own
                // logs hold the crash output and the previous instance may already be gone.
                let previous = restarted && !terminated_now;
                (restarted || running || terminated_now).then(|| (st.name.clone(), previous))
            })
            .collect();
        for (container, previous) in wanted {
            let lp = LogParams {
                container: Some(container.clone()),
                previous,
                tail_lines: Some(tail),
                ..LogParams::default()
            };
            match api.logs(&name, &lp).await {
                Ok(raw) if raw.starts_with("unable to retrieve container logs") => un.push(Unavailable {
                    what: format!("{}logs of container {container}", if previous { "previous " } else { "" }),
                    reason: "the runtime no longer has them (the container was removed after its crash)".into(),
                }),
                Ok(raw) => logs.push(ContainerLog {
                    lines: dedup_lines(redact_log(ctx, &raw, &secret_values).into_iter().filter(|l| !is_marker_line(l))),
                    container,
                    previous,
                }),
                Err(e) => un.push(Unavailable {
                    what: format!("{}logs of container {container}", if previous { "previous " } else { "" }),
                    reason: Error::kube(format!("get logs of pod {name}"), &e).to_string(),
                }),
            }
        }
    }
    PodEvidence {
        pod,
        events,
        logs,
        node,
        nodes,
        refs,
        pvcs,
        service_account,
        unavailable: un,
        now,
    }
}

fn note(
    un: &mut Vec<Unavailable>,
    what: &str,
    e: &kube::Error,
) -> (Option<bool>, Option<Vec<String>>) {
    un.push(Unavailable {
        what: what.to_owned(),
        reason: Error::kube(format!("check {what}"), e).to_string(),
    });
    (None, None)
}

/// Redact one container log: exact Secret values first (every level), then patterns, tracking
/// multi-line PEM keys.
pub fn redact_log(ctx: &Ctx, raw: &str, secret_values: &[String]) -> Vec<String> {
    let mut lines: Vec<String> = raw.lines().map(|l| strip_ansi(l).into_owned()).collect();
    k8s_mcp_core::redact::scrub_values(&mut lines, secret_values);
    ctx.redactor.lines(lines.iter().map(String::as_str))
}

/// Secret values as text (keys are not secret; values are kept in memory only for masking).
fn values_of(s: &Secret) -> Vec<String> {
    let data = s
        .data
        .iter()
        .flatten()
        .map(|(_, v)| String::from_utf8_lossy(&v.0).into_owned());
    let string_data = s.string_data.iter().flatten().map(|(_, v)| v.clone());
    data.chain(string_data).collect()
}

/// Values of the Secrets a pod references, for masking them in its logs. When RBAC forbids
/// reading a Secret, records a note and returns what it could read.
pub async fn pod_secret_values(sc: &Scope, pod: &Pod, notes: &mut Vec<Unavailable>) -> Vec<String> {
    let ns = pod.metadata.namespace.clone().unwrap_or_default();
    let api: Api<Secret> = Api::namespaced(sc.target.client.clone(), &ns);
    let mut out = Vec::new();
    for (_, name) in collect_refs(pod)
        .into_iter()
        .filter(|(k, _)| *k == RefKind::Secret)
        .take(MAX_REFS)
    {
        match api.get_opt(&name).await {
            Ok(Some(s)) => out.extend(values_of(&s)),
            Ok(None) => {}
            Err(e) => notes.push(Unavailable {
                what: format!("Secret {name} values for masking in logs"),
                reason: format!(
                    "{}; only pattern redaction was applied",
                    Error::kube(format!("read Secret {name}"), &e)
                ),
            }),
        }
    }
    out
}

/// Every ConfigMap, Secret, PVC and ServiceAccount a pod references.
fn collect_refs(pod: &Pod) -> Vec<(RefKind, String)> {
    let mut out: BTreeSet<(u8, String)> = BTreeSet::new();
    let code = |k: RefKind| match k {
        RefKind::ConfigMap => 0,
        RefKind::Secret => 1,
        RefKind::PersistentVolumeClaim => 2,
        RefKind::ServiceAccount => 3,
    };
    let Some(spec) = &pod.spec else {
        return Vec::new();
    };
    for c in spec
        .containers
        .iter()
        .chain(spec.init_containers.iter().flatten())
    {
        for e in c.env.iter().flatten() {
            if let Some(vf) = &e.value_from {
                if let Some(r) = &vf.config_map_key_ref {
                    out.insert((code(RefKind::ConfigMap), r.name.clone()));
                }
                if let Some(r) = &vf.secret_key_ref {
                    out.insert((code(RefKind::Secret), r.name.clone()));
                }
            }
        }
        for ef in c.env_from.iter().flatten() {
            if let Some(r) = &ef.config_map_ref {
                out.insert((code(RefKind::ConfigMap), r.name.clone()));
            }
            if let Some(r) = &ef.secret_ref {
                out.insert((code(RefKind::Secret), r.name.clone()));
            }
        }
    }
    for v in spec.volumes.iter().flatten() {
        if let Some(cm) = &v.config_map {
            out.insert((code(RefKind::ConfigMap), cm.name.clone()));
        }
        if let Some(name) = v.secret.as_ref().and_then(|s| s.secret_name.clone()) {
            out.insert((code(RefKind::Secret), name));
        }
        if let Some(p) = &v.persistent_volume_claim {
            out.insert((code(RefKind::PersistentVolumeClaim), p.claim_name.clone()));
        }
        for src in v.projected.iter().flat_map(|p| p.sources.iter().flatten()) {
            if let Some(cm) = &src.config_map {
                out.insert((code(RefKind::ConfigMap), cm.name.clone()));
            }
            if let Some(s) = &src.secret {
                out.insert((code(RefKind::Secret), s.name.clone()));
            }
        }
    }
    for s in spec.image_pull_secrets.iter().flatten() {
        out.insert((code(RefKind::Secret), s.name.clone()));
    }
    out.insert((
        code(RefKind::ServiceAccount),
        spec.service_account_name
            .clone()
            .unwrap_or_else(|| "default".into()),
    ));
    out.into_iter()
        .filter(|(_, n)| !n.is_empty())
        .map(|(k, n)| {
            let kind = match k {
                0 => RefKind::ConfigMap,
                1 => RefKind::Secret,
                2 => RefKind::PersistentVolumeClaim,
                _ => RefKind::ServiceAccount,
            };
            (kind, n)
        })
        .collect()
}

fn render_pod(ctx: &Ctx, sc: &Scope, ev: &PodEvidence, findings: Vec<Finding>) -> Envelope {
    let name = ev.pod.metadata.name.clone().unwrap_or_default();
    let ns = ev.pod.metadata.namespace.clone().unwrap_or_default();
    let status = pod_status(&ev.pod);
    let summary = match findings.first() {
        Some(f) => format!("{name} ({ns}) is {status}: {}.", f.title),
        None => format!("{name} ({ns}) is {status}; no problems found by the diagnosis rules."),
    };
    let mut e = envelope(sc, summary);
    if !ev.unavailable.is_empty() {
        let _ = write!(
            e.summary,
            " Some evidence was unavailable ({}), so confidence may be lower.",
            ev.unavailable.len()
        );
    }
    let mut row = pod_row(&ev.pod);
    row["name"] = json!(name);
    row["age"] = json!(
        ev.pod
            .metadata
            .creation_timestamp
            .as_ref()
            .map(|t| k8s_mcp_core::text::age(ev.now, t.0))
    );
    e.columns = vec!["name", "status", "ready", "restarts", "node", "age"];
    e.items = vec![row];
    let warnings: Vec<Event> = ev
        .events
        .iter()
        .filter(|e| e.type_.as_deref() == Some("Warning"))
        .cloned()
        .collect();
    if !warnings.is_empty() {
        e.sections.push(events_section(ctx, &warnings, ev.now));
    }
    // Log excerpt: the container named by the top finding, else the first log with errors.
    let wanted = findings.first().and_then(|f| {
        ev.logs
            .iter()
            .find(|l| f.title.contains(&format!("{:?}", l.container)))
    });
    if let Some(log) = wanted.or_else(|| {
        ev.logs
            .iter()
            .find(|l| !k8s_mcp_diagnose::rules::error_lines(&l.lines, 1).is_empty())
    }) {
        let n = log.lines.len();
        e.sections.push(Section {
            title: format!(
                "LOG EXCERPT ({} instance, last {} of {n} lines, redacted)",
                if log.previous { "previous" } else { "current" },
                n.min(5)
            ),
            lines: log.lines[n.saturating_sub(5)..].to_vec(),
            untrusted: Some(vec![
                ("source".into(), "log".into()),
                ("container".into(), log.container.clone()),
            ]),
        });
    }
    e.findings = findings;
    e.untrusted_fields =
        vec!["findings[*].evidence[?(@.source=='event' || @.source=='log')].text".into()];
    add_notes(&mut e, &ev.unavailable);
    e
}

// ---------------------------------------------------------------------------------------
// diagnose_workload

/// Inputs for `diagnose_workload`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiagnoseWorkloadInput {
    /// Deployment, StatefulSet, DaemonSet, ReplicaSet, Job or CronJob (short names work).
    pub kind: String,
    /// Workload name.
    pub name: String,
    /// Namespace (default: the context's namespace).
    pub namespace: Option<String>,
    /// Kubeconfig context.
    pub context: Option<String>,
}

/// Normalise a workload kind name.
fn workload_kind(kind: &str) -> Result<&'static str> {
    Ok(match kind.to_ascii_lowercase().as_str() {
        "deployment" | "deployments" | "deploy" => "Deployment",
        "statefulset" | "statefulsets" | "sts" => "StatefulSet",
        "daemonset" | "daemonsets" | "ds" => "DaemonSet",
        "replicaset" | "replicasets" | "rs" => "ReplicaSet",
        "job" | "jobs" => "Job",
        "cronjob" | "cronjobs" | "cj" => "CronJob",
        other => {
            return Err(Error::InvalidInput(format!(
                "unsupported workload kind {other:?}: use Deployment, StatefulSet, DaemonSet, ReplicaSet, Job or CronJob (for a single pod use diagnose_pod)"
            )));
        }
    })
}

/// Fetch a workload and the pods it selects.
pub async fn workload_pods(sc: &Scope, kind: &str, name: &str) -> Result<(Workload, Vec<Pod>)> {
    let kind = workload_kind(kind)?;
    let ns = sc.namespace.clone().unwrap_or_default();
    let client = sc.target.client.clone();
    let what = format!("get {kind} {name} in namespace {ns}");
    let (wl, selector): (Workload, Option<LabelSelector>) = match kind {
        "Deployment" => {
            let d = Api::<Deployment>::namespaced(client.clone(), &ns)
                .get(name)
                .await
                .map_err(|e| Error::kube(&what, &e))?;
            let s = d.spec.as_ref().map(|s| s.selector.clone());
            (Workload::Deployment(d), s)
        }
        "StatefulSet" => {
            let d = Api::<StatefulSet>::namespaced(client.clone(), &ns)
                .get(name)
                .await
                .map_err(|e| Error::kube(&what, &e))?;
            let s = d.spec.as_ref().map(|s| s.selector.clone());
            (Workload::StatefulSet(d), s)
        }
        "DaemonSet" => {
            let d = Api::<DaemonSet>::namespaced(client.clone(), &ns)
                .get(name)
                .await
                .map_err(|e| Error::kube(&what, &e))?;
            let s = d.spec.as_ref().map(|s| s.selector.clone());
            (Workload::DaemonSet(d), s)
        }
        "ReplicaSet" => {
            let d = Api::<ReplicaSet>::namespaced(client.clone(), &ns)
                .get(name)
                .await
                .map_err(|e| Error::kube(&what, &e))?;
            let s = d.spec.as_ref().map(|s| s.selector.clone());
            (Workload::ReplicaSet(d), s)
        }
        "Job" => {
            let d = Api::<Job>::namespaced(client.clone(), &ns)
                .get(name)
                .await
                .map_err(|e| Error::kube(&what, &e))?;
            let s = d.spec.as_ref().and_then(|s| s.selector.clone());
            (Workload::Job(d), s)
        }
        _ => {
            let d = Api::<CronJob>::namespaced(client.clone(), &ns)
                .get(name)
                .await
                .map_err(|e| Error::kube(&what, &e))?;
            (Workload::CronJob(d), None)
        }
    };
    let pods_api: Api<Pod> = Api::namespaced(client.clone(), &ns);
    let pods = match (&wl, selector) {
        (Workload::CronJob(_), _) => {
            let jobs = owned::<Job>(&client, &ns, "CronJob", name).await?;
            let names: Vec<String> = jobs
                .iter()
                .filter_map(|j| j.metadata.name.clone())
                .collect();
            if names.is_empty() {
                Vec::new()
            } else {
                pods_api
                    .list(
                        &ListParams::default()
                            .labels(&format!("job-name in ({})", names.join(","))),
                    )
                    .await
                    .map_err(|e| Error::kube(format!("list pods of CronJob {name}"), &e))?
                    .items
            }
        }
        (_, Some(sel)) => {
            pods_api
                .list(&ListParams::default().labels(&selector_string(&sel)))
                .await
                .map_err(|e| Error::kube(format!("list pods of {kind} {name}"), &e))?
                .items
        }
        _ => Vec::new(),
    };
    Ok((wl, pods))
}

/// The label selector a workload uses for its pods (CronJobs select through their Jobs).
fn workload_selector(w: &Workload) -> Option<&LabelSelector> {
    match w {
        Workload::Deployment(d) => d.spec.as_ref().map(|s| &s.selector),
        Workload::StatefulSet(s) => s.spec.as_ref().map(|s| &s.selector),
        Workload::DaemonSet(d) => d.spec.as_ref().map(|s| &s.selector),
        Workload::ReplicaSet(r) => r.spec.as_ref().map(|s| &s.selector),
        Workload::Job(j) => j.spec.as_ref().and_then(|s| s.selector.as_ref()),
        Workload::CronJob(_) => None,
    }
}

/// Objects of type K in `ns` owned by `owner_kind/owner`, newest first.
pub(crate) async fn owned<K>(
    client: &kube::Client,
    ns: &str,
    owner_kind: &str,
    owner: &str,
) -> Result<Vec<K>>
where
    K: Resource<Scope = k8s_openapi::NamespaceResourceScope>
        + Clone
        + serde::de::DeserializeOwned
        + std::fmt::Debug,
    <K as Resource>::DynamicType: Default,
{
    let mut items: Vec<K> = Api::<K>::namespaced(client.clone(), ns)
        .list(&ListParams::default())
        .await
        .map_err(|e| {
            Error::kube(
                format!(
                    "list {} in namespace {ns}",
                    K::plural(&K::DynamicType::default())
                ),
                &e,
            )
        })?
        .items
        .into_iter()
        .filter(|o| {
            o.meta()
                .owner_references
                .iter()
                .flatten()
                .any(|r| r.kind == owner_kind && r.name == owner)
        })
        .collect();
    items.sort_by_key(|o| std::cmp::Reverse(o.meta().creation_timestamp.as_ref().map(|t| t.0)));
    Ok(items)
}

/// Root-cause a workload.
pub async fn diagnose_workload(ctx: &Ctx, input: DiagnoseWorkloadInput) -> Result<Envelope> {
    check_name("name", &input.name)?;
    let sc = scope(
        ctx,
        input.context.as_deref(),
        input.namespace.as_deref(),
        false,
    )
    .await?;
    let ns = sc.namespace.clone().unwrap_or_default();
    let now = ctx.now();
    let client = sc.target.client.clone();
    let (workload, pods) = workload_pods(&sc, &input.kind, &input.name).await?;
    let kind = workload_kind(&input.kind)?;
    let mut un = Vec::new();

    let replicasets = if kind == "Deployment" {
        soft(
            owned::<ReplicaSet>(&client, &ns, "Deployment", &input.name).await,
            "ReplicaSets",
            &mut un,
        )
        .unwrap_or_default()
    } else {
        Vec::new()
    };
    let jobs = if kind == "CronJob" {
        soft(
            owned::<Job>(&client, &ns, "CronJob", &input.name).await,
            "Jobs",
            &mut un,
        )
        .unwrap_or_default()
    } else {
        Vec::new()
    };
    let mut related: BTreeSet<String> = BTreeSet::from([input.name.clone()]);
    related.extend(replicasets.iter().filter_map(|r| r.metadata.name.clone()));
    related.extend(jobs.iter().filter_map(|j| j.metadata.name.clone()));
    let mut ns_events: Vec<Event> = soft(
        Api::<Event>::namespaced(client.clone(), &ns)
            .list(&ListParams::default())
            .await
            .map(|l| l.items)
            .map_err(|e| Error::kube(format!("list events in namespace {ns}"), &e)),
        "events",
        &mut un,
    )
    .unwrap_or_default();
    retain_recent(&mut ns_events, now, SignedDuration::from_hours(1));
    let events: Vec<Event> = ns_events
        .iter()
        .filter(|e| {
            e.involved_object.kind.as_deref() != Some("Pod")
                && e.involved_object
                    .name
                    .as_ref()
                    .is_some_and(|n| related.contains(n))
        })
        .cloned()
        .collect();

    let mut ordered: Vec<&Pod> = pods.iter().collect();
    ordered.sort_by_key(|p| {
        (
            unhealthy(p, now).is_none(),
            std::cmp::Reverse(p.metadata.creation_timestamp.as_ref().map(|t| t.0)),
        )
    });
    let failing = ordered
        .iter()
        .filter(|p| unhealthy(p, now).is_some())
        .count();
    let mut pod_evidence = Vec::new();
    for p in ordered.iter().take(if failing > 0 {
        failing.min(MAX_PODS)
    } else {
        1
    }) {
        let pod_name = p.metadata.name.clone().unwrap_or_default();
        let pod_events = ns_events
            .iter()
            .filter(|e| {
                e.involved_object.kind.as_deref() == Some("Pod")
                    && e.involved_object.name.as_deref() == Some(pod_name.as_str())
            })
            .cloned()
            .collect();
        let logs = unhealthy(p, now).is_some().then_some(100);
        pod_evidence.push(gather_pod(ctx, &sc, (*p).clone(), logs, Some(pod_events)).await);
    }
    let quotas = soft(
        Api::<ResourceQuota>::namespaced(client.clone(), &ns)
            .list(&ListParams::default())
            .await
            .map(|l| l.items)
            .map_err(|e| Error::kube("list resourcequotas", &e)),
        "ResourceQuotas",
        &mut un,
    )
    .unwrap_or_default();
    let hpa = soft(
        Api::<HorizontalPodAutoscaler>::namespaced(client.clone(), &ns)
            .list(&ListParams::default())
            .await
            .map(|l| l.items)
            .map_err(|e| Error::kube("list horizontalpodautoscalers", &e)),
        "HorizontalPodAutoscalers",
        &mut un,
    )
    .and_then(|hpas| {
        hpas.into_iter().find(|h| {
            h.spec.as_ref().is_some_and(|s| {
                s.scale_target_ref.kind == kind && s.scale_target_ref.name == input.name
            })
        })
    });

    let ev = WorkloadEvidence {
        workload,
        replicasets,
        jobs,
        events,
        pods: pod_evidence,
        pod_count: Some(pods.len()),
        quotas,
        hpa,
        unavailable: un,
        now,
    };
    let findings = k8s_mcp_diagnose::diagnose_workload(&ev);

    // riseno/k8s-mcp#32: measure against desired replicas, not just the pods that exist.
    let health = match k8s_mcp_diagnose::rules::rollout::replicas(&ev.workload) {
        Some((desired, available)) => format!(
            "{available}/{desired} replicas available ({} pod(s) exist)",
            pods.len()
        ),
        None => format!(
            "{}/{} pods healthy",
            pods.iter().filter(|p| unhealthy(p, now).is_none()).count(),
            pods.len()
        ),
    };
    let mut e = envelope(
        &sc,
        match findings.first() {
            Some(f) => format!(
                "{kind} {} ({ns}): {health}. Top finding: {}.",
                input.name, f.title
            ),
            None => format!(
                "{kind} {} ({ns}): {health}; no problems found by the diagnosis rules.",
                input.name
            ),
        },
    );
    e.columns = vec!["name", "status", "ready", "restarts", "node", "age"];
    e.items = ordered
        .iter()
        .take(20)
        .map(|p| {
            let mut r = pod_row(p);
            r["name"] = json!(p.metadata.name);
            r["age"] = json!(
                p.metadata
                    .creation_timestamp
                    .as_ref()
                    .map(|t| k8s_mcp_core::text::age(now, t.0))
            );
            r
        })
        .collect();
    if pods.len() > 20 {
        e.omitted.items = pods.len() - 20;
    }
    let warnings: Vec<Event> = ev
        .events
        .iter()
        .filter(|e| e.type_.as_deref() == Some("Warning"))
        .cloned()
        .collect();
    if !warnings.is_empty() {
        e.sections.push(events_section(ctx, &warnings, now));
    }
    e.findings = findings;
    e.untrusted_fields =
        vec!["findings[*].evidence[?(@.source=='event' || @.source=='log')].text".into()];
    let mut notes = ev.unavailable.clone();
    for p in &ev.pods {
        notes.extend(p.unavailable.iter().cloned());
    }
    add_notes(&mut e, &notes);
    Ok(e)
}

// ---------------------------------------------------------------------------------------
// diagnose_node

/// Inputs for `diagnose_node`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiagnoseNodeInput {
    /// Node name.
    pub name: String,
    /// Kubeconfig context.
    pub context: Option<String>,
}

/// Root-cause a node.
pub async fn diagnose_node(ctx: &Ctx, input: DiagnoseNodeInput) -> Result<Envelope> {
    check_name("node", &input.name)?;
    let sc = scope(ctx, input.context.as_deref(), None, true).await?;
    let now = ctx.now();
    let client = sc.target.client.clone();
    let node = Api::<Node>::all(client.clone())
        .get(&input.name)
        .await
        .map_err(|e| Error::kube(format!("get node {}", input.name), &e))?;
    let mut un = Vec::new();
    let events = soft(
        events_for(&sc.target, "", "Node", &input.name, now).await,
        "node events",
        &mut un,
    )
    .unwrap_or_default();
    let pods = soft(
        list_scoped::<Pod>(
            ctx,
            &sc,
            &ListParams::default().fields(&format!("spec.nodeName={}", input.name)),
            "pods on the node",
            &mut un,
        )
        .await,
        "pods on the node",
        &mut un,
    );
    if !ctx.policy.namespaces.is_empty() || !ctx.policy.deny_namespaces.is_empty() {
        un.push(Unavailable {
            what: "pods outside the allowed namespaces".into(),
            reason:
                "hidden by k8s-mcp namespace policy; request totals cover allowed namespaces only"
                    .into(),
        });
    }
    let server_version = client.apiserver_version().await.ok().and_then(|v| {
        Some((
            v.major.trim_end_matches('+').parse().ok()?,
            v.minor.trim_end_matches('+').parse().ok()?,
        ))
    });
    let ev = NodeEvidence {
        node,
        events,
        pods,
        server_version,
        unavailable: un,
        now,
    };
    let findings = k8s_mcp_diagnose::diagnose_node(&ev);
    let mut row = node_row(&ev.node);
    row["name"] = json!(input.name);
    let mut e = envelope(
        &sc,
        match findings.first() {
            Some(f) => format!(
                "Node {} is {}: {}.",
                input.name,
                row["status"].as_str().unwrap_or("?"),
                f.title
            ),
            None => format!(
                "Node {} is {}; no problems found by the diagnosis rules.",
                input.name,
                row["status"].as_str().unwrap_or("?")
            ),
        },
    );
    e.namespace = None;
    e.columns = vec!["name", "status", "roles", "version", "pool"];
    e.items = vec![row];
    if !ev.events.is_empty() {
        e.sections.push(events_section(ctx, &ev.events, now));
    }
    let failing: Vec<String> = ev
        .pods
        .iter()
        .flatten()
        .filter_map(|p| {
            unhealthy(p, now).map(|s| {
                format!(
                    "{}/{}: {s}",
                    p.metadata.namespace.as_deref().unwrap_or(""),
                    p.metadata.name.as_deref().unwrap_or("")
                )
            })
        })
        .take(20)
        .collect();
    if !failing.is_empty() {
        e.sections.push(Section {
            title: "UNHEALTHY PODS ON THIS NODE".into(),
            lines: failing,
            untrusted: None,
        });
    }
    e.findings = findings;
    add_notes(&mut e, &ev.unavailable);
    Ok(e)
}

// ---------------------------------------------------------------------------------------
// find_problems

/// What `find_problems` can scan (its `kinds` values), all by default.
const KINDS: &[&str] = &["pods", "workloads", "nodes", "services"];

/// Inputs for `find_problems`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindProblemsInput {
    /// Limit the scan to one namespace.
    pub namespace: Option<String>,
    /// Scan all allowed namespaces (default true unless `namespace` is set).
    pub all_namespaces: Option<bool>,
    /// What to scan: any of `pods`, `workloads`, `nodes`, `services` (default all).
    pub kinds: Option<Vec<String>>,
    /// Lowest severity to report (default `medium`).
    pub min_severity: Option<Severity>,
    /// Kubeconfig context.
    pub context: Option<String>,
}

/// Scan for anything broken.
pub async fn find_problems(ctx: &Ctx, input: FindProblemsInput) -> Result<Envelope> {
    let all_ns = input.all_namespaces.unwrap_or(input.namespace.is_none());
    let sc = scope(
        ctx,
        input.context.as_deref(),
        input.namespace.as_deref(),
        all_ns,
    )
    .await?;
    let now = ctx.now();
    // Nodes are cluster-wide: in a namespace scan, only nodes running its pods are reported,
    // unless nodes were asked for explicitly.
    let only_namespace_nodes = sc.namespace.is_some() && input.kinds.is_none();
    let kinds = input
        .kinds
        .unwrap_or_else(|| KINDS.iter().map(|k| (*k).to_owned()).collect());
    if let Some(bad) = kinds
        .iter()
        .find(|k| !KINDS.iter().any(|v| k.eq_ignore_ascii_case(v)))
    {
        return Err(Error::InvalidInput(format!(
            "unknown kind {bad:?} in kinds; valid values are {}",
            KINDS.join(", ")
        )));
    }
    let want = |k: &str| kinds.iter().any(|x| x.eq_ignore_ascii_case(k));
    let min = input.min_severity.unwrap_or(Severity::Medium);
    let mut un = Vec::new();
    let mut warnings: Vec<Event> = soft(
        list_scoped(
            ctx,
            &sc,
            &ListParams::default().fields("type=Warning"),
            "warning events",
            &mut un,
        )
        .await,
        "warning events",
        &mut un,
    )
    .unwrap_or_default();
    retain_recent(&mut warnings, now, SignedDuration::from_hours(1));
    let events_about = |kind: &str, ns: &str, pred: &dyn Fn(&str) -> bool| -> Vec<Event> {
        warnings
            .iter()
            .filter(|e| {
                e.involved_object.kind.as_deref() == Some(kind)
                    && e.involved_object.namespace.as_deref().unwrap_or("") == ns
                    && e.involved_object.name.as_deref().is_some_and(pred)
            })
            .cloned()
            .collect()
    };
    let mut findings: Vec<Finding> = Vec::new();
    let mut scanned = Vec::new();
    let mut listed_pods: Option<Vec<Pod>> = None;

    if want("pods") {
        let pods: Vec<Pod> = list_scoped(ctx, &sc, &ListParams::default(), "pods", &mut un).await?;
        scanned.push(format!("{} pods", pods.len()));
        for p in pods.iter().filter(|p| unhealthy(p, now).is_some()) {
            let (name, ns) = (
                p.metadata.name.clone().unwrap_or_default(),
                p.metadata.namespace.clone().unwrap_or_default(),
            );
            let ev = PodEvidence {
                pod: p.clone(),
                events: events_about("Pod", &ns, &|n| n == name),
                now,
                ..PodEvidence::default()
            };
            for f in k8s_mcp_diagnose::diagnose_pod(&ev) {
                findings.push(f.object(ObjectRef::new("Pod", Some(&ns), &name)));
            }
        }
        listed_pods = Some(pods);
    }
    if want("workloads") {
        let mut wls: Vec<(Workload, String, String)> = Vec::new();
        macro_rules! collect {
            ($ty:ty, $variant:ident) => {
                for o in
                    list_scoped::<$ty>(ctx, &sc, &ListParams::default(), stringify!($ty), &mut un)
                        .await
                        .unwrap_or_default()
                {
                    let (n, ns) = (
                        o.metadata.name.clone().unwrap_or_default(),
                        o.metadata.namespace.clone().unwrap_or_default(),
                    );
                    wls.push((Workload::$variant(o), n, ns));
                }
            };
        }
        collect!(Deployment, Deployment);
        collect!(StatefulSet, StatefulSet);
        collect!(DaemonSet, DaemonSet);
        collect!(Job, Job);
        collect!(CronJob, CronJob);
        scanned.push(format!("{} workloads", wls.len()));
        for (wl, name, ns) in wls {
            let kind = match &wl {
                Workload::Deployment(_) => "Deployment",
                Workload::StatefulSet(_) => "StatefulSet",
                Workload::DaemonSet(_) => "DaemonSet",
                Workload::ReplicaSet(_) => "ReplicaSet",
                Workload::Job(_) => "Job",
                Workload::CronJob(_) => "CronJob",
            };
            let prefix = format!("{name}-");
            let mut events = events_about(kind, &ns, &|n| n == name);
            events.extend(events_about("ReplicaSet", &ns, &|n| n.starts_with(&prefix)));
            // Count the workload's pods only when they were listed; never guess 0.
            let pod_count = listed_pods
                .as_ref()
                .zip(workload_selector(&wl))
                .map(|(pods, sel)| {
                    pods.iter()
                        .filter(|p| p.metadata.namespace.as_deref() == Some(ns.as_str()))
                        .filter(|p| selector_matches(sel, p.metadata.labels.as_ref()))
                        .count()
                });
            let ev = WorkloadEvidence {
                workload: wl,
                events,
                pod_count,
                now,
                ..WorkloadEvidence::default()
            };
            for f in k8s_mcp_diagnose::diagnose_workload(&ev) {
                findings.push(f.object(ObjectRef::new(kind, Some(&ns), &name)));
            }
        }
    }
    if want("nodes")
        && let Some(nodes) = soft(
            Api::<Node>::all(sc.target.client.clone())
                .list(&ListParams::default())
                .await
                .map(|l| l.items)
                .map_err(|e| Error::kube("list nodes", &e)),
            "nodes",
            &mut un,
        )
    {
        let mut nodes = nodes;
        if only_namespace_nodes {
            let used: BTreeSet<&str> = listed_pods
                .iter()
                .flatten()
                .filter_map(|p| p.spec.as_ref()?.node_name.as_deref())
                .collect();
            nodes.retain(|n| {
                n.metadata
                    .name
                    .as_deref()
                    .is_some_and(|name| used.contains(name))
            });
        }
        scanned.push(format!("{} nodes", nodes.len()));
        for n in nodes {
            let name = n.metadata.name.clone().unwrap_or_default();
            let ev = NodeEvidence {
                events: events_about("Node", "", &|x| x == name),
                node: n,
                now,
                ..NodeEvidence::default()
            };
            findings.extend(
                k8s_mcp_diagnose::diagnose_node(&ev)
                    .into_iter()
                    .map(|f| f.object(ObjectRef::new("Node", None, &name))),
            );
        }
    }
    if want("services")
        && let Some(services) = soft(
            list_scoped::<Service>(ctx, &sc, &ListParams::default(), "services", &mut un).await,
            "services",
            &mut un,
        )
    {
        scanned.push(format!("{} services", services.len()));
        // Selector checks need the pods; reuse the pod scan when there was one.
        let pods = match listed_pods.take() {
            Some(p) => Some(p),
            None => soft(
                list_scoped::<Pod>(ctx, &sc, &ListParams::default(), "pods", &mut un).await,
                "pods (for Service selectors)",
                &mut un,
            ),
        };
        for svc in services {
            let (name, ns) = (
                svc.metadata.name.clone().unwrap_or_default(),
                svc.metadata.namespace.clone().unwrap_or_default(),
            );
            let ev = ServiceEvidence {
                service: svc,
                pods: pods.as_ref().map(|all| {
                    all.iter()
                        .filter(|p| p.metadata.namespace.as_deref() == Some(ns.as_str()))
                        .cloned()
                        .collect()
                }),
                events: events_about("Service", &ns, &|n| n == name),
                now,
                ..ServiceEvidence::default()
            };
            findings.extend(
                k8s_mcp_diagnose::diagnose_service(&ev)
                    .into_iter()
                    .map(|f| f.object(ObjectRef::new("Service", Some(&ns), &name))),
            );
        }
        if want("pods") {
            listed_pods = pods;
        }
    }
    findings.retain(|f| f.severity <= min);
    rank(&mut findings);
    dedup(&mut findings);
    for f in &mut findings {
        f.evidence.truncate(2);
        f.explanation.clear();
        if let Some(o) = &f.object {
            let (tool, args) = match o.kind.as_str() {
                "Pod" => (
                    "diagnose_pod",
                    json!({"name": o.name, "namespace": o.namespace}),
                ),
                "Node" => ("diagnose_node", json!({"name": o.name})),
                "Service" => (
                    "diagnose_service",
                    json!({"name": o.name, "namespace": o.namespace}),
                ),
                k => (
                    "diagnose_workload",
                    json!({"kind": k, "name": o.name, "namespace": o.namespace}),
                ),
            };
            f.next = vec![k8s_mcp_core::finding::NextCall::new(
                tool,
                args,
                "root-cause with full evidence",
            )];
        }
    }
    if findings.is_empty() && listed_pods.as_ref().is_some_and(Vec::is_empty) {
        ensure_namespace(&sc).await?;
    }
    // One finding per root cause: after evidence is trimmed, so the merged list is kept.
    let mut findings = group_same_cause(findings);
    let total = findings.len();
    let by_severity = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ]
    .iter()
    .filter_map(|s| {
        let n = findings.iter().filter(|f| f.severity == *s).count();
        (n > 0).then(|| format!("{n} {}", s.as_str()))
    })
    .collect::<Vec<_>>()
    .join(", ");
    findings.truncate(50);
    let mut e = envelope(
        &sc,
        if total == 0 {
            format!(
                "No problems at severity {} or above (scanned {}).",
                min.as_str(),
                scanned.join(", ")
            )
        } else {
            format!(
                "{total} findings ({by_severity}) across {}.",
                scanned.join(", ")
            )
        },
    );
    if total > findings.len() {
        e.truncated = true;
        e.omitted.findings = total - findings.len();
    }
    e.findings = findings;
    e.untrusted_fields =
        vec!["findings[*].evidence[?(@.source=='event' || @.source=='log')].text".into()];
    add_notes(&mut e, &un);
    Ok(e)
}
