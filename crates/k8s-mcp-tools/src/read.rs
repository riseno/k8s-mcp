//! Core read tools (PROPOSAL §8.1).

use std::collections::{BTreeMap, HashMap};

use jiff::SignedDuration;
use k8s_mcp_core::envelope::Section;
use k8s_mcp_core::finding::{NextCall, ObjectRef, group_same_cause, rank};
use k8s_mcp_core::quantity::{bytes, cpu_millis, fmt_bytes};
use k8s_mcp_core::text::{age, parse_duration, truncate};
use k8s_mcp_core::{Error, Result};
use k8s_mcp_diagnose::{NodeEvidence, PodEvidence, Unavailable};
use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec,
    SelfSubjectRulesReview, SelfSubjectRulesReviewSpec,
};
use k8s_openapi::api::core::v1::{Event, Namespace, Node, Pod};
use kube::api::{Api, DynamicObject, ListParams, PostParams};
use kube::discovery::ApiResource;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::common::{
    Scope, check_name, clean, envelope, events_for, fallback_namespaces, list_scoped,
    retain_recent, scope, soft,
};
use crate::discovery::{api_resource, resolve, resources};
use crate::rows::{self, node_pool, pod_row, provider_from_nodes, unhealthy};
use crate::{Ctx, Envelope};

const DEFAULT_LIMIT: u32 = 50;
const MAX_LIMIT: u32 = 500;

// ---------------------------------------------------------------------------------------
// list_contexts

/// No inputs.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListContextsInput {}

/// Allowed kubeconfig contexts.
pub fn list_contexts(ctx: &Ctx, _input: ListContextsInput) -> Envelope {
    let contexts = ctx.clusters.contexts(&ctx.policy);
    let mut e = Envelope::new(format!(
        "{} context(s) allowed; default is {}. Pass `context` to target another allowed one.",
        contexts.len(),
        ctx.clusters.default_context()
    ));
    e.columns = vec!["name", "server_host", "namespace", "provider", "is_default"];
    e.items = contexts.iter().map(|c| json!(c)).collect();
    e
}

// ---------------------------------------------------------------------------------------
// cluster_overview

/// Inputs for `cluster_overview`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClusterOverviewInput {
    /// Kubeconfig context (default: the server's default context).
    pub context: Option<String>,
}

/// Health at a glance.
pub async fn cluster_overview(ctx: &Ctx, input: ClusterOverviewInput) -> Result<Envelope> {
    let sc = scope(ctx, input.context.as_deref(), None, true).await?;
    let now = ctx.now();
    let mut notes = Vec::new();
    let client = sc.target.client.clone();

    let version = client
        .apiserver_version()
        .await
        .map_err(|e| Error::kube("get the API server version", &e))?;
    let nodes = soft(
        Api::<Node>::all(client.clone())
            .list(&ListParams::default())
            .await
            .map(|l| l.items)
            .map_err(|e| Error::kube("list nodes", &e)),
        "nodes",
        &mut notes,
    );
    let namespaces = soft(
        Api::<Namespace>::all(client.clone())
            .list_metadata(&ListParams::default())
            .await
            .map(|l| {
                l.items
                    .iter()
                    .filter(|n| {
                        n.metadata
                            .name
                            .as_deref()
                            .is_some_and(|n| ctx.policy.namespace_allowed(n))
                    })
                    .count()
            })
            .map_err(|e| Error::kube("list namespaces", &e)),
        "namespaces",
        &mut notes,
    );
    let pods: Vec<Pod> = list_scoped(ctx, &sc, &ListParams::default(), "pods", &mut notes).await?;
    let mut warnings: Vec<Event> = soft(
        list_scoped(
            ctx,
            &sc,
            &ListParams::default().fields("type=Warning"),
            "events",
            &mut notes,
        )
        .await,
        "warning events",
        &mut notes,
    )
    .unwrap_or_default();
    retain_recent(&mut warnings, now, SignedDuration::from_hours(1));
    // One request: full discovery walks every API group, and broken aggregated APIs stall it.
    let metrics = client
        .list_api_groups()
        .await
        .is_ok_and(|g| g.groups.iter().any(|g| g.name == "metrics.k8s.io"));

    let mut phases: BTreeMap<String, usize> = BTreeMap::new();
    for p in &pods {
        *phases
            .entry(
                p.status
                    .as_ref()
                    .and_then(|s| s.phase.clone())
                    .unwrap_or_else(|| "Unknown".into()),
            )
            .or_default() += 1;
    }
    let mut bad: Vec<(&Pod, String)> = pods
        .iter()
        .filter_map(|p| unhealthy(p, now).map(|s| (p, s)))
        .collect();
    bad.sort_by_key(|(p, _)| std::cmp::Reverse(rows::restarts(p)));

    // Quick scan: pod rules on unhealthy pods (with their events, no logs) and node rules.
    let mut findings = Vec::new();
    for (p, _) in bad.iter().take(20) {
        let name = p.metadata.name.clone().unwrap_or_default();
        let ns = p.metadata.namespace.clone().unwrap_or_default();
        let events = warnings
            .iter()
            .filter(|e| e.involved_object.name.as_deref() == Some(&name))
            .cloned()
            .collect();
        let ev = PodEvidence {
            pod: (*p).clone(),
            events,
            now,
            ..PodEvidence::default()
        };
        for f in k8s_mcp_diagnose::diagnose_pod(&ev) {
            findings.push(f.object(ObjectRef::new("Pod", Some(&ns), &name)));
        }
    }
    let mut pools: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for n in nodes.iter().flatten() {
        let ready = rows::node_row(n)["status"]
            .as_str()
            .is_some_and(|s| s.starts_with("Ready"));
        let e = pools.entry(node_pool(n)).or_default();
        if ready {
            e.0 += 1;
        } else {
            e.1 += 1;
        }
        if !ready {
            let ev = NodeEvidence {
                node: n.clone(),
                now,
                ..NodeEvidence::default()
            };
            let name = n.metadata.name.clone().unwrap_or_default();
            findings.extend(
                k8s_mcp_diagnose::diagnose_node(&ev)
                    .into_iter()
                    .map(|f| f.object(ObjectRef::new("Node", None, &name))),
            );
        }
    }
    rank(&mut findings);
    let mut findings = group_same_cause(findings);
    findings.truncate(10);

    let provider = nodes.as_deref().and_then(provider_from_nodes).or_else(|| {
        ctx.clusters
            .contexts(&ctx.policy)
            .into_iter()
            .find(|c| c.name == sc.target.context)
            .and_then(|c| c.provider)
    });
    let (ready, not_ready) = pools.values().fold((0, 0), |(a, b), (r, n)| (a + r, b + n));
    let phase_text = phases
        .iter()
        .map(|(k, v)| format!("{v} {k}"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut e = envelope(
        &sc,
        format!(
            "Kubernetes {} ({}): {}; {} pods ({phase_text}) in {} namespaces; {} unhealthy pods; {} warning events in the last hour; metrics-server {}.",
            version.git_version,
            provider.unwrap_or("provider not detected"),
            if nodes.is_some() {
                format!("{ready}/{} nodes Ready", ready + not_ready)
            } else {
                "nodes not readable".into()
            },
            pods.len(),
            namespaces.map_or_else(|| "?".into(), |n| n.to_string()),
            bad.len(),
            warnings.len(),
            if metrics {
                "present"
            } else {
                "not installed (top will not work)"
            },
        ),
    );
    e.findings = findings;
    e.columns = vec!["ns", "name", "status", "restarts", "age", "node"];
    e.items = bad
        .iter()
        .take(10)
        .map(|(p, status)| {
            let mut r = pod_row(p);
            r["ns"] = json!(p.metadata.namespace);
            r["name"] = json!(p.metadata.name);
            r["status"] = json!(status);
            r["age"] = json!(
                p.metadata
                    .creation_timestamp
                    .as_ref()
                    .map(|t| age(now, t.0))
            );
            r
        })
        .collect();
    if !pools.is_empty() {
        e.sections.push(Section {
            title: "NODE POOLS (ready/not ready)".into(),
            lines: pools
                .iter()
                .map(|(p, (r, n))| format!("{p}: {r} Ready, {n} NotReady"))
                .collect(),
            untrusted: None,
        });
    }
    add_notes(&mut e, &notes);
    e.next.push(NextCall::new(
        "find_problems",
        json!({}),
        "list every broken object with findings",
    ));
    Ok(e)
}

/// Append an "UNAVAILABLE EVIDENCE" section listing what could not be read.
pub fn add_notes(e: &mut Envelope, notes: &[Unavailable]) {
    if notes.is_empty() {
        return;
    }
    e.sections.push(Section {
        title: "UNAVAILABLE EVIDENCE".into(),
        lines: notes
            .iter()
            .map(|n| format!("{}: {}", n.what, n.reason))
            .collect(),
        untrusted: None,
    });
}

// ---------------------------------------------------------------------------------------
// api_resources

/// Inputs for `api_resources`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApiResourcesInput {
    /// Kubeconfig context.
    pub context: Option<String>,
    /// Only this API group (`""` or `core` for the core group).
    pub group: Option<String>,
    /// Only namespaced (true) or cluster-scoped (false) kinds.
    pub namespaced: Option<bool>,
}

/// Kinds served by the cluster, CRDs included.
pub async fn api_resources(ctx: &Ctx, input: ApiResourcesInput) -> Result<Envelope> {
    let sc = scope(ctx, input.context.as_deref(), None, true).await?;
    let all = resources(ctx, &sc.target).await?;
    let group = input
        .group
        .as_deref()
        .map(|g| if g == "core" { "" } else { g });
    let items: Vec<Value> = all
        .iter()
        .filter(|r| group.is_none_or(|g| r.group == g))
        .filter(|r| input.namespaced.is_none_or(|n| r.namespaced == n))
        .map(|r| json!({"kind": r.kind, "api_version": r.api_version(), "namespaced": r.namespaced, "short_names": r.short_names, "verbs": r.verbs}))
        .collect();
    let mut e = envelope(&sc, format!("{} resource kinds.", items.len()));
    e.columns = vec!["kind", "api_version", "namespaced", "short_names", "verbs"];
    e.items = items;
    Ok(e)
}

// ---------------------------------------------------------------------------------------
// list_resources

/// Inputs for `list_resources`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListResourcesInput {
    /// Kind, plural or short name (e.g. `Deployment`, `pods`, `pvc`, a CRD kind).
    pub kind: String,
    /// API version (`apps/v1`) when a kind name is ambiguous.
    pub api_version: Option<String>,
    /// Namespace (default: the context's namespace). Ignored for cluster-scoped kinds.
    pub namespace: Option<String>,
    /// List across all allowed namespaces.
    #[serde(default)]
    pub all_namespaces: bool,
    /// Label selector, e.g. `app=web,tier!=db`.
    pub label_selector: Option<String>,
    /// Field selector, e.g. `status.phase=Pending`.
    pub field_selector: Option<String>,
    /// Max rows (default 50, max 500).
    pub limit: Option<u32>,
    /// Continue token from a previous call.
    #[serde(rename = "continue")]
    pub continue_token: Option<String>,
    /// Kubeconfig context.
    pub context: Option<String>,
}

/// List objects of any kind as compact rows.
pub async fn list_resources(ctx: &Ctx, input: ListResourcesInput) -> Result<Envelope> {
    let target = ctx
        .clusters
        .target(input.context.as_deref(), &ctx.policy)
        .await?;
    let info = resolve(ctx, &target, &input.kind, input.api_version.as_deref()).await?;
    let ar = api_resource(&info);
    let all_ns = !info.namespaced || input.all_namespaces;
    let sc = scope(
        ctx,
        input.context.as_deref(),
        input.namespace.as_deref(),
        all_ns,
    )
    .await?;
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let mut lp = ListParams::default().limit(limit);
    if let Some(l) = &input.label_selector {
        lp = lp.labels(&truncate(l, 1000));
    }
    if let Some(f) = &input.field_selector {
        lp = lp.fields(&truncate(f, 1000));
    }
    if let Some(c) = &input.continue_token {
        lp = lp.continue_token(c);
    }
    let mut notes = Vec::new();
    let (objects, cont) = list_dynamic(ctx, &sc, &ar, info.namespaced, &lp, &mut notes).await?;
    let now = ctx.now();
    let mut items: Vec<Value> = objects
        .iter()
        .map(|o| rows::row(&info.kind, o, now))
        .collect();
    if info.kind == "Namespace" {
        items.retain(|r| {
            r["name"]
                .as_str()
                .is_some_and(|n| ctx.policy.namespace_allowed(n))
        });
    }
    let where_ = match (&sc.namespace, info.namespaced) {
        (_, false) => "cluster-wide".to_owned(),
        (Some(ns), true) => format!("in namespace {ns}"),
        (None, true) => "across allowed namespaces".to_owned(),
    };
    let mut e = envelope(
        &sc,
        format!(
            "{} {} {where_}{}.",
            items.len(),
            info.plural,
            if cont.is_some() {
                " (more available)"
            } else {
                ""
            }
        ),
    );
    e.columns = rows::columns(&info.kind, info.namespaced && sc.namespace.is_none());
    e.items = items;
    if let Some(c) = cont {
        // Repeat the whole query: a page cursor is only valid for the same selectors.
        let mut args = json!({"kind": input.kind, "continue": c, "limit": limit});
        let fields = [
            ("api_version", input.api_version.as_ref()),
            ("namespace", input.namespace.as_ref()),
            ("label_selector", input.label_selector.as_ref()),
            ("field_selector", input.field_selector.as_ref()),
            ("context", input.context.as_ref()),
        ];
        for (k, v) in fields {
            if let Some(v) = v {
                args[k] = json!(v);
            }
        }
        if input.all_namespaces {
            args["all_namespaces"] = json!(true);
        }
        e.next
            .push(NextCall::new("list_resources", args, "fetch the next page"));
    }
    add_notes(&mut e, &notes);
    Ok(e)
}

async fn list_dynamic(
    ctx: &Ctx,
    sc: &Scope,
    ar: &ApiResource,
    namespaced: bool,
    lp: &ListParams,
    notes: &mut Vec<Unavailable>,
) -> Result<(Vec<Value>, Option<String>)> {
    let client = sc.target.client.clone();
    let to_values = |items: Vec<DynamicObject>| -> Vec<Value> {
        items
            .into_iter()
            .filter_map(|o| serde_json::to_value(o).ok())
            .collect()
    };
    if let (true, Some(ns)) = (namespaced, &sc.namespace) {
        let list = Api::<DynamicObject>::namespaced_with(client, ns, ar)
            .list(lp)
            .await
            .map_err(|e| Error::kube(format!("list {} in namespace {ns}", ar.plural), &e))?;
        return Ok((
            to_values(list.items),
            list.metadata.continue_.filter(|c| !c.is_empty()),
        ));
    }
    match Api::<DynamicObject>::all_with(client.clone(), ar)
        .list(lp)
        .await
    {
        Ok(list) => {
            let cont = list.metadata.continue_.filter(|c| !c.is_empty());
            let items = list
                .items
                .into_iter()
                .filter(|o| {
                    !namespaced
                        || o.metadata
                            .namespace
                            .as_deref()
                            .is_some_and(|n| ctx.policy.namespace_allowed(n))
                })
                .collect();
            Ok((to_values(items), cont))
        }
        Err(err) => {
            let err = Error::kube(format!("list {} in all namespaces", ar.plural), &err);
            if !namespaced || !err.is_forbidden() {
                return Err(err);
            }
            let namespaces = fallback_namespaces(ctx, sc, &ar.plural, notes);
            let mut out = Vec::new();
            for ns in namespaces {
                match Api::<DynamicObject>::namespaced_with(client.clone(), &ns, ar)
                    .list(lp)
                    .await
                {
                    Ok(l) => out.extend(to_values(l.items)),
                    Err(e) => notes.push(Unavailable {
                        what: format!("{} in {ns}", ar.plural),
                        reason: Error::kube("list", &e).to_string(),
                    }),
                }
            }
            Ok((out, None))
        }
    }
}

// ---------------------------------------------------------------------------------------
// get_resource

/// How much of an object to return.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum View {
    /// Key spec/status fields, conditions and events.
    #[default]
    Summary,
    /// The cleaned object as YAML text.
    Yaml,
    /// The cleaned object as structured JSON plus YAML text.
    Full,
}

/// Inputs for `get_resource`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetResourceInput {
    /// Kind, plural or short name.
    pub kind: String,
    /// Object name.
    pub name: String,
    /// Namespace (default: the context's namespace).
    pub namespace: Option<String>,
    /// API version when a kind name is ambiguous.
    pub api_version: Option<String>,
    /// `summary` (default), `yaml` or `full`.
    #[serde(default)]
    pub view: View,
    /// Include recent events about the object (default true).
    pub include_events: Option<bool>,
    /// Kubeconfig context.
    pub context: Option<String>,
}

/// Describe one object.
pub async fn get_resource(ctx: &Ctx, input: GetResourceInput) -> Result<Envelope> {
    check_name("name", &input.name)?;
    let target = ctx
        .clusters
        .target(input.context.as_deref(), &ctx.policy)
        .await?;
    let info = resolve(ctx, &target, &input.kind, input.api_version.as_deref()).await?;
    let ar = api_resource(&info);
    let sc = scope(
        ctx,
        input.context.as_deref(),
        input.namespace.as_deref(),
        !info.namespaced,
    )
    .await?;
    if info.kind == "Namespace" {
        ctx.policy.check_namespace(&input.name)?;
    }
    let api = match (&sc.namespace, info.namespaced) {
        (Some(ns), true) => {
            Api::<DynamicObject>::namespaced_with(sc.target.client.clone(), ns, &ar)
        }
        _ => Api::<DynamicObject>::all_with(sc.target.client.clone(), &ar),
    };
    let obj = api
        .get(&input.name)
        .await
        .map_err(|e| Error::kube(format!("get {} {}", info.kind, input.name), &e))?;
    let raw = serde_json::to_value(&obj).map_err(|e| Error::Api(e.to_string()))?;
    let cleaned = clean(ctx, &info.kind, raw);
    let now = ctx.now();
    let view = if info.kind == "Secret" {
        View::Yaml
    } else {
        input.view
    };
    let shown = match view {
        View::Summary if info.kind == "Pod" => prune(pod_summary(&cleaned, now)),
        View::Summary => prune(depth_limited(&cleaned, 0)),
        View::Yaml | View::Full => cleaned.clone(),
    };
    let mut e = envelope(
        &sc,
        format!(
            "{} {}{}: {}.",
            info.kind,
            input.name,
            sc.namespace
                .as_ref()
                .filter(|_| info.namespaced)
                .map(|n| format!(" ({n})"))
                .unwrap_or_default(),
            rows::row(&info.kind, &cleaned, now)
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("found")
        ),
    );
    if info.kind == "Secret" {
        e.summary
            .push_str(" Secret values are never returned: only key names and sizes.");
    }
    if view != View::Yaml {
        e.items.push(shown.clone());
    }
    let yaml = serde_saphyr::to_string(&shown).unwrap_or_else(|_| shown.to_string());
    e.sections.push(Section {
        title: format!(
            "OBJECT ({})",
            match view {
                View::Summary => "summary",
                View::Yaml => "yaml",
                View::Full => "full",
            }
        ),
        lines: yaml.lines().map(str::to_owned).collect(),
        untrusted: Some(vec![
            ("source".into(), "object".into()),
            ("kind".into(), info.kind.clone()),
        ]),
    });
    e.untrusted_fields = vec![
        "items[*].metadata.annotations".into(),
        "items[*].status".into(),
        "items[*].data".into(),
    ];
    if input.include_events.unwrap_or(true) {
        let ns = if info.namespaced {
            sc.namespace.clone().unwrap_or_default()
        } else {
            String::new()
        };
        match events_for(&sc.target, &ns, &info.kind, &input.name, now).await {
            Ok(events) if !events.is_empty() => e.sections.push(events_section(ctx, &events, now)),
            Ok(_) => {}
            Err(err) => add_notes(
                &mut e,
                &[Unavailable {
                    what: "events".into(),
                    reason: err.to_string(),
                }],
            ),
        }
    }
    Ok(e)
}

/// Curated pod summary.
fn pod_summary(p: &Value, now: jiff::Timestamp) -> Value {
    let pod: Pod = serde_json::from_value(p.clone()).unwrap_or_default();
    let statuses = pod
        .status
        .as_ref()
        .and_then(|s| s.container_statuses.clone())
        .unwrap_or_default();
    let containers: Vec<Value> = p
        .pointer("/spec/containers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|c| {
            let name = c["name"].as_str().unwrap_or("");
            let st = statuses.iter().find(|s| s.name == name);
            let state = st.and_then(|s| s.state.as_ref()).map(|s| {
                if let Some(w) = &s.waiting {
                    format!("waiting: {}", w.reason.as_deref().unwrap_or("-"))
                } else if let Some(r) = &s.running {
                    format!("running for {}", r.started_at.as_ref().map_or_else(|| "?".into(), |t| age(now, t.0)))
                } else if let Some(t) = &s.terminated {
                    format!("terminated: {} exit {}", t.reason.as_deref().unwrap_or("-"), t.exit_code)
                } else {
                    "unknown".into()
                }
            });
            let last = st.and_then(|s| s.last_state.as_ref()).and_then(|s| s.terminated.as_ref()).map(|t| {
                format!("{} exit {}{}", t.reason.as_deref().unwrap_or("-"), t.exit_code, t.finished_at.as_ref().map(|f| format!(" {} ago", age(now, f.0))).unwrap_or_default())
            });
            json!({
                "name": name,
                "image": c["image"],
                "ready": st.is_some_and(|s| s.ready),
                "restarts": st.map_or(0, |s| s.restart_count),
                "state": state,
                "last_termination": last,
                "resources": c.get("resources"),
                "ports": c.get("ports"),
                "env": c.get("env"),
                "envFrom": c.get("envFrom"),
                "probes": {"liveness": c.get("livenessProbe"), "readiness": c.get("readinessProbe"), "startup": c.get("startupProbe")},
            })
        })
        .collect();
    json!({
        "name": p.pointer("/metadata/name"),
        "namespace": p.pointer("/metadata/namespace"),
        "status": rows::pod_status(&pod),
        "node": p.pointer("/spec/nodeName"),
        "age": pod.metadata.creation_timestamp.as_ref().map(|t| age(now, t.0)),
        "owners": p.pointer("/metadata/ownerReferences"),
        "labels": p.pointer("/metadata/labels"),
        "serviceAccount": p.pointer("/spec/serviceAccountName"),
        "conditions": p.pointer("/status/conditions"),
        "initContainers": p.pointer("/status/initContainerStatuses"),
        "containers": containers,
        "volumes": p.pointer("/spec/volumes"),
    })
}

/// Drop nulls and empty objects/arrays (summary views only).
fn prune(v: Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.into_iter()
                .map(|(k, v)| (k, prune(v)))
                .filter(|(_, v)| {
                    !(v.is_null()
                        || v.as_object().is_some_and(serde_json::Map::is_empty)
                        || v.as_array().is_some_and(Vec::is_empty))
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.into_iter().map(prune).collect()),
        other => other,
    }
}

/// Replace values nested deeper than 4 levels or long arrays with short placeholders.
fn depth_limited(v: &Value, depth: usize) -> Value {
    match v {
        Value::Object(m) if depth >= 4 => json!(format!("{{… {} keys}}", m.len())),
        Value::Array(a) if depth >= 4 => json!(format!("[… {} items]", a.len())),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, v)| (k.clone(), depth_limited(v, depth + 1)))
                .collect(),
        ),
        Value::Array(a) => {
            let mut out: Vec<Value> = a
                .iter()
                .take(10)
                .map(|v| depth_limited(v, depth + 1))
                .collect();
            if a.len() > 10 {
                out.push(json!(format!("… {} more", a.len() - 10)));
            }
            Value::Array(out)
        }
        other => other.clone(),
    }
}

// ---------------------------------------------------------------------------------------
// list_events

/// Inputs for `list_events`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListEventsInput {
    /// Namespace (default: the context's namespace).
    pub namespace: Option<String>,
    /// All allowed namespaces.
    #[serde(default)]
    pub all_namespaces: bool,
    /// Only events about this kind (e.g. `Pod`).
    pub involved_kind: Option<String>,
    /// Only events about this object name.
    pub involved_name: Option<String>,
    /// Event types to include (default `["Warning"]`; use `["Normal","Warning"]` for all).
    pub types: Option<Vec<String>>,
    /// Look-back window such as `30m`, `2h` (default `1h`).
    pub since: Option<String>,
    /// Max grouped rows (default 50).
    pub limit: Option<u32>,
    /// Kubeconfig context.
    pub context: Option<String>,
}

/// Recent events, grouped by (type, reason, object, message).
pub async fn list_events(ctx: &Ctx, input: ListEventsInput) -> Result<Envelope> {
    let sc = scope(
        ctx,
        input.context.as_deref(),
        input.namespace.as_deref(),
        input.all_namespaces,
    )
    .await?;
    let since =
        parse_duration(input.since.as_deref().unwrap_or("1h")).map_err(Error::InvalidInput)?;
    let types = input.types.unwrap_or_else(|| vec!["Warning".into()]);
    let mut fields = Vec::new();
    if let [t] = types.as_slice() {
        fields.push(format!("type={t}"));
    }
    if let Some(k) = &input.involved_kind {
        fields.push(format!("involvedObject.kind={k}"));
    }
    if let Some(n) = &input.involved_name {
        check_name("involved_name", n)?;
        fields.push(format!("involvedObject.name={n}"));
    }
    let lp = if fields.is_empty() {
        ListParams::default()
    } else {
        ListParams::default().fields(&fields.join(","))
    };
    let mut notes = Vec::new();
    let mut events: Vec<Event> = list_scoped(ctx, &sc, &lp, "events", &mut notes).await?;
    events.retain(|e| types.iter().any(|t| e.type_.as_deref() == Some(t)));
    let now = ctx.now();
    retain_recent(&mut events, now, since);
    let rows = group_events(ctx, &events, now, sc.namespace.is_none());
    let total = rows.len();
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT) as usize;
    let mut e = envelope(
        &sc,
        format!(
            "{total} event groups ({} events) of type {} in the last {}.",
            events.len(),
            types.join("/"),
            input.since.as_deref().unwrap_or("1h")
        ),
    );
    e.columns = if sc.namespace.is_none() {
        vec![
            "ns",
            "type",
            "reason",
            "object",
            "count",
            "first_seen",
            "last_seen",
            "message",
        ]
    } else {
        vec![
            "type",
            "reason",
            "object",
            "count",
            "first_seen",
            "last_seen",
            "message",
        ]
    };
    e.items = rows.into_iter().take(limit).collect();
    if total > limit {
        e.truncated = true;
        e.omitted.items = total - limit;
    }
    e.items_untrusted = Some("event");
    e.untrusted_fields = vec!["items[*].message".into()];
    add_notes(&mut e, &notes);
    Ok(e)
}

/// Group events by (type, reason, object, message), warnings first, then most recent.
pub fn group_events(
    ctx: &Ctx,
    events: &[Event],
    now: jiff::Timestamp,
    with_ns: bool,
) -> Vec<Value> {
    // (ns, type, reason, object, message) -> (count, first seen, last seen)
    type Key = (String, String, String, String, String);
    let mut groups: HashMap<Key, (i32, Option<jiff::Timestamp>, Option<jiff::Timestamp>)> =
        HashMap::new();
    for ev in events {
        let obj = format!(
            "{}/{}",
            ev.involved_object.kind.as_deref().unwrap_or("?"),
            ev.involved_object.name.as_deref().unwrap_or("?")
        );
        let key = (
            ev.metadata.namespace.clone().unwrap_or_default(),
            ev.type_.clone().unwrap_or_default(),
            ev.reason.clone().unwrap_or_default(),
            obj,
            strip_uids(&ctx.redactor.text(ev.message.as_deref().unwrap_or(""))),
        );
        let t = k8s_mcp_diagnose::rules::last_seen(ev);
        let first = ev.first_timestamp.as_ref().map(|t| t.0).or(t);
        let g = groups.entry(key).or_insert((0, first, t));
        g.0 += k8s_mcp_diagnose::rules::count(ev);
        g.1 = g.1.min(first).or(first);
        g.2 = g.2.max(t);
    }
    let mut rows: Vec<_> = groups.into_iter().collect();
    rows.sort_by(|a, b| {
        (a.0.1 != "Warning", std::cmp::Reverse(a.1.2), &a.0.3).cmp(&(
            b.0.1 != "Warning",
            std::cmp::Reverse(b.1.2),
            &b.0.3,
        ))
    });
    rows.into_iter()
        .map(|((ns, ty, reason, obj, msg), (count, first, last))| {
            let mut r = json!({
                "type": ty, "reason": reason, "object": obj, "count": count,
                "first_seen": first.map(|t| age(now, t)), "last_seen": last.map(|t| age(now, t)),
                "message": truncate(&msg, 300),
            });
            if with_ns {
                r["ns"] = json!(ns);
            }
            r
        })
        .collect()
}

/// Drop object UIDs such as `(ac5c6640-378b-4786-b7a7-35da71d94376)` from event messages.
fn strip_uids(msg: &str) -> String {
    #[allow(clippy::unwrap_used)] // constant pattern
    static UID: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"\(?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\)?")
            .unwrap()
    });
    UID.replace_all(msg, "").into_owned()
}

/// Grouped events as an untrusted text section.
pub fn events_section(ctx: &Ctx, events: &[Event], now: jiff::Timestamp) -> Section {
    Section {
        title: "EVENTS (last 1h)".into(),
        lines: group_events(ctx, events, now, false)
            .iter()
            .take(15)
            .map(|r| {
                format!(
                    "×{} {} {}: {} (last {} ago)",
                    r["count"],
                    r["type"].as_str().unwrap_or(""),
                    r["reason"].as_str().unwrap_or(""),
                    r["message"].as_str().unwrap_or(""),
                    r["last_seen"].as_str().unwrap_or("?")
                )
            })
            .collect(),
        untrusted: Some(vec![("source".into(), "event".into())]),
    }
}

// ---------------------------------------------------------------------------------------
// top

/// What to measure.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum TopTarget {
    /// Pods (per pod, summed over containers).
    #[default]
    Pods,
    /// Nodes.
    Nodes,
}

/// Sort key.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SortBy {
    /// CPU usage.
    #[default]
    Cpu,
    /// Memory usage.
    Memory,
}

/// Inputs for `top`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TopInput {
    /// `pods` (default) or `nodes`.
    #[serde(default)]
    pub target: TopTarget,
    /// Namespace for pods (default: the context's namespace).
    pub namespace: Option<String>,
    /// Pods across all allowed namespaces.
    #[serde(default)]
    pub all_namespaces: bool,
    /// `cpu` (default) or `memory`.
    #[serde(default)]
    pub sort_by: SortBy,
    /// Max rows (default 20).
    pub limit: Option<u32>,
    /// Kubeconfig context.
    pub context: Option<String>,
}

/// Resource usage vs requests/limits (needs metrics-server).
pub async fn top(ctx: &Ctx, input: TopInput) -> Result<Envelope> {
    let nodes_mode = input.target == TopTarget::Nodes;
    let sc = scope(
        ctx,
        input.context.as_deref(),
        input.namespace.as_deref(),
        nodes_mode || input.all_namespaces,
    )
    .await?;
    let all = resources(ctx, &sc.target).await?;
    let Some(info) = all.iter().find(|r| {
        r.group == "metrics.k8s.io" && r.plural == if nodes_mode { "nodes" } else { "pods" }
    }) else {
        return Err(Error::Unavailable("metrics.k8s.io is not available: metrics-server is not installed in this cluster, so live CPU/memory usage cannot be read. Install metrics-server, or use get_resource to see requests/limits.".into()));
    };
    let ar = api_resource(info);
    let mut notes = Vec::new();
    let (metrics, _) = list_dynamic(
        ctx,
        &sc,
        &ar,
        !nodes_mode,
        &ListParams::default(),
        &mut notes,
    )
    .await?;
    let limit = input.limit.unwrap_or(20).clamp(1, MAX_LIMIT) as usize;
    let mut items: Vec<Value> = if nodes_mode {
        let nodes: HashMap<String, Node> = Api::<Node>::all(sc.target.client.clone())
            .list(&ListParams::default())
            .await
            .map_err(|e| Error::kube("list nodes", &e))?
            .items
            .into_iter()
            .map(|n| (n.metadata.name.clone().unwrap_or_default(), n))
            .collect();
        metrics
            .iter()
            .map(|m| {
                let name = m.pointer("/metadata/name").and_then(Value::as_str).unwrap_or("");
                let cpu = m.pointer("/usage/cpu").and_then(Value::as_str).and_then(cpu_millis).unwrap_or(0);
                let mem = m.pointer("/usage/memory").and_then(Value::as_str).and_then(bytes).unwrap_or(0);
                let alloc = nodes.get(name).and_then(|n| n.status.as_ref()).and_then(|s| s.allocatable.as_ref());
                let acpu = alloc.and_then(|a| a.get("cpu")).and_then(|q| cpu_millis(&q.0));
                let amem = alloc.and_then(|a| a.get("memory")).and_then(|q| bytes(&q.0));
                json!({"name": name, "cpu_m": cpu, "cpu_alloc_m": acpu, "cpu_pct": pct(cpu, acpu), "mem": fmt_bytes(mem), "mem_bytes": mem, "mem_alloc": amem.map(fmt_bytes), "mem_pct": pct(mem, amem)})
            })
            .collect()
    } else {
        let pods: Vec<Pod> =
            list_scoped(ctx, &sc, &ListParams::default(), "pods", &mut notes).await?;
        let by_name: HashMap<(String, String), &Pod> = pods
            .iter()
            .map(|p| {
                (
                    (
                        p.metadata.namespace.clone().unwrap_or_default(),
                        p.metadata.name.clone().unwrap_or_default(),
                    ),
                    p,
                )
            })
            .collect();
        metrics
            .iter()
            .map(|m| {
                let name = m.pointer("/metadata/name").and_then(Value::as_str).unwrap_or("").to_owned();
                let ns = m.pointer("/metadata/namespace").and_then(Value::as_str).unwrap_or("").to_owned();
                let (mut cpu, mut mem) = (0, 0);
                for c in m.get("containers").and_then(Value::as_array).into_iter().flatten() {
                    cpu += c.pointer("/usage/cpu").and_then(Value::as_str).and_then(cpu_millis).unwrap_or(0);
                    mem += c.pointer("/usage/memory").and_then(Value::as_str).and_then(bytes).unwrap_or(0);
                }
                let res = by_name.get(&(ns.clone(), name.clone())).map(|p| pod_resources(p)).unwrap_or_default();
                json!({
                    "ns": ns, "name": name,
                    "cpu_m": cpu, "cpu_req_m": res.0, "cpu_lim_m": res.1,
                    "mem": fmt_bytes(mem), "mem_bytes": mem, "mem_req": res.2.map(fmt_bytes), "mem_lim": res.3.map(fmt_bytes),
                    "mem_pct_of_limit": pct(mem, res.3),
                })
            })
            .collect()
    };
    let key = if input.sort_by == SortBy::Memory {
        "mem_bytes"
    } else {
        "cpu_m"
    };
    items.sort_by_key(|r| std::cmp::Reverse(r[key].as_i64().unwrap_or(0)));
    let total = items.len();
    items.truncate(limit);
    let mut e = envelope(
        &sc,
        format!(
            "Top {} of {total} {} by {}.",
            items.len(),
            if nodes_mode { "nodes" } else { "pods" },
            if key == "cpu_m" { "CPU" } else { "memory" }
        ),
    );
    e.columns = if nodes_mode {
        vec![
            "name",
            "cpu_m",
            "cpu_alloc_m",
            "cpu_pct",
            "mem",
            "mem_alloc",
            "mem_pct",
        ]
    } else {
        vec![
            "ns",
            "name",
            "cpu_m",
            "cpu_req_m",
            "cpu_lim_m",
            "mem",
            "mem_req",
            "mem_lim",
            "mem_pct_of_limit",
        ]
    };
    e.items = items;
    if total > limit {
        e.omitted.items = total - limit;
    }
    add_notes(&mut e, &notes);
    Ok(e)
}

fn pct(used: i64, total: Option<i64>) -> Option<i64> {
    total.filter(|t| *t > 0).map(|t| used * 100 / t)
}

/// (cpu request, cpu limit, mem request, mem limit) summed over containers.
fn pod_resources(p: &Pod) -> (Option<i64>, Option<i64>, Option<i64>, Option<i64>) {
    let mut out = (None, None, None, None);
    let add = |acc: &mut Option<i64>, v: Option<i64>| {
        if let Some(v) = v {
            *acc = Some(acc.unwrap_or(0) + v);
        }
    };
    for c in p.spec.iter().flat_map(|s| &s.containers) {
        let r = c.resources.as_ref();
        let get = |m: Option<
            &BTreeMap<String, k8s_openapi::apimachinery::pkg::api::resource::Quantity>,
        >,
                   k: &str| m.and_then(|m| m.get(k)).map(|q| q.0.clone());
        add(
            &mut out.0,
            get(r.and_then(|r| r.requests.as_ref()), "cpu")
                .as_deref()
                .and_then(cpu_millis),
        );
        add(
            &mut out.1,
            get(r.and_then(|r| r.limits.as_ref()), "cpu")
                .as_deref()
                .and_then(cpu_millis),
        );
        add(
            &mut out.2,
            get(r.and_then(|r| r.requests.as_ref()), "memory")
                .as_deref()
                .and_then(bytes),
        );
        add(
            &mut out.3,
            get(r.and_then(|r| r.limits.as_ref()), "memory")
                .as_deref()
                .and_then(bytes),
        );
    }
    out
}

// ---------------------------------------------------------------------------------------
// check_permissions

/// Inputs for `check_permissions`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckPermissionsInput {
    /// Namespace to check (default: the context's namespace).
    pub namespace: Option<String>,
    /// Extra resources to check `get`/`list` on, e.g. `["deployments.apps", "pods/log"]`.
    pub verbs_for: Option<Vec<String>>,
    /// Kubeconfig context.
    pub context: Option<String>,
}

/// What this identity can do, plus the effective k8s-mcp policy.
pub async fn check_permissions(ctx: &Ctx, input: CheckPermissionsInput) -> Result<Envelope> {
    let sc = scope(
        ctx,
        input.context.as_deref(),
        input.namespace.as_deref(),
        false,
    )
    .await?;
    let ns = sc.namespace.clone().unwrap_or_default();
    let client = sc.target.client.clone();
    let mut checks: Vec<(String, &str, String, String, bool)> = vec![
        // (label, verb, group, resource[/sub], namespaced)
        (
            "list pods".into(),
            "list",
            String::new(),
            "pods".into(),
            true,
        ),
        (
            "read pod logs".into(),
            "get",
            String::new(),
            "pods/log".into(),
            true,
        ),
        (
            "list events".into(),
            "list",
            String::new(),
            "events".into(),
            true,
        ),
        (
            "list deployments".into(),
            "list",
            "apps".into(),
            "deployments".into(),
            true,
        ),
        (
            "list nodes (cluster)".into(),
            "list",
            String::new(),
            "nodes".into(),
            false,
        ),
        (
            "read pod metrics".into(),
            "list",
            "metrics.k8s.io".into(),
            "pods".into(),
            true,
        ),
        (
            "read secrets (k8s-mcp never returns values)".into(),
            "get",
            String::new(),
            "secrets".into(),
            true,
        ),
        (
            "do everything (cluster-admin)".into(),
            "*",
            "*".into(),
            "*".into(),
            false,
        ),
    ];
    for r in input.verbs_for.unwrap_or_default().into_iter().take(10) {
        let (res, group) = r
            .split_once('.')
            .map_or((r.clone(), String::new()), |(a, b)| {
                (a.to_owned(), b.to_owned())
            });
        checks.push((format!("list {r}"), "list", group, res, true));
    }
    let api: Api<SelfSubjectAccessReview> = Api::all(client.clone());
    let mut items = Vec::new();
    let mut admin = false;
    for (label, verb, group, resource, namespaced) in &checks {
        let (resource, sub) = resource
            .split_once('/')
            .map_or((resource.as_str(), None), |(a, b)| (a, Some(b.to_owned())));
        let review = SelfSubjectAccessReview {
            spec: SelfSubjectAccessReviewSpec {
                resource_attributes: Some(ResourceAttributes {
                    namespace: namespaced.then(|| ns.clone()),
                    verb: Some((*verb).to_owned()),
                    group: Some(group.clone()),
                    resource: Some(resource.to_owned()),
                    subresource: sub,
                    ..ResourceAttributes::default()
                }),
                ..SelfSubjectAccessReviewSpec::default()
            },
            ..SelfSubjectAccessReview::default()
        };
        let allowed = api
            .create(&PostParams::default(), &review)
            .await
            .map(|r| r.status.is_some_and(|s| s.allowed))
            .map_err(|e| Error::kube("create a SelfSubjectAccessReview", &e))?;
        if *verb == "*" && allowed {
            admin = true;
        }
        items.push(json!({"check": label, "allowed": allowed}));
    }
    let rules = Api::<SelfSubjectRulesReview>::all(client)
        .create(
            &PostParams::default(),
            &SelfSubjectRulesReview {
                spec: SelfSubjectRulesReviewSpec {
                    namespace: Some(ns.clone()),
                },
                ..SelfSubjectRulesReview::default()
            },
        )
        .await
        .ok()
        .and_then(|r| r.status)
        .map(|s| {
            s.resource_rules
                .iter()
                .take(30)
                .map(|r| {
                    format!(
                        "{} on {}",
                        r.verbs.join(","),
                        r.resources.clone().unwrap_or_default().join(",")
                    )
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut e = envelope(
        &sc,
        if admin {
            format!(
                "WARNING: this identity can do everything (`*` on `*`) in {ns}. k8s-mcp stays read-only, but consider a dedicated read-only kubeconfig for AI tools (see docs)."
            )
        } else {
            format!(
                "Permission checks for namespace {ns}. k8s-mcp is read-only; RBAC is the real boundary."
            )
        },
    );
    e.columns = vec!["check", "allowed"];
    e.items = items;
    e.sections.push(Section {
        title: "EFFECTIVE K8S-MCP POLICY".into(),
        lines: ctx
            .policy
            .to_json()
            .to_string()
            .lines()
            .map(str::to_owned)
            .collect(),
        untrusted: None,
    });
    if !rules.is_empty() {
        e.sections.push(Section {
            title: format!("RBAC RULES IN {ns} (first 30)"),
            lines: rules,
            untrusted: None,
        });
    }
    Ok(e)
}
