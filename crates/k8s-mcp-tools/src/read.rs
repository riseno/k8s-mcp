//! Core read tools (PROPOSAL §8.1).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;

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
use k8s_openapi::kube_aggregator::pkg::apis::apiregistration::v1::APIService;
use kube::api::{Api, DynamicObject, ListParams, PostParams};
use kube::discovery::ApiResource;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::common::{
    Scope, bounded, check_name, clean, ensure_namespace, envelope, events_for, fallback_namespaces,
    list_scoped, retain_recent, scope, soft,
};
use crate::discovery::{Resolved, api_resource, resolve, resources};
use crate::rows::{self, node_pool, pod_row, unhealthy};
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
    e.columns = vec![
        "name",
        "server_host",
        "namespace",
        "provider",
        "provider_source",
        "is_default",
    ];
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
    )?;
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
    )?;
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
    )?
    .unwrap_or_default();
    retain_recent(&mut warnings, now, SignedDuration::from_hours(1));
    // One request: full discovery walks every API group, and broken aggregated APIs stall it.
    let metrics = match apiservice(&client, METRICS_APISERVICE).await {
        Some(m) => m,
        // APIServices not readable: is the group registered at all?
        None if client
            .list_api_groups()
            .await
            .is_ok_and(|g| g.groups.iter().any(|g| g.name == "metrics.k8s.io")) =>
        {
            Aggregated::Available
        }
        None => Aggregated::Missing,
    };

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

    let node_list = nodes.as_deref().unwrap_or_default();
    let provider = ctx
        .clusters
        .detect_provider(&sc.target.context, node_list)
        .map(|d| d.describe())
        .or_else(|| {
            // Not a cloud provider (kind, k3s, ...), but worth naming.
            let platforms = k8s_mcp_core::provider::node_platforms(node_list);
            (!platforms.is_empty()).then(|| platforms.join(", "))
        })
        .map(|p| {
            match ctx
                .clusters
                .detection_conflict(&sc.target.context, node_list)
            {
                // Issue #64: say why the kubeconfig's cloud was not believed.
                Some(why) => format!("{p} (the context {why})"),
                None => p,
            }
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
            "Kubernetes {} {}: {}; {} pods ({phase_text}) in {} namespaces; {} unhealthy pods; {} warning events in the last hour; metrics-server {}.",
            version.git_version,
            provider.map_or_else(
                || "(provider not detected)".to_owned(),
                |p| format!("on {p}")
            ),
            if nodes.is_some() {
                format!("{ready}/{} nodes Ready", ready + not_ready)
            } else {
                "nodes not readable".into()
            },
            pods.len(),
            namespaces.map_or_else(|| "?".into(), |n| n.to_string()),
            bad.len(),
            warnings.len(),
            match &metrics {
                Aggregated::Available => "present".into(),
                Aggregated::Missing => "not installed (top will not work)".into(),
                Aggregated::Unavailable(why) =>
                    format!("installed but unavailable ({why}; top will not work)"),
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
    // Unmasked Secret values are a leak, not just missing evidence: say so up front.
    let unmasked: Vec<&str> = notes
        .iter()
        .filter_map(|n| {
            n.what
                .strip_prefix("Secret ")?
                .strip_suffix(crate::diagnose::UNMASKED)
        })
        .collect();
    if !unmasked.is_empty() {
        e.summary = format!(
            "{} Secret values could not be masked (k8s-mcp may not read Secret {}): the logs may contain them.",
            e.summary,
            unmasked.join(", ")
        );
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

/// The verbs every ordinary resource supports; shown as `all` to save output.
const STANDARD_VERBS: [&str; 8] = [
    "create",
    "delete",
    "deletecollection",
    "get",
    "list",
    "patch",
    "update",
    "watch",
];

/// Kinds served by the cluster, CRDs included.
pub async fn api_resources(ctx: &Ctx, input: ApiResourcesInput) -> Result<Envelope> {
    let sc = scope(ctx, input.context.as_deref(), None, true).await?;
    let all = resources(ctx, &sc.target).await?;
    let group = input
        .group
        .as_deref()
        .map(|g| if g == "core" { "" } else { g });
    let shown: Vec<_> = all
        .iter()
        .filter(|r| group.is_none_or(|g| r.group == g))
        .filter(|r| input.namespaced.is_none_or(|n| r.namespaced == n))
        .collect();
    let items: Vec<Value> = shown
        .iter()
        .map(|r| {
            let mut verbs = r.verbs.clone();
            verbs.sort();
            let verbs = if verbs == STANDARD_VERBS { json!("all") } else { json!(verbs) };
            json!({"kind": r.kind, "api_version": r.api_version(), "namespaced": r.namespaced, "short_names": r.short_names, "verbs": verbs})
        })
        .collect();
    let mut summary = format!("{} resource kinds.", items.len());
    // An aggregated API whose server is down is registered but serves no kinds (#76).
    if let Some(g) = group.filter(|g| items.is_empty() && !g.is_empty())
        && let Ok(groups) = sc.target.client.list_api_groups().await
        && let Some(registered) = groups.groups.iter().find(|r| r.name == g)
    {
        let why = match registered.preferred_version.as_ref() {
            Some(v) => match apiservice(&sc.target.client, &format!("{}.{g}", v.version)).await {
                Some(Aggregated::Unavailable(why)) => format!(" (APIService {}.{g}: {why})", v.version),
                _ => String::new(),
            },
            None => String::new(),
        };
        summary = format!("0 resource kinds: API group {g} is registered but its server is unavailable{why}.");
    }
    if group.is_none() {
        // Name every group, so a truncated table can always be narrowed with `group`.
        let groups: BTreeSet<&str> = shown
            .iter()
            .map(|r| {
                if r.group.is_empty() {
                    "core"
                } else {
                    r.group.as_str()
                }
            })
            .collect();
        summary = format!(
            "{} resource kinds in {} API groups; pass group=<name> to list one group: {}.",
            items.len(),
            groups.len(),
            groups.into_iter().collect::<Vec<_>>().join(", ")
        );
    }
    let mut e = envelope(&sc, summary);
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
    let resolved = resolve(ctx, &target, &input.kind, input.api_version.as_deref()).await?;
    let info = resolved.info.clone();
    let ar = api_resource(&info);
    let all_ns = !info.namespaced || input.all_namespaces;
    let sc = scope(
        ctx,
        input.context.as_deref(),
        input.namespace.as_deref(),
        all_ns,
    )
    .await?;
    let limit = bounded("limit", input.limit, DEFAULT_LIMIT, MAX_LIMIT)?;
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
    if objects.is_empty() && info.namespaced {
        ensure_namespace(&sc).await?;
    }
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
    let mut args = json!({"kind": input.kind});
    if let Some(ns) = &input.namespace {
        args["namespace"] = json!(ns);
    }
    add_alternatives(&mut e, &resolved, "list_resources", &args);
    add_notes(&mut e, &notes);
    Ok(e)
}

/// Say which other API groups serve an ambiguous kind, with a call for each (riseno/k8s-mcp#27).
fn add_alternatives(e: &mut Envelope, resolved: &Resolved, tool: &str, args: &Value) {
    if let Some(note) = resolved.note() {
        e.summary.push_str(&note);
    }
    for alt in resolved.alternatives.iter().take(3) {
        let mut a = args.clone();
        a["api_version"] = json!(alt.api_version());
        e.next.push(NextCall::new(
            tool,
            a,
            &format!("the {} served by {}", alt.kind, alt.api_version()),
        ));
    }
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
    let resolved = resolve(ctx, &target, &input.kind, input.api_version.as_deref()).await?;
    let info = resolved.info.clone();
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
        View::Summary => prune(with_template_containers(
            depth_limited(&cleaned, 0),
            &cleaned,
        )),
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
    // The object goes only in the OBJECT section, which is marked untrusted in both renderings.
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
    if view == View::Summary {
        let lines = related(&sc, &info.kind, &input.name, &cleaned, now).await;
        if !lines.is_empty() {
            e.sections.push(Section {
                title: "RELATED".into(),
                lines,
                untrusted: None,
            });
        }
    }
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
    let mut args = json!({"kind": input.kind, "name": input.name});
    if let Some(ns) = &input.namespace {
        args["namespace"] = json!(ns);
    }
    add_alternatives(&mut e, &resolved, "get_resource", &args);
    Ok(e)
}

/// Rows shown per related list.
const RELATED_ROWS: usize = 5;

/// Objects that explain this one (PROPOSAL §8.1, riseno/k8s-mcp#30): a Service's matching pods
/// and endpoints, a workload's pods and revisions, a Pod's owner chain and node, a PVC's volume
/// and StorageClass. Lists are capped; failed reads are reported as lines.
async fn related(
    sc: &Scope,
    kind: &str,
    name: &str,
    obj: &Value,
    now: jiff::Timestamp,
) -> Vec<String> {
    use k8s_openapi::api::apps::v1::ReplicaSet;
    use k8s_openapi::api::batch::v1::Job;
    use k8s_openapi::api::core::v1::PersistentVolume;
    use k8s_openapi::api::discovery::v1::EndpointSlice;
    use k8s_openapi::api::storage::v1::StorageClass;

    let client = sc.target.client.clone();
    let ns = sc.namespace.clone().unwrap_or_default();
    let mut out = Vec::new();
    let failed =
        |what: &str, e: &kube::Error| format!("{what}: {}", Error::kube(format!("read {what}"), e));
    let pod_rows = |pods: &[Pod], out: &mut Vec<String>| {
        let ready = pods.iter().filter(|p| unhealthy(p, now).is_none()).count();
        out.push(format!("pods: {ready}/{} healthy", pods.len()));
        for p in pods.iter().take(RELATED_ROWS) {
            let r = pod_row(p);
            out.push(format!(
                "  pod {}: {} ready {} restarts {}",
                p.metadata.name.as_deref().unwrap_or("?"),
                r["status"].as_str().unwrap_or("?"),
                r["ready"].as_str().unwrap_or("?"),
                r["restarts"]
            ));
        }
        if pods.len() > RELATED_ROWS {
            out.push(format!("  … and {} more", pods.len() - RELATED_ROWS));
        }
    };
    match kind {
        "Service" => {
            let selector: Vec<String> = obj
                .pointer("/spec/selector")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
                .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or("")))
                .collect();
            if selector.is_empty() {
                out.push("no selector: endpoints are managed outside Kubernetes".into());
            } else {
                match Api::<Pod>::namespaced(client.clone(), &ns)
                    .list(&ListParams::default().labels(&selector.join(",")))
                    .await
                {
                    Ok(l) => pod_rows(&l.items, &mut out),
                    Err(e) => out.push(failed("pods matching the selector", &e)),
                }
            }
            match Api::<EndpointSlice>::namespaced(client, &ns)
                .list(&ListParams::default().labels(&format!("kubernetes.io/service-name={name}")))
                .await
            {
                Ok(l) => {
                    let endpoints: Vec<_> =
                        l.items.iter().flat_map(|s| s.endpoints.iter()).collect();
                    let ready = endpoints
                        .iter()
                        .filter(|e| e.conditions.as_ref().and_then(|c| c.ready).unwrap_or(false))
                        .count();
                    out.push(format!(
                        "endpointslices: {} with {ready}/{} ready endpoints",
                        l.items.len(),
                        endpoints.len()
                    ));
                }
                Err(e) => out.push(failed("EndpointSlices", &e)),
            }
        }
        "Deployment" | "StatefulSet" | "DaemonSet" | "ReplicaSet" | "Job" | "CronJob" => {
            match crate::diagnose::workload_pods(sc, kind, name).await {
                Ok((_, pods)) => pod_rows(&pods, &mut out),
                Err(e) => out.push(format!("pods: {e}")),
            }
            if kind == "Deployment" {
                match crate::diagnose::owned::<ReplicaSet>(&client, &ns, "Deployment", name).await {
                    Ok(rss) => {
                        for rs in rss.iter().take(RELATED_ROWS) {
                            let rev = rs
                                .metadata
                                .annotations
                                .as_ref()
                                .and_then(|a| a.get("deployment.kubernetes.io/revision"))
                                .map_or("?", String::as_str);
                            let images: Vec<&str> = rs
                                .spec
                                .iter()
                                .flat_map(|s| s.template.iter())
                                .flat_map(|t| t.spec.iter())
                                .flat_map(|s| s.containers.iter())
                                .map(|c| c.image.as_deref().unwrap_or("?"))
                                .collect();
                            let st = rs.status.as_ref();
                            out.push(format!(
                                "replicaset {} (revision {rev}): {}/{} ready, images {}",
                                rs.metadata.name.as_deref().unwrap_or("?"),
                                st.and_then(|s| s.ready_replicas).unwrap_or(0),
                                rs.spec.as_ref().and_then(|s| s.replicas).unwrap_or(0),
                                images.join(", ")
                            ));
                        }
                    }
                    Err(e) => out.push(format!("replicasets: {e}")),
                }
            }
            if kind == "CronJob" {
                match crate::diagnose::owned::<Job>(&client, &ns, "CronJob", name).await {
                    Ok(jobs) => {
                        for j in jobs.iter().take(RELATED_ROWS) {
                            let st = j.status.as_ref();
                            out.push(format!(
                                "job {}: {} succeeded, {} failed",
                                j.metadata.name.as_deref().unwrap_or("?"),
                                st.and_then(|s| s.succeeded).unwrap_or(0),
                                st.and_then(|s| s.failed).unwrap_or(0)
                            ));
                        }
                    }
                    Err(e) => out.push(format!("jobs: {e}")),
                }
            }
        }
        "Pod" => {
            let mut chain = vec![format!("Pod/{name}")];
            let mut owner = obj.pointer("/metadata/ownerReferences/0").cloned();
            for _ in 0..3 {
                let Some(o) = owner.take() else { break };
                let (ok, on) = (
                    o["kind"].as_str().unwrap_or("?").to_owned(),
                    o["name"].as_str().unwrap_or("?").to_owned(),
                );
                chain.push(format!("{ok}/{on}"));
                if ok == "ReplicaSet" {
                    owner = Api::<ReplicaSet>::namespaced(client.clone(), &ns)
                        .get_opt(&on)
                        .await
                        .ok()
                        .flatten()
                        .and_then(|rs| {
                            rs.metadata
                                .owner_references
                                .and_then(|r| r.into_iter().next())
                        })
                        .map(|r| json!({"kind": r.kind, "name": r.name}));
                }
            }
            chain.reverse();
            out.push(format!("owner chain: {}", chain.join(" → ")));
            if let Some(node) = obj.pointer("/spec/nodeName").and_then(Value::as_str) {
                match Api::<Node>::all(client).get(node).await {
                    Ok(n) => out.push(format!(
                        "node {node}: {}",
                        rows::node_row(&n)["status"].as_str().unwrap_or("?")
                    )),
                    Err(e) => out.push(failed(&format!("node {node}"), &e)),
                }
            }
        }
        "PersistentVolumeClaim" => {
            if let Some(pv) = obj
                .pointer("/spec/volumeName")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
            {
                match Api::<PersistentVolume>::all(client.clone()).get(pv).await {
                    Ok(v) => out.push(format!(
                        "volume {pv}: {}, capacity {}, reclaim {}",
                        v.status
                            .as_ref()
                            .and_then(|s| s.phase.as_deref())
                            .unwrap_or("?"),
                        v.spec
                            .as_ref()
                            .and_then(|s| s.capacity.as_ref())
                            .and_then(|c| c.get("storage"))
                            .map_or("?", |q| q.0.as_str()),
                        v.spec
                            .as_ref()
                            .and_then(|s| s.persistent_volume_reclaim_policy.as_deref())
                            .unwrap_or("?")
                    )),
                    Err(e) => out.push(failed(&format!("PersistentVolume {pv}"), &e)),
                }
            } else {
                out.push("volume: not bound yet".into());
            }
            if let Some(sc_name) = obj
                .pointer("/spec/storageClassName")
                .and_then(Value::as_str)
            {
                match Api::<StorageClass>::all(client).get_opt(sc_name).await {
                    Ok(Some(c)) => out.push(format!(
                        "storageclass {sc_name}: provisioner {}, binding {}",
                        c.provisioner,
                        c.volume_binding_mode.as_deref().unwrap_or("Immediate")
                    )),
                    Ok(None) => out.push(format!("storageclass {sc_name}: does not exist")),
                    Err(e) => out.push(failed(&format!("StorageClass {sc_name}"), &e)),
                }
            }
        }
        _ => {}
    }
    out
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

/// Workloads keep their pod template deep in the object, where the depth limit hides it: add
/// its containers (already redacted) at the top level of the summary.
fn with_template_containers(mut summary: Value, cleaned: &Value) -> Value {
    const FIELDS: &[&str] = &[
        "name",
        "image",
        "command",
        "args",
        "ports",
        "env",
        "envFrom",
        "resources",
        "livenessProbe",
        "readinessProbe",
        "startupProbe",
    ];
    let Some(spec) = [
        "/spec/template/spec",
        "/spec/jobTemplate/spec/template/spec",
    ]
    .iter()
    .find_map(|p| cleaned.pointer(p)) else {
        return summary;
    };
    for key in ["initContainers", "containers"] {
        if let Some(cs) = spec.get(key).and_then(Value::as_array) {
            let picked: Vec<Value> = cs
                .iter()
                .map(|c| {
                    Value::Object(
                        FIELDS
                            .iter()
                            .filter_map(|f| c.get(*f).map(|v| ((*f).to_owned(), v.clone())))
                            .collect(),
                    )
                })
                .collect();
            summary[key] = Value::Array(picked);
        }
    }
    summary
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
    if let Some(bad) = types
        .iter()
        .find(|t| !matches!(t.as_str(), "Normal" | "Warning"))
    {
        return Err(Error::InvalidInput(format!(
            "event type {bad:?} is not valid; use Normal and/or Warning"
        )));
    }
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
    if events.is_empty() {
        ensure_namespace(&sc).await?;
    }
    // One row per cause across objects, unless the caller asked about one object.
    let rows = group_events(
        ctx,
        &events,
        now,
        sc.namespace.is_none(),
        input.involved_name.is_none(),
    );
    let total = rows.len();
    let occurrences: i64 = rows.iter().filter_map(|r| r["count"].as_i64()).sum();
    let limit = bounded("limit", input.limit, DEFAULT_LIMIT, MAX_LIMIT)? as usize;
    let mut e = envelope(
        &sc,
        format!(
            "{total} event groups ({} occurrences) of type {} in the last {}.",
            human_count(occurrences),
            types.join("/"),
            input.since.as_deref().unwrap_or("1h")
        ),
    );
    e.columns = if sc.namespace.is_none() {
        vec![
            "ns",
            "type",
            "reason",
            "objects",
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
            "objects",
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

/// Group events by (namespace, type, reason, message), warnings first, then most recent.
/// With `across_objects`, events that differ only in the object they are about (one root cause
/// on many pods) share a row that counts the objects and names up to three of them.
pub fn group_events(
    ctx: &Ctx,
    events: &[Event],
    now: jiff::Timestamp,
    with_ns: bool,
    across_objects: bool,
) -> Vec<Value> {
    #[derive(Default)]
    struct Group {
        count: i32,
        first: Option<jiff::Timestamp>,
        last: Option<jiff::Timestamp>,
        objects: BTreeSet<String>,
    }
    // (ns, type, reason, kind, object or "", message)
    let mut groups: HashMap<(String, String, String, String, String, String), Group> =
        HashMap::new();
    for ev in events {
        let kind = ev
            .involved_object
            .kind
            .clone()
            .unwrap_or_else(|| "?".into());
        let name = ev
            .involved_object
            .name
            .clone()
            .unwrap_or_else(|| "?".into());
        let mut msg = strip_uids(&ctx.redactor.text(ev.message.as_deref().unwrap_or("")));
        if across_objects && name.len() >= 3 {
            msg = msg.replace(&name, &format!("<{}>", kind.to_ascii_lowercase()));
        }
        let key = (
            ev.metadata.namespace.clone().unwrap_or_default(),
            ev.type_.clone().unwrap_or_default(),
            ev.reason.clone().unwrap_or_default(),
            kind.clone(),
            if across_objects {
                String::new()
            } else {
                name.clone()
            },
            msg,
        );
        let t = k8s_mcp_diagnose::rules::last_seen(ev);
        let first = ev.first_timestamp.as_ref().map(|t| t.0).or(t);
        let g = groups.entry(key).or_default();
        g.count += k8s_mcp_diagnose::rules::count(ev);
        g.first = g.first.min(first).or(first);
        g.last = g.last.max(t);
        g.objects.insert(format!("{kind}/{name}"));
    }
    let mut rows: Vec<_> = groups.into_iter().collect();
    rows.sort_by(|(a, ga), (b, gb)| {
        (a.1 != "Warning", std::cmp::Reverse(ga.last), &ga.objects).cmp(&(
            b.1 != "Warning",
            std::cmp::Reverse(gb.last),
            &gb.objects,
        ))
    });
    rows.into_iter()
        .map(|((ns, ty, reason, _, _, msg), g)| {
            let mut object = g.objects.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
            if g.objects.len() > 3 {
                let _ = write!(object, " (+{} more)", g.objects.len() - 3);
            }
            let mut r = json!({
                "type": ty, "reason": reason, "objects": g.objects.len(), "object": object, "count": g.count,
                "first_seen": g.first.map(|t| age(now, t)), "last_seen": g.last.map(|t| age(now, t)),
                "message": truncate(&msg, 300),
            });
            if with_ns {
                r["ns"] = json!(ns);
            }
            r
        })
        .collect()
}

/// `950`, `12.3k`, `1.1M`.
fn human_count(n: i64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let f = n as f64;
    match n {
        n if n >= 1_000_000 => format!("{:.1}M", f / 1e6),
        n if n >= 10_000 => format!("{:.1}k", f / 1e3),
        n => n.to_string(),
    }
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
        lines: group_events(ctx, events, now, false, false)
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

/// The APIService that serves `metrics.k8s.io`.
const METRICS_APISERVICE: &str = "v1beta1.metrics.k8s.io";
const CHECK_METRICS_SERVER: &str = "Check it with diagnose_workload kind=Deployment name=metrics-server namespace=kube-system.";

/// An aggregated API, by its APIService's `Available` condition (riseno/k8s-mcp#76).
enum Aggregated {
    Missing,
    Available,
    /// `reason: message` of the condition.
    Unavailable(String),
}

/// The state of APIService `name`; `None` when it cannot be read (RBAC).
async fn apiservice(client: &kube::Client, name: &str) -> Option<Aggregated> {
    let svc = Api::<APIService>::all(client.clone())
        .get_opt(name)
        .await
        .ok()?;
    let Some(svc) = svc else {
        return Some(Aggregated::Missing);
    };
    let available = svc
        .status
        .and_then(|s| s.conditions)
        .into_iter()
        .flatten()
        .find(|c| c.type_ == "Available");
    Some(match available {
        Some(c) if c.status == "True" => Aggregated::Available,
        Some(c) => Aggregated::Unavailable(truncate(
            &format!(
                "{}: {}",
                c.reason.as_deref().unwrap_or("-"),
                c.message.as_deref().unwrap_or("")
            ),
            200,
        )),
        None => Aggregated::Unavailable("no Available condition yet".into()),
    })
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
        return Err(Error::Unavailable(
            match apiservice(&sc.target.client, METRICS_APISERVICE).await {
                Some(Aggregated::Missing) => "metrics.k8s.io is not available: metrics-server is not installed in this cluster, so live CPU/memory usage cannot be read. Install metrics-server, or use get_resource to see requests/limits.".into(),
                Some(Aggregated::Unavailable(why)) => format!("metrics-server is installed but unavailable (APIService {METRICS_APISERVICE}: {why}), so live CPU/memory usage cannot be read. {CHECK_METRICS_SERVER}"),
                Some(Aggregated::Available) => "metrics.k8s.io did not answer discovery although its APIService reports Available; retry in a minute.".into(),
                None => format!("metrics.k8s.io is not available: metrics-server is not installed or not running (APIService {METRICS_APISERVICE} could not be read to tell which), so live CPU/memory usage cannot be read. {CHECK_METRICS_SERVER}"),
            },
        ));
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
    if metrics.is_empty() && !nodes_mode {
        ensure_namespace(&sc).await?;
    }
    let limit = bounded("limit", input.limit, 20, MAX_LIMIT)? as usize;
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

/// (cpu request, cpu limit, mem request, mem limit) for a pod. Requests add up what is set; a
/// limit is `None` (unbounded) as soon as one container has none, since usage covers them all.
fn pod_resources(p: &Pod) -> (Option<i64>, Option<i64>, Option<i64>, Option<i64>) {
    let containers: Vec<&k8s_openapi::api::core::v1::Container> =
        p.spec.iter().flat_map(|s| &s.containers).collect();
    let value =
        |c: &k8s_openapi::api::core::v1::Container, limit: bool, key: &str| -> Option<i64> {
            let r = c.resources.as_ref()?;
            let q = if limit {
                r.limits.as_ref()
            } else {
                r.requests.as_ref()
            }?
            .get(key)?;
            if key == "cpu" {
                cpu_millis(&q.0)
            } else {
                bytes(&q.0)
            }
        };
    let requests = |key: &str| {
        let set: Vec<i64> = containers
            .iter()
            .filter_map(|c| value(c, false, key))
            .collect();
        (!set.is_empty()).then(|| set.iter().sum())
    };
    let limits = |key: &str| {
        containers
            .iter()
            .map(|c| value(c, true, key))
            .sum::<Option<i64>>()
    };
    (
        requests("cpu"),
        limits("cpu"),
        requests("memory"),
        limits("memory"),
    )
}

// ---------------------------------------------------------------------------------------
// check_permissions

/// Inputs for `check_permissions`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckPermissionsInput {
    /// Namespace to check (default: the context's namespace).
    pub namespace: Option<String>,
    /// Extra resources to check, e.g. `["deployments.apps", "pods/log", "pods/exec"]`: `get` for `*/log`, `create` for `*/exec`, `*/attach`, `*/portforward` and `*/eviction`, else `get` and `list`.
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
    let extra = input.verbs_for.unwrap_or_default();
    if extra.len() > 10 {
        return Err(Error::InvalidInput(format!(
            "verbs_for takes at most 10 resources, got {}",
            extra.len()
        )));
    }
    for r in extra {
        let (res, group) = r
            .split_once('.')
            .map_or((r.clone(), String::new()), |(a, b)| {
                (a.to_owned(), b.to_owned())
            });
        for verb in verbs_for(&res) {
            checks.push((
                format!("{verb} {r}"),
                verb,
                group.clone(),
                res.clone(),
                true,
            ));
        }
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

/// The verbs that answer "can I use this resource?": subresources are not listed.
fn verbs_for(resource: &str) -> &'static [&'static str] {
    match resource.split_once('/').map(|(_, sub)| sub) {
        Some("log") => &["get"],
        Some("exec" | "attach" | "portforward" | "eviction") => &["create"],
        _ => &["get", "list"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// riseno/k8s-mcp#17: subresources are checked with the verb that governs them.
    #[test]
    fn verbs_match_the_resource() {
        assert_eq!(verbs_for("pods/log"), ["get"]);
        assert_eq!(verbs_for("pods/exec"), ["create"]);
        assert_eq!(verbs_for("pods/eviction"), ["create"]);
        assert_eq!(verbs_for("deployments"), ["get", "list"]);
    }

    /// riseno/k8s-mcp#10: a limit set on only some containers does not bound the pod.
    #[test]
    fn pod_limit_is_unbounded_when_a_container_has_none() {
        let p: Pod = serde_json::from_value(json!({
            "metadata": {"name": "anetd"},
            "spec": {"containers": [
                {"name": "a", "image": "i", "resources": {"requests": {"cpu": "100m", "memory": "64Mi"}, "limits": {"cpu": "200m", "memory": "65Mi"}}},
                {"name": "b", "image": "i", "resources": {"requests": {"memory": "32Mi"}}}
            ]}
        }))
        .unwrap();
        let (cpu_req, cpu_lim, mem_req, mem_lim) = pod_resources(&p);
        assert_eq!(
            (cpu_req, cpu_lim, mem_req, mem_lim),
            (Some(100), None, Some(100_663_296), None)
        );
        assert_eq!(pct(430 << 20, mem_lim), None);

        let all_set: Pod = serde_json::from_value(json!({
            "metadata": {"name": "x"},
            "spec": {"containers": [
                {"name": "a", "image": "i", "resources": {"limits": {"memory": "64Mi"}}},
                {"name": "b", "image": "i", "resources": {"limits": {"memory": "64Mi"}}}
            ]}
        }))
        .unwrap();
        assert_eq!(pod_resources(&all_set).3, Some(128 << 20));
    }
}
