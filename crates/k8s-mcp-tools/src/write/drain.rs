//! `drain_node`: cordon a node and evict its pods through the Eviction API, which respects
//! PodDisruptionBudgets. It issues the evictions and reports each pod's outcome; it does not
//! wait for the pods to terminate (v0.4 decision 3).

use k8s_mcp_core::finding::NextCall;
use k8s_mcp_core::{Error, Result};
use k8s_openapi::api::core::v1::{Node, Pod};
use kube::api::{Api, ListParams, Patch};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use super::node::check_node_write;
use super::{Change, Mode, check_confirm, run, state};
use crate::common::{check_name, scope};
use crate::{Ctx, Envelope};

/// Inputs for `drain_node`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrainNodeInput {
    /// Node name.
    pub name: String,
    /// Kubeconfig context.
    pub context: Option<String>,
    /// Leave DaemonSet pods in place (default true); with false, a node running any refuses.
    pub ignore_daemonsets: Option<bool>,
    /// `true` (default): a server-side dry run of the cordon and every eviction, returning the
    /// plan (which pods a PodDisruptionBudget blocks) and a `confirm_token`.
    /// `false`: make the change; needs that `confirm_token`.
    pub dry_run: Option<bool>,
    /// The token from the plan, with `dry_run: false`.
    pub confirm_token: Option<String>,
}

/// A pod on the node and what the drain does with it.
struct Placed {
    namespace: String,
    name: String,
    /// The pod's [`state`] for the confirm token.
    state: String,
    /// `Err(why)` for a pod the drain leaves alone.
    action: std::result::Result<String, String>,
}

fn classify(p: &Pod, ignore_daemonsets: bool) -> Result<std::result::Result<String, String>> {
    let meta = &p.metadata;
    let id = format!(
        "{}/{}",
        meta.namespace.as_deref().unwrap_or(""),
        meta.name.as_deref().unwrap_or("")
    );
    let phase = p
        .status
        .as_ref()
        .and_then(|s| s.phase.as_deref())
        .unwrap_or("");
    if matches!(phase, "Succeeded" | "Failed") {
        return Ok(Err(format!("{phase}: nothing to evict")));
    }
    if meta
        .annotations
        .as_ref()
        .is_some_and(|a| a.contains_key("kubernetes.io/config.mirror"))
    {
        return Ok(Err("static pod: the kubelet keeps it on the node".into()));
    }
    let owner = meta
        .owner_references
        .iter()
        .flatten()
        .find(|o| o.controller == Some(true));
    let Some(owner) = owner else {
        return Ok(Err(
            "no owner: evicting it would lose it for good (delete_pod with allow_unowned=true if that is intended)".into(),
        ));
    };
    if owner.kind == "DaemonSet" {
        if ignore_daemonsets {
            return Ok(Err(format!(
                "DaemonSet {}: it runs on every node, so it stays",
                owner.name
            )));
        }
        return Err(Error::InvalidInput(format!(
            "pod {id} belongs to DaemonSet {}, which would recreate it on this node: pass ignore_daemonsets=true (the default) to drain around DaemonSet pods",
            owner.name
        )));
    }
    let empty_dir = p
        .spec
        .as_ref()
        .and_then(|s| s.volumes.as_ref())
        .is_some_and(|v| v.iter().any(|v| v.empty_dir.is_some()));
    Ok(Ok(format!(
        "{} {}{}",
        owner.kind,
        owner.name,
        if empty_dir {
            "; its emptyDir data is lost"
        } else {
            ""
        }
    )))
}

/// Cordon a node and evict its pods.
pub async fn drain_node(ctx: &Ctx, input: DrainNodeInput) -> Result<Envelope> {
    check_confirm("drain_node", input.dry_run, input.confirm_token.as_deref())?;
    check_name("node", &input.name)?;
    check_node_write(ctx, "drain_node")?;
    if !ctx.policy.deny_namespaces.is_empty() {
        return Err(Error::Forbidden(format!(
            "drain_node evicts pods in every namespace, and --deny-namespaces hides {} from k8s-mcp: drain the node with kubectl instead",
            ctx.policy.deny_namespaces.raw().join(",")
        )));
    }
    let sc = scope(ctx, input.context.as_deref(), None, true).await?;
    let name = input.name.as_str();
    let client = sc.target.writer.clone();
    let nodes: Api<Node> = Api::all(client.clone());
    let node = nodes
        .get(name)
        .await
        .map_err(|e| Error::kube(format!("get node {name}"), &e))?;
    let node_rv = node.metadata.resource_version.clone();
    let cordoned = node
        .spec
        .as_ref()
        .and_then(|s| s.unschedulable)
        .unwrap_or(false);
    let pods = Api::<Pod>::all(client.clone())
        .list(&ListParams::default().fields(&format!("spec.nodeName={name}")))
        .await
        .map_err(|e| Error::kube(format!("list the pods on node {name}"), &e))?
        .items;
    let ignore_daemonsets = input.ignore_daemonsets.unwrap_or(true);
    let mut placed = Vec::new();
    for p in &pods {
        placed.push(Placed {
            namespace: p.metadata.namespace.clone().unwrap_or_default(),
            name: p.metadata.name.clone().unwrap_or_default(),
            state: state(p),
            action: classify(p, ignore_daemonsets)?,
        });
    }
    placed.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
    let mut targets = vec![(format!("Node/{name}"), Some(state(&node)))];
    targets.extend(placed.iter().filter(|p| p.action.is_ok()).map(|p| {
        (
            format!("Pod/{}/{}", p.namespace, p.name),
            Some(p.state.clone()),
        )
    }));
    let args = json!({"name": name, "ignore_daemonsets": ignore_daemonsets});
    let (nodes, placed, client) = (&nodes, &placed, &client);
    run(
        ctx,
        &sc,
        "drain_node",
        args,
        &targets,
        (input.dry_run, input.confirm_token.as_deref()),
        |mode| async move {
            let mut lines = vec![if cordoned {
                "spec.unschedulable: true (already cordoned)".to_owned()
            } else {
                let patch = json!({"metadata": {"resourceVersion": node_rv}, "spec": {"unschedulable": true}});
                nodes
                    .patch(name, &mode.patch(), &Patch::Merge(&patch))
                    .await
                    .map_err(|e| Error::kube(format!("cordon node {name}"), &e))?;
                "spec.unschedulable: false → true".to_owned()
            }];
            let (mut evicted, mut blocked, mut skipped) = (0, 0, 0);
            // ponytail: one eviction at a time; parallel if nodes with hundreds of pods hit
            // the 30 s call budget.
            for p in placed {
                let id = format!("{}/{}", p.namespace, p.name);
                match &p.action {
                    Err(why) => {
                        skipped += 1;
                        lines.push(format!("skip {id}: {why}"));
                    }
                    Ok(owner) => match evict(client, mode, &p.namespace, &p.name).await {
                        Ok(()) => {
                            evicted += 1;
                            let verb = if mode == Mode::PLAN { "evict" } else { "evicted" };
                            lines.push(format!("{verb} {id} ({owner})"));
                        }
                        Err(why) => {
                            blocked += 1;
                            lines.push(format!("blocked {id} ({owner}): {why}"));
                        }
                    },
                }
            }
            if blocked > 0 && mode != Mode::PLAN {
                lines.push("the node stays cordoned: call drain_node again to retry the blocked pods once their budgets allow".into());
            }
            Ok(Change {
                summary: format!(
                    "drain node {name}: cordon it, evict {evicted} pod(s), {blocked} blocked, {skipped} left in place"
                ),
                lines,
                next: vec![NextCall::new(
                    "diagnose_node",
                    json!({"name": name}),
                    "see what still runs on the node",
                )],
            })
        },
    )
    .await
}

/// Evict one pod; `Err` says why it could not be evicted now.
async fn evict(
    client: &kube::Client,
    mode: Mode,
    ns: &str,
    name: &str,
) -> std::result::Result<(), String> {
    match Api::<Pod>::namespaced(client.clone(), ns)
        .evict(name, &mode.evict())
        .await
    {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(s)) if s.code == 429 => Err(format!(
            "a PodDisruptionBudget allows no disruption now ({})",
            s.message
        )),
        Err(e) => Err(Error::kube(format!("evict pod {ns}/{name}"), &e).to_string()),
    }
}
