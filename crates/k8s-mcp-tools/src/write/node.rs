//! `cordon_node` / `uncordon_node`: mark a node (un)schedulable.

use k8s_mcp_core::finding::NextCall;
use k8s_mcp_core::{Error, Result};
use k8s_openapi::api::core::v1::{Node, Pod};
use kube::api::{Api, ListParams, Patch};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use super::{Change, check_confirm, run, state};
use crate::common::{check_name, scope};
use crate::{Ctx, Envelope};

/// Inputs for `cordon_node` and `uncordon_node`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeWriteInput {
    /// Node name.
    pub name: String,
    /// Kubeconfig context.
    pub context: Option<String>,
    /// `true` (default): a server-side dry run that returns the plan and a `confirm_token`.
    /// `false`: make the change; needs that `confirm_token`.
    pub dry_run: Option<bool>,
    /// The token from the plan, with `dry_run: false`.
    pub confirm_token: Option<String>,
}

/// Stop scheduling new pods on a node; the ones there keep running.
pub async fn cordon_node(ctx: &Ctx, input: NodeWriteInput) -> Result<Envelope> {
    set_unschedulable(ctx, input, true).await
}

/// Let new pods be scheduled on a node again.
pub async fn uncordon_node(ctx: &Ctx, input: NodeWriteInput) -> Result<Envelope> {
    set_unschedulable(ctx, input, false).await
}

/// A node write affects every namespace, so a server limited to some refuses it.
pub(crate) fn check_node_write(ctx: &Ctx, tool: &str) -> Result<()> {
    if ctx.policy.namespaces.is_empty() {
        Ok(())
    } else {
        Err(Error::Forbidden(format!(
            "{tool} changes a node, which affects pods in every namespace: k8s-mcp refuses node writes while --namespaces limits it to {}",
            ctx.policy.describe_namespaces()
        )))
    }
}

async fn set_unschedulable(ctx: &Ctx, input: NodeWriteInput, cordon: bool) -> Result<Envelope> {
    let tool = if cordon {
        "cordon_node"
    } else {
        "uncordon_node"
    };
    check_confirm(tool, input.dry_run, input.confirm_token.as_deref())?;
    check_name("node", &input.name)?;
    check_node_write(ctx, tool)?;
    let sc = scope(ctx, input.context.as_deref(), None, true).await?;
    let name = input.name.as_str();
    let api: Api<Node> = Api::all(sc.target.writer.clone());
    let node = api
        .get(name)
        .await
        .map_err(|e| Error::kube(format!("get node {name}"), &e))?;
    let rv = node.metadata.resource_version.clone();
    let was = node
        .spec
        .as_ref()
        .and_then(|s| s.unschedulable)
        .unwrap_or(false);
    let mut lines = vec![if was == cordon {
        format!("spec.unschedulable: {was} (already; nothing changes)")
    } else {
        format!("spec.unschedulable: {was} → {cordon}")
    }];
    if cordon {
        let pods = Api::<Pod>::all(sc.target.writer.clone())
            .list_metadata(&ListParams::default().fields(&format!("spec.nodeName={name}")))
            .await
            .map(|l| l.items.len());
        lines.push(match pods {
            Ok(n) => format!(
                "its {n} pod(s) keep running; no new pod is scheduled on it (drain_node evicts them)"
            ),
            Err(_) => "its pods keep running; no new pod is scheduled on it".into(),
        });
    } else {
        lines.push("the scheduler may place new pods on it again".into());
    }
    let args = json!({"name": name});
    let targets = [(format!("Node/{name}"), Some(state(&node)))];
    let api = &api;
    run(
        ctx,
        &sc,
        tool,
        args,
        &targets,
        (input.dry_run, input.confirm_token.as_deref()),
        |mode| async move {
            let patch = json!({
                "metadata": {"resourceVersion": rv},
                "spec": {"unschedulable": cordon},
            });
            api.patch(name, &mode.patch(), &Patch::Merge(&patch))
                .await
                .map_err(|e| Error::kube(format!("{tool} {name}"), &e))?;
            Ok(Change {
                summary: format!("{} node {name}", if cordon { "cordon" } else { "uncordon" }),
                lines,
                next: vec![NextCall::new(
                    "diagnose_node",
                    json!({"name": name}),
                    "check the node",
                )],
            })
        },
    )
    .await
}
