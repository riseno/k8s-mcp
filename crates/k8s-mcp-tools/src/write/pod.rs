//! `delete_pod`: delete one pod so its controller replaces it.

use k8s_mcp_core::finding::NextCall;
use k8s_mcp_core::{Error, Result};
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, Preconditions};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use super::{Change, check_confirm, run};
use crate::common::{check_name, scope};
use crate::{Ctx, Envelope};

/// Inputs for `delete_pod`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeletePodInput {
    /// Pod name.
    pub name: String,
    /// Namespace (default: the context's namespace).
    pub namespace: Option<String>,
    /// Kubeconfig context.
    pub context: Option<String>,
    /// Allow deleting a pod that no controller recreates (default false).
    pub allow_unowned: Option<bool>,
    /// `true` (default): a server-side dry run that returns the plan and a `confirm_token`.
    /// `false`: make the change; needs that `confirm_token`.
    pub dry_run: Option<bool>,
    /// The token from the plan, with `dry_run: false`.
    pub confirm_token: Option<String>,
}

/// Delete a pod; its controller (ReplicaSet, StatefulSet, DaemonSet, Job) creates a new one.
pub async fn delete_pod(ctx: &Ctx, input: DeletePodInput) -> Result<Envelope> {
    check_confirm("delete_pod", input.dry_run, input.confirm_token.as_deref())?;
    check_name("pod", &input.name)?;
    let sc = scope(
        ctx,
        input.context.as_deref(),
        input.namespace.as_deref(),
        false,
    )
    .await?;
    let ns = sc.namespace.clone().unwrap_or_default();
    ctx.policy.check_write_namespace(&ns)?;
    let name = input.name.as_str();
    let api: Api<Pod> = Api::namespaced(sc.target.writer.clone(), &ns);
    let pod = api
        .get(name)
        .await
        .map_err(|e| Error::kube(format!("get pod {ns}/{name}"), &e))?;
    let meta = &pod.metadata;
    if let Some(at) = &meta.deletion_timestamp {
        return Err(Error::InvalidInput(format!(
            "pod {ns}/{name} is already being deleted (since {}): it goes away once its containers stop or its grace period ends, so there is nothing to do",
            at.0
        )));
    }
    if meta
        .annotations
        .as_ref()
        .is_some_and(|a| a.contains_key("kubernetes.io/config.mirror"))
    {
        return Err(Error::InvalidInput(format!(
            "pod {ns}/{name} is a static pod's mirror: the kubelet recreates it from the node's manifest, so deleting it changes nothing. Fix the manifest on the node instead."
        )));
    }
    let owner = meta
        .owner_references
        .iter()
        .flatten()
        .find(|o| o.controller == Some(true))
        .or_else(|| meta.owner_references.iter().flatten().next());
    let allow_unowned = input.allow_unowned.unwrap_or(false);
    let replacement = match owner {
        Some(o) => format!("its {} {} creates a replacement", o.kind, o.name),
        None if allow_unowned => {
            "it has no owner: nothing recreates it, it is gone for good".into()
        }
        None => {
            return Err(Error::InvalidInput(format!(
                "pod {ns}/{name} has no owner, so nothing recreates it once deleted. If losing it is intended, pass allow_unowned=true."
            )));
        }
    };
    let grace = pod
        .spec
        .as_ref()
        .and_then(|s| s.termination_grace_period_seconds)
        .unwrap_or(30);
    let preconditions = Preconditions {
        resource_version: meta.resource_version.clone(),
        uid: meta.uid.clone(),
    };
    let args = json!({"name": name, "namespace": ns, "allow_unowned": allow_unowned});
    let targets = [(format!("Pod/{ns}/{name}"), meta.resource_version.clone())];
    let (api, ns_ref) = (&api, ns.as_str());
    run(
        ctx,
        &sc,
        "delete_pod",
        args,
        &targets,
        (input.dry_run, input.confirm_token.as_deref()),
        |mode| async move {
            let mut params = mode.delete();
            params.preconditions = Some(preconditions);
            api.delete(name, &params)
                .await
                .map_err(|e| Error::kube(format!("delete pod {ns_ref}/{name}"), &e))?;
            Ok(Change {
                summary: format!("delete pod {ns_ref}/{name}"),
                lines: vec![
                    format!("pod {ns_ref}/{name} stops (grace period {grace}s)"),
                    replacement,
                ],
                next: vec![NextCall::new(
                    "list_resources",
                    json!({"kind": "Pod", "namespace": ns_ref}),
                    "see the replacement pod",
                )],
            })
        },
    )
    .await
}
