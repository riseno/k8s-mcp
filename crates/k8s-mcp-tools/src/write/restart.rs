//! `restart_workload`: a rolling restart, as `kubectl rollout restart` does it.

use k8s_mcp_core::finding::NextCall;
use k8s_mcp_core::{Error, Result};
use kube::api::{Api, DynamicObject, Patch};
use kube::core::{ApiResource, GroupVersionKind};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Change, check_confirm, run, writable_kind};
use crate::common::{check_name, scope};
use crate::{Ctx, Envelope};

const RESTARTED_AT: &str = "kubectl.kubernetes.io/restartedAt";

/// Inputs for `restart_workload`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RestartWorkloadInput {
    /// `Deployment`, `StatefulSet` or `DaemonSet`.
    pub kind: String,
    /// Workload name.
    pub name: String,
    /// Namespace (default: the context's namespace).
    pub namespace: Option<String>,
    /// Kubeconfig context.
    pub context: Option<String>,
    /// `true` (default): a server-side dry run that returns the plan and a `confirm_token`.
    /// `false`: make the change; needs that `confirm_token`.
    pub dry_run: Option<bool>,
    /// The token from the plan, with `dry_run: false`.
    pub confirm_token: Option<String>,
}

/// How the controller replaces the pods once the template changes.
fn impact(kind: &str, obj: &Value) -> String {
    let strategy = obj
        .pointer(if kind == "Deployment" {
            "/spec/strategy/type"
        } else {
            "/spec/updateStrategy/type"
        })
        .and_then(Value::as_str)
        .unwrap_or("RollingUpdate");
    let pods = match obj
        .pointer("/status/replicas")
        .or_else(|| obj.pointer("/status/currentNumberScheduled"))
    {
        Some(n) => format!("its {n} pod(s)"),
        None => "its pods".into(),
    };
    match strategy {
        "Recreate" => format!("{strategy}: all of {pods} stop, then new ones start (downtime)"),
        "OnDelete" => format!(
            "{strategy}: no pod restarts until it is deleted; delete_pod each pod to pick up the change"
        ),
        _ => format!(
            "{strategy}: {pods} are replaced a few at a time, as the update strategy allows"
        ),
    }
}

/// Rolling restart of a workload: a new `restartedAt` annotation on its pod template.
pub async fn restart_workload(ctx: &Ctx, input: RestartWorkloadInput) -> Result<Envelope> {
    check_confirm(
        "restart_workload",
        input.dry_run,
        input.confirm_token.as_deref(),
    )?;
    check_name("workload", &input.name)?;
    let kind = writable_kind(
        "restart_workload",
        &input.kind,
        &["Deployment", "StatefulSet", "DaemonSet"],
    )?;
    let sc = scope(
        ctx,
        input.context.as_deref(),
        input.namespace.as_deref(),
        false,
    )
    .await?;
    let ns = sc.namespace.clone().unwrap_or_default();
    ctx.policy.check_write_namespace(&ns)?;
    let ar = ApiResource::from_gvk(&GroupVersionKind::gvk("apps", "v1", kind));
    let api: Api<DynamicObject> = Api::namespaced_with(sc.target.client.clone(), &ns, &ar);
    let name = input.name.as_str();
    let obj = api
        .get(name)
        .await
        .map_err(|e| Error::kube(format!("get {kind} {ns}/{name}"), &e))?;
    let rv = obj.metadata.resource_version.clone();
    let data = serde_json::to_value(&obj).unwrap_or_default();
    let before = data
        .pointer("/spec/template/metadata/annotations")
        .and_then(|a| a.get(RESTARTED_AT))
        .and_then(Value::as_str)
        .unwrap_or("(none)")
        .to_owned();
    let args = json!({"kind": kind, "name": name, "namespace": ns});
    let targets = [(format!("{kind}/{ns}/{name}"), rv.clone())];
    let now = ctx.now().to_string();
    let (api, ns_ref) = (&api, ns.as_str());
    run(
        ctx,
        &sc,
        "restart_workload",
        args,
        &targets,
        (input.dry_run, input.confirm_token.as_deref()),
        |mode| async move {
            // The resourceVersion makes the API server refuse the patch (409) if the object
            // changed after it was read.
            let patch = json!({
                "metadata": {"resourceVersion": rv},
                "spec": {"template": {"metadata": {"annotations": {RESTARTED_AT: now}}}},
            });
            api.patch(name, &mode.patch(), &Patch::Merge(&patch))
                .await
                .map_err(|e| Error::kube(format!("restart {kind} {ns_ref}/{name}"), &e))?;
            Ok(Change {
                summary: format!("restart {kind} {ns_ref}/{name}"),
                lines: vec![
                    format!("spec.template.metadata.annotations[{RESTARTED_AT}]: {before} → {now}"),
                    impact(kind, &data),
                ],
                next: vec![NextCall::new(
                    "diagnose_workload",
                    json!({"kind": kind, "name": name, "namespace": ns_ref}),
                    "follow the rollout",
                )],
            })
        },
    )
    .await
}
