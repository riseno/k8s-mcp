//! `scale_workload`: change the replica count through the scale subresource.

use k8s_mcp_core::finding::NextCall;
use k8s_mcp_core::{Error, Result};
use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;
use kube::api::{Api, DynamicObject, ListParams, Patch};
use kube::core::{ApiResource, GroupVersionKind};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use super::{Change, check_confirm, run, state, writable_kind};
use crate::common::{check_name, scope};
use crate::{Ctx, Envelope};

/// Inputs for `scale_workload`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScaleWorkloadInput {
    /// `Deployment`, `StatefulSet` or `ReplicaSet`.
    pub kind: String,
    /// Workload name.
    pub name: String,
    /// The new replica count.
    pub replicas: u32,
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

/// Set a workload's replicas.
pub async fn scale_workload(ctx: &Ctx, input: ScaleWorkloadInput) -> Result<Envelope> {
    check_confirm(
        "scale_workload",
        input.dry_run,
        input.confirm_token.as_deref(),
    )?;
    check_name("workload", &input.name)?;
    let kind = writable_kind(
        "scale_workload",
        &input.kind,
        &["Deployment", "StatefulSet", "ReplicaSet"],
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
    let name = input.name.as_str();
    let ar = ApiResource::from_gvk(&GroupVersionKind::gvk("apps", "v1", kind));
    let api: Api<DynamicObject> = Api::namespaced_with(sc.target.writer.clone(), &ns, &ar);
    let scale = api
        .get_scale(name)
        .await
        .map_err(|e| Error::kube(format!("get the scale of {kind} {ns}/{name}"), &e))?;
    let rv = scale.metadata.resource_version.clone();
    let current = scale.spec.as_ref().and_then(|s| s.replicas).unwrap_or(0);
    let mut lines = vec![format!("spec.replicas: {current} → {}", input.replicas)];
    if input.replicas == 0 {
        lines.push("scaled to zero: it serves nothing until it is scaled up again".into());
    }
    // An HPA owns the replica count and would undo the change on its next sync.
    let hpas = Api::<HorizontalPodAutoscaler>::namespaced(sc.target.writer.clone(), &ns)
        .list(&ListParams::default())
        .await
        .map(|l| l.items)
        .unwrap_or_default();
    for h in hpas.iter().filter(|h| {
        h.spec
            .as_ref()
            .is_some_and(|s| s.scale_target_ref.kind == kind && s.scale_target_ref.name == name)
    }) {
        let spec = h.spec.as_ref();
        lines.push(format!(
            "HorizontalPodAutoscaler {} manages these replicas ({}–{}) and will set them back: change its minReplicas/maxReplicas instead",
            h.metadata.name.as_deref().unwrap_or("?"),
            spec.and_then(|s| s.min_replicas).unwrap_or(1),
            spec.map_or(0, |s| s.max_replicas)
        ));
    }
    let args = json!({"kind": kind, "name": name, "namespace": ns, "replicas": input.replicas});
    let targets = [(format!("{kind}/{ns}/{name}"), Some(state(&scale)))];
    let (api, ns_ref) = (&api, ns.as_str());
    run(
        ctx,
        &sc,
        "scale_workload",
        args,
        &targets,
        (input.dry_run, input.confirm_token.as_deref()),
        |mode| async move {
            let patch = json!({
                "metadata": {"resourceVersion": rv},
                "spec": {"replicas": input.replicas},
            });
            api.patch_scale(name, &mode.patch(), &Patch::Merge(&patch))
                .await
                .map_err(|e| Error::kube(format!("scale {kind} {ns_ref}/{name}"), &e))?;
            Ok(Change {
                summary: format!(
                    "scale {kind} {ns_ref}/{name} from {current} to {} replicas",
                    input.replicas
                ),
                lines,
                next: vec![NextCall::new(
                    "diagnose_workload",
                    json!({"kind": kind, "name": name, "namespace": ns_ref}),
                    "check the new replicas come up",
                )],
            })
        },
    )
    .await
}
