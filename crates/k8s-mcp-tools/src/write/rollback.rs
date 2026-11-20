//! `rollback_workload`: put a Deployment back on an earlier revision's pod template, as
//! `kubectl rollout undo` does.

use k8s_mcp_core::finding::NextCall;
use k8s_mcp_core::{Error, Result};
use k8s_openapi::api::apps::v1::Deployment;
use kube::api::Api;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Change, check_confirm, run, state};
use crate::changes::{revisions, template_diff};
use crate::common::{check_name, scope};
use crate::{Ctx, Envelope};

const REVISION: &str = "deployment.kubernetes.io/revision";

/// Inputs for `rollback_workload`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RollbackWorkloadInput {
    /// Deployment name.
    pub name: String,
    /// Revision to go back to (default: the one before the current; rollout_history lists them).
    pub to_revision: Option<i64>,
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

/// Roll a Deployment back to an earlier revision's pod template.
pub async fn rollback_workload(ctx: &Ctx, input: RollbackWorkloadInput) -> Result<Envelope> {
    check_confirm(
        "rollback_workload",
        input.dry_run,
        input.confirm_token.as_deref(),
    )?;
    check_name("deployment", &input.name)?;
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
    let client = sc.target.writer.clone();
    let api: Api<Deployment> = Api::namespaced(client.clone(), &ns);
    let mut dep = api
        .get(name)
        .await
        .map_err(|e| Error::kube(format!("get Deployment {ns}/{name}"), &e))?;
    let dep_state = state(&dep);
    let spec = dep
        .spec
        .as_mut()
        .ok_or_else(|| Error::Api(format!("Deployment {ns}/{name} has no spec")))?;
    if spec.paused == Some(true) {
        return Err(Error::InvalidInput(format!(
            "Deployment {ns}/{name} is paused: a rollback would not roll out. Resume it first (`kubectl rollout resume`), then plan the rollback again."
        )));
    }
    let current: i64 = dep
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(REVISION))
        .and_then(|r| r.parse().ok())
        .unwrap_or(0);
    let revs = revisions(&client, &ns, "Deployment", name).await?;
    let target = match input.to_revision {
        Some(n) => revs.iter().find(|r| r.number == n).ok_or_else(|| {
            Error::NotFound(format!(
                "Deployment {ns}/{name} has no revision {n}: rollout_history lists its revisions"
            ))
        })?,
        None => revs.iter().find(|r| r.number < current).ok_or_else(|| {
            Error::InvalidInput(format!(
                "Deployment {ns}/{name} has no revision before {current} to roll back to (its ReplicaSets may have been pruned by revisionHistoryLimit)"
            ))
        })?,
    };
    if target.number == current {
        return Err(Error::InvalidInput(format!(
            "Deployment {ns}/{name} is already at revision {current}"
        )));
    }
    let mut template = target.template.clone();
    // Each ReplicaSet's own label: the Deployment controller adds it back.
    if let Some(labels) = template.metadata.as_mut().and_then(|m| m.labels.as_mut()) {
        labels.remove("pod-template-hash");
    }
    // The summary covers the common fields; the paths of every changed field (values left out:
    // env values may be credentials) make sure nothing else changes unseen.
    let mut fields = Vec::new();
    changed_paths(
        &serde_json::to_value(&spec.template).unwrap_or_default(),
        &serde_json::to_value(&template).unwrap_or_default(),
        "",
        &mut fields,
    );
    if fields.is_empty() {
        return Err(Error::InvalidInput(format!(
            "revision {} of Deployment {ns}/{name} has the same pod template as the current one: nothing would change",
            target.number
        )));
    }
    let mut lines: Vec<String> = template_diff(&spec.template, &template)
        .into_iter()
        .filter(|l| l != "no pod template change")
        .collect();
    let more = fields.len().saturating_sub(MAX_FIELDS);
    fields.truncate(MAX_FIELDS);
    lines.push(format!(
        "changed fields: {}{}",
        fields.join(", "),
        if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        }
    ));
    lines.push(
        "the Deployment rolls out the revision's pod template following its update strategy".into(),
    );
    spec.template = template;
    let to = target.number;
    let args = json!({"name": name, "namespace": ns, "to_revision": to});
    // The source revision too: a confirm after it was edited would apply another template.
    let targets = [
        (format!("Deployment/{ns}/{name}"), Some(dep_state)),
        target.source.clone(),
    ];
    let (api, ns_ref) = (&api, ns.as_str());
    run(
        ctx,
        &sc,
        "rollback_workload",
        args,
        &targets,
        (input.dry_run, input.confirm_token.as_deref()),
        |mode| async move {
            // A replace carries the resourceVersion it read: the API server refuses it (409)
            // if the Deployment changed since.
            api.replace(name, &mode.post(), &dep)
                .await
                .map_err(|e| Error::kube(format!("roll back Deployment {ns_ref}/{name}"), &e))?;
            Ok(Change {
                summary: format!(
                    "roll back Deployment {ns_ref}/{name} from revision {current} to {to}"
                ),
                lines,
                next: vec![
                    NextCall::new(
                        "diagnose_workload",
                        json!({"kind": "Deployment", "name": name, "namespace": ns_ref}),
                        "follow the rollout",
                    ),
                    NextCall::new(
                        "rollout_history",
                        json!({"kind": "Deployment", "name": name, "namespace": ns_ref}),
                        "see the revisions",
                    ),
                ],
            })
        },
    )
    .await
}

/// Changed-field paths listed in a rollback plan.
const MAX_FIELDS: usize = 30;

/// Paths of the fields that differ between two JSON values, e.g.
/// `spec.containers[0].securityContext.privileged`.
fn changed_paths(old: &Value, new: &Value, path: &str, out: &mut Vec<String>) {
    match (old, new) {
        (Value::Object(before), Value::Object(after)) => {
            let keys: std::collections::BTreeSet<&String> =
                before.keys().chain(after.keys()).collect();
            for key in keys {
                let at = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                changed_paths(
                    before.get(key).unwrap_or(&Value::Null),
                    after.get(key).unwrap_or(&Value::Null),
                    &at,
                    out,
                );
            }
        }
        (Value::Array(before), Value::Array(after)) if before.len() == after.len() => {
            for (i, (was, now)) in before.iter().zip(after).enumerate() {
                changed_paths(was, now, &format!("{path}[{i}]"), out);
            }
        }
        _ if old != new => out.push(path.to_owned()),
        _ => {}
    }
}
