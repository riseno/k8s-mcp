//! `autoscaling_status`: why the cluster is not scaling (or scaling oddly). Cloud-agnostic:
//! Karpenter (`karpenter.sh/v1`), the Cluster Autoscaler (its status ConfigMap) and HPAs.

use jiff::SignedDuration;
use k8s_mcp_core::{Error, Result};
use k8s_mcp_diagnose::{AutoscalingEvidence, Unavailable};
use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;
use k8s_openapi::api::core::v1::{ConfigMap, Event};
use kube::api::{Api, ApiResource, DynamicObject, ListParams};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::common::{envelope, list_scoped, retain_recent, scope, soft};
use crate::read::add_notes;
use crate::{Ctx, Envelope};

/// Where the Cluster Autoscaler writes its status.
const CA_NS: &str = "kube-system";
const CA_STATUS: &str = "cluster-autoscaler-status";

/// Inputs for `autoscaling_status`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AutoscalingStatusInput {
    /// Limit HPAs and scale-up events to one namespace (Karpenter and the Cluster Autoscaler
    /// are cluster-wide). Default: all allowed namespaces.
    pub namespace: Option<String>,
    /// Kubeconfig context.
    pub context: Option<String>,
}

fn karpenter(kind: &str, plural: &str) -> ApiResource {
    ApiResource {
        group: "karpenter.sh".into(),
        version: "v1".into(),
        api_version: "karpenter.sh/v1".into(),
        kind: kind.into(),
        plural: plural.into(),
    }
}

/// List a cluster-scoped Karpenter kind: `Ok(None)` when Karpenter is not installed.
async fn list_karpenter(
    client: &kube::Client,
    kind: &str,
    plural: &str,
) -> Result<Option<Vec<Value>>> {
    match Api::<DynamicObject>::all_with(client.clone(), &karpenter(kind, plural))
        .list(&ListParams::default())
        .await
    {
        Ok(l) => Ok(Some(
            l.items
                .into_iter()
                .filter_map(|o| serde_json::to_value(o).ok())
                .collect(),
        )),
        Err(e) => match Error::kube(format!("list Karpenter {plural}"), &e) {
            Error::NotFound(_) => Ok(None),
            other => Err(other),
        },
    }
}

/// Parse the CA status (YAML since CA 1.30); older plain-text statuses are not understood.
fn parse_ca_status(text: &str) -> Option<Value> {
    serde_saphyr::from_str::<Value>(text)
        .ok()
        .filter(|v| v.get("autoscalerStatus").is_some())
}

/// Why a read failed, in a few words for the summary (the unavailable note has the detail).
fn unread(e: &Error) -> String {
    if matches!(e, Error::Forbidden(_)) {
        "not checked (RBAC forbids reading it)".into()
    } else {
        "not checked (the read failed)".into()
    }
}

/// Report Karpenter, Cluster Autoscaler and HPA state, with findings.
pub async fn autoscaling_status(ctx: &Ctx, input: AutoscalingStatusInput) -> Result<Envelope> {
    let sc = scope(
        ctx,
        input.context.as_deref(),
        input.namespace.as_deref(),
        input.namespace.is_none(),
    )
    .await?;
    let now = ctx.now();
    let client = sc.target.client.clone();
    let mut un = Vec::new();
    let nodepools = list_karpenter(&client, "NodePool", "nodepools").await;
    let karpenter_unread = nodepools.as_ref().err().map(unread);
    let nodepools = soft(nodepools, "Karpenter NodePools", &mut un).flatten();
    let mut nodeclaims_unread = None;
    let nodeclaims = if nodepools.is_some() {
        let claims = list_karpenter(&client, "NodeClaim", "nodeclaims").await;
        nodeclaims_unread = claims.as_ref().err().map(unread);
        soft(claims, "Karpenter NodeClaims", &mut un)
            .flatten()
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    // What the summary says when there is no parsed status.
    let mut ca_absent = "no Cluster Autoscaler status ConfigMap".to_owned();
    let ca_status = if ctx.policy.namespace_allowed(CA_NS) {
        match Api::<ConfigMap>::namespaced(client.clone(), CA_NS)
            .get_opt(CA_STATUS)
            .await
        {
            Ok(cm) => {
                let text = cm
                    .and_then(|c| c.data)
                    .and_then(|d| d.get("status").cloned());
                let parsed = text.as_deref().and_then(parse_ca_status);
                if text.is_some() && parsed.is_none() {
                    ca_absent = "Cluster Autoscaler status not understood (older format)".into();
                    un.push(Unavailable {
                        what: "the Cluster Autoscaler status".into(),
                        reason: "not in the YAML format of Cluster Autoscaler 1.30+; read the ConfigMap directly".into(),
                    });
                }
                parsed
            }
            Err(e) => {
                let e = Error::kube(format!("get configmap {CA_STATUS}"), &e);
                ca_absent = format!("Cluster Autoscaler status {}", unread(&e));
                un.push(Unavailable {
                    what: "the Cluster Autoscaler status".into(),
                    reason: e.to_string(),
                });
                None
            }
        }
    } else {
        ca_absent =
            "Cluster Autoscaler status not checked (kube-system is outside the namespace policy)"
                .into();
        un.push(Unavailable {
            what: "the Cluster Autoscaler status in kube-system".into(),
            reason: "kube-system is outside the namespaces k8s-mcp may read (--namespaces / --deny-namespaces)".into(),
        });
        None
    };
    let hpas = soft(
        list_scoped::<HorizontalPodAutoscaler>(
            ctx,
            &sc,
            &ListParams::default(),
            "horizontalpodautoscalers",
            &mut un,
        )
        .await,
        "HorizontalPodAutoscalers",
        &mut un,
    );
    let mut events: Vec<Event> = soft(
        list_scoped(
            ctx,
            &sc,
            &ListParams::default().fields("reason=NotTriggerScaleUp"),
            "events",
            &mut un,
        )
        .await,
        "NotTriggerScaleUp events",
        &mut un,
    )
    .unwrap_or_default();
    retain_recent(&mut events, now, SignedDuration::from_hours(1));
    let ev = AutoscalingEvidence {
        nodepools,
        nodeclaims,
        ca_status,
        hpas,
        events,
        unavailable: un,
        now,
    };
    let findings = k8s_mcp_diagnose::diagnose_autoscaling(&ev);

    let mut parts = vec![match (&ev.nodepools, karpenter_unread) {
        (Some(np), _) => format!(
            "Karpenter {} NodePools, {}",
            np.len(),
            nodeclaims_unread.map_or_else(
                || format!("{} NodeClaims", ev.nodeclaims.len()),
                |why| format!("NodeClaims {why}")
            )
        ),
        (None, Some(why)) => format!("Karpenter {why}"),
        (None, None) => "no Karpenter".into(),
    }];
    parts.push(match &ev.ca_status {
        Some(s) => format!(
            "Cluster Autoscaler {} with {} node groups",
            s["autoscalerStatus"].as_str().unwrap_or("?"),
            s["nodeGroups"].as_array().map_or(0, Vec::len)
        ),
        None => ca_absent,
    });
    if let Some(h) = &ev.hpas {
        parts.push(format!("{} HPAs", h.len()));
    }
    let head = parts.join("; ");
    let mut e = envelope(
        &sc,
        match findings.first() {
            Some(f) => format!("{head}. Top finding: {}.", f.title),
            None => format!("{head}; no problems found by the diagnosis rules."),
        },
    );
    e.columns = vec!["kind", "name", "status", "size", "limits"];
    e.items = rows(&ev);
    e.findings = findings;
    e.untrusted_fields = vec!["findings[*].evidence[?(@.source=='event')].text".into()];
    add_notes(&mut e, &ev.unavailable);
    Ok(e)
}

fn rows(ev: &AutoscalingEvidence) -> Vec<Value> {
    let mut rows = Vec::new();
    for np in ev.nodepools.iter().flatten() {
        let used = &np["status"]["resources"];
        let limits = np["spec"]["limits"].as_object().map_or_else(
            || "none".into(),
            |l| {
                l.iter()
                    .map(|(r, lim)| {
                        format!(
                            "{r} {}/{}",
                            used[r].as_str().unwrap_or("0"),
                            lim.as_str().unwrap_or("?")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        );
        let ready = np["status"]["conditions"]
            .as_array()
            .and_then(|c| c.iter().find(|c| c["type"] == "Ready"))
            .and_then(|c| c["status"].as_str())
            .map_or("?", |s| if s == "True" { "Ready" } else { "not Ready" });
        rows.push(json!({
            "kind": "NodePool",
            "name": np["metadata"]["name"],
            "status": ready,
            "size": format!("{} nodes", used["nodes"].as_str().unwrap_or("0")),
            "limits": limits,
        }));
    }
    for g in ev
        .ca_status
        .iter()
        .flat_map(|s| s["nodeGroups"].as_array().into_iter().flatten())
    {
        let h = &g["health"];
        rows.push(json!({
            "kind": "NodeGroup",
            "name": g["name"],
            "status": format!("{}, scale-up {}", h["status"].as_str().unwrap_or("?"), g["scaleUp"]["status"].as_str().unwrap_or("?")),
            "size": format!("target {} ({}-{})", h["cloudProviderTarget"], h["minSize"], h["maxSize"]),
            "limits": "-",
        }));
    }
    for hpa in ev.hpas.iter().flatten() {
        let (Some(spec), status) = (&hpa.spec, hpa.status.as_ref()) else {
            continue;
        };
        rows.push(json!({
            "kind": "HPA",
            "name": format!("{}/{}", hpa.metadata.namespace.as_deref().unwrap_or(""), hpa.metadata.name.as_deref().unwrap_or("")),
            "status": format!("{} -> {} replicas", status.and_then(|s| s.current_replicas).unwrap_or(0), status.map_or(0, |s| s.desired_replicas)),
            "size": format!("{}-{}", spec.min_replicas.unwrap_or(1), spec.max_replicas),
            "limits": format!("{}/{}", spec.scale_target_ref.kind, spec.scale_target_ref.name),
        }));
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real ConfigMap holds the status as YAML text (CA 1.30+); older text is rejected.
    #[test]
    fn ca_status_yaml_is_parsed() {
        let v = parse_ca_status("time: 2026-11-14 11:59:00 +0000 UTC\nautoscalerStatus: Running\nnodeGroups:\n- name: ng-1\n  health:\n    status: Healthy\n    maxSize: 3\n").unwrap();
        assert_eq!(v["nodeGroups"][0]["health"]["maxSize"], 3);
        assert!(parse_ca_status("Cluster-autoscaler status at 2026-11-14 11:59:00:\nCluster-wide:\n  Health:      Healthy (ready=3)").is_none());
    }
}
