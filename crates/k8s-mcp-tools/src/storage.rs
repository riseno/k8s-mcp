//! `diagnose_pvc`: why storage is stuck.

use jiff::SignedDuration;
use k8s_mcp_core::envelope::Section;
use k8s_mcp_core::{Error, Result};
use k8s_mcp_diagnose::PvcEvidence;
use k8s_mcp_diagnose::rules::pvc::storage_class;
use k8s_openapi::api::core::v1::{Event, PersistentVolume, PersistentVolumeClaim, Pod};
use k8s_openapi::api::storage::v1::StorageClass;
use kube::api::{Api, ListParams};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use crate::common::{check_name, envelope, retain_recent, scope, soft};
use crate::read::{add_notes, events_section};
use crate::{Ctx, Envelope};

/// Inputs for `diagnose_pvc`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiagnosePvcInput {
    /// PersistentVolumeClaim name.
    pub name: String,
    /// Namespace (default: the context's namespace).
    pub namespace: Option<String>,
    /// Kubeconfig context.
    pub context: Option<String>,
}

/// True when the pod mounts the claim.
pub(crate) fn uses_claim(pod: &Pod, claim: &str) -> bool {
    pod.spec
        .iter()
        .flat_map(|s| s.volumes.iter().flatten())
        .filter_map(|v| v.persistent_volume_claim.as_ref())
        .any(|c| c.claim_name == claim)
}

/// Root-cause a PVC: StorageClass, provisioning, binding, attach and mount failures.
pub async fn diagnose_pvc(ctx: &Ctx, input: DiagnosePvcInput) -> Result<Envelope> {
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
    let pvc = Api::<PersistentVolumeClaim>::namespaced(client.clone(), &ns)
        .get(&input.name)
        .await
        .map_err(|e| {
            Error::kube(
                format!("get persistentvolumeclaim {} in namespace {ns}", input.name),
                &e,
            )
        })?;
    let mut un = Vec::new();
    let storage_classes = soft(
        Api::<StorageClass>::all(client.clone())
            .list(&ListParams::default())
            .await
            .map(|l| l.items)
            .map_err(|e| Error::kube("list storageclasses", &e)),
        "StorageClasses",
        &mut un,
    )?;
    let volume = pvc.spec.as_ref().and_then(|s| s.volume_name.clone());
    let pv = match &volume {
        Some(v) => soft(
            Api::<PersistentVolume>::all(client.clone())
                .get(v)
                .await
                .map_err(|e| Error::kube(format!("get persistentvolume {v}"), &e)),
            "the bound PersistentVolume",
            &mut un,
        )?,
        None => None,
    };
    let pods: Vec<Pod> = soft(
        Api::<Pod>::namespaced(client.clone(), &ns)
            .list(&ListParams::default())
            .await
            .map(|l| l.items)
            .map_err(|e| Error::kube(format!("list pods in namespace {ns}"), &e)),
        "pods using the claim",
        &mut un,
    )?
    .unwrap_or_default()
    .into_iter()
    .filter(|p| uses_claim(p, &input.name))
    .collect();
    let mut ns_events: Vec<Event> = soft(
        Api::<Event>::namespaced(client, &ns)
            .list(&ListParams::default())
            .await
            .map(|l| l.items)
            .map_err(|e| Error::kube(format!("list events in namespace {ns}"), &e)),
        "events",
        &mut un,
    )?
    .unwrap_or_default();
    retain_recent(&mut ns_events, now, SignedDuration::from_hours(1));
    let about = |kind: &str, names: &[&str]| -> Vec<Event> {
        ns_events
            .iter()
            .filter(|e| {
                e.involved_object.kind.as_deref() == Some(kind)
                    && e.involved_object
                        .name
                        .as_deref()
                        .is_some_and(|n| names.contains(&n))
            })
            .cloned()
            .collect()
    };
    let pod_names: Vec<&str> = pods
        .iter()
        .filter_map(|p| p.metadata.name.as_deref())
        .collect();
    let ev = PvcEvidence {
        events: about("PersistentVolumeClaim", &[input.name.as_str()]),
        pod_events: about("Pod", &pod_names),
        pvc,
        storage_classes,
        pv,
        pods: pods.clone(),
        unavailable: un,
        now,
    };
    let findings = k8s_mcp_diagnose::diagnose_pvc(&ev);

    let spec = ev.pvc.spec.clone().unwrap_or_default();
    let status = ev.pvc.status.clone().unwrap_or_default();
    let phase = status.phase.as_deref().unwrap_or("Unknown");
    let class = match (storage_class(&ev), spec.storage_class_name.as_deref()) {
        (Some(c), _) => format!(
            "StorageClass {} ({}, {})",
            c.metadata.name.as_deref().unwrap_or(""),
            c.provisioner,
            c.volume_binding_mode.as_deref().unwrap_or("Immediate")
        ),
        (None, Some("")) => "no StorageClass (static binding)".to_owned(),
        (None, Some(n)) => format!("StorageClass {n} (not found)"),
        (None, None) => "the default StorageClass (none found)".to_owned(),
    };
    let size = status
        .capacity
        .as_ref()
        .and_then(|c| c.get("storage"))
        .or_else(|| spec.resources.as_ref()?.requests.as_ref()?.get("storage"))
        .map_or_else(|| "?".to_owned(), |q| q.0.clone());
    let modes = spec.access_modes.clone().unwrap_or_default().join(",");
    let head = format!(
        "PVC {} ({ns}): {phase}, {class}, {size} {modes}, used by {} pod(s)",
        input.name,
        pods.len()
    );
    let mut e = envelope(
        &sc,
        match findings.first() {
            Some(f) => format!("{head}. Top finding: {}.", f.title),
            None => format!("{head}; no problems found by the diagnosis rules."),
        },
    );
    e.columns = vec!["name", "status", "volume", "capacity", "access", "used_by"];
    e.items = vec![json!({
        "name": input.name,
        "status": phase,
        "volume": volume.as_deref().unwrap_or("-"),
        "capacity": size,
        "access": modes,
        "used_by": pod_names.join(","),
    })];
    if !pods.is_empty() {
        e.sections.push(Section {
            title: format!("PODS USING THE CLAIM ({})", pods.len()),
            lines: pods
                .iter()
                .map(|p| {
                    format!(
                        "{}  {}  node={}",
                        p.metadata.name.as_deref().unwrap_or(""),
                        p.status
                            .as_ref()
                            .and_then(|s| s.phase.as_deref())
                            .unwrap_or("?"),
                        p.spec
                            .as_ref()
                            .and_then(|s| s.node_name.as_deref())
                            .unwrap_or("-")
                    )
                })
                .collect(),
            untrusted: None,
        });
    }
    let events: Vec<Event> = ev.events.iter().chain(&ev.pod_events).cloned().collect();
    if !events.is_empty() {
        e.sections.push(events_section(ctx, &events, now));
    }
    e.findings = findings;
    e.untrusted_fields = vec!["findings[*].evidence[?(@.source=='event')].text".into()];
    add_notes(&mut e, &ev.unavailable);
    Ok(e)
}
