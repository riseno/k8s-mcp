//! `diagnose_service`: why traffic does not reach a Service.

use k8s_mcp_core::envelope::Section;
use k8s_mcp_core::{Error, Result};
use k8s_mcp_diagnose::ServiceEvidence;
use k8s_mcp_diagnose::rules::pod_ready;
use k8s_mcp_diagnose::rules::service::{exposes, selects};
use k8s_openapi::api::core::v1::{Pod, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{Api, ListParams};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use crate::common::{check_name, envelope, events_for, scope, soft};
use crate::read::{add_notes, events_section};
use crate::{Ctx, Envelope};

/// Pods listed in the MATCHING PODS section.
const SHOWN_PODS: usize = 10;

/// Inputs for `diagnose_service`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiagnoseServiceInput {
    /// Service name.
    pub name: String,
    /// Namespace (default: the context's namespace).
    pub namespace: Option<String>,
    /// Kubeconfig context.
    pub context: Option<String>,
}

/// Root-cause a Service: selector vs pod labels, ready endpoints, port mapping, load balancer.
pub async fn diagnose_service(ctx: &Ctx, input: DiagnoseServiceInput) -> Result<Envelope> {
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
    let service = Api::<Service>::namespaced(client.clone(), &ns)
        .get(&input.name)
        .await
        .map_err(|e| Error::kube(format!("get service {} in namespace {ns}", input.name), &e))?;
    let mut un = Vec::new();
    let pods = soft(
        Api::<Pod>::namespaced(client.clone(), &ns)
            .list(&ListParams::default())
            .await
            .map(|l| l.items)
            .map_err(|e| Error::kube(format!("list pods in namespace {ns}"), &e)),
        "pods",
        &mut un,
    )?;
    let slices = soft(
        Api::<EndpointSlice>::namespaced(client, &ns)
            .list(
                &ListParams::default()
                    .labels(&format!("kubernetes.io/service-name={}", input.name)),
            )
            .await
            .map(|l| l.items)
            .map_err(|e| Error::kube("list endpointslices", &e)),
        "EndpointSlices",
        &mut un,
    )?;
    let events = soft(
        events_for(&sc.target, &ns, "Service", &input.name, now).await,
        "service events",
        &mut un,
    )?
    .unwrap_or_default();
    let ev = ServiceEvidence {
        service,
        pods,
        events,
        unavailable: un,
        now,
    };
    let findings = k8s_mcp_diagnose::diagnose_service(&ev);

    let spec = ev.service.spec.clone().unwrap_or_default();
    let type_ = spec.type_.as_deref().unwrap_or("ClusterIP");
    let matched: Vec<&Pod> = match (&spec.selector, &ev.pods) {
        (Some(sel), Some(pods)) if !sel.is_empty() => {
            pods.iter().filter(|p| selects(sel, p)).collect()
        }
        _ => Vec::new(),
    };
    let selector = spec
        .selector
        .as_ref()
        .filter(|s| !s.is_empty())
        .map_or_else(
            || "no selector (endpoints managed outside the Service)".to_owned(),
            |s| {
                format!(
                    "selector {} matches {} pods ({} Ready)",
                    s.iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join(","),
                    matched.len(),
                    matched.iter().filter(|p| pod_ready(p)).count()
                )
            },
        );
    let endpoints = slices.as_ref().map_or_else(String::new, |s| {
        let ready = s
            .iter()
            .flat_map(|s| &s.endpoints)
            .filter(|e| e.conditions.as_ref().and_then(|c| c.ready) != Some(false))
            .count();
        format!("; {ready} ready endpoints")
    });
    let head = format!(
        "Service {} ({ns}, {type_}): {selector}{endpoints}",
        input.name
    );
    let mut e = envelope(
        &sc,
        match findings.first() {
            Some(f) => format!("{head}. Top finding: {}.", f.title),
            None => format!("{head}; no problems found by the diagnosis rules."),
        },
    );
    e.columns = vec!["port", "target", "protocol", "exposed_by"];
    e.items = spec
        .ports
        .iter()
        .flatten()
        .map(|p| {
            let target = match &p.target_port {
                Some(IntOrString::String(s)) => s.clone(),
                Some(IntOrString::Int(n)) => n.to_string(),
                None => p.port.to_string(),
            };
            json!({
                "port": p.name.as_ref().map_or_else(|| p.port.to_string(), |n| format!("{n} {}", p.port)),
                "target": target,
                "protocol": p.protocol.as_deref().unwrap_or("TCP"),
                "exposed_by": format!("{}/{} pods", matched.iter().filter(|pod| exposes(pod, p)).count(), matched.len()),
            })
        })
        .collect();
    if !matched.is_empty() {
        e.sections.push(Section {
            title: format!("MATCHING PODS ({})", matched.len()),
            lines: matched
                .iter()
                .take(SHOWN_PODS)
                .map(|p| {
                    format!(
                        "{}  {}  {}",
                        p.metadata.name.as_deref().unwrap_or(""),
                        p.status
                            .as_ref()
                            .and_then(|s| s.phase.as_deref())
                            .unwrap_or("?"),
                        if pod_ready(p) { "Ready" } else { "not Ready" }
                    )
                })
                .collect(),
            untrusted: None,
        });
    }
    if !ev.events.is_empty() {
        e.sections.push(events_section(ctx, &ev.events, now));
    }
    e.findings = findings;
    add_notes(&mut e, &ev.unavailable);
    Ok(e)
}
