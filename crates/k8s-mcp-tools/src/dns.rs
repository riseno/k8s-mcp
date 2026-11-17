//! `diagnose_dns`: is DNS the problem? Checks the pod's NetworkPolicies, the cluster DNS in
//! kube-system (only when the namespace policy allows reading it) and the pod's logs.

use k8s_mcp_core::envelope::Section;
use k8s_mcp_core::{Error, Result};
use k8s_mcp_diagnose::rules::pod_ready;
use k8s_mcp_diagnose::{DnsEvidence, Unavailable};
use k8s_openapi::api::core::v1::{Pod, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use kube::api::{Api, ListParams};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use crate::common::{check_name, ensure_namespace, envelope, scope, soft};
use crate::diagnose::{container_logs, pod_secret_values};
use crate::read::add_notes;
use crate::rows::pod_row;
use crate::{Ctx, Envelope};

/// Where the cluster DNS runs.
const DNS_NS: &str = "kube-system";
const POD_LOG_TAIL: i64 = 100;
const DNS_LOG_TAIL: i64 = 50;
/// CoreDNS pods whose logs are read.
const DNS_LOG_PODS: usize = 2;

/// Inputs for `diagnose_dns`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiagnoseDnsInput {
    /// Pod whose DNS fails (optional: without it, the namespace and the cluster DNS are checked).
    pub pod: Option<String>,
    /// Namespace (default: the context's namespace).
    pub namespace: Option<String>,
    /// Kubeconfig context.
    pub context: Option<String>,
}

/// Check every layer of a pod's DNS path: NetworkPolicies, CoreDNS, kube-dns, the app's logs.
pub async fn diagnose_dns(ctx: &Ctx, input: DiagnoseDnsInput) -> Result<Envelope> {
    if let Some(p) = &input.pod {
        check_name("pod", p)?;
    }
    let sc = scope(
        ctx,
        input.context.as_deref(),
        input.namespace.as_deref(),
        false,
    )
    .await?;
    // A mistyped namespace must not read as "nothing found" (#67).
    if input.namespace.is_some() {
        ensure_namespace(&sc).await?;
    }
    let ns = sc.namespace.clone().unwrap_or_default();
    let now = ctx.now();
    let client = sc.target.client.clone();
    let mut un = Vec::new();
    let (pod, pod_logs) = match &input.pod {
        Some(name) => {
            let pod = Api::<Pod>::namespaced(client.clone(), &ns)
                .get(name)
                .await
                .map_err(|e| Error::kube(format!("get pod {name} in namespace {ns}"), &e))?;
            let secrets = pod_secret_values(&sc, &pod, &mut un).await;
            let logs = container_logs(ctx, &sc, &pod, POD_LOG_TAIL, &secrets, &mut un).await;
            (Some(pod), logs)
        }
        None => (None, Vec::new()),
    };
    let network_policies = soft(
        Api::<NetworkPolicy>::namespaced(client.clone(), &ns)
            .list(&ListParams::default())
            .await
            .map(|l| l.items)
            .map_err(|e| Error::kube(format!("list networkpolicies in namespace {ns}"), &e)),
        "NetworkPolicies",
        &mut un,
    )?;
    let mut ev = DnsEvidence {
        pod,
        namespace: ns.clone(),
        pod_logs,
        network_policies,
        now,
        ..DnsEvidence::default()
    };
    if ctx.policy.namespace_allowed(DNS_NS) {
        ev.dns_pods = soft(
            Api::<Pod>::namespaced(client.clone(), DNS_NS)
                .list(&ListParams::default().labels("k8s-app=kube-dns"))
                .await
                .map(|l| l.items)
                .map_err(|e| Error::kube("list the cluster DNS pods in kube-system", &e)),
            "cluster DNS pods",
            &mut un,
        )?;
        ev.dns_service = soft(
            Api::<Service>::namespaced(client.clone(), DNS_NS)
                .get_opt("kube-dns")
                .await
                .map_err(|e| Error::kube("get the kube-dns Service", &e)),
            "the kube-dns Service",
            &mut un,
        )?;
        ev.dns_ready_endpoints = soft(
            Api::<EndpointSlice>::namespaced(client.clone(), DNS_NS)
                .list(&ListParams::default().labels("kubernetes.io/service-name=kube-dns"))
                .await
                .map(|l| {
                    l.items
                        .iter()
                        .flat_map(|s| &s.endpoints)
                        .filter(|e| e.conditions.as_ref().and_then(|c| c.ready) != Some(false))
                        .count()
                })
                .map_err(|e| Error::kube("list the kube-dns EndpointSlices", &e)),
            "kube-dns EndpointSlices",
            &mut un,
        )?;
        // Not-Ready pods first: their logs explain the failure.
        let mut dns_pods: Vec<&Pod> = ev.dns_pods.iter().flatten().collect();
        dns_pods.sort_by_key(|p| pod_ready(p));
        for p in dns_pods.into_iter().take(DNS_LOG_PODS) {
            let logs = container_logs(ctx, &sc, p, DNS_LOG_TAIL, &[], &mut un).await;
            ev.dns_logs.extend(logs);
        }
    } else {
        un.push(Unavailable {
            what: "the cluster DNS in kube-system".into(),
            reason: "kube-system is outside the namespaces k8s-mcp may read (--namespaces / --deny-namespaces)".into(),
        });
    }
    ev.unavailable = un;
    let findings = k8s_mcp_diagnose::diagnose_dns(&ev);

    let subject = ev.pod.as_ref().map_or_else(
        || format!("DNS for namespace {ns}"),
        |p| {
            format!(
                "DNS for pod {} ({ns})",
                p.metadata.name.as_deref().unwrap_or("")
            )
        },
    );
    let mut parts = Vec::new();
    if let Some(pods) = &ev.dns_pods {
        parts.push(format!(
            "CoreDNS {}/{} Ready",
            pods.iter().filter(|p| pod_ready(p)).count(),
            pods.len()
        ));
    }
    match (&ev.dns_service, ev.dns_ready_endpoints) {
        (Some(Some(_)), Some(n)) => parts.push(format!("kube-dns has {n} ready endpoints")),
        (Some(None), _) => parts.push("no kube-dns Service".into()),
        _ => {}
    }
    if let Some(np) = &ev.network_policies {
        parts.push(format!("{} NetworkPolicies in {ns}", np.len()));
    }
    let head = if parts.is_empty() {
        subject
    } else {
        format!("{subject}: {}", parts.join(", "))
    };
    let mut e = envelope(
        &sc,
        match findings.first() {
            Some(f) => format!("{head}. Top finding: {}.", f.title),
            None => format!("{head}; no problems found by the diagnosis rules."),
        },
    );
    e.columns = vec!["name", "status", "ready", "restarts", "node", "age"];
    e.items = ev
        .dns_pods
        .iter()
        .flatten()
        .map(|p| {
            let mut r = pod_row(p);
            r["name"] = json!(p.metadata.name);
            r["age"] = json!(
                p.metadata
                    .creation_timestamp
                    .as_ref()
                    .map(|t| k8s_mcp_core::text::age(now, t.0))
            );
            r
        })
        .collect();
    if let Some(spec) = ev.pod.as_ref().and_then(|p| p.spec.as_ref()) {
        let mut lines = vec![format!(
            "dnsPolicy: {}",
            spec.dns_policy.as_deref().unwrap_or("ClusterFirst")
        )];
        if let Some(c) = &spec.dns_config {
            lines.push(format!("dnsConfig: {}", json!(c)));
        }
        e.sections.push(Section {
            title: "POD DNS SETTINGS".into(),
            lines,
            untrusted: Some(vec![("source".into(), "object".into())]),
        });
    }
    e.findings = findings;
    e.untrusted_fields = vec![
        "findings[*].evidence[?(@.source=='log')].text".into(),
        "sections[?(@.untrusted)].lines".into(),
    ];
    add_notes(&mut e, &ev.unavailable);
    Ok(e)
}
