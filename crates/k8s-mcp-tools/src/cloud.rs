//! What the provider toolsets (`eks_*`, `gke_*`) share: their inputs, the Kubernetes side of
//! the identity check, and log query validation, so every provider's tools take the same
//! arguments and enforce the same policy.

use jiff::SignedDuration;
use k8s_mcp_core::envelope::Envelope;
use k8s_mcp_core::provider::{ClusterIdentity, ProviderId};
use k8s_mcp_core::text::parse_duration;
use k8s_mcp_core::{Error, Result};
use k8s_mcp_provider::{LogQuery, WorkloadIdentity};
use k8s_openapi::api::apps::v1::DaemonSet;
use k8s_openapi::api::core::v1::{Node, Pod, ServiceAccount};
use kube::api::{Api, ListParams};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::Ctx;
use crate::common::{Scope, check_name, scope};

/// Inputs of the cluster-level provider tools (cluster info, node pools, add-ons).
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderInput {
    /// Kubeconfig context (default: the server's default context).
    pub context: Option<String>,
}

/// Inputs of the provider identity checks.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityInput {
    /// ServiceAccount name.
    pub service_account: String,
    /// Namespace (default: the context's namespace).
    pub namespace: Option<String>,
    /// Kubeconfig context.
    pub context: Option<String>,
}

/// Inputs of the provider log tools.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LogsInput {
    /// `control-plane` (default) or `application` (container logs: Container Insights on EKS,
    /// Cloud Logging on GKE).
    pub source: Option<String>,
    /// Control-plane component: api, audit, controllerManager, scheduler, or authenticator (EKS).
    pub component: Option<String>,
    /// Application logs of this namespace (required when --namespaces restricts namespaces).
    pub namespace: Option<String>,
    /// Application logs of this pod.
    pub pod: Option<String>,
    /// Text the lines must contain.
    pub grep: Option<String>,
    /// Look-back window such as `30m` or `6h` (default `1h`, at most `24h`).
    pub since: Option<String>,
    /// Most lines (default 100, max 500).
    pub limit: Option<i32>,
    /// Kubeconfig context.
    pub context: Option<String>,
}

/// Nodes read when the kubeconfig alone does not identify the cluster.
const DETECT_NODES: u32 = 20;

/// The identity detection gives for `provider`'s cluster: kubeconfig signals first, then a few
/// nodes (labels, providerIDs) when `complete` says something is still missing.
pub(crate) async fn detected_identity(
    ctx: &Ctx,
    sc: &Scope,
    provider: ProviderId,
    complete: impl Fn(&ClusterIdentity) -> bool,
) -> Option<ClusterIdentity> {
    let context = &sc.target.context;
    let of = |d: Option<k8s_mcp_core::provider::Detection>| {
        d.filter(|d| d.provider == provider).map(|d| d.identity)
    };
    let found = of(ctx.clusters.detect_provider(context, &[]));
    if found.as_ref().is_some_and(&complete) {
        return found;
    }
    let nodes: Vec<Node> = Api::<Node>::all(sc.target.client.clone())
        .list(&ListParams::default().limit(DETECT_NODES))
        .await
        .map(|l| l.items)
        .unwrap_or_default();
    of(ctx.clusters.detect_provider(context, &nodes)).or(found)
}

/// Stamp the envelope with the context it describes.
pub(crate) fn finish(sc: &Scope, mut e: Envelope) -> Envelope {
    e.context = Some(sc.target.context.clone());
    e
}

/// The Kubernetes side of an identity check: the ServiceAccount, the pods running as it and,
/// when `agent` names one, whether that kube-system DaemonSet (the provider's identity agent)
/// is ready.
pub(crate) async fn workload_identity(
    ctx: &Ctx,
    input: &IdentityInput,
    agent: Option<&str>,
) -> Result<(Scope, String, WorkloadIdentity)> {
    check_name("service_account", &input.service_account)?;
    let sc = scope(
        ctx,
        input.context.as_deref(),
        input.namespace.as_deref(),
        false,
    )
    .await?;
    let ns = sc.namespace.clone().unwrap_or_default();
    let client = sc.target.client.clone();
    let service_account = Api::<ServiceAccount>::namespaced(client.clone(), &ns)
        .get(&input.service_account)
        .await
        .map_err(|e| {
            Error::kube(
                format!(
                    "get serviceaccount {} in namespace {ns}",
                    input.service_account
                ),
                &e,
            )
        })?;
    let pods = Api::<Pod>::namespaced(client.clone(), &ns)
        .list(&ListParams::default())
        .await
        .map(|l| l.items)
        .unwrap_or_default()
        .into_iter()
        .filter(|p| {
            p.spec
                .as_ref()
                .and_then(|s| s.service_account_name.as_deref())
                == Some(input.service_account.as_str())
        })
        .collect();
    let agent_ready = match agent {
        Some(name) if ctx.policy.namespace_allowed("kube-system") => {
            match Api::<DaemonSet>::namespaced(client, "kube-system")
                .get_opt(name)
                .await
            {
                Ok(Some(ds)) => ds.status.map(|s| {
                    s.desired_number_scheduled > 0 && s.number_ready == s.desired_number_scheduled
                }),
                Ok(None) => Some(false),
                Err(_) => None,
            }
        }
        _ => None,
    };
    Ok((
        sc,
        ns,
        WorkloadIdentity {
            service_account,
            pods,
            agent_ready,
        },
    ))
}

/// Validate a log request against the namespace policy and bounds, and build the query.
/// `components` are the control-plane components this provider has.
pub(crate) fn log_query(ctx: &Ctx, input: LogsInput, components: &[&str]) -> Result<LogQuery> {
    let source = input.source.unwrap_or_else(|| "control-plane".into());
    let restricted = !ctx.policy.namespaces.is_empty() || !ctx.policy.deny_namespaces.is_empty();
    match source.as_str() {
        "control-plane" => {
            if restricted {
                return Err(Error::Forbidden("control-plane logs cover every namespace, so they are not available while --namespaces or --deny-namespaces restrict namespaces; use source=application with an allowed namespace".into()));
            }
            if let Some(c) = &input.component
                && !components.contains(&c.as_str())
            {
                return Err(Error::InvalidInput(format!("unknown component {c:?}: use {}", components.join(", "))));
            }
        }
        "application" => match &input.namespace {
            Some(ns) => ctx.policy.check_namespace(ns)?,
            None if restricted => return Err(Error::InvalidInput("give a namespace: --namespaces or --deny-namespaces restrict which application logs may be read".into())),
            None => {}
        },
        other => return Err(Error::InvalidInput(format!("unknown source {other:?}: use control-plane or application"))),
    }
    if let Some(p) = &input.pod {
        check_name("pod", p)?;
    }
    if let Some(g) = &input.grep
        && (g.is_empty() || g.len() > 200 || g.chars().any(char::is_control))
    {
        return Err(Error::InvalidInput(
            "grep must be 1-200 printable characters".into(),
        ));
    }
    let since = match &input.since {
        Some(s) => parse_duration(s).map_err(Error::InvalidInput)?,
        None => SignedDuration::from_hours(1),
    };
    if since <= SignedDuration::ZERO || since > SignedDuration::from_hours(24) {
        return Err(Error::InvalidInput(
            "since must be between 1s and 24h".into(),
        ));
    }
    let limit = input.limit.unwrap_or(100);
    if !(1..=500).contains(&limit) {
        return Err(Error::InvalidInput(format!(
            "limit must be 1-500, got {limit}"
        )));
    }
    let start = ctx.now().checked_sub(since).unwrap_or_else(|_| ctx.now());
    Ok(LogQuery {
        source,
        component: input.component,
        namespace: input.namespace,
        pod: input.pod,
        grep: input.grep,
        since_ms: start.as_millisecond(),
        limit,
    })
}
