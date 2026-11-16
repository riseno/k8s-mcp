//! Amazon EKS tools (PROPOSAL §8.4): thin wrappers around `k8s-mcp-provider-eks` that find
//! the cluster's identity (detection, then nodes, then `--eks-cluster`/`--eks-region`) and
//! render the cloud-neutral reports.

use jiff::SignedDuration;
use k8s_mcp_core::envelope::Envelope;
use k8s_mcp_core::provider::{ClusterIdentity, Detection, ProviderId};
use k8s_mcp_core::text::parse_duration;
use k8s_mcp_core::{Error, Result};
use k8s_mcp_provider::{
    LogQuery, Provider, Report, UpgradeInfo, WorkloadIdentity, access_envelope, addons_envelope,
    cluster_info_envelope, identity_envelope, logs_envelope, node_pools_envelope,
};
use k8s_mcp_provider_eks::{Eks, identity::evaluate};
use k8s_openapi::api::apps::v1::DaemonSet;
use k8s_openapi::api::core::v1::{ConfigMap, Node, Pod, ServiceAccount};
use kube::api::{Api, ListParams};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::Ctx;
use crate::common::{Scope, check_name, scope};

/// Nodes read when the kubeconfig alone does not identify the cluster.
const DETECT_NODES: u32 = 20;

/// Inputs shared by the EKS tools.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EksInput {
    /// Kubeconfig context (default: the server's default context).
    pub context: Option<String>,
}

fn is_eks(d: Option<&Detection>) -> bool {
    d.is_some_and(|d| d.provider == ProviderId::Eks)
}

/// The EKS cluster behind a context: kubeconfig signals, then nodes, then the flags.
async fn identity(ctx: &Ctx, sc: &Scope) -> Result<ClusterIdentity> {
    let context = &sc.target.context;
    let mut found = ctx.clusters.detect_provider(context, &[]);
    let complete = |d: &Option<Detection>| {
        is_eks(d.as_ref())
            && d.as_ref()
                .is_some_and(|d| d.identity.name.is_some() && d.identity.region.is_some())
    };
    if !complete(&found) {
        let nodes: Vec<Node> = Api::<Node>::all(sc.target.client.clone())
            .list(&ListParams::default().limit(DETECT_NODES))
            .await
            .map(|l| l.items)
            .unwrap_or_default();
        found = ctx.clusters.detect_provider(context, &nodes).or(found);
    }
    let mut id = match found {
        Some(d) if d.provider == ProviderId::Eks => d.identity,
        _ if ctx.cloud.cluster.is_some() => ClusterIdentity::default(),
        other => {
            return Err(Error::NotFound(format!(
                "context {context:?} does not look like an EKS cluster (detected: {}); EKS tools need one, or pass --eks-cluster <name> and --eks-region <region>",
                other.map_or_else(|| "none".to_owned(), |d| d.describe())
            )));
        }
    };
    if let Some(c) = &ctx.cloud.cluster {
        id.name = Some(c.clone());
    }
    if let Some(r) = &ctx.cloud.region {
        id.region = Some(r.clone());
    }
    Ok(id)
}

async fn eks_for(ctx: &Ctx, sc: &Scope) -> Result<Eks> {
    Eks::connect(&identity(ctx, sc).await?).await
}

/// The EKS section of `upgrade_readiness`.
pub(crate) async fn upgrade(ctx: &Ctx, sc: &Scope, target: &str) -> Result<Report<UpgradeInfo>> {
    eks_for(ctx, sc).await?.upgrade_checks(Some(target)).await
}

async fn connect(ctx: &Ctx, input: &EksInput) -> Result<(Scope, Eks)> {
    let sc = scope(ctx, input.context.as_deref(), None, true).await?;
    let eks = eks_for(ctx, &sc).await?;
    Ok((sc, eks))
}

fn finish(sc: &Scope, mut e: Envelope) -> Envelope {
    e.context = Some(sc.target.context.clone());
    e
}

/// `eks_cluster_info`.
pub async fn eks_cluster_info(ctx: &Ctx, input: EksInput) -> Result<Envelope> {
    let (sc, eks) = connect(ctx, &input).await?;
    Ok(finish(
        &sc,
        cluster_info_envelope(eks.id(), eks.cluster_info().await?),
    ))
}

/// `eks_nodegroups`.
pub async fn eks_nodegroups(ctx: &Ctx, input: EksInput) -> Result<Envelope> {
    let (sc, eks) = connect(ctx, &input).await?;
    Ok(finish(
        &sc,
        node_pools_envelope(eks.id(), eks.node_pools().await?),
    ))
}

/// `eks_addons`.
pub async fn eks_addons(ctx: &Ctx, input: EksInput) -> Result<Envelope> {
    let (sc, eks) = connect(ctx, &input).await?;
    Ok(finish(&sc, addons_envelope(eks.id(), eks.addons().await?)))
}

/// `eks_access`: access entries, plus `aws-auth` when kube-system may be read.
pub async fn eks_access(ctx: &Ctx, input: EksInput) -> Result<Envelope> {
    let (sc, mut eks) = connect(ctx, &input).await?;
    if ctx.policy.namespace_allowed("kube-system") {
        eks.aws_auth = Api::<ConfigMap>::namespaced(sc.target.client.clone(), "kube-system")
            .get_opt("aws-auth")
            .await
            .ok()
            .flatten();
    }
    Ok(finish(&sc, access_envelope(eks.id(), eks.access().await?)))
}

/// Inputs for `eks_identity_check`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EksIdentityInput {
    /// ServiceAccount name.
    pub service_account: String,
    /// Namespace (default: the context's namespace).
    pub namespace: Option<String>,
    /// Kubeconfig context.
    pub context: Option<String>,
}

/// `eks_identity_check`: the Kubernetes side always; the AWS side when it can be asked
/// (`cloud_checks` says why it was skipped otherwise).
pub async fn eks_identity_check(ctx: &Ctx, input: EksIdentityInput) -> Result<Envelope> {
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
    let agent_ready = if ctx.policy.namespace_allowed("kube-system") {
        match Api::<DaemonSet>::namespaced(client, "kube-system")
            .get_opt("eks-pod-identity-agent")
            .await
        {
            Ok(Some(ds)) => ds.status.map(|s| {
                s.desired_number_scheduled > 0 && s.number_ready == s.desired_number_scheduled
            }),
            Ok(None) => Some(false),
            Err(_) => None,
        }
    } else {
        None
    };
    let k8s = WorkloadIdentity {
        service_account,
        pods,
        agent_ready,
    };
    let report = match eks_for(ctx, &sc).await {
        Ok(eks) => eks.identity_check(&k8s).await,
        Err(e) => evaluate(&k8s, Err(&e.to_string())),
    };
    let mut e = finish(
        &sc,
        identity_envelope(
            ProviderId::Eks,
            &format!("ServiceAccount {ns}/{}", input.service_account),
            report,
        ),
    );
    e.namespace = Some(ns);
    Ok(e)
}

/// Inputs for `eks_logs`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EksLogsInput {
    /// `control-plane` (default; log group /aws/eks/<cluster>/cluster) or `application`
    /// (Container Insights, /aws/containerinsights/<cluster>/application).
    pub source: Option<String>,
    /// Control-plane component: api, audit, authenticator, controllerManager or scheduler.
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

/// `eks_logs`: CloudWatch Logs lines, redacted and marked untrusted.
pub async fn eks_logs(ctx: &Ctx, input: EksLogsInput) -> Result<Envelope> {
    let source = input
        .source
        .clone()
        .unwrap_or_else(|| "control-plane".into());
    let restricted = !ctx.policy.namespaces.is_empty() || !ctx.policy.deny_namespaces.is_empty();
    match source.as_str() {
        "control-plane" => {
            if restricted {
                return Err(Error::Forbidden("control-plane logs cover every namespace, so they are not available while --namespaces or --deny-namespaces restrict namespaces; use source=application with an allowed namespace".into()));
            }
            if let Some(c) = &input.component
                && !["api", "audit", "authenticator", "controllerManager", "scheduler"].contains(&c.as_str())
            {
                return Err(Error::InvalidInput(format!("unknown component {c:?}: use api, audit, authenticator, controllerManager or scheduler")));
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
    let sc = scope(ctx, input.context.as_deref(), None, true).await?;
    let eks = eks_for(ctx, &sc).await?;
    let start = ctx.now().checked_sub(since).unwrap_or_else(|_| ctx.now());
    let q = LogQuery {
        source,
        component: input.component,
        namespace: input.namespace,
        pod: input.pod,
        grep: input.grep,
        since_ms: start.as_millisecond(),
        limit,
    };
    let mut logs = eks.logs(&q).await?;
    logs.lines = ctx.redactor.lines(logs.lines.iter().map(String::as_str));
    Ok(finish(&sc, logs_envelope(ProviderId::Eks, logs)))
}
