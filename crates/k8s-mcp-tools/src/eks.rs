//! Amazon EKS tools (PROPOSAL §8.4): thin wrappers around `k8s-mcp-provider-eks` that find
//! the cluster's identity (detection, then nodes, then `--eks-cluster`/`--eks-region`) and
//! render the cloud-neutral reports.

use k8s_mcp_core::envelope::Envelope;
use k8s_mcp_core::provider::{ClusterIdentity, Detection, ProviderId};
use k8s_mcp_core::{Error, Result};
use k8s_mcp_provider::{
    Provider, Report, UpgradeInfo, access_envelope, addons_envelope, cluster_info_envelope,
    identity_envelope, logs_envelope, node_pools_envelope,
};
use k8s_mcp_provider_eks::{Eks, identity::evaluate};
use k8s_openapi::api::core::v1::{ConfigMap, Node};
use kube::api::{Api, ListParams};

use crate::Ctx;
use crate::cloud::{IdentityInput, LogsInput, ProviderInput, finish, log_query, workload_identity};
use crate::common::{Scope, scope};

/// Nodes read when the kubeconfig alone does not identify the cluster.
const DETECT_NODES: u32 = 20;
/// EKS control-plane log types.
const COMPONENTS: &[&str] = &[
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler",
];

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

async fn connect(ctx: &Ctx, input: &ProviderInput) -> Result<(Scope, Eks)> {
    let sc = scope(ctx, input.context.as_deref(), None, true).await?;
    let eks = eks_for(ctx, &sc).await?;
    Ok((sc, eks))
}

/// `eks_cluster_info`.
pub async fn eks_cluster_info(ctx: &Ctx, input: ProviderInput) -> Result<Envelope> {
    let (sc, eks) = connect(ctx, &input).await?;
    Ok(finish(
        &sc,
        cluster_info_envelope(eks.id(), eks.cluster_info().await?),
    ))
}

/// `eks_nodegroups`.
pub async fn eks_nodegroups(ctx: &Ctx, input: ProviderInput) -> Result<Envelope> {
    let (sc, eks) = connect(ctx, &input).await?;
    Ok(finish(
        &sc,
        node_pools_envelope(eks.id(), eks.node_pools().await?),
    ))
}

/// `eks_addons`.
pub async fn eks_addons(ctx: &Ctx, input: ProviderInput) -> Result<Envelope> {
    let (sc, eks) = connect(ctx, &input).await?;
    Ok(finish(&sc, addons_envelope(eks.id(), eks.addons().await?)))
}

/// `eks_access`: access entries, plus `aws-auth` when kube-system may be read.
pub async fn eks_access(ctx: &Ctx, input: ProviderInput) -> Result<Envelope> {
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

/// `eks_identity_check`: the Kubernetes side always; the AWS side when it can be asked
/// (`cloud_checks` says why it was skipped otherwise).
pub async fn eks_identity_check(ctx: &Ctx, input: IdentityInput) -> Result<Envelope> {
    let (sc, ns, k8s) = workload_identity(ctx, &input, Some("eks-pod-identity-agent")).await?;
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

/// `eks_logs`: CloudWatch Logs lines, redacted and marked untrusted.
pub async fn eks_logs(ctx: &Ctx, input: LogsInput) -> Result<Envelope> {
    let context = input.context.clone();
    let q = log_query(ctx, input, COMPONENTS)?;
    let sc = scope(ctx, context.as_deref(), None, true).await?;
    let eks = eks_for(ctx, &sc).await?;
    let mut logs = eks.logs(&q).await?;
    logs.lines = ctx.redactor.lines(logs.lines.iter().map(String::as_str));
    Ok(finish(&sc, logs_envelope(ProviderId::Eks, logs)))
}
