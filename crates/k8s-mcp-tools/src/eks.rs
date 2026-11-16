//! Amazon EKS tools (PROPOSAL §8.4): thin wrappers around `k8s-mcp-provider-eks` that find
//! the cluster's identity (detection, then nodes, then `--eks-cluster`/`--eks-region`) and
//! render the cloud-neutral reports.

use k8s_mcp_core::envelope::Envelope;
use k8s_mcp_core::provider::{ClusterIdentity, Detection, ProviderId};
use k8s_mcp_core::{Error, Result};
use k8s_mcp_provider::{
    Provider, access_envelope, addons_envelope, cluster_info_envelope, node_pools_envelope,
};
use k8s_mcp_provider_eks::Eks;
use k8s_openapi::api::core::v1::{ConfigMap, Node};
use kube::api::{Api, ListParams};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::Ctx;
use crate::common::{Scope, scope};

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

async fn connect(ctx: &Ctx, input: &EksInput) -> Result<(Scope, Eks)> {
    let sc = scope(ctx, input.context.as_deref(), None, true).await?;
    let id = identity(ctx, &sc).await?;
    Ok((sc, Eks::connect(&id).await?))
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
