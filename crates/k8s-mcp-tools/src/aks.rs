//! Azure Kubernetes Service tools (PROPOSAL §8.4): thin wrappers around
//! `k8s-mcp-provider-aks` that find the cluster's identity (detection, or
//! `--aks-cluster subscription/resourceGroup/name`) and render the cloud-neutral reports.

use k8s_mcp_core::envelope::Envelope;
use k8s_mcp_core::provider::{ClusterIdentity, ProviderId};
use k8s_mcp_core::{Error, Result};
use k8s_mcp_provider::{
    Provider, Report, UpgradeInfo, addons_envelope, cluster_info_envelope, identity_envelope,
    logs_envelope, node_pools_envelope,
};
use k8s_mcp_provider_aks::{Aks, identity::evaluate};

use crate::Ctx;
use crate::cloud::{
    IdentityInput, LogsInput, ProviderInput, detected_identity, finish, log_query,
    workload_identity,
};
use crate::common::{Scope, scope};

/// AKS control-plane log categories.
const COMPONENTS: &[&str] = &["api", "audit", "controllerManager", "scheduler"];

/// `--aks-cluster subscription/resourceGroup/name`.
fn flag_identity(flag: &str) -> Result<ClusterIdentity> {
    let parts: Vec<&str> = flag.split('/').collect();
    let [subscription, resource_group, name] = parts.as_slice() else {
        return Err(Error::InvalidInput(format!(
            "--aks-cluster {flag:?} must be <subscription>/<resourceGroup>/<name>"
        )));
    };
    Ok(ClusterIdentity {
        name: Some((*name).to_owned()),
        account: Some((*subscription).to_owned()),
        resource_group: Some((*resource_group).to_owned()),
        ..ClusterIdentity::default()
    })
}

/// The AKS cluster behind a context: the flag, else detection.
async fn identity(ctx: &Ctx, sc: &Scope) -> Result<ClusterIdentity> {
    if let Some(flag) = &ctx.cloud.aks {
        return flag_identity(flag);
    }
    detected_identity(ctx, sc, ProviderId::Aks, "--aks-cluster <subscription>/<resourceGroup>/<name>")
        .await?
        .ok_or_else(|| Error::NotFound(format!(
            "context {:?} does not look like an AKS cluster; AKS tools need one, or pass --aks-cluster <subscription>/<resourceGroup>/<name>",
            sc.target.context
        )))
}

async fn aks_for(ctx: &Ctx, sc: &Scope) -> Result<Aks> {
    Aks::connect(&identity(ctx, sc).await?)
}

/// The AKS section of `upgrade_readiness`.
pub(crate) async fn upgrade(ctx: &Ctx, sc: &Scope, target: &str) -> Result<Report<UpgradeInfo>> {
    aks_for(ctx, sc).await?.upgrade_checks(Some(target)).await
}

async fn connect(ctx: &Ctx, input: &ProviderInput) -> Result<(Scope, Aks)> {
    let sc = scope(ctx, input.context.as_deref(), None, true).await?;
    let aks = aks_for(ctx, &sc).await?;
    Ok((sc, aks))
}

/// `aks_cluster_info`.
pub async fn aks_cluster_info(ctx: &Ctx, input: ProviderInput) -> Result<Envelope> {
    let (sc, aks) = connect(ctx, &input).await?;
    Ok(finish(
        &sc,
        cluster_info_envelope(aks.id(), aks.cluster_info().await?),
    ))
}

/// `aks_node_pools`.
pub async fn aks_node_pools(ctx: &Ctx, input: ProviderInput) -> Result<Envelope> {
    let (sc, aks) = connect(ctx, &input).await?;
    Ok(finish(
        &sc,
        node_pools_envelope(aks.id(), aks.node_pools().await?),
    ))
}

/// `aks_addons`.
pub async fn aks_addons(ctx: &Ctx, input: ProviderInput) -> Result<Envelope> {
    let (sc, aks) = connect(ctx, &input).await?;
    Ok(finish(&sc, addons_envelope(aks.id(), aks.addons().await?)))
}

/// `aks_identity_check`: the Kubernetes side always; the Azure side when it can be asked
/// (`cloud_checks` says why it was skipped otherwise).
pub async fn aks_identity_check(ctx: &Ctx, input: IdentityInput) -> Result<Envelope> {
    let (sc, ns, k8s) = workload_identity(ctx, &input, None).await?;
    let report = match aks_for(ctx, &sc).await {
        Ok(aks) => aks.identity_check(&k8s).await,
        Err(e) => evaluate(&k8s, Err(&e.to_string())),
    };
    let mut e = finish(
        &sc,
        identity_envelope(
            ProviderId::Aks,
            &format!("ServiceAccount {ns}/{}", input.service_account),
            report,
        ),
    );
    e.namespace = Some(ns);
    Ok(e)
}

/// `aks_logs`: Log Analytics lines, redacted and marked untrusted.
pub async fn aks_logs(ctx: &Ctx, input: LogsInput) -> Result<Envelope> {
    let context = input.context.clone();
    let q = log_query(ctx, input, COMPONENTS)?;
    let sc = scope(ctx, context.as_deref(), None, true).await?;
    let aks = aks_for(ctx, &sc).await?;
    let mut logs = aks.logs(&q).await?;
    logs.lines = ctx.redactor.lines(logs.lines.iter().map(String::as_str));
    Ok(finish(&sc, logs_envelope(ProviderId::Aks, logs)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn aks_cluster_flag() {
        let id = flag_identity("sub-1/shop-rg/shop").unwrap();
        assert_eq!(
            (
                id.account.as_deref(),
                id.resource_group.as_deref(),
                id.name.as_deref()
            ),
            (Some("sub-1"), Some("shop-rg"), Some("shop"))
        );
        assert!(flag_identity("sub-1/shop").is_err());
    }
}
