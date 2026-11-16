//! Google Kubernetes Engine tools (PROPOSAL §8.4): thin wrappers around
//! `k8s-mcp-provider-gke` that find the cluster's identity (detection, then nodes, then
//! `--gke-cluster project/location/name`) and render the cloud-neutral reports.

use k8s_mcp_core::envelope::Envelope;
use k8s_mcp_core::provider::{ClusterIdentity, ProviderId};
use k8s_mcp_core::{Error, Result};
use k8s_mcp_provider::{
    Provider, Report, UpgradeInfo, addons_envelope, cluster_info_envelope, identity_envelope,
    logs_envelope, node_pools_envelope,
};
use k8s_mcp_provider_gke::{Gke, identity::evaluate};

use crate::Ctx;
use crate::cloud::{
    IdentityInput, LogsInput, ProviderInput, detected_identity, finish, log_query,
    workload_identity,
};
use crate::common::{Scope, scope};

/// GKE control-plane log sources.
const COMPONENTS: &[&str] = &["api", "audit", "controllerManager", "scheduler"];

/// `--gke-cluster project/location/name`.
fn flag_identity(flag: &str) -> Result<ClusterIdentity> {
    let parts: Vec<&str> = flag.split('/').collect();
    let [project, location, name] = parts.as_slice() else {
        return Err(Error::InvalidInput(format!(
            "--gke-cluster {flag:?} must be <project>/<location>/<name>"
        )));
    };
    Ok(ClusterIdentity {
        name: Some((*name).to_owned()),
        region: Some((*location).to_owned()),
        account: Some((*project).to_owned()),
        ..ClusterIdentity::default()
    })
}

/// The GKE cluster behind a context: the flag, else detection.
async fn identity(ctx: &Ctx, sc: &Scope) -> Result<ClusterIdentity> {
    if let Some(flag) = &ctx.cloud.gke {
        return flag_identity(flag);
    }
    detected_identity(ctx, sc, ProviderId::Gke, "--gke-cluster <project>/<location>/<name>")
        .await?
        .ok_or_else(|| Error::NotFound(format!(
            "context {:?} does not look like a GKE cluster; GKE tools need one, or pass --gke-cluster <project>/<location>/<name>",
            sc.target.context
        )))
}

async fn gke_for(ctx: &Ctx, sc: &Scope) -> Result<Gke> {
    Gke::connect(&identity(ctx, sc).await?).await
}

/// The GKE section of `upgrade_readiness`.
pub(crate) async fn upgrade(ctx: &Ctx, sc: &Scope, target: &str) -> Result<Report<UpgradeInfo>> {
    gke_for(ctx, sc).await?.upgrade_checks(Some(target)).await
}

async fn connect(ctx: &Ctx, input: &ProviderInput) -> Result<(Scope, Gke)> {
    let sc = scope(ctx, input.context.as_deref(), None, true).await?;
    let gke = gke_for(ctx, &sc).await?;
    Ok((sc, gke))
}

/// `gke_cluster_info`.
pub async fn gke_cluster_info(ctx: &Ctx, input: ProviderInput) -> Result<Envelope> {
    let (sc, gke) = connect(ctx, &input).await?;
    Ok(finish(
        &sc,
        cluster_info_envelope(gke.id(), gke.cluster_info().await?),
    ))
}

/// `gke_node_pools`.
pub async fn gke_node_pools(ctx: &Ctx, input: ProviderInput) -> Result<Envelope> {
    let (sc, gke) = connect(ctx, &input).await?;
    Ok(finish(
        &sc,
        node_pools_envelope(gke.id(), gke.node_pools().await?),
    ))
}

/// `gke_addons`.
pub async fn gke_addons(ctx: &Ctx, input: ProviderInput) -> Result<Envelope> {
    let (sc, gke) = connect(ctx, &input).await?;
    Ok(finish(&sc, addons_envelope(gke.id(), gke.addons().await?)))
}

/// `gke_identity_check`: the Kubernetes side always; the Google Cloud side when it can be
/// asked (`cloud_checks` says why it was skipped otherwise).
pub async fn gke_identity_check(ctx: &Ctx, input: IdentityInput) -> Result<Envelope> {
    let (sc, ns, k8s) = workload_identity(ctx, &input, None).await?;
    let report = match gke_for(ctx, &sc).await {
        Ok(gke) => gke.identity_check(&k8s).await,
        Err(e) => evaluate(&k8s, Err(&e.to_string())),
    };
    let mut e = finish(
        &sc,
        identity_envelope(
            ProviderId::Gke,
            &format!("ServiceAccount {ns}/{}", input.service_account),
            report,
        ),
    );
    e.namespace = Some(ns);
    Ok(e)
}

/// `gke_logs`: Cloud Logging lines, redacted and marked untrusted.
pub async fn gke_logs(ctx: &Ctx, input: LogsInput) -> Result<Envelope> {
    let context = input.context.clone();
    let q = log_query(ctx, input, COMPONENTS)?;
    let sc = scope(ctx, context.as_deref(), None, true).await?;
    let gke = gke_for(ctx, &sc).await?;
    let mut logs = gke.logs(&q).await?;
    logs.lines = ctx.redactor.lines(logs.lines.iter().map(String::as_str));
    Ok(finish(&sc, logs_envelope(ProviderId::Gke, logs)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn gke_cluster_flag() {
        let id = flag_identity("acme/europe-west1/shop").unwrap();
        assert_eq!(
            (
                id.account.as_deref(),
                id.region.as_deref(),
                id.name.as_deref()
            ),
            (Some("acme"), Some("europe-west1"), Some("shop"))
        );
        assert!(flag_identity("shop").is_err());
    }
}
