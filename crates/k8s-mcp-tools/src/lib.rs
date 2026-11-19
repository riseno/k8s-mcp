#![forbid(unsafe_code)]
//! Tool implementations: gather data through kube, apply policy and redaction, call the
//! pure rule engine, and shape everything into an [`Envelope`]. Transport-agnostic.

#[cfg(feature = "provider-aks")]
mod aks;
mod autoscaling;
mod changes;
#[cfg(any(
    feature = "provider-eks",
    feature = "provider-gke",
    feature = "provider-aks"
))]
mod cloud;
mod common;
mod diagnose;
mod discovery;
mod dns;
#[cfg(feature = "provider-eks")]
mod eks;
#[cfg(feature = "provider-gke")]
mod gke;
mod helm;
mod logs;
mod read;
mod rows;
mod service;
mod storage;
mod upgrade;
mod write;

use std::sync::Arc;

use jiff::Timestamp;
use k8s_mcp_core::cluster::ClusterManager;
pub use k8s_mcp_core::envelope::Envelope;
use k8s_mcp_core::policy::Policy;
use k8s_mcp_core::redact::Redactor;

#[cfg(feature = "provider-aks")]
pub use aks::{
    aks_access, aks_addons, aks_cluster_info, aks_identity_check, aks_logs, aks_node_pools,
};
pub use autoscaling::{AutoscalingStatusInput, autoscaling_status};
pub use changes::{RecentChangesInput, RolloutHistoryInput, recent_changes, rollout_history};
#[cfg(any(
    feature = "provider-eks",
    feature = "provider-gke",
    feature = "provider-aks"
))]
pub use cloud::{IdentityInput, LogsInput, ProviderInput};
pub use diagnose::{
    DiagnoseNodeInput, DiagnosePodInput, DiagnoseWorkloadInput, FindProblemsInput, diagnose_node,
    diagnose_pod, diagnose_workload, find_problems,
};
pub use dns::{DiagnoseDnsInput, diagnose_dns};
#[cfg(feature = "provider-eks")]
pub use eks::{
    eks_access, eks_addons, eks_cluster_info, eks_identity_check, eks_logs, eks_nodegroups,
};
#[cfg(feature = "provider-gke")]
pub use gke::{
    gke_access, gke_addons, gke_cluster_info, gke_identity_check, gke_logs, gke_node_pools,
};
pub use helm::{HelmReleaseInput, HelmReleasesInput, helm_release, helm_releases};
#[cfg(feature = "provider-aks")]
pub use k8s_mcp_provider_aks::RULES as AKS_RULES;
#[cfg(feature = "provider-aks")]
pub use k8s_mcp_provider_aks::identity::RULES as AKS_IDENTITY_RULES;
#[cfg(feature = "provider-eks")]
pub use k8s_mcp_provider_eks::RULES as EKS_RULES;
#[cfg(feature = "provider-eks")]
pub use k8s_mcp_provider_eks::identity::RULES as EKS_IDENTITY_RULES;
#[cfg(feature = "provider-gke")]
pub use k8s_mcp_provider_gke::RULES as GKE_RULES;
#[cfg(feature = "provider-gke")]
pub use k8s_mcp_provider_gke::identity::RULES as GKE_IDENTITY_RULES;
pub use logs::{GetLogsInput, get_logs};
pub use read::{
    ApiResourcesInput, CheckPermissionsInput, ClusterOverviewInput, GetResourceInput,
    ListContextsInput, ListEventsInput, ListResourcesInput, TopInput, api_resources,
    check_permissions, cluster_overview, get_resource, list_contexts, list_events, list_resources,
    top,
};
pub use service::{DiagnoseServiceInput, diagnose_service};
pub use storage::{DiagnosePvcInput, diagnose_pvc};
pub use upgrade::{UpgradeReadinessInput, upgrade_readiness};
pub use write::{
    ApplyManifestInput, DeletePodInput, DrainNodeInput, NodeWriteInput, RestartWorkloadInput,
    RollbackWorkloadInput, ScaleWorkloadInput, apply_manifest, cordon_node, delete_pod, drain_node,
    restart_workload, rollback_workload, scale_workload, uncordon_node,
};

/// Source of "now", injected so tests and golden snapshots are deterministic.
pub type Clock = Arc<dyn Fn() -> Timestamp + Send + Sync>;

/// Everything a tool needs.
#[derive(Clone)]
pub struct Ctx {
    /// Kubeconfig contexts and clients.
    pub clusters: Arc<ClusterManager>,
    /// Safety policy.
    pub policy: Arc<Policy>,
    /// Redaction engine.
    pub redactor: Redactor,
    /// Clock.
    pub clock: Clock,
    /// Cluster identity given on the command line (`--eks-cluster`, `--eks-region`), which
    /// wins over detection.
    pub cloud: CloudOverride,
    /// Providers whose toolsets are registered: `upgrade_readiness` adds their upgrade checks.
    pub providers: Vec<k8s_mcp_core::provider::ProviderId>,
    /// Issues and checks the confirm tokens of write plans (one key per process).
    pub confirm: Arc<k8s_mcp_core::confirm::Confirmer>,
}

/// Cloud cluster identity from flags, for when detection cannot tell (in-cluster, aliases).
#[derive(Clone, Debug, Default)]
pub struct CloudOverride {
    /// EKS cluster name (`--eks-cluster`).
    pub cluster: Option<String>,
    /// EKS region (`--eks-region`).
    pub region: Option<String>,
    /// GKE cluster as `project/location/name` (`--gke-cluster`).
    pub gke: Option<String>,
    /// AKS cluster as `subscription/resourceGroup/name` (`--aks-cluster`).
    pub aks: Option<String>,
}

/// Add the cluster's provider hints to the findings (PROPOSAL §8.4): the provider detected for
/// the envelope's context from the kubeconfig, else the registered provider toolset (in-cluster).
pub fn provider_hints(ctx: &Ctx, env: &mut Envelope) {
    if env.findings.is_empty() {
        return;
    }
    let context = env
        .context
        .clone()
        .unwrap_or_else(|| ctx.clusters.default_context().to_owned());
    let provider = ctx
        .clusters
        .detect_provider(&context, &[])
        .map(|d| d.provider)
        .or_else(|| ctx.providers.first().copied());
    if let Some(p) = provider {
        k8s_mcp_diagnose::hints::apply(p, &mut env.findings);
    }
}

impl Ctx {
    /// A context using the system clock and the policy's redaction level.
    pub fn new(clusters: Arc<ClusterManager>, policy: Arc<Policy>) -> Self {
        Self {
            clusters,
            redactor: Redactor::new(policy.redact),
            policy,
            clock: Arc::new(Timestamp::now),
            cloud: CloudOverride::default(),
            providers: Vec::new(),
            confirm: Arc::default(),
        }
    }

    /// Current time.
    pub fn now(&self) -> Timestamp {
        (self.clock)()
    }
}
