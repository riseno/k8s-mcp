#![forbid(unsafe_code)]
//! Tool implementations: gather data through kube, apply policy and redaction, call the
//! pure rule engine, and shape everything into an [`Envelope`]. Transport-agnostic.

mod autoscaling;
mod changes;
mod common;
mod diagnose;
mod discovery;
mod dns;
#[cfg(feature = "provider-eks")]
mod eks;
mod logs;
mod read;
mod rows;
mod service;
mod storage;
mod upgrade;

use std::sync::Arc;

use jiff::Timestamp;
use k8s_mcp_core::cluster::ClusterManager;
pub use k8s_mcp_core::envelope::Envelope;
use k8s_mcp_core::policy::Policy;
use k8s_mcp_core::redact::Redactor;

pub use autoscaling::{AutoscalingStatusInput, autoscaling_status};
pub use changes::{RecentChangesInput, RolloutHistoryInput, recent_changes, rollout_history};
pub use diagnose::{
    DiagnoseNodeInput, DiagnosePodInput, DiagnoseWorkloadInput, FindProblemsInput, diagnose_node,
    diagnose_pod, diagnose_workload, find_problems,
};
pub use dns::{DiagnoseDnsInput, diagnose_dns};
#[cfg(feature = "provider-eks")]
pub use eks::{
    EksIdentityInput, EksInput, EksLogsInput, eks_access, eks_addons, eks_cluster_info,
    eks_identity_check, eks_logs, eks_nodegroups,
};
#[cfg(feature = "provider-eks")]
pub use k8s_mcp_provider_eks::RULES as EKS_RULES;
#[cfg(feature = "provider-eks")]
pub use k8s_mcp_provider_eks::identity::RULES as EKS_IDENTITY_RULES;
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
}

/// Cloud cluster identity from flags, for when detection cannot tell (in-cluster, aliases).
#[derive(Clone, Debug, Default)]
pub struct CloudOverride {
    /// Cluster name.
    pub cluster: Option<String>,
    /// Region.
    pub region: Option<String>,
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
        }
    }

    /// Current time.
    pub fn now(&self) -> Timestamp {
        (self.clock)()
    }
}
