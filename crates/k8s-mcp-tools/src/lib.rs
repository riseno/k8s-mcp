#![forbid(unsafe_code)]
//! Tool implementations: gather data through kube, apply policy and redaction, call the
//! pure rule engine, and shape everything into an [`Envelope`]. Transport-agnostic.

mod common;
mod diagnose;
mod discovery;
mod logs;
mod read;
mod rows;
mod service;
mod storage;

use std::sync::Arc;

use jiff::Timestamp;
use k8s_mcp_core::cluster::ClusterManager;
pub use k8s_mcp_core::envelope::Envelope;
use k8s_mcp_core::policy::Policy;
use k8s_mcp_core::redact::Redactor;

pub use diagnose::{
    DiagnoseNodeInput, DiagnosePodInput, DiagnoseWorkloadInput, FindProblemsInput, diagnose_node,
    diagnose_pod, diagnose_workload, find_problems,
};
pub use logs::{GetLogsInput, get_logs};
pub use read::{
    ApiResourcesInput, CheckPermissionsInput, ClusterOverviewInput, GetResourceInput,
    ListContextsInput, ListEventsInput, ListResourcesInput, TopInput, api_resources,
    check_permissions, cluster_overview, get_resource, list_contexts, list_events, list_resources,
    top,
};
pub use service::{DiagnoseServiceInput, diagnose_service};
pub use storage::{DiagnosePvcInput, diagnose_pvc};

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
}

impl Ctx {
    /// A context using the system clock and the policy's redaction level.
    pub fn new(clusters: Arc<ClusterManager>, policy: Arc<Policy>) -> Self {
        Self {
            clusters,
            redactor: Redactor::new(policy.redact),
            policy,
            clock: Arc::new(Timestamp::now),
        }
    }

    /// Current time.
    pub fn now(&self) -> Timestamp {
        (self.clock)()
    }
}
