//! Evidence bundles gathered by the tools crate and handed to the pure rule engine.
//!
//! Anything that could not be gathered (missing RBAC, API errors) is recorded in
//! `unavailable` and the corresponding field is left empty/`None`; rules must then lower
//! their confidence instead of failing.

use jiff::Timestamp;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;
use k8s_openapi::api::batch::v1::{CronJob, Job};
use k8s_openapi::api::core::v1::{
    Event, Node, PersistentVolumeClaim, Pod, ResourceQuota, ServiceAccount,
};

/// A piece of evidence that could not be gathered, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unavailable {
    /// What was attempted, e.g. `previous logs of container app`.
    pub what: String,
    /// Why it failed, e.g. `forbidden: cannot get pods/log`.
    pub reason: String,
}

/// Log tail of one container (already ANSI-stripped and redacted).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainerLog {
    /// Container name.
    pub container: String,
    /// True if this is the previous (crashed) instance.
    pub previous: bool,
    /// Lines, oldest first.
    pub lines: Vec<String>,
}

/// Kind of an object referenced from a pod spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefKind {
    /// ConfigMap (env, envFrom, volume, projected).
    ConfigMap,
    /// Secret (env, envFrom, volume, projected, imagePullSecrets).
    Secret,
    /// PersistentVolumeClaim volume.
    PersistentVolumeClaim,
    /// The pod's ServiceAccount.
    ServiceAccount,
}

/// Existence check of a referenced object (metadata only; Secret values are never read).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefCheck {
    /// Kind of object.
    pub kind: RefKind,
    /// Object name (in the pod's namespace).
    pub name: String,
    /// `Some(true/false)` when checked, `None` when the check was not permitted.
    pub exists: Option<bool>,
    /// Key names (ConfigMap/Secret), when the object exists and was readable.
    pub keys: Option<Vec<String>>,
}

/// Everything `diagnose_pod` knows about one pod.
#[derive(Debug, Clone, Default)]
pub struct PodEvidence {
    /// The pod.
    pub pod: Pod,
    /// Events whose involvedObject is this pod (last hour).
    pub events: Vec<Event>,
    /// At most one log tail per container (`previous` if it restarted).
    pub logs: Vec<ContainerLog>,
    /// The node the pod runs on, if scheduled and readable.
    pub node: Option<Node>,
    /// All nodes, for scheduling-fit checks. `None` if not readable.
    pub nodes: Option<Vec<Node>>,
    /// Existence of referenced ConfigMaps, Secrets, PVCs and the ServiceAccount.
    pub refs: Vec<RefCheck>,
    /// PVCs mounted by the pod (that exist).
    pub pvcs: Vec<PersistentVolumeClaim>,
    /// The pod's ServiceAccount (for imagePullSecrets), if readable.
    pub service_account: Option<ServiceAccount>,
    /// Evidence that could not be gathered.
    pub unavailable: Vec<Unavailable>,
    /// Current time (injected for determinism).
    pub now: Timestamp,
}

/// A controller object.
#[allow(clippy::large_enum_variant)] // built once per call; boxing would only add noise
#[derive(Debug, Clone)]
pub enum Workload {
    /// apps/v1 Deployment.
    Deployment(Deployment),
    /// apps/v1 StatefulSet.
    StatefulSet(StatefulSet),
    /// apps/v1 DaemonSet.
    DaemonSet(DaemonSet),
    /// apps/v1 ReplicaSet.
    ReplicaSet(ReplicaSet),
    /// batch/v1 Job.
    Job(Job),
    /// batch/v1 CronJob.
    CronJob(CronJob),
}

impl Default for Workload {
    fn default() -> Self {
        Self::Deployment(Deployment::default())
    }
}

/// Everything `diagnose_workload` knows about one workload.
#[derive(Debug, Clone, Default)]
pub struct WorkloadEvidence {
    /// The workload.
    pub workload: Workload,
    /// ReplicaSets owned by a Deployment (newest first).
    pub replicasets: Vec<ReplicaSet>,
    /// Jobs owned by a CronJob (newest first).
    pub jobs: Vec<Job>,
    /// Events for the workload and its ReplicaSets/Jobs (last hour).
    pub events: Vec<Event>,
    /// Evidence for representative pods (failing pods first).
    pub pods: Vec<PodEvidence>,
    /// Pods selected by the workload, when known (`None` when they were not listed).
    pub pod_count: Option<usize>,
    /// ResourceQuotas in the namespace.
    pub quotas: Vec<ResourceQuota>,
    /// HPA targeting the workload, if any.
    pub hpa: Option<HorizontalPodAutoscaler>,
    /// Evidence that could not be gathered.
    pub unavailable: Vec<Unavailable>,
    /// Current time.
    pub now: Timestamp,
}

/// Everything `diagnose_node` knows about one node.
#[derive(Debug, Clone, Default)]
pub struct NodeEvidence {
    /// The node.
    pub node: Node,
    /// Events whose involvedObject is this node (last hour).
    pub events: Vec<Event>,
    /// Pods scheduled on the node, if readable.
    pub pods: Option<Vec<Pod>>,
    /// API server version as (major, minor), if known.
    pub server_version: Option<(u32, u32)>,
    /// Evidence that could not be gathered.
    pub unavailable: Vec<Unavailable>,
    /// Current time.
    pub now: Timestamp,
}
