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
    Event, Node, PersistentVolume, PersistentVolumeClaim, Pod, ResourceQuota, Service,
    ServiceAccount,
};
use k8s_openapi::api::networking::v1::NetworkPolicy;
use k8s_openapi::api::storage::v1::StorageClass;

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

/// Everything `diagnose_service` knows about one Service.
#[derive(Debug, Clone, Default)]
pub struct ServiceEvidence {
    /// The Service.
    pub service: Service,
    /// Pods in the Service's namespace (the rules apply its selector); `None` if unreadable.
    pub pods: Option<Vec<Pod>>,
    /// Events whose involvedObject is the Service (last hour).
    pub events: Vec<Event>,
    /// Evidence that could not be gathered.
    pub unavailable: Vec<Unavailable>,
    /// Current time.
    pub now: Timestamp,
}

/// Everything `diagnose_pvc` knows about one PersistentVolumeClaim.
#[derive(Debug, Clone, Default)]
pub struct PvcEvidence {
    /// The claim.
    pub pvc: PersistentVolumeClaim,
    /// All StorageClasses (to find the named or default one); `None` if unreadable.
    pub storage_classes: Option<Vec<StorageClass>>,
    /// The bound PersistentVolume, if any and readable.
    pub pv: Option<PersistentVolume>,
    /// Events whose involvedObject is the claim (last hour).
    pub events: Vec<Event>,
    /// Pods in the namespace that mount the claim.
    pub pods: Vec<Pod>,
    /// Events of those pods (attach, mount and scheduling failures).
    pub pod_events: Vec<Event>,
    /// Evidence that could not be gathered.
    pub unavailable: Vec<Unavailable>,
    /// Current time.
    pub now: Timestamp,
}

/// Everything `diagnose_dns` knows about the DNS path of a pod (or of a namespace).
#[derive(Debug, Clone, Default)]
pub struct DnsEvidence {
    /// The pod being checked, if one was named.
    pub pod: Option<Pod>,
    /// The namespace being checked (the pod's).
    pub namespace: String,
    /// Log tails of the pod's containers.
    pub pod_logs: Vec<ContainerLog>,
    /// NetworkPolicies in the namespace; `None` if unreadable.
    pub network_policies: Option<Vec<NetworkPolicy>>,
    /// Cluster DNS pods (`k8s-app=kube-dns` in kube-system); `None` if unreadable.
    pub dns_pods: Option<Vec<Pod>>,
    /// The kube-dns Service: `Some(None)` when it does not exist, `None` if unreadable.
    pub dns_service: Option<Option<Service>>,
    /// Ready endpoints in the kube-dns EndpointSlices; `None` if unreadable.
    pub dns_ready_endpoints: Option<usize>,
    /// Recent log lines of the cluster DNS pods.
    pub dns_logs: Vec<ContainerLog>,
    /// Evidence that could not be gathered.
    pub unavailable: Vec<Unavailable>,
    /// Current time.
    pub now: Timestamp,
}

/// Everything `autoscaling_status` knows about the cluster's autoscalers.
#[derive(Debug, Clone, Default)]
pub struct AutoscalingEvidence {
    /// Karpenter NodePools (`karpenter.sh/v1`) as JSON; `None` when Karpenter is absent or
    /// unreadable.
    pub nodepools: Option<Vec<serde_json::Value>>,
    /// Karpenter NodeClaims (`karpenter.sh/v1`) as JSON.
    pub nodeclaims: Vec<serde_json::Value>,
    /// The Cluster Autoscaler status (ConfigMap `cluster-autoscaler-status`, key `status`,
    /// parsed from YAML); `None` when there is none.
    pub ca_status: Option<serde_json::Value>,
    /// HorizontalPodAutoscalers in the allowed namespaces; `None` if unreadable.
    pub hpas: Option<Vec<HorizontalPodAutoscaler>>,
    /// Recent `NotTriggerScaleUp` events (pods the Cluster Autoscaler would not scale up for).
    pub events: Vec<Event>,
    /// Evidence that could not be gathered.
    pub unavailable: Vec<Unavailable>,
    /// Current time.
    pub now: Timestamp,
}

/// A deprecated API version: requested by clients (the API server's
/// `apiserver_requested_deprecated_apis` metric), or a CRD version marked `deprecated`.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeprecatedApi {
    /// API group (`""` for core).
    pub group: String,
    /// Version, e.g. `v1beta1`.
    pub version: String,
    /// Plural resource, e.g. `flowschemas`.
    pub resource: String,
    /// Minor version that removes it (`1.32` becomes 32); `None` when no removal is planned
    /// (or, for CRDs, when the CRD owner decides).
    pub removed_in: Option<u32>,
    /// What to use instead, when known.
    pub replacement: Option<String>,
    /// A custom resource version.
    pub crd: bool,
}

impl DeprecatedApi {
    /// `group/version`, or `version` for the core group.
    pub fn group_version(&self) -> String {
        if self.group.is_empty() {
            self.version.clone()
        } else {
            format!("{}/{}", self.group, self.version)
        }
    }
}

/// An object last written with a deprecated API version: a `managedFields` entry or the
/// `kubectl.kubernetes.io/last-applied-configuration` annotation names it.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct StaleWrite {
    /// The deprecated API it was written with.
    pub api: DeprecatedApi,
    /// Object kind.
    pub kind: String,
    /// Namespace, when namespaced.
    pub namespace: Option<String>,
    /// Object name.
    pub name: String,
    /// Field manager (client-supplied text), or `kubectl apply` for the annotation.
    pub manager: String,
}

/// Everything `upgrade_readiness` knows about upgrading the control plane to `target`.
#[derive(Debug, Clone, Default)]
pub struct UpgradeEvidence {
    /// Control-plane minor version now (`1.33` is 33).
    pub current: u32,
    /// Minor version to upgrade to.
    pub target: u32,
    /// Deprecated APIs clients requested since the API server started; `None` if the metric
    /// could not be read.
    pub requested: Option<Vec<DeprecatedApi>>,
    /// Served CRD versions marked deprecated.
    pub deprecated_crd_versions: Vec<DeprecatedApi>,
    /// Objects last written with a deprecated API version.
    pub stale_writes: Vec<StaleWrite>,
    /// Nodes (kubelet versions); `None` if unreadable.
    pub nodes: Option<Vec<Node>>,
    /// PodDisruptionBudgets in the allowed namespaces; `None` if unreadable.
    pub pdbs: Option<Vec<k8s_openapi::api::policy::v1::PodDisruptionBudget>>,
    /// Deployments in the allowed namespaces; `None` if unreadable.
    pub deployments: Option<Vec<Deployment>>,
    /// StatefulSets in the allowed namespaces; `None` if unreadable.
    pub statefulsets: Option<Vec<StatefulSet>>,
    /// The managed cluster's cloud (`EKS`, ...) and when standard support of the current
    /// version ends (Unix seconds), when a provider says.
    pub support_ends: Option<(String, i64)>,
    /// Evidence that could not be gathered.
    pub unavailable: Vec<Unavailable>,
    /// Current time.
    pub now: Timestamp,
}
