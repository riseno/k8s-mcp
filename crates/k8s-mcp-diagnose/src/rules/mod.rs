//! Detection rules, one module per area (PROPOSAL §9.2). Each module exposes `RULES`
//! (metadata for every id it can emit) and one or more `check` functions.
//!
//! Conventions for rule authors:
//! - Put cluster-supplied text (event messages, log lines) only in evidence with
//!   `Source::Event` / `Source::Log`; the renderer wraps those as untrusted. Never copy it
//!   into `title` or `fix`.
//! - Names parsed out of messages must pass [`dns_name`].
//! - Confidence is `High` only for definitive status fields or event reasons.

pub mod config;
pub mod crashloop;
pub mod creating;
pub mod dns;
pub mod image;
pub mod init;
pub mod node;
pub mod oom;
pub mod pending;
pub mod probe;
pub mod rollout;
pub mod terminating;

use std::collections::BTreeMap;

use jiff::Timestamp;
use k8s_mcp_core::finding::RuleMeta;
use k8s_mcp_core::quantity::{bytes, cpu_millis, fmt_bytes};
use k8s_mcp_core::text::{age, truncate};
use k8s_openapi::api::core::v1::{Container, ContainerStatus, Event, Node, Pod, PodCondition};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use serde_json::{Value, json};

/// Kubernetes docs links shared by rules.
pub mod docs {
    /// Debugging pods.
    pub const DEBUG_PODS: &str =
        "https://kubernetes.io/docs/tasks/debug/debug-application/debug-pods/";
    /// Container restart policy and states.
    pub const LIFECYCLE: &str = "https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/";
    /// Memory requests and limits.
    pub const MEMORY: &str =
        "https://kubernetes.io/docs/tasks/configure-pod-container/assign-memory-resource/";
    /// Images and pulling.
    pub const IMAGES: &str = "https://kubernetes.io/docs/concepts/containers/images/";
    /// Pulling from a private registry.
    pub const PULL_SECRET: &str =
        "https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/";
    /// Probes.
    pub const PROBES: &str = "https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/";
    /// Scheduling: taints and tolerations.
    pub const TAINTS: &str =
        "https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/";
    /// Scheduling: assigning pods to nodes.
    pub const AFFINITY: &str =
        "https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/";
    /// Resource management.
    pub const RESOURCES: &str =
        "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/";
    /// Topology spread.
    pub const TOPOLOGY: &str =
        "https://kubernetes.io/docs/concepts/scheduling-eviction/topology-spread-constraints/";
    /// Persistent volumes.
    pub const PV: &str = "https://kubernetes.io/docs/concepts/storage/persistent-volumes/";
    /// Resource quotas.
    pub const QUOTA: &str = "https://kubernetes.io/docs/concepts/policy/resource-quotas/";
    /// ConfigMaps.
    pub const CONFIGMAP: &str = "https://kubernetes.io/docs/concepts/configuration/configmap/";
    /// Secrets.
    pub const SECRET: &str = "https://kubernetes.io/docs/concepts/configuration/secret/";
    /// Service accounts.
    pub const SERVICE_ACCOUNT: &str =
        "https://kubernetes.io/docs/concepts/security/service-accounts/";
    /// Init containers.
    pub const INIT: &str = "https://kubernetes.io/docs/concepts/workloads/pods/init-containers/";
    /// Node-pressure eviction.
    pub const EVICTION: &str =
        "https://kubernetes.io/docs/concepts/scheduling-eviction/node-pressure-eviction/";
    /// Finalizers.
    pub const FINALIZERS: &str =
        "https://kubernetes.io/docs/concepts/overview/working-with-objects/finalizers/";
    /// Deployments.
    pub const DEPLOYMENT: &str =
        "https://kubernetes.io/docs/concepts/workloads/controllers/deployment/";
    /// Jobs.
    pub const JOB: &str = "https://kubernetes.io/docs/concepts/workloads/controllers/job/";
    /// CronJobs.
    pub const CRONJOB: &str =
        "https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/";
    /// Nodes.
    pub const NODES: &str = "https://kubernetes.io/docs/concepts/architecture/nodes/";
    /// Version skew policy.
    pub const SKEW: &str = "https://kubernetes.io/releases/version-skew-policy/";
    /// DNS debugging.
    pub const DNS: &str =
        "https://kubernetes.io/docs/tasks/administer-cluster/dns-debugging-resolution/";
    /// Pod Security Admission.
    pub const PSA: &str = "https://kubernetes.io/docs/concepts/security/pod-security-admission/";
    /// Network plugins.
    pub const NETWORK: &str = "https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/";
}

/// Pod name and namespace.
pub fn pod_ref(pod: &Pod) -> (&str, &str) {
    (
        pod.metadata.name.as_deref().unwrap_or(""),
        pod.metadata.namespace.as_deref().unwrap_or("default"),
    )
}

/// `{"name": .., "namespace": ..}` for `next` suggestions.
pub fn pod_args(pod: &Pod) -> Value {
    let (name, ns) = pod_ref(pod);
    json!({ "name": name, "namespace": ns })
}

/// `{"pod": .., "namespace": .., ...extra}` for `get_logs` suggestions.
pub fn logs_args(pod: &Pod, container: &str, previous: bool) -> Value {
    let (name, ns) = pod_ref(pod);
    json!({ "pod": name, "namespace": ns, "container": container, "previous": previous, "tail": 200 })
}

/// Main containers paired with their status.
pub fn containers(pod: &Pod) -> Vec<(&Container, Option<&ContainerStatus>)> {
    let spec = pod
        .spec
        .as_ref()
        .map(|s| s.containers.as_slice())
        .unwrap_or_default();
    let statuses = pod
        .status
        .as_ref()
        .and_then(|s| s.container_statuses.as_deref())
        .unwrap_or_default();
    pair(spec, statuses)
}

/// Init containers paired with their status.
pub fn init_containers(pod: &Pod) -> Vec<(&Container, Option<&ContainerStatus>)> {
    let spec = pod
        .spec
        .as_ref()
        .and_then(|s| s.init_containers.as_deref())
        .unwrap_or_default();
    let statuses = pod
        .status
        .as_ref()
        .and_then(|s| s.init_container_statuses.as_deref())
        .unwrap_or_default();
    pair(spec, statuses)
}

/// Init containers then main containers, each paired with its status.
pub fn all_containers(pod: &Pod) -> Vec<(&Container, Option<&ContainerStatus>)> {
    let mut v = init_containers(pod);
    v.extend(containers(pod));
    v
}

fn pair<'a>(
    spec: &'a [Container],
    statuses: &'a [ContainerStatus],
) -> Vec<(&'a Container, Option<&'a ContainerStatus>)> {
    spec.iter()
        .map(|c| (c, statuses.iter().find(|s| s.name == c.name)))
        .collect()
}

/// Waiting reason of a container status.
pub fn waiting_reason(st: &ContainerStatus) -> Option<&str> {
    st.state.as_ref()?.waiting.as_ref()?.reason.as_deref()
}

/// Waiting message of a container status.
pub fn waiting_message(st: &ContainerStatus) -> Option<&str> {
    st.state.as_ref()?.waiting.as_ref()?.message.as_deref()
}

/// Pod phase.
pub fn phase(pod: &Pod) -> &str {
    pod.status
        .as_ref()
        .and_then(|s| s.phase.as_deref())
        .unwrap_or("Unknown")
}

/// Pod condition of `type_`.
pub fn pod_condition<'a>(pod: &'a Pod, type_: &str) -> Option<&'a PodCondition> {
    pod.status
        .as_ref()?
        .conditions
        .as_ref()?
        .iter()
        .find(|c| c.type_ == type_)
}

/// Docs URL registered for `id` in `rules` (empty if unregistered, which tests rule out).
pub fn rule_docs(rules: &[RuleMeta], id: &str) -> &'static str {
    rules.iter().find(|r| r.id == id).map_or("", |r| r.docs)
}

/// `{"kind": .., "name": .., "namespace": ..}` for `get_resource` suggestions.
pub fn resource_args(kind: &str, name: &str, namespace: &str) -> Value {
    json!({ "kind": kind, "name": name, "namespace": namespace })
}

/// `{"namespace": .., "involved_kind": "Pod", "involved_name": ..}` for `list_events` suggestions.
pub fn pod_events_args(pod: &Pod) -> Value {
    let (name, ns) = pod_ref(pod);
    json!({ "namespace": ns, "involved_kind": "Pod", "involved_name": name })
}

/// Event message (empty if absent).
pub fn msg(e: &Event) -> &str {
    e.message.as_deref().unwrap_or("")
}

/// Event reason (empty if absent).
pub fn reason(e: &Event) -> &str {
    e.reason.as_deref().unwrap_or("")
}

/// Events with one of `reasons`.
pub fn events_with<'a>(
    events: &'a [Event],
    reasons: &'a [&str],
) -> impl Iterator<Item = &'a Event> {
    events.iter().filter(move |e| reasons.contains(&reason(e)))
}

/// True if `e` is about container `name` (by involvedObject.fieldPath), or names no container.
pub fn about_container(e: &Event, name: &str) -> bool {
    e.involved_object
        .field_path
        .as_deref()
        .is_none_or(|p| p.ends_with(&format!("{{{name}}}")))
}

/// The most recently seen of `events`.
pub fn latest<'a>(events: impl Iterator<Item = &'a Event>) -> Option<&'a Event> {
    events.max_by_key(|e| last_seen(e))
}

/// Most recent time an event was seen.
pub fn last_seen(e: &Event) -> Option<Timestamp> {
    e.last_timestamp
        .as_ref()
        .map(|t| t.0)
        .or_else(|| {
            e.series
                .as_ref()
                .and_then(|s| s.last_observed_time.as_ref())
                .map(|t| t.0)
        })
        .or_else(|| e.event_time.as_ref().map(|t| t.0))
        .or_else(|| e.first_timestamp.as_ref().map(|t| t.0))
}

/// Total occurrences of an event.
pub fn count(e: &Event) -> i32 {
    e.series
        .as_ref()
        .and_then(|s| s.count)
        .or(e.count)
        .unwrap_or(1)
        .max(1)
}

/// Quote an event for evidence: `×9 BackOff: Back-off restarting … (last 40s ago)`.
pub fn quote_event(e: &Event, now: Timestamp) -> String {
    let ago = last_seen(e)
        .map(|t| format!(" (last {} ago)", age(now, t)))
        .unwrap_or_default();
    format!(
        "×{} {}: {}{ago}",
        count(e),
        reason(e),
        truncate(msg(e), 300)
    )
}

/// True if `s` is a valid DNS-1123 subdomain (safe to echo as an object name).
pub fn dns_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

/// Lines of `log` matching an application error pattern, last `n` of them.
pub fn error_lines(lines: &[String], n: usize) -> Vec<String> {
    static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        #[allow(clippy::unwrap_used)]
        regex::Regex::new(r"(?i)\b(panic|panicked|error|exception|fatal|traceback|segmentation fault|caused by|failed)\b").unwrap()
    });
    let mut v: Vec<String> = lines.iter().filter(|l| RE.is_match(l)).cloned().collect();
    let start = v.len().saturating_sub(n);
    v.drain(..start);
    v
}

/// Restart policy of a pod (`Always` when unset).
pub fn restart_policy(pod: &Pod) -> &str {
    pod.spec
        .as_ref()
        .and_then(|s| s.restart_policy.as_deref())
        .unwrap_or("Always")
}

/// True if the kubelet restarted `container` because a liveness or startup probe failed.
pub fn probe_killed(events: &[Event], container: &str) -> bool {
    events.iter().any(|e| {
        let m = msg(e);
        let mentions = m.contains(&format!("Container {container} ")) || !m.contains("Container ");
        reason(e) == "Killing"
            && (m.contains("failed liveness probe") || m.contains("failed startup probe"))
            && mentions
    })
}

/// Last termination of a container (lastState, else current state).
pub fn last_termination(
    st: &ContainerStatus,
) -> Option<&k8s_openapi::api::core::v1::ContainerStateTerminated> {
    st.last_state
        .as_ref()
        .and_then(|s| s.terminated.as_ref())
        .or_else(|| st.state.as_ref().and_then(|s| s.terminated.as_ref()))
}

/// Describe a termination: `reason=Error exitCode=1 (4m ago)`.
pub fn describe_termination(
    t: &k8s_openapi::api::core::v1::ContainerStateTerminated,
    now: Timestamp,
) -> String {
    let ago = t
        .finished_at
        .as_ref()
        .map(|f| format!(" ({} ago)", age(now, f.0)))
        .unwrap_or_default();
    format!(
        "reason={} exitCode={}{}{ago}",
        t.reason.as_deref().unwrap_or("-"),
        t.exit_code,
        t.signal.map(|s| format!(" signal={s}")).unwrap_or_default()
    )
}

/// Seconds from `then` to `now` (negative if `then` is in the future).
pub fn secs_since(now: Timestamp, then: Timestamp) -> i64 {
    now.duration_since(then).as_secs()
}

/// Parse a resource quantity: CPU in millicores, anything else (memory, storage,
/// extended resources such as `nvidia.com/gpu`) as a plain number of bytes/units.
pub fn quantity(resource: &str, q: &Quantity) -> Option<i64> {
    if resource == "cpu" {
        cpu_millis(&q.0)
    } else {
        bytes(&q.0)
    }
}

/// Render a value from [`quantity`]: `64` or `500m` CPU, `128Mi`, or a plain count.
pub fn fmt_quantity(resource: &str, v: i64) -> String {
    match resource {
        "cpu" if v % 1000 == 0 => format!("{}", v / 1000),
        "cpu" => format!("{v}m"),
        r if r == "memory" || r == "ephemeral-storage" || r.starts_with("hugepages-") => {
            fmt_bytes(v)
        }
        _ => v.to_string(),
    }
}

fn requests(c: &Container) -> impl Iterator<Item = (&String, i64)> {
    c.resources
        .as_ref()
        .and_then(|r| r.requests.as_ref())
        .into_iter()
        .flatten()
        .filter_map(|(k, q)| Some((k, quantity(k, q)?)))
}

/// Effective resource requests of a pod as the scheduler sees them: the larger of the
/// main containers' sum and the largest init container, plus pod overhead.
// ponytail: restartable (sidecar) init containers are treated like plain init containers,
// so their requests are not added to the main sum; add them if sidecar-heavy pods misfit.
pub fn pod_requests(pod: &Pod) -> BTreeMap<String, i64> {
    let mut out: BTreeMap<String, i64> = BTreeMap::new();
    let Some(spec) = pod.spec.as_ref() else {
        return out;
    };
    for (k, v) in spec.containers.iter().flat_map(requests) {
        *out.entry(k.clone()).or_default() += v;
    }
    for (k, v) in spec.init_containers.iter().flatten().flat_map(requests) {
        let e = out.entry(k.clone()).or_default();
        *e = (*e).max(v);
    }
    for (k, q) in spec.overhead.iter().flatten() {
        if let Some(v) = quantity(k, q) {
            *out.entry(k.clone()).or_default() += v;
        }
    }
    out
}

/// Allocatable resources of a node (units as in [`quantity`]).
pub fn allocatable(node: &Node) -> BTreeMap<String, i64> {
    node.status
        .as_ref()
        .and_then(|s| s.allocatable.as_ref())
        .into_iter()
        .flatten()
        .filter_map(|(k, q)| Some((k.clone(), quantity(k, q)?)))
        .collect()
}

/// Node name (empty if absent).
pub fn node_name(node: &Node) -> &str {
    node.metadata.name.as_deref().unwrap_or("")
}

/// The pod's ServiceAccount name (`default` when unset).
pub fn service_account_name(pod: &Pod) -> &str {
    pod.spec
        .as_ref()
        .and_then(|s| s.service_account_name.as_deref())
        .unwrap_or("default")
}
