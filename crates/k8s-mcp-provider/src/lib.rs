#![forbid(unsafe_code)]
//! The cloud provider contract (ADR 0006): the [`Provider`] trait, the cloud-neutral types
//! every provider fills in, and their rendering into envelopes, so EKS, GKE and AKS tools have
//! the same output shape. Detection lives in `k8s_mcp_core::provider` (ADR 0010).

use std::collections::BTreeMap;
use std::future::Future;

use k8s_mcp_core::Result;
use k8s_mcp_core::envelope::Envelope;
use k8s_mcp_core::finding::{Finding, rank};
use k8s_mcp_core::provider::ProviderId;
use serde_json::json;

/// The managed cluster as its cloud describes it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClusterInfo {
    /// Cluster name.
    pub name: String,
    /// Kubernetes version.
    pub version: String,
    /// Cloud-side status, e.g. `ACTIVE`.
    pub status: String,
    /// Provider-specific facts (platform version, endpoint access, auth mode, OIDC issuer...).
    pub details: BTreeMap<String, String>,
}

/// A node group or pool managed by the cloud.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodePool {
    /// Name.
    pub name: String,
    /// `managed`, `fargate`, ...
    pub kind: String,
    /// Cloud-side status.
    pub status: String,
    /// Kubernetes version of its nodes.
    pub version: String,
    /// `desired (min-max)`.
    pub size: String,
    /// Instance types and capacity type.
    pub machine: String,
}

/// An add-on installed by the cloud.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Addon {
    /// Name.
    pub name: String,
    /// Installed version.
    pub version: String,
    /// Cloud-side status.
    pub status: String,
    /// Newest version compatible with the cluster's Kubernetes version, when known.
    pub latest: String,
}

/// Who the cloud maps to Kubernetes identities.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccessMapping {
    /// Cloud principal (role or user).
    pub principal: String,
    /// Where the mapping comes from, e.g. `access entry` or `aws-auth`.
    pub source: String,
    /// Kubernetes username.
    pub username: String,
    /// Kubernetes groups and access policies.
    pub grants: Vec<String>,
    /// Cluster-admin: `system:masters` or a cluster-scoped admin policy.
    pub cluster_admin: bool,
}

/// One step of a workload identity check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityCheck {
    /// `kubernetes` or the cloud's name.
    pub side: &'static str,
    /// What was checked.
    pub check: String,
    /// `ok`, `fail` (configured and wrong), `not configured` or `skipped` (not checkable).
    pub result: &'static str,
    /// What was found.
    pub detail: String,
}

/// A workload identity check: every step, plus whether the cloud half ran.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentityReport {
    /// The steps, Kubernetes side first.
    pub checks: Vec<IdentityCheck>,
    /// `done`, or `skipped: <reason>` when the cloud could not be asked.
    pub cloud_checks: String,
}

/// Log lines from the cloud's logging service.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CloudLogs {
    /// Where they came from (log group and filter).
    pub source: String,
    /// Lines, oldest first, already redacted by the caller.
    pub lines: Vec<String>,
    /// More lines matched than were returned.
    pub truncated: bool,
}

/// A provider's answer: rows plus findings.
pub type Report<T> = (T, Vec<Finding>);

/// What every provider module implements (ADR 0006: dispatched through an enum, not `dyn`).
pub trait Provider {
    /// Which provider.
    fn id(&self) -> ProviderId;
    /// The cluster as the cloud describes it.
    fn cluster_info(&self) -> impl Future<Output = Result<Report<ClusterInfo>>> + Send;
    /// Node groups or pools.
    fn node_pools(&self) -> impl Future<Output = Result<Report<Vec<NodePool>>>> + Send;
    /// Installed add-ons, with the newest compatible versions.
    fn addons(&self) -> impl Future<Output = Result<Report<Vec<Addon>>>> + Send;
    /// Cloud principals mapped into the cluster.
    fn access(&self) -> impl Future<Output = Result<Report<Vec<AccessMapping>>>> + Send;
    /// The cloud identity of a ServiceAccount: the Kubernetes side always, the cloud side when
    /// credentials allow (otherwise `cloud_checks` says why it was skipped).
    fn identity_check(
        &self,
        k8s: &WorkloadIdentity,
    ) -> impl Future<Output = Report<IdentityReport>> + Send;
    /// Lines from the cloud's logging service.
    fn logs(&self, q: &LogQuery) -> impl Future<Output = Result<CloudLogs>> + Send;
}

/// The Kubernetes side of a workload identity check, gathered by the caller.
#[derive(Debug, Clone, Default)]
pub struct WorkloadIdentity {
    /// The ServiceAccount.
    pub service_account: k8s_openapi::api::core::v1::ServiceAccount,
    /// Pods running as it.
    pub pods: Vec<k8s_openapi::api::core::v1::Pod>,
    /// Whether the provider's identity agent (DaemonSet) runs and is ready; `None` if unknown.
    pub agent_ready: Option<bool>,
}

/// What `logs` should return.
#[derive(Debug, Clone, Default)]
pub struct LogQuery {
    /// `control-plane` or `application`.
    pub source: String,
    /// Control-plane component (`api`, `audit`, `authenticator`, `controllerManager`, `scheduler`).
    pub component: Option<String>,
    /// Application logs of this namespace.
    pub namespace: Option<String>,
    /// Application logs of this pod.
    pub pod: Option<String>,
    /// Text that lines must contain.
    pub grep: Option<String>,
    /// Start of the window, as Unix milliseconds.
    pub since_ms: i64,
    /// Most lines to return.
    pub limit: i32,
}

fn with_findings(mut e: Envelope, mut findings: Vec<Finding>) -> Envelope {
    rank(&mut findings);
    e.findings = findings;
    e
}

fn top(findings: &[Finding]) -> String {
    findings
        .iter()
        .min_by_key(|f| (f.severity, f.confidence))
        .map_or_else(
            || "; no problems found by the provider rules.".into(),
            |f| format!(". Top finding: {}.", f.title),
        )
}

/// `<provider>_cluster_info`.
pub fn cluster_info_envelope(p: ProviderId, (info, findings): Report<ClusterInfo>) -> Envelope {
    let mut e = Envelope::new(format!(
        "{} cluster {}: Kubernetes {}, status {}{}",
        p.as_str().to_uppercase(),
        info.name,
        info.version,
        info.status,
        top(&findings)
    ));
    e.columns = vec!["field", "value"];
    e.items = info
        .details
        .iter()
        .map(|(k, v)| json!({"field": k, "value": v}))
        .collect();
    with_findings(e, findings)
}

/// `<provider>_nodegroups` / `_node_pools`.
pub fn node_pools_envelope(p: ProviderId, (pools, findings): Report<Vec<NodePool>>) -> Envelope {
    let mut e = Envelope::new(format!(
        "{} {} node pools{}",
        p.as_str().to_uppercase(),
        pools.len(),
        top(&findings)
    ));
    e.columns = vec!["name", "kind", "status", "version", "size", "machine"];
    e.items = pools
        .iter()
        .map(|n| json!({"name": n.name, "kind": n.kind, "status": n.status, "version": n.version, "size": n.size, "machine": n.machine}))
        .collect();
    with_findings(e, findings)
}

/// `<provider>_addons`.
pub fn addons_envelope(p: ProviderId, (addons, findings): Report<Vec<Addon>>) -> Envelope {
    let mut e = Envelope::new(format!(
        "{} {} add-ons{}",
        p.as_str().to_uppercase(),
        addons.len(),
        top(&findings)
    ));
    e.columns = vec!["name", "version", "status", "latest"];
    e.items = addons
        .iter()
        .map(|a| json!({"name": a.name, "version": a.version, "status": a.status, "latest": a.latest}))
        .collect();
    with_findings(e, findings)
}

/// `<provider>_access`.
pub fn access_envelope(
    p: ProviderId,
    (mappings, findings): Report<Vec<AccessMapping>>,
) -> Envelope {
    let admins = mappings.iter().filter(|m| m.cluster_admin).count();
    let mut e = Envelope::new(format!(
        "{} {} principals mapped into the cluster, {admins} with cluster-admin{}",
        p.as_str().to_uppercase(),
        mappings.len(),
        top(&findings)
    ));
    e.columns = vec!["principal", "source", "username", "grants", "admin"];
    e.items = mappings
        .iter()
        .map(|m| json!({"principal": m.principal, "source": m.source, "username": m.username, "grants": m.grants.join(","), "admin": m.cluster_admin}))
        .collect();
    with_findings(e, findings)
}

/// `<provider>_identity_check`.
pub fn identity_envelope(
    p: ProviderId,
    subject: &str,
    (report, findings): Report<IdentityReport>,
) -> Envelope {
    let count = |r: &str| report.checks.iter().filter(|c| c.result == r).count();
    let tally: Vec<String> = [
        ("ok", "passed"),
        ("fail", "failed"),
        ("not configured", "not configured"),
        ("skipped", "skipped"),
    ]
    .iter()
    .filter_map(|(r, label)| {
        let n = count(r);
        (n > 0).then(|| format!("{n} {label}"))
    })
    .collect();
    let unseen = if count("ok") + count("fail") == 0 {
        ": no cloud identity that k8s-mcp can see"
    } else {
        ""
    };
    let mut e = Envelope::new(format!(
        "{} identity of {subject}: {} checks ({}){unseen}; cloud checks {}{}",
        p.as_str().to_uppercase(),
        report.checks.len(),
        tally.join(", "),
        report.cloud_checks,
        top(&findings)
    ));
    e.columns = vec!["side", "check", "result", "detail"];
    e.items = report
        .checks
        .iter()
        .map(|c| json!({"side": c.side, "check": c.check, "result": c.result, "detail": c.detail}))
        .collect();
    with_findings(e, findings)
}

/// `<provider>_logs`: the lines are cloud-held log text, so the section is untrusted.
pub fn logs_envelope(p: ProviderId, logs: CloudLogs) -> Envelope {
    let mut e = Envelope::new(format!(
        "{} {} log lines from {}{}",
        p.as_str().to_uppercase(),
        logs.lines.len(),
        logs.source,
        if logs.truncated {
            " (more matched: narrow with grep, since or limit)"
        } else {
            ""
        }
    ));
    // Truncation happened on the cloud side (the summary says so), not by the size cap.
    e.sections.push(k8s_mcp_core::envelope::Section {
        title: format!("LOGS ({})", logs.source),
        lines: logs.lines,
        untrusted: Some(vec![("source".into(), "log".into())]),
    });
    e.untrusted_fields = vec!["sections[?(@.untrusted)].lines".into()];
    e
}
