//! Upgrade readiness (PROPOSAL §8.1, v0.3): is the cluster ready for the next control-plane
//! minor? Deprecated and removed APIs still in use, kubelets that the target leaves too far
//! behind, PodDisruptionBudgets that block node drains, single-replica workloads, and the end
//! of standard support.
//!
//! Removed-API usage has two signals. The API server's `apiserver_requested_deprecated_apis`
//! metric is definitive (high confidence) but only covers requests since that API server
//! instance started. Objects whose `managedFields` or last-applied annotation name a deprecated
//! version show who wrote them that way (medium confidence: the writer may have moved on since).

use std::collections::BTreeMap;

use k8s_mcp_core::finding::{Confidence, Finding, ObjectRef, RuleMeta, Severity, Source};
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use serde_json::json;

use super::{docs, parse_version};
use crate::evidence::{DeprecatedApi, StaleWrite, UpgradeEvidence};

const DOCS_DEPRECATION: &str = "https://kubernetes.io/docs/reference/using-api/deprecation-guide/";
const DOCS_CRD_VERSIONS: &str = "https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definition-versioning/";
const DOCS_PDB: &str = "https://kubernetes.io/docs/tasks/run-application/configure-pdb/";
const DOCS_DRAIN: &str = "https://kubernetes.io/docs/tasks/administer-cluster/safely-drain-node/";
const DOCS_RELEASES: &str = "https://kubernetes.io/releases/";

/// Rules emitted by this module.
pub const RULES: &[RuleMeta] = &[
    RuleMeta {
        id: "upgrade.target_skips_minor",
        title: "The target version skips a control-plane minor",
        docs: docs::SKEW,
    },
    RuleMeta {
        id: "upgrade.removed_api_in_use",
        title: "Clients use an API version that the target version removes",
        docs: DOCS_DEPRECATION,
    },
    RuleMeta {
        id: "upgrade.deprecated_api_in_use",
        title: "Clients use deprecated API versions",
        docs: DOCS_DEPRECATION,
    },
    RuleMeta {
        id: "upgrade.kubelet_skew",
        title: "Nodes would be too old for the target control plane",
        docs: docs::SKEW,
    },
    RuleMeta {
        id: "upgrade.pdb_blocks_drain",
        title: "A PodDisruptionBudget allows no disruptions, so node drains stall",
        docs: DOCS_PDB,
    },
    RuleMeta {
        id: "upgrade.single_replica_workloads",
        title: "Single-replica workloads go down while their node is drained",
        docs: DOCS_DRAIN,
    },
    RuleMeta {
        id: "upgrade.version_support_ending",
        title: "Standard support of the current version ends soon or has ended",
        docs: DOCS_RELEASES,
    },
];

/// Built-in APIs removed by a release, per the Kubernetes deprecation guide (no removals are
/// scheduled after 1.32): group, version, resource, removing minor, replacement.
const REMOVED: &[(&str, &str, &str, u32, &str)] = &[
    (
        "flowcontrol.apiserver.k8s.io",
        "v1beta3",
        "flowschemas",
        32,
        "flowcontrol.apiserver.k8s.io/v1",
    ),
    (
        "flowcontrol.apiserver.k8s.io",
        "v1beta3",
        "prioritylevelconfigurations",
        32,
        "flowcontrol.apiserver.k8s.io/v1",
    ),
    (
        "flowcontrol.apiserver.k8s.io",
        "v1beta2",
        "flowschemas",
        29,
        "flowcontrol.apiserver.k8s.io/v1",
    ),
    (
        "flowcontrol.apiserver.k8s.io",
        "v1beta2",
        "prioritylevelconfigurations",
        29,
        "flowcontrol.apiserver.k8s.io/v1",
    ),
    (
        "storage.k8s.io",
        "v1beta1",
        "csistoragecapacities",
        27,
        "storage.k8s.io/v1",
    ),
    (
        "flowcontrol.apiserver.k8s.io",
        "v1beta1",
        "flowschemas",
        26,
        "flowcontrol.apiserver.k8s.io/v1",
    ),
    (
        "flowcontrol.apiserver.k8s.io",
        "v1beta1",
        "prioritylevelconfigurations",
        26,
        "flowcontrol.apiserver.k8s.io/v1",
    ),
    (
        "autoscaling",
        "v2beta2",
        "horizontalpodautoscalers",
        26,
        "autoscaling/v2",
    ),
    ("batch", "v1beta1", "cronjobs", 25, "batch/v1"),
    (
        "discovery.k8s.io",
        "v1beta1",
        "endpointslices",
        25,
        "discovery.k8s.io/v1",
    ),
    ("events.k8s.io", "v1beta1", "events", 25, "events.k8s.io/v1"),
    (
        "autoscaling",
        "v2beta1",
        "horizontalpodautoscalers",
        25,
        "autoscaling/v2",
    ),
    ("policy", "v1beta1", "poddisruptionbudgets", 25, "policy/v1"),
    (
        "policy",
        "v1beta1",
        "podsecuritypolicies",
        25,
        "Pod Security Admission",
    ),
    (
        "node.k8s.io",
        "v1beta1",
        "runtimeclasses",
        25,
        "node.k8s.io/v1",
    ),
];

/// Kubelets may be this many minors older than the API server (since 1.28).
const MAX_KUBELET_SKEW: u32 = 3;
/// Findings per rule that names objects one by one.
const SHOWN: usize = 5;
/// Support ending within this many days is worth a finding.
const SUPPORT_WARNING_DAYS: i64 = 90;
const METRIC: &str = "apiserver_requested_deprecated_apis";

/// Built-in APIs deprecated without a planned removal, with what replaces them and who uses
/// them on most clusters: group, version, resource, replacement, note.
const DEPRECATED: &[(&str, &str, &str, &str, &str)] = &[(
    "",
    "v1",
    "endpoints",
    "discovery.k8s.io/v1 EndpointSlices",
    "the control plane's endpoints controller writes them and kube-proxy or older clients read them; act only if your own tools use v1 Endpoints (the API server audit log names the callers)",
)];

fn removal(group: &str, version: &str, resource: &str) -> Option<(u32, &'static str)> {
    REMOVED
        .iter()
        .find(|(g, v, r, _, _)| *g == group && *v == version && *r == resource)
        .map(|(_, _, _, m, repl)| (*m, *repl))
}

/// The deprecated APIs clients requested, from the API server's Prometheus text. Only series
/// with a non-zero value count; subresources fold into their resource.
pub fn requested_deprecated_apis(metrics: &str) -> Vec<DeprecatedApi> {
    let mut out: Vec<DeprecatedApi> = metrics
        .lines()
        .filter_map(|l| l.strip_prefix(METRIC)?.strip_prefix('{'))
        .filter_map(|rest| {
            let (labels, value) = rest.rsplit_once('}')?;
            (value.trim().parse::<f64>().ok()? > 0.0).then_some(labels)
        })
        .map(|labels| {
            let get = |key: &str| {
                labels
                    .split(',')
                    .filter_map(|kv| kv.split_once('='))
                    .find(|(k, _)| k.trim() == key)
                    .map(|(_, v)| v.trim().trim_matches('"').to_owned())
                    .unwrap_or_default()
            };
            let (group, version, resource) = (get("group"), get("version"), get("resource"));
            let table = removal(&group, &version, &resource);
            let removed_in = parse_version(&get("removed_release"))
                .map(|(_, m)| m)
                .or(table.map(|(m, _)| m));
            let kept = DEPRECATED
                .iter()
                .find(|(g, v, r, ..)| *g == group && *v == version && *r == resource);
            DeprecatedApi {
                replacement: table
                    .map(|(_, r)| r.to_owned())
                    .or_else(|| kept.map(|(_, _, _, r, _)| (*r).to_owned())),
                group,
                version,
                resource,
                removed_in,
                crd: false,
            }
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Split metric entries into those the cluster still serves and those it does not (the gauge
/// keeps an entry until the API server restarts, also after its CRD is deleted). `served` holds
/// `group/version` strings, with `v1` for the core group.
pub fn split_served(
    apis: Vec<DeprecatedApi>,
    served: &[String],
) -> (Vec<DeprecatedApi>, Vec<DeprecatedApi>) {
    apis.into_iter()
        .partition(|a| served.contains(&a.group_version()))
}

/// Served CRD versions marked `deprecated`, with the CRD's storage version as replacement.
pub fn deprecated_crd_versions(crds: &[CustomResourceDefinition]) -> Vec<DeprecatedApi> {
    let mut out = Vec::new();
    for crd in crds {
        let spec = &crd.spec;
        let storage = spec.versions.iter().find(|v| v.storage).map(|v| &v.name);
        for v in &spec.versions {
            if v.served && v.deprecated == Some(true) {
                out.push(DeprecatedApi {
                    group: spec.group.clone(),
                    version: v.name.clone(),
                    resource: spec.names.plural.clone(),
                    removed_in: None,
                    replacement: storage
                        .filter(|s| **s != v.name)
                        .map(|s| format!("{}/{s}", spec.group)),
                    crd: true,
                });
            }
        }
    }
    out.sort();
    out
}

/// The deprecated APIs whose objects are worth scanning for stale writes: still-served ones
/// that a release removes or that a CRD deprecates (a built-in deprecated without a planned
/// removal, such as core `v1` Endpoints, is not worth naming writers for), and table removals
/// between now and the target.
pub fn scan_targets(
    current: u32,
    target: u32,
    requested: &[DeprecatedApi],
    crd_versions: &[DeprecatedApi],
) -> Vec<DeprecatedApi> {
    let worth = |a: &&DeprecatedApi| match a.removed_in {
        Some(m) => m > current,
        None => a.crd,
    };
    let mut out: Vec<DeprecatedApi> = requested
        .iter()
        .chain(crd_versions)
        .filter(worth)
        .cloned()
        .chain(
            REMOVED
                .iter()
                .filter(|(_, _, _, m, _)| *m > current && *m <= target)
                .map(|(g, v, r, m, repl)| DeprecatedApi {
                    group: (*g).to_owned(),
                    version: (*v).to_owned(),
                    resource: (*r).to_owned(),
                    removed_in: Some(*m),
                    replacement: Some((*repl).to_owned()),
                    crd: false,
                }),
        )
        .collect();
    out.sort();
    out.dedup_by(|a, b| (&a.group, &a.version, &a.resource) == (&b.group, &b.version, &b.resource));
    out
}

/// Who last wrote an object with `api`: its `managedFields` entries for that version, and the
/// last-applied annotation when it names that version.
pub fn stale_writes(api: &DeprecatedApi, kind: &str, meta: &ObjectMeta) -> Vec<StaleWrite> {
    let gv = api.group_version();
    let mut managers: Vec<String> = meta
        .managed_fields
        .iter()
        .flatten()
        .filter(|m| m.api_version.as_deref() == Some(gv.as_str()))
        .map(|m| m.manager.clone().unwrap_or_else(|| "unknown".into()))
        .collect();
    let applied = meta
        .annotations
        .as_ref()
        .and_then(|a| a.get("kubectl.kubernetes.io/last-applied-configuration"))
        .and_then(|t| serde_json::from_str::<serde_json::Value>(t).ok())
        .is_some_and(|v| v["apiVersion"] == gv.as_str());
    // The annotation only adds a writer when no managedFields entry already names one.
    if applied && managers.is_empty() {
        managers.push("kubectl apply".into());
    }
    managers.sort();
    managers.dedup();
    managers
        .into_iter()
        .map(|manager| StaleWrite {
            api: api.clone(),
            kind: kind.to_owned(),
            namespace: meta.namespace.clone(),
            name: meta.name.clone().unwrap_or_default(),
            manager,
        })
        .collect()
}

fn version(minor: u32) -> String {
    format!("1.{minor}")
}

fn describe(a: &DeprecatedApi) -> String {
    format!("{} {}", a.group_version(), a.resource)
}

fn stale_line(w: &StaleWrite) -> String {
    format!(
        "{} {}{} last written with {} by {}",
        w.kind,
        w.namespace
            .as_ref()
            .map(|n| format!("{n}/"))
            .unwrap_or_default(),
        w.name,
        w.api.group_version(),
        w.manager
    )
}

/// `upgrade_readiness`.
pub fn check(ev: &UpgradeEvidence, out: &mut Vec<Finding>) {
    target_step(ev, out);
    apis(ev, out);
    kubelets(ev, out);
    pdbs(ev, out);
    single_replicas(ev, out);
    support(ev, out);
}

fn target_step(ev: &UpgradeEvidence, out: &mut Vec<Finding>) {
    if ev.target <= ev.current + 1 {
        return;
    }
    let steps: Vec<String> = (ev.current..=ev.target).map(version).collect();
    out.push(
        Finding::new(
            "upgrade.target_skips_minor",
            Severity::High,
            Confidence::High,
            format!("The control plane cannot go from {} to {} in one step", version(ev.current), version(ev.target)),
        )
        .explain("Kubernetes upgrades the control plane one minor version at a time; managed clusters refuse larger jumps.")
        .evidence(Source::Status, format!("control plane {}, target {}", version(ev.current), version(ev.target)))
        .docs(docs::SKEW)
        .fix(format!("Upgrade in steps: {}. Run upgrade_readiness with each intermediate target.", steps.join(" → "))),
    );
}

/// Deprecated APIs in use, by (group, version, resource): the API, whether the metric saw it
/// requested, and the objects last written with it.
type InUse<'a> = BTreeMap<(String, String, String), (DeprecatedApi, bool, Vec<&'a StaleWrite>)>;

/// Every deprecated API in use: requested (metric) or last written (objects), keyed by API.
fn in_use(ev: &UpgradeEvidence) -> InUse<'_> {
    let mut apis = InUse::new();
    let key = |a: &DeprecatedApi| (a.group.clone(), a.version.clone(), a.resource.clone());
    for a in ev.requested.iter().flatten() {
        // The CRD knows the replacement (its storage version); the metric does not.
        let a = ev
            .deprecated_crd_versions
            .iter()
            .find(|c| key(c) == key(a))
            .unwrap_or(a)
            .clone();
        apis.entry(key(&a)).or_insert((a, true, Vec::new())).1 = true;
    }
    for w in &ev.stale_writes {
        apis.entry(key(&w.api))
            .or_insert((w.api.clone(), false, Vec::new()))
            .2
            .push(w);
    }
    apis
}

/// Whether the upgrade to the target removes this API.
fn removed_by_target(ev: &UpgradeEvidence, api: &DeprecatedApi) -> bool {
    api.removed_in
        .is_some_and(|m| m > ev.current && m <= ev.target)
}

fn apis(ev: &UpgradeEvidence, out: &mut Vec<Finding>) {
    let mut deprecated = Vec::new();
    for (api, requested, writes) in in_use(ev).into_values() {
        if !removed_by_target(ev, &api) {
            deprecated.push((api, requested, writes));
            continue;
        }
        let replacement = api
            .replacement
            .clone()
            .unwrap_or_else(|| "a newer version".into());
        let mut f = Finding::new(
            "upgrade.removed_api_in_use",
            Severity::High,
            if requested { Confidence::High } else { Confidence::Medium },
            format!("{} is removed in {}, and clients still use it", describe(&api), version(api.removed_in.unwrap_or(ev.target))),
        )
        .explain("After the upgrade the API server no longer serves this version: clients and manifests that use it fail with 404 (\"the server could not find the requested resource\"). Stored objects are converted and stay readable through the replacement.")
        .docs(DOCS_DEPRECATION)
        .fix(format!("Move every client and manifest (Helm charts, operators, CI pipelines) to {replacement} before upgrading; the API server audit log's userAgent names the callers."));
        if requested {
            f = f.evidence(
                Source::Status,
                format!(
                    "{METRIC}: {} requested since the API server started",
                    describe(&api)
                ),
            );
        }
        for w in writes.iter().take(SHOWN) {
            f = f.evidence(Source::Related, stale_line(w));
        }
        if let Some(w) = writes.first() {
            f = f.object(ObjectRef::new(&w.kind, w.namespace.as_deref(), &w.name));
        }
        out.push(f);
    }
    if deprecated.is_empty() {
        return;
    }
    let any_crd = deprecated.iter().any(|(a, _, _)| a.crd);
    let mut f = Finding::new(
        "upgrade.deprecated_api_in_use",
        if any_crd { Severity::Low } else { Severity::Info },
        Confidence::High,
        format!("Clients use {} deprecated API version(s) that {} does not remove", deprecated.len(), version(ev.target)),
    )
    .explain("Deprecated versions keep working until a release removes them: built-in APIs follow the Kubernetes deprecation policy, while a CRD's owner may drop a deprecated version in any release of their operator.")
    .docs(if any_crd { DOCS_CRD_VERSIONS } else { DOCS_DEPRECATION })
    .fix("Plan the move to the replacement versions; for CRDs, read the operator's release notes before upgrading it.");
    for (api, _, writes) in deprecated.iter().take(SHOWN) {
        f = f.evidence(
            Source::Status,
            format!(
                "{}{}{}{}",
                describe(api),
                if api.crd { " (CRD version)" } else { "" },
                api.replacement
                    .as_ref()
                    .map(|r| format!(", use {r}"))
                    .unwrap_or_default(),
                // Issue #68: on most clusters this one is the control plane itself.
                DEPRECATED
                    .iter()
                    .find(|(g, v, r, ..)| {
                        (*g, *v, *r)
                            == (
                                api.group.as_str(),
                                api.version.as_str(),
                                api.resource.as_str(),
                            )
                    })
                    .map(|(.., note)| format!(": {note}"))
                    .unwrap_or_default()
            ),
        );
        for w in writes.iter().take(2) {
            f = f.evidence(Source::Related, stale_line(w));
        }
    }
    out.push(f);
}

/// Nodes (name, kubelet version) more than the supported skew behind the target, sorted.
fn old_kubelets(ev: &UpgradeEvidence) -> Vec<(String, String)> {
    let oldest_allowed = ev.target.saturating_sub(MAX_KUBELET_SKEW);
    let mut behind: Vec<(String, String)> = ev
        .nodes
        .iter()
        .flatten()
        .filter_map(|n| {
            let v = &n.status.as_ref()?.node_info.as_ref()?.kubelet_version;
            let (_, minor) = parse_version(v)?;
            (minor < oldest_allowed)
                .then(|| (n.metadata.name.clone().unwrap_or_default(), v.clone()))
        })
        .collect();
    behind.sort();
    behind
}

fn kubelets(ev: &UpgradeEvidence, out: &mut Vec<Finding>) {
    let oldest_allowed = ev.target.saturating_sub(MAX_KUBELET_SKEW);
    let behind = old_kubelets(ev);
    if behind.is_empty() {
        return;
    }
    let mut f = Finding::new(
        "upgrade.kubelet_skew",
        Severity::High,
        Confidence::High,
        format!("{} node(s) run kubelets older than {}, the oldest a {} control plane supports", behind.len(), version(oldest_allowed), version(ev.target)),
    )
    .explain(format!("A kubelet may be at most {MAX_KUBELET_SKEW} minors older than the API server. After the control-plane upgrade these nodes are outside the supported skew: they may fail to register, report status or run new features correctly."))
    .docs(docs::SKEW)
    .fix(format!("Upgrade these nodes (their node groups or pools) to at least {} before the control plane, or replace them.", version(oldest_allowed)));
    for (name, v) in behind.iter().take(SHOWN) {
        f = f.evidence(Source::Status, format!("node {name}: kubelet {v}"));
    }
    out.push(f);
}

fn is_zero(v: Option<&IntOrString>) -> bool {
    match v {
        Some(IntOrString::Int(n)) => *n == 0,
        Some(IntOrString::String(s)) => s.trim_end_matches('%').trim() == "0",
        None => false,
    }
}

/// PodDisruptionBudgets that allow no disruption while they cover pods.
fn blocking_pdbs(
    ev: &UpgradeEvidence,
) -> impl Iterator<Item = &k8s_openapi::api::policy::v1::PodDisruptionBudget> {
    ev.pdbs.iter().flatten().filter(|p| {
        p.status
            .as_ref()
            .is_some_and(|s| s.disruptions_allowed == 0 && s.expected_pods > 0)
    })
}

fn pdbs(ev: &UpgradeEvidence, out: &mut Vec<Finding>) {
    let mut blocking: Vec<Finding> = Vec::new();
    for pdb in blocking_pdbs(ev) {
        let Some(status) = &pdb.status else { continue };
        let name = pdb.metadata.name.as_deref().unwrap_or("");
        let ns = pdb.metadata.namespace.as_deref().unwrap_or("");
        let spec = pdb.spec.as_ref();
        let max_unavailable = spec.and_then(|s| s.max_unavailable.as_ref());
        let min_available = spec.and_then(|s| s.min_available.as_ref());
        let unhealthy = status.current_healthy < status.desired_healthy;
        let budget = match (min_available, max_unavailable) {
            (Some(m), _) => format!("minAvailable {}", int_or_string(m)),
            (None, Some(m)) => format!("maxUnavailable {}", int_or_string(m)),
            (None, None) => "no budget".into(),
        };
        let why = if unhealthy {
            format!(
                "only {} of the {} required pods are healthy, so none may be evicted",
                status.current_healthy, status.desired_healthy
            )
        } else if is_zero(max_unavailable) {
            "maxUnavailable is 0: no pod may ever be evicted".to_owned()
        } else {
            format!(
                "{budget} with {} pods leaves no room for an eviction",
                status.expected_pods
            )
        };
        blocking.push(
            Finding::new(
                "upgrade.pdb_blocks_drain",
                Severity::High,
                Confidence::High,
                format!("PodDisruptionBudget {ns}/{name} allows no disruptions, so draining its pods' nodes stalls"),
            )
            .explain(format!("Node upgrades drain each node through the eviction API, which refuses evictions the budget does not allow: {why}. Managed upgrades then wait, fail, or (after a timeout) force the eviction."))
            .evidence(Source::Status, format!("{budget}; expectedPods {}, currentHealthy {}, desiredHealthy {}, disruptionsAllowed 0", status.expected_pods, status.current_healthy, status.desired_healthy))
            .object(ObjectRef::new("PodDisruptionBudget", Some(ns), name))
            .docs(DOCS_PDB)
            .fix(if unhealthy {
                "Fix the unhealthy pods first (diagnose_workload on the workload the budget covers); the budget then allows evictions again.".to_owned()
            } else {
                "Allow at least one disruption during the upgrade: run more replicas than minAvailable, or set maxUnavailable: 1.".to_owned()
            })
            .next("get_resource", json!({"kind": "PodDisruptionBudget", "name": name, "namespace": ns}), "see the budget and its selector"),
        );
    }
    out.extend(blocking.into_iter().take(SHOWN * 2));
}

fn int_or_string(v: &IntOrString) -> String {
    match v {
        IntOrString::Int(n) => n.to_string(),
        IntOrString::String(s) => s.clone(),
    }
}

/// `Kind namespace/name` of the Deployments and StatefulSets that run one replica, sorted.
fn single_replica_names(ev: &UpgradeEvidence) -> Vec<String> {
    let one = |r: Option<i32>| r == Some(1);
    let mut names: Vec<String> = ev
        .deployments
        .iter()
        .flatten()
        .filter(|d| one(d.spec.as_ref().and_then(|s| s.replicas)))
        .map(|d| {
            format!(
                "Deployment {}/{}",
                d.metadata.namespace.as_deref().unwrap_or(""),
                d.metadata.name.as_deref().unwrap_or("")
            )
        })
        .chain(
            ev.statefulsets
                .iter()
                .flatten()
                .filter(|s| one(s.spec.as_ref().and_then(|s| s.replicas)))
                .map(|s| {
                    format!(
                        "StatefulSet {}/{}",
                        s.metadata.namespace.as_deref().unwrap_or(""),
                        s.metadata.name.as_deref().unwrap_or("")
                    )
                }),
        )
        .collect();
    names.sort();
    names
}

fn single_replicas(ev: &UpgradeEvidence, out: &mut Vec<Finding>) {
    let names = single_replica_names(ev);
    if names.is_empty() {
        return;
    }
    let mut f = Finding::new(
        "upgrade.single_replica_workloads",
        Severity::Low,
        Confidence::High,
        format!("{} workload(s) run a single replica and go down while their node is drained", names.len()),
    )
    .explain("Node upgrades replace or drain every node. A workload with one replica is unavailable from its pod's eviction until the replacement is ready on another node.")
    .docs(DOCS_DRAIN)
    .fix("Run at least two replicas (with a PodDisruptionBudget of maxUnavailable: 1) for workloads that must stay up, or accept a short outage during the upgrade.");
    for n in names.iter().take(SHOWN) {
        f = f.evidence(Source::Spec, format!("{n}: replicas 1"));
    }
    out.push(f);
}

fn support(ev: &UpgradeEvidence, out: &mut Vec<Finding>) {
    let Some((cloud, ends)) = &ev.support_ends else {
        return;
    };
    let days = (ends - ev.now.as_second()) / 86_400;
    if days > SUPPORT_WARNING_DAYS {
        return;
    }
    let date = jiff::Timestamp::from_second(*ends)
        .map_or_else(|_| ends.to_string(), |t| t.strftime("%Y-%m-%d").to_string());
    let (severity, title) = if days < 0 {
        (
            Severity::High,
            format!(
                "Standard support of Kubernetes {} on {cloud} ended on {date}",
                version(ev.current)
            ),
        )
    } else {
        (
            Severity::Medium,
            format!(
                "Standard support of Kubernetes {} on {cloud} ends on {date}, in {days} days",
                version(ev.current)
            ),
        )
    };
    out.push(
        Finding::new("upgrade.version_support_ending", severity, Confidence::High, title)
            .explain("After standard support ends the cloud stops shipping fixes for this version: EKS moves the cluster to paid extended support, GKE and AKS upgrade it automatically.")
            .evidence(Source::Related, format!("{cloud} end of standard support: {date}"))
            .docs(DOCS_RELEASES)
            .fix(format!("Plan the upgrade to {} before {date}.", version(ev.current + 1))),
    );
}

/// What blocks the upgrade and what to review, counted in objects (not checklist rows), for
/// the summary (#66): `(blocked, review)` phrases such as `4 PodDisruptionBudgets`.
pub fn tally(ev: &UpgradeEvidence) -> (Vec<String>, Vec<String>) {
    let (mut blocked, mut review) = (Vec::new(), Vec::new());
    if ev.target > ev.current + 1 {
        blocked.push(format!("a target {} minors ahead", ev.target - ev.current));
    }
    let (removed, deprecated): (Vec<_>, Vec<_>) = in_use(ev)
        .into_values()
        .partition(|(a, ..)| removed_by_target(ev, a));
    let add = |into: &mut Vec<String>, n: usize, one: &str, many: &str| {
        if n > 0 {
            into.push(format!("{n} {}", if n == 1 { one } else { many }));
        }
    };
    add(
        &mut blocked,
        removed.len(),
        "removed API in use",
        "removed APIs in use",
    );
    add(
        &mut blocked,
        old_kubelets(ev).len(),
        "node too old for the target",
        "nodes too old for the target",
    );
    add(
        &mut blocked,
        blocking_pdbs(ev).count(),
        "PodDisruptionBudget",
        "PodDisruptionBudgets",
    );
    add(
        &mut review,
        deprecated.len(),
        "deprecated API",
        "deprecated APIs",
    );
    add(
        &mut review,
        single_replica_names(ev).len(),
        "single-replica workload",
        "single-replica workloads",
    );
    if ev
        .support_ends
        .as_ref()
        .is_some_and(|(_, ends)| (ends - ev.now.as_second()) / 86_400 <= SUPPORT_WARNING_DAYS)
    {
        review.push("the end of standard support".into());
    }
    (blocked, review)
}

/// One checklist row of `upgrade_readiness`: what was checked, `ok`/`warn`/`blocked`/
/// `not checked`, and a short detail.
pub type Check = (&'static str, &'static str, String);

/// The checklist, from the evidence and the findings `check` produced.
pub fn checklist(ev: &UpgradeEvidence, findings: &[Finding]) -> Vec<Check> {
    let count = |id: &str| findings.iter().filter(|f| f.id == id).count();
    let mut rows = vec![if count("upgrade.target_skips_minor") > 0 {
        (
            "control-plane step",
            "blocked",
            format!(
                "{} → {} skips a minor",
                version(ev.current),
                version(ev.target)
            ),
        )
    } else {
        (
            "control-plane step",
            "ok",
            format!("{} → {}", version(ev.current), version(ev.target)),
        )
    }];
    let removed = count("upgrade.removed_api_in_use");
    rows.push(match (&ev.requested, removed) {
        (_, n) if n > 0 => ("removed APIs", "blocked", format!("{n} still in use")),
        (None, _) => (
            "removed APIs",
            "not checked",
            format!("the {METRIC} metric is unreadable; object scan only"),
        ),
        (Some(_), _) => (
            "removed APIs",
            "ok",
            format!("none removed by {} in use", version(ev.target)),
        ),
    });
    let unserved = match ev.unserved.len() {
        0 => String::new(),
        n => format!(
            "; {n} more requested earlier but no longer served (the metric keeps them until the API server restarts)"
        ),
    };
    rows.push(
        match findings
            .iter()
            .find(|f| f.id == "upgrade.deprecated_api_in_use")
        {
            Some(f) => ("deprecated APIs", "warn", format!("{}{unserved}", f.title)),
            None if ev.requested.is_none() => {
                ("deprecated APIs", "not checked", "metric unreadable".into())
            }
            None => ("deprecated APIs", "ok", format!("none in use{unserved}")),
        },
    );
    rows.push(match (&ev.nodes, count("upgrade.kubelet_skew")) {
        (None, _) => ("kubelet skew", "not checked", "nodes unreadable".into()),
        (Some(_), n) if n > 0 => (
            "kubelet skew",
            "blocked",
            "nodes too old for the target".into(),
        ),
        (Some(nodes), _) => (
            "kubelet skew",
            "ok",
            format!(
                "{} node(s) within {MAX_KUBELET_SKEW} minors of {}",
                nodes.len(),
                version(ev.target)
            ),
        ),
    });
    rows.push(match (&ev.pdbs, count("upgrade.pdb_blocks_drain")) {
        (None, _) => ("PodDisruptionBudgets", "not checked", "unreadable".into()),
        (Some(_), n) if n > 0 => (
            "PodDisruptionBudgets",
            "blocked",
            format!("{n} allow no disruptions"),
        ),
        (Some(p), _) => (
            "PodDisruptionBudgets",
            "ok",
            format!("{} checked, none block drains", p.len()),
        ),
    });
    rows.push(
        match findings
            .iter()
            .find(|f| f.id == "upgrade.single_replica_workloads")
        {
            Some(f) => ("single-replica workloads", "warn", f.title.clone()),
            None if ev.deployments.is_none() && ev.statefulsets.is_none() => (
                "single-replica workloads",
                "not checked",
                "unreadable".into(),
            ),
            None => ("single-replica workloads", "ok", "none".into()),
        },
    );
    if ev.support_ends.is_some() {
        rows.push(
            match findings
                .iter()
                .find(|f| f.id == "upgrade.version_support_ending")
            {
                Some(f) => ("standard support", "warn", f.title.clone()),
                None => ("standard support", "ok", "more than 90 days left".into()),
            },
        );
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::upgrade_fixture;

    fn ids(ev: &UpgradeEvidence) -> Vec<String> {
        let mut out = Vec::new();
        check(ev, &mut out);
        k8s_mcp_core::finding::rank(&mut out);
        out.into_iter().map(|f| f.id).collect()
    }

    #[test]
    fn metric_lines_parse_into_apis() {
        let text = "# HELP apiserver_requested_deprecated_apis ...\n\
            apiserver_requested_deprecated_apis{group=\"\",removed_release=\"\",resource=\"endpoints\",subresource=\"\",version=\"v1\"} 1\n\
            apiserver_requested_deprecated_apis{group=\"flowcontrol.apiserver.k8s.io\",removed_release=\"1.32\",resource=\"flowschemas\",subresource=\"status\",version=\"v1beta3\"} 1\n\
            apiserver_requested_deprecated_apis{group=\"flowcontrol.apiserver.k8s.io\",removed_release=\"1.32\",resource=\"flowschemas\",subresource=\"\",version=\"v1beta3\"} 1\n\
            apiserver_requested_deprecated_apis{group=\"old.example\",removed_release=\"\",resource=\"things\",subresource=\"\",version=\"v1\"} 0\n\
            apiserver_request_total{code=\"200\"} 5\n";
        let apis = requested_deprecated_apis(text);
        assert_eq!(apis.len(), 2, "{apis:?}");
        assert_eq!(
            (apis[0].resource.as_str(), apis[0].removed_in),
            ("endpoints", None)
        );
        assert_eq!(
            apis[0].replacement.as_deref(),
            Some("discovery.k8s.io/v1 EndpointSlices")
        );
        assert_eq!(apis[1].removed_in, Some(32));
        assert_eq!(
            apis[1].replacement.as_deref(),
            Some("flowcontrol.apiserver.k8s.io/v1")
        );
    }

    /// v0.3 AC 3: removed-API usage (metric and stale writes) and a blocking PDB.
    #[test]
    fn removed_apis_and_blocking_pdbs() {
        let ev = upgrade_fixture("upgrade/removed-api-and-pdb.yaml");
        assert_eq!(
            ids(&ev),
            [
                "upgrade.removed_api_in_use",
                "upgrade.pdb_blocks_drain",
                "upgrade.pdb_blocks_drain",
                "upgrade.single_replica_workloads",
                "upgrade.deprecated_api_in_use",
            ]
        );
        let mut out = Vec::new();
        check(&ev, &mut out);
        let removed = out
            .iter()
            .find(|f| f.id == "upgrade.removed_api_in_use")
            .unwrap();
        assert_eq!(removed.confidence, Confidence::High);
        assert!(removed.evidence.iter().any(|e| e.text == "FlowSchema team-a last written with flowcontrol.apiserver.k8s.io/v1beta3 by helm"), "{:?}", removed.evidence);
        let pdbs: Vec<&Finding> = out
            .iter()
            .filter(|f| f.id == "upgrade.pdb_blocks_drain")
            .collect();
        assert!(
            pdbs.iter()
                .any(|f| f.explanation.contains("maxUnavailable is 0"))
        );
        assert!(pdbs.iter().any(|f| {
            f.explanation
                .contains("only 1 of the 2 required pods are healthy")
        }));
        let rows = checklist(&ev, &out);
        assert!(
            rows.contains(&("removed APIs", "blocked", "1 still in use".into())),
            "{rows:?}"
        );
        // Issue #66: the summary counts objects, not checklist rows.
        assert_eq!(
            tally(&ev),
            (
                vec![
                    "1 removed API in use".to_owned(),
                    "2 PodDisruptionBudgets".to_owned()
                ],
                vec![
                    "1 deprecated API".to_owned(),
                    "1 single-replica workload".to_owned()
                ]
            )
        );
        assert!(rows.contains(&(
            "PodDisruptionBudgets",
            "blocked",
            "2 allow no disruptions".into()
        )));
    }

    #[test]
    fn deprecated_crd_versions_and_stale_writes() {
        let ev = upgrade_fixture("upgrade/deprecated-crd.yaml");
        let mut out = Vec::new();
        check(&ev, &mut out);
        assert_eq!(out.len(), 1, "{out:?}");
        let f = &out[0];
        assert_eq!(
            (f.id.as_str(), f.severity),
            ("upgrade.deprecated_api_in_use", Severity::Low)
        );
        assert!(
            f.evidence.iter().any(|e| e.text
                == "probe.k8s-mcp.dev/v1beta1 widgets (CRD version), use probe.k8s-mcp.dev/v1"),
            "{:?}",
            f.evidence
        );
        assert!(f.evidence.iter().any(|e| e.text == "Widget default/w1 last written with probe.k8s-mcp.dev/v1beta1 by kubectl-client-side-apply"));
        // Issue #65: the deleted CRD's metric entry is neither evidence nor counted.
        assert!(
            !f.evidence
                .iter()
                .any(|e| e.text.contains("gone.example.com")),
            "{:?}",
            f.evidence
        );
        assert!(
            f.title.starts_with("Clients use 1 deprecated API"),
            "{}",
            f.title
        );
        let rows = checklist(&ev, &out);
        let row = rows.iter().find(|r| r.0 == "deprecated APIs").unwrap();
        assert!(row.2.ends_with("1 more requested earlier but no longer served (the metric keeps them until the API server restarts)"), "{}", row.2);
    }

    #[test]
    fn skew_steps_and_support() {
        let mut ev = upgrade_fixture("upgrade/ready.yaml");
        assert!(ids(&ev).is_empty(), "{:?}", ids(&ev));
        assert!(checklist(&ev, &[]).iter().all(|(_, s, _)| *s == "ok"));
        ev.target = ev.current + 2;
        assert_eq!(ids(&ev), ["upgrade.target_skips_minor"]);
        ev.target = 38; // 1.33 kubelets: more than 3 minors behind 1.38
        assert!(ids(&ev).contains(&"upgrade.kubelet_skew".to_owned()));
        ev.target = ev.current + 1;
        ev.support_ends = Some(("EKS".into(), ev.now.as_second() + 30 * 86_400));
        let mut out = Vec::new();
        check(&ev, &mut out);
        assert_eq!(out[0].severity, Severity::Medium);
        assert!(out[0].title.ends_with("in 30 days"), "{}", out[0].title);
        ev.support_ends = Some(("EKS".into(), ev.now.as_second() - 86_400));
        assert_eq!(ids(&ev), ["upgrade.version_support_ending"]);
    }

    #[test]
    fn scan_targets_skip_what_is_no_longer_served() {
        let requested = vec![DeprecatedApi {
            group: "batch".into(),
            version: "v1beta1".into(),
            resource: "cronjobs".into(),
            removed_in: Some(25),
            ..Default::default()
        }];
        assert!(scan_targets(33, 34, &requested, &[]).is_empty());
        let targets = scan_targets(31, 32, &[], &[]);
        assert_eq!(
            targets.len(),
            2,
            "flowcontrol v1beta3 removed in 1.32: {targets:?}"
        );
    }
}
