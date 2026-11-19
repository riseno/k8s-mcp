//! GKE rules: pure functions from Cluster Manager objects to cloud-neutral rows and findings.

use std::collections::BTreeMap;

use google_cloud_container_v1::model::{Cluster, NodePool as GkeNodePool, ServerConfig};
use k8s_mcp_core::finding::{Confidence, Finding, RuleMeta, Severity, Source};
use k8s_mcp_core::text::truncate;
use k8s_mcp_provider::{
    AccessMapping, Addon, ClusterInfo, NodePool, RbacGrant, Report, UpgradeCheck, UpgradeInfo,
};

const DOCS_TROUBLESHOOT: &str = "https://cloud.google.com/kubernetes-engine/docs/troubleshooting";
const DOCS_CHANNELS: &str =
    "https://cloud.google.com/kubernetes-engine/docs/concepts/release-channels";
const DOCS_AUTHORIZED: &str =
    "https://cloud.google.com/kubernetes-engine/docs/how-to/authorized-networks";
const DOCS_VERSIONS: &str = "https://cloud.google.com/kubernetes-engine/versioning";
const DOCS_GROUPS: &str =
    "https://cloud.google.com/kubernetes-engine/docs/how-to/google-groups-rbac";
const DOCS_ABAC: &str = "https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#leave_abac_disabled";

/// Rules emitted by the GKE provider.
pub const RULES: &[RuleMeta] = &[
    RuleMeta {
        id: "gke.cluster.unhealthy",
        title: "The GKE cluster reports an error or degraded status",
        docs: DOCS_TROUBLESHOOT,
    },
    RuleMeta {
        id: "gke.cluster.no_release_channel",
        title: "The cluster is not enrolled in a release channel",
        docs: DOCS_CHANNELS,
    },
    RuleMeta {
        id: "gke.cluster.public_endpoint",
        title: "The control-plane endpoint is public without authorized networks",
        docs: DOCS_AUTHORIZED,
    },
    RuleMeta {
        id: "gke.nodepool.unhealthy",
        title: "A node pool reports an error or degraded status",
        docs: DOCS_TROUBLESHOOT,
    },
    RuleMeta {
        id: "gke.nodepool.version_skew",
        title: "A node pool runs an older Kubernetes minor than the control plane",
        docs: DOCS_VERSIONS,
    },
    RuleMeta {
        id: "gke.access.legacy_abac",
        title: "Legacy ABAC is enabled: it grants rights outside RBAC",
        docs: DOCS_ABAC,
    },
    RuleMeta {
        id: "gke.access.google_groups_off",
        title: "RBAC binds Google groups, but Google Groups for RBAC is off",
        docs: DOCS_GROUPS,
    },
];

/// `gke_access`: the RBAC bindings of Google principals (users and service accounts, which
/// are email addresses, and Google groups), with the cluster settings that decide whether
/// they apply. IAM roles on the project (`roles/container.*`) grant access too; they are not
/// listed.
pub fn access(c: &Cluster, rbac: &[RbacGrant]) -> Report<Vec<AccessMapping>> {
    let google = |g: &&RbacGrant| match g.kind.as_str() {
        "User" => g.subject.contains('@'),
        "Group" => !g.subject.starts_with("system:"),
        _ => false,
    };
    let grants: Vec<&RbacGrant> = rbac.iter().filter(google).collect();
    let mut findings = Vec::new();
    let name = &c.name;
    if c.legacy_abac.as_ref().is_some_and(|a| a.enabled) {
        findings.push(
            Finding::new("gke.access.legacy_abac", Severity::High, Confidence::High, format!("Legacy ABAC is enabled on {name}"))
                .explain("With legacy ABAC, the cluster grants rights from static policies outside RBAC, including broad rights to every authenticated user and ServiceAccount. RBAC bindings and their reviews do not show them.")
                .evidence(Source::Spec, "legacyAbac.enabled: true")
                .docs(DOCS_ABAC)
                .fix("Disable it (`gcloud container clusters update <cluster> --no-enable-legacy-authorization`) after granting what is still needed through RBAC."),
        );
    }
    let groups_on = c
        .authenticator_groups_config
        .as_ref()
        .is_some_and(|g| g.enabled);
    let groups: Vec<&str> = grants
        .iter()
        .filter(|g| g.kind == "Group")
        .map(|g| g.subject.as_str())
        .collect();
    if !groups_on && !groups.is_empty() {
        findings.push(
            Finding::new("gke.access.google_groups_off", Severity::Medium, Confidence::Medium, format!("{} RBAC binding(s) name groups, but Google Groups for RBAC is off on {name}", groups.len()))
                .explain("Without Google Groups for RBAC, GKE does not put a user's Google group memberships into their Kubernetes identity, so bindings to Google groups grant nothing; members are refused or rely on IAM roles instead.")
                .evidence(Source::Related, format!("groups bound: {}", truncate(&groups.join(", "), 300)))
                .evidence(Source::Spec, "authenticatorGroupsConfig.enabled: false")
                .docs(DOCS_GROUPS)
                .fix("Enable it with the domain's gke-security-groups group (`gcloud container clusters update <cluster> --security-group=gke-security-groups@<domain>`), or bind the users directly."),
        );
    }
    let mut rows: Vec<AccessMapping> = grants.iter().map(|g| g.mapping()).collect();
    rows.sort_by(|a, b| (&a.principal, &a.source).cmp(&(&b.principal, &b.source)));
    (rows, findings)
}

/// Minor of a GKE version such as `1.33.5-gke.1000`.
pub fn minor(v: &str) -> Option<u32> {
    v.split('.')
        .nth(1)?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

fn name_of(n: Option<&str>) -> String {
    n.unwrap_or("UNKNOWN").to_owned()
}

fn status_issues(conditions: &[google_cloud_container_v1::model::StatusCondition]) -> Vec<String> {
    conditions
        .iter()
        .map(|c| {
            format!(
                "{}: {}",
                c.canonical_code.name().unwrap_or("?"),
                truncate(&c.message, 300)
            )
        })
        .collect()
}

/// `gke_cluster_info`.
pub fn cluster(c: &Cluster) -> Report<ClusterInfo> {
    let status = name_of(c.status.name());
    let mut details = BTreeMap::new();
    let mut put = |k: &str, v: String| {
        if !v.is_empty() {
            details.insert(k.to_owned(), v);
        }
    };
    let autopilot = c.autopilot.as_ref().is_some_and(|a| a.enabled);
    put(
        "mode",
        if autopilot { "Autopilot" } else { "Standard" }.into(),
    );
    put("location", c.location.clone());
    let channel = c
        .release_channel
        .as_ref()
        .and_then(|r| r.channel.name())
        .unwrap_or("UNSPECIFIED");
    put("release channel", channel.into());
    put("endpoint", c.endpoint.clone());
    let ip = c
        .control_plane_endpoints_config
        .as_ref()
        .and_then(|e| e.ip_endpoints_config.as_ref());
    // An unset enablePublicEndpoint means the public endpoint is on.
    let public = ip.is_none_or(|i| i.enable_public_endpoint != Some(false));
    let authorized = ip
        .and_then(|i| i.authorized_networks_config.as_ref())
        .is_some_and(|m| m.enabled);
    put(
        "endpoint access",
        format!(
            "public endpoint={public} authorized networks={authorized} private nodes={}",
            c.network_config
                .as_ref()
                .and_then(|n| n.default_enable_private_nodes)
                .unwrap_or(false)
        ),
    );
    put(
        "workload identity pool",
        c.workload_identity_config
            .as_ref()
            .map(|w| w.workload_pool.clone())
            .unwrap_or_default(),
    );
    put("logging", c.logging_service.clone());
    put("monitoring", c.monitoring_service.clone());
    put(
        "maintenance window",
        if c.maintenance_policy
            .as_ref()
            .and_then(|m| m.window.as_ref())
            .is_some_and(|w| w.policy.is_some())
        {
            "set".into()
        } else {
            "none (GKE picks the time)".into()
        },
    );

    let mut findings = Vec::new();
    let issues = status_issues(&c.conditions);
    if matches!(status.as_str(), "ERROR" | "DEGRADED") || !issues.is_empty() {
        let mut f = Finding::new(
            "gke.cluster.unhealthy",
            if status == "ERROR" { Severity::Critical } else { Severity::High },
            Confidence::High,
            format!("GKE cluster {} is {status} with {} condition(s)", c.name, issues.len()),
        )
        .explain("GKE reports a control-plane problem it cannot fix by itself, often a quota, a missing or changed network resource, or a broken service account or key.")
        .docs(DOCS_TROUBLESHOOT)
        .fix("Fix each condition in the evidence on the Google Cloud side (quota, subnet, firewall, service account, KMS key); GKE retries reconciliation afterwards.");
        for i in issues.iter().take(5) {
            f = f.evidence(Source::Status, i.clone());
        }
        findings.push(f);
    }
    if channel == "UNSPECIFIED" {
        findings.push(
            Finding::new("gke.cluster.no_release_channel", Severity::Low, Confidence::High, format!("{} is not enrolled in a release channel", c.name))
                .explain("Without a release channel, upgrades are manual and the version can drift towards its end of support, when GKE upgrades it automatically anyway.")
                .evidence(Source::Spec, "releaseChannel: UNSPECIFIED")
                .docs(DOCS_CHANNELS)
                .fix("Enroll the cluster in the REGULAR or STABLE channel and set a maintenance window."),
        );
    }
    if public && !authorized {
        findings.push(
            Finding::new("gke.cluster.public_endpoint", Severity::Low, Confidence::High, format!("The control plane of {} accepts connections from any IP address", c.name))
                .explain("The endpoint is public and no authorized networks restrict it. Authentication still applies, but the API server is exposed to scanning and credential stuffing.")
                .evidence(Source::Spec, "public endpoint enabled, authorized networks disabled")
                .docs(DOCS_AUTHORIZED)
                .fix("Enable master authorized networks for your networks, or use the private endpoint."),
        );
    }
    (
        ClusterInfo {
            name: c.name.clone(),
            version: c.current_master_version.clone(),
            status,
            details,
        },
        findings,
    )
}

/// `gke_node_pools`.
pub fn node_pools(master_version: &str, pools: &[GkeNodePool]) -> Report<Vec<NodePool>> {
    let mut rows = Vec::new();
    let mut findings = Vec::new();
    for p in pools {
        let status = name_of(p.status.name());
        let config = p.config.as_ref();
        let size = p.autoscaling.as_ref().filter(|a| a.enabled).map_or_else(
            || format!("{} (fixed)", p.initial_node_count),
            |a| {
                if a.total_max_node_count > 0 {
                    format!(
                        "autoscaling {}-{} total",
                        a.total_min_node_count, a.total_max_node_count
                    )
                } else {
                    format!(
                        "autoscaling {}-{} per zone",
                        a.min_node_count, a.max_node_count
                    )
                }
            },
        );
        let capacity = config.map_or("", |c| {
            if c.spot {
                "spot"
            } else if c.preemptible {
                "preemptible"
            } else {
                "on-demand"
            }
        });
        rows.push(NodePool {
            name: p.name.clone(),
            kind: config
                .and_then(|c| c.workload_metadata_config.as_ref())
                .and_then(|w| w.mode.name())
                .map_or_else(|| "managed".into(), |m| format!("managed, metadata {m}")),
            status: status.clone(),
            version: p.version.clone(),
            size,
            machine: format!(
                "{} {capacity}",
                config.map_or("", |c| c.machine_type.as_str())
            )
            .trim()
            .to_owned(),
        });
        let issues = status_issues(&p.conditions);
        if matches!(status.as_str(), "ERROR" | "RUNNING_WITH_ERROR") || !issues.is_empty() {
            let mut f = Finding::new("gke.nodepool.unhealthy", Severity::High, Confidence::High, format!("Node pool {} is {status} with {} condition(s)", p.name, issues.len()))
                .explain("GKE cannot keep the node pool at its size or manage its nodes, usually because of zone capacity or quota (GCE_STOCKOUT, quota exceeded), the node service account, or the subnet running out of addresses.")
                .docs(DOCS_TROUBLESHOOT)
                .fix("Fix the cause in the evidence: request quota, use another zone or machine type, or restore the node service account's roles (roles/container.defaultNodeServiceAccount).");

            for i in issues.iter().take(5) {
                f = f.evidence(Source::Status, i.clone());
            }
            findings.push(f);
        }
        if let (Some(cm), Some(pm)) = (minor(master_version), minor(&p.version))
            && pm < cm
        {
            findings.push(
                Finding::new("gke.nodepool.version_skew", Severity::Medium, Confidence::High, format!("Node pool {} runs Kubernetes {}, behind the control plane's {master_version}", p.name, p.version))
                    .explain("Nodes may lag the control plane by a few minors, but each lagging minor must be upgraded before the next control-plane upgrade, and new features and fixes do not reach these nodes.")
                    .evidence(Source::Status, format!("node pool version {}, control plane {master_version}", p.version))
                    .docs(DOCS_VERSIONS)
                    .fix("Upgrade the node pool to the control plane's version (a surge upgrade that respects PodDisruptionBudgets), or enable auto-upgrade."),
            );
        }
    }
    (rows, findings)
}

/// `gke_addons`: the add-ons GKE manages for the cluster (enabled or not; GKE does not expose
/// their versions).
pub fn addons(c: &Cluster) -> Report<Vec<Addon>> {
    let mut rows = Vec::new();
    if let Some(a) = &c.addons_config {
        let row = |name: &str, on: Option<bool>| {
            on.map(|on| Addon {
                name: name.into(),
                version: "managed".into(),
                status: if on { "enabled" } else { "disabled" }.into(),
                latest: String::new(),
            })
        };
        let candidates = [
            row(
                "HttpLoadBalancing",
                a.http_load_balancing.as_ref().map(|x| !x.disabled),
            ),
            row(
                "HorizontalPodAutoscaling",
                a.horizontal_pod_autoscaling.as_ref().map(|x| !x.disabled),
            ),
            row(
                "NetworkPolicy",
                a.network_policy_config.as_ref().map(|x| !x.disabled),
            ),
            row(
                "NodeLocalDNS",
                a.dns_cache_config.as_ref().map(|x| x.enabled),
            ),
            row(
                "GcePersistentDiskCsiDriver",
                a.gce_persistent_disk_csi_driver_config
                    .as_ref()
                    .map(|x| x.enabled),
            ),
            row(
                "GcpFilestoreCsiDriver",
                a.gcp_filestore_csi_driver_config
                    .as_ref()
                    .map(|x| x.enabled),
            ),
            row(
                "GcsFuseCsiDriver",
                a.gcs_fuse_csi_driver_config.as_ref().map(|x| x.enabled),
            ),
            row(
                "GkeBackupAgent",
                a.gke_backup_agent_config.as_ref().map(|x| x.enabled),
            ),
            row(
                "ConfigConnector",
                a.config_connector_config.as_ref().map(|x| x.enabled),
            ),
        ];
        rows.extend(candidates.into_iter().flatten());
    }
    (rows, Vec::new())
}

/// The GKE section of `upgrade_readiness`: versions the cluster's release channel offers
/// after the current one, and the channel's upgrade target.
pub fn upgrade(c: &Cluster, server: &ServerConfig) -> Report<UpgradeInfo> {
    let current = c.current_master_version.clone();
    let channel = c.release_channel.as_ref().map(|r| r.channel.clone());
    let config = server
        .channels
        .iter()
        .find(|ch| Some(&ch.channel) == channel.as_ref());
    let offered: Vec<&String> = config.map_or_else(
        || server.valid_master_versions.iter().collect(),
        |ch| ch.valid_versions.iter().collect(),
    );
    let mut available: Vec<(u32, String)> = offered
        .into_iter()
        .filter_map(|v| {
            let m = minor(v)?;
            (m > minor(&current)?).then(|| (m, format!("1.{m}")))
        })
        .collect();
    available.sort();
    available.dedup();
    let mut checks = vec![UpgradeCheck {
        name: "release channel".into(),
        status: if config.is_some() {
            "passing"
        } else {
            "warning"
        }
        .into(),
        detail: channel
            .as_ref()
            .and_then(|c| c.name())
            .unwrap_or("UNSPECIFIED")
            .into(),
    }];
    if let Some(ch) = config
        && !ch.upgrade_target_version.is_empty()
    {
        checks.push(UpgradeCheck {
            name: "channel upgrade target".into(),
            status: "passing".into(),
            detail: format!(
                "GKE upgrades this channel's clusters to {}",
                ch.upgrade_target_version
            ),
        });
    }
    (
        UpgradeInfo {
            current,
            available: available.into_iter().map(|(_, v)| v).collect(),
            support_ends: None,
            checks,
        },
        Vec::new(),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn minors() {
        assert_eq!(minor("1.33.5-gke.1000"), Some(33));
        assert_eq!(minor("bogus"), None);
    }

    #[test]
    fn every_rule_id_is_catalogued_once() {
        let mut ids: Vec<&str> = RULES.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), RULES.len());
        assert!(ids.iter().all(|i| i.starts_with("gke.")));
    }
}
