//! EKS rules: pure functions from AWS API objects to cloud-neutral rows and findings.

use std::collections::BTreeMap;

use aws_sdk_eks::types::{
    AccessEntry, Addon as EksAddon, AddonInfo, AssociatedAccessPolicy, Cluster,
    ClusterVersionInformation, FargateProfile, Insight, InsightStatusValue, InsightSummary,
    Nodegroup,
};
use k8s_mcp_core::finding::{Confidence, Finding, RuleMeta, Severity, Source};
use k8s_mcp_core::text::truncate;
use k8s_mcp_provider::{
    AccessMapping, Addon, ClusterInfo, NodePool, Report, UpgradeCheck, UpgradeInfo,
};
use k8s_openapi::api::core::v1::ConfigMap;
use serde::Deserialize;
use serde_json::json;

const DOCS_BEST_PRACTICES: &str =
    "https://docs.aws.amazon.com/eks/latest/best-practices/introduction.html";
const DOCS_HEALTH: &str = "https://docs.aws.amazon.com/eks/latest/userguide/troubleshooting.html";
const DOCS_ADDONS: &str = "https://docs.aws.amazon.com/eks/latest/userguide/eks-add-ons.html";
const DOCS_ACCESS: &str = "https://docs.aws.amazon.com/eks/latest/userguide/grant-k8s-access.html";
const DOCS_LOGGING: &str =
    "https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html";
const DOCS_ENDPOINT: &str =
    "https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html";
const DOCS_INSIGHTS: &str =
    "https://docs.aws.amazon.com/eks/latest/userguide/cluster-insights.html";

/// Rules emitted by the EKS provider.
pub const RULES: &[RuleMeta] = &[
    RuleMeta {
        id: "eks.cluster.unhealthy",
        title: "The EKS control plane reports health issues",
        docs: DOCS_HEALTH,
    },
    RuleMeta {
        id: "eks.cluster.public_endpoint",
        title: "The API server endpoint is public to the whole internet",
        docs: DOCS_ENDPOINT,
    },
    RuleMeta {
        id: "eks.cluster.audit_logging_off",
        title: "Control-plane audit logs are not sent to CloudWatch",
        docs: DOCS_LOGGING,
    },
    RuleMeta {
        id: "eks.cluster.auth_configmap_only",
        title: "Cluster access relies only on the aws-auth ConfigMap",
        docs: DOCS_ACCESS,
    },
    RuleMeta {
        id: "eks.nodegroup.unhealthy",
        title: "A managed node group reports health issues",
        docs: DOCS_HEALTH,
    },
    RuleMeta {
        id: "eks.nodegroup.version_skew",
        title: "A node group runs an older Kubernetes minor than the control plane",
        docs: DOCS_BEST_PRACTICES,
    },
    RuleMeta {
        id: "eks.addon.unhealthy",
        title: "An EKS add-on is degraded or failed",
        docs: DOCS_ADDONS,
    },
    RuleMeta {
        id: "eks.addon.incompatible",
        title: "An EKS add-on version is not compatible with the cluster version",
        docs: DOCS_ADDONS,
    },
    RuleMeta {
        id: "eks.access.aws_auth_invalid",
        title: "The aws-auth ConfigMap cannot be parsed",
        docs: DOCS_ACCESS,
    },
    RuleMeta {
        id: "eks.upgrade.insight_failing",
        title: "An EKS upgrade insight reports a problem for the next version",
        docs: DOCS_INSIGHTS,
    },
];

fn minor(v: &str) -> Option<u32> {
    v.split('.')
        .nth(1)?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

/// `eks_cluster_info`.
pub fn cluster(c: &Cluster) -> Report<ClusterInfo> {
    let name = c.name().unwrap_or("");
    let status = c.status().map_or("UNKNOWN", |s| s.as_str());
    let mut details = BTreeMap::new();
    let mut put = |k: &str, v: Option<String>| {
        if let Some(v) = v.filter(|v| !v.is_empty()) {
            details.insert(k.to_owned(), v);
        }
    };
    put("platform version", c.platform_version().map(str::to_owned));
    put("endpoint", c.endpoint().map(str::to_owned));
    let vpc = c.resources_vpc_config();
    put(
        "endpoint access",
        vpc.map(|v| {
            format!(
                "public={} private={}{}",
                v.endpoint_public_access(),
                v.endpoint_private_access(),
                if v.endpoint_public_access() {
                    format!(" (from {})", v.public_access_cidrs().join(","))
                } else {
                    String::new()
                }
            )
        }),
    );
    put("vpc", vpc.and_then(|v| v.vpc_id().map(str::to_owned)));
    let auth = c
        .access_config()
        .and_then(|a| a.authentication_mode())
        .map(|m| m.as_str().to_owned());
    put("authentication mode", auth.clone());
    put(
        "oidc issuer",
        c.identity()
            .and_then(|i| i.oidc())
            .and_then(|o| o.issuer())
            .map(str::to_owned),
    );
    let enabled_logs: Vec<String> = c
        .logging()
        .map(aws_sdk_eks::types::Logging::cluster_logging)
        .unwrap_or_default()
        .iter()
        .filter(|s| s.enabled() == Some(true))
        .flat_map(|s| s.types().iter().map(|t| t.as_str().to_owned()))
        .collect();
    put(
        "control-plane logs",
        Some(if enabled_logs.is_empty() {
            "none".into()
        } else {
            enabled_logs.join(",")
        }),
    );
    put(
        "auto mode",
        c.compute_config()
            .and_then(aws_sdk_eks::types::ComputeConfigResponse::enabled)
            .map(|e| e.to_string()),
    );
    put(
        "support",
        c.upgrade_policy()
            .and_then(|u| u.support_type())
            .map(|s| s.as_str().to_owned()),
    );

    let mut findings = Vec::new();
    let issues = c
        .health()
        .map(aws_sdk_eks::types::ClusterHealth::issues)
        .unwrap_or_default();
    if !issues.is_empty() || !matches!(status, "ACTIVE" | "CREATING" | "UPDATING") {
        let mut f = Finding::new(
            "eks.cluster.unhealthy",
            if status == "FAILED" { Severity::Critical } else { Severity::High },
            Confidence::High,
            format!("EKS cluster {name} is {status} with {} health issue(s)", issues.len()),
        )
        .explain("EKS reports control-plane problems that it cannot fix by itself, typically because a resource it depends on (subnets, security groups, the cluster IAM role, a KMS key) was changed or deleted.")
        .docs(DOCS_HEALTH)
        .fix("Fix each issue in the evidence on the AWS side (restore the subnet, security group, IAM role or KMS key permission); EKS clears the issue once the resource works again.");
        for i in issues.iter().take(5) {
            f = f.evidence(
                Source::Status,
                format!(
                    "{}: {}",
                    i.code().map_or("?", |c| c.as_str()),
                    truncate(i.message().unwrap_or(""), 300)
                ),
            );
        }
        findings.push(f);
    }
    if let Some(v) = vpc
        && v.endpoint_public_access()
        && v.public_access_cidrs().iter().any(|c| c == "0.0.0.0/0")
    {
        findings.push(
            Finding::new("eks.cluster.public_endpoint", Severity::Low, Confidence::High, format!("The API server of {name} accepts connections from any IP address"))
                .explain("The endpoint is public with 0.0.0.0/0 allowed. Authentication still applies, but the API server is exposed to scanning and credential stuffing.")
                .evidence(Source::Spec, format!("endpointPublicAccess=true publicAccessCidrs={}", v.public_access_cidrs().join(",")))
                .docs(DOCS_ENDPOINT)
                .fix("Restrict publicAccessCidrs to your networks, or turn the public endpoint off and use the private one."),
        );
    }
    if !enabled_logs.iter().any(|t| t == "audit") {
        findings.push(
            Finding::new("eks.cluster.audit_logging_off", Severity::Low, Confidence::High, format!("Audit logs of {name} are not sent to CloudWatch"))
                .explain("Without the audit log type, who changed what in the cluster cannot be traced afterwards, and eks_logs cannot search control-plane audit events.")
                .evidence(Source::Spec, format!("enabled log types: {}", if enabled_logs.is_empty() { "none".into() } else { enabled_logs.join(",") }))
                .docs(DOCS_LOGGING)
                .fix("Enable at least the audit and authenticator log types in the cluster's logging configuration."),
        );
    }
    if auth.as_deref() == Some("CONFIG_MAP") {
        findings.push(
            Finding::new("eks.cluster.auth_configmap_only", Severity::Low, Confidence::High, format!("{name} grants access only through the aws-auth ConfigMap"))
                .explain("With authenticationMode CONFIG_MAP, one bad edit of aws-auth can lock out nodes and users, and access entries cannot be used.")
                .evidence(Source::Spec, "authenticationMode=CONFIG_MAP")
                .docs(DOCS_ACCESS)
                .fix("Switch to API_AND_CONFIG_MAP, migrate the mappings to access entries, then to API."),
        );
    }
    (
        ClusterInfo {
            name: name.to_owned(),
            version: c.version().unwrap_or("").to_owned(),
            status: status.to_owned(),
            details,
        },
        findings,
    )
}

/// `eks_nodegroups`.
pub fn node_pools(
    cluster_version: &str,
    groups: &[Nodegroup],
    fargate: &[FargateProfile],
) -> Report<Vec<NodePool>> {
    let mut pools = Vec::new();
    let mut findings = Vec::new();
    for g in groups {
        let name = g.nodegroup_name().unwrap_or("");
        let status = g.status().map_or("UNKNOWN", |s| s.as_str());
        let version = g.version().unwrap_or("");
        let size = g.scaling_config().map_or_else(String::new, |s| {
            format!(
                "{} ({}-{})",
                s.desired_size().unwrap_or(0),
                s.min_size().unwrap_or(0),
                s.max_size().unwrap_or(0)
            )
        });
        pools.push(NodePool {
            name: name.to_owned(),
            kind: "managed".into(),
            status: status.to_owned(),
            version: version.to_owned(),
            size,
            machine: format!(
                "{} {}",
                g.instance_types().join(","),
                g.capacity_type().map_or("", |c| c.as_str())
            )
            .trim()
            .to_owned(),
        });
        let issues = g
            .health()
            .map(aws_sdk_eks::types::NodegroupHealth::issues)
            .unwrap_or_default();
        if !issues.is_empty() || matches!(status, "DEGRADED" | "CREATE_FAILED" | "DELETE_FAILED") {
            let mut f = Finding::new("eks.nodegroup.unhealthy", Severity::High, Confidence::High, format!("Node group {name} is {status} with {} health issue(s)", issues.len()))
                .explain("EKS cannot keep the node group at its desired size or manage its instances, usually because of the launch template, the node IAM role, subnets out of IP addresses, or EC2 capacity and quotas.")
                .docs(DOCS_HEALTH)
                .fix("Fix the cause named in each issue in the evidence (for example AsgInstanceLaunchFailures: read the Auto Scaling group's activity; NodeCreationFailure: nodes cannot join, check the node role and the subnet's route to the API server).");
            for i in issues.iter().take(5) {
                f = f.evidence(
                    Source::Status,
                    format!(
                        "{}: {}",
                        i.code().map_or("?", |c| c.as_str()),
                        truncate(i.message().unwrap_or(""), 300)
                    ),
                );
            }
            findings.push(f);
        }
        if let (Some(cm), Some(gm)) = (minor(cluster_version), minor(version))
            && gm < cm
        {
            findings.push(
                Finding::new("eks.nodegroup.version_skew", Severity::Medium, Confidence::High, format!("Node group {name} runs Kubernetes {version}, behind the control plane's {cluster_version}"))
                    .explain("Nodes may lag the control plane by a few minors, but each lagging minor must be upgraded before the next control-plane upgrade, and new features and fixes do not reach these nodes.")
                    .evidence(Source::Status, format!("node group version {version}, cluster version {cluster_version}"))
                    .docs(DOCS_BEST_PRACTICES)
                    .fix("Update the node group to the cluster's version (a managed rolling update that respects PodDisruptionBudgets)."),
            );
        }
    }
    for p in fargate {
        pools.push(NodePool {
            name: p.fargate_profile_name().unwrap_or("").to_owned(),
            kind: "fargate".into(),
            status: p.status().map_or("UNKNOWN", |s| s.as_str()).to_owned(),
            version: cluster_version.to_owned(),
            size: "-".into(),
            machine: "fargate".into(),
        });
    }
    (pools, findings)
}

/// `eks_addons`: each add-on with the versions EKS publishes for the cluster's version.
pub fn addons(
    cluster_version: &str,
    installed: &[(EksAddon, Vec<AddonInfo>)],
) -> Report<Vec<Addon>> {
    let mut rows = Vec::new();
    let mut findings = Vec::new();
    for (a, infos) in installed {
        let name = a.addon_name().unwrap_or("");
        let version = a.addon_version().unwrap_or("");
        let status = a.status().map_or("UNKNOWN", |s| s.as_str());
        let compatible: Vec<&str> = infos
            .iter()
            .filter(|i| i.addon_name() == Some(name))
            .flat_map(aws_sdk_eks::types::AddonInfo::addon_versions)
            .filter(|v| {
                v.compatibilities()
                    .iter()
                    .any(|c| c.cluster_version() == Some(cluster_version))
            })
            .filter_map(|v| v.addon_version())
            .collect();
        // EKS lists versions newest first.
        let latest = compatible.first().copied().unwrap_or("");
        rows.push(Addon {
            name: name.into(),
            version: version.into(),
            status: status.into(),
            latest: latest.into(),
        });
        let issues = a
            .health()
            .map(aws_sdk_eks::types::AddonHealth::issues)
            .unwrap_or_default();
        if !issues.is_empty() || matches!(status, "DEGRADED" | "CREATE_FAILED" | "UPDATE_FAILED") {
            let mut f = Finding::new("eks.addon.unhealthy", Severity::High, Confidence::High, format!("Add-on {name} is {status}"))
                .explain("EKS manages this add-on and reports that it is not working; the cluster feature it provides (networking, DNS, storage, identity) may be impaired.")
                .docs(DOCS_ADDONS)
                .fix("Fix the issues in the evidence (often a missing IAM role for the add-on's ServiceAccount, or configuration values the add-on rejects), then update the add-on to retry.");
            for i in issues.iter().take(5) {
                f = f.evidence(
                    Source::Status,
                    format!(
                        "{}: {}",
                        i.code().map_or("?", |c| c.as_str()),
                        truncate(i.message().unwrap_or(""), 300)
                    ),
                );
            }
            findings.push(f);
        }
        if !compatible.is_empty() && !compatible.contains(&version) {
            findings.push(
                Finding::new("eks.addon.incompatible", Severity::High, Confidence::High, format!("Add-on {name} {version} is not a published version for Kubernetes {cluster_version}"))
                    .explain("EKS publishes the add-on versions it supports per Kubernetes version; this one is not among them, so it may misbehave and blocks a clean upgrade.")
                    .evidence(Source::Related, format!("compatible versions: {}", compatible.iter().take(5).copied().collect::<Vec<_>>().join(", ")))
                    .docs(DOCS_ADDONS)
                    .fix(format!("Update {name} to {latest} (or another compatible version) with the EKS add-on API before the next cluster upgrade.")),
            );
        }
    }
    (rows, findings)
}

/// Most failing insights described in findings.
pub const DESCRIBED_INSIGHTS: usize = 5;

fn insight_status(s: Option<&InsightStatusValue>) -> &'static str {
    match s {
        Some(InsightStatusValue::Passing) => "passing",
        Some(InsightStatusValue::Warning) => "warning",
        Some(InsightStatusValue::Error) => "error",
        _ => "unknown",
    }
}

/// Upgrade data for `upgrade_readiness`: versions after `current`, its end of standard
/// support, and the upgrade-readiness insights (`described` holds the failing ones in full).
pub fn upgrade(
    current: &str,
    versions: &[ClusterVersionInformation],
    insights: &[InsightSummary],
    described: &[Insight],
) -> Report<UpgradeInfo> {
    let mut available: Vec<(u32, String)> = versions
        .iter()
        .filter_map(|v| {
            let version = v.cluster_version()?;
            let m = minor(version)?;
            (m > minor(current)?).then(|| (m, version.to_owned()))
        })
        .collect();
    available.sort();
    available.dedup();
    let support_ends = versions
        .iter()
        .find(|v| v.cluster_version() == Some(current))
        .and_then(|v| v.end_of_standard_support_date())
        .map(aws_sdk_eks::primitives::DateTime::secs);
    let mut checks: Vec<UpgradeCheck> = insights
        .iter()
        .map(|i| {
            let status = i.insight_status();
            UpgradeCheck {
                name: i.name().unwrap_or("").to_owned(),
                status: insight_status(status.and_then(|s| s.status())).to_owned(),
                detail: truncate(status.and_then(|s| s.reason()).unwrap_or(""), 200),
            }
        })
        .collect();
    checks.sort_by(|a, b| a.name.cmp(&b.name));
    let mut findings = Vec::new();
    for i in described {
        let status = insight_status(i.insight_status().and_then(|s| s.status()));
        if !matches!(status, "error" | "warning") {
            continue;
        }
        let name = i.name().unwrap_or("");
        let version = i.kubernetes_version().unwrap_or("the next version");
        let mut f = Finding::new(
            "eks.upgrade.insight_failing",
            if status == "error" { Severity::High } else { Severity::Medium },
            Confidence::High,
            format!(
                "EKS upgrade insight {name:?} {} for Kubernetes {version}",
                if status == "error" { "fails" } else { "warns" }
            ),
        )
        .explain(truncate(i.description().unwrap_or("EKS checks the cluster against what changes in the next Kubernetes version."), 300))
        .docs(DOCS_INSIGHTS)
        .fix(truncate(i.recommendation().unwrap_or("Resolve what the insight reports before upgrading; EKS refreshes insights about once a day."), 300));
        if let Some(reason) = i.insight_status().and_then(|s| s.reason()) {
            f = f.evidence(Source::Status, truncate(reason, 300));
        }
        for d in i
            .category_specific_summary()
            .map(aws_sdk_eks::types::InsightCategorySpecificSummary::deprecation_details)
            .unwrap_or_default()
            .iter()
            .take(3)
        {
            let agents: Vec<&str> = d
                .client_stats()
                .iter()
                .filter_map(|c| c.user_agent())
                .take(3)
                .collect();
            f = f.evidence(
                Source::Related,
                truncate(
                    &format!(
                        "{} stops being served in {}; use {}{}",
                        d.usage().unwrap_or("?"),
                        d.stop_serving_version().unwrap_or("?"),
                        d.replaced_with().unwrap_or("?"),
                        if agents.is_empty() {
                            String::new()
                        } else {
                            format!(" (recent callers: {})", agents.join(", "))
                        }
                    ),
                    300,
                ),
            );
        }
        for r in i.resources().iter().take(3) {
            if let Some(uri) = r.kubernetes_resource_uri().or_else(|| r.arn()) {
                f = f.evidence(Source::Related, format!("affected: {}", truncate(uri, 200)));
            }
        }
        findings.push(f);
    }
    (
        UpgradeInfo {
            current: current.to_owned(),
            available: available.into_iter().map(|(_, v)| v).collect(),
            support_ends,
            checks,
        },
        findings,
    )
}

#[derive(Deserialize)]
struct AwsAuthEntry {
    #[serde(alias = "rolearn", alias = "userarn")]
    arn: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    groups: Vec<String>,
}

/// `eks_access`: access entries with their policies, then `aws-auth` mappings.
pub fn access(
    entries: &[(AccessEntry, Vec<AssociatedAccessPolicy>)],
    aws_auth: Option<&ConfigMap>,
) -> Report<Vec<AccessMapping>> {
    let mut rows = Vec::new();
    let mut findings = Vec::new();
    for (e, policies) in entries {
        let groups = e.kubernetes_groups().iter().cloned();
        let grants: Vec<String> = groups
            .chain(policies.iter().map(|p| {
                let policy = p
                    .policy_arn()
                    .unwrap_or("")
                    .rsplit('/')
                    .next()
                    .unwrap_or("")
                    .to_owned();
                match p.access_scope() {
                    Some(s) if !s.namespaces().is_empty() => {
                        format!("{policy} in {}", s.namespaces().join(","))
                    }
                    _ => policy,
                }
            }))
            .collect();
        let cluster_admin = grants
            .iter()
            .any(|g| g == "system:masters" || g == "AmazonEKSClusterAdminPolicy");
        rows.push(AccessMapping {
            principal: e.principal_arn().unwrap_or("").into(),
            source: format!("access entry ({})", e.r#type().unwrap_or("STANDARD")),
            username: e.username().unwrap_or("").into(),
            grants,
            cluster_admin,
        });
    }
    if let Some(cm) = aws_auth {
        for key in ["mapRoles", "mapUsers"] {
            let Some(text) = cm.data.as_ref().and_then(|d| d.get(key)) else {
                continue;
            };
            match serde_saphyr::from_str::<Vec<AwsAuthEntry>>(text) {
                Ok(list) => rows.extend(list.into_iter().map(|m| AccessMapping {
                    cluster_admin: m.groups.iter().any(|g| g == "system:masters"),
                    principal: m.arn,
                    source: format!("aws-auth {key}"),
                    username: m.username,
                    grants: m.groups,
                })),
                Err(err) => findings.push(
                    Finding::new("eks.access.aws_auth_invalid", Severity::High, Confidence::High, format!("aws-auth {key} is not valid YAML"))
                        .explain("EKS ignores mappings it cannot parse: nodes mapped through aws-auth cannot join and users mapped there are refused.")
                        .evidence(
                            Source::Status,
                            // The first line: the rest quotes the ConfigMap back.
                            truncate(err.to_string().lines().next().unwrap_or(""), 300),
                        )
                        .docs(DOCS_ACCESS)
                        .fix("Fix the YAML of the aws-auth ConfigMap in kube-system (a list of rolearn/userarn, username and groups), or move the mappings to access entries.")
                        .next("get_resource", json!({"kind": "ConfigMap", "name": "aws-auth", "namespace": "kube-system", "view": "yaml"}), "read the aws-auth ConfigMap"),
                ),
            }
        }
    }
    rows.sort_by(|a, b| {
        b.cluster_admin
            .cmp(&a.cluster_admin)
            .then_with(|| a.principal.cmp(&b.principal))
    });
    (rows, findings)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn minors() {
        assert_eq!(minor("1.33"), Some(33));
        assert_eq!(minor("1.31.4-eks-abc"), Some(31));
        assert_eq!(minor("bogus"), None);
    }

    #[test]
    fn every_rule_id_is_catalogued_once() {
        let mut ids: Vec<&str> = RULES.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), RULES.len());
        assert!(ids.iter().all(|i| i.starts_with("eks.")));
    }
}
