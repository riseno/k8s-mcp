//! AKS rules: pure functions from ARM JSON (`Microsoft.ContainerService/managedClusters`) to
//! cloud-neutral rows and findings.

use std::collections::BTreeMap;

use k8s_mcp_core::finding::{Confidence, Finding, RuleMeta, Severity, Source};
use k8s_mcp_core::text::truncate;
use k8s_mcp_provider::{
    AccessMapping, Addon, ClusterInfo, NodePool, RbacGrant, Report, UpgradeCheck, UpgradeInfo,
};
use serde_json::Value;

const DOCS_TROUBLESHOOT: &str =
    "https://learn.microsoft.com/troubleshoot/azure/azure-kubernetes/welcome-azure-kubernetes";
const DOCS_LOCAL_ACCOUNTS: &str =
    "https://learn.microsoft.com/azure/aks/manage-local-accounts-managed-azure-ad";
const DOCS_API_ACCESS: &str =
    "https://learn.microsoft.com/azure/aks/api-server-authorized-ip-ranges";
const DOCS_VERSIONS: &str = "https://learn.microsoft.com/azure/aks/supported-kubernetes-versions";

/// Rules emitted by the AKS provider.
pub const RULES: &[RuleMeta] = &[
    RuleMeta {
        id: "aks.cluster.unhealthy",
        title: "The AKS cluster failed to provision or is stopped",
        docs: DOCS_TROUBLESHOOT,
    },
    RuleMeta {
        id: "aks.cluster.local_accounts",
        title: "Local accounts are enabled, so a static admin kubeconfig exists",
        docs: DOCS_LOCAL_ACCOUNTS,
    },
    RuleMeta {
        id: "aks.cluster.public_endpoint",
        title: "The API server is public without authorized IP ranges",
        docs: DOCS_API_ACCESS,
    },
    RuleMeta {
        id: "aks.nodepool.unhealthy",
        title: "A node pool failed to provision or is stopped",
        docs: DOCS_TROUBLESHOOT,
    },
    RuleMeta {
        id: "aks.nodepool.version_skew",
        title: "A node pool runs an older Kubernetes minor than the control plane",
        docs: DOCS_VERSIONS,
    },
];

/// Minor of a version such as `1.33.2`.
pub fn minor(v: &str) -> Option<u32> {
    v.split('.').nth(1)?.parse().ok()
}

fn s<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    path.iter().fold(v, |v, k| &v[*k]).as_str().unwrap_or("")
}

fn b(v: &Value, path: &[&str]) -> Option<bool> {
    path.iter().fold(v, |v, k| &v[*k]).as_bool()
}

fn local_accounts(name: &str) -> Finding {
    Finding::new("aks.cluster.local_accounts", Severity::Low, Confidence::High, format!("Local accounts are enabled on {name}"))
        .explain("With local accounts, `az aks get-credentials --admin` returns a static cluster-admin certificate that bypasses Entra ID and cannot be revoked short of rotating the cluster certificates.")
        .evidence(Source::Spec, "disableLocalAccounts: false")
        .docs(DOCS_LOCAL_ACCOUNTS)
        .fix("Enable Entra ID integration and set disableLocalAccounts (`az aks update --disable-local-accounts`).")
}

/// Built-in Azure roles that act on AKS clusters: id, name, and whether it is cluster-admin
/// (for the credential roles: only while local accounts are enabled).
const AKS_ROLES: &[(&str, &str, bool)] = &[
    (
        "b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b",
        "Azure Kubernetes Service RBAC Cluster Admin",
        true,
    ),
    (
        "3498e952-d568-435e-9b2c-8d77e338d7f7",
        "Azure Kubernetes Service RBAC Admin",
        false,
    ),
    (
        "a7ffa36f-339b-4b5c-8bdf-e2c188b2c0eb",
        "Azure Kubernetes Service RBAC Writer",
        false,
    ),
    (
        "7f6c6a51-bcf8-42ba-9220-52d62157d7db",
        "Azure Kubernetes Service RBAC Reader",
        false,
    ),
    (
        "0ab0b1a8-8aac-4efd-b8c2-3ee1fb270be8",
        "Azure Kubernetes Service Cluster Admin Role",
        true,
    ),
    (
        "4abbcc35-e782-43d8-92c5-2d3f1bd2253f",
        "Azure Kubernetes Service Cluster User Role",
        false,
    ),
];

/// `aks_access`: Entra admin groups, Azure role assignments that apply to the cluster, and the
/// RBAC bindings of Entra principals (object ids, user principal names and groups).
pub fn access(c: &Value, assignments: &[Value], rbac: &[RbacGrant]) -> Report<Vec<AccessMapping>> {
    let p = &c["properties"];
    let local = !b(p, &["disableLocalAccounts"]).unwrap_or(false);
    let mut rows: Vec<AccessMapping> = p["aadProfile"]["adminGroupObjectIDs"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|g| AccessMapping {
            principal: g.to_owned(),
            source: "Entra admin group (aadProfile)".into(),
            username: g.to_owned(),
            grants: vec!["ClusterRole/cluster-admin".into()],
            cluster_admin: true,
        })
        .collect();
    for a in assignments {
        let role_id = s(a, &["properties", "roleDefinitionId"])
            .rsplit('/')
            .next()
            .unwrap_or("");
        let (role, admin) = AKS_ROLES.iter().find(|(id, _, _)| *id == role_id).map_or(
            (role_id, false),
            |(id, name, admin)| {
                (
                    *name,
                    *admin && (local || *id != "0ab0b1a8-8aac-4efd-b8c2-3ee1fb270be8"),
                )
            },
        );
        let principal = s(a, &["properties", "principalId"]);
        let scope = s(a, &["properties", "scope"]);
        rows.push(AccessMapping {
            principal: principal.to_owned(),
            source: format!(
                "Azure role assignment ({}{})",
                s(a, &["properties", "principalType"]),
                if scope.to_ascii_lowercase().ends_with(&format!(
                    "/managedclusters/{}",
                    s(c, &["name"]).to_ascii_lowercase()
                )) {
                    ""
                } else {
                    ", inherited"
                }
            ),
            username: principal.to_owned(),
            grants: vec![role.to_owned()],
            cluster_admin: admin,
        });
    }
    let entra = |g: &&RbacGrant| match g.kind.as_str() {
        "User" => g.subject.contains('@') || is_object_id(&g.subject),
        "Group" => !g.subject.starts_with("system:"),
        _ => false,
    };
    rows.extend(rbac.iter().filter(entra).map(RbacGrant::mapping));
    rows.sort_by(|a, b| (&a.source, &a.principal).cmp(&(&b.source, &b.principal)));
    let findings = if local {
        vec![local_accounts(s(c, &["name"]))]
    } else {
        Vec::new()
    };
    (rows, findings)
}

/// An Entra object id (a GUID).
fn is_object_id(s: &str) -> bool {
    s.len() == 36
        && s.chars().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// The control plane's version: the running one, else the requested one.
pub fn version(c: &Value) -> &str {
    let current = s(c, &["properties", "currentKubernetesVersion"]);
    if current.is_empty() {
        s(c, &["properties", "kubernetesVersion"])
    } else {
        current
    }
}

/// `aks_cluster_info`.
pub fn cluster(c: &Value) -> Report<ClusterInfo> {
    let p = &c["properties"];
    let name = s(c, &["name"]);
    let provisioning = s(p, &["provisioningState"]);
    let power = s(p, &["powerState", "code"]);
    let mut details = BTreeMap::new();
    let mut put = |k: &str, v: String| {
        if !v.is_empty() {
            details.insert(k.to_owned(), v);
        }
    };
    put("location", s(c, &["location"]).into());
    put("sku tier", s(c, &["sku", "tier"]).into());
    put("power state", power.into());
    put(
        "network plugin",
        s(p, &["networkProfile", "networkPlugin"]).into(),
    );
    put(
        "network plugin mode",
        s(p, &["networkProfile", "networkPluginMode"]).into(),
    );
    put("fqdn", s(p, &["fqdn"]).into());
    let private = b(p, &["apiServerAccessProfile", "enablePrivateCluster"]).unwrap_or(false);
    let ranges: Vec<&str> = p["apiServerAccessProfile"]["authorizedIPRanges"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    put(
        "api server access",
        format!(
            "private={private} authorized ranges={}",
            if ranges.is_empty() {
                "none".to_owned()
            } else {
                ranges.join(",")
            }
        ),
    );
    let oidc = b(p, &["oidcIssuerProfile", "enabled"]).unwrap_or(false);
    put(
        "oidc issuer",
        if oidc {
            s(p, &["oidcIssuerProfile", "issuerURL"]).to_owned()
        } else {
            "disabled".into()
        },
    );
    put(
        "workload identity",
        if b(p, &["securityProfile", "workloadIdentity", "enabled"]).unwrap_or(false) {
            "enabled"
        } else {
            "disabled"
        }
        .into(),
    );
    put(
        "entra id integration",
        if p["aadProfile"].is_object() {
            "enabled"
        } else {
            "disabled"
        }
        .into(),
    );
    put(
        "azure rbac",
        b(p, &["aadProfile", "enableAzureRBAC"]).map_or_else(String::new, |v| v.to_string()),
    );
    let local_disabled = b(p, &["disableLocalAccounts"]).unwrap_or(false);
    put(
        "local accounts",
        if local_disabled {
            "disabled"
        } else {
            "enabled"
        }
        .into(),
    );
    put("support plan", s(p, &["supportPlan"]).into());
    put(
        "auto upgrade channel",
        s(p, &["autoUpgradeProfile", "upgradeChannel"]).into(),
    );

    let mut findings = Vec::new();
    if provisioning == "Failed" || power == "Stopped" {
        let mut f = Finding::new(
            "aks.cluster.unhealthy",
            if power == "Stopped" { Severity::Critical } else { Severity::High },
            Confidence::High,
            format!("AKS cluster {name} is {} (provisioning {provisioning})", if power.is_empty() { "unknown" } else { power }),
        )
        .explain("A Failed provisioning state means the last operation on the cluster did not complete, often because of quota, a policy, or a changed network or identity resource; a Stopped cluster runs no control plane.")
        .docs(DOCS_TROUBLESHOOT)
        .fix("For Failed, read the operation's error in the activity log, fix it (quota, policy, subnet, identity), then reconcile with `az aks update`. For Stopped, `az aks start`.");
        f = f.evidence(
            Source::Status,
            format!("provisioningState {provisioning}, powerState {power}"),
        );
        findings.push(f);
    }
    if !local_disabled {
        findings.push(local_accounts(name));
    }
    if !private && ranges.is_empty() {
        findings.push(
            Finding::new("aks.cluster.public_endpoint", Severity::Low, Confidence::High, format!("The API server of {name} accepts connections from any IP address"))
                .explain("The cluster is not private and no authorized IP ranges restrict the API server. Authentication still applies, but the endpoint is exposed to scanning and credential stuffing.")
                .evidence(Source::Spec, "enablePrivateCluster false, authorizedIPRanges empty")
                .docs(DOCS_API_ACCESS)
                .fix("Set authorized IP ranges (`az aks update --api-server-authorized-ip-ranges`), or use a private cluster."),
        );
    }
    (
        ClusterInfo {
            name: name.to_owned(),
            version: version(c).to_owned(),
            status: if power.is_empty() {
                provisioning.to_owned()
            } else {
                format!("{power} ({provisioning})")
            },
            details,
        },
        findings,
    )
}

/// `aks_node_pools`, from the cluster's `agentPoolProfiles`.
pub fn node_pools(c: &Value) -> Report<Vec<NodePool>> {
    let control_plane = version(c).to_owned();
    let mut rows = Vec::new();
    let mut findings = Vec::new();
    for p in c["properties"]["agentPoolProfiles"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let name = s(p, &["name"]);
        let provisioning = s(p, &["provisioningState"]);
        let power = s(p, &["powerState", "code"]);
        let version = {
            let v = s(p, &["currentOrchestratorVersion"]);
            if v.is_empty() {
                s(p, &["orchestratorVersion"])
            } else {
                v
            }
        };
        let size = if b(p, &["enableAutoScaling"]).unwrap_or(false) {
            format!(
                "{} (autoscaling {}-{})",
                p["count"], p["minCount"], p["maxCount"]
            )
        } else {
            format!("{} (fixed)", p["count"])
        };
        let spot = s(p, &["scaleSetPriority"]) == "Spot";
        rows.push(NodePool {
            name: name.into(),
            kind: format!("{} pool", s(p, &["mode"])),
            status: if power.is_empty() {
                provisioning.into()
            } else {
                format!("{power} ({provisioning})")
            },
            version: version.into(),
            size,
            machine: format!("{}{}", s(p, &["vmSize"]), if spot { " spot" } else { "" }),
        });
        if provisioning == "Failed" || power == "Stopped" {
            findings.push(
                Finding::new("aks.nodepool.unhealthy", Severity::High, Confidence::High, format!("Node pool {name} is {} (provisioning {provisioning})", if power.is_empty() { "unknown" } else { power }))
                    .explain("The last operation on the node pool did not complete (often VM SKU quota or capacity, subnet address space, or a policy), or the pool is stopped and runs no nodes.")
                    .evidence(Source::Status, format!("provisioningState {provisioning}, powerState {power}, node image {}", truncate(s(p, &["nodeImageVersion"]), 100)))
                    .docs(DOCS_TROUBLESHOOT)
                    .fix("Read the failed operation in the activity log, fix the cause (request quota for the VM size, enlarge the subnet, adjust the policy), then reconcile with `az aks nodepool update`; for a stopped pool, `az aks nodepool start`."),
            );
        }
        if let (Some(cm), Some(pm)) = (minor(&control_plane), minor(version))
            && pm < cm
        {
            findings.push(
                Finding::new("aks.nodepool.version_skew", Severity::Medium, Confidence::High, format!("Node pool {name} runs Kubernetes {version}, behind the control plane's {control_plane}"))
                    .explain("Node pools may lag the control plane by a few minors, but each lagging minor must be upgraded before the next control-plane upgrade, and new features and fixes do not reach these nodes.")
                    .evidence(Source::Status, format!("node pool version {version}, control plane {control_plane}"))
                    .docs(DOCS_VERSIONS)
                    .fix("Upgrade the node pool to the control plane's version (`az aks nodepool upgrade`), which drains nodes and respects PodDisruptionBudgets."),
            );
        }
    }
    (rows, findings)
}

/// `aks_addons`: add-on profiles of the cluster, then cluster extensions.
pub fn addons(c: &Value, extensions: &[Value]) -> Report<Vec<Addon>> {
    let mut rows: Vec<Addon> = c["properties"]["addonProfiles"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(name, p)| Addon {
            name: name.clone(),
            version: "managed".into(),
            status: if b(p, &["enabled"]).unwrap_or(false) {
                "enabled"
            } else {
                "disabled"
            }
            .into(),
            latest: String::new(),
        })
        .collect();
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    rows.extend(extensions.iter().map(|e| Addon {
        name: format!("extension {}", s(e, &["properties", "extensionType"])),
        version: s(e, &["properties", "version"]).into(),
        status: s(e, &["properties", "provisioningState"]).into(),
        latest: String::new(),
    }));
    (rows, Vec::new())
}

/// The AKS section of `upgrade_readiness`: the control-plane versions the upgrade profile
/// offers (previews left out) and the support plan.
pub fn upgrade(c: &Value, profile: &Value) -> Report<UpgradeInfo> {
    let current = version(c).to_owned();
    let mut available: Vec<(u32, String)> =
        profile["properties"]["controlPlaneProfile"]["upgrades"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|u| !u["isPreview"].as_bool().unwrap_or(false))
            .filter_map(|u| {
                let v = u["kubernetesVersion"].as_str()?;
                let m = minor(v)?;
                (m > minor(&current)?).then(|| (m, format!("1.{m}")))
            })
            .collect();
    available.sort();
    available.dedup();
    let plan = s(&c["properties"], &["supportPlan"]);
    let checks = vec![UpgradeCheck {
        name: "support plan".into(),
        status: "passing".into(),
        detail: if plan.is_empty() {
            "KubernetesOfficial".into()
        } else {
            plan.into()
        },
    }];
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
    use super::*;

    #[test]
    fn minors() {
        assert_eq!(minor("1.33.2"), Some(33));
        assert_eq!(minor("bogus"), None);
    }

    #[test]
    fn every_rule_id_is_catalogued_once() {
        let mut ids: Vec<&str> = RULES.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), RULES.len());
        assert!(ids.iter().all(|i| i.starts_with("aks.")));
    }
}
