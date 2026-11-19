#![forbid(unsafe_code)]
//! The Azure Kubernetes Service provider (PROPOSAL §8.4): cluster info, node pools, add-ons,
//! workload identity checks, Log Analytics logs and upgrade data, as cloud-neutral reports with
//! findings. It calls ARM and the Log Analytics query API directly (pinned GA api-versions),
//! with tokens from `azure_identity`.
//!
//! Credentials are chosen from the environment, never probed: workload identity
//! (`AZURE_FEDERATED_TOKEN_FILE`), a service principal secret (`AZURE_TENANT_ID`,
//! `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`), or managed identity where `IDENTITY_ENDPOINT` is
//! set. The Azure CLI credential is not used: k8s-mcp runs no commands besides kubeconfig exec
//! plugins (clippy.toml forbids those types). TLS is rustls with ring.

pub mod identity;
mod rules;

use std::sync::Arc;
use std::time::Duration;

use azure_core::credentials::{Secret, TokenCredential};
use azure_core::http::{ClientOptions, Transport};
use azure_identity::{
    ClientAssertionCredentialOptions, ClientSecretCredential, ClientSecretCredentialOptions,
    ManagedIdentityCredential, ManagedIdentityCredentialOptions, WorkloadIdentityCredential,
    WorkloadIdentityCredentialOptions,
};
use k8s_mcp_core::provider::{ClusterIdentity, ProviderId};
use k8s_mcp_core::text::truncate;
use k8s_mcp_core::{Error, Result};
use k8s_mcp_provider::{
    AccessMapping, Addon, CloudLogs, ClusterInfo, IdentityReport, LogQuery, NodePool, Provider,
    Report, UpgradeInfo, WorkloadIdentity,
};
use serde_json::{Value, json};

pub use rules::RULES;

/// Azure Resource Manager.
pub const ARM: &str = "https://management.azure.com";
/// The Log Analytics query API.
pub const LOG_ANALYTICS: &str = "https://api.loganalytics.azure.com";
const ARM_SCOPE: &str = "https://management.azure.com/.default";
const LA_SCOPE: &str = "https://api.loganalytics.io/.default";
/// Pinned GA api-versions.
const AKS_API: &str = "2026-09-01";
const EXTENSIONS_API: &str = "2025-03-01";
const ROLE_ASSIGNMENTS_API: &str = "2022-04-01";
const IDENTITY_API: &str = "2024-11-30";
const WORKSPACE_API: &str = "2026-03-01";
/// Pages of a list followed at most.
const MAX_PAGES: usize = 20;
/// The first words of the no-credentials error, which the identity check turns into its skip
/// reason.
const NO_CREDENTIALS: &str = "no Azure credentials found";

/// An AKS cluster reached through ARM.
pub struct Aks {
    /// The cluster's RBAC bindings, set by the caller before `access` (the provider makes no
    /// Kubernetes calls).
    pub rbac: Vec<k8s_mcp_provider::RbacGrant>,
    http: reqwest::Client,
    credential: Arc<dyn TokenCredential>,
    arm: String,
    log_analytics: String,
    subscription: String,
    resource_group: String,
    cluster: String,
}

fn client_options(http: &reqwest::Client) -> ClientOptions {
    ClientOptions {
        transport: Some(Transport::new(Arc::new(http.clone()))),
        ..Default::default()
    }
}

/// The credential the environment provides (no subprocess, no probing).
fn credential(http: &reqwest::Client) -> Result<Arc<dyn TokenCredential>> {
    let var = |k| std::env::var(k).ok().filter(|v: &String| !v.is_empty());
    let built = |e: azure_core::Error| {
        Error::Forbidden(format!(
            "set up the Azure credential: {}",
            truncate(&e.to_string(), 300)
        ))
    };
    if var("AZURE_FEDERATED_TOKEN_FILE").is_some() {
        let options = WorkloadIdentityCredentialOptions {
            credential_options: ClientAssertionCredentialOptions {
                client_options: client_options(http),
            },
            ..Default::default()
        };
        return Ok(WorkloadIdentityCredential::new(Some(options)).map_err(built)?);
    }
    if let (Some(tenant), Some(client), Some(secret)) = (
        var("AZURE_TENANT_ID"),
        var("AZURE_CLIENT_ID"),
        var("AZURE_CLIENT_SECRET"),
    ) {
        let options = ClientSecretCredentialOptions {
            client_options: client_options(http),
        };
        return Ok(ClientSecretCredential::new(
            &tenant,
            client,
            Secret::new(secret),
            Some(options),
        )
        .map_err(built)?);
    }
    if var("IDENTITY_ENDPOINT").is_some() {
        let options = ManagedIdentityCredentialOptions {
            client_options: client_options(http),
            ..Default::default()
        };
        return Ok(ManagedIdentityCredential::new(Some(options)).map_err(built)?);
    }
    Err(Error::Forbidden(format!(
        "{NO_CREDENTIALS} (tried workload identity via AZURE_FEDERATED_TOKEN_FILE, a service principal via AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET, and managed identity via IDENTITY_ENDPOINT). Set a service principal's variables, or use AKS workload identity in-cluster; the Azure CLI login is not used because k8s-mcp runs no commands."
    )))
}

/// An ARM or Log Analytics error as a k8s-mcp error.
fn http_error(what: &str, status: reqwest::StatusCode, body: &Value) -> Error {
    let message = truncate(
        body["error"]["message"]
            .as_str()
            .or_else(|| body["error"]["innererror"]["message"].as_str())
            .unwrap_or(""),
        300,
    );
    match status.as_u16() {
        403 => Error::Forbidden(format!(
            "{what}: permission denied ({message}). Grant the roles in docs/providers/aks.md (Reader on the cluster and the managed identities checked, Log Analytics Reader on the workspace) to the identity k8s-mcp uses."
        )),
        404 => Error::NotFound(format!(
            "{what}: not found ({message}). Check the subscription, resource group and cluster name, or pass --aks-cluster <subscription>/<resourceGroup>/<name>."
        )),
        401 => Error::Forbidden(format!(
            "{what}: the Azure credentials were rejected ({message}). Renew them or check workload identity."
        )),
        code => Error::Api(format!("{what}: Azure returned {code}: {message}")),
    }
}

/// Quote a string for KQL.
fn kql_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The KQL for a query on one cluster (`cluster_id` is its ARM resource id).
fn kql(cluster_id: &str, q: &LogQuery, since: &str) -> Result<String> {
    let mut parts = Vec::new();
    let who = if q.source == "application" {
        parts.push("ContainerLogV2".to_owned());
        parts.push(format!("where TimeGenerated >= datetime({since})"));
        parts.push(format!("where _ResourceId =~ {}", kql_string(cluster_id)));
        if let Some(ns) = &q.namespace {
            parts.push(format!("where PodNamespace == {}", kql_string(ns)));
        }
        if let Some(p) = &q.pod {
            parts.push(format!("where PodName == {}", kql_string(p)));
        }
        parts.push("extend Message = tostring(LogMessage)".into());
        "PodName"
    } else {
        match q.component.as_deref() {
            Some("audit") => {
                parts.push("AKSAudit".into());
                parts.push(format!("where TimeGenerated >= datetime({since})"));
                parts.push(format!("where _ResourceId =~ {}", kql_string(cluster_id)));
                parts.push("extend Message = strcat(Verb, \" \", RequestUri, \" by \", tostring(User.username), \": \", tostring(ResponseStatus.code))".into());
                parts.push("extend Who = \"kube-audit\"".into());
            }
            component => {
                let category = match component {
                    None | Some("api") => "kube-apiserver",
                    Some("controllerManager") => "kube-controller-manager",
                    Some("scheduler") => "kube-scheduler",
                    Some(other) => {
                        return Err(Error::InvalidInput(format!(
                            "unknown component {other:?} for AKS: use api, audit, controllerManager or scheduler"
                        )));
                    }
                };
                parts.push("AKSControlPlane".into());
                parts.push(format!("where TimeGenerated >= datetime({since})"));
                parts.push(format!("where _ResourceId =~ {}", kql_string(cluster_id)));
                parts.push(format!("where Category == {}", kql_string(category)));
                parts.push("extend Who = Category".into());
            }
        }
        "Who"
    };
    if let Some(g) = &q.grep {
        parts.push(format!("where Message has {}", kql_string(g)));
    }
    parts.push(format!("project TimeGenerated, Who = {who}, Message"));
    parts.push("order by TimeGenerated desc".into());
    parts.push(format!("take {}", q.limit));
    Ok(parts.join(" | "))
}

impl Aks {
    /// Clients for the cluster in `identity` (subscription, resource group and name are
    /// required). No request is made until a report is asked for.
    pub fn connect(identity: &ClusterIdentity) -> Result<Self> {
        let (Some(cluster), Some(resource_group), Some(subscription)) = (
            identity.name.clone(),
            identity.resource_group.clone(),
            identity.account.clone(),
        ) else {
            return Err(Error::InvalidInput(
                "the AKS subscription, resource group or cluster name is unknown from the kubeconfig and nodes; pass --aks-cluster <subscription>/<resourceGroup>/<name>".into(),
            ));
        };
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| Error::Config(format!("build the Azure HTTP client: {e}")))?;
        let credential = credential(&http)?;
        Ok(Self::with_clients(
            http,
            credential,
            ARM.into(),
            LOG_ANALYTICS.into(),
            subscription,
            resource_group,
            cluster,
        ))
    }

    /// From an HTTP client, a credential and base URLs (tests point them at a mock server).
    pub fn with_clients(
        http: reqwest::Client,
        credential: Arc<dyn TokenCredential>,
        arm: String,
        log_analytics: String,
        subscription: String,
        resource_group: String,
        cluster: String,
    ) -> Self {
        Self {
            rbac: Vec::new(),
            http,
            credential,
            arm,
            log_analytics,
            subscription,
            resource_group,
            cluster,
        }
    }

    fn cluster_id(&self) -> String {
        format!(
            "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.ContainerService/managedClusters/{}",
            self.subscription, self.resource_group, self.cluster
        )
    }

    async fn token(&self, scope: &str) -> Result<String> {
        let t = self
            .credential
            .get_token(&[scope], None)
            .await
            .map_err(|e| Error::Forbidden(format!("get an Azure token: {}. Check the credential (workload identity or service principal).", truncate(&e.to_string(), 300))))?;
        Ok(t.token.secret().to_owned())
    }

    async fn send(&self, what: &str, req: reqwest::RequestBuilder) -> Result<Value> {
        let resp = req
            .send()
            .await
            .map_err(|e| Error::Api(format!("{what}: {}", truncate(&e.to_string(), 300))))?;
        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        if status.is_success() {
            Ok(body)
        } else {
            Err(http_error(what, status, &body))
        }
    }

    /// GET an ARM path. `path` may come from an ARM response (a resource id): it must start
    /// with `/`, so it cannot move the request, and the token, to another host
    /// (`@other.host/...` would make the ARM host a user name).
    async fn arm_get(&self, what: &str, path: &str, api_version: &str) -> Result<Value> {
        if !path.starts_with('/') {
            return Err(Error::Api(format!(
                "{what}: Azure returned a resource id that is not an ARM path; check the cluster's add-on configuration"
            )));
        }
        let token = self.token(ARM_SCOPE).await?;
        self.send(
            what,
            self.http
                .get(format!("{}{path}?api-version={api_version}", self.arm))
                .bearer_auth(token),
        )
        .await
    }

    /// Every item of an ARM list, following `nextLink` only on the ARM host (the token must
    /// never reach another host).
    async fn arm_list(&self, what: &str, path: &str, api_version: &str) -> Result<Vec<Value>> {
        let token = self.token(ARM_SCOPE).await?;
        let mut url = format!("{}{path}?api-version={api_version}", self.arm);
        let mut out = Vec::new();
        for _ in 0..MAX_PAGES {
            let page = self
                .send(what, self.http.get(&url).bearer_auth(&token))
                .await?;
            out.extend(page["value"].as_array().cloned().unwrap_or_default());
            match page["nextLink"].as_str() {
                Some(next) if next.starts_with(&format!("{}/", self.arm)) => {
                    next.clone_into(&mut url);
                }
                _ => break,
            }
        }
        Ok(out)
    }

    async fn get_cluster(&self) -> Result<Value> {
        self.arm_get(
            &format!(
                "get AKS cluster {} in {}/{}",
                self.cluster, self.subscription, self.resource_group
            ),
            &self.cluster_id(),
            AKS_API,
        )
        .await
    }

    /// The facts the identity check needs from Azure.
    async fn identity_facts(&self, k8s: &WorkloadIdentity) -> Result<identity::CloudFacts> {
        let c = self.get_cluster().await?;
        let p = &c["properties"];
        let oidc_issuer = (p["oidcIssuerProfile"]["enabled"].as_bool() == Some(true)).then(|| {
            p["oidcIssuerProfile"]["issuerURL"]
                .as_str()
                .unwrap_or("")
                .to_owned()
        });
        let workload_identity =
            p["securityProfile"]["workloadIdentity"]["enabled"].as_bool() == Some(true);
        let client_id = k8s
            .service_account
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(identity::CLIENT_ID_ANNOTATION))
            .cloned();
        let searched = format!("subscription {}", self.subscription);
        let mut identity = None;
        if let Some(client_id) = client_id {
            let all = self
                .arm_list(
                    "list user-assigned managed identities",
                    &format!("/subscriptions/{}/providers/Microsoft.ManagedIdentity/userAssignedIdentities", self.subscription),
                    IDENTITY_API,
                )
                .await?;
            if let Some(found) = all.iter().find(|i| {
                i["properties"]["clientId"]
                    .as_str()
                    .is_some_and(|c| c.eq_ignore_ascii_case(&client_id))
            }) {
                let id = found["id"].as_str().unwrap_or("");
                let name = found["name"].as_str().unwrap_or("").to_owned();
                let credentials = self
                    .arm_list(
                        &format!("list the federated credentials of {name}"),
                        &format!("{id}/federatedIdentityCredentials"),
                        IDENTITY_API,
                    )
                    .await?;
                identity = Some(identity::ManagedIdentity {
                    name,
                    federated: credentials
                        .iter()
                        .map(|f| identity::FederatedCredential {
                            name: f["name"].as_str().unwrap_or("").into(),
                            issuer: f["properties"]["issuer"].as_str().unwrap_or("").into(),
                            subject: f["properties"]["subject"].as_str().unwrap_or("").into(),
                            audiences: f["properties"]["audiences"]
                                .as_array()
                                .map(|a| {
                                    a.iter()
                                        .filter_map(|v| v.as_str().map(str::to_owned))
                                        .collect()
                                })
                                .unwrap_or_default(),
                        })
                        .collect(),
                });
            }
        }
        Ok(identity::CloudFacts {
            oidc_issuer,
            workload_identity,
            identity,
            searched,
        })
    }

    /// The Log Analytics workspace (its customerId) the monitoring add-on sends to.
    async fn workspace(&self, c: &Value) -> Result<String> {
        let config = &c["properties"]["addonProfiles"]["omsagent"];
        let id = config["config"]
            .as_object()
            .and_then(|m| {
                m.iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("logAnalyticsWorkspaceResourceID"))
            })
            .and_then(|(_, v)| v.as_str())
            .filter(|_| config["enabled"].as_bool() == Some(true));
        let Some(id) = id else {
            return Err(Error::NotFound(format!(
                "Container insights (the monitoring add-on) is not enabled on {}, so its Log Analytics workspace is unknown; enable it (`az aks enable-addons -a monitoring`)",
                self.cluster
            )));
        };
        let ws = self
            .arm_get("get the Log Analytics workspace", id, WORKSPACE_API)
            .await?;
        ws["properties"]["customerId"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| {
                Error::Api(format!(
                    "the Log Analytics workspace {id} has no customerId"
                ))
            })
    }
}

/// Why the cloud half of a check was skipped, for `cloud_checks`.
fn skip_reason(e: &Error) -> String {
    let text = e.to_string();
    if text.starts_with(NO_CREDENTIALS) {
        "no Azure credentials".into()
    } else {
        truncate(&text, 300)
    }
}

/// `who: message` lines from a Log Analytics result, oldest first.
fn log_lines(result: &Value) -> Vec<String> {
    let table = &result["tables"][0];
    let column = |name: &str| {
        table["columns"]
            .as_array()
            .and_then(|c| c.iter().position(|c| c["name"] == name))
    };
    let (Some(who), Some(message)) = (column("Who"), column("Message")) else {
        return Vec::new();
    };
    let mut lines: Vec<String> = table["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| {
            let text = r[message].as_str().unwrap_or("").trim_end();
            match r[who].as_str() {
                Some(w) if !w.is_empty() => format!("{w}: {text}"),
                _ => text.to_owned(),
            }
        })
        .collect();
    lines.reverse();
    lines
}

impl Provider for Aks {
    fn id(&self) -> ProviderId {
        ProviderId::Aks
    }

    async fn cluster_info(&self) -> Result<Report<ClusterInfo>> {
        Ok(rules::cluster(&self.get_cluster().await?))
    }

    async fn node_pools(&self) -> Result<Report<Vec<NodePool>>> {
        Ok(rules::node_pools(&self.get_cluster().await?))
    }

    async fn addons(&self) -> Result<Report<Vec<Addon>>> {
        let c = self.get_cluster().await?;
        // Extensions need Microsoft.KubernetesConfiguration; without it the add-on profiles
        // still answer.
        let extensions = self
            .arm_list(
                "list cluster extensions",
                &format!(
                    "{}/providers/Microsoft.KubernetesConfiguration/extensions",
                    self.cluster_id()
                ),
                EXTENSIONS_API,
            )
            .await
            .unwrap_or_else(|e| {
                tracing::debug!(error = %e, "cluster extensions unavailable");
                Vec::new()
            });
        Ok(rules::addons(&c, &extensions))
    }

    async fn access(&self) -> Result<Report<Vec<AccessMapping>>> {
        let c = self.get_cluster().await?;
        // Assignments at the cluster's scope and inherited from above it.
        let assignments = self
            .arm_list(
                "list the Azure role assignments that apply to the cluster (needs Microsoft.Authorization/roleAssignments/read, part of Reader)",
                &format!(
                    "{}/providers/Microsoft.Authorization/roleAssignments",
                    self.cluster_id()
                ),
                ROLE_ASSIGNMENTS_API,
            )
            .await?;
        Ok(rules::access(&c, &assignments, &self.rbac))
    }

    async fn identity_check(&self, k8s: &WorkloadIdentity) -> Report<IdentityReport> {
        match self.identity_facts(k8s).await {
            Ok(facts) => identity::evaluate(k8s, Ok(&facts)),
            Err(e) => identity::evaluate(k8s, Err(&skip_reason(&e))),
        }
    }

    async fn logs(&self, q: &LogQuery) -> Result<CloudLogs> {
        let since = jiff::Timestamp::from_millisecond(q.since_ms)
            .unwrap_or(jiff::Timestamp::UNIX_EPOCH)
            .to_string();
        let query = kql(&self.cluster_id(), q, &since)?;
        let c = self.get_cluster().await?;
        let workspace = self.workspace(&c).await?;
        let token = self.token(LA_SCOPE).await?;
        let result = self
            .send(
                &format!("query Log Analytics workspace {workspace}"),
                self.http
                    .post(format!("{}/v1/workspaces/{workspace}/query", self.log_analytics))
                    .bearer_auth(token)
                    // The query filters on TimeGenerated; the timespan bounds it server-side.
                    .json(&json!({"query": query, "timespan": "P1D"})),
            )
            .await
            .map_err(|e| match e {
                Error::Api(m) if m.contains("Failed to resolve table") => Error::NotFound(format!(
                    "{m}. Control-plane logs need the cluster's diagnostic settings to send kube-apiserver, kube-audit, kube-controller-manager and kube-scheduler to this workspace as resource-specific tables (AKSControlPlane, AKSAudit)."
                )),
                other => other,
            })?;
        let lines = log_lines(&result);
        let limit = usize::try_from(q.limit).unwrap_or(0);
        Ok(CloudLogs {
            truncated: lines.len() >= limit && limit > 0,
            source: format!("Log Analytics {query}"),
            lines,
        })
    }

    async fn upgrade_checks(&self, _target: Option<&str>) -> Result<Report<UpgradeInfo>> {
        let c = self.get_cluster().await?;
        let profile = self
            .arm_get(
                "get the AKS upgrade profile",
                &format!("{}/upgradeProfiles/default", self.cluster_id()),
                AKS_API,
            )
            .await?;
        Ok(rules::upgrade(&c, &profile))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn kql_quotes_and_filters() {
        let q = LogQuery {
            source: "application".into(),
            namespace: Some("shop".into()),
            pod: Some("api-1".into()),
            grep: Some("time\"out".into()),
            limit: 50,
            ..Default::default()
        };
        assert_eq!(
            kql("/subscriptions/s/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/c", &q, "2026-11-16T11:00:00Z").unwrap(),
            r#"ContainerLogV2 | where TimeGenerated >= datetime(2026-11-16T11:00:00Z) | where _ResourceId =~ "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/c" | where PodNamespace == "shop" | where PodName == "api-1" | extend Message = tostring(LogMessage) | where Message has "time\"out" | project TimeGenerated, Who = PodName, Message | order by TimeGenerated desc | take 50"#
        );
        let q = LogQuery {
            source: "control-plane".into(),
            component: Some("authenticator".into()),
            ..Default::default()
        };
        assert!(kql("id", &q, "t").is_err());
    }

    #[test]
    fn no_credentials_skip_reason() {
        assert_eq!(
            skip_reason(&Error::Forbidden(format!("{NO_CREDENTIALS} (tried ...)"))),
            "no Azure credentials"
        );
    }
}
