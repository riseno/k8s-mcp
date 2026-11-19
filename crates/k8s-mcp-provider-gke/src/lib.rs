#![forbid(unsafe_code)]
//! The Google Kubernetes Engine provider (PROPOSAL §8.4): cluster info, node pools, add-ons,
//! Workload Identity checks, Cloud Logging and upgrade data, as cloud-neutral reports with
//! findings.
//!
//! Credentials come from Application Default Credentials: `GOOGLE_APPLICATION_CREDENTIALS`,
//! the gcloud ADC file, or (in a cluster or with `GCE_METADATA_HOST`) the metadata server.
//! Executable-sourced credentials are refused: k8s-mcp runs no commands besides kubeconfig exec
//! plugins. TLS is rustls with ring, which the binary installs as the process provider.

pub mod identity;
mod rules;

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use google_cloud_auth::credentials::{self, Credentials};
use google_cloud_container_v1::client::ClusterManager;
use google_cloud_container_v1::model::Cluster;
use google_cloud_iam_admin_v1::client::Iam;
use google_cloud_logging_v2::client::LoggingServiceV2;
use k8s_mcp_core::provider::{ClusterIdentity, ProviderId};
use k8s_mcp_core::text::truncate;
use k8s_mcp_core::{Error, Result};
use k8s_mcp_provider::{
    AccessMapping, Addon, CloudLogs, ClusterInfo, IdentityReport, LogQuery, NodePool, Provider,
    Report, UpgradeInfo, WorkloadIdentity,
};

pub use rules::RULES;

/// Per-call timeout for Google Cloud APIs.
const GCP_TIMEOUT: Duration = Duration::from_secs(15);

/// A GKE cluster reached through the Google Cloud APIs.
pub struct Gke {
    /// The cluster's RBAC bindings, set by the caller before `access` (the provider makes no
    /// Kubernetes calls).
    pub rbac: Vec<k8s_mcp_provider::RbacGrant>,
    clusters: ClusterManager,
    iam: Iam,
    logging: LoggingServiceV2,
    project: String,
    location: String,
    cluster: String,
}

/// Whether Application Default Credentials can resolve without probing the network: a key or
/// ADC file, or a metadata server that exists (in a cluster, or pointed to by
/// `GCE_METADATA_HOST`). Off Google Cloud with neither, the metadata server lookup would only
/// time out.
fn adc_available() -> bool {
    let file = std::env::var_os("GOOGLE_APPLICATION_CREDENTIALS").is_some()
        || adc_file().is_some_and(|p| p.exists());
    let metadata = std::env::var_os("KUBERNETES_SERVICE_HOST").is_some()
        || std::env::var_os("GCE_METADATA_HOST").is_some();
    file || metadata
}

/// The gcloud ADC file (`gcloud auth application-default login`).
fn adc_file() -> Option<std::path::PathBuf> {
    if cfg!(windows) {
        std::env::var_os("APPDATA").map(|d| {
            std::path::PathBuf::from(d).join("gcloud/application_default_credentials.json")
        })
    } else {
        std::env::var_os("HOME").map(|d| {
            std::path::PathBuf::from(d).join(".config/gcloud/application_default_credentials.json")
        })
    }
}

/// The first line of the no-credentials error, which the identity check turns into its skip
/// reason.
const NO_CREDENTIALS: &str = "no Google Cloud credentials found";

fn credentials() -> Result<Credentials> {
    if std::env::var("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES").as_deref() == Ok("1") {
        return Err(Error::Forbidden(
            "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1 allows executable-sourced Google credentials, which run a command; k8s-mcp runs no commands besides kubeconfig exec plugins. Unset it and use a credentials file, `gcloud auth application-default login` or Workload Identity.".into(),
        ));
    }
    if !adc_available() {
        return Err(Error::Forbidden(format!(
            "{NO_CREDENTIALS} (tried GOOGLE_APPLICATION_CREDENTIALS, the gcloud ADC file and, in a cluster, the metadata server). Run `gcloud auth application-default login`, set GOOGLE_APPLICATION_CREDENTIALS, or use GKE Workload Identity."
        )));
    }
    credentials::Builder::default()
        // Skips the metadata-server lookup of the universe domain when building clients.
        .with_universe_domain("googleapis.com")
        .build()
        .map_err(|e| {
            Error::Forbidden(format!(
                "load Google Cloud credentials: {}",
                truncate(&e.to_string(), 300)
            ))
        })
}

/// A Google Cloud error as a k8s-mcp error: what failed, why, and what to do.
fn gcp_error(what: &str, e: &google_cloud_container_v1::Error) -> Error {
    tracing::debug!(error = ?e, "Google Cloud call failed: {what}");
    let message = e
        .status()
        .map_or_else(|| e.to_string(), |s| s.message.clone());
    let message = truncate(message.lines().next().unwrap_or(""), 300);
    match e.http_status_code() {
        Some(403) => Error::Forbidden(format!(
            "{what}: permission denied ({message}). Grant the read-only roles in docs/providers/gke.md (roles/container.clusterViewer, roles/logging.viewer, and iam.serviceAccounts.get/getIamPolicy for identity checks) to the identity k8s-mcp uses."
        )),
        Some(404) => Error::NotFound(format!(
            "{what}: not found ({message}). Check the project, location and cluster name, or pass --gke-cluster <project>/<location>/<name>."
        )),
        Some(401) => Error::Forbidden(format!(
            "{what}: the Google Cloud credentials were rejected ({message}). Renew them (`gcloud auth application-default login`) or check Workload Identity."
        )),
        _ if e.is_authentication() => Error::Forbidden(format!(
            "{what}: the Google Cloud credentials could not be used ({message}). Renew them (`gcloud auth application-default login`) or check Workload Identity."
        )),
        _ => Error::Api(format!("{what}: {message}")),
    }
}

/// Run one Google Cloud call with the timeout and error mapping. `request` builds the SDK's
/// request future inside the box: those futures are large (over 20 KB), and every caller would
/// otherwise carry one.
fn call<'a, T, F, Fut>(
    what: &'a str,
    request: F,
) -> Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>
where
    T: Send + 'a,
    F: FnOnce() -> Fut + Send + 'a,
    Fut: Future<Output = google_cloud_container_v1::Result<T>> + Send + 'a,
{
    Box::pin(async move {
        match tokio::time::timeout(GCP_TIMEOUT, request()).await {
            Ok(r) => r.map_err(|e| gcp_error(what, &e)),
            Err(_) => Err(Error::Api(format!(
                "{what}: no answer within {}s",
                GCP_TIMEOUT.as_secs()
            ))),
        }
    })
}

impl Gke {
    /// Clients for the cluster in `identity` (name, location and project are required). No
    /// request is made until a report is asked for.
    pub async fn connect(identity: &ClusterIdentity) -> Result<Self> {
        let (Some(cluster), Some(location), Some(project)) = (
            identity.name.clone(),
            identity.region.clone(),
            identity.account.clone(),
        ) else {
            return Err(Error::InvalidInput(
                "the GKE project, location or cluster name is unknown from the kubeconfig and nodes; pass --gke-cluster <project>/<location>/<name>".into(),
            ));
        };
        let creds = credentials()?;
        let build = |what: &str, e: &dyn std::fmt::Display| {
            Error::Config(format!("build the {what} client: {e}"))
        };
        let clusters = ClusterManager::builder()
            .with_credentials(creds.clone())
            .build()
            .await
            .map_err(|e| build("GKE", &e))?;
        let iam = Iam::builder()
            .with_credentials(creds.clone())
            .build()
            .await
            .map_err(|e| build("IAM", &e))?;
        let logging = LoggingServiceV2::builder()
            .with_credentials(creds)
            .build()
            .await
            .map_err(|e| build("Cloud Logging", &e))?;
        Ok(Self::with_clients(
            clusters, iam, logging, project, location, cluster,
        ))
    }

    /// From existing clients (tests point them at a mock server).
    pub fn with_clients(
        clusters: ClusterManager,
        iam: Iam,
        logging: LoggingServiceV2,
        project: String,
        location: String,
        cluster: String,
    ) -> Self {
        Self {
            rbac: Vec::new(),
            clusters,
            iam,
            logging,
            project,
            location,
            cluster,
        }
    }

    fn name(&self) -> String {
        format!(
            "projects/{}/locations/{}/clusters/{}",
            self.project, self.location, self.cluster
        )
    }

    /// Boxed: `Cluster` is large (over 20 KB) and callers keep it across further calls.
    async fn get_cluster(&self) -> Result<Box<Cluster>> {
        call(
            &format!(
                "get GKE cluster {} in {}/{}",
                self.cluster, self.project, self.location
            ),
            || self.clusters.get_cluster().set_name(self.name()).send(),
        )
        .await
        .map(Box::new)
    }

    /// The facts the identity check needs from Google Cloud.
    async fn identity_facts(&self, k8s: &WorkloadIdentity) -> Result<identity::CloudFacts> {
        let c = self.get_cluster().await?;
        let node_pool_modes = c
            .node_pools
            .iter()
            .map(|p| {
                let mode = p
                    .config
                    .as_ref()
                    .and_then(|c| c.workload_metadata_config.as_ref())
                    .and_then(|w| w.mode.name());
                (
                    p.name.clone(),
                    mode.unwrap_or("MODE_UNSPECIFIED").to_owned(),
                )
            })
            .collect();
        let email = k8s
            .service_account
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(identity::GSA_ANNOTATION))
            .cloned();
        let gsa = match email {
            None => None,
            Some(email) => Some(self.gsa(&email).await?),
        };
        Ok(identity::CloudFacts {
            workload_pool: c
                .workload_identity_config
                .map(|w| w.workload_pool)
                .unwrap_or_default(),
            autopilot: c.autopilot.is_some_and(|a| a.enabled),
            node_pool_modes,
            gsa,
        })
    }

    /// A Google service account, and the members of its workloadIdentityUser bindings.
    async fn gsa(&self, email: &str) -> Result<identity::GsaFacts> {
        let name = format!("projects/-/serviceAccounts/{email}");
        let sa = match call(&format!("get service account {email}"), || {
            self.iam.get_service_account().set_name(&name).send()
        })
        .await
        {
            Ok(sa) => sa,
            Err(Error::NotFound(_)) => {
                return Ok(identity::GsaFacts {
                    email: email.to_owned(),
                    ..Default::default()
                });
            }
            Err(e) => return Err(e),
        };
        let policy = call(&format!("get the IAM policy of {email}"), || {
            self.iam.get_iam_policy().set_resource(&name).send()
        })
        .await?;
        Ok(identity::GsaFacts {
            email: email.to_owned(),
            exists: true,
            disabled: sa.disabled,
            wi_users: policy
                .bindings
                .into_iter()
                .filter(|b| b.role == identity::WI_USER_ROLE)
                .flat_map(|b| b.members)
                .collect(),
        })
    }
}

/// Why the cloud half of a check was skipped, for `cloud_checks`.
fn skip_reason(e: &Error) -> String {
    let text = e.to_string();
    if text.starts_with(NO_CREDENTIALS) {
        "no Google Cloud credentials".into()
    } else {
        truncate(&text, 300)
    }
}

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The Cloud Logging filter for a query on this cluster.
fn log_filter(
    project: &str,
    location: &str,
    cluster: &str,
    q: &LogQuery,
    since: &str,
) -> Result<String> {
    let mut terms = vec![
        format!("resource.labels.project_id={}", quote(project)),
        format!("resource.labels.location={}", quote(location)),
        format!("resource.labels.cluster_name={}", quote(cluster)),
        format!("timestamp>={}", quote(since)),
    ];
    if q.source == "application" {
        terms.push("resource.type=\"k8s_container\"".into());
        if let Some(ns) = &q.namespace {
            terms.push(format!("resource.labels.namespace_name={}", quote(ns)));
        }
        if let Some(p) = &q.pod {
            terms.push(format!("resource.labels.pod_name={}", quote(p)));
        }
    } else {
        match q.component.as_deref() {
            Some("audit") => {
                terms.push("resource.type=\"k8s_cluster\"".into());
                terms.push("logName:\"cloudaudit.googleapis.com\"".into());
            }
            Some(c) => {
                let component = match c {
                    "api" => "apiserver",
                    "scheduler" => "scheduler",
                    "controllerManager" => "controller-manager",
                    other => {
                        return Err(Error::InvalidInput(format!(
                            "unknown component {other:?} for GKE: use api, audit, controllerManager or scheduler"
                        )));
                    }
                };
                terms.push("resource.type=\"k8s_control_plane_component\"".into());
                terms.push(format!(
                    "resource.labels.component_name={}",
                    quote(component)
                ));
            }
            None => terms.push("resource.type=\"k8s_control_plane_component\"".into()),
        }
    }
    if let Some(g) = &q.grep {
        terms.push(quote(g));
    }
    Ok(terms.join(" AND "))
}

/// `pod: message` from a log entry (text or the JSON payload's `message`/`log`).
fn entry_line(e: &google_cloud_logging_v2::model::LogEntry) -> String {
    let labels = e.resource.as_ref().map(|r| &r.labels);
    let who = labels
        .and_then(|l| l.get("pod_name").or_else(|| l.get("component_name")))
        .cloned()
        .unwrap_or_default();
    let text = e.text_payload().cloned().or_else(|| {
        e.json_payload().map(|j| {
            ["message", "log", "msg"]
                .iter()
                .find_map(|k| j.get(*k).and_then(|v| v.as_str()).map(str::to_owned))
                .unwrap_or_else(|| serde_json::Value::Object((**j).clone()).to_string())
        })
    });
    let text = text.unwrap_or_default();
    let text = text.trim_end();
    if who.is_empty() {
        text.to_owned()
    } else {
        format!("{who}: {text}")
    }
}

impl Provider for Gke {
    fn id(&self) -> ProviderId {
        ProviderId::Gke
    }

    async fn cluster_info(&self) -> Result<Report<ClusterInfo>> {
        Ok(rules::cluster(&*self.get_cluster().await?))
    }

    async fn node_pools(&self) -> Result<Report<Vec<NodePool>>> {
        let c = self.get_cluster().await?;
        Ok(rules::node_pools(&c.current_master_version, &c.node_pools))
    }

    async fn addons(&self) -> Result<Report<Vec<Addon>>> {
        Ok(rules::addons(&*self.get_cluster().await?))
    }

    async fn access(&self) -> Result<Report<Vec<AccessMapping>>> {
        Ok(rules::access(&*self.get_cluster().await?, &self.rbac))
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
        let filter = log_filter(&self.project, &self.location, &self.cluster, q, &since)?;
        let out = call(
            &format!("read Cloud Logging for cluster {}", self.cluster),
            || {
                self.logging
                    .list_log_entries()
                    .set_resource_names([format!("projects/{}", self.project)])
                    .set_filter(&filter)
                    .set_order_by("timestamp desc")
                    .set_page_size(q.limit)
                    .send()
            },
        )
        .await?;
        let mut lines: Vec<String> = out.entries.iter().map(entry_line).collect();
        lines.reverse(); // newest first from the API; oldest first in the output
        Ok(CloudLogs {
            source: format!("Cloud Logging matching {filter}"),
            lines,
            truncated: !out.next_page_token.is_empty(),
        })
    }

    async fn upgrade_checks(&self, _target: Option<&str>) -> Result<Report<UpgradeInfo>> {
        let c = self.get_cluster().await?;
        let server = call(
            &format!(
                "get the GKE server config of {}/{}",
                self.project, self.location
            ),
            || {
                self.clusters
                    .get_server_config()
                    .set_name(format!(
                        "projects/{}/locations/{}",
                        self.project, self.location
                    ))
                    .send()
            },
        )
        .await?;
        Ok(rules::upgrade(&c, &server))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn log_filters() {
        let q = LogQuery {
            source: "application".into(),
            namespace: Some("shop".into()),
            pod: Some("api-1".into()),
            grep: Some("time\"out".into()),
            ..Default::default()
        };
        assert_eq!(
            log_filter("acme", "europe-west1", "shop", &q, "2026-11-16T11:00:00Z").unwrap(),
            r#"resource.labels.project_id="acme" AND resource.labels.location="europe-west1" AND resource.labels.cluster_name="shop" AND timestamp>="2026-11-16T11:00:00Z" AND resource.type="k8s_container" AND resource.labels.namespace_name="shop" AND resource.labels.pod_name="api-1" AND "time\"out""#
        );
        let q = LogQuery {
            source: "control-plane".into(),
            component: Some("authenticator".into()),
            ..Default::default()
        };
        assert!(log_filter("p", "l", "c", &q, "t").is_err());
    }

    #[test]
    fn no_credentials_is_one_short_line() {
        let e = Error::Forbidden(format!("{NO_CREDENTIALS} (tried ...)"));
        assert_eq!(skip_reason(&e), "no Google Cloud credentials");
    }
}
