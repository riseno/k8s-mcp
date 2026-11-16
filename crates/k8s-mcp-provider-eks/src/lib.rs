#![forbid(unsafe_code)]
//! The Amazon EKS provider (PROPOSAL §8.4): cluster info, managed node groups and Fargate
//! profiles, add-ons with their compatible versions, and access entries plus `aws-auth`, as
//! cloud-neutral reports with findings.
//!
//! Credentials come from the AWS default chain (environment, profile, SSO cache, IRSA, EKS
//! Pod Identity), never prompted for. `credential_process` profiles are not supported: k8s-mcp
//! runs no commands besides kubeconfig exec plugins. The HTTP client is rustls + ring
//! (ADR 0007).

pub mod identity;
mod rules;

use std::time::Duration;

use aws_config::BehaviorVersion;
use aws_config::timeout::TimeoutConfig;
use aws_sdk_eks::Client;
use aws_sdk_eks::error::DisplayErrorContext;
use aws_sdk_eks::types::{AssociatedAccessPolicy, FargateProfile, Nodegroup};
use aws_smithy_http_client::tls::{self, rustls_provider::CryptoMode};
use k8s_mcp_core::provider::{ClusterIdentity, ProviderId};
use k8s_mcp_core::{Error, Result};
use k8s_mcp_provider::{
    AccessMapping, Addon, CloudLogs, ClusterInfo, IdentityReport, LogQuery, NodePool, Provider,
    Report, WorkloadIdentity,
};
use k8s_openapi::api::core::v1::ConfigMap;

pub use rules::RULES;

/// Per-operation timeout for AWS calls.
const AWS_TIMEOUT: Duration = Duration::from_secs(15);

/// An EKS cluster reached through the AWS API.
pub struct Eks {
    client: Client,
    iam: aws_sdk_iam::Client,
    logs: aws_sdk_cloudwatchlogs::Client,
    cluster: String,
    region: String,
    /// The `aws-auth` ConfigMap from kube-system, when readable (for `access`).
    pub aws_auth: Option<ConfigMap>,
}

impl Eks {
    /// Clients for the cluster in `identity` (its name and region are required), with the
    /// kubeconfig's AWS profile when it has one. No request is made until a report is asked for.
    pub async fn connect(identity: &ClusterIdentity) -> Result<Self> {
        let (Some(cluster), Some(region)) = (identity.name.clone(), identity.region.clone()) else {
            return Err(Error::InvalidInput(
                "the EKS cluster name or region is unknown from the kubeconfig and nodes; pass --eks-cluster <name> and --eks-region <region>".into(),
            ));
        };
        let http = aws_smithy_http_client::Builder::new()
            .tls_provider(tls::Provider::Rustls(CryptoMode::Ring))
            .build_https();
        let mut loader = aws_config::defaults(BehaviorVersion::latest())
            .http_client(http)
            .region(aws_config::Region::new(region.clone()))
            .timeout_config(
                TimeoutConfig::builder()
                    .operation_timeout(AWS_TIMEOUT)
                    .build(),
            );
        if let Some(p) = &identity.profile {
            loader = loader.profile_name(p);
        }
        let config = loader.load().await;
        Ok(Self::with_clients(
            Client::new(&config),
            aws_sdk_iam::Client::new(&config),
            aws_sdk_cloudwatchlogs::Client::new(&config),
            cluster,
            region,
        ))
    }

    /// From existing clients (tests use mocked clients).
    pub fn with_clients(
        client: Client,
        iam: aws_sdk_iam::Client,
        logs: aws_sdk_cloudwatchlogs::Client,
        cluster: String,
        region: String,
    ) -> Self {
        Self {
            client,
            iam,
            logs,
            cluster,
            region,
            aws_auth: None,
        }
    }

    /// The facts the identity check needs from AWS.
    async fn identity_facts(&self, k8s: &WorkloadIdentity) -> Result<identity::CloudFacts> {
        let cluster = self
            .client
            .describe_cluster()
            .name(&self.cluster)
            .send()
            .await
            .map_err(|e| self.err("describe the cluster", &e))?;
        let issuer = cluster
            .cluster
            .and_then(|c| c.identity)
            .and_then(|i| i.oidc)
            .and_then(|o| o.issuer)
            .unwrap_or_default();
        let oidc_providers = self
            .iam
            .list_open_id_connect_providers()
            .send()
            .await
            .map_err(|e| aws_error("list IAM OIDC providers", &e))?
            .open_id_connect_provider_list
            .unwrap_or_default()
            .into_iter()
            .filter_map(|p| p.arn)
            .collect();
        let sa = &k8s.service_account.metadata;
        let irsa_role = match sa
            .annotations
            .as_ref()
            .and_then(|a| a.get(identity::ROLE_ANNOTATION))
        {
            Some(arn) => Some(self.role(arn).await?),
            None => None,
        };
        let associations = self
            .client
            .list_pod_identity_associations()
            .cluster_name(&self.cluster)
            .set_namespace(sa.namespace.clone())
            .set_service_account(sa.name.clone())
            .send()
            .await
            .map_err(|e| self.err("list Pod Identity associations", &e))?
            .associations
            .unwrap_or_default();
        let mut roles = Vec::new();
        for a in associations {
            let Some(id) = a.association_id else { continue };
            let described = self
                .client
                .describe_pod_identity_association()
                .cluster_name(&self.cluster)
                .association_id(&id)
                .send()
                .await
                .map_err(|e| self.err(&format!("describe Pod Identity association {id}"), &e))?;
            if let Some(arn) = described.association.and_then(|a| a.role_arn) {
                roles.push(self.role(&arn).await?);
            }
        }
        Ok(identity::CloudFacts {
            issuer,
            oidc_providers,
            irsa_role,
            associations: roles,
        })
    }

    /// A role and its trust policy (`trust: None` when the role does not exist).
    async fn role(&self, arn: &str) -> Result<identity::RoleFacts> {
        let name = arn.rsplit('/').next().unwrap_or(arn);
        match self.iam.get_role().role_name(name).send().await {
            Ok(out) => Ok(identity::RoleFacts {
                arn: arn.to_owned(),
                trust: out
                    .role
                    .and_then(|r| r.assume_role_policy_document)
                    .and_then(|d| identity::decode_policy(&d)),
            }),
            Err(e)
                if e.as_service_error().is_some_and(
                    aws_sdk_iam::operation::get_role::GetRoleError::is_no_such_entity_exception,
                ) =>
            {
                Ok(identity::RoleFacts {
                    arn: arn.to_owned(),
                    trust: None,
                })
            }
            Err(e) => Err(aws_error(&format!("get IAM role {name}"), &e)),
        }
    }

    fn err<E, R>(&self, what: &str, e: &aws_sdk_eks::error::SdkError<E, R>) -> Error
    where
        E: std::error::Error + 'static,
        R: std::fmt::Debug,
    {
        aws_error(
            &format!("{what} for EKS cluster {} in {}", self.cluster, self.region),
            e,
        )
    }

    async fn nodegroups(&self) -> Result<Vec<Nodegroup>> {
        let names: Vec<String> = self
            .client
            .list_nodegroups()
            .cluster_name(&self.cluster)
            .into_paginator()
            .items()
            .send()
            .collect::<std::result::Result<_, _>>()
            .await
            .map_err(|e| self.err("list node groups", &e))?;
        let mut out = Vec::new();
        for n in names {
            let ng = self
                .client
                .describe_nodegroup()
                .cluster_name(&self.cluster)
                .nodegroup_name(&n)
                .send()
                .await
                .map_err(|e| self.err(&format!("describe node group {n}"), &e))?;
            out.extend(ng.nodegroup);
        }
        Ok(out)
    }

    async fn fargate_profiles(&self) -> Result<Vec<FargateProfile>> {
        let names: Vec<String> = self
            .client
            .list_fargate_profiles()
            .cluster_name(&self.cluster)
            .into_paginator()
            .items()
            .send()
            .collect::<std::result::Result<_, _>>()
            .await
            .map_err(|e| self.err("list Fargate profiles", &e))?;
        let mut out = Vec::new();
        for n in names {
            let p = self
                .client
                .describe_fargate_profile()
                .cluster_name(&self.cluster)
                .fargate_profile_name(&n)
                .send()
                .await
                .map_err(|e| self.err(&format!("describe Fargate profile {n}"), &e))?;
            out.extend(p.fargate_profile);
        }
        Ok(out)
    }

    async fn version(&self) -> Result<String> {
        let c = self
            .client
            .describe_cluster()
            .name(&self.cluster)
            .send()
            .await
            .map_err(|e| self.err("describe the cluster", &e))?;
        Ok(c.cluster.and_then(|c| c.version).unwrap_or_default())
    }
}

/// An AWS error as a k8s-mcp error: what failed, why, and what to do. The SDK's debug dump
/// is only logged (`--log-level debug`): it is long and buries the guidance.
fn aws_error(what: &str, e: &dyn std::error::Error) -> Error {
    let full = DisplayErrorContext(e).to_string();
    tracing::debug!(error = %full, "AWS call failed: {what}");
    // CredentialsNotLoaded: every provider of the default chain found nothing to use.
    if full.contains("the credential provider was not enabled") {
        return Error::Forbidden(format!(
            "no AWS credentials found (tried environment variables, the shared config and credentials files, web identity, the container and instance metadata endpoints), so k8s-mcp cannot {what}. Provide them through AWS_PROFILE or environment variables, an SSO login, IRSA or EKS Pod Identity."
        ));
    }
    let detail = k8s_mcp_core::text::truncate(&k8s_mcp_core::error::error_chain(e), 500);
    if full.contains("AccessDenied")
        || full.contains("UnauthorizedOperation")
        || full.contains("not authorized")
    {
        Error::Forbidden(format!(
            "{what}: {detail}. Grant the read-only EKS permissions in docs/providers/eks.md to the AWS identity k8s-mcp uses."
        ))
    } else if full.contains("ResourceNotFound") {
        Error::NotFound(format!(
            "{what}: {detail}. Check the cluster name and region, or pass --eks-cluster and --eks-region."
        ))
    } else if full.to_ascii_lowercase().contains("credential") {
        Error::Forbidden(format!(
            "{what}: the AWS credentials could not be loaded ({detail}). Check AWS_PROFILE or the environment variables, renew an expired SSO login (`aws sso login`), or check IRSA or EKS Pod Identity."
        ))
    } else {
        Error::Api(format!("{what}: {detail}"))
    }
}

impl Provider for Eks {
    fn id(&self) -> ProviderId {
        ProviderId::Eks
    }

    async fn cluster_info(&self) -> Result<Report<ClusterInfo>> {
        let out = self
            .client
            .describe_cluster()
            .name(&self.cluster)
            .send()
            .await
            .map_err(|e| self.err("describe the cluster", &e))?;
        let cluster = out
            .cluster
            .ok_or_else(|| Error::NotFound(format!("EKS cluster {} not found", self.cluster)))?;
        Ok(rules::cluster(&cluster))
    }

    async fn node_pools(&self) -> Result<Report<Vec<NodePool>>> {
        let version = self.version().await?;
        Ok(rules::node_pools(
            &version,
            &self.nodegroups().await?,
            &self.fargate_profiles().await?,
        ))
    }

    async fn addons(&self) -> Result<Report<Vec<Addon>>> {
        let version = self.version().await?;
        let names: Vec<String> = self
            .client
            .list_addons()
            .cluster_name(&self.cluster)
            .into_paginator()
            .items()
            .send()
            .collect::<std::result::Result<_, _>>()
            .await
            .map_err(|e| self.err("list add-ons", &e))?;
        let mut addons = Vec::new();
        for n in &names {
            let a = self
                .client
                .describe_addon()
                .cluster_name(&self.cluster)
                .addon_name(n)
                .send()
                .await
                .map_err(|e| self.err(&format!("describe add-on {n}"), &e))?;
            let versions = self
                .client
                .describe_addon_versions()
                .addon_name(n)
                .kubernetes_version(&version)
                .send()
                .await
                .map_err(|e| self.err(&format!("list versions of add-on {n}"), &e))?;
            if let Some(a) = a.addon {
                addons.push((a, versions.addons.unwrap_or_default()));
            }
        }
        Ok(rules::addons(&version, &addons))
    }

    async fn access(&self) -> Result<Report<Vec<AccessMapping>>> {
        let principals: Vec<String> = match self
            .client
            .list_access_entries()
            .cluster_name(&self.cluster)
            .into_paginator()
            .items()
            .send()
            .collect::<std::result::Result<_, _>>()
            .await
        {
            Ok(p) => p,
            // Clusters in CONFIG_MAP mode have no access entries; aws-auth still applies.
            Err(e)
                if DisplayErrorContext(&e)
                    .to_string()
                    .contains("authentication mode") =>
            {
                Vec::new()
            }
            Err(e) => return Err(self.err("list access entries", &e)),
        };
        let mut entries = Vec::new();
        for p in principals {
            let entry = self
                .client
                .describe_access_entry()
                .cluster_name(&self.cluster)
                .principal_arn(&p)
                .send()
                .await
                .map_err(|e| self.err(&format!("describe access entry {p}"), &e))?;
            let policies: Vec<AssociatedAccessPolicy> = self
                .client
                .list_associated_access_policies()
                .cluster_name(&self.cluster)
                .principal_arn(&p)
                .send()
                .await
                .map_err(|e| self.err(&format!("list access policies of {p}"), &e))?
                .associated_access_policies
                .unwrap_or_default();
            if let Some(e) = entry.access_entry {
                entries.push((e, policies));
            }
        }
        Ok(rules::access(&entries, self.aws_auth.as_ref()))
    }

    async fn identity_check(&self, k8s: &WorkloadIdentity) -> Report<IdentityReport> {
        match self.identity_facts(k8s).await {
            Ok(facts) => identity::evaluate(k8s, Ok(&facts)),
            Err(e) => identity::evaluate(k8s, Err(&skip_reason(&e))),
        }
    }

    async fn logs(&self, q: &LogQuery) -> Result<CloudLogs> {
        let quote = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
        let (group, prefix, pattern) = if q.source == "application" {
            // Container Insights (Fluent Bit) writes JSON records with kubernetes metadata.
            let mut terms = Vec::new();
            if let Some(ns) = &q.namespace {
                terms.push(format!("$.kubernetes.namespace_name = {}", quote(ns)));
            }
            if let Some(p) = &q.pod {
                terms.push(format!("$.kubernetes.pod_name = {}", quote(p)));
            }
            if let Some(g) = &q.grep {
                terms.push(format!("$.log = {}", quote(&format!("*{g}*"))));
            }
            let pattern = (!terms.is_empty()).then(|| format!("{{ {} }}", terms.join(" && ")));
            (
                format!("/aws/containerinsights/{}/application", self.cluster),
                None,
                pattern,
            )
        } else {
            let prefix = q.component.as_deref().map(|c| {
                match c {
                    "audit" => "kube-apiserver-audit-",
                    "authenticator" => "authenticator-",
                    "controllerManager" => "kube-controller-manager-",
                    "scheduler" => "kube-scheduler-",
                    _ => "kube-apiserver-",
                }
                .to_owned()
            });
            (
                format!("/aws/eks/{}/cluster", self.cluster),
                prefix,
                q.grep.as_deref().map(quote),
            )
        };
        let out = self
            .logs
            .filter_log_events()
            .log_group_name(&group)
            .set_log_stream_name_prefix(prefix)
            .set_filter_pattern(pattern.clone())
            .start_time(q.since_ms)
            .limit(q.limit)
            .send()
            .await
            .map_err(|e| {
                if DisplayErrorContext(&e).to_string().contains("ResourceNotFound") {
                    Error::NotFound(format!("log group {group} does not exist: turn on the control-plane log types (eks_cluster_info lists them) or Container Insights for application logs"))
                } else {
                    aws_error(&format!("read CloudWatch log group {group}"), &e)
                }
            })?;
        let lines = out
            .events
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| e.message)
            .map(|m| application_line(&m).unwrap_or(m))
            .collect();
        Ok(CloudLogs {
            source: match pattern {
                Some(p) => format!("{group} matching {p}"),
                None => group,
            },
            lines,
            truncated: out.next_token.is_some(),
        })
    }
}

/// `pod: log` from a Container Insights JSON record.
fn application_line(message: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(message).ok()?;
    Some(format!(
        "{}: {}",
        v["kubernetes"]["pod_name"].as_str()?,
        v["log"].as_str()?.trim_end()
    ))
}

/// Why the cloud half of a check was skipped, for `cloud_checks`.
fn skip_reason(e: &Error) -> String {
    let text = e.to_string();
    if text.starts_with("no AWS credentials found") {
        "no AWS credentials".into()
    } else {
        k8s_mcp_core::text::truncate(&text, 300)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Issue #47: the no-credentials error is one line, and the identity check still turns it
    /// into its short skip reason.
    #[test]
    fn no_credentials_is_one_short_line() {
        #[derive(Debug)]
        struct NotLoaded;
        impl std::fmt::Display for NotLoaded {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("the credential provider was not enabled")
            }
        }
        impl std::error::Error for NotLoaded {}
        let e = aws_error("describe the cluster", &NotLoaded);
        assert!(matches!(e, Error::Forbidden(_)));
        assert!(!e.to_string().contains('\n'));
        assert_eq!(skip_reason(&e), "no AWS credentials");
    }
}
