#![forbid(unsafe_code)]
//! The Amazon EKS provider (PROPOSAL §8.4): cluster info, managed node groups and Fargate
//! profiles, add-ons with their compatible versions, and access entries plus `aws-auth`, as
//! cloud-neutral reports with findings.
//!
//! Credentials come from the AWS default chain (environment, profile, SSO cache, IRSA, EKS
//! Pod Identity), never prompted for. `credential_process` profiles are not supported: k8s-mcp
//! runs no commands besides kubeconfig exec plugins. The HTTP client is rustls + ring
//! (ADR 0007).

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
use k8s_mcp_provider::{AccessMapping, Addon, ClusterInfo, NodePool, Provider, Report};
use k8s_openapi::api::core::v1::ConfigMap;

pub use rules::RULES;

/// Per-operation timeout for AWS calls.
const AWS_TIMEOUT: Duration = Duration::from_secs(15);

/// An EKS cluster reached through the AWS API.
pub struct Eks {
    client: Client,
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
        Ok(Self::with_client(Client::new(&config), cluster, region))
    }

    /// From an existing client (tests use mocked clients).
    pub fn with_client(client: Client, cluster: String, region: String) -> Self {
        Self {
            client,
            cluster,
            region,
            aws_auth: None,
        }
    }

    fn err<E, R>(&self, what: &str, e: &aws_sdk_eks::error::SdkError<E, R>) -> Error
    where
        E: std::error::Error + 'static,
        R: std::fmt::Debug,
    {
        aws_error(
            &format!("{what} for EKS cluster {} in {}", self.cluster, self.region),
            &DisplayErrorContext(e).to_string(),
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

/// An AWS error as a k8s-mcp error: what failed, why, and what to do.
fn aws_error(what: &str, detail: &str) -> Error {
    if detail.contains("AccessDenied")
        || detail.contains("UnauthorizedOperation")
        || detail.contains("not authorized")
    {
        Error::Forbidden(format!(
            "{what}: {detail}. Grant the read-only EKS permissions in docs/providers/eks.md to the AWS identity k8s-mcp uses."
        ))
    } else if detail.contains("ResourceNotFound") {
        Error::NotFound(format!(
            "{what}: {detail}. Check the cluster name and region, or pass --eks-cluster and --eks-region."
        ))
    } else if detail.to_ascii_lowercase().contains("credential") {
        Error::Forbidden(format!(
            "{what}: no AWS credentials resolved ({detail}). Provide them through the default chain: AWS_PROFILE or environment variables, an SSO login, IRSA or EKS Pod Identity."
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
}
