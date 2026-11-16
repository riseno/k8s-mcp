//! Cloud provider detection from Kubernetes-side signals only (PROPOSAL §10.2): node
//! providerIDs and labels, the API server host, the kubeconfig exec plugin and the context
//! name. Never calls a cloud API and never fails. Also extracts what identifies the cluster to
//! its cloud (name, region, account), which provider modules need for their API calls.
//!
//! A bare providerID (`aws://`, `gce://`, `azure://`) is weak evidence: self-managed clusters
//! on the same clouds have it too, so on its own it gives `Confidence::Low`.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::Node;
use serde::Serialize;

/// A managed Kubernetes offering with a provider module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderId {
    /// Amazon EKS.
    Eks,
    /// Google GKE.
    Gke,
    /// Azure AKS.
    Aks,
}

impl ProviderId {
    /// Lower-case name, as in `--providers`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eks => "eks",
            Self::Gke => "gke",
            Self::Aks => "aks",
        }
    }
}

/// How sure the detection is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// A signal only the managed offering has (API host, managed labels, its auth plugin).
    High,
    /// Only node providerIDs, which self-managed clusters on that cloud share.
    Low,
}

/// What identifies the cluster to its cloud, as far as the signals tell.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ClusterIdentity {
    /// Cluster name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Region or location.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// AWS account, GCP project or Azure subscription.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Azure resource group of the cluster.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_group: Option<String>,
    /// AWS profile the kubeconfig's exec plugin uses (`--profile` or `AWS_PROFILE`), so cloud
    /// calls use the same account as the cluster credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

/// The detected provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Detection {
    /// Which provider.
    pub provider: ProviderId,
    /// How sure.
    pub confidence: Confidence,
    /// What identifies the cluster.
    pub identity: ClusterIdentity,
    /// The signals that matched, for display.
    pub signals: Vec<String>,
}

impl Detection {
    /// `eks (cluster prod, us-east-1, account 123456789012)`.
    pub fn describe(&self) -> String {
        let id = &self.identity;
        let mut parts: Vec<String> = Vec::new();
        if let Some(n) = &id.name {
            parts.push(format!("cluster {n}"));
        }
        parts.extend(id.region.clone());
        if let Some(a) = &id.account {
            parts.push(format!("account {a}"));
        }
        if self.confidence == Confidence::Low {
            parts.push("low confidence".into());
        }
        if parts.is_empty() {
            self.provider.as_str().to_owned()
        } else {
            format!("{} ({})", self.provider.as_str(), parts.join(", "))
        }
    }
}

/// Everything detection looks at.
#[derive(Debug, Default)]
pub struct Signals<'a> {
    /// Kubeconfig context name.
    pub context: &'a str,
    /// API server host.
    pub server_host: &'a str,
    /// Exec plugin command (as written in the kubeconfig).
    pub exec_command: &'a str,
    /// Exec plugin arguments.
    pub exec_args: &'a [String],
    /// Exec plugin environment (`name`, `value`).
    pub exec_env: &'a [(String, String)],
    /// Nodes, when they were listed.
    pub nodes: &'a [Node],
}

/// Evidence for one provider while detecting.
#[derive(Default)]
struct Candidate {
    strong: Vec<String>,
    weak: Vec<String>,
    identity: ClusterIdentity,
}

impl Candidate {
    fn into_detection(self, provider: ProviderId) -> Option<Detection> {
        let confidence = if !self.strong.is_empty() {
            Confidence::High
        } else if !self.weak.is_empty() {
            Confidence::Low
        } else {
            return None;
        };
        Some(Detection {
            provider,
            confidence,
            identity: self.identity,
            signals: self.strong.into_iter().chain(self.weak).collect(),
        })
    }
}

fn set(slot: &mut Option<String>, value: Option<&str>) {
    if slot.is_none()
        && let Some(v) = value.filter(|v| !v.is_empty())
    {
        *slot = Some(v.to_owned());
    }
}

/// Value of `--flag value` or `--flag=value` in exec args.
fn arg<'a>(args: &'a [String], flags: &[&str]) -> Option<&'a str> {
    args.iter().enumerate().find_map(|(i, a)| {
        flags.iter().find_map(|f| {
            if a == f {
                args.get(i + 1).map(String::as_str)
            } else {
                a.strip_prefix(f).and_then(|r| r.strip_prefix('='))
            }
        })
    })
}

fn labels(n: &Node) -> Option<&BTreeMap<String, String>> {
    n.metadata.labels.as_ref()
}

fn provider_ids(nodes: &[Node]) -> impl Iterator<Item = &str> {
    nodes
        .iter()
        .filter_map(|n| n.spec.as_ref()?.provider_id.as_deref())
}

fn node_label<'a>(nodes: &'a [Node], key: &str) -> Option<&'a str> {
    nodes
        .iter()
        .find_map(|n| labels(n)?.get(key).map(String::as_str))
}

fn has_label_prefix(nodes: &[Node], prefix: &str) -> bool {
    nodes
        .iter()
        .any(|n| labels(n).is_some_and(|l| l.keys().any(|k| k.starts_with(prefix))))
}

fn eks(s: &Signals) -> Candidate {
    let mut c = Candidate::default();
    let exec = s
        .exec_command
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(s.exec_command);
    let host = s.server_host.split(':').next().unwrap_or("");
    if let Some(prefix) = host
        .strip_suffix(".eks.amazonaws.com")
        .or_else(|| host.strip_suffix(".eks.amazonaws.com.cn"))
    {
        c.strong.push(format!("API server {host}"));
        // <id>.<cell>.<region>.eks.amazonaws.com
        set(&mut c.identity.region, prefix.rsplit('.').next());
    }
    let env = |k: &str| {
        s.exec_env
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
    };
    let aws_exec = exec == "aws" && s.exec_args.iter().any(|a| a == "eks");
    if aws_exec {
        c.strong.push("kubeconfig exec `aws eks get-token`".into());
        set(
            &mut c.identity.name,
            arg(s.exec_args, &["--cluster-name", "--cluster-id"]),
        );
    } else if exec == "aws-iam-authenticator" {
        c.strong
            .push("kubeconfig exec aws-iam-authenticator".into());
        set(
            &mut c.identity.name,
            arg(s.exec_args, &["-i", "--cluster-id"]),
        );
    }
    if aws_exec || exec == "aws-iam-authenticator" {
        set(
            &mut c.identity.region,
            arg(s.exec_args, &["--region"]).or_else(|| env("AWS_REGION")),
        );
        set(
            &mut c.identity.profile,
            arg(s.exec_args, &["--profile"]).or_else(|| env("AWS_PROFILE")),
        );
    }
    // `aws eks update-kubeconfig` names the context after the cluster ARN.
    if let Some(rest) = s
        .context
        .strip_prefix("arn:aws:eks:")
        .or_else(|| s.context.strip_prefix("arn:aws-cn:eks:"))
    {
        let mut parts = rest.splitn(3, ':');
        let (region, account, resource) = (parts.next(), parts.next(), parts.next());
        if let Some(name) = resource.and_then(|r| r.strip_prefix("cluster/")) {
            c.strong.push("context is an EKS cluster ARN".into());
            set(&mut c.identity.name, Some(name));
            set(&mut c.identity.region, region);
            set(&mut c.identity.account, account);
        }
    }
    // eksctl: `<user>@<cluster>.<region>.eksctl.io`.
    if let Some(rest) = s.context.strip_suffix(".eksctl.io") {
        let cluster = rest.rsplit('@').next().unwrap_or(rest);
        if let Some((name, region)) = cluster.rsplit_once('.') {
            c.strong.push("eksctl context".into());
            set(&mut c.identity.name, Some(name));
            set(&mut c.identity.region, Some(region));
        }
    }
    if has_label_prefix(s.nodes, "eks.amazonaws.com/") {
        c.strong.push("node labels eks.amazonaws.com/*".into());
    }
    set(
        &mut c.identity.name,
        node_label(s.nodes, "alpha.eksctl.io/cluster-name"),
    );
    if provider_ids(s.nodes).any(|id| id.starts_with("aws://")) {
        c.weak.push("node providerID aws://".into());
        set(
            &mut c.identity.region,
            node_label(s.nodes, "topology.kubernetes.io/region"),
        );
    }
    c
}

fn gke(s: &Signals) -> Candidate {
    let mut c = Candidate::default();
    let exec = s
        .exec_command
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(s.exec_command);
    if exec == "gke-gcloud-auth-plugin" {
        c.strong
            .push("kubeconfig exec gke-gcloud-auth-plugin".into());
    }
    // `gcloud container clusters get-credentials`: gke_<project>_<location>_<name>.
    if let Some(rest) = s.context.strip_prefix("gke_") {
        let parts: Vec<&str> = rest.splitn(3, '_').collect();
        if let [project, location, name] = parts.as_slice() {
            c.strong.push("gke_ context name".into());
            set(&mut c.identity.account, Some(project));
            set(&mut c.identity.region, Some(location));
            set(&mut c.identity.name, Some(name));
        }
    }
    if has_label_prefix(s.nodes, "cloud.google.com/gke-") {
        c.strong.push("node labels cloud.google.com/gke-*".into());
    }
    // gce://<project>/<zone>/<instance>
    if let Some(project) =
        provider_ids(s.nodes).find_map(|id| id.strip_prefix("gce://")?.split('/').next())
    {
        c.weak.push("node providerID gce://".into());
        set(&mut c.identity.account, Some(project));
        set(
            &mut c.identity.region,
            node_label(s.nodes, "topology.kubernetes.io/region"),
        );
    }
    c
}

fn aks(s: &Signals) -> Candidate {
    let mut c = Candidate::default();
    let exec = s
        .exec_command
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(s.exec_command);
    let host = s.server_host.split(':').next().unwrap_or("");
    if let Some(prefix) = host.strip_suffix(".azmk8s.io") {
        c.strong.push(format!("API server {host}"));
        // <dns>-<hash>.hcp.<region>.azmk8s.io
        set(&mut c.identity.region, prefix.rsplit('.').next());
        // `az aks get-credentials` names the context after the cluster.
        set(&mut c.identity.name, Some(s.context));
    }
    if exec == "kubelogin" {
        c.strong.push("kubeconfig exec kubelogin".into());
    }
    if has_label_prefix(s.nodes, "kubernetes.azure.com/") {
        c.strong.push("node labels kubernetes.azure.com/*".into());
        set(
            &mut c.identity.region,
            node_label(s.nodes, "topology.kubernetes.io/region"),
        );
        // MC_<resource group>_<cluster>_<region>, the node resource group.
        if let (Some(mc), Some(name), Some(region)) = (
            node_label(s.nodes, "kubernetes.azure.com/cluster"),
            c.identity.name.clone(),
            c.identity.region.clone(),
        ) && let Some(rg) = mc
            .strip_prefix("MC_")
            .and_then(|r| r.strip_suffix(&format!("_{name}_{region}")))
        {
            set(&mut c.identity.resource_group, Some(rg));
        }
    }
    // azure:///subscriptions/<id>/resourceGroups/...
    if let Some(sub) = provider_ids(s.nodes).find_map(|id| {
        id.strip_prefix("azure:///subscriptions/")?
            .split('/')
            .next()
    }) {
        c.weak.push("node providerID azure://".into());
        set(&mut c.identity.account, Some(sub));
    }
    c
}

/// Detect the provider. Strong signals beat weak ones; between equals the first of EKS, GKE,
/// AKS wins (signals of two clouds at once do not occur on real clusters).
pub fn detect(s: &Signals) -> Option<Detection> {
    let mut found: Vec<Detection> = [
        (ProviderId::Eks, eks(s)),
        (ProviderId::Gke, gke(s)),
        (ProviderId::Aks, aks(s)),
    ]
    .into_iter()
    .filter_map(|(p, c)| c.into_detection(p))
    .collect();
    found.sort_by_key(|d| d.confidence != Confidence::High);
    found.into_iter().next()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use serde_json::json;

    use super::*;

    fn nodes(v: serde_json::Value) -> Vec<Node> {
        serde_json::from_value(v).unwrap()
    }

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_owned()).collect()
    }

    /// v0.2 acceptance criterion 3: EKS from node providerIDs and labels, exec args, the API
    /// host and the context ARN, with no cloud calls.
    #[test]
    fn eks_from_every_signal() {
        let eks_nodes = nodes(json!([{"metadata": {"name": "ip-10-0-1-5", "labels": {
            "eks.amazonaws.com/nodegroup": "general", "topology.kubernetes.io/region": "eu-west-1"}},
            "spec": {"providerID": "aws:///eu-west-1a/i-0abc"}}]));
        let d = detect(&Signals {
            nodes: &eks_nodes,
            ..Signals::default()
        })
        .unwrap();
        assert_eq!(
            (d.provider, d.confidence),
            (ProviderId::Eks, Confidence::High)
        );
        assert_eq!(d.identity.region.as_deref(), Some("eu-west-1"));

        let a = args(&[
            "--region",
            "us-east-1",
            "eks",
            "get-token",
            "--cluster-name",
            "prod",
            "--output",
            "json",
        ]);
        let d = detect(&Signals {
            exec_command: "/opt/homebrew/bin/aws",
            exec_args: &a,
            ..Signals::default()
        })
        .unwrap();
        assert_eq!(
            d.identity,
            ClusterIdentity {
                name: Some("prod".into()),
                region: Some("us-east-1".into()),
                ..ClusterIdentity::default()
            }
        );

        let d = detect(&Signals {
            context: "arn:aws:eks:us-east-2:123456789012:cluster/payments",
            server_host: "ABCDEF.gr7.us-east-2.eks.amazonaws.com",
            ..Signals::default()
        })
        .unwrap();
        assert_eq!(
            d.describe(),
            "eks (cluster payments, us-east-2, account 123456789012)"
        );

        let d = detect(&Signals {
            context: "ops@staging.ap-south-1.eksctl.io",
            ..Signals::default()
        })
        .unwrap();
        assert_eq!(d.describe(), "eks (cluster staging, ap-south-1)");

        let a = args(&["token", "-i", "legacy"]);
        let env = [
            ("AWS_PROFILE".to_owned(), "ops".to_owned()),
            ("AWS_REGION".to_owned(), "eu-north-1".to_owned()),
        ];
        let d = detect(&Signals {
            exec_command: "aws-iam-authenticator",
            exec_args: &a,
            exec_env: &env,
            ..Signals::default()
        })
        .unwrap();
        assert_eq!(
            d.identity,
            ClusterIdentity {
                name: Some("legacy".into()),
                region: Some("eu-north-1".into()),
                profile: Some("ops".into()),
                ..ClusterIdentity::default()
            }
        );
    }

    #[test]
    fn a_bare_ec2_provider_id_is_low_confidence() {
        let ec2 = nodes(
            json!([{"metadata": {"name": "n1"}, "spec": {"providerID": "aws:///us-west-2b/i-1"}}]),
        );
        let d = detect(&Signals {
            nodes: &ec2,
            ..Signals::default()
        })
        .unwrap();
        assert_eq!(
            (d.provider, d.confidence),
            (ProviderId::Eks, Confidence::Low)
        );
        assert_eq!(d.describe(), "eks (low confidence)");
    }

    #[test]
    fn gke_and_aks() {
        let d = detect(&Signals {
            context: "gke_acme-prod_europe-west1_shop",
            exec_command: "gke-gcloud-auth-plugin",
            ..Signals::default()
        })
        .unwrap();
        assert_eq!(
            d.describe(),
            "gke (cluster shop, europe-west1, account acme-prod)"
        );

        let aks_nodes = nodes(json!([{"metadata": {"name": "aks-sys-1", "labels": {
            "kubernetes.azure.com/agentpool": "sys", "kubernetes.azure.com/cluster": "MC_rg_web_shop_westeurope",
            "topology.kubernetes.io/region": "westeurope"}},
            "spec": {"providerID": "azure:///subscriptions/0000-1111/resourceGroups/mc_rg_web_shop_westeurope/providers/Microsoft.Compute/virtualMachineScaleSets/aks-sys/virtualMachines/0"}}]));
        let d = detect(&Signals {
            context: "shop",
            server_host: "shop-dns-1a2b.hcp.westeurope.azmk8s.io:443",
            nodes: &aks_nodes,
            ..Signals::default()
        })
        .unwrap();
        assert_eq!(d.provider, ProviderId::Aks);
        assert_eq!(
            d.identity,
            ClusterIdentity {
                name: Some("shop".into()),
                region: Some("westeurope".into()),
                account: Some("0000-1111".into()),
                resource_group: Some("rg_web".into()),
                profile: None,
            }
        );
    }

    #[test]
    fn kind_and_bare_clusters_are_not_providers() {
        let kind = nodes(
            json!([{"metadata": {"name": "kind-control-plane"}, "spec": {"providerID": "kind://docker/kind/kind-control-plane"}}]),
        );
        assert!(
            detect(&Signals {
                context: "kind-dev",
                server_host: "127.0.0.1:6443",
                nodes: &kind,
                ..Signals::default()
            })
            .is_none()
        );
        assert!(detect(&Signals::default()).is_none());
    }

    #[test]
    fn strong_signals_beat_weak_ones() {
        let ec2 = nodes(
            json!([{"metadata": {"name": "n1"}, "spec": {"providerID": "aws:///us-west-2b/i-1"}}]),
        );
        let d = detect(&Signals {
            exec_command: "kubelogin",
            nodes: &ec2,
            ..Signals::default()
        })
        .unwrap();
        assert_eq!(d.provider, ProviderId::Aks);
    }
}
