//! Provider hints (PROPOSAL §8.4, last row): when the cluster's cloud is known, findings whose
//! cause is often cloud-specific get a concrete hint for that cloud appended to their fix. No
//! cloud calls and no new findings: only the rule id and the finding's own evidence decide.

use k8s_mcp_core::finding::Finding;
use k8s_mcp_core::provider::ProviderId;

/// Whether the finding's title or evidence mentions any of `needles` (case-insensitive).
fn mentions(f: &Finding, needles: &[&str]) -> bool {
    let hay = std::iter::once(f.title.as_str())
        .chain(f.evidence.iter().map(|e| e.text.as_str()))
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join("\n");
    needles.iter().any(|n| hay.contains(n))
}

/// The hint for one finding on one cloud, if any.
fn hint(p: ProviderId, f: &Finding) -> Option<&'static str> {
    use ProviderId::{Aks, Eks, Gke};
    let ip_exhausted = || {
        mentions(
            f,
            &[
                "failed to assign an ip",
                "no available addresses",
                "failed to allocate address",
                "ipam",
            ],
        )
    };
    let quota = || mentions(f, &["quota"]);
    Some(match (p, f.id.as_str()) {
        (Eks, "pod.creating.cni") if ip_exhausted() => {
            "On EKS the VPC CNI is out of IPs on this node's subnet or ENIs: enable prefix delegation (`kubectl set env ds aws-node -n kube-system ENABLE_PREFIX_DELEGATION=true`), add subnets with custom networking, or use instance types with more ENIs."
        }
        (Aks, "pod.creating.cni") if ip_exhausted() => {
            "On AKS, Azure CNI (without Overlay) reserves pod IPs per node from the node subnet: move to Azure CNI Overlay, or give the node pool a larger subnet."
        }
        (Eks, "pod.image.auth") if mentions(f, &[".dkr.ecr."]) => {
            "On EKS the node role needs AmazonEC2ContainerRegistryReadOnly (ecr:GetAuthorizationToken, ecr:BatchGetImage); for a repository in another account, its repository policy must allow the node role."
        }
        (Gke, "pod.image.auth") if mentions(f, &["-docker.pkg.dev", "gcr.io"]) => {
            "On GKE grant roles/artifactregistry.reader on the repository to the node pool's service account (by default the Compute Engine default service account)."
        }
        (Aks, "pod.image.auth") if mentions(f, &[".azurecr.io"]) => {
            "On AKS attach the registry to the cluster (`az aks update --attach-acr <registry>`), which grants the kubelet identity AcrPull."
        }
        (Eks, "pod.image.rate_limited") => {
            "On EKS an ECR pull-through cache for Docker Hub avoids the anonymous pull limit."
        }
        (Gke, "pod.image.rate_limited") => {
            "On GKE an Artifact Registry remote repository for Docker Hub avoids the anonymous pull limit."
        }
        (Aks, "pod.image.rate_limited") => {
            "On AKS an ACR cache rule for Docker Hub avoids the anonymous pull limit."
        }
        (Eks, "pvc.attach.limit") => {
            "On EKS, Nitro instances share their attachment slots (about 28 on most types) between EBS volumes and network interfaces: spread the pods with topologySpreadConstraints or use larger instance types."
        }
        (Aks, "pvc.attach.limit") => {
            "On AKS the number of data disks per node depends on the VM size (maxDataDiskCount): use a larger VM size for this node pool, or spread the pods."
        }
        (Gke, "pvc.attach.limit") => {
            "On GKE the number of Persistent Disks per node depends on the machine type: use a larger machine type for this node pool, or spread the pods."
        }
        (Eks, "autoscaling.karpenter.nodeclaim_not_launched") => {
            "On EKS check the NodePool's EC2NodeClass (subnetSelectorTerms, securityGroupSelectorTerms, the node role's instance profile) with `kubectl describe ec2nodeclass`, and EC2 capacity or quota for its instance types."
        }
        (Gke, "autoscaling.ca.not_triggered") if quota() => {
            "On GKE the project's Compute Engine quota (CPUS, IN_USE_ADDRESSES, the machine family) in this region blocks new nodes: request more quota."
        }
        (Aks, "autoscaling.ca.not_triggered") if quota() => {
            "On AKS the subscription's regional vCPU quota for this VM family blocks new nodes: request a quota increase or use another VM size."
        }
        (Eks, "autoscaling.ca.not_triggered") if quota() => {
            "On EKS the account's EC2 vCPU quota (Running On-Demand or Spot instances) blocks new nodes: request a Service Quotas increase."
        }
        _ => return None,
    })
}

/// Append the provider's hints to the findings it applies to.
pub fn apply(provider: ProviderId, findings: &mut [Finding]) {
    for f in findings {
        if let Some(h) = hint(provider, f) {
            if !f.fix.is_empty() {
                f.fix.push(' ');
            }
            f.fix.push_str(h);
        }
    }
}

#[cfg(test)]
mod tests {
    use k8s_mcp_core::finding::{Confidence, Severity, Source};

    use super::*;

    fn finding(id: &str, evidence: &str) -> Finding {
        Finding::new(id, Severity::High, Confidence::High, "t")
            .evidence(Source::Event, evidence)
            .fix("Generic fix.")
    }

    #[test]
    fn hints_follow_the_cloud_and_the_evidence() {
        let mut f = vec![
            finding(
                "pod.creating.cni",
                "plugin type=\"aws-cni\" failed (add): add cmd: failed to assign an IP address to container",
            ),
            finding(
                "pod.image.auth",
                "Failed to pull image \"123456789012.dkr.ecr.eu-west-1.amazonaws.com/api:1\": 403 Forbidden",
            ),
            finding(
                "pod.image.auth",
                "Failed to pull image \"ghcr.io/acme/api:1\": 401 Unauthorized",
            ),
            finding("pod.oom.container", "OOMKilled"),
        ];
        apply(ProviderId::Eks, &mut f);
        assert!(
            f[0].fix
                .starts_with("Generic fix. On EKS the VPC CNI is out of IPs"),
            "{}",
            f[0].fix
        );
        assert!(f[1].fix.contains("AmazonEC2ContainerRegistryReadOnly"));
        assert_eq!(f[2].fix, "Generic fix.", "not an ECR image");
        assert_eq!(f[3].fix, "Generic fix.", "no hint for this rule");
    }

    #[test]
    fn each_cloud_gets_its_own_hint() {
        let acr = || {
            vec![finding(
                "pod.image.auth",
                "Failed to pull image \"acme.azurecr.io/api:1\": unauthorized",
            )]
        };
        let mut aks = acr();
        apply(ProviderId::Aks, &mut aks);
        assert!(aks[0].fix.contains("--attach-acr"));
        let mut eks = acr();
        apply(ProviderId::Eks, &mut eks);
        assert_eq!(
            eks[0].fix, "Generic fix.",
            "an ACR image on EKS gets no AKS hint"
        );
        let mut gke = vec![finding(
            "autoscaling.ca.not_triggered",
            "pod didn't trigger scale-up: 1 Quota 'CPUS' exceeded",
        )];
        apply(ProviderId::Gke, &mut gke);
        assert!(gke[0].fix.contains("Compute Engine quota"));
        let mut gke = vec![finding(
            "autoscaling.ca.not_triggered",
            "pod didn't trigger scale-up: 1 max node group size reached",
        )];
        apply(ProviderId::Gke, &mut gke);
        assert_eq!(gke[0].fix, "Generic fix.");
    }
}
