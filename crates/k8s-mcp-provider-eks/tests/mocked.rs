//! EKS reports against mocked AWS responses (v0.2 acceptance criterion 4): golden snapshots
//! of each tool's rendering. No network: `aws-smithy-mocks` answers every call.
#![allow(clippy::unwrap_used)]

use aws_sdk_eks::Client;
use aws_sdk_eks::operation::describe_access_entry::DescribeAccessEntryOutput;
use aws_sdk_eks::operation::describe_addon::DescribeAddonOutput;
use aws_sdk_eks::operation::describe_addon_versions::DescribeAddonVersionsOutput;
use aws_sdk_eks::operation::describe_cluster::DescribeClusterOutput;
use aws_sdk_eks::operation::describe_nodegroup::DescribeNodegroupOutput;
use aws_sdk_eks::operation::list_access_entries::ListAccessEntriesOutput;
use aws_sdk_eks::operation::list_addons::ListAddonsOutput;
use aws_sdk_eks::operation::list_associated_access_policies::ListAssociatedAccessPoliciesOutput;
use aws_sdk_eks::operation::list_fargate_profiles::ListFargateProfilesOutput;
use aws_sdk_eks::operation::list_nodegroups::ListNodegroupsOutput;
use aws_sdk_eks::types::{
    AccessConfigResponse, AccessEntry, AccessScope, AccessScopeType, Addon, AddonHealth, AddonInfo,
    AddonIssue, AddonIssueCode, AddonStatus, AddonVersionInfo, AssociatedAccessPolicy,
    AuthenticationMode, Cluster, ClusterHealth, ClusterIssue, ClusterIssueCode, ClusterStatus,
    Compatibility, Identity, Issue, LogSetup, LogType, Logging, Nodegroup, NodegroupHealth,
    NodegroupIssueCode, NodegroupScalingConfig, NodegroupStatus, Oidc, VpcConfigResponse,
};
use aws_smithy_mocks::{RuleMode, mock, mock_client};
use k8s_mcp_provider::{
    Provider, access_envelope, addons_envelope, cluster_info_envelope, node_pools_envelope,
};
use k8s_mcp_provider_eks::Eks;
use k8s_openapi::api::core::v1::ConfigMap;
use serde_json::json;

fn cluster() -> Cluster {
    Cluster::builder()
        .name("shop")
        .version("1.33")
        .status(ClusterStatus::Active)
        .platform_version("eks.9")
        .endpoint("https://ABCDEF.gr7.eu-west-1.eks.amazonaws.com")
        .resources_vpc_config(
            VpcConfigResponse::builder()
                .vpc_id("vpc-0a1b")
                .endpoint_public_access(true)
                .endpoint_private_access(true)
                .public_access_cidrs("0.0.0.0/0")
                .build(),
        )
        .access_config(
            AccessConfigResponse::builder()
                .authentication_mode(AuthenticationMode::ApiAndConfigMap)
                .build(),
        )
        .identity(
            Identity::builder()
                .oidc(
                    Oidc::builder()
                        .issuer("https://oidc.eks.eu-west-1.amazonaws.com/id/ABCDEF")
                        .build(),
                )
                .build(),
        )
        .logging(
            Logging::builder()
                .cluster_logging(
                    LogSetup::builder()
                        .types(LogType::Api)
                        .enabled(true)
                        .build(),
                )
                .cluster_logging(
                    LogSetup::builder()
                        .types(LogType::Audit)
                        .enabled(false)
                        .build(),
                )
                .build(),
        )
        .health(
            ClusterHealth::builder()
                .issues(
                    ClusterIssue::builder()
                        .code(ClusterIssueCode::Ec2SubnetNotFound)
                        .message("One or more subnets are no longer available: subnet-0dead")
                        .build(),
                )
                .build(),
        )
        .build()
}

fn client() -> Client {
    let describe_cluster = mock!(Client::describe_cluster)
        .then_output(|| DescribeClusterOutput::builder().cluster(cluster()).build());
    let list_nodegroups = mock!(Client::list_nodegroups).then_output(|| {
        ListNodegroupsOutput::builder()
            .nodegroups("general")
            .nodegroups("legacy")
            .build()
    });
    let describe_nodegroup = mock!(Client::describe_nodegroup).then_output(|| {
        DescribeNodegroupOutput::builder()
            .nodegroup(
                Nodegroup::builder()
                    .nodegroup_name("general")
                    .status(NodegroupStatus::Active)
                    .version("1.33")
                    .instance_types("m7g.large")
                    .capacity_type(aws_sdk_eks::types::CapacityTypes::OnDemand)
                    .scaling_config(
                        NodegroupScalingConfig::builder()
                            .min_size(2)
                            .max_size(6)
                            .desired_size(3)
                            .build(),
                    )
                    .build(),
            )
            .build()
    });
    let describe_legacy = mock!(Client::describe_nodegroup)
        .match_requests(|r| r.nodegroup_name() == Some("legacy"))
        .then_output(|| {
            DescribeNodegroupOutput::builder()
                .nodegroup(
                    Nodegroup::builder()
                        .nodegroup_name("legacy")
                        .status(NodegroupStatus::Degraded)
                        .version("1.31")
                        .instance_types("m5.large")
                        .capacity_type(aws_sdk_eks::types::CapacityTypes::Spot)
                        .scaling_config(NodegroupScalingConfig::builder().min_size(1).max_size(3).desired_size(1).build())
                        .health(
                            NodegroupHealth::builder()
                                .issues(
                                    Issue::builder()
                                        .code(NodegroupIssueCode::AsgInstanceLaunchFailures)
                                        .message("Could not launch Spot Instances. InsufficientInstanceCapacity")
                                        .build(),
                                )
                                .build(),
                        )
                        .build(),
                )
                .build()
        });
    let list_fargate = mock!(Client::list_fargate_profiles)
        .then_output(|| ListFargateProfilesOutput::builder().build());
    let list_addons = mock!(Client::list_addons).then_output(|| {
        ListAddonsOutput::builder()
            .addons("vpc-cni")
            .addons("coredns")
            .build()
    });
    let describe_cni = mock!(Client::describe_addon)
        .match_requests(|r| r.addon_name() == Some("vpc-cni"))
        .then_output(|| {
            DescribeAddonOutput::builder()
                .addon(
                    Addon::builder()
                        .addon_name("vpc-cni")
                        .addon_version("v1.16.0-eksbuild.1")
                        .status(AddonStatus::Degraded)
                        .health(
                            AddonHealth::builder()
                                .issues(
                                    AddonIssue::builder()
                                        .code(AddonIssueCode::InsufficientNumberOfReplicas)
                                        .message("The add-on is unhealthy because it doesn't have the desired number of replicas.")
                                        .build(),
                                )
                                .build(),
                        )
                        .build(),
                )
                .build()
        });
    let describe_coredns = mock!(Client::describe_addon)
        .match_requests(|r| r.addon_name() == Some("coredns"))
        .then_output(|| {
            DescribeAddonOutput::builder()
                .addon(
                    Addon::builder()
                        .addon_name("coredns")
                        .addon_version("v1.12.1-eksbuild.2")
                        .status(AddonStatus::Active)
                        .build(),
                )
                .build()
        });
    let versions = |name: &'static str, list: &'static [&'static str]| {
        mock!(Client::describe_addon_versions)
            .match_requests(move |r| r.addon_name() == Some(name))
            .then_output(move || {
                let mut info = AddonInfo::builder().addon_name(name);
                for v in list {
                    info = info.addon_versions(
                        AddonVersionInfo::builder()
                            .addon_version(*v)
                            .compatibilities(
                                Compatibility::builder().cluster_version("1.33").build(),
                            )
                            .build(),
                    );
                }
                DescribeAddonVersionsOutput::builder()
                    .addons(info.build())
                    .build()
            })
    };
    let cni_versions = versions("vpc-cni", &["v1.20.4-eksbuild.1", "v1.19.6-eksbuild.1"]);
    let coredns_versions = versions("coredns", &["v1.12.1-eksbuild.2"]);
    let list_entries = mock!(Client::list_access_entries).then_output(|| {
        ListAccessEntriesOutput::builder()
            .access_entries("arn:aws:iam::123456789012:role/platform-admin")
            .build()
    });
    let describe_entry = mock!(Client::describe_access_entry).then_output(|| {
        DescribeAccessEntryOutput::builder()
            .access_entry(
                AccessEntry::builder()
                    .principal_arn("arn:aws:iam::123456789012:role/platform-admin")
                    .username(
                        "arn:aws:sts::123456789012:assumed-role/platform-admin/{{SessionName}}",
                    )
                    .r#type("STANDARD")
                    .build(),
            )
            .build()
    });
    let policies = mock!(Client::list_associated_access_policies).then_output(|| {
        ListAssociatedAccessPoliciesOutput::builder()
            .associated_access_policies(
                AssociatedAccessPolicy::builder()
                    .policy_arn(
                        "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy",
                    )
                    .access_scope(
                        AccessScope::builder()
                            .r#type(AccessScopeType::Cluster)
                            .build(),
                    )
                    .build(),
            )
            .build()
    });
    mock_client!(
        aws_sdk_eks,
        RuleMode::MatchAny,
        &[
            &describe_cluster,
            &list_nodegroups,
            &describe_legacy,
            &describe_nodegroup,
            &list_fargate,
            &list_addons,
            &describe_cni,
            &describe_coredns,
            &cni_versions,
            &coredns_versions,
            &list_entries,
            &describe_entry,
            &policies,
        ]
    )
}

fn eks() -> Eks {
    Eks::with_client(client(), "shop".into(), "eu-west-1".into())
}

#[tokio::test]
async fn eks_cluster_info() {
    let e = cluster_info_envelope(
        k8s_mcp_core::provider::ProviderId::Eks,
        eks().cluster_info().await.unwrap(),
    );
    insta::assert_snapshot!(e.render());
}

#[tokio::test]
async fn eks_nodegroups() {
    let e = node_pools_envelope(
        k8s_mcp_core::provider::ProviderId::Eks,
        eks().node_pools().await.unwrap(),
    );
    insta::assert_snapshot!(e.render());
}

#[tokio::test]
async fn eks_addons() {
    let e = addons_envelope(
        k8s_mcp_core::provider::ProviderId::Eks,
        eks().addons().await.unwrap(),
    );
    insta::assert_snapshot!(e.render());
}

#[tokio::test]
async fn eks_access() {
    let mut p = eks();
    p.aws_auth = Some(
        serde_json::from_value::<ConfigMap>(json!({"metadata": {"name": "aws-auth", "namespace": "kube-system"}, "data": {
            "mapRoles": "- rolearn: arn:aws:iam::123456789012:role/nodes\n  username: system:node:{{EC2PrivateDNSName}}\n  groups: [system:bootstrappers, system:nodes]\n- rolearn: arn:aws:iam::123456789012:role/break-glass\n  username: break-glass\n  groups: [system:masters]\n",
            "mapUsers": "- userarn: arn:aws:iam::123456789012:user/ops\n  username: ops\n  groups: [view\n"
        }}))
        .unwrap(),
    );
    let e = access_envelope(
        k8s_mcp_core::provider::ProviderId::Eks,
        p.access().await.unwrap(),
    );
    insta::assert_snapshot!(e.render());
}
