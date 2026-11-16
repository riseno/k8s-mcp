# Amazon EKS provider

The `eks` toolset (cargo feature `provider-eks`, on by default) adds AWS's view of an EKS
cluster to the Kubernetes one. Every tool is read-only.

| Tool | What it shows |
|---|---|
| `eks_cluster_info` | Version, platform version, status and health issues, endpoint access, authentication mode, OIDC issuer, control-plane log types, Auto Mode, support policy |
| `eks_nodegroups` | Managed node groups (version, instance and capacity type, desired/min/max, health issues) and Fargate profiles |
| `eks_addons` | Installed add-ons, their status and health, and the newest version compatible with the cluster's Kubernetes version |
| `eks_access` | Access entries with their access policies, and `aws-auth` role and user mappings, with cluster-admin flagged |

Rules: `eks.cluster.*`, `eks.nodegroup.*`, `eks.addon.*`, `eks.access.*` (see
[rules.md](../rules.md)).

## When the tools are available

With `--providers auto` (the default) the toolset is registered when the default context is
EKS with high confidence: an `*.eks.amazonaws.com` API server, the `aws eks get-token` or
`aws-iam-authenticator` exec plugin, a cluster-ARN or eksctl context name, or (in-cluster)
nodes with `eks.amazonaws.com/*` labels. `--providers eks` registers it regardless, and
`--providers none` never does.

The cluster name and region come from the same signals (`--cluster-name`, `--region`, the
ARN, the API host, node labels). When they cannot be found, for example in-cluster without
eksctl labels, pass `--eks-cluster <name>` and `--eks-region <region>`. The AWS profile the
kubeconfig's exec plugin uses (`--profile` or `AWS_PROFILE` in its env) is used for the AWS
calls too, so they reach the same account as the cluster credentials.

## Credentials

AWS calls use the default credential chain, never prompting: environment variables, the
shared config and credentials files (profiles, cached SSO logins), IRSA (web identity) and
EKS Pod Identity. Profiles that use `credential_process` are not supported, because k8s-mcp
runs no commands besides kubeconfig exec plugins. Without credentials the tools return an
error saying so. The HTTP client uses rustls with ring (ADR 0007).

In-cluster, give the chart's ServiceAccount an IAM role with IRSA
(`serviceAccount.annotations."eks\.amazonaws\.com/role-arn"`) or an EKS Pod Identity
association; see [in-cluster.md](../in-cluster.md).

## Permissions

A read-only policy for the identity k8s-mcp uses (PROPOSAL Appendix C). Scope `Resource` to
your clusters, roles and log groups in production.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": [
        "eks:DescribeCluster", "eks:ListNodegroups", "eks:DescribeNodegroup", "eks:ListFargateProfiles",
        "eks:DescribeFargateProfile", "eks:ListAddons", "eks:DescribeAddon", "eks:DescribeAddonVersions",
        "eks:ListAccessEntries", "eks:DescribeAccessEntry", "eks:ListAssociatedAccessPolicies",
        "eks:ListPodIdentityAssociations", "eks:DescribePodIdentityAssociation"
      ], "Resource": "*" },
    { "Effect": "Allow", "Action": [ "iam:GetRole", "iam:ListOpenIDConnectProviders", "iam:GetOpenIDConnectProvider" ], "Resource": "*" },
    { "Effect": "Allow", "Action": [ "logs:DescribeLogGroups", "logs:FilterLogEvents", "logs:StartQuery", "logs:GetQueryResults" ], "Resource": "*" },
    { "Effect": "Allow", "Action": [ "sts:GetCallerIdentity" ], "Resource": "*" }
  ]
}
```

The `iam:` and `logs:` actions are for `eks_identity_check` and `eks_logs` (next release
step). `eks_access` also reads the `aws-auth` ConfigMap through Kubernetes, when the namespace
policy allows kube-system.
