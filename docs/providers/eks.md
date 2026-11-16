# Amazon EKS provider

The `eks` toolset (cargo feature `provider-eks`, on by default) adds AWS's view of an EKS
cluster to the Kubernetes one. Every tool is read-only.

| Tool | What it shows |
|---|---|
| `eks_cluster_info` | Version, platform version, status and health issues, endpoint access, authentication mode, OIDC issuer, control-plane log types, Auto Mode, support policy |
| `eks_nodegroups` | Managed node groups (version, instance and capacity type, desired/min/max, health issues) and Fargate profiles |
| `eks_addons` | Installed add-ons, their status and health, and the newest version compatible with the cluster's Kubernetes version |
| `eks_access` | Access entries with their access policies, and `aws-auth` role and user mappings, with cluster-admin flagged |
| `eks_identity_check` | A ServiceAccount's AWS identity: IRSA (annotation, role, trust policy, IAM OIDC provider) and Pod Identity (association, role trust, agent), and whether its pods got the credentials |
| `eks_logs` | CloudWatch control-plane logs (api, audit, authenticator, controllerManager, scheduler) or Container Insights application logs, redacted and untrusted |

Rules: `eks.cluster.*`, `eks.nodegroup.*`, `eks.addon.*`, `eks.access.*`, `eks.irsa.*`,
`eks.pod_identity.*` and `eks.identity.pods_not_injected` (see [rules.md](../rules.md)).

## Identity checks

`eks_identity_check` always runs the Kubernetes side: the `eks.amazonaws.com/role-arn`
annotation, whether the ServiceAccount's pods carry the injected credentials
(`AWS_WEB_IDENTITY_TOKEN_FILE` for IRSA, `AWS_CONTAINER_CREDENTIALS_FULL_URI` for Pod
Identity; pods created before the identity was set up need a restart), and the
`eks-pod-identity-agent` DaemonSet when kube-system may be read. The AWS side then checks that
the IRSA role exists and that its trust policy allows `sts:AssumeRoleWithWebIdentity` for this
cluster's OIDC provider with a `sub` condition matching `system:serviceaccount:<ns>:<sa>` (and
an `aud` allowing `sts.amazonaws.com` or the `eks.amazonaws.com/audience` annotation), that the
issuer is registered as an IAM OIDC provider, and that Pod Identity association roles trust
`pods.eks.amazonaws.com` with `sts:AssumeRole` and `sts:TagSession`. When AWS cannot be asked
(no credentials, access denied, cluster unknown) the result says `cloud checks skipped: <why>`
and still returns the Kubernetes side.

## Logs

`eks_logs` reads `/aws/eks/<cluster>/cluster` (`source: control-plane`, the default; enable the
log types first) or `/aws/containerinsights/<cluster>/application` (`source: application`,
needs Container Insights), with `grep`, `since` (default 1h, at most 24h) and `limit` (default
100, at most 500). Control-plane logs cover every namespace, so they are refused while
`--namespaces` or `--deny-namespaces` restrict namespaces; application logs then need an
allowed `namespace`.

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

The `iam:` actions are for `eks_identity_check` and the `logs:` actions for `eks_logs`.
`eks_access` also reads the `aws-auth` ConfigMap through Kubernetes, when the namespace policy
allows kube-system.
