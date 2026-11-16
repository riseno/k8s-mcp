# Azure Kubernetes Service provider

The `aks` toolset (cargo feature `provider-aks`, on by default) adds Azure's view of an AKS
cluster to the Kubernetes one. Every tool is read-only, and the tools match the EKS and GKE
ones (same inputs, same output shape).

| Tool | What it shows |
|---|---|
| `aks_cluster_info` | Version, provisioning and power state, SKU tier, network plugin, API server access (private, authorized IP ranges), OIDC issuer and workload identity, Entra ID integration and Azure RBAC, local accounts, support plan, auto-upgrade channel |
| `aks_node_pools` | Node pools: mode, VM size, spot, version, count and autoscaler range, provisioning and power state, node image |
| `aks_addons` | Add-on profiles (enabled or not) and cluster extensions with their versions and state |
| `aks_identity_check` | A ServiceAccount's workload identity: client-id annotation, the pods' label and injected environment, OIDC issuer, workload identity, the managed identity and its federated credentials |
| `aks_logs` | Log Analytics: container logs (`ContainerLogV2`) or control-plane logs (`AKSControlPlane`, `AKSAudit`), redacted and untrusted |

`upgrade_readiness` adds the versions the cluster's upgrade profile offers (previews left out)
and the support plan when the `aks` toolset is registered. Rules: `aks.cluster.*`,
`aks.nodepool.*` and `aks.wi.*` (see [rules.md](../rules.md)).

## Identity checks

`aks_identity_check` always runs the Kubernetes side: the `azure.workload.identity/client-id`
annotation, the `azure.workload.identity/use: "true"` label on the ServiceAccount's pods, and
the `AZURE_FEDERATED_TOKEN_FILE` the webhook injects (pods created before the label or the
annotation need a restart). The Azure side checks that the cluster's OIDC issuer and workload
identity are enabled, finds the user-assigned managed identity with that client id in the
cluster's subscription, and checks that one of its federated credentials names this cluster's
issuer, the subject `system:serviceaccount:<namespace>:<name>` and the audience
`api://AzureADTokenExchange`. A client id that belongs to an Entra application registration (or
an identity in another subscription) is reported as not found, with low confidence. Without
credentials the result says `cloud checks skipped: <why>`.

## Logs

`aks_logs` queries the Log Analytics workspace of the cluster's monitoring add-on (Container
insights), filtered to this cluster. `source=application` reads `ContainerLogV2` and takes
`namespace` and `pod`; `source=control-plane` reads `AKSControlPlane` (`api`,
`controllerManager`, `scheduler`) or `AKSAudit` (`audit`), which need the cluster's diagnostic
settings to send those categories to the same workspace as resource-specific tables. `grep`
adds a `has` term. Control-plane logs are refused while `--namespaces` or `--deny-namespaces`
restrict namespaces.

## When the tools are available

With `--providers auto` (the default) the `aks` toolset is registered when the default context
is detected as AKS with high confidence (an `*.azmk8s.io` API server, the `kubelogin` exec
plugin, or AKS node labels). `--providers aks` forces it. The subscription and resource group
come from the nodes (providerIDs and the node resource group label); when they cannot be
detected, pass `--aks-cluster <subscription>/<resourceGroup>/<name>`, which also registers the
toolset.

## Credentials

k8s-mcp picks the Azure credential from the environment, without probing:
- workload identity, when `AZURE_FEDERATED_TOKEN_FILE` is set (with `AZURE_CLIENT_ID` and
  `AZURE_TENANT_ID`, as the AKS webhook injects them);
- a service principal, from `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET`;
- managed identity, where `IDENTITY_ENDPOINT` is set.

The Azure CLI login (`az login`) is not used: reading it means running `az`, and k8s-mcp runs
no commands besides kubeconfig exec plugins. On a laptop, use a service principal's variables.
Without credentials the tools say so at once. The HTTP client uses rustls with ring (ADR 0013).

In-cluster, give the chart's ServiceAccount a workload identity
(`serviceAccount.annotations."azure\.workload\.identity/client-id"` and
`podLabels."azure\.workload\.identity/use"="true"`); see [in-cluster.md](../in-cluster.md).

## Permissions

Grant the identity k8s-mcp uses:
- `Reader` on the AKS cluster (cluster, node pools, upgrade profile, extensions);
- `Reader` on the user-assigned managed identities to check (or the subscription), for the
  identity list and their federated credentials;
- `Log Analytics Reader` on the monitoring workspace (`aks_logs`).

Never the `Azure Kubernetes Service Cluster User` or `Admin` roles: k8s-mcp uses your existing
kubeconfig for Kubernetes access.
