# Google Kubernetes Engine provider

The `gke` toolset (cargo feature `provider-gke`, on by default) adds Google Cloud's view of a
GKE cluster to the Kubernetes one. Every tool is read-only, and the tools match the EKS ones
(same inputs, same output shape).

| Tool | What it shows |
|---|---|
| `gke_cluster_info` | Version, status and conditions, Autopilot or Standard, release channel, endpoint access (public endpoint, authorized networks, private nodes), Workload Identity pool, logging and monitoring, maintenance window |
| `gke_node_pools` | Node pools: version, machine type, spot, autoscaling, workload metadata mode, status and conditions (for example `GCE_STOCKOUT`) |
| `gke_addons` | GKE-managed add-ons and whether each is enabled (GKE does not expose their versions) |
| `gke_access` | Google principals in the cluster's RBAC: bindings of Google users, service accounts and groups (cluster-admin flagged), whether Google Groups for RBAC is on so group bindings apply (`gke.access.google_groups_off`), and legacy ABAC (`gke.access.legacy_abac`). IAM roles on the project (`roles/container.*`) grant access too and are not listed |
| `gke_identity_check` | A ServiceAccount's Workload Identity: annotation, workload pool, node pools in `GKE_METADATA` mode, the Google service account and its `roles/iam.workloadIdentityUser` binding |
| `gke_logs` | Cloud Logging: control-plane logs (api, audit, controllerManager, scheduler) or container logs of a namespace or pod, redacted and untrusted |

`upgrade_readiness` adds the versions the cluster's release channel offers and the channel's
upgrade target when the `gke` toolset is registered. Rules: `gke.cluster.*`, `gke.nodepool.*`
and `gke.wi.*` (see [rules.md](../rules.md)).

## Identity checks

`gke_identity_check` always runs the Kubernetes side: the `iam.gke.io/gcp-service-account`
annotation. The Google Cloud side then checks that the cluster has a workload pool
(`<project>.svc.id.goog`), that no node pool runs in `GCE_METADATA` mode (pods there get the
node's service account; Autopilot always runs the GKE metadata server), that the Google service
account exists and is enabled, and that its IAM policy grants `roles/iam.workloadIdentityUser`
to `serviceAccount:<project>.svc.id.goog[<namespace>/<ksa>]`. A ServiceAccount without the
annotation is reported as `not configured`; IAM grants made directly to the Kubernetes
ServiceAccount's principal (Workload Identity Federation without a Google service account) are
not checked. Without credentials the result says `cloud checks skipped: <why>`.

## Logs

`gke_logs` reads Cloud Logging entries of this cluster (project, location and cluster name in
the filter), newest first and returned oldest first. `source=application` (container logs)
takes `namespace` and `pod`; `source=control-plane` takes `component` (`api`, `scheduler`,
`controllerManager`, which need control-plane logging enabled on the cluster, or `audit` for
Cloud Audit Logs). `grep` adds a free-text search term. Control-plane logs are refused while
`--namespaces` or `--deny-namespaces` restrict namespaces.

## When the tools are available

With `--providers auto` (the default) the `gke` toolset is registered when the default context
is detected as GKE with high confidence (the `gke-gcloud-auth-plugin` exec plugin, a
`gke_<project>_<location>_<name>` context name, or GKE node labels). `--providers gke` forces
it. The project, location and cluster name come from the context name; when they cannot be
detected (in-cluster, renamed contexts), pass `--gke-cluster <project>/<location>/<name>`,
which also registers the toolset.

## Credentials

Google Cloud calls use Application Default Credentials, never prompting:
`GOOGLE_APPLICATION_CREDENTIALS`, the file `gcloud auth application-default login` writes,
and, in a cluster (or with `GCE_METADATA_HOST`), the metadata server, which serves GKE Workload
Identity. Off Google Cloud without a credentials file, the tools say so at once instead of
probing the metadata server. Executable-sourced credentials
(`GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1`) are refused, because k8s-mcp runs no commands
besides kubeconfig exec plugins. The HTTP client uses rustls with ring (ADR 0012).

In-cluster, bind the chart's ServiceAccount to a Google service account with Workload Identity
(`serviceAccount.annotations."iam\.gke\.io/gcp-service-account"`); see
[in-cluster.md](../in-cluster.md).

## Permissions

Grant the identity k8s-mcp uses, on the cluster's project:
- `roles/container.clusterViewer` (cluster, node pools, server config);
- `roles/logging.viewer` (`gke_logs`; `roles/logging.privateLogViewer` for Data Access audit
  logs);
- for `gke_identity_check`, `iam.serviceAccounts.get` and `iam.serviceAccounts.getIamPolicy`
  on the Google service accounts to check (for example `roles/iam.serviceAccountViewer`, or a
  custom role with those two permissions).
