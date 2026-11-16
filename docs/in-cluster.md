# In-cluster endpoint (Helm)

Run one shared, read-only, audited MCP endpoint inside a cluster, instead of a local binary
per user. It works on any conformant cluster (EKS, GKE, AKS, k3s, kind, on-prem); the chart
has no cloud-specific templates beyond optional identity annotations.

## Install

```bash
helm install k8s-mcp oci://ghcr.io/riseno/charts/k8s-mcp -n k8s-mcp --create-namespace
```

The chart creates:
- a Deployment (1 replica, stateless) and a `ClusterIP` Service on port 8080, path `/mcp`;
- a ServiceAccount bound to a read-only ClusterRole (no Secrets; `templates/rbac.yaml`);
- a binding to `system:auth-delegator`, so the server can validate callers' tokens.

**Secret values in logs.** Without access to Secrets the server cannot mask the values of the
Secrets a pod uses in that pod's logs: a pod that prints such a value returns it in clear, with
only pattern redaction (tokens, keys, passwords) applied. Responses say so in the summary
(`Secret values could not be masked ...`). `rbac.secretsMetadata: true` adds `get` on Secrets
so the values can be masked; the server still never returns them, but its ServiceAccount can
then read every Secret.

The pod runs as non-root (UID 65532) with a read-only root filesystem, all capabilities
dropped and the `RuntimeDefault` seccomp profile. `/healthz` is the liveness probe, and
`/readyz` (the API server answers within 3 s) is the readiness probe.

## Connect a client

Callers authenticate with a bearer token. By default (`auth.mode: tokenreview`) that is any
token the cluster accepts: a ServiceAccount token or an OIDC token. The server checks it
with the TokenReview API, but **acts with its own ServiceAccount**: the caller's RBAC does
not apply, so anyone the cluster authenticates gets the server's read-only view. Restrict who
can reach the Service (NetworkPolicy, ingress auth) if that is too broad.

```bash
kubectl -n k8s-mcp port-forward svc/k8s-mcp 8080:8080
TOKEN=$(kubectl -n <namespace> create token <serviceaccount>)
claude mcp add --transport http k8s http://localhost:8080/mcp --header "Authorization: Bearer $TOKEN"
```

Behind an ingress, add its hostname to `allowedHosts` (the server rejects unknown `Host`
values to block DNS rebinding) and terminate TLS at the ingress or a service mesh.

With `auth.mode: static`, callers share one token stored in a Secret:

```bash
kubectl -n k8s-mcp create secret generic k8s-mcp-token --from-literal=token="$(openssl rand -hex 32)"
helm install k8s-mcp oci://ghcr.io/riseno/charts/k8s-mcp -n k8s-mcp \
  --set auth.mode=static --set auth.existingSecret=k8s-mcp-token
```

## Audit

Every tool call is written as one JSON line to the pod's stderr, including the authenticated
`caller` (the TokenReview username, or `static-token`), so the cluster's log pipeline
collects it. Tokens are never logged.

## Cloud identity

Provider tools (v0.2: EKS) use the pod's cloud identity. Set it with chart values:

| Cloud | Mechanism | Values |
|---|---|---|
| EKS | IRSA | `serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::<account>:role/<role>` |
| EKS | Pod Identity | none: create the association for the ServiceAccount outside the chart |
| GKE | Workload Identity | `serviceAccount.annotations."iam\.gke\.io/gcp-service-account"=<gsa>@<project>.iam.gserviceaccount.com`, or bind the Kubernetes ServiceAccount principal directly (Workload Identity Federation) |
| AKS | Azure Workload Identity | `serviceAccount.annotations."azure\.workload\.identity/client-id"=<client-id>` and `podLabels."azure\.workload\.identity/use"="true"` |

## NetworkPolicy

`networkPolicy.enabled: true` allows ingress to port 8080 (from `networkPolicy.ingressFrom`,
or anywhere when empty) and egress only to DNS, the API server and `networkPolicy.extraEgress`.
Set `networkPolicy.apiServerCIDRs` to the API server's endpoint IPs, which most CNIs see after
the `kubernetes` Service is translated (`kubectl get endpointslices -n default -l
kubernetes.io/service-name=kubernetes`). Provider tools also need egress to the cloud APIs.

## Values

| Value | Default | Purpose |
|---|---|---|
| `image.repository`, `image.tag`, `image.pullPolicy` | `ghcr.io/riseno/k8s-mcp`, `v` + the chart `appVersion` (the release tag), `IfNotPresent` | Image |
| `replicaCount` | `1` | Replicas (clients on protocol `2025-11-25` keep a session: use session affinity with more than one) |
| `auth.mode` | `tokenreview` | `tokenreview` or `static` |
| `auth.existingSecret` | `""` | Secret with key `token`, for `static` |
| `allowedHosts` | `[]` | Extra `Host` values (ingress hostnames); the Service names, `localhost` and `127.0.0.1` are always accepted |
| `allowedOrigins` | `[]` | Browser `Origin` values accepted; any other `Origin` gets 403 |
| `redact` | `standard` | `strict`, `standard` or `off` |
| `logLevel` | `info` | stderr log level |
| `extraArgs` | `[]` | Extra flags, e.g. `--namespaces=shop,payments` |
| `clusterDomain` | `cluster.local` | For the accepted Service DNS names |
| `serviceAccount.create`, `.name`, `.annotations`, `.labels` | `true`, release name, `{}`, `{}` | ServiceAccount and cloud identity |
| `rbac.create` | `true` | Read-only ClusterRole and bindings |
| `rbac.secretsMetadata` | `false` | Adds `get` on Secrets, for existence checks and masking Secret values in logs. Without it, logs may contain the values of Secrets a pod uses (see Install). Values are never returned, but the grant allows reading them |
| `rbac.extraRules` | `[]` | Extra ClusterRole rules |
| `service.type`, `service.port` | `ClusterIP`, `8080` | Service |
| `podLabels`, `podAnnotations` | `{}` | Pod metadata |
| `resources` | 50m / 64Mi requests, 256Mi limit | Container resources |
| `networkPolicy.*` | disabled | See above |
| `podDisruptionBudget.enabled`, `.maxUnavailable` | `false`, `1` | PDB |
| `nodeSelector`, `tolerations`, `affinity` | empty | Scheduling |

`values.schema.json` validates every value, so a typo fails at install time.
