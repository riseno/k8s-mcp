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
- a ServiceAccount bound to a read-only ClusterRole (`templates/rbac.yaml`), with `get` on
  Secrets so their values can be masked in logs (`rbac.secretsMetadata`);
- a binding to `system:auth-delegator`, so the server can validate callers' tokens;
- `get` on the API server's `/metrics`, for the deprecated-API metric `upgrade_readiness`
  reads. To also name who writes objects through a deprecated CRD version, add `list` on that
  custom resource to `rbac.extraRules` (`upgrade_readiness` names the exact rule).
- `get` on APIServices, so `top`, `cluster_overview` and `api_resources` can tell an
  aggregated API that is down (metrics-server crashed or without endpoints) from one that is
  not installed.

**Secret values in logs.** The ClusterRole includes `get` on Secrets (`rbac.secretsMetadata:
true`, the default) so the server can mask the values of the Secrets a pod uses in that pod's
logs. It never returns them, but its ServiceAccount can read every Secret. With
`rbac.secretsMetadata: false` it cannot mask them: a pod that prints such a value returns it in
clear, with only pattern redaction (tokens, keys, passwords) applied, and responses say so in
the summary (`Secret values could not be masked ...`).

The pod runs as non-root (UID 65532) with a read-only root filesystem, all capabilities
dropped and the `RuntimeDefault` seccomp profile. `/healthz` is the liveness probe, and
`/readyz` (the API server answers within 3 s) is the readiness probe.

## Connect a client

Callers authenticate with a bearer token. By default (`auth.mode: tokenreview`) that is a
ServiceAccount token minted for the audience `k8s-mcp` (`auth.audience`). The server checks
it with the TokenReview API, but **acts with its own ServiceAccount**: the caller's RBAC does
not apply, so every caller gets the server's read-only view (pod logs, events and object specs
cluster-wide).

```bash
kubectl -n k8s-mcp port-forward svc/k8s-mcp 8080:8080
TOKEN=$(kubectl -n <namespace> create token <serviceaccount> --audience k8s-mcp)
claude mcp add --transport http k8s http://localhost:8080/mcp --header "Authorization: Bearer $TOKEN"
```

Limit who that is:
- **Audience.** The audience requirement keeps the token every pod has by default (minted for
  the API server's audience) from working, so a compromised pod cannot reuse it. Setting
  `auth.audience: ""` accepts any token the cluster authenticates, including OIDC tokens and
  those default pod tokens.
- **Allowed callers.** `auth.allowedCallers` lists who may call, as globs over the TokenReview
  username or `group:<glob>` over its groups, for example
  `[system:serviceaccount:platform:*, group:sre]`. Others get 403, and the refusal is audited
  (`"result": "refused"`).
- **Network.** Restrict who can reach the Service (NetworkPolicy, ingress auth).

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
| `auth.audience` | `k8s-mcp` | Audience `tokenreview` tokens must be minted for (`--auth-audience`); `""` accepts any token the cluster authenticates |
| `auth.allowedCallers` | `[]` | `tokenreview` callers let in: username globs or `group:<glob>` (`--allowed-callers`); empty: all |
| `auth.existingSecret` | `""` | Secret with key `token`, for `static` |
| `allowedHosts` | `[]` | Extra `Host` values (ingress hostnames); the Service names, `localhost` and `127.0.0.1` are always accepted |
| `allowedOrigins` | `[]` | Browser `Origin` values accepted; any other `Origin` gets 403 |
| `redact` | `standard` | `strict`, `standard` or `off` |
| `logLevel` | `info` | stderr log level |
| `extraArgs` | `[]` | Extra flags, e.g. `--namespaces=shop,payments` |
| `clusterDomain` | `cluster.local` | For the accepted Service DNS names |
| `serviceAccount.create`, `.name`, `.annotations`, `.labels` | `true`, release name, `{}`, `{}` | ServiceAccount and cloud identity |
| `rbac.create` | `true` | Read-only ClusterRole and bindings |
| `rbac.secretsMetadata` | `true` | `get` on Secrets, for existence checks and masking Secret values in logs. Values are never returned, but the grant allows reading them. With `false`, logs may contain the values of Secrets a pod uses (see Install) |
| `rbac.extraRules` | `[]` | Extra ClusterRole rules |
| `service.type`, `service.port` | `ClusterIP`, `8080` | Service |
| `podLabels`, `podAnnotations` | `{}` | Pod metadata |
| `resources` | 50m / 64Mi requests, 256Mi limit | Container resources |
| `networkPolicy.*` | disabled | See above |
| `podDisruptionBudget.enabled`, `.maxUnavailable` | `false`, `1` | PDB |
| `nodeSelector`, `tolerations`, `affinity` | empty | Scheduling |

`values.schema.json` validates every value, so a typo fails at install time.
