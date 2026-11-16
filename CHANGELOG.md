# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses SemVer.

## [Unreleased]

### Fixed
- The Helm chart's default image is `v<appVersion>`, the tag images are published under; chart
  0.2.0 pointed at `ghcr.io/riseno/k8s-mcp:0.2.0`, which does not exist (#45). The release
  workflow now checks that the packaged chart's default image resolves before pushing the
  chart.
- `prompts/get` tells an unknown prompt (`unknown prompt "x"`) apart from a missing required
  argument (`prompt "explain-workload" needs argument "kind" (...)`); `investigate-incident`
  now requires its `symptom` as declared (#49).
- `eks_identity_check` reports an absent IRSA annotation or Pod Identity association as
  `not configured` instead of a failure, a missing OIDC provider or role as `fail`, and
  tallies the results in the summary (`2 checks (1 not configured, 1 skipped): no cloud
  identity that k8s-mcp can see`) instead of "1 failed ... no problems found" (#48).
- `autoscaling_status` summaries tell "not checked" from "absent": `Karpenter not checked
  (RBAC forbids reading it)`, `Cluster Autoscaler status not checked (kube-system is outside
  the namespace policy)` and `no Cluster Autoscaler status ConfigMap`, instead of
  `no Karpenter; no Cluster Autoscaler status` for all of them (#50).
- EKS tools without AWS credentials return one line with the guidance (`no AWS credentials
  found (tried ...), so k8s-mcp cannot describe the cluster ... Provide them through ...`)
  instead of 1.7 KB of AWS SDK debug output; other AWS errors drop the SDK debug dump too.
  The full SDK error is logged at `--log-level debug` (#47).
- A context that is not in the kubeconfig is reported as such (`context "docker-desktop" is
  not in the kubeconfig (<path>); allowed contexts: ...`); the `--contexts` advice is kept for
  contexts that exist but are not allowed (#51).
- `k8s-mcp://cluster/{context}/overview` percent-decodes the context, so names that RFC 6570
  expansion encodes (EKS context ARNs with `:` and `/`) resolve.

## [0.2.0] - 2026-11-16

### Added
- `eks_identity_check`: IRSA and EKS Pod Identity for a ServiceAccount, with rules
  `eks.irsa.role_missing`, `eks.irsa.trust_mismatch` (sub/aud conditions, StringLike
  wildcards), `eks.irsa.oidc_provider_missing`, `eks.pod_identity.association_missing`,
  `eks.pod_identity.trust_mismatch`, `eks.pod_identity.agent_missing` and
  `eks.identity.pods_not_injected`. Without AWS credentials it returns the Kubernetes side with
  `cloud checks skipped`.
- `eks_logs`: CloudWatch control-plane and Container Insights application logs, redacted and
  untrusted; control-plane logs are refused while the namespace policy restricts namespaces.
- Amazon EKS provider (cargo feature `provider-eks`, default): `eks_cluster_info`,
  `eks_nodegroups`, `eks_addons` and `eks_access`, with rules `eks.cluster.*` (health
  issues, public endpoint, audit logging off, aws-auth-only access), `eks.nodegroup.*`
  (health issues, version skew), `eks.addon.*` (degraded, incompatible with the cluster
  version) and `eks.access.aws_auth_invalid`. Registered with `--providers auto` (default)
  when the default context is EKS with high confidence, or `--providers eks`;
  `--eks-cluster`/`--eks-region` when detection cannot tell. AWS credentials come from the
  default chain (no `credential_process`); the HTTP client is rustls + ring (ADR 0007). See
  `docs/providers/eks.md`.
- `k8s-mcp-provider`: the provider trait and cloud-neutral report types (ADR 0006).
- Cloud provider detection with no cloud calls (ADR 0010): EKS, GKE and AKS from node
  providerIDs and labels, the API server host, the exec plugin and its arguments, and the
  context name, with the cluster's name, region and account. `cluster_overview` reports it
  (`Kubernetes v1.33.5 on eks (cluster shop, eu-west-1)`), as do `list_contexts` and `doctor`.
  A bare providerID is reported with low confidence.
- Streamable HTTP transport for in-cluster use: `--transport http` serves MCP at `/mcp`
  (stateless for protocol `2026-07-28`, sessions for older clients) with `/healthz` and
  `/readyz`, on `--listen` (default `127.0.0.1:8080`).
- HTTP auth: `--auth tokenreview` (default; Kubernetes tokens validated with the TokenReview
  API, cached 60 s), `--auth static --auth-token-file <path>`, or `--auth none` on loopback
  only. `Host` and `Origin` allow-lists (`--allowed-hosts`, `--allowed-origins`).
- Audit records carry the authenticated HTTP `caller`.
- Cargo feature `http` (default); `--no-default-features` builds a stdio-only binary.
- Helm chart `deploy/helm/k8s-mcp`, published to `oci://ghcr.io/riseno/charts/k8s-mcp` on
  release: Deployment and Service (`/mcp` on 8080), read-only ClusterRole without Secrets,
  `system:auth-delegator` binding for TokenReview, identity values for EKS, GKE and AKS,
  optional NetworkPolicy and PodDisruptionBudget, a hardened pod, and `values.schema.json`.
  CI lints it, validates the rendered manifests and installs it on kind and k3s with an HTTP
  smoke test. See `docs/in-cluster.md`.
- `diagnose_service`: why traffic does not reach a Service. Rules `svc.no_matching_pods`
  (with the exact label diff against the closest pods), `svc.target_port_mismatch` (named
  targetPorts are definitive; numeric ones are medium confidence), `svc.no_ready_endpoints`
  and `svc.lb_pending`. Returns the port mapping table and the matching pods.
- `diagnose_pvc`: why storage is stuck. Rules `pvc.pending.no_storageclass` (named class
  missing, or no default), `pvc.pending.provisioning_failed` (provisioner errors, or an
  external provisioner silent for 5 minutes), `pvc.pending.wffc_waiting` (info with no pod,
  medium when the pod is Pending), `pvc.attach.multi_attach` and `pvc.attach.limit`. Returns
  the claim, the pods using it and their events. `pod.pending.pvc_unbound` now suggests it.
- `diagnose_dns`: is DNS the problem? For a pod or a namespace, rules
  `dns.netpol_blocks_egress` (an egress NetworkPolicy with no rule that can reach port 53;
  judged conservatively), `dns.coredns_unhealthy` (missing or not-Ready CoreDNS, forwarding
  loops, upstream timeouts in its logs), `dns.no_endpoints` (kube-dns missing or routing to
  nothing), plus `dns.app_resolution_errors` and the `dns.ndots_hint` for external names.
  kube-system is read only when the namespace policy allows it.
- `autoscaling_status`: why the cluster is not scaling, for any cluster. Rules
  `autoscaling.karpenter.limit_reached` (NodePool `status.resources` at `spec.limits`),
  `autoscaling.karpenter.nodeclaim_not_launched` (launch failures, or nodes that never
  register), `autoscaling.ca.not_triggered` (`NotTriggerScaleUp` reasons, with the fix chosen
  from them), `autoscaling.ca.unhealthy` (the CA 1.30+ status ConfigMap: unhealthy groups,
  scale-up backoff), `autoscaling.hpa.not_scaling` and `autoscaling.hpa.at_max`. Rows for
  NodePools, CA node groups and HPAs.
- `rollout_history`: a Deployment's, StatefulSet's or DaemonSet's revisions (images, replicas,
  redacted change-cause) with a field diff of the newest two or `compare: [a, b]`.
- `recent_changes`: rollouts with diffs, objects created or updated (and by which field
  manager) and Helm release revisions in a window (`since`, default 2h). Diffs show env names,
  never values; object changes come from metadata-only lists, so Secret and ConfigMap bodies are
  never read.
- Prompts `explain-workload` and `access-review`; `investigate-incident` now checks
  `recent_changes` and `cluster-health-check` checks `autoscaling_status`.
- Resource template `k8s-mcp://cluster/{context}/overview` (cluster_overview through the tool
  path: context policy, cap, redaction and audit apply).
- The kind Secret-canary test covers every tool, the v0.2 ones included.
- `find_problems` scans Services and PVCs (`kinds: services, pvcs`, on by default; ADR 0008).
- Eval scenarios 15 (Service selector mismatch), 16 (targetPort mismatch) and 17 (DNS blocked
  by a NetworkPolicy) and 18 (the autoscaler cannot scale up).

## [0.1.4] - 2026-11-15

### Fixed
- Node conditions not known to affect pods (vendor or unknown problem types) say how many pods
  run on the node instead of claiming they are affected (#32).
- `diagnose_workload` summaries count available against desired replicas, e.g.
  `1/2 replicas available (1 pod(s) exist)`, instead of only the pods that exist (#32).
- Small `--max-output-bytes` caps cut findings to their headlines before dropping whole
  findings or table rows, so a 3,000-byte cap still returns the top finding (#32).

## [0.1.3] - 2026-11-15

### Security
- Cluster text in `structuredContent` (what Claude Code shows the model) is now neutralized and
  marked: `<<`/`>>` are defanged in every string, event/log evidence and event messages are
  wrapped in `<<untrusted …>>`, and log lines and objects live only in untrusted sections (#23).
- Multi-line PEM private keys in logs are masked entirely, not just their `BEGIN` line (#24).
- Logs are scrubbed of the exact values of the Secrets their pod references, at every redaction
  level (ADR 0009), and bare AWS secret access keys next to an access key id or the word
  "secret" are masked (#25).

### Fixed
- `structuredContent` now carries every section (get_resource YAML and events, node pools,
  unavailable-evidence notes); clients that read only it (Claude Code) got an empty YAML view.
  YAML sections are trimmed from the end, logs from the start (#9).
- `--max-output-bytes` is a hard cap on the message actually sent (#15).
- The audit log records the MCP client; `--help` gives the real default audit path per platform (#16).
- `list_resources` next-page calls keep selectors and the rest of the query (#11).
- `top` reports an unbounded pod limit when a container has none, instead of >100% usage (#10).
- `get_resource` workload summaries show pod-template containers (image, resources, probes, env) (#12).
- `find_problems` in a namespace reports only nodes running its pods, and its summary counts
  every severity (#13, #14).
- `list_events` groups one cause across objects and counts occurrences (#21, #14).
- `check_permissions` `verbs_for` uses `get` for `*/log` and `create` for `*/exec` and similar (#17).
- `get_logs` drops Python traceback caret lines and merges identical output across a workload's pods (#20).
- `api_resources` names every API group in its summary and shows the standard verb set as `all` (#22).
- Quick scans (`find_problems`, `cluster_overview`) no longer report liveness-killed containers
  as `pod.crashloop.exit_zero`; the eval also checks `find_problems` for forbidden ids (#26).
- Ambiguous kinds name the other API groups serving them; `plural.group` and `Kind.group` work (#27).
- `get_logs previous=true` falls back to the crashed current instance between restarts, and the
  rules suggest `previous` only when a previous instance exists (#28).
- Invalid inputs are rejected instead of clamped or ignored, namespace names are validated, and
  a namespace that does not exist is reported as such (#29).
- `get_resource` summaries include related objects: a Service's matching pods and endpoints, a
  workload's pods and revisions, a Pod's owner chain and node, a PVC's volume and StorageClass (#30).

### Added
- `pod.crashloop.dependency_unreachable`, and log-based `pod.crashloop.command_not_found`
  (`Failed to spawn`, `executable file not found`), for crash loops whose logs name the cause (#19).

### Changed
- ADR 0008: `find_problems` covers Services and PVCs from v0.2 (#18).

## [0.1.2] - 2026-11-15

### Fixed
- Node conditions: GKE's `SysctlChanged` and `KubeletConfigChanged` (config snapshots that stay
  `True` on healthy nodes) no longer produce `high` findings with drain advice. Known
  node-problem-detector faults stay `high`; unknown vendor conditions are `medium` and never
  advise draining (#5).
- `find_problems` and `cluster_overview`: one root cause on many pods is one finding listing
  the other objects, dropped findings are counted in `omitted.findings`, and output capping
  keeps `cluster_overview`'s unhealthy-pod table ahead of extra findings (#4).
- A Deployment past its progress deadline gives one `workload.rollout.stuck` finding instead
  of also `workload.replicas.unavailable` (#6).
- `find_problems` no longer reports "pods seen: 0" for workloads whose pods exist (#7).

## [0.1.1] - 2026-11-15

### Fixed
- A tool call could hang forever without a response: when findings alone exceeded
  `--max-output-bytes`, output capping looped endlessly. Seen as `cluster_overview` never
  returning on a GKE cluster.
- API discovery no longer stalls on aggregated APIs that never answer (each group now has a
  5 s budget and groups are fetched concurrently), and `cluster_overview` detects
  metrics-server with a single request.

## [0.1.0] - 2026-11-15

### Fixed
- `pod.oom.container` now also fires (medium confidence) for exit 137 under a memory limit
  when the runtime reports reason `Error` instead of `OOMKilled` and no probe kill, eviction
  or preemption explains the SIGKILL; previously this was misread as `pod.crashloop.sigkill`.
  Found by the eval suite on GitHub-hosted runners (kind 1.37).

### Added
- stdio MCP server (`k8s-mcp`, crate `k8s-mcp-server`) built on rmcp 3.10 and kube 5.1.
- Read tools: `list_contexts`, `cluster_overview`, `api_resources`, `list_resources`,
  `get_resource`, `list_events`, `get_logs`, `top`, `check_permissions`.
- Diagnose tools: `diagnose_pod`, `diagnose_workload`, `diagnose_node`, `find_problems`,
  backed by a pure rule engine with stable finding ids (see `docs/rules.md`).
- Prompts `investigate-incident` and `cluster-health-check`; resources
  `k8s-mcp://policy`, `k8s-mcp://contexts`, `k8s-mcp://rules`.
- Safety: read-only tier only, Secret values never returned, redaction engine
  (`--redact`), context allow-list (default context only), namespace allow/deny globs,
  output cap, JSONL audit log with rotation, untrusted-content delimiters.
- Kubeconfig exec plugins run non-interactively with `--path-prepend` and macOS
  Homebrew PATH handling.
- `doctor`, `version` and `completions` subcommands.
- `cargo xtask kind-up | kind-down | eval | docs`; 14 eval scenarios (top-1 14/14 on kind 1.37).
- CI, integration and eval workflows; cargo-deny config; dist release config, Dockerfile
  (distroless, non-root) and container signing/SBOM workflow.
