# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses SemVer.

## [Unreleased]

### Fixed
- `list_contexts` and `k8s-mcp://contexts` report the node-backed provider once a tool has
  listed a context's nodes (`cluster_overview`, `doctor`, provider tools, startup), with
  `provider_conflict` when the nodes contradict the kubeconfig, still without an API call. New
  `provider_source` says which: `nodes`, or `kubeconfig (nodes not checked)` (#71).
- Exec auth plugin failures no longer echo the plugin's output or the command's environment:
  a malformed credential (whose parse error quoted stdout, tokens included) and a failing
  plugin (whose message held every `env:` value and PATH) are reported as "the plugin's
  output is not an ExecCredential" or "the plugin failed (exit status: N)" (#74).
- A kubeconfig exec plugin that stalls fails the call after 20 s ("did not finish within
  20s; run it yourself") instead of holding it indefinitely: kube-client runs the plugin with
  a blocking call that stopped the 30 s call timeout from firing (#73).
- When the API server cannot be reached or the credentials fail, tools that gather optional
  evidence (`recent_changes`, `autoscaling_status`, `diagnose_dns` and others) return the
  "could not reach the API server" error at the first failed request instead of noting each
  one and running into the 30 s call timeout. The timeout message no longer assumes a large
  request (#80).
- `get_logs` and `diagnose_pod` show logs that contain invalid UTF-8 (binary output, Latin-1,
  a cut multi-byte character) with `�` for the bad bytes instead of dropping the whole log
  with a misleading network error. Control characters other than tab are shown as symbols
  (`\0` as `␀`, a lone `\r` as `␍`), and a response that cannot be decoded gets its own
  message (#75).

## [0.3.1] - 2026-11-16

### Fixed
- Provider detection treats listed nodes as authoritative: a kubeconfig that looks like one
  cloud (a `gke_...` context name, an EKS ARN, an exec plugin) no longer wins over nodes whose
  providerIDs name another platform (`kind://`, `k3s://`, another cloud). Such a cluster gets no
  provider toolset with `--providers auto`, `cluster_overview` and `doctor` name the conflict,
  and provider tools refuse before any cloud call unless the provider's `--<cloud>-cluster` flag
  is given, so credentials are never used against a cluster that is not this one (#64).
- `upgrade_readiness` checks the deprecated-API metric against the group/versions the cluster
  serves: entries for deleted CRDs, which the gauge keeps until the API server restarts, are no
  longer counted as in use and are noted as "requested earlier but no longer served" (#65).
- The `upgrade_readiness` summary counts the objects behind each check instead of checklist
  rows: `blocked by 4 PodDisruptionBudgets; review 4 deprecated APIs and 17 single-replica
  workloads` rather than `1 blocked, 2 to review` (#66).
- `upgrade_readiness`, `autoscaling_status`, `recent_changes` and `diagnose_dns` reject a
  `namespace` that does not exist, like the other namespaced tools, instead of reporting nothing
  found there (#67).
- `upgrade_readiness` explains core `v1 endpoints` (replaced by EndpointSlices; on most
  clusters the control plane's endpoints controller writes them and kube-proxy reads them, so
  act only if your own tools use them) instead of a bare "plan the move", and in-cluster, a
  forbidden scan of objects written through a deprecated CRD version names the
  `rbac.extraRules` entry to add (#68). Endpoints objects are not read for their writers:
  listing them would itself be a deprecated-API request.

## [0.3.0] - 2026-11-16

### Added
- Provider hints: when the cluster's cloud is known (from the kubeconfig, or the registered
  provider toolset in-cluster), findings whose cause is often cloud-specific get a concrete hint
  for that cloud in their fix: VPC CNI and Azure CNI IP exhaustion, ECR, Artifact Registry and
  ACR pull permissions, Docker Hub pull caches, EBS, Azure disk and Persistent Disk attach
  limits, Karpenter EC2NodeClass, and EC2, Compute Engine and Azure vCPU quota in Cluster
  Autoscaler events. No cloud calls.
- Azure Kubernetes Service provider (cargo feature `provider-aks`, default): `aks_cluster_info`,
  `aks_node_pools`, `aks_addons`, `aks_identity_check` (workload identity: client-id annotation,
  pod label and injected environment, OIDC issuer, the managed identity and its federated
  credentials) and `aks_logs` (Log Analytics), with rules `aks.cluster.*`, `aks.nodepool.*` and
  `aks.wi.*`, and the upgrade profile in `upgrade_readiness`. Registered with `--providers auto`
  when the default context is AKS with high confidence, `--providers aks`, or
  `--aks-cluster <subscription>/<resourceGroup>/<name>`. Credentials: workload identity, a
  service principal or managed identity from the environment; the Azure CLI login is not used
  (ADR 0013). See `docs/providers/aks.md`.
- Google Kubernetes Engine provider (cargo feature `provider-gke`, default): `gke_cluster_info`,
  `gke_node_pools`, `gke_addons`, `gke_identity_check` (Workload Identity: annotation, workload
  pool, node pools in `GKE_METADATA` mode, the Google service account and its
  `roles/iam.workloadIdentityUser` binding) and `gke_logs` (Cloud Logging), with rules
  `gke.cluster.*`, `gke.nodepool.*` and `gke.wi.*`, and the release channel's versions in
  `upgrade_readiness`. Registered with `--providers auto` when the default context is GKE with
  high confidence, `--providers gke`, or `--gke-cluster <project>/<location>/<name>`.
  Credentials: Application Default Credentials (no executable-sourced credentials); the SDK runs
  on rustls + ring (ADR 0012). See `docs/providers/gke.md`.
- `upgrade_readiness` (`target_version?`, default: the next minor): a checklist of what stands
  between the cluster and the next control-plane minor, with rules `upgrade.target_skips_minor`,
  `upgrade.removed_api_in_use`, `upgrade.deprecated_api_in_use`, `upgrade.kubelet_skew`,
  `upgrade.pdb_blocks_drain`, `upgrade.single_replica_workloads` and
  `upgrade.version_support_ending`. Removed and deprecated APIs come from the API server's
  `apiserver_requested_deprecated_apis` metric and from objects last written with them (who
  wrote them, from managedFields), read through each group's preferred version (ADR 0011). With
  the `eks` toolset it adds the EKS upgrade insights and the end of standard support. The chart
  grants `get` on `/metrics`.
- Prompt `upgrade-readiness` (`target_version`); `cluster-health-check` includes upgrade
  readiness.
- `upgrade_readiness` takes an optional `namespace` for its namespaced checks (PDBs, workloads,
  objects written with deprecated APIs).
- Eval scenarios 19–27 (27 in total): deprecated CRD version in use, PodDisruptionBudget
  blocking drains, init container failing, Job backoff limit, Service without ready endpoints,
  invalid image name, missing Secret, suspended CronJob, HPA that cannot compute its metric.
  A scenario may ship CRDs in `crds.yaml`, applied (and removed) around the run.
- Provider trait `upgrade_checks(target)` with a cloud-neutral `UpgradeInfo` (versions on offer,
  end of standard support, the cloud's own checks), and a default `access` for providers
  without access mapping before v1.0. EKS implements it with upgrade insights
  (`ListInsights`/`DescribeInsight`) and `DescribeClusterVersions`; rule
  `eks.upgrade.insight_failing` quotes the deprecated API usage, its callers and the affected
  resources. The IAM policy in `docs/providers/eks.md` adds the three actions.

## [0.2.1] - 2026-11-16

### Changed
- The Helm chart grants `get` on Secrets by default (`rbac.secretsMetadata: true`), so Secret
  values that pods print are masked in their logs. Values are still never returned, but the
  server's ServiceAccount can now read every Secret; set `rbac.secretsMetadata: false` to
  withhold it (logs may then contain those values, and the summary says so) (#46).
- The Helm chart requires caller tokens for the audience `k8s-mcp` (`auth.audience`): create
  them with `kubectl create token <sa> --audience k8s-mcp`. `auth.audience: ""` accepts any
  token the cluster authenticates, as in 0.2.0 (#52).

### Added
- `diagnose_dns` rule `dns.pod_bypasses_cluster_dns`: a pod whose nameservers skip the kube-dns
  Service (`dnsPolicy: None` or `Default` without its ClusterIP, or `ClusterFirst` with
  `hostNetwork`, which falls back to `Default`). `medium` when the pod's logs show failed
  `.svc` lookups, `info` otherwise; NodeLocal DNSCache (169.254.20.10) counts as the cluster
  DNS (#53).
- `--auth-audience` and `--allowed-callers` for `--auth tokenreview`. With an audience, only
  tokens the API server confirms for it pass (`kubectl create token <sa> --audience k8s-mcp`),
  so the ServiceAccount token every pod has by default no longer works. Allowed callers are
  globs over the TokenReview username or `group:<glob>`; others get 403 and an audit record
  with `"result": "refused"`. The Helm chart sets `auth.audience: k8s-mcp` by default and adds
  `auth.allowedCallers`; without an audience the server warns at startup (#52).

### Fixed
- When RBAC hides a Secret a pod uses, `get_logs`, `diagnose_pod` and `diagnose_dns` say in
  the summary that its values could not be masked and the logs may contain them, instead of
  only an `UNAVAILABLE EVIDENCE` line. The policy resource's `secret_values`, the server
  instructions, `docs/in-cluster.md` and `docs/security.md` describe this instead of
  "never returned" (#46).
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
