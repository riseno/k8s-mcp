# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses SemVer.

## [Unreleased]

### Added
- Streamable HTTP transport for in-cluster use: `--transport http` serves MCP at `/mcp`
  (stateless for protocol `2026-07-28`, sessions for older clients) with `/healthz` and
  `/readyz`, on `--listen` (default `127.0.0.1:8080`).
- HTTP auth: `--auth tokenreview` (default; Kubernetes tokens validated with the TokenReview
  API, cached 60 s), `--auth static --auth-token-file <path>`, or `--auth none` on loopback
  only. `Host` and `Origin` allow-lists (`--allowed-hosts`, `--allowed-origins`).
- Audit records carry the authenticated HTTP `caller`.
- Cargo feature `http` (default); `--no-default-features` builds a stdio-only binary.

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
