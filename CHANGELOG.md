# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses SemVer.

## [Unreleased]

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
