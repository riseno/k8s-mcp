# CLAUDE.md: k8s-mcp

## Purpose
k8s-mcp is an open-source MCP server, written in Rust, that lets AI assistants (Claude Code, Claude Desktop, Cursor, Grok Build) investigate and troubleshoot **any** conformant Kubernetes cluster safely: EKS, GKE, AKS, k3s, kind, on-prem and others. It ships as a single static binary. Optional provider modules add depth for EKS, GKE and AKS. It is the open-source core of a future hosted AI ops platform for any Kubernetes.

The full specification is in **PROPOSAL.md**. Follow its milestones (§16) in order: M0 → v0.1 → v0.2 → v0.3 → v0.4 → v1.0. Use Appendix A for the task order and the definition of done. Track progress in `docs/progress.md`, and record deviations as ADRs in `docs/adr/`.

## Principles (in priority order)
1. **Dead-simple install.** A single static binary with no runtime, no `kubectl` and no config file. It uses the existing kubeconfig (including exec auth plugins) and cloud credentials, and needs one line of MCP client config.
2. **Safe by default.**
   - Read-only unless `--allow-write` is set. Writes are dry-run by default and need a confirm token.
   - Secret values are never returned.
   - Env values, logs and annotations are redacted.
   - Namespaces and contexts can be allow-listed or denied.
   - Every tool call goes to the JSONL audit log.
3. **Deterministic first, LLM second.** Rules produce findings with evidence. The server never calls an LLM.
4. **Cloud-agnostic core.** EKS, GKE and AKS live in feature-gated provider crates with the same trait and parity. They are auto-detected and degrade gracefully.
5. **Token-efficient output.** Summaries first, hard caps, de-duplicated logs, stripped noise fields.

## Stack
- **Rust** stable, ≥ 1.95 (`kube` 5.x MSRV), edition 2024, `#![forbid(unsafe_code)]`.
- **Libraries:**
  - `rmcp` 3.x (official MCP Rust SDK), with `kube` 5.x and `k8s-openapi` 0.29.
  - `tokio`, `clap` 4, `serde`/`schemars`, `tracing`, and `axum` for HTTP (v0.2).
  - Providers: `aws-sdk-*` (EKS); `google-cloud-*` (GKE); `azure_identity` plus ARM REST via `reqwest` (AKS).
- **Tests:** `tower-test` (mock API server), `insta` (golden snapshots), `wiremock`, `proptest`, and kind integration.
- **Release:** `dist` (cargo-dist) for musl static Linux, macOS and Windows builds; a distroless multi-arch image; cosign; SBOM.
- **Before using any crate API, verify its current version and API on docs.rs. Do not copy outdated examples, and do not invent APIs.**

## Layout
`crates/`:
- `k8s-mcp`: the bin crate. Published as `k8s-mcp-server`, binary name `k8s-mcp`.
- `k8s-mcp-core`: policy, redaction, audit, output shaping, cache, ClusterManager.
- `k8s-mcp-diagnose`: the pure rule engine. **No I/O.**
- `k8s-mcp-tools`, `k8s-mcp-server`, `k8s-mcp-provider` and `k8s-mcp-provider-{eks,gke,aks}`.
- `k8s-mcp-testkit`.

Elsewhere: `xtask/`, `evals/scenarios/`, `deploy/helm/k8s-mcp/` and `docs/`.

## Commands
```bash
cargo build --workspace
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
cargo insta review                       # golden snapshots
cargo zigbuild --release --target x86_64-unknown-linux-musl   # static build check
cargo xtask kind-up                      # local kind cluster "k8s-mcp-dev", kubeconfig in ./.dev/kubeconfig
cargo xtask eval                         # run eval scenarios against kind
cargo xtask kind-down
cargo run -- doctor --kubeconfig ./.dev/kubeconfig
```
Create these xtask commands in M0 if they do not exist yet.

## Conventions
- **Process boundaries:**
  - **stdout is the MCP channel.** Never print to stdout in server code. Logs go to stderr, and clippy enforces `print_stdout = "deny"` in libraries.
  - No shelling out (no kubectl or sh) outside kube-rs exec plugins and `xtask`.
- **Errors:** no `unwrap`/`expect` outside tests. Errors must say what failed, why, and what to do next.
- **Tools:**
  - snake_case names matching PROPOSAL.md §8.
  - Inputs use `deny_unknown_fields` with documented fields.
  - Outputs use the Envelope (§7.7): summary, findings, items, truncated, next.
- **Rules:** one file per area, each with a stable dotted id and positive and negative fixtures. Never rename a released id.
- **Determinism:** inject a `Clock` and sort output.
- **Commits:** small Conventional Commits, with tests in the same commit. Update `docs/`, `CHANGELOG.md` and `docs/progress.md`.
- **Dependencies:** ask before adding one that is not listed in PROPOSAL.md §7.2.

## Safety rules (non-negotiable)
- **Test only against the local kind cluster** (context `kind-k8s-mcp-dev`, kubeconfig `./.dev/kubeconfig`) or against mocks and fixtures.
- **Never run k8s-mcp, kubectl, helm, aws, gcloud or az against any real cluster or cloud account**, even read-only, unless the user explicitly says so in this session for that specific target.
- Verify the context before any cluster command.
- Never read, print or copy `~/.kube/config`, `~/.aws`, `~/.config/gcloud`, `~/.azure` or any credentials or tokens.
- Cloud provider code is tested with mocks only. CI never calls real clouds.
- Never push, tag, publish crates, push images or create releases unless asked.
- Never weaken a safety default or disable a safety test to get green CI. Fix the code or ask.
