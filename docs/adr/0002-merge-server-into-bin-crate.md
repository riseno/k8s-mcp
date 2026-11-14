# ADR 0002: MCP server wiring lives in the bin crate

- Status: accepted (M0)
- Date: 2026-11-14

## Context
PROPOSAL §7.3 lists a library crate `crates/k8s-mcp-server` *and* publishes the bin crate
`crates/k8s-mcp` under the package name `k8s-mcp-server` (§18). Cargo rejects two packages
with the same name in one workspace.

## Decision
Drop the separate library crate. The rmcp `ServerHandler`, tool registry, prompts and
resources live in `crates/k8s-mcp/src/server.rs` (package `k8s-mcp-server`, binary
`k8s-mcp`). Tool logic stays transport-free in `k8s-mcp-tools`, which keeps §17.1's
"tool logic separate from transports".

## Consequences
One fewer crate. If a future hosted layer needs to embed the handler, extract it then
under a non-clashing name (for example `k8s-mcp-handler`).
