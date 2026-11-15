# MCP clients

The snippets in the [README](../README.md#client-setup) work for Claude Code, Claude
Desktop, Cursor and Grok Build. Grok Build also reads `.mcp.json`, `.cursor/mcp.json` and
`~/.claude.json`, so an existing Claude or Cursor entry works there too.

## Verified clients

Manual verification (PROPOSAL §16 v0.1 criterion 2) is recorded here with client versions.

| Client | Version | Platform | Result |
|---|---|---|---|
| Claude Code | 2.1.285 | macOS 26.6.2 (arm64), k8s-mcp 0.1.0 via `brew install riseno/tap/k8s-mcp` | ✅ `claude mcp add k8s -- k8s-mcp` connects; `k8s-mcp doctor` passes (2026-11-15) |
| Claude Desktop | not yet verified | macOS | |
| Cursor | not yet verified | | |
| Grok Build | not yet verified | | |

## Protocol

k8s-mcp uses rmcp 3.10, which negotiates MCP `2026-07-28` and stays compatible with
`2025-11-25`. It does not use sampling, roots or server logging.
