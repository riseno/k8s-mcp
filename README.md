# k8s-mcp

**Safe, zero-setup Kubernetes troubleshooting for AI assistants.** One static binary that lets Claude Code, Claude Desktop, Cursor, Grok Build and other MCP clients investigate any conformant cluster (EKS, GKE, AKS, k3s, kind, on-prem). It is read-only, needs no config file, and returns diagnoses with evidence instead of raw YAML.

## Quickstart

1. Install (pick one):

       brew install riseno/tap/k8s-mcp
       # or
       curl -fsSL https://github.com/riseno/k8s-mcp/releases/latest/download/k8s-mcp-server-installer.sh | sh

2. Check it can see your cluster (uses your current kubeconfig context):

       k8s-mcp doctor

3. Add it to your AI assistant:

       claude mcp add k8s -- k8s-mcp          # Claude Code
       grok mcp add k8s -- k8s-mcp            # Grok Build

   (Cursor and Claude Desktop: see [Client setup](#client-setup).)

4. Ask: "Why is the checkout pod in namespace shop crash-looping?"

k8s-mcp is read-only by default. It never returns Secret values and redacts
credentials in logs and env vars. Nothing to configure.

## Client setup

All snippets assume `k8s-mcp` is on `PATH`. If a GUI client cannot find it, use the absolute path (for example `/opt/homebrew/bin/k8s-mcp`).

**Claude Code**

```bash
claude mcp add k8s -- k8s-mcp
# pin a context and namespaces:
claude mcp add k8s -- k8s-mcp --context staging --namespaces 'shop,payments'
```

**Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows)

```json
{
  "mcpServers": {
    "k8s": {
      "command": "/opt/homebrew/bin/k8s-mcp",
      "args": [],
      "env": { "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin" }
    }
  }
}
```

GUI apps start with a minimal `PATH`, so kubeconfig exec plugins (`aws`, `gke-gcloud-auth-plugin`, `kubelogin`) may not be found. Set `PATH` as above or pass `--path-prepend <dirs>`; on macOS k8s-mcp also adds `/opt/homebrew/bin` and `/usr/local/bin` for exec plugins.

**Cursor** (`~/.cursor/mcp.json`, or `.cursor/mcp.json` per project)

```json
{ "mcpServers": { "k8s": { "command": "k8s-mcp", "args": [] } } }
```

**Grok Build**: `grok mcp add k8s -- k8s-mcp`, or in `~/.grok/config.toml`:

```toml
[mcp_servers.k8s]
command = "k8s-mcp"
args = []
```

## Example

`diagnose_pod {"name": "checkout-7d9f8c6b5-x2k4q", "namespace": "shop"}` returns (text content, abridged):

```
checkout-7d9f8c6b5-x2k4q (shop) is CrashLoopBackOff: container "app" was OOMKilled: it exceeded its 128Mi memory limit.

FINDINGS
1. [critical/high] pod.oom.container: container "app" was OOMKilled: it exceeded its 128Mi memory limit
   evidence (status): lastState.terminated reason=OOMKilled exitCode=137 (4m ago)
   evidence (spec): heap flag -Xmx256m in env JAVA_OPTS exceeds the 128Mi limit
   fix: Set the heap well below the limit (for JVMs prefer -XX:MaxRAMPercentage=75 instead of -Xmx256m), or raise resources.limits.memory to at least 384Mi.

LOG EXCERPT (previous instance, last 2 of 2 lines, redacted)
<<untrusted source="log" container="app">>
  Exception in thread "main" java.lang.OutOfMemoryError: Java heap space
<</untrusted>>

NEXT
- get_logs {"container":"app","namespace":"shop","pod":"checkout-7d9f8c6b5-x2k4q","previous":true,"tail":200} : see what the process was doing before the kill
```

## Tools

| Toolset | Tools |
|---|---|
| `core` | `list_contexts`, `cluster_overview`, `api_resources`, `list_resources`, `get_resource`, `list_events`, `get_logs`, `top`, `check_permissions` |
| `diagnose` | `diagnose_pod`, `diagnose_workload`, `diagnose_node`, `find_problems` |

Prompts: `investigate-incident`, `cluster-health-check`. Resources: `k8s-mcp://policy`, `k8s-mcp://contexts`, `k8s-mcp://rules`. See [docs/tools.md](docs/tools.md) and [docs/rules.md](docs/rules.md).

## Safety model

- **Read-only.** v0.1 has no write tools at all; every tool carries `readOnlyHint: true`.
- **Secret values are never returned**: only key names and sizes, in every mode.
- **Redaction** of credentials in logs, env values, annotations, ConfigMaps, args and the audit log (`--redact strict|standard|off`).
- **Scoping**: only the default context unless `--contexts` widens it; `--namespaces` / `--deny-namespaces` globs.
- **Audit log** of every tool call (JSONL, `0600`, rotated) at `$XDG_STATE_HOME/k8s-mcp/audit.jsonl`.
- **Prompt-injection hygiene**: cluster text is wrapped in `<<untrusted>>` blocks and capped; the server never calls an LLM and never shells out.

RBAC is the real boundary: k8s-mcp cannot reduce what your kubeconfig may do, so prefer a dedicated read-only identity for AI tools ([docs/security.md](docs/security.md)).

## Flags

No config file is needed; every flag also reads `K8S_MCP_<FLAG>` (for example `K8S_MCP_NAMESPACES`).

| Flag | Default | Purpose |
|---|---|---|
| `--kubeconfig <path>` | `$KUBECONFIG` or `~/.kube/config` | Kubeconfig |
| `--in-cluster` | auto | Use the ServiceAccount token |
| `--context <name>` | current-context | Default context |
| `--contexts <glob,...>` | default only | Other contexts the AI may target (`*` = all) |
| `--namespaces <glob,...>` | all | Namespace allow-list |
| `--deny-namespaces <glob,...>` | none | Deny-list (wins over allow) |
| `--redact strict\|standard\|off` | `standard` | Redaction level |
| `--max-output-bytes` | `24000` | Hard cap per tool response |
| `--audit-log <path>\|stderr\|off` | state dir (stderr in-cluster) | Audit sink |
| `--toolsets <list>` | `core,diagnose` | Reduce the tool list for small-context models |
| `--path-prepend <dirs>` | none | Extra `PATH` for exec plugins |
| `--log-level` | `warn` | Logs go to stderr only |

Subcommands: `serve` (default), `doctor`, `version`, `completions <shell>`.

## How it compares

k8s-mcp is deterministic first: tested rules turn container states, events, logs and node state into ranked findings with evidence, and the assistant explains and plans on top. See [PROPOSAL.md §3](PROPOSAL.md#3-landscape-and-differentiation) for a comparison with other Kubernetes MCP servers, k8sgpt and HolmesGPT.

## Development

```bash
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo xtask kind-up            # local kind cluster k8s-mcp-dev, kubeconfig in ./.dev/kubeconfig
cargo xtask eval               # diagnosis eval scenarios against kind
cargo run -- doctor --kubeconfig ./.dev/kubeconfig
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/](docs/SUMMARY.md). Licence: [Apache-2.0](LICENSE).
