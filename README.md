# k8s-mcp

**Safe, zero-setup Kubernetes troubleshooting for AI assistants.** One static binary that lets Claude Code, Claude Desktop, Cursor, Grok Build and other MCP clients investigate any conformant cluster (EKS, GKE, AKS, k3s, kind, on-prem). It is read-only by default, needs no config file, and returns diagnoses with evidence instead of raw YAML.

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
| `core` | `list_contexts`, `cluster_overview`, `api_resources`, `list_resources`, `get_resource`, `list_events`, `get_logs`, `top`, `autoscaling_status`, `upgrade_readiness`, `recent_changes`, `rollout_history`, `check_permissions` |
| `diagnose` | `diagnose_pod`, `diagnose_workload`, `diagnose_node`, `diagnose_service`, `diagnose_pvc`, `diagnose_dns`, `find_problems` |
| `eks` (when the cluster is EKS) | `eks_cluster_info`, `eks_nodegroups`, `eks_addons`, `eks_access`, `eks_identity_check`, `eks_logs` ([docs/providers/eks.md](docs/providers/eks.md)) |
| `gke` (when the cluster is GKE) | `gke_cluster_info`, `gke_node_pools`, `gke_addons`, `gke_access`, `gke_identity_check`, `gke_logs` ([docs/providers/gke.md](docs/providers/gke.md)) |
| `aks` (when the cluster is AKS) | `aks_cluster_info`, `aks_node_pools`, `aks_addons`, `aks_access`, `aks_identity_check`, `aks_logs` ([docs/providers/aks.md](docs/providers/aks.md)) |
| `helm` (`--allow-helm-releases`) | `helm_releases`, `helm_release`: releases, revision history, failure descriptions and notes from Helm's release records; values are never shown |
| write (`--allow-write`) | `restart_workload`, `scale_workload`, `rollback_workload`, `delete_pod`, `cordon_node`, `uncordon_node`; with `--allow-destructive` also `drain_node`, `apply_manifest` ([docs/writes.md](docs/writes.md)) |

From 1.0, tool names and arguments, rule ids and the output envelope are stable across 1.x ([docs/stability.md](docs/stability.md)).

Prompts: `investigate-incident`, `cluster-health-check`, `explain-workload`, `access-review`, `upgrade-readiness`. Resources: `k8s-mcp://policy`, `k8s-mcp://contexts`, `k8s-mcp://rules` and the template `k8s-mcp://cluster/{context}/overview`. See [docs/tools.md](docs/tools.md) and [docs/rules.md](docs/rules.md).

## In-cluster endpoint

One shared, audited endpoint for a team: `helm install k8s-mcp oci://ghcr.io/riseno/charts/k8s-mcp -n k8s-mcp --create-namespace --set 'auth.allowedCallers={group:sre}'`
serves streamable HTTP at `/mcp`, authenticates callers with Kubernetes tokens (TokenReview)
and acts with a read-only ServiceAccount. See [docs/in-cluster.md](docs/in-cluster.md).

## Safety model

- **Read-only by default.** Write tools exist only with `--allow-write`; each change is a server-side dry-run plan first and needs that plan's confirm token, bound to the exact request and object versions ([docs/writes.md](docs/writes.md)).
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
| `--transport stdio\|http` | `stdio` | MCP transport; `http` serves streamable HTTP at `/mcp`, with `/healthz` and `/readyz` |
| `--listen <addr>` | `127.0.0.1:8080` | HTTP listen address |
| `--auth tokenreview\|static\|none` | `tokenreview` | HTTP bearer auth: Kubernetes tokens checked with TokenReview, one token from `--auth-token-file`, or none (loopback only) |
| `--auth-token-file <path>` | none | Bearer token file for `--auth static` |
| `--auth-audience <aud,...>` | none (the Helm chart: `k8s-mcp`) | Audiences `tokenreview` tokens must be minted for; without one, every pod's default ServiceAccount token is accepted |
| `--allowed-callers <glob,...>` | all authenticated | `tokenreview` callers let in: username globs or `group:<glob>`; others get 403, audited |
| `--allowed-hosts <host,...>` | `localhost`, `127.0.0.1`, `::1` | HTTP `Host` values accepted (DNS-rebinding protection) |
| `--allowed-origins <origin,...>` | none | Browser `Origin` values accepted; any other `Origin` gets 403 |
| `--providers auto\|none\|eks\|gke\|aks` | `auto` | Cloud provider toolsets: `auto` registers one when the default context is detected as that provider |
| `--eks-cluster`, `--eks-region` | detected | EKS cluster name and region when detection cannot tell (in-cluster) |
| `--gke-cluster <project>/<location>/<name>` | detected | GKE cluster when detection cannot tell (in-cluster) |
| `--aks-cluster <subscription>/<resourceGroup>/<name>` | detected | AKS cluster when detection cannot tell |
| `--kubeconfig <path>` | `$KUBECONFIG` or `~/.kube/config` | Kubeconfig |
| `--in-cluster` | auto | Use the ServiceAccount token |
| `--context <name>` | current-context | Default context |
| `--contexts <glob,...>` | default only | Other contexts the AI may target (`*` = all) |
| `--namespaces <glob,...>` | all | Namespace allow-list |
| `--deny-namespaces <glob,...>` | none | Deny-list (wins over allow) |
| `--allow-write` | off | Register the write tools: each change is a server-side dry-run plan first and needs the plan's confirm token |
| `--allow-destructive` | off | Also register `drain_node` and `apply_manifest`; needs `--allow-write` |
| `--allow-helm-releases` | off | Register `helm_releases` and `helm_release` (needs `list` on Secrets, where Helm keeps its records) |
| `--write-deny-namespaces <glob,...>` | `kube-system,kube-public,kube-node-lease` | Namespaces no write tool changes objects in (`''` clears the list) |
| `--redact strict\|standard\|off` | `standard` | Redaction level |
| `--max-output-bytes` | `24000` | Hard cap per tool response |
| `--audit-log <path>\|stderr\|off` | state dir (stderr in-cluster) | Audit sink |
| `--toolsets <list>` | `core,diagnose` | Reduce the tool list for small-context models |
| `--path-prepend <dirs>` | none | Extra `PATH` for exec plugins |
| `--log-level` | `warn` | Logs go to stderr only |

Subcommands: `serve` (default), `doctor`, `version`, `completions <shell>`.

## How it compares

k8s-mcp is deterministic first: tested rules turn container states, events, logs and node state into ranked findings with evidence, and the assistant explains and plans on top. Compared with general-purpose Kubernetes MCP servers, it is read-only by default, needs no kubectl and redacts what it returns; compared with k8sgpt and HolmesGPT, the server itself never calls an LLM.

## Development

```bash
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo xtask kind-up            # local kind cluster k8s-mcp-dev, kubeconfig in ./.dev/kubeconfig, API audit log in ./.dev/audit/
cargo xtask eval               # diagnosis eval scenarios against kind
cargo run -- doctor --kubeconfig ./.dev/kubeconfig
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and the docs ([docs/](docs/SUMMARY.md), published at <https://riseno.github.io/k8s-mcp/>). Licence: [Apache-2.0](LICENSE).
