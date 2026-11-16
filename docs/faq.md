# FAQ

**Why not just use kubectl?** The assistant can, but raw `describe` and `logs` output is
large and pushes all correlation onto the model. k8s-mcp gathers the related facts
(container states, exit codes, events, previous logs, node, referenced objects) in one
bounded call and returns ranked findings with evidence and a fix.

**Does it call an LLM or need an API key?** No. Rules are deterministic; your MCP client
is the agent.

**Can it change my cluster?** Not in v0.1: no write tools exist. A guarded write tier
(dry-run plus confirm tokens) is planned for v0.4 behind `--allow-write`.

**Can it read my Secrets?** If your kubeconfig can, k8s-mcp checks existence and key names
for diagnosis, but values are never returned. Use a read-only identity without Secrets
access for the strongest guarantee.

**My exec plugin is not found from Claude Desktop.** GUI apps start with a minimal `PATH`.
Set `env.PATH` in the client config or pass `--path-prepend /opt/homebrew/bin`.
`k8s-mcp doctor` shows which plugin is missing.

**How is this different from other Kubernetes MCP servers?** It is read-only
by default, no runtime or kubectl, deterministic diagnosis with evidence, and (from v0.2)
EKS/GKE/AKS provider depth with one safety model.
