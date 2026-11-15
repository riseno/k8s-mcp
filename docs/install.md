# Install

k8s-mcp is a single binary with no runtime, no `kubectl` and no config file.

| Method | Command |
|---|---|
| Homebrew | `brew install riseno/tap/k8s-mcp` |
| Shell installer | `curl -fsSL https://github.com/riseno/k8s-mcp/releases/latest/download/k8s-mcp-server-installer.sh \| sh` |
| PowerShell | `irm https://github.com/riseno/k8s-mcp/releases/latest/download/k8s-mcp-server-installer.ps1 \| iex` |
| cargo | `cargo binstall k8s-mcp-server` or `cargo install k8s-mcp-server --locked` (the binary is `k8s-mcp`) |
| Container | `docker run --rm -i -v ~/.kube:/home/nonroot/.kube:ro ghcr.io/riseno/k8s-mcp:latest` |

The crate is `k8s-mcp-server` because `k8s-mcp` is taken on crates.io.

The container image has no exec auth plugins (`aws`, `gke-gcloud-auth-plugin`,
`kubelogin`), so for EKS, GKE and AKS prefer the native binary.

## Check the setup

```text
$ k8s-mcp doctor
✓ kubeconfig: /home/me/.kube/config
✓ context: staging
✓ API server reachable: Kubernetes v1.34.2
✓ can list pods in default: yes
✓ can read pod logs in default: yes
...
All checks passed. Add k8s-mcp to your MCP client, e.g. `claude mcp add k8s -- k8s-mcp`.
```

`doctor` exits non-zero with an actionable message on failure, for example when an exec
plugin is not on `PATH` ("install it, or pass --path-prepend <dir>").

## A dedicated read-only identity

k8s-mcp is read-only, but it acts with your kubeconfig's rights. For AI tools, create a
ServiceAccount bound to the read-only ClusterRole in PROPOSAL.md Appendix C (no Secrets
access) and give k8s-mcp a kubeconfig for it with `--kubeconfig`.
