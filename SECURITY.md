# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub Security Advisories:
**Security → Report a vulnerability** on the repository. Do not open a public issue.

Include the k8s-mcp version (`k8s-mcp version`), the MCP client, and steps to reproduce.
You will get an acknowledgement within 7 days. Fixes are released as patch versions and
credited in the advisory unless you ask otherwise.

## Scope

In scope: anything that lets tool output include Secret values or unredacted credentials,
bypasses the context or namespace policy, writes to the cluster, writes to stdout outside
MCP frames, or leaks kubeconfig or cloud credentials. The threat model is in
[docs/security.md](docs/security.md) and PROPOSAL.md §12.

Out of scope: what the kubeconfig identity itself may do through RBAC (k8s-mcp cannot
reduce those rights), and prompt-injection content that the model follows despite the
untrusted-content markers, when no write tools are enabled.
