# ADR 0013: Azure through ARM REST, tokens from azure_identity, on ring

- Status: accepted (v0.3)
- Date: 2026-11-16

## Context
The AKS provider reads managed clusters, their upgrade profile and extensions, user-assigned
managed identities and their federated credentials, a Log Analytics workspace, and Log
Analytics queries. PROPOSAL §7.2 picks `azure_identity`, `azure_core` and `reqwest` with our own
ARM and Log Analytics calls instead of the management SDK crates. Their default features pull
aws-lc-rs (reqwest `rustls`) and OpenSSL (`azure_identity/client_certificate`), which ADR 0001
rules out. `azure_identity` 1.0 has no `DefaultAzureCredential`, and three of its credentials
(`AzureCliCredential`, `AzureDeveloperCliCredential`, `DeveloperToolsCredential`) run `az` or
`azd`.

## Decision
- `azure_core` (`reqwest`, `tokio`), `azure_identity` and `reqwest` (`rustls-no-provider`,
  `json`) with default features off; the ring provider the binary installs (ADR 0012) serves
  their TLS, and our reqwest client is the credentials' transport.
- Credentials are chosen from the environment, never probed: workload identity, a service
  principal secret, or managed identity where `IDENTITY_ENDPOINT` is set (the VM metadata
  endpoint retries for over a minute off Azure). The command-running credentials are banned in
  `clippy.toml` (`disallowed-types`).
- Pinned GA api-versions: managedClusters and upgradeProfiles `2026-09-01`, extensions
  `2025-03-01`, managed identities and federated credentials `2024-11-30`, workspaces
  `2026-03-01`; logs through `https://api.loganalytics.azure.com/v1/workspaces/{customerId}/query`.
- ARM `nextLink`s are followed only on the ARM host, so the bearer token never reaches another
  host (a test checks it).

## Consequences
Laptop users without workload identity need a service principal's variables; `az login` alone
is not enough. Tests use a static `TokenCredential` and wiremock; the real credential types
cannot be pointed at a mock (their authority host must be HTTPS).
