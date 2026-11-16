# ADR 0010: provider detection lives in core

- Status: accepted (v0.2)
- Date: 2026-11-15

## Context
PROPOSAL §7.3 puts detection in `k8s-mcp-provider` next to the `Provider` trait. Detection
is pure (kubeconfig signals and node fields, no cloud calls) and is needed by core itself
(`ContextInfo.provider` for `list_contexts` and the `k8s-mcp://contexts` resource), by
`cluster_overview` and by `doctor`, in every build, including ones without provider
modules. v0.1 already had two partial detectors: `guess_provider` in core (kubeconfig) and
`provider_from_nodes` in the tools crate (providerIDs), neither of which extracted the
cluster's identity. Provider modules need that identity (name, region, account) for their
cloud calls.

## Decision
`k8s_mcp_core::provider::detect` replaces both detectors. It covers EKS, GKE and AKS from
node providerIDs and labels, the API server host, the exec plugin and its arguments, and the
context name, and returns the provider, a confidence (a bare providerID is `Low`: self-managed
clusters on the same cloud share it) and the identity. `ClusterManager::detect_provider`
feeds it a context's kubeconfig signals plus any listed nodes.

`k8s-mcp-provider` (the `Provider` trait and shared types, ADR 0006) is created with the EKS
provider, its first implementation (ADR 0004), and uses core's detection.

Listed nodes are authoritative (issue #64): a provider whose kubeconfig signals the nodes'
providerIDs contradict (every node on another platform or cloud) is dropped, and
`provider::conflict` says why. Startup with `--providers auto` reads a few nodes before
registering a toolset the kubeconfig suggests, and provider tools read them before any cloud
call.

## Consequences
Core has no dependency on provider crates, so there is no cycle, and detection works in
`--no-default-features` builds. Explicit identity flags (`--eks-cluster` and friends,
PROPOSAL §10.2) arrive with the provider modules that need them.
