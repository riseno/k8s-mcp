# ADR 0011: upgrade readiness reads the deprecated-API metric and managedFields

- Status: accepted (v0.3)
- Date: 2026-11-16

## Context
`upgrade_readiness` must find clients that still use API versions the target release
removes (PROPOSAL §8.1). The Kubernetes deprecation guide lists no built-in removals after
1.32, and k8s-mcp supports 1.33 and later, so a static table of removed APIs finds nothing on
supported clusters. What is still deprecated on them is mostly beta APIs, CRD versions marked
`deprecated`, and core `v1` Endpoints (deprecated since 1.33, no removal planned).

## Decision
Two signals, both checked on kind 1.37:
- The API server's `apiserver_requested_deprecated_apis` metric (`GET /metrics`): every
  deprecated group/version/resource requested since that API server started, with
  `removed_release`. It covers CRD versions marked `deprecated`. Findings from it are high
  confidence. The chart's ClusterRole gets `get` on the `/metrics` non-resource URL; without
  it the checklist says "not checked".
- Objects whose `managedFields` (or last-applied annotation) name a deprecated version, which
  says who wrote them that way (field managers are client text, so the evidence is marked
  untrusted). Medium confidence on its own, because the writer may have moved on since. Only
  APIs that a release removes and deprecated CRD versions are scanned. Objects are listed
  through the group's preferred version, never the deprecated one, so k8s-mcp does not show
  up as a deprecated-API caller itself.

Severity follows the removal: removed by the target is high; deprecated without removal by
the target is low for CRD versions (the owner may drop them in any release) and info for
built-ins. The static removal table (≤ 1.32) stays for older clusters.

## Consequences
On a highly available control plane the metric only covers the API server instance that
answered, and it resets when that instance restarts; EKS upgrade insights (30 days of audit
data) complement it on EKS. Clusters that deny `/metrics` still get the object scan.
