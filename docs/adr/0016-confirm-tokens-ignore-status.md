# ADR 0016: Confirm tokens ignore status updates

- Status: accepted (1.0.1)
- Date: 2026-11-19
- Amends: [ADR 0015](0015-confirm-tokens.md)

## Context
ADR 0015 bound each object a plan touches by its `resourceVersion`. Every write to an object
changes it, status updates included, and controllers update the status of exactly the
workloads one acts on during an incident: a rollout in progress, a crash-looping pod, a
scale-up. On kind, plans for such a Deployment were rejected after a few seconds while its
`metadata.generation` never moved (riseno/k8s-mcp#122), so users had to approve, re-plan and
approve again.

## Decision
A token binds each object's *state*: a SHA-256 digest of the object as JSON (keys sorted)
without `status`, `metadata.resourceVersion` and `metadata.managedFields`
(`k8s_mcp_core::confirm::state`). A change to the spec, data, labels, annotations, owner
references, deletion timestamp or UID still voids the token; a status update does not.

The write itself is unchanged: it still carries the resourceVersion read in the confirming
call as a precondition (and the UID for `delete_pod`), so a change between that read and the
write fails with a conflict.

## Consequences
- Plans for unsettled workloads stay confirmable for their 120 s.
- A plan's informational lines that come from status (ready counts, pods on a node) can be
  older than the change they precede; what the change does depends only on what the token
  binds.
- `generation` alone was not used: Pods, Nodes and ConfigMaps have none, and label or
  annotation changes do not bump it.
- The signed message is versioned `k8s-mcp/confirm/v2`.
