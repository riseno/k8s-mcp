# Write tools

k8s-mcp is read-only unless you start it with `--allow-write`. Even then, no tool changes the
cluster on its first call: every change is a server-side dry run first, and the change itself
needs the token that dry run returned.

## Enable them

| Flag | Registers |
|---|---|
| `--allow-write` | `restart_workload`, `scale_workload`, `rollback_workload`, `delete_pod`, `cordon_node`, `uncordon_node` |
| `--allow-destructive` (needs `--allow-write`) | `drain_node`, `apply_manifest` |
| `--write-deny-namespaces <globs>` | Namespaces no write tool changes objects in. Default `kube-system,kube-public,kube-node-lease`; `''` clears it |

Without the flags the tools are not registered at all: they are absent from `tools/list`, and
a call by name gets "tool not found". `--namespaces`, `--deny-namespaces` and `--contexts`
apply to writes as to reads. Over HTTP (`--transport http`), `--allow-write` also needs
`--auth tokenreview` with `--allowed-callers`, so only the users or groups you name can change
the cluster. With the Helm chart, set `writes.enabled` ([in-cluster.md](in-cluster.md#install)).

Every write tool is annotated `destructiveHint: true` (`scale_workload` and the node tools also
`idempotentHint: true`), so MCP clients that ask before risky tool calls ask before these.

## Two calls: plan, then confirm

1. **Plan.** Call the tool as usual (`dry_run` defaults to `true`). k8s-mcp sends the change to
   the API server with `dryRun=All`, which runs admission, validation and (for evictions)
   PodDisruptionBudgets without persisting anything. The result shows what would change
   (`path: before → after`) and its impact, plus a `confirm_token` and the exact call to
   confirm it in `next`.
2. **Confirm.** Show the plan to the user. Only once they agree, call again with
   `dry_run: false` and that `confirm_token`. The server instructions tell the model the same.

The token is an HMAC (SHA-256) of the tool, its arguments, the context and the
`resourceVersion` of every object the plan touches ([ADR 0015](adr/0015-confirm-tokens.md)).
It is rejected, and nothing changes, when:

- the arguments or the context differ from the plan's,
- any of those objects changed since the plan (a controller's status update counts),
- more than 120 seconds passed, or
- the token comes from another k8s-mcp process (the key is random per process).

The change itself carries the object's `resourceVersion` (and for `delete_pod` its UID) as a
precondition, so an update in the moment between the check and the write fails with a
conflict instead of applying. Write requests are never retried automatically.

## The tools

| Tool | What the plan shows | Refuses |
|---|---|---|
| `restart_workload` | the new `restartedAt` template annotation; how the update strategy replaces the pods (`OnDelete` replaces none) | kinds other than Deployment, StatefulSet, DaemonSet |
| `scale_workload` | `spec.replicas: a → b`; scaling to zero; an HPA that would set the replicas back | kinds other than Deployment, StatefulSet, ReplicaSet |
| `rollback_workload` | the pod template diff to the target revision (default: the previous one), then the path of every changed field (values left out); the token also binds the revision's ReplicaSet | paused Deployments, unknown or current revisions, identical templates |
| `delete_pod` | the grace period and which controller recreates the pod | pods without an owner (unless `allow_unowned: true`), static pods' mirrors, pods already terminating |
| `cordon_node`, `uncordon_node` | `spec.unschedulable`, the pods on the node | any node while `--namespaces` limits the server |
| `drain_node` | the cordon, then every pod: evicted, blocked by a PodDisruptionBudget, or left in place (DaemonSet, static, finished, no owner); pods losing `emptyDir` data | `ignore_daemonsets: false` on a node with DaemonSet pods; any node while `--namespaces` or `--deny-namespaces` limits the server |
| `apply_manifest` | each object's field diff (live against the dry-run result, values redacted), or `create` | Secrets; any object in the RBAC (`rbac.authorization.k8s.io`), admission (`admissionregistration.k8s.io`), CRD (`apiextensions.k8s.io`) or aggregated-API (`apiregistration.k8s.io`) groups; more than 20 objects or 256 KiB. Policy engines' own kinds (Kyverno, Gatekeeper) are not known and not refused: deny them with RBAC |

`drain_node` uses the Eviction API, so PodDisruptionBudgets hold. It reports each pod's outcome
and does not wait for the pods to terminate; call it again to retry the pods a budget blocked
(the node stays cordoned). Like `kubectl drain`, it evicts pods in every namespace: the write
deny-list protects the objects the other tools target directly.

`apply_manifest` is a server-side apply with field manager `k8s-mcp`, never forced: a field
another manager owns comes back as a conflict, and the plan fails rather than taking it over.

## Audit

Every write call is in the audit log with its tier and `dry_run` (`true` for a plan, `false` for
a confirm), including refused tokens and policy refusals, which are recorded as errors. The
`confirm_token` argument is masked like any token.
