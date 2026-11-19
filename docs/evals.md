# Evals

The eval suite measures whether the diagnosis tools name the right root cause. Each
scenario under `evals/scenarios/<NN-id>/` deploys a broken workload to the local kind
cluster in its own `eval-<id>` namespace.

```yaml
# evals/scenarios/06-liveness-wrong-port/scenario.yaml
id: liveness-wrong-port
symptom: The frontend deployment keeps restarting but nginx logs look clean. Why?
tool: diagnose_workload
args: {kind: Deployment, name: frontend, namespace: eval-liveness-wrong-port}
settle_seconds: 90
expected:
  primary: pod.probe.port_mismatch          # must rank first
  acceptable: [pod.probe.liveness_failing]  # allowed in the top 3
forbidden: [pod.crashloop.exit_zero]        # must not appear
```

## Running

```bash
cargo xtask kind-up                   # once
cargo xtask eval                      # all scenarios
cargo xtask eval --scenario oom-killed --keep
```

The runner builds `k8s-mcp`, applies every manifest (a scenario's optional `crds.yaml` first,
waiting until its CRDs are established, then its optional `setup.yaml`, waiting until its
ResourceQuotas are in force), waits for the longest `settle_seconds`, then calls
each scenario's tool over stdio MCP, then calls the first `diagnose_pod` scenario 20 more times
and the cluster-wide tools (`find_problems`, `recent_changes`, `upgrade_readiness`,
`cluster_overview`, no namespace) once each, and reports:

| Metric | Gate |
|---|---|
| Top-1 accuracy (primary ranked first) | ≥ 85% |
| Top-3 accuracy | 100% |
| Forbidden-finding rate | 0 |
| `diagnose_pod` p95 over the 20 runs (a failed call counts as 60 s) | < 2 s (v1.0) |
| Median response bytes, p95 latency, p50/p95 per tool, cluster-wide call times | reported |

Results are written to `evals/results/<version>.md`; the command exits non-zero when a gate
fails. Scenario objects' real statuses and events are kept as a test corpus in
`crates/k8s-mcp-testkit/fixtures/messages/`.

## Release gate

Releases are gated by the same suite. Pushing a version tag runs `release-gate.yml`, which
runs the evals on kind 1.34 and 1.37 and only then dispatches the dist-generated
`release.yml` for that tag. (dist's own plan jobs cannot block a release: a failed plan job
only skips the builds, and dist still creates an empty release, which is what happened to
`v0.1.0-rc.2`.)

After a release is published, `cargo xtask release-check [<version>]` (default: the latest
release) runs the README quickstart on a clean machine: an `ubuntu:24.04` container on kind's
Docker network runs the published shell installer, then `k8s-mcp doctor` against the kind
cluster, and fails if either fails, the version differs, or the two take more than 60 s. The
kind kubeconfig reaches the container on stdin; no copy is written to disk.

## Manual LLM-in-the-loop check

Not run in CI: point Claude Code (headless) or Grok Build at the kind cluster, invoke the
`investigate-incident` prompt with a scenario's `symptom`, and check that the final answer
names the expected root cause and fix.
