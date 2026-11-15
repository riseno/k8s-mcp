# ADR 0008: `find_problems` covers Services and PVCs from v0.2

- Status: accepted (v0.1.3)
- Date: 2026-11-15

## Context
PROPOSAL §8.1 describes v0.1 `find_problems` as finding problems "across pods, workloads,
nodes, PVCs, services, jobs". §9.2, however, schedules the Service (`svc.*`) and PVC (`pvc.*`)
rules for v0.2, together with `diagnose_service` and `diagnose_pvc`. v0.1 shipped
`find_problems` with `kinds` = `pods`, `workloads` (including Jobs and CronJobs) and `nodes`,
and `docs/progress.md` marked it done without recording the gap (riseno/k8s-mcp#18).

In v0.1 a PVC stuck `Pending` is reported only through the pod that mounts it
(`pod.pending.pvc_unbound`), and a Service whose selector matches no pods is not reported.

## Decision
Keep v0.1 as shipped. Add `services` and `pvcs` to `find_problems`' `kinds` in v0.2, built on
the `svc.*` and `pvc.*` rules from §9.2 rather than on ad-hoc v0.1 checks.

## Consequences
- v0.2 task 4 in `docs/progress.md` includes the two new `kinds`.
- Until then, `find_problems` does not surface unused PVCs or selector-less Services.
