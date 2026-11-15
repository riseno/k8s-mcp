# Progress

Status key: ✅ done · 🚧 in progress · ⏳ not started · ⛔ blocked (needs the maintainer)

## M0: Spike and skeleton

| Task | Status | Notes |
|---|---|---|
| Workspace, toolchain pin, lints, release profile | ✅ | Rust 1.98, edition 2024, pedantic clippy with documented allows |
| Bin crate: clap skeleton, tracing to stderr | 🚧 | |
| stdio server with `cluster_overview` | 🚧 | Server wiring merged into bin crate (ADR 0002) |
| ClusterManager, kubeconfig, exec-plugin test | 🚧 | |
| CI, musl static build, crypto ADR | 🚧 | ADR 0001: rustls + ring |
| xtask kind-up/kind-down, stdio integration test | 🚧 | |

## v0.1: MVP

| Task | Status | Notes |
|---|---|---|
| core: policy | ✅ | |
| core: redaction (corpus, proptest) | ✅ | 0 false negatives on corpus |
| core: envelope, text shaping, truncation | ✅ | |
| core: audit (JSONL, rotation) | 🚧 | |
| core: cache | ✅ | discovery cache only, list cache deferred (ADR 0004) |
| Read tools (§8.1) | 🚧 | |
| Diagnose rules (§9.2) | ✅ | all v0.1 areas; FailedScheduling parser; fixtures for the 14 eval scenarios with a ranking test (root cause first, forbidden ids absent). Evidence gathering for `node.npd.*`/quotas/HPA lives in the tools crate |
| diagnose_pod / workload / node, find_problems | 🚧 | |
| Prompts and resources | ⏳ | |
| doctor, PATH handling | ⏳ | |
| Eval scenarios, xtask eval | ⏳ | |
| Release config (dist, container, cosign, SBOM) | ⏳ | config only; publishing is the maintainer's call |
| Docs | ⏳ | |

## Deviations
- ADR 0002: no separate `k8s-mcp-server` library crate (name clash with the published bin).
- ADR 0003: serde-saphyr and jiff.
- ADR 0004: list cache and empty provider crates deferred.
