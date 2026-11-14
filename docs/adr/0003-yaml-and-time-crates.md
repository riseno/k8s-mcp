# ADR 0003: serde-saphyr for YAML, jiff for time

- Status: accepted (M0)
- Date: 2026-11-14

PROPOSAL §7.2 leaves YAML (`serde_yaml` is unmaintained; evaluate forks) and time (`jiff`
or `chrono`) open. kube 5.1 already depends on `serde-saphyr` and k8s-openapi 0.29 uses
`jiff::Timestamp` for `Time`/`MicroTime`, so both choices add no new crates to the tree.
