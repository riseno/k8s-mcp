# ADR 0005: kind test matrix 1.34/1.37, `[profile.dist]` in `.cargo/config.toml`

- Status: accepted (M0)
- Date: 2026-11-14

## Context
PROPOSAL §7.9 and §13 run integration tests on kind at the oldest and newest supported minors.
The default build targets `k8s-openapi` `v1_33`. kind v0.33.0 (current) publishes node images for
1.34.11, 1.35.8, 1.36.4 and 1.37.0 only, and its release notes say only those digests are
guaranteed to work with it.

`dist init` adds a `[profile.dist]` (with `lto = "thin"`) to the root `Cargo.toml`.

## Decision
- The integration matrix uses `kindest/node:v1.34.11` and `v1.37.0`, pinned by digest. 1.33 is
  covered by the `v1_33` API types and fixtures, not by a live cluster.
- `[profile.dist]` lives in `.cargo/config.toml` and only inherits `release`, so release
  artifacts keep the release profile's fat LTO. Cargo reads profiles from config files, and
  `dist plan`/`dist generate` accept it.

## Consequences
- When kind drops 1.34, move the oldest matrix entry forward and revisit `v1_33`.
- Re-run `dist generate` after changing `dist-workspace.toml`. Never edit `release.yml` by hand.
