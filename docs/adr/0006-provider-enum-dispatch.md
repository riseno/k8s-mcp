# ADR 0006: providers dispatch through an enum, not a trait object

- Status: accepted (v0.2)
- Date: 2026-11-15

## Context
PROPOSAL §10.1 sketches `#[async_trait] pub trait Provider` used as `dyn Provider`. Native
`async fn` in traits (Rust 2024) is not object-safe, so `dyn` dispatch needs either the
`async-trait` crate (not in §7.2) or hand-written boxed futures. There are exactly three
providers, each behind its own cargo feature.

## Decision
Keep the `Provider` trait as the contract each provider crate implements (so the parity
tests apply), with native `async fn`. The server holds detected providers as
`enum Detected { #[cfg(feature = "provider-eks")] Eks(EksProvider), ... }` and matches on it.
No `async-trait`, no boxing.

## Consequences
Adding a provider means one enum variant and one match arm per call site (a handful), which
the compiler enforces. Community providers (v1.0+) would revisit this if there are many.
