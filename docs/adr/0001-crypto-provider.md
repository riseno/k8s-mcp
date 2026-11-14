# ADR 0001: rustls with the `ring` crypto provider

- Status: accepted (M0)
- Date: 2026-11-14

## Context
PROPOSAL §14 asks for exactly one rustls crypto provider across the dependency tree,
no OpenSSL, and painless musl static builds.

## Decision
Use `ring`. It is kube 5.1's default (`default = ["client", "rustls-tls", "ring"]`), it
cross-compiles for `*-unknown-linux-musl` without CMake or a C++ toolchain, and v0.1 has
no other TLS consumer.

## Consequences
- v0.2 provider crates (AWS SDK defaults to `aws-lc-rs`) must select their `ring`/rustls
  variants, or this ADR is revisited with measured binary size and build-time numbers.
- `cargo tree -i aws-lc-rs` and `cargo tree -i openssl-sys` must stay empty; CI checks this.
