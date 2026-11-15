# ADR 0007: the AWS SDK uses rustls with ring

- Status: accepted (v0.2)
- Date: 2026-11-15

## Context
ADR 0001 chose one rustls crypto provider, `ring`, for the whole tree. The AWS SDK for Rust
defaults to `aws-lc-rs`, which needs a C/CMake toolchain for musl builds and would put a
second provider in the binary.

## Decision
Use the SDK crates (`aws-config`, `aws-sdk-eks`, `aws-sdk-iam`, `aws-sdk-sts`,
`aws-sdk-cloudwatchlogs`) with default features off, and build their HTTP client with
`aws-smithy-http-client`'s `rustls-ring` feature (a direct dependency, approved by the
maintainer). EKS tests use `aws-smithy-mocks` as a dev-dependency (approved).

## Consequences
`cargo tree -i aws-lc-rs` must stay empty; `deny.toml` keeps banning `aws-lc-rs`/`aws-lc-sys`.
SDK upgrades must keep the `rustls-ring` client path working.
