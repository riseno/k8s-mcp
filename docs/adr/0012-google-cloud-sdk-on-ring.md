# ADR 0012: the Google Cloud SDK on rustls + ring

- Status: accepted (v0.3)
- Date: 2026-11-16

## Context
The GKE provider needs the Cluster Manager, IAM and Cloud Logging APIs. The official Google
Cloud Rust SDK covers them (`google-cloud-container-v1`, `google-cloud-iam-admin-v1`,
`google-cloud-logging-v2`, `google-cloud-auth`; Apache-2.0, MSRV 1.91), but every crate's
default features pull aws-lc-rs through rustls, which ADR 0001 rules out (and `deny.toml`
bans). `google-cloud-iam-admin-v1` is not in PROPOSAL §7.2; crates outside §7.2 were approved
for v0.3 (`docs/progress.md`).

## Decision
All four crates with `default-features = false`. Their reqwest then has no rustls crypto
provider, so the binary installs ring as the process default in `main`, before any client is
built (the AWS SDK and kube bring their own ring configuration and are unaffected). `rustls`
becomes a direct dependency for that. Credentials: Application Default Credentials, except that
the provider refuses executable-sourced credentials and, off Google Cloud with no credentials
file, says so without probing the metadata server. `google-cloud-logging-v2` builds a tonic
gRPC client besides the HTTP one it uses (about 10 more crates); the binary size is reported in
the v0.3 size task.

## Consequences
One crate left on its defaults would bring aws-lc-rs back for the whole build; the `deny.toml`
bans catch it in CI. Tests run the clients against wiremock with anonymous credentials, and a
stdio test checks that a process without credentials gets one line of guidance without network
access.
