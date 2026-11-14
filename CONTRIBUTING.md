# Contributing

Thanks for helping. Contributions are accepted under the Apache-2.0 licence with a
[Developer Certificate of Origin](https://developercertificate.org/) sign-off: commit with
`git commit -s`.

## Ground rules

- Read [CLAUDE.md](CLAUDE.md) (project conventions) and the relevant part of [PROPOSAL.md](PROPOSAL.md).
- stdout is the MCP channel: never print to it from server code. Logs go to stderr.
- No `unwrap`/`expect` outside tests. Errors say what failed, why, and what to do next.
- Never weaken a safety default or disable a safety test.
- Small Conventional Commits with tests in the same commit; update `CHANGELOG.md` and docs.

Before opening a PR:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo xtask docs     # regenerates docs/tools.md and docs/rules.md
```

## Adding a detection rule

1. Pick the area file in `crates/k8s-mcp-diagnose/src/rules/` and a stable dotted id
   (`pod.<area>.<cause>`). Ids are never renamed once released.
2. Add a `RuleMeta` entry to the module's `RULES`, then the check. Quote cluster text only
   as `Source::Event`/`Source::Log` evidence; confidence is `high` only for definitive
   status fields or event reasons.
3. Add positive and negative fixtures under `crates/k8s-mcp-testkit/fixtures/` and tests.
   Real kubelet/scheduler messages go in `fixtures/messages/`.
4. Run `cargo xtask docs`.

## Adding an eval scenario

Create `evals/scenarios/<NN-id>/` with `manifest.yaml` (a broken workload in its own
`eval-<id>` namespace), `scenario.yaml` (symptom, tool, args, expected primary finding,
acceptable and forbidden ids) and a short `README.md`, then run `cargo xtask eval
--scenario <id>` against kind. A wrong diagnosis in the wild makes a great scenario.
