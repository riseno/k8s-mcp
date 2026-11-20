# ADR 0015: Confirm tokens for write tools

- Status: accepted (v0.4); what the token binds per object changed in [0016](0016-confirm-tokens-ignore-status.md)
- Date: 2026-11-18

## Context
PROPOSAL §12.4 makes every write a two-step call: a dry-run plan that returns a `confirm_token`,
then the change itself, accepted only with that token. The token is an HMAC over the tool, its
arguments, the context, the objects' `resourceVersion` and a 120 s expiry, keyed per process,
and it must be rejected when any of these change (v0.4 AC 3).

## Decision
- `k8s-mcp-core::confirm` signs with HMAC-SHA256 from `ring`, which the build already uses as
  its TLS crypto provider (ADR 0001); the key comes from ring's `SystemRandom` on first use and
  lives only in memory, so a restart invalidates every outstanding token.
- The signed text is versioned and line based: `k8s-mcp/confirm/v1`, the expiry, the tool,
  the context, the arguments as JSON with sorted keys (the request with defaults resolved and
  without `dry_run`/`confirm_token`), and one `kind/namespace/name=resourceVersion` line per
  target object, sorted (`-` for an object that does not exist yet).
- A token is `<expiry unix seconds>.<hex MAC>`. Verification rejects a malformed token, then
  an expired one, then compares the MAC in constant time (`ring::hmac::verify`). Every
  rejection says nothing was changed and asks for a new plan.

## Consequences
A token proves the change is the one that was planned against the same object state, by this
server process, within 120 s. It does not prove a human saw the plan: that remains the MCP
client's approval prompt, which the tools trigger with `destructiveHint: true`. The expiry is
in the token, so a tampered expiry fails the MAC check.
