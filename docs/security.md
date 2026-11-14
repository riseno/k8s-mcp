# Security and threat model

The full threat model is PROPOSAL.md §12. This page summarises what v0.1 enforces and how
it is tested.

| Threat | v0.1 mitigation | Test |
|---|---|---|
| Prompt injection via cluster content | No write tools exist; untrusted text is delimited, neutralised and capped; server instructions and tool descriptions say it is data | `envelope`/`text` unit tests, `list_events` golden test |
| Secret exfiltration | Secret values are never returned (keys and sizes only) in any mode, including `--redact off`; env/ConfigMap/annotation/log/audit redaction | `secrets_never_show_values_in_any_view`, redaction corpus (0 false negatives), kind canary test |
| Excessive privilege | Tool surface is read-only; `check_permissions` and `doctor` warn about `*` on `*` | kind tests |
| Context hopping | Only the default context unless `--contexts`; every response names its context | `cluster` unit tests, stdio test |
| Namespace escape | `--namespaces`/`--deny-namespaces` checked before every call and applied to cluster-wide results | per-tool namespace policy test |
| Resource exhaustion | List limits, log caps, output cap, 20 s API timeout, 30 s call timeout, 8 concurrent calls, client cancellation | envelope `fit` tests |
| Credential leakage by the server | Kubeconfig never written or shown; exec plugin output never echoed; errors and audit args redacted; no telemetry | stdio tests |
| Malicious arguments | Typed inputs with `deny_unknown_fields`; names validated; the kubeconfig path cannot be changed by the client; no shelling out | input tests |
| stdin hijack by exec plugins | Exec plugins forced to `interactiveMode: Never` | `cluster` unit test |

## Redaction levels

- `standard` (default): sensitive env names (`password`, `token`, `secret`, `api_key`, ...)
  are masked; values matching AWS keys, JWTs, bearer tokens, PEM keys, URL credentials, GCP
  service-account keys, Azure connection strings, GitHub/GitLab/Slack tokens and
  `password=`-style pairs are masked everywhere; `last-applied-configuration` is stripped.
- `strict`: also ConfigMap values (sizes only), IP addresses and email addresses.
- `off`: no redaction except Secret values; every response carries a warning.

## Audit log

One JSON line per tool call (timestamp, session, client, tool, tier, context, namespace,
redacted args, result, findings, bytes, truncated, duration, server version) at
`$XDG_STATE_HOME/k8s-mcp/audit.jsonl` (`~/Library/Application Support/k8s-mcp/` on macOS),
mode `0600`, rotated at 10 MB with 5 files kept. In-cluster it goes to stderr.
`--audit-log off` logs a warning at startup.
