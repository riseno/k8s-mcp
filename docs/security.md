# Security and threat model

This page summarises the threat model: what is enforced and how it is tested.

| Threat | Mitigation | Test |
|---|---|---|
| Prompt injection via cluster content | No write tools exist; untrusted text is delimited, neutralised and capped; server instructions and tool descriptions say it is data | `envelope`/`text` unit tests, `list_events` golden test |
| Secret exfiltration | Secret values are never returned (keys and sizes only) in any mode, including `--redact off`; in pod logs, values of the Secrets the pod uses are masked when k8s-mcp may read them (otherwise the summary warns); env/ConfigMap/annotation/log/audit redaction | `secrets_never_show_values_in_any_view`, redaction corpus (0 false negatives), kind canary test |
| Excessive privilege | Tool surface is read-only unless `--allow-write`; `check_permissions` and `doctor` warn about `*` on `*` | kind tests |
| Writes going wrong (T10) | Write tools only with `--allow-write`; every change is a `dryRun=All` plan first and needs its confirm token (HMAC over tool, args, context and resourceVersions, 120 s, per process); resourceVersion/UID preconditions; no automatic retries; `--write-deny-namespaces` (default `kube-system,kube-public,kube-node-lease`); PodDisruptionBudget-respecting evictions; unowned pods refused; `apply_manifest` never forced and refuses Secrets, RBAC, admission control and CRDs; over HTTP only `--allowed-callers` ([writes.md](writes.md)) | `tests/write.rs` (every tool sends only dry runs without its token), the kind test against the API server's audit log, the chart smoke test |
| Context hopping | Only the default context unless `--contexts`; every response names its context | `cluster` unit tests, stdio test |
| Namespace escape | `--namespaces`/`--deny-namespaces` checked before every call and applied to cluster-wide results | per-tool namespace policy test |
| Resource exhaustion | List limits, log caps, output cap, 20 s API timeout, 30 s call timeout, 8 concurrent calls, client cancellation | envelope `fit` tests |
| Credential leakage by the server | Kubeconfig never written or shown; exec plugin output never echoed; errors and audit args redacted; no telemetry | stdio tests |
| Malicious arguments | Typed inputs with `deny_unknown_fields`; names validated; the kubeconfig path cannot be changed by the client; no shelling out | input tests |
| Unauthorised HTTP access, DNS rebinding, CSRF (`--transport http`) | Bearer auth on `/mcp` (TokenReview, or a static token compared in constant time); TokenReview checks `--auth-audience` (the chart requires `k8s-mcp`, so default pod tokens do not work) and `--allowed-callers` (403, audited); `--auth none` refused unless the listen address is loopback; `Host` allow-list (loopback by default); any `Origin` not in `--allowed-origins` gets 403 (none by default, no CORS); 1 MiB request body cap; TLS terminates at an ingress or mesh | `http` unit tests (401, 403, TokenReview, loopback check), kind smoke test |
| stdin hijack by exec plugins | Exec plugins get no stdin and run as `interactiveMode: Never`; `Always` is refused | `cluster` and `exec` unit tests |
| Stalled exec plugins | k8s-mcp runs exec plugins itself, kills them and their process group after 20 s and runs one per context at a time (ADR 0014) | `exec` unit tests, stdio test |

## Redaction levels

- `standard` (default): sensitive env names (`password`, `token`, `secret`, `api_key`, ...)
  are masked; values matching AWS keys, JWTs, bearer tokens, PEM keys, URL credentials, GCP
  service-account keys, Azure connection strings, GitHub/GitLab/Slack tokens and
  `password=`-style pairs are masked everywhere; `last-applied-configuration` is stripped.
- `strict`: also ConfigMap values (sizes only), IP addresses and email addresses.
- `off`: no redaction except Secret values; every response carries a warning.

## Audit log

One JSON line per tool call (timestamp, session, client, HTTP caller, tool, tier, context,
namespace, redacted args, result, findings, bytes, truncated, duration, server version) at
`$XDG_STATE_HOME/k8s-mcp/audit.jsonl` (`~/Library/Application Support/k8s-mcp/` on macOS),
mode `0600`, rotated at 10 MB with 5 files kept. In-cluster it goes to stderr.
`--audit-log off` logs a warning at startup.
