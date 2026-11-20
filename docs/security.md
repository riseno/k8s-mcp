# Security and threat model

This page summarises the threat model: what is enforced and how it is tested. The v1.0
review of the code against it is in [security-review.md](security-review.md).

| Threat | Mitigation | Test |
|---|---|---|
| Prompt injection via cluster content | Read-only unless `--allow-write`. Cluster text is delimited, neutralised and capped: every finding's evidence (except k8s-mcp's own `unavailable` notes), the rows of `list_resources` and `list_events`, and log, event and object sections; a custom resource's status is shown only as one short word. Server instructions and tool descriptions say it is data. With writes on, an injected instruction can still lead the model to plan a change: the confirm token proves a plan was made for exactly that change, not that a person approved it, so approval rests on the client asking before destructive tool calls (`destructiveHint`) | `envelope`/`text` unit tests and property tests (no text can open or close a block), `list_events` golden test, `free_text_status_is_not_shown` |
| Secret exfiltration | Secret values are never returned (keys and sizes only) in any mode, including `--redact off`; in pod logs, values of the Secrets the pod uses are masked when k8s-mcp may read them, line by line for multi-line values (otherwise the summary warns); env/ConfigMap/annotation/log/audit redaction. Cloud provider logs (`eks_logs`, `gke_logs`, `aks_logs`) get pattern redaction only: no pod's Secrets are known for them | `secrets_never_show_values_in_any_view`, redaction corpus (0 false negatives), `shaped_logs_are_capped_and_never_show_secret_values` (property test), kind canary test |
| Excessive privilege | Tool surface is read-only unless `--allow-write`; `check_permissions` and `doctor` warn about `*` on `*` | kind tests |
| Writes going wrong (T10) | Write tools only with `--allow-write`; every change is a `dryRun=All` plan first and needs its confirm token (HMAC over tool, args, context and each object's state without its status, 120 s, per process); resourceVersion/UID preconditions; no automatic retries; `--write-deny-namespaces` (default `kube-system,kube-public,kube-node-lease`); PodDisruptionBudget-respecting evictions; unowned pods refused; `rollback_workload` lists every changed field and binds the source ReplicaSet; `apply_manifest` is never forced, carries each live object's resourceVersion, and refuses Secrets and the RBAC, admission, CRD and aggregated-API groups; over HTTP only `--allowed-callers`, which must name someone ([writes.md](writes.md)) | `tests/write.rs` (every tool sends only dry runs without its token), the kind test against the API server's audit log, the chart smoke test |
| Context hopping | Only the default context unless `--contexts`; every response names its context | `cluster` unit tests, stdio test |
| Namespace escape | `--namespaces`/`--deny-namespaces` checked before every call and applied to cluster-wide results | per-tool namespace policy test |
| Resource exhaustion | List limits, log caps (8 MiB read per container log, then line caps), output cap, 256 KiB / 20-object manifests, YAML alias bombs refused, 20 s API timeout, 30 s call timeout, 8 concurrent calls, client cancellation | envelope `fit` tests, `alias_bombs_are_refused`, log `limitBytes` mock test |
| Credential leakage by the server | Kubeconfig never written or shown; exec plugin output never echoed; errors and audit args redacted; no telemetry | stdio tests |
| Malicious arguments | Typed inputs with `deny_unknown_fields`; names validated; the kubeconfig path cannot be changed by the client; no shelling out | input tests |
| Unauthorised HTTP access, DNS rebinding, CSRF (`--transport http`) | Bearer auth on `/mcp` (TokenReview, or a static token compared in constant time); TokenReview checks `--auth-audience` (the chart sets `k8s-mcp`, so default pod tokens do not work; anyone who may create pods or tokens for a ServiceAccount can still mint one with that audience, so the chart requires `auth.allowedCallers` unless `auth.allowAnyCaller` is set) and `--allowed-callers` (403, audited); `--auth none` refused unless the listen address is loopback; `Host` allow-list (loopback by default); any `Origin` not in `--allowed-origins` gets 403 (none by default, no CORS); 1 MiB request body cap; TLS terminates at an ingress or mesh | `http` unit tests (401, 403, TokenReview, loopback check), kind smoke test |
| Cloud credentials sent to another host (providers) | AKS: `nextLink` is followed only on the ARM host and resource ids from ARM responses must be ARM paths; EKS and GKE use their SDKs' endpoints and follow no URLs from responses | `foreign_next_links_are_not_followed`, `foreign_resource_ids_are_not_fetched` |
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
`--audit-log off` logs a warning at startup. A `confirm_token` and any argument under a
sensitive name are masked at every redaction level, `--redact off` included. An existing file
is narrowed to `0600` when it is opened.

## Known limits

Accepted after the v1.0 review; each is low severity:

- A failed audit write is logged to stderr and the call proceeds (availability over a hard stop).
- Resource reads of `k8s-mcp://policy` and `k8s-mcp://contexts` and prompt fetches are not
  audited: they return only k8s-mcp's own configuration.
- Failed TokenReviews are not cached or rate-limited: each request with a bad token makes one
  TokenReview call, which the API server's own flow control limits.
- An exec plugin's output is read in full: the plugin is a program the user's kubeconfig names,
  trusted as `kubectl` trusts it.
- GitHub Actions are pinned to release tags, not commit SHAs, and the image base to a tag.
