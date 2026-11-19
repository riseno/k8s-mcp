# Security review (v1.0)

A review of the code against the [threat model](security.md), done for 1.0.0: each area below
was checked in the code with file-level evidence, by a reviewer reading the code independently
of the docs, and the parsers were fuzzed with property tests. Findings were fixed in the same
change unless listed as accepted. The external sign-off is recorded at the end.

## Checklist

| # | Area | Result | Evidence |
|---|---|---|---|
| 1 | Input validation | Meets | Every tool input has `deny_unknown_fields`; names and namespaces are validated before they reach an API path (`common::check_name`, `check_namespace_name`); `grep` uses the linear-time `regex` crate with a 1 MiB program limit; `tail`, `limit` and `max_pods` out of range are refused, not clamped; provider `grep` is 1–200 printable characters and quoted in every query |
| 2 | Prompt injection | Meets (after fixes) | Untrusted blocks cannot be opened or closed by cluster text (property test). Fixed: evidence from `spec` and `related` (commands, images, annotations) is now wrapped like `status`/`event`/`log`; `list_resources` and `list_events` rows are marked untrusted as a whole; a custom resource's free-text `status.phase` no longer reaches summaries |
| 3 | Redaction | Meets (after fixes) | Levels as documented; Secret values are masked at every level. Fixed: multi-line Secret values in logs are masked line by line; `--redact off` no longer unmasks `confirm_token` in the audit log. Cloud provider logs get pattern redaction only (documented) |
| 4 | Secrets | Meets | `sanitize_secret` in every object view, Secrets forced to the YAML view, key counts only in rows; Helm release Secrets read as metadata only; rollout diffs show env names only; `apply_manifest` refuses Secrets; values are read only to mask them |
| 5 | Scoping | Meets | The context allow-list is enforced when a target is resolved; namespace policy before every call and on cluster-wide results; write-deny namespaces; node writes refused under `--namespaces`, drains under `--deny-namespaces`; control-plane logs refused while namespaces are restricted |
| 6 | Outbound requests (SSRF) | Meets (after fix) | AKS `nextLink` only on the ARM host. Fixed: an ARM resource id from a response must be an ARM path, so it cannot send the bearer token to another host. EKS and GKE follow no URLs from responses |
| 7 | Resource limits | Meets (after fixes) | 20 s API and 30 s call timeouts, 8 concurrent calls, output cap, 256 KiB / 20-object manifests, YAML alias bombs refused. Fixed: each container log read is capped at 8 MiB (`limitBytes`). Exec plugin output is read in full (accepted) |
| 8 | Write tier | Meets (after fixes) | Only the confirm gate yields a non-dry-run mode; every write tool goes through it; the token binds tool, args, context and resourceVersions, 120 s; no-retry writer. Fixed: rollback plans list every changed field and refuse identical templates, and the token binds the source ReplicaSet; `apply_manifest` sends the live resourceVersion as a precondition and refuses the RBAC, admission, CRD and aggregated-API groups whole |
| 9 | HTTP transport | Meets (after fix), one open item | Auth modes enforced (`none` loopback-only), audience checked, refused callers get 403 and are audited, Host and Origin checks, 1 MiB bodies. Fixed: a blank `--allowed-callers` no longer satisfies the HTTP write requirement. Open: finding 1 |
| 10 | Exec plugins | Meets | Env passed as configured, no stdin, `interactiveMode: Always` refused, killed with its process group at the deadline, output never quoted in errors, apiVersion checked, credentials cached per context |
| 11 | Supply chain | Partial (accepted) | `cargo deny` (advisories, licences, sources; openssl and aws-lc banned); cosign-signed image, chart and checksums with provenance and SBOMs; distroless nonroot image. Actions pinned to tags, not SHAs |
| 12 | Audit log | Meets (after fix) | Every tool call recorded, errors and refused callers included; 10 MB rotation, 5 kept; sensitive args masked at every level. Fixed: an existing file is narrowed to `0600` on open |

## Findings

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | With the chart's default `auth.allowedCallers: []`, anyone who may create pods (or tokens) for a ServiceAccount can mint a token with the `k8s-mcp` audience and use the server's cluster-wide read access | Medium | Open: decision on the chart default pending |
| 2 | Cluster text without untrusted markers: custom resource status in summaries, `list_resources` rows, event columns other than `message`, spec and related evidence quoting annotations | Medium | Fixed |
| 3 | Rollback plans could hide changes: the identical-template refusal never triggered, the summary left out fields such as `securityContext`, and the token did not bind the source ReplicaSet | Medium | Fixed |
| 4 | Log reads had no byte limit | Low–medium | Fixed (8 MiB per read) |
| 5 | A blank `--allowed-callers` satisfied the HTTP write requirement while letting everyone in | Low | Fixed |
| 6 | `--redact off` wrote `confirm_token` and secret-named arguments to the audit log | Low | Fixed |
| 7 | `apply_manifest` had no resourceVersion precondition | Low | Fixed |
| 8 | `apply_manifest` refused kinds, not groups (`APIService` was allowed) | Low | Fixed; policy engines' own kinds are left to RBAC (documented) |
| 9 | AKS `arm_get` joined a resource id from a response to the ARM host, so `@host/...` could send the token elsewhere | Low | Fixed |
| 10 | Failed TokenReviews are not cached or rate-limited | Low | Accepted (API server flow control) |
| 11 | Audit file mode set only at creation; a failed audit write lets the call proceed | Low | Mode fixed; proceeding accepted |
| 12 | Exec plugin output read without a limit | Low | Accepted (the user's own plugin) |
| 13 | Actions pinned to tags, image base to a tag | Low | Accepted for 1.0 |
| 14 | Multi-line Secret values in logs were masked only as a whole (found by the property tests) | Medium | Fixed |

## Fuzzing

Property tests (`proptest`, in the regular test suite) run every parser on arbitrary input and
check it neither panics nor breaks its guarantee:

- durations, CPU and memory quantities, Kubernetes versions;
- `FailedScheduling` messages and kubelet container messages;
- the `apiserver_requested_deprecated_apis` metric;
- exec plugin output (ExecCredential);
- manifests;
- label selectors;
- log shaping (tail cap; no Secret value shown);
- truncation, control-character escaping, untrusted blocks (no text opens or closes one);
- every pod rule on arbitrary container states, events and log lines;
- confirm tokens and redaction (since v0.4 and v0.1).

## Sign-off

- Code review and fixes: done for 1.0.0.
- External sign-off: pending.
