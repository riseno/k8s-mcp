# ADR 0009: mask the values of a pod's Secrets in its logs

- Status: accepted (v0.1.3)
- Date: 2026-11-15

## Context
Redaction is pattern-based, so a credential logged without a keyword in front of it passes:
an application that prints the value of a Secret it receives through `secretKeyRef` leaked
that value through `get_logs` and `diagnose_pod`, contradicting "Secret values are never
returned" (riseno/k8s-mcp#25).

## Decision
Before shaping a container's log, read the Secrets the pod references (`env[].valueFrom.
secretKeyRef`, `envFrom[].secretRef`, `volumes[].secret`, projected secrets,
`imagePullSecrets`) and mask exact occurrences of their values (6 characters or longer) as
`«redacted»`. This applies at every redaction level, including `--redact off`. The values are
held in memory for the call only and never returned, logged or audited. `diagnose_pod` reuses
the Secret reads it already makes for existence checks.

If RBAC forbids reading a Secret (as with the read-only ClusterRole in PROPOSAL Appendix C),
the response says so under UNAVAILABLE EVIDENCE and only pattern redaction applies.

## Consequences
- `get_logs` makes up to 20 extra GETs per pod for its Secrets.
- Identities that may read Secrets get stronger log redaction; the read-only ClusterRole keeps
  working with pattern redaction and a visible note.
- Values derived from a Secret (base64 forms, substrings) are not matched.
