# ADR 0004: defer the moka list cache and empty provider crates

- Status: accepted (v0.1)
- Date: 2026-11-14

## Decision
- v0.1 caches API discovery per context (5 min TTL) with a std `Mutex<HashMap>`. The 10 s
  list cache from §7.8 is deferred: every v0.1 tool issues a handful of reads and the
  cache's invalidation rules only matter once writes exist (v0.4). `moka` is not added yet.
- `k8s-mcp-provider` and `k8s-mcp-provider-{eks,gke,aks}` are created in v0.2 together with
  their first implementation instead of as empty v0.1 scaffolding.

## Revisit when
Latency measurements on kind or real clusters show repeated identical list calls, or when
v0.2 work starts.
