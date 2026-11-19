#!/usr/bin/env bash
# Smoke test of an installed k8s-mcp chart: probes, 401/403, and a TokenReview-authenticated
# client that lists tools and runs diagnose_pod; the audit log must name the caller and never
# the token. A token without the chart's audience (k8s-mcp) must get 401, and one with it for a
# ServiceAccount not in auth.allowedCallers 403. The release must allow
# system:serviceaccount:default:mcp-caller. Only kind and k3d clusters are allowed.
#
# With WRITES=1 (a release with writes.enabled and the caller below in auth.allowedCallers), the
# client also plans and confirms a restart of a scratch Deployment through the chart's write
# ClusterRole; otherwise it checks that no write tool is registered.
#
# Usage: [WRITES=1] deploy/helm/smoke.sh <kubeconfig> <context> <namespace> <release>
set -euo pipefail
KC=$1 CTX=$2 NS=$3 REL=$4
case "$CTX" in kind-* | k3d-*) ;; *) echo "refusing context $CTX: only kind-* and k3d-* clusters" >&2; exit 2 ;; esac
k() { kubectl --kubeconfig "$KC" --context "$CTX" "$@"; }

k create serviceaccount mcp-caller -n default --dry-run=client -o yaml | k apply -f - >/dev/null
TOKEN=$(k create token mcp-caller -n default --duration 10m --audience k8s-mcp)
DEFAULT_TOKEN=$(k create token mcp-caller -n default --duration 10m)
k create serviceaccount mcp-stranger -n default --dry-run=client -o yaml | k apply -f - >/dev/null
STRANGER_TOKEN=$(k create token mcp-stranger -n default --duration 10m --audience k8s-mcp)
PORT=18081
k -n "$NS" port-forward "svc/$REL" "$PORT:8080" >/dev/null 2>&1 &
PF=$!
trap 'kill $PF 2>/dev/null || true' EXIT
URL=http://127.0.0.1:$PORT
for _ in $(seq 1 50); do curl -sf -o /dev/null "$URL/healthz" && break; sleep 0.2; done

fail=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: expected $2, got $3"; fail=1; fi
}
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
H=(-H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream')
A=(-H "Authorization: Bearer $TOKEN")
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"chart-smoke","version":"1"}}}'
# The JSON-RPC message of a response (the last SSE data line).
rpc() { curl -s "${H[@]}" "${A[@]}" -H "Mcp-Session-Id: $SID" -d "$1" "$URL/mcp" | sed -n 's/^data: //p' | grep . | tail -1 || true; }

check "/healthz" 200 "$(code "$URL/healthz")"
check "/readyz" 200 "$(code "$URL/readyz")"
check "no token -> 401" 401 "$(code "${H[@]}" -d "$INIT" "$URL/mcp")"
check "bad token -> 401" 401 "$(code "${H[@]}" -H 'Authorization: Bearer nope' -d "$INIT" "$URL/mcp")"
check "API-server-audience token -> 401" 401 "$(code "${H[@]}" -H "Authorization: Bearer $DEFAULT_TOKEN" -d "$INIT" "$URL/mcp")"
check "caller not in allowedCallers -> 403" 403 "$(code "${H[@]}" -H "Authorization: Bearer $STRANGER_TOKEN" -d "$INIT" "$URL/mcp")"
check "bad Origin -> 403" 403 "$(code "${H[@]}" "${A[@]}" -H 'Origin: https://evil.example' -d "$INIT" "$URL/mcp")"
SID=$(curl -s -D - -o /dev/null "${H[@]}" "${A[@]}" -d "$INIT" "$URL/mcp" | tr -d '\r' | awk -F': ' 'tolower($1)=="mcp-session-id"{print $2}')
check "session" yes "${SID:+yes}"
curl -s -o /dev/null "${H[@]}" "${A[@]}" -H "Mcp-Session-Id: $SID" -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$URL/mcp"
check "tools/list has diagnose_pod" true "$(rpc '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | jq '[.result.tools[].name] | index("diagnose_pod") != null')"
HAS_WRITE=$(rpc '{"jsonrpc":"2.0","id":4,"method":"tools/list"}' | jq '[.result.tools[].name] | index("restart_workload") != null')
if [ "${WRITES:-0}" = 1 ]; then
  check "tools/list has restart_workload" true "$HAS_WRITE"
  k create namespace smoke-writes --dry-run=client -o yaml | k apply -f - >/dev/null
  k -n smoke-writes create deployment web --image=busybox:1.36 --dry-run=client -o yaml -- sleep 3600 | k apply -f - >/dev/null
  k -n smoke-writes rollout status deploy/web --timeout=120s >/dev/null
  GEN=$(k -n smoke-writes get deploy web -o jsonpath='{.metadata.generation}')
  P=$(rpc '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"restart_workload","arguments":{"kind":"Deployment","name":"web","namespace":"smoke-writes"}}}')
  check "restart plan" false "$(jq '.result.isError' <<<"$P")"
  check "plan changed nothing" "$GEN" "$(k -n smoke-writes get deploy web -o jsonpath='{.metadata.generation}')"
  CONFIRM=$(jq -c '.result.structuredContent.next[0].args' <<<"$P")
  C=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"restart_workload\",\"arguments\":$CONFIRM}}")
  check "restart confirmed" false "$(jq '.result.isError' <<<"$C")"
  check "generation after confirm" "$((GEN + 1))" "$(k -n smoke-writes get deploy web -o jsonpath='{.metadata.generation}')"
else
  check "no write tools by default" false "$HAS_WRITE"
fi
POD=$(k -n "$NS" get pod -l "app.kubernetes.io/instance=$REL" -o jsonpath='{.items[0].metadata.name}')
R=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"diagnose_pod\",\"arguments\":{\"namespace\":\"$NS\",\"name\":\"$POD\"}}}")
check "diagnose_pod" false "$(jq '.result.isError' <<<"$R")"
echo "     $(jq -r '.result.structuredContent.summary' <<<"$R" | cut -c1-120)"
sleep 1
LOGS=$(k -n "$NS" logs "deploy/$REL")
check "audit caller" found "$(grep -q -F '"caller":"system:serviceaccount:default:mcp-caller"' <<<"$LOGS" && echo found || echo missing)"
check "token in pod log" 0 "$(grep -c -F -e "$TOKEN" -e "$DEFAULT_TOKEN" -e "$STRANGER_TOKEN" <<<"$LOGS" || true)"
if [ "${WRITES:-0}" = 1 ]; then
  check "audit: restart plan and confirm" 2 "$(grep -F '"tool":"restart_workload"' <<<"$LOGS" | grep -c -e '"dry_run":true' -e '"dry_run":false' || true)"
  k delete namespace smoke-writes --wait=false >/dev/null
fi
exit $fail
