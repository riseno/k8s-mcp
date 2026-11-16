# 23 Service without ready endpoints

The Service selects two running pods, but their readiness probe fails, so the EndpointSlices
list no ready endpoint.

Expected: `svc.no_ready_endpoints` (the selector and target port are right); the pods'
readiness failure is acceptable.
