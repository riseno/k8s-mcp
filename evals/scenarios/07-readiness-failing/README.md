# 07 Readiness probe failing

An nginx Deployment has a readiness probe on `/healthz`, which nginx answers with 404.

Observed: the pod is `Running`, `ready: false`, `restartCount: 0`. `Unhealthy` events say
`Readiness probe failed: HTTP probe failed with statuscode: 404`, after one early `connect: connection refused`
before nginx was listening.

Expected: `pod.probe.readiness_failing`.
