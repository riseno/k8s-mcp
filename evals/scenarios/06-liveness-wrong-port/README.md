# 06 Liveness probe on the wrong port

An nginx Deployment listens on 80, but its liveness probe checks 8080 every 2 seconds (failureThreshold 2).

Observed:
- `Unhealthy` events: `Liveness probe failed: Get "http://10.244.0.13:8080/": dial tcp ...:8080: connect: connection refused`.
- `Killing` events: `Container frontend failed liveness probe, will be restarted`.
- nginx exits cleanly on the stop signal, so `lastState.terminated` is `reason: Completed`, `exitCode: 0`, and the
  pod goes into `CrashLoopBackOff`.

Expected: `pod.probe.port_mismatch` (8080 is not a declared containerPort). `pod.probe.liveness_failing` is
acceptable. Exit 0 or SIGTERM findings are misdiagnoses.
