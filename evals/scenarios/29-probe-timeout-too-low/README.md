# 29 Probe timeout too low

The readiness check succeeds, but takes 3s against the default `timeoutSeconds: 1`, so every
probe times out (`command timed out`) and the pod is never Ready.

Expected: `pod.probe.timeout_too_low`.
