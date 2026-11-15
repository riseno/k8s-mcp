# 16 Service targetPort does not match the container port

nginx declares and listens on port 80; the Service's `targetPort` is 8080.

Observed: the pod is `Running` and Ready, the Service has an endpoint, and connections are
refused.

Expected: `svc.target_port_mismatch` (medium confidence: declared container ports are
informational, so the rule cannot prove what the app listens on).
