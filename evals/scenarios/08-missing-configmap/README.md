# 08 Missing ConfigMap

A Pod reads `LOG_LEVEL` through `configMapKeyRef` from `billing-config`, which does not exist.

Observed: `waiting.reason: CreateContainerConfigError` with the message `configmap "billing-config" not found`, and
`Failed` events `Error: configmap "billing-config" not found`.

Expected: `pod.config.missing_configmap`, naming `billing-config` and the env var that references it.
