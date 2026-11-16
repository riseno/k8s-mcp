# 27 HPA cannot compute its metric

The HPA targets 70% CPU utilization, but the Deployment's container has no CPU request, so
the controller reports `FailedGetResourceMetric` and `ScalingActive=False`.

Expected: `autoscaling.hpa.not_scaling`, quoting the controller's reason.
