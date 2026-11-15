# 18 The autoscaler cannot scale up

A pod requests 64 CPUs. With the Cluster Autoscaler, the only node group is at its maximum
size, so CA reports `NotTriggerScaleUp: 1 max node group size reached`. kind has no
autoscaler, so the manifest applies that event; the CA status ConfigMap and Karpenter
NodePool cases are covered by rule fixtures (`fixtures/autoscaling/`).

Expected: `autoscaling.ca.not_triggered`, telling to raise the node group's maximum size.
