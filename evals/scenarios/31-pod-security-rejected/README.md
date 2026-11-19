# 31 Rejected by Pod Security admission

The namespace enforces the `restricted` Pod Security level and the pod template sets no
securityContext, so every create fails (`violates PodSecurity "restricted:latest"`).

Expected: `workload.create_failed` titled "pods are rejected by Pod Security admission (level
restricted)".
