# 35 Topology spread cannot be satisfied

The pod must spread across `topology.kubernetes.io/zone` with `whenUnsatisfiable:
DoNotSchedule`, but the kind node has no zone label, so the scheduler reports `didn't match
pod topology spread constraints (missing required label)`.

Expected: `pod.pending.topology_spread`, with evidence that the nodes lack the label.
