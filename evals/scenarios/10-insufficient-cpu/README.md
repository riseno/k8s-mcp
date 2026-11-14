# 10 Insufficient CPU

A Pod requests 64 CPUs, more than any node has.

Observed: `PodScheduled=False reason=Unschedulable`, and a `FailedScheduling` event
`0/1 nodes are available: 1 Insufficient cpu. preemption: 0/1 nodes are available: 1 Preemption is not helpful for scheduling.`

Expected: `pod.pending.insufficient_resources`. Ideally it also says that the request is larger than any node's
allocatable, so the pod can never fit.
