# 11 nodeSelector mismatch

A Pod has `nodeSelector: {disktype: ssd}`, and no node has that label.

Observed: `PodScheduled=False reason=Unschedulable`, and a `FailedScheduling` event
`0/1 nodes are available: 1 node(s) didn't match Pod's node affinity/selector. preemption: ... 1 Preemption is not helpful for scheduling.`

Expected: `pod.pending.node_selector_affinity`, showing the unmatched label.
