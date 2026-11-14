# 14 ResourceQuota exceeded

A ResourceQuota caps `requests.cpu` at 250m, and a Deployment with 2 replicas requests 200m per pod. The first pod
runs. The second is never created.

Observed:
- The Deployment has `availableReplicas: 1` and the condition `ReplicaFailure=True reason=FailedCreate`.
- The ReplicaSet gets `FailedCreate` events: `Error creating: pods "web-..." is forbidden: exceeded quota: compute,
  requested: requests.cpu=200m, used: requests.cpu=200m, limited: requests.cpu=250m`.
- After about 10 repeats, the event recorder aggregates them, and the message gains the prefix
  `(combined from similar events): `.

Expected: `pod.pending.quota`, showing used/hard. `workload.replicas.unavailable` and `workload.create_failed`
(the generic FailedCreate rule) are acceptable in the top 3. No Pod object exists for the missing replica, so the
finding must come from the ReplicaSet events or the Deployment condition.
