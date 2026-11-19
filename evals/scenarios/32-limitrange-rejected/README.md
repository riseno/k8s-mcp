# 32 Rejected by a LimitRange

A LimitRange caps containers at 500m CPU and the template's limit is 1 CPU, so every create
fails (`maximum cpu usage per Container is 500m, but limit is 1`).

Expected: `workload.create_failed` titled "pods violate the namespace's LimitRange".
