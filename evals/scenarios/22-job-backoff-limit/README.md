# 22 Job reached its backoff limit

A Job whose pod exits 2 with `backoffLimit: 1` fails after two attempts
(`BackoffLimitExceeded`).

Expected: `job.backoff_limit`; the pods' app error is acceptable.
