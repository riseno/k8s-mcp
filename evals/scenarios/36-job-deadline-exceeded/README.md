# 36 Job deadline exceeded

The Job's pod runs fine but the Job allows `activeDeadlineSeconds: 10`, so the controller
terminates it and marks the Job `Failed` with reason `DeadlineExceeded`.

Expected: `job.deadline_exceeded`, not `job.backoff_limit`.
