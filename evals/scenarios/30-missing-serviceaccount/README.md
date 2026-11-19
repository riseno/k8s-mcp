# 30 Missing ServiceAccount

The Deployment's pods run as ServiceAccount `build-bot`, which does not exist, so the
ReplicaSet's creates fail (`FailedCreate ... serviceaccount "build-bot" not found`) and no pod
exists to diagnose.

Expected: `pod.config.missing_serviceaccount`, from the ReplicaSet's event.
