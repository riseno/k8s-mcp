# 12 Unbound PVC

A Pod mounts the PVC `data`, whose StorageClass `does-not-exist` does not exist.

Observed:
- `FailedScheduling`: `0/1 nodes are available: pod has unbound immediate PersistentVolumeClaims. not found`.
  The trailing ` not found` is real scheduler output.
- The PVC has `ProvisioningFailed` events: `storageclass.storage.k8s.io "does-not-exist" not found`.

Expected: `pod.pending.pvc_unbound`, naming the PVC and pointing at the missing StorageClass.
