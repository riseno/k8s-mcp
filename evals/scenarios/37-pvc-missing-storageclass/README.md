# 37 Missing StorageClass

The claim asks for StorageClass `fast-ssd`, which does not exist on kind (only `standard`), so
no provisioner acts on it and it stays Pending.

Expected: `pvc.pending.no_storageclass`, listing the StorageClasses that do exist.
