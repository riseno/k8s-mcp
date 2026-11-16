# 20 PodDisruptionBudget blocks node drains (upgrade readiness)

A one-replica Deployment is covered by a PodDisruptionBudget with `minAvailable: 1`, so the
eviction API never allows a disruption.

Expected: `upgrade.pdb_blocks_drain`; the single replica and any deprecated API the cluster's
metric reports are acceptable.
