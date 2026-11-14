# 09 Missing Secret key

A Deployment reads `DB_PASSWORD` from key `password` of the Secret `db-credentials`, which has only `username`.

Observed: `waiting.reason: CreateContainerConfigError` with the message
`couldn't find key password in Secret eval-missing-secret-key/db-credentials`, repeated as `Failed` events
(`Error: couldn't find key ...`).

Expected: `pod.config.missing_key`. The Secret exists, so `pod.config.missing_secret` is a misdiagnosis.
