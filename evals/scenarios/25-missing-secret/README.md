# 25 Missing Secret

The pod reads an env var from a Secret that does not exist (`CreateContainerConfigError`).

Expected: `pod.config.missing_secret`, naming `stripe-credentials`, not a missing key.
