# 02 Private image without a pull secret

A Pod pulls a Docker Hub repository that anonymous clients cannot read. Neither the Pod nor its
ServiceAccount has `imagePullSecrets`.

Observed: `waiting.reason: ImagePullBackOff`, and a `Failed` event `... pull access denied, repository does not
exist or may require authorization: server message: insufficient_scope: authorization failed`. Docker Hub
does not say whether the repository is private or missing, so `pod.image.not_found` is acceptable in the top 3.
For comparison, ghcr.io answers the same request with `failed to authorize: failed to fetch anonymous
token: ... 403 Forbidden` (see `fixtures/messages/image-auth-ghcr-403.yaml`).

Expected: `pod.image.auth`, pointing at the missing `imagePullSecrets`.
