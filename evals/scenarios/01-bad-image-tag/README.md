# 01 Bad image tag

A Pod runs `nginx:doesnotexist`, a tag that is not in the repository.

Observed on kind (Kubernetes 1.37, containerd 2.3): `waiting.reason: ImagePullBackOff`, and a `Failed` event
`Failed to pull image "nginx:doesnotexist": rpc error: code = NotFound desc = ... docker.io/library/nginx:doesnotexist: not found`.

Expected: `pod.image.not_found`, naming the exact image reference.
