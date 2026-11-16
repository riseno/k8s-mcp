# 24 Invalid image name

The image reference has upper-case letters in the repository, so the kubelet refuses it
(`InvalidImageName`) before any pull.

Expected: `pod.image.invalid_name`, not a missing image or an auth problem.
