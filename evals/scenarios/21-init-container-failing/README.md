# 21 Init container failing

The pod's init container exits 1, so the app container never starts (`Init:CrashLoopBackOff`).

Expected: `pod.init.failing`, quoting the init container's error, not a crash loop of the app
container.
