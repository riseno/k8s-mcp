# 28 Startup probe too short

The container needs 30s to start, but its startup probe allows `failureThreshold × periodSeconds`
= 6s, so the kubelet kills it (`failed startup probe, will be restarted`) before it is ever up.

Expected: `pod.probe.startup_too_short`, not a crash-loop finding: the exit code is the
kubelet's kill, not the app's.
