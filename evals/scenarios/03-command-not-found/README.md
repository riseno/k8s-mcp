# 03 Command not found (exit 127)

A busybox Pod runs `sh -c "missing-cmd"`.

Observed: `lastState.terminated` `reason: Error`, `exitCode: 127`, then `CrashLoopBackOff`. The previous log is
`sh: line 0: missing-cmd: not found`.

Expected: `pod.crashloop.command_not_found`.
