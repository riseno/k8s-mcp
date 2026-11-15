# 13 Exit 0 with restartPolicy Always

A one-shot command (`echo migrations applied`) runs in a bare Pod with `restartPolicy: Always`.

Observed: `lastState.terminated` `reason: Completed`, `exitCode: 0`, then `CrashLoopBackOff`. The previous log is
`migrations applied`.

Expected: `pod.crashloop.exit_zero`, suggesting a Job or a foreground process.
