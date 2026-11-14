# 05 OOMKilled

A Python Pod with a 32Mi memory limit writes 256 MiB.

Observed: `lastState.terminated` `reason: OOMKilled`, `exitCode: 137`, then `CrashLoopBackOff`. There are no
OOM-specific events (only `BackOff`) and no log output.

Expected: `pod.oom.container`, quoting the 32Mi limit. Do not report `pod.crashloop.sigkill`: the exit code is
137 because of the OOM kill.
