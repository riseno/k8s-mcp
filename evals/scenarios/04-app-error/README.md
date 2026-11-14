# 04 App exits 1 with a stack trace

A Deployment runs a Python one-liner that raises `ConnectionError` while connecting to its database.

Observed: `lastState.terminated` `reason: Error`, `exitCode: 1`, then `CrashLoopBackOff`. The log ends with a Python
traceback and `ConnectionError: could not connect to database at postgres://...`.

Between restarts, Kubernetes 1.37 leaves the container in `state.terminated` (STATUS `Error`) for up to a
minute before it reports `waiting: CrashLoopBackOff`. In that window `previous=true` logs fail ("unable to
retrieve container logs") and the current logs hold the traceback. See
`fixtures/messages/04-app-error-terminated-window.yaml`.

Expected: `pod.crashloop.app_error`, quoting the error lines from the logs.
