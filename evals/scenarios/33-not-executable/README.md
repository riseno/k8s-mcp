# 33 Command not executable

The container's command is a file without the execute bit, so the runtime fails to start it
(`exec: "/etc/passwd": permission denied`, reason `StartError`, exit code 128).

Expected: `pod.crashloop.not_executable`.
