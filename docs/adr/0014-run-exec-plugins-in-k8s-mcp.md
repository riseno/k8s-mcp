# ADR 0014: k8s-mcp runs kubeconfig exec plugins itself

- Status: accepted (v0.3.3; process groups, credential checks and reuse in v0.3.4)
- Date: 2026-11-17

## Context
kube-client runs a kubeconfig exec auth plugin inside `Client::try_from`, and again on token
refresh, with a blocking `std::process::Command::output` and no deadline. In 0.3.2 the client
was built on a blocking thread with a 20 s timeout (#73), so the call failed on time, but the
plugin process could not be killed: kube-client owns it. Every retry started another one, and
they outlived the server (#84). kube-client's credential types are private, and its exec errors
format the command's environment and the plugin's output (#74).

## Decision
- `k8s-mcp-core::exec` runs the plugin with `tokio::process`, following the client-go contract:
  its `args` and `env`, `drop_env`, `KUBERNETES_EXEC_INFO` (`interactive: false`, the cluster
  when `provideClusterInfo` is set), stdin and stderr closed, and an ExecCredential (JSON or
  YAML) read from stdout, which must have `kind: ExecCredential` and the `apiVersion` the
  kubeconfig asks for. `interactiveMode: Always` is refused before the plugin runs, because the
  server has no terminal. On Unix the plugin runs in its own process group, and when the 20 s
  deadline or a cancelled call drops the future, the group is killed (`rustix`, approved
  2026-11-17), wrappers' children included; elsewhere `kill_on_drop` kills the plugin itself.
- The credential replaces the exec section of the context's `AuthInfo` (a token, or a client
  certificate and key as base64 `*-data`), so kube-client never runs the plugin itself.
- `ClusterManager` caches each client until two minutes before its credential expires (half
  the lifetime for short-lived ones), and at least 30 s, one call, even when the plugin returns
  an expired credential (a clock ahead of the issuer's, which is logged).
- One client build per context at a time: calls that waited reuse its client or its error
  instead of starting another plugin.

## Consequences
This is the one place the server runs a command, and it is the command the kubeconfig names,
as kube-client would. A plugin's own children are killed on Unix only (a Windows Job Object
needs unsafe APIs). Processes a plugin leaves behind after it exits are left alone, as with
client-go. The legacy `auth-provider` (`gcp` `cmd-path`) is still run by kube-client.
