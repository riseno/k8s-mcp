//! Kubeconfig exec auth plugins, run here instead of by kube-client so that a plugin which
//! stalls is killed at the deadline (riseno/k8s-mcp#73, #84). Same contract as client-go and
//! kube-client: the plugin gets its args, its `env`, `KUBERNETES_EXEC_INFO` and no terminal, and
//! prints an ExecCredential (JSON or YAML) on stdout.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use jiff::Timestamp;
use kube::config::{AuthInfo, ExecConfig};
use serde::Deserialize;

/// Budget for a plugin to print its credential.
pub(crate) const EXEC_TIMEOUT: Duration = Duration::from_secs(20);

pub(crate) const RUN_IT: &str =
    "Run the plugin command yourself to see its error, re-authenticate if needed, then retry.";
pub(crate) const INSTALL_IT: &str = "Is it installed and on PATH for this MCP client? Install it, or start k8s-mcp with --path-prepend <dir containing it>.";

#[derive(Deserialize)]
struct ExecCredential {
    status: Option<Status>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    token: Option<String>,
    expiration_timestamp: Option<String>,
    client_certificate_data: Option<String>,
    client_key_data: Option<String>,
}

/// Run `auth`'s exec plugin, if it has one, and replace the exec section with the credential
/// it printed. Returns when the credential expires. Errors never quote the plugin's output or
/// environment (#74).
pub(crate) async fn resolve(
    auth: &mut AuthInfo,
    deadline: Duration,
) -> Result<Option<Timestamp>, String> {
    let Some(exec) = auth.exec.take() else {
        return Ok(None);
    };
    let command = exec
        .command
        .clone()
        .ok_or("the kubeconfig's exec section has no command")?;
    let name = Path::new(&command)
        .file_name()
        .map_or_else(|| command.clone(), |f| f.to_string_lossy().into_owned());
    let plugin = |what: &str| format!("the kubeconfig exec auth plugin `{name}` {what}");
    let mut cmd = tokio::process::Command::new(&command);
    cmd.args(exec.args.iter().flatten())
        .envs(
            exec.env
                .iter()
                .flatten()
                .filter_map(|e| Some((e.get("name")?, e.get("value")?))),
        )
        .env("KUBERNETES_EXEC_INFO", exec_info(&exec))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    for var in exec.drop_env.iter().flatten() {
        cmd.env_remove(var);
    }
    let child = cmd
        .spawn()
        .map_err(|e| plugin(&format!("could not be started ({e}). {INSTALL_IT}")))?;
    // On the deadline the future, and with it the child, is dropped: kill_on_drop kills it.
    // ponytail: processes the plugin itself started are not killed (that needs a process-group
    // kill, which needs libc); the plugins in use (aws, gke-gcloud-auth-plugin, kubelogin) are
    // one process.
    let out = tokio::time::timeout(deadline, child.wait_with_output())
        .await
        .map_err(|_| {
            plugin(&format!("did not finish within {}s. Run it yourself to see why (it may be waiting for a login or the network), then retry.", deadline.as_secs()))
        })?
        .map_err(|e| plugin(&format!("could not be read ({e})")))?;
    if !out.status.success() {
        return Err(plugin(&format!("failed ({}). {RUN_IT}", out.status)));
    }
    let status = serde_saphyr::from_slice::<ExecCredential>(&out.stdout)
        .ok()
        .and_then(|c| c.status)
        .ok_or_else(|| {
            plugin(&format!(
                "returned output that is not an ExecCredential. {RUN_IT}"
            ))
        })?;
    let expires = status
        .expiration_timestamp
        .as_deref()
        .map(str::parse::<Timestamp>)
        .transpose()
        .map_err(|_| {
            plugin(&format!(
                "returned a malformed expirationTimestamp. {RUN_IT}"
            ))
        })?;
    // A client certificate wins over a token, as in kube-client.
    match (
        status.client_certificate_data,
        status.client_key_data,
        status.token,
    ) {
        (Some(cert), Some(key), _) => {
            auth.client_certificate_data = Some(base64(cert));
            auth.client_key_data = Some(base64(key).into());
        }
        (_, _, Some(token)) => auth.token = Some(token.into()),
        _ => {
            return Err(plugin(&format!(
                "returned no token or client certificate. {RUN_IT}"
            )));
        }
    }
    Ok(expires)
}

/// `KUBERNETES_EXEC_INFO`: the request, non-interactive, with the cluster when the plugin asks.
fn exec_info(exec: &ExecConfig) -> String {
    let mut spec = serde_json::json!({"interactive": false});
    if exec.provide_cluster_info
        && let Some(cluster) = &exec.cluster
    {
        spec["cluster"] = serde_json::to_value(cluster).unwrap_or_default();
    }
    serde_json::json!({"apiVersion": exec.api_version, "kind": "ExecCredential", "spec": spec})
        .to_string()
}

/// Kubeconfig `*-data` fields hold base64 of the PEM the plugin printed.
fn base64(pem: String) -> String {
    match serde_json::to_value(k8s_openapi::ByteString(pem.into_bytes())) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    /// An `AuthInfo` whose exec plugin is the shell script `body`, run with arg `get-token` and
    /// `env` FROM_ENV=tok-env.
    fn with_plugin(dir: &Path, body: &str) -> AuthInfo {
        let p = dir.join("plugin");
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        AuthInfo {
            exec: Some(ExecConfig {
                api_version: Some("client.authentication.k8s.io/v1beta1".into()),
                command: Some(p.display().to_string()),
                args: Some(vec!["get-token".into()]),
                env: Some(vec![
                    [("name", "FROM_ENV"), ("value", "tok-env")]
                        .map(|(k, v)| (k.to_owned(), v.to_owned()))
                        .into(),
                ]),
                ..ExecConfig::default()
            }),
            ..AuthInfo::default()
        }
    }

    fn json(auth: &AuthInfo) -> serde_json::Value {
        serde_json::to_value(auth).unwrap()
    }

    #[tokio::test]
    async fn the_credential_replaces_the_exec_section() {
        let dir = tempfile::tempdir().unwrap();
        let mut auth = with_plugin(
            dir.path(),
            r#"[ "$1" = get-token ] && [ "$FROM_ENV" = tok-env ] || exit 3
case "$KUBERNETES_EXEC_INFO" in *'"interactive":false'*) ;; *) exit 4 ;; esac
echo '{"kind":"ExecCredential","status":{"token":"tok-123","expirationTimestamp":"2026-11-17T12:00:00Z"}}'"#,
        );
        let expires = resolve(&mut auth, EXEC_TIMEOUT).await.unwrap();
        assert_eq!(expires, Some("2026-11-17T12:00:00Z".parse().unwrap()));
        assert!(auth.exec.is_none());
        assert_eq!(json(&auth)["token"], "tok-123");

        // YAML is accepted, and a client certificate wins over a token.
        let mut auth = with_plugin(
            dir.path(),
            "echo 'status: {token: t, clientCertificateData: CERT, clientKeyData: KEY}'",
        );
        assert_eq!(resolve(&mut auth, EXEC_TIMEOUT).await.unwrap(), None);
        let v = json(&auth);
        assert_eq!(
            (
                v["client-certificate-data"].as_str(),
                v["client-key-data"].as_str()
            ),
            (Some("Q0VSVA=="), Some("S0VZ"))
        );
        assert!(v.get("token").is_none_or(serde_json::Value::is_null), "{v}");
    }

    #[tokio::test]
    async fn failures_never_quote_the_plugin_output() {
        let dir = tempfile::tempdir().unwrap();
        for (body, expected) in [
            (
                "echo TOKEN-1; echo TOKEN-2 >&2; exit 1",
                "failed (exit status: 1)",
            ),
            ("echo 'not json at all TOKEN-1'", "not an ExecCredential"),
            ("echo '{\"status\":{}}'", "no token or client certificate"),
        ] {
            let err = resolve(&mut with_plugin(dir.path(), body), EXEC_TIMEOUT)
                .await
                .unwrap_err();
            assert!(
                err.contains(expected) && !err.contains("TOKEN"),
                "{body}: {err}"
            );
        }
    }

    /// riseno/k8s-mcp#84: the deadline kills the plugin instead of leaving it running.
    #[tokio::test]
    async fn a_stalled_plugin_is_killed_at_the_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let mut auth = with_plugin(
            dir.path(),
            &format!("echo $$ > {}\nexec sleep 30", pidfile.display()),
        );
        let err = resolve(&mut auth, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(err.contains("`plugin` did not finish within 1s"), "{err}");
        let pid = std::fs::read_to_string(&pidfile).unwrap();
        let alive = || {
            std::process::Command::new("kill")
                .args(["-0", pid.trim()])
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        };
        for _ in 0..50 {
            if !alive() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("plugin {} still running after the deadline", pid.trim());
    }
}
