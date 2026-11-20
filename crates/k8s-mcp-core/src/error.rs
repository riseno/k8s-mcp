//! Errors shown to the model. Every message says what failed, why, and what to do next.

use std::fmt::Display;

use kube::client::AuthError;

use crate::exec::{INSTALL_IT, RUN_IT};

/// Result alias for k8s-mcp operations.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// A user-actionable error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    /// The requested context is outside the allow-list.
    #[error(
        "context {context:?} is not allowed. Allowed contexts: {allowed}. To target it, restart k8s-mcp with --contexts (for example --contexts '{context}')."
    )]
    ContextNotAllowed {
        /// Requested context.
        context: String,
        /// Allowed contexts, comma separated.
        allowed: String,
    },
    /// The namespace is outside the namespace policy.
    #[error(
        "namespace {namespace:?} is not allowed by k8s-mcp policy (allowed: {allowed}). Use an allowed namespace; the policy comes from --namespaces and --deny-namespaces."
    )]
    NamespaceNotAllowed {
        /// Requested namespace.
        namespace: String,
        /// Description of the allowed namespaces.
        allowed: String,
    },
    /// Bad tool arguments.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// The object or kind does not exist.
    #[error("{0}")]
    NotFound(String),
    /// RBAC denied the request.
    #[error("{0}")]
    Forbidden(String),
    /// A capability (such as metrics-server) is not installed.
    #[error("{0}")]
    Unavailable(String),
    /// Kubeconfig or flag problem.
    #[error("configuration error: {0}")]
    Config(String),
    /// The API server cannot be reached, or this context's credentials cannot be obtained or
    /// were rejected: no other request to the context will succeed either.
    #[error("{0}")]
    Unreachable(String),
    /// Any other API failure.
    #[error("{0}")]
    Api(String),
}

impl Error {
    /// Translate a kube error into an actionable message. `what` describes the attempted
    /// action, e.g. `list pods in namespace shop`.
    pub fn kube(what: impl Display, err: &kube::Error) -> Self {
        if let kube::Error::Api(status) = err {
            let msg = &status.message;
            return match status.code {
                403 => Self::Forbidden(format!(
                    "Forbidden: cannot {what}. Ask an admin for the RBAC permission, or call check_permissions to see what this identity can do. (API: {msg})"
                )),
                404 => Self::NotFound(format!(
                    "Not found: cannot {what}: {msg}. Check the name, kind and namespace (list_resources or api_resources can help)."
                )),
                401 => Self::Unreachable(format!(
                    "Unauthorized: cannot {what}: the credentials for this context were rejected or expired. Re-authenticate with your cloud CLI (for example `aws sso login`, `gcloud auth login`, `az login`) and retry."
                )),
                code => Self::Api(format!("cannot {what}: API returned {code}: {msg}")),
            };
        }
        // Exec plugin and auth provider failures. Never show their output, the parser's
        // excerpt of it, or kube's `Debug` dump of the command and its environment (#74).
        if let Some(a) = std::iter::successors(Some(err as &dyn std::error::Error), |e| e.source())
            .find_map(|e| e.downcast_ref::<AuthError>())
        {
            return Self::Unreachable(format!("cannot {what}: {}", auth_failure(a)));
        }
        let chain = error_chain(err);
        match err {
            kube::Error::HyperError(_) | kube::Error::Service(_) => Self::Unreachable(format!(
                "cannot {what}: could not reach the API server ({chain}). Check network or VPN access and that the cluster is running; `k8s-mcp doctor` shows details."
            )),
            kube::Error::FromUtf8(_) | kube::Error::SerdeError(_) => Self::Api(format!(
                "cannot {what}: the API server's response could not be decoded ({chain}). Retry; if it persists, please report it at https://github.com/riseno/k8s-mcp/issues."
            )),
            _ => Self::Api(format!("cannot {what}: {chain}")),
        }
    }

    /// True for RBAC denials.
    pub fn is_forbidden(&self) -> bool {
        matches!(self, Self::Forbidden(_))
    }

    /// True when the object (or what the call names) does not exist.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound(_))
    }

    /// True when the API server cannot be reached or the credentials fail.
    pub fn is_unreachable(&self) -> bool {
        matches!(self, Self::Unreachable(_))
    }
}

/// What went wrong with the credentials, without any plugin output.
/// (k8s-mcp runs exec plugins itself, in `crate::exec`; kube-client reports the exec variants
/// only if a client is ever built with an exec section left in.)
fn auth_failure(a: &AuthError) -> String {
    match a {
        AuthError::AuthExecStart(e) => {
            format!("the kubeconfig exec auth plugin could not be started ({e}). {INSTALL_IT}")
        }
        AuthError::AuthExecRun { out, .. } => {
            format!(
                "the kubeconfig exec auth plugin failed ({}). {RUN_IT}",
                out.status
            )
        }
        AuthError::AuthExecParse(_) | AuthError::ExecPluginFailed => {
            format!("the kubeconfig exec auth plugin's output is not an ExecCredential. {RUN_IT}")
        }
        AuthError::ParseTokenKey(_) => {
            format!("the kubeconfig auth provider command's output is not JSON. {RUN_IT}")
        }
        // Their messages name no plugin output. (No catch-all: a new kube variant must be
        // checked for leaks before it is shown.)
        AuthError::AuthExec(_)
        | AuthError::AuthExecSerialize(_)
        | AuthError::ExecMissingClusterInfo
        | AuthError::InvalidBasicAuth(_)
        | AuthError::InvalidBearerToken(_)
        | AuthError::MalformedTokenExpirationDate(_)
        | AuthError::MissingCommand
        | AuthError::NoValidNativeRootCA(_)
        | AuthError::ReadTokenFile(..)
        | AuthError::UnrefreshableTokenResponse => format!(
            "authentication failed ({a}). Check that the kubeconfig credentials work (`k8s-mcp doctor`) and re-authenticate if they expired."
        ),
    }
}

/// Flatten an error and its sources into one line.
pub fn error_chain(err: &dyn std::error::Error) -> String {
    let mut parts = vec![err.to_string()];
    let mut cur = err.source();
    while let Some(e) = cur {
        let s = e.to_string();
        if !parts.iter().any(|p| p.contains(&s)) {
            parts.push(s);
        }
        cur = e.source();
    }
    parts.join(": ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api_err(code: u16) -> kube::Error {
        let status: kube::core::Status = serde_json::from_value(serde_json::json!({
            "status": "Failure", "message": "pods is forbidden", "reason": "Forbidden", "code": code
        }))
        .unwrap();
        kube::Error::Api(Box::new(status))
    }

    #[test]
    fn forbidden_is_actionable() {
        let e = Error::kube("list pods in namespace shop", &api_err(403));
        assert!(e.is_forbidden());
        let msg = e.to_string();
        assert!(msg.contains("cannot list pods in namespace shop"));
        assert!(msg.contains("check_permissions"));
    }

    /// riseno/k8s-mcp#74: kube's message for a failed plugin holds the command's whole
    /// environment (`env:` secrets, PATH) and its captured output.
    #[cfg(unix)]
    #[test]
    fn failed_exec_plugin_shows_only_its_exit_status() {
        use std::os::unix::process::ExitStatusExt;
        let err = kube::Error::Auth(AuthError::AuthExecRun {
            cmd: r#"AZURE_CLIENT_SECRET="env-secret-456" PATH="/Users/someone/bin" "kubelogin" "get-token""#.into(),
            out: Box::new(std::process::Output {
                status: std::process::ExitStatus::from_raw(256),
                stdout: b"STDOUT-TOKEN-789".to_vec(),
                stderr: b"STDERR-TOKEN-123".to_vec(),
            }),
        });
        let e = Error::kube("create a client for context \"aks\"", &err);
        assert!(e.is_unreachable());
        let msg = e.to_string();
        assert!(msg.contains("plugin failed (exit status: 1)"), "{msg}");
        for leak in ["env-secret-456", "someone", "TOKEN", "kubelogin"] {
            assert!(!msg.contains(leak), "{leak} in {msg}");
        }
    }

    #[test]
    fn not_found_maps() {
        assert!(matches!(
            Error::kube("get pod x", &api_err(404)),
            Error::NotFound(_)
        ));
    }
}
