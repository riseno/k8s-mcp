//! Errors shown to the model. Every message says what failed, why, and what to do next.

use std::fmt::Display;

/// Result alias for k8s-mcp operations.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// A user-actionable error.
#[derive(Debug, thiserror::Error)]
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
    /// Any other API or transport failure.
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
                401 => Self::Api(format!(
                    "Unauthorized: cannot {what}: the credentials for this context were rejected or expired. Re-authenticate with your cloud CLI (for example `aws sso login`, `gcloud auth login`, `az login`) and retry."
                )),
                code => Self::Api(format!("cannot {what}: API returned {code}: {msg}")),
            };
        }
        let chain = error_chain(err);
        if chain.contains("unable to run auth exec") {
            return Self::Api(format!(
                "cannot {what}: the kubeconfig exec auth plugin could not be started ({}). Is the plugin (for example `aws`, `gke-gcloud-auth-plugin` or `kubelogin`) installed and on PATH for this MCP client? Install it, or start k8s-mcp with --path-prepend <dir containing it>.",
                after(&chain, "unable to run auth exec: ")
            ));
        }
        if let Some(i) = chain.find("auth exec command") {
            // Never echo the plugin's captured stdout/stderr: it can contain credentials.
            let head = &chain[i..];
            let head = head.find(": Output").map_or(head, |j| &head[..j]);
            return Self::Api(format!(
                "cannot {what}: {head}. Run the plugin command yourself to see its error, re-authenticate if needed, then retry."
            ));
        }
        if chain.contains("auth") {
            return Self::Api(format!(
                "cannot {what}: authentication failed ({chain}). Check that the kubeconfig credentials work (`k8s-mcp doctor`) and re-authenticate if they expired."
            ));
        }
        Self::Api(format!(
            "cannot {what}: could not reach the API server ({chain}). Check network or VPN access and that the cluster is running; `k8s-mcp doctor` shows details."
        ))
    }

    /// True for RBAC denials.
    pub fn is_forbidden(&self) -> bool {
        matches!(self, Self::Forbidden(_))
    }
}

fn after<'a>(s: &'a str, marker: &str) -> &'a str {
    s.find(marker).map_or(s, |i| &s[i + marker.len()..])
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

    #[test]
    fn not_found_maps() {
        assert!(matches!(
            Error::kube("get pod x", &api_err(404)),
            Error::NotFound(_)
        ));
    }
}
