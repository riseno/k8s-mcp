//! `k8s-mcp doctor`: a CLI self-check (PROPOSAL §6.1). Exits non-zero with an actionable
//! message on any failure.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use k8s_mcp_tools::{ApiResourcesInput, CheckPermissionsInput};

use crate::{Opts, print_stdout};

/// Run the checks and print a report to stdout.
pub async fn run(opts: &Opts) -> anyhow::Result<ExitCode> {
    let mut out = String::new();
    let mut ok = true;
    let mut line = |good: bool, text: &str| {
        let _ = writeln!(out, "{} {text}", if good { "✓" } else { "✗" });
    };

    let ctx = match opts.ctx() {
        Ok(c) => c,
        Err(e) => {
            line(false, &format!("kubeconfig: {e:#}"));
            print_stdout(&out);
            return Ok(ExitCode::FAILURE);
        }
    };
    let cm = &ctx.clusters;
    let paths: Vec<String> = cm
        .kubeconfig_paths
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    line(
        true,
        &format!(
            "kubeconfig: {}",
            if paths.is_empty() {
                "in-cluster ServiceAccount".into()
            } else {
                paths.join(", ")
            }
        ),
    );
    line(true, &format!("context: {}", cm.default_context()));

    for plugin in &cm.exec_plugins {
        let found = find_on_path(plugin, opts);
        ok &= found.is_some();
        match found {
            Some(p) => line(
                true,
                &format!("exec auth plugin `{plugin}`: {}", p.display()),
            ),
            None => line(
                false,
                &format!(
                    "exec auth plugin `{plugin}` not found on PATH: install it, or pass --path-prepend <dir containing it> (GUI MCP clients start with a minimal PATH)"
                ),
            ),
        }
    }

    let target = cm.target(None, &ctx.policy).await;
    let version = match &target {
        Ok(t) => t
            .client
            .apiserver_version()
            .await
            .map_err(|e| k8s_mcp_core::Error::kube("reach the API server", &e)),
        Err(e) => Err(k8s_mcp_core::Error::Config(e.to_string())),
    };
    match version {
        Ok(v) => line(
            true,
            &format!("API server reachable: Kubernetes {}", v.git_version),
        ),
        Err(e) => {
            line(false, &format!("API server: {e}"));
            print_stdout(&out);
            return Ok(ExitCode::FAILURE);
        }
    }

    match k8s_mcp_tools::check_permissions(&ctx, CheckPermissionsInput::default()).await {
        Ok(env) => {
            let ns = env.namespace.clone().unwrap_or_default();
            for item in &env.items {
                let check = item["check"].as_str().unwrap_or("");
                let allowed = item["allowed"].as_bool().unwrap_or(false);
                let (good, verdict) = match (check, allowed) {
                    (c, true) if c.starts_with("do everything") => (
                        true,
                        "yes (warning: broad rights; prefer a read-only kubeconfig for AI tools)"
                            .to_owned(),
                    ),
                    (c, false)
                        if c.starts_with("do everything") || c.starts_with("read secrets") =>
                    {
                        (true, "no (good)".to_owned())
                    }
                    (c, a) if c.contains("nodes") || c.contains("metrics") => (
                        true,
                        if a {
                            "yes".into()
                        } else {
                            "no (some tools will report it as unavailable)".into()
                        },
                    ),
                    (_, a) => (a, if a { "yes".into() } else { "no".into() }),
                };
                ok &= good;
                line(good, &format!("can {check} in {ns}: {verdict}"));
            }
        }
        Err(e) => {
            ok = false;
            line(false, &format!("permission check: {e}"));
        }
    }

    let metrics = k8s_mcp_tools::api_resources(
        &ctx,
        ApiResourcesInput {
            group: Some("metrics.k8s.io".into()),
            ..ApiResourcesInput::default()
        },
    )
    .await
    .is_ok_and(|e| !e.items.is_empty());
    line(
        true,
        &format!(
            "metrics-server: {}",
            if metrics {
                "present"
            } else {
                "not installed (the `top` tool will report it)"
            }
        ),
    );
    let provider = cm
        .contexts(&ctx.policy)
        .into_iter()
        .find(|c| c.is_default)
        .and_then(|c| c.provider);
    line(
        true,
        &format!(
            "provider: {} (cloud provider modules arrive in v0.2)",
            provider.unwrap_or("none detected")
        ),
    );
    line(
        true,
        &format!(
            "safety: read-only, secret values never returned, redaction {:?}, namespaces {}, max {} bytes per response",
            ctx.policy.redact,
            ctx.policy.describe_namespaces(),
            ctx.policy.max_output_bytes
        ),
    );
    let _ = writeln!(
        out,
        "\n{}",
        if ok {
            "All checks passed. Add k8s-mcp to your MCP client, e.g. `claude mcp add k8s -- k8s-mcp`."
        } else {
            "Some checks failed; fix the items marked ✗ above."
        }
    );
    print_stdout(&out);
    Ok(if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Look up an exec plugin like kube-rs will: absolute paths as-is, else PATH (plus
/// `--path-prepend` and, on macOS, Homebrew dirs).
fn find_on_path(cmd: &str, opts: &Opts) -> Option<PathBuf> {
    let p = Path::new(cmd);
    if p.is_absolute() || cmd.contains(std::path::MAIN_SEPARATOR) {
        return p.exists().then(|| p.to_path_buf());
    }
    let prepend: Vec<PathBuf> = opts
        .path_prepend
        .as_deref()
        .map(|s| std::env::split_paths(s).collect())
        .unwrap_or_default();
    let dirs = k8s_mcp_core::cluster::exec_search_path(&prepend);
    let exts: &[&str] = if cfg!(windows) {
        &[".exe", ".cmd", ".bat", ""]
    } else {
        &[""]
    };
    dirs.iter()
        .flat_map(|d| exts.iter().map(move |e| d.join(format!("{cmd}{e}"))))
        .find(|c| c.is_file())
}
