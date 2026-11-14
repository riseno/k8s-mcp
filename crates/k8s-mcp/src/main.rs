#![forbid(unsafe_code)]
//! `k8s-mcp`: a safe, read-only-by-default MCP server for troubleshooting any Kubernetes
//! cluster. stdout is the MCP channel; every log line goes to stderr.

mod doctor;
mod server;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, bail};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use k8s_mcp_core::audit::Audit;
use k8s_mcp_core::cluster::{ClusterManager, LoadOptions};
use k8s_mcp_core::policy::{Policy, RedactLevel};
use k8s_mcp_tools::Ctx;
use rmcp::ServiceExt;

/// Safe, read-only Kubernetes troubleshooting for AI assistants (MCP server).
#[derive(Parser)]
#[command(name = "k8s-mcp", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    opts: Opts,
}

#[derive(Subcommand)]
enum Command {
    /// Run the MCP server over stdio (default).
    Serve,
    /// Check that k8s-mcp can reach and read the cluster, then exit.
    Doctor,
    /// Print the version.
    Version,
    /// Print shell completions.
    Completions {
        /// Shell to generate completions for.
        shell: clap_complete::Shell,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Redact {
    Strict,
    Standard,
    Off,
}

/// Flags (each also readable from `K8S_MCP_<FLAG>`). No config file is needed.
#[derive(Args, Clone)]
pub struct Opts {
    /// Kubeconfig file [default: $KUBECONFIG or ~/.kube/config].
    #[arg(long, global = true, env = "K8S_MCP_KUBECONFIG")]
    kubeconfig: Option<PathBuf>,
    /// Use the in-cluster ServiceAccount (auto-detected when no kubeconfig exists).
    #[arg(long, global = true, env = "K8S_MCP_IN_CLUSTER")]
    in_cluster: bool,
    /// Default context [default: current-context].
    #[arg(long, global = true, env = "K8S_MCP_CONTEXT")]
    context: Option<String>,
    /// Extra contexts the assistant may target (globs, comma separated; `*` = all).
    #[arg(long, global = true, env = "K8S_MCP_CONTEXTS", value_delimiter = ',')]
    contexts: Vec<String>,
    /// Namespace allow-list (globs, comma separated) [default: all].
    #[arg(long, global = true, env = "K8S_MCP_NAMESPACES", value_delimiter = ',')]
    namespaces: Vec<String>,
    /// Namespace deny-list (globs, comma separated); wins over the allow-list.
    #[arg(
        long,
        global = true,
        env = "K8S_MCP_DENY_NAMESPACES",
        value_delimiter = ','
    )]
    deny_namespaces: Vec<String>,
    /// Redaction level; `off` prints a warning on every response.
    #[arg(
        long,
        global = true,
        env = "K8S_MCP_REDACT",
        value_enum,
        default_value = "standard"
    )]
    redact: Redact,
    /// Hard cap on each tool response, in bytes.
    #[arg(
        long,
        global = true,
        env = "K8S_MCP_MAX_OUTPUT_BYTES",
        default_value_t = 24_000
    )]
    max_output_bytes: usize,
    /// Audit log: a file path, `stderr` or `off` [default: $XDG_STATE_HOME/k8s-mcp/audit.jsonl; stderr in-cluster].
    #[arg(long, global = true, env = "K8S_MCP_AUDIT_LOG")]
    audit_log: Option<String>,
    /// Toolsets to expose (comma separated): core, diagnose.
    #[arg(
        long,
        global = true,
        env = "K8S_MCP_TOOLSETS",
        value_delimiter = ',',
        default_value = "core,diagnose"
    )]
    toolsets: Vec<String>,
    /// Extra directories for kubeconfig exec plugins, separated like PATH.
    #[arg(long, global = true, env = "K8S_MCP_PATH_PREPEND")]
    path_prepend: Option<String>,
    /// Log level for stderr (error, warn, info, debug, trace).
    #[arg(long, global = true, env = "K8S_MCP_LOG_LEVEL", default_value = "warn")]
    log_level: String,
}

impl Opts {
    fn load_options(&self) -> LoadOptions {
        LoadOptions {
            kubeconfig: self.kubeconfig.clone(),
            context: self.context.clone(),
            in_cluster: self.in_cluster.then_some(true),
            path_prepend: self
                .path_prepend
                .as_deref()
                .map(|p| std::env::split_paths(p).collect())
                .unwrap_or_default(),
        }
    }

    fn policy(&self) -> anyhow::Result<Policy> {
        let redact = match self.redact {
            Redact::Strict => RedactLevel::Strict,
            Redact::Standard => RedactLevel::Standard,
            Redact::Off => RedactLevel::Off,
        };
        if self.max_output_bytes < 2_000 {
            bail!("--max-output-bytes must be at least 2000");
        }
        Ok(Policy::new(
            &self.contexts,
            &self.namespaces,
            &self.deny_namespaces,
            redact,
            self.max_output_bytes,
        )?)
    }

    /// Build the tool context: kubeconfig, policy, redaction.
    pub fn ctx(&self) -> anyhow::Result<Ctx> {
        let clusters = ClusterManager::load(&self.load_options())?;
        Ok(Ctx::new(Arc::new(clusters), Arc::new(self.policy()?)))
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(&cli.opts.log_level)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_ansi(false)
        .init();
    let result = match cli.command.unwrap_or(Command::Serve) {
        Command::Version => {
            print_stdout(&format!("k8s-mcp {}\n", server::VERSION));
            Ok(ExitCode::SUCCESS)
        }
        Command::Completions { shell } => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "k8s-mcp",
                &mut std::io::stdout(),
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Doctor => runtime().and_then(|rt| rt.block_on(doctor::run(&cli.opts))),
        Command::Serve => runtime()
            .and_then(|rt| rt.block_on(serve(&cli.opts)))
            .map(|()| ExitCode::SUCCESS),
    };
    result.unwrap_or_else(|e| {
        tracing::error!("{e:#}");
        eprintln!("k8s-mcp: {e:#}");
        ExitCode::FAILURE
    })
}

/// Write CLI output (version, doctor). Never used by the MCP server path.
#[allow(clippy::print_stdout)]
pub fn print_stdout(s: &str) {
    print!("{s}");
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("start the async runtime")
}

async fn serve(opts: &Opts) -> anyhow::Result<()> {
    for t in &opts.toolsets {
        if !matches!(t.as_str(), "core" | "diagnose") {
            bail!("unknown toolset {t:?}; valid toolsets are core and diagnose");
        }
    }
    let ctx = opts.ctx()?;
    if ctx.policy.redact == RedactLevel::Off {
        tracing::warn!(
            "redaction is off (--redact off): credentials in logs and env vars may reach the model"
        );
    }
    let in_cluster =
        opts.in_cluster || ctx.clusters.default_context() == k8s_mcp_core::cluster::IN_CLUSTER;
    let audit_target = match &opts.audit_log {
        Some(t) => t.clone(),
        None if in_cluster => "stderr".into(),
        None => k8s_mcp_core::audit::default_path()
            .map_or_else(|| "stderr".into(), |p| p.display().to_string()),
    };
    let audit = Arc::new(Audit::open(&audit_target)?);
    tracing::info!(context = ctx.clusters.default_context(), audit = %audit_target, "k8s-mcp {} serving on stdio", server::VERSION);
    let server = server::K8sMcp::new(ctx, audit.clone(), &opts.toolsets);
    let running = Box::pin(server.serve(rmcp::transport::stdio()))
        .await
        .context("start the MCP stdio transport")?;
    let ct = running.cancellation_token();
    tokio::spawn(async move {
        shutdown_signal().await;
        ct.cancel();
    });
    let reason = running.waiting().await.context("MCP service task failed")?;
    tracing::info!(?reason, "k8s-mcp stopped");
    audit.close();
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = term.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
