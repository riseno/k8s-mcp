#![forbid(unsafe_code)]
//! `k8s-mcp`: a safe, read-only-by-default MCP server for troubleshooting any Kubernetes
//! cluster. stdout is the MCP channel; every log line goes to stderr.

mod doctor;
#[cfg(feature = "http")]
mod http;
mod server;

use std::net::SocketAddr;
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

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Transport {
    Stdio,
    Http,
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
    /// MCP transport: stdio, or streamable HTTP (`/mcp`) for in-cluster use.
    #[arg(
        long,
        global = true,
        env = "K8S_MCP_TRANSPORT",
        value_enum,
        default_value = "stdio"
    )]
    transport: Transport,
    /// HTTP listen address.
    #[arg(
        long,
        global = true,
        env = "K8S_MCP_LISTEN",
        default_value = "127.0.0.1:8080"
    )]
    listen: SocketAddr,
    /// HTTP auth: tokenreview (Kubernetes tokens), static (--auth-token-file) or none (loopback only).
    #[arg(
        long,
        global = true,
        env = "K8S_MCP_AUTH",
        default_value = "tokenreview",
        value_parser = ["tokenreview", "static", "none"]
    )]
    auth: String,
    /// File holding the bearer token for `--auth static`.
    #[arg(long, global = true, env = "K8S_MCP_AUTH_TOKEN_FILE")]
    auth_token_file: Option<PathBuf>,
    /// Audiences `--auth tokenreview` tokens must be minted for, comma separated (`kubectl create token <sa> --audience <aud>`). Without one, any token for the API server's audience passes, including every pod's default ServiceAccount token.
    #[arg(
        long = "auth-audience",
        global = true,
        env = "K8S_MCP_AUTH_AUDIENCE",
        value_delimiter = ','
    )]
    auth_audiences: Vec<String>,
    /// Callers `--auth tokenreview` lets in, comma separated: globs over the username (`system:serviceaccount:platform:*`) or `group:<glob>` over its groups. Others get 403 and an audit record [default: every authenticated caller].
    #[arg(
        long,
        global = true,
        env = "K8S_MCP_ALLOWED_CALLERS",
        value_delimiter = ','
    )]
    allowed_callers: Vec<String>,
    /// HTTP `Host` values accepted, comma separated (DNS-rebinding protection) [default: localhost, 127.0.0.1, ::1].
    #[arg(
        long,
        global = true,
        env = "K8S_MCP_ALLOWED_HOSTS",
        value_delimiter = ','
    )]
    allowed_hosts: Vec<String>,
    /// Browser `Origin` values accepted, comma separated, with scheme [default: none, so any request with an Origin gets 403].
    #[arg(
        long,
        global = true,
        env = "K8S_MCP_ALLOWED_ORIGINS",
        value_delimiter = ','
    )]
    allowed_origins: Vec<String>,
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
    /// Audit log: a file path, `stderr` or `off` [default: ~/Library/Application Support/k8s-mcp/audit.jsonl on macOS, $XDG_STATE_HOME/k8s-mcp/audit.jsonl (else ~/.local/state/k8s-mcp/audit.jsonl) on Linux, %LOCALAPPDATA%\k8s-mcp\audit.jsonl on Windows; stderr in-cluster].
    #[arg(long, global = true, env = "K8S_MCP_AUDIT_LOG")]
    audit_log: Option<String>,
    /// Cloud provider modules (comma separated): auto (when the default context is detected,
    /// with high confidence, as that provider), none, or eks.
    #[arg(
        long,
        global = true,
        env = "K8S_MCP_PROVIDERS",
        value_delimiter = ',',
        default_value = "auto"
    )]
    providers: Vec<String>,
    /// EKS cluster name, when detection cannot tell (in-cluster, renamed contexts).
    #[arg(long, global = true, env = "K8S_MCP_EKS_CLUSTER")]
    eks_cluster: Option<String>,
    /// EKS cluster region, when detection cannot tell.
    #[arg(long, global = true, env = "K8S_MCP_EKS_REGION")]
    eks_region: Option<String>,
    /// Toolsets to expose (comma separated): core, diagnose, eks (provider toolsets are added
    /// per --providers).
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
        let mut ctx = Ctx::new(Arc::new(clusters), Arc::new(self.policy()?));
        ctx.cloud = k8s_mcp_tools::CloudOverride {
            cluster: self.eks_cluster.clone(),
            region: self.eks_region.clone(),
        };
        Ok(ctx)
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

/// The toolsets to expose: `--toolsets`, plus provider toolsets per `--providers`.
async fn toolsets(opts: &Opts, ctx: &Ctx) -> anyhow::Result<Vec<String>> {
    if let Some(t) = opts
        .toolsets
        .iter()
        .find(|t| !matches!(t.as_str(), "core" | "diagnose" | "eks"))
    {
        bail!("unknown toolset {t:?}; valid toolsets are core, diagnose and eks");
    }
    let p = &opts.providers;
    if let Some(bad) = p
        .iter()
        .find(|p| !matches!(p.as_str(), "auto" | "none" | "eks"))
    {
        bail!("unknown provider {bad:?}: use auto, none or eks (GKE and AKS arrive in v0.3)");
    }
    let mut out = opts.toolsets.clone();
    if p.iter().any(|x| x == "none") {
        if p.len() > 1 {
            bail!("--providers none cannot be combined with other providers");
        }
        return Ok(out);
    }
    let explicit = p.iter().any(|x| x == "eks");
    let eks = explicit
        || opts.eks_cluster.is_some()
        || (p.iter().any(|x| x == "auto") && detected_eks(ctx).await);
    if eks && !cfg!(feature = "provider-eks") {
        if explicit {
            bail!("this build has no EKS provider (built without the `provider-eks` feature)");
        }
    } else if eks && !out.iter().any(|t| t == "eks") {
        out.push("eks".into());
    }
    Ok(out)
}

/// Whether the default context is EKS with high confidence: from the kubeconfig, or in-cluster
/// (where the kubeconfig says nothing) from a few nodes.
async fn detected_eks(ctx: &Ctx) -> bool {
    use k8s_mcp_core::provider::{Confidence, Detection, ProviderId};
    let is_eks = |d: Option<Detection>| {
        d.is_some_and(|d| d.provider == ProviderId::Eks && d.confidence == Confidence::High)
    };
    let default = ctx.clusters.default_context().to_owned();
    if is_eks(ctx.clusters.detect_provider(&default, &[])) {
        return true;
    }
    if default != k8s_mcp_core::cluster::IN_CLUSTER {
        return false;
    }
    let Ok(target) = ctx.clusters.target(None, &ctx.policy).await else {
        return false;
    };
    let lp = kube::api::ListParams::default().limit(20);
    let nodes = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        kube::Api::<k8s_openapi::api::core::v1::Node>::all(target.client).list(&lp),
    )
    .await;
    matches!(nodes, Ok(Ok(l)) if is_eks(ctx.clusters.detect_provider(&default, &l.items)))
}

async fn serve(opts: &Opts) -> anyhow::Result<()> {
    let mut ctx = opts.ctx()?;
    let toolsets = toolsets(opts, &ctx).await?;
    if toolsets.iter().any(|t| t == "eks") {
        ctx.providers.push(k8s_mcp_core::provider::ProviderId::Eks);
    }
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
    tracing::info!(context = ctx.clusters.default_context(), audit = %audit_target, "k8s-mcp {} starting", server::VERSION);
    tracing::info!(toolsets = ?toolsets, "toolsets");
    if opts.transport == Transport::Http {
        return serve_http(opts, ctx, audit, &toolsets).await;
    }
    let server = server::K8sMcp::new(ctx, audit.clone(), &toolsets);
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

#[cfg(feature = "http")]
async fn serve_http(
    opts: &Opts,
    ctx: Ctx,
    audit: Arc<Audit>,
    toolsets: &[String],
) -> anyhow::Result<()> {
    // TokenReview and /readyz use the server's own identity (the default context).
    let client = ctx.clusters.target(None, &ctx.policy).await?.client;
    let auth = http::Auth::new(
        &opts.auth,
        opts.auth_token_file.as_deref(),
        opts.listen,
        client.clone(),
        &opts.auth_audiences,
        &opts.allowed_callers,
    )?;
    let server = server::K8sMcp::new(ctx, audit.clone(), toolsets);
    let (app, stop) = http::router(
        server,
        auth,
        client,
        &opts.allowed_hosts,
        &opts.allowed_origins,
    );
    let served = http::serve(opts.listen, app, stop).await;
    audit.close();
    served
}

#[cfg(not(feature = "http"))]
async fn serve_http(_: &Opts, _: Ctx, _: Arc<Audit>, _: &[String]) -> anyhow::Result<()> {
    bail!(
        "this build has no HTTP transport (built without the `http` feature); use --transport stdio"
    )
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
