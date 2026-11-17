//! Kubeconfig loading, context policy and lazily created clients (PROPOSAL §7.5).
//!
//! The kubeconfig is read once and never written. Exec auth plugins are forced to
//! `interactiveMode: Never` (stdin is the MCP channel in stdio mode) and get an extended
//! `PATH` (`--path-prepend`, plus Homebrew dirs on macOS) through their `env`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kube::Client;
use kube::config::{Config, ExecInteractiveMode, KubeConfigOptions, Kubeconfig, KubeconfigError};

use k8s_openapi::api::core::v1::Node;

use crate::error::{Error, Result};
use crate::policy::Policy;
use crate::provider::{Detection, ProviderId, Signals, detect};

/// Name used for the in-cluster ServiceAccount "context".
pub const IN_CLUSTER: &str = "in-cluster";

/// How long discovery results are reused.
const DISCOVERY_TTL: Duration = Duration::from_secs(300);

/// Per-request timeout for API calls.
pub const API_TIMEOUT: Duration = Duration::from_secs(20);
/// Budget for a kubeconfig exec auth plugin to print its credential.
const EXEC_TIMEOUT: Duration = Duration::from_secs(20);

/// Options for [`ClusterManager::load`].
#[derive(Debug, Clone, Default)]
pub struct LoadOptions {
    /// Explicit kubeconfig file (else `$KUBECONFIG`, else `~/.kube/config`).
    pub kubeconfig: Option<PathBuf>,
    /// Default context (else the kubeconfig's current-context).
    pub context: Option<String>,
    /// Force (`Some(true)`) or forbid (`Some(false)`) in-cluster config; `None` = auto.
    pub in_cluster: Option<bool>,
    /// Extra directories to put in front of `PATH` for exec plugins.
    pub path_prepend: Vec<PathBuf>,
}

/// A context the assistant may target (credentials are never included).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ContextInfo {
    /// Context name.
    pub name: String,
    /// API server host (no scheme, path or credentials).
    pub server_host: String,
    /// Namespace used when a tool gets none.
    pub namespace: String,
    /// Whether this is the default context.
    pub is_default: bool,
    /// Provider detected from the kubeconfig, or from its nodes once a tool has listed them
    /// (no cloud calls).
    pub provider: Option<&'static str>,
    /// `nodes` when the nodes were checked, else `kubeconfig (nodes not checked)`.
    pub provider_source: &'static str,
    /// Why the kubeconfig's provider does not hold, when the nodes contradict it (#64).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_conflict: Option<String>,
}

/// What the nodes of a context said about its provider, the last time a tool listed them.
#[derive(Debug, Clone)]
struct NodeCheck {
    provider: Option<ProviderId>,
    conflict: Option<String>,
}

const FROM_NODES: &str = "nodes";
const FROM_KUBECONFIG: &str = "kubeconfig (nodes not checked)";

/// One API resource from discovery.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ResourceInfo {
    /// API group (`""` for core).
    pub group: String,
    /// Version, e.g. `v1`.
    pub version: String,
    /// Kind, e.g. `Deployment`.
    pub kind: String,
    /// Plural resource name, e.g. `deployments`.
    pub plural: String,
    /// Whether objects are namespaced.
    pub namespaced: bool,
    /// Short names, e.g. `deploy`.
    pub short_names: Vec<String>,
    /// Supported verbs.
    pub verbs: Vec<String>,
}

impl ResourceInfo {
    /// `group/version`, or `version` for the core group.
    pub fn api_version(&self) -> String {
        if self.group.is_empty() {
            self.version.clone()
        } else {
            format!("{}/{}", self.group, self.version)
        }
    }
}

enum Source {
    Kubeconfig(Box<Kubeconfig>),
    InCluster,
    Fixed(Client),
}

/// A resolved target context.
#[derive(Clone)]
pub struct Target {
    /// Context name.
    pub context: String,
    /// The context's default namespace.
    pub namespace: String,
    /// API client.
    pub client: Client,
}

type Discovered = Arc<Vec<ResourceInfo>>;

/// Holds the kubeconfig, the default context and one lazily created client per context.
pub struct ClusterManager {
    source: Source,
    default_context: String,
    default_namespace: String,
    /// Kubeconfig files that were read (for `doctor`).
    pub kubeconfig_paths: Vec<PathBuf>,
    /// Exec plugin commands referenced by the kubeconfig (for `doctor`).
    pub exec_plugins: Vec<String>,
    clients: Mutex<HashMap<String, Client>>,
    discovery: Mutex<HashMap<String, (Instant, Discovered)>>,
    /// Node-backed detection per context, from tools that listed the nodes (#71).
    node_checks: Mutex<HashMap<String, NodeCheck>>,
}

impl ClusterManager {
    /// Load the kubeconfig (or in-cluster config) according to `opts`.
    pub fn load(opts: &LoadOptions) -> Result<Self> {
        let in_cluster_env = std::env::var_os("KUBERNETES_SERVICE_HOST").is_some();
        if opts.in_cluster == Some(true) {
            return Ok(Self::in_cluster());
        }
        let (kc, paths) = match &opts.kubeconfig {
            Some(p) => (Kubeconfig::read_from(p), vec![p.clone()]),
            None => (Kubeconfig::read(), default_paths()),
        };
        let mut kc = match kc {
            Ok(kc) => kc,
            Err(e) if in_cluster_env && opts.in_cluster.is_none() && opts.kubeconfig.is_none() => {
                tracing::info!(error = %e, "no kubeconfig found; using in-cluster ServiceAccount");
                return Ok(Self::in_cluster());
            }
            Err(e) => return Err(kubeconfig_error(&e, &paths)),
        };
        let exec_plugins = harden_exec_plugins(&mut kc, &opts.path_prepend);
        let default_context = opts
            .context
            .clone()
            .or_else(|| kc.current_context.clone())
            .filter(|c| !c.is_empty())
            .ok_or_else(|| {
                Error::Config("the kubeconfig has no current-context; pass --context <name>".into())
            })?;
        let ctx = kc
            .contexts
            .iter()
            .find(|c| c.name == default_context)
            .ok_or_else(|| {
                Error::Config(format!(
                    "context {default_context:?} is not in the kubeconfig (available: {}); pass --context with one of them",
                    kc.contexts.iter().map(|c| c.name.as_str()).collect::<Vec<_>>().join(", ")
                ))
            })?;
        let default_namespace = ctx
            .context
            .as_ref()
            .and_then(|c| c.namespace.clone())
            .unwrap_or_else(|| "default".into());
        Ok(Self {
            source: Source::Kubeconfig(Box::new(kc)),
            default_context,
            default_namespace,
            kubeconfig_paths: paths,
            exec_plugins,
            clients: Mutex::default(),
            discovery: Mutex::default(),
            node_checks: Mutex::default(),
        })
    }

    fn in_cluster() -> Self {
        let ns = std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
            .map_or_else(|_| "default".into(), |s| s.trim().to_owned());
        Self {
            source: Source::InCluster,
            default_context: IN_CLUSTER.into(),
            default_namespace: ns,
            kubeconfig_paths: Vec::new(),
            exec_plugins: Vec::new(),
            clients: Mutex::default(),
            discovery: Mutex::default(),
            node_checks: Mutex::default(),
        }
    }

    /// A manager around a ready-made client (tests and mocks).
    pub fn fixed(client: Client, context: &str, namespace: &str) -> Self {
        Self {
            source: Source::Fixed(client),
            default_context: context.into(),
            default_namespace: namespace.into(),
            kubeconfig_paths: Vec::new(),
            exec_plugins: Vec::new(),
            clients: Mutex::default(),
            discovery: Mutex::default(),
            node_checks: Mutex::default(),
        }
    }

    /// The default context name.
    pub fn default_context(&self) -> &str {
        &self.default_context
    }

    /// Detect the cloud provider of a context from its kubeconfig and, when given, its nodes.
    /// No cloud calls.
    pub fn detect_provider(&self, context: &str, nodes: &[Node]) -> Option<Detection> {
        self.remember_nodes(context, nodes);
        self.with_signals(context, nodes, detect)
    }

    /// When the context's kubeconfig looks like one cloud but its nodes run elsewhere, why
    /// (see [`crate::provider::conflict`]).
    pub fn detection_conflict(&self, context: &str, nodes: &[Node]) -> Option<String> {
        self.remember_nodes(context, nodes);
        self.with_signals(context, nodes, crate::provider::conflict)
    }

    /// Keep what listed nodes say, so `contexts()` can report it without an API call (#71).
    fn remember_nodes(&self, context: &str, nodes: &[Node]) {
        if nodes.is_empty() {
            return;
        }
        let check = NodeCheck {
            provider: self
                .with_signals(context, nodes, detect)
                .map(|d| d.provider),
            conflict: self.with_signals(context, nodes, crate::provider::conflict),
        };
        self.node_checks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(context.to_owned(), check);
    }

    fn node_check(&self, context: &str) -> Option<NodeCheck> {
        self.node_checks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(context)
            .cloned()
    }

    fn with_signals<T>(&self, context: &str, nodes: &[Node], f: impl Fn(&Signals) -> T) -> T {
        let (host, exec_command, exec_args, exec_env) = match &self.source {
            Source::Kubeconfig(kc) => kubeconfig_signals(kc, context),
            _ => Default::default(),
        };
        f(&Signals {
            context,
            server_host: &host,
            exec_command: &exec_command,
            exec_args: &exec_args,
            exec_env: &exec_env,
            nodes,
        })
    }

    /// Contexts allowed by `policy`, default first. Never includes credentials.
    pub fn contexts(&self, policy: &Policy) -> Vec<ContextInfo> {
        let Source::Kubeconfig(kc) = &self.source else {
            return vec![ContextInfo {
                name: self.default_context.clone(),
                server_host: if matches!(self.source, Source::InCluster) {
                    "kubernetes.default.svc".into()
                } else {
                    "-".into()
                },
                namespace: self.default_namespace.clone(),
                is_default: true,
                provider: None,
                provider_source: FROM_KUBECONFIG,
                provider_conflict: None,
            }];
        };
        let mut out: Vec<ContextInfo> = kc
            .contexts
            .iter()
            .filter(|c| policy.context_allowed(&c.name, &self.default_context))
            .map(|c| {
                let ctx = c.context.as_ref();
                let checked = self.node_check(&c.name);
                let (provider, provider_source, provider_conflict) = match checked {
                    Some(n) => (n.provider.map(ProviderId::as_str), FROM_NODES, n.conflict),
                    None => (
                        self.detect_provider(&c.name, &[])
                            .map(|d| d.provider.as_str()),
                        FROM_KUBECONFIG,
                        None,
                    ),
                };
                ContextInfo {
                    provider,
                    provider_source,
                    provider_conflict,
                    server_host: kubeconfig_signals(kc, &c.name).0,
                    namespace: ctx
                        .and_then(|c| c.namespace.clone())
                        .unwrap_or_else(|| "default".into()),
                    is_default: c.name == self.default_context,
                    name: c.name.clone(),
                }
            })
            .collect();
        out.sort_by(|a, b| b.is_default.cmp(&a.is_default).then(a.name.cmp(&b.name)));
        out
    }

    /// Resolve `context` (or the default), enforce the context allow-list, and return a
    /// client for it.
    pub async fn target(&self, context: Option<&str>, policy: &Policy) -> Result<Target> {
        let name = context.unwrap_or(&self.default_context);
        let allowed = self.contexts(policy);
        let names = || {
            allowed
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let exists = match &self.source {
            Source::Kubeconfig(kc) => kc.contexts.iter().any(|c| c.name == name),
            _ => name == self.default_context,
        };
        // Only a context that exists can be allowed with --contexts (issue #51).
        if !exists {
            let files: Vec<String> = self
                .kubeconfig_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect();
            return Err(Error::NotFound(format!(
                "context {name:?} is not in the kubeconfig{}; allowed contexts: {}. Use one of them (list_contexts shows them).",
                if files.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", files.join(", "))
                },
                names()
            )));
        }
        let Some(namespace) = allowed
            .iter()
            .find(|c| c.name == name)
            .map(|c| c.namespace.clone())
        else {
            return Err(Error::ContextNotAllowed {
                context: name.into(),
                allowed: names(),
            });
        };
        if let Some(c) = self.lock_clients().get(name) {
            return Ok(Target {
                context: name.into(),
                namespace,
                client: c.clone(),
            });
        }
        let client = self.build_client(name).await?;
        self.lock_clients().insert(name.into(), client.clone());
        Ok(Target {
            context: name.into(),
            namespace,
            client,
        })
    }

    async fn build_client(&self, name: &str) -> Result<Client> {
        let mut config = match &self.source {
            Source::Fixed(c) => return Ok(c.clone()),
            Source::InCluster => Config::incluster().map_err(|e| {
                Error::Config(format!(
                    "in-cluster config failed: {e}. Is the ServiceAccount token mounted?"
                ))
            })?,
            Source::Kubeconfig(kc) => Config::from_custom_kubeconfig(
                (**kc).clone(),
                &KubeConfigOptions {
                    context: Some(name.into()),
                    ..KubeConfigOptions::default()
                },
            )
            .await
            .map_err(|e| {
                Error::Config(format!(
                    "cannot load context {name:?} from the kubeconfig: {e}"
                ))
            })?,
        };
        config.connect_timeout = Some(Duration::from_secs(10));
        config.read_timeout = Some(API_TIMEOUT);
        let what = format!("create a client for context {name:?}");
        let Some(plugin) = config.auth_info.exec.as_ref().and_then(|e| e.command.clone()) else {
            return Client::try_from(config).map_err(|e| Error::kube(what, &e));
        };
        // `Client::try_from` runs the exec plugin with a blocking `Command::output`: on the
        // async worker a stalled plugin would hold the call past every timeout (#73).
        // ponytail: the stalled plugin keeps its blocking thread until it exits; kube-client
        // owns the process, so it cannot be killed from here.
        let build = tokio::task::spawn_blocking(move || Client::try_from(config));
        match tokio::time::timeout(EXEC_TIMEOUT, build).await {
            Ok(Ok(built)) => built.map_err(|e| Error::kube(what, &e)),
            Ok(Err(e)) => Err(Error::Api(format!(
                "cannot {what}: the exec auth plugin task failed ({e})"
            ))),
            Err(_) => Err(Error::Unreachable(format!(
                "cannot {what}: the kubeconfig exec auth plugin `{}` did not finish within {}s. Run it yourself to see why (it may be waiting for a login or the network), then retry.",
                Path::new(&plugin).file_name().map_or(plugin.as_str().into(), |f| f.to_string_lossy()),
                EXEC_TIMEOUT.as_secs()
            ))),
        }
    }

    fn lock_clients(&self) -> std::sync::MutexGuard<'_, HashMap<String, Client>> {
        self.clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Cached discovery for `context`, if fresh.
    pub fn cached_discovery(&self, context: &str) -> Option<Arc<Vec<ResourceInfo>>> {
        let map = self
            .discovery
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.get(context)
            .filter(|(at, _)| at.elapsed() < DISCOVERY_TTL)
            .map(|(_, v)| v.clone())
    }

    /// Store discovery results for `context`.
    pub fn store_discovery(&self, context: &str, resources: Arc<Vec<ResourceInfo>>) {
        self.discovery
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(context.into(), (Instant::now(), resources));
    }

    /// Drop cached discovery (after a lookup miss).
    pub fn forget_discovery(&self, context: &str) {
        self.discovery
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(context);
    }
}

fn default_paths() -> Vec<PathBuf> {
    match std::env::var_os("KUBECONFIG") {
        Some(v) => std::env::split_paths(&v)
            .filter(|p| !p.as_os_str().is_empty())
            .collect(),
        None => home_dir()
            .map(|h| vec![h.join(".kube").join("config")])
            .unwrap_or_default(),
    }
}

/// The user's home directory from the environment.
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn kubeconfig_error(e: &KubeconfigError, paths: &[PathBuf]) -> Error {
    let shown = paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Error::Config(format!(
        "cannot read kubeconfig ({shown}): {e}. Check that `kubectl get pods` works, or pass --kubeconfig <path>."
    ))
}

/// Force non-interactive exec plugins and extend their PATH. Returns the plugin commands.
/// Directories searched for exec plugins: `prepend`, then `PATH`, then (macOS) the Homebrew
/// dirs GUI clients usually lack.
pub fn exec_search_path(prepend: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = prepend.to_vec();
    dirs.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    if cfg!(target_os = "macos") {
        for extra in ["/opt/homebrew/bin", "/usr/local/bin"] {
            let p = PathBuf::from(extra);
            if !dirs.contains(&p) {
                tracing::info!(dir = extra, "appending to PATH for kubeconfig exec plugins");
                dirs.push(p);
            }
        }
    }
    dirs
}

fn harden_exec_plugins(kc: &mut Kubeconfig, prepend: &[PathBuf]) -> Vec<String> {
    let path = std::env::join_paths(exec_search_path(prepend))
        .ok()
        .and_then(|p| p.into_string().ok());
    let mut plugins = Vec::new();
    for auth in kc
        .auth_infos
        .iter_mut()
        .filter_map(|a| a.auth_info.as_mut())
    {
        let Some(exec) = auth.exec.as_mut() else {
            continue;
        };
        exec.interactive_mode = Some(ExecInteractiveMode::Never);
        if let Some(path) = &path {
            let env = exec.env.get_or_insert_with(Vec::new);
            if !env
                .iter()
                .any(|e| e.get("name").is_some_and(|n| n == "PATH"))
            {
                env.push(HashMap::from([
                    ("name".into(), "PATH".into()),
                    ("value".into(), path.clone()),
                ]));
            }
        }
        if let Some(cmd) = &exec.command
            && !plugins.contains(cmd)
        {
            plugins.push(cmd.clone());
        }
    }
    plugins
}

/// Host part of a server URL, without scheme, port-less path or userinfo.
pub fn server_host(server: &str) -> String {
    let rest = server.split_once("://").map_or(server, |(_, r)| r);
    let rest = rest.split('/').next().unwrap_or(rest);
    rest.rsplit('@').next().unwrap_or(rest).to_owned()
}

/// API server host and exec plugin (command, args, env) of a kubeconfig context.
fn kubeconfig_signals(
    kc: &Kubeconfig,
    context: &str,
) -> (String, String, Vec<String>, Vec<(String, String)>) {
    let ctx = kc
        .contexts
        .iter()
        .find(|c| c.name == context)
        .and_then(|c| c.context.as_ref());
    let server = ctx
        .and_then(|ctx| kc.clusters.iter().find(|cl| cl.name == ctx.cluster))
        .and_then(|cl| cl.cluster.as_ref())
        .and_then(|cl| cl.server.clone())
        .unwrap_or_default();
    let exec = ctx
        .and_then(|ctx| ctx.user.as_ref())
        .and_then(|u| kc.auth_infos.iter().find(|a| &a.name == u))
        .and_then(|a| a.auth_info.as_ref())
        .and_then(|a| a.exec.as_ref());
    (
        server_host(&server),
        exec.and_then(|e| e.command.clone()).unwrap_or_default(),
        exec.and_then(|e| e.args.clone()).unwrap_or_default(),
        exec.and_then(|e| e.env.as_ref())
            .into_iter()
            .flatten()
            .filter_map(|v| Some((v.get("name")?.clone(), v.get("value")?.clone())))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::RedactLevel;

    const KUBECONFIG: &str = r"
apiVersion: v1
kind: Config
current-context: dev
clusters:
- name: dev
  cluster: {server: 'https://127.0.0.1:6443'}
- name: prod
  cluster: {server: 'https://ABC.gr7.us-east-1.eks.amazonaws.com'}
contexts:
- name: dev
  context: {cluster: dev, user: dev, namespace: shop}
- name: prod
  context: {cluster: prod, user: prod}
users:
- name: dev
  user: {token: not-shown}
- name: prod
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: aws
      args: [eks, get-token, --cluster-name, prod]
";

    fn load(policy_contexts: &[&str]) -> (ClusterManager, Policy) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        std::fs::write(&path, KUBECONFIG).unwrap();
        let cm = ClusterManager::load(&LoadOptions {
            kubeconfig: Some(path),
            path_prepend: vec![PathBuf::from("/opt/plugins")],
            ..LoadOptions::default()
        })
        .unwrap();
        let ctx: Vec<String> = policy_contexts.iter().map(|s| (*s).to_owned()).collect();
        (
            cm,
            Policy::new(&ctx, &[], &[], RedactLevel::Standard, 24_000).unwrap(),
        )
    }

    /// Issue #71: once nodes were listed, contexts() reports what they say (here: a context
    /// that looks like EKS, whose nodes run on kind), still without an API call.
    #[test]
    fn contexts_use_the_last_node_check() {
        let (cm, policy) = load(&["prod"]);
        let prod = |cm: &ClusterManager| {
            cm.contexts(&policy)
                .into_iter()
                .find(|c| c.name == "prod")
                .unwrap()
        };
        let before = prod(&cm);
        assert_eq!(
            (
                before.provider,
                before.provider_source,
                before.provider_conflict.as_deref()
            ),
            (Some("eks"), FROM_KUBECONFIG, None)
        );
        let kind: Vec<Node> = serde_json::from_value(serde_json::json!([{"metadata": {"name": "n"}, "spec": {"providerID": "kind://docker/dev/n"}}])).unwrap();
        assert!(cm.detect_provider("prod", &kind).is_none());
        let after = prod(&cm);
        assert_eq!((after.provider, after.provider_source), (None, FROM_NODES));
        assert!(
            after
                .provider_conflict
                .unwrap()
                .ends_with("but its nodes run on kind")
        );
        assert_eq!(prod(&cm).provider_source, FROM_NODES, "kept");
        assert_eq!(
            cm.contexts(&policy)[0].provider_source,
            FROM_KUBECONFIG,
            "other contexts unchanged"
        );
    }

    #[test]
    fn default_context_only_unless_widened() {
        let (cm, policy) = load(&[]);
        let ctxs = cm.contexts(&policy);
        assert_eq!(ctxs.len(), 1);
        assert_eq!(ctxs[0].name, "dev");
        assert_eq!(ctxs[0].namespace, "shop");
        assert_eq!(ctxs[0].server_host, "127.0.0.1:6443");

        let (cm, policy) = load(&["*"]);
        let names: Vec<_> = cm
            .contexts(&policy)
            .into_iter()
            .map(|c| (c.name, c.provider))
            .collect();
        assert_eq!(names, [("dev".into(), None), ("prod".into(), Some("eks"))]);
    }

    #[tokio::test]
    async fn disallowed_context_is_refused_with_allowed_list() {
        let (cm, policy) = load(&[]);
        let err = cm
            .target(Some("prod"), &policy)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.contains("not allowed") && err.contains("Allowed contexts: dev"),
            "{err}"
        );
    }

    /// Issue #51: a name the kubeconfig does not have gets no `--contexts` advice.
    #[tokio::test]
    async fn unknown_context_is_reported_as_not_in_the_kubeconfig() {
        let (cm, policy) = load(&[]);
        let err = cm
            .target(Some("docker-desktop"), &policy)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.starts_with("context \"docker-desktop\" is not in the kubeconfig (")
                && err.contains("/config); allowed contexts: dev.")
                && !err.contains("--contexts"),
            "{err}"
        );
    }

    #[test]
    fn exec_plugins_are_non_interactive_with_extended_path() {
        let (cm, _) = load(&[]);
        assert_eq!(cm.exec_plugins, ["aws"]);
        let Source::Kubeconfig(kc) = &cm.source else {
            panic!()
        };
        let exec = kc.auth_infos[1]
            .auth_info
            .as_ref()
            .unwrap()
            .exec
            .as_ref()
            .unwrap();
        assert_eq!(exec.interactive_mode, Some(ExecInteractiveMode::Never));
        let path = &exec.env.as_ref().unwrap()[0];
        assert_eq!(path["name"], "PATH");
        assert!(path["value"].starts_with("/opt/plugins"));
    }

    #[test]
    fn server_host_strips_scheme_path_and_userinfo() {
        assert_eq!(
            server_host("https://u:p@example.com:6443/x"),
            "example.com:6443"
        );
        assert_eq!(server_host("example.com"), "example.com");
    }
}
