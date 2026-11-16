//! Streamable HTTP transport for in-cluster use: MCP at `/mcp` behind bearer auth, plus
//! unauthenticated `/healthz` and `/readyz` for probes. rmcp checks `Host` and `Origin`
//! (DNS-rebinding protection) and caps the request body.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use axum::Router;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use k8s_mcp_core::policy::Patterns;
use k8s_openapi::api::authentication::v1::{TokenReview, TokenReviewSpec};
use kube::api::{Api, PostParams};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

use crate::server::{Caller, K8sMcp};

/// How long a successful TokenReview is trusted before the token is checked again.
const REVIEW_TTL: Duration = Duration::from_secs(60);
/// Cached reviews kept at most; the cache is emptied when full.
const REVIEW_CACHE: usize = 1024;
/// Largest accepted request body (tool arguments are small).
const MAX_BODY: usize = 1 << 20;

/// Who a TokenReview says the caller is.
#[derive(Clone)]
pub struct Identity {
    username: String,
    groups: Vec<String>,
}

/// `--allowed-callers`: globs over the TokenReview username, or `group:<glob>` over its groups.
pub struct Callers {
    users: Patterns,
    groups: Patterns,
}

impl Callers {
    /// `None` (every authenticated caller) when no pattern is given.
    pub fn new(patterns: &[String]) -> anyhow::Result<Option<Self>> {
        let patterns: Vec<&str> = patterns
            .iter()
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .collect();
        if patterns.is_empty() {
            return Ok(None);
        }
        let (groups, users): (Vec<&str>, Vec<&str>) =
            patterns.iter().partition(|p| p.starts_with("group:"));
        let owned = |v: Vec<&str>, prefix: &str| -> Vec<String> {
            v.iter()
                .map(|p| p.trim_start_matches(prefix).to_owned())
                .collect()
        };
        Ok(Some(Self {
            users: Patterns::new(&owned(users, ""))?,
            groups: Patterns::new(&owned(groups, "group:"))?,
        }))
    }

    fn allows(&self, id: &Identity) -> bool {
        self.users.is_match(&id.username) || id.groups.iter().any(|g| self.groups.is_match(g))
    }
}

/// How HTTP callers prove who they are.
#[allow(clippy::large_enum_variant)] // one value per process
pub enum Auth {
    /// Validate bearer tokens with the TokenReview API, as the server's own identity.
    TokenReview {
        client: kube::Client,
        /// Audiences the token must be minted for (`--auth-audience`); empty: the API server's.
        audiences: Vec<String>,
        callers: Option<Callers>,
        cache: Mutex<HashMap<String, (Instant, Identity)>>,
    },
    /// One shared bearer token.
    Static(String),
    /// No authentication (loopback listeners only).
    None,
}

/// The outcome of authenticating one request.
enum Verdict {
    /// Authenticated and allowed, as this caller.
    Allowed(String),
    /// No token, or one that is not valid (401).
    Unauthenticated,
    /// Authenticated, but not in `--allowed-callers` (403).
    Refused(String),
}

impl Auth {
    /// Check the flags: `none` only on loopback, `static` needs a non-empty token file, and
    /// audiences and allowed callers only apply to `tokenreview`.
    pub fn new(
        mode: &str,
        token_file: Option<&std::path::Path>,
        listen: SocketAddr,
        client: kube::Client,
        audiences: &[String],
        allowed_callers: &[String],
    ) -> anyhow::Result<Self> {
        let audiences: Vec<String> = audiences
            .iter()
            .map(|a| a.trim().to_owned())
            .filter(|a| !a.is_empty())
            .collect();
        let callers = Callers::new(allowed_callers)?;
        if mode != "tokenreview" && (!audiences.is_empty() || callers.is_some()) {
            bail!("--auth-audience and --allowed-callers need --auth tokenreview, not {mode}");
        }
        Ok(match mode {
            "tokenreview" => {
                if audiences.is_empty() {
                    tracing::warn!(
                        "--auth tokenreview without --auth-audience accepts any token for the API server's audience, including the ServiceAccount token every pod gets by default; set --auth-audience (the Helm chart uses k8s-mcp)"
                    );
                }
                Self::TokenReview {
                    client,
                    audiences,
                    callers,
                    cache: Mutex::default(),
                }
            }
            "static" => {
                let path = token_file.context("--auth static needs --auth-token-file <path>")?;
                let token = std::fs::read_to_string(path)
                    .with_context(|| format!("read the auth token file {}", path.display()))?;
                let token = token.trim();
                if token.is_empty() {
                    bail!("the auth token file {} is empty", path.display());
                }
                Self::Static(token.to_owned())
            }
            "none" if listen.ip().is_loopback() => Self::None,
            "none" => bail!(
                "--auth none is only allowed on a loopback address, not {listen}; use --auth tokenreview or --auth static"
            ),
            other => bail!("unknown --auth mode {other:?}; use tokenreview, static or none"),
        })
    }

    /// Who the caller is, and whether it may in.
    async fn verdict(&self, token: Option<&str>) -> anyhow::Result<Verdict> {
        Ok(match (self, token) {
            (Self::None, _) => Verdict::Allowed("anonymous".into()),
            (Self::Static(want), Some(t)) if same(want.as_bytes(), t.as_bytes()) => {
                Verdict::Allowed("static-token".into())
            }
            (_, None) | (Self::Static(_), Some(_)) => Verdict::Unauthenticated,
            (
                Self::TokenReview {
                    client,
                    audiences,
                    callers,
                    cache,
                },
                Some(t),
            ) => match review(client, audiences, cache, t).await? {
                None => Verdict::Unauthenticated,
                Some(id) if callers.as_ref().is_some_and(|c| !c.allows(&id)) => {
                    Verdict::Refused(id.username)
                }
                Some(id) => Verdict::Allowed(id.username),
            },
        })
    }
}

/// Constant-time comparison, so response timing does not reveal how much of a token matched.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn review(
    client: &kube::Client,
    audiences: &[String],
    cache: &Mutex<HashMap<String, (Instant, Identity)>>,
    token: &str,
) -> anyhow::Result<Option<Identity>> {
    let cached = cache.lock().ok().and_then(|c| c.get(token).cloned());
    if let Some((at, id)) = cached
        && at.elapsed() < REVIEW_TTL
    {
        return Ok(Some(id));
    }
    let request = TokenReview {
        spec: TokenReviewSpec {
            token: Some(token.to_owned()),
            audiences: (!audiences.is_empty()).then(|| audiences.to_vec()),
        },
        ..TokenReview::default()
    };
    let reviewed = Api::<TokenReview>::all(client.clone())
        .create(&PostParams::default(), &request)
        .await
        .context("create a TokenReview (the server's ServiceAccount needs `create` on tokenreviews.authentication.k8s.io)")?;
    let id = reviewed
        .status
        .filter(|s| s.authenticated == Some(true))
        // An authenticator that ignores audiences answers with none: the token was only
        // checked against the API server's own audience.
        .filter(|s| {
            audiences.is_empty() || s.audiences.iter().flatten().any(|a| audiences.contains(a))
        })
        .and_then(|s| s.user)
        .and_then(|u| {
            Some(Identity {
                username: u.username?,
                groups: u.groups.unwrap_or_default(),
            })
        });
    if let (Some(id), Ok(mut c)) = (&id, cache.lock()) {
        if c.len() >= REVIEW_CACHE {
            c.clear();
        }
        c.insert(token.to_owned(), (Instant::now(), id.clone()));
    }
    Ok(id)
}

/// The middleware's state: who may call, and where refusals are audited.
struct Gate {
    auth: Auth,
    server: K8sMcp,
}

async fn authenticate(State(gate): State<Arc<Gate>>, mut req: Request, next: Next) -> Response {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim);
    match gate.auth.verdict(token).await {
        Ok(Verdict::Allowed(caller)) => {
            req.extensions_mut().insert(Caller(caller));
            next.run(req).await
        }
        Ok(Verdict::Refused(caller)) => {
            gate.server.audit_refused(&caller);
            (
                StatusCode::FORBIDDEN,
                "this identity is not in the server's --allowed-callers\n",
            )
                .into_response()
        }
        Ok(Verdict::Unauthenticated) => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "missing or invalid bearer token\n",
        )
            .into_response(),
        Err(e) => {
            tracing::warn!("token validation failed: {e:#}");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "could not validate the bearer token; see the server log\n",
            )
                .into_response()
        }
    }
}

/// Ready when the API server answers within 3 seconds.
async fn readyz(client: kube::Client) -> StatusCode {
    match tokio::time::timeout(Duration::from_secs(3), client.apiserver_version()).await {
        Ok(Ok(_)) => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// The app, and a function that ends open MCP streams (call it on shutdown).
pub fn router(
    server: K8sMcp,
    auth: Auth,
    client: kube::Client,
    allowed_hosts: &[String],
    allowed_origins: &[String],
) -> (Router, impl FnOnce() + Send + 'static) {
    let mut config = StreamableHttpServerConfig::default()
        .with_allowed_origins(allowed_origins)
        .enforce_origin_validation()
        .with_max_request_body_bytes(MAX_BODY);
    if !allowed_hosts.is_empty() {
        config = config.with_allowed_hosts(allowed_hosts);
    }
    let gate = Arc::new(Gate {
        auth,
        server: server.clone(),
    });
    let mcp = StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    let ct = mcp.config.cancellation_token.clone();
    let app = Router::new()
        .nest_service("/mcp", mcp)
        .layer(middleware::from_fn_with_state(gate, authenticate))
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/readyz", get(move || readyz(client.clone())));
    (app, move || ct.cancel())
}

/// Serve until SIGTERM or Ctrl-C.
pub async fn serve(
    listen: SocketAddr,
    app: Router,
    stop: impl FnOnce() + Send + 'static,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("listen on {listen}"))?;
    tracing::info!(
        "k8s-mcp {} serving MCP on http://{listen}/mcp",
        crate::server::VERSION
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            crate::shutdown_signal().await;
            stop();
        })
        .await
        .context("HTTP server failed")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use k8s_mcp_core::audit::Audit;
    use k8s_mcp_core::cluster::ClusterManager;
    use k8s_mcp_core::policy::Policy;
    use k8s_mcp_testkit::mock::MockApi;
    use k8s_mcp_tools::Ctx;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::*;

    const TOKEN: &str = "s3cret-token";

    fn app(
        auth: impl FnOnce(kube::Client) -> Auth,
        mock: &k8s_mcp_testkit::mock::Mock,
        audit: &str,
    ) -> Router {
        let ctx = Ctx::new(
            Arc::new(ClusterManager::fixed(mock.client.clone(), "test", "shop")),
            Arc::new(Policy::permissive()),
        );
        let audit = Arc::new(Audit::open(audit).unwrap());
        let server = K8sMcp::new(ctx, audit, &["core".into(), "diagnose".into()]);
        router(
            server,
            auth(mock.client.clone()),
            mock.client.clone(),
            &[],
            &[],
        )
        .0
    }

    fn post(body: &Value, token: Option<&str>, session: Option<&str>) -> Request<Body> {
        let mut r = Request::post("/mcp")
            .header(header::HOST, "localhost:8080")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream");
        if let Some(t) = token {
            r = r.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        if let Some(s) = session {
            r = r.header("mcp-session-id", s);
        }
        r.body(Body::from(body.to_string())).unwrap()
    }

    fn initialize() -> Value {
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0"}}})
    }

    /// The JSON-RPC message in a response (plain JSON or the last SSE `data:` line).
    async fn message(resp: Response) -> Value {
        let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        let data = text
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(str::trim)
            .rfind(|l| !l.is_empty())
            .unwrap_or(&text)
            .to_owned();
        serde_json::from_str(&data).unwrap_or(Value::Null)
    }

    #[tokio::test]
    async fn requests_without_a_valid_token_get_401() {
        let mock = MockApi::new().start();
        let app = app(|_| Auth::Static(TOKEN.into()), &mock, "off");
        for token in [None, Some("wrong"), Some("s3cret-tokeN")] {
            let resp = app
                .clone()
                .oneshot(post(&initialize(), token, None))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{token:?}");
            assert_eq!(resp.headers()[header::WWW_AUTHENTICATE], "Bearer");
        }
    }

    #[tokio::test]
    async fn bad_origin_and_host_get_403() {
        let mock = MockApi::new().start();
        let app = app(|_| Auth::Static(TOKEN.into()), &mock, "off");
        let mut req = post(&initialize(), Some(TOKEN), None);
        req.headers_mut()
            .insert(header::ORIGIN, "https://evil.example".parse().unwrap());
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let mut req = post(&initialize(), Some(TOKEN), None);
        req.headers_mut()
            .insert(header::HOST, "evil.example".parse().unwrap());
        assert_eq!(
            app.oneshot(req).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }

    /// A static-token client lists tools and calls one; the audit log names the caller.
    #[tokio::test]
    async fn authenticated_client_calls_a_tool_and_is_audited() {
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit.jsonl");
        let mock = MockApi::new().start();
        let app = app(
            |_| Auth::Static(TOKEN.into()),
            &mock,
            audit.to_str().unwrap(),
        );

        let resp = app
            .clone()
            .oneshot(post(&initialize(), Some(TOKEN), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let session = resp.headers()["mcp-session-id"]
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            message(resp).await["result"]["serverInfo"]["name"],
            "k8s-mcp"
        );
        let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        let resp = app
            .clone()
            .oneshot(post(&note, Some(TOKEN), Some(&session)))
            .await
            .unwrap();
        assert!(resp.status().is_success(), "{}", resp.status());

        let list = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
        let resp = app
            .clone()
            .oneshot(post(&list, Some(TOKEN), Some(&session)))
            .await
            .unwrap();
        // The exact tool list is covered by the stdio test; here, that HTTP serves it.
        let tools = message(resp).await["result"]["tools"].clone();
        let names: Vec<&str> = tools
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        assert!(
            names.contains(&"list_contexts") && names.contains(&"diagnose_pod"),
            "{names:?}"
        );

        let call = json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_contexts", "arguments": {}}});
        let resp = app
            .oneshot(post(&call, Some(TOKEN), Some(&session)))
            .await
            .unwrap();
        assert_eq!(message(resp).await["result"]["isError"], false);

        let mut log = String::new();
        for _ in 0..50 {
            log = std::fs::read_to_string(&audit).unwrap_or_default();
            if !log.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let rec: Value = serde_json::from_str(log.lines().next().unwrap()).unwrap();
        assert_eq!(rec["tool"], "list_contexts");
        assert_eq!(rec["caller"], "static-token");
        assert_eq!(rec["client"], "test-client/1.0");
        assert!(!log.contains(TOKEN));
    }

    #[tokio::test]
    async fn tokenreview_accepts_only_authenticated_tokens() {
        let path = "/apis/authentication.k8s.io/v1/tokenreviews";
        let review = |authenticated: bool| {
            json!({"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "spec": {},
                "status": {"authenticated": authenticated, "user": {"username": "system:serviceaccount:shop:ai"}}})
        };
        let tokenreview = |client| Auth::TokenReview {
            client,
            audiences: Vec::new(),
            callers: None,
            cache: Mutex::default(),
        };

        let mock = MockApi::new()
            .route("POST", path, 201, review(true))
            .start();
        let resp = app(tokenreview, &mock, "off")
            .oneshot(post(&initialize(), Some("sa-token"), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mock = MockApi::new()
            .route("POST", path, 201, review(false))
            .start();
        let resp = app(tokenreview, &mock, "off")
            .oneshot(post(&initialize(), Some("sa-token"), None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Issue #52: with --auth-audience, only tokens the API server confirms for that audience
    /// pass. An answer without audiences means the token was only checked for the API server.
    #[tokio::test]
    async fn tokenreview_with_an_audience_needs_it_confirmed() {
        let path = "/apis/authentication.k8s.io/v1/tokenreviews";
        let review = |audiences: Value| {
            json!({"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "spec": {},
                "status": {"authenticated": true, "audiences": audiences, "user": {"username": "system:serviceaccount:shop:ai"}}})
        };
        let tokenreview = |client| {
            Auth::new(
                "tokenreview",
                None,
                "0.0.0.0:8080".parse().unwrap(),
                client,
                &["k8s-mcp".into()],
                &[],
            )
            .unwrap()
        };
        for (audiences, want) in [
            (json!(["k8s-mcp"]), StatusCode::OK),
            (json!(null), StatusCode::UNAUTHORIZED),
            (
                json!(["https://kubernetes.default.svc"]),
                StatusCode::UNAUTHORIZED,
            ),
        ] {
            let mock = MockApi::new()
                .route("POST", path, 201, review(audiences.clone()))
                .start();
            let resp = app(tokenreview, &mock, "off")
                .oneshot(post(&initialize(), Some("sa-token"), None))
                .await
                .unwrap();
            assert_eq!(resp.status(), want, "{audiences}");
        }
    }

    /// Issue #52: --allowed-callers matches the username or a group; others get 403, audited.
    #[tokio::test]
    async fn callers_outside_the_allow_list_get_403_and_an_audit_record() {
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit.jsonl");
        let mock = MockApi::new()
            .route("POST", "/apis/authentication.k8s.io/v1/tokenreviews", 201, json!({
                "apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "spec": {},
                "status": {"authenticated": true, "user": {"username": "system:serviceaccount:shop:ai",
                    "groups": ["system:serviceaccounts", "sre"]}}}))
            .start();
        let with = |callers: &[&str]| {
            let callers: Vec<String> = callers.iter().map(|c| (*c).to_owned()).collect();
            move |client| {
                Auth::new(
                    "tokenreview",
                    None,
                    "0.0.0.0:8080".parse().unwrap(),
                    client,
                    &[],
                    &callers,
                )
                .unwrap()
            }
        };
        for (callers, want) in [
            (&["system:serviceaccount:shop:*"][..], StatusCode::OK),
            (
                &["system:serviceaccount:platform:*", "group:sre"],
                StatusCode::OK,
            ),
            (
                &["system:serviceaccount:platform:*", "group:admins"],
                StatusCode::FORBIDDEN,
            ),
        ] {
            let resp = app(with(callers), &mock, audit.to_str().unwrap())
                .oneshot(post(&initialize(), Some("sa-token"), None))
                .await
                .unwrap();
            assert_eq!(resp.status(), want, "{callers:?}");
        }
        let mut log = String::new();
        for _ in 0..50 {
            log = std::fs::read_to_string(&audit).unwrap_or_default();
            if log.contains("refused") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let rec: Value = serde_json::from_str(log.lines().last().unwrap()).unwrap();
        assert_eq!(
            (&rec["result"], &rec["caller"], &rec["tool"]),
            (
                &json!("refused"),
                &json!("system:serviceaccount:shop:ai"),
                &json!("-")
            )
        );
        assert!(!log.contains("sa-token"));
    }

    #[tokio::test]
    async fn probes_need_no_token() {
        let version = json!({"major": "1", "minor": "37", "gitVersion": "v1.37.0", "gitCommit": "", "gitTreeState": "", "buildDate": "", "goVersion": "", "compiler": "", "platform": ""});
        let mock = MockApi::new().get("/version", version).start();
        let up = app(|_| Auth::Static(TOKEN.into()), &mock, "off");
        for path in ["/healthz", "/readyz"] {
            let req = Request::get(path).body(Body::empty()).unwrap();
            assert_eq!(
                up.clone().oneshot(req).await.unwrap().status(),
                StatusCode::OK,
                "{path}"
            );
        }
        // No /version route: the API server "is down".
        let mock = MockApi::new().start();
        let down = app(|_| Auth::None, &mock, "off");
        let req = Request::get("/readyz").body(Body::empty()).unwrap();
        assert_eq!(
            down.oneshot(req).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn auth_none_is_refused_off_loopback() {
        let client = || {
            kube::Client::try_from(kube::Config::new("http://127.0.0.1:1".parse().unwrap()))
                .unwrap()
        };
        assert!(
            Auth::new(
                "none",
                None,
                "127.0.0.1:8080".parse().unwrap(),
                client(),
                &[],
                &[]
            )
            .is_ok()
        );
        let err = Auth::new(
            "none",
            None,
            "0.0.0.0:8080".parse().unwrap(),
            client(),
            &[],
            &[],
        )
        .err()
        .unwrap();
        assert!(
            err.to_string().contains("only allowed on a loopback"),
            "{err}"
        );
        assert!(
            Auth::new(
                "static",
                None,
                "0.0.0.0:8080".parse().unwrap(),
                client(),
                &[],
                &[]
            )
            .is_err()
        );
        // Audiences and allowed callers only mean something to TokenReview.
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("token");
        std::fs::write(&token, "t").unwrap();
        let err = Auth::new(
            "static",
            Some(&token),
            "0.0.0.0:8080".parse().unwrap(),
            client(),
            &["k8s-mcp".into()],
            &[],
        )
        .err()
        .unwrap();
        assert!(err.to_string().contains("need --auth tokenreview"), "{err}");
    }
}
