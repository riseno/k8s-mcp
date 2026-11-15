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

/// How HTTP callers prove who they are.
pub enum Auth {
    /// Validate bearer tokens with the TokenReview API, as the server's own identity.
    TokenReview {
        client: kube::Client,
        cache: Mutex<HashMap<String, (Instant, String)>>,
    },
    /// One shared bearer token.
    Static(String),
    /// No authentication (loopback listeners only).
    None,
}

impl Auth {
    /// Check the flags: `none` only on loopback, `static` needs a non-empty token file.
    pub fn new(
        mode: &str,
        token_file: Option<&std::path::Path>,
        listen: SocketAddr,
        client: kube::Client,
    ) -> anyhow::Result<Self> {
        Ok(match mode {
            "tokenreview" => Self::TokenReview {
                client,
                cache: Mutex::default(),
            },
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

    /// The caller's identity, `None` when the token is missing or invalid.
    async fn caller(&self, token: Option<&str>) -> anyhow::Result<Option<String>> {
        match (self, token) {
            (Self::None, _) => Ok(Some("anonymous".into())),
            (_, None) => Ok(None),
            (Self::Static(want), Some(t)) => {
                Ok(same(want.as_bytes(), t.as_bytes()).then(|| "static-token".into()))
            }
            (Self::TokenReview { client, cache }, Some(t)) => review(client, cache, t).await,
        }
    }
}

/// Constant-time comparison, so response timing does not reveal how much of a token matched.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn review(
    client: &kube::Client,
    cache: &Mutex<HashMap<String, (Instant, String)>>,
    token: &str,
) -> anyhow::Result<Option<String>> {
    let cached = cache.lock().ok().and_then(|c| c.get(token).cloned());
    if let Some((at, user)) = cached
        && at.elapsed() < REVIEW_TTL
    {
        return Ok(Some(user));
    }
    let request = TokenReview {
        spec: TokenReviewSpec {
            token: Some(token.to_owned()),
            ..TokenReviewSpec::default()
        },
        ..TokenReview::default()
    };
    let reviewed = Api::<TokenReview>::all(client.clone())
        .create(&PostParams::default(), &request)
        .await
        .context("create a TokenReview (the server's ServiceAccount needs `create` on tokenreviews.authentication.k8s.io)")?;
    let user = reviewed
        .status
        .filter(|s| s.authenticated == Some(true))
        .and_then(|s| s.user)
        .and_then(|u| u.username);
    if let (Some(user), Ok(mut c)) = (&user, cache.lock()) {
        if c.len() >= REVIEW_CACHE {
            c.clear();
        }
        c.insert(token.to_owned(), (Instant::now(), user.clone()));
    }
    Ok(user)
}

async fn authenticate(State(auth): State<Arc<Auth>>, mut req: Request, next: Next) -> Response {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim);
    match auth.caller(token).await {
        Ok(Some(caller)) => {
            req.extensions_mut().insert(Caller(caller));
            next.run(req).await
        }
        Ok(None) => (
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
    let mcp = StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    let ct = mcp.config.cancellation_token.clone();
    let app = Router::new()
        .nest_service("/mcp", mcp)
        .layer(middleware::from_fn_with_state(Arc::new(auth), authenticate))
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
        let tools = message(resp).await["result"]["tools"]
            .as_array()
            .unwrap()
            .len();
        assert_eq!(tools, 13);

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
        assert!(Auth::new("none", None, "127.0.0.1:8080".parse().unwrap(), client()).is_ok());
        let err = Auth::new("none", None, "0.0.0.0:8080".parse().unwrap(), client())
            .err()
            .unwrap();
        assert!(
            err.to_string().contains("only allowed on a loopback"),
            "{err}"
        );
        assert!(Auth::new("static", None, "0.0.0.0:8080".parse().unwrap(), client()).is_err());
    }
}
