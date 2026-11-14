//! A mock Kubernetes API server for tool tests, built on `tower_test::mock::pair` (the
//! documented kube-rs testing pattern). Routes match on method and path (query ignored);
//! unmatched requests get a 404 `Status`. Every request is recorded for assertions.

use std::sync::{Arc, Mutex};

use kube::client::Body;
use serde_json::{Value, json};

/// A canned response.
#[derive(Clone)]
struct Route {
    method: &'static str,
    path: String,
    status: u16,
    body: Value,
}

/// Builder for a mock API server.
#[derive(Default)]
pub struct MockApi {
    routes: Vec<Route>,
}

/// A running mock: a kube client wired to it and the request log.
pub struct Mock {
    /// Client whose requests the mock answers.
    pub client: kube::Client,
    /// `METHOD path?query` of every request, in order.
    pub requests: Arc<Mutex<Vec<String>>>,
}

impl MockApi {
    /// An empty mock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Answer `GET path` with 200 and `body` (a JSON string body is sent as plain text,
    /// which is how the logs endpoint responds).
    #[must_use]
    pub fn get(self, path: &str, body: Value) -> Self {
        self.route("GET", path, 200, body)
    }

    /// Answer `method path` with `status` and `body`.
    #[must_use]
    pub fn route(mut self, method: &'static str, path: &str, status: u16, body: Value) -> Self {
        self.routes.push(Route {
            method,
            path: path.to_owned(),
            status,
            body,
        });
        self
    }

    /// Answer `GET path` with 403 Forbidden.
    #[must_use]
    pub fn forbid(self, path: &str) -> Self {
        let body = status(403, "Forbidden", "forbidden by RBAC (mock)");
        self.route("GET", path, 403, body)
    }

    /// Answer `GET /api/v1/.../items` style list paths with an object list of `items`.
    #[must_use]
    pub fn list(self, path: &str, items: impl Into<Vec<Value>>) -> Self {
        let items = items.into();
        self.get(
            path,
            json!({"apiVersion": "v1", "kind": "List", "metadata": {}, "items": items}),
        )
    }

    /// Start serving. Must be called inside a Tokio runtime.
    pub fn start(self) -> Mock {
        let (svc, mut handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let log = requests.clone();
        tokio::spawn(async move {
            while let Some((req, send)) = handle.next_request().await {
                let method = req.method().as_str().to_owned();
                let path = req.uri().path().to_owned();
                let query = req
                    .uri()
                    .query()
                    .map(|q| format!("?{q}"))
                    .unwrap_or_default();
                log.lock().unwrap().push(format!("{method} {path}{query}"));
                let route = self
                    .routes
                    .iter()
                    .find(|r| r.method == method && r.path == path);
                let (code, body) = match route {
                    Some(r) => (r.status, r.body.clone()),
                    None => (
                        404,
                        status(
                            404,
                            "NotFound",
                            &format!("{path} not found (no mock route)"),
                        ),
                    ),
                };
                let bytes = match body {
                    Value::String(s) => s.into_bytes(),
                    v => serde_json::to_vec(&v).unwrap(),
                };
                send.send_response(
                    http::Response::builder()
                        .status(code)
                        .body(Body::from(bytes))
                        .unwrap(),
                );
            }
        });
        Mock {
            client: kube::Client::new(svc, "default"),
            requests,
        }
    }
}

/// A Kubernetes `Status` error body.
pub fn status(code: u16, reason: &str, message: &str) -> Value {
    json!({"apiVersion": "v1", "kind": "Status", "status": "Failure", "reason": reason, "message": message, "code": code})
}

/// Discovery responses for the core group and `apps/v1`, enough for kind resolution.
#[must_use]
pub fn with_discovery(mock: MockApi) -> MockApi {
    let res = |name: &str, kind: &str, namespaced: bool, short: &[&str]| json!({"name": name, "singularName": "", "kind": kind, "namespaced": namespaced, "shortNames": short, "verbs": ["get", "list", "watch"]});
    mock.get(
        "/api/v1",
        json!({"kind": "APIResourceList", "groupVersion": "v1", "resources": [
            res("pods", "Pod", true, &["po"]),
            res("pods/log", "Pod", true, &[]),
            res("secrets", "Secret", true, &[]),
            res("configmaps", "ConfigMap", true, &["cm"]),
            res("events", "Event", true, &["ev"]),
            res("nodes", "Node", false, &["no"]),
            res("namespaces", "Namespace", false, &["ns"]),
            res("persistentvolumeclaims", "PersistentVolumeClaim", true, &["pvc"]),
        ]}),
    )
    .get(
        "/apis",
        json!({"kind": "APIGroupList", "groups": [
            {"name": "apps", "versions": [{"groupVersion": "apps/v1", "version": "v1"}], "preferredVersion": {"groupVersion": "apps/v1", "version": "v1"}}
        ]}),
    )
    .get(
        "/apis/apps/v1",
        json!({"kind": "APIResourceList", "groupVersion": "apps/v1", "resources": [
            res("deployments", "Deployment", true, &["deploy"]),
            res("replicasets", "ReplicaSet", true, &["rs"]),
        ]}),
    )
}
