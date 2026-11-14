//! End-to-end tests: spawn the `k8s-mcp` binary and talk MCP over stdio with the rmcp client.
//!
//! Tests marked `#[ignore]` need the local kind cluster (`cargo xtask kind-up`) and run
//! with `cargo test -p k8s-mcp-server --test stdio -- --ignored`.
#![allow(clippy::unwrap_used)] // test helpers

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rmcp::model::{CallToolRequestParams, ReadResourceRequestParams};
use rmcp::service::RunningService;
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use rmcp::{RoleClient, ServiceExt};
use serde_json::{Value, json};

async fn spawn(args: &[&str]) -> RunningService<RoleClient, ()> {
    let bin = env!("CARGO_BIN_EXE_k8s-mcp");
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    let transport = TokioChildProcess::new(tokio::process::Command::new(bin).configure(|cmd| {
        cmd.args(&args)
            .env_remove("KUBECONFIG")
            .env("HOME", std::env::temp_dir());
    }))
    .unwrap();
    ().serve(transport).await.unwrap()
}

async fn call(
    client: &RunningService<RoleClient, ()>,
    tool: &str,
    args: Value,
) -> rmcp::model::CallToolResult {
    let params = CallToolRequestParams::new(tool.to_owned())
        .with_arguments(args.as_object().unwrap().clone());
    client.call_tool(params).await.unwrap()
}

fn text(r: &rmcp::model::CallToolResult) -> String {
    r.content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.clone()))
        .collect()
}

fn offline_kubeconfig(dir: &Path, server: &str, user: &str) -> PathBuf {
    let path = dir.join("kubeconfig");
    std::fs::write(
        &path,
        format!(
            "apiVersion: v1\nkind: Config\ncurrent-context: test\nclusters:\n- name: test\n  cluster: {{server: '{server}'}}\ncontexts:\n- name: test\n  context: {{cluster: test, user: test, namespace: shop}}\nusers:\n- name: test\n  user:\n{user}\n"
        ),
    )
    .unwrap();
    path
}

#[tokio::test]
async fn default_tool_list_is_read_only_and_well_formed() {
    let dir = tempfile::tempdir().unwrap();
    let kc = offline_kubeconfig(
        dir.path(),
        "https://127.0.0.1:1",
        "    token: not-a-real-token",
    );
    let client = spawn(&["--kubeconfig", kc.to_str().unwrap(), "--audit-log", "off"]).await;

    let tools = client.list_all_tools().await.unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(tools.len(), 13, "{names:?}");
    for t in &tools {
        let a = t
            .annotations
            .as_ref()
            .unwrap_or_else(|| panic!("{} has no annotations", t.name));
        assert_eq!(
            a.read_only_hint,
            Some(true),
            "{} must be readOnlyHint",
            t.name
        );
        assert_eq!(a.destructive_hint, Some(false), "{}", t.name);
        assert!(t.output_schema.is_some(), "{} has no output schema", t.name);
        assert_eq!(t.input_schema.get("type"), Some(&json!("object")));
    }
    for unwanted in ["delete_pod", "apply_manifest", "restart_workload", "exec"] {
        assert!(!names.contains(&unwanted));
    }

    assert_eq!(client.list_all_prompts().await.unwrap().len(), 2);
    assert_eq!(client.list_all_resources().await.unwrap().len(), 3);
    let policy = client
        .read_resource(ReadResourceRequestParams::new("k8s-mcp://policy"))
        .await
        .unwrap();
    let body = serde_json::to_string(&policy).unwrap();
    assert!(
        body.contains("never returned") && body.contains("\\\"write\\\": false"),
        "{body}"
    );

    // Works offline: the kubeconfig is read, credentials never shown.
    let r = call(&client, "list_contexts", json!({})).await;
    assert_ne!(r.is_error, Some(true));
    let t = text(&r);
    assert!(
        t.contains("127.0.0.1:1") && !t.contains("not-a-real-token"),
        "{t}"
    );

    // A cluster call fails with an actionable, redacted message instead of crashing.
    let r = call(&client, "cluster_overview", json!({})).await;
    assert_eq!(r.is_error, Some(true));
    assert!(
        text(&r).contains("could not reach the API server"),
        "{}",
        text(&r)
    );

    // Policy: other contexts and denied namespaces are refused.
    let r = call(&client, "list_events", json!({"context": "prod"})).await;
    assert!(text(&r).contains("not allowed"), "{}", text(&r));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn namespace_policy_refuses_other_namespaces() {
    let dir = tempfile::tempdir().unwrap();
    let kc = offline_kubeconfig(dir.path(), "https://127.0.0.1:1", "    token: t");
    let client = spawn(&[
        "--kubeconfig",
        kc.to_str().unwrap(),
        "--audit-log",
        "off",
        "--namespaces",
        "shop",
    ])
    .await;
    for (tool, args) in [
        ("list_events", json!({"namespace": "payments"})),
        ("get_logs", json!({"namespace": "payments", "pod": "x"})),
        (
            "diagnose_pod",
            json!({"namespace": "payments", "name": "x"}),
        ),
        (
            "diagnose_workload",
            json!({"namespace": "payments", "kind": "Deployment", "name": "x"}),
        ),
        ("check_permissions", json!({"namespace": "payments"})),
        ("top", json!({"namespace": "payments"})),
        ("find_problems", json!({"namespace": "payments"})),
    ] {
        let r = call(&client, tool, args).await;
        assert_eq!(r.is_error, Some(true), "{tool}");
        assert!(
            text(&r).contains("namespace \"payments\" is not allowed"),
            "{tool}: {}",
            text(&r)
        );
    }
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn audit_log_records_calls_with_redacted_args() {
    let dir = tempfile::tempdir().unwrap();
    let kc = offline_kubeconfig(dir.path(), "https://127.0.0.1:1", "    token: t");
    let audit = dir.path().join("audit.jsonl");
    let client = spawn(&[
        "--kubeconfig",
        kc.to_str().unwrap(),
        "--audit-log",
        audit.to_str().unwrap(),
    ])
    .await;
    let _ = call(
        &client,
        "get_logs",
        json!({"pod": "web", "grep": "password=hunter2"}),
    )
    .await;
    client.cancel().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let log = std::fs::read_to_string(&audit).unwrap();
    let rec: Value = serde_json::from_str(log.lines().next().unwrap()).unwrap();
    assert_eq!(rec["tool"], "get_logs");
    assert_eq!(rec["context"], "test");
    assert_eq!(rec["result"], "error");
    assert!(!log.contains("hunter2"), "{log}");
}

/// A fake exec auth plugin, found only through `--path-prepend`, supplies the bearer token.
#[cfg(unix)]
#[tokio::test]
async fn exec_plugin_token_is_used_via_path_prepend() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let bin_dir = dir.path().join("plugins");
    std::fs::create_dir(&bin_dir).unwrap();
    let plugin = bin_dir.join("fake-auth-plugin");
    std::fs::write(
        &plugin,
        "#!/bin/sh\necho '{\"apiVersion\":\"client.authentication.k8s.io/v1beta1\",\"kind\":\"ExecCredential\",\"status\":{\"token\":\"fake-exec-token\"}}'\n",
    )
    .unwrap();
    std::fs::set_permissions(&plugin, std::fs::Permissions::from_mode(0o755)).unwrap();

    // Minimal HTTP API server: /version succeeds, everything else is 403. Records auth headers.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen2 = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut s = stream;
            let mut buf = vec![0u8; 16384];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let auth = req
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                .unwrap_or("")
                .to_owned();
            seen2.lock().unwrap().push(auth);
            let (code, body) = if req.starts_with("GET /version") {
                ("200 OK", r#"{"major":"1","minor":"37","gitVersion":"v1.37.0","gitCommit":"","gitTreeState":"","buildDate":"","goVersion":"","compiler":"","platform":""}"#.to_owned())
            } else {
                ("403 Forbidden", r#"{"kind":"Status","apiVersion":"v1","status":"Failure","message":"forbidden","reason":"Forbidden","code":403}"#.to_owned())
            };
            let _ = write!(
                s,
                "HTTP/1.1 {code}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });

    let user = "    exec:\n      apiVersion: client.authentication.k8s.io/v1beta1\n      command: fake-auth-plugin\n      interactiveMode: IfAvailable";
    let kc = offline_kubeconfig(dir.path(), &format!("http://{addr}"), user);
    let client = spawn(&[
        "--kubeconfig",
        kc.to_str().unwrap(),
        "--audit-log",
        "off",
        "--path-prepend",
        bin_dir.to_str().unwrap(),
    ])
    .await;
    let r = call(&client, "cluster_overview", json!({})).await;
    assert_ne!(r.is_error, Some(true), "{}", text(&r));
    assert!(text(&r).contains("v1.37.0"), "{}", text(&r));
    assert!(
        text(&r).contains("UNAVAILABLE EVIDENCE"),
        "forbidden reads are reported: {}",
        text(&r)
    );
    client.cancel().await.unwrap();
    let seen = seen.lock().unwrap();
    assert!(!seen.is_empty());
    assert!(
        seen.iter().all(|a| a.contains("Bearer fake-exec-token")),
        "{seen:?}"
    );
}

fn kind_kubeconfig() -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.dev/kubeconfig");
    assert!(p.exists(), "run `cargo xtask kind-up` first");
    p.canonicalize().unwrap().display().to_string()
}

#[tokio::test]
#[ignore = "needs the local kind cluster (cargo xtask kind-up)"]
async fn kind_cluster_overview_and_find_problems() {
    let kc = kind_kubeconfig();
    let client = spawn(&[
        "--kubeconfig",
        &kc,
        "--context",
        "kind-k8s-mcp-dev",
        "--audit-log",
        "off",
    ])
    .await;
    let r = call(&client, "cluster_overview", json!({})).await;
    assert_ne!(r.is_error, Some(true), "{}", text(&r));
    assert!(text(&r).contains("nodes Ready"), "{}", text(&r));
    let r = call(&client, "find_problems", json!({})).await;
    assert_ne!(r.is_error, Some(true), "{}", text(&r));
    client.cancel().await.unwrap();
}
