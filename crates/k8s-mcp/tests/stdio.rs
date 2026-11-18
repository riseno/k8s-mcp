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
            "apiVersion: v1\nkind: Config\ncurrent-context: test\nclusters:\n- name: test\n  cluster: {{server: '{server}'}}\ncontexts:\n- name: test\n  context: {{cluster: test, user: test, namespace: shop}}\n- name: prod\n  context: {{cluster: test, user: test}}\nusers:\n- name: test\n  user:\n{user}\n"
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
    assert_eq!(tools.len(), 20, "{names:?}");
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

    assert_eq!(client.list_all_prompts().await.unwrap().len(), 5);
    assert_eq!(client.list_all_resources().await.unwrap().len(), 3);
    let templates = client.list_all_resource_templates().await.unwrap();
    assert_eq!(
        templates[0].uri_template,
        "k8s-mcp://cluster/{context}/overview"
    );
    // Through the tool path: the context policy applies to the template too.
    let err = client
        .read_resource(ReadResourceRequestParams::new(
            "k8s-mcp://cluster/prod/overview",
        ))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not allowed"), "{err}");
    // Names the kubeconfig does not have get no --contexts advice (issue #51), after the
    // template value is percent-decoded.
    for (uri, context) in [
        (
            "k8s-mcp://cluster/docker-desktop/overview",
            "docker-desktop",
        ),
        (
            "k8s-mcp://cluster/..%2F..%2Fpolicy/overview",
            "../../policy",
        ),
    ] {
        let err = client
            .read_resource(ReadResourceRequestParams::new(uri))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(&format!("context {context:?} is not in the kubeconfig"))
                && err.contains("allowed contexts: test.")
                && !err.contains("--contexts"),
            "{err}"
        );
    }
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
    // riseno/k8s-mcp#16: the client's name/version is recorded, not null.
    assert!(
        rec["client"].as_str().is_some_and(|c| c.contains('/')),
        "{rec}"
    );
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

/// A fake exec auth plugin `name` in `dir` that runs `body`.
#[cfg(unix)]
fn fake_plugin(dir: &Path, name: &str, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A server whose only context authenticates with the fake plugin `command` (with an `env:`
/// secret), found through `--path-prepend dir`.
#[cfg(unix)]
async fn spawn_with_plugin(dir: &Path, command: &str) -> RunningService<RoleClient, ()> {
    let user = format!(
        "    exec:\n      apiVersion: client.authentication.k8s.io/v1beta1\n      command: {command}\n      env:\n      - {{name: AZURE_CLIENT_SECRET, value: envsecret456}}"
    );
    let kc = offline_kubeconfig(dir, "https://127.0.0.1:1", &user);
    spawn(&[
        "--kubeconfig",
        kc.to_str().unwrap(),
        "--audit-log",
        "off",
        "--path-prepend",
        dir.to_str().unwrap(),
    ])
    .await
}

/// riseno/k8s-mcp#74: a failing or malformed exec plugin is reported without its output, the
/// parser's excerpt of it, or the command's environment.
#[cfg(unix)]
#[tokio::test]
async fn exec_plugin_failures_never_echo_output_or_env() {
    let dir = tempfile::tempdir().unwrap();
    fake_plugin(
        dir.path(),
        "bad-json-plugin",
        "echo 'not json at all STDOUTTOKEN789'",
    );
    fake_plugin(
        dir.path(),
        "failing-plugin",
        "echo STDOUTTOKEN789; echo STDERRTOKEN123 >&2; exit 1",
    );
    for (plugin, expected) in [
        (
            "bad-json-plugin",
            "`bad-json-plugin` returned output that is not an ExecCredential",
        ),
        ("failing-plugin", "`failing-plugin` failed (exit status: 1)"),
    ] {
        let client = spawn_with_plugin(dir.path(), plugin).await;
        let r = call(&client, "list_resources", json!({"kind": "Pod"})).await;
        let t = text(&r);
        assert_eq!(r.is_error, Some(true), "{t}");
        assert!(t.contains(expected), "{t}");
        for leak in [
            "STDOUTTOKEN789",
            "STDERRTOKEN123",
            "envsecret456",
            "KUBERNETES_EXEC_INFO",
            "PATH",
        ] {
            assert!(!t.contains(leak), "{leak} leaked: {t}");
        }
        client.cancel().await.unwrap();
    }
}

/// riseno/k8s-mcp#73, #84, #89: a stalled exec plugin fails the call after 20 s instead of
/// hanging it, is killed at the deadline with the process it started, and concurrent calls
/// share one plugin run.
#[cfg(unix)]
#[tokio::test]
async fn stalled_exec_plugin_fails_the_call_and_is_killed() {
    let dir = tempfile::tempdir().unwrap();
    let pids = dir.path().join("pids");
    fake_plugin(
        dir.path(),
        "stalled-plugin",
        &format!(
            "echo \"run $$\" >> {p}\nsleep 30 &\necho \"child $!\" >> {p}\nwait",
            p = pids.display()
        ),
    );
    let client = spawn_with_plugin(dir.path(), "stalled-plugin").await;
    let start = std::time::Instant::now();
    let (a, b) = tokio::join!(
        call(&client, "list_resources", json!({"kind": "Pod"})),
        call(&client, "list_resources", json!({"kind": "Deployment"})),
    );
    for r in [a, b] {
        let t = text(&r);
        assert!(
            t.contains("exec auth plugin `stalled-plugin` did not finish within 20s"),
            "{t}"
        );
    }
    assert!(start.elapsed().as_secs() < 25, "{:?}", start.elapsed());
    let pids = std::fs::read_to_string(&pids).unwrap();
    let runs = pids.lines().filter(|l| l.starts_with("run ")).count();
    assert_eq!(runs, 1, "one plugin run for both calls: {pids:?}");
    let alive = |line: &str| {
        let pid = line.split_once(' ').map_or(line, |(_, p)| p);
        std::process::Command::new("kill")
            .args(["-0", pid])
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    for _ in 0..50 {
        if !pids.lines().any(alive) {
            client.cancel().await.unwrap();
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("plugin or its child still running while the server runs: {pids:?}");
}

/// riseno/k8s-mcp#80: against an API server that accepts connections and never answers, tools
/// that gather optional evidence fail with the network error before the 30 s call timeout.
#[tokio::test]
async fn silent_api_server_fails_with_the_network_error() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let held: Vec<_> = listener.incoming().flatten().collect();
        drop(held);
    });
    let dir = tempfile::tempdir().unwrap();
    let kc = offline_kubeconfig(
        dir.path(),
        &format!("https://{addr}"),
        "    token: not-a-real-token",
    );
    let client = spawn(&["--kubeconfig", kc.to_str().unwrap(), "--audit-log", "off"]).await;
    let (changes, autoscaling, dns) = tokio::join!(
        call(&client, "recent_changes", json!({})),
        call(&client, "autoscaling_status", json!({})),
        call(&client, "diagnose_dns", json!({})),
    );
    for r in [changes, autoscaling, dns] {
        let t = text(&r);
        assert_eq!(r.is_error, Some(true), "{t}");
        assert!(t.contains("could not reach the API server"), "{t}");
    }
    client.cancel().await.unwrap();
}

/// v0.4 AC 1 and 5: write tools are registered only with --allow-write (annotated as
/// destructive), are refused by name without it, and every write call is audited with its tier
/// and `dry_run`.
#[tokio::test]
async fn write_tools_need_allow_write_and_every_call_is_audited() {
    let dir = tempfile::tempdir().unwrap();
    let kc = offline_kubeconfig(dir.path(), "https://127.0.0.1:1", "    token: t");
    let kc = kc.to_str().unwrap();
    let restart = json!({"kind": "Deployment", "name": "web"});

    let client = spawn(&["--kubeconfig", kc, "--audit-log", "off"]).await;
    let tools = client.list_all_tools().await.unwrap();
    assert!(tools.iter().all(|t| t.name != "restart_workload"));
    // rmcp answers a call to an unregistered tool with a protocol error.
    let params = CallToolRequestParams::new("restart_workload")
        .with_arguments(restart.as_object().unwrap().clone());
    let err = client.call_tool(params).await.unwrap_err().to_string();
    assert!(err.contains("tool \"restart_workload\" not found"), "{err}");
    client.cancel().await.unwrap();

    let audit = dir.path().join("audit.jsonl");
    let client = spawn(&[
        "--kubeconfig",
        kc,
        "--audit-log",
        audit.to_str().unwrap(),
        "--allow-write",
    ])
    .await;
    let tools = client.list_all_tools().await.unwrap();
    let t = tools.iter().find(|t| t.name == "restart_workload").unwrap();
    let a = t.annotations.as_ref().unwrap();
    assert_eq!(
        (a.read_only_hint, a.destructive_hint),
        (Some(false), Some(true))
    );
    assert!(
        tools.iter().all(|t| t.name != "drain_node"),
        "destructive tools need --allow-destructive"
    );
    let _ = call(&client, "restart_workload", restart.clone()).await;
    let mut confirm = restart;
    confirm["dry_run"] = json!(false);
    let r = call(&client, "restart_workload", confirm).await;
    assert!(text(&r).contains("needs the confirm_token"), "{}", text(&r));
    client.cancel().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let log = std::fs::read_to_string(&audit).unwrap();
    let recs: Vec<Value> = log
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .filter(|r: &Value| r["tool"] == "restart_workload")
        .collect();
    let got: Vec<(&Value, &Value)> = recs.iter().map(|r| (&r["tier"], &r["dry_run"])).collect();
    assert_eq!(
        got,
        [
            (&json!("write"), &json!(true)),
            (&json!("write"), &json!(false))
        ],
        "{log}"
    );
}

/// v0.4: write tiers need explicit flags; destructive needs write; writes over HTTP need a
/// caller allow-list.
#[test]
fn write_flags_are_checked_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let kc = offline_kubeconfig(
        dir.path(),
        "https://127.0.0.1:1",
        "    token: not-a-real-token",
    );
    for (args, expected) in [
        (
            &["--allow-destructive"][..],
            "--allow-destructive needs --allow-write",
        ),
        (
            &["--allow-write", "--transport", "http", "--auth", "none"][..],
            "--allow-write over HTTP needs --auth tokenreview with --allowed-callers",
        ),
    ] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_k8s-mcp"))
            .args(["--kubeconfig", kc.to_str().unwrap(), "--audit-log", "off"])
            .args(args)
            .env_remove("KUBECONFIG")
            .env("HOME", dir.path())
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{args:?} started");
        assert!(stderr.contains(expected), "{args:?}: {stderr}");
    }
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

/// A process with no AWS credentials or config at all, whose AWS requests could only reach
/// 127.0.0.1:1, so a test can never call a real AWS account.
async fn spawn_without_aws(args: &[&str], home: &Path) -> RunningService<RoleClient, ()> {
    let bin = env!("CARGO_BIN_EXE_k8s-mcp");
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    let home = home.to_owned();
    let transport = TokioChildProcess::new(tokio::process::Command::new(bin).configure(|cmd| {
        cmd.args(&args)
            .env_clear()
            .env("HOME", &home)
            .env("AWS_CONFIG_FILE", home.join("no-aws-config"))
            .env(
                "AWS_SHARED_CREDENTIALS_FILE",
                home.join("no-aws-credentials"),
            )
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .env("AWS_ENDPOINT_URL", "http://127.0.0.1:1");
    }))
    .unwrap();
    ().serve(transport).await.unwrap()
}

/// v0.2: EKS tools are registered when the kubeconfig says EKS (and not otherwise), are
/// read-only and open-world, and without AWS credentials fail with an actionable message.
#[cfg(all(unix, feature = "provider-eks"))]
#[tokio::test]
async fn eks_tools_follow_detection_and_need_credentials() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    // A fake `aws` found first on the plugin PATH: the real CLI must never run in tests.
    let plugins = dir.path().join("plugins");
    std::fs::create_dir(&plugins).unwrap();
    let fake = plugins.join("aws");
    std::fs::write(
        &fake,
        "#!/bin/sh\necho '{\"apiVersion\":\"client.authentication.k8s.io/v1beta1\",\"kind\":\"ExecCredential\",\"status\":{\"token\":\"fake\"}}'\n",
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let plugins = plugins.to_str().unwrap().to_owned();
    let user = "    exec:\n      apiVersion: client.authentication.k8s.io/v1beta1\n      command: aws\n      args: [--region, eu-west-1, eks, get-token, --cluster-name, shop]";
    let kc = offline_kubeconfig(
        dir.path(),
        "https://ABCDEF.gr7.eu-west-1.eks.amazonaws.com",
        user,
    );
    let eks_tools = |tools: &[rmcp::model::Tool]| -> Vec<String> {
        tools
            .iter()
            .map(|t| t.name.to_string())
            .filter(|n| n.starts_with("eks_"))
            .collect()
    };

    let client = spawn_without_aws(
        &[
            "--kubeconfig",
            kc.to_str().unwrap(),
            "--audit-log",
            "off",
            "--path-prepend",
            &plugins,
        ],
        dir.path(),
    )
    .await;
    let tools = client.list_all_tools().await.unwrap();
    assert_eq!(
        eks_tools(&tools),
        [
            "eks_cluster_info",
            "eks_nodegroups",
            "eks_addons",
            "eks_access",
            "eks_identity_check",
            "eks_logs"
        ]
    );
    for t in tools.iter().filter(|t| t.name.starts_with("eks_")) {
        let a = t.annotations.as_ref().unwrap();
        assert_eq!(
            (a.read_only_hint, a.open_world_hint),
            (Some(true), Some(true)),
            "{}",
            t.name
        );
    }
    // Issue #47: one short line with the guidance, not the SDK's debug dump.
    let r = call(&client, "eks_cluster_info", json!({})).await;
    assert_eq!(r.is_error, Some(true));
    assert_eq!(
        text(&r),
        "no AWS credentials found (tried environment variables, the shared config and credentials files, web identity, the container and instance metadata endpoints), so k8s-mcp cannot describe the cluster for EKS cluster shop in eu-west-1. Provide them through AWS_PROFILE or environment variables, an SSO login, IRSA or EKS Pod Identity."
    );
    client.cancel().await.unwrap();

    let none = spawn_without_aws(
        &[
            "--kubeconfig",
            kc.to_str().unwrap(),
            "--audit-log",
            "off",
            "--providers",
            "none",
        ],
        dir.path(),
    )
    .await;
    assert!(eks_tools(&none.list_all_tools().await.unwrap()).is_empty());
    none.cancel().await.unwrap();

    let local = offline_kubeconfig(dir.path(), "https://127.0.0.1:1", "    token: t");
    let plain = spawn_without_aws(
        &[
            "--kubeconfig",
            local.to_str().unwrap(),
            "--audit-log",
            "off",
        ],
        dir.path(),
    )
    .await;
    assert!(
        eks_tools(&plain.list_all_tools().await.unwrap()).is_empty(),
        "not EKS: not registered"
    );
    plain.cancel().await.unwrap();
}

/// v0.3: GKE tools follow the provider flags, are read-only and open-world, and without Google
/// Cloud credentials fail with one line of guidance before any network call (the process has no
/// credentials file and no metadata server).
#[cfg(all(unix, feature = "provider-gke"))]
#[tokio::test]
async fn gke_tools_need_credentials() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    // A fake plugin first on the plugin PATH: the real gcloud tooling must never run in tests.
    let plugins = dir.path().join("plugins");
    std::fs::create_dir(&plugins).unwrap();
    let fake = plugins.join("gke-gcloud-auth-plugin");
    std::fs::write(
        &fake,
        "#!/bin/sh\necho '{\"apiVersion\":\"client.authentication.k8s.io/v1beta1\",\"kind\":\"ExecCredential\",\"status\":{\"token\":\"fake\"}}'\n",
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let plugins = plugins.to_str().unwrap().to_owned();
    let user = "    exec:\n      apiVersion: client.authentication.k8s.io/v1beta1\n      command: gke-gcloud-auth-plugin";
    let kc = offline_kubeconfig(dir.path(), "https://127.0.0.1:1", user);
    let client = spawn_without_aws(
        &[
            "--kubeconfig",
            kc.to_str().unwrap(),
            "--audit-log",
            "off",
            "--path-prepend",
            &plugins,
            "--gke-cluster",
            "acme/europe-west1/shop",
        ],
        dir.path(),
    )
    .await;
    let tools = client.list_all_tools().await.unwrap();
    let gke: Vec<String> = tools
        .iter()
        .map(|t| t.name.to_string())
        .filter(|n| n.starts_with("gke_"))
        .collect();
    assert_eq!(
        gke,
        [
            "gke_cluster_info",
            "gke_node_pools",
            "gke_addons",
            "gke_identity_check",
            "gke_logs"
        ]
    );
    assert!(!tools.iter().any(|t| t.name.starts_with("eks_")));
    for t in tools.iter().filter(|t| t.name.starts_with("gke_")) {
        let a = t.annotations.as_ref().unwrap();
        assert_eq!(
            (a.read_only_hint, a.open_world_hint),
            (Some(true), Some(true)),
            "{}",
            t.name
        );
    }
    let r = call(&client, "gke_cluster_info", json!({})).await;
    assert_eq!(r.is_error, Some(true));
    assert_eq!(
        text(&r),
        "no Google Cloud credentials found (tried GOOGLE_APPLICATION_CREDENTIALS, the gcloud ADC file and, in a cluster, the metadata server). Run `gcloud auth application-default login`, set GOOGLE_APPLICATION_CREDENTIALS, or use GKE Workload Identity."
    );
    client.cancel().await.unwrap();
}

/// v0.3: AKS tools follow the provider flags, are read-only and open-world, and without Azure
/// credentials fail with one line of guidance before any network call (no AZURE_* variables;
/// the Azure CLI login is never used).
#[cfg(all(unix, feature = "provider-aks"))]
#[tokio::test]
async fn aks_tools_need_credentials() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let plugins = dir.path().join("plugins");
    std::fs::create_dir(&plugins).unwrap();
    let fake = plugins.join("kubelogin");
    std::fs::write(
        &fake,
        "#!/bin/sh\necho '{\"apiVersion\":\"client.authentication.k8s.io/v1beta1\",\"kind\":\"ExecCredential\",\"status\":{\"token\":\"fake\"}}'\n",
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let plugins = plugins.to_str().unwrap().to_owned();
    let user = "    exec:\n      apiVersion: client.authentication.k8s.io/v1beta1\n      command: kubelogin\n      args: [get-token, --login, azurecli]";
    let kc = offline_kubeconfig(dir.path(), "https://127.0.0.1:1", user);
    let client = spawn_without_aws(
        &[
            "--kubeconfig",
            kc.to_str().unwrap(),
            "--audit-log",
            "off",
            "--path-prepend",
            &plugins,
            "--aks-cluster",
            "sub-1/shop-rg/shop",
        ],
        dir.path(),
    )
    .await;
    let tools = client.list_all_tools().await.unwrap();
    let aks: Vec<String> = tools
        .iter()
        .map(|t| t.name.to_string())
        .filter(|n| n.starts_with("aks_"))
        .collect();
    assert_eq!(
        aks,
        [
            "aks_cluster_info",
            "aks_node_pools",
            "aks_addons",
            "aks_identity_check",
            "aks_logs"
        ]
    );
    for t in tools.iter().filter(|t| t.name.starts_with("aks_")) {
        let a = t.annotations.as_ref().unwrap();
        assert_eq!(
            (a.read_only_hint, a.open_world_hint),
            (Some(true), Some(true)),
            "{}",
            t.name
        );
    }
    let r = call(&client, "aks_cluster_info", json!({})).await;
    assert_eq!(r.is_error, Some(true));
    assert!(
        text(&r).starts_with("no Azure credentials found (tried workload identity"),
        "{}",
        text(&r)
    );
    assert!(
        text(&r).ends_with("the Azure CLI login is not used because k8s-mcp runs no commands."),
        "{}",
        text(&r)
    );
    client.cancel().await.unwrap();
}
