//! Acceptance tests against the local kind cluster (PROPOSAL §16 v0.1 criteria 4 and 9).
//! Run with `cargo xtask kind-up` then `cargo test -p k8s-mcp-server --test kind -- --ignored`.
//! Every test refuses to run unless the kubeconfig's context is `kind-k8s-mcp-dev`.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code

use std::path::{Path, PathBuf};
use std::time::Duration;

use k8s_openapi::api::authentication::v1::{TokenRequest, TokenRequestSpec};
use k8s_openapi::api::core::v1::{Namespace, Pod, ServiceAccount};
use kube::api::{Api, DeleteParams, PostParams};
use kube::config::{KubeConfigOptions, Kubeconfig};
use rmcp::model::CallToolRequestParams;
use rmcp::service::RunningService;
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use rmcp::{RoleClient, ServiceExt};
use serde_json::{Value, json};

const CONTEXT: &str = "kind-k8s-mcp-dev";

fn kubeconfig_path() -> PathBuf {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.dev/kubeconfig");
    assert!(p.exists(), "run `cargo xtask kind-up` first");
    p.canonicalize().unwrap()
}

async fn admin() -> kube::Client {
    let kc = Kubeconfig::read_from(kubeconfig_path()).unwrap();
    assert!(
        kc.contexts.iter().any(|c| c.name == CONTEXT),
        "refusing: {CONTEXT} not in .dev/kubeconfig"
    );
    let cfg = kube::Config::from_custom_kubeconfig(
        kc,
        &KubeConfigOptions {
            context: Some(CONTEXT.into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(
        cfg.cluster_url
            .host()
            .is_some_and(|h| h == "127.0.0.1" || h == "localhost"),
        "refusing: not a local kind API server"
    );
    kube::Client::try_from(cfg).unwrap()
}

fn suffix() -> String {
    format!(
        "{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            % 1_000_000
    )
}

async fn apply(client: &kube::Client, ns: &str, docs: &[Value]) {
    let pp = PostParams::default();
    Api::<Namespace>::all(client.clone())
        .create(
            &pp,
            &serde_json::from_value(json!({"metadata": {"name": ns}})).unwrap(),
        )
        .await
        .unwrap();
    for d in docs {
        let ar = match d["kind"].as_str().unwrap() {
            "Secret" => {
                kube::discovery::ApiResource::erase::<k8s_openapi::api::core::v1::Secret>(&())
            }
            "ConfigMap" => {
                kube::discovery::ApiResource::erase::<k8s_openapi::api::core::v1::ConfigMap>(&())
            }
            "Pod" => kube::discovery::ApiResource::erase::<Pod>(&()),
            "Service" => {
                kube::discovery::ApiResource::erase::<k8s_openapi::api::core::v1::Service>(&())
            }
            "PersistentVolumeClaim" => kube::discovery::ApiResource::erase::<
                k8s_openapi::api::core::v1::PersistentVolumeClaim,
            >(&()),
            "Deployment" => {
                kube::discovery::ApiResource::erase::<k8s_openapi::api::apps::v1::Deployment>(&())
            }
            "ServiceAccount" => kube::discovery::ApiResource::erase::<ServiceAccount>(&()),
            "Role" => kube::discovery::ApiResource::erase::<k8s_openapi::api::rbac::v1::Role>(&()),
            "RoleBinding" => {
                kube::discovery::ApiResource::erase::<k8s_openapi::api::rbac::v1::RoleBinding>(&())
            }
            k => panic!("unsupported kind {k}"),
        };
        let obj: kube::api::DynamicObject = serde_json::from_value(d.clone()).unwrap();
        Api::<kube::api::DynamicObject>::namespaced_with(client.clone(), ns, &ar)
            .create(&pp, &obj)
            .await
            .unwrap();
    }
}

async fn wait_for(client: &kube::Client, ns: &str, pod: &str, pred: impl Fn(&Pod) -> bool) {
    let api: Api<Pod> = Api::namespaced(client.clone(), ns);
    for _ in 0..90 {
        if api.get_opt(pod).await.unwrap().is_some_and(|p| pred(&p)) {
            return;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    panic!("pod {ns}/{pod} did not reach the expected state");
}

async fn cleanup(client: &kube::Client, ns: &str) {
    let _ = Api::<Namespace>::all(client.clone())
        .delete(ns, &DeleteParams::default())
        .await;
}

async fn spawn(kubeconfig: &Path, extra: &[&str]) -> RunningService<RoleClient, ()> {
    let mut args = vec!["--kubeconfig".to_owned(), kubeconfig.display().to_string()];
    args.extend(extra.iter().map(|s| (*s).to_owned()));
    let transport = TokioChildProcess::new(
        tokio::process::Command::new(env!("CARGO_BIN_EXE_k8s-mcp")).configure(|c| {
            c.args(&args).env_remove("KUBECONFIG");
        }),
    )
    .unwrap();
    ().serve(transport).await.unwrap()
}

async fn call(
    client: &RunningService<RoleClient, ()>,
    tool: &str,
    args: Value,
) -> (String, rmcp::model::CallToolResult) {
    let r = client
        .call_tool(
            CallToolRequestParams::new(tool.to_owned())
                .with_arguments(args.as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    (serde_json::to_string(&r).unwrap(), r)
}

/// Criterion 4: a canary Secret referenced from env, envFrom and a volume never appears in
/// any tool output or in the audit log.
#[tokio::test]
#[ignore = "needs the local kind cluster (cargo xtask kind-up)"]
async fn secret_canary_never_leaks() {
    let client = admin().await;
    let ns = format!("canary-{}", suffix());
    let canary = format!("CANARY-{}-c8f3a1", suffix());
    let literal = format!("LITERAL-{}-9d2e", suffix());
    apply(&client, &ns, &[
        json!({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "canary"}, "stringData": {"token": canary, "url": format!("https://u:{canary}@db")}}),
        json!({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "canary", "labels": {"app": "canary"}, "annotations": {"note": format!("password={literal}")}}, "spec": {
            "containers": [{"name": "app", "image": "busybox:1.36", "command": ["sh", "-c", "echo started; sleep 3600"],
                "env": [
                    {"name": "FROM_REF", "valueFrom": {"secretKeyRef": {"name": "canary", "key": "token"}}},
                    {"name": "DB_PASSWORD", "value": literal}
                ],
                "envFrom": [{"secretRef": {"name": "canary"}}],
                "volumeMounts": [{"name": "s", "mountPath": "/etc/canary"}]}],
            "volumes": [{"name": "s", "secret": {"secretName": "canary"}}]}}),
        // For the v0.2 tools: a Service, a claim and a Deployment that also use the Secret.
        json!({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "canary"}, "spec": {"selector": {"app": "canary"}, "ports": [{"port": 80}]}}),
        json!({"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "canary"}, "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Mi"}}}}),
        json!({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "canary-web"}, "spec": {"replicas": 0,
            "selector": {"matchLabels": {"app": "canary-web"}}, "template": {"metadata": {"labels": {"app": "canary-web"}}, "spec": {
                "containers": [{"name": "app", "image": "busybox:1.36", "env": [
                    {"name": "FROM_REF", "valueFrom": {"secretKeyRef": {"name": "canary", "key": "token"}}},
                    {"name": "DB_PASSWORD", "value": literal}]}]}}}}),
    ])
    .await;
    wait_for(&client, &ns, "canary", |p| {
        p.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Running")
    })
    .await;

    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit.jsonl");
    let mcp = spawn(
        &kubeconfig_path(),
        &["--context", CONTEXT, "--audit-log", audit.to_str().unwrap()],
    )
    .await;
    let node = Api::<Pod>::namespaced(client.clone(), &ns)
        .get("canary")
        .await
        .unwrap()
        .spec
        .unwrap()
        .node_name
        .unwrap();
    let calls = [
        ("list_contexts", json!({})),
        ("cluster_overview", json!({})),
        ("api_resources", json!({})),
        (
            "list_resources",
            json!({"kind": "secrets", "namespace": ns}),
        ),
        ("list_resources", json!({"kind": "pods", "namespace": ns})),
        (
            "list_resources",
            json!({"kind": "secrets", "all_namespaces": true}),
        ),
        (
            "get_resource",
            json!({"kind": "Secret", "name": "canary", "namespace": ns, "view": "summary"}),
        ),
        (
            "get_resource",
            json!({"kind": "Secret", "name": "canary", "namespace": ns, "view": "yaml"}),
        ),
        (
            "get_resource",
            json!({"kind": "Secret", "name": "canary", "namespace": ns, "view": "full"}),
        ),
        (
            "get_resource",
            json!({"kind": "Pod", "name": "canary", "namespace": ns, "view": "summary"}),
        ),
        (
            "get_resource",
            json!({"kind": "Pod", "name": "canary", "namespace": ns, "view": "yaml"}),
        ),
        (
            "get_resource",
            json!({"kind": "Pod", "name": "canary", "namespace": ns, "view": "full"}),
        ),
        (
            "list_events",
            json!({"namespace": ns, "types": ["Normal", "Warning"]}),
        ),
        ("get_logs", json!({"pod": "canary", "namespace": ns})),
        ("top", json!({"namespace": ns})),
        ("check_permissions", json!({"namespace": ns})),
        ("diagnose_pod", json!({"name": "canary", "namespace": ns})),
        (
            "find_problems",
            json!({"namespace": ns, "min_severity": "info"}),
        ),
        ("diagnose_node", json!({"name": node})),
        (
            "diagnose_service",
            json!({"name": "canary", "namespace": ns}),
        ),
        ("diagnose_pvc", json!({"name": "canary", "namespace": ns})),
        ("diagnose_dns", json!({"pod": "canary", "namespace": ns})),
        ("autoscaling_status", json!({"namespace": ns})),
        ("upgrade_readiness", json!({})),
        ("recent_changes", json!({"namespace": ns})),
        (
            "rollout_history",
            json!({"kind": "Deployment", "name": "canary-web", "namespace": ns}),
        ),
    ];
    for (tool, args) in calls {
        let (raw, r) = call(&mcp, tool, args.clone()).await;
        assert!(
            !raw.contains(&canary),
            "{tool} {args} leaked the Secret value: {raw}"
        );
        assert!(
            !raw.contains(&literal),
            "{tool} {args} leaked a sensitive literal: {raw}"
        );
        // top may fail if metrics are not scraped yet; every other call must succeed.
        if tool != "top" {
            assert_ne!(r.is_error, Some(true), "{tool} {args}: {raw}");
        }
    }
    mcp.cancel().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let log = std::fs::read_to_string(&audit).unwrap();
    assert!(log.lines().count() >= 25 && !log.contains(&canary) && !log.contains(&literal));
    cleanup(&client, &ns).await;
}

/// Criterion 9: under a namespace-scoped Role (no cluster-scope rights), diagnose_pod still
/// returns findings and states which evidence was unavailable.
#[tokio::test]
#[ignore = "needs the local kind cluster (cargo xtask kind-up)"]
async fn namespace_scoped_rbac_still_diagnoses() {
    let client = admin().await;
    let ns = format!("scoped-{}", suffix());
    apply(&client, &ns, &[
        json!({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "reader"}}),
        json!({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "reader"}, "rules": [
            {"apiGroups": [""], "resources": ["pods", "events", "configmaps", "serviceaccounts"], "verbs": ["get", "list"]},
            {"apiGroups": ["apps"], "resources": ["deployments", "replicasets"], "verbs": ["get", "list"]}
        ]}),
        json!({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "reader"},
               "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "reader"},
               "subjects": [{"kind": "ServiceAccount", "name": "reader", "namespace": ns}]}),
        json!({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "broken"}, "spec": {"containers": [{"name": "app", "image": "nginx:doesnotexist-k8s-mcp"}]}}),
    ])
    .await;
    wait_for(&client, &ns, "broken", |p| {
        p.status
            .iter()
            .flat_map(|s| s.container_statuses.iter().flatten())
            .any(|c| {
                c.state
                    .as_ref()
                    .and_then(|s| s.waiting.as_ref())
                    .and_then(|w| w.reason.as_deref())
                    .is_some_and(|r| r.contains("Image"))
            })
    })
    .await;
    let token = Api::<ServiceAccount>::namespaced(client.clone(), &ns)
        .create_token_request(
            "reader",
            &PostParams::default(),
            &TokenRequest {
                spec: TokenRequestSpec {
                    audiences: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .status
        .unwrap()
        .token;

    // A kubeconfig for the scoped identity, pointing at the same kind API server.
    let admin_kc = Kubeconfig::read_from(kubeconfig_path()).unwrap();
    let ctx = admin_kc
        .contexts
        .iter()
        .find(|c| c.name == CONTEXT)
        .unwrap()
        .context
        .clone()
        .unwrap();
    let cluster = admin_kc
        .clusters
        .iter()
        .find(|c| c.name == ctx.cluster)
        .unwrap()
        .cluster
        .clone()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let kc_path = dir.path().join("scoped");
    std::fs::write(&kc_path, format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: scoped\nclusters:\n- name: kind\n  cluster:\n    server: {}\n    certificate-authority-data: {}\ncontexts:\n- name: scoped\n  context: {{cluster: kind, user: reader, namespace: {ns}}}\nusers:\n- name: reader\n  user: {{token: {token}}}\n",
        cluster.server.unwrap(),
        cluster.certificate_authority_data.unwrap(),
    )).unwrap();

    let mcp = spawn(&kc_path, &["--audit-log", "off"]).await;
    let (raw, r) = call(&mcp, "diagnose_pod", json!({"name": "broken"})).await;
    assert_ne!(r.is_error, Some(true), "{raw}");
    let sc = r.structured_content.unwrap();
    assert!(
        !sc["findings"].as_array().unwrap().is_empty(),
        "no findings under scoped RBAC: {raw}"
    );
    let text = r.content[0].as_text().unwrap().text.clone();
    assert!(
        text.contains("UNAVAILABLE EVIDENCE") && text.contains("node"),
        "should say the node was unreadable: {text}"
    );
    assert!(!raw.contains(&token));

    // Cluster-wide scans fall back to the context's namespace instead of failing.
    let (raw, r) = call(&mcp, "find_problems", json!({})).await;
    assert_ne!(r.is_error, Some(true), "{raw}");
    assert!(raw.contains("broken"), "{raw}");
    mcp.cancel().await.unwrap();
    cleanup(&client, &ns).await;
}

/// Issue #64: the kind cluster under a context renamed like GKE. Detection believes the nodes
/// (kind://), so `cluster_overview` says kind and names the conflict, and the GKE tools, even
/// forced with `--providers gke`, refuse before any cloud call. The server has no credentials
/// and no metadata server, so a regression could not reach Google Cloud either.
#[tokio::test]
#[ignore = "needs the local kind cluster (cargo xtask kind-up)"]
async fn renamed_context_never_reaches_a_cloud() {
    let dir = tempfile::tempdir().unwrap();
    let mut kc = Kubeconfig::read_from(kubeconfig_path()).unwrap();
    let name = "gke_fake-project_us-central1_fake-cluster";
    for c in &mut kc.contexts {
        if c.name == CONTEXT {
            c.name = name.into();
        }
    }
    kc.current_context = Some(name.into());
    let path = dir.path().join("kubeconfig");
    std::fs::write(&path, serde_json::to_string(&kc).unwrap()).unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir(&home).unwrap();
    let args = [
        "--kubeconfig".to_owned(),
        path.display().to_string(),
        "--audit-log".into(),
        "off".into(),
        "--providers".into(),
        "gke".into(),
    ];
    let transport = TokioChildProcess::new(
        tokio::process::Command::new(env!("CARGO_BIN_EXE_k8s-mcp")).configure(|c| {
            c.args(&args).env_clear().env("HOME", &home);
        }),
    )
    .unwrap();
    let client = ().serve(transport).await.unwrap();
    let (text, r) = call(&client, "gke_cluster_info", json!({})).await;
    assert_eq!(r.is_error, Some(true));
    assert!(
        text.contains("its nodes run on kind") && text.contains("--gke-cluster"),
        "{text}"
    );
    let (text, _) = call(&client, "cluster_overview", json!({})).await;
    assert!(
        text.contains("on kind (the context looks like gke"),
        "{text}"
    );
    client.cancel().await.unwrap();
}
