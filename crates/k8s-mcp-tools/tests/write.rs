//! Write tools against a mock API server: a plan only sends dry-run requests, and nothing
//! mutates without the plan's token for the same request and object state (v0.4 AC 2, 3).
#![allow(clippy::unwrap_used)] // test helpers

use std::sync::Arc;

use k8s_mcp_core::cluster::ClusterManager;
use k8s_mcp_core::policy::Policy;
use k8s_mcp_testkit::mock::{Mock, MockApi};
use k8s_mcp_testkit::now;
use k8s_mcp_tools::{Ctx, RestartWorkloadInput};
use serde_json::{Value, json};

fn ctx(mock: &Mock) -> Ctx {
    let mut c = Ctx::new(
        Arc::new(ClusterManager::fixed(mock.client.clone(), "test", "shop")),
        Arc::new(Policy::permissive()),
    );
    c.clock = Arc::new(now);
    c
}

fn deployment(rv: &str) -> Value {
    json!({"apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": "web", "namespace": "shop", "resourceVersion": rv},
        "spec": {"replicas": 3, "strategy": {"type": "RollingUpdate"},
            "selector": {"matchLabels": {"app": "web"}},
            "template": {"metadata": {"labels": {"app": "web"}}, "spec": {"containers": [{"name": "app", "image": "nginx:1.27"}]}}},
        "status": {"replicas": 3}})
}

const WEB: &str = "/apis/apps/v1/namespaces/shop/deployments/web";

fn mock(rv: &str) -> Mock {
    MockApi::new()
        .get(WEB, deployment(rv))
        .route("PATCH", WEB, 200, deployment(rv))
        .start()
}

/// The write requests (anything but GET) the mock received.
fn writes(m: &Mock) -> Vec<String> {
    m.requests
        .lock()
        .unwrap()
        .iter()
        .filter(|r| !r.starts_with("GET "))
        .cloned()
        .collect()
}

fn restart(dry_run: Option<bool>, token: Option<&str>) -> RestartWorkloadInput {
    RestartWorkloadInput {
        kind: "deploy".into(),
        name: "web".into(),
        dry_run,
        confirm_token: token.map(str::to_owned),
        ..Default::default()
    }
}

#[tokio::test]
async fn a_restart_is_planned_as_a_dry_run_and_applied_only_with_its_token() {
    let m = mock("41");
    let c = ctx(&m);
    let plan = k8s_mcp_tools::restart_workload(&c, restart(None, None))
        .await
        .unwrap();
    assert!(
        plan.summary.starts_with(
            "Plan (server-side dry run; nothing changed): restart Deployment shop/web."
        ),
        "{}",
        plan.summary
    );
    assert_eq!(
        plan.sections[0].lines,
        [
            "spec.template.metadata.annotations[kubectl.kubernetes.io/restartedAt]: (none) → 2026-11-14T12:00:00Z",
            "RollingUpdate: its 3 pod(s) are replaced a few at a time, as the update strategy allows",
        ]
    );
    let confirm = &plan.next[0];
    assert_eq!(confirm.tool, "restart_workload");
    assert_eq!(confirm.args["dry_run"], false);
    assert_eq!(confirm.args["context"], "test");
    let token = confirm.args["confirm_token"].as_str().unwrap().to_owned();
    // The plan sent one patch, as a dry run.
    let sent = writes(&m);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert!(
        sent[0].starts_with(&format!("PATCH {WEB}?")) && sent[0].contains("dryRun=All"),
        "{sent:?}"
    );

    // dry_run=false without a token, or with a token for another request: nothing is sent.
    let no_token = k8s_mcp_tools::restart_workload(&c, restart(Some(false), None)).await;
    assert!(
        no_token
            .unwrap_err()
            .to_string()
            .contains("needs the confirm_token of a plan")
    );
    let mut other = restart(Some(false), Some(&token));
    other.kind = "StatefulSet".into();
    let mismatch = k8s_mcp_tools::restart_workload(&c, other).await;
    assert!(mismatch.is_err());
    assert_eq!(writes(&m).len(), 1, "no write without a valid token");

    // With the plan's token: the real patch, carrying the resourceVersion as a precondition.
    let done = k8s_mcp_tools::restart_workload(&c, restart(Some(false), Some(&token)))
        .await
        .unwrap();
    assert!(
        done.summary
            .starts_with("Applied: restart Deployment shop/web."),
        "{}",
        done.summary
    );
    let sent = writes(&m);
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert!(!sent[1].contains("dryRun"), "{sent:?}");
    assert_eq!(done.next[0].tool, "diagnose_workload");
}

#[tokio::test]
async fn a_token_is_void_once_the_object_changed() {
    let before = mock("41");
    let c = ctx(&before);
    let plan = k8s_mcp_tools::restart_workload(&c, restart(None, None))
        .await
        .unwrap();
    let token = plan.next[0].args["confirm_token"]
        .as_str()
        .unwrap()
        .to_owned();
    // Same server process (same confirmer), but the Deployment was written since the plan.
    let after = mock("42");
    let mut c2 = ctx(&after);
    c2.confirm = c.confirm.clone();
    let err = k8s_mcp_tools::restart_workload(&c2, restart(Some(false), Some(&token)))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("changed since the plan") && err.contains("Nothing was changed"),
        "{err}"
    );
    assert!(writes(&after).is_empty());
}

#[tokio::test]
async fn protected_namespaces_are_refused_before_any_request() {
    let m = mock("41");
    let mut input = restart(None, None);
    input.namespace = Some("kube-system".into());
    let err = k8s_mcp_tools::restart_workload(&ctx(&m), input)
        .await
        .unwrap_err();
    assert!(
        err.is_forbidden() && err.to_string().contains("protected from writes"),
        "{err}"
    );
    assert!(m.requests.lock().unwrap().is_empty());
}
