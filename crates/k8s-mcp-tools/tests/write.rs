//! Write tools against a mock API server: a plan only sends dry-run requests, and nothing
//! mutates without the plan's token for the same request and object state (v0.4 AC 2, 3).
#![allow(clippy::unwrap_used)] // test helpers

use std::sync::Arc;

use k8s_mcp_core::cluster::ClusterManager;
use k8s_mcp_core::policy::Policy;
use k8s_mcp_testkit::mock::{Mock, MockApi};
use k8s_mcp_testkit::now;
use k8s_mcp_tools::{
    Ctx, DeletePodInput, DrainNodeInput, Envelope, NodeWriteInput, RestartWorkloadInput,
    RollbackWorkloadInput, ScaleWorkloadInput,
};
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

/// A server-side dry run: `dryRun=All` in the query, or for a delete in its body.
fn dry(request: &str) -> bool {
    request.contains("dryRun=All") || request.contains(r#""dryRun":["All"]"#)
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
        sent[0].starts_with(&format!("PATCH {WEB}?")) && dry(&sent[0]),
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
    assert!(!dry(&sent[1]), "{sent:?}");
    assert_eq!(done.next[0].tool, "diagnose_workload");
}

/// The token binds the objects without their status (ADR 0016, issue #122): a status update
/// since the plan still confirms, with the current resourceVersion as the write's
/// precondition; a spec change voids the token.
#[tokio::test]
async fn a_token_is_void_once_the_object_changed_but_not_by_status() {
    let before = mock("41");
    let c = ctx(&before);
    let plan = k8s_mcp_tools::restart_workload(&c, restart(None, None))
        .await
        .unwrap();
    let token = plan.next[0].args["confirm_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let confirm = |m: &Mock| {
        // Same server process (same confirmer), the Deployment read again.
        let mut c2 = ctx(m);
        c2.confirm = c.confirm.clone();
        let token = token.clone();
        async move { k8s_mcp_tools::restart_workload(&c2, restart(Some(false), Some(&token))).await }
    };

    // Only the status changed (a controller's update): the change is made, conditional on 42.
    let mut status_only = deployment("42");
    status_only["status"] = json!({"replicas": 3, "readyReplicas": 1, "observedGeneration": 7});
    let after = MockApi::new()
        .get(WEB, status_only.clone())
        .route("PATCH", WEB, 200, status_only)
        .start();
    confirm(&after).await.unwrap();
    let sent = writes(&after);
    assert!(
        sent.len() == 1 && !dry(&sent[0]) && sent[0].contains(r#""resourceVersion":"42""#),
        "{sent:?}"
    );

    // The spec changed: rejected, nothing sent.
    let mut respec = deployment("43");
    respec["spec"]["replicas"] = json!(5);
    let after = MockApi::new().get(WEB, respec).start();
    let err = confirm(&after).await.unwrap_err().to_string();
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

fn rs(revision: u32, image: &str) -> Value {
    // Revision 2 also runs privileged: a change the summary lines do not name.
    let security = if revision == 2 {
        json!({"privileged": true})
    } else {
        json!(null)
    };
    json!({"apiVersion": "apps/v1", "kind": "ReplicaSet",
        "metadata": {"name": format!("web-{revision}"), "namespace": "shop",
            "annotations": {"deployment.kubernetes.io/revision": revision.to_string()},
            "ownerReferences": [{"apiVersion": "apps/v1", "kind": "Deployment", "name": "web", "uid": "u1", "controller": true}]},
        "spec": {"replicas": 0, "selector": {"matchLabels": {"app": "web"}},
            "template": {"metadata": {"labels": {"app": "web", "pod-template-hash": format!("h{revision}")}},
                "spec": {"containers": [{"name": "app", "image": image, "securityContext": security}]}}}})
}

fn pod(owned: bool, mirror: bool) -> Value {
    let mut meta =
        json!({"name": "web-1", "namespace": "shop", "resourceVersion": "9", "uid": "p1"});
    if owned {
        meta["ownerReferences"] = json!([{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "web-3", "uid": "r3", "controller": true}]);
    }
    if mirror {
        meta["annotations"] = json!({"kubernetes.io/config.mirror": "x"});
    }
    json!({"apiVersion": "v1", "kind": "Pod", "metadata": meta,
        "spec": {"containers": [{"name": "app", "image": "nginx"}], "terminationGracePeriodSeconds": 45}})
}

const POD: &str = "/api/v1/namespaces/shop/pods/web-1";
const NODE: &str = "/api/v1/nodes/n1";

/// A mock that serves every object the write-tier tools read and accepts their writes.
fn cluster() -> Mock {
    let mut dep = deployment("41");
    dep["metadata"]["annotations"] = json!({"deployment.kubernetes.io/revision": "3"});
    dep["spec"]["template"]["spec"]["containers"][0]["image"] = json!("nginx:1.27");
    let scale = json!({"apiVersion": "autoscaling/v1", "kind": "Scale",
        "metadata": {"name": "web", "namespace": "shop", "resourceVersion": "41"},
        "spec": {"replicas": 3}, "status": {"replicas": 3}});
    let node = json!({"apiVersion": "v1", "kind": "Node", "metadata": {"name": "n1", "resourceVersion": "5"}, "spec": {}});
    MockApi::new()
        .get(WEB, dep.clone())
        .route("PATCH", WEB, 200, dep.clone())
        .route("PUT", WEB, 200, dep)
        .get(&format!("{WEB}/scale"), scale.clone())
        .route("PATCH", &format!("{WEB}/scale"), 200, scale)
        .list(
            "/apis/autoscaling/v2/namespaces/shop/horizontalpodautoscalers",
            vec![json!({"apiVersion": "autoscaling/v2", "kind": "HorizontalPodAutoscaler",
                "metadata": {"name": "web", "namespace": "shop"},
                "spec": {"scaleTargetRef": {"apiVersion": "apps/v1", "kind": "Deployment", "name": "web"}, "minReplicas": 2, "maxReplicas": 10}})],
        )
        .list(
            "/apis/apps/v1/namespaces/shop/replicasets",
            vec![rs(3, "nginx:1.27"), rs(2, "nginx:1.26"), rs(1, "nginx:1.27")],
        )
        .get(POD, pod(true, false))
        .route("DELETE", POD, 200, pod(true, false))
        .get(NODE, node.clone())
        .route("PATCH", NODE, 200, node)
        .list("/api/v1/pods", vec![pod(true, false)])
        .route("POST", &format!("{POD}/eviction"), 201, json!({"kind": "Status", "apiVersion": "v1", "status": "Success", "code": 201}))
        .start()
}

async fn call(c: &Ctx, tool: &str, args: Value) -> k8s_mcp_core::Result<Envelope> {
    let a = args;
    match tool {
        "restart_workload" => {
            k8s_mcp_tools::restart_workload(
                c,
                serde_json::from_value::<RestartWorkloadInput>(a).unwrap(),
            )
            .await
        }
        "scale_workload" => {
            k8s_mcp_tools::scale_workload(
                c,
                serde_json::from_value::<ScaleWorkloadInput>(a).unwrap(),
            )
            .await
        }
        "rollback_workload" => {
            k8s_mcp_tools::rollback_workload(
                c,
                serde_json::from_value::<RollbackWorkloadInput>(a).unwrap(),
            )
            .await
        }
        "delete_pod" => {
            k8s_mcp_tools::delete_pod(c, serde_json::from_value::<DeletePodInput>(a).unwrap()).await
        }
        "cordon_node" => {
            k8s_mcp_tools::cordon_node(c, serde_json::from_value::<NodeWriteInput>(a).unwrap())
                .await
        }
        "uncordon_node" => {
            k8s_mcp_tools::uncordon_node(c, serde_json::from_value::<NodeWriteInput>(a).unwrap())
                .await
        }
        "drain_node" => {
            k8s_mcp_tools::drain_node(c, serde_json::from_value::<DrainNodeInput>(a).unwrap()).await
        }
        other => panic!("{other}"),
    }
}

/// v0.4 AC 2 for every write-tier tool: a plan sends only dry-run writes, and without the
/// plan's token (or with another plan's) nothing else is sent; with it, the real write.
#[tokio::test]
async fn every_write_tool_mutates_only_with_its_plans_token() {
    let cases = [
        (
            "restart_workload",
            json!({"kind": "Deployment", "name": "web"}),
            "PATCH",
        ),
        (
            "scale_workload",
            json!({"kind": "Deployment", "name": "web", "replicas": 5}),
            "PATCH",
        ),
        ("rollback_workload", json!({"name": "web"}), "PUT"),
        ("delete_pod", json!({"name": "web-1"}), "DELETE"),
        ("cordon_node", json!({"name": "n1"}), "PATCH"),
        ("uncordon_node", json!({"name": "n1"}), "PATCH"),
        ("drain_node", json!({"name": "n1"}), "POST"),
    ];
    let m = cluster();
    let c = ctx(&m);
    let mut tokens = Vec::new();
    for (tool, args, verb) in &cases {
        let plan = call(&c, tool, args.clone())
            .await
            .unwrap_or_else(|e| panic!("{tool}: {e}"));
        let sent = writes(&m);
        let last = sent.last().unwrap();
        assert!(last.starts_with(verb) && dry(last), "{tool}: {sent:?}");
        assert!(sent.iter().all(|r| dry(r)), "{tool}: {sent:?}");
        tokens.push(plan.next[0].args.clone());
    }
    let planned = writes(&m).len();
    for (i, (tool, args, _)) in cases.iter().enumerate() {
        let mut no_token = args.clone();
        no_token["dry_run"] = json!(false);
        assert!(call(&c, tool, no_token).await.is_err(), "{tool}");
        // Another tool's token does not confirm this tool's plan.
        let mut wrong = args.clone();
        wrong["dry_run"] = json!(false);
        wrong["confirm_token"] = tokens[(i + 1) % tokens.len()]["confirm_token"].clone();
        assert!(call(&c, tool, wrong).await.is_err(), "{tool}");
    }
    assert_eq!(writes(&m).len(), planned, "no write without a valid token");
    for ((tool, _, verb), confirm) in cases.iter().zip(tokens) {
        call(&c, tool, confirm)
            .await
            .unwrap_or_else(|e| panic!("{tool}: {e}"));
        let last = writes(&m).pop().unwrap();
        assert!(last.starts_with(verb) && !dry(&last), "{tool}: {last}");
    }
}

#[tokio::test]
async fn plans_show_the_change_and_its_impact() {
    let m = cluster();
    let c = ctx(&m);
    let lines = |e: &Envelope| e.sections[0].lines.clone();

    let scale = call(
        &c,
        "scale_workload",
        json!({"kind": "deploy", "name": "web", "replicas": 0}),
    )
    .await
    .unwrap();
    assert_eq!(
        lines(&scale)[..2],
        [
            "spec.replicas: 3 → 0",
            "scaled to zero: it serves nothing until it is scaled up again"
        ]
    );
    assert!(
        lines(&scale)[2].starts_with("HorizontalPodAutoscaler web manages these replicas (2–10)"),
        "{:?}",
        lines(&scale)
    );

    let rollback = call(&c, "rollback_workload", json!({"name": "web"}))
        .await
        .unwrap();
    assert!(
        rollback
            .summary
            .contains("roll back Deployment shop/web from revision 3 to 2"),
        "{}",
        rollback.summary
    );
    assert!(
        lines(&rollback)
            .iter()
            .any(|l| l.contains("nginx:1.27") && l.contains("nginx:1.26")),
        "{:?}",
        lines(&rollback)
    );
    assert!(
        lines(&rollback)
            .iter()
            .any(|l| l.starts_with("changed fields: ")
                && l.contains("spec.containers[0].image")
                && l.contains("spec.containers[0].securityContext")),
        "{:?}",
        lines(&rollback)
    );
    assert_eq!(
        rollback.next[0].args["to_revision"], 2,
        "the default resolved into the confirm call"
    );
    for (args, expected) in [
        (
            json!({"name": "web", "to_revision": 1}),
            "has the same pod template as the current one",
        ),
        (
            json!({"name": "web", "to_revision": 3}),
            "already at revision 3",
        ),
        (
            json!({"name": "web", "to_revision": 7}),
            "has no revision 7",
        ),
    ] {
        let err = call(&c, "rollback_workload", args)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains(expected), "{err}");
    }

    let delete = call(&c, "delete_pod", json!({"name": "web-1"}))
        .await
        .unwrap();
    assert_eq!(
        lines(&delete),
        [
            "pod shop/web-1 stops (grace period 45s)",
            "its ReplicaSet web-3 creates a replacement"
        ]
    );

    let cordon = call(&c, "cordon_node", json!({"name": "n1"}))
        .await
        .unwrap();
    assert_eq!(
        lines(&cordon),
        [
            "spec.unschedulable: false → true",
            "its 1 pod(s) keep running; no new pod is scheduled on it (drain_node evicts them)"
        ]
    );
    let uncordon = call(&c, "uncordon_node", json!({"name": "n1"}))
        .await
        .unwrap();
    assert_eq!(
        lines(&uncordon)[0],
        "spec.unschedulable: false (already; nothing changes)"
    );
}

#[tokio::test]
async fn unowned_and_mirror_pods_and_limited_servers_are_refused() {
    let mut terminating = pod(true, false);
    terminating["metadata"]["deletionTimestamp"] = json!("2026-11-14T11:59:00Z");
    for (body, allow, expected) in [
        (pod(false, false), false, "has no owner"),
        (pod(true, true), false, "static pod's mirror"),
        (terminating, false, "already being deleted"),
    ] {
        let m = MockApi::new().get(POD, body).start();
        let err = call(
            &ctx(&m),
            "delete_pod",
            json!({"name": "web-1", "allow_unowned": allow}),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains(expected), "{err}");
        assert!(writes(&m).is_empty());
    }
    let m = MockApi::new()
        .get(POD, pod(false, false))
        .route("DELETE", POD, 200, pod(false, false))
        .start();
    let plan = call(
        &ctx(&m),
        "delete_pod",
        json!({"name": "web-1", "allow_unowned": true}),
    )
    .await
    .unwrap();
    assert!(plan.sections[0].lines[1].contains("gone for good"));

    // A server limited to some namespaces does not touch nodes.
    let m = cluster();
    let mut c = ctx(&m);
    let mut limited = Policy::permissive();
    limited.namespaces = k8s_mcp_core::policy::Patterns::new(&["shop".into()]).unwrap();
    c.policy = Arc::new(limited);
    let err = call(&c, "cordon_node", json!({"name": "n1"}))
        .await
        .unwrap_err();
    assert!(
        err.is_forbidden() && err.to_string().contains("--namespaces"),
        "{err}"
    );
    assert!(m.requests.lock().unwrap().is_empty());
}

/// v0.4 AC 4: the drain plan dry-runs every eviction and names the pods a PodDisruptionBudget
/// blocks; DaemonSet, static, finished and unowned pods are left in place.
#[tokio::test]
async fn drain_plans_each_pod_and_reports_the_ones_a_pdb_blocks() {
    let on_node = |name: &str, owner: Option<(&str, &str)>| {
        let mut p = json!({"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": "shop", "resourceVersion": "1"},
            "spec": {"nodeName": "n1", "containers": [{"name": "c", "image": "x"}]},
            "status": {"phase": "Running"}});
        if let Some((kind, owner)) = owner {
            p["metadata"]["ownerReferences"] = json!([{"apiVersion": "apps/v1", "kind": kind, "name": owner, "uid": "u", "controller": true}]);
        }
        p
    };
    let mut api = on_node("api-1", Some(("ReplicaSet", "api-7")));
    api["spec"]["volumes"] = json!([{"name": "tmp", "emptyDir": {}}]);
    let mut mirror = on_node("etcd-n1", Some(("Node", "n1")));
    mirror["metadata"]["annotations"] = json!({"kubernetes.io/config.mirror": "m"});
    let mut done = on_node("job-done", Some(("Job", "once")));
    done["status"]["phase"] = json!("Succeeded");
    let pods = vec![
        api,
        on_node("db-0", Some(("StatefulSet", "db"))),
        on_node("fluent-x", Some(("DaemonSet", "fluent"))),
        mirror,
        done,
        on_node("loner", None),
    ];
    let node = json!({"apiVersion": "v1", "kind": "Node", "metadata": {"name": "n1", "resourceVersion": "5"}, "spec": {}});
    let blocked = json!({"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "TooManyRequests",
        "message": "Cannot evict pod as it would violate the pod's disruption budget.", "code": 429});
    let ok = json!({"kind": "Status", "apiVersion": "v1", "status": "Success", "code": 201});
    let m = MockApi::new()
        .get(NODE, node.clone())
        .route("PATCH", NODE, 200, node)
        .list("/api/v1/pods", pods)
        .route(
            "POST",
            "/api/v1/namespaces/shop/pods/api-1/eviction",
            201,
            ok,
        )
        .route(
            "POST",
            "/api/v1/namespaces/shop/pods/db-0/eviction",
            429,
            blocked,
        )
        .start();
    let c = ctx(&m);
    let plan = call(&c, "drain_node", json!({"name": "n1"})).await.unwrap();
    assert!(
        plan.summary
            .contains("drain node n1: cordon it, evict 1 pod(s), 1 blocked, 4 left in place"),
        "{}",
        plan.summary
    );
    let lines = &plan.sections[0].lines;
    for expected in [
        "spec.unschedulable: false → true",
        "evict shop/api-1 (ReplicaSet api-7; its emptyDir data is lost)",
        "blocked shop/db-0 (StatefulSet db): a PodDisruptionBudget allows no disruption now (Cannot evict pod as it would violate the pod's disruption budget.)",
        "skip shop/etcd-n1: static pod: the kubelet keeps it on the node",
        "skip shop/fluent-x: DaemonSet fluent: it runs on every node, so it stays",
        "skip shop/job-done: Succeeded: nothing to evict",
    ] {
        assert!(
            lines.iter().any(|l| l == expected),
            "{expected:?} not in {lines:?}"
        );
    }
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("skip shop/loner: no owner")),
        "{lines:?}"
    );
    // The cordon and the two evictable pods, all dry runs; nothing else was written.
    let sent = writes(&m);
    assert_eq!(sent.len(), 3, "{sent:?}");
    assert!(sent.iter().all(|r| dry(r)), "{sent:?}");
    // ignore_daemonsets=false refuses a node that runs DaemonSet pods.
    let err = call(
        &c,
        "drain_node",
        json!({"name": "n1", "ignore_daemonsets": false}),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("ignore_daemonsets=true"), "{err}");
}

/// Discovery for core (configmaps, secrets), apps (deployments) and RBAC.
fn discovery(m: MockApi) -> MockApi {
    let res = |name: &str, kind: &str, namespaced: bool| json!({"name": name, "singularName": "", "kind": kind, "namespaced": namespaced, "verbs": ["get", "list", "patch"]});
    let group = |g: &str| json!({"name": g, "versions": [{"groupVersion": format!("{g}/v1"), "version": "v1"}], "preferredVersion": {"groupVersion": format!("{g}/v1"), "version": "v1"}});
    m.get("/api/v1", json!({"kind": "APIResourceList", "groupVersion": "v1", "resources": [res("configmaps", "ConfigMap", true), res("secrets", "Secret", true), res("namespaces", "Namespace", false)]}))
        .get("/apis", json!({"kind": "APIGroupList", "groups": [group("apps"), group("rbac.authorization.k8s.io"), group("apiregistration.k8s.io")]}))
        .get("/apis/apiregistration.k8s.io/v1", json!({"kind": "APIResourceList", "groupVersion": "apiregistration.k8s.io/v1", "resources": [res("apiservices", "APIService", false)]}))
        .get("/apis/apps/v1", json!({"kind": "APIResourceList", "groupVersion": "apps/v1", "resources": [res("deployments", "Deployment", true)]}))
        .get("/apis/rbac.authorization.k8s.io/v1", json!({"kind": "APIResourceList", "groupVersion": "rbac.authorization.k8s.io/v1", "resources": [res("clusterrolebindings", "ClusterRoleBinding", false)]}))
}

const MANIFEST: &str = "apiVersion: v1
kind: ConfigMap
metadata: {name: app}
data: {level: debug}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: api}
spec:
  replicas: 1
  selector: {matchLabels: {app: api}}
  template:
    metadata: {labels: {app: api}}
    spec: {containers: [{name: api, image: nginx}]}
";

async fn apply(c: &Ctx, manifest: &str) -> k8s_mcp_core::Result<Envelope> {
    k8s_mcp_tools::apply_manifest(
        c,
        k8s_mcp_tools::ApplyManifestInput {
            manifest: manifest.into(),
            ..Default::default()
        },
    )
    .await
}

/// v0.4: apply_manifest plans a server-side dry-run apply per object (never forced) and shows
/// each object's diff; Secrets, RBAC and protected namespaces are refused before any write.
#[tokio::test]
async fn apply_manifest_plans_a_dry_run_apply_per_object() {
    let cm = |level: &str, rv: &str| {
        json!({"apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "app", "namespace": "shop", "resourceVersion": rv}, "data": {"level": level}})
    };
    let dep = json!({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "api", "namespace": "shop"}, "spec": {"replicas": 1}});
    let m = discovery(MockApi::new())
        .get("/api/v1/namespaces/shop/configmaps/app", cm("info", "7"))
        .route(
            "PATCH",
            "/api/v1/namespaces/shop/configmaps/app",
            200,
            cm("debug", "8"),
        )
        .route(
            "PATCH",
            "/apis/apps/v1/namespaces/shop/deployments/api",
            200,
            dep,
        )
        .start();
    let c = ctx(&m);
    let plan = apply(&c, MANIFEST).await.unwrap();
    assert!(
        plan.summary.contains("server-side apply of 2 object(s)"),
        "{}",
        plan.summary
    );
    assert_eq!(
        plan.sections[0].lines,
        [
            "update ConfigMap shop/app:",
            "  data.level: \"info\" → \"debug\"",
            "create Deployment shop/api"
        ]
    );
    let sent = writes(&m);
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert!(
        sent.iter()
            .all(|r| dry(r) && r.contains("fieldManager=k8s-mcp") && !r.contains("force")),
        "{sent:?}"
    );
    // The existing object's apply is conditional on the resourceVersion the plan read.
    let (update, create) = (&sent[0], &sent[1]);
    assert!(update.contains(r#""resourceVersion":"7""#), "{update}");
    assert!(!create.contains("resourceVersion"), "{create}");

    for (manifest, expected) in [
        (
            "apiVersion: v1\nkind: Secret\nmetadata: {name: s}\nstringData: {pw: hunter2}\n",
            "does not apply Secret objects",
        ),
        (
            "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata: {name: me-admin}\n",
            "does not apply ClusterRoleBinding objects",
        ),
        (
            "apiVersion: apiregistration.k8s.io/v1\nkind: APIService\nmetadata: {name: v1.metrics.example}\n",
            "does not apply APIService objects",
        ),
        (
            "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x, namespace: kube-system}\n",
            "protected from writes",
        ),
        (
            "apiVersion: v1\nkind: ConfigMap\nmetadata: {generateName: x-}\n",
            "needs metadata.name",
        ),
        ("kind: [unclosed", "not valid YAML"),
    ] {
        let err = apply(&c, manifest).await.unwrap_err().to_string();
        assert!(err.contains(expected), "{manifest}: {err}");
        assert!(!err.contains("hunter2"), "{err}");
    }
    assert_eq!(writes(&m).len(), 2, "refusals send nothing");
}
