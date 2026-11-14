//! Fixture loading for rule tests.
//!
//! A pod fixture is a multi-document YAML file under `k8s-mcp-testkit/fixtures/` holding
//! one `Pod` plus any of: `Event`, `Node`, `PersistentVolumeClaim`, `ServiceAccount`, and
//! these pseudo-kinds for evidence that has no API object:
//!
//! ```yaml
//! kind: ContainerLog      # one per container log tail
//! container: app
//! previous: true
//! lines: ["line 1", "line 2"]
//! ---
//! kind: RefCheck          # existence of a referenced object
//! refKind: ConfigMap      # ConfigMap | Secret | PersistentVolumeClaim | ServiceAccount
//! name: app-config
//! exists: false           # omit for "not checked (forbidden)"
//! keys: [a, b]            # optional
//! ---
//! kind: Unavailable
//! what: previous logs of container app
//! reason: forbidden
//! ```
//!
//! Nodes listed are used both as `nodes` and (when the pod's `spec.nodeName` matches)
//! as `node`. All timestamps are relative to [`k8s_mcp_testkit::now`].

use k8s_mcp_testkit::{Fixture, load, now};
use k8s_openapi::api::core::v1::{Node, Pod};
use serde_json::Value;

use crate::evidence::{ContainerLog, PodEvidence, RefCheck, RefKind, Unavailable};

/// Load a pod fixture into a [`PodEvidence`].
pub fn pod_fixture(name: &str) -> PodEvidence {
    pod_evidence(&load(name))
}

/// Build a [`PodEvidence`] from an already-loaded fixture.
pub fn pod_evidence(fx: &Fixture) -> PodEvidence {
    let pod: Pod = fx.one("Pod");
    let nodes: Vec<Node> = fx.all("Node");
    let node_name = pod.spec.as_ref().and_then(|s| s.node_name.clone());
    let node = nodes.iter().find(|n| n.metadata.name == node_name).cloned();
    PodEvidence {
        events: fx.all("Event"),
        logs: pseudo(fx, "ContainerLog")
            .map(|o| ContainerLog {
                container: o["container"].as_str().unwrap().to_owned(),
                previous: o["previous"].as_bool().unwrap_or(false),
                lines: o["lines"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|l| l.as_str().unwrap().to_owned())
                    .collect(),
            })
            .collect(),
        nodes: (!nodes.is_empty()).then(|| nodes.clone()),
        node,
        refs: pseudo(fx, "RefCheck")
            .map(|o| RefCheck {
                kind: match o["refKind"].as_str().unwrap() {
                    "ConfigMap" => RefKind::ConfigMap,
                    "Secret" => RefKind::Secret,
                    "PersistentVolumeClaim" => RefKind::PersistentVolumeClaim,
                    "ServiceAccount" => RefKind::ServiceAccount,
                    other => panic!("unknown refKind {other}"),
                },
                name: o["name"].as_str().unwrap().to_owned(),
                exists: o["exists"].as_bool(),
                keys: o["keys"]
                    .as_array()
                    .map(|a| a.iter().map(|k| k.as_str().unwrap().to_owned()).collect()),
            })
            .collect(),
        pvcs: fx.all("PersistentVolumeClaim"),
        service_account: fx.first("ServiceAccount"),
        unavailable: pseudo(fx, "Unavailable")
            .map(|o| Unavailable {
                what: o["what"].as_str().unwrap().to_owned(),
                reason: o["reason"].as_str().unwrap().to_owned(),
            })
            .collect(),
        now: now(),
        pod,
    }
}

fn pseudo<'a>(fx: &'a Fixture, kind: &'a str) -> impl Iterator<Item = &'a Value> {
    fx.objects.iter().filter(move |o| o["kind"] == kind)
}
