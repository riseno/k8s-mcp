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
//!
//! A workload fixture (`workloads/`) holds one workload: the first Deployment, StatefulSet,
//! DaemonSet or CronJob, else the first Job, else the first ReplicaSet. Alongside it may be
//! ReplicaSets (a Deployment's), Jobs (a CronJob's, newest first), `ResourceQuota`s, a
//! `HorizontalPodAutoscaler`, Events, Pods and anything a pod fixture accepts. Each Pod
//! becomes a [`PodEvidence`] whose events are the Events whose `involvedObject.name` is that
//! pod; the remaining Events are the workload's. Pseudo-kinds apply to every pod unless they
//! carry `pod: <name>`.
//!
//! A Service fixture (`services/`) holds one Service, the Pods of its namespace and the
//! Service's Events.
//!
//! A PVC fixture (`pvcs/`) holds one PersistentVolumeClaim, the cluster's StorageClasses, an
//! optional PersistentVolume, the Pods that use the claim and Events about either.
//!
//! A DNS fixture (`dns/`): see [`dns_fixture`].
//!
//! A node fixture (`nodes/`) holds one Node plus any Events, Pods (all taken as running on
//! the node; with no Pod documents `pods` is `None`, i.e. unreadable), `Unavailable`, and
//! this pseudo-kind for the API server version:
//!
//! ```yaml
//! kind: ServerVersion
//! major: 1
//! minor: 33
//! ```

use k8s_mcp_testkit::{Fixture, load, now};
use k8s_openapi::api::core::v1::{Event, Node, Pod};
use serde_json::Value;

use crate::evidence::{
    ContainerLog, DnsEvidence, NodeEvidence, PodEvidence, PvcEvidence, RefCheck, RefKind,
    ServiceEvidence, Unavailable, Workload, WorkloadEvidence,
};

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
        unavailable: unavailable(fx),
        now: now(),
        pod,
    }
}

/// Load a workload fixture into a [`WorkloadEvidence`].
pub fn workload_fixture(name: &str) -> WorkloadEvidence {
    let fx = load(name);
    let workload = if let Some(w) = fx.first("Deployment") {
        Workload::Deployment(w)
    } else if let Some(w) = fx.first("StatefulSet") {
        Workload::StatefulSet(w)
    } else if let Some(w) = fx.first("DaemonSet") {
        Workload::DaemonSet(w)
    } else if let Some(w) = fx.first("CronJob") {
        Workload::CronJob(w)
    } else if let Some(w) = fx.first("Job") {
        Workload::Job(w)
    } else {
        Workload::ReplicaSet(fx.first("ReplicaSet").expect("a workload document"))
    };
    let pods: Vec<&Value> = pseudo(&fx, "Pod").collect();
    let pod_name = |o: &Value| o["metadata"]["name"].as_str().unwrap().to_owned();
    let pod_names: Vec<String> = pods.iter().map(|p| pod_name(p)).collect();
    let pod_evidences = pods
        .iter()
        .map(|p| {
            let name = pod_name(p);
            let objects = fx
                .objects
                .iter()
                .filter(|o| match o["kind"].as_str() {
                    Some("Pod") => o == p,
                    Some("Event") => o["involvedObject"]["name"] == name.as_str(),
                    _ => o["pod"].as_str().is_none_or(|n| n == name),
                })
                .cloned()
                .collect();
            pod_evidence(&Fixture { objects })
        })
        .collect();
    let mut events: Vec<Event> = fx.all("Event");
    events.retain(|e| {
        e.involved_object
            .name
            .as_ref()
            .is_none_or(|n| !pod_names.contains(n))
    });
    WorkloadEvidence {
        replicasets: match workload {
            Workload::Deployment(_) => fx.all("ReplicaSet"),
            _ => Vec::new(),
        },
        jobs: match workload {
            Workload::CronJob(_) => fx.all("Job"),
            _ => Vec::new(),
        },
        workload,
        events,
        pod_count: Some(pod_names.len()),
        pods: pod_evidences,
        quotas: fx.all("ResourceQuota"),
        hpa: fx.first("HorizontalPodAutoscaler"),
        unavailable: unavailable(&fx),
        now: now(),
    }
}

/// Load a node fixture into a [`NodeEvidence`].
pub fn node_fixture(name: &str) -> NodeEvidence {
    let fx = load(name);
    let pods: Vec<Pod> = fx.all("Pod");
    let version = |o: &Value, k: &str| u32::try_from(o[k].as_u64().unwrap()).unwrap();
    NodeEvidence {
        node: fx.one("Node"),
        events: fx.all("Event"),
        pods: (!pods.is_empty()).then_some(pods),
        server_version: pseudo(&fx, "ServerVersion")
            .next()
            .map(|o| (version(o, "major"), version(o, "minor"))),
        unavailable: unavailable(&fx),
        now: now(),
    }
}

/// Load a Service fixture (`services/`): one Service plus the namespace's Pods and the
/// Service's Events.
pub fn service_fixture(name: &str) -> ServiceEvidence {
    let fx = load(name);
    ServiceEvidence {
        service: fx.one("Service"),
        pods: Some(fx.all("Pod")),
        events: fx.all("Event"),
        unavailable: unavailable(&fx),
        now: now(),
    }
}

/// Load a PVC fixture (`pvcs/`): one PersistentVolumeClaim, the StorageClasses, an optional
/// PersistentVolume, the Pods using the claim, and Events (about the claim, or about a Pod).
pub fn pvc_fixture(name: &str) -> PvcEvidence {
    let fx = load(name);
    let events: Vec<Event> = fx.all("Event");
    let about = |kind: &str| {
        events
            .iter()
            .filter(|e| e.involved_object.kind.as_deref() == Some(kind))
            .cloned()
            .collect()
    };
    PvcEvidence {
        pvc: fx.one("PersistentVolumeClaim"),
        storage_classes: Some(fx.all("StorageClass")),
        pv: fx.first("PersistentVolume"),
        events: about("PersistentVolumeClaim"),
        pods: fx.all("Pod"),
        pod_events: about("Pod"),
        unavailable: unavailable(&fx),
        now: now(),
    }
}

/// Load a DNS fixture (`dns/`). Pods in kube-system labeled `k8s-app: kube-dns` are the DNS
/// pods; the first other Pod is the pod under test. `ContainerLog`s carry `pod: <name>`. The
/// Service (if any) is kube-dns, and EndpointSlices give its ready endpoints.
pub fn dns_fixture(name: &str) -> DnsEvidence {
    let fx = load(name);
    let is_dns = |p: &Pod| {
        p.metadata.namespace.as_deref() == Some("kube-system")
            && p.metadata
                .labels
                .as_ref()
                .is_some_and(|l| l.get("k8s-app").is_some_and(|v| v == "kube-dns"))
    };
    let (dns_pods, others): (Vec<Pod>, Vec<Pod>) =
        fx.all::<Pod>("Pod").into_iter().partition(is_dns);
    let pod = others.into_iter().next();
    let dns_names: Vec<String> = dns_pods
        .iter()
        .filter_map(|p| p.metadata.name.clone())
        .collect();
    let (mut dns_logs, mut pod_logs) = (Vec::new(), Vec::new());
    for o in pseudo(&fx, "ContainerLog") {
        let log = ContainerLog {
            container: o["container"].as_str().unwrap().to_owned(),
            previous: false,
            lines: o["lines"]
                .as_array()
                .unwrap()
                .iter()
                .map(|l| l.as_str().unwrap().to_owned())
                .collect(),
        };
        if dns_names.iter().any(|n| o["pod"] == n.as_str()) {
            dns_logs.push(log);
        } else {
            pod_logs.push(log);
        }
    }
    let slices: Vec<k8s_openapi::api::discovery::v1::EndpointSlice> = fx.all("EndpointSlice");
    DnsEvidence {
        namespace: pod
            .as_ref()
            .and_then(|p| p.metadata.namespace.clone())
            .unwrap_or_else(|| "shop".into()),
        pod,
        pod_logs,
        network_policies: Some(fx.all("NetworkPolicy")),
        dns_pods: Some(dns_pods),
        dns_service: Some(fx.first("Service")),
        dns_ready_endpoints: Some(
            slices
                .iter()
                .flat_map(|s| &s.endpoints)
                .filter(|e| e.conditions.as_ref().and_then(|c| c.ready) != Some(false))
                .count(),
        ),
        dns_logs,
        unavailable: unavailable(&fx),
        now: now(),
    }
}

fn unavailable(fx: &Fixture) -> Vec<Unavailable> {
    pseudo(fx, "Unavailable")
        .map(|o| Unavailable {
            what: o["what"].as_str().unwrap().to_owned(),
            reason: o["reason"].as_str().unwrap().to_owned(),
        })
        .collect()
}

fn pseudo<'a>(fx: &'a Fixture, kind: &'a str) -> impl Iterator<Item = &'a Value> {
    fx.objects.iter().filter(move |o| o["kind"] == kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workload_pods_get_their_own_events() {
        let ev = workload_fixture("workloads/rollout-stuck.yaml");
        assert!(matches!(ev.workload, Workload::Deployment(_)));
        assert_eq!(
            (ev.pods.len(), ev.pod_count, ev.replicasets.len()),
            (2, Some(2), 1)
        );
        for p in &ev.pods {
            assert!(!p.events.is_empty());
            assert!(
                p.events
                    .iter()
                    .all(|e| e.involved_object.name == p.pod.metadata.name)
            );
        }
        assert!(
            ev.events
                .iter()
                .all(|e| e.involved_object.kind.as_deref() != Some("Pod"))
        );
    }
}
