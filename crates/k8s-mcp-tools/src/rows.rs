//! Kind-aware compact rows (like `kubectl get -o wide`) and pod health.

use jiff::Timestamp;
use k8s_mcp_core::text::age;
use k8s_openapi::api::core::v1::{Node, Pod};
use serde_json::{Value, json};

/// Columns shown for a kind (the `ns` column is added for cross-namespace lists).
pub fn columns(kind: &str, all_namespaces: bool) -> Vec<&'static str> {
    let mut cols: Vec<&'static str> = match kind {
        "Pod" => vec!["name", "ready", "status", "restarts", "age", "node"],
        "Deployment" => vec!["name", "ready", "up_to_date", "available", "age", "images"],
        "StatefulSet" => vec!["name", "ready", "age", "images"],
        "DaemonSet" => vec!["name", "desired", "ready", "up_to_date", "available", "age"],
        "ReplicaSet" => vec!["name", "desired", "ready", "age", "images"],
        "Job" => vec!["name", "status", "completions", "age"],
        "CronJob" => vec![
            "name",
            "schedule",
            "suspend",
            "active",
            "last_schedule",
            "age",
        ],
        "Service" => vec!["name", "type", "cluster_ip", "ports", "age"],
        "Node" => vec!["name", "status", "roles", "version", "age"],
        "PersistentVolumeClaim" => vec![
            "name",
            "status",
            "volume",
            "capacity",
            "storage_class",
            "age",
        ],
        "Secret" => vec!["name", "type", "keys", "age"],
        "ConfigMap" => vec!["name", "keys", "age"],
        _ => vec!["name", "status", "age"],
    };
    if all_namespaces {
        cols.insert(0, "ns");
    }
    cols
}

/// One compact row for an object of `kind` (as JSON). Never includes Secret or ConfigMap
/// values.
pub fn row(kind: &str, o: &Value, now: Timestamp) -> Value {
    let s = |p: &str| {
        o.pointer(p)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    };
    let n = |p: &str| o.pointer(p).and_then(Value::as_i64).unwrap_or(0);
    let created = o
        .pointer("/metadata/creationTimestamp")
        .and_then(Value::as_str)
        .and_then(|t| t.parse::<Timestamp>().ok())
        .map(|t| age(now, t));
    let images = || -> Vec<String> {
        [
            "/spec/template/spec/containers",
            "/spec/jobTemplate/spec/template/spec/containers",
        ]
        .iter()
        .filter_map(|p| o.pointer(p).and_then(Value::as_array))
        .flatten()
        .filter_map(|c| c["image"].as_str().map(str::to_owned))
        .collect()
    };
    let mut r = match kind {
        "Pod" => match serde_json::from_value::<Pod>(o.clone()) {
            Ok(p) => pod_row(&p),
            Err(_) => json!({}),
        },
        "Deployment" => json!({
            "ready": format!("{}/{}", n("/status/readyReplicas"), n("/spec/replicas")),
            "up_to_date": n("/status/updatedReplicas"),
            "available": n("/status/availableReplicas"),
            "images": images(),
        }),
        "StatefulSet" => json!({
            "ready": format!("{}/{}", n("/status/readyReplicas"), n("/spec/replicas")),
            "images": images(),
        }),
        "DaemonSet" => json!({
            "desired": n("/status/desiredNumberScheduled"),
            "ready": n("/status/numberReady"),
            "up_to_date": n("/status/updatedNumberScheduled"),
            "available": n("/status/numberAvailable"),
        }),
        "ReplicaSet" => json!({
            "desired": n("/spec/replicas"),
            "ready": n("/status/readyReplicas"),
            "images": images(),
        }),
        "Job" => {
            let status = o
                .pointer("/status/conditions")
                .and_then(Value::as_array)
                .and_then(|c| {
                    c.iter()
                        .find(|c| c["status"] == "True")
                        .and_then(|c| c["type"].as_str())
                })
                .unwrap_or(if n("/status/active") > 0 {
                    "Running"
                } else {
                    "Pending"
                })
                .to_owned();
            json!({
                "status": status,
                "completions": format!("{}/{}", n("/status/succeeded"), o.pointer("/spec/completions").and_then(Value::as_i64).unwrap_or(1)),
            })
        }
        "CronJob" => json!({
            "schedule": s("/spec/schedule"),
            "suspend": o.pointer("/spec/suspend").and_then(Value::as_bool).unwrap_or(false),
            "active": o.pointer("/status/active").and_then(Value::as_array).map_or(0, Vec::len),
            "last_schedule": o.pointer("/status/lastScheduleTime").and_then(Value::as_str).and_then(|t| t.parse::<Timestamp>().ok()).map(|t| age(now, t)),
        }),
        "Service" => json!({
            "type": s("/spec/type"),
            "cluster_ip": s("/spec/clusterIP"),
            "ports": o.pointer("/spec/ports").and_then(Value::as_array).map(|ps| ps.iter().map(|p| format!(
                "{}/{}",
                p["port"].as_i64().unwrap_or(0),
                p["protocol"].as_str().unwrap_or("TCP")
            )).collect::<Vec<_>>()),
        }),
        "Node" => match serde_json::from_value::<Node>(o.clone()) {
            Ok(node) => node_row(&node),
            Err(_) => json!({}),
        },
        "PersistentVolumeClaim" => json!({
            "status": s("/status/phase"),
            "volume": s("/spec/volumeName"),
            "capacity": s("/status/capacity/storage"),
            "storage_class": s("/spec/storageClassName"),
        }),
        "Secret" => json!({
            "type": s("/type"),
            "keys": o.get("data").and_then(Value::as_object).map_or(0, serde_json::Map::len),
        }),
        "ConfigMap" => json!({
            "keys": o.get("data").and_then(Value::as_object).map_or(0, serde_json::Map::len)
                + o.get("binaryData").and_then(Value::as_object).map_or(0, serde_json::Map::len),
        }),
        _ => json!({ "status": generic_status(o) }),
    };
    if let Some(m) = r.as_object_mut() {
        m.insert("name".into(), json!(s("/metadata/name")));
        if let Some(ns) = o.pointer("/metadata/namespace").and_then(Value::as_str) {
            m.insert("ns".into(), json!(ns));
        }
        m.entry("age").or_insert(json!(created));
    }
    r
}

/// `status.phase`, else the Ready/Available condition, else `-`.
fn generic_status(o: &Value) -> String {
    if let Some(p) = o.pointer("/status/phase").and_then(Value::as_str) {
        return p.to_owned();
    }
    let conds = o.pointer("/status/conditions").and_then(Value::as_array);
    for t in ["Ready", "Available", "Established", "Synced"] {
        if let Some(c) = conds.and_then(|c| c.iter().find(|c| c["type"] == t)) {
            return format!("{t}={}", c["status"].as_str().unwrap_or("?"));
        }
    }
    "-".into()
}

/// Pod row: ready, status, restarts, node.
pub fn pod_row(p: &Pod) -> Value {
    let statuses = p
        .status
        .as_ref()
        .and_then(|s| s.container_statuses.as_deref())
        .unwrap_or_default();
    let total = p.spec.as_ref().map_or(0, |s| s.containers.len());
    let ready = statuses.iter().filter(|c| c.ready).count();
    let restarts: i32 = statuses.iter().map(|c| c.restart_count).sum();
    json!({
        "ready": format!("{ready}/{total}"),
        "status": pod_status(p),
        "restarts": restarts,
        "node": p.spec.as_ref().and_then(|s| s.node_name.clone()),
    })
}

/// kubectl-style display status: a waiting/terminated reason if any, else the phase.
pub fn pod_status(p: &Pod) -> String {
    if p.metadata.deletion_timestamp.is_some() {
        return "Terminating".into();
    }
    let st = p.status.as_ref();
    if let Some(r) = st.and_then(|s| s.reason.clone()) {
        return r; // Evicted, NodeLost, ...
    }
    let init = st
        .and_then(|s| s.init_container_statuses.as_deref())
        .unwrap_or_default();
    for c in init {
        if let Some(w) = c
            .state
            .as_ref()
            .and_then(|s| s.waiting.as_ref())
            .and_then(|w| w.reason.as_deref())
            && w != "PodInitializing"
        {
            return format!("Init:{w}");
        }
        if let Some(t) = c.state.as_ref().and_then(|s| s.terminated.as_ref())
            && t.exit_code != 0
        {
            return format!("Init:{}", t.reason.as_deref().unwrap_or("Error"));
        }
    }
    let containers = st
        .and_then(|s| s.container_statuses.as_deref())
        .unwrap_or_default();
    for c in containers {
        if let Some(w) = c
            .state
            .as_ref()
            .and_then(|s| s.waiting.as_ref())
            .and_then(|w| w.reason.clone())
        {
            return w;
        }
    }
    for c in containers {
        if let Some(t) = c.state.as_ref().and_then(|s| s.terminated.as_ref()) {
            return t
                .reason
                .clone()
                .unwrap_or_else(|| format!("ExitCode:{}", t.exit_code));
        }
    }
    let phase = st
        .and_then(|s| s.phase.clone())
        .unwrap_or_else(|| "Unknown".into());
    if phase == "Running" && containers.iter().any(|c| !c.ready) {
        return "Running (not ready)".into();
    }
    phase
}

/// Whether a pod needs attention, and why (its display status).
pub fn unhealthy(p: &Pod, now: Timestamp) -> Option<String> {
    let status = pod_status(p);
    let age_secs = p
        .metadata
        .creation_timestamp
        .as_ref()
        .map_or(i64::MAX, |t| now.duration_since(t.0).as_secs());
    let phase = p
        .status
        .as_ref()
        .and_then(|s| s.phase.as_deref())
        .unwrap_or("Unknown");
    match (phase, status.as_str()) {
        ("Succeeded", _) | ("Running", "Running") => None,
        // A Completed container that keeps restarting is an exit-0 crash loop, not done.
        (_, "Completed") if restarts(p) == 0 => None,
        // Give new pods two minutes to start or become ready.
        ("Pending", "Pending" | "ContainerCreating" | "PodInitializing")
        | ("Running", "Running (not ready)")
            if age_secs < 120 =>
        {
            None
        }
        _ => Some(status),
    }
}

fn restarts(p: &Pod) -> i32 {
    p.status
        .as_ref()
        .and_then(|s| s.container_statuses.as_ref())
        .map_or(0, |c| c.iter().map(|c| c.restart_count).sum())
}

/// Node row: status, roles, version.
pub fn node_row(n: &Node) -> Value {
    let ready = n
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .and_then(|c| c.iter().find(|c| c.type_ == "Ready"))
        .map_or("Unknown", |c| {
            if c.status == "True" {
                "Ready"
            } else {
                "NotReady"
            }
        });
    let mut status = ready.to_owned();
    if n.spec
        .as_ref()
        .and_then(|s| s.unschedulable)
        .unwrap_or(false)
    {
        status.push_str(",SchedulingDisabled");
    }
    let roles: Vec<String> = n
        .metadata
        .labels
        .iter()
        .flatten()
        .filter_map(|(k, _)| {
            k.strip_prefix("node-role.kubernetes.io/")
                .map(str::to_owned)
        })
        .collect();
    json!({
        "status": status,
        "roles": roles,
        "version": n.status.as_ref().and_then(|s| s.node_info.as_ref()).map(|i| i.kubelet_version.clone()),
        "pool": node_pool(n),
    })
}

/// Node pool / group from well-known labels (EKS, GKE, AKS, Karpenter, kind).
pub fn node_pool(n: &Node) -> String {
    const LABELS: &[&str] = &[
        "eks.amazonaws.com/nodegroup",
        "cloud.google.com/gke-nodepool",
        "kubernetes.azure.com/agentpool",
        "karpenter.sh/nodepool",
        "node.kubernetes.io/instance-type",
    ];
    let labels = n.metadata.labels.as_ref();
    LABELS
        .iter()
        .find_map(|l| labels.and_then(|m| m.get(*l)).cloned())
        .unwrap_or_else(|| "-".into())
}

/// Provider from node `spec.providerID` (PROPOSAL §10.2).
pub fn provider_from_nodes(nodes: &[Node]) -> Option<&'static str> {
    nodes.iter().find_map(|n| {
        let id = n.spec.as_ref()?.provider_id.as_deref()?;
        if id.starts_with("aws://") {
            Some("eks")
        } else if id.starts_with("gce://") {
            Some("gke")
        } else if id.starts_with("azure://") {
            Some("aks")
        } else if id.starts_with("kind://") {
            Some("kind")
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod(v: Value) -> Pod {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn pod_status_prefers_waiting_reason() {
        let p = pod(json!({
            "metadata": {"name": "a"},
            "status": {"phase": "Running", "containerStatuses": [
                {"name": "c", "ready": false, "restartCount": 3, "image": "i", "imageID": "",
                 "state": {"waiting": {"reason": "CrashLoopBackOff"}}}
            ]}
        }));
        assert_eq!(pod_status(&p), "CrashLoopBackOff");
        let now: Timestamp = "2026-11-14T12:00:00Z".parse().unwrap();
        assert_eq!(unhealthy(&p, now).as_deref(), Some("CrashLoopBackOff"));
    }

    #[test]
    fn completed_with_restarts_is_unhealthy() {
        let now: Timestamp = "2026-11-14T12:00:00Z".parse().unwrap();
        let p = pod(json!({
            "metadata": {"name": "a"},
            "status": {"phase": "Running", "containerStatuses": [
                {"name": "c", "ready": false, "restartCount": 4, "image": "i", "imageID": "",
                 "state": {"terminated": {"exitCode": 0, "reason": "Completed"}}}
            ]}
        }));
        assert_eq!(unhealthy(&p, now).as_deref(), Some("Completed"));
    }

    #[test]
    fn young_pending_pod_is_not_flagged() {
        let p = pod(
            json!({"metadata": {"name": "a", "creationTimestamp": "2026-11-14T11:59:30Z"}, "status": {"phase": "Pending"}}),
        );
        let now: Timestamp = "2026-11-14T12:00:00Z".parse().unwrap();
        assert_eq!(unhealthy(&p, now), None);
    }

    #[test]
    fn secret_rows_show_key_counts_not_values() {
        let s = json!({"kind": "Secret", "metadata": {"name": "db"}, "type": "Opaque", "data": {"password": "aHVudGVyMg=="}});
        let now: Timestamp = "2026-11-14T12:00:00Z".parse().unwrap();
        let r = row("Secret", &s, now);
        assert_eq!(r["keys"], 1);
        assert!(!r.to_string().contains("aHVudGVyMg"));
    }
}
