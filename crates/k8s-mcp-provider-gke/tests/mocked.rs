//! GKE reports against a mocked Google Cloud (v0.3 AC 1 and 2): golden snapshots of each
//! tool's rendering. No network: wiremock answers every call, with anonymous credentials.
#![allow(clippy::unwrap_used)]

use google_cloud_auth::credentials::anonymous;
use google_cloud_container_v1::client::ClusterManager;
use google_cloud_iam_admin_v1::client::Iam;
use google_cloud_logging_v2::client::LoggingServiceV2;
use k8s_mcp_core::provider::ProviderId;
use k8s_mcp_provider::{
    LogQuery, Provider, WorkloadIdentity, addons_envelope, cluster_info_envelope,
    identity_envelope, logs_envelope, node_pools_envelope,
};
use k8s_mcp_provider_gke::Gke;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CLUSTER: &str = "/v1/projects/acme/locations/europe-west1/clusters/shop";
const GSA: &str = "/v1/projects/-/serviceAccounts/api@acme.iam.gserviceaccount.com";

fn cluster() -> serde_json::Value {
    json!({
        "name": "shop", "location": "europe-west1", "status": "RUNNING",
        "currentMasterVersion": "1.33.5-gke.1000", "endpoint": "34.76.0.10",
        "releaseChannel": {"channel": "REGULAR"},
        "workloadIdentityConfig": {"workloadPool": "acme.svc.id.goog"},
        "loggingService": "logging.googleapis.com/kubernetes",
        "monitoringService": "monitoring.googleapis.com/kubernetes",
        "controlPlaneEndpointsConfig": {"ipEndpointsConfig": {"enablePublicEndpoint": true, "authorizedNetworksConfig": {"enabled": true}}},
        "addonsConfig": {"httpLoadBalancing": {}, "horizontalPodAutoscaling": {}, "dnsCacheConfig": {"enabled": true},
            "gcePersistentDiskCsiDriverConfig": {"enabled": true}, "gcsFuseCsiDriverConfig": {"enabled": false}},
        "nodePools": [
            {"name": "general", "version": "1.33.5-gke.1000", "status": "RUNNING", "initialNodeCount": 3,
             "config": {"machineType": "e2-standard-4", "workloadMetadataConfig": {"mode": "GKE_METADATA"}},
             "autoscaling": {"enabled": true, "totalMinNodeCount": 3, "totalMaxNodeCount": 12},
             "management": {"autoUpgrade": true, "autoRepair": true}},
            {"name": "legacy", "version": "1.31.9-gke.200", "status": "RUNNING_WITH_ERROR", "initialNodeCount": 1,
             "config": {"machineType": "n1-standard-2", "spot": true, "workloadMetadataConfig": {"mode": "GCE_METADATA"}},
             "conditions": [{"canonicalCode": "RESOURCE_EXHAUSTED", "message": "GCE_STOCKOUT: The zone europe-west1-b does not have enough resources available."}]}
        ]
    })
}

async fn gke(server: &MockServer) -> Gke {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let creds = || anonymous::Builder::new().build();
    let clusters = ClusterManager::builder()
        .with_endpoint(server.uri())
        .with_credentials(creds())
        .build()
        .await
        .unwrap();
    let iam = Iam::builder()
        .with_endpoint(server.uri())
        .with_credentials(creds())
        .build()
        .await
        .unwrap();
    let logging = LoggingServiceV2::builder()
        .with_endpoint(server.uri())
        .with_credentials(creds())
        .build()
        .await
        .unwrap();
    Gke::with_clients(
        clusters,
        iam,
        logging,
        "acme".into(),
        "europe-west1".into(),
        "shop".into(),
    )
}

async fn server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(CLUSTER))
        .respond_with(ResponseTemplate::new(200).set_body_json(cluster()))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn gke_cluster_info() {
    let server = server().await;
    let e = cluster_info_envelope(
        ProviderId::Gke,
        gke(&server).await.cluster_info().await.unwrap(),
    );
    insta::assert_snapshot!(e.render());
}

#[tokio::test]
async fn gke_node_pools() {
    let server = server().await;
    let e = node_pools_envelope(
        ProviderId::Gke,
        gke(&server).await.node_pools().await.unwrap(),
    );
    insta::assert_snapshot!(e.render());
}

#[tokio::test]
async fn gke_addons() {
    let server = server().await;
    let e = addons_envelope(ProviderId::Gke, gke(&server).await.addons().await.unwrap());
    insta::assert_snapshot!(e.render());
}

/// v0.3 AC 2 through the provider: the GSA's policy grants workloadIdentityUser to another
/// ServiceAccount, and a node pool runs GCE_METADATA.
#[tokio::test]
async fn gke_identity_check() {
    let server = server().await;
    Mock::given(method("GET")).and(path(GSA))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": "projects/acme/serviceAccounts/api@acme.iam.gserviceaccount.com", "email": "api@acme.iam.gserviceaccount.com"})))
        .mount(&server).await;
    Mock::given(method("POST")).and(path(format!("{GSA}:getIamPolicy")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"bindings": [{"role": "roles/iam.workloadIdentityUser", "members": ["serviceAccount:acme.svc.id.goog[shop/worker]"]}]})))
        .mount(&server).await;
    let k8s = WorkloadIdentity {
        service_account: serde_json::from_value(json!({"metadata": {"name": "api", "namespace": "shop",
            "annotations": {"iam.gke.io/gcp-service-account": "api@acme.iam.gserviceaccount.com"}}})).unwrap(),
        pods: Vec::new(),
        agent_ready: None,
    };
    let e = identity_envelope(
        ProviderId::Gke,
        "ServiceAccount shop/api",
        gke(&server).await.identity_check(&k8s).await,
    );
    insta::assert_snapshot!(e.render());
}

#[tokio::test]
async fn gke_logs() {
    let server = MockServer::start().await;
    Mock::given(method("POST")).and(path("/v2/entries:list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "entries": [
                {"textPayload": "connect ECONNREFUSED 10.0.3.4:5432", "resource": {"type": "k8s_container", "labels": {"pod_name": "api-1", "namespace_name": "shop"}}},
                {"jsonPayload": {"message": "starting", "level": "info"}, "resource": {"type": "k8s_container", "labels": {"pod_name": "api-1"}}}
            ],
            "nextPageToken": "more"
        })))
        .mount(&server).await;
    let q = LogQuery {
        source: "application".into(),
        namespace: Some("shop".into()),
        grep: Some("ECONN".into()),
        since_ms: 1_794_000_000_000,
        limit: 50,
        ..Default::default()
    };
    let e = logs_envelope(ProviderId::Gke, gke(&server).await.logs(&q).await.unwrap());
    insta::assert_snapshot!(e.render());
}

#[tokio::test]
async fn gke_upgrade_checks() {
    let server = server().await;
    Mock::given(method("GET")).and(path("/v1/projects/acme/locations/europe-west1/serverConfig"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "validMasterVersions": ["1.35.1-gke.100", "1.34.3-gke.200", "1.33.5-gke.1000"],
            "channels": [{"channel": "REGULAR", "validVersions": ["1.34.3-gke.200", "1.33.5-gke.1000"], "upgradeTargetVersion": "1.34.3-gke.200"}]
        })))
        .mount(&server).await;
    let (info, findings) = gke(&server).await.upgrade_checks(None).await.unwrap();
    assert!(findings.is_empty());
    assert_eq!(
        info.available,
        ["1.34"],
        "the REGULAR channel's versions, not every valid master version"
    );
    insta::assert_snapshot!(k8s_mcp_provider::upgrade_lines(ProviderId::Gke, &info).join("\n"));
}

/// A missing cluster maps to NotFound with the flag to pass.
#[tokio::test]
async fn gke_errors_say_what_to_do() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(path(CLUSTER))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"error": {"code": 404, "message": "Not found: projects/acme/locations/europe-west1/clusters/shop.", "status": "NOT_FOUND"}})))
        .mount(&server).await;
    let err = gke(&server)
        .await
        .cluster_info()
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("not found") && err.contains("--gke-cluster"),
        "{err}"
    );
}
