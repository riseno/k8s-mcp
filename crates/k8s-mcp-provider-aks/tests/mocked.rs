//! AKS reports against mocked ARM and Log Analytics (v0.3 AC 1 and 2): golden snapshots of
//! each tool's rendering. No network: wiremock answers every call, with a static token.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use azure_core::credentials::{AccessToken, TokenCredential, TokenRequestOptions};
use azure_core::time::{Duration, OffsetDateTime};
use k8s_mcp_core::provider::ProviderId;
use k8s_mcp_provider::{
    LogQuery, Provider, WorkloadIdentity, addons_envelope, cluster_info_envelope,
    identity_envelope, logs_envelope, node_pools_envelope,
};
use k8s_mcp_provider_aks::Aks;
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Debug)]
struct StaticToken;

#[async_trait::async_trait]
impl TokenCredential for StaticToken {
    async fn get_token(
        &self,
        _: &[&str],
        _: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        Ok(AccessToken::new(
            "fake-token",
            OffsetDateTime::now_utc() + Duration::hours(1),
        ))
    }
}

const CLUSTER: &str = "/subscriptions/sub-1/resourceGroups/shop-rg/providers/Microsoft.ContainerService/managedClusters/shop";
const ISSUER: &str = "https://westeurope.oic.prod-aks.azure.com/tenant-1/guid-1/";

fn cluster() -> serde_json::Value {
    json!({
        "name": "shop", "location": "westeurope", "sku": {"tier": "Standard"},
        "properties": {
            "provisioningState": "Succeeded", "powerState": {"code": "Running"},
            "kubernetesVersion": "1.33", "currentKubernetesVersion": "1.33.2",
            "fqdn": "shop-abc.hcp.westeurope.azmk8s.io",
            "networkProfile": {"networkPlugin": "azure", "networkPluginMode": "overlay"},
            "apiServerAccessProfile": {"authorizedIPRanges": ["203.0.113.0/24"]},
            "oidcIssuerProfile": {"enabled": true, "issuerURL": ISSUER},
            "securityProfile": {"workloadIdentity": {"enabled": true}},
            "aadProfile": {"managed": true, "enableAzureRBAC": true},
            "disableLocalAccounts": true,
            "supportPlan": "KubernetesOfficial",
            "autoUpgradeProfile": {"upgradeChannel": "patch"},
            "addonProfiles": {
                "azurepolicy": {"enabled": true},
                "omsagent": {"enabled": true, "config": {"logAnalyticsWorkspaceResourceID": "/subscriptions/sub-1/resourceGroups/ops/providers/Microsoft.OperationalInsights/workspaces/ops-logs"}}
            },
            "agentPoolProfiles": [
                {"name": "system", "mode": "System", "vmSize": "Standard_D4s_v5", "count": 3, "enableAutoScaling": true, "minCount": 3, "maxCount": 6,
                 "orchestratorVersion": "1.33.2", "currentOrchestratorVersion": "1.33.2", "provisioningState": "Succeeded", "powerState": {"code": "Running"}},
                {"name": "batch", "mode": "User", "vmSize": "Standard_D8s_v5", "count": 0, "scaleSetPriority": "Spot",
                 "orchestratorVersion": "1.31.8", "currentOrchestratorVersion": "1.31.8", "provisioningState": "Failed", "powerState": {"code": "Running"},
                 "nodeImageVersion": "AKSUbuntu-2204gen2containerd-202611.03.0"}
            ]
        }
    })
}

async fn server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(CLUSTER))
        .and(header("authorization", "Bearer fake-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(cluster()))
        .mount(&server)
        .await;
    server
}

fn aks(server: &MockServer) -> Aks {
    let _ = rustls::crypto::ring::default_provider().install_default();
    Aks::with_clients(
        reqwest::Client::new(),
        Arc::new(StaticToken),
        server.uri(),
        server.uri(),
        "sub-1".into(),
        "shop-rg".into(),
        "shop".into(),
    )
}

#[tokio::test]
async fn aks_cluster_info() {
    let server = server().await;
    let e = cluster_info_envelope(ProviderId::Aks, aks(&server).cluster_info().await.unwrap());
    insta::assert_snapshot!(e.render());
}

#[tokio::test]
async fn aks_node_pools() {
    let server = server().await;
    let e = node_pools_envelope(ProviderId::Aks, aks(&server).node_pools().await.unwrap());
    insta::assert_snapshot!(e.render());
}

#[tokio::test]
async fn aks_addons() {
    let server = server().await;
    Mock::given(method("GET")).and(path(format!("{CLUSTER}/providers/Microsoft.KubernetesConfiguration/extensions")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"value": [
            {"name": "flux", "properties": {"extensionType": "microsoft.flux", "version": "1.15.1", "provisioningState": "Succeeded"}}
        ]})))
        .mount(&server).await;
    let e = addons_envelope(ProviderId::Aks, aks(&server).addons().await.unwrap());
    insta::assert_snapshot!(e.render());
}

/// v0.3 AC 2 through the provider: the identity's federated credential names another
/// ServiceAccount (and the identity list is paged).
#[tokio::test]
async fn aks_identity_check() {
    let server = server().await;
    let identities =
        "/subscriptions/sub-1/providers/Microsoft.ManagedIdentity/userAssignedIdentities";
    let identity = "/subscriptions/sub-1/resourceGroups/shop-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/shop-api";
    Mock::given(method("GET")).and(path(identities))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{"name": "other", "id": "/x", "properties": {"clientId": "99999999-0000-0000-0000-000000000000"}}],
            "nextLink": format!("{}{identities}?api-version=2024-11-30&$skiptoken=2", server.uri())
        })))
        .up_to_n_times(1)
        .mount(&server).await;
    Mock::given(method("GET")).and(path(identities))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{"name": "shop-api", "id": identity, "properties": {"clientId": "11111111-2222-3333-4444-555555555555"}}]
        })))
        .mount(&server).await;
    Mock::given(method("GET")).and(path(format!("{identity}/federatedIdentityCredentials")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"value": [
            {"name": "shop-worker", "properties": {"issuer": ISSUER, "subject": "system:serviceaccount:shop:worker", "audiences": ["api://AzureADTokenExchange"]}}
        ]})))
        .mount(&server).await;
    let k8s = WorkloadIdentity {
        service_account: serde_json::from_value(json!({"metadata": {"name": "api", "namespace": "shop",
            "annotations": {"azure.workload.identity/client-id": "11111111-2222-3333-4444-555555555555"}}})).unwrap(),
        pods: vec![serde_json::from_value(json!({"metadata": {"name": "api-1", "labels": {"azure.workload.identity/use": "true"}},
            "spec": {"containers": [{"name": "app", "env": [{"name": "AZURE_FEDERATED_TOKEN_FILE", "value": "/var/run/secrets/azure/tokens/azure-identity-token"}]}]}})).unwrap()],
        agent_ready: None,
    };
    let e = identity_envelope(
        ProviderId::Aks,
        "ServiceAccount shop/api",
        aks(&server).identity_check(&k8s).await,
    );
    insta::assert_snapshot!(e.render());
}

#[tokio::test]
async fn aks_logs() {
    let server = server().await;
    Mock::given(method("GET")).and(path("/subscriptions/sub-1/resourceGroups/ops/providers/Microsoft.OperationalInsights/workspaces/ops-logs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"properties": {"customerId": "ws-guid"}})))
        .mount(&server).await;
    Mock::given(method("POST")).and(path("/v1/workspaces/ws-guid/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"tables": [{"name": "PrimaryResult",
            "columns": [{"name": "TimeGenerated", "type": "datetime"}, {"name": "Who", "type": "string"}, {"name": "Message", "type": "string"}],
            "rows": [["2026-11-16T11:59:00Z", "api-1", "connect ECONNREFUSED 10.0.3.4:5432"], ["2026-11-16T11:58:00Z", "api-1", "starting"]]}]})))
        .mount(&server).await;
    let q = LogQuery {
        source: "application".into(),
        namespace: Some("shop".into()),
        grep: Some("ECONN".into()),
        since_ms: 1_794_000_000_000,
        limit: 50,
        ..Default::default()
    };
    let e = logs_envelope(ProviderId::Aks, aks(&server).logs(&q).await.unwrap());
    insta::assert_snapshot!(e.render());
}

#[tokio::test]
async fn aks_upgrade_checks() {
    let server = server().await;
    Mock::given(method("GET")).and(path(format!("{CLUSTER}/upgradeProfiles/default")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"properties": {"controlPlaneProfile": {"kubernetesVersion": "1.33.2",
            "upgrades": [{"kubernetesVersion": "1.33.5"}, {"kubernetesVersion": "1.34.1"}, {"kubernetesVersion": "1.35.0", "isPreview": true}]}}})))
        .mount(&server).await;
    let (info, findings) = aks(&server).upgrade_checks(None).await.unwrap();
    assert!(findings.is_empty());
    assert_eq!(
        info.available,
        ["1.34"],
        "previews and patches are left out"
    );
    insta::assert_snapshot!(k8s_mcp_provider::upgrade_lines(ProviderId::Aks, &info).join("\n"));
}

/// A resource id from ARM is fetched as a path on the ARM host: one that would move the
/// request elsewhere (`@host/...` makes the ARM host a user name) is refused.
#[tokio::test]
async fn foreign_resource_ids_are_not_fetched() {
    let (server, evil) = (MockServer::start().await, MockServer::start().await);
    let mut c = cluster();
    c["properties"]["addonProfiles"]["omsagent"]["config"]["logAnalyticsWorkspaceResourceID"] =
        json!(format!("@{}/x", evil.address()));
    Mock::given(method("GET"))
        .and(path(CLUSTER))
        .respond_with(ResponseTemplate::new(200).set_body_json(c))
        .mount(&server)
        .await;
    let q = LogQuery {
        source: "application".into(),
        since_ms: 1_794_000_000_000,
        limit: 10,
        ..Default::default()
    };
    assert!(aks(&server).logs(&q).await.is_err());
    assert!(
        evil.received_requests().await.unwrap().is_empty(),
        "the token went to another host"
    );
}

/// The bearer token never leaves the ARM host: a nextLink to another host is not followed.
#[tokio::test]
async fn foreign_next_links_are_not_followed() {
    let server = server().await;
    let evil = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/steal"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"value": []})))
        .mount(&evil)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/subscriptions/sub-1/providers/Microsoft.ManagedIdentity/userAssignedIdentities",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"value": [], "nextLink": format!("{}/steal", evil.uri())})),
        )
        .mount(&server)
        .await;
    let k8s = WorkloadIdentity {
        service_account: serde_json::from_value(json!({"metadata": {"name": "api", "namespace": "shop",
            "annotations": {"azure.workload.identity/client-id": "11111111-2222-3333-4444-555555555555"}}})).unwrap(),
        ..Default::default()
    };
    let (report, _) = aks(&server).identity_check(&k8s).await;
    assert_eq!(report.cloud_checks, "done");
    assert!(
        evil.received_requests().await.unwrap().is_empty(),
        "the token went to another host"
    );
}

/// A missing cluster maps to NotFound with the flag to pass.
#[tokio::test]
async fn aks_errors_say_what_to_do() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(path(CLUSTER))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"error": {"code": "ResourceNotFound", "message": "The Resource 'Microsoft.ContainerService/managedClusters/shop' under resource group 'shop-rg' was not found."}})))
        .mount(&server).await;
    let err = aks(&server).cluster_info().await.unwrap_err().to_string();
    assert!(
        err.contains("not found") && err.contains("--aks-cluster"),
        "{err}"
    );
}
