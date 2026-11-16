//! `eks_identity_check`: does a ServiceAccount's AWS identity work? IRSA (role annotation ->
//! role -> trust policy -> IAM OIDC provider) and EKS Pod Identity (association -> role trust ->
//! agent), plus the pod side (injected credentials). [`evaluate`] is pure: facts in, checks
//! and findings out.

use k8s_mcp_core::finding::{Confidence, Finding, RuleMeta, Severity, Source};
use k8s_mcp_provider::{IdentityCheck, IdentityReport, Report, WorkloadIdentity};
use k8s_openapi::api::core::v1::Pod;
use serde_json::{Value, json};

const DOCS_IRSA: &str =
    "https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html";
const DOCS_POD_IDENTITY: &str =
    "https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html";

/// ServiceAccount annotation that selects an IRSA role.
pub const ROLE_ANNOTATION: &str = "eks.amazonaws.com/role-arn";
const AUDIENCE_ANNOTATION: &str = "eks.amazonaws.com/audience";

/// Rules emitted by the identity check.
pub const RULES: &[RuleMeta] = &[
    RuleMeta {
        id: "eks.irsa.role_missing",
        title: "The IAM role in the IRSA annotation does not exist",
        docs: DOCS_IRSA,
    },
    RuleMeta {
        id: "eks.irsa.trust_mismatch",
        title: "The IRSA role's trust policy does not allow this ServiceAccount",
        docs: DOCS_IRSA,
    },
    RuleMeta {
        id: "eks.irsa.oidc_provider_missing",
        title: "The cluster's OIDC issuer is not registered as an IAM OIDC provider",
        docs: DOCS_IRSA,
    },
    RuleMeta {
        id: "eks.pod_identity.association_missing",
        title: "The ServiceAccount has no AWS identity (no IRSA role, no Pod Identity association)",
        docs: DOCS_POD_IDENTITY,
    },
    RuleMeta {
        id: "eks.pod_identity.trust_mismatch",
        title: "The Pod Identity role's trust policy does not allow EKS Pod Identity",
        docs: DOCS_POD_IDENTITY,
    },
    RuleMeta {
        id: "eks.pod_identity.agent_missing",
        title: "The EKS Pod Identity agent is not running",
        docs: DOCS_POD_IDENTITY,
    },
    RuleMeta {
        id: "eks.identity.pods_not_injected",
        title: "Pods of the ServiceAccount did not get the AWS credentials injected",
        docs: DOCS_IRSA,
    },
];

/// A role as IAM returned it: `None` trust when the role does not exist.
#[derive(Debug, Clone, Default)]
pub struct RoleFacts {
    /// Role ARN.
    pub arn: String,
    /// The decoded trust policy; `None` when the role does not exist.
    pub trust: Option<Value>,
}

/// What AWS said, when it could be asked.
#[derive(Debug, Clone, Default)]
pub struct CloudFacts {
    /// The cluster's OIDC issuer URL.
    pub issuer: String,
    /// ARNs of the account's IAM OIDC providers.
    pub oidc_providers: Vec<String>,
    /// The IRSA role, when the ServiceAccount is annotated.
    pub irsa_role: Option<RoleFacts>,
    /// Roles of the Pod Identity associations for the ServiceAccount.
    pub associations: Vec<RoleFacts>,
}

/// Decode an IAM policy document (RFC 3986 percent-encoded JSON).
pub fn decode_policy(encoded: &str) -> Option<Value> {
    let bytes = encoded.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            // `get` fails on a truncated escape, which makes the document invalid.
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    serde_json::from_slice(&out).ok()
}

/// A JSON value that IAM allows as a string or a list of strings.
fn strings(v: &Value) -> Vec<&str> {
    match v {
        Value::String(s) => vec![s.as_str()],
        Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

fn statements(policy: &Value) -> Vec<&Value> {
    match &policy["Statement"] {
        Value::Array(a) => a.iter().collect(),
        s @ Value::Object(_) => vec![s],
        _ => Vec::new(),
    }
}

fn allows(st: &Value, action: &str) -> bool {
    st["Effect"] == "Allow"
        && strings(&st["Action"])
            .iter()
            .any(|a| *a == action || *a == "sts:*")
}

/// IAM `StringLike` matching: `*` and `?` wildcards.
fn like(pattern: &str, value: &str) -> bool {
    fn go(p: &[u8], v: &[u8]) -> bool {
        match (p.first(), v.first()) {
            (None, None) => true,
            (Some(b'*'), _) => go(&p[1..], v) || (!v.is_empty() && go(p, &v[1..])),
            (Some(b'?'), Some(_)) => go(&p[1..], &v[1..]),
            (Some(a), Some(b)) if a == b => go(&p[1..], &v[1..]),
            _ => false,
        }
    }
    go(pattern.as_bytes(), value.as_bytes())
}

/// Values a condition key must match, with whether they are `StringLike` patterns.
fn condition<'a>(st: &'a Value, key: &str) -> Vec<(&'a str, bool)> {
    let mut out = Vec::new();
    for (op, like_op) in [("StringEquals", false), ("StringLike", true)] {
        if let Some(obj) = st["Condition"][op].as_object() {
            for (k, v) in obj {
                if k == key {
                    out.extend(strings(v).into_iter().map(|s| (s, like_op)));
                }
            }
        }
    }
    out
}

/// Why an IRSA trust policy does not let `ns/sa` of `issuer` assume the role (`None`: it does).
fn irsa_trust_problem(
    trust: &Value,
    issuer_host: &str,
    ns: &str,
    sa: &str,
    audience: &str,
) -> Option<String> {
    let provider_suffix = format!(":oidc-provider/{issuer_host}");
    let candidates: Vec<&Value> = statements(trust)
        .into_iter()
        .filter(|st| allows(st, "sts:AssumeRoleWithWebIdentity"))
        .filter(|st| {
            strings(&st["Principal"]["Federated"])
                .iter()
                .any(|p| p.ends_with(&provider_suffix))
        })
        .collect();
    if candidates.is_empty() {
        return Some(format!(
            "no statement allows sts:AssumeRoleWithWebIdentity for the federated principal of this cluster's OIDC provider ({issuer_host})"
        ));
    }
    let subject = format!("system:serviceaccount:{ns}:{sa}");
    let ok = candidates.iter().any(|st| {
        let subs = condition(st, &format!("{issuer_host}:sub"));
        let auds = condition(st, &format!("{issuer_host}:aud"));
        let sub_ok = subs.is_empty()
            || subs
                .iter()
                .any(|(v, l)| if *l { like(v, &subject) } else { *v == subject });
        let aud_ok = auds.is_empty()
            || auds.iter().any(|(v, l)| {
                if *l {
                    like(v, audience)
                } else {
                    *v == audience
                }
            });
        sub_ok && aud_ok
    });
    if ok {
        return None;
    }
    let found: Vec<String> = candidates
        .iter()
        .flat_map(|st| condition(st, &format!("{issuer_host}:sub")))
        .map(|(v, _)| v.to_owned())
        .collect();
    Some(format!(
        "the trust policy's {issuer_host}:sub condition allows {} but not {subject} (or its :aud does not allow {audience})",
        if found.is_empty() {
            "nothing".into()
        } else {
            found.join(", ")
        }
    ))
}

fn pod_identity_trust_ok(trust: &Value) -> bool {
    statements(trust).iter().any(|st| {
        strings(&st["Principal"]["Service"]).contains(&"pods.eks.amazonaws.com")
            && allows(st, "sts:AssumeRole")
            && allows(st, "sts:TagSession")
    })
}

fn env_names(p: &Pod) -> Vec<&str> {
    p.spec
        .iter()
        .flat_map(|s| &s.containers)
        .flat_map(|c| c.env.iter().flatten())
        .map(|e| e.name.as_str())
        .collect()
}

fn check(
    side: &'static str,
    check: &str,
    result: &'static str,
    detail: impl Into<String>,
) -> IdentityCheck {
    IdentityCheck {
        side,
        check: check.into(),
        result,
        detail: detail.into(),
    }
}

/// Turn the facts into checks and findings. `cloud` is `Err(reason)` when AWS could not be asked.
#[allow(clippy::too_many_lines)] // one pass over the identity chain reads best in one place
pub fn evaluate(
    k8s: &WorkloadIdentity,
    cloud: Result<&CloudFacts, &str>,
) -> Report<IdentityReport> {
    let sa = k8s.service_account.metadata.name.as_deref().unwrap_or("");
    let ns = k8s
        .service_account
        .metadata
        .namespace
        .as_deref()
        .unwrap_or("default");
    let ann = k8s.service_account.metadata.annotations.as_ref();
    let role_arn = ann.and_then(|a| a.get(ROLE_ANNOTATION)).cloned();
    let audience = ann
        .and_then(|a| a.get(AUDIENCE_ANNOTATION))
        .map_or("sts.amazonaws.com", String::as_str);
    let mut checks = Vec::new();
    let mut findings = Vec::new();
    let subject = format!("ServiceAccount {ns}/{sa}");

    checks.push(match &role_arn {
        Some(r) => check("kubernetes", "IRSA role annotation", "ok", r.clone()),
        None => check(
            "kubernetes",
            "IRSA role annotation",
            "missing",
            format!("no {ROLE_ANNOTATION} annotation"),
        ),
    });
    // Pods get the credentials injected at creation: IRSA env from the pod identity webhook,
    // Pod Identity env from the EKS Pod Identity webhook.
    let associations = cloud.map(|c| c.associations.as_slice()).unwrap_or_default();
    let expected: Option<(&str, &str)> = if role_arn.is_some() {
        Some(("AWS_WEB_IDENTITY_TOKEN_FILE", "IRSA"))
    } else if !associations.is_empty() {
        Some(("AWS_CONTAINER_CREDENTIALS_FULL_URI", "Pod Identity"))
    } else {
        None
    };
    if let Some((var, how)) = expected {
        let missing: Vec<&str> = k8s
            .pods
            .iter()
            .filter(|p| !env_names(p).contains(&var))
            .filter_map(|p| p.metadata.name.as_deref())
            .collect();
        checks.push(check(
            "kubernetes",
            &format!("{how} credentials injected into pods"),
            if missing.is_empty() { "ok" } else { "fail" },
            if k8s.pods.is_empty() {
                "no pods run as this ServiceAccount".to_owned()
            } else {
                format!(
                    "{}/{} pods have {var}",
                    k8s.pods.len() - missing.len(),
                    k8s.pods.len()
                )
            },
        ));
        if !missing.is_empty() {
            findings.push(
                Finding::new("eks.identity.pods_not_injected", Severity::High, Confidence::High, format!("{} pod(s) of {subject} run without the {how} credentials", missing.len()))
                    .explain("Credentials are injected when a pod is created, so pods started before the identity was configured (or created while the injecting webhook was down) still use the node's IAM role or none at all.")
                    .evidence(Source::Status, format!("pods without {var}: {}", missing.iter().take(5).copied().collect::<Vec<_>>().join(", ")))
                    .docs(if how == "IRSA" { DOCS_IRSA } else { DOCS_POD_IDENTITY })
                    .fix("Restart the pods (`kubectl rollout restart` on their workload) so they are recreated with the credentials."),
            );
        }
    }

    let facts = match cloud {
        Ok(f) => f,
        Err(reason) => {
            if role_arn.is_none() {
                checks.push(check(
                    "kubernetes",
                    "Pod Identity",
                    "skipped",
                    "associations are only visible through the EKS API",
                ));
            }
            return (
                IdentityReport {
                    checks,
                    cloud_checks: format!("skipped: {reason}"),
                },
                findings,
            );
        }
    };
    let issuer_host = facts.issuer.trim_start_matches("https://");

    if let Some(arn) = &role_arn {
        let provider = facts
            .oidc_providers
            .iter()
            .find(|p| p.ends_with(&format!(":oidc-provider/{issuer_host}")));
        checks.push(check(
            "aws",
            "IAM OIDC provider for the cluster issuer",
            if provider.is_some() { "ok" } else { "missing" },
            provider.cloned().unwrap_or_else(|| issuer_host.to_owned()),
        ));
        if provider.is_none() {
            findings.push(
                Finding::new("eks.irsa.oidc_provider_missing", Severity::Critical, Confidence::High, format!("The cluster's OIDC issuer is not an IAM OIDC provider, so IRSA cannot work for {subject}"))
                    .explain("STS only accepts web-identity tokens from issuers registered as IAM OIDC providers in the account. Without it every IRSA role in the cluster fails with InvalidIdentityToken.")
                    .evidence(Source::Related, format!("issuer {issuer_host} not among {} IAM OIDC provider(s)", facts.oidc_providers.len()))
                    .docs(DOCS_IRSA)
                    .fix("Create the IAM OIDC provider for the cluster (`eksctl utils associate-iam-oidc-provider --cluster <name> --approve`, or an aws_iam_openid_connect_provider resource with the issuer URL)."),
            );
        }
        match facts.irsa_role.as_ref().and_then(|r| r.trust.as_ref()) {
            None => {
                checks.push(check("aws", "IRSA role exists", "missing", arn.clone()));
                findings.push(
                    Finding::new("eks.irsa.role_missing", Severity::Critical, Confidence::High, format!("IAM role {arn} in the IRSA annotation of {subject} does not exist"))
                        .explain("The pod identity webhook injects this role, and STS cannot assume a role that does not exist, so the pods' AWS calls fail.")
                        .evidence(Source::Spec, format!("{ROLE_ANNOTATION}: {arn}"))
                        .docs(DOCS_IRSA)
                        .fix("Create the role (with a trust policy for this cluster's OIDC provider and this ServiceAccount), or correct the annotation."),
                );
            }
            Some(trust) => {
                checks.push(check("aws", "IRSA role exists", "ok", arn.clone()));
                match irsa_trust_problem(trust, issuer_host, ns, sa, audience) {
                    None => checks.push(check(
                        "aws",
                        "IRSA trust policy allows the ServiceAccount",
                        "ok",
                        format!("system:serviceaccount:{ns}:{sa}"),
                    )),
                    Some(problem) => {
                        checks.push(check(
                            "aws",
                            "IRSA trust policy allows the ServiceAccount",
                            "fail",
                            problem.clone(),
                        ));
                        findings.push(
                            Finding::new("eks.irsa.trust_mismatch", Severity::Critical, Confidence::High, format!("The trust policy of {arn} does not allow {subject}"))
                                .explain("STS refuses AssumeRoleWithWebIdentity unless the role trusts this cluster's OIDC provider and its sub condition matches the ServiceAccount, so the pods get AccessDenied.")
                                .evidence(Source::Related, problem)
                                .docs(DOCS_IRSA)
                                .fix(format!("Add (or correct) a statement allowing sts:AssumeRoleWithWebIdentity for Federated arn:aws:iam::<account>:oidc-provider/{issuer_host}, with Condition StringEquals {issuer_host}:sub = system:serviceaccount:{ns}:{sa} and {issuer_host}:aud = {audience}."))
                                .next("get_resource", json!({"kind": "ServiceAccount", "name": sa, "namespace": ns}), "check the ServiceAccount name and namespace the policy must name"),
                        );
                    }
                }
            }
        }
    }

    checks.push(check(
        "aws",
        "Pod Identity associations",
        // Without associations, IRSA (when annotated) is the identity: not a failure.
        match (associations.is_empty(), role_arn.is_some()) {
            (false, _) => "ok",
            (true, true) => "none",
            (true, false) => "missing",
        },
        if associations.is_empty() {
            "none for this ServiceAccount".to_owned()
        } else {
            associations
                .iter()
                .map(|r| r.arn.clone())
                .collect::<Vec<_>>()
                .join(", ")
        },
    ));
    if role_arn.is_none() && associations.is_empty() {
        findings.push(
            Finding::new("eks.pod_identity.association_missing", Severity::High, Confidence::High, format!("{subject} has no AWS identity: no IRSA role annotation and no Pod Identity association"))
                .explain("Pods running as this ServiceAccount fall back to the node's IAM role (or IMDS is blocked and they get no credentials), which usually lacks the permissions the workload needs.")
                .evidence(Source::Related, "no eks.amazonaws.com/role-arn annotation; ListPodIdentityAssociations returned none")
                .docs(DOCS_POD_IDENTITY)
                .fix(format!("Create a Pod Identity association for namespace {ns}, ServiceAccount {sa} and the workload's role (`aws eks create-pod-identity-association`), or annotate the ServiceAccount with an IRSA role.")),
        );
    }
    for role in associations {
        match &role.trust {
            Some(t) if pod_identity_trust_ok(t) => checks.push(check(
                "aws",
                "Pod Identity role trusts pods.eks.amazonaws.com",
                "ok",
                role.arn.clone(),
            )),
            _ => {
                checks.push(check(
                    "aws",
                    "Pod Identity role trusts pods.eks.amazonaws.com",
                    "fail",
                    role.arn.clone(),
                ));
                findings.push(
                    Finding::new("eks.pod_identity.trust_mismatch", Severity::Critical, Confidence::High, format!("The Pod Identity role {} of {subject} does not trust EKS Pod Identity", role.arn))
                        .explain("EKS Pod Identity assumes the role as the pods.eks.amazonaws.com service with sts:AssumeRole and sts:TagSession; without that statement (or if the role is gone) the pods get no credentials.")
                        .evidence(Source::Related, if role.trust.is_some() { "trust policy has no Allow for Service pods.eks.amazonaws.com with sts:AssumeRole and sts:TagSession" } else { "the role does not exist" })
                        .docs(DOCS_POD_IDENTITY)
                        .fix("Set the role's trust policy to allow Principal {\"Service\": \"pods.eks.amazonaws.com\"} the actions sts:AssumeRole and sts:TagSession."),
                );
            }
        }
    }
    if !associations.is_empty() && k8s.agent_ready == Some(false) {
        findings.push(
            Finding::new("eks.pod_identity.agent_missing", Severity::Critical, Confidence::High, format!("{subject} uses Pod Identity, but the EKS Pod Identity agent is not running"))
                .explain("Pods get Pod Identity credentials from the agent DaemonSet on their node; without it the credential endpoint does not answer.")
                .evidence(Source::Related, "DaemonSet kube-system/eks-pod-identity-agent missing or not ready")
                .docs(DOCS_POD_IDENTITY)
                .fix("Install (or repair) the eks-pod-identity-agent add-on."),
        );
    }
    (
        IdentityReport {
            checks,
            cloud_checks: "done".into(),
        },
        findings,
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const ISSUER: &str = "https://oidc.eks.eu-west-1.amazonaws.com/id/ABC123";
    const HOST: &str = "oidc.eks.eu-west-1.amazonaws.com/id/ABC123";

    fn trust(sub: &str) -> Value {
        json!({"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
            "Principal": {"Federated": format!("arn:aws:iam::123456789012:oidc-provider/{HOST}")},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringEquals": {format!("{HOST}:sub"): sub, format!("{HOST}:aud"): "sts.amazonaws.com"}}}]})
    }

    fn sa(annotated: bool) -> WorkloadIdentity {
        let mut v = json!({"metadata": {"name": "api", "namespace": "shop"}});
        if annotated {
            v["metadata"]["annotations"] =
                json!({ROLE_ANNOTATION: "arn:aws:iam::123456789012:role/shop-api"});
        }
        let pod: Pod = serde_json::from_value(json!({"metadata": {"name": "api-1"}, "spec": {"containers": [{"name": "app",
            "env": [{"name": "AWS_ROLE_ARN", "value": "x"}, {"name": "AWS_WEB_IDENTITY_TOKEN_FILE", "value": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"}]}]}})).unwrap();
        WorkloadIdentity {
            service_account: serde_json::from_value(v).unwrap(),
            pods: vec![pod],
            agent_ready: Some(true),
        }
    }

    fn facts(trust: Option<Value>) -> CloudFacts {
        CloudFacts {
            issuer: ISSUER.into(),
            oidc_providers: vec![format!("arn:aws:iam::123456789012:oidc-provider/{HOST}")],
            irsa_role: Some(RoleFacts {
                arn: "arn:aws:iam::123456789012:role/shop-api".into(),
                trust,
            }),
            associations: Vec::new(),
        }
    }

    fn ids(r: &Report<IdentityReport>) -> Vec<&str> {
        r.1.iter().map(|f| f.id.as_str()).collect()
    }

    #[test]
    fn working_irsa_has_no_findings() {
        let r = evaluate(
            &sa(true),
            Ok(&facts(Some(trust("system:serviceaccount:shop:api")))),
        );
        assert!(r.1.is_empty(), "{:?}", r.1);
        assert!(
            r.0.checks
                .iter()
                .all(|c| c.result == "ok" || c.check == "Pod Identity associations"),
            "{:?}",
            r.0.checks
        );
    }

    /// v0.2 acceptance criterion 4: IRSA trust-policy mismatch.
    #[test]
    fn trust_policy_for_another_service_account() {
        let r = evaluate(
            &sa(true),
            Ok(&facts(Some(trust("system:serviceaccount:shop:worker")))),
        );
        assert_eq!(ids(&r), ["eks.irsa.trust_mismatch"]);
        assert!(
            r.1[0].evidence[0].text.contains(
                "allows system:serviceaccount:shop:worker but not system:serviceaccount:shop:api"
            ),
            "{}",
            r.1[0].evidence[0].text
        );
    }

    /// v0.2 acceptance criterion 4: missing OIDC provider.
    #[test]
    fn missing_oidc_provider() {
        let mut f = facts(Some(trust("system:serviceaccount:shop:api")));
        f.oidc_providers.clear();
        assert_eq!(
            ids(&evaluate(&sa(true), Ok(&f))),
            ["eks.irsa.oidc_provider_missing"]
        );
    }

    /// v0.2 acceptance criterion 4: missing Pod Identity association.
    #[test]
    fn no_annotation_and_no_association() {
        let r = evaluate(&sa(false), Ok(&facts(None)));
        assert_eq!(ids(&r), ["eks.pod_identity.association_missing"]);
    }

    /// v0.2 acceptance criterion 3: without credentials, the Kubernetes side plus `skipped`.
    #[test]
    fn without_credentials_the_kubernetes_side_still_runs() {
        let r = evaluate(&sa(true), Err("no AWS credentials resolved"));
        assert_eq!(r.0.cloud_checks, "skipped: no AWS credentials resolved");
        assert!(r.0.checks.iter().all(|c| c.side == "kubernetes"));
        assert_eq!(r.0.checks.len(), 2, "annotation and injection");
    }

    #[test]
    fn missing_role_wildcards_and_pod_identity() {
        assert_eq!(
            ids(&evaluate(&sa(true), Ok(&facts(None)))),
            ["eks.irsa.role_missing"]
        );
        let mut like_trust = trust("x");
        like_trust["Statement"][0]["Condition"] =
            json!({"StringLike": {format!("{HOST}:sub"): "system:serviceaccount:shop:*"}});
        assert!(
            evaluate(&sa(true), Ok(&facts(Some(like_trust))))
                .1
                .is_empty()
        );

        let mut f = facts(None);
        f.irsa_role = None;
        f.associations = vec![RoleFacts {
            arn: "arn:aws:iam::123456789012:role/pi".into(),
            trust: Some(
                json!({"Statement": {"Effect": "Allow", "Principal": {"Service": "pods.eks.amazonaws.com"}, "Action": ["sts:AssumeRole", "sts:TagSession"]}}),
            ),
        }];
        let mut k = sa(false);
        k.agent_ready = Some(false);
        let r = evaluate(&k, Ok(&f));
        // Pods lack the Pod Identity env (they were made for IRSA) and the agent is down.
        assert_eq!(
            ids(&r),
            [
                "eks.identity.pods_not_injected",
                "eks.pod_identity.agent_missing"
            ]
        );
        f.associations[0].trust = Some(
            json!({"Statement": {"Effect": "Allow", "Principal": {"Service": "pods.eks.amazonaws.com"}, "Action": "sts:AssumeRole"}}),
        );
        assert!(
            ids(&evaluate(&sa(false), Ok(&f))).contains(&"eks.pod_identity.trust_mismatch"),
            "TagSession is required"
        );
    }

    #[test]
    fn policies_decode() {
        let v = decode_policy("%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%5D%7D")
            .unwrap();
        assert_eq!(v["Version"], "2012-10-17");
        assert!(decode_policy("%7").is_none());
        assert!(like(
            "system:serviceaccount:shop:*",
            "system:serviceaccount:shop:api"
        ));
        assert!(!like(
            "system:serviceaccount:shop:?",
            "system:serviceaccount:shop:api"
        ));
    }
}
