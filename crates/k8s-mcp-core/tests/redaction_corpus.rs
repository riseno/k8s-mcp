//! Redaction corpus (PROPOSAL §12.3): every positive sample's secret must disappear
//! (target false-negative rate 0), and negative samples must pass through unchanged.

use k8s_mcp_core::policy::RedactLevel;
use k8s_mcp_core::redact::Redactor;
use proptest::prelude::*;

/// (line, secret that must not survive)
const POSITIVE: &[(&str, &str)] = &[
    ("aws key AKIAIOSFODNN7EXAMPLE used", "AKIAIOSFODNN7EXAMPLE"),
    (
        "session ASIAY34FZKBOKMUTVV7A expired",
        "ASIAY34FZKBOKMUTVV7A",
    ),
    (
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ),
    (
        "AWS_SECRET_ACCESS_KEY: \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"",
        "wJalrXUtnFEMI/K7MDENG",
    ),
    (
        "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c ok",
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    ),
    (
        "Authorization: Bearer abcdef0123456789abcdef",
        "abcdef0123456789abcdef",
    ),
    (
        "curl -H 'Authorization: Basic dXNlcjpodW50ZXIy' http://x",
        "dXNlcjpodW50ZXIy",
    ),
    (
        "sent bearer 0123456789ABCDEFGHIJ to upstream",
        "0123456789ABCDEFGHIJ",
    ),
    (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7\n-----END RSA PRIVATE KEY-----",
        "MIIEpAIBAAKCAQEA7",
    ),
    (
        "-----BEGIN PRIVATE KEY----- MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
    ),
    (
        "connecting to postgres://app:s3cretPw@db.shop:5432/orders",
        "s3cretPw",
    ),
    ("redis://:hunter2@cache:6379", "hunter2"),
    ("https://user:pa55word@registry.example.com/v2/", "pa55word"),
    (
        r#"{"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANB\n-----END PRIVATE KEY-----\n", "client_email": "x"}"#,
        "MIIEvgIBADANB",
    ),
    (
        r#""private_key_id": "a1b2c3d4e5f6a1b2c3d4e5f6""#,
        "a1b2c3d4e5f6a1b2c3d4e5f6",
    ),
    (
        "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4==;EndpointSuffix=core.windows.net",
        "Zm9vYmFyYmF6cXV4",
    ),
    (
        "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=root;SharedAccessKey=abcDEF123+/=",
        "abcDEF123",
    ),
    (
        "https://acct.blob.core.windows.net/c/b?sv=2022&sig=AbCdEf%2B123&se=2026",
        "AbCdEf%2B123",
    ),
    (
        "git clone with ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    ),
    (
        "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz",
        "github_pat_11ABCDEFG0123456789",
    ),
    (
        "GITLAB glpat-xxxxxxxxxxxxxxxxxxxx1 configured",
        "glpat-xxxxxxxxxxxxxxxxxxxx1",
    ),
    (
        "slack xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOp",
        "xoxb-123456789012",
    ),
    ("login password=hunter2 user=bob", "hunter2"),
    ("DB_PASSWORD=Tr0ub4dor&3", "Tr0ub4dor"),
    (
        r#"{"password": "correct-horse", "user": "bob"}"#,
        "correct-horse",
    ),
    ("client_secret: s3cr3t-value-here", "s3cr3t-value-here"),
    ("--api-key=sk_live_51HabcDEF", "sk_live_51HabcDEF"),
    (
        "X-Api-Key: 7f9c2ba4e88f827d616045507605853e",
        "7f9c2ba4e88f827d616045507605853e",
    ),
    (
        "access_key=AKIDEXAMPLE123 region=us-east-1",
        "AKIDEXAMPLE123",
    ),
    (
        "refresh_token=1//0gLONGrefreshTOKENvalue",
        "1//0gLONGrefreshTOKENvalue",
    ),
    (r#"msg="auth ok" token=abc.def.ghi"#, "abc.def.ghi"),
    (r#"{\"password\":\"escaped-in-json\"}"#, "escaped-in-json"),
    // riseno/k8s-mcp#25: AWS secret key without a key=value keyword.
    (
        "aws key AKIAIOSFODNN7EXAMPLE secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ),
    (
        "AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ),
];

/// Lines that must pass through `standard` redaction unchanged.
const NEGATIVE: &[&str] = &[
    "GET /healthz 200 3ms",
    "Starting server on :8080",
    "Exception in thread \"main\" java.lang.OutOfMemoryError: Java heap space",
    "connection refused: dial tcp 10.96.0.10:53",
    "user bob logged in from 192.168.1.10",
    "token refresh succeeded",
    "Back-off restarting failed container app in pod checkout-7d9f8c6b5-x2k4q",
    "pulling image \"ghcr.io/acme/checkout:1.4.2\"",
    "configmap \"app-config\" not found",
    "couldn't find key password in Secret shop/db-creds",
    "https://kubernetes.io/docs/concepts/configuration/secret/",
    "level=info msg=\"cache warmed\" keys=1200",
    "AKIA is a prefix but AKIASHORT is too short",
    "deployed commit 3f2a1b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a to prod",
];

#[test]
fn corpus_positive_has_zero_false_negatives() {
    let r = Redactor::new(RedactLevel::Standard);
    let misses: Vec<_> = POSITIVE
        .iter()
        .filter_map(|(line, secret)| {
            let out = r.text(line);
            out.contains(secret).then(|| format!("{line:?} -> {out:?}"))
        })
        .collect();
    assert!(misses.is_empty(), "false negatives:\n{}", misses.join("\n"));
}

#[test]
fn corpus_negative_is_untouched() {
    let r = Redactor::new(RedactLevel::Standard);
    for line in NEGATIVE {
        assert_eq!(r.text(line), *line);
    }
}

#[test]
fn redaction_is_idempotent_on_corpus() {
    let r = Redactor::new(RedactLevel::Standard);
    for (line, _) in POSITIVE {
        let once = r.text(line).into_owned();
        assert_eq!(r.text(&once), once);
    }
}

/// riseno/k8s-mcp#24: a PEM key logged across lines must not leak its body.
#[test]
fn multi_line_pem_keys_in_logs_are_masked() {
    let log = [
        "starting",
        "-----BEGIN RSA PRIVATE KEY-----",
        "MIIEpAIBAAKCAQEAsecretbody1",
        "secretbody2line+/==",
        "-----END RSA PRIVATE KEY-----",
        "ready",
    ];
    let out = Redactor::new(RedactLevel::Standard).lines(log);
    let all = out.join("\n");
    assert!(!all.contains("secretbody"), "{all}");
    assert_eq!(out[0], "starting");
    assert_eq!(out[5], "ready", "lines after the END line are untouched");
}

/// riseno/k8s-mcp#25: exact Secret values are masked even when nothing marks them as secret,
/// and at every redaction level.
#[test]
fn exact_secret_values_are_scrubbed() {
    let mut lines = vec![
        "echoed env: s3cr3t-from-secret and $OTHER".to_owned(),
        "ok".to_owned(),
    ];
    k8s_mcp_core::redact::scrub_values(&mut lines, &["s3cr3t-from-secret".into(), "1".into()]);
    assert_eq!(lines, ["echoed env: «redacted» and $OTHER", "ok"]);
}

fn safe_text() -> impl Strategy<Value = String> {
    "[a-z ]{0,30}".prop_map(|s| format!(" {s} "))
}

proptest! {
    #[test]
    fn never_panics(s in "\\PC{0,300}") {
        let _ = Redactor::new(RedactLevel::Strict).text(&s);
    }

    #[test]
    fn embedded_aws_keys_are_removed(pre in safe_text(), post in safe_text(), key in "[A-Z0-9]{16}") {
        let secret = format!("AKIA{key}");
        let out = Redactor::default().text(&format!("{pre}{secret}{post}")).into_owned();
        prop_assert!(!out.contains(&secret));
    }

    #[test]
    fn embedded_passwords_are_removed(pre in safe_text(), post in safe_text(), pw in "[A-Za-z0-9!@#$%^*()_+-]{4,40}") {
        let out = Redactor::default().text(&format!("{pre}password={pw}{post}")).into_owned();
        let needle = format!("password={pw}");
        prop_assert!(!out.contains(&needle));
    }

    #[test]
    fn embedded_url_credentials_are_removed(pre in safe_text(), pw in "[A-Za-z0-9]{6,20}") {
        let out = Redactor::default().text(&format!("{pre}https://u:{pw}@h.example/x")).into_owned();
        let needle = format!(":{pw}@");
        prop_assert!(!out.contains(&needle));
    }
}
