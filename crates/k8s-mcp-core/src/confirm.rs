//! Confirm tokens for write tools (PROPOSAL §12.4). A plan returns a token bound to the exact
//! request and to the state of the objects it would change; executing needs that token back
//! within 120 s. The key is random per process, so a token never outlives the server.

use std::fmt::Write as _;
use std::sync::OnceLock;

use jiff::{SignedDuration, Timestamp};
use ring::hmac;
use ring::rand::SystemRandom;
use serde_json::Value;

use crate::error::{Error, Result};

/// How long a plan's token stays valid.
pub const TTL: SignedDuration = SignedDuration::from_secs(120);

/// What a token is bound to.
pub struct Binding<'a> {
    /// The write tool.
    pub tool: &'a str,
    /// The kubeconfig context it targets.
    pub context: &'a str,
    /// The request, with defaults resolved and without `dry_run` and `confirm_token`.
    pub args: &'a Value,
    /// Each object the plan would change (`kind/namespace/name`) and its [`state`] (`None`
    /// when it does not exist yet).
    pub states: &'a [(String, Option<String>)],
}

/// Issues and checks confirm tokens.
#[derive(Default)]
pub struct Confirmer {
    key: OnceLock<Option<hmac::Key>>,
}

impl Confirmer {
    fn key(&self) -> Result<&hmac::Key> {
        self.key
            .get_or_init(|| hmac::Key::generate(hmac::HMAC_SHA256, &SystemRandom::new()).ok())
            .as_ref()
            .ok_or_else(|| {
                Error::Api(
                    "cannot create the confirm-token key: the system random number generator failed. Restart k8s-mcp.".into(),
                )
            })
    }

    /// A token for `binding`, valid until `now` + [`TTL`].
    pub fn issue(&self, binding: &Binding<'_>, now: Timestamp) -> Result<String> {
        let expires = now.as_second() + TTL.as_secs();
        let tag = hmac::sign(self.key()?, message(binding, expires).as_bytes());
        Ok(format!("{expires}.{}", hex(tag.as_ref())))
    }

    /// Accept `token` only for the same `binding`, before it expires.
    pub fn verify(&self, token: &str, binding: &Binding<'_>, now: Timestamp) -> Result<()> {
        let (expires, tag) = token
            .split_once('.')
            .and_then(|(e, t)| Some((e.parse::<i64>().ok()?, unhex(t)?)))
            .ok_or_else(|| rejected("it is not a confirm token from a plan"))?;
        if now.as_second() > expires {
            return Err(rejected("it expired (a plan's token lasts 120 s)"));
        }
        hmac::verify(self.key()?, message(binding, expires).as_bytes(), &tag).map_err(|_| {
            rejected(
                "the arguments, the context or the objects (other than their status) changed since the plan, or the token comes from another k8s-mcp process",
            )
        })
    }
}

fn rejected(why: &str) -> Error {
    Error::InvalidInput(format!(
        "confirm_token rejected: {why}. Nothing was changed. Call the tool with dry_run=true for a new plan, review it, then confirm with its token."
    ))
}

/// The signed text: versioned, one field per line, JSON with sorted keys.
fn message(b: &Binding<'_>, expires: i64) -> String {
    let mut out = format!("k8s-mcp/confirm/v2\n{expires}\n{}\n{}\n", b.tool, b.context);
    canonical(b.args, &mut out);
    let mut states: Vec<String> = b
        .states
        .iter()
        .map(|(object, state)| format!("{object}={}", state.as_deref().unwrap_or("-")))
        .collect();
    states.sort();
    for v in states {
        out.push('\n');
        out.push_str(&v);
    }
    out
}

/// What a token binds for one object (ADR 0016): a digest of it without `status`,
/// `metadata.resourceVersion` and `metadata.managedFields`. Any change to its spec, data,
/// labels, annotations or UID voids a plan; a status update (ready counts, a restarting
/// container) does not. The write still carries the current resourceVersion as a
/// precondition.
pub fn state<T: serde::Serialize>(object: &T) -> String {
    let mut v = serde_json::to_value(object).unwrap_or_default();
    if let Some(o) = v.as_object_mut() {
        o.remove("status");
    }
    if let Some(m) = v.get_mut("metadata").and_then(Value::as_object_mut) {
        m.remove("resourceVersion");
        m.remove("managedFields");
    }
    let mut text = String::new();
    canonical(&v, &mut text);
    hex(&ring::digest::digest(&ring::digest::SHA256, text.as_bytes()).as_ref()[..16])
}

/// JSON with object keys sorted, so equal requests sign equally whatever their key order.
fn canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                canonical(&map[k], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use serde_json::json;

    use super::*;

    fn now() -> Timestamp {
        "2026-11-18T10:00:00Z".parse().unwrap()
    }

    fn states(state: Option<&str>) -> Vec<(String, Option<String>)> {
        vec![("Deployment/shop/web".into(), state.map(str::to_owned))]
    }

    /// ADR 0016: the state ignores status, resourceVersion and managedFields (and key order),
    /// and changes with the spec, labels, annotations or UID.
    #[test]
    fn state_ignores_status_only() {
        let obj = serde_json::json!({"metadata": {"name": "web", "uid": "u1", "resourceVersion": "41",
            "labels": {"app": "web"}, "managedFields": [{"manager": "a"}]},
            "spec": {"replicas": 3}, "status": {"readyReplicas": 3}});
        let base = state(&obj);
        let mut churned = obj.clone();
        churned["metadata"]["resourceVersion"] = "42".into();
        churned["metadata"]["managedFields"] = serde_json::json!([{"manager": "b"}]);
        churned["status"] = serde_json::json!({"readyReplicas": 1, "conditions": []});
        assert_eq!(state(&churned), base);
        let reordered: Value = serde_json::from_str(r#"{"status": {}, "spec": {"replicas": 3}, "metadata": {"labels": {"app": "web"}, "uid": "u1", "name": "web"}}"#).unwrap();
        assert_eq!(state(&reordered), base);
        for (path, value) in [
            ("/spec/replicas", serde_json::json!(4)),
            ("/metadata/labels/app", "api".into()),
            ("/metadata/uid", "u2".into()),
        ] {
            let mut changed = obj.clone();
            *changed.pointer_mut(path).unwrap() = value;
            assert_ne!(state(&changed), base, "{path}");
        }
    }

    #[test]
    fn a_token_confirms_only_the_planned_request_within_120_s() {
        let c = Confirmer::default();
        let args = json!({"kind": "Deployment", "name": "web", "replicas": 3});
        let v = states(Some("41"));
        let plan = Binding {
            tool: "scale_workload",
            context: "dev",
            args: &args,
            states: &v,
        };
        let token = c.issue(&plan, now()).unwrap();
        c.verify(&token, &plan, now()).unwrap();
        c.verify(&token, &plan, now() + TTL).unwrap();

        // Key order does not matter; any other change does.
        let reordered = json!({"replicas": 3, "name": "web", "kind": "Deployment"});
        c.verify(
            &token,
            &Binding {
                args: &reordered,
                ..plan
            },
            now(),
        )
        .unwrap();
        let other_args = json!({"kind": "Deployment", "name": "web", "replicas": 30});
        let newer = states(Some("42"));
        let absent = states(None);
        for changed in [
            Binding {
                args: &other_args,
                ..plan
            },
            Binding {
                context: "prod",
                ..plan
            },
            Binding {
                tool: "restart_workload",
                ..plan
            },
            Binding {
                states: &newer,
                ..plan
            },
            Binding {
                states: &absent,
                ..plan
            },
        ] {
            let err = c.verify(&token, &changed, now()).unwrap_err().to_string();
            assert!(err.contains("changed since the plan"), "{err}");
        }
        let late = c.verify(&token, &plan, now() + TTL + SignedDuration::from_secs(1));
        assert!(late.unwrap_err().to_string().contains("expired"));
        let other_process = Confirmer::default().verify(&token, &plan, now());
        assert!(other_process.is_err());
        for junk in ["", "abc", "1.zz", "99999999999.", &token[..token.len() - 1]] {
            assert!(c.verify(junk, &plan, now()).is_err(), "{junk:?}");
        }
    }

    proptest! {
        #[test]
        fn any_changed_argument_is_rejected(name in "[a-z]{1,12}", other in "[a-z]{1,12}") {
            prop_assume!(name != other);
            let c = Confirmer::default();
            let v = states(Some("7"));
            let args = json!({"name": name});
            let plan = Binding { tool: "delete_pod", context: "dev", args: &args, states: &v };
            let token = c.issue(&plan, now()).unwrap();
            let changed = json!({"name": other});
            let rejected = c
                .verify(&token, &Binding { args: &changed, ..plan }, now())
                .is_err();
            prop_assert!(rejected);
        }
    }
}
