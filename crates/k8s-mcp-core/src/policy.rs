//! Safety policy: permission tiers, context and namespace allow/deny lists, redaction level
//! and output caps. Checked before every Kubernetes API call and applied to results.

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Serialize;
use serde_json::{Value, json};

use crate::error::{Error, Result};

/// Permission tier of a tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Reads only.
    Read,
    /// Mutations (v0.4).
    Write,
    /// Destructive mutations (v0.4).
    Destructive,
}

/// Redaction level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RedactLevel {
    /// Standard plus all ConfigMap values, IP addresses and email addresses.
    Strict,
    /// Credentials in env, logs, annotations and ConfigMaps.
    #[default]
    Standard,
    /// Nothing except Secret values (which are never shown). Warns on every response.
    Off,
}

/// A compiled list of glob patterns, keeping the source text for messages.
#[derive(Debug, Clone)]
pub struct Patterns {
    raw: Vec<String>,
    set: GlobSet,
}

impl Patterns {
    /// Compile patterns such as `shop`, `team-*` or `*`.
    pub fn new(patterns: &[String]) -> Result<Self> {
        let mut b = GlobSetBuilder::new();
        let mut raw = Vec::new();
        for p in patterns.iter().map(|p| p.trim()).filter(|p| !p.is_empty()) {
            let glob =
                Glob::new(p).map_err(|e| Error::Config(format!("invalid pattern {p:?}: {e}")))?;
            b.add(glob);
            raw.push(p.to_owned());
        }
        let set = b
            .build()
            .map_err(|e| Error::Config(format!("invalid patterns: {e}")))?;
        Ok(Self { raw, set })
    }

    /// No patterns.
    pub fn none() -> Self {
        Self {
            raw: Vec::new(),
            set: GlobSet::empty(),
        }
    }

    /// True if any pattern matches.
    pub fn is_match(&self, s: &str) -> bool {
        self.set.is_match(s)
    }

    /// True if no patterns were given.
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// The patterns as given.
    pub fn raw(&self) -> &[String] {
        &self.raw
    }
}

/// The effective safety settings for this process.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Contexts the assistant may target besides the default one. Empty = default only.
    pub contexts: Patterns,
    /// Namespace allow-list. Empty = all.
    pub namespaces: Patterns,
    /// Namespace deny-list. Wins over the allow-list.
    pub deny_namespaces: Patterns,
    /// Redaction level.
    pub redact: RedactLevel,
    /// Hard cap on each tool response, in bytes.
    pub max_output_bytes: usize,
}

impl Policy {
    /// Build a policy from CLI values.
    pub fn new(
        contexts: &[String],
        namespaces: &[String],
        deny_namespaces: &[String],
        redact: RedactLevel,
        max_output_bytes: usize,
    ) -> Result<Self> {
        Ok(Self {
            contexts: Patterns::new(contexts)?,
            namespaces: Patterns::new(namespaces)?,
            deny_namespaces: Patterns::new(deny_namespaces)?,
            redact,
            max_output_bytes,
        })
    }

    /// Permissive defaults for tests: all namespaces, standard redaction.
    pub fn permissive() -> Self {
        Self {
            contexts: Patterns::none(),
            namespaces: Patterns::none(),
            deny_namespaces: Patterns::none(),
            redact: RedactLevel::Standard,
            max_output_bytes: 24_000,
        }
    }

    /// Whether a tool of this tier may be registered and called.
    pub fn tier_enabled(&self, tier: Tier) -> bool {
        match tier {
            Tier::Read => true,
            Tier::Write | Tier::Destructive => false,
        }
    }

    /// Whether `context` may be targeted, given the default context.
    pub fn context_allowed(&self, context: &str, default: &str) -> bool {
        context == default || self.contexts.is_match(context)
    }

    /// Whether objects in `ns` may be read and shown.
    pub fn namespace_allowed(&self, ns: &str) -> bool {
        !self.deny_namespaces.is_match(ns)
            && (self.namespaces.is_empty() || self.namespaces.is_match(ns))
    }

    /// Fail with an actionable error if `ns` is not allowed.
    pub fn check_namespace(&self, ns: &str) -> Result<()> {
        if self.namespace_allowed(ns) {
            Ok(())
        } else {
            Err(Error::NamespaceNotAllowed {
                namespace: ns.to_owned(),
                allowed: self.describe_namespaces(),
            })
        }
    }

    /// Allow-list entries that are plain names (no glob characters), used to list namespace
    /// by namespace when cluster-wide listing is forbidden by RBAC.
    pub fn literal_namespaces(&self) -> Vec<String> {
        self.namespaces
            .raw()
            .iter()
            .filter(|p| !p.contains(['*', '?', '[', '{']))
            .filter(|p| self.namespace_allowed(p))
            .cloned()
            .collect()
    }

    /// Human description of the namespace policy.
    pub fn describe_namespaces(&self) -> String {
        let allow = if self.namespaces.is_empty() {
            "all".to_owned()
        } else {
            self.namespaces.raw().join(",")
        };
        if self.deny_namespaces.is_empty() {
            allow
        } else {
            format!("{allow} except {}", self.deny_namespaces.raw().join(","))
        }
    }

    /// The policy as JSON, for `check_permissions` and the `k8s-mcp://policy` resource.
    pub fn to_json(&self) -> Value {
        json!({
            "tiers": { "read": true, "write": false, "destructive": false },
            "write_tools": "not available in this version",
            "extra_contexts": self.contexts.raw(),
            "namespaces": if self.namespaces.is_empty() { json!("all") } else { json!(self.namespaces.raw()) },
            "deny_namespaces": self.deny_namespaces.raw(),
            "redaction": self.redact,
            "max_output_bytes": self.max_output_bytes,
            "secret_values": "never returned by object reads; in pod logs, masked only where k8s-mcp may read the Secrets the pod references (otherwise pattern redaction only, and the summary says so)",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(allow: &[&str], deny: &[&str]) -> Policy {
        let v = |s: &[&str]| s.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        Policy::new(&[], &v(allow), &v(deny), RedactLevel::Standard, 24_000).unwrap()
    }

    #[test]
    fn empty_allow_list_allows_all() {
        assert!(p(&[], &[]).namespace_allowed("anything"));
    }

    #[test]
    fn globs_and_deny_wins() {
        let pol = p(&["shop", "team-*"], &["team-secret"]);
        assert!(pol.namespace_allowed("shop"));
        assert!(pol.namespace_allowed("team-a"));
        assert!(!pol.namespace_allowed("team-secret"));
        assert!(!pol.namespace_allowed("payments"));
        assert!(
            pol.check_namespace("payments")
                .unwrap_err()
                .to_string()
                .contains("shop,team-*")
        );
    }

    #[test]
    fn literal_namespaces_skip_globs_and_denied() {
        let pol = p(&["shop", "team-*", "kube-system"], &["kube-*"]);
        assert_eq!(pol.literal_namespaces(), ["shop"]);
    }

    #[test]
    fn contexts_default_only_unless_widened() {
        let pol = p(&[], &[]);
        assert!(pol.context_allowed("dev", "dev"));
        assert!(!pol.context_allowed("prod", "dev"));
        let wide = Policy::new(&["*".into()], &[], &[], RedactLevel::Standard, 1).unwrap();
        assert!(wide.context_allowed("prod", "dev"));
    }

    #[test]
    fn only_read_tier_enabled() {
        let pol = p(&[], &[]);
        assert!(pol.tier_enabled(Tier::Read));
        assert!(!pol.tier_enabled(Tier::Write));
        assert!(!pol.tier_enabled(Tier::Destructive));
    }
}
