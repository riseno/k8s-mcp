//! Diagnosis findings: the unit of output for every `diagnose_*` tool and `find_problems`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// How bad a finding is. Ordered most severe first, so `sort()` ranks critical first.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// The workload is down or not serving.
    Critical,
    /// Degraded, or will fail soon.
    High,
    /// A misconfiguration likely to bite.
    Medium,
    /// A hint.
    Low,
    /// Informational.
    Info,
}

impl Severity {
    /// Lower-case name, as used in ids and text output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }
}

/// How sure the rule is. `High` only when a definitive status field or event reason matched.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Matched a definitive status field or event reason.
    High,
    /// Rests on message parsing or a log pattern.
    Medium,
    /// Inferred, or key evidence was unavailable.
    Low,
}

impl Confidence {
    /// Lower-case name, as used in text output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    /// One step less sure (used when evidence was unavailable).
    #[must_use]
    pub fn lower(self) -> Self {
        match self {
            Self::High => Self::Medium,
            Self::Medium | Self::Low => Self::Low,
        }
    }
}

/// Where a piece of evidence came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// Object status (container states, conditions, phase; untrusted text).
    Status,
    /// A Kubernetes event (untrusted text).
    Event,
    /// A container log line (untrusted text).
    Log,
    /// Object spec.
    Spec,
    /// Another object (node, PVC, ConfigMap existence, quota).
    Related,
    /// Evidence that could not be gathered.
    Unavailable,
}

impl Source {
    /// Lower-case name, as used in text output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Event => "event",
            Self::Log => "log",
            Self::Spec => "spec",
            Self::Related => "related",
            Self::Unavailable => "unavailable",
        }
    }
}

/// One quoted fact supporting a finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Evidence {
    /// Where the fact came from.
    pub source: Source,
    /// The fact itself (redacted).
    pub text: String,
}

/// A reference to a Kubernetes object.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ObjectRef {
    /// Kind, e.g. `Pod`.
    pub kind: String,
    /// Namespace, if namespaced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Object name.
    pub name: String,
}

impl ObjectRef {
    /// Build a reference.
    pub fn new(kind: &str, namespace: Option<&str>, name: &str) -> Self {
        Self {
            kind: kind.to_owned(),
            namespace: namespace.map(str::to_owned),
            name: name.to_owned(),
        }
    }
}

impl std::fmt::Display for ObjectRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.namespace {
            Some(ns) => write!(f, "{}/{} ({ns})", self.kind, self.name),
            None => write!(f, "{}/{}", self.kind, self.name),
        }
    }
}

/// A suggested follow-up tool call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct NextCall {
    /// Tool name.
    pub tool: String,
    /// Arguments to pass.
    pub args: Value,
    /// Why this call helps.
    pub why: String,
}

impl NextCall {
    /// Build a suggestion.
    pub fn new(tool: &str, args: Value, why: &str) -> Self {
        Self {
            tool: tool.to_owned(),
            args,
            why: why.to_owned(),
        }
    }
}

/// A diagnosis result produced by a deterministic rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Finding {
    /// Stable dotted rule id, e.g. `pod.oom.container`. Never renamed once released.
    pub id: String,
    /// How bad it is.
    pub severity: Severity,
    /// How sure the rule is.
    pub confidence: Confidence,
    /// One-line headline.
    pub title: String,
    /// 2-4 sentences on what is happening.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub explanation: String,
    /// Quoted facts supporting the finding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    /// Concrete steps to fix it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fix: String,
    /// Reference documentation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docs: Option<String>,
    /// The object the finding is about (set by `find_problems` and `diagnose_workload`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<ObjectRef>,
    /// Suggested follow-up calls.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub next: Vec<NextCall>,
}

impl Finding {
    /// Start a finding; chain the builder methods to fill it in.
    pub fn new(
        id: &str,
        severity: Severity,
        confidence: Confidence,
        title: impl Into<String>,
    ) -> Self {
        Self {
            id: id.to_owned(),
            severity,
            confidence,
            title: title.into(),
            explanation: String::new(),
            evidence: Vec::new(),
            fix: String::new(),
            docs: None,
            object: None,
            next: Vec::new(),
        }
    }

    /// Set the explanation.
    #[must_use]
    pub fn explain(mut self, text: impl Into<String>) -> Self {
        self.explanation = text.into();
        self
    }

    /// Add a piece of evidence.
    #[must_use]
    pub fn evidence(mut self, source: Source, text: impl Into<String>) -> Self {
        self.evidence.push(Evidence {
            source,
            text: text.into(),
        });
        self
    }

    /// Set the fix.
    #[must_use]
    pub fn fix(mut self, text: impl Into<String>) -> Self {
        self.fix = text.into();
        self
    }

    /// Set the docs link.
    #[must_use]
    pub fn docs(mut self, url: &str) -> Self {
        self.docs = Some(url.to_owned());
        self
    }

    /// Set the object.
    #[must_use]
    pub fn object(mut self, object: ObjectRef) -> Self {
        self.object = Some(object);
        self
    }

    /// Add a suggested follow-up call.
    #[must_use]
    pub fn next(mut self, tool: &str, args: Value, why: &str) -> Self {
        self.next.push(NextCall::new(tool, args, why));
        self
    }
}

/// Rank findings: severity, then confidence, then the order rules produced them
/// (rules run root causes before symptoms). Stable, so ties keep rule order.
pub fn rank(findings: &mut [Finding]) {
    findings.sort_by_key(|f| (f.severity, f.confidence));
}

/// Remove findings with the same id and object, keeping the first (highest ranked after `rank`).
pub fn dedup(findings: &mut Vec<Finding>) {
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert((f.id.clone(), f.object.clone())));
}

/// Merge findings with the same id and title on different objects (the same root cause seen on
/// many pods, e.g. one missing image) into the first one, listing the other objects in its
/// evidence. Keeps order, so call it after [`rank`].
pub fn group_same_cause(findings: Vec<Finding>) -> Vec<Finding> {
    const SHOWN: usize = 5;
    let mut out: Vec<(Finding, Vec<String>)> = Vec::new();
    for f in findings {
        let same = f.object.as_ref().and_then(|o| {
            out.iter_mut()
                .find(|(g, _)| g.id == f.id && g.title == f.title && g.object.as_ref() != Some(o))
                .map(|(_, more)| (more, o.to_string()))
        });
        match same {
            Some((more, name)) => more.push(name),
            None => out.push((f, Vec::new())),
        }
    }
    out.into_iter()
        .map(|(mut f, more)| {
            if !more.is_empty() {
                let mut text = format!(
                    "same finding on {} more: {}",
                    more.len(),
                    more.iter()
                        .take(SHOWN)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                if more.len() > SHOWN {
                    use std::fmt::Write as _;
                    let _ = write!(text, " and {} others", more.len() - SHOWN);
                }
                f.evidence.push(Evidence {
                    source: Source::Related,
                    text,
                });
            }
            f
        })
        .collect()
}

/// Metadata for one detection rule, used for the `k8s-mcp://rules` resource and generated docs.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct RuleMeta {
    /// Stable dotted id.
    pub id: &'static str,
    /// What the rule detects.
    pub title: &'static str,
    /// Reference documentation.
    pub docs: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rank_orders_by_severity_then_confidence_and_keeps_rule_order() {
        let mut f = vec![
            Finding::new("a", Severity::High, Confidence::High, "a"),
            Finding::new("b", Severity::Critical, Confidence::Medium, "b"),
            Finding::new("c", Severity::Critical, Confidence::High, "c"),
            Finding::new("d", Severity::High, Confidence::High, "d"),
        ];
        rank(&mut f);
        let ids: Vec<_> = f.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, ["c", "b", "a", "d"]);
    }

    #[test]
    fn group_same_cause_merges_one_root_cause_across_pods() {
        let f = |pod: &str, title: &str| {
            Finding::new(
                "pod.image.not_found",
                Severity::Critical,
                Confidence::High,
                title,
            )
            .object(ObjectRef::new("Pod", Some("shop"), pod))
        };
        let mut all: Vec<Finding> = (0..8)
            .map(|i| f(&format!("web-{i}"), "image \"app:latest\" not found"))
            .collect();
        all.push(f("api-0", "image \"api:2\" not found"));
        let grouped = group_same_cause(all);
        assert_eq!(grouped.len(), 2);
        let merged = grouped[0].evidence.last().unwrap();
        assert_eq!(merged.source, Source::Related);
        assert!(
            merged
                .text
                .starts_with("same finding on 7 more: Pod/web-1 (shop)"),
            "{}",
            merged.text
        );
        assert!(merged.text.ends_with("and 2 others"), "{}", merged.text);
        assert!(grouped[1].evidence.is_empty());
    }

    #[test]
    fn dedup_keeps_first_per_id_and_object() {
        let mut f = vec![
            Finding::new("a", Severity::High, Confidence::High, "1"),
            Finding::new("a", Severity::Low, Confidence::High, "2"),
            Finding::new("a", Severity::Low, Confidence::High, "3").object(ObjectRef::new(
                "Pod",
                Some("ns"),
                "p",
            )),
        ];
        dedup(&mut f);
        let titles: Vec<_> = f.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(titles, ["1", "3"]);
    }
}
