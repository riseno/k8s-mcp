//! Redaction of credentials in text and structured output (PROPOSAL §12.3).
//!
//! Secret values are never fetched for output; [`sanitize_secret`] reduces a Secret to key
//! names and byte sizes. Everything else (logs, env values, annotations, ConfigMap values,
//! args, audit records) goes through [`Redactor`].

use std::borrow::Cow;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

use crate::policy::RedactLevel;

/// Replacement for redacted values.
pub const MASK: &str = "«redacted»";

fn re(pattern: &str) -> Regex {
    #[allow(clippy::unwrap_used)] // constant patterns, all exercised by the corpus tests
    Regex::new(pattern).unwrap()
}

/// Env var / map key names whose literal values are always masked.
static SENSITIVE_NAME: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)(pass(word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth|dsn|conn(ection)?[_-]?str|cookie|session|signature)",
    )
});

/// Value patterns, applied in order. `$k` keeps a captured key/prefix.
static PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        // PEM private key blocks (complete, or cut off at the end of the text).
        (
            re(
                r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?s:.*?)(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)",
            ),
            "-----BEGIN PRIVATE KEY-----«redacted»-----END PRIVATE KEY-----",
        ),
        // GCP service-account JSON.
        (
            re(r#"(?i)(?P<k>\\?"private_key(?:_id)?\\?"\s*:\s*\\?")(?:[^"\\]|\\[^"])*"#),
            "${k}«redacted»",
        ),
        // JWTs.
        (
            re(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"),
            MASK,
        ),
        // Authorization headers.
        (
            re(
                r#"(?i)(?P<k>authorization["']?\s*[:=]\s*["']?)(?:(?:basic|bearer|token|digest|negotiate)\s+)?[^\s"',;]+"#,
            ),
            "${k}«redacted»",
        ),
        // Bearer tokens anywhere.
        (
            re(r"(?i)(?P<k>\bbearer\s+)[A-Za-z0-9._~+/-]{8,}=*"),
            "${k}«redacted»",
        ),
        // Credentials in URLs: scheme://user:pass@host
        (
            re(r"(?P<k>[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]*):[^@\s/]+@"),
            "${k}:«redacted»@",
        ),
        // AWS access key ids.
        (re(r"\b(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}\b"), MASK),
        // AWS secret keys in key/value context.
        (
            re(
                r#"(?i)(?P<k>(?:aws_?)?secret_?access_?key["']?\s*[:=]\s*["']?)[A-Za-z0-9/+=]{30,}"#,
            ),
            "${k}«redacted»",
        ),
        // Azure connection strings and SAS signatures.
        (
            re(r"(?i)(?P<k>\b(?:AccountKey|SharedAccessKey|SharedAccessSignature)=)[^;\s'\x22]+"),
            "${k}«redacted»",
        ),
        (re(r"(?P<k>[?&]sig=)[^&\s'\x22]+"), "${k}«redacted»"),
        // GitHub / GitLab tokens.
        (
            re(
                r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,})",
            ),
            MASK,
        ),
        // Slack tokens.
        (re(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), MASK),
        // Generic key=value / key: value with a sensitive key.
        (
            re(
                r#"(?i)(?P<k>\b[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)[A-Za-z0-9_.-]*\\?["']?\s*[:=]\s*\\?["']?)(?:[^\s"'\\,;&«]|\\[^"])+"#,
            ),
            "${k}«redacted»",
        ),
    ]
});

/// Lines that open or close a PEM private key block (logs carry keys across many lines).
static PEM_BEGIN: LazyLock<Regex> = LazyLock::new(|| re(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"));
static PEM_END: LazyLock<Regex> = LazyLock::new(|| re(r"-----END [A-Z0-9 ]*PRIVATE KEY-----"));
/// An AWS access key id or the word "secret": context in which a bare 40-character token is
/// treated as an AWS secret access key.
static AWS_SECRET_CONTEXT: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bsecret"));
static AWS_SECRET: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?P<a>^|[^A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?P<b>[^A-Za-z0-9/+=]|$)"));

static IPV4: LazyLock<Regex> = LazyLock::new(|| re(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"));
static EMAIL: LazyLock<Regex> =
    LazyLock::new(|| re(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"));

/// Applies the configured redaction level.
#[derive(Debug, Clone, Copy, Default)]
pub struct Redactor {
    level: RedactLevel,
}

impl Redactor {
    /// A redactor for `level`.
    pub fn new(level: RedactLevel) -> Self {
        Self { level }
    }

    /// Redact credentials in free text (log lines, messages, annotation values, args).
    pub fn text(self, s: &str) -> Cow<'_, str> {
        if self.level == RedactLevel::Off {
            return Cow::Borrowed(s);
        }
        let aws_context = AWS_SECRET_CONTEXT.is_match(s);
        let mut out = Cow::Borrowed(s);
        if aws_context && AWS_SECRET.is_match(&out) {
            out = Cow::Owned(
                AWS_SECRET
                    .replace_all(&out, "${a}«redacted»${b}")
                    .into_owned(),
            );
        }
        for (pattern, rep) in PATTERNS.iter() {
            if pattern.is_match(&out) {
                out = Cow::Owned(pattern.replace_all(&out, *rep).into_owned());
            }
        }
        if self.level == RedactLevel::Strict {
            if IPV4.is_match(&out) {
                out = Cow::Owned(IPV4.replace_all(&out, "«ip»").into_owned());
            }
            if EMAIL.is_match(&out) {
                out = Cow::Owned(EMAIL.replace_all(&out, "«email»").into_owned());
            }
        }
        out
    }

    /// Redact consecutive lines of one stream (a container log). Like [`Self::text`] per line,
    /// and also masks every line inside a PEM private key block, which spans lines.
    pub fn lines<'a>(self, lines: impl IntoIterator<Item = &'a str>) -> Vec<String> {
        let mut in_key = false;
        lines
            .into_iter()
            .map(|l| {
                if self.level == RedactLevel::Off {
                    return l.to_owned();
                }
                if in_key {
                    in_key = !PEM_END.is_match(l);
                    return MASK.to_owned();
                }
                in_key = PEM_BEGIN.is_match(l) && !PEM_END.is_match(l);
                self.text(l).into_owned()
            })
            .collect()
    }

    /// Redact a named value (env var, ConfigMap entry, annotation): masked entirely when the
    /// name looks sensitive, otherwise pattern-redacted.
    pub fn named(self, name: &str, value: &str) -> String {
        match self.level {
            RedactLevel::Off => value.to_owned(),
            _ if SENSITIVE_NAME.is_match(name) => MASK.to_owned(),
            _ => self.text(value).into_owned(),
        }
    }

    /// Redact a ConfigMap value. `strict` shows keys only.
    pub fn config_value(self, name: &str, value: &str) -> String {
        if self.level == RedactLevel::Strict {
            return format!("«{} bytes»", value.len());
        }
        self.named(name, value)
    }

    /// Pattern-redact every string inside a JSON value (used for audit args and YAML views).
    pub fn json(self, v: &mut Value) {
        match v {
            Value::String(s) => {
                if let Cow::Owned(r) = self.text(s) {
                    *s = r;
                }
            }
            Value::Array(a) => a.iter_mut().for_each(|v| self.json(v)),
            Value::Object(m) => m.values_mut().for_each(|v| self.json(v)),
            _ => {}
        }
    }

    /// Redact every value of a string map by key name (annotations, ConfigMap data).
    pub fn map(self, m: &mut Map<String, Value>) {
        for (k, v) in m.iter_mut() {
            if let Value::String(s) = v {
                *s = self.named(k, s);
            }
        }
    }
}

/// Mask exact occurrences of known secret values (for example the values of Secrets a pod
/// references) in `lines`. Applied at every redaction level: Secret values are never returned.
/// Values shorter than 6 characters are ignored to avoid masking common words.
pub fn scrub_values(lines: &mut [String], values: &[String]) {
    let mut values: Vec<&str> = values
        .iter()
        .map(|v| v.trim())
        .filter(|v| v.len() >= 6)
        .collect();
    values.sort_by_key(|v| std::cmp::Reverse(v.len()));
    values.dedup();
    if values.is_empty() {
        return;
    }
    for line in lines.iter_mut() {
        for v in &values {
            if line.contains(v) {
                *line = line.replace(v, MASK);
            }
        }
    }
}

/// Reduce a Secret (as JSON) to key names and sizes: `data` and `stringData` values become
/// `"<N bytes>"`. Applied in every mode, including `--redact off`.
pub fn sanitize_secret(obj: &mut Value) {
    for field in ["data", "stringData"] {
        if let Some(Value::Object(m)) = obj.get_mut(field) {
            for v in m.values_mut() {
                let n = match v {
                    Value::String(s) if field == "data" => base64_len(s),
                    Value::String(s) => s.len(),
                    _ => 0,
                };
                *v = Value::String(format!("<{n} bytes>"));
            }
        }
    }
    if let Some(Value::Object(meta)) = obj.get_mut("metadata")
        && let Some(Value::Object(ann)) = meta.get_mut("annotations")
    {
        ann.remove("kubectl.kubernetes.io/last-applied-configuration");
    }
}

/// Decoded length of a base64 string, without decoding it.
fn base64_len(s: &str) -> usize {
    let s = s.trim();
    let pad = s.bytes().rev().take_while(|b| *b == b'=').count();
    (s.len() / 4 * 3).saturating_sub(pad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn named_masks_sensitive_env_names() {
        let r = Redactor::default();
        assert_eq!(r.named("DB_PASSWORD", "hunter2"), MASK);
        assert_eq!(r.named("GITHUB_TOKEN", "abc"), MASK);
        assert_eq!(r.named("LOG_LEVEL", "debug"), "debug");
    }

    #[test]
    fn off_level_leaves_text_but_secrets_stay_sanitized() {
        let r = Redactor::new(RedactLevel::Off);
        assert_eq!(r.text("password=hunter2"), "password=hunter2");
        let mut s = json!({"data": {"k": "aHVudGVyMg=="}});
        sanitize_secret(&mut s);
        assert_eq!(s, json!({"data": {"k": "<7 bytes>"}}));
    }

    #[test]
    fn strict_masks_ips_emails_and_configmap_values() {
        let r = Redactor::new(RedactLevel::Strict);
        assert_eq!(r.text("from 10.1.2.3 by a@b.io"), "from «ip» by «email»");
        assert_eq!(r.config_value("LOG_LEVEL", "debug"), "«5 bytes»");
    }

    #[test]
    fn json_and_map() {
        let r = Redactor::default();
        let mut v = json!({"args": ["--token=abcdef123", "ok"], "n": 1});
        r.json(&mut v);
        assert_eq!(v, json!({"args": ["--token=«redacted»", "ok"], "n": 1}));
        let mut m = json!({"my-api-key": "x", "team": "a"});
        r.map(m.as_object_mut().unwrap());
        assert_eq!(m, json!({"my-api-key": MASK, "team": "a"}));
    }
}
