//! `get_logs`: shaped container logs (PROPOSAL §7.7 rule 4).

use std::sync::LazyLock;

use k8s_mcp_core::envelope::Section;
use k8s_mcp_core::text::{dedup_lines, parse_duration, strip_ansi};
use k8s_mcp_core::{Error, Result};
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, LogParams};
use regex::{Regex, RegexBuilder};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use crate::common::{check_name, envelope, scope};
use crate::diagnose::workload_pods;
use crate::read::add_notes;
use crate::rows::unhealthy;
use crate::{Ctx, Envelope};

const DEFAULT_TAIL: i64 = 200;
const MAX_TAIL: i64 = 2000;

#[allow(clippy::unwrap_used)] // constant pattern
static ERRORS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(error|err|exception|fatal|panic|panicked|traceback|fail(ed|ure)?|critical|crit|refused|denied|timeout|timed out|unable|cannot|can't|oom|killed|segfault|stack trace)\b|^\s+at |^\s+File ").unwrap()
});

/// Inputs for `get_logs`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetLogsInput {
    /// Pod name. Give either `pod` or `workload`.
    pub pod: Option<String>,
    /// Workload as `kind/name`, e.g. `deployment/checkout`; logs come from up to `max_pods` pods, failing pods first.
    pub workload: Option<String>,
    /// Namespace (default: the context's namespace).
    pub namespace: Option<String>,
    /// Container name (default: every container when `all_containers`, else the first).
    pub container: Option<String>,
    /// Logs of the previous (crashed) instance.
    #[serde(default)]
    pub previous: bool,
    /// Last N lines (default 200, max 2000).
    pub tail: Option<i64>,
    /// Only lines newer than this, e.g. `10m`, `1h`.
    pub since: Option<String>,
    /// Case-insensitive regex filter.
    pub grep: Option<String>,
    /// Lines of context around each grep match (default 0, max 10).
    pub context_lines: Option<usize>,
    /// Keep only lines matching a built-in error pattern set.
    #[serde(default)]
    pub errors_only: bool,
    /// All containers of each pod.
    #[serde(default)]
    pub all_containers: bool,
    /// Max pods for `workload` (default 3, max 10).
    pub max_pods: Option<usize>,
    /// Kubeconfig context.
    pub context: Option<String>,
}

/// Container logs: ANSI-stripped, redacted, filtered, de-duplicated and capped.
pub async fn get_logs(ctx: &Ctx, input: GetLogsInput) -> Result<Envelope> {
    let sc = scope(
        ctx,
        input.context.as_deref(),
        input.namespace.as_deref(),
        false,
    )
    .await?;
    let ns = sc.namespace.clone().unwrap_or_default();
    let api: Api<Pod> = Api::namespaced(sc.target.client.clone(), &ns);
    let now = ctx.now();
    let pods: Vec<Pod> = match (&input.pod, &input.workload) {
        (Some(p), None) => {
            check_name("pod", p)?;
            vec![
                api.get(p)
                    .await
                    .map_err(|e| Error::kube(format!("get pod {p} in namespace {ns}"), &e))?,
            ]
        }
        (None, Some(w)) => {
            let (kind, name) = w.split_once('/').ok_or_else(|| {
                Error::InvalidInput(format!(
                    "workload {w:?} must look like kind/name, e.g. deployment/checkout"
                ))
            })?;
            check_name("workload", name)?;
            let mut pods = workload_pods(&sc, kind, name).await?.1;
            pods.sort_by_key(|p| unhealthy(p, now).is_none());
            pods.truncate(input.max_pods.unwrap_or(3).clamp(1, 10));
            pods
        }
        _ => {
            return Err(Error::InvalidInput(
                "give exactly one of `pod` or `workload`".into(),
            ));
        }
    };
    let grep = input
        .grep
        .as_deref()
        .map(|g| {
            RegexBuilder::new(g)
                .case_insensitive(true)
                .size_limit(1 << 20)
                .build()
        })
        .transpose()
        .map_err(|e| Error::InvalidInput(format!("grep is not a valid regex: {e}")))?;
    let since = input
        .since
        .as_deref()
        .map(parse_duration)
        .transpose()
        .map_err(Error::InvalidInput)?;
    let tail = input.tail.unwrap_or(DEFAULT_TAIL).clamp(1, MAX_TAIL);
    let ctx_lines = input.context_lines.unwrap_or(0).min(10);

    let mut e = envelope(&sc, String::new());
    let mut notes = Vec::new();
    let mut total = 0;
    for pod in &pods {
        let pod_name = pod.metadata.name.clone().unwrap_or_default();
        let containers: Vec<String> = if let Some(c) = &input.container {
            vec![c.clone()]
        } else {
            let all: Vec<String> = pod
                .spec
                .iter()
                .flat_map(|s| &s.containers)
                .map(|c| c.name.clone())
                .collect();
            if input.all_containers {
                all
            } else {
                all.into_iter().take(1).collect()
            }
        };
        for container in containers {
            let lp = LogParams {
                container: Some(container.clone()),
                previous: input.previous,
                tail_lines: Some(if grep.is_some() || input.errors_only {
                    MAX_TAIL
                } else {
                    tail
                }),
                since_seconds: since.map(|d| d.as_secs()),
                ..LogParams::default()
            };
            let raw = match api.logs(&pod_name, &lp).await {
                Ok(r) => r,
                Err(err) => {
                    notes.push(k8s_mcp_diagnose::Unavailable {
                        what: format!(
                            "logs of {pod_name}/{container}{}",
                            if input.previous { " (previous)" } else { "" }
                        ),
                        reason: Error::kube(
                            format!("get logs of pod {pod_name} container {container}"),
                            &err,
                        )
                        .to_string(),
                    });
                    continue;
                }
            };
            if raw.starts_with("unable to retrieve container logs") {
                notes.push(k8s_mcp_diagnose::Unavailable {
                    what: format!("logs of {pod_name}/{container}"),
                    reason: "the runtime no longer has them (the container was removed); try previous=false or a newer instance".into(),
                });
                continue;
            }
            let (lines, omitted) = shape(
                ctx,
                &raw,
                grep.as_ref(),
                ctx_lines,
                input.errors_only,
                usize::try_from(tail).unwrap_or(200),
            );
            total += lines.len();
            e.items.push(json!({"pod": pod_name, "container": container, "previous": input.previous, "lines": lines, "omitted_lines": omitted}));
            e.sections.push(Section {
                title: format!(
                    "LOGS {pod_name}/{container}{} ({} lines{})",
                    if input.previous {
                        " previous instance"
                    } else {
                        ""
                    },
                    lines.len(),
                    if omitted > 0 {
                        format!(", {omitted} older omitted")
                    } else {
                        String::new()
                    }
                ),
                lines,
                untrusted: Some(vec![
                    ("source".into(), "log".into()),
                    ("pod".into(), pod_name.clone()),
                    ("container".into(), container),
                ]),
            });
        }
    }
    e.summary = format!(
        "{total} log lines from {} container(s) in {} pod(s){}{}.",
        e.items.len(),
        pods.len(),
        input
            .grep
            .as_deref()
            .map(|g| format!(" matching /{g}/"))
            .unwrap_or_default(),
        if input.errors_only {
            " (errors only)"
        } else {
            ""
        }
    );
    e.untrusted_fields = vec!["items[*].lines".into()];
    add_notes(&mut e, &notes);
    Ok(e)
}

/// Strip ANSI, redact, filter, de-duplicate, then keep the last `tail` lines.
fn shape(
    ctx: &Ctx,
    raw: &str,
    grep: Option<&Regex>,
    context: usize,
    errors_only: bool,
    tail: usize,
) -> (Vec<String>, usize) {
    let lines: Vec<String> = raw
        .lines()
        .map(|l| ctx.redactor.text(&strip_ansi(l)).into_owned())
        .collect();
    let keep: Vec<bool> = if let (None, false) = (grep, errors_only) {
        vec![true; lines.len()]
    } else {
        let hit: Vec<bool> = lines
            .iter()
            .map(|l| grep.is_none_or(|g| g.is_match(l)) && (!errors_only || ERRORS.is_match(l)))
            .collect();
        (0..lines.len())
            .map(|i| {
                hit[i.saturating_sub(context)..=(i + context).min(lines.len().saturating_sub(1))]
                    .iter()
                    .any(|h| *h)
            })
            .collect()
    };
    let filtered = lines
        .into_iter()
        .zip(keep)
        .filter_map(|(l, k)| k.then_some(l));
    let mut out = dedup_lines(filtered);
    let omitted = out.len().saturating_sub(tail);
    out.drain(..omitted);
    (out, omitted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_mcp_core::cluster::ClusterManager;
    use k8s_mcp_core::policy::Policy;
    use std::sync::Arc;

    fn ctx() -> Ctx {
        // A client that is never used: shape() is pure.
        let (svc, _handle) = tower_test::mock::pair::<
            http::Request<kube::client::Body>,
            http::Response<kube::client::Body>,
        >();
        let client = kube::Client::new(svc, "default");
        Ctx::new(
            Arc::new(ClusterManager::fixed(client, "test", "default")),
            Arc::new(Policy::permissive()),
        )
    }

    #[tokio::test]
    async fn shapes_logs() {
        let raw = "\x1b[32mINFO\x1b[0m start\nretry\nretry\nretry\nERROR connect failed password=hunter2\nINFO ok\n";
        let (lines, omitted) = shape(&ctx(), raw, None, 0, false, 10);
        assert_eq!(omitted, 0);
        assert_eq!(
            lines,
            [
                "INFO start",
                "[×3] retry",
                "ERROR connect failed password=«redacted»",
                "INFO ok"
            ]
        );
        let (errs, _) = shape(&ctx(), raw, None, 0, true, 10);
        assert_eq!(errs, ["ERROR connect failed password=«redacted»"]);
        let grep = RegexBuilder::new("connect")
            .case_insensitive(true)
            .build()
            .unwrap();
        let (ctx_lines, _) = shape(&ctx(), raw, Some(&grep), 1, false, 10);
        assert_eq!(
            ctx_lines,
            [
                "retry",
                "ERROR connect failed password=«redacted»",
                "INFO ok"
            ]
        );
        let (tail, omitted) = shape(&ctx(), raw, None, 0, false, 2);
        assert_eq!((tail.len(), omitted), (2, 2));
    }
}
