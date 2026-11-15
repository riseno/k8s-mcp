//! Workload-level rules (PROPOSAL §9.2): pod creation failures (ResourceQuota, admission
//! webhooks, Pod Security, LimitRange, missing ServiceAccount), failed Jobs, CronJobs that do
//! not run, stuck rollouts, unavailable replicas and single-replica workloads.
//!
//! Root causes come first and are `critical`; the symptoms (`workload.rollout.stuck`,
//! `workload.replicas.unavailable`) are `high`, so pod-level root causes rank above them;
//! `workload.single_replica` is a `low` hint. A `FailedCreate` naming a missing ServiceAccount
//! is reported as `pod.config.missing_serviceaccount` (registered in [`super::config`]).
//! Missed CronJob schedules are detected from controller events only: computing them from
//! `spec.schedule` would need a cron parser.

use std::cmp::Reverse;
use std::sync::LazyLock;

use k8s_mcp_core::finding::{Confidence, Finding, ObjectRef, RuleMeta, Severity, Source};
use k8s_mcp_core::text::truncate;
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::Event;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use regex::Regex;
use serde_json::json;

use super::config::{Issue, issue_finding, parse_issue};
use super::{
    dns_name, docs, events_with, last_seen, msg, quote_event, re, reason, resource_args, rule_docs,
};
use crate::evidence::{RefKind, Workload, WorkloadEvidence};

/// Rules emitted by this module.
pub const RULES: &[RuleMeta] = &[
    RuleMeta {
        id: "workload.rollout.stuck",
        title: "Deployment rollout exceeded its progress deadline",
        docs: docs::DEPLOYMENT,
    },
    RuleMeta {
        id: "workload.replicas.unavailable",
        title: "Fewer replicas are available than desired",
        docs: docs::DEPLOYMENT,
    },
    RuleMeta {
        id: "workload.create_failed",
        title: "The controller cannot create pods (admission webhook, Pod Security, LimitRange)",
        docs: docs::DEPLOYMENT,
    },
    RuleMeta {
        id: "pod.pending.quota",
        title: "Pod creation is blocked by a ResourceQuota",
        docs: docs::QUOTA,
    },
    RuleMeta {
        id: "job.backoff_limit",
        title: "Job failed: its pods failed more often than backoffLimit allows",
        docs: docs::JOB,
    },
    RuleMeta {
        id: "job.deadline_exceeded",
        title: "Job failed: it ran longer than activeDeadlineSeconds",
        docs: docs::JOB,
    },
    RuleMeta {
        id: "cronjob.not_scheduling",
        title: "CronJob is suspended or not starting Jobs on schedule",
        docs: docs::CRONJOB,
    },
    RuleMeta {
        id: "workload.single_replica",
        title: "Workload runs a single replica (no redundancy)",
        docs: docs::DEPLOYMENT,
    },
];

static QUOTA: LazyLock<Regex> = LazyLock::new(|| re(r"(exceeded|failed) quota: ([^,:\s]+)"));
static PSA: LazyLock<Regex> =
    LazyLock::new(|| re(r#"violates PodSecurity "(baseline|restricted|privileged)(?::[^"]*)?""#));
static WEBHOOK_DENIED: LazyLock<Regex> =
    LazyLock::new(|| re(r#"admission webhook "([^"]+)" denied the request"#));
static WEBHOOK_DOWN: LazyLock<Regex> = LazyLock::new(|| re(r#"failed calling webhook "([^"]+)""#));

/// CronJob controller event reasons that mean Jobs are not being started.
const CRONJOB_TROUBLE: &[&str] = &[
    "InvalidSchedule",
    "UnknownTimeZone",
    "JobAlreadyActive",
    "TooManyMissedTimes",
    "MissSchedule",
];

/// Run the workload checks; every finding is tagged with the workload as its object.
pub fn check(ev: &WorkloadEvidence, out: &mut Vec<Finding>) {
    let (kind, meta) = kind_meta(&ev.workload);
    let name = meta.name.as_deref().unwrap_or("");
    let ns = meta.namespace.as_deref().unwrap_or("default");
    let mut found = Vec::new();
    create_failures(ev, ns, &mut found);
    match &ev.workload {
        Workload::Job(j) => job(j, &mut found),
        Workload::CronJob(c) => {
            cronjob(ev, c, &mut found);
            if let Some(j) = ev.jobs.first() {
                job(j, &mut found);
            }
        }
        _ => {}
    }
    rollout(ev, kind, name, ns, &mut found);
    let obj = ObjectRef::new(kind, Some(ns), name);
    out.extend(found.into_iter().map(|f| f.object(obj.clone())));
}

/// `FailedCreate` events on the workload or its ReplicaSets/Jobs, newest first, one finding
/// per rule id.
fn create_failures(ev: &WorkloadEvidence, ns: &str, out: &mut Vec<Finding>) {
    let mut failed: Vec<&Event> = events_with(&ev.events, &["FailedCreate"]).collect();
    failed.sort_by_key(|e| Reverse(last_seen(e)));
    for e in failed {
        let m = msg(e);
        let mut f = if let Some(c) = QUOTA.captures(m) {
            quota(ev, ns, &c[2], &c[1] == "failed")
        } else if let Some(issue @ Issue::Missing(RefKind::ServiceAccount, _)) = parse_issue(m) {
            issue_finding(&issue, ns)
        } else if let Some(c) = PSA.captures(m) {
            Finding::new("workload.create_failed", Severity::Critical, Confidence::High, format!("pods are rejected by Pod Security admission (level {})", &c[1]))
                .explain("The namespace enforces a Pod Security Standard and the pod template violates it, so the API server rejects every pod the controller tries to create. The event lists each violating field.")
                .fix("Set the securityContext fields the message lists (for `restricted`: runAsNonRoot: true, allowPrivilegeEscalation: false, capabilities.drop: [ALL], seccompProfile.type: RuntimeDefault). If the workload truly needs more privilege, label the namespace with a lower `pod-security.kubernetes.io/enforce` level.")
                .docs(docs::PSA)
        } else if let Some(c) = WEBHOOK_DENIED.captures(m) {
            Finding::new("workload.create_failed", Severity::Critical, Confidence::High, format!("admission webhook {} denies pod creation", webhook(&c[1])))
                .explain("A validating admission webhook rejects the pod template, so no pod is created. Its message (quoted below) says which policy fired.")
                .fix("Change the pod template to satisfy the policy, or the policy itself (Kyverno, Gatekeeper and similar tools name the rule in the message). `kubectl get validatingwebhookconfigurations` shows which webhooks apply.")
        } else if let Some(c) = WEBHOOK_DOWN.captures(m) {
            Finding::new("workload.create_failed", Severity::Critical, Confidence::High, format!("admission webhook {} cannot be reached, so pod creation fails", webhook(&c[1])))
                .explain("The API server must call this webhook before creating pods and the call fails. With failurePolicy: Fail, every matching create is rejected while the webhook is down.")
                .fix("Check the webhook's Service and pods (they may be crash-looping or have no endpoints). `kubectl get validatingwebhookconfigurations,mutatingwebhookconfigurations` shows it; failurePolicy Ignore trades safety for availability.")
        } else {
            let limit_range = m.contains("per Container") || m.contains("per Pod");
            Finding::new("workload.create_failed", Severity::Critical, Confidence::High, if limit_range { "pods violate the namespace's LimitRange" } else { "the controller cannot create pods" })
                .explain("The API server rejects the pods the controller tries to create, so missing replicas are never started. The error is quoted below.")
                .fix(if limit_range {
                    "Bring the template's resources within the LimitRange's min/max (or adjust the LimitRange): `kubectl describe limitrange -n <namespace>` shows the bounds."
                } else {
                    "Read the API error quoted below; it names the rejected field or the component that refused the pod."
                })
        };
        if out.iter().all(|o| o.id != f.id) {
            if f.docs.is_none() {
                f.docs = Some(rule_docs(RULES, &f.id).to_owned());
            }
            out.push(f.evidence(Source::Event, quote_event(e, ev.now)));
        }
    }
}

fn webhook(name: &str) -> String {
    if dns_name(name) {
        format!("{name:?}")
    } else {
        "(name withheld)".to_owned()
    }
}

/// `pod.pending.quota` for ResourceQuota `name` (`requires_limits` for `failed quota: must specify ...`).
fn quota(ev: &WorkloadEvidence, ns: &str, name: &str, requires_limits: bool) -> Finding {
    let shown = if dns_name(name) {
        format!("ResourceQuota {name:?}")
    } else {
        "a ResourceQuota".to_owned()
    };
    let mut f = if requires_limits {
        Finding::new("pod.pending.quota", Severity::Critical, Confidence::High, format!("{shown} rejects pods that do not set resource requests/limits"))
            .explain("The namespace's quota covers requests/limits, so every pod must declare them; the pod template does not, and the API server rejects each pod.")
            .fix("Set resources.requests and resources.limits for every container in the template, or add a LimitRange with defaults for the namespace.")
    } else {
        Finding::new("pod.pending.quota", Severity::Critical, Confidence::High, format!("pod creation is blocked by {shown}"))
            .explain("Creating another pod would exceed the namespace's ResourceQuota, so the controller cannot create it. Existing pods keep running; the missing replicas never appear.")
            .fix(format!("Raise the quota's hard limits (`kubectl edit resourcequota <name> -n {ns}`), lower the pod template's requests, or free quota by scaling down other workloads in the namespace."))
    };
    f = f.docs(docs::QUOTA);
    if !dns_name(name) {
        return f;
    }
    if let Some(q) = ev
        .quotas
        .iter()
        .find(|q| q.metadata.name.as_deref() == Some(name))
    {
        let status = q.status.as_ref();
        let used = status.and_then(|s| s.used.as_ref());
        for (res, hard) in status.and_then(|s| s.hard.as_ref()).into_iter().flatten() {
            let u = used.and_then(|u| u.get(res)).map_or("?", |q| q.0.as_str());
            f = f.evidence(
                Source::Related,
                format!("ResourceQuota {name} {res}: used {u} / hard {}", hard.0),
            );
        }
    }
    f.next(
        "get_resource",
        resource_args("ResourceQuota", name, ns),
        "see the quota's limits and current use",
    )
}

fn job(j: &Job, out: &mut Vec<Finding>) {
    let name = j.metadata.name.as_deref().unwrap_or("");
    let status = j.status.as_ref();
    let spec = j.spec.as_ref();
    let Some(cond) = status
        .and_then(|s| s.conditions.as_ref())
        .into_iter()
        .flatten()
        .find(|c| c.type_ == "Failed" && c.status == "True")
    else {
        return;
    };
    let failed = status.and_then(|s| s.failed).unwrap_or(0);
    let mut f = match cond.reason.as_deref() {
        Some("BackoffLimitExceeded") => {
            let limit = spec.and_then(|s| s.backoff_limit).unwrap_or(6);
            Finding::new("job.backoff_limit", Severity::Critical, Confidence::High, format!("Job {name} failed: its pods failed {failed} times (backoffLimit {limit})"))
                .explain("The Job retries failed pods up to spec.backoffLimit times and then gives up. The pod-level findings show why the pods fail.")
                .fix("Fix the pod failure first (see the pod findings and their logs), then re-run the Job. Raise spec.backoffLimit only for work that is genuinely flaky.")
        }
        Some("DeadlineExceeded") => {
            let deadline = spec.and_then(|s| s.active_deadline_seconds).map_or_else(
                || "its deadline".to_owned(),
                |d| format!("activeDeadlineSeconds={d}"),
            );
            Finding::new("job.deadline_exceeded", Severity::Critical, Confidence::High, format!("Job {name} was stopped after {deadline}"))
                .explain("The Job ran longer than spec.activeDeadlineSeconds, so its pods were terminated and the Job marked failed.")
                .fix("Make the work faster, raise activeDeadlineSeconds, or check whether its pods spent the time Pending or crash-looping (see the pod findings).")
        }
        _ => return,
    };
    f = f
        .evidence(
            Source::Status,
            format!(
                "condition Failed=True reason={}: {}",
                cond.reason.as_deref().unwrap_or("-"),
                truncate(cond.message.as_deref().unwrap_or(""), 300)
            ),
        )
        .evidence(Source::Status, format!("status.failed={failed}"));
    out.push(f.docs(docs::JOB));
}

fn cronjob(
    ev: &WorkloadEvidence,
    c: &k8s_openapi::api::batch::v1::CronJob,
    out: &mut Vec<Finding>,
) {
    let spec = c.spec.as_ref();
    let last = c
        .status
        .as_ref()
        .and_then(|s| s.last_schedule_time.as_ref())
        .map(|t| {
            format!(
                "last scheduled {} ago",
                k8s_mcp_core::text::age(ev.now, t.0)
            )
        });
    let f = if spec.and_then(|s| s.suspend) == Some(true) {
        Finding::new("cronjob.not_scheduling", Severity::Medium, Confidence::High, "CronJob is suspended: no Jobs are created")
            .explain("spec.suspend is true, so the controller skips every scheduled run until it is unsuspended. Runs missed meanwhile are not caught up unless startingDeadlineSeconds allows it.")
            .evidence(Source::Spec, "spec.suspend=true")
            .fix("If the suspension is not intentional, set spec.suspend to false (`kubectl patch cronjob <name> -p '{\"spec\":{\"suspend\":false}}'`).")
    } else {
        let trouble: Vec<&Event> = events_with(&ev.events, CRONJOB_TROUBLE).collect();
        let Some(first) = CRONJOB_TROUBLE
            .iter()
            .find(|r| trouble.iter().any(|e| reason(e) == **r))
        else {
            return;
        };
        let fix = match *first {
            "InvalidSchedule" | "UnknownTimeZone" => {
                "Fix spec.schedule (standard 5-field cron syntax) or spec.timeZone (an IANA name such as Europe/London)."
            }
            "JobAlreadyActive" => {
                "The previous Job is still running and concurrencyPolicy is Forbid. Find out why it does not finish (see its pods), give the job template an activeDeadlineSeconds, or use concurrencyPolicy Replace."
            }
            "TooManyMissedTimes" => {
                "More than 100 start times were missed, so the controller stopped catching up. Set spec.startingDeadlineSeconds and check that kube-controller-manager is healthy and its clock is right."
            }
            _ => {
                "The controller missed start times: kube-controller-manager was down or overloaded, or startingDeadlineSeconds is shorter than its delay. Check the control plane and raise startingDeadlineSeconds."
            }
        };
        let mut f = Finding::new(
            "cronjob.not_scheduling",
            Severity::High,
            Confidence::High,
            "CronJob is not starting Jobs on schedule",
        )
        .explain("The CronJob controller reports that scheduled runs are being skipped.")
        .fix(fix);
        for e in trouble.iter().take(3) {
            f = f.evidence(Source::Event, quote_event(e, ev.now));
        }
        if let Some(policy) = spec.and_then(|s| s.concurrency_policy.as_deref()) {
            f = f.evidence(Source::Spec, format!("spec.concurrencyPolicy={policy}"));
        }
        f
    };
    let f = match last {
        Some(l) => f.evidence(Source::Status, l),
        None => f,
    };
    out.push(f.docs(docs::CRONJOB));
}

fn rollout(ev: &WorkloadEvidence, kind: &str, name: &str, ns: &str, out: &mut Vec<Finding>) {
    let counts = replicas(&ev.workload);
    if let Workload::Deployment(d) = &ev.workload
        && let Some(c) = d
            .status
            .as_ref()
            .and_then(|s| s.conditions.as_ref())
            .into_iter()
            .flatten()
            .find(|c| {
                c.type_ == "Progressing"
                    && c.status == "False"
                    && c.reason.as_deref() == Some("ProgressDeadlineExceeded")
            })
    {
        let mut f = Finding::new("workload.rollout.stuck", Severity::High, Confidence::High, format!("rollout of Deployment {name} is stuck (progress deadline exceeded)"))
            .explain("The newest ReplicaSet's pods did not become available within spec.progressDeadlineSeconds. The rollout halts; the pod findings show why the new pods fail.")
            .evidence(Source::Status, format!("condition Progressing=False reason=ProgressDeadlineExceeded: {}", truncate(c.message.as_deref().unwrap_or(""), 300)))
            .fix(format!("Fix what the pod findings report, or roll back to the last working revision (`kubectl rollout undo deployment/{name} -n {ns}`)."))
            .docs(docs::DEPLOYMENT);
        if let Some((desired, available)) = counts {
            f = f.evidence(Source::Status, replica_counts(ev, desired, available));
        }
        // The stuck rollout already explains the missing replicas: one finding per cause.
        out.push(with_pods_next(f, &ev.workload, ns));
    } else if let Some((desired, available)) = counts
        && available < desired
    {
        let f = Finding::new("workload.replicas.unavailable", Severity::High, Confidence::High, format!("{kind} {name} has {available}/{desired} replicas available"))
            .explain("Some desired pods are missing or not ready. This is a symptom: the pod and creation findings show the cause.")
            .evidence(Source::Status, replica_counts(ev, desired, available))
            .fix("Fix the root cause reported by the other findings. If there are none, the pods may still be starting (minReadySeconds, slow readiness) or were never created (look for FailedCreate events).")
            .docs(docs::DEPLOYMENT);
        out.push(with_pods_next(f, &ev.workload, ns));
    }
    let Some((desired, _)) = counts else {
        return;
    };
    let scaled = ev
        .hpa
        .as_ref()
        .and_then(|h| h.spec.as_ref())
        .is_some_and(|s| s.min_replicas.unwrap_or(1) > 1);
    if desired == 1
        && !scaled
        && matches!(
            ev.workload,
            Workload::Deployment(_) | Workload::StatefulSet(_)
        )
    {
        out.push(
            Finding::new("workload.single_replica", Severity::Low, Confidence::High, format!("{kind} {name} runs a single replica"))
                .explain("With one replica, any restart, rollout or node drain takes the workload down.")
                .evidence(Source::Spec, "spec.replicas=1")
                .fix("If it must stay available, run at least 2 replicas with a PodDisruptionBudget and spread them across nodes (topologySpreadConstraints).")
                .docs(docs::DEPLOYMENT),
        );
    }
}

fn kind_meta(w: &Workload) -> (&'static str, &ObjectMeta) {
    match w {
        Workload::Deployment(o) => ("Deployment", &o.metadata),
        Workload::StatefulSet(o) => ("StatefulSet", &o.metadata),
        Workload::DaemonSet(o) => ("DaemonSet", &o.metadata),
        Workload::ReplicaSet(o) => ("ReplicaSet", &o.metadata),
        Workload::Job(o) => ("Job", &o.metadata),
        Workload::CronJob(o) => ("CronJob", &o.metadata),
    }
}

/// (desired, available) replicas for workloads that keep pods running.
fn replicas(w: &Workload) -> Option<(i32, i32)> {
    match w {
        Workload::Deployment(d) => Some((
            d.spec.as_ref()?.replicas.unwrap_or(1),
            d.status
                .as_ref()
                .and_then(|s| s.available_replicas)
                .unwrap_or(0),
        )),
        Workload::StatefulSet(s) => Some((
            s.spec.as_ref()?.replicas.unwrap_or(1),
            s.status
                .as_ref()
                .and_then(|s| s.available_replicas)
                .unwrap_or(0),
        )),
        Workload::ReplicaSet(r) => Some((
            r.spec.as_ref()?.replicas.unwrap_or(1),
            r.status
                .as_ref()
                .and_then(|s| s.available_replicas)
                .unwrap_or(0),
        )),
        Workload::DaemonSet(d) => {
            let s = d.status.as_ref()?;
            Some((s.desired_number_scheduled, s.number_available.unwrap_or(0)))
        }
        Workload::Job(_) | Workload::CronJob(_) => None,
    }
}

/// `desired=N available=M`, plus `(pods seen: K)` when the pods were counted.
fn replica_counts(ev: &WorkloadEvidence, desired: i32, available: i32) -> String {
    match ev.pod_count {
        Some(n) => format!("desired={desired} available={available} (pods seen: {n})"),
        None => format!("desired={desired} available={available}"),
    }
}

/// Suggest listing the workload's pods, when it has a label selector.
fn with_pods_next(f: Finding, w: &Workload, ns: &str) -> Finding {
    match selector(w) {
        Some(sel) => f.next(
            "list_resources",
            json!({"kind": "Pod", "namespace": ns, "label_selector": sel}),
            "see the workload's pods and their status",
        ),
        None => f,
    }
}

/// `matchLabels` of the pod selector as a label selector string.
fn selector(w: &Workload) -> Option<String> {
    let sel: &LabelSelector = match w {
        Workload::Deployment(d) => &d.spec.as_ref()?.selector,
        Workload::StatefulSet(s) => &s.spec.as_ref()?.selector,
        Workload::ReplicaSet(r) => &r.spec.as_ref()?.selector,
        Workload::DaemonSet(d) => &d.spec.as_ref()?.selector,
        Workload::Job(_) | Workload::CronJob(_) => return None,
    };
    let labels: Vec<String> = sel
        .match_labels
        .iter()
        .flatten()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    (!labels.is_empty()).then(|| labels.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::workload_fixture;

    fn run(ev: &WorkloadEvidence) -> Vec<Finding> {
        let mut out = Vec::new();
        check(ev, &mut out);
        out
    }

    fn ids(ev: &WorkloadEvidence) -> Vec<String> {
        run(ev).into_iter().map(|f| f.id).collect()
    }

    #[test]
    fn quota_exceeded_quotes_used_and_hard() {
        let out = run(&workload_fixture("workloads/quota-exceeded.yaml"));
        let got: Vec<_> = out.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(got, ["pod.pending.quota", "workload.replicas.unavailable"]);
        let q = &out[0];
        assert!(q.title.contains("\"pods-quota\""), "{}", q.title);
        assert!(
            q.evidence
                .iter()
                .any(|e| e.text == "ResourceQuota pods-quota pods: used 1 / hard 1")
        );
        assert_eq!(q.object.as_ref().unwrap().kind, "Deployment");
    }

    #[test]
    fn create_failures_by_message() {
        let base = workload_fixture("workloads/webhook-denied.yaml");
        assert_eq!(ids(&base)[0], "workload.create_failed");
        assert!(
            run(&base)[0]
                .title
                .contains("\"require-labels.kyverno.svc\"")
        );
        let cases = [
            (
                "pods \"api-6d9f-\" is forbidden: violates PodSecurity \"restricted:latest\": allowPrivilegeEscalation != false (container \"api\" must set securityContext.allowPrivilegeEscalation=false)",
                "workload.create_failed",
                "level restricted",
            ),
            (
                "pods \"api-6d9f-\" is forbidden: error looking up service account shop/api-sa: serviceaccount \"api-sa\" not found",
                "pod.config.missing_serviceaccount",
                "\"api-sa\"",
            ),
            (
                "pods \"api-6d9f-\" is forbidden: maximum cpu usage per Container is 1, but limit is 2",
                "workload.create_failed",
                "LimitRange",
            ),
            (
                "Internal error occurred: failed calling webhook \"mutate.istio.io\": failed to call webhook: Post \"https://istiod.istio-system.svc:443/inject\": dial tcp 10.96.4.2:443: connect: connection refused",
                "workload.create_failed",
                "cannot be reached",
            ),
            (
                "pods \"api-6d9f-\" is forbidden: failed quota: compute: must specify limits.cpu for: api",
                "pod.pending.quota",
                "do not set resource",
            ),
        ];
        for (message, id, title) in cases {
            let mut ev = base.clone();
            ev.events[0].message = Some(message.into());
            let f = &run(&ev)[0];
            assert_eq!(f.id, id, "{message}");
            assert!(f.title.contains(title), "{}", f.title);
        }
    }

    #[test]
    fn stuck_rollout_is_one_high_finding_with_replica_counts() {
        let out = run(&workload_fixture("workloads/rollout-stuck.yaml"));
        let got: Vec<_> = out.iter().map(|f| (f.id.as_str(), f.severity)).collect();
        assert_eq!(got, [("workload.rollout.stuck", Severity::High)]);
        assert!(
            out[0]
                .evidence
                .iter()
                .any(|e| e.text.starts_with("desired=")),
            "{:?}",
            out[0].evidence
        );
        assert_eq!(out[0].next[0].args["label_selector"], "app=api");
    }

    #[test]
    fn failed_jobs() {
        let ev = workload_fixture("workloads/job-backoff.yaml");
        let out = run(&ev);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "job.backoff_limit");
        assert!(
            out[0].title.contains("failed 4 times (backoffLimit 3)"),
            "{}",
            out[0].title
        );

        let mut ev = ev;
        let Workload::Job(j) = &mut ev.workload else {
            unreachable!()
        };
        j.status.as_mut().unwrap().conditions.as_mut().unwrap()[0].reason =
            Some("DeadlineExceeded".into());
        assert_eq!(ids(&ev), ["job.deadline_exceeded"]);
    }

    #[test]
    fn cronjobs() {
        let out = run(&workload_fixture("workloads/cronjob-suspended.yaml"));
        assert_eq!(out.len(), 1);
        assert_eq!(
            (out[0].id.as_str(), out[0].severity),
            ("cronjob.not_scheduling", Severity::Medium)
        );

        let out = run(&workload_fixture("workloads/cronjob-forbid.yaml"));
        assert_eq!(out.len(), 1);
        assert_eq!(
            (out[0].id.as_str(), out[0].severity),
            ("cronjob.not_scheduling", Severity::High)
        );
        assert!(out[0].fix.contains("concurrencyPolicy"));
    }

    #[test]
    fn single_replica_is_a_low_hint_only() {
        let out = run(&workload_fixture("workloads/statefulset-single.yaml"));
        assert_eq!(out.len(), 1);
        assert_eq!(
            (out[0].id.as_str(), out[0].severity),
            ("workload.single_replica", Severity::Low)
        );
    }

    #[test]
    fn healthy_workload_has_no_findings() {
        let mut ev = workload_fixture("workloads/quota-exceeded.yaml");
        ev.events.clear();
        let Workload::Deployment(d) = &mut ev.workload else {
            unreachable!()
        };
        d.status.as_mut().unwrap().available_replicas = Some(2);
        assert!(run(&ev).is_empty());
    }
}
