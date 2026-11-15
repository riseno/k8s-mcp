//! PersistentVolumeClaims (PROPOSAL §9.2, v0.2): why a claim stays Pending (StorageClass,
//! provisioning, WaitForFirstConsumer) and why its volume cannot attach (Multi-Attach, per-node
//! attach limits).

use std::sync::LazyLock;

use k8s_mcp_core::finding::{Confidence, Finding, RuleMeta, Severity, Source};
use k8s_mcp_core::text::age;
use k8s_openapi::api::core::v1::Event;
use k8s_openapi::api::storage::v1::StorageClass;
use regex::Regex;
use serde_json::json;

use super::{docs, msg, phase, pod_ref, re, reason, resource_args};
use crate::evidence::PvcEvidence;

/// Rules emitted by this module.
pub const RULES: &[RuleMeta] = &[
    RuleMeta {
        id: "pvc.pending.no_storageclass",
        title: "The claim's StorageClass does not exist (or there is no default)",
        docs: docs::STORAGE_CLASS,
    },
    RuleMeta {
        id: "pvc.pending.provisioning_failed",
        title: "The provisioner failed (or never tried) to create the volume",
        docs: docs::DYNAMIC_PROVISIONING,
    },
    RuleMeta {
        id: "pvc.pending.wffc_waiting",
        title: "The claim waits for a pod to be scheduled (WaitForFirstConsumer)",
        docs: docs::STORAGE_CLASS,
    },
    RuleMeta {
        id: "pvc.attach.multi_attach",
        title: "The volume is still attached to another node (Multi-Attach)",
        docs: docs::PV,
    },
    RuleMeta {
        id: "pvc.attach.limit",
        title: "Nodes have reached their volume attach limit",
        docs: docs::VOLUME_LIMITS,
    },
];

/// A claim may wait this long for an external provisioner before it is reported.
const PROVISION_GRACE_SECS: i64 = 300;
const DEFAULT_CLASS: &[&str] = &[
    "storageclass.kubernetes.io/is-default-class",
    "storageclass.beta.kubernetes.io/is-default-class",
];

static ATTACH_LIMIT: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)exceed max volume count|max(imum)? (number of )?(volume )?attach|attachvolumelimitexceeded|volume attach limit",
    )
});

/// Check one claim.
pub fn check(ev: &PvcEvidence, out: &mut Vec<Finding>) {
    let name = ev.pvc.metadata.name.as_deref().unwrap_or("");
    let ns = ev.pvc.metadata.namespace.as_deref().unwrap_or("default");
    let pending = ev.pvc.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Pending");
    // A claim no pod uses blocks nothing yet.
    let severity = if ev.pods.is_empty() {
        Severity::High
    } else {
        Severity::Critical
    };
    if pending {
        if let Some(f) = no_storage_class(ev, name, severity) {
            out.push(f);
        } else if let Some(f) = provisioning(ev, name, ns, severity) {
            out.push(f);
        } else if let Some(f) = wait_for_consumer(ev, name, ns) {
            out.push(f);
        }
    }
    attach(ev, name, ns, out);
}

fn spec_class(ev: &PvcEvidence) -> Option<&str> {
    ev.pvc.spec.as_ref()?.storage_class_name.as_deref()
}

fn is_default(sc: &StorageClass) -> bool {
    sc.metadata.annotations.as_ref().is_some_and(|a| {
        DEFAULT_CLASS
            .iter()
            .any(|k| a.get(*k).is_some_and(|v| v == "true"))
    })
}

/// The StorageClass that provisions the claim: the named one, else the default.
pub fn storage_class(ev: &PvcEvidence) -> Option<&StorageClass> {
    let classes = ev.storage_classes.as_ref()?;
    match spec_class(ev) {
        Some(n) => classes
            .iter()
            .find(|c| c.metadata.name.as_deref() == Some(n)),
        None => classes.iter().find(|c| is_default(c)),
    }
}

fn no_storage_class(ev: &PvcEvidence, name: &str, severity: Severity) -> Option<Finding> {
    let classes = ev.storage_classes.as_ref()?;
    // A volumeName or an empty class means static binding to an existing PV.
    let spec = ev.pvc.spec.as_ref()?;
    if spec.volume_name.is_some() || spec_class(ev) == Some("") || storage_class(ev).is_some() {
        return None;
    }
    let existing = classes
        .iter()
        .map(|c| {
            let n = c.metadata.name.as_deref().unwrap_or("");
            if is_default(c) {
                format!("{n} (default)")
            } else {
                n.to_owned()
            }
        })
        .collect::<Vec<_>>();
    let existing = if existing.is_empty() {
        "the cluster has no StorageClasses".to_owned()
    } else {
        format!("StorageClasses: {}", existing.join(", "))
    };
    let (title, explain) = match spec_class(ev) {
        Some(c) => (
            format!("PVC {name} names StorageClass {c:?}, which does not exist"),
            "No StorageClass has this name, so nothing provisions a volume and the claim stays Pending.",
        ),
        None => (
            format!("PVC {name} names no StorageClass and the cluster has no default"),
            "The claim relies on the default StorageClass, but no class is marked default, so nothing provisions a volume and the claim stays Pending.",
        ),
    };
    Some(
        Finding::new("pvc.pending.no_storageclass", severity, Confidence::High, title)
            .explain(explain)
            .evidence(
                Source::Spec,
                format!("storageClassName: {}", spec_class(ev).unwrap_or("(unset)")),
            )
            .evidence(Source::Related, existing)
            .docs(docs::STORAGE_CLASS)
            .fix("Set storageClassName to an existing class (a PVC's class cannot be changed after creation: recreate the claim, or the StatefulSet's volumeClaimTemplate), or create the missing StorageClass, or mark one as default with the annotation storageclass.kubernetes.io/is-default-class=true.")
            .next(
                "list_resources",
                json!({"kind": "StorageClass"}),
                "see the StorageClasses",
            ),
    )
}

fn warnings<'a>(events: &'a [Event], reasons: &[&str]) -> Vec<&'a Event> {
    events
        .iter()
        .filter(|e| e.type_.as_deref() == Some("Warning") && reasons.contains(&reason(e)))
        .collect()
}

fn provisioning(ev: &PvcEvidence, name: &str, ns: &str, severity: Severity) -> Option<Finding> {
    let failed = warnings(&ev.events, &["ProvisioningFailed"]);
    let provisioner = storage_class(ev).map_or("its provisioner", |c| c.provisioner.as_str());
    let f = if failed.is_empty() {
        // Waiting on an external provisioner for too long: it is likely not running.
        let waiting = ev
            .events
            .iter()
            .any(|e| reason(e) == "ExternalProvisioning");
        let created = ev.pvc.metadata.creation_timestamp.as_ref()?.0;
        if !waiting || ev.now.duration_since(created).as_secs() < PROVISION_GRACE_SECS {
            return None;
        }
        Finding::new(
            "pvc.pending.provisioning_failed",
            severity,
            Confidence::Medium,
            format!("PVC {name} has waited {} for provisioner {provisioner:?}", age(ev.now, created)),
        )
        .explain("The claim is waiting for an external (CSI) provisioner that has not created a volume or reported an error. The provisioner's controller is usually not running, or not installed.")
        .fix(format!("Check that the CSI driver for {provisioner:?} is installed and its controller pods are running (often in kube-system), and look at their logs."))
    } else {
        let mut f = Finding::new(
            "pvc.pending.provisioning_failed",
            severity,
            Confidence::High,
            format!("Provisioning a volume for PVC {name} failed"),
        )
        .explain(format!("{provisioner:?} tried to create the volume and failed; the claim stays Pending until it succeeds."))
        .fix("Fix the cause in the event: provisioner credentials or cloud permissions, quota, an unsupported parameter in the StorageClass, or a zone with no capacity. The provisioner retries on its own.");
        for e in failed.iter().take(2) {
            f = f.evidence(Source::Event, format!("{}: {}", reason(e), msg(e)));
        }
        f
    };
    Some(f.docs(docs::DYNAMIC_PROVISIONING).next(
        "list_events",
        json!({"namespace": ns, "involved_kind": "PersistentVolumeClaim", "involved_name": name, "types": ["Warning", "Normal"]}),
        "see the provisioning events",
    ))
}

fn wait_for_consumer(ev: &PvcEvidence, name: &str, ns: &str) -> Option<Finding> {
    let class = storage_class(ev)?;
    if class.volume_binding_mode.as_deref() != Some("WaitForFirstConsumer") {
        return None;
    }
    let class_name = class.metadata.name.as_deref().unwrap_or("");
    let f = match ev.pods.iter().find(|p| phase(p) == "Pending") {
        None if ev.pods.is_empty() => Finding::new(
            "pvc.pending.wffc_waiting",
            Severity::Info,
            Confidence::High,
            format!("PVC {name} waits for its first pod (StorageClass {class_name} binds on first use)"),
        )
        .explain("With volumeBindingMode WaitForFirstConsumer the volume is created only once a pod using the claim is scheduled, so a Pending claim with no pod is normal.")
        .fix("Nothing to fix unless a pod should already use this claim: then check that pod's claimName."),
        None => return None,
        Some(pod) => {
            let (pod_name, _) = pod_ref(pod);
            Finding::new(
                "pvc.pending.wffc_waiting",
                Severity::Medium,
                Confidence::Medium,
                format!("PVC {name} waits for pod {pod_name} to be scheduled"),
            )
            .explain(format!("StorageClass {class_name} binds on first use, so the volume is created only after the scheduler places the pod; the pod is still Pending, so the claim is a symptom, not the cause."))
            .fix("Find out why the pod is not scheduled (diagnose_pod): the volume follows the pod's node and zone.")
            .next("diagnose_pod", json!({"name": pod_name, "namespace": ns}), "find out why the pod is not scheduled")
        }
    };
    Some(f.docs(docs::STORAGE_CLASS).evidence(
        Source::Related,
        format!(
            "StorageClass {class_name}: volumeBindingMode=WaitForFirstConsumer, provisioner={}",
            class.provisioner
        ),
    ))
}

fn attach(ev: &PvcEvidence, name: &str, ns: &str, out: &mut Vec<Finding>) {
    let volume = ev.pvc.spec.as_ref().and_then(|s| s.volume_name.as_deref());
    // Pod events about this claim's volume (any attach event when the volume is unknown).
    let about = |e: &&Event| volume.is_none_or(|v| msg(e).contains(v));
    let multi: Vec<&Event> = warnings(&ev.pod_events, &["FailedAttachVolume"])
        .into_iter()
        .filter(|e| msg(e).contains("Multi-Attach error"))
        .filter(about)
        .collect();
    if !multi.is_empty() {
        let mut f = Finding::new(
            "pvc.attach.multi_attach",
            Severity::High,
            Confidence::High,
            format!("The volume of PVC {name} is still attached to another node"),
        )
        .explain("The volume is ReadWriteOnce and attached to a node where another pod used it, so it cannot attach where the new pod runs. This happens when a rolling update or rescheduling starts the new pod before the old one released the volume, or when the old node is down.")
        .docs(docs::PV)
        .fix("Let the old pod finish terminating (or delete it if its node is gone; the attach-detach controller force-detaches after about 6 minutes). For Deployments with a ReadWriteOnce claim use strategy Recreate, or a StatefulSet; use ReadWriteMany storage if pods must share the volume.");
        for e in multi.iter().take(2) {
            f = f.evidence(Source::Event, msg(e).to_owned());
        }
        out.push(f.next(
            "get_resource",
            resource_args("PersistentVolumeClaim", name, ns),
            "see which pods use the claim",
        ));
    }
    let limit: Vec<&Event> = warnings(&ev.pod_events, &["FailedAttachVolume", "FailedScheduling"])
        .into_iter()
        .filter(|e| ATTACH_LIMIT.is_match(msg(e)))
        .collect();
    if !limit.is_empty() {
        let mut f = Finding::new(
            "pvc.attach.limit",
            Severity::High,
            Confidence::Medium,
            format!("Nodes cannot attach more volumes for the pods using PVC {name}"),
        )
        .explain("Each node type supports a limited number of attached volumes (for example, cloud instance attachment limits). The nodes that could run the pod are full.")
        .docs(docs::VOLUME_LIMITS)
        .fix("Spread volume-heavy pods across more nodes (topology spread or anti-affinity), use node types with a higher attach limit, or reduce volumes per pod. Cluster autoscalers add nodes only when the limit is known to them.");
        for e in limit.iter().take(2) {
            f = f.evidence(Source::Event, format!("{}: {}", reason(e), msg(e)));
        }
        out.push(f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::pvc_fixture;

    fn run(fixture: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        check(&pvc_fixture(fixture), &mut out);
        out
    }

    fn ids(fixture: &str) -> Vec<String> {
        run(fixture).into_iter().map(|f| f.id).collect()
    }

    #[test]
    fn missing_named_class_is_critical_when_a_pod_waits() {
        let f = &run("pvcs/missing-class.yaml")[0];
        assert_eq!(
            (f.id.as_str(), f.severity),
            ("pvc.pending.no_storageclass", Severity::Critical)
        );
        assert!(f.title.contains("\"fast-ssd\""), "{}", f.title);
        assert_eq!(f.evidence[1].text, "StorageClasses: standard (default)");
    }

    #[test]
    fn no_default_class_is_reported_for_classless_claims() {
        let out = run("pvcs/no-default-class.yaml");
        assert_eq!(out.len(), 1);
        assert!(out[0].title.contains("no default"), "{}", out[0].title);
        assert_eq!(out[0].severity, Severity::High, "no pod uses it");
    }

    #[test]
    fn provisioning_failure_quotes_the_event() {
        let f = &run("pvcs/provisioning-failed.yaml")[0];
        assert_eq!(
            (f.id.as_str(), f.confidence),
            ("pvc.pending.provisioning_failed", Confidence::High)
        );
        assert_eq!(f.evidence[0].source, Source::Event);
        assert!(
            f.explanation.contains("ebs.csi.aws.com"),
            "{}",
            f.explanation
        );
    }

    #[test]
    fn a_silent_external_provisioner_is_medium_after_five_minutes() {
        let mut ev = pvc_fixture("pvcs/provisioning-failed.yaml");
        for e in &mut ev.events {
            e.type_ = Some("Normal".into());
            e.reason = Some("ExternalProvisioning".into());
        }
        let mut out = Vec::new();
        check(&ev, &mut out);
        assert_eq!(out[0].confidence, Confidence::Medium);
        assert!(out[0].title.contains("has waited 20m"), "{}", out[0].title);
    }

    #[test]
    fn wait_for_first_consumer_without_pods_is_info() {
        let f = &run("pvcs/wffc-no-consumer.yaml")[0];
        assert_eq!(
            (f.id.as_str(), f.severity),
            ("pvc.pending.wffc_waiting", Severity::Info)
        );
    }

    #[test]
    fn wait_for_first_consumer_points_at_the_pending_pod() {
        let mut ev = pvc_fixture("pvcs/wffc-no-consumer.yaml");
        ev.pods = crate::test_support::pvc_fixture("pvcs/missing-class.yaml").pods;
        let mut out = Vec::new();
        check(&ev, &mut out);
        assert_eq!(out[0].severity, Severity::Medium);
        assert_eq!(out[0].next[0].tool, "diagnose_pod");
    }

    #[test]
    fn multi_attach_and_attach_limits_come_from_pod_events() {
        assert_eq!(ids("pvcs/multi-attach.yaml"), ["pvc.attach.multi_attach"]);
        assert_eq!(ids("pvcs/attach-limit.yaml"), ["pvc.attach.limit"]);
    }

    #[test]
    fn bound_claims_and_static_binding_have_no_findings() {
        assert!(ids("pvcs/healthy.yaml").is_empty());
        let mut ev = pvc_fixture("pvcs/missing-class.yaml");
        ev.pvc.spec.as_mut().unwrap().storage_class_name = Some(String::new());
        let mut out = Vec::new();
        check(&ev, &mut out);
        assert!(out.is_empty(), "{out:?}");
        // Unreadable StorageClasses: no claim about them.
        let mut ev = pvc_fixture("pvcs/missing-class.yaml");
        ev.storage_classes = None;
        let mut out = Vec::new();
        check(&ev, &mut out);
        assert!(out.is_empty(), "{out:?}");
    }
}
