//! Fuzzing (v1.0 security review): the parsers and the pod rules never panic on cluster text,
//! whatever it says.

use std::collections::BTreeMap;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, LabelSelectorRequirement};
use proptest::prelude::*;

use crate::parse::failed_scheduling;
use crate::rules::config::parse_issue;
use crate::rules::upgrade::requested_deprecated_apis;
use crate::rules::{parse_version, selector_matches};
use crate::test_support::pod_fixture;

const WAITING: &[&str] = &[
    "CrashLoopBackOff",
    "CreateContainerConfigError",
    "CreateContainerError",
    "RunContainerError",
    "ImagePullBackOff",
    "ErrImagePull",
    "InvalidImageName",
    "ContainerCreating",
];
const TERMINATED: &[&str] = &[
    "Error",
    "OOMKilled",
    "StartError",
    "ContainerCannotRun",
    "Completed",
];
const EVENTS: &[&str] = &[
    "Failed",
    "FailedMount",
    "Unhealthy",
    "Killing",
    "FailedScheduling",
    "FailedCreatePodSandBox",
    "BackOff",
];

proptest! {
    #[test]
    fn parsers_never_panic(s in any::<String>()) {
        let _ = failed_scheduling(&s);
        let _ = parse_issue(&s);
        let _ = parse_version(&s);
        let _ = requested_deprecated_apis(&s);
    }

    #[test]
    fn deprecated_api_metric_lines_never_panic(
        group in "[ -~]{0,20}", version in "[ -~]{0,10}", resource in "[ -~]{0,20}", value in "[ -~]{0,12}",
    ) {
        let line = format!(
            "apiserver_requested_deprecated_apis{{group=\"{group}\",removed_release=\"1.32\",resource=\"{resource}\",subresource=\"\",version=\"{version}\"}} {value}"
        );
        let _ = requested_deprecated_apis(&line);
    }

    /// Every container-state and event text a kubelet, runtime or app can write.
    #[test]
    fn pod_rules_never_panic_on_cluster_text(
        waiting in prop::sample::select(WAITING),
        terminated in prop::sample::select(TERMINATED),
        event in prop::sample::select(EVENTS),
        exit_code in any::<i32>(),
        restarts in 0i32..10,
        texts in prop::collection::vec(any::<String>(), 4),
        lines in prop::collection::vec(any::<String>(), 0..6),
    ) {
        let mut ev = pod_fixture("pods/crashloop-exit1.yaml");
        let st = &mut ev.pod.status.as_mut().unwrap().container_statuses.as_mut().unwrap()[0];
        st.restart_count = restarts;
        let w = st.state.as_mut().unwrap().waiting.as_mut().unwrap();
        w.reason = Some(waiting.into());
        w.message = Some(texts[0].clone());
        let t = st.last_state.as_mut().unwrap().terminated.as_mut().unwrap();
        t.reason = Some(terminated.into());
        t.exit_code = exit_code;
        t.message = Some(texts[1].clone());
        ev.events[0].reason = Some(event.into());
        ev.events[0].message = Some(texts[2].clone());
        ev.logs[0].lines = lines;
        ev.logs[0].lines.push(texts[3].clone());
        let _ = crate::diagnose_pod(&ev);
    }

    #[test]
    fn selectors_never_panic(
        operator in "[A-Za-z]{0,12}",
        key in "[ -~]{0,10}",
        values in prop::option::of(prop::collection::vec("[ -~]{0,6}", 0..3)),
        labels in prop::collection::btree_map("[ -~]{0,10}", "[ -~]{0,6}", 0..4),
    ) {
        let sel = LabelSelector {
            match_expressions: Some(vec![LabelSelectorRequirement { key, operator, values }]),
            match_labels: Some(BTreeMap::from([("app".to_owned(), "web".to_owned())])),
        };
        let _ = selector_matches(&sel, Some(&labels));
        let _ = selector_matches(&sel, None);
    }
}
