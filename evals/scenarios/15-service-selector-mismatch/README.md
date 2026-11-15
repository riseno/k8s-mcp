# 15 Service selector matches no pods

The Deployment's pods are labeled `app=web-v2`, but the Service selects `app=web`.

Observed: the pod is `Running` and Ready; the Service has no endpoints.

Expected: `svc.no_matching_pods`, with the label diff `app=web-v2 (selector wants app=web)`.
