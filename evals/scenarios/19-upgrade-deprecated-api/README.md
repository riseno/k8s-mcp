# 19 Deprecated API in use (upgrade readiness)

A CRD serves `v1beta1` marked `deprecated`, and an object is created through it.

Observed: the API server's `apiserver_requested_deprecated_apis` metric lists
`eval.k8s-mcp.dev/v1beta1 widgets`, and the object's managedFields keep that apiVersion.

Expected: `upgrade.deprecated_api_in_use` (low: a CRD owner may drop the version in any
release), naming the replacement `eval.k8s-mcp.dev/v1` and the object's writer. Nothing is
removed by the next minor, so no `upgrade.removed_api_in_use`.
