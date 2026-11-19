# 39 Pod bypasses cluster DNS

The pod sets `dnsPolicy: Default`, so it resolves through the node's resolv.conf instead of
kube-dns, and every lookup of a `.svc.cluster.local` name fails (logged as Go's `no such
host`).

Expected: `dns.pod_bypasses_cluster_dns` ranked above the `dns.app_resolution_errors` symptom.
