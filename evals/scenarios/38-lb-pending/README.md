# 38 LoadBalancer pending

A `type: LoadBalancer` Service on kind, which runs no load-balancer controller: the pods are
ready, but no controller ever assigns an external address.

Expected: `svc.lb_pending` (after its 2-minute grace period), noting that no controller has
reported on the Service.
