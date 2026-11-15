# 17 DNS blocked by a NetworkPolicy

An egress NetworkPolicy lets the client reach only the database on 5432, so DNS (port 53)
is not allowed.

Observed: with a CNI that enforces NetworkPolicy, `nslookup` times out in the pod's logs;
the cluster DNS itself is healthy.

Expected: `dns.netpol_blocks_egress` (from the policy itself, so it does not depend on the
CNI enforcing it); `dns.app_resolution_errors` is acceptable.
