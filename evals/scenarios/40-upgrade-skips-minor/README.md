# 40 Upgrade target skips minor versions

The target 1.40 is more than one minor version ahead of the control plane (1.34 or 1.37 in CI),
and the control plane upgrades one minor at a time.

Expected: `upgrade.target_skips_minor`, listing the intermediate steps.
