//! TODO: rules for this area (PROPOSAL §9.2).

use k8s_mcp_core::finding::{Finding, RuleMeta};

use crate::evidence::NodeEvidence;

/// Rules emitted by this module.
pub const RULES: &[RuleMeta] = &[];

/// Run the checks.
pub fn check(_ev: &NodeEvidence, _out: &mut Vec<Finding>) {}
