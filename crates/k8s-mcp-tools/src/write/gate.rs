//! The one way to a request that changes the cluster: a [`Mode`] is a dry run unless
//! [`confirmed`] checked the plan's token. Write tools live outside this module, so they cannot
//! build an executing `Mode` themselves (v0.4 AC 2).

use k8s_mcp_core::Result;
use k8s_mcp_core::confirm::{Binding, Confirmer};
use kube::api::PatchParams;

/// Field manager of every k8s-mcp write (server-side apply, patches).
pub const MANAGER: &str = "k8s-mcp";

/// Whether write requests are server-side dry runs (`dryRun=All`).
#[derive(Clone, Copy, Debug)]
pub struct Mode {
    dry_run: bool,
}

impl Mode {
    /// A plan: every request is a dry run.
    pub const PLAN: Self = Self { dry_run: true };

    /// Parameters for a patch.
    pub fn patch(self) -> PatchParams {
        let p = PatchParams {
            field_manager: Some(MANAGER.into()),
            ..PatchParams::default()
        };
        if self.dry_run { p.dry_run() } else { p }
    }
}

/// An executing mode, only for the token of a plan of exactly this change.
pub fn confirmed(
    confirmer: &Confirmer,
    token: &str,
    binding: &Binding<'_>,
    now: jiff::Timestamp,
) -> Result<Mode> {
    confirmer.verify(token, binding, now)?;
    Ok(Mode { dry_run: false })
}
