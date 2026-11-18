//! Write tools (PROPOSAL §8.3, §12.4). Every change is two calls: a server-side dry run that
//! returns the plan and a `confirm_token`, then the same call with `dry_run: false` and that
//! token. Only [`gate::confirmed`] yields a request that is not a dry run.

mod apply;
mod drain;
mod gate;
mod node;
mod pod;
mod restart;
mod rollback;
mod scale;

use std::future::Future;

use k8s_mcp_core::confirm::Binding;
use k8s_mcp_core::envelope::Section;
use k8s_mcp_core::finding::NextCall;
use k8s_mcp_core::{Error, Result};
use serde_json::{Value, json};

pub use apply::{ApplyManifestInput, apply_manifest};
pub use drain::{DrainNodeInput, drain_node};
pub use gate::Mode;
pub use node::{NodeWriteInput, cordon_node, uncordon_node};
pub use pod::{DeletePodInput, delete_pod};
pub use restart::{RestartWorkloadInput, restart_workload};
pub use rollback::{RollbackWorkloadInput, rollback_workload};
pub use scale::{ScaleWorkloadInput, scale_workload};

use crate::common::{Scope, envelope};
use crate::{Ctx, Envelope};

/// What a write does, the same for its plan and its execution.
pub(crate) struct Change {
    /// One sentence, e.g. "restart Deployment shop/web".
    pub summary: String,
    /// The fields it changes, `path: before → after`, and its impact.
    pub lines: Vec<String>,
    /// Follow-ups once it is applied.
    pub next: Vec<NextCall>,
}

/// The canonical kind if `tool` accepts it.
pub(crate) fn writable_kind(tool: &str, kind: &str, allowed: &[&str]) -> Result<&'static str> {
    let k = crate::diagnose::workload_kind(kind)?;
    if allowed.contains(&k) {
        Ok(k)
    } else {
        Err(Error::InvalidInput(format!(
            "{tool} works on {}, not {k}",
            allowed.join(", ")
        )))
    }
}

/// Refuse `dry_run: false` without a token before any request is made.
pub(crate) fn check_confirm(tool: &str, dry_run: Option<bool>, token: Option<&str>) -> Result<()> {
    if dry_run == Some(false) && token.is_none() {
        return Err(Error::InvalidInput(format!(
            "dry_run=false needs the confirm_token of a plan. Call {tool} with dry_run=true first, show the plan to the user, and confirm with its token once they agree."
        )));
    }
    Ok(())
}

/// One write call: a plan (the default), or with `dry_run: false` and the plan's token, the
/// change. `args` is the request with defaults resolved, without `context`, `dry_run` and
/// `confirm_token`; `targets` are the objects it changes with their current resourceVersion,
/// read for this call, so a change since the plan voids the token.
pub(crate) async fn run<F, Fut>(
    ctx: &Ctx,
    sc: &Scope,
    tool: &str,
    args: Value,
    targets: &[(String, Option<String>)],
    (dry_run, token): (Option<bool>, Option<&str>),
    change: F,
) -> Result<Envelope>
where
    F: FnOnce(Mode) -> Fut,
    Fut: Future<Output = Result<Change>> + Send,
{
    let now = ctx.now();
    let binding = Binding {
        tool,
        context: &sc.target.context,
        args: &args,
        versions: targets,
    };
    if !dry_run.unwrap_or(true) {
        check_confirm(tool, dry_run, token)?;
        let mode = gate::confirmed(&ctx.confirm, token.unwrap_or_default(), &binding, now)?;
        let done = change(mode).await?;
        let mut e = envelope(sc, format!("Applied: {}.", done.summary));
        e.sections.push(Section {
            title: "CHANGED".into(),
            lines: done.lines,
            untrusted: None,
        });
        e.next = done.next;
        return Ok(e);
    }
    let planned = change(Mode::PLAN).await?;
    let token = ctx.confirm.issue(&binding, now)?;
    let mut confirm = args.clone();
    confirm["context"] = json!(sc.target.context);
    confirm["dry_run"] = json!(false);
    confirm["confirm_token"] = json!(token);
    let mut e = envelope(
        sc,
        format!(
            "Plan (server-side dry run; nothing changed): {}. Show it to the user; only if they agree, call {tool} again with dry_run=false and confirm_token {token} (valid 120 s, and only while the objects are unchanged).",
            planned.summary
        ),
    );
    e.sections.push(Section {
        title: "PLAN".into(),
        lines: planned.lines,
        untrusted: None,
    });
    e.next = vec![NextCall::new(
        tool,
        confirm,
        "apply this plan, only after the user agrees to it",
    )];
    Ok(e)
}
