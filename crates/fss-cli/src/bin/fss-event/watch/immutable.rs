#![forbid(unsafe_code)]
//! Short entry previews over sealed custody while the capture publisher remains open.

use std::time::Instant;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId};
use fss_reference::retained_source::{ImmutableRetainedSource, RetainedReadUsage};

use super::*;

pub(crate) fn run(action: &WatchAction, out: &mut impl Write) -> RunResult<()> {
    if !action.is_immutable_preview() {
        return Err(WatchError::InvalidPlan(
            "immutable watch requires an unapproved short entry preview",
        )
        .into());
    }
    let root = std::fs::canonicalize(&action.root)?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:event-cli".into(),
        operation_id: OperationId::parse("operation:event-cli")?,
        principal: action.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".into(), "CAP-READ-MEDIA-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(action.read_limits.max_read_bytes as u64)
            .storage_operations(action.read_limits.max_read_objects as u64)
            .build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(action.site.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    let cx = ReplayCx::from_context_authority_read_only(&authority, root.clone())?;
    let scalar = ScalarExecCx::new();
    let started = Instant::now();
    let cancelled = || started.elapsed() >= super::super::retained_read::DEADLINE;
    let result = run_with(action, &root, &cx, &scalar, &cancelled, out);
    scalar.drain_and_finalize();
    cx.drain_and_finalize();
    result.map(|_| ())
}

fn run_with(
    action: &WatchAction,
    root: &Path,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
    cancelled: &(dyn Fn() -> bool + Sync),
    out: &mut impl Write,
) -> RunResult<RetainedReadUsage> {
    // Repeat admission for internal callers before model, profile or source reads. No
    // immutable operation can acquire a publisher through this path.
    if !action.is_immutable_preview() {
        return Err(WatchError::InvalidPlan(
            "immutable watch requires an unapproved short entry preview",
        )
        .into());
    }
    super::super::detector::check_watch_fusion_mode(action.cascade.as_ref(), true, false)?;
    let (profile, package) = load_short_inputs(action, cx, scalar)?;
    let mut cascade = short_cascade(action, package.as_ref(), scalar)?;
    let source =
        ImmutableRetainedSource::open_cancellable(root, action.read_limits, cx, cancelled)?;
    if source.site_lineage() != action.site {
        return Err(WatchError::InvalidPlan("retained deployment site lineage mismatch").into());
    }
    let plan = short_plan(action, &source, cx)?;
    let report = WatchReport::analyze_with_health(
        &source,
        &plan,
        &action.limits,
        cascade.as_mut(),
        action.options,
        action
            .health_screen
            .then_some(RecordedHealthPolicy::ConservativeV1),
        cx,
    )?;
    let fusion = match (&profile, cascade.as_ref()) {
        (Some(profile), Some(cascade)) => Some(EventFusionReport::watch(
            &report, cascade, profile, &source, cx,
        )?),
        (None, _) => None,
        _ => return Err(EventFusionError::Scope.into()),
    };
    let json = format!(
        "{}\n",
        render_short_watch(
            action,
            &report,
            &report,
            source.current_anchor().commit_sequence,
            fusion.as_ref(),
        )?
    );
    if json.len() > super::super::MAX_ANALYSIS_REPORT_BYTES {
        return Err(WatchError::Limit.into());
    }
    // Include every original and supporting capsule in final custody, even when the
    // analysis was quiet, health-degraded or tolerant of a decode refusal. Budget and
    // cancellation cannot turn failed verification into a successful report prefix.
    report.revalidate_derived_source(&source, cx)?;
    cx.checkpoint("watch_preview:delivery")?;
    source.revalidate_snapshot_metadata()?;
    source.revalidate()?;
    if let Some(path) = &action.report_out {
        export(path, json.as_bytes(), root, cx)?;
    }
    out.write_all(json.as_bytes())?;
    Ok(source.usage())
}

#[cfg(test)]
#[path = "immutable_tests.rs"]
mod tests;
