#![forbid(unsafe_code)]
//! Two-camera previews over sealed custody while the capture publisher remains open.

use std::time::Instant;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId};
use fss_reference::retained_source::{ImmutableRetainedSource, RetainedReadUsage};

use super::*;

pub(crate) fn run(action: &CorroborateAction, out: &mut impl Write) -> RunResult<()> {
    if !action.is_immutable_preview() {
        return Err(CorroborationError::InvalidPlan(
            "immutable corroboration requires an unapproved preview",
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
    action: &CorroborateAction,
    root: &Path,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
    cancelled: &(dyn Fn() -> bool + Sync),
    out: &mut impl Write,
) -> RunResult<RetainedReadUsage> {
    // Repeat admission for internal callers before model, profile or source reads. No
    // immutable operation can acquire a publisher through this path.
    if !action.is_immutable_preview() {
        return Err(CorroborationError::InvalidPlan(
            "immutable corroboration requires an unapproved preview",
        )
        .into());
    }
    super::super::optical_health::short_only(action.health_screen, action.streaming.is_some())?;
    super::super::detector::check_fusion_mode(action.cascade.as_ref(), true, false)?;
    let source =
        ImmutableRetainedSource::open_cancellable(root, action.read_limits, cx, cancelled)?;
    if source.site_lineage() != action.site {
        return Err(
            CorroborationError::InvalidPlan("retained deployment site lineage mismatch").into(),
        );
    }
    let complete = if let Some(limits) = &action.streaming {
        let (report, fusion) = streaming::analyze(action, &source, limits, cx, scalar)?;
        let json = streaming::render(
            action,
            &report,
            source.current_anchor().commit_sequence,
            None,
            fusion.as_ref(),
        )?;
        // A health-degraded diagnostic is still a valid preview. Every original source and
        // capsule must remain intact; the publication gate applies only to derived advice.
        if fusion.is_some() {
            streaming::revalidate_fusion_delivery(&report, &source, cx)?;
        } else {
            report.revalidate_preview_sources(&source, cx)?;
        }
        json
    } else {
        short_preview(action, &source, cx, scalar)?
    };
    let json = format!("{complete}\n");
    if json.len() > super::super::MAX_ANALYSIS_REPORT_BYTES {
        return Err(CorroborationError::Limit.into());
    }
    // All source reads, metadata and final custody verification share the opening allowance.
    // Any refusal withholds both stdout and an optional external report.
    cx.checkpoint("corroborate_preview:delivery")?;
    source.revalidate_snapshot_metadata()?;
    source.revalidate()?;
    if let Some(path) = &action.report_out {
        export(path, json.as_bytes(), root, cx)?;
    }
    out.write_all(json.as_bytes())?;
    Ok(source.usage())
}

fn short_preview(
    action: &CorroborateAction,
    source: &dyn RetainedSource,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
) -> RunResult<String> {
    let inputs = short::ShortInputs::load(action, source, cx, scalar)?;
    let provenance = retained_provenance(&inputs.sources, inputs.calibration);
    let visibility = inputs.visibility(action);
    let mut cascade = inputs.cascade(action, scalar)?;
    let report = CorroborationReport::analyze_with_dependencies(
        source,
        &action.plan,
        &action.limits,
        cascade.as_mut(),
        &visibility,
        &provenance,
        &inputs.covariances,
        action.recovery,
        action.health_screen,
        &action.dependencies,
        cx,
    )?;
    let mut guard_budget = fss_geometry::WorkBudget::new(
        fss_reference::ingest::calibration_coverage::MAX_CALIBRATION_COVERAGE_WORK,
    );
    let guard = calibration_coverage::assess(
        action,
        inputs.calibration_record.as_ref(),
        inputs.calibration,
        source,
        &report,
        cx,
        &mut guard_budget,
    )?;
    let fusion = match (&inputs.fusion_profile, cascade.as_ref()) {
        (Some(profile), Some(cascade)) => Some(match &guard {
            Some(guard) => guard.fuse(&report, cascade, profile, source, cx)?,
            None => EventFusionReport::corroborate(&report, cascade, profile, source, cx)?,
        }),
        (None, _) => None,
        _ => return Err(EventFusionError::Scope.into()),
    };
    let json = inputs.render(
        action,
        &report,
        &report,
        guard.as_ref(),
        source.current_anchor().commit_sequence,
        fusion.as_ref(),
    )?;
    // Include every original and supporting capsule in final custody, even when the
    // analysis was quiet, health-degraded or tolerant of a decode refusal. Budget and
    // cancellation cannot turn failed verification into a successful report prefix.
    report.revalidate_derived_sources(source, cx)?;
    if let Some(guard) = &guard {
        guard.revalidate(source, cx)?;
    }
    Ok(json)
}

#[cfg(test)]
#[path = "immutable_tests.rs"]
mod tests;
