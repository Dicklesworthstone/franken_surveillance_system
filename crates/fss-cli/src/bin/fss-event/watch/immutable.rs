#![forbid(unsafe_code)]
//! Entry and dwell previews over sealed custody while the capture publisher remains open.

use std::time::Instant;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId};
use fss_reference::retained_source::{ImmutableRetainedSource, RetainedReadUsage};

use super::*;

pub(crate) fn run(action: &WatchAction, out: &mut impl Write) -> RunResult<()> {
    if !action.is_immutable_preview() {
        return Err(WatchError::InvalidPlan(
            "immutable watch requires an unapproved, nonincremental preview",
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
            "immutable watch requires an unapproved, nonincremental preview",
        )
        .into());
    }
    super::super::optical_health::short_only(
        action.health_screen.then_some(action.health_policy),
        action.stream_watch.is_some() || action.stream_dwell.is_some() || action.dwell.is_some(),
    )?;
    super::super::detector::check_watch_fusion_mode(action.cascade.as_ref(), true, false)?;
    // Load pinned external models and profiles before opening any retained recording.
    let inputs = match (&action.stream_watch, &action.stream_dwell) {
        (Some(_), None) => PreviewInputs::Whole(whole::Inputs::load(
            action,
            whole::Scope::Watch,
            cx,
            scalar,
        )?),
        (None, Some(_)) => PreviewInputs::Whole(whole::Inputs::load(
            action,
            whole::Scope::Dwell,
            cx,
            scalar,
        )?),
        (None, None) => {
            if action.health_screen && action.dwell.is_some() {
                return Err(WatchError::InvalidPlan(
                    "short dwell sensor-health screening is unsupported",
                )
                .into());
            }
            let (profile, package) = load_short_inputs(action, cx, scalar)?;
            PreviewInputs::Short { profile, package }
        }
        _ => return Err(WatchError::InvalidPlan("choose one whole-recording analysis").into()),
    };
    let source =
        ImmutableRetainedSource::open_cancellable(root, action.read_limits, cx, cancelled)?;
    if source.site_lineage() != action.site {
        return Err(WatchError::InvalidPlan("retained deployment site lineage mismatch").into());
    }
    let json = match inputs {
        PreviewInputs::Whole(inputs) => {
            if let Some(limits) = &action.stream_watch {
                let (report, fusion) = inputs.watch(action, &source, limits, cx, scalar)?;
                let json = whole::render_watch(
                    action,
                    &report,
                    source.current_anchor().commit_sequence,
                    None,
                    fusion.as_ref(),
                )?;
                // Diagnostic previews remain readable when health blocks publication.
                // Fusion and the publishing owner retain their stricter health gates.
                report.revalidate_preview_source(&source, cx)?;
                json
            } else {
                let limits = action.stream_dwell.as_ref().ok_or(WatchError::InvalidPlan(
                    "whole-recording dwell limits are missing",
                ))?;
                let (report, fusion) = inputs.dwell(action, &source, limits, cx, scalar)?;
                let json = whole::render_dwell(
                    action,
                    &report,
                    source.current_anchor().commit_sequence,
                    None,
                    fusion.as_ref(),
                )?;
                report.revalidate_preview_source(&source, cx)?;
                json
            }
        }
        PreviewInputs::Short { profile, package } => {
            let mut cascade = short_cascade(action, package.as_ref(), scalar)?;
            let plan = short_plan(action, &source, cx)?;
            if let Some(rule) = action.dwell {
                let report = DwellReport::analyze(
                    &source,
                    &plan,
                    rule,
                    &action.limits,
                    cascade.as_mut(),
                    action.options,
                    cx,
                )?;
                let fusion = match (&profile, cascade.as_ref()) {
                    (Some(profile), Some(cascade)) => Some(EventFusionReport::dwell(
                        &report, cascade, profile, &source, cx,
                    )?),
                    (None, _) => None,
                    _ => return Err(EventFusionError::Scope.into()),
                };
                let json = render_short_dwell(
                    action,
                    &report,
                    source.current_anchor().commit_sequence,
                    fusion.as_ref(),
                )?;
                report.revalidate_derived_source(&source, cx)?;
                json
            } else {
                let report = WatchReport::analyze_with_health(
                    &source,
                    &plan,
                    &action.limits,
                    cascade.as_mut(),
                    action.options,
                    action.health_screen.then_some(action.health_policy),
                    cx,
                )?;
                let fusion = match (&profile, cascade.as_ref()) {
                    (Some(profile), Some(cascade)) => Some(EventFusionReport::watch(
                        &report, cascade, profile, &source, cx,
                    )?),
                    (None, _) => None,
                    _ => return Err(EventFusionError::Scope.into()),
                };
                let json = render_short_watch(
                    action,
                    &report,
                    &report,
                    source.current_anchor().commit_sequence,
                    fusion.as_ref(),
                )?;
                report.revalidate_derived_source(&source, cx)?;
                json
            }
        }
    };
    let json = format!("{json}\n");
    if json.len() > super::super::MAX_ANALYSIS_REPORT_BYTES {
        return Err(WatchError::Limit.into());
    }
    // Revalidate every source object actually read, including quiet frames and diagnostic
    // support. Metadata, source reads and all final checks share this owner's original allowance.
    cx.checkpoint("watch_preview:delivery")?;
    source.revalidate_snapshot_metadata()?;
    source.revalidate()?;
    if let Some(path) = &action.report_out {
        export(path, json.as_bytes(), root, cx)?;
    }
    out.write_all(json.as_bytes())?;
    Ok(source.usage())
}

enum PreviewInputs {
    Short {
        profile: Option<EventFusionProfile>,
        package: Option<RgbDetectorPackage>,
    },
    Whole(whole::Inputs),
}

#[cfg(test)]
#[path = "immutable_tests.rs"]
mod tests;
