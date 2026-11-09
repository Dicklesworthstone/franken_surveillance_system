#![forbid(unsafe_code)]
//! Protected UTC revalidation followed by the common source-closed native acquisition loop.

use fss_geometry::WorkBudget;
use fss_object::SpoolIo;
use fss_publication::custody_audit::pinned_closure::PinnedClosureReader;

use super::super::{STAGE_QUERY_IMPORT, STAGE_QUERY_REVALIDATE, batch};
use super::*;
use crate::ReplayCx;

type Result<T> = std::result::Result<T, RtspUtcQueryImportFailure>;

fn admit(
    plan: &RtspUtcQueryImportPlan,
    authority: &dyn RtspUtcQueryImportAuthority,
    destination: &ReferenceDeployment,
    cx: &ReplayCx,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> std::result::Result<(), RtspQueryImportError> {
    if cancelled()
        || cx.checkpoint(STAGE_QUERY_IMPORT).is_err()
        || destination.root() != plan.deployment_root.as_path()
        || destination.site_lineage() != plan.settings.site.as_str()
        || !authority.permit(plan, destination)
    {
        return Err(RtspQueryImportError::Denied);
    }
    Ok(())
}

fn owners(
    reader: &PinnedClosureReader<'_>,
    plan: &RtspUtcQueryImportPlan,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
) -> std::result::Result<(), RtspQueryImportError> {
    let minimum = (plan.windows.len() as u64)
        .checked_mul(crate::ingest::rtsp_import::MAX_ORIGINAL_BYTES * 3)
        .and_then(|reads| reads.checked_add(plan.original_bytes));
    if reader.root_dir() != plan.archive_root.as_path()
        || cx.root_dir() != plan.deployment_root.as_path()
        || reader.limits() != plan.source_limits()
        || work.remaining() > plan.settings.max_work
        || minimum.is_none_or(|minimum| minimum > work.remaining())
    {
        return Err(RtspQueryImportError::Invalid(
            "UTC query import owner or allowance binding",
        ));
    }
    work.charge(0).map_err(|_| RtspQueryImportError::Denied)
}

fn selected_receipts(
    plan: &RtspUtcQueryImportPlan,
    imports: Vec<RtspImportReceipt>,
) -> Vec<RtspUtcQueryImportedWindow> {
    plan.windows
        .iter()
        .zip(imports)
        .map(|(window, import)| RtspUtcQueryImportedWindow {
            selection: window.clone(),
            import,
        })
        .collect()
}

/// Acquire every selected whole native candidate with its original independent source scope.
///
/// Exact protected revalidation precedes all publication. One caller-owned pinned reader and
/// one WorkBudget cover the entire selection; no archive writer/recovery owner is opened.
/// Native source verification does not promote conditional clock metadata to camera capture
/// time. Every unknown-clock row remains in the plan, receipt and aggregate bounds.
#[allow(clippy::too_many_arguments)]
pub fn import_rtsp_utc_query_pinned(
    io: &dyn SpoolIo,
    reader: &mut PinnedClosureReader<'_>,
    destination: &mut ReferenceDeployment,
    plan: &RtspUtcQueryImportPlan,
    authority: &dyn RtspUtcQueryImportAuthority,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<RtspUtcQueryImportReceipt> {
    owners(reader, plan, cx, work).map_err(failure)?;
    admit(plan, authority, destination, cx, cancelled).map_err(failure)?;
    let revalidation_cancelled = || cancelled() || cx.checkpoint(STAGE_QUERY_REVALIDATE).is_err();
    let fresh = preview_rtsp_utc_query_import(
        io,
        &plan.deployment_root,
        &plan.archive_root,
        &plan.input,
        &plan.settings,
        &revalidation_cancelled,
    )
    .map_err(failure)?;
    let snapshot = fresh.query.snapshot();
    if fresh.digest != plan.digest
        || destination.root() != plan.deployment_root.as_path()
        || destination.site_lineage() != snapshot.site_lineage.as_str()
        || destination.current_anchor() != &snapshot.anchor
        || destination.ledger().journal_root() != snapshot.ledger_root
        || destination.effects().last_root() != snapshot.effect_journal_root
    {
        return Err(failure(RtspQueryImportError::StalePlan));
    }
    admit(plan, authority, destination, cx, cancelled).map_err(failure)?;
    let windows = plan
        .windows
        .iter()
        .map(|window| batch::Window {
            request: &window.request,
            entry: &window.row.entry,
            scope: &window.scope,
        })
        .collect::<Vec<_>>();
    let permit =
        |destination: &ReferenceDeployment| admit(plan, authority, destination, cx, cancelled);
    match batch::run(
        &mut batch::Source::Pinned(reader),
        destination,
        &plan.settings,
        &windows,
        (plan.frames, plan.original_bytes),
        &permit,
        cx,
        work,
    ) {
        Ok(receipt) => Ok(RtspUtcQueryImportReceipt {
            plan_digest: plan.digest,
            imports: selected_receipts(plan, receipt.imports),
            frames: receipt.frames,
            original_bytes: receipt.original_bytes,
            media_bytes: receipt.media_bytes,
            work_used: receipt.work_used,
        }),
        Err(error) => Err(RtspUtcQueryImportFailure {
            reason: error.reason,
            completed: selected_receipts(plan, error.completed),
            next_window: error.next_window,
            current_import_may_be_durable: error.current_import_may_be_durable,
        }),
    }
}

/// Open only the existing approved destination, preserving unrelated pending effects.
/// Fresh protected metadata revalidation under this owner precedes every native batch.
#[allow(clippy::too_many_arguments)]
pub fn import_rtsp_utc_query_pinned_existing(
    io: &dyn SpoolIo,
    reader: &mut PinnedClosureReader<'_>,
    plan: &RtspUtcQueryImportPlan,
    authority: &dyn RtspUtcQueryImportAuthority,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<RtspUtcQueryImportReceipt> {
    owners(reader, plan, cx, work).map_err(failure)?;
    if cancelled() || cx.checkpoint(STAGE_QUERY_IMPORT).is_err() || !authority.permit_open(plan) {
        return Err(failure(RtspQueryImportError::Denied));
    }
    let mut destination = ReferenceDeployment::open_existing_without_effect_reconciliation(
        &plan.deployment_root,
        &plan.settings.site,
        cx,
    )
    .map_err(|error| failure(RtspQueryImportError::Destination(Box::new(error))))?;
    import_rtsp_utc_query_pinned(
        io,
        reader,
        &mut destination,
        plan,
        authority,
        cx,
        work,
        cancelled,
    )
}
