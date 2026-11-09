#![forbid(unsafe_code)]
//! Exact protected revalidation and adapters to the common selected-window custody owner.

use fss_geometry::WorkBudget;
use fss_object::SpoolIo;
use fss_publication::LocalRootPublisher;
use fss_publication::custody_audit::pinned_closure::PinnedClosureReader;

use super::*;
use crate::ReplayCx;

type Result<T> = std::result::Result<T, RtspQueryImportFailure>;

fn admit(
    plan: &RtspQueryImportPlan,
    authority: &dyn RtspQueryImportAuthority,
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
    source_root: &Path,
    plan: &RtspQueryImportPlan,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
) -> std::result::Result<(), RtspQueryImportError> {
    if source_root != plan.archive_root.as_path()
        || cx.root_dir() != plan.deployment_root.as_path()
        || work.remaining() > plan.settings.max_work
    {
        return Err(RtspQueryImportError::Invalid(
            "query import owner or work binding",
        ));
    }
    work.charge(0).map_err(|_| RtspQueryImportError::Denied)
}

fn pinned_owner(
    reader: &PinnedClosureReader<'_>,
    plan: &RtspQueryImportPlan,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
) -> std::result::Result<(), RtspQueryImportError> {
    owners(reader.root_dir(), plan, cx, work)?;
    let minimum = (plan.windows.len() as u64)
        .checked_mul(super::super::MAX_ORIGINAL_BYTES * 3)
        .and_then(|reads| reads.checked_add(plan.original_bytes));
    if reader.limits() != plan.source_limits()
        || minimum.is_none_or(|minimum| minimum > work.remaining())
    {
        return Err(RtspQueryImportError::Invalid(
            "pinned query source allowance",
        ));
    }
    Ok(())
}

fn revalidate(
    io: &dyn SpoolIo,
    destination: &ReferenceDeployment,
    plan: &RtspQueryImportPlan,
    cx: &ReplayCx,
    cancelled: &(impl Fn() -> bool + Sync),
) -> std::result::Result<(), RtspQueryImportError> {
    let revalidation_cancelled = || cancelled() || cx.checkpoint(STAGE_QUERY_REVALIDATE).is_err();
    let fresh = preview_rtsp_query_import(
        io,
        &plan.deployment_root,
        &plan.archive_root,
        &plan.request,
        &plan.limits,
        &plan.settings,
        &revalidation_cancelled,
    )?;
    if fresh.digest != plan.digest
        || destination.root() != plan.deployment_root.as_path()
        || destination.site_lineage() != fresh.query.snapshot.site_lineage.as_str()
        || destination.current_anchor() != &fresh.query.snapshot.anchor
        || destination.ledger().journal_root() != fresh.query.snapshot.ledger_root
        || destination.effects().last_root() != fresh.query.snapshot.effect_journal_root
    {
        return Err(RtspQueryImportError::StalePlan);
    }
    Ok(())
}

fn selected_receipts(
    plan: &RtspQueryImportPlan,
    imports: Vec<RtspImportReceipt>,
) -> Vec<RtspQueryImportedWindow> {
    plan.windows
        .iter()
        .zip(imports)
        .map(|(window, import)| RtspQueryImportedWindow {
            ordinal: window.row.ordinal,
            source_root: window.row.entry.root(),
            overlap: window.row.overlap.clone(),
            import,
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn execute(
    io: &dyn SpoolIo,
    source: &mut batch::Source<'_, '_>,
    destination: &mut ReferenceDeployment,
    plan: &RtspQueryImportPlan,
    authority: &dyn RtspQueryImportAuthority,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<RtspQueryImportReceipt> {
    admit(plan, authority, destination, cx, cancelled).map_err(failure)?;
    revalidate(io, destination, plan, cx, cancelled).map_err(failure)?;
    admit(plan, authority, destination, cx, cancelled).map_err(failure)?;
    let windows = plan
        .windows
        .iter()
        .map(|window| batch::Window {
            request: &window.request,
            entry: &window.row.entry,
            scope: &plan.request.recording.scope,
        })
        .collect::<Vec<_>>();
    let permit =
        |destination: &ReferenceDeployment| admit(plan, authority, destination, cx, cancelled);
    match batch::run(
        source,
        destination,
        &plan.settings,
        &windows,
        (plan.frames, plan.original_bytes),
        &permit,
        cx,
        work,
    ) {
        Ok(receipt) => Ok(RtspQueryImportReceipt {
            plan_digest: plan.digest,
            imports: selected_receipts(plan, receipt.imports),
            frames: receipt.frames,
            original_bytes: receipt.original_bytes,
            media_bytes: receipt.media_bytes,
            work_used: receipt.work_used,
        }),
        Err(error) => Err(RtspQueryImportFailure {
            reason: error.reason,
            completed: selected_receipts(plan, error.completed),
            next_window: error.next_window,
            current_import_may_be_durable: error.current_import_may_be_durable,
        }),
    }
}

/// Revalidate a protected plan and acquire its complete selected windows through an open publisher.
///
/// Existing publisher recovery may have read unselected archive objects. This compatibility
/// path preserves the v1 plan digest, native request/proof identities and work accounting.
/// The shared selected-window owner checks complete descriptors, aggregate bounds, current
/// authority and partial/uncertain progress without retaining any partial catalog root.
#[allow(clippy::too_many_arguments)]
pub fn import_rtsp_query(
    io: &dyn SpoolIo,
    publisher: &LocalRootPublisher,
    destination: &mut ReferenceDeployment,
    plan: &RtspQueryImportPlan,
    authority: &dyn RtspQueryImportAuthority,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<RtspQueryImportReceipt> {
    owners(publisher.root_dir(), plan, cx, work).map_err(failure)?;
    execute(
        io,
        &mut batch::Source::Publisher(publisher),
        destination,
        plan,
        authority,
        cx,
        work,
        cancelled,
    )
}

/// Acquire selected source closures using one cumulative read-only pinned reader.
///
/// Only the five objects of each selected complete native window are read and rehashed.
/// The reader must use exactly `plan.source_limits()`; caller-owned usage remains available
/// on both success and failure. The plan's original v1 identity is unchanged; transports
/// must additionally bind this read strategy and allowance in their exact approval identity.
/// No archive writer lock, recovery, directory creation or unselected payload read occurs.
#[allow(clippy::too_many_arguments)]
pub fn import_rtsp_query_pinned(
    io: &dyn SpoolIo,
    reader: &mut PinnedClosureReader<'_>,
    destination: &mut ReferenceDeployment,
    plan: &RtspQueryImportPlan,
    authority: &dyn RtspQueryImportAuthority,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<RtspQueryImportReceipt> {
    pinned_owner(reader, plan, cx, work).map_err(failure)?;
    execute(
        io,
        &mut batch::Source::Pinned(reader),
        destination,
        plan,
        authority,
        cx,
        work,
        cancelled,
    )
}

fn open_destination(
    plan: &RtspQueryImportPlan,
    authority: &dyn RtspQueryImportAuthority,
    cx: &ReplayCx,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<ReferenceDeployment> {
    if cancelled() || cx.checkpoint(STAGE_QUERY_IMPORT).is_err() || !authority.permit_open(plan) {
        return Err(failure(RtspQueryImportError::Denied));
    }
    ReferenceDeployment::open_existing_without_effect_reconciliation(
        &plan.deployment_root,
        &plan.settings.site,
        cx,
    )
    .map_err(|error| failure(RtspQueryImportError::Destination(Box::new(error))))
}

/// Open only the approved existing destination, preserving unrelated pending effects.
/// Source publisher recovery is separately admitted by the caller before this compatibility call.
#[allow(clippy::too_many_arguments)]
pub fn import_rtsp_query_existing(
    io: &dyn SpoolIo,
    publisher: &LocalRootPublisher,
    plan: &RtspQueryImportPlan,
    authority: &dyn RtspQueryImportAuthority,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<RtspQueryImportReceipt> {
    owners(publisher.root_dir(), plan, cx, work).map_err(failure)?;
    let mut destination = open_destination(plan, authority, cx, cancelled)?;
    import_rtsp_query(
        io,
        publisher,
        &mut destination,
        plan,
        authority,
        cx,
        work,
        cancelled,
    )
}

/// Open only the existing destination after independent exact approval, using read-only source custody.
/// The full protected query is revalidated under the destination owner before any child publication.
#[allow(clippy::too_many_arguments)]
pub fn import_rtsp_query_pinned_existing(
    io: &dyn SpoolIo,
    reader: &mut PinnedClosureReader<'_>,
    plan: &RtspQueryImportPlan,
    authority: &dyn RtspQueryImportAuthority,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<RtspQueryImportReceipt> {
    pinned_owner(reader, plan, cx, work).map_err(failure)?;
    let mut destination = open_destination(plan, authority, cx, cancelled)?;
    import_rtsp_query_pinned(
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
