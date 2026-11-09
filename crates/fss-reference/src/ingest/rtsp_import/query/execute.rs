#![forbid(unsafe_code)]
//! Incremental selected-window acquisition under a revalidated protected plan.

use fss_geometry::WorkBudget;
use fss_object::SpoolIo;
use fss_publication::LocalRootPublisher;

use super::*;
use crate::ReplayCx;
use crate::ingest::rtsp_import::{RtspImportAuthority, import_rtsp_checked};
use crate::rtsp::recording::PreparedRecording;

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
    publisher: &LocalRootPublisher,
    plan: &RtspQueryImportPlan,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
) -> std::result::Result<(), RtspQueryImportError> {
    if publisher.root_dir() != plan.archive_root.as_path()
        || cx.root_dir() != plan.deployment_root.as_path()
        || work.remaining() > plan.settings.max_work
    {
        return Err(RtspQueryImportError::Invalid(
            "query import owner or work binding",
        ));
    }
    work.charge(0).map_err(|_| RtspQueryImportError::Denied)
}

struct Access<'a> {
    plan: &'a RtspQueryImportPlan,
    owner: &'a dyn RtspQueryImportAuthority,
    request: ContentDigest,
    cx: &'a ReplayCx,
    cancelled: &'a (dyn Fn() -> bool + Sync),
}
impl RtspImportAuthority for Access<'_> {
    fn permit(&self, request: &RtspImportRequest, destination: &ReferenceDeployment) -> bool {
        request.digest().is_ok_and(|digest| digest == self.request)
            && admit(self.plan, self.owner, destination, self.cx, self.cancelled).is_ok()
    }
}

/// Revalidate a protected plan and acquire only its selected whole windows.
///
/// The supplied publisher is already open; its existing recovery may have read and rehashed
/// unselected archive objects. This function adds no such payload reads: native imports retain
/// only the selected original window closures, never a partial catalog graph. One supplied
/// WorkBudget carries the existing native read, reconstruction and publication charges plus
/// descriptor rehash work, without replenishment. Metadata queries and archive-owner recovery
/// retain their separate limits; this account does not claim to meter total filesystem I/O.
///
/// The opened destination, its site, authority/effect roots and both owner paths must match
/// the fresh protected snapshot before the first import. Current authority is rechecked at
/// every native boundary. Later failure preserves a confirmed prefix and an explicit unknown
/// current outcome. After any changed destination anchor, obtain a new preview/approval;
/// unchanged native child requests reconcile their existing publication identities.
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
    owners(publisher, plan, cx, work).map_err(failure)?;
    admit(plan, authority, destination, cx, cancelled).map_err(failure)?;
    let initial_work = work.used();
    {
        let revalidation_cancelled =
            || cancelled() || cx.checkpoint(STAGE_QUERY_REVALIDATE).is_err();
        let fresh = preview_rtsp_query_import(
            io,
            &plan.deployment_root,
            &plan.archive_root,
            &plan.request,
            &plan.limits,
            &plan.settings,
            &revalidation_cancelled,
        )
        .map_err(failure)?;
        if fresh.digest != plan.digest
            || destination.root() != plan.deployment_root.as_path()
            || destination.site_lineage() != fresh.query.snapshot.site_lineage.as_str()
            || destination.current_anchor() != &fresh.query.snapshot.anchor
            || destination.ledger().journal_root() != fresh.query.snapshot.ledger_root
            || destination.effects().last_root() != fresh.query.snapshot.effect_journal_root
        {
            return Err(failure(RtspQueryImportError::StalePlan));
        }
    }
    admit(plan, authority, destination, cx, cancelled).map_err(failure)?;

    let mut completed = Vec::with_capacity(plan.windows.len());
    let mut frames = 0_usize;
    let mut original_bytes = 0_u64;
    let mut media_bytes = 0_u64;
    for (index, window) in plan.windows.iter().enumerate() {
        if cx.checkpoint(STAGE_QUERY_WINDOW).is_err() {
            return Err(RtspQueryImportFailure {
                reason: RtspQueryImportError::Denied,
                completed,
                next_window: index,
                current_import_may_be_durable: false,
            });
        }
        if let Err(reason) = admit(plan, authority, destination, cx, cancelled) {
            return Err(RtspQueryImportFailure {
                reason,
                completed,
                next_window: index,
                current_import_may_be_durable: false,
            });
        }
        let request_digest = match window.request.digest() {
            Ok(digest) => digest,
            Err(error) => {
                return Err(RtspQueryImportFailure {
                    reason: error.into(),
                    completed,
                    next_window: index,
                    current_import_may_be_durable: false,
                });
            }
        };
        let access = Access {
            plan,
            owner: authority,
            request: request_digest,
            cx,
            cancelled,
        };
        let mut admitted = None;
        let mut check_window = |recording: &PreparedRecording, work: &mut WorkBudget<'_>| {
            // Full descriptor equality rehashes the original children. Charge that added
            // pass before it starts, using the verified window's actual size, not its quote.
            work.charge(recording.byte_len() as u64)
                .map_err(|_| RtspImportError::Invalid("selected descriptor work allowance"))?;
            window
                .row
                .entry
                .verify_window(&plan.request.recording.scope, recording)
                .map_err(|_| {
                    RtspImportError::Invalid(
                        "selected native window differs from catalog descriptor",
                    )
                })?;
            let next_frames = frames
                .checked_add(recording.summary().samples)
                .ok_or(RtspImportError::Invalid("selected sample count overflow"))?;
            let next_original = original_bytes
                .checked_add(recording.byte_len() as u64)
                .ok_or(RtspImportError::Invalid("selected original byte overflow"))?;
            let objects = recording.objects();
            let window_media = objects
                .initialization
                .len()
                .checked_add(objects.media.len())
                .ok_or(RtspImportError::Invalid("selected media size overflow"))?;
            let next_media = media_bytes
                .checked_add(window_media as u64)
                .ok_or(RtspImportError::Invalid("selected media byte overflow"))?;
            if next_frames > plan.settings.max_frames
                || next_original > plan.settings.max_original_bytes
                || next_media > plan.settings.max_media_bytes
            {
                return Err(RtspImportError::Invalid("aggregate selected-window bounds"));
            }
            admitted = Some((next_frames, next_original, next_media));
            Ok(())
        };
        let mut publication_started = false;
        let result = import_rtsp_checked(
            publisher,
            destination,
            &window.request,
            &access,
            cx,
            work,
            &mut check_window,
            &mut publication_started,
        );
        match result {
            Ok(import) => {
                completed.push(RtspQueryImportedWindow {
                    ordinal: window.row.ordinal,
                    source_root: window.row.entry.root(),
                    overlap: window.row.overlap.clone(),
                    import,
                });
                let Some((next_frames, next_original, next_media)) = admitted else {
                    return Err(RtspQueryImportFailure {
                        reason: RtspQueryImportError::Invalid("missing native admission"),
                        completed,
                        next_window: index + 1,
                        current_import_may_be_durable: false,
                    });
                };
                frames = next_frames;
                original_bytes = next_original;
                media_bytes = next_media;
            }
            Err(error) => {
                return Err(RtspQueryImportFailure {
                    reason: error.into(),
                    completed,
                    next_window: index,
                    current_import_may_be_durable: publication_started,
                });
            }
        }
    }
    if frames != plan.frames || original_bytes != plan.original_bytes {
        return Err(RtspQueryImportFailure {
            reason: RtspQueryImportError::Invalid("complete selected-window accounting"),
            next_window: completed.len(),
            completed,
            current_import_may_be_durable: false,
        });
    }
    if let Err(reason) = admit(plan, authority, destination, cx, cancelled) {
        return Err(RtspQueryImportFailure {
            reason,
            next_window: completed.len(),
            completed,
            current_import_may_be_durable: false,
        });
    }
    Ok(RtspQueryImportReceipt {
        plan_digest: plan.digest,
        imports: completed,
        frames,
        original_bytes,
        media_bytes,
        work_used: work.used() - initial_work,
    })
}

/// Open only the plan's existing destination without reconciling unrelated effect states.
///
/// Exact before-open admission is mandatory. The owning deployment mode cannot initialize a
/// missing destination and is not exposed as a general mutable handle. Its existing recovery
/// rules remain intact; post-lock protected revalidation still precedes every native import.
/// The caller separately admits the source publisher's existing open/recovery boundary.
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
    owners(publisher, plan, cx, work).map_err(failure)?;
    if cancelled() || cx.checkpoint(STAGE_QUERY_IMPORT).is_err() || !authority.permit_open(plan) {
        return Err(failure(RtspQueryImportError::Denied));
    }
    let mut destination = ReferenceDeployment::open_existing_without_effect_reconciliation(
        &plan.deployment_root,
        &plan.settings.site,
        cx,
    )
    .map_err(|error| failure(RtspQueryImportError::Destination(Box::new(error))))?;
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
