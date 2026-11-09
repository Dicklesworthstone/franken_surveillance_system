#![forbid(unsafe_code)]
//! One native acquisition loop for decode-clock and conditional UTC selections.
//!
//! Plans supply exact immutable rows and current authority. This owner shares complete
//! descriptor verification, cumulative bounds, native custody and partial-progress semantics.

use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_publication::LocalRootPublisher;
use fss_publication::custody_audit::CustodyAuditLimits;
use fss_publication::custody_audit::pinned_closure::PinnedClosureReader;

use super::{
    RtspQueryImportError, RtspQueryImportSettings, STAGE_QUERY_FINALIZE, STAGE_QUERY_WINDOW,
};
use crate::ingest::rtsp_import::{
    RtspImportAuthority, RtspImportError, RtspImportReceipt, RtspImportRequest,
    import_rtsp_checked, import_rtsp_pinned_checked,
};
use crate::rtsp::recording::PreparedRecording;
use crate::rtsp::recording_catalog::{CatalogEntry, CatalogScope};
use crate::{ReferenceDeployment, ReplayCx};

pub(super) enum Source<'a, 'io> {
    Publisher(&'a LocalRootPublisher),
    Pinned(&'a mut PinnedClosureReader<'io>),
}

/// One root plus four direct native children, counted conservatively for every selected window.
/// Both complete reads and per-file reservation slack share the same unrefilled read owner.
pub(super) fn source_limits(
    windows: usize,
    original_bytes: u64,
    largest_window: usize,
) -> CustodyAuditLimits {
    CustodyAuditLimits {
        max_catalogue_entries: windows,
        max_objects: windows * 5,
        max_edges: windows * 4,
        max_object_bytes: largest_window,
        max_read_bytes: original_bytes * 2 + largest_window as u64 + windows as u64 * 32 * 1024,
        max_io_calls: windows as u64 * 1024 + 16,
    }
}

pub(super) struct Window<'a> {
    pub request: &'a RtspImportRequest,
    pub entry: &'a CatalogEntry,
    pub scope: &'a CatalogScope,
}

pub(super) struct Receipt {
    pub imports: Vec<RtspImportReceipt>,
    pub frames: usize,
    pub original_bytes: u64,
    pub media_bytes: u64,
    pub work_used: u64,
}

pub(super) struct Failure {
    pub reason: RtspQueryImportError,
    pub completed: Vec<RtspImportReceipt>,
    pub next_window: usize,
    pub current_import_may_be_durable: bool,
}

struct Access<'a> {
    request: ContentDigest,
    permit: &'a dyn Fn(&ReferenceDeployment) -> Result<(), RtspQueryImportError>,
}
impl RtspImportAuthority for Access<'_> {
    fn permit(&self, request: &RtspImportRequest, destination: &ReferenceDeployment) -> bool {
        request.digest().is_ok_and(|digest| digest == self.request)
            && (self.permit)(destination).is_ok()
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run(
    source: &mut Source<'_, '_>,
    destination: &mut ReferenceDeployment,
    settings: &RtspQueryImportSettings,
    windows: &[Window<'_>],
    expected: (usize, u64),
    permit: &dyn Fn(&ReferenceDeployment) -> Result<(), RtspQueryImportError>,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
) -> Result<Receipt, Failure> {
    let initial_work = work.used();
    let mut completed = Vec::with_capacity(windows.len());
    let mut frames = 0_usize;
    let mut original_bytes = 0_u64;
    let mut media_bytes = 0_u64;
    for (index, window) in windows.iter().enumerate() {
        let admission = cx
            .checkpoint(STAGE_QUERY_WINDOW)
            .map_err(|_| RtspQueryImportError::Denied)
            .and_then(|()| permit(destination));
        if let Err(reason) = admission {
            return Err(Failure {
                reason,
                completed,
                next_window: index,
                current_import_may_be_durable: false,
            });
        }
        let request_digest = match window.request.digest() {
            Ok(digest) => digest,
            Err(error) => {
                return Err(Failure {
                    reason: error.into(),
                    completed,
                    next_window: index,
                    current_import_may_be_durable: false,
                });
            }
        };
        let access = Access {
            request: request_digest,
            permit,
        };
        let mut admitted = None;
        let mut check_window = |recording: &PreparedRecording, work: &mut WorkBudget<'_>| {
            // Charge the added complete-descriptor hash pass before it begins.
            work.charge(recording.byte_len() as u64)
                .map_err(|_| RtspImportError::Invalid("selected descriptor work allowance"))?;
            window
                .entry
                .verify_window(window.scope, recording)
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
            if next_frames > settings.max_frames
                || next_original > settings.max_original_bytes
                || next_media > settings.max_media_bytes
            {
                return Err(RtspImportError::Invalid("aggregate selected-window bounds"));
            }
            admitted = Some((next_frames, next_original, next_media));
            Ok(())
        };
        let mut publication_started = false;
        let result = match source {
            Source::Publisher(publisher) => import_rtsp_checked(
                publisher,
                destination,
                window.request,
                &access,
                cx,
                work,
                &mut check_window,
                &mut publication_started,
            ),
            Source::Pinned(reader) => import_rtsp_pinned_checked(
                reader,
                destination,
                window.request,
                &access,
                cx,
                work,
                &mut check_window,
                &mut publication_started,
            ),
        };
        match result {
            Ok(import) => {
                completed.push(import);
                let Some(totals) = admitted else {
                    return Err(Failure {
                        reason: RtspQueryImportError::Invalid("missing native admission"),
                        completed,
                        next_window: index + 1,
                        current_import_may_be_durable: false,
                    });
                };
                (frames, original_bytes, media_bytes) = totals;
            }
            Err(error) => {
                return Err(Failure {
                    reason: error.into(),
                    completed,
                    next_window: index,
                    current_import_may_be_durable: publication_started,
                });
            }
        }
    }
    if (frames, original_bytes) != expected {
        return Err(Failure {
            reason: RtspQueryImportError::Invalid("complete selected-window accounting"),
            next_window: completed.len(),
            completed,
            current_import_may_be_durable: false,
        });
    }
    if let Err(reason) = permit(destination) {
        return Err(Failure {
            reason,
            next_window: completed.len(),
            completed,
            current_import_may_be_durable: false,
        });
    }
    if let Source::Pinned(reader) = source {
        let final_observation = cx
            .checkpoint(STAGE_QUERY_FINALIZE)
            .map_err(|_| RtspQueryImportError::Denied)
            .and_then(|()| permit(destination))
            .and_then(|()| {
                reader
                    .finalize()
                    .map(|_| ())
                    .map_err(|error| RtspImportError::Source(error.reason().to_owned()).into())
            });
        if let Err(reason) = final_observation {
            return Err(Failure {
                reason,
                next_window: completed.len(),
                completed,
                current_import_may_be_durable: false,
            });
        }
    }
    Ok(Receipt {
        imports: completed,
        frames,
        original_bytes,
        media_bytes,
        work_used: work.used() - initial_work,
    })
}
