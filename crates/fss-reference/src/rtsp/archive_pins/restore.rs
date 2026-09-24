#![forbid(unsafe_code)]
//! Storage-only restoration selected by the independent journal, not conversation state.
//!
//! Restore only the already checkpointed page/window. Never prepare additional pages here:
//! doing so would invalidate the original recovery pin after a lost response.

use super::*;
use crate::rtsp::recording::local::{RecordingIoError, RecordingProgress, RecordingPublication};
use crate::rtsp::recording_archive::{ArchiveNamespace, ArchiveSnapshot};

/// Completed restoration of the selected original work, not complete camera capture or indexing.
#[must_use]
#[derive(Debug)]
pub struct ArchivePinRestoration {
    /// Exact independently stored checkpoint used throughout this attempt.
    pub pin: StoredArchivePin,
    /// Journal tip after any candidate confirmation. No new record for an exact confirmed retry.
    pub journal_anchor: ArchivePinAnchor,
    /// Present when this attempt first confirmed an existing candidate's complete work graph.
    pub confirmation: Option<ArchivePinReceipt>,
    /// Actual original catalog-slot publication/reverification, absent if no page was pending.
    pub catalog: Option<LocalPublicationReceipt>,
    /// Actual original recording-slot publication/reverification, absent if none was pending.
    pub window: Option<LocalPublicationReceipt>,
    /// Source-verified normal archive inventory after restoration, not an authority ledger root.
    pub snapshot_digest: ContentDigest,
    /// Normal durable windows, excluding auxiliary checkpoint roots.
    pub durable_windows: usize,
    /// Normal windows represented in a published catalog page.
    pub indexed_windows: usize,
    /// Normal published catalog pages; no new page is invented by restoration.
    pub pages: usize,
}

impl ArchivePinJournal {
    /// Open an existing journal without any incomplete-tail repair. This is the ordinary
    /// operator recovery entrypoint; accepted scope, independent minimum and limits are
    /// identical to open_existing. Missing storage is never initialized or adopted.
    pub fn open_complete(
        directory: impl AsRef<Path>,
        scope: ArchivePinScope,
        minimum: Option<ArchivePinAnchor>,
        limits: ArchivePinLimits,
        cancel: &dyn PublishCancellation,
    ) -> PinResult<Self> {
        Self::open_existing(
            directory,
            scope,
            minimum,
            limits,
            IncompleteTailPolicy::Reject,
            cancel,
        )
    }

    /// Reconcile and restore exactly the journal's active work. A candidate takes precedence;
    /// its missing/corrupt/deleted work is an error, never a reason to try the older confirmation.
    /// With no candidate, restore the last confirmation. Empty journals have no restoration.
    ///
    /// Source replay, namespace and payload checks precede candidate confirmation. Confirmation
    /// is synchronized BEFORE any normal archive write. Restore the original prepared page
    /// before a waiting next window, retaining the original work pin after every possible cut.
    /// Repeated calls reverify the same roots and produce AlreadyPublished receipts rather than
    /// duplicates. Unprepared discovery metadata remains explicitly unindexed.
    ///
    /// Both owners must be exclusive and separately authorized. `now` only admits this bounded
    /// synchronous operation; cancellation must also enforce live deadline/revocation at I/O
    /// boundaries. A failure may follow committed metadata or archive roots. Keep both stores,
    /// reopen/reconcile uncertain storage, and retry the same journal work, never another ordinal.
    pub fn restore_work(
        &mut self,
        publisher: &mut LocalRootPublisher,
        bounds: ArchiveWorkLimits,
        now: u64,
        deadline: u64,
        cancel: &dyn PublishCancellation,
    ) -> PinResult<ArchivePinRestoration> {
        if now >= deadline {
            return Err(ArchiveError::Deadline.into());
        }
        check(cancel)?;
        self.verify(cancel)?;
        let (which, pin) = match (&self.replay.pins.candidate, &self.replay.pins.confirmed) {
            (Some(pin), _) => (ArchivePinPhase::Candidate, pin.clone()),
            (None, Some(pin)) => (ArchivePinPhase::Confirmed, pin.clone()),
            (None, None) => return Err(ArchivePinError::History),
        };
        let work = self.load_work(which, publisher, bounds, cancel)?;
        // Allocate retained receipt metadata before either kind of publication side effect.
        let result_pin = pin.clone();
        let confirmation = if which == ArchivePinPhase::Candidate {
            Some(self.persist(pin, ArchivePinPhase::Confirmed, cancel)?)
        } else {
            None
        };
        let catalog = match &work.prepared_page {
            None => None,
            Some(page) => {
                check(cancel)?;
                let slot = work
                    .snapshot
                    .namespace()
                    .page_slot(work.snapshot.indexed_windows())?;
                let digest = publisher
                    .stage_object(page.index_bytes())
                    .map_err(publication_error)?;
                if Some(digest) != page.manifest().metadata_digest() {
                    return Err(ArchiveError::Metadata.into());
                }
                Some(require_durable(
                    publisher
                        .publish_cancellable(&slot, page.manifest(), cancel)
                        .map_err(publication_error)?,
                    page.manifest().root(),
                )?)
            }
        };
        let window = match &work.pending {
            None => None,
            Some(window) => {
                check(cancel)?;
                let slot = work
                    .snapshot
                    .namespace()
                    .window_slot(work.snapshot.windows().len())?;
                let mut job = RecordingPublication::new(
                    window,
                    publisher,
                    slot,
                    bounds.max_pending_bytes,
                    deadline,
                )
                .map_err(ArchiveError::from)?;
                let mut receipt = None;
                for _ in 0..5 {
                    if let RecordingProgress::Published(value) =
                        job.step(now, cancel).map_err(ArchiveError::from)?
                    {
                        receipt = Some(require_durable(value, window.manifest().root())?);
                        break;
                    }
                }
                Some(receipt.ok_or(ArchiveError::Metadata)?)
            }
        };
        check(cancel)?;
        self.require_settled(publisher, bounds, cancel)?;
        let namespace = ArchiveNamespace::new(work.snapshot.namespace().scope().clone())?;
        let snapshot = ArchiveSnapshot::load(publisher, namespace, work.snapshot.limits(), cancel)?;
        let snapshot_digest = snapshot.digest()?;
        self.verify(cancel)?;
        Ok(ArchivePinRestoration {
            pin: result_pin,
            journal_anchor: self.anchor(),
            confirmation,
            catalog,
            window,
            snapshot_digest,
            durable_windows: snapshot.windows().len(),
            indexed_windows: snapshot.indexed_windows(),
            pages: snapshot.pages().len(),
        })
    }
}

fn publication_error(error: fss_publication::LocalPublicationError) -> ArchivePinError {
    ArchiveError::Storage(RecordingIoError::from(error)).into()
}
fn require_durable(
    receipt: LocalPublicationReceipt,
    expected: ContentDigest,
) -> PinResult<LocalPublicationReceipt> {
    if receipt.root != expected || receipt.claims.local != LocalPublicationState::Durable {
        return Err(ArchiveError::Storage(RecordingIoError::NotDurable).into());
    }
    Ok(receipt)
}
