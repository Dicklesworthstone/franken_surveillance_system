#![forbid(unsafe_code)]
//! HEVC publication/readback using the shared catalog storage and cancellation engine.

use super::*;
use crate::rtsp::recording_catalog::local::{
    CatalogIoError, CatalogProgress, CatalogPublication, RangeReceipt, RecordingRangeRead,
    load_catalog_for,
};
use fss_publication::{LocalRootPublisher, PublishCancellation};

type IoResult<T> = std::result::Result<T, CatalogIoError>;

/// Existing publisher protocol with a permanently pinned HEVC window verifier.
/// It replays each existing recording before staging the index, then publishes
/// the root last. It creates no spool, worker, filesystem path or effect authority.
#[derive(Debug)]
pub struct HevcCatalogPublication<'a>(CatalogPublication<'a>);
impl<'a> HevcCatalogPublication<'a> {
    /// Borrow exact catalog bytes and an already-authorized storage owner. The
    /// reservation covers new catalog payload; source reads have separate bounds.
    pub fn new(catalog: &'a HevcRecordingCatalog, publisher: &'a mut LocalRootPublisher,
        slot: SlotName, reserved_catalog_bytes: usize, deadline_ns: u64) -> IoResult<Self>
    {
        CatalogPublication::new_for(&catalog.0, publisher, slot, reserved_catalog_bytes,
            deadline_ns, CatalogFamily::Hevc).map(Self)
    }
    /// Reverify one HEVC window, stage metadata, or execute the existing root commit.
    /// An error stops the attempt; preserve exact bytes for explicit reconciliation.
    /// The owner drives live revocation/deadline checks through the cancellation probe.
    pub fn step(&mut self, now_ns: u64, cancel: &dyn PublishCancellation) -> IoResult<CatalogProgress> {
        self.0.step(now_ns, cancel)
    }
}

/// Reopen an exact durable HEVC catalog and verify metadata, scope, object closure
/// and current slot/root/tombstone bindings. This does not read every media object;
/// use HevcRecordingRangeRead for source-replay-verified window transfer.
pub fn load_hevc_catalog(publisher: &LocalRootPublisher, slot: &SlotName,
    expected_root: ContentDigest, scope: &CatalogScope, cancel: &dyn PublishCancellation)
    -> IoResult<HevcRecordingCatalog>
{
    load_catalog_for(publisher, slot, expected_root, scope, cancel, CatalogFamily::Hevc)
        .map(HevcRecordingCatalog)
}

/// HEVC-only output; original source packets and typed sample mappings stay available.
#[derive(Debug)]
pub enum HevcRangeProgress {
    /// One complete window passed native source replay before transfer.
    Window {
        /// Ordinal in this exact immutable catalog page.
        ordinal: usize,
        /// Requested overlap, without cropping or rewriting compressed media.
        requested_interval: Range<u64>,
        /// Fully loaded and replay-verified HEVC source, media and index.
        recording: PreparedHevcRecording,
    },
    /// All selected windows transferred, and the exact catalog was re-read.
    /// Explicit unindexed intervals remain distinct from coverage/absence claims.
    Complete(RangeReceipt),
    /// The aggregate receipt was already returned; no fresh verification occurred.
    Exhausted,
}

/// One bounded HEVC window per step over the existing catalog read state machine.
/// A later refusal never reclaims previously returned windows and never emits a
/// false aggregate success. Only metadata is retained between calls.
#[derive(Debug)]
pub struct HevcRecordingRangeRead<'a>(RecordingRangeRead<'a>);
impl<'a> HevcRecordingRangeRead<'a> {
    /// Pin a durable catalog slot/root and atomically select against count/byte
    /// bounds. Complete window size is charged even for a one-tick intersection.
    pub fn new(publisher: &'a LocalRootPublisher, catalog: &'a HevcRecordingCatalog,
        slot: &SlotName, query: Range<u64>, limits: CatalogQueryLimits, deadline_ns: u64)
        -> IoResult<Self>
    {
        RecordingRangeRead::new_for(publisher, &catalog.0, slot, query, limits,
            deadline_ns, CatalogFamily::Hevc).map(Self)
    }
    /// Metadata selection only, not successful media retrieval or physical coverage.
    pub fn selection(&self) -> &CatalogSelection { self.0.selection() }
    /// Windows already returned, including after an error on a later step.
    pub fn returned_windows(&self) -> usize { self.0.returned_windows() }
    /// Rehash and replay one complete source window through the actual HEVC owners,
    /// recheck descriptor/budget/cancellation, or return the sole aggregate receipt.
    pub fn step(&mut self, now_ns: u64, cancel: &dyn PublishCancellation) -> IoResult<HevcRangeProgress> {
        self.0.step_hevc(now_ns, cancel)
    }
}
