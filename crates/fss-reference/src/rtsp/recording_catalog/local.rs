#![forbid(unsafe_code)]
//! Root-last catalog publication and bounded, incremental original-media retrieval.

use super::*;
use super::super::recording::local::{RecordingIoError, load_recording};
use super::super::recording::hevc::{PreparedHevcRecording, local::load_hevc_recording};
use fss_publication::{LocalPublicationReceipt, LocalPublicationState, LocalRootPublisher,
    PublishCancellation, PublishCutPoint};

/// Content refusals remain distinct from the publisher's cancellation, indeterminacy,
/// tombstone, and recovery errors. Neither variant prints paths or protected bytes.
#[derive(Debug)]
pub enum CatalogIoError {
    /// A canonical index, scope, selection, or descriptor check failed.
    Catalog(CatalogError),
    /// Existing recording/publication owner failure; indeterminacy is not flattened.
    Storage(RecordingIoError),
}
impl std::fmt::Display for CatalogIoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "recording catalog I/O refusal: {self:?}")
    }
}
impl std::error::Error for CatalogIoError {}
impl From<CatalogError> for CatalogIoError {
    fn from(e: CatalogError) -> Self { Self::Catalog(e) }
}
impl From<RecordingIoError> for CatalogIoError {
    fn from(e: RecordingIoError) -> Self { Self::Storage(e) }
}
type IoResult<T> = std::result::Result<T, CatalogIoError>;

/// Publication progress. A verified window or staged index is not a visible catalog.
#[derive(Debug)]
pub enum CatalogProgress {
    /// One existing durable window was fully loaded and its source provenance checked.
    WindowVerified {
        /// Zero-based ordinal of the verified window within the catalog.
        ordinal: usize,
        /// Content digest checked against the original recording manifest.
        root: ContentDigest,
        /// Retained payload byte count of the verified window.
        bytes: usize,
    },
    /// Canonical catalog metadata was staged, without publishing the catalog root.
    IndexStaged {
        /// Content digest of the staged canonical index object.
        digest: ContentDigest,
        /// Canonical index byte count staged into the owner.
        bytes: usize,
    },
    /// Actual root-last publisher receipt, with remote/protection rungs unclaimed.
    Published(LocalPublicationReceipt),
    /// The same request already returned its publication receipt; no fresh I/O occurred.
    Complete,
}

/// Exclusive request over an existing local owner. Each window is fully checked
/// before the index is staged. Root publication rechecks the flat object closure
/// through the existing publisher; it can perform more than one window's I/O.
pub struct CatalogPublication<'a> {
    catalog: &'a RecordingCatalog,
    publisher: &'a mut LocalRootPublisher,
    slot: SlotName,
    next: usize,
    index_staged: bool,
    clock: RequestClock,
    done: bool,
}
impl<'a> CatalogPublication<'a> {
    /// Admit a prepared page. Reservation covers NEW catalog payload, not a claim
    /// about syscall bytes or already archived source. Limits of the supplied
    /// publisher still bound full-closure verification and filesystem overhead.
    pub fn new(catalog: &'a RecordingCatalog, publisher: &'a mut LocalRootPublisher,
        slot: SlotName, reserved_catalog_bytes: usize, deadline_ns: u64) -> IoResult<Self>
    {
        Self::new_for(catalog, publisher, slot, reserved_catalog_bytes, deadline_ns, CatalogFamily::Avc)
    }
    pub(super) fn new_for(catalog: &'a RecordingCatalog, publisher: &'a mut LocalRootPublisher,
        slot: SlotName, reserved_catalog_bytes: usize, deadline_ns: u64, family: CatalogFamily) -> IoResult<Self>
    {
        if catalog.family != family { return Err(CatalogError::Digest.into()); }
        if catalog.byte_len() > reserved_catalog_bytes
            || publisher.limits().max_children < catalog.manifest.children().len()
            || catalog.index.len() > publisher.limits().spool.max_object_bytes
            || catalog.manifest.canonical_bytes().len() > publisher.limits().spool.max_object_bytes {
            return Err(RecordingIoError::Budget.into());
        }
        owner_ready(publisher)?;
        if publisher.root(&slot).is_some_and(|r| r.root != catalog.manifest.root()) {
            return Err(RecordingIoError::RootConflict.into());
        }
        Ok(Self { catalog, publisher, slot, next: 0, index_staged: false,
            clock: RequestClock::new(deadline_ns)?, done: false })
    }
    /// Admission time is supplied by the owner. Its cancellation probe must also
    /// enforce live deadline/revocation at I/O cut points. On failure this request
    /// stops; preserve the immutable page and reopen/reconcile an indeterminate owner.
    pub fn step(&mut self, now_ns: u64, cancel: &dyn PublishCancellation) -> IoResult<CatalogProgress> {
        if self.done { return Ok(CatalogProgress::Complete); }
        self.clock.admit(now_ns, cancel)?;
        let result = self.advance(cancel);
        if result.is_err() { self.clock.stopped = true; }
        result
    }
    fn advance(&mut self, cancel: &dyn PublishCancellation) -> IoResult<CatalogProgress> {
        owner_ready(self.publisher)?;
        if let Some(entry) = self.catalog.entries.get(self.next) {
            let window = load_window(self.publisher, self.catalog, entry, cancel)?;
            entry.verify_window(&self.catalog.scope, window.plan())?;
            cancelled(cancel)?;
            let ordinal = self.next; self.next += 1;
            return Ok(CatalogProgress::WindowVerified { ordinal, root: entry.root, bytes: window.plan().byte_len() });
        }
        for entry in &self.catalog.entries { durable_root(self.publisher, &entry.slot, entry.root)?; }
        if !self.index_staged {
            let observed = self.publisher.stage_object(&self.catalog.index)
                .map_err(RecordingIoError::Publication)?;
            if Some(observed) != self.catalog.manifest.metadata_digest() { return Err(CatalogError::Digest.into()); }
            self.index_staged = true;
            return Ok(CatalogProgress::IndexStaged { digest: observed, bytes: self.catalog.index.len() });
        }
        let receipt = self.publisher.publish_cancellable(&self.slot, &self.catalog.manifest, cancel)
            .map_err(RecordingIoError::Publication)?;
        self.done = true;
        Ok(CatalogProgress::Published(receipt))
    }
}

/// Load an exact durable page and check its metadata, reference closure, scope,
/// tombstones, and slot/root bindings. Window payloads are not yet returned or
/// provenance-certified: `RecordingRangeRead` verifies those independently.
/// Read allocation is bounded by the supplied spool (at most 32 MiB per object),
/// not merely by the smaller 64 KiB accepted catalog-payload limit.
pub fn load_catalog(publisher: &LocalRootPublisher, slot: &SlotName, expected_root: ContentDigest,
    scope: &CatalogScope, cancel: &dyn PublishCancellation) -> IoResult<RecordingCatalog>
{
    load_catalog_for(publisher, slot, expected_root, scope, cancel, CatalogFamily::Avc)
}

pub(super) fn load_catalog_for(publisher: &LocalRootPublisher, slot: &SlotName, expected_root: ContentDigest,
    scope: &CatalogScope, cancel: &dyn PublishCancellation, family: CatalogFamily) -> IoResult<RecordingCatalog>
{
    owner_ready(publisher)?;
    durable_root(publisher, slot, expected_root)?;
    let root_bytes = read_object(publisher, expected_root, cancel)?;
    if root_bytes.len() > MAX_CATALOG_BYTES { return Err(CatalogError::Limit.into()); }
    let manifest = ObjectManifest::from_canonical_bytes(&root_bytes).map_err(|_| CatalogError::Malformed)?;
    if manifest.root() != expected_root || manifest.kind() != family.kind()
        || manifest.children().len() > MAX_CATALOG_WINDOWS * 5 + 1 { return Err(CatalogError::Digest.into()); }
    let index_digest = manifest.metadata_digest().ok_or(CatalogError::Malformed)?;
    let index = read_object(publisher, index_digest, cancel)?;
    let catalog = verify_catalog_for(&manifest, &index, scope, family)?;
    live_catalog(publisher, slot, &catalog, cancel)?;
    Ok(catalog)
}

/// Incremental output. Only `Complete` certifies all selected windows were read;
/// an empty selection still completes with the entire query explicitly unindexed.
#[derive(Debug)]
pub enum RangeProgress {
    /// One whole original window, rehashed and source-verified before transfer.
    Window {
        /// Index into the exact catalog page.
        ordinal: usize,
        /// Requested subinterval; the returned encoded window is never cropped.
        requested_interval: Range<u64>,
        /// Exact original/initialization/media/index objects and verified summary.
        recording: PreparedRecording,
    },
    /// All selected windows passed verification and were transferred exactly once.
    Complete(RangeReceipt),
    /// Completion was already returned; this is not a new verification receipt.
    Exhausted,
}

/// Point-in-time retrieval accounting, NOT future availability or camera coverage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RangeReceipt {
    /// Immutable discovery page queried.
    pub catalog_root: ContentDigest,
    /// Explicit clock/stream basis for the interval.
    pub scope: CatalogScope,
    /// Original half-open request.
    pub query: Range<u64>,
    /// Whole windows successfully transferred during this attempt.
    pub windows: usize,
    /// Sum of exact recording payloads returned; not physical filesystem I/O.
    pub output_bytes: u64,
    /// Intervals not indexed by this page, never evidence of scene/event absence.
    pub unindexed: Vec<Range<u64>>,
}

/// One window per progress call; the request holds metadata only between calls.
/// Previously returned windows stay caller-owned after any later refusal. A
/// cancelled/failed attempt never emits a successful aggregate completion receipt.
pub struct RecordingRangeRead<'a> {
    publisher: &'a LocalRootPublisher,
    catalog: &'a RecordingCatalog,
    slot: SlotName,
    selection: CatalogSelection,
    next: usize,
    returned_bytes: u64,
    clock: RequestClock,
    done: bool,
}
impl<'a> RecordingRangeRead<'a> {
    /// Select atomically against a fixed catalog. A budget overflow refuses the
    /// whole query rather than returning an incomplete answer labeled complete.
    pub fn new(publisher: &'a LocalRootPublisher, catalog: &'a RecordingCatalog, slot: &SlotName,
        query: Range<u64>, limits: CatalogQueryLimits, deadline_ns: u64) -> IoResult<Self>
    {
        Self::new_for(publisher, catalog, slot, query, limits, deadline_ns, CatalogFamily::Avc)
    }
    pub(super) fn new_for(publisher: &'a LocalRootPublisher, catalog: &'a RecordingCatalog, slot: &SlotName,
        query: Range<u64>, limits: CatalogQueryLimits, deadline_ns: u64, family: CatalogFamily) -> IoResult<Self>
    {
        if catalog.family != family { return Err(CatalogError::Digest.into()); }
        owner_ready(publisher)?;
        durable_root(publisher, slot, catalog.manifest.root())?;
        let selection = catalog.select(query, limits)?;
        Ok(Self { publisher, catalog, slot: slot.clone(), selection, next: 0,
            returned_bytes: 0, clock: RequestClock::new(deadline_ns)?, done: false })
    }
    /// Metadata-only answer; no whole-query success is implied by this selection.
    pub fn selection(&self) -> &CatalogSelection { &self.selection }
    /// Count already returned, including when a later step fails.
    pub fn returned_windows(&self) -> usize { self.next }
    /// Verify one original window, or return the one terminal aggregate receipt.
    /// Full-window transient payload is independently bounded by MAX_RECORDING_BYTES
    /// and the supplied spool. max_output_bytes is a RETURNED payload budget, not
    /// a syscall budget; a malicious descriptor cannot cause excess output.
    pub fn step(&mut self, now_ns: u64, cancel: &dyn PublishCancellation) -> IoResult<RangeProgress> {
        if self.catalog.family != CatalogFamily::Avc { return Err(CatalogError::Digest.into()); }
        match self.step_window(now_ns, cancel)? {
            WindowProgress::Window { ordinal, requested_interval, recording: LoadedWindow::Avc(recording) } =>
                Ok(RangeProgress::Window { ordinal, requested_interval, recording }),
            WindowProgress::Complete(receipt) => Ok(RangeProgress::Complete(receipt)),
            WindowProgress::Exhausted => Ok(RangeProgress::Exhausted),
            _ => { self.clock.stopped = true; Err(CatalogError::WindowMismatch.into()) }
        }
    }
    pub(super) fn step_hevc(&mut self, now_ns: u64, cancel: &dyn PublishCancellation)
        -> IoResult<super::hevc::local::HevcRangeProgress>
    {
        use super::hevc::local::HevcRangeProgress;
        if self.catalog.family != CatalogFamily::Hevc { return Err(CatalogError::Digest.into()); }
        match self.step_window(now_ns, cancel)? {
            WindowProgress::Window { ordinal, requested_interval, recording: LoadedWindow::Hevc(recording) } =>
                Ok(HevcRangeProgress::Window { ordinal, requested_interval, recording }),
            WindowProgress::Complete(receipt) => Ok(HevcRangeProgress::Complete(receipt)),
            WindowProgress::Exhausted => Ok(HevcRangeProgress::Exhausted),
            _ => { self.clock.stopped = true; Err(CatalogError::WindowMismatch.into()) }
        }
    }
    fn step_window(&mut self, now_ns: u64, cancel: &dyn PublishCancellation) -> IoResult<WindowProgress> {
        if self.done { return Ok(WindowProgress::Exhausted); }
        self.clock.admit(now_ns, cancel)?;
        let result = self.advance(cancel);
        if result.is_err() { self.clock.stopped = true; }
        result
    }
    fn advance(&mut self, cancel: &dyn PublishCancellation) -> IoResult<WindowProgress> {
        live_catalog(self.publisher, &self.slot, self.catalog, cancel)?;
        if let Some(selected) = self.selection.selected.get(self.next) {
            let entry = &self.catalog.entries[selected.ordinal];
            let recording = load_window(self.publisher, self.catalog, entry, cancel)?;
            entry.verify_window(&self.catalog.scope, recording.plan())?;
            cancelled(cancel)?;
            let bytes = self.returned_bytes.checked_add(recording.plan().byte_len() as u64).ok_or(CatalogError::Limit)?;
            if bytes > self.selection.bytes { return Err(CatalogError::Limit.into()); }
            self.returned_bytes = bytes; self.next += 1;
            return Ok(WindowProgress::Window { ordinal: selected.ordinal,
                requested_interval: selected.interval.clone(), recording });
        }
        if self.returned_bytes != self.selection.bytes { return Err(CatalogError::WindowMismatch.into()); }
        // Re-read the pinned catalog itself before the aggregate receipt: in-memory
        // discovery metadata alone is not a fresh successful local retrieval.
        let reloaded = load_catalog_for(self.publisher, &self.slot, self.catalog.manifest.root(),
            &self.catalog.scope, cancel, self.catalog.family)?;
        if reloaded.index != self.catalog.index { return Err(CatalogError::Digest.into()); }
        cancelled(cancel)?;
        let mut unindexed = bounded_vec(self.selection.unindexed.len())?;
        unindexed.extend(self.selection.unindexed.iter().cloned());
        self.done = true;
        Ok(WindowProgress::Complete(RangeReceipt { catalog_root: self.catalog.manifest.root(),
            scope: self.catalog.scope.clone(), query: self.selection.query.clone(), windows: self.next,
            output_bytes: self.returned_bytes, unindexed }))
    }
}

// The private sum is never returned by a public API. Its variant is fixed by
// the typed catalog constructor; network/disk metadata cannot select a verifier.
enum LoadedWindow { Avc(PreparedRecording), Hevc(PreparedHevcRecording) }
impl LoadedWindow {
    fn plan(&self) -> &PreparedRecording {
        match self { Self::Avc(plan) => plan, Self::Hevc(plan) => plan.publication_plan() }
    }
}
enum WindowProgress {
    Window { ordinal: usize, requested_interval: Range<u64>, recording: LoadedWindow },
    Complete(RangeReceipt),
    Exhausted,
}
fn load_window(publisher: &LocalRootPublisher, catalog: &RecordingCatalog,
    entry: &CatalogEntry, cancel: &dyn PublishCancellation) -> IoResult<LoadedWindow>
{
    Ok(match catalog.family {
        CatalogFamily::Avc => LoadedWindow::Avc(load_recording(
            publisher, &entry.slot, entry.root, &catalog.scope.recording, cancel)?),
        CatalogFamily::Hevc => LoadedWindow::Hevc(load_hevc_recording(
            publisher, &entry.slot, entry.root, &catalog.scope.recording, cancel)?),
    })
}

#[derive(Debug)]
struct RequestClock { deadline_ns: u64, last_ns: Option<u64>, stopped: bool }
impl RequestClock {
    fn new(deadline_ns: u64) -> IoResult<Self> {
        if deadline_ns == 0 { return Err(RecordingIoError::Deadline.into()); }
        Ok(Self { deadline_ns, last_ns: None, stopped: false })
    }
    fn admit(&mut self, now_ns: u64, cancel: &dyn PublishCancellation) -> IoResult<()> {
        if self.stopped { return Err(RecordingIoError::Stopped.into()); }
        if self.last_ns.is_some_and(|last| now_ns < last) { return Err(RecordingIoError::ClockReversed.into()); }
        self.last_ns = Some(now_ns);
        if now_ns >= self.deadline_ns { self.stopped = true; return Err(RecordingIoError::Deadline.into()); }
        if let Err(e) = cancelled(cancel) { self.stopped = true; return Err(e); }
        Ok(())
    }
}
fn cancelled(cancel: &dyn PublishCancellation) -> IoResult<()> {
    if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) { return Err(RecordingIoError::Cancelled.into()); }
    Ok(())
}
fn owner_ready(p: &LocalRootPublisher) -> IoResult<()> {
    if p.is_poisoned() { return Err(RecordingIoError::ReopenRequired.into()); }
    if p.limits().spool.max_object_bytes > MAX_RECORDING_BYTES { return Err(RecordingIoError::Budget.into()); }
    Ok(())
}
fn durable_root(p: &LocalRootPublisher, slot: &SlotName, root: ContentDigest) -> IoResult<()> {
    let known = p.root(slot).ok_or(RecordingIoError::NotDurable)?;
    if known.root != root { return Err(RecordingIoError::RootConflict.into()); }
    if known.state != LocalPublicationState::Durable { return Err(RecordingIoError::NotDurable.into()); }
    if p.tombstones().any(|d| *d == root) { return Err(RecordingIoError::Tombstoned.into()); }
    Ok(())
}
fn live_catalog(p: &LocalRootPublisher, slot: &SlotName, catalog: &RecordingCatalog,
    cancel: &dyn PublishCancellation) -> IoResult<()>
{
    cancelled(cancel)?; owner_ready(p)?; durable_root(p, slot, catalog.manifest.root())?;
    for entry in &catalog.entries { durable_root(p, &entry.slot, entry.root)?; }
    for tombstone in p.tombstones() {
        if catalog.manifest.children().binary_search(tombstone).is_ok() { return Err(RecordingIoError::Tombstoned.into()); }
    }
    Ok(())
}
fn read_object(p: &LocalRootPublisher, digest: ContentDigest, cancel: &dyn PublishCancellation) -> IoResult<Vec<u8>> {
    cancelled(cancel)?;
    if p.tombstones().any(|d| *d == digest) { return Err(RecordingIoError::Tombstoned.into()); }
    p.spool().read(digest).map_err(|e| RecordingIoError::Spool(e).into())
}

impl std::fmt::Debug for CatalogPublication<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CatalogPublication").field("root", &self.catalog.manifest.root())
            .field("next", &self.next).field("done", &self.done).finish_non_exhaustive()
    }
}
impl std::fmt::Debug for RecordingRangeRead<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingRangeRead").field("root", &self.catalog.manifest.root())
            .field("returned_windows", &self.next).field("done", &self.done).finish_non_exhaustive()
    }
}
