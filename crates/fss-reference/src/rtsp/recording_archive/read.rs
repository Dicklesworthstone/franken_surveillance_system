#![forbid(unsafe_code)]
//! Whole-window, cross-page retrieval from a fixed recovered inventory.

use super::*;
use std::ops::Range;

/// Atomic query bounds; exceeding either refuses rather than truncates the answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveQueryLimits {
    /// Complete windows selected across all published pages.
    pub max_windows: usize,
    /// Sum of complete recording payload bytes, not syscall traffic or RSS.
    pub max_output_bytes: u64,
}
impl Default for ArchiveQueryLimits {
    fn default() -> Self { Self { max_windows: 64, max_output_bytes: 256 * 1024 * 1024 } }
}
/// Metadata-only selection, not a media verification or absence receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveSelection {
    snapshot: ContentDigest,
    query: Range<u64>,
    ordinals: Vec<usize>,
    unindexed: Vec<Range<u64>>,
    bytes: u64,
}
impl ArchiveSelection {
    /// Exact inventory against which the query was selected.
    pub fn snapshot_digest(&self) -> ContentDigest { self.snapshot }
    /// Selected recording ordinals, never byte-level edits of a window.
    pub fn ordinals(&self) -> &[usize] { &self.ordinals }
    /// All query intervals absent from published pages; never physical absence evidence.
    pub fn unindexed(&self) -> &[Range<u64>] { &self.unindexed }
    /// Advertised whole-window output, rechecked before returning media.
    pub fn output_bytes(&self) -> u64 { self.bytes }
}
impl<C: ArchiveCodec> CodecArchiveSnapshot<C> {
    /// Query every published page in one fixed bounded snapshot. Durable-but-unindexed
    /// tail windows remain explicitly unindexed until a catalog is actually published.
    pub fn select(&self, query: Range<u64>, limits: ArchiveQueryLimits) -> ArchiveResult<ArchiveSelection> {
        if query.start >= query.end { return Err(CatalogError::Interval.into()); }
        if limits.max_windows == 0 || limits.max_windows > MAX_ARCHIVE_WINDOWS
            || limits.max_output_bytes == 0
            || limits.max_output_bytes > MAX_ARCHIVE_WINDOWS as u64 * MAX_RECORDING_BYTES as u64 {
            return Err(ArchiveError::Limit);
        }
        let mut ordinals = bounded_vec(self.indexed.min(limits.max_windows))?;
        let mut unindexed = bounded_vec(self.indexed + 1)?;
        let mut cursor = query.start; let mut bytes = 0_u64;
        for (ordinal, entry) in self.windows[..self.indexed].iter().enumerate() {
            let interval = entry.decode_interval();
            let start = query.start.max(interval.start); let end = query.end.min(interval.end);
            if start >= end { continue; }
            if ordinals.len() == limits.max_windows { return Err(ArchiveError::Limit); }
            bytes = bytes.checked_add(entry.byte_len() as u64).ok_or(ArchiveError::Limit)?;
            if bytes > limits.max_output_bytes { return Err(ArchiveError::Limit); }
            if cursor < start { unindexed.push(cursor..start); }
            ordinals.push(ordinal); cursor = end;
        }
        if cursor < query.end { unindexed.push(cursor..query.end); }
        Ok(ArchiveSelection { snapshot: self.digest()?, query, ordinals, unindexed, bytes })
    }
}

/// Point-in-time accounting, not a future availability or camera-coverage certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveReadReceipt {
    /// Recovered inventory identity, explicitly not a published authority root.
    pub snapshot_digest: ContentDigest,
    /// Exact stream and decode-clock basis.
    pub scope: CatalogScope,
    /// Original half-open query.
    pub query: Range<u64>,
    /// Complete windows transferred after original-byte verification.
    pub windows: usize,
    /// Actual complete-window payload bytes returned.
    pub output_bytes: u64,
    /// All intervals unindexed by published pages in the selected snapshot.
    pub unindexed: Vec<Range<u64>>,
}
/// One incremental cross-page output; only Complete settles the whole query.
#[derive(Debug)]
pub enum ArchiveReadProgress<C: ArchiveCodec = AvcArchiveCodec> {
    /// Complete original window plus the requested overlap, not a cropped rendition.
    Window {
        /// Zero-based ordinal of the loaded window in the queried snapshot.
        ordinal: usize,
        /// Exactly the requested decode interval, including any requested overlap.
        requested_interval: Range<u64>,
        /// Fully verified original window bytes for that interval.
        recording: C::Recording,
    },
    /// Every selected window has been verified and transferred exactly once.
    Complete(Box<ArchiveReadReceipt>),
    /// Completion was already returned; no fresh verification took place.
    Exhausted,
}
/// One source-verified window per step. Earlier outputs stay caller-owned after a
/// later refusal; a cancelled or failed attempt never emits aggregate success.
pub type ArchiveRead<'a> = CodecArchiveRead<'a, AvcArchiveCodec>;

/// Shared request implementation; public aliases pin the verifier at compile time.
#[doc(hidden)]
pub struct CodecArchiveRead<'a, C: ArchiveCodec> {
    publisher: &'a LocalRootPublisher,
    snapshot: &'a CodecArchiveSnapshot<C>,
    selection: ArchiveSelection,
    next: usize,
    bytes: u64,
    deadline_ns: u64,
    last_ns: Option<u64>,
    blocked: bool,
    done: bool,
}
impl<'a, C: ArchiveCodec> CodecArchiveRead<'a, C> {
    /// The caller separately authorizes WHOLE selected windows. A time query is not
    /// a privacy filter. The supplied owner must be the one that holds these roots.
    pub fn new(publisher: &'a LocalRootPublisher, snapshot: &'a CodecArchiveSnapshot<C>,
        query: Range<u64>, limits: ArchiveQueryLimits, deadline_ns: u64) -> ArchiveResult<Self>
    {
        owner_ready(publisher)?;
        if deadline_ns == 0 { return Err(ArchiveError::Deadline); }
        let selection = snapshot.select(query, limits)?;
        Ok(Self { publisher, snapshot, selection, next: 0, bytes: 0, deadline_ns,
            last_ns: None, blocked: false, done: false })
    }
    /// Pure selection only, not an aggregate successful read.
    pub fn selection(&self) -> &ArchiveSelection { &self.selection }
    /// Number already transferred, including after a later failure.
    pub fn returned_windows(&self) -> usize { self.next }
    /// Supplied time controls admission. The cancellation probe must also check live
    /// deadlines/revocation at read boundaries, not merely the entry timestamp.
    pub fn step(&mut self, now_ns: u64, cancel: &dyn PublishCancellation) -> ArchiveResult<ArchiveReadProgress<C>> {
        if self.done { return Ok(ArchiveReadProgress::Exhausted); }
        if self.blocked { return Err(ArchiveError::Blocked); }
        if self.last_ns.is_some_and(|last| now_ns < last) { return Err(ArchiveError::ClockReversed); }
        self.last_ns = Some(now_ns);
        if now_ns >= self.deadline_ns { self.blocked = true; return Err(ArchiveError::Deadline); }
        let result = probe(cancel).and_then(|()| self.advance(cancel));
        if result.is_err() { self.blocked = true; }
        result
    }
    fn advance(&mut self, cancel: &dyn PublishCancellation) -> ArchiveResult<ArchiveReadProgress<C>> {
        owner_ready(self.publisher)?;
        if let Some(&ordinal) = self.selection.ordinals.get(self.next) {
            let entry = &self.snapshot.windows[ordinal];
            let page = self.snapshot.pages.iter().find(|p| ordinal >= p.first
                && ordinal < p.first + C::entries(&p.catalog).len()).ok_or(ArchiveError::Metadata)?;
            // Recheck the selected catalog before returning its original media.
            let loaded = C::load_catalog(self.publisher, &page.slot, C::manifest(&page.catalog).root(),
                &self.snapshot.namespace.scope, cancel)?;
            if C::index(&loaded) != C::index(&page.catalog) { return Err(ArchiveError::Metadata); }
            let recording = C::load_recording(self.publisher, entry.slot(), entry.root(),
                &self.snapshot.namespace.scope.recording, cancel)?;
            verify_descriptor_for::<C>(&self.snapshot.namespace.scope, entry, &recording)?;
            probe(cancel)?;
            let bytes = self.bytes.checked_add(C::plan(&recording).byte_len() as u64).ok_or(ArchiveError::Limit)?;
            if bytes > self.selection.bytes { return Err(ArchiveError::Limit); }
            let interval = entry.decode_interval();
            let requested_interval = self.selection.query.start.max(interval.start)..self.selection.query.end.min(interval.end);
            self.bytes = bytes; self.next += 1;
            return Ok(ArchiveReadProgress::Window { ordinal, requested_interval, recording });
        }
        if self.bytes != self.selection.bytes { return Err(ArchiveError::Metadata); }
        // Also fence empty answers and pages which only contributed an unindexed gap.
        for page in &self.snapshot.pages {
            let loaded = C::load_catalog(self.publisher, &page.slot, C::manifest(&page.catalog).root(),
                &self.snapshot.namespace.scope, cancel)?;
            if C::index(&loaded) != C::index(&page.catalog) { return Err(ArchiveError::Metadata); }
        }
        probe(cancel)?;
        let mut unindexed = bounded_vec(self.selection.unindexed.len())?;
        unindexed.extend(self.selection.unindexed.iter().cloned());
        self.done = true;
        Ok(ArchiveReadProgress::Complete(Box::new(ArchiveReadReceipt { snapshot_digest: self.selection.snapshot,
            scope: self.snapshot.namespace.scope.clone(), query: self.selection.query.clone(),
            windows: self.next, output_bytes: self.bytes, unindexed })))
    }
}
impl<C: ArchiveCodec> std::fmt::Debug for CodecArchiveRead<'_, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveRead").field("returned_windows", &self.next)
            .field("blocked", &self.blocked).field("done", &self.done).finish_non_exhaustive()
    }
}
