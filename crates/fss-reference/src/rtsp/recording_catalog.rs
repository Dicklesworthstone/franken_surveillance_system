#![forbid(unsafe_code)]
//! Immutable, owner-scoped discovery of recorded decode-time ranges.
//!
//! A catalog is not camera coverage, a capture-time mapping, or permission to
//! disclose footage. Its index is structurally verified independently of the
//! original-packet verification performed for each retrieved recording window.

/// Publication, reopening, and incremental verified retrieval through an existing owner.
pub mod local;
mod wire;

use std::ops::Range;
use fss_core::{CanonicalEncode, ContentDigest};
use fss_object::ObjectManifest;
use fss_publication::SlotName;
use super::recording::{PreparedRecording, RecordingScope, MAX_RECORDING_BYTES,
    MAX_RECORDING_MAPPINGS, MAX_RECORDING_PACKETS, MAX_RECORDING_SAMPLES};

/// A page never scans or returns more than this many independently sealed windows.
pub const MAX_CATALOG_WINDOWS: usize = 64;
/// Combined canonical index and root-manifest payload limit.
pub const MAX_CATALOG_BYTES: usize = 64 * 1024;
/// Typed manifest family. The index is its metadata child.
pub const CATALOG_KIND: &str = "avc_recording_catalog_v1";

/// Owner-supplied time basis. Receive-clock identity alone does not identify DTS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogScope {
    /// Exact sensor, stream epoch, authority anchor, and original receive clock.
    pub recording: RecordingScope,
    /// Explicit owner identity for the decode timeline, not inferred from RTP.
    pub decode_clock: ContentDigest,
    /// Tick rate shared by every window and query in this page.
    pub time_scale: u32,
}

/// Borrowed verified recording and its exact existing local slot.
pub struct CatalogWindow<'a> {
    /// Local routing hint; the expected root, not this name, pins content.
    pub slot: &'a SlotName,
    /// Immutable recording prepared or fully reverified by the recording API.
    pub recording: &'a PreparedRecording,
}

/// Payload-free pure catalog refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogError {
    /// Scope, timeline basis, stream epoch, or tick rate differs.
    Scope,
    /// A fixed count, byte, allocation, or output-selection ceiling was reached.
    Limit,
    /// Unsupported, truncated, noncanonical, or inconsistent index.
    Malformed,
    /// Checksum, child closure, or expected content identity differs.
    Digest,
    /// Windows overlap, are unordered, or repeat a root or slot.
    Order,
    /// Empty/reversed query or window decode interval.
    Interval,
    /// Fully loaded window disagrees with its catalog descriptor.
    WindowMismatch,
}
impl std::fmt::Display for CatalogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "recording catalog refusal: {self:?}")
    }
}
impl std::error::Error for CatalogError {}

type Result<T> = std::result::Result<T, CatalogError>;

/// Immutable index metadata, not a fresh proof that the named bytes are retrievable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogEntry {
    slot: SlotName,
    root: ContentDigest,
    interval: Range<u64>,
    packets: usize,
    samples: usize,
    nals: usize,
    bytes: usize,
    // Role order: original source, initialization, media, canonical window index.
    objects: [ContentDigest; 4],
}
impl CatalogEntry {
    /// Exact local slot that must still bind the expected root on retrieval.
    pub fn slot(&self) -> &SlotName { &self.slot }
    /// Immutable recording root, not a directory/name-based content guess.
    pub fn root(&self) -> ContentDigest { self.root }
    /// Half-open decode interval in the page's explicitly declared time basis.
    pub fn decode_interval(&self) -> Range<u64> { self.interval.clone() }
    /// Advertised complete recording payload including its root, rechecked on read.
    pub fn byte_len(&self) -> usize { self.bytes }
    /// Advertised primary-picture groups; these are not decoded-completeness certificates.
    pub fn samples(&self) -> usize { self.samples }

    fn from_window(slot: &SlotName, recording: &PreparedRecording) -> Self {
        let s = recording.summary();
        Self { slot: slot.clone(), root: s.root, interval: s.decode_interval.clone(),
            packets: s.packets, samples: s.samples, nals: s.nals, bytes: recording.byte_len(),
            objects: recording.children().map(|(_, digest, _)| digest) }
    }
    fn verify_window(&self, scope: &CatalogScope, recording: &PreparedRecording) -> Result<()> {
        if recording.summary().scope != scope.recording || recording.summary().time_scale != scope.time_scale {
            return Err(CatalogError::Scope);
        }
        if self != &Self::from_window(&self.slot, recording) { return Err(CatalogError::WindowMismatch); }
        Ok(())
    }
}

/// Immutable, checksummed discovery page. Original-window validation is separate.
/// Publish pages in distinct slots; this API neither overwrites an old page nor
/// invents an unbounded linked list or a mutable "latest" pointer.
pub struct RecordingCatalog {
    scope: CatalogScope,
    entries: Vec<CatalogEntry>,
    index: Vec<u8>,
    manifest: ObjectManifest,
}
impl std::fmt::Debug for RecordingCatalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingCatalog").field("root", &self.manifest.root())
            .field("windows", &self.entries.len()).finish_non_exhaustive()
    }
}
impl RecordingCatalog {
    /// Root-last manifest, including every window root AND every referenced leaf.
    pub fn manifest(&self) -> &ObjectManifest { &self.manifest }
    /// Exact canonical metadata bytes, without source/media payload.
    pub fn index_bytes(&self) -> &[u8] { &self.index }
    /// Exact owner-supplied scope and decode clock.
    pub fn scope(&self) -> &CatalogScope { &self.scope }
    /// Chronologically ordered nonoverlapping recording descriptors.
    pub fn entries(&self) -> &[CatalogEntry] { &self.entries }
    /// New catalog payload only; already archived recording objects are not recopied.
    pub fn byte_len(&self) -> usize { self.index.len() + self.manifest.canonical_bytes().len() }

    /// Select complete IDR-led windows that overlap the query. Never crop encoded
    /// bytes or silently truncate a response to meet a budget. Unindexed intervals
    /// are explicit, including outside this page; none is evidence of physical absence.
    pub fn select(&self, query: Range<u64>, limits: CatalogQueryLimits) -> Result<CatalogSelection> {
        limits.validate()?;
        if query.start >= query.end { return Err(CatalogError::Interval); }
        let mut selected = bounded_vec(self.entries.len())?;
        let mut unindexed = bounded_vec(self.entries.len() + 1)?;
        let mut cursor = query.start;
        let mut bytes = 0_u64;
        for (ordinal, entry) in self.entries.iter().enumerate() {
            let start = query.start.max(entry.interval.start);
            let end = query.end.min(entry.interval.end);
            if start >= end { continue; }
            if selected.len() == limits.max_windows { return Err(CatalogError::Limit); }
            bytes = bytes.checked_add(entry.bytes as u64).ok_or(CatalogError::Limit)?;
            if bytes > limits.max_output_bytes { return Err(CatalogError::Limit); }
            if cursor < start { unindexed.push(cursor..start); }
            selected.push(SelectedWindow { ordinal, interval: start..end });
            cursor = end;
        }
        if cursor < query.end { unindexed.push(cursor..query.end); }
        Ok(CatalogSelection { root: self.manifest.root(), query, selected, unindexed, bytes })
    }
}

/// Independent selection/output bounds. They are not a promise about filesystem
/// metadata reads, hashing CPU, or allocator overhead; local reads have separate bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogQueryLimits {
    /// Refuse, rather than silently paginate, a query touching more windows.
    pub max_windows: usize,
    /// Maximum sum of complete recording payloads returned, including their roots.
    pub max_output_bytes: u64,
}
impl Default for CatalogQueryLimits {
    fn default() -> Self {
        Self { max_windows: MAX_CATALOG_WINDOWS, max_output_bytes: 256 * 1024 * 1024 }
    }
}
impl CatalogQueryLimits {
    fn validate(self) -> Result<()> {
        if !(1..=MAX_CATALOG_WINDOWS).contains(&self.max_windows) || self.max_output_bytes == 0
            || self.max_output_bytes > (MAX_CATALOG_WINDOWS * MAX_RECORDING_BYTES) as u64 {
            return Err(CatalogError::Limit);
        }
        Ok(())
    }
}

/// A whole-window selection with a requested subinterval, not a byte-level edit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedWindow {
    ordinal: usize,
    interval: Range<u64>,
}
impl SelectedWindow {
    /// Index into this exact catalog's entries, not another page's cursor.
    pub fn ordinal(&self) -> usize { self.ordinal }
    /// Requested overlap; the retriever still returns the complete original window.
    pub fn requested_interval(&self) -> Range<u64> { self.interval.clone() }
}

/// Pure index answer, not a successful media-read receipt or a coverage witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogSelection {
    root: ContentDigest,
    query: Range<u64>,
    selected: Vec<SelectedWindow>,
    unindexed: Vec<Range<u64>>,
    bytes: u64,
}
impl CatalogSelection {
    /// Exact immutable catalog against which the query was evaluated.
    pub fn catalog_root(&self) -> ContentDigest { self.root }
    /// Original half-open query in the declared decode clock.
    pub fn query(&self) -> Range<u64> { self.query.clone() }
    /// Ordered complete windows selected for subsequent verification.
    pub fn windows(&self) -> &[SelectedWindow] { &self.selected }
    /// Parts of the query not indexed by this page; never camera-coverage evidence.
    pub fn unindexed(&self) -> &[Range<u64>] { &self.unindexed }
    /// Advertised complete-window output bytes, rechecked by the reader.
    pub fn output_bytes(&self) -> u64 { self.bytes }
}

/// Prepare a bounded chronological page from already verified recording values.
/// The caller owns the decode-clock assertion and separately authorizes catalog
/// retention. Preparation performs no I/O and asserts no publication success.
pub fn prepare_catalog(scope: CatalogScope, windows: &[CatalogWindow<'_>]) -> Result<RecordingCatalog> {
    if windows.is_empty() || windows.len() > MAX_CATALOG_WINDOWS { return Err(CatalogError::Limit); }
    let mut entries = bounded_vec(windows.len())?;
    for window in windows {
        if window.recording.summary().scope != scope.recording
            || window.recording.summary().time_scale != scope.time_scale { return Err(CatalogError::Scope); }
        entries.push(CatalogEntry::from_window(window.slot, window.recording));
    }
    validate(&scope, &entries)?;
    let index = wire::encode(&scope, &entries)?;
    let manifest = manifest(&entries, digest(&index)?)?;
    if index.len() + manifest.canonical_bytes().len() > MAX_CATALOG_BYTES { return Err(CatalogError::Limit); }
    Ok(RecordingCatalog { scope, entries, index, manifest })
}

/// Verify checksum, canonical fields, expected owner time basis, and exact flat
/// reference closure. This deliberately does not claim to read the named windows.
pub fn verify_catalog(manifest_value: &ObjectManifest, index: &[u8], expected: &CatalogScope)
    -> Result<RecordingCatalog>
{
    if index.len().checked_add(manifest_value.canonical_bytes().len())
        .is_none_or(|n| n > MAX_CATALOG_BYTES) { return Err(CatalogError::Limit); }
    let (scope, entries) = wire::decode(index)?;
    if &scope != expected { return Err(CatalogError::Scope); }
    validate(&scope, &entries)?;
    if manifest(&entries, digest(index)?)? != *manifest_value { return Err(CatalogError::Digest); }
    if wire::encode(&scope, &entries)? != index { return Err(CatalogError::Malformed); }
    let mut owned = bounded_vec(index.len())?;
    owned.extend_from_slice(index);
    Ok(RecordingCatalog { scope, entries, index: owned, manifest: manifest_value.clone() })
}

fn validate(scope: &CatalogScope, entries: &[CatalogEntry]) -> Result<()> {
    if scope.recording.generation == 0 || scope.time_scale == 0 { return Err(CatalogError::Scope); }
    if entries.is_empty() || entries.len() > MAX_CATALOG_WINDOWS { return Err(CatalogError::Limit); }
    for (i, e) in entries.iter().enumerate() {
        if e.interval.start >= e.interval.end { return Err(CatalogError::Interval); }
        if e.packets == 0 || e.packets > MAX_RECORDING_PACKETS || e.samples == 0 || e.samples > MAX_RECORDING_SAMPLES
            || e.nals == 0 || e.nals > MAX_RECORDING_MAPPINGS || e.bytes == 0 || e.bytes > MAX_RECORDING_BYTES {
            return Err(CatalogError::Limit);
        }
        if e.root.algorithm() != fss_core::DigestAlgorithm::Sha256
            || e.objects.iter().any(|d| d.algorithm() != fss_core::DigestAlgorithm::Sha256) {
            return Err(CatalogError::Digest);
        }
        // A descriptor must name the exact standard recording manifest, not an
        // arbitrary object that merely happens to have plausible time/count fields.
        let window = ObjectManifest::new(super::recording::RECORDING_KIND,
            [e.objects[0], e.objects[1], e.objects[2]], Some(e.objects[3]))
            .map_err(|_| CatalogError::Digest)?;
        if window.root() != e.root { return Err(CatalogError::Digest); }
        if i > 0 && entries[i - 1].interval.end > e.interval.start
            || entries[..i].iter().any(|p| p.root == e.root || p.slot == e.slot) { return Err(CatalogError::Order); }
    }
    Ok(())
}
fn manifest(entries: &[CatalogEntry], index: ContentDigest) -> Result<ObjectManifest> {
    let mut closure = bounded_vec(entries.len() * 5)?;
    for e in entries { closure.push(e.root); closure.extend_from_slice(&e.objects); }
    closure.sort_unstable(); closure.dedup();
    // Flatten leaf references so tombstoning any source/derivative invalidates this
    // catalog even when a child root is unavailable to the publisher's descent.
    ObjectManifest::new(CATALOG_KIND, closure, Some(index)).map_err(|_| CatalogError::Digest)
}
fn digest(bytes: &[u8]) -> Result<ContentDigest> {
    ContentDigest::try_sha256(bytes).map_err(|_| CatalogError::Limit)
}
fn bounded_vec<T>(capacity: usize) -> Result<Vec<T>> {
    let mut v = Vec::new();
    v.try_reserve_exact(capacity).map_err(|_| CatalogError::Limit)?;
    Ok(v)
}
