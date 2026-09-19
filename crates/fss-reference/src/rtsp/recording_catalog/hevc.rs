#![forbid(unsafe_code)]
//! Codec-pinned HEVC discovery over the existing bounded recording catalog core.
//!
//! The public type admits only replay-verified HEVC recordings. Untrusted
//! metadata cannot choose the codec, the window verifier, or the decode clock.

use super::*;
use crate::rtsp::recording::hevc::PreparedHevcRecording;

/// Separate immutable manifest family; the AVC catalog contract is unchanged.
pub const HEVC_CATALOG_KIND: &str = "hevc_recording_catalog_v1";

/// Borrowed source-replay-verified HEVC window and its exact storage slot.
pub struct HevcCatalogWindow<'a> {
    /// Routing hint, never a substitute for the immutable expected root.
    pub slot: &'a SlotName,
    /// Prepared or fully replay-verified HEVC recording; no AVC fallback.
    pub recording: &'a PreparedHevcRecording,
}

/// Bounded HEVC discovery page. Its private shared core cannot escape as an AVC
/// catalog or accept a caller-supplied verifier. This is metadata, not custody.
pub struct HevcRecordingCatalog(pub(super) RecordingCatalog);
impl std::fmt::Debug for HevcRecordingCatalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HevcRecordingCatalog").field("root", &self.manifest().root())
            .field("windows", &self.entries().len()).finish_non_exhaustive()
    }
}
impl HevcRecordingCatalog {
    /// Exact root with every window root and all its source/derivative leaves.
    pub fn manifest(&self) -> &ObjectManifest { self.0.manifest() }
    /// Versioned, checksummed canonical HEVC metadata, without media bytes.
    pub fn index_bytes(&self) -> &[u8] { self.0.index_bytes() }
    /// Owner-declared recording and decode-clock basis; no RTP time inference.
    pub fn scope(&self) -> &CatalogScope { self.0.scope() }
    /// Chronological nonoverlapping window descriptors, not fresh read receipts.
    pub fn entries(&self) -> &[CatalogEntry] { self.0.entries() }
    /// Newly retained catalog payload only; window bytes are not copied here.
    pub fn byte_len(&self) -> usize { self.0.byte_len() }
    /// Select complete IDR-led windows under the shared count/byte ceilings.
    /// Requested overlaps are metadata only; encoded windows are never cropped.
    /// Unindexed intervals are not evidence of physical/event absence.
    pub fn select(&self, query: Range<u64>, limits: CatalogQueryLimits) -> Result<CatalogSelection> {
        self.0.select(query, limits)
    }
}

/// Metadata-only construction: push/drop each large source window independently.
#[derive(Debug)]
pub struct HevcCatalogBuilder(CatalogBuilder);
impl HevcCatalogBuilder {
    /// Pin the exact owner scope before any admission. No I/O authority is created.
    pub fn new(scope: CatalogScope) -> Result<Self> {
        CatalogBuilder::new_for(scope, CatalogFamily::Hevc).map(Self)
    }
    /// Number of retained metadata descriptors.
    pub fn len(&self) -> usize { self.0.len() }
    /// Whether no window has been selected.
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
    /// Add an immutable replay-verified HEVC window, without consuming it.
    /// Wrong scope, overlapping time, duplicate root/slot or limits leave state intact.
    pub fn push(&mut self, slot: &SlotName, recording: &PreparedHevcRecording) -> Result<()> {
        self.0.push(slot, recording.publication_plan())
    }
    /// Seal the fixed page. This neither publishes nor establishes retrievability.
    pub fn prepare(self) -> Result<HevcRecordingCatalog> {
        self.0.prepare().map(HevcRecordingCatalog)
    }
}

/// Build one bounded HEVC page from already verified recordings, without I/O.
pub fn prepare_hevc_catalog(scope: CatalogScope, windows: &[HevcCatalogWindow<'_>])
    -> Result<HevcRecordingCatalog>
{
    if windows.is_empty() || windows.len() > MAX_CATALOG_WINDOWS { return Err(CatalogError::Limit); }
    let mut builder = HevcCatalogBuilder::new(scope)?;
    for window in windows { builder.push(window.slot, window.recording)?; }
    builder.prepare()
}

/// Check canonical encoding, checksum, exact flat object closure, codec family
/// and externally supplied time/scope basis before returning a discovery page.
/// Window provenance is verified separately on retrieval; this is not a read receipt.
pub fn verify_hevc_catalog(manifest: &ObjectManifest, index: &[u8], expected: &CatalogScope)
    -> Result<HevcRecordingCatalog>
{
    verify_catalog_for(manifest, index, expected, CatalogFamily::Hevc).map(HevcRecordingCatalog)
}
