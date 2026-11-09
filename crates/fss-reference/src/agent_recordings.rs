#![forbid(unsafe_code)]
//! Bounded, read-only discovery of exactly pinned native AVC/HEVC recording metadata.
//!
//! One canonical catalog supplies byte-free handles, native decode-clock overlaps, indexed
//! gaps, and the cost of later whole-window hydration. No original packets, initialization,
//! media, or per-window index are read. Catalog and member publication slots, metadata, and
//! local tombstone absence are revalidated under one nonrefillable request allowance.
//! Neither a catalog interval nor a local root record proves camera coverage, payload
//! availability, UTC time, a current deployment belief, or disclosure authority.

/// Bounded metadata discovery within an exact native archive source namespace.
pub mod discover;
/// Bounded discovery over an explicitly pinned catalog set in one decode-clock scope.
pub mod set;
/// Conditional UTC candidates from independently pinned retained clock metadata.
pub mod utc;
/// Conditional UTC candidates across an explicitly pinned catalog set and one clock index.
pub mod utc_set;

use std::collections::BTreeSet;
use std::fmt;
use std::ops::Range;
use std::path::Path;

use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_object::SpoolIo;
use fss_publication::SlotName;
use fss_publication::custody_audit::CustodyAuditLimits;
pub use fss_publication::custody_audit::pinned_metadata::MetadataReadUsage;
use fss_publication::custody_audit::pinned_metadata::{PinnedMetadataError, PinnedMetadataReader};

use crate::rtsp::recording::hevc::HEVC_RECORDING_KIND;
use crate::rtsp::recording::{MAX_RECORDING_BYTES, RECORDING_KIND};
use crate::rtsp::recording_catalog::hevc::{HEVC_CATALOG_KIND, verify_hevc_catalog};
use crate::rtsp::recording_catalog::{
    CATALOG_KIND, CatalogEntry, CatalogError, CatalogQueryLimits, CatalogScope, CatalogSelection,
    MAX_CATALOG_BYTES, MAX_CATALOG_WINDOWS, verify_catalog,
};

/// Codec selection is a caller pin, never inferred from untrusted stored metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordingQueryCodec {
    /// Native source-replay-verifiable AVC recording family.
    Avc,
    /// Native source-replay-verifiable HEVC recording family.
    Hevc,
}
impl RecordingQueryCodec {
    /// Stable wire/display spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Avc => "avc",
            Self::Hevc => "hevc",
        }
    }
    const fn catalog_kind(self) -> &'static str {
        match self {
            Self::Avc => CATALOG_KIND,
            Self::Hevc => HEVC_CATALOG_KIND,
        }
    }
    const fn window_kind(self) -> &'static str {
        match self {
            Self::Avc => RECORDING_KIND,
            Self::Hevc => HEVC_RECORDING_KIND,
        }
    }
}

/// Exact immutable metadata and timeline pins. Paths and current deployment authority are
/// supplied by the caller's protected context, independently of this historical scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingQueryRequest {
    /// Native codec family; no fallback to another codec.
    pub codec: RecordingQueryCodec,
    /// Exact original sensor, stream generation, anchor, receive clock, decode clock and rate.
    pub scope: CatalogScope,
    /// Exact local publication slot; no directory discovery or arbitrary object lookup.
    pub catalog_slot: SlotName,
    /// Immutable expected catalog root; a slot name alone is insufficient.
    pub catalog_root: ContentDigest,
    /// Half-open interval in the declared native decode clock, never UTC or RTP inference.
    pub interval: Range<u64>,
    /// Maximum complete windows selected; excess refuses atomically instead of truncating.
    pub max_windows: usize,
    /// Upper bound on quoted later whole-window hydration, not bytes read by this query.
    pub max_hydration_bytes: u64,
}
impl RecordingQueryRequest {
    /// Validate all caller pins before any filesystem access.
    pub fn validate(&self) -> Result<()> {
        let recording = &self.scope.recording;
        if recording.generation == 0
            || self.scope.time_scale == 0
            || self.interval.start >= self.interval.end
            || !(1..=MAX_CATALOG_WINDOWS).contains(&self.max_windows)
            || self.max_hydration_bytes == 0
            || self.max_hydration_bytes > (MAX_CATALOG_WINDOWS * MAX_RECORDING_BYTES) as u64
            || [
                self.catalog_root,
                recording.anchor,
                recording.receive_clock,
                self.scope.decode_clock,
            ]
            .iter()
            .any(|digest| !sha(*digest))
        {
            return Err(RecordingQueryError::InvalidRequest);
        }
        Ok(())
    }

    /// Canonical request identity binds the semantic query and every nonrefillable allowance.
    pub fn request_digest(&self, limits: RecordingQueryLimits) -> Result<ContentDigest> {
        self.validate()?;
        limits.validate()?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.agent_recordings.request.v1");
        encoder.text(self.codec.as_str());
        encoder.text(self.catalog_slot.as_str());
        encoder.digest(self.catalog_root);
        let recording = &self.scope.recording;
        encoder.text(recording.sensor.as_str());
        encoder.text(recording.stream.as_str());
        encoder.u64(recording.generation);
        encoder.digest(recording.anchor);
        encoder.digest(recording.receive_clock);
        encoder.digest(self.scope.decode_clock);
        encoder.u32(self.scope.time_scale);
        encoder.u64(self.interval.start);
        encoder.u64(self.interval.end);
        encoder.u64(self.max_windows as u64);
        encoder.u64(self.max_hydration_bytes);
        for limit in [
            limits.metadata.max_catalogue_entries as u64,
            limits.metadata.max_objects as u64,
            limits.metadata.max_edges as u64,
            limits.metadata.max_object_bytes as u64,
            limits.metadata.max_read_bytes,
            limits.metadata.max_io_calls,
        ] {
            encoder.u64(limit);
        }
        Ok(ContentDigest::sha256(&encoder.finish()))
    }
}

/// Separate metadata-read limits; no hydration occurs or consumes the quoted source-byte cost.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordingQueryLimits {
    /// One allowance shared by every catalog/member read and the complete revalidation pass.
    pub metadata: CustodyAuditLimits,
}
impl Default for RecordingQueryLimits {
    fn default() -> Self {
        Self {
            metadata: CustodyAuditLimits {
                max_catalogue_entries: MAX_CATALOG_WINDOWS + 1,
                max_objects: 2 * (MAX_CATALOG_WINDOWS + 1),
                max_edges: 1024,
                max_object_bytes: MAX_CATALOG_BYTES,
                max_read_bytes: 8 * 1024 * 1024,
                max_io_calls: 10_000,
            },
        }
    }
}
impl RecordingQueryLimits {
    /// Finite native-query ceilings. Zero allowances fail when corresponding work is attempted.
    pub fn validate(self) -> Result<()> {
        let maximum = Self::default().metadata;
        let limits = self.metadata;
        if limits.max_catalogue_entries > maximum.max_catalogue_entries
            || limits.max_objects > maximum.max_objects
            || limits.max_edges > maximum.max_edges
            || limits.max_object_bytes > maximum.max_object_bytes
            || limits.max_read_bytes > maximum.max_read_bytes
            || limits.max_io_calls > maximum.max_io_calls
        {
            return Err(RecordingQueryError::InvalidRequest);
        }
        Ok(())
    }
}

/// One byte-free handle to a complete original window, with a requested overlap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingQueryRow {
    /// Stable ordinal within the exact catalog root, not a cross-catalog cursor.
    pub ordinal: usize,
    /// Original immutable catalog descriptor; retrieval must independently verify source bytes.
    pub entry: CatalogEntry,
    /// Requested overlap in native decode ticks; encoded source is never cropped by this query.
    pub overlap: Range<u64>,
}
impl RecordingQueryRow {
    /// Canonical handle identity; catalog identity is separately bound by the result decision.
    #[must_use]
    pub fn row_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.agent_recordings.row.v1");
        encoder.u64(self.ordinal as u64);
        encoder.text(self.entry.slot().as_str());
        encoder.digest(self.entry.root());
        let interval = self.entry.decode_interval();
        for value in [
            interval.start,
            interval.end,
            self.overlap.start,
            self.overlap.end,
            self.entry.byte_len() as u64,
            self.entry.packets() as u64,
            self.entry.samples() as u64,
            self.entry.nals() as u64,
        ] {
            encoder.u64(value);
        }
        ContentDigest::sha256(&encoder.finish())
    }
}

/// Revalidated metadata only; physical coverage, source retrievability and UTC remain unknown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingQuery {
    /// Canonical caller pins and budget identity.
    pub request_digest: ContentDigest,
    /// Canonical metadata decision identity, independent of local filesystem path.
    pub decision_digest: ContentDigest,
    /// Exactly requested immutable catalog root.
    pub catalog_root: ContentDigest,
    /// Canonical catalog index payload, rehashed on both passes.
    pub catalog_metadata_digest: ContentDigest,
    /// Complete pinned catalog closure, including unselected roots and source leaves.
    /// Current deployment deletion authority must check every reference, not only output rows.
    pub reference_digests: Vec<ContentDigest>,
    /// Chronological whole-window handles; never source bytes.
    pub rows: Vec<RecordingQueryRow>,
    /// Query intervals absent from this exact bounded index, never evidence of camera absence.
    pub indexed_gaps: Vec<Range<u64>>,
    /// Sum of complete selected windows including retained boundary packets and manifests.
    pub quoted_hydration_bytes: u64,
    /// Every catalog member was checked even when it did not intersect the query.
    pub scanned_windows: usize,
    /// Aggregate metadata work including final revalidation; no source reads are hidden here.
    pub read_usage: MetadataReadUsage,
}

/// No successful partial or empty response is substituted for an unverifiable catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordingQueryError {
    /// Missing/invalid exact pins, reversed interval or unsupported limits.
    InvalidRequest,
    /// Canonical native catalog verification or atomic selection refused the request.
    Catalog(CatalogError),
    /// Read-only publication/metadata observation refused the request.
    Storage(PinnedMetadataError),
}
impl RecordingQueryError {
    /// Stable payload-free refusal identifier for typed transports.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_recording_query_request",
            Self::Catalog(CatalogError::Limit) => "recording_query_budget_exhausted",
            Self::Catalog(CatalogError::Scope) => "recording_query_scope_mismatch",
            Self::Catalog(_) => "recording_catalog_unverifiable",
            Self::Storage(error) => error.reason(),
        }
    }
}
impl fmt::Display for RecordingQueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}
impl std::error::Error for RecordingQueryError {}
impl From<CatalogError> for RecordingQueryError {
    fn from(error: CatalogError) -> Self {
        Self::Catalog(error)
    }
}
impl From<PinnedMetadataError> for RecordingQueryError {
    fn from(error: PinnedMetadataError) -> Self {
        Self::Storage(error)
    }
}
type Result<T> = std::result::Result<T, RecordingQueryError>;

/// Query one exact AVC/HEVC catalog through an explicit read-only filesystem capability.
///
/// This does not open a publisher, recover a spool, scan directories, take a lock, hydrate
/// source/derivative leaves, or infer capture time. Every member's currently published root
/// and the entire flat child closure's local tombstone absence are verified, including members
/// outside the requested interval. Cancellation and any exhausted allowance return no result.
pub fn query_recordings(
    io: &dyn SpoolIo,
    root: &Path,
    request: &RecordingQueryRequest,
    limits: RecordingQueryLimits,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<RecordingQuery> {
    let request_digest = request.request_digest(limits)?;
    let mut reader = PinnedMetadataReader::new(io, root, limits.metadata, cancelled)?;
    let manifest = reader.manifest(&request.catalog_slot, request.catalog_root)?;
    if manifest.kind() != request.codec.catalog_kind() {
        return Err(CatalogError::Malformed.into());
    }
    let catalog_metadata_digest = manifest.metadata_digest().ok_or(CatalogError::Malformed)?;
    let reference_digests = std::iter::once(manifest.root())
        .chain(manifest.children().iter().copied())
        .chain(std::iter::once(catalog_metadata_digest))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let index = reader.metadata(&manifest)?;
    let selection_limits = CatalogQueryLimits {
        max_windows: request.max_windows,
        max_output_bytes: request.max_hydration_bytes,
    };
    let (entries, selection): (Vec<CatalogEntry>, CatalogSelection) = match request.codec {
        RecordingQueryCodec::Avc => {
            let catalog = verify_catalog(&manifest, &index, &request.scope)?;
            let selection = catalog.select(request.interval.clone(), selection_limits)?;
            (catalog.entries().to_vec(), selection)
        }
        RecordingQueryCodec::Hevc => {
            let catalog = verify_hevc_catalog(&manifest, &index, &request.scope)?;
            let selection = catalog.select(request.interval.clone(), selection_limits)?;
            (catalog.entries().to_vec(), selection)
        }
    };
    for entry in &entries {
        let window = reader.manifest(entry.slot(), entry.root())?;
        if window.kind() != request.codec.window_kind() {
            return Err(CatalogError::WindowMismatch.into());
        }
    }
    let rows: Vec<_> = selection
        .windows()
        .iter()
        .map(|window| RecordingQueryRow {
            ordinal: window.ordinal(),
            entry: entries[window.ordinal()].clone(),
            overlap: window.requested_interval(),
        })
        .collect();
    let indexed_gaps = selection.unindexed().to_vec();
    let quoted_hydration_bytes = selection.output_bytes();
    let scanned_windows = entries.len();
    let read_usage = reader.finish()?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_recordings.decision.v1");
    encoder.digest(request_digest);
    encoder.digest(request.catalog_root);
    encoder.digest(catalog_metadata_digest);
    encoder.u64(scanned_windows as u64);
    encoder.u64(quoted_hydration_bytes);
    encoder.u64(rows.len() as u64);
    for row in &rows {
        encoder.digest(row.row_digest());
    }
    encoder.u64(indexed_gaps.len() as u64);
    for gap in &indexed_gaps {
        encoder.u64(gap.start);
        encoder.u64(gap.end);
    }
    Ok(RecordingQuery {
        request_digest,
        decision_digest: ContentDigest::sha256(&encoder.finish()),
        catalog_root: request.catalog_root,
        catalog_metadata_digest,
        reference_digests,
        rows,
        indexed_gaps,
        quoted_hydration_bytes,
        scanned_windows,
        read_usage,
    })
}

fn sha(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256 && digest.bytes() != [0; 32]
}
