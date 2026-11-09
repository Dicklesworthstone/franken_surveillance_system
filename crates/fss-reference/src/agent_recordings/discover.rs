#![forbid(unsafe_code)]
//! Bounded, metadata-only discovery within one exact native recording archive namespace.
//!
//! The namespace is derived from the caller's complete codec/source/clock scope. Every
//! published window must belong to a verified, contiguous catalog page. Root records,
//! manifests, indexes, and local deletion markers share one allowance and final revalidation.
//! An unindexed tail or malformed sequence refuses the whole observation, including when
//! outside the requested interval. Discovery never opens the publisher or hydrates media.

use std::fmt;
use std::ops::Range;
use std::path::Path;

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_object::SpoolIo;
use fss_publication::custody_audit::pinned_metadata::{
    MetadataReadUsage, PinnedMetadataError, PinnedMetadataReader,
};
use fss_publication::custody_audit::{CustodyAuditError, CustodyAuditLimits};

use super::set::{RecordingSetCatalog, RecordingSetLocation, RecordingSetQueryRow};
use super::{RecordingQueryCodec, sha};
use crate::rtsp::recording::MAX_RECORDING_BYTES;
use crate::rtsp::recording_archive::{
    ArchiveCodec, ArchiveError, AvcArchiveCodec, CodecArchiveNamespace, HevcArchiveCodec,
    MAX_ARCHIVE_WINDOWS,
};
use crate::rtsp::recording_catalog::{
    CatalogEntry, CatalogError, CatalogScope, MAX_CATALOG_BYTES, MAX_CATALOG_WINDOWS,
};

pub(super) mod namespace;

/// Exact source scope and decode-clock selection, without manually supplied catalog pins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingDiscoveryRequest {
    /// Explicit native codec family, never inferred from stored data.
    pub codec: RecordingQueryCodec,
    /// Exact historical sensor, stream generation, authority and receive/decode clocks.
    pub scope: CatalogScope,
    /// Half-open native decode ticks. Discovery supplies no UTC conversion.
    pub interval: Range<u64>,
    /// Complete output ceiling, independent of the larger archive metadata scan allowance.
    pub max_windows: usize,
    /// Aggregate later whole-window hydration quote; this request reads no source media.
    pub max_hydration_bytes: u64,
}
impl RecordingDiscoveryRequest {
    /// Admit a finite exact source scope before any filesystem access.
    pub fn validate(&self) -> Result<()> {
        let recording = &self.scope.recording;
        if recording.generation == 0
            || self.scope.time_scale == 0
            || self.interval.start >= self.interval.end
            || !(1..=MAX_CATALOG_WINDOWS).contains(&self.max_windows)
            || self.max_hydration_bytes == 0
            || self.max_hydration_bytes > (MAX_CATALOG_WINDOWS * MAX_RECORDING_BYTES) as u64
            || [
                recording.anchor,
                recording.receive_clock,
                self.scope.decode_clock,
            ]
            .iter()
            .any(|digest| !sha(*digest))
        {
            return Err(RecordingDiscoveryError::InvalidRequest);
        }
        Ok(())
    }

    /// Identity of exact scope, interval, output limits and every shared scan/read ceiling.
    pub fn request_digest(&self, limits: RecordingDiscoveryLimits) -> Result<ContentDigest> {
        self.validate()?;
        limits.validate()?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.agent_recordings.discovery.request.v1");
        encoder.text(self.codec.as_str());
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
            limits.max_scan_roots as u64,
            limits.max_windows as u64,
            limits.max_pages as u64,
            limits.metadata.max_catalogue_entries as u64,
            limits.metadata.max_objects as u64,
            limits.metadata.max_edges as u64,
            limits.metadata.max_object_bytes as u64,
            limits.metadata.max_read_bytes,
            limits.metadata.max_io_calls,
        ] {
            encoder.u64(limit);
        }
        digest(encoder)
    }
}

/// Finite discovery allowances, separate from the much smaller selected-window output bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordingDiscoveryLimits {
    /// All root-directory entries examined per pass, including unrelated namespaces.
    pub max_scan_roots: usize,
    /// Canonical window roots and verified descriptors admitted in the selected namespace.
    pub max_windows: usize,
    /// Catalog pages admitted in the selected namespace.
    pub max_pages: usize,
    /// One allowance for namespace observations, all metadata and final revalidation.
    pub metadata: CustodyAuditLimits,
}
impl Default for RecordingDiscoveryLimits {
    fn default() -> Self {
        Self {
            max_scan_roots: 16_384,
            max_windows: MAX_ARCHIVE_WINDOWS,
            max_pages: 1024,
            metadata: CustodyAuditLimits {
                max_catalogue_entries: 5120,
                max_objects: 6144,
                max_edges: 65_536,
                max_object_bytes: MAX_CATALOG_BYTES,
                max_read_bytes: 64 * 1024 * 1024,
                max_io_calls: 1_000_000,
            },
        }
    }
}
impl RecordingDiscoveryLimits {
    /// Ceilings may narrow, including to zero; work never refills them between pages.
    pub fn validate(self) -> Result<()> {
        let maximum = Self::default();
        if self.max_scan_roots > maximum.max_scan_roots
            || self.max_windows > maximum.max_windows
            || self.max_pages > maximum.max_pages
            || self.metadata.max_catalogue_entries > maximum.metadata.max_catalogue_entries
            || self.metadata.max_objects > maximum.metadata.max_objects
            || self.metadata.max_edges > maximum.metadata.max_edges
            || self.metadata.max_object_bytes > maximum.metadata.max_object_bytes
            || self.metadata.max_read_bytes > maximum.metadata.max_read_bytes
            || self.metadata.max_io_calls > maximum.metadata.max_io_calls
        {
            return Err(RecordingDiscoveryError::InvalidRequest);
        }
        Ok(())
    }
}

/// Complete metadata observation of one exact source namespace, not source registration,
/// successful retrieval, physical coverage, trusted UTC or permission to disclose media.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingDiscoveryQuery {
    /// Exact source, selection and all discovery/read allowance identity.
    pub request_digest: ContentDigest,
    /// Existing codec-specific archive routing identity, not a published authority root.
    pub namespace_digest: ContentDigest,
    /// Complete ordered root-record inventory, including each exact record's content digest.
    pub inventory_digest: ContentDigest,
    /// Complete inventory, verified metadata, selection and indexed gaps bound to the request.
    pub decision_digest: ContentDigest,
    /// All verified pages in first-window-ordinal order. Projections may show selected pages
    /// with this complete inventory identity and counts, without listing every unselected page.
    pub catalogs: Vec<RecordingSetCatalog>,
    /// Selected unique whole-window handles with exact catalog root and within-page ordinal.
    pub rows: Vec<RecordingSetQueryRow>,
    /// Complete verified reference union, including unselected member sources. Current
    /// deployment deletion authority must check this entire set before releasing a response.
    pub reference_digests: Vec<ContentDigest>,
    /// Query intervals absent from this namespace's complete published indexes. An empty
    /// namespace gives the full requested interval; it does not establish physical absence.
    pub indexed_gaps: Vec<Range<u64>>,
    /// Sum of selected whole-window hydration quotes, not media read by this query.
    pub quoted_hydration_bytes: u64,
    /// Every namespace window verified, including members outside the requested interval.
    pub scanned_windows: usize,
    /// Root-directory entries examined in the initial observation, including unrelated names.
    /// Both observations' actual work is charged in `read_usage`.
    pub scanned_root_entries: usize,
    /// Aggregate work through complete final revalidation.
    pub read_usage: MetadataReadUsage,
}

/// No incomplete namespace, exhausted allowance or changed observation becomes an empty match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordingDiscoveryError {
    /// Unsupported source/query pins or ceilings, rejected before filesystem access.
    InvalidRequest,
    /// A namespace, allocation, output count or hydration quote ceiling was exhausted.
    Limit,
    /// Noncanonical slot, missing ordinal, overlapping pages/windows or duplicate window root.
    Sequence,
    /// Published windows lack complete catalog coverage, including a pending unindexed tail.
    UnindexedWindows,
    /// Canonical page metadata, exact scope or member descriptors failed verification.
    Catalog(CatalogError),
    /// Namespace, publication, deletion, metadata, shared budget or cancellation refusal.
    Storage(PinnedMetadataError),
}
impl RecordingDiscoveryError {
    /// Stable payload-free refusal reason shared by transports.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_recording_discovery_request",
            Self::Limit | Self::Catalog(CatalogError::Limit) => {
                "recording_discovery_budget_exhausted"
            }
            Self::Sequence => "recording_discovery_sequence_invalid",
            Self::UnindexedWindows => "recording_discovery_unindexed_windows",
            Self::Catalog(CatalogError::Scope) => "recording_discovery_scope_mismatch",
            Self::Catalog(_) => "recording_discovery_metadata_unverifiable",
            Self::Storage(error) => error.reason(),
        }
    }
}
impl fmt::Display for RecordingDiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}
impl std::error::Error for RecordingDiscoveryError {}
impl From<CatalogError> for RecordingDiscoveryError {
    fn from(error: CatalogError) -> Self {
        Self::Catalog(error)
    }
}
impl From<PinnedMetadataError> for RecordingDiscoveryError {
    fn from(error: PinnedMetadataError) -> Self {
        Self::Storage(error)
    }
}
impl From<ArchiveError> for RecordingDiscoveryError {
    fn from(error: ArchiveError) -> Self {
        match error {
            ArchiveError::Limit => Self::Limit,
            _ => Self::Sequence,
        }
    }
}
type Result<T> = std::result::Result<T, RecordingDiscoveryError>;

/// Discover and select complete native archive metadata in one exact source namespace.
///
/// All namespace windows and pages must form the archive writer's canonical contiguous
/// sequence, with no unindexed tail. Unrelated namespaces are charged for enumeration but
/// neither interpreted nor hydrated. Initial and final namespace membership observations,
/// page/member metadata and deletion checks all use one nonrefillable capability. Matching
/// observations do not create an atomic filesystem snapshot or a media-retrieval guarantee.
pub fn discover_recordings(
    io: &dyn SpoolIo,
    root: &Path,
    request: &RecordingDiscoveryRequest,
    limits: RecordingDiscoveryLimits,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<RecordingDiscoveryQuery> {
    let request_digest = request.request_digest(limits)?;
    match request.codec {
        RecordingQueryCodec::Avc => discover_namespace(
            io,
            root,
            request,
            limits,
            cancelled,
            request_digest,
            CodecArchiveNamespace::<AvcArchiveCodec>::new(request.scope.clone())?,
        ),
        RecordingQueryCodec::Hevc => discover_namespace(
            io,
            root,
            request,
            limits,
            cancelled,
            request_digest,
            CodecArchiveNamespace::<HevcArchiveCodec>::new(request.scope.clone())?,
        ),
    }
}

fn discover_namespace<C: ArchiveCodec>(
    io: &dyn SpoolIo,
    root: &Path,
    request: &RecordingDiscoveryRequest,
    limits: RecordingDiscoveryLimits,
    cancelled: &(impl Fn() -> bool + Sync),
    request_digest: ContentDigest,
    namespace: CodecArchiveNamespace<C>,
) -> Result<RecordingDiscoveryQuery> {
    let mut reader = PinnedMetadataReader::new(io, root, limits.metadata, cancelled)?;
    let mut rows = bounded_vec(request.max_windows)?;
    let mut indexed_gaps = bounded_vec(request.max_windows + 1)?;
    let mut cursor = request.interval.start;
    let mut quoted_hydration_bytes = 0_u64;
    let namespace::VerifiedNamespace {
        namespace_digest,
        inventory_digest,
        catalogs,
        references,
        scanned_windows: indexed,
        scanned_root_entries,
    } = namespace::read_namespace(
        &mut reader,
        request.codec,
        &request.scope,
        namespace,
        namespace::NamespaceLimits {
            max_scan_roots: limits.max_scan_roots,
            max_windows: limits.max_windows,
            max_pages: limits.max_pages,
        },
        cancelled,
        &mut |entry: &CatalogEntry, location: RecordingSetLocation| {
            let interval = entry.decode_interval();
            let overlap =
                request.interval.start.max(interval.start)..request.interval.end.min(interval.end);
            if overlap.start >= overlap.end {
                return Ok(());
            }
            if rows.len() == request.max_windows {
                return Err(RecordingDiscoveryError::Limit);
            }
            quoted_hydration_bytes = quoted_hydration_bytes
                .checked_add(entry.byte_len() as u64)
                .filter(|bytes| *bytes <= request.max_hydration_bytes)
                .ok_or(RecordingDiscoveryError::Limit)?;
            if cursor < overlap.start {
                indexed_gaps.push(cursor..overlap.start);
            }
            cursor = cursor.max(overlap.end);
            let mut locations = bounded_vec(1)?;
            locations.push(location);
            rows.push(RecordingSetQueryRow {
                entry: entry.clone(),
                overlap,
                locations,
            });
            Ok(())
        },
    )?;
    if cursor < request.interval.end {
        indexed_gaps.push(cursor..request.interval.end);
    }
    let mut reference_digests = bounded_vec(references.len())?;
    reference_digests.extend(references);
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_recordings.discovery.decision.v1");
    encoder.digest(request_digest);
    encoder.digest(namespace_digest);
    encoder.digest(inventory_digest);
    encoder.u64(indexed as u64);
    encoder.u64(catalogs.len() as u64);
    for catalog in &catalogs {
        checkpoint(cancelled)?;
        encoder.text(catalog.pin.slot.as_str());
        encoder.digest(catalog.pin.root);
        encoder.digest(catalog.metadata_digest);
        encoder.u64(catalog.scanned_windows as u64);
    }
    encoder.u64(quoted_hydration_bytes);
    encoder.u64(rows.len() as u64);
    for row in &rows {
        checkpoint(cancelled)?;
        encoder.digest(row.row_digest());
    }
    encoder.u64(indexed_gaps.len() as u64);
    for gap in &indexed_gaps {
        encoder.u64(gap.start);
        encoder.u64(gap.end);
    }
    encoder.u64(reference_digests.len() as u64);
    for reference in &reference_digests {
        checkpoint(cancelled)?;
        encoder.digest(*reference);
    }
    let decision_digest = digest(encoder)?;
    // No per-page result escapes. This also rechecks initial namespace membership, so a new
    // catalog or window during metadata reads cannot become a falsely complete old inventory.
    let read_usage = reader.finish()?;
    Ok(RecordingDiscoveryQuery {
        request_digest,
        namespace_digest,
        inventory_digest,
        decision_digest,
        catalogs,
        rows,
        reference_digests,
        indexed_gaps,
        quoted_hydration_bytes,
        scanned_windows: indexed,
        scanned_root_entries,
        read_usage,
    })
}

pub(super) fn digest(encoder: CanonicalEncoder) -> Result<ContentDigest> {
    let bytes = encoder
        .finish_checked()
        .map_err(|_| RecordingDiscoveryError::Limit)?;
    ContentDigest::try_sha256(&bytes).map_err(|_| RecordingDiscoveryError::Limit)
}

pub(super) fn checkpoint(cancelled: &(impl Fn() -> bool + Sync)) -> Result<()> {
    if cancelled() {
        return Err(PinnedMetadataError::Audit(CustodyAuditError::Cancelled).into());
    }
    Ok(())
}

fn bounded_vec<T>(capacity: usize) -> Result<Vec<T>> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(capacity)
        .map_err(|_| RecordingDiscoveryError::Limit)?;
    Ok(result)
}
