#![forbid(unsafe_code)]
//! Conditional UTC lookup over one complete native recording archive namespace.
//!
//! The caller pins the original source and one retained clock, not a manually assembled
//! catalog list. Namespace discovery, every page/member, the complete clock join and final
//! namespace/metadata/tombstone revalidation share one nonrefillable read capability. Missing
//! window clocks remain explicit candidates; an incomplete universe cannot become an empty
//! result. The query does not replay packets, authenticate UTC or claim physical coverage.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Range;
use std::path::Path;

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_object::SpoolIo;
use fss_publication::SlotName;
use fss_publication::custody_audit::CustodyAuditLimits;
use fss_publication::custody_audit::pinned_metadata::{
    MetadataReadUsage, PinnedMetadataError, PinnedMetadataReader,
};

use super::discover::namespace::{NamespaceLimits, VerifiedNamespace, read_namespace};
use super::discover::{
    RecordingDiscoveryError, RecordingDiscoveryLimits, RecordingDiscoveryRequest,
};
use super::set::{RecordingSetCatalog, RecordingSetLocation};
use super::utc::RecordingUtcQueryError;
use super::utc_set::{
    RecordingUtcSetQueryRow, UtcSelectionRequest, UtcWindow, VerifiedUtcSelection, clock_codec,
    select_utc,
};
use super::{RecordingQueryCodec, sha};
use crate::rtsp::recording_archive::{
    ArchiveCodec, ArchiveError, AvcArchiveCodec, CodecArchiveNamespace, HevcArchiveCodec,
};
use crate::rtsp::recording_catalog::{CatalogEntry, CatalogScope};
use crate::rtsp::recording_clock::{
    MAX_CLOCK_INDEX_BYTES, MAX_CLOCK_WINDOWS, RecordingClockError, clock_slot,
};
use crate::site::clock::{ClockCorrelationPolicy, ClockOffsetInterval};

type Result<T> = std::result::Result<T, RecordingUtcDiscoveryError>;

/// Exact source universe, independently pinned clock and a half-open Unix-nanosecond query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingUtcDiscoveryRequest {
    /// Caller-selected native codec family; no inference from discovered metadata.
    pub codec: RecordingQueryCodec,
    /// Exact historical sensor, stream generation, authority and receive/decode clocks.
    pub scope: CatalogScope,
    /// Exact retained-clock slot derived from codec and the complete source scope.
    pub clock_slot: SlotName,
    /// Independently pinned immutable retained-clock root; discovery cannot replace it.
    pub clock_root: ContentDigest,
    /// Half-open Unix nanoseconds compared to inclusive conditional observation envelopes.
    pub interval: Range<u64>,
    /// Complete unique output ceiling, including every window without clock annotations.
    pub max_windows: usize,
    /// Later whole-window hydration quote; this query reads no source media.
    pub max_hydration_bytes: u64,
}

impl RecordingUtcDiscoveryRequest {
    /// Reject malformed scope, clock pins and output bounds before any filesystem access.
    pub fn validate(&self) -> Result<()> {
        RecordingDiscoveryRequest {
            codec: self.codec,
            scope: self.scope.clone(),
            interval: self.interval.clone(),
            max_windows: self.max_windows,
            max_hydration_bytes: self.max_hydration_bytes,
        }
        .validate()
        .map_err(|_| RecordingUtcDiscoveryError::InvalidRequest)?;
        if !sha(self.clock_root)
            || self.clock_root.is_laboratory()
            || clock_slot(clock_codec(self.codec), &self.scope)? != self.clock_slot
        {
            return Err(RecordingUtcDiscoveryError::InvalidRequest);
        }
        Ok(())
    }

    /// Bind source, clock, UTC interpretation and every shared discovery/read allowance.
    pub fn request_digest(&self, limits: RecordingUtcDiscoveryLimits) -> Result<ContentDigest> {
        self.validate()?;
        limits.validate()?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.agent_recordings.utc_discovery.request.v1");
        encoder.text(self.codec.as_str());
        let recording = &self.scope.recording;
        encoder.text(recording.sensor.as_str());
        encoder.text(recording.stream.as_str());
        encoder.u64(recording.generation);
        encoder.digest(recording.anchor);
        encoder.digest(recording.receive_clock);
        encoder.digest(self.scope.decode_clock);
        encoder.u32(self.scope.time_scale);
        encoder.text(self.clock_slot.as_str());
        encoder.digest(self.clock_root);
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

/// Whole-namespace scan bounds, independent of the smaller selected-window output bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordingUtcDiscoveryLimits {
    /// All root-directory entries per observation, including unrelated sources and the clock.
    pub max_scan_roots: usize,
    /// Canonical namespace windows and admitted descriptors, including unselected members.
    pub max_windows: usize,
    /// Verified catalog pages in the selected namespace, without an explicit-pin page ceiling.
    pub max_pages: usize,
    /// One allowance for both namespace observations, all metadata and final global checks.
    pub metadata: CustodyAuditLimits,
}

impl Default for RecordingUtcDiscoveryLimits {
    fn default() -> Self {
        let discovery = RecordingDiscoveryLimits::default();
        Self {
            max_scan_roots: discovery.max_scan_roots,
            max_windows: discovery.max_windows,
            max_pages: discovery.max_pages,
            metadata: CustodyAuditLimits {
                max_catalogue_entries: discovery.metadata.max_catalogue_entries + 1,
                max_objects: discovery.metadata.max_objects + 2,
                max_edges: discovery.metadata.max_edges + MAX_CLOCK_WINDOWS * 5 + 1,
                max_object_bytes: MAX_CLOCK_INDEX_BYTES,
                ..discovery.metadata
            },
        }
    }
}

impl RecordingUtcDiscoveryLimits {
    /// Narrowed ceilings may be zero; attempted work refuses rather than refilling them.
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
            return Err(RecordingUtcDiscoveryError::InvalidRequest);
        }
        Ok(())
    }
}

/// Complete conditional UTC selection from one fully verified native archive namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingUtcDiscoveryQuery {
    /// Exact source, clock, UTC query and work-ceiling identity.
    pub request_digest: ContentDigest,
    /// Existing codec-specific archive routing identity, not a published authority root.
    pub namespace_digest: ContentDigest,
    /// Complete sorted root-record inventory, using the existing discovery inventory domain.
    pub inventory_digest: ContentDigest,
    /// Binds the full namespace, clock, catalog membership, selections and conditional gaps.
    pub decision_digest: ContentDigest,
    /// Every verified page in first-window-ordinal order. Bounded projections may expose only
    /// selected pages while retaining the complete inventory identity and counts.
    pub catalogs: Vec<RecordingSetCatalog>,
    /// Exactly requested retained-clock root.
    pub clock_root: ContentDigest,
    /// Rehashed canonical retained-clock metadata.
    pub clock_metadata_digest: ContentDigest,
    /// Original capture approval identity, not present acquisition or disclosure authority.
    pub clock_approval_digest: ContentDigest,
    /// Retained sample-width, drift and lifetime assumptions.
    pub clock_policy: ClockCorrelationPolicy,
    /// Reconstructed unauthenticated UTC-minus-local correction and its uncertainty.
    pub clock_offset: ClockOffsetInterval,
    /// Number of reconstructed completed read/admission brackets.
    pub clock_brackets: usize,
    /// Every retained clock window, matched to the complete namespace before filtering.
    pub clock_windows: usize,
    /// Full sorted reference closure, including unselected sources and the retained clock.
    /// Protected callers must apply current deployment deletion authority to this whole set.
    pub reference_digests: Vec<ContentDigest>,
    /// Unique whole-window candidates or clock-unavailable rows in native decode order.
    pub rows: Vec<RecordingUtcSetQueryRow>,
    /// Requested UTC portions outside declared clock envelopes; unknown-clock windows may
    /// overlap them. These gaps never establish physical absence or source availability.
    pub indexed_gaps: Vec<Range<u64>>,
    /// Sum of complete later hydration quotes for emitted windows; no media is read here.
    pub quoted_hydration_bytes: u64,
    /// Complete verified namespace descriptors, including windows outside the requested time.
    pub scanned_windows: usize,
    /// Unique namespace windows; canonical discovery refuses duplicate membership or roots.
    pub unique_windows: usize,
    /// All initial root-directory entries, including unrelated namespaces. Both passes' actual
    /// enumeration and reads are included in the shared read-usage counters.
    pub scanned_root_entries: usize,
    /// Complete metered work, including final namespace, metadata and tombstone revalidation.
    pub read_usage: MetadataReadUsage,
}

/// An incomplete catalog/clock universe, unavailable metadata or exhausted bound is a refusal.
#[derive(Debug)]
pub enum RecordingUtcDiscoveryError {
    /// Invalid source, clock, interval or output/work ceilings, rejected before filesystem I/O.
    InvalidRequest,
    /// Exact-namespace discovery, sequence, catalog, storage or shared-allowance refusal.
    Discovery(RecordingDiscoveryError),
    /// Retained clock evidence, complete catalog join or conditional selection refusal.
    Utc(RecordingUtcQueryError),
}

impl RecordingUtcDiscoveryError {
    /// Stable payload-free refusal reason, preserving existing discovery and UTC reasons.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_recording_utc_discovery_request",
            Self::Discovery(error) => error.reason(),
            Self::Utc(error) => error.reason(),
        }
    }
}

impl fmt::Display for RecordingUtcDiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}
impl std::error::Error for RecordingUtcDiscoveryError {}
impl From<RecordingDiscoveryError> for RecordingUtcDiscoveryError {
    fn from(error: RecordingDiscoveryError) -> Self {
        Self::Discovery(error)
    }
}
impl From<RecordingUtcQueryError> for RecordingUtcDiscoveryError {
    fn from(error: RecordingUtcQueryError) -> Self {
        Self::Utc(error)
    }
}
impl From<RecordingClockError> for RecordingUtcDiscoveryError {
    fn from(error: RecordingClockError) -> Self {
        Self::Utc(error.into())
    }
}
impl From<PinnedMetadataError> for RecordingUtcDiscoveryError {
    fn from(error: PinnedMetadataError) -> Self {
        Self::Discovery(error.into())
    }
}
impl From<ArchiveError> for RecordingUtcDiscoveryError {
    fn from(error: ArchiveError) -> Self {
        Self::Discovery(error.into())
    }
}

/// Discover one complete exact source namespace and join an independently pinned clock.
///
/// Every canonical page and member is verified before any UTC selection. Missing clock rows
/// do not exclude windows; missing catalog rows for any clock member refuse the entire result.
/// One reader and one final pass cover namespace membership, all publications and both flat
/// reference closures. No directory snapshot, source replay, trusted UTC or media authority is
/// inferred. Existing tick discovery and explicit-pin UTC reads retain their own identities.
pub fn discover_recordings_utc(
    io: &dyn SpoolIo,
    root: &Path,
    request: &RecordingUtcDiscoveryRequest,
    limits: RecordingUtcDiscoveryLimits,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<RecordingUtcDiscoveryQuery> {
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
    request: &RecordingUtcDiscoveryRequest,
    limits: RecordingUtcDiscoveryLimits,
    cancelled: &(impl Fn() -> bool + Sync),
    request_digest: ContentDigest,
    namespace: CodecArchiveNamespace<C>,
) -> Result<RecordingUtcDiscoveryQuery> {
    let mut reader = PinnedMetadataReader::new(io, root, limits.metadata, cancelled)?;
    let mut windows = BTreeMap::new();
    let VerifiedNamespace {
        namespace_digest,
        inventory_digest,
        catalogs,
        references,
        scanned_windows,
        scanned_root_entries,
    } = read_namespace(
        &mut reader,
        request.codec,
        &request.scope,
        namespace,
        NamespaceLimits {
            max_scan_roots: limits.max_scan_roots,
            max_windows: limits.max_windows,
            max_pages: limits.max_pages,
        },
        cancelled,
        &mut |entry: &CatalogEntry, location: RecordingSetLocation| {
            let mut locations = Vec::new();
            locations
                .try_reserve_exact(1)
                .map_err(|_| RecordingDiscoveryError::Limit)?;
            locations.push(location);
            if windows
                .insert(entry.root(), UtcWindow::new(entry.clone(), locations))
                .is_some()
            {
                return Err(RecordingDiscoveryError::Sequence);
            }
            Ok(())
        },
    )?;
    let unique_windows = windows.len();
    let VerifiedUtcSelection {
        clock_metadata_digest,
        clock,
        reference_digests,
        rows,
        indexed_gaps,
        quoted_hydration_bytes,
    } = select_utc(
        &mut reader,
        &UtcSelectionRequest {
            codec: request.codec,
            scope: &request.scope,
            clock_slot: &request.clock_slot,
            clock_root: request.clock_root,
            interval: request.interval.clone(),
            max_windows: request.max_windows,
            max_hydration_bytes: request.max_hydration_bytes,
        },
        windows,
        references,
        cancelled,
    )?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_recordings.utc_discovery.decision.v1");
    encoder.digest(request_digest);
    encoder.digest(namespace_digest);
    encoder.digest(inventory_digest);
    encoder.u64(catalogs.len() as u64);
    for catalog in &catalogs {
        checkpoint(cancelled)?;
        encoder.text(catalog.pin.slot.as_str());
        encoder.digest(catalog.pin.root);
        encoder.digest(catalog.metadata_digest);
        encoder.u64(catalog.scanned_windows as u64);
    }
    for digest in [
        request.clock_root,
        clock_metadata_digest,
        clock.approval_digest(),
    ] {
        encoder.digest(digest);
    }
    for count in [
        scanned_windows,
        unique_windows,
        clock.windows().len(),
        clock.bracket_count(),
    ] {
        encoder.u64(count as u64);
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
    let read_usage = reader.finish()?;
    Ok(RecordingUtcDiscoveryQuery {
        request_digest,
        namespace_digest,
        inventory_digest,
        decision_digest,
        catalogs,
        clock_root: request.clock_root,
        clock_metadata_digest,
        clock_approval_digest: clock.approval_digest(),
        clock_policy: clock.policy(),
        clock_offset: clock.offset_interval(),
        clock_brackets: clock.bracket_count(),
        clock_windows: clock.windows().len(),
        reference_digests,
        rows,
        indexed_gaps,
        quoted_hydration_bytes,
        scanned_windows,
        unique_windows,
        scanned_root_entries,
        read_usage,
    })
}

fn checkpoint(cancelled: &(impl Fn() -> bool + Sync)) -> Result<()> {
    super::discover::checkpoint(cancelled).map_err(Into::into)
}

fn digest(encoder: CanonicalEncoder) -> Result<ContentDigest> {
    super::discover::digest(encoder).map_err(Into::into)
}
