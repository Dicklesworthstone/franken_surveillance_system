#![forbid(unsafe_code)]
//! Conditional UTC candidates from exact retained catalog and clock metadata.
//!
//! This query reconstructs declared node read/admission envelopes, not original source
//! coordinates. Missing clocks cannot exclude a recording. Every catalog and clock reference
//! remains subject to current publication/tombstone checks under one shared read allowance.

use std::collections::BTreeSet;
use std::fmt;
use std::ops::Range;
use std::path::Path;

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_object::SpoolIo;
use fss_publication::SlotName;
use fss_publication::custody_audit::CustodyAuditLimits;
use fss_publication::custody_audit::pinned_metadata::{PinnedMetadataError, PinnedMetadataReader};

use super::{MetadataReadUsage, RecordingQueryCodec, RecordingQueryRequest};
use crate::rtsp::recording_catalog::hevc::verify_hevc_catalog;
use crate::rtsp::recording_catalog::{
    CatalogEntry, CatalogError, CatalogScope, MAX_CATALOG_WINDOWS, verify_catalog,
};
use crate::rtsp::recording_clock::{
    CLOCK_INDEX_KIND, MAX_CLOCK_INDEX_BYTES, RecordingClockCodec, RecordingClockError, UtcInterval,
    clock_slot, verify_clock_metadata,
};
use crate::site::clock::{ClockCorrelationPolicy, ClockOffsetInterval};

/// Independently pinned source catalog, retained clock companion and half-open UTC request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingUtcQueryRequest {
    /// Exact selected native codec; no stored-tag fallback.
    pub codec: RecordingQueryCodec,
    /// Historical generation, anchor, receive clock, decode clock and native rate.
    pub scope: CatalogScope,
    /// Exact immutable catalog publication slot.
    pub catalog_slot: SlotName,
    /// Exact expected catalog content root.
    pub catalog_root: ContentDigest,
    /// Exact retained-clock slot derived from the selected codec and source scope.
    pub clock_slot: SlotName,
    /// Independently expected retained-clock content root.
    pub clock_root: ContentDigest,
    /// Half-open Unix nanoseconds, compared to closed declared node observation envelopes.
    pub interval: Range<u64>,
    /// Complete output bound, including every catalog member with unavailable clock evidence.
    pub max_windows: usize,
    /// Quoted later whole-window hydration bound; no media is hydrated by this request.
    pub max_hydration_bytes: u64,
}

impl RecordingUtcQueryRequest {
    /// Check exact pins and finite query bounds before any filesystem access.
    pub fn validate(&self) -> Result<()> {
        let base = RecordingQueryRequest {
            codec: self.codec,
            scope: self.scope.clone(),
            catalog_slot: self.catalog_slot.clone(),
            catalog_root: self.catalog_root,
            interval: self.interval.clone(),
            max_windows: self.max_windows,
            max_hydration_bytes: self.max_hydration_bytes,
        };
        base.validate()
            .map_err(|_| RecordingUtcQueryError::InvalidRequest)?;
        if !super::sha(self.clock_root)
            || self.clock_root.is_laboratory()
            || clock_slot(clock_codec(self.codec), &self.scope)? != self.clock_slot
        {
            return Err(RecordingUtcQueryError::InvalidRequest);
        }
        Ok(())
    }

    /// Identity binds both immutable owners, exact timeline interpretation and all allowances.
    pub fn request_digest(&self, limits: RecordingUtcQueryLimits) -> Result<ContentDigest> {
        self.validate()?;
        limits.validate()?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.agent_recordings.utc_request.v1");
        encoder.text(self.codec.as_str());
        encoder.text(self.catalog_slot.as_str());
        encoder.digest(self.catalog_root);
        encoder.text(self.clock_slot.as_str());
        encoder.digest(self.clock_root);
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
        for value in [
            limits.metadata.max_catalogue_entries as u64,
            limits.metadata.max_objects as u64,
            limits.metadata.max_edges as u64,
            limits.metadata.max_object_bytes as u64,
            limits.metadata.max_read_bytes,
            limits.metadata.max_io_calls,
        ] {
            encoder.u64(value);
        }
        Ok(ContentDigest::sha256(&encoder.finish()))
    }
}

/// One nonrefillable allowance shared by catalog, clock, members and final revalidation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordingUtcQueryLimits {
    /// Metadata object, reference, I/O and total byte ceilings; no source reads are admitted.
    pub metadata: CustodyAuditLimits,
}

impl Default for RecordingUtcQueryLimits {
    fn default() -> Self {
        Self {
            metadata: CustodyAuditLimits {
                max_catalogue_entries: MAX_CATALOG_WINDOWS + 2,
                max_objects: 2 * (MAX_CATALOG_WINDOWS + 2),
                max_edges: 1024,
                max_object_bytes: MAX_CLOCK_INDEX_BYTES,
                max_read_bytes: 64 * 1024 * 1024,
                max_io_calls: 20_000,
            },
        }
    }
}

impl RecordingUtcQueryLimits {
    /// Bounded request ceilings. A zero allowance refuses the first corresponding operation.
    pub fn validate(self) -> Result<()> {
        let ceiling = Self::default().metadata;
        let limits = self.metadata;
        if limits.max_catalogue_entries > ceiling.max_catalogue_entries
            || limits.max_objects > ceiling.max_objects
            || limits.max_edges > ceiling.max_edges
            || limits.max_object_bytes > ceiling.max_object_bytes
            || limits.max_read_bytes > ceiling.max_read_bytes
            || limits.max_io_calls > ceiling.max_io_calls
        {
            return Err(RecordingUtcQueryError::InvalidRequest);
        }
        Ok(())
    }
}

/// A conditional UTC candidate or a recording that cannot be excluded without clock evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingUtcQueryRow {
    /// Stable position in the exact catalog, not the independent clock index.
    pub ordinal: usize,
    /// Complete original recording descriptor; no source availability is asserted.
    pub entry: CatalogEntry,
    /// Exact retained-clock row if one exists; missing clock evidence is explicit.
    pub clock_ordinal: Option<usize>,
    /// Closed declared observation envelope; `None` means time is not observable here.
    pub utc_interval: Option<UtcInterval>,
}

impl RecordingUtcQueryRow {
    /// Stable whole-window handle, including the retained-clock or unavailable-clock status.
    #[must_use]
    pub fn row_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.agent_recordings.utc_row.v1");
        encoder.u64(self.ordinal as u64);
        encoder.text(self.entry.slot().as_str());
        encoder.digest(self.entry.root());
        let interval = self.entry.decode_interval();
        for value in [
            interval.start,
            interval.end,
            self.entry.byte_len() as u64,
            self.entry.packets() as u64,
            self.entry.samples() as u64,
            self.entry.nals() as u64,
        ] {
            encoder.u64(value);
        }
        match self.clock_ordinal {
            Some(ordinal) => {
                encoder.u8(1);
                encoder.u64(ordinal as u64);
            }
            None => encoder.u8(0),
        }
        match self.utc_interval {
            Some(interval) => {
                encoder.u8(1);
                encoder.u64(interval.earliest_ns);
                encoder.u64(interval.latest_ns);
            }
            None => encoder.u8(0),
        }
        ContentDigest::sha256(&encoder.finish())
    }
}

/// Bounded retained-metadata interpretation, without fresh source replay or physical truth.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingUtcQuery {
    /// Both pins, source scope, UTC request and nonrefillable allowance identity.
    pub request_digest: ContentDigest,
    /// Complete conditional candidate decision identity, independent of local paths.
    pub decision_digest: ContentDigest,
    /// Exactly requested catalog manifest root.
    pub catalog_root: ContentDigest,
    /// Rehashed canonical catalog metadata payload.
    pub catalog_metadata_digest: ContentDigest,
    /// Independently requested clock companion root.
    pub clock_root: ContentDigest,
    /// Rehashed canonical clock metadata payload.
    pub clock_metadata_digest: ContentDigest,
    /// Declared original capture approval, not current effect authorization.
    pub clock_approval_digest: ContentDigest,
    /// Drift, sample-width and synchronization lifetime assumptions retained in the index.
    pub clock_policy: ClockCorrelationPolicy,
    /// Reconstructed unauthenticated UTC-minus-local correction, including uncertainty.
    pub clock_offset: ClockOffsetInterval,
    /// Number of reconstructed retained completed read/admission brackets.
    pub clock_brackets: usize,
    /// Number of clock-index members; all must also be exact catalog members.
    pub clock_windows: usize,
    /// Sorted complete closure for current deployment deletion-authority checks.
    pub reference_digests: Vec<ContentDigest>,
    /// Whole-window candidate and clock-unavailable handles in catalog decode order.
    pub rows: Vec<RecordingUtcQueryRow>,
    /// UTC request portions absent from the union of declared clock envelopes. These are
    /// metadata gaps, not source-recording gaps, source exclusions, coverage or absence proof.
    pub indexed_gaps: Vec<Range<u64>>,
    /// Cost of every emitted whole-window handle, including unavailable-clock rows.
    pub quoted_hydration_bytes: u64,
    /// Every catalog member checked, including members excluded by retained clock claims.
    pub scanned_windows: usize,
    /// Aggregate work including final revalidation, with no hidden source reads.
    pub read_usage: MetadataReadUsage,
}

/// An unverifiable or over-budget clock query cannot become a successful empty result.
#[derive(Debug)]
pub enum RecordingUtcQueryError {
    /// Invalid pins, bounds or ceilings, rejected before filesystem access.
    InvalidRequest,
    /// Canonical catalog verification or output limits refused the request.
    Catalog(CatalogError),
    /// Retained raw clock evidence did not reconstruct canonically under the pinned scope.
    Clock(RecordingClockError),
    /// Any clock row differs from or is absent in the independently pinned catalog.
    ClockCatalogMismatch,
    /// Current publication, metadata, local tombstone or read allowance refused the request.
    Storage(PinnedMetadataError),
}

impl RecordingUtcQueryError {
    /// Stable payload-free reason for all transports.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_recording_utc_query_request",
            Self::Catalog(CatalogError::Limit) | Self::Clock(RecordingClockError::Limit) => {
                "recording_utc_query_budget_exhausted"
            }
            Self::Catalog(CatalogError::Scope) | Self::Clock(RecordingClockError::Scope) => {
                "recording_utc_query_scope_mismatch"
            }
            Self::Catalog(_) => "recording_catalog_unverifiable",
            Self::Clock(_) => "recording_clock_metadata_unverifiable",
            Self::ClockCatalogMismatch => "recording_clock_catalog_mismatch",
            Self::Storage(error) => error.reason(),
        }
    }
}
impl fmt::Display for RecordingUtcQueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}
impl std::error::Error for RecordingUtcQueryError {}
impl From<CatalogError> for RecordingUtcQueryError {
    fn from(error: CatalogError) -> Self {
        Self::Catalog(error)
    }
}
impl From<RecordingClockError> for RecordingUtcQueryError {
    fn from(error: RecordingClockError) -> Self {
        Self::Clock(error)
    }
}
impl From<PinnedMetadataError> for RecordingUtcQueryError {
    fn from(error: PinnedMetadataError) -> Self {
        Self::Storage(error)
    }
}
type Result<T> = std::result::Result<T, RecordingUtcQueryError>;

/// Select retained UTC candidates through one explicit, read-only metadata capability.
///
/// Every clock assertion is matched to its catalog descriptor before time filtering. All
/// catalog members with no clock assertion remain output handles and consume both quotas.
/// Both complete flat closures and every member slot are revalidated on the same reader.
/// No publisher, recovery, lock, directory discovery, packet replay or hydration is invoked.
pub fn query_recordings_utc(
    io: &dyn SpoolIo,
    root: &Path,
    request: &RecordingUtcQueryRequest,
    limits: RecordingUtcQueryLimits,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<RecordingUtcQuery> {
    let request_digest = request.request_digest(limits)?;
    let mut reader = PinnedMetadataReader::new(io, root, limits.metadata, cancelled)?;
    let catalog_manifest = reader.manifest(&request.catalog_slot, request.catalog_root)?;
    if catalog_manifest.kind() != request.codec.catalog_kind() {
        return Err(CatalogError::Malformed.into());
    }
    let catalog_metadata_digest = catalog_manifest
        .metadata_digest()
        .ok_or(CatalogError::Malformed)?;
    let catalog_metadata = reader.metadata(&catalog_manifest)?;
    let entries = match request.codec {
        RecordingQueryCodec::Avc => {
            verify_catalog(&catalog_manifest, &catalog_metadata, &request.scope)?
                .entries()
                .to_vec()
        }
        RecordingQueryCodec::Hevc => {
            verify_hevc_catalog(&catalog_manifest, &catalog_metadata, &request.scope)?
                .entries()
                .to_vec()
        }
    };
    let clock_manifest = reader.manifest(&request.clock_slot, request.clock_root)?;
    if clock_manifest.kind() != CLOCK_INDEX_KIND {
        return Err(RecordingClockError::Malformed.into());
    }
    let clock_metadata_digest = clock_manifest
        .metadata_digest()
        .ok_or(RecordingClockError::Malformed)?;
    let clock_metadata = reader.metadata(&clock_manifest)?;
    let clock = verify_clock_metadata(
        &clock_manifest,
        &clock_metadata,
        &request.scope,
        clock_codec(request.codec),
    )?;
    let mut bindings = vec![None; entries.len()];
    for (clock_ordinal, window) in clock.windows().iter().enumerate() {
        let (ordinal, entry) = entries
            .iter()
            .enumerate()
            .find(|(_, entry)| entry.slot() == window.slot())
            .ok_or(RecordingUtcQueryError::ClockCatalogMismatch)?;
        if entry.root() != window.root()
            || entry.decode_interval() != window.decode_interval()
            || entry.byte_len() != window.byte_len()
            || entry.packets() != window.packets()
            || entry.samples() != window.samples()
            || entry.nals() != window.nals()
            || bindings[ordinal].is_some()
        {
            return Err(RecordingUtcQueryError::ClockCatalogMismatch);
        }
        bindings[ordinal] = Some(clock_ordinal);
    }
    for entry in &entries {
        let manifest = reader.manifest(entry.slot(), entry.root())?;
        if manifest.kind() != request.codec.window_kind() {
            return Err(CatalogError::WindowMismatch.into());
        }
    }
    let mut rows = Vec::with_capacity(entries.len().min(request.max_windows));
    let mut observed = Vec::with_capacity(clock.windows().len());
    let mut quoted_hydration_bytes = 0_u64;
    for (ordinal, (entry, binding)) in entries.iter().zip(&bindings).enumerate() {
        let utc_interval = binding.map(|index| clock.windows()[index].utc_interval());
        if let Some(interval) = utc_interval {
            if interval.latest_ns < request.interval.start
                || interval.earliest_ns >= request.interval.end
            {
                continue;
            }
            // Clamp a closed integer-nanosecond envelope to the half-open request. If
            // latest is u64::MAX, the request's representable end is already narrower.
            observed.push(
                interval.earliest_ns.max(request.interval.start)
                    ..interval
                        .latest_ns
                        .saturating_add(1)
                        .min(request.interval.end),
            );
        }
        if rows.len() == request.max_windows {
            return Err(CatalogError::Limit.into());
        }
        quoted_hydration_bytes = quoted_hydration_bytes
            .checked_add(entry.byte_len() as u64)
            .ok_or(CatalogError::Limit)?;
        if quoted_hydration_bytes > request.max_hydration_bytes {
            return Err(CatalogError::Limit.into());
        }
        rows.push(RecordingUtcQueryRow {
            ordinal,
            entry: entry.clone(),
            clock_ordinal: *binding,
            utc_interval,
        });
    }
    let indexed_gaps = declared_gaps(request.interval.clone(), observed);
    let reference_digests: Vec<_> = [catalog_manifest.root(), clock_manifest.root()]
        .into_iter()
        .chain(catalog_manifest.children().iter().copied())
        .chain(clock_manifest.children().iter().copied())
        .chain([catalog_metadata_digest, clock_metadata_digest])
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let read_usage = reader.finish()?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_recordings.utc_decision.v1");
    for digest in [
        request_digest,
        request.catalog_root,
        catalog_metadata_digest,
        request.clock_root,
        clock_metadata_digest,
        clock.approval_digest(),
    ] {
        encoder.digest(digest);
    }
    encoder.u64(entries.len() as u64);
    encoder.u64(clock.windows().len() as u64);
    encoder.u64(clock.bracket_count() as u64);
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
    Ok(RecordingUtcQuery {
        request_digest,
        decision_digest: ContentDigest::sha256(&encoder.finish()),
        catalog_root: request.catalog_root,
        catalog_metadata_digest,
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
        scanned_windows: entries.len(),
        read_usage,
    })
}

fn clock_codec(codec: RecordingQueryCodec) -> RecordingClockCodec {
    match codec {
        RecordingQueryCodec::Avc => RecordingClockCodec::Avc,
        RecordingQueryCodec::Hevc => RecordingClockCodec::Hevc,
    }
}

fn declared_gaps(query: Range<u64>, mut intervals: Vec<Range<u64>>) -> Vec<Range<u64>> {
    intervals.sort_unstable_by_key(|interval| (interval.start, interval.end));
    let mut gaps = Vec::with_capacity(intervals.len() + 1);
    let mut cursor = query.start;
    for interval in intervals {
        if cursor < interval.start {
            gaps.push(cursor..interval.start);
        }
        cursor = cursor.max(interval.end);
    }
    if cursor < query.end {
        gaps.push(cursor..query.end);
    }
    gaps
}
