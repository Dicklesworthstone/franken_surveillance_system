#![forbid(unsafe_code)]
//! One bounded conditional UTC lookup across explicitly pinned capture sessions.
//!
//! Capture restarts may change source generations, receive/decode clocks and codec. Each
//! session retains its own verified clock assumptions and catalog provenance. The combined
//! candidates share one read/output/quote allowance, and every unknown-time member survives.
//! Neither the union nor its conditional gaps establish clock equivalence or physical absence.

use std::collections::BTreeSet;
use std::fmt;
use std::ops::Range;
use std::path::Path;

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_object::SpoolIo;
use fss_publication::SlotName;
use fss_publication::custody_audit::pinned_metadata::{
    MetadataReadUsage, PinnedMetadataError, PinnedMetadataReader,
};
use fss_publication::custody_audit::{CustodyAuditError, CustodyAuditLimits};

use super::RecordingQueryCodec;
use super::set::{RecordingCatalogPin, RecordingSetCatalog};
use super::utc::RecordingUtcQueryError;
use super::utc_set::{
    RecordingUtcSetQueryLimits, RecordingUtcSetQueryRequest, RecordingUtcSetQueryRow,
    UtcSelectionRequest, VerifiedUtcCatalogs, VerifiedUtcSelection, declared_gaps, read_catalogs,
    select_utc,
};
use crate::rtsp::recording::MAX_RECORDING_BYTES;
use crate::rtsp::recording_catalog::{CatalogError, CatalogScope, MAX_CATALOG_WINDOWS};
use crate::site::clock::{ClockCorrelationPolicy, ClockOffsetInterval};

/// Maximum independently pinned capture sessions in one complete observation.
pub const MAX_RECORDING_UTC_SESSIONS: usize = 8;

type Result<T> = std::result::Result<T, RecordingUtcSessionsError>;

/// One exact native source scope, complete caller-pinned catalog universe and retained clock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingUtcSessionPin {
    /// Explicit native codec family; different sessions may select different families.
    pub codec: RecordingQueryCodec,
    /// Historical source generation, authority and receive/decode clocks; never normalized.
    pub scope: CatalogScope,
    /// One to eight catalog pins, unordered; each session admits at most 64 descriptors.
    pub catalogs: Vec<RecordingCatalogPin>,
    /// Exact clock publication slot derived from codec and the entire original scope.
    pub clock_slot: SlotName,
    /// Independently pinned immutable clock root; no implicit latest lookup.
    pub clock_root: ContentDigest,
}

impl RecordingUtcSessionPin {
    /// Validate the exact source, distinct catalog pins and independently pinned clock.
    pub fn validate(&self) -> Result<()> {
        self.as_set(
            0..1,
            MAX_CATALOG_WINDOWS,
            (MAX_CATALOG_WINDOWS * MAX_RECORDING_BYTES) as u64,
        )
        .validate()
        .map_err(|_| RecordingUtcSessionsError::InvalidRequest)
    }

    /// Canonical source identity independent of caller ordering, local paths or UTC predicate.
    pub fn session_digest(&self) -> Result<ContentDigest> {
        self.validate()?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.agent_recordings.utc_sessions.session.v1");
        encoder.text(self.codec.as_str());
        let recording = &self.scope.recording;
        encoder.text(recording.sensor.as_str());
        encoder.text(recording.stream.as_str());
        encoder.u64(recording.generation);
        encoder.digest(recording.anchor);
        encoder.digest(recording.receive_clock);
        encoder.digest(self.scope.decode_clock);
        encoder.u32(self.scope.time_scale);
        let mut catalogs = bounded_vec(self.catalogs.len())?;
        catalogs.extend(self.catalogs.iter());
        catalogs.sort_unstable();
        encoder.u64(catalogs.len() as u64);
        for catalog in catalogs {
            encoder.text(catalog.slot.as_str());
            encoder.digest(catalog.root);
        }
        encoder.text(self.clock_slot.as_str());
        encoder.digest(self.clock_root);
        digest(encoder)
    }

    fn as_set(
        &self,
        interval: Range<u64>,
        max_windows: usize,
        max_hydration_bytes: u64,
    ) -> RecordingUtcSetQueryRequest {
        RecordingUtcSetQueryRequest {
            codec: self.codec,
            scope: self.scope.clone(),
            catalogs: self.catalogs.clone(),
            clock_slot: self.clock_slot.clone(),
            clock_root: self.clock_root,
            interval,
            max_windows,
            max_hydration_bytes,
        }
    }
}

/// Complete bounded UTC candidate query for one exact sensor and stream across capture epochs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingUtcSessionsRequest {
    /// One to eight independently pinned sessions. Every sensor and stream must match exactly.
    pub sessions: Vec<RecordingUtcSessionPin>,
    /// Half-open Unix nanoseconds compared to each session's conditional inclusive envelopes.
    pub interval: Range<u64>,
    /// Whole-result ceiling, including every unknown-time window from every input session.
    pub max_windows: usize,
    /// Whole-result later hydration quote; this observation reads no source media.
    pub max_hydration_bytes: u64,
}

impl RecordingUtcSessionsRequest {
    /// Refuse invalid bounds, mixed sources and repeated scopes or publication pins before I/O.
    pub fn validate(&self) -> Result<()> {
        if self.sessions.is_empty() || self.sessions.len() > MAX_RECORDING_UTC_SESSIONS {
            return Err(RecordingUtcSessionsError::InvalidRequest);
        }
        let first = &self.sessions[0].scope.recording;
        let mut slots = BTreeSet::new();
        let mut roots = BTreeSet::new();
        for (index, session) in self.sessions.iter().enumerate() {
            session
                .as_set(
                    self.interval.clone(),
                    self.max_windows,
                    self.max_hydration_bytes,
                )
                .validate()
                .map_err(|_| RecordingUtcSessionsError::InvalidRequest)?;
            let recording = &session.scope.recording;
            if recording.sensor != first.sensor
                || recording.stream != first.stream
                || self.sessions[..index]
                    .iter()
                    .any(|prior| prior.scope == session.scope)
                || !slots.insert(&session.clock_slot)
                || !roots.insert(session.clock_root)
            {
                return Err(RecordingUtcSessionsError::InvalidRequest);
            }
            for catalog in &session.catalogs {
                if !slots.insert(&catalog.slot) || !roots.insert(catalog.root) {
                    return Err(RecordingUtcSessionsError::InvalidRequest);
                }
            }
        }
        Ok(())
    }

    /// Bind every original source/clock pin, predicate and aggregate nonrefillable ceiling.
    pub fn request_digest(&self, limits: RecordingUtcSessionsLimits) -> Result<ContentDigest> {
        self.validate()?;
        limits.validate()?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.agent_recordings.utc_sessions.request.v1");
        encoder.u64(self.sessions.len() as u64);
        for (session_digest, _) in self.ordered_sessions()? {
            encoder.digest(session_digest);
        }
        encoder.u64(self.interval.start);
        encoder.u64(self.interval.end);
        encoder.u64(self.max_windows as u64);
        encoder.u64(self.max_hydration_bytes);
        for value in [
            limits.max_scanned_windows as u64,
            limits.metadata.max_catalogue_entries as u64,
            limits.metadata.max_objects as u64,
            limits.metadata.max_edges as u64,
            limits.metadata.max_object_bytes as u64,
            limits.metadata.max_read_bytes,
            limits.metadata.max_io_calls,
        ] {
            encoder.u64(value);
        }
        digest(encoder)
    }

    fn ordered_sessions(&self) -> Result<Vec<(ContentDigest, &RecordingUtcSessionPin)>> {
        let mut sessions = bounded_vec(self.sessions.len())?;
        for session in &self.sessions {
            sessions.push((session.session_digest()?, session));
        }
        sessions.sort_unstable_by_key(|(digest, _)| *digest);
        Ok(sessions)
    }
}

/// Aggregate work shared by every session, all references and the one final revalidation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordingUtcSessionsLimits {
    /// Total admitted descriptors, including repeated catalog memberships within a session.
    /// Every individual source universe separately remains bounded to 64 descriptors.
    pub max_scanned_windows: usize,
    /// One reader, never one fresh allowance per source; original media is not read.
    pub metadata: CustodyAuditLimits,
}

impl Default for RecordingUtcSessionsLimits {
    fn default() -> Self {
        let single = RecordingUtcSetQueryLimits::default();
        Self {
            max_scanned_windows: MAX_RECORDING_UTC_SESSIONS * single.max_scanned_windows,
            metadata: CustodyAuditLimits {
                max_catalogue_entries: MAX_RECORDING_UTC_SESSIONS
                    * single.metadata.max_catalogue_entries,
                max_objects: MAX_RECORDING_UTC_SESSIONS * single.metadata.max_objects,
                max_edges: MAX_RECORDING_UTC_SESSIONS * single.metadata.max_edges,
                max_io_calls: MAX_RECORDING_UTC_SESSIONS as u64 * single.metadata.max_io_calls,
                // The aggregate byte ceiling stays 64 MiB; it is not multiplied by sessions.
                ..single.metadata
            },
        }
    }
}

impl RecordingUtcSessionsLimits {
    /// Ceilings may only be narrowed; a zero allowance refuses its first attempted work.
    pub fn validate(self) -> Result<()> {
        let maximum = Self::default();
        if self.max_scanned_windows > maximum.max_scanned_windows
            || self.metadata.max_catalogue_entries > maximum.metadata.max_catalogue_entries
            || self.metadata.max_objects > maximum.metadata.max_objects
            || self.metadata.max_edges > maximum.metadata.max_edges
            || self.metadata.max_object_bytes > maximum.metadata.max_object_bytes
            || self.metadata.max_read_bytes > maximum.metadata.max_read_bytes
            || self.metadata.max_io_calls > maximum.metadata.max_io_calls
        {
            return Err(RecordingUtcSessionsError::InvalidRequest);
        }
        Ok(())
    }
}

/// One source's verified catalog universe and independently conditioned clock interpretation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingUtcSession {
    /// Canonical pin identity; sessions are sorted by this digest, not asserted UTC chronology.
    pub session_digest: ContentDigest,
    /// Original explicit codec family.
    pub codec: RecordingQueryCodec,
    /// Exact historical source scope; clocks and source generations are never merged.
    pub scope: CatalogScope,
    /// All verified catalogs, including pages with no selected windows, in canonical pin order.
    pub catalogs: Vec<RecordingSetCatalog>,
    /// Exact retained-clock publication binding.
    pub clock_slot: SlotName,
    /// Exact independently requested immutable clock root.
    pub clock_root: ContentDigest,
    /// Rehashed and canonically reconstructed retained clock metadata.
    pub clock_metadata_digest: ContentDigest,
    /// Historical acquisition approval, never present disclosure or acquisition authority.
    pub clock_approval_digest: ContentDigest,
    /// This source's original clock-correlation assumptions.
    pub clock_policy: ClockCorrelationPolicy,
    /// This source's reconstructed unauthenticated UTC-minus-local correction and uncertainty.
    pub clock_offset: ClockOffsetInterval,
    /// Reconstructed completed native read/admission brackets for this session only.
    pub clock_brackets: usize,
    /// All clock-index rows, matched to this exact catalog universe before selection.
    pub clock_windows: usize,
    /// This source's conditional metadata gaps; another session cannot erase these gaps.
    pub indexed_gaps: Vec<Range<u64>>,
    /// Complete selected whole-window quote for this source, charged to the aggregate bound.
    pub quoted_hydration_bytes: u64,
    /// Admitted catalog descriptors, counting every retained catalog membership.
    pub scanned_windows: usize,
    /// Unique coherent descriptors in this session, including unselected windows.
    pub unique_windows: usize,
}

/// One whole-window candidate with exact original source and catalog provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingUtcSessionsRow {
    /// Index into the canonical session vector; no ordering of physical observations is implied.
    pub session_index: usize,
    /// Independently bound source pin identity, preserved with the row.
    pub session_digest: ContentDigest,
    /// Original descriptor, exact memberships and known or unavailable clock envelope.
    pub row: RecordingUtcSetQueryRow,
}

impl RecordingUtcSessionsRow {
    /// Bind the complete row and both exact source coordinates.
    #[must_use]
    pub fn row_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.agent_recordings.utc_sessions.row.v1");
        encoder.u64(self.session_index as u64);
        encoder.digest(self.session_digest);
        encoder.digest(self.row.row_digest());
        ContentDigest::sha256(&encoder.finish())
    }
}

/// A complete conditional candidate union; no single input is silently truncated or skipped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingUtcSessionsQuery {
    /// Canonical sources, clock interpretations, predicate and work-ceiling identity.
    pub request_digest: ContentDigest,
    /// Complete source-provenance, selection, gap and reference identity.
    pub decision_digest: ContentDigest,
    /// Independently verified sessions in canonical pin-digest order.
    pub sessions: Vec<RecordingUtcSession>,
    /// Full sorted closure, including all unselected members and original source leaves.
    /// Protected callers must apply current deployment deletion authority to every reference.
    pub reference_digests: Vec<ContentDigest>,
    /// Whole-window candidates, ordered by session digest and then that session's decode ticks.
    pub rows: Vec<RecordingUtcSessionsRow>,
    /// Conditional gaps outside the union of independently conditioned UTC envelopes. Unknown
    /// windows may overlap any gap; this does not establish physical absence or clock equivalence.
    pub indexed_gaps: Vec<Range<u64>>,
    /// Aggregate complete later hydration quote. No media is read or authorized here.
    pub quoted_hydration_bytes: u64,
    /// Aggregate admitted descriptors, including duplicate memberships within one source.
    pub scanned_windows: usize,
    /// Aggregate unique windows; duplicate roots or slots across distinct sessions refuse.
    pub unique_windows: usize,
    /// Complete shared work including final revalidation of early and unselected sources.
    pub read_usage: MetadataReadUsage,
}

/// Invalid or incomplete input, unknown custody and exhausted bounds refuse the entire union.
#[derive(Debug)]
pub enum RecordingUtcSessionsError {
    /// Malformed bounds, mixed sensor/stream, or repeated source/publication pins before I/O.
    InvalidRequest,
    /// Existing catalog, clock, member, storage, cancellation or read/output-bound refusal.
    Utc(RecordingUtcQueryError),
}

impl RecordingUtcSessionsError {
    /// Stable payload-free refusal spelling, preserving existing lower-layer reasons.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_recording_utc_sessions_request",
            Self::Utc(error) => error.reason(),
        }
    }
}
impl fmt::Display for RecordingUtcSessionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}
impl std::error::Error for RecordingUtcSessionsError {}
impl From<RecordingUtcQueryError> for RecordingUtcSessionsError {
    fn from(error: RecordingUtcQueryError) -> Self {
        Self::Utc(error)
    }
}
impl From<PinnedMetadataError> for RecordingUtcSessionsError {
    fn from(error: PinnedMetadataError) -> Self {
        Self::Utc(error.into())
    }
}
impl From<CatalogError> for RecordingUtcSessionsError {
    fn from(error: CatalogError) -> Self {
        Self::Utc(error.into())
    }
}

/// Observe explicitly pinned capture sessions of one sensor and stream under one read owner.
///
/// Every complete clock index joins its own verified catalog universe before a source can
/// contribute an empty result. Every unknown-clock member is emitted and charged. Distinct
/// sessions cannot alias recording roots or slots. The final global pass revalidates every
/// publication, metadata object and flat reference closure after the last source was read.
/// This opens no publisher, performs no recovery and reads no original packet or media bytes.
pub fn query_recordings_utc_sessions(
    io: &dyn SpoolIo,
    root: &Path,
    request: &RecordingUtcSessionsRequest,
    limits: RecordingUtcSessionsLimits,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<RecordingUtcSessionsQuery> {
    let request_digest = request.request_digest(limits)?;
    let mut reader = PinnedMetadataReader::new(io, root, limits.metadata, cancelled)?;
    let mut sessions = bounded_vec(request.sessions.len())?;
    let mut rows = bounded_vec(request.max_windows)?;
    let mut observed = bounded_vec(request.max_windows)?;
    let mut references = BTreeSet::new();
    let mut member_roots = BTreeSet::new();
    let mut member_slots = BTreeSet::new();
    let mut scanned_windows = 0_usize;
    let mut unique_windows = 0_usize;
    let mut quoted_hydration_bytes = 0_u64;

    for (session_digest, pin) in request.ordered_sessions()? {
        check_cancelled(cancelled)?;
        let input = pin.as_set(
            request.interval.clone(),
            request.max_windows,
            request.max_hydration_bytes,
        );
        let remaining_descriptors = limits.max_scanned_windows.saturating_sub(scanned_windows);
        let VerifiedUtcCatalogs {
            catalogs,
            references: source_references,
            by_root,
            scanned_windows: source_scanned,
        } = read_catalogs(
            &mut reader,
            &input,
            remaining_descriptors.min(MAX_CATALOG_WINDOWS),
            cancelled,
        )?;
        let source_unique = by_root.len();
        for (member_root, member) in &by_root {
            check_cancelled(cancelled)?;
            if !member_roots.insert(*member_root)
                || !member_slots.insert(member.entry().slot().clone())
            {
                return Err(CatalogError::WindowMismatch.into());
            }
        }
        scanned_windows = scanned_windows
            .checked_add(source_scanned)
            .ok_or(CatalogError::Limit)?;
        unique_windows = unique_windows
            .checked_add(source_unique)
            .ok_or(CatalogError::Limit)?;
        let VerifiedUtcSelection {
            clock_metadata_digest,
            clock,
            reference_digests,
            rows: source_rows,
            indexed_gaps,
            quoted_hydration_bytes: source_quote,
        } = select_utc(
            &mut reader,
            &UtcSelectionRequest {
                codec: pin.codec,
                scope: &pin.scope,
                clock_slot: &pin.clock_slot,
                clock_root: pin.clock_root,
                interval: request.interval.clone(),
                max_windows: request.max_windows.saturating_sub(rows.len()),
                max_hydration_bytes: request
                    .max_hydration_bytes
                    .saturating_sub(quoted_hydration_bytes),
            },
            by_root,
            source_references,
            cancelled,
        )?;
        quoted_hydration_bytes = quoted_hydration_bytes
            .checked_add(source_quote)
            .ok_or(CatalogError::Limit)?;
        references.extend(reference_digests);
        let session_index = sessions.len();
        for row in source_rows {
            check_cancelled(cancelled)?;
            if let Some(interval) = row.utc_interval {
                observed.push(
                    interval.earliest_ns.max(request.interval.start)
                        ..interval
                            .latest_ns
                            .saturating_add(1)
                            .min(request.interval.end),
                );
            }
            rows.push(RecordingUtcSessionsRow {
                session_index,
                session_digest,
                row,
            });
        }
        sessions.push(RecordingUtcSession {
            session_digest,
            codec: pin.codec,
            scope: pin.scope.clone(),
            catalogs,
            clock_slot: pin.clock_slot.clone(),
            clock_root: pin.clock_root,
            clock_metadata_digest,
            clock_approval_digest: clock.approval_digest(),
            clock_policy: clock.policy(),
            clock_offset: clock.offset_interval(),
            clock_brackets: clock.bracket_count(),
            clock_windows: clock.windows().len(),
            indexed_gaps,
            quoted_hydration_bytes: source_quote,
            scanned_windows: source_scanned,
            unique_windows: source_unique,
        });
    }
    let indexed_gaps = declared_gaps(request.interval.clone(), observed)?;
    let mut reference_digests = bounded_vec(references.len())?;
    reference_digests.extend(references);
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_recordings.utc_sessions.decision.v1");
    encoder.digest(request_digest);
    encoder.u64(sessions.len() as u64);
    for session in &sessions {
        check_cancelled(cancelled)?;
        encoder.digest(session.session_digest);
        encoder.u64(session.catalogs.len() as u64);
        for catalog in &session.catalogs {
            encoder.text(catalog.pin.slot.as_str());
            encoder.digest(catalog.pin.root);
            encoder.digest(catalog.metadata_digest);
            encoder.u64(catalog.scanned_windows as u64);
        }
        encoder.digest(session.clock_metadata_digest);
        encoder.digest(session.clock_approval_digest);
        for count in [
            session.clock_brackets,
            session.clock_windows,
            session.scanned_windows,
            session.unique_windows,
        ] {
            encoder.u64(count as u64);
        }
        encoder.u64(session.quoted_hydration_bytes);
        encode_gaps(&mut encoder, &session.indexed_gaps);
    }
    encoder.u64(rows.len() as u64);
    for row in &rows {
        check_cancelled(cancelled)?;
        encoder.digest(row.row_digest());
    }
    encode_gaps(&mut encoder, &indexed_gaps);
    encoder.u64(quoted_hydration_bytes);
    encoder.u64(scanned_windows as u64);
    encoder.u64(unique_windows as u64);
    encoder.u64(reference_digests.len() as u64);
    for reference in &reference_digests {
        check_cancelled(cancelled)?;
        encoder.digest(*reference);
    }
    let decision_digest = digest(encoder)?;
    let read_usage = reader.finish()?;
    Ok(RecordingUtcSessionsQuery {
        request_digest,
        decision_digest,
        sessions,
        reference_digests,
        rows,
        indexed_gaps,
        quoted_hydration_bytes,
        scanned_windows,
        unique_windows,
        read_usage,
    })
}

fn encode_gaps(encoder: &mut CanonicalEncoder, gaps: &[Range<u64>]) {
    encoder.u64(gaps.len() as u64);
    for gap in gaps {
        encoder.u64(gap.start);
        encoder.u64(gap.end);
    }
}

fn check_cancelled(cancelled: &(impl Fn() -> bool + Sync)) -> Result<()> {
    if cancelled() {
        return Err(PinnedMetadataError::Audit(CustodyAuditError::Cancelled).into());
    }
    Ok(())
}

fn bounded_vec<T>(capacity: usize) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| CatalogError::Limit)?;
    Ok(values)
}

fn digest(encoder: CanonicalEncoder) -> Result<ContentDigest> {
    let bytes = encoder.finish_checked().map_err(|_| CatalogError::Limit)?;
    Ok(ContentDigest::sha256(&bytes))
}
