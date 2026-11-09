#![forbid(unsafe_code)]
//! One conditional UTC selection across explicit native catalog pages and a retained clock.
//!
//! A capture's clock index can span several immutable catalog pages. Every clock descriptor
//! must match the verified union before time filtering. Repeated identical windows keep all
//! memberships but consume one output row and hydration quote. Missing clocks cannot exclude
//! a window. All metadata, member publications and final revalidation share one allowance.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::path::Path;

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_object::SpoolIo;
use fss_publication::SlotName;
use fss_publication::custody_audit::pinned_metadata::{
    MetadataReadUsage, PinnedMetadataError, PinnedMetadataReader,
};
use fss_publication::custody_audit::{CustodyAuditError, CustodyAuditLimits};

use super::set::{
    MAX_RECORDING_QUERY_CATALOGS, RecordingCatalogPin, RecordingSetCatalog, RecordingSetLocation,
    RecordingSetQueryRequest,
};
use super::utc::RecordingUtcQueryError;
use super::{RecordingQueryCodec, sha};
use crate::rtsp::recording_catalog::hevc::verify_hevc_catalog;
use crate::rtsp::recording_catalog::{
    CatalogEntry, CatalogError, CatalogScope, MAX_CATALOG_WINDOWS, verify_catalog,
};
use crate::rtsp::recording_clock::{
    CLOCK_INDEX_KIND, MAX_CLOCK_INDEX_BYTES, RecordingClockCodec, RecordingClockError,
    RecordingClockMetadata, UtcInterval, clock_slot, verify_clock_metadata,
};
use crate::site::clock::{ClockCorrelationPolicy, ClockOffsetInterval};

type Result<T> = std::result::Result<T, RecordingUtcQueryError>;

/// Caller-pinned catalog universe and one retained clock in exactly the same source scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingUtcSetQueryRequest {
    /// Explicit native codec family; no stored-tag inference or fallback.
    pub codec: RecordingQueryCodec,
    /// Historical sensor, stream generation, authority and receive/decode clocks.
    pub scope: CatalogScope,
    /// One to eight exact pins, treated as an unordered set; repeated slots or roots refuse.
    pub catalogs: Vec<RecordingCatalogPin>,
    /// Exact clock publication slot derived from codec and source scope.
    pub clock_slot: SlotName,
    /// Independently pinned immutable clock root; no implicit latest lookup.
    pub clock_root: ContentDigest,
    /// Half-open Unix nanoseconds compared to closed conditional node-observation envelopes.
    pub interval: Range<u64>,
    /// Unique output ceiling, including every window without clock evidence.
    pub max_windows: usize,
    /// Aggregate later whole-window hydration quote; no media is read or authorized here.
    pub max_hydration_bytes: u64,
}

impl RecordingUtcSetQueryRequest {
    /// Validate exact scope, distinct pins and finite ceilings before filesystem access.
    pub fn validate(&self) -> Result<()> {
        if self.catalogs.is_empty() || self.catalogs.len() > MAX_RECORDING_QUERY_CATALOGS {
            return Err(RecordingUtcQueryError::InvalidRequest);
        }
        RecordingSetQueryRequest {
            codec: self.codec,
            scope: self.scope.clone(),
            catalogs: self.catalogs.clone(),
            interval: self.interval.clone(),
            max_windows: self.max_windows,
            max_hydration_bytes: self.max_hydration_bytes,
        }
        .validate()
        .map_err(|_| RecordingUtcQueryError::InvalidRequest)?;
        if !sha(self.clock_root)
            || self.clock_root.is_laboratory()
            || clock_slot(clock_codec(self.codec), &self.scope)? != self.clock_slot
        {
            return Err(RecordingUtcQueryError::InvalidRequest);
        }
        Ok(())
    }

    /// Canonical identity over every pin, temporal interpretation and shared work ceiling.
    pub fn request_digest(&self, limits: RecordingUtcSetQueryLimits) -> Result<ContentDigest> {
        self.validate()?;
        limits.validate()?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.agent_recordings.utc_set.request.v1");
        encoder.text(self.codec.as_str());
        let recording = &self.scope.recording;
        encoder.text(recording.sensor.as_str());
        encoder.text(recording.stream.as_str());
        encoder.u64(recording.generation);
        encoder.digest(recording.anchor);
        encoder.digest(recording.receive_clock);
        encoder.digest(self.scope.decode_clock);
        encoder.u32(self.scope.time_scale);
        encoder.u64(self.catalogs.len() as u64);
        for pin in self.ordered_pins()? {
            encoder.text(pin.slot.as_str());
            encoder.digest(pin.root);
        }
        encoder.text(self.clock_slot.as_str());
        encoder.digest(self.clock_root);
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

    fn ordered_pins(&self) -> Result<Vec<&RecordingCatalogPin>> {
        let mut pins = bounded_vec(self.catalogs.len())?;
        pins.extend(self.catalogs.iter());
        pins.sort_unstable();
        Ok(pins)
    }
}

/// Complete metadata read allowance, shared across all catalogs, the clock and final checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordingUtcSetQueryLimits {
    /// Aggregate admitted descriptors, including duplicate memberships across catalogs.
    /// Each catalog parser separately has its own fixed bound; this is not an iteration meter.
    pub max_scanned_windows: usize,
    /// One nonrefillable manifest, metadata, reference, read-byte and filesystem-call budget.
    pub metadata: CustodyAuditLimits,
}

impl Default for RecordingUtcSetQueryLimits {
    fn default() -> Self {
        Self {
            max_scanned_windows: MAX_CATALOG_WINDOWS,
            metadata: CustodyAuditLimits {
                max_catalogue_entries: MAX_CATALOG_WINDOWS + MAX_RECORDING_QUERY_CATALOGS + 1,
                // Member manifests, plus one manifest/typed-index pair per catalog and clock.
                // Original window metadata and source children are only reference-checked.
                max_objects: MAX_CATALOG_WINDOWS + 2 * MAX_RECORDING_QUERY_CATALOGS + 2,
                max_edges: 2048,
                max_object_bytes: MAX_CLOCK_INDEX_BYTES,
                max_read_bytes: 64 * 1024 * 1024,
                max_io_calls: 20_000,
            },
        }
    }
}

impl RecordingUtcSetQueryLimits {
    /// Refuse enlarged ceilings. A narrowed zero allowance refuses its first admitted work.
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
            return Err(RecordingUtcQueryError::InvalidRequest);
        }
        Ok(())
    }
}

/// One unique whole recording with every catalog membership and an explicit clock status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingUtcSetQueryRow {
    /// Original immutable recording descriptor; source payload availability remains unknown.
    pub entry: CatalogEntry,
    /// Memberships in canonical catalog order, retaining each original catalog ordinal.
    pub locations: Vec<RecordingSetLocation>,
    /// Exact ordinal within the independently verified retained clock index, if present.
    pub clock_ordinal: Option<usize>,
    /// Conditional inclusive observation envelope; unavailable timing never excludes this row.
    pub utc_interval: Option<UtcInterval>,
}

impl RecordingUtcSetQueryRow {
    /// Binds original coordinates, all catalog memberships and exact optional clock status.
    #[must_use]
    pub fn row_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.agent_recordings.utc_set.row.v1");
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
        encoder.u64(self.locations.len() as u64);
        for location in &self.locations {
            encoder.u64(location.catalog_index as u64);
            encoder.digest(location.catalog_root);
            encoder.u64(location.ordinal as u64);
        }
        encoder.bool(self.clock_ordinal.is_some());
        if let Some(ordinal) = self.clock_ordinal {
            encoder.u64(ordinal as u64);
        }
        encoder.bool(self.utc_interval.is_some());
        if let Some(interval) = self.utc_interval {
            encoder.u64(interval.earliest_ns);
            encoder.u64(interval.latest_ns);
        }
        ContentDigest::sha256(&encoder.finish())
    }
}

/// Complete conditional UTC selection over the explicitly pinned index union.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingUtcSetQuery {
    /// Canonical pin set, clock, interval and work-ceiling identity.
    pub request_digest: ContentDigest,
    /// Complete metadata, membership, selection and gap identity; independent of local paths.
    pub decision_digest: ContentDigest,
    /// All exact catalog metadata in canonical slot/root order, including unselected pages.
    pub catalogs: Vec<RecordingSetCatalog>,
    /// Exact independently requested clock root.
    pub clock_root: ContentDigest,
    /// Rehashed canonical retained clock metadata.
    pub clock_metadata_digest: ContentDigest,
    /// Historical capture approval identity; no current acquisition or disclosure authority.
    pub clock_approval_digest: ContentDigest,
    /// Original sample-width, drift and lifetime assumptions.
    pub clock_policy: ClockCorrelationPolicy,
    /// Reconstructed unauthenticated UTC-minus-local correction with its uncertainty.
    pub clock_offset: ClockOffsetInterval,
    /// Reconstructed completed native read/admission brackets.
    pub clock_brackets: usize,
    /// Exact clock-index windows, all matched to the verified catalog union.
    pub clock_windows: usize,
    /// Full sorted reference union, including unselected members and original source leaves.
    /// The protected caller must check it against current deletion authority before output.
    pub reference_digests: Vec<ContentDigest>,
    /// Unique candidate or clock-unavailable windows in native decode order.
    pub rows: Vec<RecordingUtcSetQueryRow>,
    /// UTC intervals outside the union of declared clock envelopes, not physical absence.
    /// Windows with unavailable clocks may overlap any of these metadata gaps.
    pub indexed_gaps: Vec<Range<u64>>,
    /// Unique selected whole-window byte quote; this query reads no source media.
    pub quoted_hydration_bytes: u64,
    /// Aggregate verified catalog descriptors, including repeated memberships.
    pub scanned_windows: usize,
    /// Unique coherent recording descriptors across the complete selected catalog union.
    pub unique_windows: usize,
    /// Aggregate metadata and filesystem work including final global revalidation.
    pub read_usage: MetadataReadUsage,
}

/// A member already admitted by the caller's catalog or namespace verifier.
pub(super) struct UtcWindow {
    entry: CatalogEntry,
    locations: Vec<RecordingSetLocation>,
    clock_ordinal: Option<usize>,
}

impl UtcWindow {
    pub(super) fn new(entry: CatalogEntry, locations: Vec<RecordingSetLocation>) -> Self {
        Self {
            entry,
            locations,
            clock_ordinal: None,
        }
    }
}

/// Exact temporal selection pins, independent of how the catalog universe was admitted.
pub(super) struct UtcSelectionRequest<'a> {
    pub codec: RecordingQueryCodec,
    pub scope: &'a CatalogScope,
    pub clock_slot: &'a SlotName,
    pub clock_root: ContentDigest,
    pub interval: Range<u64>,
    pub max_windows: usize,
    pub max_hydration_bytes: u64,
}

/// Complete clock join and conditional selection; the borrowed read owner must still finish.
pub(super) struct VerifiedUtcSelection {
    pub clock_metadata_digest: ContentDigest,
    pub clock: RecordingClockMetadata,
    pub reference_digests: Vec<ContentDigest>,
    pub rows: Vec<RecordingUtcSetQueryRow>,
    pub indexed_gaps: Vec<Range<u64>>,
    pub quoted_hydration_bytes: u64,
}

/// Read all explicit catalog pages and one retained clock under the same bounded authority.
///
/// No single-catalog query is repeated with a fresh budget. Every clock descriptor must match
/// an exact unique union member before UTC filtering; unknown-clock members always survive.
/// All member slots, metadata and tombstones, including excluded pages, are revalidated once
/// after the complete result identity is built. This is neither source replay, trusted UTC,
/// physical coverage, directory discovery nor an atomic cross-owner snapshot.
pub fn query_recordings_utc_set(
    io: &dyn SpoolIo,
    root: &Path,
    request: &RecordingUtcSetQueryRequest,
    limits: RecordingUtcSetQueryLimits,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<RecordingUtcSetQuery> {
    let request_digest = request.request_digest(limits)?;
    let mut reader = PinnedMetadataReader::new(io, root, limits.metadata, cancelled)?;
    let mut catalogs = bounded_vec(request.catalogs.len())?;
    let mut references = BTreeSet::new();
    let mut by_root = BTreeMap::<ContentDigest, UtcWindow>::new();
    let mut by_slot = BTreeMap::<SlotName, ContentDigest>::new();
    let mut scanned_windows = 0_usize;

    for pin in request.ordered_pins()? {
        check_cancelled(cancelled)?;
        let manifest = reader.manifest(&pin.slot, pin.root)?;
        if manifest.kind() != request.codec.catalog_kind() {
            return Err(CatalogError::Malformed.into());
        }
        let metadata_digest = manifest.metadata_digest().ok_or(CatalogError::Malformed)?;
        let metadata = reader.metadata(&manifest)?;
        let entries = match request.codec {
            RecordingQueryCodec::Avc => {
                let catalog = verify_catalog(&manifest, &metadata, &request.scope)?;
                let mut entries = bounded_vec(catalog.entries().len())?;
                entries.extend_from_slice(catalog.entries());
                entries
            }
            RecordingQueryCodec::Hevc => {
                let catalog = verify_hevc_catalog(&manifest, &metadata, &request.scope)?;
                let mut entries = bounded_vec(catalog.entries().len())?;
                entries.extend_from_slice(catalog.entries());
                entries
            }
        };
        scanned_windows = scanned_windows
            .checked_add(entries.len())
            .filter(|count| *count <= limits.max_scanned_windows)
            .ok_or(CatalogError::Limit)?;
        references.insert(manifest.root());
        references.insert(metadata_digest);
        references.extend(manifest.children().iter().copied());
        for (ordinal, entry) in entries.iter().enumerate() {
            check_cancelled(cancelled)?;
            if by_slot
                .get(entry.slot())
                .is_some_and(|root| *root != entry.root())
                || by_root
                    .get(&entry.root())
                    .is_some_and(|prior| prior.entry != *entry)
            {
                return Err(CatalogError::WindowMismatch.into());
            }
            let member = reader.manifest(entry.slot(), entry.root())?;
            if member.kind() != request.codec.window_kind() {
                return Err(CatalogError::WindowMismatch.into());
            }
            references.insert(member.root());
            references.extend(member.children().iter().copied());
            if let Some(metadata) = member.metadata_digest() {
                references.insert(metadata);
            }
            let location = RecordingSetLocation {
                catalog_index: catalogs.len(),
                catalog_root: pin.root,
                ordinal,
            };
            if let Some(prior) = by_root.get_mut(&entry.root()) {
                prior
                    .locations
                    .try_reserve(1)
                    .map_err(|_| CatalogError::Limit)?;
                prior.locations.push(location);
            } else {
                let mut locations = bounded_vec(1)?;
                locations.push(location);
                by_slot.insert(entry.slot().clone(), entry.root());
                by_root.insert(entry.root(), UtcWindow::new(entry.clone(), locations));
            }
        }
        catalogs.push(RecordingSetCatalog {
            pin: pin.clone(),
            metadata_digest,
            scanned_windows: entries.len(),
        });
    }

    let unique_windows = by_root.len();
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
        by_root,
        references,
        cancelled,
    )?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_recordings.utc_set.decision.v1");
    encoder.digest(request_digest);
    encoder.u64(catalogs.len() as u64);
    for catalog in &catalogs {
        check_cancelled(cancelled)?;
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
        check_cancelled(cancelled)?;
        encoder.digest(row.row_digest());
    }
    encoder.u64(indexed_gaps.len() as u64);
    for gap in &indexed_gaps {
        encoder.u64(gap.start);
        encoder.u64(gap.end);
    }
    encoder.u64(reference_digests.len() as u64);
    for reference in &reference_digests {
        check_cancelled(cancelled)?;
        encoder.digest(*reference);
    }
    let decision_digest = digest(encoder)?;
    // One final pass includes early catalogs after later pages and the clock were admitted.
    let read_usage = reader.finish()?;
    Ok(RecordingUtcSetQuery {
        request_digest,
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
        read_usage,
    })
}

/// Join every retained clock row before selection using the caller's original read allowance.
/// Neither explicit-set nor discovered-namespace callers can refill or finish this owner here.
pub(super) fn select_utc<F: Fn() -> bool + Sync>(
    reader: &mut PinnedMetadataReader<'_, F>,
    request: &UtcSelectionRequest<'_>,
    mut by_root: BTreeMap<ContentDigest, UtcWindow>,
    mut references: BTreeSet<ContentDigest>,
    cancelled: &F,
) -> Result<VerifiedUtcSelection> {
    let clock_manifest = reader.manifest(request.clock_slot, request.clock_root)?;
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
        request.scope,
        clock_codec(request.codec),
    )?;
    references.insert(clock_manifest.root());
    references.insert(clock_metadata_digest);
    references.extend(clock_manifest.children().iter().copied());
    for (ordinal, timed) in clock.windows().iter().enumerate() {
        check_cancelled(cancelled)?;
        let window = by_root
            .get_mut(&timed.root())
            .ok_or(RecordingUtcQueryError::ClockCatalogMismatch)?;
        let entry = &window.entry;
        if entry.slot() != timed.slot()
            || entry.decode_interval() != timed.decode_interval()
            || entry.byte_len() != timed.byte_len()
            || entry.packets() != timed.packets()
            || entry.samples() != timed.samples()
            || entry.nals() != timed.nals()
            || window.clock_ordinal.replace(ordinal).is_some()
        {
            return Err(RecordingUtcQueryError::ClockCatalogMismatch);
        }
    }

    let unique_windows = by_root.len();
    let mut windows = bounded_vec(unique_windows)?;
    windows.extend(by_root.into_values());
    windows.sort_unstable_by(|left, right| {
        let left_interval = left.entry.decode_interval();
        let right_interval = right.entry.decode_interval();
        (
            left_interval.start,
            left_interval.end,
            left.entry.root(),
            left.entry.slot(),
        )
            .cmp(&(
                right_interval.start,
                right_interval.end,
                right.entry.root(),
                right.entry.slot(),
            ))
    });
    let mut rows = bounded_vec(unique_windows.min(request.max_windows))?;
    let mut observed = bounded_vec(clock.windows().len())?;
    let mut quoted_hydration_bytes = 0_u64;
    for window in windows {
        check_cancelled(cancelled)?;
        let utc_interval = window
            .clock_ordinal
            .map(|index| clock.windows()[index].utc_interval());
        if let Some(interval) = utc_interval {
            if interval.latest_ns < request.interval.start
                || interval.earliest_ns >= request.interval.end
            {
                continue;
            }
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
            .checked_add(window.entry.byte_len() as u64)
            .filter(|bytes| *bytes <= request.max_hydration_bytes)
            .ok_or(CatalogError::Limit)?;
        rows.push(RecordingUtcSetQueryRow {
            entry: window.entry,
            locations: window.locations,
            clock_ordinal: window.clock_ordinal,
            utc_interval,
        });
    }
    let indexed_gaps = declared_gaps(request.interval.clone(), observed)?;
    let mut reference_digests = bounded_vec(references.len())?;
    reference_digests.extend(references);
    Ok(VerifiedUtcSelection {
        clock_metadata_digest,
        clock,
        reference_digests,
        rows,
        indexed_gaps,
        quoted_hydration_bytes,
    })
}

pub(super) fn clock_codec(codec: RecordingQueryCodec) -> RecordingClockCodec {
    match codec {
        RecordingQueryCodec::Avc => RecordingClockCodec::Avc,
        RecordingQueryCodec::Hevc => RecordingClockCodec::Hevc,
    }
}

fn declared_gaps(query: Range<u64>, mut intervals: Vec<Range<u64>>) -> Result<Vec<Range<u64>>> {
    intervals.sort_unstable_by_key(|interval| (interval.start, interval.end));
    let mut gaps = bounded_vec(intervals.len() + 1)?;
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
    Ok(gaps)
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
