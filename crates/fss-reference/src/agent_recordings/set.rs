#![forbid(unsafe_code)]
//! One bounded metadata observation across explicit catalogs in the same native time basis.
//!
//! Every catalog and member shares one read allowance and one final revalidation. Repeated
//! identical windows keep all catalog memberships but are returned and priced only once.
//! The union's gaps describe only the selected immutable indexes, never physical absence,
//! retrievable media, current camera coverage, trusted UTC, or permission to disclose footage.

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

use super::{RecordingQueryCodec, RecordingQueryError, RecordingQueryRequest, sha};
use crate::rtsp::recording_catalog::hevc::verify_hevc_catalog;
use crate::rtsp::recording_catalog::{
    CatalogEntry, CatalogError, CatalogScope, MAX_CATALOG_BYTES, MAX_CATALOG_WINDOWS,
    verify_catalog,
};

/// Maximum explicit catalog pins in a single request. No directory enumeration is performed.
pub const MAX_RECORDING_QUERY_CATALOGS: usize = 8;

type Result<T> = std::result::Result<T, RecordingQueryError>;

/// Exact immutable catalog identity and its current local publication binding.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RecordingCatalogPin {
    /// Exact publication slot; a slot alone is not a content identity.
    pub slot: SlotName,
    /// Expected immutable catalog root.
    pub root: ContentDigest,
}

/// Caller-selected catalog set in exactly one sensor, stream generation and decode clock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingSetQueryRequest {
    /// One explicitly selected codec family; no inference or fallback.
    pub codec: RecordingQueryCodec,
    /// Exact original sensor, stream epoch, authority anchor and receive/decode clocks.
    pub scope: CatalogScope,
    /// Explicit pins, treated as an unordered set. Repeated roots or slots are refused.
    pub catalogs: Vec<RecordingCatalogPin>,
    /// Half-open native decode-tick query, never a cross-clock or UTC conversion.
    pub interval: Range<u64>,
    /// Aggregate unique selected windows. Exceeding this ceiling refuses the whole request.
    pub max_windows: usize,
    /// Sum of unique selected whole-window hydration quotes. No source bytes are read here.
    pub max_hydration_bytes: u64,
}
impl RecordingSetQueryRequest {
    /// Validate every explicit pin and finite ceiling before filesystem access.
    pub fn validate(&self) -> Result<()> {
        if self.catalogs.is_empty() || self.catalogs.len() > MAX_RECORDING_QUERY_CATALOGS {
            return Err(RecordingQueryError::InvalidRequest);
        }
        let mut slots = BTreeSet::new();
        let mut roots = BTreeSet::new();
        for pin in &self.catalogs {
            if !sha(pin.root) || !slots.insert(&pin.slot) || !roots.insert(pin.root) {
                return Err(RecordingQueryError::InvalidRequest);
            }
        }
        // Preserve the singleton query's exact scope, interval and hydration admission rules.
        let first = &self.catalogs[0];
        RecordingQueryRequest {
            codec: self.codec,
            scope: self.scope.clone(),
            catalog_slot: first.slot.clone(),
            catalog_root: first.root,
            interval: self.interval.clone(),
            max_windows: self.max_windows,
            max_hydration_bytes: self.max_hydration_bytes,
        }
        .validate()
    }

    /// Canonical order-independent identity of the set, query and every shared allowance.
    pub fn request_digest(&self, limits: RecordingSetQueryLimits) -> Result<ContentDigest> {
        self.validate()?;
        limits.validate()?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.agent_recordings.set.request.v1");
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
        Ok(ContentDigest::sha256(&encoder.finish()))
    }

    fn ordered_pins(&self) -> Result<Vec<&RecordingCatalogPin>> {
        let mut pins = bounded_vec(self.catalogs.len())?;
        pins.extend(self.catalogs.iter());
        pins.sort_unstable();
        Ok(pins)
    }
}

/// One request's nonrefillable catalog, metadata, I/O and final revalidation allowances.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordingSetQueryLimits {
    /// Total verified descriptors admitted, including repeated windows in different catalogs.
    /// At most 64; each catalog first verifies under its own fixed 64-descriptor parser bound.
    /// This is not a parser-iteration budget. Actual reads remain charged to `metadata` even
    /// when the catalog is then refused for exceeding the aggregate descriptor allowance.
    pub max_scanned_windows: usize,
    /// Shared by all catalogs, all member manifests and the single final revalidation pass.
    pub metadata: CustodyAuditLimits,
}
impl Default for RecordingSetQueryLimits {
    fn default() -> Self {
        Self {
            max_scanned_windows: MAX_CATALOG_WINDOWS,
            metadata: CustodyAuditLimits {
                max_catalogue_entries: MAX_CATALOG_WINDOWS + MAX_RECORDING_QUERY_CATALOGS,
                max_objects: MAX_CATALOG_WINDOWS + 2 * MAX_RECORDING_QUERY_CATALOGS,
                max_edges: 1024,
                max_object_bytes: MAX_CATALOG_BYTES,
                max_read_bytes: 8 * 1024 * 1024,
                max_io_calls: 10_000,
            },
        }
    }
}
impl RecordingSetQueryLimits {
    /// Refuse enlarged ceilings; zero allowances refuse when their work would begin.
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
            return Err(RecordingQueryError::InvalidRequest);
        }
        Ok(())
    }
}

/// Revalidated catalog metadata in canonical slot/root order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingSetCatalog {
    /// Caller pin, still bound to the same publication slot on the final pass.
    pub pin: RecordingCatalogPin,
    /// Canonical index payload digest, rehashed on the final pass.
    pub metadata_digest: ContentDigest,
    /// All descriptors examined, including members outside the requested interval.
    pub scanned_windows: usize,
}

/// Provenance of one window descriptor within one exact catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordingSetLocation {
    /// Index in the result's canonical `catalogs` vector, independent of caller pin ordering.
    pub catalog_index: usize,
    /// Exact immutable catalog whose scope and descriptor membership this location binds.
    pub catalog_root: ContentDigest,
    /// Stable ordinal within that catalog's canonical index.
    pub ordinal: usize,
}

/// One unique whole-window handle with all its exact catalog memberships.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingSetQueryRow {
    /// Complete original descriptor. Retrieval must independently verify its source bytes.
    pub entry: CatalogEntry,
    /// Requested native decode-tick overlap; no encoded bytes are cropped or returned.
    pub overlap: Range<u64>,
    /// Every matching catalog membership, sorted by canonical catalog index then ordinal.
    pub locations: Vec<RecordingSetLocation>,
}
impl RecordingSetQueryRow {
    /// Canonical row identity, binding every catalog membership as well as the exact descriptor.
    #[must_use]
    pub fn row_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.agent_recordings.set.row.v1");
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
        encoder.u64(self.locations.len() as u64);
        for location in &self.locations {
            encoder.u64(location.catalog_index as u64);
            encoder.digest(location.catalog_root);
            encoder.u64(location.ordinal as u64);
        }
        ContentDigest::sha256(&encoder.finish())
    }
}

/// Metadata-only observation of a caller-selected index universe.
///
/// This does not claim an atomic archive/deployment snapshot. The caller must independently
/// revalidate its current authority, including deletion denial of the entire `reference_digests`
/// union, before exposing a decision-bearing response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingSetQuery {
    /// Canonical input set, time basis, selection and nonrefillable allowances.
    pub request_digest: ContentDigest,
    /// Canonical metadata decision identity, independent of local filesystem path/pin order.
    pub decision_digest: ContentDigest,
    /// Every requested catalog, in canonical slot/root order.
    pub catalogs: Vec<RecordingSetCatalog>,
    /// Full sorted closure of catalog/member roots and source/derivative/metadata references.
    /// Includes all unselected members; no source availability claim follows from this list.
    pub reference_digests: Vec<ContentDigest>,
    /// Unique selected windows, sorted by decode start/end, root, then slot.
    pub rows: Vec<RecordingSetQueryRow>,
    /// Query intervals not indexed by the union of the exact selected catalogs.
    pub indexed_gaps: Vec<Range<u64>>,
    /// Sum of unique selected whole-window payload quotes; repeated memberships count once.
    pub quoted_hydration_bytes: u64,
    /// Total descriptors read across every catalog, including repeated memberships.
    pub scanned_windows: usize,
    /// Distinct coherent window descriptors across every catalog, including unselected windows.
    pub unique_windows: usize,
    /// Shared metadata and I/O work, including complete final revalidation.
    pub read_usage: MetadataReadUsage,
}

struct Window {
    entry: CatalogEntry,
    locations: Vec<RecordingSetLocation>,
}

/// Query explicit immutable catalogs under one capability, one allowance and one final pass.
///
/// Pins and window membership are canonicalized without ambient discovery. All member roots
/// and flat source references are checked even outside the query. Exact duplicates retain their
/// memberships while distinct overlapping windows remain distinct; index gaps use the union.
/// Rebinding one slot, conflicting descriptors, cancellation, exhausted allowance, or a failed
/// final check refuses the complete result. No lock, repair, payload hydration or mutation occurs.
pub fn query_recording_set(
    io: &dyn SpoolIo,
    root: &Path,
    request: &RecordingSetQueryRequest,
    limits: RecordingSetQueryLimits,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<RecordingSetQuery> {
    let request_digest = request.request_digest(limits)?;
    let mut reader = PinnedMetadataReader::new(io, root, limits.metadata, cancelled)?;
    let mut catalogs = bounded_vec(request.catalogs.len())?;
    let mut references = BTreeSet::new();
    let mut by_root = BTreeMap::<ContentDigest, Window>::new();
    let mut by_slot = BTreeMap::<SlotName, ContentDigest>::new();
    let mut scanned_windows = 0_usize;

    for pin in request.ordered_pins()? {
        check_cancelled(cancelled)?;
        let manifest = reader.manifest(&pin.slot, pin.root)?;
        if manifest.kind() != request.codec.catalog_kind() {
            return Err(CatalogError::Malformed.into());
        }
        let metadata_digest = manifest.metadata_digest().ok_or(CatalogError::Malformed)?;
        let index = reader.metadata(&manifest)?;
        let entries = match request.codec {
            RecordingQueryCodec::Avc => {
                let catalog = verify_catalog(&manifest, &index, &request.scope)?;
                let mut entries = bounded_vec(catalog.entries().len())?;
                entries.extend_from_slice(catalog.entries());
                entries
            }
            RecordingQueryCodec::Hevc => {
                let catalog = verify_hevc_catalog(&manifest, &index, &request.scope)?;
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
                .is_some_and(|expected| *expected != entry.root())
            {
                return Err(CatalogError::WindowMismatch.into());
            }
            if by_root
                .get(&entry.root())
                .is_some_and(|prior| prior.entry != *entry)
            {
                return Err(CatalogError::WindowMismatch.into());
            }
            let window = reader.manifest(entry.slot(), entry.root())?;
            if window.kind() != request.codec.window_kind() {
                return Err(CatalogError::WindowMismatch.into());
            }
            // Include the actually admitted member closure as well as the catalog's flat one.
            references.insert(window.root());
            references.extend(window.children().iter().copied());
            if let Some(metadata) = window.metadata_digest() {
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
                by_root.insert(
                    entry.root(),
                    Window {
                        entry: entry.clone(),
                        locations,
                    },
                );
            }
        }
        catalogs.push(RecordingSetCatalog {
            pin: pin.clone(),
            metadata_digest,
            scanned_windows: entries.len(),
        });
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
    let mut indexed_gaps = bounded_vec(unique_windows + 1)?;
    let mut cursor = request.interval.start;
    let mut quoted_hydration_bytes = 0_u64;
    for window in windows {
        check_cancelled(cancelled)?;
        let interval = window.entry.decode_interval();
        let overlap =
            request.interval.start.max(interval.start)..request.interval.end.min(interval.end);
        if overlap.start >= overlap.end {
            continue;
        }
        if rows.len() == request.max_windows {
            return Err(CatalogError::Limit.into());
        }
        quoted_hydration_bytes = quoted_hydration_bytes
            .checked_add(window.entry.byte_len() as u64)
            .filter(|bytes| *bytes <= request.max_hydration_bytes)
            .ok_or(CatalogError::Limit)?;
        if cursor < overlap.start {
            indexed_gaps.push(cursor..overlap.start);
        }
        cursor = cursor.max(overlap.end);
        rows.push(RecordingSetQueryRow {
            entry: window.entry,
            overlap,
            locations: window.locations,
        });
    }
    if cursor < request.interval.end {
        indexed_gaps.push(cursor..request.interval.end);
    }

    let mut reference_digests = bounded_vec(references.len())?;
    reference_digests.extend(references);
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_recordings.set.decision.v1");
    encoder.digest(request_digest);
    encoder.u64(catalogs.len() as u64);
    for catalog in &catalogs {
        check_cancelled(cancelled)?;
        encoder.text(catalog.pin.slot.as_str());
        encoder.digest(catalog.pin.root);
        encoder.digest(catalog.metadata_digest);
        encoder.u64(catalog.scanned_windows as u64);
    }
    encoder.u64(scanned_windows as u64);
    encoder.u64(unique_windows as u64);
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
    for digest in &reference_digests {
        check_cancelled(cancelled)?;
        encoder.digest(*digest);
    }
    let decision_digest = ContentDigest::sha256(&encoder.finish());
    // No intermediate per-catalog observation escapes. Earlier catalogs and their complete
    // closures are revalidated only after every later catalog, selection and digest operation.
    let read_usage = reader.finish()?;
    Ok(RecordingSetQuery {
        request_digest,
        decision_digest,
        catalogs,
        reference_digests,
        rows,
        indexed_gaps,
        quoted_hydration_bytes,
        scanned_windows,
        unique_windows,
        read_usage,
    })
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
