#![forbid(unsafe_code)]
//! Read-only operational inventory over verified committed deployment state (fss-2h5zq.59).
//!
//! The sensor list is an inventory of retained capsule metadata, not a device registry or a
//! liveness check. Recorded gaps are not a current health assessment. Source payloads are not
//! read, and neither an empty inventory nor a gap-free stream certifies physical absence.
//! The existing orientation reader owns event, deletion and effect semantics. A second bounded
//! authority read must reproduce its anchor and record root before the inventory is returned.
//!
//! Per-stream continuity is knowledge about committed history only: `verified` means a retained
//! source coverage witness declares continuous delivery of every retained capsule of the stream,
//! never that the camera is online now. A stream whose capsules all carry an estimated clock is a
//! recorded-file source and is never a continuity source. Capsules committed by a file import that
//! never completed are excluded from every stream and capsule count and reported separately.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use fss_core::{
    CanonicalDecode, ClockBasis, ContentDigest, CoverageContinuity, EvidenceDelta,
    EvidenceDeltaBatch, SensorCapsule, TimestampNs,
};
use fss_ledger::{HostJournalReadIo, JournalReadIo, LedgerInspection, inspect_durable};
use fss_object::HostSpoolIo;
use fss_publication::{HostLockTableSource, WriterDetectionOptions, WriterState, detect_writers};

use crate::agent_orient::{DeploymentReadError, DeploymentSnapshot, OrientLimits, read_deployment};
use crate::doctor::{FILE_IMPORT_BATCH_PREFIX, writer_lock_paths, writer_state_name};
use crate::reference_deployment::{
    DEPLOYMENT_LAYOUT_FILENAME, DeploymentLayout, FAMILY_DELETION_TOMBSTONE, FAMILY_FILE_IMPORT,
    FAMILY_SENSOR_CAPSULE,
};

/// Limits on additional inventory work, independent of orientation's own bounded reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusLimits {
    /// Existing layout, journal, event and object read limits.
    pub snapshot: OrientLimits,
    /// Maximum distinct committed ledger objects indexed for inventory.
    pub max_objects: usize,
    /// Maximum retained capsules hydrated; exceeding the limit refuses, never truncates.
    pub max_capsules: usize,
    /// Maximum distinct (sensor, stream) rows.
    pub max_streams: usize,
    /// Maximum total capsule metadata bytes read.
    pub max_metadata_bytes: usize,
}

impl Default for StatusLimits {
    fn default() -> Self {
        Self {
            snapshot: OrientLimits::default(),
            max_objects: 65_536,
            max_capsules: 16_384,
            max_streams: 1024,
            max_metadata_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Fixed, non-disclosing status refusal. No failure returns a fabricated empty inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusError {
    /// Missing or invalid deployment layout.
    NotADeployment,
    /// A bounded input cannot be read.
    Unreadable,
    /// A committed record, object or identity is inconsistent.
    Corrupt,
    /// An input, aggregate or output cardinality exceeds the admitted budget.
    OverBudget,
    /// Committed authority changed while the inventory was being read.
    Changed,
    /// The owner requested cancellation at a checkpoint.
    Cancelled,
}
impl std::fmt::Display for StatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotADeployment => "not a readable reference deployment layout",
            Self::Unreadable => "a required status input cannot be read",
            Self::Corrupt => "committed status input failed verification",
            Self::OverBudget => "status inventory exceeds its read or output budget",
            Self::Changed => "deployment authority changed during the status read; retry the read",
            Self::Cancelled => "status read cancelled",
        })
    }
}
impl std::error::Error for StatusError {}
impl From<DeploymentReadError> for StatusError {
    fn from(error: DeploymentReadError) -> Self {
        match error {
            DeploymentReadError::NotADeployment { .. } => Self::NotADeployment,
            DeploymentReadError::Unreadable { .. } => Self::Unreadable,
            DeploymentReadError::Corrupt { .. } => Self::Corrupt,
            DeploymentReadError::NotCommitted { .. } => Self::Changed,
        }
    }
}

/// Retained metadata of one stream generation, not a claim that its camera is online.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamInventory {
    /// Sensor identity, never a URL or credential.
    pub sensor_id: String,
    /// Stream generation identity.
    pub stream_id: String,
    /// Distinct retained capsules in this stream.
    pub capsules: usize,
    /// Capsules explicitly declaring a preceding gap; zero does not prove continuity.
    pub recorded_gaps: usize,
    /// Sum of source-byte counts declared by capsules, not reverified payload availability.
    pub declared_source_bytes: u64,
    /// Clock bases observed in capsule metadata, in canonical order.
    pub clock_bases: BTreeSet<String>,
    /// Earliest declared capture instant over the stream's retained capsules, on the capsules'
    /// own clock bases (an estimated basis is never capture truth).
    pub capture_earliest: TimestampNs,
    /// Latest declared capture instant over the stream's retained capsules.
    pub capture_latest: TimestampNs,
    /// Retained capsules that are frames of a retained source coverage witness declaring
    /// continuous delivery (and of no witness declaring otherwise).
    pub witnessed_continuous: usize,
    /// Retained capsules that are frames of a retained witness declaring a gap or unknown
    /// continuity.
    pub witnessed_degraded: usize,
    /// Continuity knowledge of the stream over committed history; never live health.
    pub continuity: StreamContinuity,
}

/// Continuity knowledge of one stream over committed history at the status anchor. No value is a
/// statement about the camera now.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamContinuity {
    /// Every retained capsule is a frame of a retained source coverage witness declaring
    /// continuous delivery, and no capsule declares a preceding gap.
    Verified,
    /// A capsule declares a preceding gap, a covering witness declares a gap or unknown
    /// continuity, or only part of the stream is witnessed.
    Degraded,
    /// Every capsule carries an estimated clock: a recorded-file source, which is never a
    /// continuity source and never certifies absence.
    NotObservableFileSource,
    /// Device-clocked capsules without any retained continuity witness.
    NotObservable,
}

impl StreamContinuity {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Degraded => "degraded",
            Self::NotObservableFileSource => "not_observable_file_source",
            Self::NotObservable => "not_observable",
        }
    }
}

/// Source and import inventory derived from one committed authority prefix.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SourceInventory {
    /// Sensor identities represented by retained metadata, in canonical order.
    pub sensors: BTreeSet<String>,
    /// Stream rows sorted by (sensor identity, stream identity).
    pub streams: Vec<StreamInventory>,
    /// Historical distinct capsule objects, including committed deletions.
    pub capsule_objects: usize,
    /// Retained capsule metadata objects that were read and rehashed.
    pub retained_capsules: usize,
    /// Capsule objects withdrawn by committed deletion; never read back.
    pub deleted_capsules: usize,
    /// Import lifecycle objects still at generation one; their input may need an exact rerun.
    pub incomplete_imports: Vec<String>,
    /// Capsule objects committed by an import that never completed; excluded from every stream,
    /// sensor and retained-capsule count and never hydrated.
    pub incomplete_import_capsules: usize,
    /// Import lifecycle objects at generation two, excluding deleted imports.
    pub completed_imports: usize,
    /// Import lifecycle objects with a committed deletion tombstone.
    pub deleted_imports: usize,
    /// Capsule metadata bytes read and rehashed, excluding the orientation reader's own work.
    pub metadata_bytes_read: usize,
}

/// One operational report; effects and event states retain their existing semantic owners.
#[derive(Clone, Debug, PartialEq)]
pub struct DeploymentStatus {
    /// Anchor-pinned events, deletion state, effects, obligations and history diagnostics.
    pub snapshot: DeploymentSnapshot,
    /// Whether the authority journal was present on the final bounded read.
    pub ledger_present: bool,
    /// Source inventory checked against exactly the same authority anchor and root.
    pub sources: SourceInventory,
    /// Writer lock state observed before the authority read (lock table only; nothing locked).
    pub writer_before: WriterState,
    /// Writer lock state observed after the final authority check.
    pub writer_after: WriterState,
}

impl DeploymentStatus {
    /// Whether the report may already be stale: a writer or shared holder was observed, the
    /// writer state could not be determined, or it changed during the read.
    #[must_use]
    pub fn possibly_stale(&self) -> bool {
        self.writer_before.possibly_stale()
            || self.writer_after.possibly_stale()
            || writer_state_name(&self.writer_before) != writer_state_name(&self.writer_after)
    }
}

/// Explicit read boundary for status. Implementations must not write or repair deployment state.
/// A principal label is not an authorization mechanism; the caller supplies access to the root.
pub trait StatusReadIo {
    /// Read the existing bounded orientation snapshot, preserving its refusal semantics.
    fn snapshot(
        &self,
        root: &Path,
        limits: &OrientLimits,
    ) -> Result<DeploymentSnapshot, StatusError>;
    /// Read the canonical layout through a bounded, non-symlink regular-file read.
    fn layout(&self, root: &Path, max_bytes: usize) -> Result<Vec<u8>, StatusError>;
    /// Read and replay the authority journal without locks or mutation.
    fn ledger(
        &self,
        root: &Path,
        layout: &DeploymentLayout,
        max_bytes: usize,
    ) -> Result<LedgerInspection, StatusError>;
    /// Read one content-addressed metadata object; the inventory additionally checks its digest.
    fn object(
        &self,
        root: &Path,
        layout: &DeploymentLayout,
        digest: ContentDigest,
        max_bytes: usize,
    ) -> Result<Vec<u8>, StatusError>;
    /// Observe writer locks on the deployment without taking a lock or modifying anything.
    fn writer_state(&self, root: &Path, layout: &DeploymentLayout) -> WriterState;
}

/// Host reference adapter. Every operation delegates to an existing read-only bounded reader.
#[derive(Clone, Copy, Debug, Default)]
pub struct HostStatusReadIo;
impl StatusReadIo for HostStatusReadIo {
    fn snapshot(
        &self,
        root: &Path,
        limits: &OrientLimits,
    ) -> Result<DeploymentSnapshot, StatusError> {
        read_deployment(root, limits).map_err(Into::into)
    }
    fn layout(&self, root: &Path, max_bytes: usize) -> Result<Vec<u8>, StatusError> {
        let path = root.join(DEPLOYMENT_LAYOUT_FILENAME);
        let meta = HostJournalReadIo.symlink_metadata(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StatusError::NotADeployment
            } else {
                StatusError::Unreadable
            }
        })?;
        if !meta.is_file || meta.is_symlink {
            return Err(StatusError::NotADeployment);
        }
        if meta.len > max_bytes as u64 {
            return Err(StatusError::OverBudget);
        }
        let bytes = HostJournalReadIo
            .read_bounded(&path, max_bytes.saturating_add(1))
            .map_err(|_| StatusError::Unreadable)?;
        if bytes.len() > max_bytes {
            return Err(StatusError::OverBudget);
        }
        Ok(bytes)
    }
    fn ledger(
        &self,
        root: &Path,
        layout: &DeploymentLayout,
        max_bytes: usize,
    ) -> Result<LedgerInspection, StatusError> {
        inspect_durable(
            root.join(&layout.ledger_relpath),
            layout.site_lineage.clone(),
            max_bytes,
        )
        .map_err(|error| match error {
            fss_ledger::DurableLedgerError::OverBudget { .. } => StatusError::OverBudget,
            fss_ledger::DurableLedgerError::Io(_) => StatusError::Unreadable,
            _ => StatusError::Corrupt,
        })
    }
    fn object(
        &self,
        root: &Path,
        layout: &DeploymentLayout,
        digest: ContentDigest,
        max_bytes: usize,
    ) -> Result<Vec<u8>, StatusError> {
        fss_publication::read_verified(root.join(&layout.objects_relpath), digest, max_bytes)
            .map_err(|_| StatusError::Corrupt)
    }
    fn writer_state(&self, root: &Path, layout: &DeploymentLayout) -> WriterState {
        detect_writers(
            &HostSpoolIo,
            &writer_lock_paths(root, layout),
            Some(&HostLockTableSource),
            WriterDetectionOptions::default(),
        )
    }
}

/// Read the host deployment, with no mutations and no claims of current physical health.
pub fn inspect_deployment_status(
    root: &Path,
    limits: &StatusLimits,
) -> Result<DeploymentStatus, StatusError> {
    inspect_deployment_status_with(&HostStatusReadIo, root, limits, &mut || Ok(()))
}

/// Read through explicit authority and cooperative cancellation. On a concurrent append or
/// layout replacement, return `Changed` instead of combining different authority generations.
pub fn inspect_deployment_status_with(
    io: &dyn StatusReadIo,
    root: &Path,
    limits: &StatusLimits,
    checkpoint: &mut dyn FnMut() -> Result<(), StatusError>,
) -> Result<DeploymentStatus, StatusError> {
    validate_limits(limits)?;
    checkpoint()?;
    let layout_bytes = io.layout(root, limits.snapshot.max_layout_bytes)?;
    let layout = DeploymentLayout::parse_canonical_text(
        std::str::from_utf8(&layout_bytes).map_err(|_| StatusError::NotADeployment)?,
    )
    .map_err(|_| StatusError::NotADeployment)?;
    let writer_before = io.writer_state(root, &layout);
    checkpoint()?;
    // The ledger is bounded first, so a journal over its byte bound is refused as over budget
    // (the orientation reader would report it as a failed replay).
    let ledger = io.ledger(root, &layout, limits.snapshot.max_journal_bytes)?;
    checkpoint()?;
    let snapshot = io.snapshot(root, &limits.snapshot)?;
    if snapshot.events.len() > limits.snapshot.max_events {
        return Err(StatusError::OverBudget);
    }
    checkpoint()?;
    same_authority(&snapshot, &layout, &ledger)?;
    let witnessed = witnessed_capsules(&snapshot);
    let sources = inventory_witnessed(
        &ledger.batches,
        limits,
        &witnessed,
        &mut |digest| snapshot.deletions.object(digest).is_some(),
        &mut |digest, max_bytes| io.object(root, &layout, digest, max_bytes),
        checkpoint,
    )?;
    checkpoint()?;
    // Deletion may race object hydration. No report escapes without this final authority check.
    let after = io.ledger(root, &layout, limits.snapshot.max_journal_bytes)?;
    same_authority(&snapshot, &layout, &after)?;
    if io.layout(root, limits.snapshot.max_layout_bytes)? != layout_bytes {
        return Err(StatusError::Changed);
    }
    let writer_after = io.writer_state(root, &layout);
    checkpoint()?;
    Ok(DeploymentStatus {
        snapshot,
        sources,
        ledger_present: after.status == fss_ledger::DurableLedgerStatus::Present,
        writer_before,
        writer_after,
    })
}

/// Continuity each retained source coverage witness declares for its frames, by capsule digest.
/// A capsule named by several witnesses keeps the most conservative declaration.
fn witnessed_capsules(
    snapshot: &DeploymentSnapshot,
) -> BTreeMap<ContentDigest, CoverageContinuity> {
    let mut witnessed = BTreeMap::new();
    for retained in &snapshot.source_coverage {
        let continuity = retained.record.witness.continuity;
        for frame in &retained.record.frames {
            witnessed
                .entry(frame.capsule_digest)
                .and_modify(|seen| {
                    if continuity != CoverageContinuity::Continuous {
                        *seen = continuity;
                    }
                })
                .or_insert(continuity);
        }
    }
    witnessed
}

fn validate_limits(limits: &StatusLimits) -> Result<(), StatusError> {
    if limits.max_objects == 0
        || limits.max_objects > 65_536
        || limits.max_capsules == 0
        || limits.max_capsules > 16_384
        || limits.max_streams == 0
        || limits.max_streams > 1024
        || limits.max_metadata_bytes == 0
        || limits.max_metadata_bytes > 64 * 1024 * 1024
        || limits.snapshot.max_layout_bytes == 0
        || limits.snapshot.max_layout_bytes > 4096
        || limits.snapshot.max_journal_bytes == 0
        || limits.snapshot.max_journal_bytes > 64 * 1024 * 1024
        || limits.snapshot.max_object_bytes == 0
        || limits.snapshot.max_object_bytes > 16 * 1024 * 1024
        || limits.snapshot.max_events == 0
        || limits.snapshot.max_events > 128
        || limits.snapshot.max_revisions_per_event == 0
        || limits.snapshot.max_revisions_per_event > 64
    {
        return Err(StatusError::OverBudget);
    }
    Ok(())
}

fn same_authority(
    snapshot: &DeploymentSnapshot,
    layout: &DeploymentLayout,
    ledger: &LedgerInspection,
) -> Result<(), StatusError> {
    if snapshot.site_lineage != layout.site_lineage
        || snapshot.anchor != ledger.snapshot.anchor
        || snapshot.ledger_root != ledger.last_root
    {
        return Err(StatusError::Changed);
    }
    Ok(())
}

#[cfg(test)]
fn inventory(
    batches: &[EvidenceDeltaBatch],
    limits: &StatusLimits,
    deleted: &mut dyn FnMut(ContentDigest) -> bool,
    read: &mut dyn FnMut(ContentDigest, usize) -> Result<Vec<u8>, StatusError>,
    checkpoint: &mut dyn FnMut() -> Result<(), StatusError>,
) -> Result<SourceInventory, StatusError> {
    inventory_witnessed(batches, limits, &BTreeMap::new(), deleted, read, checkpoint)
}

/// Whether `batch` may hold capsules of the incomplete import started by batch `start`: every
/// planned capsule batch of its identity (`batch:file-import:<identity>:c<k>`) or, for an import
/// started under another batch identity, exactly the batch that started it.
fn incomplete_import_batch(batch: &str, start: &str) -> bool {
    match planned_capsule_prefix(start) {
        Some(prefix) => batch
            .strip_prefix(prefix)
            .is_some_and(|k| !k.is_empty() && k.bytes().all(|b| b.is_ascii_digit())),
        None => batch == start,
    }
}

/// `batch:file-import:<identity>:c` of a planned capsule batch identity, if it is one.
fn planned_capsule_prefix(start: &str) -> Option<&str> {
    let rest = start.strip_prefix(FILE_IMPORT_BATCH_PREFIX)?;
    let (identity, k) = rest.rsplit_once(":c")?;
    if identity.is_empty() || k.is_empty() || !k.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    start.get(..FILE_IMPORT_BATCH_PREFIX.len() + identity.len() + 2)
}

fn inventory_witnessed(
    batches: &[EvidenceDeltaBatch],
    limits: &StatusLimits,
    witnessed: &BTreeMap<ContentDigest, CoverageContinuity>,
    deleted: &mut dyn FnMut(ContentDigest) -> bool,
    read: &mut dyn FnMut(ContentDigest, usize) -> Result<Vec<u8>, StatusError>,
    checkpoint: &mut dyn FnMut() -> Result<(), StatusError>,
) -> Result<SourceInventory, StatusError> {
    let mut latest: BTreeMap<&str, (&EvidenceDelta, &str)> = BTreeMap::new();
    let mut capsules = BTreeSet::new();
    let mut imports = BTreeSet::new();
    for batch in batches {
        checkpoint()?;
        for delta in &batch.deltas {
            checkpoint()?;
            let id = delta.object_id.as_str();
            if !latest.contains_key(id) && latest.len() == limits.max_objects {
                return Err(StatusError::OverBudget);
            }
            latest.insert(id, (delta, batch.batch_id.as_str()));
            if delta.family == FAMILY_SENSOR_CAPSULE {
                capsules.insert(id);
            }
            if delta.family == FAMILY_FILE_IMPORT {
                imports.insert(id);
            }
        }
    }
    let mut output = SourceInventory {
        capsule_objects: capsules.len(),
        ..SourceInventory::default()
    };
    // Batches that started an import still at generation one: its capsules are never counted.
    let mut incomplete_starts = Vec::new();
    for id in &imports {
        let (delta, batch) = *latest.get(id).ok_or(StatusError::Corrupt)?;
        if delta.family == FAMILY_FILE_IMPORT
            && delta.new_generation == 1
            && !deleted(delta.payload_digest)
        {
            incomplete_starts.push(batch);
        }
    }
    let mut streams: BTreeMap<(String, String), StreamInventory> = BTreeMap::new();
    let mut identities = BTreeSet::new();
    for id in capsules {
        checkpoint()?;
        let (delta, batch) = *latest.get(id).ok_or(StatusError::Corrupt)?;
        if delta.family == FAMILY_DELETION_TOMBSTONE || deleted(delta.payload_digest) {
            output.deleted_capsules += 1;
            continue;
        }
        if delta.family != FAMILY_SENSOR_CAPSULE {
            return Err(StatusError::Corrupt);
        }
        if incomplete_starts
            .iter()
            .any(|start| incomplete_import_batch(batch, start))
        {
            output.incomplete_import_capsules += 1;
            continue;
        }
        if output.retained_capsules == limits.max_capsules {
            return Err(StatusError::OverBudget);
        }
        let remaining = limits.max_metadata_bytes - output.metadata_bytes_read;
        if remaining == 0 {
            return Err(StatusError::OverBudget);
        }
        let bound = remaining.min(limits.snapshot.max_object_bytes);
        let bytes = read(delta.payload_digest, bound)?;
        if bytes.len() > bound {
            return Err(StatusError::OverBudget);
        }
        if ContentDigest::sha256(&bytes) != delta.payload_digest {
            return Err(StatusError::Corrupt);
        }
        let capsule =
            SensorCapsule::from_canonical_bytes(&bytes).map_err(|_| StatusError::Corrupt)?;
        if !identities.insert(capsule.capsule_id.clone()) {
            return Err(StatusError::Corrupt);
        }
        output.metadata_bytes_read += bytes.len();
        output.retained_capsules += 1;
        add_capsule(&mut streams, &capsule, limits.max_streams)?;
        let key = (
            capsule.sensor_id.as_str().to_owned(),
            capsule.stream_id.as_str().to_owned(),
        );
        let row = streams.get_mut(&key).ok_or(StatusError::Corrupt)?;
        match witnessed.get(&delta.payload_digest) {
            Some(CoverageContinuity::Continuous) => row.witnessed_continuous += 1,
            Some(_) => row.witnessed_degraded += 1,
            None => {}
        }
    }
    for row in streams.values_mut() {
        row.continuity = classify_continuity(row);
    }
    for id in imports {
        checkpoint()?;
        let (delta, _) = *latest.get(id).ok_or(StatusError::Corrupt)?;
        if delta.family == FAMILY_DELETION_TOMBSTONE || deleted(delta.payload_digest) {
            output.deleted_imports += 1;
        } else if delta.family != FAMILY_FILE_IMPORT {
            return Err(StatusError::Corrupt);
        } else {
            match delta.new_generation {
                1 => output.incomplete_imports.push(id.to_owned()),
                2 => output.completed_imports += 1,
                _ => return Err(StatusError::Corrupt),
            }
        }
    }
    output.sensors = streams.keys().map(|(sensor, _)| sensor.clone()).collect();
    output.streams = streams.into_values().collect();
    Ok(output)
}

/// The one continuity rule: a file source first, then witnesses. Anything short of a continuous
/// witness of every capsule with no declared gap is degraded or not observable.
fn classify_continuity(row: &StreamInventory) -> StreamContinuity {
    if row.clock_bases.len() == 1 && row.clock_bases.contains(ClockBasis::Estimated.as_str()) {
        StreamContinuity::NotObservableFileSource
    } else if row.witnessed_continuous == 0 && row.witnessed_degraded == 0 {
        StreamContinuity::NotObservable
    } else if row.witnessed_continuous == row.capsules
        && row.witnessed_degraded == 0
        && row.recorded_gaps == 0
    {
        StreamContinuity::Verified
    } else {
        StreamContinuity::Degraded
    }
}

fn add_capsule(
    rows: &mut BTreeMap<(String, String), StreamInventory>,
    capsule: &SensorCapsule,
    max_streams: usize,
) -> Result<(), StatusError> {
    let key = (
        capsule.sensor_id.as_str().to_owned(),
        capsule.stream_id.as_str().to_owned(),
    );
    if !rows.contains_key(&key) && rows.len() == max_streams {
        return Err(StatusError::OverBudget);
    }
    let row = rows.entry(key.clone()).or_insert_with(|| StreamInventory {
        sensor_id: key.0,
        stream_id: key.1,
        capsules: 0,
        recorded_gaps: 0,
        declared_source_bytes: 0,
        clock_bases: BTreeSet::new(),
        capture_earliest: capsule.capture.earliest,
        capture_latest: capsule.capture.latest,
        witnessed_continuous: 0,
        witnessed_degraded: 0,
        continuity: StreamContinuity::NotObservable,
    });
    row.capsules += 1;
    row.capture_earliest = row.capture_earliest.min(capsule.capture.earliest);
    row.capture_latest = row.capture_latest.max(capsule.capture.latest);
    row.recorded_gaps += usize::from(capsule.gap_before);
    row.declared_source_bytes = row
        .declared_source_bytes
        .checked_add(capsule.source_bytes)
        .ok_or(StatusError::OverBudget)?;
    row.clock_bases
        .insert(capsule.clock_basis.as_str().to_owned());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_core::{
        BatchId, CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis, ObjectId, Plane,
        ReferenceLedger, SensorId, StreamId, TimestampNs,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn capsule(
        name: &str,
        sensor: &str,
        stream: &str,
    ) -> Result<SensorCapsule, fss_core::ContractError> {
        Ok(SensorCapsule {
            capsule_id: CapsuleId::parse(name)?,
            sensor_id: SensorId::parse(sensor)?,
            stream_id: StreamId::parse(stream)?,
            sequence: 1,
            capture: CaptureInterval::new(TimestampNs(0), TimestampNs(10))?,
            receive_time: TimestampNs(10),
            clock_basis: fss_core::ClockBasis::Estimated,
            source_digest: ContentDigest::sha256(b"pixels"),
            source_bytes: 6,
            frame_count: 1,
            gap_before: false,
        })
    }
    fn delta(
        id: &str,
        family: &str,
        generation: u64,
        bytes: &[u8],
    ) -> Result<EvidenceDelta, fss_core::ContractError> {
        Ok(EvidenceDelta {
            delta_id: format!("delta:{id}:{generation}"),
            family: family.to_owned(),
            object_id: ObjectId::parse(id)?,
            prior_generation: generation.checked_sub(1).filter(|n| *n > 0),
            new_generation: generation,
            validity: CaptureInterval::new(TimestampNs(0), TimestampNs(10))?,
            plane: Plane::Authority,
            payload_digest: ContentDigest::sha256(bytes),
            witness_digest: None,
            operation_id: None,
        })
    }
    fn append(ledger: &mut ReferenceLedger, changes: Vec<EvidenceDelta>) -> TestResult {
        let roots: Vec<_> = changes.iter().map(|d| d.payload_digest).collect();
        let batch = ledger.prepare_batch(
            BatchId::parse(format!("batch:{}", ledger.batches().len()))?,
            changes,
            roots,
        )?;
        let _ = ledger.append(batch)?;
        Ok(())
    }
    fn run(
        ledger: &ReferenceLedger,
        objects: &BTreeMap<ContentDigest, Vec<u8>>,
        limits: &StatusLimits,
    ) -> Result<SourceInventory, StatusError> {
        inventory(
            ledger.batches(),
            limits,
            &mut |_| false,
            &mut |digest, _| objects.get(&digest).cloned().ok_or(StatusError::Unreadable),
            &mut || Ok(()),
        )
    }

    #[test]
    fn empty_inventory_does_not_read_objects() -> TestResult {
        let output = inventory(
            &[],
            &StatusLimits::default(),
            &mut |_| false,
            &mut |_, _| Err(StatusError::Unreadable),
            &mut || Ok(()),
        )?;
        assert_eq!(output, SourceInventory::default());
        Ok(())
    }

    #[test]
    fn streams_are_sensor_scoped_and_gaps_keep_their_clock_basis() -> TestResult {
        let mut a = capsule("capsule:a", "sensor:a", "stream:shared")?;
        a.gap_before = true;
        let mut b = capsule("capsule:b", "sensor:b", "stream:shared")?;
        b.clock_basis = ClockBasis::DeviceMonotonic;
        let mut rows = BTreeMap::new();
        add_capsule(&mut rows, &b, 2)?;
        add_capsule(&mut rows, &a, 2)?;
        assert_eq!(rows.len(), 2);
        let values: Vec<_> = rows.values().collect();
        assert_eq!(values[0].sensor_id, "sensor:a");
        assert_eq!(values[0].recorded_gaps, 1);
        assert!(values[0].clock_bases.contains("estimated"));
        assert!(values[1].clock_bases.contains("device_monotonic"));
        assert_eq!(values[1].recorded_gaps, 0);
        Ok(())
    }

    #[test]
    fn stream_and_byte_count_bounds_fail_closed() -> TestResult {
        let a = capsule("capsule:a", "sensor:a", "stream:a")?;
        let b = capsule("capsule:b", "sensor:b", "stream:b")?;
        let mut rows = BTreeMap::new();
        add_capsule(&mut rows, &a, 1)?;
        assert_eq!(add_capsule(&mut rows, &b, 1), Err(StatusError::OverBudget));
        let mut huge = a.clone();
        huge.source_bytes = u64::MAX;
        assert_eq!(
            add_capsule(&mut rows, &huge, 1),
            Err(StatusError::OverBudget)
        );
        Ok(())
    }

    #[test]
    fn import_lifecycle_counts_current_objects_not_historical_deltas() -> TestResult {
        let mut ledger = ReferenceLedger::new("site:status");
        append(
            &mut ledger,
            vec![delta("object:import:a", FAMILY_FILE_IMPORT, 1, b"started")?],
        )?;
        append(
            &mut ledger,
            vec![delta(
                "object:import:a",
                FAMILY_FILE_IMPORT,
                2,
                b"complete",
            )?],
        )?;
        append(
            &mut ledger,
            vec![delta("object:import:b", FAMILY_FILE_IMPORT, 1, b"pending")?],
        )?;
        let output = run(&ledger, &BTreeMap::new(), &StatusLimits::default())?;
        assert_eq!(output.completed_imports, 1);
        assert_eq!(output.incomplete_imports, ["object:import:b"]);
        Ok(())
    }

    #[test]
    fn tombstoned_capsule_and_import_are_never_hydrated() -> TestResult {
        let mut ledger = ReferenceLedger::new("site:status");
        append(
            &mut ledger,
            vec![
                delta("object:capsule:a", FAMILY_SENSOR_CAPSULE, 1, b"gone")?,
                delta("object:import:a", FAMILY_FILE_IMPORT, 1, b"gone")?,
            ],
        )?;
        append(
            &mut ledger,
            vec![
                delta(
                    "object:capsule:a",
                    FAMILY_DELETION_TOMBSTONE,
                    2,
                    b"tombstone",
                )?,
                delta(
                    "object:import:a",
                    FAMILY_DELETION_TOMBSTONE,
                    2,
                    b"tombstone",
                )?,
            ],
        )?;
        let output = run(&ledger, &BTreeMap::new(), &StatusLimits::default())?;
        assert_eq!(output.deleted_capsules, 1);
        assert_eq!(output.deleted_imports, 1);
        assert_eq!(output.retained_capsules, 0);
        assert!(output.sensors.is_empty());
        Ok(())
    }

    #[test]
    fn retained_capsule_integrity_identity_and_exact_byte_bound_are_checked() -> TestResult {
        let c = capsule("capsule:a", "sensor:a", "stream:a")?;
        let mut encoder = fss_core::CanonicalEncoder::new();
        c.encode_canonical(&mut encoder);
        let bytes = encoder.finish_checked()?;
        let digest = ContentDigest::sha256(&bytes);
        let mut ledger = ReferenceLedger::new("site:status");
        append(
            &mut ledger,
            vec![delta("object:capsule:a", FAMILY_SENSOR_CAPSULE, 1, &bytes)?],
        )?;
        let mut objects = BTreeMap::from([(digest, bytes.clone())]);
        let limits = StatusLimits {
            max_metadata_bytes: bytes.len(),
            ..StatusLimits::default()
        };
        let output = run(&ledger, &objects, &limits)?;
        assert_eq!(output.retained_capsules, 1);
        assert_eq!(output.metadata_bytes_read, bytes.len());
        let smaller = StatusLimits {
            max_metadata_bytes: bytes.len() - 1,
            ..limits
        };
        assert_eq!(
            run(&ledger, &objects, &smaller),
            Err(StatusError::OverBudget)
        );
        objects.insert(digest, vec![0; bytes.len()]);
        assert_eq!(run(&ledger, &objects, &limits), Err(StatusError::Corrupt));
        objects.insert(digest, bytes.clone());
        append(
            &mut ledger,
            vec![delta(
                "object:capsule:duplicate",
                FAMILY_SENSOR_CAPSULE,
                1,
                &bytes,
            )?],
        )?;
        assert_eq!(
            run(&ledger, &objects, &StatusLimits::default()),
            Err(StatusError::Corrupt)
        );
        Ok(())
    }

    #[test]
    fn committed_deletion_index_overrides_still_present_capsule_bytes() -> TestResult {
        let mut ledger = ReferenceLedger::new("site:status");
        append(
            &mut ledger,
            vec![delta(
                "object:capsule:a",
                FAMILY_SENSOR_CAPSULE,
                1,
                b"removed",
            )?],
        )?;
        let output = inventory(
            ledger.batches(),
            &StatusLimits::default(),
            &mut |_| true,
            &mut |_, _| Err(StatusError::Unreadable),
            &mut || Ok(()),
        )?;
        assert_eq!(output.deleted_capsules, 1);
        assert_eq!(output.metadata_bytes_read, 0);
        Ok(())
    }

    #[test]
    fn cancellation_and_object_budget_return_no_partial_inventory() -> TestResult {
        let mut ledger = ReferenceLedger::new("site:status");
        append(
            &mut ledger,
            vec![
                delta("object:import:a", FAMILY_FILE_IMPORT, 1, b"a")?,
                delta("object:import:b", FAMILY_FILE_IMPORT, 1, b"b")?,
            ],
        )?;
        assert_eq!(
            inventory(
                ledger.batches(),
                &StatusLimits::default(),
                &mut |_| false,
                &mut |_, _| Err(StatusError::Unreadable),
                &mut || Err(StatusError::Cancelled)
            ),
            Err(StatusError::Cancelled)
        );
        let limits = StatusLimits {
            max_objects: 1,
            ..StatusLimits::default()
        };
        assert_eq!(
            run(&ledger, &BTreeMap::new(), &limits),
            Err(StatusError::OverBudget)
        );
        Ok(())
    }

    fn append_named(
        ledger: &mut ReferenceLedger,
        batch: &str,
        changes: Vec<EvidenceDelta>,
    ) -> TestResult {
        let roots: Vec<_> = changes.iter().map(|d| d.payload_digest).collect();
        let batch = ledger.prepare_batch(BatchId::parse(batch)?, changes, roots)?;
        let _ = ledger.append(batch)?;
        Ok(())
    }

    fn encoded(capsule: &SensorCapsule) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut encoder = fss_core::CanonicalEncoder::new();
        capsule.encode_canonical(&mut encoder);
        Ok(encoder.finish_checked()?)
    }

    #[test]
    fn capsules_of_an_incomplete_import_are_excluded_from_every_count() -> TestResult {
        let started = capsule("capsule:ab:000000", "sensor:crashed", "stream:crashed")?;
        let later = capsule("capsule:ab:000001", "sensor:crashed", "stream:crashed")?;
        let done = capsule("capsule:cd:000000", "sensor:done", "stream:done")?;
        let mut objects = BTreeMap::new();
        for c in [&started, &later, &done] {
            let bytes = encoded(c)?;
            objects.insert(ContentDigest::sha256(&bytes), bytes);
        }
        let mut ledger = ReferenceLedger::new("site:status");
        append_named(
            &mut ledger,
            "batch:file-import:ab:c0",
            vec![
                delta("object:file-import:ab", FAMILY_FILE_IMPORT, 1, b"ab-start")?,
                delta(
                    "object:capsule:capsule:ab:000000",
                    FAMILY_SENSOR_CAPSULE,
                    1,
                    &encoded(&started)?,
                )?,
            ],
        )?;
        append_named(
            &mut ledger,
            "batch:file-import:ab:c1",
            vec![delta(
                "object:capsule:capsule:ab:000001",
                FAMILY_SENSOR_CAPSULE,
                1,
                &encoded(&later)?,
            )?],
        )?;
        append_named(
            &mut ledger,
            "batch:file-import:cd:c0",
            vec![
                delta("object:file-import:cd", FAMILY_FILE_IMPORT, 1, b"cd-start")?,
                delta(
                    "object:capsule:capsule:cd:000000",
                    FAMILY_SENSOR_CAPSULE,
                    1,
                    &encoded(&done)?,
                )?,
            ],
        )?;
        append_named(
            &mut ledger,
            "batch:file-import:cd:manifest",
            vec![delta(
                "object:file-import:cd",
                FAMILY_FILE_IMPORT,
                2,
                b"cd-done",
            )?],
        )?;
        let output = run(&ledger, &objects, &StatusLimits::default())?;
        assert_eq!(output.incomplete_imports, ["object:file-import:ab"]);
        assert_eq!(output.completed_imports, 1);
        assert_eq!(output.incomplete_import_capsules, 2);
        assert_eq!(output.retained_capsules, 1);
        assert_eq!(output.capsule_objects, 3);
        assert_eq!(
            output.sensors.iter().collect::<Vec<_>>(),
            [&"sensor:done".to_owned()]
        );
        assert_eq!(output.streams.len(), 1);
        assert_eq!(output.streams[0].capsules, 1);
        // Planted negative: the started import completes, and its capsules count again.
        append_named(
            &mut ledger,
            "batch:file-import:ab:manifest",
            vec![delta(
                "object:file-import:ab",
                FAMILY_FILE_IMPORT,
                2,
                b"ab-done",
            )?],
        )?;
        let output = run(&ledger, &objects, &StatusLimits::default())?;
        assert!(output.incomplete_imports.is_empty());
        assert_eq!(output.incomplete_import_capsules, 0);
        assert_eq!(output.retained_capsules, 3);
        Ok(())
    }

    #[test]
    fn planned_capsule_batches_are_attributed_exactly() {
        assert!(incomplete_import_batch(
            "batch:file-import:ab:c12",
            "batch:file-import:ab:c0"
        ));
        assert!(!incomplete_import_batch(
            "batch:file-import:abc:c1",
            "batch:file-import:ab:c0"
        ));
        assert!(!incomplete_import_batch(
            "batch:file-import:ab:manifest",
            "batch:file-import:ab:c0"
        ));
        assert!(!incomplete_import_batch(
            "batch:file-import:ab:c",
            "batch:file-import:ab:c0"
        ));
        assert!(incomplete_import_batch("batch:other", "batch:other"));
        assert!(!incomplete_import_batch("batch:other:2", "batch:other"));
    }

    #[test]
    fn continuity_is_file_source_unwitnessed_verified_or_degraded() -> TestResult {
        let mut file = capsule("capsule:file", "sensor:file", "stream:file")?;
        file.gap_before = true;
        let mut device = Vec::new();
        for (sensor, n) in [("sensor:full", 2), ("sensor:none", 1), ("sensor:part", 2)] {
            for i in 0..n {
                let mut c = capsule(&format!("capsule:{sensor}:{i}"), sensor, "stream:cam")?;
                c.clock_basis = ClockBasis::DeviceMonotonic;
                c.sequence = i + 1;
                device.push(c);
            }
        }
        let mut gapped = capsule("capsule:gap", "sensor:gap", "stream:cam")?;
        gapped.clock_basis = ClockBasis::DeviceMonotonic;
        gapped.gap_before = true;
        let mut objects = BTreeMap::new();
        let mut deltas = Vec::new();
        let mut witnessed = BTreeMap::new();
        for c in std::iter::once(&file).chain(&device).chain([&gapped]) {
            let bytes = encoded(c)?;
            let digest = ContentDigest::sha256(&bytes);
            objects.insert(digest, bytes.clone());
            deltas.push(delta(
                &format!("object:{}", c.capsule_id.as_str()),
                FAMILY_SENSOR_CAPSULE,
                1,
                &bytes,
            )?);
            let sensor = c.sensor_id.as_str();
            if sensor == "sensor:full"
                || sensor == "sensor:gap"
                || (sensor == "sensor:part" && c.sequence == 1)
            {
                witnessed.insert(digest, CoverageContinuity::Continuous);
            }
        }
        let mut ledger = ReferenceLedger::new("site:status");
        append(&mut ledger, deltas)?;
        let output = inventory_witnessed(
            ledger.batches(),
            &StatusLimits::default(),
            &witnessed,
            &mut |_| false,
            &mut |digest, _| objects.get(&digest).cloned().ok_or(StatusError::Unreadable),
            &mut || Ok(()),
        )?;
        let knowledge: BTreeMap<&str, StreamContinuity> = output
            .streams
            .iter()
            .map(|row| (row.sensor_id.as_str(), row.continuity))
            .collect();
        assert_eq!(
            knowledge["sensor:file"],
            StreamContinuity::NotObservableFileSource
        );
        assert_eq!(knowledge["sensor:full"], StreamContinuity::Verified);
        assert_eq!(knowledge["sensor:none"], StreamContinuity::NotObservable);
        assert_eq!(knowledge["sensor:part"], StreamContinuity::Degraded);
        assert_eq!(knowledge["sensor:gap"], StreamContinuity::Degraded);
        // A gapped witness of every capsule is never verified.
        let all_gapped: BTreeMap<_, _> = witnessed
            .keys()
            .map(|digest| (*digest, CoverageContinuity::Gapped))
            .collect();
        let output = inventory_witnessed(
            ledger.batches(),
            &StatusLimits::default(),
            &all_gapped,
            &mut |_| false,
            &mut |digest, _| objects.get(&digest).cloned().ok_or(StatusError::Unreadable),
            &mut || Ok(()),
        )?;
        assert!(
            output
                .streams
                .iter()
                .all(|row| row.continuity != StreamContinuity::Verified)
        );
        let file_row = output
            .streams
            .iter()
            .find(|row| row.sensor_id == "sensor:file")
            .ok_or("file stream")?;
        assert_eq!(file_row.capture_earliest, TimestampNs(0));
        assert_eq!(file_row.capture_latest, TimestampNs(10));
        Ok(())
    }
}
