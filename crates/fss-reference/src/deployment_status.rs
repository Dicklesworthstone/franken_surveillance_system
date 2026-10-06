#![forbid(unsafe_code)]
//! Read-only operational inventory over verified committed deployment state (fss-2h5zq.59).
//!
//! The sensor list is an inventory of retained capsule metadata, not a device registry or a
//! liveness check. Recorded gaps are not a current health assessment. Source payloads are not
//! read, and neither an empty inventory nor a gap-free stream certifies physical absence.
//! The existing orientation reader owns event, deletion and effect semantics. A second bounded
//! authority read must reproduce its anchor and record root before the inventory is returned.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use fss_core::{CanonicalDecode, ContentDigest, EvidenceDelta, EvidenceDeltaBatch, SensorCapsule};
use fss_ledger::{HostJournalReadIo, JournalReadIo, LedgerInspection, inspect_durable};

use crate::agent_orient::{DeploymentReadError, DeploymentSnapshot, OrientLimits, read_deployment};
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
    checkpoint()?;
    let snapshot = io.snapshot(root, &limits.snapshot)?;
    if snapshot.events.len() > limits.snapshot.max_events {
        return Err(StatusError::OverBudget);
    }
    checkpoint()?;
    let ledger = io.ledger(root, &layout, limits.snapshot.max_journal_bytes)?;
    same_authority(&snapshot, &layout, &ledger)?;
    let sources = inventory(
        &ledger.batches,
        limits,
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
    checkpoint()?;
    Ok(DeploymentStatus {
        snapshot,
        sources,
        ledger_present: after.status == fss_ledger::DurableLedgerStatus::Present,
    })
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

fn inventory(
    batches: &[EvidenceDeltaBatch],
    limits: &StatusLimits,
    deleted: &mut dyn FnMut(ContentDigest) -> bool,
    read: &mut dyn FnMut(ContentDigest, usize) -> Result<Vec<u8>, StatusError>,
    checkpoint: &mut dyn FnMut() -> Result<(), StatusError>,
) -> Result<SourceInventory, StatusError> {
    let mut latest: BTreeMap<&str, &EvidenceDelta> = BTreeMap::new();
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
            latest.insert(id, delta);
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
    let mut streams: BTreeMap<(String, String), StreamInventory> = BTreeMap::new();
    let mut identities = BTreeSet::new();
    for id in capsules {
        checkpoint()?;
        let delta = latest.get(id).ok_or(StatusError::Corrupt)?;
        if delta.family == FAMILY_DELETION_TOMBSTONE || deleted(delta.payload_digest) {
            output.deleted_capsules += 1;
            continue;
        }
        if delta.family != FAMILY_SENSOR_CAPSULE {
            return Err(StatusError::Corrupt);
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
    }
    for id in imports {
        checkpoint()?;
        let delta = latest.get(id).ok_or(StatusError::Corrupt)?;
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
    });
    row.capsules += 1;
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
}
