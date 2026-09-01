//! Immutable sensor evidence, witnessed absence, and append-only reference MVCC.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    BatchId, CanonicalEncode, CanonicalEncoder, CapsuleId, CaptureInterval, Completeness,
    ContentDigest, ContractError, ObjectId, OperationId, Plane, SensorId, StreamId, TimestampNs,
};

/// Clock basis used by a source capsule.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ClockBasis {
    /// Disciplined UTC estimate.
    UtcDisciplined,
    /// Device monotonic clock.
    DeviceMonotonic,
    /// Host monotonic clock.
    HostMonotonic,
    /// Inferred clock with explicit uncertainty.
    Estimated,
}

impl ClockBasis {
    fn as_str(self) -> &'static str {
        match self {
            Self::UtcDisciplined => "utc_disciplined",
            Self::DeviceMonotonic => "device_monotonic",
            Self::HostMonotonic => "host_monotonic",
            Self::Estimated => "estimated",
        }
    }
}

/// Immutable description of a captured source segment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensorCapsule {
    /// Capsule identity.
    pub capsule_id: CapsuleId,
    /// Sensor identity.
    pub sensor_id: SensorId,
    /// Stream generation identity.
    pub stream_id: StreamId,
    /// Sequence within the stream generation.
    pub sequence: u64,
    /// Conservative capture interval.
    pub capture: CaptureInterval,
    /// Host receive time.
    pub receive_time: TimestampNs,
    /// Clock basis for the capture interval.
    pub clock_basis: ClockBasis,
    /// Digest of exact source bytes.
    pub source_digest: ContentDigest,
    /// Number of source bytes represented.
    pub source_bytes: u64,
    /// Number of decoded frames represented.
    pub frame_count: u32,
    /// Whether a continuity gap precedes this capsule.
    pub gap_before: bool,
}

impl SensorCapsule {
    /// Constructs a capsule and binds its identity to exact source bytes.
    pub fn from_source_bytes(
        capsule_id: CapsuleId,
        sensor_id: SensorId,
        stream_id: StreamId,
        sequence: u64,
        capture: CaptureInterval,
        receive_time: TimestampNs,
        clock_basis: ClockBasis,
        source: &[u8],
        frame_count: u32,
        gap_before: bool,
    ) -> Self {
        Self {
            capsule_id,
            sensor_id,
            stream_id,
            sequence,
            capture,
            receive_time,
            clock_basis,
            source_digest: ContentDigest::sha256(source),
            source_bytes: source.len() as u64,
            frame_count,
            gap_before,
        }
    }

    /// Returns the canonical metadata digest for this capsule.
    #[must_use]
    pub fn metadata_digest(&self) -> ContentDigest {
        self.canonical_digest("fss.sensor_capsule.metadata.v1")
    }
}

impl CanonicalEncode for SensorCapsule {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.capsule_id.encode_canonical(encoder);
        self.sensor_id.encode_canonical(encoder);
        self.stream_id.encode_canonical(encoder);
        encoder.u64(self.sequence);
        self.capture.encode_canonical(encoder);
        self.receive_time.encode_canonical(encoder);
        encoder.text(self.clock_basis.as_str());
        encoder.digest(self.source_digest);
        encoder.u64(self.source_bytes);
        encoder.u32(self.frame_count);
        encoder.bool(self.gap_before);
    }
}

/// A stable MVCC anchor for one complete authority state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerAnchor {
    /// Deployment lineage.
    pub site_lineage: String,
    /// Epoch incremented by restore or incompatible reset.
    pub ledger_epoch: u64,
    /// Commit sequence within the epoch.
    pub commit_sequence: u64,
    /// Adapter registry epoch.
    pub adapter_registry_epoch: u64,
    /// Schema epoch.
    pub schema_epoch: u64,
    /// Policy epoch.
    pub policy_epoch: u64,
    /// Privacy epoch.
    pub privacy_epoch: u64,
    /// Root of the complete authority state.
    pub state_root: ContentDigest,
}

impl LedgerAnchor {
    /// Creates the genesis anchor for an empty state.
    #[must_use]
    pub fn genesis(site_lineage: impl Into<String>) -> Self {
        let state_root = state_root(&BTreeMap::new());
        Self {
            site_lineage: site_lineage.into(),
            ledger_epoch: 0,
            commit_sequence: 0,
            adapter_registry_epoch: 0,
            schema_epoch: 1,
            policy_epoch: 1,
            privacy_epoch: 1,
            state_root,
        }
    }
}

impl CanonicalEncode for LedgerAnchor {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.site_lineage);
        encoder.u64(self.ledger_epoch);
        encoder.u64(self.commit_sequence);
        encoder.u64(self.adapter_registry_epoch);
        encoder.u64(self.schema_epoch);
        encoder.u64(self.policy_epoch);
        encoder.u64(self.privacy_epoch);
        encoder.digest(self.state_root);
    }
}

/// One semantic object revision in the canonical evidence stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceDelta {
    /// Stable delta identity.
    pub delta_id: String,
    /// Semantic family.
    pub family: String,
    /// Stable object identity.
    pub object_id: ObjectId,
    /// Prior object generation, or no prior generation for creation.
    pub prior_generation: Option<u64>,
    /// New object generation.
    pub new_generation: u64,
    /// Validity interval.
    pub validity: CaptureInterval,
    /// Plane that owns the object.
    pub plane: Plane,
    /// Digest of the immutable object payload.
    pub payload_digest: ContentDigest,
    /// Optional witness digest.
    pub witness_digest: Option<ContentDigest>,
    /// Optional external operation identity.
    pub operation_id: Option<OperationId>,
}

impl EvidenceDelta {
    fn sort_key(&self) -> (&str, &str, u64, &str) {
        (
            self.family.as_str(),
            self.object_id.as_str(),
            self.new_generation,
            self.delta_id.as_str(),
        )
    }
}

impl CanonicalEncode for EvidenceDelta {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.delta_id);
        encoder.text(&self.family);
        self.object_id.encode_canonical(encoder);
        match self.prior_generation {
            Some(value) => {
                encoder.bool(true);
                encoder.u64(value);
            }
            None => encoder.bool(false),
        }
        encoder.u64(self.new_generation);
        self.validity.encode_canonical(encoder);
        self.plane.encode_canonical(encoder);
        encoder.digest(self.payload_digest);
        match self.witness_digest {
            Some(value) => {
                encoder.bool(true);
                encoder.digest(value);
            }
            None => encoder.bool(false),
        }
        match &self.operation_id {
            Some(value) => {
                encoder.bool(true);
                value.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
    }
}

/// Materialized semantic object state at one ledger anchor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectRevision {
    /// Object generation.
    pub generation: u64,
    /// Semantic family.
    pub family: String,
    /// Owning plane.
    pub plane: Plane,
    /// Payload digest.
    pub payload_digest: ContentDigest,
    /// Validity interval.
    pub validity: CaptureInterval,
}

impl CanonicalEncode for ObjectRevision {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.generation);
        encoder.text(&self.family);
        self.plane.encode_canonical(encoder);
        encoder.digest(self.payload_digest);
        self.validity.encode_canonical(encoder);
    }
}

/// One root-last published batch in the canonical history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceDeltaBatch {
    /// Stable batch identity.
    pub batch_id: BatchId,
    /// Exact basis anchor.
    pub basis_anchor: LedgerAnchor,
    /// Successor anchor.
    pub new_anchor: LedgerAnchor,
    /// Canonically ordered deltas.
    pub deltas: Vec<EvidenceDelta>,
    /// Child object roots that must exist before the batch root publishes.
    pub children: Vec<ContentDigest>,
    /// Digest of the complete batch.
    pub batch_digest: ContentDigest,
}

impl EvidenceDeltaBatch {
    /// Returns true when deltas follow the frozen canonical order.
    #[must_use]
    pub fn is_canonically_ordered(&self) -> bool {
        self.deltas
            .windows(2)
            .all(|pair| pair[0].sort_key() < pair[1].sort_key())
            && self.children.windows(2).all(|pair| pair[0] < pair[1])
    }

    /// Recomputes the batch digest with the digest field omitted.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        self.batch_id.encode_canonical(&mut encoder);
        self.basis_anchor.encode_canonical(&mut encoder);
        self.new_anchor.encode_canonical(&mut encoder);
        encoder.u64(self.deltas.len() as u64);
        for delta in &self.deltas {
            delta.encode_canonical(&mut encoder);
        }
        encoder.u64(self.children.len() as u64);
        for child in &self.children {
            encoder.digest(*child);
        }
        ContentDigest::sha256(&encoder.finish())
    }
}

/// Immutable state and history at one ledger commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerSnapshot {
    /// Snapshot anchor.
    pub anchor: LedgerAnchor,
    /// Materialized objects in canonical object-ID order.
    pub objects: BTreeMap<ObjectId, ObjectRevision>,
}

/// Single-threaded deterministic reference ledger.
#[derive(Clone, Debug)]
pub struct ReferenceLedger {
    snapshots: Vec<LedgerSnapshot>,
    batches: Vec<EvidenceDeltaBatch>,
}

impl ReferenceLedger {
    /// Creates an empty ledger.
    #[must_use]
    pub fn new(site_lineage: impl Into<String>) -> Self {
        let anchor = LedgerAnchor::genesis(site_lineage);
        Self {
            snapshots: vec![LedgerSnapshot {
                anchor,
                objects: BTreeMap::new(),
            }],
            batches: Vec::new(),
        }
    }

    /// Returns the latest complete snapshot.
    #[must_use]
    pub fn current(&self) -> &LedgerSnapshot {
        &self.snapshots[self.snapshots.len() - 1]
    }

    /// Returns the immutable published batches.
    #[must_use]
    pub fn batches(&self) -> &[EvidenceDeltaBatch] {
        &self.batches
    }

    /// Returns a snapshot at an exact commit sequence in the current epoch.
    #[must_use]
    pub fn snapshot_at(&self, sequence: u64) -> Option<&LedgerSnapshot> {
        self.snapshots
            .iter()
            .find(|snapshot| snapshot.anchor.commit_sequence == sequence)
    }

    /// Prepares a complete successor batch without publishing it.
    pub fn prepare_batch(
        &self,
        batch_id: BatchId,
        mut deltas: Vec<EvidenceDelta>,
        child_roots: impl IntoIterator<Item = ContentDigest>,
    ) -> Result<EvidenceDeltaBatch, ContractError> {
        deltas.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
        let mut children: Vec<_> = child_roots.into_iter().collect();
        children.sort_unstable();
        children.dedup();
        let next_objects = apply_deltas(&self.current().objects, &deltas)?;
        let basis_anchor = self.current().anchor.clone();
        let mut new_anchor = basis_anchor.clone();
        new_anchor.commit_sequence = new_anchor
            .commit_sequence
            .checked_add(1)
            .ok_or(ContractError::InvalidAnchorSuccessor)?;
        new_anchor.state_root = state_root(&next_objects);
        let mut batch = EvidenceDeltaBatch {
            batch_id,
            basis_anchor,
            new_anchor,
            deltas,
            children,
            batch_digest: ContentDigest::sha256(b"unpublished"),
        };
        batch.batch_digest = batch.computed_digest();
        Ok(batch)
    }

    /// Atomically verifies and publishes a prepared batch.
    pub fn append(&mut self, batch: EvidenceDeltaBatch) -> Result<&LedgerSnapshot, ContractError> {
        if batch.basis_anchor != self.current().anchor {
            return Err(ContractError::StaleAnchor);
        }
        let expected_sequence = batch
            .basis_anchor
            .commit_sequence
            .checked_add(1)
            .ok_or(ContractError::InvalidAnchorSuccessor)?;
        if batch.new_anchor.site_lineage != batch.basis_anchor.site_lineage
            || batch.new_anchor.ledger_epoch != batch.basis_anchor.ledger_epoch
            || batch.new_anchor.commit_sequence != expected_sequence
            || batch.new_anchor.adapter_registry_epoch
                != batch.basis_anchor.adapter_registry_epoch
            || batch.new_anchor.schema_epoch != batch.basis_anchor.schema_epoch
            || batch.new_anchor.policy_epoch != batch.basis_anchor.policy_epoch
            || batch.new_anchor.privacy_epoch != batch.basis_anchor.privacy_epoch
        {
            return Err(ContractError::InvalidAnchorSuccessor);
        }
        if !batch.is_canonically_ordered() {
            return Err(ContractError::NonCanonicalOrdering);
        }
        if batch.computed_digest() != batch.batch_digest {
            return Err(ContractError::DigestMismatch);
        }
        let next_objects = apply_deltas(&self.current().objects, &batch.deltas)?;
        if state_root(&next_objects) != batch.new_anchor.state_root {
            return Err(ContractError::DigestMismatch);
        }
        self.snapshots.push(LedgerSnapshot {
            anchor: batch.new_anchor.clone(),
            objects: next_objects,
        });
        self.batches.push(batch);
        Ok(self.current())
    }

    /// Replays a sequence of batches into a fresh ledger and returns its terminal anchor.
    pub fn replay(
        site_lineage: impl Into<String>,
        batches: impl IntoIterator<Item = EvidenceDeltaBatch>,
    ) -> Result<Self, ContractError> {
        let mut ledger = Self::new(site_lineage);
        for batch in batches {
            let _ = ledger.append(batch)?;
        }
        Ok(ledger)
    }
}

/// Continuity classification for a negative-read witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageContinuity {
    /// No gap exists in the declared interval and domain.
    Continuous,
    /// At least one declared gap exists.
    Gapped,
    /// Continuity could not be established.
    Unknown,
}

/// Why coverage evaluation stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageStopReason {
    /// The complete declared domain was evaluated.
    Complete,
    /// The resource budget ended evaluation.
    BudgetExhausted,
    /// The caller cancelled evaluation.
    Cancelled,
    /// A source gap prevented certification.
    SourceGap,
    /// Capability filtering removed required state.
    AuthorizationFiltered,
    /// The requested predicate is unsupported.
    Unsupported,
    /// An expected failure occurred.
    Error,
}

/// Proof boundary for a negative claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageWitness {
    /// Exact ledger anchor.
    pub anchor: LedgerAnchor,
    /// Authorized domain requested by the caller.
    pub authorized_domain: BTreeSet<String>,
    /// Domain actually observed.
    pub observed_domain: BTreeSet<String>,
    /// Explicit exclusions.
    pub excluded_domain: BTreeSet<String>,
    /// Continuity classification.
    pub continuity: CoverageContinuity,
    /// Completeness classification.
    pub completeness: Completeness,
    /// Predicate whose absence is claimed.
    pub negative_predicate: String,
    /// Evaluation stop reason.
    pub stop_reason: CoverageStopReason,
}

impl CoverageWitness {
    /// Returns whether this witness certifies absence for its exact declared domain.
    #[must_use]
    pub fn certifies_absence(&self) -> bool {
        !self.negative_predicate.is_empty()
            && self.continuity == CoverageContinuity::Continuous
            && self.completeness == Completeness::Complete
            && self.stop_reason == CoverageStopReason::Complete
            && self.excluded_domain.is_empty()
            && self.authorized_domain == self.observed_domain
    }

    /// Returns a stable witness digest.
    #[must_use]
    pub fn witness_digest(&self) -> ContentDigest {
        self.canonical_digest("fss.coverage_witness.v1")
    }

    /// Fails closed if the witness cannot certify absence.
    pub fn require_certified_absence(&self) -> Result<(), ContractError> {
        if self.certifies_absence() {
            Ok(())
        } else {
            Err(ContractError::CoverageUncertified)
        }
    }
}

impl CanonicalEncode for CoverageWitness {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.anchor.encode_canonical(encoder);
        encode_set(&self.authorized_domain, encoder);
        encode_set(&self.observed_domain, encoder);
        encode_set(&self.excluded_domain, encoder);
        encoder.u8(match self.continuity {
            CoverageContinuity::Continuous => 1,
            CoverageContinuity::Gapped => 2,
            CoverageContinuity::Unknown => 3,
        });
        encoder.u8(match self.completeness {
            Completeness::Complete => 1,
            Completeness::Bounded => 2,
            Completeness::Partial => 3,
            Completeness::Unknown => 4,
            Completeness::NotObservable => 5,
            Completeness::Unauthorized => 6,
            Completeness::Stale => 7,
        });
        encoder.text(&self.negative_predicate);
        encoder.u8(match self.stop_reason {
            CoverageStopReason::Complete => 1,
            CoverageStopReason::BudgetExhausted => 2,
            CoverageStopReason::Cancelled => 3,
            CoverageStopReason::SourceGap => 4,
            CoverageStopReason::AuthorizationFiltered => 5,
            CoverageStopReason::Unsupported => 6,
            CoverageStopReason::Error => 7,
        });
    }
}

fn encode_set(values: &BTreeSet<String>, encoder: &mut CanonicalEncoder) {
    encoder.u64(values.len() as u64);
    for value in values {
        encoder.text(value);
    }
}

fn apply_deltas(
    basis: &BTreeMap<ObjectId, ObjectRevision>,
    deltas: &[EvidenceDelta],
) -> Result<BTreeMap<ObjectId, ObjectRevision>, ContractError> {
    let mut next = basis.clone();
    let mut seen = BTreeSet::new();
    for delta in deltas {
        if !seen.insert(delta.object_id.clone()) {
            return Err(ContractError::GenerationConflict);
        }
        match next.get(&delta.object_id) {
            Some(current) => {
                let expected_generation = current
                    .generation
                    .checked_add(1)
                    .ok_or(ContractError::GenerationConflict)?;
                if delta.prior_generation != Some(current.generation)
                    || delta.new_generation != expected_generation
                {
                    return Err(ContractError::GenerationConflict);
                }
            }
            None => {
                if delta.prior_generation.is_some() || delta.new_generation != 1 {
                    return Err(ContractError::GenerationConflict);
                }
            }
        }
        next.insert(
            delta.object_id.clone(),
            ObjectRevision {
                generation: delta.new_generation,
                family: delta.family.clone(),
                plane: delta.plane,
                payload_digest: delta.payload_digest,
                validity: delta.validity,
            },
        );
    }
    Ok(next)
}

fn state_root(objects: &BTreeMap<ObjectId, ObjectRevision>) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.reference_state.v1");
    encoder.u64(objects.len() as u64);
    for (object_id, revision) in objects {
        object_id.encode_canonical(&mut encoder);
        revision.encode_canonical(&mut encoder);
    }
    ContentDigest::sha256(&encoder.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interval() -> Result<CaptureInterval, ContractError> {
        CaptureInterval::new(TimestampNs(10), TimestampNs(20))
    }

    fn delta(id: &str, object: &str, prior: Option<u64>, generation: u64) -> Result<EvidenceDelta, ContractError> {
        Ok(EvidenceDelta {
            delta_id: id.to_owned(),
            family: "sensor_capsule".to_owned(),
            object_id: ObjectId::parse(object)?,
            prior_generation: prior,
            new_generation: generation,
            validity: interval()?,
            plane: Plane::Authority,
            payload_digest: ContentDigest::sha256(id.as_bytes()),
            witness_digest: None,
            operation_id: None,
        })
    }

    #[test]
    fn ledger_replay_is_deterministic() -> Result<(), ContractError> {
        let mut ledger = ReferenceLedger::new("site:one");
        let batch = ledger.prepare_batch(
            BatchId::parse("batch:one")?,
            vec![delta("delta:b", "object:b", None, 1)?, delta("delta:a", "object:a", None, 1)?],
            [],
        )?;
        let terminal = ledger.append(batch.clone())?.anchor.clone();
        let replay = ReferenceLedger::replay("site:one", [batch])?;
        assert_eq!(terminal, replay.current().anchor);
        Ok(())
    }

    #[test]
    fn stale_anchor_is_rejected() -> Result<(), ContractError> {
        let ledger = ReferenceLedger::new("site:one");
        let mut batch = ledger.prepare_batch(
            BatchId::parse("batch:one")?,
            vec![delta("delta:a", "object:a", None, 1)?],
            [],
        )?;
        batch.basis_anchor.commit_sequence = 99;
        let mut target = ReferenceLedger::new("site:one");
        assert_eq!(target.append(batch), Err(ContractError::StaleAnchor));
        Ok(())
    }

    #[test]
    fn negative_read_requires_complete_continuous_domain() {
        let anchor = LedgerAnchor::genesis("site:one");
        let witness = CoverageWitness {
            anchor,
            authorized_domain: BTreeSet::from(["zone:yard".to_owned()]),
            observed_domain: BTreeSet::from(["zone:yard".to_owned()]),
            excluded_domain: BTreeSet::new(),
            continuity: CoverageContinuity::Continuous,
            completeness: Completeness::Complete,
            negative_predicate: "no_person_present".to_owned(),
            stop_reason: CoverageStopReason::Complete,
        };
        assert!(witness.certifies_absence());
    }
}
