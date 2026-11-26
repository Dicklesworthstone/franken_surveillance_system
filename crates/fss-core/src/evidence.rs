//! Immutable sensor evidence, witnessed absence, and append-only reference MVCC.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

mod append;
pub use append::{LedgerAppendGuard, PreparedLedgerAppend, ResumeLedgerAppendError};

use crate::{
    BatchId, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CapsuleId,
    CaptureInterval, Completeness, ContentDigest, ContractError, ObjectId, OperationId, Plane,
    SensorId, StreamId, TimestampNs,
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
    /// Returns the canonical string representation of this clock basis.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UtcDisciplined => "utc_disciplined",
            Self::DeviceMonotonic => "device_monotonic",
            Self::HostMonotonic => "host_monotonic",
            Self::Estimated => "estimated",
        }
    }

    /// Parses a clock basis from its canonical string representation.
    pub fn parse(s: &str) -> Result<Self, ContractError> {
        match s {
            "utc_disciplined" => Ok(Self::UtcDisciplined),
            "device_monotonic" => Ok(Self::DeviceMonotonic),
            "host_monotonic" => Ok(Self::HostMonotonic),
            "estimated" => Ok(Self::Estimated),
            other => Err(ContractError::UnknownClockBasisName(other.to_string())),
        }
    }
}

impl core::fmt::Display for ClockBasis {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::str::FromStr for ClockBasis {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
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

/// Parameters for constructing a `SensorCapsule` from raw source bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensorSourceBytesSpec<'a> {
    /// Canonical capsule identity.
    pub capsule_id: CapsuleId,
    /// Sensor identity.
    pub sensor_id: SensorId,
    /// Stream identity.
    pub stream_id: StreamId,
    /// Stream sequence number.
    pub sequence: u64,
    /// Time interval captured by this capsule.
    pub capture: CaptureInterval,
    /// Ingest arrival time.
    pub receive_time: TimestampNs,
    /// Clock synchronization state at ingest.
    pub clock_basis: ClockBasis,
    /// Exact source payload bytes.
    pub source: &'a [u8],
    /// Number of decoded frames represented.
    pub frame_count: u32,
    /// Whether a continuity gap precedes this capsule.
    pub gap_before: bool,
}

impl<'a> SensorSourceBytesSpec<'a> {
    /// Validates physical and temporal invariants of this sensor specification.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.capture.earliest > self.capture.latest || self.receive_time < self.capture.earliest
        {
            return Err(ContractError::InvertedTimeInterval);
        }
        if self.source.is_empty() && self.frame_count > 0 {
            return Err(ContractError::EvidenceRequired);
        }
        Ok(())
    }
}

impl SensorCapsule {
    /// Constructs a capsule and binds its identity to exact source bytes.
    pub fn from_source_bytes(spec: SensorSourceBytesSpec<'_>) -> Result<Self, ContractError> {
        spec.validate()?;
        Ok(Self {
            capsule_id: spec.capsule_id,
            sensor_id: spec.sensor_id,
            stream_id: spec.stream_id,
            sequence: spec.sequence,
            capture: spec.capture,
            receive_time: spec.receive_time,
            clock_basis: spec.clock_basis,
            source_digest: ContentDigest::sha256(spec.source),
            source_bytes: spec.source.len() as u64,
            frame_count: spec.frame_count,
            gap_before: spec.gap_before,
        })
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

impl CanonicalDecode for SensorCapsule {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let capsule_id = CapsuleId::decode_canonical(decoder)?;
        let sensor_id = SensorId::decode_canonical(decoder)?;
        let stream_id = StreamId::decode_canonical(decoder)?;
        let sequence = decoder.u64()?;
        let capture = CaptureInterval::decode_canonical(decoder)?;
        let receive_time = TimestampNs::decode_canonical(decoder)?;
        let clock_basis = ClockBasis::parse(decoder.text()?)?;
        let source_digest = decoder.digest()?;
        let source_bytes = decoder.u64()?;
        let frame_count = decoder.u32()?;
        let gap_before = decoder.bool()?;

        if capture.earliest > capture.latest || receive_time < capture.earliest {
            return Err(ContractError::InvertedTimeInterval);
        }

        Ok(Self {
            capsule_id,
            sensor_id,
            stream_id,
            sequence,
            capture,
            receive_time,
            clock_basis,
            source_digest,
            source_bytes,
            frame_count,
            gap_before,
        })
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

impl CanonicalDecode for LedgerAnchor {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let site_lineage = decoder.text()?.to_string();
        let ledger_epoch = decoder.u64()?;
        let commit_sequence = decoder.u64()?;
        let adapter_registry_epoch = decoder.u64()?;
        let schema_epoch = decoder.u64()?;
        let policy_epoch = decoder.u64()?;
        let privacy_epoch = decoder.u64()?;
        let state_root = decoder.digest()?;
        Ok(Self {
            site_lineage,
            ledger_epoch,
            commit_sequence,
            adapter_registry_epoch,
            schema_epoch,
            policy_epoch,
            privacy_epoch,
            state_root,
        })
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
    /// Plane that owns the object, fixed by its first committed generation.
    /// A successor must preserve this owner; validated cross-plane publication uses a distinct
    /// target object identity and its own authority checks.
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

impl From<&EvidenceDelta> for ObjectRevision {
    fn from(delta: &EvidenceDelta) -> Self {
        Self {
            generation: delta.new_generation,
            family: delta.family.clone(),
            plane: delta.plane,
            payload_digest: delta.payload_digest,
            validity: delta.validity,
        }
    }
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
    /// Registered schema identity (registries/SCHEMAS.md row
    /// SCHEMA-EVIDENCE-DELTA-001; mirrors `schemas/evidence_delta_batch.v1.json`).
    pub const SCHEMA: &'static str = "fss.evidence_delta_batch.v1";

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

/// Which committed object-map materializations a reference ledger keeps resident.
///
/// This changes memory ownership only. Every canonical batch and committed batch identity is
/// retained in either mode; no evidence, journal record or object-retention policy is changed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LedgerSnapshotRetention {
    /// Retain every materialized commit, including genesis, for [`ReferenceLedger::snapshot_at`].
    #[default]
    FullHistory,
    /// Retain only the current materialized commit. Historical states can be replayed from batches.
    CurrentOnly,
}

/// Single-threaded deterministic reference ledger.
#[derive(Debug)]
pub struct ReferenceLedger {
    snapshots: Vec<LedgerSnapshot>,
    snapshot_retention: LedgerSnapshotRetention,
    batches: Vec<EvidenceDeltaBatch>,
    committed_batches: BTreeMap<BatchId, ContentDigest>,
    // Private live identity, never encoded or used as canonical evidence. A
    // cloned reference branch cannot install another owner's suspended stage.
    append_owner: Arc<()>,
}

impl Clone for ReferenceLedger {
    fn clone(&self) -> Self {
        Self {
            snapshots: self.snapshots.clone(),
            snapshot_retention: self.snapshot_retention,
            batches: self.batches.clone(),
            committed_batches: self.committed_batches.clone(),
            append_owner: Arc::new(()),
        }
    }
}

impl ReferenceLedger {
    /// Creates an empty ledger that retains every historical materialized snapshot.
    #[must_use]
    pub fn new(site_lineage: impl Into<String>) -> Self {
        Self::new_with_snapshot_retention(site_lineage, LedgerSnapshotRetention::FullHistory)
    }

    /// Creates an empty ledger with explicit resident snapshot ownership.
    ///
    /// `CurrentOnly` keeps exactly one committed object map, initially genesis. A staged append
    /// privately owns one additional successor until it commits or is abandoned. Canonical
    /// batches and their identity index remain complete, independent of the selected mode.
    #[must_use]
    pub fn new_with_snapshot_retention(
        site_lineage: impl Into<String>,
        snapshot_retention: LedgerSnapshotRetention,
    ) -> Self {
        let anchor = LedgerAnchor::genesis(site_lineage);
        Self {
            snapshots: vec![LedgerSnapshot {
                anchor,
                objects: BTreeMap::new(),
            }],
            snapshot_retention,
            batches: Vec::new(),
            committed_batches: BTreeMap::new(),
            append_owner: Arc::new(()),
        }
    }

    /// Selected resident snapshot ownership; fixed for this live ledger's lifetime.
    #[must_use]
    pub const fn snapshot_retention(&self) -> LedgerSnapshotRetention {
        self.snapshot_retention
    }

    /// Number of resident committed object maps, excluding a privately staged successor.
    ///
    /// This is one in `CurrentOnly` mode. It does not count canonical batches or identity entries,
    /// which remain resident in both modes, and is not a total-memory measurement.
    #[must_use]
    pub fn retained_snapshot_count(&self) -> usize {
        self.snapshots.len()
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

    /// Returns a retained snapshot at an exact commit sequence in the current epoch.
    ///
    /// The default `FullHistory` mode retains every committed sequence. `CurrentOnly` returns
    /// `None` for older sequences even though their complete canonical batches remain available.
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
        Ok(self.stage_append(batch)?.commit())
    }

    /// Replays a sequence of batches into a fresh ledger and returns its terminal anchor.
    pub fn replay(
        site_lineage: impl Into<String>,
        batches: impl IntoIterator<Item = EvidenceDeltaBatch>,
    ) -> Result<Self, ContractError> {
        Self::replay_with_snapshot_retention(
            site_lineage,
            LedgerSnapshotRetention::FullHistory,
            batches,
        )
    }

    /// Replays every batch with the ordinary semantic checks and explicit snapshot ownership.
    ///
    /// Both modes preserve the exact terminal state and full canonical batch/identity history.
    pub fn replay_with_snapshot_retention(
        site_lineage: impl Into<String>,
        snapshot_retention: LedgerSnapshotRetention,
        batches: impl IntoIterator<Item = EvidenceDeltaBatch>,
    ) -> Result<Self, ContractError> {
        let mut ledger = Self::new_with_snapshot_retention(site_lineage, snapshot_retention);
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
    /// Authorized generation requested by the caller.
    pub authorized_generation: u64,
    /// Generation actually observed.
    pub observed_generation: u64,
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
            && !self.authorized_domain.is_empty()
            && self.authorized_domain == self.observed_domain
            && self.authorized_generation > 0
            && self.authorized_generation == self.observed_generation
    }

    /// Returns a stable witness digest.
    #[must_use]
    pub fn witness_digest(&self) -> ContentDigest {
        self.canonical_digest("fss.coverage_witness.v1")
    }

    /// Fails closed if the witness cannot certify absence.
    pub fn require_certified_absence(&self) -> Result<(), ContractError> {
        if self.authorized_generation == 0 || self.authorized_generation != self.observed_generation
        {
            return Err(ContractError::GenerationConflict);
        }
        if self.authorized_domain.is_empty() || self.authorized_domain != self.observed_domain {
            return Err(ContractError::CoverageUncertified);
        }
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
        encoder.u64(self.authorized_generation);
        encoder.u64(self.observed_generation);
    }
}

impl CanonicalDecode for CoverageWitness {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let anchor = LedgerAnchor::decode_canonical(decoder)?;
        let authorized_domain = decode_set(decoder)?;
        let observed_domain = decode_set(decoder)?;
        let excluded_domain = decode_set(decoder)?;
        let continuity = match decoder.u8()? {
            1 => CoverageContinuity::Continuous,
            2 => CoverageContinuity::Gapped,
            3 => CoverageContinuity::Unknown,
            _ => return Err(ContractError::InvalidIdentifier),
        };
        let completeness = match decoder.u8()? {
            1 => Completeness::Complete,
            2 => Completeness::Bounded,
            3 => Completeness::Partial,
            4 => Completeness::Unknown,
            5 => Completeness::NotObservable,
            6 => Completeness::Unauthorized,
            7 => Completeness::Stale,
            _ => return Err(ContractError::InvalidIdentifier),
        };
        let negative_predicate = decoder.text()?.to_string();
        let stop_reason = match decoder.u8()? {
            1 => CoverageStopReason::Complete,
            2 => CoverageStopReason::BudgetExhausted,
            3 => CoverageStopReason::Cancelled,
            4 => CoverageStopReason::SourceGap,
            5 => CoverageStopReason::AuthorizationFiltered,
            6 => CoverageStopReason::Unsupported,
            7 => CoverageStopReason::Error,
            _ => return Err(ContractError::InvalidIdentifier),
        };
        let authorized_generation = decoder.u64()?;
        let observed_generation = decoder.u64()?;
        Ok(Self {
            anchor,
            authorized_domain,
            observed_domain,
            excluded_domain,
            continuity,
            completeness,
            negative_predicate,
            stop_reason,
            authorized_generation,
            observed_generation,
        })
    }
}

fn encode_set(values: &BTreeSet<String>, encoder: &mut CanonicalEncoder) {
    encoder.u64(values.len() as u64);
    for value in values {
        encoder.text(value);
    }
}

fn decode_set(decoder: &mut CanonicalDecoder<'_>) -> Result<BTreeSet<String>, ContractError> {
    let len = decoder.u64()?;
    let len = usize::try_from(len).map_err(|_| ContractError::InvalidIdentifier)?;
    let mut set = BTreeSet::new();
    for _ in 0..len {
        let value = decoder.text()?.to_string();
        // Canonical sets are encoded strictly increasing. Accepting a duplicate or out-of-order
        // entry would let several byte strings decode to the same witness.
        if set
            .last()
            .is_some_and(|previous: &String| previous >= &value)
        {
            return Err(ContractError::NonCanonicalOrdering);
        }
        set.insert(value);
    }
    Ok(set)
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
                if delta.plane != current.plane {
                    return Err(ContractError::ObjectPlaneConflict {
                        object_id: delta.object_id.clone(),
                        committed_plane: current.plane,
                        delta_plane: delta.plane,
                    });
                }
            }
            None => {
                if delta.prior_generation.is_some() || delta.new_generation != 1 {
                    return Err(ContractError::GenerationConflict);
                }
            }
        }
        next.insert(delta.object_id.clone(), ObjectRevision::from(delta));
    }
    Ok(next)
}

/// Computes the canonical v1 reference-state commitment for a materialized object map.
#[must_use]
pub fn state_root(objects: &BTreeMap<ObjectId, ObjectRevision>) -> ContentDigest {
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

    fn delta(
        id: &str,
        object: &str,
        prior: Option<u64>,
        generation: u64,
    ) -> Result<EvidenceDelta, ContractError> {
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
            vec![
                delta("delta:b", "object:b", None, 1)?,
                delta("delta:a", "object:a", None, 1)?,
            ],
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
            authorized_generation: 1,
            observed_generation: 1,
        };
        assert!(witness.certifies_absence());
        assert_eq!(witness.require_certified_absence(), Ok(()));
    }

    #[test]
    fn negative_read_fails_on_generation_mismatch() {
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
            authorized_generation: 2,
            observed_generation: 1,
        };
        assert!(!witness.certifies_absence());
        assert_eq!(
            witness.require_certified_absence(),
            Err(ContractError::GenerationConflict)
        );
    }

    #[test]
    fn negative_read_fails_on_gapped_continuity() {
        let anchor = LedgerAnchor::genesis("site:one");
        let witness = CoverageWitness {
            anchor,
            authorized_domain: BTreeSet::from(["zone:yard".to_owned()]),
            observed_domain: BTreeSet::from(["zone:yard".to_owned()]),
            excluded_domain: BTreeSet::new(),
            continuity: CoverageContinuity::Gapped,
            completeness: Completeness::Complete,
            negative_predicate: "no_person_present".to_owned(),
            stop_reason: CoverageStopReason::Complete,
            authorized_generation: 1,
            observed_generation: 1,
        };
        assert!(!witness.certifies_absence());
        assert_eq!(
            witness.require_certified_absence(),
            Err(ContractError::CoverageUncertified)
        );
    }

    #[test]
    fn batch_id_reuse_with_different_content_is_rejected() -> Result<(), ContractError> {
        let mut ledger = ReferenceLedger::new("site:one");
        let first = ledger.prepare_batch(
            BatchId::parse("batch:one")?,
            vec![delta("delta:a", "object:a", None, 1)?],
            [],
        )?;
        let first_snapshot = ledger.append(first.clone())?.clone();
        assert_eq!(first_snapshot.anchor.commit_sequence, 1);

        // Prepare a new successor batch reusing the same BatchId with different content
        let reuse = ledger.prepare_batch(
            BatchId::parse("batch:one")?,
            vec![delta("delta:b", "object:b", None, 1)?],
            [],
        )?;
        assert_eq!(reuse.basis_anchor, ledger.current().anchor);
        assert_ne!(reuse.batch_digest, first.batch_digest);

        let result = ledger.append(reuse);
        assert_eq!(result, Err(ContractError::IdempotencyConflict));
        assert_eq!(ledger.current().anchor.commit_sequence, 1);
        assert_eq!(ledger.batches().len(), 1);
        Ok(())
    }

    #[test]
    fn identical_batch_resubmission_keeps_stale_anchor_classification() -> Result<(), ContractError>
    {
        let mut ledger = ReferenceLedger::new("site:one");
        let first = ledger.prepare_batch(
            BatchId::parse("batch:one")?,
            vec![delta("delta:a", "object:a", None, 1)?],
            [],
        )?;
        let first_snapshot = ledger.append(first.clone())?.clone();
        assert_eq!(first_snapshot.anchor.commit_sequence, 1);

        // Identical resubmission: same batch_id and same content
        let resubmission_result = ledger.append(first);
        assert_eq!(resubmission_result, Err(ContractError::StaleAnchor));
        assert_eq!(ledger.current().anchor.commit_sequence, 1);
        assert_eq!(ledger.batches().len(), 1);
        Ok(())
    }
}
