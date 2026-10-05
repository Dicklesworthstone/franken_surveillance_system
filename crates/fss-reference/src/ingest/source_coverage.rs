#![forbid(unsafe_code)]
//! Retained coverage witnesses of continuous live or virtual sources, and the one rule by which a
//! stored witness certifies a rejected event's absence (fss-tch7u).
//!
//! The recorded pipelines ([`super::recorded_coverage`]) retain a witness per analysed recording.
//! A live or virtual camera has no such analysis: what it can honestly say is that each failure
//! domain delivered sensor capsules that tile an interval with no gap. A [`SourceCoverageRecord`]
//! retains exactly that: the interval, every source frame (failure domain, sensor, stream,
//! sequence, conservative capture interval, clock basis, `gap_before`, capsule digest and source
//! payload digest), and the fss-core [`CoverageWitness`] *derived* from them, anchored at the
//! authority anchor the producer read (the witness basis). A domain is observed only when its
//! frames tile the whole interval, none is preceded by a gap, and none has an `estimated` clock;
//! a file import (always `estimated`) is never a continuity source and is refused. Decoding
//! re-derives the witness from the frames, so a record cannot carry a witness its frames do not
//! support.
//!
//! Retention ([`retain_source_coverage`]) follows the recorded coverage approval discipline: the
//! caller presents [`SourceCoverageRecord::approval_digest`], every source capsule is re-read from
//! the spool and must decode to exactly its recorded frame, and the record is committed as one
//! `coverage_witness` ledger delta (the same family as the recorded pipelines; the record has its
//! own magic `FSSSCW01` and registered digest domain `fss.source_coverage_record.v1`) whose batch
//! children are the record, the witness and every source capsule and payload: the record's custody.
//!
//! [`verify_retained_coverage`] is the shared rule of the situation compiler and `fss orient`.
//! A stored witness certifies a rejected event's absence only when its record is committed and
//! intact, the witness certifies absence over a domain covering the event's domains and interval
//! with the event kind's predicate, the event cites the stored witness as contradicting evidence,
//! its basis is a committed anchor of this ledger, and **no coverage-relevant commit follows the
//! basis**. Every delta committed after the basis, and every delta committed at or before it whose
//! validity overlaps the record's interval (the producer assesses delivery, not observations, so
//! evidence of the interval is never skipped by choosing a later basis), is coverage-relevant
//! except exactly these bookkeeping deltas:
//!
//! * the record's own `coverage_witness` retention delta;
//! * the `event_revision` delta publishing exactly the cited revision of the event, and the
//!   `sensor_tamper_status` delta of the event in that same batch;
//! * a `sensor_capsule` delta whose payload is one of the record's own source capsules;
//! * a `local_root_reachability` delta (a slot commit),
//!
//! and only in a batch whose child objects are all accounted for: the record's source capsules and
//! payloads, the witness, the record, and the cited publication's objects (its event root,
//! revision object, revision digest object and tamper status). Any other delta (another sensor's
//! capsule, any observation or model result, another event or another revision of this event, a
//! privacy mask, a deletion or retraction, a hold, another coverage record, an effect outcome, an
//! unknown family) and any change of the ledger epoch, site lineage, adapter-registry, schema,
//! policy or privacy epoch after the basis invalidates the certification. When in doubt, it
//! invalidates.
//!
//! **No-Claim.** Certification means only that the retained pipeline over the authorized domains
//! observed nothing during the interval: every authorized domain delivered continuously and the
//! policy rejected the candidate over that evidence. It is not physical absence outside the
//! authorized domains, outside the interval, or below what the sensors and model can perceive.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{
    BatchId, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    ClockBasis, Completeness, ContentDigest, ContractError, CoverageContinuity, CoverageStopReason,
    CoverageWitness, EventHypothesis, EventKind, EventState, EvidenceDelta, EvidenceDeltaBatch,
    LedgerAnchor, ObjectId, Plane, SensorCapsule, TimestampNs,
};
use fss_object::SpoolError;
use fss_publication::ROOT_REACHABILITY_FAMILY;

use crate::reference_deployment::{
    FAMILY_COVERAGE_WITNESS, FAMILY_EVENT_REVISION, FAMILY_SENSOR_CAPSULE,
    FAMILY_SENSOR_TAMPER_STATUS,
};
use crate::{ReferenceDeployment, ReferenceError, ReplayCx};

/// Magic prefix of a source coverage record (distinct from the recorded pipelines' `FSSCOV01`).
pub const SOURCE_RECORD_MAGIC: &[u8] = b"FSSSCW01";
/// Format version of a source coverage record.
pub const SOURCE_RECORD_VERSION: u32 = 1;
/// Registered digest domain bound into every record's bytes.
pub const SOURCE_RECORD_DOMAIN: &str = "fss.source_coverage_record.v1";
/// Registered digest domain of the exact retention approval.
pub const SOURCE_APPROVAL_DOMAIN: &str = "fss.source_coverage_approval.v1";
/// Most source frames one record may name.
pub const MAX_SOURCE_FRAMES: usize = 65_536;
/// Most authorized domains one record may name.
pub const MAX_SOURCE_DOMAINS: usize = 64;
/// Largest record byte image accepted on read.
pub const MAX_SOURCE_RECORD_BYTES: usize = 16 * 1024 * 1024;

fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// One delivered source frame a record rests on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceFrame {
    /// Failure domain the frame's sensor belongs to (owner-declared).
    pub failure_domain: String,
    /// Sensor identity.
    pub sensor_id: String,
    /// Stream identity.
    pub stream_id: String,
    /// Sequence within the stream.
    pub sequence: u64,
    /// Conservative capture interval.
    pub capture: CaptureInterval,
    /// Clock basis of the capture interval.
    pub clock_basis: ClockBasis,
    /// Whether a continuity gap precedes the frame.
    pub gap_before: bool,
    /// Spool digest of the canonical capsule bytes.
    pub capsule_digest: ContentDigest,
    /// Spool digest of the exact source payload the capsule binds.
    pub source_digest: ContentDigest,
}

impl SourceFrame {
    /// The frame of `capsule`, retained under `failure_domain`.
    #[must_use]
    pub fn of(failure_domain: &str, capsule: &SensorCapsule) -> Self {
        Self {
            failure_domain: failure_domain.to_owned(),
            sensor_id: capsule.sensor_id.as_str().to_owned(),
            stream_id: capsule.stream_id.as_str().to_owned(),
            sequence: capsule.sequence,
            capture: capsule.capture,
            clock_basis: capsule.clock_basis,
            gap_before: capsule.gap_before,
            capsule_digest: ContentDigest::sha256(&capsule.canonical_bytes()),
            source_digest: capsule.source_digest,
        }
    }

    /// Whether `capsule` is exactly this frame.
    fn matches(&self, capsule: &SensorCapsule) -> bool {
        Self::of(&self.failure_domain, capsule) == *self
    }

    fn order_key(&self) -> (&str, TimestampNs, TimestampNs, u64, ContentDigest) {
        (
            self.failure_domain.as_str(),
            self.capture.earliest,
            self.capture.latest,
            self.sequence,
            self.capsule_digest,
        )
    }

    fn encode(&self, e: &mut CanonicalEncoder) {
        e.text(&self.failure_domain);
        e.text(&self.sensor_id);
        e.text(&self.stream_id);
        e.u64(self.sequence);
        self.capture.encode_canonical(e);
        self.clock_basis.encode_canonical(e);
        e.bool(self.gap_before);
        e.digest(self.capsule_digest);
        e.digest(self.source_digest);
    }

    fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            failure_domain: d.text()?.to_owned(),
            sensor_id: d.text()?.to_owned(),
            stream_id: d.text()?.to_owned(),
            sequence: d.u64()?,
            capture: CaptureInterval::decode_canonical(d)?,
            clock_basis: ClockBasis::decode_canonical(d)?,
            gap_before: d.bool()?,
            capsule_digest: d.digest()?,
            source_digest: d.digest()?,
        })
    }
}

/// Inputs of [`build_source_coverage`].
#[derive(Clone, Debug)]
pub struct SourceCoverageInput<'a> {
    /// Authority anchor the producer read: the witness basis.
    pub basis: LedgerAnchor,
    /// Interval whose continuous delivery is assessed.
    pub interval: CaptureInterval,
    /// Negative predicate the witness states (for example `no_unknown_person_present`).
    pub negative_predicate: &'a str,
    /// Owner-authorized failure domains.
    pub authorized_domain: BTreeSet<String>,
    /// Every delivered capsule with its failure domain.
    pub sources: Vec<(String, &'a SensorCapsule)>,
}

/// One retained continuity witness of live or virtual sources.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceCoverageRecord {
    /// Interval whose delivery the witness assesses.
    pub interval: CaptureInterval,
    /// Every source frame, in canonical (domain, capture, sequence, digest) order.
    pub frames: Vec<SourceFrame>,
    /// The witness derived from the frames, anchored at the producer's basis.
    pub witness: CoverageWitness,
}

/// Builds the record of `input`: the witness is derived from the frames, never supplied.
///
/// # Errors
/// [`ContractError::CoverageUncertified`] for a frame with an `estimated` clock (a file import is
/// never a continuity source); [`ContractError::InvalidIdentifier`] for an empty or unauthorized
/// domain, an empty predicate, a duplicate capsule, a sensor named under two domains, or a frame
/// outside the interval; [`ContractError::BudgetExhausted`] above the frame or domain bound.
pub fn build_source_coverage(
    input: &SourceCoverageInput<'_>,
) -> Result<SourceCoverageRecord, ContractError> {
    let mut frames: Vec<SourceFrame> = input
        .sources
        .iter()
        .map(|(domain, capsule)| SourceFrame::of(domain, capsule))
        .collect();
    frames.sort_by(|a, b| a.order_key().cmp(&b.order_key()));
    let witness = derive_witness(
        &input.basis,
        input.interval,
        input.negative_predicate,
        &input.authorized_domain,
        &frames,
    )?;
    Ok(SourceCoverageRecord {
        interval: input.interval,
        frames,
        witness,
    })
}

/// Derives the witness of `frames` (already in canonical order) over `interval`.
fn derive_witness(
    basis: &LedgerAnchor,
    interval: CaptureInterval,
    predicate: &str,
    authorized: &BTreeSet<String>,
    frames: &[SourceFrame],
) -> Result<CoverageWitness, ContractError> {
    if frames.len() > MAX_SOURCE_FRAMES || authorized.len() > MAX_SOURCE_DOMAINS {
        return Err(ContractError::BudgetExhausted);
    }
    if predicate.is_empty()
        || authorized.is_empty()
        || authorized.iter().any(String::is_empty)
        || interval.earliest >= interval.latest
    {
        return Err(ContractError::InvalidIdentifier);
    }
    let mut digests = BTreeSet::new();
    let mut sensor_domain: BTreeMap<&str, &str> = BTreeMap::new();
    let mut by_domain: BTreeMap<&str, Vec<&SourceFrame>> = BTreeMap::new();
    for frame in frames {
        if frame.clock_basis == ClockBasis::Estimated {
            return Err(ContractError::CoverageUncertified);
        }
        if !authorized.contains(&frame.failure_domain)
            || !digests.insert(frame.capsule_digest)
            || frame.capture.latest < interval.earliest
            || frame.capture.earliest > interval.latest
            || *sensor_domain
                .entry(frame.sensor_id.as_str())
                .or_insert(frame.failure_domain.as_str())
                != frame.failure_domain
        {
            return Err(ContractError::InvalidIdentifier);
        }
        by_domain
            .entry(frame.failure_domain.as_str())
            .or_default()
            .push(frame);
    }
    let observed: BTreeSet<String> = authorized
        .iter()
        .filter(|domain| {
            by_domain
                .get(domain.as_str())
                .is_some_and(|frames| tiles(frames, interval))
        })
        .cloned()
        .collect();
    let complete = observed == *authorized;
    Ok(CoverageWitness {
        anchor: basis.clone(),
        authorized_domain: authorized.clone(),
        excluded_domain: BTreeSet::new(),
        continuity: if complete {
            CoverageContinuity::Continuous
        } else {
            CoverageContinuity::Gapped
        },
        completeness: if complete {
            Completeness::Complete
        } else if observed.is_empty() {
            Completeness::NotObservable
        } else {
            Completeness::Partial
        },
        negative_predicate: predicate.to_owned(),
        stop_reason: if complete {
            CoverageStopReason::Complete
        } else {
            CoverageStopReason::SourceGap
        },
        authorized_generation: basis.policy_epoch,
        observed_generation: basis.policy_epoch,
        observed_domain: observed,
    })
}

/// Whether one domain's frames (in capture order) tile `interval` with no gap.
fn tiles(frames: &[&SourceFrame], interval: CaptureInterval) -> bool {
    let Some(first) = frames.first() else {
        return false;
    };
    if first.capture.earliest > interval.earliest {
        return false;
    }
    let mut reached = first.capture.latest;
    for frame in frames {
        if frame.gap_before || frame.capture.earliest > reached {
            return false;
        }
        reached = reached.max(frame.capture.latest);
    }
    reached >= interval.latest
}

impl SourceCoverageRecord {
    /// Exact record bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.bytes(SOURCE_RECORD_MAGIC);
        e.u32(SOURCE_RECORD_VERSION);
        e.text(SOURCE_RECORD_DOMAIN);
        self.interval.encode_canonical(&mut e);
        e.u64(self.frames.len() as u64);
        for frame in &self.frames {
            frame.encode(&mut e);
        }
        self.witness.encode_canonical(&mut e);
        e.finish()
    }

    /// Record digest: the spool digest of [`Self::to_bytes`], committed as the delta payload.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_bytes())
    }

    /// Spool digest of the witness's canonical bytes: the object an event cites.
    #[must_use]
    pub fn witness_object(&self) -> ContentDigest {
        ContentDigest::sha256(&self.witness.canonical_bytes())
    }

    /// Ledger object of this record.
    pub fn object_id(&self) -> Result<ObjectId, ContractError> {
        ObjectId::parse(format!("object:coverage:source:{}", hex(self.digest())))
    }

    /// Exact retention approval of this record.
    #[must_use]
    pub fn approval_digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(SOURCE_APPROVAL_DOMAIN);
        e.digest(self.digest());
        ContentDigest::sha256(&e.finish())
    }

    /// Every object the record names: its source capsules and their payloads.
    pub fn source_objects(&self) -> impl Iterator<Item = ContentDigest> + '_ {
        self.frames
            .iter()
            .flat_map(|frame| [frame.capsule_digest, frame.source_digest])
    }

    /// Re-derives the witness from the frames and requires it byte for byte, with frames in
    /// canonical order.
    ///
    /// # Errors
    /// [`ContractError::NonCanonicalOrdering`] for unordered frames, or the derivation's refusal,
    /// or [`ContractError::CoverageUncertified`] when the carried witness is not the derived one.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self
            .frames
            .windows(2)
            .any(|pair| pair[0].order_key() >= pair[1].order_key())
        {
            return Err(ContractError::NonCanonicalOrdering);
        }
        let derived = derive_witness(
            &self.witness.anchor,
            self.interval,
            &self.witness.negative_predicate,
            &self.witness.authorized_domain,
            &self.frames,
        )?;
        if derived != self.witness {
            return Err(ContractError::CoverageUncertified);
        }
        Ok(())
    }

    /// Whether `bytes` carry a source coverage record (by magic; nothing else is decoded).
    #[must_use]
    pub fn is_source_record(bytes: &[u8]) -> bool {
        CanonicalDecoder::new(bytes)
            .bytes()
            .is_ok_and(|magic| magic == SOURCE_RECORD_MAGIC)
    }

    /// Decodes and validates exact retained bytes against their authority digest.
    ///
    /// # Errors
    /// [`ContractError::DigestMismatch`] when the bytes do not hash to `expected`, a decode
    /// refusal, or [`Self::validate`]'s refusal.
    pub fn from_bytes(bytes: &[u8], expected: ContentDigest) -> Result<Self, ContractError> {
        if bytes.len() > MAX_SOURCE_RECORD_BYTES {
            return Err(ContractError::BudgetExhausted);
        }
        if ContentDigest::sha256(bytes) != expected {
            return Err(ContractError::DigestMismatch);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != SOURCE_RECORD_MAGIC
            || d.u32()? != SOURCE_RECORD_VERSION
            || d.text()? != SOURCE_RECORD_DOMAIN
        {
            return Err(ContractError::InvalidIdentifier);
        }
        let interval = CaptureInterval::decode_canonical(&mut d)?;
        let count = usize::try_from(d.u64()?).map_err(|_| ContractError::BudgetExhausted)?;
        if count > MAX_SOURCE_FRAMES {
            return Err(ContractError::BudgetExhausted);
        }
        let mut frames = Vec::with_capacity(count);
        for _ in 0..count {
            frames.push(SourceFrame::decode(&mut d)?);
        }
        let witness = CoverageWitness::decode_canonical(&mut d)?;
        d.ensure_finished()?;
        let record = Self {
            interval,
            frames,
            witness,
        };
        record.validate()?;
        if record.to_bytes() != bytes {
            return Err(ContractError::NonCanonicalOrdering);
        }
        Ok(record)
    }
}

/// Retention state of a source coverage record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceCoverageStatus {
    /// Retained by this call.
    Retained,
    /// Already retained; nothing was written.
    AlreadyRetained,
}

/// Typed refusal of source coverage retention.
#[derive(Debug)]
pub enum SourceCoverageError {
    /// The approval is not this record's exact approval.
    StaleApproval(ContentDigest),
    /// A source capsule or payload is missing, corrupt, or not exactly the recorded frame.
    SourceMismatch(ContentDigest),
    /// The witness basis is not a committed anchor of this ledger at or before its head.
    BasisNotCommitted,
    /// Record construction or validation failed.
    Contract(ContractError),
    /// Spool refusal.
    Spool(SpoolError),
    /// Spool or ledger refusal.
    Reference(Box<ReferenceError>),
}

impl SourceCoverageError {
    /// Registered stable identity (registries/ERRORS.md).
    #[must_use]
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::StaleApproval(_) => "ERR-COVERAGE-APPROVAL-STALE-001",
            Self::SourceMismatch(_)
            | Self::BasisNotCommitted
            | Self::Contract(_)
            | Self::Spool(_)
            | Self::Reference(_) => "ERR-COVERAGE-001",
        }
    }
}

impl fmt::Display for SourceCoverageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleApproval(digest) => write!(
                f,
                "source coverage approval {digest} is not the exact approval of this record"
            ),
            Self::SourceMismatch(digest) => write!(
                f,
                "source capsule {digest} is missing, corrupt, or not exactly the recorded frame"
            ),
            Self::BasisNotCommitted => f.write_str(
                "the coverage witness basis is not a committed anchor of this deployment",
            ),
            Self::Contract(error) => write!(f, "source coverage record: {error}"),
            Self::Spool(error) => write!(f, "source coverage spool: {error}"),
            Self::Reference(error) => write!(f, "source coverage retention: {error}"),
        }
    }
}

impl std::error::Error for SourceCoverageError {}

impl From<ContractError> for SourceCoverageError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

impl From<SpoolError> for SourceCoverageError {
    fn from(error: SpoolError) -> Self {
        Self::Spool(error)
    }
}

impl From<ReferenceError> for SourceCoverageError {
    fn from(error: ReferenceError) -> Self {
        Self::Reference(Box::new(error))
    }
}

/// Committed retention of `record` in `batches`: (batch index, the delta).
fn retention_in<'a>(
    batches: &'a [EvidenceDeltaBatch],
    record: &SourceCoverageRecord,
) -> Option<(usize, &'a EvidenceDelta)> {
    let digest = record.digest();
    let object = record.object_id().ok()?;
    let witness = record.witness_object();
    batches.iter().enumerate().find_map(|(index, batch)| {
        batch
            .deltas
            .iter()
            .find(|delta| {
                delta.family == FAMILY_COVERAGE_WITNESS
                    && delta.object_id == object
                    && delta.payload_digest == digest
                    && delta.witness_digest == Some(witness)
                    && delta.new_generation == 1
                    && delta.prior_generation.is_none()
            })
            .map(|delta| (index, delta))
    })
}

/// Whether `basis` is the genesis anchor of `head`'s lineage or an anchor some committed batch
/// starts from or reaches.
fn basis_committed(
    basis: &LedgerAnchor,
    batches: &[EvidenceDeltaBatch],
    head: &LedgerAnchor,
) -> bool {
    basis.site_lineage == head.site_lineage
        && basis.ledger_epoch == head.ledger_epoch
        && basis.commit_sequence <= head.commit_sequence
        && (*basis == LedgerAnchor::genesis(head.site_lineage.clone())
            || batches
                .iter()
                .any(|batch| batch.new_anchor == *basis || batch.basis_anchor == *basis))
}

/// Retains exactly the approved record: approval must be [`SourceCoverageRecord::approval_digest`].
/// Every source capsule is re-read from the spool and must decode to exactly its frame, and its
/// payload must be present; the witness basis must be a committed anchor. The witness and record
/// are staged and committed in one `coverage_witness` batch whose children are the record, the
/// witness and every source object. A record already retained is never rewritten.
///
/// # Errors
/// [`SourceCoverageError`].
pub fn retain_source_coverage(
    deployment: &mut ReferenceDeployment,
    record: &SourceCoverageRecord,
    approval: ContentDigest,
    cx: &ReplayCx,
) -> Result<SourceCoverageStatus, SourceCoverageError> {
    record.validate()?;
    if approval != record.approval_digest() {
        return Err(SourceCoverageError::StaleApproval(approval));
    }
    if retention_in(deployment.ledger().batches(), record).is_some() {
        return Ok(SourceCoverageStatus::AlreadyRetained);
    }
    let head = deployment.current_anchor().clone();
    if !basis_committed(&record.witness.anchor, deployment.ledger().batches(), &head) {
        return Err(SourceCoverageError::BasisNotCommitted);
    }
    for frame in &record.frames {
        let bytes = deployment
            .publisher()
            .spool()
            .read(frame.capsule_digest)
            .map_err(|_| SourceCoverageError::SourceMismatch(frame.capsule_digest))?;
        let capsule = SensorCapsule::from_canonical_bytes(&bytes)
            .map_err(|_| SourceCoverageError::SourceMismatch(frame.capsule_digest))?;
        if !frame.matches(&capsule) {
            return Err(SourceCoverageError::SourceMismatch(frame.capsule_digest));
        }
        deployment
            .publisher()
            .spool()
            .read(frame.source_digest)
            .map_err(|_| SourceCoverageError::SourceMismatch(frame.source_digest))?;
    }
    let witness_object = deployment.stage_payload(&record.witness.canonical_bytes())?;
    let digest = deployment.stage_payload(&record.to_bytes())?;
    if witness_object != record.witness_object() || digest != record.digest() {
        return Err(ContractError::DigestMismatch.into());
    }
    let mut children: BTreeSet<ContentDigest> = record.source_objects().collect();
    children.insert(witness_object);
    children.insert(digest);
    let delta = EvidenceDelta {
        delta_id: format!("delta:coverage:source:{}", hex(digest)),
        family: FAMILY_COVERAGE_WITNESS.to_owned(),
        object_id: record.object_id()?,
        prior_generation: None,
        new_generation: 1,
        validity: record.interval,
        plane: Plane::Authority,
        payload_digest: digest,
        witness_digest: Some(witness_object),
        operation_id: None,
    };
    let batch = BatchId::parse(format!("batch:coverage:source:{}", hex(digest)))?;
    deployment.append_batch(batch, vec![delta], children.into_iter().collect(), cx)?;
    Ok(SourceCoverageStatus::Retained)
}

/// The negative predicate a rejected event of `kind` requires of a certifying witness.
#[must_use]
pub const fn absence_predicate(kind: EventKind) -> &'static str {
    match kind {
        EventKind::UnknownPresence => "no_unknown_person_present",
        EventKind::PerimeterBreach => "no_perimeter_breach",
        EventKind::CovertApproach => "no_covert_approach",
        EventKind::SensorTamper => "no_sensor_tamper",
        EventKind::BenignRoutine => "no_benign_routine",
        EventKind::Unclassified => "no_unclassified_event",
    }
}

/// The domains a rejected event's absence must cover: its evidence failure domains and zones.
#[must_use]
pub fn required_domains(event: &EventHypothesis) -> BTreeSet<String> {
    event
        .evidence
        .iter()
        .map(|edge| edge.failure_domain.clone())
        .chain(event.zone_ids.iter().cloned())
        .filter(|domain| !domain.is_empty())
        .collect()
}

/// A verified certification by a stored witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedAbsence {
    /// Committed record digest (the `coverage_witness` delta payload): the stated reason.
    pub record_digest: ContentDigest,
    /// Commit sequence that retained the record.
    pub record_sequence: u64,
    /// The witness's registered digest (`fss.coverage_witness.v1`).
    pub witness_digest: ContentDigest,
    /// Spool digest of the witness bytes the event cites.
    pub witness_object: ContentDigest,
    /// Commit sequence of the witness basis.
    pub basis_sequence: u64,
    /// Interval the record covers.
    pub interval: CaptureInterval,
    /// Authorized (and observed) domains.
    pub domains: BTreeSet<String>,
}

impl RetainedAbsence {
    /// One sentence naming the record, its basis and the No-Claim.
    #[must_use]
    pub fn statement(&self) -> String {
        format!(
            "Absence is certified by retained coverage_witness record {} (commit {}): its \
             witness {} over domains [{}] for [{}, {}] ns has basis commit {} and no \
             coverage-relevant commit follows it. This certifies only that the retained pipeline \
             over the authorized domains observed nothing during the interval; it is not physical \
             absence outside them.",
            self.record_digest,
            self.record_sequence,
            self.witness_digest,
            self.domains.iter().cloned().collect::<Vec<_>>().join(","),
            self.interval.earliest.0,
            self.interval.latest.0,
            self.basis_sequence,
        )
    }
}

/// Why a stored witness does not certify.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetainedCoverageRefusal {
    /// The record does not validate (frames do not support its witness).
    RecordInvalid,
    /// No committed `coverage_witness` delta retains exactly this record (missing or tampered).
    NotRetained,
    /// The record's batch does not hold every source object, the witness and the record.
    NoCustody,
    /// The witness does not certify absence (gapped, partial, excluded, or generation 0).
    WitnessDoesNotCertify,
    /// The event is not rejected.
    EventNotRejected,
    /// The event does not cite the stored witness as contradicting evidence.
    WitnessNotCited,
    /// The witness predicate is not the event kind's.
    PredicateMismatch,
    /// The authorized domain does not cover the event's domains.
    DomainNotCovered,
    /// The event interval lies outside the record's interval.
    IntervalNotCovered,
    /// The witness basis is not a committed anchor of this history.
    BasisNotCommitted,
    /// The witness generation is not the basis and head policy epoch.
    GenerationMismatch,
    /// An epoch or lineage changed after the basis.
    EpochChanged {
        /// Commit sequence of the batch that changed it.
        sequence: u64,
    },
    /// A coverage-relevant commit follows the basis.
    CoverageRelevantCommit {
        /// Its commit sequence.
        sequence: u64,
        /// Its delta family (or `children` for an unaccounted child object).
        family: String,
        /// Its delta identity (or the unaccounted object).
        delta_id: String,
    },
}

impl RetainedCoverageRefusal {
    /// Whether the refusal is an invalidation by a later commit (the witness was valid at its
    /// basis but is no longer current).
    #[must_use]
    pub const fn invalidated(&self) -> bool {
        matches!(
            self,
            Self::EpochChanged { .. } | Self::CoverageRelevantCommit { .. }
        )
    }
}

impl fmt::Display for RetainedCoverageRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecordInvalid => f.write_str("the coverage record's frames do not support its witness"),
            Self::NotRetained => f.write_str(
                "no committed coverage_witness record retains exactly this witness",
            ),
            Self::NoCustody => f.write_str(
                "the coverage record's batch does not hold custody of every source object",
            ),
            Self::WitnessDoesNotCertify => f.write_str(
                "the stored coverage witness is not complete and continuous over its authorized domain",
            ),
            Self::EventNotRejected => f.write_str("the event is not rejected"),
            Self::WitnessNotCited => f.write_str(
                "the event does not cite the stored coverage witness as contradicting evidence",
            ),
            Self::PredicateMismatch => {
                f.write_str("the stored witness predicate is not the event kind's predicate")
            }
            Self::DomainNotCovered => f.write_str(
                "the stored witness's authorized domain does not cover the event's domains",
            ),
            Self::IntervalNotCovered => {
                f.write_str("the event interval lies outside the stored witness's interval")
            }
            Self::BasisNotCommitted => {
                f.write_str("the stored witness basis is not a committed anchor of this ledger")
            }
            Self::GenerationMismatch => f.write_str(
                "the stored witness generation is not the basis and current policy epoch",
            ),
            Self::EpochChanged { sequence } => write!(
                f,
                "an epoch or lineage changed at commit {sequence}, after the stored witness basis"
            ),
            Self::CoverageRelevantCommit {
                sequence,
                family,
                delta_id,
            } => write!(
                f,
                "coverage-relevant commit {sequence} ({family} {delta_id}) follows the stored \
                 witness basis"
            ),
        }
    }
}

fn same_epochs(left: &LedgerAnchor, right: &LedgerAnchor) -> bool {
    left.site_lineage == right.site_lineage
        && left.ledger_epoch == right.ledger_epoch
        && left.adapter_registry_epoch == right.adapter_registry_epoch
        && left.schema_epoch == right.schema_epoch
        && left.policy_epoch == right.policy_epoch
        && left.privacy_epoch == right.privacy_epoch
}

/// The shared rule: does the stored witness of `record` certify absence at `head` over the
/// committed `batches` (the whole committed history through `head`)? With `event`, the rejected
/// event whose absence is certified (its cited publication is bookkeeping); without, coverage is
/// assessed with no event publication counted as bookkeeping.
///
/// # Errors
/// The first [`RetainedCoverageRefusal`] that applies.
pub fn verify_retained_coverage(
    record: &SourceCoverageRecord,
    event: Option<&EventHypothesis>,
    batches: &[EvidenceDeltaBatch],
    head: &LedgerAnchor,
) -> Result<RetainedAbsence, RetainedCoverageRefusal> {
    use RetainedCoverageRefusal as Refusal;

    record.validate().map_err(|_| Refusal::RecordInvalid)?;
    let (record_index, _) = retention_in(batches, record).ok_or(Refusal::NotRetained)?;
    let record_batch = &batches[record_index];
    let witness = &record.witness;
    let witness_object = record.witness_object();
    let record_digest = record.digest();
    let custody: BTreeSet<ContentDigest> = record_batch.children.iter().copied().collect();
    if !record
        .source_objects()
        .all(|digest| custody.contains(&digest))
        || !custody.contains(&witness_object)
        || !custody.contains(&record_digest)
    {
        return Err(Refusal::NoCustody);
    }
    if !witness.certifies_absence() {
        return Err(Refusal::WitnessDoesNotCertify);
    }
    let mut accounted: BTreeSet<ContentDigest> = record.source_objects().collect();
    accounted.insert(witness_object);
    accounted.insert(record_digest);
    // The cited publication: (batch index, event object id) when an event is certified.
    let mut citing: Option<(usize, ObjectId)> = None;
    if let Some(event) = event {
        if event.state != EventState::Rejected {
            return Err(Refusal::EventNotRejected);
        }
        if !event
            .evidence
            .iter()
            .any(|edge| edge.digest == witness_object && edge.counts_as_contradiction())
        {
            return Err(Refusal::WitnessNotCited);
        }
        if witness.negative_predicate != absence_predicate(event.kind) {
            return Err(Refusal::PredicateMismatch);
        }
        let required = required_domains(event);
        if required.is_empty() || !required.is_subset(&witness.authorized_domain) {
            return Err(Refusal::DomainNotCovered);
        }
        if event.interval.earliest < record.interval.earliest
            || event.interval.latest > record.interval.latest
        {
            return Err(Refusal::IntervalNotCovered);
        }
        let object = ObjectId::parse(format!("object:event:{}", event.event_id.as_str()))
            .map_err(|_| Refusal::WitnessNotCited)?;
        let revision = event.revision_digest();
        let found = batches.iter().enumerate().find_map(|(index, batch)| {
            batch.deltas.iter().find(|delta| {
                delta.family == FAMILY_EVENT_REVISION
                    && delta.object_id == object
                    && delta.new_generation == event.revision
                    && delta.witness_digest == Some(revision)
            })?;
            Some(index)
        });
        if let Some(index) = found {
            let tamper =
                ObjectId::parse(format!("object:event:{}:tamper", event.event_id.as_str()))
                    .map_err(|_| Refusal::WitnessNotCited)?;
            for delta in &batches[index].deltas {
                if delta.object_id == object && delta.family == FAMILY_EVENT_REVISION {
                    accounted.insert(delta.payload_digest);
                }
                if delta.object_id == tamper && delta.family == FAMILY_SENSOR_TAMPER_STATUS {
                    accounted.extend(delta.witness_digest);
                }
            }
            accounted.insert(ContentDigest::sha256(&event.canonical_bytes()));
            accounted.insert(revision);
            citing = Some((index, object));
        }
    }
    let basis = &witness.anchor;
    if batches
        .last()
        .is_some_and(|batch| batch.new_anchor != *head)
        || !basis_committed(basis, batches, head)
    {
        return Err(Refusal::BasisNotCommitted);
    }
    if witness.authorized_generation != basis.policy_epoch
        || witness.authorized_generation != head.policy_epoch
    {
        return Err(Refusal::GenerationMismatch);
    }
    if record_batch.new_anchor.commit_sequence <= basis.commit_sequence {
        return Err(Refusal::BasisNotCommitted);
    }
    let record_object = record.object_id().map_err(|_| Refusal::NotRetained)?;
    let sources: BTreeSet<ContentDigest> = record
        .frames
        .iter()
        .map(|frame| frame.capsule_digest)
        .collect();
    let interval = record.interval;
    let overlaps = |validity: &CaptureInterval| {
        validity.earliest <= interval.latest && validity.latest >= interval.earliest
    };
    for (index, batch) in batches.iter().enumerate() {
        let sequence = batch.new_anchor.commit_sequence;
        let after = sequence > basis.commit_sequence;
        // At or before the basis only what bears on the interval counts: the producer read that
        // history, but it assessed delivery, not observations, so evidence of the interval
        // committed before a later-chosen basis is never skipped.
        if !after && !batch.deltas.iter().any(|delta| overlaps(&delta.validity)) {
            continue;
        }
        if after
            && (!same_epochs(&batch.new_anchor, basis) || !same_epochs(&batch.basis_anchor, basis))
        {
            return Err(Refusal::EpochChanged { sequence });
        }
        for delta in &batch.deltas {
            if !after && !overlaps(&delta.validity) {
                continue;
            }
            let bookkeeping = match delta.family.as_str() {
                FAMILY_COVERAGE_WITNESS => {
                    delta.object_id == record_object && delta.payload_digest == record_digest
                }
                FAMILY_EVENT_REVISION | FAMILY_SENSOR_TAMPER_STATUS => {
                    citing.as_ref().is_some_and(|(citing_index, object)| {
                        *citing_index == index
                            && (delta.object_id == *object
                                || delta.object_id.as_str()
                                    == format!("{}:tamper", object.as_str()))
                    })
                }
                FAMILY_SENSOR_CAPSULE => sources.contains(&delta.payload_digest),
                ROOT_REACHABILITY_FAMILY => true,
                _ => false,
            };
            if !bookkeeping {
                return Err(Refusal::CoverageRelevantCommit {
                    sequence,
                    family: delta.family.clone(),
                    delta_id: delta.delta_id.clone(),
                });
            }
        }
        if let Some(child) = batch
            .children
            .iter()
            .find(|child| !accounted.contains(child))
        {
            return Err(Refusal::CoverageRelevantCommit {
                sequence,
                family: "children".to_owned(),
                delta_id: child.to_string(),
            });
        }
    }
    Ok(RetainedAbsence {
        record_digest,
        record_sequence: record_batch.new_anchor.commit_sequence,
        witness_digest: witness.witness_digest(),
        witness_object,
        basis_sequence: basis.commit_sequence,
        interval: record.interval,
        domains: witness.authorized_domain.clone(),
    })
}

#[cfg(test)]
mod tests;
