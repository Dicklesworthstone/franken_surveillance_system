//! Deterministic event-policy reference separating model findings from canonical event truth.

use std::collections::BTreeSet;

use fss_core::{
    BatchId, CanonicalDecode, CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest,
    DecisionPath, EventEvidence, EventHypothesis, EventId, EventKind, EventState, EvidenceClass,
    EvidenceDelta, EvidenceEdgeRelation, LedgerAnchor, ObjectId, Plane, ProbabilityInterval,
};
use fss_ledger::DurableReferenceLedger;
use fss_object::{InMemoryObjectStore, ObjectManifest, VerifiedObjectCatalog};
use fss_publication::AuthorityPublisher;

use crate::executor_activity::{ExecutorModelOutcome, ExecutorModelResult};
use crate::ingest::source_coverage::{SourceCoverageRecord, analysis_covering_frames};
use crate::{MockModelOutcome, MockModelResult, MockSemanticLabel, ReferenceError};

const MAX_POLICY_OBSERVATIONS: usize = 64;
const MAX_FAILURE_DOMAIN_BYTES: usize = 256;

/// The retained model result a policy observation carries: a scripted mock result, or the result
/// of a real scalar-executor invocation over decoded pixels. An executor result is never encoded
/// as a [`MockModelResult`]; each variant keeps its own canonical encoding and domain.
#[derive(Clone, Debug, PartialEq)]
pub enum ReferenceModelResult {
    /// Scripted reference result (policy-semantics fixtures).
    Mock(MockModelResult),
    /// Executor-backed result bound to its invocation and decode receipts (fss-2h5zq.51).
    ScalarExecutor(ExecutorModelResult),
}

impl ReferenceModelResult {
    /// Canonical object identity of the retained result bytes (dedup key of the policy).
    #[must_use]
    pub fn object_digest(&self) -> ContentDigest {
        match self {
            Self::Mock(result) => result.object_digest(),
            Self::ScalarExecutor(result) => result.object_digest(),
        }
    }

    /// Exact retained bytes whose SHA-256 is [`Self::object_digest`].
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        match self {
            Self::Mock(result) => result.canonical_bytes(),
            Self::ScalarExecutor(result) => result.canonical_bytes(),
        }
    }

    /// Recording sensor.
    #[must_use]
    pub fn sensor_id(&self) -> &fss_core::SensorId {
        match self {
            Self::Mock(result) => &result.sensor_id,
            Self::ScalarExecutor(result) => &result.sensor_id,
        }
    }

    /// Exact capture object consumed (corroboration counts distinct capture roots).
    #[must_use]
    pub fn input_capture_root(&self) -> ContentDigest {
        match self {
            Self::Mock(result) => result.input_capture_root,
            Self::ScalarExecutor(result) => result.input_capture_root,
        }
    }
}

impl From<MockModelResult> for ReferenceModelResult {
    fn from(result: MockModelResult) -> Self {
        Self::Mock(result)
    }
}

impl From<ExecutorModelResult> for ReferenceModelResult {
    fn from(result: ExecutorModelResult) -> Self {
        Self::ScalarExecutor(result)
    }
}

/// One retained model result with the physical/shared failure domain assigned by deployment truth.
#[derive(Clone, Debug, PartialEq)]
pub struct ReferenceModelObservation {
    /// Exact retained model result.
    pub result: ReferenceModelResult,
    /// Failure-domain identity used for corroboration accounting.
    pub failure_domain: String,
    /// Physical validity interval represented by this observation.
    pub interval: CaptureInterval,
}

impl ReferenceModelObservation {
    /// Constructs a bounded observation without granting any event/effect authority.
    pub fn new(
        result: impl Into<ReferenceModelResult>,
        failure_domain: impl Into<String>,
        interval: CaptureInterval,
    ) -> Result<Self, ReferenceError> {
        let result = result.into();
        let failure_domain = failure_domain.into();
        if failure_domain.is_empty() || failure_domain.len() > MAX_FAILURE_DOMAIN_BYTES {
            return Err(ReferenceError::InvalidSpec("failure_domain"));
        }
        Ok(Self {
            result,
            failure_domain,
            interval,
        })
    }
}

/// Reference policy output. `PrepareAlert` is only an affordance; it is not an external effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferencePolicyAction {
    /// Retain/investigate without preparing an alert effect.
    Hold,
    /// Evidence is sufficient for a separate alert-preparation step to become available.
    PrepareAlert,
}

/// Canonical policy decision over an unknown-person-presence hypothesis.
#[derive(Clone, Debug, PartialEq)]
pub struct ReferencePolicyDecision {
    /// Immutable event revision.
    pub event: EventHypothesis,
    /// Safe next effect-level affordance.
    pub action: ReferencePolicyAction,
}

/// Receipt after the event revision and its evidence closure become authority-visible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceEventReceipt {
    /// Root of the event revision object graph.
    pub event_root: ContentDigest,
    /// Exact canonical event object bytes.
    pub event_object_digest: ContentDigest,
    /// Domain-separated event revision fingerprint.
    pub event_revision_digest: ContentDigest,
    /// Authority anchor after publication.
    pub authority_anchor: LedgerAnchor,
    /// Verified accumulated sensor-tamper status across this event lineage.
    pub lineage_tamper_status: fss_core::SensorTamperStatus,
    /// Exact canonical encodings of every earlier revision of this event's lineage, oldest first,
    /// as the authority ledger published them.
    ///
    /// Hydration only: alert preparation, alert dispatch and situation compilation admit them
    /// solely when each decodes to the revision the ledger's `event_revision` witness names at its
    /// position, then recompute the lineage tamper status from them (fss-2uftm).
    pub prior_revision_encodings: Vec<Vec<u8>>,
}

/// Evaluates the narrow reference question "is an unknown person present?".
///
/// The function intentionally does not fuse model-local probability numbers. Until a calibrated
/// fusion layer exists, the event probability remains the maximally conservative `[0, 1]`.
/// Corroboration is based on distinct supporting failure domains and distinct sensor capture
/// roots with no retained alternate model outcome. Duplicate result objects or multiple models
/// evaluated against the same capture root cannot be relabeled into multiple independent witnesses.
pub fn evaluate_unknown_presence(
    event_id: EventId,
    observations: Vec<ReferenceModelObservation>,
) -> Result<ReferencePolicyDecision, ReferenceError> {
    if observations.is_empty() || observations.len() > MAX_POLICY_OBSERVATIONS {
        return Err(ReferenceError::InvalidSpec("policy_observations"));
    }

    let mut observations = observations;
    observations.sort_by(|left, right| {
        (left.failure_domain.as_str(), left.result.object_digest())
            .cmp(&(right.failure_domain.as_str(), right.result.object_digest()))
    });
    let mut seen_results = BTreeSet::new();
    let mut support_domains = BTreeSet::new();
    let mut support_capture_roots = BTreeSet::new();
    let mut support_sensors = BTreeSet::new();
    let mut contradictory = 0_usize;
    let mut unresolved = 0_usize;
    let mut evidence = Vec::with_capacity(observations.len());
    let mut model_receipts = Vec::with_capacity(observations.len());
    let mut earliest = observations[0].interval.earliest;
    let mut latest = observations[0].interval.latest;

    for observation in &observations {
        let result_digest = observation.result.object_digest();
        if !seen_results.insert(result_digest) {
            return Err(ReferenceError::InvalidSpec("duplicate_model_result"));
        }
        if observation.interval.earliest < earliest {
            earliest = observation.interval.earliest;
        }
        if observation.interval.latest > latest {
            latest = observation.interval.latest;
        }

        let mock_outcome = match &observation.result {
            ReferenceModelResult::Mock(result) => &result.outcome,
            ReferenceModelResult::ScalarExecutor(result) => {
                let relation = match result.outcome {
                    // Pixel activity above the documented threshold supports the hypothesis from
                    // this one sensor only; corroboration still needs independent sensors.
                    ExecutorModelOutcome::Activity { .. } => {
                        support_domains.insert(observation.failure_domain.clone());
                        support_capture_roots.insert(result.input_capture_root);
                        support_sensors.insert(result.sensor_id.clone());
                        EvidenceEdgeRelation::Supports
                    }
                    // Below threshold is not absence and not a contradiction: a neutral edge.
                    ExecutorModelOutcome::NoActivity { .. } => EvidenceEdgeRelation::DerivedFrom,
                    // An executor failure says nothing about presence and holds the event open.
                    ExecutorModelOutcome::Abstained { .. } => {
                        unresolved += 1;
                        EvidenceEdgeRelation::DerivedFrom
                    }
                };
                evidence.push(EventEvidence {
                    digest: result_digest,
                    class: EvidenceClass::Derived,
                    failure_domain: observation.failure_domain.clone(),
                    supports: relation.required_supports_flag(),
                    relation,
                    capsule_digest: None,
                    identity_digest: None,
                });
                model_receipts.push(result_digest);
                continue;
            }
        };
        let relation = match mock_outcome {
            MockModelOutcome::Finding {
                label: MockSemanticLabel::PersonLike,
                ..
            } => {
                support_domains.insert(observation.failure_domain.clone());
                support_capture_roots.insert(observation.result.input_capture_root());
                support_sensors.insert(observation.result.sensor_id().clone());
                EvidenceEdgeRelation::Supports
            }
            // A benign alternative explanation is evidence against unknown-person presence.
            MockModelOutcome::Finding {
                label: MockSemanticLabel::AnimalLike,
                ..
            } => {
                contradictory += 1;
                EvidenceEdgeRelation::Contradicts
            }
            // TamperLike is a sensor-integrity risk, not evidence against presence (tampering can
            // hide a person, not refute one): its own relation, so the situation surfaces it.
            MockModelOutcome::Finding {
                label: MockSemanticLabel::TamperLike,
                ..
            } => {
                unresolved += 1;
                EvidenceEdgeRelation::SensorTamper
            }
            // Evidenced restoration of sensor integrity retires prior tamper.
            MockModelOutcome::Finding {
                label: MockSemanticLabel::IntegrityRestored,
                ..
            } => EvidenceEdgeRelation::SensorIntegrityRestoration,
            // Unknown and abstention say nothing about presence: a neutral derivation edge that
            // holds the event unresolved without contradicting it.
            MockModelOutcome::Finding {
                label: MockSemanticLabel::Unknown,
                ..
            }
            | MockModelOutcome::Abstained { .. } => {
                unresolved += 1;
                EvidenceEdgeRelation::DerivedFrom
            }
            // An analysed frame with nothing found says nothing about the rest of the interval:
            // without a coverage record whose every frame was analysed, it is a neutral edge that
            // neither supports, contradicts nor holds the event (fss-f8jls). Only
            // `evaluate_unknown_presence_over_coverage` may reject from it.
            MockModelOutcome::NothingFound { .. } => EvidenceEdgeRelation::DerivedFrom,
        };
        let capsule_digest = match mock_outcome {
            MockModelOutcome::NothingFound { analysed_capsule } => Some(*analysed_capsule),
            _ => None,
        };
        let identity_digest = match relation {
            EvidenceEdgeRelation::SensorTamper
            | EvidenceEdgeRelation::SensorIntegrityRestoration => Some(ContentDigest::sha256(
                observation.result.sensor_id().as_str().as_bytes(),
            )),
            _ => None,
        };
        evidence.push(EventEvidence {
            digest: result_digest,
            class: EvidenceClass::Derived,
            failure_domain: observation.failure_domain.clone(),
            supports: relation.required_supports_flag(),
            relation,
            capsule_digest,
            identity_digest,
        });
        model_receipts.push(result_digest);
    }

    let state = if support_sensors.len() >= 2
        && support_capture_roots.len() >= 2
        && support_domains.len() >= 2
        && contradictory == 0
        && unresolved == 0
    {
        EventState::Corroborated
    } else if !support_domains.is_empty() && contradictory == 0 && unresolved == 0 {
        EventState::Witnessed
    } else if support_domains.is_empty() && contradictory > 0 && unresolved == 0 {
        EventState::Rejected
    } else {
        EventState::Indeterminate
    };
    let action = if state == EventState::Corroborated {
        ReferencePolicyAction::PrepareAlert
    } else {
        ReferencePolicyAction::Hold
    };
    let interval = CaptureInterval::new(earliest, latest)?;
    let probability = ProbabilityInterval::new(0.0, 1.0)?;
    let decision_path = policy_decision_path(&event_id, &evidence, state, action);
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_string(),
        event_id,
        revision: 1,
        supersedes: None,
        state,
        kind: EventKind::UnknownPresence,
        interval,
        uncertainty_reason: None,
        zone_ids: Vec::new(),
        track_ids: Vec::new(),
        probability,
        evidence,
        model_receipts,
        decision_path,
    };
    event.validate()?;
    Ok(ReferencePolicyDecision { event, action })
}

/// Uncertainty reason of an unknown-presence decision over a coverage record whose frames the
/// observations do not all analyse with nothing found under one model generation.
pub const COVERAGE_ANALYSIS_INCOMPLETE: &str =
    "analysed-nothing results do not cover every coverage frame under one model generation";

/// Uncertainty reason of an unknown-presence decision over a coverage record whose witness does
/// not certify absence (a gapped, partial or excluded delivery): analysed-nothing results of the
/// frames that were delivered say nothing about the frames that were not (fss-f8jls).
pub const COVERAGE_WITNESS_NOT_CERTIFYING: &str = "the coverage witness does not certify absence: delivery over the authorized domain is \
     gapped or partial, so analysed-nothing results cannot reject the candidate";

/// Evaluates "is an unknown person present?" over a retained source coverage `record` and the
/// model observations of its frames (fss-f8jls).
///
/// The candidate is rejected only when every observation is an analysed-nothing result, the
/// results are under one model generation, each is bound to a frame of the record (capsule,
/// source payload, sensor and failure domain), and together they cover every frame
/// ([`analysis_covering_frames`], the check the stored-witness rule repeats). The rejected event
/// cites each result as contradicting evidence carrying the analysed capsule's digest, and the
/// record's witness as contradicting evidence of each observed domain; its interval is the
/// record's. Whether that rejection certifies absence is not decided here: the witness must
/// still certify and survive the stored-witness rule.
///
/// Any finding, abstention or other result is decided exactly as [`evaluate_unknown_presence`]
/// decides it. Over a record whose witness does not certify absence (a camera dark for a tick or
/// the whole interval), analysed-nothing results leave the event indeterminate with reason
/// [`COVERAGE_WITNESS_NOT_CERTIFYING`]: never rejected, because what was not delivered was not
/// analysed. Analysed-nothing results that do not cover the record leave the event
/// indeterminate with reason [`COVERAGE_ANALYSIS_INCOMPLETE`]: a frame that was never analysed is
/// never read as empty.
///
/// # Errors
/// [`evaluate_unknown_presence`]'s refusals.
pub fn evaluate_unknown_presence_over_coverage(
    event_id: EventId,
    observations: Vec<ReferenceModelObservation>,
    record: &SourceCoverageRecord,
) -> Result<ReferencePolicyDecision, ReferenceError> {
    let generic = evaluate_unknown_presence(event_id.clone(), observations.clone())?;
    let mut analyses = Vec::with_capacity(observations.len());
    for observation in &observations {
        match &observation.result {
            ReferenceModelResult::Mock(result)
                if matches!(result.outcome, MockModelOutcome::NothingFound { .. }) =>
            {
                analyses.push((observation.failure_domain.as_str(), result));
            }
            _ => return Ok(generic),
        }
    }
    // A gapped or partial witness never certifies, so nothing analysed over it rejects: the
    // candidate stays indeterminate and says why (fss-f8jls review D2).
    if !record.witness.certifies_absence() {
        let mut decision = generic;
        decision.event.uncertainty_reason = Some(COVERAGE_WITNESS_NOT_CERTIFYING.to_owned());
        decision.event.validate()?;
        return Ok(decision);
    }
    if analysis_covering_frames(record, &analyses).is_err() {
        let mut decision = generic;
        decision.event.uncertainty_reason = Some(COVERAGE_ANALYSIS_INCOMPLETE.to_owned());
        decision.event.validate()?;
        return Ok(decision);
    }

    // Every observation is a covering analysed-nothing result. Keep the generic (domain, result)
    // order; each edge now contradicts the candidate and names the capsule it analysed.
    let mut evidence: Vec<EventEvidence> = generic
        .event
        .evidence
        .iter()
        .map(|edge| EventEvidence {
            supports: false,
            relation: EvidenceEdgeRelation::Contradicts,
            ..edge.clone()
        })
        .collect();
    let witness_object = record.witness_object();
    for domain in &record.witness.observed_domain {
        evidence.push(EventEvidence {
            digest: witness_object,
            class: EvidenceClass::Derived,
            failure_domain: domain.clone(),
            supports: false,
            relation: EvidenceEdgeRelation::Contradicts,
            capsule_digest: None,
            identity_digest: None,
        });
    }
    let state = EventState::Rejected;
    let action = ReferencePolicyAction::Hold;
    let decision_path = policy_decision_path(&event_id, &evidence, state, action);
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_string(),
        event_id,
        revision: 1,
        supersedes: None,
        state,
        kind: EventKind::UnknownPresence,
        interval: record.interval,
        uncertainty_reason: None,
        zone_ids: Vec::new(),
        track_ids: Vec::new(),
        probability: ProbabilityInterval::new(0.0, 1.0)?,
        evidence,
        model_receipts: generic.event.model_receipts,
        decision_path,
    };
    event.validate()?;
    Ok(ReferencePolicyDecision { event, action })
}

struct StagedEventRevision {
    event_root: ContentDigest,
    event_object_digest: ContentDigest,
    event_revision_digest: ContentDigest,
}

fn stage_event_revision(
    decision: &ReferencePolicyDecision,
    objects: &mut InMemoryObjectStore,
) -> Result<StagedEventRevision, ReferenceError> {
    for model_receipt in &decision.event.model_receipts {
        objects.require_verified(*model_receipt)?;
    }
    let event_bytes = decision.event.canonical_bytes();
    let event_object_digest = objects.put_verified(&event_bytes)?;
    let mut revision_encoder = CanonicalEncoder::new();
    revision_encoder.text("fss.canonical.v1");
    revision_encoder.text("fss.event_hypothesis.v1");
    decision.event.encode_canonical(&mut revision_encoder);
    let event_revision_digest = objects.put_verified(&revision_encoder.finish())?;
    let event_manifest = ObjectManifest::new(
        "event-revision",
        decision.event.model_receipts.iter().copied(),
        Some(event_object_digest),
    )?;
    let event_root = objects.publish_manifest(event_manifest)?.root;
    Ok(StagedEventRevision {
        event_root,
        event_object_digest,
        event_revision_digest,
    })
}

/// Retains the event/evidence closure and publishes one canonical event revision to authority.
pub fn publish_reference_event(
    decision: &ReferencePolicyDecision,
    objects: &mut InMemoryObjectStore,
    ledger: &mut DurableReferenceLedger,
) -> Result<ReferenceEventReceipt, ReferenceError> {
    // Only a verified revision becomes authority.
    decision.event.validate()?;
    let event_name = decision.event.event_id.as_str();
    let object_id = ObjectId::parse(format!("object:event:{event_name}"))?;
    let (prior_generation, predecessor) = authority_predecessor(ledger, &object_id)?;
    let candidate_revision_digest = decision.event.revision_digest();

    let mut prior_events = Vec::new();
    for batch in ledger.batches() {
        for delta in &batch.deltas {
            if delta.object_id == object_id && delta.family == "event_revision" {
                let manifest = objects.published_manifest(delta.payload_digest)?;
                let payload = manifest
                    .metadata_digest()
                    .or_else(|| manifest.children().first().copied())
                    .ok_or(fss_core::ContractError::EvidenceRequired)?;
                let bytes = objects.read_verified(payload)?;
                let rev = EventHypothesis::from_canonical_bytes(bytes)?;
                if rev.revision < decision.event.revision {
                    prior_events.push(rev);
                }
            }
        }
    }
    prior_events.sort_by_key(|e| e.revision);
    prior_events.dedup_by_key(|e| e.revision);

    let prior_tamper = fss_core::event::compute_sensor_tamper_status(prior_events.iter(), None);
    let mut combined_tamper = prior_tamper.clone();

    // Tamper checks apply to both new publications and idempotent retries: an exact retry of a
    // revision that drops an unretired tamper must still be refused. The step is the one
    // `EventHypothesis::verify_chain` and lineage replay use: it refuses a tamper-vetoed state
    // with any tamper open, and a revision that does not carry forward every tamper that was open
    // before it and that it did not retire.
    fss_core::event::apply_revision_tamper_step(&mut combined_tamper, &decision.event)?;
    if decision
        .event
        .evidence
        .iter()
        .any(|e| e.reports_integrity_restoration())
        && prior_tamper.open_tamper_records.is_empty()
    {
        return Err(fss_core::ContractError::EvidenceRequired.into());
    }

    // Re-publishing the identical revision that is already current is idempotent.
    // A caller that published and then lost the receipt (e.g. crash after durable commit)
    // can recover it without mutating authority or being confused with a fork.
    if predecessor == Some(candidate_revision_digest) {
        let (committed_anchor, payload_digest) = ledger
            .batches()
            .iter()
            .rev()
            .find_map(|batch| {
                batch
                    .deltas
                    .iter()
                    .find(|delta| {
                        delta.object_id == object_id
                            && delta.family == "event_revision"
                            && delta.new_generation == decision.event.revision
                            && delta.witness_digest == Some(candidate_revision_digest)
                    })
                    .map(|delta| (batch.new_anchor.clone(), delta.payload_digest))
            })
            .ok_or(fss_core::ContractError::SupersessionMismatch)?;

        let staged = stage_event_revision(decision, objects)?;
        if staged.event_root != payload_digest {
            return Err(fss_core::ContractError::SupersessionMismatch.into());
        }
        let mut tamper_encoder = CanonicalEncoder::new();
        combined_tamper.encode_canonical(&mut tamper_encoder);
        let _ = objects.put_verified(&tamper_encoder.finish())?;
        let _ = objects.verify_closure(staged.event_root)?;

        return Ok(ReferenceEventReceipt {
            event_root: staged.event_root,
            event_object_digest: staged.event_object_digest,
            event_revision_digest: staged.event_revision_digest,
            authority_anchor: committed_anchor,
            lineage_tamper_status: combined_tamper,
            prior_revision_encodings: prior_events
                .iter()
                .map(crate::alert::event_revision_encoding)
                .collect(),
        });
    }

    // A revision must supersede exactly the revision the authority currently holds, and a
    // genesis revision requires the event object to be absent: anything else is a fork.
    if decision.event.supersedes != predecessor {
        return Err(fss_core::ContractError::SupersessionMismatch.into());
    }

    let staged = stage_event_revision(decision, objects)?;
    let mut tamper_encoder = CanonicalEncoder::new();
    combined_tamper.encode_canonical(&mut tamper_encoder);
    let _ = objects.put_verified(&tamper_encoder.finish())?;

    let delta = EvidenceDelta {
        delta_id: format!("delta:event:{event_name}:{}", decision.event.revision),
        family: "event_revision".to_owned(),
        object_id: object_id.clone(),
        prior_generation,
        new_generation: decision.event.revision,
        validity: decision.event.interval,
        plane: Plane::Authority,
        payload_digest: staged.event_root,
        witness_digest: Some(staged.event_revision_digest),
        operation_id: None,
    };

    let tamper_delta = EvidenceDelta {
        delta_id: format!(
            "delta:event:{event_name}:tamper:{}",
            decision.event.revision
        ),
        family: "sensor_tamper_status".to_owned(),
        object_id: ObjectId::parse(format!("object:event:{event_name}:tamper"))?,
        prior_generation,
        new_generation: decision.event.revision,
        validity: decision.event.interval,
        plane: Plane::Authority,
        payload_digest: staged.event_root,
        witness_digest: Some(combined_tamper.canonical_digest()),
        operation_id: None,
    };

    let authority_anchor = {
        let mut publisher = AuthorityPublisher::new(objects, ledger);
        let batch = publisher.prepare_batch(
            BatchId::parse(format!(
                "batch:event:{event_name}:{}",
                decision.event.revision
            ))?,
            vec![delta, tamper_delta],
            [staged.event_root],
        )?;
        publisher.append(batch)?
    };
    Ok(ReferenceEventReceipt {
        event_root: staged.event_root,
        event_object_digest: staged.event_object_digest,
        event_revision_digest: staged.event_revision_digest,
        authority_anchor,
        lineage_tamper_status: combined_tamper,
        prior_revision_encodings: prior_events
            .iter()
            .map(crate::alert::event_revision_encoding)
            .collect(),
    })
}

/// Returns the authority's current generation of `object_id` and the revision digest it holds.
///
/// The ledger's current `ObjectRevision` is authoritative for which revision is current: its
/// generation and `payload_digest` (the event root). The root does not name the revision digest,
/// so the digest is taken from the `witness_digest` of the committed batch delta that published
/// exactly that generation and payload; a delta that disagrees with the current object is not the
/// current revision. A current object with no such witnessed delta fails closed.
fn authority_predecessor(
    ledger: &DurableReferenceLedger,
    object_id: &ObjectId,
) -> Result<(Option<u64>, Option<fss_core::ContentDigest>), ReferenceError> {
    let Some(current) = ledger.current().objects.get(object_id) else {
        return Ok((None, None));
    };
    let witness = ledger
        .batches()
        .iter()
        .rev()
        .flat_map(|batch| batch.deltas.iter())
        .find(|delta| {
            delta.object_id == *object_id
                && delta.family == "event_revision"
                && delta.new_generation == current.generation
                && delta.payload_digest == current.payload_digest
        })
        .and_then(|delta| delta.witness_digest)
        .ok_or(fss_core::ContractError::SupersessionMismatch)?;
    Ok((Some(current.generation), Some(witness)))
}

/// Decision path of the reference unknown-presence policy for `event_id`: the policy generation
/// and a fingerprint over the event, its state, the action and every evidence edge. Callers that
/// publish a decision outside [`evaluate_unknown_presence`] (for example a certified-quiet event)
/// use this so the path cannot drift from the policy's own encoding.
#[must_use]
pub fn policy_decision_path(
    event_id: &EventId,
    evidence: &[EventEvidence],
    state: EventState,
    action: ReferencePolicyAction,
) -> DecisionPath {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.reference_unknown_presence_policy.v2");
    event_id.encode_canonical(&mut encoder);
    encoder.text(state.as_str());
    encoder.u8(match action {
        ReferencePolicyAction::Hold => 1,
        ReferencePolicyAction::PrepareAlert => 2,
    });
    encoder.u64(evidence.len() as u64);
    for edge in evidence {
        edge.encode_canonical(&mut encoder);
    }
    let fingerprint = ContentDigest::sha256(&encoder.finish());
    DecisionPath {
        policy_generation: ContentDigest::sha256(b"fss.reference_unknown_presence_policy.v2"),
        fingerprint,
        abstained: false,
        abstention_reason: None,
    }
}

const ZONE_ENTRY_POLICY: &str = "fss.reference_zone_entry_corroboration_policy.v1";
const MAX_ZONE_ENTRY_WITNESSES: usize = 8;

/// One retained per-sensor zone-entry observation offered to the zone-entry policy.
///
/// The record is caller-retained evidence (for example a model-free foreground track projected
/// through an owner-supplied ground homography); it carries no calibration, identity or class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZoneEntryWitness {
    /// Digest of the retained observation record.
    pub record_digest: ContentDigest,
    /// Digest of the recording sensor identity.
    pub sensor_digest: ContentDigest,
    /// Retained source-capsule payload digest of the entry frame.
    pub capsule_digest: ContentDigest,
    /// Failure domain assigned from deployment truth (one recording sensor is one domain).
    pub failure_domain: String,
    /// Conservative capture interval of the entry observation.
    pub interval: CaptureInterval,
}

/// Inputs to [`evaluate_zone_entry_corroboration`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZoneEntryCorroboration {
    /// Deterministic event identity.
    pub event_id: EventId,
    /// Owner-drawn zone entered.
    pub zone_id: String,
    /// Sensor-local track labels; never a physical identity.
    pub track_ids: Vec<String>,
    /// Per-sensor entry witnesses (1..=8; corroboration needs independent ones).
    pub witnesses: Vec<ZoneEntryWitness>,
    /// Retained association record binding the witnesses under explicit gates.
    pub association_digest: ContentDigest,
    /// Failure domain of the association computation itself (neutral lineage).
    pub association_domain: String,
    /// Bounded explanation of the interval and uncalibrated semantics.
    pub uncertainty_reason: String,
}

/// Evaluates "did independent sensors observe the same zone entry?".
///
/// Every witness becomes a supporting edge in its own failure domain; the association record is a
/// neutral derivation edge. The event is `Corroborated` (and the affordance `PrepareAlert`) only
/// when the supporting edges come from at least two distinct sensors, two distinct capture roots
/// and two distinct failure domains; otherwise it is `Witnessed` and held. The kind stays
/// `Unclassified` and the probability the maximally conservative `[0, 1]`: corroborated means
/// independently observed, not classified, calibrated or identified. `PrepareAlert` is only an
/// affordance for a separately approved alert preparation, never an effect.
pub fn evaluate_zone_entry_corroboration(
    input: ZoneEntryCorroboration,
) -> Result<ReferencePolicyDecision, ReferenceError> {
    if input.witnesses.is_empty() || input.witnesses.len() > MAX_ZONE_ENTRY_WITNESSES {
        return Err(ReferenceError::InvalidSpec("zone_entry_witnesses"));
    }
    if input.association_domain.is_empty()
        || input.association_domain.len() > MAX_FAILURE_DOMAIN_BYTES
    {
        return Err(ReferenceError::InvalidSpec("failure_domain"));
    }
    let mut sensors = BTreeSet::new();
    let mut captures = BTreeSet::new();
    let mut domains = BTreeSet::new();
    let mut records = BTreeSet::new();
    let mut evidence = Vec::with_capacity(input.witnesses.len() + 1);
    let mut earliest = input.witnesses[0].interval.earliest;
    let mut latest = input.witnesses[0].interval.latest;
    for witness in &input.witnesses {
        if witness.failure_domain.is_empty()
            || witness.failure_domain.len() > MAX_FAILURE_DOMAIN_BYTES
        {
            return Err(ReferenceError::InvalidSpec("failure_domain"));
        }
        if !records.insert(witness.record_digest) {
            return Err(ReferenceError::InvalidSpec("duplicate_zone_entry_witness"));
        }
        sensors.insert(witness.sensor_digest);
        captures.insert(witness.capsule_digest);
        domains.insert(witness.failure_domain.as_str());
        earliest = earliest.min(witness.interval.earliest);
        latest = latest.max(witness.interval.latest);
        evidence.push(EventEvidence {
            digest: witness.record_digest,
            class: EvidenceClass::Derived,
            failure_domain: witness.failure_domain.clone(),
            supports: true,
            relation: EvidenceEdgeRelation::Supports,
            capsule_digest: Some(witness.capsule_digest),
            identity_digest: Some(witness.sensor_digest),
        });
    }
    evidence.push(EventEvidence {
        digest: input.association_digest,
        class: EvidenceClass::Derived,
        failure_domain: input.association_domain.clone(),
        supports: false,
        relation: EvidenceEdgeRelation::DerivedFrom,
        capsule_digest: None,
        identity_digest: None,
    });
    let state = if sensors.len() >= 2 && captures.len() >= 2 && domains.len() >= 2 {
        EventState::Corroborated
    } else {
        EventState::Witnessed
    };
    let action = if state == EventState::Corroborated {
        ReferencePolicyAction::PrepareAlert
    } else {
        ReferencePolicyAction::Hold
    };
    let decision_path = zone_entry_decision_path(&input.event_id, &evidence, state, action);
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_string(),
        event_id: input.event_id,
        revision: 1,
        supersedes: None,
        state,
        kind: EventKind::Unclassified,
        interval: CaptureInterval::new(earliest, latest)?,
        uncertainty_reason: Some(input.uncertainty_reason),
        zone_ids: vec![input.zone_id],
        track_ids: input.track_ids,
        probability: ProbabilityInterval::new(0.0, 1.0)?,
        evidence,
        model_receipts: Vec::new(),
        decision_path,
    };
    event.validate()?;
    Ok(ReferencePolicyDecision { event, action })
}

/// Decision path of the zone-entry corroboration policy over this exact event identity, state,
/// action and evidence. Alert eligibility recognizes it exactly as it recognizes the
/// unknown-presence policy path; any other path holds.
pub(crate) fn zone_entry_decision_path(
    event_id: &EventId,
    evidence: &[EventEvidence],
    state: EventState,
    action: ReferencePolicyAction,
) -> DecisionPath {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(ZONE_ENTRY_POLICY);
    event_id.encode_canonical(&mut encoder);
    encoder.text(state.as_str());
    encoder.u8(match action {
        ReferencePolicyAction::Hold => 1,
        ReferencePolicyAction::PrepareAlert => 2,
    });
    encoder.u64(evidence.len() as u64);
    for edge in evidence {
        edge.encode_canonical(&mut encoder);
    }
    DecisionPath {
        policy_generation: ContentDigest::sha256(ZONE_ENTRY_POLICY.as_bytes()),
        fingerprint: ContentDigest::sha256(&encoder.finish()),
        abstained: false,
        abstention_reason: None,
    }
}
