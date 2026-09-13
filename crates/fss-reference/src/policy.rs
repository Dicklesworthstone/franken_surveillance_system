//! Deterministic event-policy reference separating model findings from canonical event truth.

use std::collections::BTreeSet;

use fss_core::{
    BatchId, CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest, DecisionPath,
    EventEvidence, EventHypothesis, EventId, EventKind, EventState, EvidenceClass, EvidenceDelta,
    EvidenceEdgeRelation, LedgerAnchor, ObjectId, Plane, ProbabilityInterval,
};
use fss_ledger::DurableReferenceLedger;
use fss_object::{InMemoryObjectStore, ObjectManifest, VerifiedObjectCatalog};
use fss_publication::AuthorityPublisher;

use crate::{MockModelOutcome, MockModelResult, MockSemanticLabel, ReferenceError};

const MAX_POLICY_OBSERVATIONS: usize = 64;
const MAX_FAILURE_DOMAIN_BYTES: usize = 256;

/// One retained model result with the physical/shared failure domain assigned by deployment truth.
#[derive(Clone, Debug, PartialEq)]
pub struct ReferenceModelObservation {
    /// Exact retained model result.
    pub result: MockModelResult,
    /// Failure-domain identity used for corroboration accounting.
    pub failure_domain: String,
    /// Physical validity interval represented by this observation.
    pub interval: CaptureInterval,
}

impl ReferenceModelObservation {
    /// Constructs a bounded observation without granting any event/effect authority.
    pub fn new(
        result: MockModelResult,
        failure_domain: impl Into<String>,
        interval: CaptureInterval,
    ) -> Result<Self, ReferenceError> {
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

        let relation = match &observation.result.outcome {
            MockModelOutcome::Finding {
                label: MockSemanticLabel::PersonLike,
                ..
            } => {
                support_domains.insert(observation.failure_domain.clone());
                support_capture_roots.insert(observation.result.input_capture_root);
                support_sensors.insert(observation.result.sensor_id.clone());
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
        let _ = objects.verify_closure(staged.event_root)?;

        return Ok(ReferenceEventReceipt {
            event_root: staged.event_root,
            event_object_digest: staged.event_object_digest,
            event_revision_digest: staged.event_revision_digest,
            authority_anchor: committed_anchor,
        });
    }

    // A revision must supersede exactly the revision the authority currently holds, and a
    // genesis revision requires the event object to be absent: anything else is a fork.
    if decision.event.supersedes != predecessor {
        return Err(fss_core::ContractError::SupersessionMismatch.into());
    }

    let staged = stage_event_revision(decision, objects)?;

    let delta = EvidenceDelta {
        delta_id: format!("delta:event:{event_name}:{}", decision.event.revision),
        family: "event_revision".to_owned(),
        object_id,
        prior_generation,
        new_generation: decision.event.revision,
        validity: decision.event.interval,
        plane: Plane::Authority,
        payload_digest: staged.event_root,
        witness_digest: Some(staged.event_revision_digest),
        operation_id: None,
    };

    let authority_anchor = {
        let mut publisher = AuthorityPublisher::new(objects, ledger);
        let batch = publisher.prepare_batch(
            BatchId::parse(format!(
                "batch:event:{event_name}:{}",
                decision.event.revision
            ))?,
            vec![delta],
            [staged.event_root],
        )?;
        publisher.append(batch)?
    };
    Ok(ReferenceEventReceipt {
        event_root: staged.event_root,
        event_object_digest: staged.event_object_digest,
        event_revision_digest: staged.event_revision_digest,
        authority_anchor,
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

fn policy_decision_path(
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
