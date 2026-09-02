//! Deterministic event-policy reference separating model findings from canonical event truth.

use std::collections::BTreeSet;

use fss_core::{
    BatchId, CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest, EventEvidence,
    EventHypothesis, EventId, EventKind, EventState, EvidenceDelta, LedgerAnchor, ObjectId, Plane,
    ProbabilityInterval,
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
/// Corroboration is based solely on distinct supporting failure domains with no retained alternate
/// model outcome. Duplicate result objects are rejected so one model receipt cannot be relabeled
/// into multiple independent witnesses.
pub fn evaluate_unknown_presence(
    event_id: EventId,
    observations: Vec<ReferenceModelObservation>,
) -> Result<ReferencePolicyDecision, ReferenceError> {
    if observations.is_empty() || observations.len() > MAX_POLICY_OBSERVATIONS {
        return Err(ReferenceError::InvalidSpec("policy_observations"));
    }

    let mut observations = observations;
    observations.sort_by(|left, right| {
        (left.failure_domain.as_str(), left.result.object_digest()).cmp(&(
            right.failure_domain.as_str(),
            right.result.object_digest(),
        ))
    });
    let mut seen_results = BTreeSet::new();
    let mut support_domains = BTreeSet::new();
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

        let supports = match &observation.result.outcome {
            MockModelOutcome::Finding {
                label: MockSemanticLabel::PersonLike,
                ..
            } => {
                support_domains.insert(observation.failure_domain.clone());
                true
            }
            MockModelOutcome::Finding {
                label: MockSemanticLabel::AnimalLike,
                ..
            } => {
                contradictory += 1;
                false
            }
            MockModelOutcome::Finding {
                label: MockSemanticLabel::TamperLike | MockSemanticLabel::Unknown,
                ..
            }
            | MockModelOutcome::Abstained { .. } => {
                unresolved += 1;
                false
            }
        };
        evidence.push(EventEvidence {
            digest: result_digest,
            failure_domain: observation.failure_domain.clone(),
            supports,
        });
        model_receipts.push(result_digest);
    }

    let state = if support_domains.len() >= 2 && contradictory == 0 && unresolved == 0 {
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
        event_id,
        revision: 1,
        state,
        kind: EventKind::UnknownPresence,
        interval,
        probability,
        evidence,
        model_receipts,
        decision_path,
    };
    event.validate()?;
    Ok(ReferencePolicyDecision { event, action })
}

/// Retains the event/evidence closure and publishes one canonical event revision to authority.
pub fn publish_reference_event(
    decision: &ReferencePolicyDecision,
    objects: &mut InMemoryObjectStore,
    ledger: &mut DurableReferenceLedger,
) -> Result<ReferenceEventReceipt, ReferenceError> {
    for model_receipt in &decision.event.model_receipts {
        objects.require_verified(*model_receipt)?;
    }
    let event_bytes = decision.event.canonical_bytes();
    let event_object_digest = objects.put_verified(&event_bytes)?;
    let event_revision_digest = decision.event.revision_digest();
    let event_manifest = ObjectManifest::new(
        "event-revision",
        decision.event.model_receipts.iter().copied(),
        Some(event_object_digest),
    )?;
    let event_root = objects.publish_manifest(event_manifest)?.root;

    let event_name = decision.event.event_id.as_str();
    let delta = EvidenceDelta {
        delta_id: format!("delta:event:{event_name}:{}", decision.event.revision),
        family: "event_revision".to_owned(),
        object_id: ObjectId::parse(format!("object:event:{event_name}"))?,
        prior_generation: None,
        new_generation: decision.event.revision,
        validity: decision.event.interval,
        plane: Plane::Authority,
        payload_digest: event_root,
        witness_digest: Some(event_revision_digest),
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
            [event_root],
        )?;
        publisher.append(batch)?
    };
    Ok(ReferenceEventReceipt {
        event_root,
        event_object_digest,
        event_revision_digest,
        authority_anchor,
    })
}

fn policy_decision_path(
    event_id: &EventId,
    evidence: &[EventEvidence],
    state: EventState,
    action: ReferencePolicyAction,
) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.reference_unknown_presence_policy.v1");
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
    ContentDigest::sha256(&encoder.finish())
}
