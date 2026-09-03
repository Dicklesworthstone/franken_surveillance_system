//! Canonical publication of deterministic alert-effect outcomes.

use fss_core::{
    BatchId, CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest, EffectJournal,
    EffectState, EvidenceDelta, LedgerAnchor, ObjectId, ObligationState, OperationReceipt, Plane,
};
use fss_ledger::DurableReferenceLedger;
use fss_object::{InMemoryObjectStore, ObjectManifest};
use fss_publication::AuthorityPublisher;

use crate::{
    ReferenceAlertPlan, ReferenceError,
    alert::{reference_alert_terminal_proof_bytes, validate_reference_alert_plan},
};

const ALERT_OUTCOME_FAMILY: &str = "alert_effect_outcome";
const ALERT_OUTCOME_GENERATION: u64 = 1;

/// Immutable semantic record tying one alert operation to its event basis and terminal evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceAlertOutcome {
    /// Exact terminal or indeterminate operation receipt.
    pub operation_receipt: OperationReceipt,
    /// Terminal-proof obligation owned by the operation.
    pub obligation_id: fss_core::ObligationId,
    /// Event graph against which the alert was prepared.
    pub event_root: ContentDigest,
    /// Exact event revision witness.
    pub event_revision_digest: ContentDigest,
    /// Bounded provider channel identity.
    pub channel: String,
    /// Content object containing the canonical operation receipt bytes.
    pub operation_object_digest: ContentDigest,
    /// Retained provider proof object, absent only for an indeterminate outcome.
    pub proof_object_digest: Option<ContentDigest>,
}

impl CanonicalEncode for ReferenceAlertOutcome {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text("fss.reference_alert_outcome.v1");
        self.operation_receipt.encode_canonical(encoder);
        self.obligation_id.encode_canonical(encoder);
        encoder.digest(self.event_root);
        encoder.digest(self.event_revision_digest);
        encoder.text(&self.channel);
        encoder.digest(self.operation_object_digest);
        match self.proof_object_digest {
            Some(digest) => {
                encoder.bool(true);
                encoder.digest(digest);
            }
            None => encoder.bool(false),
        }
    }
}

/// Authority receipt for one published alert-effect outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceAlertOutcomeReceipt {
    /// Canonical semantic outcome.
    pub outcome: ReferenceAlertOutcome,
    /// Stable effect object identity.
    pub effect_object_id: ObjectId,
    /// Effect object generation.
    pub effect_generation: u64,
    /// Root of the complete outcome object graph.
    pub outcome_root: ContentDigest,
    /// Exact canonical outcome metadata object.
    pub outcome_object_digest: ContentDigest,
    /// Authority anchor after publication, or the current anchor on an exact retry.
    pub authority_anchor: LedgerAnchor,
}

/// Publishes one verified, failed, or indeterminate alert outcome exactly once.
///
/// Provider success and known failure retain their exact deterministic proof bytes. An ambiguous
/// outcome is published without fabricating proof and remains `Indeterminate`. Exact retries return
/// the existing authority state; a different payload under the same operation identity fails before
/// staging any conflicting object.
pub fn publish_reference_alert_outcome(
    plan: &ReferenceAlertPlan,
    journal: &EffectJournal,
    objects: &mut InMemoryObjectStore,
    ledger: &mut DurableReferenceLedger,
) -> Result<ReferenceAlertOutcomeReceipt, ReferenceError> {
    validate_reference_alert_plan(plan)?;
    let operation = journal
        .operation(&plan.intent.operation_id)
        .ok_or(fss_core::ContractError::NotFound)?
        .clone();
    if operation.intent != plan.intent || operation.committed_at.is_none() {
        return Err(ReferenceError::InvalidSpec("alert_outcome_operation"));
    }

    let obligation = journal
        .obligations()
        .find(|candidate| candidate.obligation_id == plan.obligation_id)
        .ok_or(fss_core::ContractError::NotFound)?;
    if obligation.operation_id != plan.intent.operation_id {
        return Err(ReferenceError::InvalidSpec("alert_outcome_obligation"));
    }
    let expected_obligation_state = match operation.state {
        EffectState::Verified => ObligationState::Verified,
        EffectState::Failed => ObligationState::Failed,
        EffectState::Indeterminate => ObligationState::Indeterminate,
        _ => return Err(ReferenceError::InvalidSpec("alert_outcome_not_publishable")),
    };
    if obligation.state != expected_obligation_state
        || obligation.proof_digest != operation.result_digest
    {
        return Err(ReferenceError::InvalidSpec("alert_outcome_obligation"));
    }

    let event_is_published = ledger.batches().iter().any(|batch| {
        batch.deltas.iter().any(|delta| {
            delta.family == "event_revision"
                && delta.payload_digest == plan.event_root
                && delta.witness_digest == Some(plan.event_revision_digest)
        })
    });
    if !event_is_published {
        return Err(ReferenceError::InvalidSpec("alert_outcome_event_basis"));
    }
    let _ = objects.verify_closure(plan.event_root)?;

    let proof_bytes = reference_alert_terminal_proof_bytes(plan, &operation)?;
    let proof_object_digest = proof_bytes.as_deref().map(ContentDigest::sha256);
    if proof_object_digest != operation.result_digest {
        return Err(ReferenceError::InvalidSpec("alert_outcome_proof"));
    }

    let operation_bytes = operation.canonical_bytes();
    let operation_object_digest = ContentDigest::sha256(&operation_bytes);
    let outcome = ReferenceAlertOutcome {
        operation_receipt: operation.clone(),
        obligation_id: plan.obligation_id.clone(),
        event_root: plan.event_root,
        event_revision_digest: plan.event_revision_digest,
        channel: plan.channel.clone(),
        operation_object_digest,
        proof_object_digest,
    };
    let outcome_bytes = outcome.canonical_bytes();
    let outcome_object_digest = ContentDigest::sha256(&outcome_bytes);
    let mut children = vec![plan.event_root, operation_object_digest];
    if let Some(proof) = proof_object_digest {
        children.push(proof);
    }
    let outcome_manifest =
        ObjectManifest::new("alert-effect-outcome", children, Some(outcome_object_digest))?;
    let outcome_root = outcome_manifest.root();
    let effect_object_id = ObjectId::parse(format!(
        "object:effect:{}",
        plan.intent.operation_id.as_str()
    ))?;

    if let Some(current) = ledger.current().objects.get(&effect_object_id) {
        if current.generation == ALERT_OUTCOME_GENERATION
            && current.family == ALERT_OUTCOME_FAMILY
            && current.plane == Plane::Effect
            && current.payload_digest == outcome_root
        {
            let _ = objects.verify_closure(outcome_root)?;
            return Ok(ReferenceAlertOutcomeReceipt {
                outcome,
                effect_object_id,
                effect_generation: current.generation,
                outcome_root,
                outcome_object_digest,
                authority_anchor: ledger.current().anchor.clone(),
            });
        }
        return Err(fss_core::ContractError::IdempotencyConflict.into());
    }

    let stored_operation = objects.put_verified(&operation_bytes)?;
    if stored_operation != operation_object_digest {
        return Err(ReferenceError::DigestMismatch);
    }
    if let Some(bytes) = proof_bytes.as_deref() {
        let stored_proof = objects.put_verified(bytes)?;
        if Some(stored_proof) != proof_object_digest {
            return Err(ReferenceError::DigestMismatch);
        }
    }
    let stored_outcome = objects.put_verified(&outcome_bytes)?;
    if stored_outcome != outcome_object_digest {
        return Err(ReferenceError::DigestMismatch);
    }
    let published = objects.publish_manifest(outcome_manifest)?;
    if published.root != outcome_root {
        return Err(ReferenceError::DigestMismatch);
    }

    let validity = CaptureInterval::new(operation.prepared_at, operation.updated_at)?;
    let operation_name = plan.intent.operation_id.as_str();
    let delta = EvidenceDelta {
        delta_id: format!("delta:alert-outcome:{operation_name}:1"),
        family: ALERT_OUTCOME_FAMILY.to_owned(),
        object_id: effect_object_id.clone(),
        prior_generation: None,
        new_generation: ALERT_OUTCOME_GENERATION,
        validity,
        plane: Plane::Effect,
        payload_digest: outcome_root,
        witness_digest: Some(operation.receipt_digest()),
        operation_id: Some(plan.intent.operation_id.clone()),
    };
    let authority_anchor = {
        let mut publisher = AuthorityPublisher::new(objects, ledger);
        let batch = publisher.prepare_batch(
            BatchId::parse(format!("batch:alert-outcome:{operation_name}:1"))?,
            vec![delta],
            [outcome_root],
        )?;
        publisher.append(batch)?
    };

    Ok(ReferenceAlertOutcomeReceipt {
        outcome,
        effect_object_id,
        effect_generation: ALERT_OUTCOME_GENERATION,
        outcome_root,
        outcome_object_digest,
        authority_anchor,
    })
}
