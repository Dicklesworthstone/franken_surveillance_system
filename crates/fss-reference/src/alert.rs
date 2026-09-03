//! Deterministic alert-effect oracle with lost-ACK reconciliation.

use std::collections::BTreeMap;

use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, EffectIntent, EffectJournal, EffectState,
    IdempotencyKey, ObligationId, OperationId, OperationReceipt, TimestampNs,
};
use fss_ledger::DurableReferenceLedger;

use crate::{ReferenceError, ReferenceEventReceipt, ReferencePolicyAction, ReferencePolicyDecision};

const MAX_ALERT_CHANNEL_BYTES: usize = 256;

/// Immutable prepared alert plan. Preparation grants no external dispatch by itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceAlertPlan {
    /// Exact effect intent registered in the effect journal.
    pub intent: EffectIntent,
    /// Existing terminal-proof obligation owned by the operation.
    pub obligation_id: ObligationId,
    /// Exact canonical event graph being reported.
    pub event_root: ContentDigest,
    /// Event revision fingerprint.
    pub event_revision_digest: ContentDigest,
    /// Stable bounded alert channel identity.
    pub channel: String,
}

/// Deterministic provider fault choice for one dispatch attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceProviderBehavior {
    /// Provider stores the message and returns trustworthy delivery proof.
    Deliver,
    /// Provider stores the message but the caller loses the acknowledgement.
    LoseAckAfterDelivery,
    /// Provider proves the request failed before any message was created.
    FailBeforeDelivery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderDispatch {
    Delivered(ContentDigest),
    LostAck,
    KnownFailure(ContentDigest),
    ConflictingIdempotency,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProviderMessage {
    request_digest: ContentDigest,
    proof_digest: ContentDigest,
}

/// Deterministic idempotent alert provider oracle.
#[derive(Clone, Debug, Default)]
pub struct ReferenceAlertProvider {
    messages: BTreeMap<IdempotencyKey, ProviderMessage>,
}

impl ReferenceAlertProvider {
    /// Creates an empty deterministic provider.
    #[must_use]
    pub fn new() -> Self {
        Self {
            messages: BTreeMap::new(),
        }
    }

    /// Number of unique provider messages created.
    #[must_use]
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    fn dispatch(
        &mut self,
        intent: &EffectIntent,
        behavior: ReferenceProviderBehavior,
    ) -> ProviderDispatch {
        if let Some(existing) = self.messages.get(&intent.idempotency_key) {
            return if existing.request_digest == intent.request_digest {
                ProviderDispatch::Delivered(existing.proof_digest)
            } else {
                ProviderDispatch::ConflictingIdempotency
            };
        }
        if behavior == ReferenceProviderBehavior::FailBeforeDelivery {
            return ProviderDispatch::KnownFailure(provider_failure_proof(intent));
        }

        let proof_digest = provider_delivery_proof(intent);
        self.messages.insert(
            intent.idempotency_key.clone(),
            ProviderMessage {
                request_digest: intent.request_digest,
                proof_digest,
            },
        );
        match behavior {
            ReferenceProviderBehavior::Deliver => ProviderDispatch::Delivered(proof_digest),
            ReferenceProviderBehavior::LoseAckAfterDelivery => ProviderDispatch::LostAck,
            ReferenceProviderBehavior::FailBeforeDelivery => {
                ProviderDispatch::KnownFailure(provider_failure_proof(intent))
            }
        }
    }

    fn lookup(&self, intent: &EffectIntent) -> Result<Option<ContentDigest>, ReferenceError> {
        match self.messages.get(&intent.idempotency_key) {
            Some(message) if message.request_digest == intent.request_digest => {
                Ok(Some(message.proof_digest))
            }
            Some(_) => Err(ReferenceError::InvalidSpec(
                "provider_idempotency_conflict",
            )),
            None => Ok(None),
        }
    }
}

/// Prepares an alert effect only from a currently authoritative independently corroborated event.
///
/// The supplied event receipt must match the current durable authority anchor and the latest
/// publication batch must contain the exact event root/revision witness. This prevents a forged or
/// stale typed receipt from becoming effect authority.
pub fn prepare_reference_alert(
    decision: &ReferencePolicyDecision,
    event_receipt: &ReferenceEventReceipt,
    authority: &DurableReferenceLedger,
    operation_id: OperationId,
    idempotency_key: IdempotencyKey,
    obligation_id: ObligationId,
    channel: impl Into<String>,
    now: TimestampNs,
    journal: &mut EffectJournal,
) -> Result<ReferenceAlertPlan, ReferenceError> {
    if decision.action != ReferencePolicyAction::PrepareAlert
        || decision.event.state != fss_core::EventState::Corroborated
    {
        return Err(ReferenceError::InvalidSpec("alert_not_eligible"));
    }
    if event_receipt.event_revision_digest != decision.event.revision_digest() {
        return Err(ReferenceError::InvalidSpec("event_receipt_mismatch"));
    }
    if authority.current().anchor != event_receipt.authority_anchor {
        return Err(ReferenceError::InvalidSpec("event_authority_stale"));
    }
    let latest_contains_event = authority.batches().last().is_some_and(|batch| {
        batch.deltas.iter().any(|delta| {
            delta.family == "event_revision"
                && delta.payload_digest == event_receipt.event_root
                && delta.witness_digest == Some(event_receipt.event_revision_digest)
        })
    });
    if !latest_contains_event {
        return Err(ReferenceError::InvalidSpec("event_receipt_mismatch"));
    }

    let channel = channel.into();
    if channel.is_empty() || channel.len() > MAX_ALERT_CHANNEL_BYTES {
        return Err(ReferenceError::InvalidSpec("alert_channel"));
    }

    let request_digest = alert_request_digest(event_receipt, &channel);
    let precondition_digest = alert_precondition_digest(decision, event_receipt);
    let intent = EffectIntent {
        operation_id,
        idempotency_key,
        effect_class: "alert.dispatch".to_owned(),
        request_digest,
        precondition_digest,
    };
    let receipt = journal.prepare(
        intent.clone(),
        obligation_id,
        "provider delivery is independently reconciled",
        now,
    )?;
    let actual_obligation = journal
        .obligations()
        .find(|obligation| obligation.operation_id == receipt.intent.operation_id)
        .ok_or(fss_core::ContractError::NotFound)?
        .obligation_id
        .clone();
    Ok(ReferenceAlertPlan {
        intent: receipt.intent.clone(),
        obligation_id: actual_obligation,
        event_root: event_receipt.event_root,
        event_revision_digest: event_receipt.event_revision_digest,
        channel,
    })
}

/// Commits and dispatches one exact prepared alert plan through the deterministic provider oracle.
///
/// A second call after `Indeterminate` fails in the effect journal before the provider is touched.
/// This models the required no-blind-retry rule for ambiguous external effects.
pub fn dispatch_reference_alert(
    plan: &ReferenceAlertPlan,
    behavior: ReferenceProviderBehavior,
    commit_at: TimestampNs,
    outcome_at: TimestampNs,
    journal: &mut EffectJournal,
    provider: &mut ReferenceAlertProvider,
) -> Result<OperationReceipt, ReferenceError> {
    validate_reference_alert_plan(plan)?;
    let operation_id = &plan.intent.operation_id;
    let _ = journal.transition(
        operation_id,
        EffectState::Committed,
        commit_at,
        None,
        None,
    )?;

    match provider.dispatch(&plan.intent, behavior) {
        ProviderDispatch::Delivered(proof) => {
            let _ = journal.transition(
                operation_id,
                EffectState::AdapterAccepted,
                outcome_at,
                None,
                None,
            )?;
            let _ = journal.transition(
                operation_id,
                EffectState::Observed,
                outcome_at,
                Some(proof),
                None,
            )?;
            let receipt = journal.transition(
                operation_id,
                EffectState::Verified,
                outcome_at,
                Some(proof),
                None,
            )?;
            Ok(receipt.clone())
        }
        ProviderDispatch::LostAck => Ok(journal
            .mark_indeterminate(operation_id, outcome_at, "provider_ack_lost")?
            .clone()),
        ProviderDispatch::KnownFailure(proof) => Ok(journal
            .transition(
                operation_id,
                EffectState::Failed,
                outcome_at,
                Some(proof),
                Some("provider_failed_before_delivery".to_owned()),
            )?
            .clone()),
        ProviderDispatch::ConflictingIdempotency => Ok(journal
            .mark_indeterminate(
                operation_id,
                outcome_at,
                "provider_idempotency_conflict",
            )?
            .clone()),
    }
}

/// Reconciles an indeterminate alert from independent provider state without resending it.
///
/// `Ok(None)` means no positive terminal proof is currently available; the operation intentionally
/// remains indeterminate rather than being guessed failed.
pub fn reconcile_reference_alert(
    plan: &ReferenceAlertPlan,
    now: TimestampNs,
    journal: &mut EffectJournal,
    provider: &ReferenceAlertProvider,
) -> Result<Option<OperationReceipt>, ReferenceError> {
    validate_reference_alert_plan(plan)?;
    let Some(proof_digest) = provider.lookup(&plan.intent)? else {
        return Ok(None);
    };
    Ok(Some(
        journal
            .reconcile_verified(&plan.intent.operation_id, proof_digest, now)?
            .clone(),
    ))
}

fn alert_request_digest(
    event_receipt: &ReferenceEventReceipt,
    channel: &str,
) -> ContentDigest {
    alert_request_digest_parts(
        event_receipt.event_root,
        event_receipt.event_revision_digest,
        channel,
    )
}

fn alert_request_digest_parts(
    event_root: ContentDigest,
    event_revision_digest: ContentDigest,
    channel: &str,
) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.reference_alert_request.v1");
    encoder.digest(event_root);
    encoder.digest(event_revision_digest);
    encoder.text(channel);
    ContentDigest::sha256(&encoder.finish())
}

pub(crate) fn validate_reference_alert_plan(
    plan: &ReferenceAlertPlan,
) -> Result<(), ReferenceError> {
    if plan.channel.is_empty()
        || plan.channel.len() > MAX_ALERT_CHANNEL_BYTES
        || plan.intent.effect_class != "alert.dispatch"
        || plan.intent.request_digest
            != alert_request_digest_parts(
                plan.event_root,
                plan.event_revision_digest,
                &plan.channel,
            )
    {
        return Err(ReferenceError::InvalidSpec("alert_plan_integrity"));
    }
    Ok(())
}

fn alert_precondition_digest(
    decision: &ReferencePolicyDecision,
    event_receipt: &ReferenceEventReceipt,
) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.reference_alert_precondition.v1");
    encoder.digest(event_receipt.event_revision_digest);
    event_receipt.authority_anchor.encode_canonical(&mut encoder);
    encoder.text(decision.event.state.as_str());
    encoder.digest(decision.event.decision_path);
    ContentDigest::sha256(&encoder.finish())
}

fn provider_delivery_proof(intent: &EffectIntent) -> ContentDigest {
    ContentDigest::sha256(&provider_delivery_proof_bytes(intent))
}

fn provider_failure_proof(intent: &EffectIntent) -> ContentDigest {
    ContentDigest::sha256(&provider_failure_proof_bytes(intent))
}

fn provider_delivery_proof_bytes(intent: &EffectIntent) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.reference_alert_provider_message.v1");
    intent.idempotency_key.encode_canonical(&mut encoder);
    encoder.digest(intent.request_digest);
    encoder.finish()
}

fn provider_failure_proof_bytes(intent: &EffectIntent) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.reference_alert_provider_failure.v1");
    intent.idempotency_key.encode_canonical(&mut encoder);
    encoder.digest(intent.request_digest);
    encoder.text("failed_before_delivery");
    encoder.finish()
}

pub(crate) fn reference_alert_terminal_proof_bytes(
    plan: &ReferenceAlertPlan,
    receipt: &OperationReceipt,
) -> Result<Option<Vec<u8>>, ReferenceError> {
    if receipt.intent != plan.intent {
        return Err(ReferenceError::InvalidSpec("alert_outcome_operation"));
    }
    match receipt.state {
        EffectState::Verified => {
            if receipt.error_code.is_some() {
                return Err(ReferenceError::InvalidSpec("alert_outcome_proof"));
            }
            let bytes = provider_delivery_proof_bytes(&receipt.intent);
            if receipt.result_digest != Some(ContentDigest::sha256(&bytes)) {
                return Err(ReferenceError::InvalidSpec("alert_outcome_proof"));
            }
            Ok(Some(bytes))
        }
        EffectState::Failed => {
            if receipt.error_code.as_deref().is_none_or(str::is_empty) {
                return Err(ReferenceError::InvalidSpec("alert_outcome_proof"));
            }
            let bytes = provider_failure_proof_bytes(&receipt.intent);
            if receipt.result_digest != Some(ContentDigest::sha256(&bytes)) {
                return Err(ReferenceError::InvalidSpec("alert_outcome_proof"));
            }
            Ok(Some(bytes))
        }
        EffectState::Indeterminate => {
            if receipt.result_digest.is_some()
                || receipt.error_code.as_deref().is_none_or(str::is_empty)
            {
                return Err(ReferenceError::InvalidSpec("alert_outcome_proof"));
            }
            Ok(None)
        }
        _ => Err(ReferenceError::InvalidSpec("alert_outcome_not_publishable")),
    }
}
