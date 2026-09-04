//! Idempotent effect preparation, terminal-proof obligations, and reconciliation.

use std::collections::BTreeMap;

use crate::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, ContractError, IdempotencyKey, ObligationId,
    OperationId, TimestampNs,
};

/// Effect lifecycle. Transport acceptance is not terminal success.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EffectState {
    /// Immutable intent and preconditions were durably prepared.
    Prepared,
    /// Dispatch authority was committed.
    Committed,
    /// The external adapter accepted the request.
    AdapterAccepted,
    /// A resulting physical or provider state was observed.
    Observed,
    /// Terminal postconditions were proved.
    Verified,
    /// Cancellation completed without an unresolved external effect.
    Cancelled,
    /// The operation failed with a known terminal outcome.
    Failed,
    /// The effect may have happened but cannot yet be established.
    Indeterminate,
}

impl EffectState {
    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Committed => "committed",
            Self::AdapterAccepted => "adapter_accepted",
            Self::Observed => "observed",
            Self::Verified => "verified",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::Indeterminate => "indeterminate",
        }
    }

    /// Returns true for a terminal state that permits no ordinary progress transition.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Verified | Self::Cancelled | Self::Failed)
    }
}

/// Immutable effect intent prepared before crossing an external boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectIntent {
    /// Operation identity.
    pub operation_id: OperationId,
    /// Replay identity.
    pub idempotency_key: IdempotencyKey,
    /// Stable effect class.
    pub effect_class: String,
    /// Digest of the exact request.
    pub request_digest: ContentDigest,
    /// Digest of the exact preconditions.
    pub precondition_digest: ContentDigest,
}

impl CanonicalEncode for EffectIntent {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.operation_id.encode_canonical(encoder);
        self.idempotency_key.encode_canonical(encoder);
        encoder.text(&self.effect_class);
        encoder.digest(self.request_digest);
        encoder.digest(self.precondition_digest);
    }
}

/// Durable operation receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationReceipt {
    /// Prepared intent.
    pub intent: EffectIntent,
    /// Current effect state.
    pub state: EffectState,
    /// Prepare timestamp.
    pub prepared_at: TimestampNs,
    /// Commit timestamp, when committed.
    pub committed_at: Option<TimestampNs>,
    /// Last transition timestamp.
    pub updated_at: TimestampNs,
    /// Result or observation digest.
    pub result_digest: Option<ContentDigest>,
    /// Stable error code.
    pub error_code: Option<String>,
}

impl OperationReceipt {
    /// Returns the receipt digest.
    #[must_use]
    pub fn receipt_digest(&self) -> ContentDigest {
        self.canonical_digest("fss.operation_receipt.v1")
    }
}

impl CanonicalEncode for OperationReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.intent.encode_canonical(encoder);
        encoder.text(self.state.as_str());
        self.prepared_at.encode_canonical(encoder);
        match self.committed_at {
            Some(value) => {
                encoder.bool(true);
                value.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
        self.updated_at.encode_canonical(encoder);
        match self.result_digest {
            Some(value) => {
                encoder.bool(true);
                encoder.digest(value);
            }
            None => encoder.bool(false),
        }
        match &self.error_code {
            Some(value) => {
                encoder.bool(true);
                encoder.text(value);
            }
            None => encoder.bool(false),
        }
    }
}

/// Terminal-proof obligation state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObligationState {
    /// Terminal predicate has not yet been proved.
    Pending,
    /// Terminal predicate is proved.
    Verified,
    /// A known terminal failure is proved.
    Failed,
    /// An external outcome remains unresolved.
    Indeterminate,
    /// Cancellation completed before external commitment.
    Cancelled,
}

/// Durable obligation tied to one effect operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Obligation {
    /// Obligation identity.
    pub obligation_id: ObligationId,
    /// Owning operation.
    pub operation_id: OperationId,
    /// Terminal predicate description.
    pub terminal_predicate: String,
    /// Current state.
    pub state: ObligationState,
    /// Proof digest, when terminal.
    pub proof_digest: Option<ContentDigest>,
}

/// Deterministic in-memory effect and obligation journal.
#[derive(Clone, Debug, Default)]
pub struct EffectJournal {
    operations: BTreeMap<OperationId, OperationReceipt>,
    idempotency: BTreeMap<IdempotencyKey, OperationId>,
    obligations: BTreeMap<ObligationId, Obligation>,
}

impl EffectJournal {
    /// Creates an empty journal.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            operations: BTreeMap::new(),
            idempotency: BTreeMap::new(),
            obligations: BTreeMap::new(),
        }
    }

    /// Prepares an effect exactly once and returns the existing receipt on an exact retry.
    pub fn prepare(
        &mut self,
        intent: EffectIntent,
        obligation_id: ObligationId,
        terminal_predicate: impl Into<String>,
        now: TimestampNs,
    ) -> Result<&OperationReceipt, ContractError> {
        if let Some(existing_id) = self.idempotency.get(&intent.idempotency_key) {
            let existing = self
                .operations
                .get(existing_id)
                .ok_or(ContractError::NotFound)?;
            if existing.intent == intent {
                return Ok(existing);
            }
            return Err(ContractError::IdempotencyConflict);
        }
        if self.operations.contains_key(&intent.operation_id) {
            return Err(ContractError::IdempotencyConflict);
        }
        if self.obligations.contains_key(&obligation_id) {
            return Err(ContractError::ObligationConflict);
        }
        let operation_id = intent.operation_id.clone();
        let idempotency_key = intent.idempotency_key.clone();
        self.operations.insert(
            operation_id.clone(),
            OperationReceipt {
                intent,
                state: EffectState::Prepared,
                prepared_at: now,
                committed_at: None,
                updated_at: now,
                result_digest: None,
                error_code: None,
            },
        );
        self.idempotency
            .insert(idempotency_key, operation_id.clone());
        self.obligations.insert(
            obligation_id.clone(),
            Obligation {
                obligation_id,
                operation_id: operation_id.clone(),
                terminal_predicate: terminal_predicate.into(),
                state: ObligationState::Pending,
                proof_digest: None,
            },
        );
        self.operations
            .get(&operation_id)
            .ok_or(ContractError::NotFound)
    }

    /// Advances an operation through a valid lifecycle transition.
    pub fn transition(
        &mut self,
        operation_id: &OperationId,
        next: EffectState,
        now: TimestampNs,
        result_digest: Option<ContentDigest>,
        error_code: Option<String>,
    ) -> Result<&OperationReceipt, ContractError> {
        {
            let receipt = self
                .operations
                .get_mut(operation_id)
                .ok_or(ContractError::NotFound)?;
            if now < receipt.updated_at {
                return Err(ContractError::InvertedTimeInterval);
            }
            if !valid_transition(receipt.state, next) {
                return Err(if receipt.state == EffectState::Indeterminate {
                    ContractError::ReconciliationRequired
                } else {
                    ContractError::InvalidEffectTransition
                });
            }
            if next == EffectState::Verified && result_digest.is_none() {
                return Err(ContractError::EvidenceRequired);
            }
            if next == EffectState::Failed
                && (result_digest.is_none() || error_code.as_deref().is_none_or(str::is_empty))
            {
                return Err(ContractError::EvidenceRequired);
            }
            if next == EffectState::Committed && receipt.committed_at.is_none() {
                receipt.committed_at = Some(now);
            }
            receipt.state = next;
            receipt.updated_at = now;
            if result_digest.is_some() {
                receipt.result_digest = result_digest;
            }
            if error_code.is_some() {
                receipt.error_code = error_code;
            }
        }
        let obligation_state = match next {
            EffectState::Verified => Some(ObligationState::Verified),
            EffectState::Cancelled => Some(ObligationState::Cancelled),
            EffectState::Failed => Some(ObligationState::Failed),
            EffectState::Indeterminate => Some(ObligationState::Indeterminate),
            _ => None,
        };
        if let Some(state) = obligation_state {
            for obligation in self
                .obligations
                .values_mut()
                .filter(|obligation| obligation.operation_id == *operation_id)
            {
                obligation.state = state;
                if matches!(state, ObligationState::Verified | ObligationState::Failed) {
                    obligation.proof_digest = result_digest;
                }
            }
        }
        self.operations
            .get(operation_id)
            .ok_or(ContractError::NotFound)
    }

    /// Marks an operation indeterminate after dispatch without a trustworthy terminal result.
    pub fn mark_indeterminate(
        &mut self,
        operation_id: &OperationId,
        now: TimestampNs,
        reason: impl Into<String>,
    ) -> Result<&OperationReceipt, ContractError> {
        let reason = reason.into();
        if reason.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        self.transition(
            operation_id,
            EffectState::Indeterminate,
            now,
            None,
            Some(reason),
        )
    }

    /// Reconciles an indeterminate operation using independently observed terminal proof.
    pub fn reconcile_verified(
        &mut self,
        operation_id: &OperationId,
        proof_digest: ContentDigest,
        now: TimestampNs,
    ) -> Result<&OperationReceipt, ContractError> {
        {
            let current = self
                .operations
                .get(operation_id)
                .ok_or(ContractError::NotFound)?;
            if now < current.updated_at {
                return Err(ContractError::InvertedTimeInterval);
            }
            if current.state != EffectState::Indeterminate && current.state != EffectState::Observed
            {
                return Err(ContractError::InvalidEffectTransition);
            }
        }
        let receipt = self
            .operations
            .get_mut(operation_id)
            .ok_or(ContractError::NotFound)?;
        receipt.state = EffectState::Verified;
        receipt.updated_at = now;
        receipt.result_digest = Some(proof_digest);
        receipt.error_code = None;
        for obligation in self
            .obligations
            .values_mut()
            .filter(|obligation| obligation.operation_id == *operation_id)
        {
            obligation.state = ObligationState::Verified;
            obligation.proof_digest = Some(proof_digest);
        }
        self.operations
            .get(operation_id)
            .ok_or(ContractError::NotFound)
    }

    /// Returns one operation receipt.
    #[must_use]
    pub fn operation(&self, operation_id: &OperationId) -> Option<&OperationReceipt> {
        self.operations.get(operation_id)
    }

    /// Returns all obligations in canonical identity order.
    #[must_use]
    pub fn obligations(&self) -> impl Iterator<Item = &Obligation> {
        self.obligations.values()
    }

    /// Computes a canonical journal root.
    #[must_use]
    pub fn journal_root(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.effect_journal.v1");
        encoder.u64(self.operations.len() as u64);
        for receipt in self.operations.values() {
            receipt.encode_canonical(&mut encoder);
        }
        encoder.u64(self.obligations.len() as u64);
        for obligation in self.obligations.values() {
            obligation.obligation_id.encode_canonical(&mut encoder);
            obligation.operation_id.encode_canonical(&mut encoder);
            encoder.text(&obligation.terminal_predicate);
            encoder.u8(match obligation.state {
                ObligationState::Pending => 1,
                ObligationState::Verified => 2,
                ObligationState::Failed => 3,
                ObligationState::Indeterminate => 4,
                ObligationState::Cancelled => 5,
            });
            match obligation.proof_digest {
                Some(value) => {
                    encoder.bool(true);
                    encoder.digest(value);
                }
                None => encoder.bool(false),
            }
        }
        ContentDigest::sha256(&encoder.finish())
    }
}

fn valid_transition(current: EffectState, next: EffectState) -> bool {
    matches!(
        (current, next),
        (EffectState::Prepared, EffectState::Committed)
            | (EffectState::Prepared, EffectState::Cancelled)
            | (EffectState::Prepared, EffectState::Failed)
            | (EffectState::Committed, EffectState::AdapterAccepted)
            | (EffectState::Committed, EffectState::Indeterminate)
            | (EffectState::Committed, EffectState::Failed)
            | (EffectState::AdapterAccepted, EffectState::Observed)
            | (EffectState::AdapterAccepted, EffectState::Indeterminate)
            | (EffectState::AdapterAccepted, EffectState::Failed)
            | (EffectState::Observed, EffectState::Verified)
            | (EffectState::Observed, EffectState::Indeterminate)
            | (EffectState::Observed, EffectState::Failed)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent(request: &[u8]) -> Result<EffectIntent, ContractError> {
        Ok(EffectIntent {
            operation_id: OperationId::parse("operation:alert:one")?,
            idempotency_key: IdempotencyKey::parse("idem:alert:one")?,
            effect_class: "alert.dispatch".to_owned(),
            request_digest: ContentDigest::sha256(request),
            precondition_digest: ContentDigest::sha256(b"event-corroborated"),
        })
    }

    #[test]
    fn exact_retry_is_idempotent_and_conflicting_retry_fails() -> Result<(), ContractError> {
        let mut journal = EffectJournal::new();
        let first = intent(b"same")?;
        let _ = journal.prepare(
            first.clone(),
            ObligationId::parse("obligation:one")?,
            "provider delivery is independently observed",
            TimestampNs(1),
        )?;
        let _ = journal.prepare(
            first,
            ObligationId::parse("obligation:unused")?,
            "unused",
            TimestampNs(2),
        )?;
        assert_eq!(
            journal.prepare(
                intent(b"different")?,
                ObligationId::parse("obligation:two")?,
                "different",
                TimestampNs(3),
            ),
            Err(ContractError::IdempotencyConflict)
        );
        Ok(())
    }

    #[test]
    fn lost_ack_requires_reconciliation() -> Result<(), ContractError> {
        let mut journal = EffectJournal::new();
        let effect = intent(b"alert")?;
        let operation_id = effect.operation_id.clone();
        let _ = journal.prepare(
            effect,
            ObligationId::parse("obligation:one")?,
            "delivery proved",
            TimestampNs(1),
        )?;
        let _ = journal.transition(
            &operation_id,
            EffectState::Committed,
            TimestampNs(2),
            None,
            None,
        )?;
        let _ = journal.mark_indeterminate(&operation_id, TimestampNs(3), "lost_ack")?;
        assert_eq!(
            journal.transition(
                &operation_id,
                EffectState::Committed,
                TimestampNs(4),
                None,
                None,
            ),
            Err(ContractError::ReconciliationRequired)
        );
        let _ = journal.reconcile_verified(
            &operation_id,
            ContentDigest::sha256(b"provider-delivery"),
            TimestampNs(5),
        )?;
        assert_eq!(
            journal
                .operation(&operation_id)
                .map(|receipt| receipt.state),
            Some(EffectState::Verified)
        );
        Ok(())
    }

    #[test]
    fn backward_transition_is_rejected_without_mutation() -> Result<(), ContractError> {
        let mut journal = EffectJournal::new();
        let effect = intent(b"ordered")?;
        let operation_id = effect.operation_id.clone();
        let _ = journal.prepare(
            effect,
            ObligationId::parse("obligation:one")?,
            "delivery proved",
            TimestampNs(10),
        )?;
        let before = journal
            .operation(&operation_id)
            .ok_or(ContractError::NotFound)?
            .clone();
        assert_eq!(
            journal.transition(
                &operation_id,
                EffectState::Committed,
                TimestampNs(9),
                None,
                None,
            ),
            Err(ContractError::InvertedTimeInterval)
        );
        assert_eq!(journal.operation(&operation_id), Some(&before));
        Ok(())
    }

    #[test]
    fn failed_outcome_requires_terminal_proof() -> Result<(), ContractError> {
        let mut journal = EffectJournal::new();
        let effect = intent(b"failed")?;
        let operation_id = effect.operation_id.clone();
        let obligation_id = ObligationId::parse("obligation:one")?;
        let _ = journal.prepare(
            effect,
            obligation_id.clone(),
            "known non-delivery proved",
            TimestampNs(1),
        )?;
        let _ = journal.transition(
            &operation_id,
            EffectState::Committed,
            TimestampNs(2),
            None,
            None,
        )?;
        assert_eq!(
            journal.transition(
                &operation_id,
                EffectState::Failed,
                TimestampNs(3),
                None,
                Some("provider_failed_before_delivery".to_owned()),
            ),
            Err(ContractError::EvidenceRequired)
        );

        let proof = ContentDigest::sha256(b"provider-known-failure");
        let receipt = journal.transition(
            &operation_id,
            EffectState::Failed,
            TimestampNs(3),
            Some(proof),
            Some("provider_failed_before_delivery".to_owned()),
        )?;
        assert_eq!(receipt.result_digest, Some(proof));
        let obligation = journal
            .obligations()
            .find(|item| item.obligation_id == obligation_id)
            .ok_or(ContractError::NotFound)?;
        assert_eq!(obligation.state, ObligationState::Failed);
        assert_eq!(obligation.proof_digest, Some(proof));
        Ok(())
    }

    #[test]
    fn backward_reconciliation_is_rejected_without_mutation() -> Result<(), ContractError> {
        let mut journal = EffectJournal::new();
        let effect = intent(b"reconcile-order")?;
        let operation_id = effect.operation_id.clone();
        let _ = journal.prepare(
            effect,
            ObligationId::parse("obligation:one")?,
            "delivery proved",
            TimestampNs(1),
        )?;
        let _ = journal.transition(
            &operation_id,
            EffectState::Committed,
            TimestampNs(2),
            None,
            None,
        )?;
        let _ = journal.mark_indeterminate(&operation_id, TimestampNs(4), "lost_ack")?;
        let before = journal
            .operation(&operation_id)
            .ok_or(ContractError::NotFound)?
            .clone();
        assert_eq!(
            journal.reconcile_verified(
                &operation_id,
                ContentDigest::sha256(b"provider-delivery"),
                TimestampNs(3),
            ),
            Err(ContractError::InvertedTimeInterval)
        );
        assert_eq!(journal.operation(&operation_id), Some(&before));
        Ok(())
    }
}
