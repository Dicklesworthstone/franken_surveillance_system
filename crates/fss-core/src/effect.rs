//! Idempotent effect preparation, terminal-proof obligations, and reconciliation.

use std::collections::BTreeMap;

use crate::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, IdempotencyKey, ObligationId, OperationId, TimestampNs,
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

    /// Returns true if this state can legally transition to the target state.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Prepared, Self::Committed)
                | (Self::Prepared, Self::Cancelled)
                | (Self::Prepared, Self::Failed)
                | (Self::Committed, Self::AdapterAccepted)
                | (Self::Committed, Self::Indeterminate)
                | (Self::Committed, Self::Failed)
                | (Self::AdapterAccepted, Self::Observed)
                | (Self::AdapterAccepted, Self::Indeterminate)
                | (Self::AdapterAccepted, Self::Failed)
                | (Self::Observed, Self::Verified)
                | (Self::Observed, Self::Indeterminate)
                | (Self::Indeterminate, Self::Observed)
        )
    }
}

impl CanonicalEncode for EffectState {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

impl CanonicalDecode for EffectState {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let text = decoder.text()?;
        match text {
            "prepared" => Ok(Self::Prepared),
            "committed" => Ok(Self::Committed),
            "adapter_accepted" => Ok(Self::AdapterAccepted),
            "observed" => Ok(Self::Observed),
            "verified" => Ok(Self::Verified),
            "cancelled" => Ok(Self::Cancelled),
            "failed" => Ok(Self::Failed),
            "indeterminate" => Ok(Self::Indeterminate),
            _ => Err(ContractError::InvalidIdentifier),
        }
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

impl CanonicalDecode for EffectIntent {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let operation_id = OperationId::decode_canonical(decoder)?;
        let idempotency_key = IdempotencyKey::decode_canonical(decoder)?;
        let effect_class = decoder.text()?.to_string();
        let request_digest = decoder.digest()?;
        let precondition_digest = decoder.digest()?;
        Ok(Self {
            operation_id,
            idempotency_key,
            effect_class,
            request_digest,
            precondition_digest,
        })
    }
}

impl EffectIntent {
    /// Computes the unique canonical terminal proof digest binding full intent and terminal predicate.
    #[must_use]
    pub fn terminal_proof(&self, terminal_predicate: &str) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.effect_proof.v1");
        self.operation_id.encode_canonical(&mut encoder);
        self.idempotency_key.encode_canonical(&mut encoder);
        encoder.text(&self.effect_class);
        encoder.digest(self.request_digest);
        encoder.digest(self.precondition_digest);
        encoder.text(terminal_predicate);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Computes the unique canonical failure proof digest binding full intent and failure error code.
    #[must_use]
    pub fn failure_proof(&self, error_code: &str) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.effect_proof.v1");
        self.operation_id.encode_canonical(&mut encoder);
        self.idempotency_key.encode_canonical(&mut encoder);
        encoder.text(&self.effect_class);
        encoder.digest(self.request_digest);
        encoder.digest(self.precondition_digest);
        encoder.text(error_code);
        ContentDigest::sha256(&encoder.finish())
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

/// Canonical transition record for durable journal replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectJournalTransition {
    /// Effect preparation transition.
    Prepare {
        /// Prepared effect intent.
        intent: EffectIntent,
        /// Associated obligation id.
        obligation_id: ObligationId,
        /// Terminal predicate to be proven.
        terminal_predicate: String,
        /// Preparation timestamp.
        now: TimestampNs,
    },
    /// General effect state transition.
    Transition {
        /// Target operation id.
        operation_id: OperationId,
        /// Next effect state.
        next: EffectState,
        /// Transition timestamp.
        now: TimestampNs,
        /// Optional observation or proof digest.
        result_digest: Option<ContentDigest>,
        /// Optional error code or reason.
        error_code: Option<String>,
    },
    /// Verified reconciliation transition.
    ReconcileVerified {
        /// Target operation id.
        operation_id: OperationId,
        /// Independent proof digest.
        proof_digest: ContentDigest,
        /// Reconciliation timestamp.
        now: TimestampNs,
    },
    /// Failed reconciliation transition.
    ReconcileFailed {
        /// Target operation id.
        operation_id: OperationId,
        /// Independent failure proof digest.
        proof_digest: ContentDigest,
        /// Reconciliation timestamp.
        now: TimestampNs,
        /// Terminal failure reason.
        reason: String,
    },
}

impl CanonicalEncode for EffectJournalTransition {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text("fss.effect_transition.v1");
        match self {
            Self::Prepare {
                intent,
                obligation_id,
                terminal_predicate,
                now,
            } => {
                encoder.u8(1);
                intent.encode_canonical(encoder);
                obligation_id.encode_canonical(encoder);
                encoder.text(terminal_predicate);
                now.encode_canonical(encoder);
            }
            Self::Transition {
                operation_id,
                next,
                now,
                result_digest,
                error_code,
            } => {
                encoder.u8(2);
                operation_id.encode_canonical(encoder);
                next.encode_canonical(encoder);
                now.encode_canonical(encoder);
                match result_digest {
                    Some(digest) => {
                        encoder.bool(true);
                        encoder.digest(*digest);
                    }
                    None => encoder.bool(false),
                }
                match error_code {
                    Some(code) => {
                        encoder.bool(true);
                        encoder.text(code);
                    }
                    None => encoder.bool(false),
                }
            }
            Self::ReconcileVerified {
                operation_id,
                proof_digest,
                now,
            } => {
                encoder.u8(3);
                operation_id.encode_canonical(encoder);
                encoder.digest(*proof_digest);
                now.encode_canonical(encoder);
            }
            Self::ReconcileFailed {
                operation_id,
                proof_digest,
                now,
                reason,
            } => {
                encoder.u8(4);
                operation_id.encode_canonical(encoder);
                encoder.digest(*proof_digest);
                now.encode_canonical(encoder);
                encoder.text(reason);
            }
        }
    }
}

impl CanonicalDecode for EffectJournalTransition {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let magic = decoder.text()?;
        if magic != "fss.effect_transition.v1" {
            return Err(ContractError::InvalidIdentifier);
        }
        let tag = decoder.tag()?;
        match tag {
            1 => {
                let intent = EffectIntent::decode_canonical(decoder)?;
                let obligation_id = ObligationId::decode_canonical(decoder)?;
                let terminal_predicate = decoder.text()?.to_string();
                let now = TimestampNs::decode_canonical(decoder)?;
                Ok(Self::Prepare {
                    intent,
                    obligation_id,
                    terminal_predicate,
                    now,
                })
            }
            2 => {
                let operation_id = OperationId::decode_canonical(decoder)?;
                let next = EffectState::decode_canonical(decoder)?;
                let now = TimestampNs::decode_canonical(decoder)?;
                let result_digest = if decoder.bool()? {
                    Some(decoder.digest()?)
                } else {
                    None
                };
                let error_code = if decoder.bool()? {
                    Some(decoder.text()?.to_string())
                } else {
                    None
                };
                Ok(Self::Transition {
                    operation_id,
                    next,
                    now,
                    result_digest,
                    error_code,
                })
            }
            3 => {
                let operation_id = OperationId::decode_canonical(decoder)?;
                let proof_digest = decoder.digest()?;
                let now = TimestampNs::decode_canonical(decoder)?;
                Ok(Self::ReconcileVerified {
                    operation_id,
                    proof_digest,
                    now,
                })
            }
            4 => {
                let operation_id = OperationId::decode_canonical(decoder)?;
                let proof_digest = decoder.digest()?;
                let now = TimestampNs::decode_canonical(decoder)?;
                let reason = decoder.text()?.to_string();
                Ok(Self::ReconcileFailed {
                    operation_id,
                    proof_digest,
                    now,
                    reason,
                })
            }
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Deterministic in-memory effect and obligation journal.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
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
            if now <= receipt.updated_at {
                return Err(ContractError::InvertedTimeInterval);
            }
            if !valid_transition(receipt.state, next) {
                return Err(if receipt.state == EffectState::Indeterminate {
                    ContractError::ReconciliationRequired
                } else {
                    ContractError::InvalidEffectTransition
                });
            }
            if (next == EffectState::Observed
                || next == EffectState::Verified
                || next == EffectState::Cancelled)
                && result_digest.is_none()
            {
                return Err(ContractError::EvidenceRequired);
            }
            if next == EffectState::Verified {
                let obs_digest = receipt
                    .result_digest
                    .ok_or(ContractError::EvidenceRequired)?;
                if result_digest != Some(obs_digest) {
                    return Err(ContractError::InvalidDigest);
                }
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
                if matches!(
                    state,
                    ObligationState::Verified
                        | ObligationState::Failed
                        | ObligationState::Cancelled
                ) {
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

    /// Reconciles an observed operation using independently observed terminal proof.
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
            if current.state == EffectState::Verified {
                if current.result_digest == Some(proof_digest) {
                    return Ok(current);
                }
                return Err(ContractError::IdempotencyConflict);
            }
            if now <= current.updated_at {
                return Err(ContractError::InvertedTimeInterval);
            }
            if current.state != EffectState::Observed {
                return Err(ContractError::InvalidEffectTransition);
            }
            let obs_digest = current
                .result_digest
                .ok_or(ContractError::EvidenceRequired)?;
            if proof_digest != obs_digest {
                return Err(ContractError::InvalidDigest);
            }
        }
        let receipt = self
            .operations
            .get_mut(operation_id)
            .ok_or(ContractError::NotFound)?;
        receipt.state = EffectState::Verified;
        receipt.updated_at = now;
        receipt.result_digest = Some(proof_digest);
        // Reconciliation preserves indeterminate error_code in receipt history
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

    /// Reconciles an indeterminate operation to a terminal failure using proof.
    pub fn reconcile_failed(
        &mut self,
        operation_id: &OperationId,
        proof_digest: ContentDigest,
        now: TimestampNs,
        reason: impl Into<String>,
    ) -> Result<&OperationReceipt, ContractError> {
        let reason = reason.into();
        if reason.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        {
            let current = self
                .operations
                .get(operation_id)
                .ok_or(ContractError::NotFound)?;
            if current.state == EffectState::Failed {
                if current.result_digest == Some(proof_digest)
                    && current.error_code.as_deref() == Some(&reason)
                {
                    return Ok(current);
                }
                return Err(ContractError::IdempotencyConflict);
            }
            if now <= current.updated_at {
                return Err(ContractError::InvertedTimeInterval);
            }
            if current.state != EffectState::Indeterminate
                && current.state != EffectState::Committed
                && current.state != EffectState::AdapterAccepted
            {
                return Err(ContractError::InvalidEffectTransition);
            }
        }
        let receipt = self
            .operations
            .get_mut(operation_id)
            .ok_or(ContractError::NotFound)?;
        receipt.state = EffectState::Failed;
        receipt.updated_at = now;
        receipt.result_digest = Some(proof_digest);
        receipt.error_code = Some(reason);
        for obligation in self
            .obligations
            .values_mut()
            .filter(|obligation| obligation.operation_id == *operation_id)
        {
            obligation.state = ObligationState::Failed;
            obligation.proof_digest = Some(proof_digest);
        }
        self.operations
            .get(operation_id)
            .ok_or(ContractError::NotFound)
    }

    /// Pre-validates a prepare request without mutating the journal.
    /// Returns `Ok(Some(receipt))` if this is an idempotent retry of an existing identical prepare,
    /// or `Ok(None)` if it is a valid new prepare.
    pub fn validate_prepare(
        &self,
        intent: &EffectIntent,
        obligation_id: &ObligationId,
    ) -> Result<Option<&OperationReceipt>, ContractError> {
        if let Some(existing_id) = self.idempotency.get(&intent.idempotency_key) {
            let existing = self
                .operations
                .get(existing_id)
                .ok_or(ContractError::NotFound)?;
            if &existing.intent == intent {
                return Ok(Some(existing));
            }
            return Err(ContractError::IdempotencyConflict);
        }
        if self.operations.contains_key(&intent.operation_id) {
            return Err(ContractError::IdempotencyConflict);
        }
        if self.obligations.contains_key(obligation_id) {
            return Err(ContractError::ObligationConflict);
        }
        Ok(None)
    }

    /// Pre-validates a transition without mutating the journal.
    pub fn validate_transition(
        &self,
        operation_id: &OperationId,
        next: EffectState,
        now: TimestampNs,
        result_digest: Option<ContentDigest>,
        error_code: Option<&str>,
    ) -> Result<&OperationReceipt, ContractError> {
        let receipt = self
            .operations
            .get(operation_id)
            .ok_or(ContractError::NotFound)?;
        if now <= receipt.updated_at {
            return Err(ContractError::InvertedTimeInterval);
        }
        if !receipt.state.can_transition_to(next) {
            return Err(if receipt.state == EffectState::Indeterminate {
                ContractError::ReconciliationRequired
            } else {
                ContractError::InvalidEffectTransition
            });
        }
        if (next == EffectState::Observed
            || next == EffectState::Verified
            || next == EffectState::Cancelled)
            && result_digest.is_none()
        {
            return Err(ContractError::EvidenceRequired);
        }
        if next == EffectState::Verified {
            let obs_digest = receipt
                .result_digest
                .ok_or(ContractError::EvidenceRequired)?;
            if result_digest != Some(obs_digest) {
                return Err(ContractError::InvalidDigest);
            }
        }
        if next == EffectState::Failed
            && (result_digest.is_none() || error_code.is_none_or(str::is_empty))
        {
            return Err(ContractError::EvidenceRequired);
        }
        Ok(receipt)
    }

    /// Pre-validates reconcile_verified without mutating the journal.
    /// Returns `Ok(Some(receipt))` if this is an idempotent no-op (already Verified with matching proof),
    /// or `Ok(None)` if it is a valid transition from Observed to Verified.
    pub fn validate_reconcile_verified(
        &self,
        operation_id: &OperationId,
        proof_digest: ContentDigest,
        now: TimestampNs,
    ) -> Result<Option<&OperationReceipt>, ContractError> {
        let current = self
            .operations
            .get(operation_id)
            .ok_or(ContractError::NotFound)?;
        if current.state == EffectState::Verified {
            if current.result_digest == Some(proof_digest) {
                return Ok(Some(current));
            }
            return Err(ContractError::IdempotencyConflict);
        }
        if now <= current.updated_at {
            return Err(ContractError::InvertedTimeInterval);
        }
        if current.state != EffectState::Observed {
            return Err(ContractError::InvalidEffectTransition);
        }
        let obs_digest = current
            .result_digest
            .ok_or(ContractError::EvidenceRequired)?;
        if proof_digest != obs_digest {
            return Err(ContractError::InvalidDigest);
        }
        Ok(None)
    }

    /// Pre-validates reconcile_failed without mutating the journal.
    /// Returns `Ok(Some(receipt))` if this is an idempotent no-op (already Failed with matching proof/reason),
    /// or `Ok(None)` if it is a valid failure reconciliation.
    pub fn validate_reconcile_failed(
        &self,
        operation_id: &OperationId,
        proof_digest: ContentDigest,
        now: TimestampNs,
        reason: &str,
    ) -> Result<Option<&OperationReceipt>, ContractError> {
        let current = self
            .operations
            .get(operation_id)
            .ok_or(ContractError::NotFound)?;
        if current.state == EffectState::Failed {
            if current.result_digest == Some(proof_digest)
                && current.error_code.as_deref() == Some(reason)
            {
                return Ok(Some(current));
            }
            return Err(ContractError::IdempotencyConflict);
        }
        if now <= current.updated_at {
            return Err(ContractError::InvertedTimeInterval);
        }
        if current.state != EffectState::Indeterminate
            && current.state != EffectState::Committed
            && current.state != EffectState::AdapterAccepted
        {
            return Err(ContractError::InvalidEffectTransition);
        }
        Ok(None)
    }

    /// Returns one operation receipt.
    #[must_use]
    pub fn operation(&self, operation_id: &OperationId) -> Option<&OperationReceipt> {
        self.operations.get(operation_id)
    }

    /// Returns all obligations in canonical identity order.
    pub fn obligations(&self) -> impl Iterator<Item = &Obligation> {
        self.obligations.values()
    }

    /// Returns all operation receipts in canonical identity order.
    pub fn operations(&self) -> impl Iterator<Item = &OperationReceipt> {
        self.operations.values()
    }

    /// Replays a sequence of transitions from a durable log, reconstructing the exact in-memory state.
    pub fn replay(
        transitions: impl IntoIterator<Item = EffectJournalTransition>,
    ) -> Result<Self, ContractError> {
        let mut journal = Self::new();
        for transition in transitions {
            let _receipt = journal.apply_transition(transition)?;
        }
        Ok(journal)
    }

    /// Applies one transition to the journal, returning receipt or error on invariant failure.
    pub fn apply_transition(
        &mut self,
        transition: EffectJournalTransition,
    ) -> Result<&OperationReceipt, ContractError> {
        match transition {
            EffectJournalTransition::Prepare {
                intent,
                obligation_id,
                terminal_predicate,
                now,
            } => self.prepare(intent, obligation_id, terminal_predicate, now),
            EffectJournalTransition::Transition {
                operation_id,
                next,
                now,
                result_digest,
                error_code,
            } => self.transition(&operation_id, next, now, result_digest, error_code),
            EffectJournalTransition::ReconcileVerified {
                operation_id,
                proof_digest,
                now,
            } => self.reconcile_verified(&operation_id, proof_digest, now),
            EffectJournalTransition::ReconcileFailed {
                operation_id,
                proof_digest,
                now,
                reason,
            } => self.reconcile_failed(&operation_id, proof_digest, now, reason),
        }
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

pub const fn valid_transition(current: EffectState, next: EffectState) -> bool {
    current.can_transition_to(next)
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
            effect.clone(),
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
        let obs_proof = ContentDigest::sha256(b"delivery-observation");
        let _ = journal.transition(
            &operation_id,
            EffectState::Observed,
            TimestampNs(5),
            Some(obs_proof),
            None,
        )?;
        let _ = journal.reconcile_verified(&operation_id, obs_proof, TimestampNs(6))?;
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

    #[test]
    fn test_journal_transitions_codec_and_replay() -> Result<(), ContractError> {
        let mut live = EffectJournal::new();
        let effect = intent(b"replay-test")?;
        let op = effect.operation_id.clone();
        let obl = ObligationId::parse("obligation:replay:test")?;
        let t1 = TimestampNs(10);
        let t2 = TimestampNs(20);
        let t3 = TimestampNs(30);
        let t4 = TimestampNs(40);
        let t5 = TimestampNs(50);

        let tr1 = EffectJournalTransition::Prepare {
            intent: effect.clone(),
            obligation_id: obl.clone(),
            terminal_predicate: "delivery_proved".to_string(),
            now: t1,
        };
        let tr2 = EffectJournalTransition::Transition {
            operation_id: op.clone(),
            next: EffectState::Committed,
            now: t2,
            result_digest: None,
            error_code: None,
        };
        let tr3 = EffectJournalTransition::Transition {
            operation_id: op.clone(),
            next: EffectState::AdapterAccepted,
            now: t3,
            result_digest: None,
            error_code: None,
        };
        let obs_proof = ContentDigest::sha256(b"obs-proof");
        let tr4 = EffectJournalTransition::Transition {
            operation_id: op.clone(),
            next: EffectState::Observed,
            now: t4,
            result_digest: Some(obs_proof),
            error_code: None,
        };
        let tr5 = EffectJournalTransition::ReconcileVerified {
            operation_id: op.clone(),
            proof_digest: obs_proof,
            now: t5,
        };

        let transitions = vec![tr1, tr2, tr3, tr4, tr5];
        let mut decoded_transitions = Vec::new();
        for tr in &transitions {
            let bytes = tr.canonical_bytes();
            let decoded = EffectJournalTransition::from_canonical_bytes(&bytes)?;
            assert_eq!(&decoded, tr);
            decoded_transitions.push(decoded);
        }

        for tr in &transitions {
            live.apply_transition(tr.clone())?;
        }

        let replayed = EffectJournal::replay(decoded_transitions)?;
        assert_eq!(replayed, live);
        assert_eq!(replayed.journal_root(), live.journal_root());
        Ok(())
    }
}
