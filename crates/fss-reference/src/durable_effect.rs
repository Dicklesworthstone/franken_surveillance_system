#![forbid(unsafe_code)]
//! Durable effect and obligation journal backed by the crash-safe reference ledger.
//!
//! Reconstructs exact in-memory `EffectJournal` state across process restarts and ensures
//! every prepare, transition, and reconciliation is durably committed before taking effect.

use std::error::Error;
use std::fmt;
use std::path::Path;

use fss_core::{
    CanonicalDecode, CanonicalEncode, ContentDigest, ContractError, EffectIntent, EffectJournal,
    EffectJournalTransition, EffectState, Obligation, ObligationId, OperationId, OperationReceipt,
    TimestampNs,
};
use fss_ledger::{
    ExternalMutationKind, IncompleteTailPolicy, Journal, JournalError, RecoveryReport, inspect,
};

use crate::alert::{
    ProviderDispatch, ReferenceAlertPlan, ReferenceAlertProvider, ReferenceProviderBehavior,
};
use crate::error::ReferenceError;

/// Dedicated journal record kind for canonical effect journal transitions.
pub const EFFECT_TRANSITION_RECORD_KIND: u16 = 2;

/// Errors raised by the durable effect journal.
#[derive(Debug)]
pub enum DurableEffectError {
    /// Underlying journal I/O, tail error, or corruption.
    Journal(JournalError),
    /// Violation of effect or obligation contract semantics.
    Contract(ContractError),
    /// Reference alert or perception error.
    Reference(ReferenceError),
    /// A journal record had an unsupported record kind.
    UnexpectedRecordKind {
        /// Sequence carrying the unsupported record kind.
        sequence: u64,
        /// Unsupported record kind.
        kind: u16,
    },
    /// Canonical decode failure while replaying a transition record.
    Decode {
        /// Sequence of the malformed record.
        sequence: u64,
        /// Underlying contract decode error.
        error: ContractError,
    },
}

impl fmt::Display for DurableEffectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(error) => write!(formatter, "durable effect journal error: {error}"),
            Self::Contract(error) => write!(formatter, "durable effect contract error: {error}"),
            Self::Reference(error) => write!(formatter, "durable effect reference error: {error}"),
            Self::UnexpectedRecordKind { sequence, kind } => write!(
                formatter,
                "durable effect record {sequence} has unsupported kind {kind}"
            ),
            Self::Decode { sequence, error } => write!(
                formatter,
                "durable effect record {sequence} failed canonical decode: {error}"
            ),
        }
    }
}

impl Error for DurableEffectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Journal(error) => Some(error),
            Self::Contract(error) => Some(error),
            Self::Reference(error) => Some(error),
            Self::UnexpectedRecordKind { .. } => None,
            Self::Decode { error, .. } => Some(error),
        }
    }
}

impl From<JournalError> for DurableEffectError {
    fn from(value: JournalError) -> Self {
        Self::Journal(value)
    }
}

impl From<ContractError> for DurableEffectError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}

impl From<ReferenceError> for DurableEffectError {
    fn from(value: ReferenceError) -> Self {
        Self::Reference(value)
    }
}

/// Durable crash-safe wrapper around [`EffectJournal`].
///
/// Every state change is serialized via [`EffectJournalTransition`] and appended to an
/// underlying [`Journal`] before being installed in memory.
#[derive(Debug)]
pub struct DurableEffectJournal {
    journal: Journal,
    memory: EffectJournal,
}

impl DurableEffectJournal {
    /// Opens, verifies, and replays the durable effect history.
    ///
    /// When tail truncation is requested, all complete prior records are replayed first.
    /// A torn or corrupt prefix fails validation before mutation.
    pub fn open(
        path: impl AsRef<Path>,
        tail_policy: IncompleteTailPolicy,
    ) -> Result<Self, DurableEffectError> {
        let path = path.as_ref().to_path_buf();

        let preflight = if path.exists() {
            let report = inspect(&path)?;
            let _ = replay_report(&report)?;
            Some(report)
        } else {
            None
        };

        let journal = Journal::open(&path, tail_policy)?;
        let report = inspect(journal.path())?;

        if let Some(preflight) = preflight
            && (report.last_root() != preflight.last_root()
                || report.committed_len() != preflight.committed_len())
        {
            let kind = if report.committed_len() != preflight.committed_len() {
                ExternalMutationKind::LengthDivergence
            } else {
                ExternalMutationKind::ContentDivergence
            };
            return Err(JournalError::ExternalMutation {
                expected_len: preflight.committed_len(),
                observed_len: report.committed_len(),
                kind,
            }
            .into());
        }

        let memory = replay_report(&report)?;
        Ok(Self { journal, memory })
    }

    /// Path backing this journal.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.journal.path()
    }

    /// Root digest of the latest committed journal record.
    #[must_use]
    pub fn last_root(&self) -> ContentDigest {
        self.journal.last_root()
    }

    /// Reconciled byte length of the committed journal prefix.
    #[must_use]
    pub const fn committed_len(&self) -> u64 {
        self.journal.committed_len()
    }

    /// Borrow the replayed in-memory effect journal.
    #[must_use]
    pub const fn effect_journal(&self) -> &EffectJournal {
        &self.memory
    }

    /// Returns one operation receipt if present.
    #[must_use]
    pub fn operation(&self, operation_id: &OperationId) -> Option<&OperationReceipt> {
        self.memory.operation(operation_id)
    }

    /// Returns all operation receipts in canonical identity order.
    pub fn operations(&self) -> impl Iterator<Item = &OperationReceipt> {
        self.memory.operations()
    }

    /// Returns all obligations in canonical identity order.
    pub fn obligations(&self) -> impl Iterator<Item = &Obligation> {
        self.memory.obligations()
    }

    /// Prepares an effect intent durably. Exact retries return existing receipt.
    pub fn prepare(
        &mut self,
        intent: EffectIntent,
        obligation_id: ObligationId,
        terminal_predicate: impl Into<String>,
        now: TimestampNs,
    ) -> Result<&OperationReceipt, DurableEffectError> {
        let mut candidate = self.memory.clone();
        let terminal_predicate_str = terminal_predicate.into();
        let op_id = intent.operation_id.clone();
        let _ = candidate.prepare(
            intent.clone(),
            obligation_id.clone(),
            terminal_predicate_str.clone(),
            now,
        )?;

        if candidate != self.memory {
            let transition = EffectJournalTransition::Prepare {
                intent,
                obligation_id,
                terminal_predicate: terminal_predicate_str,
                now,
            };
            let bytes = transition.try_canonical_bytes()?;
            self.journal.append(EFFECT_TRANSITION_RECORD_KIND, &bytes)?;
            self.memory = candidate;
        }

        self.memory
            .operation(&op_id)
            .ok_or_else(|| ContractError::NotFound.into())
    }

    /// Transitions an operation state durably.
    pub fn transition(
        &mut self,
        operation_id: &OperationId,
        next: EffectState,
        now: TimestampNs,
        result_digest: Option<ContentDigest>,
        error_code: Option<String>,
    ) -> Result<&OperationReceipt, DurableEffectError> {
        let mut candidate = self.memory.clone();
        let _ = candidate.transition(operation_id, next, now, result_digest, error_code.clone())?;

        if candidate != self.memory {
            let transition = EffectJournalTransition::Transition {
                operation_id: operation_id.clone(),
                next,
                now,
                result_digest,
                error_code,
            };
            let bytes = transition.try_canonical_bytes()?;
            self.journal.append(EFFECT_TRANSITION_RECORD_KIND, &bytes)?;
            self.memory = candidate;
        }

        self.memory
            .operation(operation_id)
            .ok_or_else(|| ContractError::NotFound.into())
    }

    /// Marks an operation indeterminate after dispatch without a trustworthy terminal result.
    pub fn mark_indeterminate(
        &mut self,
        operation_id: &OperationId,
        now: TimestampNs,
        reason: impl Into<String>,
    ) -> Result<&OperationReceipt, DurableEffectError> {
        let reason_str = reason.into();
        if reason_str.is_empty() {
            return Err(ContractError::EvidenceRequired.into());
        }
        self.transition(
            operation_id,
            EffectState::Indeterminate,
            now,
            None,
            Some(reason_str),
        )
    }

    /// Reconciles an observed operation to verified using independently observed terminal proof.
    pub fn reconcile_verified(
        &mut self,
        operation_id: &OperationId,
        proof_digest: ContentDigest,
        now: TimestampNs,
    ) -> Result<&OperationReceipt, DurableEffectError> {
        let mut candidate = self.memory.clone();
        let _ = candidate.reconcile_verified(operation_id, proof_digest, now)?;

        if candidate != self.memory {
            let transition = EffectJournalTransition::ReconcileVerified {
                operation_id: operation_id.clone(),
                proof_digest,
                now,
            };
            let bytes = transition.try_canonical_bytes()?;
            self.journal.append(EFFECT_TRANSITION_RECORD_KIND, &bytes)?;
            self.memory = candidate;
        }

        self.memory
            .operation(operation_id)
            .ok_or_else(|| ContractError::NotFound.into())
    }

    /// Reconciles an indeterminate operation to terminal failure using proof.
    pub fn reconcile_failed(
        &mut self,
        operation_id: &OperationId,
        proof_digest: ContentDigest,
        now: TimestampNs,
        reason: impl Into<String>,
    ) -> Result<&OperationReceipt, DurableEffectError> {
        let reason_str = reason.into();
        let mut candidate = self.memory.clone();
        let _ = candidate.reconcile_failed(operation_id, proof_digest, now, reason_str.clone())?;

        if candidate != self.memory {
            let transition = EffectJournalTransition::ReconcileFailed {
                operation_id: operation_id.clone(),
                proof_digest,
                now,
                reason: reason_str,
            };
            let bytes = transition.try_canonical_bytes()?;
            self.journal.append(EFFECT_TRANSITION_RECORD_KIND, &bytes)?;
            self.memory = candidate;
        }

        self.memory
            .operation(operation_id)
            .ok_or_else(|| ContractError::NotFound.into())
    }

    /// Dispatches a reference alert durably, guaranteeing commitment is journaled before provider dispatch.
    pub fn dispatch_alert(
        &mut self,
        plan: &ReferenceAlertPlan,
        behavior: ReferenceProviderBehavior,
        committed_at: TimestampNs,
        outcome_at: TimestampNs,
        provider: &mut ReferenceAlertProvider,
    ) -> Result<OperationReceipt, DurableEffectError> {
        crate::alert::validate_reference_alert_plan(plan)?;
        // Step 1: Durably commit first. Refuses blind retry if already Indeterminate!
        self.transition(
            &plan.intent.operation_id,
            EffectState::Committed,
            committed_at,
            None,
            None,
        )?;

        // Step 2: Provider interaction only after durable commitment:
        match provider.dispatch(&plan.intent, behavior) {
            ProviderDispatch::Delivered(_proof) => {
                let receipt = self.transition(
                    &plan.intent.operation_id,
                    EffectState::AdapterAccepted,
                    outcome_at,
                    None,
                    None,
                )?;
                Ok(receipt.clone())
            }
            ProviderDispatch::LostAck => {
                let receipt = self.mark_indeterminate(
                    &plan.intent.operation_id,
                    outcome_at,
                    "provider_ack_lost",
                )?;
                Ok(receipt.clone())
            }
            ProviderDispatch::KnownFailure(proof) => {
                let receipt = self.transition(
                    &plan.intent.operation_id,
                    EffectState::Failed,
                    outcome_at,
                    Some(proof),
                    Some(crate::alert::REFERENCE_ALERT_FAILURE_REASON.to_owned()),
                )?;
                Ok(receipt.clone())
            }
            ProviderDispatch::ConflictingIdempotency => {
                Err(ContractError::IdempotencyConflict.into())
            }
        }
    }

    /// Observes a delivered alert with provider observation receipt.
    pub fn observe_alert(
        &mut self,
        plan: &ReferenceAlertPlan,
        observation_proof: ContentDigest,
        observed_at: TimestampNs,
        provider: &ReferenceAlertProvider,
    ) -> Result<OperationReceipt, DurableEffectError> {
        crate::alert::validate_reference_alert_plan(plan)?;
        let Some(provider_receipt) = provider.lookup(&plan.intent)? else {
            return Err(ReferenceError::InvalidSpec("provider_proof_missing").into());
        };
        if observation_proof != provider_receipt.receipt_digest() {
            return Err(ContractError::InvalidDigest.into());
        }
        let receipt = self.transition(
            &plan.intent.operation_id,
            EffectState::Observed,
            observed_at,
            Some(observation_proof),
            None,
        )?;
        Ok(receipt.clone())
    }

    /// Verifies an observed alert using provider proof.
    pub fn verify_alert(
        &mut self,
        plan: &ReferenceAlertPlan,
        verified_at: TimestampNs,
        provider: &ReferenceAlertProvider,
    ) -> Result<OperationReceipt, DurableEffectError> {
        crate::alert::validate_reference_alert_plan(plan)?;
        let Some(provider_receipt) = provider.lookup(&plan.intent)? else {
            return Err(ReferenceError::InvalidSpec("provider_proof_missing").into());
        };
        let receipt = self.reconcile_verified(
            &plan.intent.operation_id,
            provider_receipt.receipt_digest(),
            verified_at,
        )?;
        Ok(receipt.clone())
    }

    /// Reconciles an indeterminate reference alert durably using provider observation receipt.
    pub fn reconcile_alert(
        &mut self,
        plan: &ReferenceAlertPlan,
        now: TimestampNs,
        provider: &ReferenceAlertProvider,
    ) -> Result<Option<OperationReceipt>, DurableEffectError> {
        crate::alert::validate_reference_alert_plan(plan)?;
        let Some(provider_receipt) = provider.lookup(&plan.intent)? else {
            return Ok(None);
        };
        let op = &plan.intent.operation_id;
        let current_state = self
            .operation(op)
            .map(|r| r.state)
            .ok_or(ContractError::NotFound)?;

        match current_state {
            EffectState::Verified => {
                let receipt =
                    self.reconcile_verified(op, provider_receipt.receipt_digest(), now)?;
                Ok(Some(receipt.clone()))
            }
            EffectState::Observed => {
                let receipt =
                    self.reconcile_verified(op, provider_receipt.receipt_digest(), now)?;
                Ok(Some(receipt.clone()))
            }
            EffectState::Indeterminate => {
                let obs_time = now;
                let ver_time = TimestampNs(now.0.saturating_add(1));
                self.transition(
                    op,
                    EffectState::Observed,
                    obs_time,
                    Some(provider_receipt.receipt_digest()),
                    None,
                )?;
                let receipt =
                    self.reconcile_verified(op, provider_receipt.receipt_digest(), ver_time)?;
                Ok(Some(receipt.clone()))
            }
            _ => Err(ContractError::InvalidEffectTransition.into()),
        }
    }

    /// Reconciles a failed reference alert durably.
    pub fn reconcile_failed_alert(
        &mut self,
        plan: &ReferenceAlertPlan,
        proof_digest: ContentDigest,
        reason: impl Into<String>,
        now: TimestampNs,
        provider: &ReferenceAlertProvider,
    ) -> Result<OperationReceipt, DurableEffectError> {
        crate::alert::validate_reference_alert_plan(plan)?;
        if provider.lookup(&plan.intent)?.is_some() {
            return Err(ContractError::InvalidEffectTransition.into());
        }
        let reason_str = reason.into();
        let receipt =
            self.reconcile_failed(&plan.intent.operation_id, proof_digest, now, reason_str)?;
        Ok(receipt.clone())
    }
}

fn replay_report(report: &RecoveryReport) -> Result<EffectJournal, DurableEffectError> {
    let mut transitions = Vec::with_capacity(report.records().len());
    for record in report.records() {
        if record.kind() != EFFECT_TRANSITION_RECORD_KIND {
            return Err(DurableEffectError::UnexpectedRecordKind {
                sequence: record.sequence(),
                kind: record.kind(),
            });
        }
        let transition =
            EffectJournalTransition::from_canonical_bytes(record.payload()).map_err(|error| {
                DurableEffectError::Decode {
                    sequence: record.sequence(),
                    error,
                }
            })?;
        transitions.push(transition);
    }
    let journal = EffectJournal::replay(transitions)?;
    Ok(journal)
}
