#![forbid(unsafe_code)]
//! Durable effect and obligation journal backed by the crash-safe reference ledger.
//!
//! Reconstructs exact in-memory `EffectJournal` state across process restarts and ensures
//! every prepare, transition, and reconciliation is durably committed before taking effect.

use std::error::Error;
use std::fmt;
use std::path::Path;

use fss_core::{
    BatchId, CanonicalDecode, CanonicalEncode, ContentDigest, ContractError, EffectIntent,
    EffectJournal, EffectJournalTransition, EffectState, LedgerAnchor, ObjectId, Obligation,
    ObligationId, OperationId, OperationReceipt, Plane, TimestampNs,
};
use fss_ledger::{
    DurableReferenceLedger, ExternalMutationKind, IncompleteTailPolicy, Journal, JournalError,
    RecoveryReport, inspect,
};
use fss_object::InMemoryObjectStore;

use crate::alert::{
    ProviderDispatch, ReferenceAlertPlan, ReferenceAlertProvider, ReferenceProviderBehavior,
};
use crate::error::ReferenceError;
use crate::outcome::{ALERT_OUTCOME_FAMILY, ReferenceAlertOutcomeReceipt};

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
    /// An obligation is transient and not persisted in the durable effect journal (INV-111).
    TransientObligation {
        /// Offending transient obligation identity.
        obligation_id: ObligationId,
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
            Self::TransientObligation { obligation_id } => write!(
                formatter,
                "obligation {obligation_id} is transient and not durably recorded (INV-111 violation)"
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
            Self::UnexpectedRecordKind { .. } | Self::TransientObligation { .. } => None,
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

/// An obligation that is recorded in the durable effect journal but whose outcome is not yet published to the canonical ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingLedgerObligation {
    /// The durable obligation recorded in the journal.
    pub obligation: Obligation,
    /// The operation receipt recorded in the journal.
    pub receipt: OperationReceipt,
}

/// An obligation whose outcome is durably recorded in the journal and published to the canonical ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgeredObligation {
    /// The durable obligation recorded in the journal.
    pub obligation: Obligation,
    /// The operation receipt recorded in the journal.
    pub receipt: OperationReceipt,
    /// Anchor of the batch that published the outcome.
    pub anchor: LedgerAnchor,
    /// Batch identity of that publication.
    pub batch_id: BatchId,
    /// Manifest root of the published outcome.
    pub outcome_root: ContentDigest,
}

/// Joint durable journal and canonical ledger classification of one obligation (INV-111).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObligationLedgerState {
    /// The obligation is not recorded in the durable journal and the ledger names none.
    Absent,
    /// The obligation is durably journaled, but its outcome has not been published to the canonical ledger.
    PendingLedger(PendingLedgerObligation),
    /// The obligation is durably journaled and its exact outcome is published in the canonical ledger.
    Ledgered(LedgeredObligation),
    /// The obligation is durably journaled, but the ledger publishes a different outcome or family for this operation.
    LedgerConflict {
        /// Obligation identity.
        obligation_id: ObligationId,
        /// Journal receipt digest.
        journal_receipt_digest: ContentDigest,
        /// Ledger witness digest.
        ledgered_witness_digest: Option<ContentDigest>,
        /// Family named by the ledger.
        ledgered_family: String,
    },
    /// The ledger contains an effect outcome for an operation that does not exist in the durable journal.
    UnbackedLedgerClaim {
        /// Operation identity from the ledger object.
        operation_id: OperationId,
        /// Manifest root payload in the ledger.
        ledgered_root: ContentDigest,
    },
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
            let preflight_journal = replay_report(&report)?;
            Some((report, preflight_journal.journal_root()))
        } else {
            None
        };

        let journal = Journal::open(&path, tail_policy)?;
        let report = inspect(journal.path())?;

        if let Some((preflight, _preflight_root)) = preflight
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

    /// Returns one obligation if present in the replayed journal.
    #[must_use]
    pub fn obligation(&self, obligation_id: &ObligationId) -> Option<&Obligation> {
        self.memory
            .obligations()
            .find(|candidate| &candidate.obligation_id == obligation_id)
    }

    /// Acknowledges an obligation, proving it is durably recorded in the journal (INV-111).
    ///
    /// Rejects any transient or unpersisted obligation with [`DurableEffectError::TransientObligation`].
    pub fn acknowledge_obligation(
        &self,
        obligation_id: &ObligationId,
    ) -> Result<&Obligation, DurableEffectError> {
        self.obligation(obligation_id)
            .ok_or_else(|| DurableEffectError::TransientObligation {
                obligation_id: obligation_id.clone(),
            })
    }

    /// Classifies an obligation against both the durable effect journal and the canonical reference ledger.
    ///
    /// Follows the `PendingLedger` pattern to distinguish between unledgered durable obligations,
    /// ledgered obligations, and conflicts.
    pub fn classify_obligation(
        &self,
        obligation_id: &ObligationId,
        ledger: &DurableReferenceLedger,
    ) -> Result<ObligationLedgerState, DurableEffectError> {
        let Some(obligation) = self.obligation(obligation_id) else {
            return Ok(ObligationLedgerState::Absent);
        };
        let receipt = self
            .operation(&obligation.operation_id)
            .ok_or(ContractError::NotFound)?;
        let effect_object_id = ObjectId::parse(format!(
            "object:effect:{}",
            obligation.operation_id.as_str()
        ))?;
        let Some(published) = ledger.current().objects.get(&effect_object_id) else {
            return Ok(ObligationLedgerState::PendingLedger(
                PendingLedgerObligation {
                    obligation: obligation.clone(),
                    receipt: receipt.clone(),
                },
            ));
        };
        if published.family != ALERT_OUTCOME_FAMILY || published.plane != Plane::Effect {
            return Ok(ObligationLedgerState::LedgerConflict {
                obligation_id: obligation_id.clone(),
                journal_receipt_digest: receipt.receipt_digest(),
                ledgered_witness_digest: None,
                ledgered_family: published.family.clone(),
            });
        }
        let matching_batch = ledger.batches().iter().rev().find(|batch| {
            batch
                .deltas
                .iter()
                .any(|delta| delta.object_id == effect_object_id)
        });
        let matching_delta = matching_batch.and_then(|batch| {
            batch
                .deltas
                .iter()
                .rev()
                .find(|delta| delta.object_id == effect_object_id)
        });
        let ledgered_witness = matching_delta.and_then(|d| d.witness_digest);
        if ledgered_witness == Some(receipt.receipt_digest())
            && published.payload_digest
                == matching_delta
                    .map(|d| d.payload_digest)
                    .unwrap_or(published.payload_digest)
        {
            let batch = matching_batch.ok_or(ContractError::NotFound)?;
            Ok(ObligationLedgerState::Ledgered(LedgeredObligation {
                obligation: obligation.clone(),
                receipt: receipt.clone(),
                anchor: batch.new_anchor.clone(),
                batch_id: batch.batch_id.clone(),
                outcome_root: published.payload_digest,
            }))
        } else {
            Ok(ObligationLedgerState::LedgerConflict {
                obligation_id: obligation_id.clone(),
                journal_receipt_digest: receipt.receipt_digest(),
                ledgered_witness_digest: ledgered_witness,
                ledgered_family: published.family.clone(),
            })
        }
    }

    /// Classifies an operation identity against both the durable effect journal and the canonical reference ledger.
    pub fn classify_operation(
        &self,
        operation_id: &OperationId,
        ledger: &DurableReferenceLedger,
    ) -> Result<ObligationLedgerState, DurableEffectError> {
        let effect_object_id = ObjectId::parse(format!("object:effect:{}", operation_id.as_str()))?;
        let Some(_receipt) = self.operation(operation_id) else {
            if let Some(published) = ledger.current().objects.get(&effect_object_id) {
                return Ok(ObligationLedgerState::UnbackedLedgerClaim {
                    operation_id: operation_id.clone(),
                    ledgered_root: published.payload_digest,
                });
            }
            return Ok(ObligationLedgerState::Absent);
        };
        let Some(obligation) = self.obligations().find(|o| o.operation_id == *operation_id) else {
            return Ok(ObligationLedgerState::Absent);
        };
        self.classify_obligation(&obligation.obligation_id, ledger)
    }

    /// Prepares an effect intent durably. Exact retries return existing receipt.
    pub fn prepare(
        &mut self,
        intent: EffectIntent,
        obligation_id: ObligationId,
        terminal_predicate: impl Into<String>,
        now: TimestampNs,
    ) -> Result<&OperationReceipt, DurableEffectError> {
        let terminal_predicate_str = terminal_predicate.into();
        if let Some(existing) = self.memory.validate_prepare(&intent, &obligation_id)? {
            return Ok(existing);
        }

        let transition = EffectJournalTransition::Prepare {
            intent: intent.clone(),
            obligation_id: obligation_id.clone(),
            terminal_predicate: terminal_predicate_str.clone(),
            now,
        };
        let bytes = transition.try_canonical_bytes()?;
        self.journal.append(EFFECT_TRANSITION_RECORD_KIND, &bytes)?;
        let receipt = self
            .memory
            .prepare(intent, obligation_id, terminal_predicate_str, now)?;
        Ok(receipt)
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
        let _validated = self.memory.validate_transition(
            operation_id,
            next,
            now,
            result_digest,
            error_code.as_deref(),
        )?;

        let transition = EffectJournalTransition::Transition {
            operation_id: operation_id.clone(),
            next,
            now,
            result_digest,
            error_code: error_code.clone(),
        };
        let bytes = transition.try_canonical_bytes()?;
        self.journal.append(EFFECT_TRANSITION_RECORD_KIND, &bytes)?;
        let receipt = self
            .memory
            .transition(operation_id, next, now, result_digest, error_code)?;
        Ok(receipt)
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
        if let Some(existing) =
            self.memory
                .validate_reconcile_verified(operation_id, proof_digest, now)?
        {
            return Ok(existing);
        }

        let transition = EffectJournalTransition::ReconcileVerified {
            operation_id: operation_id.clone(),
            proof_digest,
            now,
        };
        let bytes = transition.try_canonical_bytes()?;
        self.journal.append(EFFECT_TRANSITION_RECORD_KIND, &bytes)?;
        let receipt = self
            .memory
            .reconcile_verified(operation_id, proof_digest, now)?;
        Ok(receipt)
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
        if let Some(existing) =
            self.memory
                .validate_reconcile_failed(operation_id, proof_digest, now, &reason_str)?
        {
            return Ok(existing);
        }

        let transition = EffectJournalTransition::ReconcileFailed {
            operation_id: operation_id.clone(),
            proof_digest,
            now,
            reason: reason_str.clone(),
        };
        let bytes = transition.try_canonical_bytes()?;
        self.journal.append(EFFECT_TRANSITION_RECORD_KIND, &bytes)?;
        let receipt = self
            .memory
            .reconcile_failed(operation_id, proof_digest, now, reason_str)?;
        Ok(receipt)
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
        let current_state = self
            .operation(&plan.intent.operation_id)
            .map(|r| r.state)
            .ok_or(ContractError::NotFound)?;

        match current_state {
            EffectState::Prepared => {
                // Step 1: Durably commit first. Refuses blind retry if already Indeterminate!
                self.transition(
                    &plan.intent.operation_id,
                    EffectState::Committed,
                    committed_at,
                    None,
                    None,
                )?;
            }
            EffectState::Committed => {
                // Idempotent continuation after restart: commitment already journaled.
            }
            EffectState::Indeterminate => {
                // Indeterminate effects must be reconciled, not blindly retried!
                return Err(ContractError::ReconciliationRequired.into());
            }
            _ => return Err(ContractError::InvalidEffectTransition.into()),
        }

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
            EffectState::AdapterAccepted => {
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
            EffectState::Committed => {
                let acc_time = now;
                let obs_time = TimestampNs(now.0.saturating_add(1));
                let ver_time = TimestampNs(now.0.saturating_add(2));
                self.transition(op, EffectState::AdapterAccepted, acc_time, None, None)?;
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

    /// Reconciles a failed reference alert durably using provider failure receipt.
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
        let Some(failure_receipt) = provider.lookup_failure(&plan.intent)? else {
            return Err(ReferenceError::InvalidSpec("provider_failure_proof_missing").into());
        };
        if proof_digest != failure_receipt.receipt_digest() {
            return Err(ContractError::InvalidDigest.into());
        }
        let reason_str = reason.into();
        if reason_str != failure_receipt.error_code {
            return Err(ReferenceError::InvalidSpec("provider_failure_reason_mismatch").into());
        }
        let receipt =
            self.reconcile_failed(&plan.intent.operation_id, proof_digest, now, reason_str)?;
        Ok(receipt.clone())
    }

    /// Prepares a reference alert plan durably, appending the prepare transition to disk before returning (INV-111).
    pub fn prepare_alert(
        &mut self,
        params: crate::alert::PrepareAlertParams<'_>,
    ) -> Result<ReferenceAlertPlan, DurableEffectError> {
        let now = params.now;
        let mut validation_journal = EffectJournal::new();
        let plan = crate::alert::prepare_reference_alert(params, &mut validation_journal)?;
        self.prepare(
            plan.intent.clone(),
            plan.obligation_id.clone(),
            crate::alert::REFERENCE_ALERT_TERMINAL_PREDICATE,
            now,
        )?;
        Ok(plan)
    }

    /// Publishes an authoritative alert effect outcome to the canonical ledger only after acknowledging
    /// that the obligation is durably journaled (INV-111).
    pub fn publish_alert_outcome(
        &self,
        plan: &ReferenceAlertPlan,
        objects: &mut InMemoryObjectStore,
        ledger: &mut DurableReferenceLedger,
        provider: &ReferenceAlertProvider,
    ) -> Result<ReferenceAlertOutcomeReceipt, DurableEffectError> {
        self.acknowledge_obligation(&plan.obligation_id)?;
        let receipt = crate::outcome::publish_reference_alert_outcome(
            plan,
            &self.memory,
            objects,
            ledger,
            provider,
        )?;
        Ok(receipt)
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
