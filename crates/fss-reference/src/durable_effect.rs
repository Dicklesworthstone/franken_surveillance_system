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
    EffectJournal, EffectJournalTransition, EffectRecordVersion, EffectState, LedgerAnchor,
    ObjectId, Obligation, ObligationId, ObligationState, OperationId, OperationReceipt, Plane,
    TimestampNs,
};
use fss_ledger::{
    DurableLedgerLimits, DurableReferenceLedger, ExternalMutationKind, HostJournalReadIo,
    IncompleteTailPolicy, Journal, JournalError, JournalReadIo, JournalRecord, RecoveryReport,
    inspect,
};
use fss_object::InMemoryObjectStore;

use crate::alert::{ReferenceAlertPlan, ReferenceAlertProvider, ReferenceProviderBehavior};
use crate::error::ReferenceError;
use crate::outcome::{ALERT_OUTCOME_FAMILY, ReferenceAlertOutcomeReceipt};

/// Journal record kind of an effect transition written before fss-deir9
/// ([`EffectRecordVersion::V1`]).
///
/// Replay still reads it, under the legacy rules the record was written under, and the operation
/// it prepared keeps the v1 receipt encoding; the journal never writes it again (fss-deir9).
pub const EFFECT_TRANSITION_RECORD_KIND: u16 = 2;

/// Journal record kind of an effect transition written by fss-deir9 or later
/// ([`EffectRecordVersion::V2`]).
///
/// The payload is the same `fss.effect_transition.v1` encoding; the kind records which transition
/// rules and receipt encoding the record was written under, so replay verifies every witness
/// under its own version without migrating or rewriting any stored byte.
pub const EFFECT_TRANSITION_V2_RECORD_KIND: u16 = 3;

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
    /// Underlying filesystem or read I/O error.
    Io(std::io::Error),
    /// The journal path is a symlink or not a regular file.
    InvalidLayout {
        /// Offending path.
        path: std::path::PathBuf,
    },
    /// Journal file length exceeded configured byte limit.
    OverBudget {
        /// Configured limit in bytes.
        limit: usize,
        /// Observed actual length in bytes.
        actual: usize,
    },
    /// The journal doctor failed for a reason with no narrower variant here.
    Repair(Box<fss_ledger::RepairError>),
    /// An obligation is transient and not persisted in the durable effect journal (INV-111).
    TransientObligation {
        /// Offending transient obligation identity.
        obligation_id: ObligationId,
    },
    /// Canonical reference ledger has an uncommitted or pending append that requires reconciliation.
    LedgerReconciliationRequired {
        /// Sequence of the pending append.
        sequence: u64,
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
            Self::LedgerReconciliationRequired { sequence } => write!(
                formatter,
                "canonical ledger has uncommitted pending append at sequence {sequence} requiring reconciliation"
            ),
            Self::Io(error) => write!(formatter, "durable effect I/O error: {error}"),
            Self::InvalidLayout { path } => write!(
                formatter,
                "durable effect journal has invalid layout: {}",
                path.display()
            ),
            Self::OverBudget { limit, actual } => write!(
                formatter,
                "durable effect journal size {actual} exceeded limit {limit}"
            ),
            Self::Repair(error) => write!(formatter, "durable effect journal doctor: {error}"),
        }
    }
}

impl Error for DurableEffectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Journal(error) => Some(error),
            Self::Contract(error) => Some(error),
            Self::Reference(error) => Some(error),
            Self::UnexpectedRecordKind { .. }
            | Self::TransientObligation { .. }
            | Self::LedgerReconciliationRequired { .. }
            | Self::InvalidLayout { .. }
            | Self::OverBudget { .. } => None,
            Self::Decode { error, .. } => Some(error),
            Self::Io(error) => Some(error),
            Self::Repair(error) => Some(error),
        }
    }
}

impl From<std::io::Error> for DurableEffectError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// Status of a durable effect journal on disk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectJournalStatus {
    /// Journal file does not exist on disk.
    Absent,
    /// Journal file exists on disk.
    Present,
}

/// Breakdown of obligations by [`ObligationState`]; every state has its own count, so an
/// indeterminate obligation is never folded into pending or terminal.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObligationCounts {
    /// Total number of obligations recorded.
    pub total: usize,
    /// Terminal predicate not yet proved.
    pub pending: usize,
    /// Terminal predicate proved.
    pub verified: usize,
    /// A known terminal failure proved.
    pub failed: usize,
    /// Cancellation completed before external commitment.
    pub cancelled: usize,
    /// External outcome unresolved; each has a reconcile affordance.
    pub indeterminate: usize,
}

impl ObligationCounts {
    /// Obligations in a terminal state (verified, failed, or cancelled).
    #[must_use]
    pub const fn terminal(&self) -> usize {
        self.verified + self.failed + self.cancelled
    }
}

/// An indeterminate operation and its corresponding reconcile affordance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndeterminateOperationInfo {
    /// Identifier of the indeterminate operation.
    pub operation_id: OperationId,
    /// Canonical affordance for reconciling the operation.
    pub reconcile_affordance: String,
}

/// Non-mutating inspection of a durable effect journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectJournalInspection {
    /// Whether the journal was present or absent.
    pub status: EffectJournalStatus,
    /// Reconstructed in-memory effect journal if present.
    pub journal: Option<EffectJournal>,
    /// Obligation counts by state.
    pub obligation_counts: ObligationCounts,
    /// Operations in indeterminate state paired with reconcile affordances.
    pub indeterminate_operations: Vec<IndeterminateOperationInfo>,
    /// Offset of an incomplete journal tail, if present.
    pub incomplete_tail: Option<u64>,
    /// Range of foreign trailing bytes, if present.
    pub foreign_range: Option<fss_ledger::ForeignRange>,
}

impl EffectJournalInspection {
    /// True if the journal does not exist on disk.
    #[must_use]
    pub fn is_absent(&self) -> bool {
        self.status == EffectJournalStatus::Absent
    }

    /// True if the journal exists, has no incomplete tail, and has no foreign trailing bytes.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.status == EffectJournalStatus::Present
            && self.incomplete_tail.is_none()
            && self.foreign_range.is_none()
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
    /// A contract violation keeps its contract identity, and a durable transition failure surfaced
    /// through the shared alert helper is unwrapped back to the durable error that caused it, so a
    /// durable caller sees the same error shape whichever layer detected the failure.
    fn from(value: ReferenceError) -> Self {
        match value {
            ReferenceError::Contract(contract_err) => Self::Contract(contract_err),
            ReferenceError::DurableTransitionFailed(durable_err) => *durable_err,
            other => Self::Reference(other),
        }
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
    /// The obligation is in an in-flight, non-terminal state (Prepared, Committed, AdapterAccepted, Observed) and cannot yet be published to the ledger.
    InFlight {
        /// The durable obligation recorded in the journal.
        obligation: Obligation,
        /// The operation receipt recorded in the journal.
        receipt: OperationReceipt,
    },
    /// The obligation is durably in a terminal state (Verified, Failed, or Indeterminate) in the journal, but not yet published to the canonical ledger.
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

    /// Non-mutating inspection of a durable effect journal through an injected [`JournalReadIo`].
    pub fn inspect_with_io(
        io: &dyn JournalReadIo,
        path: impl AsRef<Path>,
        limits: impl Into<DurableLedgerLimits>,
    ) -> Result<EffectJournalInspection, DurableEffectError> {
        let path = path.as_ref();
        let limits = limits.into();

        let meta = match io.symlink_metadata(path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(EffectJournalInspection {
                    status: EffectJournalStatus::Absent,
                    journal: None,
                    obligation_counts: ObligationCounts::default(),
                    indeterminate_operations: Vec::new(),
                    incomplete_tail: None,
                    foreign_range: None,
                });
            }
            Err(err) => return Err(DurableEffectError::Io(err)),
        };

        if meta.is_symlink || !meta.is_file {
            return Err(DurableEffectError::InvalidLayout {
                path: path.to_path_buf(),
            });
        }

        let cap = limits.max_journal_bytes.saturating_add(1);
        let buf = io.read_bounded(path, cap)?;
        if buf.len() > limits.max_journal_bytes {
            return Err(DurableEffectError::OverBudget {
                limit: limits.max_journal_bytes,
                actual: usize::try_from(meta.len)
                    .unwrap_or(usize::MAX)
                    .max(buf.len()),
            });
        }

        let doctor_report = fss_ledger::doctor(&buf).map_err(|err| match err {
            fss_ledger::RepairError::OverBudget { limit, actual } => {
                DurableEffectError::OverBudget { limit, actual }
            }
            fss_ledger::RepairError::Journal(j) => DurableEffectError::Journal(j),
            fss_ledger::RepairError::Io(e) => DurableEffectError::Io(e),
            other => DurableEffectError::Repair(Box::new(other)),
        })?;

        let committed = usize::try_from(doctor_report.committed_len())
            .ok()
            .and_then(|len| buf.get(..len))
            .ok_or(DurableEffectError::Journal(JournalError::LengthOverflow))?;
        let recovery = fss_ledger::recover_bytes(committed)?;
        let journal = replay_report(&recovery)?;

        let mut obligation_counts = ObligationCounts::default();
        for obl in journal.obligations() {
            obligation_counts.total += 1;
            match obl.state {
                ObligationState::Pending => obligation_counts.pending += 1,
                ObligationState::Verified => obligation_counts.verified += 1,
                ObligationState::Failed => obligation_counts.failed += 1,
                ObligationState::Cancelled => obligation_counts.cancelled += 1,
                ObligationState::Indeterminate => obligation_counts.indeterminate += 1,
            }
        }

        let mut indeterminate_operations = Vec::new();
        for op in journal.operations() {
            if op.state == EffectState::Indeterminate {
                indeterminate_operations.push(IndeterminateOperationInfo {
                    operation_id: op.intent.operation_id.clone(),
                    reconcile_affordance: crate::situation_guard::EFFECT_RECONCILE_AFFORDANCE
                        .to_string(),
                });
            }
        }

        Ok(EffectJournalInspection {
            status: EffectJournalStatus::Present,
            journal: Some(journal),
            obligation_counts,
            indeterminate_operations,
            incomplete_tail: doctor_report.incomplete_tail(),
            foreign_range: doctor_report.foreign_range().cloned(),
        })
    }

    /// Non-mutating inspection of a durable effect journal.
    ///
    /// Reads up to `limits.max_journal_bytes + 1` bytes without acquiring exclusive locks,
    /// mutating the file, or fsyncing. If the file is missing, returns [`EffectJournalStatus::Absent`].
    pub fn inspect(
        path: impl AsRef<Path>,
        limits: impl Into<DurableLedgerLimits>,
    ) -> Result<EffectJournalInspection, DurableEffectError> {
        Self::inspect_with_io(&HostJournalReadIo, path, limits)
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

    /// The committed records on disk, refused unless they are exactly this handle's verified
    /// history: the same committed length and the same last root, which chains every record. Bytes
    /// swapped under the open handle (another journal's history copied over its file) are refused
    /// as [`JournalError::ExternalMutation`], as reopening the file would refuse them (fss-mnlz1).
    fn verified_history(&self) -> Result<RecoveryReport, DurableEffectError> {
        let report = inspect(self.path())?;
        let observed_len = report.committed_len();
        if observed_len != self.committed_len() || report.last_root() != self.last_root() {
            let kind = if observed_len == self.committed_len() {
                ExternalMutationKind::ContentDivergence
            } else {
                ExternalMutationKind::LengthDivergence
            };
            return Err(JournalError::ExternalMutation {
                expected_len: self.committed_len(),
                observed_len,
                kind,
            }
            .into());
        }
        Ok(report)
    }

    /// Roots of every committed record of this handle's verified history, in commit order: the
    /// history a sealed journal root must belong to (fss-mnlz1).
    pub(crate) fn committed_roots(&self) -> Result<Vec<ContentDigest>, DurableEffectError> {
        Ok(self
            .verified_history()?
            .records()
            .iter()
            .map(JournalRecord::root)
            .collect())
    }

    /// The effect journal as this handle's verified history stood right after the record whose
    /// root is `root`, or `None` when no committed record has that root (fss-mnlz1).
    pub(crate) fn replay_through(
        &self,
        root: ContentDigest,
    ) -> Result<Option<EffectJournal>, DurableEffectError> {
        let report = self.verified_history()?;
        let records = report.records();
        let Some(last) = records.iter().position(|record| record.root() == root) else {
            return Ok(None);
        };
        let (before, from) = records.split_at(last);
        let Some(through) = from.first() else {
            return Ok(None);
        };
        let mut prefix = before.to_vec();
        prefix.push(through.clone());
        replay_records(&prefix).map(Some)
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
        if let Some(sequence) = ledger.pending_append_sequence() {
            return Err(DurableEffectError::LedgerReconciliationRequired { sequence });
        }
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
            if matches!(
                receipt.state,
                EffectState::Verified | EffectState::Failed | EffectState::Indeterminate
            ) {
                return Ok(ObligationLedgerState::PendingLedger(
                    PendingLedgerObligation {
                        obligation: obligation.clone(),
                        receipt: receipt.clone(),
                    },
                ));
            } else {
                return Ok(ObligationLedgerState::InFlight {
                    obligation: obligation.clone(),
                    receipt: receipt.clone(),
                });
            }
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
        let delta_payload = matching_delta.map(|d| d.payload_digest);
        if ledgered_witness == Some(receipt.receipt_digest())
            && delta_payload == Some(published.payload_digest)
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
        if let Some(sequence) = ledger.pending_append_sequence() {
            return Err(DurableEffectError::LedgerReconciliationRequired { sequence });
        }
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
        self.journal
            .append(EFFECT_TRANSITION_V2_RECORD_KIND, &bytes)?;
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
        self.journal
            .append(EFFECT_TRANSITION_V2_RECORD_KIND, &bytes)?;
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
        self.journal
            .append(EFFECT_TRANSITION_V2_RECORD_KIND, &bytes)?;
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
        self.journal
            .append(EFFECT_TRANSITION_V2_RECORD_KIND, &bytes)?;
        let receipt = self
            .memory
            .reconcile_failed(operation_id, proof_digest, now, reason_str)?;
        Ok(receipt)
    }

    /// Dispatches a reference alert durably, guaranteeing commitment is journaled before provider dispatch.
    pub fn dispatch_alert(
        &mut self,
        plan: &ReferenceAlertPlan,
        authority: &DurableReferenceLedger,
        behavior: ReferenceProviderBehavior,
        committed_at: TimestampNs,
        outcome_at: TimestampNs,
        provider: &mut ReferenceAlertProvider,
    ) -> Result<OperationReceipt, DurableEffectError> {
        crate::alert::execute_alert_dispatch(
            plan,
            authority,
            behavior,
            committed_at,
            outcome_at,
            self,
            provider,
        )
        .map_err(DurableEffectError::from)
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
        let op = &plan.intent.operation_id;

        // Finding 4: Must check for recorded provider failures and transition to Failed
        if let Some(failure_receipt) = provider.lookup_failure(&plan.intent)? {
            let receipt = self.reconcile_failed(
                op,
                failure_receipt.receipt_digest(),
                now,
                failure_receipt.error_code.clone(),
            )?;
            return Ok(Some(receipt.clone()));
        }

        let Some(provider_receipt) = provider.lookup(&plan.intent)? else {
            return Ok(None);
        };
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
                let ind_time = now;
                let obs_time = TimestampNs(now.0.saturating_add(1));
                let ver_time = TimestampNs(now.0.saturating_add(2));
                self.mark_indeterminate(
                    op,
                    ind_time,
                    "restart_reconciliation_pending_observation",
                )?;
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

impl crate::alert::AlertEffectTransitioner for DurableEffectJournal {
    fn operation(&self, operation_id: &OperationId) -> Option<&OperationReceipt> {
        self.operation(operation_id)
    }

    fn obligation(&self, obligation_id: &ObligationId) -> Option<&Obligation> {
        self.obligation(obligation_id)
    }

    fn transition_cancelled(
        &mut self,
        operation_id: &OperationId,
        now: TimestampNs,
        proof: ContentDigest,
        reason: String,
    ) -> Result<(), ReferenceError> {
        self.transition(
            operation_id,
            EffectState::Cancelled,
            now,
            Some(proof),
            Some(reason),
        )
        .map(|_| ())
        .map_err(|e| match e {
            DurableEffectError::Reference(ref_err) => ref_err,
            DurableEffectError::Contract(contract_err) => ReferenceError::Contract(contract_err),
            other => ReferenceError::DurableTransitionFailed(Box::new(other)),
        })
    }

    fn transition_committed(
        &mut self,
        operation_id: &OperationId,
        now: TimestampNs,
    ) -> Result<(), ReferenceError> {
        self.transition(operation_id, EffectState::Committed, now, None, None)
            .map(|_| ())
            .map_err(|e| match e {
                DurableEffectError::Reference(ref_err) => ref_err,
                DurableEffectError::Contract(contract_err) => {
                    ReferenceError::Contract(contract_err)
                }
                other => ReferenceError::DurableTransitionFailed(Box::new(other)),
            })
    }

    fn transition_adapter_accepted(
        &mut self,
        operation_id: &OperationId,
        now: TimestampNs,
    ) -> Result<OperationReceipt, ReferenceError> {
        self.transition(operation_id, EffectState::AdapterAccepted, now, None, None)
            .cloned()
            .map_err(|e| match e {
                DurableEffectError::Reference(ref_err) => ref_err,
                DurableEffectError::Contract(contract_err) => {
                    ReferenceError::Contract(contract_err)
                }
                other => ReferenceError::DurableTransitionFailed(Box::new(other)),
            })
    }

    fn mark_indeterminate(
        &mut self,
        operation_id: &OperationId,
        now: TimestampNs,
        reason: &str,
    ) -> Result<OperationReceipt, ReferenceError> {
        self.mark_indeterminate(operation_id, now, reason)
            .cloned()
            .map_err(|e| match e {
                DurableEffectError::Reference(ref_err) => ref_err,
                DurableEffectError::Contract(contract_err) => {
                    ReferenceError::Contract(contract_err)
                }
                other => ReferenceError::DurableTransitionFailed(Box::new(other)),
            })
    }

    fn transition_failed(
        &mut self,
        operation_id: &OperationId,
        now: TimestampNs,
        proof: Option<ContentDigest>,
        reason: Option<String>,
    ) -> Result<OperationReceipt, ReferenceError> {
        self.transition(operation_id, EffectState::Failed, now, proof, reason)
            .cloned()
            .map_err(|e| match e {
                DurableEffectError::Reference(ref_err) => ref_err,
                DurableEffectError::Contract(contract_err) => {
                    ReferenceError::Contract(contract_err)
                }
                other => ReferenceError::DurableTransitionFailed(Box::new(other)),
            })
    }
}

fn replay_report(report: &RecoveryReport) -> Result<EffectJournal, DurableEffectError> {
    replay_records(report.records())
}

/// Replays `records`, in commit order, into a fresh effect journal, each under the version its
/// record kind names (fss-deir9).
///
/// A legacy (v1) record after a current (v2) one is refused as an unexpected record kind: the
/// legacy rules are reachable only for history written before any current record.
fn replay_records(records: &[JournalRecord]) -> Result<EffectJournal, DurableEffectError> {
    let mut transitions = Vec::with_capacity(records.len());
    let mut newest = EffectRecordVersion::V1;
    for record in records {
        let version = match record.kind() {
            EFFECT_TRANSITION_RECORD_KIND => EffectRecordVersion::V1,
            EFFECT_TRANSITION_V2_RECORD_KIND => EffectRecordVersion::V2,
            _ => {
                return Err(DurableEffectError::UnexpectedRecordKind {
                    sequence: record.sequence(),
                    kind: record.kind(),
                });
            }
        };
        if version < newest {
            return Err(DurableEffectError::UnexpectedRecordKind {
                sequence: record.sequence(),
                kind: record.kind(),
            });
        }
        newest = version;
        let transition =
            EffectJournalTransition::from_canonical_bytes(record.payload()).map_err(|error| {
                DurableEffectError::Decode {
                    sequence: record.sequence(),
                    error,
                }
            })?;
        transitions.push((version, transition));
    }
    let journal = EffectJournal::replay_versioned(transitions)?;
    Ok(journal)
}
