//! Crash-safe evidence-history wrapper proving restart equivalence.

use std::error::Error;
use std::fmt;
use std::path::Path;

use fss_core::{
    BatchId, ContentDigest, ContractError, EvidenceDelta, EvidenceDeltaBatch, LedgerSnapshot,
    ReferenceLedger,
};

use crate::{
    AppendReconciliation, BatchCodecError, IncompleteTailPolicy, Journal, JournalError,
    RecoveryReport, decode_batch, encode_batch,
};

#[cfg(test)]
use crate::AppendPhase;

const EVIDENCE_BATCH_RECORD_KIND: u16 = 1;

/// Errors raised by the durable reference ledger.
#[derive(Debug)]
pub enum DurableLedgerError {
    /// Underlying journal I/O, corruption, or reconciliation failure.
    Journal(JournalError),
    /// Durable evidence-batch bytes are malformed or semantically invalid.
    Codec(BatchCodecError),
    /// Replaying or preparing the canonical evidence history violates a core contract.
    Contract(ContractError),
    /// A committed record kind is not understood by this durable ledger version.
    UnexpectedRecordKind {
        /// Sequence carrying the unsupported record kind.
        sequence: u64,
        /// Unsupported record kind.
        kind: u16,
    },
}

impl fmt::Display for DurableLedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(error) => write!(formatter, "durable ledger journal error: {error}"),
            Self::Codec(error) => write!(formatter, "durable ledger codec error: {error}"),
            Self::Contract(error) => write!(formatter, "durable ledger contract error: {error}"),
            Self::UnexpectedRecordKind { sequence, kind } => write!(
                formatter,
                "durable ledger record {sequence} has unsupported kind {kind}"
            ),
        }
    }
}

impl Error for DurableLedgerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Journal(error) => Some(error),
            Self::Codec(error) => Some(error),
            Self::Contract(error) => Some(error),
            Self::UnexpectedRecordKind { .. } => None,
        }
    }
}

impl From<JournalError> for DurableLedgerError {
    fn from(value: JournalError) -> Self {
        Self::Journal(value)
    }
}

impl From<BatchCodecError> for DurableLedgerError {
    fn from(value: BatchCodecError) -> Self {
        Self::Codec(value)
    }
}

impl From<ContractError> for DurableLedgerError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}

/// Result of reconciling one indeterminate durable evidence-batch append.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableAppendReconciliation {
    /// The exact prevalidated candidate became canonical exactly once.
    Committed {
        /// Durable journal sequence of the committed batch.
        sequence: u64,
        /// Stable batch identity now visible in the canonical ledger.
        batch_id: BatchId,
    },
    /// The batch did not commit and its sequence remains reusable.
    NotCommitted {
        /// Sequence available for a safe retry.
        sequence: u64,
    },
}

#[derive(Clone, Debug)]
struct PendingLedgerAppend {
    candidate: ReferenceLedger,
    sequence: u64,
    batch_id: BatchId,
}

/// Durable wrapper around the deterministic in-memory reference ledger.
///
/// On open, every committed journal record is decoded and replayed through the same
/// `ReferenceLedger::append` checks used by live publication. This makes restart state a
/// deterministic function of the durable committed prefix.
#[derive(Debug)]
pub struct DurableReferenceLedger {
    journal: Journal,
    ledger: ReferenceLedger,
    pending: Option<PendingLedgerAppend>,
}

impl DurableReferenceLedger {
    /// Opens, verifies, and replays the durable evidence history.
    ///
    /// When tail truncation is requested, the complete committed prefix is semantically replayed
    /// before any repair mutation is allowed. A malformed batch, unsupported record kind, stale
    /// site lineage, or other semantic failure therefore leaves an incomplete suffix untouched for
    /// diagnosis. `Journal::open` revalidates the structural prefix before the repair itself.
    pub fn open(
        path: impl AsRef<Path>,
        site_lineage: impl Into<String>,
        tail_policy: IncompleteTailPolicy,
    ) -> Result<Self, DurableLedgerError> {
        let path = path.as_ref().to_path_buf();
        let site_lineage = site_lineage.into();

        let preflight = if path.exists() {
            let report = crate::inspect(&path)?;
            let _ = replay_report(&report, &site_lineage)?;
            Some(report)
        } else {
            None
        };

        let journal = Journal::open(&path, tail_policy)?;
        let report = crate::inspect(journal.path())?;

        if let Some(preflight) = preflight {
            if report.last_root() != preflight.last_root()
                || report.committed_len() != preflight.committed_len()
            {
                return Err(JournalError::ExternalMutation {
                    expected_len: preflight.committed_len(),
                    observed_len: report.committed_len(),
                }
                .into());
            }
        }

        let ledger = replay_report(&report, &site_lineage)?;
        Ok(Self {
            journal,
            ledger,
            pending: None,
        })
    }

    /// Latest complete canonical evidence snapshot.
    #[must_use]
    pub fn current(&self) -> &LedgerSnapshot {
        self.ledger.current()
    }

    /// Immutable batches reconstructed from the durable committed prefix.
    #[must_use]
    pub fn batches(&self) -> &[EvidenceDeltaBatch] {
        self.ledger.batches()
    }

    /// Root of the latest reconciled durable journal prefix.
    #[must_use]
    pub const fn journal_root(&self) -> ContentDigest {
        self.journal.last_root()
    }

    /// Sequence of an indeterminate append that must be reconciled, if present.
    #[must_use]
    pub fn pending_append_sequence(&self) -> Option<u64> {
        self.pending.as_ref().map(|pending| pending.sequence)
    }

    /// Prepares a successor against the current in-memory/durable anchor.
    pub fn prepare_batch(
        &self,
        batch_id: BatchId,
        deltas: Vec<EvidenceDelta>,
        child_roots: impl IntoIterator<Item = ContentDigest>,
    ) -> Result<EvidenceDeltaBatch, DurableLedgerError> {
        Ok(self
            .ledger
            .prepare_batch(batch_id, deltas, child_roots)?)
    }

    /// Validates, durably commits, then exposes one evidence batch.
    ///
    /// The exact successor ledger and durable bytes are prepared before journal I/O. If the
    /// journal returns `AppendIndeterminate`, the candidate remains private and this ledger blocks
    /// further mutation until `reconcile_pending` proves whether that exact batch committed.
    pub fn append(
        &mut self,
        batch: EvidenceDeltaBatch,
    ) -> Result<&LedgerSnapshot, DurableLedgerError> {
        if let Some(pending) = &self.pending {
            return Err(JournalError::ReconciliationRequired {
                sequence: pending.sequence,
            }
            .into());
        }

        let mut candidate = self.ledger.clone();
        candidate.append(batch.clone())?;
        let encoded = encode_batch(&batch)?;
        let batch_id = batch.batch_id.clone();
        match self.journal.append(EVIDENCE_BATCH_RECORD_KIND, &encoded) {
            Ok(_record) => {
                self.ledger = candidate;
                Ok(self.ledger.current())
            }
            Err(error) => {
                if let JournalError::AppendIndeterminate { sequence, .. } = &error {
                    self.pending = Some(PendingLedgerAppend {
                        candidate,
                        sequence: *sequence,
                        batch_id,
                    });
                }
                Err(error.into())
            }
        }
    }

    /// Reconciles the exact prevalidated candidate retained after an indeterminate append.
    ///
    /// A committed result installs the already validated candidate without replaying a fallible
    /// semantic transition after the durable decision. A not-committed result discards the private
    /// candidate and leaves the canonical ledger unchanged.
    pub fn reconcile_pending(
        &mut self,
        tail_policy: IncompleteTailPolicy,
    ) -> Result<DurableAppendReconciliation, DurableLedgerError> {
        let pending = self
            .pending
            .take()
            .ok_or(JournalError::NoPendingAppend)?;
        match self.journal.reconcile_pending(tail_policy) {
            Ok(AppendReconciliation::Committed(_record)) => {
                self.ledger = pending.candidate;
                Ok(DurableAppendReconciliation::Committed {
                    sequence: pending.sequence,
                    batch_id: pending.batch_id,
                })
            }
            Ok(AppendReconciliation::NotCommitted { sequence }) => {
                Ok(DurableAppendReconciliation::NotCommitted { sequence })
            }
            Err(error) => {
                self.pending = Some(pending);
                Err(error.into())
            }
        }
    }

    /// Re-verifies the reconciled durable prefix and journal root.
    pub fn verify_storage(&mut self) -> Result<ContentDigest, DurableLedgerError> {
        let report = self.journal.verify()?;
        Ok(report.last_root())
    }

    #[cfg(test)]
    pub(crate) fn fail_journal_after_phase(&mut self, phase: AppendPhase) {
        self.journal.fail_after_phase(phase);
    }
}

fn replay_report(
    report: &RecoveryReport,
    site_lineage: &str,
) -> Result<ReferenceLedger, DurableLedgerError> {
    let mut ledger = ReferenceLedger::new(site_lineage);
    for record in report.records() {
        if record.kind() != EVIDENCE_BATCH_RECORD_KIND {
            return Err(DurableLedgerError::UnexpectedRecordKind {
                sequence: record.sequence(),
                kind: record.kind(),
            });
        }
        let batch = decode_batch(record.payload())?;
        ledger.append(batch)?;
    }
    Ok(ledger)
}
