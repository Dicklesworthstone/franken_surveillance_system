//! Crash-safe evidence-history wrapper proving restart equivalence.

use std::error::Error;
use std::fmt;
use std::path::Path;

use fss_core::{
    BatchId, ContentDigest, ContractError, EvidenceDelta, EvidenceDeltaBatch, LedgerSnapshot,
    ReferenceLedger,
};

use crate::{
    BatchCodecError, IncompleteTailPolicy, Journal, JournalError, decode_batch, encode_batch,
};

const EVIDENCE_BATCH_RECORD_KIND: u16 = 1;

/// Errors raised by the durable reference ledger.
#[derive(Debug)]
pub enum DurableLedgerError {
    /// Underlying journal I/O or corruption failure.
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

/// Durable wrapper around the deterministic in-memory reference ledger.
///
/// On open, every committed journal record is decoded and replayed through the same
/// `ReferenceLedger::append` checks used by live publication. This makes restart state a
/// deterministic function of the durable committed prefix.
#[derive(Debug)]
pub struct DurableReferenceLedger {
    journal: Journal,
    ledger: ReferenceLedger,
}

impl DurableReferenceLedger {
    /// Opens, verifies, and replays the durable evidence history.
    pub fn open(
        path: impl AsRef<Path>,
        site_lineage: impl Into<String>,
        tail_policy: IncompleteTailPolicy,
    ) -> Result<Self, DurableLedgerError> {
        let journal = Journal::open(path, tail_policy)?;
        let report = crate::inspect(journal.path())?;
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
        Ok(Self { journal, ledger })
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

    /// Root of the durable journal prefix.
    #[must_use]
    pub const fn journal_root(&self) -> ContentDigest {
        self.journal.last_root()
    }

    /// Prepares a successor against the current in-memory/durable anchor.
    pub fn prepare_batch(
        &self,
        batch_id: BatchId,
        deltas: Vec<EvidenceDelta>,
        child_roots: impl IntoIterator<Item = ContentDigest>,
    ) -> Result<EvidenceDeltaBatch, DurableLedgerError> {
        Ok(self.ledger.prepare_batch(batch_id, deltas, child_roots)?)
    }

    /// Validates, durably commits, then exposes one evidence batch.
    ///
    /// All semantic validation and durable-envelope allocation happen before journal I/O.
    /// A cloned candidate ledger proves the exact successor first. After journal commit, the
    /// candidate is installed with no remaining fallible semantic transition.
    pub fn append(
        &mut self,
        batch: EvidenceDeltaBatch,
    ) -> Result<&LedgerSnapshot, DurableLedgerError> {
        let mut candidate = self.ledger.clone();
        candidate.append(batch.clone())?;
        let encoded = encode_batch(&batch)?;
        let _record = self.journal.append(EVIDENCE_BATCH_RECORD_KIND, &encoded)?;
        self.ledger = candidate;
        Ok(self.ledger.current())
    }

    /// Re-verifies the durable prefix and journal root.
    pub fn verify_storage(&mut self) -> Result<ContentDigest, DurableLedgerError> {
        let report = self.journal.verify()?;
        Ok(report.last_root())
    }
}
