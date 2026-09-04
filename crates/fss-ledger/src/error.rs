//! Stable journal error and corruption taxonomy.

use std::error::Error;
use std::fmt;
use std::io;

/// Stable corruption classifications surfaced by recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CorruptionKind {
    /// Record magic is invalid where a complete header exists.
    RecordMagic,
    /// Durable format version is unsupported.
    FormatVersion,
    /// Record sequence is not contiguous.
    Sequence,
    /// Record names the wrong prior committed root.
    PreviousRoot,
    /// Payload length exceeds the format bound.
    PayloadLength,
    /// Payload bytes do not match their committed digest.
    PayloadDigest,
    /// Commit-trailer magic is invalid.
    CommitMagic,
    /// Commit-trailer root does not match the record body.
    CommitRoot,
}

/// Append or reconciliation phase at which the durable outcome became uncertain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppendPhase {
    /// The record body write returned or simulated an error.
    BodyWrite,
    /// Synchronizing the record body returned or simulated an error.
    BodySync,
    /// The commit-trailer write returned or simulated an error.
    CommitWrite,
    /// Synchronizing the commit trailer returned or simulated an error.
    CommitSync,
    /// Reading the journal during reconciliation failed.
    ReconcileRead,
    /// Truncating a proven incomplete suffix during reconciliation failed.
    ReconcileTruncate,
    /// Synchronizing a reconciled commit or truncation failed.
    ReconcileSync,
    /// Restoring the file cursor after reconciliation failed.
    ReconcileSeek,
}

/// Journal errors distinguish incomplete tails, verified corruption, and uncertain appends.
#[derive(Debug)]
pub enum JournalError {
    /// Host filesystem I/O failed before an append could become ambiguous.
    Io(io::Error),
    /// A fully present byte range violates a durable invariant.
    Corrupt {
        /// Byte offset where the invalid record begins.
        offset: u64,
        /// Stable corruption classification.
        kind: CorruptionKind,
    },
    /// The file ends in a non-committed suffix.
    IncompleteTail {
        /// First byte of the incomplete record.
        offset: u64,
    },
    /// Caller payload is larger than the format permits.
    PayloadTooLarge {
        /// Attempted payload length.
        length: usize,
        /// Maximum admitted length.
        maximum: usize,
    },
    /// Sequence space is exhausted.
    SequenceExhausted,
    /// An append may or may not have crossed its durable commit boundary.
    AppendIndeterminate {
        /// Sequence assigned to the attempted record.
        sequence: u64,
        /// Last phase whose completion is not safely known to the caller.
        phase: AppendPhase,
        /// Underlying host I/O or deterministic fault-injection error.
        source: io::Error,
    },
    /// A prior indeterminate append must be reconciled before another operation.
    ReconciliationRequired {
        /// Sequence of the unresolved append.
        sequence: u64,
    },
    /// No unresolved append exists on this journal handle.
    NoPendingAppend,
    /// The path changed outside the single-writer journal handle.
    ExternalMutation {
        /// Byte length owned by the current handle or expected reconciliation state.
        expected_len: u64,
        /// Byte length observed on disk.
        observed_len: u64,
    },
}

impl fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "journal I/O error: {error}"),
            Self::Corrupt { offset, kind } => {
                write!(formatter, "journal corruption at byte {offset}: {kind:?}")
            }
            Self::IncompleteTail { offset } => {
                write!(formatter, "journal has incomplete tail at byte {offset}")
            }
            Self::PayloadTooLarge { length, maximum } => {
                write!(
                    formatter,
                    "journal payload {length} exceeds maximum {maximum}"
                )
            }
            Self::SequenceExhausted => formatter.write_str("journal sequence space exhausted"),
            Self::AppendIndeterminate {
                sequence,
                phase,
                source,
            } => write!(
                formatter,
                "journal append {sequence} became indeterminate during {phase:?}: {source}"
            ),
            Self::ReconciliationRequired { sequence } => write!(
                formatter,
                "journal append {sequence} requires reconciliation before further use"
            ),
            Self::NoPendingAppend => {
                formatter.write_str("journal has no pending append to reconcile")
            }
            Self::ExternalMutation {
                expected_len,
                observed_len,
            } => write!(
                formatter,
                concat!(
                    "journal changed outside this writer: expected length {expected_len}, ",
                    "observed {observed_len}"
                )
            ),
        }
    }
}

impl Error for JournalError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) | Self::AppendIndeterminate { source: error, .. } => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for JournalError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
