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

/// Journal errors distinguish incomplete tails from verified corruption.
#[derive(Debug)]
pub enum JournalError {
    /// Host filesystem I/O failed.
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
                write!(formatter, "journal payload {length} exceeds maximum {maximum}")
            }
            Self::SequenceExhausted => formatter.write_str("journal sequence space exhausted"),
        }
    }
}

impl Error for JournalError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for JournalError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
