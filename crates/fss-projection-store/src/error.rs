#![forbid(unsafe_code)]
//! Typed error surfaces for materialized MVCC projections and flat-combining commit coalescing.

use core::fmt;
use std::io;
use std::sync::Arc;

use fss_core::{ContentDigest, ContractError, ObjectId};
use fss_ledger::{BatchCodecError, CommitReceipt, EpochLedgerError};
use fss_pack::PackError;

use crate::schema::ProjectionAnchor;

/// Disk or filesystem operation associated with a [`ProjectionError::Io`] failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProjectionIoOperation {
    /// Creating the projection or quarantine directory hierarchy.
    CreateDir,
    /// Opening a snapshot, WAL, or epoch file.
    Open,
    /// Reading file metadata or byte length.
    Metadata,
    /// Reading bytes from disk.
    Read,
    /// Writing bytes to disk.
    Write,
    /// Flushing buffered bytes to OS buffers.
    Flush,
    /// Synchronizing file contents to durable media.
    SyncFile,
    /// Synchronizing a parent directory after atomic rename.
    SyncDir,
    /// Atomically renaming a temporary snapshot or quarantining a corrupt file.
    Rename,
    /// Truncating a WAL file after snapshot compaction or rebuild.
    Truncate,
    /// Removing a temporary or superseded file.
    Remove,
    /// Enumerating directory entries.
    ReadDir,
}

impl ProjectionIoOperation {
    /// Stable machine-readable operation label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreateDir => "create_dir",
            Self::Open => "open",
            Self::Metadata => "metadata",
            Self::Read => "read",
            Self::Write => "write",
            Self::Flush => "flush",
            Self::SyncFile => "sync_file",
            Self::SyncDir => "sync_dir",
            Self::Rename => "rename",
            Self::Truncate => "truncate",
            Self::Remove => "remove",
            Self::ReadDir => "read_dir",
        }
    }
}

/// Typed failure returned by [`crate::ProjectionStore`] and [`crate::MvccProjectionStore`] operations.
#[derive(Debug)]
pub enum ProjectionError {
    /// Filesystem I/O failure during persistence, recovery, or epoch history reads.
    Io {
        /// Specific operation that failed.
        operation: ProjectionIoOperation,
        /// Underlying OS error.
        source: io::Error,
    },
    /// Invalid configuration or request argument.
    InvalidRequest(&'static str),
    /// Canonical encoding or decoding failed.
    Contract(ContractError),
    /// Canonical ledger batch binary codec failed.
    BatchCodec(BatchCodecError),
    /// Underlying canonical epoch ledger error.
    Ledger(EpochLedgerError),
    /// Underlying packfile store error while resolving content-addressed payloads.
    Pack(PackError),
    /// The projection head is already published, but its optional snapshot compaction failed.
    /// Reapplying the batch is not safe or necessary; repair and call `compact_snapshot`.
    AppliedMaintenanceFailed {
        /// Exact visible projection anchor, unaffected by the maintenance failure.
        anchor: ProjectionAnchor,
        /// Failed snapshot write or WAL-reset operation.
        source: Box<ProjectionError>,
    },
    /// Offered delta batch does not advance from the store's current anchor.
    AnchorMismatch {
        /// Expected basis commit sequence.
        expected_sequence: u64,
        /// Observed batch basis commit sequence.
        actual_sequence: u64,
        /// Explanation of the mismatch.
        detail: &'static str,
    },
    /// Batch digest did not match recomputed canonical digest.
    BatchDigestMismatch {
        /// Digest declared on the batch.
        declared: ContentDigest,
        /// Recomputed SHA-256 digest.
        computed: ContentDigest,
    },
    /// Required immutable payload bytes could not be resolved.
    MissingPayload {
        /// Missing content digest.
        digest: ContentDigest,
        /// Delta family requiring the payload.
        family: String,
    },
    /// Resolved payload bytes did not match the delta's SHA-256 `payload_digest`.
    PayloadDigestMismatch {
        /// Expected digest from the canonical delta.
        expected: ContentDigest,
        /// Actual SHA-256 digest of resolved bytes.
        actual: ContentDigest,
    },
    /// Payload bytes could not be decoded for the declared delta family.
    InvalidPayload {
        /// Delta family name.
        family: String,
        /// Diagnostic detail.
        detail: String,
    },
    /// Persisted `mvcc.snap` or `mvcc.wal` failed magic, CRC32C, SHA-256, or schema validation.
    CorruptDerivedStore {
        /// Which file failed verification (`mvcc.snap` or `mvcc.wal`).
        artifact: &'static str,
        /// Diagnostic detail.
        detail: String,
    },
    /// Requested historical commit sequence is ahead of the store's current head.
    SequenceAhead {
        /// Requested commit sequence.
        requested: u64,
        /// Current head commit sequence.
        head: u64,
    },
    /// Requested historical snapshot was evicted from the bounded MVCC snapshot retention window.
    SnapshotEvicted {
        /// Requested commit sequence.
        requested: u64,
        /// Oldest commit sequence currently retained in memory.
        oldest_retained: Option<u64>,
    },
    /// Requested scrub receipt failed anchor or range validation.
    InvalidScrubReceipt(&'static str),
    /// Arithmetic overflow in multiplicity, sequence, or length calculation.
    ArithmeticOverflow(&'static str),
    /// Internal synchronization lock was poisoned by a panic elsewhere.
    LockPoisoned,
    /// Caller-owned authority/cancellation token requested cancellation before commit.
    Cancelled,
}

impl ProjectionError {
    /// Constructs a typed I/O error.
    #[must_use]
    pub const fn io(operation: ProjectionIoOperation, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

impl fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, source } => {
                write!(
                    f,
                    "projection I/O error during {}: {source}",
                    operation.as_str()
                )
            }
            Self::InvalidRequest(msg) => write!(f, "invalid projection request: {msg}"),
            Self::Contract(err) => write!(f, "projection canonical contract error: {err}"),
            Self::BatchCodec(err) => write!(f, "projection batch codec error: {err}"),
            Self::Ledger(err) => write!(f, "canonical ledger error: {err}"),
            Self::Pack(err) => write!(f, "pack store payload error: {err}"),
            Self::AppliedMaintenanceFailed { anchor, source } => write!(
                f,
                "projection sequence {} is already applied, but snapshot maintenance failed: {source}; repair and compact_snapshot without reapplying the batch",
                anchor.commit_sequence
            ),
            Self::AnchorMismatch {
                expected_sequence,
                actual_sequence,
                detail,
            } => write!(
                f,
                "projection anchor mismatch (expected seq {expected_sequence}, got {actual_sequence}): {detail}"
            ),
            Self::BatchDigestMismatch { declared, computed } => write!(
                f,
                "batch digest mismatch: declared {declared}, computed {computed}"
            ),
            Self::MissingPayload { digest, family } => {
                write!(f, "missing payload {digest} for delta family '{family}'")
            }
            Self::PayloadDigestMismatch { expected, actual } => write!(
                f,
                "payload digest mismatch: expected {expected}, computed {actual}"
            ),
            Self::InvalidPayload { family, detail } => {
                write!(f, "invalid payload for delta family '{family}': {detail}")
            }
            Self::CorruptDerivedStore { artifact, detail } => {
                write!(
                    f,
                    "corrupt derived projection artifact '{artifact}': {detail}"
                )
            }
            Self::SequenceAhead { requested, head } => write!(
                f,
                "requested commit sequence {requested} is ahead of head {head}"
            ),
            Self::SnapshotEvicted {
                requested,
                oldest_retained,
            } => write!(
                f,
                "historical snapshot at seq {requested} was evicted (oldest retained: {oldest_retained:?})"
            ),
            Self::InvalidScrubReceipt(msg) => write!(f, "invalid doctor scrub receipt: {msg}"),
            Self::ArithmeticOverflow(field) => {
                write!(f, "arithmetic overflow computing {field}")
            }
            Self::LockPoisoned => f.write_str("projection store lock poisoned"),
            Self::Cancelled => f.write_str("projection operation cancelled"),
        }
    }
}

impl std::error::Error for ProjectionError {}

impl From<ContractError> for ProjectionError {
    fn from(err: ContractError) -> Self {
        Self::Contract(err)
    }
}

impl From<BatchCodecError> for ProjectionError {
    fn from(err: BatchCodecError) -> Self {
        Self::BatchCodec(err)
    }
}

impl From<EpochLedgerError> for ProjectionError {
    fn from(err: EpochLedgerError) -> Self {
        Self::Ledger(err)
    }
}

impl From<PackError> for ProjectionError {
    fn from(err: PackError) -> Self {
        Self::Pack(err)
    }
}

/// Typed failure returned by [`crate::CommitCombiner`].
#[derive(Debug)]
pub enum CombinerError {
    /// Combiner configuration failed validation.
    InvalidConfig(&'static str),
    /// Submitted proposal failed pre-queue validation.
    InvalidProposal(&'static str),
    /// Bounded pending queue is full; caller must back off and retry.
    QueueFull {
        /// Configured maximum queued proposals.
        max_pending: usize,
    },
    /// Proposal contains a duplicate `ObjectId` within itself.
    DuplicateObjectInProposal {
        /// Conflicting object identifier.
        object_id: ObjectId,
    },
    /// Proposal failed generation validation against current canonical state.
    GenerationConflict {
        /// Conflicting object identifier.
        object_id: ObjectId,
        /// Current committed generation (`None` if absent).
        committed_generation: Option<u64>,
        /// Prior generation declared by proposal delta.
        prior_generation: Option<u64>,
        /// New generation declared by proposal delta.
        new_generation: u64,
    },
    /// Caller cancelled the proposal before commit execution.
    Cancelled,
    /// Combiner has been shut down and refuses new submissions.
    Shutdown,
    /// Underlying packfile write failed.
    Pack(PackError),
    /// Underlying canonical ledger append failed.
    Ledger(EpochLedgerError),
    /// Underlying materialized projection apply failed.
    Projection(ProjectionError),
    /// The canonical batch is durable, but the projection operation returned an error.
    /// Reconcile the projection from the committed receipt; do not resubmit the wave.
    CommittedProjectionFailed {
        /// Exact receipt from the ledger, shared across submitters in this wave.
        receipt: Arc<CommitReceipt>,
        /// Independent failure of periodic ledger checkpoint maintenance, when attempted.
        checkpoint_failure: Option<Arc<str>>,
        /// Failure while applying or checkpointing the projection.
        source: Arc<ProjectionError>,
    },
    /// Sink reported an opaque typed failure.
    SinkFailure(String),
    /// Internal combiner mutex or condvar lock was poisoned.
    LockPoisoned,
}

impl fmt::Display for CombinerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid commit combiner config: {msg}"),
            Self::InvalidProposal(msg) => write!(f, "invalid commit proposal: {msg}"),
            Self::QueueFull { max_pending } => {
                write!(f, "commit combiner queue full (capacity {max_pending})")
            }
            Self::DuplicateObjectInProposal { object_id } => {
                write!(
                    f,
                    "duplicate object '{object_id}' within single commit proposal"
                )
            }
            Self::GenerationConflict {
                object_id,
                committed_generation,
                prior_generation,
                new_generation,
            } => write!(
                f,
                "generation conflict for '{object_id}': committed={committed_generation:?}, prior={prior_generation:?}, new={new_generation}"
            ),
            Self::Cancelled => f.write_str("commit proposal cancelled before commit"),
            Self::Shutdown => f.write_str("commit combiner has been shut down"),
            Self::Pack(err) => write!(f, "commit combiner pack error: {err}"),
            Self::Ledger(err) => write!(f, "commit combiner ledger error: {err}"),
            Self::Projection(err) => write!(f, "commit combiner projection error: {err}"),
            Self::CommittedProjectionFailed {
                receipt,
                checkpoint_failure,
                source,
            } => {
                write!(
                    f,
                    "batch {} durably committed at sequence {}, projection operation failed: {source}",
                    receipt.batch_id, receipt.sequence
                )?;
                if let Some(checkpoint) = checkpoint_failure {
                    write!(f, "; ledger checkpoint also failed: {checkpoint}")?;
                }
                Ok(())
            }
            Self::SinkFailure(msg) => write!(f, "commit combiner sink failure: {msg}"),
            Self::LockPoisoned => f.write_str("commit combiner lock poisoned"),
        }
    }
}

impl std::error::Error for CombinerError {}

impl From<PackError> for CombinerError {
    fn from(err: PackError) -> Self {
        Self::Pack(err)
    }
}

impl From<EpochLedgerError> for CombinerError {
    fn from(err: EpochLedgerError) -> Self {
        Self::Ledger(err)
    }
}

impl From<ProjectionError> for CombinerError {
    fn from(err: ProjectionError) -> Self {
        Self::Projection(err)
    }
}
