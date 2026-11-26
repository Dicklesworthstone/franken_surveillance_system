#![forbid(unsafe_code)]
//! Typed error and corruption taxonomy for v2 epoch journals and checkpoints.

use std::error::Error;
use std::fmt;
use std::io;
use std::path::PathBuf;

use fss_core::{BatchId, ContentDigest, ContractError, ObjectId, Plane};

use crate::batch_codec::BatchCodecError;
use crate::error::AppendPhase;
use crate::merkle::MerkleError;
use crate::oracle::{AnchorField, CommitReceipt, OracleBoundField};

/// Stable classification of corruption detected in an epoch segment file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpochCorruptionKind {
    /// File ends before the complete fixed-size epoch header.
    TruncatedHeader,
    /// Epoch file magic is not `FSSE`.
    InvalidMagic,
    /// Epoch format version is not version `2`.
    UnsupportedVersion,
    /// Header `epoch_id` disagrees with the epoch filename.
    EpochIdMismatch,
    /// Header `first_commit_seq` does not continue the previous epoch's head.
    FirstCommitSeqMismatch,
    /// Header `prev_history_root` does not match the prior committed history root.
    PrevHistoryRootMismatch,
    /// Header CRC32 or SHA-256 digest failed verification.
    HeaderChecksumMismatch,
    /// Record magic (or non-empty trailing junk prefix) is not `FSSR`.
    RecordMagic,
    /// Reserved record flags are non-zero.
    RecordFlags,
    /// Record header CRC32 failed verification.
    RecordHeaderChecksum,
    /// Record commit sequence is not contiguous.
    RecordSequence,
    /// Record payload length exceeds `MAX_RECORD_PAYLOAD_BYTES`.
    PayloadLength,
    /// Record payload CRC32 failed verification.
    PayloadChecksum,
    /// Record payload SHA-256 failed verification.
    PayloadDigest,
    /// Commit trailer magic is not `FSST`.
    TrailerMagic,
    /// Commit trailer CRC32 failed verification.
    TrailerChecksum,
    /// Commit trailer history root disagrees with recomputed history chain.
    HistoryRootMismatch,
    /// A sealed (non-final) epoch file ended with an incomplete record.
    IncompleteTailInSealedEpoch,
    /// Record payload failed canonical `EvidenceDeltaBatch` decoding.
    BatchCodec,
}

/// Stable classification of corruption or inconsistency detected in a checkpoint file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointCorruptionKind {
    /// File is shorter than the minimum magic + version + trailing SHA-256 size.
    TooShort,
    /// Checkpoint magic is not `FSSC`.
    InvalidMagic,
    /// Checkpoint format version is not version `2`.
    UnsupportedVersion,
    /// Trailing whole-file SHA-256 integrity digest failed verification.
    IntegrityDigestMismatch,
    /// Checkpoint domain tag is not `fss.ledger.checkpoint.v2`.
    InvalidDomain,
    /// Canonical body decode failed or contained trailing bytes.
    CanonicalDecode,
    /// Checkpoint header fields disagree with `latest_anchor` or `live_object_count`.
    AnchorInconsistency,
    /// Checkpoint site lineage does not match the requested ledger lineage.
    SiteLineageMismatch,
    /// Checkpoint filename commit sequence disagrees with the payload commit sequence.
    FilenameSequenceMismatch,
    /// Serialized trie snapshot failed structural or root validation.
    TrieSnapshotInvalid,
    /// Referenced epoch file is missing or shorter than `epoch_byte_offset`.
    EpochOffsetMismatch,
    /// Epoch file header or commit trailer at `epoch_byte_offset` disagrees with `history_root`.
    EpochTrailerMismatch,
}

/// Typed errors raised by [`crate::epochs::MerkleEpochLedger`] and its epoch/checkpoint layers.
#[derive(Debug)]
pub enum EpochLedgerError {
    /// Invalid ledger configuration or site lineage.
    InvalidConfig(&'static str),
    /// Host filesystem I/O failure.
    Io(io::Error),
    /// Another writable handle owns this ledger root; recovery and mutation were not started.
    WriterLocked,
    /// Record bytes may have reached storage; reconcile this exact append before further writes.
    AppendIndeterminate {
        /// Epoch containing the attempted append.
        epoch_id: u64,
        /// Attempted canonical commit sequence.
        sequence: u64,
        /// I/O phase whose outcome is unresolved.
        phase: AppendPhase,
        /// Original I/O failure.
        source: io::Error,
    },
    /// A prior append remains unresolved and fences new preparation, mutation, and verification.
    ReconciliationRequired {
        /// Sequence of the unresolved append.
        sequence: u64,
    },
    /// Reconciliation was requested without an unresolved append.
    NoPendingAppend,
    /// The batch is durably committed, but its optional periodic checkpoint failed.
    CommittedCheckpointFailed {
        /// Exact durable result; callers must not treat this batch as uncommitted.
        receipt: Box<CommitReceipt>,
        /// Checkpoint maintenance failure, safe to retry separately with `force_checkpoint`.
        source: Box<EpochLedgerError>,
    },
    /// Verified corruption in an epoch segment file.
    CorruptEpoch {
        /// Epoch segment identifier.
        epoch_id: u64,
        /// Byte offset in the epoch file where corruption occurred.
        offset: u64,
        /// Stable corruption classification.
        kind: EpochCorruptionKind,
    },
    /// Active epoch ended in an uncommitted truncated tail record.
    IncompleteTail {
        /// Active epoch identifier.
        epoch_id: u64,
        /// First byte offset of the incomplete tail record.
        offset: u64,
    },
    /// Contiguous epoch file is missing from `<dir>/epochs/`.
    MissingEpoch {
        /// Expected contiguous epoch identifier.
        expected_epoch_id: u64,
    },
    /// Explicit checkpoint verification failed.
    CorruptCheckpoint {
        /// Offending checkpoint path.
        path: PathBuf,
        /// Stable corruption classification.
        kind: CheckpointCorruptionKind,
    },
    /// Canonical `EvidenceDeltaBatch` codec error.
    Codec(BatchCodecError),
    /// Radix-Merkle accumulator error.
    Merkle(MerkleError),
    /// Core semantic contract error.
    Contract(ContractError),
    /// A bounded batch field exceeded its limit.
    BoundExceeded {
        /// Bounded field.
        field: OracleBoundField,
        /// Observed length.
        length: usize,
        /// Maximum admitted length.
        maximum: usize,
    },
    /// Deltas or child roots are not in strictly increasing canonical order.
    NonCanonicalOrdering {
        /// Offered batch identity.
        batch_id: BatchId,
    },
    /// Declared batch digest does not match recomputed digest.
    BatchDigestMismatch {
        /// Offered batch identity.
        batch_id: BatchId,
        /// Digest carried by the batch.
        declared: ContentDigest,
        /// Digest recomputed from content.
        computed: ContentDigest,
    },
    /// Identical batch is already committed.
    DuplicateBatch {
        /// Batch identity.
        batch_id: BatchId,
        /// Commit sequence where it became canonical.
        committed_sequence: u64,
    },
    /// Batch identity is already committed with different content.
    BatchIdConflict {
        /// Reused batch identity.
        batch_id: BatchId,
        /// Canonical commit sequence owning this identity.
        committed_sequence: u64,
        /// Digest of the canonical batch.
        committed_digest: ContentDigest,
        /// Digest of the offered conflicting batch.
        offered_digest: ContentDigest,
    },
    /// Batch builds on a sequence beyond the current head.
    SequenceGap {
        /// Current head commit sequence.
        head_sequence: u64,
        /// Offered basis sequence.
        basis_sequence: u64,
    },
    /// Basis anchor does not match this ledger's history.
    BasisForked {
        /// Offered basis commit sequence.
        basis_sequence: u64,
    },
    /// Another batch already committed after `basis_sequence`.
    SuccessorConflict {
        /// Offered basis commit sequence.
        basis_sequence: u64,
        /// Current head commit sequence.
        head_sequence: u64,
    },
    /// Successor anchor field does not follow basis anchor.
    InvalidSuccessorAnchor {
        /// First non-following field in canonical order.
        field: AnchorField,
    },
    /// `u64` commit sequence or epoch sequence space is exhausted.
    SequenceExhausted,
    /// One batch contains duplicate deltas targeting the same object.
    DuplicateObjectInBatch {
        /// Repeated object identity.
        object_id: ObjectId,
    },
    /// Delta generation does not strictly follow committed object generation.
    GenerationConflict {
        /// Object identity.
        object_id: ObjectId,
        /// Currently committed generation, if present.
        committed_generation: Option<u64>,
        /// Prior generation declared by the delta.
        prior_generation: Option<u64>,
        /// New generation declared by the delta.
        new_generation: u64,
    },
    /// Delta attempts to mutate an object's owning semantic plane.
    PlaneConflict {
        /// Object identity.
        object_id: ObjectId,
        /// Plane fixed at the object's first revision.
        committed_plane: Plane,
        /// Plane claimed by the offered delta.
        delta_plane: Plane,
    },
    /// Configured `max_objects` ceiling would be exceeded.
    ObjectCapacityExhausted {
        /// Configured ceiling.
        max_objects: u64,
        /// Required live objects.
        required: u64,
    },
    /// Declared successor `state_root` does not equal the incremental Merkle root.
    StateRootMismatch {
        /// Declared root on `batch.new_anchor.state_root`.
        declared: ContentDigest,
        /// Recomputed v2 Radix-Merkle root.
        computed: ContentDigest,
    },
    /// Bounded receipt verification exhausted its explicit work allowance.
    ReceiptProofLimitExceeded {
        /// Resource whose next operation would exceed the allowance.
        resource: super::receipt::ReceiptProofResource,
        /// Amount already charged before the refused operation.
        used: u64,
        /// Additional amount required by the refused operation.
        requested: u64,
        /// Caller-supplied maximum allowance for this resource.
        maximum: u64,
    },
    /// Full-chain verification diverged from live in-memory ledger state.
    LiveStateDivergence(&'static str),
}

impl fmt::Display for EpochLedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(formatter, "invalid epoch ledger config: {msg}"),
            Self::Io(error) => write!(formatter, "epoch ledger I/O error: {error}"),
            Self::WriterLocked => formatter.write_str("epoch ledger already has a writer"),
            Self::AppendIndeterminate {
                epoch_id,
                sequence,
                phase,
                source,
            } => write!(
                formatter,
                "epoch {epoch_id:016} append {sequence} indeterminate at {phase:?}: {source}; reconcile before retry"
            ),
            Self::ReconciliationRequired { sequence } => write!(
                formatter,
                "epoch append {sequence} requires reconciliation before further work"
            ),
            Self::NoPendingAppend => formatter.write_str("no epoch append requires reconciliation"),
            Self::CommittedCheckpointFailed { receipt, source } => write!(
                formatter,
                "epoch append {} committed durably, but checkpoint failed: {source}; repair checkpoint storage and retry force_checkpoint",
                receipt.sequence
            ),
            Self::CorruptEpoch {
                epoch_id,
                offset,
                kind,
            } => write!(
                formatter,
                "corrupt epoch {epoch_id:016} at byte {offset}: {kind:?}"
            ),
            Self::IncompleteTail { epoch_id, offset } => write!(
                formatter,
                "epoch {epoch_id:016} has incomplete tail at byte {offset}"
            ),
            Self::MissingEpoch { expected_epoch_id } => {
                write!(formatter, "missing epoch file {expected_epoch_id:016}.fssj")
            }
            Self::CorruptCheckpoint { path, kind } => {
                write!(formatter, "corrupt checkpoint {}: {kind:?}", path.display())
            }
            Self::Codec(error) => write!(formatter, "epoch batch codec error: {error}"),
            Self::Merkle(error) => write!(formatter, "epoch merkle error: {error}"),
            Self::Contract(error) => write!(formatter, "epoch contract error: {error}"),
            Self::BoundExceeded {
                field,
                length,
                maximum,
            } => write!(
                formatter,
                "batch field {field:?} length {length} exceeds {maximum}"
            ),
            Self::NonCanonicalOrdering { batch_id } => {
                write!(formatter, "batch {batch_id} is not canonically ordered")
            }
            Self::BatchDigestMismatch {
                batch_id,
                declared,
                computed,
            } => write!(
                formatter,
                "batch {batch_id} declares digest {declared}, computed {computed}"
            ),
            Self::DuplicateBatch {
                batch_id,
                committed_sequence,
            } => write!(
                formatter,
                "batch {batch_id} already committed at sequence {committed_sequence}"
            ),
            Self::BatchIdConflict {
                batch_id,
                committed_sequence,
                committed_digest,
                offered_digest,
            } => write!(
                formatter,
                "batch id {batch_id} committed at {committed_sequence} as {committed_digest}, offered as {offered_digest}"
            ),
            Self::SequenceGap {
                head_sequence,
                basis_sequence,
            } => write!(
                formatter,
                "basis sequence {basis_sequence} beyond head {head_sequence}"
            ),
            Self::BasisForked { basis_sequence } => {
                write!(
                    formatter,
                    "basis anchor forked at sequence {basis_sequence}"
                )
            }
            Self::SuccessorConflict {
                basis_sequence,
                head_sequence,
            } => write!(
                formatter,
                "successor conflict on basis {basis_sequence}; head is {head_sequence}"
            ),
            Self::InvalidSuccessorAnchor { field } => {
                write!(formatter, "successor anchor field {field:?} invalid")
            }
            Self::SequenceExhausted => formatter.write_str("u64 sequence space exhausted"),
            Self::DuplicateObjectInBatch { object_id } => {
                write!(formatter, "duplicate object {object_id} in one batch")
            }
            Self::GenerationConflict {
                object_id,
                committed_generation,
                prior_generation,
                new_generation,
            } => write!(
                formatter,
                "object {object_id} committed {committed_generation:?}, delta {prior_generation:?} -> {new_generation}"
            ),
            Self::PlaneConflict {
                object_id,
                committed_plane,
                delta_plane,
            } => write!(
                formatter,
                "object {object_id} plane conflict: committed {committed_plane:?}, offered {delta_plane:?}"
            ),
            Self::ObjectCapacityExhausted {
                max_objects,
                required,
            } => write!(
                formatter,
                "live objects {required} exceed limit {max_objects}"
            ),
            Self::StateRootMismatch { declared, computed } => write!(
                formatter,
                "state root mismatch: declared {declared}, computed {computed}"
            ),
            Self::ReceiptProofLimitExceeded {
                resource,
                used,
                requested,
                maximum,
            } => write!(
                formatter,
                "receipt proof {resource:?} limit exceeded: used {used}, requested {requested}, maximum {maximum}"
            ),
            Self::LiveStateDivergence(reason) => {
                write!(formatter, "full-chain verification diverged: {reason}")
            }
        }
    }
}

impl Error for EpochLedgerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) | Self::AppendIndeterminate { source: error, .. } => Some(error),
            Self::CommittedCheckpointFailed { source, .. } => Some(source.as_ref()),
            Self::Codec(error) => Some(error),
            Self::Merkle(error) => Some(error),
            Self::Contract(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for EpochLedgerError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<BatchCodecError> for EpochLedgerError {
    fn from(value: BatchCodecError) -> Self {
        Self::Codec(value)
    }
}

impl From<MerkleError> for EpochLedgerError {
    fn from(value: MerkleError) -> Self {
        Self::Merkle(value)
    }
}

impl From<ContractError> for EpochLedgerError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}
