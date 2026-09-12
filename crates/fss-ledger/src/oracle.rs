//! Deterministic in-memory canonical ledger oracle (FSS-016).
//!
//! [`LedgerOracle`] models exactly one ordered `EvidenceDeltaBatch` universe for one site lineage
//! and ledger epoch. It is a reference oracle: synchronous, single-owner, bounded, free of ambient
//! time and global state, and deliberately simple. Its admission, delta-application, MVCC read, and
//! state-root rules are written independently of `fss_core::ReferenceLedger`, so differential tests
//! against the durable journal compare two implementations rather than one implementation with
//! itself. The shared definitions are the `fss-core` canonical encoders, `LedgerAnchor::genesis`,
//! and `EvidenceDeltaBatch::computed_digest`.
//!
//! Every offered batch follows one explicit state machine:
//!
//! - `offered -> staged`: [`LedgerOracle::stage`] validates the complete batch and computes the exact
//!   successor state privately. A [`StagedBatch`] is not visible to any read.
//! - `staged -> committed`: [`LedgerOracle::commit`] publishes the staged successor atomically after
//!   re-proving that the head has not moved since staging. A stale stage is refused.
//! - `offered -> rejected`: any failure returns a typed [`OracleError`] and leaves the oracle
//!   bit-identical to its prior state.
//! - `staged -> cancelled`: dropping a [`StagedBatch`] abandons the publication with no trace.
//!
//! The oracle performs no I/O, so it has no indeterminate outcome. A durable adapter whose append
//! becomes indeterminate must reconcile first and then either commit or drop the matching stage.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use fss_core::{
    BatchId, CanonicalEncode, CanonicalEncoder, ContentDigest, ContractError, EvidenceDelta,
    EvidenceDeltaBatch, LedgerAnchor, LedgerSnapshot, ObjectId, ObjectRevision, Plane,
};

/// Registered digest domain for the oracle's append-only history chain root.
pub const LEDGER_ORACLE_HISTORY_DOMAIN: &str = "fss.ledger_oracle_history.v1";
/// Root canonical-encoder domain shared by every FSS canonical digest.
const CANONICAL_DOMAIN: &str = "fss.canonical.v1";
/// Registered digest domain for the materialized reference object state.
const REFERENCE_STATE_DOMAIN: &str = "fss.reference_state.v1";

/// Hard ceiling for the configurable number of committed batches.
pub const MAX_ORACLE_BATCHES: usize = 65_536;
/// Hard ceiling for the configurable number of distinct live objects.
pub const MAX_ORACLE_OBJECTS: usize = 1_048_576;
/// Maximum deltas in one batch; equal to the durable batch-codec bound.
pub const MAX_ORACLE_DELTAS_PER_BATCH: usize = 16_384;
/// Maximum child roots in one batch; equal to the durable batch-codec bound.
pub const MAX_ORACLE_CHILDREN_PER_BATCH: usize = 16_384;
/// Maximum UTF-8 bytes in one text field; equal to the durable batch-codec bound.
pub const MAX_ORACLE_TEXT_BYTES: usize = 4_096;

/// Configuration field rejected by [`OracleLimits::new`] or [`LedgerOracle::new`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleConfigField {
    /// Maximum committed batches.
    MaxBatches,
    /// Maximum distinct live objects.
    MaxObjects,
    /// Site lineage text.
    SiteLineage,
}

/// Bounded batch field whose limit was exceeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleBoundField {
    /// Number of deltas in one batch.
    Deltas,
    /// Number of child roots in one batch.
    Children,
    /// Byte length of one delta identity.
    DeltaIdText,
    /// Byte length of one delta family.
    FamilyText,
    /// Byte length of an anchor site lineage.
    SiteLineageText,
}

/// Successor-anchor field that does not follow its basis anchor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorField {
    /// Site lineage changed.
    SiteLineage,
    /// Ledger epoch changed.
    LedgerEpoch,
    /// Commit sequence is not exactly the basis sequence plus one.
    CommitSequence,
    /// Adapter registry epoch changed.
    AdapterRegistryEpoch,
    /// Schema epoch changed.
    SchemaEpoch,
    /// Policy epoch changed.
    PolicyEpoch,
    /// Privacy epoch changed.
    PrivacyEpoch,
}

/// Safe next action for a rejected oracle operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleGuidance {
    /// The exact batch is already canonical; do not retry.
    AlreadyCommitted,
    /// The input is malformed or self-inconsistent; repair the producer and do not retry as-is.
    RejectInput,
    /// Another batch won the slot; rebase onto the current head and prepare a new batch.
    Rebase,
    /// Predecessor batches are missing; supply them in canonical order first.
    SupplyPredecessors,
    /// A hard capacity bound is reached; archive or rotate before appending.
    ArchiveOrRotate,
    /// The head moved after staging; stage again against the current head.
    Restage,
    /// The oracle configuration is invalid; repair the configuration.
    RepairConfiguration,
}

/// Typed admission failure. A rejected operation never changes oracle state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OracleError {
    /// A configuration value is outside its admitted range.
    InvalidConfig {
        /// Rejected field.
        field: OracleConfigField,
        /// Rejected value (a count or a byte length).
        value: usize,
        /// Largest admitted value; the smallest admitted value is always one.
        maximum: usize,
    },
    /// A bounded batch field exceeds its limit.
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
    /// The declared batch digest does not match the batch content.
    BatchDigestMismatch {
        /// Offered batch identity.
        batch_id: BatchId,
        /// Digest carried by the batch.
        declared: ContentDigest,
        /// Digest recomputed from the batch content.
        computed: ContentDigest,
    },
    /// The exact batch is already committed.
    DuplicateBatch {
        /// Batch identity.
        batch_id: BatchId,
        /// Commit sequence at which it became canonical.
        committed_sequence: u64,
    },
    /// A committed batch already uses this identity with different content.
    BatchIdConflict {
        /// Reused batch identity.
        batch_id: BatchId,
        /// Commit sequence of the canonical batch with this identity.
        committed_sequence: u64,
        /// Digest of the canonical batch.
        committed_digest: ContentDigest,
        /// Digest of the offered batch.
        offered_digest: ContentDigest,
    },
    /// The committed-batch capacity is exhausted.
    CapacityExhausted {
        /// Configured maximum committed batches.
        max_batches: usize,
    },
    /// The batch builds on an anchor beyond the head; predecessors are missing.
    SequenceGap {
        /// Current head commit sequence.
        head_sequence: u64,
        /// Offered basis commit sequence.
        basis_sequence: u64,
    },
    /// The basis anchor is not the committed anchor at its sequence (foreign lineage, epoch, or
    /// state root).
    BasisForked {
        /// Offered basis commit sequence.
        basis_sequence: u64,
    },
    /// A different batch already committed on the same basis (first committer wins).
    SuccessorConflict {
        /// Shared basis commit sequence.
        basis_sequence: u64,
        /// Current head commit sequence.
        head_sequence: u64,
        /// Identity of the batch that already committed on this basis.
        committed_batch_id: BatchId,
    },
    /// The successor anchor does not follow the basis anchor.
    InvalidSuccessorAnchor {
        /// First non-following field in canonical field order.
        field: AnchorField,
    },
    /// The commit-sequence space is exhausted.
    SequenceExhausted,
    /// One batch contains more than one delta for the same object.
    DuplicateObjectInBatch {
        /// Repeated object identity.
        object_id: ObjectId,
    },
    /// A delta's generations do not follow the committed object generation.
    GenerationConflict {
        /// Object identity.
        object_id: ObjectId,
        /// Generation committed at the basis anchor, if the object exists.
        committed_generation: Option<u64>,
        /// Prior generation claimed by the delta.
        prior_generation: Option<u64>,
        /// New generation claimed by the delta.
        new_generation: u64,
    },
    /// Applying the batch would exceed the live-object capacity.
    ObjectCapacityExhausted {
        /// Configured maximum live objects.
        max_objects: usize,
        /// Live objects the batch would require.
        required: usize,
    },
    /// The declared successor state root does not match the applied deltas.
    StateRootMismatch {
        /// State root carried by the successor anchor.
        declared: ContentDigest,
        /// State root recomputed by the oracle.
        computed: ContentDigest,
    },
    /// The head moved after the batch was staged, or the stage belongs to another history.
    StaleStage {
        /// Basis sequence the stage was validated against.
        staged_basis_sequence: u64,
        /// Current head commit sequence.
        head_sequence: u64,
    },
    /// Canonical encoding of a digest input failed its encoder bound.
    Encoding(ContractError),
    /// A delta violates a canonical evidence contract.
    Contract(ContractError),
    /// A delta attempts to mutate an object's semantic plane across revisions.
    PlaneConflict {
        /// Object identity.
        object_id: ObjectId,
        /// Semantic plane committed at prior revision.
        committed_plane: Plane,
        /// Semantic plane attempted in this delta.
        delta_plane: Plane,
    },
}

impl OracleError {
    /// Registered stable error identity.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfig { .. } => "ERR-LEDGER-ORACLE-INVALID-CONFIG-001",
            Self::BoundExceeded { .. } => "ERR-LEDGER-ORACLE-BOUND-001",
            Self::NonCanonicalOrdering { .. } => "ERR-LEDGER-ORACLE-NON-CANONICAL-001",
            Self::BatchDigestMismatch { .. } => "ERR-LEDGER-ORACLE-DIGEST-MISMATCH-001",
            Self::DuplicateBatch { .. } => "ERR-LEDGER-ORACLE-DUPLICATE-BATCH-001",
            Self::BatchIdConflict { .. } => "ERR-LEDGER-ORACLE-BATCH-ID-CONFLICT-001",
            Self::CapacityExhausted { .. } => "ERR-LEDGER-ORACLE-CAPACITY-001",
            Self::SequenceGap { .. } => "ERR-LEDGER-ORACLE-SEQUENCE-GAP-001",
            Self::BasisForked { .. } => "ERR-LEDGER-ORACLE-BASIS-FORKED-001",
            Self::SuccessorConflict { .. } => "ERR-LEDGER-ORACLE-SUCCESSOR-CONFLICT-001",
            Self::InvalidSuccessorAnchor { .. } => "ERR-LEDGER-ORACLE-INVALID-SUCCESSOR-001",
            Self::SequenceExhausted => "ERR-LEDGER-ORACLE-SEQUENCE-EXHAUSTED-001",
            Self::DuplicateObjectInBatch { .. } => "ERR-LEDGER-ORACLE-DUPLICATE-OBJECT-001",
            Self::GenerationConflict { .. } => "ERR-LEDGER-ORACLE-GENERATION-CONFLICT-001",
            Self::ObjectCapacityExhausted { .. } => "ERR-LEDGER-ORACLE-OBJECT-CAPACITY-001",
            Self::StateRootMismatch { .. } => "ERR-LEDGER-ORACLE-STATE-ROOT-MISMATCH-001",
            Self::StaleStage { .. } => "ERR-LEDGER-ORACLE-STALE-STAGE-001",
            Self::Encoding(_) => "ERR-LEDGER-ORACLE-ENCODING-001",
            Self::Contract(_) => "ERR-LEDGER-ORACLE-CONTRACT-001",
            Self::PlaneConflict { .. } => "ERR-LEDGER-ORACLE-PLANE-CONFLICT-001",
        }
    }

    /// Safe next action for this failure.
    #[must_use]
    pub const fn guidance(&self) -> OracleGuidance {
        match self {
            Self::InvalidConfig { .. } => OracleGuidance::RepairConfiguration,
            Self::DuplicateBatch { .. } => OracleGuidance::AlreadyCommitted,
            Self::SuccessorConflict { .. } => OracleGuidance::Rebase,
            Self::SequenceGap { .. } => OracleGuidance::SupplyPredecessors,
            Self::CapacityExhausted { .. }
            | Self::ObjectCapacityExhausted { .. }
            | Self::SequenceExhausted => OracleGuidance::ArchiveOrRotate,
            Self::StaleStage { .. } => OracleGuidance::Restage,
            Self::BoundExceeded { .. }
            | Self::NonCanonicalOrdering { .. }
            | Self::BatchDigestMismatch { .. }
            | Self::BatchIdConflict { .. }
            | Self::BasisForked { .. }
            | Self::InvalidSuccessorAnchor { .. }
            | Self::DuplicateObjectInBatch { .. }
            | Self::GenerationConflict { .. }
            | Self::StateRootMismatch { .. }
            | Self::Encoding(_)
            | Self::Contract(_)
            | Self::PlaneConflict { .. } => OracleGuidance::RejectInput,
        }
    }
}

impl fmt::Display for OracleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: ", self.code())?;
        match self {
            Self::InvalidConfig {
                field,
                value,
                maximum,
            } => write!(
                formatter,
                "oracle config {field:?} value {value} outside 1..={maximum}"
            ),
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
                "batch {batch_id} declares digest {declared} but content digests to {computed}"
            ),
            Self::DuplicateBatch {
                batch_id,
                committed_sequence,
            } => write!(
                formatter,
                "batch {batch_id} is already committed at sequence {committed_sequence}"
            ),
            Self::BatchIdConflict {
                batch_id,
                committed_sequence,
                committed_digest,
                offered_digest,
            } => write!(
                formatter,
                "batch id {batch_id} committed at sequence {committed_sequence} as {committed_digest}, offered as {offered_digest}"
            ),
            Self::CapacityExhausted { max_batches } => {
                write!(
                    formatter,
                    "committed batch capacity {max_batches} exhausted"
                )
            }
            Self::SequenceGap {
                head_sequence,
                basis_sequence,
            } => write!(
                formatter,
                "basis sequence {basis_sequence} is beyond head sequence {head_sequence}"
            ),
            Self::BasisForked { basis_sequence } => write!(
                formatter,
                "basis anchor at sequence {basis_sequence} is not the committed anchor"
            ),
            Self::SuccessorConflict {
                basis_sequence,
                head_sequence,
                committed_batch_id,
            } => write!(
                formatter,
                "batch {committed_batch_id} already committed on basis {basis_sequence}; head is {head_sequence}"
            ),
            Self::InvalidSuccessorAnchor { field } => write!(
                formatter,
                "successor anchor field {field:?} does not follow basis"
            ),
            Self::SequenceExhausted => formatter.write_str("commit sequence space exhausted"),
            Self::DuplicateObjectInBatch { object_id } => {
                write!(formatter, "object {object_id} appears twice in one batch")
            }
            Self::GenerationConflict {
                object_id,
                committed_generation,
                prior_generation,
                new_generation,
            } => write!(
                formatter,
                "object {object_id} committed generation {committed_generation:?}, delta claims {prior_generation:?} -> {new_generation}"
            ),
            Self::ObjectCapacityExhausted {
                max_objects,
                required,
            } => write!(
                formatter,
                "batch requires {required} live objects; capacity is {max_objects}"
            ),
            Self::StateRootMismatch { declared, computed } => write!(
                formatter,
                "successor declares state root {declared} but deltas produce {computed}"
            ),
            Self::StaleStage {
                staged_basis_sequence,
                head_sequence,
            } => write!(
                formatter,
                "stage validated against sequence {staged_basis_sequence}; head is {head_sequence}"
            ),
            Self::Encoding(error) => write!(formatter, "canonical encoding failed: {error}"),
            Self::Contract(error) => write!(formatter, "canonical contract violated: {error}"),
            Self::PlaneConflict {
                object_id,
                committed_plane,
                delta_plane,
            } => write!(
                formatter,
                "object {object_id} committed plane {committed_plane:?}, delta claims {delta_plane:?}"
            ),
        }
    }
}

impl Error for OracleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Encoding(error) | Self::Contract(error) => Some(error),
            _ => None,
        }
    }
}

/// Typed anchor-pinned read failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OracleReadError {
    /// The requested anchor is beyond the committed head.
    BeyondHead {
        /// Requested commit sequence.
        requested: u64,
        /// Current head commit sequence.
        head: u64,
    },
    /// The requested anchor is not the committed anchor at its sequence.
    AnchorMismatch {
        /// Requested commit sequence.
        sequence: u64,
    },
}

impl OracleReadError {
    /// Registered stable error identity.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::BeyondHead { .. } => "ERR-LEDGER-ORACLE-READ-BEYOND-HEAD-001",
            Self::AnchorMismatch { .. } => "ERR-LEDGER-ORACLE-READ-ANCHOR-MISMATCH-001",
        }
    }
}

impl fmt::Display for OracleReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeyondHead { requested, head } => write!(
                formatter,
                "{}: read at sequence {requested} is beyond head {head}",
                self.code()
            ),
            Self::AnchorMismatch { sequence } => write!(
                formatter,
                "{}: anchor at sequence {sequence} is not committed in this history",
                self.code()
            ),
        }
    }
}

impl Error for OracleReadError {}

/// Failure while rebuilding an oracle from an ordered batch sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OracleReplayError {
    /// The oracle could not be constructed.
    Config(OracleError),
    /// The batch at `position` (zero-based) was rejected.
    Batch {
        /// Zero-based position in the replayed sequence.
        position: usize,
        /// Typed rejection.
        error: Box<OracleError>,
    },
}

impl fmt::Display for OracleReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(formatter, "oracle replay config error: {error}"),
            Self::Batch { position, error } => {
                write!(
                    formatter,
                    "oracle replay rejected batch {position}: {error}"
                )
            }
        }
    }
}

impl Error for OracleReplayError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::Batch { error, .. } => Some(error.as_ref()),
        }
    }
}

/// Validated hard bounds for one oracle instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OracleLimits {
    max_batches: usize,
    max_objects: usize,
}

impl OracleLimits {
    /// The largest admitted limits.
    pub const CEILING: Self = Self {
        max_batches: MAX_ORACLE_BATCHES,
        max_objects: MAX_ORACLE_OBJECTS,
    };

    /// Validates limits: each must be in `1..=` its hard ceiling.
    pub fn new(max_batches: usize, max_objects: usize) -> Result<Self, OracleError> {
        if max_batches == 0 || max_batches > MAX_ORACLE_BATCHES {
            return Err(OracleError::InvalidConfig {
                field: OracleConfigField::MaxBatches,
                value: max_batches,
                maximum: MAX_ORACLE_BATCHES,
            });
        }
        if max_objects == 0 || max_objects > MAX_ORACLE_OBJECTS {
            return Err(OracleError::InvalidConfig {
                field: OracleConfigField::MaxObjects,
                value: max_objects,
                maximum: MAX_ORACLE_OBJECTS,
            });
        }
        Ok(Self {
            max_batches,
            max_objects,
        })
    }

    /// Maximum committed batches.
    #[must_use]
    pub const fn max_batches(&self) -> usize {
        self.max_batches
    }

    /// Maximum distinct live objects.
    #[must_use]
    pub const fn max_objects(&self) -> usize {
        self.max_objects
    }
}

/// A fully validated successor that is not yet visible.
///
/// A stage is single-use and bound to the exact head (sequence and history root) it was validated
/// against. Dropping it cancels the publication.
#[derive(Clone, Debug)]
pub struct StagedBatch {
    batch: EvidenceDeltaBatch,
    basis_sequence: u64,
    basis_history_root: ContentDigest,
    next_objects: BTreeMap<ObjectId, ObjectRevision>,
    changes: Vec<(ObjectId, ObjectRevision)>,
    history_root: ContentDigest,
}

impl StagedBatch {
    /// The validated batch.
    #[must_use]
    pub const fn batch(&self) -> &EvidenceDeltaBatch {
        &self.batch
    }

    /// Consumes the staged batch, returning the inner validated evidence delta batch.
    #[must_use]
    pub fn into_batch(self) -> EvidenceDeltaBatch {
        self.batch
    }

    /// Basis commit sequence the stage was validated against.
    #[must_use]
    pub const fn basis_sequence(&self) -> u64 {
        self.basis_sequence
    }

    /// Basis history root the stage was validated against.
    #[must_use]
    pub const fn basis_history_root(&self) -> ContentDigest {
        self.basis_history_root
    }

    /// Revisions applied by this staged batch.
    #[must_use]
    pub fn changes(&self) -> &[(ObjectId, ObjectRevision)] {
        &self.changes
    }

    /// History root the oracle will have if this stage commits.
    #[must_use]
    pub const fn history_root(&self) -> ContentDigest {
        self.history_root
    }
}

/// Proof that one batch became canonical.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    /// Commit sequence of the batch.
    pub sequence: u64,
    /// Committed batch identity.
    pub batch_id: BatchId,
    /// Committed batch digest.
    pub batch_digest: ContentDigest,
    /// Anchor at which the batch is visible.
    pub anchor: LedgerAnchor,
    /// History chain root through this batch.
    pub history_root: ContentDigest,
}

/// Deterministic identity of the complete oracle state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleFingerprint {
    /// Head anchor, including the materialized state root.
    pub head_anchor: LedgerAnchor,
    /// History chain root through the head.
    pub history_root: ContentDigest,
    /// Number of committed batches.
    pub batch_count: usize,
    /// Number of live objects at the head.
    pub object_count: usize,
}

/// Result of reading one object at an exact anchor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectRead<'a> {
    /// The object exists at the anchor.
    Present {
        /// Revision visible at the anchor.
        revision: &'a ObjectRevision,
        /// Commit sequence that produced this revision.
        committed_sequence: u64,
    },
    /// The object has no revision at or before the anchor. The oracle holds the complete state,
    /// so this absence is exact for this anchor and no other.
    AbsentAtAnchor {
        /// Anchor sequence at which absence holds.
        sequence: u64,
    },
}

#[derive(Clone, Debug)]
struct CommittedEntry {
    batch: EvidenceDeltaBatch,
    history_root: ContentDigest,
}

/// Deterministic in-memory canonical ledger oracle for one ordered batch universe.
#[derive(Clone, Debug)]
pub struct LedgerOracle {
    limits: OracleLimits,
    genesis: LedgerAnchor,
    genesis_history_root: ContentDigest,
    entries: Vec<CommittedEntry>,
    batch_index: BTreeMap<BatchId, (u64, ContentDigest)>,
    head_objects: BTreeMap<ObjectId, ObjectRevision>,
    revisions: BTreeMap<ObjectId, Vec<(u64, ObjectRevision)>>,
}

impl LedgerOracle {
    /// Creates an empty oracle at the genesis anchor of `site_lineage`.
    ///
    /// The lineage must be 1 to [`MAX_ORACLE_TEXT_BYTES`] bytes. The genesis state root is
    /// recomputed independently and must equal `LedgerAnchor::genesis`.
    pub fn new(site_lineage: impl Into<String>, limits: OracleLimits) -> Result<Self, OracleError> {
        let site_lineage = site_lineage.into();
        if site_lineage.is_empty() || site_lineage.len() > MAX_ORACLE_TEXT_BYTES {
            return Err(OracleError::InvalidConfig {
                field: OracleConfigField::SiteLineage,
                value: site_lineage.len(),
                maximum: MAX_ORACLE_TEXT_BYTES,
            });
        }
        let genesis = LedgerAnchor::genesis(site_lineage);
        let computed = state_root(&BTreeMap::new())?;
        if computed != genesis.state_root {
            return Err(OracleError::StateRootMismatch {
                declared: genesis.state_root,
                computed,
            });
        }
        let genesis_history_root = genesis_history_root(&genesis)?;
        Ok(Self {
            limits,
            genesis,
            genesis_history_root,
            entries: Vec::new(),
            batch_index: BTreeMap::new(),
            head_objects: BTreeMap::new(),
            revisions: BTreeMap::new(),
        })
    }

    /// Rebuilds an oracle by replaying `batches` in order through [`LedgerOracle::append`].
    pub fn rebuild(
        site_lineage: impl Into<String>,
        limits: OracleLimits,
        batches: impl IntoIterator<Item = EvidenceDeltaBatch>,
    ) -> Result<Self, OracleReplayError> {
        let mut oracle = Self::new(site_lineage, limits).map_err(OracleReplayError::Config)?;
        for (position, batch) in batches.into_iter().enumerate() {
            oracle
                .append(batch)
                .map_err(|error| OracleReplayError::Batch {
                    position,
                    error: Box::new(error),
                })?;
        }
        Ok(oracle)
    }

    /// Configured limits.
    #[must_use]
    pub const fn limits(&self) -> OracleLimits {
        self.limits
    }

    /// Genesis anchor of this history.
    #[must_use]
    pub const fn genesis_anchor(&self) -> &LedgerAnchor {
        &self.genesis
    }

    /// Latest committed anchor.
    #[must_use]
    pub fn head_anchor(&self) -> &LedgerAnchor {
        self.entries
            .last()
            .map_or(&self.genesis, |entry| &entry.batch.new_anchor)
    }

    /// Latest committed sequence; zero at genesis.
    #[must_use]
    pub fn head_sequence(&self) -> u64 {
        self.head_anchor().commit_sequence
    }

    /// History chain root through the head.
    #[must_use]
    pub fn head_history_root(&self) -> ContentDigest {
        self.entries
            .last()
            .map_or(self.genesis_history_root, |entry| entry.history_root)
    }

    /// Number of committed batches.
    #[must_use]
    pub fn batch_count(&self) -> usize {
        self.entries.len()
    }

    /// Committed batches in canonical order.
    pub fn batches(&self) -> impl ExactSizeIterator<Item = &EvidenceDeltaBatch> {
        self.entries.iter().map(|entry| &entry.batch)
    }

    /// Deterministic identity of the complete oracle state.
    #[must_use]
    pub fn fingerprint(&self) -> OracleFingerprint {
        OracleFingerprint {
            head_anchor: self.head_anchor().clone(),
            history_root: self.head_history_root(),
            batch_count: self.entries.len(),
            object_count: self.head_objects.len(),
        }
    }

    /// Pins a read to the committed anchor at `sequence`.
    pub fn view_at(&self, sequence: u64) -> Result<AnchoredView<'_>, OracleReadError> {
        let beyond = OracleReadError::BeyondHead {
            requested: sequence,
            head: self.head_sequence(),
        };
        let anchor = self.anchor_at(sequence).ok_or_else(|| beyond.clone())?;
        let history_root = self
            .history_root_at(sequence)
            .ok_or_else(|| beyond.clone())?;
        let batch_limit = sequence_index(sequence).ok_or(beyond)?;
        Ok(AnchoredView {
            oracle: self,
            sequence,
            anchor,
            history_root,
            batch_limit,
        })
    }

    /// Pins a read to an exact anchor, which must be committed in this history.
    pub fn view_at_anchor(
        &self,
        anchor: &LedgerAnchor,
    ) -> Result<AnchoredView<'_>, OracleReadError> {
        let view = self.view_at(anchor.commit_sequence)?;
        if view.anchor() != anchor {
            return Err(OracleReadError::AnchorMismatch {
                sequence: anchor.commit_sequence,
            });
        }
        Ok(view)
    }

    /// Prepares the canonical successor of the head without staging or publishing it.
    ///
    /// Deltas are sorted into canonical order and child roots are sorted and deduplicated. The
    /// same bound, generation, and object-capacity checks as [`LedgerOracle::stage`] apply.
    pub fn prepare_batch(
        &self,
        batch_id: BatchId,
        mut deltas: Vec<EvidenceDelta>,
        child_roots: impl IntoIterator<Item = ContentDigest>,
    ) -> Result<EvidenceDeltaBatch, OracleError> {
        if self.entries.len() >= self.limits.max_batches {
            return Err(OracleError::CapacityExhausted {
                max_batches: self.limits.max_batches,
            });
        }
        deltas.sort_by(|left, right| delta_order_key(left).cmp(&delta_order_key(right)));
        let mut children: Vec<ContentDigest> = child_roots.into_iter().collect();
        children.sort_unstable();
        children.dedup();
        let basis_anchor = self.head_anchor().clone();
        check_counts(deltas.len(), children.len())?;
        check_texts(&deltas, &basis_anchor, &basis_anchor)?;
        check_deltas(&deltas)?;
        let (next_objects, _) = apply_deltas(&self.head_objects, &deltas, self.limits.max_objects)?;
        let mut new_anchor = basis_anchor.clone();
        new_anchor.commit_sequence = basis_anchor
            .commit_sequence
            .checked_add(1)
            .ok_or(OracleError::SequenceExhausted)?;
        new_anchor.state_root = state_root(&next_objects)?;
        let mut batch = EvidenceDeltaBatch {
            batch_id,
            basis_anchor,
            new_anchor,
            deltas,
            children,
            batch_digest: ContentDigest::sha256(b"unpublished"),
        };
        batch.batch_digest = batch.computed_digest();
        Ok(batch)
    }

    /// Checks whether `staged` is still valid against the current head without consuming it.
    pub fn check_stage(&self, staged: &StagedBatch) -> Result<(), OracleError> {
        let head_sequence = self.head_sequence();
        if staged.basis_sequence != head_sequence
            || staged.basis_history_root != self.head_history_root()
        {
            return Err(OracleError::StaleStage {
                staged_basis_sequence: staged.basis_sequence,
                head_sequence,
            });
        }
        if self.entries.len() >= self.limits.max_batches {
            return Err(OracleError::CapacityExhausted {
                max_batches: self.limits.max_batches,
            });
        }
        if staged.next_objects.len() > self.limits.max_objects {
            return Err(OracleError::ObjectCapacityExhausted {
                max_objects: self.limits.max_objects,
                required: staged.next_objects.len(),
            });
        }
        Ok(())
    }

    /// Validates `batch` completely against the head and returns a private stage.
    ///
    /// Checks run in a fixed order: per-batch bounds, canonical ordering, batch digest, identity
    /// (duplicate or conflicting reuse), batch capacity, basis position (gap, fork, or lost
    /// first-committer race), successor anchor, delta generations, object capacity, and state root.
    pub fn stage(&self, batch: EvidenceDeltaBatch) -> Result<StagedBatch, OracleError> {
        check_counts(batch.deltas.len(), batch.children.len())?;
        check_texts(&batch.deltas, &batch.basis_anchor, &batch.new_anchor)?;
        check_deltas(&batch.deltas)?;
        if !is_canonically_ordered(&batch) {
            return Err(OracleError::NonCanonicalOrdering {
                batch_id: batch.batch_id,
            });
        }
        let computed = batch.computed_digest();
        if computed != batch.batch_digest {
            return Err(OracleError::BatchDigestMismatch {
                batch_id: batch.batch_id,
                declared: batch.batch_digest,
                computed,
            });
        }
        if let Some(&(committed_sequence, committed_digest)) = self.batch_index.get(&batch.batch_id)
        {
            return Err(if committed_digest == batch.batch_digest {
                OracleError::DuplicateBatch {
                    batch_id: batch.batch_id,
                    committed_sequence,
                }
            } else {
                OracleError::BatchIdConflict {
                    batch_id: batch.batch_id,
                    committed_sequence,
                    committed_digest,
                    offered_digest: batch.batch_digest,
                }
            });
        }
        if self.entries.len() >= self.limits.max_batches {
            return Err(OracleError::CapacityExhausted {
                max_batches: self.limits.max_batches,
            });
        }

        let head_sequence = self.head_sequence();
        let basis_sequence = batch.basis_anchor.commit_sequence;
        if basis_sequence > head_sequence {
            return Err(OracleError::SequenceGap {
                head_sequence,
                basis_sequence,
            });
        }
        if self.anchor_at(basis_sequence) != Some(&batch.basis_anchor) {
            return Err(OracleError::BasisForked { basis_sequence });
        }
        if basis_sequence < head_sequence {
            return Err(
                match sequence_index(basis_sequence).and_then(|index| self.entries.get(index)) {
                    Some(winner) => OracleError::SuccessorConflict {
                        basis_sequence,
                        head_sequence,
                        committed_batch_id: winner.batch.batch_id.clone(),
                    },
                    None => OracleError::SequenceGap {
                        head_sequence,
                        basis_sequence,
                    },
                },
            );
        }

        let expected_sequence = head_sequence
            .checked_add(1)
            .ok_or(OracleError::SequenceExhausted)?;
        check_successor(&batch.basis_anchor, &batch.new_anchor, expected_sequence)?;

        let (next_objects, changes) =
            apply_deltas(&self.head_objects, &batch.deltas, self.limits.max_objects)?;
        let computed_root = state_root(&next_objects)?;
        if computed_root != batch.new_anchor.state_root {
            return Err(OracleError::StateRootMismatch {
                declared: batch.new_anchor.state_root,
                computed: computed_root,
            });
        }
        let basis_history_root = self.head_history_root();
        let history_root = successor_history_root(
            basis_history_root,
            expected_sequence,
            batch.batch_digest,
            &batch.new_anchor,
        )?;
        Ok(StagedBatch {
            batch,
            basis_sequence: head_sequence,
            basis_history_root,
            next_objects,
            changes,
            history_root,
        })
    }

    /// Atomically publishes a stage validated against the current head.
    ///
    /// All checks precede the first mutation, and every mutation after them is infallible, so a
    /// refused commit leaves the oracle unchanged.
    pub fn commit(&mut self, staged: StagedBatch) -> Result<CommitReceipt, OracleError> {
        let head_sequence = self.head_sequence();
        if staged.basis_sequence != head_sequence
            || staged.basis_history_root != self.head_history_root()
        {
            return Err(OracleError::StaleStage {
                staged_basis_sequence: staged.basis_sequence,
                head_sequence,
            });
        }
        if self.entries.len() >= self.limits.max_batches {
            return Err(OracleError::CapacityExhausted {
                max_batches: self.limits.max_batches,
            });
        }
        if staged.next_objects.len() > self.limits.max_objects {
            return Err(OracleError::ObjectCapacityExhausted {
                max_objects: self.limits.max_objects,
                required: staged.next_objects.len(),
            });
        }
        let StagedBatch {
            batch,
            next_objects,
            changes,
            history_root,
            ..
        } = staged;
        let sequence = batch.new_anchor.commit_sequence;
        let receipt = CommitReceipt {
            sequence,
            batch_id: batch.batch_id.clone(),
            batch_digest: batch.batch_digest,
            anchor: batch.new_anchor.clone(),
            history_root,
        };
        for (object_id, revision) in changes {
            self.revisions
                .entry(object_id)
                .or_default()
                .push((sequence, revision));
        }
        self.batch_index
            .insert(batch.batch_id.clone(), (sequence, batch.batch_digest));
        self.head_objects = next_objects;
        self.entries.push(CommittedEntry {
            batch,
            history_root,
        });
        Ok(receipt)
    }

    /// Stages and commits `batch` as one atomic operation.
    pub fn append(&mut self, batch: EvidenceDeltaBatch) -> Result<CommitReceipt, OracleError> {
        let staged = self.stage(batch)?;
        self.commit(staged)
    }

    fn anchor_at(&self, sequence: u64) -> Option<&LedgerAnchor> {
        if sequence == 0 {
            return Some(&self.genesis);
        }
        let index = sequence_index(sequence.checked_sub(1)?)?;
        self.entries.get(index).map(|entry| &entry.batch.new_anchor)
    }

    fn history_root_at(&self, sequence: u64) -> Option<ContentDigest> {
        if sequence == 0 {
            return Some(self.genesis_history_root);
        }
        let index = sequence_index(sequence.checked_sub(1)?)?;
        self.entries.get(index).map(|entry| entry.history_root)
    }
}

/// An immutable read pinned to one committed anchor. It never observes later batches.
#[derive(Clone, Copy, Debug)]
pub struct AnchoredView<'a> {
    oracle: &'a LedgerOracle,
    sequence: u64,
    anchor: &'a LedgerAnchor,
    history_root: ContentDigest,
    batch_limit: usize,
}

impl<'a> AnchoredView<'a> {
    /// Pinned commit sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Pinned anchor.
    #[must_use]
    pub const fn anchor(&self) -> &'a LedgerAnchor {
        self.anchor
    }

    /// History chain root through the pinned anchor.
    #[must_use]
    pub const fn history_root(&self) -> ContentDigest {
        self.history_root
    }

    /// Batches committed at or before the pinned anchor, in canonical order.
    pub fn batches(&self) -> impl Iterator<Item = &'a EvidenceDeltaBatch> + use<'a> {
        self.oracle
            .entries
            .iter()
            .take(self.batch_limit)
            .map(|entry| &entry.batch)
    }

    /// Reads one object exactly as of the pinned anchor.
    #[must_use]
    pub fn object(&self, object_id: &ObjectId) -> ObjectRead<'a> {
        self.oracle
            .revisions
            .get(object_id)
            .and_then(|history| revision_at(history, self.sequence))
            .map_or(
                ObjectRead::AbsentAtAnchor {
                    sequence: self.sequence,
                },
                |(committed_sequence, revision)| ObjectRead::Present {
                    revision,
                    committed_sequence,
                },
            )
    }

    /// Materializes the complete object state at the pinned anchor.
    #[must_use]
    pub fn snapshot(&self) -> LedgerSnapshot {
        let objects = self
            .oracle
            .revisions
            .iter()
            .filter_map(|(object_id, history)| {
                revision_at(history, self.sequence)
                    .map(|(_, revision)| (object_id.clone(), revision.clone()))
            })
            .collect();
        LedgerSnapshot {
            anchor: self.anchor.clone(),
            objects,
        }
    }
}

fn revision_at(history: &[(u64, ObjectRevision)], sequence: u64) -> Option<(u64, &ObjectRevision)> {
    let visible = history.partition_point(|(committed, _)| *committed <= sequence);
    let index = visible.checked_sub(1)?;
    history
        .get(index)
        .map(|(committed, revision)| (*committed, revision))
}

fn sequence_index(sequence: u64) -> Option<usize> {
    usize::try_from(sequence).ok()
}

fn delta_order_key(delta: &EvidenceDelta) -> (&str, &str, u64, &str) {
    (
        delta.family.as_str(),
        delta.object_id.as_str(),
        delta.new_generation,
        delta.delta_id.as_str(),
    )
}

fn is_canonically_ordered(batch: &EvidenceDeltaBatch) -> bool {
    let deltas_ordered = batch.deltas.windows(2).all(|pair| match pair {
        [left, right] => delta_order_key(left) < delta_order_key(right),
        _ => false,
    });
    let children_ordered = batch.children.windows(2).all(|pair| match pair {
        [left, right] => left < right,
        _ => false,
    });
    deltas_ordered && children_ordered
}

fn check_counts(deltas: usize, children: usize) -> Result<(), OracleError> {
    if deltas > MAX_ORACLE_DELTAS_PER_BATCH {
        return Err(OracleError::BoundExceeded {
            field: OracleBoundField::Deltas,
            length: deltas,
            maximum: MAX_ORACLE_DELTAS_PER_BATCH,
        });
    }
    if children > MAX_ORACLE_CHILDREN_PER_BATCH {
        return Err(OracleError::BoundExceeded {
            field: OracleBoundField::Children,
            length: children,
            maximum: MAX_ORACLE_CHILDREN_PER_BATCH,
        });
    }
    Ok(())
}

fn check_text(field: OracleBoundField, value: &str) -> Result<(), OracleError> {
    if value.len() > MAX_ORACLE_TEXT_BYTES {
        return Err(OracleError::BoundExceeded {
            field,
            length: value.len(),
            maximum: MAX_ORACLE_TEXT_BYTES,
        });
    }
    Ok(())
}

fn check_texts(
    deltas: &[EvidenceDelta],
    basis: &LedgerAnchor,
    successor: &LedgerAnchor,
) -> Result<(), OracleError> {
    check_text(OracleBoundField::SiteLineageText, &basis.site_lineage)?;
    check_text(OracleBoundField::SiteLineageText, &successor.site_lineage)?;
    for delta in deltas {
        check_text(OracleBoundField::DeltaIdText, &delta.delta_id)?;
        check_text(OracleBoundField::FamilyText, &delta.family)?;
    }
    Ok(())
}

fn check_deltas(deltas: &[EvidenceDelta]) -> Result<(), OracleError> {
    for delta in deltas {
        if delta.delta_id.is_empty() || delta.family.is_empty() {
            return Err(OracleError::Contract(ContractError::InvalidIdentifier));
        }
        if delta.validity.earliest > delta.validity.latest {
            return Err(OracleError::Contract(ContractError::InvertedTimeInterval));
        }
    }
    Ok(())
}

fn check_successor(
    basis: &LedgerAnchor,
    successor: &LedgerAnchor,
    expected_sequence: u64,
) -> Result<(), OracleError> {
    let field = if successor.site_lineage != basis.site_lineage {
        Some(AnchorField::SiteLineage)
    } else if successor.ledger_epoch != basis.ledger_epoch {
        Some(AnchorField::LedgerEpoch)
    } else if successor.commit_sequence != expected_sequence {
        Some(AnchorField::CommitSequence)
    } else if successor.adapter_registry_epoch != basis.adapter_registry_epoch {
        Some(AnchorField::AdapterRegistryEpoch)
    } else if successor.schema_epoch != basis.schema_epoch {
        Some(AnchorField::SchemaEpoch)
    } else if successor.policy_epoch != basis.policy_epoch {
        Some(AnchorField::PolicyEpoch)
    } else if successor.privacy_epoch != basis.privacy_epoch {
        Some(AnchorField::PrivacyEpoch)
    } else {
        None
    };
    match field {
        Some(field) => Err(OracleError::InvalidSuccessorAnchor { field }),
        None => Ok(()),
    }
}

type AppliedDeltas = (
    BTreeMap<ObjectId, ObjectRevision>,
    Vec<(ObjectId, ObjectRevision)>,
);

fn apply_deltas(
    basis: &BTreeMap<ObjectId, ObjectRevision>,
    deltas: &[EvidenceDelta],
    max_objects: usize,
) -> Result<AppliedDeltas, OracleError> {
    let mut next = basis.clone();
    let mut touched = BTreeSet::new();
    let mut changes = Vec::with_capacity(deltas.len());
    for delta in deltas {
        if !touched.insert(&delta.object_id) {
            return Err(OracleError::DuplicateObjectInBatch {
                object_id: delta.object_id.clone(),
            });
        }
        let committed_revision = basis.get(&delta.object_id);
        let committed_generation = committed_revision.map(|revision| revision.generation);
        let follows = match committed_generation {
            Some(generation) => {
                delta.prior_generation == Some(generation)
                    && generation.checked_add(1) == Some(delta.new_generation)
            }
            None => delta.prior_generation.is_none() && delta.new_generation == 1,
        };
        if !follows {
            return Err(OracleError::GenerationConflict {
                object_id: delta.object_id.clone(),
                committed_generation,
                prior_generation: delta.prior_generation,
                new_generation: delta.new_generation,
            });
        }
        if let Some(existing) = committed_revision
            && delta.plane != existing.plane
        {
            return Err(OracleError::PlaneConflict {
                object_id: delta.object_id.clone(),
                committed_plane: existing.plane,
                delta_plane: delta.plane,
            });
        }
        let revision = ObjectRevision {
            generation: delta.new_generation,
            family: delta.family.clone(),
            plane: delta.plane,
            payload_digest: delta.payload_digest,
            validity: delta.validity,
        };
        next.insert(delta.object_id.clone(), revision.clone());
        changes.push((delta.object_id.clone(), revision));
    }
    if next.len() > max_objects {
        return Err(OracleError::ObjectCapacityExhausted {
            max_objects,
            required: next.len(),
        });
    }
    Ok((next, changes))
}

fn state_root(objects: &BTreeMap<ObjectId, ObjectRevision>) -> Result<ContentDigest, OracleError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(REFERENCE_STATE_DOMAIN);
    encoder.u64(objects.len() as u64);
    for (object_id, revision) in objects {
        object_id.encode_canonical(&mut encoder);
        revision.encode_canonical(&mut encoder);
    }
    let bytes = encoder.finish_checked().map_err(OracleError::Encoding)?;
    Ok(ContentDigest::sha256(&bytes))
}

fn genesis_history_root(genesis: &LedgerAnchor) -> Result<ContentDigest, OracleError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(CANONICAL_DOMAIN);
    encoder.text(LEDGER_ORACLE_HISTORY_DOMAIN);
    encoder.tag(0);
    genesis.encode_canonical(&mut encoder);
    let bytes = encoder.finish_checked().map_err(OracleError::Encoding)?;
    Ok(ContentDigest::sha256(&bytes))
}

fn successor_history_root(
    previous: ContentDigest,
    sequence: u64,
    batch_digest: ContentDigest,
    new_anchor: &LedgerAnchor,
) -> Result<ContentDigest, OracleError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(CANONICAL_DOMAIN);
    encoder.text(LEDGER_ORACLE_HISTORY_DOMAIN);
    encoder.tag(1);
    encoder.digest(previous);
    encoder.u64(sequence);
    encoder.digest(batch_digest);
    new_anchor.encode_canonical(&mut encoder);
    let bytes = encoder.finish_checked().map_err(OracleError::Encoding)?;
    Ok(ContentDigest::sha256(&bytes))
}
