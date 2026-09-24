//! Crash-safe evidence-history wrapper proving restart equivalence.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

use fss_core::{
    AuthoritativeLedger, BatchId, ContentDigest, ContractError, DigestAlgorithm, EvidenceDelta,
    EvidenceDeltaBatch, LedgerSnapshot, ReferenceLedger,
};

use crate::{
    AppendPhase, AppendReconciliation, BatchCodecError, ExternalMutationKind, ForeignRange,
    IncompleteTailPolicy, Journal, JournalError, RecoveryReport, RepairError, decode_batch,
    encode_batch,
};

const EVIDENCE_BATCH_RECORD_KIND: u16 = 1;

/// Registered stable error ID for a committed durable batch identity reused with different content.
pub const ERR_LEDGER_DURABLE_BATCH_ID_CONFLICT_001: &str =
    "ERR-LEDGER-DURABLE-BATCH-ID-CONFLICT-001";

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
    /// A committed batch already uses this stable identity with different content.
    ///
    /// Stable batch IDs are never reused. An identical resubmission is not this error; it keeps
    /// its idempotent-duplicate classification.
    BatchIdConflict {
        /// Reused batch identity.
        batch_id: BatchId,
        /// Commit sequence of the canonical batch that owns this identity.
        committed_sequence: u64,
        /// Content digest of the canonical batch.
        committed_digest: ContentDigest,
        /// Content digest of the offered batch.
        offered_digest: ContentDigest,
    },
    /// A journal record header sequence does not match the decoded batch commit sequence.
    RecordSequenceMismatch {
        /// Sequence recorded in the journal record header.
        record_sequence: u64,
        /// Commit sequence declared by the decoded batch new anchor.
        batch_commit_sequence: u64,
    },
    /// A journal path is a symlink or the wrong file type.
    InvalidLayout {
        /// Offending path.
        path: PathBuf,
    },
    /// Journal file length exceeded configured byte limit.
    OverBudget {
        /// Configured limit in bytes.
        limit: usize,
        /// Observed actual length in bytes.
        actual: usize,
    },
    /// Low-level repair or doctor failure (boxed: it carries digests and paths).
    Repair(Box<RepairError>),
    /// Low-level journal I/O failure.
    Io(std::io::Error),
}

impl DurableLedgerError {
    /// Stable registered error identity if defined.
    #[must_use]
    pub const fn stable_id(&self) -> Option<&'static str> {
        match self {
            Self::Journal(error) => error.stable_id(),
            Self::BatchIdConflict { .. } => Some(ERR_LEDGER_DURABLE_BATCH_ID_CONFLICT_001),
            Self::Codec(_)
            | Self::Contract(_)
            | Self::UnexpectedRecordKind { .. }
            | Self::RecordSequenceMismatch { .. }
            | Self::InvalidLayout { .. }
            | Self::OverBudget { .. }
            | Self::Repair(_)
            | Self::Io(_) => None,
        }
    }
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
            Self::RecordSequenceMismatch {
                record_sequence,
                batch_commit_sequence,
            } => write!(
                formatter,
                "durable ledger journal record sequence {record_sequence} does not match batch commit sequence {batch_commit_sequence}"
            ),
            Self::BatchIdConflict {
                batch_id,
                committed_sequence,
                committed_digest,
                offered_digest,
            } => write!(
                formatter,
                "durable ledger batch id {batch_id} committed at sequence {committed_sequence} as {committed_digest}, offered as {offered_digest} ({ERR_LEDGER_DURABLE_BATCH_ID_CONFLICT_001})"
            ),
            Self::InvalidLayout { path } => {
                write!(
                    formatter,
                    "durable ledger path is not a regular file: {}",
                    path.display()
                )
            }
            Self::OverBudget { limit, actual } => {
                write!(
                    formatter,
                    "durable ledger size {actual} bytes exceeds limit of {limit} bytes"
                )
            }
            Self::Repair(error) => write!(formatter, "durable ledger repair error: {error}"),
            Self::Io(error) => write!(formatter, "durable ledger I/O error: {error}"),
        }
    }
}

impl Error for DurableLedgerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Journal(error) => Some(error),
            Self::Codec(error) => Some(error),
            Self::Contract(error) => Some(error),
            Self::Repair(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::UnexpectedRecordKind { .. }
            | Self::BatchIdConflict { .. }
            | Self::RecordSequenceMismatch { .. }
            | Self::InvalidLayout { .. }
            | Self::OverBudget { .. } => None,
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

impl From<RepairError> for DurableLedgerError {
    fn from(value: RepairError) -> Self {
        match value {
            RepairError::Journal(error) => Self::Journal(error),
            RepairError::Io(error) => Self::Io(error),
            RepairError::OverBudget { limit, actual } => Self::OverBudget { limit, actual },
            other => Self::Repair(Box::new(other)),
        }
    }
}

impl From<std::io::Error> for DurableLedgerError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
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

/// Stable identity of one committed batch: its commit sequence and content digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CommittedIdentity {
    commit_sequence: u64,
    batch_digest: ContentDigest,
}

impl CommittedIdentity {
    const fn of(batch: &EvidenceDeltaBatch) -> Self {
        Self {
            commit_sequence: batch.new_anchor.commit_sequence,
            batch_digest: batch.batch_digest,
        }
    }
}

/// Index of every committed stable batch identity.
///
/// It holds exactly one entry per batch in the durable committed prefix, so it is bounded by the
/// history the wrapped `ReferenceLedger` already retains. It is rebuilt from the journal by
/// `replay_report` on open and on `verify_storage`; it is never the sole record of an identity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct BatchIdentityIndex {
    committed: BTreeMap<BatchId, CommittedIdentity>,
}

impl BatchIdentityIndex {
    /// Refuses `batch` when a committed batch owns its identity with different content.
    ///
    /// Content identity is the recomputed canonical batch digest. An identical resubmission passes
    /// this check unchanged, so it keeps the existing duplicate classification from the core
    /// ledger (`ContractError::StaleAnchor`) and never becomes a conflict.
    fn check_not_reused(&self, batch: &EvidenceDeltaBatch) -> Result<(), DurableLedgerError> {
        let Some(committed) = self.committed.get(&batch.batch_id) else {
            return Ok(());
        };
        let offered_digest = batch.computed_digest();
        if offered_digest == committed.batch_digest {
            return Ok(());
        }
        Err(DurableLedgerError::BatchIdConflict {
            batch_id: batch.batch_id.clone(),
            committed_sequence: committed.commit_sequence,
            committed_digest: committed.batch_digest,
            offered_digest,
        })
    }

    /// Records one batch that has just become canonical.
    fn insert(&mut self, batch_id: BatchId, identity: CommittedIdentity) {
        self.committed.insert(batch_id, identity);
    }
}

#[derive(Clone, Debug)]
struct PendingLedgerAppend {
    candidate: ReferenceLedger,
    sequence: u64,
    batch_id: BatchId,
    identity: CommittedIdentity,
}

/// Durable wrapper around the deterministic in-memory reference ledger.
///
/// On open, every committed journal record is decoded and replayed through the same
/// batch-identity check and `ReferenceLedger::append` checks used by live publication. This makes
/// restart state a deterministic function of the durable committed prefix.
#[derive(Debug)]
pub struct DurableReferenceLedger {
    journal: Journal,
    ledger: ReferenceLedger,
    identities: BatchIdentityIndex,
    pending: Option<PendingLedgerAppend>,
}

impl DurableReferenceLedger {
    /// Opens, verifies, and replays the durable evidence history.
    ///
    /// When tail truncation is requested, the complete committed prefix is semantically replayed
    /// before any repair mutation is allowed. A malformed batch, unsupported record kind, stale
    /// site lineage, reused batch identity, or other semantic failure therefore leaves an
    /// incomplete suffix untouched for diagnosis. `Journal::open` revalidates the structural
    /// prefix before the repair itself.
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

        let (ledger, identities) = replay_report(&report, &site_lineage)?;
        Ok(Self {
            journal,
            ledger,
            identities,
            pending: None,
        })
    }

    /// Latest complete canonical evidence snapshot.
    #[must_use]
    pub fn current(&self) -> &LedgerSnapshot {
        self.ledger.current()
    }

    /// Returns the authoritative ledger handle witnessing the on-disk committed head.
    ///
    /// Borrows this opened `DurableReferenceLedger` handle for lifetime `'_`, guaranteeing at compile
    /// time that this handle cannot be held across subsequent ledger mutations (`append`).
    ///
    /// # Threat Model
    /// This is type-level discipline against *accidental or stale* authority. Code in the same process
    /// that can write the deployment can always forge durable state, so the goal is that no public API
    /// turns a rewound or in-memory ledger into world-fact authority by mistake.
    ///
    /// # Compile-fail: cannot append while an `AuthoritativeLedger` handle is held (fss-sz0cc)
    /// The held handle immutably borrows the durable ledger, so the mutable borrow taken by
    /// `append` is refused (E0502). No I/O is involved: the probe is a function over an
    /// already-opened handle and an already-prepared batch.
    /// ```compile_fail,E0502
    /// use fss_core::EvidenceDeltaBatch;
    /// use fss_ledger::DurableReferenceLedger;
    ///
    /// fn append_while_held(
    ///     durable: &mut DurableReferenceLedger,
    ///     batch: EvidenceDeltaBatch,
    /// ) -> Result<(), Box<dyn std::error::Error>> {
    ///     let held = durable.authoritative_ledger()?;
    ///     durable.append(batch)?;
    ///     let _ = held.anchor();
    ///     Ok(())
    /// }
    /// ```
    pub fn authoritative_ledger(&self) -> Result<AuthoritativeLedger<'_>, ContractError> {
        AuthoritativeLedger::__durable_ledger_only_from_committed_anchor(
            self.current().anchor.clone(),
        )
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

    /// Bounded fail-closed proof that the durable journal still ends exactly where this handle's
    /// replayed state ends.
    ///
    /// Refuses an unresolved append, then delegates to [`Journal::verify_committed_tail`]: the
    /// path is reopened, its length compared with the reconciled committed length, and only the
    /// final commit trailer (at most 40 bytes) is read. A commit by another handle, an appended,
    /// torn, or corrupt suffix, a truncation, a missing path, or an I/O failure is an error. It
    /// never replays history; [`DurableReferenceLedger::verify_storage`] does.
    pub fn verify_durable_head(&self) -> Result<(), DurableLedgerError> {
        if let Some(pending) = &self.pending {
            return Err(JournalError::ReconciliationRequired {
                sequence: pending.sequence,
            }
            .into());
        }
        Ok(self.journal.verify_committed_tail()?)
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
        Ok(self.ledger.prepare_batch(batch_id, deltas, child_roots)?)
    }

    /// Validates, durably commits, then exposes one evidence batch.
    ///
    /// A batch whose stable identity is already committed with different content is refused with
    /// `DurableLedgerError::BatchIdConflict` before any other check and before journal I/O. The
    /// exact successor ledger and durable bytes are then prepared before journal I/O. If the
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

        self.identities.check_not_reused(&batch)?;
        let mut candidate = self.ledger.clone();
        candidate.append(batch.clone())?;
        let encoded = encode_batch(&batch)?;
        let batch_id = batch.batch_id.clone();
        let identity = CommittedIdentity::of(&batch);
        match self.journal.append(EVIDENCE_BATCH_RECORD_KIND, &encoded) {
            Ok(_record) => {
                self.ledger = candidate;
                self.identities.insert(batch_id, identity);
                Ok(self.ledger.current())
            }
            Err(error) => {
                if let JournalError::AppendIndeterminate { sequence, .. } = &error {
                    self.pending = Some(PendingLedgerAppend {
                        candidate,
                        sequence: *sequence,
                        batch_id,
                        identity,
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
        let pending = self.pending.take().ok_or(JournalError::NoPendingAppend)?;
        match self.journal.reconcile_pending(tail_policy) {
            Ok(AppendReconciliation::Committed(_record)) => {
                self.ledger = pending.candidate;
                self.identities
                    .insert(pending.batch_id.clone(), pending.identity);
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

    /// Re-verifies the reconciled durable prefix and journal root with full semantic batch validation.
    pub fn verify_storage(&mut self) -> Result<ContentDigest, DurableLedgerError> {
        let report = self.journal.verify()?;
        let (replayed, identities) =
            replay_report(&report, &self.ledger.current().anchor.site_lineage)?;
        if report.last_root() != self.journal.last_root()
            || replayed.current() != self.ledger.current()
            || identities != self.identities
        {
            return Err(DurableLedgerError::Journal(
                JournalError::ExternalMutation {
                    expected_len: self.journal.committed_len(),
                    observed_len: self.journal.committed_len(),
                    kind: ExternalMutationKind::ContentDivergence,
                },
            ));
        }
        Ok(report.last_root())
    }

    /// Injects a failure into the underlying journal for testing.
    #[doc(hidden)]
    pub fn fail_journal_after_phase(&mut self, phase: AppendPhase) {
        self.journal.fail_after_phase(phase);
    }

    /// Non-mutating inspection of a durable reference ledger.
    pub fn inspect(
        path: impl AsRef<Path>,
        site_lineage: impl Into<String>,
        limits: impl Into<DurableLedgerLimits>,
    ) -> Result<LedgerInspection, DurableLedgerError> {
        inspect_durable(path, site_lineage, limits)
    }
}

/// Replays the committed prefix through the live identity and core-ledger checks.
fn replay_report(
    report: &RecoveryReport,
    site_lineage: &str,
) -> Result<(ReferenceLedger, BatchIdentityIndex), DurableLedgerError> {
    let mut ledger = ReferenceLedger::new(site_lineage);
    let mut identities = BatchIdentityIndex::default();
    for record in report.records() {
        if record.kind() != EVIDENCE_BATCH_RECORD_KIND {
            return Err(DurableLedgerError::UnexpectedRecordKind {
                sequence: record.sequence(),
                kind: record.kind(),
            });
        }
        let batch = decode_batch(record.payload())?;
        if record.sequence() != batch.new_anchor.commit_sequence {
            return Err(DurableLedgerError::RecordSequenceMismatch {
                record_sequence: record.sequence(),
                batch_commit_sequence: batch.new_anchor.commit_sequence,
            });
        }
        identities.check_not_reused(&batch)?;
        let batch_id = batch.batch_id.clone();
        let identity = CommittedIdentity::of(&batch);
        ledger.append(batch)?;
        identities.insert(batch_id, identity);
    }
    Ok((ledger, identities))
}

/// Resource limits for durable ledger inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableLedgerLimits {
    /// Maximum journal file size in bytes to read and inspect.
    pub max_journal_bytes: usize,
}

impl DurableLedgerLimits {
    /// Default limit (64 MiB).
    pub const DEFAULT_MAX_JOURNAL_BYTES: usize = 64 * 1024 * 1024;
}

impl Default for DurableLedgerLimits {
    fn default() -> Self {
        Self {
            max_journal_bytes: Self::DEFAULT_MAX_JOURNAL_BYTES,
        }
    }
}

impl From<usize> for DurableLedgerLimits {
    fn from(max_journal_bytes: usize) -> Self {
        Self { max_journal_bytes }
    }
}

/// Whether an inspected journal file exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableLedgerStatus {
    /// No journal file exists; nothing was created.
    Absent,
    /// A journal file exists (it may be empty).
    Present,
}

/// Non-mutating inspection of a durable reference ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerInspection {
    /// Whether the journal file exists; an absent journal is never reported as an empty one.
    pub status: DurableLedgerStatus,
    /// Committed evidence batches replayed in sequence order.
    pub batches: Vec<EvidenceDeltaBatch>,
    /// Replayed ledger snapshot at the latest committed batch.
    pub snapshot: LedgerSnapshot,
    /// Committed length in bytes.
    pub committed_len: u64,
    /// Root of the last committed record, or zero if empty.
    pub last_root: ContentDigest,
    /// Offset of an incomplete journal tail, if present.
    pub incomplete_tail: Option<u64>,
    /// Range of foreign trailing bytes, if present.
    pub foreign_range: Option<ForeignRange>,
}

impl LedgerInspection {
    /// Returns true if the journal has neither an incomplete tail nor foreign trailing bytes.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.incomplete_tail.is_none() && self.foreign_range.is_none()
    }
}

/// Metadata for a journal file inspected through [`JournalReadIo`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalFileMetadata {
    /// True if the entry is a regular file.
    pub is_file: bool,
    /// True if the entry is a symbolic link.
    pub is_symlink: bool,
    /// Size of the entry in bytes.
    pub len: u64,
}

/// Injected read capability for non-mutating journal inspection.
pub trait JournalReadIo: Send + Sync {
    /// Obtains metadata without following symlinks.
    fn symlink_metadata(&self, path: &Path) -> std::io::Result<JournalFileMetadata>;
    /// Reads up to `max_bytes` bytes from the file.
    fn read_bounded(&self, path: &Path, max_bytes: usize) -> std::io::Result<Vec<u8>>;
}

/// Default [`JournalReadIo`] using standard host filesystem calls.
#[derive(Clone, Copy, Debug, Default)]
pub struct HostJournalReadIo;

impl JournalReadIo for HostJournalReadIo {
    fn symlink_metadata(&self, path: &Path) -> std::io::Result<JournalFileMetadata> {
        let meta = std::fs::symlink_metadata(path)?;
        let ft = meta.file_type();
        Ok(JournalFileMetadata {
            is_file: ft.is_file(),
            is_symlink: ft.is_symlink(),
            len: meta.len(),
        })
    }

    fn read_bounded(&self, path: &Path, max_bytes: usize) -> std::io::Result<Vec<u8>> {
        use std::io::Read;
        let mut file = std::fs::File::open(path)?;
        let mut buf = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take(max_bytes as u64)
            .read_to_end(&mut buf)?;
        Ok(buf)
    }
}

/// Inspects a durable reference ledger through an injected [`JournalReadIo`].
pub fn inspect_durable_with_io(
    io: &dyn JournalReadIo,
    path: impl AsRef<Path>,
    site_lineage: impl Into<String>,
    limits: impl Into<DurableLedgerLimits>,
) -> Result<LedgerInspection, DurableLedgerError> {
    let path = path.as_ref();
    let site_lineage = site_lineage.into();
    let limits = limits.into();

    let meta = match io.symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let ledger = ReferenceLedger::new(site_lineage);
            let snapshot = ledger.current().clone();
            return Ok(LedgerInspection {
                status: DurableLedgerStatus::Absent,
                batches: Vec::new(),
                snapshot,
                committed_len: 0,
                last_root: ContentDigest::new(DigestAlgorithm::Sha256, [0_u8; 32]),
                incomplete_tail: None,
                foreign_range: None,
            });
        }
        Err(err) => return Err(DurableLedgerError::Io(err)),
    };

    if meta.is_symlink || !meta.is_file {
        return Err(DurableLedgerError::InvalidLayout {
            path: path.to_path_buf(),
        });
    }

    // A journal whose stat length already exceeds the limit is rejected before any read. The
    // read itself stays bounded at `limit + 1` bytes, so a journal that grows after the stat is
    // still caught.
    let stat_over_limit = observed_len(meta.len, 0) > limits.max_journal_bytes;
    let buf = if stat_over_limit {
        Vec::new()
    } else {
        io.read_bounded(path, limits.max_journal_bytes.saturating_add(1))?
    };
    if stat_over_limit || buf.len() > limits.max_journal_bytes {
        return Err(DurableLedgerError::OverBudget {
            limit: limits.max_journal_bytes,
            actual: observed_len(meta.len, buf.len()),
        });
    }

    let doctor_report = crate::doctor(&buf)?;
    let recovery = crate::recover_bytes(committed_prefix(&buf, doctor_report.committed_len)?)?;
    let (ledger, _) = replay_report(&recovery, &site_lineage)?;

    Ok(LedgerInspection {
        status: DurableLedgerStatus::Present,
        batches: ledger.batches().to_vec(),
        snapshot: ledger.current().clone(),
        committed_len: doctor_report.committed_len,
        last_root: doctor_report.last_root,
        incomplete_tail: doctor_report.incomplete_tail,
        foreign_range: doctor_report.foreign_range,
    })
}

/// The larger of the stat length and the bytes actually read, saturating on 32-bit targets.
pub(crate) fn observed_len(stat_len: u64, read_len: usize) -> usize {
    usize::try_from(stat_len)
        .unwrap_or(usize::MAX)
        .max(read_len)
}

/// The committed prefix of `bytes` that [`crate::doctor`] reported.
fn committed_prefix(bytes: &[u8], committed_len: u64) -> Result<&[u8], DurableLedgerError> {
    usize::try_from(committed_len)
        .ok()
        .and_then(|len| bytes.get(..len))
        .ok_or(DurableLedgerError::Journal(JournalError::LengthOverflow))
}

/// Inspects a durable reference ledger without acquiring locks or modifying files.
///
/// A journal whose stat length exceeds `limits.max_journal_bytes` is rejected with
/// [`DurableLedgerError::OverBudget`] before any read; otherwise the read is capped at
/// `limits.max_journal_bytes + 1` bytes, so a journal that grows after the stat is still rejected
/// and memory stays bounded. If the journal does not exist, an empty [`LedgerInspection`] is
/// returned without creating the file.
/// If the path is a symlink or non-regular file, [`DurableLedgerError::InvalidLayout`] is returned.
pub fn inspect_durable(
    path: impl AsRef<Path>,
    site_lineage: impl Into<String>,
    limits: impl Into<DurableLedgerLimits>,
) -> Result<LedgerInspection, DurableLedgerError> {
    inspect_durable_with_io(&HostJournalReadIo, path, site_lineage, limits)
}

/// Journal position of one committed evidence batch in a durable reference ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommittedBatchPosition {
    /// Commit sequence of the batch, which is also its journal record sequence.
    pub commit_sequence: u64,
    /// Root of the batch's journal record, chaining it to every prior committed record.
    pub record_root: ContentDigest,
    /// Byte length of the committed journal prefix through this record.
    pub prefix_len: u64,
}

/// Recomputes the committed journal position of every batch `inspection` replayed.
///
/// Each batch is re-encoded exactly as [`DurableReferenceLedger::append`] frames it, and record
/// roots are chained exactly as the journal chains them. Returns `None` unless the recomputed
/// chain ends at the inspected committed length and last root, so every returned position is one
/// the inspected committed bytes actually hold; an absent or empty ledger has no positions. Nothing
/// is read or written: this is a pure function of the inspection.
#[must_use]
pub fn committed_batch_positions(
    inspection: &LedgerInspection,
) -> Option<Vec<CommittedBatchPosition>> {
    let mut previous = [0_u8; 32];
    let mut offset = 0_u64;
    let mut positions = Vec::with_capacity(inspection.batches.len());
    for batch in &inspection.batches {
        let payload = encode_batch(batch).ok()?;
        let payload_len = u32::try_from(payload.len()).ok()?;
        let sequence = batch.new_anchor.commit_sequence;
        previous = crate::format::record_root(
            sequence,
            EVIDENCE_BATCH_RECORD_KIND,
            payload_len,
            previous,
            fss_core::sha256(&payload),
        );
        let framed = crate::format::HEADER_LEN
            .checked_add(payload.len())?
            .checked_add(crate::format::TRAILER_LEN)?;
        offset = offset.checked_add(u64::try_from(framed).ok()?)?;
        positions.push(CommittedBatchPosition {
            commit_sequence: sequence,
            record_root: ContentDigest::new(DigestAlgorithm::Sha256, previous),
            prefix_len: offset,
        });
    }
    let last_root = ContentDigest::new(DigestAlgorithm::Sha256, previous);
    (offset == inspection.committed_len && last_root == inspection.last_root).then_some(positions)
}
