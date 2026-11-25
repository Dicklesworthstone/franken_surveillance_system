#![forbid(unsafe_code)]
//! Deterministic commit combiner and semantic SSI conflict oracle (`FSS-104`, `fss-x4a.9.11`).
//!
//! Composes [`SemanticWitness`] (`FSS-103`), [`LedgerOracle`], and [`DurableReferenceLedger`] to
//! serialize concurrent semantic transaction intents into deterministic flat-combined canonical
//! [`EvidenceDeltaBatch`] commits with full Serializable Snapshot Isolation (SSI) conflict detection:
//!
//! - **Canonical submission-order independence:** intents in a combining round are sorted strictly
//!   by `(basis_anchor.commit_sequence, intent_digest, intent_id)` so arrival/thread scheduling
//!   order never changes winners, aborts, or committed batch digests.
//! - **Explicit authority-before-commit:** capability, privacy, generation, plane, and family
//!   projections are validated before conflict analysis or storage I/O.
//! - **Non-collapsed semantic conflict detection:**
//!   - [`ConflictKind::PositiveReadStale`] when an object in a positive read witness mutated after
//!     `basis_anchor`;
//!   - [`ConflictKind::NegativePhantomWrite`] when an object proven absent by a certified
//!     [`NegativeWitness`] was inserted after `basis_anchor` (or earlier in the same round);
//!   - [`ConflictKind::UncertifiedAbsenceBasis`] when an intent relies on an uncertified negative
//!     witness (`!coverage.certifies_absence()`);
//!   - [`ConflictKind::WriteWriteGenerationConflict`] on overlapping writes against stale prior
//!     generations or same-round winners;
//!   - [`ConflictKind::SsiDangerousWriteSkew`] on mutual/cyclic `rw`-antidependencies between
//!     concurrent transactions even with disjoint write sets.
//! - **Semantic idempotency & indeterminate honesty:** exact duplicate `intent_id` + matching
//!   `intent_digest` returns [`IntentOutcome::IdempotentReplay`]; conflicting `intent_id` fails
//!   closed; durable `AppendIndeterminate` yields [`CombiningRoundOutcome::Indeterminate`] until
//!   reconciled (never upgrading uncertain durability to `Committed`).

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use fss_core::{
    BatchId, CanonicalEncode, CanonicalEncoder, ContentDigest, EvidenceDelta, LedgerAnchor,
    ObjectId, Plane,
};

use crate::durable::{DurableLedgerError, DurableReferenceLedger};
use crate::error::JournalError;
use crate::oracle::{LedgerOracle, ObjectRead};
use crate::witness::{NegativeWitness, PositiveWitness, SemanticWitness};

/// Registered digest domain for deterministic commit-combiner round receipts (`FSS-104`).
pub const LEDGER_COMMIT_COMBINER_ROUND_DOMAIN: &str = "fss.ledger_commit_combiner_round.v1";
/// Registered digest domain for semantic commit intent identities (`FSS-104`).
pub const LEDGER_COMMIT_INTENT_DOMAIN: &str = "fss.ledger_commit_intent.v1";
/// Hard ceiling on intents admitted into one deterministic combining round.
pub const MAX_COMBINER_ROUND_INTENTS: usize = 256;
/// Hard ceiling on semantic read witnesses per intent.
pub const MAX_INTENT_READ_WITNESSES: usize = 512;
/// Hard ceiling on write deltas per intent.
pub const MAX_INTENT_WRITES: usize = 512;
/// Hard ceiling on child roots per intent.
pub const MAX_INTENT_CHILDREN: usize = 512;
/// Hard ceiling on retained committed intent idempotency records.
pub const MAX_IDEMPOTENCY_HISTORY: usize = 65_536;
/// Maximum UTF-8 bytes in `intent_id`.
pub const MAX_INTENT_ID_BYTES: usize = 128;

/// Safe operator/agent recovery guidance for a refused or conflicted commit combiner call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CombinerGuidance {
    /// Fix invalid intent structure, bounds, or duplicate target writes before resubmitting.
    RepairIntent,
    /// Re-authorize revoked capability, privacy epoch, authority generation, or plane scope.
    ReauthorizeAndReanchor,
    /// Re-read from the latest canonical anchor and rebase the intent before retrying.
    RebaseOnFreshAnchor,
    /// Absence predicate was backed by gapped/partial coverage; wait for certified coverage.
    WaitForCertifiedCoverage,
    /// Conflicting intent reused an existing `intent_id`; mint a distinct idempotency key.
    MintDistinctIntentId,
    /// Durable append is indeterminate; reconcile pending append before submitting new rounds.
    ReconcilePendingAppend,
    /// Cooperative cancellation observed before commit; safe to retry when ready.
    RetryWhenReady,
}

/// Typed pre-flight or infrastructure error from [`DeterministicCommitCombiner`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitCombinerError {
    /// Intent or round violated structural bounds or invariants.
    InvalidInput(String),
    /// Cooperative cancellation observed before committing any intent in this round.
    Cancelled,
    /// Durable ledger has an unresolved indeterminate append blocking new rounds.
    PendingReconciliation {
        /// Sequence of the pending append.
        sequence: u64,
    },
    /// Bounded round or history limit exceeded.
    BoundsExceeded {
        /// Observed count.
        observed: usize,
        /// Hard ceiling.
        maximum: usize,
    },
    /// Canonical encoding or underlying ledger error.
    Ledger(String),
}

impl CommitCombinerError {
    /// Registered stable error identity.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "ERR-LEDGER-COMBINER-INVALID-INPUT-001",
            Self::Cancelled => "ERR-LEDGER-COMBINER-CANCELLED-001",
            Self::PendingReconciliation { .. } => "ERR-LEDGER-COMBINER-PENDING-RECONCILE-001",
            Self::BoundsExceeded { .. } => "ERR-LEDGER-COMBINER-BOUNDS-001",
            Self::Ledger(_) => "ERR-LEDGER-COMBINER-LEDGER-001",
        }
    }

    /// Safe recovery guidance.
    #[must_use]
    pub const fn guidance(&self) -> CombinerGuidance {
        match self {
            Self::InvalidInput(_) | Self::BoundsExceeded { .. } => CombinerGuidance::RepairIntent,
            Self::Cancelled => CombinerGuidance::RetryWhenReady,
            Self::PendingReconciliation { .. } => CombinerGuidance::ReconcilePendingAppend,
            Self::Ledger(_) => CombinerGuidance::RebaseOnFreshAnchor,
        }
    }
}

impl fmt::Display for CommitCombinerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}

impl Error for CommitCombinerError {}

/// Explicit authority, privacy, generation, and plane projection carried by each intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntentAuthorityContext {
    /// Active authority generation.
    pub authority_generation: u64,
    /// Expected authority generation pinned at prepare time.
    pub expected_authority_generation: u64,
    /// Active privacy policy epoch.
    pub privacy_epoch: u64,
    /// True while write/commit capability remains valid.
    pub capability_active: bool,
    /// True while privacy authorization remains valid.
    pub privacy_active: bool,
    /// Semantic planes authorized for writes in this intent.
    pub allowed_planes: BTreeSet<Plane>,
}

impl IntentAuthorityContext {
    /// Constructs an active authority context allowing `allowed_planes`.
    #[must_use]
    pub fn active(
        authority_generation: u64,
        privacy_epoch: u64,
        allowed_planes: impl IntoIterator<Item = Plane>,
    ) -> Self {
        Self {
            authority_generation,
            expected_authority_generation: authority_generation,
            privacy_epoch,
            capability_active: true,
            privacy_active: true,
            allowed_planes: allowed_planes.into_iter().collect(),
        }
    }
}

/// Non-collapsed semantic conflict classification emitted by the SSI conflict oracle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConflictKind {
    /// Capability, privacy, authority generation, or plane authorization refused.
    AuthorityOrPrivacyRefused,
    /// `intent_id` was previously committed with a different canonical intent digest.
    SemanticIdempotencyConflict,
    /// Basis anchor disagrees with lineage/epoch/sequence or is ahead of committed head.
    StaleOrDivergentBasisAnchor,
    /// Read witness failed self-invariants or disagreed with `basis_anchor`.
    InvalidReadWitness,
    /// Negative read witness carried uncertified/gapped coverage (`!certifies_absence()`).
    UncertifiedAbsenceBasis,
    /// Object observed in a positive read witness mutated after `basis_anchor`.
    PositiveReadStale,
    /// Object proven absent by a certified negative witness became present (phantom write).
    NegativePhantomWrite,
    /// Write target mutated after `basis_anchor` or collided with an earlier winner in the round.
    WriteWriteGenerationConflict,
    /// Mutual/cyclic `rw`-antidependency detected across concurrent transactions (SSI write skew).
    SsiDangerousWriteSkew,
}

impl ConflictKind {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorityOrPrivacyRefused => "authority_or_privacy_refused",
            Self::SemanticIdempotencyConflict => "semantic_idempotency_conflict",
            Self::StaleOrDivergentBasisAnchor => "stale_or_divergent_basis_anchor",
            Self::InvalidReadWitness => "invalid_read_witness",
            Self::UncertifiedAbsenceBasis => "uncertified_absence_basis",
            Self::PositiveReadStale => "positive_read_stale",
            Self::NegativePhantomWrite => "negative_phantom_write",
            Self::WriteWriteGenerationConflict => "write_write_generation_conflict",
            Self::SsiDangerousWriteSkew => "ssi_dangerous_write_skew",
        }
    }

    /// Safe recovery guidance for this conflict kind.
    #[must_use]
    pub const fn guidance(self) -> CombinerGuidance {
        match self {
            Self::AuthorityOrPrivacyRefused => CombinerGuidance::ReauthorizeAndReanchor,
            Self::SemanticIdempotencyConflict => CombinerGuidance::MintDistinctIntentId,
            Self::UncertifiedAbsenceBasis => CombinerGuidance::WaitForCertifiedCoverage,
            Self::InvalidReadWitness => CombinerGuidance::RepairIntent,
            Self::StaleOrDivergentBasisAnchor
            | Self::PositiveReadStale
            | Self::NegativePhantomWrite
            | Self::WriteWriteGenerationConflict
            | Self::SsiDangerousWriteSkew => CombinerGuidance::RebaseOnFreshAnchor,
        }
    }
}

/// Typed semantic conflict witness pinpointing the exact conflicting object/peer intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConflictWitness {
    /// Non-collapsed conflict classification.
    pub kind: ConflictKind,
    /// Offending object identity, when applicable.
    pub object_id: Option<ObjectId>,
    /// Earlier winning `intent_id` in the same combining round, when intra-round conflict occurred.
    pub conflicting_intent_id: Option<String>,
    /// Secret-free diagnostic detail.
    pub detail: String,
    /// Safe recovery guidance.
    pub guidance: CombinerGuidance,
}

/// Prepared semantic write transaction submitted to [`DeterministicCommitCombiner`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitIntent {
    /// Stable idempotency key (`1..=MAX_INTENT_ID_BYTES`, no control chars).
    pub intent_id: String,
    /// Exact canonical anchor against which reads and prior generations were prepared.
    pub basis_anchor: LedgerAnchor,
    /// Exact canonical history-chain root at `basis_anchor`.
    pub basis_history_root: ContentDigest,
    /// Semantic read witnesses (`FSS-103`) guarding positive and negative read dependencies.
    pub read_witnesses: Vec<SemanticWitness>,
    /// Proposed canonical write deltas.
    pub writes: Vec<EvidenceDelta>,
    /// Optional content-addressed child roots linked to this write set.
    pub child_roots: Vec<ContentDigest>,
    /// Explicit authority and privacy context evaluated before conflict analysis or commit.
    pub authority: IntentAuthorityContext,
}

impl CommitIntent {
    /// Validates basic structural bounds (non-empty ID, non-empty writes, unique target objects).
    pub fn validate_structure(&self) -> Result<(), CommitCombinerError> {
        if self.intent_id.is_empty()
            || self.intent_id.len() > MAX_INTENT_ID_BYTES
            || self.intent_id.chars().any(char::is_control)
        {
            return Err(CommitCombinerError::InvalidInput(
                "intent_id must be 1..=128 non-control UTF-8 bytes".to_owned(),
            ));
        }
        if self.read_witnesses.len() > MAX_INTENT_READ_WITNESSES {
            return Err(CommitCombinerError::BoundsExceeded {
                observed: self.read_witnesses.len(),
                maximum: MAX_INTENT_READ_WITNESSES,
            });
        }
        if self.writes.is_empty() || self.writes.len() > MAX_INTENT_WRITES {
            return Err(CommitCombinerError::BoundsExceeded {
                observed: self.writes.len(),
                maximum: MAX_INTENT_WRITES,
            });
        }
        if self.child_roots.len() > MAX_INTENT_CHILDREN {
            return Err(CommitCombinerError::BoundsExceeded {
                observed: self.child_roots.len(),
                maximum: MAX_INTENT_CHILDREN,
            });
        }
        let mut seen_targets = BTreeSet::new();
        for delta in &self.writes {
            if !seen_targets.insert(&delta.object_id) {
                return Err(CommitCombinerError::InvalidInput(format!(
                    "intent '{}' contains duplicate writes to object '{}'",
                    self.intent_id,
                    delta.object_id.as_str()
                )));
            }
            if delta.new_generation == 0 {
                return Err(CommitCombinerError::InvalidInput(format!(
                    "intent '{}' has zero new_generation on '{}'",
                    self.intent_id,
                    delta.object_id.as_str()
                )));
            }
        }
        Ok(())
    }

    /// Computes the deterministic domain-separated digest of this intent (`fss.ledger_commit_intent.v1`).
    pub fn canonical_digest(&self) -> Result<ContentDigest, CommitCombinerError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(LEDGER_COMMIT_INTENT_DOMAIN);
        enc.text(&self.intent_id);
        self.basis_anchor.encode_canonical(&mut enc);
        enc.digest(self.basis_history_root);
        let mut witness_digests: Vec<ContentDigest> = self
            .read_witnesses
            .iter()
            .map(SemanticWitness::witness_digest)
            .collect();
        witness_digests.sort_unstable();
        enc.u64(witness_digests.len() as u64);
        for d in witness_digests {
            enc.digest(d);
        }
        let mut sorted_writes: Vec<&EvidenceDelta> = self.writes.iter().collect();
        sorted_writes.sort_by(|a, b| {
            (
                a.object_id.as_str(),
                a.new_generation,
                a.delta_id.as_str(),
                a.family.as_str(),
            )
                .cmp(&(
                    b.object_id.as_str(),
                    b.new_generation,
                    b.delta_id.as_str(),
                    b.family.as_str(),
                ))
        });
        enc.u64(sorted_writes.len() as u64);
        for w in sorted_writes {
            w.encode_canonical(&mut enc);
        }
        let mut sorted_children = self.child_roots.clone();
        sorted_children.sort_unstable();
        sorted_children.dedup();
        enc.u64(sorted_children.len() as u64);
        for c in sorted_children {
            enc.digest(c);
        }
        let bytes = enc
            .finish_checked()
            .map_err(|e| CommitCombinerError::Ledger(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }
}

/// Committed receipt returned for one accepted or idempotently replayed intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntentCommitReceipt {
    /// Intent identifier.
    pub intent_id: String,
    /// Canonical digest of the committed intent.
    pub intent_digest: ContentDigest,
    /// Committed canonical sequence number.
    pub committed_sequence: u64,
    /// Canonical batch identifier containing this intent's deltas.
    pub batch_id: BatchId,
    /// Canonical batch digest.
    pub batch_digest: ContentDigest,
    /// Committed canonical anchor after this round.
    pub committed_anchor: LedgerAnchor,
    /// Canonical history-chain root after this round.
    pub committed_history_root: ContentDigest,
}

/// Non-collapsed per-intent outcome within a combining round.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IntentOutcome {
    /// Intent passed authority and SSI conflict checks and committed in this round.
    Committed(IntentCommitReceipt),
    /// Exact duplicate intent was already committed previously; no second commit occurred.
    IdempotentReplay(IntentCommitReceipt),
    /// Intent was refused or aborted due to authority or SSI conflict without mutating the ledger.
    Aborted(ConflictWitness),
    /// Round append entered durable indeterminate state; commit status is unresolved.
    Indeterminate {
        /// Sequence of the pending indeterminate append.
        pending_sequence: u64,
        /// Intent canonical digest preserved for post-reconciliation verification.
        intent_digest: ContentDigest,
    },
}

/// Non-collapsed terminal outcome of one deterministic flat-combining round.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CombiningRoundOutcome {
    /// At least one intent committed into one coalesced canonical `EvidenceDeltaBatch`.
    Committed {
        /// Monotonic combining round number.
        round_id: u64,
        /// Coalesced canonical batch ID.
        batch_id: BatchId,
        /// Coalesced canonical batch digest.
        batch_digest: ContentDigest,
        /// Committed anchor after this round.
        new_anchor: LedgerAnchor,
        /// Canonical history root after this round.
        new_history_root: ContentDigest,
        /// Per-intent outcomes keyed by `intent_id`.
        outcomes: BTreeMap<String, IntentOutcome>,
        /// Domain-separated SHA-256 commitment (`fss.ledger_commit_combiner_round.v1`).
        round_digest: ContentDigest,
    },
    /// Zero new writes committed (every intent was an idempotent replay or conflicted/aborted).
    NoNewCommit {
        /// Monotonic combining round number.
        round_id: u64,
        /// Unchanged ledger head anchor.
        head_anchor: LedgerAnchor,
        /// Per-intent outcomes keyed by `intent_id`.
        outcomes: BTreeMap<String, IntentOutcome>,
        /// Domain-separated SHA-256 commitment (`fss.ledger_commit_combiner_round.v1`).
        round_digest: ContentDigest,
    },
    /// Durable append terminated indeterminate; ledger mutation awaits reconciliation.
    Indeterminate {
        /// Monotonic combining round number.
        round_id: u64,
        /// Sequence of the unresolved indeterminate append.
        pending_sequence: u64,
        /// Per-intent outcomes (`Indeterminate` for winners, `Aborted`/`IdempotentReplay` for others).
        outcomes: BTreeMap<String, IntentOutcome>,
        /// Domain-separated SHA-256 commitment (`fss.ledger_commit_combiner_round.v1`).
        round_digest: ContentDigest,
    },
}

/// Flattened positive and negative read sets extracted recursively from [`SemanticWitness`].
#[derive(Default)]
struct ExtractedReads {
    positives: Vec<PositiveWitness>,
    negatives: Vec<NegativeWitness>,
}

fn extract_reads(witness: &SemanticWitness, out: &mut ExtractedReads) {
    match witness {
        SemanticWitness::Positive(p) => out.positives.push(p.clone()),
        SemanticWitness::Negative(n) => out.negatives.push(n.clone()),
        SemanticWitness::Hierarchical(h) => {
            for child in &h.children {
                extract_reads(child, out);
            }
        }
    }
}

/// Records the read and write sets of an already-admitted winner in the current round for
/// intra-round SSI write-skew and overlap checks.
struct RoundWinner {
    intent_id: String,
    intent_digest: ContentDigest,
    read_objects: BTreeSet<ObjectId>,
    write_objects: BTreeSet<ObjectId>,
    writes: Vec<EvidenceDelta>,
    child_roots: Vec<ContentDigest>,
}

/// Read-only abstraction over [`LedgerOracle`] and [`DurableReferenceLedger`] for unified
/// SSI conflict evaluation.
trait ConflictSnapshotSource {
    fn head_anchor(&self) -> LedgerAnchor;
    fn anchor_and_history_at(&self, sequence: u64) -> Option<(LedgerAnchor, ContentDigest)>;
    /// Returns `(current_generation, last_committed_sequence, payload_digest)` if present at head.
    fn current_object_state(&self, object_id: &ObjectId) -> Option<(u64, u64, ContentDigest)>;
    /// Returns `true` if `object_id` already existed at `at_seq` (`1..=at_seq`).
    fn object_existed_at(&self, object_id: &ObjectId, at_seq: u64) -> bool;
    /// Returns `true` if `object_id` was written by any committed batch in `(after_seq..=head]`.
    fn object_mutated_after(&self, object_id: &ObjectId, after_seq: u64) -> bool;
}

impl ConflictSnapshotSource for LedgerOracle {
    fn head_anchor(&self) -> LedgerAnchor {
        self.head_anchor().clone()
    }

    fn anchor_and_history_at(&self, sequence: u64) -> Option<(LedgerAnchor, ContentDigest)> {
        let anchor = self.anchor_at(sequence)?.clone();
        let hist = self.history_root_at(sequence)?;
        Some((anchor, hist))
    }

    fn current_object_state(&self, object_id: &ObjectId) -> Option<(u64, u64, ContentDigest)> {
        let view = self.view_at(self.head_sequence()).ok()?;
        match view.object(object_id) {
            ObjectRead::Present {
                revision,
                committed_sequence,
            } => Some((
                revision.generation,
                committed_sequence,
                revision.payload_digest,
            )),
            ObjectRead::AbsentAtAnchor { .. } => None,
        }
    }

    fn object_existed_at(&self, object_id: &ObjectId, at_seq: u64) -> bool {
        self.view_at(at_seq)
            .ok()
            .is_some_and(|view| matches!(view.object(object_id), ObjectRead::Present { .. }))
    }

    fn object_mutated_after(&self, object_id: &ObjectId, after_seq: u64) -> bool {
        let total = self.batch_count();
        let start = usize::try_from(after_seq).unwrap_or(total);
        for idx in start..total {
            if let Some((batch, _)) = self.entry_at_index(idx)
                && batch.deltas.iter().any(|d| &d.object_id == object_id)
            {
                return true;
            }
        }
        false
    }
}

impl ConflictSnapshotSource for DurableReferenceLedger {
    fn head_anchor(&self) -> LedgerAnchor {
        self.current().anchor.clone()
    }

    fn anchor_and_history_at(&self, sequence: u64) -> Option<(LedgerAnchor, ContentDigest)> {
        let head = &self.current().anchor;
        if sequence > head.commit_sequence {
            return None;
        }
        let anchor = if sequence == 0 {
            LedgerAnchor::genesis(head.site_lineage.clone())
        } else {
            let idx = usize::try_from(sequence - 1).ok()?;
            self.batches().get(idx)?.new_anchor.clone()
        };
        let hist = self.history_root_at(sequence)?;
        Some((anchor, hist))
    }

    fn current_object_state(&self, object_id: &ObjectId) -> Option<(u64, u64, ContentDigest)> {
        let mut found: Option<(u64, u64, ContentDigest)> = None;
        for batch in self.batches() {
            for delta in &batch.deltas {
                if &delta.object_id == object_id {
                    found = Some((
                        delta.new_generation,
                        batch.new_anchor.commit_sequence,
                        delta.payload_digest,
                    ));
                }
            }
        }
        found
    }

    fn object_existed_at(&self, object_id: &ObjectId, at_seq: u64) -> bool {
        let limit = usize::try_from(at_seq).unwrap_or(self.batches().len());
        self.batches()[..limit.min(self.batches().len())]
            .iter()
            .any(|batch| batch.deltas.iter().any(|d| &d.object_id == object_id))
    }

    fn object_mutated_after(&self, object_id: &ObjectId, after_seq: u64) -> bool {
        let batches = self.batches();
        let start = usize::try_from(after_seq).unwrap_or(batches.len());
        batches[start.min(batches.len())..]
            .iter()
            .any(|batch| batch.deltas.iter().any(|d| &d.object_id == object_id))
    }
}

/// Deterministic flat-combining commit coalescer and semantic SSI conflict oracle (`FSS-104`).
#[derive(Clone, Debug, Default)]
pub struct DeterministicCommitCombiner {
    next_round_id: u64,
    committed_intents: BTreeMap<String, IntentCommitReceipt>,
}

impl DeterministicCommitCombiner {
    /// Creates a fresh combiner state starting at round 1.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_round_id: 1,
            committed_intents: BTreeMap::new(),
        }
    }

    /// Looks up a previously committed intent receipt by its stable `intent_id`.
    #[must_use]
    pub fn receipt_for(&self, intent_id: &str) -> Option<&IntentCommitReceipt> {
        self.committed_intents.get(intent_id)
    }

    /// Executes one deterministic flat-combining round against an in-memory [`LedgerOracle`].
    pub fn execute_round_oracle(
        &mut self,
        oracle: &mut LedgerOracle,
        intents: Vec<CommitIntent>,
        cancelled: bool,
    ) -> Result<CombiningRoundOutcome, CommitCombinerError> {
        if cancelled {
            return Err(CommitCombinerError::Cancelled);
        }
        let round_id = self.next_round_id;
        let (winners, mut outcomes) = self.plan_round(oracle, intents)?;
        if winners.is_empty() {
            let head_anchor = oracle.head_anchor().clone();
            let round_digest = compute_round_digest(round_id, None, &head_anchor, &outcomes)?;
            self.next_round_id = self.next_round_id.saturating_add(1);
            return Ok(CombiningRoundOutcome::NoNewCommit {
                round_id,
                head_anchor,
                outcomes,
                round_digest,
            });
        }

        let (batch_id, all_deltas, all_children) = assemble_coalesced_batch(round_id, &winners)?;
        let batch = oracle
            .prepare_batch(batch_id.clone(), all_deltas, all_children)
            .map_err(|e| CommitCombinerError::Ledger(e.to_string()))?;
        let receipt = oracle
            .append(batch)
            .map_err(|e| CommitCombinerError::Ledger(e.to_string()))?;

        self.record_committed_winners(
            &winners,
            receipt.sequence,
            &receipt.batch_id,
            receipt.batch_digest,
            &receipt.anchor,
            receipt.history_root,
            &mut outcomes,
        )?;
        let round_digest = compute_round_digest(
            round_id,
            Some(receipt.batch_digest),
            &receipt.anchor,
            &outcomes,
        )?;
        self.next_round_id = self.next_round_id.saturating_add(1);
        Ok(CombiningRoundOutcome::Committed {
            round_id,
            batch_id: receipt.batch_id,
            batch_digest: receipt.batch_digest,
            new_anchor: receipt.anchor,
            new_history_root: receipt.history_root,
            outcomes,
            round_digest,
        })
    }

    /// Executes one deterministic flat-combining round against a [`DurableReferenceLedger`],
    /// preserving pending indeterminate-append isolation and propagating `AppendIndeterminate`
    /// without falsely reporting `Committed`.
    pub fn execute_round_durable(
        &mut self,
        durable: &mut DurableReferenceLedger,
        intents: Vec<CommitIntent>,
        cancelled: bool,
    ) -> Result<CombiningRoundOutcome, CommitCombinerError> {
        if cancelled {
            return Err(CommitCombinerError::Cancelled);
        }
        if let Some(sequence) = durable.pending_append_sequence() {
            return Err(CommitCombinerError::PendingReconciliation { sequence });
        }
        let round_id = self.next_round_id;
        let (winners, mut outcomes) = self.plan_round(durable, intents)?;
        if winners.is_empty() {
            let head_anchor = durable.current().anchor.clone();
            let round_digest = compute_round_digest(round_id, None, &head_anchor, &outcomes)?;
            self.next_round_id = self.next_round_id.saturating_add(1);
            return Ok(CombiningRoundOutcome::NoNewCommit {
                round_id,
                head_anchor,
                outcomes,
                round_digest,
            });
        }

        let (batch_id, all_deltas, all_children) = assemble_coalesced_batch(round_id, &winners)?;
        let batch = durable
            .prepare_batch(batch_id.clone(), all_deltas, all_children)
            .map_err(|e| CommitCombinerError::Ledger(e.to_string()))?;
        let batch_digest = batch.batch_digest;
        match durable.append(batch) {
            Ok(snapshot) => {
                let committed_anchor = snapshot.anchor.clone();
                let committed_history_root = durable.head_history_root();
                self.record_committed_winners(
                    &winners,
                    committed_anchor.commit_sequence,
                    &batch_id,
                    batch_digest,
                    &committed_anchor,
                    committed_history_root,
                    &mut outcomes,
                )?;
                let round_digest = compute_round_digest(
                    round_id,
                    Some(batch_digest),
                    &committed_anchor,
                    &outcomes,
                )?;
                self.next_round_id = self.next_round_id.saturating_add(1);
                Ok(CombiningRoundOutcome::Committed {
                    round_id,
                    batch_id,
                    batch_digest,
                    new_anchor: committed_anchor,
                    new_history_root: committed_history_root,
                    outcomes,
                    round_digest,
                })
            }
            Err(DurableLedgerError::Journal(JournalError::AppendIndeterminate {
                sequence,
                ..
            })) => {
                for w in &winners {
                    outcomes.insert(
                        w.intent_id.clone(),
                        IntentOutcome::Indeterminate {
                            pending_sequence: sequence,
                            intent_digest: w.intent_digest,
                        },
                    );
                }
                let head_anchor = durable.current().anchor.clone();
                let round_digest =
                    compute_round_digest(round_id, Some(batch_digest), &head_anchor, &outcomes)?;
                self.next_round_id = self.next_round_id.saturating_add(1);
                Ok(CombiningRoundOutcome::Indeterminate {
                    round_id,
                    pending_sequence: sequence,
                    outcomes,
                    round_digest,
                })
            }
            Err(other) => Err(CommitCombinerError::Ledger(other.to_string())),
        }
    }

    fn plan_round<S: ConflictSnapshotSource>(
        &self,
        source: &S,
        intents: Vec<CommitIntent>,
    ) -> Result<(Vec<RoundWinner>, BTreeMap<String, IntentOutcome>), CommitCombinerError> {
        if intents.is_empty() || intents.len() > MAX_COMBINER_ROUND_INTENTS {
            return Err(CommitCombinerError::BoundsExceeded {
                observed: intents.len(),
                maximum: MAX_COMBINER_ROUND_INTENTS,
            });
        }

        // Validate structure, compute canonical intent digests, and detect duplicate IDs in-round.
        let mut keyed: Vec<(u64, ContentDigest, String, CommitIntent)> =
            Vec::with_capacity(intents.len());
        let mut seen_in_round: BTreeMap<String, (ContentDigest, IntentAuthorityContext)> =
            BTreeMap::new();
        let mut in_round_conflicts: BTreeSet<String> = BTreeSet::new();
        for intent in intents {
            intent.validate_structure()?;
            let digest = intent.canonical_digest()?;
            if let Some((prev_digest, prev_auth)) = seen_in_round.get(&intent.intent_id) {
                if *prev_digest == digest && *prev_auth == intent.authority {
                    // Exact duplicate (same digest and authority) within same round collapses idempotently.
                    continue;
                }
                in_round_conflicts.insert(intent.intent_id.clone());
                continue;
            }
            seen_in_round.insert(intent.intent_id.clone(), (digest, intent.authority.clone()));
            keyed.push((
                intent.basis_anchor.commit_sequence,
                digest,
                intent.intent_id.clone(),
                intent,
            ));
        }

        // Canonical flat-combining order independent of submission/thread arrival order.
        keyed.sort_by(|a, b| (a.0, a.1, a.2.as_str()).cmp(&(b.0, b.1, b.2.as_str())));

        let head_anchor = source.head_anchor();
        let mut winners: Vec<RoundWinner> = Vec::new();
        let mut outcomes: BTreeMap<String, IntentOutcome> = BTreeMap::new();

        for (basis_seq, intent_digest, intent_id, intent) in keyed {
            if in_round_conflicts.contains(&intent_id) {
                outcomes.insert(
                    intent_id,
                    IntentOutcome::Aborted(conflict(
                        ConflictKind::SemanticIdempotencyConflict,
                        None,
                        None,
                        "conflicting intents shared intent_id within the same round",
                    )),
                );
                continue;
            }

            // 1. Prior committed idempotency check.
            if let Some(prev) = self.committed_intents.get(&intent_id) {
                if prev.intent_digest == intent_digest {
                    outcomes.insert(intent_id, IntentOutcome::IdempotentReplay(prev.clone()));
                } else {
                    outcomes.insert(
                        intent_id,
                        IntentOutcome::Aborted(conflict(
                            ConflictKind::SemanticIdempotencyConflict,
                            None,
                            None,
                            "intent_id already committed with a different canonical digest",
                        )),
                    );
                }
                continue;
            }

            // 2. Explicit authority, privacy, generation, and plane check BEFORE conflict/commit.
            if let Some(auth_conflict) = validate_intent_authority(&intent) {
                outcomes.insert(intent_id, IntentOutcome::Aborted(auth_conflict));
                continue;
            }

            // 3. Validate basis_anchor and basis_history_root against committed history.
            if intent.basis_anchor.site_lineage != head_anchor.site_lineage
                || intent.basis_anchor.ledger_epoch != head_anchor.ledger_epoch
                || basis_seq > head_anchor.commit_sequence
            {
                outcomes.insert(
                    intent_id,
                    IntentOutcome::Aborted(conflict(
                        ConflictKind::StaleOrDivergentBasisAnchor,
                        None,
                        None,
                        "basis_anchor lineage, epoch, or sequence disagrees with ledger",
                    )),
                );
                continue;
            }
            match source.anchor_and_history_at(basis_seq) {
                Some((expected_anchor, expected_hist))
                    if expected_anchor == intent.basis_anchor
                        && expected_hist == intent.basis_history_root => {}
                _ => {
                    outcomes.insert(
                        intent_id,
                        IntentOutcome::Aborted(conflict(
                            ConflictKind::StaleOrDivergentBasisAnchor,
                            None,
                            None,
                            "basis_anchor or basis_history_root diverged from canonical history",
                        )),
                    );
                    continue;
                }
            }

            // 4. Verify every FSS-103 semantic read witness & extract read sets.
            let mut read_conflict: Option<ConflictWitness> = None;
            let mut extracted = ExtractedReads::default();
            for witness in &intent.read_witnesses {
                if let Err(err) = witness.verify_self_invariants() {
                    read_conflict = Some(conflict(
                        ConflictKind::InvalidReadWitness,
                        None,
                        None,
                        format!("read witness failed invariant check: {err}"),
                    ));
                    break;
                }
                if witness.anchor() != &intent.basis_anchor
                    || witness.history_root() != intent.basis_history_root
                {
                    read_conflict = Some(conflict(
                        ConflictKind::InvalidReadWitness,
                        None,
                        None,
                        "read witness anchor/history_root disagrees with intent basis",
                    ));
                    break;
                }
                extract_reads(witness, &mut extracted);
            }
            if let Some(cw) = read_conflict {
                outcomes.insert(intent_id, IntentOutcome::Aborted(cw));
                continue;
            }

            // 5. Evaluate positive & negative read witnesses against committed history AND earlier winners.
            let mut read_objects: BTreeSet<ObjectId> = BTreeSet::new();
            for pos in &extracted.positives {
                read_objects.insert(pos.object_id.clone());
                if source.object_mutated_after(&pos.object_id, basis_seq) {
                    read_conflict = Some(conflict(
                        ConflictKind::PositiveReadStale,
                        Some(pos.object_id.clone()),
                        None,
                        "positive read witness object mutated in committed history after basis_anchor",
                    ));
                    break;
                }
                // Since object did not mutate after `basis_seq`, head state MUST exactly match
                // the witnessed `(generation, committed_sequence, payload_digest)` at `basis_anchor`.
                match source.current_object_state(&pos.object_id) {
                    Some((generation, seq, digest))
                        if generation == pos.revision.generation
                            && seq == pos.committed_sequence
                            && digest == pos.revision.payload_digest => {}
                    _ => {
                        read_conflict = Some(conflict(
                            ConflictKind::InvalidReadWitness,
                            Some(pos.object_id.clone()),
                            None,
                            "positive read witness disagrees with canonical ledger revision at basis_anchor",
                        ));
                        break;
                    }
                }
                if let Some(winner) = winners
                    .iter()
                    .find(|w| w.write_objects.contains(&pos.object_id))
                {
                    read_conflict = Some(conflict(
                        ConflictKind::PositiveReadStale,
                        Some(pos.object_id.clone()),
                        Some(winner.intent_id.clone()),
                        "positive read witness object written by earlier winner in same round",
                    ));
                    break;
                }
            }
            if let Some(cw) = read_conflict {
                outcomes.insert(intent_id, IntentOutcome::Aborted(cw));
                continue;
            }

            for neg in &extracted.negatives {
                if !neg.certified || !neg.coverage.certifies_absence() {
                    read_conflict = Some(conflict(
                        ConflictKind::UncertifiedAbsenceBasis,
                        Some(neg.object_id.clone()),
                        None,
                        "negative read witness coverage does not certify absence",
                    ));
                    break;
                }
                read_objects.insert(neg.object_id.clone());
                if source.object_existed_at(&neg.object_id, basis_seq) {
                    read_conflict = Some(conflict(
                        ConflictKind::InvalidReadWitness,
                        Some(neg.object_id.clone()),
                        None,
                        "negative read witness claimed absence for object already present at basis_anchor",
                    ));
                    break;
                }
                if source.object_mutated_after(&neg.object_id, basis_seq)
                    || source.current_object_state(&neg.object_id).is_some()
                {
                    read_conflict = Some(conflict(
                        ConflictKind::NegativePhantomWrite,
                        Some(neg.object_id.clone()),
                        None,
                        "phantom write: object proven absent at basis_anchor now exists",
                    ));
                    break;
                }
                if let Some(winner) = winners
                    .iter()
                    .find(|w| w.write_objects.contains(&neg.object_id))
                {
                    read_conflict = Some(conflict(
                        ConflictKind::NegativePhantomWrite,
                        Some(neg.object_id.clone()),
                        Some(winner.intent_id.clone()),
                        "phantom write: earlier winner in same round inserted object proven absent",
                    ));
                    break;
                }
            }
            if let Some(cw) = read_conflict {
                outcomes.insert(intent_id, IntentOutcome::Aborted(cw));
                continue;
            }

            // 6. Write-write conflict detection against committed history AND earlier round winners.
            let write_objects: BTreeSet<ObjectId> =
                intent.writes.iter().map(|d| d.object_id.clone()).collect();
            let mut write_conflict: Option<ConflictWitness> = None;
            for delta in &intent.writes {
                let current_gen = source
                    .current_object_state(&delta.object_id)
                    .map(|(g, _, _)| g);
                let expected_new = current_gen.map_or(1, |g| g.saturating_add(1));
                if delta.prior_generation != current_gen || delta.new_generation != expected_new {
                    write_conflict = Some(conflict(
                        ConflictKind::WriteWriteGenerationConflict,
                        Some(delta.object_id.clone()),
                        None,
                        format!(
                            "stale write generation: prior={:?}/new={} vs current={:?}",
                            delta.prior_generation, delta.new_generation, current_gen
                        ),
                    ));
                    break;
                }
                if let Some(winner) = winners
                    .iter()
                    .find(|w| w.write_objects.contains(&delta.object_id))
                {
                    write_conflict = Some(conflict(
                        ConflictKind::WriteWriteGenerationConflict,
                        Some(delta.object_id.clone()),
                        Some(winner.intent_id.clone()),
                        "concurrent write-write collision with earlier winner in same round",
                    ));
                    break;
                }
            }
            if let Some(cw) = write_conflict {
                outcomes.insert(intent_id, IntentOutcome::Aborted(cw));
                continue;
            }

            // 7. SSI dangerous-structure (write-skew) detection:
            // If an earlier winner W in this concurrent combining round read an object that this
            // intent writes (W --rw--> T) AND either:
            //   - this intent read an object that W writes (already caught above), OR
            //   - W and T executed against concurrent snapshots (neither saw the other's writes)
            //     and W's read set intersects T's write set while T's basis_seq <= head,
            // check for dangerous rw-antidependency: W read something T writes AND (T read
            // something written by W or another winner, or W itself has an incoming rw-edge).
            // Conservatively and soundly: if ANY earlier winner W has `W.read_objects` intersecting
            // `T.write_objects`, admitting T AFTER W in the same coalesced commit means W's read
            // witnesses remain valid only if T's write doesn't form a cycle — wait: if W read X
            // and wrote Y, and T writes X and ALSO has a non-empty read set (or wrote Y), check
            // exact rw-graph cycle / consecutive rw-edges!
            if let Some(skew) = detect_ssi_write_skew(&winners, &read_objects, &write_objects) {
                outcomes.insert(intent_id, IntentOutcome::Aborted(skew));
                continue;
            }

            winners.push(RoundWinner {
                intent_id,
                intent_digest,
                read_objects,
                write_objects,
                writes: intent.writes,
                child_roots: intent.child_roots,
            });
        }

        Ok((winners, outcomes))
    }

    #[allow(clippy::too_many_arguments)]
    fn record_committed_winners(
        &mut self,
        winners: &[RoundWinner],
        committed_sequence: u64,
        batch_id: &BatchId,
        batch_digest: ContentDigest,
        committed_anchor: &LedgerAnchor,
        committed_history_root: ContentDigest,
        outcomes: &mut BTreeMap<String, IntentOutcome>,
    ) -> Result<(), CommitCombinerError> {
        if self.committed_intents.len().saturating_add(winners.len()) > MAX_IDEMPOTENCY_HISTORY {
            return Err(CommitCombinerError::BoundsExceeded {
                observed: self.committed_intents.len().saturating_add(winners.len()),
                maximum: MAX_IDEMPOTENCY_HISTORY,
            });
        }
        for w in winners {
            let receipt = IntentCommitReceipt {
                intent_id: w.intent_id.clone(),
                intent_digest: w.intent_digest,
                committed_sequence,
                batch_id: batch_id.clone(),
                batch_digest,
                committed_anchor: committed_anchor.clone(),
                committed_history_root,
            };
            self.committed_intents
                .insert(w.intent_id.clone(), receipt.clone());
            outcomes.insert(w.intent_id.clone(), IntentOutcome::Committed(receipt));
        }
        Ok(())
    }
}

/// Detects SSI dangerous `rw`-antidependency structures among concurrent winners in the same
/// combining round:
/// - Since winners `W_0 .. W_{k-1}` are already committed conceptually before candidate `T` in the
///   same coalesced batch, a `W_i --rw--> T` edge exists whenever `W_i.read_objects` intersects
///   `T.write_objects`.
/// - If `T` writes an object that `W_i` read AND `W_i` is concurrent with `T` (`W_i.basis_sequence
///   <= T.basis_sequence` or vice versa, both unseen by each other because they are in the same
///   coalesced batch) AND `W_i` has any write (so `W_i` and `T` both mutate state while `W_i`
///   depended on `X` that `T` now mutates in the very same atomic batch), OR if a chain of two
///   consecutive `rw`-edges `W_a --rw--> W_b --rw--> T` forms (Cahill SSI dangerous structure),
///   abort `T` with [`ConflictKind::SsiDangerousWriteSkew`]!
fn detect_ssi_write_skew(
    winners: &[RoundWinner],
    candidate_reads: &BTreeSet<ObjectId>,
    candidate_writes: &BTreeSet<ObjectId>,
) -> Option<ConflictWitness> {
    // 1. Direct write-skew: earlier winner W read object X that candidate writes, while W also
    //    wrote some object Y and candidate read any witness (or vice versa): in a single coalesced
    //    batch, both execute against pre-batch snapshots without observing each other's writes.
    //    If W read X that T writes, T cannot be coalesced into the SAME atomic batch as W without
    //    violating W's snapshot serializability if T also depends on pre-batch state or if W has
    //    an incoming rw-edge from another winner!
    for w in winners {
        if let Some(obj) = w
            .read_objects
            .iter()
            .find(|r| candidate_writes.contains(*r))
        {
            // Check whether W and candidate form a dangerous structure:
            // (a) Candidate has any read witnesses (classic write-skew: W reads X writes Y, T reads
            //     Y or Z and writes X; even if T's read Z wasn't written by W, W's post-condition
            //     is invalidated by T in the same batch), OR
            // (b) Another winner V already had V --rw--> W (2-edge dangerous structure V -> W -> T).
            let has_incoming_rw = winners.iter().any(|v| {
                v.intent_id != w.intent_id
                    && v.read_objects.iter().any(|r| w.write_objects.contains(r))
            });
            if !candidate_reads.is_empty() || has_incoming_rw {
                return Some(conflict(
                    ConflictKind::SsiDangerousWriteSkew,
                    Some(obj.clone()),
                    Some(w.intent_id.clone()),
                    "SSI dangerous rw-antidependency structure detected across concurrent round intents",
                ));
            }
        }
    }
    None
}

fn validate_intent_authority(intent: &CommitIntent) -> Option<ConflictWitness> {
    if !intent.authority.capability_active {
        return Some(conflict(
            ConflictKind::AuthorityOrPrivacyRefused,
            None,
            None,
            "commit capability revoked",
        ));
    }
    if !intent.authority.privacy_active {
        return Some(conflict(
            ConflictKind::AuthorityOrPrivacyRefused,
            None,
            None,
            "privacy authorization revoked",
        ));
    }
    if intent.authority.authority_generation != intent.authority.expected_authority_generation {
        return Some(conflict(
            ConflictKind::AuthorityOrPrivacyRefused,
            None,
            None,
            format!(
                "stale authority generation {} != expected {}",
                intent.authority.authority_generation,
                intent.authority.expected_authority_generation
            ),
        ));
    }
    for delta in &intent.writes {
        if !intent.authority.allowed_planes.contains(&delta.plane) {
            return Some(conflict(
                ConflictKind::AuthorityOrPrivacyRefused,
                Some(delta.object_id.clone()),
                None,
                format!(
                    "plane '{}' not authorized by intent capability",
                    delta.plane.as_str()
                ),
            ));
        }
    }
    None
}

fn conflict(
    kind: ConflictKind,
    object_id: Option<ObjectId>,
    conflicting_intent_id: Option<String>,
    detail: impl Into<String>,
) -> ConflictWitness {
    ConflictWitness {
        kind,
        object_id,
        conflicting_intent_id,
        detail: detail.into(),
        guidance: kind.guidance(),
    }
}

fn assemble_coalesced_batch(
    round_id: u64,
    winners: &[RoundWinner],
) -> Result<(BatchId, Vec<EvidenceDelta>, Vec<ContentDigest>), CommitCombinerError> {
    let mut all_deltas = Vec::new();
    let mut all_children = Vec::new();
    for w in winners {
        all_deltas.extend(w.writes.iter().cloned());
        all_children.extend(w.child_roots.iter().copied());
    }
    let batch_id = BatchId::parse(format!("batch:combiner-round-{round_id:08}"))
        .map_err(|e| CommitCombinerError::Ledger(e.to_string()))?;
    Ok((batch_id, all_deltas, all_children))
}

fn compute_round_digest(
    round_id: u64,
    batch_digest: Option<ContentDigest>,
    anchor: &LedgerAnchor,
    outcomes: &BTreeMap<String, IntentOutcome>,
) -> Result<ContentDigest, CommitCombinerError> {
    let mut enc = CanonicalEncoder::new();
    enc.text(LEDGER_COMMIT_COMBINER_ROUND_DOMAIN);
    enc.u64(round_id);
    match batch_digest {
        Some(d) => {
            enc.bool(true);
            enc.digest(d);
        }
        None => enc.bool(false),
    }
    anchor.encode_canonical(&mut enc);
    enc.u64(outcomes.len() as u64);
    for (id, outcome) in outcomes {
        enc.text(id);
        match outcome {
            IntentOutcome::Committed(r) => {
                enc.u8(1);
                enc.digest(r.intent_digest);
                enc.u64(r.committed_sequence);
                enc.digest(r.batch_digest);
            }
            IntentOutcome::IdempotentReplay(r) => {
                enc.u8(2);
                enc.digest(r.intent_digest);
                enc.u64(r.committed_sequence);
                enc.digest(r.batch_digest);
            }
            IntentOutcome::Aborted(cw) => {
                enc.u8(3);
                enc.text(cw.kind.as_str());
                match &cw.object_id {
                    Some(obj) => {
                        enc.bool(true);
                        obj.encode_canonical(&mut enc);
                    }
                    None => enc.bool(false),
                }
            }
            IntentOutcome::Indeterminate {
                pending_sequence,
                intent_digest,
            } => {
                enc.u8(4);
                enc.u64(*pending_sequence);
                enc.digest(*intent_digest);
            }
        }
    }
    let bytes = enc
        .finish_checked()
        .map_err(|e| CommitCombinerError::Ledger(e.to_string()))?;
    Ok(ContentDigest::sha256(&bytes))
}
