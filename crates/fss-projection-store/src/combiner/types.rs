#![forbid(unsafe_code)]
//! Proposal, receipt, configuration, and production [`CommitSink`] types for [`crate::CommitCombiner`].

use std::collections::BTreeSet;
use std::sync::Arc;

use fss_core::{BatchId, ContentDigest, EvidenceDelta, EvidenceDeltaBatch, ObjectId};
use fss_ledger::{
    CommitReceipt, EpochLedgerError, MAX_ORACLE_CHILDREN_PER_BATCH, MAX_ORACLE_DELTAS_PER_BATCH,
    MerkleEpochLedger,
};
use fss_pack::{DEFAULT_MAX_READ_BYTES, PackObjectInput, PackReadBudget, PackStore};

use crate::error::{CombinerError, ProjectionError};
use crate::payloads::PackStorePayloadResolver;
use crate::schema::HistoryChainMode;
use crate::store::{MvccProjectionStore, ProjectionStore};

/// Default maximum queued proposals waiting in the bounded collector.
pub const DEFAULT_MAX_PENDING_PROPOSALS: usize = 4_096;
/// Default maximum proposals combined into a single coalesced commit wave.
pub const DEFAULT_MAX_BATCH_PROPOSALS: usize = 128;
/// Default maximum total deltas admitted into one coalesced batch.
pub const DEFAULT_MAX_DELTAS_PER_BATCH: usize = 4_096;
/// Default maximum total pack objects admitted into one coalesced batch.
pub const DEFAULT_MAX_OBJECTS_PER_BATCH: usize = 4_096;

/// Owned immutable object payload queued for group-commit packfile persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedPackObject {
    /// Object kind tag (e.g. `PACK_KIND_METADATA`, `PACK_KIND_RAW_PAYLOAD`).
    pub object_kind: u16,
    /// Record-level flags (`0` by default).
    pub flags: u16,
    /// Exact immutable payload bytes.
    pub payload: Vec<u8>,
    /// Optional caller-asserted content digest verified before persistence.
    pub expected_digest: Option<ContentDigest>,
}

impl OwnedPackObject {
    /// Creates a new owned pack object whose SHA-256 digest is verified on ingest.
    #[must_use]
    pub fn new(object_kind: u16, flags: u16, payload: Vec<u8>) -> Self {
        Self {
            object_kind,
            flags,
            payload,
            expected_digest: None,
        }
    }

    /// Creates a new owned pack object pinned to an explicit expected digest.
    #[must_use]
    pub fn with_digest(
        object_kind: u16,
        flags: u16,
        payload: Vec<u8>,
        expected_digest: ContentDigest,
    ) -> Self {
        Self {
            object_kind,
            flags,
            payload,
            expected_digest: Some(expected_digest),
        }
    }

    /// Borrows this owned object as a zero-copy [`PackObjectInput`].
    #[must_use]
    pub fn as_pack_input(&self) -> PackObjectInput<'_> {
        match self.expected_digest {
            Some(digest) => {
                PackObjectInput::with_digest(self.object_kind, self.flags, &self.payload, digest)
            }
            None => PackObjectInput::new(self.object_kind, self.flags, &self.payload),
        }
    }
}

impl From<PackObjectInput<'_>> for OwnedPackObject {
    fn from(input: PackObjectInput<'_>) -> Self {
        Self {
            object_kind: input.object_kind,
            flags: input.flags,
            payload: input.payload.to_vec(),
            expected_digest: input.expected_digest,
        }
    }
}

/// One writer submission queued into [`crate::CommitCombiner`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitProposal {
    /// Deterministic caller request digest used as secondary canonical sort key.
    pub request_digest: ContentDigest,
    /// Sensor or partition scope used as primary canonical sort key.
    pub sensor_scope: String,
    /// Immutable pack objects that must commit durably before the ledger batch publishes.
    pub objects: Vec<OwnedPackObject>,
    /// Canonical semantic deltas to include in the coalesced [`fss_core::EvidenceDeltaBatch`].
    pub deltas: Vec<EvidenceDelta>,
    /// Portable identifier prefix used when synthesizing the deterministic coalesced [`BatchId`].
    pub batch_id_prefix: String,
}

impl CommitProposal {
    /// Constructs a [`CommitProposal`] from borrowed [`PackObjectInput`] slices.
    #[must_use]
    pub fn from_pack_inputs(
        request_digest: ContentDigest,
        sensor_scope: impl Into<String>,
        objects: &[PackObjectInput<'_>],
        deltas: Vec<EvidenceDelta>,
        batch_id_prefix: impl Into<String>,
    ) -> Self {
        Self {
            request_digest,
            sensor_scope: sensor_scope.into(),
            objects: objects.iter().copied().map(OwnedPackObject::from).collect(),
            deltas,
            batch_id_prefix: batch_id_prefix.into(),
        }
    }

    /// Validates structural invariants before entering the combiner queue.
    pub fn validate(&self) -> Result<(), CombinerError> {
        if self.sensor_scope.is_empty() || self.sensor_scope.len() > 256 {
            return Err(CombinerError::InvalidProposal(
                "sensor_scope length outside 1..=256",
            ));
        }
        if self.batch_id_prefix.is_empty() || self.batch_id_prefix.len() > 64 {
            return Err(CombinerError::InvalidProposal(
                "batch_id_prefix length outside 1..=64",
            ));
        }
        if !self
            .batch_id_prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        {
            return Err(CombinerError::InvalidProposal(
                "batch_id_prefix contains non-portable characters",
            ));
        }
        let mut seen = BTreeSet::new();
        for delta in &self.deltas {
            if !seen.insert(delta.object_id.clone()) {
                return Err(CombinerError::DuplicateObjectInProposal {
                    object_id: delta.object_id.clone(),
                });
            }
        }
        Ok(())
    }
}

/// Exact receipt returned to each submitter after its coalesced wave commits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoalescedCommitReceipt {
    /// Committed canonical ledger sequence.
    pub commit_sequence: u64,
    /// Deterministic coalesced batch identifier.
    pub batch_id: BatchId,
    /// Committed canonical authority state root (`LedgerAnchor::state_root`).
    pub authority_root: ContentDigest,
    /// Committed append-only history-chain root.
    pub history_root: ContentDigest,
    /// Canonical digest of the committed `EvidenceDeltaBatch`.
    pub batch_digest: ContentDigest,
    /// Total number of proposals combined into this single commit round.
    pub coalesced_count: usize,
    /// Actual OS durability fsync barriers executed during this commit round (pack + epoch).
    pub fsyncs_executed: u64,
    /// Failure of the optional ledger checkpoint after this batch became durable.
    /// The canonical batch and its projection both succeeded; repair the checkpoint separately.
    pub checkpoint_failure: Option<Arc<str>>,
    /// Zero-based deterministic position in canonical `(sensor_scope, request_digest)` order.
    pub proposal_position: usize,
}

/// Outcome returned by [`CommitSink::commit_coalesced_wave`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SinkCommitOutcome {
    /// Committed canonical sequence.
    pub commit_sequence: u64,
    /// Committed batch identity.
    pub batch_id: BatchId,
    /// Committed authority state root.
    pub authority_root: ContentDigest,
    /// Committed history-chain root.
    pub history_root: ContentDigest,
    /// Committed batch digest.
    pub batch_digest: ContentDigest,
    /// Actual fsync barriers executed for this wave.
    pub fsyncs_executed: u64,
    /// Failure of the optional ledger checkpoint after this batch became durable.
    /// The canonical batch and its projection both succeeded; repair the checkpoint separately.
    pub checkpoint_failure: Option<Arc<str>>,
}

/// Abstract durable commit target invoked exclusively by the elected combiner thread.
pub trait CommitSink: Send {
    /// Returns the currently committed generation of `object_id` (`None` if not yet created).
    fn current_object_generation(&self, object_id: &ObjectId) -> Option<u64>;

    /// Observes an exact durable head receipt without appending or changing any state.
    ///
    /// Unsupported sinks leave the request unresolved. Implementations must also verify
    /// that required materialized publication is complete before returning a receipt.
    fn receipt_for_exact_head(
        &self,
        _batch: &EvidenceDeltaBatch,
    ) -> Result<Option<CommitReceipt>, CombinerError> {
        Ok(None)
    }

    /// Commits an exact prepared batch as a singleton under the combiner's sink mutex.
    ///
    /// Implementations must preserve every anchor, delta, child, and the original batch identity.
    /// A sink without exact-batch support refuses rather than silently converting it to a proposal.
    fn commit_exact_batch(
        &mut self,
        _batch: EvidenceDeltaBatch,
    ) -> Result<SinkCommitOutcome, CombinerError> {
        Err(CombinerError::InvalidProposal(
            "this commit sink does not support exact canonical batches",
        ))
    }

    /// Atomically executes one coalesced commit wave: pack append -> ledger append -> projection apply.
    fn commit_coalesced_wave(
        &mut self,
        batch_id: BatchId,
        objects: &[OwnedPackObject],
        deltas: Vec<EvidenceDelta>,
        child_roots: Vec<ContentDigest>,
    ) -> Result<SinkCommitOutcome, CombinerError>;
}

/// Production [`CommitSink`] uniting [`MerkleEpochLedger`], [`PackStore`], and [`MvccProjectionStore`].
pub struct LedgerPackProjectionSink {
    ledger: MerkleEpochLedger,
    pack_store: Arc<PackStore>,
    projection: Arc<MvccProjectionStore>,
}

impl LedgerPackProjectionSink {
    /// Constructs a production commit sink over an open ledger, pack store, and projection store.
    #[must_use]
    pub const fn new(
        ledger: MerkleEpochLedger,
        pack_store: Arc<PackStore>,
        projection: Arc<MvccProjectionStore>,
    ) -> Self {
        Self {
            ledger,
            pack_store,
            projection,
        }
    }

    /// Borrows the underlying [`MerkleEpochLedger`].
    #[must_use]
    pub const fn ledger(&self) -> &MerkleEpochLedger {
        &self.ledger
    }

    /// Borrows the underlying [`PackStore`].
    #[must_use]
    pub const fn pack_store(&self) -> &Arc<PackStore> {
        &self.pack_store
    }

    /// Borrows the underlying [`MvccProjectionStore`].
    #[must_use]
    pub const fn projection(&self) -> &Arc<MvccProjectionStore> {
        &self.projection
    }

    /// Consumes the sink and returns its component stores.
    #[must_use]
    pub fn into_parts(self) -> (MerkleEpochLedger, Arc<PackStore>, Arc<MvccProjectionStore>) {
        (self.ledger, self.pack_store, self.projection)
    }
}

impl CommitSink for LedgerPackProjectionSink {
    fn current_object_generation(&self, object_id: &ObjectId) -> Option<u64> {
        self.ledger.get_object(object_id).map(|rev| rev.generation)
    }

    fn receipt_for_exact_head(
        &self,
        batch: &EvidenceDeltaBatch,
    ) -> Result<Option<CommitReceipt>, CombinerError> {
        let Some(receipt) = self.ledger.receipt_for_exact_head(batch)? else {
            return Ok(None);
        };
        let projected = self.projection.head_anchor();
        if projected.commit_sequence != receipt.sequence
            || projected.authority_root != receipt.anchor.state_root
            || projected.history_root != receipt.history_root
            || projected.high_water_digest != receipt.batch_digest
        {
            return Err(ProjectionError::AnchorMismatch {
                expected_sequence: receipt.sequence,
                actual_sequence: projected.commit_sequence,
                detail: "exact ledger head has no matching materialized publication",
            }
            .into());
        }
        Ok(Some(receipt))
    }

    fn commit_exact_batch(
        &mut self,
        batch: EvidenceDeltaBatch,
    ) -> Result<SinkCommitOutcome, CombinerError> {
        // A prior durable append may still await projection replay. Exact forwarding
        // must honor the same publication fence as ordinary coalesced proposals.
        let projected = self.projection.head_anchor();
        let canonical = self.ledger.head_anchor();
        if projected.commit_sequence != canonical.commit_sequence
            || projected.authority_root != canonical.state_root
            || projected.history_root != self.ledger.history_root()
        {
            return Err(ProjectionError::AnchorMismatch {
                expected_sequence: canonical.commit_sequence,
                actual_sequence: projected.commit_sequence,
                detail: "replay the projection to the canonical head before forwarding another batch",
            }
            .into());
        }
        if batch.children.len() > MAX_ORACLE_CHILDREN_PER_BATCH
            || batch.deltas.len() > MAX_ORACLE_DELTAS_PER_BATCH
        {
            return Err(CombinerError::InvalidProposal(
                "exact batch exceeds canonical closure bounds",
            ));
        }
        // Forwarding carries no object bytes. Verify the declared closure and implicit
        // payload/witness references before publishing authority, including unknown families.
        // A cumulative budget prevents many small references from causing unbounded reads.
        let mut children: BTreeSet<_> = batch.children.iter().copied().collect();
        for delta in &batch.deltas {
            children.insert(delta.payload_digest);
            if let Some(witness) = delta.witness_digest {
                children.insert(witness);
            }
        }
        let budget = PackReadBudget::new(DEFAULT_MAX_READ_BYTES);
        for child in children {
            let _ = self.pack_store.read_verified_with_budget(&child, &budget)?;
        }

        // Native admission checks the exact live basis, successor, generations, state root,
        // identity, and digest. Never reconstruct this batch against a different head.
        let (ledger_receipt, checkpoint_failure) = match self.ledger.append_batch(batch.clone()) {
            Ok(receipt) => (receipt, None),
            Err(EpochLedgerError::CommittedCheckpointFailed { receipt, source }) => {
                (*receipt, Some(Arc::<str>::from(source.to_string())))
            }
            Err(error) => return Err(error.into()),
        };
        let resolver = PackStorePayloadResolver::new(&self.pack_store);
        let proj_anchor = match self.projection.apply_delta_batch(&batch, &resolver) {
            Ok(anchor) => anchor,
            Err(source) => {
                return Err(CombinerError::CommittedProjectionFailed {
                    receipt: Arc::new(ledger_receipt),
                    checkpoint_failure,
                    source: Arc::new(source),
                });
            }
        };
        Ok(SinkCommitOutcome {
            commit_sequence: ledger_receipt.sequence,
            batch_id: ledger_receipt.batch_id,
            authority_root: proj_anchor.authority_root,
            history_root: proj_anchor.history_root,
            batch_digest: ledger_receipt.batch_digest,
            fsyncs_executed: 1,
            checkpoint_failure,
        })
    }

    fn commit_coalesced_wave(
        &mut self,
        batch_id: BatchId,
        objects: &[OwnedPackObject],
        deltas: Vec<EvidenceDelta>,
        child_roots: Vec<ContentDigest>,
    ) -> Result<SinkCommitOutcome, CombinerError> {
        // A failed projection can leave a durable ledger batch waiting for replay.
        // Do not append another wave on top of a known gap in the materialized view.
        let snapshot = self.projection.snapshot_latest();
        let projected = snapshot.anchor();
        let canonical = self.ledger.head_anchor();
        if projected.commit_sequence != canonical.commit_sequence
            || projected.authority_root != canonical.state_root
            || (snapshot.history_mode == HistoryChainMode::V2MerkleEpoch
                && projected.history_root != self.ledger.history_root())
        {
            return Err(ProjectionError::AnchorMismatch {
                expected_sequence: canonical.commit_sequence,
                actual_sequence: projected.commit_sequence,
                detail: "replay the projection to the canonical head before submitting another wave",
            }.into());
        }

        let pack_fsyncs_before = self.pack_store.telemetry_snapshot()?.pack_fsync_count;
        if !objects.is_empty() {
            let inputs: Vec<PackObjectInput<'_>> =
                objects.iter().map(OwnedPackObject::as_pack_input).collect();
            let _locs = self.pack_store.append_batch(&inputs)?;
        }
        let pack_fsyncs_after = self.pack_store.telemetry_snapshot()?.pack_fsync_count;
        let pack_fsyncs = pack_fsyncs_after.saturating_sub(pack_fsyncs_before);

        let batch = self.ledger.prepare_batch(batch_id, deltas, child_roots)?;
        let (ledger_receipt, checkpoint_failure) = match self.ledger.append_batch(batch.clone()) {
            Ok(receipt) => (receipt, None),
            Err(EpochLedgerError::CommittedCheckpointFailed { receipt, source }) => {
                (*receipt, Some(Arc::<str>::from(source.to_string())))
            }
            Err(error) => return Err(error.into()),
        };
        let epoch_fsyncs = 1_u64;

        let resolver = PackStorePayloadResolver::new(&self.pack_store);
        let proj_anchor = match self.projection.apply_delta_batch(&batch, &resolver) {
            Ok(anchor) => anchor,
            Err(source) => {
                return Err(CombinerError::CommittedProjectionFailed {
                    receipt: Arc::new(ledger_receipt),
                    checkpoint_failure,
                    source: Arc::new(source),
                });
            }
        };

        Ok(SinkCommitOutcome {
            commit_sequence: ledger_receipt.sequence,
            batch_id: ledger_receipt.batch_id,
            authority_root: proj_anchor.authority_root,
            history_root: proj_anchor.history_root,
            batch_digest: ledger_receipt.batch_digest,
            fsyncs_executed: pack_fsyncs.saturating_add(epoch_fsyncs),
            checkpoint_failure,
        })
    }
}

/// Bounded configuration for [`crate::CommitCombiner`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitCombinerConfig {
    /// Maximum proposals permitted in the bounded waiting queue at once.
    pub max_pending_proposals: usize,
    /// Maximum proposals combined into one commit round.
    pub max_batch_proposals: usize,
    /// Maximum deltas combined into one canonical batch.
    pub max_deltas_per_batch: usize,
    /// Maximum pack objects combined into one pack append batch.
    pub max_objects_per_batch: usize,
}

impl Default for CommitCombinerConfig {
    fn default() -> Self {
        Self {
            max_pending_proposals: DEFAULT_MAX_PENDING_PROPOSALS,
            max_batch_proposals: DEFAULT_MAX_BATCH_PROPOSALS,
            max_deltas_per_batch: DEFAULT_MAX_DELTAS_PER_BATCH,
            max_objects_per_batch: DEFAULT_MAX_OBJECTS_PER_BATCH,
        }
    }
}

impl CommitCombinerConfig {
    /// Validates non-zero bounded ceilings.
    pub fn validate(&self) -> Result<(), CombinerError> {
        if self.max_pending_proposals == 0 {
            return Err(CombinerError::InvalidConfig(
                "max_pending_proposals must be >= 1",
            ));
        }
        if self.max_batch_proposals == 0 {
            return Err(CombinerError::InvalidConfig(
                "max_batch_proposals must be >= 1",
            ));
        }
        if self.max_deltas_per_batch == 0 || self.max_deltas_per_batch > MAX_ORACLE_DELTAS_PER_BATCH
        {
            return Err(CombinerError::InvalidConfig(
                "max_deltas_per_batch outside 1..=MAX_ORACLE_DELTAS_PER_BATCH",
            ));
        }
        if self.max_objects_per_batch == 0 {
            return Err(CombinerError::InvalidConfig(
                "max_objects_per_batch must be >= 1",
            ));
        }
        Ok(())
    }
}

/// Cumulative coalescing and fsync amortization telemetry for [`crate::CommitCombiner`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CommitCombinerStats {
    /// Number of coalesced commit rounds executed.
    pub rounds_executed: u64,
    /// Total proposals successfully committed across all rounds.
    pub proposals_committed: u64,
    /// Total individual proposals amortized into shared batches (`proposals_committed - rounds_executed`).
    pub coalesced_commits: u64,
    /// Actual OS fsync barriers executed across all rounds.
    pub fsyncs_executed: u64,
    /// Estimated fsync barriers saved relative to uncoalesced 2-fsync commits.
    pub fsyncs_saved: u64,
}
