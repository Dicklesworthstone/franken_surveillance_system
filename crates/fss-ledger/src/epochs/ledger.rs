#![forbid(unsafe_code)]
//! Massive-scale durable v2 canonical ledger backed by segmented epochs, verified checkpoints,
//! and an incremental `O(log N)` Radix-Merkle accumulator.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

use fss_core::{
    BatchId, ContentDigest, EvidenceDelta, EvidenceDeltaBatch, LedgerAnchor, ObjectId,
    ObjectRevision,
};

use crate::batch_codec::encode_batch;
use crate::error::AppendPhase;
use crate::journal::IncompleteTailPolicy;
use crate::merkle::{MerkleProof, RadixMerkleTrie, merkle_genesis_anchor};
use crate::oracle::{CommitReceipt, MAX_ORACLE_TEXT_BYTES};

use super::checkpoint::{
    CheckpointData, list_checkpoint_files_desc, quarantine_corrupt_checkpoint,
    read_checkpoint_with_head_digest, write_checkpoint_atomic,
};
use super::segment::{
    EPOCH_HEADER_LEN, EpochHeader, create_epoch_file_atomic, list_epoch_ids, scan_epoch_from,
    verify_checkpoint_epoch_anchor,
};
use super::validate::{
    ValidatedBatch, apply_deltas_incremental, check_counts, check_deltas, check_texts,
    delta_order_key, validate_and_apply_batch,
};
use super::verify::{ReplayState, replay_epoch_records, verify_full_chain_from_disk};
use super::writer::{EpochSegmentWriter, quarantine_and_truncate_tail};
use super::{
    CheckpointSummary, EpochCorruptionKind, EpochLedgerConfig, EpochLedgerError,
    EpochVerificationReport, OpenRecoverySummary, genesis_history_root_v2,
};

/// Production-scale durable canonical ledger using incremental Radix-Merkle state roots,
/// segmented immutable epoch files, and atomic self-verifying checkpoints.
#[derive(Debug)]
pub struct MerkleEpochLedger {
    root_dir: PathBuf,
    epochs_dir: PathBuf,
    checkpoints_dir: PathBuf,
    config: EpochLedgerConfig,
    genesis: LedgerAnchor,
    head_anchor: LedgerAnchor,
    head_batch_digest: Option<ContentDigest>,
    history_root: ContentDigest,
    trie: RadixMerkleTrie,
    batch_index: BTreeMap<BatchId, (u64, ContentDigest)>,
    active_writer: EpochSegmentWriter,
    recovery_summary: OpenRecoverySummary,
    latest_checkpoint: Option<CheckpointSummary>,
    pending: Option<ValidatedBatch>,
    // Drop the writer before releasing exclusive root ownership. The lock file stays on disk;
    // unlinking it would permit independent locks on different inodes for the same ledger root.
    _lock_file: File,
}

/// Exact outcome of resolving one previously indeterminate v2 evidence-batch append.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EpochAppendReconciliation {
    /// The attempted batch is durably committed and is now published exactly once.
    Committed(Box<CommitReceipt>),
    /// The attempted batch did not commit; its proven incomplete tail was quarantined if present.
    NotCommitted {
        /// Sequence still available for a safe retry.
        sequence: u64,
    },
}

impl MerkleEpochLedger {
    /// Opens or initializes a v2 [`MerkleEpochLedger`] in `dir`.
    ///
    /// Loads the latest valid checkpoint snapshot in `O(1)` (quarantining corrupt, partial, or
    /// epoch-mismatched newer checkpoints and falling back cleanly to the prior valid checkpoint
    /// or genesis), then replays ONLY the post-checkpoint epoch tail. Truncated tails at the
    /// active epoch end honor `tail_policy` strictly after semantic preflight of all prior records.
    ///
    /// An exclusive operating-system lock on `<dir>/LOCK` is acquired before recovery or file
    /// creation inside the ledger and remains held until this handle is dropped. A competing
    /// writer fails immediately with [`EpochLedgerError::WriterLocked`]. Read-only inspection
    /// remains available through [`super::inspect_epochs_readonly`].
    pub fn open(
        dir: impl AsRef<Path>,
        site_lineage: impl Into<String>,
        config: EpochLedgerConfig,
        tail_policy: IncompleteTailPolicy,
    ) -> Result<Self, EpochLedgerError> {
        config.validate()?;
        let site_lineage = site_lineage.into();
        if site_lineage.is_empty() || site_lineage.len() > MAX_ORACLE_TEXT_BYTES {
            return Err(EpochLedgerError::InvalidConfig(
                "site_lineage length outside 1..=MAX_ORACLE_TEXT_BYTES",
            ));
        }

        let root_dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&root_dir)?;
        let lock_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(root_dir.join("LOCK"))?;
        match lock_file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(EpochLedgerError::WriterLocked),
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }
        let epochs_dir = root_dir.join("epochs");
        let checkpoints_dir = root_dir.join("checkpoints");
        fs::create_dir_all(&epochs_dir)?;
        fs::create_dir_all(&checkpoints_dir)?;

        let genesis = merkle_genesis_anchor(&site_lineage);
        let genesis_history = genesis_history_root_v2(&genesis)?;

        let mut epoch_ids = list_epoch_ids(&epochs_dir)?;
        if epoch_ids.is_empty() {
            let header0 = EpochHeader {
                epoch_id: 0,
                first_commit_seq: 1,
                prev_history_root: genesis_history,
            };
            create_epoch_file_atomic(&epochs_dir, &header0)?;
            epoch_ids.push(0);
        }

        let (mut state, resume_epoch_id, resume_offset, latest_checkpoint, quarantined_checkpoints) =
            load_best_checkpoint_or_genesis(
                &epochs_dir,
                &checkpoints_dir,
                &site_lineage,
                &genesis,
                genesis_history,
            )?;

        let first_epoch_id = epoch_ids
            .first()
            .copied()
            .ok_or(EpochLedgerError::MissingEpoch {
                expected_epoch_id: 0,
            })?;
        let last_epoch_id = epoch_ids
            .last()
            .copied()
            .ok_or(EpochLedgerError::MissingEpoch {
                expected_epoch_id: 0,
            })?;
        if resume_epoch_id < first_epoch_id || resume_epoch_id > last_epoch_id {
            return Err(EpochLedgerError::MissingEpoch {
                expected_epoch_id: resume_epoch_id,
            });
        }

        let mut replayed_tail_batches = 0_u64;
        let mut active_header = EpochHeader {
            epoch_id: 0,
            first_commit_seq: 1,
            prev_history_root: genesis_history,
        };
        let mut active_committed_len = EPOCH_HEADER_LEN as u64;
        let mut active_incomplete_tail: Option<u64> = None;

        for epoch_id in resume_epoch_id..=last_epoch_id {
            let start_offset = if epoch_id == resume_epoch_id {
                resume_offset
            } else {
                EPOCH_HEADER_LEN as u64
            };
            let next_seq = state
                .head_anchor
                .commit_sequence
                .checked_add(1)
                .ok_or(EpochLedgerError::SequenceExhausted)?;
            let report = scan_epoch_from(
                &epochs_dir,
                epoch_id,
                start_offset,
                next_seq,
                state.history_root,
            )?;

            if report.incomplete_tail.is_some() && epoch_id != last_epoch_id {
                return Err(EpochLedgerError::CorruptEpoch {
                    epoch_id,
                    offset: report.committed_len,
                    kind: EpochCorruptionKind::IncompleteTailInSealedEpoch,
                });
            }

            let applied =
                replay_epoch_records(epoch_id, &report.records, &mut state, config.max_objects)?;
            replayed_tail_batches = replayed_tail_batches
                .checked_add(applied)
                .ok_or(EpochLedgerError::SequenceExhausted)?;

            if epoch_id == last_epoch_id {
                active_header = report.header;
                active_committed_len = report.committed_len;
                active_incomplete_tail = report.incomplete_tail;
            }
        }

        let truncated_tail_quarantine = if let Some(tail_offset) = active_incomplete_tail {
            match tail_policy {
                IncompleteTailPolicy::Reject => {
                    return Err(EpochLedgerError::IncompleteTail {
                        epoch_id: last_epoch_id,
                        offset: tail_offset,
                    });
                }
                IncompleteTailPolicy::Truncate => Some(quarantine_and_truncate_tail(
                    &root_dir,
                    &epochs_dir,
                    last_epoch_id,
                    active_committed_len,
                )?),
            }
        } else {
            None
        };

        let active_batch_count = state
            .head_anchor
            .commit_sequence
            .checked_add(1)
            .and_then(|next| next.checked_sub(active_header.first_commit_seq))
            .ok_or(EpochLedgerError::SequenceExhausted)?;

        let active_writer = EpochSegmentWriter::open(
            &epochs_dir,
            active_header,
            active_committed_len,
            active_batch_count,
            state.history_root,
        )?;

        let recovery_summary = OpenRecoverySummary {
            loaded_checkpoint: latest_checkpoint.clone(),
            quarantined_checkpoints,
            replayed_tail_batches,
            truncated_tail_quarantine,
        };

        Ok(Self {
            root_dir,
            epochs_dir,
            checkpoints_dir,
            config,
            genesis,
            head_anchor: state.head_anchor,
            head_batch_digest: state.head_batch_digest,
            history_root: state.history_root,
            trie: state.trie,
            batch_index: state.batch_index,
            active_writer,
            recovery_summary,
            latest_checkpoint,
            pending: None,
            _lock_file: lock_file,
        })
    }

    /// Root directory backing this ledger.
    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Active configuration bounds.
    #[must_use]
    pub const fn config(&self) -> EpochLedgerConfig {
        self.config
    }

    /// Genesis anchor bound to [`crate::merkle::empty_root`].
    #[must_use]
    pub const fn genesis_anchor(&self) -> &LedgerAnchor {
        &self.genesis
    }

    /// Latest committed canonical anchor.
    #[must_use]
    pub const fn head_anchor(&self) -> &LedgerAnchor {
        &self.head_anchor
    }

    /// Digest of the latest durably published batch, or `None` at genesis.
    #[must_use]
    pub const fn head_batch_digest(&self) -> Option<ContentDigest> {
        self.head_batch_digest
    }

    /// Latest committed sequence (`0` at genesis).
    #[must_use]
    pub const fn commit_sequence(&self) -> u64 {
        self.head_anchor.commit_sequence
    }

    /// Latest committed canonical v2 history-chain root.
    #[must_use]
    pub const fn history_root(&self) -> ContentDigest {
        self.history_root
    }

    /// Recovers a receipt only when the offered batch is exactly the verified current head.
    ///
    /// This performs no append, repair, or historical scan. A nonmatching or historical
    /// request remains unresolved; an indeterminate writer must be reconciled separately.
    pub fn receipt_for_exact_head(
        &self,
        batch: &EvidenceDeltaBatch,
    ) -> Result<Option<CommitReceipt>, EpochLedgerError> {
        self.active_writer.ensure_reconciled()?;
        check_counts(batch.deltas.len(), batch.children.len())?;
        check_texts(&batch.deltas, &batch.basis_anchor, &batch.new_anchor)?;
        check_deltas(&batch.deltas)?;
        if !batch.is_canonically_ordered() {
            return Err(EpochLedgerError::NonCanonicalOrdering {
                batch_id: batch.batch_id.clone(),
            });
        }
        let computed = batch.computed_digest();
        if computed != batch.batch_digest {
            return Err(EpochLedgerError::BatchDigestMismatch {
                batch_id: batch.batch_id.clone(),
                declared: batch.batch_digest,
                computed,
            });
        }
        if batch.new_anchor != self.head_anchor {
            return Ok(None);
        }
        let Some(&(sequence, digest)) = self.batch_index.get(&batch.batch_id) else {
            return Ok(None);
        };
        if sequence != self.head_anchor.commit_sequence || digest != batch.batch_digest {
            return Ok(None);
        }
        Ok(Some(CommitReceipt {
            sequence,
            batch_id: batch.batch_id.clone(),
            batch_digest: digest,
            anchor: self.head_anchor.clone(),
            history_root: self.history_root,
        }))
    }

    /// Latest committed canonical v2 Radix-Merkle state root.
    #[must_use]
    pub const fn state_root(&self) -> ContentDigest {
        self.head_anchor.state_root
    }

    /// Number of distinct live (including tombstoned) objects at the head.
    #[must_use]
    pub const fn live_object_count(&self) -> u64 {
        self.trie.len()
    }

    /// Currently active epoch segment identifier.
    #[must_use]
    pub const fn active_epoch_id(&self) -> u64 {
        self.active_writer.epoch_id()
    }

    /// Committed byte offset of the currently active epoch segment file.
    #[must_use]
    pub const fn active_epoch_bytes(&self) -> u64 {
        self.active_writer.committed_len()
    }

    /// Sequence of the unresolved append, if this handle is fenced pending reconciliation.
    #[must_use]
    pub fn pending_append_sequence(&self) -> Option<u64> {
        self.active_writer.pending_sequence()
    }

    /// Recovery summary observed when this handle opened.
    #[must_use]
    pub const fn recovery_summary(&self) -> &OpenRecoverySummary {
        &self.recovery_summary
    }

    /// Summary of the most recently loaded or emitted checkpoint snapshot.
    #[must_use]
    pub const fn latest_checkpoint_summary(&self) -> Option<&CheckpointSummary> {
        self.latest_checkpoint.as_ref()
    }

    /// Reads the latest committed revision of `object_id` in `O(log N)`.
    #[must_use]
    pub fn get_object(&self, object_id: &ObjectId) -> Option<&ObjectRevision> {
        self.trie.get(object_id)
    }

    /// Generates an `O(log N)` standalone Merkle inclusion or non-inclusion proof for `object_id`.
    pub fn prove_object(&self, object_id: &ObjectId) -> Result<MerkleProof, EpochLedgerError> {
        Ok(self.trie.prove(object_id)?)
    }

    /// Materializes a sorted copy of all live (including tombstoned) objects at the head.
    #[must_use]
    pub fn snapshot_objects(&self) -> BTreeMap<ObjectId, ObjectRevision> {
        self.trie
            .iter()
            .map(|(id, rev)| (id.clone(), rev.clone()))
            .collect()
    }

    /// Prepares the canonical v2 successor batch against the current head in `O(k log N)`.
    ///
    /// Deltas are sorted into canonical order and child roots are sorted and deduplicated.
    pub fn prepare_batch(
        &self,
        batch_id: BatchId,
        mut deltas: Vec<EvidenceDelta>,
        child_roots: impl IntoIterator<Item = ContentDigest>,
    ) -> Result<EvidenceDeltaBatch, EpochLedgerError> {
        self.active_writer.ensure_reconciled()?;
        deltas.sort_by(|left, right| delta_order_key(left).cmp(&delta_order_key(right)));
        let mut children: Vec<ContentDigest> = child_roots.into_iter().collect();
        children.sort_unstable();
        children.dedup();

        let basis_anchor = self.head_anchor.clone();
        check_counts(deltas.len(), children.len())?;
        check_texts(&deltas, &basis_anchor, &basis_anchor)?;
        check_deltas(&deltas)?;

        let next_trie = apply_deltas_incremental(&self.trie, &deltas, self.config.max_objects)?;
        let mut new_anchor = basis_anchor.clone();
        new_anchor.commit_sequence = basis_anchor
            .commit_sequence
            .checked_add(1)
            .ok_or(EpochLedgerError::SequenceExhausted)?;
        new_anchor.state_root = next_trie.root();

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

    /// Validates, durably commits into the active epoch segment, and atomically publishes `batch`.
    ///
    /// Triggers atomic epoch rollover (with checkpoint emission) whenever `max_epoch_bytes` or
    /// `max_batches_per_epoch` is reached, and emits a verified checkpoint snapshot every
    /// `checkpoint_stride` commits. Record write/sync failures retain the exact candidate and
    /// fence later preparation, appends, checkpoints, and verification until reconciliation.
    /// A failed periodic checkpoint returns [`EpochLedgerError::CommittedCheckpointFailed`]
    /// carrying the durable receipt; that batch must not be treated as an uncommitted attempt.
    pub fn append_batch(
        &mut self,
        batch: EvidenceDeltaBatch,
    ) -> Result<CommitReceipt, EpochLedgerError> {
        self.active_writer.ensure_reconciled()?;
        let validated = validate_and_apply_batch(
            &self.head_anchor,
            self.history_root,
            &self.trie,
            &self.batch_index,
            batch,
            self.config.max_objects,
        )?;
        let encoded = encode_batch(&validated.batch)?;
        let framed_len = EpochSegmentWriter::framed_record_len(encoded.len())?;

        let batches_full = self.active_writer.batch_count() >= self.config.max_batches_per_epoch;
        let bytes_full = self.active_writer.batch_count() > 0
            && self
                .active_writer
                .committed_len()
                .saturating_add(framed_len)
                > self.config.max_epoch_bytes;
        if batches_full || bytes_full {
            self.rollover_epoch()?;
        }

        let seq = validated.batch.new_anchor.commit_sequence;
        if let Err(error) =
            self.active_writer
                .append_record(seq, &encoded, validated.next_history_root)
        {
            if matches!(&error, EpochLedgerError::AppendIndeterminate { .. }) {
                self.pending = Some(validated);
            }
            return Err(error);
        }

        let receipt = self.publish_validated(validated);
        if self.config.checkpoint_stride > 0
            && seq.is_multiple_of(self.config.checkpoint_stride)
            && let Err(source) = self.emit_checkpoint()
        {
            return Err(EpochLedgerError::CommittedCheckpointFailed {
                receipt: Box::new(receipt),
                source: Box::new(source),
            });
        }

        Ok(receipt)
    }

    fn publish_validated(&mut self, validated: ValidatedBatch) -> CommitReceipt {
        let seq = validated.batch.new_anchor.commit_sequence;
        let receipt = CommitReceipt {
            sequence: seq,
            batch_id: validated.batch.batch_id.clone(),
            batch_digest: validated.batch.batch_digest,
            anchor: validated.batch.new_anchor.clone(),
            history_root: validated.next_history_root,
        };

        self.batch_index.insert(
            validated.batch.batch_id,
            (seq, validated.batch.batch_digest),
        );
        self.head_batch_digest = Some(validated.batch.batch_digest);
        self.head_anchor = validated.batch.new_anchor;
        self.history_root = validated.next_history_root;
        self.trie = validated.next_trie;

        receipt
    }

    /// Resolves the exact retained candidate without releasing writer ownership.
    ///
    /// A complete byte-for-byte match is synchronized before publication. A matching incomplete
    /// suffix remains blocked under `Reject`, or is quarantined and durably truncated under
    /// `Truncate`. Divergent bytes, changed committed boundaries, and reconciliation I/O failures
    /// preserve the fence. At most the bounded attempted record is read; historical replay is
    /// unnecessary. Losing the handle instead uses the normal open/recovery rules.
    pub fn reconcile_pending(
        &mut self,
        tail_policy: IncompleteTailPolicy,
    ) -> Result<EpochAppendReconciliation, EpochLedgerError> {
        let pending = self
            .pending
            .take()
            .ok_or(EpochLedgerError::NoPendingAppend)?;
        let sequence = pending.batch.new_anchor.commit_sequence;
        match self
            .active_writer
            .reconcile_pending(&self.root_dir, tail_policy)
        {
            Ok(true) => Ok(EpochAppendReconciliation::Committed(Box::new(
                self.publish_validated(pending),
            ))),
            Ok(false) => Ok(EpochAppendReconciliation::NotCommitted { sequence }),
            Err(error) => {
                self.pending = Some(pending);
                Err(error)
            }
        }
    }

    /// Injects one post-I/O failure at an append or reconciliation phase for fault qualification.
    #[doc(hidden)]
    pub fn fail_journal_after_phase(&mut self, phase: AppendPhase) {
        self.active_writer.fail_after_phase(phase);
    }

    /// Explicitly emits an immutable verified checkpoint snapshot at the current head commit.
    pub fn force_checkpoint(&mut self) -> Result<CheckpointSummary, EpochLedgerError> {
        self.active_writer.ensure_reconciled()?;
        self.emit_checkpoint()
    }

    /// Independently verifies EVERY epoch segment file and EVERY committed batch from genesis
    /// through the current head, recomputing every Merkle hash from scratch.
    pub fn verify_full_chain(&self) -> Result<EpochVerificationReport, EpochLedgerError> {
        self.active_writer.ensure_reconciled()?;
        verify_full_chain_from_disk(
            &self.epochs_dir,
            &self.genesis,
            self.config.max_objects,
            &self.head_anchor,
            self.history_root,
            &self.trie,
            &self.batch_index,
        )
    }

    fn rollover_epoch(&mut self) -> Result<(), EpochLedgerError> {
        self.active_writer.seal()?;

        let already_checkpointed = self
            .latest_checkpoint
            .as_ref()
            .is_some_and(|cp| cp.commit_sequence == self.head_anchor.commit_sequence);
        if !already_checkpointed {
            let _ = self.emit_checkpoint()?;
        }

        let next_epoch_id = self
            .active_writer
            .epoch_id()
            .checked_add(1)
            .ok_or(EpochLedgerError::SequenceExhausted)?;
        let next_first_seq = self
            .head_anchor
            .commit_sequence
            .checked_add(1)
            .ok_or(EpochLedgerError::SequenceExhausted)?;
        let next_header = EpochHeader {
            epoch_id: next_epoch_id,
            first_commit_seq: next_first_seq,
            prev_history_root: self.history_root,
        };
        let _ = create_epoch_file_atomic(&self.epochs_dir, &next_header)?;
        let mut next_writer = EpochSegmentWriter::open(
            &self.epochs_dir,
            next_header,
            EPOCH_HEADER_LEN as u64,
            0,
            self.history_root,
        )?;
        if let Some(phase) = self.active_writer.take_failure_injection() {
            next_writer.fail_after_phase(phase);
        }
        self.active_writer = next_writer;
        Ok(())
    }

    fn emit_checkpoint(&mut self) -> Result<CheckpointSummary, EpochLedgerError> {
        let data = CheckpointData {
            commit_sequence: self.head_anchor.commit_sequence,
            history_root: self.history_root,
            merkle_state_root: self.trie.root(),
            latest_anchor: self.head_anchor.clone(),
            epoch_id: self.active_writer.epoch_id(),
            epoch_byte_offset: self.active_writer.committed_len(),
            live_object_count: self.trie.len(),
            trie: self.trie.clone(),
            batch_index: self.batch_index.clone(),
        };
        let summary = write_checkpoint_atomic(&self.checkpoints_dir, &data)?;
        self.latest_checkpoint = Some(summary.clone());
        Ok(summary)
    }
}

type LoadedCheckpointResult = (
    ReplayState,
    u64,
    u64,
    Option<CheckpointSummary>,
    Vec<(PathBuf, super::CheckpointCorruptionKind)>,
);

fn load_best_checkpoint_or_genesis(
    epochs_dir: &Path,
    checkpoints_dir: &Path,
    site_lineage: &str,
    genesis: &LedgerAnchor,
    genesis_history: ContentDigest,
) -> Result<LoadedCheckpointResult, EpochLedgerError> {
    let mut quarantined = Vec::new();
    for (seq, path) in list_checkpoint_files_desc(checkpoints_dir)? {
        match read_checkpoint_with_head_digest(&path, Some(seq), site_lineage, false) {
            Ok((data, file_bytes, head_batch_digest)) => {
                match verify_checkpoint_epoch_anchor(
                    epochs_dir,
                    data.epoch_id,
                    data.epoch_byte_offset,
                    data.history_root,
                ) {
                    Ok(()) => {
                        let summary = CheckpointSummary {
                            path,
                            commit_sequence: data.commit_sequence,
                            history_root: data.history_root,
                            merkle_state_root: data.merkle_state_root,
                            epoch_id: data.epoch_id,
                            epoch_byte_offset: data.epoch_byte_offset,
                            live_object_count: data.live_object_count,
                            file_bytes,
                        };
                        let state = ReplayState {
                            head_anchor: data.latest_anchor,
                            head_batch_digest,
                            history_root: data.history_root,
                            trie: data.trie,
                            batch_index: data.batch_index,
                        };
                        return Ok((
                            state,
                            data.epoch_id,
                            data.epoch_byte_offset,
                            Some(summary),
                            quarantined,
                        ));
                    }
                    Err(kind) => {
                        let qpath = quarantine_corrupt_checkpoint(checkpoints_dir, &path)?;
                        quarantined.push((qpath, kind));
                    }
                }
            }
            Err(kind) => {
                let qpath = quarantine_corrupt_checkpoint(checkpoints_dir, &path)?;
                quarantined.push((qpath, kind));
            }
        }
    }

    let state = ReplayState {
        head_anchor: genesis.clone(),
        head_batch_digest: None,
        history_root: genesis_history,
        trie: RadixMerkleTrie::new(),
        batch_index: BTreeMap::new(),
    };
    Ok((state, 0, EPOCH_HEADER_LEN as u64, None, quarantined))
}
