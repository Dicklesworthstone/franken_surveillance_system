#![forbid(unsafe_code)]
//! Shared epoch-record semantic replay and full-chain genesis-to-head verification.

use std::collections::BTreeMap;
use std::path::Path;

use fss_core::{BatchId, ContentDigest, EvidenceDeltaBatch, LedgerAnchor};

use crate::batch_codec::decode_batch;
use crate::durable::CommittedBatchPosition;
use crate::merkle::{RadixMerkleTrie, merkle_genesis_anchor};

use super::segment::{EPOCH_HEADER_LEN, EpochRecord, list_epoch_ids, scan_epoch_from};
use super::validate::validate_and_apply_batch;
use super::{
    EpochCorruptionKind, EpochLedgerError, EpochVerificationReport, genesis_history_root_v2,
};

/// Result of a strictly read-only, lock-free inspection of a v2 `MerkleEpochLedger` directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochLedgerInspection {
    /// Deterministic empty genesis anchor for `site_lineage`.
    pub genesis_anchor: LedgerAnchor,
    /// Verified committed head anchor through the last intact record.
    pub head_anchor: LedgerAnchor,
    /// Verified v2 history-chain root at `head_anchor`.
    pub history_root: ContentDigest,
    /// All committed batches in strictly ascending commit sequence order.
    pub batches: Vec<EvidenceDeltaBatch>,
    /// Committed byte-prefix and record-root positions parallel to `batches`.
    pub positions: Vec<CommittedBatchPosition>,
    /// Total epoch segment files verified.
    pub epochs_verified: u64,
    /// Number of live objects tracked in the Radix-Merkle trie at `head_anchor`.
    pub live_objects: u64,
    /// `true` if the final active epoch file carried an uncommitted/partial tail record.
    pub incomplete_tail: bool,
}

/// Strictly read-only, lock-free verification and replay of a v2 `MerkleEpochLedger` directory
/// (`<ledger_dir>/epochs/`). NEVER creates directories, writes files, quarantines, or takes locks.
pub fn inspect_epochs_readonly(
    ledger_dir: &Path,
    site_lineage: &str,
) -> Result<EpochLedgerInspection, EpochLedgerError> {
    let epochs_dir = ledger_dir.join("epochs");
    if !epochs_dir.is_dir() {
        return Err(EpochLedgerError::MissingEpoch {
            expected_epoch_id: 0,
        });
    }
    let epoch_ids = list_epoch_ids(&epochs_dir)?;
    if epoch_ids.first().copied() != Some(0) {
        return Err(EpochLedgerError::MissingEpoch {
            expected_epoch_id: 0,
        });
    }
    let last_epoch_id = epoch_ids
        .last()
        .copied()
        .ok_or(EpochLedgerError::MissingEpoch {
            expected_epoch_id: 0,
        })?;

    let genesis_anchor = merkle_genesis_anchor(site_lineage);
    let genesis_history = genesis_history_root_v2(&genesis_anchor)?;
    let mut state = ReplayState {
        head_anchor: genesis_anchor.clone(),
        history_root: genesis_history,
        trie: RadixMerkleTrie::new(),
        batch_index: BTreeMap::new(),
        head_batch_digest: None,
    };
    let mut batches = Vec::new();
    let mut positions = Vec::new();
    let mut cumulative_bytes = 0_u64;
    let mut incomplete_tail = false;

    for &epoch_id in &epoch_ids {
        let expected_first_seq = state
            .head_anchor
            .commit_sequence
            .checked_add(1)
            .ok_or(EpochLedgerError::SequenceExhausted)?;
        let report = scan_epoch_from(
            &epochs_dir,
            epoch_id,
            EPOCH_HEADER_LEN as u64,
            expected_first_seq,
            state.history_root,
        )?;
        if let Some(tail_offset) = report.incomplete_tail {
            if epoch_id != last_epoch_id {
                return Err(EpochLedgerError::IncompleteTail {
                    epoch_id,
                    offset: tail_offset,
                });
            }
            incomplete_tail = true;
        }
        for record in &report.records {
            let batch =
                decode_batch(&record.payload).map_err(|_| EpochLedgerError::CorruptEpoch {
                    epoch_id,
                    offset: record.start_offset,
                    kind: EpochCorruptionKind::BatchCodec,
                })?;
            if batch.new_anchor.commit_sequence != record.commit_seq {
                return Err(EpochLedgerError::CorruptEpoch {
                    epoch_id,
                    offset: record.start_offset,
                    kind: EpochCorruptionKind::RecordSequence,
                });
            }
            let validated = validate_and_apply_batch(
                &state.head_anchor,
                state.history_root,
                &state.trie,
                &state.batch_index,
                batch,
                None,
            )?;
            if validated.next_history_root != record.history_root {
                return Err(EpochLedgerError::CorruptEpoch {
                    epoch_id,
                    offset: record.start_offset,
                    kind: EpochCorruptionKind::HistoryRootMismatch,
                });
            }
            let record_len = record.end_offset.saturating_sub(record.start_offset);
            cumulative_bytes = cumulative_bytes.saturating_add(record_len);
            let commit_sequence = validated.batch.new_anchor.commit_sequence;
            state.batch_index.insert(
                validated.batch.batch_id.clone(),
                (commit_sequence, validated.batch.batch_digest),
            );
            state.head_batch_digest = Some(validated.batch.batch_digest);
            state.head_anchor = validated.batch.new_anchor.clone();
            state.history_root = validated.next_history_root;
            state.trie = validated.next_trie;
            batches.push(validated.batch);
            positions.push(CommittedBatchPosition {
                commit_sequence,
                prefix_len: cumulative_bytes,
                record_root: validated.next_history_root,
            });
        }
    }

    state.trie.verify_all_digests()?;
    Ok(EpochLedgerInspection {
        genesis_anchor,
        head_anchor: state.head_anchor,
        history_root: state.history_root,
        batches,
        positions,
        epochs_verified: epoch_ids.len() as u64,
        live_objects: state.trie.len(),
        incomplete_tail,
    })
}

/// Mutable canonical ledger state advanced during tail replay or full-chain verification.
pub(super) struct ReplayState {
    pub(super) head_anchor: LedgerAnchor,
    pub(super) history_root: ContentDigest,
    pub(super) head_batch_digest: Option<ContentDigest>,
    pub(super) trie: RadixMerkleTrie,
    pub(super) batch_index: BTreeMap<BatchId, (u64, ContentDigest)>,
}

/// Decodes, semantically validates, and applies every framed record in `records` to `state`.
pub(super) fn replay_epoch_records(
    epoch_id: u64,
    records: &[EpochRecord],
    state: &mut ReplayState,
    max_objects: Option<u64>,
) -> Result<u64, EpochLedgerError> {
    let mut applied = 0_u64;
    for record in records {
        let batch = decode_batch(&record.payload).map_err(|_| EpochLedgerError::CorruptEpoch {
            epoch_id,
            offset: record.start_offset,
            kind: EpochCorruptionKind::BatchCodec,
        })?;
        if batch.new_anchor.commit_sequence != record.commit_seq {
            return Err(EpochLedgerError::CorruptEpoch {
                epoch_id,
                offset: record.start_offset,
                kind: EpochCorruptionKind::RecordSequence,
            });
        }
        let validated = validate_and_apply_batch(
            &state.head_anchor,
            state.history_root,
            &state.trie,
            &state.batch_index,
            batch,
            max_objects,
        )?;
        if validated.next_history_root != record.history_root {
            return Err(EpochLedgerError::CorruptEpoch {
                epoch_id,
                offset: record.start_offset,
                kind: EpochCorruptionKind::HistoryRootMismatch,
            });
        }
        state.batch_index.insert(
            validated.batch.batch_id,
            (
                validated.batch.new_anchor.commit_sequence,
                validated.batch.batch_digest,
            ),
        );
        state.head_batch_digest = Some(validated.batch.batch_digest);
        state.head_anchor = validated.batch.new_anchor;
        state.history_root = validated.next_history_root;
        state.trie = validated.next_trie;
        applied = applied
            .checked_add(1)
            .ok_or(EpochLedgerError::SequenceExhausted)?;
    }
    Ok(applied)
}

/// Replays and verifies every epoch segment file from genesis through head against live state.
pub(super) fn verify_full_chain_from_disk(
    epochs_dir: &Path,
    genesis: &LedgerAnchor,
    max_objects: Option<u64>,
    live_head_anchor: &LedgerAnchor,
    live_history_root: ContentDigest,
    live_trie: &RadixMerkleTrie,
    live_batch_index: &BTreeMap<BatchId, (u64, ContentDigest)>,
) -> Result<EpochVerificationReport, EpochLedgerError> {
    let epoch_ids = list_epoch_ids(epochs_dir)?;
    if epoch_ids.first().copied() != Some(0) {
        return Err(EpochLedgerError::MissingEpoch {
            expected_epoch_id: 0,
        });
    }

    let mut state = ReplayState {
        head_anchor: genesis.clone(),
        history_root: genesis_history_root_v2(genesis)?,
        trie: RadixMerkleTrie::new(),
        batch_index: BTreeMap::new(),
        head_batch_digest: None,
    };
    let mut batches_verified = 0_u64;

    for &epoch_id in &epoch_ids {
        let expected_first_seq = state
            .head_anchor
            .commit_sequence
            .checked_add(1)
            .ok_or(EpochLedgerError::SequenceExhausted)?;
        let report = scan_epoch_from(
            epochs_dir,
            epoch_id,
            EPOCH_HEADER_LEN as u64,
            expected_first_seq,
            state.history_root,
        )?;
        if let Some(tail_offset) = report.incomplete_tail {
            return Err(EpochLedgerError::IncompleteTail {
                epoch_id,
                offset: tail_offset,
            });
        }
        let applied = replay_epoch_records(epoch_id, &report.records, &mut state, max_objects)?;
        batches_verified = batches_verified
            .checked_add(applied)
            .ok_or(EpochLedgerError::SequenceExhausted)?;
    }

    state.trie.verify_all_digests()?;
    if &state.head_anchor != live_head_anchor {
        return Err(EpochLedgerError::LiveStateDivergence(
            "head_anchor mismatch",
        ));
    }
    if state.history_root != live_history_root {
        return Err(EpochLedgerError::LiveStateDivergence(
            "history_root mismatch",
        ));
    }
    if state.trie.root() != live_trie.root() || state.trie.len() != live_trie.len() {
        return Err(EpochLedgerError::LiveStateDivergence(
            "merkle trie mismatch",
        ));
    }
    if &state.batch_index != live_batch_index {
        return Err(EpochLedgerError::LiveStateDivergence(
            "batch_index mismatch",
        ));
    }

    Ok(EpochVerificationReport {
        epochs_verified: epoch_ids.len() as u64,
        batches_verified,
        live_objects: state.trie.len(),
        head_commit_sequence: state.head_anchor.commit_sequence,
        history_root: state.history_root,
        state_root: state.head_anchor.state_root,
    })
}
