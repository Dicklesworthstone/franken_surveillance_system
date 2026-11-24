#![forbid(unsafe_code)]
//! Canonical ledger history adapters enabling deterministic catch-up and full rebuilds from
//! [`MerkleEpochLedger`], [`LedgerOracle`], [`DurableReferenceLedger`], or batch slices.

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use fss_core::{ContentDigest, DigestAlgorithm, EvidenceDeltaBatch, LedgerAnchor, sha256};
use fss_ledger::{
    DurableReferenceLedger, EPOCH_HEADER_LEN, EPOCH_RECORD_HEADER_LEN, EPOCH_RECORD_MAGIC,
    EPOCH_RECORD_TRAILER_LEN, EPOCH_TRAILER_MAGIC, EpochHeader, LedgerOracle,
    MAX_RECORD_PAYLOAD_BYTES, MerkleEpochLedger, crc32_ieee, decode_batch, epoch_file_path,
};

use crate::error::{ProjectionError, ProjectionIoOperation};
use crate::schema::{HistoryChainMode, ProjectionAnchor};

/// Read-only canonical batch history source consumed by [`crate::MvccProjectionStore::open_or_rebuild`].
pub trait CanonicalBatchSource {
    /// Returns the history-root chaining mode used by this canonical ledger.
    fn history_mode(&self) -> HistoryChainMode;

    /// Returns the canonical genesis [`LedgerAnchor`].
    fn genesis_anchor(&self) -> LedgerAnchor;

    /// Returns the latest committed canonical [`LedgerAnchor`].
    fn head_ledger_anchor(&self) -> LedgerAnchor;

    /// Returns the canonical head history-chain root.
    fn head_history_root(&self) -> ContentDigest;

    /// Verifies whether `candidate` matches the exact committed canonical state at
    /// `candidate.commit_sequence` (`true` if exact match, `false` on anchor mismatch/fork).
    fn matches_anchor(&self, candidate: &ProjectionAnchor) -> Result<bool, ProjectionError>;

    /// Reads canonical committed [`EvidenceDeltaBatch`] entries whose `commit_sequence` falls in
    /// `from_seq..=to_seq` (inclusive, 1-based), in strictly increasing commit order.
    fn read_batches_range(
        &self,
        from_seq: u64,
        to_seq: u64,
    ) -> Result<Vec<EvidenceDeltaBatch>, ProjectionError>;
}

impl CanonicalBatchSource for MerkleEpochLedger {
    fn history_mode(&self) -> HistoryChainMode {
        HistoryChainMode::V2MerkleEpoch
    }

    fn genesis_anchor(&self) -> LedgerAnchor {
        self.genesis_anchor().clone()
    }

    fn head_ledger_anchor(&self) -> LedgerAnchor {
        self.head_anchor().clone()
    }

    fn head_history_root(&self) -> ContentDigest {
        self.history_root()
    }

    fn matches_anchor(&self, candidate: &ProjectionAnchor) -> Result<bool, ProjectionError> {
        let head = self.head_anchor();
        if candidate.commit_sequence > head.commit_sequence {
            return Ok(false);
        }
        if candidate.commit_sequence == 0 {
            let expected = ProjectionAnchor::genesis(self.genesis_anchor(), self.history_mode())?;
            return Ok(*candidate == expected);
        }
        if candidate.commit_sequence == head.commit_sequence {
            return Ok(candidate.authority_root == head.state_root
                && candidate.history_root == self.history_root());
        }
        // Historical anchor check: inspect the single canonical record at candidate.commit_sequence.
        let records = read_epoch_batches_in_range(
            &self.root_dir().join("epochs"),
            candidate.commit_sequence,
            candidate.commit_sequence,
        )?;
        let Some((batch, history_root)) = records.into_iter().next() else {
            return Ok(false);
        };
        Ok(
            batch.new_anchor.commit_sequence == candidate.commit_sequence
                && batch.new_anchor.state_root == candidate.authority_root
                && history_root == candidate.history_root
                && batch.batch_digest == candidate.high_water_digest,
        )
    }

    fn read_batches_range(
        &self,
        from_seq: u64,
        to_seq: u64,
    ) -> Result<Vec<EvidenceDeltaBatch>, ProjectionError> {
        if from_seq == 0 || from_seq > to_seq {
            return Ok(Vec::new());
        }
        let pairs = read_epoch_batches_in_range(&self.root_dir().join("epochs"), from_seq, to_seq)?;
        Ok(pairs.into_iter().map(|(batch, _)| batch).collect())
    }
}

impl CanonicalBatchSource for LedgerOracle {
    fn history_mode(&self) -> HistoryChainMode {
        HistoryChainMode::V1LedgerOracle
    }

    fn genesis_anchor(&self) -> LedgerAnchor {
        self.genesis_anchor().clone()
    }

    fn head_ledger_anchor(&self) -> LedgerAnchor {
        self.head_anchor().clone()
    }

    fn head_history_root(&self) -> ContentDigest {
        self.head_history_root()
    }

    fn matches_anchor(&self, candidate: &ProjectionAnchor) -> Result<bool, ProjectionError> {
        let head = self.head_anchor();
        if candidate.commit_sequence > head.commit_sequence {
            return Ok(false);
        }
        if candidate.commit_sequence == 0 {
            let expected = ProjectionAnchor::genesis(self.genesis_anchor(), self.history_mode())?;
            return Ok(*candidate == expected);
        }
        if candidate.commit_sequence == head.commit_sequence {
            return Ok(candidate.authority_root == head.state_root
                && candidate.history_root == self.head_history_root());
        }
        let mut running_root = self.history_mode().genesis_root(self.genesis_anchor())?;
        for batch in self.batches() {
            let seq = batch.new_anchor.commit_sequence;
            running_root = self.history_mode().successor_root(
                running_root,
                seq,
                batch.batch_digest,
                &batch.new_anchor,
            )?;
            if seq == candidate.commit_sequence {
                return Ok(batch.new_anchor.state_root == candidate.authority_root
                    && running_root == candidate.history_root
                    && batch.batch_digest == candidate.high_water_digest);
            }
        }
        Ok(false)
    }

    fn read_batches_range(
        &self,
        from_seq: u64,
        to_seq: u64,
    ) -> Result<Vec<EvidenceDeltaBatch>, ProjectionError> {
        if from_seq == 0 || from_seq > to_seq {
            return Ok(Vec::new());
        }
        Ok(self
            .batches()
            .filter(|b| {
                let s = b.new_anchor.commit_sequence;
                s >= from_seq && s <= to_seq
            })
            .cloned()
            .collect())
    }
}

impl CanonicalBatchSource for DurableReferenceLedger {
    fn history_mode(&self) -> HistoryChainMode {
        HistoryChainMode::V1LedgerOracle
    }

    fn genesis_anchor(&self) -> LedgerAnchor {
        LedgerAnchor::genesis(&self.current().anchor.site_lineage)
    }

    fn head_ledger_anchor(&self) -> LedgerAnchor {
        self.current().anchor.clone()
    }

    fn head_history_root(&self) -> ContentDigest {
        let mode = HistoryChainMode::V1LedgerOracle;
        let genesis = self.genesis_anchor();
        let Ok(mut root) = mode.genesis_root(&genesis) else {
            return genesis.state_root;
        };
        for batch in self.batches() {
            match mode.successor_root(
                root,
                batch.new_anchor.commit_sequence,
                batch.batch_digest,
                &batch.new_anchor,
            ) {
                Ok(next) => root = next,
                Err(_) => break,
            }
        }
        root
    }

    fn matches_anchor(&self, candidate: &ProjectionAnchor) -> Result<bool, ProjectionError> {
        let head = self.head_ledger_anchor();
        if candidate.commit_sequence > head.commit_sequence {
            return Ok(false);
        }
        let mode = HistoryChainMode::V1LedgerOracle;
        let genesis = self.genesis_anchor();
        if candidate.commit_sequence == 0 {
            let expected = ProjectionAnchor::genesis(&genesis, mode)?;
            return Ok(*candidate == expected);
        }
        let mut running = mode.genesis_root(&genesis)?;
        for batch in self.batches() {
            let seq = batch.new_anchor.commit_sequence;
            running = mode.successor_root(running, seq, batch.batch_digest, &batch.new_anchor)?;
            if seq == candidate.commit_sequence {
                return Ok(batch.new_anchor.state_root == candidate.authority_root
                    && running == candidate.history_root
                    && batch.batch_digest == candidate.high_water_digest);
            }
        }
        Ok(false)
    }

    fn read_batches_range(
        &self,
        from_seq: u64,
        to_seq: u64,
    ) -> Result<Vec<EvidenceDeltaBatch>, ProjectionError> {
        if from_seq == 0 || from_seq > to_seq {
            return Ok(Vec::new());
        }
        Ok(self
            .batches()
            .iter()
            .filter(|b| {
                let s = b.new_anchor.commit_sequence;
                s >= from_seq && s <= to_seq
            })
            .cloned()
            .collect())
    }
}

/// In-memory batch slice adapter implementing [`CanonicalBatchSource`] for deterministic replay
/// and differential testing.
#[derive(Clone, Debug)]
pub struct SliceBatchSource {
    genesis: LedgerAnchor,
    mode: HistoryChainMode,
    batches: Vec<EvidenceDeltaBatch>,
    head_history_root: ContentDigest,
}

impl SliceBatchSource {
    /// Constructs a [`SliceBatchSource`] and precomputes its exact history chain root.
    pub fn new(
        genesis: LedgerAnchor,
        mode: HistoryChainMode,
        batches: Vec<EvidenceDeltaBatch>,
    ) -> Result<Self, ProjectionError> {
        let mut history_root = mode.genesis_root(&genesis)?;
        for batch in &batches {
            history_root = mode.successor_root(
                history_root,
                batch.new_anchor.commit_sequence,
                batch.batch_digest,
                &batch.new_anchor,
            )?;
        }
        Ok(Self {
            genesis,
            mode,
            batches,
            head_history_root: history_root,
        })
    }
}

impl CanonicalBatchSource for SliceBatchSource {
    fn history_mode(&self) -> HistoryChainMode {
        self.mode
    }

    fn genesis_anchor(&self) -> LedgerAnchor {
        self.genesis.clone()
    }

    fn head_ledger_anchor(&self) -> LedgerAnchor {
        self.batches
            .last()
            .map_or_else(|| self.genesis.clone(), |b| b.new_anchor.clone())
    }

    fn head_history_root(&self) -> ContentDigest {
        self.head_history_root
    }

    fn matches_anchor(&self, candidate: &ProjectionAnchor) -> Result<bool, ProjectionError> {
        let head = self.head_ledger_anchor();
        if candidate.commit_sequence > head.commit_sequence {
            return Ok(false);
        }
        if candidate.commit_sequence == 0 {
            let expected = ProjectionAnchor::genesis(&self.genesis, self.mode)?;
            return Ok(*candidate == expected);
        }
        let mut running = self.mode.genesis_root(&self.genesis)?;
        for batch in &self.batches {
            let seq = batch.new_anchor.commit_sequence;
            running =
                self.mode
                    .successor_root(running, seq, batch.batch_digest, &batch.new_anchor)?;
            if seq == candidate.commit_sequence {
                return Ok(batch.new_anchor.state_root == candidate.authority_root
                    && running == candidate.history_root
                    && batch.batch_digest == candidate.high_water_digest);
            }
        }
        Ok(false)
    }

    fn read_batches_range(
        &self,
        from_seq: u64,
        to_seq: u64,
    ) -> Result<Vec<EvidenceDeltaBatch>, ProjectionError> {
        if from_seq == 0 || from_seq > to_seq {
            return Ok(Vec::new());
        }
        Ok(self
            .batches
            .iter()
            .filter(|b| {
                let s = b.new_anchor.commit_sequence;
                s >= from_seq && s <= to_seq
            })
            .cloned()
            .collect())
    }
}

fn list_epoch_ids(epochs_dir: &Path) -> Result<Vec<u64>, ProjectionError> {
    if !epochs_dir.exists() {
        return Ok(Vec::new());
    }
    let mut ids = Vec::new();
    for entry in fs::read_dir(epochs_dir)
        .map_err(|err| ProjectionError::io(ProjectionIoOperation::ReadDir, err))?
    {
        let entry =
            entry.map_err(|err| ProjectionError::io(ProjectionIoOperation::ReadDir, err))?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if let Some(stem) = name_str.strip_suffix(".fssj")
            && stem.len() == 16
            && stem.bytes().all(|b| b.is_ascii_digit())
            && let Ok(id) = stem.parse::<u64>()
        {
            ids.push(id);
        }
    }
    ids.sort_unstable();
    Ok(ids)
}

/// Scans verified `FSSE` v2 epoch segment files under `epochs_dir`, skipping epochs whose headers
/// prove they lie entirely outside `from_seq..=to_seq`.
fn read_epoch_batches_in_range(
    epochs_dir: &Path,
    from_seq: u64,
    to_seq: u64,
) -> Result<Vec<(EvidenceDeltaBatch, ContentDigest)>, ProjectionError> {
    let epoch_ids = list_epoch_ids(epochs_dir)?;
    if epoch_ids.is_empty() {
        return Ok(Vec::new());
    }
    // Read headers once to locate the starting epoch without scanning irrelevant older epochs.
    let mut headers = Vec::with_capacity(epoch_ids.len());
    for epoch_id in epoch_ids {
        let path = epoch_file_path(epochs_dir, epoch_id);
        let mut file = File::open(&path)
            .map_err(|err| ProjectionError::io(ProjectionIoOperation::Open, err))?;
        let mut hdr_buf = [0_u8; EPOCH_HEADER_LEN];
        file.read_exact(&mut hdr_buf)
            .map_err(|err| ProjectionError::io(ProjectionIoOperation::Read, err))?;
        let header = EpochHeader::decode(&hdr_buf, epoch_id)?;
        headers.push((epoch_id, header));
    }

    let mut out = Vec::new();
    for (idx, &(epoch_id, header)) in headers.iter().enumerate() {
        if header.first_commit_seq > to_seq {
            break;
        }
        if let Some(&(_, next_hdr)) = headers.get(idx + 1)
            && next_hdr.first_commit_seq <= from_seq
        {
            continue;
        }
        let path = epoch_file_path(epochs_dir, epoch_id);
        let raw =
            fs::read(&path).map_err(|err| ProjectionError::io(ProjectionIoOperation::Read, err))?;
        parse_epoch_records(&raw, epoch_id, from_seq, to_seq, &mut out)?;
    }
    Ok(out)
}

fn parse_epoch_records(
    raw: &[u8],
    epoch_id: u64,
    from_seq: u64,
    to_seq: u64,
    out: &mut Vec<(EvidenceDeltaBatch, ContentDigest)>,
) -> Result<(), ProjectionError> {
    if raw.len() < EPOCH_HEADER_LEN {
        return Err(ProjectionError::CorruptDerivedStore {
            artifact: "epoch_segment",
            detail: format!("epoch {epoch_id} shorter than header"),
        });
    }
    let mut cursor = EPOCH_HEADER_LEN;
    while cursor < raw.len() {
        let remaining = raw.len() - cursor;
        if remaining < EPOCH_RECORD_HEADER_LEN + EPOCH_RECORD_TRAILER_LEN {
            break;
        }
        let hdr = &raw[cursor..cursor + EPOCH_RECORD_HEADER_LEN];
        if hdr[0..4] != EPOCH_RECORD_MAGIC {
            return Err(ProjectionError::CorruptDerivedStore {
                artifact: "epoch_segment",
                detail: format!("invalid record magic in epoch {epoch_id} at offset {cursor}"),
            });
        }
        let stored_hdr_crc = u32::from_be_bytes([hdr[54], hdr[55], hdr[56], hdr[57]]);
        if crc32_ieee(&hdr[0..54]) != stored_hdr_crc {
            return Err(ProjectionError::CorruptDerivedStore {
                artifact: "epoch_segment",
                detail: format!(
                    "record header CRC mismatch in epoch {epoch_id} at offset {cursor}"
                ),
            });
        }
        let commit_seq = u64::from_be_bytes([
            hdr[6], hdr[7], hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13],
        ]);
        let payload_len = u32::from_be_bytes([hdr[14], hdr[15], hdr[16], hdr[17]]) as usize;
        if payload_len > MAX_RECORD_PAYLOAD_BYTES {
            return Err(ProjectionError::CorruptDerivedStore {
                artifact: "epoch_segment",
                detail: format!("record payload too large in epoch {epoch_id}"),
            });
        }
        let payload_start = cursor + EPOCH_RECORD_HEADER_LEN;
        let payload_end = payload_start.saturating_add(payload_len);
        let record_end = payload_end.saturating_add(EPOCH_RECORD_TRAILER_LEN);
        if record_end > raw.len() {
            break;
        }

        if commit_seq >= from_seq && commit_seq <= to_seq {
            let payload = &raw[payload_start..payload_end];
            let expected_crc = u32::from_be_bytes([hdr[18], hdr[19], hdr[20], hdr[21]]);
            if crc32_ieee(payload) != expected_crc || sha256(payload) != hdr[22..54] {
                return Err(ProjectionError::CorruptDerivedStore {
                    artifact: "epoch_segment",
                    detail: format!("record payload checksum mismatch at seq {commit_seq}"),
                });
            }
            let trailer = &raw[payload_end..record_end];
            if trailer[0..4] != EPOCH_TRAILER_MAGIC {
                return Err(ProjectionError::CorruptDerivedStore {
                    artifact: "epoch_segment",
                    detail: format!("invalid trailer magic at seq {commit_seq}"),
                });
            }
            let trailer_crc =
                u32::from_be_bytes([trailer[36], trailer[37], trailer[38], trailer[39]]);
            if crc32_ieee(&trailer[0..36]) != trailer_crc {
                return Err(ProjectionError::CorruptDerivedStore {
                    artifact: "epoch_segment",
                    detail: format!("trailer CRC mismatch at seq {commit_seq}"),
                });
            }
            let mut root_bytes = [0_u8; 32];
            root_bytes.copy_from_slice(&trailer[4..36]);
            let history_root = ContentDigest::new(DigestAlgorithm::Sha256, root_bytes);
            let batch = decode_batch(payload)?;
            out.push((batch, history_root));
        }

        cursor = record_end;
        if commit_seq >= to_seq {
            break;
        }
    }
    Ok(())
}
