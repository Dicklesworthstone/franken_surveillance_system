#![forbid(unsafe_code)]
//! CRC32C-framed segmented epoch journal (`{epoch_id:016}.fssa`) with SHA-256 sealed epoch
//! trailers and periodic verified checkpoint snapshots (`seq-{last_seq:020}.fsac`).
//!
//! Supports `O(tail)` cold-open from the latest verified checkpoint, strict
//! `IncompleteTailPolicy::Reject`, crash-cut mid-epoch rollover recovery under
//! `IncompleteTailPolicy::Truncate`, and bit-exact full replay from immutable sealed epochs.

use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fss_core::ContentDigest;
use fss_ledger::IncompleteTailPolicy;
use fss_pack::DurabilityMode;

use super::epoch_checkpoint::{
    load_latest_valid_checkpoint, quarantine_tail_slice, write_checkpoint_atomic,
};
use super::epoch_codec::{
    EpochHeader, EpochSeal, advance_chain_digest, create_epoch_file_atomic, encode_epoch_seal,
    encode_record_frame, genesis_chain_digest, list_epoch_ids, open_rw, read_epoch_header,
    recover_active_header, scan_epoch_tail,
};
use crate::error::{ProjectionError, ProjectionIoOperation};
use crate::wal::sync_file_mode;

pub use super::epoch_codec::{
    AGENT_EPOCH_CHECKPOINT_DOMAIN, AGENT_EPOCH_CHECKPOINT_MAGIC, AGENT_EPOCH_FILE_MAGIC,
    AGENT_EPOCH_FORMAT_VERSION, AGENT_EPOCH_HEADER_DOMAIN, AGENT_EPOCH_HEADER_LEN,
    AGENT_EPOCH_RECORD_MAGIC, AGENT_EPOCH_SEAL_DOMAIN, AGENT_EPOCH_SEAL_LEN,
    AGENT_EPOCH_SEAL_MAGIC, AGENT_RECORD_HEADER_LEN, AGENT_RECORD_TRAILER_LEN,
    DEFAULT_AGENT_CHECKPOINT_STRIDE, DEFAULT_MAX_AGENT_EPOCH_BYTES, MAX_AGENT_CHECKPOINT_BYTES,
    MAX_AGENT_RECORD_BYTES, MIN_AGENT_EPOCH_BYTES,
};

/// Configuration bounds and durability policy for [`SegmentedEpochJournal`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochJournalConfig {
    /// Maximum byte size of an epoch segment before sealing and rolling over (default 64 MiB).
    pub max_epoch_bytes: u64,
    /// Periodic verified checkpoint stride in records (`0` disables automatic stride checks).
    pub checkpoint_stride: u64,
    /// OS fsync durability barrier mode.
    pub durability: DurabilityMode,
    /// Handling policy for incomplete or corrupt trailing bytes at the active epoch tail.
    pub tail_policy: IncompleteTailPolicy,
}

impl Default for EpochJournalConfig {
    fn default() -> Self {
        Self {
            max_epoch_bytes: DEFAULT_MAX_AGENT_EPOCH_BYTES,
            checkpoint_stride: DEFAULT_AGENT_CHECKPOINT_STRIDE,
            durability: DurabilityMode::Fsync,
            tail_policy: IncompleteTailPolicy::Reject,
        }
    }
}

impl EpochJournalConfig {
    /// Validates configuration invariants, failing closed on sub-minimum bounds.
    pub fn validate(&self) -> Result<(), ProjectionError> {
        if self.max_epoch_bytes < MIN_AGENT_EPOCH_BYTES {
            return Err(ProjectionError::InvalidRequest(
                "max_epoch_bytes below minimum bound",
            ));
        }
        Ok(())
    }
}

/// One CRC32C-verified record decoded from a segmented epoch file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochJournalRecord {
    /// Strictly monotonic 1-based journal sequence number.
    pub seq: u64,
    /// Caller-assigned record kind tag.
    pub kind: u16,
    /// Exact verified canonical record payload bytes.
    pub body: Vec<u8>,
}

/// Receipt emitted after writing an immutable verified checkpoint snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochCheckpointReceipt {
    /// Filesystem path of the published checkpoint snapshot.
    pub path: PathBuf,
    /// Last journal sequence captured by the checkpoint.
    pub last_seq: u64,
    /// Epoch segment containing `last_seq`.
    pub epoch_id: u64,
    /// Exact byte offset immediately following `last_seq` inside `epoch_id`.
    pub epoch_byte_offset: u64,
    /// Chained SHA-256 epoch digest at `last_seq`.
    pub chain_digest: ContentDigest,
    /// Total on-disk checkpoint size in bytes.
    pub file_bytes: usize,
}

/// Diagnostics and replay artifacts returned when opening a [`SegmentedEpochJournal`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochOpenReport {
    /// Verified checkpoint sequence loaded on open (`None` when opened from genesis).
    pub loaded_checkpoint_seq: Option<u64>,
    /// Opaque verified checkpoint payload bytes owned by the index layer.
    pub checkpoint_payload: Option<Vec<u8>>,
    /// Post-checkpoint (or genesis) tail records replayed to reach head.
    pub tail_records: Vec<EpochJournalRecord>,
    /// Trailing torn bytes truncated and quarantined under `IncompleteTailPolicy::Truncate`.
    pub truncated_tail_bytes: u64,
    /// Corrupt checkpoint files quarantined during fallback.
    pub quarantined_checkpoints: u64,
    /// Total contiguous epoch segment files currently present on disk.
    pub epoch_count: u64,
}

/// Append-only segmented epoch journal with SHA-256 sealed trailers and verified checkpoints.
pub struct SegmentedEpochJournal {
    root_dir: PathBuf,
    config: EpochJournalConfig,
    active_file: File,
    active_epoch_id: u64,
    active_offset: u64,
    active_record_count: u64,
    active_sealed: bool,
    last_seq: u64,
    chain_digest: ContentDigest,
    records_since_checkpoint: u64,
}

impl SegmentedEpochJournal {
    /// Opens or initializes a segmented epoch journal, loading the latest verified checkpoint
    /// and replaying only post-checkpoint tail records in `O(tail)`.
    pub fn open(
        root_dir: PathBuf,
        config: EpochJournalConfig,
    ) -> Result<(Self, EpochOpenReport), ProjectionError> {
        Self::open_inner(root_dir, config, true)
    }

    /// Opens the journal ignoring all checkpoints, verifying and replaying every epoch from
    /// genesis to prove bit-identical rebuildability from immutable sealed epoch segments.
    pub fn open_from_genesis(
        root_dir: PathBuf,
        config: EpochJournalConfig,
    ) -> Result<(Self, EpochOpenReport), ProjectionError> {
        Self::open_inner(root_dir, config, false)
    }

    fn open_inner(
        root_dir: PathBuf,
        config: EpochJournalConfig,
        use_checkpoints: bool,
    ) -> Result<(Self, EpochOpenReport), ProjectionError> {
        config.validate()?;
        let epochs_dir = root_dir.join("epochs");
        let checkpoints_dir = root_dir.join("checkpoints");
        for dir in [&epochs_dir, &checkpoints_dir] {
            if !dir.is_dir() {
                fs::create_dir_all(dir)
                    .map_err(|err| ProjectionError::io(ProjectionIoOperation::CreateDir, err))?;
            }
        }
        let mut epoch_ids = list_epoch_ids(&epochs_dir)?;
        if epoch_ids.is_empty() {
            return Self::init_fresh(root_dir, &epochs_dir, config);
        }
        let mut truncated_tail_bytes = 0_u64;
        let last_hdr = recover_active_header(
            &root_dir,
            &epochs_dir,
            &mut epoch_ids,
            config.tail_policy,
            &mut truncated_tail_bytes,
        )?;
        let last_epoch_id = last_hdr.epoch_id;
        let mut quarantined_checkpoints = 0_u64;
        let loaded_ckpt = if use_checkpoints {
            load_latest_valid_checkpoint(
                &root_dir,
                &checkpoints_dir,
                &epochs_dir,
                last_epoch_id,
                config.tail_policy,
                &mut quarantined_checkpoints,
            )?
        } else {
            None
        };
        let (start_epoch, start_offset, mut cur_seq, mut cur_chain, ckpt_seq, ckpt_payload) =
            match loaded_ckpt {
                Some(c) => (
                    c.epoch_id,
                    c.epoch_byte_offset,
                    c.last_seq,
                    c.chain_digest,
                    Some(c.last_seq),
                    Some(c.payload),
                ),
                None => (
                    0_u64,
                    AGENT_EPOCH_HEADER_LEN as u64,
                    0_u64,
                    genesis_chain_digest(),
                    None,
                    None,
                ),
            };
        let mut tail_records = Vec::new();
        let mut active_offset = start_offset;
        let mut active_sealed = false;
        for eid in start_epoch..=last_epoch_id {
            let is_last = eid == last_epoch_id;
            let path = epoch_path(&epochs_dir, eid);
            let offset_in_epoch = if eid == start_epoch {
                start_offset
            } else {
                let hdr = if is_last {
                    last_hdr
                } else {
                    read_epoch_header(&path, eid)?
                };
                if hdr.first_seq != cur_seq.saturating_add(1) || hdr.prev_chain != cur_chain {
                    return Err(corrupt_epoch(format!(
                        "inter-epoch chain discontinuity at {eid}"
                    )));
                }
                AGENT_EPOCH_HEADER_LEN as u64
            };
            let scan = scan_epoch_tail(&path, eid, offset_in_epoch, cur_seq, cur_chain, is_last)?;
            if let Some(torn_at) = scan.torn_tail_offset {
                if !is_last || config.tail_policy == IncompleteTailPolicy::Reject {
                    return Err(corrupt_epoch(format!(
                        "incomplete or corrupt tail at {torn_at} in epoch {eid}"
                    )));
                }
                let raw_len = fs::metadata(&path)
                    .map_err(|err| ProjectionError::io(ProjectionIoOperation::Metadata, err))?
                    .len();
                quarantine_tail_slice(&root_dir, &path, eid, torn_at)?;
                let trunc_file = open_rw(&path)?;
                trunc_file
                    .set_len(torn_at)
                    .map_err(|err| ProjectionError::io(ProjectionIoOperation::Truncate, err))?;
                sync_file_mode(&trunc_file, config.durability)?;
                truncated_tail_bytes =
                    truncated_tail_bytes.saturating_add(raw_len.saturating_sub(torn_at));
            }
            if !is_last && scan.sealed.is_none() {
                return Err(corrupt_epoch(format!(
                    "non-tail epoch {eid} missing SHA-256 seal trailer"
                )));
            }
            cur_seq = scan.last_seq;
            cur_chain = scan.chain_digest;
            active_offset = scan.committed_len;
            active_sealed = scan.sealed.is_some();
            tail_records.extend(scan.records);
        }
        let active_record_count = cur_seq.saturating_sub(last_hdr.first_seq.saturating_sub(1));
        let mut active_file = open_rw(&epoch_path(&epochs_dir, last_epoch_id))?;
        active_file
            .seek(SeekFrom::Start(active_offset))
            .map_err(|err| ProjectionError::io(ProjectionIoOperation::Write, err))?;
        let records_since_checkpoint = tail_records.len() as u64;
        Ok((
            Self {
                root_dir,
                config,
                active_file,
                active_epoch_id: last_epoch_id,
                active_offset,
                active_record_count,
                active_sealed,
                last_seq: cur_seq,
                chain_digest: cur_chain,
                records_since_checkpoint,
            },
            EpochOpenReport {
                loaded_checkpoint_seq: ckpt_seq,
                checkpoint_payload: ckpt_payload,
                tail_records,
                truncated_tail_bytes,
                quarantined_checkpoints,
                epoch_count: epoch_ids.len() as u64,
            },
        ))
    }

    fn init_fresh(
        root_dir: PathBuf,
        epochs_dir: &Path,
        config: EpochJournalConfig,
    ) -> Result<(Self, EpochOpenReport), ProjectionError> {
        let hdr = EpochHeader {
            epoch_id: 0,
            first_seq: 1,
            prev_chain: genesis_chain_digest(),
        };
        let path = create_epoch_file_atomic(epochs_dir, &hdr, config.durability)?;
        let mut active_file = open_rw(&path)?;
        active_file
            .seek(SeekFrom::End(0))
            .map_err(|err| ProjectionError::io(ProjectionIoOperation::Write, err))?;
        Ok((
            Self {
                root_dir,
                config,
                active_file,
                active_epoch_id: 0,
                active_offset: AGENT_EPOCH_HEADER_LEN as u64,
                active_record_count: 0,
                active_sealed: false,
                last_seq: 0,
                chain_digest: hdr.prev_chain,
                records_since_checkpoint: 0,
            },
            EpochOpenReport {
                loaded_checkpoint_seq: None,
                checkpoint_payload: None,
                tail_records: Vec::new(),
                truncated_tail_bytes: 0,
                quarantined_checkpoints: 0,
                epoch_count: 1,
            },
        ))
    }

    /// Appends one record durably into the active epoch, sealing and rotating epochs when needed.
    pub fn append(&mut self, kind: u16, body: &[u8]) -> Result<u64, ProjectionError> {
        let mut seqs = self.append_batch(&[(kind, body)])?;
        seqs.pop()
            .ok_or(ProjectionError::ArithmeticOverflow("append_seq"))
    }

    /// Group-commits a batch of `(kind, body)` records with clean epoch sealing/rollover.
    pub fn append_batch(&mut self, items: &[(u16, &[u8])]) -> Result<Vec<u64>, ProjectionError> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let mut seqs = Vec::with_capacity(items.len());
        let mut pending_buf = Vec::new();
        let mut pending_records = 0_u64;

        for &(kind, body) in items {
            if body.len() > MAX_AGENT_RECORD_BYTES {
                return Err(ProjectionError::InvalidRequest(
                    "agent epoch record exceeds MAX_AGENT_RECORD_BYTES",
                ));
            }
            let frame_len =
                (AGENT_RECORD_HEADER_LEN + body.len() + AGENT_RECORD_TRAILER_LEN) as u64;
            let projected = self
                .active_offset
                .saturating_add(pending_buf.len() as u64)
                .saturating_add(frame_len)
                .saturating_add(AGENT_EPOCH_SEAL_LEN as u64);

            if self.active_sealed
                || (projected > self.config.max_epoch_bytes
                    && (self.active_record_count > 0 || pending_records > 0))
            {
                if !pending_buf.is_empty() {
                    self.flush_pending(&pending_buf, pending_records)?;
                    pending_buf.clear();
                    pending_records = 0;
                }
                self.seal_and_rotate()?;
            }

            let next_seq = self
                .last_seq
                .checked_add(1)
                .ok_or(ProjectionError::ArithmeticOverflow("agent_journal_seq"))?;
            encode_record_frame(kind, next_seq, body, &mut pending_buf)?;
            self.last_seq = next_seq;
            self.chain_digest = advance_chain_digest(
                self.chain_digest,
                self.active_epoch_id,
                next_seq,
                kind,
                body,
            );
            pending_records = pending_records.saturating_add(1);
            seqs.push(next_seq);
        }

        if !pending_buf.is_empty() {
            self.flush_pending(&pending_buf, pending_records)?;
        }
        Ok(seqs)
    }

    /// Returns `true` when `checkpoint_stride` is enabled and reached since the last checkpoint.
    #[must_use]
    pub const fn should_checkpoint(&self) -> bool {
        self.config.checkpoint_stride > 0
            && self.records_since_checkpoint >= self.config.checkpoint_stride
    }

    /// Atomically publishes a SHA-256 verified checkpoint snapshot capturing `payload` at head.
    pub fn write_checkpoint(
        &mut self,
        payload: &[u8],
    ) -> Result<EpochCheckpointReceipt, ProjectionError> {
        let receipt = write_checkpoint_atomic(
            &self.root_dir,
            self.last_seq,
            self.active_epoch_id,
            self.active_offset,
            self.chain_digest,
            payload,
            self.config.durability,
        )?;
        self.records_since_checkpoint = 0;
        Ok(receipt)
    }

    /// Returns the highest committed sequence number (`0` when empty).
    #[must_use]
    pub const fn last_seq(&self) -> u64 {
        self.last_seq
    }

    /// Returns the active epoch identifier.
    #[must_use]
    pub const fn active_epoch_id(&self) -> u64 {
        self.active_epoch_id
    }

    /// Returns the running SHA-256 chain digest through `last_seq`.
    #[must_use]
    pub const fn chain_digest(&self) -> ContentDigest {
        self.chain_digest
    }

    fn flush_pending(&mut self, bytes: &[u8], count: u64) -> Result<(), ProjectionError> {
        self.active_file
            .write_all(bytes)
            .map_err(|err| ProjectionError::io(ProjectionIoOperation::Write, err))?;
        sync_file_mode(&self.active_file, self.config.durability)?;
        self.active_offset = self
            .active_offset
            .checked_add(bytes.len() as u64)
            .ok_or(ProjectionError::ArithmeticOverflow("active_offset"))?;
        self.active_record_count = self.active_record_count.saturating_add(count);
        self.records_since_checkpoint = self.records_since_checkpoint.saturating_add(count);
        Ok(())
    }

    fn seal_and_rotate(&mut self) -> Result<(), ProjectionError> {
        if !self.active_sealed {
            let seal = encode_epoch_seal(EpochSeal {
                epoch_id: self.active_epoch_id,
                record_count: self.active_record_count,
                last_seq: self.last_seq,
                seal_digest: self.chain_digest,
            });
            self.active_file
                .write_all(&seal)
                .map_err(|err| ProjectionError::io(ProjectionIoOperation::Write, err))?;
            sync_file_mode(&self.active_file, self.config.durability)?;
            self.active_offset = self
                .active_offset
                .saturating_add(AGENT_EPOCH_SEAL_LEN as u64);
            self.active_sealed = true;
        }
        let next_id = self
            .active_epoch_id
            .checked_add(1)
            .ok_or(ProjectionError::ArithmeticOverflow("next_epoch_id"))?;
        let next_hdr = EpochHeader {
            epoch_id: next_id,
            first_seq: self.last_seq.saturating_add(1),
            prev_chain: self.chain_digest,
        };
        let path = create_epoch_file_atomic(
            &self.root_dir.join("epochs"),
            &next_hdr,
            self.config.durability,
        )?;
        let mut file = open_rw(&path)?;
        file.seek(SeekFrom::End(0))
            .map_err(|err| ProjectionError::io(ProjectionIoOperation::Write, err))?;
        self.active_file = file;
        self.active_epoch_id = next_id;
        self.active_offset = AGENT_EPOCH_HEADER_LEN as u64;
        self.active_record_count = 0;
        self.active_sealed = false;
        Ok(())
    }
}

fn corrupt_epoch(detail: String) -> ProjectionError {
    ProjectionError::CorruptDerivedStore {
        artifact: "agent_epoch_journal",
        detail,
    }
}

/// Returns the canonical path `<dir>/epochs/{epoch_id:016}.fssa`.
#[must_use]
pub fn epoch_path(epochs_dir: &Path, epoch_id: u64) -> PathBuf {
    epochs_dir.join(format!("{epoch_id:016}.fssa"))
}

/// Returns the canonical path `<dir>/checkpoints/seq-{seq:020}.fsac`.
#[must_use]
pub fn checkpoint_path(checkpoints_dir: &Path, seq: u64) -> PathBuf {
    checkpoints_dir.join(format!("seq-{seq:020}.fsac"))
}
