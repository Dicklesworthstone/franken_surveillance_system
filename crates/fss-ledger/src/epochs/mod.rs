#![forbid(unsafe_code)]
//! Segmented epoch journals and verified checkpoint snapshots for the v2 Merkle ledger.
//!
//! Replaces the single-file bounded v1 journal (`MAX_ORACLE_BATCHES = 65_536`) with bounded
//! immutable epoch segment files (`<dir>/epochs/{epoch_id:016}.fssj`) and atomic self-verifying
//! checkpoint snapshots (`<dir>/checkpoints/seq-{commit_seq:020}.fssc`), supporting `u64` commit
//! sequences and `O(1)` checkpoint cold-open with bounded post-checkpoint tail replay.

pub mod archive;
mod checkpoint;
mod error;
mod ledger;
mod segment;
mod validate;
mod verify;
mod writer;

#[cfg(test)]
mod tests;

use std::io;
use std::path::PathBuf;

use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, LedgerAnchor};

pub use archive::{
    ArchivedEpochEntry, EPOCH_ARCHIVAL_RECEIPT_DOMAIN, EPOCH_ARCHIVAL_RECEIPT_MAGIC,
    EPOCH_ARCHIVAL_RECEIPT_VERSION, EpochArchivalError, EpochArchivalPolicy, EpochArchivalReceipt,
    archive_sealed_epochs,
};

pub use checkpoint::{
    CHECKPOINT_FORMAT_VERSION, CHECKPOINT_MAGIC, CheckpointData, checkpoint_file_path,
    read_and_verify_checkpoint,
};
pub use error::{CheckpointCorruptionKind, EpochCorruptionKind, EpochLedgerError};
pub use ledger::{EpochAppendReconciliation, MerkleEpochLedger};
pub use segment::{
    EPOCH_FILE_MAGIC, EPOCH_FORMAT_VERSION, EPOCH_HEADER_LEN, EPOCH_RECORD_HEADER_LEN,
    EPOCH_RECORD_MAGIC, EPOCH_RECORD_TRAILER_LEN, EPOCH_TRAILER_MAGIC, EpochHeader, EpochRecord,
    EpochScanReport, epoch_file_path,
};
pub use verify::{EpochLedgerInspection, inspect_epochs_readonly};

/// Registered canonical digest domain for v2 verified ledger checkpoint snapshots.
pub const CHECKPOINT_DOMAIN: &str = "fss.ledger.checkpoint.v2";
/// Registered canonical digest domain for v2 epoch file headers.
pub const EPOCH_HEADER_DOMAIN: &str = "fss.ledger.epoch_header.v2";
/// Registered canonical digest domain for v2 Merkle epoch history-chain roots.
pub const EPOCH_HISTORY_DOMAIN: &str = "fss.ledger.epoch_history.v2";

/// Root canonical-encoder domain shared across FSS history digests.
const CANONICAL_DOMAIN: &str = "fss.canonical.v1";

/// Default maximum byte length of one epoch segment file (64 MiB).
pub const DEFAULT_MAX_EPOCH_BYTES: u64 = 64 * 1024 * 1024;
/// Default maximum committed batches per epoch segment file.
pub const DEFAULT_MAX_BATCHES_PER_EPOCH: u64 = 10_000;
/// Default commit stride between periodic verified checkpoint snapshots.
pub const DEFAULT_CHECKPOINT_STRIDE: u64 = 1_024;
/// Minimum admitted `max_epoch_bytes` configuration (must fit header plus at least one record).
pub const MIN_MAX_EPOCH_BYTES: u64 = 256;

/// Configuration bounds for a [`MerkleEpochLedger`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochLedgerConfig {
    /// Maximum target byte size for one epoch file before rolling over to the next epoch.
    pub max_epoch_bytes: u64,
    /// Maximum committed batches stored in one epoch file before rolling over.
    pub max_batches_per_epoch: u64,
    /// Emit a verified checkpoint every `checkpoint_stride` commits (`0` disables stride
    /// checkpoints while preserving checkpoints emitted on epoch rollover).
    pub checkpoint_stride: u64,
    /// Optional ceiling on distinct live (including tombstoned) objects (`None` = `u64` unbounded).
    pub max_objects: Option<u64>,
}

impl Default for EpochLedgerConfig {
    fn default() -> Self {
        Self {
            max_epoch_bytes: DEFAULT_MAX_EPOCH_BYTES,
            max_batches_per_epoch: DEFAULT_MAX_BATCHES_PER_EPOCH,
            checkpoint_stride: DEFAULT_CHECKPOINT_STRIDE,
            max_objects: None,
        }
    }
}

impl EpochLedgerConfig {
    /// Validates configuration invariants, failing closed on zero or sub-minimum bounds.
    pub fn validate(&self) -> Result<(), EpochLedgerError> {
        if self.max_epoch_bytes < MIN_MAX_EPOCH_BYTES {
            return Err(EpochLedgerError::InvalidConfig(
                "max_epoch_bytes below minimum",
            ));
        }
        if self.max_batches_per_epoch == 0 {
            return Err(EpochLedgerError::InvalidConfig(
                "max_batches_per_epoch must be >= 1",
            ));
        }
        if self.max_objects == Some(0) {
            return Err(EpochLedgerError::InvalidConfig(
                "max_objects must be >= 1 when set",
            ));
        }
        Ok(())
    }
}

/// Summary of one emitted or loaded verified checkpoint snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointSummary {
    /// Path to the immutable checkpoint file.
    pub path: PathBuf,
    /// Commit sequence captured by this checkpoint.
    pub commit_sequence: u64,
    /// History root at this checkpoint.
    pub history_root: ContentDigest,
    /// Merkle state root at this checkpoint.
    pub merkle_state_root: ContentDigest,
    /// Epoch ID referenced by this checkpoint.
    pub epoch_id: u64,
    /// Byte offset inside `epoch_id` immediately following `commit_sequence`.
    pub epoch_byte_offset: u64,
    /// Distinct live (including tombstoned) objects at this checkpoint.
    pub live_object_count: u64,
    /// On-disk size of the checkpoint file in bytes.
    pub file_bytes: u64,
}

/// Diagnostics reported after opening a [`MerkleEpochLedger`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenRecoverySummary {
    /// Checkpoint loaded to initialize state, or `None` when opened from genesis.
    pub loaded_checkpoint: Option<CheckpointSummary>,
    /// Newer corrupt/partial/inconsistent checkpoints quarantined during fallback.
    pub quarantined_checkpoints: Vec<(PathBuf, CheckpointCorruptionKind)>,
    /// Number of epoch batches replayed after the loaded checkpoint (or genesis).
    pub replayed_tail_batches: u64,
    /// Quarantined incomplete tail file path, if `IncompleteTailPolicy::Truncate` truncated a tail.
    pub truncated_tail_quarantine: Option<PathBuf>,
}

/// Result of full-chain cryptographic verification from genesis through head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochVerificationReport {
    /// Total contiguous epoch segment files verified from epoch 0.
    pub epochs_verified: u64,
    /// Total committed batches decoded and semantically verified from genesis.
    pub batches_verified: u64,
    /// Total distinct live (including tombstoned) objects at head.
    pub live_objects: u64,
    /// Verified head commit sequence.
    pub head_commit_sequence: u64,
    /// Verified head history root.
    pub history_root: ContentDigest,
    /// Verified head v2 Merkle state root.
    pub state_root: ContentDigest,
}

/// Computes the canonical v2 genesis history root for `genesis`.
pub fn genesis_history_root_v2(genesis: &LedgerAnchor) -> Result<ContentDigest, EpochLedgerError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(CANONICAL_DOMAIN);
    encoder.text(EPOCH_HISTORY_DOMAIN);
    encoder.tag(0);
    genesis.encode_canonical(&mut encoder);
    let bytes = encoder.finish_checked()?;
    Ok(ContentDigest::sha256(&bytes))
}

/// Computes the canonical v2 successor history root after committing `batch_digest` at `sequence`.
pub fn successor_history_root_v2(
    previous: ContentDigest,
    sequence: u64,
    batch_digest: ContentDigest,
    new_anchor: &LedgerAnchor,
) -> Result<ContentDigest, EpochLedgerError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(CANONICAL_DOMAIN);
    encoder.text(EPOCH_HISTORY_DOMAIN);
    encoder.tag(1);
    encoder.digest(previous);
    encoder.u64(sequence);
    encoder.digest(batch_digest);
    new_anchor.encode_canonical(&mut encoder);
    let bytes = encoder.finish_checked()?;
    Ok(ContentDigest::sha256(&bytes))
}

/// Computes standard IEEE 802.3 CRC-32 (`0xEDB8_8320`) in pure safe Rust.
#[must_use]
pub fn crc32_ieee(bytes: &[u8]) -> u32 {
    const TABLE: [u32; 256] = build_crc32_table();
    let mut crc = 0xFFFF_FFFF_u32;
    for &byte in bytes {
        let index = ((crc ^ u32::from(byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ TABLE[index];
    }
    !crc
}

const fn build_crc32_table() -> [u32; 256] {
    let mut table = [0_u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// Synchronizes a directory entry table on Unix platforms (best-effort no-op on non-Unix).
pub(crate) fn sync_directory(dir: &std::path::Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let handle = std::fs::File::open(dir)?;
        handle.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}
