#![forbid(unsafe_code)]
//! Immutable, self-verifying v2 ledger checkpoint snapshots (`<dir>/checkpoints/seq-{seq:020}.fssc`).
//!
//! Checkpoints are published atomically via temporary file write -> `sync_all()` -> atomic rename
//! -> parent directory sync. Each file carries magic `b"FSSC"`, format version `2`, domain
//! `"fss.ledger.checkpoint.v2"`, canonical anchor/epoch metadata, the compact structural
//! [`RadixMerkleTrie`] snapshot, the committed batch-ID index, and a trailing whole-file SHA-256
//! integrity digest.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use fss_core::{
    BatchId, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    LedgerAnchor, sha256,
};

use crate::merkle::RadixMerkleTrie;

use super::{
    CHECKPOINT_DOMAIN, CheckpointCorruptionKind, CheckpointSummary, EpochLedgerError,
    sync_directory,
};

/// Magic bytes identifying a v2 FSS ledger checkpoint snapshot.
pub const CHECKPOINT_MAGIC: [u8; 4] = *b"FSSC";
/// Format version for v2 FSS ledger checkpoint snapshots.
pub const CHECKPOINT_FORMAT_VERSION: u16 = 2;

const CHECKPOINT_PREFIX_LEN: usize = 4 + 2;
const CHECKPOINT_TRAILER_SHA256_LEN: usize = 32;
const MIN_CHECKPOINT_LEN: usize = CHECKPOINT_PREFIX_LEN + CHECKPOINT_TRAILER_SHA256_LEN;

/// Complete verified state materialized inside one checkpoint snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointData {
    /// Commit sequence captured by this checkpoint.
    pub commit_sequence: u64,
    /// Canonical v2 history root through `commit_sequence`.
    pub history_root: ContentDigest,
    /// Canonical v2 Radix-Merkle state root at `commit_sequence`.
    pub merkle_state_root: ContentDigest,
    /// Latest committed [`LedgerAnchor`] at `commit_sequence`.
    pub latest_anchor: LedgerAnchor,
    /// Epoch segment identifier containing `commit_sequence` (or `0` at genesis).
    pub epoch_id: u64,
    /// Exact byte offset inside `epoch_id` immediately following `commit_sequence`.
    pub epoch_byte_offset: u64,
    /// Number of distinct live (including tombstoned) objects at `commit_sequence`.
    pub live_object_count: u64,
    /// Reconstructed [`RadixMerkleTrie`] matching `merkle_state_root`.
    pub trie: RadixMerkleTrie,
    /// Committed batch identities through `commit_sequence` for duplicate/conflict enforcement.
    pub batch_index: BTreeMap<BatchId, (u64, ContentDigest)>,
}

/// Returns the canonical path `<checkpoints_dir>/seq-{commit_sequence:020}.fssc`.
#[must_use]
pub fn checkpoint_file_path(checkpoints_dir: &Path, commit_sequence: u64) -> PathBuf {
    checkpoints_dir.join(format!("seq-{commit_sequence:020}.fssc"))
}

/// Lists all candidate checkpoint files in `checkpoints_dir`, sorted by `commit_sequence` descending.
pub(crate) fn list_checkpoint_files_desc(
    checkpoints_dir: &Path,
) -> Result<Vec<(u64, PathBuf)>, EpochLedgerError> {
    if !checkpoints_dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(checkpoints_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if name_str.starts_with('.') {
            continue;
        }
        if let Some(middle) = name_str
            .strip_prefix("seq-")
            .and_then(|rest| rest.strip_suffix(".fssc"))
            && middle.len() == 20
            && middle.bytes().all(|b| b.is_ascii_digit())
            && let Ok(seq) = middle.parse::<u64>()
        {
            entries.push((seq, entry.path()));
        }
    }
    entries.sort_by_key(|a| std::cmp::Reverse(a.0));
    Ok(entries)
}

/// Atomically writes, fsyncs, and publishes one immutable verified checkpoint snapshot.
pub(crate) fn write_checkpoint_atomic(
    checkpoints_dir: &Path,
    checkpoint: &CheckpointData,
) -> Result<CheckpointSummary, EpochLedgerError> {
    fs::create_dir_all(checkpoints_dir)?;
    let final_path = checkpoint_file_path(checkpoints_dir, checkpoint.commit_sequence);
    let tmp_path =
        checkpoints_dir.join(format!(".seq-{:020}.fssc.tmp", checkpoint.commit_sequence));

    let bytes = encode_checkpoint(checkpoint)?;
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp_path, &final_path)?;
    sync_directory(checkpoints_dir)?;

    Ok(CheckpointSummary {
        path: final_path,
        commit_sequence: checkpoint.commit_sequence,
        history_root: checkpoint.history_root,
        merkle_state_root: checkpoint.merkle_state_root,
        epoch_id: checkpoint.epoch_id,
        epoch_byte_offset: checkpoint.epoch_byte_offset,
        live_object_count: checkpoint.live_object_count,
        file_bytes: bytes.len() as u64,
    })
}

/// Encodes one [`CheckpointData`] into its exact binary representation including trailing SHA-256.
pub(crate) fn encode_checkpoint(checkpoint: &CheckpointData) -> Result<Vec<u8>, EpochLedgerError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(CHECKPOINT_DOMAIN);
    encoder.u64(checkpoint.commit_sequence);
    encoder.digest(checkpoint.history_root);
    encoder.digest(checkpoint.merkle_state_root);
    checkpoint.latest_anchor.encode_canonical(&mut encoder);
    encoder.u64(checkpoint.epoch_id);
    encoder.u64(checkpoint.epoch_byte_offset);
    encoder.u64(checkpoint.live_object_count);
    checkpoint.trie.encode_snapshot(&mut encoder);

    encoder.u64(checkpoint.batch_index.len() as u64);
    for (batch_id, &(seq, digest)) in &checkpoint.batch_index {
        batch_id.encode_canonical(&mut encoder);
        encoder.u64(seq);
        encoder.digest(digest);
    }

    let body = encoder.finish_checked()?;
    let mut out =
        Vec::with_capacity(CHECKPOINT_PREFIX_LEN + body.len() + CHECKPOINT_TRAILER_SHA256_LEN);
    out.extend_from_slice(&CHECKPOINT_MAGIC);
    out.extend_from_slice(&CHECKPOINT_FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&body);
    let whole_file_digest = sha256(&out);
    out.extend_from_slice(&whole_file_digest);
    Ok(out)
}

/// Reads and verifies one checkpoint snapshot file against its integrity digest, invariants,
/// and expected site lineage.
pub fn read_and_verify_checkpoint(
    path: &Path,
    expected_filename_seq: Option<u64>,
    expected_site_lineage: &str,
    verify_trie_digests: bool,
) -> Result<(CheckpointData, u64), CheckpointCorruptionKind> {
    let bytes = fs::read(path).map_err(|_| CheckpointCorruptionKind::TooShort)?;
    let file_bytes = bytes.len() as u64;
    if bytes.len() < MIN_CHECKPOINT_LEN {
        return Err(CheckpointCorruptionKind::TooShort);
    }
    if bytes[0..4] != CHECKPOINT_MAGIC {
        return Err(CheckpointCorruptionKind::InvalidMagic);
    }
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if version != CHECKPOINT_FORMAT_VERSION {
        return Err(CheckpointCorruptionKind::UnsupportedVersion);
    }

    let body_end = bytes.len() - CHECKPOINT_TRAILER_SHA256_LEN;
    let computed_sha = sha256(&bytes[..body_end]);
    if bytes[body_end..] != computed_sha {
        return Err(CheckpointCorruptionKind::IntegrityDigestMismatch);
    }

    let mut decoder = CanonicalDecoder::new(&bytes[CHECKPOINT_PREFIX_LEN..body_end]);
    let domain = decoder
        .text()
        .map_err(|_| CheckpointCorruptionKind::CanonicalDecode)?;
    if domain != CHECKPOINT_DOMAIN {
        return Err(CheckpointCorruptionKind::InvalidDomain);
    }

    let commit_sequence = decoder
        .u64()
        .map_err(|_| CheckpointCorruptionKind::CanonicalDecode)?;
    if let Some(filename_seq) = expected_filename_seq
        && filename_seq != commit_sequence
    {
        return Err(CheckpointCorruptionKind::FilenameSequenceMismatch);
    }

    let history_root = decoder
        .digest()
        .map_err(|_| CheckpointCorruptionKind::CanonicalDecode)?;
    let merkle_state_root = decoder
        .digest()
        .map_err(|_| CheckpointCorruptionKind::CanonicalDecode)?;
    let latest_anchor = LedgerAnchor::decode_canonical(&mut decoder)
        .map_err(|_| CheckpointCorruptionKind::CanonicalDecode)?;
    let epoch_id = decoder
        .u64()
        .map_err(|_| CheckpointCorruptionKind::CanonicalDecode)?;
    let epoch_byte_offset = decoder
        .u64()
        .map_err(|_| CheckpointCorruptionKind::CanonicalDecode)?;
    let live_object_count = decoder
        .u64()
        .map_err(|_| CheckpointCorruptionKind::CanonicalDecode)?;

    if latest_anchor.site_lineage != expected_site_lineage {
        return Err(CheckpointCorruptionKind::SiteLineageMismatch);
    }
    if latest_anchor.commit_sequence != commit_sequence
        || latest_anchor.state_root != merkle_state_root
    {
        return Err(CheckpointCorruptionKind::AnchorInconsistency);
    }

    let trie =
        RadixMerkleTrie::decode_snapshot(&mut decoder, merkle_state_root, verify_trie_digests)
            .map_err(|_| CheckpointCorruptionKind::TrieSnapshotInvalid)?;
    if trie.len() != live_object_count {
        return Err(CheckpointCorruptionKind::AnchorInconsistency);
    }

    let batch_count = usize::try_from(
        decoder
            .u64()
            .map_err(|_| CheckpointCorruptionKind::CanonicalDecode)?,
    )
    .map_err(|_| CheckpointCorruptionKind::CanonicalDecode)?;
    let mut batch_index = BTreeMap::new();
    let mut prev_batch_id: Option<BatchId> = None;
    for _ in 0..batch_count {
        let batch_id = BatchId::decode_canonical(&mut decoder)
            .map_err(|_| CheckpointCorruptionKind::CanonicalDecode)?;
        if prev_batch_id.as_ref().is_some_and(|prev| prev >= &batch_id) {
            return Err(CheckpointCorruptionKind::CanonicalDecode);
        }
        let seq = decoder
            .u64()
            .map_err(|_| CheckpointCorruptionKind::CanonicalDecode)?;
        if seq == 0 || seq > commit_sequence {
            return Err(CheckpointCorruptionKind::AnchorInconsistency);
        }
        let digest = decoder
            .digest()
            .map_err(|_| CheckpointCorruptionKind::CanonicalDecode)?;
        prev_batch_id = Some(batch_id.clone());
        batch_index.insert(batch_id, (seq, digest));
    }

    decoder
        .ensure_finished()
        .map_err(|_| CheckpointCorruptionKind::CanonicalDecode)?;

    Ok((
        CheckpointData {
            commit_sequence,
            history_root,
            merkle_state_root,
            latest_anchor,
            epoch_id,
            epoch_byte_offset,
            live_object_count,
            trie,
            batch_index,
        },
        file_bytes,
    ))
}

/// Quarantines a corrupt or inconsistent checkpoint file into `<checkpoints_dir>/quarantine/`.
pub(crate) fn quarantine_corrupt_checkpoint(
    checkpoints_dir: &Path,
    bad_path: &Path,
) -> Result<PathBuf, EpochLedgerError> {
    let quarantine_dir = checkpoints_dir.join("quarantine");
    fs::create_dir_all(&quarantine_dir)?;
    let base_name = bad_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown.fssc");
    let mut target = quarantine_dir.join(format!("{base_name}.corrupt"));
    let mut attempt = 1_u32;
    while target.exists() {
        target = quarantine_dir.join(format!("{base_name}.corrupt.{attempt}"));
        attempt = attempt.saturating_add(1);
    }
    fs::rename(bad_path, &target)?;
    sync_directory(&quarantine_dir)?;
    sync_directory(checkpoints_dir)?;
    Ok(target)
}
