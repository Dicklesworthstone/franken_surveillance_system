#![forbid(unsafe_code)]
//! Verified checkpoint persistence, loading, and forensic quarantine helpers for
//! [`super::epoch_journal::SegmentedEpochJournal`].

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, sha256};
use fss_ledger::IncompleteTailPolicy;
use fss_pack::DurabilityMode;

use super::epoch_journal::{
    AGENT_EPOCH_CHECKPOINT_DOMAIN, AGENT_EPOCH_CHECKPOINT_MAGIC, AGENT_EPOCH_FORMAT_VERSION,
    AGENT_EPOCH_HEADER_LEN, EpochCheckpointReceipt, MAX_AGENT_CHECKPOINT_BYTES, checkpoint_path,
    epoch_path,
};
use crate::error::{ProjectionError, ProjectionIoOperation};
use crate::wal::{sync_directory, sync_file_mode};

pub(super) struct ParsedCheckpoint {
    pub(super) last_seq: u64,
    pub(super) epoch_id: u64,
    pub(super) epoch_byte_offset: u64,
    pub(super) chain_digest: ContentDigest,
    pub(super) payload: Vec<u8>,
}

pub(super) fn write_checkpoint_atomic(
    root_dir: &Path,
    last_seq: u64,
    epoch_id: u64,
    epoch_byte_offset: u64,
    chain_digest: ContentDigest,
    payload: &[u8],
    durability: DurabilityMode,
) -> Result<EpochCheckpointReceipt, ProjectionError> {
    let checkpoints_dir = root_dir.join("checkpoints");
    fs::create_dir_all(&checkpoints_dir)
        .map_err(|err| ProjectionError::io(ProjectionIoOperation::CreateDir, err))?;
    let final_path = checkpoint_path(&checkpoints_dir, last_seq);
    let tmp_path = checkpoints_dir.join(format!(".seq-{last_seq:020}.fsac.tmp"));

    let mut enc = CanonicalEncoder::new();
    enc.text(AGENT_EPOCH_CHECKPOINT_DOMAIN);
    enc.u64(last_seq);
    enc.u64(epoch_id);
    enc.u64(epoch_byte_offset);
    enc.digest(chain_digest);
    enc.bytes(payload);
    let body = enc.finish_checked()?;

    let mut raw = Vec::with_capacity(6 + body.len() + 32);
    raw.extend_from_slice(&AGENT_EPOCH_CHECKPOINT_MAGIC);
    raw.extend_from_slice(&AGENT_EPOCH_FORMAT_VERSION.to_be_bytes());
    raw.extend_from_slice(&body);
    raw.extend_from_slice(&sha256(&raw));

    {
        let mut tmp = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|err| ProjectionError::io(ProjectionIoOperation::Open, err))?;
        tmp.write_all(&raw)
            .map_err(|err| ProjectionError::io(ProjectionIoOperation::Write, err))?;
        sync_file_mode(&tmp, durability)?;
    }
    fs::rename(&tmp_path, &final_path)
        .map_err(|err| ProjectionError::io(ProjectionIoOperation::Rename, err))?;
    sync_directory(&checkpoints_dir)?;

    Ok(EpochCheckpointReceipt {
        path: final_path,
        last_seq,
        epoch_id,
        epoch_byte_offset,
        chain_digest,
        file_bytes: raw.len(),
    })
}

pub(super) fn load_latest_valid_checkpoint(
    root_dir: &Path,
    checkpoints_dir: &Path,
    epochs_dir: &Path,
    last_epoch_id: u64,
    policy: IncompleteTailPolicy,
    quarantined: &mut u64,
) -> Result<Option<ParsedCheckpoint>, ProjectionError> {
    let mut files: Vec<(u64, PathBuf)> = Vec::new();
    for entry in fs::read_dir(checkpoints_dir)
        .map_err(|err| ProjectionError::io(ProjectionIoOperation::ReadDir, err))?
    {
        let entry =
            entry.map_err(|err| ProjectionError::io(ProjectionIoOperation::ReadDir, err))?;
        let name = entry.file_name();
        if let Some(s) = name.to_str()
            && let Some(mid) = s.strip_prefix("seq-").and_then(|r| r.strip_suffix(".fsac"))
            && mid.len() == 20
            && mid.bytes().all(|b| b.is_ascii_digit())
            && let Ok(seq) = mid.parse::<u64>()
        {
            files.push((seq, entry.path()));
        }
    }
    files.sort_by_key(|a| std::cmp::Reverse(a.0));

    for (expected_seq, path) in files {
        match parse_checkpoint_file(&path, expected_seq, epochs_dir, last_epoch_id) {
            Ok(ckpt) => return Ok(Some(ckpt)),
            Err(err) => {
                if policy == IncompleteTailPolicy::Reject {
                    return Err(err);
                }
                quarantine_file(root_dir, &path)?;
                *quarantined = quarantined.saturating_add(1);
            }
        }
    }
    Ok(None)
}

fn parse_checkpoint_file(
    path: &Path,
    expected_seq: u64,
    epochs_dir: &Path,
    last_epoch_id: u64,
) -> Result<ParsedCheckpoint, ProjectionError> {
    let meta = fs::metadata(path)
        .map_err(|err| ProjectionError::io(ProjectionIoOperation::Metadata, err))?;
    if meta.len() > MAX_AGENT_CHECKPOINT_BYTES || meta.len() < 38 {
        return Err(corrupt_ckpt("checkpoint length out of bounds"));
    }
    let raw =
        fs::read(path).map_err(|err| ProjectionError::io(ProjectionIoOperation::Read, err))?;
    if raw[0..4] != AGENT_EPOCH_CHECKPOINT_MAGIC
        || u16::from_be_bytes([raw[4], raw[5]]) != AGENT_EPOCH_FORMAT_VERSION
    {
        return Err(corrupt_ckpt("invalid checkpoint magic or version"));
    }
    let body_end = raw.len() - 32;
    if raw[body_end..] != sha256(&raw[..body_end]) {
        return Err(corrupt_ckpt("checkpoint SHA-256 mismatch"));
    }
    let mut dec = CanonicalDecoder::new(&raw[6..body_end]);
    if dec.text().map_err(|_| corrupt_ckpt("domain"))? != AGENT_EPOCH_CHECKPOINT_DOMAIN {
        return Err(corrupt_ckpt("domain mismatch"));
    }
    let last_seq = dec.u64().map_err(|_| corrupt_ckpt("last_seq"))?;
    let epoch_id = dec.u64().map_err(|_| corrupt_ckpt("epoch_id"))?;
    let epoch_byte_offset = dec.u64().map_err(|_| corrupt_ckpt("epoch_byte_offset"))?;
    let chain_digest = dec.digest().map_err(|_| corrupt_ckpt("chain_digest"))?;
    let payload = dec.bytes().map_err(|_| corrupt_ckpt("payload"))?.to_vec();
    dec.ensure_finished()
        .map_err(|_| corrupt_ckpt("trailing"))?;

    if last_seq != expected_seq || epoch_id > last_epoch_id {
        return Err(corrupt_ckpt("sequence or epoch anchor mismatch"));
    }
    let ep_len = fs::metadata(epoch_path(epochs_dir, epoch_id))
        .map_err(|_| corrupt_ckpt("referenced epoch missing"))?
        .len();
    if epoch_byte_offset < AGENT_EPOCH_HEADER_LEN as u64 || epoch_byte_offset > ep_len {
        return Err(corrupt_ckpt("epoch offset outside file bounds"));
    }
    Ok(ParsedCheckpoint {
        last_seq,
        epoch_id,
        epoch_byte_offset,
        chain_digest,
        payload,
    })
}

fn corrupt_ckpt(detail: &str) -> ProjectionError {
    ProjectionError::CorruptDerivedStore {
        artifact: "agent_epoch_checkpoint",
        detail: detail.to_owned(),
    }
}

pub(super) fn quarantine_file(root_dir: &Path, bad_path: &Path) -> Result<(), ProjectionError> {
    let qdir = root_dir.join("quarantine");
    fs::create_dir_all(&qdir)
        .map_err(|err| ProjectionError::io(ProjectionIoOperation::CreateDir, err))?;
    let name = bad_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");
    for attempt in 1_u32..=10_000 {
        let dst = qdir.join(format!("{name}.quarantine-{attempt:04}"));
        if !dst.exists() {
            fs::rename(bad_path, &dst)
                .map_err(|err| ProjectionError::io(ProjectionIoOperation::Rename, err))?;
            sync_directory(&qdir)?;
            return Ok(());
        }
    }
    Err(ProjectionError::InvalidRequest(
        "quarantine slots exhausted",
    ))
}

pub(super) fn quarantine_tail_slice(
    root_dir: &Path,
    path: &Path,
    epoch_id: u64,
    torn_at: u64,
) -> Result<(), ProjectionError> {
    let mut f =
        File::open(path).map_err(|err| ProjectionError::io(ProjectionIoOperation::Open, err))?;
    f.seek(SeekFrom::Start(torn_at))
        .map_err(|err| ProjectionError::io(ProjectionIoOperation::Read, err))?;
    let mut torn = Vec::new();
    f.read_to_end(&mut torn)
        .map_err(|err| ProjectionError::io(ProjectionIoOperation::Read, err))?;
    let qdir = root_dir.join("quarantine");
    fs::create_dir_all(&qdir)
        .map_err(|err| ProjectionError::io(ProjectionIoOperation::CreateDir, err))?;
    let dst = qdir.join(format!("{epoch_id:016}.tail-at-{torn_at}.bin"));
    fs::write(&dst, &torn).map_err(|err| ProjectionError::io(ProjectionIoOperation::Write, err))?;
    sync_directory(&qdir)?;
    Ok(())
}
