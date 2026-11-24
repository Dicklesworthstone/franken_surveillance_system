#![forbid(unsafe_code)]
//! Binary framing, epoch header/seal codecs, and tail scanning for
//! [`super::epoch_journal::SegmentedEpochJournal`].

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, DigestAlgorithm, Sha256Hasher, sha256};
use fss_ledger::IncompleteTailPolicy;
use fss_pack::{DurabilityMode, crc32c};

use super::epoch_checkpoint::quarantine_file;
use super::epoch_journal::{EpochJournalRecord, epoch_path};
use crate::error::{ProjectionError, ProjectionIoOperation};
use crate::wal::{sync_directory, sync_file_mode};

/// Canonical digest domain for segmented agent-index epoch genesis and header binding.
pub const AGENT_EPOCH_HEADER_DOMAIN: &str = "fss.agent_index.epoch_header.v1";
/// Canonical digest domain for chained SHA-256 sealed epoch trailers.
pub const AGENT_EPOCH_SEAL_DOMAIN: &str = "fss.agent_index.epoch_seal.v1";
/// Canonical digest domain embedded inside verified agent-index checkpoint snapshots.
pub const AGENT_EPOCH_CHECKPOINT_DOMAIN: &str = "fss.agent_index.checkpoint.v1";

/// Magic bytes prefixing every segmented agent epoch file (`FSSA`).
pub const AGENT_EPOCH_FILE_MAGIC: [u8; 4] = *b"FSSA";
/// Magic bytes prefixing every framed record inside an agent epoch file (`FSAR`).
pub const AGENT_EPOCH_RECORD_MAGIC: [u8; 4] = *b"FSAR";
/// Magic bytes prefixing the SHA-256 sealed trailer of a closed epoch file (`FSAS`).
pub const AGENT_EPOCH_SEAL_MAGIC: [u8; 4] = *b"FSAS";
/// Magic bytes prefixing every verified checkpoint snapshot file (`FSAC`).
pub const AGENT_EPOCH_CHECKPOINT_MAGIC: [u8; 4] = *b"FSAC";
/// Binary format version for epoch files, record frames, and checkpoints.
pub const AGENT_EPOCH_FORMAT_VERSION: u16 = 1;

/// Fixed epoch header length (`4 + 2 + 8 + 8 + 32 + 4 = 58` bytes).
pub const AGENT_EPOCH_HEADER_LEN: usize = 58;
/// Fixed record frame header length (`4 + 2 + 2 + 8 + 4 = 20` bytes).
pub const AGENT_RECORD_HEADER_LEN: usize = 20;
/// Fixed record CRC32C trailer length (`4` bytes).
pub const AGENT_RECORD_TRAILER_LEN: usize = 4;
/// Fixed sealed epoch trailer length (`4 + 8 + 8 + 8 + 32 + 4 = 64` bytes).
pub const AGENT_EPOCH_SEAL_LEN: usize = 64;
/// Default maximum byte size per epoch segment file (64 MiB).
pub const DEFAULT_MAX_AGENT_EPOCH_BYTES: u64 = 64 * 1024 * 1024;
/// Minimum configurable epoch segment byte limit (for deterministic rollover tests).
pub const MIN_AGENT_EPOCH_BYTES: u64 = 256;
/// Default record stride between periodic verified checkpoint snapshots.
pub const DEFAULT_AGENT_CHECKPOINT_STRIDE: u64 = 1_024;
/// Maximum payload bytes admitted for a single framed record (4 MiB).
pub const MAX_AGENT_RECORD_BYTES: usize = 4 * 1024 * 1024;
/// Maximum checkpoint snapshot size admitted on read (256 MiB).
pub const MAX_AGENT_CHECKPOINT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub(super) struct EpochHeader {
    pub(super) epoch_id: u64,
    pub(super) first_seq: u64,
    pub(super) prev_chain: ContentDigest,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct EpochSeal {
    pub(super) epoch_id: u64,
    pub(super) record_count: u64,
    pub(super) last_seq: u64,
    pub(super) seal_digest: ContentDigest,
}

pub(super) struct ScanOutcome {
    pub(super) records: Vec<EpochJournalRecord>,
    pub(super) committed_len: u64,
    pub(super) last_seq: u64,
    pub(super) chain_digest: ContentDigest,
    pub(super) sealed: Option<EpochSeal>,
    pub(super) torn_tail_offset: Option<u64>,
}

pub(super) fn genesis_chain_digest() -> ContentDigest {
    let mut h = Sha256Hasher::new();
    h.update(AGENT_EPOCH_HEADER_DOMAIN.as_bytes());
    h.update(b":genesis");
    ContentDigest::new(DigestAlgorithm::Sha256, h.finalize().unwrap_or_default())
}

pub(super) fn advance_chain_digest(
    prev: ContentDigest,
    epoch_id: u64,
    seq: u64,
    kind: u16,
    body: &[u8],
) -> ContentDigest {
    let mut h = Sha256Hasher::new();
    h.update(AGENT_EPOCH_SEAL_DOMAIN.as_bytes());
    h.update(&prev.bytes());
    h.update(&epoch_id.to_be_bytes());
    h.update(&seq.to_be_bytes());
    h.update(&kind.to_be_bytes());
    h.update(&sha256(body));
    ContentDigest::new(DigestAlgorithm::Sha256, h.finalize().unwrap_or_default())
}

pub(super) fn encode_epoch_header(hdr: &EpochHeader) -> [u8; AGENT_EPOCH_HEADER_LEN] {
    let mut out = [0_u8; AGENT_EPOCH_HEADER_LEN];
    out[0..4].copy_from_slice(&AGENT_EPOCH_FILE_MAGIC);
    out[4..6].copy_from_slice(&AGENT_EPOCH_FORMAT_VERSION.to_be_bytes());
    out[6..14].copy_from_slice(&hdr.epoch_id.to_be_bytes());
    out[14..22].copy_from_slice(&hdr.first_seq.to_be_bytes());
    out[22..54].copy_from_slice(&hdr.prev_chain.bytes());
    let crc = crc32c(&out[0..54]);
    out[54..58].copy_from_slice(&crc.to_be_bytes());
    out
}

pub(super) fn read_epoch_header(
    path: &Path,
    expected_epoch: u64,
) -> Result<EpochHeader, ProjectionError> {
    let mut f =
        File::open(path).map_err(|err| ProjectionError::io(ProjectionIoOperation::Open, err))?;
    let mut buf = [0_u8; AGENT_EPOCH_HEADER_LEN];
    f.read_exact(&mut buf)
        .map_err(|_| ProjectionError::CorruptDerivedStore {
            artifact: "agent_epoch_journal",
            detail: format!("truncated epoch header in epoch {expected_epoch}"),
        })?;
    if buf[0..4] != AGENT_EPOCH_FILE_MAGIC
        || u16::from_be_bytes([buf[4], buf[5]]) != AGENT_EPOCH_FORMAT_VERSION
        || crc32c(&buf[0..54]) != read_u32(&buf, 54)
    {
        return Err(ProjectionError::CorruptDerivedStore {
            artifact: "agent_epoch_journal",
            detail: format!("invalid header magic/version/crc in epoch {expected_epoch}"),
        });
    }
    let epoch_id = read_u64(&buf, 6);
    if epoch_id != expected_epoch {
        return Err(ProjectionError::CorruptDerivedStore {
            artifact: "agent_epoch_journal",
            detail: format!("epoch header id {epoch_id} != filename {expected_epoch}"),
        });
    }
    let mut prev = [0_u8; 32];
    prev.copy_from_slice(&buf[22..54]);
    Ok(EpochHeader {
        epoch_id,
        first_seq: read_u64(&buf, 14),
        prev_chain: ContentDigest::new(DigestAlgorithm::Sha256, prev),
    })
}

pub(super) fn encode_record_frame(
    kind: u16,
    seq: u64,
    body: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), ProjectionError> {
    let body_len = u32::try_from(body.len())
        .map_err(|_| ProjectionError::ArithmeticOverflow("record_body_len"))?;
    let start = out.len();
    out.extend_from_slice(&AGENT_EPOCH_RECORD_MAGIC);
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&body_len.to_be_bytes());
    out.extend_from_slice(body);
    let crc = crc32c(&out[start..]);
    out.extend_from_slice(&crc.to_be_bytes());
    Ok(())
}

pub(super) fn encode_epoch_seal(seal: EpochSeal) -> [u8; AGENT_EPOCH_SEAL_LEN] {
    let mut out = [0_u8; AGENT_EPOCH_SEAL_LEN];
    out[0..4].copy_from_slice(&AGENT_EPOCH_SEAL_MAGIC);
    out[4..12].copy_from_slice(&seal.epoch_id.to_be_bytes());
    out[12..20].copy_from_slice(&seal.record_count.to_be_bytes());
    out[20..28].copy_from_slice(&seal.last_seq.to_be_bytes());
    out[28..60].copy_from_slice(&seal.seal_digest.bytes());
    let crc = crc32c(&out[0..60]);
    out[60..64].copy_from_slice(&crc.to_be_bytes());
    out
}

fn decode_epoch_seal(buf: &[u8]) -> Option<EpochSeal> {
    if buf.len() != AGENT_EPOCH_SEAL_LEN || buf[0..4] != AGENT_EPOCH_SEAL_MAGIC {
        return None;
    }
    if crc32c(&buf[0..60]) != read_u32(buf, 60) {
        return None;
    }
    let mut d = [0_u8; 32];
    d.copy_from_slice(&buf[28..60]);
    Some(EpochSeal {
        epoch_id: read_u64(buf, 4),
        record_count: read_u64(buf, 12),
        last_seq: read_u64(buf, 20),
        seal_digest: ContentDigest::new(DigestAlgorithm::Sha256, d),
    })
}

pub(super) fn scan_epoch_tail(
    path: &Path,
    epoch_id: u64,
    start_offset: u64,
    start_seq: u64,
    start_chain: ContentDigest,
    allow_torn_tail: bool,
) -> Result<ScanOutcome, ProjectionError> {
    let mut file =
        File::open(path).map_err(|err| ProjectionError::io(ProjectionIoOperation::Open, err))?;
    let file_len = file
        .metadata()
        .map_err(|err| ProjectionError::io(ProjectionIoOperation::Metadata, err))?
        .len();
    if start_offset < AGENT_EPOCH_HEADER_LEN as u64 || start_offset > file_len {
        return Err(ProjectionError::CorruptDerivedStore {
            artifact: "agent_epoch_journal",
            detail: format!("invalid start offset {start_offset} for epoch {epoch_id}"),
        });
    }
    if start_offset == file_len {
        return Ok(ScanOutcome {
            records: Vec::new(),
            committed_len: start_offset,
            last_seq: start_seq,
            chain_digest: start_chain,
            sealed: None,
            torn_tail_offset: None,
        });
    }
    file.seek(SeekFrom::Start(start_offset))
        .map_err(|err| ProjectionError::io(ProjectionIoOperation::Read, err))?;
    let mut raw = Vec::new();
    file.read_to_end(&mut raw)
        .map_err(|err| ProjectionError::io(ProjectionIoOperation::Read, err))?;

    let mut records = Vec::new();
    let mut cursor = 0_usize;
    let mut seq = start_seq;
    let mut chain = start_chain;
    let mut sealed = None;

    while cursor < raw.len() {
        let abs_pos = start_offset.saturating_add(cursor as u64);
        let rem = raw.len() - cursor;

        if rem >= 4 && raw[cursor..cursor + 4] == AGENT_EPOCH_SEAL_MAGIC {
            if rem == AGENT_EPOCH_SEAL_LEN
                && let Some(s) = decode_epoch_seal(&raw[cursor..cursor + AGENT_EPOCH_SEAL_LEN])
                && s.epoch_id == epoch_id
                && s.last_seq == seq
                && s.seal_digest == chain
            {
                cursor += AGENT_EPOCH_SEAL_LEN;
                sealed = Some(s);
                break;
            }
            if allow_torn_tail {
                return Ok(ScanOutcome {
                    records,
                    committed_len: abs_pos,
                    last_seq: seq,
                    chain_digest: chain,
                    sealed: None,
                    torn_tail_offset: Some(abs_pos),
                });
            }
            return Err(ProjectionError::CorruptDerivedStore {
                artifact: "agent_epoch_journal",
                detail: format!("corrupt epoch seal trailer in epoch {epoch_id} at {abs_pos}"),
            });
        }

        let Some((kind, rec_seq, body_len, frame_len)) = parse_record_header(&raw[cursor..], seq)
        else {
            return Ok(ScanOutcome {
                records,
                committed_len: abs_pos,
                last_seq: seq,
                chain_digest: chain,
                sealed: None,
                torn_tail_offset: Some(abs_pos),
            });
        };

        let body_start = cursor + AGENT_RECORD_HEADER_LEN;
        let body = raw[body_start..body_start + body_len].to_vec();
        chain = advance_chain_digest(chain, epoch_id, rec_seq, kind, &body);
        seq = rec_seq;
        records.push(EpochJournalRecord {
            seq: rec_seq,
            kind,
            body,
        });
        cursor += frame_len;
    }

    Ok(ScanOutcome {
        records,
        committed_len: start_offset.saturating_add(cursor as u64),
        last_seq: seq,
        chain_digest: chain,
        sealed,
        torn_tail_offset: None,
    })
}

fn parse_record_header(slice: &[u8], prev_seq: u64) -> Option<(u16, u64, usize, usize)> {
    if slice.len() < AGENT_RECORD_HEADER_LEN + AGENT_RECORD_TRAILER_LEN {
        return None;
    }
    if slice[0..4] != AGENT_EPOCH_RECORD_MAGIC || u16::from_be_bytes([slice[6], slice[7]]) != 0 {
        return None;
    }
    let kind = u16::from_be_bytes([slice[4], slice[5]]);
    let rec_seq = read_u64(slice, 8);
    if rec_seq != prev_seq.saturating_add(1) {
        return None;
    }
    let body_len = read_u32(slice, 16) as usize;
    if body_len > MAX_AGENT_RECORD_BYTES {
        return None;
    }
    let frame_len = AGENT_RECORD_HEADER_LEN
        .checked_add(body_len)?
        .checked_add(AGENT_RECORD_TRAILER_LEN)?;
    if frame_len > slice.len() {
        return None;
    }
    let crc_pos = frame_len - AGENT_RECORD_TRAILER_LEN;
    if crc32c(&slice[..crc_pos]) != read_u32(slice, crc_pos) {
        return None;
    }
    Some((kind, rec_seq, body_len, frame_len))
}

pub(super) fn list_epoch_ids(epochs_dir: &Path) -> Result<Vec<u64>, ProjectionError> {
    let mut ids = Vec::new();
    for entry in fs::read_dir(epochs_dir)
        .map_err(|err| ProjectionError::io(ProjectionIoOperation::ReadDir, err))?
    {
        let entry =
            entry.map_err(|err| ProjectionError::io(ProjectionIoOperation::ReadDir, err))?;
        let name = entry.file_name();
        if let Some(s) = name.to_str()
            && !s.starts_with('.')
            && let Some(stem) = s.strip_suffix(".fssa")
            && stem.len() == 16
            && stem.bytes().all(|b| b.is_ascii_digit())
            && let Ok(id) = stem.parse::<u64>()
        {
            ids.push(id);
        }
    }
    ids.sort_unstable();
    for (idx, &id) in ids.iter().enumerate() {
        if id != idx as u64 {
            return Err(ProjectionError::CorruptDerivedStore {
                artifact: "agent_epoch_journal",
                detail: format!("non-contiguous epoch {id} where {idx} expected"),
            });
        }
    }
    Ok(ids)
}

pub(super) fn create_epoch_file_atomic(
    epochs_dir: &Path,
    hdr: &EpochHeader,
    durability: DurabilityMode,
) -> Result<PathBuf, ProjectionError> {
    let final_path = epoch_path(epochs_dir, hdr.epoch_id);
    let tmp_path = epochs_dir.join(format!(".{:016}.fssa.tmp", hdr.epoch_id));
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|err| ProjectionError::io(ProjectionIoOperation::Open, err))?;
        f.write_all(&encode_epoch_header(hdr))
            .map_err(|err| ProjectionError::io(ProjectionIoOperation::Write, err))?;
        sync_file_mode(&f, durability)?;
    }
    fs::rename(&tmp_path, &final_path)
        .map_err(|err| ProjectionError::io(ProjectionIoOperation::Rename, err))?;
    sync_directory(epochs_dir)?;
    Ok(final_path)
}

pub(super) fn recover_active_header(
    root_dir: &Path,
    epochs_dir: &Path,
    epoch_ids: &mut Vec<u64>,
    policy: IncompleteTailPolicy,
    truncated_tail_bytes: &mut u64,
) -> Result<EpochHeader, ProjectionError> {
    let last_id = *epoch_ids
        .last()
        .ok_or(ProjectionError::CorruptDerivedStore {
            artifact: "agent_epoch_journal",
            detail: "no epoch files present".to_owned(),
        })?;
    match read_epoch_header(&epoch_path(epochs_dir, last_id), last_id) {
        Ok(hdr) => Ok(hdr),
        Err(err) if last_id == 0 || policy == IncompleteTailPolicy::Reject => Err(err),
        Err(_) => {
            let bad_path = epoch_path(epochs_dir, last_id);
            *truncated_tail_bytes = truncated_tail_bytes
                .saturating_add(fs::metadata(&bad_path).map(|m| m.len()).unwrap_or(0));
            quarantine_file(root_dir, &bad_path)?;
            epoch_ids.pop();
            let prev_id = *epoch_ids
                .last()
                .ok_or(ProjectionError::CorruptDerivedStore {
                    artifact: "agent_epoch_journal",
                    detail: "no readable epoch remained after quarantining torn rollover"
                        .to_owned(),
                })?;
            read_epoch_header(&epoch_path(epochs_dir, prev_id), prev_id)
        }
    }
}

pub(super) fn open_rw(path: &Path) -> Result<File, ProjectionError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|err| ProjectionError::io(ProjectionIoOperation::Open, err))
}

fn read_u32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn read_u64(b: &[u8], o: usize) -> u64 {
    u64::from_be_bytes([
        b[o],
        b[o + 1],
        b[o + 2],
        b[o + 3],
        b[o + 4],
        b[o + 5],
        b[o + 6],
        b[o + 7],
    ])
}
