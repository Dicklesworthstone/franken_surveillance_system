#![forbid(unsafe_code)]
//! Bounded immutable epoch segment headers, scanning, and O(1) checkpoint anchor checks.
//!
//! Each epoch file (`<dir>/epochs/{epoch_id:016}.fssj`) carries a verified 90-byte `FSSE` v2
//! header followed by length-framed, CRC32 + SHA-256 + commit-trailer (`FSST`) verified canonical
//! `EvidenceDeltaBatch` records. Crash-tail detection follows `LEDGER-CRASH-001`.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, DigestAlgorithm, Sha256Hasher, sha256};

use crate::MAX_RECORD_PAYLOAD_BYTES;

use super::{
    CheckpointCorruptionKind, EPOCH_HEADER_DOMAIN, EpochCorruptionKind, EpochLedgerError,
    crc32_ieee, sync_directory,
};

/// Magic bytes identifying a v2 FSS epoch segment file.
pub const EPOCH_FILE_MAGIC: [u8; 4] = *b"FSSE";
/// Format version for v2 FSS epoch segment files.
pub const EPOCH_FORMAT_VERSION: u16 = 2;
/// Fixed byte length of one epoch segment file header:
/// `magic(4) + version(2) + epoch_id(8) + first_commit_seq(8) + prev_history_root(32) + crc32(4) + sha256(32)`.
pub const EPOCH_HEADER_LEN: usize = 90;

/// Magic bytes identifying one framed batch record inside an epoch segment file.
pub const EPOCH_RECORD_MAGIC: [u8; 4] = *b"FSSR";
/// Fixed byte length of one record header:
/// `magic(4) + flags(2) + commit_seq(8) + payload_len(4) + payload_crc32(4) + payload_sha256(32) + header_crc32(4)`.
pub const EPOCH_RECORD_HEADER_LEN: usize = 58;

/// Magic bytes identifying one record commit trailer inside an epoch segment file.
pub const EPOCH_TRAILER_MAGIC: [u8; 4] = *b"FSST";
/// Fixed byte length of one record commit trailer:
/// `magic(4) + history_root(32) + trailer_crc32(4)`.
pub const EPOCH_RECORD_TRAILER_LEN: usize = 40;

/// Decoded header of one v2 epoch segment file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochHeader {
    /// Zero-based monotonically increasing epoch segment identifier.
    pub epoch_id: u64,
    /// First commit sequence expected inside this epoch (`1` for epoch `0`).
    pub first_commit_seq: u64,
    /// Canonical v2 history root immediately prior to `first_commit_seq`.
    pub prev_history_root: ContentDigest,
}

impl EpochHeader {
    /// Serializes this epoch header into its exact 90-byte canonical binary representation.
    #[must_use]
    pub fn encode(&self) -> [u8; EPOCH_HEADER_LEN] {
        let mut out = [0_u8; EPOCH_HEADER_LEN];
        out[0..4].copy_from_slice(&EPOCH_FILE_MAGIC);
        out[4..6].copy_from_slice(&EPOCH_FORMAT_VERSION.to_be_bytes());
        out[6..14].copy_from_slice(&self.epoch_id.to_be_bytes());
        out[14..22].copy_from_slice(&self.first_commit_seq.to_be_bytes());
        out[22..54].copy_from_slice(&self.prev_history_root.bytes());
        let crc = crc32_ieee(&out[0..54]);
        out[54..58].copy_from_slice(&crc.to_be_bytes());
        let digest = epoch_header_digest(&out[0..54]);
        out[58..90].copy_from_slice(&digest);
        out
    }

    /// Decodes and verifies a 90-byte epoch header against `expected_epoch_id`.
    pub fn decode(bytes: &[u8], expected_epoch_id: u64) -> Result<Self, EpochLedgerError> {
        if bytes.len() < EPOCH_HEADER_LEN {
            return Err(EpochLedgerError::CorruptEpoch {
                epoch_id: expected_epoch_id,
                offset: 0,
                kind: EpochCorruptionKind::TruncatedHeader,
            });
        }
        if bytes[0..4] != EPOCH_FILE_MAGIC {
            return Err(EpochLedgerError::CorruptEpoch {
                epoch_id: expected_epoch_id,
                offset: 0,
                kind: EpochCorruptionKind::InvalidMagic,
            });
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != EPOCH_FORMAT_VERSION {
            return Err(EpochLedgerError::CorruptEpoch {
                epoch_id: expected_epoch_id,
                offset: 0,
                kind: EpochCorruptionKind::UnsupportedVersion,
            });
        }
        let stored_crc = u32::from_be_bytes([bytes[54], bytes[55], bytes[56], bytes[57]]);
        if crc32_ieee(&bytes[0..54]) != stored_crc {
            return Err(EpochLedgerError::CorruptEpoch {
                epoch_id: expected_epoch_id,
                offset: 0,
                kind: EpochCorruptionKind::HeaderChecksumMismatch,
            });
        }
        let expected_digest = epoch_header_digest(&bytes[0..54]);
        if bytes[58..90] != expected_digest {
            return Err(EpochLedgerError::CorruptEpoch {
                epoch_id: expected_epoch_id,
                offset: 0,
                kind: EpochCorruptionKind::HeaderChecksumMismatch,
            });
        }
        let epoch_id = read_u64_be(bytes, 6);
        if epoch_id != expected_epoch_id {
            return Err(EpochLedgerError::CorruptEpoch {
                epoch_id: expected_epoch_id,
                offset: 0,
                kind: EpochCorruptionKind::EpochIdMismatch,
            });
        }
        let first_commit_seq = read_u64_be(bytes, 14);
        let mut prev_root = [0_u8; 32];
        prev_root.copy_from_slice(&bytes[22..54]);
        Ok(Self {
            epoch_id,
            first_commit_seq,
            prev_history_root: ContentDigest::new(DigestAlgorithm::Sha256, prev_root),
        })
    }
}

/// One framing-verified record read from an epoch segment file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochRecord {
    /// Monotone commit sequence carried by the record header.
    pub commit_seq: u64,
    /// Exact canonical `encode_batch` payload bytes.
    pub payload: Vec<u8>,
    /// Verified SHA-256 digest of `payload`.
    pub payload_digest: ContentDigest,
    /// History root sealed in the commit trailer.
    pub history_root: ContentDigest,
    /// Starting byte offset of this record in the epoch file.
    pub start_offset: u64,
    /// Byte offset immediately following this record's commit trailer.
    pub end_offset: u64,
}

/// Result of scanning one epoch segment file from a starting offset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochScanReport {
    /// Verified epoch file header.
    pub header: EpochHeader,
    /// Framing-verified records decoded starting from `start_offset`.
    pub records: Vec<EpochRecord>,
    /// Byte offset immediately following the last complete record (or `start_offset` if none).
    pub committed_len: u64,
    /// Starting byte offset of a valid incomplete tail record, if present.
    pub incomplete_tail: Option<u64>,
    /// Last committed history root observed at `committed_len`.
    pub last_history_root: ContentDigest,
}

/// Returns the canonical path `<epochs_dir>/{epoch_id:016}.fssj`.
#[must_use]
pub fn epoch_file_path(epochs_dir: &Path, epoch_id: u64) -> PathBuf {
    epochs_dir.join(format!("{epoch_id:016}.fssj"))
}

/// Lists all epoch IDs present in `epochs_dir`, sorted ascending, verifying contiguity from `0`.
pub(crate) fn list_epoch_ids(epochs_dir: &Path) -> Result<Vec<u64>, EpochLedgerError> {
    if !epochs_dir.exists() {
        return Ok(Vec::new());
    }
    let mut ids = Vec::new();
    for entry in fs::read_dir(epochs_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if name_str.starts_with('.') {
            continue;
        }
        if let Some(stem) = name_str.strip_suffix(".fssj")
            && stem.len() == 16
            && stem.bytes().all(|b| b.is_ascii_digit())
            && let Ok(id) = stem.parse::<u64>()
        {
            ids.push(id);
        }
    }
    ids.sort_unstable();
    if let Some(&first_id) = ids.first() {
        for (offset, &observed) in ids.iter().enumerate() {
            let expected_u64 = first_id.saturating_add(offset as u64);
            if observed != expected_u64 {
                return Err(EpochLedgerError::MissingEpoch {
                    expected_epoch_id: expected_u64,
                });
            }
        }
    }
    Ok(ids)
}

/// Atomically creates a new epoch segment file with its verified 90-byte header via temp+fsync+rename.
pub(crate) fn create_epoch_file_atomic(
    epochs_dir: &Path,
    header: &EpochHeader,
) -> Result<PathBuf, EpochLedgerError> {
    fs::create_dir_all(epochs_dir)?;
    let final_path = epoch_file_path(epochs_dir, header.epoch_id);
    let tmp_path = epochs_dir.join(format!(".{:016}.fssj.tmp", header.epoch_id));
    let header_bytes = header.encode();
    {
        let mut tmp = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        tmp.write_all(&header_bytes)?;
        tmp.sync_all()?;
    }
    fs::rename(&tmp_path, &final_path)?;
    sync_directory(epochs_dir)?;
    Ok(final_path)
}

/// Verifies in `O(1)` that a checkpoint's `(epoch_id, epoch_byte_offset, history_root)` matches
/// the on-disk epoch header or commit trailer at `epoch_byte_offset`.
pub(crate) fn verify_checkpoint_epoch_anchor(
    epochs_dir: &Path,
    epoch_id: u64,
    epoch_byte_offset: u64,
    expected_history_root: ContentDigest,
) -> Result<(), CheckpointCorruptionKind> {
    let path = epoch_file_path(epochs_dir, epoch_id);
    let mut file = File::open(&path).map_err(|_| CheckpointCorruptionKind::EpochOffsetMismatch)?;
    let file_len = file
        .metadata()
        .map_err(|_| CheckpointCorruptionKind::EpochOffsetMismatch)?
        .len();
    if epoch_byte_offset < EPOCH_HEADER_LEN as u64 || file_len < epoch_byte_offset {
        return Err(CheckpointCorruptionKind::EpochOffsetMismatch);
    }

    let mut header_buf = [0_u8; EPOCH_HEADER_LEN];
    file.read_exact(&mut header_buf)
        .map_err(|_| CheckpointCorruptionKind::EpochOffsetMismatch)?;
    let header = EpochHeader::decode(&header_buf, epoch_id)
        .map_err(|_| CheckpointCorruptionKind::EpochTrailerMismatch)?;

    if epoch_byte_offset == EPOCH_HEADER_LEN as u64 {
        return if header.prev_history_root == expected_history_root {
            Ok(())
        } else {
            Err(CheckpointCorruptionKind::EpochTrailerMismatch)
        };
    }

    let min_after_record =
        (EPOCH_HEADER_LEN + EPOCH_RECORD_HEADER_LEN + EPOCH_RECORD_TRAILER_LEN) as u64;
    if epoch_byte_offset < min_after_record {
        return Err(CheckpointCorruptionKind::EpochOffsetMismatch);
    }
    let trailer_offset = epoch_byte_offset - EPOCH_RECORD_TRAILER_LEN as u64;
    file.seek(SeekFrom::Start(trailer_offset))
        .map_err(|_| CheckpointCorruptionKind::EpochTrailerMismatch)?;
    let mut trailer_buf = [0_u8; EPOCH_RECORD_TRAILER_LEN];
    file.read_exact(&mut trailer_buf)
        .map_err(|_| CheckpointCorruptionKind::EpochTrailerMismatch)?;
    let trailer_root = decode_trailer(&trailer_buf, epoch_id, trailer_offset)
        .map_err(|_| CheckpointCorruptionKind::EpochTrailerMismatch)?;
    if trailer_root != expected_history_root {
        return Err(CheckpointCorruptionKind::EpochTrailerMismatch);
    }
    Ok(())
}

/// Scans an epoch file starting from `start_offset`, reading ONLY the header, optional anchor
/// trailer, and post-offset tail bytes `[start_offset..EOF]`.
pub(crate) fn scan_epoch_from(
    epochs_dir: &Path,
    expected_epoch_id: u64,
    start_offset: u64,
    start_commit_seq: u64,
    start_history_root: ContentDigest,
) -> Result<EpochScanReport, EpochLedgerError> {
    let path = epoch_file_path(epochs_dir, expected_epoch_id);
    let mut file = File::open(&path)?;
    let file_len = file.metadata()?.len();
    if file_len < EPOCH_HEADER_LEN as u64 {
        return Err(EpochLedgerError::CorruptEpoch {
            epoch_id: expected_epoch_id,
            offset: 0,
            kind: EpochCorruptionKind::TruncatedHeader,
        });
    }

    let mut header_buf = [0_u8; EPOCH_HEADER_LEN];
    file.read_exact(&mut header_buf)?;
    let header = EpochHeader::decode(&header_buf, expected_epoch_id)?;

    if start_offset == EPOCH_HEADER_LEN as u64 {
        if header.first_commit_seq != start_commit_seq {
            return Err(EpochLedgerError::CorruptEpoch {
                epoch_id: expected_epoch_id,
                offset: 0,
                kind: EpochCorruptionKind::FirstCommitSeqMismatch,
            });
        }
        if header.prev_history_root != start_history_root {
            return Err(EpochLedgerError::CorruptEpoch {
                epoch_id: expected_epoch_id,
                offset: 0,
                kind: EpochCorruptionKind::PrevHistoryRootMismatch,
            });
        }
    } else if start_offset < EPOCH_HEADER_LEN as u64 || start_offset > file_len {
        return Err(EpochLedgerError::CorruptEpoch {
            epoch_id: expected_epoch_id,
            offset: start_offset,
            kind: EpochCorruptionKind::TruncatedHeader,
        });
    } else {
        let trailer_pos = start_offset
            .checked_sub(EPOCH_RECORD_TRAILER_LEN as u64)
            .ok_or(EpochLedgerError::CorruptEpoch {
                epoch_id: expected_epoch_id,
                offset: start_offset,
                kind: EpochCorruptionKind::TrailerMagic,
            })?;
        file.seek(SeekFrom::Start(trailer_pos))?;
        let mut trailer_buf = [0_u8; EPOCH_RECORD_TRAILER_LEN];
        file.read_exact(&mut trailer_buf)?;
        let trailer_root = decode_trailer(&trailer_buf, expected_epoch_id, trailer_pos)?;
        if trailer_root != start_history_root {
            return Err(EpochLedgerError::CorruptEpoch {
                epoch_id: expected_epoch_id,
                offset: trailer_pos,
                kind: EpochCorruptionKind::HistoryRootMismatch,
            });
        }
    }

    file.seek(SeekFrom::Start(start_offset))?;
    let mut tail_bytes = Vec::new();
    file.read_to_end(&mut tail_bytes)?;

    parse_tail_records(
        &tail_bytes,
        header,
        expected_epoch_id,
        start_offset,
        start_commit_seq,
        start_history_root,
    )
}

fn parse_tail_records(
    tail_bytes: &[u8],
    header: EpochHeader,
    expected_epoch_id: u64,
    start_offset: u64,
    start_commit_seq: u64,
    start_history_root: ContentDigest,
) -> Result<EpochScanReport, EpochLedgerError> {
    let mut cursor = 0_usize;
    let mut expected_seq = start_commit_seq;
    let mut last_history_root = start_history_root;
    let mut records = Vec::new();

    while cursor < tail_bytes.len() {
        let rec_abs_offset = start_offset
            .checked_add(cursor as u64)
            .ok_or(EpochLedgerError::SequenceExhausted)?;
        let remaining = tail_bytes.len() - cursor;

        // LEDGER-CRASH-001: non-magic bytes after the last commit trailer are ALWAYS Corrupt.
        let magic_check = remaining.min(EPOCH_RECORD_MAGIC.len());
        if tail_bytes[cursor..cursor + magic_check] != EPOCH_RECORD_MAGIC[..magic_check] {
            return Err(EpochLedgerError::CorruptEpoch {
                epoch_id: expected_epoch_id,
                offset: rec_abs_offset,
                kind: EpochCorruptionKind::RecordMagic,
            });
        }
        if remaining < EPOCH_RECORD_HEADER_LEN {
            return Ok(EpochScanReport {
                header,
                records,
                committed_len: rec_abs_offset,
                incomplete_tail: Some(rec_abs_offset),
                last_history_root,
            });
        }

        let hdr = &tail_bytes[cursor..cursor + EPOCH_RECORD_HEADER_LEN];
        if u16::from_be_bytes([hdr[4], hdr[5]]) != 0 {
            return Err(EpochLedgerError::CorruptEpoch {
                epoch_id: expected_epoch_id,
                offset: rec_abs_offset,
                kind: EpochCorruptionKind::RecordFlags,
            });
        }
        if crc32_ieee(&hdr[0..54]) != read_u32_be(hdr, 54) {
            return Err(EpochLedgerError::CorruptEpoch {
                epoch_id: expected_epoch_id,
                offset: rec_abs_offset,
                kind: EpochCorruptionKind::RecordHeaderChecksum,
            });
        }
        let commit_seq = read_u64_be(hdr, 6);
        if commit_seq != expected_seq {
            return Err(EpochLedgerError::CorruptEpoch {
                epoch_id: expected_epoch_id,
                offset: rec_abs_offset,
                kind: EpochCorruptionKind::RecordSequence,
            });
        }
        let payload_len = read_u32_be(hdr, 14) as usize;
        if payload_len > MAX_RECORD_PAYLOAD_BYTES {
            return Err(EpochLedgerError::CorruptEpoch {
                epoch_id: expected_epoch_id,
                offset: rec_abs_offset,
                kind: EpochCorruptionKind::PayloadLength,
            });
        }
        let expected_payload_crc = read_u32_be(hdr, 18);
        let mut expected_payload_sha = [0_u8; 32];
        expected_payload_sha.copy_from_slice(&hdr[22..54]);

        let payload_start = cursor + EPOCH_RECORD_HEADER_LEN;
        let payload_end = payload_start.saturating_add(payload_len);
        let record_end = payload_end.saturating_add(EPOCH_RECORD_TRAILER_LEN);

        if tail_bytes.len() < payload_end {
            return Ok(EpochScanReport {
                header,
                records,
                committed_len: rec_abs_offset,
                incomplete_tail: Some(rec_abs_offset),
                last_history_root,
            });
        }

        let payload = &tail_bytes[payload_start..payload_end];
        if crc32_ieee(payload) != expected_payload_crc {
            return Err(EpochLedgerError::CorruptEpoch {
                epoch_id: expected_epoch_id,
                offset: rec_abs_offset,
                kind: EpochCorruptionKind::PayloadChecksum,
            });
        }
        if sha256(payload) != expected_payload_sha {
            return Err(EpochLedgerError::CorruptEpoch {
                epoch_id: expected_epoch_id,
                offset: rec_abs_offset,
                kind: EpochCorruptionKind::PayloadDigest,
            });
        }

        if tail_bytes.len() < record_end {
            let trailer_prefix = &tail_bytes[payload_end..];
            let check = trailer_prefix.len().min(EPOCH_TRAILER_MAGIC.len());
            if trailer_prefix[..check] != EPOCH_TRAILER_MAGIC[..check] {
                return Err(EpochLedgerError::CorruptEpoch {
                    epoch_id: expected_epoch_id,
                    offset: rec_abs_offset,
                    kind: EpochCorruptionKind::TrailerMagic,
                });
            }
            return Ok(EpochScanReport {
                header,
                records,
                committed_len: rec_abs_offset,
                incomplete_tail: Some(rec_abs_offset),
                last_history_root,
            });
        }

        let trailer = &tail_bytes[payload_end..record_end];
        let history_root = decode_trailer(trailer, expected_epoch_id, rec_abs_offset)?;
        let abs_end = start_offset
            .checked_add(record_end as u64)
            .ok_or(EpochLedgerError::SequenceExhausted)?;

        records.push(EpochRecord {
            commit_seq,
            payload: payload.to_vec(),
            payload_digest: ContentDigest::new(DigestAlgorithm::Sha256, expected_payload_sha),
            history_root,
            start_offset: rec_abs_offset,
            end_offset: abs_end,
        });

        cursor = record_end;
        last_history_root = history_root;
        expected_seq = expected_seq
            .checked_add(1)
            .ok_or(EpochLedgerError::SequenceExhausted)?;
    }

    let committed_len = start_offset
        .checked_add(cursor as u64)
        .ok_or(EpochLedgerError::SequenceExhausted)?;
    Ok(EpochScanReport {
        header,
        records,
        committed_len,
        incomplete_tail: None,
        last_history_root,
    })
}

fn decode_trailer(
    trailer: &[u8],
    epoch_id: u64,
    offset: u64,
) -> Result<ContentDigest, EpochLedgerError> {
    if trailer.len() != EPOCH_RECORD_TRAILER_LEN || trailer[0..4] != EPOCH_TRAILER_MAGIC {
        return Err(EpochLedgerError::CorruptEpoch {
            epoch_id,
            offset,
            kind: EpochCorruptionKind::TrailerMagic,
        });
    }
    if crc32_ieee(&trailer[0..36]) != read_u32_be(trailer, 36) {
        return Err(EpochLedgerError::CorruptEpoch {
            epoch_id,
            offset,
            kind: EpochCorruptionKind::TrailerChecksum,
        });
    }
    let mut root = [0_u8; 32];
    root.copy_from_slice(&trailer[4..36]);
    Ok(ContentDigest::new(DigestAlgorithm::Sha256, root))
}

fn epoch_header_digest(header_prefix: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256Hasher::new();
    let domain = EPOCH_HEADER_DOMAIN.as_bytes();
    hasher.update(&(domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update(header_prefix);
    hasher.finalize().unwrap_or_default()
}

#[inline]
fn read_u32_be(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[inline]
fn read_u64_be(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}
