#![forbid(unsafe_code)]
//! Compact CRC32C-framed binary WAL (`mvcc.wal`), atomic verified snapshot persistence,
//! and corrupt-artifact quarantine helpers for derived projection storage.
//!
//! # WAL Frame Layout (`FMVW` v1, big-endian)
//!
//! ```text
//! [magic(4) = b"FMVW" | version(u16=1) | op_tag(u16) | seq(u64)
//!  | body_len(u32) | body_bytes(body_len) | frame_crc32c(u32)]
//! ```

use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fss_core::{CanonicalDecode, CanonicalEncode, EvidenceDeltaBatch};
use fss_ledger::{decode_batch, encode_batch};
use fss_pack::{DurabilityMode, crc32c};

use crate::error::{ProjectionError, ProjectionIoOperation};
use crate::schema::DoctorScrubReceipt;
use crate::snapshot::{MAX_PROJECTION_SNAPSHOT_BYTES, ProjectionSnapshot};

/// Filename for the atomic verified projection snapshot inside `<projection_dir>/`.
pub const SNAPSHOT_FILENAME: &str = "mvcc.snap";
/// Filename for the CRC32C-framed binary projection WAL inside `<projection_dir>/`.
pub const WAL_FILENAME: &str = "mvcc.wal";
/// Subdirectory holding quarantined corrupt derived files.
pub const QUARANTINE_DIRNAME: &str = "quarantine";

/// Magic bytes prefixing every `mvcc.wal` frame (`FMVW`).
pub const WAL_FRAME_MAGIC: [u8; 4] = *b"FMVW";
/// Supported WAL binary format version.
pub const WAL_FORMAT_VERSION: u16 = 1;
/// Fixed header byte length of one WAL frame (`4 + 2 + 2 + 8 + 4 = 20`).
pub const WAL_FRAME_HEADER_LEN: usize = 20;
/// Fixed CRC32C trailer byte length of one WAL frame.
pub const WAL_FRAME_TRAILER_LEN: usize = 4;
/// Maximum WAL frame body byte length (16 MiB, aligned with ledger max record size).
pub const MAX_WAL_FRAME_BODY_BYTES: usize = 16 * 1024 * 1024;

const WAL_OP_APPLY_BATCH: u16 = 1;
const WAL_OP_SCRUB_RECEIPT: u16 = 2;

/// Controls whether derived WAL appends invoke an OS fsync barrier on every commit.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum WalSyncPolicy {
    /// Flush WAL bytes to OS page cache per commit; fsync on snapshot compaction and scrub receipts.
    ///
    /// Canonical durability is enforced by `PackStore` and `MerkleEpochLedger`; on crash, any
    /// un-flushed derived WAL tail is deterministically replayed from the canonical ledger.
    #[default]
    FlushOnly,
    /// Invoke `sync_data` / `sync_all` on every derived WAL append.
    EveryCommit(DurabilityMode),
}

/// Decoded operation stored in one verified CRC32C WAL frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WalRecord {
    ApplyBatch {
        commit_sequence: u64,
        batch: EvidenceDeltaBatch,
    },
    RecordScrubReceipt {
        commit_sequence: u64,
        receipt: DoctorScrubReceipt,
    },
}

/// Append-only CRC32C-framed binary WAL writer for `<projection_dir>/mvcc.wal`.
pub(crate) struct ProjectionWal {
    path: PathBuf,
    file: File,
    sync_policy: WalSyncPolicy,
    durability: DurabilityMode,
    frames_written: u64,
}

impl ProjectionWal {
    /// Opens or creates `mvcc.wal` positioned at EOF for appending.
    pub(crate) fn open_append(
        dir: &Path,
        sync_policy: WalSyncPolicy,
        durability: DurabilityMode,
    ) -> Result<Self, ProjectionError> {
        let path = dir.join(WAL_FILENAME);
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|err| ProjectionError::io(ProjectionIoOperation::Open, err))?;
        file.seek(SeekFrom::End(0))
            .map_err(|err| ProjectionError::io(ProjectionIoOperation::Write, err))?;
        Ok(Self {
            path,
            file,
            sync_policy,
            durability,
            frames_written: 0,
        })
    }

    /// Truncates `mvcc.wal` to zero bytes and resets the frame counter after snapshot compaction.
    pub(crate) fn reset_empty(&mut self) -> Result<(), ProjectionError> {
        self.file
            .set_len(0)
            .map_err(|err| ProjectionError::io(ProjectionIoOperation::Truncate, err))?;
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|err| ProjectionError::io(ProjectionIoOperation::Write, err))?;
        sync_file_mode(&self.file, self.durability)?;
        self.frames_written = 0;
        Ok(())
    }

    /// Returns number of frames written since the last snapshot compaction.
    #[must_use]
    pub(crate) const fn frames_written(&self) -> u64 {
        self.frames_written
    }

    /// Appends an already encoded and bounded `ApplyBatch` frame to `mvcc.wal`.
    pub(crate) fn append_prepared_batch(
        &mut self,
        batch: &PreparedWalBatch,
    ) -> Result<(), ProjectionError> {
        self.write_frame(&batch.frame, false)
    }

    /// Appends a verified `RecordScrubReceipt` frame and always fsyncs it durably.
    pub(crate) fn append_scrub_receipt(
        &mut self,
        receipt: &DoctorScrubReceipt,
    ) -> Result<(), ProjectionError> {
        let body = receipt.try_canonical_bytes()?;
        let frame = encode_wal_frame(WAL_OP_SCRUB_RECEIPT, receipt.anchor.commit_sequence, &body)?;
        self.write_frame(&frame, true)
    }

    fn write_frame(&mut self, frame: &[u8], force_sync: bool) -> Result<(), ProjectionError> {
        self.file
            .write_all(frame)
            .map_err(|err| ProjectionError::io(ProjectionIoOperation::Write, err))?;
        self.file
            .flush()
            .map_err(|err| ProjectionError::io(ProjectionIoOperation::Flush, err))?;
        if force_sync {
            sync_file_mode(&self.file, self.durability)?;
        } else if let WalSyncPolicy::EveryCommit(mode) = self.sync_policy {
            sync_file_mode(&self.file, mode)?;
        }
        self.frames_written = self.frames_written.saturating_add(1);
        Ok(())
    }

    /// Returns the filesystem path of `mvcc.wal`.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

/// A fully encoded, bounded batch frame prepared before canonical commitment.
/// Its private bytes cannot be replaced between validation and persistence.
pub(crate) struct PreparedWalBatch {
    frame: Vec<u8>,
}

impl PreparedWalBatch {
    pub(crate) fn encode(batch: &EvidenceDeltaBatch) -> Result<Self, ProjectionError> {
        let body = encode_batch(batch)?;
        let frame = encode_wal_frame(WAL_OP_APPLY_BATCH, batch.new_anchor.commit_sequence, &body)?;
        Ok(Self { frame })
    }
}

/// Encodes one CRC32C-framed binary WAL record.
pub(crate) fn encode_wal_frame(
    op_tag: u16,
    seq: u64,
    body: &[u8],
) -> Result<Vec<u8>, ProjectionError> {
    if body.len() > MAX_WAL_FRAME_BODY_BYTES {
        return Err(ProjectionError::InvalidRequest(
            "WAL frame body exceeds maximum bound",
        ));
    }
    let body_len = u32::try_from(body.len())
        .map_err(|_| ProjectionError::ArithmeticOverflow("wal_body_len"))?;
    let total = WAL_FRAME_HEADER_LEN
        .checked_add(body.len())
        .and_then(|v| v.checked_add(WAL_FRAME_TRAILER_LEN))
        .ok_or(ProjectionError::ArithmeticOverflow("wal_frame_len"))?;
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(&WAL_FRAME_MAGIC);
    frame.extend_from_slice(&WAL_FORMAT_VERSION.to_be_bytes());
    frame.extend_from_slice(&op_tag.to_be_bytes());
    frame.extend_from_slice(&seq.to_be_bytes());
    frame.extend_from_slice(&body_len.to_be_bytes());
    frame.extend_from_slice(body);
    let checksum = crc32c(&frame);
    frame.extend_from_slice(&checksum.to_be_bytes());
    Ok(frame)
}

/// Reads and strictly verifies every frame in `mvcc.wal`.
///
/// Any truncated frame, bad magic, version mismatch, CRC32C mismatch, or codec error returns
/// [`ProjectionError::CorruptDerivedStore`] so `open_or_rebuild` can quarantine and rebuild.
pub(crate) fn visit_verified_wal(
    path: &Path,
    visit: impl FnMut(WalRecord) -> Result<(), ProjectionError>,
) -> Result<(), ProjectionError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(ProjectionError::io(ProjectionIoOperation::Open, err)),
    };
    let file_len = file
        .metadata()
        .map_err(|err| ProjectionError::io(ProjectionIoOperation::Metadata, err))?
        .len();
    if let Some(offset) = visit_wal_frames(&file, file_len, visit)? {
        return Err(ProjectionError::CorruptDerivedStore {
            artifact: WAL_FILENAME,
            detail: format!("truncated WAL frame at byte offset {offset}"),
        });
    }
    Ok(())
}

/// Visits complete frames within the observed length. A live writer can leave an incomplete
/// final frame. The caller decides whether that prefix is inspectable or requires recovery.
fn visit_wal_frames(
    file: &File,
    file_len: u64,
    mut visit: impl FnMut(WalRecord) -> Result<(), ProjectionError>,
) -> Result<Option<u64>, ProjectionError> {
    let mut reader = BufReader::new(file.take(file_len));
    let mut frame = Vec::new();
    let mut offset = 0_u64;
    let read_error = |err| ProjectionError::io(ProjectionIoOperation::Read, err);
    while offset < file_len {
        frame.clear();
        reader
            .by_ref()
            .take(WAL_FRAME_HEADER_LEN as u64)
            .read_to_end(&mut frame)
            .map_err(read_error)?;
        let remaining = file_len - offset;
        if frame.len() < WAL_FRAME_HEADER_LEN
            || remaining < (WAL_FRAME_HEADER_LEN + WAL_FRAME_TRAILER_LEN) as u64
        {
            let prefix = frame.len().min(WAL_FRAME_MAGIC.len());
            if frame[..prefix] != WAL_FRAME_MAGIC[..prefix] {
                return Err(ProjectionError::CorruptDerivedStore {
                    artifact: WAL_FILENAME,
                    detail: format!("invalid WAL frame magic at byte offset {offset}"),
                });
            }
            return Ok(Some(offset));
        }
        let hdr = &frame[..];
        if hdr[0..4] != WAL_FRAME_MAGIC {
            return Err(ProjectionError::CorruptDerivedStore {
                artifact: WAL_FILENAME,
                detail: format!("invalid WAL frame magic at byte offset {offset}"),
            });
        }
        let version = u16::from_be_bytes([hdr[4], hdr[5]]);
        if version != WAL_FORMAT_VERSION {
            return Err(ProjectionError::CorruptDerivedStore {
                artifact: WAL_FILENAME,
                detail: format!("unsupported WAL version {version} at byte offset {offset}"),
            });
        }
        let op_tag = u16::from_be_bytes([hdr[6], hdr[7]]);
        let seq = u64::from_be_bytes([
            hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
        ]);
        let body_len = u32::from_be_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]) as usize;
        if body_len > MAX_WAL_FRAME_BODY_BYTES {
            return Err(ProjectionError::CorruptDerivedStore {
                artifact: WAL_FILENAME,
                detail: format!("WAL frame body_len {body_len} exceeds max at offset {offset}"),
            });
        }
        let frame_len = WAL_FRAME_HEADER_LEN
            .checked_add(body_len)
            .and_then(|v| v.checked_add(WAL_FRAME_TRAILER_LEN))
            .ok_or(ProjectionError::ArithmeticOverflow("wal_frame_len"))?;
        if frame_len as u64 > remaining {
            return Ok(Some(offset));
        }
        reader
            .by_ref()
            .take((body_len + WAL_FRAME_TRAILER_LEN) as u64)
            .read_to_end(&mut frame)
            .map_err(read_error)?;
        if frame.len() != frame_len {
            return Ok(Some(offset));
        }
        let crc_pos = frame_len - WAL_FRAME_TRAILER_LEN;
        let stored_crc = u32::from_be_bytes([
            frame[crc_pos],
            frame[crc_pos + 1],
            frame[crc_pos + 2],
            frame[crc_pos + 3],
        ]);
        if crc32c(&frame[..crc_pos]) != stored_crc {
            return Err(ProjectionError::CorruptDerivedStore {
                artifact: WAL_FILENAME,
                detail: format!("WAL CRC32C checksum mismatch at byte offset {offset}"),
            });
        }
        let body = &frame[WAL_FRAME_HEADER_LEN..crc_pos];
        match op_tag {
            WAL_OP_APPLY_BATCH => {
                let batch =
                    decode_batch(body).map_err(|err| ProjectionError::CorruptDerivedStore {
                        artifact: WAL_FILENAME,
                        detail: format!("WAL batch decode failed at offset {offset}: {err}"),
                    })?;
                if batch.new_anchor.commit_sequence != seq {
                    return Err(ProjectionError::CorruptDerivedStore {
                        artifact: WAL_FILENAME,
                        detail: format!(
                            "WAL sequence mismatch at offset {offset}: frame={seq}, batch={}",
                            batch.new_anchor.commit_sequence
                        ),
                    });
                }
                visit(WalRecord::ApplyBatch {
                    commit_sequence: seq,
                    batch,
                })?;
            }
            WAL_OP_SCRUB_RECEIPT => {
                let receipt = DoctorScrubReceipt::from_canonical_bytes(body).map_err(|err| {
                    ProjectionError::CorruptDerivedStore {
                        artifact: WAL_FILENAME,
                        detail: format!(
                            "WAL scrub receipt decode failed at offset {offset}: {err}"
                        ),
                    }
                })?;
                if receipt.anchor.commit_sequence != seq {
                    return Err(ProjectionError::CorruptDerivedStore {
                        artifact: WAL_FILENAME,
                        detail: format!("WAL scrub receipt sequence mismatch at offset {offset}"),
                    });
                }
                visit(WalRecord::RecordScrubReceipt {
                    commit_sequence: seq,
                    receipt,
                })?;
            }
            other => {
                return Err(ProjectionError::CorruptDerivedStore {
                    artifact: WAL_FILENAME,
                    detail: format!("unknown WAL op tag {other} at byte offset {offset}"),
                });
            }
        }
        offset += frame_len as u64;
    }
    Ok(None)
}

/// Strictly read-only inspection summary of `mvcc.wal` produced without acquiring locks or
/// modifying any file on disk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalInspectionSummary {
    /// Number of verified `ApplyBatch` frames observed in `mvcc.wal`.
    pub batch_frames: u64,
    /// Number of verified `RecordScrubReceipt` frames observed in `mvcc.wal`.
    pub scrub_receipt_frames: u64,
    /// Highest commit sequence observed across verified WAL batch frames (`0` if none).
    pub max_commit_sequence: u64,
    /// Latest verified [`DoctorScrubReceipt`] recorded in `mvcc.wal`, if any.
    pub latest_scrub_receipt: Option<DoctorScrubReceipt>,
    /// True when the file ended mid-frame (e.g., an active live writer was appending concurrently).
    pub incomplete_tail: bool,
}

/// Reads and verifies `mvcc.wal` strictly read-only up to `max_bytes`, returning a bounded summary
/// without acquiring locks or mutating any files.
pub fn inspect_wal_readonly(
    path: &Path,
    max_bytes: u64,
) -> Result<WalInspectionSummary, ProjectionError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(WalInspectionSummary {
                batch_frames: 0,
                scrub_receipt_frames: 0,
                max_commit_sequence: 0,
                latest_scrub_receipt: None,
                incomplete_tail: false,
            });
        }
        Err(err) => return Err(ProjectionError::io(ProjectionIoOperation::Metadata, err)),
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(ProjectionError::CorruptDerivedStore {
            artifact: WAL_FILENAME,
            detail: "mvcc.wal is not a regular non-symlink file".to_owned(),
        });
    }
    if meta.len() > max_bytes {
        return Err(ProjectionError::CorruptDerivedStore {
            artifact: WAL_FILENAME,
            detail: format!(
                "mvcc.wal size {} exceeds read-only inspection bound {max_bytes}",
                meta.len()
            ),
        });
    }
    let file =
        File::open(path).map_err(|err| ProjectionError::io(ProjectionIoOperation::Open, err))?;
    let opened_meta = file
        .metadata()
        .map_err(|err| ProjectionError::io(ProjectionIoOperation::Metadata, err))?;
    if !opened_meta.file_type().is_file() {
        return Err(ProjectionError::CorruptDerivedStore {
            artifact: WAL_FILENAME,
            detail: "mvcc.wal is not a regular non-symlink file".to_owned(),
        });
    }
    if opened_meta.len() > max_bytes {
        return Err(ProjectionError::CorruptDerivedStore {
            artifact: WAL_FILENAME,
            detail: format!("mvcc.wal exceeded read-only inspection bound {max_bytes}"),
        });
    }
    let mut summary = WalInspectionSummary {
        batch_frames: 0,
        scrub_receipt_frames: 0,
        max_commit_sequence: 0,
        latest_scrub_receipt: None,
        incomplete_tail: false,
    };
    let incomplete = visit_wal_frames(&file, opened_meta.len(), |record| {
        match record {
            WalRecord::ApplyBatch {
                commit_sequence, ..
            } => {
                summary.batch_frames = summary.batch_frames.saturating_add(1);
                summary.max_commit_sequence = summary.max_commit_sequence.max(commit_sequence);
            }
            WalRecord::RecordScrubReceipt { receipt, .. } => {
                summary.scrub_receipt_frames = summary.scrub_receipt_frames.saturating_add(1);
                summary.latest_scrub_receipt = Some(receipt);
            }
        }
        Ok(())
    })?;
    summary.incomplete_tail = incomplete.is_some();
    Ok(summary)
}

/// Atomically writes a verified `mvcc.snap` snapshot via temp file + sync + rename + dir sync.
pub(crate) fn write_snapshot_atomic(
    dir: &Path,
    snapshot: &ProjectionSnapshot,
    durability: DurabilityMode,
) -> Result<usize, ProjectionError> {
    fs::create_dir_all(dir)
        .map_err(|err| ProjectionError::io(ProjectionIoOperation::CreateDir, err))?;
    let bytes = snapshot.encode_snapshot_bytes()?;
    let tmp_path = dir.join(".mvcc.snap.tmp");
    let final_path = dir.join(SNAPSHOT_FILENAME);
    {
        let mut tmp = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|err| ProjectionError::io(ProjectionIoOperation::Open, err))?;
        tmp.write_all(&bytes)
            .map_err(|err| ProjectionError::io(ProjectionIoOperation::Write, err))?;
        sync_file_mode(&tmp, durability)?;
    }
    fs::rename(&tmp_path, &final_path)
        .map_err(|err| ProjectionError::io(ProjectionIoOperation::Rename, err))?;
    sync_directory(dir)?;
    Ok(bytes.len())
}

/// Reads and verifies `mvcc.snap` if present; returns `Ok(None)` when missing.
pub(crate) fn load_snapshot_if_present(
    dir: &Path,
) -> Result<Option<ProjectionSnapshot>, ProjectionError> {
    let path = dir.join(SNAPSHOT_FILENAME);
    if !path.exists() {
        return Ok(None);
    }
    let mut file =
        File::open(&path).map_err(|err| ProjectionError::io(ProjectionIoOperation::Open, err))?;
    let len = file
        .metadata()
        .map_err(|err| ProjectionError::io(ProjectionIoOperation::Metadata, err))?
        .len();
    if len > MAX_PROJECTION_SNAPSHOT_BYTES {
        return Err(ProjectionError::CorruptDerivedStore {
            artifact: SNAPSHOT_FILENAME,
            detail: format!(
                "snapshot length {len} exceeds maximum {MAX_PROJECTION_SNAPSHOT_BYTES}"
            ),
        });
    }
    let mut raw = Vec::with_capacity(len as usize);
    file.read_to_end(&mut raw)
        .map_err(|err| ProjectionError::io(ProjectionIoOperation::Read, err))?;
    ProjectionSnapshot::decode_snapshot_bytes(&raw).map(Some)
}

/// Moves any existing derived `mvcc.snap` and `mvcc.wal` into `<dir>/quarantine/` for forensic
/// retention before rebuilding from canonical ledger history.
pub(crate) fn quarantine_derived_files(dir: &Path) -> Result<Vec<PathBuf>, ProjectionError> {
    let quarantine_dir = dir.join(QUARANTINE_DIRNAME);
    let mut moved = Vec::new();
    for filename in [SNAPSHOT_FILENAME, WAL_FILENAME] {
        let src = dir.join(filename);
        if !src.exists() {
            continue;
        }
        fs::create_dir_all(&quarantine_dir)
            .map_err(|err| ProjectionError::io(ProjectionIoOperation::CreateDir, err))?;
        let dst = next_quarantine_path(&quarantine_dir, filename)?;
        fs::rename(&src, &dst)
            .map_err(|err| ProjectionError::io(ProjectionIoOperation::Rename, err))?;
        moved.push(dst);
    }
    if !moved.is_empty() {
        sync_directory(&quarantine_dir)?;
        sync_directory(dir)?;
    }
    Ok(moved)
}

fn next_quarantine_path(quarantine_dir: &Path, filename: &str) -> Result<PathBuf, ProjectionError> {
    for attempt in 1_u64..=10_000 {
        let candidate = quarantine_dir.join(format!("{filename}.corrupt-{attempt:04}"));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(ProjectionError::InvalidRequest(
        "quarantine directory exhausted attempt slots",
    ))
}

pub(crate) fn sync_file_mode(file: &File, mode: DurabilityMode) -> Result<(), ProjectionError> {
    let res = match mode {
        DurabilityMode::Fsync => file.sync_data(),
        DurabilityMode::FullSync => file.sync_all(),
    };
    res.map_err(|err| ProjectionError::io(ProjectionIoOperation::SyncFile, err))
}

pub(crate) fn sync_directory(dir: &Path) -> Result<(), ProjectionError> {
    #[cfg(unix)]
    {
        let handle =
            File::open(dir).map_err(|err| ProjectionError::io(ProjectionIoOperation::Open, err))?;
        handle
            .sync_all()
            .map_err(|err| ProjectionError::io(ProjectionIoOperation::SyncDir, err))?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "fss-wal-inspect-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn wal_visitors_verify_each_frame_before_reporting_it() {
        use crate::schema::{ProjectionAnchor, ScrubVerdict};
        use fss_core::{ContentDigest, TimestampNs};

        let dir = unique_temp_dir("frame-visitor");
        let path = dir.join(WAL_FILENAME);
        let digest = ContentDigest::sha256(b"recording history");
        let receipt = DoctorScrubReceipt {
            scrubbed_at_ns: TimestampNs(10),
            anchor: ProjectionAnchor {
                commit_sequence: 7,
                authority_root: digest,
                history_root: digest,
                high_water_digest: digest,
            },
            first_seq: 1,
            last_seq: 7,
            verified_objects: 2,
            verified_packs: 1,
            verified_fraction_ppm: 1_000_000,
            verdict: ScrubVerdict::Clean,
        };
        let body = receipt.try_canonical_bytes().expect("encode receipt");
        let valid = encode_wal_frame(WAL_OP_SCRUB_RECEIPT, 7, &body).expect("encode frame");
        let wrong_seq = encode_wal_frame(WAL_OP_SCRUB_RECEIPT, 8, &body).expect("encode frame");
        fs::write(&path, [valid.as_slice(), &wrong_seq].concat()).expect("write WAL");
        let mut delivered = 0;
        let result = visit_verified_wal(&path, |_| {
            delivered += 1;
            Ok(())
        });
        assert!(matches!(
            result,
            Err(ProjectionError::CorruptDerivedStore { .. })
        ));
        assert_eq!(delivered, 1);
        assert!(matches!(
            inspect_wal_readonly(&path, u64::MAX),
            Err(ProjectionError::CorruptDerivedStore { .. })
        ));

        fs::write(&path, [valid.as_slice(), b"FM"].concat()).expect("write torn WAL");
        let observed = inspect_wal_readonly(&path, u64::MAX).expect("inspect complete prefix");
        assert_eq!(observed.latest_scrub_receipt, Some(receipt));
        assert_eq!(observed.scrub_receipt_frames, 1);
        assert!(observed.incomplete_tail);
        assert!(matches!(
            visit_verified_wal(&path, |_| Ok(())),
            Err(ProjectionError::CorruptDerivedStore { .. })
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn inspect_wal_readonly_handles_missing_incomplete_corrupt_oversize_and_symlink() {
        let dir = unique_temp_dir("cases");
        let missing = dir.join("missing.wal");
        let empty = inspect_wal_readonly(&missing, 4096).expect("missing wal");
        assert_eq!(
            empty,
            WalInspectionSummary {
                batch_frames: 0,
                scrub_receipt_frames: 0,
                max_commit_sequence: 0,
                latest_scrub_receipt: None,
                incomplete_tail: false,
            }
        );

        // Partial FMVW header prefix -> incomplete_tail = true.
        let partial = dir.join("partial.wal");
        fs::write(&partial, b"FMVW\x00\x01").expect("write partial");
        let partial_summary = inspect_wal_readonly(&partial, 4096).expect("partial wal");
        assert!(partial_summary.incomplete_tail);
        assert_eq!(partial_summary.batch_frames, 0);

        // Short garbage that does not even match FMVW magic -> CorruptDerivedStore.
        let garbage = dir.join("garbage.wal");
        fs::write(&garbage, b"NOPE").expect("write garbage");
        assert!(matches!(
            inspect_wal_readonly(&garbage, 4096),
            Err(ProjectionError::CorruptDerivedStore { .. })
        ));

        // Corrupt CRC32C frame -> CorruptDerivedStore.
        let mut frame = encode_wal_frame(WAL_OP_APPLY_BATCH, 1, b"bad").expect("encode frame");
        let last = frame.len() - 1;
        frame[last] ^= 0xFF;
        let bad_crc = dir.join("bad_crc.wal");
        fs::write(&bad_crc, &frame).expect("write bad crc");
        assert!(matches!(
            inspect_wal_readonly(&bad_crc, 4096),
            Err(ProjectionError::CorruptDerivedStore { .. })
        ));

        // Oversize file exceeds max_bytes -> CorruptDerivedStore.
        assert!(matches!(
            inspect_wal_readonly(&bad_crc, 4),
            Err(ProjectionError::CorruptDerivedStore { .. })
        ));

        // Symlinked WAL -> refused fail-closed.
        #[cfg(unix)]
        {
            let link = dir.join("link.wal");
            std::os::unix::fs::symlink(&partial, &link).expect("symlink");
            assert!(matches!(
                inspect_wal_readonly(&link, 4096),
                Err(ProjectionError::CorruptDerivedStore { .. })
            ));
        }

        let _ = fs::remove_dir_all(&dir);
    }
}
