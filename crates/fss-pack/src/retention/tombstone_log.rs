#![forbid(unsafe_code)]
//! Durable append-only CRC32C-framed object deletion tombstone log (`object-tombstones.fssr`).
//!
//! Enforces the deletion ordering invariant: physical compaction and packfile unlink refuse to
//! reclaim any object unless its deletion tombstone is durably fsynced here first. Once committed,
//! subsequent verified reads of the tombstoned digest return [`PackError::EvidenceDeleted`]
//! (`ERR-EVIDENCE-DELETED-001`) rather than conflating deleted evidence with never-existed objects.
//!
//! # Record Layout (`FSTD` v1, 76 bytes fixed)
//!
//! ```text
//! [magic(4) = b"FSTD" | version(u16=1) | flags(u16=0)
//!  | deleted_sha256(32) | reason_sha256(32) | crc32c(4)]
//! ```

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::path::Path;

use fss_core::{ContentDigest, DigestAlgorithm};

use crate::crc32c::crc32c;
use crate::error::{PackError, PackIoOperation};
use crate::format::{DurabilityMode, read_exact_at_bounded, write_all_bounded};

/// Magic bytes for each fixed-size object tombstone frame.
pub const OBJECT_TOMBSTONE_MAGIC: [u8; 4] = *b"FSTD";
/// Supported binary format version for the object tombstone log.
pub const OBJECT_TOMBSTONE_VERSION: u16 = 1;
/// Fixed byte length of one object tombstone record (`4 + 2 + 2 + 32 + 32 + 4 = 76`).
pub const OBJECT_TOMBSTONE_RECORD_LEN: usize = 76;

/// Append-only durable object deletion tombstone log.
#[derive(Debug)]
pub struct ObjectTombstoneLog {
    file: File,
    durability: DurabilityMode,
    offset: u64,
    entries: HashMap<[u8; 32], ContentDigest>,
}

impl ObjectTombstoneLog {
    /// Opens or creates `path`, replaying all CRC32C-verified tombstones.
    ///
    /// An incomplete trailing record is an interrupted append and is truncated. A complete
    /// record with invalid framing, version, flags, or checksum fails closed without changing
    /// the log: silently dropping it could make previously deleted evidence readable again.
    /// Read failures also propagate without truncating deletion history.
    pub fn open(path: &Path, durability: DurabilityMode) -> Result<Self, PackError> {
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .map_err(|err| PackError::io(PackIoOperation::Open, err))?;
        let file_len = file
            .metadata()
            .map_err(|err| PackError::io(PackIoOperation::Metadata, err))?
            .len();

        let mut entries = HashMap::new();
        let mut offset = 0_u64;
        let mut record = [0_u8; OBJECT_TOMBSTONE_RECORD_LEN];

        while offset < file_len {
            let remaining = file_len - offset;
            if remaining < OBJECT_TOMBSTONE_RECORD_LEN as u64 {
                break;
            }
            read_exact_at_bounded(&file, offset, &mut record)?;
            if record[0..4] != OBJECT_TOMBSTONE_MAGIC {
                return Err(PackError::CorruptCatalog {
                    detail: format!("invalid object tombstone magic at offset {offset}"),
                });
            }
            let version = u16::from_be_bytes([record[4], record[5]]);
            if version != OBJECT_TOMBSTONE_VERSION {
                return Err(PackError::CorruptCatalog {
                    detail: format!(
                        "unsupported object tombstone version {version} at offset {offset}"
                    ),
                });
            }
            let flags = u16::from_be_bytes([record[6], record[7]]);
            if flags != 0 {
                return Err(PackError::CorruptCatalog {
                    detail: format!(
                        "unsupported object tombstone flags {flags} at offset {offset}"
                    ),
                });
            }
            let stored_crc = u32::from_be_bytes([record[72], record[73], record[74], record[75]]);
            if crc32c(&record[..72]) != stored_crc {
                return Err(PackError::CorruptCatalog {
                    detail: format!("object tombstone checksum mismatch at offset {offset}"),
                });
            }
            let mut deleted_sha = [0_u8; 32];
            deleted_sha.copy_from_slice(&record[8..40]);
            let mut reason_sha = [0_u8; 32];
            reason_sha.copy_from_slice(&record[40..72]);
            entries
                .entry(deleted_sha)
                .or_insert_with(|| ContentDigest::new(DigestAlgorithm::Sha256, reason_sha));
            offset = offset
                .checked_add(OBJECT_TOMBSTONE_RECORD_LEN as u64)
                .ok_or(PackError::ArithmeticOverflow)?;
        }

        if file_len > offset {
            file.set_len(offset)
                .map_err(|err| PackError::io(PackIoOperation::Truncate, err))?;
            durability.sync_file(&file)?;
        }
        file.seek(SeekFrom::Start(offset))
            .map_err(|err| PackError::io(PackIoOperation::Write, err))?;

        Ok(Self {
            file,
            durability,
            offset,
            entries,
        })
    }

    /// Returns the committed tombstone reason digest if `digest` was deleted.
    #[must_use]
    pub fn get(&self, digest: &ContentDigest) -> Option<ContentDigest> {
        if digest.algorithm() != DigestAlgorithm::Sha256 {
            return None;
        }
        self.entries.get(&digest.bytes()).copied()
    }

    /// Returns the committed tombstone reason digest for a raw 32-byte SHA-256 digest.
    #[must_use]
    pub fn get_sha256(&self, sha256_bytes: &[u8; 32]) -> Option<ContentDigest> {
        self.entries.get(sha256_bytes).copied()
    }

    /// Returns true if `sha256_bytes` has a durably committed deletion tombstone.
    #[must_use]
    pub fn contains_sha256(&self, sha256_bytes: &[u8; 32]) -> bool {
        self.entries.contains_key(sha256_bytes)
    }

    /// Returns a cloned snapshot map of all committed tombstoned object digests.
    #[must_use]
    pub fn snapshot_map(&self) -> HashMap<[u8; 32], ContentDigest> {
        self.entries.clone()
    }

    /// Returns the total number of distinct tombstoned object digests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if no objects have been tombstoned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Durably appends and fsyncs a batch of `(deleted_digest, reason_digest)` deletion tombstones.
    ///
    /// Already-tombstoned digests are treated idempotently without duplicate disk writes.
    pub fn append_batch(
        &mut self,
        items: &[(ContentDigest, ContentDigest)],
    ) -> Result<usize, PackError> {
        let mut to_write: Vec<([u8; 32], [u8; 32])> = Vec::new();
        for &(deleted, reason) in items {
            if deleted.algorithm() != DigestAlgorithm::Sha256 {
                return Err(PackError::UnsupportedDigestAlgorithm(deleted.algorithm()));
            }
            if reason.algorithm() != DigestAlgorithm::Sha256 {
                return Err(PackError::UnsupportedDigestAlgorithm(reason.algorithm()));
            }
            let del_bytes = deleted.bytes();
            if self.entries.contains_key(&del_bytes) {
                continue;
            }
            if !to_write.iter().any(|(d, _)| *d == del_bytes) {
                to_write.push((del_bytes, reason.bytes()));
            }
        }
        if to_write.is_empty() {
            return Ok(0);
        }

        let mut buf = Vec::with_capacity(to_write.len() * OBJECT_TOMBSTONE_RECORD_LEN);
        for &(del_bytes, reason_bytes) in &to_write {
            let mut rec = [0_u8; OBJECT_TOMBSTONE_RECORD_LEN];
            rec[0..4].copy_from_slice(&OBJECT_TOMBSTONE_MAGIC);
            rec[4..6].copy_from_slice(&OBJECT_TOMBSTONE_VERSION.to_be_bytes());
            rec[6..8].copy_from_slice(&0_u16.to_be_bytes());
            rec[8..40].copy_from_slice(&del_bytes);
            rec[40..72].copy_from_slice(&reason_bytes);
            let crc = crc32c(&rec[..72]);
            rec[72..76].copy_from_slice(&crc.to_be_bytes());
            buf.extend_from_slice(&rec);
        }

        let rollback_offset = self.offset;
        let write_res = (|| -> Result<(), PackError> {
            write_all_bounded(&mut self.file, &buf)?;
            self.durability.sync_file(&self.file)?;
            Ok(())
        })();
        if let Err(err) = write_res {
            let _ = self.file.set_len(rollback_offset);
            let _ = self.file.seek(SeekFrom::Start(rollback_offset));
            return Err(err);
        }

        self.offset = self
            .offset
            .checked_add(buf.len() as u64)
            .ok_or(PackError::ArithmeticOverflow)?;
        let written = to_write.len();
        for (del_bytes, reason_bytes) in to_write {
            self.entries.insert(
                del_bytes,
                ContentDigest::new(DigestAlgorithm::Sha256, reason_bytes),
            );
        }
        Ok(written)
    }
}
