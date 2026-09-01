//! Writable two-phase journal publication.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, DigestAlgorithm, sha256};

use crate::error::{CorruptionKind, JournalError};
use crate::format::{COMMIT_MAGIC, FORMAT_VERSION, HEADER_LEN, RECORD_MAGIC, record_root};
use crate::recovery::{JournalRecord, RecoveryReport, recover_bytes};
use crate::MAX_RECORD_PAYLOAD_BYTES;

/// Explicit policy for a validated incomplete final record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncompleteTailPolicy {
    /// Refuse to open a journal that ends with an incomplete record.
    Reject,
    /// Truncate exactly the incomplete suffix after validating every committed record.
    Truncate,
}

/// Writable crash-classifying reference journal.
#[derive(Debug)]
pub struct Journal {
    path: PathBuf,
    file: File,
    next_sequence: u64,
    last_root: [u8; 32],
}

impl Journal {
    /// Opens or creates a journal after verifying its complete prefix.
    ///
    /// `Truncate` removes only a suffix already classified as incomplete. Corruption is
    /// never repaired or skipped. All validation that can fail happens before truncation.
    pub fn open(
        path: impl AsRef<Path>,
        tail_policy: IncompleteTailPolicy,
    ) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)?;
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let recovery = recover_bytes(&bytes)?;
        let next_sequence = recovery.records.last().map_or(Ok(1_u64), |record| {
            record
                .sequence
                .checked_add(1)
                .ok_or(JournalError::SequenceExhausted)
        })?;
        if let Some(offset) = recovery.incomplete_tail {
            match tail_policy {
                IncompleteTailPolicy::Reject => {
                    return Err(JournalError::IncompleteTail { offset });
                }
                IncompleteTailPolicy::Truncate => {
                    file.set_len(recovery.committed_len)?;
                    file.sync_all()?;
                }
            }
        }
        file.seek(SeekFrom::End(0))?;
        Ok(Self {
            path,
            file,
            next_sequence,
            last_root: recovery.last_root.bytes(),
        })
    }

    /// Path backing this journal.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Root of the latest committed record.
    #[must_use]
    pub const fn last_root(&self) -> ContentDigest {
        ContentDigest::new(DigestAlgorithm::Sha256, self.last_root)
    }

    /// Appends and durably commits one record.
    ///
    /// Every fallible semantic check and payload allocation happens before I/O. The record body
    /// is synchronized before the commit trailer. In-memory sequence/root advances only after
    /// the trailer has itself been synchronized, and nothing fallible remains after that point.
    pub fn append(&mut self, kind: u16, payload: &[u8]) -> Result<JournalRecord, JournalError> {
        if payload.len() > MAX_RECORD_PAYLOAD_BYTES {
            return Err(JournalError::PayloadTooLarge {
                length: payload.len(),
                maximum: MAX_RECORD_PAYLOAD_BYTES,
            });
        }
        let sequence = self.next_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceExhausted)?;
        let payload_copy = payload.to_vec();
        let payload_len =
            u32::try_from(payload.len()).map_err(|_| JournalError::PayloadTooLarge {
                length: payload.len(),
                maximum: MAX_RECORD_PAYLOAD_BYTES,
            })?;
        let payload_digest = sha256(payload);
        let root = record_root(sequence, kind, payload_len, self.last_root, payload_digest);

        let mut body = Vec::with_capacity(HEADER_LEN + payload.len());
        body.extend_from_slice(&RECORD_MAGIC);
        body.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        body.extend_from_slice(&sequence.to_be_bytes());
        body.extend_from_slice(&kind.to_be_bytes());
        body.extend_from_slice(&payload_len.to_be_bytes());
        body.extend_from_slice(&self.last_root);
        body.extend_from_slice(&payload_digest);
        body.extend_from_slice(payload);
        self.file.write_all(&body)?;
        self.file.sync_data()?;

        self.file.write_all(&COMMIT_MAGIC)?;
        self.file.write_all(&root)?;
        self.file.sync_all()?;

        self.next_sequence = next_sequence;
        self.last_root = root;
        Ok(JournalRecord {
            sequence,
            kind,
            payload: payload_copy,
            payload_digest: ContentDigest::new(DigestAlgorithm::Sha256, payload_digest),
            root: ContentDigest::new(DigestAlgorithm::Sha256, root),
        })
    }

    /// Re-reads durable bytes and proves they match this handle's last root.
    pub fn verify(&mut self) -> Result<RecoveryReport, JournalError> {
        self.file.sync_all()?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        self.file.read_to_end(&mut bytes)?;
        let report = recover_bytes(&bytes)?;
        if let Some(offset) = report.incomplete_tail {
            return Err(JournalError::IncompleteTail { offset });
        }
        if report.last_root.bytes() != self.last_root {
            return Err(JournalError::Corrupt {
                offset: report.committed_len,
                kind: CorruptionKind::CommitRoot,
            });
        }
        self.file.seek(SeekFrom::End(0))?;
        Ok(report)
    }
}
