//! Non-mutating journal recovery and verification.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use fss_core::{ContentDigest, DigestAlgorithm, sha256};

use crate::error::{CorruptionKind, JournalError};
use crate::format::{
    COMMIT_MAGIC, FORMAT_VERSION, HEADER_LEN, RECORD_MAGIC, TRAILER_LEN, read_u16, read_u32,
    read_u64, record_root,
};
use crate::MAX_RECORD_PAYLOAD_BYTES;

/// One committed journal record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalRecord {
    pub(crate) sequence: u64,
    pub(crate) kind: u16,
    pub(crate) payload: Vec<u8>,
    pub(crate) payload_digest: ContentDigest,
    pub(crate) root: ContentDigest,
}

impl JournalRecord {
    /// Monotone committed sequence, starting at one.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Application-defined bounded record kind.
    #[must_use]
    pub const fn kind(&self) -> u16 {
        self.kind
    }

    /// Exact committed payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// SHA-256 of the exact committed payload.
    #[must_use]
    pub const fn payload_digest(&self) -> ContentDigest {
        self.payload_digest
    }

    /// Root chaining this record to every prior committed record.
    #[must_use]
    pub const fn root(&self) -> ContentDigest {
        self.root
    }
}

/// Non-mutating recovery result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryReport {
    pub(crate) records: Vec<JournalRecord>,
    pub(crate) committed_len: u64,
    pub(crate) incomplete_tail: Option<u64>,
    pub(crate) last_root: ContentDigest,
}

impl RecoveryReport {
    /// Fully committed records in sequence order.
    #[must_use]
    pub fn records(&self) -> &[JournalRecord] {
        &self.records
    }

    /// Byte length through the last complete commit trailer.
    #[must_use]
    pub const fn committed_len(&self) -> u64 {
        self.committed_len
    }

    /// First byte of an incomplete suffix, if present.
    #[must_use]
    pub const fn incomplete_tail(&self) -> Option<u64> {
        self.incomplete_tail
    }

    /// Root of the last committed record, or zero for an empty journal.
    #[must_use]
    pub const fn last_root(&self) -> ContentDigest {
        self.last_root
    }
}

/// Inspects a journal without modifying it.
///
/// A torn final record is returned as `incomplete_tail`; fully present corruption is an error.
pub fn inspect(path: impl AsRef<Path>) -> Result<RecoveryReport, JournalError> {
    let mut file = OpenOptions::new().read(true).open(path)?;
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    recover_bytes(&bytes)
}

pub(crate) fn recover_bytes(bytes: &[u8]) -> Result<RecoveryReport, JournalError> {
    let mut offset = 0_usize;
    let mut expected_sequence = 1_u64;
    let mut previous_root = [0_u8; 32];
    let mut records = Vec::new();

    while offset < bytes.len() {
        let start = offset;
        if bytes.len() - offset < HEADER_LEN {
            return Ok(report(records, start, Some(start), previous_root));
        }
        if bytes[offset..offset + 8] != RECORD_MAGIC {
            return Err(corrupt(start, CorruptionKind::RecordMagic));
        }
        offset += 8;
        if read_u16(bytes, &mut offset) != FORMAT_VERSION {
            return Err(corrupt(start, CorruptionKind::FormatVersion));
        }
        let sequence = read_u64(bytes, &mut offset);
        if sequence != expected_sequence {
            return Err(corrupt(start, CorruptionKind::Sequence));
        }
        let kind = read_u16(bytes, &mut offset);
        let payload_len = read_u32(bytes, &mut offset);
        let payload_len_usize =
            usize::try_from(payload_len).map_err(|_| corrupt(start, CorruptionKind::PayloadLength))?;
        if payload_len_usize > MAX_RECORD_PAYLOAD_BYTES {
            return Err(corrupt(start, CorruptionKind::PayloadLength));
        }

        let mut named_previous = [0_u8; 32];
        named_previous.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;
        if named_previous != previous_root {
            return Err(corrupt(start, CorruptionKind::PreviousRoot));
        }
        let mut named_payload_digest = [0_u8; 32];
        named_payload_digest.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        if bytes.len() - offset < payload_len_usize.saturating_add(TRAILER_LEN) {
            return Ok(report(records, start, Some(start), previous_root));
        }
        let payload = &bytes[offset..offset + payload_len_usize];
        offset += payload_len_usize;
        if sha256(payload) != named_payload_digest {
            return Err(corrupt(start, CorruptionKind::PayloadDigest));
        }
        if bytes[offset..offset + 8] != COMMIT_MAGIC {
            return Err(corrupt(start, CorruptionKind::CommitMagic));
        }
        offset += 8;
        let mut committed_root = [0_u8; 32];
        committed_root.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;
        let expected_root = record_root(
            sequence,
            kind,
            payload_len,
            previous_root,
            named_payload_digest,
        );
        if committed_root != expected_root {
            return Err(corrupt(start, CorruptionKind::CommitRoot));
        }

        records.push(JournalRecord {
            sequence,
            kind,
            payload: payload.to_vec(),
            payload_digest: ContentDigest::new(DigestAlgorithm::Sha256, named_payload_digest),
            root: ContentDigest::new(DigestAlgorithm::Sha256, committed_root),
        });
        previous_root = committed_root;
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceExhausted)?;
    }

    Ok(report(records, offset, None, previous_root))
}

fn report(
    records: Vec<JournalRecord>,
    committed_len: usize,
    incomplete_tail: Option<usize>,
    last_root: [u8; 32],
) -> RecoveryReport {
    RecoveryReport {
        records,
        committed_len: committed_len as u64,
        incomplete_tail: incomplete_tail.map(|value| value as u64),
        last_root: ContentDigest::new(DigestAlgorithm::Sha256, last_root),
    }
}

fn corrupt(offset: usize, kind: CorruptionKind) -> JournalError {
    JournalError::Corrupt {
        offset: offset as u64,
        kind,
    }
}
