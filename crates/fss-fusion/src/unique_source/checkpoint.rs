#![forbid(unsafe_code)]
//! Canonical bounded continuation of the declared-source-once accumulator.
//!
//! Version 1 is an eight-byte magic, big-endian `u32` version, big-endian `u64` payload length,
//! a handwritten canonical payload, then a 32-byte SHA-256 checksum of the header and payload.
//! The externally supplied SHA-256 names the complete bytes including that checksum. It is
//! verified before interpreting any header or payload field. The payload preserves the full
//! lifetime source inventory, numerical state, active supporting-domain components, last reset,
//! configuration and both transcript heads; no observations are replayed during restoration.
//!
//! A checkpoint is derived continuation state, not proof that its claimed history occurred.
//! Its checksum proves neither authenticity nor freshness. The caller must obtain the expected
//! digest from independently trusted custody and select its latest committed checkpoint to
//! prevent rollback. Current source custody, privacy, model/calibration validity, independent
//! errors and any test-supermartingale assumption remain separate owner responsibilities.

use std::collections::BTreeMap;
use std::fmt;

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, ContractError, DigestAlgorithm};

use super::{MAX_UNIQUE_SOURCES, SeenSource, UniqueSourceEProcess};
use crate::{MAX_EVIDENCE, SequentialEProcess};

/// Magic for the strict declared-source-once checkpoint envelope.
pub const UNIQUE_SOURCE_CHECKPOINT_MAGIC: [u8; 8] = *b"FSSUSCP\0";
/// The only admitted checkpoint version. Unknown versions are never guessed or migrated.
pub const UNIQUE_SOURCE_CHECKPOINT_VERSION: u32 = 1;
/// Complete encoded-byte ceiling, checked before hashing or parsing untrusted input (32 MiB).
///
/// The source ceiling additionally bounds active support to 4096 components and at most
/// 4096 * 17 domains. Each domain is at most 263 UTF-8 bytes (including an intrinsic `sensor:`
/// prefix); each of the at most two last-reset strings is at most 64 KiB.
pub const MAX_UNIQUE_SOURCE_CHECKPOINT_BYTES: usize = 32 * 1024 * 1024;

const HEADER_BYTES: usize = 8 + 4 + 8;
const CHECKSUM_BYTES: usize = 32;
const SOURCE_RECORD_BYTES: usize = 33 + 33 + 8;

/// A refusal to export or restore a complete source-once checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UniqueSourceCheckpointError {
    /// A byte, source, domain or text allowance would be exceeded.
    Limit,
    /// The independently supplied SHA-256 or embedded checksum does not match the bytes.
    DigestMismatch,
    /// The envelope names a version this implementation cannot interpret.
    UnsupportedVersion,
    /// Bytes are truncated, malformed, noncanonical, or contain unconsumed trailing data.
    InvalidEncoding,
    /// The complete decoded state violates the accumulator's structural invariants.
    InvalidState,
}

impl UniqueSourceCheckpointError {
    /// Stable refusal identity; no refusal returns a partially restored process.
    #[must_use]
    pub const fn stable_id(self) -> &'static str {
        match self {
            Self::Limit => "ERR-FUSION-CHECKPOINT-LIMIT-001",
            Self::DigestMismatch => "ERR-FUSION-CHECKPOINT-DIGEST-001",
            Self::UnsupportedVersion => "ERR-FUSION-CHECKPOINT-VERSION-001",
            Self::InvalidEncoding | Self::InvalidState => "ERR-FUSION-CHECKPOINT-INVALID-001",
        }
    }
}

impl fmt::Display for UniqueSourceCheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Limit => "source-once checkpoint exceeds a declared resource bound",
            Self::DigestMismatch => "source-once checkpoint does not match its SHA-256 identity",
            Self::UnsupportedVersion => "unsupported source-once checkpoint version",
            Self::InvalidEncoding => "invalid or noncanonical source-once checkpoint encoding",
            Self::InvalidState => "source-once checkpoint contains inconsistent accumulator state",
        })
    }
}

impl std::error::Error for UniqueSourceCheckpointError {}

impl From<ContractError> for UniqueSourceCheckpointError {
    fn from(_: ContractError) -> Self {
        Self::InvalidEncoding
    }
}

pub(crate) type Result<T> = std::result::Result<T, UniqueSourceCheckpointError>;

/// Complete immutable continuation bytes and their independently usable content identity.
///
/// Retaining these bytes is the caller's I/O responsibility. Publishing only the embedded hash
/// does not establish source custody, safe freshness, historical validity or effect authority.
#[derive(Clone, Eq, PartialEq)]
pub struct UniqueSourceCheckpoint {
    bytes: Vec<u8>,
    digest: ContentDigest,
}

impl fmt::Debug for UniqueSourceCheckpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UniqueSourceCheckpoint")
            .field("byte_len", &self.bytes.len())
            .field("digest", &self.digest)
            .finish()
    }
}

impl UniqueSourceCheckpoint {
    /// The entire canonical envelope, including its header and checksum.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// SHA-256 of the complete canonical envelope, to retain independently of the bytes.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
}

pub(crate) fn encode_optional_digest(encoder: &mut CanonicalEncoder, value: Option<ContentDigest>) {
    encoder.bool(value.is_some());
    if let Some(value) = value {
        encoder.digest(value);
    }
}

pub(crate) fn require_sha256(value: ContentDigest) -> Result<ContentDigest> {
    if value.algorithm() != DigestAlgorithm::Sha256 || value.is_laboratory() {
        return Err(UniqueSourceCheckpointError::InvalidState);
    }
    Ok(value)
}

pub(crate) fn decode_optional_digest(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<Option<ContentDigest>> {
    if decoder.bool()? {
        Ok(Some(require_sha256(decoder.digest()?)?))
    } else {
        Ok(None)
    }
}

pub(crate) fn count(decoder: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<usize> {
    let count = usize::try_from(decoder.u32()?).map_err(|_| UniqueSourceCheckpointError::Limit)?;
    if count > maximum {
        return Err(UniqueSourceCheckpointError::Limit);
    }
    Ok(count)
}

impl UniqueSourceEProcess {
    fn validate_checkpoint(&self) -> Result<()> {
        if !(1..=MAX_UNIQUE_SOURCES).contains(&self.source_limit)
            || self.seen.len() > self.source_limit
        {
            return Err(UniqueSourceCheckpointError::Limit);
        }
        self.inner.validate_checkpoint(self.seen.len())?;
        let step = self.inner.step_index();
        if self.last_receipt.is_some() != (step > 0) {
            return Err(UniqueSourceCheckpointError::InvalidState);
        }
        if let Some(head) = self.last_receipt {
            require_sha256(head)?;
        }
        let mut admissions_per_step = BTreeMap::<u64, usize>::new();
        for (source, entry) in &self.seen {
            if source.is_laboratory() || entry.first_step == 0 || entry.first_step > step {
                return Err(UniqueSourceCheckpointError::InvalidState);
            }
            require_sha256(entry.item_digest)?;
            let count = admissions_per_step.entry(entry.first_step).or_default();
            *count += 1;
            // The original counter saturates. Several real transitions may share MAX's index.
            if entry.first_step != u64::MAX && *count > MAX_EVIDENCE {
                return Err(UniqueSourceCheckpointError::InvalidState);
            }
        }
        // An observed admission and a reset cannot be the same transition. The saturating epoch
        // is a lower bound on actual resets, so this remains necessary even after saturation.
        if (admissions_per_step.len() as u64)
            .saturating_add(u64::from(self.inner.checkpoint_regime_epoch()))
            > step
        {
            return Err(UniqueSourceCheckpointError::InvalidState);
        }
        Ok(())
    }

    /// Captures the complete bounded source-once and numerical continuation without mutation.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal if the state cannot be represented within the frozen format's
    /// limits. In particular, legacy infallible resets may carry strings larger than 64 KiB;
    /// those states remain in memory but cannot be silently truncated into a checkpoint.
    pub fn checkpoint(&self) -> Result<UniqueSourceCheckpoint> {
        self.validate_checkpoint()?;
        let mut encoder = CanonicalEncoder::new();
        encoder.u32(self.source_limit as u32);
        encoder.u32(self.seen.len() as u32);
        for (source, entry) in &self.seen {
            encoder.digest(*source);
            encoder.digest(entry.item_digest);
            encoder.u64(entry.first_step);
        }
        encode_optional_digest(&mut encoder, self.last_receipt);
        self.inner.encode_checkpoint(&mut encoder);
        // Validation bounds this allocation by the finite source/domain inventory and reset
        // text ceilings before encoding; the final ceiling also guards future format edits.
        let payload = encoder.finish_checked()?;
        let total = payload
            .len()
            .checked_add(HEADER_BYTES + CHECKSUM_BYTES)
            .filter(|&length| length <= MAX_UNIQUE_SOURCE_CHECKPOINT_BYTES)
            .ok_or(UniqueSourceCheckpointError::Limit)?;
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(&UNIQUE_SOURCE_CHECKPOINT_MAGIC);
        bytes.extend_from_slice(&UNIQUE_SOURCE_CHECKPOINT_VERSION.to_be_bytes());
        bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&payload);
        let checksum = ContentDigest::sha256(&bytes);
        bytes.extend_from_slice(&checksum.bytes());
        Ok(UniqueSourceCheckpoint {
            digest: ContentDigest::sha256(&bytes),
            bytes,
        })
    }

    /// Restores one exact complete checkpoint against an independently obtained SHA-256.
    ///
    /// No input is interpreted until its total size and external digest pass. Counts and UTF-8
    /// lengths are checked before allocation, source keys/components/domains must be strictly
    /// ordered with no duplicates, and structural state relations are validated. No history is
    /// replayed or certified. The caller must separately reject stale checkpoint selection and
    /// a restored hypothesis/configuration inconsistent with its current intended operation.
    ///
    /// # Errors
    ///
    /// Refuses an excessive input, digest/checksum mismatch, unknown version, malformed or
    /// noncanonical encoding, and inconsistent state. A refusal returns no partial process.
    pub fn from_checkpoint(bytes: &[u8], expected: ContentDigest) -> Result<Self> {
        if bytes.len() > MAX_UNIQUE_SOURCE_CHECKPOINT_BYTES {
            return Err(UniqueSourceCheckpointError::Limit);
        }
        if expected.algorithm() != DigestAlgorithm::Sha256
            || ContentDigest::sha256(bytes) != expected
        {
            return Err(UniqueSourceCheckpointError::DigestMismatch);
        }
        if bytes.len() < HEADER_BYTES + CHECKSUM_BYTES
            || bytes[..8] != UNIQUE_SOURCE_CHECKPOINT_MAGIC
        {
            return Err(UniqueSourceCheckpointError::InvalidEncoding);
        }
        let mut header = CanonicalDecoder::new(&bytes[8..HEADER_BYTES]);
        if header.u32()? != UNIQUE_SOURCE_CHECKPOINT_VERSION {
            return Err(UniqueSourceCheckpointError::UnsupportedVersion);
        }
        let payload_len =
            usize::try_from(header.u64()?).map_err(|_| UniqueSourceCheckpointError::Limit)?;
        if payload_len != bytes.len() - HEADER_BYTES - CHECKSUM_BYTES {
            return Err(UniqueSourceCheckpointError::InvalidEncoding);
        }
        let payload_end = HEADER_BYTES + payload_len;
        if ContentDigest::sha256(&bytes[..payload_end]).bytes() != bytes[payload_end..] {
            return Err(UniqueSourceCheckpointError::DigestMismatch);
        }
        let mut decoder = CanonicalDecoder::new(&bytes[HEADER_BYTES..payload_end]);
        let source_limit = count(&mut decoder, MAX_UNIQUE_SOURCES)?;
        if source_limit == 0 {
            return Err(UniqueSourceCheckpointError::InvalidState);
        }
        let source_count = count(&mut decoder, source_limit)?;
        if source_count * SOURCE_RECORD_BYTES > decoder.remaining() {
            return Err(UniqueSourceCheckpointError::InvalidEncoding);
        }
        let mut seen = BTreeMap::new();
        let mut previous = None;
        for _ in 0..source_count {
            let source = decoder.digest()?;
            if previous.is_some_and(|previous| previous >= source) {
                return Err(UniqueSourceCheckpointError::InvalidEncoding);
            }
            let item_digest = require_sha256(decoder.digest()?)?;
            let first_step = decoder.u64()?;
            seen.insert(
                source,
                SeenSource {
                    item_digest,
                    first_step,
                },
            );
            previous = Some(source);
        }
        let last_receipt = decode_optional_digest(&mut decoder)?;
        let inner = SequentialEProcess::decode_checkpoint(&mut decoder, source_count)?;
        decoder.ensure_finished()?;
        let restored = Self {
            inner,
            source_limit,
            seen,
            last_receipt,
        };
        restored.validate_checkpoint()?;
        Ok(restored)
    }
}

#[cfg(test)]
mod tests;
