//! Self-describing on-disk envelope for one spooled object.
//!
//! Layout (little-endian): `magic[8] | version:u16 | algorithm:u16 | payload_len:u64 |
//! digest[32] | payload[payload_len]`. The object identity is the SHA-256 of the payload alone,
//! so a spooled object has the same `ContentDigest` the in-memory oracle assigns it. The header
//! lets a reader distinguish truncation, trailing bytes, a foreign file, a misnamed file, and a
//! payload digest mismatch as separate typed failures.

use fss_core::{ContentDigest, DigestAlgorithm};

use super::CorruptionKind;

/// Magic prefix of every spooled object file.
pub const SPOOL_OBJECT_MAGIC: [u8; 8] = *b"FSSSPOOL";
/// Envelope format version written by this implementation.
pub const SPOOL_OBJECT_FORMAT_VERSION: u16 = 1;
/// Fixed envelope header length in bytes.
pub const SPOOL_OBJECT_HEADER_LEN: usize = 8 + 2 + 2 + 8 + 32;

const ALGORITHM_TAG_SHA256: u16 = 1;
const VERSION_OFFSET: usize = 8;
const ALGORITHM_OFFSET: usize = 10;
const LENGTH_OFFSET: usize = 12;
const DIGEST_OFFSET: usize = 20;

/// Encodes one payload under its already-verified SHA-256 identity.
pub(crate) fn encode_object(digest: ContentDigest, payload: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(SPOOL_OBJECT_HEADER_LEN + payload.len());
    encoded.extend_from_slice(&SPOOL_OBJECT_MAGIC);
    encoded.extend_from_slice(&SPOOL_OBJECT_FORMAT_VERSION.to_le_bytes());
    encoded.extend_from_slice(&ALGORITHM_TAG_SHA256.to_le_bytes());
    encoded.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    encoded.extend_from_slice(&digest.bytes());
    encoded.extend_from_slice(payload);
    encoded
}

/// Verifies one complete envelope against the digest its file name claims.
///
/// `raw.len()` is the number of bytes observed. The caller bounds the read at
/// `SPOOL_OBJECT_HEADER_LEN + max_payload + 1` so trailing bytes stay detectable without an
/// unbounded read.
pub(crate) fn verify_object_bytes(
    expected: ContentDigest,
    raw: &[u8],
    max_payload: usize,
) -> Result<(), CorruptionKind> {
    let observed = raw.len() as u64;
    let Some((header, payload)) = raw.split_at_checked(SPOOL_OBJECT_HEADER_LEN) else {
        let prefix = raw.len().min(SPOOL_OBJECT_MAGIC.len());
        if raw.get(..prefix) == SPOOL_OBJECT_MAGIC.get(..prefix) {
            return Err(CorruptionKind::Truncated {
                expected_len: SPOOL_OBJECT_HEADER_LEN as u64,
                actual_len: observed,
            });
        }
        return Err(CorruptionKind::ForeignFile);
    };
    if header.get(..VERSION_OFFSET) != Some(&SPOOL_OBJECT_MAGIC[..]) {
        return Err(CorruptionKind::ForeignFile);
    }
    let version = read_u16(header, VERSION_OFFSET).ok_or(CorruptionKind::ForeignFile)?;
    if version != SPOOL_OBJECT_FORMAT_VERSION {
        return Err(CorruptionKind::UnsupportedFormatVersion(version));
    }
    let algorithm = read_u16(header, ALGORITHM_OFFSET).ok_or(CorruptionKind::ForeignFile)?;
    if algorithm != ALGORITHM_TAG_SHA256 {
        return Err(CorruptionKind::UnsupportedAlgorithmTag(algorithm));
    }
    let declared = read_u64(header, LENGTH_OFFSET).ok_or(CorruptionKind::ForeignFile)?;
    let recorded_bytes = header
        .get(DIGEST_OFFSET..SPOOL_OBJECT_HEADER_LEN)
        .and_then(|slice| <[u8; 32]>::try_from(slice).ok())
        .ok_or(CorruptionKind::ForeignFile)?;
    let recorded = ContentDigest::new(DigestAlgorithm::Sha256, recorded_bytes);
    if recorded != expected {
        return Err(CorruptionKind::NameDigestMismatch { recorded });
    }
    let maximum = max_payload as u64;
    if declared > maximum {
        return Err(CorruptionKind::DeclaredLengthExceedsLimit { declared, maximum });
    }
    let expected_len = SPOOL_OBJECT_HEADER_LEN as u64 + declared;
    if observed < expected_len {
        return Err(CorruptionKind::Truncated {
            expected_len,
            actual_len: observed,
        });
    }
    if observed > expected_len {
        return Err(CorruptionKind::TrailingBytes {
            expected_len,
            actual_len: observed,
        });
    }
    let computed = ContentDigest::sha256(payload);
    if computed != expected {
        return Err(CorruptionKind::ContentDigestMismatch { computed });
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let chunk = <[u8; 2]>::try_from(bytes.get(offset..end)?).ok()?;
    Some(u16::from_le_bytes(chunk))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let chunk = <[u8; 8]>::try_from(bytes.get(offset..end)?).ok()?;
    Some(u64::from_le_bytes(chunk))
}
