//! Self-describing on-disk envelope for one spooled object.
//!
//! Layout (little-endian): `magic[8] | version:u16 | algorithm:u16 | payload_len:u64 |
//! digest[32] | payload[payload_len]`. Built on top of the shared canonical durable-format
//! framework [`DurableFormat`]. The object identity is the SHA-256 of the payload alone,
//! so a spooled object has the same `ContentDigest` the in-memory oracle assigns it. The header
//! lets a reader distinguish truncation, trailing bytes, a foreign file, a misnamed file, and a
//! payload digest mismatch as separate typed failures.

use fss_core::durable::{DurableError, DurableFormat};
use fss_core::{ContentDigest, DigestAlgorithm};

use super::{CorruptionKind, SpoolError};

/// Magic prefix of every spooled object file.
pub const SPOOL_OBJECT_MAGIC: [u8; 8] = *b"FSSSPOOL";
/// Envelope format version written by this implementation.
pub const SPOOL_OBJECT_FORMAT_VERSION: u16 = 1;
/// Fixed envelope header length in bytes.
pub const SPOOL_OBJECT_HEADER_LEN: usize = 8 + 2 + 2 + 8 + 32;

/// Returns the shared [`DurableFormat`] specification for spool objects.
#[must_use]
pub fn spool_durable_format(max_payload: usize) -> DurableFormat {
    DurableFormat::spool_object(
        &SPOOL_OBJECT_MAGIC,
        SPOOL_OBJECT_FORMAT_VERSION,
        max_payload,
    )
}

/// Encodes one payload as the exact envelope the spool writes for it.
///
/// The spool keys objects by SHA-256 of the payload, so `digest` must be a SHA-256 digest and the
/// payload must hash to it; anything else is a typed error, never an empty or mislabeled envelope.
pub fn encode_spool_object(digest: ContentDigest, payload: &[u8]) -> Result<Vec<u8>, SpoolError> {
    if digest.algorithm() != DigestAlgorithm::Sha256 {
        return Err(SpoolError::UnsupportedAlgorithm(digest.algorithm()));
    }
    let computed = ContentDigest::sha256(payload);
    if computed != digest {
        return Err(SpoolError::DigestMismatch {
            declared: digest,
            computed,
        });
    }
    spool_durable_format(payload.len())
        .encode_with_checksum(payload, digest)
        .map_err(|error| match error {
            DurableError::OverLimitLength { limit, actual } => SpoolError::ObjectTooLarge {
                length: actual,
                maximum: limit,
            },
            // The format is built for exactly this payload length; no other encode error exists.
            _ => SpoolError::AccountingOverflow,
        })
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
    let format = spool_durable_format(max_payload);

    // Decode and validate the fixed header first to inspect recorded identity and limits
    let header = match format.decode_header_raw(raw) {
        Ok(h) => h,
        Err(DurableError::BadMagic { .. }) => return Err(CorruptionKind::ForeignFile),
        Err(DurableError::UnknownVersion { actual, .. }) => {
            return Err(CorruptionKind::UnsupportedFormatVersion(actual as u16));
        }
        Err(DurableError::UnsupportedTag { actual, .. }) => {
            return Err(CorruptionKind::UnsupportedAlgorithmTag(actual));
        }
        Err(DurableError::Truncated {
            expected_len,
            actual_len,
        }) => {
            return Err(CorruptionKind::Truncated {
                expected_len: expected_len as u64,
                actual_len: actual_len as u64,
            });
        }
        Err(_) => return Err(CorruptionKind::ForeignFile),
    };

    // NameDigestMismatch check: envelope records a different digest than the file name claims
    // Checked BEFORE DeclaredLengthExceedsLimit (Finding 9)
    if let Some(recorded) = header.recorded_checksum()
        && recorded != expected
    {
        return Err(CorruptionKind::NameDigestMismatch { recorded });
    }

    // Declared length limit check
    if header.declared_payload_len() > max_payload {
        return Err(CorruptionKind::DeclaredLengthExceedsLimit {
            declared: header.declared_payload_len() as u64,
            maximum: max_payload as u64,
        });
    }

    // Now verify the entire envelope: payload length, trailing bytes, and payload checksum
    match format.decode(raw) {
        Ok(_) => Ok(()),
        Err(DurableError::BadMagic { .. }) => Err(CorruptionKind::ForeignFile),
        Err(DurableError::UnknownVersion { actual, .. }) => {
            Err(CorruptionKind::UnsupportedFormatVersion(actual as u16))
        }
        Err(DurableError::UnsupportedTag { actual, .. }) => {
            Err(CorruptionKind::UnsupportedAlgorithmTag(actual))
        }
        Err(DurableError::Truncated {
            expected_len,
            actual_len,
        }) => Err(CorruptionKind::Truncated {
            expected_len: expected_len as u64,
            actual_len: actual_len as u64,
        }),
        Err(DurableError::TrailingBytes {
            expected_len,
            actual_len,
        }) => Err(CorruptionKind::TrailingBytes {
            expected_len: expected_len as u64,
            actual_len: actual_len as u64,
        }),
        Err(DurableError::OverLimitLength { limit, actual }) => {
            Err(CorruptionKind::DeclaredLengthExceedsLimit {
                declared: actual as u64,
                maximum: limit as u64,
            })
        }
        Err(DurableError::ChecksumMismatch {
            actual: computed, ..
        }) => Err(CorruptionKind::ContentDigestMismatch { computed }),
        Err(DurableError::InvalidFormat { .. } | DurableError::DigestComputationFailed) => {
            Err(CorruptionKind::ForeignFile)
        }
    }
}
