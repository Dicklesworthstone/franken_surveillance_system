//! Slot names and the hand-audited on-disk record encodings.
//!
//! # Root record (`fss.local_root_record.v1`)
//!
//! ```text
//! u64be len ‖ "fss.local_root_record.v1"      domain tag
//! u64be 1                                     format version
//! u64be len ‖ slot name                       ASCII, 1..=128 bytes, slot grammar
//! u8 1 ‖ 32-byte SHA-256                      manifest root
//! u64be child count                           direct children, including metadata
//! u8 1 ‖ 32-byte SHA-256(all preceding bytes) trailer checksum
//! ```
//!
//! # Tombstone record (`fss.local_tombstone_record.v1`)
//!
//! ```text
//! u64be len ‖ "fss.local_tombstone_record.v1" domain tag
//! u64be 1                                     format version
//! u64be len ‖ canonical TombstoneRecord bytes
//! u8 1 ‖ 32-byte SHA-256(all preceding bytes) trailer checksum
//! ```
//!
//! Both use `fss_core::CanonicalEncoder` primitives and nothing else. Decoding verifies the
//! trailer before interpreting any field, rejects unknown format versions, and rejects trailing
//! bytes.

use std::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    TombstoneRecord,
};

use super::{BrokenRootReason, LocalPublicationError, SlotViolation};

/// Domain tag of a local root record.
pub const LOCAL_ROOT_RECORD_DOMAIN: &str = "fss.local_root_record.v1";
/// Domain tag of a local tombstone record.
pub const LOCAL_TOMBSTONE_RECORD_DOMAIN: &str = "fss.local_tombstone_record.v1";
/// The only root and tombstone record format version this build reads or writes.
pub const LOCAL_ROOT_RECORD_FORMAT_VERSION: u64 = 1;
/// Maximum slot name length in bytes.
pub const MAX_SLOT_NAME_BYTES: usize = 128;
/// Maximum on-disk root record length; the largest valid record is 250 bytes.
pub const MAX_ROOT_RECORD_BYTES: u64 = 512;
/// Maximum on-disk tombstone record length.
pub const MAX_TOMBSTONE_RECORD_BYTES: u64 = 16 * 1024;

const TRAILER_LEN: usize = 33;

/// Validated name of one publication slot.
///
/// Grammar: 1..=[`MAX_SLOT_NAME_BYTES`] bytes; the first byte is `[a-z0-9]`, later bytes are
/// `[a-z0-9_-]`. The grammar excludes `.`, `/`, and uppercase so a slot maps to exactly one file
/// name on every supported filesystem.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SlotName(String);

impl SlotName {
    /// Parses a slot name, rejecting anything outside the grammar.
    pub fn parse(value: &str) -> Result<Self, SlotViolation> {
        if value.is_empty() {
            return Err(SlotViolation::Empty);
        }
        if value.len() > MAX_SLOT_NAME_BYTES {
            return Err(SlotViolation::TooLong {
                length: value.len(),
                maximum: MAX_SLOT_NAME_BYTES,
            });
        }
        for (index, byte) in value.bytes().enumerate() {
            let admitted = byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && (byte == b'-' || byte == b'_'));
            if !admitted {
                return Err(SlotViolation::InvalidByte { index });
            }
        }
        Ok(Self(value.to_owned()))
    }

    /// The slot name text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SlotName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Exact canonical bytes of the root record for `slot` naming `root` with `child_count` children.
pub fn root_record_bytes(
    slot: &SlotName,
    root: ContentDigest,
    child_count: usize,
) -> Result<Vec<u8>, LocalPublicationError> {
    let count =
        u64::try_from(child_count).map_err(|_| LocalPublicationError::ManifestChildBound {
            count: child_count,
            maximum: fss_object::MAX_MANIFEST_CHILDREN,
        })?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text(LOCAL_ROOT_RECORD_DOMAIN);
    encoder.u64(LOCAL_ROOT_RECORD_FORMAT_VERSION);
    encoder.text(slot.as_str());
    encoder.digest(root);
    encoder.u64(count);
    seal(encoder)
}

/// Exact canonical bytes of the durable tombstone record for `record`.
pub fn tombstone_record_bytes(record: &TombstoneRecord) -> Result<Vec<u8>, LocalPublicationError> {
    let body = record
        .try_canonical_bytes()
        .map_err(LocalPublicationError::Encoding)?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text(LOCAL_TOMBSTONE_RECORD_DOMAIN);
    encoder.u64(LOCAL_ROOT_RECORD_FORMAT_VERSION);
    encoder.bytes(&body);
    let sealed = seal(encoder)?;
    let length = sealed.len() as u64;
    if length > MAX_TOMBSTONE_RECORD_BYTES {
        return Err(LocalPublicationError::RecordTooLarge {
            length,
            maximum: MAX_TOMBSTONE_RECORD_BYTES,
        });
    }
    Ok(sealed)
}

fn seal(encoder: CanonicalEncoder) -> Result<Vec<u8>, LocalPublicationError> {
    let mut bytes = encoder
        .finish_checked()
        .map_err(LocalPublicationError::Encoding)?;
    let mut trailer = CanonicalEncoder::new();
    trailer.digest(ContentDigest::sha256(&bytes));
    bytes.extend_from_slice(
        &trailer
            .finish_checked()
            .map_err(LocalPublicationError::Encoding)?,
    );
    Ok(bytes)
}

/// Verifies the trailer checksum and returns the checksummed body.
fn unseal(bytes: &[u8]) -> Result<&[u8], BrokenRootReason> {
    let split = bytes
        .len()
        .checked_sub(TRAILER_LEN)
        .ok_or(BrokenRootReason::Undecodable)?;
    let (body, trailer) = bytes.split_at(split);
    let mut decoder = CanonicalDecoder::new(trailer);
    let checksum = decoder
        .digest()
        .map_err(|_| BrokenRootReason::Undecodable)?;
    if checksum != ContentDigest::sha256(body) {
        return Err(BrokenRootReason::ChecksumMismatch);
    }
    Ok(body)
}

fn read_header<'a>(body: &'a [u8], domain: &str) -> Result<CanonicalDecoder<'a>, BrokenRootReason> {
    let mut decoder = CanonicalDecoder::new(body);
    let tag = decoder.text().map_err(|_| BrokenRootReason::Undecodable)?;
    if tag != domain {
        return Err(BrokenRootReason::Undecodable);
    }
    let version = decoder.u64().map_err(|_| BrokenRootReason::Undecodable)?;
    if version != LOCAL_ROOT_RECORD_FORMAT_VERSION {
        return Err(BrokenRootReason::UnsupportedVersion { version });
    }
    Ok(decoder)
}

/// Fields of a root record whose trailer, domain, version, and framing verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DecodedRootRecord {
    pub(crate) slot: String,
    pub(crate) root: ContentDigest,
    pub(crate) child_count: u64,
}

pub(crate) fn decode_root_record(bytes: &[u8]) -> Result<DecodedRootRecord, BrokenRootReason> {
    let body = unseal(bytes)?;
    let mut decoder = read_header(body, LOCAL_ROOT_RECORD_DOMAIN)?;
    let slot = decoder
        .text()
        .map_err(|_| BrokenRootReason::Undecodable)?
        .to_owned();
    let root = decoder
        .digest()
        .map_err(|_| BrokenRootReason::Undecodable)?;
    let child_count = decoder.u64().map_err(|_| BrokenRootReason::Undecodable)?;
    decoder
        .ensure_finished()
        .map_err(|_| BrokenRootReason::Undecodable)?;
    Ok(DecodedRootRecord {
        slot,
        root,
        child_count,
    })
}

pub(crate) fn decode_tombstone_record(bytes: &[u8]) -> Result<TombstoneRecord, BrokenRootReason> {
    let body = unseal(bytes)?;
    let mut decoder = read_header(body, LOCAL_TOMBSTONE_RECORD_DOMAIN)?;
    let record_bytes = decoder.bytes().map_err(|_| BrokenRootReason::Undecodable)?;
    decoder
        .ensure_finished()
        .map_err(|_| BrokenRootReason::Undecodable)?;
    TombstoneRecord::from_canonical_bytes(record_bytes).map_err(|_| BrokenRootReason::Undecodable)
}

#[cfg(test)]
mod tests {
    use fss_core::{ContentDigest, Generation, ObjectId, TombstoneReason, TombstoneRecord};

    use super::{
        MAX_ROOT_RECORD_BYTES, MAX_SLOT_NAME_BYTES, SlotName, decode_root_record,
        decode_tombstone_record, root_record_bytes, tombstone_record_bytes,
    };
    use crate::local::BrokenRootReason;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn root_record_round_trips_and_largest_record_fits_bound() -> TestResult {
        let slot = SlotName::parse(&"z".repeat(MAX_SLOT_NAME_BYTES))?;
        let root = ContentDigest::sha256(b"root");
        let bytes = root_record_bytes(&slot, root, usize::MAX)?;
        assert_eq!(bytes.len(), 250);
        assert!(bytes.len() as u64 <= MAX_ROOT_RECORD_BYTES);
        let decoded = decode_root_record(&bytes)?;
        assert_eq!(decoded.slot, slot.as_str());
        assert_eq!(decoded.root, root);
        assert_eq!(decoded.child_count, usize::MAX as u64);
        Ok(())
    }

    #[test]
    fn truncated_and_trailing_records_are_undecodable() -> TestResult {
        let slot = SlotName::parse("slot")?;
        let bytes = root_record_bytes(&slot, ContentDigest::sha256(b"r"), 1)?;
        let body_len = bytes.len() - 33;
        // Too short to hold a body: the would-be trailer tag is the 0x00 high byte of the domain
        // length prefix, which is no digest algorithm.
        assert_eq!(
            decode_root_record(&bytes[..32]),
            Err(BrokenRootReason::Undecodable)
        );
        assert_eq!(
            decode_root_record(&bytes[..20]),
            Err(BrokenRootReason::Undecodable)
        );
        // A body byte removed under the original trailer fails the checksum.
        let mut shortened = bytes[..body_len - 1].to_vec();
        shortened.extend_from_slice(&bytes[body_len..]);
        assert_eq!(
            decode_root_record(&shortened),
            Err(BrokenRootReason::ChecksumMismatch)
        );
        // Trailing body bytes are rejected even under a recomputed, valid checksum.
        let mut padded = bytes[..body_len].to_vec();
        padded.push(0);
        let checksum = ContentDigest::sha256(&padded);
        padded.push(1);
        padded.extend_from_slice(&checksum.bytes());
        assert_eq!(
            decode_root_record(&padded),
            Err(BrokenRootReason::Undecodable)
        );
        Ok(())
    }

    #[test]
    fn tombstone_record_round_trips_and_rejects_wrong_domain() -> TestResult {
        let record = TombstoneRecord::new(
            ObjectId::parse("object:clip:1")?,
            Generation(2),
            Generation(1),
            TombstoneReason::Deleted,
            Some(ContentDigest::sha256(b"w")),
            ContentDigest::sha256(b"p"),
        )?;
        let bytes = tombstone_record_bytes(&record)?;
        assert_eq!(decode_tombstone_record(&bytes)?, record);
        let root = root_record_bytes(&SlotName::parse("slot")?, ContentDigest::sha256(b"r"), 1)?;
        assert_eq!(
            decode_tombstone_record(&root),
            Err(BrokenRootReason::Undecodable)
        );
        Ok(())
    }
}
