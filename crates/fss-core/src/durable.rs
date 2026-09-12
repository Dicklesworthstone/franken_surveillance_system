//! Canonical durable-format framework for self-describing binary envelopes.
//!
//! Every durable format in FSS satisfies:
//! 1. Versioned magic header: deterministic magic prefix and explicit format version.
//! 2. Explicit length limits checked before allocation: hostile declared lengths fail
//!    closed before allocating heap memory or reading the payload.
//! 3. Exact checksum verification: cryptographic digest (`ContentDigest`, default SHA-256)
//!    validates integrity over exact payload or envelope bytes.
//! 4. Typed error taxonomy: distinct variants for bad magic, unknown version, truncated
//!    input, trailing bytes, over-limit length, and checksum mismatch.

use core::fmt;
use std::error::Error;

use crate::{ContentDigest, DigestAlgorithm, Sha256Hasher};

/// Format magic prefix default for canonical durable envelopes.
pub const CANONICAL_DURABLE_MAGIC: [u8; 4] = *b"FSSD";

/// Default format version for canonical durable envelopes.
pub const CANONICAL_DURABLE_VERSION_1: u32 = 1;

/// Default maximum payload length (16 MiB).
pub const DEFAULT_MAX_PAYLOAD_LEN: usize = 16 * 1024 * 1024;

/// Checksum byte length for SHA-256 digests.
pub const CHECKSUM_LEN: usize = 32;

/// Typed errors produced during durable envelope encoding, decoding, or verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableError {
    /// File magic header does not match the expected format magic.
    BadMagic {
        /// Expected magic bytes.
        expected: Vec<u8>,
        /// Actual observed bytes (up to the magic length).
        actual: Vec<u8>,
    },
    /// File format version is not supported by this implementation.
    UnknownVersion {
        /// Minimum supported version (inclusive).
        expected_min: u32,
        /// Maximum supported version (inclusive).
        expected_max: u32,
        /// Actual observed version.
        actual: u32,
    },
    /// Input ended prematurely before one complete header, trailer, or declared payload.
    Truncated {
        /// Minimum required byte length.
        expected_len: usize,
        /// Actual byte length observed.
        actual_len: usize,
    },
    /// Additional bytes remain after one complete validated envelope.
    TrailingBytes {
        /// Expected byte length of the complete envelope.
        expected_len: usize,
        /// Actual byte length observed.
        actual_len: usize,
    },
    /// Declared payload length exceeds the configured pre-allocation limit.
    OverLimitLength {
        /// Maximum permitted payload length in bytes.
        limit: usize,
        /// Declared payload length in bytes.
        actual: usize,
    },
    /// Checksum verification over the exact bytes failed.
    ChecksumMismatch {
        /// Checksum recorded in or expected for the envelope.
        expected: ContentDigest,
        /// Checksum computed from the actual data.
        actual: ContentDigest,
    },
    /// Optional format tag or algorithm discriminator is unsupported.
    UnsupportedTag {
        /// Expected tag value.
        expected: u16,
        /// Actual tag value observed.
        actual: u16,
    },
    /// Invalid format specification or builder configuration.
    InvalidFormat {
        /// Rationale for the rejection.
        reason: &'static str,
    },
    /// Cryptographic hashing or digest computation failed.
    DigestComputationFailed,
}

impl DurableError {
    /// Returns true if this error represents a bad format magic.
    #[must_use]
    pub const fn is_bad_magic(&self) -> bool {
        matches!(self, Self::BadMagic { .. })
    }

    /// Returns true if this error represents an unknown format version.
    #[must_use]
    pub const fn is_unknown_version(&self) -> bool {
        matches!(self, Self::UnknownVersion { .. })
    }

    /// Returns true if this error represents truncated input.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        matches!(self, Self::Truncated { .. })
    }

    /// Returns true if this error represents trailing bytes.
    #[must_use]
    pub const fn is_trailing_bytes(&self) -> bool {
        matches!(self, Self::TrailingBytes { .. })
    }

    /// Returns true if this error represents an over-limit declared length.
    #[must_use]
    pub const fn is_over_limit(&self) -> bool {
        matches!(self, Self::OverLimitLength { .. })
    }

    /// Returns true if this error represents a checksum mismatch.
    #[must_use]
    pub const fn is_checksum_mismatch(&self) -> bool {
        matches!(self, Self::ChecksumMismatch { .. })
    }

    /// Returns true if this error represents an invalid format configuration.
    #[must_use]
    pub const fn is_invalid_format(&self) -> bool {
        matches!(self, Self::InvalidFormat { .. })
    }

    /// Returns true if this error represents a digest computation failure.
    #[must_use]
    pub const fn is_digest_error(&self) -> bool {
        matches!(self, Self::DigestComputationFailed)
    }
}

impl fmt::Display for DurableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic { expected, actual } => {
                write!(
                    formatter,
                    "durable format bad magic: expected {expected:?}, found {actual:?}"
                )
            }
            Self::UnknownVersion {
                expected_min,
                expected_max,
                actual,
            } => {
                if expected_min == expected_max {
                    write!(
                        formatter,
                        "durable format unknown version {actual}: expected {expected_min}"
                    )
                } else {
                    write!(
                        formatter,
                        "durable format unknown version {actual}: expected {expected_min}..={expected_max}"
                    )
                }
            }
            Self::Truncated {
                expected_len,
                actual_len,
            } => {
                write!(
                    formatter,
                    "durable format truncated input: expected {expected_len} bytes, found {actual_len}"
                )
            }
            Self::TrailingBytes {
                expected_len,
                actual_len,
            } => {
                write!(
                    formatter,
                    "durable format trailing bytes: expected {expected_len} bytes, found {actual_len}"
                )
            }
            Self::OverLimitLength { limit, actual } => {
                write!(
                    formatter,
                    "durable format over-limit length: limit is {limit} bytes, declared {actual}"
                )
            }
            Self::ChecksumMismatch { expected, actual } => {
                write!(
                    formatter,
                    "durable format checksum mismatch: expected {expected}, computed {actual}"
                )
            }
            Self::UnsupportedTag { expected, actual } => {
                write!(
                    formatter,
                    "durable format unsupported tag: expected {expected}, found {actual}"
                )
            }
            Self::InvalidFormat { reason } => {
                write!(formatter, "durable format invalid configuration: {reason}")
            }
            Self::DigestComputationFailed => {
                write!(formatter, "durable format digest computation failed")
            }
        }
    }
}

impl Error for DurableError {}

/// Where the checksum is placed within the durable envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChecksumPlacement {
    /// Stored in the fixed header before the payload.
    Header,
    /// Stored as a trailer immediately following the payload.
    Trailer,
}

/// The byte range covered by the checksum calculation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChecksumScope {
    /// Checksum covers only the payload bytes.
    PayloadOnly,
    /// Checksum covers all envelope bytes preceding the checksum field.
    HeaderAndPayload,
}

/// Endianness for integer fields (version, length, tags).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endianness {
    /// Big-endian (network byte order, canonical default).
    BigEndian,
    /// Little-endian.
    LittleEndian,
}

/// Bit-width of the version field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionWidth {
    /// 16-bit unsigned integer (2 bytes).
    U16,
    /// 32-bit unsigned integer (4 bytes).
    U32,
}

/// Bit-width of the payload length field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LengthWidth {
    /// 32-bit unsigned integer (4 bytes).
    U32,
    /// 64-bit unsigned integer (8 bytes).
    U64,
}

/// Parsed header of a durable envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableHeader {
    magic: Vec<u8>,
    version: u32,
    tag: Option<u16>,
    declared_payload_len: usize,
    recorded_checksum: Option<ContentDigest>,
    header_len: usize,
}

impl DurableHeader {
    /// Format magic bytes from the header.
    #[must_use]
    pub fn magic(&self) -> &[u8] {
        &self.magic
    }

    /// Format version decoded from the header.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Optional format/algorithm tag decoded from the header.
    #[must_use]
    pub const fn tag(&self) -> Option<u16> {
        self.tag
    }

    /// Declared payload length in bytes.
    #[must_use]
    pub const fn declared_payload_len(&self) -> usize {
        self.declared_payload_len
    }

    /// Recorded checksum if stored in the header.
    #[must_use]
    pub const fn recorded_checksum(&self) -> Option<ContentDigest> {
        self.recorded_checksum
    }

    /// Fixed header length in bytes.
    #[must_use]
    pub const fn header_len(&self) -> usize {
        self.header_len
    }
}

/// A borrowed, verified durable frame referencing the raw input buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableFrame<'a> {
    version: u32,
    tag: Option<u16>,
    checksum: ContentDigest,
    payload: &'a [u8],
}

impl<'a> DurableFrame<'a> {
    /// Format version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Optional format/algorithm tag.
    #[must_use]
    pub const fn tag(&self) -> Option<u16> {
        self.tag
    }

    /// Validated checksum over the exact bytes.
    #[must_use]
    pub const fn checksum(&self) -> ContentDigest {
        self.checksum
    }

    /// Borrowed payload bytes.
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Clones the payload into an owned vector.
    #[must_use]
    pub fn to_payload_vec(&self) -> Vec<u8> {
        self.payload.to_vec()
    }
}

/// Self-describing durable envelope format specification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableFormat {
    magic: Vec<u8>,
    min_version: u32,
    max_version: u32,
    version_width: VersionWidth,
    length_width: LengthWidth,
    endianness: Endianness,
    checksum_placement: ChecksumPlacement,
    checksum_scope: ChecksumScope,
    checksum_algorithm: DigestAlgorithm,
    tag_field: Option<u16>,
    max_payload_len: usize,
}

impl DurableFormat {
    /// Creates a builder for configuring a durable format specification.
    #[must_use]
    pub fn builder(magic: &[u8]) -> DurableFormatBuilder {
        DurableFormatBuilder::new(magic)
    }

    /// Standard canonical format preset:
    /// - Magic bytes as specified
    /// - Version 32-bit big-endian
    /// - Length 64-bit big-endian
    /// - Trailer checksum (SHA-256) covering header and payload
    #[must_use]
    pub fn canonical(magic: &[u8], version: u32, max_payload_len: usize) -> Self {
        Self {
            magic: magic.to_vec(),
            min_version: version,
            max_version: version,
            version_width: VersionWidth::U32,
            length_width: LengthWidth::U64,
            endianness: Endianness::BigEndian,
            checksum_placement: ChecksumPlacement::Trailer,
            checksum_scope: ChecksumScope::HeaderAndPayload,
            checksum_algorithm: DigestAlgorithm::Sha256,
            tag_field: None,
            max_payload_len,
        }
    }

    /// Standard spool object format preset:
    /// - 8-byte magic (`b"FSSSPOOL"`)
    /// - Version 16-bit little-endian
    /// - Algorithm tag 16-bit little-endian (default 1 for SHA-256)
    /// - Length 64-bit little-endian
    /// - Header checksum (SHA-256) covering payload only
    #[must_use]
    pub fn spool_object(magic: &[u8], version: u16, max_payload_len: usize) -> Self {
        Self {
            magic: magic.to_vec(),
            min_version: u32::from(version),
            max_version: u32::from(version),
            version_width: VersionWidth::U16,
            length_width: LengthWidth::U64,
            endianness: Endianness::LittleEndian,
            checksum_placement: ChecksumPlacement::Header,
            checksum_scope: ChecksumScope::PayloadOnly,
            checksum_algorithm: DigestAlgorithm::Sha256,
            tag_field: Some(1),
            max_payload_len,
        }
    }

    /// Magic prefix bytes.
    #[must_use]
    pub fn magic(&self) -> &[u8] {
        &self.magic
    }

    /// Minimum supported version.
    #[must_use]
    pub const fn min_version(&self) -> u32 {
        self.min_version
    }

    /// Maximum supported version.
    #[must_use]
    pub const fn max_version(&self) -> u32 {
        self.max_version
    }

    /// Configured maximum payload length.
    #[must_use]
    pub const fn max_payload_len(&self) -> usize {
        self.max_payload_len
    }

    /// Format endianness.
    #[must_use]
    pub const fn endianness(&self) -> Endianness {
        self.endianness
    }

    /// Placement of the checksum field.
    #[must_use]
    pub const fn checksum_placement(&self) -> ChecksumPlacement {
        self.checksum_placement
    }

    /// Scope covered by the checksum.
    #[must_use]
    pub const fn checksum_scope(&self) -> ChecksumScope {
        self.checksum_scope
    }

    /// Checksum algorithm.
    #[must_use]
    pub const fn checksum_algorithm(&self) -> DigestAlgorithm {
        self.checksum_algorithm
    }

    /// Expected format/algorithm tag, if configured.
    #[must_use]
    pub const fn tag_field(&self) -> Option<u16> {
        self.tag_field
    }

    /// Fixed byte length of the header.
    #[must_use]
    pub fn header_len(&self) -> usize {
        let version_bytes = match self.version_width {
            VersionWidth::U16 => 2,
            VersionWidth::U32 => 4,
        };
        let tag_bytes = if self.tag_field.is_some() { 2 } else { 0 };
        let length_bytes = match self.length_width {
            LengthWidth::U32 => 4,
            LengthWidth::U64 => 8,
        };
        let checksum_bytes = match self.checksum_placement {
            ChecksumPlacement::Header => CHECKSUM_LEN,
            ChecksumPlacement::Trailer => 0,
        };
        self.magic
            .len()
            .saturating_add(version_bytes)
            .saturating_add(tag_bytes)
            .saturating_add(length_bytes)
            .saturating_add(checksum_bytes)
    }

    /// Fixed byte length of the trailer.
    #[must_use]
    pub const fn trailer_len(&self) -> usize {
        match self.checksum_placement {
            ChecksumPlacement::Header => 0,
            ChecksumPlacement::Trailer => CHECKSUM_LEN,
        }
    }

    /// Minimum valid byte length for an envelope with a zero-length payload.
    #[must_use]
    pub fn min_envelope_len(&self) -> usize {
        self.header_len().saturating_add(self.trailer_len())
    }

    /// Decodes the envelope header slice without enforcing configured payload length limits.
    pub fn decode_header_raw(&self, raw: &[u8]) -> Result<DurableHeader, DurableError> {
        let header_len = self.header_len();
        let min_envelope_len = self.min_envelope_len();
        let magic_len = self.magic.len();

        let check_len = raw.len().min(magic_len);
        let prefix = raw.get(..check_len).unwrap_or(&[]);
        if prefix != &self.magic[..check_len] {
            return Err(DurableError::BadMagic {
                expected: self.magic.clone(),
                actual: prefix.to_vec(),
            });
        }

        if raw.len() < header_len {
            return Err(DurableError::Truncated {
                expected_len: header_len.max(min_envelope_len),
                actual_len: raw.len(),
            });
        }

        let mut cursor = 0;

        // Magic
        let magic_slice = raw.get(cursor..cursor + magic_len).unwrap_or(&[]);
        if magic_slice != self.magic.as_slice() {
            return Err(DurableError::BadMagic {
                expected: self.magic.clone(),
                actual: magic_slice.to_vec(),
            });
        }
        cursor += magic_len;

        // Version
        let version = match self.version_width {
            VersionWidth::U16 => {
                let bytes: [u8; 2] = raw
                    .get(cursor..cursor + 2)
                    .and_then(|slice| slice.try_into().ok())
                    .ok_or(DurableError::Truncated {
                        expected_len: header_len,
                        actual_len: raw.len(),
                    })?;
                cursor += 2;
                match self.endianness {
                    Endianness::BigEndian => u32::from(u16::from_be_bytes(bytes)),
                    Endianness::LittleEndian => u32::from(u16::from_le_bytes(bytes)),
                }
            }
            VersionWidth::U32 => {
                let bytes: [u8; 4] = raw
                    .get(cursor..cursor + 4)
                    .and_then(|slice| slice.try_into().ok())
                    .ok_or(DurableError::Truncated {
                        expected_len: header_len,
                        actual_len: raw.len(),
                    })?;
                cursor += 4;
                match self.endianness {
                    Endianness::BigEndian => u32::from_be_bytes(bytes),
                    Endianness::LittleEndian => u32::from_le_bytes(bytes),
                }
            }
        };
        if version < self.min_version || version > self.max_version {
            return Err(DurableError::UnknownVersion {
                expected_min: self.min_version,
                expected_max: self.max_version,
                actual: version,
            });
        }

        // Tag field (if configured)
        let tag = if let Some(expected_tag) = self.tag_field {
            let bytes: [u8; 2] = raw
                .get(cursor..cursor + 2)
                .and_then(|slice| slice.try_into().ok())
                .ok_or(DurableError::Truncated {
                    expected_len: header_len,
                    actual_len: raw.len(),
                })?;
            cursor += 2;
            let actual_tag = match self.endianness {
                Endianness::BigEndian => u16::from_be_bytes(bytes),
                Endianness::LittleEndian => u16::from_le_bytes(bytes),
            };
            if actual_tag != expected_tag {
                return Err(DurableError::UnsupportedTag {
                    expected: expected_tag,
                    actual: actual_tag,
                });
            }
            Some(actual_tag)
        } else {
            None
        };

        // Length
        let declared_payload_len = match self.length_width {
            LengthWidth::U32 => {
                let bytes: [u8; 4] = raw
                    .get(cursor..cursor + 4)
                    .and_then(|slice| slice.try_into().ok())
                    .ok_or(DurableError::Truncated {
                        expected_len: header_len,
                        actual_len: raw.len(),
                    })?;
                cursor += 4;
                let val = match self.endianness {
                    Endianness::BigEndian => u32::from_be_bytes(bytes),
                    Endianness::LittleEndian => u32::from_le_bytes(bytes),
                };
                val as usize
            }
            LengthWidth::U64 => {
                let bytes: [u8; 8] = raw
                    .get(cursor..cursor + 8)
                    .and_then(|slice| slice.try_into().ok())
                    .ok_or(DurableError::Truncated {
                        expected_len: header_len,
                        actual_len: raw.len(),
                    })?;
                cursor += 8;
                let val = match self.endianness {
                    Endianness::BigEndian => u64::from_be_bytes(bytes),
                    Endianness::LittleEndian => u64::from_le_bytes(bytes),
                };
                if val > (usize::MAX as u64) {
                    return Err(DurableError::OverLimitLength {
                        limit: self.max_payload_len,
                        actual: usize::MAX,
                    });
                }
                val as usize
            }
        };

        // Checksum if stored in header
        let recorded_checksum = if self.checksum_placement == ChecksumPlacement::Header {
            let bytes: [u8; CHECKSUM_LEN] = raw
                .get(cursor..cursor + CHECKSUM_LEN)
                .and_then(|slice| slice.try_into().ok())
                .ok_or(DurableError::Truncated {
                    expected_len: header_len,
                    actual_len: raw.len(),
                })?;
            Some(ContentDigest::new(self.checksum_algorithm, bytes))
        } else {
            None
        };

        Ok(DurableHeader {
            magic: self.magic.clone(),
            version,
            tag,
            declared_payload_len,
            recorded_checksum,
            header_len,
        })
    }

    /// Decodes and semantically validates the envelope header without allocating memory for the payload.
    pub fn decode_header(&self, raw: &[u8]) -> Result<DurableHeader, DurableError> {
        let header = self.decode_header_raw(raw)?;
        if header.declared_payload_len > self.max_payload_len {
            return Err(DurableError::OverLimitLength {
                limit: self.max_payload_len,
                actual: header.declared_payload_len,
            });
        }
        Ok(header)
    }

    /// Decodes and verifies a complete durable envelope from bytes, borrowing the payload without allocations.
    pub fn decode<'a>(&self, raw: &'a [u8]) -> Result<DurableFrame<'a>, DurableError> {
        let header = self.decode_header(raw)?;
        let trailer_len = self.trailer_len();

        let expected_total_len = header
            .header_len
            .checked_add(header.declared_payload_len)
            .and_then(|len| len.checked_add(trailer_len))
            .ok_or(DurableError::OverLimitLength {
                limit: self.max_payload_len,
                actual: usize::MAX,
            })?;

        if raw.len() < expected_total_len {
            return Err(DurableError::Truncated {
                expected_len: expected_total_len,
                actual_len: raw.len(),
            });
        }

        if raw.len() > expected_total_len {
            return Err(DurableError::TrailingBytes {
                expected_len: expected_total_len,
                actual_len: raw.len(),
            });
        }

        let payload_start = header.header_len;
        let payload_end = payload_start + header.declared_payload_len;
        let payload = raw
            .get(payload_start..payload_end)
            .ok_or(DurableError::Truncated {
                expected_len: expected_total_len,
                actual_len: raw.len(),
            })?;

        let (recorded, computed) = match self.checksum_placement {
            ChecksumPlacement::Header => {
                let recorded = header.recorded_checksum.ok_or(DurableError::Truncated {
                    expected_len: expected_total_len,
                    actual_len: raw.len(),
                })?;
                let computed = match self.checksum_scope {
                    ChecksumScope::PayloadOnly => ContentDigest::sha256(payload),
                    ChecksumScope::HeaderAndPayload => {
                        let mut hasher = Sha256Hasher::new();
                        let header_before_checksum = raw
                            .get(..header.header_len.saturating_sub(CHECKSUM_LEN))
                            .unwrap_or(&[]);
                        hasher.update(header_before_checksum);
                        hasher.update(payload);
                        let digest_bytes = hasher
                            .finalize()
                            .map_err(|_| DurableError::DigestComputationFailed)?;
                        ContentDigest::new(DigestAlgorithm::Sha256, digest_bytes)
                    }
                };
                (recorded, computed)
            }
            ChecksumPlacement::Trailer => {
                let trailer_start = expected_total_len.saturating_sub(CHECKSUM_LEN);
                let trailer_bytes: [u8; CHECKSUM_LEN] = raw
                    .get(trailer_start..expected_total_len)
                    .and_then(|slice| slice.try_into().ok())
                    .ok_or(DurableError::Truncated {
                        expected_len: expected_total_len,
                        actual_len: raw.len(),
                    })?;
                let recorded = ContentDigest::new(self.checksum_algorithm, trailer_bytes);
                let computed = match self.checksum_scope {
                    ChecksumScope::PayloadOnly => ContentDigest::sha256(payload),
                    ChecksumScope::HeaderAndPayload => {
                        let body = raw.get(..trailer_start).unwrap_or(&[]);
                        ContentDigest::sha256(body)
                    }
                };
                (recorded, computed)
            }
        };

        if recorded != computed {
            return Err(DurableError::ChecksumMismatch {
                expected: recorded,
                actual: computed,
            });
        }

        Ok(DurableFrame {
            version: header.version,
            tag: header.tag,
            checksum: recorded,
            payload,
        })
    }

    /// Verifies the entire envelope and returns the borrowed payload slice.
    pub fn decode_payload<'a>(&self, raw: &'a [u8]) -> Result<&'a [u8], DurableError> {
        let frame = self.decode(raw)?;
        Ok(frame.payload)
    }

    /// Verifies the complete envelope for structural and cryptographic validity.
    pub fn verify(&self, raw: &[u8]) -> Result<(), DurableError> {
        let _ = self.decode(raw)?;
        Ok(())
    }

    /// Verifies the complete envelope and asserts that the recorded/computed checksum matches expected.
    pub fn verify_with_expected_checksum(
        &self,
        raw: &[u8],
        expected: ContentDigest,
    ) -> Result<(), DurableError> {
        let frame = self.decode(raw)?;
        if frame.checksum != expected {
            return Err(DurableError::ChecksumMismatch {
                expected,
                actual: frame.checksum,
            });
        }
        Ok(())
    }

    /// Encodes one payload using an explicit format version into a complete durable envelope.
    pub fn encode_version(&self, version: u32, payload: &[u8]) -> Result<Vec<u8>, DurableError> {
        if version < self.min_version || version > self.max_version {
            return Err(DurableError::UnknownVersion {
                expected_min: self.min_version,
                expected_max: self.max_version,
                actual: version,
            });
        }
        if (self.length_width == LengthWidth::U32 && payload.len() > u32::MAX as usize)
            || payload.len() > self.max_payload_len
        {
            return Err(DurableError::OverLimitLength {
                limit: self.max_payload_len,
                actual: payload.len(),
            });
        }

        let header_len = self.header_len();
        let trailer_len = self.trailer_len();
        let total_len = header_len
            .checked_add(payload.len())
            .and_then(|len| len.checked_add(trailer_len))
            .ok_or(DurableError::OverLimitLength {
                limit: self.max_payload_len,
                actual: payload.len(),
            })?;

        let mut out = Vec::with_capacity(total_len);

        // 1. Magic
        out.extend_from_slice(&self.magic);

        // 2. Version
        match self.version_width {
            VersionWidth::U16 => {
                let val = version as u16;
                match self.endianness {
                    Endianness::BigEndian => out.extend_from_slice(&val.to_be_bytes()),
                    Endianness::LittleEndian => out.extend_from_slice(&val.to_le_bytes()),
                }
            }
            VersionWidth::U32 => {
                let val = version;
                match self.endianness {
                    Endianness::BigEndian => out.extend_from_slice(&val.to_be_bytes()),
                    Endianness::LittleEndian => out.extend_from_slice(&val.to_le_bytes()),
                }
            }
        }

        // 3. Tag field (if configured)
        if let Some(tag) = self.tag_field {
            match self.endianness {
                Endianness::BigEndian => out.extend_from_slice(&tag.to_be_bytes()),
                Endianness::LittleEndian => out.extend_from_slice(&tag.to_le_bytes()),
            }
        }

        // 4. Declared length
        match self.length_width {
            LengthWidth::U32 => {
                let val = payload.len() as u32;
                match self.endianness {
                    Endianness::BigEndian => out.extend_from_slice(&val.to_be_bytes()),
                    Endianness::LittleEndian => out.extend_from_slice(&val.to_le_bytes()),
                }
            }
            LengthWidth::U64 => {
                let val = payload.len() as u64;
                match self.endianness {
                    Endianness::BigEndian => out.extend_from_slice(&val.to_be_bytes()),
                    Endianness::LittleEndian => out.extend_from_slice(&val.to_le_bytes()),
                }
            }
        }

        // 5. Header checksum (if Header placement)
        if self.checksum_placement == ChecksumPlacement::Header {
            let digest = match self.checksum_scope {
                ChecksumScope::PayloadOnly => ContentDigest::sha256(payload),
                ChecksumScope::HeaderAndPayload => {
                    let mut hasher = Sha256Hasher::new();
                    hasher.update(&out);
                    hasher.update(payload);
                    let digest_bytes = hasher
                        .finalize()
                        .map_err(|_| DurableError::DigestComputationFailed)?;
                    ContentDigest::new(DigestAlgorithm::Sha256, digest_bytes)
                }
            };
            out.extend_from_slice(&digest.bytes());
        }

        // 6. Payload
        out.extend_from_slice(payload);

        // 7. Trailer checksum (if Trailer placement)
        if self.checksum_placement == ChecksumPlacement::Trailer {
            let digest = match self.checksum_scope {
                ChecksumScope::PayloadOnly => ContentDigest::sha256(payload),
                ChecksumScope::HeaderAndPayload => ContentDigest::sha256(&out),
            };
            out.extend_from_slice(&digest.bytes());
        }

        Ok(out)
    }

    /// Encodes one payload into a complete durable envelope using the maximum supported version.
    pub fn encode(&self, payload: &[u8]) -> Result<Vec<u8>, DurableError> {
        self.encode_version(self.max_version, payload)
    }

    /// Encodes a payload with an explicit/pre-computed checksum using an explicit format version.
    pub fn encode_version_with_checksum(
        &self,
        version: u32,
        payload: &[u8],
        checksum: ContentDigest,
    ) -> Result<Vec<u8>, DurableError> {
        if version < self.min_version || version > self.max_version {
            return Err(DurableError::UnknownVersion {
                expected_min: self.min_version,
                expected_max: self.max_version,
                actual: version,
            });
        }
        if (self.length_width == LengthWidth::U32 && payload.len() > u32::MAX as usize)
            || payload.len() > self.max_payload_len
        {
            return Err(DurableError::OverLimitLength {
                limit: self.max_payload_len,
                actual: payload.len(),
            });
        }

        let header_len = self.header_len();
        let trailer_len = self.trailer_len();
        let total_len = header_len
            .checked_add(payload.len())
            .and_then(|len| len.checked_add(trailer_len))
            .ok_or(DurableError::OverLimitLength {
                limit: self.max_payload_len,
                actual: payload.len(),
            })?;

        let mut out = Vec::with_capacity(total_len);

        out.extend_from_slice(&self.magic);

        match self.version_width {
            VersionWidth::U16 => {
                let val = version as u16;
                match self.endianness {
                    Endianness::BigEndian => out.extend_from_slice(&val.to_be_bytes()),
                    Endianness::LittleEndian => out.extend_from_slice(&val.to_le_bytes()),
                }
            }
            VersionWidth::U32 => {
                let val = version;
                match self.endianness {
                    Endianness::BigEndian => out.extend_from_slice(&val.to_be_bytes()),
                    Endianness::LittleEndian => out.extend_from_slice(&val.to_le_bytes()),
                }
            }
        }

        if let Some(tag) = self.tag_field {
            match self.endianness {
                Endianness::BigEndian => out.extend_from_slice(&tag.to_be_bytes()),
                Endianness::LittleEndian => out.extend_from_slice(&tag.to_le_bytes()),
            }
        }

        match self.length_width {
            LengthWidth::U32 => {
                let val = payload.len() as u32;
                match self.endianness {
                    Endianness::BigEndian => out.extend_from_slice(&val.to_be_bytes()),
                    Endianness::LittleEndian => out.extend_from_slice(&val.to_le_bytes()),
                }
            }
            LengthWidth::U64 => {
                let val = payload.len() as u64;
                match self.endianness {
                    Endianness::BigEndian => out.extend_from_slice(&val.to_be_bytes()),
                    Endianness::LittleEndian => out.extend_from_slice(&val.to_le_bytes()),
                }
            }
        }

        if self.checksum_placement == ChecksumPlacement::Header {
            out.extend_from_slice(&checksum.bytes());
        }

        out.extend_from_slice(payload);

        if self.checksum_placement == ChecksumPlacement::Trailer {
            out.extend_from_slice(&checksum.bytes());
        }

        Ok(out)
    }

    /// Encodes a payload with an explicit/pre-computed checksum into a complete durable envelope using the maximum supported version.
    pub fn encode_with_checksum(
        &self,
        payload: &[u8],
        checksum: ContentDigest,
    ) -> Result<Vec<u8>, DurableError> {
        self.encode_version_with_checksum(self.max_version, payload, checksum)
    }
}

/// Builder for configuring [`DurableFormat`] specifications.
#[derive(Clone, Debug)]
pub struct DurableFormatBuilder {
    magic: Vec<u8>,
    min_version: u32,
    max_version: u32,
    version_width: VersionWidth,
    length_width: LengthWidth,
    endianness: Endianness,
    checksum_placement: ChecksumPlacement,
    checksum_scope: ChecksumScope,
    checksum_algorithm: DigestAlgorithm,
    tag_field: Option<u16>,
    max_payload_len: usize,
}

impl DurableFormatBuilder {
    /// Initializes builder with format magic prefix bytes.
    #[must_use]
    pub fn new(magic: &[u8]) -> Self {
        Self {
            magic: magic.to_vec(),
            min_version: 1,
            max_version: 1,
            version_width: VersionWidth::U32,
            length_width: LengthWidth::U64,
            endianness: Endianness::BigEndian,
            checksum_placement: ChecksumPlacement::Trailer,
            checksum_scope: ChecksumScope::HeaderAndPayload,
            checksum_algorithm: DigestAlgorithm::Sha256,
            tag_field: None,
            max_payload_len: DEFAULT_MAX_PAYLOAD_LEN,
        }
    }

    /// Sets single supported format version.
    #[must_use]
    pub const fn version(mut self, version: u32) -> Self {
        self.min_version = version;
        self.max_version = version;
        self
    }

    /// Sets supported version range.
    #[must_use]
    pub const fn version_range(mut self, min: u32, max: u32) -> Self {
        self.min_version = min;
        self.max_version = max;
        self
    }

    /// Sets bit-width of version field.
    #[must_use]
    pub const fn version_width(mut self, width: VersionWidth) -> Self {
        self.version_width = width;
        self
    }

    /// Sets bit-width of payload length field.
    #[must_use]
    pub const fn length_width(mut self, width: LengthWidth) -> Self {
        self.length_width = width;
        self
    }

    /// Sets integer endianness.
    #[must_use]
    pub const fn endianness(mut self, endianness: Endianness) -> Self {
        self.endianness = endianness;
        self
    }

    /// Sets placement of checksum (Header or Trailer).
    #[must_use]
    pub const fn checksum_placement(mut self, placement: ChecksumPlacement) -> Self {
        self.checksum_placement = placement;
        self
    }

    /// Sets byte scope covered by checksum.
    #[must_use]
    pub const fn checksum_scope(mut self, scope: ChecksumScope) -> Self {
        self.checksum_scope = scope;
        self
    }

    /// Sets checksum algorithm.
    #[must_use]
    pub const fn checksum_algorithm(mut self, algorithm: DigestAlgorithm) -> Self {
        self.checksum_algorithm = algorithm;
        self
    }

    /// Sets optional format tag (e.g. algorithm discriminator in header).
    #[must_use]
    pub const fn tag_field(mut self, tag: Option<u16>) -> Self {
        self.tag_field = tag;
        self
    }

    /// Sets maximum permitted payload length.
    #[must_use]
    pub const fn max_payload_len(mut self, max: usize) -> Self {
        self.max_payload_len = max;
        self
    }

    /// Finalizes and builds the [`DurableFormat`].
    pub fn build(self) -> Result<DurableFormat, DurableError> {
        if self.min_version > self.max_version {
            return Err(DurableError::InvalidFormat {
                reason: "min_version exceeds max_version in version_range",
            });
        }
        if self.version_width == VersionWidth::U16 && self.max_version > u16::MAX as u32 {
            return Err(DurableError::InvalidFormat {
                reason: "version exceeds u16::MAX for VersionWidth::U16",
            });
        }
        if self.length_width == LengthWidth::U32 && self.max_payload_len > u32::MAX as usize {
            return Err(DurableError::InvalidFormat {
                reason: "max_payload_len exceeds u32::MAX for LengthWidth::U32",
            });
        }
        if self.checksum_scope == ChecksumScope::PayloadOnly {
            if self.min_version != self.max_version {
                return Err(DurableError::InvalidFormat {
                    reason: "PayloadOnly checksum scope does not authenticate header fields across a version range; use HeaderAndPayload",
                });
            }
            if self.checksum_placement == ChecksumPlacement::Trailer {
                return Err(DurableError::InvalidFormat {
                    reason: "PayloadOnly checksum scope with Trailer placement leaves header unauthenticated; use HeaderAndPayload",
                });
            }
        }
        Ok(DurableFormat {
            magic: self.magic,
            min_version: self.min_version,
            max_version: self.max_version,
            version_width: self.version_width,
            length_width: self.length_width,
            endianness: self.endianness,
            checksum_placement: self.checksum_placement,
            checksum_scope: self.checksum_scope,
            checksum_algorithm: self.checksum_algorithm,
            tag_field: self.tag_field,
            max_payload_len: self.max_payload_len,
        })
    }
}
