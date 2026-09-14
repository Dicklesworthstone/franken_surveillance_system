//! Deterministic binary encoding used for semantic fingerprints.

use crate::{ContentDigest, ContractError};

/// Maximum byte length allowed for a single canonical text string (64 KiB).
pub const MAX_CANONICAL_TEXT_BYTES: usize = 65_536;

/// Maximum byte length allowed for a single canonical byte slice (16 MiB).
pub const MAX_CANONICAL_BYTES_LEN: usize = 16 * 1024 * 1024;

/// Canonical format magic header for versioned binary envelopes.
pub const CANONICAL_FORMAT_MAGIC: [u8; 4] = *b"FSSC";

/// Current canonical envelope format version.
pub const CANONICAL_VERSION_1: u16 = 1;

/// A deterministic length-prefixed binary encoder.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CanonicalEncoder {
    bytes: Vec<u8>,
    error: Option<ContractError>,
}

impl CanonicalEncoder {
    /// Creates an empty encoder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            error: None,
        }
    }

    /// Returns true if an error has occurred during encoding (e.g. text/bytes over-bound).
    #[must_use]
    pub const fn has_error(&self) -> bool {
        self.error.is_some()
    }

    /// Returns the recorded encoding error if any.
    #[must_use]
    pub fn error(&self) -> Option<&ContractError> {
        self.error.as_ref()
    }

    /// Appends a one-byte field discriminator.
    pub fn tag(&mut self, value: u8) {
        if self.error.is_some() {
            return;
        }
        self.bytes.push(value);
    }

    /// Appends an unsigned 8-bit value.
    pub fn u8(&mut self, value: u8) {
        self.tag(value);
    }

    /// Appends an unsigned 32-bit value in network byte order.
    pub fn u32(&mut self, value: u32) {
        if self.error.is_some() {
            return;
        }
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends an unsigned 64-bit value in network byte order.
    pub fn u64(&mut self, value: u64) {
        if self.error.is_some() {
            return;
        }
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends a signed 128-bit value in network byte order (standard two's complement big-endian).
    ///
    /// NOTE: Standard two's complement big-endian does NOT preserve lexicographical byte order
    /// across negative and positive values (e.g. `-1` encodes as `0xFF...FF` which is byte-wise
    /// greater than `+1` as `0x00...01`). Do NOT rely on raw canonical byte sorting for signed values;
    /// sort using typed `TimestampNs` or `i128` values before encoding.
    pub fn i128(&mut self, value: i128) {
        if self.error.is_some() {
            return;
        }
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends a Boolean value.
    pub fn bool(&mut self, value: bool) {
        self.tag(u8::from(value));
    }

    /// Appends bytes with a 64-bit length prefix.
    ///
    /// Fails closed if `value.len() > MAX_CANONICAL_BYTES_LEN`.
    pub fn bytes(&mut self, value: &[u8]) {
        if self.error.is_some() {
            return;
        }
        if value.len() > MAX_CANONICAL_BYTES_LEN {
            self.error = Some(ContractError::InvalidDigest);
            return;
        }
        self.u64(value.len() as u64);
        self.bytes.extend_from_slice(value);
    }

    /// Appends UTF-8 text with a 64-bit byte-length prefix.
    ///
    /// Fails closed if `value.len() > MAX_CANONICAL_TEXT_BYTES`.
    pub fn text(&mut self, value: &str) {
        if self.error.is_some() {
            return;
        }
        if value.len() > MAX_CANONICAL_TEXT_BYTES {
            self.error = Some(ContractError::InvalidIdentifier);
            return;
        }
        self.bytes(value.as_bytes());
    }

    /// Attempts to append bytes with a 64-bit length prefix, returning an error if over bound.
    pub fn try_bytes(&mut self, value: &[u8]) -> Result<(), ContractError> {
        if value.len() > MAX_CANONICAL_BYTES_LEN {
            self.error = Some(ContractError::InvalidDigest);
            return Err(ContractError::InvalidDigest);
        }
        self.bytes(value);
        Ok(())
    }

    /// Attempts to append UTF-8 text with a 64-bit length prefix, returning an error if over bound.
    pub fn try_text(&mut self, value: &str) -> Result<(), ContractError> {
        if value.len() > MAX_CANONICAL_TEXT_BYTES {
            self.error = Some(ContractError::InvalidIdentifier);
            return Err(ContractError::InvalidIdentifier);
        }
        self.text(value);
        Ok(())
    }

    /// Appends a digest with an explicit algorithm discriminator.
    pub fn digest(&mut self, value: ContentDigest) {
        if self.error.is_some() {
            return;
        }
        self.tag(match value.algorithm() {
            crate::DigestAlgorithm::Sha256 => 1,
            crate::DigestAlgorithm::Blake3 => 2,
        });
        self.bytes.extend_from_slice(&value.bytes());
    }

    /// Records an encoding failure for encoders that cannot represent a value.
    ///
    /// The first recorded error wins; later writes are ignored and [`Self::finish_checked`]
    /// returns the error instead of a partial encoding.
    pub(crate) fn fail(&mut self, error: ContractError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }

    /// Returns the accumulated canonical bytes, failing closed to an empty vector if an error occurred.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        if self.error.is_some() {
            Vec::new()
        } else {
            self.bytes
        }
    }

    /// Returns the accumulated canonical bytes or the error that occurred during encoding.
    pub fn finish_checked(self) -> Result<Vec<u8>, ContractError> {
        if let Some(err) = self.error {
            Err(err)
        } else {
            Ok(self.bytes)
        }
    }
}

/// A deterministic length-prefixed binary decoder matching [`CanonicalEncoder`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
    /// Set once any read failed because fewer bytes remained than it needed.
    hit_eof: bool,
}

impl<'a> CanonicalDecoder<'a> {
    /// Creates a decoder over the given bytes.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            hit_eof: false,
        }
    }

    /// Returns true once any read failed because fewer bytes remained than it needed (end of
    /// input). The error each read returns is unchanged; a caller may use this to name a plain
    /// truncation at its own decode boundary.
    #[must_use]
    pub const fn hit_end_of_input(&self) -> bool {
        self.hit_eof
    }

    /// Returns the current read offset in bytes.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Returns remaining unread bytes.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    /// Returns true if all bytes have been consumed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Ensures that all bytes were consumed, returning error on trailing unparsed bytes.
    pub fn ensure_finished(&self) -> Result<(), ContractError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(ContractError::NonCanonicalOrdering)
        }
    }

    /// Decodes a 1-byte discriminator tag.
    pub fn tag(&mut self) -> Result<u8, ContractError> {
        if self.remaining() < 1 {
            self.hit_eof = true;
            return Err(ContractError::InvalidDigest);
        }
        let val = self.bytes[self.offset];
        self.offset += 1;
        Ok(val)
    }

    /// Decodes an unsigned 8-bit value.
    pub fn u8(&mut self) -> Result<u8, ContractError> {
        self.tag()
    }

    /// Decodes an unsigned 32-bit value in network byte order.
    pub fn u32(&mut self) -> Result<u32, ContractError> {
        self.read_u32()
    }

    /// Decodes an unsigned 32-bit value in network byte order.
    pub fn read_u32(&mut self) -> Result<u32, ContractError> {
        if self.remaining() < 4 {
            self.hit_eof = true;
            return Err(ContractError::InvalidDigest);
        }
        let slice: [u8; 4] = self.bytes[self.offset..self.offset + 4]
            .try_into()
            .map_err(|_| ContractError::InvalidDigest)?;
        self.offset += 4;
        Ok(u32::from_be_bytes(slice))
    }

    /// Decodes an unsigned 64-bit value in network byte order.
    pub fn u64(&mut self) -> Result<u64, ContractError> {
        if self.remaining() < 8 {
            self.hit_eof = true;
            return Err(ContractError::InvalidDigest);
        }
        let slice: [u8; 8] = self.bytes[self.offset..self.offset + 8]
            .try_into()
            .map_err(|_| ContractError::InvalidDigest)?;
        self.offset += 8;
        Ok(u64::from_be_bytes(slice))
    }

    /// Decodes a signed 128-bit value in network byte order.
    pub fn i128(&mut self) -> Result<i128, ContractError> {
        if self.remaining() < 16 {
            self.hit_eof = true;
            return Err(ContractError::InvalidDigest);
        }
        let slice: [u8; 16] = self.bytes[self.offset..self.offset + 16]
            .try_into()
            .map_err(|_| ContractError::InvalidDigest)?;
        self.offset += 16;
        Ok(i128::from_be_bytes(slice))
    }

    /// Decodes a Boolean value. Returns error if byte is neither 0 nor 1.
    pub fn bool(&mut self) -> Result<bool, ContractError> {
        match self.tag()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }

    /// Decodes bytes prefixed with a 64-bit length.
    pub fn bytes(&mut self) -> Result<&'a [u8], ContractError> {
        let len_u64 = self.u64()?;
        let len = usize::try_from(len_u64).map_err(|_| ContractError::InvalidDigest)?;
        if len > MAX_CANONICAL_BYTES_LEN {
            return Err(ContractError::InvalidDigest);
        }
        if self.remaining() < len {
            self.hit_eof = true;
            return Err(ContractError::InvalidDigest);
        }
        let slice = &self.bytes[self.offset..self.offset + len];
        self.offset += len;
        Ok(slice)
    }

    /// Decodes UTF-8 text prefixed with a 64-bit byte-length.
    pub fn text(&mut self) -> Result<&'a str, ContractError> {
        let raw = self.bytes()?;
        if raw.len() > MAX_CANONICAL_TEXT_BYTES {
            return Err(ContractError::InvalidIdentifier);
        }
        core::str::from_utf8(raw).map_err(|_| ContractError::InvalidIdentifier)
    }

    /// Decodes a digest with algorithm discriminator.
    pub fn digest(&mut self) -> Result<ContentDigest, ContractError> {
        let algo_tag = self.tag()?;
        let algo = match algo_tag {
            1 => crate::DigestAlgorithm::Sha256,
            2 => crate::DigestAlgorithm::Blake3,
            _ => return Err(ContractError::UnsupportedDigestAlgorithm),
        };
        if self.remaining() < 32 {
            self.hit_eof = true;
            return Err(ContractError::InvalidDigest);
        }
        let digest_bytes: [u8; 32] = self.bytes[self.offset..self.offset + 32]
            .try_into()
            .map_err(|_| ContractError::InvalidDigest)?;
        self.offset += 32;
        Ok(ContentDigest::new(algo, digest_bytes))
    }
}

/// A value with a stable canonical byte representation.
pub trait CanonicalEncode {
    /// Appends this value's canonical representation.
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder);

    /// Serializes self to canonical bytes.
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        encoder.finish()
    }

    /// Serializes self to canonical bytes, verifying encoder limits.
    fn try_canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        encoder.finish_checked()
    }

    /// Computes a domain-separated SHA-256 semantic fingerprint.
    #[must_use]
    fn canonical_digest(&self, domain: &str) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.canonical.v1");
        encoder.text(domain);
        self.encode_canonical(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }
}

/// A value that can be deterministically decoded from canonical bytes.
pub trait CanonicalDecode: Sized {
    /// Decodes a value from the canonical decoder.
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError>;

    /// Decodes a value from a complete canonical byte slice, verifying no trailing bytes.
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        let mut decoder = CanonicalDecoder::new(bytes);
        let value = Self::decode_canonical(&mut decoder)?;
        decoder.ensure_finished()?;
        Ok(value)
    }
}

impl CanonicalEncode for ContentDigest {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.digest(*self);
    }
}

impl CanonicalDecode for ContentDigest {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        decoder.digest()
    }
}

impl CanonicalEncode for str {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self);
    }
}

impl CanonicalEncode for String {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self);
    }
}

impl CanonicalDecode for String {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        decoder.text().map(ToOwned::to_owned)
    }
}

impl CanonicalEncode for u8 {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(*self);
    }
}

impl CanonicalDecode for u8 {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        decoder.u8()
    }
}

impl CanonicalEncode for u32 {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(*self);
    }
}

impl CanonicalDecode for u32 {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        decoder.u32()
    }
}

impl CanonicalEncode for u64 {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(*self);
    }
}

impl CanonicalDecode for u64 {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        decoder.u64()
    }
}

impl CanonicalEncode for i128 {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.i128(*self);
    }
}

impl CanonicalDecode for i128 {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        decoder.i128()
    }
}

impl CanonicalEncode for bool {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.bool(*self);
    }
}

impl CanonicalDecode for bool {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        decoder.bool()
    }
}

/// A versioned wrapper for canonical objects enforcing fail-closed unknown-version behavior.
///
/// Follows non-negotiable rule INV-059: "Canonical durable bytes use hand-written versioned
/// formats with magic, limits, canonical ordering, checksums, and migration fixtures; serde
/// layout is never the format."
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalVersionEnvelope<T> {
    /// Format version number.
    pub version: u16,
    /// Encoded payload.
    pub payload: T,
}

impl<T> CanonicalVersionEnvelope<T> {
    /// Magic header bytes for canonical version envelopes.
    pub const MAGIC: [u8; 4] = CANONICAL_FORMAT_MAGIC;
    /// Current supported format version.
    pub const CURRENT_VERSION: u16 = CANONICAL_VERSION_1;

    /// Wraps a payload with the current format version.
    #[must_use]
    pub const fn new(payload: T) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            payload,
        }
    }

    /// Wraps a payload with an explicit format version.
    #[must_use]
    pub const fn with_version(version: u16, payload: T) -> Self {
        Self { version, payload }
    }
}

impl<T: CanonicalEncode> CanonicalVersionEnvelope<T> {
    /// Encodes the envelope canonically.
    pub fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.bytes(&Self::MAGIC);
        encoder.u32(self.version as u32);
        self.payload.encode_canonical(encoder);
    }

    /// Returns canonical binary bytes for this envelope.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        encoder.finish()
    }
}

impl<T: CanonicalDecode> CanonicalVersionEnvelope<T> {
    /// Decodes a versioned envelope, enforcing supported version bounds.
    ///
    /// If the version is unknown / outside `[min_supported, max_supported]`,
    /// it fails closed with [`ContractError::InvalidAnchorSuccessor`].
    pub fn decode_canonical_bounded(
        decoder: &mut CanonicalDecoder<'_>,
        min_supported: u16,
        max_supported: u16,
    ) -> Result<Self, ContractError> {
        let magic = decoder.bytes()?;
        if magic != Self::MAGIC {
            return Err(ContractError::InvalidDigest);
        }
        let version_u32 = decoder.read_u32()?;
        let version = u16::try_from(version_u32).map_err(|_| ContractError::InvalidDigest)?;
        if version < min_supported || version > max_supported {
            return Err(ContractError::InvalidAnchorSuccessor);
        }
        let payload = T::decode_canonical(decoder)?;
        Ok(Self { version, payload })
    }

    /// Decodes a versioned envelope from a complete byte slice, enforcing supported versions.
    pub fn from_canonical_bytes_bounded(
        bytes: &[u8],
        min_supported: u16,
        max_supported: u16,
    ) -> Result<Self, ContractError> {
        let mut decoder = CanonicalDecoder::new(bytes);
        let envelope = Self::decode_canonical_bounded(&mut decoder, min_supported, max_supported)?;
        decoder.ensure_finished()?;
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_is_length_delimited() {
        let mut first = CanonicalEncoder::new();
        first.text("ab");
        first.text("c");
        let mut second = CanonicalEncoder::new();
        second.text("a");
        second.text("bc");
        assert_ne!(first.finish(), second.finish());
    }

    #[test]
    fn round_trip_primitives() -> Result<(), ContractError> {
        let mut encoder = CanonicalEncoder::new();
        encoder.u8(42);
        encoder.u32(1337);
        encoder.u64(987_654_321);
        encoder.i128(-555_123_456_789);
        encoder.bool(true);
        encoder.text("stable_fss_id");
        let bytes = encoder.finish();

        let mut decoder = CanonicalDecoder::new(&bytes);
        assert_eq!(decoder.u8()?, 42);
        assert_eq!(decoder.read_u32()?, 1337);
        assert_eq!(decoder.u64()?, 987_654_321);
        assert_eq!(decoder.i128()?, -555_123_456_789);
        assert!(decoder.bool()?);
        assert_eq!(decoder.text()?, "stable_fss_id");
        decoder.ensure_finished()?;
        Ok(())
    }

    #[test]
    fn trailing_bytes_rejected() -> Result<(), ContractError> {
        let mut encoder = CanonicalEncoder::new();
        encoder.u32(10);
        encoder.u8(99);
        let bytes = encoder.finish();

        let mut decoder = CanonicalDecoder::new(&bytes);
        assert_eq!(decoder.read_u32()?, 10);
        assert_eq!(
            decoder.ensure_finished(),
            Err(ContractError::NonCanonicalOrdering)
        );
        Ok(())
    }

    #[test]
    fn boolean_invalid_byte_rejected() {
        let bytes = [2_u8];
        let mut decoder = CanonicalDecoder::new(&bytes);
        assert_eq!(decoder.bool(), Err(ContractError::InvalidIdentifier));
    }

    #[test]
    fn version_envelope_rejects_unknown_version() -> Result<(), ContractError> {
        let envelope = CanonicalVersionEnvelope::with_version(999, "payload".to_owned());
        let bytes = envelope.canonical_bytes();

        let result = CanonicalVersionEnvelope::<String>::from_canonical_bytes_bounded(&bytes, 1, 1);
        assert_eq!(result, Err(ContractError::InvalidAnchorSuccessor));
        Ok(())
    }

    #[test]
    fn version_envelope_accepts_supported_version() -> Result<(), ContractError> {
        let envelope = CanonicalVersionEnvelope::new("payload".to_owned());
        let bytes = envelope.canonical_bytes();

        let decoded =
            CanonicalVersionEnvelope::<String>::from_canonical_bytes_bounded(&bytes, 1, 1)?;
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.payload, "payload");
        Ok(())
    }
}
