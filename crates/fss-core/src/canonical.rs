//! Deterministic binary encoding used for semantic fingerprints.

use crate::ContentDigest;

/// A deterministic length-prefixed binary encoder.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CanonicalEncoder {
    bytes: Vec<u8>,
}

impl CanonicalEncoder {
    /// Creates an empty encoder.
    #[must_use]
    pub const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Appends a one-byte field discriminator.
    pub fn tag(&mut self, value: u8) {
        self.bytes.push(value);
    }

    /// Appends an unsigned 8-bit value.
    pub fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    /// Appends an unsigned 32-bit value in network byte order.
    pub fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends an unsigned 64-bit value in network byte order.
    pub fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends a signed 128-bit value in network byte order.
    pub fn i128(&mut self, value: i128) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends a Boolean value.
    pub fn bool(&mut self, value: bool) {
        self.bytes.push(u8::from(value));
    }

    /// Appends bytes with a 64-bit length prefix.
    pub fn bytes(&mut self, value: &[u8]) {
        self.u64(value.len() as u64);
        self.bytes.extend_from_slice(value);
    }

    /// Appends UTF-8 text with a 64-bit byte-length prefix.
    pub fn text(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    /// Appends a digest with an explicit algorithm discriminator.
    pub fn digest(&mut self, value: ContentDigest) {
        self.tag(match value.algorithm() {
            crate::DigestAlgorithm::Sha256 => 1,
            crate::DigestAlgorithm::Blake3 => 2,
        });
        self.bytes.extend_from_slice(&value.bytes());
    }

    /// Returns the accumulated canonical bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

/// A value with a stable canonical byte representation.
pub trait CanonicalEncode {
    /// Appends this value's canonical representation.
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder);

    /// Returns this value's canonical bytes.
    #[must_use]
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        encoder.finish()
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

impl CanonicalEncode for ContentDigest {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.digest(*self);
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
}
