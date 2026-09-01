use std::fmt;

const INITIAL_STATE: [u32; 8] = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
];

const ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest([u8; 32]);

impl Digest {
    pub const ZERO: Self = Self([0; 32]);

    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestError {
    InputTooLarge,
    FieldTooLarge,
}

impl fmt::Display for DigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InputTooLarge => "input exceeds the SHA-256 length domain",
            Self::FieldTooLarge => "canonical field length exceeds u64",
        })
    }
}

impl std::error::Error for DigestError {}

#[derive(Debug, Default, Clone)]
pub struct CanonicalWriter {
    bytes: Vec<u8>,
}

impl CanonicalWriter {
    #[must_use]
    pub fn new(domain: &str) -> Result<Self, DigestError> {
        let mut writer = Self::default();
        writer.push_bytes(domain.as_bytes())?;
        Ok(writer)
    }

    pub fn push_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub fn push_bool(&mut self, value: bool) {
        self.push_u8(u8::from(value));
    }

    pub fn push_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub fn push_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub fn push_digest(&mut self, value: Digest) {
        self.bytes.extend_from_slice(&value.as_bytes());
    }

    pub fn push_str(&mut self, value: &str) -> Result<(), DigestError> {
        self.push_bytes(value.as_bytes())
    }

    pub fn push_bytes(&mut self, value: &[u8]) -> Result<(), DigestError> {
        let length = u64::try_from(value.len()).map_err(|_| DigestError::FieldTooLarge)?;
        self.push_u64(length);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }

    pub fn digest(self) -> Result<Digest, DigestError> {
        sha256(&self.bytes)
    }
}

pub fn domain_digest(domain: &str, payload: &[u8]) -> Result<Digest, DigestError> {
    let mut writer = CanonicalWriter::new("fss-domain-digest-v1")?;
    writer.push_str(domain)?;
    writer.push_bytes(payload)?;
    writer.digest()
}

pub fn sha256(input: &[u8]) -> Result<Digest, DigestError> {
    let byte_length = u64::try_from(input.len()).map_err(|_| DigestError::InputTooLarge)?;
    let bit_length = byte_length
        .checked_mul(8)
        .ok_or(DigestError::InputTooLarge)?;
    let mut state = INITIAL_STATE;
    let mut chunks = input.chunks_exact(64);
    for chunk in &mut chunks {
        let block: &[u8; 64] = chunk.try_into().expect("chunks_exact yields 64-byte blocks");
        compress(&mut state, block);
    }

    let remainder = chunks.remainder();
    let final_len = if remainder.len() < 56 { 64 } else { 128 };
    let mut final_blocks = [0_u8; 128];
    final_blocks[..remainder.len()].copy_from_slice(remainder);
    final_blocks[remainder.len()] = 0x80;
    final_blocks[final_len - 8..final_len].copy_from_slice(&bit_length.to_be_bytes());
    for chunk in final_blocks[..final_len].chunks_exact(64) {
        let block: &[u8; 64] = chunk.try_into().expect("final padding uses 64-byte blocks");
        compress(&mut state, block);
    }

    let mut output = [0_u8; 32];
    for (index, word) in state.into_iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    Ok(Digest(output))
}

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut schedule = [0_u32; 64];
    for (index, word) in block.chunks_exact(4).enumerate() {
        schedule[index] = u32::from_be_bytes(word.try_into().expect("four-byte word"));
    }
    for index in 16..64 {
        let s0 = schedule[index - 15].rotate_right(7)
            ^ schedule[index - 15].rotate_right(18)
            ^ (schedule[index - 15] >> 3);
        let s1 = schedule[index - 2].rotate_right(17)
            ^ schedule[index - 2].rotate_right(19)
            ^ (schedule[index - 2] >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(s0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for index in 0..64 {
        let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choice = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(sum1)
            .wrapping_add(choice)
            .wrapping_add(ROUND_CONSTANTS[index])
            .wrapping_add(schedule[index]);
        let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = sum0.wrapping_add(majority);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[cfg(test)]
mod tests {
    use super::{CanonicalWriter, domain_digest, sha256};

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256(b"").expect("digest").to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256(b"abc").expect("digest").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256(&vec![b'a'; 1_000_000]).expect("digest").to_hex(),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn canonical_fields_are_unambiguous() {
        let mut left = CanonicalWriter::new("test").expect("writer");
        left.push_str("ab").expect("field");
        left.push_str("c").expect("field");
        let mut right = CanonicalWriter::new("test").expect("writer");
        right.push_str("a").expect("field");
        right.push_str("bc").expect("field");
        assert_ne!(left.digest().expect("digest"), right.digest().expect("digest"));
    }

    #[test]
    fn domains_are_separated() {
        assert_ne!(
            domain_digest("source", b"same").expect("source digest"),
            domain_digest("event", b"same").expect("event digest")
        );
    }
}
