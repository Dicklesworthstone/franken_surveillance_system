//! Bounds-checked bit reader over RBSP bytes with the exp-Golomb mappings
//! of ITU-T H.265 clause 9.2: unsigned (`ue(v)`), signed (`se(v)`), and
//! fixed-width unsigned reads (`u(n)`).
//!
//! Every read is limit-checked against the construction bound; no method
//! panics and no method reads past `bit_limit`. The CABAC engine reads its
//! bits through the same reader, so a truncated slice ends in a typed
//! [`DecodeError::Limit`], never an out-of-bounds access.

use crate::DecodeError;

/// A bit-position reader over a shared RBSP slice.
#[derive(Clone, Copy, Debug)]
pub struct BitReader<'a> {
    bytes: &'a [u8],
    bit_limit: usize,
    position: usize,
}

impl<'a> BitReader<'a> {
    /// Bounds the reader to `bit_limit` bits of `bytes` (callers pass
    /// `bytes.len() * 8` unless a narrower bound is known). A bound beyond
    /// the slice is clamped to the slice.
    #[must_use]
    pub fn new(bytes: &'a [u8], bit_limit: usize) -> Self {
        Self {
            bytes,
            bit_limit: bit_limit.min(bytes.len().saturating_mul(8)),
            position: 0,
        }
    }

    /// Bits consumed so far.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.position
    }

    /// The bound this reader enforces.
    #[must_use]
    pub const fn bit_limit(&self) -> usize {
        self.bit_limit
    }

    /// True when no bits remain within the bound.
    #[must_use]
    pub const fn exhausted(&self) -> bool {
        self.position >= self.bit_limit
    }

    /// True when the position is on a byte boundary.
    #[must_use]
    pub const fn byte_aligned(&self) -> bool {
        self.position & 7 == 0
    }

    /// Bits left before the bound.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.bit_limit.saturating_sub(self.position)
    }

    /// Advances to the next byte boundary (no-op when aligned).
    ///
    /// # Errors
    /// [`DecodeError::Limit`] when the boundary lies past the bound.
    pub fn align(&mut self) -> Result<(), DecodeError> {
        let aligned = self.position.next_multiple_of(8);
        if aligned > self.bit_limit {
            return Err(DecodeError::Limit);
        }
        self.position = aligned;
        Ok(())
    }

    /// Skips `count` bits.
    ///
    /// # Errors
    /// [`DecodeError::Limit`] when fewer than `count` bits remain.
    pub fn skip(&mut self, count: usize) -> Result<(), DecodeError> {
        let end = self.position.checked_add(count).ok_or(DecodeError::Limit)?;
        if end > self.bit_limit {
            return Err(DecodeError::Limit);
        }
        self.position = end;
        Ok(())
    }

    /// Reads one flag bit as a boolean.
    ///
    /// # Errors
    /// [`DecodeError::Limit`] when the bound is exhausted.
    pub fn flag(&mut self) -> Result<bool, DecodeError> {
        Ok(self.bit()? == 1)
    }

    /// Reads one bit.
    ///
    /// # Errors
    /// [`DecodeError::Limit`] when the bound is exhausted.
    pub fn bit(&mut self) -> Result<u8, DecodeError> {
        if self.position >= self.bit_limit {
            return Err(DecodeError::Limit);
        }
        let byte = *self
            .bytes
            .get(self.position >> 3)
            .ok_or(DecodeError::Limit)?;
        let shift = 7 - (self.position & 7);
        self.position += 1;
        Ok((byte >> shift) & 1)
    }

    /// Reads `count` bits MSB-first as an unsigned integer (`count <= 32`).
    ///
    /// # Errors
    /// [`DecodeError::Limit`] when fewer than `count` bits remain;
    /// [`DecodeError::Malformed`] when `count` exceeds 32.
    pub fn uint(&mut self, count: u32) -> Result<u32, DecodeError> {
        if count > 32 {
            return Err(DecodeError::Malformed);
        }
        let mut value: u32 = 0;
        for _ in 0..count {
            value = (value << 1) | u32::from(self.bit()?);
        }
        Ok(value)
    }

    /// Reads one unsigned exp-Golomb symbol capped at `cap`.
    ///
    /// # Errors
    /// [`DecodeError::Limit`] when the bits run out;
    /// [`DecodeError::Malformed`] when the decoded value exceeds `cap`.
    pub fn ue(&mut self, cap: u32) -> Result<u32, DecodeError> {
        let mut leading_zeros: u32 = 0;
        while self.bit()? == 0 {
            leading_zeros += 1;
            if leading_zeros >= 32 {
                return Err(DecodeError::Malformed);
            }
        }
        if leading_zeros == 0 {
            return Ok(0);
        }
        let suffix = self.uint(leading_zeros)?;
        let value = u64::from((1u32 << leading_zeros) - 1) + u64::from(suffix);
        let value = u32::try_from(value).map_err(|_| DecodeError::Malformed)?;
        if value > cap {
            return Err(DecodeError::Malformed);
        }
        Ok(value)
    }

    /// Reads one signed exp-Golomb symbol that must lie in `min..=max`.
    ///
    /// # Errors
    /// [`DecodeError::Malformed`] when the value is outside the range;
    /// [`DecodeError::Limit`] on bound exhaustion.
    pub fn se(&mut self, min: i32, max: i32) -> Result<i32, DecodeError> {
        let magnitude = min.unsigned_abs().max(max.unsigned_abs());
        let raw = self.ue(magnitude.saturating_mul(2))?;
        // Clause 9.2.2: k -> (-1)^(k+1) * Ceil(k / 2).
        let half = i64::from(raw.div_ceil(2));
        let value = if raw & 1 == 1 { half } else { -half };
        let value = i32::try_from(value).map_err(|_| DecodeError::Malformed)?;
        if value < min || value > max {
            return Err(DecodeError::Malformed);
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack(code: &str) -> (Vec<u8>, usize) {
        let bits: Vec<u8> = code
            .bytes()
            .filter(|b| *b != b' ')
            .map(|b| b - b'0')
            .collect();
        let len = bits.len();
        let mut padded = bits;
        while !padded.len().is_multiple_of(8) {
            padded.push(0);
        }
        let bytes = padded
            .chunks(8)
            .map(|chunk| chunk.iter().fold(0u8, |acc, &b| (acc << 1) | b))
            .collect();
        (bytes, len)
    }

    /// Table 9-2 codewords: "1" -> 0, "010" -> 1, "011" -> 2,
    /// "00100" -> 3, "00111" -> 6, "0001000" -> 7.
    #[test]
    fn exp_golomb_table_9_2_codewords() {
        let (bytes, len) = pack("1 010 011 00100 00111 0001000");
        let mut reader = BitReader::new(&bytes, len);
        for expected in [0, 1, 2, 3, 6, 7] {
            assert_eq!(reader.ue(u32::MAX), Ok(expected));
        }
        assert!(reader.exhausted());
    }

    /// Table 9-3 mapping: k = 0, 1, 2, 3, 4 -> 0, 1, -1, 2, -2.
    #[test]
    fn signed_mapping_table_9_3() {
        let (bytes, len) = pack("1 010 011 00100 00101");
        let mut reader = BitReader::new(&bytes, len);
        for expected in [0, 1, -1, 2, -2] {
            assert_eq!(reader.se(-26, 25), Ok(expected));
        }
        let (bytes, len) = pack("00101");
        let mut reader = BitReader::new(&bytes, len);
        assert_eq!(reader.se(-1, 1), Err(DecodeError::Malformed));
    }

    #[test]
    fn caps_and_bounds_are_enforced() {
        let (bytes, len) = pack("00100");
        assert_eq!(
            BitReader::new(&bytes, len).ue(2),
            Err(DecodeError::Malformed)
        );
        let (bytes, _) = pack("010");
        let mut reader = BitReader::new(&bytes, 2);
        assert_eq!(reader.ue(31), Err(DecodeError::Limit));
        assert_eq!(reader.position(), 2);
        let mut reader = BitReader::new(&[0xB0], 4);
        assert_eq!(reader.uint(4), Ok(0b1011));
        assert_eq!(reader.uint(33), Err(DecodeError::Malformed));
        // A bound past the slice is clamped to the slice.
        let reader = BitReader::new(&[0xFF], 64);
        assert_eq!(reader.bit_limit(), 8);
    }

    #[test]
    fn align_and_skip_respect_the_bound() {
        let bytes = [0xFF, 0x00];
        let mut reader = BitReader::new(&bytes, 16);
        assert_eq!(reader.skip(3), Ok(()));
        assert_eq!(reader.align(), Ok(()));
        assert_eq!(reader.position(), 8);
        assert_eq!(reader.align(), Ok(()));
        assert_eq!(reader.position(), 8);
        assert_eq!(reader.skip(9), Err(DecodeError::Limit));
        let mut short = BitReader::new(&bytes, 10);
        assert_eq!(short.skip(9), Ok(()));
        assert_eq!(short.align(), Err(DecodeError::Limit));
    }
}
