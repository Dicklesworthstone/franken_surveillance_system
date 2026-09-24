//! Bounds-checked bit reader over RBSP bytes with the H.264 coded-symbol
//! mappings: unsigned exp-Golomb (`ue`), signed exp-Golomb (`se`), and the
//! capped truncated mapping (`te`).
//!
//! Every read is limit-checked against the construction bound; no method
//! panics, no method reads past `bit_limit`. The reader is the single
//! low-level syntax surface this crate uses — `fss-packet` has its own
//! private reader for parameter sets, which stay the custody owner.

use crate::DecodeError;

/// A bit-position reader over a shared RBSP slice.
#[derive(Clone, Copy, Debug)]
pub struct BitReader<'a> {
    bytes: &'a [u8],
    bit_limit: usize,
    position: usize,
}

impl<'a> BitReader<'a> {
    /// Bounds the reader to `bit_limit` bits of `bytes` ( callers pass
    /// `bytes.len() * 8` unless a narrower bound is known).
    #[must_use]
    pub const fn new(bytes: &'a [u8], bit_limit: usize) -> Self {
        Self {
            bytes,
            bit_limit,
            position: 0,
        }
    }

    /// Bits consumed so far.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.position
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

    /// Reads one flag bit as a boolean.
    ///
    /// # Errors
    /// [`DecodeError::Limit`] when the bound is exhausted.
    pub fn flag(&mut self) -> Result<bool, DecodeError> {
        Ok(self.bit()? == 1)
    }

    /// Reads a truncated exp-Golomb `te(v)` symbol whose range is
    /// `0..=range` (clause 9.1.1): one inverted bit when `range == 1`,
    /// otherwise `ue(v)` capped at `range`.
    ///
    /// # Errors
    /// Same as [`Self::ue`]; `range == 0` is a caller error (Malformed).
    pub fn te(&mut self, range: u32) -> Result<u32, DecodeError> {
        match range {
            0 => Err(DecodeError::Malformed),
            1 => Ok(u32::from(self.bit()? ^ 1)),
            _ => self.ue(range),
        }
    }

    /// Reads one bit.
    ///
    /// # Errors
    /// [`DecodeError::Limit`] when the bound is exhausted.
    pub fn bit(&mut self) -> Result<u8, DecodeError> {
        if self.position >= self.bit_limit {
            return Err(DecodeError::Limit);
        }
        // A bound larger than the slice is a caller error; refuse it as a
        // limit rather than indexing out of range.
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
    pub fn uint(&mut self, count: u8) -> Result<u32, DecodeError> {
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
    /// [`DecodeError::Limit`] when the leading-zero run exceeds the bound;
    /// [`DecodeError::Malformed`] when the decoded value exceeds `cap`.
    pub fn ue(&mut self, cap: u32) -> Result<u32, DecodeError> {
        let mut leading_zeros: u32 = 0;
        while self.bit()? == 0 {
            leading_zeros += 1;
            // 32 or more leading zeros cannot encode a value below 2^32 - 1
            // (and `1 << 32` would overflow the codeNum arithmetic).
            if leading_zeros >= 32 {
                return Err(DecodeError::Malformed);
            }
        }
        if leading_zeros == 0 {
            return Ok(0);
        }
        if leading_zeros > cap {
            return Err(DecodeError::Malformed);
        }
        let suffix = self.uint(leading_zeros as u8)?;
        let value = (1u32 << leading_zeros) - 1 + suffix;
        if value > cap {
            return Err(DecodeError::Malformed);
        }
        Ok(value)
    }

    /// Reads one signed exp-Golomb symbol in `[-cap, cap]`.
    ///
    /// # Errors
    /// Same as [`Self::ue`], plus a value outside the symmetric cap.
    pub fn se(&mut self, cap: u32) -> Result<i32, DecodeError> {
        let raw = self.ue(cap)?;
        // Spec mapping: k = 2|v| for v <= 0, k = 2v - 1 for v > 0.
        let magnitude = raw.div_ceil(2);
        let signed: i32 = if raw & 1 == 1 {
            i32::try_from(magnitude).map_err(|_| DecodeError::Malformed)?
        } else {
            -i32::try_from(magnitude).map_err(|_| DecodeError::Malformed)?
        };
        Ok(signed)
    }

    /// Reads one signed exp-Golomb symbol that must lie in `min..=max`.
    ///
    /// # Errors
    /// [`DecodeError::Malformed`] when the value is outside the range;
    /// [`DecodeError::Limit`] on bound exhaustion.
    pub fn se_range(&mut self, min: i32, max: i32) -> Result<i32, DecodeError> {
        let magnitude = min.unsigned_abs().max(max.unsigned_abs());
        let value = self.se(magnitude.saturating_mul(2))?;
        if value < min || value > max {
            return Err(DecodeError::Malformed);
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// Clause 9.1 codeword goldens from Table 9-1: "1"→0, "010"→1,
    /// "011"→2, "00100"→3, then a trailing spare bit.
    #[test]
    fn spec_exp_golomb_sample_stream() {
        let data = [0b1010_0110, 0b0100_1000];
        let mut reader = BitReader::new(&data, 13);
        assert_eq!(reader.ue(31).unwrap(), 0);
        assert_eq!(reader.ue(31).unwrap(), 1);
        assert_eq!(reader.ue(31).unwrap(), 2);
        assert_eq!(reader.ue(31).unwrap(), 3);
        assert_eq!(reader.position(), 12);
        assert!(reader.bit().is_ok());
        assert!(reader.exhausted());
    }

    #[test]
    fn se_mapping_matches_spec() {
        // se(k): 0 -> 0, 1 -> 1, 2 -> -1, 3 -> 2, 4 -> -2 (Table 9-2 via 9-1).
        let mut bits = Vec::new();
        let mut push = |code: &str| {
            for bit in code.bytes() {
                bits.push(bit - b'0');
            }
        };
        push("1"); // ue 0 -> 0
        push("010"); // ue 1 -> +1
        push("011"); // ue 2 -> -1
        push("00100"); // ue 3 -> +2
        push("00101"); // ue 4 -> -2
        while !bits.len().is_multiple_of(8) {
            bits.push(0);
        }
        let data: Vec<u8> = bits
            .chunks(8)
            .map(|chunk| chunk.iter().fold(0u8, |acc, &b| (acc << 1) | b))
            .collect();
        let mut reader = BitReader::new(&data, bits.len());
        assert_eq!(reader.se(31).unwrap(), 0);
        assert_eq!(reader.se(31).unwrap(), 1);
        assert_eq!(reader.se(31).unwrap(), -1);
        assert_eq!(reader.se(31).unwrap(), 2);
        assert_eq!(reader.se(31).unwrap(), -2);
    }

    #[test]
    fn ue_cap_refuses_oversized_symbols() {
        // "00100" = 3; a cap of 2 must refuse it.
        let data = [0b0010_0000];
        let mut reader = BitReader::new(&data, 5);
        assert_eq!(reader.ue(2).unwrap_err(), DecodeError::Malformed);
    }

    #[test]
    fn bound_enforcement_never_reads_past_limit() {
        // "010" needs 3 bits; bound it to 2.
        let data = [0b0100_0000];
        let mut reader = BitReader::new(&data, 2);
        assert_eq!(reader.ue(31).unwrap_err(), DecodeError::Limit);
        assert_eq!(reader.position(), 2);
    }

    #[test]
    fn uint_reads_msb_first() {
        let data = [0b1011_0000];
        let mut reader = BitReader::new(&data, 4);
        assert_eq!(reader.uint(4).unwrap(), 0b1011);
    }
}
