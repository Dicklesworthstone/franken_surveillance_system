#![forbid(unsafe_code)]
//! Bounded baseline Huffman output; partially encoded data never escapes this module.

use crate::tables::{self, Code};
use crate::transform::ZIGZAG;
use crate::{EncodeBudget, EncodeError};

pub(crate) struct Output {
    bytes: Vec<u8>,
    maximum: usize,
    pending: u32,
    bits: u8,
}

impl Output {
    pub fn new(maximum: usize) -> Self {
        Self { bytes: Vec::new(), maximum, pending: 0, bits: 0 }
    }

    pub fn raw(&mut self, bytes: &[u8], budget: &mut EncodeBudget<'_>) -> Result<(), EncodeError> {
        let needed = self.bytes.len().checked_add(bytes.len()).ok_or(EncodeError::Limit)?;
        if needed > self.maximum {
            return Err(EncodeError::Limit);
        }
        budget.charge(bytes.len() as u64)?;
        if needed > self.bytes.capacity() {
            let capacity = self.bytes.capacity();
            let target = needed.max(capacity.saturating_mul(2).max(4096)).min(self.maximum);
            self.bytes.try_reserve_exact(target - self.bytes.len()).map_err(|_| EncodeError::Allocation)?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    pub fn marker(&mut self, marker: u8, budget: &mut EncodeBudget<'_>) -> Result<(), EncodeError> {
        self.raw(&[0xff, marker], budget)
    }

    pub fn segment(&mut self, marker: u8, bytes: &[u8], budget: &mut EncodeBudget<'_>) -> Result<(), EncodeError> {
        let length = bytes.len().checked_add(2).and_then(|n| u16::try_from(n).ok()).ok_or(EncodeError::Limit)?;
        self.marker(marker, budget)?;
        self.raw(&length.to_be_bytes(), budget)?;
        self.raw(bytes, budget)
    }

    fn bits(&mut self, value: u16, count: u8, budget: &mut EncodeBudget<'_>) -> Result<(), EncodeError> {
        if count == 0 || count > 16 || u32::from(value) >= 1_u32 << count {
            return Err(EncodeError::CoefficientRange);
        }
        self.pending = (self.pending << count) | u32::from(value);
        self.bits += count;
        while self.bits >= 8 {
            self.bits -= 8;
            let byte = (self.pending >> self.bits) as u8;
            self.raw(&[byte], budget)?;
            if byte == 0xff {
                self.raw(&[0], budget)?;
            }
        }
        self.pending &= (1_u32 << self.bits) - 1;
        Ok(())
    }

    fn symbol(&mut self, table: &[Code; 256], value: u8, budget: &mut EncodeBudget<'_>) -> Result<(), EncodeError> {
        let code = table[usize::from(value)];
        self.bits(code.bits, code.width, budget)
    }

    pub fn block(&mut self, coefficients: &[i16; 64], previous_dc: &mut i16, chroma: bool, budget: &mut EncodeBudget<'_>) -> Result<(), EncodeError> {
        let (dc, ac) = if chroma { (&tables::CHROMA_DC, &tables::CHROMA_AC) } else { (&tables::LUMA_DC, &tables::LUMA_AC) };
        let difference = i32::from(coefficients[0]) - i32::from(*previous_dc);
        let (width, bits) = amplitude(difference)?;
        if width > 11 {
            return Err(EncodeError::CoefficientRange);
        }
        self.symbol(dc, width, budget)?;
        if width != 0 {
            self.bits(bits, width, budget)?;
        }
        let mut zeros = 0_u8;
        for &index in &ZIGZAG[1..] {
            let value = i32::from(coefficients[index]);
            if value == 0 {
                zeros += 1;
                continue;
            }
            while zeros >= 16 {
                self.symbol(ac, 0xf0, budget)?;
                zeros -= 16;
            }
            let (width, bits) = amplitude(value)?;
            if width > 10 {
                return Err(EncodeError::CoefficientRange);
            }
            self.symbol(ac, (zeros << 4) | width, budget)?;
            self.bits(bits, width, budget)?;
            zeros = 0;
        }
        if zeros != 0 {
            self.symbol(ac, 0, budget)?;
        }
        *previous_dc = coefficients[0];
        Ok(())
    }

    pub fn finish(mut self, budget: &mut EncodeBudget<'_>) -> Result<Vec<u8>, EncodeError> {
        if self.bits != 0 {
            let padding = 8 - self.bits;
            self.bits((1_u16 << padding) - 1, padding, budget)?;
        }
        self.marker(0xd9, budget)?;
        Ok(self.bytes)
    }
}

fn amplitude(value: i32) -> Result<(u8, u16), EncodeError> {
    if value == 0 {
        return Ok((0, 0));
    }
    if !(-2047..=2047).contains(&value) {
        return Err(EncodeError::CoefficientRange);
    }
    let magnitude = value.unsigned_abs();
    let width = (32 - magnitude.leading_zeros()) as u8;
    let bits = if value > 0 { magnitude } else { ((1_u32 << width) - 1) ^ magnitude };
    Ok((width, bits as u16))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_ff_is_stuffed_and_final_padding_is_ones() -> Result<(), EncodeError> {
        let mut budget = EncodeBudget::new(100);
        let mut output = Output::new(100);
        output.bits(0xff, 8, &mut budget)?;
        output.bits(0b101, 3, &mut budget)?;
        assert_eq!(output.finish(&mut budget)?, [0xff, 0, 0xbf, 0xff, 0xd9]);
        assert_eq!(budget.used(), 5);
        Ok(())
    }

    #[test]
    fn negative_amplitudes_are_ones_complement_and_dc_is_differential() -> Result<(), EncodeError> {
        assert_eq!(amplitude(-1)?, (1, 0));
        assert_eq!(amplitude(-2)?, (2, 1));
        assert_eq!(amplitude(-3)?, (2, 0));
        assert_eq!(amplitude(1023)?, (10, 1023));
        assert_eq!(amplitude(-2040)?, (11, 7));
        assert_eq!(amplitude(2048), Err(EncodeError::CoefficientRange));
        Ok(())
    }
}
