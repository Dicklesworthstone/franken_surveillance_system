#![forbid(unsafe_code)]

use super::AvcError;

/// Borrowed EBSP reader. No full-NAL copy is needed to inspect a slice prefix.
/// Escape validation is performed for the bytes actually consumed. Parameter-set
/// parsing consumes the complete RBSP; slice identity leaves macroblocks opaque.
#[derive(Clone)]
pub(super) struct Bits<'a> {
    bytes: &'a [u8],
    next_byte: usize,
    current: u8,
    left: u8,
    zero_run: u8,
    consumed: usize,
    ceiling: usize,
}

impl<'a> Bits<'a> {
    pub(super) fn new(bytes: &'a [u8], ceiling: usize) -> Self {
        Self {
            bytes,
            next_byte: 0,
            current: 0,
            left: 0,
            zero_run: 0,
            consumed: 0,
            ceiling,
        }
    }

    fn byte(&mut self) -> Result<u8, AvcError> {
        let mut value = *self.bytes.get(self.next_byte).ok_or(AvcError::Truncated)?;
        self.next_byte += 1;
        if self.zero_run == 2 {
            if value == 3 {
                value = *self.bytes.get(self.next_byte).ok_or(AvcError::Truncated)?;
                if value > 3 {
                    return Err(AvcError::Malformed);
                }
                self.next_byte += 1;
                // The escape interrupts the encoded zero run. The escaped byte
                // starts the next run; counting decoded zeros would be wrong.
                self.zero_run = 0;
            } else if value <= 2 {
                return Err(AvcError::Malformed);
            }
        }
        self.zero_run = if value == 0 { self.zero_run + 1 } else { 0 };
        Ok(value)
    }

    pub(super) fn bit(&mut self) -> Result<bool, AvcError> {
        if self.consumed == self.ceiling {
            return Err(AvcError::Limit);
        }
        if self.left == 0 {
            self.current = self.byte()?;
            self.left = 8;
        }
        self.left -= 1;
        self.consumed += 1;
        Ok((self.current >> self.left) & 1 != 0)
    }

    pub(super) fn uint(&mut self, width: u8) -> Result<u32, AvcError> {
        if width > 32 {
            return Err(AvcError::Limit);
        }
        let mut value = 0;
        for _ in 0..width {
            value = (value << 1) | u32::from(self.bit()?);
        }
        Ok(value)
    }

    pub(super) fn ue(&mut self, max: u32) -> Result<u32, AvcError> {
        let mut zeros = 0;
        while !self.bit()? {
            zeros += 1;
            // All supported syntax ranges fit a 31-zero Exp-Golomb prefix.
            // Bound work before shifting, adding, or looking for an absent one.
            if zeros > 31 || ((1_u64 << zeros) - 1) > u64::from(max) {
                return Err(AvcError::Limit);
            }
        }
        let value = ((1_u64 << zeros) - 1) + u64::from(self.uint(zeros)?);
        if value > u64::from(max) {
            return Err(AvcError::Limit);
        }
        Ok(value as u32)
    }

    pub(super) fn se(&mut self, min: i32, max: i32) -> Result<i32, AvcError> {
        let code = self.ue(u32::MAX - 1)?;
        let value = if code & 1 == 1 {
            (i64::from(code) + 1) / 2
        } else {
            -(i64::from(code) / 2)
        };
        if value < i64::from(min) || value > i64::from(max) {
            return Err(AvcError::Limit);
        }
        Ok(value as i32)
    }

    pub(super) fn consumed(&self) -> usize {
        self.consumed
    }

    /// Exact rbsp_stop_one_bit, zero alignment, and no suffix bytes.
    pub(super) fn finish(&mut self) -> Result<(), AvcError> {
        if !self.bit()? {
            return Err(AvcError::Malformed);
        }
        while self.left != 0 {
            if self.bit()? {
                return Err(AvcError::Malformed);
            }
        }
        if self.next_byte != self.bytes.len() {
            return Err(AvcError::Malformed);
        }
        Ok(())
    }

    /// PPS extensions are present unless the *entire* remainder is trailing bits.
    pub(super) fn more_data(&self) -> bool {
        let mut probe = self.clone();
        probe.finish().is_err()
    }
}
