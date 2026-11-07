#![forbid(unsafe_code)]
//! Small checked EBML encodings; callers own IDs and all admitted payload lengths.

use super::MatroskaGrayError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Buffer<const N: usize> {
    bytes: [u8; N],
    length: usize,
}

impl<const N: usize> Buffer<N> {
    pub(super) const fn new() -> Self {
        Self { bytes: [0; N], length: 0 }
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    pub(super) fn append(&mut self, bytes: &[u8]) -> Result<(), MatroskaGrayError> {
        let end = self.length.checked_add(bytes.len()).ok_or(MatroskaGrayError::Layout)?;
        self.bytes.get_mut(self.length..end).ok_or(MatroskaGrayError::Layout)?
            .copy_from_slice(bytes);
        self.length = end;
        Ok(())
    }

    pub(super) fn header(&mut self, id: &[u8], size: usize) -> Result<(), MatroskaGrayError> {
        self.append(id)?;
        let width = size_width(size)?;
        let value = u64::try_from(size).map_err(|_| MatroskaGrayError::Layout)?;
        let encoded = ((1_u64 << (7 * width)) | value).to_be_bytes();
        self.append(&encoded[8 - width..])
    }

    pub(super) fn element(&mut self, id: &[u8], value: &[u8]) -> Result<(), MatroskaGrayError> {
        self.header(id, value.len())?;
        self.append(value)
    }

    pub(super) fn unsigned(&mut self, id: &[u8], value: u64) -> Result<(), MatroskaGrayError> {
        let encoded = value.to_be_bytes();
        self.element(id, &encoded[8 - integer_width(value)..])
    }
}

fn integer_width(value: u64) -> usize {
    ((u64::BITS - value.leading_zeros()) as usize).div_ceil(8).max(1)
}

fn size_width(size: usize) -> Result<usize, MatroskaGrayError> {
    let size = u64::try_from(size).map_err(|_| MatroskaGrayError::Layout)?;
    for width in 1..=8 {
        // All-one data bits denote unknown size, never a finite element length.
        if size < (1_u64 << (7 * width)) - 1 {
            return Ok(width);
        }
    }
    Err(MatroskaGrayError::Layout)
}

pub(super) fn element_len(id_bytes: usize, payload: usize) -> Result<usize, MatroskaGrayError> {
    id_bytes.checked_add(size_width(payload)?)
        .and_then(|size| size.checked_add(payload)).ok_or(MatroskaGrayError::Layout)
}

pub(super) fn unsigned_len(id_bytes: usize, value: u64) -> Result<usize, MatroskaGrayError> {
    element_len(id_bytes, integer_width(value))
}

#[cfg(test)]
mod tests {
    use super::{Buffer, MatroskaGrayError, size_width};

    #[test]
    fn finite_sizes_skip_the_reserved_unknown_values() -> Result<(), MatroskaGrayError> {
        for (size, expected) in [
            (0, &[0xa1, 0x80][..]),
            (126, &[0xa1, 0xfe][..]),
            (127, &[0xa1, 0x40, 0x7f][..]),
            (16382, &[0xa1, 0x7f, 0xfe][..]),
            (16383, &[0xa1, 0x20, 0x3f, 0xff][..]),
            (2097150, &[0xa1, 0x3f, 0xff, 0xfe][..]),
            (2097151, &[0xa1, 0x10, 0x1f, 0xff, 0xff][..]),
        ] {
            let mut header = Buffer::<9>::new();
            header.header(&[0xa1], size)?;
            assert_eq!(header.bytes(), expected);
        }
        if usize::BITS >= 64 {
            let maximum = ((1_u64 << 56) - 2) as usize;
            assert_eq!(size_width(maximum), Ok(8));
            assert_eq!(size_width(maximum + 1), Err(MatroskaGrayError::Layout));
        }
        Ok(())
    }

    #[test]
    fn fixed_storage_and_unsigned_integer_boundaries_are_checked() -> Result<(), MatroskaGrayError> {
        for (value, expected) in [
            (0, &[0xe7, 0x81, 0x00][..]),
            (255, &[0xe7, 0x81, 0xff][..]),
            (256, &[0xe7, 0x82, 0x01, 0x00][..]),
            (u64::MAX, &[0xe7, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..]),
        ] {
            let mut buffer = Buffer::<10>::new();
            buffer.unsigned(&[0xe7], value)?;
            assert_eq!(buffer.bytes(), expected);
            assert_eq!(buffer.append(&[0; 11]), Err(MatroskaGrayError::Layout));
            assert_eq!(buffer.bytes(), expected);
        }
        Ok(())
    }
}
