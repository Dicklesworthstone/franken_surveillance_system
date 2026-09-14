#![forbid(unsafe_code)]
use crate::DecodeError;

pub(crate) struct Reader<'a> { pub bytes: &'a [u8], pub pos: usize }
impl<'a> Reader<'a> {
    pub fn take(&mut self, count: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(count).ok_or(DecodeError::Limit)?;
        let data = self.bytes.get(self.pos..end).ok_or(DecodeError::Truncated)?;
        self.pos = end; Ok(data)
    }
    pub fn byte(&mut self) -> Result<u8, DecodeError> { Ok(self.take(1)?[0]) }
    pub fn marker(&mut self) -> Result<u8, DecodeError> {
        if self.byte()? != 255 { return Err(DecodeError::Malformed); }
        let mut value = self.byte()?;
        while value == 255 { value = self.byte()?; }
        if value == 0 { return Err(DecodeError::Malformed); }
        Ok(value)
    }
    pub fn segment(&mut self) -> Result<&'a [u8], DecodeError> {
        let length = self.take(2)?;
        let count = usize::from(u16::from_be_bytes([length[0],length[1]]));
        self.take(count.checked_sub(2).ok_or(DecodeError::Malformed)?)
    }
}

/// Canonical Huffman codes, with the all-ones word excluded at every length.
pub(crate) struct Huffman {
    first: [u32; 16],
    offset: [usize; 16],
    count: [u8; 16],
    values: Vec<u8>,
}
impl Huffman {
    pub fn new(count: [u8; 16], values: &[u8], ac: bool) -> Result<Self, DecodeError> {
        let total = count.iter().map(|v| usize::from(*v)).sum::<usize>();
        if total == 0 || total > 256 || total != values.len() { return Err(DecodeError::Malformed); }
        let mut seen = [false; 256];
        for &value in values {
            if seen[value as usize] || (!ac && value > 11)
                || (ac && ((value & 15) > 10 || (value & 15 == 0 && value != 0 && value != 240))) {
                return Err(DecodeError::Malformed);
            }
            seen[value as usize] = true;
        }
        let mut first = [0; 16]; let mut offset = [0; 16];
        let mut code = 0_u32; let mut used = 0;
        for i in 0..16 {
            let n = u32::from(count[i]);
            if code+n >= 1_u32 << (i+1) { return Err(DecodeError::Malformed); }
            first[i] = code; offset[i] = used; used += usize::from(count[i]);
            code = (code+n)*2;
        }
        let mut owned = Vec::new();
        owned.try_reserve_exact(total).map_err(|_| DecodeError::Limit)?;
        owned.extend_from_slice(values);
        Ok(Self { first, offset, count, values: owned })
    }
    pub fn symbol(&self, input: &mut Bits<'_, '_>) -> Result<u8, DecodeError> {
        let mut code = 0;
        for i in 0..16 {
            code = code*2+input.read(1)?;
            if code >= self.first[i] && code-self.first[i] < u32::from(self.count[i]) {
                return self.values.get(self.offset[i]+(code-self.first[i]) as usize)
                    .copied().ok_or(DecodeError::Malformed);
            }
        }
        Err(DecodeError::Malformed)
    }
}

/// No speculative reads: the cursor stops before each following marker.
pub(crate) struct Bits<'a, 'b> { pub reader: &'b mut Reader<'a>, byte: u8, left: u8 }
impl<'a, 'b> Bits<'a, 'b> {
    pub fn new(reader: &'b mut Reader<'a>) -> Self { Self { reader, byte: 0, left: 0 } }
    pub fn read(&mut self, count: u8) -> Result<u32, DecodeError> {
        let mut value = 0;
        for _ in 0..count {
            if self.left == 0 {
                self.byte = self.reader.byte()?;
                if self.byte == 255 && self.reader.byte()? != 0 { return Err(DecodeError::Malformed); }
                self.left = 8;
            }
            self.left -= 1;
            value = (value << 1) | u32::from((self.byte >> self.left) & 1);
        }
        Ok(value)
    }
    pub fn signed(&mut self, count: u8) -> Result<i32, DecodeError> {
        if count == 0 { return Ok(0); }
        let value = self.read(count)? as i32;
        Ok(if value < 1_i32 << (count-1) { value - ((1_i32 << count)-1) } else { value })
    }
    pub fn align(&mut self) -> Result<(), DecodeError> {
        let mask = (1_u16 << self.left)-1;
        if u16::from(self.byte) & mask != mask { return Err(DecodeError::Malformed); }
        self.left = 0; Ok(())
    }
    pub fn restart(&mut self, expected: u8) -> Result<(), DecodeError> {
        self.align()?;
        if self.reader.marker()? != 0xd0+expected { return Err(DecodeError::Malformed); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stuffed_ff_is_data_but_marker_ff_is_not() -> Result<(),DecodeError> {
        let mut r = Reader { bytes: &[255,0,255,217], pos:0 };
        let mut bits = Bits::new(&mut r); assert_eq!(bits.read(8)?,255); bits.align()?;
        assert_eq!(bits.reader.marker()?,217);
        let mut r = Reader { bytes: &[255,217], pos:0 };
        assert_eq!(Bits::new(&mut r).read(8),Err(DecodeError::Malformed)); Ok(())
    }
    #[test]
    fn impossible_huffman_trees_and_categories_fail() {
        let mut counts = [0;16]; counts[0] = 2;
        assert!(Huffman::new(counts,&[0,1],false).is_err());
        counts[0] = 1;
        assert!(Huffman::new(counts,&[12],false).is_err());
        assert!(Huffman::new(counts,&[0x10],true).is_err());
        assert!(Huffman::new(counts,&[0x0b],true).is_err());
    }
}
