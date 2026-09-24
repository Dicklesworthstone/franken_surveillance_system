//! CAVLC coding of macroblock-layer syntax elements (clauses 7.3.5, 9.1,
//! 9.2): Exp-Golomb mb_type / sub_mb_type / ref_idx / mvd / cbp, the
//! intra prediction mode fields, and CAVLC residual blocks.

use crate::DecodeError;
use crate::bits::BitReader;
use crate::cavlc::context_nc;
use crate::macroblock::{MbDecoder, ResidualBlock, SyntaxReader};
use crate::residual::{ResidualKind, decode_coefficients};
use crate::slice::SliceKind;

/// coded_block_pattern mapping for Intra_4x4 / Intra_8x8 macroblocks
/// (Table 9-4).
const CBP_INTRA: [u8; 48] = [
    47, 31, 15, 0, 23, 27, 29, 30, 7, 11, 13, 14, 39, 43, 45, 46, 16, 3, 5, 10, 12, 19, 21, 26, 28,
    35, 37, 42, 44, 1, 2, 4, 8, 17, 18, 20, 24, 6, 9, 22, 25, 32, 33, 34, 36, 40, 38, 41,
];
/// coded_block_pattern mapping for Inter macroblocks (Table 9-4).
const CBP_INTER: [u8; 48] = [
    0, 16, 1, 2, 4, 8, 32, 3, 5, 10, 12, 15, 47, 7, 11, 13, 14, 6, 9, 31, 35, 37, 42, 44, 33, 34,
    36, 40, 39, 43, 45, 46, 17, 18, 20, 24, 19, 21, 26, 28, 23, 27, 29, 30, 22, 25, 38, 41,
];

/// CAVLC syntax source over the slice's bit reader.
pub(crate) struct CavlcReader<'r, 'b> {
    reader: &'r mut BitReader<'b>,
}

impl<'r, 'b> CavlcReader<'r, 'b> {
    pub(crate) fn new(reader: &'r mut BitReader<'b>) -> Self {
        Self { reader }
    }
}

/// nC for a luma block (raster index) of the current macroblock.
fn luma_nc(mb: &MbDecoder<'_, '_, '_>, raster: usize) -> i32 {
    let left = mb.left_block(raster).map(|(info, blk)| info.nz[blk]);
    let above = mb.above_block(raster).map(|(info, blk)| info.nz[blk]);
    context_nc(left, above)
}

fn chroma_nc(mb: &MbDecoder<'_, '_, '_>, component: usize, blk: usize) -> i32 {
    let left = mb
        .left_chroma(blk)
        .map(|(info, b)| info.nz_chroma[component][b]);
    let above = mb
        .above_chroma(blk)
        .map(|(info, b)| info.nz_chroma[component][b]);
    context_nc(left, above)
}

impl SyntaxReader for CavlcReader<'_, '_> {
    fn is_cabac(&self) -> bool {
        false
    }

    fn mb_type(&mut self, mb: &MbDecoder<'_, '_, '_>) -> Result<u32, DecodeError> {
        let cap = match mb.ctx.header.kind {
            SliceKind::I => 25,
            SliceKind::P => 30,
            SliceKind::B => 48,
        };
        self.reader.ue(cap)
    }

    fn sub_mb_type(&mut self, kind: SliceKind) -> Result<u32, DecodeError> {
        self.reader.ue(if kind == SliceKind::B { 12 } else { 3 })
    }

    fn transform_8x8_flag(&mut self, _mb: &MbDecoder<'_, '_, '_>) -> Result<bool, DecodeError> {
        self.reader.flag()
    }

    fn intra_pred_mode(&mut self, predicted: u8) -> Result<u8, DecodeError> {
        if self.reader.flag()? {
            return Ok(predicted);
        }
        let rem = u8::try_from(self.reader.uint(3)?).map_err(|_| DecodeError::Malformed)?;
        Ok(if rem < predicted { rem } else { rem + 1 })
    }

    fn chroma_pred_mode(&mut self, _mb: &MbDecoder<'_, '_, '_>) -> Result<u8, DecodeError> {
        u8::try_from(self.reader.ue(3)?).map_err(|_| DecodeError::Malformed)
    }

    fn ref_idx(
        &mut self,
        _mb: &MbDecoder<'_, '_, '_>,
        _list: usize,
        _raster: usize,
        count: u32,
    ) -> Result<i8, DecodeError> {
        i8::try_from(self.reader.te(count - 1)?).map_err(|_| DecodeError::Malformed)
    }

    fn mvd(
        &mut self,
        _mb: &MbDecoder<'_, '_, '_>,
        _list: usize,
        _raster: usize,
        _component: usize,
    ) -> Result<i32, DecodeError> {
        self.reader.se_range(-32_768, 32_767)
    }

    fn cbp(&mut self, _mb: &MbDecoder<'_, '_, '_>, intra_nxn: bool) -> Result<u8, DecodeError> {
        let code = usize::try_from(self.reader.ue(47)?).map_err(|_| DecodeError::Malformed)?;
        Ok(if intra_nxn {
            CBP_INTRA[code]
        } else {
            CBP_INTER[code]
        })
    }

    fn qp_delta(&mut self) -> Result<i32, DecodeError> {
        self.reader.se_range(-26, 25)
    }

    fn no_qp_delta(&mut self) {}

    fn residual(
        &mut self,
        mb: &MbDecoder<'_, '_, '_>,
        block: ResidualBlock,
        out: &mut [i32; 64],
    ) -> Result<u8, DecodeError> {
        *out = [0; 64];
        let mut scan = [0i32; 16];
        let count = match block {
            ResidualBlock::LumaDc => {
                decode_coefficients(self.reader, ResidualKind::Max16, luma_nc(mb, 0), &mut scan)?
            }
            ResidualBlock::LumaAc(raster) => decode_coefficients(
                self.reader,
                ResidualKind::Max15,
                luma_nc(mb, raster),
                &mut scan,
            )?,
            ResidualBlock::Luma4x4(raster) => decode_coefficients(
                self.reader,
                ResidualKind::Max16,
                luma_nc(mb, raster),
                &mut scan,
            )?,
            ResidualBlock::ChromaDc(_) => {
                decode_coefficients(self.reader, ResidualKind::ChromaDC, -1, &mut scan)?
            }
            ResidualBlock::ChromaAc(component, blk) => decode_coefficients(
                self.reader,
                ResidualKind::Max15,
                chroma_nc(mb, component, blk),
                &mut scan,
            )?,
            // CAVLC codes 8x8 blocks as four interleaved 4x4 blocks.
            ResidualBlock::Luma8x8(_) => return Err(DecodeError::Malformed),
        };
        out[..16].copy_from_slice(&scan);
        Ok(count)
    }

    fn pcm(&mut self) -> Result<[u8; 384], DecodeError> {
        while !self.reader.byte_aligned() {
            if self.reader.bit()? != 0 {
                return Err(DecodeError::Malformed);
            }
        }
        let mut samples = [0u8; 384];
        for sample in &mut samples {
            *sample = u8::try_from(self.reader.uint(8)?).map_err(|_| DecodeError::Malformed)?;
        }
        Ok(samples)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbp_tables_are_permutations() {
        for table in [CBP_INTRA, CBP_INTER] {
            let mut seen = [false; 48];
            for &value in &table {
                assert!(!seen[usize::from(value)]);
                seen[usize::from(value)] = true;
            }
        }
    }
}
