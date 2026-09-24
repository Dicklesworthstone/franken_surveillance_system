//! CABAC coding of slice-data and macroblock-layer syntax elements
//! (clause 9.3): binarizations (9.3.2), context index selection
//! (9.3.3.1) and residual blocks (7.3.5.3.3), on top of the arithmetic
//! engine in [`crate::cabac`].

use crate::DecodeError;
use crate::bits::BitReader;
use crate::cabac::{CabacEngine, Context, init_contexts};
use crate::cabac_tables::{LAST_COEFF_8X8, SIG_COEFF_8X8_FRAME};
use crate::macroblock::{MbDecoder, MbInfo, MbKind, ResidualBlock, SyntaxReader, b8_of};
use crate::slice::{SliceHeader, SliceKind};

/// Upper bound on Exp-Golomb suffix prefixes; a longer run of ones cannot
/// encode a value an 8-bit stream may carry.
const MAX_EG_PREFIX: u32 = 24;

/// Largest coefficient magnitude accepted from `coeff_abs_level_minus1`.
const MAX_COEFF_LEVEL: u32 = 1 << 16;

/// CABAC syntax source: engine, context variables and the one piece of
/// cross-macroblock state (`mb_qp_delta` of the previous macroblock).
pub(crate) struct CabacReader<'r, 'b> {
    reader: &'r mut BitReader<'b>,
    engine: CabacEngine,
    contexts: Vec<Context>,
    last_dqp_nonzero: bool,
    kind: SliceKind,
}

fn cond(value: bool) -> usize {
    usize::from(value)
}

impl<'r, 'b> CabacReader<'r, 'b> {
    /// Initialises contexts and the engine at the (byte-aligned) start of
    /// `slice_data()`.
    pub(crate) fn new(
        reader: &'r mut BitReader<'b>,
        header: &SliceHeader,
    ) -> Result<Self, DecodeError> {
        let idc = (header.kind != SliceKind::I).then_some(header.cabac_init_idc);
        let contexts = init_contexts(idc, header.qp)?;
        let engine = CabacEngine::new(reader)?;
        Ok(Self {
            reader,
            engine,
            contexts,
            last_dqp_nonzero: false,
            kind: header.kind,
        })
    }

    fn decision(&mut self, ctx_idx: usize) -> Result<u8, DecodeError> {
        let ctx = self
            .contexts
            .get_mut(ctx_idx)
            .ok_or(DecodeError::Malformed)?;
        self.engine.decision(self.reader, ctx)
    }

    fn flag(&mut self, ctx_idx: usize) -> Result<bool, DecodeError> {
        Ok(self.decision(ctx_idx)? == 1)
    }

    fn bypass(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from(self.engine.bypass(self.reader)?))
    }

    /// `mb_skip_flag` (ctxIdxOffset 11 for P, 24 for B).
    pub(crate) fn skip_flag(&mut self, mb: &MbDecoder<'_, '_, '_>) -> Result<bool, DecodeError> {
        let term = |n: Option<&MbInfo>| cond(n.is_some_and(|m| !m.skip));
        let inc = term(mb.neighbour_mb(-1, 0)) + term(mb.neighbour_mb(0, -1));
        let base = if self.kind == SliceKind::B { 24 } else { 11 };
        self.flag(base + inc)
    }

    /// `end_of_slice_flag`.
    pub(crate) fn end_of_slice(&mut self) -> Result<bool, DecodeError> {
        Ok(self.engine.terminate(self.reader)? == 1)
    }

    /// Intra `mb_type` (prefix/suffix with I, P or B context offsets).
    fn intra_mb_type(
        &mut self,
        mb: &MbDecoder<'_, '_, '_>,
        base: usize,
        intra_slice: bool,
    ) -> Result<u32, DecodeError> {
        let state = if intra_slice {
            let term = |n: Option<&MbInfo>| {
                cond(n.is_some_and(|m| matches!(m.kind, MbKind::Intra16x16 | MbKind::Pcm)))
            };
            let inc = term(mb.neighbour_mb(-1, 0)) + term(mb.neighbour_mb(0, -1));
            if !self.flag(base + inc)? {
                return Ok(0);
            }
            base + 2
        } else {
            if !self.flag(base)? {
                return Ok(0);
            }
            base
        };
        if self.engine.terminate(self.reader)? == 1 {
            return Ok(25);
        }
        let i = cond(intra_slice);
        let mut mb_type = 1 + 12 * u32::from(self.decision(state + 1)?);
        if self.flag(state + 2)? {
            mb_type += 4 + 4 * u32::from(self.decision(state + 2 + i)?);
        }
        mb_type += 2 * u32::from(self.decision(state + 3 + i)?);
        mb_type += u32::from(self.decision(state + 3 + 2 * i)?);
        Ok(mb_type)
    }

    /// coded_block_flag context increment (9.3.3.1.1.9) for one block.
    fn coded_block_ctx(&self, mb: &MbDecoder<'_, '_, '_>, block: ResidualBlock) -> usize {
        let intra = mb.current_is_intra();
        // Neighbour term for a block in another macroblock: unavailable ->
        // intra ? 1 : 0; I_PCM -> 1; skipped -> 0; otherwise `coded`.
        let other = |n: Option<&MbInfo>, coded: &dyn Fn(&MbInfo) -> bool| -> usize {
            match n {
                None => cond(intra),
                Some(m) if m.kind == MbKind::Pcm => 1,
                Some(m) if m.skip => 0,
                Some(m) => cond(coded(m)),
            }
        };
        let (a, b) = match block {
            ResidualBlock::LumaDc => {
                let coded = |m: &MbInfo| m.kind == MbKind::Intra16x16 && m.coded_dc & 1 != 0;
                (
                    other(mb.neighbour_mb(-1, 0), &coded),
                    other(mb.neighbour_mb(0, -1), &coded),
                )
            }
            ResidualBlock::ChromaDc(c) => {
                let coded = |m: &MbInfo| m.cbp >> 4 != 0 && m.coded_dc & (2 << c) != 0;
                (
                    other(mb.neighbour_mb(-1, 0), &coded),
                    other(mb.neighbour_mb(0, -1), &coded),
                )
            }
            ResidualBlock::LumaAc(raster) | ResidualBlock::Luma4x4(raster) => {
                let term = |n: Option<(&MbInfo, usize)>, own: bool| -> usize {
                    match n {
                        None => cond(intra),
                        Some((m, blk)) => {
                            if own {
                                cond(m.nz[blk] != 0)
                            } else if m.kind == MbKind::Pcm {
                                1
                            } else if m.skip || m.cbp & (1 << b8_of(blk)) == 0 {
                                0
                            } else if m.transform_8x8 {
                                1
                            } else {
                                cond(m.nz[blk] != 0)
                            }
                        }
                    }
                };
                (
                    term(mb.left_block(raster), raster % 4 > 0),
                    term(mb.above_block(raster), raster >= 4),
                )
            }
            ResidualBlock::ChromaAc(c, blk) => {
                let term = |n: Option<(&MbInfo, usize)>, own: bool| -> usize {
                    match n {
                        None => cond(intra),
                        Some((m, b)) => {
                            if own {
                                cond(m.nz_chroma[c][b] != 0)
                            } else if m.kind == MbKind::Pcm {
                                1
                            } else if m.skip || m.cbp >> 4 != 2 {
                                0
                            } else {
                                cond(m.nz_chroma[c][b] != 0)
                            }
                        }
                    }
                };
                (
                    term(mb.left_chroma(blk), blk % 2 > 0),
                    term(mb.above_chroma(blk), blk >= 2),
                )
            }
            ResidualBlock::Luma8x8(_) => (0, 0),
        };
        a + 2 * b
    }

    /// Unsigned Exp-Golomb (k-th order) bypass suffix (9.3.2.3).
    fn exp_golomb_bypass(&mut self, mut k: u32) -> Result<u32, DecodeError> {
        let mut value: u32 = 0;
        while self.bypass()? == 1 {
            value += 1 << k;
            k += 1;
            if k > MAX_EG_PREFIX {
                return Err(DecodeError::Malformed);
            }
        }
        while k > 0 {
            k -= 1;
            value += self.bypass()? << k;
        }
        Ok(value)
    }
}

impl SyntaxReader for CabacReader<'_, '_> {
    fn is_cabac(&self) -> bool {
        true
    }

    fn mb_type(&mut self, mb: &MbDecoder<'_, '_, '_>) -> Result<u32, DecodeError> {
        match self.kind {
            SliceKind::I => self.intra_mb_type(mb, 3, true),
            SliceKind::P => {
                if self.flag(14)? {
                    return Ok(5 + self.intra_mb_type(mb, 17, false)?);
                }
                if self.flag(15)? {
                    Ok(2 - u32::from(self.decision(17)?))
                } else {
                    Ok(3 * u32::from(self.decision(16)?))
                }
            }
            SliceKind::B => {
                let term = |n: Option<&MbInfo>| cond(n.is_some_and(|m| !m.direct16));
                let inc = term(mb.neighbour_mb(-1, 0)) + term(mb.neighbour_mb(0, -1));
                if !self.flag(27 + inc)? {
                    return Ok(0);
                }
                if !self.flag(27 + 3)? {
                    return Ok(1 + u32::from(self.decision(27 + 5)?));
                }
                let mut bits = u32::from(self.decision(27 + 4)?) << 3;
                bits |= u32::from(self.decision(27 + 5)?) << 2;
                bits |= u32::from(self.decision(27 + 5)?) << 1;
                bits |= u32::from(self.decision(27 + 5)?);
                match bits {
                    0..=7 => Ok(bits + 3),
                    13 => Ok(23 + self.intra_mb_type(mb, 32, false)?),
                    14 => Ok(11),
                    15 => Ok(22),
                    _ => {
                        let bits = (bits << 1) | u32::from(self.decision(27 + 5)?);
                        Ok(bits - 4)
                    }
                }
            }
        }
    }

    fn sub_mb_type(&mut self, kind: SliceKind) -> Result<u32, DecodeError> {
        if kind == SliceKind::P {
            if self.flag(21)? {
                return Ok(0);
            }
            if !self.flag(22)? {
                return Ok(1);
            }
            return Ok(if self.flag(23)? { 2 } else { 3 });
        }
        if !self.flag(36)? {
            return Ok(0);
        }
        if !self.flag(37)? {
            return Ok(1 + u32::from(self.decision(39)?));
        }
        let mut sub = 3;
        if self.flag(38)? {
            if self.flag(39)? {
                return Ok(11 + u32::from(self.decision(39)?));
            }
            sub += 4;
        }
        sub += 2 * u32::from(self.decision(39)?);
        sub += u32::from(self.decision(39)?);
        Ok(sub)
    }

    fn transform_8x8_flag(&mut self, mb: &MbDecoder<'_, '_, '_>) -> Result<bool, DecodeError> {
        let term = |n: Option<&MbInfo>| cond(n.is_some_and(|m| m.transform_8x8));
        let inc = term(mb.neighbour_mb(-1, 0)) + term(mb.neighbour_mb(0, -1));
        self.flag(399 + inc)
    }

    fn intra_pred_mode(&mut self, predicted: u8) -> Result<u8, DecodeError> {
        if self.flag(68)? {
            return Ok(predicted);
        }
        let mut rem = self.decision(69)?;
        rem += 2 * self.decision(69)?;
        rem += 4 * self.decision(69)?;
        Ok(if rem < predicted { rem } else { rem + 1 })
    }

    fn chroma_pred_mode(&mut self, mb: &MbDecoder<'_, '_, '_>) -> Result<u8, DecodeError> {
        let term = |n: Option<&MbInfo>| {
            cond(n.is_some_and(|m| {
                matches!(
                    m.kind,
                    MbKind::Intra4x4 | MbKind::Intra8x8 | MbKind::Intra16x16
                ) && m.chroma_pred_mode != 0
            }))
        };
        let inc = term(mb.neighbour_mb(-1, 0)) + term(mb.neighbour_mb(0, -1));
        if !self.flag(64 + inc)? {
            return Ok(0);
        }
        if !self.flag(64 + 3)? {
            return Ok(1);
        }
        Ok(if self.flag(64 + 3)? { 3 } else { 2 })
    }

    fn ref_idx(
        &mut self,
        mb: &MbDecoder<'_, '_, '_>,
        list: usize,
        raster: usize,
        count: u32,
    ) -> Result<i8, DecodeError> {
        let b_slice = self.kind == SliceKind::B;
        let term = |n: Option<(&MbInfo, usize)>| -> usize {
            n.map_or(0, |(m, blk)| {
                let b8 = b8_of(blk);
                cond(
                    !m.is_intra()
                        && !m.skip
                        && !(b_slice && m.direct8 & (1 << b8) != 0)
                        && m.ref_idx[list][b8] > 0,
                )
            })
        };
        let mut ctx = term(mb.left_block(raster)) + 2 * term(mb.above_block(raster));
        let mut value: u32 = 0;
        while self.flag(54 + ctx)? {
            value += 1;
            if value >= count {
                return Err(DecodeError::Malformed);
            }
            ctx = if ctx < 4 { 4 } else { 5 };
        }
        i8::try_from(value).map_err(|_| DecodeError::Malformed)
    }

    fn mvd(
        &mut self,
        mb: &MbDecoder<'_, '_, '_>,
        list: usize,
        raster: usize,
        component: usize,
    ) -> Result<i32, DecodeError> {
        let abs = |n: Option<(&MbInfo, usize)>| -> u32 {
            n.map_or(0, |(m, blk)| u32::from(m.mvd[list][blk][component]))
        };
        let sum = abs(mb.left_block(raster)) + abs(mb.above_block(raster));
        let base = if component == 0 { 40 } else { 47 };
        let inc = if sum < 3 {
            0
        } else if sum <= 32 {
            1
        } else {
            2
        };
        if !self.flag(base + inc)? {
            return Ok(0);
        }
        let mut value: u32 = 1;
        let mut ctx = base + 3;
        while value < 9 && self.flag(ctx)? {
            if value < 4 {
                ctx += 1;
            }
            value += 1;
        }
        if value >= 9 {
            value += self.exp_golomb_bypass(3)?;
        }
        let signed = i32::try_from(value).map_err(|_| DecodeError::Malformed)?;
        Ok(if self.bypass()? == 1 { -signed } else { signed })
    }

    fn cbp(&mut self, mb: &MbDecoder<'_, '_, '_>, _intra_nxn: bool) -> Result<u8, DecodeError> {
        // Luma prefix: one bin per 8x8, condTermFlagN = 0 when N is
        // unavailable or I_PCM or (not skipped and its bit b8N is set).
        let bit_of = |n: Option<(&MbInfo, usize)>, current: u8, own: bool| -> usize {
            match n {
                None => 0,
                Some((m, blk)) => {
                    let cbp = if own { current } else { m.cbp };
                    if !own && m.kind == MbKind::Pcm {
                        0
                    } else if !own && m.skip {
                        1
                    } else {
                        cond(cbp & (1 << b8_of(blk)) == 0)
                    }
                }
            }
        };
        let mut luma: u8 = 0;
        for b8 in 0..4usize {
            let raster = (b8 / 2) * 8 + (b8 % 2) * 2;
            let a = bit_of(mb.left_block(raster), luma, b8 % 2 == 1);
            let b = bit_of(mb.above_block(raster), luma, b8 >= 2);
            luma |= self.decision(73 + a + 2 * b)? << b8;
        }
        let chroma_term = |n: Option<&MbInfo>, need_two: bool| -> usize {
            cond(n.is_some_and(|m| {
                m.kind == MbKind::Pcm
                    || (!m.skip
                        && if need_two {
                            m.cbp >> 4 == 2
                        } else {
                            m.cbp >> 4 != 0
                        })
            }))
        };
        let left = mb.neighbour_mb(-1, 0);
        let above = mb.neighbour_mb(0, -1);
        let inc = chroma_term(left, false) + 2 * chroma_term(above, false);
        let chroma = if self.flag(77 + inc)? {
            let inc = chroma_term(left, true) + 2 * chroma_term(above, true);
            1 + self.decision(77 + 4 + inc)?
        } else {
            0
        };
        Ok(luma | (chroma << 4))
    }

    fn qp_delta(&mut self) -> Result<i32, DecodeError> {
        let mut ctx = 60 + cond(self.last_dqp_nonzero);
        let mut value: u32 = 0;
        while self.flag(ctx)? {
            value += 1;
            if value > 52 {
                return Err(DecodeError::Malformed);
            }
            ctx = if ctx < 62 { 62 } else { 63 };
        }
        self.last_dqp_nonzero = value != 0;
        let magnitude = i32::try_from(value.div_ceil(2)).map_err(|_| DecodeError::Malformed)?;
        Ok(if value % 2 == 1 {
            magnitude
        } else {
            -magnitude
        })
    }

    fn no_qp_delta(&mut self) {
        self.last_dqp_nonzero = false;
    }

    fn residual(
        &mut self,
        mb: &MbDecoder<'_, '_, '_>,
        block: ResidualBlock,
        out: &mut [i32; 64],
    ) -> Result<u8, DecodeError> {
        *out = [0; 64];
        let max = block.max_coeff();
        let (cat, cbf_offset, sig_offset, abs_offset) = match block {
            ResidualBlock::LumaDc => (0, 0, 0, 0),
            ResidualBlock::LumaAc(_) => (1, 4, 15, 10),
            ResidualBlock::Luma4x4(_) => (2, 8, 29, 20),
            ResidualBlock::ChromaDc(_) => (3, 12, 44, 30),
            ResidualBlock::ChromaAc(..) => (4, 16, 47, 39),
            ResidualBlock::Luma8x8(_) => (5, 0, 0, 0),
        };
        if cat != 5 {
            let inc = self.coded_block_ctx(mb, block);
            if !self.flag(85 + cbf_offset + inc)? {
                return Ok(0);
            }
        }
        let (sig_base, last_base, abs_base) = if cat == 5 {
            (402, 417, 426)
        } else {
            (105 + sig_offset, 166 + sig_offset, 227 + abs_offset)
        };
        let mut significant = [false; 64];
        let mut num_coeff = max;
        let mut i = 0;
        while i + 1 < num_coeff {
            let (sig_inc, last_inc) = match cat {
                3 => (i.min(2), i.min(2)),
                5 => (
                    usize::from(SIG_COEFF_8X8_FRAME[i]),
                    usize::from(LAST_COEFF_8X8[i]),
                ),
                _ => (i, i),
            };
            if self.flag(sig_base + sig_inc)? {
                significant[i] = true;
                if self.flag(last_base + last_inc)? {
                    num_coeff = i + 1;
                }
            }
            i += 1;
        }
        if num_coeff == max {
            significant[max - 1] = true;
        }
        let mut eq1: usize = 0;
        let mut gt1: usize = 0;
        let mut count: u8 = 0;
        let gt1_cap = if cat == 3 { 3 } else { 4 };
        for index in (0..num_coeff).rev() {
            if !significant[index] {
                continue;
            }
            let inc0 = if gt1 != 0 { 0 } else { (1 + eq1).min(4) };
            let mut level: u32 = 1;
            if self.flag(abs_base + inc0)? {
                let ctx = abs_base + 5 + gt1.min(gt1_cap);
                level = 2;
                while level < 15 && self.flag(ctx)? {
                    level += 1;
                }
                if level >= 15 {
                    level += self.exp_golomb_bypass(0)?;
                }
                // An 8-bit stream's levels stay far below 2^16 (the
                // scaled coefficients are bounded by 2^15, 8.5.12.1).
                if level > MAX_COEFF_LEVEL {
                    return Err(DecodeError::Malformed);
                }
            }
            if level == 1 {
                eq1 += 1;
            } else {
                gt1 += 1;
            }
            let value = i32::try_from(level).map_err(|_| DecodeError::Malformed)?;
            out[index] = if self.bypass()? == 1 { -value } else { value };
            count += 1;
        }
        Ok(count)
    }

    fn pcm(&mut self) -> Result<[u8; 384], DecodeError> {
        // The terminate bin that selected I_PCM left the reader just past
        // the bits the arithmetic decoder consumed; the samples start at
        // the next byte boundary (pcm_alignment_zero_bit). Encoders pad
        // the arithmetic flush differently, so the padding value is not
        // policed here (FFmpeg does not either).
        while !self.reader.byte_aligned() {
            self.reader.bit()?;
        }
        let mut samples = [0u8; 384];
        for sample in &mut samples {
            *sample = u8::try_from(self.reader.uint(8)?).map_err(|_| DecodeError::Malformed)?;
        }
        self.engine = CabacEngine::new(self.reader)?;
        Ok(samples)
    }
}
