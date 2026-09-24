//! CABAC arithmetic decoding engine (ITU-T H.265 clause 9.3.4.3) and
//! context-variable initialisation (clause 9.3.2.2).
//!
//! The engine reads one bit at a time from the bounded [`BitReader`], so
//! every renormalisation is limit-checked: a truncated or hostile slice
//! ends in [`DecodeError::Limit`], never a panic or an out-of-bounds read.

use crate::DecodeError;
use crate::bits::BitReader;
use crate::cabac_tables::{CTX_COUNT, INIT_VALUES, RANGE_TAB_LPS, TRANS_IDX_LPS, TRANS_IDX_MPS};

/// One context variable: `pStateIdx` and `valMps`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Context {
    /// Probability state index, 0..=62.
    pub state: u8,
    /// Value of the most probable symbol, 0 or 1.
    pub mps: u8,
}

impl Context {
    /// Initialises one context from its `initValue` at `slice_qp`
    /// (equations 9-4 to 9-6).
    #[must_use]
    pub fn init(init_value: u8, slice_qp: i32) -> Self {
        let slope = i32::from(init_value >> 4);
        let offset = i32::from(init_value & 15);
        let m = slope * 5 - 45;
        let n = (offset << 3) - 16;
        let pre = (((m * slice_qp.clamp(0, 51)) >> 4) + n).clamp(1, 126);
        if pre <= 63 {
            Self {
                state: u8::try_from(63 - pre).unwrap_or(0),
                mps: 0,
            }
        } else {
            Self {
                state: u8::try_from(pre - 64).unwrap_or(0),
                mps: 1,
            }
        }
    }
}

/// The full set of context variables of one slice segment.
pub type Contexts = [Context; CTX_COUNT];

/// Initialises every context for `init_type` (0 for I slices; 1 or 2 for
/// P/B slices depending on `cabac_init_flag`, clause 9.3.2.2).
///
/// # Errors
/// [`DecodeError::Malformed`] for an `init_type` above 2.
pub fn init_contexts(init_type: usize, slice_qp: i32) -> Result<Contexts, DecodeError> {
    let values = INIT_VALUES.get(init_type).ok_or(DecodeError::Malformed)?;
    let mut contexts = [Context::default(); CTX_COUNT];
    for (context, &value) in contexts.iter_mut().zip(values.iter()) {
        *context = Context::init(value, slice_qp);
    }
    Ok(contexts)
}

/// The arithmetic decoding engine state (`ivlCurrRange`, `ivlOffset`).
#[derive(Debug)]
pub struct CabacEngine {
    range: u32,
    offset: u32,
}

impl CabacEngine {
    /// Initialises the engine (clause 9.3.2.5): `ivlCurrRange = 510`,
    /// `ivlOffset` from nine bits.
    ///
    /// # Errors
    /// [`DecodeError::Limit`] on truncation; [`DecodeError::Malformed`]
    /// when the offset is 510 or 511 (forbidden).
    pub fn new(reader: &mut BitReader<'_>) -> Result<Self, DecodeError> {
        let offset = reader.uint(9)?;
        if offset >= 510 {
            return Err(DecodeError::Malformed);
        }
        Ok(Self { range: 510, offset })
    }

    fn renormalize(&mut self, reader: &mut BitReader<'_>) -> Result<(), DecodeError> {
        while self.range < 256 {
            self.range <<= 1;
            self.offset = (self.offset << 1) | u32::from(reader.bit()?);
        }
        Ok(())
    }

    /// `DecodeDecision` (clause 9.3.4.3.2) with the context it updates.
    ///
    /// # Errors
    /// [`DecodeError::Limit`] when renormalisation runs out of bits.
    pub fn decision(
        &mut self,
        reader: &mut BitReader<'_>,
        ctx: &mut Context,
    ) -> Result<u8, DecodeError> {
        let state = usize::from(ctx.state.min(62));
        let q = ((self.range >> 6) & 3) as usize;
        let lps = u32::from(RANGE_TAB_LPS[state][q]);
        self.range -= lps;
        let bin = if self.offset >= self.range {
            let bin = 1 - ctx.mps;
            self.offset -= self.range;
            self.range = lps;
            if state == 0 {
                ctx.mps = 1 - ctx.mps;
            }
            ctx.state = TRANS_IDX_LPS[state];
            bin
        } else {
            ctx.state = TRANS_IDX_MPS[state];
            ctx.mps
        };
        self.renormalize(reader)?;
        Ok(bin)
    }

    /// `DecodeBypass` (clause 9.3.4.3.4).
    ///
    /// # Errors
    /// [`DecodeError::Limit`] when no bit remains.
    pub fn bypass(&mut self, reader: &mut BitReader<'_>) -> Result<u8, DecodeError> {
        self.offset = (self.offset << 1) | u32::from(reader.bit()?);
        if self.offset >= self.range {
            self.offset -= self.range;
            Ok(1)
        } else {
            Ok(0)
        }
    }

    /// `count` bypass bins, most significant first (fixed-length suffixes).
    ///
    /// # Errors
    /// [`DecodeError::Limit`] when the bits run out.
    pub fn bypass_bits(
        &mut self,
        reader: &mut BitReader<'_>,
        count: u32,
    ) -> Result<u32, DecodeError> {
        let mut value = 0u32;
        for _ in 0..count {
            value = (value << 1) | u32::from(self.bypass(reader)?);
        }
        Ok(value)
    }

    /// `DecodeTerminate` (clause 9.3.4.3.5). After a 1 no renormalisation
    /// is done: the reader then sits just past the last bit the encoder's
    /// flush wrote (the `rbsp_stop_one_bit` for `end_of_slice_segment_flag`,
    /// the `alignment_bit_equal_to_one` for `end_of_subset_one_bit`, or the
    /// bit before `pcm_alignment_zero_bit` for `pcm_flag`).
    ///
    /// # Errors
    /// [`DecodeError::Limit`] when renormalisation runs out of bits.
    pub fn terminate(&mut self, reader: &mut BitReader<'_>) -> Result<u8, DecodeError> {
        self.range -= 2;
        if self.offset >= self.range {
            Ok(1)
        } else {
            self.renormalize(reader)?;
            Ok(0)
        }
    }
}

/// A slice segment's entropy decoder: the bounded reader, the arithmetic
/// engine and the context variables, with the per-element helpers.
pub(crate) struct SliceCabac<'a> {
    pub reader: BitReader<'a>,
    pub engine: CabacEngine,
    pub ctx: Contexts,
}

impl<'a> SliceCabac<'a> {
    /// Starts decoding at the reader's (byte-aligned) position.
    pub fn new(mut reader: BitReader<'a>, ctx: Contexts) -> Result<Self, DecodeError> {
        let engine = CabacEngine::new(&mut reader)?;
        Ok(Self {
            reader,
            engine,
            ctx,
        })
    }

    /// Re-initialises the arithmetic engine at the next byte boundary
    /// (after PCM samples or at a wavefront substream start).
    pub fn restart_engine(&mut self) -> Result<(), DecodeError> {
        self.reader.align()?;
        self.engine = CabacEngine::new(&mut self.reader)?;
        Ok(())
    }

    /// One context-coded bin with context `index`.
    pub fn bin(&mut self, index: usize) -> Result<u8, DecodeError> {
        let ctx = self.ctx.get_mut(index).ok_or(DecodeError::Malformed)?;
        self.engine.decision(&mut self.reader, ctx)
    }

    /// One context-coded bin as a flag.
    pub fn flag(&mut self, index: usize) -> Result<bool, DecodeError> {
        Ok(self.bin(index)? == 1)
    }

    /// One bypass bin.
    pub fn bypass(&mut self) -> Result<u8, DecodeError> {
        self.engine.bypass(&mut self.reader)
    }

    /// `count` bypass bins, most significant first.
    pub fn bypass_bits(&mut self, count: u32) -> Result<u32, DecodeError> {
        self.engine.bypass_bits(&mut self.reader, count)
    }

    /// One terminating bin.
    pub fn terminate(&mut self) -> Result<u8, DecodeError> {
        self.engine.terminate(&mut self.reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cabac_tables as t;

    fn reader_for(bits: &str) -> (Vec<u8>, usize) {
        let mut padded: Vec<u8> = bits.bytes().map(|b| b - b'0').collect();
        let len = padded.len();
        while !padded.len().is_multiple_of(8) {
            padded.push(0);
        }
        let bytes = padded
            .chunks(8)
            .map(|chunk| chunk.iter().fold(0u8, |acc, &b| (acc << 1) | b))
            .collect();
        (bytes, len)
    }

    /// initValue rows typed from ITU-T H.265 Tables 9-5..9-37 (by initType
    /// 0, 1, 2), checked against the generated table.
    #[test]
    fn init_values_match_spec_rows() {
        let rows: &[(usize, [&[u8]; 3])] = &[
            // Table 9-11 split_cu_flag.
            (
                t::SPLIT_CODING_UNIT_FLAG,
                [&[139, 141, 157], &[107, 139, 126], &[107, 139, 126]],
            ),
            // Table 9-6 sao_merge_left_flag / Table 9-7 sao_type_idx.
            (t::SAO_MERGE_FLAG, [&[153], &[153], &[153]]),
            (t::SAO_TYPE_IDX, [&[200], &[185], &[160]]),
            // Table 9-13 cu_skip_flag (initType 1, 2).
            (
                t::SKIP_FLAG,
                [&[154, 154, 154], &[197, 185, 201], &[197, 185, 201]],
            ),
            // Table 9-15 part_mode.
            (
                t::PART_MODE,
                [&[184], &[154, 139, 154, 154], &[154, 139, 154, 154]],
            ),
            // Table 9-16 prev_intra_luma_pred_flag, 9-17 chroma mode.
            (t::PREV_INTRA_LUMA_PRED_FLAG, [&[184], &[154], &[183]]),
            (t::INTRA_CHROMA_PRED_MODE, [&[63], &[152], &[152]]),
            // Table 9-22 split_transform_flag, 9-23 cbf_luma.
            (
                t::SPLIT_TRANSFORM_FLAG,
                [&[153, 138, 138], &[124, 138, 94], &[224, 167, 122]],
            ),
            (t::CBF_LUMA, [&[111, 141], &[153, 111], &[153, 111]]),
            // Table 9-24 cbf_cb / cbf_cr (first four per initType).
            (
                t::CBF_CB_CR,
                [
                    &[94, 138, 182, 154],
                    &[149, 107, 167, 154],
                    &[149, 92, 167, 154],
                ],
            ),
            // Table 9-29 coded_sub_block_flag.
            (
                t::SIGNIFICANT_COEFF_GROUP_FLAG,
                [
                    &[91, 171, 134, 141],
                    &[121, 140, 61, 154],
                    &[121, 140, 61, 154],
                ],
            ),
            // Table 9-31 coeff_abs_level_greater2_flag.
            (
                t::COEFF_ABS_LEVEL_GREATER2_FLAG,
                [
                    &[138, 153, 136, 167, 152, 152],
                    &[107, 167, 91, 122, 107, 167],
                    &[107, 167, 91, 107, 107, 167],
                ],
            ),
            // Table 9-27 last_sig_coeff_x_prefix (first six).
            (
                t::LAST_SIGNIFICANT_COEFF_X_PREFIX,
                [
                    &[110, 110, 124, 125, 140, 153],
                    &[125, 110, 94, 110, 95, 79],
                    &[125, 110, 124, 110, 95, 94],
                ],
            ),
            // Table 9-19 merge_idx, 9-20 inter_pred_idc, 9-25 mvp flag.
            (t::MERGE_IDX, [&[154], &[122], &[137]]),
            (
                t::INTER_PRED_IDC,
                [&[154; 5], &[95, 79, 63, 31, 31], &[95, 79, 63, 31, 31]],
            ),
            (t::MVP_LX_FLAG, [&[154], &[168], &[168]]),
        ];
        for (offset, per_type) in rows {
            for (init_type, values) in per_type.iter().enumerate() {
                for (k, &value) in values.iter().enumerate() {
                    assert_eq!(
                        t::INIT_VALUES[init_type][offset + k],
                        value,
                        "context {} (+{k}) initType {init_type}",
                        offset
                    );
                }
            }
        }
    }

    /// Equations 9-4..9-6 by hand. initValue 139 (slope 8, offset 11):
    /// m = -5, n = 72; QP 26: ((-130) >> 4) + 72 = -9 + 72 = 63 -> state 0,
    /// MPS 0. initValue 154 (m = 0, n = 64) at any QP: 64 -> state 0,
    /// MPS 1. initValue 63 (m = -30, n = 104) at QP 51: (-1530 >> 4) + 104
    /// = -96 + 104 = 8 -> state 55, MPS 0. initValue 224
    /// (m = 25, n = -16) at QP 40: (1000 >> 4) - 16 = 62 - 16 = 46 ->
    /// state 17, MPS 0.
    #[test]
    fn context_init_equations_by_hand() {
        assert_eq!(Context::init(139, 26), Context { state: 0, mps: 0 });
        assert_eq!(Context::init(154, 0), Context { state: 0, mps: 1 });
        assert_eq!(Context::init(154, 51), Context { state: 0, mps: 1 });
        assert_eq!(Context::init(63, 51), Context { state: 55, mps: 0 });
        // Lower clip: initValue 0 (m = -45, n = -16) at QP 51 -> (-2295 >> 4)
        // - 16 = -160 -> 1 -> state 62, MPS 0.
        assert_eq!(Context::init(0, 51), Context { state: 62, mps: 0 });
        assert_eq!(Context::init(224, 40), Context { state: 17, mps: 0 });
        // QP is clipped to 0..=51 first: initValue 111 (m = -15, n = 104)
        // at QP -6 behaves as QP 0 -> 104 -> state 40, MPS 1.
        assert_eq!(Context::init(111, -6), Context { state: 40, mps: 1 });
        assert!(init_contexts(3, 26).is_err());
        assert!(init_contexts(2, 26).is_ok());
    }

    /// Table 9-52 rows 0, 1, 12, 62 and 63, typed from the standard, and
    /// Table 9-53 transIdxLps / transIdxMps.
    #[test]
    fn range_and_transition_tables_match_spec() {
        assert_eq!(t::RANGE_TAB_LPS[0], [128, 176, 208, 240]);
        assert_eq!(t::RANGE_TAB_LPS[1], [128, 167, 197, 227]);
        assert_eq!(t::RANGE_TAB_LPS[12], [77, 94, 111, 128]);
        assert_eq!(t::RANGE_TAB_LPS[60], [6, 8, 9, 11]);
        assert_eq!(t::RANGE_TAB_LPS[62], [6, 7, 8, 9]);
        assert_eq!(t::RANGE_TAB_LPS[63], [2, 2, 2, 2]);
        let trans_lps: [u8; 64] = [
            0, 0, 1, 2, 2, 4, 4, 5, 6, 7, 8, 9, 9, 11, 11, 12, 13, 13, 15, 15, 16, 16, 18, 18, 19,
            19, 21, 21, 22, 22, 23, 24, 24, 25, 26, 26, 27, 27, 28, 29, 29, 30, 30, 30, 31, 32, 32,
            33, 33, 33, 34, 34, 35, 35, 35, 36, 36, 36, 37, 37, 37, 38, 38, 63,
        ];
        assert_eq!(t::TRANS_IDX_LPS, trans_lps);
        for (state, &next) in t::TRANS_IDX_MPS.iter().enumerate().take(62) {
            assert_eq!(usize::from(next), state + 1);
        }
        assert_eq!(t::TRANS_IDX_MPS[62], 62);
    }

    /// Hand-computed engine run. Offset bits "000000000" (0), range 510.
    /// Decision with state 0 / MPS 0: q = (510 >> 6) & 3 = 3, LPS = 240,
    /// range 270, offset 0 < 270 -> MPS (0), state -> 1, no renorm.
    /// Decision again: q = (270 >> 6) & 3 = 0, LPS = 128, range 142 < 256
    /// -> MPS 0, state -> 2, renorm one bit ("1"): range 284, offset 1.
    /// Bypass with next bit "1": offset 3 < 284 -> 0.
    /// Terminate: range 282, offset 3 < 282 -> 0, no renorm (282 >= 256).
    #[test]
    fn engine_decodes_hand_computed_bins() -> Result<(), DecodeError> {
        let (bytes, len) = reader_for(concat!("000000000", "1", "1"));
        let mut reader = BitReader::new(&bytes, len);
        let mut engine = CabacEngine::new(&mut reader)?;
        let mut ctx = Context { state: 0, mps: 0 };
        assert_eq!(engine.decision(&mut reader, &mut ctx), Ok(0));
        assert_eq!(ctx, Context { state: 1, mps: 0 });
        assert_eq!((engine.range, engine.offset), (270, 0));
        assert_eq!(engine.decision(&mut reader, &mut ctx), Ok(0));
        assert_eq!(ctx, Context { state: 2, mps: 0 });
        assert_eq!((engine.range, engine.offset), (284, 1));
        assert_eq!(engine.bypass(&mut reader), Ok(0));
        assert_eq!(engine.offset, 3);
        assert_eq!(engine.terminate(&mut reader), Ok(0));
        assert_eq!(engine.range, 282);
        assert_eq!(reader.position(), 11);
        Ok(())
    }

    /// LPS path by hand. Offset "111101111" = 495, range 510, state 0,
    /// MPS 0: LPS 240, range 270, offset 495 >= 270 -> bin 1 (LPS), offset
    /// 225, range 240, MPS flips to 1, state stays 0; renorm once with
    /// bit "0": range 480, offset 450. A forced offset of 510 is refused;
    /// a terminate at offset 509 fires with no further reads.
    #[test]
    fn engine_lps_path_forbidden_offset_and_terminate() -> Result<(), DecodeError> {
        let (bytes, len) = reader_for(concat!("111101111", "0"));
        let mut reader = BitReader::new(&bytes, len);
        let mut engine = CabacEngine::new(&mut reader)?;
        let mut ctx = Context { state: 0, mps: 0 };
        assert_eq!(engine.decision(&mut reader, &mut ctx), Ok(1));
        assert_eq!(ctx, Context { state: 0, mps: 1 });
        assert_eq!((engine.range, engine.offset), (480, 450));
        let (bytes, len) = reader_for("111111110");
        let mut reader = BitReader::new(&bytes, len);
        assert_eq!(
            CabacEngine::new(&mut reader).err(),
            Some(DecodeError::Malformed)
        );
        let (bytes, len) = reader_for("111111101");
        let mut reader = BitReader::new(&bytes, len);
        let mut engine = CabacEngine::new(&mut reader)?;
        assert_eq!(engine.terminate(&mut reader), Ok(1));
        assert_eq!(reader.position(), 9);
        // Four bypass bins "1011" after offset 0: offsets 1, 2, 5, 11,
        // all below 510 -> "0000".
        let (bytes, len) = reader_for(concat!("000000000", "1011"));
        let mut reader = BitReader::new(&bytes, len);
        let mut engine = CabacEngine::new(&mut reader)?;
        assert_eq!(engine.bypass_bits(&mut reader, 4), Ok(0));
        assert_eq!(engine.bypass(&mut reader), Err(DecodeError::Limit));
        Ok(())
    }
}
