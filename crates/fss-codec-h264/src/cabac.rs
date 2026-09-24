//! CABAC arithmetic decoding engine (clause 9.3.1.2 and 9.3.3.2) and
//! context-variable initialisation (clause 9.3.1.1).
//!
//! The engine reads one bit at a time from the bounded [`BitReader`], so
//! every renormalisation is limit-checked: a truncated or hostile slice
//! ends in [`DecodeError::Limit`], never a panic or an out-of-bounds read.

use crate::DecodeError;
use crate::bits::BitReader;
use crate::cabac_tables::{CTX_INIT_I, CTX_INIT_PB, RANGE_TAB_LPS, TRANS_IDX_LPS, TRANS_IDX_MPS};

/// One context variable: `pStateIdx` and `valMPS`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Context {
    /// Probability state index, 0..=63.
    pub state: u8,
    /// Value of the most probable symbol, 0 or 1.
    pub mps: u8,
}

impl Context {
    /// Initialises one context from its `(m, n)` pair at `slice_qp`
    /// (equations 9-5 and 9-6).
    #[must_use]
    pub fn init(m: i8, n: i8, slice_qp: i32) -> Self {
        let qp = slice_qp.clamp(0, 51);
        let pre = (((i32::from(m) * qp) >> 4) + i32::from(n)).clamp(1, 126);
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

/// Initialises all `CTX_COUNT` contexts for a slice: the I table when
/// `init_idc` is `None`, else the P/B table for `cabac_init_idc`.
///
/// # Errors
/// [`DecodeError::Malformed`] for `cabac_init_idc > 2`.
pub fn init_contexts(init_idc: Option<u8>, slice_qp: i32) -> Result<Vec<Context>, DecodeError> {
    let table = match init_idc {
        None => &CTX_INIT_I,
        Some(idc) => CTX_INIT_PB
            .get(usize::from(idc))
            .ok_or(DecodeError::Malformed)?,
    };
    Ok(table
        .iter()
        .map(|&(m, n)| Context::init(m, n, slice_qp))
        .collect())
}

/// The arithmetic decoding engine state (`codIRange`, `codIOffset`).
#[derive(Debug)]
pub struct CabacEngine {
    range: u32,
    offset: u32,
}

impl CabacEngine {
    /// Initialises the engine (9.3.1.2): `codIRange = 510`, `codIOffset`
    /// from nine bits.
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

    /// `DecodeDecision` (9.3.3.2.1) with the context it updates.
    ///
    /// # Errors
    /// [`DecodeError::Limit`] when renormalisation runs out of bits.
    pub fn decision(
        &mut self,
        reader: &mut BitReader<'_>,
        ctx: &mut Context,
    ) -> Result<u8, DecodeError> {
        let state = usize::from(ctx.state.min(63));
        let q = usize::try_from((self.range >> 6) & 3).unwrap_or(0);
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

    /// `DecodeBypass` (9.3.3.2.3).
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

    /// `DecodeTerminate` (9.3.3.2.2). After a 1 no renormalisation is
    /// done: the reader then sits just past the last bit the encoder's
    /// flush wrote (the `rbsp_stop_one_bit` for `end_of_slice_flag`, or the
    /// bit before `pcm_alignment_zero_bit` for I_PCM).
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::cabac_tables::CTX_COUNT;

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

    /// Table 9-12 rows (ctxIdx 0..=10, identical for all slice types) and
    /// Table 9-13 (ctxIdx 11..=23, cabac_init_idc 0..=2), typed from the
    /// standard, against the generated tables.
    #[test]
    fn init_tables_match_spec_rows() {
        let t9_12: [(i8, i8); 11] = [
            (20, -15),
            (2, 54),
            (3, 74),
            (20, -15),
            (2, 54),
            (3, 74),
            (-28, 127),
            (-23, 104),
            (-6, 53),
            (-1, 54),
            (7, 51),
        ];
        for (ctx, &pair) in t9_12.iter().enumerate() {
            assert_eq!(CTX_INIT_I[ctx], pair, "I ctxIdx {ctx}");
            for (idc, table) in CTX_INIT_PB.iter().enumerate() {
                assert_eq!(table[ctx], pair, "PB{idc} ctxIdx {ctx}");
            }
        }
        let t9_13: [[(i8, i8); 13]; 3] = [
            [
                (23, 33),
                (23, 2),
                (21, 0),
                (1, 9),
                (0, 49),
                (-37, 118),
                (5, 57),
                (-13, 78),
                (-11, 65),
                (1, 62),
                (12, 49),
                (-4, 73),
                (17, 50),
            ],
            [
                (22, 25),
                (34, 0),
                (16, 0),
                (-2, 9),
                (4, 41),
                (-29, 118),
                (2, 65),
                (-6, 71),
                (-13, 79),
                (5, 52),
                (9, 50),
                (-3, 70),
                (10, 54),
            ],
            [
                (29, 16),
                (25, 0),
                (14, 0),
                (-10, 51),
                (-3, 62),
                (-27, 99),
                (26, 16),
                (-4, 85),
                (-24, 102),
                (5, 57),
                (6, 57),
                (-17, 73),
                (14, 57),
            ],
        ];
        for (idc, rows) in t9_13.iter().enumerate() {
            for (k, &pair) in rows.iter().enumerate() {
                assert_eq!(CTX_INIT_PB[idc][11 + k], pair, "PB{idc} ctxIdx {}", 11 + k);
            }
        }
        // Table 9-18 (end of I-slice luma/chroma contexts): ctxIdx 276 is
        // the terminate context and has no init; 399..401 (Table 9-33,
        // transform_size_8x8_flag) for I: (31, 21), (31, 31), (25, 50).
        assert_eq!(CTX_INIT_I[399], (31, 21));
        assert_eq!(CTX_INIT_I[400], (31, 31));
        assert_eq!(CTX_INIT_I[401], (25, 50));
        // Table 9-24 ctxIdx 60..=69 (mb_qp_delta, intra modes), I slices.
        let t9_17: [(i8, i8); 10] = [
            (0, 41),
            (0, 63),
            (0, 63),
            (0, 63),
            (-9, 83),
            (4, 86),
            (0, 97),
            (-7, 72),
            (13, 41),
            (3, 62),
        ];
        for (k, &pair) in t9_17.iter().enumerate() {
            assert_eq!(CTX_INIT_I[60 + k], pair, "I ctxIdx {}", 60 + k);
        }
    }

    /// Equations 9-5/9-6 by hand. ctxIdx 0 (m = 20, n = -15) at SliceQP 26:
    /// ((20 * 26) >> 4) - 15 = 32 - 15 = 17 <= 63 -> pStateIdx 46, MPS 0.
    /// ctxIdx 2 (3, 74) at QP 26: (78 >> 4) + 74 = 78 -> state 14, MPS 1.
    /// ctxIdx 6 (-28, 127) at QP 51: (-1428 >> 4) + 127 = -90 + 127 = 37
    /// -> state 26, MPS 0 (arithmetic shift floors -89.25 to -90).
    /// Clipping: (20, -15) at QP 0 -> max(1, -15) = 1 -> state 62.
    #[test]
    fn context_init_equations_by_hand() {
        assert_eq!(Context::init(20, -15, 26), Context { state: 46, mps: 0 });
        assert_eq!(Context::init(3, 74, 26), Context { state: 14, mps: 1 });
        assert_eq!(Context::init(-28, 127, 51), Context { state: 26, mps: 0 });
        assert_eq!(Context::init(20, -15, 0), Context { state: 62, mps: 0 });
        // Upper clip: (0, 127) -> 126 -> state 62, MPS 1.
        assert_eq!(Context::init(0, 127, 30), Context { state: 62, mps: 1 });
        let all = init_contexts(Some(1), 26).unwrap();
        assert_eq!(all.len(), CTX_COUNT);
        // ctxIdx 11 with cabac_init_idc 1 is (22, 25): (572 >> 4) + 25 = 60
        // -> state 3, MPS 0.
        assert_eq!(all[11], Context { state: 3, mps: 0 });
        assert!(init_contexts(Some(3), 26).is_err());
    }

    /// Table 9-44 rows 0, 1, 12, 62 and 63, typed from the standard, and
    /// Table 9-45 transIdxLPS.
    #[test]
    fn range_and_transition_tables_match_spec() {
        assert_eq!(RANGE_TAB_LPS[0], [128, 176, 208, 240]);
        assert_eq!(RANGE_TAB_LPS[1], [128, 167, 197, 227]);
        assert_eq!(RANGE_TAB_LPS[12], [77, 94, 111, 128]);
        assert_eq!(RANGE_TAB_LPS[62], [6, 7, 8, 9]);
        assert_eq!(RANGE_TAB_LPS[63], [2, 2, 2, 2]);
        let trans_lps: [u8; 64] = [
            0, 0, 1, 2, 2, 4, 4, 5, 6, 7, 8, 9, 9, 11, 11, 12, 13, 13, 15, 15, 16, 16, 18, 18, 19,
            19, 21, 21, 22, 22, 23, 24, 24, 25, 26, 26, 27, 27, 28, 29, 29, 30, 30, 30, 31, 32, 32,
            33, 33, 33, 34, 34, 35, 35, 35, 36, 36, 36, 37, 37, 37, 38, 38, 63,
        ];
        assert_eq!(TRANS_IDX_LPS, trans_lps);
        for (state, &next) in TRANS_IDX_MPS.iter().enumerate().take(62) {
            assert_eq!(usize::from(next), state + 1);
        }
        assert_eq!(TRANS_IDX_MPS[62], 62);
        assert_eq!(TRANS_IDX_MPS[63], 63);
    }

    /// Hand-computed engine run. Offset bits "000000000" (0), range 510.
    /// Decision with state 0 / MPS 0: q = (510 >> 6) & 3 = 3, LPS = 240,
    /// range 270, offset 0 < 270 -> MPS (0), state -> 1, no renorm.
    /// Decision again: q = (270 >> 6) & 3 = 0, LPS = rangeTabLPS[1][0] =
    /// 128, range 142 < 256 -> MPS 0, state -> 2, renorm one bit ("1"):
    /// range 284, offset 1.
    /// Bypass with next bit "1": offset 3 < 284 -> 0.
    /// Terminate: range 282, offset 3 < 282 -> 0, no renorm (282 >= 256).
    #[test]
    fn engine_decodes_hand_computed_bins() {
        let (bytes, len) = reader_for(concat!("000000000", "1", "1"));
        let mut reader = BitReader::new(&bytes, len);
        let mut engine = CabacEngine::new(&mut reader).unwrap();
        let mut ctx = Context { state: 0, mps: 0 };
        assert_eq!(engine.decision(&mut reader, &mut ctx).unwrap(), 0);
        assert_eq!(ctx, Context { state: 1, mps: 0 });
        assert_eq!((engine.range, engine.offset), (270, 0));
        assert_eq!(engine.decision(&mut reader, &mut ctx).unwrap(), 0);
        assert_eq!(ctx, Context { state: 2, mps: 0 });
        assert_eq!((engine.range, engine.offset), (284, 1));
        assert_eq!(engine.bypass(&mut reader).unwrap(), 0);
        assert_eq!(engine.offset, 3);
        assert_eq!(engine.terminate(&mut reader).unwrap(), 0);
        assert_eq!(engine.range, 282);
        assert_eq!(reader.position(), 11);
    }

    /// LPS path by hand. Offset "111101111" = 495, range 510, state 0,
    /// MPS 0: LPS 240, range 270, offset 495 >= 270 -> bin 1 (LPS),
    /// offset 225, range 240, MPS flips to 1 (state 0), state stays 0
    /// (transIdxLPS[0] = 0); renorm once with bit "0": range 480, offset
    /// 450. Terminate: range 478, offset 450 < 478 -> 0. Then terminate
    /// again: range 476 -> 0. A forced offset of 510 is refused.
    #[test]
    fn engine_lps_path_and_forbidden_offset() {
        let (bytes, len) = reader_for(concat!("111101111", "0"));
        let mut reader = BitReader::new(&bytes, len);
        let mut engine = CabacEngine::new(&mut reader).unwrap();
        let mut ctx = Context { state: 0, mps: 0 };
        assert_eq!(engine.decision(&mut reader, &mut ctx).unwrap(), 1);
        assert_eq!(ctx, Context { state: 0, mps: 1 });
        assert_eq!((engine.range, engine.offset), (480, 450));
        assert_eq!(engine.terminate(&mut reader).unwrap(), 0);
        assert_eq!(engine.terminate(&mut reader).unwrap(), 0);
        // A forced initial offset of 510 is refused.
        let (bytes, len) = reader_for("111111110");
        let mut reader = BitReader::new(&bytes, len);
        assert_eq!(
            CabacEngine::new(&mut reader).unwrap_err(),
            DecodeError::Malformed
        );
        // Terminate that fires: offset 509 (111111101) >= 508 -> 1 with no
        // renormalisation and no further reads.
        let (bytes, len) = reader_for("111111101");
        let mut reader = BitReader::new(&bytes, len);
        let mut engine = CabacEngine::new(&mut reader).unwrap();
        assert_eq!(engine.terminate(&mut reader).unwrap(), 1);
        assert_eq!(reader.position(), 9);
    }

    /// Truncation during renormalisation is a typed Limit.
    #[test]
    fn truncated_renormalisation_is_limit() {
        let (bytes, len) = reader_for("000000000");
        let mut reader = BitReader::new(&bytes, len);
        let mut engine = CabacEngine::new(&mut reader).unwrap();
        let mut ctx = Context { state: 0, mps: 0 };
        assert_eq!(engine.decision(&mut reader, &mut ctx).unwrap(), 0);
        assert_eq!(
            engine.decision(&mut reader, &mut ctx).unwrap_err(),
            DecodeError::Limit
        );
    }
}
