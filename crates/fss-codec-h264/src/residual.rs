//! CAVLC residual-block decoding (clause 9.2) and coefficient combining
//! (clause 9.2.4), driven by the validated spec tables in `super::tables`.

use crate::bits::BitReader;
use crate::cavlc::{context_nc, VlcTable};
use crate::tables::tables;
use crate::DecodeError;

/// Which residual block variant is being decoded. Selects the maximum
/// coefficient count and the total_zeros table family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidualKind {
    /// Luma 4x4 blocks and the Intra16x16 DC block: maxNumCoeff = 16,
    /// nC from neighbouring blocks (DC uses luma4x4BlkIdx 0 context).
    Max16,
    /// AC-only blocks (Intra16x16 luma AC, chroma AC 4:2:0): maxNumCoeff = 15.
    Max15,
    /// ChromaDC 2x2 (4:2:0): maxNumCoeff = 4, nC == -1 context.
    ChromaDC,
}

impl ResidualKind {
    /// Maximum coefficient count for this block kind.
    #[must_use]
    pub const fn max_num_coeff(self) -> usize {
        match self {
            Self::Max16 => 16,
            Self::Max15 => 15,
            Self::ChromaDC => 4,
        }
    }
}

/// Residual coefficients decoded from one block, in positional order.
#[derive(Clone, Debug, PartialEq)]
pub struct ResidualBlock {
    /// Total non-zero coefficients, 0..=maxNumCoeff.
    pub total_coeff: usize,
    /// Coefficients equal to ±1 among the first `trailing_ones` in decode
    /// order, 0..=3.
    pub trailing_ones: usize,
    /// Levels in decode order (trailing ones first), clause 9.2.2.
    pub levels: Vec<i32>,
    /// Positional coefficient array of length maxNumCoeff: zeros interleaved
    /// with the decoded levels per clause 9.2.4.
    pub coeff_level: Vec<i32>,
}

/// Decodes one residual block.
///
/// `coeff_token_table` is selected by the caller from the block's nC
/// context (see [`context_nc`]): luma contexts 0..=2 map to table indices
/// 0..=2, nC >= 8 is not yet table-backed, and ChromaDC always uses index
/// 3 with [`ResidualKind::ChromaDC`].
///
/// # Errors
/// [`DecodeError::Unsupported`] for nC >= 8 (table increment pending);
/// [`DecodeError::Malformed`] on impossible decoded values;
/// [`DecodeError::Limit`] on bound exhaustion.
pub fn decode_residual_block(
    reader: &mut BitReader<'_>,
    kind: ResidualKind,
    coeff_token_table: &VlcTable,
) -> Result<ResidualBlock, DecodeError> {
    let max_num_coeff = kind.max_num_coeff();
    let packed = coeff_token_table.decode(reader)?;
    let total_coeff = usize::from(packed / 4);
    let trailing_ones = usize::from(packed % 4);
    if total_coeff > max_num_coeff || trailing_ones > 3 || trailing_ones > total_coeff {
        return Err(DecodeError::Malformed);
    }
    if total_coeff == 0 {
        // Clause 9.2: TotalCoeff == 0 -> all-zero block; no levels, no runs.
        return Ok(ResidualBlock {
            total_coeff: 0,
            trailing_ones: 0,
            levels: Vec::new(),
            coeff_level: vec![0; max_num_coeff],
        });
    }

    // ----- 9.2.2 level information -----
    let mut levels = Vec::with_capacity(total_coeff);
    for _ in 0..trailing_ones {
        levels.push(if reader.bit()? == 0 { 1 } else { -1 });
    }

    let mut suffix_length: u32 = if total_coeff > 10 && trailing_ones < 3 { 1 } else { 0 };
    for index in trailing_ones..total_coeff {
        // 9.2.2.1 level_prefix: leading zeros before the terminating 1.
        let mut level_prefix: u32 = 0;
        while reader.bit()? == 0 {
            level_prefix += 1;
            if level_prefix > 15 {
                // Baseline caps level_prefix at 15.
                return Err(DecodeError::Unsupported);
            }
        }
        let level_suffix_size: u32 = if level_prefix == 14 && suffix_length == 0 {
            4
        } else if level_prefix >= 15 {
            level_prefix - 3
        } else {
            suffix_length
        };
        let level_suffix = if level_suffix_size == 0 {
            0
        } else {
            reader.uint(u8::try_from(level_suffix_size).map_err(|_| DecodeError::Malformed)?)?
        };

        // 9.2.2 steps 4-7.
        let mut level_code = (level_prefix.min(15) << suffix_length) + level_suffix;
        if level_prefix >= 15 && suffix_length == 0 {
            level_code += 15;
        }
        if level_prefix >= 16 {
            level_code += (1 << (level_prefix - 3)) - 4096;
        }
        if index == trailing_ones && trailing_ones < 3 {
            level_code += 2;
        }

        // Step 8: even -> positive, odd -> negative.
        let level = if level_code % 2 == 0 {
            i32::try_from((level_code + 2) / 2).map_err(|_| DecodeError::Malformed)?
        } else {
            -i32::try_from((level_code + 1) / 2).map_err(|_| DecodeError::Malformed)?
        };
        levels.push(level);

        // Steps 9-10: suffixLength adaptation.
        if suffix_length == 0 {
            suffix_length = 1;
        }
        if level.unsigned_abs() > (3 << (suffix_length - 1)) && suffix_length < 6 {
            suffix_length += 1;
        }
    }

    // ----- 9.2.3 run information -----
    let mut zero_runs = vec![0u8; total_coeff];
    let mut zeros_left: usize = if total_coeff == max_num_coeff {
        0
    } else {
        let tz_table = match kind {
            ResidualKind::ChromaDC => {
                &tables().total_zeros_chroma_dc[total_coeff]
            }
            _ => &tables().total_zeros_4x4[total_coeff],
        };
        usize::from(tz_table.decode(reader)?)
    };
    for run_index in 0..total_coeff.saturating_sub(1) {
        if zeros_left == 0 {
            zero_runs[run_index] = 0;
            continue;
        }
        if zeros_left > 15 {
            return Err(DecodeError::Malformed);
        }
        let run = usize::from(
            tables().run_before[zeros_left].decode(reader)?,
        );
        if run > zeros_left {
            return Err(DecodeError::Malformed);
        }
        zero_runs[run_index] = u8::try_from(run).map_err(|_| DecodeError::Malformed)?;
        zeros_left -= run;
    }
    // The final run absorbs whatever zeros remain.
    if total_coeff > 0 {
        zero_runs[total_coeff - 1] = u8::try_from(zeros_left).map_err(|_| DecodeError::Malformed)?;
    }

    // ----- 9.2.4 combine level and run information -----
    let mut coeff_level = vec![0i32; max_num_coeff];
    let mut coeff_num: isize = -1;
    for index in (0..total_coeff).rev() {
        coeff_num += isize::from(zero_runs[index]) + 1;
        if coeff_num < 0 || coeff_num >= isize::try_from(max_num_coeff).map_err(|_| DecodeError::Malformed)? {
            return Err(DecodeError::Malformed);
        }
        coeff_level[coeff_num as usize] = levels[index];
    }

    Ok(ResidualBlock {
        total_coeff,
        trailing_ones,
        levels,
        coeff_level,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::tables::tables;

    fn push_bits(out: &mut Vec<u8>, bits: &str) {
        for bit in bits.bytes() {
            out.push(bit - b'0');
        }
    }

    fn to_bytes(packed: &[u8]) -> Vec<u8> {
        let mut padded = packed.to_vec();
        while padded.len() % 8 != 0 {
            padded.push(0);
        }
        padded
            .chunks(8)
            .map(|chunk| chunk.iter().fold(0u8, |acc, &b| (acc << 1) | b))
            .collect()
    }

    /// tc=2, to=2 via the nC<2 table ("001"), signs 0,1 (+1,-1),
    /// total_zeros tzVlcIndex=2 -> "110" (tz=1), run_before zerosLeft=1 ->
    /// "0" (run=1). Combined per 9.2.4: coeffLevel = [-1, 0, 1, 0, ...].
    #[test]
    fn hand_computed_block_decodes_per_spec() {
        let mut bits = Vec::new();
        push_bits(&mut bits, "001"); // coeff_token (tc=2, to=2)
        push_bits(&mut bits, "0"); // sign +1
        push_bits(&mut bits, "1"); // sign -1
        push_bits(&mut bits, "110"); // total_zeros = 1
        push_bits(&mut bits, "0"); // run_before = 1 (zerosLeft=1)
        let reader_bytes = to_bytes(&bits);
        let mut reader = BitReader::new(&reader_bytes, bits.len());

        let block = decode_residual_block(
            &mut reader,
            ResidualKind::Max16,
            &tables().coeff_token[0],
        )
        .expect("hand-computed block decodes");

        assert_eq!(block.total_coeff, 2);
        assert_eq!(block.trailing_ones, 2);
        assert_eq!(block.levels, vec![1, -1]);
        // Trailing ones are the LAST coefficients in decode order; combining
        // places levelVal[1]=-1 at index 0 and levelVal[0]=+1 at index 2.
        assert_eq!(&block.coeff_level[..3], &[-1, 0, 1]);
        assert_eq!(block.coeff_level[0], -1);
        assert_eq!(block.coeff_level[2], 1);
        // Bits fully consumed: 3 (coeff) + 2 (signs) + 3 (tz) + 1 (run) = 9.
        assert_eq!(reader.position(), 9);
    }

    /// tc=0 codeword ("1" in nC<2): empty block, nothing else read.
    #[test]
    fn zero_coefficient_block_reads_only_coeff_token() {
        let bytes = vec![0b1000_0000];
        let mut reader = BitReader::new(&bytes, 1);
        let block = decode_residual_block(
            &mut reader,
            ResidualKind::Max16,
            &tables().coeff_token[0],
        )
        .expect("empty block");
        assert_eq!(block.total_coeff, 0);
        assert!(block.coeff_level.iter().all(|&c| c == 0));
        assert_eq!(reader.position(), 1);
    }

    /// tc == maxNumCoeff (ChromaDC 2x2, tc=4): total_zeros is skipped
    /// entirely (zerosLeft starts at 0) and the three run_before iterations
    /// take the zero fast path.
    #[test]
    fn full_block_skips_total_zeros_when_complete() {
        // nC=-1 tc=4,to=3 codeword "0000000" (7 bits) + 3 sign bits "010".
        let mut bits = Vec::new();
        push_bits(&mut bits, "0000000");
        push_bits(&mut bits, "0");
        push_bits(&mut bits, "1");
        push_bits(&mut bits, "0");
        let bytes = to_bytes(&bits);
        let mut reader = BitReader::new(&bytes, bits.len());
        let block = decode_residual_block(
            &mut reader,
            ResidualKind::ChromaDC,
            &tables().coeff_token[3],
        )
        .expect("full chroma block decodes");
        assert_eq!(block.total_coeff, 4);
        assert_eq!(block.trailing_ones, 3);
        // All four positions carry the three trailing ones and one zero:
        // combine order i=2..0 puts +1,-1,+1 at positions 0,1,2.
        assert_eq!(&block.coeff_level, &[1, -1, 1, 0]);
        assert_eq!(reader.position(), 10);
    }

    /// ChromaDC block: nC=-1 table, maxNumCoeff=4, 2x2 total_zeros family.
    #[test]
    fn chroma_dc_block_uses_dedicated_tables() {
        // nC=-1 tc=2,to=2 -> "001" (chroma table); tzVlcIndex=2 -> "01"
        // (tz=1); run_before zerosLeft=1 -> "0" (run=1).
        let mut bits = Vec::new();
        push_bits(&mut bits, "001");
        push_bits(&mut bits, "0");
        push_bits(&mut bits, "1");
        push_bits(&mut bits, "01");
        push_bits(&mut bits, "0");
        let bytes = to_bytes(&bits);
        let mut reader = BitReader::new(&bytes, bits.len());
        let block = decode_residual_block(
            &mut reader,
            ResidualKind::ChromaDC,
            &tables().coeff_token[3],
        )
        .expect("chroma DC block decodes");
        assert_eq!(block.total_coeff, 2);
        // Combined per 9.2.4: trailing -1 lands at the first position, +1
        // after one zero run.
        assert_eq!(&block.coeff_level[..3], &[-1, 0, 1]);
        assert_eq!(reader.position(), 10);
    }

    /// Impossible (to > tc) never occurs from the tables, but a level above
    /// the baseline prefix cap is refused as Unsupported.
    #[test]
    fn overlong_level_prefix_is_typed_unsupported() {
        // tc=1,to=0 -> "000101" (nC<2), then 16+ zero bits for the level
        // prefix: exceeds the baseline 15 cap.
        let mut bits = Vec::new();
        push_bits(&mut bits, "000101");
        for _ in 0..17 {
            bits.push(0);
        }
        push_bits(&mut bits, "1");
        let bytes = to_bytes(&bits);
        let mut reader = BitReader::new(&bytes, bits.len());
        assert_eq!(
            decode_residual_block(
                &mut reader,
                ResidualKind::Max16,
                &tables().coeff_token[0],
            )
            .unwrap_err(),
            DecodeError::Unsupported
        );
    }
}

#[cfg(test)]
mod debug_probe {
    #[test]
    fn print_coeff_token_head() {
        let t = crate::tables::tables().coeff_token[0].entries();
        eprintln!("coeff_token[0] head: {:?}", &t[..t.len().min(6)]);
        eprintln!("count: {}", t.len());
        assert!(t.iter().any(|e| e.len == 1 && e.code == 1), "tc0 codeword must exist");
    }
}

#[cfg(test)]
mod debug_probe2 {
    #[test]
    fn debug_minimal_decode() {
        let t = &crate::tables::tables().coeff_token[0];
        eprintln!("first entry: {:?}", t.entries()[0]);
        let mut reader = crate::bits::BitReader::new(&[0x80], 1);
        let result = t.decode(&mut reader);
        eprintln!("decode result: {:?}", result);
        assert_eq!(result, Ok(0));
    }
}
