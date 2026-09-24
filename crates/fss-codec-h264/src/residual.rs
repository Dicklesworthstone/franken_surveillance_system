//! CAVLC residual-block decoding (clause 9.2) and coefficient combining
//! (clause 9.2.4), driven by the validated spec tables in `super::tables`.

use crate::bits::BitReader;
use crate::cavlc::VlcTable;
use crate::tables::tables;
use crate::{DecodeError, UnsupportedFeature};

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

/// Coefficient-token source: one of the four VLC tables, or the 6-bit
/// fixed-length code used for `nC >= 8`.
#[derive(Clone, Copy)]
enum TokenSource<'a> {
    Table(&'a VlcTable),
    FixedLength,
}

/// Decodes one residual block with an explicitly supplied coeff_token
/// table (luma contexts 0..=2 are table indices 0..=2; ChromaDC is index 3
/// with [`ResidualKind::ChromaDC`]). See [`decode_residual_block_nc`] for
/// selection by `nC`, which also covers the `nC >= 8` fixed-length code.
///
/// # Errors
/// [`DecodeError::Unsupported`] for a `level_prefix` above 15;
/// [`DecodeError::Malformed`] on impossible decoded values;
/// [`DecodeError::Limit`] on bound exhaustion.
pub fn decode_residual_block(
    reader: &mut BitReader<'_>,
    kind: ResidualKind,
    coeff_token_table: &VlcTable,
) -> Result<ResidualBlock, DecodeError> {
    decode_to_block(reader, kind, TokenSource::Table(coeff_token_table))
}

/// Decodes one residual block, selecting the coeff_token code from the
/// block's `nC` context (clause 9.2.1, Table 9-5): `0..2`, `2..4`, `4..8`
/// use the three VLC tables, `>= 8` the 6-bit fixed-length code, and `-1`
/// the ChromaDC table.
///
/// # Errors
/// As [`decode_residual_block`]; a negative `nC` other than `-1`, or `-1`
/// with a non-ChromaDC kind, is Malformed.
pub fn decode_residual_block_nc(
    reader: &mut BitReader<'_>,
    kind: ResidualKind,
    nc: i32,
) -> Result<ResidualBlock, DecodeError> {
    let source = token_source(kind, nc)?;
    decode_to_block(reader, kind, source)
}

fn decode_to_block(
    reader: &mut BitReader<'_>,
    kind: ResidualKind,
    source: TokenSource<'_>,
) -> Result<ResidualBlock, DecodeError> {
    let mut coeffs = [0i32; 16];
    let mut levels = [0i32; 16];
    let (total_coeff, trailing_ones) = decode_core(reader, kind, source, &mut coeffs, &mut levels)?;
    let max = kind.max_num_coeff();
    Ok(ResidualBlock {
        total_coeff,
        trailing_ones,
        levels: levels[..total_coeff].to_vec(),
        coeff_level: coeffs[..max].to_vec(),
    })
}

fn token_source(kind: ResidualKind, nc: i32) -> Result<TokenSource<'static>, DecodeError> {
    let table = &tables().coeff_token;
    match (kind, nc) {
        (ResidualKind::ChromaDC, -1) => Ok(TokenSource::Table(&table[3])),
        (ResidualKind::ChromaDC, _) | (_, i32::MIN..=-1) => Err(DecodeError::Malformed),
        (_, 0..=1) => Ok(TokenSource::Table(&table[0])),
        (_, 2..=3) => Ok(TokenSource::Table(&table[1])),
        (_, 4..=7) => Ok(TokenSource::Table(&table[2])),
        _ => Ok(TokenSource::FixedLength),
    }
}

/// Allocation-free decode used by the macroblock layer: writes the
/// positional coefficients (`kind.max_num_coeff()` entries, scan order)
/// into `coeffs` and returns TotalCoeff.
///
/// # Errors
/// As [`decode_residual_block_nc`].
pub(crate) fn decode_coefficients(
    reader: &mut BitReader<'_>,
    kind: ResidualKind,
    nc: i32,
    coeffs: &mut [i32; 16],
) -> Result<u8, DecodeError> {
    let source = token_source(kind, nc)?;
    let mut levels = [0i32; 16];
    let (total, _) = decode_core(reader, kind, source, coeffs, &mut levels)?;
    u8::try_from(total).map_err(|_| DecodeError::Malformed)
}

fn read_coeff_token(
    reader: &mut BitReader<'_>,
    source: TokenSource<'_>,
) -> Result<(usize, usize), DecodeError> {
    match source {
        TokenSource::Table(table) => {
            let packed = table.decode(reader)?;
            Ok((usize::from(packed / 4), usize::from(packed % 4)))
        }
        TokenSource::FixedLength => {
            // Table 9-5, 8 <= nC: xxxxyy with TotalCoeff-1 in the high four
            // bits and TrailingOnes in the low two; 000011 is (0, 0).
            let code = reader.uint(6)?;
            if code == 3 {
                return Ok((0, 0));
            }
            let total = usize::try_from(code >> 2).map_err(|_| DecodeError::Malformed)? + 1;
            let ones = usize::try_from(code & 3).map_err(|_| DecodeError::Malformed)?;
            Ok((total, ones))
        }
    }
}

fn decode_core(
    reader: &mut BitReader<'_>,
    kind: ResidualKind,
    source: TokenSource<'_>,
    coeffs: &mut [i32; 16],
    levels: &mut [i32; 16],
) -> Result<(usize, usize), DecodeError> {
    let max_num_coeff = kind.max_num_coeff();
    *coeffs = [0; 16];
    let (total_coeff, trailing_ones) = read_coeff_token(reader, source)?;
    if total_coeff > max_num_coeff || trailing_ones > 3 || trailing_ones > total_coeff {
        return Err(DecodeError::Malformed);
    }
    if total_coeff == 0 {
        // Clause 9.2: TotalCoeff == 0 -> all-zero block; no levels, no runs.
        return Ok((0, 0));
    }

    // ----- 9.2.2 level information -----
    for level in levels.iter_mut().take(trailing_ones) {
        *level = if reader.bit()? == 0 { 1 } else { -1 };
    }

    let mut suffix_length: u32 = if total_coeff > 10 && trailing_ones < 3 {
        1
    } else {
        0
    };
    for (index, slot) in levels
        .iter_mut()
        .enumerate()
        .take(total_coeff)
        .skip(trailing_ones)
    {
        // 9.2.2.1 level_prefix: leading zeros before the terminating 1.
        let mut level_prefix: u32 = 0;
        while reader.bit()? == 0 {
            level_prefix += 1;
            if level_prefix > 15 {
                // 8-bit Baseline/Main/Extended cap level_prefix at 15.
                return Err(DecodeError::Unsupported(
                    UnsupportedFeature::LevelPrefixEscape,
                ));
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
        if index == trailing_ones && trailing_ones < 3 {
            level_code += 2;
        }

        // Step 8: even -> positive, odd -> negative.
        let level = if level_code.is_multiple_of(2) {
            i32::try_from((level_code + 2) / 2).map_err(|_| DecodeError::Malformed)?
        } else {
            -i32::try_from(level_code.div_ceil(2)).map_err(|_| DecodeError::Malformed)?
        };
        *slot = level;

        // Steps 9-10: suffixLength adaptation.
        if suffix_length == 0 {
            suffix_length = 1;
        }
        if level.unsigned_abs() > (3 << (suffix_length - 1)) && suffix_length < 6 {
            suffix_length += 1;
        }
    }

    // ----- 9.2.3 run information -----
    let mut zero_runs = [0usize; 16];
    let mut zeros_left: usize = if total_coeff == max_num_coeff {
        0
    } else {
        let tz_table = match kind {
            ResidualKind::ChromaDC => &tables().total_zeros_chroma_dc[total_coeff],
            _ => &tables().total_zeros_4x4[total_coeff],
        };
        usize::from(tz_table.decode(reader)?)
    };
    if zeros_left + total_coeff > max_num_coeff {
        return Err(DecodeError::Malformed);
    }
    for run in zero_runs.iter_mut().take(total_coeff - 1) {
        if zeros_left == 0 {
            break;
        }
        let value = usize::from(tables().run_before[zeros_left.min(15)].decode(reader)?);
        if value > zeros_left {
            return Err(DecodeError::Malformed);
        }
        *run = value;
        zeros_left -= value;
    }
    // The final run absorbs whatever zeros remain.
    zero_runs[total_coeff - 1] = zeros_left;

    // ----- 9.2.4 combine level and run information -----
    let mut coeff_num: usize = 0;
    for index in (0..total_coeff).rev() {
        coeff_num += zero_runs[index];
        if coeff_num >= max_num_coeff {
            return Err(DecodeError::Malformed);
        }
        coeffs[coeff_num] = levels[index];
        coeff_num += 1;
    }
    Ok((total_coeff, trailing_ones))
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
        while !padded.len().is_multiple_of(8) {
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

        let block =
            decode_residual_block(&mut reader, ResidualKind::Max16, &tables().coeff_token[0])
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
        let block =
            decode_residual_block(&mut reader, ResidualKind::Max16, &tables().coeff_token[0])
                .expect("empty block");
        assert_eq!(block.total_coeff, 0);
        assert!(block.coeff_level.iter().all(|&c| c == 0));
        assert_eq!(reader.position(), 1);
    }

    /// tc == maxNumCoeff (ChromaDC 2x2, tc=4): total_zeros is skipped
    /// entirely (zerosLeft starts at 0) and every run_before is skipped.
    ///
    /// Root cause of the earlier failure: the original vector encoded
    /// TotalCoeff=4, TrailingOnes=3 but supplied only the three trailing-one
    /// sign bits, omitting the fourth (non-trailing-one) level, and expected
    /// a zero among four nonzero coefficients. The decoder correctly ran out
    /// of bits (Limit). The corrected vector adds that level by hand:
    /// suffixLength=0 (TotalCoeff <= 10), TrailingOnes == 3 so no +2 bias,
    /// level_prefix "1" (0) -> levelCode 0 -> level +1.
    #[test]
    fn full_block_skips_total_zeros_when_complete() {
        // nC=-1 tc=4,to=3 codeword "0000000" (7 bits) + 3 sign bits "010"
        // + level_prefix "1".
        let mut bits = Vec::new();
        push_bits(&mut bits, "0000000");
        push_bits(&mut bits, "0");
        push_bits(&mut bits, "1");
        push_bits(&mut bits, "0");
        push_bits(&mut bits, "1");
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
        assert_eq!(block.levels, vec![1, -1, 1, 1]);
        // Decode order is reverse scan order: levelVal[3] lands at scan
        // position 0, levelVal[0] at position 3, no zero runs.
        assert_eq!(&block.coeff_level, &[1, 1, -1, 1]);
        assert_eq!(reader.position(), 11);
    }

    /// ChromaDC block: nC=-1 table, maxNumCoeff=4, 2x2 total_zeros family.
    ///
    /// Root cause of the earlier failure: the expected bit position (10)
    /// was miscounted. The vector is 3 (coeff_token) + 2 (signs) + 2
    /// (total_zeros) + 1 (run_before) = 8 bits, and the reader is bounded
    /// to exactly those 8 bits, so 10 was unreachable; the decoded
    /// coefficients were already correct.
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
        assert_eq!(reader.position(), 8);
    }

    /// A level above the 8-bit baseline prefix cap is refused as Unsupported.
    #[test]
    fn overlong_level_prefix_is_typed_unsupported() {
        // tc=1,to=0 -> "000101" (nC<2), then 16+ zero bits for the level
        // prefix: exceeds the baseline 15 cap.
        let mut bits = Vec::new();
        push_bits(&mut bits, "000101");
        bits.extend(std::iter::repeat_n(0, 17));
        push_bits(&mut bits, "1");
        let bytes = to_bytes(&bits);
        let mut reader = BitReader::new(&bytes, bits.len());
        assert_eq!(
            decode_residual_block(&mut reader, ResidualKind::Max16, &tables().coeff_token[0])
                .unwrap_err(),
            DecodeError::Unsupported(UnsupportedFeature::LevelPrefixEscape)
        );
    }

    /// nC >= 8 uses the 6-bit fixed-length coeff_token (Table 9-5):
    /// "000101" is TotalCoeff 2, TrailingOnes 1; one sign bit "1" (-1);
    /// the second level, first non-trailing-one with TrailingOnes < 3, uses
    /// suffixLength 0 and prefix "01" (1) -> levelCode 1 + 2 = 3 -> -2;
    /// total_zeros tzVlcIndex=2 "111" = 0. Positions: [-2, -1].
    #[test]
    fn fixed_length_token_for_large_nc() {
        let mut bits = Vec::new();
        push_bits(&mut bits, "000101");
        push_bits(&mut bits, "1");
        push_bits(&mut bits, "01");
        push_bits(&mut bits, "111");
        let bytes = to_bytes(&bits);
        let mut reader = BitReader::new(&bytes, bits.len());
        let block = decode_residual_block_nc(&mut reader, ResidualKind::Max16, 9).unwrap();
        assert_eq!(block.total_coeff, 2);
        assert_eq!(block.trailing_ones, 1);
        assert_eq!(block.levels, vec![-1, -2]);
        assert_eq!(&block.coeff_level[..3], &[-2, -1, 0]);
        assert_eq!(reader.position(), 12);

        // "000011" is the (0, 0) escape; "000010" (tc=1, to=2) is impossible.
        let zero = to_bytes(&[0, 0, 0, 0, 1, 1]);
        let mut reader = BitReader::new(&zero, 6);
        assert_eq!(
            decode_residual_block_nc(&mut reader, ResidualKind::Max16, 8)
                .unwrap()
                .total_coeff,
            0
        );
        let bad = to_bytes(&[0, 0, 0, 0, 1, 0]);
        let mut reader = BitReader::new(&bad, 6);
        assert_eq!(
            decode_residual_block_nc(&mut reader, ResidualKind::Max16, 8).unwrap_err(),
            DecodeError::Malformed
        );
    }

    #[test]
    fn nc_selection_refuses_inconsistent_contexts() {
        let bytes = [0xFF];
        let mut reader = BitReader::new(&bytes, 8);
        assert_eq!(
            decode_residual_block_nc(&mut reader, ResidualKind::Max16, -1).unwrap_err(),
            DecodeError::Malformed
        );
        assert_eq!(
            decode_residual_block_nc(&mut reader, ResidualKind::ChromaDC, 0).unwrap_err(),
            DecodeError::Malformed
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
        assert!(
            t.iter().any(|e| e.len == 1 && e.code == 1),
            "tc0 codeword must exist"
        );
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
