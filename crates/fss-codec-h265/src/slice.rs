//! Slice segment header (ITU-T H.265 clause 7.3.6) including the
//! prediction weight table (clause 7.3.6.3).

use crate::bits::BitReader;
use crate::nal::NalHeader;
use crate::params::{MAX_DPB, Pps, ShortTermRps, Sps, parse_short_term_rps};
use crate::{DecodeError, UnsupportedFeature};

/// `slice_type` (Table 7-7).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SliceType {
    /// Bi-predictive.
    B,
    /// Predictive.
    P,
    /// Intra.
    I,
}

/// One long-term reference entry of the slice header (clause 7.4.7.1),
/// before the picture order count of the current picture is known.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LongTermEntry {
    /// `PocLsbLt[i]`.
    pub poc_lsb: u32,
    /// `UsedByCurrPicLt[i]`.
    pub used: bool,
    /// `DeltaPocMsbCycleLt[i]` when `delta_poc_msb_present_flag[i]`.
    pub msb_cycle: Option<u32>,
}

/// Explicit weighted prediction parameters (clause 7.4.7.3), per list and
/// reference index: luma `(weight, offset)` and chroma `[(weight,
/// offset); 2]`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PredWeights {
    /// `luma_log2_weight_denom`.
    pub luma_log2_denom: u32,
    /// `ChromaLog2WeightDenom`.
    pub chroma_log2_denom: u32,
    /// `LumaWeightLX` / `luma_offset_lX` per list.
    pub luma: [Vec<(i32, i32)>; 2],
    /// `ChromaWeightLX` / `ChromaOffsetLX` per list and component.
    pub chroma: [Vec<[(i32, i32); 2]>; 2],
}

/// Decode-relevant slice segment header fields.
#[derive(Clone, Debug)]
pub struct SliceHeader {
    /// `first_slice_segment_in_pic_flag`.
    pub first_slice_in_pic: bool,
    /// `no_output_of_prior_pics_flag` (IRAP pictures).
    pub no_output_of_prior_pics: bool,
    /// `slice_pic_parameter_set_id`.
    pub pps_id: u8,
    /// `slice_segment_address` (raster CTB address).
    pub segment_address: u32,
    /// `slice_type`.
    pub slice_type: SliceType,
    /// `pic_output_flag`.
    pub pic_output: bool,
    /// `slice_pic_order_cnt_lsb` (0 for IDR pictures).
    pub poc_lsb: u32,
    /// The short-term RPS in use (`None` for IDR pictures).
    pub st_rps: Option<ShortTermRps>,
    /// Long-term entries (empty unless `long_term_ref_pics_present_flag`).
    pub long_term: Vec<LongTermEntry>,
    /// `slice_temporal_mvp_enabled_flag`.
    pub temporal_mvp: bool,
    /// `slice_sao_luma_flag`.
    pub sao_luma: bool,
    /// `slice_sao_chroma_flag`.
    pub sao_chroma: bool,
    /// `num_ref_idx_l0/l1_active_minus1 + 1` (0 for unused lists).
    pub num_ref_idx: [u32; 2],
    /// `list_entry_lX` when `ref_pic_list_modification_flag_lX`.
    pub list_entry: [Option<Vec<u32>>; 2],
    /// `mvd_l1_zero_flag`.
    pub mvd_l1_zero: bool,
    /// `cabac_init_flag`.
    pub cabac_init: bool,
    /// `collocated_from_l0_flag`.
    pub collocated_from_l0: bool,
    /// `collocated_ref_idx`.
    pub collocated_ref_idx: u32,
    /// Explicit weights when weighted prediction applies to this slice.
    pub weights: Option<PredWeights>,
    /// `MaxNumMergeCand`.
    pub max_num_merge_cand: u32,
    /// `SliceQpY`.
    pub slice_qp: i32,
    /// `slice_cb_qp_offset`.
    pub cb_qp_offset: i32,
    /// `slice_cr_qp_offset`.
    pub cr_qp_offset: i32,
    /// `slice_deblocking_filter_disabled_flag`.
    pub deblocking_disabled: bool,
    /// `slice_beta_offset_div2 * 2`.
    pub beta_offset: i32,
    /// `slice_tc_offset_div2 * 2`.
    pub tc_offset: i32,
    /// `slice_loop_filter_across_slices_enabled_flag`.
    pub loop_filter_across_slices: bool,
    /// Bit position of `slice_segment_data()` in the RBSP.
    pub data_bit_offset: usize,
}

impl SliceHeader {
    /// `NumPicTotalCurr` (equation 7-55).
    #[must_use]
    pub fn num_pic_total_curr(&self) -> usize {
        let st = self.st_rps.as_ref().map_or(0, |rps| {
            rps.used_s0.iter().filter(|u| **u).count() + rps.used_s1.iter().filter(|u| **u).count()
        });
        st + self.long_term.iter().filter(|lt| lt.used).count()
    }
}

/// `Ceil(Log2(n))`.
fn ceil_log2(n: u32) -> u32 {
    if n <= 1 {
        0
    } else {
        32 - (n - 1).leading_zeros()
    }
}

fn pred_weight_table(
    reader: &mut BitReader<'_>,
    slice_type: SliceType,
    num_ref_idx: [u32; 2],
) -> Result<PredWeights, DecodeError> {
    let luma_log2_denom = reader.ue(7)?;
    let delta = reader.se(-7, 7)?;
    let chroma_log2_denom = u32::try_from(i64::from(luma_log2_denom) + i64::from(delta))
        .map_err(|_| DecodeError::Malformed)?;
    if chroma_log2_denom > 7 {
        return Err(DecodeError::Malformed);
    }
    let mut weights = PredWeights {
        luma_log2_denom,
        chroma_log2_denom,
        ..PredWeights::default()
    };
    let lists = if slice_type == SliceType::B { 2 } else { 1 };
    for list in 0..lists {
        let count = num_ref_idx[list] as usize;
        let mut luma_flags = [false; MAX_DPB];
        let mut chroma_flags = [false; MAX_DPB];
        for flag in luma_flags.iter_mut().take(count) {
            *flag = reader.flag()?;
        }
        for flag in chroma_flags.iter_mut().take(count) {
            *flag = reader.flag()?;
        }
        for i in 0..count {
            let luma = if luma_flags[i] {
                let dw = reader.se(-128, 127)?;
                let offset = reader.se(-128, 127)?;
                ((1 << luma_log2_denom) + dw, offset)
            } else {
                (1 << luma_log2_denom, 0)
            };
            weights.luma[list].push(luma);
            let mut chroma = [(1 << chroma_log2_denom, 0); 2];
            if chroma_flags[i] {
                for entry in &mut chroma {
                    let dw = reader.se(-128, 127)?;
                    let doffset = reader.se(-512, 511)?;
                    let weight = (1 << chroma_log2_denom) + dw;
                    // Equation 7-56 with wpOffsetHalfRangeC = 128.
                    let offset =
                        (128 + doffset - ((128 * weight) >> chroma_log2_denom)).clamp(-128, 127);
                    *entry = (weight, offset);
                }
            }
            weights.chroma[list].push(chroma);
        }
    }
    Ok(weights)
}

/// Parses a slice segment header from the RBSP of a VCL NAL unit.
/// `pps_lookup` resolves a PPS id to the PPS and its SPS.
///
/// # Errors
/// [`DecodeError::MissingParameterSet`] for unknown ids,
/// [`DecodeError::Unsupported`] for dependent slice segments, and
/// [`DecodeError::Malformed`] / [`DecodeError::Limit`] otherwise.
pub fn parse_slice_header<'p>(
    rbsp: &[u8],
    bit_limit: usize,
    nal: NalHeader,
    pps_lookup: impl Fn(u8) -> Option<(&'p Pps, &'p Sps)>,
) -> Result<SliceHeader, DecodeError> {
    let mut reader = BitReader::new(rbsp, bit_limit);
    let r = &mut reader;
    let first_slice_in_pic = r.flag()?;
    let no_output_of_prior_pics = if nal.is_irap() { r.flag()? } else { false };
    let pps_id = r.ue(63)? as u8;
    let (pps, sps) = pps_lookup(pps_id).ok_or(DecodeError::MissingParameterSet)?;
    let pic_size_in_ctbs = sps.ctb_width() * sps.ctb_height();
    let mut segment_address = 0;
    if !first_slice_in_pic {
        if pps.dependent_slices_enabled && r.flag()? {
            return Err(DecodeError::Unsupported(
                UnsupportedFeature::DependentSlices,
            ));
        }
        segment_address = r.uint(ceil_log2(pic_size_in_ctbs))?;
        if segment_address >= pic_size_in_ctbs {
            return Err(DecodeError::Malformed);
        }
    }
    r.skip(pps.num_extra_slice_header_bits as usize)?;
    let slice_type = match r.ue(2)? {
        0 => SliceType::B,
        1 => SliceType::P,
        _ => SliceType::I,
    };
    if nal.is_irap() && slice_type != SliceType::I {
        return Err(DecodeError::Malformed);
    }
    let pic_output = if pps.output_flag_present {
        r.flag()?
    } else {
        true
    };
    let mut poc_lsb = 0;
    let mut st_rps = None;
    let mut long_term = Vec::new();
    let mut temporal_mvp = false;
    if !nal.is_idr() {
        poc_lsb = r.uint(sps.log2_max_poc_lsb)?;
        let from_sps = r.flag()?;
        if from_sps {
            if sps.st_rps.is_empty() {
                return Err(DecodeError::Malformed);
            }
            let bits =
                ceil_log2(u32::try_from(sps.st_rps.len()).map_err(|_| DecodeError::Malformed)?);
            let idx = r.uint(bits)? as usize;
            st_rps = Some(sps.st_rps.get(idx).ok_or(DecodeError::Malformed)?.clone());
        } else {
            st_rps = Some(parse_short_term_rps(
                r,
                &sps.st_rps,
                true,
                sps.max_dec_pic_buffering as usize,
            )?);
        }
        if sps.long_term_refs_present {
            let lt_sps =
                u32::try_from(sps.lt_ref_pics_sps.len()).map_err(|_| DecodeError::Malformed)?;
            let num_sps = if lt_sps > 0 { r.ue(lt_sps)? } else { 0 };
            let num_pics = r.ue(MAX_DPB as u32)?;
            if (num_sps + num_pics) as usize > MAX_DPB {
                return Err(DecodeError::Malformed);
            }
            let mut previous_cycle = 0u32;
            for i in 0..num_sps + num_pics {
                let (poc_lsb, used) = if i < num_sps {
                    let idx = if lt_sps > 1 {
                        r.uint(ceil_log2(lt_sps))?
                    } else {
                        0
                    };
                    *sps.lt_ref_pics_sps
                        .get(idx as usize)
                        .ok_or(DecodeError::Malformed)?
                } else {
                    (r.uint(sps.log2_max_poc_lsb)?, r.flag()?)
                };
                let msb_cycle = if r.flag()? {
                    let delta = r.ue(1 << 24)?;
                    let cycle = if i == 0 || i == num_sps {
                        delta
                    } else {
                        delta + previous_cycle
                    };
                    previous_cycle = cycle;
                    Some(cycle)
                } else {
                    None
                };
                long_term.push(LongTermEntry {
                    poc_lsb,
                    used,
                    msb_cycle,
                });
            }
        }
        if sps.temporal_mvp_enabled {
            temporal_mvp = r.flag()?;
        }
    }
    let (mut sao_luma, mut sao_chroma) = (false, false);
    if sps.sao_enabled {
        sao_luma = r.flag()?;
        sao_chroma = r.flag()?;
    }
    let mut header = SliceHeader {
        first_slice_in_pic,
        no_output_of_prior_pics,
        pps_id,
        segment_address,
        slice_type,
        pic_output,
        poc_lsb,
        st_rps,
        long_term,
        temporal_mvp,
        sao_luma,
        sao_chroma,
        num_ref_idx: [0, 0],
        list_entry: [None, None],
        mvd_l1_zero: false,
        cabac_init: false,
        collocated_from_l0: true,
        collocated_ref_idx: 0,
        weights: None,
        max_num_merge_cand: 5,
        slice_qp: 0,
        cb_qp_offset: 0,
        cr_qp_offset: 0,
        deblocking_disabled: false,
        beta_offset: 0,
        tc_offset: 0,
        loop_filter_across_slices: false,
        data_bit_offset: 0,
    };
    if slice_type != SliceType::I {
        let mut num = [pps.num_ref_idx_l0_default, 0];
        if slice_type == SliceType::B {
            num[1] = pps.num_ref_idx_l1_default;
        }
        if r.flag()? {
            num[0] = r.ue(14)? + 1;
            if slice_type == SliceType::B {
                num[1] = r.ue(14)? + 1;
            }
        }
        header.num_ref_idx = num;
        let total = header.num_pic_total_curr();
        if total == 0 {
            return Err(DecodeError::Malformed);
        }
        if pps.lists_modification_present && total > 1 {
            let bits = ceil_log2(u32::try_from(total).map_err(|_| DecodeError::Malformed)?);
            let lists = if slice_type == SliceType::B { 2 } else { 1 };
            for list in 0..lists {
                if r.flag()? {
                    let mut entries = Vec::with_capacity(num[list] as usize);
                    for _ in 0..num[list] {
                        let entry = r.uint(bits)?;
                        if entry as usize >= total {
                            return Err(DecodeError::Malformed);
                        }
                        entries.push(entry);
                    }
                    header.list_entry[list] = Some(entries);
                }
            }
        }
        if slice_type == SliceType::B {
            header.mvd_l1_zero = r.flag()?;
        }
        if pps.cabac_init_present {
            header.cabac_init = r.flag()?;
        }
        if temporal_mvp {
            if slice_type == SliceType::B {
                header.collocated_from_l0 = r.flag()?;
            }
            let list = usize::from(!header.collocated_from_l0);
            if num[list] > 1 {
                header.collocated_ref_idx = r.ue(num[list] - 1)?;
            }
        }
        if (pps.weighted_pred && slice_type == SliceType::P)
            || (pps.weighted_bipred && slice_type == SliceType::B)
        {
            header.weights = Some(pred_weight_table(r, slice_type, num)?);
        }
        header.max_num_merge_cand = 5 - r.ue(4)?;
    }
    let qp_delta = r.se(-(26 + 25), 25 + 26)?;
    header.slice_qp = pps.init_qp + qp_delta;
    if !(0..=51).contains(&header.slice_qp) {
        return Err(DecodeError::Malformed);
    }
    if pps.slice_chroma_qp_offsets_present {
        header.cb_qp_offset = r.se(-12, 12)?;
        header.cr_qp_offset = r.se(-12, 12)?;
        if !(-12..=12).contains(&(pps.cb_qp_offset + header.cb_qp_offset))
            || !(-12..=12).contains(&(pps.cr_qp_offset + header.cr_qp_offset))
        {
            return Err(DecodeError::Malformed);
        }
    }
    let override_flag = pps.deblocking_override_enabled && r.flag()?;
    if override_flag {
        header.deblocking_disabled = r.flag()?;
        if !header.deblocking_disabled {
            header.beta_offset = r.se(-6, 6)? * 2;
            header.tc_offset = r.se(-6, 6)? * 2;
        }
    } else {
        header.deblocking_disabled = pps.deblocking_disabled;
        header.beta_offset = pps.beta_offset;
        header.tc_offset = pps.tc_offset;
    }
    header.loop_filter_across_slices = if pps.loop_filter_across_slices
        && (sao_luma || sao_chroma || !header.deblocking_disabled)
    {
        r.flag()?
    } else {
        pps.loop_filter_across_slices
    };
    if pps.entropy_coding_sync {
        let entries = r.ue(sps.ctb_height().saturating_sub(1))?;
        if entries > 0 {
            let bits = r.ue(31)? + 1;
            for _ in 0..entries {
                r.uint(bits)?;
            }
        }
    }
    if pps.slice_header_extension_present {
        let length = r.ue(256)?;
        r.skip(length as usize * 8)?;
    }
    // byte_alignment(): alignment_bit_equal_to_one, then zero bits.
    if !r.flag()? {
        return Err(DecodeError::Malformed);
    }
    while !r.byte_aligned() {
        if r.flag()? {
            return Err(DecodeError::Malformed);
        }
    }
    header.data_bit_offset = r.position();
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceil_log2_by_hand() {
        assert_eq!(ceil_log2(0), 0);
        assert_eq!(ceil_log2(1), 0);
        assert_eq!(ceil_log2(2), 1);
        assert_eq!(ceil_log2(3), 2);
        assert_eq!(ceil_log2(4), 2);
        assert_eq!(ceil_log2(5), 3);
        assert_eq!(ceil_log2(99), 7);
    }

    /// Equation 7-56 by hand: ChromaLog2WeightDenom 6, delta weight 0
    /// (weight 64) and delta offset 0: 128 + 0 - (128 * 64 >> 6) = 0.
    /// Delta weight -32 (weight 32), delta offset 10: 128 + 10 - 64 = 74.
    #[test]
    fn chroma_offset_equation_by_hand() -> Result<(), DecodeError> {
        // luma denom 6 ("00111"), chroma delta 0 ("1"); one ref:
        // luma flag 0, chroma flag 1; Cb: dw 0 ("1"), doffset 0 ("1");
        // Cr: dw -32 (ue 64 = "0000001000001"), doffset +10 (ue 19 =
        // "000010100").
        let code = "00111 1 0 1 1 1 0000001000001 000010100";
        let bits: Vec<u8> = code
            .bytes()
            .filter(|b| *b != b' ')
            .map(|b| b - b'0')
            .collect();
        let len = bits.len();
        let mut padded = bits;
        while !padded.len().is_multiple_of(8) {
            padded.push(0);
        }
        let bytes: Vec<u8> = padded
            .chunks(8)
            .map(|chunk| chunk.iter().fold(0u8, |acc, &b| (acc << 1) | b))
            .collect();
        let mut reader = BitReader::new(&bytes, len);
        let weights = pred_weight_table(&mut reader, SliceType::P, [1, 0])?;
        assert_eq!(reader.position(), len);
        assert_eq!(weights.luma[0], vec![(64, 0)]);
        assert_eq!(weights.chroma[0], vec![[(64, 0), (32, 74)]]);
        Ok(())
    }
}
