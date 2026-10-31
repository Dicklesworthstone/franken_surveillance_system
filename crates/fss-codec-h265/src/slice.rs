//! Slice segment header (ITU-T H.265 clause 7.3.6) including the
//! prediction weight table (clause 7.3.6.3).

use crate::DecodeError;
use crate::bits::BitReader;
use crate::nal::NalHeader;
use crate::params::{MAX_DPB, Pps, ShortTermRps, Sps, parse_short_term_rps};

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SliceHeader {
    /// `first_slice_segment_in_pic_flag`.
    pub first_slice_in_pic: bool,
    /// `dependent_slice_segment_flag`. Omitted coding fields inherit the
    /// most recent independent slice header in the same picture.
    pub dependent: bool,
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
    /// Tile substream lengths in original escaped NAL bytes, excluding the
    /// final substream. Untiled WPP retains its historical admission behavior.
    pub tile_entry_offsets: Vec<usize>,
    /// Bit position of `slice_segment_data()` in the RBSP.
    pub data_bit_offset: usize,
}

impl SliceHeader {
    /// Decode-relevant values that clause 7.4.7.1 requires to agree across
    /// a picture. QP, slice type, active lists, weights and filter settings
    /// may differ between independent slices and are deliberately absent.
    pub(crate) fn same_picture_as(&self, other: &Self) -> bool {
        self.pps_id == other.pps_id
            && self.no_output_of_prior_pics == other.no_output_of_prior_pics
            && self.pic_output == other.pic_output
            && self.poc_lsb == other.poc_lsb
            && self.st_rps == other.st_rps
            && self.long_term == other.long_term
            && self.temporal_mvp == other.temporal_mvp
    }

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
/// This stateless entry point parses independent segments. The streaming
/// decoder supplies the preceding independent header for dependent segments.
///
/// # Errors
/// [`DecodeError::MissingParameterSet`] for unknown ids,
/// [`DecodeError::IncompletePicture`] when a dependent segment has no
/// preceding independent header, and
/// [`DecodeError::Malformed`] / [`DecodeError::Limit`] otherwise.
pub fn parse_slice_header<'p>(
    rbsp: &[u8],
    bit_limit: usize,
    nal: NalHeader,
    pps_lookup: impl Fn(u8) -> Option<(&'p Pps, &'p Sps)>,
) -> Result<SliceHeader, DecodeError> {
    parse_slice_header_with_previous(rbsp, bit_limit, nal, pps_lookup, None)
}

/// The caller binds `previous` to the same picture and frozen parameter
/// sets. It is the most recent independent header, never a dependent one.
pub(crate) fn parse_slice_header_with_previous<'p>(
    rbsp: &[u8],
    bit_limit: usize,
    nal: NalHeader,
    pps_lookup: impl Fn(u8) -> Option<(&'p Pps, &'p Sps)>,
    previous: Option<&SliceHeader>,
) -> Result<SliceHeader, DecodeError> {
    let mut reader = BitReader::new(rbsp, bit_limit);
    let r = &mut reader;
    let first_slice_in_pic = r.flag()?;
    let no_output_of_prior_pics = if nal.is_irap() { r.flag()? } else { false };
    let pps_id = r.ue(63)? as u8;
    let (pps, sps) = pps_lookup(pps_id).ok_or(DecodeError::MissingParameterSet)?;
    let pic_size_in_ctbs = sps.ctb_width() * sps.ctb_height();
    let mut segment_address = 0;
    let mut dependent = false;
    if !first_slice_in_pic {
        dependent = pps.dependent_slices_enabled && r.flag()?;
        segment_address = r.uint(ceil_log2(pic_size_in_ctbs))?;
        if segment_address >= pic_size_in_ctbs {
            return Err(DecodeError::Malformed);
        }
    }
    if dependent {
        let previous = previous.ok_or(DecodeError::IncompletePicture)?;
        if previous.dependent
            || previous.pps_id != pps_id
            || previous.no_output_of_prior_pics != no_output_of_prior_pics
            || crate::tiles::scan_address(pps, sps, segment_address)?
                <= crate::tiles::scan_address(pps, sps, previous.segment_address)?
        {
            return Err(DecodeError::Malformed);
        }
        // Clause 7.4.7.1: only absent fields are inherited. The segment's
        // own entry points, extension and byte alignment follow below.
        let mut header = previous.clone();
        header.first_slice_in_pic = false;
        header.dependent = true;
        header.segment_address = segment_address;
        return finish_slice_header(r, pps, sps, header);
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
                // DeltaPocMsbCycleLt accumulates within the SPS and the slice entries; an
                // absent delta_poc_msb_cycle_lt is inferred to be zero (clause 7.4.7.1).
                let present = r.flag()?;
                let delta = if present { r.ue(1 << 24)? } else { 0 };
                let cycle = if i == 0 || i == num_sps {
                    delta
                } else {
                    delta
                        .checked_add(previous_cycle)
                        .ok_or(DecodeError::Malformed)?
                };
                previous_cycle = cycle;
                let msb_cycle = present.then_some(cycle);
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
        dependent: false,
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
        tile_entry_offsets: Vec::new(),
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
    finish_slice_header(r, pps, sps, header)
}

/// Fields present in both independent and dependent segment headers.
fn finish_slice_header(
    r: &mut BitReader<'_>,
    pps: &Pps,
    sps: &Sps,
    mut header: SliceHeader,
) -> Result<SliceHeader, DecodeError> {
    header.tile_entry_offsets.clear();
    if pps.entropy_coding_sync || pps.tiles_enabled {
        let maximum = if pps.tiles_enabled {
            pps.tile_columns * pps.tile_rows - 1
        } else {
            sps.ctb_height().saturating_sub(1)
        };
        let entries = r.ue(maximum)?;
        if entries > 0 {
            let bits = r.ue(31)? + 1;
            for _ in 0..entries {
                let minus_one = r.uint(bits)?;
                if pps.tiles_enabled {
                    let length = usize::try_from(u64::from(minus_one) + 1)
                        .map_err(|_| DecodeError::Limit)?;
                    header.tile_entry_offsets.push(length);
                }
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

    /// An abbreviated dependent header inherits every inter-coding field
    /// from real P/B headers, including reference sets, weighting, temporal
    /// MVP, SAO and filtering. Its own syntax is not inherited.
    #[test]
    fn dependent_headers_inherit_real_inter_slice_fields() -> Result<(), DecodeError> {
        use crate::nal::{rbsp_from_ebsp, stop_bit_position};
        use crate::params::{parse_pps, parse_sps};

        fn fixed(bits: &mut Vec<u8>, width: u32, value: u32) {
            for shift in (0..width).rev() {
                bits.push(((value >> shift) & 1) as u8);
            }
        }
        fn ue(bits: &mut Vec<u8>, value: u32) {
            let code = value + 1;
            let width = u32::BITS - code.leading_zeros();
            fixed(bits, width - 1, 0);
            fixed(bits, width, code);
        }

        let streams: [&[u8]; 2] = [
            include_bytes!("../tests/fixtures/decode/p_qcif_ref1.h265"),
            include_bytes!("../tests/fixtures/decode/b_128x96_weighted.h265"),
        ];
        let mut seen = [false; 2];
        let mut weighted = false;
        for stream in streams {
            let (mut sps, mut pps) = (None, None);
            for bytes in crate::annex_b_nal_units(stream) {
                let (nal, payload) = NalHeader::split(bytes)?;
                if !matches!(nal.unit_type, 0..=9 | 33 | 34) {
                    continue;
                }
                let rbsp = rbsp_from_ebsp(payload, stream.len())?;
                match nal.unit_type {
                    33 => {
                        sps = Some(parse_sps(&rbsp)?);
                        continue;
                    }
                    34 => {
                        let mut parsed = parse_pps(&rbsp)?;
                        // The original first segment has no dependent bit.
                        parsed.dependent_slices_enabled = true;
                        pps = Some(parsed);
                        continue;
                    }
                    _ => {}
                }
                let sps = sps.as_ref().ok_or(DecodeError::MissingParameterSet)?;
                let pps = pps.as_ref().ok_or(DecodeError::MissingParameterSet)?;
                let lookup = |id| (id == pps.id).then_some((pps, sps));
                let independent =
                    parse_slice_header(&rbsp, stop_bit_position(&rbsp)?, nal, lookup)?;
                assert!(independent.first_slice_in_pic);
                let index = match independent.slice_type {
                    SliceType::P => 0,
                    SliceType::B => 1,
                    SliceType::I => continue,
                };
                seen[index] = true;
                weighted |= independent.weights.is_some();

                let mut bits = vec![0]; // not first in picture
                ue(&mut bits, u32::from(pps.id));
                bits.push(1); // dependent
                let size = sps.ctb_width() * sps.ctb_height();
                assert!(size > 1);
                fixed(&mut bits, ceil_log2(size), 1); // CTB address 1
                if pps.entropy_coding_sync {
                    ue(&mut bits, 0); // no entry points in this segment
                }
                if pps.slice_header_extension_present {
                    ue(&mut bits, 0); // no extension bytes
                }
                bits.push(1); // byte_alignment
                while !bits.len().is_multiple_of(8) {
                    bits.push(0);
                }
                let dependent_rbsp: Vec<u8> = bits
                    .as_chunks::<8>()
                    .0
                    .iter()
                    .map(|chunk| chunk.iter().fold(0, |byte, bit| (byte << 1) | bit))
                    .collect();
                let dependent = parse_slice_header_with_previous(
                    &dependent_rbsp,
                    bits.len(),
                    nal,
                    lookup,
                    Some(&independent),
                )?;
                let mut expected = independent;
                expected.first_slice_in_pic = false;
                expected.dependent = true;
                expected.segment_address = 1;
                expected.data_bit_offset = bits.len();
                assert_eq!(dependent, expected);
                assert_eq!(
                    parse_slice_header(&dependent_rbsp, bits.len(), nal, lookup).err(),
                    Some(DecodeError::IncompletePicture)
                );
            }
        }
        assert_eq!(seen, [true, true]);
        assert!(weighted);
        Ok(())
    }

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
