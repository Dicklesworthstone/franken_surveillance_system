//! Slice header syntax (clause 7.3.3) for the admitted tool set: I, P and
//! B slices of frame pictures, reference list modification, explicit
//! weighted prediction tables and reference picture marking.

use crate::bits::BitReader;
use crate::params::{PicParams, SeqParams};
use crate::{DecodeError, UnsupportedFeature};

/// Slice coding type after the `% 5` fold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SliceKind {
    /// P slice (inter prediction from list 0).
    P,
    /// I slice (intra only).
    I,
    /// B slice (inter prediction from lists 0 and 1).
    B,
}

/// One `ref_pic_list_modification()` operation (clause 7.4.3.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefListModification {
    /// `modification_of_pic_nums_idc == 0`: subtract
    /// `abs_diff_pic_num_minus1 + 1` from the picture number prediction.
    ShortTermSubtract(u32),
    /// `modification_of_pic_nums_idc == 1`: add
    /// `abs_diff_pic_num_minus1 + 1`.
    ShortTermAdd(u32),
    /// `modification_of_pic_nums_idc == 2`: `long_term_pic_num`.
    LongTerm(u32),
}

/// One `memory_management_control_operation` (clause 7.4.3.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mmco {
    /// 1: mark a short-term picture unused (`difference_of_pic_nums_minus1`).
    UnmarkShortTerm(u32),
    /// 2: mark a long-term picture unused (`long_term_pic_num`).
    UnmarkLongTerm(u32),
    /// 3: convert a short-term picture to long-term
    /// (`difference_of_pic_nums_minus1`, `long_term_frame_idx`).
    ShortTermToLongTerm(u32, u32),
    /// 4: `max_long_term_frame_idx_plus1`.
    MaxLongTermFrameIdx(u32),
    /// 5: mark all reference pictures unused and reset numbering.
    UnmarkAll,
    /// 6: mark the current picture long-term (`long_term_frame_idx`).
    CurrentToLongTerm(u32),
}

/// `dec_ref_pic_marking()` of a reference picture.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum RefPicMarking {
    /// Non-reference picture (`nal_ref_idc == 0`): no marking syntax.
    #[default]
    None,
    /// IDR marking.
    Idr {
        /// `no_output_of_prior_pics_flag`.
        no_output_of_prior_pics: bool,
        /// `long_term_reference_flag`.
        long_term: bool,
    },
    /// Sliding-window marking (`adaptive_ref_pic_marking_mode_flag == 0`).
    SlidingWindow,
    /// Adaptive marking with its operations, in order.
    Adaptive(Vec<Mmco>),
}

/// Explicit prediction weights of one reference index (clause 7.4.3.2),
/// already defaulted when the corresponding flag is 0.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WeightEntry {
    /// Luma (weight, offset).
    pub luma: (i32, i32),
    /// Cb and Cr (weight, offset).
    pub chroma: [(i32, i32); 2],
}

/// `pred_weight_table()`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PredWeightTable {
    /// `luma_log2_weight_denom` (0..=7).
    pub luma_log2_denom: u32,
    /// `chroma_log2_weight_denom` (0..=7).
    pub chroma_log2_denom: u32,
    /// Entries for list 0 and list 1, indexed by reference index.
    pub lists: [Vec<WeightEntry>; 2],
}

/// Parsed slice header. Refused syntax returns a typed
/// [`UnsupportedFeature`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SliceHeader {
    /// `nal_unit_type == 5`.
    pub idr: bool,
    /// `nal_ref_idc`.
    pub nal_ref_idc: u8,
    /// `first_mb_in_slice`.
    pub first_mb: u32,
    /// Folded slice type.
    pub kind: SliceKind,
    /// `pic_parameter_set_id`.
    pub pps_id: u8,
    /// `frame_num`.
    pub frame_num: u32,
    /// `idr_pic_id` (IDR only).
    pub idr_pic_id: u32,
    /// `pic_order_cnt_lsb` (POC type 0).
    pub poc_lsb: u32,
    /// `delta_pic_order_cnt_bottom` (POC type 0 with the PPS flag).
    pub delta_poc_bottom: i32,
    /// `redundant_pic_cnt`.
    pub redundant_pic_cnt: u32,
    /// `direct_spatial_mv_pred_flag` (B slices).
    pub direct_spatial: bool,
    /// Active list-0 size (`num_ref_idx_l0_active_minus1 + 1`), P and B.
    pub num_ref_idx_l0_active: u32,
    /// Active list-1 size, B only.
    pub num_ref_idx_l1_active: u32,
    /// `ref_pic_list_modification()` operations for lists 0 and 1.
    pub modifications: [Vec<RefListModification>; 2],
    /// Explicit weights, when the PPS selects explicit weighting for this
    /// slice type.
    pub weights: Option<PredWeightTable>,
    /// `dec_ref_pic_marking()`.
    pub marking: RefPicMarking,
    /// `cabac_init_idc` (0 for I slices and CAVLC).
    pub cabac_init_idc: u8,
    /// `26 + pic_init_qp_minus26 + slice_qp_delta`.
    pub qp: i32,
    /// `disable_deblocking_filter_idc` (0, 1 or 2).
    pub disable_deblocking_filter_idc: u8,
    /// `FilterOffsetA = slice_alpha_c0_offset_div2 << 1`.
    pub filter_offset_a: i32,
    /// `FilterOffsetB = slice_beta_offset_div2 << 1`.
    pub filter_offset_b: i32,
}

/// The first three slice-header fields: enough to find the PPS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlicePrefix {
    /// `first_mb_in_slice`.
    pub first_mb: u32,
    /// Raw `slice_type` (0..=9).
    pub slice_type: u32,
    /// `pic_parameter_set_id`.
    pub pps_id: u8,
}

/// Upper bound on list-modification or MMCO operations in one header; the
/// syntax is otherwise unbounded and a hostile stream could loop forever.
const MAX_HEADER_OPERATIONS: usize = 66;

/// Reads `first_mb_in_slice`, `slice_type` and `pic_parameter_set_id`.
///
/// # Errors
/// Malformed / Limit on bad syntax.
pub fn parse_slice_prefix(reader: &mut BitReader<'_>) -> Result<SlicePrefix, DecodeError> {
    let first_mb = reader.ue(1 << 20)?;
    let slice_type = reader.ue(9)?;
    let pps_id = u8::try_from(reader.ue(255)?).map_err(|_| DecodeError::Malformed)?;
    Ok(SlicePrefix {
        first_mb,
        slice_type,
        pps_id,
    })
}

fn ref_list_modification(
    reader: &mut BitReader<'_>,
    max_pic_num: u32,
) -> Result<Vec<RefListModification>, DecodeError> {
    let mut ops = Vec::new();
    if !reader.flag()? {
        return Ok(ops);
    }
    loop {
        let idc = reader.ue(3)?;
        let op = match idc {
            0 => RefListModification::ShortTermSubtract(reader.ue(max_pic_num - 1)?),
            1 => RefListModification::ShortTermAdd(reader.ue(max_pic_num - 1)?),
            2 => RefListModification::LongTerm(reader.ue(31)?),
            _ => break,
        };
        if ops.len() >= MAX_HEADER_OPERATIONS {
            return Err(DecodeError::Malformed);
        }
        ops.push(op);
    }
    Ok(ops)
}

fn weight_pair(reader: &mut BitReader<'_>, denom: u32) -> Result<(i32, i32), DecodeError> {
    if reader.flag()? {
        Ok((reader.se_range(-128, 127)?, reader.se_range(-128, 127)?))
    } else {
        Ok((1 << denom, 0))
    }
}

fn pred_weight_table(
    reader: &mut BitReader<'_>,
    counts: [u32; 2],
) -> Result<PredWeightTable, DecodeError> {
    let luma_log2_denom = reader.ue(7)?;
    let chroma_log2_denom = reader.ue(7)?;
    let mut lists: [Vec<WeightEntry>; 2] = [Vec::new(), Vec::new()];
    for (list, &count) in lists.iter_mut().zip(&counts) {
        for _ in 0..count {
            let luma = weight_pair(reader, luma_log2_denom)?;
            let chroma = if reader.flag()? {
                [
                    (reader.se_range(-128, 127)?, reader.se_range(-128, 127)?),
                    (reader.se_range(-128, 127)?, reader.se_range(-128, 127)?),
                ]
            } else {
                [(1 << chroma_log2_denom, 0); 2]
            };
            list.push(WeightEntry { luma, chroma });
        }
    }
    Ok(PredWeightTable {
        luma_log2_denom,
        chroma_log2_denom,
        lists,
    })
}

fn dec_ref_pic_marking(
    reader: &mut BitReader<'_>,
    idr: bool,
    max_pic_num: u32,
) -> Result<RefPicMarking, DecodeError> {
    if idr {
        return Ok(RefPicMarking::Idr {
            no_output_of_prior_pics: reader.flag()?,
            long_term: reader.flag()?,
        });
    }
    if !reader.flag()? {
        return Ok(RefPicMarking::SlidingWindow);
    }
    let mut ops = Vec::new();
    loop {
        let op = match reader.ue(6)? {
            0 => break,
            1 => Mmco::UnmarkShortTerm(reader.ue(max_pic_num - 1)?),
            2 => Mmco::UnmarkLongTerm(reader.ue(31)?),
            3 => Mmco::ShortTermToLongTerm(reader.ue(max_pic_num - 1)?, reader.ue(15)?),
            4 => Mmco::MaxLongTermFrameIdx(reader.ue(16)?),
            5 => Mmco::UnmarkAll,
            _ => Mmco::CurrentToLongTerm(reader.ue(15)?),
        };
        if ops.len() >= MAX_HEADER_OPERATIONS {
            return Err(DecodeError::Malformed);
        }
        ops.push(op);
    }
    Ok(RefPicMarking::Adaptive(ops))
}

/// Parses the remainder of a slice header after [`parse_slice_prefix`],
/// leaving the reader at the first bit of `slice_data()`.
///
/// # Errors
/// [`DecodeError::Unsupported`] for SP/SI slices;
/// [`DecodeError::Malformed`] on impossible values.
pub fn parse_slice_header(
    reader: &mut BitReader<'_>,
    nal: crate::rbsp::NalHeader,
    prefix: SlicePrefix,
    sps: &SeqParams,
    pps: &PicParams,
) -> Result<SliceHeader, DecodeError> {
    let SlicePrefix {
        first_mb,
        slice_type,
        pps_id,
    } = prefix;
    let nal_ref_idc = nal.ref_idc;
    let idr = nal.unit_type == 5;
    let kind = match slice_type % 5 {
        0 => SliceKind::P,
        1 => SliceKind::B,
        2 => SliceKind::I,
        _ => return Err(DecodeError::Unsupported(UnsupportedFeature::SwitchingSlice)),
    };
    if idr && kind != SliceKind::I {
        return Err(DecodeError::Malformed);
    }
    if first_mb >= sps.mbs() {
        return Err(DecodeError::Malformed);
    }
    let frame_num = reader.uint(sps.log2_max_frame_num)?;
    // frame_mbs_only_flag == 1 is enforced at SPS parse: no field syntax.
    let idr_pic_id = if idr { reader.ue(65_535)? } else { 0 };
    let mut poc_lsb = 0;
    let mut delta_poc_bottom = 0;
    if sps.poc_type == 0 {
        poc_lsb = reader.uint(sps.log2_max_poc_lsb)?;
        if pps.bottom_field_pic_order_present {
            delta_poc_bottom = reader.se_range(-(1 << 30), 1 << 30)?;
        }
    }
    let redundant_pic_cnt = if pps.redundant_pic_cnt_present {
        reader.ue(127)?
    } else {
        0
    };
    let direct_spatial = kind == SliceKind::B && reader.flag()?;
    let mut num_ref_idx_l0_active = pps.num_ref_idx_l0_default;
    let mut num_ref_idx_l1_active = pps.num_ref_idx_l1_default;
    if kind != SliceKind::I && reader.flag()? {
        num_ref_idx_l0_active = reader.ue(31)? + 1;
        if kind == SliceKind::B {
            num_ref_idx_l1_active = reader.ue(31)? + 1;
        }
    }
    match kind {
        SliceKind::I => {
            num_ref_idx_l0_active = 0;
            num_ref_idx_l1_active = 0;
        }
        SliceKind::P => num_ref_idx_l1_active = 0,
        SliceKind::B => {}
    }
    let max_pic_num = 1u32 << sps.log2_max_frame_num;
    let mut modifications = [Vec::new(), Vec::new()];
    if kind != SliceKind::I {
        modifications[0] = ref_list_modification(reader, max_pic_num)?;
    }
    if kind == SliceKind::B {
        modifications[1] = ref_list_modification(reader, max_pic_num)?;
    }
    let weights = if (pps.weighted_pred && kind == SliceKind::P)
        || (pps.weighted_bipred_idc == 1 && kind == SliceKind::B)
    {
        Some(pred_weight_table(
            reader,
            [num_ref_idx_l0_active, num_ref_idx_l1_active],
        )?)
    } else {
        None
    };
    let marking = if nal_ref_idc != 0 {
        dec_ref_pic_marking(reader, idr, max_pic_num)?
    } else {
        RefPicMarking::None
    };
    let cabac_init_idc = if pps.entropy_coding_mode && kind != SliceKind::I {
        u8::try_from(reader.ue(2)?).map_err(|_| DecodeError::Malformed)?
    } else {
        0
    };
    let qp = pps.pic_init_qp + reader.se_range(-51, 51)?;
    if !(0..=51).contains(&qp) {
        return Err(DecodeError::Malformed);
    }
    let mut disable_deblocking_filter_idc = 0;
    let mut filter_offset_a = 0;
    let mut filter_offset_b = 0;
    if pps.deblocking_filter_control_present {
        disable_deblocking_filter_idc =
            u8::try_from(reader.ue(2)?).map_err(|_| DecodeError::Malformed)?;
        if disable_deblocking_filter_idc != 1 {
            filter_offset_a = reader.se_range(-6, 6)? * 2;
            filter_offset_b = reader.se_range(-6, 6)? * 2;
        }
    }
    Ok(SliceHeader {
        idr,
        nal_ref_idc,
        first_mb,
        kind,
        pps_id,
        frame_num,
        idr_pic_id,
        poc_lsb,
        delta_poc_bottom,
        redundant_pic_cnt,
        direct_spatial,
        num_ref_idx_l0_active,
        num_ref_idx_l1_active,
        modifications,
        weights,
        marking,
        cabac_init_idc,
        qp,
        disable_deblocking_filter_idc,
        filter_offset_a,
        filter_offset_b,
    })
}
