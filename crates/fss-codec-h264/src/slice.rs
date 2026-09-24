//! Slice header syntax (clause 7.3.3) for the admitted tool set.

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
}

/// Parsed slice header. Only fields the admitted tool set can carry are
/// kept; refused syntax returns a typed [`UnsupportedFeature`].
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
    /// Active list-0 size (`num_ref_idx_l0_active_minus1 + 1`), P only.
    pub num_ref_idx_l0_active: u32,
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

/// Parses the remainder of a slice header after [`parse_slice_prefix`],
/// leaving the reader at the first bit of `slice_data()`.
///
/// # Errors
/// [`DecodeError::Unsupported`] for B/SP/SI slices, reference list
/// modification, weighted prediction, long-term or MMCO marking;
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
        2 => SliceKind::I,
        1 => return Err(DecodeError::Unsupported(UnsupportedFeature::BSlice)),
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
    let mut num_ref_idx_l0_active = pps.num_ref_idx_l0_default;
    if kind == SliceKind::P {
        if reader.flag()? {
            num_ref_idx_l0_active = reader.ue(31)? + 1;
        }
        // ref_pic_list_modification(): only the "no modification" form.
        if reader.flag()? {
            return Err(DecodeError::Unsupported(
                UnsupportedFeature::RefPicListModification,
            ));
        }
        if pps.weighted_pred {
            return Err(DecodeError::Unsupported(
                UnsupportedFeature::WeightedPrediction,
            ));
        }
    }
    if nal_ref_idc != 0 {
        // dec_ref_pic_marking()
        if idr {
            let _no_output_of_prior_pics = reader.flag()?;
            if reader.flag()? {
                return Err(DecodeError::Unsupported(
                    UnsupportedFeature::LongTermReference,
                ));
            }
        } else if reader.flag()? {
            return Err(DecodeError::Unsupported(
                UnsupportedFeature::AdaptiveRefPicMarking,
            ));
        }
    }
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
        num_ref_idx_l0_active,
        qp,
        disable_deblocking_filter_idc,
        filter_offset_a,
        filter_offset_b,
    })
}
