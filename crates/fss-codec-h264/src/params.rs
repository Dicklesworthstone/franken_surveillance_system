//! Decode-relevant SPS and PPS fields (clauses 7.3.2.1.1 and 7.3.2.2).
//!
//! `fss-packet` owns parameter-set *admission* (bounds, profile, VUI
//! validity, custody of the exact bytes). The decoder admits every SPS/PPS
//! through it first and then reads here the fields custody deliberately
//! leaves in the original bytes (QP init, chroma offsets, deblocking and
//! constrained-intra controls, POC and frame_num widths, cropping). Tools
//! outside the admitted set are refused with a typed
//! [`UnsupportedFeature`], never approximated.

use crate::bits::BitReader;
use crate::{DecodeError, UnsupportedFeature};

/// Hard ceiling on picture width/height in macroblocks accepted by syntax
/// (matches `fss-packet`); budgets in `DecoderLimits` are usually tighter.
pub const MAX_DIMENSION_MBS: u32 = 1_024;

/// Sequence parameter set fields used by the pixel decoder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeqParams {
    /// `seq_parameter_set_id` (0..=31).
    pub id: u8,
    /// `profile_idc`.
    pub profile_idc: u8,
    /// Width of `frame_num` in bits (4..=16).
    pub log2_max_frame_num: u8,
    /// `pic_order_cnt_type` (0 or 2 admitted; 1 is refused).
    pub poc_type: u8,
    /// Width of `pic_order_cnt_lsb` in bits (POC type 0 only).
    pub log2_max_poc_lsb: u8,
    /// `max_num_ref_frames` (0..=16).
    pub max_num_ref_frames: u32,
    /// `gaps_in_frame_num_value_allowed_flag`.
    pub gaps_in_frame_num_allowed: bool,
    /// Picture width in macroblocks.
    pub width_mbs: u32,
    /// Picture height in macroblocks (frame pictures only).
    pub height_mbs: u32,
    /// Luma crop offsets in samples: left, right, top, bottom.
    pub crop: [u32; 4],
}

impl SeqParams {
    /// Coded luma width in samples (before cropping).
    #[must_use]
    pub const fn coded_width(&self) -> u32 {
        self.width_mbs * 16
    }

    /// Coded luma height in samples (before cropping).
    #[must_use]
    pub const fn coded_height(&self) -> u32 {
        self.height_mbs * 16
    }

    /// Visible luma width after cropping.
    #[must_use]
    pub const fn display_width(&self) -> u32 {
        self.coded_width() - self.crop[0] - self.crop[1]
    }

    /// Visible luma height after cropping.
    #[must_use]
    pub const fn display_height(&self) -> u32 {
        self.coded_height() - self.crop[2] - self.crop[3]
    }

    /// `PicSizeInMbs`.
    #[must_use]
    pub const fn mbs(&self) -> u32 {
        self.width_mbs * self.height_mbs
    }
}

/// Picture parameter set fields used by the pixel decoder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PicParams {
    /// `pic_parameter_set_id` (0..=255).
    pub id: u8,
    /// `seq_parameter_set_id` this PPS refers to.
    pub sps_id: u8,
    /// `bottom_field_pic_order_in_frame_present_flag`.
    pub bottom_field_pic_order_present: bool,
    /// `num_ref_idx_l0_default_active_minus1 + 1`.
    pub num_ref_idx_l0_default: u32,
    /// `weighted_pred_flag` (refused at slice level for P slices).
    pub weighted_pred: bool,
    /// `26 + pic_init_qp_minus26`.
    pub pic_init_qp: i32,
    /// `chroma_qp_index_offset` (Cb).
    pub chroma_qp_index_offset: i32,
    /// `second_chroma_qp_index_offset` (Cr); equals the Cb offset when absent.
    pub second_chroma_qp_index_offset: i32,
    /// `deblocking_filter_control_present_flag`.
    pub deblocking_filter_control_present: bool,
    /// `constrained_intra_pred_flag`.
    pub constrained_intra_pred: bool,
    /// `redundant_pic_cnt_present_flag`.
    pub redundant_pic_cnt_present: bool,
}

fn refuse(feature: UnsupportedFeature) -> DecodeError {
    DecodeError::Unsupported(feature)
}

/// Profiles whose SPS carries chroma_format_idc and bit-depth syntax.
const fn has_chroma_format_syntax(profile: u8) -> bool {
    matches!(
        profile,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
    )
}

/// Parses SPS decode fields from the RBSP (NAL header already removed).
///
/// # Errors
/// [`DecodeError::Malformed`] on out-of-range syntax or bad cropping;
/// [`DecodeError::Unsupported`] for tools outside the admitted set;
/// [`DecodeError::Limit`] when dimensions exceed [`MAX_DIMENSION_MBS`].
pub fn parse_sps(rbsp: &[u8]) -> Result<SeqParams, DecodeError> {
    let mut r = BitReader::new(rbsp, rbsp.len() * 8);
    let profile_idc = u8::try_from(r.uint(8)?).map_err(|_| DecodeError::Malformed)?;
    let _constraints = r.uint(8)?;
    let _level = r.uint(8)?;
    let id = u8::try_from(r.ue(31)?).map_err(|_| DecodeError::Malformed)?;
    if has_chroma_format_syntax(profile_idc) {
        let chroma_format_idc = r.ue(3)?;
        if chroma_format_idc == 3 {
            // separate_colour_plane_flag: either way 4:4:4 is refused.
            r.bit()?;
        }
        if chroma_format_idc != 1 {
            return Err(refuse(UnsupportedFeature::SampleFormat));
        }
        let bit_depth_luma = r.ue(6)?;
        let bit_depth_chroma = r.ue(6)?;
        if bit_depth_luma != 0 || bit_depth_chroma != 0 {
            return Err(refuse(UnsupportedFeature::SampleFormat));
        }
        if r.flag()? {
            return Err(refuse(UnsupportedFeature::TransformBypass));
        }
        if r.flag()? {
            return Err(refuse(UnsupportedFeature::ScalingMatrix));
        }
    }
    let log2_max_frame_num = u8::try_from(r.ue(12)? + 4).map_err(|_| DecodeError::Malformed)?;
    let poc_type = u8::try_from(r.ue(2)?).map_err(|_| DecodeError::Malformed)?;
    let mut log2_max_poc_lsb = 0;
    match poc_type {
        0 => {
            log2_max_poc_lsb = u8::try_from(r.ue(12)? + 4).map_err(|_| DecodeError::Malformed)?;
        }
        1 => return Err(refuse(UnsupportedFeature::PocType1)),
        _ => {}
    }
    let max_num_ref_frames = r.ue(16)?;
    let gaps_in_frame_num_allowed = r.flag()?;
    let width_mbs = r.ue(MAX_DIMENSION_MBS - 1)? + 1;
    let height_map_units = r.ue(MAX_DIMENSION_MBS - 1)? + 1;
    let frame_mbs_only = r.flag()?;
    if !frame_mbs_only {
        return Err(refuse(UnsupportedFeature::Interlaced));
    }
    let _direct_8x8_inference = r.flag()?;
    let mut crop = [0u32; 4];
    if r.flag()? {
        // left, right, top, bottom in crop units (2 luma samples for 4:2:0
        // frame pictures).
        for value in &mut crop {
            *value = r.ue(8 * MAX_DIMENSION_MBS)?.saturating_mul(2);
        }
    }
    let height_mbs = height_map_units;
    if crop[0] + crop[1] >= width_mbs * 16 || crop[2] + crop[3] >= height_mbs * 16 {
        return Err(DecodeError::Malformed);
    }
    // VUI (if any) carries no decode-relevant syntax for this tool set; its
    // validity was already established by fss-packet admission.
    Ok(SeqParams {
        id,
        profile_idc,
        log2_max_frame_num,
        poc_type,
        log2_max_poc_lsb,
        max_num_ref_frames,
        gaps_in_frame_num_allowed,
        width_mbs,
        height_mbs,
        crop,
    })
}

/// Parses PPS decode fields from the RBSP (NAL header already removed).
///
/// # Errors
/// [`DecodeError::Malformed`] on out-of-range syntax;
/// [`DecodeError::Unsupported`] for CABAC, slice groups, the 8x8 transform
/// or scaling matrices.
pub fn parse_pps(rbsp: &[u8]) -> Result<PicParams, DecodeError> {
    let stop = crate::rbsp::stop_bit_position(rbsp)?;
    let mut r = BitReader::new(rbsp, stop);
    let id = u8::try_from(r.ue(255)?).map_err(|_| DecodeError::Malformed)?;
    let sps_id = u8::try_from(r.ue(31)?).map_err(|_| DecodeError::Malformed)?;
    if r.flag()? {
        return Err(refuse(UnsupportedFeature::Cabac));
    }
    let bottom_field_pic_order_present = r.flag()?;
    if r.ue(7)? != 0 {
        return Err(refuse(UnsupportedFeature::SliceGroups));
    }
    let num_ref_idx_l0_default = r.ue(31)? + 1;
    let _num_ref_idx_l1_default = r.ue(31)?;
    let weighted_pred = r.flag()?;
    if r.uint(2)? > 2 {
        return Err(DecodeError::Malformed);
    }
    let pic_init_qp = 26 + r.se_range(-26, 25)?;
    let _pic_init_qs = r.se_range(-26, 25)?;
    let chroma_qp_index_offset = r.se_range(-12, 12)?;
    let deblocking_filter_control_present = r.flag()?;
    let constrained_intra_pred = r.flag()?;
    let redundant_pic_cnt_present = r.flag()?;
    let mut second_chroma_qp_index_offset = chroma_qp_index_offset;
    // more_rbsp_data(): bits remain before the stop bit.
    if !r.exhausted() {
        if r.flag()? {
            return Err(refuse(UnsupportedFeature::Transform8x8));
        }
        if r.flag()? {
            return Err(refuse(UnsupportedFeature::ScalingMatrix));
        }
        second_chroma_qp_index_offset = r.se_range(-12, 12)?;
    }
    if !r.exhausted() {
        return Err(DecodeError::Malformed);
    }
    Ok(PicParams {
        id,
        sps_id,
        bottom_field_pic_order_present,
        num_ref_idx_l0_default,
        weighted_pred,
        pic_init_qp,
        chroma_qp_index_offset,
        second_chroma_qp_index_offset,
        deblocking_filter_control_present,
        constrained_intra_pred,
        redundant_pic_cnt_present,
    })
}
