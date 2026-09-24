//! Decode-relevant SPS and PPS fields (clauses 7.3.2.1.1, 7.3.2.2 and
//! Annex E.1.1).
//!
//! `fss-packet` owns parameter-set *admission* (bounds, profile, VUI
//! validity, custody of the exact bytes). The decoder admits every SPS/PPS
//! through it first and then reads here the fields custody deliberately
//! leaves in the original bytes (QP init, chroma offsets, deblocking and
//! constrained-intra controls, entropy coding mode, weighted prediction,
//! the 8x8 transform, scaling lists, POC and frame_num widths, cropping,
//! and the VUI reorder/DPB bounds). Tools outside the admitted set are
//! refused with a typed [`UnsupportedFeature`], never approximated.

use crate::bits::BitReader;
use crate::transform::{ZIGZAG_4X4, ZIGZAG_8X8};
use crate::{DecodeError, UnsupportedFeature};

/// Hard ceiling on picture width/height in macroblocks accepted by syntax
/// (matches `fss-packet`); budgets in `DecoderLimits` are usually tighter.
pub const MAX_DIMENSION_MBS: u32 = 1_024;

/// `Default_4x4_Intra` (Table 7-3), raster order.
pub const DEFAULT_4X4_INTRA: [u8; 16] = [
    6, 13, 20, 28, 13, 20, 28, 32, 20, 28, 32, 37, 28, 32, 37, 42,
];
/// `Default_4x4_Inter` (Table 7-3), raster order.
pub const DEFAULT_4X4_INTER: [u8; 16] = [
    10, 14, 20, 24, 14, 20, 24, 27, 20, 24, 27, 30, 24, 27, 30, 34,
];
/// `Default_8x8_Intra` (Table 7-4), raster order.
pub const DEFAULT_8X8_INTRA: [u8; 64] = [
    6, 10, 13, 16, 18, 23, 25, 27, 10, 11, 16, 18, 23, 25, 27, 29, 13, 16, 18, 23, 25, 27, 29, 31,
    16, 18, 23, 25, 27, 29, 31, 33, 18, 23, 25, 27, 29, 31, 33, 36, 23, 25, 27, 29, 31, 33, 36, 38,
    25, 27, 29, 31, 33, 36, 38, 40, 27, 29, 31, 33, 36, 38, 40, 42,
];
/// `Default_8x8_Inter` (Table 7-4), raster order.
pub const DEFAULT_8X8_INTER: [u8; 64] = [
    9, 13, 15, 17, 19, 21, 22, 24, 13, 13, 17, 19, 21, 22, 24, 25, 15, 17, 19, 21, 22, 24, 25, 27,
    17, 19, 21, 22, 24, 25, 27, 28, 19, 21, 22, 24, 25, 27, 28, 30, 21, 22, 24, 25, 27, 28, 30, 32,
    22, 24, 25, 27, 28, 30, 32, 33, 24, 25, 27, 28, 30, 32, 33, 35,
];

/// Resolved scaling matrices for 4:2:0 (clause 7.4.2.1.1): six 4x4 lists
/// (Intra Y, Cb, Cr, Inter Y, Cb, Cr) and two 8x8 lists (Intra Y, Inter
/// Y), all in raster order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScalingMatrix {
    /// `weightScale4x4` per list, raster order.
    pub list4x4: [[u8; 16]; 6],
    /// `weightScale8x8` per list, raster order.
    pub list8x8: [[u8; 64]; 2],
}

impl ScalingMatrix {
    /// `Flat_4x4_16` / `Flat_8x8_16` everywhere.
    #[must_use]
    pub const fn flat() -> Self {
        Self {
            list4x4: [[16; 16]; 6],
            list8x8: [[16; 64]; 2],
        }
    }
}

/// One `scaling_list()` as coded: absent, "use the default list", or
/// explicit values (raster order).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScalingListSyntax {
    /// `*_scaling_list_present_flag == 0`: a fall-back rule applies.
    NotPresent,
    /// `useDefaultScalingMatrixFlag == 1`.
    UseDefault,
    /// Explicit 4x4 list, raster order.
    Explicit4x4([u8; 16]),
    /// Explicit 8x8 list, raster order.
    Explicit8x8(Box<[u8; 64]>),
}

/// Sequence parameter set fields used by the pixel decoder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeqParams {
    /// `seq_parameter_set_id` (0..=31).
    pub id: u8,
    /// `profile_idc`.
    pub profile_idc: u8,
    /// `constraint_set3_flag` (level 1b signalling for level_idc 11).
    pub constraint_set3: bool,
    /// `level_idc`.
    pub level_idc: u8,
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
    /// `direct_8x8_inference_flag`.
    pub direct_8x8_inference: bool,
    /// Luma crop offsets in samples: left, right, top, bottom.
    pub crop: [u32; 4],
    /// Sequence-level scaling matrices; `None` when
    /// `seq_scaling_matrix_present_flag == 0` (flat).
    pub scaling: Option<ScalingMatrix>,
    /// VUI `max_num_reorder_frames`, when `bitstream_restriction_flag`.
    pub max_num_reorder_frames: Option<u32>,
    /// VUI `max_dec_frame_buffering`, when `bitstream_restriction_flag`.
    pub max_dec_frame_buffering: Option<u32>,
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

    /// `MaxDpbFrames` (clause A.3.1 item h, Table A-1): `MaxDpbMbs /
    /// PicSizeInMbs`, at most 16, and never below `max_num_ref_frames` or
    /// the VUI `max_dec_frame_buffering`. Unknown levels use 16.
    #[must_use]
    pub fn max_dpb_frames(&self) -> u32 {
        let max_dpb_mbs: u32 = match (self.level_idc, self.constraint_set3) {
            (9 | 10, _) | (11, true) => 396,
            (11, false) => 900,
            (12 | 13 | 20, _) => 2_376,
            (21, _) => 4_752,
            (22 | 30, _) => 8_100,
            (31, _) => 18_000,
            (32, _) => 20_480,
            (40 | 41, _) => 32_768,
            (42, _) => 34_816,
            (50, _) => 110_400,
            (51 | 52, _) => 184_320,
            (60..=62, _) => 696_320,
            _ => u32::MAX,
        };
        let by_level = (max_dpb_mbs / self.mbs().max(1)).clamp(1, 16);
        let by_vui = self.max_dec_frame_buffering.unwrap_or(0).min(16);
        by_level
            .max(by_vui)
            .max(self.max_num_ref_frames.max(1))
            .min(16)
    }
}

/// Picture parameter set fields used by the pixel decoder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PicParams {
    /// `pic_parameter_set_id` (0..=255).
    pub id: u8,
    /// `seq_parameter_set_id` this PPS refers to.
    pub sps_id: u8,
    /// `entropy_coding_mode_flag` (CABAC when set).
    pub entropy_coding_mode: bool,
    /// `bottom_field_pic_order_in_frame_present_flag`.
    pub bottom_field_pic_order_present: bool,
    /// `num_ref_idx_l0_default_active_minus1 + 1`.
    pub num_ref_idx_l0_default: u32,
    /// `num_ref_idx_l1_default_active_minus1 + 1`.
    pub num_ref_idx_l1_default: u32,
    /// `weighted_pred_flag` (explicit weighted prediction in P slices).
    pub weighted_pred: bool,
    /// `weighted_bipred_idc` (0 default, 1 explicit, 2 implicit).
    pub weighted_bipred_idc: u8,
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
    /// `transform_8x8_mode_flag`.
    pub transform_8x8_mode: bool,
    /// Picture-level scaling list syntax (`pic_scaling_matrix_present_flag`),
    /// resolved against the SPS by [`resolve_scaling`].
    pub scaling: Option<Vec<ScalingListSyntax>>,
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

/// Reads one `scaling_list()` (clause 7.3.2.1.1.1) of `size` 16 or 64
/// entries; values are delivered in raster order.
fn scaling_list(r: &mut BitReader<'_>, size: usize) -> Result<ScalingListSyntax, DecodeError> {
    let mut values = [0u8; 64];
    let mut last: i32 = 8;
    let mut next: i32 = 8;
    for j in 0..size {
        if next != 0 {
            let delta = r.se_range(-128, 127)?;
            next = (last + delta + 256) % 256;
            if j == 0 && next == 0 {
                return Ok(ScalingListSyntax::UseDefault);
            }
        }
        let value = if next == 0 { last } else { next };
        let raster = if size == 16 {
            ZIGZAG_4X4[j]
        } else {
            ZIGZAG_8X8[j]
        };
        values[raster] = u8::try_from(value).map_err(|_| DecodeError::Malformed)?;
        last = value;
    }
    if size == 16 {
        let mut list = [0u8; 16];
        list.copy_from_slice(&values[..16]);
        Ok(ScalingListSyntax::Explicit4x4(list))
    } else {
        Ok(ScalingListSyntax::Explicit8x8(Box::new(values)))
    }
}

fn scaling_lists(
    r: &mut BitReader<'_>,
    count: usize,
) -> Result<Vec<ScalingListSyntax>, DecodeError> {
    let mut lists = Vec::with_capacity(count);
    for index in 0..count {
        lists.push(if r.flag()? {
            scaling_list(r, if index < 6 { 16 } else { 64 })?
        } else {
            ScalingListSyntax::NotPresent
        });
    }
    Ok(lists)
}

/// Applies fall-back rules (Table 7-2) to coded list syntax. `fallback4`
/// and `fallback8` supply the list used when list 0/3 (4x4) or 6/7 (8x8)
/// is absent: the defaults (rule A) or the sequence-level lists (rule B).
fn apply_fallback(
    syntax: &[ScalingListSyntax],
    fallback4: [&[u8; 16]; 2],
    fallback8: [&[u8; 64]; 2],
) -> ScalingMatrix {
    let mut out = ScalingMatrix::flat();
    for index in 0..6 {
        let default = if index < 3 {
            &DEFAULT_4X4_INTRA
        } else {
            &DEFAULT_4X4_INTER
        };
        out.list4x4[index] = match syntax.get(index) {
            Some(ScalingListSyntax::Explicit4x4(list)) => *list,
            Some(ScalingListSyntax::UseDefault) => *default,
            _ if index == 0 || index == 3 => *fallback4[index / 3],
            _ => out.list4x4[index - 1],
        };
    }
    for index in 0..2 {
        let default = if index == 0 {
            &DEFAULT_8X8_INTRA
        } else {
            &DEFAULT_8X8_INTER
        };
        out.list8x8[index] = match syntax.get(6 + index) {
            Some(ScalingListSyntax::Explicit8x8(list)) => **list,
            Some(ScalingListSyntax::UseDefault) => *default,
            _ => *fallback8[index],
        };
    }
    out
}

/// Scaling matrices in force for a slice (clause 7.4.2.2): the PPS lists
/// when `pic_scaling_matrix_present_flag`, with fall-back rule A (when the
/// SPS has no matrices) or rule B (SPS lists); otherwise the SPS lists;
/// otherwise flat.
#[must_use]
pub fn resolve_scaling(sps: &SeqParams, pps: &PicParams) -> ScalingMatrix {
    match (&pps.scaling, &sps.scaling) {
        (Some(syntax), Some(seq)) => apply_fallback(
            syntax,
            [&seq.list4x4[0], &seq.list4x4[3]],
            [&seq.list8x8[0], &seq.list8x8[1]],
        ),
        (Some(syntax), None) => apply_fallback(
            syntax,
            [&DEFAULT_4X4_INTRA, &DEFAULT_4X4_INTER],
            [&DEFAULT_8X8_INTRA, &DEFAULT_8X8_INTER],
        ),
        (None, Some(seq)) => seq.clone(),
        (None, None) => ScalingMatrix::flat(),
    }
}

fn hrd_parameters(r: &mut BitReader<'_>) -> Result<(), DecodeError> {
    let count = r.ue(31)? + 1;
    r.uint(8)?; // bit_rate_scale, cpb_size_scale
    for _ in 0..count {
        r.ue(u32::MAX - 1)?;
        r.ue(u32::MAX - 1)?;
        r.bit()?;
    }
    r.uint(20)?; // four 5-bit length fields
    Ok(())
}

/// Reads `vui_parameters()` far enough to recover the bitstream
/// restriction (Annex E.1.1). Returns `(max_num_reorder_frames,
/// max_dec_frame_buffering)` when present.
fn vui_parameters(r: &mut BitReader<'_>) -> Result<Option<(u32, u32)>, DecodeError> {
    if r.flag()? && r.uint(8)? == 255 {
        r.uint(32)?; // sar_width, sar_height
    }
    if r.flag()? {
        r.bit()?; // overscan_appropriate_flag
    }
    if r.flag()? {
        r.uint(4)?; // video_format, video_full_range_flag
        if r.flag()? {
            r.uint(24)?;
        }
    }
    if r.flag()? {
        r.ue(5)?;
        r.ue(5)?;
    }
    if r.flag()? {
        r.uint(32)?;
        r.uint(32)?;
        r.bit()?;
    }
    let nal_hrd = r.flag()?;
    if nal_hrd {
        hrd_parameters(r)?;
    }
    let vcl_hrd = r.flag()?;
    if vcl_hrd {
        hrd_parameters(r)?;
    }
    if nal_hrd || vcl_hrd {
        r.bit()?; // low_delay_hrd_flag
    }
    r.bit()?; // pic_struct_present_flag
    if !r.flag()? {
        return Ok(None);
    }
    r.bit()?; // motion_vectors_over_pic_boundaries_flag
    for _ in 0..4 {
        r.ue(u32::MAX - 1)?;
    }
    let reorder = r.ue(16)?;
    let buffering = r.ue(16)?;
    if reorder > buffering {
        return Err(DecodeError::Malformed);
    }
    Ok(Some((reorder, buffering)))
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
    let constraints = r.uint(8)?;
    let level_idc = u8::try_from(r.uint(8)?).map_err(|_| DecodeError::Malformed)?;
    let id = u8::try_from(r.ue(31)?).map_err(|_| DecodeError::Malformed)?;
    let mut scaling = None;
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
            let syntax = scaling_lists(&mut r, 8)?;
            scaling = Some(apply_fallback(
                &syntax,
                [&DEFAULT_4X4_INTRA, &DEFAULT_4X4_INTER],
                [&DEFAULT_8X8_INTRA, &DEFAULT_8X8_INTER],
            ));
        }
        // Scaling matrices are admitted by the High-profile stage.
        if scaling.is_some() {
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
    let direct_8x8_inference = r.flag()?;
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
    let restriction = if r.flag()? {
        vui_parameters(&mut r)?
    } else {
        None
    };
    Ok(SeqParams {
        id,
        profile_idc,
        constraint_set3: constraints & 0x10 != 0,
        level_idc,
        log2_max_frame_num,
        poc_type,
        log2_max_poc_lsb,
        max_num_ref_frames,
        gaps_in_frame_num_allowed,
        width_mbs,
        height_mbs,
        direct_8x8_inference,
        crop,
        scaling,
        max_num_reorder_frames: restriction.map(|(reorder, _)| reorder),
        max_dec_frame_buffering: restriction.map(|(_, buffering)| buffering),
    })
}

/// Parses PPS decode fields from the RBSP (NAL header already removed).
///
/// # Errors
/// [`DecodeError::Malformed`] on out-of-range syntax;
/// [`DecodeError::Unsupported`] for slice groups, the 8x8 transform or
/// scaling matrices.
pub fn parse_pps(rbsp: &[u8]) -> Result<PicParams, DecodeError> {
    let stop = crate::rbsp::stop_bit_position(rbsp)?;
    let mut r = BitReader::new(rbsp, stop);
    let id = u8::try_from(r.ue(255)?).map_err(|_| DecodeError::Malformed)?;
    let sps_id = u8::try_from(r.ue(31)?).map_err(|_| DecodeError::Malformed)?;
    let entropy_coding_mode = r.flag()?;
    let bottom_field_pic_order_present = r.flag()?;
    if r.ue(7)? != 0 {
        return Err(refuse(UnsupportedFeature::SliceGroups));
    }
    let num_ref_idx_l0_default = r.ue(31)? + 1;
    let num_ref_idx_l1_default = r.ue(31)? + 1;
    let weighted_pred = r.flag()?;
    let weighted_bipred_idc = u8::try_from(r.uint(2)?).map_err(|_| DecodeError::Malformed)?;
    if weighted_bipred_idc > 2 {
        return Err(DecodeError::Malformed);
    }
    let pic_init_qp = 26 + r.se_range(-26, 25)?;
    let _pic_init_qs = r.se_range(-26, 25)?;
    let chroma_qp_index_offset = r.se_range(-12, 12)?;
    let deblocking_filter_control_present = r.flag()?;
    let constrained_intra_pred = r.flag()?;
    let redundant_pic_cnt_present = r.flag()?;
    let mut second_chroma_qp_index_offset = chroma_qp_index_offset;
    let mut transform_8x8_mode = false;
    let mut scaling = None;
    // more_rbsp_data(): bits remain before the stop bit.
    if !r.exhausted() {
        transform_8x8_mode = r.flag()?;
        if r.flag()? {
            let count = 6 + if transform_8x8_mode { 2 } else { 0 };
            scaling = Some(scaling_lists(&mut r, count)?);
        }
        second_chroma_qp_index_offset = r.se_range(-12, 12)?;
        // The 8x8 transform and scaling matrices are admitted by the
        // High-profile stage.
        if transform_8x8_mode {
            return Err(refuse(UnsupportedFeature::Transform8x8));
        }
        if scaling.is_some() {
            return Err(refuse(UnsupportedFeature::ScalingMatrix));
        }
    }
    if !r.exhausted() {
        return Err(DecodeError::Malformed);
    }
    Ok(PicParams {
        id,
        sps_id,
        entropy_coding_mode,
        bottom_field_pic_order_present,
        num_ref_idx_l0_default,
        num_ref_idx_l1_default,
        weighted_pred,
        weighted_bipred_idc,
        pic_init_qp,
        chroma_qp_index_offset,
        second_chroma_qp_index_offset,
        deblocking_filter_control_present,
        constrained_intra_pred,
        redundant_pic_cnt_present,
        transform_8x8_mode,
        scaling,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn sps_with(scaling: Option<ScalingMatrix>) -> SeqParams {
        SeqParams {
            id: 0,
            profile_idc: 100,
            constraint_set3: false,
            level_idc: 30,
            log2_max_frame_num: 4,
            poc_type: 2,
            log2_max_poc_lsb: 0,
            max_num_ref_frames: 1,
            gaps_in_frame_num_allowed: false,
            width_mbs: 11,
            height_mbs: 9,
            direct_8x8_inference: true,
            crop: [0; 4],
            scaling,
            max_num_reorder_frames: None,
            max_dec_frame_buffering: None,
        }
    }

    fn pps_with(scaling: Option<Vec<ScalingListSyntax>>) -> PicParams {
        PicParams {
            id: 0,
            sps_id: 0,
            entropy_coding_mode: true,
            bottom_field_pic_order_present: false,
            num_ref_idx_l0_default: 1,
            num_ref_idx_l1_default: 1,
            weighted_pred: false,
            weighted_bipred_idc: 0,
            pic_init_qp: 26,
            chroma_qp_index_offset: 0,
            second_chroma_qp_index_offset: 0,
            deblocking_filter_control_present: true,
            constrained_intra_pred: false,
            redundant_pic_cnt_present: false,
            transform_8x8_mode: true,
            scaling,
        }
    }

    /// Default lists are the Table 7-3/7-4 zig-zag sequences placed in
    /// raster order: zig-zag index 2 (value 13) lands at raster 4, index 5
    /// (value 20) at raster 2.
    #[test]
    fn default_lists_match_table_7_3_in_zigzag_order() {
        let zigzag_intra = [
            6, 13, 13, 20, 20, 20, 28, 28, 28, 28, 32, 32, 32, 37, 37, 42,
        ];
        let zigzag_inter = [
            10, 14, 14, 20, 20, 20, 24, 24, 24, 24, 27, 27, 27, 30, 30, 34,
        ];
        for k in 0..16 {
            assert_eq!(DEFAULT_4X4_INTRA[ZIGZAG_4X4[k]], zigzag_intra[k]);
            assert_eq!(DEFAULT_4X4_INTER[ZIGZAG_4X4[k]], zigzag_inter[k]);
        }
        // Table 7-4, first and last zig-zag entries and a few in between.
        let intra8 = [
            (0, 6),
            (1, 10),
            (2, 10),
            (3, 13),
            (4, 11),
            (15, 23),
            (63, 42),
        ];
        for (k, value) in intra8 {
            assert_eq!(DEFAULT_8X8_INTRA[ZIGZAG_8X8[k]], value, "intra idx {k}");
        }
        let inter8 = [(0, 9), (1, 13), (5, 15), (21, 22), (62, 33), (63, 35)];
        for (k, value) in inter8 {
            assert_eq!(DEFAULT_8X8_INTER[ZIGZAG_8X8[k]], value, "inter idx {k}");
        }
    }

    /// Fall-back rule A (no SPS matrices): absent lists 0/3/6/7 take the
    /// defaults, absent lists 1, 2, 4, 5 copy their predecessor.
    #[test]
    fn fallback_rule_a_uses_defaults_and_predecessors() {
        let mut custom = [0u8; 16];
        for (i, value) in custom.iter_mut().enumerate() {
            *value = u8::try_from(i + 1).unwrap();
        }
        let syntax = vec![
            ScalingListSyntax::NotPresent,
            ScalingListSyntax::Explicit4x4(custom),
            ScalingListSyntax::NotPresent,
            ScalingListSyntax::NotPresent,
            ScalingListSyntax::UseDefault,
            ScalingListSyntax::NotPresent,
            ScalingListSyntax::NotPresent,
            ScalingListSyntax::UseDefault,
        ];
        let resolved = resolve_scaling(&sps_with(None), &pps_with(Some(syntax)));
        assert_eq!(resolved.list4x4[0], DEFAULT_4X4_INTRA);
        assert_eq!(resolved.list4x4[1], custom);
        assert_eq!(resolved.list4x4[2], custom, "list 2 falls back to list 1");
        assert_eq!(resolved.list4x4[3], DEFAULT_4X4_INTER);
        assert_eq!(resolved.list4x4[4], DEFAULT_4X4_INTER);
        assert_eq!(resolved.list4x4[5], DEFAULT_4X4_INTER);
        assert_eq!(resolved.list8x8[0], DEFAULT_8X8_INTRA);
        assert_eq!(resolved.list8x8[1], DEFAULT_8X8_INTER);
    }

    /// Fall-back rule B (SPS carries matrices): absent PPS lists 0, 3, 6, 7
    /// take the sequence-level lists instead of the defaults.
    #[test]
    fn fallback_rule_b_uses_sequence_lists() {
        let mut seq = ScalingMatrix::flat();
        seq.list4x4[0] = [7; 16];
        seq.list4x4[3] = [9; 16];
        seq.list8x8[0] = [11; 64];
        seq.list8x8[1] = [12; 64];
        let syntax = vec![ScalingListSyntax::NotPresent; 8];
        let resolved = resolve_scaling(&sps_with(Some(seq)), &pps_with(Some(syntax)));
        assert_eq!(
            resolved.list4x4,
            [[7; 16], [7; 16], [7; 16], [9; 16], [9; 16], [9; 16]]
        );
        assert_eq!(resolved.list8x8, [[11; 64], [12; 64]]);
        // No PPS matrices: the SPS lists stand; neither: flat.
        let seq_only = resolve_scaling(&sps_with(Some(ScalingMatrix::flat())), &pps_with(None));
        assert_eq!(seq_only, ScalingMatrix::flat());
        assert_eq!(
            resolve_scaling(&sps_with(None), &pps_with(None)),
            ScalingMatrix::flat()
        );
    }

    /// `scaling_list()` delta decoding: deltas 0 then +2 then a delta that
    /// makes nextScale 0, which repeats the last value to the end.
    #[test]
    fn scaling_list_deltas_and_repeat() {
        // se(0) = "1"; se(+2) = "00100"; se(-10) = ue(20) = "000010101".
        let bits = "1".to_owned() + "00100" + "000010101";
        let mut padded: Vec<u8> = bits.bytes().map(|b| b - b'0').collect();
        while !padded.len().is_multiple_of(8) {
            padded.push(0);
        }
        let bytes: Vec<u8> = padded
            .chunks(8)
            .map(|chunk| chunk.iter().fold(0u8, |acc, &b| (acc << 1) | b))
            .collect();
        let mut reader = BitReader::new(&bytes, bits.len());
        let parsed = scaling_list(&mut reader, 16).unwrap();
        let ScalingListSyntax::Explicit4x4(list) = parsed else {
            panic!("explicit list expected, got {parsed:?}");
        };
        // zig-zag values 8, 10, then 10 repeated.
        assert_eq!(list[ZIGZAG_4X4[0]], 8);
        assert_eq!(list[ZIGZAG_4X4[1]], 10);
        for k in 2..16 {
            assert_eq!(list[ZIGZAG_4X4[k]], 10);
        }
        // First delta -8 makes nextScale 0 at j == 0: use the default list.
        // se(-8) = ue(16) = "000010001".
        let bytes = [0b0000_1000, 0b1000_0000];
        let mut reader = BitReader::new(&bytes, 9);
        assert_eq!(
            scaling_list(&mut reader, 16).unwrap(),
            ScalingListSyntax::UseDefault
        );
    }
}
