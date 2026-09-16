#![forbid(unsafe_code)]

use std::{fmt, sync::Arc};

use super::{AvcError, AvcSyntaxLimits, bits::Bits, checked_nal};

/// Picture-order syntax needed for primary-picture identity, not decoded POC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PocMode {
    /// Type zero carries a wrapping least-significant picture-order counter.
    Lsb {
        /// Width of pic_order_cnt_lsb in bits, between four and sixteen.
        bits: u8,
    },
    /// Type one may carry signed picture-order deltas.
    Delta {
        /// Whether both deltas are implicitly zero.
        always_zero: bool,
    },
    /// Type two derives order without explicit slice-header POC fields.
    Implicit,
}

/// Uninterpreted VUI clock ratio. It does not establish capture time or live FPS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AvcTimingInfo {
    /// Positive num_units_in_tick from the bitstream.
    pub num_units_in_tick: u32,
    /// Positive time_scale from the bitstream.
    pub time_scale: u32,
    /// Sender's fixed-frame-rate assertion; not a continuity certificate.
    pub fixed_frame_rate: bool,
}

/// Validated SPS metadata. Construction is restricted to the bounded parser.
/// The exact original SPS NAL remains necessary for decoding and provenance.
#[derive(Clone, Eq, PartialEq)]
pub struct AvcSps {
    source: Arc<[u8]>,
    pub(super) id: u8,
    profile: u8,
    level: u8,
    constraints: u8,
    pub(super) frame_num_bits: u8,
    pub(super) poc: PocMode,
    pub(super) frame_mbs_only: bool,
    pub(super) mb_adaptive_frame_field: bool,
    pub(super) width_mbs: u32,
    pub(super) height_map_units: u32,
    coded_width: u32,
    coded_height: u32,
    display_width: u32,
    display_height: u32,
    crop_origin: (u32, u32),
    reference_frames: u32,
    timing: Option<AvcTimingInfo>,
}

impl fmt::Debug for AvcSps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AvcSps")
            .field("id", &self.id)
            .field("profile", &self.profile)
            .field("level", &self.level)
            .field("coded_dimensions", &self.coded_dimensions())
            .field("display_dimensions", &self.display_dimensions())
            .field("nal_bytes", &self.source.len())
            .finish_non_exhaustive()
    }
}

impl AvcSps {
    /// Exact immutable original SPS NAL, not a re-encoded approximation.
    pub fn nal_bytes(&self) -> &[u8] {
        &self.source
    }

    pub(super) fn check_limits(&self, limits: AvcSyntaxLimits) -> Result<(), AvcError> {
        limits.validate()?;
        if self.source.len() > limits.max_parameter_set_bytes
            || self.coded_width > limits.max_width
            || self.coded_height > limits.max_height
            || u64::from(self.coded_width) * u64::from(self.coded_height) > limits.max_luma_samples
            || self.reference_frames > limits.max_reference_frames
        {
            return Err(AvcError::Limit);
        }
        Ok(())
    }

    /// Bitstream-local SPS id; it is not an immutable configuration identity.
    pub fn id(&self) -> u8 {
        self.id
    }
    /// Baseline (66), Main (77), or High (100) profile indicator.
    pub fn profile_idc(&self) -> u8 {
        self.profile
    }
    /// Signalled level indicator, without claiming complete level conformance.
    pub fn level_idc(&self) -> u8 {
        self.level
    }
    /// Constraint flag byte with its reserved low two bits verified zero.
    pub fn constraint_flags(&self) -> u8 {
        self.constraints
    }
    /// Coded luma dimensions, before frame cropping.
    pub fn coded_dimensions(&self) -> (u32, u32) {
        (self.coded_width, self.coded_height)
    }
    /// Visible luma dimensions, after checked chroma-dependent cropping.
    pub fn display_dimensions(&self) -> (u32, u32) {
        (self.display_width, self.display_height)
    }
    /// Luma-pixel origin of the cropped visible rectangle.
    pub fn crop_origin(&self) -> (u32, u32) {
        self.crop_origin
    }
    /// Whether every coded picture is a frame rather than a field.
    pub fn frame_mbs_only(&self) -> bool {
        self.frame_mbs_only
    }
    /// Frame-number field width; wrapping is not a source-generation change by itself.
    pub fn frame_num_bits(&self) -> u8 {
        self.frame_num_bits
    }
    /// Picture-order syntax admitted for slice identity parsing.
    pub fn poc_mode(&self) -> PocMode {
        self.poc
    }
    /// Declared reference-frame count, not observed decoder memory use.
    pub fn max_num_ref_frames(&self) -> u32 {
        self.reference_frames
    }
    /// Optional signalled timing; no wall-clock or NTP inference is made.
    pub fn timing(&self) -> Option<AvcTimingInfo> {
        self.timing
    }
}

/// Validated PPS metadata tied to one parsed SPS. Decode syntax not represented
/// here remains in the exact original PPS NAL, never in a reconstructed default.
#[derive(Clone, Eq, PartialEq)]
pub struct AvcPps {
    source: Arc<[u8]>,
    sps_source: Arc<[u8]>,
    pub(super) id: u16,
    pub(super) sps_id: u8,
    pub(super) bottom_poc_present: bool,
    pub(super) redundant_pic_cnt_present: bool,
    entropy_coding: bool,
    transform_8x8: bool,
}

impl fmt::Debug for AvcPps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AvcPps")
            .field("id", &self.id)
            .field("sps_id", &self.sps_id)
            .field("nal_bytes", &self.source.len())
            .finish_non_exhaustive()
    }
}

impl AvcPps {
    /// Exact immutable original PPS NAL, not an inferred/defaulted reconstruction.
    pub fn nal_bytes(&self) -> &[u8] {
        &self.source
    }

    pub(super) fn binds(&self, sps: &AvcSps) -> bool {
        self.sps_id == sps.id
            && (Arc::ptr_eq(&self.sps_source, &sps.source) || self.sps_source == sps.source)
    }

    /// Bitstream-local PPS id; reusing it does not preserve configuration identity.
    pub fn id(&self) -> u16 {
        self.id
    }
    /// SPS id to which this PPS refers.
    pub fn sps_id(&self) -> u8 {
        self.sps_id
    }
    /// Whether CABAC rather than CAVLC is signalled.
    pub fn entropy_coding_mode(&self) -> bool {
        self.entropy_coding
    }
    /// Whether 8x8 transform syntax is enabled.
    pub fn transform_8x8_mode(&self) -> bool {
        self.transform_8x8
    }
}

fn parameter_bits(nal: &[u8], kind: u8, limits: AvcSyntaxLimits) -> Result<Bits<'_>, AvcError> {
    let header = checked_nal(nal, limits)?;
    if nal.len() > limits.max_parameter_set_bytes {
        return Err(AvcError::Limit);
    }
    if header & 31 != kind {
        return Err(AvcError::UnexpectedNal);
    }
    if header & 0x60 == 0 {
        return Err(AvcError::Malformed);
    }
    Ok(Bits::new(&nal[1..], limits.max_parameter_set_bytes * 8))
}

/// Parse a complete SPS, including bounded scaling lists, VUI/HRD, and trailing
/// bits. All dimension budgets apply before cropping. Only a successfully parsed,
/// byte-bounded original parameter set is copied into immutable shared storage.
pub fn parse_sps(nal: &[u8], limits: AvcSyntaxLimits) -> Result<AvcSps, AvcError> {
    let mut b = parameter_bits(nal, 7, limits)?;
    let profile = b.uint(8)? as u8;
    if !matches!(profile, 66 | 77 | 100) {
        return Err(AvcError::UnsupportedProfile);
    }
    let constraints = b.uint(8)? as u8;
    if constraints & 3 != 0 {
        return Err(AvcError::Malformed);
    }
    let level = b.uint(8)? as u8;
    let id = b.ue(31)? as u8;
    if profile == 100 {
        if b.ue(3)? != 1 || b.ue(6)? != 0 || b.ue(6)? != 0 {
            return Err(AvcError::UnsupportedSampleFormat);
        }
        b.bit()?; // qpprime_y_zero_transform_bypass_flag
        if b.bit()? {
            for index in 0..8 {
                if b.bit()? {
                    scaling_list(&mut b, if index < 6 { 16 } else { 64 })?;
                }
            }
        }
    }
    let frame_num_bits = b.ue(12)? as u8 + 4;
    let poc = match b.ue(2)? {
        0 => PocMode::Lsb { bits: b.ue(12)? as u8 + 4 },
        1 => {
            let always_zero = b.bit()?;
            b.se(i32::MIN + 1, i32::MAX)?;
            b.se(i32::MIN + 1, i32::MAX)?;
            let count = b.ue(255)?;
            for _ in 0..count {
                b.se(i32::MIN + 1, i32::MAX)?;
            }
            PocMode::Delta { always_zero }
        }
        _ => PocMode::Implicit,
    };
    let reference_frames = b.ue(limits.max_reference_frames)?;
    b.bit()?; // gaps_in_frame_num_value_allowed_flag
    let width_mbs = b.ue(1_023)? + 1;
    let height_map_units = b.ue(1_023)? + 1;
    let frame_mbs_only = b.bit()?;
    let mb_adaptive_frame_field = if frame_mbs_only { false } else { b.bit()? };
    b.bit()?; // direct_8x8_inference_flag
    let field_factor = if frame_mbs_only { 1 } else { 2 };
    let coded_width = width_mbs * 16;
    let coded_height = height_map_units * 16 * field_factor;
    if coded_width > limits.max_width
        || coded_height > limits.max_height
        || u64::from(coded_width) * u64::from(coded_height) > limits.max_luma_samples
    {
        return Err(AvcError::Limit);
    }
    let mut crop = [0_u32; 4];
    if b.bit()? {
        for value in &mut crop {
            *value = b.ue(16_384)?;
        }
    }
    // 8-bit 4:2:0 has crop units (2, 2 * frame/field factor).
    let horizontal_crop = (crop[0] + crop[1]) * 2;
    let vertical_crop = (crop[2] + crop[3]) * 2 * field_factor;
    if horizontal_crop >= coded_width || vertical_crop >= coded_height {
        return Err(AvcError::Malformed);
    }
    let timing = if b.bit()? { vui(&mut b, reference_frames)? } else { None };
    b.finish()?;
    Ok(AvcSps {
        source: retain(nal)?,
        id, profile, level, constraints, frame_num_bits, poc, frame_mbs_only,
        mb_adaptive_frame_field, width_mbs, height_map_units, coded_width, coded_height,
        display_width: coded_width - horizontal_crop,
        display_height: coded_height - vertical_crop,
        crop_origin: (crop[0] * 2, crop[2] * 2 * field_factor),
        reference_frames, timing,
    })
}

/// Parse a complete PPS against its exact SPS. Unsupported slice groups fail
/// before traversing a potentially large map. Optional High-profile fields and
/// rbsp_trailing_bits are checked; malformed suffixes cannot be accepted silently.
pub fn parse_pps(nal: &[u8], sps: &AvcSps, limits: AvcSyntaxLimits) -> Result<AvcPps, AvcError> {
    sps.check_limits(limits)?;
    let mut b = parameter_bits(nal, 8, limits)?;
    let id = b.ue(255)? as u16;
    let sps_id = b.ue(31)? as u8;
    if sps_id != sps.id {
        return Err(AvcError::ParameterSetMismatch);
    }
    let entropy_coding = b.bit()?;
    if entropy_coding && sps.profile == 66 {
        return Err(AvcError::UnsupportedPicture);
    }
    let bottom_poc_present = b.bit()?;
    if b.ue(7)? != 0 {
        return Err(AvcError::UnsupportedSliceGroups);
    }
    b.ue(31)?; // num_ref_idx_l0_default_active_minus1
    b.ue(31)?; // num_ref_idx_l1_default_active_minus1
    b.bit()?; // weighted_pred_flag
    if b.uint(2)? > 2 {
        return Err(AvcError::Malformed);
    }
    b.se(-26, 25)?; // pic_init_qp_minus26
    b.se(-26, 25)?; // pic_init_qs_minus26
    b.se(-12, 12)?; // chroma_qp_index_offset
    b.bit()?; // deblocking_filter_control_present_flag
    b.bit()?; // constrained_intra_pred_flag
    let redundant_pic_cnt_present = b.bit()?;
    let mut transform_8x8 = false;
    if b.more_data() {
        transform_8x8 = b.bit()?;
        if transform_8x8 && sps.profile != 100 {
            return Err(AvcError::UnsupportedPicture);
        }
        if b.bit()? {
            for index in 0..(6 + if transform_8x8 { 2 } else { 0 }) {
                if b.bit()? {
                    scaling_list(&mut b, if index < 6 { 16 } else { 64 })?;
                }
            }
        }
        b.se(-12, 12)?; // second_chroma_qp_index_offset
    }
    b.finish()?;
    Ok(AvcPps { source: retain(nal)?, sps_source: Arc::clone(&sps.source), id, sps_id, bottom_poc_present, redundant_pic_cnt_present,
        entropy_coding, transform_8x8 })
}

fn scaling_list(b: &mut Bits<'_>, size: usize) -> Result<(), AvcError> {
    let mut last = 8;
    let mut next = 8;
    for _ in 0..size {
        if next != 0 {
            next = (last + b.se(-128, 127)? + 256) % 256;
        }
        if next != 0 { last = next; }
    }
    Ok(())
}

fn hrd(b: &mut Bits<'_>) -> Result<(), AvcError> {
    let count = b.ue(31)? + 1;
    b.uint(4)?; // bit_rate_scale
    b.uint(4)?; // cpb_size_scale
    for _ in 0..count {
        b.ue(u32::MAX - 1)?;
        b.ue(u32::MAX - 1)?;
        b.bit()?;
    }
    for _ in 0..4 { b.uint(5)?; }
    Ok(())
}

fn vui(b: &mut Bits<'_>, reference_frames: u32) -> Result<Option<AvcTimingInfo>, AvcError> {
    if b.bit()? { // aspect_ratio_info_present_flag
        let idc = b.uint(8)?;
        if idc == 255 {
            if b.uint(16)? == 0 || b.uint(16)? == 0 {
                return Err(AvcError::Malformed);
            }
        } else if idc > 16 {
            return Err(AvcError::Malformed);
        }
    }
    if b.bit()? { b.bit()?; } // overscan_info_present_flag
    if b.bit()? { // video_signal_type_present_flag
        if b.uint(3)? > 5 { return Err(AvcError::Malformed); }
        b.bit()?;
        if b.bit()? { b.uint(8)?; b.uint(8)?; b.uint(8)?; }
    }
    if b.bit()? { b.ue(5)?; b.ue(5)?; } // chroma_loc_info_present_flag
    let timing = if b.bit()? {
        let num_units_in_tick = b.uint(32)?;
        let time_scale = b.uint(32)?;
        let fixed_frame_rate = b.bit()?;
        if num_units_in_tick == 0 || time_scale == 0 { return Err(AvcError::Malformed); }
        Some(AvcTimingInfo { num_units_in_tick, time_scale, fixed_frame_rate })
    } else { None };
    let nal_hrd = b.bit()?;
    if nal_hrd { hrd(b)?; }
    let vcl_hrd = b.bit()?;
    if vcl_hrd { hrd(b)?; }
    if nal_hrd || vcl_hrd { b.bit()?; }
    b.bit()?; // pic_struct_present_flag
    if b.bit()? { // bitstream_restriction_flag
        b.bit()?;
        for _ in 0..4 { b.ue(16)?; }
        let reordered = b.ue(16)?;
        let buffered = b.ue(16)?;
        if reordered > buffered || buffered < reference_frames {
            return Err(AvcError::Malformed);
        }
    }
    Ok(timing)
}

fn retain(nal: &[u8]) -> Result<Arc<[u8]>, AvcError> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(nal.len()).map_err(|_| AvcError::Allocation)?;
    bytes.extend_from_slice(nal);
    Ok(Arc::from(bytes))
}
