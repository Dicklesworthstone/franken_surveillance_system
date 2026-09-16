#![forbid(unsafe_code)]

use super::{AvcError, AvcPps, AvcSps, AvcSyntaxLimits, PocMode, bits::Bits, checked_nal};

/// Normalized slice types admitted by this reference parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AvcSliceType {
    /// Forward/inter prediction.
    P,
    /// Bidirectional prediction.
    B,
    /// Intra prediction; not necessarily an IDR/random-access picture.
    I,
}

/// Bounded primary-picture identity prefix, not a fully validated slice header.
/// Macroblocks, entropy coding, reference lists, and trailing slice data remain
/// opaque. Equality of these fields does not certify that any picture is complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AvcSliceIdentity {
    first_mb: u32,
    slice_type: AvcSliceType,
    pps_id: u16,
    frame_num: u16,
    field_pic: bool,
    bottom_field: bool,
    reference: bool,
    idr_pic_id: Option<u16>,
    poc_lsb: Option<u16>,
    delta_bottom: i32,
    delta_poc: [i32; 2],
    redundant_pic_cnt: u8,
    prefix_bits: usize,
}

impl AvcSliceIdentity {
    /// First macroblock address; not a count of decoded/covered macroblocks.
    pub fn first_mb_in_slice(self) -> u32 {
        self.first_mb
    }
    /// Normalized slice type, preserving I-versus-IDR distinction.
    pub fn slice_type(self) -> AvcSliceType {
        self.slice_type
    }
    /// Referenced bitstream-local PPS identifier.
    pub fn pps_id(self) -> u16 {
        self.pps_id
    }
    /// Wrapping frame number as signalled by this slice.
    pub fn frame_num(self) -> u16 {
        self.frame_num
    }
    /// Whether this is a field picture.
    pub fn field_pic(self) -> bool {
        self.field_pic
    }
    /// Bottom field flag, false when field_pic is false.
    pub fn bottom_field(self) -> bool {
        self.bottom_field
    }
    /// Whether nal_ref_idc is nonzero, without collapsing this into keyframe state.
    pub fn is_reference(self) -> bool {
        self.reference
    }
    /// IDR picture identifier, absent for a non-IDR I slice.
    pub fn idr_pic_id(self) -> Option<u16> {
        self.idr_pic_id
    }
    /// Wrapping type-zero POC field, absent for the other two POC modes.
    pub fn pic_order_cnt_lsb(self) -> Option<u16> {
        self.poc_lsb
    }
    /// Redundant-picture counter; zero denotes a primary picture.
    pub fn redundant_pic_cnt(self) -> u8 {
        self.redundant_pic_cnt
    }
    /// Number of consumed RBSP bits (escapes and the NAL header excluded).
    pub fn prefix_bits(self) -> usize {
        self.prefix_bits
    }

    /// H.264 7.4.1.2.4 picture-boundary comparison for one unchanged exact
    /// configuration. The caller must separately fence configuration changes.
    /// first_mb_in_slice and slice_type are intentionally NOT boundary tests.
    pub fn starts_new_picture(self, previous: Self) -> bool {
        self.frame_num != previous.frame_num
            || self.pps_id != previous.pps_id
            || self.field_pic != previous.field_pic
            || (self.field_pic && previous.field_pic && self.bottom_field != previous.bottom_field)
            || self.reference != previous.reference
            || self.poc_lsb != previous.poc_lsb
            || self.delta_bottom != previous.delta_bottom
            || self.delta_poc != previous.delta_poc
            || self.idr_pic_id != previous.idr_pic_id
    }
}

/// Parse only the fields required for primary-picture identification. This
/// borrows and unescapes only the consumed prefix, applies a bit-work ceiling,
/// checks all parameter references, and does not inspect or copy the slice body.
pub fn parse_slice_identity(
    nal: &[u8],
    sps: &AvcSps,
    pps: &AvcPps,
    limits: AvcSyntaxLimits,
) -> Result<AvcSliceIdentity, AvcError> {
    let header = checked_nal(nal, limits)?;
    let idr = match header & 31 {
        1 => false,
        5 => true,
        2..=4 | 19..=21 => return Err(AvcError::UnsupportedPicture),
        _ => return Err(AvcError::UnexpectedNal),
    };
    if idr && header & 0x60 == 0 { return Err(AvcError::Malformed); }
    sps.check_limits(limits)?;
    if pps.nal_bytes().len() > limits.max_parameter_set_bytes { return Err(AvcError::Limit); }
    if !pps.binds(sps) { return Err(AvcError::ParameterSetMismatch); }
    let mut b = Bits::new(&nal[1..], limits.max_slice_identity_bits);
    let first_mb = b.ue(1_048_575)?;
    let slice_type = match b.ue(9)? % 5 {
        0 => AvcSliceType::P,
        1 => AvcSliceType::B,
        2 => AvcSliceType::I,
        _ => return Err(AvcError::UnsupportedPicture),
    };
    if idr && slice_type != AvcSliceType::I { return Err(AvcError::Malformed); }
    let pps_id = b.ue(255)? as u16;
    if pps_id != pps.id { return Err(AvcError::ParameterSetMismatch); }
    let frame_num = b.uint(sps.frame_num_bits)? as u16;
    if idr && frame_num != 0 { return Err(AvcError::Malformed); }
    let field_pic = !sps.frame_mbs_only && b.bit()?;
    let bottom_field = field_pic && b.bit()?;
    let idr_pic_id = if idr { Some(b.ue(65_535)? as u16) } else { None };
    let mut poc_lsb = None;
    let mut delta_bottom = 0;
    let mut delta_poc = [0; 2];
    match sps.poc {
        PocMode::Lsb { bits } => {
            poc_lsb = Some(b.uint(bits)? as u16);
            if pps.bottom_poc_present && !field_pic {
                delta_bottom = b.se(i32::MIN + 1, i32::MAX)?;
            }
        }
        PocMode::Delta { always_zero: false } => {
            delta_poc[0] = b.se(i32::MIN + 1, i32::MAX)?;
            if pps.bottom_poc_present && !field_pic {
                delta_poc[1] = b.se(i32::MIN + 1, i32::MAX)?;
            }
        }
        _ => {}
    }
    let redundant_pic_cnt = if pps.redundant_pic_cnt_present { b.ue(127)? as u8 } else { 0 };
    let frame_factor = if sps.frame_mbs_only || field_pic { 1 } else { 2 };
    let mbaff_factor = if sps.mb_adaptive_frame_field && !field_pic { 2 } else { 1 };
    let picture_mbs = sps.width_mbs * sps.height_map_units * frame_factor;
    if u64::from(first_mb) * mbaff_factor >= u64::from(picture_mbs) {
        return Err(AvcError::Malformed);
    }
    Ok(AvcSliceIdentity {
        first_mb, slice_type, pps_id, frame_num, field_pic, bottom_field,
        reference: header & 0x60 != 0, idr_pic_id, poc_lsb, delta_bottom,
        delta_poc, redundant_pic_cnt, prefix_bits: b.consumed(),
    })
}
