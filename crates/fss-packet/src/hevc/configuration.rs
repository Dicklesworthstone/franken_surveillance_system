#![forbid(unsafe_code)]
//! Bounded configuration-prefix metadata for HEVC remux, not full parameter-set validation.

/// Resource ceilings for one immutable VPS/SPS/PPS tuple.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HevcConfigurationLimits {
    /// Bytes per original parameter NAL, including its header, in 3..=65535.
    pub max_parameter_bytes: usize,
    /// Coded luma width and height ceilings, each in 1..=16384.
    pub max_width: u32,
    /// Coded height, before conformance cropping.
    pub max_height: u32,
    /// Coded luma sample ceiling, in 1..=268435456.
    pub max_luma_samples: u64,
}
impl Default for HevcConfigurationLimits {
    fn default() -> Self {
        Self { max_parameter_bytes: 65_535, max_width: 8192, max_height: 8192,
            max_luma_samples: 8192 * 8192 }
    }
}
impl HevcConfigurationLimits {
    /// Invalid policies are rejected, never silently widened.
    pub fn validate(self) -> Result<()> {
        if !(3..=65_535).contains(&self.max_parameter_bytes)
            || !(1..=16_384).contains(&self.max_width)
            || !(1..=16_384).contains(&self.max_height)
            || !(1..=268_435_456).contains(&self.max_luma_samples)
        { return Err(HevcConfigurationError::Configuration); }
        Ok(())
    }
}

/// Payload-free prefix-screening failures. None is a decoder verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HevcConfigurationError {
    /// Invalid owner policy.
    Configuration,
    /// Original byte, prefix-work, dimension or arithmetic ceiling exceeded.
    Limit,
    /// Required header or prefix bits were absent.
    Truncated,
    /// Invalid escape, reserved field, identifier or conformance crop.
    Malformed,
    /// Corrupt forbidden-zero bit.
    Corrupt,
    /// Only layer zero, Main/Main10 4:2:0, and a single-layer VPS are admitted.
    Unsupported,
    /// Referenced IDs, temporal configuration or profile declarations disagree.
    Mismatch,
    /// Bounded metadata allocation failed.
    Allocation,
}
impl std::fmt::Display for HevcConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HEVC configuration-prefix refusal: {self:?}")
    }
}
impl std::error::Error for HevcConfigurationError {}
type Result<T> = std::result::Result<T, HevcConfigurationError>;

/// Prefix-screened immutable configuration, retaining exact original NALs.
///
/// The VPS is read through profile_tier_level, the SPS through bit depths, and
/// the PPS through its two IDs. Entire EBSP escape framing is checked, but the
/// remaining RBSP syntax (including VUI/HRD/extensions/trailing bits) is NOT
/// certified. IDs bind the tuple; full parameter-set compatibility, slice bodies,
/// profile conformance and decoding are outside this metadata contract.
///
/// Only Main/Main10, 4:2:0, equal 8/10-bit component depths and one layer are
/// admitted. VPS/SPS temporal declarations and general PTL must agree exactly.
/// Sublayer profiles, when present, must match the general profile; sublayer
/// levels may not exceed it. These restrictions avoid inventing merged metadata.
#[derive(Eq, PartialEq)]
pub struct HevcConfiguration {
    vps: Vec<u8>,
    sps: Vec<u8>,
    pps: Vec<u8>,
    vps_id: u8,
    sps_id: u8,
    pps_id: u8,
    profile: [u8; 12],
    temporal_layers: u8,
    temporal_nested: bool,
    coded: (u32, u32),
    display: (u32, u32),
    crop: [u32; 4],
    bit_depth: u8,
    prefix_bits: [usize; 3],
}
impl std::fmt::Debug for HevcConfiguration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HevcConfiguration")
            .field("ids", &(self.vps_id, self.sps_id, self.pps_id))
            .field("coded", &self.coded).field("display", &self.display)
            .field("bit_depth", &self.bit_depth).field("prefix_bits", &self.prefix_bits)
            .finish_non_exhaustive()
    }
}
impl HevcConfiguration {
    /// Screen bounded metadata before retaining a copy of the original tuple.
    pub fn parse(vps: &[u8], sps: &[u8], pps: &[u8], limits: HevcConfigurationLimits) -> Result<Self> {
        limits.validate()?;
        // Check all sizes before allocating any RBSP or retained source bytes.
        for (nal, kind) in [(vps, 32), (sps, 33), (pps, 34)] {
            check_nal(nal, kind, limits)?;
        }
        let v = vps_prefix(vps)?;
        let s = sps_prefix(sps, limits)?;
        let mut p = Bits::new(pps)?;
        let pps_id = p.ue(63)? as u8;
        let pps_sps_id = p.ue(15)? as u8;
        if s.vps_id != v.id || pps_sps_id != s.id || s.profile != v.profile
            || s.layers != v.layers || s.nested != v.nested
        { return Err(HevcConfigurationError::Mismatch); }
        Ok(Self {
            vps: copy(vps)?, sps: copy(sps)?, pps: copy(pps)?,
            vps_id: v.id, sps_id: s.id, pps_id, profile: s.profile,
            temporal_layers: s.layers, temporal_nested: s.nested,
            coded: s.coded, display: s.display, crop: s.crop, bit_depth: s.bit_depth,
            prefix_bits: [v.bits, s.bits, p.at],
        })
    }
    /// Exact original VPS, without Annex-B delimiter.
    pub fn vps(&self) -> &[u8] { &self.vps }
    /// Exact original SPS, including any uninterpreted suffix.
    pub fn sps(&self) -> &[u8] { &self.sps }
    /// Exact original PPS, including any uninterpreted suffix.
    pub fn pps(&self) -> &[u8] { &self.pps }
    /// VPS identifier referenced by the SPS.
    pub fn vps_id(&self) -> u8 { self.vps_id }
    /// SPS identifier referenced by the PPS.
    pub fn sps_id(&self) -> u8 { self.sps_id }
    /// PPS identifier which admitted slices must reference.
    pub fn pps_id(&self) -> u8 { self.pps_id }
    /// Exact 12-byte general profile_tier_level prefix: profile byte, compatibility
    /// flags, six constraint bytes, and level. This is signaling, not conformance.
    pub fn profile_tier_level(&self) -> &[u8; 12] { &self.profile }
    /// Maximum temporal sublayers from the matching VPS/SPS declarations, in 1..=7.
    pub fn temporal_layers(&self) -> u8 { self.temporal_layers }
    /// Matching temporal nesting flag.
    pub fn temporal_nested(&self) -> bool { self.temporal_nested }
    /// Coded luma dimensions, before conformance cropping.
    pub fn coded_dimensions(&self) -> (u32, u32) { self.coded }
    /// Dimensions after the SPS conformance window; VUI display window is not interpreted.
    pub fn display_dimensions(&self) -> (u32, u32) { self.display }
    /// Conformance crop offsets in luma samples, ordered left/right/top/bottom.
    pub fn conformance_crop(&self) -> [u32; 4] { self.crop }
    /// Equal luma/chroma component depth, either 8 or 10.
    pub fn bit_depth(&self) -> u8 { self.bit_depth }
    /// Number of interpreted RBSP prefix bits for VPS, SPS, PPS respectively.
    /// This makes the intentionally limited syntax inspection explicit.
    pub fn inspected_prefix_bits(&self) -> [usize; 3] { self.prefix_bits }
}

fn copy(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len()).map_err(|_| HevcConfigurationError::Allocation)?;
    out.extend_from_slice(bytes);
    Ok(out)
}
fn check_nal(nal: &[u8], kind: u8, limits: HevcConfigurationLimits) -> Result<()> {
    if nal.len() > limits.max_parameter_bytes { return Err(HevcConfigurationError::Limit); }
    if nal.len() < 3 { return Err(HevcConfigurationError::Truncated); }
    if nal[0] & 0x80 != 0 { return Err(HevcConfigurationError::Corrupt); }
    if (nal[0] >> 1) & 63 != kind || nal[1] & 7 != 1 {
        return Err(HevcConfigurationError::Malformed);
    }
    if nal[0] & 1 != 0 || nal[1] >> 3 != 0 { return Err(HevcConfigurationError::Unsupported); }
    Ok(())
}

struct Vps { id: u8, layers: u8, nested: bool, profile: [u8; 12], bits: usize }
fn vps_prefix(nal: &[u8]) -> Result<Vps> {
    let mut b = Bits::new(nal)?;
    let id = b.read(4)? as u8;
    let internal = b.read(1)? != 0;
    let available = b.read(1)? != 0;
    if !internal || !available || b.read(6)? != 0 { return Err(HevcConfigurationError::Unsupported); }
    let layers = layers(&mut b)?;
    let nested = b.read(1)? != 0;
    if layers == 1 && !nested || b.read(16)? != 0xffff { return Err(HevcConfigurationError::Malformed); }
    let profile = ptl(&mut b, layers)?;
    Ok(Vps { id, layers, nested, profile, bits: b.at })
}
struct Sps {
    vps_id: u8, id: u8, layers: u8, nested: bool, profile: [u8; 12],
    coded: (u32, u32), display: (u32, u32), crop: [u32; 4], bit_depth: u8, bits: usize,
}
fn sps_prefix(nal: &[u8], limits: HevcConfigurationLimits) -> Result<Sps> {
    let mut b = Bits::new(nal)?;
    let vps_id = b.read(4)? as u8;
    let layers = layers(&mut b)?;
    let nested = b.read(1)? != 0;
    if layers == 1 && !nested { return Err(HevcConfigurationError::Malformed); }
    let profile = ptl(&mut b, layers)?;
    let id = b.ue(15)? as u8;
    if b.ue(3)? != 1 { return Err(HevcConfigurationError::Unsupported); }
    let width = b.ue(limits.max_width)?;
    let height = b.ue(limits.max_height)?;
    if width == 0 || height == 0 { return Err(HevcConfigurationError::Malformed); }
    if u64::from(width) * u64::from(height) > limits.max_luma_samples {
        return Err(HevcConfigurationError::Limit);
    }
    let mut crop = [0; 4];
    if b.read(1)? != 0 {
        for offset in &mut crop {
            // This subset is 4:2:0; each signaled crop unit is two luma samples.
            *offset = b.ue(16_384)?.checked_mul(2).ok_or(HevcConfigurationError::Limit)?;
        }
    }
    let display_width = width.checked_sub(crop[0] + crop[1]).filter(|v| *v != 0)
        .ok_or(HevcConfigurationError::Malformed)?;
    let display_height = height.checked_sub(crop[2] + crop[3]).filter(|v| *v != 0)
        .ok_or(HevcConfigurationError::Malformed)?;
    let luma = b.ue(8)?;
    let chroma = b.ue(8)?;
    if !matches!(luma, 0 | 2) || luma != chroma || profile[0] & 31 == 1 && luma != 0 {
        return Err(HevcConfigurationError::Unsupported);
    }
    Ok(Sps { vps_id, id, layers, nested, profile, coded: (width, height),
        display: (display_width, display_height), crop, bit_depth: 8 + luma as u8, bits: b.at })
}
fn layers(b: &mut Bits) -> Result<u8> {
    let value = b.read(3)? as u8;
    if value > 6 { return Err(HevcConfigurationError::Malformed); }
    Ok(value + 1)
}
fn ptl(b: &mut Bits, layers: u8) -> Result<[u8; 12]> {
    let mut general = [0; 12];
    for byte in &mut general { *byte = b.read(8)? as u8; }
    if general[0] >> 6 != 0 || !matches!(general[0] & 31, 1 | 2) {
        return Err(HevcConfigurationError::Unsupported);
    }
    let mut flags = [(false, false); 6];
    for flag in flags.iter_mut().take(usize::from(layers - 1)) {
        *flag = (b.read(1)? != 0, b.read(1)? != 0);
    }
    if layers > 1 {
        for _ in layers - 1..8 {
            if b.read(2)? != 0 { return Err(HevcConfigurationError::Malformed); }
        }
    }
    for (profile, level) in flags.into_iter().take(usize::from(layers - 1)) {
        if profile {
            for expected in &general[..11] {
                if b.read(8)? != u32::from(*expected) { return Err(HevcConfigurationError::Mismatch); }
            }
        }
        if level && b.read(8)? > u32::from(general[11]) { return Err(HevcConfigurationError::Mismatch); }
    }
    Ok(general)
}

/// One bounded RBSP allocation and at most 2048 interpreted prefix bits.
struct Bits { bytes: Vec<u8>, at: usize }
impl Bits {
    fn new(nal: &[u8]) -> Result<Self> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(nal.len() - 2).map_err(|_| HevcConfigurationError::Allocation)?;
        let mut zeros = 0;
        let mut at = 2;
        while at < nal.len() {
            let byte = nal[at];
            if zeros == 2 {
                if byte == 3 {
                    if !nal.get(at + 1).is_some_and(|next| *next <= 3) {
                        return Err(HevcConfigurationError::Malformed);
                    }
                    zeros = 0;
                    at += 1;
                    continue;
                }
                if byte <= 2 { return Err(HevcConfigurationError::Malformed); }
            }
            bytes.push(byte);
            zeros = if byte == 0 { zeros + 1 } else { 0 };
            at += 1;
        }
        Ok(Self { bytes, at: 0 })
    }
    fn read(&mut self, count: usize) -> Result<u32> {
        if count > 32 || self.at + count > 2048 { return Err(HevcConfigurationError::Limit); }
        if self.at + count > self.bytes.len() * 8 { return Err(HevcConfigurationError::Truncated); }
        let mut value = 0;
        for _ in 0..count {
            value = (value << 1) | u32::from((self.bytes[self.at / 8] >> (7 - self.at % 8)) & 1);
            self.at += 1;
        }
        Ok(value)
    }
    fn ue(&mut self, max: u32) -> Result<u32> {
        let mut zeros = 0;
        while self.read(1)? == 0 {
            zeros += 1;
            if zeros > 31 { return Err(HevcConfigurationError::Limit); }
        }
        let value = ((1_u64 << zeros) - 1) + u64::from(self.read(zeros)?);
        if value > u64::from(max) { return Err(HevcConfigurationError::Limit); }
        Ok(value as u32)
    }
}
