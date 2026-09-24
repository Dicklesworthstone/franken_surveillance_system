//! Parameter sets (ITU-T H.265 clauses 7.3.2.1..7.3.2.3, 7.3.4, 7.3.7,
//! E.2): the video, sequence and picture parameter set fields the pixel
//! decoder needs, with every value range-checked before it can size an
//! allocation or index a table.

use crate::bits::BitReader;
use crate::tables::{DEFAULT_SCALING_INTER, DEFAULT_SCALING_INTRA, diagonal_scan};
use crate::{DecodeError, UnsupportedFeature};

/// Maximum number of pictures in any reference picture set / DPB.
pub const MAX_DPB: usize = 16;

/// One short-term reference picture set (clause 7.4.8), in derived form.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ShortTermRps {
    /// `DeltaPocS0` (negative, decreasing).
    pub delta_s0: Vec<i32>,
    /// `UsedByCurrPicS0`.
    pub used_s0: Vec<bool>,
    /// `DeltaPocS1` (positive, increasing).
    pub delta_s1: Vec<i32>,
    /// `UsedByCurrPicS1`.
    pub used_s1: Vec<bool>,
}

impl ShortTermRps {
    /// `NumDeltaPocs`.
    #[must_use]
    pub fn num_delta_pocs(&self) -> usize {
        self.delta_s0.len() + self.delta_s1.len()
    }
}

/// Parses `st_ref_pic_set(stRpsIdx)` (clause 7.3.7) against the sets
/// already parsed (`previous`, the SPS list). `in_slice_header` is true for
/// the slice-header instance (`stRpsIdx == num_short_term_ref_pic_sets`).
///
/// # Errors
/// [`DecodeError::Malformed`] on out-of-range syntax or more than
/// [`MAX_DPB`] pictures.
pub fn parse_short_term_rps(
    reader: &mut BitReader<'_>,
    previous: &[ShortTermRps],
    in_slice_header: bool,
    max_dec_pic_buffering: usize,
) -> Result<ShortTermRps, DecodeError> {
    let idx = previous.len();
    let inter = idx != 0 && reader.flag()?;
    if inter {
        let delta_idx = if in_slice_header {
            reader.ue(u32::try_from(idx).map_err(|_| DecodeError::Malformed)? - 1)? as usize + 1
        } else {
            1
        };
        let reference = previous
            .get(idx.checked_sub(delta_idx).ok_or(DecodeError::Malformed)?)
            .ok_or(DecodeError::Malformed)?;
        let sign = reader.flag()?;
        let abs = i32::try_from(reader.ue(1 << 15)?).map_err(|_| DecodeError::Malformed)? + 1;
        let delta_rps = if sign { -abs } else { abs };
        let count = reference.num_delta_pocs();
        let mut used = vec![false; count + 1];
        let mut use_delta = vec![true; count + 1];
        for j in 0..=count {
            used[j] = reader.flag()?;
            if !used[j] {
                use_delta[j] = reader.flag()?;
            }
        }
        let neg = reference.delta_s0.len();
        let mut rps = ShortTermRps::default();
        // Equation 7-61.
        for j in (0..reference.delta_s1.len()).rev() {
            let d = reference.delta_s1[j] + delta_rps;
            if d < 0 && use_delta[neg + j] {
                rps.delta_s0.push(d);
                rps.used_s0.push(used[neg + j]);
            }
        }
        if delta_rps < 0 && use_delta[count] {
            rps.delta_s0.push(delta_rps);
            rps.used_s0.push(used[count]);
        }
        for j in 0..neg {
            let d = reference.delta_s0[j] + delta_rps;
            if d < 0 && use_delta[j] {
                rps.delta_s0.push(d);
                rps.used_s0.push(used[j]);
            }
        }
        // Equation 7-62.
        for j in (0..neg).rev() {
            let d = reference.delta_s0[j] + delta_rps;
            if d > 0 && use_delta[j] {
                rps.delta_s1.push(d);
                rps.used_s1.push(used[j]);
            }
        }
        if delta_rps > 0 && use_delta[count] {
            rps.delta_s1.push(delta_rps);
            rps.used_s1.push(used[count]);
        }
        for j in 0..reference.delta_s1.len() {
            let d = reference.delta_s1[j] + delta_rps;
            if d > 0 && use_delta[neg + j] {
                rps.delta_s1.push(d);
                rps.used_s1.push(used[neg + j]);
            }
        }
        if rps.num_delta_pocs() > max_dec_pic_buffering.min(MAX_DPB) {
            return Err(DecodeError::Malformed);
        }
        return Ok(rps);
    }
    let cap = u32::try_from(max_dec_pic_buffering.min(MAX_DPB)).unwrap_or(16);
    let num_negative = reader.ue(cap)? as usize;
    let num_positive = reader.ue(cap)? as usize;
    if num_negative + num_positive > cap as usize {
        return Err(DecodeError::Malformed);
    }
    let mut rps = ShortTermRps::default();
    let mut poc = 0i32;
    for _ in 0..num_negative {
        poc -= i32::try_from(reader.ue(1 << 15)?).map_err(|_| DecodeError::Malformed)? + 1;
        rps.delta_s0.push(poc);
        rps.used_s0.push(reader.flag()?);
    }
    poc = 0;
    for _ in 0..num_positive {
        poc += i32::try_from(reader.ue(1 << 15)?).map_err(|_| DecodeError::Malformed)? + 1;
        rps.delta_s1.push(poc);
        rps.used_s1.push(reader.flag()?);
    }
    Ok(rps)
}

/// Scaling factors `m[x][y]` for every transform size and matrixId
/// (clause 7.4.5), stored row-major (`y * size + x`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScalingList {
    /// `[sizeId][matrixId]` factors; sizeId 3 uses matrixId 0 and 3 (the
    /// 4:2:0 chroma 32x32 entries are never used).
    factors: [[Vec<u8>; 6]; 4],
}

impl ScalingList {
    /// The default lists (Tables 7-5 and 7-6), used when scaling lists
    /// are enabled without explicit data.
    #[must_use]
    pub fn default_lists() -> Self {
        let mut coded: [[[u8; 64]; 6]; 4] = [[[16; 64]; 6]; 4];
        let mut dc = [[16u8; 6]; 4];
        for size_id in 1..4 {
            for matrix_id in 0..6 {
                coded[size_id][matrix_id] = if matrix_id < 3 {
                    DEFAULT_SCALING_INTRA
                } else {
                    DEFAULT_SCALING_INTER
                };
                dc[size_id][matrix_id] = 16;
            }
        }
        Self::expand(&coded, &dc)
    }

    /// Flat 16 everywhere (`scaling_list_enabled_flag == 0`).
    #[must_use]
    pub fn flat() -> Self {
        let coded: [[[u8; 64]; 6]; 4] = [[[16; 64]; 6]; 4];
        Self::expand(&coded, &[[16; 6]; 4])
    }

    /// `scaling_list_data()` (clause 7.3.4).
    ///
    /// # Errors
    /// [`DecodeError::Malformed`] on out-of-range deltas or references.
    pub fn parse(reader: &mut BitReader<'_>) -> Result<Self, DecodeError> {
        let mut coded: [[[u8; 64]; 6]; 4] = [[[16; 64]; 6]; 4];
        let mut dc = [[16u8; 6]; 4];
        for size_id in 0..4usize {
            let step = if size_id == 3 { 3 } else { 1 };
            let coef_num = if size_id == 0 { 16 } else { 64 };
            let mut matrix_id = 0usize;
            while matrix_id < 6 {
                let pred_mode = reader.flag()?;
                if pred_mode {
                    let mut next: i32 = 8;
                    if size_id > 1 {
                        next = reader.se(-7, 247)? + 8;
                        dc[size_id][matrix_id] =
                            u8::try_from(next).map_err(|_| DecodeError::Malformed)?;
                    }
                    for coef in coded[size_id][matrix_id].iter_mut().take(coef_num) {
                        let delta = reader.se(-128, 127)?;
                        next = (next + delta + 256).rem_euclid(256);
                        *coef = u8::try_from(next).map_err(|_| DecodeError::Malformed)?;
                    }
                } else {
                    let delta = reader.ue(5)? as usize * step;
                    if delta == 0 {
                        let default = if size_id == 0 {
                            [16u8; 64]
                        } else if matrix_id < 3 {
                            DEFAULT_SCALING_INTRA
                        } else {
                            DEFAULT_SCALING_INTER
                        };
                        coded[size_id][matrix_id] = default;
                        dc[size_id][matrix_id] = 16;
                    } else {
                        let reference =
                            matrix_id.checked_sub(delta).ok_or(DecodeError::Malformed)?;
                        coded[size_id][matrix_id] = coded[size_id][reference];
                        dc[size_id][matrix_id] = dc[size_id][reference];
                    }
                }
                matrix_id += step;
            }
        }
        Ok(Self::expand(&coded, &dc))
    }

    /// Expands coded (diagonal-scan) lists to per-size factor matrices
    /// (equations 7-40..7-43).
    fn expand(coded: &[[[u8; 64]; 6]; 4], dc: &[[u8; 6]; 4]) -> Self {
        let scan4 = diagonal_scan(4);
        let scan8 = diagonal_scan(8);
        let factors = std::array::from_fn(|size_id| {
            std::array::from_fn(|matrix_id| {
                let size = 4usize << size_id;
                let mut out = vec![0u8; size * size];
                if size_id == 0 {
                    for (i, &(x, y)) in scan4.iter().enumerate() {
                        out[usize::from(y) * 4 + usize::from(x)] = coded[0][matrix_id][i];
                    }
                    return out;
                }
                let ratio = size / 8;
                for (i, &(x, y)) in scan8.iter().enumerate() {
                    for dy in 0..ratio {
                        for dx in 0..ratio {
                            let px = usize::from(x) * ratio + dx;
                            let py = usize::from(y) * ratio + dy;
                            out[py * size + px] = coded[size_id][matrix_id][i];
                        }
                    }
                }
                if size_id >= 2 {
                    out[0] = dc[size_id][matrix_id];
                }
                out
            })
        });
        Self { factors }
    }

    /// Factor matrix for a `4 << size_id` block and matrixId
    /// (`3 * inter + cIdx`), row-major.
    #[must_use]
    pub fn factors(&self, size_id: usize, matrix_id: usize) -> &[u8] {
        // For 32x32 only matrixId 0 and 3 exist in 4:2:0 streams.
        let matrix_id = if size_id == 3 {
            (matrix_id / 3) * 3
        } else {
            matrix_id
        };
        &self.factors[size_id.min(3)][matrix_id.min(5)]
    }
}

/// Decode-relevant sequence parameter set fields.
#[derive(Clone, Debug)]
pub struct Sps {
    /// `sps_seq_parameter_set_id`.
    pub id: u8,
    /// `sps_video_parameter_set_id`.
    pub vps_id: u8,
    /// `sps_max_sub_layers_minus1 + 1`.
    pub max_sub_layers: u8,
    /// `pic_width_in_luma_samples`.
    pub width: u32,
    /// `pic_height_in_luma_samples`.
    pub height: u32,
    /// Conformance window in luma samples: left, right, top, bottom.
    pub crop: [u32; 4],
    /// `log2_max_pic_order_cnt_lsb_minus4 + 4`.
    pub log2_max_poc_lsb: u32,
    /// `sps_max_dec_pic_buffering_minus1 + 1` of the highest sub-layer.
    pub max_dec_pic_buffering: u32,
    /// `sps_max_num_reorder_pics` of the highest sub-layer.
    pub max_num_reorder: u32,
    /// `sps_max_latency_increase_plus1` of the highest sub-layer.
    pub max_latency_increase_plus1: u32,
    /// `MinCbLog2SizeY`.
    pub min_cb_log2: u32,
    /// `CtbLog2SizeY`.
    pub ctb_log2: u32,
    /// `MinTbLog2SizeY`.
    pub min_tb_log2: u32,
    /// `MaxTbLog2SizeY`.
    pub max_tb_log2: u32,
    /// `max_transform_hierarchy_depth_inter`.
    pub max_th_depth_inter: u32,
    /// `max_transform_hierarchy_depth_intra`.
    pub max_th_depth_intra: u32,
    /// `scaling_list_enabled_flag`.
    pub scaling_list_enabled: bool,
    /// The SPS lists (default lists when no data is sent).
    pub scaling_list: Option<ScalingList>,
    /// `amp_enabled_flag`.
    pub amp_enabled: bool,
    /// `sample_adaptive_offset_enabled_flag`.
    pub sao_enabled: bool,
    /// PCM parameters when `pcm_enabled_flag`.
    pub pcm: Option<PcmParams>,
    /// The SPS short-term reference picture sets.
    pub st_rps: Vec<ShortTermRps>,
    /// `long_term_ref_pics_present_flag`.
    pub long_term_refs_present: bool,
    /// `lt_ref_pic_poc_lsb_sps` / `used_by_curr_pic_lt_sps_flag`.
    pub lt_ref_pics_sps: Vec<(u32, bool)>,
    /// `sps_temporal_mvp_enabled_flag`.
    pub temporal_mvp_enabled: bool,
    /// `strong_intra_smoothing_enabled_flag`.
    pub strong_intra_smoothing: bool,
}

/// PCM sample parameters (clause 7.4.3.2.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PcmParams {
    /// `PcmBitDepthY`.
    pub bit_depth_luma: u32,
    /// `PcmBitDepthC`.
    pub bit_depth_chroma: u32,
    /// `Log2MinIpcmCbSizeY`.
    pub log2_min: u32,
    /// `Log2MaxIpcmCbSizeY`.
    pub log2_max: u32,
    /// `pcm_loop_filter_disabled_flag`.
    pub loop_filter_disabled: bool,
}

impl Sps {
    /// Coding tree blocks per row.
    #[must_use]
    pub fn ctb_width(&self) -> u32 {
        self.width.div_ceil(1 << self.ctb_log2)
    }

    /// Coding tree blocks per column.
    #[must_use]
    pub fn ctb_height(&self) -> u32 {
        self.height.div_ceil(1 << self.ctb_log2)
    }

    /// Luma samples per picture.
    #[must_use]
    pub fn luma_samples(&self) -> u64 {
        u64::from(self.width) * u64::from(self.height)
    }
}

/// `profile_tier_level(1, maxNumSubLayersMinus1)` (clause 7.3.3); returns
/// whether the general profile is decodable Main / Main Still Picture.
fn profile_tier_level(
    reader: &mut BitReader<'_>,
    max_sub_layers_minus1: u32,
) -> Result<bool, DecodeError> {
    let _profile_space = reader.uint(2)?;
    let _tier = reader.flag()?;
    let profile_idc = reader.uint(5)?;
    let compatibility = reader.uint(32)?;
    // progressive, interlaced, non_packed, frame_only + 43 + 1 bits.
    reader.skip(4 + 43 + 1)?;
    let _level_idc = reader.uint(8)?;
    let mut sub_profile = [false; 8];
    let mut sub_level = [false; 8];
    for i in 0..max_sub_layers_minus1 as usize {
        sub_profile[i] = reader.flag()?;
        sub_level[i] = reader.flag()?;
    }
    if max_sub_layers_minus1 > 0 {
        for _ in max_sub_layers_minus1..8 {
            reader.skip(2)?;
        }
    }
    for i in 0..max_sub_layers_minus1 as usize {
        if sub_profile[i] {
            reader.skip(88)?;
        }
        if sub_level[i] {
            reader.skip(8)?;
        }
    }
    // Main (1) or Main Still Picture (3), or a stream that declares
    // compatibility with Main (general_profile_compatibility_flag[1]).
    let main_compatible = compatibility & (1 << 30) != 0;
    Ok(profile_idc == 1 || profile_idc == 3 || main_compatible)
}

/// Parses a VPS just far enough to validate its id.
///
/// # Errors
/// [`DecodeError::Limit`] / [`DecodeError::Malformed`] on truncation.
pub fn parse_vps_id(rbsp: &[u8]) -> Result<u8, DecodeError> {
    let mut reader = BitReader::new(rbsp, rbsp.len() * 8);
    Ok(reader.uint(4)? as u8)
}

fn hrd_parameters(
    reader: &mut BitReader<'_>,
    common: bool,
    max_sub_layers_minus1: u32,
) -> Result<(), DecodeError> {
    let mut nal = false;
    let mut vcl = false;
    let mut sub_pic = false;
    if common {
        nal = reader.flag()?;
        vcl = reader.flag()?;
        if nal || vcl {
            sub_pic = reader.flag()?;
            if sub_pic {
                reader.skip(8 + 5 + 1 + 5)?;
            }
            reader.skip(4 + 4)?;
            if sub_pic {
                reader.skip(4)?;
            }
            reader.skip(5 + 5 + 5)?;
        }
    }
    for _ in 0..=max_sub_layers_minus1 {
        let fixed_general = reader.flag()?;
        let fixed_within_cvs = if fixed_general { true } else { reader.flag()? };
        let mut low_delay = false;
        if fixed_within_cvs {
            reader.ue(2047)?;
        } else {
            low_delay = reader.flag()?;
        }
        let cpb_cnt = if low_delay { 1 } else { reader.ue(31)? + 1 };
        for present in [nal, vcl] {
            if present {
                for _ in 0..cpb_cnt {
                    reader.ue(u32::MAX - 1)?;
                    reader.ue(u32::MAX - 1)?;
                    if sub_pic {
                        reader.ue(u32::MAX - 1)?;
                        reader.ue(u32::MAX - 1)?;
                    }
                    reader.skip(1)?;
                }
            }
        }
    }
    Ok(())
}

/// VUI (clause E.2.1); returns `field_seq_flag`.
fn vui_parameters(
    reader: &mut BitReader<'_>,
    max_sub_layers_minus1: u32,
) -> Result<bool, DecodeError> {
    if reader.flag()? {
        let aspect_ratio_idc = reader.uint(8)?;
        if aspect_ratio_idc == 255 {
            reader.skip(32)?;
        }
    }
    if reader.flag()? {
        reader.skip(1)?;
    }
    if reader.flag()? {
        reader.skip(3 + 1)?;
        if reader.flag()? {
            reader.skip(24)?;
        }
    }
    if reader.flag()? {
        reader.ue(5)?;
        reader.ue(5)?;
    }
    let _neutral_chroma = reader.flag()?;
    let field_seq = reader.flag()?;
    let _frame_field_info = reader.flag()?;
    if reader.flag()? {
        for _ in 0..4 {
            reader.ue(u32::MAX - 1)?;
        }
    }
    if reader.flag()? {
        reader.skip(32 + 32)?;
        if reader.flag()? {
            reader.ue(u32::MAX - 1)?;
        }
        if reader.flag()? {
            hrd_parameters(reader, true, max_sub_layers_minus1)?;
        }
    }
    if reader.flag()? {
        reader.skip(3)?;
        reader.ue(4095)?;
        reader.ue(16)?;
        reader.ue(16)?;
        reader.ue(16)?;
        reader.ue(16)?;
    }
    Ok(field_seq)
}

/// Parses an SPS RBSP (header bytes removed).
///
/// # Errors
/// [`DecodeError::Unsupported`] for profiles, formats and extensions
/// outside the admitted set; [`DecodeError::Malformed`] /
/// [`DecodeError::Limit`] on bad or truncated syntax.
pub fn parse_sps(rbsp: &[u8]) -> Result<Sps, DecodeError> {
    let mut reader = BitReader::new(rbsp, rbsp.len() * 8);
    let r = &mut reader;
    let vps_id = r.uint(4)? as u8;
    let max_sub_layers_minus1 = r.uint(3)?;
    if max_sub_layers_minus1 > 6 {
        return Err(DecodeError::Malformed);
    }
    let _temporal_id_nesting = r.flag()?;
    let main = profile_tier_level(r, max_sub_layers_minus1)?;
    let id = r.ue(15)? as u8;
    let chroma_format_idc = r.ue(3)?;
    if chroma_format_idc == 3 {
        let _separate_colour_plane = r.flag()?;
    }
    let width = r.ue(16_888)?;
    let height = r.ue(16_888)?;
    if width == 0 || height == 0 {
        return Err(DecodeError::Malformed);
    }
    let mut crop = [0u32; 4];
    if r.flag()? {
        for value in &mut crop {
            *value = r.ue(8_444)? * 2;
        }
    }
    let bit_depth_luma = r.ue(8)? + 8;
    let bit_depth_chroma = r.ue(8)? + 8;
    if chroma_format_idc != 1 || bit_depth_luma != 8 || bit_depth_chroma != 8 {
        return Err(DecodeError::Unsupported(UnsupportedFeature::SampleFormat));
    }
    if !main {
        return Err(DecodeError::Unsupported(UnsupportedFeature::Profile));
    }
    let log2_max_poc_lsb = r.ue(12)? + 4;
    let ordering_info_present = r.flag()?;
    let first = if ordering_info_present {
        0
    } else {
        max_sub_layers_minus1
    };
    let (mut max_dec, mut reorder, mut latency) = (1, 0, 0);
    for _ in first..=max_sub_layers_minus1 {
        max_dec = r.ue(15)? + 1;
        reorder = r.ue(max_dec - 1)?;
        latency = r.ue(u32::MAX - 1)?;
    }
    let min_cb_log2 = r.ue(3)? + 3;
    let ctb_log2 = min_cb_log2 + r.ue(3)?;
    let min_tb_log2 = r.ue(3)? + 2;
    let max_tb_log2 = min_tb_log2 + r.ue(3)?;
    if !(4..=6).contains(&ctb_log2)
        || min_tb_log2 >= min_cb_log2
        || max_tb_log2 > ctb_log2.min(5)
        || width % (1 << min_cb_log2) != 0
        || height % (1 << min_cb_log2) != 0
    {
        return Err(DecodeError::Malformed);
    }
    let max_th_depth_inter = r.ue(ctb_log2 - min_tb_log2)?;
    let max_th_depth_intra = r.ue(ctb_log2 - min_tb_log2)?;
    let scaling_list_enabled = r.flag()?;
    let scaling_list = if scaling_list_enabled {
        Some(if r.flag()? {
            ScalingList::parse(r)?
        } else {
            ScalingList::default_lists()
        })
    } else {
        None
    };
    let amp_enabled = r.flag()?;
    let sao_enabled = r.flag()?;
    let pcm = if r.flag()? {
        let bit_depth_luma = r.uint(4)? + 1;
        let bit_depth_chroma = r.uint(4)? + 1;
        let log2_min = r.ue(2)? + 3;
        let log2_max = log2_min + r.ue(2)?;
        if bit_depth_luma > 8 || bit_depth_chroma > 8 || log2_max > ctb_log2.min(5) {
            return Err(DecodeError::Malformed);
        }
        Some(PcmParams {
            bit_depth_luma,
            bit_depth_chroma,
            log2_min,
            log2_max,
            loop_filter_disabled: r.flag()?,
        })
    } else {
        None
    };
    let num_st_rps = r.ue(64)? as usize;
    let mut st_rps: Vec<ShortTermRps> = Vec::with_capacity(num_st_rps);
    for _ in 0..num_st_rps {
        let set = parse_short_term_rps(r, &st_rps, false, max_dec as usize)?;
        st_rps.push(set);
    }
    let long_term_refs_present = r.flag()?;
    let mut lt_ref_pics_sps = Vec::new();
    if long_term_refs_present {
        let count = r.ue(32)?;
        for _ in 0..count {
            let lsb = r.uint(log2_max_poc_lsb)?;
            lt_ref_pics_sps.push((lsb, r.flag()?));
        }
    }
    let temporal_mvp_enabled = r.flag()?;
    let strong_intra_smoothing = r.flag()?;
    if r.flag()? && vui_parameters(r, max_sub_layers_minus1)? {
        return Err(DecodeError::Unsupported(UnsupportedFeature::Interlaced));
    }
    if r.flag()? {
        let range = r.flag()?;
        let multilayer = r.flag()?;
        let three_d = r.flag()?;
        let scc = r.flag()?;
        let _extension_4bits = r.uint(4)?;
        if range {
            return Err(DecodeError::Unsupported(UnsupportedFeature::RangeExtension));
        }
        if multilayer || three_d {
            return Err(DecodeError::Unsupported(UnsupportedFeature::MultiLayer));
        }
        if scc {
            return Err(DecodeError::Unsupported(UnsupportedFeature::ScreenContent));
        }
    }
    if crop[0] + crop[1] >= width || crop[2] + crop[3] >= height {
        return Err(DecodeError::Malformed);
    }
    Ok(Sps {
        id,
        vps_id,
        max_sub_layers: u8::try_from(max_sub_layers_minus1 + 1).unwrap_or(1),
        width,
        height,
        crop,
        log2_max_poc_lsb,
        max_dec_pic_buffering: max_dec,
        max_num_reorder: reorder,
        max_latency_increase_plus1: latency,
        min_cb_log2,
        ctb_log2,
        min_tb_log2,
        max_tb_log2,
        max_th_depth_inter,
        max_th_depth_intra,
        scaling_list_enabled,
        scaling_list,
        amp_enabled,
        sao_enabled,
        pcm,
        st_rps,
        long_term_refs_present,
        lt_ref_pics_sps,
        temporal_mvp_enabled,
        strong_intra_smoothing,
    })
}

/// Decode-relevant picture parameter set fields.
#[derive(Clone, Debug)]
pub struct Pps {
    /// `pps_pic_parameter_set_id`.
    pub id: u8,
    /// `pps_seq_parameter_set_id`.
    pub sps_id: u8,
    /// `dependent_slice_segments_enabled_flag`.
    pub dependent_slices_enabled: bool,
    /// `output_flag_present_flag`.
    pub output_flag_present: bool,
    /// `num_extra_slice_header_bits`.
    pub num_extra_slice_header_bits: u32,
    /// `sign_data_hiding_enabled_flag`.
    pub sign_data_hiding: bool,
    /// `cabac_init_present_flag`.
    pub cabac_init_present: bool,
    /// `num_ref_idx_l0_default_active_minus1 + 1`.
    pub num_ref_idx_l0_default: u32,
    /// `num_ref_idx_l1_default_active_minus1 + 1`.
    pub num_ref_idx_l1_default: u32,
    /// `init_qp_minus26 + 26`.
    pub init_qp: i32,
    /// `constrained_intra_pred_flag`.
    pub constrained_intra_pred: bool,
    /// `transform_skip_enabled_flag`.
    pub transform_skip_enabled: bool,
    /// `cu_qp_delta_enabled_flag`.
    pub cu_qp_delta_enabled: bool,
    /// `diff_cu_qp_delta_depth`.
    pub diff_cu_qp_delta_depth: u32,
    /// `pps_cb_qp_offset`.
    pub cb_qp_offset: i32,
    /// `pps_cr_qp_offset`.
    pub cr_qp_offset: i32,
    /// `pps_slice_chroma_qp_offsets_present_flag`.
    pub slice_chroma_qp_offsets_present: bool,
    /// `weighted_pred_flag`.
    pub weighted_pred: bool,
    /// `weighted_bipred_flag`.
    pub weighted_bipred: bool,
    /// `transquant_bypass_enabled_flag`.
    pub transquant_bypass_enabled: bool,
    /// `tiles_enabled_flag`.
    pub tiles_enabled: bool,
    /// `entropy_coding_sync_enabled_flag`.
    pub entropy_coding_sync: bool,
    /// `pps_loop_filter_across_slices_enabled_flag`.
    pub loop_filter_across_slices: bool,
    /// `deblocking_filter_override_enabled_flag`.
    pub deblocking_override_enabled: bool,
    /// `pps_deblocking_filter_disabled_flag`.
    pub deblocking_disabled: bool,
    /// `pps_beta_offset_div2 * 2`.
    pub beta_offset: i32,
    /// `pps_tc_offset_div2 * 2`.
    pub tc_offset: i32,
    /// PPS scaling lists, when `pps_scaling_list_data_present_flag`.
    pub scaling_list: Option<ScalingList>,
    /// `lists_modification_present_flag`.
    pub lists_modification_present: bool,
    /// `Log2ParMrgLevel`.
    pub log2_parallel_merge_level: u32,
    /// `slice_segment_header_extension_present_flag`.
    pub slice_header_extension_present: bool,
}

/// Parses a PPS RBSP (header bytes removed). Fields that depend on the
/// SPS are range-checked at activation ([`Pps::validate`]).
///
/// # Errors
/// [`DecodeError::Unsupported`] for extensions; [`DecodeError::Malformed`]
/// / [`DecodeError::Limit`] on bad or truncated syntax.
pub fn parse_pps(rbsp: &[u8]) -> Result<Pps, DecodeError> {
    let mut reader = BitReader::new(rbsp, rbsp.len() * 8);
    let r = &mut reader;
    let id = r.ue(63)? as u8;
    let sps_id = r.ue(15)? as u8;
    let dependent_slices_enabled = r.flag()?;
    let output_flag_present = r.flag()?;
    let num_extra_slice_header_bits = r.uint(3)?;
    let sign_data_hiding = r.flag()?;
    let cabac_init_present = r.flag()?;
    let num_ref_idx_l0_default = r.ue(14)? + 1;
    let num_ref_idx_l1_default = r.ue(14)? + 1;
    let init_qp = r.se(-26, 25)? + 26;
    let constrained_intra_pred = r.flag()?;
    let transform_skip_enabled = r.flag()?;
    let cu_qp_delta_enabled = r.flag()?;
    let diff_cu_qp_delta_depth = if cu_qp_delta_enabled { r.ue(3)? } else { 0 };
    let cb_qp_offset = r.se(-12, 12)?;
    let cr_qp_offset = r.se(-12, 12)?;
    let slice_chroma_qp_offsets_present = r.flag()?;
    let weighted_pred = r.flag()?;
    let weighted_bipred = r.flag()?;
    let transquant_bypass_enabled = r.flag()?;
    let tiles_enabled = r.flag()?;
    let entropy_coding_sync = r.flag()?;
    if tiles_enabled {
        return Err(DecodeError::Unsupported(UnsupportedFeature::Tiles));
    }
    let loop_filter_across_slices = r.flag()?;
    let mut deblocking_override_enabled = false;
    let mut deblocking_disabled = false;
    let mut beta_offset = 0;
    let mut tc_offset = 0;
    if r.flag()? {
        deblocking_override_enabled = r.flag()?;
        deblocking_disabled = r.flag()?;
        if !deblocking_disabled {
            beta_offset = r.se(-6, 6)? * 2;
            tc_offset = r.se(-6, 6)? * 2;
        }
    }
    let scaling_list = if r.flag()? {
        Some(ScalingList::parse(r)?)
    } else {
        None
    };
    let lists_modification_present = r.flag()?;
    let log2_parallel_merge_level = r.ue(4)? + 2;
    let slice_header_extension_present = r.flag()?;
    if r.flag()? {
        let range = r.flag()?;
        let multilayer = r.flag()?;
        let three_d = r.flag()?;
        let scc = r.flag()?;
        if range {
            return Err(DecodeError::Unsupported(UnsupportedFeature::RangeExtension));
        }
        if multilayer || three_d {
            return Err(DecodeError::Unsupported(UnsupportedFeature::MultiLayer));
        }
        if scc {
            return Err(DecodeError::Unsupported(UnsupportedFeature::ScreenContent));
        }
    }
    Ok(Pps {
        id,
        sps_id,
        dependent_slices_enabled,
        output_flag_present,
        num_extra_slice_header_bits,
        sign_data_hiding,
        cabac_init_present,
        num_ref_idx_l0_default,
        num_ref_idx_l1_default,
        init_qp,
        constrained_intra_pred,
        transform_skip_enabled,
        cu_qp_delta_enabled,
        diff_cu_qp_delta_depth,
        cb_qp_offset,
        cr_qp_offset,
        slice_chroma_qp_offsets_present,
        weighted_pred,
        weighted_bipred,
        transquant_bypass_enabled,
        tiles_enabled,
        entropy_coding_sync,
        loop_filter_across_slices,
        deblocking_override_enabled,
        deblocking_disabled,
        beta_offset,
        tc_offset,
        scaling_list,
        lists_modification_present,
        log2_parallel_merge_level,
        slice_header_extension_present,
    })
}

impl Pps {
    /// Checks the SPS-dependent ranges (clause 7.4.3.3).
    ///
    /// # Errors
    /// [`DecodeError::Malformed`] when a field exceeds its SPS bound.
    pub fn validate(&self, sps: &Sps) -> Result<(), DecodeError> {
        if self.diff_cu_qp_delta_depth > sps.ctb_log2 - sps.min_cb_log2
            || self.log2_parallel_merge_level > sps.ctb_log2
        {
            return Err(DecodeError::Malformed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack(code: &str) -> (Vec<u8>, usize) {
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
        let bytes = padded
            .chunks(8)
            .map(|chunk| chunk.iter().fold(0u8, |acc, &b| (acc << 1) | b))
            .collect();
        (bytes, len)
    }

    /// An explicit set: num_negative 2 ("011"), num_positive 1 ("010"),
    /// delta_poc_s0_minus1 0 ("1") used 1, delta_poc_s0_minus1 1 ("010")
    /// used 0, delta_poc_s1_minus1 2 ("011") used 1 -> S0 {-1, -3},
    /// S1 {+3}. Then an inter-predicted set (SPS index 1): flag 1,
    /// delta_rps_sign 1, abs_delta_rps_minus1 0 ("1") -> deltaRps -1;
    /// used_by_curr_pic_flag for j = 0..=3 all "1" -> S0 from
    /// {-1-1, -3-1} plus deltaRps itself: equation 7-61 order gives
    /// (S1 reversed: 3-1 = 2 > 0, skipped), deltaRps -1, then -2, -4;
    /// S1: (S0 reversed: -3-1, -1-1 negative, skipped), 3-1 = 2.
    #[test]
    fn short_term_rps_explicit_and_predicted() -> Result<(), DecodeError> {
        let (bytes, len) = pack("011 010 1 1 010 0 011 1   1 1 1 1 1 1 1");
        let mut reader = BitReader::new(&bytes, len);
        let first = parse_short_term_rps(&mut reader, &[], false, 16)?;
        assert_eq!(first.delta_s0, vec![-1, -3]);
        assert_eq!(first.used_s0, vec![true, false]);
        assert_eq!(first.delta_s1, vec![3]);
        let second = parse_short_term_rps(&mut reader, std::slice::from_ref(&first), false, 16)?;
        assert_eq!(second.delta_s0, vec![-1, -2, -4]);
        assert_eq!(second.delta_s1, vec![2]);
        assert_eq!(second.used_s0, vec![true, true, true]);
        assert_eq!(reader.position(), len);
        Ok(())
    }

    /// Flat lists are 16 everywhere; the default 8x8 intra list places
    /// diagonal entry 35 (value 24) at raster (7, 0) and entry 63 (115)
    /// at (7, 7); 16x16 replicates each entry 2x2 and 32x32 4x4 with the
    /// DC entry 16.
    #[test]
    fn scaling_list_expansion() {
        let flat = ScalingList::flat();
        assert!(flat.factors(3, 0).iter().all(|&v| v == 16));
        let default = ScalingList::default_lists();
        let intra8 = default.factors(1, 0);
        assert_eq!(intra8[7], 24);
        assert_eq!(intra8[63], 115);
        let inter8 = default.factors(1, 3);
        assert_eq!(inter8[63], 91);
        let intra16 = default.factors(2, 1);
        assert_eq!(intra16[15], 24);
        assert_eq!(intra16[14], 24);
        assert_eq!(intra16[16 + 15], 24);
        assert_eq!(intra16[255], 115);
        assert_eq!(intra16[0], 16);
        let intra32 = default.factors(3, 2);
        assert_eq!(intra32[1023], 115);
        assert!(default.factors(0, 4).iter().all(|&v| v == 16));
    }

    /// scaling_list_data with every matrix predicted as default
    /// ("1" = pred_mode_flag 0 + delta "1" = 0) except sizeId 0 matrixId 1
    /// coded explicitly: 16 deltas, first +2 ("010"... se(+2) is "00100")
    /// then fifteen 0 ("1") -> 10 everywhere; then matrixId 2 copies
    /// matrixId 1 (delta 1 = "010").
    #[test]
    fn scaling_list_data_explicit_and_copied() -> Result<(), DecodeError> {
        let mut code = String::from("0 1 ");
        code.push_str("1 00100 ");
        for _ in 0..15 {
            code.push_str("1 ");
        }
        code.push_str("0 010 ");
        // sizeId 0 matrixId 3..5, sizeId 1 and 2 x6, sizeId 3 x2.
        for _ in 0..(3 + 6 + 6 + 2) {
            code.push_str("0 1 ");
        }
        let (bytes, len) = pack(&code);
        let mut reader = BitReader::new(&bytes, len);
        let lists = ScalingList::parse(&mut reader)?;
        assert_eq!(reader.position(), len);
        assert!(lists.factors(0, 1).iter().all(|&v| v == 10));
        assert!(lists.factors(0, 2).iter().all(|&v| v == 10));
        assert!(lists.factors(0, 0).iter().all(|&v| v == 16));
        assert_eq!(lists.factors(1, 0)[63], 115);
        Ok(())
    }
}
