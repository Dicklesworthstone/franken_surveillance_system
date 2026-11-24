#![forbid(unsafe_code)]
//! Explicit OSD / static-overlay ignore masks and deterministic corner-clock candidate proposals.
//!
//! OSD ignore regions are strictly distinct from [`super::privacy_mask::PrivacyMaskPolicy`]:
//! privacy masks redact pixels from all viewers and withdraw zone coverage witnesses, whereas
//! OSD ignore regions exclude known camera timestamp/logo overlays only during foreground motion
//! extraction while keeping source pixels untouched in custody.
//!
//! [`detect_osd_candidates`] inspects a retained recording (MJPEG, H.264, or H.265) read-only and
//! proposes candidate corner/edge bounding boxes exhibiting repeated isolated pixel changes (such
//! as a ticking `HH:MM:SS` camera clock) with exact `--ignore-rect X,Y,W,H` suggestions and
//! canonical provenance digests. Proposed rectangles are NEVER activated silently; an operator
//! must explicitly pass them as `--ignore-rect` to `fss-event watch`.

use std::fmt::{self, Write as _};

use fss_codec_mjpeg::{DecodeBudget, decode_luma_v1 as decode_luma};
use fss_core::{CanonicalEncoder, ContentDigest, SensorCapsule};

use super::privacy_mask::{MaskBinding, current_mask};
use super::recorded_decode::h264::{
    DecoderLimits as H264DecoderLimits, RecordedH264Range, RecordedH264Request,
};
use super::recorded_decode::h265::{
    DecoderLimits as H265DecoderLimits, RecordedH265Range, RecordedH265Request,
};
use super::recorded_decode::{
    ComponentInterpretation, DecodeLimits, RecordedDecodeError, source_capsule, validate_limits,
};
use super::{FileIngestError, RetainedFileImport, RetainedReadLimits, VerifiedChunkCache};
use crate::{ReplayCx, RetainedSource};

/// Maximum explicit OSD ignore rectangles accepted by one watch analysis or proposal.
pub const MAX_IGNORE_REGIONS: usize = 16;

/// Minimum frames required to distinguish repeated OSD ticks from single-pass scene motion.
pub const MIN_OSD_DETECT_FRAMES: usize = 4;

/// Maximum frames inspected by one bounded [`detect_osd_candidates`] invocation.
pub const MAX_OSD_DETECT_FRAMES: usize = 128;

/// Hard ceiling on raw connected components before merging (guards against global noise/flicker).
const MAX_RAW_COMPONENTS: usize = 4096;

/// Canonical digest domain for OSD ignore-region configuration sets.
pub const OSD_IGNORE_REGIONS_DOMAIN: &str = "fss.osd_ignore_regions.v1";

/// Canonical digest domain for watch plans bound to non-empty OSD ignore regions.
pub const WATCH_IGNORE_PLAN_DOMAIN: &str = "fss.recorded_watch_ignore_plan.v1";

/// Canonical digest domain for deterministic OSD candidate proposals.
pub const OSD_CANDIDATE_PROPOSAL_DOMAIN: &str = "fss.osd_candidate_proposal.v1";

/// Schema identifier for `fss-event detect-osd` JSON proposals.
pub const OSD_CANDIDATE_REPORT_SCHEMA: &str = "fss.osd_candidate_report.v1";

/// An explicit axis-aligned pixel rectangle (`X,Y,W,H`) excluded from foreground motion
/// triggers while keeping source pixels untouched in custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ImageRect {
    /// Left edge in decoded pixels.
    pub x: u32,
    /// Top edge in decoded pixels.
    pub y: u32,
    /// Positive width in decoded pixels.
    pub width: u32,
    /// Positive height in decoded pixels.
    pub height: u32,
}

impl ImageRect {
    /// Constructs a validated finite non-empty pixel rectangle.
    pub fn new(x: u32, y: u32, width: u32, height: u32) -> Result<Self, OsdMaskError> {
        if width == 0
            || height == 0
            || x.checked_add(width).is_none()
            || y.checked_add(height).is_none()
        {
            return Err(OsdMaskError::InvalidRect(
                "ignore rect must have positive finite extent",
            ));
        }
        Ok(Self {
            x,
            y,
            width,
            height,
        })
    }

    /// Parses an `X,Y,W,H` unsigned integer pixel rectangle.
    pub fn parse_xywh(value: &str) -> Result<Self, OsdMaskError> {
        let mut parts = value.split(',');
        let parse_next = |iter: &mut std::str::Split<'_, char>| {
            iter.next()
                .and_then(|token| token.parse::<u32>().ok())
                .ok_or(OsdMaskError::InvalidRect(
                    "ignore rect must be four unsigned integers X,Y,W,H",
                ))
        };
        let x = parse_next(&mut parts)?;
        let y = parse_next(&mut parts)?;
        let width = parse_next(&mut parts)?;
        let height = parse_next(&mut parts)?;
        if parts.next().is_some() {
            return Err(OsdMaskError::InvalidRect(
                "ignore rect must be four unsigned integers X,Y,W,H",
            ));
        }
        Self::new(x, y, width, height)
    }

    /// Formats as the exact CLI argument value `X,Y,W,H`.
    #[must_use]
    pub fn to_xywh(self) -> String {
        format!("{},{},{},{}", self.x, self.y, self.width, self.height)
    }

    /// Returns true iff this rectangle lies completely inside `dimensions = [width, height]`.
    #[must_use]
    pub fn fits_within(self, dimensions: [u32; 2]) -> bool {
        u64::from(self.x) + u64::from(self.width) <= u64::from(dimensions[0])
            && u64::from(self.y) + u64::from(self.height) <= u64::from(dimensions[1])
    }
}

/// Typed refusal for OSD ignore-region validation and candidate detection.
#[derive(Debug)]
pub enum OsdMaskError {
    /// Invalid rectangle, duplicate entry, out-of-frame bounds, or invalid detection request.
    InvalidRect(&'static str),
    /// Invalid detection configuration or segment range.
    InvalidRequest(&'static str),
    /// A retained source gap lies inside the inspected clip.
    SourceGap {
        /// First segment whose predecessor bytes are missing.
        segment: usize,
    },
    /// Frame dimensions changed inside the inspected clip.
    DimensionChange {
        /// First segment with different dimensions.
        segment: usize,
    },
    /// Hard candidate or component ceiling exceeded.
    Limit,
    /// Retained source or codec decode refusal.
    Decode(Box<RecordedDecodeError>),
}

impl OsdMaskError {
    /// Stable refusal identity for CLI/agent diagnostics.
    #[must_use]
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::InvalidRect(_) | Self::InvalidRequest(_) => "ERR-WATCH-PLAN-INVALID-001",
            Self::SourceGap { .. } => "ERR-WATCH-SOURCE-GAP-001",
            Self::DimensionChange { .. } | Self::Limit => "ERR-WATCH-LIMIT-001",
            Self::Decode(error) => error.stable_id(),
        }
    }
}

impl fmt::Display for OsdMaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRect(why) => write!(f, "invalid OSD ignore region: {why}"),
            Self::InvalidRequest(why) => write!(f, "invalid OSD detection request: {why}"),
            Self::SourceGap { segment } => {
                write!(
                    f,
                    "OSD detection crosses a source gap before segment {segment}"
                )
            }
            Self::DimensionChange { segment } => {
                write!(f, "frame dimensions change at segment {segment}")
            }
            Self::Limit => f.write_str("OSD detection bound exceeded"),
            Self::Decode(error) => write!(f, "OSD detection decode: {error}"),
        }
    }
}

impl std::error::Error for OsdMaskError {}

impl From<RecordedDecodeError> for OsdMaskError {
    fn from(error: RecordedDecodeError) -> Self {
        Self::Decode(Box::new(error))
    }
}

impl From<FileIngestError> for OsdMaskError {
    fn from(error: FileIngestError) -> Self {
        Self::Decode(Box::new(error.into()))
    }
}

/// Validates and canonically sorts an explicit slice of OSD ignore rectangles.
///
/// Refuses more than [`MAX_IGNORE_REGIONS`] entries, zero-sized/overflowing extents, and
/// duplicates. Canonical ordering ensures argument permutation yields identical digests.
pub fn validate_ignore_regions(regions: &[ImageRect]) -> Result<Vec<ImageRect>, OsdMaskError> {
    if regions.len() > MAX_IGNORE_REGIONS {
        return Err(OsdMaskError::InvalidRect(
            "at most sixteen ignore regions are allowed",
        ));
    }
    let mut sorted = Vec::with_capacity(regions.len());
    for &rect in regions {
        let validated = ImageRect::new(rect.x, rect.y, rect.width, rect.height)?;
        sorted.push(validated);
    }
    sorted.sort_unstable();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(OsdMaskError::InvalidRect("duplicate ignore region"));
    }
    Ok(sorted)
}

/// Verifies every validated ignore region lies completely inside the decoded frame dimensions.
pub fn validate_ignore_regions_in_bounds(
    regions: &[ImageRect],
    dimensions: [u32; 2],
) -> Result<(), OsdMaskError> {
    for rect in regions {
        if !rect.fits_within(dimensions) {
            return Err(OsdMaskError::InvalidRect(
                "ignore region extends outside decoded frame dimensions",
            ));
        }
    }
    Ok(())
}

/// Canonical encoded bytes of a canonically sorted OSD ignore-region set.
#[must_use]
pub fn ignore_regions_bytes(canonical_regions: &[ImageRect]) -> Vec<u8> {
    let mut e = CanonicalEncoder::new();
    e.text(OSD_IGNORE_REGIONS_DOMAIN);
    e.u64(canonical_regions.len() as u64);
    for rect in canonical_regions {
        e.u32(rect.x);
        e.u32(rect.y);
        e.u32(rect.width);
        e.u32(rect.height);
    }
    e.finish()
}

/// Canonical SHA-256 digest of a canonically sorted OSD ignore-region set.
#[must_use]
pub fn ignore_regions_digest(canonical_regions: &[ImageRect]) -> ContentDigest {
    ContentDigest::sha256(&ignore_regions_bytes(canonical_regions))
}

/// Folds non-empty OSD ignore regions into a watch plan digest; empty regions leave the base
/// digest unchanged so historical plans and golden digests remain byte-identical.
#[must_use]
pub fn ignore_regions_plan_digest(
    base_plan_digest: ContentDigest,
    canonical_regions: &[ImageRect],
) -> ContentDigest {
    if canonical_regions.is_empty() {
        return base_plan_digest;
    }
    let mut e = CanonicalEncoder::new();
    e.text(WATCH_IGNORE_PLAN_DOMAIN);
    e.digest(base_plan_digest);
    e.digest(ignore_regions_digest(canonical_regions));
    ContentDigest::sha256(&e.finish())
}

/// Neutralizes pixels inside `ignore_regions` on a scratch copy of a decoded luma plane for
/// foreground motion extraction ONLY.
///
/// Setting every ignored pixel to a constant (`0`) on every frame guarantees zero deviation from
/// the running background model (and breaks 4-connected foreground flood-fill at the ignore-rect
/// boundary) while leaving the original custody/receipt luma plane completely untouched.
pub fn mask_ignore_regions_for_foreground(
    source_luma: &[u8],
    dimensions: [u32; 2],
    ignore_regions: &[ImageRect],
    scratch: &mut Vec<u8>,
) {
    scratch.clear();
    scratch.extend_from_slice(source_luma);
    let width = dimensions[0] as usize;
    let height = dimensions[1] as usize;
    if width == 0 || height == 0 || scratch.len() != width.saturating_mul(height) {
        return;
    }
    for rect in ignore_regions {
        let x0 = (rect.x as usize).min(width);
        let y0 = (rect.y as usize).min(height);
        let x1 = (rect.x as usize)
            .saturating_add(rect.width as usize)
            .min(width);
        let y1 = (rect.y as usize)
            .saturating_add(rect.height as usize)
            .min(height);
        for y in y0..y1 {
            let row_start = y * width;
            scratch[row_start + x0..row_start + x1].fill(0);
        }
    }
}

/// Perimeter anchor classification for a proposed OSD candidate box.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OsdCorner {
    /// Inside both top and left perimeter bands.
    TopLeft,
    /// Inside both top and right perimeter bands.
    TopRight,
    /// Inside both bottom and left perimeter bands.
    BottomLeft,
    /// Inside both bottom and right perimeter bands.
    BottomRight,
    /// Inside the top perimeter band only.
    TopEdge,
    /// Inside the bottom perimeter band only.
    BottomEdge,
    /// Inside the left perimeter band only.
    LeftEdge,
    /// Inside the right perimeter band only.
    RightEdge,
}

impl OsdCorner {
    /// Stable lowercase identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TopLeft => "top_left",
            Self::TopRight => "top_right",
            Self::BottomLeft => "bottom_left",
            Self::BottomRight => "bottom_right",
            Self::TopEdge => "top_edge",
            Self::BottomEdge => "bottom_edge",
            Self::LeftEdge => "left_edge",
            Self::RightEdge => "right_edge",
        }
    }
}

/// Explicit deterministic thresholds for [`detect_osd_candidates`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OsdDetectConfig {
    /// Minimum per-pixel absolute luma delta between consecutive frames to count as a change.
    pub pixel_delta_threshold: u8,
    /// Minimum distinct frame transitions on a pixel for it to count as repeatedly toggling.
    /// Defaults to `3`, which rejects single-pass moving objects (at most 2 transitions/pixel:
    /// entry and exit) while capturing ticking `HH:MM:SS` clocks.
    pub min_transitions: u16,
    /// Minimum repeatedly-toggling pixels in a merged candidate region.
    pub min_active_pixels: usize,
    /// Maximum candidate box area as parts-per-million of frame area (default 100_000 = 10%).
    pub max_candidate_area_ppm: u32,
    /// Perimeter band width/height as parts-per-million of each axis (default 250_000 = 25%).
    pub edge_margin_ppm: u32,
    /// Minimum quiet-border fraction (ppm) in the 1px halo outside the padded candidate box.
    pub min_border_quiet_ppm: u32,
    /// Horizontal pixel gap across which nearby toggling digit clusters merge into one rect.
    pub merge_gap_x: u32,
    /// Vertical pixel gap across which nearby toggling clusters merge into one rect.
    pub merge_gap_y: u32,
    /// Pixel margin added around each detected cluster (clamped to frame bounds) to absorb codec
    /// ringing around sharp OSD glyphs.
    pub padding_px: u32,
}

impl Default for OsdDetectConfig {
    fn default() -> Self {
        Self {
            pixel_delta_threshold: 24,
            min_transitions: 3,
            min_active_pixels: 4,
            max_candidate_area_ppm: 100_000,
            edge_margin_ppm: 250_000,
            min_border_quiet_ppm: 850_000,
            merge_gap_x: 8,
            merge_gap_y: 4,
            padding_px: 2,
        }
    }
}

impl OsdDetectConfig {
    /// Validates all numeric bounds before any media is read.
    pub fn validate(&self) -> Result<(), OsdMaskError> {
        if self.pixel_delta_threshold == 0 {
            return Err(OsdMaskError::InvalidRequest(
                "pixel_delta_threshold must be positive",
            ));
        }
        if self.min_transitions < 2 {
            return Err(OsdMaskError::InvalidRequest(
                "min_transitions must be at least 2",
            ));
        }
        if self.min_active_pixels == 0 {
            return Err(OsdMaskError::InvalidRequest(
                "min_active_pixels must be positive",
            ));
        }
        if self.max_candidate_area_ppm == 0 || self.max_candidate_area_ppm > 500_000 {
            return Err(OsdMaskError::InvalidRequest(
                "max_candidate_area_ppm must be 1..=500000",
            ));
        }
        if self.edge_margin_ppm < 10_000 || self.edge_margin_ppm > 500_000 {
            return Err(OsdMaskError::InvalidRequest(
                "edge_margin_ppm must be 10000..=500000",
            ));
        }
        if self.min_border_quiet_ppm > 1_000_000 {
            return Err(OsdMaskError::InvalidRequest(
                "min_border_quiet_ppm must be <= 1000000",
            ));
        }
        if self.merge_gap_x > 128 || self.merge_gap_y > 128 || self.padding_px > 64 {
            return Err(OsdMaskError::InvalidRequest(
                "merge gap and padding must be bounded (gap <= 128, padding <= 64)",
            ));
        }
        Ok(())
    }
}

/// Exact retained clip selection for [`detect_osd_candidates`].
#[derive(Clone, Debug)]
pub struct OsdDetectRequest {
    /// Completed retained import (MJPEG, H.264, or H.265).
    pub import_identity: ContentDigest,
    /// Explicit component interpretation (H.264/H.265 require `YCbCr`).
    pub interpretation: ComponentInterpretation,
    /// First segment (H.264: IDR; H.265: IRAP).
    pub first_segment: usize,
    /// Number of contiguous segments to inspect (`4..=128`).
    pub segment_count: usize,
    /// Deterministic candidate thresholds.
    pub config: OsdDetectConfig,
}

/// Resource ceilings for [`detect_osd_candidates`].
#[derive(Clone, Copy, Debug)]
pub struct OsdDetectLimits {
    /// Custody-read ceilings per segment.
    pub read_limits: RetainedReadLimits,
    /// JPEG codec ceilings.
    pub jpeg_limits: DecodeLimits,
    /// Cumulative JPEG codec work allowance.
    pub jpeg_work_units: u64,
    /// H.264 codec ceilings.
    pub h264_limits: H264DecoderLimits,
    /// H.265 codec ceilings.
    pub h265_limits: H265DecoderLimits,
}

impl Default for OsdDetectLimits {
    fn default() -> Self {
        let jpeg_limits = DecodeLimits::default();
        Self {
            read_limits: RetainedReadLimits::default(),
            jpeg_limits,
            jpeg_work_units: jpeg_limits.luma_work_bound(),
            h264_limits: H264DecoderLimits::default(),
            h265_limits: H265DecoderLimits::default(),
        }
    }
}

/// One proposed OSD ignore rectangle with supporting quantitative evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OsdCandidate {
    /// Proposed padded `--ignore-rect X,Y,W,H` clamped to frame bounds.
    pub rect: ImageRect,
    /// Tight unpadded bounding box of repeatedly toggling pixels.
    pub raw_rect: ImageRect,
    /// Perimeter anchor region where the candidate sits.
    pub corner: OsdCorner,
    /// Count of repeatedly toggling pixels inside the candidate.
    pub active_pixels: usize,
    /// Maximum per-pixel transition count observed inside the candidate.
    pub max_pixel_transitions: u16,
    /// Mean per-pixel transition count across active pixels, scaled by 1000.
    pub mean_pixel_transitions_x1000: u64,
    /// Candidate box area as parts-per-million of frame area.
    pub box_area_ppm: u32,
    /// Quiet fraction (ppm) of the 1px halo outside the padded box.
    pub border_quiet_ppm: u32,
}

/// Complete read-only OSD candidate proposal. Never activates any mask automatically.
#[derive(Clone, Debug)]
pub struct OsdDetectReport {
    /// Exact retained import identity.
    pub import_identity: ContentDigest,
    /// Published import root.
    pub import_root: ContentDigest,
    /// Retained media format (`mjpeg`, `annexb`, `mp4avc`, `hevc`, `mp4hevc`, ...).
    pub media_format: String,
    /// First requested segment.
    pub first_segment: usize,
    /// Requested segment count.
    pub segment_count: usize,
    /// Frames actually decoded and compared.
    pub frames_analyzed: usize,
    /// Decoded frame dimensions `[width, height]`.
    pub dimensions: [u32; 2],
    /// Applied privacy mask binding (never bypassed).
    pub privacy: MaskBinding,
    /// Actual JPEG codec work units consumed (0 for H.264/H.265).
    pub jpeg_decode_work_units: u64,
    /// Configuration applied.
    pub config: OsdDetectConfig,
    /// Canonical SHA-256 digest pinning source frames, privacy binding, config, and proposals.
    pub proposal_digest: ContentDigest,
    /// Proposed candidate ignore rectangles in canonical order.
    pub candidates: Vec<OsdCandidate>,
}

impl OsdDetectReport {
    /// Exact CLI arguments (`--ignore-rect`, `X,Y,W,H`, ...) an operator can copy into
    /// `fss-event watch` after reviewing the proposal.
    #[must_use]
    pub fn suggested_ignore_rect_args(&self) -> Vec<String> {
        let mut args = Vec::with_capacity(self.candidates.len() * 2);
        for candidate in &self.candidates {
            args.push("--ignore-rect".to_owned());
            args.push(candidate.rect.to_xywh());
        }
        args
    }

    /// Canonical deterministic JSON proposal (`fss.osd_candidate_report.v1`).
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        let _ = write!(
            out,
            concat!(
                "{{\"schema\":\"{schema}\",\"import_identity\":\"{import}\",\"import_root\":\"{root}\",",
                "\"media_format\":{format},\"first_segment\":{first},\"segment_count\":{count},",
                "\"frames_analyzed\":{analyzed},\"width\":{w},\"height\":{h},",
                "\"proposal_digest\":\"{digest}\",\"privacy_mask\":{privacy},",
                "\"jpeg_decode_work_units\":{work},\"auto_activated\":false,",
                "\"distinct_from_privacy_mask\":true,\"effects_authorized\":false,",
                "\"config\":{{\"pixel_delta_threshold\":{delta},\"min_transitions\":{min_t},",
                "\"min_active_pixels\":{min_px},\"max_candidate_area_ppm\":{max_area},",
                "\"edge_margin_ppm\":{edge},\"min_border_quiet_ppm\":{quiet},",
                "\"merge_gap_x\":{gx},\"merge_gap_y\":{gy},\"padding_px\":{pad}}},",
                "\"candidate_count\":{cand_count},\"candidates\":["
            ),
            schema = OSD_CANDIDATE_REPORT_SCHEMA,
            import = self.import_identity,
            root = self.import_root,
            format = json_string(&self.media_format),
            first = self.first_segment,
            count = self.segment_count,
            analyzed = self.frames_analyzed,
            w = self.dimensions[0],
            h = self.dimensions[1],
            digest = self.proposal_digest,
            privacy = self.privacy.to_json(),
            work = self.jpeg_decode_work_units,
            delta = self.config.pixel_delta_threshold,
            min_t = self.config.min_transitions,
            min_px = self.config.min_active_pixels,
            max_area = self.config.max_candidate_area_ppm,
            edge = self.config.edge_margin_ppm,
            quiet = self.config.min_border_quiet_ppm,
            gx = self.config.merge_gap_x,
            gy = self.config.merge_gap_y,
            pad = self.config.padding_px,
            cand_count = self.candidates.len(),
        );
        for (i, c) in self.candidates.iter().enumerate() {
            if i != 0 {
                out.push(',');
            }
            let _ = write!(
                out,
                concat!(
                    "{{\"rect\":{{\"x\":{x},\"y\":{y},\"width\":{w},\"height\":{h}}},",
                    "\"raw_rect\":{{\"x\":{rx},\"y\":{ry},\"width\":{rw},\"height\":{rh}}},",
                    "\"ignore_rect_arg\":{arg},\"corner\":\"{corner}\",",
                    "\"active_pixels\":{px},\"max_pixel_transitions\":{max_t},",
                    "\"mean_pixel_transitions_x1000\":{mean_t},\"box_area_ppm\":{area},",
                    "\"border_quiet_ppm\":{quiet}}}"
                ),
                x = c.rect.x,
                y = c.rect.y,
                w = c.rect.width,
                h = c.rect.height,
                rx = c.raw_rect.x,
                ry = c.raw_rect.y,
                rw = c.raw_rect.width,
                rh = c.raw_rect.height,
                arg = json_string(&c.rect.to_xywh()),
                corner = c.corner.as_str(),
                px = c.active_pixels,
                max_t = c.max_pixel_transitions,
                mean_t = c.mean_pixel_transitions_x1000,
                area = c.box_area_ppm,
                quiet = c.border_quiet_ppm,
            );
        }
        out.push_str("],\"suggested_ignore_rect_args\":[");
        for (i, arg) in self.suggested_ignore_rect_args().iter().enumerate() {
            if i != 0 {
                out.push(',');
            }
            out.push_str(&json_string(arg));
        }
        out.push_str(
            concat!(
                "],\"limitations\":[",
                "\"Proposal only: OSD ignore regions are never activated automatically.\",",
                "\"Review each candidate and pass explicit --ignore-rect X,Y,W,H flags to fss-event watch.\",",
                "\"OSD ignore regions exclude overlays from foreground motion triggers only; they do NOT redact pixels from source custody and are strictly distinct from privacy masks.\"",
                "]}"
            ),
        );
        out
    }
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

enum OsdFrameSource {
    Jpeg {
        retained: Box<RetainedFileImport>,
        next: usize,
        end: usize,
        mask: Box<MaskBinding>,
        chunks: Box<VerifiedChunkCache>,
    },
    H264(Box<RecordedH264Range>),
    H265(Box<RecordedH265Range>),
}

struct OsdDecodedFrame {
    segment: usize,
    capsule: SensorCapsule,
    capsule_digest: ContentDigest,
    dimensions: [u32; 2],
    pixels: Vec<u8>,
}

impl OsdFrameSource {
    fn next(
        &mut self,
        deployment: &dyn RetainedSource,
        request: &OsdDetectRequest,
        limits: &OsdDetectLimits,
        budget: &mut DecodeBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<Option<OsdDecodedFrame>, OsdMaskError> {
        match self {
            Self::Jpeg {
                retained,
                next,
                end,
                mask,
                chunks,
            } => {
                if *next >= *end {
                    return Ok(None);
                }
                let segment = *next;
                let span = &retained.manifest().segment_spans[segment];
                if span.len > limits.jpeg_limits.maximum_bytes as u64 {
                    return Err(RecordedDecodeError::Limit.into());
                }
                let (capsule, capsule_digest) = source_capsule(deployment, retained, segment)?;
                let bytes = retained.read_segment_cached(
                    deployment,
                    segment,
                    limits.read_limits,
                    cx,
                    chunks,
                )?;
                let image = decode_luma(
                    &bytes,
                    capsule.source_digest.bytes(),
                    request.interpretation,
                    limits.jpeg_limits,
                    budget,
                )
                .map_err(RecordedDecodeError::from)?;
                let mut pixels = image.pixels().to_vec();
                mask.apply_luma(&mut pixels, image.dimensions())
                    .map_err(RecordedDecodeError::from)?;
                *next += 1;
                Ok(Some(OsdDecodedFrame {
                    segment,
                    capsule,
                    capsule_digest,
                    dimensions: image.dimensions(),
                    pixels,
                }))
            }
            Self::H264(range) => {
                let Some(frame) = range.next_frame(deployment, cx)? else {
                    return Ok(None);
                };
                Ok(Some(OsdDecodedFrame {
                    segment: usize::try_from(frame.segment_index())
                        .map_err(|_| OsdMaskError::Limit)?,
                    capsule: frame.capsule().clone(),
                    capsule_digest: frame.capsule_digest(),
                    dimensions: frame.dimensions(),
                    pixels: frame.pixels().to_vec(),
                }))
            }
            Self::H265(range) => {
                let Some(frame) = range.next_frame(deployment, cx)? else {
                    return Ok(None);
                };
                Ok(Some(OsdDecodedFrame {
                    segment: usize::try_from(frame.segment_index())
                        .map_err(|_| OsdMaskError::Limit)?,
                    capsule: frame.capsule().clone(),
                    capsule_digest: frame.capsule_digest(),
                    dimensions: frame.dimensions(),
                    pixels: frame.pixels().to_vec(),
                }))
            }
        }
    }
}

/// Inspects a retained recording (MJPEG, H.264, or H.265) read-only and deterministically proposes
/// corner/edge OSD ignore-rectangle candidates without activating anything.
pub fn detect_osd_candidates(
    deployment: &dyn RetainedSource,
    request: &OsdDetectRequest,
    limits: &OsdDetectLimits,
    cx: &ReplayCx,
) -> Result<OsdDetectReport, OsdMaskError> {
    cx.checkpoint("osd_detect:begin")
        .map_err(|_| RecordedDecodeError::Cancelled)?;
    request.config.validate()?;
    if request.segment_count < MIN_OSD_DETECT_FRAMES
        || request.segment_count > MAX_OSD_DETECT_FRAMES
    {
        return Err(OsdMaskError::InvalidRequest(
            "segment_count must be 4..=128",
        ));
    }
    let end = request
        .first_segment
        .checked_add(request.segment_count)
        .ok_or(OsdMaskError::InvalidRequest("segment range overflows"))?;
    validate_limits(limits.jpeg_limits)?;
    let retained =
        RetainedFileImport::open(deployment, request.import_identity, limits.read_limits, cx)?;
    let spans = &retained.manifest().segment_spans;
    if end > spans.len() {
        return Err(RecordedDecodeError::Unavailable.into());
    }
    if let Some(span) = spans[request.first_segment + 1..end]
        .iter()
        .find(|s| s.gap_before)
    {
        return Err(OsdMaskError::SourceGap {
            segment: span.segment_index,
        });
    }
    let media_format = retained.manifest().format.clone();
    let import_root = retained.import_root();
    let (first_capsule, _) = source_capsule(deployment, &retained, request.first_segment)?;
    let privacy =
        current_mask(deployment, &first_capsule.sensor_id).map_err(RecordedDecodeError::from)?;
    let mut source = match media_format.as_str() {
        "mjpeg" | "avimjpeg" => OsdFrameSource::Jpeg {
            retained: Box::new(retained),
            next: request.first_segment,
            end,
            mask: Box::new(privacy.clone()),
            chunks: Box::default(),
        },
        "annexb" | "mp4avc" | "mkvavc" | "flvavc" => {
            OsdFrameSource::H264(Box::new(RecordedH264Range::open(
                deployment,
                RecordedH264Request {
                    import_identity: request.import_identity,
                    first_segment: request.first_segment,
                    segment_count: request.segment_count,
                    interpretation: request.interpretation,
                    read_limits: limits.read_limits,
                    decoder_limits: limits.h264_limits,
                },
                cx,
            )?))
        }
        "hevc" | "mp4hevc" | "mkvhevc" => OsdFrameSource::H265(Box::new(RecordedH265Range::open(
            deployment,
            RecordedH265Request {
                import_identity: request.import_identity,
                first_segment: request.first_segment,
                segment_count: request.segment_count,
                interpretation: request.interpretation,
                read_limits: limits.read_limits,
                decoder_limits: limits.h265_limits,
            },
            cx,
        )?)),
        _ => return Err(RecordedDecodeError::UnsupportedMedia.into()),
    };

    let mut budget = DecodeBudget::new(limits.jpeg_work_units);
    let mut dimensions = [0_u32, 0_u32];
    let mut prev_luma: Option<Vec<u8>> = None;
    let mut pixel_changes: Vec<u16> = Vec::new();
    let mut frame_provenance: Vec<(usize, ContentDigest, ContentDigest)> =
        Vec::with_capacity(request.segment_count);

    while let Some(frame) = source.next(deployment, request, limits, &mut budget, cx)? {
        cx.checkpoint("osd_detect:frame")
            .map_err(|_| RecordedDecodeError::Cancelled)?;
        if frame.capsule.sensor_id != first_capsule.sensor_id {
            return Err(RecordedDecodeError::InvalidReceipt.into());
        }
        if frame_provenance.is_empty() {
            dimensions = frame.dimensions;
            let count = (dimensions[0] as usize)
                .checked_mul(dimensions[1] as usize)
                .filter(|n| *n > 0)
                .ok_or(OsdMaskError::Limit)?;
            pixel_changes = vec![0_u16; count];
        } else if frame.dimensions != dimensions {
            return Err(OsdMaskError::DimensionChange {
                segment: frame.segment,
            });
        }
        let luma_digest = ContentDigest::sha256(&frame.pixels);
        frame_provenance.push((frame.segment, frame.capsule_digest, luma_digest));
        if let Some(prev) = &prev_luma {
            let delta = request.config.pixel_delta_threshold;
            for ((&cur, &old), changes) in frame
                .pixels
                .iter()
                .zip(prev.iter())
                .zip(pixel_changes.iter_mut())
            {
                if cur.abs_diff(old) >= delta {
                    *changes = changes.saturating_add(1);
                }
            }
        }
        prev_luma = Some(frame.pixels);
    }

    if frame_provenance.len() < MIN_OSD_DETECT_FRAMES {
        return Err(OsdMaskError::InvalidRequest(
            "fewer than four decoded frames available for OSD detection",
        ));
    }

    let candidates = extract_osd_candidates(&pixel_changes, dimensions, request.config)?;
    let proposal_digest = compute_proposal_digest(
        request,
        import_root,
        &media_format,
        dimensions,
        &privacy,
        &frame_provenance,
        &candidates,
    );

    Ok(OsdDetectReport {
        import_identity: request.import_identity,
        import_root,
        media_format,
        first_segment: request.first_segment,
        segment_count: request.segment_count,
        frames_analyzed: frame_provenance.len(),
        dimensions,
        privacy,
        jpeg_decode_work_units: budget.used(),
        config: request.config,
        proposal_digest,
        candidates,
    })
}

#[derive(Clone, Copy)]
struct RawBox {
    min_x: u32,
    min_y: u32,
    max_x: u32,
    max_y: u32,
}

impl RawBox {
    fn to_rect(self) -> Result<ImageRect, OsdMaskError> {
        ImageRect::new(
            self.min_x,
            self.min_y,
            self.max_x - self.min_x + 1,
            self.max_y - self.min_y + 1,
        )
    }

    fn close_enough(self, other: Self, gap_x: u32, gap_y: u32) -> bool {
        let x_overlap = self.min_x <= other.max_x.saturating_add(gap_x)
            && other.min_x <= self.max_x.saturating_add(gap_x);
        let y_overlap = self.min_y <= other.max_y.saturating_add(gap_y)
            && other.min_y <= self.max_y.saturating_add(gap_y);
        x_overlap && y_overlap
    }

    fn union(self, other: Self) -> Self {
        Self {
            min_x: self.min_x.min(other.min_x),
            min_y: self.min_y.min(other.min_y),
            max_x: self.max_x.max(other.max_x),
            max_y: self.max_y.max(other.max_y),
        }
    }
}

/// Pure deterministic extraction of OSD candidate rectangles from per-pixel transition counts.
pub fn extract_osd_candidates(
    pixel_changes: &[u16],
    dimensions: [u32; 2],
    config: OsdDetectConfig,
) -> Result<Vec<OsdCandidate>, OsdMaskError> {
    config.validate()?;
    let [width, height] = dimensions;
    let w = width as usize;
    let h = height as usize;
    let frame_pixels = w
        .checked_mul(h)
        .filter(|n| *n > 0 && *n == pixel_changes.len())
        .ok_or(OsdMaskError::Limit)?;

    // 1. Extract 8-connected components of repeatedly toggling pixels.
    let mut visited = vec![false; frame_pixels];
    let mut raw_boxes: Vec<RawBox> = Vec::new();
    let mut stack: Vec<usize> = Vec::new();

    for start in 0..frame_pixels {
        if pixel_changes[start] < config.min_transitions || visited[start] {
            continue;
        }
        visited[start] = true;
        stack.clear();
        stack.push(start);
        let sx = (start % w) as u32;
        let sy = (start / w) as u32;
        let mut bbox = RawBox {
            min_x: sx,
            min_y: sy,
            max_x: sx,
            max_y: sy,
        };
        while let Some(idx) = stack.pop() {
            let px = idx % w;
            let py = idx / w;
            bbox.min_x = bbox.min_x.min(px as u32);
            bbox.max_x = bbox.max_x.max(px as u32);
            bbox.min_y = bbox.min_y.min(py as u32);
            bbox.max_y = bbox.max_y.max(py as u32);
            let y_lo = py.saturating_sub(1);
            let y_hi = (py + 1).min(h - 1);
            let x_lo = px.saturating_sub(1);
            let x_hi = (px + 1).min(w - 1);
            for ny in y_lo..=y_hi {
                let row = ny * w;
                for nx in x_lo..=x_hi {
                    let nidx = row + nx;
                    if !visited[nidx] && pixel_changes[nidx] >= config.min_transitions {
                        visited[nidx] = true;
                        stack.push(nidx);
                    }
                }
            }
        }
        if raw_boxes.len() >= MAX_RAW_COMPONENTS {
            // Too many scattered toggling fragments across the frame: noisy/flickering scene,
            // not isolated corner OSDs. Return no candidates rather than proposing junk rects.
            return Ok(Vec::new());
        }
        raw_boxes.push(bbox);
    }

    // 2. Deterministically merge nearby clusters (e.g. adjacent digits of HH:MM:SS).
    let mut merged = raw_boxes;
    loop {
        let mut changed = false;
        let mut next: Vec<RawBox> = Vec::with_capacity(merged.len());
        let mut used = vec![false; merged.len()];
        for i in 0..merged.len() {
            if used[i] {
                continue;
            }
            used[i] = true;
            let mut current = merged[i];
            let mut grew = true;
            while grew {
                grew = false;
                for j in (i + 1)..merged.len() {
                    if !used[j]
                        && current.close_enough(merged[j], config.merge_gap_x, config.merge_gap_y)
                    {
                        current = current.union(merged[j]);
                        used[j] = true;
                        grew = true;
                        changed = true;
                    }
                }
            }
            next.push(current);
        }
        merged = next;
        if !changed {
            break;
        }
    }

    // 3. Classify perimeter confinement, smallness, and quiet-halo isolation.
    let margin_x = ((u64::from(width) * u64::from(config.edge_margin_ppm)) / 1_000_000)
        .max(16)
        .min((u64::from(width) / 2).max(1)) as u32;
    let margin_y = ((u64::from(height) * u64::from(config.edge_margin_ppm)) / 1_000_000)
        .max(16)
        .min((u64::from(height) / 2).max(1)) as u32;
    let max_box_w = (width / 2).max(1);
    let max_box_h = (height / 4).max(1);

    let mut candidates = Vec::new();
    for raw in merged {
        let raw_rect = raw.to_rect()?;
        let in_top = raw_rect.y + raw_rect.height <= margin_y;
        let in_bottom = raw_rect.y >= height.saturating_sub(margin_y);
        let in_left = raw_rect.x + raw_rect.width <= margin_x;
        let in_right = raw_rect.x >= width.saturating_sub(margin_x);
        let corner = match (in_top, in_bottom, in_left, in_right) {
            (true, _, true, _) => OsdCorner::TopLeft,
            (true, _, _, true) => OsdCorner::TopRight,
            (_, true, true, _) => OsdCorner::BottomLeft,
            (_, true, _, true) => OsdCorner::BottomRight,
            (true, _, _, _) => OsdCorner::TopEdge,
            (_, true, _, _) => OsdCorner::BottomEdge,
            (_, _, true, _) => OsdCorner::LeftEdge,
            (_, _, _, true) => OsdCorner::RightEdge,
            _ => continue,
        };

        let pad_x0 = raw.min_x.saturating_sub(config.padding_px);
        let pad_y0 = raw.min_y.saturating_sub(config.padding_px);
        let pad_x1 = raw.max_x.saturating_add(config.padding_px).min(width - 1);
        let pad_y1 = raw.max_y.saturating_add(config.padding_px).min(height - 1);
        let padded = ImageRect::new(pad_x0, pad_y0, pad_x1 - pad_x0 + 1, pad_y1 - pad_y0 + 1)?;
        if padded.width > max_box_w || padded.height > max_box_h {
            continue;
        }
        let box_area = u64::from(padded.width) * u64::from(padded.height);
        let box_area_ppm = ((box_area * 1_000_000) / (frame_pixels as u64)).min(1_000_000) as u32;
        if box_area_ppm > config.max_candidate_area_ppm {
            continue;
        }

        // Measure active pixels and transition stats inside the raw box.
        let mut active_pixels = 0_usize;
        let mut max_pixel_transitions = 0_u16;
        let mut transition_sum = 0_u64;
        for py in raw.min_y..=raw.max_y {
            let row = (py as usize) * w;
            for px in raw.min_x..=raw.max_x {
                let c = pixel_changes[row + px as usize];
                if c >= config.min_transitions {
                    active_pixels += 1;
                    max_pixel_transitions = max_pixel_transitions.max(c);
                    transition_sum = transition_sum.saturating_add(u64::from(c));
                }
            }
        }
        if active_pixels < config.min_active_pixels {
            continue;
        }
        let mean_pixel_transitions_x1000 =
            (transition_sum.saturating_mul(1000)) / (active_pixels as u64);

        // Measure 1px halo quietness around the padded box (in-bounds pixels only).
        let border_quiet_ppm =
            compute_border_quiet_ppm(pixel_changes, dimensions, padded, config.min_transitions);
        if border_quiet_ppm < config.min_border_quiet_ppm {
            continue;
        }

        candidates.push(OsdCandidate {
            rect: padded,
            raw_rect,
            corner,
            active_pixels,
            max_pixel_transitions,
            mean_pixel_transitions_x1000,
            box_area_ppm,
            border_quiet_ppm,
        });
    }

    candidates.sort_by_key(|c| c.rect);
    candidates.dedup_by_key(|c| c.rect);
    if candidates.len() > MAX_IGNORE_REGIONS {
        candidates.truncate(MAX_IGNORE_REGIONS);
    }
    Ok(candidates)
}

fn compute_border_quiet_ppm(
    pixel_changes: &[u16],
    dimensions: [u32; 2],
    rect: ImageRect,
    min_transitions: u16,
) -> u32 {
    let [width, height] = dimensions;
    let w = width as usize;
    let x0 = rect.x;
    let y0 = rect.y;
    let x1 = rect.x + rect.width - 1;
    let y1 = rect.y + rect.height - 1;
    let ring_x0 = x0.saturating_sub(1);
    let ring_y0 = y0.saturating_sub(1);
    let ring_x1 = (x1 + 1).min(width - 1);
    let ring_y1 = (y1 + 1).min(height - 1);

    let mut total = 0_u64;
    let mut quiet = 0_u64;
    for y in ring_y0..=ring_y1 {
        let row = (y as usize) * w;
        for x in ring_x0..=ring_x1 {
            if x >= x0 && x <= x1 && y >= y0 && y <= y1 {
                continue;
            }
            total += 1;
            if pixel_changes[row + x as usize] < min_transitions {
                quiet += 1;
            }
        }
    }
    if total == 0 {
        return 1_000_000;
    }
    ((quiet * 1_000_000) / total) as u32
}

fn compute_proposal_digest(
    request: &OsdDetectRequest,
    import_root: ContentDigest,
    media_format: &str,
    dimensions: [u32; 2],
    privacy: &MaskBinding,
    frames: &[(usize, ContentDigest, ContentDigest)],
    candidates: &[OsdCandidate],
) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(OSD_CANDIDATE_PROPOSAL_DOMAIN);
    e.digest(request.import_identity);
    e.digest(import_root);
    e.text(media_format);
    e.u8(match request.interpretation {
        ComponentInterpretation::Grayscale => 0,
        ComponentInterpretation::YCbCr => 1,
    });
    e.u64(request.first_segment as u64);
    e.u64(request.segment_count as u64);
    e.u32(dimensions[0]);
    e.u32(dimensions[1]);
    e.digest(privacy.digest());
    e.u32(u32::from(request.config.pixel_delta_threshold));
    e.u32(u32::from(request.config.min_transitions));
    e.u64(request.config.min_active_pixels as u64);
    e.u32(request.config.max_candidate_area_ppm);
    e.u32(request.config.edge_margin_ppm);
    e.u32(request.config.min_border_quiet_ppm);
    e.u32(request.config.merge_gap_x);
    e.u32(request.config.merge_gap_y);
    e.u32(request.config.padding_px);
    e.u64(frames.len() as u64);
    for &(segment, capsule, luma) in frames {
        e.u64(segment as u64);
        e.digest(capsule);
        e.digest(luma);
    }
    e.u64(candidates.len() as u64);
    for c in candidates {
        for v in [
            c.rect.x,
            c.rect.y,
            c.rect.width,
            c.rect.height,
            c.raw_rect.x,
            c.raw_rect.y,
            c.raw_rect.width,
            c.raw_rect.height,
        ] {
            e.u32(v);
        }
        e.text(c.corner.as_str());
        e.u64(c.active_pixels as u64);
        e.u32(u32::from(c.max_pixel_transitions));
        e.u64(c.mean_pixel_transitions_x1000);
        e.u32(c.box_area_ppm);
        e.u32(c.border_quiet_ppm);
    }
    ContentDigest::sha256(&e.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ReferenceDeployment;
    use crate::ingest::{FileFormatHint, FileIngestAdapter, FileIngestRequest};
    use crate::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
    use fss_core::region::{ContextAuthority, RootAuthoritySpec};
    use fss_core::{BudgetVector, OperationId, SensorId, StreamId, TimestampNs};
    use std::error::Error;
    use std::fs;
    use std::path::{Path, PathBuf};

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(name: &str) -> TestResult<Self> {
            for attempt in 0..100_u32 {
                let path = std::env::temp_dir().join(format!(
                    "fss-osd-mask-{name}-{}-{attempt}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Ok(Self(path)),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Err("temp dir capacity".into())
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn context(root: &Path) -> TestResult<ReplayCx> {
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:osd-mask".to_owned(),
            operation_id: OperationId::parse("operation:osd-mask")?,
            principal: "principal:osd-mask".to_owned(),
            capabilities: vec!["ADP-REPLAY-001".to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(64 * 1024 * 1024)
                .storage_operations(4096)
                .build()?,
            privacy_scope: "privacy:test".to_owned(),
            retention_scope: "retention:test".to_owned(),
            anchor_universe: ContentDigest::sha256(b"site:osd-mask"),
            generation: 1,
        })?;
        authority.validate()?;
        Ok(ReplayCx::from_context_authority(
            &authority,
            root.to_path_buf(),
        )?)
    }

    /// 128x96 grayscale MJPEG with a ticking corner clock at (4, 4, 16, 8) and optional moving
    /// object crossing the middle of the frame.
    fn synthetic_clock_mjpeg(tick_clock: bool, include_moving_object: bool) -> TestResult<Vec<u8>> {
        let (w, h) = (128_u32, 96_u32);
        let config = JpegConfig {
            quality: 95,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        };
        let mut stream = Vec::new();
        for frame in 0..12_usize {
            let mut pixels = vec![40_u8; (w * h) as usize];
            if tick_clock {
                // Alternate high-contrast digit blocks inside (4, 4, 16, 8) every 2 frames.
                let bright = (frame / 2) % 2 == 1;
                let value = if bright { 235_u8 } else { 40_u8 };
                for y in 4..12 {
                    for x in 4..20 {
                        pixels[y * w as usize + x] = value;
                    }
                }
            }
            if include_moving_object && frame >= 2 {
                let left = ((frame - 2) * 10).min(112);
                for y in 44..60 {
                    for x in left..(left + 12).min(w as usize) {
                        pixels[y * w as usize + x] = 220;
                    }
                }
            }
            stream.extend(encode_jpeg(w, h, &pixels, &config)?);
        }
        Ok(stream)
    }

    #[test]
    fn image_rect_validation_canonicalizes_and_rejects_bad_or_duplicate_entries() -> TestResult {
        let a = ImageRect::parse_xywh("10,20,30,40")?;
        let b = ImageRect::parse_xywh("0,0,12,8")?;
        assert_eq!(a.to_xywh(), "10,20,30,40");
        let canonical = validate_ignore_regions(&[a, b])?;
        assert_eq!(canonical, vec![b, a]);
        assert_eq!(
            ignore_regions_digest(&validate_ignore_regions(&[a, b])?),
            ignore_regions_digest(&validate_ignore_regions(&[b, a])?)
        );
        validate_ignore_regions_in_bounds(&canonical, [40, 60])?;
        assert!(validate_ignore_regions_in_bounds(&canonical, [39, 60]).is_err());
        assert!(validate_ignore_regions(&[a, a]).is_err());
        assert!(ImageRect::parse_xywh("0,0,0,10").is_err());
        assert!(ImageRect::parse_xywh("0,0,10").is_err());
        assert!(ImageRect::parse_xywh("0,0,10,10,1").is_err());
        let too_many: Vec<_> = (0..=MAX_IGNORE_REGIONS as u32)
            .map(|i| ImageRect {
                x: i,
                y: 0,
                width: 1,
                height: 1,
            })
            .collect();
        assert!(validate_ignore_regions(&too_many).is_err());
        Ok(())
    }

    #[test]
    fn detect_osd_candidates_pinpoints_ticking_corner_clock_and_ignores_moving_object() -> TestResult
    {
        let dir = TempDir::new("clock")?;
        let root = dir.0.join("deployment");
        let clip = dir.0.join("clock.mjpeg");
        fs::write(&clip, synthetic_clock_mjpeg(true, true)?)?;
        let cx = context(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, "site:osd-mask", &cx)?;
        let imported = FileIngestAdapter::ingest(
            FileIngestRequest::new(
                &clip,
                SensorId::parse("sensor:osd-mask")?,
                StreamId::parse("stream:osd-mask")?,
            )
            .with_receive_time(TimestampNs(1_000_000_000)),
            &cx,
            &mut deployment,
        )?;
        let before = deployment.current_anchor().clone();
        let request = OsdDetectRequest {
            import_identity: imported.import_identity,
            interpretation: ComponentInterpretation::Grayscale,
            first_segment: 0,
            segment_count: 12,
            config: OsdDetectConfig::default(),
        };
        let report =
            detect_osd_candidates(&deployment, &request, &OsdDetectLimits::default(), &cx)?;
        // Read-only proposal never mutates authority.
        assert_eq!(*deployment.current_anchor(), before);
        assert_eq!(report.frames_analyzed, 12);
        assert_eq!(report.candidates.len(), 1);
        let cand = &report.candidates[0];
        assert_eq!(cand.corner, OsdCorner::TopLeft);
        // Proposed rect must cover the ticking (4,4,16,8) clock without swallowing the moving object at y=44..60.
        assert!(cand.rect.x <= 4 && cand.rect.x + cand.rect.width >= 20);
        assert!(cand.rect.y <= 4 && cand.rect.y + cand.rect.height >= 12);
        assert!(cand.rect.y + cand.rect.height < 40);
        let json = report.to_json();
        assert!(json.contains("\"schema\":\"fss.osd_candidate_report.v1\""));
        assert!(json.contains("\"auto_activated\":false"));
        assert!(json.contains("\"distinct_from_privacy_mask\":true"));
        assert!(json.contains(&format!("\"--ignore-rect\",\"{}\"", cand.rect.to_xywh())));

        // Deterministic across repeated runs.
        let again = detect_osd_candidates(&deployment, &request, &OsdDetectLimits::default(), &cx)?;
        assert_eq!(report.proposal_digest, again.proposal_digest);
        assert_eq!(json, again.to_json());
        Ok(())
    }

    #[test]
    fn detect_osd_candidates_emits_zero_candidates_on_static_and_non_osd_motion() -> TestResult {
        let dir = TempDir::new("quiet")?;
        let root = dir.0.join("deployment");
        let clip = dir.0.join("moving_only.mjpeg");
        fs::write(&clip, synthetic_clock_mjpeg(false, true)?)?;
        let cx = context(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, "site:osd-mask", &cx)?;
        let imported = FileIngestAdapter::ingest(
            FileIngestRequest::new(
                &clip,
                SensorId::parse("sensor:osd-quiet")?,
                StreamId::parse("stream:osd-quiet")?,
            )
            .with_receive_time(TimestampNs(1_000_000_000)),
            &cx,
            &mut deployment,
        )?;
        let report = detect_osd_candidates(
            &deployment,
            &OsdDetectRequest {
                import_identity: imported.import_identity,
                interpretation: ComponentInterpretation::Grayscale,
                first_segment: 0,
                segment_count: 12,
                config: OsdDetectConfig::default(),
            },
            &OsdDetectLimits::default(),
            &cx,
        )?;
        assert!(report.candidates.is_empty());
        Ok(())
    }

    #[test]
    fn detect_osd_candidates_runs_on_h265_and_h264_imports() -> TestResult {
        const H265: &[u8] =
            include_bytes!("../../tests/fixtures/hevc_ingest/watch_96x48_moving.h265");
        const H264: &[u8] =
            include_bytes!("../../../fss-codec-h264/tests/fixtures/decode/p_qcif_ref3_p4x4.h264");
        let dir = TempDir::new("video")?;
        let root = dir.0.join("deployment");
        let cx = context(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, "site:osd-mask", &cx)?;
        for (name, bytes, hint, count) in [
            ("clip.h265", H265, FileFormatHint::Hevc, 14_usize),
            ("clip.h264", H264, FileFormatHint::AnnexB, 12_usize),
        ] {
            let path = dir.0.join(name);
            fs::write(&path, bytes)?;
            let imported = FileIngestAdapter::ingest(
                FileIngestRequest::new(
                    &path,
                    SensorId::parse(format!("sensor:osd-{name}").replace('.', "-"))?,
                    StreamId::parse("stream:osd-video")?,
                )
                .with_format_hint(hint)
                .with_receive_time(TimestampNs(1_000_000_000)),
                &cx,
                &mut deployment,
            )?;
            let report = detect_osd_candidates(
                &deployment,
                &OsdDetectRequest {
                    import_identity: imported.import_identity,
                    interpretation: ComponentInterpretation::YCbCr,
                    first_segment: 0,
                    segment_count: count,
                    config: OsdDetectConfig::default(),
                },
                &OsdDetectLimits::default(),
                &cx,
            )?;
            assert_eq!(report.frames_analyzed, count);
            assert_eq!(report.jpeg_decode_work_units, 0);
        }
        Ok(())
    }
}
