#![forbid(unsafe_code)]
//! Bounded visual-degradation screening, not a tamper detector or a coverage certificate.
//!
//! `conservative-v1` is an explicit opt-in policy. It flags persistent extreme clipping,
//! exact image repetition, and loss of previously observed contrast. A static scene can
//! legitimately repeat; a clear screen does not establish health, observability or absence.
//! The retained adapter verifies source custody before supplying these derived measurements.

use std::collections::BTreeSet;

use fss_core::{CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest};

use crate::ReplayCx;

/// Custody-verified screening of complete retained recording ranges.
pub mod retained;
/// Constant-memory screening for a strictly ordered live source generation.
pub mod sequential;

/// Immutable name of the only admitted reference screening policy.
pub const POLICY_NAME: &str = "conservative-v1";
/// Maximum distinct frames admitted by the compatibility constructor.
pub const MAX_HEALTH_FRAMES: usize = 128;
/// Hard ceiling for an explicitly bounded whole-recording screen.
pub const MAX_LONG_HEALTH_FRAMES: usize = 65_536;
/// Maximum luma samples per frame, matching the retained luma ceiling.
pub const MAX_HEALTH_PIXELS: usize = 4_194_304;
const POLICY: &[u8] = b"fss.sensor_health.policy.v1:conservative-v1:dark<=20:bright>=235:\
clipped_fraction>=995000ppm:clipped_run>=3:equal_luma_run>=8:\
contrast=p95-p05:textured>=32:collapsed<=2:collapsed_run>=3:\
no_tamper_or_coverage_authority";

/// Exact fixed policy bytes, suitable for retaining beside their digest.
#[must_use]
pub const fn policy_bytes() -> &'static [u8] {
    POLICY
}

/// Digest of every fixed threshold and interpretation of the screening policy.
#[must_use]
pub fn policy_digest() -> ContentDigest {
    ContentDigest::sha256(POLICY)
}

/// A reason for refusing opt-in admission. These are suspected degradation, not diagnoses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthFinding {
    /// At least 99.5% of samples are <= 20 for three successive frames.
    PersistentDarkField,
    /// At least 99.5% of samples are >= 235 for three successive frames.
    PersistentBrightField,
    /// Eight distinct source frames carry exactly identical decoded luma.
    ExactFrameRepetition,
    /// Three low-contrast frames follow a textured frame in the same continuity segment.
    ContrastCollapse,
}

impl HealthFinding {
    /// Stable non-disclosing diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PersistentDarkField => "persistent_dark_field",
            Self::PersistentBrightField => "persistent_bright_field",
            Self::ExactFrameRepetition => "exact_frame_repetition",
            Self::ContrastCollapse => "contrast_collapse",
        }
    }
}

/// One exact input in decoder output order; segment numbers may differ from display order.
#[derive(Clone, Copy)]
pub struct HealthFrame<'a> {
    /// Import, sensor, stream and interpretation identity supplied by the custody owner.
    pub source_generation: ContentDigest,
    /// Original retained segment, not an invented timestamp or a frame-rate estimate.
    pub segment: u64,
    /// Verified original capsule payload digest.
    pub capsule_digest: ContentDigest,
    /// Original conservative capture bounds.
    pub capture: CaptureInterval,
    /// Decoded luma dimensions.
    pub dimensions: [u32; 2],
    /// Original source discontinuity, when known.
    pub gap_before: bool,
    /// Complete row-major decoded luma; never returned or retained by this screen.
    pub pixels: &'a [u8],
}

/// Complete measurements for one frame. Failed calls return no observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthObservation {
    /// Source/interpretation generation actually screened.
    pub source_generation: ContentDigest,
    /// Original retained segment.
    pub segment: u64,
    /// Original capsule payload digest.
    pub capsule_digest: ContentDigest,
    /// Digest of the exact decoded bytes screened.
    pub luma_digest: ContentDigest,
    /// Exact preceding observation in this continuity segment, or none after a reset.
    pub predecessor_digest: Option<ContentDigest>,
    /// Original capture bounds, without clock conversion.
    pub capture: CaptureInterval,
    /// Decoded dimensions.
    pub dimensions: [u32; 2],
    /// Whether this frame reset temporal comparisons.
    pub baseline_reset: bool,
    /// Total luma samples inspected.
    pub samples: u64,
    /// Samples at or below the policy's dark threshold.
    pub dark_samples: u64,
    /// Samples at or above the policy's bright threshold.
    pub bright_samples: u64,
    /// Exact nearest-rank p95 minus p05, in luma units.
    pub contrast_span: u8,
    /// Number of distinct consecutive source frames with this same decoded digest.
    pub repeated_frames: u32,
    /// All current screening findings, in fixed policy order.
    pub findings: Vec<HealthFinding>,
}

impl HealthObservation {
    /// Existing canonical measurement encoding, without pixels or new authority.
    /// The byte layout and domain are unchanged from the original digest implementation.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.sensor_health.observation.v1");
        e.digest(policy_digest());
        e.digest(self.source_generation);
        e.u64(self.segment);
        e.digest(self.capsule_digest);
        e.digest(self.luma_digest);
        e.bool(self.predecessor_digest.is_some());
        if let Some(digest) = self.predecessor_digest {
            e.digest(digest);
        }
        self.capture.encode_canonical(&mut e);
        for dimension in self.dimensions {
            e.u32(dimension);
        }
        e.bool(self.baseline_reset);
        e.u64(self.samples);
        e.u64(self.dark_samples);
        e.u64(self.bright_samples);
        e.u8(self.contrast_span);
        e.u32(self.repeated_frames);
        e.u32(self.findings.len() as u32);
        for finding in &self.findings {
            e.text(finding.as_str());
        }
        e.finish()
    }

    /// Binds policy, source, measurements and every finding; confers no authority.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.canonical_bytes())
    }
}

/// Typed screening failure; none means a clear or empty screen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthError {
    /// Dimensions, sample count or capture bounds are invalid.
    InvalidImage,
    /// A source position was substituted or replayed out of decoder order.
    ReplayedSource,
    /// Cumulative samples or distinct-frame capacity would be exceeded.
    Limit,
    /// Owner cancellation; completed row work remains charged.
    Cancelled,
}

impl std::fmt::Display for HealthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidImage => "invalid sensor-health image",
            Self::ReplayedSource => "sensor-health source position replayed or substituted",
            Self::Limit => "sensor-health work or frame bound exceeded",
            Self::Cancelled => "sensor-health owner cancelled",
        })
    }
}
impl std::error::Error for HealthError {}

#[derive(Clone, Debug)]
struct Previous {
    observation: HealthObservation,
    gap_before: bool,
    dark_run: u32,
    bright_run: u32,
    contrast_run: u32,
    textured: bool,
}

/// Bounded synchronous screen retaining digests and counters, never prior image bytes.
#[derive(Debug)]
pub struct HealthScreen {
    maximum_samples: u64,
    maximum_frames: usize,
    used_samples: u64,
    seen: BTreeSet<(ContentDigest, u64)>,
    previous: Option<Previous>,
}

impl HealthScreen {
    /// Constructs a screen with an explicit cumulative luma-sample allowance.
    /// This compatibility entry point retains its original 128-frame ceiling.
    #[must_use]
    pub fn new(maximum_samples: u64) -> Self {
        Self {
            maximum_samples,
            maximum_frames: MAX_HEALTH_FRAMES,
            used_samples: 0,
            seen: BTreeSet::new(),
            previous: None,
        }
    }

    /// Construct one whole-range screen with an explicit 1..=65536 distinct-frame ceiling.
    /// Resource ceilings are not policy: an admitted observation keeps the same bytes for any
    /// sufficient ceiling. Gaps reset comparisons, never the used samples or replay set.
    pub fn with_frame_limit(
        maximum_samples: u64,
        maximum_frames: usize,
    ) -> Result<Self, HealthError> {
        if !(1..=MAX_LONG_HEALTH_FRAMES).contains(&maximum_frames) {
            return Err(HealthError::Limit);
        }
        Ok(Self {
            maximum_frames,
            ..Self::new(maximum_samples)
        })
    }

    /// Samples processed, including work before cancellation and exact retry validation.
    #[must_use]
    pub const fn samples_used(&self) -> u64 {
        self.used_samples
    }

    /// Screen a frame, polling the owner before each row and before digesting its bytes.
    /// Failed pushes never advance history. An exact immediate retry returns the same
    /// observation without incrementing streaks, but rechecking its bytes still costs work.
    pub fn observe(
        &mut self,
        frame: HealthFrame<'_>,
        cx: &ReplayCx,
    ) -> Result<HealthObservation, HealthError> {
        self.observe_with(frame, || {
            cx.checkpoint("sensor_health:row")
                .map_err(|_| HealthError::Cancelled)
        })
    }

    fn observe_with(
        &mut self,
        frame: HealthFrame<'_>,
        mut check: impl FnMut() -> Result<(), HealthError>,
    ) -> Result<HealthObservation, HealthError> {
        check()?;
        let [width, height] = frame.dimensions;
        let count = u64::from(width) * u64::from(height);
        if width == 0
            || height == 0
            || width > 4096
            || height > 4096
            || count > MAX_HEALTH_PIXELS as u64
            || count != frame.pixels.len() as u64
            || frame.capture.earliest > frame.capture.latest
        {
            return Err(HealthError::InvalidImage);
        }
        if count > self.maximum_samples - self.used_samples {
            return Err(HealthError::Limit);
        }
        let key = (frame.source_generation, frame.segment);
        let retry = self
            .previous
            .as_ref()
            .is_some_and(|p| (p.observation.source_generation, p.observation.segment) == key);
        if !retry && self.seen.contains(&key) {
            return Err(HealthError::ReplayedSource);
        }
        if !retry && self.seen.len() >= self.maximum_frames {
            return Err(HealthError::Limit);
        }
        let mut histogram = [0_u64; 256];
        for row in frame.pixels.chunks_exact(width as usize) {
            check()?;
            for pixel in row {
                histogram[usize::from(*pixel)] += 1;
            }
            self.used_samples += row.len() as u64;
        }
        check()?;
        let luma_digest = ContentDigest::sha256(frame.pixels);
        if retry {
            let previous = self.previous.as_ref().ok_or(HealthError::ReplayedSource)?;
            let p = &previous.observation;
            if p.capsule_digest != frame.capsule_digest
                || p.capture != frame.capture
                || p.dimensions != frame.dimensions
                || p.luma_digest != luma_digest
                || previous.gap_before != frame.gap_before
            {
                return Err(HealthError::ReplayedSource);
            }
            return Ok(p.clone());
        }
        let predecessor = self.previous.as_ref().filter(|p| {
            !frame.gap_before
                && p.observation.source_generation == frame.source_generation
                && p.observation.dimensions == frame.dimensions
        });
        let dark_samples: u64 = histogram[..=20].iter().sum();
        let bright_samples: u64 = histogram[235..].iter().sum();
        let dark = dark_samples * 1_000_000 >= count * 995_000;
        let bright = bright_samples * 1_000_000 >= count * 995_000;
        let contrast_span = percentile(&histogram, (count * 95).div_ceil(100))
            - percentile(&histogram, (count * 5).div_ceil(100));
        let textured_before = predecessor.is_some_and(|p| p.textured);
        let dark_run = if dark {
            predecessor.map_or(1, |p| p.dark_run.saturating_add(1))
        } else {
            0
        };
        let bright_run = if bright {
            predecessor.map_or(1, |p| p.bright_run.saturating_add(1))
        } else {
            0
        };
        let contrast_run = if textured_before && contrast_span <= 2 {
            predecessor.map_or(1, |p| p.contrast_run.saturating_add(1))
        } else {
            0
        };
        let repeated_frames = predecessor
            .filter(|p| p.observation.luma_digest == luma_digest)
            .map_or(1, |p| p.observation.repeated_frames.saturating_add(1));
        let mut findings = Vec::new();
        if dark_run >= 3 {
            findings.push(HealthFinding::PersistentDarkField);
        }
        if bright_run >= 3 {
            findings.push(HealthFinding::PersistentBrightField);
        }
        if repeated_frames >= 8 {
            findings.push(HealthFinding::ExactFrameRepetition);
        }
        if contrast_run >= 3 {
            findings.push(HealthFinding::ContrastCollapse);
        }
        let observation = HealthObservation {
            source_generation: frame.source_generation,
            segment: frame.segment,
            capsule_digest: frame.capsule_digest,
            luma_digest,
            predecessor_digest: predecessor.map(|p| p.observation.digest()),
            capture: frame.capture,
            dimensions: frame.dimensions,
            baseline_reset: predecessor.is_none(),
            samples: count,
            dark_samples,
            bright_samples,
            contrast_span,
            repeated_frames,
            findings,
        };
        self.seen.insert(key);
        self.previous = Some(Previous {
            observation: observation.clone(),
            gap_before: frame.gap_before,
            dark_run,
            bright_run,
            contrast_run,
            textured: textured_before || contrast_span >= 32,
        });
        Ok(observation)
    }
}

fn percentile(histogram: &[u64; 256], rank: u64) -> u8 {
    let mut cumulative = 0;
    for (value, count) in histogram.iter().enumerate() {
        cumulative += count;
        if cumulative >= rank {
            return value as u8;
        }
    }
    255
}

/// Digest domain for additive optical-quality screening (`SCHEMA-DOMAIN-SENSOR-HEALTH-OPTICAL-QUALITY-001`).
pub const OPTICAL_QUALITY_DOMAIN: &str = "fss.sensor_health.optical_quality.v1";

/// Pure-integer thresholds for optical sharpness and localized highlight-glare screening.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpticalThresholds {
    /// Minimum discrete 4-neighbor Laplacian variance scaled by 1000 (`50_000` = variance `50.0`).
    /// Interior variance strictly below this threshold emits [`OpticalFinding::SevereBlur`].
    pub min_laplacian_variance_x1000: u64,
    /// Luma value at or above which a sample counts as localized highlight saturation (default 250).
    pub glare_luma_min: u8,
    /// Minimum saturated-highlight share in parts per million to emit
    /// [`OpticalFinding::LocalizedHighlightGlare`] (default `150_000` = 15%).
    pub max_glare_ppm: u32,
}

impl Default for OpticalThresholds {
    fn default() -> Self {
        Self {
            min_laplacian_variance_x1000: 50_000,
            glare_luma_min: 250,
            max_glare_ppm: 150_000,
        }
    }
}

/// Additive optical-quality findings (suspected optical degradation, never tamper or absence proof).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpticalFinding {
    /// Discrete 4-neighbor Laplacian variance fell below the configured sharpness floor.
    SevereBlur,
    /// Localized highlight saturation (`luma >= glare_luma_min`) met or exceeded `max_glare_ppm`.
    LocalizedHighlightGlare,
    /// Frame dimensions are smaller than `3x3`, so interior Laplacian sharpness is not observable.
    InsufficientResolution,
}

impl OpticalFinding {
    /// Stable diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SevereBlur => "severe_blur",
            Self::LocalizedHighlightGlare => "localized_highlight_glare",
            Self::InsufficientResolution => "insufficient_resolution",
        }
    }
}

/// Exact integer optical sharpness and localized highlight-glare measurements for one frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpticalQualityMetrics {
    /// Source/interpretation generation actually screened.
    pub source_generation: ContentDigest,
    /// Original retained segment.
    pub segment: u64,
    /// Original capsule payload digest.
    pub capsule_digest: ContentDigest,
    /// Digest of the exact decoded luma bytes screened.
    pub luma_digest: ContentDigest,
    /// Decoded frame dimensions `[width, height]`.
    pub dimensions: [u32; 2],
    /// Number of interior pixels `(width - 2) * (height - 2)` evaluated by the 4-neighbor Laplacian.
    pub interior_pixels: u64,
    /// Exact integer variance `Var(L) * 1000` of the 4-neighbor discrete Laplacian `L(x, y)`.
    pub laplacian_variance_x1000: u64,
    /// Count of samples with `luma >= thresholds.glare_luma_min`.
    pub glare_pixels: u64,
    /// Exact floor parts-per-million of glare-saturated pixels across the frame.
    pub glare_ppm: u32,
    /// Thresholds under which this screen was evaluated.
    pub thresholds: OpticalThresholds,
    /// All optical degradation findings in fixed policy order.
    pub findings: Vec<OpticalFinding>,
}

impl OpticalQualityMetrics {
    /// Canonical domain-separated encoding without raw pixels or effect authority.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.text(OPTICAL_QUALITY_DOMAIN);
        e.digest(self.source_generation);
        e.u64(self.segment);
        e.digest(self.capsule_digest);
        e.digest(self.luma_digest);
        for dim in self.dimensions {
            e.u32(dim);
        }
        e.u64(self.interior_pixels);
        e.u64(self.laplacian_variance_x1000);
        e.u64(self.glare_pixels);
        e.u32(self.glare_ppm);
        e.u64(self.thresholds.min_laplacian_variance_x1000);
        e.u8(self.thresholds.glare_luma_min);
        e.u32(self.thresholds.max_glare_ppm);
        e.u32(self.findings.len() as u32);
        for finding in &self.findings {
            e.text(finding.as_str());
        }
        e.finish()
    }

    /// Domain-separated SHA-256 digest of the optical-quality measurement.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.canonical_bytes())
    }
}

/// Screens one decoded luma frame for blur sharpness (exact integer 4-neighbor Laplacian variance)
/// and localized highlight glare saturation, checking cooperative cancellation on every row.
///
/// This helper is strictly additive to `conservative-v1` and does not modify
/// [`HealthObservation`] bytes.
///
/// # Errors
///
/// Returns [`HealthError::InvalidImage`] on invalid dimensions/bounds/capture interval and
/// [`HealthError::Cancelled`] if `cx` is cancelled.
pub fn screen_optical_quality(
    frame: HealthFrame<'_>,
    thresholds: OpticalThresholds,
    cx: &ReplayCx,
) -> Result<OpticalQualityMetrics, HealthError> {
    cx.checkpoint("sensor_health:optical_start")
        .map_err(|_| HealthError::Cancelled)?;
    let [width, height] = frame.dimensions;
    let count = u64::from(width) * u64::from(height);
    if width == 0
        || height == 0
        || width > 4096
        || height > 4096
        || count > MAX_HEALTH_PIXELS as u64
        || count != frame.pixels.len() as u64
        || frame.capture.earliest > frame.capture.latest
        || thresholds.max_glare_ppm > 1_000_000
    {
        return Err(HealthError::InvalidImage);
    }

    let w = width as usize;
    let h = height as usize;
    let mut glare_pixels = 0_u64;
    for row in frame.pixels.chunks_exact(w) {
        cx.checkpoint("sensor_health:optical_glare_row")
            .map_err(|_| HealthError::Cancelled)?;
        for &px in row {
            if px >= thresholds.glare_luma_min {
                glare_pixels += 1;
            }
        }
    }
    let glare_ppm = ((u128::from(glare_pixels) * 1_000_000) / u128::from(count)) as u32;

    let mut findings = Vec::new();
    let (interior_pixels, laplacian_variance_x1000) = if w < 3 || h < 3 {
        findings.push(OpticalFinding::InsufficientResolution);
        (0, 0)
    } else {
        let interior = (w as u64 - 2) * (h as u64 - 2);
        let mut sum_lap: i128 = 0;
        let mut sum_lap_sq: u128 = 0;
        for y in 1..(h - 1) {
            cx.checkpoint("sensor_health:optical_laplacian_row")
                .map_err(|_| HealthError::Cancelled)?;
            let row_above = (y - 1) * w;
            let row_mid = y * w;
            let row_below = (y + 1) * w;
            for x in 1..(w - 1) {
                let center = i64::from(frame.pixels[row_mid + x]);
                let lap = i64::from(frame.pixels[row_above + x])
                    + i64::from(frame.pixels[row_below + x])
                    + i64::from(frame.pixels[row_mid + x - 1])
                    + i64::from(frame.pixels[row_mid + x + 1])
                    - 4 * center;
                sum_lap += i128::from(lap);
                sum_lap_sq += (lap * lap) as u128;
            }
        }
        // Var(L) = (N * sum(L^2) - (sum(L))^2) / N^2; scaled by 1000 in exact u128 arithmetic.
        let n = u128::from(interior);
        let sum_sq_term = n.saturating_mul(sum_lap_sq);
        let mean_sq_term = sum_lap
            .unsigned_abs()
            .saturating_mul(sum_lap.unsigned_abs());
        let numer = sum_sq_term.saturating_sub(mean_sq_term);
        let denom = n.saturating_mul(n);
        let var_x1000 = numer
            .saturating_mul(1000)
            .checked_div(denom)
            .map_or(0, |scaled| u64::try_from(scaled).unwrap_or(u64::MAX));
        if var_x1000 < thresholds.min_laplacian_variance_x1000 {
            findings.push(OpticalFinding::SevereBlur);
        }
        (interior, var_x1000)
    };

    if glare_ppm >= thresholds.max_glare_ppm {
        findings.push(OpticalFinding::LocalizedHighlightGlare);
    }

    let luma_digest = ContentDigest::sha256(frame.pixels);
    Ok(OpticalQualityMetrics {
        source_generation: frame.source_generation,
        segment: frame.segment,
        capsule_digest: frame.capsule_digest,
        luma_digest,
        dimensions: frame.dimensions,
        interior_pixels,
        laplacian_variance_x1000,
        glare_pixels,
        glare_ppm,
        thresholds,
        findings,
    })
}

#[cfg(test)]
mod optical_tests {
    use super::*;
    use fss_core::{BudgetVector, ContextAuthority, OperationId, RootAuthoritySpec, TimestampNs};

    fn test_cx() -> Result<ReplayCx, Box<dyn std::error::Error>> {
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:optical-health".to_owned(),
            operation_id: OperationId::parse("op:optical-health")?,
            principal: "principal:test".to_owned(),
            capabilities: vec!["ADP-REPLAY-001".to_owned()],
            deadline: None,
            priority: 1,
            budgets: BudgetVector::builder().tokens(100).bytes(4096).build()?,
            privacy_scope: "privacy:test".to_owned(),
            retention_scope: "retention:test".to_owned(),
            anchor_universe: ContentDigest::sha256(b"optical-universe"),
            generation: 1,
        })?;
        Ok(ReplayCx::from_context_authority(
            &authority,
            std::env::temp_dir(),
        )?)
    }

    fn make_frame<'a>(
        dimensions: [u32; 2],
        pixels: &'a [u8],
    ) -> Result<HealthFrame<'a>, Box<dyn std::error::Error>> {
        Ok(HealthFrame {
            source_generation: ContentDigest::sha256(b"gen:cam1"),
            segment: 1,
            capsule_digest: ContentDigest::sha256(b"cap:1"),
            capture: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
            dimensions,
            gap_before: false,
            pixels,
        })
    }

    #[test]
    fn sharp_checkerboard_passes_while_flat_blur_flags_severe_blur()
    -> Result<(), Box<dyn std::error::Error>> {
        let cx = test_cx()?;
        let mut sharp = vec![0_u8; 32 * 32];
        for y in 0..32 {
            for x in 0..32 {
                sharp[y * 32 + x] = if (x + y) % 2 == 0 { 200 } else { 40 };
            }
        }
        let sharp_metrics = screen_optical_quality(
            make_frame([32, 32], &sharp)?,
            OpticalThresholds::default(),
            &cx,
        )?;
        assert!(sharp_metrics.findings.is_empty());
        assert!(sharp_metrics.laplacian_variance_x1000 > 1_000_000);
        assert_eq!(sharp_metrics.glare_ppm, 0);

        // Smooth low-frequency gradient simulates heavy defocus blur (Laplacian == 0 everywhere).
        let mut blurred = vec![0_u8; 32 * 32];
        for y in 0..32 {
            for x in 0..32 {
                blurred[y * 32 + x] = 100 + (x as u8);
            }
        }
        let blur_metrics = screen_optical_quality(
            make_frame([32, 32], &blurred)?,
            OpticalThresholds::default(),
            &cx,
        )?;
        assert_eq!(blur_metrics.laplacian_variance_x1000, 0);
        assert_eq!(blur_metrics.findings, vec![OpticalFinding::SevereBlur]);
        assert_ne!(sharp_metrics.digest(), blur_metrics.digest());
        Ok(())
    }

    #[test]
    fn localized_highlight_glare_detected_below_full_frame_whiteout()
    -> Result<(), Box<dyn std::error::Error>> {
        let cx = test_cx()?;
        // 25% of frame blown out by headlight/IR glare (255), rest crisp textured scene.
        let mut pixels = vec![0_u8; 32 * 32];
        for y in 0..32 {
            for x in 0..32 {
                pixels[y * 32 + x] = if y < 8 {
                    255
                } else if (x + y) % 2 == 0 {
                    180
                } else {
                    60
                };
            }
        }
        let metrics = screen_optical_quality(
            make_frame([32, 32], &pixels)?,
            OpticalThresholds::default(),
            &cx,
        )?;
        assert_eq!(metrics.glare_ppm, 250_000);
        assert_eq!(
            metrics.findings,
            vec![OpticalFinding::LocalizedHighlightGlare]
        );
        Ok(())
    }

    #[test]
    fn tiny_frame_reports_insufficient_resolution_and_cancel_refuses()
    -> Result<(), Box<dyn std::error::Error>> {
        let cx = test_cx()?;
        let tiny = screen_optical_quality(
            make_frame([2, 2], &[10, 20, 30, 40])?,
            OpticalThresholds::default(),
            &cx,
        )?;
        assert_eq!(tiny.findings, vec![OpticalFinding::InsufficientResolution]);
        assert_eq!(tiny.interior_pixels, 0);

        cx.request_cancellation();
        let cancelled = screen_optical_quality(
            make_frame([8, 8], &[120; 64])?,
            OpticalThresholds::default(),
            &cx,
        );
        assert_eq!(cancelled, Err(HealthError::Cancelled));
        Ok(())
    }
}

#[cfg(test)]
mod long_tests;
#[cfg(test)]
mod tests;
