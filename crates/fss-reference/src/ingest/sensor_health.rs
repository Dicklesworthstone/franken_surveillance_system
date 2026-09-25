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

/// Immutable name of the only admitted reference screening policy.
pub const POLICY_NAME: &str = "conservative-v1";
/// Maximum distinct frames admitted by one screen.
pub const MAX_HEALTH_FRAMES: usize = 128;
/// Maximum luma samples per frame, matching the retained luma ceiling.
pub const MAX_HEALTH_PIXELS: usize = 4_194_304;
const POLICY: &[u8] = b"fss.sensor_health.policy.v1:conservative-v1:dark<=20:bright>=235:\
clipped_fraction>=995000ppm:clipped_run>=3:equal_luma_run>=8:\
contrast=p95-p05:textured>=32:collapsed<=2:collapsed_run>=3:\
no_tamper_or_coverage_authority";

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
    /// Binds policy, source, measurements and every finding; confers no authority.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
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
        ContentDigest::sha256(&e.finish())
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
    used_samples: u64,
    seen: BTreeSet<(ContentDigest, u64)>,
    previous: Option<Previous>,
}

impl HealthScreen {
    /// Constructs a screen with an explicit cumulative luma-sample allowance.
    #[must_use]
    pub fn new(maximum_samples: u64) -> Self {
        Self {
            maximum_samples,
            used_samples: 0,
            seen: BTreeSet::new(),
            previous: None,
        }
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
        if !retry && self.seen.len() == MAX_HEALTH_FRAMES {
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
            predecessor.map_or(1, |p| p.dark_run + 1)
        } else {
            0
        };
        let bright_run = if bright {
            predecessor.map_or(1, |p| p.bright_run + 1)
        } else {
            0
        };
        let contrast_run = if textured_before && contrast_span <= 2 {
            predecessor.map_or(1, |p| p.contrast_run + 1)
        } else {
            0
        };
        let repeated_frames = predecessor
            .filter(|p| p.observation.luma_digest == luma_digest)
            .map_or(1, |p| p.observation.repeated_frames + 1);
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

#[cfg(test)]
mod tests;
