#![forbid(unsafe_code)]
//! Read-only screening of verified retained MJPEG, AVC and HEVC source ranges.
//!
//! This is an admission preflight, not a new decode publication, coverage format or event
//! policy. It deliberately refuses a requested range with missing frames or discontinuity.
//! It never writes, exports pixels, runs a model, publishes a witness or authorizes an alert.
//!
//! Every decoded plane is masked by the sensor's current retained privacy mask before it is
//! screened (MJPEG here; AVC and HEVC ranges mask themselves), like every retained decode.

use std::collections::BTreeSet;

use fss_codec_mjpeg::{DecodeBudget, decode_luma};
use fss_core::{CanonicalEncoder, ContentDigest, SensorCapsule};

use super::{
    HealthError, HealthFinding, HealthFrame, HealthObservation, HealthScreen, OPTICAL_QUALITY_DOMAIN,
    OpticalFinding, OpticalQualityMetrics, OpticalThresholds, POLICY_NAME, policy_digest,
    screen_optical_quality,
};
use crate::ingest::RetainedFileImport;
use crate::ingest::privacy_mask::current_mask;
use crate::ingest::recorded_decode::h264::{
    RecordedH264RangeV2 as RecordedH264Range, RecordedH264Request,
};
use crate::ingest::recorded_decode::h265::{
    RecordedH265RangeV1 as RecordedH265Range, RecordedH265Request,
};
use crate::ingest::recorded_decode::{RecordedDecodeError, source_capsule, validate_limits};
use crate::ingest::recorded_watch::{WatchError, WatchLimits, WatchPlan, media_decoder_label};
use crate::{ReferenceDeployment, ReplayCx};

/// A failed preflight has no complete screening result and cannot admit a watch run.
#[derive(Debug)]
pub enum ScreeningError {
    /// The ordinary watch plan is invalid.
    Plan(WatchError),
    /// Source custody, codec or decoder budget failed.
    Decode(Box<RecordedDecodeError>),
    /// Screening input, sample budget, frame limit or cancellation failed.
    Screen(HealthError),
}

impl std::fmt::Display for ScreeningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plan(error) => write!(f, "sensor-health plan: {error}"),
            Self::Decode(error) => write!(f, "sensor-health decode: {error}"),
            Self::Screen(error) => write!(f, "sensor-health screen: {error}"),
        }
    }
}
impl std::error::Error for ScreeningError {}
impl From<RecordedDecodeError> for ScreeningError {
    fn from(error: RecordedDecodeError) -> Self {
        Self::Decode(Box::new(error))
    }
}
impl From<HealthError> for ScreeningError {
    fn from(error: HealthError) -> Self {
        Self::Screen(error)
    }
}

/// Complete source-bound screening record. It is a diagnostic, not retained authority.
#[derive(Clone, Debug)]
pub struct ScreeningReport {
    import_identity: ContentDigest,
    import_root: ContentDigest,
    plan_digest: ContentDigest,
    first_segment: usize,
    segment_count: usize,
    range_complete: bool,
    samples_used: u64,
    observations: Vec<HealthObservation>,
    optical_observations: Vec<OpticalQualityMetrics>,
}

impl ScreeningReport {
    /// Decode and screen one complete watch range using the existing custody and codec owners.
    /// A separate cumulative sample allowance prices only screening, not codec work or I/O.
    /// This extra decode pass does not replace the watch's independent source revalidation.
    pub fn analyze(
        deployment: &ReferenceDeployment,
        plan: &WatchPlan,
        limits: &WatchLimits,
        maximum_samples: u64,
        cx: &ReplayCx,
    ) -> Result<Self, ScreeningError> {
        Self::analyze_with_optical(deployment, plan, limits, maximum_samples, None, cx)
    }

    /// Decode and screen one complete watch range with optional additive Stage-1 optical quality
    /// screening (4-neighbor Laplacian blur variance and localized highlight glare) over the exact
    /// privacy-masked luma plane.
    ///
    /// Preserves byte-identical `conservative-v1` [`Self::observations`], [`Self::digest`], and
    /// [`Self::to_json`] regardless of whether `optical_thresholds` is enabled.
    pub fn analyze_with_optical(
        deployment: &ReferenceDeployment,
        plan: &WatchPlan,
        limits: &WatchLimits,
        maximum_samples: u64,
        optical_thresholds: Option<OpticalThresholds>,
        cx: &ReplayCx,
    ) -> Result<Self, ScreeningError> {
        cx.checkpoint("sensor_health:source")
            .map_err(|_| HealthError::Cancelled)?;
        plan.validate().map_err(ScreeningError::Plan)?;
        validate_limits(limits.jpeg_limits)?;
        let retained =
            RetainedFileImport::open(deployment, plan.import_identity, limits.read_limits, cx)
                .map_err(RecordedDecodeError::from)?;
        let end = plan
            .first_segment
            .checked_add(plan.segment_count)
            .ok_or(HealthError::Limit)?;
        let spans = retained
            .manifest()
            .segment_spans
            .get(plan.first_segment..end)
            .ok_or(RecordedDecodeError::Unavailable)?;
        let import_root = retained.import_root();
        let media = retained.manifest().format.as_str();
        let mut complete = !spans.iter().any(|span| span.gap_before);
        let mut screen = HealthScreen::new(maximum_samples);
        let mut observations = Vec::with_capacity(plan.segment_count);
        let mut optical_observations = if optical_thresholds.is_some() {
            Vec::with_capacity(plan.segment_count)
        } else {
            Vec::new()
        };
        let mut seen = BTreeSet::new();
        let mut accept = |segment: u64,
                          capsule: &SensorCapsule,
                          capsule_digest: ContentDigest,
                          dimensions: [u32; 2],
                          pixels: &[u8]|
         -> Result<(), ScreeningError> {
            let index = usize::try_from(segment).map_err(|_| HealthError::Limit)?;
            if index < plan.first_segment || index >= end || !seen.insert(index) {
                return Err(HealthError::ReplayedSource.into());
            }
            let mut e = CanonicalEncoder::new();
            e.text("fss.sensor_health.source.v1");
            e.digest(plan.import_identity);
            e.digest(import_root);
            e.text(capsule.sensor_id.as_str());
            e.text(capsule.stream_id.as_str());
            e.text(media_decoder_label(media));
            e.u8(match plan.interpretation {
                crate::ingest::recorded_decode::ComponentInterpretation::Grayscale => 0,
                crate::ingest::recorded_decode::ComponentInterpretation::YCbCr => 1,
            });
            let source_generation = ContentDigest::sha256(&e.finish());
            let frame = HealthFrame {
                source_generation,
                segment,
                capsule_digest,
                capture: capsule.capture,
                dimensions,
                gap_before: capsule.gap_before,
                pixels,
            };
            let observation = screen.observe(frame, cx)?;
            if let Some(thresholds) = optical_thresholds {
                let optical = screen_optical_quality(frame, thresholds, cx)?;
                optical_observations.push(optical);
            }
            if let Some(first) = observations.first() {
                let first: &HealthObservation = first;
                complete &= first.source_generation == observation.source_generation
                    && first.dimensions == observation.dimensions;
            }
            complete &= !capsule.gap_before;
            observations.push(observation);
            Ok(())
        };
        match media {
            "mjpeg" => {
                let mut budget = DecodeBudget::new(limits.jpeg_work_units);
                // The sensor's current mask, resolved once; applied before screening.
                let (first, _) = source_capsule(deployment, &retained, plan.first_segment)?;
                let mask = current_mask(deployment, &first.sensor_id)
                    .map_err(RecordedDecodeError::from)?;
                let mut chunks = crate::ingest::VerifiedChunkCache::default();
                for segment in plan.first_segment..end {
                    cx.checkpoint("sensor_health:decode")
                        .map_err(|_| HealthError::Cancelled)?;
                    let span = &retained.manifest().segment_spans[segment];
                    if span.len > limits.jpeg_limits.maximum_bytes as u64 {
                        return Err(RecordedDecodeError::Limit.into());
                    }
                    let (capsule, digest) = source_capsule(deployment, &retained, segment)?;
                    if capsule.sensor_id != first.sensor_id {
                        return Err(RecordedDecodeError::InvalidReceipt.into());
                    }
                    let bytes = retained
                        .read_segment_cached(
                            deployment,
                            segment,
                            limits.read_limits,
                            cx,
                            &mut chunks,
                        )
                        .map_err(RecordedDecodeError::from)?;
                    let image = decode_luma(
                        &bytes,
                        capsule.source_digest.bytes(),
                        plan.interpretation,
                        limits.jpeg_limits,
                        &mut budget,
                    )
                    .map_err(RecordedDecodeError::from)?;
                    let image = mask.mask_luma(image).map_err(RecordedDecodeError::from)?;
                    accept(
                        segment as u64,
                        &capsule,
                        digest,
                        image.dimensions(),
                        image.pixels(),
                    )?;
                }
            }
            "annexb" | "mp4avc" | "mkvavc" => {
                let mut source = RecordedH264Range::open(
                    deployment,
                    RecordedH264Request {
                        import_identity: plan.import_identity,
                        first_segment: plan.first_segment,
                        segment_count: plan.segment_count,
                        interpretation: plan.interpretation,
                        read_limits: limits.read_limits,
                        decoder_limits: limits.h264_limits,
                    },
                    cx,
                )?;
                while let Some(frame) = source.next_frame(deployment, cx)? {
                    accept(
                        frame.segment_index(),
                        frame.capsule(),
                        frame.capsule_digest(),
                        frame.dimensions(),
                        frame.pixels(),
                    )?;
                }
            }
            "hevc" | "mp4hevc" | "mkvhevc" => {
                let mut source = RecordedH265Range::open(
                    deployment,
                    RecordedH265Request {
                        import_identity: plan.import_identity,
                        first_segment: plan.first_segment,
                        segment_count: plan.segment_count,
                        interpretation: plan.interpretation,
                        read_limits: limits.read_limits,
                        decoder_limits: limits.h265_limits,
                    },
                    cx,
                )?;
                while let Some(frame) = source.next_frame(deployment, cx)? {
                    accept(
                        frame.segment_index(),
                        frame.capsule(),
                        frame.capsule_digest(),
                        frame.dimensions(),
                        frame.pixels(),
                    )?;
                }
            }
            _ => return Err(RecordedDecodeError::UnsupportedMedia.into()),
        }
        // A skipped HEVC RASL picture is explicit incomplete screening, never an all-clear.
        complete &= seen.len() == plan.segment_count;
        cx.checkpoint("sensor_health:complete")
            .map_err(|_| HealthError::Cancelled)?;
        Ok(Self {
            import_identity: plan.import_identity,
            import_root,
            plan_digest: plan.digest(),
            first_segment: plan.first_segment,
            segment_count: plan.segment_count,
            range_complete: complete,
            samples_used: screen.samples_used(),
            observations,
            optical_observations,
        })
    }

    /// True only for a fully screened range with no policy finding; not a health certificate.
    #[must_use]
    pub fn admitted(&self) -> bool {
        self.range_complete && self.observations.iter().all(|row| row.findings.is_empty())
    }

    /// Complete source-bound measurements in decoder output order.
    #[must_use]
    pub fn observations(&self) -> &[HealthObservation] {
        &self.observations
    }

    /// Additive Stage-1 optical-quality measurements in decoder output order (empty unless
    /// requested through [`Self::analyze_with_optical`]).
    #[must_use]
    pub fn optical_observations(&self) -> &[OpticalQualityMetrics] {
        &self.optical_observations
    }

    /// True if any screened frame exhibited an additive optical degradation finding.
    #[must_use]
    pub fn has_optical_findings(&self) -> bool {
        self.optical_observations
            .iter()
            .any(|row| !row.findings.is_empty())
    }

    /// True only when both `conservative-v1` and complete additive optical screening reported zero
    /// findings over the full range; never a physical health or coverage certificate.
    #[must_use]
    pub fn optical_admitted(&self) -> bool {
        self.admitted()
            && self.optical_observations.len() == self.observations.len()
            && !self.optical_observations.is_empty()
            && !self.has_optical_findings()
    }

    /// Canonical digest binding the `conservative-v1` report and every additive optical measurement
    /// when optical screening was requested.
    #[must_use]
    pub fn optical_digest(&self) -> Option<ContentDigest> {
        if self.optical_observations.is_empty() {
            return None;
        }
        let mut e = CanonicalEncoder::new();
        e.text(OPTICAL_QUALITY_DOMAIN);
        e.digest(self.digest());
        e.u32(self.optical_observations.len() as u32);
        for metric in &self.optical_observations {
            e.digest(metric.digest());
        }
        Some(ContentDigest::sha256(&e.finish()))
    }

    /// Bounded local-operator optical-quality diagnostic JSON (no raw pixels or effect authority).
    #[must_use]
    pub fn to_optical_json(&self) -> String {
        let rows: Vec<String> = self
            .optical_observations
            .iter()
            .map(|row| {
                let findings: Vec<String> = row
                    .findings
                    .iter()
                    .map(|finding| format!("\"{}\"", OpticalFinding::as_str(*finding)))
                    .collect();
                format!(
                    concat!(
                        "{{\"segment\":{},\"capsule_digest\":\"{}\",\"luma_digest\":\"{}\",",
                        "\"optical_digest\":\"{}\",\"width\":{},\"height\":{},",
                        "\"interior_pixels\":{},\"laplacian_variance_x1000\":{},",
                        "\"glare_pixels\":{},\"glare_ppm\":{},\"findings\":[{}]}}"
                    ),
                    row.segment,
                    row.capsule_digest,
                    row.luma_digest,
                    row.digest(),
                    row.dimensions[0],
                    row.dimensions[1],
                    row.interior_pixels,
                    row.laplacian_variance_x1000,
                    row.glare_pixels,
                    row.glare_ppm,
                    findings.join(",")
                )
            })
            .collect();
        let optical_digest = self
            .optical_digest()
            .map_or_else(|| "null".to_owned(), |d| format!("\"{d}\""));
        format!(
            concat!(
                "{{\"domain\":\"{}\",\"report_digest\":\"{}\",\"optical_report_digest\":{},",
                "\"import_identity\":\"{}\",\"frames_screened\":{},\"range_complete\":{},",
                "\"optical_admitted\":{},\"has_optical_findings\":{},",
                "\"health_certified\":false,\"tamper_proven\":false,",
                "\"absence_certifiable\":false,\"effect_authority\":false,\"frames\":[{}]}}"
            ),
            OPTICAL_QUALITY_DOMAIN,
            self.digest(),
            optical_digest,
            self.import_identity,
            rows.len(),
            self.range_complete,
            self.optical_admitted(),
            self.has_optical_findings(),
            rows.join(",")
        )
    }

    /// Canonical identity of the entire screen, independent of later publication state.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text("fss.sensor_health.report.v1");
        e.digest(policy_digest());
        e.digest(self.import_identity);
        e.digest(self.import_root);
        e.digest(self.plan_digest);
        e.u64(self.first_segment as u64);
        e.u64(self.segment_count as u64);
        e.bool(self.range_complete);
        e.u64(self.samples_used);
        e.u32(self.observations.len() as u32);
        for observation in &self.observations {
            e.digest(observation.digest());
        }
        ContentDigest::sha256(&e.finish())
    }

    /// Require explicit preflight admission. Suspicion never becomes a successful empty result.
    pub fn require_admission(&self) -> Result<(), ScreeningRefusal> {
        if self.admitted() {
            Ok(())
        } else {
            Err(ScreeningRefusal {
                report_digest: self.digest(),
                range_complete: self.range_complete,
            })
        }
    }

    /// Bounded local-operator diagnostic JSON. No raw pixels, identities of people or credentials.
    #[must_use]
    pub fn to_json(&self) -> String {
        let rows: Vec<String> = self
            .observations
            .iter()
            .map(|row| {
                let findings: Vec<String> = row
                    .findings
                    .iter()
                    .map(|finding| format!("\"{}\"", HealthFinding::as_str(*finding)))
                    .collect();
                format!(
                    concat!(
                        "{{\"segment\":{},\"capsule_digest\":\"{}\",\"luma_digest\":\"{}\",",
                        "\"observation_digest\":\"{}\",\"capture_ns\":[\"{}\",\"{}\"],",
                        "\"width\":{},\"height\":{},\"baseline_reset\":{},\"samples\":{},",
                        "\"dark_samples\":{},\"bright_samples\":{},\"contrast_span\":{},",
                        "\"repeated_frames\":{},\"findings\":[{}]}}"
                    ),
                    row.segment,
                    row.capsule_digest,
                    row.luma_digest,
                    row.digest(),
                    row.capture.earliest.0,
                    row.capture.latest.0,
                    row.dimensions[0],
                    row.dimensions[1],
                    row.baseline_reset,
                    row.samples,
                    row.dark_samples,
                    row.bright_samples,
                    row.contrast_span,
                    row.repeated_frames,
                    findings.join(",")
                )
            })
            .collect();
        format!(
            concat!(
                "{{\"format\":\"fss.local_sensor_health_report.v1\",",
                "\"policy\":\"{}\",\"policy_digest\":\"{}\",\"report_digest\":\"{}\",",
                "\"import_identity\":\"{}\",\"import_root\":\"{}\",\"plan_digest\":\"{}\",",
                "\"first_segment\":{},\"segment_count\":{},\"frames_screened\":{},",
                "\"range_complete\":{},\"admitted\":{},\"status\":\"{}\",",
                "\"samples_used\":{},\"health_certified\":false,\"tamper_proven\":false,",
                "\"absence_certifiable\":false,\"effect_authority\":false,\"frames\":[{}]}}"
            ),
            POLICY_NAME,
            policy_digest(),
            self.digest(),
            self.import_identity,
            self.import_root,
            self.plan_digest,
            self.first_segment,
            self.segment_count,
            rows.len(),
            self.range_complete,
            self.admitted(),
            if self.admitted() {
                "no_screening_findings"
            } else {
                "refused"
            },
            self.samples_used,
            rows.join(",")
        )
    }
}

/// A complete screen refused admission. It does not claim a physical cause or tamper diagnosis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScreeningRefusal {
    /// Exact diagnostic screen that must be inspected.
    pub report_digest: ContentDigest,
    /// False when source discontinuity or skipped/changed frames prevented a complete screen.
    pub range_complete: bool,
}
impl std::fmt::Display for ScreeningRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "sensor-health admission refused: {}; report {}",
            if self.range_complete {
                "suspected visual degradation (not a tamper diagnosis)"
            } else {
                "incomplete or discontinuous source range"
            },
            self.report_digest
        )
    }
}
impl std::error::Error for ScreeningRefusal {}

#[cfg(test)]
mod optical_retained_tests {
    use super::*;
    use crate::ingest::recorded_decode::ComponentInterpretation;
    use crate::ingest::recorded_watch::{WatchDetectorConfig, WatchTrackerConfig, WatchZone};
    use crate::ingest::{FileIngestAdapter, FileIngestRequest};
    use crate::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
    use fss_core::region::{ContextAuthority, RootAuthoritySpec};
    use fss_core::{BudgetVector, OperationId, SensorId, StreamId, TimestampNs};
    use std::fs;
    use std::path::{Path, PathBuf};

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Result<Self, Box<dyn std::error::Error>> {
            for attempt in 0..100_u32 {
                let path = std::env::temp_dir().join(format!(
                    "fss-optical-retained-{tag}-{}-{attempt}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Ok(Self(path)),
                    Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(err) => return Err(err.into()),
                }
            }
            Err(std::io::Error::other("temp dir capacity").into())
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_cx(root: &Path) -> Result<ReplayCx, Box<dyn std::error::Error>> {
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:optical-retained".to_owned(),
            operation_id: OperationId::parse("operation:optical-retained")?,
            principal: "principal:optical-retained".to_owned(),
            capabilities: vec!["ADP-REPLAY-001".to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(64 * 1024 * 1024)
                .storage_operations(4096)
                .build()?,
            privacy_scope: "privacy:test".to_owned(),
            retention_scope: "retention:test".to_owned(),
            anchor_universe: ContentDigest::sha256(b"site:optical-retained"),
            generation: 1,
        })?;
        authority.validate()?;
        Ok(ReplayCx::from_context_authority(
            &authority,
            root.to_path_buf(),
        )?)
    }

    fn sharp_pixels(w: u32, h: u32) -> Vec<u8> {
        let mut out = vec![0_u8; (w * h) as usize];
        for y in 0..h {
            for x in 0..w {
                out[(y * w + x) as usize] = if ((x / 4) + (y / 4)) % 2 == 0 {
                    200
                } else {
                    40
                };
            }
        }
        out
    }

    #[test]
    fn retained_mjpeg_optical_screening_preserves_baseline_and_flags_blur_and_glare()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new("mixed")?;
        let root = dir.0.join("deployment");
        let w = 64_u32;
        let h = 48_u32;
        let cfg = JpegConfig {
            quality: 95,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        };

        // Frame 0: sharp block checkerboard.
        let frame0 = sharp_pixels(w, h);
        // Frame 1: flat low-frequency defocused field (Laplacian variance near 0).
        let frame1 = vec![120_u8; (w * h) as usize];
        // Frame 2: sharp texture with top 25% saturated highlight glare (255).
        let mut frame2 = sharp_pixels(w, h);
        for y in 0..(h / 4) {
            for x in 0..w {
                frame2[(y * w + x) as usize] = 255;
            }
        }

        let mut stream = Vec::new();
        for pixels in [&frame0, &frame1, &frame2] {
            stream.extend(encode_jpeg(w, h, pixels, &cfg)?);
        }
        let mjpeg_path = dir.0.join("optical.mjpeg");
        fs::write(&mjpeg_path, &stream)?;

        let cx = test_cx(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, "site:optical-retained", &cx)?;
        let import_id = FileIngestAdapter::ingest(
            FileIngestRequest::new(
                mjpeg_path,
                SensorId::parse("sensor:optical-cam")?,
                StreamId::parse("stream:main")?,
            )
            .with_receive_time(TimestampNs(1_000_000_000)),
            &cx,
            &mut deployment,
        )?
        .import_identity;

        let plan = WatchPlan {
            import_identity: import_id,
            interpretation: ComponentInterpretation::Grayscale,
            first_segment: 0,
            segment_count: 3,
            zones: vec![WatchZone {
                zone_id: "entry".to_owned(),
                x: 0,
                y: 0,
                width: w,
                height: h,
            }],
            detector: WatchDetectorConfig::default(),
            tracker: WatchTrackerConfig::default(),
        };
        let limits = WatchLimits::default();

        let baseline = ScreeningReport::analyze(&deployment, &plan, &limits, 1_000_000, &cx)?;
        let optical = ScreeningReport::analyze_with_optical(
            &deployment,
            &plan,
            &limits,
            1_000_000,
            Some(OpticalThresholds::default()),
            &cx,
        )?;

        assert_eq!(baseline.digest(), optical.digest());
        assert_eq!(baseline.to_json(), optical.to_json());
        assert!(baseline.optical_observations().is_empty());
        assert!(baseline.optical_digest().is_none());

        assert_eq!(optical.optical_observations().len(), 3);
        assert!(optical.optical_observations()[0].findings.is_empty());
        assert!(
            optical.optical_observations()[1]
                .findings
                .contains(&OpticalFinding::SevereBlur)
        );
        assert!(
            optical.optical_observations()[2]
                .findings
                .contains(&OpticalFinding::LocalizedHighlightGlare)
        );
        assert!(optical.has_optical_findings());
        assert!(!optical.optical_admitted());
        assert!(optical.optical_digest().is_some());

        let json = optical.to_optical_json();
        assert!(json.contains("\"severe_blur\""));
        assert!(json.contains("\"localized_highlight_glare\""));
        assert!(json.contains("\"health_certified\":false"));
        assert!(json.contains("\"effect_authority\":false"));
        assert!(json.contains("\"optical_admitted\":false"));
        Ok(())
    }

    #[test]
    fn retained_mjpeg_all_sharp_frames_pass_optical_admission()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new("sharp")?;
        let root = dir.0.join("deployment");
        let w = 64_u32;
        let h = 48_u32;
        let cfg = JpegConfig {
            quality: 95,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        };
        let mut stream = Vec::new();
        for offset in [0_u8, 4_u8, 8_u8] {
            let mut pixels = sharp_pixels(w, h);
            for p in &mut pixels {
                *p = p.saturating_add(offset);
            }
            stream.extend(encode_jpeg(w, h, &pixels, &cfg)?);
        }
        let mjpeg_path = dir.0.join("sharp.mjpeg");
        fs::write(&mjpeg_path, &stream)?;

        let cx = test_cx(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, "site:optical-sharp", &cx)?;
        let import_id = FileIngestAdapter::ingest(
            FileIngestRequest::new(
                mjpeg_path,
                SensorId::parse("sensor:optical-cam")?,
                StreamId::parse("stream:main")?,
            )
            .with_receive_time(TimestampNs(2_000_000_000)),
            &cx,
            &mut deployment,
        )?
        .import_identity;

        let plan = WatchPlan {
            import_identity: import_id,
            interpretation: ComponentInterpretation::Grayscale,
            first_segment: 0,
            segment_count: 3,
            zones: vec![WatchZone {
                zone_id: "entry".to_owned(),
                x: 0,
                y: 0,
                width: w,
                height: h,
            }],
            detector: WatchDetectorConfig::default(),
            tracker: WatchTrackerConfig::default(),
        };
        let report = ScreeningReport::analyze_with_optical(
            &deployment,
            &plan,
            &WatchLimits::default(),
            1_000_000,
            Some(OpticalThresholds::default()),
            &cx,
        )?;
        assert!(report.admitted());
        assert!(report.optical_admitted());
        assert!(!report.has_optical_findings());
        assert!(report.to_optical_json().contains("\"optical_admitted\":true"));
        Ok(())
    }
}
