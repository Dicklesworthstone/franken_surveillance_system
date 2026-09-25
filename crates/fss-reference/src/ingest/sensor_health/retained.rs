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
    HealthError, HealthFinding, HealthFrame, HealthObservation, HealthScreen, POLICY_NAME,
    policy_digest,
};
use crate::ingest::RetainedFileImport;
use crate::ingest::privacy_mask::current_mask;
use crate::ingest::recorded_decode::h264::{RecordedH264Range, RecordedH264Request};
use crate::ingest::recorded_decode::h265::{RecordedH265Range, RecordedH265Request};
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
            let observation = screen.observe(
                HealthFrame {
                    source_generation,
                    segment,
                    capsule_digest,
                    capture: capsule.capture,
                    dimensions,
                    gap_before: capsule.gap_before,
                    pixels,
                },
                cx,
            )?;
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
                        .read_segment(deployment, segment, limits.read_limits, cx)
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
            "annexb" => {
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
                    let receipt = frame.receipt();
                    accept(
                        receipt.segment_index(),
                        receipt.capsule(),
                        receipt.capsule_digest(),
                        receipt.dimensions(),
                        frame.pixels(),
                    )?;
                }
            }
            "hevc" => {
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
                    let receipt = frame.receipt();
                    accept(
                        receipt.segment_index(),
                        receipt.capsule(),
                        receipt.capsule_digest(),
                        receipt.dimensions(),
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
