#![forbid(unsafe_code)]
//! Bounded whole-recording projection and unchanged contiguous package-report children.

use std::fmt::{self, Write as _};

use fss_core::ContentDigest;

use super::{
    LONG_SENTINEL_POLICY, LONG_SENTINEL_REPORT_SCHEMA, LongSentinelConfig, LongSentinelLimits,
    LongSentinelPlan, LongSentinelRequest, LongSentinelReservation,
};
use crate::ingest::package_detect::sentinel::validate_burst;
use crate::ingest::package_detect::{
    PackageDetectError, PackageDetectFrame, PackageDetectReport, PackageDetectRequest,
    finish_report, json_string,
};
use crate::ingest::privacy_mask::MaskBinding;
use crate::ingest::recorded_decode::video_budget::{
    VIDEO_DECODE_SEPARATE_AXIS_POLICY, VIDEO_DECODE_WORK_MODEL,
};
use crate::ingest::rgb_detections::RgbDetectionContract;
use crate::ingest::rgb_package::RgbDetectorPackage;

/// Actual counters from one completed native operation; separate from admitted ceilings.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LongSentinelUsage {
    /// Source chunk bytes fetched, including verified origin reads.
    pub source_chunk_bytes: u64,
    /// Sum of decoded raster pixels, including unsampled video reference frames.
    pub pixel_samples: u64,
    /// Encoded bytes admitted before native video decode, including parameter sets.
    pub video_encoded_bytes: u64,
    /// Configured per-access-unit coded-luma capacities admitted before native video decode.
    /// This includes decode-ahead and skipped pictures, not only returned output pixels.
    pub video_coded_luma_capacity: u64,
    /// Total native video admission units; JPEG leaves all three video counters at zero.
    pub video_decode_work_units: u64,
    /// JPEG work charged by the one shared codec budget.
    pub jpeg_work_units: u64,
    /// Detection-head work charged by the one shared head budget.
    pub detection_work_units: u64,
    /// Native pictures decoded, not an assertion that unsampled time was observed by a model.
    pub decoded_frames: usize,
    /// Complete native model/head pipelines, exactly the admitted frame count on success.
    pub inferences: usize,
    /// Logical privacy projection, normalization, and resizing work actually charged.
    pub preprocess_work: u64,
    /// Native executor numerical operations actually charged.
    pub execution_macs: u64,
}

/// Complete immutable aggregate. Child reports remain separate contiguous analysis bursts.
#[derive(Debug)]
pub struct LongSentinelReport {
    request: LongSentinelRequest,
    limits: LongSentinelLimits,
    plan: LongSentinelPlan,
    reports: Vec<PackageDetectReport>,
    reservation: LongSentinelReservation,
    usage: LongSentinelUsage,
    json: String,
    digest: ContentDigest,
}
impl LongSentinelReport {
    /// Exact retained source range, interpretation, and threshold request.
    #[must_use]
    pub const fn request(&self) -> &LongSentinelRequest {
        &self.request
    }
    /// Exact motion-independent sampling and whole-operation inference allowance.
    #[must_use]
    pub const fn config(&self) -> LongSentinelConfig {
        self.plan.config()
    }
    /// Original exact resource settings; later replay ceilings are admission only.
    #[must_use]
    pub const fn limits(&self) -> &LongSentinelLimits {
        &self.limits
    }
    /// Whole source schedule, including every later budget-skipped burst.
    #[must_use]
    pub const fn plan(&self) -> &LongSentinelPlan {
        &self.plan
    }
    /// Ordinary complete contiguous reports; never concatenate their frames for tracking.
    #[must_use]
    pub fn reports(&self) -> &[PackageDetectReport] {
        &self.reports
    }
    /// Checked whole-operation ceilings, separate from actual usage.
    #[must_use]
    pub const fn reservation(&self) -> &LongSentinelReservation {
        &self.reservation
    }
    /// Counters from the one completed native execution.
    #[must_use]
    pub const fn usage(&self) -> &LongSentinelUsage {
        &self.usage
    }
    /// Complete bounded report; no event, effect, or durable-retention acknowledgement.
    #[must_use]
    pub fn json(&self) -> &str {
        &self.json
    }
    /// SHA-256 of exact aggregate JSON, including schedule, settings, and child identities.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
}

/// Refuse before growing past the report owner rather than truncating a partially built object.
struct BoundedJson {
    value: String,
    maximum: usize,
}
impl fmt::Write for BoundedJson {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let required = self.value.len().checked_add(text.len()).ok_or(fmt::Error)?;
        if required > self.maximum {
            return Err(fmt::Error);
        }
        self.value.try_reserve(text.len()).map_err(|_| fmt::Error)?;
        self.value.push_str(text);
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_report(
    package: &RgbDetectorPackage,
    request: &LongSentinelRequest,
    limits: &LongSentinelLimits,
    contract: &RgbDetectionContract,
    import_root: ContentDigest,
    media_format: String,
    privacy: MaskBinding,
    frames: Vec<PackageDetectFrame>,
    plan: LongSentinelPlan,
    reservation: LongSentinelReservation,
    usage: LongSentinelUsage,
) -> Result<LongSentinelReport, PackageDetectError> {
    let admitted: Vec<_> = plan
        .bursts()
        .iter()
        .copied()
        .filter(|burst| burst.admitted)
        .collect();
    let mut groups: Vec<Vec<PackageDetectFrame>> =
        (0..admitted.len()).map(|_| Vec::new()).collect();
    for frame in frames {
        let index = admitted
            .iter()
            .position(|burst| {
                frame.segment >= burst.first_segment
                    && frame.segment < burst.first_segment + burst.segment_count
            })
            .ok_or(PackageDetectError::InvalidRequest)?;
        // Preserve native display order inside each independently tracked contiguous burst.
        groups[index].push(frame);
    }
    let mut reports = Vec::with_capacity(admitted.len());
    let mut child_bytes = 0_usize;
    for (burst, frames) in admitted.into_iter().zip(groups) {
        validate_burst(burst, &frames)?;
        let child_request = PackageDetectRequest {
            import_identity: request.import_identity,
            first_segment: burst.first_segment,
            segment_count: burst.segment_count,
            interpretation: request.interpretation,
            minimum_score_ppm: request.minimum_score_ppm,
        };
        let report = finish_report(
            package,
            &child_request,
            contract,
            import_root,
            media_format.clone(),
            frames,
            privacy.clone(),
        )?;
        child_bytes = child_bytes
            .checked_add(report.json.len())
            .ok_or(PackageDetectError::InvalidRequest)?;
        if child_bytes > limits.maximum_report_bytes {
            return Err(PackageDetectError::InvalidRequest);
        }
        reports.push(report);
    }
    let json = render_report(
        package,
        request,
        limits,
        import_root,
        &media_format,
        &privacy,
        &plan,
        &reports,
        reservation,
        usage,
    )
    .map_err(|_| PackageDetectError::InvalidRequest)?;
    let digest = ContentDigest::sha256(json.as_bytes());
    Ok(LongSentinelReport {
        request: request.clone(),
        limits: *limits,
        plan,
        reports,
        reservation,
        usage,
        json,
        digest,
    })
}

#[allow(clippy::too_many_arguments)]
fn render_report(
    package: &RgbDetectorPackage,
    request: &LongSentinelRequest,
    limits: &LongSentinelLimits,
    import_root: ContentDigest,
    media_format: &str,
    privacy: &MaskBinding,
    plan: &LongSentinelPlan,
    reports: &[PackageDetectReport],
    reservation: LongSentinelReservation,
    usage: LongSentinelUsage,
) -> Result<String, fmt::Error> {
    let mut out = BoundedJson {
        value: String::new(),
        maximum: limits.maximum_report_bytes,
    };
    let config = plan.config();
    write!(
        out,
        "{{\"schema\":\"{LONG_SENTINEL_REPORT_SCHEMA}\",\"source_import\":\"{}\",\"import_root\":\"{}\",\"package_digest\":\"{}\",\"model_digest\":\"{}\",\"media_format\":{},\"privacy_mask\":{},\"decode_range\":{{\"first_segment\":{},\"segment_count\":{}}},\"sampling\":{{\"policy\":{},\"schedule_digest\":\"{}\",\"every_frames\":{},\"burst_frames\":{},\"max_inferences\":{},\"admitted_inferences\":{},\"motion_independent\":true,\"phase\":\"relative_to_first_segment\"}},\"limits_digest\":\"{}\",",
        request.import_identity,
        import_root,
        package.archive_digest(),
        package.model().digest(),
        json_string(media_format),
        privacy.to_json(),
        request.first_segment,
        request.segment_count,
        json_string(LONG_SENTINEL_POLICY),
        plan.digest(),
        config.every_frames,
        config.burst_frames,
        config.max_inferences,
        reservation.inferences,
        limits.digest(),
    )?;
    write!(
        out,
        "\"resource_reservation\":{{\"source_chunk_bytes\":{},\"pixel_samples\":{},\"video_encoded_bytes\":{},\"video_coded_luma_capacity\":{},\"video_decode_work_units\":{},\"jpeg_work_units\":{},\"detection_work_units\":{},\"inferences\":{},\"preprocess_macs\":{},\"execution_macs\":{},\"output_bytes\":{},\"report_bytes\":{}}},",
        reservation.source_chunk_bytes,
        reservation.pixel_samples,
        reservation.video_encoded_bytes,
        reservation.video_coded_luma_capacity,
        reservation.video_decode_work_units,
        reservation.jpeg_work_units,
        reservation.detection_work_units,
        reservation.inferences,
        reservation.preprocess_macs,
        reservation.execution_macs,
        reservation.output_bytes,
        reservation.report_bytes,
    )?;
    write!(
        out,
        "\"resource_usage\":{{\"source_chunk_bytes\":{},\"pixel_samples\":{},\"video_encoded_bytes\":{},\"video_coded_luma_capacity\":{},\"video_decode_work_units\":{},\"jpeg_work_units\":{},\"detection_work_units\":{},\"decoded_frames\":{},\"inferences\":{},\"preprocess_work\":{},\"execution_macs\":{}}},\"video_decode_work_model\":{},\"video_decode_admission_policy\":{},\"source_execution\":{},\"unsampled_ranges\":[",
        usage.source_chunk_bytes,
        usage.pixel_samples,
        usage.video_encoded_bytes,
        usage.video_coded_luma_capacity,
        usage.video_decode_work_units,
        usage.jpeg_work_units,
        usage.detection_work_units,
        usage.decoded_frames,
        usage.inferences,
        usage.preprocess_work,
        usage.execution_macs,
        json_string(VIDEO_DECODE_WORK_MODEL),
        json_string(VIDEO_DECODE_SEPARATE_AXIS_POLICY),
        json_string(if media_format == "mjpeg" {
            "selected_mjpeg_frames"
        } else {
            "strict_whole_video_range"
        }),
    )?;
    for (index, range) in plan.unsampled_ranges().iter().enumerate() {
        if index != 0 {
            out.write_char(',')?;
        }
        write!(
            out,
            "{{\"first_segment\":{},\"segment_count\":{}}}",
            range.first_segment, range.segment_count
        )?;
    }
    out.write_str("],\"bursts\":[")?;
    let mut reports_iter = reports.iter();
    for (index, burst) in plan.bursts().iter().enumerate() {
        if index != 0 {
            out.write_char(',')?;
        }
        write!(
            out,
            "{{\"first_segment\":{},\"segment_count\":{},",
            burst.first_segment, burst.segment_count
        )?;
        if burst.admitted {
            let report = reports_iter.next().ok_or(fmt::Error)?;
            write!(
                out,
                "\"status\":\"completed\",\"report_digest\":\"{}\",\"report\":{}}}",
                report.digest,
                report.json.trim_end()
            )?;
        } else {
            out.write_str(
                "\"status\":\"budget_exhausted\",\"report_digest\":null,\"report\":null}",
            )?;
        }
    }
    if reports_iter.next().is_some() {
        return Err(fmt::Error);
    }
    let complete = plan.bursts().iter().all(|burst| burst.admitted);
    writeln!(
        out,
        "],\"executed_inferences\":{},\"executed_macs\":\"{}\",\"scheduled_bursts_complete\":{complete},\"continuous_coverage\":false,\"tracking_across_bursts\":false,\"absence_certifiable\":false,\"effects_authorized\":false,\"model_outputs\":\"uncalibrated\",\"quality_claim\":\"none\",\"retention\":\"not_asserted_by_computation\"}}",
        usage.inferences, usage.execution_macs,
    )?;
    Ok(out.value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_writer_refuses_before_append_and_counts_utf8_bytes() -> fmt::Result {
        let mut out = BoundedJson {
            value: String::new(),
            maximum: 4,
        };
        out.write_str("é")?;
        out.write_str("[]")?;
        assert_eq!(out.value.len(), 4);
        assert!(out.write_char('x').is_err());
        assert_eq!(out.value, "é[]");
        Ok(())
    }
}
