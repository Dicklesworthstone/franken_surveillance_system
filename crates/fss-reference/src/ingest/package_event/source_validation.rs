#![forbid(unsafe_code)]
//! Revalidate package detections against their exact retained import before deriving events.

use std::collections::BTreeSet;

use fss_core::{DigestAlgorithm, SensorId};

use super::{
    MAX_DETECTIONS, MAX_LABELS, MAX_PACKAGE_DETECT_FRAMES, MAX_TEXT,
    PackageDetectionRecord, PackageEventError, ReferenceDeployment, ReplayCx, Result, checkpoint,
};
use crate::ingest::recorded_decode::{RecordedDecodeError, source_capsule};
use crate::ingest::{RetainedFileImport, RetainedReadLimits};

/// A source-coordinate boundary that starts a fresh package-tracking epoch.
/// Reasons are independent: one boundary may carry several of them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageTrackingBoundary {
    /// First segment of the new epoch, in retained source coordinates.
    pub before_segment: u64,
    /// The authoritative source capsule explicitly declares missing preceding bytes.
    pub source_gap: bool,
    /// Capsule sequence is not the checked successor of the previous source capsule.
    pub sequence_gap: bool,
    /// The decoded image dimensions changed; image coordinates cannot be carried across it.
    pub dimensions_changed: bool,
}

impl PackageDetectionRecord {
    /// Validate complete bounded structure without trusting the report's `complete` marker.
    /// Display order is allowed to differ from source order, but every requested segment must
    /// occur exactly once. This does not attest numerical inference or source custody.
    pub(super) fn validate_shape(&self) -> Result<()> {
        if self.segment_count == 0 || self.segment_count > MAX_PACKAGE_DETECT_FRAMES as u64
            || self.frames.len() != self.segment_count as usize
            || self.labels.is_empty() || self.labels.len() > MAX_LABELS
            || self.minimum_score_ppm > 1_000_000
        {
            return Err(PackageEventError::Mismatch);
        }
        let end = self.first_segment.checked_add(self.segment_count)
            .ok_or(PackageEventError::Mismatch)?;
        if [&self.model_id, &self.generation].into_iter().any(|s| s.is_empty() || s.len() > MAX_TEXT)
            || self.labels.iter().any(|s| s.is_empty() || s.len() > MAX_TEXT)
            || self.labels.iter().collect::<BTreeSet<_>>().len() != self.labels.len()
        {
            return Err(PackageEventError::Mismatch);
        }
        let color = match self.media_format.as_str() {
            "mjpeg" => "jpeg_rgb",
            "annexb" | "hevc" => "ycbcr420_bt601_limited_rgb",
            _ => return Err(PackageEventError::Mismatch),
        };
        if [self.report_digest, self.package_digest, self.manifest_digest, self.model_digest,
            self.graph_digest, self.contract_digest, self.import_identity, self.import_root]
            .iter().any(|d| d.algorithm() != DigestAlgorithm::Sha256)
        {
            return Err(PackageEventError::Mismatch);
        }
        let sensor = &self.frames[0].sensor_id;
        SensorId::parse(sensor).map_err(|_| PackageEventError::Mismatch)?;
        let mut segments = BTreeSet::new();
        let mut capsules = BTreeSet::new();
        for frame in &self.frames {
            if frame.segment < self.first_segment || frame.segment >= end
                || !segments.insert(frame.segment) || !capsules.insert(frame.capsule_digest)
                || frame.sensor_id != *sensor || frame.color != color
                || frame.capture.earliest > frame.capture.latest
                || frame.detections.len() > MAX_DETECTIONS
                || [frame.capsule_digest, frame.inference_identity, frame.output_digest,
                    frame.detection_report_digest].iter().any(|d| d.algorithm() != DigestAlgorithm::Sha256)
            {
                return Err(PackageEventError::Mismatch);
            }
            let [width, height] = frame.dimensions;
            let right = width.checked_mul(256).filter(|v| *v > 0).ok_or(PackageEventError::Mismatch)?;
            let bottom = height.checked_mul(256).filter(|v| *v > 0).ok_or(PackageEventError::Mismatch)?;
            let mut rows = BTreeSet::new();
            for detection in &frame.detections {
                let score = f32::from_bits(detection.score_bits);
                let [x0, y0, x1, y1] = detection.bounds;
                if !rows.insert(detection.row) || detection.class_index >= self.labels.len() as u64
                    || !score.is_finite() || !(0.0..=1.0).contains(&score)
                    || x0 >= x1 || y0 >= y1 || x1 > right || y1 > bottom
                {
                    return Err(PackageEventError::Mismatch);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct SourcePoint {
    segment: u64,
    sequence: u64,
    gap_before: bool,
    dimensions: [u32; 2],
}

fn boundary(previous: SourcePoint, current: SourcePoint) -> Option<PackageTrackingBoundary> {
    let value = PackageTrackingBoundary {
        before_segment: current.segment,
        source_gap: current.gap_before,
        sequence_gap: previous.sequence.checked_add(1) != Some(current.sequence),
        dimensions_changed: previous.dimensions != current.dimensions,
    };
    (value.source_gap || value.sequence_gap || value.dimensions_changed).then_some(value)
}

/// Read-only source closure verification. The metadata record cannot substitute a foreign
/// capsule, sensor, capture window, format, or import root. Raw source is re-read through the
/// existing bounded custody reader (not decoded or repaired); deleted/corrupt data is refused.
/// A maximum of 64 segments is verified, sequentially, with the existing 16 MiB per-segment and
/// 512 MiB source ceilings. This is custody work, not an additional model call.
pub(super) fn verify_sources(
    deployment: &ReferenceDeployment,
    record: &PackageDetectionRecord,
    cx: &ReplayCx,
) -> Result<Vec<PackageTrackingBoundary>> {
    record.validate_shape()?;
    checkpoint(cx, "package_event:verify_sources")?;
    let limits = RetainedReadLimits::default();
    let retained = RetainedFileImport::open(deployment, record.import_identity, limits, cx)
        .map_err(RecordedDecodeError::from)?;
    if retained.import_root() != record.import_root || retained.manifest().format != record.media_format {
        return Err(PackageEventError::Mismatch);
    }
    let mut ordered: Vec<_> = record.frames.iter().collect();
    ordered.sort_unstable_by_key(|frame| frame.segment);
    let mut previous = None;
    let mut clock = None;
    let mut boundaries = Vec::new();
    for frame in ordered {
        checkpoint(cx, "package_event:verify_source_frame")?;
        let segment = usize::try_from(frame.segment).map_err(|_| PackageEventError::Limit)?;
        let (capsule, digest) = source_capsule(deployment, &retained, segment)?;
        if digest != frame.capsule_digest || capsule.sensor_id.as_str() != frame.sensor_id
            || capsule.capture != frame.capture
        {
            return Err(PackageEventError::Mismatch);
        }
        if clock.as_ref().is_some_and(|basis| basis != &capsule.clock_basis) {
            return Err(PackageEventError::InvalidRequest("package event source clock changed"));
        }
        clock = Some(capsule.clock_basis.clone());
        // Drop each verified segment before reading the next; never buffer the source range.
        let bytes = retained.read_segment(deployment, segment, limits, cx)
            .map_err(RecordedDecodeError::from)?;
        drop(bytes);
        let point = SourcePoint {
            segment: frame.segment,
            sequence: capsule.sequence,
            gap_before: capsule.gap_before,
            dimensions: frame.dimensions,
        };
        if let Some(previous) = previous
            && let Some(value) = boundary(previous, point)
        {
            boundaries.push(value);
        }
        previous = Some(point);
    }
    Ok(boundaries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{RecordDetection, RecordFrame};
    use fss_core::{CaptureInterval, ContentDigest, TimestampNs};

    fn record() -> PackageDetectionRecord {
        let d = ContentDigest::sha256(b"fixture");
        PackageDetectionRecord {
            report_digest: d, package_digest: d, manifest_digest: d,
            model_id: "MOD-TEST-001".into(), generation: "g1".into(), model_digest: d,
            graph_digest: d, contract_digest: d, import_identity: d, import_root: d,
            media_format: "mjpeg".into(), first_segment: 0, segment_count: 2,
            minimum_score_ppm: 300_000, labels: vec!["person".into()],
            frames: (0..2_u64).map(|segment| RecordFrame {
                segment, capsule_digest: ContentDigest::sha256(&segment.to_be_bytes()),
                sensor_id: "sensor:fixture".into(),
                capture: CaptureInterval { earliest: TimestampNs(10), latest: TimestampNs(20) },
                dimensions: [64, 48], color: "jpeg_rgb".into(), inference_identity: d,
                output_digest: d, detection_report_digest: d,
                detections: vec![RecordDetection {
                    row: 7, class_index: 0, score_bits: 0.75_f32.to_bits(),
                    bounds: [0, 0, 256, 512], clipped: false,
                }],
            }).collect(),
        }
    }

    #[test]
    fn complete_display_reordering_is_allowed_but_sparse_duplicate_and_foreign_frames_are_not() -> Result<()> {
        let original = record();
        original.validate_shape()?;
        let mut reordered = original.clone();
        reordered.frames.reverse();
        reordered.validate_shape()?;
        let mut sparse = original.clone();
        sparse.frames.pop();
        assert!(sparse.validate_shape().is_err());
        let mut duplicate = original.clone();
        duplicate.frames[1].segment = 0;
        assert!(duplicate.validate_shape().is_err());
        let mut foreign = original.clone();
        foreign.frames[1].sensor_id = "sensor:other".into();
        assert!(foreign.validate_shape().is_err());
        let mut rebound = original.clone();
        rebound.frames[1].capsule_digest = rebound.frames[0].capsule_digest;
        assert!(rebound.validate_shape().is_err());
        let mut overflow = original;
        overflow.first_segment = u64::MAX;
        assert!(overflow.validate_shape().is_err());
        Ok(())
    }

    #[test]
    fn detector_rows_labels_geometry_and_nonfinite_scores_are_refused_before_tracking() {
        for score in [f32::NAN, f32::INFINITY, -0.1, 1.1] {
            let mut value = record();
            value.frames[0].detections[0].score_bits = score.to_bits();
            assert!(value.validate_shape().is_err());
        }
        for bounds in [[1, 0, 1, 256], [0, 256, 256, 0], [0, 0, 64 * 256 + 1, 256]] {
            let mut value = record();
            value.frames[0].detections[0].bounds = bounds;
            assert!(value.validate_shape().is_err());
        }
        let mut duplicate = record();
        let detection = duplicate.frames[0].detections[0];
        duplicate.frames[0].detections.push(detection);
        assert!(duplicate.validate_shape().is_err());
        let mut class = record();
        class.frames[0].detections[0].class_index = 1;
        assert!(class.validate_shape().is_err());
        let mut labels = record();
        labels.labels.push("person".into());
        assert!(labels.validate_shape().is_err());
        let mut dimensions = record();
        dimensions.frames[0].dimensions = [u32::MAX, 1];
        assert!(dimensions.validate_shape().is_err());
    }

    #[test]
    fn every_source_boundary_reason_is_retained_independently() {
        let previous = SourcePoint { segment: 7, sequence: 12, gap_before: false, dimensions: [64, 48] };
        for flags in 0..8_u8 {
            let current = SourcePoint {
                segment: 8, sequence: if flags & 2 == 0 { 13 } else { 19 },
                gap_before: flags & 1 != 0,
                dimensions: if flags & 4 == 0 { [64, 48] } else { [128, 96] },
            };
            let result = boundary(previous, current);
            if flags == 0 { assert!(result.is_none()); }
            else {
                assert_eq!(result, Some(PackageTrackingBoundary {
                    before_segment: 8, source_gap: flags & 1 != 0,
                    sequence_gap: flags & 2 != 0, dimensions_changed: flags & 4 != 0,
                }));
            }
        }
        let exhausted = SourcePoint { sequence: u64::MAX, ..previous };
        let wrapped = SourcePoint { sequence: 0, segment: 8, ..previous };
        assert!(boundary(exhausted, wrapped).is_some_and(|value| value.sequence_gap));
    }
}
