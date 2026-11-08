#![forbid(unsafe_code)]
//! Actual package-record and tracker data shapes, shared by native custody and pure consumers.
//! These public records describe data; only the existing retained owners authenticate it.

use fss_core::{CaptureInterval, ContentDigest};

/// One surviving detection of a retained frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordDetection {
    /// Head row.
    pub row: u64,
    /// Label index.
    pub class_index: u64,
    /// F32 score bits (uncalibrated).
    pub score_bits: u32,
    /// Source-grid XYXY in 1/256 pixels.
    pub bounds: [u32; 4],
    /// Clipped to the image.
    pub clipped: bool,
}

/// One retained frame of a package detection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordFrame {
    /// Retained segment.
    pub segment: u64,
    /// Source-capsule payload digest.
    pub capsule_digest: ContentDigest,
    /// Recording sensor.
    pub sensor_id: String,
    /// Conservative capture interval.
    pub capture: CaptureInterval,
    /// Coded dimensions.
    pub dimensions: [u32; 2],
    /// Colour path (`jpeg_rgb` or `ycbcr420_bt601_limited_rgb`).
    pub color: String,
    /// Inference identity.
    pub inference_identity: ContentDigest,
    /// Output tensor digest.
    pub output_digest: ContentDigest,
    /// Head projection report digest.
    pub detection_report_digest: ContentDigest,
    /// Every NMS survivor, in report order.
    pub detections: Vec<RecordDetection>,
}

/// Canonical record of one completed package detection (the retained ledger payload).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageDetectionRecord {
    /// SHA-256 of the exact report JSON.
    pub report_digest: ContentDigest,
    /// Package archive digest.
    pub package_digest: ContentDigest,
    /// Package manifest digest.
    pub manifest_digest: ContentDigest,
    /// Model id.
    pub model_id: String,
    /// Model generation.
    pub generation: String,
    /// Built model digest.
    pub model_digest: ContentDigest,
    /// Graph artifact digest.
    pub graph_digest: ContentDigest,
    /// Applied head contract digest.
    pub contract_digest: ContentDigest,
    /// Exact import.
    pub import_identity: ContentDigest,
    /// Import root.
    pub import_root: ContentDigest,
    /// Retained media format.
    pub media_format: String,
    /// First segment of the range.
    pub first_segment: u64,
    /// Requested segment count.
    pub segment_count: u64,
    /// Applied threshold.
    pub minimum_score_ppm: u32,
    /// Ordered label vocabulary.
    pub labels: Vec<String>,
    /// Completed frames.
    pub frames: Vec<RecordFrame>,
}

/// Kalman/IoU tracking policy of a package analysis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageTrackingConfig {
    /// Consecutive hits before a track is confirmed.
    pub confirmation_hits: u32,
    /// Consecutive misses before a track is deleted.
    pub maximum_missed_frames: u32,
    /// Minimum predicted-box IoU for association, parts per million.
    pub minimum_iou_ppm: u32,
}
/// One matched frame of a tracked label, with the detection it was actually assigned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageObservation {
    /// Retained segment.
    pub segment: u64,
    /// Source-capsule payload digest.
    pub capsule_digest: ContentDigest,
    /// Filtered track box `(cx, cy, w, h)` in pixels, rounded.
    pub track_box: [i64; 4],
    /// Actual assigned detection `(row, score bits, bounds, descriptive filtered-box IoU ppm)`.
    /// New v2 analyses always populate this for observations; no nearby-row substitution.
    pub detection: Option<(u64, u32, [u32; 4], u32)>,
}

/// One track of the chosen label, confined to one source-continuity epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageTrack {
    /// Deterministic identity (record, label, policy, tracker id); not a physical identity.
    pub identity: ContentDigest,
    /// Analysis-local id, never recycled across source-continuity epochs.
    pub track_id: u64,
    /// Whether the track was ever confirmed.
    pub confirmed: bool,
    /// Matched frames in display order within this epoch.
    pub observations: Vec<PackageObservation>,
}

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

/// Native confirmation-index rule: tentative tracks retire on their first miss,
/// and a surviving track confirms on its configured match without rewriting earlier samples.
/// Callers validate the tracker configuration and the observation's ownership separately.
pub(crate) fn sample_confirmed(config: PackageTrackingConfig, observation: usize) -> bool {
    observation >= config.confirmation_hits.saturating_sub(1) as usize
}
