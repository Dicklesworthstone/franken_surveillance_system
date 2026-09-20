#![forbid(unsafe_code)]
//! Native foreground reports to anonymous image trajectories, without a mock model.
//! Complete foreground reports remain the source of masks, omissions and pixel labels.

use crate::foreground::{ForegroundReport, FrameAssessment};
use crate::image_tracking::{ImageDetection, ImageTracker, ImageTrackingError,
    ImageTrackingFrame, ImageTrackingReport, TrackingAvailability};
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;

impl ImageTracker {
    /// Track the actual output of the native luma/rectification/JPEG foreground path.
    ///
    /// This consumes every retained region or refuses the whole update; it never
    /// truncates a busy scene to fit. The generation binds the frozen background and
    /// every detector setting. Size-filtered components, unknown pixels, masks and
    /// disturbance findings remain reachable through the original report identity.
    ///
    /// Widespread change and unavailable comparison pixels cannot start or confirm
    /// trajectories. Empty available reports age hypotheses, not certify absence.
    /// A permission or generation change requires an explicitly new owner episode.
    pub fn update_foreground(&mut self, report: &ForegroundReport,
        budget: &mut WorkBudget<'_>) -> Result<ImageTrackingReport, ImageTrackingError> {
        budget.charge(512)?;
        if report.regions().len() > self.policy().maximum_detections {
            return Err(ImageTrackingError::Limit);
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(256).map_err(|_| ImageTrackingError::Limit)?;
        bytes.extend_from_slice(b"fss/foreground-tracker/generation/1\0");
        bytes.extend_from_slice(&report.baseline_digest());
        let policy = report.policy();
        for n in [u64::from(policy.minimum_change), policy.minimum_area as u64,
            policy.maximum_regions as u64, u64::from(policy.widespread_per_mille)] {
            bytes.extend_from_slice(&n.to_le_bytes());
        }
        let detector = ContentDigest::sha256(&bytes).bytes();
        let frame = ImageTrackingFrame {
            source: report.source(), detector, permission_mask: report.mask_digest(),
            evidence: report.digest(), availability: match report.assessment() {
                FrameAssessment::NoComparablePixels => TrackingAvailability::Unobservable,
                FrameAssessment::WidespreadChange => TrackingAvailability::Disturbed,
                FrameAssessment::NoAboveThresholdChange | FrameAssessment::LocalChange => TrackingAvailability::Available,
            },
        };
        let mut detections = Vec::new();
        detections.try_reserve_exact(report.regions().len()).map_err(|_| ImageTrackingError::Limit)?;
        for region in report.regions() {
            budget.charge(256)?;
            bytes.clear();
            bytes.extend_from_slice(b"fss/foreground-tracker/component/1\0");
            bytes.extend_from_slice(&report.digest());
            for n in [u64::from(region.id), region.area as u64,
                u64::from(region.min[0]), u64::from(region.min[1]),
                u64::from(region.max[0]), u64::from(region.max[1]),
                region.brighter as u64, region.darker as u64] {
                bytes.extend_from_slice(&n.to_le_bytes());
            }
            bytes.push(u8::from(region.touches_unknown)); bytes.push(u8::from(region.touches_edge));
            detections.push(ImageDetection { id: u64::from(region.id),
                evidence: ContentDigest::sha256(&bytes).bytes(), min: region.min, max: region.max,
                partial: region.touches_unknown || region.touches_edge });
        }
        // The transactional engine owns the only state mutation and final cancel poll.
        self.update(frame, &detections, budget)
    }
}
