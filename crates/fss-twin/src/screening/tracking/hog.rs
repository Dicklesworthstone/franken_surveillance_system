#![forbid(unsafe_code)]
//! Learned scan -> existing anonymous tracker -> existing resumable zone monitor.
//! A positive window is neither a semantic person identity nor effect authority.
use super::super::{ScreeningHealth, ScreeningReport};
use crate::hog_scan::{HogScan, WindowDisposition};
use crate::image_tracking::{
    ImageDetection, ImageTrackingError, ImageTrackingFrame, TrackingAvailability,
};
use crate::image_zones::pipeline::{ImageZonePipeline, ZonePipelineError, ZonePipelineProgress};
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;

/// Failures precede new tracking consumption. The caller keeps its complete borrowed scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HogZoneError {
    /// Model-source/screen/mask/generation/policy mismatch or nonempty initial pipeline.
    BasisMismatch,
    /// The health sequence or receive clock regressed/repeated.
    OutOfOrder,
    /// The existing pipeline refused, including pending prior analysis or work exhaustion.
    Pipeline(ZonePipelineError),
}
impl std::fmt::Display for HogZoneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BasisMismatch => "HOG zone source or health basis mismatch",
            Self::OutOfOrder => "HOG zone health input did not advance",
            Self::Pipeline(_) => "HOG zone pipeline refused before source consumption",
        })
    }
}
impl std::error::Error for HogZoneError {}
impl From<ZonePipelineError> for HogZoneError {
    fn from(error: ZonePipelineError) -> Self {
        Self::Pipeline(error)
    }
}
fn charge(budget: &mut WorkBudget<'_>, n: u64) -> Result<(), HogZoneError> {
    budget
        .charge(n)
        .map_err(|e| HogZoneError::Pipeline(ZonePipelineError::Tracking(e.into())))
}

/// Owns the EXISTING tracker/zone pipeline and a bounded independent health-chain cursor.
/// A Pending outcome retains its accepted scan/screen identities; resume never scans again.
/// The caller retains the actual HogScan and its source media under the original privacy scope.
pub struct HogZonePipeline {
    pipeline: ImageZonePipeline,
    generation: u64,
    last_screen: Option<ScreeningReport>,
    scan: Option<[u8; 32]>,
    history_gap: bool,
}
impl HogZonePipeline {
    /// Move an empty, explicitly configured pipeline into one screened learned-model lane.
    /// This does not upgrade an unscreened trajectory or silently restart a live episode.
    pub fn new(
        pipeline: ImageZonePipeline,
        stream_generation: u64,
        budget: &mut WorkBudget<'_>,
    ) -> Result<Self, HogZoneError> {
        charge(budget, 1)?;
        if stream_generation == 0 || pipeline.tracker().exposure_count() != 0 {
            return Err(HogZoneError::BasisMismatch);
        }
        Ok(Self {
            pipeline,
            generation: stream_generation,
            last_screen: None,
            scan: None,
            history_gap: false,
        })
    }
    /// Immutable existing trajectory and zone reports, including accepted-but-pending state.
    pub fn pipeline(&self) -> &ImageZonePipeline {
        &self.pipeline
    }
    /// Exact complete scan backing the last accepted observation, even while zones are pending.
    pub fn scan_digest(&self) -> Option<[u8; 32]> {
        self.scan
    }
    /// Independent health report, never modified to acknowledge semantic completion.
    pub fn last_screening(&self) -> Option<&ScreeningReport> {
        self.last_screen.as_ref()
    }
    /// Whether this accepted frame encountered omitted screening history.
    pub fn health_history_gap(&self) -> bool {
        self.history_gap
    }
    /// Forward the next screening request's active-track analysis floor.
    pub fn requires_analysis(&self) -> bool {
        !self.pipeline.tracker().tracks().is_empty()
    }
    /// Finish only the accepted frame's outstanding zone computation.
    pub fn resume(
        &mut self,
        budget: &mut WorkBudget<'_>,
    ) -> Result<ZonePipelineProgress, HogZoneError> {
        Ok(self.pipeline.resume(budget)?)
    }
    /// Consume every selected learned proposal or refuse the complete frame at capacity.
    ///
    /// The scan retains all other margins, masked windows and suppression alternatives.
    /// Only an exact independent screen can admit measurements. Any health concern or
    /// missing history weakens availability. Missing foreground in that screen stays
    /// degraded; this lane does not reinterpret or clear another subsystem's findings.
    pub fn observe(
        &mut self,
        scan: &HogScan,
        screen: &ScreeningReport,
        budget: &mut WorkBudget<'_>,
    ) -> Result<ZonePipelineProgress, HogZoneError> {
        charge(budget, 1024)?;
        if self.pipeline.is_pending() {
            return Err(ZonePipelineError::PendingAnalysis.into());
        }
        if scan.source() != screen.source
            || scan.mask_digest() != screen.mask
            || screen.stamp.stream_generation != self.generation
            || self
                .last_screen
                .is_some_and(|old| old.policy != screen.policy)
        {
            return Err(HogZoneError::BasisMismatch);
        }
        let mut skipped = 0;
        let history_gap = if let Some(old) = self.last_screen {
            if screen.stamp.sequence <= old.stamp.sequence
                || screen.stamp.received_at_ns < old.stamp.received_at_ns
            {
                return Err(HogZoneError::OutOfOrder);
            }
            if screen.previous.is_none() {
                return Err(HogZoneError::BasisMismatch);
            }
            skipped = screen.stamp.sequence - old.stamp.sequence - 1;
            screen.previous != Some(old.digest()) || skipped != 0
        } else {
            screen.previous.is_some()
        };
        charge(budget, scan.windows().len() as u64 * 2)?;
        let count = scan.selected().count();
        if count > self.pipeline.tracker().policy().maximum_detections {
            return Err(ZonePipelineError::Tracking(ImageTrackingError::Limit).into());
        }
        let observable = scan.windows().iter().any(|w| w.margin.is_some());
        let availability = if !observable || screen.health == ScreeningHealth::NotObservable {
            TrackingAvailability::Unobservable
        } else if screen.health != ScreeningHealth::NoFaultObserved || history_gap {
            TrackingAvailability::Disturbed
        } else {
            TrackingAvailability::Available
        };
        let mut binding = [0_u8; 160];
        binding[..32].copy_from_slice(&scan.generation());
        binding[32..64].copy_from_slice(&screen.policy);
        binding[64..72].copy_from_slice(&self.generation.to_le_bytes());
        let tag = b"fss/screened-hog/measurement-generation/1\0";
        binding[72..72 + tag.len()].copy_from_slice(tag);
        let detector = ContentDigest::sha256(&binding).bytes();
        binding.fill(0);
        binding[..32].copy_from_slice(&scan.digest());
        binding[32..64].copy_from_slice(&screen.digest());
        binding[64..72].copy_from_slice(&skipped.to_le_bytes());
        binding[72] = u8::from(history_gap);
        let tag = b"fss/screened-hog/source/1\0";
        binding[73..73 + tag.len()].copy_from_slice(tag);
        let evidence = ContentDigest::sha256(&binding).bytes();
        let mut detections = Vec::new();
        detections.try_reserve_exact(count).map_err(|_| {
            HogZoneError::Pipeline(ZonePipelineError::Tracking(ImageTrackingError::Limit))
        })?;
        for window in scan.windows() {
            if window.disposition != WindowDisposition::Selected {
                continue;
            }
            charge(budget, 128)?;
            let mut record = [0_u8; 80];
            record[..32].copy_from_slice(&evidence);
            record[32..40].copy_from_slice(&window.id.to_le_bytes());
            let tag = b"fss/screened-hog/window/1\0";
            record[40..40 + tag.len()].copy_from_slice(tag);
            let partial = (0..2).any(|axis| {
                window.source_min[axis] == 0
                    || window.source_max[axis] == scan.source().image.dimensions[axis]
            });
            detections.push(ImageDetection {
                id: window.id,
                evidence: ContentDigest::sha256(&record).bytes(),
                min: window.source_min,
                max: window.source_max,
                partial,
            });
        }
        let frame = ImageTrackingFrame {
            source: scan.source(),
            detector,
            permission_mask: scan.mask_digest(),
            evidence,
            availability,
        };
        // The existing owner performs the only track mutation and retains pending zone work.
        // No fallible operation or allocation follows successful source consumption.
        let progress = self
            .pipeline
            .observe_detections(frame, &detections, budget)?;
        self.last_screen = Some(*screen);
        self.scan = Some(scan.digest());
        self.history_gap = history_gap;
        Ok(progress)
    }
}

/// Native JPEG source ownership and resumable learned-event processing.
pub mod jpeg;
