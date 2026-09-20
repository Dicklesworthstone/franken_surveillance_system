#![forbid(unsafe_code)]
//! Health-gated continuity from actual foreground, JPEG and framed MJPEG evidence.
//!
//! Health and trajectory state have separate ownership and work budgets. Screening
//! remains useful when tracking refuses an input. A failed tracking call changes no
//! track, sequence or receipt state and may be retried against the immutable screen.
//! These cheap proposals do NOT acknowledge semantic analysis or authorize effects.

use super::{ScreeningHealth, ScreeningReport};
use crate::foreground::{ForegroundError, ForegroundReport};
use crate::foreground_tracking::foreground_input;
use crate::image_tracking::{ImageTracker, ImageTrackingError, ImageTrackingPolicy,
    ImageTrackingReport, TrackingAvailability};
use crate::mjpeg::stream::StreamFrameReceipt;
use crate::screened_mjpeg::{ForegroundStage, FramedScreenedJpeg, ScreenedJpeg};
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;

/// A tracking refusal never erases the independently retained health/source report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScreenedTrackingError {
    /// Screen, foreground, stream, lane or screening-policy identities disagree.
    BasisMismatch,
    /// An original sequence was reused/regressed or its receive clock regressed.
    OutOfOrder,
    /// The caller did not provide an admitted frozen-background model.
    NotConfigured,
    /// The foreground stage refused; this is not an empty successful comparison.
    Foreground(ForegroundError),
    /// Complete-output, capture, exposure, numeric, work or cancellation refusal.
    Tracking(ImageTrackingError),
}
impl From<ImageTrackingError> for ScreenedTrackingError {
    fn from(error: ImageTrackingError) -> Self { Self::Tracking(error) }
}
impl std::fmt::Display for ScreenedTrackingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BasisMismatch => "screened tracking basis mismatch",
            Self::OutOfOrder => "screened tracking input did not advance",
            Self::NotConfigured => "screened tracking background not configured",
            Self::Foreground(_) => "screened tracking foreground refused",
            Self::Tracking(_) => "screened tracking update refused",
        })
    }
}
impl std::error::Error for ScreenedTrackingError {}

/// One successful compound update, retaining every proposal and health restriction.
#[derive(Debug)]
pub struct ScreenedTrackingReport {
    digest: [u8; 32], prior: [u8; 32], input: [u8; 32],
    screen: ScreeningReport, stream: Option<StreamFrameReceipt>,
    tracking: ImageTrackingReport, skipped: u64, history_gap: bool, work_units: u64,
}
impl ScreenedTrackingReport {
    /// Local, history-linked derivation fingerprint, not a canonical ledger publication.
    pub fn digest(&self) -> [u8; 32] { self.digest }
    /// Previous compound result, or the initial episode root for the first update.
    pub fn prior_digest(&self) -> [u8; 32] { self.prior }
    /// Exact screen, screened JPEG or framed screened JPEG consumed by this lane.
    pub fn input_digest(&self) -> [u8; 32] { self.input }
    /// Original independent health and semantic-admission result; no acknowledgement added.
    pub fn screening(&self) -> &ScreeningReport { &self.screen }
    /// Original stream source, generation, ordinal and byte range when framed input was used.
    pub fn stream(&self) -> Option<StreamFrameReceipt> { self.stream }
    /// Full existing assignment report, including unavailable and unresolved proposals.
    pub fn tracking(&self) -> &ImageTrackingReport { &self.tracking }
    /// Original ordinals omitted since the last successful tracking update.
    pub fn skipped_sequences(&self) -> u64 { self.skipped }
    /// Screening advanced without this tracker, or the previous screen is unavailable.
    /// This frame cannot assimilate measurements across that discontinuity.
    pub fn health_history_gap(&self) -> bool { self.history_gap }
    /// Deterministic tracking work actually charged, excluding prior decode/health work.
    pub fn work_units(&self) -> u64 { self.work_units }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lane { Foreground, Jpeg, Framed([u8; 32]) }
impl Lane {
    fn identity(self) -> [u8; 33] {
        let mut bytes = [0; 33];
        match self {
            Self::Foreground => {}, Self::Jpeg => bytes[0] = 1,
            Self::Framed(source) => { bytes[0] = 2; bytes[1..].copy_from_slice(&source); }
        }
        bytes
    }
}

/// Explicitly owned bounded episode over one original stream generation and input lane.
/// No underlying mutable tracker is exposed, so callers cannot bypass health admission
/// and then present that state as screened. A restart/change needs a fresh episode.
#[derive(Debug)]
pub struct ScreenedImageTracker {
    tracker: ImageTracker, generation: u64, digest: [u8; 32],
    last: Option<ScreeningReport>, lane: Option<Lane>,
}
impl ScreenedImageTracker {
    /// Begin a replayable episode. Neither ID nor policy authenticates a physical sensor.
    pub fn new(episode: [u8; 32], stream_generation: u64, policy: ImageTrackingPolicy,
        budget: &mut WorkBudget<'_>) -> Result<Self, ScreenedTrackingError> {
        budget.charge(256).map_err(ImageTrackingError::from)?;
        if stream_generation == 0 { return Err(ScreenedTrackingError::BasisMismatch); }
        let tracker = ImageTracker::new(episode, policy, budget)?;
        let mut bytes = [0; 80];
        bytes[..32].copy_from_slice(&tracker.digest());
        bytes[32..40].copy_from_slice(&stream_generation.to_le_bytes());
        let tag = b"fss/screened-image-tracker/episode/v1\0";
        bytes[40..40 + tag.len()].copy_from_slice(tag);
        let digest = ContentDigest::sha256(&bytes).bytes();
        budget.charge(0).map_err(ImageTrackingError::from)?;
        Ok(Self { tracker, generation: stream_generation, digest, last: None, lane: None })
    }
    /// Read-only underlying state, also usable with source-linked image-motion estimators.
    pub fn tracker(&self) -> &ImageTracker { &self.tracker }
    /// Current compound receipt head, unchanged by every failed call.
    pub fn digest(&self) -> [u8; 32] { self.digest }
    /// Set ScreeningStamp.owner_requests_analysis before screening the NEXT input.
    /// Active/coasting tracks must not silently lose the owner's semantic-analysis floor.
    pub fn requires_analysis(&self) -> bool { !self.tracker.tracks().is_empty() }
    /// Last successfully consumed screen; the health monitor may legitimately be ahead.
    pub fn last_screening(&self) -> Option<&ScreeningReport> { self.last.as_ref() }
    /// Consume independently derived, exactly paired luma foreground and health reports.
    pub fn update_foreground(&mut self, foreground: &ForegroundReport, screen: &ScreeningReport,
        budget: &mut WorkBudget<'_>) -> Result<ScreenedTrackingReport, ScreenedTrackingError> {
        self.update_inner(foreground, screen, screen.digest(), Lane::Foreground, None, budget)
    }
    /// Connect the actual native decode/rectification/foreground/screening pipeline.
    /// This never acknowledges the monitor's pending semantic analysis.
    pub fn update_jpeg(&mut self, input: &ScreenedJpeg, budget: &mut WorkBudget<'_>)
        -> Result<ScreenedTrackingReport, ScreenedTrackingError> {
        budget.charge(0).map_err(ImageTrackingError::from)?;
        let foreground = complete(input)?;
        self.update_inner(foreground, input.screening(), input.digest(), Lane::Jpeg, None, budget)
    }
    /// Preserve source byte offsets and original stream identity through trajectory updates.
    pub fn update_framed_jpeg(&mut self, input: &FramedScreenedJpeg, budget: &mut WorkBudget<'_>)
        -> Result<ScreenedTrackingReport, ScreenedTrackingError> {
        budget.charge(0).map_err(ImageTrackingError::from)?;
        let source = input.source(); let screen = input.result().screening();
        if source.basis.generation != self.generation || source.ordinal != screen.stamp.sequence {
            return Err(ScreenedTrackingError::BasisMismatch);
        }
        let foreground = complete(input.result())?;
        self.update_inner(foreground, screen, input.digest(), Lane::Framed(source.basis.source),
            Some(source), budget)
    }
    #[allow(clippy::too_many_arguments)]
    fn update_inner(&mut self, foreground: &ForegroundReport, screen: &ScreeningReport,
        input: [u8; 32], lane: Lane, stream: Option<StreamFrameReceipt>, budget: &mut WorkBudget<'_>)
        -> Result<ScreenedTrackingReport, ScreenedTrackingError> {
        let before = budget.used();
        // Fixed hashes and receipt construction are paid before the engine can commit.
        budget.charge(1024).map_err(ImageTrackingError::from)?;
        if screen.source != foreground.source() || screen.mask != foreground.mask_digest()
            || screen.foreground != Some(foreground.digest())
            || screen.stamp.stream_generation != self.generation
            || self.lane.is_some_and(|old| old != lane)
            || self.last.is_some_and(|old| old.policy != screen.policy) {
            return Err(ScreenedTrackingError::BasisMismatch);
        }
        let mut skipped = 0;
        let history_gap = if let Some(old) = self.last {
            if screen.stamp.sequence <= old.stamp.sequence || screen.stamp.received_at_ns < old.stamp.received_at_ns {
                return Err(ScreenedTrackingError::OutOfOrder);
            }
            // A new monitor must not silently reuse an existing tracking episode.
            if screen.previous.is_none() { return Err(ScreenedTrackingError::BasisMismatch); }
            skipped = screen.stamp.sequence - old.stamp.sequence - 1;
            screen.previous != Some(old.digest()) || skipped != 0
        } else { screen.previous.is_some() };
        let (mut frame, detections) = foreground_input(foreground, self.tracker.policy().maximum_detections, budget)?;
        let mut basis = [0; 128];
        basis[..32].copy_from_slice(&frame.detector);
        basis[32..64].copy_from_slice(&screen.policy);
        basis[64..72].copy_from_slice(&self.generation.to_le_bytes());
        basis[72..105].copy_from_slice(&lane.identity());
        let tag = b"fss/screened-basis/v1\0";
        basis[105..105 + tag.len()].copy_from_slice(tag);
        frame.detector = ContentDigest::sha256(&basis).bytes();
        frame.evidence = input;
        // Availability can only weaken foreground findings, never clear a disturbance.
        if screen.health == ScreeningHealth::NotObservable {
            frame.availability = TrackingAvailability::Unobservable;
        } else if (screen.health != ScreeningHealth::NoFaultObserved || history_gap)
            && frame.availability == TrackingAvailability::Available {
            frame.availability = TrackingAvailability::Disturbed;
        }
        let mut bytes = [0; 256];
        bytes[..32].copy_from_slice(&self.digest);
        bytes[32..64].copy_from_slice(&input);
        bytes[64..96].copy_from_slice(&screen.digest());
        bytes[128..136].copy_from_slice(&skipped.to_le_bytes());
        bytes[136] = u8::from(history_gap);
        let tag = b"fss/screened-tracking/receipt/1\0";
        bytes[145..145 + tag.len()].copy_from_slice(tag);
        // This is the only mutation-bearing fallible call. Nothing after it allocates,
        // polls cancellation or can return an error leaving hidden tracker credit.
        let tracking = self.tracker.update(frame, &detections, budget)?;
        let work_units = budget.used() - before;
        bytes[96..128].copy_from_slice(&tracking.digest());
        bytes[137..145].copy_from_slice(&work_units.to_le_bytes());
        let digest = ContentDigest::sha256(&bytes).bytes();
        let result = ScreenedTrackingReport { digest, prior: self.digest, input, screen: *screen,
            stream, tracking, skipped, history_gap, work_units };
        self.digest = digest; self.last = Some(*screen); self.lane = Some(lane);
        Ok(result)
    }
}
fn complete(input: &ScreenedJpeg) -> Result<&ForegroundReport, ScreenedTrackingError> {
    match input.foreground() {
        ForegroundStage::Complete(report) => Ok(report),
        ForegroundStage::Refused(error) => Err(ScreenedTrackingError::Foreground(error)),
        ForegroundStage::NotConfigured => Err(ScreenedTrackingError::NotConfigured),
    }
}
