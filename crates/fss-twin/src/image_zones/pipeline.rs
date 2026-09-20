#![forbid(unsafe_code)]
//! Native foreground/JPEG/luma -> trajectories -> zone observations with resumable
//! stage completion. A zone-budget refusal retains the consumed tracking receipt
//! and prevents the next exposure from hiding that unfinished derivation.
use super::{ImageZoneBasis, ImageZoneError, ImageZoneMonitor, ImageZonePolicy,
    ImageZoneReport, ImageZoneSpec};
use crate::foreground::{ForegroundPolicy, ForegroundReport};
use crate::foreground::pipeline::{FrameCapture, ForegroundPipelineError, RectifiedBackground,
    RectifiedForeground};
use crate::image_tracking::{ImageTracker, ImageTrackingError, ImageTrackingPolicy, ImageTrackingReport};
use crate::mjpeg::{JpegBackground, JpegForeground, JpegFrameBinding, JpegPipelineError};
use crate::rectification::{RawGrayFrame, RectificationPlan};
use fss_codec_mjpeg::{DecodeBudget, DecodeLimits};
use fss_geometry::WorkBudget;

/// Outer failures occur before a new tracking observation is accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZonePipelineError {
    /// An accepted tracking observation still needs its zone stage resumed.
    PendingAnalysis,
    /// There is no accepted observation to resume yet.
    NoObservation,
    /// Invalid zone configuration, source basis or zone-stage input.
    Zones(ImageZoneError),
    /// Tracking refused before changing its state.
    Tracking(ImageTrackingError),
}
impl std::fmt::Display for ZonePipelineError {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::PendingAnalysis => "resume pending image-zone analysis before the next exposure",
            Self::NoObservation => "no image-zone observation has been accepted",
            Self::Zones(_) => "image-zone configuration or source refused",
            Self::Tracking(_) => "image-zone upstream tracking refused",
        })
    }
}
impl std::error::Error for ZonePipelineError {}
/// Both cases mean tracking already consumed this exposure. Never re-ingest it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZonePipelineProgress {
    /// Tracking and zone derivation both completed; full reports remain accessible.
    Complete {
        /// Exact accepted trajectory receipt.
        tracking: [u8;32],
        /// Exact complete zone result.
        zones: [u8;32],
    },
    /// Tracking completed but zone derivation did not. Call resume, not observe.
    Pending {
        /// Retained accepted receipt; it cannot be overwritten while pending.
        tracking: [u8;32],
        /// Typed refusal; spent work remains charged.
        error: ImageZoneError,
    },
}
/// Exclusive owner of tracking and its gap-free zone projection. Neither stage
/// performs source acquisition, publication, network effects or wall-clock reads.
pub struct ImageZonePipeline {
    tracker: ImageTracker,
    monitor: ImageZoneMonitor,
    tracking: Option<ImageTrackingReport>,
    foreground: Option<[u8;32]>,
    pending: bool,
}
impl ImageZonePipeline {
    /// Begin a new explicit episode with frozen tracking/zone assumptions.
    pub fn new(episode:[u8;32], tracking:ImageTrackingPolicy, basis:ImageZoneBasis,
        policy:ImageZonePolicy, zones:&[ImageZoneSpec], budget:&mut WorkBudget<'_>)
        -> Result<Self,ZonePipelineError> {
        let tracker = ImageTracker::new(episode,tracking,budget).map_err(ZonePipelineError::Tracking)?;
        let monitor = ImageZoneMonitor::new(&tracker,basis,policy,zones,budget).map_err(ZonePipelineError::Zones)?;
        Ok(Self { tracker,monitor,tracking:None,foreground:None,pending:false })
    }
    /// Current immutable tracker for optional motion estimation, never mutable access.
    pub fn tracker(&self) -> &ImageTracker { &self.tracker }
    /// Accepted source receipt, including one awaiting zone derivation.
    pub fn tracking_report(&self) -> Option<&ImageTrackingReport> { self.tracking.as_ref() }
    /// Complete zone result for the accepted source only; never a stale predecessor.
    pub fn zone_report(&self) -> Option<&ImageZoneReport> {
        if self.pending { None } else { self.monitor.latest() }
    }
    /// Exact foreground input bound to the retained tracking receipt.
    pub fn foreground_digest(&self) -> Option<[u8;32]> { self.foreground }
    /// Whether new source assimilation is blocked until the zone stage completes.
    pub fn is_pending(&self) -> bool { self.pending }

    /// Advance from an opaque actual-pixel foreground report. Outer errors precede
    /// tracking mutation; Pending is successful source consumption, not a retry hint.
    pub fn observe_foreground(&mut self, foreground:&ForegroundReport,
        budget:&mut WorkBudget<'_>) -> Result<ZonePipelineProgress,ZonePipelineError> {
        if self.pending { return Err(ZonePipelineError::PendingAnalysis); }
        let s = foreground.source(); let basis = self.monitor.basis();
        if s.camera != basis.camera || s.clock != basis.clock || s.calibration != basis.calibration
            || s.image.image_domain != basis.image_domain || s.image.dimensions != basis.dimensions {
            return Err(ZonePipelineError::Zones(ImageZoneError::BasisMismatch));
        }
        let report = self.tracker.update_foreground(foreground,budget).map_err(ZonePipelineError::Tracking)?;
        self.tracking = Some(report); self.foreground = Some(foreground.digest()); self.pending = true;
        self.resume(budget)
    }
    /// Retry only the unfinished zone derivation without consuming a second exposure.
    /// Cancellation/exhaustion keeps the exact upstream receipt and blocks advancement.
    pub fn resume(&mut self,budget:&mut WorkBudget<'_>) -> Result<ZonePipelineProgress,ZonePipelineError> {
        let tracking = self.tracking.as_ref().ok_or(ZonePipelineError::NoObservation)?;
        if !self.pending {
            let zones = self.monitor.latest().ok_or(ZonePipelineError::NoObservation)?;
            return Ok(ZonePipelineProgress::Complete { tracking:tracking.digest(),zones:zones.digest() });
        }
        match self.monitor.observe(&self.tracker,tracking,budget) {
            Ok(zones) => {
                self.pending = false;
                Ok(ZonePipelineProgress::Complete { tracking:tracking.digest(),zones:zones.digest() })
            }
            Err(error) => Ok(ZonePipelineProgress::Pending { tracking:tracking.digest(),error }),
        }
    }

    /// Native luma rectification/foreground and zone processing. The returned image
    /// survives downstream refusals. An outer image error precedes tracking mutation.
    pub fn analyze_luma(&mut self, background:&RectifiedBackground, plan:&RectificationPlan,
        raw:&RawGrayFrame<'_>, capture:FrameCapture, policy:ForegroundPolicy,
        budget:&mut WorkBudget<'_>) -> Result<LumaZoneAnalysis,ForegroundPipelineError> {
        let foreground = background.detect_luma(plan,raw,capture,policy,budget)?;
        let progress = self.observe_foreground(foreground.report(),budget);
        Ok(LumaZoneAnalysis { foreground,progress })
    }
    /// Native JPEG decode/rectification/foreground and zone processing. No codec,
    /// source identity, permission mask or accepted receipt is replaced by a mock.
    pub fn analyze_jpeg(&mut self, background:&JpegBackground, plan:&RectificationPlan,
        input:JpegZoneInput<'_>, policy:ForegroundPolicy, decoder:&mut DecodeBudget<'_>,
        budget:&mut WorkBudget<'_>) -> Result<JpegZoneAnalysis,JpegPipelineError> {
        let foreground = background.detect(plan,input.bytes,input.allowed,input.source,
            input.capture,policy,input.limits,decoder,budget)?;
        let progress = self.observe_foreground(foreground.analysis().report(),budget);
        Ok(JpegZoneAnalysis { foreground,progress })
    }
}
/// Exact authorized encoded input, source basis and bounded decoder profile.
#[derive(Clone, Copy)]
pub struct JpegZoneInput<'a> {
    /// Complete encoded JPEG frame, not a URL.
    pub bytes:&'a [u8],
    /// Coded-grid permission mask; zero pixels remain disallowed.
    pub allowed:&'a [u8],
    /// Original encoded-source/calibration/decoder interpretation binding.
    pub source:JpegFrameBinding,
    /// Actual camera/capture interval on the supplied clock.
    pub capture:FrameCapture,
    /// Explicit existing JPEG limits, never a fallback codec.
    pub limits:DecodeLimits,
}
/// Retained source-linked luma plus an explicit downstream stage result.
pub struct LumaZoneAnalysis {
    foreground:RectifiedForeground,progress:Result<ZonePipelineProgress,ZonePipelineError>,
}
impl LumaZoneAnalysis {
    /// Actual rectified pixels, mask, source receipt and region report.
    pub fn foreground(&self) -> &RectifiedForeground { &self.foreground }
    /// Outer Err here means tracking did not consume this image.
    pub fn progress(&self) -> Result<ZonePipelineProgress,ZonePipelineError> { self.progress }
    /// Transfer source evidence and stage result together.
    pub fn into_parts(self) -> (RectifiedForeground,Result<ZonePipelineProgress,ZonePipelineError>) {
        (self.foreground,self.progress)
    }
}
/// Retained encoded/decoded lineage, actual pixels and downstream stage result.
pub struct JpegZoneAnalysis {
    foreground:JpegForeground,progress:Result<ZonePipelineProgress,ZonePipelineError>,
}
impl JpegZoneAnalysis {
    /// Native JPEG/rectification receipts and complete foreground output.
    pub fn foreground(&self) -> &JpegForeground { &self.foreground }
    /// Complete versus source-consumed/pending versus not-consumed failure.
    pub fn progress(&self) -> Result<ZonePipelineProgress,ZonePipelineError> { self.progress }
    /// Transfer decoded evidence even after downstream resource refusal.
    pub fn into_parts(self) -> (JpegForeground,Result<ZonePipelineProgress,ZonePipelineError>) {
        (self.foreground,self.progress)
    }
}
