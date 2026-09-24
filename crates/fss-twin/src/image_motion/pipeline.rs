#![forbid(unsafe_code)]
//! Actual luma/JPEG -> foreground -> anonymous trajectories -> conditional motion.
//!
//! Decoding and foreground failures precede any tracker mutation. Tracking and
//! optional motion are separate, retained outcomes: a motion-budget refusal does
//! not roll back an accepted observation or ask the caller to ingest it twice.
//! No model labels, physical identity, ground contact, or absence are inferred.

use super::{ImageMotionError, ImageMotionPolicy, ImageMotionReport, estimate_image_motion};
use crate::foreground::pipeline::{
    ForegroundPipelineError, FrameCapture, RectifiedBackground, RectifiedForeground,
};
use crate::foreground::{ForegroundPolicy, ForegroundReport};
use crate::image_tracking::{ImageTracker, ImageTrackingError, ImageTrackingReport};
use crate::mjpeg::{JpegBackground, JpegForeground, JpegFrameBinding, JpegPipelineError};
use crate::rectification::{RawGrayFrame, RectificationPlan};
use fss_codec_mjpeg::{DecodeBudget, DecodeLimits};
use fss_geometry::WorkBudget;

/// Exact stage boundary. A Tracked result has consumed the exposure even when
/// its optional motion result is an error. Do not retry that exposure's tracking.
// Keep the committed receipt inline: returning it must not allocate after commit.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum MotionPipelineOutcome {
    /// Preparation or tracking failed; the tracker's state and receipt did not change.
    TrackingFailed(ImageTrackingError),
    /// The tracker accepted the source; its receipt survives every motion failure.
    Tracked {
        /// Accepted tracking receipt, retaining all candidates, decisions and retirements.
        tracking: ImageTrackingReport,
        /// Complete conditional motion view or an explicit optional-stage refusal.
        motion: Result<ImageMotionReport, ImageMotionError>,
    },
}

/// Coupled foreground identity and explicit tracking/motion completion state.
#[derive(Debug)]
pub struct ForegroundMotionAnalysis {
    foreground: [u8; 32],
    outcome: MotionPipelineOutcome,
}
impl ForegroundMotionAnalysis {
    /// Exact complete foreground report, including small components and availability.
    pub fn foreground_digest(&self) -> [u8; 32] {
        self.foreground
    }
    /// Inspect whether tracking committed before deciding which stage can be retried.
    pub fn outcome(&self) -> &MotionPipelineOutcome {
        &self.outcome
    }
    /// Transfer the complete stage results without discarding an accepted receipt.
    pub fn into_outcome(self) -> MotionPipelineOutcome {
        self.outcome
    }
}

/// Convert a real, opaque ForegroundReport and advance the existing tracker.
///
/// Every region is retained; count overflow refuses instead of top-k selection.
/// The detector identity binds the frozen background and the entire foreground
/// policy. Unknown/edge silhouettes remain partial, and scene-wide changes remain
/// disturbed rather than becoming confident trajectories. The permission mask and
/// original capture/calibration/image identities are unchanged.
///
/// If motion fails after tracking succeeds, retain the returned tracking receipt.
/// Retry only estimate_image_motion with that receipt, the unchanged tracker and
/// a fresh budget. Advancing the tracker makes that old motion request stale.
#[must_use]
pub fn track_foreground_motion(
    tracker: &mut ImageTracker,
    foreground: &ForegroundReport,
    policy: ImageMotionPolicy,
    budget: &mut WorkBudget<'_>,
) -> ForegroundMotionAnalysis {
    let tracked = tracker.update_foreground(foreground, budget);
    let outcome = match tracked {
        Ok(tracking) => {
            let motion = estimate_image_motion(tracker, &tracking, policy, budget);
            MotionPipelineOutcome::Tracked { tracking, motion }
        }
        Err(error) => MotionPipelineOutcome::TrackingFailed(error),
    };
    ForegroundMotionAnalysis {
        foreground: foreground.digest(),
        outcome,
    }
}

/// Owner-framed encoded JPEG and original source/capture/permission declarations.
#[derive(Clone, Copy)]
pub struct JpegMotionInput<'a> {
    /// Complete compressed frame; not a URL or executable model/runtime input.
    pub bytes: &'a [u8],
    /// Exact coded-grid permission mask, bound by source.allowed_mask.
    pub allowed: &'a [u8],
    /// Original encoded-source, decoder interpretation and calibration bindings.
    pub source: JpegFrameBinding,
    /// Actual owner-provided capture interval, never inferred from processing time.
    pub capture: FrameCapture,
}
/// Native decoder/rectifier/foreground output plus all downstream stage outcomes.
pub struct JpegMotionReport {
    foreground: JpegForeground,
    analysis: ForegroundMotionAnalysis,
}
impl JpegMotionReport {
    /// Original encoded/decoded receipts, actual pixels, masks and complete regions.
    pub fn foreground(&self) -> &JpegForeground {
        &self.foreground
    }
    /// Tracking completion and optional motion, including refusals after decode.
    pub fn analysis(&self) -> &ForegroundMotionAnalysis {
        &self.analysis
    }
    /// Transfer all source and stage ownership without losing a refused analysis input.
    pub fn into_parts(self) -> (JpegForeground, ForegroundMotionAnalysis) {
        (self.foreground, self.analysis)
    }
}

/// Execute native JPEG decoding and the actual foreground/trajectory/motion chain.
/// An outer error means decoding/foreground failed before any tracker mutation.
/// An outer success retains the image even when tracking or motion was refused.
#[allow(clippy::too_many_arguments)]
pub fn analyze_jpeg_motion(
    tracker: &mut ImageTracker,
    background: &JpegBackground,
    plan: &RectificationPlan,
    input: JpegMotionInput<'_>,
    foreground_policy: ForegroundPolicy,
    motion_policy: ImageMotionPolicy,
    limits: DecodeLimits,
    decoder: &mut DecodeBudget<'_>,
    geometry: &mut WorkBudget<'_>,
) -> Result<JpegMotionReport, JpegPipelineError> {
    let foreground = background.detect(
        plan,
        input.bytes,
        input.allowed,
        input.source,
        input.capture,
        foreground_policy,
        limits,
        decoder,
        geometry,
    )?;
    let analysis = track_foreground_motion(
        tracker,
        foreground.analysis().report(),
        motion_policy,
        geometry,
    );
    Ok(JpegMotionReport {
        foreground,
        analysis,
    })
}

/// Actual raw-plane/rectification/foreground output plus all downstream outcomes.
pub struct LumaMotionReport {
    foreground: RectifiedForeground,
    analysis: ForegroundMotionAnalysis,
}
impl LumaMotionReport {
    /// Unmodified source-linked pixels, masks, rectification receipt and foreground.
    pub fn foreground(&self) -> &RectifiedForeground {
        &self.foreground
    }
    /// Explicit tracking completion and optional motion outcome.
    pub fn analysis(&self) -> &ForegroundMotionAnalysis {
        &self.analysis
    }
    /// Transfer the actual image and every stage result together.
    pub fn into_parts(self) -> (RectifiedForeground, ForegroundMotionAnalysis) {
        (self.foreground, self.analysis)
    }
}
/// Execute the same chain for an already validated raw luma plane.
/// Outer errors precede tracking; successful results retain downstream refusals.
#[allow(clippy::too_many_arguments)]
pub fn analyze_luma_motion(
    tracker: &mut ImageTracker,
    background: &RectifiedBackground,
    plan: &RectificationPlan,
    raw: &RawGrayFrame<'_>,
    capture: FrameCapture,
    foreground_policy: ForegroundPolicy,
    motion_policy: ImageMotionPolicy,
    budget: &mut WorkBudget<'_>,
) -> Result<LumaMotionReport, ForegroundPipelineError> {
    let foreground = background.detect_luma(plan, raw, capture, foreground_policy, budget)?;
    let analysis = track_foreground_motion(tracker, foreground.report(), motion_policy, budget);
    Ok(LumaMotionReport {
        foreground,
        analysis,
    })
}
