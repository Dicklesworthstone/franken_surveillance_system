#![forbid(unsafe_code)]
//! Exclusive borrowed temporal owner for JPEG -> neural detections -> tracks -> zones.
//! Completed stages are not repeated on downstream pressure. Complete results must
//! be taken before another exposure is admitted; retirement transfers unfinished inputs.

use fss_codec_mjpeg::DecodeBudget;
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_twin::image_tracking::{ExpiredImageTrack, ImageAssociationCandidate, ImageDetectionDecision,
    ImageTrack, ImageTrackingFrame, ImageTrackingReport};
use fss_twin::image_zones::{ImageZoneCell, ImageZoneError, ImageZoneEvent, ImageZoneReport};
use crate::ScalarExecCx;
use crate::ingest::rgb_detections::{RgbDetectionBudget, RgbDetectionContract, RgbDetectionError};
use crate::ingest::rgb_detections::pipeline::{PendingRgbDetection, RgbDetectionInput,
    RgbDetectionRun, RgbDetectionStep, RgbDetector, RgbDetectorError};
use crate::ingest::rgb_inference::{RgbInferenceModel, RgbRunLimits};
use super::{RgbFrameAdmission, RgbTrackingDecision, RgbTrackingError, RgbZoneProgress, RgbZoneTracker};

/// At most one complete set of bounded temporal records is copied for delivery.
pub const MAX_RGB_ZONE_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
/// Observable work state, distinct from custody, health, or effect success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RgbZonePhase {
    /// No owned frame; another input may be attempted.
    Ready,
    /// Actual neural output awaits head projection.
    Projection,
    /// Complete detector output awaits temporal assimilation.
    Tracking,
    /// Tracking committed; its exact zone derivation is pending.
    Zones,
    /// Zones committed; the complete owned output copy is pending.
    Snapshot,
    /// Complete output is held until the caller takes it.
    Complete,
}
/// Outer refusals do not discard already accepted source work.
#[derive(Debug)]
pub enum RgbJpegZoneError {
    /// Existing work must be resumed or explicitly retired.
    PendingFrame,
    /// Take the completed result before admitting another exposure.
    ResultNotTaken,
    /// There is no accepted work to resume.
    NoPendingFrame,
    /// The selected-class temporal owner belongs to another head contract.
    ContractMismatch,
    /// The availability declaration is not for the exact incoming source.
    AdmissionMismatch,
    /// The scalar owner requested cancellation; accepted work remains accessible.
    Cancelled,
    /// An impossible internal stage combination was encountered; nothing is reset.
    StageInvariant,
    /// The existing JPEG/inference owner refused the input or operation.
    Detector(RgbDetectorError),
}
impl From<RgbDetectorError> for RgbJpegZoneError {
    fn from(e: RgbDetectorError) -> Self { Self::Detector(e) }
}
impl std::fmt::Display for RgbJpegZoneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::PendingFrame => "RGB zone pipeline has unfinished source work",
            Self::ResultNotTaken => "take complete RGB zone result before next source",
            Self::NoPendingFrame => "no RGB zone source work to resume",
            Self::ContractMismatch => "RGB zone head and class owner mismatch",
            Self::AdmissionMismatch => "RGB zone admission belongs to another source",
            Self::Cancelled => "RGB zone owner cancelled",
            Self::StageInvariant => "RGB zone stage invariant failed",
            Self::Detector(_) => "RGB zone source or neural execution refused",
        })
    }
}
impl std::error::Error for RgbJpegZoneError {}
/// Progress after actual inference acceptance; Pending never requests a new JPEG.
#[derive(Debug)]
pub enum RgbJpegZoneProgress {
    /// Complete source-linked output is held by the owner, ready to take.
    Complete {
        /// Original neural inference identity.
        inference: ContentDigest,
        /// Complete source-space head projection.
        detections: ContentDigest,
        /// Exact accepted tracking receipt.
        tracking: [u8; 32],
        /// Exact accepted zone receipt.
        zones: [u8; 32],
    },
    /// Existing head projection refused; neural tensors and mask are retained.
    ProjectionPending(RgbDetectionError),
    /// No temporal state changed; full detector output is retained.
    TrackingPending(RgbTrackingError),
    /// Tracking already committed; resume only zone derivation.
    ZonesPending(ImageZoneError),
    /// Temporal stages completed; retry only the bounded owned-output copy.
    SnapshotPending(RgbTrackingError),
}

/// Complete owned temporal projection. The original unmodified owners remain the
/// semantic engines. Snapshot fields are read-only; their digests are not grants.
#[derive(Debug)]
pub struct RgbTemporalSnapshot {
    preparation: ContentDigest, selected_class: usize,
    tracking: [u8; 32], tracking_prior: [u8; 32], assignment_cost: u64,
    zones: [u8; 32], zones_prior: [u8; 32], zone_config: [u8; 32], frame: ImageTrackingFrame,
    rgb_decisions: Vec<RgbTrackingDecision>, tracks: Vec<ImageTrack>,
    candidates: Vec<ImageAssociationCandidate>, decisions: Vec<ImageDetectionDecision>,
    expired: Vec<ExpiredImageTrack>, cells: Vec<ImageZoneCell>, events: Vec<ImageZoneEvent>,
}
impl RgbTemporalSnapshot {
    /// Exact class/availability/coordinate-conversion receipt.
    pub fn preparation_digest(&self) -> ContentDigest { self.preparation }
    /// Frozen vocabulary index; retain the head contract to resolve its label.
    pub fn selected_class(&self) -> usize { self.selected_class }
    /// Complete current tracker result identity.
    pub fn tracking_digest(&self) -> [u8; 32] { self.tracking }
    /// Immediately preceding tracker receipt.
    pub fn tracking_prior(&self) -> [u8; 32] { self.tracking_prior }
    /// Existing assignment objective, not identity confidence.
    pub fn assignment_cost(&self) -> u64 { self.assignment_cost }
    /// Complete current zone result identity.
    pub fn zone_digest(&self) -> [u8; 32] { self.zones }
    /// Immediately preceding zone receipt.
    pub fn zone_prior(&self) -> [u8; 32] { self.zones_prior }
    /// Exact frozen zone configuration identity.
    pub fn zone_config_digest(&self) -> [u8; 32] { self.zone_config }
    /// Actual source and explicit assimilation availability.
    pub fn frame(&self) -> ImageTrackingFrame { self.frame }
    /// All selected- and other-class post-NMS outcomes.
    pub fn rgb_decisions(&self) -> &[RgbTrackingDecision] { &self.rgb_decisions }
    /// Complete active trajectory set, including coasting hypotheses.
    pub fn tracks(&self) -> &[ImageTrack] { &self.tracks }
    /// Every candidate edge, including excluded/unresolved alternatives.
    pub fn candidates(&self) -> &[ImageAssociationCandidate] { &self.candidates }
    /// Every selected-class proposal's assimilation outcome.
    pub fn decisions(&self) -> &[ImageDetectionDecision] { &self.decisions }
    /// All explicit trajectory retirements from this update.
    pub fn expired(&self) -> &[ExpiredImageTrack] { &self.expired }
    /// Every current/expired track-zone cell.
    pub fn cells(&self) -> &[ImageZoneCell] { &self.cells }
    /// Every observed transition, interruption and retirement with source endpoints.
    pub fn events(&self) -> &[ImageZoneEvent] { &self.events }
}
fn copy<T: Copy>(values: &[T]) -> Result<Vec<T>, RgbTrackingError> {
    let mut out = Vec::new(); out.try_reserve_exact(values.len()).map_err(|_| RgbTrackingError::Limit)?;
    out.extend_from_slice(values); Ok(out)
}
fn snapshot(owner: &RgbZoneTracker, budget: &mut WorkBudget<'_>) -> Result<RgbTemporalSnapshot, RgbTrackingError> {
    let p = owner.prepared().ok_or(RgbTrackingError::NoObservation)?;
    let t = owner.tracking_report().ok_or(RgbTrackingError::NoObservation)?;
    let z = owner.zone_report().ok_or(RgbTrackingError::PendingZones)?;
    let bytes = [std::mem::size_of_val(p.decisions()), std::mem::size_of_val(owner.tracker().tracks()),
        std::mem::size_of_val(t.candidates()), std::mem::size_of_val(t.decisions()),
        std::mem::size_of_val(t.expired()), std::mem::size_of_val(z.cells()), std::mem::size_of_val(z.events())]
        .into_iter().try_fold(std::mem::size_of::<RgbTemporalSnapshot>(), |n, b| n.checked_add(b).ok_or(RgbTrackingError::Limit))?;
    if bytes > MAX_RGB_ZONE_SNAPSHOT_BYTES { return Err(RgbTrackingError::Limit); }
    budget.charge(bytes as u64)?;
    let result = RgbTemporalSnapshot { preparation: p.digest(), selected_class: owner.contract().class_index(),
        tracking: t.digest(), tracking_prior: t.prior_digest(), assignment_cost: t.assignment_cost(),
        zones: z.digest(), zones_prior: z.prior_digest(), zone_config: z.config_digest(), frame: z.frame(),
        rgb_decisions: copy(p.decisions())?, tracks: copy(owner.tracker().tracks())?,
        candidates: copy(t.candidates())?, decisions: copy(t.decisions())?, expired: copy(t.expired())?,
        cells: copy(z.cells())?, events: copy(z.events())? };
    budget.charge(0)?; Ok(result)
}
/// Entire accepted source computation plus complete owned temporal records.
#[derive(Debug)]
pub struct RgbZoneCompletion { run: RgbDetectionRun, admission: RgbFrameAdmission, temporal: RgbTemporalSnapshot }
impl RgbZoneCompletion {
    /// Actual tensors, source, original mask and every detector decision.
    pub fn detection_run(&self) -> &RgbDetectionRun { &self.run }
    /// Original independent owner availability declaration.
    pub fn admission(&self) -> RgbFrameAdmission { self.admission }
    /// Complete owned temporal result, valid after the processor advances or is dropped.
    pub fn temporal(&self) -> &RgbTemporalSnapshot { &self.temporal }
    /// Transfer all stage evidence together; this does not assert disk custody.
    pub fn into_parts(self) -> (RgbDetectionRun, RgbFrameAdmission, RgbTemporalSnapshot) {
        (self.run, self.admission, self.temporal)
    }
}
/// Explicit retirement transfers every unfinished input; it never acknowledges
/// missing work. The separately owned temporal tracker may still need zone resume.
#[derive(Debug)]
pub struct RetiredRgbZoneWork {
    /// Last stage reached, not a success claim.
    pub phase: RgbZonePhase,
    /// Availability declaration for any accepted source.
    pub admission: Option<RgbFrameAdmission>,
    /// Actual tensors/mask when head projection is unfinished.
    pub inference: Option<PendingRgbDetection>,
    /// Complete detector input when temporal/snapshot work is unfinished.
    pub detections: Option<RgbDetectionRun>,
    /// A complete result not yet taken by the caller.
    pub complete: Option<RgbZoneCompletion>,
}

/// One frame of backpressure across every accepted stage. The borrowed tracker
/// cannot be advanced elsewhere until this owner is dropped or retired. No I/O,
/// hidden worker, timeout, policy reset, persistent checkpoint, or effect occurs.
pub struct RgbJpegZonePipeline<'model, 'temporal> {
    detector: RgbDetector<'model>, temporal: &'temporal mut RgbZoneTracker,
    phase: RgbZonePhase, admission: Option<RgbFrameAdmission>,
    current: Option<RgbDetectionRun>, complete: Option<RgbZoneCompletion>,
}
impl<'model, 'temporal> RgbJpegZonePipeline<'model, 'temporal> {
    /// Attach to the exact selected-class owner at its current completed position.
    /// Refusal leaves that owner unchanged, including any pending zone obligation.
    pub fn new(model: &'model RgbInferenceModel, head: &'model RgbDetectionContract,
        temporal: &'temporal mut RgbZoneTracker) -> Result<Self, RgbJpegZoneError> {
        if temporal.contract().head_digest() != head.digest() { return Err(RgbJpegZoneError::ContractMismatch); }
        if temporal.is_pending() { return Err(RgbJpegZoneError::PendingFrame); }
        Ok(Self { detector: RgbDetector::new(model, head)?, temporal, phase: RgbZonePhase::Ready,
            admission: None, current: None, complete: None })
    }
    /// Exact accepted-stage boundary; never infer it solely from an error string.
    pub fn phase(&self) -> RgbZonePhase { self.phase }
    /// Retained actual inference while head projection is unfinished.
    pub fn pending_inference(&self) -> Option<&PendingRgbDetection> { self.detector.pending() }
    /// Current complete detector result, including one awaiting temporal work.
    pub fn detection_run(&self) -> Option<&RgbDetectionRun> {
        self.current.as_ref().or_else(|| self.complete.as_ref().map(|c| &c.run))
    }
    /// Accepted current-frame tracking only, never its predecessor during inference.
    pub fn tracking_report(&self) -> Option<&ImageTrackingReport> {
        if matches!(self.phase, RgbZonePhase::Zones | RgbZonePhase::Snapshot | RgbZonePhase::Complete) {
            self.temporal.tracking_report()
        } else { None }
    }
    /// Accepted current-frame zones, including those awaiting the output copy.
    pub fn zone_report(&self) -> Option<&ImageZoneReport> {
        if matches!(self.phase, RgbZonePhase::Snapshot | RgbZonePhase::Complete) {
            self.temporal.zone_report()
        } else { None }
    }
    /// Complete owned result before explicit transfer to the caller.
    pub fn completed(&self) -> Option<&RgbZoneCompletion> { self.complete.as_ref() }
    /// Execute a new source only when no prior input/result is held. Decoder and
    /// scalar cancellation owners remain explicit; temporal work has its own budget.
    /// An inference error before acceptance leaves the temporal state untouched.
    #[allow(clippy::too_many_arguments)]
    pub fn run_jpeg(&mut self, input: RgbDetectionInput<'_>, admission: RgbFrameAdmission,
        limits: RgbRunLimits, decoder: &mut DecodeBudget<'_>, post: &mut RgbDetectionBudget,
        work: &mut WorkBudget<'_>, cx: &ScalarExecCx) -> Result<RgbJpegZoneProgress, RgbJpegZoneError> {
        match self.phase {
            RgbZonePhase::Ready => {},
            RgbZonePhase::Complete => return Err(RgbJpegZoneError::ResultNotTaken),
            _ => return Err(RgbJpegZoneError::PendingFrame),
        }
        if input.source != admission.source() { return Err(RgbJpegZoneError::AdmissionMismatch); }
        let step = self.detector.run_jpeg(input, limits, decoder, post, cx)?;
        self.admission = Some(admission);
        self.accept_detection_step(step, work, cx)
    }
    fn accept_detection_step(&mut self, step: RgbDetectionStep, work: &mut WorkBudget<'_>, cx: &ScalarExecCx)
        -> Result<RgbJpegZoneProgress, RgbJpegZoneError> {
        match step {
            RgbDetectionStep::Pending(error) => {
                self.phase = RgbZonePhase::Projection; Ok(RgbJpegZoneProgress::ProjectionPending(error))
            }
            RgbDetectionStep::Complete(run) => {
                self.current = Some(run); self.phase = RgbZonePhase::Tracking; self.advance(work, cx)
            }
        }
    }
    /// Retry only the unfinished stage. This signature accepts no JPEG, replacement
    /// source, mask, model, or admission: completed work cannot be reinterpreted.
    pub fn resume(&mut self, post: &mut RgbDetectionBudget, work: &mut WorkBudget<'_>, cx: &ScalarExecCx)
        -> Result<RgbJpegZoneProgress, RgbJpegZoneError> {
        match self.phase {
            RgbZonePhase::Ready => Err(RgbJpegZoneError::NoPendingFrame),
            RgbZonePhase::Complete => self.complete_progress(),
            RgbZonePhase::Projection => {
                let step = self.detector.resume(post, cx)?; self.accept_detection_step(step, work, cx)
            }
            _ => self.advance(work, cx),
        }
    }
    fn advance(&mut self, work: &mut WorkBudget<'_>, cx: &ScalarExecCx)
        -> Result<RgbJpegZoneProgress, RgbJpegZoneError> {
        cx.checkpoint("rgb-zones:advance").map_err(|_| RgbJpegZoneError::Cancelled)?;
        let progress = match self.phase {
            RgbZonePhase::Tracking => {
                let run = self.current.as_ref().ok_or(RgbJpegZoneError::StageInvariant)?;
                let admission = self.admission.ok_or(RgbJpegZoneError::StageInvariant)?;
                match self.temporal.observe(run.inference(), run.report(), admission, work) {
                    Ok(progress) => Some(progress),
                    Err(error) => return Ok(RgbJpegZoneProgress::TrackingPending(error)),
                }
            }
            RgbZonePhase::Zones => Some(self.temporal.resume(work).map_err(|_| RgbJpegZoneError::StageInvariant)?),
            RgbZonePhase::Snapshot => None,
            _ => return Err(RgbJpegZoneError::StageInvariant),
        };
        if let Some(progress) = progress {
            match progress {
                RgbZoneProgress::Pending { error, .. } => {
                    self.phase = RgbZonePhase::Zones; return Ok(RgbJpegZoneProgress::ZonesPending(error));
                }
                RgbZoneProgress::Complete { .. } => self.phase = RgbZonePhase::Snapshot,
            }
        }
        let temporal = match snapshot(self.temporal, work) {
            Ok(value) => value,
            Err(error) => return Ok(RgbJpegZoneProgress::SnapshotPending(error)),
        };
        // Both caller cancellation owners are polled before ownership transfer.
        cx.checkpoint("rgb-zones:complete").map_err(|_| RgbJpegZoneError::Cancelled)?;
        // Every fallible allocation and final work poll precedes ownership transfer.
        let admission = self.admission.ok_or(RgbJpegZoneError::StageInvariant)?;
        let run = self.current.take().ok_or(RgbJpegZoneError::StageInvariant)?;
        self.complete = Some(RgbZoneCompletion { run, admission, temporal });
        self.phase = RgbZonePhase::Complete;
        self.complete_progress()
    }
    fn complete_progress(&self) -> Result<RgbJpegZoneProgress, RgbJpegZoneError> {
        let c = self.complete.as_ref().ok_or(RgbJpegZoneError::StageInvariant)?;
        Ok(RgbJpegZoneProgress::Complete { inference: c.run.inference().identity(), detections: c.run.report().digest(),
            tracking: c.temporal.tracking, zones: c.temporal.zones })
    }
    /// Transfer the whole result before the next exposure can overwrite any report.
    /// None leaves unfinished stages intact. Transfer does not certify durable custody.
    pub fn take_complete(&mut self) -> Option<RgbZoneCompletion> {
        if self.phase != RgbZonePhase::Complete { return None; }
        let result = self.complete.take()?;
        self.admission = None; self.phase = RgbZonePhase::Ready; Some(result)
    }
    /// End this processor without silently dropping unfinished inputs. The borrowed
    /// temporal owner is released and retains its accepted state/pending zone work.
    #[must_use]
    pub fn retire(self) -> RetiredRgbZoneWork {
        RetiredRgbZoneWork { phase: self.phase, admission: self.admission, inference: self.detector.retire(),
            detections: self.current, complete: self.complete }
    }
}
