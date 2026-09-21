#![forbid(unsafe_code)]
//! Actual RGB detections -> existing anonymous image tracker -> observed image zones.
//!
//! One explicitly selected model class is tracked per owner. Other classes remain
//! visible in the preparation receipt and original report, not silently top-k cut.
//! Availability is an evidence-linked owner declaration, NOT a model health finding.
//! Coordinates remain on the original coded RGB grid; no rectification is invented.

use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_geometry::{GeometryError, WorkBudget};
use fss_twin::foreground::ForegroundSource;
use fss_twin::image_tracking::{ImageDetection, ImageTracker, ImageTrackingError,
    ImageTrackingFrame, ImageTrackingPolicy, ImageTrackingReport, MAX_IMAGE_TRACKS,
    TrackingAvailability};
use fss_twin::image_zones::{ImageZoneBasis, ImageZoneError, ImageZoneMonitor,
    ImageZonePolicy, ImageZoneReport, ImageZoneSpec};
use fss_twin::localization::ImageIdentity;
use super::detections::BOX_SUBPIXELS;
use super::rgb_detections::{RgbDetection, RgbDetectionContract, RgbDetectionReport};
use super::rgb_inference::{RgbInference, RgbSourceBinding};

/// Failures before tracking leave both temporal owners unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RgbTrackingError {
    /// Invalid selection, availability declaration or missing evidence identity.
    InvalidInput,
    /// Wrong inference, head contract, original source or coordinate basis.
    BindingMismatch,
    /// Complete selected-class set or fallible allocation exceeds the bound.
    Limit,
    /// The previous accepted track update must finish its zone derivation first.
    PendingZones,
    /// No accepted observation exists to resume.
    NoObservation,
    /// A bounded receipt could not be encoded.
    Encoding,
    /// Preparation work was cancelled or exhausted.
    Work(GeometryError),
    /// The existing tracker refused without changing state.
    Tracking(ImageTrackingError),
    /// The existing zone owner refused configuration or input.
    Zones(ImageZoneError),
}
impl From<GeometryError> for RgbTrackingError {
    fn from(e: GeometryError) -> Self { Self::Work(e) }
}
impl std::fmt::Display for RgbTrackingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid RGB tracking selection or admission",
            Self::BindingMismatch => "RGB tracking source or contract mismatch",
            Self::Limit => "RGB tracking complete-input or allocation limit",
            Self::PendingZones => "resume accepted RGB zone observation first",
            Self::NoObservation => "no accepted RGB tracking observation",
            Self::Encoding => "RGB tracking receipt encoding failed",
            Self::Work(_) => "RGB tracking preparation interrupted",
            Self::Tracking(_) => "RGB image tracking refused",
            Self::Zones(_) => "RGB image-zone configuration refused",
        })
    }
}
impl std::error::Error for RgbTrackingError {}
fn identity(e: CanonicalEncoder) -> Result<ContentDigest, RgbTrackingError> {
    Ok(ContentDigest::sha256(&e.finish_checked().map_err(|_| RgbTrackingError::Encoding)?))
}
fn valid_digest(d: ContentDigest) -> bool {
    d.algorithm() == DigestAlgorithm::Sha256 && d.bytes() != [0; 32]
}

/// Frozen class interpretation for a single anonymous trajectory/zone episode.
#[derive(Debug)]
pub struct RgbTrackingContract {
    digest: ContentDigest, head: ContentDigest, model: ContentDigest,
    class_index: usize, label: String,
}
impl RgbTrackingContract {
    /// Select one exact vocabulary entry. Use a separate explicit owner for another
    /// class; a multi-label row must not become two objects in the same tracker.
    pub fn new(head: &RgbDetectionContract, class_index: usize, selection_evidence: ContentDigest)
        -> Result<Self, RgbTrackingError> {
        let label = head.spec().labels.get(class_index).ok_or(RgbTrackingError::InvalidInput)?;
        if !valid_digest(selection_evidence) { return Err(RgbTrackingError::InvalidInput); }
        let mut e = CanonicalEncoder::new();
        e.text("fss.rgb-tracking-selection.reference.v1:one-class:outward-pixel-cover");
        e.digest(head.digest()); e.digest(selection_evidence); e.u64(class_index as u64);
        Ok(Self { digest: identity(e)?, head: head.digest(), model: head.spec().model,
            class_index, label: label.clone() })
    }
    /// Exact head, class choice, selection evidence and box-conversion rule.
    pub fn digest(&self) -> ContentDigest { self.digest }
    /// Full frozen detector-head identity, including vocabulary and selection limits.
    pub fn head_digest(&self) -> ContentDigest { self.head }
    /// Class retained by this owner. Class scores never authorize an effect.
    pub fn class_index(&self) -> usize { self.class_index }
    /// Original model vocabulary string, not an independently verified object identity.
    pub fn label(&self) -> &str { &self.label }
}

/// Explicit source-bound availability declaration from the owning screening path.
/// A nonzero evidence handle is linkage, not authentication or health qualification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RgbFrameAdmission {
    source: RgbSourceBinding, availability: TrackingAvailability, evidence: ContentDigest,
}
impl RgbFrameAdmission {
    /// Bind a decision to the exact exposure/mask/capture before assimilation.
    /// Never derive Available solely from successful decoding or a high model score.
    pub fn new(source: RgbSourceBinding, availability: TrackingAvailability, evidence: ContentDigest)
        -> Result<Self, RgbTrackingError> {
        if !valid_digest(evidence) || source.camera == 0 || source.clock == 0
            || source.capture[0] > source.capture[1]
            || [source.exposure, source.encoded_sha256, source.image_domain,
                source.calibration, source.permission_mask].contains(&[0; 32]) {
            return Err(RgbTrackingError::InvalidInput);
        }
        Ok(Self { source, availability, evidence })
    }
    /// Original camera/clock/calibration/source-mask declaration.
    pub fn source(&self) -> RgbSourceBinding { self.source }
    /// Owner-declared assimilation availability, not an absence assertion.
    pub fn availability(&self) -> TrackingAvailability { self.availability }
    /// Evidence supplied by the owner for this declaration.
    pub fn evidence(&self) -> ContentDigest { self.evidence }
}

/// Every post-NMS survivor remains visible, including nonselected model classes.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RgbTrackingDecision {
    /// Original exact subpixel box, row, class, score and clipping flag.
    pub detection: RgbDetection,
    /// Conservative integer-pixel proposal; None explicitly means another class.
    pub proposal: Option<ImageDetection>,
}
/// Opaque conversion receipt over actual neural output and independent availability.
#[derive(Debug)]
pub struct PreparedRgbTracking {
    digest: ContentDigest, inference: ContentDigest, detections: ContentDigest,
    admission: RgbFrameAdmission, frame: ImageTrackingFrame,
    proposals: Vec<ImageDetection>, decisions: Vec<RgbTrackingDecision>,
}
impl PreparedRgbTracking {
    /// Exact report/class/availability/rounding derivation identity.
    pub fn digest(&self) -> ContentDigest { self.digest }
    /// Original complete numerical inference identity.
    pub fn inference_identity(&self) -> ContentDigest { self.inference }
    /// Original detector report with every head row and NMS alternative.
    pub fn detection_digest(&self) -> ContentDigest { self.detections }
    /// Exact source-specific owner declaration, retained rather than inferred.
    pub fn admission(&self) -> RgbFrameAdmission { self.admission }
    /// Original coded RGB image, class generation and declared availability.
    pub fn frame(&self) -> ImageTrackingFrame { self.frame }
    /// All proposals for the selected class, never top-k truncated.
    pub fn proposals(&self) -> &[ImageDetection] { &self.proposals }
    /// Every post-NMS class proposal, including explicit nonselected classes.
    pub fn decisions(&self) -> &[RgbTrackingDecision] { &self.decisions }
}

/// Prepare complete model-class proposals without changing either temporal owner.
/// Integer boxes outwardly contain the exact q256 boxes. That subpixel expansion
/// may turn a definite side into Boundary, never the reverse. Image-edge/clipped
/// boxes remain partial. Neither box centers nor zone events become ground contacts.
pub fn prepare_rgb_tracking(inference: &RgbInference, report: &RgbDetectionReport,
    contract: &RgbTrackingContract, admission: RgbFrameAdmission, budget: &mut WorkBudget<'_>)
    -> Result<PreparedRgbTracking, RgbTrackingError> {
    budget.charge(256)?;
    if report.inference_identity() != inference.identity() || report.source() != inference.source()
        || report.geometry() != inference.geometry() || admission.source != report.source()
        || report.contract_digest() != contract.head || inference.model_digest() != contract.model {
        return Err(RgbTrackingError::BindingMismatch);
    }
    let all = report.detections();
    budget.charge(all.len() as u64)?;
    let count = all.iter().filter(|d| d.class_index() == contract.class_index).count();
    if count > MAX_IMAGE_TRACKS { return Err(RgbTrackingError::Limit); }
    let mut proposals = reserve(count)?; let mut decisions = reserve(all.len())?;
    let g = report.geometry(); let dimensions = [g.source_width as u32, g.source_height as u32];
    let mut e = CanonicalEncoder::new();
    e.text("fss.rgb-tracking-input.reference.v1"); e.digest(contract.digest());
    e.digest(report.digest()); e.digest(inference.identity()); e.digest(admission.evidence);
    e.u8(admission.availability as u8); e.u64(all.len() as u64);
    for d in all {
        budget.charge(512)?;
        let proposal = if d.class_index() == contract.class_index {
            let b = d.bounds();
            let min = [b[0] / BOX_SUBPIXELS, b[1] / BOX_SUBPIXELS];
            let max = [b[2].div_ceil(BOX_SUBPIXELS), b[3].div_ceil(BOX_SUBPIXELS)];
            let partial = d.clipped() || min.contains(&0) || max[0] == dimensions[0] || max[1] == dimensions[1];
            let id = (d.row() as u64).checked_add(1).ok_or(RgbTrackingError::Limit)?;
            let mut p = CanonicalEncoder::new(); p.text("fss.rgb-tracking-proposal.reference.v1");
            p.digest(report.digest()); p.digest(contract.digest()); p.u64(id);
            for value in b { p.u32(value); }
            for value in [min[0], min[1], max[0], max[1]] { p.u32(value); }
            p.u32(d.score().to_bits()); p.bool(partial);
            let proposal = ImageDetection { id, evidence: identity(p)?.bytes(), min, max, partial };
            proposals.push(proposal); Some(proposal)
        } else { None };
        e.u64(d.row() as u64); e.u64(d.class_index() as u64); e.u32(d.score().to_bits());
        for value in d.bounds() { e.u32(value); }
        e.bool(d.clipped()); e.bool(proposal.is_some());
        if let Some(p) = proposal { e.bytes(&p.evidence); }
        decisions.push(RgbTrackingDecision { detection: *d, proposal });
    }
    let digest = identity(e)?; let s = report.source();
    let frame = ImageTrackingFrame { source: ForegroundSource {
        image: ImageIdentity { exposure: s.exposure, pixels: inference.decode_receipt().rgb_sha256,
            image_domain: s.image_domain, dimensions }, camera: s.camera, clock: s.clock,
        calibration: s.calibration, capture: s.capture }, detector: contract.digest().bytes(),
        permission_mask: s.permission_mask, evidence: digest.bytes(), availability: admission.availability };
    budget.charge(0)?;
    Ok(PreparedRgbTracking { digest, inference: inference.identity(), detections: report.digest(),
        admission, frame, proposals, decisions })
}
fn reserve<T>(n: usize) -> Result<Vec<T>, RgbTrackingError> {
    let mut v = Vec::new(); v.try_reserve_exact(n).map_err(|_| RgbTrackingError::Limit)?; Ok(v)
}

/// Both results mean tracking consumed the exposure. Pending retries only zones.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RgbZoneProgress {
    /// Complete local tracking and zone results; not canonical publication.
    Complete {
        /// Exact accepted tracker receipt.
        tracking: [u8; 32],
        /// Complete zone result, including interruptions and retirement.
        zones: [u8; 32],
    },
    /// Tracking accepted but zones could not finish. New observations are blocked.
    Pending {
        /// Retained consumed-source receipt, never a request to ingest it twice.
        tracking: [u8; 32],
        /// Existing zone owner's explicit refusal.
        error: ImageZoneError,
    },
}
/// Composition of the existing tracker and zone monitor, not another association
/// algorithm. All state is bounded and synchronous. The owner retains original
/// inference/report bytes; this object is not a durable checkpoint or custody claim.
pub struct RgbZoneTracker {
    contract: RgbTrackingContract, tracker: ImageTracker, monitor: ImageZoneMonitor,
    prepared: Option<PreparedRgbTracking>, tracking: Option<ImageTrackingReport>, pending: bool,
}
impl RgbZoneTracker {
    /// Begin one explicit selected-class episode on the original coded image grid.
    pub fn new(episode: [u8; 32], contract: RgbTrackingContract, tracking: ImageTrackingPolicy,
        basis: ImageZoneBasis, policy: ImageZonePolicy, zones: &[ImageZoneSpec], budget: &mut WorkBudget<'_>)
        -> Result<Self, RgbTrackingError> {
        let tracker = ImageTracker::new(episode, tracking, budget).map_err(RgbTrackingError::Tracking)?;
        let monitor = ImageZoneMonitor::new(&tracker, basis, policy, zones, budget).map_err(RgbTrackingError::Zones)?;
        Ok(Self { contract, tracker, monitor, prepared: None, tracking: None, pending: false })
    }
    /// Frozen class/head selection, never mutable model activation.
    pub fn contract(&self) -> &RgbTrackingContract { &self.contract }
    /// Existing anonymous tracker, including predictions/ambiguity and exact exposures.
    pub fn tracker(&self) -> &ImageTracker { &self.tracker }
    /// Exact accepted preparation, including owner availability and other classes.
    pub fn prepared(&self) -> Option<&PreparedRgbTracking> { self.prepared.as_ref() }
    /// Accepted tracking receipt, including one with pending zone work.
    pub fn tracking_report(&self) -> Option<&ImageTrackingReport> { self.tracking.as_ref() }
    /// Zones only for the currently accepted source; None while pending, not stale data.
    pub fn zone_report(&self) -> Option<&ImageZoneReport> {
        if self.pending { None } else { self.monitor.latest() }
    }
    /// Whether new assimilation is blocked on the accepted source's zone derivation.
    pub fn is_pending(&self) -> bool { self.pending }
    /// Assimilate one actual inference/projection pair. An outer error leaves both
    /// temporal states unchanged. A Pending result means tracking DID commit.
    pub fn observe(&mut self, inference: &RgbInference, report: &RgbDetectionReport,
        admission: RgbFrameAdmission, budget: &mut WorkBudget<'_>) -> Result<RgbZoneProgress, RgbTrackingError> {
        if self.pending { return Err(RgbTrackingError::PendingZones); }
        let prepared = prepare_rgb_tracking(inference, report, &self.contract, admission, budget)?;
        let s = prepared.frame.source; let basis = self.monitor.basis();
        if s.camera != basis.camera || s.clock != basis.clock || s.calibration != basis.calibration
            || s.image.image_domain != basis.image_domain || s.image.dimensions != basis.dimensions {
            return Err(RgbTrackingError::BindingMismatch);
        }
        let tracking = self.tracker.update(prepared.frame, &prepared.proposals, budget)
            .map_err(RgbTrackingError::Tracking)?;
        self.prepared = Some(prepared); self.tracking = Some(tracking); self.pending = true;
        self.resume(budget)
    }
    /// Resume only zones. A failed zone attempt retains its upstream receipt and
    /// complete preparation. A completed repeat is idempotent and spends no work.
    pub fn resume(&mut self, budget: &mut WorkBudget<'_>) -> Result<RgbZoneProgress, RgbTrackingError> {
        let tracking = self.tracking.as_ref().ok_or(RgbTrackingError::NoObservation)?;
        if !self.pending {
            let zones = self.monitor.latest().ok_or(RgbTrackingError::NoObservation)?;
            return Ok(RgbZoneProgress::Complete { tracking: tracking.digest(), zones: zones.digest() });
        }
        match self.monitor.observe(&self.tracker, tracking, budget) {
            Ok(zones) => {
                self.pending = false;
                Ok(RgbZoneProgress::Complete { tracking: tracking.digest(), zones: zones.digest() })
            }
            Err(error) => Ok(RgbZoneProgress::Pending { tracking: tracking.digest(), error }),
        }
    }
}

/// Resumable JPEG-to-owned-trajectory/zone processing over the same temporal engines.
pub mod pipeline;
