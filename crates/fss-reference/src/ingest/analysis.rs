#![forbid(unsafe_code)]
//! Restart-reproducible, bounded recording analysis over retained model runs.
//!
//! This composes the existing detector and local tracker; it does not introduce another
//! detector, identity system, or authority ledger. Reports contain complete projections,
//! source uncertainty, retirements, and reset reasons. They never certify absence or effects.

use std::error::Error;
use std::fmt;

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, ContractError, DigestAlgorithm};

use super::detections::{
    BOX_SUBPIXELS, BoxEncoding, CoordinateSpace, DetectionBudget, DetectionContract, DetectionError,
    DetectionFrame, DetectionSpec,
};
use super::recorded_decode::{ComponentInterpretation, DecodeLimits, RecordedDecodeRequest};
use super::tracking::{
    AssociationBudget, LocalBoxTracker, TrackingConfig, TrackingError, TrackingUpdate,
};
use super::RetainedReadLimits;
use crate::{ReferenceDeployment, ReplayCx};

/// Hard ceiling for one complete, non-truncated report.
pub const MAX_ANALYSIS_FRAMES: usize = 256;
/// Hard ceiling for a self-contained plan, including the frozen detector contract.
pub const MAX_ANALYSIS_PLAN_BYTES: usize = 128 * 1024;
/// Hard ceiling for an exported report, not a bound on all process memory.
pub const MAX_ANALYSIS_REPORT_BYTES: usize = 16 * 1024 * 1024;
const PLAN_DOMAIN: &str = "fss.recorded_analysis_plan.v1";
const REPORT_DOMAIN: &str = "fss.recorded_analysis_report.v1";

/// An exact already-completed inference run at an explicitly selected source segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalysisFrame {
    /// Zero-based source segment in the immutable recording import.
    pub segment_index: usize,
    /// Exact retained model invocation, never a latest-model or latest-frame lookup.
    pub run_identity: ContentDigest,
}

/// Immutable ordered replay recipe. Gaps are allowed and remain explicit tracker resets.
#[derive(Clone, Debug)]
pub struct AnalysisPlan {
    import_identity: ContentDigest,
    interpretation: ComponentInterpretation,
    detector: DetectionContract,
    tracking: TrackingConfig,
    frames: Vec<AnalysisFrame>,
    bytes: Vec<u8>,
    digest: ContentDigest,
}

/// Fail-closed refusal. No partial report is returned, and consumed work is not refunded.
#[derive(Debug)]
pub enum AnalysisError {
    /// Empty, duplicate, reversed, or otherwise invalid replay recipe.
    InvalidPlan,
    /// A caller or hard frame/byte/allocation bound was exceeded.
    Limit,
    /// Owner cancellation before the complete report was returned.
    Cancelled,
    /// Report bytes do not reproduce from the exact retained evidence.
    Mismatch,
    /// A shared canonical contract failed.
    Contract(ContractError),
    /// Source recovery or detector projection was refused.
    Detection(DetectionError),
    /// Local association was refused.
    Tracking(TrackingError),
}
impl fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPlan => "invalid recorded analysis plan",
            Self::Limit => "recorded analysis bound exceeded",
            Self::Cancelled => "recorded analysis owner cancelled",
            Self::Mismatch => "recorded analysis replay mismatch",
            Self::Contract(_) => "invalid recorded analysis encoding",
            Self::Detection(_) => "recorded analysis detector or source refused",
            Self::Tracking(_) => "recorded analysis association refused",
        })
    }
}
impl Error for AnalysisError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Contract(e) => Some(e),
            Self::Detection(e) => Some(e),
            Self::Tracking(e) => Some(e),
            _ => None,
        }
    }
}
impl From<ContractError> for AnalysisError {
    fn from(e: ContractError) -> Self { Self::Contract(e) }
}
impl From<DetectionError> for AnalysisError {
    fn from(e: DetectionError) -> Self { Self::Detection(e) }
}
impl From<TrackingError> for AnalysisError {
    fn from(e: TrackingError) -> Self { Self::Tracking(e) }
}

fn checkpoint(cx: &ReplayCx) -> Result<(), AnalysisError> {
    cx.checkpoint("recorded_analysis:frame").map_err(|_| AnalysisError::Cancelled)
}
fn count(d: &mut CanonicalDecoder<'_>, ceiling: usize) -> Result<usize, AnalysisError> {
    let n = usize::try_from(d.u64()?).map_err(|_| AnalysisError::Limit)?;
    if n > ceiling { return Err(AnalysisError::Limit); }
    Ok(n)
}
fn name(d: &mut CanonicalDecoder<'_>) -> Result<String, AnalysisError> {
    let value = d.text()?;
    if value.len() > 128 { return Err(AnalysisError::Limit); }
    Ok(value.to_owned())
}

// Decode the existing detector contract's exact v1 bytes, not a second contract dialect.
// Reconstruction through its owning constructor checks labels, bounds, and numeric policy.
fn decode_detector(bytes: &[u8]) -> Result<DetectionSpec, AnalysisError> {
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != "fss.recorded_detection_contract.v1" { return Err(AnalysisError::InvalidPlan); }
    let model_digest = d.digest()?;
    let output_port = name(&mut d)?;
    let n = count(&mut d, 256)?;
    let mut labels = Vec::with_capacity(n);
    for _ in 0..n { labels.push(name(&mut d)?); }
    let encoding = match d.u8()? {
        0 => BoxEncoding::Xyxy, 1 => BoxEncoding::CenterSize,
        _ => return Err(AnalysisError::InvalidPlan),
    };
    let coordinates = match d.u8()? {
        0 => CoordinateSpace::Pixels, 1 => CoordinateSpace::Normalized,
        _ => return Err(AnalysisError::InvalidPlan),
    };
    if d.u32()? != BOX_SUBPIXELS { return Err(AnalysisError::InvalidPlan); }
    let minimum_score_ppm = d.u32()?;
    let nms_iou_ppm = d.u32()?;
    let maximum_rows = count(&mut d, super::detections::MAX_DETECTION_ROWS)?;
    let maximum_detections = count(&mut d, super::detections::MAX_DETECTIONS)?;
    d.ensure_finished()?;
    let spec = DetectionSpec { model_digest, output_port, labels, encoding, coordinates,
        minimum_score_ppm, nms_iou_ppm, maximum_rows, maximum_detections };
    if DetectionContract::new(spec.clone())?.encoded() != bytes { return Err(AnalysisError::InvalidPlan); }
    Ok(spec)
}

impl AnalysisPlan {
    /// Freeze an ordered single-import selection and explicit model-output/tracker policies.
    /// The selected subset is not a completeness or continuous-coverage certificate.
    pub fn new(
        import_identity: ContentDigest, interpretation: ComponentInterpretation,
        detector: DetectionSpec, tracking: TrackingConfig, frames: Vec<AnalysisFrame>,
    ) -> Result<Self, AnalysisError> {
        if import_identity.algorithm() != DigestAlgorithm::Sha256 || frames.is_empty()
            || frames.len() > MAX_ANALYSIS_FRAMES
            || frames.iter().any(|f| f.run_identity.algorithm() != DigestAlgorithm::Sha256)
            || frames.windows(2).any(|w| w[0].segment_index >= w[1].segment_index)
        { return Err(AnalysisError::InvalidPlan); }
        tracking.digest()?;
        let detector = DetectionContract::new(detector)?;
        let mut e = CanonicalEncoder::new();
        e.bytes(b"FSSAPLN1"); e.u32(1); e.text(PLAN_DOMAIN); e.digest(import_identity);
        e.u8(match interpretation {
            ComponentInterpretation::Grayscale => 0, ComponentInterpretation::YCbCr => 1,
        });
        e.bytes(detector.encoded());
        e.u32(tracking.minimum_iou_ppm); e.u32(tracking.confirmation_hits);
        e.u32(tracking.maximum_missed_frames); e.u64(tracking.maximum_tracks as u64);
        e.u64(frames.len() as u64);
        for frame in &frames { e.u64(frame.segment_index as u64); e.digest(frame.run_identity); }
        let bytes = e.finish_checked()?;
        if bytes.len() > MAX_ANALYSIS_PLAN_BYTES { return Err(AnalysisError::Limit); }
        Ok(Self { import_identity, interpretation, detector, tracking, frames,
            digest: ContentDigest::sha256(&bytes), bytes })
    }

    /// Restore a digest-pinned plan with allocation ceilings and exact canonical round-trip checks.
    /// Loading a plan does not authenticate any source or grant I/O or effect authority.
    pub fn decode(bytes: &[u8], expected: ContentDigest) -> Result<Self, AnalysisError> {
        if bytes.len() > MAX_ANALYSIS_PLAN_BYTES { return Err(AnalysisError::Limit); }
        if ContentDigest::sha256(bytes) != expected { return Err(AnalysisError::Mismatch); }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != b"FSSAPLN1" || d.u32()? != 1 || d.text()? != PLAN_DOMAIN {
            return Err(AnalysisError::InvalidPlan);
        }
        let import_identity = d.digest()?;
        let interpretation = match d.u8()? {
            0 => ComponentInterpretation::Grayscale, 1 => ComponentInterpretation::YCbCr,
            _ => return Err(AnalysisError::InvalidPlan),
        };
        let detector = decode_detector(d.bytes()?)?;
        let tracking = TrackingConfig {
            minimum_iou_ppm: d.u32()?, confirmation_hits: d.u32()?, maximum_missed_frames: d.u32()?,
            maximum_tracks: count(&mut d, super::tracking::MAX_LOCAL_TRACKS)?,
        };
        let n = count(&mut d, MAX_ANALYSIS_FRAMES)?;
        let mut frames = Vec::with_capacity(n);
        for _ in 0..n {
            frames.push(AnalysisFrame { segment_index: count(&mut d, usize::MAX)?, run_identity: d.digest()? });
        }
        d.ensure_finished()?;
        let plan = Self::new(import_identity, interpretation, detector, tracking, frames)?;
        if plan.encoded() != bytes { return Err(AnalysisError::InvalidPlan); }
        Ok(plan)
    }
    /// Exact frozen replay recipe, independent of successful admission budget sizes.
    #[must_use]
    pub fn encoded(&self) -> &[u8] { &self.bytes }
    /// Complete plan identity.
    #[must_use]
    pub fn digest(&self) -> ContentDigest { self.digest }
    /// Ordered exact source selections. Gaps are not silently filled.
    #[must_use]
    pub fn frames(&self) -> &[AnalysisFrame] { &self.frames }
    /// Original recording import.
    #[must_use]
    pub fn import_identity(&self) -> ContentDigest { self.import_identity }
    /// Frozen detector interpretation and label table.
    #[must_use]
    pub fn detector(&self) -> &DetectionContract { &self.detector }
}

/// Per-call read and output bounds; these do not change a successfully reproduced report.
#[derive(Clone, Debug)]
pub struct AnalysisLimits {
    /// Maximum selected frames, at most MAX_ANALYSIS_FRAMES.
    pub maximum_frames: usize,
    /// Complete encoded report byte ceiling, at most MAX_ANALYSIS_REPORT_BYTES.
    pub maximum_report_bytes: usize,
    /// Existing retained-source read ceilings, applied on every frame.
    pub read_limits: RetainedReadLimits,
    /// Existing decoded-frame dimension/size ceilings, applied on every frame.
    pub decode_limits: DecodeLimits,
}
impl Default for AnalysisLimits {
    fn default() -> Self {
        Self { maximum_frames: MAX_ANALYSIS_FRAMES, maximum_report_bytes: MAX_ANALYSIS_REPORT_BYTES,
            read_limits: RetainedReadLimits::default(), decode_limits: DecodeLimits::default() }
    }
}
impl AnalysisLimits {
    fn validate(&self) -> Result<(), AnalysisError> {
        if self.maximum_frames == 0 || self.maximum_frames > MAX_ANALYSIS_FRAMES
            || self.maximum_report_bytes == 0 || self.maximum_report_bytes > MAX_ANALYSIS_REPORT_BYTES
        { return Err(AnalysisError::Limit); }
        Ok(())
    }
}

/// Two separately priced cumulative work allowances. Refused work remains charged by its owner.
#[derive(Debug)]
pub struct AnalysisBudget {
    /// Row validation and class-aware NMS comparisons.
    pub detection: DetectionBudget,
    /// Candidate-edge and assignment-solver probes.
    pub association: AssociationBudget,
}
impl AnalysisBudget {
    /// Allocate independent allowances; neither is a latency or whole-process memory budget.
    #[must_use]
    pub fn new(detection_units: u64, association_units: u64) -> Self {
        Self { detection: DetectionBudget::new(detection_units), association: AssociationBudget::new(association_units) }
    }
}

/// One complete source-linked frame and its association transition.
#[derive(Clone, Debug)]
pub struct AnalysisObservation {
    detection: DetectionFrame,
    tracking: TrackingUpdate,
}
impl AnalysisObservation {
    /// Verified source/model projection, including the original uncertain capsule.
    #[must_use]
    pub fn detection(&self) -> &DetectionFrame { &self.detection }
    /// History-linked active, stale, retired, ambiguous, and reset hypotheses.
    #[must_use]
    pub fn tracking(&self) -> &TrackingUpdate { &self.tracking }
}

/// A complete read-only recording projection with a self-contained reconstruction plan.
/// Its digest protects bytes; evidence authority comes from revalidating the retained runs.
#[derive(Clone, Debug)]
pub struct AnalysisReport {
    plan: AnalysisPlan,
    observations: Vec<AnalysisObservation>,
    bytes: Vec<u8>,
    digest: ContentDigest,
}
impl AnalysisReport {
    /// Revalidate every retained run and rebuild the exact detector/tracker history.
    /// This does not execute models or append authority. A failure returns no partial report.
    pub fn read(
        deployment: &ReferenceDeployment, plan: &AnalysisPlan, limits: &AnalysisLimits,
        budget: &mut AnalysisBudget, cx: &ReplayCx,
    ) -> Result<Self, AnalysisError> {
        checkpoint(cx)?;
        limits.validate()?;
        if plan.frames.len() > limits.maximum_frames { return Err(AnalysisError::Limit); }
        let mut tracker = LocalBoxTracker::new(plan.tracking)?;
        let mut e = CanonicalEncoder::new();
        e.bytes(b"FSSARPT1"); e.u32(1); e.text(REPORT_DOMAIN); e.bytes(plan.encoded());
        e.u64(plan.frames.len() as u64);
        let mut bytes = e.finish_checked()?;
        if bytes.len() > limits.maximum_report_bytes { return Err(AnalysisError::Limit); }
        let mut observations = Vec::with_capacity(plan.frames.len());
        for selected in &plan.frames {
            checkpoint(cx)?;
            let source = RecordedDecodeRequest {
                import_identity: plan.import_identity, segment_index: selected.segment_index,
                interpretation: plan.interpretation, read_limits: limits.read_limits,
                decode_limits: limits.decode_limits,
            };
            let detection = DetectionFrame::read(deployment, selected.run_identity, &source,
                &plan.detector, &mut budget.detection, cx)?;
            let tracking = tracker.observe(&detection, &mut budget.association, cx)?;
            let mut e = CanonicalEncoder::new();
            e.bytes(&detection.encoded()?); e.bytes(&tracking.encoded()?);
            let entry = e.finish_checked()?;
            if bytes.len().checked_add(entry.len()).is_none_or(|n| n > limits.maximum_report_bytes) {
                return Err(AnalysisError::Limit);
            }
            bytes.try_reserve(entry.len()).map_err(|_| AnalysisError::Limit)?;
            bytes.extend_from_slice(&entry);
            observations.push(AnalysisObservation { detection, tracking });
        }
        checkpoint(cx)?;
        Ok(Self { plan: plan.clone(), observations, digest: ContentDigest::sha256(&bytes), bytes })
    }

    /// Verify an exported report by recomputing its full projections from retained custody.
    /// Serialized tracks are never trusted as a tracker checkpoint. Model numeric replay is
    /// separate (`RecordedInference::verify_by_replay`); this verifies postprocessing/association.
    pub fn verify(
        deployment: &ReferenceDeployment, bytes: &[u8], expected: ContentDigest,
        limits: &AnalysisLimits, budget: &mut AnalysisBudget, cx: &ReplayCx,
    ) -> Result<Self, AnalysisError> {
        checkpoint(cx)?;
        limits.validate()?;
        if bytes.len() > limits.maximum_report_bytes { return Err(AnalysisError::Limit); }
        if ContentDigest::sha256(bytes) != expected { return Err(AnalysisError::Mismatch); }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != b"FSSARPT1" || d.u32()? != 1 || d.text()? != REPORT_DOMAIN {
            return Err(AnalysisError::InvalidPlan);
        }
        let plan_bytes = d.bytes()?;
        let plan = AnalysisPlan::decode(plan_bytes, ContentDigest::sha256(plan_bytes))?;
        let n = count(&mut d, limits.maximum_frames)?;
        if n != plan.frames.len() { return Err(AnalysisError::Mismatch); }
        for _ in 0..n { let _ = d.bytes()?; let _ = d.bytes()?; }
        d.ensure_finished()?;
        let report = Self::read(deployment, &plan, limits, budget, cx)?;
        if report.encoded() != bytes { return Err(AnalysisError::Mismatch); }
        Ok(report)
    }
    /// Self-contained canonical report, including the exact recipe and complete transitions.
    #[must_use]
    pub fn encoded(&self) -> &[u8] { &self.bytes }
    /// Complete report identity; no mutable latest-frame pointer is involved.
    #[must_use]
    pub fn digest(&self) -> ContentDigest { self.digest }
    /// Exact restart recipe.
    #[must_use]
    pub fn plan(&self) -> &AnalysisPlan { &self.plan }
    /// Complete ordered projections, not a top-k summary.
    #[must_use]
    pub fn observations(&self) -> &[AnalysisObservation] { &self.observations }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn Error>>;
    fn recipe() -> Result<AnalysisPlan, AnalysisError> {
        AnalysisPlan::new(ContentDigest::sha256(b"import"), ComponentInterpretation::Grayscale,
            DetectionSpec { model_digest: ContentDigest::sha256(b"model"), output_port: "boxes".into(),
                labels: vec!["vehicle".into()], encoding: BoxEncoding::Xyxy,
                coordinates: CoordinateSpace::Normalized, minimum_score_ppm: 500_000,
                nms_iou_ppm: 500_000, maximum_rows: 4096, maximum_detections: 128 },
            TrackingConfig { minimum_iou_ppm: 100_000, confirmation_hits: 2,
                maximum_missed_frames: 1, maximum_tracks: 128 },
            vec![AnalysisFrame { segment_index: 0, run_identity: ContentDigest::sha256(b"run0") },
                AnalysisFrame { segment_index: 2, run_identity: ContentDigest::sha256(b"run2") }])
    }
    #[test]
    fn plan_round_trip_preserves_gaps_and_all_policies() -> TestResult {
        let plan = recipe()?;
        let restored = AnalysisPlan::decode(plan.encoded(), plan.digest())?;
        assert_eq!(restored.encoded(), plan.encoded());
        assert_eq!(restored.frames(), plan.frames());
        assert_eq!(restored.detector.digest(), plan.detector.digest());
        assert_eq!(restored.tracking, plan.tracking);
        Ok(())
    }
    #[test]
    fn every_truncated_plan_is_refused_even_when_rehashed() -> TestResult {
        let plan = recipe()?;
        for end in 0..plan.encoded().len() {
            let prefix = &plan.encoded()[..end];
            assert!(AnalysisPlan::decode(prefix, ContentDigest::sha256(prefix)).is_err());
        }
        let mut trailing = plan.encoded().to_vec(); trailing.push(0);
        assert!(AnalysisPlan::decode(&trailing, ContentDigest::sha256(&trailing)).is_err());
        assert!(AnalysisPlan::decode(plan.encoded(), ContentDigest::sha256(b"wrong")).is_err());
        Ok(())
    }
    #[test]
    fn unbounded_or_empty_report_limits_are_refused() {
        let mut limits = AnalysisLimits::default();
        limits.maximum_frames = MAX_ANALYSIS_FRAMES + 1;
        assert!(limits.validate().is_err());
        limits.maximum_frames = 1; limits.maximum_report_bytes = 0;
        assert!(limits.validate().is_err());
        limits.maximum_report_bytes = MAX_ANALYSIS_REPORT_BYTES + 1;
        assert!(limits.validate().is_err());
    }
}
