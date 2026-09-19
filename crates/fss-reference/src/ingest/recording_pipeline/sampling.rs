#![forbid(unsafe_code)]
//! Opt-in activity sampling on the SAME retained-source and frozen-inference runner.
//!
//! Every requested source frame is decoded or revalidated. Only model invocations are skipped.
//! Sparse analysis keeps the existing tracker's source-gap resets. All-frame execution remains
//! unchanged; this path does not grant access, activate a policy, adjudicate events, or send alerts.

mod report;
pub use report::{MAX_SAMPLED_REPORT_BYTES, SampledReport};

use std::collections::BTreeMap;
use fss_core::{CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContractError};
use super::*;
use super::super::activity::{ActivityPolicy, ActivitySampler, SamplingDecision};
use super::super::pixel_change::PixelChangeConfig;

/// Complete metadata bound, independent of source and analysis bytes.
pub const MAX_SAMPLING_PLAN_BYTES: usize = 16 * 1024;
/// At most one comparison per pixel for each of 256 bounded four-megapixel images.
pub const MAX_SAMPLING_COMPARISONS: u64 = 256 * 4_194_304;

/// An explicit inclusion constraint. The basis does not grant access or effect authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequiredFrame {
    /// Exact zero-based source segment inside the requested contiguous range.
    pub segment_index: usize,
    /// Immutable owner-provided reason/obligation identity requiring this observation.
    pub basis: ContentDigest,
}

/// Frozen source range, policy and inclusion constraints. Comparison allowance is part of the
/// recipe because its conservative fallback can change which model invocations are selected.
#[derive(Clone, Debug)]
pub struct SamplingPlan {
    import: ContentDigest,
    interpretation: ComponentInterpretation,
    first: usize,
    count: usize,
    policy: ActivityPolicy,
    maximum_comparisons: u64,
    required: BTreeMap<usize, ContentDigest>,
    bytes: Vec<u8>,
}
impl SamplingPlan {
    /// Freeze sampling for this exact request. Model/detector/tracker policies remain owned by
    /// RecordingRequest and the nested AnalysisReport rather than a second detector dialect.
    pub fn new(request: &RecordingRequest, policy: ActivityPolicy, maximum_comparisons: u64,
        required: Vec<RequiredFrame>) -> Result<Self, SamplingError>
    {
        Self::build(request.import_identity, request.interpretation, request.first_segment,
            request.segment_count, policy, maximum_comparisons, required)
    }
    fn build(import: ContentDigest, interpretation: ComponentInterpretation, first: usize,
        count: usize, policy: ActivityPolicy, maximum_comparisons: u64, required: Vec<RequiredFrame>)
        -> Result<Self, SamplingError>
    {
        policy.validate()?;
        let end = first.checked_add(count).ok_or(SamplingError::InvalidPlan)?;
        if import.algorithm() != DigestAlgorithm::Sha256 || count == 0 || count > MAX_ANALYSIS_FRAMES
            || required.len() > count || maximum_comparisons > MAX_SAMPLING_COMPARISONS
        { return Err(SamplingError::InvalidPlan); }
        let mut required_map = BTreeMap::new();
        for item in required {
            if !(first..end).contains(&item.segment_index)
                || item.basis.algorithm() != DigestAlgorithm::Sha256
                || required_map.insert(item.segment_index, item.basis).is_some()
            { return Err(SamplingError::InvalidPlan); }
        }
        let mut e = CanonicalEncoder::new();
        e.bytes(b"FSSASPL1"); e.u32(1); e.text("fss.recorded_activity_plan.v1");
        e.digest(import); e.u8(match interpretation {
            ComponentInterpretation::Grayscale => 0, ComponentInterpretation::YCbCr => 1,
        });
        e.u64(first as u64); e.u64(count as u64); policy.encode_canonical(&mut e);
        e.u64(maximum_comparisons); e.u64(required_map.len() as u64);
        for (segment, basis) in &required_map { e.u64(*segment as u64); e.digest(*basis); }
        let bytes = e.finish_checked()?;
        if bytes.len() > MAX_SAMPLING_PLAN_BYTES { return Err(SamplingError::Limit); }
        Ok(Self { import, interpretation, first, count, policy, maximum_comparisons,
            required: required_map, bytes })
    }
    /// Bounded exact-version restoration. Rehashed truncation, duplicate constraints and
    /// noncanonical constraint ordering are refused, not silently normalized on input.
    pub fn decode(bytes: &[u8], expected: ContentDigest) -> Result<Self, SamplingError> {
        if bytes.len() > MAX_SAMPLING_PLAN_BYTES { return Err(SamplingError::Limit); }
        if ContentDigest::sha256(bytes) != expected { return Err(SamplingError::Mismatch); }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != b"FSSASPL1" || d.u32()? != 1 || d.text()? != "fss.recorded_activity_plan.v1" {
            return Err(SamplingError::InvalidPlan);
        }
        let import = d.digest()?;
        let interpretation = match d.u8()? {
            0 => ComponentInterpretation::Grayscale, 1 => ComponentInterpretation::YCbCr,
            _ => return Err(SamplingError::InvalidPlan),
        };
        let first = bounded_count(&mut d, usize::MAX)?;
        let count = bounded_count(&mut d, MAX_ANALYSIS_FRAMES)?;
        let policy = ActivityPolicy {
            change: PixelChangeConfig { minimum_delta: d.u8()?, minimum_changed_pixels: d.u64()?,
                minimum_changed_fraction_ppm: d.u32()? },
            sentinel_stride: d.u32()?, post_activity_frames: d.u32()?,
        };
        let maximum_comparisons = d.u64()?;
        let n = bounded_count(&mut d, MAX_ANALYSIS_FRAMES)?;
        let mut required = Vec::with_capacity(n);
        for _ in 0..n {
            required.push(RequiredFrame { segment_index: bounded_count(&mut d, usize::MAX)?, basis: d.digest()? });
        }
        d.ensure_finished()?;
        let plan = Self::build(import, interpretation, first, count, policy, maximum_comparisons, required)?;
        if plan.encoded() != bytes { return Err(SamplingError::InvalidPlan); }
        Ok(plan)
    }
    /// Exact source range, thresholds, comparison allowance and required observations.
    #[must_use]
    pub fn encoded(&self) -> &[u8] { &self.bytes }
    /// Integrity identity; not permission to activate this policy.
    #[must_use]
    pub fn digest(&self) -> ContentDigest { ContentDigest::sha256(&self.bytes) }
    /// Exact immutable source import.
    #[must_use]
    pub fn import_identity(&self) -> ContentDigest { self.import }
    /// First requested segment.
    #[must_use]
    pub fn first_segment(&self) -> usize { self.first }
    /// Total inspected frames, including skipped model invocations.
    #[must_use]
    pub fn segment_count(&self) -> usize { self.count }
    /// Frozen opt-in measurement, sentinel and burst policy.
    #[must_use]
    pub fn policy(&self) -> ActivityPolicy { self.policy }
    /// Cumulative comparison allowance whose fallback is part of the replay recipe.
    #[must_use]
    pub fn maximum_comparisons(&self) -> u64 { self.maximum_comparisons }
    /// Exact sorted required-frame inclusion constraints.
    #[must_use]
    pub fn required_frames(&self) -> &BTreeMap<usize, ContentDigest> { &self.required }
    fn binds(&self, request: &RecordingRequest) -> bool {
        self.import == request.import_identity && self.interpretation == request.interpretation
            && self.first == request.first_segment && self.count == request.segment_count
    }
    fn source(&self, index: usize, limits: &AnalysisLimits) -> RecordedDecodeRequest {
        RecordedDecodeRequest { import_identity: self.import, interpretation: self.interpretation,
            segment_index: index, read_limits: limits.read_limits, decode_limits: limits.decode_limits }
    }
}
fn bounded_count(d: &mut CanonicalDecoder<'_>, ceiling: usize) -> Result<usize, SamplingError> {
    let n = usize::try_from(d.u64()?).map_err(|_| SamplingError::Limit)?;
    if n > ceiling { return Err(SamplingError::Limit); }
    Ok(n)
}

/// Failures in frozen sampling or report replay; no failure can become a quiet measurement.
#[derive(Debug)]
pub enum SamplingError {
    /// Invalid source range, requirement, policy or request/plan binding.
    InvalidPlan,
    /// Explicit metadata, frame, comparison or encoded-output ceiling exceeded.
    Limit,
    /// Report contents fail exact source-linked replay.
    Mismatch,
    /// Owner cancellation before a complete result.
    Cancelled,
    /// Versioned canonical data was malformed.
    Contract(ContractError),
    /// Source-linked measurement or immutable sampler transition refused.
    Activity(ActivityError),
    /// Previously completed decoded source cannot be revalidated.
    Decode(Box<RecordedDecodeError>),
    /// Existing detector/tracker report cannot be revalidated.
    Analysis(Box<AnalysisError>),
}
impl fmt::Display for SamplingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPlan => "invalid recorded sampling plan", Self::Limit => "recorded sampling bound exceeded",
            Self::Mismatch => "recorded sampling replay mismatch", Self::Cancelled => "recorded sampling cancelled",
            Self::Contract(_) => "invalid recorded sampling encoding", Self::Activity(_) => "activity sampling refused",
            Self::Decode(_) => "sampling source revalidation refused", Self::Analysis(_) => "sampling analysis revalidation refused",
        })
    }
}
impl Error for SamplingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Contract(e) => Some(e), Self::Activity(e) => Some(e),
            Self::Decode(e) => Some(e.as_ref()), Self::Analysis(e) => Some(e.as_ref()), _ => None,
        }
    }
}
impl From<ContractError> for SamplingError { fn from(e: ContractError) -> Self { Self::Contract(e) } }
impl From<ActivityError> for SamplingError { fn from(e: ActivityError) -> Self { Self::Activity(e) } }
impl From<RecordedDecodeError> for SamplingError { fn from(e: RecordedDecodeError) -> Self { Self::Decode(Box::new(e)) } }
impl From<AnalysisError> for SamplingError { fn from(e: AnalysisError) -> Self { Self::Analysis(Box::new(e)) } }

/// Complete sampling provenance and the existing complete sparse detector/tracker report.
#[derive(Clone, Debug)]
pub struct SampledRecordingOutcome {
    /// Exact, replay-verifiable trace including every skipped source frame.
    pub report: SampledReport,
    /// Existing cumulative execution/reuse counters and retained selected invocation identities.
    pub progress: RecordingProgress,
}

/// Typed source of a failed attempt; selected inference and report sealing are separate stages.
#[derive(Debug)]
pub enum SampledFailureCause {
    /// Existing source/decode/model/detector/tracker runner refused.
    Pipeline(RecordingError),
    /// Frozen plan binding, bounded report construction or cancellation refused.
    Sampling(SamplingError),
}
impl fmt::Display for SampledFailureCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self { Self::Pipeline(e) => write!(f, "{e}"), Self::Sampling(e) => write!(f, "{e}") }
    }
}
impl Error for SampledFailureCause {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self { Self::Pipeline(e) => Some(e), Self::Sampling(e) => Some(e) }
    }
}
/// Explicit incomplete progress, never a partial complete report or a trusted checkpoint.
#[derive(Debug)]
pub struct SampledRecordingFailure {
    /// Typed cause of refusal.
    pub cause: SampledFailureCause,
    /// Existing durable prefix and current pending source segment.
    pub progress: RecordingProgress,
    /// Exact decisions made before refusal, including a selected frame whose inference failed.
    pub decisions: Vec<SamplingDecision>,
    /// Actual comparison work charged, including work performed before a cancellation.
    pub comparisons_used: u64,
}
impl fmt::Display for SampledRecordingFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sampled recording {}: {}", self.progress.stage.as_str(), self.cause)
    }
}
impl Error for SampledRecordingFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> { Some(&self.cause) }
}

/// Execute an exact opt-in sampling plan with the same cumulative work buckets and source/model
/// owners as run_recording. Decoding and sampling inspect every requested frame. No skipped
/// inference is submitted to the tracker as an empty detection, and no required/sentinel frame
/// is dropped because the model budget ran out. Instead, failure returns the exact durable prefix.
///
/// Retry from the ORIGINAL full range and frozen plan. Source custody, decisions and selected
/// completed invocations are revalidated; only uncompleted model work executes. Comparison work
/// is replayed even when numeric model/decode work is cached. The plan's comparison allowance
/// is an explicit per-attempt policy input, not a lifetime budget or hardware-resource claim.
pub fn run_sampled_recording(
    deployment: &mut ReferenceDeployment, request: &RecordingRequest, model: &RecordedModel,
    sampling: &SamplingPlan, budget: &mut RecordingBudget<'_>, exec: &ScalarExecCx, cx: &ReplayCx,
) -> Result<SampledRecordingOutcome, Box<SampledRecordingFailure>> {
    let initial = RecordingProgress {
        stage: RecordingStage::Preflight, next_segment: Some(request.first_segment), completed: Vec::new(),
        new_decodes: 0, reused_decodes: 0, new_inferences: 0, reused_inferences: 0,
        anchor: deployment.current_anchor().clone(),
    };
    if !sampling.binds(request) {
        return Err(Box::new(SampledRecordingFailure { cause: SampledFailureCause::Sampling(SamplingError::InvalidPlan),
            progress: initial, decisions: Vec::new(), comparisons_used: 0 }));
    }
    let mut sampler = match ActivitySampler::new(sampling.policy, sampling.maximum_comparisons) {
        Ok(sampler) => sampler,
        Err(e) => return Err(Box::new(SampledRecordingFailure { cause: SampledFailureCause::Sampling(e.into()),
            progress: initial, decisions: Vec::new(), comparisons_used: 0 })),
    };
    let mut decisions = Vec::with_capacity(sampling.count);
    let result = {
        let mut select = |frame: &RecordedFrame, cx: &ReplayCx| -> Result<bool, RecordingError> {
            let index = usize::try_from(frame.receipt().segment_index())
                .map_err(|_| RecordingError::InvalidRequest("sampling segment index"))?;
            let decision = sampler.push(frame, sampling.required.get(&index).copied(), cx)?;
            let selected = decision.selected();
            decisions.push(decision);
            Ok(selected)
        };
        super::run_selected(deployment, request, model, budget, exec, cx, Some(&mut select))
    };
    let comparisons_used = sampler.comparisons_used();
    match result {
        Err(error) => {
            let RecordingFailure { cause, progress } = *error;
            Err(Box::new(SampledRecordingFailure { cause: SampledFailureCause::Pipeline(cause),
                progress, decisions, comparisons_used }))
        }
        Ok(outcome) => {
            // A complete nested analysis alone is not a complete sampling report.
            let mut progress = outcome.progress;
            progress.stage = RecordingStage::Analysis;
            let sealed = cx.checkpoint("sampled_recording:seal").map_err(|_| SamplingError::Cancelled)
                .and_then(|()| SampledReport::assemble(sampling.clone(), decisions.clone(), outcome.report, comparisons_used));
            match sealed {
                Ok(report) => { progress.stage = RecordingStage::Complete; Ok(SampledRecordingOutcome { report, progress }) }
                Err(cause) => Err(Box::new(SampledRecordingFailure { cause: SampledFailureCause::Sampling(cause),
                    progress, decisions, comparisons_used })),
            }
        }
    }
}
