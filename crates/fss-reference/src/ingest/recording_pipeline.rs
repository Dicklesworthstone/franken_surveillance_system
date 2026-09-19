#![forbid(unsafe_code)]
//! Bounded recording-to-analysis execution over the existing retained-media owners.
//!
//! This sequential composition does not import source, activate models, publish events, or send
//! alerts. Each successful frame/model invocation is independently durable. Retrying the same
//! request revalidates those publications; tracker history is always rebuilt from the full range.

use std::error::Error;
use std::fmt;

use fss_core::{ContentDigest, DigestAlgorithm, LedgerAnchor};

use super::analysis::{
    AnalysisBudget, AnalysisError, AnalysisFrame, AnalysisLimits, AnalysisPlan, AnalysisReport,
    MAX_ANALYSIS_FRAMES, MAX_ANALYSIS_REPORT_BYTES,
};
use super::detections::{DetectionContract, DetectionError, DetectionSpec};
use super::inference::{MAX_RUN_TENSOR_BYTES, ModelRunError, RecordedInference, RecordedModel};
use super::recorded_decode::{
    ComponentInterpretation, DecodeBudget, RecordedDecodeError, RecordedDecodeRequest, RecordedFrame,
};
use super::tracking::{TrackingConfig, TrackingError};
use super::{FileIngestError, RetainedFileImport};
use crate::{ExecBudget, ExecError, ReferenceDeployment, ReplayCx, ScalarExecCx};

/// Immutable source selection and explicit postprocessing policy for one contiguous segment range.
/// Public fields are untrusted until validated by `run`; none grants model or effect authority.
#[derive(Clone, Debug)]
pub struct RecordingRequest {
    /// Exact already-completed JPEG/MJPEG import.
    pub import_identity: ContentDigest,
    /// Explicit grayscale or YCbCr source interpretation, never inferred by this composition.
    pub interpretation: ComponentInterpretation,
    /// First zero-based source segment.
    pub first_segment: usize,
    /// Number of selected segments; positive and at most MAX_ANALYSIS_FRAMES.
    pub segment_count: usize,
    /// Frozen model-output interpretation, including the exact model digest.
    pub detector: DetectionSpec,
    /// Local association policy, not physical identity or event corroboration.
    pub tracking: TrackingConfig,
    /// Source, decoded-frame, complete-report and frame-count bounds.
    pub limits: AnalysisLimits,
    /// Per-invocation executor tensor accounting ceiling, not whole-process peak memory.
    pub maximum_tensor_bytes: usize,
}

impl RecordingRequest {
    /// Validate cheap request and frozen graph metadata before any source decoding/publication.
    /// Returns the exclusive end of the range. Source existence is checked separately by `run`.
    pub fn validate(&self, model: &RecordedModel) -> Result<usize, RecordingError> {
        if self.import_identity.algorithm() != DigestAlgorithm::Sha256
            || self.detector.model_digest != model.digest()
        {
            return Err(RecordingError::InvalidRequest("exact import/model identity"));
        }
        if self.segment_count == 0 || self.segment_count > MAX_ANALYSIS_FRAMES
            || self.limits.maximum_frames == 0 || self.limits.maximum_frames > MAX_ANALYSIS_FRAMES
            || self.segment_count > self.limits.maximum_frames
            || self.limits.maximum_report_bytes == 0
            || self.limits.maximum_report_bytes > MAX_ANALYSIS_REPORT_BYTES
            || self.maximum_tensor_bytes == 0 || self.maximum_tensor_bytes > MAX_RUN_TENSOR_BYTES
        {
            return Err(RecordingError::InvalidRequest("frame/report/tensor bounds"));
        }
        let end = self.first_segment.checked_add(self.segment_count)
            .ok_or(RecordingError::InvalidRequest("segment range overflow"))?;
        let _ = DetectionContract::new(self.detector.clone())?;
        let _ = self.tracking.digest()?;
        let port = model.graph().find_output(&self.detector.output_port)
            .ok_or(RecordingError::InvalidRequest("detector output port"))?;
        let rows = match port.shape().dims() {
            [rows, 6] | [1, rows, 6] => *rows,
            _ => return Err(RecordingError::InvalidRequest("detector output must be [N,6] or [1,N,6]")),
        };
        if rows > self.detector.maximum_rows {
            return Err(RecordingError::InvalidRequest("detector row bound"));
        }
        let input_bytes = model.graph().inputs().iter().try_fold(0_usize, |total, port| {
            let bytes = port.shape().size_bytes(port.dtype()).map_err(ModelRunError::from)?;
            total.checked_add(bytes).ok_or(ModelRunError::Limit)
        })?;
        if input_bytes > self.maximum_tensor_bytes {
            return Err(RecordingError::InvalidRequest("model input tensor bound"));
        }
        Ok(end)
    }
}

/// Four independent cumulative work buckets for an entire call, not a fresh allowance per frame.
/// The codec budget may be supplied with its own cancellation flag. Parent context cancellation
/// is polled at composition boundaries; ScalarExecCx owns cancellation inside model execution.
#[derive(Debug)]
pub struct RecordingBudget<'a> {
    /// Shared canonical JPEG work budget, including work in refused decodes.
    pub decode: DecodeBudget<'a>,
    /// Shared detector and association budgets used to reconstruct the final complete report.
    pub analysis: AnalysisBudget,
    model_remaining: u64,
    model_charged: u64,
}
impl<'a> RecordingBudget<'a> {
    /// Construct independent allowances. Model units are the executor's reference-work counter,
    /// not hardware MAC throughput, CPU time, energy, or total process memory.
    #[must_use]
    pub fn new(decode: DecodeBudget<'a>, model_units: u64, analysis: AnalysisBudget) -> Self {
        Self { decode, analysis, model_remaining: model_units, model_charged: 0 }
    }
    /// Charged model work: exact original accounting for new successful runs, conservative
    /// reserved allowance for a failed attempt, and zero numeric work for verified cached runs.
    #[must_use]
    pub fn model_charged(&self) -> u64 { self.model_charged }
    /// Allowance still available. Failed execution reservations are deliberately not refunded.
    #[must_use]
    pub fn model_remaining(&self) -> u64 { self.model_remaining }

    fn reserve_model(&mut self) -> u64 {
        let reserved = self.model_remaining;
        self.model_remaining = 0;
        // charged + remaining is the original u64 allowance, so this cannot overflow.
        self.model_charged += reserved;
        reserved
    }
    fn settle_model(&mut self, reserved: u64, actual: u64) -> Result<(), RecordingError> {
        let unused = reserved.checked_sub(actual)
            .ok_or(RecordingError::InvalidRequest("executor exceeded its reserved work"))?;
        self.model_charged -= unused;
        self.model_remaining = unused;
        Ok(())
    }
}

/// Boundary reached by the operation. Completion means requested analysis, not scene observability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordingStage {
    /// Request/model metadata and original import validation.
    Preflight,
    /// Exact retained-source decoding or recovery.
    Decode,
    /// Frozen model execution or recovery.
    Inference,
    /// Complete deterministic detector/tracker reconstruction.
    Analysis,
    /// A complete report was constructed successfully.
    Complete,
}
impl RecordingStage {
    /// Stable spelling for local operator diagnostics.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Preflight => "preflight", Self::Decode => "decode", Self::Inference => "inference",
            Self::Analysis => "analysis", Self::Complete => "complete",
        }
    }
}

/// Exact retained progress, also returned on refusal. This is diagnostic state, never a trusted
/// tracker checkpoint or permission to skip verification when resuming.
#[derive(Clone, Debug)]
pub struct RecordingProgress {
    /// Boundary reached by the attempt.
    pub stage: RecordingStage,
    /// Pending source segment during preflight/decode/inference, otherwise None.
    pub next_segment: Option<usize>,
    /// Complete inference identities in original range order; no failed entry is fabricated.
    pub completed: Vec<AnalysisFrame>,
    /// Decodes newly completed by this call, including a decode before a later inference failure.
    pub new_decodes: usize,
    /// Completed decoded frames recovered without codec execution.
    pub reused_decodes: usize,
    /// Model invocations newly completed by this call.
    pub new_inferences: usize,
    /// Model invocations revalidated without numeric execution.
    pub reused_inferences: usize,
    /// Current deployment anchor at the returned boundary, not a new job-level authority claim.
    pub anchor: LedgerAnchor,
}

/// A complete analysis report plus execution/reuse accounting. Only the existing AnalysisReport
/// encoding is exported; this wrapper does not introduce a competing durable report format.
#[derive(Clone, Debug)]
pub struct RecordingOutcome {
    /// Complete existing canonical detector/tracker report, consumable by the event workflow.
    pub report: AnalysisReport,
    /// Retained inputs and final processing boundary.
    pub progress: RecordingProgress,
}

/// Failure with an exact retained prefix. A failure never contains a partial AnalysisReport.
#[derive(Debug)]
pub struct RecordingFailure {
    /// Typed primary cause.
    pub cause: RecordingError,
    /// Successful durable work remains available for an exact retry from the original range.
    pub progress: RecordingProgress,
}
impl fmt::Display for RecordingFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "recording analysis {}: {}", self.progress.stage.as_str(), self.cause)
    }
}
impl Error for RecordingFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> { Some(&self.cause) }
}

/// No implicit source, model, format, sampling, or repaired-custody fallback.
#[derive(Debug)]
pub enum RecordingError {
    /// Caller metadata or bounds do not describe an admitted recording analysis.
    InvalidRequest(&'static str),
    /// Parent cancellation at a composition boundary.
    Cancelled,
    /// Original retained import unavailable, damaged, or outside its read bounds.
    Source(Box<FileIngestError>),
    /// Canonical source decoding/recovery refused.
    Decode(Box<RecordedDecodeError>),
    /// Exact model execution/recovery refused.
    Model(Box<ModelRunError>),
    /// Complete detector/tracker reconstruction refused.
    Analysis(Box<AnalysisError>),
    /// Detector policy invalid before execution.
    Detection(DetectionError),
    /// Tracker policy invalid before execution.
    Tracking(TrackingError),
    /// Model execution context cancelled.
    Execution(ExecError),
}
impl fmt::Display for RecordingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(reason) => write!(f, "invalid recording request: {reason}"),
            Self::Cancelled => f.write_str("recording owner cancelled"),
            Self::Source(e) => write!(f, "{e}"), Self::Decode(e) => write!(f, "{e}"),
            Self::Model(e) => write!(f, "{e}"), Self::Analysis(e) => write!(f, "{e}"),
            Self::Detection(e) => write!(f, "{e}"), Self::Tracking(e) => write!(f, "{e}"),
            Self::Execution(e) => write!(f, "{e}"),
        }
    }
}
impl Error for RecordingError {}
macro_rules! conversion {
    ($source:ty, $variant:ident) => {
        impl From<$source> for RecordingError {
            fn from(e: $source) -> Self { Self::$variant(e.into()) }
        }
    };
}
conversion!(FileIngestError, Source);
conversion!(RecordedDecodeError, Decode);
conversion!(ModelRunError, Model);
conversion!(AnalysisError, Analysis);
conversion!(DetectionError, Detection);
conversion!(TrackingError, Tracking);
conversion!(ExecError, Execution);

fn checkpoint(cx: &ReplayCx, exec: &ScalarExecCx, stage: &'static str) -> Result<(), RecordingError> {
    cx.checkpoint(stage).map_err(|_| RecordingError::Cancelled)?;
    exec.checkpoint(stage)?;
    Ok(())
}

/// Compose retained source, canonical decoding, frozen inference and complete analysis.
///
/// Uses one frame/model at a time, no background worker or foreign runtime. Validate the entire
/// range and frozen detector metadata before creating derived publications. An exact retry starts
/// from the same range, revalidates existing custody, and rebuilds association history from its
/// original first frame. It never trusts caller-supplied progress as authority.
///
/// New inference attempts reserve the remaining model-work bucket before execution. Success
/// settles the reservation to actual executor accounting. Failure retains the reservation because
/// the executor does not return trustworthy partial work accounting. Reuse costs zero numeric
/// work, but still incurs bounded source/tensor reads and report reconstruction. Source I/O,
/// serialization, clones and total process memory are not priced by these numeric work buckets.
///
/// On failure all already committed frame/model results remain durable. A cut after an underlying
/// root but before its final receipt is recovered by that owner's exact retry path. This function
/// returns no partial complete report and creates no job-level event or effect authority.
pub fn run_recording(
    deployment: &mut ReferenceDeployment,
    request: &RecordingRequest,
    model: &RecordedModel,
    budget: &mut RecordingBudget<'_>,
    exec: &ScalarExecCx,
    cx: &ReplayCx,
) -> Result<RecordingOutcome, Box<RecordingFailure>> {
    let mut progress = RecordingProgress {
        stage: RecordingStage::Preflight, next_segment: Some(request.first_segment),
        completed: Vec::new(), new_decodes: 0, reused_decodes: 0,
        new_inferences: 0, reused_inferences: 0, anchor: deployment.current_anchor().clone(),
    };
    let result = (|| -> Result<AnalysisReport, RecordingError> {
        checkpoint(cx, exec, "recording_pipeline:preflight")?;
        let end = request.validate(model)?;
        let retained = RetainedFileImport::open(deployment, request.import_identity,
            request.limits.read_limits, cx)?;
        if retained.manifest().format != "mjpeg" || end > retained.manifest().segment_spans.len() {
            return Err(RecordingError::InvalidRequest("JPEG/MJPEG source range"));
        }
        progress.completed.reserve(request.segment_count);
        for segment_index in request.first_segment..end {
            progress.next_segment = Some(segment_index);
            progress.stage = RecordingStage::Decode;
            checkpoint(cx, exec, "recording_pipeline:decode")?;
            let source = RecordedDecodeRequest {
                import_identity: request.import_identity, segment_index,
                interpretation: request.interpretation, read_limits: request.limits.read_limits,
                decode_limits: request.limits.decode_limits,
            };
            let before = deployment.current_anchor().commit_sequence;
            let frame = RecordedFrame::decode_and_publish(deployment, &source, &mut budget.decode, cx)?;
            if frame.authority_anchor().commit_sequence > before { progress.new_decodes += 1; }
            else { progress.reused_decodes += 1; }
            let identity = RecordedInference::identity_for(&frame, model);
            drop(frame);
            progress.stage = RecordingStage::Inference;
            checkpoint(cx, exec, "recording_pipeline:inference")?;
            let run = match RecordedInference::open(deployment, identity, &source, cx) {
                Ok(existing) => {
                    if existing.allocated_tensor_bytes() > request.maximum_tensor_bytes as u64 {
                        return Err(RecordingError::InvalidRequest("cached invocation tensor bound"));
                    }
                    progress.reused_inferences += 1;
                    existing
                }
                Err(ModelRunError::Unavailable) => {
                    let reserved = budget.reserve_model();
                    // The owner separately checks completion existence. A lost completed root
                    // is therefore refused here rather than silently repaired as a cache miss.
                    let result = RecordedInference::run_and_publish(deployment, &source, model,
                        ExecBudget::new(reserved, request.maximum_tensor_bytes), exec, cx)?;
                    budget.settle_model(reserved, result.executed_macs())?;
                    progress.new_inferences += 1;
                    result
                }
                Err(error) => return Err(error.into()),
            };
            progress.completed.push(AnalysisFrame { segment_index, run_identity: run.identity() });
        }
        progress.next_segment = None;
        progress.stage = RecordingStage::Analysis;
        checkpoint(cx, exec, "recording_pipeline:analysis")?;
        let plan = AnalysisPlan::new(request.import_identity, request.interpretation,
            request.detector.clone(), request.tracking, progress.completed.clone())?;
        let report = AnalysisReport::read(deployment, &plan, &request.limits, &mut budget.analysis, cx)?;
        checkpoint(cx, exec, "recording_pipeline:complete")?;
        progress.stage = RecordingStage::Complete;
        Ok(report)
    })();
    progress.anchor = deployment.current_anchor().clone();
    match result {
        Ok(report) => Ok(RecordingOutcome { report, progress }),
        Err(cause) => Err(Box::new(RecordingFailure { cause, progress })),
    }
}
