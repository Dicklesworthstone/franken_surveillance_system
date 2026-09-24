#![forbid(unsafe_code)]
//! Native JPEG -> frozen RGB neural execution -> resumable detector-head projection.
//!
//! One owner retains completed inference across postprocessing failure. New frames
//! are refused while that result is pending; resume never decodes or executes the
//! graph again. This is in-process computation, not durable source custody, a
//! trained detector distribution, sequence coverage, a tracker or effect authority.

use super::super::rgb_inference::{
    RgbInference, RgbInferenceError, RgbInferenceModel, RgbRunLimits, RgbSourceBinding,
};
use super::{
    RgbDetectionBudget, RgbDetectionContract, RgbDetectionError, RgbDetectionReport,
    project_rgb_detections,
};
use crate::{ExecBudget, ScalarExecCx};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget};

/// Borrowed owner-framed source and exact permission/capture bindings.
#[derive(Clone, Copy)]
pub struct RgbDetectionInput<'a> {
    /// Entire JPEG bytes. Their persistent custody remains with the source owner.
    pub bytes: &'a [u8],
    /// Explicit grayscale or YCbCr source interpretation.
    pub interpretation: ComponentInterpretation,
    /// Original source, camera, clock, capture interval and permission identities.
    pub source: RgbSourceBinding,
    /// Exact source-grid mask. A bounded copy is retained before inference begins.
    pub allowed: &'a [u8],
}
/// Outer failures happen before accepting a new inference; existing pending state survives.
#[derive(Debug)]
pub enum RgbDetectorError {
    /// The frozen head contract belongs to a different exact model.
    ModelContractMismatch,
    /// Complete prior inference awaits projection/resume or explicit retirement.
    PendingFrame,
    /// No accepted inference exists to resume.
    NoPendingFrame,
    /// Bounded mask-copy size, allocation or preprocessing reservation was refused.
    InputLimit,
    /// Source decode, privacy projection, resize, graph execution or cancellation failed.
    Inference(RgbInferenceError),
}
impl From<RgbInferenceError> for RgbDetectorError {
    fn from(error: RgbInferenceError) -> Self {
        Self::Inference(error)
    }
}
impl std::fmt::Display for RgbDetectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ModelContractMismatch => "RGB detector model contract mismatch",
            Self::PendingFrame => "RGB detector has pending inference",
            Self::NoPendingFrame => "RGB detector has no pending inference",
            Self::InputLimit => "RGB detector retained-mask bound",
            Self::Inference(_) => "RGB detector source or inference failed",
        })
    }
}
impl std::error::Error for RgbDetectorError {}

/// Exact completed model outputs and owned permissions awaiting detector projection.
#[derive(Debug)]
pub struct PendingRgbDetection {
    inference: RgbInference,
    allowed: Vec<u8>,
    mask_copy_work: u64,
}
impl PendingRgbDetection {
    /// Complete immutable neural result, even when postprocessing was refused.
    pub fn inference(&self) -> &RgbInference {
        &self.inference
    }
    /// Original admitted source mask; later caller buffer changes cannot reinterpret it.
    pub fn allowed(&self) -> &[u8] {
        &self.allowed
    }
    /// Additional mask-copy byte units reserved from preprocessing, beyond inference accounting.
    pub fn mask_copy_work(&self) -> u64 {
        self.mask_copy_work
    }
    /// Transfer the input of the failed stage for explicit diagnosis/reprocessing.
    pub fn into_parts(self) -> (RgbInference, Vec<u8>) {
        (self.inference, self.allowed)
    }
}
/// Complete coupled original inference, permissions and detector decisions.
#[derive(Debug)]
pub struct RgbDetectionRun {
    pending: PendingRgbDetection,
    report: RgbDetectionReport,
}
impl RgbDetectionRun {
    /// Complete model outputs and exact source/transform receipt.
    pub fn inference(&self) -> &RgbInference {
        &self.pending.inference
    }
    /// Owned exact source-grid permission mask for later reproduction.
    pub fn allowed(&self) -> &[u8] {
        &self.pending.allowed
    }
    /// Complete source-space detector decisions; empty is not verified absence.
    pub fn report(&self) -> &RgbDetectionReport {
        &self.report
    }
    /// Mask retention work, additional to inference's preprocessing work counter.
    pub fn mask_copy_work(&self) -> u64 {
        self.pending.mask_copy_work
    }
    /// Transfer all accepted stage evidence together, without losing a source handle.
    pub fn into_parts(self) -> (PendingRgbDetection, RgbDetectionReport) {
        (self.pending, self.report)
    }
}
/// Result of bounded progress after a model inference was accepted.
// Keep the accepted evidence inline; completion must not require another heap allocation.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum RgbDetectionStep {
    /// Inference and all detector decisions completed; the owner is ready for another input.
    Complete(RgbDetectionRun),
    /// Projection refused; inspect pending(), resume only this stage, or retire explicitly.
    Pending(RgbDetectionError),
}

/// One synchronous owner for a fixed model/head contract and at most one pending frame.
/// No camera selection, automatic retry, model reset, source deduplication or threads.
#[derive(Debug)]
pub struct RgbDetector<'a> {
    model: &'a RgbInferenceModel,
    contract: &'a RgbDetectionContract,
    pending: Option<PendingRgbDetection>,
}
impl<'a> RgbDetector<'a> {
    /// Bind already-admitted immutable programs. Matching hashes do not grant authority.
    pub fn new(
        model: &'a RgbInferenceModel,
        contract: &'a RgbDetectionContract,
    ) -> Result<Self, RgbDetectorError> {
        if model.digest() != contract.spec().model {
            return Err(RgbDetectorError::ModelContractMismatch);
        }
        Ok(Self {
            model,
            contract,
            pending: None,
        })
    }
    /// Accepted outputs that must not be hidden by optional-stage failure.
    pub fn pending(&self) -> Option<&PendingRgbDetection> {
        self.pending.as_ref()
    }

    /// Execute one JPEG only when there is no pending result. The preprocessing budget
    /// reserves the owned mask copy as extra bytes/work, in addition to the existing
    /// inference reservation. An outer error does not replace an accepted prior frame.
    /// Once inference succeeds, every projection error returns Pending and retains it.
    #[allow(clippy::too_many_arguments)]
    pub fn run_jpeg(
        &mut self,
        input: RgbDetectionInput<'_>,
        limits: RgbRunLimits,
        decoder: &mut DecodeBudget<'_>,
        postprocess: &mut RgbDetectionBudget,
        cx: &ScalarExecCx,
    ) -> Result<RgbDetectionStep, RgbDetectorError> {
        if self.pending.is_some() {
            return Err(RgbDetectorError::PendingFrame);
        }
        cx.checkpoint("rgb-detector:retain-mask")
            .map_err(RgbInferenceError::from)?;
        let count = input.allowed.len();
        if count == 0 || count > 4_194_304 {
            return Err(RgbDetectorError::InputLimit);
        }
        let mut adjusted = limits;
        adjusted.preprocess = ExecBudget::new(
            limits
                .preprocess
                .max_macs
                .checked_sub(count as u64)
                .ok_or(RgbDetectorError::InputLimit)?,
            limits
                .preprocess
                .max_bytes
                .checked_sub(count)
                .ok_or(RgbDetectorError::InputLimit)?,
        );
        let mut allowed = Vec::new();
        allowed
            .try_reserve_exact(count)
            .map_err(|_| RgbDetectorError::InputLimit)?;
        for chunk in input.allowed.chunks(4096) {
            cx.checkpoint("rgb-detector:mask-copy")
                .map_err(RgbInferenceError::from)?;
            allowed.extend_from_slice(chunk);
        }
        let inference = self.model.run_jpeg(
            input.bytes,
            input.interpretation,
            input.source,
            &allowed,
            adjusted,
            decoder,
            cx,
        )?;
        self.pending = Some(PendingRgbDetection {
            inference,
            allowed,
            mask_copy_work: count as u64,
        });
        self.resume(postprocess, cx)
    }

    /// Resume only projection of the same accepted outputs/mask. Failure never takes
    /// the pending value. Completion transfers it after the final cancellation poll.
    pub fn resume(
        &mut self,
        budget: &mut RgbDetectionBudget,
        cx: &ScalarExecCx,
    ) -> Result<RgbDetectionStep, RgbDetectorError> {
        let pending = self
            .pending
            .as_ref()
            .ok_or(RgbDetectorError::NoPendingFrame)?;
        match project_rgb_detections(
            &pending.inference,
            self.contract,
            &pending.allowed,
            budget,
            cx,
        ) {
            Ok(report) => {
                let pending = self
                    .pending
                    .take()
                    .ok_or(RgbDetectorError::NoPendingFrame)?;
                Ok(RgbDetectionStep::Complete(RgbDetectionRun {
                    pending,
                    report,
                }))
            }
            Err(error) => Ok(RgbDetectionStep::Pending(error)),
        }
    }

    /// Explicitly end this owner and transfer any unfinished stage. Do not silently
    /// discard a pending frame to admit a new one or claim that its scene was empty.
    #[must_use]
    pub fn retire(self) -> Option<PendingRgbDetection> {
        self.pending
    }
}
