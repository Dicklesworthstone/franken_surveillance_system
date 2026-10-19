#![forbid(unsafe_code)]
//! Independent replay of a retained native activity result from its original JPEG frames.
//!
//! This checks a computation, not custody, authorization, presence or absence. The caller owns
//! read permission and the independently selected model, policy, job, stream and budgets. No
//! configuration is recovered from the claimed score. Both native decodes and the scalar model
//! are executed again; exact result AND invocation bytes must match. No pixels are returned.

use std::fmt;

use fss_codec_mjpeg::color::{RgbDecodeLimits, decode_rgb};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeError};
use fss_core::{CanonicalDecode, ContentDigest, ContractError, SensorCapsule, SensorId, StreamId};

use crate::executor_activity::{
    ACTIVITY_MODEL_GENERATION, ActivityExecutorModel, ActivityFrameBinding,
    ActivityThresholdPolicy, ExecutorActivityError, ExecutorModelOutcome, ExecutorModelResult,
    MAX_ACTIVITY_MODEL_PIXELS, rgb_decode_receipt_bytes,
};
use crate::model_receipt::{ModelInvocationReceipt, ReceiptOutcome};
use crate::{ExecBudget, ScalarExecCx};

/// Explicit verifier-owned inputs to reproduce an invocation. Never populated from a conclusion.
#[derive(Clone, Debug)]
pub struct ActivityReplayPlan {
    /// Expected sensor for both original source capsules.
    pub sensor_id: SensorId,
    /// Expected stream generation for both capsules; the reference sequence must be earlier.
    pub stream_id: StreamId,
    /// Original invocation identity, independently selected by the caller.
    pub job_id: String,
    /// Independently selected threshold and generation, not an inferred operating point.
    pub policy: ActivityThresholdPolicy,
    /// Explicit native JPEG component interpretation for both frames.
    pub interpretation: ComponentInterpretation,
    /// Original scalar execution allowance; exact receipt reproduction binds this too.
    pub execution: ExecBudget,
}

/// The eight exact retained roles of one result. Roles may share content-addressed bytes.
#[derive(Clone, Copy, Debug)]
pub struct ActivityReplayInputs<'a> {
    /// Canonically encoded `ExecutorModelResult` offered for replay.
    pub result: &'a [u8],
    /// Exact canonical invocation JSON named by that result.
    pub invocation: &'a [u8],
    /// Original encoded evaluated JPEG, including metadata.
    pub frame_source: &'a [u8],
    /// Original encoded earlier JPEG, including metadata.
    pub reference_source: &'a [u8],
    /// Canonical evaluated-frame `SensorCapsule`.
    pub frame_capsule: &'a [u8],
    /// Canonical earlier-frame `SensorCapsule`, independently selected by the caller.
    pub reference_capsule: &'a [u8],
    /// Exact retained native RGB decode record for the evaluated frame.
    pub frame_decode: &'a [u8],
    /// Exact retained native RGB decode record for the reference frame.
    pub reference_decode: &'a [u8],
}

/// Byte and native-frame admission bounds; no smaller or partial result is substituted.
#[derive(Clone, Copy, Debug)]
pub struct ActivityReplayLimits {
    /// Maximum of each of the six metadata objects, checked before canonical decoding.
    pub max_metadata_bytes: usize,
    /// Sum of all eight input lengths, including repeated roles.
    pub max_input_bytes: usize,
    /// Combined packed RGB output bytes of both simultaneously retained decoded frames.
    /// Native decoder scratch and fixed activity preprocessing have their existing bounds.
    pub max_decoded_bytes: usize,
    /// Native JPEG syntax, pixel, metadata and per-frame RGB bounds.
    pub decode: RgbDecodeLimits,
}

impl Default for ActivityReplayLimits {
    fn default() -> Self {
        let mut decode = RgbDecodeLimits::default();
        decode.frame.maximum_pixels = MAX_ACTIVITY_MODEL_PIXELS;
        decode.maximum_output_bytes = 3 * MAX_ACTIVITY_MODEL_PIXELS;
        Self {
            max_metadata_bytes: 64 * 1024,
            max_input_bytes: 64 * 1024 * 1024,
            max_decoded_bytes: 6 * MAX_ACTIVITY_MODEL_PIXELS,
            decode,
        }
    }
}

/// Why no independently replayed result can be returned.
#[derive(Debug)]
pub enum ActivityReplayError {
    /// Invalid independently supplied configuration.
    InvalidPlan(&'static str),
    /// A byte allowance was exceeded before the corresponding allocation.
    Limit(&'static str),
    /// Exact source, capsule or decoder bindings disagree.
    Binding(&'static str),
    /// The expected model generation/identity or threshold generation/identity differs.
    RegistrationMismatch,
    /// Canonical metadata is malformed.
    Contract(ContractError),
    /// A native JPEG decode failed; no partial decoded frame is exposed.
    Decode(DecodeError),
    /// Model input, package or preprocessing failure.
    Activity(ExecutorActivityError),
    /// The offered or replayed invocation has no successful finite non-negative score.
    Unscored,
    /// Original result bytes or the complete invocation receipt do not reproduce.
    ReplayMismatch(&'static str),
    /// Owner cancellation; the scalar owner has been drained and finalized.
    Cancelled,
}

impl fmt::Display for ActivityReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPlan(field) => write!(f, "invalid activity replay plan: {field}"),
            Self::Limit(field) => write!(f, "activity replay byte allowance exhausted: {field}"),
            Self::Binding(field) => write!(f, "activity replay input binding differs: {field}"),
            Self::RegistrationMismatch => f.write_str("activity replay model or policy differs"),
            Self::Contract(error) => write!(f, "activity replay metadata: {error}"),
            Self::Decode(error) => write!(f, "activity replay native decode: {error}"),
            Self::Activity(error) => write!(f, "activity replay execution: {error}"),
            Self::Unscored => f.write_str("activity replay cannot verify an unsuccessful score"),
            Self::ReplayMismatch(field) => write!(f, "activity replay differs: {field}"),
            Self::Cancelled => f.write_str("activity replay cancelled"),
        }
    }
}
impl std::error::Error for ActivityReplayError {}
impl From<ContractError> for ActivityReplayError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}
impl From<ExecutorActivityError> for ActivityReplayError {
    fn from(error: ExecutorActivityError) -> Self {
        Self::Activity(error)
    }
}

/// A successfully re-executed computation. Private construction; not canonically decodable.
///
/// This is NOT an authority or retention proof. Use the retained-belief verifier separately for
/// current ledger membership. The uncalibrated score remains cognition, not a person detector.
#[derive(Debug)]
pub struct ReplayedActivityResult {
    result: ExecutorModelResult,
    invocation: ModelInvocationReceipt,
    decode_units: u64,
    decoded_bytes: usize,
}

impl ReplayedActivityResult {
    /// Independently recomputed result, byte-identical to the offered result.
    #[must_use]
    pub const fn result(&self) -> &ExecutorModelResult {
        &self.result
    }
    /// Complete reproduced invocation, including operator trace, budgets and output identities.
    #[must_use]
    pub const fn invocation(&self) -> &ModelInvocationReceipt {
        &self.invocation
    }
    /// Native JPEG reference work charged by this call; not wall time or scalar work.
    #[must_use]
    pub const fn decode_units(&self) -> u64 {
        self.decode_units
    }
    /// Combined packed RGB bytes held while executing the model.
    #[must_use]
    pub const fn decoded_bytes(&self) -> usize {
        self.decoded_bytes
    }
}

fn check(cx: &ScalarExecCx) -> Result<(), ActivityReplayError> {
    cx.checkpoint("activity_replay")
        .map_err(|_| ActivityReplayError::Cancelled)
}

fn scored(result: &ExecutorModelResult) -> bool {
    matches!(
        result.outcome,
        ExecutorModelOutcome::Activity { .. } | ExecutorModelOutcome::NoActivity { .. }
    ) && result
        .outcome
        .score()
        .is_some_and(|score| score.is_finite() && score >= 0.0)
}

/// Reproduces two native decodes and one scalar invocation under independent configuration.
///
/// The caller's mutable decode budget is shared across BOTH frames, never reset, and retains
/// charged work on failure. Its cancellation flag may be the caller's existing native flag;
/// scalar work uses `cx`. Cancellation from either owner returns no replay proof. The fixed
/// activity preprocessing bound is unchanged. The reference must be earlier in the same declared
/// stream; uncertain capture clocks are not upgraded to physical timing or continuity evidence.
///
/// Failed/abstaining historical results are deliberately unsupported by this success profile.
/// They remain abstentions rather than being replayed with a larger allowance into quietness.
/// A different original execution allowance or decoder implementation yields a receipt mismatch;
/// no approximate, cross-generation or score-only fallback is attempted.
pub fn replay_activity_result(
    model: &ActivityExecutorModel,
    plan: &ActivityReplayPlan,
    inputs: ActivityReplayInputs<'_>,
    limits: ActivityReplayLimits,
    decode_budget: &mut DecodeBudget<'_>,
    cx: &ScalarExecCx,
) -> Result<ReplayedActivityResult, ActivityReplayError> {
    check(cx)?;
    if plan.job_id.is_empty()
        || plan.job_id.len() > 128
        || !plan.job_id.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(ActivityReplayError::InvalidPlan("job identity"));
    }
    if limits.decode.frame.maximum_pixels > MAX_ACTIVITY_MODEL_PIXELS {
        return Err(ActivityReplayError::InvalidPlan("activity pixel ceiling"));
    }
    let metadata = [
        inputs.result,
        inputs.invocation,
        inputs.frame_capsule,
        inputs.reference_capsule,
        inputs.frame_decode,
        inputs.reference_decode,
    ];
    let mut total = 0_usize;
    for bytes in metadata {
        if bytes.len() > limits.max_metadata_bytes {
            return Err(ActivityReplayError::Limit("metadata"));
        }
        total = total
            .checked_add(bytes.len())
            .ok_or(ActivityReplayError::Limit("inputs"))?;
    }
    for bytes in [inputs.frame_source, inputs.reference_source] {
        if bytes.len() > limits.decode.frame.maximum_bytes {
            return Err(ActivityReplayError::Limit("source"));
        }
        total = total
            .checked_add(bytes.len())
            .ok_or(ActivityReplayError::Limit("inputs"))?;
    }
    if total > limits.max_input_bytes {
        return Err(ActivityReplayError::Limit("inputs"));
    }
    let offered = ExecutorModelResult::decode_canonical(inputs.result)?;
    if offered.model_generation != ACTIVITY_MODEL_GENERATION
        || offered.model_digest != model.digest()
        || offered.threshold_policy_generation != plan.policy.generation()
        || offered.threshold_policy_digest != plan.policy.digest()
    {
        return Err(ActivityReplayError::RegistrationMismatch);
    }
    if !scored(&offered) {
        return Err(ActivityReplayError::Unscored);
    }
    for (bytes, expected, role) in [
        (
            inputs.frame_source,
            offered.input_capture_root,
            "evaluated source",
        ),
        (
            inputs.reference_source,
            offered.reference_capture_root,
            "reference source",
        ),
        (
            inputs.frame_capsule,
            offered.capsule_digest,
            "evaluated capsule",
        ),
        (
            inputs.frame_decode,
            offered.decode_receipt_digest,
            "evaluated decode",
        ),
        (
            inputs.reference_decode,
            offered.reference_decode_receipt_digest,
            "reference decode",
        ),
        (
            inputs.invocation,
            offered.invocation_receipt_object,
            "invocation object",
        ),
    ] {
        if ContentDigest::sha256(bytes) != expected {
            return Err(ActivityReplayError::Binding(role));
        }
    }
    let frame_capsule = SensorCapsule::from_canonical_bytes(inputs.frame_capsule)?;
    let reference_capsule = SensorCapsule::from_canonical_bytes(inputs.reference_capsule)?;
    for (capsule, bytes, root) in [
        (
            &frame_capsule,
            inputs.frame_source,
            offered.input_capture_root,
        ),
        (
            &reference_capsule,
            inputs.reference_source,
            offered.reference_capture_root,
        ),
    ] {
        if capsule.sensor_id != plan.sensor_id
            || capsule.stream_id != plan.stream_id
            || capsule.source_digest != root
            || capsule.source_bytes != bytes.len() as u64
            || capsule.frame_count != 1
        {
            return Err(ActivityReplayError::Binding("source capsule"));
        }
    }
    if offered.sensor_id != plan.sensor_id || reference_capsule.sequence >= frame_capsule.sequence {
        return Err(ActivityReplayError::Binding("sensor or reference order"));
    }
    check(cx)?;
    let before = decode_budget.used();
    let mut frame_limits = limits.decode;
    frame_limits.maximum_output_bytes = frame_limits
        .maximum_output_bytes
        .min(limits.max_decoded_bytes);
    let native = |error| {
        if error == DecodeError::Cancelled {
            cx.drain_and_finalize();
            ActivityReplayError::Cancelled
        } else {
            ActivityReplayError::Decode(error)
        }
    };
    let frame = decode_rgb(
        inputs.frame_source,
        offered.input_capture_root.bytes(),
        plan.interpretation,
        frame_limits,
        decode_budget,
    )
    .map_err(native)?;
    check(cx)?;
    frame_limits.maximum_output_bytes = frame_limits
        .maximum_output_bytes
        .min(limits.max_decoded_bytes - frame.pixels().len());
    let reference = decode_rgb(
        inputs.reference_source,
        offered.reference_capture_root.bytes(),
        plan.interpretation,
        frame_limits,
        decode_budget,
    )
    .map_err(native)?;
    if rgb_decode_receipt_bytes(&frame.receipt()) != inputs.frame_decode
        || rgb_decode_receipt_bytes(&reference.receipt()) != inputs.reference_decode
    {
        return Err(ActivityReplayError::Binding("native decode record"));
    }
    check(cx)?;
    let (result, invocation) = model.invoke(
        &plan.sensor_id,
        ActivityFrameBinding {
            pixels: frame.pixels(),
            receipt: frame.receipt(),
            source_digest: offered.input_capture_root,
            capsule: &frame_capsule,
        },
        ActivityFrameBinding {
            pixels: reference.pixels(),
            receipt: reference.receipt(),
            source_digest: offered.reference_capture_root,
            capsule: &reference_capsule,
        },
        &plan.policy,
        plan.execution,
        &plan.job_id,
        cx,
    )?;
    check(cx)?;
    if invocation.outcome != ReceiptOutcome::Ok || !scored(&result) {
        return Err(ActivityReplayError::Unscored);
    }
    if invocation.to_json_canonical().as_bytes() != inputs.invocation {
        return Err(ActivityReplayError::ReplayMismatch("complete invocation"));
    }
    if result != offered {
        return Err(ActivityReplayError::ReplayMismatch("complete result"));
    }
    Ok(ReplayedActivityResult {
        result,
        invocation,
        decode_units: decode_budget.used() - before,
        decoded_bytes: frame.pixels().len() + reference.pixels().len(),
    })
}
