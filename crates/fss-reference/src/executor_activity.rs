#![forbid(unsafe_code)]
//! Executor-backed activity observations for the unknown-presence policy (fss-2h5zq.51).
//!
//! One first-party Model IR graph, `model:fss-activity:v1`, runs on the scalar reference
//! executor over two natively decoded RGB frames of one recording: the evaluated frame and an
//! earlier reference frame of the same file. It computes the mean squared per-channel difference
//! of the unit-scaled pixels. A documented [`ActivityThresholdPolicy`] with its own generation
//! turns that score into an [`ExecutorModelResult`]:
//!
//! - score strictly greater than the threshold: [`ExecutorModelOutcome::Activity`];
//! - score at or below the threshold: [`ExecutorModelOutcome::NoActivity`], which is NOT
//!   absence: it never contradicts presence and never certifies a negative;
//! - any executor failure (budget, cancellation, typed error) or a missing or nonfinite score:
//!   [`ExecutorModelOutcome::Abstained`], never a "no detection".
//!
//! The score is an uncalibrated pixel-change measure, not a probability, an object class or an
//! identity. A file source has no live transport continuity, so every result carries
//! [`ExecutorContinuity::NotObservable`] instead of a continuity digest. The model invocation
//! receipt of an inline reference graph carries `fss-na:` sentinels; the result records that as
//! `reference_only`, and it is never activation-backed model evidence.

use std::fmt;

use fss_codec_mjpeg::ComponentInterpretation;
use fss_codec_mjpeg::color::RgbDecodeReceipt;
use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, Generation, SensorId};
use fss_model_ir::{
    AttrValue, AttributeMap, GraphNode, ModelIrError, ModelIrGraph, OpCode, TensorPort,
    compute_model_ir_digest,
};
use fss_tensor::{DType, Shape, Tensor, TensorError};

use crate::model_receipt::{
    ModelInvocationReceipt, ReceiptOutcome, ReceiptRecordContext, execute_and_record_receipt,
};
use crate::{ChannelTransform, ExecBudget, ExecError, PreprocessProgram, ScalarExecCx};

/// Canonical domain of a retained executor model result (`SCHEMA-DOMAIN-EXECUTOR-MODEL-RESULT-001`).
pub const EXECUTOR_MODEL_RESULT_DOMAIN: &str = "fss.executor_model_result.v1";
/// Canonical domain of the activity threshold policy identity
/// (`SCHEMA-DOMAIN-EXECUTOR-ACTIVITY-THRESHOLD-POLICY-001`).
pub const ACTIVITY_THRESHOLD_POLICY_DOMAIN: &str = "fss.executor_activity_threshold_policy.v1";
/// Canonical domain of a retained native RGB decode receipt record
/// (`SCHEMA-DOMAIN-RGB-DECODE-RECEIPT-001`).
pub const RGB_DECODE_RECEIPT_DOMAIN: &str = "fss.rgb_decode_receipt.v1";
/// Canonical domain of the activity model identity (graph digest, weights and preprocessing)
/// (`SCHEMA-DOMAIN-EXECUTOR-ACTIVITY-MODEL-001`).
pub const ACTIVITY_MODEL_DOMAIN: &str = "fss.executor_activity_model.v1";
/// Stable model generation string of the activity graph.
pub const ACTIVITY_MODEL_GENERATION: &str = "model:fss-activity:v1";
/// Graph output carrying the `[1, 1]` activity score.
pub const ACTIVITY_SCORE_OUTPUT: &str = "score";
/// Tensor generation shared by the activity graph ports and its input tensors.
pub const ACTIVITY_TENSOR_GENERATION: Generation = Generation(1);
/// Largest admitted frame (pixels) for the activity graph.
pub const MAX_ACTIVITY_MODEL_PIXELS: usize = 1 << 20;

/// Failures before a result can be formed. Executor failures are NOT errors: they become an
/// abstaining [`ExecutorModelResult`] bound to the failure receipt.
#[derive(Debug)]
pub enum ExecutorActivityError {
    /// Invalid dimensions, threshold, generation or frame binding.
    InvalidInput(&'static str),
    /// The activity graph could not be built or digested.
    Graph(ModelIrError),
    /// An input tensor could not be built.
    Tensor(TensorError),
    /// Preprocessing of decoded pixels into the input tensor failed.
    Preprocess(ExecError),
}

impl fmt::Display for ExecutorActivityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(what) => write!(f, "invalid executor activity input: {what}"),
            Self::Graph(error) => write!(f, "activity graph refused: {error}"),
            Self::Tensor(error) => write!(f, "activity tensor refused: {error}"),
            Self::Preprocess(error) => write!(f, "activity preprocessing refused: {error}"),
        }
    }
}

impl std::error::Error for ExecutorActivityError {}

impl From<ModelIrError> for ExecutorActivityError {
    fn from(error: ModelIrError) -> Self {
        Self::Graph(error)
    }
}

impl From<TensorError> for ExecutorActivityError {
    fn from(error: TensorError) -> Self {
        Self::Tensor(error)
    }
}

/// Documented threshold policy with its own generation.
///
/// Semantics: a finite score strictly greater than the threshold is activity; a finite score at
/// or below it is no activity (never absence). The threshold is an operating point over an
/// uncalibrated score, not a calibrated probability or a detection-accuracy claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivityThresholdPolicy {
    generation: u64,
    threshold_bits: u32,
}

impl ActivityThresholdPolicy {
    /// Threshold of the lab reference generation 1: a mean squared unit-scaled channel
    /// difference of 0.01 (a uniform shift of about 25 of 255 code values on every channel).
    pub const REFERENCE_THRESHOLD: f32 = 0.01;

    /// Builds a policy; the generation must be positive and the threshold finite and
    /// non-negative.
    pub fn new(generation: u64, threshold: f32) -> Result<Self, ExecutorActivityError> {
        if generation == 0 {
            return Err(ExecutorActivityError::InvalidInput(
                "threshold policy generation must be positive",
            ));
        }
        if !threshold.is_finite() || threshold < 0.0 {
            return Err(ExecutorActivityError::InvalidInput(
                "threshold must be finite and non-negative",
            ));
        }
        Ok(Self {
            generation,
            threshold_bits: threshold.to_bits(),
        })
    }

    /// The lab reference policy: generation 1 at [`Self::REFERENCE_THRESHOLD`].
    pub fn reference() -> Result<Self, ExecutorActivityError> {
        Self::new(1, Self::REFERENCE_THRESHOLD)
    }

    /// Policy generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Threshold value.
    #[must_use]
    pub fn threshold(&self) -> f32 {
        f32::from_bits(self.threshold_bits)
    }

    /// Domain-separated identity of the generation, the threshold bits and the comparison rule.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(ACTIVITY_THRESHOLD_POLICY_DOMAIN);
        encoder.u64(self.generation);
        encoder.u32(self.threshold_bits);
        encoder.text("activity_if_score_strictly_greater;no_activity_is_not_absence");
        ContentDigest::sha256(&encoder.finish())
    }

    /// Classifies one finite score. Nonfinite scores abstain.
    #[must_use]
    pub fn classify(&self, score: f32) -> ExecutorModelOutcome {
        if !score.is_finite() {
            return ExecutorModelOutcome::Abstained {
                reason: ExecutorAbstentionReason::NonFiniteScore,
                receipt_outcome: ReceiptOutcome::Ok,
            };
        }
        if score > self.threshold() {
            ExecutorModelOutcome::Activity {
                score_bits: score.to_bits(),
            }
        } else {
            ExecutorModelOutcome::NoActivity {
                score_bits: score.to_bits(),
            }
        }
    }
}

/// Why transport continuity is not observable for an executor result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContinuityNotObservableReason {
    /// A recorded file has no live transport continuity witness.
    FileSource,
}

impl ContinuityNotObservableReason {
    /// Stable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileSource => "file_source",
        }
    }
}

/// Transport continuity of the evaluated input. There is deliberately no digest variant here:
/// an executor result never fabricates a continuity witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutorContinuity {
    /// Continuity cannot be observed for this source.
    NotObservable {
        /// Why.
        reason: ContinuityNotObservableReason,
    },
}

/// Why an executor result abstains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutorAbstentionReason {
    /// The invocation receipt names a non-`ok` outcome (error, cancellation, budget).
    ExecutorFailed,
    /// The executor completed but the score output was missing or malformed.
    MissingScore,
    /// The score was NaN or infinite.
    NonFiniteScore,
}

impl ExecutorAbstentionReason {
    /// Stable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExecutorFailed => "executor_failed",
            Self::MissingScore => "missing_score",
            Self::NonFiniteScore => "nonfinite_score",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::ExecutorFailed => 1,
            Self::MissingScore => 2,
            Self::NonFiniteScore => 3,
        }
    }
}

/// Typed executor outcome under one threshold policy generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutorModelOutcome {
    /// Score strictly above the threshold: unknown activity, single-source, uncalibrated.
    Activity {
        /// Exact f32 bits of the score.
        score_bits: u32,
    },
    /// Score at or below the threshold. Not absence: coverage still governs negatives.
    NoActivity {
        /// Exact f32 bits of the score.
        score_bits: u32,
    },
    /// No usable score; says nothing about presence.
    Abstained {
        /// Why.
        reason: ExecutorAbstentionReason,
        /// Outcome recorded by the invocation receipt.
        receipt_outcome: ReceiptOutcome,
    },
}

impl ExecutorModelOutcome {
    /// Stable label: `activity`, `no_activity` or `abstained`.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Activity { .. } => "activity",
            Self::NoActivity { .. } => "no_activity",
            Self::Abstained { .. } => "abstained",
        }
    }

    /// The score, when one was produced.
    #[must_use]
    pub fn score(&self) -> Option<f32> {
        match self {
            Self::Activity { score_bits } | Self::NoActivity { score_bits } => {
                Some(f32::from_bits(*score_bits))
            }
            Self::Abstained { .. } => None,
        }
    }
}

/// Retained result of one executor invocation, bound to its receipts and source bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorModelResult {
    /// Stable model generation string ([`ACTIVITY_MODEL_GENERATION`]).
    pub model_generation: String,
    /// Graph, weights and preprocessing identity ([`ActivityExecutorModel::digest`]).
    pub model_digest: ContentDigest,
    /// Threshold policy generation.
    pub threshold_policy_generation: u64,
    /// Threshold policy identity ([`ActivityThresholdPolicy::digest`]).
    pub threshold_policy_digest: ContentDigest,
    /// Recording sensor identity.
    pub sensor_id: SensorId,
    /// Source bytes of the evaluated frame (the capsule's source digest).
    pub input_capture_root: ContentDigest,
    /// Canonical sensor capsule of the evaluated frame.
    pub capsule_digest: ContentDigest,
    /// Source bytes of the reference frame of the same recording.
    pub reference_capture_root: ContentDigest,
    /// Retained [`RGB_DECODE_RECEIPT_DOMAIN`] record of the evaluated frame.
    pub decode_receipt_digest: ContentDigest,
    /// Retained [`RGB_DECODE_RECEIPT_DOMAIN`] record of the reference frame.
    pub reference_decode_receipt_digest: ContentDigest,
    /// [`ModelInvocationReceipt::compute_canonical_digest`] of the invocation.
    pub invocation_receipt_digest: ContentDigest,
    /// SHA-256 of the retained canonical receipt JSON bytes.
    pub invocation_receipt_object: ContentDigest,
    /// True when the receipt carries `fss-na:` sentinels; never activation-backed evidence.
    pub reference_only: bool,
    /// Transport continuity; never a fabricated digest.
    pub continuity: ExecutorContinuity,
    /// Typed outcome.
    pub outcome: ExecutorModelOutcome,
}

impl ExecutorModelResult {
    /// Canonical object identity of the retained result bytes.
    #[must_use]
    pub fn object_digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.canonical_bytes())
    }

    /// An executor result never certifies absence, whatever its outcome.
    #[must_use]
    pub const fn supports_absence_claim(&self) -> bool {
        false
    }
}

impl CanonicalEncode for ExecutorModelResult {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(EXECUTOR_MODEL_RESULT_DOMAIN);
        encoder.text(&self.model_generation);
        encoder.digest(self.model_digest);
        encoder.u64(self.threshold_policy_generation);
        encoder.digest(self.threshold_policy_digest);
        self.sensor_id.encode_canonical(encoder);
        encoder.digest(self.input_capture_root);
        encoder.digest(self.capsule_digest);
        encoder.digest(self.reference_capture_root);
        encoder.digest(self.decode_receipt_digest);
        encoder.digest(self.reference_decode_receipt_digest);
        encoder.digest(self.invocation_receipt_digest);
        encoder.digest(self.invocation_receipt_object);
        encoder.bool(self.reference_only);
        match self.continuity {
            ExecutorContinuity::NotObservable { reason } => {
                encoder.u8(1);
                encoder.text(reason.as_str());
            }
        }
        match self.outcome {
            ExecutorModelOutcome::Activity { score_bits } => {
                encoder.u8(1);
                encoder.u32(score_bits);
            }
            ExecutorModelOutcome::NoActivity { score_bits } => {
                encoder.u8(2);
                encoder.u32(score_bits);
            }
            ExecutorModelOutcome::Abstained {
                reason,
                receipt_outcome,
            } => {
                encoder.u8(3);
                encoder.u8(reason.tag());
                encoder.text(receipt_outcome.as_str());
            }
        }
    }
}

/// Canonical bytes of a native RGB decode receipt, retained so a result can name it by digest.
#[must_use]
pub fn rgb_decode_receipt_bytes(receipt: &RgbDecodeReceipt) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(RGB_DECODE_RECEIPT_DOMAIN);
    encoder.bytes(&receipt.encoded_sha256);
    encoder.bytes(&receipt.rgb_sha256);
    encoder.bytes(&receipt.decoder);
    encoder.u8(match receipt.interpretation {
        ComponentInterpretation::Grayscale => 1,
        ComponentInterpretation::YCbCr => 2,
    });
    encoder.u32(receipt.dimensions[0]);
    encoder.u32(receipt.dimensions[1]);
    encoder.u64(receipt.mcus as u64);
    encoder.u64(receipt.entropy_blocks as u64);
    encoder.u64(receipt.restarts as u64);
    encoder.u64(receipt.metadata_segments as u64);
    encoder.u64(receipt.metadata_bytes as u64);
    encoder.finish()
}

/// One natively decoded frame and the identities binding it to its source bytes.
#[derive(Clone, Copy, Debug)]
pub struct ActivityFrameBinding<'a> {
    /// Tightly packed RGB pixels whose digest the receipt names.
    pub pixels: &'a [u8],
    /// Native decode receipt.
    pub receipt: RgbDecodeReceipt,
    /// Staged source bytes digest of this frame.
    pub source_digest: ContentDigest,
    /// Canonical sensor capsule digest of this frame.
    pub capsule_digest: ContentDigest,
}

/// The frozen activity graph and its uniform averaging weights for one frame size.
#[derive(Debug)]
pub struct ActivityExecutorModel {
    graph: ModelIrGraph,
    program: PreprocessProgram,
    weights: Vec<f32>,
    width: u32,
    height: u32,
    digest: ContentDigest,
}

impl ActivityExecutorModel {
    /// Builds the graph for `width` x `height` RGB frames:
    /// `score = MatMul(Reshape((frame - reference)^2, [1, 3HW]), w)` with `w = 1/(3HW)`.
    pub fn new(width: u32, height: u32) -> Result<Self, ExecutorActivityError> {
        let (w, h) = (width as usize, height as usize);
        let pixels = w
            .checked_mul(h)
            .filter(|n| *n > 0 && *n <= MAX_ACTIVITY_MODEL_PIXELS)
            .ok_or(ExecutorActivityError::InvalidInput("activity frame size"))?;
        let elements = pixels * 3;
        let g = ACTIVITY_TENSOR_GENERATION;
        let image = Shape::new(vec![1, 3, h, w])?;
        let mut flatten = AttributeMap::new();
        flatten.insert("shape".into(), AttrValue::IntList(vec![1, elements as i64]));
        let graph = ModelIrGraph::builder(ACTIVITY_MODEL_GENERATION, g)
            .add_input(TensorPort::new("frame", DType::F32, image.clone(), g)?)
            .add_input(TensorPort::new("reference", DType::F32, image, g)?)
            .add_input(TensorPort::new(
                "weights",
                DType::F32,
                Shape::new(vec![elements, 1])?,
                g,
            )?)
            .add_output(TensorPort::new(
                ACTIVITY_SCORE_OUTPUT,
                DType::F32,
                Shape::new(vec![1, 1])?,
                g,
            )?)
            .add_node(GraphNode::new(
                "node:delta",
                OpCode::Sub,
                "per-channel difference against the reference frame",
                vec!["frame".into(), "reference".into()],
                vec!["delta".into()],
                AttributeMap::new(),
            )?)
            .add_node(GraphNode::new(
                "node:energy",
                OpCode::Mul,
                "squared difference",
                vec!["delta".into(), "delta".into()],
                vec!["energy".into()],
                AttributeMap::new(),
            )?)
            .add_node(GraphNode::new(
                "node:flatten",
                OpCode::Reshape,
                "flatten to one row",
                vec!["energy".into()],
                vec!["flat".into()],
                flatten,
            )?)
            .add_node(GraphNode::new(
                "node:mean",
                OpCode::MatMul,
                "uniform mean, an uncalibrated change score",
                vec!["flat".into(), "weights".into()],
                vec![ACTIVITY_SCORE_OUTPUT.into()],
                AttributeMap::new(),
            )?)
            .build_and_validate()?;
        let weight = 1.0_f32 / elements as f32;
        let weights = vec![weight; elements];
        let program = PreprocessProgram::new(h, w, ChannelTransform::Rgb, true);
        let mut encoder = CanonicalEncoder::new();
        encoder.text(ACTIVITY_MODEL_DOMAIN);
        encoder.text(ACTIVITY_MODEL_GENERATION);
        encoder.digest(compute_model_ir_digest(&graph)?);
        encoder.bytes(&program.canonical_bytes());
        encoder.u64(elements as u64);
        encoder.u32(weight.to_bits());
        let digest = ContentDigest::sha256(&encoder.finish());
        Ok(Self {
            graph,
            program,
            weights,
            width,
            height,
            digest,
        })
    }

    /// Graph, preprocessing and weight identity.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    /// Frozen graph.
    #[must_use]
    pub const fn graph(&self) -> &ModelIrGraph {
        &self.graph
    }

    /// Runs the graph on the scalar executor and classifies the score.
    ///
    /// Executor failures are recorded in the receipt and become an abstaining result; only
    /// malformed caller inputs (frame size, pixel digest) are errors.
    #[allow(clippy::too_many_arguments)]
    pub fn invoke(
        &self,
        sensor_id: &SensorId,
        frame: ActivityFrameBinding<'_>,
        reference: ActivityFrameBinding<'_>,
        policy: &ActivityThresholdPolicy,
        budget: ExecBudget,
        job_id: &str,
        cx: &ScalarExecCx,
    ) -> Result<(ExecutorModelResult, ModelInvocationReceipt), ExecutorActivityError> {
        let frame_tensor = self.tensor(&frame)?;
        let reference_tensor = self.tensor(&reference)?;
        let weights = Tensor::from_values(
            Shape::new(vec![self.weights.len(), 1])?,
            &self.weights,
            ACTIVITY_TENSOR_GENERATION,
        )?;
        let inputs = [
            ("frame", frame_tensor),
            ("reference", reference_tensor),
            ("weights", weights),
        ];
        let (run, receipt) = execute_and_record_receipt(
            &self.graph,
            &inputs,
            budget,
            cx,
            ReceiptRecordContext {
                job_id,
                preprocess_program: Some(&self.program),
                model_package_root: None,
                virtual_clock: None,
            },
        );
        let outcome = match (&run, receipt.outcome) {
            (Ok(executed), ReceiptOutcome::Ok) => match executed
                .get_output(ACTIVITY_SCORE_OUTPUT)
                .map(|tensor| tensor.to_vec::<f32>())
            {
                Some(Ok(values)) if values.len() == 1 => policy.classify(values[0]),
                _ => ExecutorModelOutcome::Abstained {
                    reason: ExecutorAbstentionReason::MissingScore,
                    receipt_outcome: receipt.outcome,
                },
            },
            _ => ExecutorModelOutcome::Abstained {
                reason: ExecutorAbstentionReason::ExecutorFailed,
                receipt_outcome: receipt.outcome,
            },
        };
        let result = ExecutorModelResult {
            model_generation: ACTIVITY_MODEL_GENERATION.to_owned(),
            model_digest: self.digest,
            threshold_policy_generation: policy.generation(),
            threshold_policy_digest: policy.digest(),
            sensor_id: sensor_id.clone(),
            input_capture_root: frame.source_digest,
            capsule_digest: frame.capsule_digest,
            reference_capture_root: reference.source_digest,
            decode_receipt_digest: ContentDigest::sha256(&rgb_decode_receipt_bytes(&frame.receipt)),
            reference_decode_receipt_digest: ContentDigest::sha256(&rgb_decode_receipt_bytes(
                &reference.receipt,
            )),
            invocation_receipt_digest: receipt.compute_canonical_digest(),
            invocation_receipt_object: ContentDigest::sha256(
                receipt.to_json_canonical().as_bytes(),
            ),
            reference_only: receipt.is_reference_only(),
            continuity: ExecutorContinuity::NotObservable {
                reason: ContinuityNotObservableReason::FileSource,
            },
            outcome,
        };
        Ok((result, receipt))
    }

    fn tensor(&self, frame: &ActivityFrameBinding<'_>) -> Result<Tensor, ExecutorActivityError> {
        if frame.receipt.dimensions != [self.width, self.height] {
            return Err(ExecutorActivityError::InvalidInput(
                "frame dimensions differ from the activity graph",
            ));
        }
        if ContentDigest::sha256(frame.pixels).bytes() != frame.receipt.rgb_sha256 {
            return Err(ExecutorActivityError::InvalidInput(
                "pixels contradict their decode receipt",
            ));
        }
        if frame.source_digest.bytes() != frame.receipt.encoded_sha256 {
            return Err(ExecutorActivityError::InvalidInput(
                "decode receipt names other source bytes",
            ));
        }
        self.program
            .execute_bytes(
                frame.pixels,
                self.height as usize,
                self.width as usize,
                3,
                ACTIVITY_TENSOR_GENERATION,
            )
            .map_err(ExecutorActivityError::Preprocess)
    }
}
