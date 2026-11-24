#![forbid(unsafe_code)]
//! Safe SIMD image transform candidates with same-binary A/A and A/B gates
//! (FSS-123 / `fss-x4a.12.22`, WP-060).
//!
//! ## Architectural contract
//!
//! - **Zero pointer tricks:** every candidate kernel uses safe fixed-lane
//!   chunked loops (`RESIZE_TILE_LANES = 8`, `RGB_LANES = 8`,
//!   `NORMALIZE_LANES = 16`) that LLVM auto-vectorizes cleanly across x86_64
//!   and AArch64 while remaining strictly memory-safe and portable.
//! - **Bit-identical to the scalar oracle (`FSS-122`):** each candidate matches
//!   [`crate::image_kernels::resize_bilinear_luma`],
//!   [`crate::image_kernels::rgb_to_luma`], and
//!   [`crate::image_kernels::normalize_luma`] byte-for-byte with zero numeric
//!   drift (`MODEL-INV-009`).
//! - **Same-binary A/A and A/B gates (`FSS-196`):** every admission emits real
//!   [`fss_core::experiment::ExperimentReceipt`] (`fss.experiment_receipt.v1`)
//!   records under one immutable `binary_identity`:
//!   - **A/A** runs the candidate twice on identical inputs/seed; divergence is
//!     a hard determinism alarm that quarantines the candidate generation.
//!   - **A/B** compares `"scalar-reference.v1"` against `"safe-simd.v1"` under
//!     the exact same binary identity, input digest, and schedule seed.
//!   - **Indeterminate runs never compare** and never certify a candidate.
//! - **Explicit failure, cancellation, authority, privacy, and pressure states:**
//!   never silently downgrades or hides divergence, cancellation, stale
//!   generations, unapproved privacy clearance, or budget exhaustion.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use fss_core::experiment::{
    ComparisonOutcome, ExperimentError, ExperimentKind, ExperimentReceipt, ExperimentRun,
};
use fss_core::{
    CanonicalEncoder, ContentDigest, DigestAlgorithm, Generation, ResourcePressure, TimestampNs,
};

use crate::image_kernels::{
    ImageKernelError, MAX_AXIS, normalize_luma, resize_bilinear_luma, rgb_to_luma,
};

/// Fixed horizontal lane width for safe bilinear resize tiles.
pub const RESIZE_TILE_LANES: usize = 8;
/// Fixed pixel lane width for safe RGB-to-luma deinterleaved vector MACs (24 bytes/chunk).
pub const RGB_LANES: usize = 8;
/// Fixed byte lane width for safe min/max luma reduction and LUT mapping.
pub const NORMALIZE_LANES: usize = 16;
/// Minimum plane size where the 256-entry exact LUT path beats direct lane scaling.
pub const NORMALIZE_LUT_THRESHOLD: usize = 256;
/// Maximum UTF-8 bytes allowed for label fields (toolchain, principal, experiment ID).
pub const MAX_LABEL_BYTES: usize = 128;
/// Maximum UTF-8 bytes allowed for reason/guidance strings.
pub const MAX_REASON_BYTES: usize = 512;
/// Maximum number of gate receipts retained in one [`SameBinaryImageGate`] ledger.
pub const MAX_GATE_RECEIPTS: usize = 256;
/// Digest domain for safe SIMD image kernel generation and gate receipts.
pub const IMAGE_KERNEL_SIMD_DOMAIN: &str = "fss.reference.image_kernels_simd.v1";

/// Which kernel implementation executed an image transform.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ImageKernelBackend {
    /// Deterministic scalar reference oracle (FSS-122).
    ScalarReferenceV1,
    /// Safe auto-vectorized fixed-lane SIMD candidate (FSS-123).
    SafeSimdV1,
}

impl ImageKernelBackend {
    /// Stable lowercase variant label recorded in `ExperimentReceipt` and logs.
    #[must_use]
    pub const fn stable_id(self) -> &'static str {
        match self {
            Self::ScalarReferenceV1 => "scalar-reference.v1",
            Self::SafeSimdV1 => "safe-simd.v1",
        }
    }

    /// Source-bound immutable kernel generation digest (`INV-045`).
    #[must_use]
    pub fn kernel_generation(self) -> ContentDigest {
        match self {
            Self::ScalarReferenceV1 => scalar_image_kernel_generation(),
            Self::SafeSimdV1 => simd_image_kernel_generation(),
        }
    }
}

/// Which image transform operator is requested.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ImageKernelOp {
    /// Q16 center-mapped bilinear luma resize.
    ResizeBilinearLuma,
    /// ITU-R BT.601 integer packed RGB to luma conversion.
    RgbToLuma,
    /// Fixed-point per-image min/max luma normalization.
    NormalizeLuma,
}

impl ImageKernelOp {
    /// Stable lowercase operator spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResizeBilinearLuma => "resize_bilinear_luma",
            Self::RgbToLuma => "rgb_to_luma",
            Self::NormalizeLuma => "normalize_luma",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::ResizeBilinearLuma => 1,
            Self::RgbToLuma => 2,
            Self::NormalizeLuma => 3,
        }
    }
}

/// Concrete transform request specifying input bytes and operator parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImageTransformRequest<'a> {
    /// Resize packed u8 luma plane `(src_w x src_h)` to `(dst_w x dst_h)`.
    ResizeBilinearLuma {
        /// Source luma pixels.
        src: &'a [u8],
        /// Source width.
        src_w: usize,
        /// Source height.
        src_h: usize,
        /// Destination width.
        dst_w: usize,
        /// Destination height.
        dst_h: usize,
    },
    /// Convert packed 24-bit RGB buffer to packed u8 luma.
    RgbToLuma {
        /// Packed `[R, G, B, ...]` input bytes.
        rgb: &'a [u8],
    },
    /// Normalize packed u8 luma plane `(width x height)` with explicit constant fill.
    NormalizeLuma {
        /// Source luma pixels.
        plane: &'a [u8],
        /// Plane width.
        width: usize,
        /// Plane height.
        height: usize,
        /// Fill value emitted for constant images (`max == min`).
        constant_fill: u8,
    },
}

impl ImageTransformRequest<'_> {
    /// Operator kind of this request.
    #[must_use]
    pub const fn op(&self) -> ImageKernelOp {
        match self {
            Self::ResizeBilinearLuma { .. } => ImageKernelOp::ResizeBilinearLuma,
            Self::RgbToLuma { .. } => ImageKernelOp::RgbToLuma,
            Self::NormalizeLuma { .. } => ImageKernelOp::NormalizeLuma,
        }
    }

    /// Input byte length.
    #[must_use]
    pub const fn input_bytes(&self) -> usize {
        match self {
            Self::ResizeBilinearLuma { src, .. } => src.len(),
            Self::RgbToLuma { rgb } => rgb.len(),
            Self::NormalizeLuma { plane, .. } => plane.len(),
        }
    }

    /// Checked expected output byte length (returns `None` on invalid/overflowing dimensions).
    #[must_use]
    pub fn expected_output_bytes(&self) -> Option<usize> {
        match *self {
            Self::ResizeBilinearLuma { dst_w, dst_h, .. } => dst_w.checked_mul(dst_h),
            Self::RgbToLuma { rgb } => {
                if rgb.len().is_multiple_of(3) {
                    Some(rgb.len() / 3)
                } else {
                    None
                }
            }
            Self::NormalizeLuma { width, height, .. } => width.checked_mul(height),
        }
    }

    /// Canonical digest over operator, geometry parameters, and exact input bytes.
    #[must_use]
    pub fn inputs_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text("image_kernel_inputs.v1");
        enc.u8(self.op().tag());
        match *self {
            Self::ResizeBilinearLuma {
                src,
                src_w,
                src_h,
                dst_w,
                dst_h,
            } => {
                enc.u64(src_w as u64);
                enc.u64(src_h as u64);
                enc.u64(dst_w as u64);
                enc.u64(dst_h as u64);
                enc.digest(ContentDigest::sha256(src));
            }
            Self::RgbToLuma { rgb } => {
                enc.u64(rgb.len() as u64);
                enc.digest(ContentDigest::sha256(rgb));
            }
            Self::NormalizeLuma {
                plane,
                width,
                height,
                constant_fill,
            } => {
                enc.u64(width as u64);
                enc.u64(height as u64);
                enc.u8(constant_fill);
                enc.digest(ContentDigest::sha256(plane));
            }
        }
        ContentDigest::sha256(&enc.finish())
    }
}

/// Source-bound immutable identity of the FSS-122 scalar reference kernels.
#[must_use]
pub fn scalar_image_kernel_generation() -> ContentDigest {
    let mut enc = CanonicalEncoder::new();
    enc.text(IMAGE_KERNEL_SIMD_DOMAIN);
    enc.text(ImageKernelBackend::ScalarReferenceV1.stable_id());
    enc.digest(ContentDigest::sha256(
        include_bytes!("image_kernels.rs").as_slice(),
    ));
    ContentDigest::sha256(&enc.finish())
}

/// Source- and lane-bound immutable identity of the FSS-123 safe SIMD kernels,
/// including the scalar oracle they must match bit-for-bit.
#[must_use]
pub fn simd_image_kernel_generation() -> ContentDigest {
    let mut enc = CanonicalEncoder::new();
    enc.text(IMAGE_KERNEL_SIMD_DOMAIN);
    enc.text(ImageKernelBackend::SafeSimdV1.stable_id());
    enc.u64(RESIZE_TILE_LANES as u64);
    enc.u64(RGB_LANES as u64);
    enc.u64(NORMALIZE_LANES as u64);
    enc.u64(NORMALIZE_LUT_THRESHOLD as u64);
    enc.digest(ContentDigest::sha256(
        include_bytes!("image_kernels_simd.rs").as_slice(),
    ));
    enc.digest(scalar_image_kernel_generation());
    ContentDigest::sha256(&enc.finish())
}

/// Same-binary identity digest binding toolchain ID and both kernel generations
/// (`FSS-196` `ExperimentRun::binary_identity`).
#[must_use]
pub fn same_binary_identity(toolchain_id: &str) -> ContentDigest {
    let mut enc = CanonicalEncoder::new();
    enc.text("fss.same_binary_image_kernels.v1");
    enc.text(toolchain_id);
    enc.digest(scalar_image_kernel_generation());
    enc.digest(simd_image_kernel_generation());
    ContentDigest::sha256(&enc.finish())
}

/// Hard resource budget enforced before and during every image transform.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageTransformBudget {
    /// Maximum admitted input bytes.
    pub max_input_bytes: usize,
    /// Maximum admitted output bytes.
    pub max_output_bytes: usize,
    /// Maximum admitted work units (output pixels processed).
    pub max_work_units: u64,
}

impl Default for ImageTransformBudget {
    fn default() -> Self {
        let max_plane = MAX_AXIS * MAX_AXIS;
        Self {
            max_input_bytes: max_plane * 3,
            max_output_bytes: max_plane,
            max_work_units: max_plane as u64,
        }
    }
}

/// Measured operation-cost row for one transform execution (`DOC-039`, `INV-045`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ImageTransformCost {
    /// Input bytes inspected.
    pub input_bytes: usize,
    /// Output bytes produced (`0` on refusal, quarantine, or cancellation).
    pub output_bytes: usize,
    /// Logical work units (output pixels evaluated before completion or cancellation).
    pub work_units: u64,
    /// Number of full fixed-lane SIMD chunks processed.
    pub simd_chunks: u64,
    /// Number of scalar tail pixels processed after full chunks.
    pub scalar_tail_items: u64,
    /// Peak scratch / precomputed tap-table / LUT bytes allocated.
    pub scratch_bytes: usize,
}

/// Deterministic fault injection hook for testing gate divergence, A/A
/// non-determinism alarms, and indeterminate comparisons without modifying
/// production kernels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateFaultInjection {
    /// Perturb the candidate output on the second A/A run (triggers A/A determinism alarm).
    AaSecondRunFlipBit,
    /// Perturb the candidate output relative to the scalar reference (triggers A/B divergence).
    AbCandidateFlipByte,
    /// Omit candidate outcome digest (triggers `ComparisonOutcome::Indeterminate`).
    CandidateOutcomeIndeterminate,
    /// Omit reference outcome digest (triggers `ComparisonOutcome::Indeterminate`).
    ReferenceOutcomeIndeterminate,
}

/// Explicit authority, privacy, generation, pressure, budget, and cancellation
/// context supplied to every gated transform (`INV-002`, `INV-044`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageKernelCx {
    /// Caller principal performing the read/transform.
    pub principal: String,
    /// Governing `ContractBasis` digest.
    pub contract_basis_digest: ContentDigest,
    /// Source-stream / preprocessing generation bound to the input buffer.
    pub source_generation: Generation,
    /// Expected generation required by the consumer/pipeline anchor.
    pub expected_generation: Generation,
    /// True iff privacy masking/capability projection cleared this buffer for transform.
    pub privacy_cleared: bool,
    /// Observed host resource pressure.
    pub pressure: ResourcePressure,
    /// Hard work/memory budget for this transform.
    pub budget: ImageTransformBudget,
    /// Optional deterministic schedule seed recorded in `ExperimentReceipt`.
    pub schedule_seed: Option<u64>,
    /// Optional deterministic cancellation checkpoint (cancels after `n` SIMD chunks).
    pub cancel_after_chunks: Option<u64>,
    /// Optional laboratory fault injection for gate-rejection/fallback proof tests.
    pub fault_injection: Option<GateFaultInjection>,
}

impl ImageKernelCx {
    /// Constructs a nominal, privacy-cleared execution context for one generation.
    #[must_use]
    pub fn nominal(
        principal: impl Into<String>,
        contract_basis_digest: ContentDigest,
        generation: Generation,
    ) -> Self {
        Self {
            principal: principal.into(),
            contract_basis_digest,
            source_generation: generation,
            expected_generation: generation,
            privacy_cleared: true,
            pressure: ResourcePressure::Nominal,
            budget: ImageTransformBudget::default(),
            schedule_seed: Some(0),
            cancel_after_chunks: None,
            fault_injection: None,
        }
    }

    fn validate(&self) -> Result<(), SimdKernelError> {
        validate_label("principal", &self.principal)?;
        validate_digest("contract_basis_digest", self.contract_basis_digest)?;
        if !self.privacy_cleared {
            return Err(SimdKernelError::PrivacyRefused {
                detail: "buffer lacks privacy/capability projection clearance before transform"
                    .to_owned(),
            });
        }
        if self.source_generation != self.expected_generation {
            return Err(SimdKernelError::StaleGeneration {
                source: self.source_generation,
                expected: self.expected_generation,
            });
        }
        Ok(())
    }
}

/// What the same-binary gate does when a candidate fails certification or is
/// already quarantined.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateFailureAction {
    /// Fail closed: emit `TransformOutcome::Quarantined` and zero output bytes.
    Quarantine,
    /// Fall back explicitly to the scalar reference oracle with an audit receipt
    /// recording the exact reason and negative evidence (`FallbackToScalar`).
    FallbackToScalar,
}

/// Governance policy for [`SameBinaryImageGate`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatePolicy {
    /// Toolchain identity bound into `same_binary_identity`.
    pub toolchain_id: String,
    /// Whether an A/A same-binary determinism proof is mandatory before A/B admission.
    pub require_aa_check: bool,
    /// Highest [`ResourcePressure`] under which the SIMD candidate may execute
    /// (above this threshold, policy refuses or falls back explicitly).
    pub max_candidate_pressure: ResourcePressure,
    /// Action taken if the SIMD candidate fails A/A, diverges on A/B, or is indeterminate.
    pub on_gate_failure: GateFailureAction,
}

impl Default for GatePolicy {
    fn default() -> Self {
        Self {
            toolchain_id: "nightly-2026-08-31-x86_64-unknown-linux-gnu".to_owned(),
            require_aa_check: true,
            max_candidate_pressure: ResourcePressure::Elevated,
            on_gate_failure: GateFailureAction::Quarantine,
        }
    }
}

impl GatePolicy {
    /// Validates policy bounds.
    pub fn validate(&self) -> Result<(), SimdKernelError> {
        validate_label("toolchain_id", &self.toolchain_id)
    }
}

/// Status of one candidate operator in the same-binary gate state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidateGateState {
    /// Not yet evaluated against the scalar oracle.
    Staged,
    /// Certified bit-identical by both A/A determinism and A/B same-binary receipts.
    Certified {
        /// Digest of the certifying `SameBinaryGateReceipt`.
        receipt_digest: ContentDigest,
        /// Timestamp when certified.
        certified_at: TimestampNs,
    },
    /// Quarantined after A/A determinism alarm, A/B divergence, or indeterminate run.
    Quarantined {
        /// Machine-readable reason.
        reason: String,
        /// Digest of the negative-evidence `SameBinaryGateReceipt`.
        receipt_digest: ContentDigest,
        /// Timestamp when quarantined.
        quarantined_at: TimestampNs,
    },
}

/// Honest reason why execution fell back from the SIMD candidate to scalar reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FallbackReason {
    /// Candidate failed A/A determinism check.
    AaDeterminismAlarm,
    /// Candidate diverged from scalar reference under A/B comparison.
    AbDivergence,
    /// Candidate or reference comparison was indeterminate.
    ComparisonIndeterminate,
    /// Candidate was previously quarantined for this operator/generation.
    PreviouslyQuarantined,
    /// Host resource pressure exceeded `GatePolicy::max_candidate_pressure`.
    PressureDegraded,
}

impl FallbackReason {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AaDeterminismAlarm => "aa_determinism_alarm",
            Self::AbDivergence => "ab_divergence",
            Self::ComparisonIndeterminate => "comparison_indeterminate",
            Self::PreviouslyQuarantined => "previously_quarantined",
            Self::PressureDegraded => "pressure_degraded",
        }
    }
}

/// Verdict of one same-binary certification run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateVerdict {
    /// Both A/A (if required) and A/B passed with `ComparisonOutcome::Identical`.
    Admitted,
    /// A/A runs diverged under identical binary/inputs/seed — determinism alarm!
    RejectedAaAlarm,
    /// A/B candidate diverged from scalar reference.
    RejectedAbDivergence,
    /// At least one run had no comparable outcome — never forced to pass.
    Indeterminate,
}

impl GateVerdict {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::RejectedAaAlarm => "rejected_aa_alarm",
            Self::RejectedAbDivergence => "rejected_ab_divergence",
            Self::Indeterminate => "indeterminate",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Admitted => 1,
            Self::RejectedAaAlarm => 2,
            Self::RejectedAbDivergence => 3,
            Self::Indeterminate => 4,
        }
    }
}

/// Durable, canonical receipt proving one same-binary A/A + A/B gate evaluation
/// (`FSS-123` + `FSS-196`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SameBinaryGateReceipt {
    /// Operator evaluated.
    pub op: ImageKernelOp,
    /// Exact same-binary identity bound into all runs.
    pub binary_identity: ContentDigest,
    /// Scalar oracle kernel generation digest.
    pub scalar_kernel_generation: ContentDigest,
    /// Safe SIMD candidate kernel generation digest.
    pub simd_kernel_generation: ContentDigest,
    /// Governing `ContractBasis` digest.
    pub contract_basis_digest: ContentDigest,
    /// Canonical digest of the exact input tensor/parameters.
    pub inputs_digest: ContentDigest,
    /// Optional A/A determinism receipt (`fss.experiment_receipt.v1`).
    pub aa_receipt: Option<ExperimentReceipt>,
    /// Mandatory A/B same-binary comparison receipt (`fss.experiment_receipt.v1`).
    pub ab_receipt: ExperimentReceipt,
    /// Resulting gate verdict.
    pub verdict: GateVerdict,
    /// Cost accounting for the candidate evaluation.
    pub candidate_cost: ImageTransformCost,
    /// Caller timestamp when recorded.
    pub evaluated_at: TimestampNs,
    /// Canonical digest binding every field of this gate receipt.
    pub receipt_digest: ContentDigest,
}

impl SameBinaryGateReceipt {
    /// Canonical digest over every field of this receipt.
    #[must_use]
    pub fn compute_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text("fss.same_binary_image_gate_receipt.v1");
        enc.u8(self.op.tag());
        enc.digest(self.binary_identity);
        enc.digest(self.scalar_kernel_generation);
        enc.digest(self.simd_kernel_generation);
        enc.digest(self.contract_basis_digest);
        enc.digest(self.inputs_digest);
        match &self.aa_receipt {
            Some(aa) => {
                enc.bool(true);
                enc.digest(aa.receipt_digest);
            }
            None => enc.bool(false),
        }
        enc.digest(self.ab_receipt.receipt_digest);
        enc.u8(self.verdict.tag());
        enc.u64(self.candidate_cost.input_bytes as u64);
        enc.u64(self.candidate_cost.output_bytes as u64);
        enc.u64(self.candidate_cost.work_units);
        enc.u64(self.candidate_cost.simd_chunks);
        enc.u64(self.candidate_cost.scalar_tail_items);
        enc.u64(self.candidate_cost.scratch_bytes as u64);
        enc.i128(self.evaluated_at.0);
        ContentDigest::sha256(&enc.finish())
    }
}

/// Distinct outcome returned by [`SameBinaryImageGate::execute_gated`].
/// Uncertainty, cancellation, fallback, and quarantine remain strictly typed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransformOutcome {
    /// Completed cleanly via the requested/certified backend.
    Completed {
        /// Output pixel bytes.
        output: Vec<u8>,
        /// Canonical SHA-256 digest of `output`.
        output_digest: ContentDigest,
        /// Exact backend that produced `output`.
        backend_used: ImageKernelBackend,
        /// Kernel generation digest of `backend_used`.
        kernel_generation: ContentDigest,
        /// Measured operation-cost row.
        cost: ImageTransformCost,
        /// Same-binary gate receipt if certification ran on this call.
        gate_receipt: Option<SameBinaryGateReceipt>,
    },
    /// Candidate was refused or degraded and policy explicitly authorized
    /// falling back to the scalar oracle with an audit trail.
    FallbackToScalar {
        /// Scalar oracle output bytes.
        output: Vec<u8>,
        /// Canonical SHA-256 digest of `output`.
        output_digest: ContentDigest,
        /// Exact reason why SIMD was bypassed.
        reason: FallbackReason,
        /// Scalar oracle kernel generation digest.
        kernel_generation: ContentDigest,
        /// Measured operation-cost row.
        cost: ImageTransformCost,
        /// Optional gate receipt preserving negative evidence from the failed check.
        gate_receipt: Option<SameBinaryGateReceipt>,
    },
    /// Cancelled cleanly at a bounded chunk checkpoint (`request -> drain -> finalize`).
    Cancelled {
        /// Backend that was cancelled cleanly.
        backend_attempted: ImageKernelBackend,
        /// Chunks completed prior to cancellation.
        completed_chunks: u64,
        /// Partial work accounting.
        cost: ImageTransformCost,
    },
    /// Gate comparison was indeterminate; no uncertified output emitted.
    Indeterminate {
        /// Machine-readable cause.
        reason: String,
        /// Partial work accounting.
        cost: ImageTransformCost,
        /// Receipt proving indeterminacy.
        gate_receipt: SameBinaryGateReceipt,
    },
    /// Candidate failed certification under `GateFailureAction::Quarantine`;
    /// fail-closed with zero output bytes emitted.
    Quarantined {
        /// Machine-readable cause.
        reason: String,
        /// Receipt preserving exact A/A or A/B divergence evidence.
        gate_receipt: SameBinaryGateReceipt,
    },
}

/// Typed, machine-actionable refusal for FSS-123 kernels and gate operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SimdKernelError {
    /// Underlying geometry/buffer validation error (identical to FSS-122).
    Kernel(ImageKernelError),
    /// Invalid label, digest, or policy field.
    InvalidInput {
        /// Field name.
        field: &'static str,
        /// Detail.
        detail: String,
    },
    /// Privacy or capability clearance was not granted before transform.
    PrivacyRefused {
        /// Refusal detail.
        detail: String,
    },
    /// Source generation does not match consumer's expected generation.
    StaleGeneration {
        /// Source buffer generation.
        source: Generation,
        /// Expected anchor generation.
        expected: Generation,
    },
    /// Input, output, or work-unit budget exceeded before allocation.
    BudgetExceeded {
        /// Bound violated.
        bound: &'static str,
        /// Observed value.
        observed: u64,
        /// Configured limit.
        limit: u64,
    },
    /// Host resource pressure exceeds `GatePolicy::max_candidate_pressure` under
    /// fail-closed policy.
    PressureRefused {
        /// Observed pressure.
        observed: ResourcePressure,
        /// Policy ceiling.
        maximum: ResourcePressure,
    },
    /// Caller timestamp regressed below previous gate timestamp.
    ClockRegression {
        /// Previous timestamp.
        previous: TimestampNs,
        /// Observed timestamp.
        observed: TimestampNs,
    },
    /// Underlying `FSS-196` experiment receipt construction failed.
    Experiment(ExperimentError),
    /// Bounded gate receipt ledger reached [`MAX_GATE_RECEIPTS`].
    CapacityExceeded {
        /// Bound name.
        bound: &'static str,
        /// Limit.
        limit: usize,
    },
}

impl fmt::Display for SimdKernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kernel(e) => write!(f, "image kernel error: {e}"),
            Self::InvalidInput { field, detail } => write!(f, "invalid {field}: {detail}"),
            Self::PrivacyRefused { detail } => write!(f, "privacy/capability refused: {detail}"),
            Self::StaleGeneration { source, expected } => write!(
                f,
                "stale generation: source {} != expected {}",
                source.get(),
                expected.get()
            ),
            Self::BudgetExceeded {
                bound,
                observed,
                limit,
            } => write!(f, "budget '{bound}' exceeded: {observed} > {limit}"),
            Self::PressureRefused { observed, maximum } => write!(
                f,
                "resource pressure '{}' exceeds candidate maximum '{}'",
                observed.as_str(),
                maximum.as_str()
            ),
            Self::ClockRegression { previous, observed } => {
                write!(f, "clock regression: {} < {}", observed.0, previous.0)
            }
            Self::Experiment(e) => write!(f, "experiment receipt error: {e}"),
            Self::CapacityExceeded { bound, limit } => {
                write!(f, "bound '{bound}' exceeded (max {limit})")
            }
        }
    }
}

impl Error for SimdKernelError {}

impl From<ImageKernelError> for SimdKernelError {
    fn from(err: ImageKernelError) -> Self {
        Self::Kernel(err)
    }
}

impl From<ExperimentError> for SimdKernelError {
    fn from(err: ExperimentError) -> Self {
        Self::Experiment(err)
    }
}

// ============================================================================
// Safe Auto-Vectorizable SIMD Image Transform Candidates (Bit-Identical to FSS-122)
// ============================================================================

/// Precomputed horizontal sampling plan for bilinear luma resize.
/// Avoids repeating `dst_w * dst_h` 64-bit divisions and supports 8-lane tiled
/// row accumulation with zero arithmetic drift from [`resize_bilinear_luma`].
#[derive(Clone, Debug)]
struct HorizontalTapPlan {
    x0: Vec<usize>,
    x1: Vec<usize>,
    fx: Vec<u64>,
    inv_fx: Vec<u64>,
}

impl HorizontalTapPlan {
    fn build(src_w: usize, dst_w: usize) -> Self {
        let mut x0 = Vec::with_capacity(dst_w);
        let mut x1 = Vec::with_capacity(dst_w);
        let mut fx = Vec::with_capacity(dst_w);
        let mut inv_fx = Vec::with_capacity(dst_w);
        let denom = 2 * dst_w as u64;
        let max_x = src_w - 1;
        for dx in 0..dst_w {
            let sx_raw = (((2 * dx as u64 + 1) * (src_w as u64)) << 16) / denom;
            let sx = sx_raw.saturating_sub(1 << 15);
            let ix0 = ((sx >> 16) as usize).min(max_x);
            let ix1 = (ix0 + 1).min(max_x);
            let frac = sx & 0xFFFF;
            x0.push(ix0);
            x1.push(ix1);
            fx.push(frac);
            inv_fx.push(0x1_0000 - frac);
        }
        Self { x0, x1, fx, inv_fx }
    }

    fn scratch_bytes(&self) -> usize {
        self.x0.len() * (2 * std::mem::size_of::<usize>() + 2 * std::mem::size_of::<u64>())
    }
}

fn check_plane_bounds(width: usize, height: usize, len: usize) -> Result<(), ImageKernelError> {
    if width == 0 || height == 0 || width > MAX_AXIS || height > MAX_AXIS {
        return Err(ImageKernelError::InvalidDimension {
            value: width.max(height),
        });
    }
    let expected = width
        .checked_mul(height)
        .ok_or(ImageKernelError::InvalidDimension { value: usize::MAX })?;
    if len != expected {
        return Err(ImageKernelError::BufferMismatch {
            expected,
            observed: len,
        });
    }
    Ok(())
}

/// Safe fixed-lane tiled bilinear luma resize candidate (FSS-123).
///
/// Computes the exact Q16/Q32 arithmetic of [`resize_bilinear_luma`] using
/// precomputed horizontal tap tables and 8-lane `[u64; 8]` fixed-width tiles.
/// Guaranteed bit-identical for all valid dimensions and pixel values.
pub fn resize_bilinear_luma_simd(
    src: &[u8],
    src_w: usize,
    src_h: usize,
    dst_w: usize,
    dst_h: usize,
) -> Result<Vec<u8>, ImageKernelError> {
    let (out, _cost) = resize_bilinear_luma_simd_metered(src, src_w, src_h, dst_w, dst_h, None)?
        .expect_completed_unchecked_cancel();
    Ok(out)
}

enum MeteredResult {
    Completed(Vec<u8>, ImageTransformCost),
    Cancelled {
        completed_chunks: u64,
        cost: ImageTransformCost,
    },
}

impl MeteredResult {
    fn expect_completed_unchecked_cancel(self) -> (Vec<u8>, ImageTransformCost) {
        match self {
            Self::Completed(out, cost) => (out, cost),
            Self::Cancelled { cost, .. } => (Vec::new(), cost),
        }
    }
}

fn resize_bilinear_luma_simd_metered(
    src: &[u8],
    src_w: usize,
    src_h: usize,
    dst_w: usize,
    dst_h: usize,
    cancel_after_chunks: Option<u64>,
) -> Result<MeteredResult, ImageKernelError> {
    check_plane_bounds(src_w, src_h, src.len())?;
    if dst_w == 0 || dst_h == 0 || dst_w > MAX_AXIS || dst_h > MAX_AXIS {
        return Err(ImageKernelError::EmptyTarget);
    }
    let total_out = dst_w
        .checked_mul(dst_h)
        .ok_or(ImageKernelError::EmptyTarget)?;
    let plan = HorizontalTapPlan::build(src_w, dst_w);
    let scratch_bytes = plan.scratch_bytes();
    let mut out = vec![0u8; total_out];
    let mut simd_chunks = 0u64;
    let mut scalar_tail_items = 0u64;
    let mut work_units = 0u64;

    let y_denom = 2 * dst_h as u64;
    let max_y = src_h - 1;
    let full_tiles = dst_w / RESIZE_TILE_LANES;
    let tail_start = full_tiles * RESIZE_TILE_LANES;

    for dy in 0..dst_h {
        let sy_raw = (((2 * dy as u64 + 1) * (src_h as u64)) << 16) / y_denom;
        let sy = sy_raw.saturating_sub(1 << 15);
        let y0 = ((sy >> 16) as usize).min(max_y);
        let y1 = (y0 + 1).min(max_y);
        let fy = sy & 0xFFFF;
        let inv_fy = 0x1_0000 - fy;

        let row0 = &src[y0 * src_w..(y0 + 1) * src_w];
        let row1 = &src[y1 * src_w..(y1 + 1) * src_w];
        let dst_row = &mut out[dy * dst_w..(dy + 1) * dst_w];

        for tile in 0..full_tiles {
            if cancel_after_chunks.is_some_and(|limit| simd_chunks >= limit) {
                return Ok(MeteredResult::Cancelled {
                    completed_chunks: simd_chunks,
                    cost: ImageTransformCost {
                        input_bytes: src.len(),
                        output_bytes: 0,
                        work_units,
                        simd_chunks,
                        scalar_tail_items,
                        scratch_bytes,
                    },
                });
            }
            let base = tile * RESIZE_TILE_LANES;
            let mut p00 = [0u64; RESIZE_TILE_LANES];
            let mut p01 = [0u64; RESIZE_TILE_LANES];
            let mut p10 = [0u64; RESIZE_TILE_LANES];
            let mut p11 = [0u64; RESIZE_TILE_LANES];
            let mut fx = [0u64; RESIZE_TILE_LANES];
            let mut inv_fx = [0u64; RESIZE_TILE_LANES];
            for lane in 0..RESIZE_TILE_LANES {
                let ix0 = plan.x0[base + lane];
                let ix1 = plan.x1[base + lane];
                p00[lane] = u64::from(row0[ix0]);
                p01[lane] = u64::from(row0[ix1]);
                p10[lane] = u64::from(row1[ix0]);
                p11[lane] = u64::from(row1[ix1]);
                fx[lane] = plan.fx[base + lane];
                inv_fx[lane] = plan.inv_fx[base + lane];
            }
            let mut tile_out = [0u8; RESIZE_TILE_LANES];
            for lane in 0..RESIZE_TILE_LANES {
                let top = p00[lane] * inv_fx[lane] + p01[lane] * fx[lane];
                let bottom = p10[lane] * inv_fx[lane] + p11[lane] * fx[lane];
                let val = (top * inv_fy + bottom * fy + (1u64 << 31)) >> 32;
                tile_out[lane] = val.min(255) as u8;
            }
            dst_row[base..base + RESIZE_TILE_LANES].copy_from_slice(&tile_out);
            simd_chunks = simd_chunks.saturating_add(1);
            work_units = work_units.saturating_add(RESIZE_TILE_LANES as u64);
        }

        if cancel_after_chunks.is_some_and(|limit| simd_chunks >= limit && tail_start < dst_w) {
            return Ok(MeteredResult::Cancelled {
                completed_chunks: simd_chunks,
                cost: ImageTransformCost {
                    input_bytes: src.len(),
                    output_bytes: 0,
                    work_units,
                    simd_chunks,
                    scalar_tail_items,
                    scratch_bytes,
                },
            });
        }

        for dx in tail_start..dst_w {
            let ix0 = plan.x0[dx];
            let ix1 = plan.x1[dx];
            let fx_v = plan.fx[dx];
            let inv_fx_v = plan.inv_fx[dx];
            let top = u64::from(row0[ix0]) * inv_fx_v + u64::from(row0[ix1]) * fx_v;
            let bottom = u64::from(row1[ix0]) * inv_fx_v + u64::from(row1[ix1]) * fx_v;
            let val = (top * inv_fy + bottom * fy + (1u64 << 31)) >> 32;
            dst_row[dx] = val.min(255) as u8;
            scalar_tail_items = scalar_tail_items.saturating_add(1);
            work_units = work_units.saturating_add(1);
        }
    }

    Ok(MeteredResult::Completed(
        out,
        ImageTransformCost {
            input_bytes: src.len(),
            output_bytes: total_out,
            work_units,
            simd_chunks,
            scalar_tail_items,
            scratch_bytes,
        },
    ))
}

/// Safe fixed-lane BT.601 packed RGB-to-luma candidate (FSS-123).
///
/// Deinterleaves 8 RGB pixels (24 bytes) per chunk into `[u32; 8]` channel
/// arrays and evaluates `(R*77 + G*150 + B*29 + 128) >> 8`. Guaranteed
/// bit-identical to [`rgb_to_luma`].
pub fn rgb_to_luma_simd(rgb: &[u8]) -> Result<Vec<u8>, ImageKernelError> {
    let (out, _cost) = rgb_to_luma_simd_metered(rgb, None)?.expect_completed_unchecked_cancel();
    Ok(out)
}

fn rgb_to_luma_simd_metered(
    rgb: &[u8],
    cancel_after_chunks: Option<u64>,
) -> Result<MeteredResult, ImageKernelError> {
    if !rgb.len().is_multiple_of(3) {
        return Err(ImageKernelError::BufferMismatch {
            expected: rgb.len() + 3 - (rgb.len() % 3),
            observed: rgb.len(),
        });
    }
    let pixels = rgb.len() / 3;
    if pixels == 0 || pixels > MAX_AXIS * MAX_AXIS {
        return Err(ImageKernelError::InvalidDimension { value: pixels });
    }

    let mut out = vec![0u8; pixels];
    let mut simd_chunks = 0u64;
    let mut scalar_tail_items = 0u64;
    let mut work_units = 0u64;

    let chunk_bytes = RGB_LANES * 3;
    let mut chunks = rgb.chunks_exact(chunk_bytes);
    let mut out_offset = 0usize;

    for chunk in &mut chunks {
        if cancel_after_chunks.is_some_and(|limit| simd_chunks >= limit) {
            return Ok(MeteredResult::Cancelled {
                completed_chunks: simd_chunks,
                cost: ImageTransformCost {
                    input_bytes: rgb.len(),
                    output_bytes: 0,
                    work_units,
                    simd_chunks,
                    scalar_tail_items,
                    scratch_bytes: 0,
                },
            });
        }
        let mut r = [0u32; RGB_LANES];
        let mut g = [0u32; RGB_LANES];
        let mut b = [0u32; RGB_LANES];
        for lane in 0..RGB_LANES {
            r[lane] = u32::from(chunk[lane * 3]);
            g[lane] = u32::from(chunk[lane * 3 + 1]);
            b[lane] = u32::from(chunk[lane * 3 + 2]);
        }
        let mut luma = [0u8; RGB_LANES];
        for lane in 0..RGB_LANES {
            let val = (r[lane] * 77 + g[lane] * 150 + b[lane] * 29 + 128) >> 8;
            luma[lane] = val.min(255) as u8;
        }
        out[out_offset..out_offset + RGB_LANES].copy_from_slice(&luma);
        out_offset += RGB_LANES;
        simd_chunks = simd_chunks.saturating_add(1);
        work_units = work_units.saturating_add(RGB_LANES as u64);
    }

    let rem = chunks.remainder();
    if cancel_after_chunks.is_some_and(|limit| simd_chunks >= limit && !rem.is_empty()) {
        return Ok(MeteredResult::Cancelled {
            completed_chunks: simd_chunks,
            cost: ImageTransformCost {
                input_bytes: rgb.len(),
                output_bytes: 0,
                work_units,
                simd_chunks,
                scalar_tail_items,
                scratch_bytes: 0,
            },
        });
    }

    for px in rem.as_chunks::<3>().0 {
        let val =
            (u32::from(px[0]) * 77 + u32::from(px[1]) * 150 + u32::from(px[2]) * 29 + 128) >> 8;
        out[out_offset] = val.min(255) as u8;
        out_offset += 1;
        scalar_tail_items = scalar_tail_items.saturating_add(1);
        work_units = work_units.saturating_add(1);
    }

    Ok(MeteredResult::Completed(
        out,
        ImageTransformCost {
            input_bytes: rgb.len(),
            output_bytes: pixels,
            work_units,
            simd_chunks,
            scalar_tail_items,
            scratch_bytes: 0,
        },
    ))
}

/// Safe fixed-lane min/max reduction + LUT/vectorized luma normalization
/// candidate (FSS-123).
///
/// Uses 16-lane `[u8; 16]` vector min/max reduction and either a 256-byte exact
/// Q16 lookup table (for planes >= 256 pixels) or 16-lane fixed-point scaling.
/// Guaranteed bit-identical to [`normalize_luma`].
pub fn normalize_luma_simd(
    plane: &[u8],
    width: usize,
    height: usize,
    constant_fill: u8,
) -> Result<Vec<u8>, ImageKernelError> {
    let (out, _cost) = normalize_luma_simd_metered(plane, width, height, constant_fill, None)?
        .expect_completed_unchecked_cancel();
    Ok(out)
}

fn normalize_luma_simd_metered(
    plane: &[u8],
    width: usize,
    height: usize,
    constant_fill: u8,
    cancel_after_chunks: Option<u64>,
) -> Result<MeteredResult, ImageKernelError> {
    check_plane_bounds(width, height, plane.len())?;

    // Pass 1: 16-lane vectorizable min/max reduction.
    let mut mins = [u8::MAX; NORMALIZE_LANES];
    let mut maxs = [0u8; NORMALIZE_LANES];
    let (chunks, rem) = plane.as_chunks::<NORMALIZE_LANES>();
    for chunk in chunks {
        for lane in 0..NORMALIZE_LANES {
            let v = chunk[lane];
            if v < mins[lane] {
                mins[lane] = v;
            }
            if v > maxs[lane] {
                maxs[lane] = v;
            }
        }
    }
    let mut min_v = u8::MAX;
    let mut max_v = 0u8;
    for lane in 0..NORMALIZE_LANES {
        min_v = min_v.min(mins[lane]);
        max_v = max_v.max(maxs[lane]);
    }
    for &v in rem {
        min_v = min_v.min(v);
        max_v = max_v.max(v);
    }

    if max_v == min_v {
        if cancel_after_chunks == Some(0) {
            return Ok(MeteredResult::Cancelled {
                completed_chunks: 0,
                cost: ImageTransformCost {
                    input_bytes: plane.len(),
                    output_bytes: 0,
                    work_units: 0,
                    simd_chunks: 0,
                    scalar_tail_items: 0,
                    scratch_bytes: 0,
                },
            });
        }
        return Ok(MeteredResult::Completed(
            vec![constant_fill; plane.len()],
            ImageTransformCost {
                input_bytes: plane.len(),
                output_bytes: plane.len(),
                work_units: plane.len() as u64,
                simd_chunks: (plane.len() / NORMALIZE_LANES) as u64,
                scalar_tail_items: (plane.len() % NORMALIZE_LANES) as u64,
                scratch_bytes: 0,
            },
        ));
    }

    let gain = (65_535u64 << 16) / u64::from(max_v - min_v);
    let half = 1u64 << 15;
    let mut out = vec![0u8; plane.len()];
    let mut simd_chunks = 0u64;
    let mut scalar_tail_items = 0u64;
    let mut work_units = 0u64;

    if plane.len() >= NORMALIZE_LUT_THRESHOLD {
        // Exact 256-entry LUT over the full u8 domain (matches scalar formula for every byte).
        let mut lut = [0u8; 256];
        for (idx, entry) in lut.iter_mut().enumerate() {
            let scaled =
                (u64::from(idx as u8).saturating_sub(u64::from(min_v)) * gain + half) >> 16;
            *entry = scaled.min(255) as u8;
        }
        let (in_chunks, rem) = plane.as_chunks::<NORMALIZE_LANES>();
        let mut offset = 0usize;
        for chunk in in_chunks {
            if cancel_after_chunks.is_some_and(|limit| simd_chunks >= limit) {
                return Ok(MeteredResult::Cancelled {
                    completed_chunks: simd_chunks,
                    cost: ImageTransformCost {
                        input_bytes: plane.len(),
                        output_bytes: 0,
                        work_units,
                        simd_chunks,
                        scalar_tail_items,
                        scratch_bytes: 256,
                    },
                });
            }
            let mut tile = [0u8; NORMALIZE_LANES];
            for lane in 0..NORMALIZE_LANES {
                tile[lane] = lut[usize::from(chunk[lane])];
            }
            out[offset..offset + NORMALIZE_LANES].copy_from_slice(&tile);
            offset += NORMALIZE_LANES;
            simd_chunks = simd_chunks.saturating_add(1);
            work_units = work_units.saturating_add(NORMALIZE_LANES as u64);
        }
        if cancel_after_chunks.is_some_and(|limit| simd_chunks >= limit && !rem.is_empty()) {
            return Ok(MeteredResult::Cancelled {
                completed_chunks: simd_chunks,
                cost: ImageTransformCost {
                    input_bytes: plane.len(),
                    output_bytes: 0,
                    work_units,
                    simd_chunks,
                    scalar_tail_items,
                    scratch_bytes: 256,
                },
            });
        }
        for &v in rem {
            out[offset] = lut[usize::from(v)];
            offset += 1;
            scalar_tail_items = scalar_tail_items.saturating_add(1);
            work_units = work_units.saturating_add(1);
        }
        return Ok(MeteredResult::Completed(
            out,
            ImageTransformCost {
                input_bytes: plane.len(),
                output_bytes: plane.len(),
                work_units,
                simd_chunks,
                scalar_tail_items,
                scratch_bytes: 256,
            },
        ));
    }

    // Small plane (< 256 pixels): direct 16-lane fixed-point scaling (zero LUT allocation).
    let (in_chunks, rem) = plane.as_chunks::<NORMALIZE_LANES>();
    let mut offset = 0usize;
    for chunk in in_chunks {
        if cancel_after_chunks.is_some_and(|limit| simd_chunks >= limit) {
            return Ok(MeteredResult::Cancelled {
                completed_chunks: simd_chunks,
                cost: ImageTransformCost {
                    input_bytes: plane.len(),
                    output_bytes: 0,
                    work_units,
                    simd_chunks,
                    scalar_tail_items,
                    scratch_bytes: 0,
                },
            });
        }
        let mut tile = [0u8; NORMALIZE_LANES];
        for lane in 0..NORMALIZE_LANES {
            let scaled =
                (u64::from(chunk[lane]).saturating_sub(u64::from(min_v)) * gain + half) >> 16;
            tile[lane] = scaled.min(255) as u8;
        }
        out[offset..offset + NORMALIZE_LANES].copy_from_slice(&tile);
        offset += NORMALIZE_LANES;
        simd_chunks = simd_chunks.saturating_add(1);
        work_units = work_units.saturating_add(NORMALIZE_LANES as u64);
    }
    if cancel_after_chunks.is_some_and(|limit| simd_chunks >= limit && !rem.is_empty()) {
        return Ok(MeteredResult::Cancelled {
            completed_chunks: simd_chunks,
            cost: ImageTransformCost {
                input_bytes: plane.len(),
                output_bytes: 0,
                work_units,
                simd_chunks,
                scalar_tail_items,
                scratch_bytes: 0,
            },
        });
    }
    for &v in rem {
        let scaled = (u64::from(v).saturating_sub(u64::from(min_v)) * gain + half) >> 16;
        out[offset] = scaled.min(255) as u8;
        offset += 1;
        scalar_tail_items = scalar_tail_items.saturating_add(1);
        work_units = work_units.saturating_add(1);
    }

    Ok(MeteredResult::Completed(
        out,
        ImageTransformCost {
            input_bytes: plane.len(),
            output_bytes: plane.len(),
            work_units,
            simd_chunks,
            scalar_tail_items,
            scratch_bytes: 0,
        },
    ))
}

fn execute_scalar_oracle(
    req: &ImageTransformRequest<'_>,
) -> Result<(Vec<u8>, ImageTransformCost), ImageKernelError> {
    let out = match *req {
        ImageTransformRequest::ResizeBilinearLuma {
            src,
            src_w,
            src_h,
            dst_w,
            dst_h,
        } => resize_bilinear_luma(src, src_w, src_h, dst_w, dst_h)?,
        ImageTransformRequest::RgbToLuma { rgb } => rgb_to_luma(rgb)?,
        ImageTransformRequest::NormalizeLuma {
            plane,
            width,
            height,
            constant_fill,
        } => normalize_luma(plane, width, height, constant_fill)?,
    };
    let len = out.len();
    Ok((
        out,
        ImageTransformCost {
            input_bytes: req.input_bytes(),
            output_bytes: len,
            work_units: len as u64,
            simd_chunks: 0,
            scalar_tail_items: len as u64,
            scratch_bytes: 0,
        },
    ))
}

fn execute_simd_metered(
    req: &ImageTransformRequest<'_>,
    cancel_after_chunks: Option<u64>,
) -> Result<MeteredResult, ImageKernelError> {
    match *req {
        ImageTransformRequest::ResizeBilinearLuma {
            src,
            src_w,
            src_h,
            dst_w,
            dst_h,
        } => {
            resize_bilinear_luma_simd_metered(src, src_w, src_h, dst_w, dst_h, cancel_after_chunks)
        }
        ImageTransformRequest::RgbToLuma { rgb } => {
            rgb_to_luma_simd_metered(rgb, cancel_after_chunks)
        }
        ImageTransformRequest::NormalizeLuma {
            plane,
            width,
            height,
            constant_fill,
        } => normalize_luma_simd_metered(plane, width, height, constant_fill, cancel_after_chunks),
    }
}

// ============================================================================
// Same-Binary Gate State Machine (FSS-123 + FSS-196)
// ============================================================================

/// Bounded metrics tracked by [`SameBinaryImageGate`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GateMetrics {
    /// Total same-binary certification runs executed.
    pub certifications_run: u64,
    /// Total certifications admitted.
    pub certifications_admitted: u64,
    /// Total A/A determinism alarms recorded.
    pub aa_alarms: u64,
    /// Total A/B divergences recorded.
    pub ab_divergences: u64,
    /// Total indeterminate gate runs recorded.
    pub indeterminates: u64,
    /// Total transforms served by the certified safe SIMD backend.
    pub simd_executions: u64,
    /// Total transforms explicitly served via scalar fallback.
    pub scalar_fallbacks: u64,
    /// Total transforms cancelled cleanly at chunk checkpoints.
    pub cancellations: u64,
    /// Total typed refusals emitted.
    pub refusals: u64,
}

/// Deterministic, stateful same-binary gate governing admission, quarantine,
/// and audited execution of safe SIMD image transform candidates against the
/// FSS-122 scalar reference oracle.
#[derive(Clone, Debug)]
pub struct SameBinaryImageGate {
    policy: GatePolicy,
    binary_identity: ContentDigest,
    states: BTreeMap<ImageKernelOp, CandidateGateState>,
    receipts: Vec<SameBinaryGateReceipt>,
    last_timestamp: Option<TimestampNs>,
    metrics: GateMetrics,
}

impl SameBinaryImageGate {
    /// Creates a new gate with all operators initially `Staged` (uncertified).
    pub fn new(policy: GatePolicy) -> Result<Self, SimdKernelError> {
        policy.validate()?;
        let binary_identity = same_binary_identity(&policy.toolchain_id);
        let mut states = BTreeMap::new();
        states.insert(
            ImageKernelOp::ResizeBilinearLuma,
            CandidateGateState::Staged,
        );
        states.insert(ImageKernelOp::RgbToLuma, CandidateGateState::Staged);
        states.insert(ImageKernelOp::NormalizeLuma, CandidateGateState::Staged);
        Ok(Self {
            policy,
            binary_identity,
            states,
            receipts: Vec::new(),
            last_timestamp: None,
            metrics: GateMetrics::default(),
        })
    }

    /// Governing policy.
    #[must_use]
    pub const fn policy(&self) -> &GatePolicy {
        &self.policy
    }

    /// Immutable same-binary identity digest bound into every `ExperimentReceipt`.
    #[must_use]
    pub const fn binary_identity(&self) -> ContentDigest {
        self.binary_identity
    }

    /// Current gate state for one operator.
    #[must_use]
    pub fn state(&self, op: ImageKernelOp) -> &CandidateGateState {
        self.states.get(&op).unwrap_or(&CandidateGateState::Staged)
    }

    /// All retained gate receipts (both certifications and negative evidence).
    #[must_use]
    pub fn receipts(&self) -> &[SameBinaryGateReceipt] {
        &self.receipts
    }

    /// Bounded gate metrics.
    #[must_use]
    pub const fn metrics(&self) -> GateMetrics {
        self.metrics
    }

    /// Runs a controlled same-binary A/A (determinism) and A/B (bit-parity vs
    /// scalar reference) certification for `request` using `FSS-196`
    /// [`ExperimentReceipt`]s, updating this operator's gate state.
    pub fn certify_operator(
        &mut self,
        experiment_id: &str,
        request: &ImageTransformRequest<'_>,
        cx: &ImageKernelCx,
        now: TimestampNs,
    ) -> Result<SameBinaryGateReceipt, SimdKernelError> {
        self.check_clock(now)?;
        validate_label("experiment_id", experiment_id).inspect_err(|_| self.bump_refusal())?;
        cx.validate().inspect_err(|_| self.bump_refusal())?;
        self.check_budget(request, cx)?;
        if self.receipts.len() >= MAX_GATE_RECEIPTS {
            self.bump_refusal();
            return Err(SimdKernelError::CapacityExceeded {
                bound: "MAX_GATE_RECEIPTS",
                limit: MAX_GATE_RECEIPTS,
            });
        }

        let inputs_digest = request.inputs_digest();
        let (scalar_out, _scalar_cost) =
            execute_scalar_oracle(request).inspect_err(|_| self.bump_refusal())?;
        let scalar_digest = ContentDigest::sha256(&scalar_out);

        let (simd_run1, candidate_cost) = match execute_simd_metered(request, None)
            .inspect_err(|_| self.bump_refusal())?
        {
            MeteredResult::Completed(out, cost) => (out, cost),
            MeteredResult::Cancelled { .. } => {
                // Certification runs with `cancel_after_chunks = None`, so unreachable.
                self.bump_refusal();
                return Err(SimdKernelError::InvalidInput {
                    field: "cancel_after_chunks",
                    detail: "unexpected cancellation during uncancelled certification".to_owned(),
                });
            }
        };
        let simd_run1_digest = ContentDigest::sha256(&simd_run1);

        // Build A/A determinism receipt if required by policy.
        let aa_receipt = if self.policy.require_aa_check {
            let (mut simd_run2, _) =
                match execute_simd_metered(request, None).inspect_err(|_| self.bump_refusal())? {
                    MeteredResult::Completed(out, cost) => (out, cost),
                    MeteredResult::Cancelled { .. } => (Vec::new(), candidate_cost),
                };
            if cx.fault_injection == Some(GateFaultInjection::AaSecondRunFlipBit)
                && let Some(first) = simd_run2.first_mut()
            {
                *first ^= 0x01;
            }
            let run2_outcome =
                if cx.fault_injection == Some(GateFaultInjection::CandidateOutcomeIndeterminate) {
                    None
                } else {
                    Some(ContentDigest::sha256(&simd_run2))
                };
            let run1_outcome =
                if cx.fault_injection == Some(GateFaultInjection::CandidateOutcomeIndeterminate) {
                    None
                } else {
                    Some(simd_run1_digest)
                };
            let aa_a = ExperimentRun {
                run_id: format!("{experiment_id}:aa-1"),
                variant_id: None,
                binary_identity: self.binary_identity,
                inputs_digest,
                schedule_seed: cx.schedule_seed,
                outcome_digest: run1_outcome,
            };
            let aa_b = ExperimentRun {
                run_id: format!("{experiment_id}:aa-2"),
                variant_id: None,
                binary_identity: self.binary_identity,
                inputs_digest,
                schedule_seed: cx.schedule_seed,
                outcome_digest: run2_outcome,
            };
            Some(ExperimentReceipt::compare(
                format!("{experiment_id}:aa"),
                ExperimentKind::Aa,
                aa_a,
                aa_b,
            )?)
        } else {
            None
        };

        // Build A/B same-binary parity receipt (scalar-reference.v1 vs safe-simd.v1).
        let mut ab_candidate_bytes = simd_run1;
        if cx.fault_injection == Some(GateFaultInjection::AbCandidateFlipByte)
            && let Some(first) = ab_candidate_bytes.first_mut()
        {
            *first ^= 0xFF;
        }
        let ab_ref_outcome =
            if cx.fault_injection == Some(GateFaultInjection::ReferenceOutcomeIndeterminate) {
                None
            } else {
                Some(scalar_digest)
            };
        let ab_cand_outcome =
            if cx.fault_injection == Some(GateFaultInjection::CandidateOutcomeIndeterminate) {
                None
            } else {
                Some(ContentDigest::sha256(&ab_candidate_bytes))
            };
        let ab_a = ExperimentRun {
            run_id: format!("{experiment_id}:ab-scalar"),
            variant_id: Some(ImageKernelBackend::ScalarReferenceV1.stable_id().to_owned()),
            binary_identity: self.binary_identity,
            inputs_digest,
            schedule_seed: cx.schedule_seed,
            outcome_digest: ab_ref_outcome,
        };
        let ab_b = ExperimentRun {
            run_id: format!("{experiment_id}:ab-simd"),
            variant_id: Some(ImageKernelBackend::SafeSimdV1.stable_id().to_owned()),
            binary_identity: self.binary_identity,
            inputs_digest,
            schedule_seed: cx.schedule_seed,
            outcome_digest: ab_cand_outcome,
        };
        let ab_receipt = ExperimentReceipt::compare(
            format!("{experiment_id}:ab"),
            ExperimentKind::Ab,
            ab_a,
            ab_b,
        )?;

        // Classify verdict honestly: A/A alarm > Indeterminate > A/B divergence > Admitted.
        let verdict = if aa_receipt
            .as_ref()
            .is_some_and(ExperimentReceipt::is_determinism_alarm)
        {
            GateVerdict::RejectedAaAlarm
        } else if aa_receipt
            .as_ref()
            .is_some_and(|r| r.comparison == ComparisonOutcome::Indeterminate)
            || ab_receipt.comparison == ComparisonOutcome::Indeterminate
        {
            GateVerdict::Indeterminate
        } else if ab_receipt.comparison == ComparisonOutcome::Divergent {
            GateVerdict::RejectedAbDivergence
        } else {
            GateVerdict::Admitted
        };

        let mut receipt = SameBinaryGateReceipt {
            op: request.op(),
            binary_identity: self.binary_identity,
            scalar_kernel_generation: scalar_image_kernel_generation(),
            simd_kernel_generation: simd_image_kernel_generation(),
            contract_basis_digest: cx.contract_basis_digest,
            inputs_digest,
            aa_receipt,
            ab_receipt,
            verdict,
            candidate_cost,
            evaluated_at: now,
            receipt_digest: ContentDigest::new(DigestAlgorithm::Sha256, [0; 32]),
        };
        receipt.receipt_digest = receipt.compute_digest();

        self.last_timestamp = Some(now);
        self.metrics.certifications_run = self.metrics.certifications_run.saturating_add(1);
        match verdict {
            GateVerdict::Admitted => {
                self.metrics.certifications_admitted =
                    self.metrics.certifications_admitted.saturating_add(1);
                self.states.insert(
                    request.op(),
                    CandidateGateState::Certified {
                        receipt_digest: receipt.receipt_digest,
                        certified_at: now,
                    },
                );
            }
            GateVerdict::RejectedAaAlarm => {
                self.metrics.aa_alarms = self.metrics.aa_alarms.saturating_add(1);
                self.states.insert(
                    request.op(),
                    CandidateGateState::Quarantined {
                        reason: "same-binary A/A determinism alarm".to_owned(),
                        receipt_digest: receipt.receipt_digest,
                        quarantined_at: now,
                    },
                );
            }
            GateVerdict::RejectedAbDivergence => {
                self.metrics.ab_divergences = self.metrics.ab_divergences.saturating_add(1);
                self.states.insert(
                    request.op(),
                    CandidateGateState::Quarantined {
                        reason: "same-binary A/B output diverged from scalar reference".to_owned(),
                        receipt_digest: receipt.receipt_digest,
                        quarantined_at: now,
                    },
                );
            }
            GateVerdict::Indeterminate => {
                self.metrics.indeterminates = self.metrics.indeterminates.saturating_add(1);
                self.states.insert(
                    request.op(),
                    CandidateGateState::Quarantined {
                        reason: "same-binary gate comparison indeterminate".to_owned(),
                        receipt_digest: receipt.receipt_digest,
                        quarantined_at: now,
                    },
                );
            }
        }
        self.receipts.push(receipt.clone());
        Ok(receipt)
    }

    /// Executes an image transform under the same-binary gate:
    ///
    /// - Enforces clock monotonicity, privacy clearance, generation parity,
    ///   hard budgets, and resource-pressure ceilings.
    /// - If the operator is `Staged`, runs same-binary A/A + A/B certification
    ///   first (`certify_operator`) and never serves uncertified SIMD output.
    /// - If the operator is `Quarantined` or certification fails, either fails
    ///   closed (`TransformOutcome::Quarantined` / `Indeterminate`) or explicitly
    ///   falls back (`TransformOutcome::FallbackToScalar`) per [`GatePolicy`].
    /// - Honors deterministic cancellation checkpoints cleanly.
    pub fn execute_gated(
        &mut self,
        experiment_id: &str,
        request: &ImageTransformRequest<'_>,
        cx: &ImageKernelCx,
        now: TimestampNs,
    ) -> Result<TransformOutcome, SimdKernelError> {
        self.check_clock(now)?;
        validate_label("experiment_id", experiment_id).inspect_err(|_| self.bump_refusal())?;
        cx.validate().inspect_err(|_| self.bump_refusal())?;
        self.check_budget(request, cx)?;

        // Check resource-pressure ceiling before invoking SIMD candidate.
        if pressure_rank(cx.pressure) > pressure_rank(self.policy.max_candidate_pressure) {
            return match self.policy.on_gate_failure {
                GateFailureAction::Quarantine => {
                    self.bump_refusal();
                    Err(SimdKernelError::PressureRefused {
                        observed: cx.pressure,
                        maximum: self.policy.max_candidate_pressure,
                    })
                }
                GateFailureAction::FallbackToScalar => {
                    let (out, cost) =
                        execute_scalar_oracle(request).inspect_err(|_| self.bump_refusal())?;
                    let output_digest = ContentDigest::sha256(&out);
                    self.last_timestamp = Some(now);
                    self.metrics.scalar_fallbacks = self.metrics.scalar_fallbacks.saturating_add(1);
                    Ok(TransformOutcome::FallbackToScalar {
                        output: out,
                        output_digest,
                        reason: FallbackReason::PressureDegraded,
                        kernel_generation: scalar_image_kernel_generation(),
                        cost,
                        gate_receipt: None,
                    })
                }
            };
        }

        let op = request.op();
        let mut gate_receipt: Option<SameBinaryGateReceipt> = None;

        // If already quarantined (from a prior run), never re-admit silently.
        if let CandidateGateState::Quarantined {
            reason,
            receipt_digest,
            ..
        } = self.state(op).clone()
        {
            let existing = self
                .receipts
                .iter()
                .rev()
                .find(|r| r.receipt_digest == receipt_digest)
                .cloned();
            return match self.policy.on_gate_failure {
                GateFailureAction::Quarantine => {
                    self.last_timestamp = Some(now);
                    if let Some(rcpt) = existing {
                        Ok(TransformOutcome::Quarantined {
                            reason: format!("operator previously quarantined: {reason}"),
                            gate_receipt: rcpt,
                        })
                    } else {
                        self.bump_refusal();
                        Err(SimdKernelError::InvalidInput {
                            field: "quarantine_receipt",
                            detail: reason,
                        })
                    }
                }
                GateFailureAction::FallbackToScalar => {
                    let (out, cost) =
                        execute_scalar_oracle(request).inspect_err(|_| self.bump_refusal())?;
                    let output_digest = ContentDigest::sha256(&out);
                    self.last_timestamp = Some(now);
                    self.metrics.scalar_fallbacks = self.metrics.scalar_fallbacks.saturating_add(1);
                    Ok(TransformOutcome::FallbackToScalar {
                        output: out,
                        output_digest,
                        reason: FallbackReason::PreviouslyQuarantined,
                        kernel_generation: scalar_image_kernel_generation(),
                        cost,
                        gate_receipt: existing,
                    })
                }
            };
        }

        // If Staged (or if fault injection is active to exercise live gate check),
        // run same-binary A/A + A/B certification before serving SIMD output.
        if matches!(self.state(op), CandidateGateState::Staged) || cx.fault_injection.is_some() {
            let rcpt = self.certify_operator(experiment_id, request, cx, now)?;
            match rcpt.verdict {
                GateVerdict::Admitted => {
                    gate_receipt = Some(rcpt);
                }
                GateVerdict::RejectedAaAlarm => {
                    return self.handle_rejected_candidate(
                        request,
                        rcpt,
                        FallbackReason::AaDeterminismAlarm,
                        "same-binary A/A determinism alarm quarantined candidate",
                        now,
                    );
                }
                GateVerdict::RejectedAbDivergence => {
                    return self.handle_rejected_candidate(
                        request,
                        rcpt,
                        FallbackReason::AbDivergence,
                        "same-binary A/B divergence from scalar reference quarantined candidate",
                        now,
                    );
                }
                GateVerdict::Indeterminate => {
                    return match self.policy.on_gate_failure {
                        GateFailureAction::Quarantine => Ok(TransformOutcome::Indeterminate {
                            reason: "same-binary gate comparison indeterminate".to_owned(),
                            cost: rcpt.candidate_cost,
                            gate_receipt: rcpt,
                        }),
                        GateFailureAction::FallbackToScalar => {
                            let (out, cost) = execute_scalar_oracle(request)
                                .inspect_err(|_| self.bump_refusal())?;
                            let output_digest = ContentDigest::sha256(&out);
                            self.metrics.scalar_fallbacks =
                                self.metrics.scalar_fallbacks.saturating_add(1);
                            Ok(TransformOutcome::FallbackToScalar {
                                output: out,
                                output_digest,
                                reason: FallbackReason::ComparisonIndeterminate,
                                kernel_generation: scalar_image_kernel_generation(),
                                cost,
                                gate_receipt: Some(rcpt),
                            })
                        }
                    };
                }
            }
        }

        // Execute certified safe SIMD candidate with cancellation checkpoints.
        match execute_simd_metered(request, cx.cancel_after_chunks)
            .inspect_err(|_| self.bump_refusal())?
        {
            MeteredResult::Completed(output, cost) => {
                let output_digest = ContentDigest::sha256(&output);
                self.last_timestamp = Some(now);
                self.metrics.simd_executions = self.metrics.simd_executions.saturating_add(1);
                Ok(TransformOutcome::Completed {
                    output,
                    output_digest,
                    backend_used: ImageKernelBackend::SafeSimdV1,
                    kernel_generation: simd_image_kernel_generation(),
                    cost,
                    gate_receipt,
                })
            }
            MeteredResult::Cancelled {
                completed_chunks,
                cost,
            } => {
                self.last_timestamp = Some(now);
                self.metrics.cancellations = self.metrics.cancellations.saturating_add(1);
                Ok(TransformOutcome::Cancelled {
                    backend_attempted: ImageKernelBackend::SafeSimdV1,
                    completed_chunks,
                    cost,
                })
            }
        }
    }

    /// Executes the deterministic scalar reference oracle directly (useful for
    /// baselines, differential harnesses, and explicit scalar-only callers).
    pub fn execute_scalar(
        &mut self,
        request: &ImageTransformRequest<'_>,
        cx: &ImageKernelCx,
        now: TimestampNs,
    ) -> Result<TransformOutcome, SimdKernelError> {
        self.check_clock(now)?;
        cx.validate().inspect_err(|_| self.bump_refusal())?;
        self.check_budget(request, cx)?;
        let (output, cost) = execute_scalar_oracle(request).inspect_err(|_| self.bump_refusal())?;
        let output_digest = ContentDigest::sha256(&output);
        self.last_timestamp = Some(now);
        Ok(TransformOutcome::Completed {
            output,
            output_digest,
            backend_used: ImageKernelBackend::ScalarReferenceV1,
            kernel_generation: scalar_image_kernel_generation(),
            cost,
            gate_receipt: None,
        })
    }

    fn handle_rejected_candidate(
        &mut self,
        request: &ImageTransformRequest<'_>,
        rcpt: SameBinaryGateReceipt,
        fallback_reason: FallbackReason,
        quarantine_reason: &str,
        now: TimestampNs,
    ) -> Result<TransformOutcome, SimdKernelError> {
        match self.policy.on_gate_failure {
            GateFailureAction::Quarantine => Ok(TransformOutcome::Quarantined {
                reason: clamp_reason(quarantine_reason),
                gate_receipt: rcpt,
            }),
            GateFailureAction::FallbackToScalar => {
                let (output, cost) =
                    execute_scalar_oracle(request).inspect_err(|_| self.bump_refusal())?;
                let output_digest = ContentDigest::sha256(&output);
                self.last_timestamp = Some(now);
                self.metrics.scalar_fallbacks = self.metrics.scalar_fallbacks.saturating_add(1);
                Ok(TransformOutcome::FallbackToScalar {
                    output,
                    output_digest,
                    reason: fallback_reason,
                    kernel_generation: scalar_image_kernel_generation(),
                    cost,
                    gate_receipt: Some(rcpt),
                })
            }
        }
    }

    fn check_clock(&mut self, now: TimestampNs) -> Result<(), SimdKernelError> {
        if let Some(prev) = self.last_timestamp
            && now < prev
        {
            self.bump_refusal();
            return Err(SimdKernelError::ClockRegression {
                previous: prev,
                observed: now,
            });
        }
        Ok(())
    }

    fn check_budget(
        &mut self,
        request: &ImageTransformRequest<'_>,
        cx: &ImageKernelCx,
    ) -> Result<(), SimdKernelError> {
        let in_bytes = request.input_bytes();
        if in_bytes > cx.budget.max_input_bytes {
            self.bump_refusal();
            return Err(SimdKernelError::BudgetExceeded {
                bound: "max_input_bytes",
                observed: in_bytes as u64,
                limit: cx.budget.max_input_bytes as u64,
            });
        }
        if let Some(out_bytes) = request.expected_output_bytes() {
            if out_bytes > cx.budget.max_output_bytes {
                self.bump_refusal();
                return Err(SimdKernelError::BudgetExceeded {
                    bound: "max_output_bytes",
                    observed: out_bytes as u64,
                    limit: cx.budget.max_output_bytes as u64,
                });
            }
            if (out_bytes as u64) > cx.budget.max_work_units {
                self.bump_refusal();
                return Err(SimdKernelError::BudgetExceeded {
                    bound: "max_work_units",
                    observed: out_bytes as u64,
                    limit: cx.budget.max_work_units,
                });
            }
        }
        Ok(())
    }

    fn bump_refusal(&mut self) {
        self.metrics.refusals = self.metrics.refusals.saturating_add(1);
    }
}

const fn pressure_rank(p: ResourcePressure) -> u8 {
    match p {
        ResourcePressure::Nominal => 0,
        ResourcePressure::Elevated => 1,
        ResourcePressure::Constrained => 2,
        ResourcePressure::Critical => 3,
    }
}

fn validate_label(field: &'static str, value: &str) -> Result<(), SimdKernelError> {
    if value.trim().is_empty()
        || value.len() > MAX_LABEL_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(SimdKernelError::InvalidInput {
            field,
            detail: format!("must be 1..={MAX_LABEL_BYTES} non-control bytes"),
        });
    }
    Ok(())
}

fn validate_digest(field: &'static str, digest: ContentDigest) -> Result<(), SimdKernelError> {
    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
        return Err(SimdKernelError::InvalidInput {
            field,
            detail: "must be a non-zero SHA-256 digest".to_owned(),
        });
    }
    Ok(())
}

fn clamp_reason(text: &str) -> String {
    let sanitized: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if sanitized.len() <= MAX_REASON_BYTES {
        sanitized
    } else {
        let mut end = MAX_REASON_BYTES;
        while end > 0 && !sanitized.is_char_boundary(end) {
            end -= 1;
        }
        sanitized[..end].to_owned()
    }
}
