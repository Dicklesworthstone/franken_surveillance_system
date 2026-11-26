#![forbid(unsafe_code)]
//! Static kernel dispatch planner and decision-path receipts (`FSS-141`, `fss-x4a.14.12`).
//!
//! Composes [`OptimizedGraph`], [`ScalarExecutor`], [`MemoryPlan`], and [`ScratchArenaPlan`]
//! (`FSS-140`) so every inference execution follows a statically decided, immutable kernel dispatch
//! schedule sealed into a verifiable `FSSKDR01` v1 receipt:
//!
//! - **Zero ambient or runtime-heuristic dispatch:** every node's kernel label and any scalar
//!   reference fallback reason are chosen deterministically at compile time from
//!   `(ModelIrGraph, constants, KernelDispatchPolicy)` and bound into `decision_path_digest`.
//! - **Thread-count invariance:** `ExecThreads` alters wall time only — the static dispatch plan,
//!   `decision_path_digest`, `receipt_digest`, and every IEEE-754 output bit are invariant across
//!   thread counts.
//! - **Optional strict zero-fallback gate:** when `policy.allow_scalar_fallback == false`, any
//!   node that cannot run on a specialized kernel fails closed at compile time rather than
//!   silently downgrading.
//! - **Optional 0-ULP scalar oracle certification:** executes the exact same graph via
//!   [`ScalarExecutor`] and refuses with [`KernelDispatchError::OracleDivergence`] on any bit
//!   mismatch.
//! - **Derived cognition only:** carries zero write or effect authority
//!   (`grants_effect_authority() == false`).

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, Sha256Hasher};
use fss_model_ir::memory::MAX_MEMORY_PLAN_VALUES;
use fss_model_ir::{
    DEFAULT_SCRATCH_ALIGNMENT, MAX_SCRATCH_ALIGNMENT, MemoryPlan, MemoryPlanError,
    MemoryPlanLimits, ModelIrGraph, OpCode, ScratchArenaPlan, ScratchPlanBudget, ScratchPlanError,
    encode_canonical_model_ir,
};
use fss_tensor::{DType, Shape, Tensor};

use crate::optimized_executor::{
    ExecThreads, KernelBackend, OptimizedGraph, OptimizedRunReport, OptimizedStepDescriptor,
};
use crate::scalar_executor::{ExecBudget, ExecError, ExecOutcome, ScalarExecCx, ScalarExecutor};

/// Registered canonical digest domain for [`KernelDispatchDecisionReceipt`] (`FSS-141`).
pub const KERNEL_DISPATCH_RECEIPT_DOMAIN: &str = "fss.reference.kernel_dispatch_receipt.v1";
/// Binary wire magic header for sealed [`KernelDispatchDecisionReceipt`] envelopes.
pub const KERNEL_DISPATCH_WIRE_MAGIC: [u8; 8] = *b"FSSKDR01";
/// Current wire format version for [`KernelDispatchDecisionReceipt`].
pub const KERNEL_DISPATCH_WIRE_VERSION: u32 = 1;
/// Hard ceiling on serialized `FSSKDR01` wire bytes (1 MiB).
pub const MAX_KERNEL_DISPATCH_WIRE_BYTES: usize = 1024 * 1024;
/// Maximum UTF-8 bytes in a node/op/kernel label inside a dispatch receipt.
pub const MAX_DISPATCH_LABEL_BYTES: usize = 256;

const WIRE_HEADER_BYTES: usize = 16;
const WIRE_CHECKSUM_BYTES: usize = 32;

/// Non-collapsed static dispatch outcome state recorded in [`KernelDispatchDecisionReceipt`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchOutcomeState {
    /// Every compiled execution step runs on a specialized static optimized CPU kernel (0 fallbacks).
    StaticOptimizedExact = 1,
    /// Optimized CPU backend runs specialized kernels where admissible and explicitly records
    /// deterministic scalar reference fallback steps.
    StaticHybridWithScalarFallback = 2,
    /// Policy explicitly selected the deterministic scalar reference oracle backend for every node.
    ScalarReferenceOnly = 3,
}

impl DispatchOutcomeState {
    /// Stable canonical string spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StaticOptimizedExact => "static_optimized_exact",
            Self::StaticHybridWithScalarFallback => "static_hybrid_with_scalar_fallback",
            Self::ScalarReferenceOnly => "scalar_reference_only",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, KernelDispatchError> {
        match tag {
            1 => Ok(Self::StaticOptimizedExact),
            2 => Ok(Self::StaticHybridWithScalarFallback),
            3 => Ok(Self::ScalarReferenceOnly),
            other => Err(KernelDispatchError::MalformedWire(format!(
                "unknown DispatchOutcomeState tag {other}"
            ))),
        }
    }
}

/// Typed, non-collapsed explanation for why a step statically dispatched to the scalar oracle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchFallbackReason {
    /// Caller policy explicitly selected [`KernelBackend::ScalarReference`].
    PolicyForcedScalarReference = 1,
    /// Operator code intentionally delegates to the verified scalar reference kernel.
    OperatorUsesScalarOracle = 2,
    /// Conv2d weights/bias were runtime inputs rather than bound immutable constants.
    DynamicOrUnpackedWeights = 3,
    /// Operator geometry/attributes fell outside specialized tile coverage.
    UnsupportedGeometryOrAttributes = 4,
}

impl DispatchFallbackReason {
    /// Stable canonical string spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyForcedScalarReference => "policy_forced_scalar_reference",
            Self::OperatorUsesScalarOracle => "operator_uses_scalar_oracle",
            Self::DynamicOrUnpackedWeights => "dynamic_or_unpacked_weights",
            Self::UnsupportedGeometryOrAttributes => "unsupported_geometry_or_attributes",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, KernelDispatchError> {
        match tag {
            1 => Ok(Self::PolicyForcedScalarReference),
            2 => Ok(Self::OperatorUsesScalarOracle),
            3 => Ok(Self::DynamicOrUnpackedWeights),
            4 => Ok(Self::UnsupportedGeometryOrAttributes),
            other => Err(KernelDispatchError::MalformedWire(format!(
                "unknown DispatchFallbackReason tag {other}"
            ))),
        }
    }
}

/// Safe operator/agent recovery guidance for a refused static kernel dispatch operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelDispatchGuidance {
    /// Repair alignment, fallback policy, or graph/constant bindings and recompile.
    RepairDispatchPolicyOrGraph,
    /// Raise scratch arena or execution work/byte ceilings or tile the model graph.
    IncreaseBudgetOrTileGraph,
    /// Cooperative cancellation observed cleanly; safe to retry from frozen Model IR.
    RetryCleanly,
    /// Quarantine offending kernel backend and fall back to verified `ScalarReference` oracle.
    QuarantineBackendAndUseScalarOracle,
    /// Reject tampered or corrupt `FSSKDR01` receipt and recompile from frozen Model IR.
    RecompileReceiptFromModelIr,
}

/// Typed fail-closed error emitted by [`StaticKernelDispatcher`].
#[derive(Clone, Debug, PartialEq)]
pub enum KernelDispatchError {
    /// Underlying [`MemoryPlan`] validation or limit failure.
    MemoryPlan(MemoryPlanError),
    /// Underlying [`ScratchArenaPlan`] (`FSS-140`) layout/budget/aliasing failure.
    ScratchPlan(ScratchPlanError),
    /// Underlying execution or preparation error from [`OptimizedGraph`] or [`ScalarExecutor`].
    Execution(String),
    /// Policy set `allow_scalar_fallback == false` but a step required scalar fallback.
    ScalarFallbackForbidden {
        /// Node ID requiring fallback.
        node_id: String,
        /// Stable operator ID.
        op_stable_id: String,
        /// Typed fallback reason.
        reason: DispatchFallbackReason,
    },
    /// Invalid dispatch policy parameter (e.g. invalid alignment).
    InvalidPolicy(String),
    /// Cooperative cancellation observed cleanly.
    Cancelled,
    /// Differential bit-exact check against [`ScalarExecutor`] detected a divergence.
    OracleDivergence {
        /// Output port name that diverged.
        output_name: String,
        /// Diagnostic mismatch detail.
        detail: String,
    },
    /// Wire envelope lacked [`KERNEL_DISPATCH_WIRE_MAGIC`].
    InvalidMagic,
    /// Wire envelope version unsupported.
    UnsupportedVersion {
        /// Unsupported version tag observed.
        version: u32,
    },
    /// Wire checksum or canonical receipt digest mismatch.
    ChecksumMismatch,
    /// Wire payload truncated, oversized, or structurally malformed.
    MalformedWire(String),
}

impl KernelDispatchError {
    /// Stable canonical machine error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MemoryPlan(_) => "ERR-MODEL-DISPATCH-MEMORY-001",
            Self::ScratchPlan(_) => "ERR-MODEL-DISPATCH-SCRATCH-001",
            Self::Execution(_) => "ERR-MODEL-DISPATCH-EXEC-001",
            Self::ScalarFallbackForbidden { .. } => "ERR-MODEL-DISPATCH-FALLBACK-FORBIDDEN-001",
            Self::InvalidPolicy(_) => "ERR-MODEL-DISPATCH-POLICY-001",
            Self::Cancelled => "ERR-MODEL-DISPATCH-CANCELLED-001",
            Self::OracleDivergence { .. } => "ERR-MODEL-DISPATCH-ORACLE-DIVERGENCE-001",
            Self::InvalidMagic | Self::UnsupportedVersion { .. } => "ERR-SCHEMA-UNSUPPORTED-001",
            Self::ChecksumMismatch => "ERR-NEG-CHECKSUM-MISMATCH-001",
            Self::MalformedWire(_) => "ERR-MODEL-DISPATCH-MALFORMED-WIRE-001",
        }
    }

    /// Safe recovery guidance for this refusal.
    #[must_use]
    pub const fn guidance(&self) -> KernelDispatchGuidance {
        match self {
            Self::MemoryPlan(MemoryPlanError::Cancelled)
            | Self::ScratchPlan(ScratchPlanError::Cancelled)
            | Self::Cancelled => KernelDispatchGuidance::RetryCleanly,
            Self::ScratchPlan(ScratchPlanError::BudgetExceeded { .. }) => {
                KernelDispatchGuidance::IncreaseBudgetOrTileGraph
            }
            Self::OracleDivergence { .. } => {
                KernelDispatchGuidance::QuarantineBackendAndUseScalarOracle
            }
            Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::ChecksumMismatch
            | Self::MalformedWire(_) => KernelDispatchGuidance::RecompileReceiptFromModelIr,
            Self::MemoryPlan(_)
            | Self::ScratchPlan(_)
            | Self::Execution(_)
            | Self::ScalarFallbackForbidden { .. }
            | Self::InvalidPolicy(_) => KernelDispatchGuidance::RepairDispatchPolicyOrGraph,
        }
    }
}

impl fmt::Display for KernelDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", self.code(), self)
    }
}

impl Error for KernelDispatchError {}

impl From<MemoryPlanError> for KernelDispatchError {
    fn from(value: MemoryPlanError) -> Self {
        Self::MemoryPlan(value)
    }
}

impl From<ScratchPlanError> for KernelDispatchError {
    fn from(value: ScratchPlanError) -> Self {
        Self::ScratchPlan(value)
    }
}

impl From<ExecError> for KernelDispatchError {
    fn from(value: ExecError) -> Self {
        match value {
            ExecError::CancellationRequested { .. } => Self::Cancelled,
            other => Self::Execution(other.to_string()),
        }
    }
}

/// Immutable static kernel dispatch policy (`FSS-141`).
///
/// Notice `threads` affects runtime wall latency ONLY and is deliberately excluded from
/// [`Self::policy_digest`] so receipts and plan identities remain thread-count invariant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelDispatchPolicy {
    /// Selected kernel family (`OptimizedCpuV1` or `ScalarReference`).
    pub backend: KernelBackend,
    /// Scoped worker thread count (execution telemetry only; never changes outputs or digests).
    pub threads: ExecThreads,
    /// Power-of-two byte alignment enforced on [`ScratchArenaPlan`] slots.
    pub alignment_bytes: usize,
    /// Explicit [`ScratchArenaPlan`] resource ceiling.
    pub scratch_budget: ScratchPlanBudget,
    /// Explicit [`MemoryPlan`] admission bounds.
    pub memory_limits: MemoryPlanLimits,
    /// Whether nodes outside specialized kernels may deterministically fall back to the scalar oracle.
    pub allow_scalar_fallback: bool,
    /// When true, [`StaticDispatchPlan::execute`] differentially checks every output bit against
    /// [`ScalarExecutor`] before returning.
    pub verify_against_scalar_oracle: bool,
}

impl Default for KernelDispatchPolicy {
    fn default() -> Self {
        Self {
            backend: KernelBackend::OptimizedCpuV1,
            threads: ExecThreads::SINGLE,
            alignment_bytes: DEFAULT_SCRATCH_ALIGNMENT,
            scratch_budget: ScratchPlanBudget::ceiling(),
            memory_limits: MemoryPlanLimits::default(),
            allow_scalar_fallback: true,
            verify_against_scalar_oracle: false,
        }
    }
}

impl KernelDispatchPolicy {
    /// Validates static policy invariants before planning.
    pub fn validate(&self) -> Result<(), KernelDispatchError> {
        if self.alignment_bytes == 0
            || !self.alignment_bytes.is_power_of_two()
            || self.alignment_bytes > MAX_SCRATCH_ALIGNMENT
        {
            return Err(KernelDispatchError::InvalidPolicy(format!(
                "alignment_bytes {} must be a power of two in 1..={MAX_SCRATCH_ALIGNMENT}",
                self.alignment_bytes
            )));
        }
        Ok(())
    }

    /// Computes canonical thread-count-invariant digest of the static dispatch policy.
    pub fn policy_digest(&self) -> Result<ContentDigest, KernelDispatchError> {
        self.validate()?;
        let mut enc = CanonicalEncoder::new();
        enc.text(KERNEL_DISPATCH_RECEIPT_DOMAIN);
        enc.text("policy");
        enc.text(self.backend.stable_id());
        enc.digest(self.backend.generation());
        enc.u64(self.alignment_bytes as u64);
        enc.u8(u8::from(self.allow_scalar_fallback));
        let bytes = enc
            .finish_checked()
            .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }
}

/// Sealed per-step static dispatch decision recorded in [`KernelDispatchDecisionReceipt`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeDispatchDecision {
    /// Zero-based static execution step index.
    pub step_index: usize,
    /// Stable node identifier from the frozen Model IR graph.
    pub node_id: String,
    /// Stable operator ID string (e.g. `"conv2d"`, `"silu"`, `"softmax"`).
    pub op_stable_id: String,
    /// Statically selected kernel label (e.g. `"conv2d.gemm_tiles.v1"`, `"scalar-reference-node.v1"`).
    pub kernel_label: String,
    /// True iff this step statically dispatches to the scalar reference oracle.
    pub is_scalar_fallback: bool,
    /// Typed reason when `is_scalar_fallback == true`; `None` for specialized static kernels.
    pub fallback_reason: Option<DispatchFallbackReason>,
    /// Aligned output activation byte offset in [`ScratchArenaPlan`] (0 if scalar-only or unmapped).
    pub output_arena_offset: usize,
    /// Aligned output activation byte reservation in [`ScratchArenaPlan`].
    pub output_aligned_bytes: usize,
    /// Number of F32 elements produced by this step.
    pub output_elements: usize,
}

/// Sealed, immutable static kernel dispatch decision-path receipt (`FSS-141`, `FSSKDR01` v1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelDispatchDecisionReceipt {
    /// Wire format version (`1`).
    pub format_version: u32,
    /// Canonical frozen Model IR graph digest.
    pub graph_digest: ContentDigest,
    /// Underlying [`MemoryPlan`] digest.
    pub memory_plan_digest: ContentDigest,
    /// Underlying zero-aliasing [`ScratchArenaPlan`] digest (`FSS-140`).
    pub scratch_plan_digest: ContentDigest,
    /// Prepared backend plan digest (`OptimizedGraph::digest` or scalar plan commitment).
    pub prepared_plan_digest: ContentDigest,
    /// Selected kernel family stable identifier.
    pub kernel_backend_id: String,
    /// Cryptographic kernel implementation generation digest.
    pub kernel_generation: ContentDigest,
    /// Thread-count-invariant dispatch policy digest.
    pub policy_digest: ContentDigest,
    /// Non-collapsed static dispatch verdict.
    pub outcome_state: DispatchOutcomeState,
    /// Canonical ordered chain digest over every [`NodeDispatchDecision`].
    pub decision_path_digest: ContentDigest,
    /// Whole-graph logical work bound (MACs).
    pub total_macs: u64,
    /// Aligned activation arena byte footprint (`FSS-140`).
    pub activation_arena_bytes: usize,
    /// Dedicated aligned operator scratch tail (`FSS-140`).
    pub operator_scratch_bytes: usize,
    /// Total contiguous arena footprint (`activation_arena_bytes + operator_scratch_bytes`).
    pub total_arena_bytes: usize,
    /// Bytes saved by deterministic scratch slot reuse (`FSS-140`).
    pub reuse_saved_bytes: usize,
    /// Number of statically dispatched steps routed to the scalar oracle.
    pub fallback_node_count: usize,
    /// Ordered static per-step dispatch decision table.
    pub decisions: Vec<NodeDispatchDecision>,
    /// Domain-separated SHA-256 commitment under [`KERNEL_DISPATCH_RECEIPT_DOMAIN`].
    pub receipt_digest: ContentDigest,
}

impl KernelDispatchDecisionReceipt {
    /// Kernel dispatch receipts are derived compilation/cognition evidence and NEVER grant effect authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Computes canonical SHA-256 commitment over the ordered `decisions` table.
    pub fn compute_decision_path_digest(
        decisions: &[NodeDispatchDecision],
    ) -> Result<ContentDigest, KernelDispatchError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(KERNEL_DISPATCH_RECEIPT_DOMAIN);
        enc.text("decision_path");
        enc.u32(decisions.len() as u32);
        for d in decisions {
            encode_decision(d, &mut enc);
        }
        let bytes = enc
            .finish_checked()
            .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    /// Computes canonical SHA-256 receipt commitment under [`KERNEL_DISPATCH_RECEIPT_DOMAIN`].
    pub fn compute_digest(&self) -> Result<ContentDigest, KernelDispatchError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(KERNEL_DISPATCH_RECEIPT_DOMAIN);
        self.encode_fields(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn encode_fields(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.format_version);
        enc.digest(self.graph_digest);
        enc.digest(self.memory_plan_digest);
        enc.digest(self.scratch_plan_digest);
        enc.digest(self.prepared_plan_digest);
        enc.text(&self.kernel_backend_id);
        enc.digest(self.kernel_generation);
        enc.digest(self.policy_digest);
        enc.u8(self.outcome_state.tag());
        enc.digest(self.decision_path_digest);
        enc.u64(self.total_macs);
        enc.u64(self.activation_arena_bytes as u64);
        enc.u64(self.operator_scratch_bytes as u64);
        enc.u64(self.total_arena_bytes as u64);
        enc.u64(self.reuse_saved_bytes as u64);
        enc.u64(self.fallback_node_count as u64);
        enc.u32(self.decisions.len() as u32);
        for d in &self.decisions {
            encode_decision(d, enc);
        }
    }

    /// Validates all structural invariants, step ordering, fallback accounting, and digests.
    pub fn verify_self(&self) -> Result<(), KernelDispatchError> {
        if self.format_version != KERNEL_DISPATCH_WIRE_VERSION {
            return Err(KernelDispatchError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        validate_label(&self.kernel_backend_id, "kernel_backend_id")?;
        if self.decisions.len() > MAX_MEMORY_PLAN_VALUES {
            return Err(KernelDispatchError::MalformedWire(format!(
                "decision count {} exceeds ceiling {MAX_MEMORY_PLAN_VALUES}",
                self.decisions.len()
            )));
        }
        if self
            .activation_arena_bytes
            .checked_add(self.operator_scratch_bytes)
            != Some(self.total_arena_bytes)
        {
            return Err(KernelDispatchError::MalformedWire(
                "arena byte totals inconsistent".to_owned(),
            ));
        }
        let mut fallback_count = 0_usize;
        for (expected_idx, d) in self.decisions.iter().enumerate() {
            if d.step_index != expected_idx {
                return Err(KernelDispatchError::MalformedWire(format!(
                    "step_index {} != expected contiguous index {expected_idx}",
                    d.step_index
                )));
            }
            validate_label(&d.node_id, "node_id")?;
            validate_label(&d.op_stable_id, "op_stable_id")?;
            validate_label(&d.kernel_label, "kernel_label")?;
            if d.is_scalar_fallback != d.fallback_reason.is_some() {
                return Err(KernelDispatchError::MalformedWire(format!(
                    "node '{}' fallback flag disagrees with fallback_reason presence",
                    d.node_id
                )));
            }
            if d.is_scalar_fallback {
                fallback_count += 1;
            }
        }
        if fallback_count != self.fallback_node_count {
            return Err(KernelDispatchError::MalformedWire(format!(
                "fallback_node_count {} disagrees with decisions ({fallback_count})",
                self.fallback_node_count
            )));
        }
        match self.outcome_state {
            DispatchOutcomeState::StaticOptimizedExact if fallback_count != 0 => {
                return Err(KernelDispatchError::MalformedWire(
                    "StaticOptimizedExact cannot carry fallback steps".to_owned(),
                ));
            }
            DispatchOutcomeState::StaticHybridWithScalarFallback if fallback_count == 0 => {
                return Err(KernelDispatchError::MalformedWire(
                    "StaticHybridWithScalarFallback requires >= 1 fallback step".to_owned(),
                ));
            }
            DispatchOutcomeState::ScalarReferenceOnly if fallback_count != self.decisions.len() => {
                return Err(KernelDispatchError::MalformedWire(
                    "ScalarReferenceOnly requires every step to record scalar reference dispatch"
                        .to_owned(),
                ));
            }
            _ => {}
        }
        if Self::compute_decision_path_digest(&self.decisions)? != self.decision_path_digest {
            return Err(KernelDispatchError::ChecksumMismatch);
        }
        if self.compute_digest()? != self.receipt_digest {
            return Err(KernelDispatchError::ChecksumMismatch);
        }
        Ok(())
    }

    /// Encodes into its versioned, checksummed `FSSKDR01` v1 binary wire envelope.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, KernelDispatchError> {
        self.verify_self()?;
        let mut enc = CanonicalEncoder::new();
        self.encode_fields(&mut enc);
        enc.digest(self.receipt_digest);
        let payload = enc
            .finish_checked()
            .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?;
        let total = WIRE_HEADER_BYTES
            .checked_add(payload.len())
            .and_then(|n| n.checked_add(WIRE_CHECKSUM_BYTES))
            .ok_or_else(|| KernelDispatchError::MalformedWire("wire length overflow".to_owned()))?;
        if total > MAX_KERNEL_DISPATCH_WIRE_BYTES {
            return Err(KernelDispatchError::MalformedWire(format!(
                "wire length {total} exceeds ceiling {MAX_KERNEL_DISPATCH_WIRE_BYTES}"
            )));
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&KERNEL_DISPATCH_WIRE_MAGIC);
        out.extend_from_slice(&KERNEL_DISPATCH_WIRE_VERSION.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        let mut hasher = Sha256Hasher::new();
        hasher.update(KERNEL_DISPATCH_RECEIPT_DOMAIN.as_bytes());
        hasher.update(&out);
        let checksum = hasher
            .finalize()
            .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?;
        out.extend_from_slice(&checksum);
        Ok(out)
    }

    /// Strictly decodes an `FSSKDR01` v1 binary wire envelope, failing closed on tamper or drift.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, KernelDispatchError> {
        let min_len = WIRE_HEADER_BYTES + WIRE_CHECKSUM_BYTES;
        if bytes.len() < min_len {
            return Err(KernelDispatchError::MalformedWire(format!(
                "wire length {} below minimum {min_len}",
                bytes.len()
            )));
        }
        if bytes.len() > MAX_KERNEL_DISPATCH_WIRE_BYTES {
            return Err(KernelDispatchError::MalformedWire(format!(
                "wire length {} exceeds ceiling {MAX_KERNEL_DISPATCH_WIRE_BYTES}",
                bytes.len()
            )));
        }
        if bytes[..8] != KERNEL_DISPATCH_WIRE_MAGIC {
            return Err(KernelDispatchError::InvalidMagic);
        }
        let version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if version != KERNEL_DISPATCH_WIRE_VERSION {
            return Err(KernelDispatchError::UnsupportedVersion { version });
        }
        let declared_len =
            u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
        let expected_total = WIRE_HEADER_BYTES
            .checked_add(declared_len)
            .and_then(|n| n.checked_add(WIRE_CHECKSUM_BYTES))
            .ok_or_else(|| {
                KernelDispatchError::MalformedWire("declared payload length overflow".to_owned())
            })?;
        if bytes.len() != expected_total {
            return Err(KernelDispatchError::MalformedWire(format!(
                "wire length {} disagrees with declared payload length {declared_len}",
                bytes.len()
            )));
        }
        let split_at = bytes.len() - WIRE_CHECKSUM_BYTES;
        let (body, trailer) = bytes.split_at(split_at);
        let mut hasher = Sha256Hasher::new();
        hasher.update(KERNEL_DISPATCH_RECEIPT_DOMAIN.as_bytes());
        hasher.update(body);
        let computed = hasher
            .finalize()
            .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?;
        if computed.as_slice() != trailer {
            return Err(KernelDispatchError::ChecksumMismatch);
        }

        let mut dec = CanonicalDecoder::new(&body[WIRE_HEADER_BYTES..]);
        let format_version = dec
            .u32()
            .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?;
        let graph_digest = dec
            .digest()
            .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?;
        let memory_plan_digest = dec
            .digest()
            .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?;
        let scratch_plan_digest = dec
            .digest()
            .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?;
        let prepared_plan_digest = dec
            .digest()
            .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?;
        let kernel_backend_id = dec
            .text()
            .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?
            .to_owned();
        let kernel_generation = dec
            .digest()
            .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?;
        let policy_digest = dec
            .digest()
            .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?;
        let outcome_state = DispatchOutcomeState::from_tag(
            dec.u8()
                .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?,
        )?;
        let decision_path_digest = dec
            .digest()
            .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?;
        let total_macs = dec
            .u64()
            .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?;
        let activation_arena_bytes = decode_usize(&mut dec)?;
        let operator_scratch_bytes = decode_usize(&mut dec)?;
        let total_arena_bytes = decode_usize(&mut dec)?;
        let reuse_saved_bytes = decode_usize(&mut dec)?;
        let fallback_node_count = decode_usize(&mut dec)?;
        let count = dec
            .u32()
            .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?
            as usize;
        if count > MAX_MEMORY_PLAN_VALUES {
            return Err(KernelDispatchError::MalformedWire(format!(
                "decision count {count} exceeds ceiling {MAX_MEMORY_PLAN_VALUES}"
            )));
        }
        let mut decisions = Vec::with_capacity(count);
        for _ in 0..count {
            let step_index = decode_usize(&mut dec)?;
            let node_id = dec
                .text()
                .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?
                .to_owned();
            let op_stable_id = dec
                .text()
                .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?
                .to_owned();
            let kernel_label = dec
                .text()
                .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?
                .to_owned();
            let is_scalar_fallback = match dec
                .u8()
                .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?
            {
                0 => false,
                1 => true,
                other => {
                    return Err(KernelDispatchError::MalformedWire(format!(
                        "unknown is_scalar_fallback tag {other}"
                    )));
                }
            };
            let fallback_reason = match dec
                .u8()
                .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?
            {
                0 => None,
                1 => Some(DispatchFallbackReason::from_tag(dec.u8().map_err(
                    |e| KernelDispatchError::MalformedWire(e.to_string()),
                )?)?),
                other => {
                    return Err(KernelDispatchError::MalformedWire(format!(
                        "unknown fallback_reason option tag {other}"
                    )));
                }
            };
            let output_arena_offset = decode_usize(&mut dec)?;
            let output_aligned_bytes = decode_usize(&mut dec)?;
            let output_elements = decode_usize(&mut dec)?;
            decisions.push(NodeDispatchDecision {
                step_index,
                node_id,
                op_stable_id,
                kernel_label,
                is_scalar_fallback,
                fallback_reason,
                output_arena_offset,
                output_aligned_bytes,
                output_elements,
            });
        }
        let receipt_digest = dec
            .digest()
            .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?;
        dec.ensure_finished()
            .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?;

        let receipt = Self {
            format_version,
            graph_digest,
            memory_plan_digest,
            scratch_plan_digest,
            prepared_plan_digest,
            kernel_backend_id,
            kernel_generation,
            policy_digest,
            outcome_state,
            decision_path_digest,
            total_macs,
            activation_arena_bytes,
            operator_scratch_bytes,
            total_arena_bytes,
            reuse_saved_bytes,
            fallback_node_count,
            decisions,
            receipt_digest,
        };
        receipt.verify_self()?;
        Ok(receipt)
    }
}

/// Result of executing a statically dispatched plan alongside its sealed receipt and run report.
#[derive(Clone, Debug)]
pub struct DispatchedExecution {
    /// Deterministic execution outputs and logical work/byte accounting.
    pub outcome: ExecOutcome,
    /// Optional runtime payload telemetry from [`OptimizedGraph`] (None for scalar-only backend).
    pub optimized_report: Option<OptimizedRunReport>,
    /// Sealed immutable static dispatch decision-path receipt (`FSSKDR01` v1).
    pub receipt: KernelDispatchDecisionReceipt,
    /// True iff differential 0-ULP scalar oracle verification was executed and passed.
    pub oracle_bit_exact_verified: bool,
}

/// Immutable compiled static kernel dispatch plan (`FSS-141`).
#[derive(Clone, Debug)]
pub struct StaticDispatchPlan {
    graph: ModelIrGraph,
    constants: BTreeMap<String, Vec<f32>>,
    policy: KernelDispatchPolicy,
    scratch_plan: ScratchArenaPlan,
    optimized: Option<OptimizedGraph>,
    receipt: KernelDispatchDecisionReceipt,
}

impl StaticDispatchPlan {
    /// Immutable sealed [`KernelDispatchDecisionReceipt`] produced at compile time.
    #[must_use]
    pub fn receipt(&self) -> &KernelDispatchDecisionReceipt {
        &self.receipt
    }

    /// Underlying zero-aliasing [`ScratchArenaPlan`] (`FSS-140`).
    #[must_use]
    pub fn scratch_plan(&self) -> &ScratchArenaPlan {
        &self.scratch_plan
    }

    /// Executes the statically dispatched plan against `runtime_inputs`, honoring `budget` and `cx`.
    pub fn execute<S: AsRef<str>>(
        &self,
        runtime_inputs: &[(S, Tensor)],
        budget: ExecBudget,
        cx: &ScalarExecCx,
    ) -> Result<DispatchedExecution, KernelDispatchError> {
        cx.checkpoint("kernel-dispatch:execute")?;
        let (outcome, optimized_report) = match &self.optimized {
            Some(opt) => {
                let (out, rep) =
                    opt.run_threaded(runtime_inputs, budget, self.policy.threads, cx)?;
                (out, Some(rep))
            }
            None => {
                let full_bindings = self.assemble_full_bindings(runtime_inputs)?;
                let out = ScalarExecutor::run(&self.graph, &full_bindings, budget, cx)?;
                (out, None)
            }
        };

        let mut oracle_verified = false;
        if self.policy.verify_against_scalar_oracle {
            let full_bindings = self.assemble_full_bindings(runtime_inputs)?;
            let oracle = ScalarExecutor::run(&self.graph, &full_bindings, budget, cx)?;
            verify_outcomes_bit_exact(&outcome, &oracle)?;
            oracle_verified = true;
        }

        Ok(DispatchedExecution {
            outcome,
            optimized_report,
            receipt: self.receipt.clone(),
            oracle_bit_exact_verified: oracle_verified,
        })
    }

    fn assemble_full_bindings<S: AsRef<str>>(
        &self,
        runtime_inputs: &[(S, Tensor)],
    ) -> Result<Vec<(String, Tensor)>, KernelDispatchError> {
        let mut all = Vec::with_capacity(self.constants.len() + runtime_inputs.len());
        for (name, values) in &self.constants {
            let port = self.graph.find_input(name).ok_or_else(|| {
                KernelDispatchError::InvalidPolicy(format!(
                    "bound constant '{name}' missing from graph inputs"
                ))
            })?;
            let shape: Shape = port.shape().clone();
            let tensor = Tensor::from_values(shape, values, self.graph.generation())
                .map_err(|e| KernelDispatchError::Execution(e.to_string()))?;
            if tensor.dtype() != DType::F32 {
                return Err(KernelDispatchError::Execution(
                    "bound constant must be F32".to_owned(),
                ));
            }
            all.push((name.clone(), tensor));
        }
        for (name, tensor) in runtime_inputs {
            all.push((name.as_ref().to_owned(), tensor.clone()));
        }
        Ok(all)
    }
}

/// Static kernel dispatcher compiling frozen Model IR + constants into sealed [`StaticDispatchPlan`].
pub struct StaticKernelDispatcher;

impl StaticKernelDispatcher {
    /// Compiles and seals a deterministic static dispatch plan + `FSSKDR01` decision-path receipt.
    pub fn compile(
        graph: &ModelIrGraph,
        constants: &BTreeMap<String, Vec<f32>>,
        policy: KernelDispatchPolicy,
        cx: &ScalarExecCx,
    ) -> Result<StaticDispatchPlan, KernelDispatchError> {
        cx.checkpoint("kernel-dispatch:compile-begin")?;
        policy.validate()?;
        let policy_digest = policy.policy_digest()?;

        let memory_plan =
            MemoryPlan::compile_cancellable(graph, policy.memory_limits, || cx.is_cancelled())?;
        let step_scratch = vec![0_usize; memory_plan.steps().len()];
        let scratch_plan = ScratchArenaPlan::compile(
            &memory_plan,
            policy.alignment_bytes,
            &step_scratch,
            policy.scratch_budget,
            || cx.is_cancelled(),
        )?;

        // Map produced tensor name -> `(arena_offset, aligned_bytes)` for exact receipt binding.
        let mut slot_map: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
        for slot in &scratch_plan.assignments {
            slot_map.insert(
                slot.tensor_name.as_str(),
                (slot.arena_offset, slot.aligned_bytes),
            );
        }

        // Map node_id -> primary output tensor name from frozen Model IR.
        let mut node_primary_out: BTreeMap<&str, &str> = BTreeMap::new();
        for node in graph.nodes() {
            if let Some(first_out) = node.outputs().first() {
                node_primary_out.insert(node.id(), first_out.as_str());
            }
        }

        let (optimized, prepared_plan_digest, total_macs, decisions) = match policy.backend {
            KernelBackend::OptimizedCpuV1 => {
                let opt = OptimizedGraph::prepare(graph, constants, cx)?;
                let descriptors = opt.step_descriptors();
                let mut decs = Vec::with_capacity(descriptors.len());
                for desc in descriptors {
                    let fallback_reason = if desc.is_scalar_fallback {
                        let reason = classify_fallback_reason(&desc, graph, constants);
                        if !policy.allow_scalar_fallback {
                            return Err(KernelDispatchError::ScalarFallbackForbidden {
                                node_id: desc.node_id,
                                op_stable_id: desc.op.stable_id().to_owned(),
                                reason,
                            });
                        }
                        Some(reason)
                    } else {
                        None
                    };
                    let (offset, aligned_bytes) = node_primary_out
                        .get(desc.node_id.as_str())
                        .and_then(|out_name| slot_map.get(out_name).copied())
                        .unwrap_or((0, 0));
                    decs.push(NodeDispatchDecision {
                        step_index: desc.step_index,
                        node_id: desc.node_id,
                        op_stable_id: desc.op.stable_id().to_owned(),
                        kernel_label: desc.kernel_label.to_owned(),
                        is_scalar_fallback: desc.is_scalar_fallback,
                        fallback_reason,
                        output_arena_offset: offset,
                        output_aligned_bytes: aligned_bytes,
                        output_elements: desc.output_len,
                    });
                }
                let digest = opt.digest();
                let macs = opt.total_macs();
                (Some(opt), digest, macs, decs)
            }
            KernelBackend::ScalarReference => {
                let compiled_scalar = crate::planned_scalar::CompiledScalarPlan::compile(
                    graph,
                    policy.memory_limits,
                    cx,
                )
                .map_err(|e| KernelDispatchError::Execution(e.to_string()))?;
                let scalar_macs = compiled_scalar.minimum_requirements().macs;
                let canonical_graph = encode_canonical_model_ir(graph)
                    .map_err(|e| KernelDispatchError::Execution(e.to_string()))?;
                let mut enc = CanonicalEncoder::new();
                enc.text(KERNEL_DISPATCH_RECEIPT_DOMAIN);
                enc.text("scalar_plan");
                enc.digest(KernelBackend::ScalarReference.generation());
                enc.digest(ContentDigest::sha256(&canonical_graph));
                let plan_digest = ContentDigest::sha256(
                    &enc.finish_checked()
                        .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?,
                );
                let mut decs = Vec::with_capacity(memory_plan.steps().len());
                for (step_index, step) in memory_plan.steps().iter().enumerate() {
                    let node_id = step.node_id();
                    let op_stable_id = graph
                        .nodes()
                        .iter()
                        .find(|n| n.id() == node_id)
                        .map(|n| n.op().stable_id())
                        .unwrap_or("unknown");
                    let first_out = step.produced().first().map(String::as_str);
                    let (offset, aligned_bytes) = first_out
                        .and_then(|name| slot_map.get(name).copied())
                        .unwrap_or((0, 0));
                    let output_elements = first_out
                        .and_then(|name| memory_plan.values().get(name))
                        .map_or(0, |lt| lt.bytes() / 4);
                    decs.push(NodeDispatchDecision {
                        step_index,
                        node_id: node_id.to_owned(),
                        op_stable_id: op_stable_id.to_owned(),
                        kernel_label: "scalar-reference-node.v1".to_owned(),
                        is_scalar_fallback: true,
                        fallback_reason: Some(DispatchFallbackReason::PolicyForcedScalarReference),
                        output_arena_offset: offset,
                        output_aligned_bytes: aligned_bytes,
                        output_elements,
                    });
                }
                (None, plan_digest, scalar_macs, decs)
            }
        };

        let fallback_node_count = decisions.iter().filter(|d| d.is_scalar_fallback).count();
        let outcome_state = match policy.backend {
            KernelBackend::ScalarReference => DispatchOutcomeState::ScalarReferenceOnly,
            KernelBackend::OptimizedCpuV1 if fallback_node_count == 0 => {
                DispatchOutcomeState::StaticOptimizedExact
            }
            KernelBackend::OptimizedCpuV1 => DispatchOutcomeState::StaticHybridWithScalarFallback,
        };
        let decision_path_digest =
            KernelDispatchDecisionReceipt::compute_decision_path_digest(&decisions)?;

        let mut receipt = KernelDispatchDecisionReceipt {
            format_version: KERNEL_DISPATCH_WIRE_VERSION,
            graph_digest: memory_plan.graph_digest(),
            memory_plan_digest: memory_plan.digest(),
            scratch_plan_digest: scratch_plan.plan_digest,
            prepared_plan_digest,
            kernel_backend_id: policy.backend.stable_id().to_owned(),
            kernel_generation: policy.backend.generation(),
            policy_digest,
            outcome_state,
            decision_path_digest,
            total_macs,
            activation_arena_bytes: scratch_plan.activation_arena_bytes,
            operator_scratch_bytes: scratch_plan.operator_scratch_bytes,
            total_arena_bytes: scratch_plan.total_arena_bytes,
            reuse_saved_bytes: scratch_plan.reuse_saved_bytes,
            fallback_node_count,
            decisions,
            receipt_digest: ContentDigest::sha256(b"unsealed-kernel-dispatch-receipt"),
        };
        receipt.receipt_digest = receipt.compute_digest()?;
        receipt.verify_self()?;

        cx.checkpoint("kernel-dispatch:compile-done")?;
        Ok(StaticDispatchPlan {
            graph: graph.clone(),
            constants: constants.clone(),
            policy,
            scratch_plan,
            optimized,
            receipt,
        })
    }
}

fn classify_fallback_reason(
    desc: &OptimizedStepDescriptor,
    graph: &ModelIrGraph,
    constants: &BTreeMap<String, Vec<f32>>,
) -> DispatchFallbackReason {
    match desc.op {
        OpCode::Gelu
        | OpCode::Tanh
        | OpCode::Sqrt
        | OpCode::Erf
        | OpCode::LayerNorm
        | OpCode::RMSNorm
        | OpCode::Softmax
        | OpCode::Embedding => DispatchFallbackReason::OperatorUsesScalarOracle,
        OpCode::Conv2d => {
            if let Some(node) = graph.nodes().iter().find(|n| n.id() == desc.node_id) {
                let w_const = node
                    .inputs()
                    .get(1)
                    .is_some_and(|w| constants.contains_key(w));
                let b_const = node
                    .inputs()
                    .get(2)
                    .is_none_or(|b| constants.contains_key(b));
                if !w_const || !b_const {
                    return DispatchFallbackReason::DynamicOrUnpackedWeights;
                }
            }
            DispatchFallbackReason::UnsupportedGeometryOrAttributes
        }
        _ => DispatchFallbackReason::UnsupportedGeometryOrAttributes,
    }
}

fn verify_outcomes_bit_exact(
    candidate: &ExecOutcome,
    oracle: &ExecOutcome,
) -> Result<(), KernelDispatchError> {
    if candidate.outputs().len() != oracle.outputs().len() {
        return Err(KernelDispatchError::OracleDivergence {
            output_name: "*".to_owned(),
            detail: format!(
                "output port count {} != oracle {}",
                candidate.outputs().len(),
                oracle.outputs().len()
            ),
        });
    }
    for (name, oracle_tensor) in oracle.outputs() {
        let Some(cand_tensor) = candidate.get_output(name) else {
            return Err(KernelDispatchError::OracleDivergence {
                output_name: name.clone(),
                detail: "missing output port in candidate execution".to_owned(),
            });
        };
        if cand_tensor.shape() != oracle_tensor.shape()
            || cand_tensor.dtype() != oracle_tensor.dtype()
        {
            return Err(KernelDispatchError::OracleDivergence {
                output_name: name.clone(),
                detail: "shape or dtype mismatch against scalar oracle".to_owned(),
            });
        }
        let cand_vals = cand_tensor
            .to_vec::<f32>()
            .map_err(|e| KernelDispatchError::Execution(e.to_string()))?;
        let oracle_vals = oracle_tensor
            .to_vec::<f32>()
            .map_err(|e| KernelDispatchError::Execution(e.to_string()))?;
        for (idx, (c, o)) in cand_vals.iter().zip(oracle_vals.iter()).enumerate() {
            if c.is_nan() && o.is_nan() {
                continue;
            }
            if c.to_bits() != o.to_bits() {
                return Err(KernelDispatchError::OracleDivergence {
                    output_name: name.clone(),
                    detail: format!(
                        "element {idx} diverged: candidate={} (0x{:08x}) != oracle={} (0x{:08x})",
                        c,
                        c.to_bits(),
                        o,
                        o.to_bits()
                    ),
                });
            }
        }
    }
    Ok(())
}

fn encode_decision(d: &NodeDispatchDecision, enc: &mut CanonicalEncoder) {
    enc.u64(d.step_index as u64);
    enc.text(&d.node_id);
    enc.text(&d.op_stable_id);
    enc.text(&d.kernel_label);
    enc.u8(u8::from(d.is_scalar_fallback));
    match d.fallback_reason {
        None => enc.u8(0),
        Some(r) => {
            enc.u8(1);
            enc.u8(r.tag());
        }
    }
    enc.u64(d.output_arena_offset as u64);
    enc.u64(d.output_aligned_bytes as u64);
    enc.u64(d.output_elements as u64);
}

fn validate_label(value: &str, label: &str) -> Result<(), KernelDispatchError> {
    if value.is_empty()
        || value.len() > MAX_DISPATCH_LABEL_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(KernelDispatchError::MalformedWire(format!(
            "{label} invalid length or contains control characters"
        )));
    }
    Ok(())
}

fn decode_usize(dec: &mut CanonicalDecoder<'_>) -> Result<usize, KernelDispatchError> {
    let raw = dec
        .u64()
        .map_err(|e| KernelDispatchError::MalformedWire(e.to_string()))?;
    usize::try_from(raw)
        .map_err(|_| KernelDispatchError::MalformedWire("usize overflow on decode".to_owned()))
}
