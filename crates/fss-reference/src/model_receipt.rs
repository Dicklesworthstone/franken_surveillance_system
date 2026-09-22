#![forbid(unsafe_code)]

//! Model execution invocation receipt for pure-Rust scalar reference executor (fss-2h5zq.47).
//!
//! Conforms to schema `fss.model_execution_receipt.v1` (`schemas/model_execution_receipt.v1.json`).
//!
//! # Schema Finding for the Owner
//! The schema `schemas/model_execution_receipt.v1.json` specifies `modelPackageRoot` and
//! `activationGeneration` as required digests constrained to `sensor_capsule.v1.json#/$defs/digest`
//! (`^[a-z0-9][a-z0-9_-]*:[0-9a-f]{32,}$`). The schema currently has no mechanism to declare a
//! `not_applicable` or unactivated state for required digests without resorting to sentinels.
//! Per ADR-0001 / ADR-0013 and bead `fss-2h5zq.47` requirements, we do not alter the schema.
//! Instead, we emit domain-separated sentinels using the distinct scheme `fss-na:<64-hex>`,
//! computed from `fss.model_execution_receipt.v1/sentinel/<field>/<reason>`. This satisfies the
//! JSON Schema regex while strictly failing pure-Rust `ContentDigest::parse`, preventing any
//! consumer from mistaking non-applicable fields for authentic content addresses.
//! Every receipt carrying any `fss-na:` sentinel is marked `is_reference_only() == true`,
//! precluding it from granting effect authority or acting as activation-backed evidence.

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};

use fss_core::CanonicalEncoder;
use fss_core::{ContentDigest, ContractError, Generation};
use fss_model_ir::{
    ModelIrError, ModelIrGraph, OPERATOR_TABLE_FREEZE_DIGEST, OpCode, compute_model_ir_digest,
    verify_operator_table_frozen,
};
use fss_tensor::{DType, Tensor};

use crate::clock::VirtualClock;
use crate::scalar_executor::{
    ChannelTransform, ExecBudget, ExecError, ExecOutcome, PreprocessProgram, ScalarExecCx,
    ScalarExecutor,
};

/// Canonical digest domain for model execution receipts.
pub const MODEL_EXECUTION_RECEIPT_DOMAIN: &str = "fss.model_execution_receipt.receipt.v1";

/// Error type emitted during receipt construction, digest parsing, or verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiptVerificationError {
    /// Schema const string mismatch.
    SchemaConstMismatch { expected: String, actual: String },
    /// Model IR graph generation mismatch.
    GenerationMismatch {
        expected: Generation,
        actual: Generation,
    },
    /// Recomputed canonical receipt digest does not match expected digest.
    DigestMismatch {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    /// Inconsistent outcome fields.
    InconsistentOutcome { reason: String },
    /// Invalid digest syntax or missing hex.
    InvalidDigestFormat { text: String },
    /// Model IR error.
    Ir(ModelIrError),
    /// Contract error.
    Contract(ContractError),
}

impl fmt::Display for ReceiptVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemaConstMismatch { expected, actual } => {
                write!(
                    f,
                    "Schema const mismatch: expected '{expected}', got '{actual}'"
                )
            }
            Self::GenerationMismatch { expected, actual } => {
                write!(f, "Generation mismatch: expected {expected}, got {actual}")
            }
            Self::DigestMismatch { expected, actual } => {
                write!(
                    f,
                    "Digest mismatch: expected {}, got {}",
                    expected.to_text(),
                    actual.to_text()
                )
            }
            Self::InconsistentOutcome { reason } => {
                write!(f, "Inconsistent outcome in receipt: {reason}")
            }
            Self::InvalidDigestFormat { text } => {
                write!(f, "Invalid digest format: '{text}'")
            }
            Self::Ir(err) => write!(f, "Model IR error: {err}"),
            Self::Contract(err) => write!(f, "Contract error: {err}"),
        }
    }
}

impl std::error::Error for ReceiptVerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ir(err) => Some(err),
            Self::Contract(err) => Some(err),
            _ => None,
        }
    }
}

impl From<ModelIrError> for ReceiptVerificationError {
    fn from(err: ModelIrError) -> Self {
        Self::Ir(err)
    }
}

impl From<ContractError> for ReceiptVerificationError {
    fn from(err: ContractError) -> Self {
        Self::Contract(err)
    }
}

/// Helper formatting bytes into lowercase hexadecimal string.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ContentDigest::sha256(bytes);
    let mut s = String::with_capacity(64);
    for b in digest.bytes() {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// A receipt digest field, which may either be an authentic [`ContentDigest`] or a typed
/// `NotApplicable` sentinel.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReceiptDigest {
    /// Authentic content-addressed payload digest (`sha256:` or `blake3:`).
    Content(ContentDigest),
    /// Explicit, typed sentinel for non-applicable required schema fields (`fss-na:`).
    NotApplicable {
        /// The target field name (e.g. `activationGeneration`).
        field: String,
        /// Reason for non-applicability (e.g. `unactivated_reference_run`).
        reason: String,
        /// Precomputed 64-hex SHA-256 over `fss.model_execution_receipt.v1/sentinel/<field>/<reason>`.
        sentinel_hex: String,
    },
}

impl ReceiptDigest {
    /// Constructs a content digest.
    #[must_use]
    pub const fn content(digest: ContentDigest) -> Self {
        Self::Content(digest)
    }

    /// Constructs a typed non-applicable sentinel.
    #[must_use]
    pub fn not_applicable(field: impl Into<String>, reason: impl Into<String>) -> Self {
        let field_str = field.into();
        let reason_str = reason.into();
        let seed = format!("fss.model_execution_receipt.v1/sentinel/{field_str}/{reason_str}");
        let sentinel_hex = sha256_hex(seed.as_bytes());
        Self::NotApplicable {
            field: field_str,
            reason: reason_str,
            sentinel_hex,
        }
    }

    /// Formats the digest as a schema-compliant string.
    #[must_use]
    pub fn to_text(&self) -> String {
        match self {
            Self::Content(digest) => digest.to_text(),
            Self::NotApplicable { sentinel_hex, .. } => format!("fss-na:{sentinel_hex}"),
        }
    }

    /// Returns `true` if this digest is a non-applicable sentinel.
    #[must_use]
    pub const fn is_not_applicable(&self) -> bool {
        matches!(self, Self::NotApplicable { .. })
    }

    /// Returns `true` if this digest is an authentic content digest.
    #[must_use]
    pub const fn is_content(&self) -> bool {
        matches!(self, Self::Content(_))
    }

    /// Returns reference to content digest if authentic.
    #[must_use]
    pub const fn as_content(&self) -> Option<&ContentDigest> {
        match self {
            Self::Content(d) => Some(d),
            Self::NotApplicable { .. } => None,
        }
    }

    /// Canonical binary encoding for deterministic digest inclusion.
    pub fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::Content(digest) => {
                encoder.tag(1);
                encoder.digest(*digest);
            }
            Self::NotApplicable {
                field,
                reason,
                sentinel_hex,
            } => {
                encoder.tag(2);
                encoder.text(field);
                encoder.text(reason);
                encoder.text(sentinel_hex);
            }
        }
    }
}

impl fmt::Display for ReceiptDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_text())
    }
}

/// Execution outcome status enum adhering to `schemas/model_execution_receipt.v1.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptOutcome {
    /// Graph execution completed successfully.
    Ok,
    /// Execution failed with a deterministic typed error.
    Error,
    /// Cooperative cancellation was requested and completed.
    Cancelled,
    /// Execution exceeded configured computational MACs or memory allocation budgets.
    BudgetExhausted,
}

impl ReceiptOutcome {
    /// String token matching the JSON Schema enum.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
            Self::Cancelled => "cancelled",
            Self::BudgetExhausted => "budget_exhausted",
        }
    }
}

/// Hardware and engine backend description.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendDescriptor {
    /// Backend identifier (<= 128 chars).
    pub id: String,
    /// Concrete implementation identifier (<= 256 chars).
    pub implementation: String,
    /// Host execution environment or device profile (<= 512 chars).
    pub hardware: String,
    /// Feature tags and declared sentinels (each <= 128 chars, max 128 items).
    pub feature_set: Vec<String>,
}

impl BackendDescriptor {
    /// Constructs the reference scalar backend descriptor.
    #[must_use]
    pub fn scalar_reference(sentinels: &[(&str, &str)]) -> Self {
        let mut feature_set = vec![
            "f32".to_string(),
            "fixed-order".to_string(),
            "no-fma".to_string(),
        ];
        for (field, reason) in sentinels {
            let entry = format!("sentinel:{field}={reason}");
            if entry.len() <= 128 && feature_set.len() < 128 {
                feature_set.push(entry);
            }
        }
        Self {
            id: "scalar-reference".to_string(),
            implementation: "fss-reference scalar_executor@1".to_string(),
            hardware: "host-independent-scalar".to_string(),
            feature_set,
        }
    }

    /// Canonical binary encoding for deterministic digest inclusion.
    pub fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.id);
        encoder.text(&self.implementation);
        encoder.text(&self.hardware);
        encoder.u64(self.feature_set.len() as u64);
        for feat in &self.feature_set {
            encoder.text(feat);
        }
    }
}

/// Execution resource quota budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ReceiptBudget {
    /// Maximum allowed input tensor bytes.
    pub input_bytes: usize,
    /// Maximum allowed output tensor bytes.
    pub output_bytes: usize,
    /// Maximum allowed peak resident buffer bytes.
    pub peak_bytes: usize,
    /// Maximum allowed work units (multiply-accumulate operations).
    pub work_units: u64,
    /// Virtual wall time quota in nanoseconds.
    pub wall_ns: u64,
}

impl ReceiptBudget {
    /// Constructs a receipt budget from [`ExecBudget`] and input/output bounds.
    #[must_use]
    pub const fn new(
        input_bytes: usize,
        output_bytes: usize,
        peak_bytes: usize,
        work_units: u64,
        wall_ns: u64,
    ) -> Self {
        Self {
            input_bytes,
            output_bytes,
            peak_bytes,
            work_units,
            wall_ns,
        }
    }

    /// Canonical binary encoding.
    pub fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.input_bytes as u64);
        encoder.u64(self.output_bytes as u64);
        encoder.u64(self.peak_bytes as u64);
        encoder.u64(self.work_units);
        encoder.u64(self.wall_ns);
    }
}

/// Actual measured execution resource usage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ReceiptUsage {
    /// Total input tensor bytes bound.
    pub input_bytes: usize,
    /// Total output tensor bytes produced.
    pub output_bytes: usize,
    /// Peak resident buffer bytes allocated.
    pub peak_bytes: usize,
    /// Total multiply-accumulate operations executed.
    pub work_units: u64,
    /// Virtual wall time consumed in nanoseconds (from VirtualClock, never host clock).
    pub wall_ns: u64,
}

impl ReceiptUsage {
    /// Constructs a receipt usage measurement.
    #[must_use]
    pub const fn new(
        input_bytes: usize,
        output_bytes: usize,
        peak_bytes: usize,
        work_units: u64,
        wall_ns: u64,
    ) -> Self {
        Self {
            input_bytes,
            output_bytes,
            peak_bytes,
            work_units,
            wall_ns,
        }
    }

    /// Canonical binary encoding.
    pub fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.input_bytes as u64);
        encoder.u64(self.output_bytes as u64);
        encoder.u64(self.peak_bytes as u64);
        encoder.u64(self.work_units);
        encoder.u64(self.wall_ns);
    }
}

/// Model execution invocation receipt binding graph, inputs, outputs, executor, and telemetry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelInvocationReceipt {
    /// Schema identity (`fss.model_execution_receipt.v1`).
    pub schema: String,
    /// Deterministic job identifier.
    pub job_id: String,
    /// Roots of input tensors or upstream decode receipts.
    pub input_roots: Vec<ReceiptDigest>,
    /// Verified package root or non-applicable sentinel for inline test graphs.
    pub model_package_root: ReceiptDigest,
    /// Activation generation or unactivated sentinel.
    pub activation_generation: ReceiptDigest,
    /// Descriptor digest of preprocessing program.
    pub preprocess_program: ReceiptDigest,
    /// Descriptor digest of postprocessing program.
    pub postprocess_program: ReceiptDigest,
    /// Frozen operator registry generation digest.
    pub operator_registry_generation: ReceiptDigest,
    /// Domain-separated execution plan digest.
    pub execution_plan_digest: ReceiptDigest,
    /// Hardware and implementation backend.
    pub backend: BackendDescriptor,
    /// Numeric policy descriptor digest.
    pub numeric_policy_digest: ReceiptDigest,
    /// Resource execution budget.
    pub budget: ReceiptBudget,
    /// Actual resource execution usage.
    pub usage: ReceiptUsage,
    /// Final execution outcome.
    pub outcome: ReceiptOutcome,
    /// Cooperative cancellation stage if cancelled.
    pub cancel_reason: Option<String>,
    /// Stable error ID if error occurred.
    pub error_id: Option<String>,
    /// Output tensor root digest on success.
    pub output_root: Option<ReceiptDigest>,
    /// Operator trace hash chain digest on success.
    pub operator_trace_digest: Option<ReceiptDigest>,
    /// Decision path execution trace digest.
    pub decision_path_digest: ReceiptDigest,
    /// Graph generation anchor.
    pub generation: Generation,
}

impl ModelInvocationReceipt {
    /// Returns `true` if any field contains a `NotApplicable` sentinel, indicating this
    /// receipt represents reference-only execution and cannot serve as activation-backed evidence.
    #[must_use]
    pub fn is_reference_only(&self) -> bool {
        self.model_package_root.is_not_applicable()
            || self.activation_generation.is_not_applicable()
            || self
                .input_roots
                .iter()
                .any(ReceiptDigest::is_not_applicable)
            || self.preprocess_program.is_not_applicable()
            || self.postprocess_program.is_not_applicable()
            || self.operator_registry_generation.is_not_applicable()
            || self.execution_plan_digest.is_not_applicable()
            || self.numeric_policy_digest.is_not_applicable()
            || self.decision_path_digest.is_not_applicable()
            || self
                .output_root
                .as_ref()
                .is_some_and(ReceiptDigest::is_not_applicable)
            || self
                .operator_trace_digest
                .as_ref()
                .is_some_and(ReceiptDigest::is_not_applicable)
    }

    /// Computes the deterministic canonical digest over all bound fields under
    /// `fss.model_execution_receipt.receipt.v1`.
    #[must_use]
    pub fn compute_canonical_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.canonical.v1");
        encoder.text(MODEL_EXECUTION_RECEIPT_DOMAIN);
        encoder.text(&self.schema);
        encoder.u64(self.generation.as_u64());
        encoder.text(&self.job_id);

        encoder.u64(self.input_roots.len() as u64);
        for root in &self.input_roots {
            root.encode_canonical(&mut encoder);
        }

        self.model_package_root.encode_canonical(&mut encoder);
        self.activation_generation.encode_canonical(&mut encoder);
        self.preprocess_program.encode_canonical(&mut encoder);
        self.postprocess_program.encode_canonical(&mut encoder);
        self.operator_registry_generation
            .encode_canonical(&mut encoder);
        self.execution_plan_digest.encode_canonical(&mut encoder);
        self.backend.encode_canonical(&mut encoder);
        self.numeric_policy_digest.encode_canonical(&mut encoder);
        self.budget.encode_canonical(&mut encoder);
        self.usage.encode_canonical(&mut encoder);

        encoder.text(self.outcome.as_str());

        match &self.cancel_reason {
            Some(reason) => {
                encoder.tag(1);
                encoder.text(reason);
            }
            None => encoder.tag(0),
        }

        match &self.error_id {
            Some(err) => {
                encoder.tag(1);
                encoder.text(err);
            }
            None => encoder.tag(0),
        }

        match &self.output_root {
            Some(out_root) => {
                encoder.tag(1);
                out_root.encode_canonical(&mut encoder);
            }
            None => encoder.tag(0),
        }

        match &self.operator_trace_digest {
            Some(trace) => {
                encoder.tag(1);
                trace.encode_canonical(&mut encoder);
            }
            None => encoder.tag(0),
        }

        self.decision_path_digest.encode_canonical(&mut encoder);

        ContentDigest::sha256(&encoder.finish())
    }

    /// Verifies that the receipt matches the expected generation and expected canonical digest,
    /// and that its internal outcome fields are fully consistent.
    pub fn verify(
        &self,
        expected_generation: Generation,
        expected_digest: &ContentDigest,
    ) -> Result<(), ReceiptVerificationError> {
        if self.schema != "fss.model_execution_receipt.v1" {
            return Err(ReceiptVerificationError::SchemaConstMismatch {
                expected: "fss.model_execution_receipt.v1".to_string(),
                actual: self.schema.clone(),
            });
        }
        if self.generation != expected_generation {
            return Err(ReceiptVerificationError::GenerationMismatch {
                expected: expected_generation,
                actual: self.generation,
            });
        }
        let computed = self.compute_canonical_digest();
        if &computed != expected_digest {
            return Err(ReceiptVerificationError::DigestMismatch {
                expected: *expected_digest,
                actual: computed,
            });
        }

        // Structural consistency invariants
        match self.outcome {
            ReceiptOutcome::Ok => {
                if self.output_root.is_none() {
                    return Err(ReceiptVerificationError::InconsistentOutcome {
                        reason: "outputRoot must be present when outcome is ok".to_string(),
                    });
                }
                if self.operator_trace_digest.is_none() {
                    return Err(ReceiptVerificationError::InconsistentOutcome {
                        reason: "operatorTraceDigest must be present when outcome is ok"
                            .to_string(),
                    });
                }
                if self.error_id.is_some() {
                    return Err(ReceiptVerificationError::InconsistentOutcome {
                        reason: "errorId must be null when outcome is ok".to_string(),
                    });
                }
                if self.cancel_reason.is_some() {
                    return Err(ReceiptVerificationError::InconsistentOutcome {
                        reason: "cancelReason must be null when outcome is ok".to_string(),
                    });
                }
            }
            ReceiptOutcome::Error => {
                if self.error_id.is_none() {
                    return Err(ReceiptVerificationError::InconsistentOutcome {
                        reason: "errorId must be present when outcome is error".to_string(),
                    });
                }
                if self.output_root.is_some() {
                    return Err(ReceiptVerificationError::InconsistentOutcome {
                        reason: "outputRoot must be null when outcome is error".to_string(),
                    });
                }
                if self.operator_trace_digest.is_some() {
                    return Err(ReceiptVerificationError::InconsistentOutcome {
                        reason: "operatorTraceDigest must be null when outcome is error"
                            .to_string(),
                    });
                }
            }
            ReceiptOutcome::Cancelled => {
                if self.cancel_reason.is_none() {
                    return Err(ReceiptVerificationError::InconsistentOutcome {
                        reason: "cancelReason must be present when outcome is cancelled"
                            .to_string(),
                    });
                }
                if self.output_root.is_some() {
                    return Err(ReceiptVerificationError::InconsistentOutcome {
                        reason: "outputRoot must be null when outcome is cancelled".to_string(),
                    });
                }
                if self.operator_trace_digest.is_some() {
                    return Err(ReceiptVerificationError::InconsistentOutcome {
                        reason: "operatorTraceDigest must be null when outcome is cancelled"
                            .to_string(),
                    });
                }
            }
            ReceiptOutcome::BudgetExhausted => {
                if self.output_root.is_some() {
                    return Err(ReceiptVerificationError::InconsistentOutcome {
                        reason: "outputRoot must be null when outcome is budget_exhausted"
                            .to_string(),
                    });
                }
                if self.operator_trace_digest.is_some() {
                    return Err(ReceiptVerificationError::InconsistentOutcome {
                        reason: "operatorTraceDigest must be null when outcome is budget_exhausted"
                            .to_string(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Emits exact, compact JSON adhering to `schemas/model_execution_receipt.v1.json`.
    #[must_use]
    pub fn to_json_canonical(&self) -> String {
        let mut s = String::with_capacity(2048);
        s.push('{');

        // 1. schema
        s.push_str(r#""schema":"fss.model_execution_receipt.v1","#);

        // 2. jobId
        s.push_str(r#""jobId":""#);
        escape_json_into(&self.job_id, &mut s);
        s.push_str(r#"","#);

        // 3. inputRoots
        s.push_str(r#""inputRoots":["#);
        for (i, root) in self.input_roots.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push('"');
            s.push_str(&root.to_text());
            s.push('"');
        }
        s.push_str(r#"],"#);

        // 4. modelPackageRoot
        s.push_str(r#""modelPackageRoot":""#);
        s.push_str(&self.model_package_root.to_text());
        s.push_str(r#"","#);

        // 5. activationGeneration
        s.push_str(r#""activationGeneration":""#);
        s.push_str(&self.activation_generation.to_text());
        s.push_str(r#"","#);

        // 6. preprocessProgram
        s.push_str(r#""preprocessProgram":""#);
        s.push_str(&self.preprocess_program.to_text());
        s.push_str(r#"","#);

        // 7. postprocessProgram
        s.push_str(r#""postprocessProgram":""#);
        s.push_str(&self.postprocess_program.to_text());
        s.push_str(r#"","#);

        // 8. operatorRegistryGeneration
        s.push_str(r#""operatorRegistryGeneration":""#);
        s.push_str(&self.operator_registry_generation.to_text());
        s.push_str(r#"","#);

        // 9. executionPlanDigest
        s.push_str(r#""executionPlanDigest":""#);
        s.push_str(&self.execution_plan_digest.to_text());
        s.push_str(r#"","#);

        // 10. backend
        s.push_str(r#""backend":{"id":""#);
        escape_json_into(&self.backend.id, &mut s);
        s.push_str(r#"","implementation":""#);
        escape_json_into(&self.backend.implementation, &mut s);
        s.push_str(r#"","hardware":""#);
        escape_json_into(&self.backend.hardware, &mut s);
        s.push_str(r#"","featureSet":["#);
        for (i, feat) in self.backend.feature_set.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push('"');
            escape_json_into(feat, &mut s);
            s.push('"');
        }
        s.push_str(r#"]},"#);

        // 11. numericPolicyDigest
        s.push_str(r#""numericPolicyDigest":""#);
        s.push_str(&self.numeric_policy_digest.to_text());
        s.push_str(r#"","#);

        // 12. budget
        let _ = write!(
            s,
            r#""budget":{{"inputBytes":{},"outputBytes":{},"peakBytes":{},"workUnits":{},"wallNs":{}}},"#,
            self.budget.input_bytes,
            self.budget.output_bytes,
            self.budget.peak_bytes,
            self.budget.work_units,
            self.budget.wall_ns,
        );

        // 13. usage
        let _ = write!(
            s,
            r#""usage":{{"inputBytes":{},"outputBytes":{},"peakBytes":{},"workUnits":{},"wallNs":{}}},"#,
            self.usage.input_bytes,
            self.usage.output_bytes,
            self.usage.peak_bytes,
            self.usage.work_units,
            self.usage.wall_ns,
        );

        // 14. outcome
        s.push_str(r#""outcome":""#);
        s.push_str(self.outcome.as_str());
        s.push_str(r#"","#);

        // 15. cancelReason
        match &self.cancel_reason {
            Some(reason) => {
                s.push_str(r#""cancelReason":""#);
                escape_json_into(reason, &mut s);
                s.push_str(r#"","#);
            }
            None => s.push_str(r#""cancelReason":null,"#),
        }

        // 16. errorId
        match &self.error_id {
            Some(err) => {
                s.push_str(r#""errorId":""#);
                escape_json_into(err, &mut s);
                s.push_str(r#"","#);
            }
            None => s.push_str(r#""errorId":null,"#),
        }

        // 17. outputRoot
        match &self.output_root {
            Some(root) => {
                s.push_str(r#""outputRoot":""#);
                s.push_str(&root.to_text());
                s.push_str(r#"","#);
            }
            None => s.push_str(r#""outputRoot":null,"#),
        }

        // 18. operatorTraceDigest
        match &self.operator_trace_digest {
            Some(trace) => {
                s.push_str(r#""operatorTraceDigest":""#);
                s.push_str(&trace.to_text());
                s.push_str(r#"","#);
            }
            None => s.push_str(r#""operatorTraceDigest":null,"#),
        }

        // 19. decisionPathDigest
        s.push_str(r#""decisionPathDigest":""#);
        s.push_str(&self.decision_path_digest.to_text());
        s.push_str(r#"","#);

        // 20. shadowComparison (null)
        s.push_str(r#""shadowComparison":null"#);

        s.push('}');
        s
    }
}

/// Helper writing escaped JSON string characters directly into destination string.
fn escape_json_into(input: &str, out: &mut String) {
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

/// Computes execution plan digest over domain-separated encoding of
/// (compute_model_ir_digest(graph), topological node-id order, bound input port names).
pub fn compute_execution_plan_digest(
    graph: &ModelIrGraph,
    bound_input_names: &[&str],
) -> Result<ContentDigest, ReceiptVerificationError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.canonical.v1");
    encoder.text("fss.model_execution_receipt.v1/execution_plan");
    let ir_digest = compute_model_ir_digest(graph)?;
    encoder.digest(ir_digest);

    // Topological node IDs
    let nodes = graph.topological_sort()?;
    encoder.u64(nodes.len() as u64);
    for node in nodes {
        encoder.text(node.id());
    }

    // Bound input port names in order
    encoder.u64(bound_input_names.len() as u64);
    for name in bound_input_names {
        encoder.text(name);
    }

    Ok(ContentDigest::sha256(&encoder.finish()))
}

/// Computes the canonical numeric policy descriptor digest.
#[must_use]
pub fn compute_numeric_policy_digest() -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.canonical.v1");
    encoder.text("fss.model_execution_receipt.v1/numeric_policy");
    encoder.text("F32");
    encoder.text("fixed_accumulation_order");
    encoder.text("deterministic_exp_f32_v1");
    encoder.bool(false); // no FMA
    encoder.bool(true); // virtual wall time only
    ContentDigest::sha256(&encoder.finish())
}

/// Computes the decision path digest from topological dispatch records.
pub fn compute_decision_path_digest(
    graph: &ModelIrGraph,
) -> Result<ContentDigest, ReceiptVerificationError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.canonical.v1");
    encoder.text("fss.model_execution_receipt.v1/decision_path");

    if let Ok(nodes) = graph.topological_sort() {
        encoder.u64(nodes.len() as u64);
        for node in nodes {
            encoder.text(node.id());
            encoder.text(node.op().stable_id());
            // Kernel variant
            encoder.text("scalar_cpu_f32");
            // Attributes in canonical sorted order
            encoder.u64(node.attributes().len() as u64);
            for (k, v) in node.attributes().iter() {
                encoder.text(k);
                encoder.text(&v.to_string());
            }
        }
    } else {
        encoder.u64(0);
    }

    Ok(ContentDigest::sha256(&encoder.finish()))
}

/// Computes the preprocess program descriptor digest.
#[must_use]
pub fn compute_preprocess_program_digest(program: Option<&PreprocessProgram>) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.canonical.v1");
    encoder.text("fss.model_execution_receipt.v1/preprocess_program");
    match program {
        Some(prog) => {
            encoder.tag(1);
            encoder.u32(prog.target_height as u32);
            encoder.u32(prog.target_width as u32);
            encoder.text(match prog.channel_transform {
                ChannelTransform::Rgb => "rgb",
                ChannelTransform::LumaOnly => "luma_only",
            });
            encoder.bool(prog.scale_to_unit);
        }
        None => {
            encoder.tag(0);
            encoder.text("identity");
        }
    }
    ContentDigest::sha256(&encoder.finish())
}

/// Computes the postprocess program descriptor digest.
#[must_use]
pub fn compute_postprocess_program_digest() -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.canonical.v1");
    encoder.text("fss.model_execution_receipt.v1/postprocess_program");
    encoder.text("identity");
    ContentDigest::sha256(&encoder.finish())
}

/// Computes the operator trace hash chain over per-node outputs.
pub fn compute_operator_trace_chain(
    graph: &ModelIrGraph,
    outcome: &ExecOutcome,
) -> Result<ContentDigest, ReceiptVerificationError> {
    let nodes = graph.topological_sort()?;
    let seed = b"fss.model_execution_receipt.v1/operator_trace";
    let mut current = ContentDigest::sha256(seed);

    for node in nodes {
        let mut encoder = CanonicalEncoder::new();
        encoder.digest(current);
        encoder.text(node.id());
        encoder.text(node.op().stable_id());

        // Bind first output tensor content digest if present in outcome
        if let Some(first_out) = node.outputs().first() {
            if let Some(tensor) = outcome.get_output(first_out) {
                if let Ok(t_digest) = tensor.content_digest() {
                    encoder.digest(t_digest);
                }
            }
        }
        current = ContentDigest::sha256(&encoder.finish());
    }

    Ok(current)
}

/// Computes output root digest from final graph outputs.
pub fn compute_output_root(
    graph: &ModelIrGraph,
    outcome: &ExecOutcome,
) -> Result<ContentDigest, ReceiptVerificationError> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.canonical.v1");
    encoder.text("fss.model_execution_receipt.v1/output_root");
    encoder.u64(graph.outputs().len() as u64);
    for out_port in graph.outputs() {
        encoder.text(out_port.name());
        let tensor = outcome.get_output(out_port.name()).ok_or_else(|| {
            ReceiptVerificationError::InconsistentOutcome {
                reason: format!("missing output tensor '{}'", out_port.name()),
            }
        })?;
        let d =
            tensor
                .content_digest()
                .map_err(|e| ReceiptVerificationError::InconsistentOutcome {
                    reason: format!("failed to compute output tensor digest: {e}"),
                })?;
        encoder.digest(d);
    }
    Ok(ContentDigest::sha256(&encoder.finish()))
}

/// Executes a model graph and emits an authoritative, verified [`ModelInvocationReceipt`].
pub fn execute_and_record_receipt(
    graph: &ModelIrGraph,
    inputs: &[(&str, Tensor)],
    budget: ExecBudget,
    cx: &ScalarExecCx,
    job_id: &str,
    preprocess_program: Option<&PreprocessProgram>,
    model_package_root: Option<ContentDigest>,
    virtual_clock: Option<&VirtualClock>,
) -> (Result<ExecOutcome, ExecError>, ModelInvocationReceipt) {
    // 1. Operator table freeze verification
    let op_registry_gen = match verify_operator_table_frozen() {
        Ok(()) => match ContentDigest::parse(OPERATOR_TABLE_FREEZE_DIGEST) {
            Ok(d) => ReceiptDigest::Content(d),
            Err(_) => {
                ReceiptDigest::not_applicable("operatorRegistryGeneration", "invalid_freeze_digest")
            }
        },
        Err(_) => {
            ReceiptDigest::not_applicable("operatorRegistryGeneration", "operator_table_unfrozen")
        }
    };

    // 2. Sentinels
    let mut sentinels = vec![("activationGeneration", "unactivated_reference_run")];
    let package_root_digest = match model_package_root {
        Some(d) => ReceiptDigest::Content(d),
        None => {
            sentinels.push(("modelPackageRoot", "inline_test_graph"));
            ReceiptDigest::not_applicable("modelPackageRoot", "inline_test_graph")
        }
    };
    let activation_gen =
        ReceiptDigest::not_applicable("activationGeneration", "unactivated_reference_run");

    // 3. Input roots
    let mut input_roots = Vec::with_capacity(inputs.len());
    let mut bound_names = Vec::with_capacity(inputs.len());
    let mut total_in_bytes: usize = 0;
    for (name, tensor) in inputs {
        bound_names.push(*name);
        match tensor.content_digest() {
            Ok(d) => input_roots.push(ReceiptDigest::Content(d)),
            Err(_) => input_roots.push(ReceiptDigest::not_applicable(
                "inputRoots",
                "tensor_digest_failure",
            )),
        }
        if let Ok(b) = tensor.shape().size_bytes(tensor.dtype()) {
            total_in_bytes = total_in_bytes.saturating_add(b);
        }
    }

    // 4. Common descriptors
    let execution_plan = match compute_execution_plan_digest(graph, &bound_names) {
        Ok(d) => ReceiptDigest::Content(d),
        Err(_) => ReceiptDigest::not_applicable("executionPlanDigest", "plan_digest_error"),
    };
    let numeric_policy = ReceiptDigest::Content(compute_numeric_policy_digest());
    let decision_path = match compute_decision_path_digest(graph) {
        Ok(d) => ReceiptDigest::Content(d),
        Err(_) => ReceiptDigest::not_applicable("decisionPathDigest", "decision_path_error"),
    };
    let preprocess_digest =
        ReceiptDigest::Content(compute_preprocess_program_digest(preprocess_program));
    let postprocess_digest = ReceiptDigest::Content(compute_postprocess_program_digest());

    let backend = BackendDescriptor::scalar_reference(&sentinels);

    // 5. Inferred output byte bounds for budget
    let mut inferred_out_bytes: usize = 0;
    for out_port in graph.outputs() {
        if let Ok(b) = out_port.shape().size_bytes(out_port.dtype()) {
            inferred_out_bytes = inferred_out_bytes.saturating_add(b);
        }
    }

    let receipt_budget = ReceiptBudget::new(
        total_in_bytes,
        inferred_out_bytes,
        budget.max_bytes,
        budget.max_macs,
        0,
    );

    // 6. Execute graph
    let run_res = ScalarExecutor::run(graph, inputs, budget, cx);

    let (outcome, cancel_reason, error_id, output_root, operator_trace_digest, usage) =
        match &run_res {
            Ok(outcome) => {
                let out_root = match compute_output_root(graph, outcome) {
                    Ok(d) => Some(ReceiptDigest::Content(d)),
                    Err(_) => None,
                };
                let trace = match compute_operator_trace_chain(graph, outcome) {
                    Ok(d) => Some(ReceiptDigest::Content(d)),
                    Err(_) => None,
                };
                let wall_ns = virtual_clock
                    .map(|c| c.now().as_nanos().min(u64::MAX as u128) as u64)
                    .unwrap_or(0);
                let rec_usage = ReceiptUsage::new(
                    total_in_bytes,
                    inferred_out_bytes,
                    outcome.allocated_bytes(),
                    outcome.executed_macs(),
                    wall_ns,
                );
                (ReceiptOutcome::Ok, None, None, out_root, trace, rec_usage)
            }
            Err(ExecError::CancellationRequested { stage }) => (
                ReceiptOutcome::Cancelled,
                Some((*stage).to_string()),
                None,
                None,
                None,
                ReceiptUsage::new(total_in_bytes, 0, 0, 0, 0),
            ),
            Err(ExecError::BudgetExceeded { macs, bytes, .. }) => (
                ReceiptOutcome::BudgetExhausted,
                None,
                None,
                None,
                None,
                ReceiptUsage::new(total_in_bytes, 0, *bytes, *macs, 0),
            ),
            Err(ExecError::UnsupportedOperator { .. }) => (
                ReceiptOutcome::Error,
                None,
                Some("ERR-EXEC-UNSUPPORTED-OPERATOR-001".to_string()),
                None,
                None,
                ReceiptUsage::new(total_in_bytes, 0, 0, 0, 0),
            ),
            Err(ExecError::UnsupportedDType { .. }) => (
                ReceiptOutcome::Error,
                None,
                Some("ERR-EXEC-UNSUPPORTED-DTYPE-001".to_string()),
                None,
                None,
                ReceiptUsage::new(total_in_bytes, 0, 0, 0, 0),
            ),
            Err(ExecError::ShapeMismatch { .. }) => (
                ReceiptOutcome::Error,
                None,
                Some("ERR-EXEC-SHAPE-MISMATCH-001".to_string()),
                None,
                None,
                ReceiptUsage::new(total_in_bytes, 0, 0, 0, 0),
            ),
            Err(ExecError::MissingInputPort { .. }) => (
                ReceiptOutcome::Error,
                None,
                Some("ERR-EXEC-MISSING-PORT-001".to_string()),
                None,
                None,
                ReceiptUsage::new(total_in_bytes, 0, 0, 0, 0),
            ),
            Err(ExecError::GenerationMismatch { .. }) => (
                ReceiptOutcome::Error,
                None,
                Some("ERR-EXEC-GENERATION-MISMATCH-001".to_string()),
                None,
                None,
                ReceiptUsage::new(total_in_bytes, 0, 0, 0, 0),
            ),
            Err(ExecError::UnsupportedVersion { .. }) => (
                ReceiptOutcome::Error,
                None,
                Some("ERR-EXEC-UNSUPPORTED-VERSION-001".to_string()),
                None,
                None,
                ReceiptUsage::new(total_in_bytes, 0, 0, 0, 0),
            ),
            Err(ExecError::ArithmeticOverflow { .. }) => (
                ReceiptOutcome::Error,
                None,
                Some("ERR-EXEC-OVERFLOW-001".to_string()),
                None,
                None,
                ReceiptUsage::new(total_in_bytes, 0, 0, 0, 0),
            ),
            Err(ExecError::Ir(_)) => (
                ReceiptOutcome::Error,
                None,
                Some("ERR-EXEC-IR-VALIDATION-001".to_string()),
                None,
                None,
                ReceiptUsage::new(total_in_bytes, 0, 0, 0, 0),
            ),
            Err(ExecError::Tensor(_)) => (
                ReceiptOutcome::Error,
                None,
                Some("ERR-EXEC-TENSOR-STORAGE-001".to_string()),
                None,
                None,
                ReceiptUsage::new(total_in_bytes, 0, 0, 0, 0),
            ),
        };

    let receipt = ModelInvocationReceipt {
        schema: "fss.model_execution_receipt.v1".to_string(),
        job_id: job_id.to_string(),
        input_roots,
        model_package_root: package_root_digest,
        activation_generation: activation_gen,
        preprocess_program: preprocess_digest,
        postprocess_program: postprocess_digest,
        operator_registry_generation: op_registry_gen,
        execution_plan_digest: execution_plan,
        backend,
        numeric_policy_digest: numeric_policy,
        budget: receipt_budget,
        usage,
        outcome,
        cancel_reason,
        error_id,
        output_root,
        operator_trace_digest,
        decision_path_digest: decision_path,
        generation: graph.generation(),
    };

    (run_res, receipt)
}
