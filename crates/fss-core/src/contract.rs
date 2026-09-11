//! Shared semantic states and stable contract errors.

use core::fmt;

use crate::canonical::{CanonicalDecode, CanonicalDecoder};
use crate::{CanonicalEncode, CanonicalEncoder, ContentDigest};

/// Which semantic plane owns a record.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Plane {
    /// Immutable observations, identities, receipts, and authoritative policy state.
    Authority,
    /// Derived tracks, hypotheses, rankings, and model outputs.
    Cognition,
    /// Alerts, camera control, retention changes, exports, and other side effects.
    Effect,
}

impl Plane {
    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authority => "authority",
            Self::Cognition => "cognition",
            Self::Effect => "effect",
        }
    }
}

impl CanonicalEncode for Plane {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

/// Evidence strength. Higher classes may depend on lower ones but never replace them.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EvidenceClass {
    /// A claim without retained source evidence.
    Assertion,
    /// A model output tied to exact inputs and model identity.
    Derived,
    /// An observation tied to retained source bytes.
    Observed,
    /// Independent corroboration from multiple failure domains.
    Corroborated,
    /// A deterministically or cryptographically verified fact.
    Verified,
}

/// The epistemic state of a proposition.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum KnowledgeState {
    /// Established within an exact validity scope.
    Known,
    /// Estimated from derived evidence.
    Estimated,
    /// No sufficient evidence is available.
    Unknown,
    /// Material evidence conflicts.
    Conflicted,
    /// The basis is older than the permitted freshness limit.
    Stale,
    /// The declared domain was not observable.
    NotObservable,
    /// Policy intentionally withheld the value.
    Redacted,
    /// An external effect or observation has unresolved outcome.
    Indeterminate,
    /// The proposition does not apply to the current domain.
    NotApplicable,
}

impl KnowledgeState {
    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Known => "known",
            Self::Estimated => "estimated",
            Self::Unknown => "unknown",
            Self::Conflicted => "conflicted",
            Self::Stale => "stale",
            Self::NotObservable => "not_observable",
            Self::Redacted => "redacted",
            Self::Indeterminate => "indeterminate",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// How a proposition entered the knowledge system.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProvenanceClass {
    /// Directly observed from a retained source capsule.
    Observed,
    /// Derived from named evidence and deterministic policy.
    Derived,
    /// Predicted by a model or hypothetical branch.
    Predicted,
    /// Retrieved from advisory memory.
    Remembered,
    /// Asserted by an authorized operator.
    OperatorAsserted,
    /// Reported by a vendor device or service.
    VendorClaimed,
    /// Established by immutable policy.
    Policy,
}

/// Disposition of a hypothesis within an investigation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum HypothesisDisposition {
    /// The hypothesis remains physically possible.
    Live,
    /// Current evidence materially supports it.
    Supported,
    /// Current evidence reduces but does not eliminate it.
    Disfavored,
    /// Evidence excludes it within the declared scope.
    Refuted,
    /// The investigation reached a terminal answer.
    Resolved,
    /// A newer hypothesis revision replaced it.
    Superseded,
}

/// Completeness of a bounded response or query.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Completeness {
    /// Complete for the declared authorized domain.
    Complete,
    /// Complete only within an explicit budget or top-k boundary.
    Bounded,
    /// Some required domain remains uncovered.
    Partial,
    /// Completeness could not be determined.
    Unknown,
    /// The domain was not observable.
    NotObservable,
    /// Authorization removed part or all of the domain.
    Unauthorized,
    /// The result is older than its permitted freshness interval.
    Stale,
}

/// Four-valued runtime completion plus explicit partial and indeterminate states.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RuntimeOutcome {
    /// Work completed successfully.
    Ok,
    /// Work failed with a stable expected error.
    Error,
    /// Work was cancelled and drained.
    Cancelled,
    /// Work terminated because an internal invariant failed.
    Panicked,
    /// A bounded response is useful but incomplete.
    Partial,
    /// An external outcome cannot yet be established.
    Indeterminate,
    /// Policy or capability denied the operation.
    Refused,
}

/// Stable recovery guidance attached to errors and partial outcomes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RecoveryClass {
    /// Retrying unchanged can duplicate or repeat a forbidden operation.
    NeverUnchanged,
    /// A read may be repeated unchanged.
    SafeReadRetry,
    /// Refresh the anchor and repeat.
    RefreshAndRetry,
    /// Recompile against a newer basis.
    RebaseRequired,
    /// Delay under the supplied backoff contract.
    Backoff,
    /// Reconcile an external effect before retrying.
    ReconciliationRequired,
    /// A human or deployment operator must intervene.
    OperatorActionRequired,
    /// Resume from the supplied exact continuation.
    ResumeFromContinuation,
}

/// Individual dimensions within a multi-dimensional resource budget vector.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum BudgetDimension {
    /// Wall-clock latency budget in milliseconds.
    LatencyMs,
    /// Output token budget.
    Tokens,
    /// Output and transfer byte budget.
    Bytes,
    /// Model invocation budget.
    ModelCalls,
    /// CPU budget in milliseconds.
    CpuMillis,
    /// Accelerator budget in milliseconds.
    AcceleratorMillis,
    /// Energy budget in millijoules.
    EnergyMillijoules,
    /// Network budget in bytes.
    NetworkBytes,
    /// Storage-operation budget.
    StorageOperations,
    /// Privacy-exposure budget in an application-defined monotone scale.
    PrivacyExposure,
    /// Operator-attention budget in seconds.
    OperatorAttentionSeconds,
}

impl BudgetDimension {
    /// Returns the canonical machine-readable identifier for this dimension.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LatencyMs => "latency_ms",
            Self::Tokens => "tokens",
            Self::Bytes => "bytes",
            Self::ModelCalls => "model_calls",
            Self::CpuMillis => "cpu_millis",
            Self::AcceleratorMillis => "accelerator_millis",
            Self::EnergyMillijoules => "energy_millijoules",
            Self::NetworkBytes => "network_bytes",
            Self::StorageOperations => "storage_operations",
            Self::PrivacyExposure => "privacy_exposure",
            Self::OperatorAttentionSeconds => "operator_attention_seconds",
        }
    }

    /// Returns the standard measurement unit for this dimension.
    #[must_use]
    pub const fn unit(self) -> &'static str {
        match self {
            Self::LatencyMs | Self::CpuMillis | Self::AcceleratorMillis => "milliseconds",
            Self::Tokens => "tokens",
            Self::Bytes | Self::NetworkBytes => "bytes",
            Self::ModelCalls => "calls",
            Self::EnergyMillijoules => "millijoules",
            Self::StorageOperations => "operations",
            Self::PrivacyExposure => "monotone_scale",
            Self::OperatorAttentionSeconds => "seconds",
        }
    }

    /// Returns true if this dimension is continuous (floating-point).
    #[must_use]
    pub const fn is_continuous(self) -> bool {
        matches!(self, Self::PrivacyExposure | Self::OperatorAttentionSeconds)
    }

    /// Parses a dimension name from a string slice.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "latency_ms" | "latencyMs" => Some(Self::LatencyMs),
            "tokens" => Some(Self::Tokens),
            "bytes" => Some(Self::Bytes),
            "model_calls" | "modelCalls" => Some(Self::ModelCalls),
            "cpu_millis" | "cpuMillis" => Some(Self::CpuMillis),
            "accelerator_millis" | "acceleratorMillis" => Some(Self::AcceleratorMillis),
            "energy_millijoules" | "energyMillijoules" | "energyMilliJoules" => {
                Some(Self::EnergyMillijoules)
            }
            "network_bytes" | "networkBytes" => Some(Self::NetworkBytes),
            "storage_operations" | "storageOperations" => Some(Self::StorageOperations),
            "privacy_exposure" | "privacyExposure" => Some(Self::PrivacyExposure),
            "operator_attention_seconds" | "operatorAttentionSeconds" => {
                Some(Self::OperatorAttentionSeconds)
            }
            _ => None,
        }
    }
}

impl fmt::Display for BudgetDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Typed failures arising from budget validation, arithmetic, or decode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BudgetError {
    /// Negative budget quantity encountered.
    NegativeQuantity {
        /// The affected budget dimension.
        dimension: BudgetDimension,
        /// Exact IEEE-754 bit representation of the negative value.
        value_bits: u64,
    },
    /// NaN budget quantity encountered.
    NaNQuantity {
        /// The affected budget dimension.
        dimension: BudgetDimension,
    },
    /// Infinite budget quantity encountered.
    InfiniteQuantity {
        /// The affected budget dimension.
        dimension: BudgetDimension,
        /// Whether the infinity was negative (-inf).
        is_negative: bool,
    },
    /// Arithmetic overflow during budget calculation.
    Overflow {
        /// The affected budget dimension.
        dimension: BudgetDimension,
        /// The operation that caused overflow (e.g. "add", "scale").
        operation: &'static str,
    },
    /// Insufficient budget remaining (underflow / over-consumption).
    Underflow {
        /// The affected budget dimension.
        dimension: BudgetDimension,
        /// Available budget bits (or integer value as u64).
        available_bits: u64,
        /// Requested budget bits (or integer value as u64).
        requested_bits: u64,
    },
    /// Incompatible unit for the specified dimension.
    IncompatibleUnit {
        /// The affected budget dimension.
        dimension: BudgetDimension,
        /// Expected unit.
        expected_unit: &'static str,
        /// Found unit description.
        found_unit: String,
    },
    /// Authority violation: cognition or model output attempted to mint or enlarge budget authority.
    AuthorityEnlargementForbidden {
        /// The affected budget dimension.
        dimension: BudgetDimension,
    },
    /// Canonical binary encoding or decoding failed.
    InvalidEncoding {
        /// Rationale for failure.
        reason: &'static str,
    },
    /// Historical persisted record quarantined due to invalid budget values.
    QuarantinedRecord {
        /// Identifier of the quarantined record.
        record_id: String,
        /// Detail of validation failure.
        reason: String,
    },
}

impl BudgetError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NegativeQuantity { .. } => "negative_budget_quantity",
            Self::NaNQuantity { .. } => "nan_budget_quantity",
            Self::InfiniteQuantity { .. } => "infinite_budget_quantity",
            Self::Overflow { .. } => "budget_overflow",
            Self::Underflow { .. } => "insufficient_budget",
            Self::IncompatibleUnit { .. } => "incompatible_budget_unit",
            Self::AuthorityEnlargementForbidden { .. } => "authority_enlargement_forbidden",
            Self::InvalidEncoding { .. } => "invalid_budget_encoding",
            Self::QuarantinedRecord { .. } => "quarantined_budget_record",
        }
    }

    /// Returns the affected budget dimension, if known.
    #[must_use]
    pub const fn dimension(&self) -> Option<BudgetDimension> {
        match self {
            Self::NegativeQuantity { dimension, .. }
            | Self::NaNQuantity { dimension }
            | Self::InfiniteQuantity { dimension, .. }
            | Self::Overflow { dimension, .. }
            | Self::Underflow { dimension, .. }
            | Self::IncompatibleUnit { dimension, .. }
            | Self::AuthorityEnlargementForbidden { dimension } => Some(*dimension),
            Self::InvalidEncoding { .. } | Self::QuarantinedRecord { .. } => None,
        }
    }

    /// Helper to construct a negative quantity error from an f64 value.
    #[must_use]
    pub fn negative_quantity(dimension: BudgetDimension, value: f64) -> Self {
        Self::NegativeQuantity {
            dimension,
            value_bits: value.to_bits(),
        }
    }

    /// Returns the negative value as an f64 if this is a `NegativeQuantity` error.
    #[must_use]
    pub fn negative_value(&self) -> Option<f64> {
        match self {
            Self::NegativeQuantity { value_bits, .. } => Some(f64::from_bits(*value_bits)),
            _ => None,
        }
    }
}

impl fmt::Display for BudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NegativeQuantity {
                dimension,
                value_bits,
            } => {
                let val = f64::from_bits(*value_bits);
                write!(
                    f,
                    "{}: dimension {} is negative ({})",
                    self.code(),
                    dimension,
                    val
                )
            }
            Self::NaNQuantity { dimension } => {
                write!(f, "{}: dimension {} is NaN", self.code(), dimension)
            }
            Self::InfiniteQuantity {
                dimension,
                is_negative,
            } => {
                let sign = if *is_negative { "-" } else { "+" };
                write!(
                    f,
                    "{}: dimension {} is {}infinity",
                    self.code(),
                    dimension,
                    sign
                )
            }
            Self::Overflow {
                dimension,
                operation,
            } => {
                write!(
                    f,
                    "{}: dimension {} overflowed during {}",
                    self.code(),
                    dimension,
                    operation
                )
            }
            Self::Underflow { dimension, .. } => {
                write!(
                    f,
                    "{}: dimension {} has insufficient budget",
                    self.code(),
                    dimension
                )
            }
            Self::IncompatibleUnit {
                dimension,
                expected_unit,
                found_unit,
            } => {
                write!(
                    f,
                    "{}: dimension {} expected unit {} but found {}",
                    self.code(),
                    dimension,
                    expected_unit,
                    found_unit
                )
            }
            Self::AuthorityEnlargementForbidden { dimension } => {
                write!(
                    f,
                    "{}: dimension {} attempted unauthorized budget expansion",
                    self.code(),
                    dimension
                )
            }
            Self::InvalidEncoding { reason } => {
                write!(f, "{}: {}", self.code(), reason)
            }
            Self::QuarantinedRecord { record_id, reason } => {
                write!(
                    f,
                    "{}: record {} quarantined: {}",
                    self.code(),
                    record_id,
                    reason
                )
            }
        }
    }
}

impl std::error::Error for BudgetError {}

/// A validated, finite, non-negative quantity for continuous budget dimensions.
///
/// Ensures values are finite (no NaN, +inf, -inf), >= 0.0, and that negative zero (-0.0)
/// is normalized to +0.0.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BudgetQuantity {
    raw: f64,
}

impl BudgetQuantity {
    /// Zero quantity.
    pub const ZERO: Self = Self { raw: 0.0 };

    /// Creates and validates a new budget quantity for a given dimension.
    pub fn new(value: f64, dimension: BudgetDimension) -> Result<Self, BudgetError> {
        if value.is_nan() {
            return Err(BudgetError::NaNQuantity { dimension });
        }
        if value.is_infinite() {
            return Err(BudgetError::InfiniteQuantity {
                dimension,
                is_negative: value.is_sign_negative(),
            });
        }
        if value < 0.0 {
            return Err(BudgetError::NegativeQuantity {
                dimension,
                value_bits: value.to_bits(),
            });
        }
        // Normalize negative zero (-0.0) to +0.0
        let normalized = if value == 0.0 { 0.0 } else { value };
        Ok(Self { raw: normalized })
    }

    /// Creates and validates a quantity with continuous dimension defaulting to PrivacyExposure.
    pub fn from_f64(value: f64) -> Result<Self, BudgetError> {
        Self::new(value, BudgetDimension::PrivacyExposure)
    }

    /// Returns the underlying f64 value (guaranteed finite and >= 0.0).
    #[must_use]
    pub const fn get(self) -> f64 {
        self.raw
    }

    /// Returns the underlying f64 value (guaranteed finite and >= 0.0).
    #[must_use]
    pub const fn as_f64(self) -> f64 {
        self.raw
    }

    /// Canonical IEEE-754 bit representation (+0.0 produces bits 0).
    #[must_use]
    pub fn canonical_bits(self) -> u64 {
        if self.raw == 0.0 {
            0
        } else {
            self.raw.to_bits()
        }
    }

    /// Checked addition of two budget quantities.
    pub fn checked_add(self, other: Self, dimension: BudgetDimension) -> Result<Self, BudgetError> {
        let sum = self.raw + other.raw;
        if !sum.is_finite() {
            return Err(BudgetError::Overflow {
                dimension,
                operation: "add",
            });
        }
        Ok(Self { raw: sum })
    }

    /// Checked subtraction of two budget quantities.
    pub fn checked_sub(self, other: Self, dimension: BudgetDimension) -> Result<Self, BudgetError> {
        if self.raw < other.raw {
            return Err(BudgetError::Underflow {
                dimension,
                available_bits: self.canonical_bits(),
                requested_bits: other.canonical_bits(),
            });
        }
        let diff = self.raw - other.raw;
        let normalized = if diff <= 0.0 { 0.0 } else { diff };
        Ok(Self { raw: normalized })
    }
}

impl Eq for BudgetQuantity {}

impl PartialOrd for BudgetQuantity {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BudgetQuantity {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        if self.raw < other.raw {
            core::cmp::Ordering::Less
        } else if self.raw > other.raw {
            core::cmp::Ordering::Greater
        } else {
            core::cmp::Ordering::Equal
        }
    }
}

impl Default for BudgetQuantity {
    fn default() -> Self {
        Self::ZERO
    }
}

impl fmt::Display for BudgetQuantity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw)
    }
}

/// A multi-dimensional resource budget.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct BudgetVector {
    /// Wall-clock latency budget in milliseconds.
    pub latency_ms: u64,
    /// Output token budget.
    pub tokens: u64,
    /// Output and transfer byte budget.
    pub bytes: u64,
    /// Model invocation budget.
    pub model_calls: u32,
    /// CPU budget in milliseconds.
    pub cpu_millis: u64,
    /// Accelerator budget in milliseconds.
    pub accelerator_millis: u64,
    /// Energy budget in millijoules.
    pub energy_millijoules: u64,
    /// Network budget in bytes.
    pub network_bytes: u64,
    /// Storage-operation budget.
    pub storage_operations: u64,
    /// Privacy-exposure budget in an application-defined monotone scale.
    pub privacy_exposure: f64,
    /// Operator-attention budget in seconds.
    pub operator_attention_seconds: f64,
}

impl BudgetVector {
    /// Zero budget across all dimensions.
    pub const ZERO: Self = Self {
        latency_ms: 0,
        tokens: 0,
        bytes: 0,
        model_calls: 0,
        cpu_millis: 0,
        accelerator_millis: 0,
        energy_millijoules: 0,
        network_bytes: 0,
        storage_operations: 0,
        privacy_exposure: 0.0,
        operator_attention_seconds: 0.0,
    };

    /// Constructs and validates a budget vector from raw components.
    ///
    /// Rejects negative, NaN, or infinite floating-point quantities with stable typed errors.
    /// Normalizes -0.0 to +0.0.
    pub fn new(
        latency_ms: u64,
        tokens: u64,
        bytes: u64,
        model_calls: u32,
        cpu_millis: u64,
        accelerator_millis: u64,
        energy_millijoules: u64,
        network_bytes: u64,
        storage_operations: u64,
        privacy_exposure: f64,
        operator_attention_seconds: f64,
    ) -> Result<Self, BudgetError> {
        let privacy = BudgetQuantity::new(privacy_exposure, BudgetDimension::PrivacyExposure)?;
        let attention = BudgetQuantity::new(
            operator_attention_seconds,
            BudgetDimension::OperatorAttentionSeconds,
        )?;
        Ok(Self {
            latency_ms,
            tokens,
            bytes,
            model_calls,
            cpu_millis,
            accelerator_millis,
            energy_millijoules,
            network_bytes,
            storage_operations,
            privacy_exposure: privacy.get(),
            operator_attention_seconds: attention.get(),
        })
    }

    /// Constructs from validated BudgetQuantity values for continuous dimensions.
    #[must_use]
    pub fn from_quantities(
        latency_ms: u64,
        tokens: u64,
        bytes: u64,
        model_calls: u32,
        cpu_millis: u64,
        accelerator_millis: u64,
        energy_millijoules: u64,
        network_bytes: u64,
        storage_operations: u64,
        privacy_exposure: BudgetQuantity,
        operator_attention_seconds: BudgetQuantity,
    ) -> Self {
        Self {
            latency_ms,
            tokens,
            bytes,
            model_calls,
            cpu_millis,
            accelerator_millis,
            energy_millijoules,
            network_bytes,
            storage_operations,
            privacy_exposure: privacy_exposure.get(),
            operator_attention_seconds: operator_attention_seconds.get(),
        }
    }

    /// Returns a builder for constructing a validated budget vector.
    #[must_use]
    pub fn builder() -> BudgetVectorBuilder {
        BudgetVectorBuilder::new()
    }

    /// Validates every component of the budget vector.
    ///
    /// Rejects negative, NaN, and infinite floating quantities with stable typed errors.
    pub fn validate(&self) -> Result<(), BudgetError> {
        let _ = BudgetQuantity::new(self.privacy_exposure, BudgetDimension::PrivacyExposure)?;
        let _ = BudgetQuantity::new(
            self.operator_attention_seconds,
            BudgetDimension::OperatorAttentionSeconds,
        )?;
        Ok(())
    }

    /// Returns true when every component is finite and nonnegative.
    #[must_use]
    pub fn is_valid(self) -> bool {
        self.validate().is_ok()
    }

    /// Returns a normalized copy where negative zero (-0.0) is converted to +0.0.
    pub fn normalized(self) -> Result<Self, BudgetError> {
        self.validate()?;
        let privacy = if self.privacy_exposure == 0.0 {
            0.0
        } else {
            self.privacy_exposure
        };
        let attention = if self.operator_attention_seconds == 0.0 {
            0.0
        } else {
            self.operator_attention_seconds
        };
        Ok(Self {
            privacy_exposure: privacy,
            operator_attention_seconds: attention,
            ..self
        })
    }

    /// Encapsulates privacy exposure as a validated `BudgetQuantity`.
    pub fn privacy_quantity(&self) -> Result<BudgetQuantity, BudgetError> {
        BudgetQuantity::new(self.privacy_exposure, BudgetDimension::PrivacyExposure)
    }

    /// Encapsulates operator attention as a validated `BudgetQuantity`.
    pub fn operator_attention_quantity(&self) -> Result<BudgetQuantity, BudgetError> {
        BudgetQuantity::new(
            self.operator_attention_seconds,
            BudgetDimension::OperatorAttentionSeconds,
        )
    }

    /// Returns true when every component fits within another valid budget.
    #[must_use]
    pub fn fits_within(self, limit: Self) -> bool {
        self.is_valid()
            && limit.is_valid()
            && self.latency_ms <= limit.latency_ms
            && self.tokens <= limit.tokens
            && self.bytes <= limit.bytes
            && self.model_calls <= limit.model_calls
            && self.cpu_millis <= limit.cpu_millis
            && self.accelerator_millis <= limit.accelerator_millis
            && self.energy_millijoules <= limit.energy_millijoules
            && self.network_bytes <= limit.network_bytes
            && self.storage_operations <= limit.storage_operations
            && self.privacy_exposure <= limit.privacy_exposure
            && self.operator_attention_seconds <= limit.operator_attention_seconds
    }

    /// Checked version of fits_within that returns a typed error if either vector is invalid.
    pub fn checked_fits_within(&self, limit: &Self) -> Result<bool, BudgetError> {
        self.validate()?;
        limit.validate()?;
        Ok(self.fits_within(*limit))
    }

    /// Checked addition of two budget vectors.
    pub fn checked_add(&self, other: &Self) -> Result<Self, BudgetError> {
        self.validate()?;
        other.validate()?;

        let latency_ms =
            self.latency_ms
                .checked_add(other.latency_ms)
                .ok_or(BudgetError::Overflow {
                    dimension: BudgetDimension::LatencyMs,
                    operation: "add",
                })?;
        let tokens = self
            .tokens
            .checked_add(other.tokens)
            .ok_or(BudgetError::Overflow {
                dimension: BudgetDimension::Tokens,
                operation: "add",
            })?;
        let bytes = self
            .bytes
            .checked_add(other.bytes)
            .ok_or(BudgetError::Overflow {
                dimension: BudgetDimension::Bytes,
                operation: "add",
            })?;
        let model_calls =
            self.model_calls
                .checked_add(other.model_calls)
                .ok_or(BudgetError::Overflow {
                    dimension: BudgetDimension::ModelCalls,
                    operation: "add",
                })?;
        let cpu_millis =
            self.cpu_millis
                .checked_add(other.cpu_millis)
                .ok_or(BudgetError::Overflow {
                    dimension: BudgetDimension::CpuMillis,
                    operation: "add",
                })?;
        let accelerator_millis = self
            .accelerator_millis
            .checked_add(other.accelerator_millis)
            .ok_or(BudgetError::Overflow {
                dimension: BudgetDimension::AcceleratorMillis,
                operation: "add",
            })?;
        let energy_millijoules = self
            .energy_millijoules
            .checked_add(other.energy_millijoules)
            .ok_or(BudgetError::Overflow {
                dimension: BudgetDimension::EnergyMillijoules,
                operation: "add",
            })?;
        let network_bytes =
            self.network_bytes
                .checked_add(other.network_bytes)
                .ok_or(BudgetError::Overflow {
                    dimension: BudgetDimension::NetworkBytes,
                    operation: "add",
                })?;
        let storage_operations = self
            .storage_operations
            .checked_add(other.storage_operations)
            .ok_or(BudgetError::Overflow {
                dimension: BudgetDimension::StorageOperations,
                operation: "add",
            })?;

        let p1 = BudgetQuantity::new(self.privacy_exposure, BudgetDimension::PrivacyExposure)?;
        let p2 = BudgetQuantity::new(other.privacy_exposure, BudgetDimension::PrivacyExposure)?;
        let privacy = p1.checked_add(p2, BudgetDimension::PrivacyExposure)?;

        let a1 = BudgetQuantity::new(
            self.operator_attention_seconds,
            BudgetDimension::OperatorAttentionSeconds,
        )?;
        let a2 = BudgetQuantity::new(
            other.operator_attention_seconds,
            BudgetDimension::OperatorAttentionSeconds,
        )?;
        let attention = a1.checked_add(a2, BudgetDimension::OperatorAttentionSeconds)?;

        Ok(Self {
            latency_ms,
            tokens,
            bytes,
            model_calls,
            cpu_millis,
            accelerator_millis,
            energy_millijoules,
            network_bytes,
            storage_operations,
            privacy_exposure: privacy.get(),
            operator_attention_seconds: attention.get(),
        })
    }

    /// Checked subtraction of two budget vectors.
    pub fn checked_sub(&self, other: &Self) -> Result<Self, BudgetError> {
        self.validate()?;
        other.validate()?;

        let latency_ms = if self.latency_ms < other.latency_ms {
            return Err(BudgetError::Underflow {
                dimension: BudgetDimension::LatencyMs,
                available_bits: self.latency_ms,
                requested_bits: other.latency_ms,
            });
        } else {
            self.latency_ms - other.latency_ms
        };

        let tokens = if self.tokens < other.tokens {
            return Err(BudgetError::Underflow {
                dimension: BudgetDimension::Tokens,
                available_bits: self.tokens,
                requested_bits: other.tokens,
            });
        } else {
            self.tokens - other.tokens
        };

        let bytes = if self.bytes < other.bytes {
            return Err(BudgetError::Underflow {
                dimension: BudgetDimension::Bytes,
                available_bits: self.bytes,
                requested_bits: other.bytes,
            });
        } else {
            self.bytes - other.bytes
        };

        let model_calls = if self.model_calls < other.model_calls {
            return Err(BudgetError::Underflow {
                dimension: BudgetDimension::ModelCalls,
                available_bits: self.model_calls as u64,
                requested_bits: other.model_calls as u64,
            });
        } else {
            self.model_calls - other.model_calls
        };

        let cpu_millis = if self.cpu_millis < other.cpu_millis {
            return Err(BudgetError::Underflow {
                dimension: BudgetDimension::CpuMillis,
                available_bits: self.cpu_millis,
                requested_bits: other.cpu_millis,
            });
        } else {
            self.cpu_millis - other.cpu_millis
        };

        let accelerator_millis = if self.accelerator_millis < other.accelerator_millis {
            return Err(BudgetError::Underflow {
                dimension: BudgetDimension::AcceleratorMillis,
                available_bits: self.accelerator_millis,
                requested_bits: other.accelerator_millis,
            });
        } else {
            self.accelerator_millis - other.accelerator_millis
        };

        let energy_millijoules = if self.energy_millijoules < other.energy_millijoules {
            return Err(BudgetError::Underflow {
                dimension: BudgetDimension::EnergyMillijoules,
                available_bits: self.energy_millijoules,
                requested_bits: other.energy_millijoules,
            });
        } else {
            self.energy_millijoules - other.energy_millijoules
        };

        let network_bytes = if self.network_bytes < other.network_bytes {
            return Err(BudgetError::Underflow {
                dimension: BudgetDimension::NetworkBytes,
                available_bits: self.network_bytes,
                requested_bits: other.network_bytes,
            });
        } else {
            self.network_bytes - other.network_bytes
        };

        let storage_operations = if self.storage_operations < other.storage_operations {
            return Err(BudgetError::Underflow {
                dimension: BudgetDimension::StorageOperations,
                available_bits: self.storage_operations,
                requested_bits: other.storage_operations,
            });
        } else {
            self.storage_operations - other.storage_operations
        };

        let p1 = BudgetQuantity::new(self.privacy_exposure, BudgetDimension::PrivacyExposure)?;
        let p2 = BudgetQuantity::new(other.privacy_exposure, BudgetDimension::PrivacyExposure)?;
        let privacy = p1.checked_sub(p2, BudgetDimension::PrivacyExposure)?;

        let a1 = BudgetQuantity::new(
            self.operator_attention_seconds,
            BudgetDimension::OperatorAttentionSeconds,
        )?;
        let a2 = BudgetQuantity::new(
            other.operator_attention_seconds,
            BudgetDimension::OperatorAttentionSeconds,
        )?;
        let attention = a1.checked_sub(a2, BudgetDimension::OperatorAttentionSeconds)?;

        Ok(Self {
            latency_ms,
            tokens,
            bytes,
            model_calls,
            cpu_millis,
            accelerator_millis,
            energy_millijoules,
            network_bytes,
            storage_operations,
            privacy_exposure: privacy.get(),
            operator_attention_seconds: attention.get(),
        })
    }

    /// Consumes `cost` from `self`.
    ///
    /// Invariant: consumption may NEVER increase remaining authority.
    pub fn checked_consume(&self, cost: &Self) -> Result<Self, BudgetError> {
        self.validate()?;
        cost.validate()?;

        if !cost.fits_within(*self) {
            return self.checked_sub(cost);
        }
        let remaining = self.checked_sub(cost)?;
        if !remaining.fits_within(*self) {
            return Err(BudgetError::AuthorityEnlargementForbidden {
                dimension: BudgetDimension::LatencyMs,
            });
        }
        Ok(remaining)
    }

    /// Calculates remaining budget after consumption.
    pub fn remaining_budget(&self, consumed: &Self) -> Result<Self, BudgetError> {
        self.checked_consume(consumed)
    }

    /// Checked reservation of `amount` from `self` (available).
    ///
    /// Returns `(remaining_available, reserved)`.
    pub fn checked_reserve(&self, amount: &Self) -> Result<(Self, Self), BudgetError> {
        let remaining = self.checked_consume(amount)?;
        Ok((remaining, *amount))
    }

    /// Checked release of previously reserved budget back to available.
    ///
    /// Ensures `amount` fits within `reserved`, then deducts from reserved
    /// and adds back to available. Returns `(new_available, new_reserved)`.
    pub fn checked_release(
        &self,
        reserved: &Self,
        amount: &Self,
    ) -> Result<(Self, Self), BudgetError> {
        let new_reserved = reserved.checked_sub(amount)?;
        let new_available = self.checked_add(amount)?;
        Ok((new_available, new_reserved))
    }

    /// Zeroes out dimensions where `predicate` returns false.
    pub fn project_dimensions<F: Fn(BudgetDimension) -> bool>(
        &self,
        predicate: F,
    ) -> Result<Self, BudgetError> {
        self.validate()?;
        Ok(Self {
            latency_ms: if predicate(BudgetDimension::LatencyMs) {
                self.latency_ms
            } else {
                0
            },
            tokens: if predicate(BudgetDimension::Tokens) {
                self.tokens
            } else {
                0
            },
            bytes: if predicate(BudgetDimension::Bytes) {
                self.bytes
            } else {
                0
            },
            model_calls: if predicate(BudgetDimension::ModelCalls) {
                self.model_calls
            } else {
                0
            },
            cpu_millis: if predicate(BudgetDimension::CpuMillis) {
                self.cpu_millis
            } else {
                0
            },
            accelerator_millis: if predicate(BudgetDimension::AcceleratorMillis) {
                self.accelerator_millis
            } else {
                0
            },
            energy_millijoules: if predicate(BudgetDimension::EnergyMillijoules) {
                self.energy_millijoules
            } else {
                0
            },
            network_bytes: if predicate(BudgetDimension::NetworkBytes) {
                self.network_bytes
            } else {
                0
            },
            storage_operations: if predicate(BudgetDimension::StorageOperations) {
                self.storage_operations
            } else {
                0
            },
            privacy_exposure: if predicate(BudgetDimension::PrivacyExposure) {
                self.privacy_exposure
            } else {
                0.0
            },
            operator_attention_seconds: if predicate(BudgetDimension::OperatorAttentionSeconds) {
                self.operator_attention_seconds
            } else {
                0.0
            },
        })
    }

    /// Checks authority separation: ensures derived cognition results do not mint or enlarge budget.
    pub fn assert_authority_unmodified(&self, prior: &Self) -> Result<(), BudgetError> {
        self.validate()?;
        prior.validate()?;
        if !self.fits_within(*prior) {
            return Err(BudgetError::AuthorityEnlargementForbidden {
                dimension: BudgetDimension::LatencyMs,
            });
        }
        Ok(())
    }

    /// Encodes to canonical binary format (exactly 84 bytes).
    pub fn encode_to_canonical(&self, encoder: &mut CanonicalEncoder) {
        let norm = match self.normalized() {
            Ok(v) => v,
            Err(_) => *self,
        };
        encoder.u64(norm.latency_ms);
        encoder.u64(norm.tokens);
        encoder.u64(norm.bytes);
        encoder.u32(norm.model_calls);
        encoder.u64(norm.cpu_millis);
        encoder.u64(norm.accelerator_millis);
        encoder.u64(norm.energy_millijoules);
        encoder.u64(norm.network_bytes);
        encoder.u64(norm.storage_operations);
        encoder.u64(canonical_f64_bits(norm.privacy_exposure));
        encoder.u64(canonical_f64_bits(norm.operator_attention_seconds));
    }

    /// Decodes from canonical binary format (exactly 84 bytes), rejecting invalid quantities.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, BudgetError> {
        if bytes.len() != 84 {
            return Err(BudgetError::InvalidEncoding {
                reason: "canonical budget encoding must be exactly 84 bytes",
            });
        }
        let mut slice_8 = [0u8; 8];
        let mut slice_4 = [0u8; 4];

        slice_8.copy_from_slice(&bytes[0..8]);
        let latency_ms = u64::from_be_bytes(slice_8);

        slice_8.copy_from_slice(&bytes[8..16]);
        let tokens = u64::from_be_bytes(slice_8);

        slice_8.copy_from_slice(&bytes[16..24]);
        let bytes_count = u64::from_be_bytes(slice_8);

        slice_4.copy_from_slice(&bytes[24..28]);
        let model_calls = u32::from_be_bytes(slice_4);

        slice_8.copy_from_slice(&bytes[28..36]);
        let cpu_millis = u64::from_be_bytes(slice_8);

        slice_8.copy_from_slice(&bytes[36..44]);
        let accelerator_millis = u64::from_be_bytes(slice_8);

        slice_8.copy_from_slice(&bytes[44..52]);
        let energy_millijoules = u64::from_be_bytes(slice_8);

        slice_8.copy_from_slice(&bytes[52..60]);
        let network_bytes = u64::from_be_bytes(slice_8);

        slice_8.copy_from_slice(&bytes[60..68]);
        let storage_operations = u64::from_be_bytes(slice_8);

        slice_8.copy_from_slice(&bytes[68..76]);
        let privacy_bits = u64::from_be_bytes(slice_8);

        slice_8.copy_from_slice(&bytes[76..84]);
        let attention_bits = u64::from_be_bytes(slice_8);

        let privacy = f64::from_bits(privacy_bits);
        let attention = f64::from_bits(attention_bits);

        Self::new(
            latency_ms,
            tokens,
            bytes_count,
            model_calls,
            cpu_millis,
            accelerator_millis,
            energy_millijoules,
            network_bytes,
            storage_operations,
            privacy,
            attention,
        )
    }

    /// Quarantines invalid historical data rather than silently normalizing it.
    pub fn quarantine_historical(bytes: &[u8], record_id: &str) -> Result<Self, BudgetError> {
        Self::decode_canonical(bytes).map_err(|err| BudgetError::QuarantinedRecord {
            record_id: record_id.to_owned(),
            reason: format!("historical budget validation failed: {err}"),
        })
    }

    /// Canonical domain-separated digest.
    #[must_use]
    pub fn canonical_digest(&self, domain: &str) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.canonical.v1");
        encoder.text(domain);
        self.encode_to_canonical(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Decodes a BudgetVector from JSON bytes without external dependencies.
    pub fn decode_json_slice(bytes: &[u8]) -> Result<Self, BudgetError> {
        let text = core::str::from_utf8(bytes).map_err(|_| BudgetError::InvalidEncoding {
            reason: "JSON bytes must be valid UTF-8",
        })?;
        let trimmed = text.trim();
        if !trimmed.starts_with('{') || !trimmed.ends_with('}') {
            return Err(BudgetError::InvalidEncoding {
                reason: "JSON budget must be an object enclosed in braces",
            });
        }
        let inner = &trimmed[1..trimmed.len() - 1];

        let mut builder = Self::builder();

        for item in inner.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            let mut colon_parts = item.splitn(2, ':');
            let raw_key = colon_parts
                .next()
                .ok_or(BudgetError::InvalidEncoding {
                    reason: "missing key in JSON budget",
                })?
                .trim();
            let raw_val = colon_parts
                .next()
                .ok_or(BudgetError::InvalidEncoding {
                    reason: "missing value in JSON budget",
                })?
                .trim();

            let key = raw_key.trim_matches('"').trim();
            let dimension = BudgetDimension::parse(key).ok_or(BudgetError::InvalidEncoding {
                reason: "unknown budget dimension in JSON",
            })?;

            let val_unquoted = raw_val.trim_matches('"').trim();
            if val_unquoted == "NaN" || val_unquoted == "nan" {
                return Err(BudgetError::NaNQuantity { dimension });
            }
            if val_unquoted == "Infinity" || val_unquoted == "+Infinity" {
                return Err(BudgetError::InfiniteQuantity {
                    dimension,
                    is_negative: false,
                });
            }
            if val_unquoted == "-Infinity" {
                return Err(BudgetError::InfiniteQuantity {
                    dimension,
                    is_negative: true,
                });
            }

            match dimension {
                BudgetDimension::LatencyMs => {
                    if raw_val.starts_with('-') {
                        return Err(BudgetError::negative_quantity(dimension, -1.0));
                    }
                    let v: u64 = raw_val.parse().map_err(|_| BudgetError::IncompatibleUnit {
                        dimension,
                        expected_unit: dimension.unit(),
                        found_unit: raw_val.to_owned(),
                    })?;
                    builder = builder.latency_ms(v);
                }
                BudgetDimension::Tokens => {
                    if raw_val.starts_with('-') {
                        return Err(BudgetError::negative_quantity(dimension, -1.0));
                    }
                    let v: u64 = raw_val.parse().map_err(|_| BudgetError::IncompatibleUnit {
                        dimension,
                        expected_unit: dimension.unit(),
                        found_unit: raw_val.to_owned(),
                    })?;
                    builder = builder.tokens(v);
                }
                BudgetDimension::Bytes => {
                    if raw_val.starts_with('-') {
                        return Err(BudgetError::negative_quantity(dimension, -1.0));
                    }
                    let v: u64 = raw_val.parse().map_err(|_| BudgetError::IncompatibleUnit {
                        dimension,
                        expected_unit: dimension.unit(),
                        found_unit: raw_val.to_owned(),
                    })?;
                    builder = builder.bytes(v);
                }
                BudgetDimension::ModelCalls => {
                    if raw_val.starts_with('-') {
                        return Err(BudgetError::negative_quantity(dimension, -1.0));
                    }
                    let v: u32 = raw_val.parse().map_err(|_| BudgetError::IncompatibleUnit {
                        dimension,
                        expected_unit: dimension.unit(),
                        found_unit: raw_val.to_owned(),
                    })?;
                    builder = builder.model_calls(v);
                }
                BudgetDimension::CpuMillis => {
                    if raw_val.starts_with('-') {
                        return Err(BudgetError::negative_quantity(dimension, -1.0));
                    }
                    let v: u64 = raw_val.parse().map_err(|_| BudgetError::IncompatibleUnit {
                        dimension,
                        expected_unit: dimension.unit(),
                        found_unit: raw_val.to_owned(),
                    })?;
                    builder = builder.cpu_millis(v);
                }
                BudgetDimension::AcceleratorMillis => {
                    if raw_val.starts_with('-') {
                        return Err(BudgetError::negative_quantity(dimension, -1.0));
                    }
                    let v: u64 = raw_val.parse().map_err(|_| BudgetError::IncompatibleUnit {
                        dimension,
                        expected_unit: dimension.unit(),
                        found_unit: raw_val.to_owned(),
                    })?;
                    builder = builder.accelerator_millis(v);
                }
                BudgetDimension::EnergyMillijoules => {
                    if raw_val.starts_with('-') {
                        return Err(BudgetError::negative_quantity(dimension, -1.0));
                    }
                    let v: u64 = raw_val.parse().map_err(|_| BudgetError::IncompatibleUnit {
                        dimension,
                        expected_unit: dimension.unit(),
                        found_unit: raw_val.to_owned(),
                    })?;
                    builder = builder.energy_millijoules(v);
                }
                BudgetDimension::NetworkBytes => {
                    if raw_val.starts_with('-') {
                        return Err(BudgetError::negative_quantity(dimension, -1.0));
                    }
                    let v: u64 = raw_val.parse().map_err(|_| BudgetError::IncompatibleUnit {
                        dimension,
                        expected_unit: dimension.unit(),
                        found_unit: raw_val.to_owned(),
                    })?;
                    builder = builder.network_bytes(v);
                }
                BudgetDimension::StorageOperations => {
                    if raw_val.starts_with('-') {
                        return Err(BudgetError::negative_quantity(dimension, -1.0));
                    }
                    let v: u64 = raw_val.parse().map_err(|_| BudgetError::IncompatibleUnit {
                        dimension,
                        expected_unit: dimension.unit(),
                        found_unit: raw_val.to_owned(),
                    })?;
                    builder = builder.storage_operations(v);
                }
                BudgetDimension::PrivacyExposure => {
                    let v: f64 =
                        val_unquoted
                            .parse()
                            .map_err(|_| BudgetError::IncompatibleUnit {
                                dimension,
                                expected_unit: dimension.unit(),
                                found_unit: raw_val.to_owned(),
                            })?;
                    if v < 0.0 {
                        return Err(BudgetError::negative_quantity(dimension, v));
                    }
                    if v.is_nan() {
                        return Err(BudgetError::NaNQuantity { dimension });
                    }
                    if v.is_infinite() {
                        return Err(BudgetError::InfiniteQuantity {
                            dimension,
                            is_negative: v.is_sign_negative(),
                        });
                    }
                    builder = builder.privacy_exposure(v);
                }
                BudgetDimension::OperatorAttentionSeconds => {
                    let v: f64 =
                        val_unquoted
                            .parse()
                            .map_err(|_| BudgetError::IncompatibleUnit {
                                dimension,
                                expected_unit: dimension.unit(),
                                found_unit: raw_val.to_owned(),
                            })?;
                    if v < 0.0 {
                        return Err(BudgetError::negative_quantity(dimension, v));
                    }
                    if v.is_nan() {
                        return Err(BudgetError::NaNQuantity { dimension });
                    }
                    if v.is_infinite() {
                        return Err(BudgetError::InfiniteQuantity {
                            dimension,
                            is_negative: v.is_sign_negative(),
                        });
                    }
                    builder = builder.operator_attention_seconds(v);
                }
            }
        }

        builder.build()
    }
}

impl CanonicalEncode for BudgetVector {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.encode_to_canonical(encoder);
    }
}

impl CanonicalDecode for BudgetVector {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let latency_ms = decoder.u64()?;
        let tokens = decoder.u64()?;
        let bytes = decoder.u64()?;
        let model_calls = decoder.read_u32()?;
        let cpu_millis = decoder.u64()?;
        let accelerator_millis = decoder.u64()?;
        let energy_millijoules = decoder.u64()?;
        let network_bytes = decoder.u64()?;
        let storage_operations = decoder.u64()?;
        let privacy_bits = decoder.u64()?;
        let attention_bits = decoder.u64()?;

        let privacy = f64::from_bits(privacy_bits);
        let attention = f64::from_bits(attention_bits);

        Self::new(
            latency_ms,
            tokens,
            bytes,
            model_calls,
            cpu_millis,
            accelerator_millis,
            energy_millijoules,
            network_bytes,
            storage_operations,
            privacy,
            attention,
        )
        .map_err(ContractError::from)
    }
}

/// A builder for constructing and validating a `BudgetVector`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct BudgetVectorBuilder {
    latency_ms: u64,
    tokens: u64,
    bytes: u64,
    model_calls: u32,
    cpu_millis: u64,
    accelerator_millis: u64,
    energy_millijoules: u64,
    network_bytes: u64,
    storage_operations: u64,
    privacy_exposure: f64,
    operator_attention_seconds: f64,
}

impl BudgetVectorBuilder {
    /// Creates a new builder with all dimensions initialized to zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            latency_ms: 0,
            tokens: 0,
            bytes: 0,
            model_calls: 0,
            cpu_millis: 0,
            accelerator_millis: 0,
            energy_millijoules: 0,
            network_bytes: 0,
            storage_operations: 0,
            privacy_exposure: 0.0,
            operator_attention_seconds: 0.0,
        }
    }

    /// Sets wall-clock latency budget in milliseconds.
    #[must_use]
    pub const fn latency_ms(mut self, value: u64) -> Self {
        self.latency_ms = value;
        self
    }

    /// Sets output token budget.
    #[must_use]
    pub const fn tokens(mut self, value: u64) -> Self {
        self.tokens = value;
        self
    }

    /// Sets output and transfer byte budget.
    #[must_use]
    pub const fn bytes(mut self, value: u64) -> Self {
        self.bytes = value;
        self
    }

    /// Sets model invocation budget.
    #[must_use]
    pub const fn model_calls(mut self, value: u32) -> Self {
        self.model_calls = value;
        self
    }

    /// Sets CPU budget in milliseconds.
    #[must_use]
    pub const fn cpu_millis(mut self, value: u64) -> Self {
        self.cpu_millis = value;
        self
    }

    /// Sets accelerator budget in milliseconds.
    #[must_use]
    pub const fn accelerator_millis(mut self, value: u64) -> Self {
        self.accelerator_millis = value;
        self
    }

    /// Sets energy budget in millijoules.
    #[must_use]
    pub const fn energy_millijoules(mut self, value: u64) -> Self {
        self.energy_millijoules = value;
        self
    }

    /// Sets network budget in bytes.
    #[must_use]
    pub const fn network_bytes(mut self, value: u64) -> Self {
        self.network_bytes = value;
        self
    }

    /// Sets storage operations budget.
    #[must_use]
    pub const fn storage_operations(mut self, value: u64) -> Self {
        self.storage_operations = value;
        self
    }

    /// Sets privacy exposure budget.
    #[must_use]
    pub const fn privacy_exposure(mut self, value: f64) -> Self {
        self.privacy_exposure = value;
        self
    }

    /// Sets operator attention budget in seconds.
    #[must_use]
    pub const fn operator_attention_seconds(mut self, value: f64) -> Self {
        self.operator_attention_seconds = value;
        self
    }

    /// Validates all dimensions and builds a `BudgetVector`.
    pub fn build(self) -> Result<BudgetVector, BudgetError> {
        BudgetVector::new(
            self.latency_ms,
            self.tokens,
            self.bytes,
            self.model_calls,
            self.cpu_millis,
            self.accelerator_millis,
            self.energy_millijoules,
            self.network_bytes,
            self.storage_operations,
            self.privacy_exposure,
            self.operator_attention_seconds,
        )
    }
}

/// Redacted schema-structured log record for budget validation failures and transitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BudgetLogRecord {
    /// Schema identity.
    pub schema: &'static str,
    /// Stable event identifier.
    pub event_id: &'static str,
    /// Stage of execution (e.g. "decode", "admission", "consumption").
    pub stage: &'static str,
    /// Request or session correlation ID.
    pub correlation_id: String,
    /// The budget dimension involved, if any.
    pub dimension: Option<&'static str>,
    /// Machine-readable stable error code.
    pub error_code: Option<&'static str>,
    /// Content digest prior to transition.
    pub before_digest: Option<String>,
    /// Content digest after transition.
    pub after_digest: Option<String>,
}

impl BudgetLogRecord {
    /// Constructs a log record for a validation failure.
    pub fn validation_failure(
        correlation_id: impl Into<String>,
        stage: &'static str,
        error: &BudgetError,
    ) -> Self {
        Self {
            schema: "budget_log_record.v1",
            event_id: "budget.validation_failure",
            stage,
            correlation_id: correlation_id.into(),
            dimension: error.dimension().map(|d| d.as_str()),
            error_code: Some(error.code()),
            before_digest: None,
            after_digest: None,
        }
    }

    /// Constructs a log record for a valid budget transition.
    pub fn transition_success(
        correlation_id: impl Into<String>,
        stage: &'static str,
        before_digest: String,
        after_digest: String,
    ) -> Self {
        Self {
            schema: "budget_log_record.v1",
            event_id: "budget.transition",
            stage,
            correlation_id: correlation_id.into(),
            dimension: None,
            error_code: None,
            before_digest: Some(before_digest),
            after_digest: Some(after_digest),
        }
    }

    /// Renders this record as deterministic JSONL without leaking secrets or payloads.
    #[must_use]
    pub fn to_jsonl(&self) -> String {
        let mut out = String::new();
        out.push_str("{\"schema\":\"");
        out.push_str(self.schema);
        out.push_str("\",\"eventId\":\"");
        out.push_str(self.event_id);
        out.push_str("\",\"stage\":\"");
        out.push_str(self.stage);
        out.push_str("\",\"correlationId\":\"");
        out.push_str(&self.correlation_id);
        out.push('"');
        if let Some(dim) = self.dimension {
            out.push_str(",\"dimension\":\"");
            out.push_str(dim);
            out.push('"');
        }
        if let Some(code) = self.error_code {
            out.push_str(",\"errorCode\":\"");
            out.push_str(code);
            out.push('"');
        }
        if let Some(ref bd) = self.before_digest {
            out.push_str(",\"beforeDigest\":\"");
            out.push_str(bd);
            out.push('"');
        }
        if let Some(ref ad) = self.after_digest {
            out.push_str(",\"afterDigest\":\"");
            out.push_str(ad);
            out.push('"');
        }
        out.push_str("}\n");
        out
    }
}

fn canonical_f64_bits(value: f64) -> u64 {
    if value == 0.0 {
        0
    } else if value.is_nan() {
        0x7ff8_0000_0000_0000
    } else {
        value.to_bits()
    }
}

/// Stable failures raised by the reference semantic kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractError {
    /// Identifier is empty, oversized, or contains a forbidden byte.
    InvalidIdentifier,
    /// Digest is malformed.
    InvalidDigest,
    /// Digest names an algorithm that the contract does not recognize.
    UnsupportedDigestAlgorithm,
    /// Capture interval is inverted.
    InvertedTimeInterval,
    /// Probability interval is malformed.
    InvalidProbabilityInterval,
    /// A transition requires retained evidence.
    EvidenceRequired,
    /// A transition requires independent corroboration.
    CorroborationRequired,
    /// Canonical ordering is violated.
    NonCanonicalOrdering,
    /// A delta was prepared against a stale anchor.
    StaleAnchor,
    /// A batch sequence or epoch does not follow its basis.
    InvalidAnchorSuccessor,
    /// A referenced object generation does not match the ledger.
    GenerationConflict,
    /// A root or content digest does not match the represented bytes.
    DigestMismatch,
    /// A negative claim lacks a complete coverage witness.
    CoverageUncertified,
    /// An effect transition is not valid from the current state.
    InvalidEffectTransition,
    /// An idempotency key was reused with different content.
    IdempotencyConflict,
    /// An obligation identity was reused by a different operation.
    ObligationConflict,
    /// An external effect is indeterminate and must be reconciled.
    ReconciliationRequired,
    /// A required child root is absent from a publication graph.
    IncompletePublicationGraph,
    /// A requested object or operation is unknown.
    NotFound,
    /// A declared budget is exhausted.
    BudgetExhausted,
    /// A budget quantity is invalid or an operation failed validation.
    InvalidBudget(BudgetError),
}

impl ContractError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidIdentifier => "invalid_identifier",
            Self::InvalidDigest => "invalid_digest",
            Self::UnsupportedDigestAlgorithm => "unsupported_digest_algorithm",
            Self::InvertedTimeInterval => "inverted_time_interval",
            Self::InvalidProbabilityInterval => "invalid_probability_interval",
            Self::EvidenceRequired => "evidence_required",
            Self::CorroborationRequired => "corroboration_required",
            Self::NonCanonicalOrdering => "noncanonical_ordering",
            Self::StaleAnchor => "stale_anchor",
            Self::InvalidAnchorSuccessor => "invalid_anchor_successor",
            Self::GenerationConflict => "generation_conflict",
            Self::DigestMismatch => "digest_mismatch",
            Self::CoverageUncertified => "coverage_uncertified",
            Self::InvalidEffectTransition => "invalid_effect_transition",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::ObligationConflict => "obligation_conflict",
            Self::ReconciliationRequired => "reconciliation_required",
            Self::IncompletePublicationGraph => "incomplete_publication_graph",
            Self::NotFound => "not_found",
            Self::BudgetExhausted => "budget_exhausted",
            Self::InvalidBudget(err) => err.code(),
        }
    }
}

impl From<BudgetError> for ContractError {
    fn from(err: BudgetError) -> Self {
        Self::InvalidBudget(err)
    }
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ContractError {}
