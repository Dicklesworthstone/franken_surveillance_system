//! Shared semantic states and stable contract errors.

use core::fmt;

use crate::{CanonicalEncode, CanonicalEncoder};

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
    /// Returns true when every component is finite and nonnegative.
    #[must_use]
    pub fn is_valid(self) -> bool {
        self.privacy_exposure.is_finite()
            && self.privacy_exposure >= 0.0
            && self.operator_attention_seconds.is_finite()
            && self.operator_attention_seconds >= 0.0
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
        }
    }
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ContractError {}
