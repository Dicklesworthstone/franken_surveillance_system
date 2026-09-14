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
    /// The proposition was valid only at an older anchor or generation and has not been revalidated.
    Stale,
    /// The declared domain was not observable.
    NotObservable,
    /// Policy intentionally withheld the value.
    Redacted,
    /// A consequential external outcome may have occurred but is not yet proved or safely negated.
    Indeterminate,
    /// The proposition does not apply to the current domain.
    NotApplicable,
}

impl KnowledgeState {
    /// Returns the stable canonical ID for this knowledge state (e.g. `KSTATE-001`).
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Known => "KSTATE-001",
            Self::Estimated => "KSTATE-002",
            Self::Unknown => "KSTATE-003",
            Self::Conflicted => "KSTATE-004",
            Self::Stale => "KSTATE-005",
            Self::NotObservable => "KSTATE-006",
            Self::Redacted => "KSTATE-007",
            Self::Indeterminate => "KSTATE-008",
            Self::NotApplicable => "KSTATE-009",
        }
    }

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

    /// Parses a knowledge state from its stable ID (`KSTATE-001` .. `KSTATE-009`).
    pub fn from_id(id: &str) -> Result<Self, ContractError> {
        match id {
            "KSTATE-001" => Ok(Self::Known),
            "KSTATE-002" => Ok(Self::Estimated),
            "KSTATE-003" => Ok(Self::Unknown),
            "KSTATE-004" => Ok(Self::Conflicted),
            "KSTATE-005" => Ok(Self::Stale),
            "KSTATE-006" => Ok(Self::NotObservable),
            "KSTATE-007" => Ok(Self::Redacted),
            "KSTATE-008" => Ok(Self::Indeterminate),
            "KSTATE-009" => Ok(Self::NotApplicable),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }

    /// Parses a knowledge state from its schema spelling (`known`, `estimated`, etc.).
    pub fn from_name(name: &str) -> Result<Self, ContractError> {
        match name {
            "known" => Ok(Self::Known),
            "estimated" => Ok(Self::Estimated),
            "unknown" => Ok(Self::Unknown),
            "conflicted" => Ok(Self::Conflicted),
            "stale" => Ok(Self::Stale),
            "not_observable" => Ok(Self::NotObservable),
            "redacted" => Ok(Self::Redacted),
            "indeterminate" => Ok(Self::Indeterminate),
            "not_applicable" => Ok(Self::NotApplicable),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }

    /// Returns the exact normative meaning of this knowledge state from the contract registry.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::Known => {
                "The proposition is established for the named anchor and validity scope by admissible evidence or a proved terminal postcondition."
            }
            Self::Estimated => {
                "The proposition is supported by a declared derivation or model with explicit uncertainty and operating-envelope limits."
            }
            Self::Unknown => {
                "The authorized evidence acquired so far does not establish the proposition."
            }
            Self::Conflicted => {
                "Material admissible evidence supports incompatible propositions or generations."
            }
            Self::Stale => {
                "The proposition was valid only at an older anchor or generation and has not been revalidated."
            }
            Self::NotObservable => {
                "The declared sensor/authorization/model domain could not have established the proposition for the requested interval."
            }
            Self::Redacted => {
                "The proposition or its evidence exists but is intentionally withheld by the current privacy/capability projection."
            }
            Self::Indeterminate => {
                "A consequential external outcome may have occurred but is not yet proved or safely negated."
            }
            Self::NotApplicable => {
                "The proposition has no meaning for the named object, scope, or lifecycle state."
            }
        }
    }

    /// Returns whether this knowledge state may support planning.
    #[must_use]
    pub const fn may_support_planning(self) -> bool {
        match self {
            Self::Known
            | Self::Estimated
            | Self::Unknown
            | Self::Conflicted
            | Self::Stale
            | Self::NotObservable
            | Self::Redacted
            | Self::Indeterminate => true,
            Self::NotApplicable => false,
        }
    }

    /// Returns the exact normative rule for planning support.
    #[must_use]
    pub const fn planning_support_description(self) -> &'static str {
        match self {
            Self::Known => "yes",
            Self::Estimated => "yes",
            Self::Unknown => "yes, as an explicit branch or open variable",
            Self::Conflicted => "yes, only as competing branches",
            Self::Stale => "yes, only as a revalidation candidate",
            Self::NotObservable => "yes, as a protected residual possibility",
            Self::Redacted => "yes, only through non-leaking abstract constraints",
            Self::Indeterminate => "yes, only in reconciliation branches",
            Self::NotApplicable => "no",
        }
    }

    /// Returns whether this knowledge state may authorize an irreversible effect.
    ///
    /// CONSTITUTIONAL HARD GATE:
    /// Only `Known` may authorize irreversible effects (subject to capability and policy).
    /// All other states (estimated, unknown, conflicted, stale, not_observable, redacted, indeterminate, not_applicable)
    /// strictly return `false`.
    #[must_use]
    pub const fn may_authorize_irreversible_effect(self) -> bool {
        matches!(self, Self::Known)
    }

    /// Returns the exact normative rule for irreversible effect authorization.
    #[must_use]
    pub const fn irreversible_effect_description(self) -> &'static str {
        match self {
            Self::Known => "yes, subject to capability and policy",
            _ => "no",
        }
    }

    /// Returns whether explicit assumptions are required to use this knowledge state.
    #[must_use]
    pub const fn explicit_assumptions_required(self) -> bool {
        !matches!(self, Self::Known | Self::NotApplicable)
    }
}

impl CanonicalEncode for KnowledgeState {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

impl CanonicalDecode for KnowledgeState {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let text = decoder.text()?;
        Self::from_name(text).or_else(|_| Self::from_id(text))
    }
}

impl fmt::Display for KnowledgeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::str::FromStr for KnowledgeState {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name(s).or_else(|_| Self::from_id(s))
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

impl ProvenanceClass {
    /// Returns the stable canonical ID for this provenance class (e.g. `PROV-001`).
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Observed => "PROV-001",
            Self::Derived => "PROV-002",
            Self::Predicted => "PROV-003",
            Self::Remembered => "PROV-004",
            Self::OperatorAsserted => "PROV-005",
            Self::VendorClaimed => "PROV-006",
            Self::Policy => "PROV-007",
        }
    }

    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Derived => "derived",
            Self::Predicted => "predicted",
            Self::Remembered => "remembered",
            Self::OperatorAsserted => "operator_asserted",
            Self::VendorClaimed => "vendor_claimed",
            Self::Policy => "policy",
        }
    }

    /// Parses a provenance class from its stable ID (`PROV-001` .. `PROV-007`).
    pub fn from_id(id: &str) -> Result<Self, ContractError> {
        match id {
            "PROV-001" => Ok(Self::Observed),
            "PROV-002" => Ok(Self::Derived),
            "PROV-003" => Ok(Self::Predicted),
            "PROV-004" => Ok(Self::Remembered),
            "PROV-005" => Ok(Self::OperatorAsserted),
            "PROV-006" => Ok(Self::VendorClaimed),
            "PROV-007" => Ok(Self::Policy),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }

    /// Parses a provenance class from its schema spelling (`observed`, `derived`, etc.).
    pub fn from_name(name: &str) -> Result<Self, ContractError> {
        match name {
            "observed" => Ok(Self::Observed),
            "derived" => Ok(Self::Derived),
            "predicted" => Ok(Self::Predicted),
            "remembered" => Ok(Self::Remembered),
            "operator_asserted" => Ok(Self::OperatorAsserted),
            "vendor_claimed" => Ok(Self::VendorClaimed),
            "policy" => Ok(Self::Policy),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }

    /// Returns the exact normative meaning of this provenance class from the contract registry.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::Observed => {
                "Directly supported by canonical sensor, device, operator, or effect evidence."
            }
            Self::Derived => {
                "Deterministically computed from named canonical inputs under a registered algorithm and generation."
            }
            Self::Predicted => {
                "Counterfactual or forward prediction under an explicit branch/model and assumptions."
            }
            Self::Remembered => {
                "Advisory operational memory or prior episode material that must be revalidated against live evidence."
            }
            Self::OperatorAsserted => {
                "A human/operator assertion with identity, time, scope, and later corroboration status."
            }
            Self::VendorClaimed => {
                "Metadata or state asserted by a device/vendor boundary and not treated as independent physical truth."
            }
            Self::Policy => {
                "A rule, threshold, capability, or privacy decision from an exact policy generation."
            }
        }
    }

    /// Returns whether this provenance class may support an irreversible effect premise.
    ///
    /// CONSTITUTIONAL HARD GATE:
    /// `Predicted`, `Remembered`, and `VendorClaimed` may NEVER authorize an irreversible effect
    /// on their own. Even with a `Known` epistemic state, advisory memory, model predictions,
    /// and unverified vendor device assertions cannot authorize irreversible effects.
    #[must_use]
    pub const fn may_authorize_irreversible_effect(self) -> bool {
        match self {
            Self::Derived | Self::Predicted | Self::Remembered | Self::VendorClaimed => false,
            Self::Observed | Self::OperatorAsserted | Self::Policy => true,
        }
    }

    /// Returns whether this provenance class represents directly observed source evidence.
    #[must_use]
    pub const fn is_observed(self) -> bool {
        matches!(self, Self::Observed)
    }

    /// Returns whether this provenance class represents deterministically computed derived beliefs (PROV-002).
    #[must_use]
    pub const fn is_derived(self) -> bool {
        matches!(self, Self::Derived)
    }

    /// Returns whether this provenance class represents counterfactual or forward predictions (PROV-003).
    #[must_use]
    pub const fn is_predicted(self) -> bool {
        matches!(self, Self::Predicted)
    }

    /// Returns whether this provenance class represents advisory operational memory or prior episode material (PROV-004).
    #[must_use]
    pub const fn is_remembered(self) -> bool {
        matches!(self, Self::Remembered)
    }

    /// Returns whether this provenance class represents human/operator assertions (PROV-005).
    #[must_use]
    pub const fn is_operator_asserted(self) -> bool {
        matches!(self, Self::OperatorAsserted)
    }

    /// Returns whether this provenance class represents vendor/device boundary assertions (PROV-006).
    #[must_use]
    pub const fn is_vendor_claimed(self) -> bool {
        matches!(self, Self::VendorClaimed)
    }

    /// Returns whether reusing evidence from `self` (source provenance) under `target`
    /// constitutes evidence or confidence laundering without fresh observation or derivation.
    ///
    /// CONSTITUTIONAL AND REGISTRY RULES (Constitution §8.3, PROV-001..007, AGENTS.md):
    /// - PROV-001 (observed): Directly supported by canonical sensor, device, operator, or effect evidence.
    /// - PROV-002 (derived): Deterministically computed from named canonical inputs under a registered
    ///   algorithm and generation. Constitution §8.3: derived cannot become observed.
    /// - PROV-003 (predicted): Counterfactual or forward expectations (never current truth).
    ///   Predicted evidence digests can NEVER be reused under non-predicted classes.
    /// - PROV-004 (remembered): Advisory operational memory from prior episodes that must be
    ///   revalidated against live evidence. Cannot be relabeled as live Observed, Derived,
    ///   OperatorAsserted, or Policy.
    /// - PROV-006 (vendor_claimed): Boundary metadata not treated as independent physical truth.
    ///   Cannot be laundered into Observed, Derived, OperatorAsserted, or Policy.
    #[must_use]
    pub const fn may_launder_evidence_into(self, target: Self) -> bool {
        match self {
            Self::Predicted => !matches!(target, Self::Predicted),
            Self::Remembered => matches!(
                target,
                Self::Observed | Self::Derived | Self::OperatorAsserted | Self::Policy
            ),
            Self::VendorClaimed => matches!(
                target,
                Self::Observed | Self::Derived | Self::OperatorAsserted | Self::Policy
            ),
            Self::Derived => matches!(target, Self::Observed),
            Self::Observed | Self::OperatorAsserted | Self::Policy => false,
        }
    }

    /// Encodes this provenance class into its canonical 1-based wire byte tag.
    #[must_use]
    pub const fn to_code(self) -> u8 {
        match self {
            Self::Observed => 1,
            Self::Derived => 2,
            Self::Predicted => 3,
            Self::Remembered => 4,
            Self::OperatorAsserted => 5,
            Self::VendorClaimed => 6,
            Self::Policy => 7,
        }
    }

    /// Decodes a provenance class from its canonical 1-based wire byte tag.
    pub const fn from_code(code: u8) -> Result<Self, ContractError> {
        match code {
            1 => Ok(Self::Observed),
            2 => Ok(Self::Derived),
            3 => Ok(Self::Predicted),
            4 => Ok(Self::Remembered),
            5 => Ok(Self::OperatorAsserted),
            6 => Ok(Self::VendorClaimed),
            7 => Ok(Self::Policy),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

impl CanonicalEncode for ProvenanceClass {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

impl CanonicalDecode for ProvenanceClass {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let text = decoder.text()?;
        Self::from_name(text)
    }
}

impl fmt::Display for ProvenanceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::str::FromStr for ProvenanceClass {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name(s)
    }
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

impl HypothesisDisposition {
    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Supported => "supported",
            Self::Disfavored => "disfavored",
            Self::Refuted => "refuted",
            Self::Resolved => "resolved",
            Self::Superseded => "superseded",
        }
    }

    /// Parses from the stable schema spelling.
    pub fn from_name(s: &str) -> Result<Self, ContractError> {
        match s {
            "live" => Ok(Self::Live),
            "supported" => Ok(Self::Supported),
            "disfavored" => Ok(Self::Disfavored),
            "refuted" => Ok(Self::Refuted),
            "resolved" => Ok(Self::Resolved),
            "superseded" => Ok(Self::Superseded),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }

    /// Returns whether this disposition is still under active consideration.
    #[must_use]
    pub const fn is_viable(self) -> bool {
        matches!(self, Self::Live | Self::Supported | Self::Disfavored)
    }

    /// Returns whether this disposition represents a terminal state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Refuted | Self::Resolved | Self::Superseded)
    }
}

impl CanonicalEncode for HypothesisDisposition {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

impl CanonicalDecode for HypothesisDisposition {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let text = decoder.text()?;
        Self::from_name(text)
    }
}

impl fmt::Display for HypothesisDisposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::str::FromStr for HypothesisDisposition {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name(s)
    }
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

impl Completeness {
    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Bounded => "bounded",
            Self::Partial => "partial",
            Self::Unknown => "unknown",
            Self::NotObservable => "not_observable",
            Self::Unauthorized => "unauthorized",
            Self::Stale => "stale",
        }
    }

    /// Parses completeness from its schema spelling.
    pub fn from_name(name: &str) -> Result<Self, ContractError> {
        match name {
            "complete" => Ok(Self::Complete),
            "bounded" => Ok(Self::Bounded),
            "partial" => Ok(Self::Partial),
            "unknown" => Ok(Self::Unknown),
            "not_observable" => Ok(Self::NotObservable),
            "unauthorized" => Ok(Self::Unauthorized),
            "stale" => Ok(Self::Stale),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }

    /// Numeric code (1..=7) used across chronicle/projection envelopes.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Complete => 1,
            Self::Bounded => 2,
            Self::Partial => 3,
            Self::Unknown => 4,
            Self::NotObservable => 5,
            Self::Unauthorized => 6,
            Self::Stale => 7,
        }
    }

    /// Resolves completeness from numeric code (1..=7).
    pub fn from_code(code: u8) -> Result<Self, ContractError> {
        match code {
            1 => Ok(Self::Complete),
            2 => Ok(Self::Bounded),
            3 => Ok(Self::Partial),
            4 => Ok(Self::Unknown),
            5 => Ok(Self::NotObservable),
            6 => Ok(Self::Unauthorized),
            7 => Ok(Self::Stale),
            _ => Err(ContractError::UnknownEntryTag(code)),
        }
    }
}

impl CanonicalEncode for Completeness {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

impl CanonicalDecode for Completeness {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let text = decoder.text()?;
        Self::from_name(text)
    }
}

impl fmt::Display for Completeness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::str::FromStr for Completeness {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name(s)
    }
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

    /// Checked scaling of a budget quantity by a non-negative finite factor.
    pub fn checked_scale(
        self,
        factor: f64,
        dimension: BudgetDimension,
    ) -> Result<Self, BudgetError> {
        if factor.is_nan() {
            return Err(BudgetError::NaNQuantity { dimension });
        }
        if factor.is_infinite() {
            return Err(BudgetError::InfiniteQuantity {
                dimension,
                is_negative: factor.is_sign_negative(),
            });
        }
        if factor < 0.0 {
            return Err(BudgetError::negative_quantity(dimension, factor));
        }
        let scaled = self.raw * factor;
        if !scaled.is_finite() {
            return Err(BudgetError::Overflow {
                dimension,
                operation: "scale",
            });
        }
        Self::new(scaled, dimension)
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

/// Typed specification for constructing and validating a [`BudgetVector`].
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct BudgetVectorSpec {
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

impl BudgetVectorSpec {
    /// Zero specification across all dimensions.
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
}

/// Typed specification for constructing a [`BudgetVector`] from pre-validated quantities.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct BudgetQuantitiesSpec {
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
    /// Privacy-exposure budget.
    pub privacy_exposure: BudgetQuantity,
    /// Operator-attention budget.
    pub operator_attention_seconds: BudgetQuantity,
}

impl BudgetQuantitiesSpec {
    /// Zero specification across all dimensions.
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
        privacy_exposure: BudgetQuantity::ZERO,
        operator_attention_seconds: BudgetQuantity::ZERO,
    };
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
    /// Privacy-exposure budget (validated quantity).
    privacy_exposure: BudgetQuantity,
    /// Operator-attention budget (validated quantity).
    operator_attention_seconds: BudgetQuantity,
}

impl BudgetVector {
    /// Maximum permitted byte size for JSON budget payload (64 KiB).
    pub const MAX_JSON_BUDGET_BYTES: usize = 64 * 1024;

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
        privacy_exposure: BudgetQuantity::ZERO,
        operator_attention_seconds: BudgetQuantity::ZERO,
    };

    /// Constructs and validates a budget vector from a typed parameter specification.
    ///
    /// Rejects negative, NaN, or infinite floating-point quantities with stable typed errors.
    /// Normalizes -0.0 to +0.0.
    pub fn new(spec: BudgetVectorSpec) -> Result<Self, BudgetError> {
        let privacy = BudgetQuantity::new(spec.privacy_exposure, BudgetDimension::PrivacyExposure)?;
        let attention = BudgetQuantity::new(
            spec.operator_attention_seconds,
            BudgetDimension::OperatorAttentionSeconds,
        )?;
        Ok(Self {
            latency_ms: spec.latency_ms,
            tokens: spec.tokens,
            bytes: spec.bytes,
            model_calls: spec.model_calls,
            cpu_millis: spec.cpu_millis,
            accelerator_millis: spec.accelerator_millis,
            energy_millijoules: spec.energy_millijoules,
            network_bytes: spec.network_bytes,
            storage_operations: spec.storage_operations,
            privacy_exposure: privacy,
            operator_attention_seconds: attention,
        })
    }

    /// Constructs from validated BudgetQuantity values for continuous dimensions.
    #[must_use]
    pub fn from_quantities(spec: BudgetQuantitiesSpec) -> Self {
        Self {
            latency_ms: spec.latency_ms,
            tokens: spec.tokens,
            bytes: spec.bytes,
            model_calls: spec.model_calls,
            cpu_millis: spec.cpu_millis,
            accelerator_millis: spec.accelerator_millis,
            energy_millijoules: spec.energy_millijoules,
            network_bytes: spec.network_bytes,
            storage_operations: spec.storage_operations,
            privacy_exposure: spec.privacy_exposure,
            operator_attention_seconds: spec.operator_attention_seconds,
        }
    }

    /// Returns a builder for constructing a validated budget vector.
    #[must_use]
    pub fn builder() -> BudgetVectorBuilder {
        BudgetVectorBuilder::new()
    }

    /// Validates every component of the budget vector.
    ///
    /// Validated-by-construction: continuous dimensions are stored as validated BudgetQuantity.
    pub const fn validate(&self) -> Result<(), BudgetError> {
        Ok(())
    }

    /// Returns true when every component is finite and nonnegative.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        true
    }

    /// Returns a normalized copy where negative zero (-0.0) is converted to +0.0.
    pub const fn normalized(self) -> Result<Self, BudgetError> {
        Ok(self)
    }

    /// Accessor for privacy exposure continuous quantity.
    #[must_use]
    pub const fn privacy_exposure(&self) -> f64 {
        self.privacy_exposure.get()
    }

    /// Accessor for operator attention continuous quantity in seconds.
    #[must_use]
    pub const fn operator_attention_seconds(&self) -> f64 {
        self.operator_attention_seconds.get()
    }

    /// Encapsulates privacy exposure as a validated `BudgetQuantity`.
    pub const fn privacy_quantity(&self) -> Result<BudgetQuantity, BudgetError> {
        Ok(self.privacy_exposure)
    }

    /// Encapsulates operator attention as a validated `BudgetQuantity`.
    pub const fn operator_attention_quantity(&self) -> Result<BudgetQuantity, BudgetError> {
        Ok(self.operator_attention_seconds)
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

        let privacy = self
            .privacy_exposure
            .checked_add(other.privacy_exposure, BudgetDimension::PrivacyExposure)?;
        let attention = self.operator_attention_seconds.checked_add(
            other.operator_attention_seconds,
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
            privacy_exposure: privacy,
            operator_attention_seconds: attention,
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

        let privacy = self
            .privacy_exposure
            .checked_sub(other.privacy_exposure, BudgetDimension::PrivacyExposure)?;
        let attention = self.operator_attention_seconds.checked_sub(
            other.operator_attention_seconds,
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
            privacy_exposure: privacy,
            operator_attention_seconds: attention,
        })
    }

    /// Returns the first configured nonzero dimension in canonical registry order, if any.
    #[must_use]
    pub fn first_nonzero_dimension(&self) -> Option<BudgetDimension> {
        if self.latency_ms > 0 {
            return Some(BudgetDimension::LatencyMs);
        }
        if self.tokens > 0 {
            return Some(BudgetDimension::Tokens);
        }
        if self.bytes > 0 {
            return Some(BudgetDimension::Bytes);
        }
        if self.model_calls > 0 {
            return Some(BudgetDimension::ModelCalls);
        }
        if self.cpu_millis > 0 {
            return Some(BudgetDimension::CpuMillis);
        }
        if self.accelerator_millis > 0 {
            return Some(BudgetDimension::AcceleratorMillis);
        }
        if self.energy_millijoules > 0 {
            return Some(BudgetDimension::EnergyMillijoules);
        }
        if self.network_bytes > 0 {
            return Some(BudgetDimension::NetworkBytes);
        }
        if self.storage_operations > 0 {
            return Some(BudgetDimension::StorageOperations);
        }
        if self.privacy_exposure.get() > 0.0 {
            return Some(BudgetDimension::PrivacyExposure);
        }
        if self.operator_attention_seconds.get() > 0.0 {
            return Some(BudgetDimension::OperatorAttentionSeconds);
        }
        None
    }

    /// Checked scaling of all budget dimensions by a non-negative finite factor.
    pub fn checked_scale(&self, factor: f64) -> Result<Self, BudgetError> {
        self.validate()?;
        let dim = self
            .first_nonzero_dimension()
            .unwrap_or(BudgetDimension::LatencyMs);
        if factor.is_nan() {
            return Err(BudgetError::NaNQuantity { dimension: dim });
        }
        if factor.is_infinite() {
            return Err(BudgetError::InfiniteQuantity {
                dimension: dim,
                is_negative: factor.is_sign_negative(),
            });
        }
        if factor < 0.0 {
            return Err(BudgetError::negative_quantity(dim, factor));
        }

        let scale_u64 = |val: u64, dim: BudgetDimension| -> Result<u64, BudgetError> {
            let scaled = (val as f64) * factor;
            if !scaled.is_finite() || scaled > u64::MAX as f64 {
                return Err(BudgetError::Overflow {
                    dimension: dim,
                    operation: "scale",
                });
            }
            Ok(scaled.round() as u64)
        };

        let scale_u32 = |val: u32, dim: BudgetDimension| -> Result<u32, BudgetError> {
            let scaled = (val as f64) * factor;
            if !scaled.is_finite() || scaled > u32::MAX as f64 {
                return Err(BudgetError::Overflow {
                    dimension: dim,
                    operation: "scale",
                });
            }
            Ok(scaled.round() as u32)
        };

        let latency_ms = scale_u64(self.latency_ms, BudgetDimension::LatencyMs)?;
        let tokens = scale_u64(self.tokens, BudgetDimension::Tokens)?;
        let bytes = scale_u64(self.bytes, BudgetDimension::Bytes)?;
        let model_calls = scale_u32(self.model_calls, BudgetDimension::ModelCalls)?;
        let cpu_millis = scale_u64(self.cpu_millis, BudgetDimension::CpuMillis)?;
        let accelerator_millis =
            scale_u64(self.accelerator_millis, BudgetDimension::AcceleratorMillis)?;
        let energy_millijoules =
            scale_u64(self.energy_millijoules, BudgetDimension::EnergyMillijoules)?;
        let network_bytes = scale_u64(self.network_bytes, BudgetDimension::NetworkBytes)?;
        let storage_operations =
            scale_u64(self.storage_operations, BudgetDimension::StorageOperations)?;

        let privacy = self
            .privacy_exposure
            .checked_scale(factor, BudgetDimension::PrivacyExposure)?;
        let attention = self
            .operator_attention_seconds
            .checked_scale(factor, BudgetDimension::OperatorAttentionSeconds)?;

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
            privacy_exposure: privacy,
            operator_attention_seconds: attention,
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
        remaining.assert_authority_unmodified(self)?;
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
                BudgetQuantity::ZERO
            },
            operator_attention_seconds: if predicate(BudgetDimension::OperatorAttentionSeconds) {
                self.operator_attention_seconds
            } else {
                BudgetQuantity::ZERO
            },
        })
    }

    /// Checks authority separation: ensures derived cognition results do not mint or enlarge budget.
    pub fn assert_authority_unmodified(&self, prior: &Self) -> Result<(), BudgetError> {
        self.validate()?;
        prior.validate()?;
        if self.latency_ms > prior.latency_ms {
            return Err(BudgetError::AuthorityEnlargementForbidden {
                dimension: BudgetDimension::LatencyMs,
            });
        }
        if self.tokens > prior.tokens {
            return Err(BudgetError::AuthorityEnlargementForbidden {
                dimension: BudgetDimension::Tokens,
            });
        }
        if self.bytes > prior.bytes {
            return Err(BudgetError::AuthorityEnlargementForbidden {
                dimension: BudgetDimension::Bytes,
            });
        }
        if self.model_calls > prior.model_calls {
            return Err(BudgetError::AuthorityEnlargementForbidden {
                dimension: BudgetDimension::ModelCalls,
            });
        }
        if self.cpu_millis > prior.cpu_millis {
            return Err(BudgetError::AuthorityEnlargementForbidden {
                dimension: BudgetDimension::CpuMillis,
            });
        }
        if self.accelerator_millis > prior.accelerator_millis {
            return Err(BudgetError::AuthorityEnlargementForbidden {
                dimension: BudgetDimension::AcceleratorMillis,
            });
        }
        if self.energy_millijoules > prior.energy_millijoules {
            return Err(BudgetError::AuthorityEnlargementForbidden {
                dimension: BudgetDimension::EnergyMillijoules,
            });
        }
        if self.network_bytes > prior.network_bytes {
            return Err(BudgetError::AuthorityEnlargementForbidden {
                dimension: BudgetDimension::NetworkBytes,
            });
        }
        if self.storage_operations > prior.storage_operations {
            return Err(BudgetError::AuthorityEnlargementForbidden {
                dimension: BudgetDimension::StorageOperations,
            });
        }
        if self.privacy_exposure > prior.privacy_exposure {
            return Err(BudgetError::AuthorityEnlargementForbidden {
                dimension: BudgetDimension::PrivacyExposure,
            });
        }
        if self.operator_attention_seconds > prior.operator_attention_seconds {
            return Err(BudgetError::AuthorityEnlargementForbidden {
                dimension: BudgetDimension::OperatorAttentionSeconds,
            });
        }
        Ok(())
    }

    /// Encodes to canonical binary format (exactly 84 bytes).
    ///
    /// Validated-by-construction: BudgetVector fields are guaranteed valid,
    /// and continuous dimensions emit canonical IEEE-754 bit encodings directly.
    pub fn encode_to_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.latency_ms);
        encoder.u64(self.tokens);
        encoder.u64(self.bytes);
        encoder.u32(self.model_calls);
        encoder.u64(self.cpu_millis);
        encoder.u64(self.accelerator_millis);
        encoder.u64(self.energy_millijoules);
        encoder.u64(self.network_bytes);
        encoder.u64(self.storage_operations);
        encoder.u64(self.privacy_exposure.canonical_bits());
        encoder.u64(self.operator_attention_seconds.canonical_bits());
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

        // Canonical binary encoding strictly maps 0.0 to 0x0000_0000_0000_0000 (+0.0).
        // IEEE-754 negative zero bits (0x8000_0000_0000_0000) are non-canonical and must be rejected.
        if privacy_bits == 0x8000_0000_0000_0000 {
            return Err(BudgetError::NegativeQuantity {
                dimension: BudgetDimension::PrivacyExposure,
                value_bits: privacy_bits,
            });
        }
        if attention_bits == 0x8000_0000_0000_0000 {
            return Err(BudgetError::NegativeQuantity {
                dimension: BudgetDimension::OperatorAttentionSeconds,
                value_bits: attention_bits,
            });
        }

        let privacy = f64::from_bits(privacy_bits);
        let attention = f64::from_bits(attention_bits);

        Self::new(BudgetVectorSpec {
            latency_ms,
            tokens,
            bytes: bytes_count,
            model_calls,
            cpu_millis,
            accelerator_millis,
            energy_millijoules,
            network_bytes,
            storage_operations,
            privacy_exposure: privacy,
            operator_attention_seconds: attention,
        })
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

    #[inline]
    const fn is_json_ws(b: u8) -> bool {
        matches!(b, b' ' | b'\t' | b'\n' | b'\r')
    }

    /// Strictly validates whether an ASCII byte sequence conforms to RFC 8259 number grammar:
    /// `^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`
    fn validate_rfc8259_number(bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return false;
        }
        let mut i = 0;
        let len = bytes.len();

        // 1. Optional minus sign
        if bytes[i] == b'-' {
            i += 1;
            if i == len {
                return false; // Bare '-'
            }
        }

        // 2. Integer part: either '0' (not followed by any digit), or '1'..='9' followed by digits
        if bytes[i] == b'0' {
            i += 1;
            // If next char is a digit, that's a leading zero (e.g. "01", "00"), which RFC 8259 forbids
            if i < len && bytes[i].is_ascii_digit() {
                return false;
            }
        } else if bytes[i].is_ascii_digit() {
            while i < len && bytes[i].is_ascii_digit() {
                i += 1;
            }
        } else {
            return false;
        }

        // 3. Optional fractional part: '.' followed by 1 or more digits
        if i < len && bytes[i] == b'.' {
            i += 1;
            if i == len || !bytes[i].is_ascii_digit() {
                return false; // "1." or trailing dot or no digits after dot
            }
            while i < len && bytes[i].is_ascii_digit() {
                i += 1;
            }
        }

        // 4. Optional exponent part: ('e' | 'E') optionally ('+' | '-') followed by 1 or more digits
        if i < len && (bytes[i] == b'e' || bytes[i] == b'E') {
            i += 1;
            if i < len && (bytes[i] == b'+' || bytes[i] == b'-') {
                i += 1;
            }
            if i == len || !bytes[i].is_ascii_digit() {
                return false; // "1e", "1e+", "1E-" without digits
            }
            while i < len && bytes[i].is_ascii_digit() {
                i += 1;
            }
        }

        i == len
    }

    /// Scans a double-quoted JSON string according to RFC 8259 Section 7.
    ///
    /// Validates that:
    /// - Unescaped control characters (< 0x20) are rejected with `InvalidEncoding`.
    /// - Valid escape characters (`"`, `\`, `/`, `b`, `f`, `n`, `r`, `t`) are accepted.
    /// - Unicode escapes (`\uXXXX`) have exactly 4 hexadecimal digits.
    ///
    /// Returns the byte range `(start, end)` of the string content inside quotes.
    fn scan_json_string(bytes: &[u8], pos: &mut usize) -> Result<(usize, usize), BudgetError> {
        if *pos >= bytes.len() || bytes[*pos] != b'"' {
            return Err(BudgetError::InvalidEncoding {
                reason: "expected double-quoted string in JSON budget",
            });
        }
        *pos += 1; // skip opening '"'
        let start = *pos;
        while *pos < bytes.len() {
            let b = bytes[*pos];
            if b < 0x20 {
                return Err(BudgetError::InvalidEncoding {
                    reason: "unescaped control character in JSON string",
                });
            }
            if b == b'"' {
                let end = *pos;
                *pos += 1; // consume closing '"'
                return Ok((start, end));
            }
            if b == b'\\' {
                *pos += 1;
                if *pos >= bytes.len() {
                    return Err(BudgetError::InvalidEncoding {
                        reason: "unterminated escape sequence in JSON string",
                    });
                }
                match bytes[*pos] {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {
                        *pos += 1;
                    }
                    b'u' => {
                        *pos += 1;
                        if *pos + 4 > bytes.len() {
                            return Err(BudgetError::InvalidEncoding {
                                reason: "incomplete \\u escape sequence in JSON string",
                            });
                        }
                        for _ in 0..4 {
                            if !bytes[*pos].is_ascii_hexdigit() {
                                return Err(BudgetError::InvalidEncoding {
                                    reason: "invalid hex digit in \\u escape sequence",
                                });
                            }
                            *pos += 1;
                        }
                    }
                    _ => {
                        return Err(BudgetError::InvalidEncoding {
                            reason: "invalid escape character in JSON string",
                        });
                    }
                }
            } else {
                *pos += 1;
            }
        }
        Err(BudgetError::InvalidEncoding {
            reason: "unterminated string in JSON budget",
        })
    }

    /// Decodes a BudgetVector from JSON bytes without external dependencies.
    pub fn decode_json_slice(bytes: &[u8]) -> Result<Self, BudgetError> {
        if bytes.len() > Self::MAX_JSON_BUDGET_BYTES {
            return Err(BudgetError::InvalidEncoding {
                reason: "budget JSON exceeds maximum permitted size",
            });
        }

        let text = core::str::from_utf8(bytes).map_err(|_| BudgetError::InvalidEncoding {
            reason: "JSON bytes must be valid UTF-8",
        })?;

        let mut pos = 0;
        let len = bytes.len();

        while pos < len && Self::is_json_ws(bytes[pos]) {
            pos += 1;
        }
        if pos == len || bytes[pos] != b'{' {
            return Err(BudgetError::InvalidEncoding {
                reason: "JSON budget must be an object enclosed in braces",
            });
        }
        pos += 1; // consume '{'

        while pos < len && Self::is_json_ws(bytes[pos]) {
            pos += 1;
        }
        if pos < len && bytes[pos] == b'}' {
            return Err(BudgetError::InvalidEncoding {
                reason: "empty JSON object is not a valid budget specification",
            });
        }
        if pos == len {
            return Err(BudgetError::InvalidEncoding {
                reason: "unterminated JSON object",
            });
        }

        let mut builder = Self::builder();
        let mut seen_dimensions: u16 = 0;

        loop {
            while pos < len && Self::is_json_ws(bytes[pos]) {
                pos += 1;
            }
            if pos == len {
                return Err(BudgetError::InvalidEncoding {
                    reason: "unterminated JSON object",
                });
            }

            // Key must be a double-quoted string
            if bytes[pos] != b'"' {
                return Err(BudgetError::InvalidEncoding {
                    reason: "JSON keys must be double-quoted strings",
                });
            }

            let (key_start, key_end) = Self::scan_json_string(bytes, &mut pos)?;
            let key_str = &text[key_start..key_end];

            let dimension =
                BudgetDimension::parse(key_str).ok_or(BudgetError::InvalidEncoding {
                    reason: "unknown budget dimension in JSON",
                })?;

            let bit = 1u16 << (dimension as u8);
            if (seen_dimensions & bit) != 0 {
                return Err(BudgetError::InvalidEncoding {
                    reason: "duplicate budget dimension in JSON",
                });
            }
            seen_dimensions |= bit;

            // Colon separator
            while pos < len && Self::is_json_ws(bytes[pos]) {
                pos += 1;
            }
            if pos >= len || bytes[pos] != b':' {
                return Err(BudgetError::InvalidEncoding {
                    reason: "missing colon after key in JSON budget",
                });
            }
            pos += 1; // consume ':'

            while pos < len && Self::is_json_ws(bytes[pos]) {
                pos += 1;
            }
            if pos >= len {
                return Err(BudgetError::InvalidEncoding {
                    reason: "missing value in JSON budget",
                });
            }

            // Value parsing: reject nested structures or leading '+'
            if bytes[pos] == b'{' || bytes[pos] == b'[' {
                return Err(BudgetError::InvalidEncoding {
                    reason: "nested structure not permitted in flat budget JSON",
                });
            }

            let (raw_val, is_quoted) = if bytes[pos] == b'"' {
                let (val_start, val_end) = Self::scan_json_string(bytes, &mut pos)?;
                let val_str = &text[val_start..val_end];
                (val_str, true)
            } else {
                let val_start = pos;
                while pos < len
                    && bytes[pos] != b','
                    && bytes[pos] != b'}'
                    && !Self::is_json_ws(bytes[pos])
                {
                    if bytes[pos] == b'{' || bytes[pos] == b'[' {
                        return Err(BudgetError::InvalidEncoding {
                            reason: "nested structure not permitted in flat budget JSON",
                        });
                    }
                    pos += 1;
                }
                let val_str = &text[val_start..pos];
                (val_str, false)
            };

            if raw_val == "NaN" || raw_val == "nan" {
                return Err(BudgetError::NaNQuantity { dimension });
            }
            if raw_val == "Infinity" || raw_val == "+Infinity" {
                return Err(BudgetError::InfiniteQuantity {
                    dimension,
                    is_negative: false,
                });
            }
            if raw_val == "-Infinity" {
                return Err(BudgetError::InfiniteQuantity {
                    dimension,
                    is_negative: true,
                });
            }

            // Strict unquoting: neither integer nor float dimensions accept quoted numerals
            if is_quoted {
                return Err(BudgetError::IncompatibleUnit {
                    dimension,
                    expected_unit: dimension.unit(),
                    found_unit: format!("\"{raw_val}\""),
                });
            }

            if raw_val.starts_with('+') {
                return Err(BudgetError::InvalidEncoding {
                    reason: "leading plus sign is forbidden in JSON numbers",
                });
            }

            // Validate against strict RFC 8259 number grammar
            if !Self::validate_rfc8259_number(raw_val.as_bytes()) {
                return Err(BudgetError::InvalidEncoding {
                    reason: "invalid JSON number format",
                });
            }

            match dimension {
                BudgetDimension::PrivacyExposure => {
                    let v: f64 = raw_val.parse().map_err(|_| BudgetError::InvalidEncoding {
                        reason: "invalid float literal",
                    })?;
                    if v.is_infinite() {
                        return Err(BudgetError::InvalidEncoding {
                            reason: "number exponent overflow",
                        });
                    }
                    if v.is_nan() {
                        return Err(BudgetError::NaNQuantity { dimension });
                    }
                    if v < 0.0 {
                        return Err(BudgetError::negative_quantity(dimension, v));
                    }
                    builder = builder.privacy_exposure(v);
                }
                BudgetDimension::OperatorAttentionSeconds => {
                    let v: f64 = raw_val.parse().map_err(|_| BudgetError::InvalidEncoding {
                        reason: "invalid float literal",
                    })?;
                    if v.is_infinite() {
                        return Err(BudgetError::InvalidEncoding {
                            reason: "number exponent overflow",
                        });
                    }
                    if v.is_nan() {
                        return Err(BudgetError::NaNQuantity { dimension });
                    }
                    if v < 0.0 {
                        return Err(BudgetError::negative_quantity(dimension, v));
                    }
                    builder = builder.operator_attention_seconds(v);
                }
                _ => {
                    if raw_val.contains('e') || raw_val.contains('E') {
                        return Err(BudgetError::InvalidEncoding {
                            reason: "scientific notation / exponent not permitted for integer budget dimension",
                        });
                    }
                    if raw_val.contains('.') {
                        return Err(BudgetError::InvalidEncoding {
                            reason: "fractional number not permitted for integer budget dimension",
                        });
                    }
                    if raw_val.starts_with('-') {
                        return Err(BudgetError::negative_quantity(dimension, -1.0));
                    }

                    match dimension {
                        BudgetDimension::LatencyMs => {
                            let v: u64 =
                                raw_val.parse().map_err(|_| BudgetError::InvalidEncoding {
                                    reason: "integer quantity out of range",
                                })?;
                            builder = builder.latency_ms(v);
                        }
                        BudgetDimension::Tokens => {
                            let v: u64 =
                                raw_val.parse().map_err(|_| BudgetError::InvalidEncoding {
                                    reason: "integer quantity out of range",
                                })?;
                            builder = builder.tokens(v);
                        }
                        BudgetDimension::Bytes => {
                            let v: u64 =
                                raw_val.parse().map_err(|_| BudgetError::InvalidEncoding {
                                    reason: "integer quantity out of range",
                                })?;
                            builder = builder.bytes(v);
                        }
                        BudgetDimension::ModelCalls => {
                            let v: u32 =
                                raw_val.parse().map_err(|_| BudgetError::InvalidEncoding {
                                    reason: "integer quantity out of range",
                                })?;
                            builder = builder.model_calls(v);
                        }
                        BudgetDimension::CpuMillis => {
                            let v: u64 =
                                raw_val.parse().map_err(|_| BudgetError::InvalidEncoding {
                                    reason: "integer quantity out of range",
                                })?;
                            builder = builder.cpu_millis(v);
                        }
                        BudgetDimension::AcceleratorMillis => {
                            let v: u64 =
                                raw_val.parse().map_err(|_| BudgetError::InvalidEncoding {
                                    reason: "integer quantity out of range",
                                })?;
                            builder = builder.accelerator_millis(v);
                        }
                        BudgetDimension::EnergyMillijoules => {
                            let v: u64 =
                                raw_val.parse().map_err(|_| BudgetError::InvalidEncoding {
                                    reason: "integer quantity out of range",
                                })?;
                            builder = builder.energy_millijoules(v);
                        }
                        BudgetDimension::NetworkBytes => {
                            let v: u64 =
                                raw_val.parse().map_err(|_| BudgetError::InvalidEncoding {
                                    reason: "integer quantity out of range",
                                })?;
                            builder = builder.network_bytes(v);
                        }
                        BudgetDimension::StorageOperations => {
                            let v: u64 =
                                raw_val.parse().map_err(|_| BudgetError::InvalidEncoding {
                                    reason: "integer quantity out of range",
                                })?;
                            builder = builder.storage_operations(v);
                        }
                        _ => unreachable!(),
                    }
                }
            }

            // Member delimiter: ',' or '}'
            while pos < len && Self::is_json_ws(bytes[pos]) {
                pos += 1;
            }
            if pos >= len {
                return Err(BudgetError::InvalidEncoding {
                    reason: "unterminated JSON object",
                });
            }
            match bytes[pos] {
                b',' => {
                    pos += 1;
                    while pos < len && Self::is_json_ws(bytes[pos]) {
                        pos += 1;
                    }
                    if pos >= len {
                        return Err(BudgetError::InvalidEncoding {
                            reason: "trailing comma in JSON budget",
                        });
                    }
                    if bytes[pos] == b',' {
                        return Err(BudgetError::InvalidEncoding {
                            reason: "consecutive commas in JSON budget",
                        });
                    }
                    if bytes[pos] == b'}' {
                        return Err(BudgetError::InvalidEncoding {
                            reason: "trailing comma in JSON budget",
                        });
                    }
                }
                b'}' => {
                    pos += 1;
                    // Check for trailing garbage after closing brace
                    while pos < len && Self::is_json_ws(bytes[pos]) {
                        pos += 1;
                    }
                    if pos < len {
                        return Err(BudgetError::InvalidEncoding {
                            reason: "trailing content after JSON budget object",
                        });
                    }
                    break;
                }
                _ => {
                    return Err(BudgetError::InvalidEncoding {
                        reason: "expected comma or closing brace after object member",
                    });
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

        // Canonical binary encoding strictly maps 0.0 to 0x0000_0000_0000_0000 (+0.0).
        // IEEE-754 negative zero bits (0x8000_0000_0000_0000) are non-canonical and must be rejected.
        if privacy_bits == 0x8000_0000_0000_0000 {
            return Err(ContractError::from(BudgetError::NegativeQuantity {
                dimension: BudgetDimension::PrivacyExposure,
                value_bits: privacy_bits,
            }));
        }
        if attention_bits == 0x8000_0000_0000_0000 {
            return Err(ContractError::from(BudgetError::NegativeQuantity {
                dimension: BudgetDimension::OperatorAttentionSeconds,
                value_bits: attention_bits,
            }));
        }

        let privacy = f64::from_bits(privacy_bits);
        let attention = f64::from_bits(attention_bits);

        Self::new(BudgetVectorSpec {
            latency_ms,
            tokens,
            bytes,
            model_calls,
            cpu_millis,
            accelerator_millis,
            energy_millijoules,
            network_bytes,
            storage_operations,
            privacy_exposure: privacy,
            operator_attention_seconds: attention,
        })
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
        BudgetVector::new(BudgetVectorSpec {
            latency_ms: self.latency_ms,
            tokens: self.tokens,
            bytes: self.bytes,
            model_calls: self.model_calls,
            cpu_millis: self.cpu_millis,
            accelerator_millis: self.accelerator_millis,
            energy_millijoules: self.energy_millijoules,
            network_bytes: self.network_bytes,
            storage_operations: self.storage_operations,
            privacy_exposure: self.privacy_exposure,
            operator_attention_seconds: self.operator_attention_seconds,
        })
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
    /// Arithmetic overflow in timestamp or interval calculation.
    ArithmeticOverflow,
    /// Uncertainty narrowing attempted in monotone widening operation.
    NonMonotoneUncertaintyNarrowing,
    /// Unrecognized canonical encoding tag for clock basis.
    UnknownClockBasis(u8),
    /// Unrecognized canonical encoding tag for an event store entry.
    UnknownEntryTag(u8),
    /// A transition requires retained evidence.
    EvidenceRequired,
    /// A witnessed revision retains evidence but no edge that counts as support for it.
    SupportingEvidenceRequired,
    /// An evidence edge's `supports` flag disagrees with its relation.
    EvidenceRelationMismatch,
    /// An event revision violates a structural bound or field invariant.
    EventRevisionMalformed,
    /// A revision that establishes or acts on presence carries a sensor-tamper report.
    SensorIntegrityRisk,
    /// A revision does not supersede the revision its object's authority currently holds.
    SupersessionMismatch,
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
    /// A subsystem generation identifier names a forbidden mutable latest alias (ADR-0004).
    LatestNotResolvable,
    /// A `redacted` knowledge cell lacks its explicit typed redaction marker.
    RedactionMarkerRequired,
    /// A knowledge cell carries a state basis that belongs to a different knowledge state.
    KnowledgeStateBasisMismatch,
    /// A `stale` knowledge cell lacks the older anchor or generation it was valid at.
    StaleBasisRequired,
    /// A stale basis is not strictly older than the current anchor or generation it names.
    StaleBasisNotOlder,
    /// An `indeterminate` knowledge cell lacks its typed reconciliation basis.
    ReconciliationBasisRequired,
    /// Legacy (v1) operation receipt bytes were offered to the public canonical decoder. A v1
    /// receipt exists only as the product of the effect journal's versioned durable replay
    /// (fss-deir9).
    LegacyReceiptRequiresJournal,
    /// A reconciliation basis dropped the occurred or the not-occurred branch.
    ReconciliationBranchesIncomplete,
    /// A derived abstraction layer or cognition type illegally claimed authority or effect ownership.
    DerivedLayerAuthorityForbidden,
    /// A derived belief lacks an anchor to canonical evidence.
    DerivedBeliefMissingAnchor,
    /// A derived belief illegally claimed the `known` knowledge state.
    DerivedBeliefKnownForbidden,
    /// A derived belief is pinned to an anchor that is neither the caller's current anchor nor
    /// strictly older than it: a future, forked, or cross-lineage anchor (AGT-LAYER-004, INV-069).
    DerivedBeliefAnchorMismatch,
    /// A derived belief lists the same evidence root twice within one evidence set (AGT-LAYER-004).
    DerivedBeliefDuplicateEvidence,
    /// A derived belief lists one evidence root as both supporting and contradicting (AGT-LAYER-004).
    DerivedBeliefEvidenceOverlap,
    /// An unknown abstraction layer identifier or name was encountered.
    UnknownAbstractionLayer(String),
    /// Attempted to promote decode or model output into source evidence (AGT-LAYER-002, INV-003).
    ProhibitedEvidencePromotion,
    /// Source evidence lacks an authoritative anchor lineage (AGT-LAYER-002, INV-003).
    SourceEvidenceMissingAnchor,
    /// Source evidence not retained under custody requires an explicit omission reason (AGT-LAYER-002, INV-003).
    SourceEvidenceOmissionRequired,
    /// Source evidence retained under custody cannot declare an omission reason (AGT-LAYER-002, INV-003).
    SourceEvidenceRetainedWithOmission,
    /// Source evidence not retained under custody cannot bind non-empty capsule bytes or non-zero digest (AGT-LAYER-002, INV-003).
    SourceEvidenceNotRetainedWithCapsuleBytes,
    /// Source evidence custody byte count does not match capsule source byte count (AGT-LAYER-002, INV-003).
    SourceEvidenceByteCountMismatch,
    /// Storage handle for retained source evidence is empty (AGT-LAYER-002, INV-003).
    SourceEvidenceEmptyStorageHandle,
    /// Storage handle for retained source evidence contains forbidden directory traversal sequence (AGT-LAYER-002, INV-003).
    SourceEvidenceStorageHandleTraversal,
    /// Storage handle for retained source evidence contains forbidden absolute path or url (AGT-LAYER-002, INV-003).
    SourceEvidenceStorageHandleAbsolutePath,
    /// Storage handle for retained source evidence has an empty segment: a doubled or trailing
    /// `/` separator (AGT-LAYER-002, INV-003).
    SourceEvidenceStorageHandleEmptySegment,
    /// Storage handle for retained source evidence exceeds its byte bound (AGT-LAYER-002, INV-003).
    SourceEvidenceStorageHandleOverLength,
    /// Storage handle for retained source evidence contains a character outside the allow-list
    /// ASCII `[A-Za-z0-9._-]` plus `/` (AGT-LAYER-002, INV-003).
    SourceEvidenceStorageHandleDisallowedCharacter,
    /// Storage handle for retained source evidence contains `%`; percent-encoding is refused
    /// outright rather than decoded (AGT-LAYER-002, INV-003).
    SourceEvidenceStorageHandlePercentEncodingRefused,
    /// Raw wire packets classification cannot carry a sensor capsule payload (AGT-LAYER-002, INV-003).
    SourceEvidenceRawWirePacketsWithCapsule,
    /// Source evidence statement is empty or exceeds 512 bytes (AGT-LAYER-002, INV-003).
    SourceEvidenceStatementMalformed,
    /// Unknown source evidence classification string token.
    UnknownSourceEvidenceClassification(String),
    /// Unknown omission reason string token.
    UnknownOmissionReason(String),
    /// Unknown source custody binary wire tag.
    UnknownSourceCustodyTag(u8),
    /// Sensor capsule classification requires a sensor capsule payload (AGT-LAYER-002).
    SourceEvidenceCapsuleRequired,
    /// Continuity witness classification requires a continuity witness digest (AGT-LAYER-002).
    SourceEvidenceWitnessRequired,
    /// Continuity witness cannot equal source digest (circular self-witness) (AGT-LAYER-002).
    SourceEvidenceWitnessEqualsSourceDigest,
    /// Source evidence not retained cannot bind a continuity witness (AGT-LAYER-002).
    SourceEvidenceNotRetainedWithWitness,
    /// Source evidence binary wire format version is unsupported (AGT-LAYER-002).
    UnsupportedSourceEvidenceVersion(u32),
    /// Clock basis name string is unrecognized.
    UnknownClockBasisName(String),
    /// Attempted to collapse uncertainty into truth or resolve an investigation without adjudication (AGT-LAYER-006, INV-104).
    UnadjudicatedUncertaintyCollapse,
    /// An investigation requires at least two competing hypotheses to preserve alternatives (AGT-LAYER-006, INV-104, AGENTS.md).
    CompetingHypothesesRequired,
    /// An investigation hypothesis lacks mandatory predicted observations or falsifiers (AGT-LAYER-006, INV-104).
    HypothesisMissingFalsifier,
    /// An investigation hypothesis cannot claim the `known` knowledge state (AGT-LAYER-006, INV-104).
    HypothesisKnownForbidden,
    /// Spatial extent, bounding box, waypoint coordinates, or crop geometry is invalid.
    InvalidSpatialExtent,
    /// An active grant is not held by the context authority (Cx).
    UnboundCapabilityGrant(String),
    /// A non-root region lacks an owning parent region (orphan work forbidden).
    OrphanRegion(String),
    /// A region names itself as its parent region (cyclic region hierarchy).
    SelfParentedRegion(String),
    /// A region entering drain or finalizing lacks an active cancellation reason in context.
    MissingCancellationReason,
    /// A closed region lacks a verified drain record or quiescence proof.
    MissingDrainRecord,
    /// A runtime authority record lists the same capability grant more than once.
    DuplicateGrant(String),
    /// A runtime authority record lists the same obligation ID more than once.
    DuplicateObligation(String),
    /// A closed region retains an obligation in the Indeterminate state.
    IndeterminateObligationOnClosure(String),
    /// A closed region retains an obligation in the Pending state.
    UnresolvedObligationOnClosure(String),
    /// An object root is unrelated to the retained source custody digest.
    CustodyRootMismatch,
    /// Attempted to infer mission meaning in the runtime authority plane (AGT-LAYER-001, INV-006).
    ProhibitedMissionMeaningInference,
    /// Attempted to infer physical truth in the runtime authority plane (AGT-LAYER-001, INV-006).
    ProhibitedPhysicalTruthInference,
    /// A capability grant identifier is not registered in the capability registry.
    UnregisteredCapabilityGrant(String),
    /// A root Process region cannot have a parent region.
    RootRegionWithParent(String),
    /// A quiescence proof does not match the closed region.
    ProofRegionMismatch(String),
    /// A quiescence proof was attached to a region that is not closed.
    PrematureQuiescenceProof,
    /// A decoded element count exceeds the remaining bytes or configured structural bound.
    CountBoundExceeded,
    /// An H4 laboratory expansion lacks an anchor to canonical evidence (AGT-H4).
    LaboratoryExpansionMissingAnchor,
    /// An H4 oracle comparison tolerance flag disagrees with discrepancy score and threshold (AGT-H4).
    LaboratoryExpansionToleranceMismatch,
    /// An H4 intermediate artifact tensor shape or byte count is malformed (AGT-H4).
    LaboratoryExpansionShapeMalformed,
    /// Access to H4 laboratory expansion requires qualification or an explicit debugging grant (AGT-H4).
    LaboratoryGrantRequired,
    /// An H4 laboratory expansion handle identifier disagrees with the bound handle (AGT-H4).
    LaboratoryExpansionHandleMismatch,
    /// An H4 laboratory expansion subject identifier disagrees with the bound handle (AGT-H4).
    LaboratoryExpansionSubjectMismatch,
    /// An H4 laboratory expansion anchor disagrees with the bound handle (AGT-H4).
    LaboratoryExpansionAnchorMismatch,
    /// An H4 laboratory expansion contract basis disagrees with the bound handle (AGT-H4).
    LaboratoryExpansionBasisMismatch,
    /// An H4 laboratory expansion retention deadline disagrees with the bound handle (AGT-H4).
    LaboratoryExpansionRetentionMismatch,
    /// An H4 laboratory expansion was presented past its retention deadline (AGT-H4).
    LaboratoryExpansionExpired,
    /// An H4 laboratory expansion subject digest disagrees with the bound handle (AGT-H4).
    LaboratoryExpansionSubjectDigestMismatch,
    /// An H4 laboratory expansion applied transform disagrees with the bound handle (AGT-H4).
    LaboratoryExpansionTransformMismatch,
    /// Privacy class is unrecognized or unauthorized for hydration artifact.
    InvalidPrivacyClass,
    /// Redaction transform is unrecognized or incompatible with the decision artifact kind.
    InvalidRedactionTransform,
    /// Canonical bytes declare more collection elements than the bytes that remain: the buffer
    /// is truncated.
    CanonicalTruncated,
    /// Evidence from a weaker provenance class was reused under a stronger provenance class without fresh live observation (AGENTS.md, Constitution §8.3).
    EvidenceLaunderingDetected,
    /// A prediction cannot claim the `known` knowledge state (PROV-003, AGENTS.md, Constitution §8.2).
    PredictedKnownForbidden,
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
            Self::ArithmeticOverflow => "arithmetic_overflow",
            Self::NonMonotoneUncertaintyNarrowing => "non_monotone_uncertainty_narrowing",
            Self::UnknownClockBasis(_) => "unknown_clock_basis",
            Self::UnknownEntryTag(_) => "unknown_entry_tag",
            Self::EvidenceRequired => "evidence_required",
            Self::SupportingEvidenceRequired => "supporting_evidence_required",
            Self::EvidenceRelationMismatch => "evidence_relation_mismatch",
            Self::EventRevisionMalformed => "event_revision_malformed",
            Self::SensorIntegrityRisk => "sensor_integrity_risk",
            Self::SupersessionMismatch => "supersession_mismatch",
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
            Self::LatestNotResolvable => "latest_not_resolvable",
            Self::RedactionMarkerRequired => "redaction_marker_required",
            Self::KnowledgeStateBasisMismatch => "knowledge_state_basis_mismatch",
            Self::StaleBasisRequired => "stale_basis_required",
            Self::StaleBasisNotOlder => "stale_basis_not_older",
            Self::ReconciliationBasisRequired => "reconciliation_basis_required",
            Self::LegacyReceiptRequiresJournal => "legacy_receipt_requires_journal",
            Self::ReconciliationBranchesIncomplete => "reconciliation_branches_incomplete",
            Self::DerivedLayerAuthorityForbidden => "derived_layer_authority_forbidden",
            Self::DerivedBeliefMissingAnchor => "derived_belief_missing_anchor",
            Self::DerivedBeliefKnownForbidden => "derived_belief_known_forbidden",
            Self::DerivedBeliefAnchorMismatch => "derived_belief_anchor_mismatch",
            Self::DerivedBeliefDuplicateEvidence => "derived_belief_duplicate_evidence",
            Self::DerivedBeliefEvidenceOverlap => "derived_belief_evidence_overlap",
            Self::UnknownAbstractionLayer(_) => "unknown_abstraction_layer",
            Self::ProhibitedEvidencePromotion => "prohibited_evidence_promotion",
            Self::SourceEvidenceMissingAnchor => "source_evidence_missing_anchor",
            Self::SourceEvidenceOmissionRequired => "source_evidence_omission_required",
            Self::SourceEvidenceRetainedWithOmission => "source_evidence_retained_with_omission",
            Self::SourceEvidenceNotRetainedWithCapsuleBytes => {
                "source_evidence_not_retained_with_capsule_bytes"
            }
            Self::SourceEvidenceByteCountMismatch => "source_evidence_byte_count_mismatch",
            Self::SourceEvidenceEmptyStorageHandle => "source_evidence_empty_storage_handle",
            Self::SourceEvidenceStorageHandleTraversal => {
                "source_evidence_storage_handle_traversal"
            }
            Self::SourceEvidenceStorageHandleAbsolutePath => {
                "source_evidence_storage_handle_absolute_path"
            }
            Self::SourceEvidenceStorageHandleEmptySegment => {
                "source_evidence_storage_handle_empty_segment"
            }
            Self::SourceEvidenceStorageHandleOverLength => {
                "source_evidence_storage_handle_over_length"
            }
            Self::SourceEvidenceStorageHandleDisallowedCharacter => {
                "source_evidence_storage_handle_disallowed_character"
            }
            Self::SourceEvidenceStorageHandlePercentEncodingRefused => {
                "source_evidence_storage_handle_percent_encoding_refused"
            }
            Self::SourceEvidenceRawWirePacketsWithCapsule => {
                "source_evidence_raw_wire_packets_with_capsule"
            }
            Self::SourceEvidenceStatementMalformed => "source_evidence_statement_malformed",
            Self::UnknownSourceEvidenceClassification(_) => {
                "unknown_source_evidence_classification"
            }
            Self::UnknownOmissionReason(_) => "unknown_omission_reason",
            Self::UnknownSourceCustodyTag(_) => "unknown_source_custody_tag",
            Self::SourceEvidenceCapsuleRequired => "source_evidence_capsule_required",
            Self::SourceEvidenceWitnessRequired => "source_evidence_witness_required",
            Self::SourceEvidenceWitnessEqualsSourceDigest => {
                "source_evidence_witness_equals_source_digest"
            }
            Self::SourceEvidenceNotRetainedWithWitness => {
                "source_evidence_not_retained_with_witness"
            }
            Self::UnsupportedSourceEvidenceVersion(_) => "source_evidence_unsupported_version",
            Self::UnknownClockBasisName(_) => "unknown_clock_basis_name",
            Self::UnadjudicatedUncertaintyCollapse => "unadjudicated_uncertainty_collapse",
            Self::CompetingHypothesesRequired => "competing_hypotheses_required",
            Self::HypothesisMissingFalsifier => "hypothesis_missing_falsifier",
            Self::HypothesisKnownForbidden => "hypothesis_known_forbidden",
            Self::InvalidSpatialExtent => "invalid_spatial_extent",
            Self::UnboundCapabilityGrant(_) => "unbound_capability_grant",
            Self::OrphanRegion(_) => "orphan_region",
            Self::SelfParentedRegion(_) => "self_parented_region",
            Self::MissingCancellationReason => "missing_cancellation_reason",
            Self::MissingDrainRecord => "missing_drain_record",
            Self::DuplicateGrant(_) => "duplicate_grant",
            Self::DuplicateObligation(_) => "duplicate_obligation",
            Self::IndeterminateObligationOnClosure(_) => "indeterminate_obligation_on_closure",
            Self::UnresolvedObligationOnClosure(_) => "unresolved_obligation_on_closure",
            Self::CustodyRootMismatch => "custody_root_mismatch",
            Self::ProhibitedMissionMeaningInference => "prohibited_mission_meaning_inference",
            Self::ProhibitedPhysicalTruthInference => "prohibited_physical_truth_inference",
            Self::UnregisteredCapabilityGrant(_) => "unregistered_capability_grant",
            Self::RootRegionWithParent(_) => "root_region_with_parent",
            Self::ProofRegionMismatch(_) => "proof_region_mismatch",
            Self::PrematureQuiescenceProof => "premature_quiescence_proof",
            Self::CountBoundExceeded => "count_bound_exceeded",
            Self::LaboratoryExpansionMissingAnchor => "laboratory_expansion_missing_anchor",
            Self::LaboratoryExpansionToleranceMismatch => "laboratory_expansion_tolerance_mismatch",
            Self::LaboratoryExpansionShapeMalformed => "laboratory_expansion_shape_malformed",
            Self::LaboratoryGrantRequired => "laboratory_grant_required",
            Self::LaboratoryExpansionHandleMismatch => "laboratory_expansion_handle_mismatch",
            Self::LaboratoryExpansionSubjectMismatch => "laboratory_expansion_subject_mismatch",
            Self::LaboratoryExpansionAnchorMismatch => "laboratory_expansion_anchor_mismatch",
            Self::LaboratoryExpansionBasisMismatch => "laboratory_expansion_basis_mismatch",
            Self::LaboratoryExpansionRetentionMismatch => "laboratory_expansion_retention_mismatch",
            Self::LaboratoryExpansionExpired => "laboratory_expansion_expired",
            Self::LaboratoryExpansionSubjectDigestMismatch => {
                "laboratory_expansion_subject_digest_mismatch"
            }
            Self::LaboratoryExpansionTransformMismatch => "laboratory_expansion_transform_mismatch",
            Self::InvalidPrivacyClass => "invalid_privacy_class",
            Self::InvalidRedactionTransform => "invalid_redaction_transform",
            Self::CanonicalTruncated => "canonical_truncated",
            Self::EvidenceLaunderingDetected => "evidence_laundering_detected",
            Self::PredictedKnownForbidden => "predicted_known_forbidden",
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
