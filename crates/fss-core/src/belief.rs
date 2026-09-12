#![forbid(unsafe_code)]
//! Deterministic belief interval and first-class contradiction types (FSS-082).
//!
//! Provides:
//! - Exact integer fixed-point `BeliefInterval` with micro-probability bounds ($[0, 1\_000\_000]$),
//!   where $L > U$ is a typed error and NEVER silently clamped.
//! - First-class `Contradiction` capturing conflicting evidence roots, independent failure domains,
//!   and the unresolved possible worlds it keeps alive, with orthogonal epistemic coordinates.

use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::contract::{
    ContractError, HypothesisDisposition, KnowledgeState, ProvenanceClass, RuntimeOutcome,
};
use crate::digest::ContentDigest;
use crate::ids::CalibrationGeneration;
use crate::time::TimestampNs;
use core::fmt;
use std::collections::BTreeSet;

/// Parts-per-million denominator for micro-probability arithmetic (1.0 = 1_000_000).
pub const MICRO_DENOMINATOR: u64 = 1_000_000;

/// Minimum conflicting evidence roots required to establish a contradiction.
pub const MIN_CONFLICTING_EVIDENCE: usize = 2;

/// Maximum conflicting evidence roots retained in one contradiction.
pub const MAX_CONFLICTING_EVIDENCE: usize = 64;

/// Minimum independent failure domains required to establish a physical contradiction.
pub const MIN_FAILURE_DOMAINS: usize = 2;

/// Maximum independent failure domains tracked in one contradiction.
pub const MAX_FAILURE_DOMAINS: usize = 32;

/// Minimum unresolved possible worlds kept alive by a contradiction.
pub const MIN_UNRESOLVED_WORLDS: usize = 1;

/// Maximum unresolved possible worlds kept alive by one contradiction.
pub const MAX_UNRESOLVED_WORLDS: usize = 64;

/// Maximum length of a contradiction identifier in bytes.
pub const MAX_CONTRADICTION_ID_LEN: usize = 128;

/// Maximum length of a contradiction statement in bytes.
pub const MAX_STATEMENT_LEN: usize = 512;

/// Maximum length of a claim identifier in bytes.
pub const MAX_CLAIM_ID_LEN: usize = 128;

/// Maximum length of a failure domain string in bytes.
pub const MAX_FAILURE_DOMAIN_LEN: usize = 128;

/// Maximum length of an unresolved world identifier in bytes.
pub const MAX_WORLD_ID_LEN: usize = 128;

/// Canonical digest domain for belief intervals.
pub const BELIEF_INTERVAL_DOMAIN: &str = "fss.belief_interval.v1";

/// Canonical digest domain for first-class contradictions.
pub const CONTRADICTION_DOMAIN: &str = "fss.contradiction.v1";

/// Errors occurring during belief interval arithmetic or contradiction verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BeliefError {
    /// Interval has lower bound strictly greater than upper bound (never clamped).
    InvertedInterval {
        /// Attempted lower micro-probability.
        lower_micro: u64,
        /// Attempted upper micro-probability.
        upper_micro: u64,
    },
    /// Intersecting intervals are disjoint, producing a contradiction.
    DisjointIntervals {
        /// First interval lower bound.
        lower_a: u64,
        /// First interval upper bound.
        upper_a: u64,
        /// Second interval lower bound.
        lower_b: u64,
        /// Second interval upper bound.
        upper_b: u64,
    },
    /// An integer bound exceeded the permissible range.
    OutOfRange {
        /// Name of the out-of-range field.
        field: &'static str,
        /// Actual observed value.
        actual: u64,
        /// Maximum permissible value.
        limit: u64,
    },
    /// Insufficient evidence roots to support contradiction claim.
    InsufficientEvidenceRoots {
        /// Actual count of evidence roots.
        actual: usize,
        /// Minimum required count.
        min_required: usize,
    },
    /// Insufficient independent failure domains to support physical contradiction.
    InsufficientFailureDomains {
        /// Actual count of independent failure domains.
        actual: usize,
        /// Minimum required count.
        min_required: usize,
    },
    /// Contradiction does not keep any unresolved worlds alive.
    EmptyUnresolvedWorlds,
    /// A collection or string length exceeded its hard bound.
    OverLimitLength {
        /// Name of the constrained field.
        field: &'static str,
        /// Actual length.
        actual: usize,
        /// Hard limit.
        limit: usize,
    },
    /// A required string field was empty.
    EmptyField {
        /// Name of the empty field.
        field: &'static str,
    },
    /// Intersecting intervals belong to conflicting calibration generations.
    CalibrationMismatch {
        /// Expected calibration generation.
        expected: String,
        /// Found calibration generation.
        found: String,
    },
    /// Float value is NaN, infinite, negative, or greater than 1.0.
    InvalidProbability(u64),
    /// Underflow or missing bytes during canonical decoding.
    Truncated {
        /// Minimum expected bytes.
        expected_min: usize,
        /// Actual available bytes.
        actual: usize,
    },
    /// Trailing bytes left unconsumed after canonical decoding.
    TrailingBytes {
        /// Count of unparsed trailing bytes.
        count: usize,
    },
    /// Non-canonical encoding or invalid discriminant encountered.
    NonCanonicalEncoding {
        /// Detail explanation.
        detail: String,
    },
    /// Core contract violation.
    Contract(ContractError),
}

impl fmt::Display for BeliefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvertedInterval {
                lower_micro,
                upper_micro,
            } => {
                write!(
                    f,
                    "inverted belief interval: lower ({lower_micro}) > upper ({upper_micro})"
                )
            }
            Self::DisjointIntervals {
                lower_a,
                upper_a,
                lower_b,
                upper_b,
            } => {
                write!(
                    f,
                    "disjoint belief intervals contradict: [{lower_a}, {upper_a}] vs [{lower_b}, {upper_b}]"
                )
            }
            Self::OutOfRange {
                field,
                actual,
                limit,
            } => {
                write!(f, "{field} value {actual} exceeds limit {limit}")
            }
            Self::InsufficientEvidenceRoots {
                actual,
                min_required,
            } => {
                write!(
                    f,
                    "insufficient conflicting evidence roots: {actual} < {min_required}"
                )
            }
            Self::InsufficientFailureDomains {
                actual,
                min_required,
            } => {
                write!(
                    f,
                    "insufficient failure domains for contradiction: {actual} < {min_required}"
                )
            }
            Self::EmptyUnresolvedWorlds => {
                write!(
                    f,
                    "contradiction must keep at least one unresolved possible world alive"
                )
            }
            Self::OverLimitLength {
                field,
                actual,
                limit,
            } => {
                write!(f, "{field} length {actual} exceeds hard bound {limit}")
            }
            Self::EmptyField { field } => {
                write!(f, "{field} must not be empty")
            }
            Self::CalibrationMismatch { expected, found } => {
                write!(
                    f,
                    "calibration generation mismatch: expected '{expected}', found '{found}'"
                )
            }
            Self::InvalidProbability(bits) => {
                write!(
                    f,
                    "invalid float probability bit representation: {bits:#018x}"
                )
            }
            Self::Truncated {
                expected_min,
                actual,
            } => {
                write!(
                    f,
                    "truncated canonical encoding: expected {expected_min} bytes, found {actual}"
                )
            }
            Self::TrailingBytes { count } => {
                write!(
                    f,
                    "non-canonical encoding has {count} trailing unparsed bytes"
                )
            }
            Self::NonCanonicalEncoding { detail } => {
                write!(f, "non-canonical encoding: {detail}")
            }
            Self::Contract(err) => write!(f, "contract error: {err}"),
        }
    }
}

impl std::error::Error for BeliefError {}

impl From<ContractError> for BeliefError {
    fn from(err: ContractError) -> Self {
        Self::Contract(err)
    }
}

impl From<BeliefError> for ContractError {
    fn from(err: BeliefError) -> Self {
        match err {
            BeliefError::InsufficientEvidenceRoots { .. } => Self::EvidenceRequired,
            BeliefError::InsufficientFailureDomains { .. } => Self::CorroborationRequired,
            BeliefError::OverLimitLength { field, .. } => match field {
                "conflicting_evidence" => Self::EvidenceRequired,
                "failure_domains" | "failure_domains[]" => Self::CorroborationRequired,
                _ => Self::InvalidIdentifier,
            },
            BeliefError::EmptyField { .. } => Self::InvalidIdentifier,
            BeliefError::EmptyUnresolvedWorlds => Self::InvalidIdentifier,
            BeliefError::InvertedInterval { .. } | BeliefError::InvalidProbability(_) => {
                Self::InvalidProbabilityInterval
            }
            BeliefError::DisjointIntervals { .. } => Self::InvalidProbabilityInterval,
            BeliefError::CalibrationMismatch { .. } => Self::GenerationConflict,
            BeliefError::OutOfRange { .. } => Self::InvalidIdentifier,
            BeliefError::NonCanonicalEncoding { .. }
            | BeliefError::TrailingBytes { .. }
            | BeliefError::Truncated { .. } => Self::NonCanonicalOrdering,
            BeliefError::Contract(c) => c,
        }
    }
}

/// Exact integer fixed-point belief interval $[L, U] \subseteq [0, 1]$ in micro-probabilities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeliefInterval {
    lower_micro: u64,
    upper_micro: u64,
    calibration_generation: Option<CalibrationGeneration>,
}

impl BeliefInterval {
    /// Constructs an uncalibrated belief interval $[L, U]$ in parts-per-million.
    ///
    /// Fails closed if $L > U$ or $U > 1\_000\_000$. Never silently clamps.
    pub fn new(lower_micro: u64, upper_micro: u64) -> Result<Self, BeliefError> {
        Self::with_calibration_opt(lower_micro, upper_micro, None)
    }

    /// Constructs a point probability interval $[P, P]$.
    pub fn point(micro: u64) -> Result<Self, BeliefError> {
        Self::new(micro, micro)
    }

    /// Constructs a calibrated belief interval $[L, U]$ bound to a calibration generation.
    pub fn with_calibration(
        lower_micro: u64,
        upper_micro: u64,
        calibration: CalibrationGeneration,
    ) -> Result<Self, BeliefError> {
        Self::with_calibration_opt(lower_micro, upper_micro, Some(calibration))
    }

    /// Internal constructor validating all invariants.
    fn with_calibration_opt(
        lower_micro: u64,
        upper_micro: u64,
        calibration_generation: Option<CalibrationGeneration>,
    ) -> Result<Self, BeliefError> {
        if lower_micro > upper_micro {
            return Err(BeliefError::InvertedInterval {
                lower_micro,
                upper_micro,
            });
        }
        if lower_micro > MICRO_DENOMINATOR {
            return Err(BeliefError::OutOfRange {
                field: "lower_micro",
                actual: lower_micro,
                limit: MICRO_DENOMINATOR,
            });
        }
        if upper_micro > MICRO_DENOMINATOR {
            return Err(BeliefError::OutOfRange {
                field: "upper_micro",
                actual: upper_micro,
                limit: MICRO_DENOMINATOR,
            });
        }
        Ok(Self {
            lower_micro,
            upper_micro,
            calibration_generation,
        })
    }

    /// Constructs a belief interval from IEEE 754 f64 probabilities using standard rounding.
    pub fn from_f64(lower: f64, upper: f64) -> Result<Self, BeliefError> {
        let (lower_micro, upper_micro) = convert_f64_pair_to_micros(lower, upper)?;
        Self::new(lower_micro, upper_micro)
    }

    /// Constructs a calibrated belief interval from IEEE 754 f64 probabilities.
    pub fn from_f64_with_calibration(
        lower: f64,
        upper: f64,
        calibration: CalibrationGeneration,
    ) -> Result<Self, BeliefError> {
        let (lower_micro, upper_micro) = convert_f64_pair_to_micros(lower, upper)?;
        Self::with_calibration(lower_micro, upper_micro, calibration)
    }

    /// Lower probability bound in micro-units ($0..=1\_000\_000$).
    #[must_use]
    pub const fn lower_micro(&self) -> u64 {
        self.lower_micro
    }

    /// Upper probability bound in micro-units ($0..=1\_000\_000$).
    #[must_use]
    pub const fn upper_micro(&self) -> u64 {
        self.upper_micro
    }

    /// Lower bound projected as f64 in $[0.0, 1.0]$.
    #[must_use]
    pub fn lower_f64(&self) -> f64 {
        (self.lower_micro as f64) / (MICRO_DENOMINATOR as f64)
    }

    /// Upper bound projected as f64 in $[0.0, 1.0]$.
    #[must_use]
    pub fn upper_f64(&self) -> f64 {
        (self.upper_micro as f64) / (MICRO_DENOMINATOR as f64)
    }

    /// Epistemic interval width $U - L$ in micro-units.
    #[must_use]
    pub const fn width_micro(&self) -> u64 {
        self.upper_micro - self.lower_micro
    }

    /// Epistemic interval width $U - L$ projected as f64.
    #[must_use]
    pub fn width_f64(&self) -> f64 {
        (self.width_micro() as f64) / (MICRO_DENOMINATOR as f64)
    }

    /// Associated metric calibration generation, if calibrated.
    #[must_use]
    pub const fn calibration_generation(&self) -> Option<&CalibrationGeneration> {
        self.calibration_generation.as_ref()
    }

    /// Returns true if this interval represents a deterministic sharp point probability ($L == U$).
    #[must_use]
    pub const fn is_point(&self) -> bool {
        self.lower_micro == self.upper_micro
    }

    /// Returns true if this interval represents total epistemic ignorance $[0, 1]$.
    #[must_use]
    pub const fn is_total_ignorance(&self) -> bool {
        self.lower_micro == 0 && self.upper_micro == MICRO_DENOMINATOR
    }

    /// Returns true if the micro-probability is contained within this interval.
    #[must_use]
    pub const fn contains_probability(&self, p_micro: u64) -> bool {
        p_micro >= self.lower_micro && p_micro <= self.upper_micro
    }

    /// Returns true if this interval overlaps with another interval ($\max(L_1, L_2) \le \min(U_1, U_2)$).
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.lower_micro.max(other.lower_micro) <= self.upper_micro.min(other.upper_micro)
    }

    /// Returns true if two intervals are disjoint, constituting a probabilistic contradiction.
    #[must_use]
    pub fn is_contradiction_with(&self, other: &Self) -> bool {
        !self.overlaps(other)
    }

    /// Computes the intersection (conjunctive fusion) of two belief intervals.
    ///
    /// Fails closed with `BeliefError::DisjointIntervals` if the intervals are disjoint.
    /// NEVER clamps an invalid or contradictory intersection.
    pub fn intersect(&self, other: &Self) -> Result<Self, BeliefError> {
        let cal = reconcile_calibrations(
            self.calibration_generation(),
            other.calibration_generation(),
        )?;
        let fused_lower = self.lower_micro.max(other.lower_micro);
        let fused_upper = self.upper_micro.min(other.upper_micro);

        if fused_lower > fused_upper {
            return Err(BeliefError::DisjointIntervals {
                lower_a: self.lower_micro,
                upper_a: self.upper_micro,
                lower_b: other.lower_micro,
                upper_b: other.upper_micro,
            });
        }

        Self::with_calibration_opt(fused_lower, fused_upper, cal)
    }

    /// Computes the convex span (disjunctive hull) $[\min(L_1, L_2), \max(U_1, U_2)]$.
    pub fn span(&self, other: &Self) -> Result<Self, BeliefError> {
        let cal = reconcile_calibrations(
            self.calibration_generation(),
            other.calibration_generation(),
        )?;
        let span_lower = self.lower_micro.min(other.lower_micro);
        let span_upper = self.upper_micro.max(other.upper_micro);
        Self::with_calibration_opt(span_lower, span_upper, cal)
    }

    /// Computes the negation / complement interval $[1 - U, 1 - L]$.
    #[must_use]
    pub fn complement(&self) -> Self {
        Self {
            lower_micro: MICRO_DENOMINATOR - self.upper_micro,
            upper_micro: MICRO_DENOMINATOR - self.lower_micro,
            calibration_generation: self.calibration_generation.clone(),
        }
    }

    /// Parse from canonical serialized bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        let mut decoder = CanonicalDecoder::new(bytes);
        let val = Self::decode_canonical(&mut decoder)?;
        decoder.ensure_finished()?;
        Ok(val)
    }

    /// Serialize to canonical bytes.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        encoder.finish()
    }

    /// Computes the canonical content digest for this belief interval.
    #[must_use]
    pub fn interval_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }
}

impl CanonicalEncode for BeliefInterval {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(BELIEF_INTERVAL_DOMAIN);
        encoder.u64(self.lower_micro);
        encoder.u64(self.upper_micro);
        match &self.calibration_generation {
            Some(cal) => {
                encoder.bool(true);
                encoder.text(cal.as_str());
            }
            None => {
                encoder.bool(false);
            }
        }
    }
}

impl CanonicalDecode for BeliefInterval {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let domain = decoder.text()?;
        if domain != BELIEF_INTERVAL_DOMAIN {
            return Err(ContractError::InvalidIdentifier);
        }
        let lower_micro = decoder.u64()?;
        let upper_micro = decoder.u64()?;
        let has_cal = decoder.bool()?;
        let calibration_generation = if has_cal {
            let cal_str = decoder.text()?;
            Some(CalibrationGeneration::parse(cal_str.to_string())?)
        } else {
            None
        };
        Self::with_calibration_opt(lower_micro, upper_micro, calibration_generation)
            .map_err(|_| ContractError::InvalidProbabilityInterval)
    }
}

/// Parameters for creating a first-class `Contradiction`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContradictionParams {
    /// Stable contradiction identifier.
    pub contradiction_id: String,
    /// Conflicting evidence roots (at least 2 required).
    pub conflicting_evidence: BTreeSet<ContentDigest>,
    /// Independent failure domains establishing the physical conflict (at least 2 required).
    pub failure_domains: BTreeSet<String>,
    /// Unresolved possible worlds kept alive by this contradiction (at least 1 required).
    pub unresolved_worlds: BTreeSet<String>,
    /// Subject claim or hypothesis identifier being contradicted, if targeted.
    pub claim_id: Option<String>,
    /// Human/agent-facing description of the contradiction.
    pub statement: String,
    /// Belief interval context associated with the conflict, if quantitative.
    pub belief_interval: Option<BeliefInterval>,
    /// Timestamp when contradiction was first recognized.
    pub created_at: TimestampNs,
    /// Epistemic knowledge state (orthogonal coordinate).
    pub knowledge_state: KnowledgeState,
    /// Provenance classification (orthogonal coordinate).
    pub provenance: ProvenanceClass,
    /// Investigation hypothesis disposition (orthogonal coordinate).
    pub disposition: HypothesisDisposition,
    /// Runtime completion outcome (orthogonal coordinate).
    pub outcome: RuntimeOutcome,
}

/// A first-class typed contradiction preserving physical conflict, evidence roots,
/// independent failure domains, and the unresolved possible worlds it keeps alive.
///
/// It must never be flattened into low confidence or omitted from decision state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Contradiction {
    contradiction_id: String,
    conflicting_evidence: BTreeSet<ContentDigest>,
    failure_domains: BTreeSet<String>,
    unresolved_worlds: BTreeSet<String>,
    claim_id: Option<String>,
    statement: String,
    belief_interval: Option<BeliefInterval>,
    created_at: TimestampNs,
    knowledge_state: KnowledgeState,
    provenance: ProvenanceClass,
    disposition: HypothesisDisposition,
    outcome: RuntimeOutcome,
}

impl Contradiction {
    /// Creates a verified first-class contradiction from parameters.
    pub fn new(params: ContradictionParams) -> Result<Self, BeliefError> {
        let contradiction = Self {
            contradiction_id: params.contradiction_id,
            conflicting_evidence: params.conflicting_evidence,
            failure_domains: params.failure_domains,
            unresolved_worlds: params.unresolved_worlds,
            claim_id: params.claim_id,
            statement: params.statement,
            belief_interval: params.belief_interval,
            created_at: params.created_at,
            knowledge_state: params.knowledge_state,
            provenance: params.provenance,
            disposition: params.disposition,
            outcome: params.outcome,
        };
        contradiction.verify()?;
        Ok(contradiction)
    }

    /// Validates all load-bearing invariants and hard bounds.
    pub fn verify(&self) -> Result<(), BeliefError> {
        if self.contradiction_id.is_empty() {
            return Err(BeliefError::EmptyField {
                field: "contradiction_id",
            });
        }
        if self.contradiction_id.len() > MAX_CONTRADICTION_ID_LEN {
            return Err(BeliefError::OverLimitLength {
                field: "contradiction_id",
                actual: self.contradiction_id.len(),
                limit: MAX_CONTRADICTION_ID_LEN,
            });
        }

        if self.statement.is_empty() {
            return Err(BeliefError::EmptyField { field: "statement" });
        }
        if self.statement.len() > MAX_STATEMENT_LEN {
            return Err(BeliefError::OverLimitLength {
                field: "statement",
                actual: self.statement.len(),
                limit: MAX_STATEMENT_LEN,
            });
        }

        if let Some(claim) = &self.claim_id {
            if claim.is_empty() {
                return Err(BeliefError::EmptyField { field: "claim_id" });
            }
            if claim.len() > MAX_CLAIM_ID_LEN {
                return Err(BeliefError::OverLimitLength {
                    field: "claim_id",
                    actual: claim.len(),
                    limit: MAX_CLAIM_ID_LEN,
                });
            }
        }

        if self.conflicting_evidence.len() < MIN_CONFLICTING_EVIDENCE {
            return Err(BeliefError::InsufficientEvidenceRoots {
                actual: self.conflicting_evidence.len(),
                min_required: MIN_CONFLICTING_EVIDENCE,
            });
        }
        if self.conflicting_evidence.len() > MAX_CONFLICTING_EVIDENCE {
            return Err(BeliefError::OverLimitLength {
                field: "conflicting_evidence",
                actual: self.conflicting_evidence.len(),
                limit: MAX_CONFLICTING_EVIDENCE,
            });
        }

        if self.failure_domains.len() < MIN_FAILURE_DOMAINS {
            return Err(BeliefError::InsufficientFailureDomains {
                actual: self.failure_domains.len(),
                min_required: MIN_FAILURE_DOMAINS,
            });
        }
        if self.failure_domains.len() > MAX_FAILURE_DOMAINS {
            return Err(BeliefError::OverLimitLength {
                field: "failure_domains",
                actual: self.failure_domains.len(),
                limit: MAX_FAILURE_DOMAINS,
            });
        }
        for domain in &self.failure_domains {
            if domain.is_empty() {
                return Err(BeliefError::EmptyField {
                    field: "failure_domains[]",
                });
            }
            if domain.len() > MAX_FAILURE_DOMAIN_LEN {
                return Err(BeliefError::OverLimitLength {
                    field: "failure_domains[]",
                    actual: domain.len(),
                    limit: MAX_FAILURE_DOMAIN_LEN,
                });
            }
        }

        if self.unresolved_worlds.len() < MIN_UNRESOLVED_WORLDS {
            return Err(BeliefError::EmptyUnresolvedWorlds);
        }
        if self.unresolved_worlds.len() > MAX_UNRESOLVED_WORLDS {
            return Err(BeliefError::OverLimitLength {
                field: "unresolved_worlds",
                actual: self.unresolved_worlds.len(),
                limit: MAX_UNRESOLVED_WORLDS,
            });
        }
        for world in &self.unresolved_worlds {
            if world.is_empty() {
                return Err(BeliefError::EmptyField {
                    field: "unresolved_worlds[]",
                });
            }
            if world.len() > MAX_WORLD_ID_LEN {
                return Err(BeliefError::OverLimitLength {
                    field: "unresolved_worlds[]",
                    actual: world.len(),
                    limit: MAX_WORLD_ID_LEN,
                });
            }
        }

        Ok(())
    }

    /// Stable contradiction identifier.
    #[must_use]
    pub fn contradiction_id(&self) -> &str {
        &self.contradiction_id
    }

    /// Conflicting evidence roots.
    #[must_use]
    pub const fn conflicting_evidence(&self) -> &BTreeSet<ContentDigest> {
        &self.conflicting_evidence
    }

    /// Independent failure domains from which the conflict arose.
    #[must_use]
    pub const fn failure_domains(&self) -> &BTreeSet<String> {
        &self.failure_domains
    }

    /// Unresolved possible worlds kept alive by this contradiction.
    #[must_use]
    pub const fn unresolved_worlds(&self) -> &BTreeSet<String> {
        &self.unresolved_worlds
    }

    /// Subject claim identifier being contradicted, if targeted.
    #[must_use]
    pub fn claim_id(&self) -> Option<&str> {
        self.claim_id.as_deref()
    }

    /// Descriptive explanation of the contradiction.
    #[must_use]
    pub fn statement(&self) -> &str {
        &self.statement
    }

    /// Associated belief interval context, if quantitative.
    #[must_use]
    pub const fn belief_interval(&self) -> Option<&BeliefInterval> {
        self.belief_interval.as_ref()
    }

    /// Timestamp of initial contradiction observation.
    #[must_use]
    pub const fn created_at(&self) -> TimestampNs {
        self.created_at
    }

    /// Epistemic knowledge state (orthogonal coordinate).
    #[must_use]
    pub const fn knowledge_state(&self) -> KnowledgeState {
        self.knowledge_state
    }

    /// Epistemic provenance class (orthogonal coordinate).
    #[must_use]
    pub const fn provenance(&self) -> ProvenanceClass {
        self.provenance
    }

    /// Investigation hypothesis disposition (orthogonal coordinate).
    #[must_use]
    pub const fn disposition(&self) -> HypothesisDisposition {
        self.disposition
    }

    /// Runtime completion outcome (orthogonal coordinate).
    #[must_use]
    pub const fn outcome(&self) -> RuntimeOutcome {
        self.outcome
    }

    /// Returns true if this contradiction actively constrains reasoning or action.
    #[must_use]
    pub fn is_active(&self) -> bool {
        if matches!(
            self.disposition,
            HypothesisDisposition::Refuted
                | HypothesisDisposition::Resolved
                | HypothesisDisposition::Superseded
        ) {
            return false;
        }

        self.knowledge_state == KnowledgeState::Conflicted
            || self.knowledge_state == KnowledgeState::Known
            || self.knowledge_state == KnowledgeState::Indeterminate
            || self.disposition == HypothesisDisposition::Live
            || self.disposition == HypothesisDisposition::Supported
            || self.outcome == RuntimeOutcome::Indeterminate
    }

    /// Parse from canonical serialized bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        let mut decoder = CanonicalDecoder::new(bytes);
        let val = Self::decode_canonical(&mut decoder)?;
        decoder.ensure_finished()?;
        Ok(val)
    }

    /// Serialize to canonical bytes.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        encoder.finish()
    }

    /// Computes canonical content digest for this contradiction.
    #[must_use]
    pub fn contradiction_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }
}

impl CanonicalEncode for Contradiction {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(CONTRADICTION_DOMAIN);
        encoder.text(&self.contradiction_id);

        encoder.u64(self.conflicting_evidence.len() as u64);
        for digest in &self.conflicting_evidence {
            encoder.digest(*digest);
        }

        encoder.u64(self.failure_domains.len() as u64);
        for domain in &self.failure_domains {
            encoder.text(domain);
        }

        encoder.u64(self.unresolved_worlds.len() as u64);
        for world in &self.unresolved_worlds {
            encoder.text(world);
        }

        match &self.claim_id {
            Some(claim) => {
                encoder.bool(true);
                encoder.text(claim);
            }
            None => {
                encoder.bool(false);
            }
        }

        encoder.text(&self.statement);

        match &self.belief_interval {
            Some(interval) => {
                encoder.bool(true);
                interval.encode_canonical(encoder);
            }
            None => {
                encoder.bool(false);
            }
        }

        self.created_at.encode_canonical(encoder);
        encoder.text(self.knowledge_state.as_str());
        encoder.u8(provenance_to_code(self.provenance));
        encoder.u8(disposition_to_code(self.disposition));
        encoder.u8(outcome_to_code(self.outcome));
    }
}

impl CanonicalDecode for Contradiction {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let domain = decoder.text()?;
        if domain != CONTRADICTION_DOMAIN {
            return Err(ContractError::InvalidIdentifier);
        }
        let contradiction_id = decoder.text()?.to_string();

        let raw_evidence_count = decoder.u64()?;
        if raw_evidence_count < MIN_CONFLICTING_EVIDENCE as u64
            || raw_evidence_count > MAX_CONFLICTING_EVIDENCE as u64
        {
            return Err(ContractError::EvidenceRequired);
        }
        let evidence_count =
            usize::try_from(raw_evidence_count).map_err(|_| ContractError::EvidenceRequired)?;
        let mut conflicting_evidence = BTreeSet::new();
        let mut prev_digest: Option<ContentDigest> = None;
        for _ in 0..evidence_count {
            let digest = decoder.digest()?;
            if prev_digest.as_ref().is_some_and(|prev| prev >= &digest) {
                return Err(ContractError::NonCanonicalOrdering);
            }
            prev_digest = Some(digest);
            conflicting_evidence.insert(digest);
        }

        let raw_domains_count = decoder.u64()?;
        if raw_domains_count < MIN_FAILURE_DOMAINS as u64
            || raw_domains_count > MAX_FAILURE_DOMAINS as u64
        {
            return Err(ContractError::CorroborationRequired);
        }
        let domains_count =
            usize::try_from(raw_domains_count).map_err(|_| ContractError::CorroborationRequired)?;
        let mut failure_domains = BTreeSet::new();
        let mut prev_domain: Option<String> = None;
        for _ in 0..domains_count {
            let domain = decoder.text()?.to_string();
            if prev_domain.as_ref().is_some_and(|prev| prev >= &domain) {
                return Err(ContractError::NonCanonicalOrdering);
            }
            prev_domain = Some(domain.clone());
            failure_domains.insert(domain);
        }

        let raw_worlds_count = decoder.u64()?;
        if raw_worlds_count < MIN_UNRESOLVED_WORLDS as u64
            || raw_worlds_count > MAX_UNRESOLVED_WORLDS as u64
        {
            return Err(ContractError::InvalidIdentifier);
        }
        let worlds_count =
            usize::try_from(raw_worlds_count).map_err(|_| ContractError::InvalidIdentifier)?;
        let mut unresolved_worlds = BTreeSet::new();
        let mut prev_world: Option<String> = None;
        for _ in 0..worlds_count {
            let world = decoder.text()?.to_string();
            if prev_world.as_ref().is_some_and(|prev| prev >= &world) {
                return Err(ContractError::NonCanonicalOrdering);
            }
            prev_world = Some(world.clone());
            unresolved_worlds.insert(world);
        }

        let has_claim = decoder.bool()?;
        let claim_id = if has_claim {
            Some(decoder.text()?.to_string())
        } else {
            None
        };

        let statement = decoder.text()?.to_string();

        let has_interval = decoder.bool()?;
        let belief_interval = if has_interval {
            Some(BeliefInterval::decode_canonical(decoder)?)
        } else {
            None
        };

        let created_at = TimestampNs::decode_canonical(decoder)?;
        let state_str = decoder.text()?;
        let knowledge_state = KnowledgeState::from_name(state_str)?;
        let provenance = provenance_from_code(decoder.u8()?)?;
        let disposition = disposition_from_code(decoder.u8()?)?;
        let outcome = outcome_from_code(decoder.u8()?)?;

        let contradiction = Self {
            contradiction_id,
            conflicting_evidence,
            failure_domains,
            unresolved_worlds,
            claim_id,
            statement,
            belief_interval,
            created_at,
            knowledge_state,
            provenance,
            disposition,
            outcome,
        };

        contradiction.verify()?;
        Ok(contradiction)
    }
}

// Helpers

fn convert_f64_pair_to_micros(lower: f64, upper: f64) -> Result<(u64, u64), BeliefError> {
    if !lower.is_finite() || lower < 0.0 || lower > 1.0 {
        return Err(BeliefError::InvalidProbability(lower.to_bits()));
    }
    if !upper.is_finite() || upper < 0.0 || upper > 1.0 {
        return Err(BeliefError::InvalidProbability(upper.to_bits()));
    }
    let lower_micro = (lower * (MICRO_DENOMINATOR as f64)).round() as u64;
    let upper_micro = (upper * (MICRO_DENOMINATOR as f64)).round() as u64;
    if lower > upper || lower_micro > upper_micro {
        return Err(BeliefError::InvertedInterval {
            lower_micro,
            upper_micro,
        });
    }
    Ok((lower_micro, upper_micro))
}

fn reconcile_calibrations(
    a: Option<&CalibrationGeneration>,
    b: Option<&CalibrationGeneration>,
) -> Result<Option<CalibrationGeneration>, BeliefError> {
    match (a, b) {
        (Some(c1), Some(c2)) => {
            if c1 == c2 {
                Ok(Some(c1.clone()))
            } else {
                Err(BeliefError::CalibrationMismatch {
                    expected: c1.as_str().to_string(),
                    found: c2.as_str().to_string(),
                })
            }
        }
        _ => Ok(None),
    }
}

fn provenance_to_code(val: ProvenanceClass) -> u8 {
    match val {
        ProvenanceClass::Observed => 1,
        ProvenanceClass::Derived => 2,
        ProvenanceClass::Predicted => 3,
        ProvenanceClass::Remembered => 4,
        ProvenanceClass::OperatorAsserted => 5,
        ProvenanceClass::VendorClaimed => 6,
        ProvenanceClass::Policy => 7,
    }
}

fn provenance_from_code(code: u8) -> Result<ProvenanceClass, ContractError> {
    match code {
        1 => Ok(ProvenanceClass::Observed),
        2 => Ok(ProvenanceClass::Derived),
        3 => Ok(ProvenanceClass::Predicted),
        4 => Ok(ProvenanceClass::Remembered),
        5 => Ok(ProvenanceClass::OperatorAsserted),
        6 => Ok(ProvenanceClass::VendorClaimed),
        7 => Ok(ProvenanceClass::Policy),
        _ => Err(ContractError::NonCanonicalOrdering),
    }
}

fn disposition_to_code(val: HypothesisDisposition) -> u8 {
    match val {
        HypothesisDisposition::Live => 1,
        HypothesisDisposition::Supported => 2,
        HypothesisDisposition::Disfavored => 3,
        HypothesisDisposition::Refuted => 4,
        HypothesisDisposition::Resolved => 5,
        HypothesisDisposition::Superseded => 6,
    }
}

fn disposition_from_code(code: u8) -> Result<HypothesisDisposition, ContractError> {
    match code {
        1 => Ok(HypothesisDisposition::Live),
        2 => Ok(HypothesisDisposition::Supported),
        3 => Ok(HypothesisDisposition::Disfavored),
        4 => Ok(HypothesisDisposition::Refuted),
        5 => Ok(HypothesisDisposition::Resolved),
        6 => Ok(HypothesisDisposition::Superseded),
        _ => Err(ContractError::NonCanonicalOrdering),
    }
}

fn outcome_to_code(val: RuntimeOutcome) -> u8 {
    match val {
        RuntimeOutcome::Ok => 1,
        RuntimeOutcome::Error => 2,
        RuntimeOutcome::Cancelled => 3,
        RuntimeOutcome::Panicked => 4,
        RuntimeOutcome::Partial => 5,
        RuntimeOutcome::Indeterminate => 6,
        RuntimeOutcome::Refused => 7,
    }
}

fn outcome_from_code(code: u8) -> Result<RuntimeOutcome, ContractError> {
    match code {
        1 => Ok(RuntimeOutcome::Ok),
        2 => Ok(RuntimeOutcome::Error),
        3 => Ok(RuntimeOutcome::Cancelled),
        4 => Ok(RuntimeOutcome::Panicked),
        5 => Ok(RuntimeOutcome::Partial),
        6 => Ok(RuntimeOutcome::Indeterminate),
        7 => Ok(RuntimeOutcome::Refused),
        _ => Err(ContractError::NonCanonicalOrdering),
    }
}
