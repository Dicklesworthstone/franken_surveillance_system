#![forbid(unsafe_code)]
//! Deterministic temporal verifier orchestration (FSS-083).
//!
//! Provides a deterministic reference orchestrator that evaluates registered temporal
//! verifiers over an anchor-pinned event window.
//!
//! # Architecture and Invariants
//!
//! - **Explicit 8-state typed state machine**: `pending`, `running`, `satisfied`, `violated`,
//!   `indeterminate`, `cancelled`, `stale-generation`, and `budget-exhausted`.
//! - **Uncertainty preservation**: Typed outcomes that never flatten `unknown` or
//!   `indeterminate` into pass or fail. A verifier over a coverage gap yields `indeterminate`
//!   (never violated or satisfied), and a missing detection during a gap is explicitly
//!   never evidence of absence (INV-001, INV-007).
//! - **Bounded work**: Work is strictly bounded by a `VerificationBudget` (max events,
//!   max verifiers, max evaluation steps); there is no unbounded retry.
//! - **Cancellation lifecycle**: Request -> drain -> finalize. When cancellation is
//!   requested, pending work is drained cleanly with no orphaned tasks.
//! - **Fault isolation via quarantine**: A verifier that errors or panics during evaluation
//!   is quarantined in the orchestrator's quarantine registry; the run records a typed
//!   quarantined outcome without crashing or terminating the host process.
//! - **Stable identities**: Verifiers and runs carry stable identifiers validated against
//!   the canonical portable alphabet (`validate_id`).

use core::fmt;
use core::ops::Deref;
use core::str::FromStr;
use std::collections::{BTreeMap, BTreeSet};

use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::contract::ContractError;
use crate::event::{EventHypothesis, EventKind};
use crate::evidence::{
    ClockBasis, CoverageContinuity, CoverageStopReason, CoverageWitness, LedgerAnchor,
};
use crate::ids::{EventId, validate_id};
use crate::time::{CaptureInterval, TemporalPrecedence};

// ============================================================================
// Stable Identifiers
// ============================================================================

/// Stable identifier for a registered temporal verifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TemporalVerifierId(String);

impl TemporalVerifierId {
    /// Parses an identifier matching the canonical portable alphabet.
    pub fn parse(value: impl Into<String>) -> Result<Self, ContractError> {
        let text = value.into();
        validate_id(&text)?;
        Ok(Self(text))
    }

    /// Returns the raw identifier string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for TemporalVerifierId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for TemporalVerifierId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for TemporalVerifierId {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl CanonicalEncode for TemporalVerifierId {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.0);
    }
}

impl CanonicalDecode for TemporalVerifierId {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let text = decoder.text()?.to_string();
        Self::parse(text)
    }
}

/// Stable identifier for an orchestration run.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VerificationRunId(String);

impl VerificationRunId {
    /// Parses an identifier matching the canonical portable alphabet.
    pub fn parse(value: impl Into<String>) -> Result<Self, ContractError> {
        let text = value.into();
        validate_id(&text)?;
        Ok(Self(text))
    }

    /// Returns the raw identifier string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for VerificationRunId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for VerificationRunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for VerificationRunId {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl CanonicalEncode for VerificationRunId {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.0);
    }
}

impl CanonicalDecode for VerificationRunId {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let text = decoder.text()?.to_string();
        Self::parse(text)
    }
}

// ============================================================================
// State Machine & Detail Types
// ============================================================================

/// Explicit typed state machine for temporal verifier orchestration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationState {
    /// Verification has been prepared and is pending execution.
    Pending,
    /// Verification is actively running.
    Running,
    /// All registered verifiers were definitively satisfied.
    Satisfied(SatisfiedDetail),
    /// At least one verifier was definitely violated.
    Violated(ViolationDetail),
    /// Outcome is indeterminate due to gaps, uncertainty, or unobservable evidence.
    Indeterminate(IndeterminateDetail),
    /// Verification was cancelled via request-drain-finalize lifecycle.
    Cancelled(CancellationDetail),
    /// Generation mismatch was detected against authorized generation.
    StaleGeneration(StaleGenerationDetail),
    /// Resource budget was exhausted before verification could complete.
    BudgetExhausted(BudgetExhaustedDetail),
}

impl VerificationState {
    /// Returns true if this state is a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Satisfied(_)
                | Self::Violated(_)
                | Self::Indeterminate(_)
                | Self::Cancelled(_)
                | Self::StaleGeneration(_)
                | Self::BudgetExhausted(_)
        )
    }

    /// Returns true if this state is pending.
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Returns true if this state is running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(self, Self::Running)
    }

    /// Returns true if this state is satisfied.
    #[must_use]
    pub const fn is_satisfied(&self) -> bool {
        matches!(self, Self::Satisfied(_))
    }

    /// Returns true if this state is violated.
    #[must_use]
    pub const fn is_violated(&self) -> bool {
        matches!(self, Self::Violated(_))
    }

    /// Returns true if this state is indeterminate.
    #[must_use]
    pub const fn is_indeterminate(&self) -> bool {
        matches!(self, Self::Indeterminate(_))
    }

    /// Returns true if this state is cancelled.
    #[must_use]
    pub const fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled(_))
    }

    /// Returns true if this state is stale-generation.
    #[must_use]
    pub const fn is_stale_generation(&self) -> bool {
        matches!(self, Self::StaleGeneration(_))
    }

    /// Returns true if this state is budget-exhausted.
    #[must_use]
    pub const fn is_budget_exhausted(&self) -> bool {
        matches!(self, Self::BudgetExhausted(_))
    }

    /// Returns the stable string tag for this state.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Satisfied(_) => "satisfied",
            Self::Violated(_) => "violated",
            Self::Indeterminate(_) => "indeterminate",
            Self::Cancelled(_) => "cancelled",
            Self::StaleGeneration(_) => "stale_generation",
            Self::BudgetExhausted(_) => "budget_exhausted",
        }
    }
}

/// Detail when all registered verifiers are satisfied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SatisfiedDetail {
    /// Total number of verifiers evaluated.
    pub verifiers_evaluated: usize,
    /// Total number of events evaluated across the window.
    pub events_evaluated: usize,
    /// Human/agent-readable summary.
    pub summary: String,
}

/// Detail when a verifier is definitely violated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViolationDetail {
    /// Verifier that detected the violation.
    pub verifier_id: TemporalVerifierId,
    /// Specific reason for the violation.
    pub reason: String,
    /// Optional identifier of the violating event.
    pub violating_event_id: Option<EventId>,
    /// Step index at which violation occurred.
    pub step: usize,
}

/// Detail when verification outcome is indeterminate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndeterminateDetail {
    /// Verifier that encountered the indeterminate condition, if applicable.
    pub verifier_id: Option<TemporalVerifierId>,
    /// Explicit reason for the indeterminate classification.
    pub reason: IndeterminateReason,
    /// Step index at which indeterminate condition was encountered.
    pub step: usize,
}

/// Detail when verification is cancelled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancellationDetail {
    /// Reason provided for cancellation.
    pub reason: String,
    /// Number of verifiers completed before cancellation.
    pub verifiers_completed: usize,
    /// Number of verifiers drained without running.
    pub verifiers_drained: usize,
}

/// Detail when evaluation detects a stale generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaleGenerationDetail {
    /// Expected generation authorized for this run.
    pub expected_generation: u64,
    /// Observed generation found on the window or witness.
    pub observed_generation: u64,
    /// Originating source of the generation mismatch.
    pub source: String,
}

/// Detail when resource budget is exhausted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BudgetExhaustedDetail {
    /// Dimension that exceeded budget (e.g. "max_events", "max_steps", "max_verifiers").
    pub dimension: String,
    /// Configured maximum limit.
    pub limit: usize,
    /// Observed count attempting to exceed the limit.
    pub observed: usize,
}

// ============================================================================
// Indeterminate Reason Taxonomy
// ============================================================================

/// Typed causes of indeterminate verification outcomes.
///
/// Under INV-001 and INV-007, indeterminate states must never be collapsed into
/// pass or fail. In particular, a missing detection during a coverage gap is
/// NEVER evidence of absence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndeterminateReason {
    /// A coverage gap exists within the evaluation window.
    CoverageGap {
        /// Interval spanning the coverage gap.
        gap_interval: CaptureInterval,
        /// Gap duration in nanoseconds.
        gap_ns: u128,
    },
    /// A required or expected detection did not occur during a coverage gap.
    /// This is strictly NEVER evidence of absence.
    MissingDetectionDuringGap {
        /// Predicate or event kind queried.
        predicate: String,
        /// Interval spanning the gap during which observation was missing.
        gap_interval: CaptureInterval,
    },
    /// Capture interval uncertainty prevents proving strict temporal ordering.
    IntervalOverlap {
        /// The overlapping interval where temporal ordering is indeterminate.
        overlap: CaptureInterval,
        /// First event ID.
        event_a: EventId,
        /// Second event ID.
        event_b: EventId,
    },
    /// Differing or uncalibrated clock bases prevent definitive temporal relation.
    ClockSkew {
        /// Clock basis of first event.
        basis_a: ClockBasis,
        /// Clock basis of second event.
        basis_b: ClockBasis,
        /// First event ID.
        event_a: EventId,
        /// Second event ID.
        event_b: EventId,
    },
    /// Observation domain is not certified or outside authorized coverage.
    Unobservable {
        /// Target domain name.
        domain: String,
        /// Specific detail explaining lack of observability.
        detail: String,
    },
    /// Verifier encountered an unexpected error and was placed in quarantine.
    VerifierQuarantined {
        /// Quarantined verifier ID.
        verifier_id: TemporalVerifierId,
        /// Quarantine error message.
        error: String,
    },
}

impl fmt::Display for IndeterminateReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CoverageGap {
                gap_interval,
                gap_ns,
            } => {
                write!(
                    f,
                    "coverage gap of {gap_ns}ns over interval [{earliest}, {latest}]",
                    earliest = gap_interval.earliest,
                    latest = gap_interval.latest
                )
            }
            Self::MissingDetectionDuringGap {
                predicate,
                gap_interval,
            } => {
                write!(
                    f,
                    "missing detection of '{predicate}' during coverage gap [{earliest}, {latest}] (never evidence of absence)",
                    earliest = gap_interval.earliest,
                    latest = gap_interval.latest
                )
            }
            Self::IntervalOverlap {
                overlap,
                event_a,
                event_b,
            } => {
                write!(
                    f,
                    "interval overlap [{earliest}, {latest}] between {event_a} and {event_b} leaves order indeterminate",
                    earliest = overlap.earliest,
                    latest = overlap.latest
                )
            }
            Self::ClockSkew {
                basis_a,
                basis_b,
                event_a,
                event_b,
            } => {
                write!(
                    f,
                    "clock skew / basis mismatch between {event_a} ({basis_a:?}) and {event_b} ({basis_b:?})"
                )
            }
            Self::Unobservable { domain, detail } => {
                write!(f, "domain '{domain}' is unobservable: {detail}")
            }
            Self::VerifierQuarantined { verifier_id, error } => {
                write!(f, "verifier '{verifier_id}' quarantined: {error}")
            }
        }
    }
}

// ============================================================================
// Verifier Outcome
// ============================================================================

/// Outcome of evaluating a single registered temporal verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifierOutcome {
    /// Verifier was definitely satisfied.
    Satisfied {
        /// Explanation of satisfaction.
        detail: String,
    },
    /// Verifier was definitely violated.
    Violated {
        /// Reason for violation.
        reason: String,
        /// Optional violating event ID.
        violating_event_id: Option<EventId>,
    },
    /// Verifier outcome is indeterminate.
    Indeterminate {
        /// Explicit cause of indeterminacy.
        reason: IndeterminateReason,
    },
    /// Verifier encountered an error and was quarantined.
    Quarantined {
        /// Verifier ID.
        verifier_id: TemporalVerifierId,
        /// Error description.
        error: String,
    },
    /// Verifier evaluation was cancelled.
    Cancelled,
    /// Verifier evaluation exceeded resource budget.
    BudgetExhausted {
        /// Budget exhaustion detail.
        detail: String,
    },
    /// Generation mismatch was detected.
    StaleGeneration {
        /// Expected generation.
        expected: u64,
        /// Actual generation.
        actual: u64,
    },
}

// ============================================================================
// Budget Envelope & Tracker
// ============================================================================

/// Hard resource envelope bounding verification work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationBudget {
    /// Maximum number of events processed in a single run.
    pub max_events: usize,
    /// Maximum number of verifiers executed in a single run.
    pub max_verifiers: usize,
    /// Maximum evaluation step limit.
    pub max_steps: usize,
}

impl VerificationBudget {
    /// Default conservative budget.
    pub const fn default_budget() -> Self {
        Self {
            max_events: 1_000,
            max_verifiers: 64,
            max_steps: 10_000,
        }
    }

    /// Sets max events.
    #[must_use]
    pub const fn with_max_events(mut self, max: usize) -> Self {
        self.max_events = max;
        self
    }

    /// Sets max verifiers.
    #[must_use]
    pub const fn with_max_verifiers(mut self, max: usize) -> Self {
        self.max_verifiers = max;
        self
    }

    /// Sets max evaluation steps.
    #[must_use]
    pub const fn with_max_steps(mut self, max: usize) -> Self {
        self.max_steps = max;
        self
    }
}

impl Default for VerificationBudget {
    fn default() -> Self {
        Self::default_budget()
    }
}

/// Tracks consumed work and enforces budget bounds without panicking.
#[derive(Clone, Debug)]
pub struct RunBudgetTracker {
    budget: VerificationBudget,
    events_evaluated: usize,
    verifiers_evaluated: usize,
    steps_evaluated: usize,
}

impl RunBudgetTracker {
    /// Creates a new tracker bounded by `budget`.
    #[must_use]
    pub const fn new(budget: VerificationBudget) -> Self {
        Self {
            budget,
            events_evaluated: 0,
            verifiers_evaluated: 0,
            steps_evaluated: 0,
        }
    }

    /// Increments evaluation step count, failing closed if budget is exceeded.
    pub fn step(&mut self) -> Result<(), BudgetExhaustedDetail> {
        self.steps_evaluated = self.steps_evaluated.saturating_add(1);
        if self.steps_evaluated > self.budget.max_steps {
            return Err(BudgetExhaustedDetail {
                dimension: "max_steps".to_string(),
                limit: self.budget.max_steps,
                observed: self.steps_evaluated,
            });
        }
        Ok(())
    }

    /// Records an event evaluation, failing closed if budget is exceeded.
    pub fn record_event(&mut self) -> Result<(), BudgetExhaustedDetail> {
        self.events_evaluated = self.events_evaluated.saturating_add(1);
        if self.events_evaluated > self.budget.max_events {
            return Err(BudgetExhaustedDetail {
                dimension: "max_events".to_string(),
                limit: self.budget.max_events,
                observed: self.events_evaluated,
            });
        }
        self.step()
    }

    /// Records a verifier invocation, failing closed if budget is exceeded.
    pub fn record_verifier(&mut self) -> Result<(), BudgetExhaustedDetail> {
        self.verifiers_evaluated = self.verifiers_evaluated.saturating_add(1);
        if self.verifiers_evaluated > self.budget.max_verifiers {
            return Err(BudgetExhaustedDetail {
                dimension: "max_verifiers".to_string(),
                limit: self.budget.max_verifiers,
                observed: self.verifiers_evaluated,
            });
        }
        self.step()
    }

    /// Number of evaluation steps consumed so far.
    #[must_use]
    pub const fn steps_consumed(&self) -> usize {
        self.steps_evaluated
    }

    /// Number of events evaluated so far.
    #[must_use]
    pub const fn events_consumed(&self) -> usize {
        self.events_evaluated
    }

    /// Number of verifiers evaluated so far.
    #[must_use]
    pub const fn verifiers_consumed(&self) -> usize {
        self.verifiers_evaluated
    }
}

// ============================================================================
// Anchor-Pinned Event Window
// ============================================================================

/// An immutable, anchor-pinned temporal window containing candidate events and coverage witness.
#[derive(Clone, Debug, PartialEq)]
pub struct AnchorPinnedEventWindow {
    /// Basis ledger anchor pinning the complete authority state.
    pub anchor: LedgerAnchor,
    /// Time interval bounds of the window.
    pub window_interval: CaptureInterval,
    /// Events observed within this window.
    pub events: Vec<EventHypothesis>,
    /// Clock basis mapping for events by ID.
    pub event_clock_bases: BTreeMap<EventId, ClockBasis>,
    /// Optional coverage witness certifying the observation domain over this window.
    pub coverage_witness: Option<CoverageWitness>,
    /// Expected generation authorized for this window.
    pub expected_generation: u64,
    /// Observed generation reported by sensors/adapters for this window.
    pub observed_generation: u64,
}

impl AnchorPinnedEventWindow {
    /// Constructs and validates a new anchor-pinned window.
    pub fn new(
        anchor: LedgerAnchor,
        window_interval: CaptureInterval,
        events: Vec<EventHypothesis>,
        coverage_witness: Option<CoverageWitness>,
        expected_generation: u64,
        observed_generation: u64,
    ) -> Result<Self, TemporalVerifierError> {
        if window_interval.earliest > window_interval.latest {
            return Err(TemporalVerifierError::Contract(
                ContractError::InvertedTimeInterval,
            ));
        }
        Ok(Self {
            anchor,
            window_interval,
            events,
            event_clock_bases: BTreeMap::new(),
            coverage_witness,
            expected_generation,
            observed_generation,
        })
    }

    /// Attaches an explicit clock basis for an event.
    #[must_use]
    pub fn with_event_clock_basis(mut self, event_id: EventId, basis: ClockBasis) -> Self {
        self.event_clock_bases.insert(event_id, basis);
        self
    }

    /// Returns the clock basis for a given event ID, defaulting to UTC disciplined if unmapped.
    #[must_use]
    pub fn clock_basis_for(&self, event_id: &EventId) -> ClockBasis {
        self.event_clock_bases
            .get(event_id)
            .copied()
            .unwrap_or(ClockBasis::UtcDisciplined)
    }
}

// ============================================================================
// Temporal Verifier Trait
// ============================================================================

/// Interface for a registered temporal verifier.
pub trait TemporalVerifier: Send + Sync {
    /// Returns the stable identifier for this verifier.
    fn id(&self) -> &TemporalVerifierId;

    /// Evaluates this verifier over the provided anchor-pinned event window.
    fn verify(
        &self,
        window: &AnchorPinnedEventWindow,
        tracker: &mut RunBudgetTracker,
    ) -> Result<VerifierOutcome, TemporalVerifierError>;
}

// ============================================================================
// Reference Verifiers
// ============================================================================

/// Verifier that enforces monotonic chronological ordering and rejects duplicate events.
pub struct OrderingVerifier {
    id: TemporalVerifierId,
}

impl OrderingVerifier {
    /// Constructs a standard ordering verifier with stable ID `verifier:temporal:ordering:v1`.
    pub fn new() -> Result<Self, ContractError> {
        Ok(Self {
            id: TemporalVerifierId::parse("verifier:temporal:ordering:v1")?,
        })
    }

    /// Constructs an ordering verifier with a custom stable ID.
    pub fn with_id(id: TemporalVerifierId) -> Self {
        Self { id }
    }
}

impl TemporalVerifier for OrderingVerifier {
    fn id(&self) -> &TemporalVerifierId {
        &self.id
    }

    fn verify(
        &self,
        window: &AnchorPinnedEventWindow,
        tracker: &mut RunBudgetTracker,
    ) -> Result<VerifierOutcome, TemporalVerifierError> {
        let mut seen_ids: BTreeSet<EventId> = BTreeSet::new();

        // Check for duplicate events
        for event in &window.events {
            tracker
                .record_event()
                .map_err(TemporalVerifierError::from)?;
            if !seen_ids.insert(event.event_id.clone()) {
                return Ok(VerifierOutcome::Violated {
                    reason: format!("duplicate event ID '{}' detected in window", event.event_id),
                    violating_event_id: Some(event.event_id.clone()),
                });
            }
        }

        // Check chronological ordering between consecutive events
        for window_slice in window.events.windows(2) {
            tracker.step().map_err(TemporalVerifierError::from)?;
            let curr = &window_slice[0];
            let next = &window_slice[1];

            let curr_basis = window.clock_basis_for(&curr.event_id);
            let next_basis = window.clock_basis_for(&next.event_id);

            // If clock bases differ, ordering is indeterminate due to clock skew
            if curr_basis != next_basis {
                return Ok(VerifierOutcome::Indeterminate {
                    reason: IndeterminateReason::ClockSkew {
                        basis_a: curr_basis,
                        basis_b: next_basis,
                        event_a: curr.event_id.clone(),
                        event_b: next.event_id.clone(),
                    },
                });
            }

            match curr.interval.temporal_precedence(next.interval) {
                TemporalPrecedence::After { .. } => {
                    return Ok(VerifierOutcome::Violated {
                        reason: format!(
                            "events out of chronological order: event '{}' occurs after event '{}'",
                            curr.event_id, next.event_id
                        ),
                        violating_event_id: Some(next.event_id.clone()),
                    });
                }
                TemporalPrecedence::Indeterminate { overlap } => {
                    return Ok(VerifierOutcome::Indeterminate {
                        reason: IndeterminateReason::IntervalOverlap {
                            overlap,
                            event_a: curr.event_id.clone(),
                            event_b: next.event_id.clone(),
                        },
                    });
                }
                TemporalPrecedence::Before { .. }
                | TemporalPrecedence::BeforeOrAt { .. }
                | TemporalPrecedence::AfterOrAt { .. } => {
                    // Valid non-inverted ordering
                }
            }
        }

        Ok(VerifierOutcome::Satisfied {
            detail: "events are strictly ordered with no duplicates".to_string(),
        })
    }
}

/// Verifier that enforces event and window duration bounds.
pub struct DurationVerifier {
    id: TemporalVerifierId,
    max_event_duration_ns: Option<u128>,
    max_window_duration_ns: Option<u128>,
}

impl DurationVerifier {
    /// Constructs a duration verifier with stable ID `verifier:temporal:duration:v1`.
    pub fn new(
        max_event_duration_ns: Option<u128>,
        max_window_duration_ns: Option<u128>,
    ) -> Result<Self, ContractError> {
        Ok(Self {
            id: TemporalVerifierId::parse("verifier:temporal:duration:v1")?,
            max_event_duration_ns,
            max_window_duration_ns,
        })
    }
}

impl TemporalVerifier for DurationVerifier {
    fn id(&self) -> &TemporalVerifierId {
        &self.id
    }

    fn verify(
        &self,
        window: &AnchorPinnedEventWindow,
        tracker: &mut RunBudgetTracker,
    ) -> Result<VerifierOutcome, TemporalVerifierError> {
        // Under INV-001, if a coverage gap exists mid-window, duration cannot be evaluated
        if let Some(witness) = &window.coverage_witness {
            tracker.step().map_err(TemporalVerifierError::from)?;
            if witness.continuity == CoverageContinuity::Gapped
                || witness.stop_reason == CoverageStopReason::SourceGap
            {
                return Ok(VerifierOutcome::Indeterminate {
                    reason: IndeterminateReason::CoverageGap {
                        gap_interval: window.window_interval,
                        gap_ns: window.window_interval.uncertainty_ns(),
                    },
                });
            }
        }

        // Check window duration bound
        if let Some(max_window_ns) = self.max_window_duration_ns {
            tracker.step().map_err(TemporalVerifierError::from)?;
            let window_duration = window.window_interval.uncertainty_ns();
            if window_duration > max_window_ns {
                return Ok(VerifierOutcome::Violated {
                    reason: format!(
                        "window duration {window_duration}ns exceeds maximum {max_window_ns}ns"
                    ),
                    violating_event_id: None,
                });
            }
        }

        // Check individual event duration bounds
        if let Some(max_event_ns) = self.max_event_duration_ns {
            for event in &window.events {
                tracker
                    .record_event()
                    .map_err(TemporalVerifierError::from)?;
                let event_duration = event.interval.uncertainty_ns();
                if event_duration > max_event_ns {
                    return Ok(VerifierOutcome::Violated {
                        reason: format!(
                            "event '{}' duration {event_duration}ns exceeds maximum {max_event_ns}ns",
                            event.event_id
                        ),
                        violating_event_id: Some(event.event_id.clone()),
                    });
                }
            }
        }

        Ok(VerifierOutcome::Satisfied {
            detail: "duration bounds satisfied".to_string(),
        })
    }
}

/// Verifier that verifies coverage continuity over the window.
///
/// Invariant: A coverage gap yields `indeterminate` (never `violated` or `satisfied`).
pub struct GapVerifier {
    id: TemporalVerifierId,
}

impl GapVerifier {
    /// Constructs a gap verifier with stable ID `verifier:temporal:gap:v1`.
    pub fn new() -> Result<Self, ContractError> {
        Ok(Self {
            id: TemporalVerifierId::parse("verifier:temporal:gap:v1")?,
        })
    }
}

impl TemporalVerifier for GapVerifier {
    fn id(&self) -> &TemporalVerifierId {
        &self.id
    }

    fn verify(
        &self,
        window: &AnchorPinnedEventWindow,
        tracker: &mut RunBudgetTracker,
    ) -> Result<VerifierOutcome, TemporalVerifierError> {
        tracker.step().map_err(TemporalVerifierError::from)?;

        let Some(witness) = &window.coverage_witness else {
            return Ok(VerifierOutcome::Indeterminate {
                reason: IndeterminateReason::Unobservable {
                    domain: "coverage".to_string(),
                    detail: "coverage witness missing over window".to_string(),
                },
            });
        };

        match witness.continuity {
            CoverageContinuity::Gapped => Ok(VerifierOutcome::Indeterminate {
                reason: IndeterminateReason::CoverageGap {
                    gap_interval: window.window_interval,
                    gap_ns: window.window_interval.uncertainty_ns(),
                },
            }),
            CoverageContinuity::Unknown => Ok(VerifierOutcome::Indeterminate {
                reason: IndeterminateReason::Unobservable {
                    domain: "coverage".to_string(),
                    detail: "coverage continuity is unknown".to_string(),
                },
            }),
            CoverageContinuity::Continuous => {
                if witness.stop_reason == CoverageStopReason::SourceGap {
                    Ok(VerifierOutcome::Indeterminate {
                        reason: IndeterminateReason::CoverageGap {
                            gap_interval: window.window_interval,
                            gap_ns: window.window_interval.uncertainty_ns(),
                        },
                    })
                } else {
                    Ok(VerifierOutcome::Satisfied {
                        detail: "continuous coverage certified over window".to_string(),
                    })
                }
            }
        }
    }
}

/// Verifier that verifies generation freshness and authority alignment.
pub struct StalenessVerifier {
    id: TemporalVerifierId,
}

impl StalenessVerifier {
    /// Constructs a staleness verifier with stable ID `verifier:temporal:staleness:v1`.
    pub fn new() -> Result<Self, ContractError> {
        Ok(Self {
            id: TemporalVerifierId::parse("verifier:temporal:staleness:v1")?,
        })
    }
}

impl TemporalVerifier for StalenessVerifier {
    fn id(&self) -> &TemporalVerifierId {
        &self.id
    }

    fn verify(
        &self,
        window: &AnchorPinnedEventWindow,
        tracker: &mut RunBudgetTracker,
    ) -> Result<VerifierOutcome, TemporalVerifierError> {
        tracker.step().map_err(TemporalVerifierError::from)?;

        if window.expected_generation != window.observed_generation {
            return Ok(VerifierOutcome::StaleGeneration {
                expected: window.expected_generation,
                actual: window.observed_generation,
            });
        }

        if let Some(witness) = &window.coverage_witness
            && witness.authorized_generation != witness.observed_generation
        {
            return Ok(VerifierOutcome::StaleGeneration {
                expected: witness.authorized_generation,
                actual: witness.observed_generation,
            });
        }

        Ok(VerifierOutcome::Satisfied {
            detail: "generation is current and matching".to_string(),
        })
    }
}

/// Verifier that verifies certified absence of a specific event kind.
///
/// Invariant: A missing detection during a coverage gap is NEVER evidence of absence.
pub struct PredicateAbsenceVerifier {
    id: TemporalVerifierId,
    target_kind: EventKind,
}

impl PredicateAbsenceVerifier {
    /// Constructs an absence verifier for `target_kind`.
    pub fn new(target_kind: EventKind) -> Result<Self, ContractError> {
        let id_str = format!("verifier:temporal:absence:{}:v1", target_kind.as_str());
        Ok(Self {
            id: TemporalVerifierId::parse(id_str)?,
            target_kind,
        })
    }
}

impl TemporalVerifier for PredicateAbsenceVerifier {
    fn id(&self) -> &TemporalVerifierId {
        &self.id
    }

    fn verify(
        &self,
        window: &AnchorPinnedEventWindow,
        tracker: &mut RunBudgetTracker,
    ) -> Result<VerifierOutcome, TemporalVerifierError> {
        tracker.step().map_err(TemporalVerifierError::from)?;

        // Search for target event kind in window
        let detected = window.events.iter().find(|e| e.kind == self.target_kind);

        if let Some(event) = detected {
            return Ok(VerifierOutcome::Violated {
                reason: format!(
                    "event kind '{:?}' detected in window (absence violated)",
                    self.target_kind
                ),
                violating_event_id: Some(event.event_id.clone()),
            });
        }

        // Event was NOT detected: verify whether absence is certified
        let Some(witness) = &window.coverage_witness else {
            return Ok(VerifierOutcome::Indeterminate {
                reason: IndeterminateReason::MissingDetectionDuringGap {
                    predicate: self.target_kind.as_str().to_string(),
                    gap_interval: window.window_interval,
                },
            });
        };

        if witness.continuity != CoverageContinuity::Continuous
            || witness.stop_reason == CoverageStopReason::SourceGap
            || !witness.certifies_absence()
        {
            // Under INV-001/INV-007, missing detection during a gap is NEVER evidence of absence
            return Ok(VerifierOutcome::Indeterminate {
                reason: IndeterminateReason::MissingDetectionDuringGap {
                    predicate: self.target_kind.as_str().to_string(),
                    gap_interval: window.window_interval,
                },
            });
        }

        Ok(VerifierOutcome::Satisfied {
            detail: format!(
                "certified absence of event kind '{:?}' with continuous coverage",
                self.target_kind
            ),
        })
    }
}

/// A verifier configured to return an error for fault and quarantine testing.
pub struct FaultyVerifier {
    id: TemporalVerifierId,
    error_message: String,
}

impl FaultyVerifier {
    /// Constructs a faulty verifier that fails with `error_message`.
    pub fn new(
        id: impl Into<String>,
        error_message: impl Into<String>,
    ) -> Result<Self, ContractError> {
        Ok(Self {
            id: TemporalVerifierId::parse(id)?,
            error_message: error_message.into(),
        })
    }
}

impl TemporalVerifier for FaultyVerifier {
    fn id(&self) -> &TemporalVerifierId {
        &self.id
    }

    fn verify(
        &self,
        _window: &AnchorPinnedEventWindow,
        _tracker: &mut RunBudgetTracker,
    ) -> Result<VerifierOutcome, TemporalVerifierError> {
        Err(TemporalVerifierError::EvaluationFailed(
            self.error_message.clone(),
        ))
    }
}

// ============================================================================
// Orchestrator & Report
// ============================================================================

/// Complete execution report returned by the orchestrator for one verification run.
#[derive(Clone, Debug, PartialEq)]
pub struct VerificationRunReport {
    /// Stable identifier for this verification run.
    pub run_id: VerificationRunId,
    /// Basis anchor over which verification ran.
    pub basis_anchor: LedgerAnchor,
    /// Final lifecycle state of the run.
    pub state: VerificationState,
    /// Individual outcomes for each evaluated verifier in deterministic order.
    pub outcomes: Vec<(TemporalVerifierId, VerifierOutcome)>,
    /// Number of evaluation steps consumed by the run.
    pub steps_consumed: usize,
    /// Set of verifier IDs currently quarantined by the orchestrator.
    pub quarantined_verifiers: BTreeSet<TemporalVerifierId>,
}

/// Deterministic reference orchestrator for temporal verifiers.
pub struct TemporalOrchestrator {
    verifiers: Vec<Box<dyn TemporalVerifier>>,
    quarantined_verifiers: BTreeSet<TemporalVerifierId>,
    budget: VerificationBudget,
    cancellation_requested: bool,
    cancellation_reason: Option<String>,
}

impl Default for TemporalOrchestrator {
    fn default() -> Self {
        Self::new(VerificationBudget::default_budget())
    }
}

impl TemporalOrchestrator {
    /// Creates a new orchestrator with the specified budget envelope.
    #[must_use]
    pub const fn new(budget: VerificationBudget) -> Self {
        Self {
            verifiers: Vec::new(),
            quarantined_verifiers: BTreeSet::new(),
            budget,
            cancellation_requested: false,
            cancellation_reason: None,
        }
    }

    /// Registers a temporal verifier, rejecting duplicates.
    pub fn register_verifier(
        &mut self,
        verifier: Box<dyn TemporalVerifier>,
    ) -> Result<(), TemporalVerifierError> {
        let id = verifier.id().clone();
        if self.verifiers.iter().any(|v| v.id() == &id) {
            return Err(TemporalVerifierError::DuplicateVerifierId(id));
        }
        self.verifiers.push(verifier);
        Ok(())
    }

    /// Returns the number of registered verifiers.
    #[must_use]
    pub fn verifier_count(&self) -> usize {
        self.verifiers.len()
    }

    /// Returns true if the given verifier ID is currently in quarantine.
    #[must_use]
    pub fn is_quarantined(&self, id: &TemporalVerifierId) -> bool {
        self.quarantined_verifiers.contains(id)
    }

    /// Returns the set of quarantined verifier IDs.
    #[must_use]
    pub const fn quarantined_verifiers(&self) -> &BTreeSet<TemporalVerifierId> {
        &self.quarantined_verifiers
    }

    /// Explicitly removes a verifier from quarantine.
    pub fn lift_quarantine(&mut self, id: &TemporalVerifierId) -> bool {
        self.quarantined_verifiers.remove(id)
    }

    /// Requests cancellation of the next or currently running verification.
    pub fn request_cancellation(&mut self, reason: impl Into<String>) {
        self.cancellation_requested = true;
        self.cancellation_reason = Some(reason.into());
    }

    /// Returns true if cancellation has been requested.
    #[must_use]
    pub const fn is_cancellation_requested(&self) -> bool {
        self.cancellation_requested
    }

    /// Clears any pending cancellation request.
    pub fn reset_cancellation(&mut self) {
        self.cancellation_requested = false;
        self.cancellation_reason = None;
    }

    /// Executes temporal verification over the anchor-pinned event window.
    pub fn execute(
        &mut self,
        run_id: VerificationRunId,
        window: &AnchorPinnedEventWindow,
    ) -> Result<VerificationRunReport, TemporalVerifierError> {
        let mut tracker = RunBudgetTracker::new(self.budget);

        // 1. Cancellation pre-check: request -> drain -> finalize
        if self.cancellation_requested {
            let reason = self
                .cancellation_reason
                .take()
                .unwrap_or_else(|| "cancellation requested before start".to_string());
            self.cancellation_requested = false;
            let drained = self.verifiers.len();
            return Ok(VerificationRunReport {
                run_id,
                basis_anchor: window.anchor.clone(),
                state: VerificationState::Cancelled(CancellationDetail {
                    reason,
                    verifiers_completed: 0,
                    verifiers_drained: drained,
                }),
                outcomes: Vec::new(),
                steps_consumed: 0,
                quarantined_verifiers: self.quarantined_verifiers.clone(),
            });
        }

        // 2. Stale generation pre-check
        if window.expected_generation != window.observed_generation {
            return Ok(VerificationRunReport {
                run_id,
                basis_anchor: window.anchor.clone(),
                state: VerificationState::StaleGeneration(StaleGenerationDetail {
                    expected_generation: window.expected_generation,
                    observed_generation: window.observed_generation,
                    source: "window_generation_precheck".to_string(),
                }),
                outcomes: Vec::new(),
                steps_consumed: 0,
                quarantined_verifiers: self.quarantined_verifiers.clone(),
            });
        }

        // 3. Event count budget pre-check
        if window.events.len() > self.budget.max_events {
            return Ok(VerificationRunReport {
                run_id,
                basis_anchor: window.anchor.clone(),
                state: VerificationState::BudgetExhausted(BudgetExhaustedDetail {
                    dimension: "max_events".to_string(),
                    limit: self.budget.max_events,
                    observed: window.events.len(),
                }),
                outcomes: Vec::new(),
                steps_consumed: 0,
                quarantined_verifiers: self.quarantined_verifiers.clone(),
            });
        }

        // 4. Verifiers count budget pre-check
        if self.verifiers.len() > self.budget.max_verifiers {
            return Ok(VerificationRunReport {
                run_id,
                basis_anchor: window.anchor.clone(),
                state: VerificationState::BudgetExhausted(BudgetExhaustedDetail {
                    dimension: "max_verifiers".to_string(),
                    limit: self.budget.max_verifiers,
                    observed: self.verifiers.len(),
                }),
                outcomes: Vec::new(),
                steps_consumed: 0,
                quarantined_verifiers: self.quarantined_verifiers.clone(),
            });
        }

        // 5. Deterministic evaluation loop
        let mut outcomes: Vec<(TemporalVerifierId, VerifierOutcome)> =
            Vec::with_capacity(self.verifiers.len());
        let mut aggregate_violation: Option<ViolationDetail> = None;
        let mut aggregate_indeterminate: Option<IndeterminateDetail> = None;
        let mut aggregate_stale: Option<StaleGenerationDetail> = None;
        let mut aggregate_budget: Option<BudgetExhaustedDetail> = None;
        let mut aggregate_cancelled: Option<CancellationDetail> = None;

        let mut verifiers_completed = 0;

        for (idx, verifier) in self.verifiers.iter().enumerate() {
            // Check cancellation mid-run
            if self.cancellation_requested {
                let reason = self
                    .cancellation_reason
                    .take()
                    .unwrap_or_else(|| "cancellation requested mid-run".to_string());
                self.cancellation_requested = false;
                let drained = self.verifiers.len().saturating_sub(idx);
                aggregate_cancelled = Some(CancellationDetail {
                    reason,
                    verifiers_completed,
                    verifiers_drained: drained,
                });
                break;
            }

            let vid = verifier.id().clone();

            // Check if verifier is quarantined
            if self.quarantined_verifiers.contains(&vid) {
                let outcome = VerifierOutcome::Quarantined {
                    verifier_id: vid.clone(),
                    error: "verifier previously quarantined due to error".to_string(),
                };
                if aggregate_indeterminate.is_none() {
                    aggregate_indeterminate = Some(IndeterminateDetail {
                        verifier_id: Some(vid.clone()),
                        reason: IndeterminateReason::VerifierQuarantined {
                            verifier_id: vid.clone(),
                            error: "verifier previously quarantined due to error".to_string(),
                        },
                        step: tracker.steps_consumed(),
                    });
                }
                outcomes.push((vid, outcome));
                verifiers_completed = verifiers_completed.saturating_add(1);
                continue;
            }

            // Record verifier execution in budget tracker
            if let Err(detail) = tracker.record_verifier() {
                aggregate_budget = Some(detail);
                break;
            }

            // Execute verifier safely without crashing
            match verifier.verify(window, &mut tracker) {
                Ok(outcome) => {
                    verifiers_completed = verifiers_completed.saturating_add(1);
                    match &outcome {
                        VerifierOutcome::Violated {
                            reason,
                            violating_event_id,
                        } => {
                            if aggregate_violation.is_none() {
                                aggregate_violation = Some(ViolationDetail {
                                    verifier_id: vid.clone(),
                                    reason: reason.clone(),
                                    violating_event_id: violating_event_id.clone(),
                                    step: tracker.steps_consumed(),
                                });
                            }
                        }
                        VerifierOutcome::Indeterminate { reason } => {
                            if aggregate_indeterminate.is_none() {
                                aggregate_indeterminate = Some(IndeterminateDetail {
                                    verifier_id: Some(vid.clone()),
                                    reason: reason.clone(),
                                    step: tracker.steps_consumed(),
                                });
                            }
                        }
                        VerifierOutcome::StaleGeneration { expected, actual } => {
                            aggregate_stale = Some(StaleGenerationDetail {
                                expected_generation: *expected,
                                observed_generation: *actual,
                                source: vid.to_string(),
                            });
                            outcomes.push((vid, outcome));
                            break;
                        }
                        VerifierOutcome::BudgetExhausted { .. } => {
                            aggregate_budget = Some(BudgetExhaustedDetail {
                                dimension: "step_budget".to_string(),
                                limit: self.budget.max_steps,
                                observed: tracker.steps_consumed(),
                            });
                            outcomes.push((vid, outcome));
                            break;
                        }
                        VerifierOutcome::Cancelled => {
                            let reason = self
                                .cancellation_reason
                                .take()
                                .unwrap_or_else(|| "cancellation requested".to_string());
                            self.cancellation_requested = false;
                            aggregate_cancelled = Some(CancellationDetail {
                                reason,
                                verifiers_completed,
                                verifiers_drained: self.verifiers.len().saturating_sub(idx + 1),
                            });
                            outcomes.push((vid, outcome));
                            break;
                        }
                        VerifierOutcome::Quarantined { .. } => {
                            self.quarantined_verifiers.insert(vid.clone());
                            if aggregate_indeterminate.is_none() {
                                aggregate_indeterminate = Some(IndeterminateDetail {
                                    verifier_id: Some(vid.clone()),
                                    reason: IndeterminateReason::VerifierQuarantined {
                                        verifier_id: vid.clone(),
                                        error: "verifier quarantined".to_string(),
                                    },
                                    step: tracker.steps_consumed(),
                                });
                            }
                        }
                        VerifierOutcome::Satisfied { .. } => {}
                    }
                    outcomes.push((vid, outcome));
                }
                Err(TemporalVerifierError::BudgetExhausted(detail)) => {
                    aggregate_budget = Some(detail);
                    break;
                }
                Err(err) => {
                    // Safe error quarantine: do NOT panic or crash
                    self.quarantined_verifiers.insert(vid.clone());
                    let err_str = err.to_string();
                    let outcome = VerifierOutcome::Quarantined {
                        verifier_id: vid.clone(),
                        error: err_str.clone(),
                    };
                    if aggregate_indeterminate.is_none() {
                        aggregate_indeterminate = Some(IndeterminateDetail {
                            verifier_id: Some(vid.clone()),
                            reason: IndeterminateReason::VerifierQuarantined {
                                verifier_id: vid.clone(),
                                error: err_str,
                            },
                            step: tracker.steps_consumed(),
                        });
                    }
                    outcomes.push((vid, outcome));
                    verifiers_completed = verifiers_completed.saturating_add(1);
                }
            }
        }

        // 6. Finalize aggregate state machine transition
        let final_state = if let Some(cancelled) = aggregate_cancelled {
            VerificationState::Cancelled(cancelled)
        } else if let Some(budget) = aggregate_budget {
            VerificationState::BudgetExhausted(budget)
        } else if let Some(stale) = aggregate_stale {
            VerificationState::StaleGeneration(stale)
        } else if let Some(violation) = aggregate_violation {
            VerificationState::Violated(violation)
        } else if let Some(indeterminate) = aggregate_indeterminate {
            VerificationState::Indeterminate(indeterminate)
        } else {
            VerificationState::Satisfied(SatisfiedDetail {
                verifiers_evaluated: verifiers_completed,
                events_evaluated: window.events.len(),
                summary: format!("all {verifiers_completed} registered verifiers satisfied"),
            })
        };

        Ok(VerificationRunReport {
            run_id,
            basis_anchor: window.anchor.clone(),
            state: final_state,
            outcomes,
            steps_consumed: tracker.steps_consumed(),
            quarantined_verifiers: self.quarantined_verifiers.clone(),
        })
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Typed error conditions for temporal verifier orchestration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TemporalVerifierError {
    /// Terminal state reached; no further state transitions permitted.
    TerminalStateImmutable(String),
    /// Illegal state machine transition requested.
    IllegalStateTransition {
        /// Source state.
        from: String,
        /// Destination state.
        to: String,
        /// Diagnostic reason.
        reason: String,
    },
    /// Duplicate verifier identifier registration attempt.
    DuplicateVerifierId(TemporalVerifierId),
    /// Verifier is in quarantine and cannot be executed.
    VerifierQuarantined(TemporalVerifierId),
    /// Internal evaluation failed inside verifier.
    EvaluationFailed(String),
    /// Work budget exhausted during evaluation.
    BudgetExhausted(BudgetExhaustedDetail),
    /// Underlying contract error.
    Contract(ContractError),
}

impl fmt::Display for TemporalVerifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TerminalStateImmutable(state) => {
                write!(
                    f,
                    "terminal verification state '{state}' is immutable; no further transitions permitted"
                )
            }
            Self::IllegalStateTransition { from, to, reason } => {
                write!(
                    f,
                    "illegal verification state transition from '{from}' to '{to}': {reason}"
                )
            }
            Self::DuplicateVerifierId(id) => {
                write!(
                    f,
                    "duplicate temporal verifier ID '{id}' already registered"
                )
            }
            Self::VerifierQuarantined(id) => {
                write!(
                    f,
                    "verifier '{id}' is quarantined and cannot execute without operator intervention"
                )
            }
            Self::EvaluationFailed(reason) => {
                write!(f, "verifier evaluation failed: {reason}")
            }
            Self::BudgetExhausted(detail) => {
                write!(
                    f,
                    "budget exhausted on dimension '{}': limit={}, observed={}",
                    detail.dimension, detail.limit, detail.observed
                )
            }
            Self::Contract(err) => write!(f, "contract violation: {err}"),
        }
    }
}

impl std::error::Error for TemporalVerifierError {}

impl From<ContractError> for TemporalVerifierError {
    fn from(err: ContractError) -> Self {
        Self::Contract(err)
    }
}

impl From<BudgetExhaustedDetail> for TemporalVerifierError {
    fn from(detail: BudgetExhaustedDetail) -> Self {
        Self::BudgetExhausted(detail)
    }
}
