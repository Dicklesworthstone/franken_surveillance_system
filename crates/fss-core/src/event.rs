#![forbid(unsafe_code)]
//! Event revision and evidence graph schemas contract (FSS-007).
//!
//! Provides canonical `EventHypothesis` (`EventRevision`) and `EvidenceGraph` contracts:
//! - Revisions are immutable; corrections supersede rather than edit.
//! - Graph edges reference capsule and identity digests with failure domain isolation.
//! - Registered schemas `fss.event_hypothesis.v1` and `fss.evidence_graph.v1`.
//! - Versioned binary encoding envelopes (`FSSE` v1 and `FSSG` v1) and deterministic
//!   JSON projections that round-trip bit-identically.
//! - Strict typed decode errors for truncation, unknown version, trailing bytes,
//!   over-limit lengths, non-canonical encodings, and invariant violations.
//! - Hard size bounds, tested at exact bound and bound+1.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::contract::EvidenceClass;
use crate::time::{CaptureInterval, TimestampNs};
use crate::{ContentDigest, ContractError, EffectState, EventId, ObligationId, OperationId};

/// Canonical schema identifier for event hypothesis / revision v1.
pub const EVENT_HYPOTHESIS_SCHEMA: &str = EventHypothesis::SCHEMA;

/// Format magic header for versioned binary event hypothesis envelopes (`FSSE`).
pub const EVENT_HYPOTHESIS_MAGIC: [u8; 4] = *b"FSSE";

/// Current binary format version for event hypothesis envelopes.
pub const EVENT_HYPOTHESIS_VERSION_1: u16 = 1;

/// Canonical schema identifier for evidence graph v1.
pub const EVIDENCE_GRAPH_SCHEMA: &str = EvidenceGraph::SCHEMA;

/// Format magic header for versioned binary evidence graph envelopes (`FSSG`).
pub const EVIDENCE_GRAPH_MAGIC: [u8; 4] = *b"FSSG";

/// Current binary format version for evidence graph envelopes.
pub const EVIDENCE_GRAPH_VERSION_1: u16 = 1;

// Hard bounds for bounded fields
/// Maximum byte length for event identifier string.
pub const MAX_EVENT_ID_LEN: usize = 128;
/// Maximum byte length for evidence graph identifier string.
pub const MAX_GRAPH_ID_LEN: usize = 128;
/// Maximum byte length for failure domain string.
pub const MAX_FAILURE_DOMAIN_LEN: usize = 128;
/// Maximum byte length for evidence node label string.
pub const MAX_NODE_LABEL_LEN: usize = 128;
/// Maximum byte length for zone identifier string.
pub const MAX_ZONE_ID_LEN: usize = 64;
/// Maximum byte length for track identifier string.
pub const MAX_TRACK_ID_LEN: usize = 64;
/// Maximum count of zones associated with an event.
pub const MAX_ZONES_COUNT: usize = 64;
/// Maximum count of tracks associated with an event.
pub const MAX_TRACKS_COUNT: usize = 64;
/// Maximum count of evidence items attached to an event or graph.
pub const MAX_EVIDENCE_COUNT: usize = 256;
/// Maximum count of nodes in an evidence graph.
pub const MAX_NODES_COUNT: usize = 256;
/// Maximum count of edges in an evidence graph.
pub const MAX_EDGES_COUNT: usize = 256;
/// Maximum count of model receipts attached to an event.
pub const MAX_MODEL_RECEIPTS_COUNT: usize = 64;
/// Maximum byte length for decision abstention reason.
pub const MAX_ABSTENTION_REASON_LEN: usize = 512;
/// Maximum byte length for capture uncertainty reason string.
pub const MAX_UNCERTAINTY_REASON_LEN: usize = 256;
/// Standard label substring for events advancing under an urgent single-sensor policy exception.
pub const SINGLE_DOMAIN_UNCONFIRMED_LABEL: &str = "single-domain/unconfirmed";
/// Maximum depth (number of revisions) allowed in a single event lineage chain.
pub const MAX_LINEAGE_DEPTH: usize = 256;
/// Maximum number of alert attempts recorded on a single event lineage.
pub const MAX_ALERT_ATTEMPTS_COUNT: usize = 64;
/// Maximum byte length for alert channel identifier string.
pub const MAX_ALERT_CHANNEL_LEN: usize = 256;
/// Maximum byte length for alert failure reason string.
pub const MAX_ALERT_FAILURE_REASON_LEN: usize = 512;

/// Typed decode errors with no default-on-error behavior.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventDecodeError {
    /// Input data was truncated before reading required field or byte sequence.
    Truncated {
        /// Minimum bytes expected.
        expected_min: usize,
        /// Actual available bytes.
        actual: usize,
    },
    /// Unknown or unsupported encoding format version.
    UnknownVersion {
        /// Decoded version number.
        version: u16,
    },
    /// Trailing unparsed bytes remaining after complete decode.
    TrailingBytes {
        /// Number of unconsumed bytes.
        count: usize,
    },
    /// A field length strictly exceeds its declared hard bound.
    OverLimitLength {
        /// Name of the offending field.
        field: &'static str,
        /// Hard limit bound.
        limit: usize,
        /// Actual observed length.
        actual: usize,
    },
    /// Non-canonical encoding (e.g. invalid discriminator, illegal magic, non-canonical numbers).
    NonCanonicalEncoding {
        /// Diagnostic detail.
        detail: String,
    },
    /// Schema identity constant mismatch.
    SchemaMismatch {
        /// Expected schema identifier.
        expected: &'static str,
        /// Observed schema identifier.
        found: String,
    },
    /// JSON syntactic or semantic parse error.
    JsonError {
        /// Diagnostic detail.
        detail: String,
    },
    /// Invalid or unpaired-surrogate Unicode escape sequence in JSON.
    InvalidUnicodeEscape {
        /// Codepoint value encountered.
        codepoint: u32,
    },
    /// Mutually contradictory field values.
    Contradiction {
        /// Name of the offending field.
        field: &'static str,
        /// Diagnostic detail.
        detail: String,
    },
    /// A numeric field lies outside its declared inclusive range.
    OutOfRange {
        /// Name of the offending field.
        field: &'static str,
        /// Inclusive minimum.
        minimum: u64,
        /// Inclusive maximum.
        maximum: u64,
        /// Observed value.
        actual: u64,
    },
    /// Underlying invariant or contract violation.
    Contract(ContractError),
}

impl fmt::Display for EventDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                expected_min,
                actual,
            } => {
                write!(
                    f,
                    "truncated input: expected at least {expected_min} bytes, found {actual}"
                )
            }
            Self::UnknownVersion { version } => {
                write!(f, "unknown event format version: {version}")
            }
            Self::TrailingBytes { count } => {
                write!(f, "trailing unconsumed bytes after decode: {count} bytes")
            }
            Self::OverLimitLength {
                field,
                limit,
                actual,
            } => {
                write!(
                    f,
                    "field '{field}' length exceeds bound: limit={limit}, actual={actual}"
                )
            }
            Self::NonCanonicalEncoding { detail } => {
                write!(f, "non-canonical encoding: {detail}")
            }
            Self::SchemaMismatch { expected, found } => {
                write!(f, "schema mismatch: expected '{expected}', found '{found}'")
            }
            Self::JsonError { detail } => {
                write!(f, "json decode error: {detail}")
            }
            Self::InvalidUnicodeEscape { codepoint } => {
                write!(f, "invalid unicode escape: U+{codepoint:04X}")
            }
            Self::Contradiction { field, detail } => {
                write!(f, "contradictory field '{field}': {detail}")
            }
            Self::OutOfRange {
                field,
                minimum,
                maximum,
                actual,
            } => {
                write!(
                    f,
                    "field '{field}' out of range: expected {minimum}..={maximum}, found {actual}"
                )
            }
            Self::Contract(err) => write!(f, "contract error: {err}"),
        }
    }
}

impl std::error::Error for EventDecodeError {}

impl From<ContractError> for EventDecodeError {
    fn from(err: ContractError) -> Self {
        Self::Contract(err)
    }
}

/// Event lifecycle. Detection, corroboration, and alerting are separate.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum EventState {
    /// Candidate created by a detector or rule.
    Hypothesized = 1,
    /// Candidate has at least one retained observation witness.
    Witnessed = 2,
    /// Candidate has independent corroboration or an explicit exception proof.
    Corroborated = 3,
    /// Policy selected a disposition.
    Adjudicated = 4,
    /// Alert delivery has a durable receipt.
    AlertDelivered = 5,
    /// A human or trusted downstream system resolved the event.
    Resolved = 6,
    /// Evidence was insufficient or an outcome remains unresolved.
    Indeterminate = 7,
    /// Evidence established that the candidate was benign or erroneous.
    Rejected = 8,
}

impl EventState {
    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hypothesized => "hypothesized",
            Self::Witnessed => "witnessed",
            Self::Corroborated => "corroborated",
            Self::Adjudicated => "adjudicated",
            Self::AlertDelivered => "alert_delivered",
            Self::Resolved => "resolved",
            Self::Indeterminate => "indeterminate",
            Self::Rejected => "rejected",
        }
    }

    /// Parses from schema string.
    pub fn parse(s: &str) -> Result<Self, EventDecodeError> {
        match s {
            "hypothesized" => Ok(Self::Hypothesized),
            "witnessed" => Ok(Self::Witnessed),
            "corroborated" => Ok(Self::Corroborated),
            "adjudicated" => Ok(Self::Adjudicated),
            "alert_delivered" => Ok(Self::AlertDelivered),
            "resolved" => Ok(Self::Resolved),
            "indeterminate" => Ok(Self::Indeterminate),
            "rejected" => Ok(Self::Rejected),
            _ => Err(EventDecodeError::NonCanonicalEncoding {
                detail: format!("unknown event state '{s}'"),
            }),
        }
    }

    /// Converts to canonical u8 tag.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Decodes from canonical u8 tag.
    pub fn from_u8(v: u8) -> Result<Self, EventDecodeError> {
        match v {
            1 => Ok(Self::Hypothesized),
            2 => Ok(Self::Witnessed),
            3 => Ok(Self::Corroborated),
            4 => Ok(Self::Adjudicated),
            5 => Ok(Self::AlertDelivered),
            6 => Ok(Self::Resolved),
            7 => Ok(Self::Indeterminate),
            8 => Ok(Self::Rejected),
            _ => Err(EventDecodeError::NonCanonicalEncoding {
                detail: format!("unknown event state tag {v}"),
            }),
        }
    }

    /// Returns true if this state is terminal (no forward transitions permitted).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Resolved | Self::Rejected)
    }

    /// Returns canonical progression rank (1 for Hypothesized through 6 for Resolved).
    ///
    /// Returns `None` for non-canonical alternative states (`Indeterminate`, `Rejected`).
    #[must_use]
    pub const fn canonical_rank(self) -> Option<u8> {
        match self {
            Self::Hypothesized => Some(1),
            Self::Witnessed => Some(2),
            Self::Corroborated => Some(3),
            Self::Adjudicated => Some(4),
            Self::AlertDelivered => Some(5),
            Self::Resolved => Some(6),
            Self::Indeterminate | Self::Rejected => None,
        }
    }

    /// Returns true if this state can legally transition to the target state.
    #[must_use]
    pub fn can_transition_to(self, next: Self, urgent_single_sensor: bool) -> bool {
        is_allowed_event_transition(self, next, urgent_single_sensor)
    }
}

/// Static rule governing a legal state transition in the event lifecycle state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventTransitionRule {
    /// Origin lifecycle state.
    pub from: EventState,
    /// Destination lifecycle state.
    pub to: EventState,
    /// Whether this transition requires an explicit urgent single-sensor policy exception.
    pub requires_urgent_exception: bool,
    /// Whether the destination state is terminal.
    pub terminal: bool,
    /// Semantic description of the transition.
    pub description: &'static str,
}

/// Registered canonical event state transition table.
///
/// Models the canonical lifecycle:
/// `Hypothesized -> Witnessed -> Corroborated -> Adjudicated -> AlertDelivered -> Resolved`,
/// with `Rejected` and `Indeterminate` alternatives.
pub static EVENT_TRANSITION_TABLE: &[EventTransitionRule] = &[
    // From Hypothesized
    EventTransitionRule {
        from: EventState::Hypothesized,
        to: EventState::Witnessed,
        requires_urgent_exception: false,
        terminal: false,
        description: "Initial observation witness attached to candidate hypothesis",
    },
    EventTransitionRule {
        from: EventState::Hypothesized,
        to: EventState::Indeterminate,
        requires_urgent_exception: false,
        terminal: false,
        description: "Observation ambiguous or coverage unverified",
    },
    EventTransitionRule {
        from: EventState::Hypothesized,
        to: EventState::Rejected,
        requires_urgent_exception: false,
        terminal: true,
        description: "Preliminary evaluation refutes hypothesis",
    },
    // From Witnessed
    EventTransitionRule {
        from: EventState::Witnessed,
        to: EventState::Corroborated,
        requires_urgent_exception: false,
        terminal: false,
        description: "Independent corroboration from >= 2 failure domains attached",
    },
    EventTransitionRule {
        from: EventState::Witnessed,
        to: EventState::Adjudicated,
        requires_urgent_exception: true,
        terminal: false,
        description: "Urgent single-sensor policy exception advances unconfirmed event",
    },
    EventTransitionRule {
        from: EventState::Witnessed,
        to: EventState::Indeterminate,
        requires_urgent_exception: false,
        terminal: false,
        description: "Evidence ambiguous, sensor health degraded, or coverage lost",
    },
    EventTransitionRule {
        from: EventState::Witnessed,
        to: EventState::Rejected,
        requires_urgent_exception: false,
        terminal: true,
        description: "Contradictory evidence refutes candidate",
    },
    // From Corroborated
    EventTransitionRule {
        from: EventState::Corroborated,
        to: EventState::Adjudicated,
        requires_urgent_exception: false,
        terminal: false,
        description: "Policy selects a disposition based on corroborated evidence",
    },
    EventTransitionRule {
        from: EventState::Corroborated,
        to: EventState::Indeterminate,
        requires_urgent_exception: false,
        terminal: false,
        description: "Late contradiction or sensor tamper creates uncertainty",
    },
    EventTransitionRule {
        from: EventState::Corroborated,
        to: EventState::Rejected,
        requires_urgent_exception: false,
        terminal: true,
        description: "Ground truth or contradictory evidence refutes corroborated event",
    },
    // From Adjudicated
    EventTransitionRule {
        from: EventState::Adjudicated,
        to: EventState::AlertDelivered,
        requires_urgent_exception: false,
        terminal: false,
        description: "Alert delivery succeeded with durable provider receipt",
    },
    EventTransitionRule {
        from: EventState::Adjudicated,
        to: EventState::Resolved,
        requires_urgent_exception: false,
        terminal: true,
        description: "Event resolved without alert dispatch or by policy",
    },
    EventTransitionRule {
        from: EventState::Adjudicated,
        to: EventState::Indeterminate,
        requires_urgent_exception: false,
        terminal: false,
        description: "Alert dispatch indeterminate, lost ACK, or outcome unresolved",
    },
    EventTransitionRule {
        from: EventState::Adjudicated,
        to: EventState::Rejected,
        requires_urgent_exception: false,
        terminal: true,
        description: "Adjudicated event refuted before/during alert action",
    },
    // From AlertDelivered
    EventTransitionRule {
        from: EventState::AlertDelivered,
        to: EventState::Resolved,
        requires_urgent_exception: false,
        terminal: true,
        description: "Operator or trusted downstream system resolves delivered alert",
    },
    EventTransitionRule {
        from: EventState::AlertDelivered,
        to: EventState::Indeterminate,
        requires_urgent_exception: false,
        terminal: false,
        description: "Post-delivery investigation needed or outcome ambiguous",
    },
    EventTransitionRule {
        from: EventState::AlertDelivered,
        to: EventState::Rejected,
        requires_urgent_exception: false,
        terminal: true,
        description: "Delivered alert determined to be benign or false positive",
    },
    // From Indeterminate (reconciliation transitions)
    EventTransitionRule {
        from: EventState::Indeterminate,
        to: EventState::Witnessed,
        requires_urgent_exception: false,
        terminal: false,
        description: "Reconciled to witnessed when observation witness confirmed",
    },
    EventTransitionRule {
        from: EventState::Indeterminate,
        to: EventState::Corroborated,
        requires_urgent_exception: false,
        terminal: false,
        description: "Reconciled to corroborated with >= 2 failure domain evidence",
    },
    EventTransitionRule {
        from: EventState::Indeterminate,
        to: EventState::Adjudicated,
        requires_urgent_exception: false,
        terminal: false,
        description: "Reconciled to adjudicated under policy",
    },
    EventTransitionRule {
        from: EventState::Indeterminate,
        to: EventState::AlertDelivered,
        requires_urgent_exception: false,
        terminal: false,
        description: "Reconciled to alert delivered when delivery ACK recovered",
    },
    EventTransitionRule {
        from: EventState::Indeterminate,
        to: EventState::Resolved,
        requires_urgent_exception: false,
        terminal: true,
        description: "Indeterminate condition resolved by operator or downstream",
    },
    EventTransitionRule {
        from: EventState::Indeterminate,
        to: EventState::Rejected,
        requires_urgent_exception: false,
        terminal: true,
        description: "Indeterminate candidate refuted by contradictory evidence",
    },
    EventTransitionRule {
        from: EventState::Indeterminate,
        to: EventState::Indeterminate,
        requires_urgent_exception: false,
        terminal: false,
        description: "Indeterminate candidate updated with new evidence or reconciliation steps",
    },
];

/// Returns the registered transition rule between two states, if one exists.
#[must_use]
pub fn get_event_transition_rule(
    from: EventState,
    to: EventState,
) -> Option<&'static EventTransitionRule> {
    EVENT_TRANSITION_TABLE
        .iter()
        .find(|r| r.from == from && r.to == to)
}

/// Returns true if a direct transition between two states is legally allowed.
#[must_use]
pub fn is_allowed_event_transition(
    from: EventState,
    to: EventState,
    urgent_single_sensor: bool,
) -> bool {
    match get_event_transition_rule(from, to) {
        Some(rule) => !rule.requires_urgent_exception || urgent_single_sensor,
        None => false,
    }
}

/// Typed event lifecycle and revision lineage transition errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventTransitionError {
    /// Attempted transition from an immutable terminal state.
    TerminalStateImmutable {
        /// The terminal state.
        state: EventState,
    },
    /// Attempted illegal state transition not permitted by the transition table.
    IllegalStateTransition {
        /// Origin state.
        from: EventState,
        /// Attempted destination state.
        to: EventState,
        /// Reason detail.
        reason: &'static str,
    },
    /// Attempted non-monotonic state transition (regressing to a predecessor state).
    NonMonotonicTransition {
        /// Origin state.
        from: EventState,
        /// Attempted destination state.
        to: EventState,
        /// Highest canonical state previously reached in this lineage.
        highest_reached: EventState,
    },
    /// Corroboration required >= 2 distinct failure domains, but fewer were observed.
    CorroborationRequired {
        /// Actual distinct failure domain count observed.
        observed_domains: usize,
    },
    /// Evidence is required after initial hypothesis, but none was provided.
    EvidenceRequired,
    /// A witnessed revision carries evidence but no edge that counts as support for it.
    SupportingEvidenceRequired,
    /// A transition to a state that establishes or acts on presence carries a sensor-tamper report.
    SensorIntegrityRisk,
    /// Revision numbering is not strictly monotonic (expected prior + 1).
    RevisionNotMonotonic {
        /// Expected revision number.
        expected: u64,
        /// Observed revision number.
        actual: u64,
    },
    /// Predecessor revision digest does not match the actual superseded revision.
    DigestMismatch {
        /// Expected predecessor digest.
        expected: ContentDigest,
        /// Actual digest found in supersedes link.
        actual: Option<ContentDigest>,
    },
    /// Lineage event ID mismatch across revisions.
    EventIdMismatch {
        /// Expected event ID.
        expected: EventId,
        /// Observed event ID.
        actual: EventId,
    },
    /// Urgent single-sensor policy exception was required for this transition but not asserted.
    UrgentExceptionRequired,
    /// Duplicate evidence item attached falsely counting the same evidence twice.
    DuplicateEvidence {
        /// Digest of the duplicate evidence item.
        digest: ContentDigest,
    },
    /// A bounded field strictly exceeds its declared hard bound.
    OverLimitLength {
        /// Field name.
        field: &'static str,
        /// Hard limit bound.
        limit: usize,
        /// Actual observed length.
        actual: usize,
    },
    /// Contradictory invariants or assertions.
    Contradiction {
        /// Field name.
        field: &'static str,
        /// Diagnostic detail.
        detail: String,
    },
    /// Underlying contract error.
    Contract(ContractError),
    /// Underlying decode error.
    Decode(EventDecodeError),
}

impl fmt::Display for EventTransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TerminalStateImmutable { state } => {
                write!(
                    f,
                    "terminal event state '{:?}' is immutable and permits no further transitions",
                    state
                )
            }
            Self::IllegalStateTransition { from, to, reason } => {
                write!(
                    f,
                    "illegal event transition from '{:?}' to '{:?}': {}",
                    from, to, reason
                )
            }
            Self::NonMonotonicTransition {
                from,
                to,
                highest_reached,
            } => {
                write!(
                    f,
                    "non-monotonic event transition from '{:?}' to '{:?}': highest reached state was '{:?}'",
                    from, to, highest_reached
                )
            }
            Self::CorroborationRequired { observed_domains } => {
                write!(
                    f,
                    "corroboration requires >= 2 distinct failure domains, found {}",
                    observed_domains
                )
            }
            Self::EvidenceRequired => {
                write!(
                    f,
                    "evidence is required for event states beyond initial hypothesis"
                )
            }
            Self::SupportingEvidenceRequired => {
                write!(
                    f,
                    "a witnessed revision requires at least one supporting evidence edge"
                )
            }
            Self::SensorIntegrityRisk => {
                write!(
                    f,
                    "a sensor-tamper report vetoes corroborated, adjudicated, and alert-delivered states"
                )
            }
            Self::RevisionNotMonotonic { expected, actual } => {
                write!(
                    f,
                    "event revision must be strictly monotonic: expected {}, got {}",
                    expected, actual
                )
            }
            Self::DigestMismatch { expected, actual } => {
                write!(
                    f,
                    "superseded digest mismatch: expected {:?}, found {:?}",
                    expected, actual
                )
            }
            Self::EventIdMismatch { expected, actual } => {
                write!(
                    f,
                    "event ID mismatch: expected {}, found {}",
                    expected, actual
                )
            }
            Self::UrgentExceptionRequired => {
                write!(
                    f,
                    "urgent single-sensor policy exception required to advance uncorroborated event"
                )
            }
            Self::DuplicateEvidence { digest } => {
                write!(
                    f,
                    "duplicate evidence falsely counted twice: digest {:?}",
                    digest
                )
            }
            Self::OverLimitLength {
                field,
                limit,
                actual,
            } => {
                write!(
                    f,
                    "field '{}' length {} exceeds limit {}",
                    field, actual, limit
                )
            }
            Self::Contradiction { field, detail } => {
                write!(f, "contradiction in field '{}': {}", field, detail)
            }
            Self::Contract(err) => write!(f, "contract violation: {}", err),
            Self::Decode(err) => write!(f, "decode error: {}", err),
        }
    }
}

impl std::error::Error for EventTransitionError {}

impl From<ContractError> for EventTransitionError {
    fn from(err: ContractError) -> Self {
        Self::Contract(err)
    }
}

impl From<EventDecodeError> for EventTransitionError {
    fn from(err: EventDecodeError) -> Self {
        match err {
            EventDecodeError::Contract(ContractError::CorroborationRequired) => {
                Self::CorroborationRequired {
                    observed_domains: 1,
                }
            }
            EventDecodeError::Contract(ContractError::EvidenceRequired) => Self::EvidenceRequired,
            EventDecodeError::Contract(ContractError::SupportingEvidenceRequired) => {
                Self::SupportingEvidenceRequired
            }
            EventDecodeError::Contract(ContractError::SensorIntegrityRisk) => {
                Self::SensorIntegrityRisk
            }
            other => Self::Decode(other),
        }
    }
}

/// Coarse event semantics used before deployment-specific extension.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum EventKind {
    /// An entity entered a protected boundary.
    PerimeterBreach = 1,
    /// Motion or appearance is consistent with covert approach.
    CovertApproach = 2,
    /// A sensor appears covered, moved, dazzled, disconnected, or replayed.
    SensorTamper = 3,
    /// Presence is real but authorization is unknown.
    UnknownPresence = 4,
    /// A routine resident, delivery, animal, weather, or other benign explanation is likely.
    BenignRoutine = 5,
    /// The taxonomy cannot express the observation without distortion.
    Unclassified = 6,
}

impl EventKind {
    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PerimeterBreach => "perimeter_breach",
            Self::CovertApproach => "covert_approach",
            Self::SensorTamper => "sensor_tamper",
            Self::UnknownPresence => "unknown_presence",
            Self::BenignRoutine => "benign_routine",
            Self::Unclassified => "unclassified",
        }
    }

    /// Parses from schema string.
    pub fn parse(s: &str) -> Result<Self, EventDecodeError> {
        match s {
            "perimeter_breach" => Ok(Self::PerimeterBreach),
            "covert_approach" => Ok(Self::CovertApproach),
            "sensor_tamper" => Ok(Self::SensorTamper),
            "unknown_presence" => Ok(Self::UnknownPresence),
            "benign_routine" => Ok(Self::BenignRoutine),
            "unclassified" => Ok(Self::Unclassified),
            _ => Err(EventDecodeError::NonCanonicalEncoding {
                detail: format!("unknown event kind '{s}'"),
            }),
        }
    }

    /// Converts to canonical u8 tag.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Decodes from canonical u8 tag.
    pub fn from_u8(v: u8) -> Result<Self, EventDecodeError> {
        match v {
            1 => Ok(Self::PerimeterBreach),
            2 => Ok(Self::CovertApproach),
            3 => Ok(Self::SensorTamper),
            4 => Ok(Self::UnknownPresence),
            5 => Ok(Self::BenignRoutine),
            6 => Ok(Self::Unclassified),
            _ => Err(EventDecodeError::NonCanonicalEncoding {
                detail: format!("unknown event kind tag {v}"),
            }),
        }
    }
}

/// Returns whether a sensor-tamper report vetoes a revision in `state`: the states that establish
/// physical presence or act on it. Tampered sensing can do neither. The match is exhaustive with
/// no wildcard, so a new state must choose.
pub const fn sensor_tamper_vetoes(state: EventState) -> bool {
    match state {
        EventState::Corroborated | EventState::Adjudicated | EventState::AlertDelivered => true,
        EventState::Hypothesized
        | EventState::Witnessed
        | EventState::Resolved
        | EventState::Indeterminate
        | EventState::Rejected => false,
    }
}

/// Internal record of an open sensor-tamper report with provenance metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TamperRecord {
    /// Failure domain of the tampered sensor.
    pub failure_domain: String,
    /// Bound sensor identity digest, if reported.
    pub identity_digest: Option<ContentDigest>,
    /// Tamper evidence root digest.
    pub digest: ContentDigest,
    /// Revision number at which this tamper report entered the lineage.
    pub revision: u64,
    /// Capture interval of the batch reporting the tamper.
    pub interval: Option<CaptureInterval>,
}

impl CanonicalEncode for TamperRecord {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.failure_domain);
        match &self.identity_digest {
            Some(d) => {
                encoder.u8(1);
                d.encode_canonical(encoder);
            }
            None => encoder.u8(0),
        }
        self.digest.encode_canonical(encoder);
        encoder.u64(self.revision);
        match &self.interval {
            Some(i) => {
                encoder.u8(1);
                i.encode_canonical(encoder);
            }
            None => encoder.u8(0),
        }
    }
}

/// Tracks active and retired sensor-tamper risks across revisions.
///
/// Every field is covered by [`SensorTamperStatus::canonical_digest`], so a receipt that edits any
/// of them no longer matches the `sensor_tamper_status` witness published with the revision.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SensorTamperStatus {
    /// Failure domains with unretired sensor-tamper reports.
    pub open_domains: BTreeSet<String>,
    /// Retained evidence root digests of unretired sensor-tamper reports.
    pub open_tamper_roots: Vec<ContentDigest>,
    /// Evidenced restorations: (failure_domain, restoration_digest).
    pub restorations: Vec<(String, ContentDigest)>,
    /// Open tamper reports: (failure_domain, tamper_digest).
    pub open_tamper_reports: Vec<(String, ContentDigest)>,
    /// Open tamper records with metadata.
    pub open_tamper_records: Vec<TamperRecord>,
    /// Historical restoration digests that have retired tamper reports.
    pub seen_restorations: BTreeSet<ContentDigest>,
    /// Retained evidence digests across the lineage ensuring restorations never reuse any digest.
    pub seen_lineage_digests: BTreeSet<ContentDigest>,
}

impl CanonicalEncode for SensorTamperStatus {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text("fss.sensor_tamper_status.v1");
        encoder.u64(self.open_domains.len() as u64);
        for d in &self.open_domains {
            encoder.text(d);
        }
        encoder.u64(self.open_tamper_roots.len() as u64);
        for r in &self.open_tamper_roots {
            r.encode_canonical(encoder);
        }
        encoder.u64(self.restorations.len() as u64);
        for (dom, dig) in &self.restorations {
            encoder.text(dom);
            dig.encode_canonical(encoder);
        }
        encoder.u64(self.open_tamper_records.len() as u64);
        for rec in &self.open_tamper_records {
            rec.encode_canonical(encoder);
        }
        encoder.u64(self.open_tamper_reports.len() as u64);
        for (dom, dig) in &self.open_tamper_reports {
            encoder.text(dom);
            dig.encode_canonical(encoder);
        }
        encoder.u64(self.seen_restorations.len() as u64);
        for dig in &self.seen_restorations {
            dig.encode_canonical(encoder);
        }
        encoder.u64(self.seen_lineage_digests.len() as u64);
        for dig in &self.seen_lineage_digests {
            dig.encode_canonical(encoder);
        }
    }
}

impl SensorTamperStatus {
    /// Returns true if any sensor-tamper risk remains unretired.
    #[must_use]
    pub fn has_open_tamper(&self) -> bool {
        !self.open_domains.is_empty() || !self.open_tamper_roots.is_empty()
    }

    /// Returns unretired tamper evidence root digests.
    #[must_use]
    pub fn open_roots(&self) -> &[ContentDigest] {
        &self.open_tamper_roots
    }

    /// Returns evidenced restoration digests.
    #[must_use]
    pub fn restoration_roots(&self) -> Vec<ContentDigest> {
        self.restorations.iter().map(|(_, d)| *d).collect()
    }

    /// Computes the deterministic canonical digest of this tamper status.
    #[must_use]
    pub fn canonical_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }
}

/// Maps a lineage replay refusal onto the chain-verification error vocabulary.
fn transition_error_as_decode(err: EventTransitionError) -> EventDecodeError {
    match err {
        EventTransitionError::Contract(contract) => EventDecodeError::Contract(contract),
        EventTransitionError::SensorIntegrityRisk => {
            EventDecodeError::Contract(ContractError::SensorIntegrityRisk)
        }
        other => EventDecodeError::Contradiction {
            field: "chain.lineage",
            detail: other.to_string(),
        },
    }
}

/// Accumulates sensor-tamper status across an ordered sequence of event revisions and/or evidence edges.
pub fn compute_sensor_tamper_status<'a>(
    history: impl IntoIterator<Item = &'a EventHypothesis>,
    current_evidence: Option<&'a [EventEvidence]>,
) -> SensorTamperStatus {
    compute_sensor_tamper_status_with_interval(history, current_evidence, None)
}

/// Accumulates sensor-tamper status with an optional capture interval for the current evidence.
///
/// The current evidence is applied with exactly `current_interval`. It never borrows the previous
/// revision's interval: without its own capture interval the current batch is not ordered after any
/// tamper, so no restoration in it can retire one.
pub fn compute_sensor_tamper_status_with_interval<'a>(
    history: impl IntoIterator<Item = &'a EventHypothesis>,
    current_evidence: Option<&'a [EventEvidence]>,
    current_interval: Option<CaptureInterval>,
) -> SensorTamperStatus {
    let mut status = SensorTamperStatus::default();
    let mut max_rev = 0u64;

    for rev in history {
        apply_evidence_batch(&mut status, &rev.evidence, rev.revision, Some(rev.interval));
        max_rev = max_rev.max(rev.revision);
    }

    if let Some(evidence) = current_evidence {
        apply_evidence_batch(
            &mut status,
            evidence,
            max_rev.saturating_add(1),
            current_interval,
        );
    }

    status
}

/// Applies one lineage revision to the running tamper status and enforces both lineage tamper
/// invariants, refusing with [`ContractError::SensorIntegrityRisk`]:
///
/// 1. a revision in a state that [`sensor_tamper_vetoes`] may not leave any tamper open;
/// 2. every tamper that was open before the revision and that the revision does not retire with an
///    evidenced restoration must be carried forward on it as a `SensorTamper` edge with the same
///    digest, so no revision can silently drop an unretired tamper.
///
/// The revision's own number and capture interval order its batch. This is the one definition that
/// [`EventHypothesis::verify_chain`], [`EventLineage::from_revisions`] and
/// [`EventLineage::replay_from_deltas`] share, so they reach the same verdict on every chain.
pub fn apply_revision_tamper_step(
    status: &mut SensorTamperStatus,
    rev: &EventHypothesis,
) -> Result<(), ContractError> {
    let open_before: Vec<ContentDigest> = status
        .open_tamper_records
        .iter()
        .map(|t| t.digest)
        .collect();
    apply_evidence_batch(status, &rev.evidence, rev.revision, Some(rev.interval));
    if sensor_tamper_vetoes(rev.state) && status.has_open_tamper() {
        return Err(ContractError::SensorIntegrityRisk);
    }
    let dropped = status.open_tamper_records.iter().any(|t| {
        open_before.contains(&t.digest)
            && !rev
                .evidence
                .iter()
                .any(|e| e.digest == t.digest && e.reports_sensor_tamper())
    });
    if dropped {
        return Err(ContractError::SensorIntegrityRisk);
    }
    Ok(())
}

pub(crate) fn apply_evidence_batch(
    status: &mut SensorTamperStatus,
    evidence: &[EventEvidence],
    batch_revision: u64,
    batch_interval: Option<CaptureInterval>,
) {
    for edge in evidence {
        if edge.reports_integrity_restoration() {
            let edge_id = edge.identity_digest;
            let count_in_batch = evidence.iter().filter(|e| e.digest == edge.digest).count();
            // `seen_lineage_digests` holds every digest an earlier batch of this lineage retained,
            // which includes every open tamper digest and every restoration that already retired a
            // tamper. That one check therefore refuses a restoration reusing a tamper's own digest
            // or re-citing an earlier restoration; no separate check for either is needed.
            //
            // A restoration retires a tamper only when its batch is captured strictly after the
            // tamper's capture ended. An overlapping or earlier capture cannot attest that integrity
            // was re-established after the tamper, and a batch or tamper with no capture interval
            // is not ordered at all, so neither retires anything.
            if count_in_batch == 1
                && !status.seen_lineage_digests.contains(&edge.digest)
                && let Some(pos) = status.open_tamper_records.iter().position(|t| {
                    t.revision < batch_revision
                        && t.failure_domain == edge.failure_domain
                        && t.identity_digest.is_some()
                        && t.identity_digest == edge_id
                        && batch_interval
                            .is_some_and(|bi| t.interval.is_some_and(|ti| bi.earliest > ti.latest))
                })
            {
                let _retired = status.open_tamper_records.remove(pos);
                status.seen_restorations.insert(edge.digest);
                if !status
                    .restorations
                    .iter()
                    .any(|(d, dig)| d == &edge.failure_domain && dig == &edge.digest)
                {
                    status
                        .restorations
                        .push((edge.failure_domain.clone(), edge.digest));
                }
            }
        }
    }
    for edge in evidence {
        if edge.reports_sensor_tamper()
            && !status
                .open_tamper_records
                .iter()
                .any(|t| t.failure_domain == edge.failure_domain && t.digest == edge.digest)
        {
            status.open_tamper_records.push(TamperRecord {
                failure_domain: edge.failure_domain.clone(),
                identity_digest: edge.identity_digest,
                digest: edge.digest,
                revision: batch_revision,
                interval: batch_interval,
            });
        }
    }
    for edge in evidence {
        status.seen_lineage_digests.insert(edge.digest);
    }
    status.open_domains = status
        .open_tamper_records
        .iter()
        .map(|t| t.failure_domain.clone())
        .collect();
    status.open_tamper_reports = status
        .open_tamper_records
        .iter()
        .map(|t| (t.failure_domain.clone(), t.digest))
        .collect();
    let mut roots = Vec::new();
    for t in &status.open_tamper_records {
        if !roots.contains(&t.digest) {
            roots.push(t.digest);
        }
    }
    status.open_tamper_roots = roots;
}

/// Semantic relationship of an evidence graph edge.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum EvidenceEdgeRelation {
    /// Edge indicates target is derived from source.
    DerivedFrom = 1,
    /// Edge indicates source evidence supports target conclusion.
    Supports = 2,
    /// Edge indicates source evidence contradicts target hypothesis.
    Contradicts = 3,
    /// Edge invalidates a prior belief or claim.
    Invalidates = 4,
    /// Edge supersedes an earlier revision.
    Supersedes = 5,
    /// Edge denotes temporal observation precedence.
    ObservedAfter = 6,
    /// Edge denotes a mandatory dependency.
    RequiredBy = 7,
    /// Edge provides causal explanation.
    Explains = 8,
    /// Edge reports a sensor-integrity risk (tamper, replay, cover, dazzle, or disconnect) for
    /// the evidence source; it neither supports nor contradicts the event itself.
    SensorTamper = 9,
    /// Edge reports explicit, evidenced restoration of sensor integrity retiring prior tamper.
    SensorIntegrityRestoration = 10,
}

impl EvidenceEdgeRelation {
    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DerivedFrom => "derived_from",
            Self::Supports => "supports",
            Self::Contradicts => "contradicts",
            Self::Invalidates => "invalidates",
            Self::Supersedes => "supersedes",
            Self::ObservedAfter => "observed_after",
            Self::RequiredBy => "required_by",
            Self::Explains => "explains",
            Self::SensorTamper => "sensor_tamper",
            Self::SensorIntegrityRestoration => "sensor_integrity_restoration",
        }
    }

    /// Parses from schema string.
    pub fn parse(s: &str) -> Result<Self, EventDecodeError> {
        match s {
            "derived_from" => Ok(Self::DerivedFrom),
            "supports" => Ok(Self::Supports),
            "contradicts" => Ok(Self::Contradicts),
            "invalidates" => Ok(Self::Invalidates),
            "supersedes" => Ok(Self::Supersedes),
            "observed_after" => Ok(Self::ObservedAfter),
            "required_by" => Ok(Self::RequiredBy),
            "explains" => Ok(Self::Explains),
            "sensor_tamper" => Ok(Self::SensorTamper),
            "sensor_integrity_restoration" => Ok(Self::SensorIntegrityRestoration),
            _ => Err(EventDecodeError::NonCanonicalEncoding {
                detail: format!("unknown evidence edge relation '{s}'"),
            }),
        }
    }

    /// Returns the `supports` flag an edge with this relation must carry.
    ///
    /// Only `Supports` counts as support for the event and only `Contradicts` counts against it.
    /// Every other relation records lineage, revision, ordering, dependency, invalidation, or
    /// explanation structure, or (`SensorTamper`) a sensor-integrity risk about the evidence
    /// source, or (`SensorIntegrityRestoration`) an evidenced retirement of that risk, and carries
    /// no evidential direction for the event, so it must be `supports=false` and counts as neither
    /// support nor contradiction. The match is exhaustive with no wildcard: a new relation must
    /// choose its evidential direction here.
    #[must_use]
    pub const fn required_supports_flag(self) -> bool {
        match self {
            Self::Supports => true,
            Self::Contradicts
            | Self::DerivedFrom
            | Self::Invalidates
            | Self::Supersedes
            | Self::ObservedAfter
            | Self::RequiredBy
            | Self::Explains
            | Self::SensorTamper
            | Self::SensorIntegrityRestoration => false,
        }
    }

    /// Converts to canonical u8 tag.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Decodes from canonical u8 tag.
    pub fn from_u8(v: u8) -> Result<Self, EventDecodeError> {
        match v {
            1 => Ok(Self::DerivedFrom),
            2 => Ok(Self::Supports),
            3 => Ok(Self::Contradicts),
            4 => Ok(Self::Invalidates),
            5 => Ok(Self::Supersedes),
            6 => Ok(Self::ObservedAfter),
            7 => Ok(Self::RequiredBy),
            8 => Ok(Self::Explains),
            9 => Ok(Self::SensorTamper),
            10 => Ok(Self::SensorIntegrityRestoration),
            _ => Err(EventDecodeError::NonCanonicalEncoding {
                detail: format!("unknown evidence edge relation tag {v}"),
            }),
        }
    }
}

/// Kind of node in an evidence graph.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum EvidenceNodeKind {
    /// Raw or proxy sensor capsule.
    SensorCapsule = 1,
    /// Source device / channel identity.
    SourceIdentity = 2,
    /// Device hardware / firmware identity.
    DeviceIdentity = 3,
    /// Adapter protocol identity.
    AdapterIdentity = 4,
    /// Execution receipt of a neural model or heuristic.
    ModelReceipt = 5,
    /// Event revision / hypothesis.
    EventHypothesis = 6,
    /// Adjudication decision receipt.
    Adjudication = 7,
    /// Direct sensor observation.
    Observation = 8,
}

impl EvidenceNodeKind {
    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SensorCapsule => "sensor_capsule",
            Self::SourceIdentity => "source_identity",
            Self::DeviceIdentity => "device_identity",
            Self::AdapterIdentity => "adapter_identity",
            Self::ModelReceipt => "model_receipt",
            Self::EventHypothesis => "event_hypothesis",
            Self::Adjudication => "adjudication",
            Self::Observation => "observation",
        }
    }

    /// Parses from schema string.
    pub fn parse(s: &str) -> Result<Self, EventDecodeError> {
        match s {
            "sensor_capsule" => Ok(Self::SensorCapsule),
            "source_identity" => Ok(Self::SourceIdentity),
            "device_identity" => Ok(Self::DeviceIdentity),
            "adapter_identity" => Ok(Self::AdapterIdentity),
            "model_receipt" => Ok(Self::ModelReceipt),
            "event_hypothesis" => Ok(Self::EventHypothesis),
            "adjudication" => Ok(Self::Adjudication),
            "observation" => Ok(Self::Observation),
            _ => Err(EventDecodeError::NonCanonicalEncoding {
                detail: format!("unknown evidence node kind '{s}'"),
            }),
        }
    }

    /// Converts to canonical u8 tag.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Decodes from canonical u8 tag.
    pub fn from_u8(v: u8) -> Result<Self, EventDecodeError> {
        match v {
            1 => Ok(Self::SensorCapsule),
            2 => Ok(Self::SourceIdentity),
            3 => Ok(Self::DeviceIdentity),
            4 => Ok(Self::AdapterIdentity),
            5 => Ok(Self::ModelReceipt),
            6 => Ok(Self::EventHypothesis),
            7 => Ok(Self::Adjudication),
            8 => Ok(Self::Observation),
            _ => Err(EventDecodeError::NonCanonicalEncoding {
                detail: format!("unknown evidence node kind tag {v}"),
            }),
        }
    }
}

/// Helper methods for `EvidenceClass` string and binary codec.
#[must_use]
pub const fn evidence_class_as_str(class: EvidenceClass) -> &'static str {
    match class {
        EvidenceClass::Assertion => "assertion",
        EvidenceClass::Derived => "derived",
        EvidenceClass::Observed => "observed",
        EvidenceClass::Corroborated => "corroborated",
        EvidenceClass::Verified => "verified",
    }
}

/// Parses `EvidenceClass` from schema string.
pub fn parse_evidence_class(s: &str) -> Result<EvidenceClass, EventDecodeError> {
    match s {
        "assertion" => Ok(EvidenceClass::Assertion),
        "derived" => Ok(EvidenceClass::Derived),
        "observed" => Ok(EvidenceClass::Observed),
        "corroborated" => Ok(EvidenceClass::Corroborated),
        "verified" => Ok(EvidenceClass::Verified),
        _ => Err(EventDecodeError::NonCanonicalEncoding {
            detail: format!("unknown evidence class '{s}'"),
        }),
    }
}

/// Converts `EvidenceClass` to canonical u8 tag.
#[must_use]
pub const fn evidence_class_to_u8(class: EvidenceClass) -> u8 {
    match class {
        EvidenceClass::Assertion => 1,
        EvidenceClass::Derived => 2,
        EvidenceClass::Observed => 3,
        EvidenceClass::Corroborated => 4,
        EvidenceClass::Verified => 5,
    }
}

/// Decodes `EvidenceClass` from canonical u8 tag.
pub fn evidence_class_from_u8(v: u8) -> Result<EvidenceClass, EventDecodeError> {
    match v {
        1 => Ok(EvidenceClass::Assertion),
        2 => Ok(EvidenceClass::Derived),
        3 => Ok(EvidenceClass::Observed),
        4 => Ok(EvidenceClass::Corroborated),
        5 => Ok(EvidenceClass::Verified),
        _ => Err(EventDecodeError::NonCanonicalEncoding {
            detail: format!("unknown evidence class tag {v}"),
        }),
    }
}

/// A probability interval rather than an unqualified point score.
///
/// # Plane boundary (ADR-0001, NEG-003)
///
/// A `ProbabilityInterval` is the model-score form of cognition output carried by event
/// hypotheses. Invariant 5: model output can never directly become an `EffectIntent`; it must
/// route through situation, affordance, and a witnessed plan before effect preparation.
///
/// ```compile_fail,E0277
/// use fss_core::ProbabilityInterval;
/// use fss_core::effect::EffectIntent;
///
/// fn forbidden_model_effect(score: ProbabilityInterval) {
///     // adr-0001/inv-5: no `From<ProbabilityInterval>` exists for `EffectIntent`.
///     let intent: EffectIntent = score.into();
///     let _ = intent;
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ProbabilityInterval {
    /// Conservative lower bound.
    pub lower: f64,
    /// Conservative upper bound.
    pub upper: f64,
    /// Calibration generation content digest.
    pub calibration_generation: Option<ContentDigest>,
}

impl ProbabilityInterval {
    /// Constructs an uncalibrated bounded interval.
    pub fn new(lower: f64, upper: f64) -> Result<Self, ContractError> {
        if !lower.is_finite()
            || !upper.is_finite()
            || !(0.0..=1.0).contains(&lower)
            || !(0.0..=1.0).contains(&upper)
            || lower > upper
        {
            return Err(ContractError::InvalidProbabilityInterval);
        }
        Ok(Self {
            lower,
            upper,
            calibration_generation: None,
        })
    }

    /// Constructs a calibrated bounded interval.
    pub fn with_calibration(
        lower: f64,
        upper: f64,
        calibration_generation: ContentDigest,
    ) -> Result<Self, ContractError> {
        if !lower.is_finite()
            || !upper.is_finite()
            || !(0.0..=1.0).contains(&lower)
            || !(0.0..=1.0).contains(&upper)
            || lower > upper
        {
            return Err(ContractError::InvalidProbabilityInterval);
        }
        Ok(Self {
            lower,
            upper,
            calibration_generation: Some(calibration_generation),
        })
    }

    /// Validates internal invariants.
    pub fn verify(&self) -> Result<(), EventDecodeError> {
        if !self.lower.is_finite()
            || !self.upper.is_finite()
            || !(0.0..=1.0).contains(&self.lower)
            || !(0.0..=1.0).contains(&self.upper)
            || self.lower > self.upper
        {
            return Err(EventDecodeError::Contract(
                ContractError::InvalidProbabilityInterval,
            ));
        }
        Ok(())
    }
}

impl CanonicalEncode for ProbabilityInterval {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(canonical_f64_bits(self.lower));
        encoder.u64(canonical_f64_bits(self.upper));
        match &self.calibration_generation {
            Some(cg) => {
                encoder.bool(true);
                encoder.digest(*cg);
            }
            None => {
                encoder.bool(false);
            }
        }
    }
}

/// Policy decision path fingerprint and abstention tracking.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionPath {
    /// Policy generation digest.
    pub policy_generation: ContentDigest,
    /// Deterministic execution fingerprint.
    pub fingerprint: ContentDigest,
    /// Whether the policy decision engine abstained.
    pub abstained: bool,
    /// Explicit abstention reason if abstained.
    pub abstention_reason: Option<String>,
}

impl DecisionPath {
    /// Validates decision path invariants.
    pub fn verify(&self) -> Result<(), EventDecodeError> {
        if self.abstained {
            match &self.abstention_reason {
                Some(reason) => {
                    if reason.is_empty() {
                        return Err(EventDecodeError::Contradiction {
                            field: "decisionPath.abstentionReason",
                            detail: "abstained decision requires non-empty abstentionReason"
                                .to_string(),
                        });
                    }
                    if reason.len() > MAX_ABSTENTION_REASON_LEN {
                        return Err(EventDecodeError::OverLimitLength {
                            field: "decisionPath.abstentionReason",
                            limit: MAX_ABSTENTION_REASON_LEN,
                            actual: reason.len(),
                        });
                    }
                }
                None => {
                    return Err(EventDecodeError::Contradiction {
                        field: "decisionPath.abstentionReason",
                        detail: "abstained decision must provide an abstention reason".to_string(),
                    });
                }
            }
        } else if self.abstention_reason.is_some() {
            return Err(EventDecodeError::Contradiction {
                field: "decisionPath.abstentionReason",
                detail: "non-abstained decision must not specify an abstention reason".to_string(),
            });
        }
        Ok(())
    }

    /// Decodes a decision path from canonical decoder with strict bounds and invariant checks.
    pub fn decode_canonical_checked(
        decoder: &mut CanonicalDecoder<'_>,
    ) -> Result<Self, EventDecodeError> {
        let policy_generation = decoder.digest().map_err(EventDecodeError::Contract)?;
        let fingerprint = decoder.digest().map_err(EventDecodeError::Contract)?;
        let abstained = decoder.bool().map_err(|_| EventDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?;
        let has_reason = decoder.bool().map_err(|_| EventDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?;
        let abstention_reason = if has_reason {
            let reason = decoder.text().map_err(|_| EventDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?;
            if reason.len() > MAX_ABSTENTION_REASON_LEN {
                return Err(EventDecodeError::OverLimitLength {
                    field: "decisionPath.abstentionReason",
                    limit: MAX_ABSTENTION_REASON_LEN,
                    actual: reason.len(),
                });
            }
            Some(reason.to_string())
        } else {
            None
        };
        let dp = Self {
            policy_generation,
            fingerprint,
            abstained,
            abstention_reason,
        };
        dp.verify()?;
        Ok(dp)
    }

    /// Emits a deterministic canonical JSON string projection.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push('{');
        out.push_str("\"abstained\":");
        out.push_str(if self.abstained { "true" } else { "false" });
        if let Some(reason) = &self.abstention_reason {
            out.push_str(",\"abstentionReason\":");
            json_write_str(&mut out, reason);
        }
        out.push_str(",\"fingerprint\":");
        json_write_str(&mut out, &self.fingerprint.to_string());
        out.push_str(",\"policyGeneration\":");
        json_write_str(&mut out, &self.policy_generation.to_string());
        out.push('}');
        out
    }

    /// Parses a decision path from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, EventDecodeError> {
        let val = parse_json_value(json)?;
        let obj = JsonObject::from_value(&val, "decisionPath")?;
        Self::from_json_obj(&obj)
    }

    /// Parses a decision path from a JsonObject.
    fn from_json_obj(obj: &JsonObject<'_>) -> Result<Self, EventDecodeError> {
        let abstained = obj.get("abstained")?.as_bool()?;
        let abstention_reason = match obj.get_opt("abstentionReason") {
            Some(JsonValue::Null) | None => None,
            Some(JsonValue::String(s)) => {
                if s.len() > MAX_ABSTENTION_REASON_LEN {
                    return Err(EventDecodeError::OverLimitLength {
                        field: "decisionPath.abstentionReason",
                        limit: MAX_ABSTENTION_REASON_LEN,
                        actual: s.len(),
                    });
                }
                Some(s.clone())
            }
            Some(_) => {
                return Err(EventDecodeError::JsonError {
                    detail: "decisionPath.abstentionReason must be string or null".to_string(),
                });
            }
        };
        let fingerprint =
            ContentDigest::parse(obj.str("fingerprint")?).map_err(EventDecodeError::Contract)?;
        let policy_generation = ContentDigest::parse(obj.str("policyGeneration")?)
            .map_err(EventDecodeError::Contract)?;
        let dp = Self {
            policy_generation,
            fingerprint,
            abstained,
            abstention_reason,
        };
        dp.verify()?;
        Ok(dp)
    }
}

impl CanonicalEncode for DecisionPath {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.digest(self.policy_generation);
        encoder.digest(self.fingerprint);
        encoder.bool(self.abstained);
        match &self.abstention_reason {
            Some(reason) => {
                encoder.bool(true);
                encoder.text(reason);
            }
            None => {
                encoder.bool(false);
            }
        }
    }
}

impl CanonicalDecode for DecisionPath {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Self::decode_canonical_checked(decoder).map_err(|e| match e {
            EventDecodeError::Contract(c) => c,
            _ => ContractError::InvalidIdentifier,
        })
    }
}

impl std::fmt::Display for DecisionPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.fingerprint)
    }
}

/// An evidence edge supporting or contradicting an event or graph relation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventEvidence {
    /// Evidence object digest.
    pub digest: ContentDigest,
    /// Strength/class of evidence.
    pub class: EvidenceClass,
    /// Failure-domain identity used to prevent false corroboration.
    pub failure_domain: String,
    /// Whether this edge supports the event.
    pub supports: bool,
    /// Semantic edge relationship.
    pub relation: EvidenceEdgeRelation,
    /// Optional underlying sensor capsule digest.
    pub capsule_digest: Option<ContentDigest>,
    /// Optional source/device/adapter identity digest.
    pub identity_digest: Option<ContentDigest>,
}

impl EventEvidence {
    /// Validates internal bounds and invariants.
    pub fn verify(&self) -> Result<(), EventDecodeError> {
        if self.failure_domain.is_empty() {
            return Err(EventDecodeError::Contradiction {
                field: "evidence.failureDomain",
                detail: "failure domain must not be empty".to_string(),
            });
        }
        if self.failure_domain.len() > MAX_FAILURE_DOMAIN_LEN {
            return Err(EventDecodeError::OverLimitLength {
                field: "evidence.failureDomain",
                limit: MAX_FAILURE_DOMAIN_LEN,
                actual: self.failure_domain.len(),
            });
        }
        // Consistency: the flag must agree with the relation for every variant.
        let required = self.relation.required_supports_flag();
        if self.supports != required {
            return Err(EventDecodeError::Contradiction {
                field: "evidence.supports",
                detail: format!(
                    "{} edge requires supports={required}",
                    self.relation.as_str()
                ),
            });
        }
        if self.relation == EvidenceEdgeRelation::SensorIntegrityRestoration {
            if self.digest.bytes() == [0u8; 32] {
                return Err(EventDecodeError::Contract(ContractError::InvalidDigest));
            }
            if self.identity_digest.is_none() {
                return Err(EventDecodeError::Contract(ContractError::EvidenceRequired));
            }
        }
        Ok(())
    }

    /// Returns true only for an edge that counts as support for the event: a `Supports`
    /// relation carrying `supports=true`.
    #[must_use]
    pub fn counts_as_support(&self) -> bool {
        self.supports && self.relation == EvidenceEdgeRelation::Supports
    }

    /// Returns true only for an edge that counts against the event: a `Contradicts` relation
    /// carrying `supports=false`. Neutral relations (lineage, abstentions) count as neither.
    #[must_use]
    pub fn counts_as_contradiction(&self) -> bool {
        !self.supports && self.relation == EvidenceEdgeRelation::Contradicts
    }

    /// Returns true only for an edge that reports a sensor-integrity risk: a `SensorTamper`
    /// relation carrying `supports=false`. Such an edge is neutral as evidence for the event but
    /// must be surfaced as a typed risk, never dropped.
    #[must_use]
    pub fn reports_sensor_tamper(&self) -> bool {
        !self.supports && self.relation == EvidenceEdgeRelation::SensorTamper
    }

    /// Returns true only for an edge that reports an explicit, evidenced sensor-integrity restoration:
    /// a `SensorIntegrityRestoration` relation carrying `supports=false`.
    #[must_use]
    pub fn reports_integrity_restoration(&self) -> bool {
        !self.supports
            && self.relation == EvidenceEdgeRelation::SensorIntegrityRestoration
            && self.digest.bytes() != [0u8; 32]
            && self.identity_digest.is_some()
            && !self.failure_domain.is_empty()
    }
}

impl CanonicalEncode for EventEvidence {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.digest(self.digest);
        encoder.u8(evidence_class_to_u8(self.class));
        encoder.text(&self.failure_domain);
        encoder.bool(self.supports);
        encoder.u8(self.relation.to_u8());
        match &self.capsule_digest {
            Some(cd) => {
                encoder.bool(true);
                encoder.digest(*cd);
            }
            None => {
                encoder.bool(false);
            }
        }
        match &self.identity_digest {
            Some(id) => {
                encoder.bool(true);
                encoder.digest(*id);
            }
            None => {
                encoder.bool(false);
            }
        }
    }
}

/// A node in an evidence graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceNode {
    /// Content digest of the referenced entity.
    pub digest: ContentDigest,
    /// Kind of entity.
    pub kind: EvidenceNodeKind,
    /// Descriptive human/agent label.
    pub label: String,
    /// Independent failure domain.
    pub failure_domain: String,
}

impl EvidenceNode {
    /// Validates node bounds.
    pub fn verify(&self) -> Result<(), EventDecodeError> {
        if self.label.len() > MAX_NODE_LABEL_LEN {
            return Err(EventDecodeError::OverLimitLength {
                field: "nodes.label",
                limit: MAX_NODE_LABEL_LEN,
                actual: self.label.len(),
            });
        }
        if self.failure_domain.len() > MAX_FAILURE_DOMAIN_LEN {
            return Err(EventDecodeError::OverLimitLength {
                field: "nodes.failureDomain",
                limit: MAX_FAILURE_DOMAIN_LEN,
                actual: self.failure_domain.len(),
            });
        }
        Ok(())
    }
}

impl CanonicalEncode for EvidenceNode {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.digest(self.digest);
        encoder.u8(self.kind.to_u8());
        encoder.text(&self.label);
        encoder.text(&self.failure_domain);
    }
}

/// Parameters for constructing a superseding event revision.
#[derive(Clone, Debug, PartialEq)]
pub struct EventSupersedeParams {
    /// Successor lifecycle state.
    pub state: EventState,
    /// Successor semantic class.
    pub kind: EventKind,
    /// Physical observation time bounds.
    pub interval: CaptureInterval,
    /// Bounded explanation for temporal uncertainty.
    pub uncertainty_reason: Option<String>,
    /// Impacted spatial zones.
    pub zone_ids: Vec<String>,
    /// Associated entity tracks.
    pub track_ids: Vec<String>,
    /// Epistemic probability interval.
    pub probability: ProbabilityInterval,
    /// Corroborating and contradictory evidence edges.
    pub evidence: Vec<EventEvidence>,
    /// Model execution receipts.
    pub model_receipts: Vec<ContentDigest>,
    /// Evaluated decision path.
    pub decision_path: DecisionPath,
}

/// Immutable event revision carrying provenance rather than model prose alone.
#[derive(Clone, Debug, PartialEq)]
pub struct EventHypothesis {
    /// Canonical schema identifier.
    pub schema: String,
    /// Stable event lineage.
    pub event_id: EventId,
    /// Monotone 1-based revision.
    pub revision: u64,
    /// Digest of the superseded event revision, if revision > 1.
    pub supersedes: Option<ContentDigest>,
    /// Lifecycle state.
    pub state: EventState,
    /// Semantic class.
    pub kind: EventKind,
    /// Event validity interval.
    pub interval: CaptureInterval,
    /// Optional capture interval uncertainty reason.
    pub uncertainty_reason: Option<String>,
    /// Spatial zone identifiers.
    pub zone_ids: Vec<String>,
    /// Correlated track identifiers.
    pub track_ids: Vec<String>,
    /// Calibrated probability interval.
    pub probability: ProbabilityInterval,
    /// Supporting and contradicting evidence.
    pub evidence: Vec<EventEvidence>,
    /// Exact model execution receipts.
    pub model_receipts: Vec<ContentDigest>,
    /// Decision-path fingerprint and policy execution.
    pub decision_path: DecisionPath,
}

/// Type alias reflecting event immutability: an event revision is an event hypothesis.
pub type EventRevision = EventHypothesis;

impl EventHypothesis {
    /// Canonical schema name.
    pub const SCHEMA: &'static str = "fss.event_hypothesis.v1";

    /// Validates load-bearing event invariants and hard bounds.
    pub fn verify(&self) -> Result<(), EventDecodeError> {
        if self.schema != Self::SCHEMA {
            return Err(EventDecodeError::SchemaMismatch {
                expected: Self::SCHEMA,
                found: self.schema.clone(),
            });
        }

        self.decision_path.verify()?;

        if self.event_id.as_str().len() > MAX_EVENT_ID_LEN {
            return Err(EventDecodeError::OverLimitLength {
                field: "eventId",
                limit: MAX_EVENT_ID_LEN,
                actual: self.event_id.as_str().len(),
            });
        }

        // Monotonic revision rules: revisions start at 1
        if self.revision == 0 {
            return Err(EventDecodeError::OutOfRange {
                field: "revision",
                minimum: 1,
                maximum: u64::MAX,
                actual: 0,
            });
        }

        // Revisions are immutable: revision 1 is genesis (supersedes None).
        // Corrections (revision > 1) MUST supersede rather than edit.
        if self.revision == 1 && self.supersedes.is_some() {
            return Err(EventDecodeError::Contradiction {
                field: "supersedes",
                detail: "genesis revision 1 cannot supersede a prior revision".to_string(),
            });
        }
        if self.revision > 1 && self.supersedes.is_none() {
            return Err(EventDecodeError::Contradiction {
                field: "supersedes",
                detail: format!(
                    "revision {} is a correction and must supersede a prior revision",
                    self.revision
                ),
            });
        }

        // Interval ordering
        if self.interval.earliest > self.interval.latest {
            return Err(EventDecodeError::Contract(
                ContractError::InvertedTimeInterval,
            ));
        }

        if let Some(reason) = &self.uncertainty_reason
            && reason.len() > MAX_UNCERTAINTY_REASON_LEN
        {
            return Err(EventDecodeError::OverLimitLength {
                field: "uncertaintyReason",
                limit: MAX_UNCERTAINTY_REASON_LEN,
                actual: reason.len(),
            });
        }

        // Bounds checks
        if self.zone_ids.len() > MAX_ZONES_COUNT {
            return Err(EventDecodeError::OverLimitLength {
                field: "zoneIds",
                limit: MAX_ZONES_COUNT,
                actual: self.zone_ids.len(),
            });
        }
        for zone in &self.zone_ids {
            if zone.len() > MAX_ZONE_ID_LEN {
                return Err(EventDecodeError::OverLimitLength {
                    field: "zoneIds[]",
                    limit: MAX_ZONE_ID_LEN,
                    actual: zone.len(),
                });
            }
        }

        if self.track_ids.len() > MAX_TRACKS_COUNT {
            return Err(EventDecodeError::OverLimitLength {
                field: "trackIds",
                limit: MAX_TRACKS_COUNT,
                actual: self.track_ids.len(),
            });
        }
        for track in &self.track_ids {
            if track.len() > MAX_TRACK_ID_LEN {
                return Err(EventDecodeError::OverLimitLength {
                    field: "trackIds[]",
                    limit: MAX_TRACK_ID_LEN,
                    actual: track.len(),
                });
            }
        }

        if self.evidence.len() > MAX_EVIDENCE_COUNT {
            return Err(EventDecodeError::OverLimitLength {
                field: "evidence",
                limit: MAX_EVIDENCE_COUNT,
                actual: self.evidence.len(),
            });
        }

        if self.model_receipts.len() > MAX_MODEL_RECEIPTS_COUNT {
            return Err(EventDecodeError::OverLimitLength {
                field: "modelReceipts",
                limit: MAX_MODEL_RECEIPTS_COUNT,
                actual: self.model_receipts.len(),
            });
        }

        self.probability.verify()?;

        for edge in &self.evidence {
            edge.verify()?;
        }

        // State invariants:
        // Evidence required after initial hypothesis
        if self.state != EventState::Hypothesized && self.evidence.is_empty() {
            return Err(EventDecodeError::Contract(ContractError::EvidenceRequired));
        }

        // A witnessed candidate is defined by a retained supporting observation witness; edges
        // that only contradict it cannot witness it.
        if self.state == EventState::Witnessed
            && !self.evidence.iter().any(EventEvidence::counts_as_support)
        {
            return Err(EventDecodeError::Contract(
                ContractError::SupportingEvidenceRequired,
            ));
        }

        // Corroboration strictly requires >= 2 distinct failure domains among supporting edges.
        // AGENTS.md prime directive: one camera's model score is NEVER corroborated.
        if self.state == EventState::Corroborated {
            let failure_domains: BTreeSet<_> = self
                .evidence
                .iter()
                .filter(|edge| edge.counts_as_support())
                .map(|edge| edge.failure_domain.as_str())
                .collect();
            if failure_domains.len() < 2 {
                return Err(EventDecodeError::Contract(
                    ContractError::CorroborationRequired,
                ));
            }
        }

        // Adjudicated and AlertDelivered require >= 2 distinct failure domains UNLESS
        // explicitly labeled as single-domain/unconfirmed under an urgent single-sensor policy.
        if matches!(
            self.state,
            EventState::Adjudicated | EventState::AlertDelivered
        ) {
            let failure_domains: BTreeSet<_> = self
                .evidence
                .iter()
                .filter(|edge| edge.counts_as_support())
                .map(|edge| edge.failure_domain.as_str())
                .collect();
            if failure_domains.len() < 2 && !self.is_single_domain_unconfirmed() {
                return Err(EventDecodeError::Contract(
                    ContractError::CorroborationRequired,
                ));
            }
        }

        // Corroboration counts only true supports, so a tamper report beside two supports would
        // otherwise pass: a sensor-integrity risk vetoes every state that establishes or acts on
        // presence.
        if sensor_tamper_vetoes(self.state)
            && self
                .evidence
                .iter()
                .any(EventEvidence::reports_sensor_tamper)
        {
            return Err(EventDecodeError::Contract(
                ContractError::SensorIntegrityRisk,
            ));
        }

        Ok(())
    }

    /// Legacy validator returning `ContractError`.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.verify().map_err(|error| match error {
            EventDecodeError::Contract(contract) => contract,
            // A supports flag that disagrees with its edge relation.
            EventDecodeError::Contradiction {
                field: "evidence.supports",
                ..
            } => ContractError::EvidenceRelationMismatch,
            // Structural bounds and field invariants are neither missing evidence nor a relation
            // mismatch. Exhaustive on purpose: a new decode error must choose its variant here.
            EventDecodeError::Truncated { .. }
            | EventDecodeError::UnknownVersion { .. }
            | EventDecodeError::TrailingBytes { .. }
            | EventDecodeError::OverLimitLength { .. }
            | EventDecodeError::NonCanonicalEncoding { .. }
            | EventDecodeError::SchemaMismatch { .. }
            | EventDecodeError::JsonError { .. }
            | EventDecodeError::InvalidUnicodeEscape { .. }
            | EventDecodeError::Contradiction { .. }
            | EventDecodeError::OutOfRange { .. } => ContractError::EventRevisionMalformed,
        })
    }

    /// Returns true if this revision is explicitly labeled as single-domain/unconfirmed
    /// under an urgent single-sensor policy exception.
    #[must_use]
    pub fn is_single_domain_unconfirmed(&self) -> bool {
        self.uncertainty_reason
            .as_deref()
            .is_some_and(|r| r.contains(SINGLE_DOMAIN_UNCONFIRMED_LABEL))
    }

    /// Analyzes corroboration and failure domains for this revision's evidence.
    #[must_use]
    pub fn analyze_corroboration(&self) -> CorroborationAnalysis {
        let mut domain_counts = BTreeMap::new();
        let mut supporting_count = 0;
        let mut contradicting_count = 0;
        for edge in &self.evidence {
            if edge.counts_as_support() {
                supporting_count += 1;
                *domain_counts
                    .entry(edge.failure_domain.clone())
                    .or_insert(0) += 1;
            } else if edge.counts_as_contradiction() {
                contradicting_count += 1;
            }
        }
        let distinct_failure_domains: BTreeSet<String> = domain_counts.keys().cloned().collect();
        let is_corroborated = distinct_failure_domains.len() >= 2;
        let domain_evidence_counts: Vec<(String, usize)> = domain_counts.into_iter().collect();
        CorroborationAnalysis {
            distinct_failure_domains,
            domain_evidence_counts,
            supporting_count,
            contradicting_count,
            is_corroborated,
        }
    }

    /// Returns the immutable event-revision digest.
    #[must_use]
    pub fn revision_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.canonical.v1");
        encoder.text(Self::SCHEMA);
        self.encode_canonical(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Constructs a successor revision that supersedes this event hypothesis.
    ///
    /// The successor has `revision = self.revision + 1` and `supersedes = Some(self.revision_digest())`.
    pub fn supersede(
        &self,
        params: EventSupersedeParams,
        chain: &[EventHypothesis],
    ) -> Result<Self, EventDecodeError> {
        if self.state.is_terminal() {
            return Err(EventDecodeError::Contradiction {
                field: "state",
                detail: format!("cannot supersede terminal state {:?}", self.state),
            });
        }
        let urgent = params
            .uncertainty_reason
            .as_deref()
            .is_some_and(|r| r.contains(SINGLE_DOMAIN_UNCONFIRMED_LABEL));
        if !is_allowed_event_transition(self.state, params.state, urgent) {
            return Err(EventDecodeError::Contradiction {
                field: "state",
                detail: format!(
                    "transition from {:?} to {:?} not permitted by state machine",
                    self.state, params.state
                ),
            });
        }
        // `chain` must be this revision's own complete lineage, genesis first and `self` last. There
        // is no fallback: an empty chain, `[self]` alone when `self` has predecessors, or any other
        // lineage would hide earlier tampers and restorations from the status computed below.
        let ends_in_self = chain
            .last()
            .is_some_and(|last| last.revision_digest() == self.revision_digest());
        let covers_lineage = u64::try_from(chain.len()).is_ok_and(|len| len == self.revision);
        if !ends_in_self || !covers_lineage {
            return Err(EventDecodeError::Contract(
                ContractError::SupersessionMismatch,
            ));
        }
        Self::verify_chain(chain)?;
        let full_chain: Vec<&EventHypothesis> = chain.iter().collect();
        let tamper_status = compute_sensor_tamper_status_with_interval(
            full_chain.iter().copied(),
            Some(&params.evidence),
            Some(params.interval),
        );
        if sensor_tamper_vetoes(params.state) && tamper_status.has_open_tamper() {
            return Err(EventDecodeError::Contract(
                ContractError::SensorIntegrityRisk,
            ));
        }

        let mut final_evidence = params.evidence;
        for prior_edge in full_chain.iter().flat_map(|r| r.evidence.iter()) {
            if prior_edge.reports_sensor_tamper()
                && tamper_status.open_tamper_roots.contains(&prior_edge.digest)
                && !final_evidence
                    .iter()
                    .any(|e| e.digest == prior_edge.digest && e.relation == prior_edge.relation)
            {
                final_evidence.push(prior_edge.clone());
            }
        }
        let rev = Self {
            schema: Self::SCHEMA.to_string(),
            event_id: self.event_id.clone(),
            revision: self
                .revision
                .checked_add(1)
                .ok_or(EventDecodeError::OutOfRange {
                    field: "revision",
                    minimum: 1,
                    maximum: u64::MAX,
                    actual: u64::MAX,
                })?,
            supersedes: Some(self.revision_digest()),
            state: params.state,
            kind: params.kind,
            interval: params.interval,
            uncertainty_reason: params.uncertainty_reason,
            zone_ids: params.zone_ids,
            track_ids: params.track_ids,
            probability: params.probability,
            evidence: final_evidence,
            model_receipts: params.model_receipts,
            decision_path: params.decision_path,
        };
        rev.verify()?;
        Ok(rev)
    }

    /// Validates an ordered supersession chain of event hypotheses.
    ///
    /// The chain must also pass every lineage replay append rule: verification and replay
    /// ([`EventLineage::from_revisions`], [`EventLineage::replay_from_deltas`]) apply the same
    /// rules, including one shared lineage tamper step, so they reach the same verdict on every
    /// chain. The one rule replay adds is [`EventLineage::new`]'s lifecycle rule that a lineage
    /// begins `Hypothesized`; a chain may begin at a later state (the reference policy publishes
    /// a first revision that is already witnessed or corroborated), so verification does not
    /// require it.
    pub fn verify_chain(chain: &[EventHypothesis]) -> Result<(), EventDecodeError> {
        Self::verify_chain_rules(chain)?;
        EventLineage::replay_append_rules(chain.to_vec()).map_err(transition_error_as_decode)?;
        Ok(())
    }

    /// Supersession, identity, state-machine and lineage tamper rules of [`Self::verify_chain`].
    fn verify_chain_rules(chain: &[EventHypothesis]) -> Result<(), EventDecodeError> {
        if chain.is_empty() {
            return Err(EventDecodeError::Contradiction {
                field: "chain",
                detail: "supersession chain cannot be empty".to_string(),
            });
        }
        let event_id = &chain[0].event_id;
        let mut prior_digest: Option<ContentDigest> = None;
        let mut prior_rev: Option<&EventHypothesis> = None;
        let mut tamper_status = SensorTamperStatus::default();
        for (i, rev) in chain.iter().enumerate() {
            rev.verify()?;
            apply_revision_tamper_step(&mut tamper_status, rev)?;
            if &rev.event_id != event_id {
                return Err(EventDecodeError::Contradiction {
                    field: "chain.eventId",
                    detail: format!(
                        "chain eventId mismatch: expected {}, found {}",
                        event_id, rev.event_id
                    ),
                });
            }
            let expected_rev = (i as u64) + 1;
            if rev.revision != expected_rev {
                return Err(EventDecodeError::OutOfRange {
                    field: "chain.revision",
                    minimum: expected_rev,
                    maximum: expected_rev,
                    actual: rev.revision,
                });
            }
            if i == 0 {
                if rev.supersedes.is_some() {
                    return Err(EventDecodeError::Contradiction {
                        field: "supersedes",
                        detail: "genesis revision 1 cannot supersede a prior revision".to_string(),
                    });
                }
            } else {
                let expected_prior =
                    prior_digest.ok_or_else(|| EventDecodeError::Contradiction {
                        field: "supersedes",
                        detail: "missing predecessor digest".to_string(),
                    })?;
                if rev.supersedes != Some(expected_prior) {
                    return Err(EventDecodeError::Contradiction {
                        field: "supersedes",
                        detail: format!(
                            "revision {} supersedes digest mismatch: expected {:?}, found {:?}",
                            rev.revision,
                            Some(expected_prior),
                            rev.supersedes
                        ),
                    });
                }
                if let Some(prev) = prior_rev {
                    if prev.state.is_terminal() {
                        return Err(EventDecodeError::Contradiction {
                            field: "chain.state",
                            detail: format!(
                                "chain continues after terminal state {:?}",
                                prev.state
                            ),
                        });
                    }
                    let urgent = rev.is_single_domain_unconfirmed();
                    if !is_allowed_event_transition(prev.state, rev.state, urgent) {
                        return Err(EventDecodeError::Contradiction {
                            field: "chain.state",
                            detail: format!(
                                "illegal transition in chain from {:?} to {:?}",
                                prev.state, rev.state
                            ),
                        });
                    }
                }
            }
            prior_digest = Some(rev.revision_digest());
            prior_rev = Some(rev);
        }
        Ok(())
    }

    /// Serializes this event revision into the canonical versioned binary envelope (`FSSE` v1).
    pub fn to_versioned_bytes(&self) -> Result<Vec<u8>, EventDecodeError> {
        self.verify()?;
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        let payload = encoder
            .finish_checked()
            .map_err(EventDecodeError::Contract)?;

        let mut out = Vec::with_capacity(6 + payload.len());
        out.extend_from_slice(&EVENT_HYPOTHESIS_MAGIC);
        out.extend_from_slice(&EVENT_HYPOTHESIS_VERSION_1.to_be_bytes());
        out.extend_from_slice(&payload);
        Ok(out)
    }

    /// Decodes an event revision from a complete versioned binary envelope (`FSSE` v1).
    pub fn from_versioned_bytes(bytes: &[u8]) -> Result<Self, EventDecodeError> {
        if bytes.len() < 6 {
            return Err(EventDecodeError::Truncated {
                expected_min: 6,
                actual: bytes.len(),
            });
        }
        if bytes[0..4] != EVENT_HYPOTHESIS_MAGIC {
            return Err(EventDecodeError::NonCanonicalEncoding {
                detail: "invalid magic header: expected FSSE".to_string(),
            });
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != EVENT_HYPOTHESIS_VERSION_1 {
            return Err(EventDecodeError::UnknownVersion { version });
        }

        let payload = &bytes[6..];
        let mut decoder = CanonicalDecoder::new(payload);
        let event = Self::decode_canonical_checked(&mut decoder)?;
        if !decoder.is_empty() {
            return Err(EventDecodeError::TrailingBytes {
                count: decoder.remaining(),
            });
        }
        event.verify()?;

        // Bit-identical round-trip verification
        let mut re_encoder = CanonicalEncoder::new();
        event.encode_canonical(&mut re_encoder);
        let reencoded = re_encoder
            .finish_checked()
            .map_err(EventDecodeError::Contract)?;
        if reencoded != payload {
            return Err(EventDecodeError::NonCanonicalEncoding {
                detail: "payload does not re-encode bit-identically".to_string(),
            });
        }
        Ok(event)
    }

    fn decode_canonical_checked(
        decoder: &mut CanonicalDecoder<'_>,
    ) -> Result<Self, EventDecodeError> {
        let schema = decoder.text().map_err(|_| EventDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?;
        if schema != Self::SCHEMA {
            return Err(EventDecodeError::SchemaMismatch {
                expected: Self::SCHEMA,
                found: schema.to_string(),
            });
        }

        let event_id_str = decoder.text().map_err(|_| EventDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?;
        if event_id_str.len() > MAX_EVENT_ID_LEN {
            return Err(EventDecodeError::OverLimitLength {
                field: "eventId",
                limit: MAX_EVENT_ID_LEN,
                actual: event_id_str.len(),
            });
        }
        let event_id = EventId::parse(event_id_str).map_err(EventDecodeError::Contract)?;

        let revision = decoder.u64().map_err(|_| EventDecodeError::Truncated {
            expected_min: 8,
            actual: 0,
        })?;

        let has_supersedes = decoder.bool().map_err(|_| EventDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?;
        let supersedes = if has_supersedes {
            Some(decoder.digest().map_err(EventDecodeError::Contract)?)
        } else {
            None
        };

        let state =
            EventState::from_u8(decoder.u8().map_err(|_| EventDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?)?;

        let kind = EventKind::from_u8(decoder.u8().map_err(|_| EventDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?)?;

        let interval =
            CaptureInterval::decode_canonical(decoder).map_err(EventDecodeError::Contract)?;

        let has_uncertainty = decoder.bool().map_err(|_| EventDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?;
        let uncertainty_reason = if has_uncertainty {
            let reason = decoder.text().map_err(|_| EventDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?;
            if reason.len() > MAX_UNCERTAINTY_REASON_LEN {
                return Err(EventDecodeError::OverLimitLength {
                    field: "uncertaintyReason",
                    limit: MAX_UNCERTAINTY_REASON_LEN,
                    actual: reason.len(),
                });
            }
            Some(reason.to_string())
        } else {
            None
        };

        let zone_count = decoder.u64().map_err(|_| EventDecodeError::Truncated {
            expected_min: 8,
            actual: 0,
        })? as usize;
        if zone_count > MAX_ZONES_COUNT {
            return Err(EventDecodeError::OverLimitLength {
                field: "zoneIds",
                limit: MAX_ZONES_COUNT,
                actual: zone_count,
            });
        }
        let mut zone_ids = Vec::with_capacity(zone_count);
        for _ in 0..zone_count {
            let zone = decoder.text().map_err(|_| EventDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?;
            if zone.len() > MAX_ZONE_ID_LEN {
                return Err(EventDecodeError::OverLimitLength {
                    field: "zoneIds[]",
                    limit: MAX_ZONE_ID_LEN,
                    actual: zone.len(),
                });
            }
            zone_ids.push(zone.to_string());
        }

        let track_count = decoder.u64().map_err(|_| EventDecodeError::Truncated {
            expected_min: 8,
            actual: 0,
        })? as usize;
        if track_count > MAX_TRACKS_COUNT {
            return Err(EventDecodeError::OverLimitLength {
                field: "trackIds",
                limit: MAX_TRACKS_COUNT,
                actual: track_count,
            });
        }
        let mut track_ids = Vec::with_capacity(track_count);
        for _ in 0..track_count {
            let track = decoder.text().map_err(|_| EventDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?;
            if track.len() > MAX_TRACK_ID_LEN {
                return Err(EventDecodeError::OverLimitLength {
                    field: "trackIds[]",
                    limit: MAX_TRACK_ID_LEN,
                    actual: track.len(),
                });
            }
            track_ids.push(track.to_string());
        }

        let prob_lower_bits = decoder.u64().map_err(|_| EventDecodeError::Truncated {
            expected_min: 8,
            actual: 0,
        })?;
        let prob_upper_bits = decoder.u64().map_err(|_| EventDecodeError::Truncated {
            expected_min: 8,
            actual: 0,
        })?;
        let prob_has_cal = decoder.bool().map_err(|_| EventDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?;
        let calibration_generation = if prob_has_cal {
            Some(decoder.digest().map_err(EventDecodeError::Contract)?)
        } else {
            None
        };
        let lower = f64::from_bits(prob_lower_bits);
        let upper = f64::from_bits(prob_upper_bits);
        let probability = ProbabilityInterval {
            lower,
            upper,
            calibration_generation,
        };

        let evidence_count = decoder.u64().map_err(|_| EventDecodeError::Truncated {
            expected_min: 8,
            actual: 0,
        })? as usize;
        if evidence_count > MAX_EVIDENCE_COUNT {
            return Err(EventDecodeError::OverLimitLength {
                field: "evidence",
                limit: MAX_EVIDENCE_COUNT,
                actual: evidence_count,
            });
        }
        let mut evidence = Vec::with_capacity(evidence_count);
        for _ in 0..evidence_count {
            let digest = decoder.digest().map_err(EventDecodeError::Contract)?;
            let class =
                evidence_class_from_u8(decoder.u8().map_err(|_| EventDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                })?)?;
            let failure_domain = decoder
                .text()
                .map_err(|_| EventDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                })?
                .to_string();
            if failure_domain.len() > MAX_FAILURE_DOMAIN_LEN {
                return Err(EventDecodeError::OverLimitLength {
                    field: "evidence.failureDomain",
                    limit: MAX_FAILURE_DOMAIN_LEN,
                    actual: failure_domain.len(),
                });
            }
            let supports = decoder.bool().map_err(|_| EventDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?;
            let relation = EvidenceEdgeRelation::from_u8(decoder.u8().map_err(|_| {
                EventDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                }
            })?)?;
            let has_capsule = decoder.bool().map_err(|_| EventDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?;
            let capsule_digest = if has_capsule {
                Some(decoder.digest().map_err(EventDecodeError::Contract)?)
            } else {
                None
            };
            let has_id = decoder.bool().map_err(|_| EventDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?;
            let identity_digest = if has_id {
                Some(decoder.digest().map_err(EventDecodeError::Contract)?)
            } else {
                None
            };
            evidence.push(EventEvidence {
                digest,
                class,
                failure_domain,
                supports,
                relation,
                capsule_digest,
                identity_digest,
            });
        }

        let receipt_count = decoder.u64().map_err(|_| EventDecodeError::Truncated {
            expected_min: 8,
            actual: 0,
        })? as usize;
        if receipt_count > MAX_MODEL_RECEIPTS_COUNT {
            return Err(EventDecodeError::OverLimitLength {
                field: "modelReceipts",
                limit: MAX_MODEL_RECEIPTS_COUNT,
                actual: receipt_count,
            });
        }
        let mut model_receipts = Vec::with_capacity(receipt_count);
        for _ in 0..receipt_count {
            model_receipts.push(decoder.digest().map_err(EventDecodeError::Contract)?);
        }

        let decision_path = DecisionPath::decode_canonical_checked(decoder)?;

        Ok(Self {
            schema: schema.to_string(),
            event_id,
            revision,
            supersedes,
            state,
            kind,
            interval,
            uncertainty_reason,
            zone_ids,
            track_ids,
            probability,
            evidence,
            model_receipts,
            decision_path,
        })
    }

    /// Emits a deterministic canonical JSON string projection.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut out = String::with_capacity(2048);
        out.push('{');

        // Deterministic alphabetical key serialization
        // 1. decisionPath
        out.push_str("\"decisionPath\":");
        out.push_str(&self.decision_path.to_canonical_json());
        out.push(',');

        // 2. eventId
        out.push_str("\"eventId\":");
        json_write_str(&mut out, self.event_id.as_str());
        out.push(',');

        // 3. evidence
        out.push_str("\"evidence\":[");
        for (i, edge) in self.evidence.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('{');
            out.push_str("\"capsuleDigest\":");
            match &edge.capsule_digest {
                Some(cd) => json_write_str(&mut out, &cd.to_string()),
                None => out.push_str("null"),
            }
            out.push_str(",\"class\":");
            json_write_str(&mut out, evidence_class_as_str(edge.class));
            out.push_str(",\"digest\":");
            json_write_str(&mut out, &edge.digest.to_string());
            out.push_str(",\"failureDomain\":");
            json_write_str(&mut out, &edge.failure_domain);
            out.push_str(",\"identityDigest\":");
            match &edge.identity_digest {
                Some(id) => json_write_str(&mut out, &id.to_string()),
                None => out.push_str("null"),
            }
            out.push_str(",\"relation\":");
            json_write_str(&mut out, edge.relation.as_str());
            out.push_str(",\"supports\":");
            out.push_str(if edge.supports { "true" } else { "false" });
            out.push('}');
        }
        out.push(']');
        out.push(',');

        // 4. kind
        out.push_str("\"kind\":");
        json_write_str(&mut out, self.kind.as_str());
        out.push(',');

        // 5. modelReceipts
        out.push_str("\"modelReceipts\":[");
        for (i, receipt) in self.model_receipts.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            json_write_str(&mut out, &receipt.to_string());
        }
        out.push(']');
        out.push(',');

        // 6. probability
        out.push_str("\"probability\":{");
        out.push_str("\"calibrationGeneration\":");
        match &self.probability.calibration_generation {
            Some(cg) => json_write_str(&mut out, &cg.to_string()),
            None => out.push_str("null"),
        }
        out.push_str(",\"lower\":");
        format_json_f64(&mut out, self.probability.lower);
        out.push_str(",\"upper\":");
        format_json_f64(&mut out, self.probability.upper);
        out.push('}');
        out.push(',');

        // 7. revision
        out.push_str("\"revision\":");
        out.push_str(&self.revision.to_string());
        out.push(',');

        // 8. schema
        out.push_str("\"schema\":");
        json_write_str(&mut out, Self::SCHEMA);
        out.push(',');

        // 9. state
        out.push_str("\"state\":");
        json_write_str(&mut out, self.state.as_str());
        out.push(',');

        // 10. supersedes
        out.push_str("\"supersedes\":");
        match &self.supersedes {
            Some(s) => json_write_str(&mut out, &s.to_string()),
            None => out.push_str("null"),
        }
        out.push(',');

        // 11. timeInterval
        out.push_str("\"timeInterval\":{");
        out.push_str("\"earliestNs\":");
        out.push_str(&self.interval.earliest.0.to_string());
        out.push_str(",\"latestNs\":");
        out.push_str(&self.interval.latest.0.to_string());
        out.push_str(",\"uncertaintyReason\":");
        json_write_str(&mut out, self.uncertainty_reason.as_deref().unwrap_or(""));
        out.push('}');
        out.push(',');

        // 12. trackIds
        out.push_str("\"trackIds\":[");
        for (i, track) in self.track_ids.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            json_write_str(&mut out, track);
        }
        out.push(']');
        out.push(',');

        // 13. uncertaintyReason
        out.push_str("\"uncertaintyReason\":");
        match &self.uncertainty_reason {
            Some(r) => json_write_str(&mut out, r),
            None => out.push_str("null"),
        }
        out.push(',');

        // 14. zoneIds
        out.push_str("\"zoneIds\":[");
        for (i, zone) in self.zone_ids.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            json_write_str(&mut out, zone);
        }
        out.push(']');

        out.push('}');
        out
    }

    /// Parses an event revision from JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, EventDecodeError> {
        let value = parse_json_value(json_str)?;
        let obj = JsonObject::from_value(&value, "eventHypothesis")?;

        let schema_val = obj.str("schema")?;
        if schema_val != Self::SCHEMA {
            return Err(EventDecodeError::SchemaMismatch {
                expected: Self::SCHEMA,
                found: schema_val.to_string(),
            });
        }

        let event_id_str = obj.str("eventId")?;
        if event_id_str.len() > MAX_EVENT_ID_LEN {
            return Err(EventDecodeError::OverLimitLength {
                field: "eventId",
                limit: MAX_EVENT_ID_LEN,
                actual: event_id_str.len(),
            });
        }
        let event_id = EventId::parse(event_id_str).map_err(EventDecodeError::Contract)?;

        let revision = obj.get("revision")?.as_u64()?;

        let supersedes = match obj.get("supersedes")? {
            JsonValue::Null => None,
            JsonValue::String(s) => {
                Some(ContentDigest::parse(s).map_err(EventDecodeError::Contract)?)
            }
            _ => {
                return Err(EventDecodeError::JsonError {
                    detail: "supersedes must be string or null".to_string(),
                });
            }
        };

        let state = EventState::parse(obj.str("state")?)?;
        let kind = EventKind::parse(obj.str("kind")?)?;

        let interval_obj = JsonObject::from_value(obj.get("timeInterval")?, "timeInterval")?;
        let earliest_ns = interval_obj.get("earliestNs")?.as_i128()?;
        let latest_ns = interval_obj.get("latestNs")?.as_i128()?;
        let interval = CaptureInterval::new(TimestampNs(earliest_ns), TimestampNs(latest_ns))
            .map_err(EventDecodeError::Contract)?;

        let interval_uncertainty = match interval_obj.get_opt("uncertaintyReason") {
            Some(JsonValue::String(s)) => {
                if s.len() > MAX_UNCERTAINTY_REASON_LEN {
                    return Err(EventDecodeError::OverLimitLength {
                        field: "timeInterval.uncertaintyReason",
                        limit: MAX_UNCERTAINTY_REASON_LEN,
                        actual: s.len(),
                    });
                }
                s.as_str()
            }
            Some(JsonValue::Null) => {
                return Err(EventDecodeError::JsonError {
                    detail: "timeInterval.uncertaintyReason cannot be null".to_string(),
                });
            }
            None => "",
            _ => {
                return Err(EventDecodeError::JsonError {
                    detail: "timeInterval.uncertaintyReason must be a string".to_string(),
                });
            }
        };

        let top_uncertainty = match obj.get_opt("uncertaintyReason") {
            Some(JsonValue::String(s)) => {
                if s.len() > MAX_UNCERTAINTY_REASON_LEN {
                    return Err(EventDecodeError::OverLimitLength {
                        field: "uncertaintyReason",
                        limit: MAX_UNCERTAINTY_REASON_LEN,
                        actual: s.len(),
                    });
                }
                Some(s.as_str())
            }
            Some(JsonValue::Null) | None => None,
            _ => {
                return Err(EventDecodeError::JsonError {
                    detail: "uncertaintyReason must be string or null".to_string(),
                });
            }
        };

        let uncertainty_reason = match (top_uncertainty, interval_uncertainty) {
            (Some(top), inter) => {
                if !inter.is_empty() && top != inter {
                    return Err(EventDecodeError::Contradiction {
                        field: "uncertaintyReason",
                        detail: "timeInterval.uncertaintyReason and top-level uncertaintyReason contradict"
                            .to_string(),
                    });
                }
                if top.is_empty() {
                    None
                } else {
                    Some(top.to_string())
                }
            }
            (None, inter) => {
                if inter.is_empty() {
                    None
                } else {
                    Some(inter.to_string())
                }
            }
        };

        let zone_ids = match obj.get_opt("zoneIds") {
            Some(JsonValue::Array(arr)) => {
                if arr.len() > MAX_ZONES_COUNT {
                    return Err(EventDecodeError::OverLimitLength {
                        field: "zoneIds",
                        limit: MAX_ZONES_COUNT,
                        actual: arr.len(),
                    });
                }
                let mut zones = Vec::with_capacity(arr.len());
                for item in arr {
                    match item {
                        JsonValue::String(z) => {
                            if z.len() > MAX_ZONE_ID_LEN {
                                return Err(EventDecodeError::OverLimitLength {
                                    field: "zoneIds[]",
                                    limit: MAX_ZONE_ID_LEN,
                                    actual: z.len(),
                                });
                            }
                            zones.push(z.clone());
                        }
                        _ => {
                            return Err(EventDecodeError::JsonError {
                                detail: "zoneIds elements must be strings".to_string(),
                            });
                        }
                    }
                }
                zones
            }
            Some(JsonValue::Null) => {
                return Err(EventDecodeError::JsonError {
                    detail: "zoneIds cannot be null, must be an array".to_string(),
                });
            }
            None => Vec::new(),
            _ => {
                return Err(EventDecodeError::JsonError {
                    detail: "zoneIds must be an array".to_string(),
                });
            }
        };

        let track_ids = match obj.get_opt("trackIds") {
            Some(JsonValue::Array(arr)) => {
                if arr.len() > MAX_TRACKS_COUNT {
                    return Err(EventDecodeError::OverLimitLength {
                        field: "trackIds",
                        limit: MAX_TRACKS_COUNT,
                        actual: arr.len(),
                    });
                }
                let mut tracks = Vec::with_capacity(arr.len());
                for item in arr {
                    match item {
                        JsonValue::String(t) => {
                            if t.len() > MAX_TRACK_ID_LEN {
                                return Err(EventDecodeError::OverLimitLength {
                                    field: "trackIds[]",
                                    limit: MAX_TRACK_ID_LEN,
                                    actual: t.len(),
                                });
                            }
                            tracks.push(t.clone());
                        }
                        _ => {
                            return Err(EventDecodeError::JsonError {
                                detail: "trackIds elements must be strings".to_string(),
                            });
                        }
                    }
                }
                tracks
            }
            Some(JsonValue::Null) => {
                return Err(EventDecodeError::JsonError {
                    detail: "trackIds cannot be null, must be an array".to_string(),
                });
            }
            None => Vec::new(),
            _ => {
                return Err(EventDecodeError::JsonError {
                    detail: "trackIds must be an array".to_string(),
                });
            }
        };

        let prob_obj = JsonObject::from_value(obj.get("probability")?, "probability")?;
        let lower = prob_obj.get("lower")?.as_f64()?;
        let upper = prob_obj.get("upper")?.as_f64()?;
        let calibration_generation = match prob_obj.get("calibrationGeneration")? {
            JsonValue::Null => None,
            JsonValue::String(s) => {
                Some(ContentDigest::parse(s).map_err(EventDecodeError::Contract)?)
            }
            _ => {
                return Err(EventDecodeError::JsonError {
                    detail: "calibrationGeneration must be string or null".to_string(),
                });
            }
        };
        let probability = ProbabilityInterval {
            lower,
            upper,
            calibration_generation,
        };

        let evidence_arr = match obj.get("evidence")? {
            JsonValue::Array(arr) => arr,
            _ => {
                return Err(EventDecodeError::JsonError {
                    detail: "evidence must be an array, not null".to_string(),
                });
            }
        };
        if evidence_arr.len() > MAX_EVIDENCE_COUNT {
            return Err(EventDecodeError::OverLimitLength {
                field: "evidence",
                limit: MAX_EVIDENCE_COUNT,
                actual: evidence_arr.len(),
            });
        }
        let mut evidence = Vec::with_capacity(evidence_arr.len());
        for (idx, item) in evidence_arr.iter().enumerate() {
            let e_obj = JsonObject::from_value(item, "evidence[]")?;
            let digest =
                ContentDigest::parse(e_obj.str("digest")?).map_err(EventDecodeError::Contract)?;
            let class = parse_evidence_class(e_obj.str("class")?)?;
            let failure_domain = e_obj.str("failureDomain")?.to_string();
            if failure_domain.len() > MAX_FAILURE_DOMAIN_LEN {
                return Err(EventDecodeError::OverLimitLength {
                    field: "evidence.failureDomain",
                    limit: MAX_FAILURE_DOMAIN_LEN,
                    actual: failure_domain.len(),
                });
            }
            let supports = e_obj.get("supports")?.as_bool()?;
            let relation = EvidenceEdgeRelation::parse(e_obj.str("relation")?)?;

            let capsule_digest = match e_obj.get_opt("capsuleDigest") {
                Some(JsonValue::String(s)) => {
                    Some(ContentDigest::parse(s).map_err(EventDecodeError::Contract)?)
                }
                Some(JsonValue::Null) | None => None,
                _ => {
                    return Err(EventDecodeError::JsonError {
                        detail: format!("evidence[{idx}].capsuleDigest must be string or null"),
                    });
                }
            };
            let identity_digest = match e_obj.get_opt("identityDigest") {
                Some(JsonValue::String(s)) => {
                    Some(ContentDigest::parse(s).map_err(EventDecodeError::Contract)?)
                }
                Some(JsonValue::Null) | None => None,
                _ => {
                    return Err(EventDecodeError::JsonError {
                        detail: format!("evidence[{idx}].identityDigest must be string or null"),
                    });
                }
            };

            evidence.push(EventEvidence {
                digest,
                class,
                failure_domain,
                supports,
                relation,
                capsule_digest,
                identity_digest,
            });
        }

        let receipts_arr = match obj.get_opt("modelReceipts") {
            Some(JsonValue::Array(arr)) => arr,
            Some(JsonValue::Null) => {
                return Err(EventDecodeError::JsonError {
                    detail: "modelReceipts cannot be null, must be an array".to_string(),
                });
            }
            None => &[][..],
            _ => {
                return Err(EventDecodeError::JsonError {
                    detail: "modelReceipts must be an array".to_string(),
                });
            }
        };
        if receipts_arr.len() > MAX_MODEL_RECEIPTS_COUNT {
            return Err(EventDecodeError::OverLimitLength {
                field: "modelReceipts",
                limit: MAX_MODEL_RECEIPTS_COUNT,
                actual: receipts_arr.len(),
            });
        }
        let mut model_receipts = Vec::with_capacity(receipts_arr.len());
        for receipt in receipts_arr {
            match receipt {
                JsonValue::String(s) => {
                    model_receipts
                        .push(ContentDigest::parse(s).map_err(EventDecodeError::Contract)?);
                }
                _ => {
                    return Err(EventDecodeError::JsonError {
                        detail: "modelReceipts element must be digest string".to_string(),
                    });
                }
            }
        }

        let dp_val = obj.get("decisionPath")?;
        let dp_obj = JsonObject::from_value(dp_val, "decisionPath")?;
        let decision_path = DecisionPath::from_json_obj(&dp_obj)?;

        let event = Self {
            schema: schema_val.to_string(),
            event_id,
            revision,
            supersedes,
            state,
            kind,
            interval,
            uncertainty_reason,
            zone_ids,
            track_ids,
            probability,
            evidence,
            model_receipts,
            decision_path,
        };
        event.verify()?;
        Ok(event)
    }
}

/// Corroboration and failure-domain analysis for an event revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorroborationAnalysis {
    /// Set of distinct failure domain identities among supporting evidence edges.
    pub distinct_failure_domains: BTreeSet<String>,
    /// Evidence counts grouped by failure domain to expose shared failure modes.
    pub domain_evidence_counts: Vec<(String, usize)>,
    /// Total count of supporting edges.
    pub supporting_count: usize,
    /// Total count of contradicting edges.
    pub contradicting_count: usize,
    /// Whether the strict corroboration rule (>= 2 distinct failure domains) is satisfied.
    pub is_corroborated: bool,
}

/// Durable record of an alert effect attempt or outcome associated with an event revision.
///
/// Preserves strict orthogonality between event lifecycle state and external effect execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertEffectRecord {
    /// Unique operation identity for the alert dispatch.
    pub operation_id: OperationId,
    /// Terminal-proof obligation ID.
    pub obligation_id: ObligationId,
    /// Event revision number when alert was attempted.
    pub event_revision: u64,
    /// Exact digest of the event revision when alert was attempted.
    pub event_revision_digest: ContentDigest,
    /// Effect lifecycle state (e.g. Prepared, Committed, AdapterAccepted, Observed, Verified, Indeterminate, Failed).
    pub effect_state: EffectState,
    /// Dispatch or observation timestamp.
    pub timestamp_ns: TimestampNs,
    /// Bounded alert channel identifier.
    pub channel: String,
    /// Provider observation receipt digest, if delivery was verified.
    pub observation_receipt: Option<ContentDigest>,
    /// Error code or failure reason if dispatch failed or is indeterminate.
    pub failure_reason: Option<String>,
}

impl AlertEffectRecord {
    /// Canonical schema identifier.
    pub const SCHEMA: &'static str = "fss.alert_effect_record.v1";

    /// Validates bounds and invariants on the alert effect record.
    pub fn verify(&self) -> Result<(), EventTransitionError> {
        if self.event_revision == 0 {
            return Err(EventTransitionError::RevisionNotMonotonic {
                expected: 1,
                actual: 0,
            });
        }
        if self.channel.len() > MAX_ALERT_CHANNEL_LEN {
            return Err(EventTransitionError::OverLimitLength {
                field: "alert_record.channel",
                limit: MAX_ALERT_CHANNEL_LEN,
                actual: self.channel.len(),
            });
        }
        if let Some(reason) = &self.failure_reason
            && reason.len() > MAX_ALERT_FAILURE_REASON_LEN
        {
            return Err(EventTransitionError::OverLimitLength {
                field: "alert_record.failure_reason",
                limit: MAX_ALERT_FAILURE_REASON_LEN,
                actual: reason.len(),
            });
        }
        Ok(())
    }

    /// Serializes this alert record into canonical binary bytes prefixed with the root domain tag.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.canonical.v1");
        self.encode_canonical(&mut encoder);
        encoder.finish()
    }

    /// Computes the canonical content digest of this alert record.
    #[must_use]
    pub fn record_digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.canonical_bytes())
    }

    /// Deserializes an alert effect record from canonical bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, EventTransitionError> {
        let mut decoder = CanonicalDecoder::new(bytes);
        let root = decoder.text().map_err(|_| {
            EventTransitionError::Decode(EventDecodeError::NonCanonicalEncoding {
                detail: "missing root canonical tag".to_string(),
            })
        })?;
        if root != "fss.canonical.v1" {
            return Err(EventTransitionError::Decode(
                EventDecodeError::SchemaMismatch {
                    expected: "fss.canonical.v1",
                    found: root.to_string(),
                },
            ));
        }
        let record = Self::decode_canonical(&mut decoder).map_err(|e| {
            EventTransitionError::Decode(EventDecodeError::NonCanonicalEncoding {
                detail: format!("failed to decode alert effect record: {e:?}"),
            })
        })?;
        if !decoder.is_empty() {
            return Err(EventTransitionError::Decode(
                EventDecodeError::TrailingBytes {
                    count: decoder.remaining(),
                },
            ));
        }
        Ok(record)
    }
}

impl CanonicalEncode for AlertEffectRecord {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        self.operation_id.encode_canonical(encoder);
        self.obligation_id.encode_canonical(encoder);
        encoder.u64(self.event_revision);
        encoder.digest(self.event_revision_digest);
        self.effect_state.encode_canonical(encoder);
        self.timestamp_ns.encode_canonical(encoder);
        encoder.text(&self.channel);
        match &self.observation_receipt {
            Some(digest) => {
                encoder.bool(true);
                encoder.digest(*digest);
            }
            None => {
                encoder.bool(false);
            }
        }
        match &self.failure_reason {
            Some(reason) => {
                encoder.bool(true);
                encoder.text(reason);
            }
            None => {
                encoder.bool(false);
            }
        }
    }
}

impl CanonicalDecode for AlertEffectRecord {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let schema = decoder.text()?;
        if schema != Self::SCHEMA {
            return Err(ContractError::InvalidIdentifier);
        }
        let operation_id = OperationId::decode_canonical(decoder)?;
        let obligation_id = ObligationId::decode_canonical(decoder)?;
        let event_revision = decoder.u64()?;
        let event_revision_digest = decoder.digest()?;
        let effect_state = EffectState::decode_canonical(decoder)?;
        let timestamp_ns = TimestampNs::decode_canonical(decoder)?;
        let channel = decoder.text()?.to_string();
        let has_receipt = decoder.bool()?;
        let observation_receipt = if has_receipt {
            Some(decoder.digest()?)
        } else {
            None
        };
        let has_failure = decoder.bool()?;
        let failure_reason = if has_failure {
            Some(decoder.text()?.to_string())
        } else {
            None
        };
        let record = Self {
            operation_id,
            obligation_id,
            event_revision,
            event_revision_digest,
            effect_state,
            timestamp_ns,
            channel,
            observation_receipt,
            failure_reason,
        };
        record
            .verify()
            .map_err(|_| ContractError::InvalidIdentifier)?;
        Ok(record)
    }
}

/// Parameters for constructing a superseding event revision in an event lineage.
#[derive(Clone, Debug, PartialEq)]
pub struct EventTransitionParams {
    /// Target event lifecycle state.
    pub target_state: EventState,
    /// Semantic event class.
    pub kind: EventKind,
    /// Physical observation time interval.
    pub interval: CaptureInterval,
    /// Bounded temporal uncertainty explanation.
    pub uncertainty_reason: Option<String>,
    /// Spatial zone identifiers.
    pub zone_ids: Vec<String>,
    /// Correlated entity track identifiers.
    pub track_ids: Vec<String>,
    /// Calibrated probability interval.
    pub probability: ProbabilityInterval,
    /// Evidence edges (supporting and contradicting).
    pub evidence: Vec<EventEvidence>,
    /// Model execution receipts.
    pub model_receipts: Vec<ContentDigest>,
    /// Evaluated policy decision path.
    pub decision_path: DecisionPath,
    /// Whether an explicit urgent single-sensor policy exception is asserted.
    pub urgent_single_sensor: bool,
}

/// Deterministic, immutable event revision lineage managing exact state transitions.
///
/// Invariants enforced:
/// - State is monotone within the lineage; corrections supersede earlier revisions.
/// - Transitions follow the exact registered transition table (`EVENT_TRANSITION_TABLE`).
/// - Event state and effect outcome remain strictly orthogonal.
/// - Corroboration strictly requires independent failure domains (>= 2 distinct domains).
/// - Urgent single-sensor policy exceptions advance while remaining explicitly labeled.
/// - Duplicate evidence items falsely counted twice are rejected.
/// - Rejection and Indeterminate retain earlier evidence and obligations.
#[derive(Clone, Debug, PartialEq)]
pub struct EventLineage {
    chain: Vec<EventHypothesis>,
    alert_attempts: Vec<AlertEffectRecord>,
}

impl EventLineage {
    /// Creates a new event lineage starting from a genesis hypothesis (revision 1).
    pub fn new(genesis: EventHypothesis) -> Result<Self, EventTransitionError> {
        if genesis.revision != 1 {
            return Err(EventTransitionError::RevisionNotMonotonic {
                expected: 1,
                actual: genesis.revision,
            });
        }
        if genesis.supersedes.is_some() {
            return Err(EventTransitionError::Contradiction {
                field: "supersedes",
                detail: "genesis revision 1 cannot supersede a prior revision".to_string(),
            });
        }
        if genesis.state != EventState::Hypothesized {
            return Err(EventTransitionError::IllegalStateTransition {
                from: EventState::Hypothesized,
                to: genesis.state,
                reason: "event lineage genesis must begin in Hypothesized state",
            });
        }
        genesis.verify()?;
        Ok(Self {
            chain: vec![genesis],
            alert_attempts: Vec::new(),
        })
    }

    /// Returns the current (latest) event revision.
    #[must_use]
    pub fn current(&self) -> &EventHypothesis {
        &self.chain[self.chain.len() - 1]
    }

    /// Returns the complete immutable history of event revisions.
    #[must_use]
    pub fn history(&self) -> &[EventHypothesis] {
        &self.chain
    }

    /// Returns the number of revisions in the lineage.
    #[must_use]
    pub fn len(&self) -> usize {
        self.chain.len()
    }

    /// Returns true if the lineage has no revisions (always false for valid lineages).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    /// Returns the stable event identifier.
    #[must_use]
    pub fn event_id(&self) -> &EventId {
        &self.chain[0].event_id
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub fn current_state(&self) -> EventState {
        self.current().state
    }

    /// Returns the current revision number.
    #[must_use]
    pub fn current_revision(&self) -> u64 {
        self.current().revision
    }

    /// Returns the accumulated sensor tamper status across this lineage.
    #[must_use]
    pub fn sensor_tamper_status(&self) -> SensorTamperStatus {
        compute_sensor_tamper_status(self.chain.iter(), None)
    }

    /// Returns true if any unretired sensor-tamper risk exists in this lineage.
    #[must_use]
    pub fn has_open_sensor_tamper(&self) -> bool {
        self.sensor_tamper_status().has_open_tamper()
    }

    /// Returns the failure domains with unretired sensor-tamper reports.
    #[must_use]
    pub fn open_sensor_tamper_domains(&self) -> BTreeSet<String> {
        self.sensor_tamper_status().open_domains
    }

    /// Returns the highest canonical progression state reached so far in the lineage.
    #[must_use]
    pub fn highest_canonical_state(&self) -> Option<EventState> {
        let mut highest: Option<(u8, EventState)> = None;
        for rev in &self.chain {
            if let Some(rank) = rev.state.canonical_rank() {
                match highest {
                    Some((h_rank, _)) if rank > h_rank => {
                        highest = Some((rank, rev.state));
                    }
                    None => {
                        highest = Some((rank, rev.state));
                    }
                    _ => {}
                }
            }
        }
        highest.map(|(_, s)| s)
    }

    /// Returns all recorded alert effect attempts.
    #[must_use]
    pub fn alert_attempts(&self) -> &[AlertEffectRecord] {
        &self.alert_attempts
    }

    /// Analyzes corroboration and failure domains for the current revision.
    #[must_use]
    pub fn analyze_corroboration(&self) -> CorroborationAnalysis {
        self.current().analyze_corroboration()
    }

    /// Transitions the lineage to a new immutable superseding revision.
    pub fn transition(
        &mut self,
        params: EventTransitionParams,
    ) -> Result<&EventHypothesis, EventTransitionError> {
        if self.chain.len() >= MAX_LINEAGE_DEPTH {
            return Err(EventTransitionError::OverLimitLength {
                field: "lineage.chain",
                limit: MAX_LINEAGE_DEPTH,
                actual: self.chain.len() + 1,
            });
        }

        let current = self.current();

        // Terminal state check
        if current.state.is_terminal() {
            return Err(EventTransitionError::TerminalStateImmutable {
                state: current.state,
            });
        }

        // Transition table rule check
        let rule = get_event_transition_rule(current.state, params.target_state).ok_or(
            EventTransitionError::IllegalStateTransition {
                from: current.state,
                to: params.target_state,
                reason: "transition not permitted by event state machine",
            },
        )?;

        // Urgent single-sensor exception check
        if rule.requires_urgent_exception {
            if !params.urgent_single_sensor {
                return Err(EventTransitionError::UrgentExceptionRequired);
            }
            if !params
                .uncertainty_reason
                .as_deref()
                .is_some_and(|r| r.contains(SINGLE_DOMAIN_UNCONFIRMED_LABEL))
            {
                return Err(EventTransitionError::Contradiction {
                    field: "uncertainty_reason",
                    detail: format!(
                        "urgent single-sensor transition requires uncertainty_reason to contain '{SINGLE_DOMAIN_UNCONFIRMED_LABEL}'"
                    ),
                });
            }
        }

        // Transitions to Adjudicated require prior corroboration OR >= 2 supporting failure domains,
        // unless an urgent single-sensor policy exception is explicitly claimed and labeled.
        if params.target_state == EventState::Adjudicated {
            let previously_corroborated = self
                .chain
                .iter()
                .any(|r| r.state == EventState::Corroborated);
            let failure_domains: BTreeSet<_> = params
                .evidence
                .iter()
                .filter(|edge| edge.counts_as_support())
                .map(|edge| edge.failure_domain.as_str())
                .collect();
            let is_corroborated = previously_corroborated || failure_domains.len() >= 2;

            if !is_corroborated {
                if !params.urgent_single_sensor {
                    return Err(EventTransitionError::UrgentExceptionRequired);
                }
                if !params
                    .uncertainty_reason
                    .as_deref()
                    .is_some_and(|r| r.contains(SINGLE_DOMAIN_UNCONFIRMED_LABEL))
                {
                    return Err(EventTransitionError::Contradiction {
                        field: "uncertainty_reason",
                        detail: format!(
                            "urgent single-sensor transition requires uncertainty_reason to contain '{SINGLE_DOMAIN_UNCONFIRMED_LABEL}'"
                        ),
                    });
                }
            }
        }

        // Monotonicity check from Indeterminate
        if current.state == EventState::Indeterminate
            && let Some(target_rank) = params.target_state.canonical_rank()
            && let Some(highest) = self.highest_canonical_state()
            && let Some(highest_rank) = highest.canonical_rank()
            && target_rank < highest_rank
        {
            return Err(EventTransitionError::NonMonotonicTransition {
                from: current.state,
                to: params.target_state,
                highest_reached: highest,
            });
        }

        // Duplicate evidence check
        let mut seen_digests = BTreeSet::new();
        for edge in &params.evidence {
            if !seen_digests.insert(edge.digest) {
                return Err(EventTransitionError::DuplicateEvidence {
                    digest: edge.digest,
                });
            }
        }

        // Evidence required after initial hypothesis
        if params.target_state != EventState::Hypothesized && params.evidence.is_empty() {
            return Err(EventTransitionError::EvidenceRequired);
        }

        // Corroboration failure domain check
        if params.target_state == EventState::Corroborated {
            let failure_domains: BTreeSet<_> = params
                .evidence
                .iter()
                .filter(|edge| edge.counts_as_support())
                .map(|edge| edge.failure_domain.as_str())
                .collect();
            if failure_domains.len() < 2 {
                return Err(EventTransitionError::CorroborationRequired {
                    observed_domains: failure_domains.len(),
                });
            }
        }

        // Tampered sensing never establishes or acts on presence: refused before the revision is
        // built, with a typed transition error. Tamper status is sticky across the lineage:
        // open tamper risks persist until an explicit, evidenced integrity restoration retires them.
        let tamper_status = compute_sensor_tamper_status_with_interval(
            self.chain.iter(),
            Some(&params.evidence),
            Some(params.interval),
        );
        if sensor_tamper_vetoes(params.target_state) && tamper_status.has_open_tamper() {
            return Err(EventTransitionError::SensorIntegrityRisk);
        }

        let mut final_evidence = params.evidence;
        for prior_edge in self.chain.iter().flat_map(|r| r.evidence.iter()) {
            if prior_edge.reports_sensor_tamper()
                && tamper_status.open_tamper_roots.contains(&prior_edge.digest)
                && !final_evidence
                    .iter()
                    .any(|e| e.digest == prior_edge.digest && e.relation == prior_edge.relation)
            {
                final_evidence.push(prior_edge.clone());
            }
        }

        let next_revision =
            current
                .revision
                .checked_add(1)
                .ok_or(EventTransitionError::RevisionNotMonotonic {
                    expected: u64::MAX,
                    actual: 0,
                })?;
        let prev_digest = current.revision_digest();

        let rev = EventHypothesis {
            schema: EventHypothesis::SCHEMA.to_string(),
            event_id: current.event_id.clone(),
            revision: next_revision,
            supersedes: Some(prev_digest),
            state: params.target_state,
            kind: params.kind,
            interval: params.interval,
            uncertainty_reason: params.uncertainty_reason,
            zone_ids: params.zone_ids,
            track_ids: params.track_ids,
            probability: params.probability,
            evidence: final_evidence,
            model_receipts: params.model_receipts,
            decision_path: params.decision_path,
        };

        rev.verify()?;
        self.chain.push(rev);
        Ok(self.current())
    }

    /// Records an alert effect dispatch attempt without modifying the event lifecycle state.
    ///
    /// Preserves strict orthogonality between event state and effect execution.
    pub fn record_alert_attempt(
        &mut self,
        record: AlertEffectRecord,
    ) -> Result<(), EventTransitionError> {
        record.verify()?;
        if self.alert_attempts.len() >= MAX_ALERT_ATTEMPTS_COUNT {
            return Err(EventTransitionError::OverLimitLength {
                field: "lineage.alert_attempts",
                limit: MAX_ALERT_ATTEMPTS_COUNT,
                actual: self.alert_attempts.len() + 1,
            });
        }
        let current = self.current();
        if record.event_revision > current.revision {
            return Err(EventTransitionError::RevisionNotMonotonic {
                expected: current.revision,
                actual: record.event_revision,
            });
        }
        self.alert_attempts.push(record);
        Ok(())
    }

    /// Reconstructs and validates an immutable event lineage from an ordered slice of event revisions.
    ///
    /// The revisions must also pass [`EventHypothesis::verify_chain`]'s rules, so replay and chain
    /// verification reach the same verdict on every chain.
    pub fn from_revisions(revisions: Vec<EventHypothesis>) -> Result<Self, EventTransitionError> {
        let genesis = revisions
            .first()
            .ok_or_else(|| EventTransitionError::Contradiction {
                field: "revisions",
                detail: "revision list cannot be empty".to_string(),
            })?;
        // The lineage lifecycle rules for a genesis, including that it begins `Hypothesized`.
        Self::new(genesis.clone())?;
        let lineage = Self::replay_append_rules(revisions)?;
        // Defensive: the append rules above already enforce every chain rule (revision verify,
        // the shared tamper step, identity, numbering, supersession, terminal state and the state
        // machine), so this cannot refuse a chain they accepted today. It keeps replay from
        // silently accepting a chain verification refuses if either rule set changes later.
        EventHypothesis::verify_chain_rules(&lineage.chain)?;
        Ok(lineage)
    }

    /// Replays revisions through the lineage append rules, with the genesis checked for revision,
    /// supersession and revision invariants but not for its lifecycle state.
    fn replay_append_rules(revisions: Vec<EventHypothesis>) -> Result<Self, EventTransitionError> {
        let mut revisions = revisions.into_iter();
        let genesis = revisions
            .next()
            .ok_or_else(|| EventTransitionError::Contradiction {
                field: "revisions",
                detail: "revision list cannot be empty".to_string(),
            })?;
        if genesis.revision != 1 {
            return Err(EventTransitionError::RevisionNotMonotonic {
                expected: 1,
                actual: genesis.revision,
            });
        }
        if genesis.supersedes.is_some() {
            return Err(EventTransitionError::Contradiction {
                field: "supersedes",
                detail: "genesis revision 1 cannot supersede a prior revision".to_string(),
            });
        }
        genesis.verify()?;
        let mut lineage = Self {
            chain: vec![genesis],
            alert_attempts: Vec::new(),
        };
        for rev in revisions {
            lineage.append_verified_revision(rev)?;
        }
        Ok(lineage)
    }

    /// Appends a verified superseding revision directly, enforcing transition rules.
    fn append_verified_revision(
        &mut self,
        rev: EventHypothesis,
    ) -> Result<(), EventTransitionError> {
        if self.chain.len() >= MAX_LINEAGE_DEPTH {
            return Err(EventTransitionError::OverLimitLength {
                field: "lineage.chain",
                limit: MAX_LINEAGE_DEPTH,
                actual: self.chain.len() + 1,
            });
        }
        if rev.state != EventState::Hypothesized && rev.evidence.is_empty() {
            return Err(EventTransitionError::EvidenceRequired);
        }
        if rev.state == EventState::Corroborated {
            let failure_domains: BTreeSet<_> = rev
                .evidence
                .iter()
                .filter(|edge| edge.counts_as_support())
                .map(|edge| edge.failure_domain.as_str())
                .collect();
            if failure_domains.len() < 2 {
                return Err(EventTransitionError::CorroborationRequired {
                    observed_domains: failure_domains.len(),
                });
            }
        }
        if rev.state == EventState::Adjudicated {
            let previously_corroborated = self
                .chain
                .iter()
                .any(|r| r.state == EventState::Corroborated);
            let failure_domains: BTreeSet<_> = rev
                .evidence
                .iter()
                .filter(|edge| edge.counts_as_support())
                .map(|edge| edge.failure_domain.as_str())
                .collect();
            let is_corroborated = previously_corroborated || failure_domains.len() >= 2;
            if !is_corroborated && !rev.is_single_domain_unconfirmed() {
                return Err(EventTransitionError::UrgentExceptionRequired);
            }
        }
        // Replay refuses a tamper-vetoed revision, or one that drops an unretired tamper, with the
        // same typed error as a transition. The revision's own capture interval orders its batch,
        // through the same step chain verification uses.
        let mut tamper_status = compute_sensor_tamper_status(self.chain.iter(), None);
        apply_revision_tamper_step(&mut tamper_status, &rev).map_err(|err| match err {
            ContractError::SensorIntegrityRisk => EventTransitionError::SensorIntegrityRisk,
            other => EventTransitionError::Contract(other),
        })?;
        rev.verify()?;
        let current = self.current();
        if rev.event_id != current.event_id {
            return Err(EventTransitionError::EventIdMismatch {
                expected: current.event_id.clone(),
                actual: rev.event_id,
            });
        }
        let expected_rev = current.revision + 1;
        if rev.revision != expected_rev {
            return Err(EventTransitionError::RevisionNotMonotonic {
                expected: expected_rev,
                actual: rev.revision,
            });
        }
        let expected_supersedes = current.revision_digest();
        if rev.supersedes != Some(expected_supersedes) {
            return Err(EventTransitionError::DigestMismatch {
                expected: expected_supersedes,
                actual: rev.supersedes,
            });
        }
        if current.state.is_terminal() {
            return Err(EventTransitionError::TerminalStateImmutable {
                state: current.state,
            });
        }
        let urgent = rev.is_single_domain_unconfirmed();
        if !is_allowed_event_transition(current.state, rev.state, urgent) {
            return Err(EventTransitionError::IllegalStateTransition {
                from: current.state,
                to: rev.state,
                reason: "transition not permitted by event state machine",
            });
        }
        if current.state == EventState::Indeterminate
            && let Some(target_rank) = rev.state.canonical_rank()
            && let Some(highest) = self.highest_canonical_state()
            && let Some(highest_rank) = highest.canonical_rank()
            && target_rank < highest_rank
        {
            return Err(EventTransitionError::NonMonotonicTransition {
                from: current.state,
                to: rev.state,
                highest_reached: highest,
            });
        }
        let mut seen = BTreeSet::new();
        for edge in &rev.evidence {
            if !seen.insert(edge.digest) {
                return Err(EventTransitionError::DuplicateEvidence {
                    digest: edge.digest,
                });
            }
        }
        self.chain.push(rev);
        Ok(())
    }

    /// Replays an event lineage from evidence deltas and a revision resolver.
    pub fn replay_from_deltas<F>(
        event_id: &EventId,
        deltas: &[crate::evidence::EvidenceDelta],
        resolver: F,
    ) -> Result<Self, EventTransitionError>
    where
        F: Fn(&ContentDigest) -> Option<EventHypothesis>,
    {
        let mut event_deltas: Vec<&crate::evidence::EvidenceDelta> = deltas
            .iter()
            .filter(|d| d.family == "event_revision" && d.object_id.as_str() == event_id.as_str())
            .collect();
        event_deltas.sort_by_key(|d| d.new_generation);
        if event_deltas.is_empty() {
            return Err(EventTransitionError::Contradiction {
                field: "deltas",
                detail: format!("no event_revision deltas found for event {}", event_id),
            });
        }
        let mut revisions = Vec::with_capacity(event_deltas.len());
        for d in event_deltas {
            let rev =
                resolver(&d.payload_digest).ok_or_else(|| EventTransitionError::Contradiction {
                    field: "payload_digest",
                    detail: format!(
                        "revision payload not found for digest {:?}",
                        d.payload_digest
                    ),
                })?;
            if let Some(w) = d.witness_digest {
                let actual_digest = rev.revision_digest();
                if w != actual_digest {
                    return Err(EventTransitionError::DigestMismatch {
                        expected: w,
                        actual: Some(actual_digest),
                    });
                }
            }
            revisions.push(rev);
        }
        Self::from_revisions(revisions)
    }

    /// Validates the full chain and all state transitions across the lineage.
    pub fn verify(&self) -> Result<(), EventTransitionError> {
        if self.chain.is_empty() {
            return Err(EventTransitionError::Contradiction {
                field: "chain",
                detail: "lineage chain cannot be empty".to_string(),
            });
        }
        if self.chain.len() > MAX_LINEAGE_DEPTH {
            return Err(EventTransitionError::OverLimitLength {
                field: "chain",
                limit: MAX_LINEAGE_DEPTH,
                actual: self.chain.len(),
            });
        }
        if self.alert_attempts.len() > MAX_ALERT_ATTEMPTS_COUNT {
            return Err(EventTransitionError::OverLimitLength {
                field: "alert_attempts",
                limit: MAX_ALERT_ATTEMPTS_COUNT,
                actual: self.alert_attempts.len(),
            });
        }
        for record in &self.alert_attempts {
            record.verify()?;
        }
        let genesis = &self.chain[0];
        if genesis.revision != 1 {
            return Err(EventTransitionError::RevisionNotMonotonic {
                expected: 1,
                actual: genesis.revision,
            });
        }
        if genesis.supersedes.is_some() {
            return Err(EventTransitionError::Contradiction {
                field: "supersedes",
                detail: "genesis revision cannot supersede a prior revision".to_string(),
            });
        }
        if genesis.state != EventState::Hypothesized {
            return Err(EventTransitionError::IllegalStateTransition {
                from: EventState::Hypothesized,
                to: genesis.state,
                reason: "genesis must begin in Hypothesized state",
            });
        }
        genesis.verify()?;

        let mut highest_rank = genesis.state.canonical_rank();
        let mut highest_state = Some(genesis.state);

        for (i, pair) in self.chain.windows(2).enumerate() {
            let prev = &pair[0];
            let curr = &pair[1];
            if curr.state != EventState::Hypothesized && curr.evidence.is_empty() {
                return Err(EventTransitionError::EvidenceRequired);
            }
            if curr.state == EventState::Corroborated {
                let failure_domains: BTreeSet<_> = curr
                    .evidence
                    .iter()
                    .filter(|edge| edge.counts_as_support())
                    .map(|edge| edge.failure_domain.as_str())
                    .collect();
                if failure_domains.len() < 2 {
                    return Err(EventTransitionError::CorroborationRequired {
                        observed_domains: failure_domains.len(),
                    });
                }
            }
            if curr.state == EventState::Adjudicated {
                let previously_corroborated = self.chain[..=i]
                    .iter()
                    .any(|r| r.state == EventState::Corroborated);
                let failure_domains: BTreeSet<_> = curr
                    .evidence
                    .iter()
                    .filter(|edge| edge.counts_as_support())
                    .map(|edge| edge.failure_domain.as_str())
                    .collect();
                let is_corroborated = previously_corroborated || failure_domains.len() >= 2;
                if !is_corroborated && !curr.is_single_domain_unconfirmed() {
                    return Err(EventTransitionError::UrgentExceptionRequired);
                }
            }
            curr.verify()?;
            if curr.event_id != prev.event_id {
                return Err(EventTransitionError::EventIdMismatch {
                    expected: prev.event_id.clone(),
                    actual: curr.event_id.clone(),
                });
            }
            let expected_rev = (i as u64) + 2;
            if curr.revision != expected_rev {
                return Err(EventTransitionError::RevisionNotMonotonic {
                    expected: expected_rev,
                    actual: curr.revision,
                });
            }
            let prev_digest = prev.revision_digest();
            if curr.supersedes != Some(prev_digest) {
                return Err(EventTransitionError::DigestMismatch {
                    expected: prev_digest,
                    actual: curr.supersedes,
                });
            }
            if prev.state.is_terminal() {
                return Err(EventTransitionError::TerminalStateImmutable { state: prev.state });
            }
            let urgent = curr.is_single_domain_unconfirmed();
            if !is_allowed_event_transition(prev.state, curr.state, urgent) {
                return Err(EventTransitionError::IllegalStateTransition {
                    from: prev.state,
                    to: curr.state,
                    reason: "transition not permitted by event state machine",
                });
            }
            if prev.state == EventState::Indeterminate
                && let Some(curr_rank) = curr.state.canonical_rank()
                && let Some(h_rank) = highest_rank
                && let Some(h_state) = highest_state
                && curr_rank < h_rank
            {
                return Err(EventTransitionError::NonMonotonicTransition {
                    from: prev.state,
                    to: curr.state,
                    highest_reached: h_state,
                });
            }
            if let Some(rank) = curr.state.canonical_rank() {
                match highest_rank {
                    Some(h) if rank > h => {
                        highest_rank = Some(rank);
                        highest_state = Some(curr.state);
                    }
                    None => {
                        highest_rank = Some(rank);
                        highest_state = Some(curr.state);
                    }
                    _ => {}
                }
            }
            let mut seen = BTreeSet::new();
            for edge in &curr.evidence {
                if !seen.insert(edge.digest) {
                    return Err(EventTransitionError::DuplicateEvidence {
                        digest: edge.digest,
                    });
                }
            }
        }
        Ok(())
    }
}

impl CanonicalEncode for EventHypothesis {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        self.event_id.encode_canonical(encoder);
        encoder.u64(self.revision);
        match &self.supersedes {
            Some(s) => {
                encoder.bool(true);
                encoder.digest(*s);
            }
            None => {
                encoder.bool(false);
            }
        }
        encoder.u8(self.state.to_u8());
        encoder.u8(self.kind.to_u8());
        self.interval.encode_canonical(encoder);
        match &self.uncertainty_reason {
            Some(r) => {
                encoder.bool(true);
                encoder.text(r);
            }
            None => {
                encoder.bool(false);
            }
        }
        encoder.u64(self.zone_ids.len() as u64);
        for zone in &self.zone_ids {
            encoder.text(zone);
        }
        encoder.u64(self.track_ids.len() as u64);
        for track in &self.track_ids {
            encoder.text(track);
        }
        self.probability.encode_canonical(encoder);
        encoder.u64(self.evidence.len() as u64);
        for edge in &self.evidence {
            edge.encode_canonical(encoder);
        }
        encoder.u64(self.model_receipts.len() as u64);
        for receipt in &self.model_receipts {
            encoder.digest(*receipt);
        }
        self.decision_path.encode_canonical(encoder);
    }
}

impl CanonicalDecode for EventHypothesis {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Self::decode_canonical_checked(decoder).map_err(|e| match e {
            EventDecodeError::Contract(c) => c,
            _ => ContractError::InvalidIdentifier,
        })
    }
}

/// Causal evidence graph over capsules, identities, model receipts, and revisions.
#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceGraph {
    /// Canonical schema identifier.
    pub schema: String,
    /// Unique graph identifier.
    pub graph_id: String,
    /// Associated event lineage.
    pub event_id: EventId,
    /// Monotone revision of this evidence graph.
    pub revision: u64,
    /// Root digest of the evidence graph envelope.
    pub root_digest: ContentDigest,
    /// Graph nodes (entities, identities, capsules).
    pub nodes: Vec<EvidenceNode>,
    /// Directed graph edges referencing capsules and identity digests.
    pub edges: Vec<EventEvidence>,
}

impl EvidenceGraph {
    /// Canonical schema name.
    pub const SCHEMA: &'static str = "fss.evidence_graph.v1";

    /// Validates evidence graph invariants and hard bounds.
    pub fn verify(&self) -> Result<(), EventDecodeError> {
        if self.schema != Self::SCHEMA {
            return Err(EventDecodeError::SchemaMismatch {
                expected: Self::SCHEMA,
                found: self.schema.clone(),
            });
        }
        if self.graph_id.is_empty() {
            return Err(EventDecodeError::Contradiction {
                field: "graphId",
                detail: "graphId must not be empty".to_string(),
            });
        }
        if self.graph_id.len() > MAX_GRAPH_ID_LEN {
            return Err(EventDecodeError::OverLimitLength {
                field: "graphId",
                limit: MAX_GRAPH_ID_LEN,
                actual: self.graph_id.len(),
            });
        }
        if self.event_id.as_str().len() > MAX_EVENT_ID_LEN {
            return Err(EventDecodeError::OverLimitLength {
                field: "eventId",
                limit: MAX_EVENT_ID_LEN,
                actual: self.event_id.as_str().len(),
            });
        }
        if self.revision == 0 {
            return Err(EventDecodeError::OutOfRange {
                field: "revision",
                minimum: 1,
                maximum: u64::MAX,
                actual: 0,
            });
        }
        if self.nodes.len() > MAX_NODES_COUNT {
            return Err(EventDecodeError::OverLimitLength {
                field: "nodes",
                limit: MAX_NODES_COUNT,
                actual: self.nodes.len(),
            });
        }
        for node in &self.nodes {
            node.verify()?;
        }
        if self.edges.len() > MAX_EDGES_COUNT {
            return Err(EventDecodeError::OverLimitLength {
                field: "edges",
                limit: MAX_EDGES_COUNT,
                actual: self.edges.len(),
            });
        }
        let node_digests: std::collections::BTreeSet<ContentDigest> =
            self.nodes.iter().map(|n| n.digest).collect();

        let mut supersedes_count = 0;
        for edge in &self.edges {
            edge.verify()?;
            if !node_digests.contains(&edge.digest) {
                return Err(EventDecodeError::Contradiction {
                    field: "edges.digest",
                    detail: format!("edge digest {} not found in graph nodes", edge.digest),
                });
            }
            if let Some(cd) = &edge.capsule_digest
                && !node_digests.contains(cd)
            {
                return Err(EventDecodeError::Contradiction {
                    field: "edges.capsuleDigest",
                    detail: format!("edge capsule digest {cd} not found in graph nodes"),
                });
            }
            if let Some(id) = &edge.identity_digest
                && !node_digests.contains(id)
            {
                return Err(EventDecodeError::Contradiction {
                    field: "edges.identityDigest",
                    detail: format!("edge identity digest {id} not found in graph nodes"),
                });
            }
            if edge.relation == EvidenceEdgeRelation::Supersedes {
                supersedes_count += 1;
                if supersedes_count > 1 {
                    return Err(EventDecodeError::Contradiction {
                        field: "edges.relation",
                        detail: "evidence graph cannot contain multiple supersession edges (fork rejected)".to_string(),
                    });
                }
                if edge.digest == self.root_digest {
                    return Err(EventDecodeError::Contradiction {
                        field: "edges.relation",
                        detail: "supersession edge cannot target own root digest (cycle detected)"
                            .to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Computes canonical graph digest.
    #[must_use]
    pub fn graph_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.canonical.v1");
        encoder.text(Self::SCHEMA);
        self.encode_canonical(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Returns iterator over supporting evidence edges.
    pub fn supporting_edges(&self) -> impl Iterator<Item = &EventEvidence> {
        self.edges.iter().filter(|e| e.counts_as_support())
    }

    /// Returns iterator over contradicting evidence edges.
    pub fn contradicting_edges(&self) -> impl Iterator<Item = &EventEvidence> {
        self.edges.iter().filter(|e| e.counts_as_contradiction())
    }

    /// Returns all distinct failure domains present in nodes and edges.
    pub fn failure_domains(&self) -> BTreeSet<&str> {
        let mut set = BTreeSet::new();
        for node in &self.nodes {
            if !node.failure_domain.is_empty() {
                set.insert(node.failure_domain.as_str());
            }
        }
        for edge in &self.edges {
            if !edge.failure_domain.is_empty() {
                set.insert(edge.failure_domain.as_str());
            }
        }
        set
    }

    /// Returns set of all capsule digests referenced by edges.
    pub fn referenced_capsules(&self) -> BTreeSet<ContentDigest> {
        let mut set = BTreeSet::new();
        for edge in &self.edges {
            if let Some(cd) = edge.capsule_digest {
                set.insert(cd);
            }
        }
        set
    }

    /// Returns set of all identity digests referenced by edges.
    pub fn referenced_identities(&self) -> BTreeSet<ContentDigest> {
        let mut set = BTreeSet::new();
        for edge in &self.edges {
            if let Some(id) = edge.identity_digest {
                set.insert(id);
            }
        }
        set
    }

    /// Serializes this evidence graph into the canonical versioned binary envelope (`FSSG` v1).
    pub fn to_versioned_bytes(&self) -> Result<Vec<u8>, EventDecodeError> {
        self.verify()?;
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        let payload = encoder
            .finish_checked()
            .map_err(EventDecodeError::Contract)?;

        let mut out = Vec::with_capacity(6 + payload.len());
        out.extend_from_slice(&EVIDENCE_GRAPH_MAGIC);
        out.extend_from_slice(&EVIDENCE_GRAPH_VERSION_1.to_be_bytes());
        out.extend_from_slice(&payload);
        Ok(out)
    }

    /// Decodes an evidence graph from a complete versioned binary envelope (`FSSG` v1).
    pub fn from_versioned_bytes(bytes: &[u8]) -> Result<Self, EventDecodeError> {
        if bytes.len() < 6 {
            return Err(EventDecodeError::Truncated {
                expected_min: 6,
                actual: bytes.len(),
            });
        }
        if bytes[0..4] != EVIDENCE_GRAPH_MAGIC {
            return Err(EventDecodeError::NonCanonicalEncoding {
                detail: "invalid magic header: expected FSSG".to_string(),
            });
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != EVIDENCE_GRAPH_VERSION_1 {
            return Err(EventDecodeError::UnknownVersion { version });
        }

        let payload = &bytes[6..];
        let mut decoder = CanonicalDecoder::new(payload);
        let graph = Self::decode_canonical_checked(&mut decoder)?;
        if !decoder.is_empty() {
            return Err(EventDecodeError::TrailingBytes {
                count: decoder.remaining(),
            });
        }
        graph.verify()?;

        let mut re_encoder = CanonicalEncoder::new();
        graph.encode_canonical(&mut re_encoder);
        let reencoded = re_encoder
            .finish_checked()
            .map_err(EventDecodeError::Contract)?;
        if reencoded != payload {
            return Err(EventDecodeError::NonCanonicalEncoding {
                detail: "payload does not re-encode bit-identically".to_string(),
            });
        }
        Ok(graph)
    }

    fn decode_canonical_checked(
        decoder: &mut CanonicalDecoder<'_>,
    ) -> Result<Self, EventDecodeError> {
        let schema = decoder.text().map_err(|_| EventDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?;
        if schema != Self::SCHEMA {
            return Err(EventDecodeError::SchemaMismatch {
                expected: Self::SCHEMA,
                found: schema.to_string(),
            });
        }

        let graph_id = decoder
            .text()
            .map_err(|_| EventDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?
            .to_string();
        if graph_id.len() > MAX_GRAPH_ID_LEN {
            return Err(EventDecodeError::OverLimitLength {
                field: "graphId",
                limit: MAX_GRAPH_ID_LEN,
                actual: graph_id.len(),
            });
        }

        let event_id_str = decoder.text().map_err(|_| EventDecodeError::Truncated {
            expected_min: 1,
            actual: 0,
        })?;
        if event_id_str.len() > MAX_EVENT_ID_LEN {
            return Err(EventDecodeError::OverLimitLength {
                field: "eventId",
                limit: MAX_EVENT_ID_LEN,
                actual: event_id_str.len(),
            });
        }
        let event_id = EventId::parse(event_id_str).map_err(EventDecodeError::Contract)?;

        let revision = decoder.u64().map_err(|_| EventDecodeError::Truncated {
            expected_min: 8,
            actual: 0,
        })?;

        let root_digest = decoder.digest().map_err(EventDecodeError::Contract)?;

        let node_count = decoder.u64().map_err(|_| EventDecodeError::Truncated {
            expected_min: 8,
            actual: 0,
        })? as usize;
        if node_count > MAX_NODES_COUNT {
            return Err(EventDecodeError::OverLimitLength {
                field: "nodes",
                limit: MAX_NODES_COUNT,
                actual: node_count,
            });
        }
        let mut nodes = Vec::with_capacity(node_count);
        for _ in 0..node_count {
            let digest = decoder.digest().map_err(EventDecodeError::Contract)?;
            let kind = EvidenceNodeKind::from_u8(decoder.u8().map_err(|_| {
                EventDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                }
            })?)?;
            let label = decoder
                .text()
                .map_err(|_| EventDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                })?
                .to_string();
            if label.len() > MAX_NODE_LABEL_LEN {
                return Err(EventDecodeError::OverLimitLength {
                    field: "nodes.label",
                    limit: MAX_NODE_LABEL_LEN,
                    actual: label.len(),
                });
            }
            let failure_domain = decoder
                .text()
                .map_err(|_| EventDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                })?
                .to_string();
            if failure_domain.len() > MAX_FAILURE_DOMAIN_LEN {
                return Err(EventDecodeError::OverLimitLength {
                    field: "nodes.failureDomain",
                    limit: MAX_FAILURE_DOMAIN_LEN,
                    actual: failure_domain.len(),
                });
            }
            nodes.push(EvidenceNode {
                digest,
                kind,
                label,
                failure_domain,
            });
        }

        let edge_count = decoder.u64().map_err(|_| EventDecodeError::Truncated {
            expected_min: 8,
            actual: 0,
        })? as usize;
        if edge_count > MAX_EDGES_COUNT {
            return Err(EventDecodeError::OverLimitLength {
                field: "edges",
                limit: MAX_EDGES_COUNT,
                actual: edge_count,
            });
        }
        let mut edges = Vec::with_capacity(edge_count);
        for _ in 0..edge_count {
            let digest = decoder.digest().map_err(EventDecodeError::Contract)?;
            let class =
                evidence_class_from_u8(decoder.u8().map_err(|_| EventDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                })?)?;
            let failure_domain = decoder
                .text()
                .map_err(|_| EventDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                })?
                .to_string();
            if failure_domain.len() > MAX_FAILURE_DOMAIN_LEN {
                return Err(EventDecodeError::OverLimitLength {
                    field: "edges.failureDomain",
                    limit: MAX_FAILURE_DOMAIN_LEN,
                    actual: failure_domain.len(),
                });
            }
            let supports = decoder.bool().map_err(|_| EventDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?;
            let relation = EvidenceEdgeRelation::from_u8(decoder.u8().map_err(|_| {
                EventDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                }
            })?)?;
            let has_capsule = decoder.bool().map_err(|_| EventDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?;
            let capsule_digest = if has_capsule {
                Some(decoder.digest().map_err(EventDecodeError::Contract)?)
            } else {
                None
            };
            let has_id = decoder.bool().map_err(|_| EventDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            })?;
            let identity_digest = if has_id {
                Some(decoder.digest().map_err(EventDecodeError::Contract)?)
            } else {
                None
            };
            edges.push(EventEvidence {
                digest,
                class,
                failure_domain,
                supports,
                relation,
                capsule_digest,
                identity_digest,
            });
        }

        Ok(Self {
            schema: schema.to_string(),
            graph_id,
            event_id,
            revision,
            root_digest,
            nodes,
            edges,
        })
    }

    /// Emits a deterministic canonical JSON string projection.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut out = String::with_capacity(2048);
        out.push('{');

        // Deterministic alphabetical key serialization
        // 1. edges
        out.push_str("\"edges\":[");
        for (i, edge) in self.edges.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('{');
            out.push_str("\"capsuleDigest\":");
            match &edge.capsule_digest {
                Some(cd) => json_write_str(&mut out, &cd.to_string()),
                None => out.push_str("null"),
            }
            out.push_str(",\"class\":");
            json_write_str(&mut out, evidence_class_as_str(edge.class));
            out.push_str(",\"digest\":");
            json_write_str(&mut out, &edge.digest.to_string());
            out.push_str(",\"failureDomain\":");
            json_write_str(&mut out, &edge.failure_domain);
            out.push_str(",\"identityDigest\":");
            match &edge.identity_digest {
                Some(id) => json_write_str(&mut out, &id.to_string()),
                None => out.push_str("null"),
            }
            out.push_str(",\"relation\":");
            json_write_str(&mut out, edge.relation.as_str());
            out.push_str(",\"supports\":");
            out.push_str(if edge.supports { "true" } else { "false" });
            out.push('}');
        }
        out.push(']');
        out.push(',');

        // 2. eventId
        out.push_str("\"eventId\":");
        json_write_str(&mut out, self.event_id.as_str());
        out.push(',');

        // 3. graphId
        out.push_str("\"graphId\":");
        json_write_str(&mut out, &self.graph_id);
        out.push(',');

        // 4. nodes
        out.push_str("\"nodes\":[");
        for (i, node) in self.nodes.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('{');
            out.push_str("\"digest\":");
            json_write_str(&mut out, &node.digest.to_string());
            out.push_str(",\"failureDomain\":");
            json_write_str(&mut out, &node.failure_domain);
            out.push_str(",\"kind\":");
            json_write_str(&mut out, node.kind.as_str());
            out.push_str(",\"label\":");
            json_write_str(&mut out, &node.label);
            out.push('}');
        }
        out.push(']');
        out.push(',');

        // 5. revision
        out.push_str("\"revision\":");
        out.push_str(&self.revision.to_string());
        out.push(',');

        // 6. rootDigest
        out.push_str("\"rootDigest\":");
        json_write_str(&mut out, &self.root_digest.to_string());
        out.push(',');

        // 7. schema
        out.push_str("\"schema\":");
        json_write_str(&mut out, Self::SCHEMA);

        out.push('}');
        out
    }

    /// Parses an evidence graph from JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, EventDecodeError> {
        let value = parse_json_value(json_str)?;
        let obj = JsonObject::from_value(&value, "evidenceGraph")?;

        let schema_val = obj.str("schema")?;
        if schema_val != Self::SCHEMA {
            return Err(EventDecodeError::SchemaMismatch {
                expected: Self::SCHEMA,
                found: schema_val.to_string(),
            });
        }

        let graph_id = obj.str("graphId")?.to_string();
        if graph_id.len() > MAX_GRAPH_ID_LEN {
            return Err(EventDecodeError::OverLimitLength {
                field: "graphId",
                limit: MAX_GRAPH_ID_LEN,
                actual: graph_id.len(),
            });
        }

        let event_id_str = obj.str("eventId")?;
        if event_id_str.len() > MAX_EVENT_ID_LEN {
            return Err(EventDecodeError::OverLimitLength {
                field: "eventId",
                limit: MAX_EVENT_ID_LEN,
                actual: event_id_str.len(),
            });
        }
        let event_id = EventId::parse(event_id_str).map_err(EventDecodeError::Contract)?;

        let revision = obj.get("revision")?.as_u64()?;

        let root_digest =
            ContentDigest::parse(obj.str("rootDigest")?).map_err(EventDecodeError::Contract)?;

        let nodes_arr = match obj.get("nodes")? {
            JsonValue::Array(arr) => arr,
            _ => {
                return Err(EventDecodeError::JsonError {
                    detail: "nodes must be an array".to_string(),
                });
            }
        };
        if nodes_arr.len() > MAX_NODES_COUNT {
            return Err(EventDecodeError::OverLimitLength {
                field: "nodes",
                limit: MAX_NODES_COUNT,
                actual: nodes_arr.len(),
            });
        }
        let mut nodes = Vec::with_capacity(nodes_arr.len());
        for item in nodes_arr {
            let n_obj = JsonObject::from_value(item, "nodes[]")?;
            let digest =
                ContentDigest::parse(n_obj.str("digest")?).map_err(EventDecodeError::Contract)?;
            let kind = EvidenceNodeKind::parse(n_obj.str("kind")?)?;
            let label = n_obj.str("label")?.to_string();
            if label.len() > MAX_NODE_LABEL_LEN {
                return Err(EventDecodeError::OverLimitLength {
                    field: "nodes.label",
                    limit: MAX_NODE_LABEL_LEN,
                    actual: label.len(),
                });
            }
            let failure_domain = n_obj.str("failureDomain")?.to_string();
            if failure_domain.len() > MAX_FAILURE_DOMAIN_LEN {
                return Err(EventDecodeError::OverLimitLength {
                    field: "nodes.failureDomain",
                    limit: MAX_FAILURE_DOMAIN_LEN,
                    actual: failure_domain.len(),
                });
            }
            nodes.push(EvidenceNode {
                digest,
                kind,
                label,
                failure_domain,
            });
        }

        let edges_arr = match obj.get("edges")? {
            JsonValue::Array(arr) => arr,
            _ => {
                return Err(EventDecodeError::JsonError {
                    detail: "edges must be an array".to_string(),
                });
            }
        };
        if edges_arr.len() > MAX_EDGES_COUNT {
            return Err(EventDecodeError::OverLimitLength {
                field: "edges",
                limit: MAX_EDGES_COUNT,
                actual: edges_arr.len(),
            });
        }
        let mut edges = Vec::with_capacity(edges_arr.len());
        for (idx, item) in edges_arr.iter().enumerate() {
            let e_obj = JsonObject::from_value(item, "edges[]")?;
            let digest =
                ContentDigest::parse(e_obj.str("digest")?).map_err(EventDecodeError::Contract)?;
            let class = parse_evidence_class(e_obj.str("class")?)?;
            let failure_domain = e_obj.str("failureDomain")?.to_string();
            if failure_domain.len() > MAX_FAILURE_DOMAIN_LEN {
                return Err(EventDecodeError::OverLimitLength {
                    field: "edges.failureDomain",
                    limit: MAX_FAILURE_DOMAIN_LEN,
                    actual: failure_domain.len(),
                });
            }
            let supports = e_obj.get("supports")?.as_bool()?;
            let relation = EvidenceEdgeRelation::parse(e_obj.str("relation")?)?;

            let capsule_digest = match e_obj.get_opt("capsuleDigest") {
                Some(JsonValue::String(s)) => {
                    Some(ContentDigest::parse(s).map_err(EventDecodeError::Contract)?)
                }
                Some(JsonValue::Null) | None => None,
                _ => {
                    return Err(EventDecodeError::JsonError {
                        detail: format!("edges[{idx}].capsuleDigest must be string or null"),
                    });
                }
            };
            let identity_digest = match e_obj.get_opt("identityDigest") {
                Some(JsonValue::String(s)) => {
                    Some(ContentDigest::parse(s).map_err(EventDecodeError::Contract)?)
                }
                Some(JsonValue::Null) | None => None,
                _ => {
                    return Err(EventDecodeError::JsonError {
                        detail: format!("edges[{idx}].identityDigest must be string or null"),
                    });
                }
            };

            edges.push(EventEvidence {
                digest,
                class,
                failure_domain,
                supports,
                relation,
                capsule_digest,
                identity_digest,
            });
        }

        let graph = Self {
            schema: schema_val.to_string(),
            graph_id,
            event_id,
            revision,
            root_digest,
            nodes,
            edges,
        };
        graph.verify()?;
        Ok(graph)
    }
}

impl CanonicalEncode for EvidenceGraph {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        encoder.text(&self.graph_id);
        self.event_id.encode_canonical(encoder);
        encoder.u64(self.revision);
        encoder.digest(self.root_digest);
        encoder.u64(self.nodes.len() as u64);
        for node in &self.nodes {
            node.encode_canonical(encoder);
        }
        encoder.u64(self.edges.len() as u64);
        for edge in &self.edges {
            edge.encode_canonical(encoder);
        }
    }
}

impl CanonicalDecode for EvidenceGraph {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Self::decode_canonical_checked(decoder).map_err(|e| match e {
            EventDecodeError::Contract(c) => c,
            _ => ContractError::InvalidIdentifier,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers: canonical float encoding & minimal deterministic JSON codec
// ---------------------------------------------------------------------------

fn canonical_f64_bits(value: f64) -> u64 {
    if value == 0.0 {
        0
    } else if value.is_nan() {
        0x7ff8_0000_0000_0000
    } else {
        value.to_bits()
    }
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

fn json_write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            control if u32::from(control) < 0x20 => {
                let code = u32::from(control) as usize;
                out.push_str("\\u00");
                out.push(char::from(HEX_DIGITS[code >> 4]));
                out.push(char::from(HEX_DIGITS[code & 0xf]));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

fn format_json_f64(out: &mut String, v: f64) {
    if v == 0.0 {
        out.push_str("0.0");
    } else if v == 1.0 {
        out.push_str("1.0");
    } else {
        let s = format!("{v}");
        if !s.contains('.') {
            out.push_str(&s);
            out.push_str(".0");
        } else {
            out.push_str(&s);
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    NumberInt(i128),
    NumberFloat(f64),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    fn as_bool(&self) -> Result<bool, EventDecodeError> {
        match self {
            Self::Bool(b) => Ok(*b),
            _ => Err(EventDecodeError::JsonError {
                detail: "expected boolean".to_string(),
            }),
        }
    }

    fn as_u64(&self) -> Result<u64, EventDecodeError> {
        match self {
            Self::NumberInt(n) => {
                if *n < 0 || *n > (u64::MAX as i128) {
                    Err(EventDecodeError::JsonError {
                        detail: format!("number {n} out of u64 range"),
                    })
                } else {
                    Ok(*n as u64)
                }
            }
            _ => Err(EventDecodeError::JsonError {
                detail: "expected integer".to_string(),
            }),
        }
    }

    fn as_i128(&self) -> Result<i128, EventDecodeError> {
        match self {
            Self::NumberInt(n) => Ok(*n),
            _ => Err(EventDecodeError::JsonError {
                detail: "expected integer".to_string(),
            }),
        }
    }

    fn as_f64(&self) -> Result<f64, EventDecodeError> {
        match self {
            Self::NumberFloat(f) => Ok(*f),
            Self::NumberInt(n) => Ok(*n as f64),
            _ => Err(EventDecodeError::JsonError {
                detail: "expected number".to_string(),
            }),
        }
    }
}

struct JsonObject<'a> {
    fields: &'a [(String, JsonValue)],
    name: &'static str,
}

impl<'a> JsonObject<'a> {
    fn from_value(value: &'a JsonValue, name: &'static str) -> Result<Self, EventDecodeError> {
        match value {
            JsonValue::Object(fields) => Ok(Self { fields, name }),
            _ => Err(EventDecodeError::JsonError {
                detail: format!("expected JSON object for '{name}'"),
            }),
        }
    }

    fn get(&self, key: &str) -> Result<&'a JsonValue, EventDecodeError> {
        for (k, v) in self.fields {
            if k == key {
                return Ok(v);
            }
        }
        Err(EventDecodeError::JsonError {
            detail: format!("missing required field '{key}' in {}", self.name),
        })
    }

    fn get_opt(&self, key: &str) -> Option<&'a JsonValue> {
        for (k, v) in self.fields {
            if k == key {
                return Some(v);
            }
        }
        None
    }

    fn str(&self, key: &str) -> Result<&'a str, EventDecodeError> {
        match self.get(key)? {
            JsonValue::String(s) => Ok(s.as_str()),
            _ => Err(EventDecodeError::JsonError {
                detail: format!("field '{key}' in {} must be string", self.name),
            }),
        }
    }
}

const MAX_JSON_DEPTH: usize = 16;

fn parse_json_value(s: &str) -> Result<JsonValue, EventDecodeError> {
    let mut parser = JsonParser::new(s.as_bytes());
    let value = parser.parse_value(0)?;
    parser.skip_whitespace();
    if parser.pos < parser.src.len() {
        return Err(EventDecodeError::TrailingBytes {
            count: parser.src.len() - parser.pos,
        });
    }
    Ok(value)
}

struct JsonParser<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self { src, pos: 0 }
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.src.len() {
            match self.src[self.pos] {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonValue, EventDecodeError> {
        if depth > MAX_JSON_DEPTH {
            return Err(EventDecodeError::JsonError {
                detail: format!("maximum JSON nesting depth ({MAX_JSON_DEPTH}) exceeded"),
            });
        }
        self.skip_whitespace();
        if self.pos >= self.src.len() {
            return Err(EventDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            });
        }
        match self.src[self.pos] {
            b'n' => self.parse_null(),
            b't' | b'f' => self.parse_bool(),
            b'"' => self.parse_string().map(JsonValue::String),
            b'[' => self.parse_array(depth + 1),
            b'{' => self.parse_object(depth + 1),
            b'-' | b'0'..=b'9' => self.parse_number(),
            ch => Err(EventDecodeError::JsonError {
                detail: format!(
                    "unexpected character '{}' at offset {}",
                    ch as char, self.pos
                ),
            }),
        }
    }

    fn parse_null(&mut self) -> Result<JsonValue, EventDecodeError> {
        if self.src[self.pos..].starts_with(b"null") {
            self.pos += 4;
            Ok(JsonValue::Null)
        } else {
            Err(EventDecodeError::JsonError {
                detail: "invalid literal, expected 'null'".to_string(),
            })
        }
    }

    fn parse_bool(&mut self) -> Result<JsonValue, EventDecodeError> {
        if self.src[self.pos..].starts_with(b"true") {
            self.pos += 4;
            Ok(JsonValue::Bool(true))
        } else if self.src[self.pos..].starts_with(b"false") {
            self.pos += 5;
            Ok(JsonValue::Bool(false))
        } else {
            Err(EventDecodeError::JsonError {
                detail: "invalid boolean literal".to_string(),
            })
        }
    }

    fn parse_string(&mut self) -> Result<String, EventDecodeError> {
        if self.pos >= self.src.len() || self.src[self.pos] != b'"' {
            return Err(EventDecodeError::JsonError {
                detail: "expected string opening quote".to_string(),
            });
        }
        self.pos += 1; // skip opening quote
        let mut s = String::new();
        loop {
            let run_start = self.pos;
            while self.pos < self.src.len()
                && !matches!(self.src[self.pos], b'"' | b'\\' | 0x00..=0x1f)
            {
                self.pos += 1;
            }
            let run = core::str::from_utf8(&self.src[run_start..self.pos]).map_err(|_| {
                EventDecodeError::JsonError {
                    detail: "invalid utf-8 in string".to_string(),
                }
            })?;
            s.push_str(run);
            if self.pos >= self.src.len() {
                return Err(EventDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                });
            }
            let b = self.src[self.pos];
            self.pos += 1;
            match b {
                b'"' => return Ok(s),
                b'\\' => self.parse_escape(&mut s)?,
                control => {
                    return Err(EventDecodeError::JsonError {
                        detail: format!("unescaped control character U+{control:04X} in string"),
                    });
                }
            }
        }
    }

    fn parse_escape(&mut self, s: &mut String) -> Result<(), EventDecodeError> {
        if self.pos >= self.src.len() {
            return Err(EventDecodeError::Truncated {
                expected_min: 1,
                actual: 0,
            });
        }
        let esc = self.src[self.pos];
        self.pos += 1;
        match esc {
            b'"' => s.push('"'),
            b'\\' => s.push('\\'),
            b'/' => s.push('/'),
            b'b' => s.push('\x08'),
            b'f' => s.push('\x0c'),
            b'n' => s.push('\n'),
            b'r' => s.push('\r'),
            b't' => s.push('\t'),
            b'u' => {
                if self.pos + 4 > self.src.len() {
                    return Err(EventDecodeError::Truncated {
                        expected_min: 4,
                        actual: self.src.len() - self.pos,
                    });
                }
                let hex_str =
                    core::str::from_utf8(&self.src[self.pos..self.pos + 4]).map_err(|_| {
                        EventDecodeError::JsonError {
                            detail: "invalid unicode escape".to_string(),
                        }
                    })?;
                self.pos += 4;
                let codepoint =
                    u16::from_str_radix(hex_str, 16).map_err(|_| EventDecodeError::JsonError {
                        detail: "invalid unicode hex digits".to_string(),
                    })?;
                if (0xD800..=0xDBFF).contains(&codepoint) {
                    if self.pos + 6 <= self.src.len() && &self.src[self.pos..self.pos + 2] == b"\\u"
                    {
                        let low_hex = core::str::from_utf8(&self.src[self.pos + 2..self.pos + 6])
                            .map_err(|_| EventDecodeError::JsonError {
                            detail: "invalid unicode escape in low surrogate".to_string(),
                        })?;
                        let low_codepoint = u16::from_str_radix(low_hex, 16).map_err(|_| {
                            EventDecodeError::JsonError {
                                detail: "invalid unicode hex digits in low surrogate".to_string(),
                            }
                        })?;
                        if (0xDC00..=0xDFFF).contains(&low_codepoint) {
                            self.pos += 6;
                            let full_codepoint = 0x10000
                                + (((u32::from(codepoint) - 0xD800) << 10)
                                    | (u32::from(low_codepoint) - 0xDC00));
                            let ch = char::from_u32(full_codepoint).ok_or(
                                EventDecodeError::InvalidUnicodeEscape {
                                    codepoint: full_codepoint,
                                },
                            )?;
                            s.push(ch);
                        } else {
                            return Err(EventDecodeError::InvalidUnicodeEscape {
                                codepoint: u32::from(codepoint),
                            });
                        }
                    } else {
                        return Err(EventDecodeError::InvalidUnicodeEscape {
                            codepoint: u32::from(codepoint),
                        });
                    }
                } else if (0xDC00..=0xDFFF).contains(&codepoint) {
                    return Err(EventDecodeError::InvalidUnicodeEscape {
                        codepoint: u32::from(codepoint),
                    });
                } else {
                    let ch = char::from_u32(u32::from(codepoint)).ok_or(
                        EventDecodeError::InvalidUnicodeEscape {
                            codepoint: u32::from(codepoint),
                        },
                    )?;
                    s.push(ch);
                }
            }
            other => {
                return Err(EventDecodeError::JsonError {
                    detail: format!("unsupported escape sequence '\\{}'", other as char),
                });
            }
        }
        Ok(())
    }

    fn parse_number(&mut self) -> Result<JsonValue, EventDecodeError> {
        let start = self.pos;
        if self.pos < self.src.len() && self.src[self.pos] == b'-' {
            self.pos += 1;
        }
        let digit_start = self.pos;
        while self.pos < self.src.len() && self.src[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        if self.pos == digit_start {
            return Err(EventDecodeError::JsonError {
                detail: "invalid number: missing integer digits".to_string(),
            });
        }
        let is_float = if self.pos < self.src.len() && self.src[self.pos] == b'.' {
            self.pos += 1;
            let frac_start = self.pos;
            while self.pos < self.src.len() && self.src[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
            if self.pos == frac_start {
                return Err(EventDecodeError::JsonError {
                    detail: "invalid number: missing fractional digits".to_string(),
                });
            }
            true
        } else {
            false
        };
        let is_float = if self.pos < self.src.len()
            && (self.src[self.pos] == b'e' || self.src[self.pos] == b'E')
        {
            self.pos += 1;
            if self.pos < self.src.len()
                && (self.src[self.pos] == b'+' || self.src[self.pos] == b'-')
            {
                self.pos += 1;
            }
            let exp_start = self.pos;
            while self.pos < self.src.len() && self.src[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
            if self.pos == exp_start {
                return Err(EventDecodeError::JsonError {
                    detail: "invalid number: missing exponent digits".to_string(),
                });
            }
            true
        } else {
            is_float
        };

        let raw = core::str::from_utf8(&self.src[start..self.pos]).map_err(|_| {
            EventDecodeError::JsonError {
                detail: "invalid UTF-8 in number".to_string(),
            }
        })?;

        if is_float {
            let f = raw
                .parse::<f64>()
                .map_err(|_| EventDecodeError::JsonError {
                    detail: format!("failed to parse float: {raw}"),
                })?;
            Ok(JsonValue::NumberFloat(f))
        } else {
            let n = raw
                .parse::<i128>()
                .map_err(|_| EventDecodeError::JsonError {
                    detail: format!("failed to parse integer: {raw}"),
                })?;
            Ok(JsonValue::NumberInt(n))
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonValue, EventDecodeError> {
        self.pos += 1; // skip '['
        let mut items = Vec::new();
        loop {
            self.skip_whitespace();
            if self.pos >= self.src.len() {
                return Err(EventDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                });
            }
            if self.src[self.pos] == b']' {
                self.pos += 1;
                return Ok(JsonValue::Array(items));
            }
            if !items.is_empty() {
                if self.src[self.pos] != b',' {
                    return Err(EventDecodeError::JsonError {
                        detail: "expected ',' in array".to_string(),
                    });
                }
                self.pos += 1;
                self.skip_whitespace();
            }
            let item = self.parse_value(depth)?;
            items.push(item);
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonValue, EventDecodeError> {
        self.pos += 1; // skip '{'
        let mut fields = Vec::new();
        loop {
            self.skip_whitespace();
            if self.pos >= self.src.len() {
                return Err(EventDecodeError::Truncated {
                    expected_min: 1,
                    actual: 0,
                });
            }
            if self.src[self.pos] == b'}' {
                self.pos += 1;
                return Ok(JsonValue::Object(fields));
            }
            if !fields.is_empty() {
                if self.src[self.pos] != b',' {
                    return Err(EventDecodeError::JsonError {
                        detail: "expected ',' in object".to_string(),
                    });
                }
                self.pos += 1;
                self.skip_whitespace();
            }
            let key = self.parse_string()?;
            if fields.iter().any(|(existing, _)| existing == &key) {
                return Err(EventDecodeError::JsonError {
                    detail: format!("duplicate object key '{key}'"),
                });
            }
            self.skip_whitespace();
            if self.pos >= self.src.len() || self.src[self.pos] != b':' {
                return Err(EventDecodeError::JsonError {
                    detail: "expected ':' after object key".to_string(),
                });
            }
            self.pos += 1;
            let val = self.parse_value(depth)?;
            fields.push((key, val));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_test_interval() -> Result<CaptureInterval, ContractError> {
        CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(2_000_000))
    }

    fn sample_test_evidence(failure_domain: &str, supports: bool) -> EventEvidence {
        let digest = ContentDigest::sha256(format!("evidence:{failure_domain}").as_bytes());
        EventEvidence {
            digest,
            class: EvidenceClass::Derived,
            failure_domain: failure_domain.to_string(),
            supports,
            relation: if supports {
                EvidenceEdgeRelation::Supports
            } else {
                EvidenceEdgeRelation::Contradicts
            },
            capsule_digest: Some(ContentDigest::sha256(
                format!("capsule:{failure_domain}").as_bytes(),
            )),
            identity_digest: Some(ContentDigest::sha256(
                format!("identity:{failure_domain}").as_bytes(),
            )),
        }
    }

    fn sample_corroborated_event(
        evidence: Vec<EventEvidence>,
    ) -> Result<EventHypothesis, ContractError> {
        let event_id = EventId::parse("event:corroboration-test")?;
        let interval = sample_test_interval()?;
        let probability = ProbabilityInterval::with_calibration(
            0.8,
            0.95,
            ContentDigest::sha256(b"cal:camera-v1"),
        )?;
        Ok(EventHypothesis {
            schema: EventHypothesis::SCHEMA.to_string(),
            event_id,
            revision: 1,
            supersedes: None,
            state: EventState::Corroborated,
            kind: EventKind::PerimeterBreach,
            interval,
            uncertainty_reason: None,
            zone_ids: vec!["zone:east".to_string()],
            track_ids: vec!["track:001".to_string()],
            probability,
            evidence,
            model_receipts: vec![ContentDigest::sha256(b"receipt-1")],
            decision_path: DecisionPath {
                policy_generation: ContentDigest::sha256(b"policy:camera-v1"),
                fingerprint: ContentDigest::sha256(b"decision-path-1"),
                abstained: false,
                abstention_reason: None,
            },
        })
    }

    #[test]
    fn corroboration_requires_distinct_failure_domains() -> Result<(), ContractError> {
        // AGENTS.md prohibits calling one camera's model score "corroborated".
        // Building an event needing corroboration without it (identical failure domain) must fail.
        let event = sample_corroborated_event(vec![
            sample_test_evidence("camera:one", true),
            sample_test_evidence("camera:one", true),
        ])?;
        assert_eq!(event.validate(), Err(ContractError::CorroborationRequired));
        assert_eq!(
            event.verify(),
            Err(EventDecodeError::Contract(
                ContractError::CorroborationRequired
            ))
        );
        Ok(())
    }

    #[test]
    fn corroboration_passes_with_distinct_failure_domains() -> Result<(), ContractError> {
        // Positive case: two distinct failure domains among supporting evidence passes.
        let event = sample_corroborated_event(vec![
            sample_test_evidence("camera:one", true),
            sample_test_evidence("camera:two", true),
        ])?;
        assert_eq!(event.validate(), Ok(()));
        assert!(event.verify().is_ok());
        Ok(())
    }
}
