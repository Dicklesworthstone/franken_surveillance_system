#![forbid(unsafe_code)]
//! Dependency-free semantic contracts for Franken Surveillance System.
//!
//! This crate is intentionally small. It establishes the vocabulary and state
//! machines that every future adapter, ledger, model executor, archive backend, and
//! agent interface must preserve. It does not acquire video or run inference.

use core::fmt;

/// A stable opaque identifier for a configured sensor.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SensorId(String);

impl SensorId {
    /// Constructs a sensor identifier after enforcing the minimal canonical form.
    pub fn parse(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        validate_id("sensor_id", &value)?;
        Ok(Self(value))
    }

    /// Returns the identifier as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A stable opaque identifier for one logical stream generation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StreamId(String);

impl StreamId {
    /// Constructs a stream identifier.
    pub fn parse(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        validate_id("stream_id", &value)?;
        Ok(Self(value))
    }

    /// Returns the identifier as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A content digest rendered as lowercase hexadecimal.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContentDigest(String);

impl ContentDigest {
    /// Constructs a digest from an algorithm-prefixed textual representation.
    pub fn parse(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        let Some((algorithm, hex)) = value.split_once(':') else {
            return Err(ContractError::InvalidDigest);
        };
        if algorithm.is_empty()
            || hex.len() < 32
            || !hex.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(ContractError::InvalidDigest);
        }
        Ok(Self(value))
    }

    /// Returns the digest as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Nanoseconds on a declared clock basis.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TimestampNs(pub i128);

/// A conservative interval within which an observation was captured.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureInterval {
    /// Earliest possible capture time.
    pub earliest: TimestampNs,
    /// Latest possible capture time.
    pub latest: TimestampNs,
}

impl CaptureInterval {
    /// Constructs a non-inverted interval.
    pub fn new(earliest: TimestampNs, latest: TimestampNs) -> Result<Self, ContractError> {
        if earliest > latest {
            return Err(ContractError::InvertedTimeInterval);
        }
        Ok(Self { earliest, latest })
    }

    /// Returns the interval width in nanoseconds.
    #[must_use]
    pub fn uncertainty_ns(self) -> u128 {
        self.latest.0.abs_diff(self.earliest.0)
    }

    /// Returns true when two uncertain capture intervals can describe the same instant.
    #[must_use]
    pub fn overlaps(self, other: Self) -> bool {
        self.earliest <= other.latest && other.earliest <= self.latest
    }
}

/// Which semantic plane owns a record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Plane {
    /// Immutable observations, identities, receipts, and authoritative policy state.
    Authority,
    /// Derived tracks, embeddings, hypotheses, rankings, and model outputs.
    Cognition,
    /// Alerts, camera control, retention changes, exports, and other side effects.
    Effect,
}

/// Evidence strength. Higher classes may depend on lower ones but never replace them.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EvidenceClass {
    /// A claim without retained source evidence; never sufficient for an alert alone.
    Assertion,
    /// A model output tied to exact inputs and model identity.
    Derived,
    /// A decoded observation tied to retained source packet or frame bytes.
    Observed,
    /// Independent corroboration from multiple failure domains.
    Corroborated,
    /// A deterministic or cryptographically verified fact.
    Verified,
}

/// Acquisition lifecycle for a sensor stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcquisitionState {
    /// An authorized caller requested acquisition.
    Requested,
    /// Credentials or local authority were accepted.
    Authenticated,
    /// The adapter accepted the operation.
    AdapterAccepted,
    /// At least one decodable frame was observed.
    FirstFrameObserved,
    /// Continuity met the configured verification window.
    ContinuityVerified,
    /// Frames continue, but one or more declared quality contracts are violated.
    Degraded,
    /// The system cannot determine whether acquisition is active.
    Indeterminate,
    /// Acquisition reached a terminal failure.
    Failed,
    /// Acquisition was cancelled and drained.
    Cancelled,
}

/// Why a stream is degraded without pretending it has failed completely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DegradationReason {
    /// Frame arrival violates the continuity budget.
    FrameGaps,
    /// Capture-time uncertainty exceeds the calibration budget.
    ClockUncertainty,
    /// Decoder output is corrupt or repeatedly concealed.
    DecodeCorruption,
    /// Effective image quality is below the declared analysis floor.
    ImageQuality,
    /// The adapter is operating against an uncertified firmware generation.
    FirmwareDrift,
    /// A required model or model generation is unavailable.
    ModelUnavailable,
    /// Archive publication is falling behind the retention contract.
    ArchiveBacklog,
}

/// A compact immutable description of one acquired media segment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensorCapsule {
    /// Sensor that produced the segment.
    pub sensor_id: SensorId,
    /// Stream generation that produced the segment.
    pub stream_id: StreamId,
    /// Original encoded bytes, retained or intentionally omitted under policy.
    pub source_digest: Option<ContentDigest>,
    /// Canonical metadata digest.
    pub metadata_digest: ContentDigest,
    /// Conservative capture interval for the segment.
    pub capture: CaptureInterval,
    /// Number of source bytes represented by the capsule.
    pub source_bytes: u64,
    /// Number of decoded frames represented by the capsule.
    pub frame_count: u32,
}

/// Event lifecycle. Detection, corroboration, and alerting are deliberately separate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventState {
    /// Candidate created by a detector or rule.
    Hypothesized,
    /// Candidate has at least one retained observation witness.
    Witnessed,
    /// Candidate has independent corroboration or a verified single-sensor exception.
    Corroborated,
    /// Policy selected an alert disposition.
    Adjudicated,
    /// Alert delivery has a durable receipt.
    AlertDelivered,
    /// A human or trusted downstream system resolved the event.
    Resolved,
    /// Evidence was insufficient; the event remains explicit rather than silently disappearing.
    Indeterminate,
    /// Evidence established that the candidate was benign or erroneous.
    Rejected,
}

/// Coarse event semantics used before any deployment-specific taxonomy extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    /// An entity entered a protected boundary.
    PerimeterBreach,
    /// Motion or appearance is consistent with covert approach.
    CovertApproach,
    /// A sensor appears covered, moved, dazzled, disconnected, or replayed.
    SensorTamper,
    /// Presence is real but authorization is unknown.
    UnknownPresence,
    /// A routine resident, delivery, animal, weather, or other benign explanation is likely.
    BenignRoutine,
    /// The taxonomy cannot yet express the observation without distortion.
    Unclassified,
}

/// A probability interval, not an unqualified point score.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ProbabilityInterval {
    /// Conservative lower bound.
    pub lower: f64,
    /// Conservative upper bound.
    pub upper: f64,
}

impl ProbabilityInterval {
    /// Constructs a bounded interval.
    pub fn new(lower: f64, upper: f64) -> Result<Self, ContractError> {
        if !lower.is_finite()
            || !upper.is_finite()
            || !(0.0..=1.0).contains(&lower)
            || !(0.0..=1.0).contains(&upper)
            || lower > upper
        {
            return Err(ContractError::InvalidProbabilityInterval);
        }
        Ok(Self { lower, upper })
    }
}

/// A minimal event hypothesis carrying provenance rather than model prose alone.
#[derive(Clone, Debug, PartialEq)]
pub struct EventHypothesis {
    /// Stable event identifier.
    pub event_id: String,
    /// Current lifecycle state.
    pub state: EventState,
    /// Current semantic class.
    pub kind: EventKind,
    /// Calibrated confidence interval.
    pub probability: ProbabilityInterval,
    /// Digests of observations, tracks, transforms, and model receipts supporting the claim.
    pub evidence: Vec<ContentDigest>,
    /// Model-generation digest that produced this revision, when applicable.
    pub model_generation: Option<ContentDigest>,
}

impl EventHypothesis {
    /// Validates the load-bearing event invariants.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_id("event_id", &self.event_id)?;
        if self.state != EventState::Hypothesized && self.evidence.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        if matches!(self.state, EventState::Corroborated | EventState::Adjudicated | EventState::AlertDelivered)
            && self.evidence.len() < 2
        {
            return Err(ContractError::CorroborationRequired);
        }
        Ok(())
    }
}

/// Stable contract errors. Future crates map these into richer typed errors without erasing them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractError {
    /// Identifier is empty, oversized, or contains a forbidden byte.
    InvalidIdentifier,
    /// Digest is malformed.
    InvalidDigest,
    /// Capture interval is inverted.
    InvertedTimeInterval,
    /// Probability interval is malformed.
    InvalidProbabilityInterval,
    /// A state transition requires retained evidence.
    EvidenceRequired,
    /// A state transition requires independent corroboration.
    CorroborationRequired,
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentifier => "invalid_identifier",
            Self::InvalidDigest => "invalid_digest",
            Self::InvertedTimeInterval => "inverted_time_interval",
            Self::InvalidProbabilityInterval => "invalid_probability_interval",
            Self::EvidenceRequired => "evidence_required",
            Self::CorroborationRequired => "corroboration_required",
        })
    }
}

impl std::error::Error for ContractError {}

fn validate_id(_field: &str, value: &str) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ContractError::InvalidIdentifier);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(seed: char) -> Result<ContentDigest, ContractError> {
        ContentDigest::parse(format!("blake3:{}", seed.to_string().repeat(64)))
    }

    #[test]
    fn capture_intervals_preserve_uncertainty() -> Result<(), ContractError> {
        let first = CaptureInterval::new(TimestampNs(10), TimestampNs(20))?;
        let second = CaptureInterval::new(TimestampNs(19), TimestampNs(30))?;
        assert_eq!(first.uncertainty_ns(), 10);
        assert!(first.overlaps(second));
        Ok(())
    }

    #[test]
    fn alert_delivery_requires_corroboration() -> Result<(), ContractError> {
        let event = EventHypothesis {
            event_id: "event:one".to_owned(),
            state: EventState::AlertDelivered,
            kind: EventKind::PerimeterBreach,
            probability: ProbabilityInterval::new(0.9, 0.99)?,
            evidence: vec![digest('a')?],
            model_generation: Some(digest('b')?),
        };
        assert_eq!(event.validate(), Err(ContractError::CorroborationRequired));
        Ok(())
    }

    #[test]
    fn witnessed_event_requires_evidence() -> Result<(), ContractError> {
        let event = EventHypothesis {
            event_id: "event:two".to_owned(),
            state: EventState::Witnessed,
            kind: EventKind::UnknownPresence,
            probability: ProbabilityInterval::new(0.4, 0.8)?,
            evidence: Vec::new(),
            model_generation: None,
        };
        assert_eq!(event.validate(), Err(ContractError::EvidenceRequired));
        Ok(())
    }
}
