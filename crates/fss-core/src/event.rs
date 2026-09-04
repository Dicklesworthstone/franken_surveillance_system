//! Event hypotheses that retain evidence and distinguish adjudication from effects.

use crate::{
    CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest, ContractError, EventId,
};

/// Event lifecycle. Detection, corroboration, and alerting are separate.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EventState {
    /// Candidate created by a detector or rule.
    Hypothesized,
    /// Candidate has at least one retained observation witness.
    Witnessed,
    /// Candidate has independent corroboration or an explicit exception proof.
    Corroborated,
    /// Policy selected a disposition.
    Adjudicated,
    /// Alert delivery has a durable receipt.
    AlertDelivered,
    /// A human or trusted downstream system resolved the event.
    Resolved,
    /// Evidence was insufficient or an outcome remains unresolved.
    Indeterminate,
    /// Evidence established that the candidate was benign or erroneous.
    Rejected,
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
}

/// Coarse event semantics used before deployment-specific extension.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
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
    /// The taxonomy cannot express the observation without distortion.
    Unclassified,
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
}

/// A probability interval rather than an unqualified point score.
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

impl CanonicalEncode for ProbabilityInterval {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(canonical_f64_bits(self.lower));
        encoder.u64(canonical_f64_bits(self.upper));
    }
}

/// An evidence edge supporting or contradicting an event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventEvidence {
    /// Evidence object digest.
    pub digest: ContentDigest,
    /// Failure-domain identity used to prevent false corroboration.
    pub failure_domain: String,
    /// Whether this edge supports the event.
    pub supports: bool,
}

impl CanonicalEncode for EventEvidence {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.digest(self.digest);
        encoder.text(&self.failure_domain);
        encoder.bool(self.supports);
    }
}

/// Immutable event revision carrying provenance rather than model prose alone.
#[derive(Clone, Debug, PartialEq)]
pub struct EventHypothesis {
    /// Stable event lineage.
    pub event_id: EventId,
    /// Monotone revision.
    pub revision: u64,
    /// Lifecycle state.
    pub state: EventState,
    /// Semantic class.
    pub kind: EventKind,
    /// Event validity interval.
    pub interval: CaptureInterval,
    /// Calibrated probability interval.
    pub probability: ProbabilityInterval,
    /// Supporting and contradicting evidence.
    pub evidence: Vec<EventEvidence>,
    /// Exact model execution receipts.
    pub model_receipts: Vec<ContentDigest>,
    /// Decision-path fingerprint.
    pub decision_path: ContentDigest,
}

impl EventHypothesis {
    /// Validates load-bearing event invariants.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.state != EventState::Hypothesized && self.evidence.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        if matches!(
            self.state,
            EventState::Corroborated | EventState::Adjudicated | EventState::AlertDelivered
        ) {
            let failure_domains: std::collections::BTreeSet<_> = self
                .evidence
                .iter()
                .filter(|edge| edge.supports)
                .map(|edge| edge.failure_domain.as_str())
                .collect();
            if failure_domains.len() < 2 {
                return Err(ContractError::CorroborationRequired);
            }
        }
        Ok(())
    }

    /// Returns the immutable event-revision digest.
    #[must_use]
    pub fn revision_digest(&self) -> ContentDigest {
        self.canonical_digest("fss.event_hypothesis.v1")
    }
}

impl CanonicalEncode for EventHypothesis {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.event_id.encode_canonical(encoder);
        encoder.u64(self.revision);
        encoder.text(self.state.as_str());
        encoder.text(self.kind.as_str());
        self.interval.encode_canonical(encoder);
        self.probability.encode_canonical(encoder);
        let mut evidence = self.evidence.clone();
        evidence.sort_by(|left, right| {
            (left.failure_domain.as_str(), left.digest, left.supports).cmp(&(
                right.failure_domain.as_str(),
                right.digest,
                right.supports,
            ))
        });
        encoder.u64(evidence.len() as u64);
        for edge in &evidence {
            edge.encode_canonical(encoder);
        }
        let mut receipts = self.model_receipts.clone();
        receipts.sort_unstable();
        encoder.u64(receipts.len() as u64);
        for receipt in receipts {
            encoder.digest(receipt);
        }
        encoder.digest(self.decision_path);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TimestampNs;

    fn interval() -> Result<CaptureInterval, ContractError> {
        CaptureInterval::new(TimestampNs(0), TimestampNs(100))
    }

    #[test]
    fn corroboration_requires_distinct_failure_domains() -> Result<(), ContractError> {
        let digest = ContentDigest::sha256(b"same-camera");
        let event = EventHypothesis {
            event_id: EventId::parse("event:one")?,
            revision: 1,
            state: EventState::Corroborated,
            kind: EventKind::PerimeterBreach,
            interval: interval()?,
            probability: ProbabilityInterval::new(0.8, 0.95)?,
            evidence: vec![
                EventEvidence {
                    digest,
                    failure_domain: "camera:one".to_owned(),
                    supports: true,
                },
                EventEvidence {
                    digest: ContentDigest::sha256(b"same-model"),
                    failure_domain: "camera:one".to_owned(),
                    supports: true,
                },
            ],
            model_receipts: Vec::new(),
            decision_path: ContentDigest::sha256(b"path"),
        };
        assert_eq!(event.validate(), Err(ContractError::CorroborationRequired));
        Ok(())
    }
}
