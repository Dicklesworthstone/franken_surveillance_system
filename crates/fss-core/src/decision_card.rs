#![forbid(unsafe_code)]
//! Decision Card evaluation framework semantics (FSS-197, bead fss-x4a.26.17):
//! the card-AGNOSTIC evaluator every registered decision-card family shares.
//!
//! The registry (`architecture/decision_cards.json`) defines each family's
//! purpose, hard clamps, safe fallback, promotion rule, and status. This
//! module evaluates a candidate against one card with the framework
//! invariants encoded in types:
//!
//! * **Hard clamps precede everything.** A tripped clamp is `Blocked`, full
//!   stop — never softened by evidence, promotion state, or fallback.
//! * **Shadow-first promotion is structural.** A card whose promotion rule is
//!   shadow-first yields `Shadow` (never direct activation) until paired
//!   outcome evidence exists.
//! * **A blocked candidate always names its safe fallback.** The card's
//!   declared fallback is carried on every non-allowed outcome.
//! * **Registry status gates execution.** A `planned` card evaluates to
//!   `Unavailable`; nothing executable flows from an unimplemented family.
//!
//! Sans-IO and deterministic: callers supply the card definition and the
//! candidate's observed clamp state; nothing here reads a clock, socket, or
//! filesystem.

use crate::{CanonicalEncoder, ContentDigest};

/// Registered schema identity for card evaluations.
pub const SCHEMA_CARD_EVALUATION: &str = "fss.decision_card_evaluation.v1";

/// A decision card's registered definition (data from the machine registry).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CardDefinition {
    /// Stable card identity (DEC-*-NNN).
    pub card_id: String,
    /// Registry status (e.g. "planned"; an executable family says otherwise).
    pub status: CardStatus,
    /// Whether the promotion rule is shadow-first (paired evidence before activation).
    pub shadow_first: bool,
    /// The declared safe fallback label (carried on every non-allowed outcome).
    pub safe_fallback: String,
}

/// Registry execution status for a card family.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CardStatus {
    /// Family registered but not implemented: never executable.
    Planned,
    /// Family implemented and admitted for evaluation.
    Admitted,
}

impl CardStatus {
    /// Parses the registry spelling.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "planned" => Some(Self::Planned),
            "admitted" => Some(Self::Admitted),
            _ => None,
        }
    }

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Admitted => "admitted",
        }
    }
}

/// A candidate action's observed state against one card.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Candidate {
    /// Hard clamps tripped by the candidate (domain-assessed by the caller).
    pub tripped_clamps: Vec<String>,
    /// Whether paired shadow outcome evidence exists for this candidate.
    pub paired_evidence: bool,
}

/// The typed evaluation outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CardEvaluation {
    /// A hard clamp tripped; the candidate is refused. Carries the clamp and
    /// the card's safe fallback — never a bare no.
    Blocked {
        /// The tripped clamp(s).
        clamps: Vec<String>,
        /// The card's declared safe fallback.
        safe_fallback: String,
    },
    /// Shadow-first: evaluation proceeds in shadow mode (no activation).
    Shadow,
    /// The family is not executable under its registry status; the safe
    /// fallback is the only honest outcome.
    Unavailable {
        /// Why (the registry status).
        status: CardStatus,
        /// The card's declared safe fallback.
        safe_fallback: String,
    },
    /// The candidate is allowed, carrying the paired-evidence witness flag.
    Allowed {
        /// Whether paired outcome evidence accompanied the candidate.
        paired_evidence: bool,
    },
}

impl CardEvaluation {
    /// Stable schema spelling for receipts.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Blocked { .. } => "blocked",
            Self::Shadow => "shadow",
            Self::Unavailable { .. } => "unavailable",
            Self::Allowed { .. } => "allowed",
        }
    }
}

/// The card-agnostic evaluator (stateless).
pub struct DecisionCardEvaluator;

impl DecisionCardEvaluator {
    /// Evaluates a candidate against a card. Ordering is the contract:
    /// clamps first, then executability, then shadow-first, then allowed.
    #[must_use]
    pub fn evaluate(card: &CardDefinition, candidate: &Candidate) -> CardEvaluation {
        if !candidate.tripped_clamps.is_empty() {
            return CardEvaluation::Blocked {
                clamps: candidate.tripped_clamps.clone(),
                safe_fallback: card.safe_fallback.clone(),
            };
        }
        if card.status == CardStatus::Planned {
            return CardEvaluation::Unavailable {
                status: card.status,
                safe_fallback: card.safe_fallback.clone(),
            };
        }
        if card.shadow_first && !candidate.paired_evidence {
            return CardEvaluation::Shadow;
        }
        CardEvaluation::Allowed {
            paired_evidence: candidate.paired_evidence,
        }
    }

    /// Deterministic digest of one evaluation (for receipts).
    #[must_use]
    pub fn evaluation_digest(card: &CardDefinition, candidate: &Candidate, outcome: &CardEvaluation) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(SCHEMA_CARD_EVALUATION);
        encoder.text(&card.card_id);
        encoder.text(card.status.as_str());
        encoder.bool(card.shadow_first);
        encoder.text(&card.safe_fallback);
        encoder.u64(candidate.tripped_clamps.len() as u64);
        for clamp in &candidate.tripped_clamps {
            encoder.text(clamp);
        }
        encoder.bool(candidate.paired_evidence);
        encoder.text(outcome.as_str());
        ContentDigest::sha256(&encoder.finish())
    }
}
