#![forbid(unsafe_code)]
//! Canonical agent abstraction tower registry types and realizations:
//! - Strongly typed [`AgentAbstractionLayer`] enum representing the 11 normative abstraction tower layers.
//! - Submodule [`world_facts`] realizing AGT-LAYER-003: world_facts_and_coverage (INV-063) in the Authority plane.
//! - Submodule [`derived_belief`] realizing AGT-LAYER-004: derived_beliefs (INV-069) in the Cognition plane.
//! - Submodule [`source_evidence`] realizing AGT-LAYER-002: source_evidence (INV-003) in the Authority plane.

use core::fmt;
use core::str::FromStr;

use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::contract::{ContractError, Plane};

pub mod derived_belief;
pub mod runtime_authority;
pub mod source_evidence;
pub mod world_facts;

pub use derived_belief::*;
pub use runtime_authority::*;
pub use source_evidence::*;
pub use world_facts::*;

/// Canonical generation identifier for the agent abstraction stack.
pub const AGENT_ABSTRACTION_GENERATION: &str = "gen:fss1:abstraction-v1";
/// Alias for plural naming.
pub const AGENT_ABSTRACTIONS_GENERATION: &str = AGENT_ABSTRACTION_GENERATION;

/// Pinned baseline freeze digest of the canonical agent abstraction stack registry.
pub const AGENT_ABSTRACTION_FREEZE_DIGEST: &str =
    "sha256:98dfe512d870a36079fe49435d1f53d669c63a0034d03a771248fbab0abf34a9";
/// Alias for plural naming.
pub const AGENT_ABSTRACTIONS_FREEZE_DIGEST: &str = AGENT_ABSTRACTION_FREEZE_DIGEST;

/// Canonical abstraction layers in strict tower order (L0 to L10).
pub const CANONICAL_LAYERS: [AgentAbstractionLayer; 11] = AgentAbstractionLayer::ALL;

/// The 11 normative abstraction tower layers in strict ascending order (L0 to L10).
///
/// Order:
/// L0  Runtime authority and custody (AGT-LAYER-001)
/// L1  Source evidence (AGT-LAYER-002)
/// L2  World facts and coverage (AGT-LAYER-003)
/// L3  Derived beliefs (AGT-LAYER-004)
/// L4  Situation capsule (AGT-LAYER-005)
/// L5  Investigation and hypotheses (AGT-LAYER-006)
/// L6  Affordance frontier (AGT-LAYER-007)
/// L7  Plan and effect (AGT-LAYER-008)
/// L8  Outcome and episode (AGT-LAYER-009)
/// L9  Learning and memory (AGT-LAYER-010)
/// L10 Workspace and handoff (AGT-LAYER-011)
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AgentAbstractionLayer {
    /// L0: Runtime authority, grants, regions, obligations, object roots, and receipts.
    RuntimeAuthorityAndCustody,
    /// L1: Immutable sensor capsules, source objects, continuity and time evidence.
    SourceEvidence,
    /// L2: Device, geometry, calibration, coverage, policy, archive, and effect facts.
    WorldFactsAndCoverage,
    /// L3: Generation-pinned derived beliefs and graph/search projections with receipts (AGT-LAYER-004, INV-069).
    DerivedBeliefs,
    /// L4: SituationCapsule containing SituationFrame with WorldEnvelope and control envelope.
    SituationCapsule,
    /// L5: Case revision, hypotheses, support, contradictions, predicted observations, and stop rules.
    InvestigationAndHypotheses,
    /// L6: Pareto frontier of read/control affordances with VOI, cost, risk, and proof.
    AffordanceFrontier,
    /// L7: Prepared plan, commit ticket, effect receipts, obligation states, and reconciliation.
    PlanAndEffect,
    /// L8: Immutable execution episode with attribution hypotheses and resource ledger.
    OutcomeAndEpisode,
    /// L9: Evidence-linked scoped proposal with counterexamples, harmful outcomes, and validation.
    LearningAndMemory,
    /// L10: Versioned workspace revision and root-last HandoffCapsule.
    WorkspaceAndHandoff,
}

impl AgentAbstractionLayer {
    /// All 11 normative layers in canonical abstraction tower order.
    pub const ALL: [Self; 11] = [
        Self::RuntimeAuthorityAndCustody,
        Self::SourceEvidence,
        Self::WorldFactsAndCoverage,
        Self::DerivedBeliefs,
        Self::SituationCapsule,
        Self::InvestigationAndHypotheses,
        Self::AffordanceFrontier,
        Self::PlanAndEffect,
        Self::OutcomeAndEpisode,
        Self::LearningAndMemory,
        Self::WorkspaceAndHandoff,
    ];

    /// Returns the stable canonical ID for this abstraction layer (e.g. `AGT-LAYER-004`).
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::RuntimeAuthorityAndCustody => "AGT-LAYER-001",
            Self::SourceEvidence => "AGT-LAYER-002",
            Self::WorldFactsAndCoverage => "AGT-LAYER-003",
            Self::DerivedBeliefs => "AGT-LAYER-004",
            Self::SituationCapsule => "AGT-LAYER-005",
            Self::InvestigationAndHypotheses => "AGT-LAYER-006",
            Self::AffordanceFrontier => "AGT-LAYER-007",
            Self::PlanAndEffect => "AGT-LAYER-008",
            Self::OutcomeAndEpisode => "AGT-LAYER-009",
            Self::LearningAndMemory => "AGT-LAYER-010",
            Self::WorkspaceAndHandoff => "AGT-LAYER-011",
        }
    }

    /// Returns the stable schema name for this layer (e.g. `derived_beliefs`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RuntimeAuthorityAndCustody => "runtime_authority_and_custody",
            Self::SourceEvidence => "source_evidence",
            Self::WorldFactsAndCoverage => "world_facts_and_coverage",
            Self::DerivedBeliefs => "derived_beliefs",
            Self::SituationCapsule => "situation_capsule",
            Self::InvestigationAndHypotheses => "investigation_and_hypotheses",
            Self::AffordanceFrontier => "affordance_frontier",
            Self::PlanAndEffect => "plan_and_effect",
            Self::OutcomeAndEpisode => "outcome_and_episode",
            Self::LearningAndMemory => "learning_and_memory",
            Self::WorkspaceAndHandoff => "workspace_and_handoff",
        }
    }

    /// Returns the owning crates or subsystems for this layer.
    #[must_use]
    pub const fn owner(self) -> &'static str {
        match self {
            Self::RuntimeAuthorityAndCustody => "asupersync/authority/object owners",
            Self::SourceEvidence => "fss-capture/fss-media/fss-chronicle",
            Self::WorldFactsAndCoverage => "fss-chronicle/fss-coverage",
            Self::DerivedBeliefs => "fss-perception/fss-association/fss-graph",
            Self::SituationCapsule => "fss-situation/fss-context-pack/fss-affordance",
            Self::InvestigationAndHypotheses => "fss-investigation",
            Self::AffordanceFrontier => "fss-attention/fss-affordance",
            Self::PlanAndEffect => "fss-agent-plan/fss-effect",
            Self::OutcomeAndEpisode => "fss-episode",
            Self::LearningAndMemory => "fss-learning",
            Self::WorkspaceAndHandoff => "fss-agent-session/fss-handoff",
        }
    }

    /// Returns the core question answered by this layer.
    #[must_use]
    pub const fn agent_question(self) -> &'static str {
        match self {
            Self::RuntimeAuthorityAndCustody => {
                "What work, authority, budget, identity, time, and object custody exist?"
            }
            Self::SourceEvidence => {
                "What exact packets, files, measurements, continuity, and capture-time intervals exist?"
            }
            Self::WorldFactsAndCoverage => {
                "What did the system authoritatively observe or do at one anchor?"
            }
            Self::DerivedBeliefs => {
                "What entities, tracks, events, relations, and uncertainties are supported?"
            }
            Self::SituationCapsule => {
                "What is the smallest sufficient mission-relative driver view now, what changed, and what can safely be done next?"
            }
            Self::InvestigationAndHypotheses => {
                "Which competing explanations remain viable and how can they be discriminated?"
            }
            Self::AffordanceFrontier => {
                "What can be done next, under current capability and budget, and why is it worth doing?"
            }
            Self::PlanAndEffect => {
                "Which witnessed contingent DAG should run and did each effect happen?"
            }
            Self::OutcomeAndEpisode => {
                "What was predicted, executed, observed, consumed, and left uncertain?"
            }
            Self::LearningAndMemory => {
                "What reusable rule, anti-pattern, fixture, or runbook improvement should be proposed?"
            }
            Self::WorkspaceAndHandoff => {
                "How can this mission resume or transfer without rediscovery or hidden staleness?"
            }
        }
    }

    /// Returns the normative output description for this layer.
    #[must_use]
    pub const fn output(self) -> &'static str {
        match self {
            Self::RuntimeAuthorityAndCustody => {
                "Context, grants, regions, obligations, object roots, and receipts."
            }
            Self::SourceEvidence => {
                "Immutable sensor capsules, source objects, continuity and time evidence."
            }
            Self::WorldFactsAndCoverage => {
                "Device, geometry, calibration, coverage, policy, archive, and effect facts."
            }
            Self::DerivedBeliefs => {
                "Generation-pinned derived beliefs and graph/search projections with receipts."
            }
            Self::SituationCapsule => {
                "SituationCapsule containing SituationFrame with WorldEnvelope, MeaningfulDelta, obligations, resource state, categorized control envelope, ContextPack, compression proof, and affordance frontier."
            }
            Self::InvestigationAndHypotheses => {
                "Case revision, hypotheses, support, contradictions, predicted observations, falsifiers, and stop rule."
            }
            Self::AffordanceFrontier => {
                "Nondominated affordance frontier with value of information, resource cost, risk, reversibility, invalidators, and expected proof."
            }
            Self::PlanAndEffect => {
                "Prepared plan, commit ticket, effect receipts, obligation states, and reconciliation."
            }
            Self::OutcomeAndEpisode => {
                "Immutable execution episode with observed outcome, attribution hypotheses, and resource ledger."
            }
            Self::LearningAndMemory => {
                "Evidence-linked scoped proposal with counterexamples, harmful outcomes, and validation runbook."
            }
            Self::WorkspaceAndHandoff => {
                "Versioned workspace revision, invalidation set, continuation leases, and root-last HandoffCapsule."
            }
        }
    }

    /// Returns the normative prohibition description for this layer.
    #[must_use]
    pub const fn prohibition(self) -> &'static str {
        match self {
            Self::RuntimeAuthorityAndCustody => "Cannot infer mission meaning or physical truth.",
            Self::SourceEvidence => {
                "Cannot promote decode or model output into source evidence."
            }
            Self::WorldFactsAndCoverage => "Cannot include unqualified cognition as fact.",
            Self::DerivedBeliefs => {
                "Cannot authorize effects or certify absence beyond coverage."
            }
            Self::SituationCapsule => {
                "Cannot hide decision-changing omissions or rebase evidence identities."
            }
            Self::InvestigationAndHypotheses => {
                "Cannot collapse uncertainty into truth without adjudication."
            }
            Self::AffordanceFrontier => "Cannot grant execution authority directly.",
            Self::PlanAndEffect => "Cannot commit without current witnesses and idempotency key.",
            Self::OutcomeAndEpisode => "Cannot mutate completed history or prune failed paths.",
            Self::LearningAndMemory => "Cannot activate unshadowed policy without qualification.",
            Self::WorkspaceAndHandoff => {
                "Cannot leave active obligations indeterminate or omit invalidations."
            }
        }
    }

    /// Returns the stable architectural invariant enforced by this layer.
    #[must_use]
    pub const fn invariant(self) -> &'static str {
        match self {
            Self::RuntimeAuthorityAndCustody => "INV-006",
            Self::SourceEvidence => "INV-003",
            Self::WorldFactsAndCoverage => "INV-063",
            Self::DerivedBeliefs => "INV-069",
            Self::SituationCapsule => "INV-116",
            Self::InvestigationAndHypotheses => "INV-104",
            Self::AffordanceFrontier => "INV-106",
            Self::PlanAndEffect => "INV-088",
            Self::OutcomeAndEpisode => "INV-098",
            Self::LearningAndMemory => "INV-094",
            Self::WorkspaceAndHandoff => "INV-096",
        }
    }

    /// Returns the stable normative status for this layer.
    #[must_use]
    pub const fn status(self) -> &'static str {
        "normative"
    }

    /// Returns the zero-indexed level in the abstraction tower (0 to 10).
    #[must_use]
    pub const fn tower_level(self) -> u8 {
        match self {
            Self::RuntimeAuthorityAndCustody => 0,
            Self::SourceEvidence => 1,
            Self::WorldFactsAndCoverage => 2,
            Self::DerivedBeliefs => 3,
            Self::SituationCapsule => 4,
            Self::InvestigationAndHypotheses => 5,
            Self::AffordanceFrontier => 6,
            Self::PlanAndEffect => 7,
            Self::OutcomeAndEpisode => 8,
            Self::LearningAndMemory => 9,
            Self::WorkspaceAndHandoff => 10,
        }
    }

    /// Returns the primary ADR-0001 semantic plane for this layer.
    #[must_use]
    pub const fn plane(self) -> Plane {
        match self {
            Self::RuntimeAuthorityAndCustody
            | Self::SourceEvidence
            | Self::WorldFactsAndCoverage
            | Self::OutcomeAndEpisode
            | Self::WorkspaceAndHandoff => Plane::Authority,
            Self::DerivedBeliefs
            | Self::SituationCapsule
            | Self::InvestigationAndHypotheses
            | Self::AffordanceFrontier
            | Self::LearningAndMemory => Plane::Cognition,
            Self::PlanAndEffect => Plane::Effect,
        }
    }

    /// Returns whether this layer may claim authority plane ownership.
    #[must_use]
    pub const fn may_claim_authority(self) -> bool {
        matches!(
            self,
            Self::RuntimeAuthorityAndCustody
                | Self::SourceEvidence
                | Self::WorldFactsAndCoverage
                | Self::OutcomeAndEpisode
                | Self::WorkspaceAndHandoff
        )
    }

    /// Returns whether this layer may authorize physical effects.
    #[must_use]
    pub const fn may_authorize_effects(self) -> bool {
        matches!(self, Self::PlanAndEffect)
    }

    /// Returns whether this layer is anchor-pinned.
    #[must_use]
    pub const fn is_anchor_pinned(self) -> bool {
        !matches!(self, Self::RuntimeAuthorityAndCustody)
    }

    /// Returns whether this layer is rebuildable from canonical history.
    #[must_use]
    pub const fn is_rebuildable(self) -> bool {
        matches!(
            self,
            Self::DerivedBeliefs
                | Self::SituationCapsule
                | Self::InvestigationAndHypotheses
                | Self::AffordanceFrontier
                | Self::OutcomeAndEpisode
        )
    }

    /// Returns whether this layer is anchor-pinned and rebuildable from canonical history.
    #[must_use]
    pub const fn is_anchor_pinned_rebuildable(self) -> bool {
        matches!(
            self,
            Self::DerivedBeliefs
                | Self::WorldFactsAndCoverage
                | Self::SituationCapsule
                | Self::InvestigationAndHypotheses
                | Self::AffordanceFrontier
                | Self::OutcomeAndEpisode
        )
    }

    /// Returns whether this layer is runtime authority and custody (AGT-LAYER-001).
    #[must_use]
    pub const fn is_runtime_authority_and_custody(self) -> bool {
        matches!(self, Self::RuntimeAuthorityAndCustody)
    }

    /// Returns whether this layer prohibits inferring mission meaning.
    ///
    /// AGT-LAYER-001 prohibition: "Cannot infer mission meaning or physical truth."
    #[must_use]
    pub const fn prohibits_mission_meaning_inference(self) -> bool {
        matches!(self, Self::RuntimeAuthorityAndCustody)
    }

    /// Returns whether this layer prohibits inferring physical truth.
    ///
    /// AGT-LAYER-001 prohibition: "Cannot infer mission meaning or physical truth."
    #[must_use]
    pub const fn prohibits_physical_truth_inference(self) -> bool {
        matches!(self, Self::RuntimeAuthorityAndCustody)
    }

    /// Validates all constitutional and semantic invariants for this abstraction layer.
    pub fn validate_invariants(&self) -> Result<(), ContractError> {
        match self {
            Self::RuntimeAuthorityAndCustody => {
                if self.plane() != Plane::Authority {
                    return Err(ContractError::InvalidEffectTransition);
                }
                if !self.prohibits_mission_meaning_inference() {
                    return Err(ContractError::InvalidIdentifier);
                }
                if !self.prohibits_physical_truth_inference() {
                    return Err(ContractError::InvalidIdentifier);
                }
                if self.invariant() != "INV-006" {
                    return Err(ContractError::InvalidIdentifier);
                }
            }
            Self::DerivedBeliefs => {
                if self.plane() != Plane::Cognition {
                    return Err(ContractError::DerivedLayerAuthorityForbidden);
                }
                if self.invariant() != "INV-069" {
                    return Err(ContractError::InvalidIdentifier);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Validates a concrete [`RuntimeAuthorityAndCustodyRecord`] against this layer's invariants.
    pub fn validate_runtime_authority(
        &self,
        record: &RuntimeAuthorityAndCustodyRecord,
    ) -> Result<(), ContractError> {
        if *self != Self::RuntimeAuthorityAndCustody {
            return Err(ContractError::UnknownAbstractionLayer(self.name().into()));
        }
        record.validate_invariants()
    }

    /// Resolves an abstraction layer from its stable identifier (e.g. `AGT-LAYER-004`).
    pub fn from_id(id: &str) -> Result<Self, ContractError> {
        match id {
            "AGT-LAYER-001" => Ok(Self::RuntimeAuthorityAndCustody),
            "AGT-LAYER-002" => Ok(Self::SourceEvidence),
            "AGT-LAYER-003" => Ok(Self::WorldFactsAndCoverage),
            "AGT-LAYER-004" => Ok(Self::DerivedBeliefs),
            "AGT-LAYER-005" => Ok(Self::SituationCapsule),
            "AGT-LAYER-006" => Ok(Self::InvestigationAndHypotheses),
            "AGT-LAYER-007" => Ok(Self::AffordanceFrontier),
            "AGT-LAYER-008" => Ok(Self::PlanAndEffect),
            "AGT-LAYER-009" => Ok(Self::OutcomeAndEpisode),
            "AGT-LAYER-010" => Ok(Self::LearningAndMemory),
            "AGT-LAYER-011" => Ok(Self::WorkspaceAndHandoff),
            _ => Err(ContractError::UnknownAbstractionLayer(id.to_owned())),
        }
    }

    /// Resolves an abstraction layer from its schema name (e.g. `derived_beliefs`).
    pub fn from_name(name: &str) -> Result<Self, ContractError> {
        match name {
            "runtime_authority_and_custody" => Ok(Self::RuntimeAuthorityAndCustody),
            "source_evidence" => Ok(Self::SourceEvidence),
            "world_facts_and_coverage" => Ok(Self::WorldFactsAndCoverage),
            "derived_beliefs" => Ok(Self::DerivedBeliefs),
            "situation_capsule" => Ok(Self::SituationCapsule),
            "investigation_and_hypotheses" => Ok(Self::InvestigationAndHypotheses),
            "affordance_frontier" => Ok(Self::AffordanceFrontier),
            "plan_and_effect" => Ok(Self::PlanAndEffect),
            "outcome_and_episode" => Ok(Self::OutcomeAndEpisode),
            "learning_and_memory" => Ok(Self::LearningAndMemory),
            "workspace_and_handoff" => Ok(Self::WorkspaceAndHandoff),
            _ => Err(ContractError::UnknownAbstractionLayer(name.to_owned())),
        }
    }

    /// Resolves an abstraction layer from its tower level index (0 to 10).
    pub const fn from_tower_level(level: u8) -> Result<Self, ContractError> {
        match level {
            0 => Ok(Self::RuntimeAuthorityAndCustody),
            1 => Ok(Self::SourceEvidence),
            2 => Ok(Self::WorldFactsAndCoverage),
            3 => Ok(Self::DerivedBeliefs),
            4 => Ok(Self::SituationCapsule),
            5 => Ok(Self::InvestigationAndHypotheses),
            6 => Ok(Self::AffordanceFrontier),
            7 => Ok(Self::PlanAndEffect),
            8 => Ok(Self::OutcomeAndEpisode),
            9 => Ok(Self::LearningAndMemory),
            10 => Ok(Self::WorkspaceAndHandoff),
            _ => Err(ContractError::UnknownEntryTag(level)),
        }
    }
}

impl fmt::Display for AgentAbstractionLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for AgentAbstractionLayer {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_id(s).or_else(|_| Self::from_name(s))
    }
}

impl CanonicalEncode for AgentAbstractionLayer {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(self.tower_level());
    }
}

impl CanonicalDecode for AgentAbstractionLayer {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let level = decoder.u8()?;
        Self::from_tower_level(level)
    }
}
