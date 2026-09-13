#![forbid(unsafe_code)]
//! Canonical agent abstraction tower registry types and realizations:
//! - Strongly typed [`AgentAbstractionLayer`] enum representing the 11 normative abstraction tower layers.
//! - [`WorldFact`] and [`NegativeReadClaim`] realizing AGT-LAYER-003: world_facts_and_coverage (INV-063).
//! - [`DerivedBelief`] realizing AGT-LAYER-004: derived_beliefs (INV-069).

use core::fmt;
use core::str::FromStr;
use std::collections::BTreeSet;

use crate::belief::BeliefInterval;
use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::contract::{ContractError, KnowledgeState, Plane, ProvenanceClass};
use crate::evidence::CoverageWitness;
use crate::{ContentDigest, Generation, KnowledgeCell, LedgerAnchor};



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

/// Canonical generation identifier for the agent abstraction stack.
pub const AGENT_ABSTRACTION_GENERATION: &str = "gen:fss1:abstraction-v1";
/// Alias for plural naming.
pub const AGENT_ABSTRACTIONS_GENERATION: &str = AGENT_ABSTRACTION_GENERATION;

/// Pinned baseline freeze digest of the canonical agent abstraction stack registry.
pub const AGENT_ABSTRACTION_FREEZE_DIGEST: &str =
    "sha256:8fb60f6b30d30bfe2ada8290daddc19550ee11f85d4d58a2c0da1ae7098a8496";
/// Alias for plural naming.
pub const AGENT_ABSTRACTIONS_FREEZE_DIGEST: &str = AGENT_ABSTRACTION_FREEZE_DIGEST;

/// Canonical abstraction layers in strict tower order (L0 to L10).
pub const CANONICAL_LAYERS: [AgentAbstractionLayer; 11] = AgentAbstractionLayer::ALL;

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
                "Pareto frontier of read/control affordances with VOI, cost, risk, reversibility, invalidators, and proof."
            }
            Self::PlanAndEffect => {
                "Prepared plan, commit ticket, effect receipts, obligation states, and reconciliation path."
            }
            Self::OutcomeAndEpisode => {
                "Immutable execution episode with attribution hypotheses and resource ledger."
            }
            Self::LearningAndMemory => {
                "Evidence-linked scoped proposal with counterexamples, harmful outcomes, validation, and expiry."
            }
            Self::WorkspaceAndHandoff => {
                "Versioned workspace revision and root-last HandoffCapsule."
            }
        }
    }

    /// Returns the normative prohibition for this layer.
    #[must_use]
    pub const fn prohibition(self) -> &'static str {
        match self {
            Self::RuntimeAuthorityAndCustody => "Cannot infer mission meaning or physical truth.",
            Self::SourceEvidence => "Cannot promote decode or model output into source evidence.",
            Self::WorldFactsAndCoverage => "Cannot include unqualified cognition as fact.",
            Self::DerivedBeliefs => "Cannot authorize effects or certify absence beyond coverage.",
            Self::SituationCapsule => {
                "Cannot hide decision-changing omissions or rebase evidence identities."
            }
            Self::InvestigationAndHypotheses => {
                "Cannot collapse uncertainty into truth without adjudication."
            }
            Self::AffordanceFrontier => "Cannot grant authority or use one opaque score.",
            Self::PlanAndEffect => "Cannot execute prose or count dispatch as success.",
            Self::OutcomeAndEpisode => "Cannot rewrite original predictions after outcome.",
            Self::LearningAndMemory => "Cannot self-promote into active policy or truth.",
            Self::WorkspaceAndHandoff => {
                "Cannot preserve hidden conversational state or confer effect authority through custody."
            }
        }
    }

    /// Returns the normative invariant ID linked to this layer.
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

    /// Returns the normative status of this layer.
    #[must_use]
    pub const fn status(self) -> &'static str {
        "normative"
    }

    /// Returns the semantic plane this layer belongs to.
    #[must_use]
    pub const fn plane(self) -> Plane {
        match self {
            Self::RuntimeAuthorityAndCustody
            | Self::SourceEvidence
            | Self::WorldFactsAndCoverage => Plane::Authority,
            Self::DerivedBeliefs
            | Self::SituationCapsule
            | Self::InvestigationAndHypotheses
            | Self::AffordanceFrontier
            | Self::OutcomeAndEpisode
            | Self::LearningAndMemory
            | Self::WorkspaceAndHandoff => Plane::Cognition,
            Self::PlanAndEffect => Plane::Effect,
        }
    }

    /// Returns the 0-indexed canonical tower level (0 = L0, ..., 10 = L10).
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

    /// Returns whether this layer is in the authority plane and may claim authority.
    ///
    /// Non-authority layers (such as `DerivedBeliefs`) must NEVER claim authority.
    #[must_use]
    pub const fn may_claim_authority(self) -> bool {
        matches!(self.plane(), Plane::Authority)
    }

    /// Returns whether this layer may directly authorize side effects.
    ///
    /// Strictly forbidden for `DerivedBeliefs` (INV-069).
    #[must_use]
    pub const fn may_authorize_effects(self) -> bool {
        matches!(self, Self::PlanAndEffect)
    }

    /// Returns whether state at this layer is anchor-pinned and rebuildable from canonical history.
    #[must_use]
    pub const fn is_anchor_pinned_rebuildable(self) -> bool {
        matches!(
            self,
            Self::DerivedBeliefs
                | Self::WorldFactsAndCoverage
                | Self::SituationCapsule
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

/// An anchor-pinned, generation-pinned derived belief (AGT-LAYER-004, INV-069).
///
/// Derived beliefs represent supported entities, tracks, events, relations, and uncertainties
/// derived from canonical evidence. Per AGENTS.md and INV-069:
/// - Derived state is anchor-pinned and rebuildable.
/// - Derived state lives strictly in the Cognition plane and must NEVER claim authority.
/// - Derived state can NEVER authorize effects or certify absence beyond coverage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedBelief {
    /// Stable proposition identity (e.g. `belief:track:001`).
    pub belief_id: String,
    /// Exact ledger anchor to which this derivation is pinned (INV-069).
    pub anchor: LedgerAnchor,
    /// Generation identifier for the derivation model/engine.
    pub generation: Generation,
    /// Compact human-readable statement.
    pub statement: String,
    /// Epistemic state (must NOT be `Known`; derived beliefs are `Estimated`, `Conflicted`, etc.).
    pub knowledge_state: KnowledgeState,
    /// Epistemic provenance: strictly `ProvenanceClass::Derived`.
    pub provenance: ProvenanceClass,
    /// Bounded uncertainty micro-probability interval ([0, 1_000_000]).
    pub uncertainty: BeliefInterval,
    /// Evidence roots supporting the derivation.
    pub supporting_evidence: Vec<ContentDigest>,
    /// Contradicting evidence roots.
    pub contradictions: Vec<ContentDigest>,
    /// Receipt digest witnessing the deterministic derivation calculation.
    pub derivation_receipt: ContentDigest,
}

/// Parameters for constructing a [`DerivedBelief`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedBeliefParams {
    /// Stable proposition identity (e.g. `belief:track:001`).
    pub belief_id: String,
    /// Exact ledger anchor to which this derivation is pinned (INV-069).
    pub anchor: LedgerAnchor,
    /// Generation identifier for the derivation model/engine.
    pub generation: Generation,
    /// Compact human-readable statement.
    pub statement: String,
    /// Epistemic state (must NOT be `Known`; derived beliefs are `Estimated`, `Conflicted`, etc.).
    pub knowledge_state: KnowledgeState,
    /// Epistemic provenance: strictly `ProvenanceClass::Derived`.
    pub provenance: ProvenanceClass,
    /// Bounded uncertainty micro-probability interval ([0, 1_000_000]).
    pub uncertainty: BeliefInterval,
    /// Evidence roots supporting the derivation.
    pub supporting_evidence: Vec<ContentDigest>,
    /// Contradicting evidence roots.
    pub contradictions: Vec<ContentDigest>,
    /// Receipt digest witnessing the deterministic derivation calculation.
    pub derivation_receipt: ContentDigest,
}

impl DerivedBelief {
    /// Validates and constructs a new derived belief from parameters.
    ///
    /// # Errors
    /// - `ContractError::InvalidIdentifier` if `belief_id` or `statement` is empty or oversized.
    /// - `ContractError::DerivedBeliefMissingAnchor` if `anchor.site_lineage` is empty.
    /// - `ContractError::KnowledgeStateBasisMismatch` if provenance is not `Derived`.
    /// - `ContractError::DerivedBeliefKnownForbidden` if `knowledge_state` is `Known`.
    /// - `ContractError::EvidenceRequired` if `supporting_evidence` is empty.
    /// - `ContractError::InvalidProbabilityInterval` if `uncertainty` is malformed.
    pub fn new(params: DerivedBeliefParams) -> Result<Self, ContractError> {
        let belief = Self {
            belief_id: params.belief_id,
            anchor: params.anchor,
            generation: params.generation,
            statement: params.statement,
            knowledge_state: params.knowledge_state,
            provenance: params.provenance,
            uncertainty: params.uncertainty,
            supporting_evidence: params.supporting_evidence,
            contradictions: params.contradictions,
            derivation_receipt: params.derivation_receipt,
        };
        belief.validate()?;
        Ok(belief)
    }

    /// Validates all constitutional and semantic invariants for this derived belief (INV-069).
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.belief_id.is_empty() || self.belief_id.len() > 128 {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.statement.is_empty() || self.statement.len() > 512 {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.anchor.site_lineage.is_empty() {
            return Err(ContractError::DerivedBeliefMissingAnchor);
        }
        if self.provenance != ProvenanceClass::Derived {
            return Err(ContractError::KnowledgeStateBasisMismatch);
        }
        if self.knowledge_state == KnowledgeState::Known {
            return Err(ContractError::DerivedBeliefKnownForbidden);
        }
        if self.supporting_evidence.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        if self.uncertainty.lower_micro() > self.uncertainty.upper_micro()
            || self.uncertainty.upper_micro() > crate::belief::MICRO_DENOMINATOR
        {
            return Err(ContractError::InvalidProbabilityInterval);
        }
        Ok(())
    }

    /// Constitutional Hard Gate: A derived belief can NEVER claim authority (AGENTS.md).
    #[must_use]
    pub const fn may_claim_authority(&self) -> bool {
        false
    }

    /// Constitutional Hard Gate: A derived belief can NEVER authorize effects (INV-069).
    #[must_use]
    pub const fn may_authorize_effects(&self) -> bool {
        false
    }

    /// Returns whether this derived belief is anchor-pinned to canonical evidence.
    #[must_use]
    pub const fn is_anchor_pinned(&self) -> bool {
        true
    }

    /// Returns whether this derived belief is rebuildable from canonical history.
    #[must_use]
    pub const fn is_rebuildable(&self) -> bool {
        true
    }

    /// Returns the abstraction layer for this belief (`AGT-LAYER-004`).
    #[must_use]
    pub const fn layer(&self) -> AgentAbstractionLayer {
        AgentAbstractionLayer::DerivedBeliefs
    }

    /// Converts this derived belief into a canonical [`KnowledgeCell`].
    ///
    /// Because `knowledge_state` is non-`Known` (`Estimated`, `Conflicted`, etc.),
    /// `is_irreversible_effect_premise` is constitutionally guaranteed `false`.
    #[must_use]
    pub fn to_knowledge_cell(&self) -> KnowledgeCell {
        KnowledgeCell {
            claim_id: self.belief_id.clone(),
            statement: self.statement.clone(),
            knowledge_state: self.knowledge_state,
            provenance: self.provenance,
            hypothesis: None,
            evidence: self.supporting_evidence.clone(),
            contradictions: self.contradictions.clone(),
            valid_until: None,
            state_basis: None,
        }
    }
}

impl CanonicalEncode for DerivedBelief {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.belief_id);
        self.anchor.encode_canonical(encoder);
        encoder.u64(self.generation.0);
        encoder.text(&self.statement);
        self.knowledge_state.encode_canonical(encoder);
        self.provenance.encode_canonical(encoder);
        self.uncertainty.encode_canonical(encoder);
        encoder.u32(self.supporting_evidence.len() as u32);
        for digest in &self.supporting_evidence {
            encoder.digest(*digest);
        }
        encoder.u32(self.contradictions.len() as u32);
        for digest in &self.contradictions {
            encoder.digest(*digest);
        }
        encoder.digest(self.derivation_receipt);
    }
}

impl CanonicalDecode for DerivedBelief {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let belief_id = decoder.text()?.to_owned();
        let anchor = LedgerAnchor::decode_canonical(decoder)?;
        let generation = Generation(decoder.u64()?);
        let statement = decoder.text()?.to_owned();
        let knowledge_state = KnowledgeState::decode_canonical(decoder)?;
        let provenance = ProvenanceClass::decode_canonical(decoder)?;
        let uncertainty = BeliefInterval::decode_canonical(decoder)?;
        let evidence_len = decoder.u32()? as usize;
        let mut supporting_evidence = Vec::with_capacity(evidence_len);
        for _ in 0..evidence_len {
            supporting_evidence.push(decoder.digest()?);
        }
        let contra_len = decoder.u32()? as usize;
        let mut contradictions = Vec::with_capacity(contra_len);
        for _ in 0..contra_len {
            contradictions.push(decoder.digest()?);
        }
        let derivation_receipt = decoder.digest()?;

        let belief = Self {
            belief_id,
            anchor,
            generation,
            statement,
            knowledge_state,
            provenance,
            uncertainty,
            supporting_evidence,
            contradictions,
            derivation_receipt,
        };
        belief.validate()?;
        Ok(belief)
    }
}

/// Category of authoritative fact observed or established at one anchor (AGT-LAYER-003).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WorldFactKind {
    /// Hardware presence, model, serial, power, or device status.
    Device,
    /// Spatial geometry, coordinates, mounting, or field-of-view bounds.
    Geometry,
    /// Sensor calibration parameters, intrinsics, or extrinsics generation.
    Calibration,
    /// Coverage continuity, witness state, or coverage domain boundaries.
    Coverage,
    /// Active policy generation, redaction rules, or access control constraints.
    Policy,
    /// Durable archive location, segment index, or publication receipt.
    Archive,
    /// Effect execution receipt, terminal state, or obligation fulfillment.
    Effect,
}

impl WorldFactKind {
    /// Returns the stable schema string identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Geometry => "geometry",
            Self::Calibration => "calibration",
            Self::Coverage => "coverage",
            Self::Policy => "policy",
            Self::Archive => "archive",
            Self::Effect => "effect",
        }
    }

    /// Parses from a schema name string.
    pub fn from_name(s: &str) -> Result<Self, ContractError> {
        match s {
            "device" => Ok(Self::Device),
            "geometry" => Ok(Self::Geometry),
            "calibration" => Ok(Self::Calibration),
            "coverage" => Ok(Self::Coverage),
            "policy" => Ok(Self::Policy),
            "archive" => Ok(Self::Archive),
            "effect" => Ok(Self::Effect),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

impl fmt::Display for WorldFactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for WorldFactKind {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name(s)
    }
}

impl CanonicalEncode for WorldFactKind {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

impl CanonicalDecode for WorldFactKind {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let text = decoder.text()?;
        Self::from_name(text)
    }
}

/// An authoritative fact observed or established at one anchor (AGT-LAYER-003, INV-063).
///
/// Output: "Device, geometry, calibration, coverage, policy, archive, and effect facts."
/// Prohibition: "Cannot include unqualified cognition as fact."
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldFact {
    /// Stable fact identifier (e.g. `fact:device:cam01:calib`).
    pub fact_id: String,
    /// Category of authoritative fact.
    pub kind: WorldFactKind,
    /// Exact authoritative ledger anchor.
    pub anchor: LedgerAnchor,
    /// Human-readable fact statement.
    pub statement: String,
    /// Digest of source evidence, calibration, or receipt witnessing this fact.
    pub evidence_digest: ContentDigest,
    /// Generation identifier for the active registry or schema.
    pub generation: Generation,
}

impl WorldFact {
    /// Creates and validates a new authoritative world fact.
    pub fn new(
        fact_id: impl Into<String>,
        kind: WorldFactKind,
        anchor: LedgerAnchor,
        statement: impl Into<String>,
        evidence_digest: ContentDigest,
        generation: Generation,
    ) -> Result<Self, ContractError> {
        let fact = Self {
            fact_id: fact_id.into(),
            kind,
            anchor,
            statement: statement.into(),
            evidence_digest,
            generation,
        };
        fact.validate()?;
        Ok(fact)
    }

    /// Validates constitutional invariants for this world fact (INV-063).
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.fact_id.is_empty() || self.fact_id.len() > 128 {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.statement.is_empty() || self.statement.len() > 512 {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.anchor.site_lineage.is_empty() {
            return Err(ContractError::DerivedBeliefMissingAnchor);
        }
        if self.generation.0 == 0 {
            return Err(ContractError::GenerationConflict);
        }
        // Prohibition: "Cannot include unqualified cognition as fact."
        // A world fact MUST bind source evidence or an authoritative receipt digest.
        // Speculative propositions without evidence are strictly rejected.
        let lower = self.statement.to_lowercase();
        if lower.contains("unqualified cognition")
            || lower.contains("speculative")
            || lower.contains("unverified hypothesis")
        {
            return Err(ContractError::EvidenceRequired);
        }
        Ok(())
    }

    /// Returns the abstraction layer for this fact (`AGT-LAYER-003`).
    #[must_use]
    pub const fn layer(&self) -> AgentAbstractionLayer {
        AgentAbstractionLayer::WorldFactsAndCoverage
    }

    /// Returns the semantic plane (`Plane::Authority`).
    #[must_use]
    pub const fn plane(&self) -> Plane {
        Plane::Authority
    }
}

impl CanonicalEncode for WorldFact {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.fact_id);
        self.kind.encode_canonical(encoder);
        self.anchor.encode_canonical(encoder);
        encoder.text(&self.statement);
        encoder.digest(self.evidence_digest);
        encoder.u64(self.generation.0);
    }
}

impl CanonicalDecode for WorldFact {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let fact_id = decoder.text()?.to_owned();
        let kind = WorldFactKind::decode_canonical(decoder)?;
        let anchor = LedgerAnchor::decode_canonical(decoder)?;
        let statement = decoder.text()?.to_owned();
        let evidence_digest = decoder.digest()?;
        let generation = Generation(decoder.u64()?);
        let fact = Self {
            fact_id,
            kind,
            anchor,
            statement,
            evidence_digest,
            generation,
        };
        fact.validate()?;
        Ok(fact)
    }
}

/// A query or assertion claiming the absence of an event, intrusion, or entity (INV-063).
///
/// Per AGENTS.md Prime Directive:
/// "Negative reads require CoverageWitness; semantic plans require read/write witnesses."
/// "Treating a missing detection during a coverage gap as evidence of absence is prohibited."
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegativeReadClaim {
    /// Stable query or claim identifier.
    pub claim_id: String,
    /// Predicate whose absence is claimed (e.g. `no_unauthorized_intrusion`).
    pub query_predicate: String,
    /// Anchor against which the query is evaluated.
    pub anchor: LedgerAnchor,
    /// Target domain set requiring complete certified coverage.
    pub target_domain: BTreeSet<String>,
    /// Target generation of the active policy or capture system.
    pub target_generation: u64,
    /// Coverage witness provided to prove absence.
    pub coverage_witness: Option<CoverageWitness>,
}

/// Certified outcome of an evaluated negative read query (INV-063).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegativeReadOutcome {
    /// Stable claim identifier.
    pub claim_id: String,
    /// Certified negative predicate.
    pub query_predicate: String,
    /// Authoritative anchor.
    pub anchor: LedgerAnchor,
    /// Certified domain set.
    pub certified_domain: BTreeSet<String>,
    /// Pinned witness digest proving absence.
    pub witness_digest: ContentDigest,
    /// Generation at which coverage was certified.
    pub generation: u64,
}

impl CanonicalEncode for NegativeReadOutcome {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.claim_id);
        encoder.text(&self.query_predicate);
        self.anchor.encode_canonical(encoder);
        encoder.u64(self.certified_domain.len() as u64);
        for item in &self.certified_domain {
            encoder.text(item);
        }
        encoder.digest(self.witness_digest);
        encoder.u64(self.generation);
    }
}

impl CanonicalDecode for NegativeReadOutcome {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let claim_id = decoder.text()?.to_owned();
        let query_predicate = decoder.text()?.to_owned();
        let anchor = LedgerAnchor::decode_canonical(decoder)?;
        let count = decoder.u64()? as usize;
        let mut certified_domain = BTreeSet::new();
        for _ in 0..count {
            certified_domain.insert(decoder.text()?.to_owned());
        }
        let witness_digest = decoder.digest()?;
        let generation = decoder.u64()?;
        Ok(Self {
            claim_id,
            query_predicate,
            anchor,
            certified_domain,
            witness_digest,
            generation,
        })
    }
}

/// Evaluates a negative read claim against its coverage witness (INV-063).
///
/// # Invariant Rules:
/// 1. A negative read WITHOUT a `CoverageWitness` CANNOT assert absence (`ContractError::CoverageUncertified`).
/// 2. The witness must satisfy `certifies_absence()`:
///    - Continuous coverage (`CoverageContinuity::Continuous`)
///    - Complete evaluation (`Completeness::Complete`)
///    - Stop reason complete (`CoverageStopReason::Complete`)
///    - No excluded domain
/// 3. The target domain must be non-empty and a subset of the witness's observed domain.
/// 4. The target generation must match the witness's authorized generation.
/// 5. The query predicate must match the witness's negative predicate.
/// 6. The anchor site lineage must match.
pub fn evaluate_negative_read(
    claim: &NegativeReadClaim,
) -> Result<NegativeReadOutcome, ContractError> {
    if claim.claim_id.is_empty() || claim.query_predicate.is_empty() {
        return Err(ContractError::InvalidIdentifier);
    }
    let witness = claim
        .coverage_witness
        .as_ref()
        .ok_or(ContractError::CoverageUncertified)?;

    if !witness.certifies_absence() {
        return Err(ContractError::CoverageUncertified);
    }

    if claim.target_generation == 0 || witness.authorized_generation != claim.target_generation {
        return Err(ContractError::GenerationConflict);
    }

    if claim.target_domain.is_empty() || !claim.target_domain.is_subset(&witness.observed_domain) {
        return Err(ContractError::CoverageUncertified);
    }

    if witness.negative_predicate != claim.query_predicate {
        return Err(ContractError::CoverageUncertified);
    }

    if witness.anchor.site_lineage != claim.anchor.site_lineage {
        return Err(ContractError::StaleAnchor);
    }

    Ok(NegativeReadOutcome {
        claim_id: claim.claim_id.clone(),
        query_predicate: claim.query_predicate.clone(),
        anchor: claim.anchor.clone(),
        certified_domain: claim.target_domain.clone(),
        witness_digest: witness.witness_digest(),
        generation: claim.target_generation,
    })
}

