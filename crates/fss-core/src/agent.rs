//! Agent-facing situation, possible-world, affordance, and handoff contracts.

use std::collections::BTreeSet;

use crate::{
    BudgetVector, CanonicalEncode, CanonicalEncoder, Completeness, ContentDigest, ContractError,
    HandoffId, HypothesisDisposition, KnowledgeState, LedgerAnchor, MissionId, ObligationId,
    PrincipalId, ProvenanceClass, SessionId, TimestampNs,
};

/// Exact semantic universe used to interpret an agent request or response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractBasis {
    /// Semantic protocol version.
    pub semantic_protocol: String,
    /// Digest of the JSON Schema catalog.
    pub schema_catalog_digest: ContentDigest,
    /// Ontology generation.
    pub ontology_generation_id: String,
    /// Public operation registry digest.
    pub operation_registry_digest: ContentDigest,
    /// View registry digest.
    pub view_registry_digest: ContentDigest,
    /// Capability registry digest.
    pub capability_registry_digest: ContentDigest,
    /// Error registry digest.
    pub error_registry_digest: ContentDigest,
    /// Cost registry digest.
    pub cost_registry_digest: ContentDigest,
    /// Producer release identity.
    pub producer_release_id: String,
    /// Accepted dated nightly identity.
    pub accepted_nightly: Option<String>,
}

impl ContractBasis {
    /// Builds a deterministic reference basis from exact registry bytes.
    #[must_use]
    pub fn from_registry_bytes(
        schema_catalog: &[u8],
        operations: &[u8],
        views: &[u8],
        capabilities: &[u8],
        errors: &[u8],
        costs: &[u8],
        producer_release_id: impl Into<String>,
        accepted_nightly: Option<String>,
    ) -> Self {
        Self {
            semantic_protocol: "fss/1".to_owned(),
            schema_catalog_digest: ContentDigest::sha256(schema_catalog),
            ontology_generation_id: "ontology:reference:v1".to_owned(),
            operation_registry_digest: ContentDigest::sha256(operations),
            view_registry_digest: ContentDigest::sha256(views),
            capability_registry_digest: ContentDigest::sha256(capabilities),
            error_registry_digest: ContentDigest::sha256(errors),
            cost_registry_digest: ContentDigest::sha256(costs),
            producer_release_id: producer_release_id.into(),
            accepted_nightly,
        }
    }

    /// Returns the canonical basis digest.
    #[must_use]
    pub fn basis_digest(&self) -> ContentDigest {
        self.canonical_digest("fss.agent_contract_basis.v1")
    }
}

impl CanonicalEncode for ContractBasis {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.semantic_protocol);
        encoder.digest(self.schema_catalog_digest);
        encoder.text(&self.ontology_generation_id);
        encoder.digest(self.operation_registry_digest);
        encoder.digest(self.view_registry_digest);
        encoder.digest(self.capability_registry_digest);
        encoder.digest(self.error_registry_digest);
        encoder.digest(self.cost_registry_digest);
        encoder.text(&self.producer_release_id);
        match &self.accepted_nightly {
            Some(value) => {
                encoder.bool(true);
                encoder.text(value);
            }
            None => encoder.bool(false),
        }
    }
}

/// One proposition with orthogonal epistemic, provenance, and hypothesis states.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KnowledgeCell {
    /// Stable proposition identity.
    pub claim_id: String,
    /// Compact human-readable statement.
    pub statement: String,
    /// Epistemic state.
    pub knowledge_state: KnowledgeState,
    /// Provenance class.
    pub provenance: ProvenanceClass,
    /// Hypothesis disposition, when applicable.
    pub hypothesis: Option<HypothesisDisposition>,
    /// Evidence roots supporting the proposition.
    pub evidence: Vec<ContentDigest>,
    /// Contradicting evidence roots.
    pub contradictions: Vec<ContentDigest>,
    /// Validity end, when bounded.
    pub valid_until: Option<TimestampNs>,
}

impl KnowledgeCell {
    /// Returns whether this cell may be used as an irreversible-effect premise.
    #[must_use]
    pub fn is_irreversible_effect_premise(&self, now: TimestampNs) -> bool {
        self.knowledge_state == KnowledgeState::Known
            && !self.evidence.is_empty()
            && self.contradictions.is_empty()
            && self.valid_until.is_none_or(|limit| now <= limit)
    }

    /// Returns the cell digest.
    #[must_use]
    pub fn cell_digest(&self) -> ContentDigest {
        self.canonical_digest("fss.agent_knowledge_cell.v1")
    }
}

impl CanonicalEncode for KnowledgeCell {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.claim_id);
        encoder.text(&self.statement);
        encoder.text(self.knowledge_state.as_str());
        encoder.u8(provenance_code(self.provenance));
        match self.hypothesis {
            Some(value) => {
                encoder.bool(true);
                encoder.u8(hypothesis_code(value));
            }
            None => encoder.bool(false),
        }
        encode_sorted_digests(&self.evidence, encoder);
        encode_sorted_digests(&self.contradictions, encoder);
        match self.valid_until {
            Some(value) => {
                encoder.bool(true);
                value.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
    }
}

/// One factorized possible world retained for decision robustness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PossibleWorld {
    /// Stable world identity.
    pub world_id: String,
    /// Short description.
    pub description: String,
    /// Claims that define this world.
    pub claim_ids: BTreeSet<String>,
    /// Evidence roots keeping this world live.
    pub evidence: Vec<ContentDigest>,
    /// Consequence severity if ignored.
    pub consequence_severity: u8,
    /// Whether policy protects this world from rank-only pruning.
    pub protected: bool,
}

impl CanonicalEncode for PossibleWorld {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.world_id);
        encoder.text(&self.description);
        encoder.u64(self.claim_ids.len() as u64);
        for claim in &self.claim_ids {
            encoder.text(claim);
        }
        encode_sorted_digests(&self.evidence, encoder);
        encoder.u8(self.consequence_severity);
        encoder.bool(self.protected);
    }
}

/// Evidence, possibility, and invariant frontier for one decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldEnvelope {
    /// Stable envelope identity.
    pub envelope_id: String,
    /// Objective identity.
    pub objective_id: String,
    /// Exact evidence anchor.
    pub anchor: LedgerAnchor,
    /// Nominal interpretation claim identities.
    pub nominal_claim_ids: BTreeSet<String>,
    /// Claims certified across all retained worlds.
    pub certified_core_claim_ids: BTreeSet<String>,
    /// Material alternative worlds.
    pub alternatives: Vec<PossibleWorld>,
    /// Protected high-loss residual worlds.
    pub adversarial_residuals: Vec<PossibleWorld>,
    /// Invariants shared by every retained world.
    pub common_invariants: BTreeSet<String>,
    /// Evidence handles that bound observability.
    pub coverage_boundary_handles: BTreeSet<String>,
}

impl WorldEnvelope {
    /// Validates that every protected residual remains represented.
    pub fn validate(&self) -> Result<(), ContractError> {
        let mut seen = BTreeSet::new();
        for world in self
            .alternatives
            .iter()
            .chain(self.adversarial_residuals.iter())
        {
            if world.world_id.is_empty()
                || world.claim_ids.is_empty()
                || world.evidence.is_empty()
                || !seen.insert(world.world_id.as_str())
            {
                return Err(ContractError::EvidenceRequired);
            }
        }
        if self
            .adversarial_residuals
            .iter()
            .any(|world| !world.protected || world.consequence_severity == 0)
        {
            return Err(ContractError::EvidenceRequired);
        }
        Ok(())
    }

    /// Returns the envelope digest bound into plans and situation frames.
    #[must_use]
    pub fn envelope_digest(&self) -> ContentDigest {
        self.canonical_digest("fss.agent_world_envelope.v1")
    }

    /// Returns all retained world identities in deterministic order.
    #[must_use]
    pub fn world_ids(&self) -> BTreeSet<String> {
        self.alternatives
            .iter()
            .chain(self.adversarial_residuals.iter())
            .map(|world| world.world_id.clone())
            .collect()
    }
}

impl CanonicalEncode for WorldEnvelope {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.envelope_id);
        encoder.text(&self.objective_id);
        self.anchor.encode_canonical(encoder);
        encode_sorted_text(&self.nominal_claim_ids, encoder);
        encode_sorted_text(&self.certified_core_claim_ids, encoder);
        let mut alternatives = self.alternatives.clone();
        alternatives.sort_by(|left, right| left.world_id.cmp(&right.world_id));
        encoder.u64(alternatives.len() as u64);
        for world in &alternatives {
            world.encode_canonical(encoder);
        }
        let mut residuals = self.adversarial_residuals.clone();
        residuals.sort_by(|left, right| left.world_id.cmp(&right.world_id));
        encoder.u64(residuals.len() as u64);
        for world in &residuals {
            world.encode_canonical(encoder);
        }
        encode_sorted_text(&self.common_invariants, encoder);
        encode_sorted_text(&self.coverage_boundary_handles, encoder);
    }
}

/// How an action relates to the retained possible-world frontier.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AffordanceClass {
    /// Safe and useful in every protected world.
    Robust,
    /// Safe only after a named observable branch predicate.
    Conditional,
    /// Primarily gathers information.
    Probe,
    /// Waits for a named wake predicate.
    Wait,
    /// Preconditions or authority currently block it.
    Blocked,
    /// No implementation or capability exists.
    Unavailable,
}

impl AffordanceClass {
    /// Returns the stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Robust => "robust",
            Self::Conditional => "conditional",
            Self::Probe => "probe",
            Self::Wait => "wait",
            Self::Blocked => "blocked",
            Self::Unavailable => "unavailable",
        }
    }
}

/// A capability-valid next action with explicit cost and world support.
#[derive(Clone, Debug, PartialEq)]
pub struct ActionAffordance {
    /// Stable affordance identity.
    pub affordance_id: String,
    /// Public operation name.
    pub operation: String,
    /// Target semantic URI.
    pub target: String,
    /// Why the action is available or blocked.
    pub rationale: String,
    /// Classification against the possible-world frontier.
    pub class: AffordanceClass,
    /// Worlds in which this action is supported.
    pub supported_worlds: BTreeSet<String>,
    /// Worlds in which this action is harmful or invalid.
    pub unsafe_worlds: BTreeSet<String>,
    /// Required capability identities.
    pub required_capabilities: BTreeSet<String>,
    /// Expected resource cost.
    pub cost: BudgetVector,
    /// Whether the action can be safely compensated.
    pub reversible: bool,
    /// Optional observable branch predicate.
    pub branch_predicate: Option<String>,
}

impl ActionAffordance {
    /// Validates the classification against a world envelope.
    pub fn validate_against(&self, envelope: &WorldEnvelope) -> Result<(), ContractError> {
        let retained = envelope.world_ids();
        if !self.supported_worlds.is_subset(&retained) || !self.unsafe_worlds.is_subset(&retained) {
            return Err(ContractError::EvidenceRequired);
        }
        if !self.supported_worlds.is_disjoint(&self.unsafe_worlds) {
            return Err(ContractError::EvidenceRequired);
        }
        if self.class == AffordanceClass::Robust
            && (!self.unsafe_worlds.is_empty() || self.supported_worlds != retained)
        {
            return Err(ContractError::EvidenceRequired);
        }
        if self.class == AffordanceClass::Conditional && self.branch_predicate.is_none() {
            return Err(ContractError::EvidenceRequired);
        }
        Ok(())
    }
}

impl CanonicalEncode for ActionAffordance {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.affordance_id);
        encoder.text(&self.operation);
        encoder.text(&self.target);
        encoder.text(&self.rationale);
        encoder.text(self.class.as_str());
        encode_sorted_text(&self.supported_worlds, encoder);
        encode_sorted_text(&self.unsafe_worlds, encoder);
        encode_sorted_text(&self.required_capabilities, encoder);
        encode_budget(self.cost, encoder);
        encoder.bool(self.reversible);
        match &self.branch_predicate {
            Some(value) => {
                encoder.bool(true);
                encoder.text(value);
            }
            None => encoder.bool(false),
        }
    }
}

/// Compact driver-facing frame answering NOW, CHANGED, WHY, UNKNOWN, AT RISK, and NEXT.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SituationFrame {
    /// Stable frame identity.
    pub frame_id: String,
    /// Objective identity.
    pub objective_id: String,
    /// Exact evidence anchor.
    pub anchor: LedgerAnchor,
    /// Possible-world frontier.
    pub world_envelope: WorldEnvelope,
    /// Selected knowledge cells.
    pub knowledge_cells: Vec<KnowledgeCell>,
    /// Current situation statements.
    pub now: Vec<String>,
    /// Meaningful changes.
    pub changed: Vec<String>,
    /// Causal or evidentiary explanation.
    pub why: Vec<String>,
    /// Material unknowns and contradictions.
    pub unknown: Vec<String>,
    /// Risks, invalidators, and urgent obligations.
    pub at_risk: Vec<String>,
    /// Nondominated next affordance identities.
    pub next: Vec<String>,
    /// Stable evidence handles.
    pub evidence_handles: BTreeSet<String>,
}

impl SituationFrame {
    /// Returns the frame fingerprint.
    #[must_use]
    pub fn frame_digest(&self) -> ContentDigest {
        self.canonical_digest("fss.agent_situation_frame.v1")
    }
}

impl CanonicalEncode for SituationFrame {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.frame_id);
        encoder.text(&self.objective_id);
        self.anchor.encode_canonical(encoder);
        self.world_envelope.encode_canonical(encoder);
        let mut cells = self.knowledge_cells.clone();
        cells.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
        encoder.u64(cells.len() as u64);
        for cell in &cells {
            cell.encode_canonical(encoder);
        }
        encode_text_vec(&self.now, encoder);
        encode_text_vec(&self.changed, encoder);
        encode_text_vec(&self.why, encoder);
        encode_text_vec(&self.unknown, encoder);
        encode_text_vec(&self.at_risk, encoder);
        encode_text_vec(&self.next, encoder);
        encode_sorted_text(&self.evidence_handles, encoder);
    }
}

/// One mission-oriented situation publication.
#[derive(Clone, Debug, PartialEq)]
pub struct SituationCapsule {
    /// Capsule identity.
    pub capsule_id: String,
    /// Monotone capsule revision.
    pub revision: u64,
    /// Contract basis.
    pub contract_basis: ContractBasis,
    /// Mission identity.
    pub mission_id: MissionId,
    /// Session identity.
    pub session_id: SessionId,
    /// Principal identity.
    pub principal_id: PrincipalId,
    /// Exact current anchor.
    pub anchor: LedgerAnchor,
    /// Prior anchor when this is a delta-oriented publication.
    pub previous_anchor: Option<LedgerAnchor>,
    /// Driver-facing frame.
    pub frame: SituationFrame,
    /// Effect obligations.
    pub obligations: Vec<ObligationId>,
    /// Current affordance frontier.
    pub affordances: Vec<ActionAffordance>,
    /// Completeness of the capsule for its mission and view.
    pub completeness: Completeness,
    /// Creation time.
    pub created_at: TimestampNs,
}

impl SituationCapsule {
    /// Validates the capsule and computes its decision fingerprint.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.anchor != self.frame.anchor
            || self.anchor != self.frame.world_envelope.anchor
            || self.frame.objective_id != self.frame.world_envelope.objective_id
        {
            return Err(ContractError::StaleAnchor);
        }
        self.frame.world_envelope.validate()?;
        for affordance in &self.affordances {
            affordance.validate_against(&self.frame.world_envelope)?;
        }
        let affordance_ids: BTreeSet<_> = self
            .affordances
            .iter()
            .map(|affordance| affordance.affordance_id.as_str())
            .collect();
        if self
            .frame
            .next
            .iter()
            .any(|next| !affordance_ids.contains(next.as_str()))
        {
            return Err(ContractError::NotFound);
        }
        Ok(())
    }

    /// Returns the decision fingerprint used for replay comparison.
    #[must_use]
    pub fn decision_fingerprint(&self) -> ContentDigest {
        self.canonical_digest("fss.situation_capsule.v1")
    }
}

impl CanonicalEncode for SituationCapsule {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.capsule_id);
        encoder.u64(self.revision);
        self.contract_basis.encode_canonical(encoder);
        self.mission_id.encode_canonical(encoder);
        self.session_id.encode_canonical(encoder);
        self.principal_id.encode_canonical(encoder);
        self.anchor.encode_canonical(encoder);
        match &self.previous_anchor {
            Some(value) => {
                encoder.bool(true);
                value.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
        self.frame.encode_canonical(encoder);
        let mut obligations = self.obligations.clone();
        obligations.sort();
        encoder.u64(obligations.len() as u64);
        for obligation in &obligations {
            obligation.encode_canonical(encoder);
        }
        let mut affordances = self.affordances.clone();
        affordances.sort_by(|left, right| left.affordance_id.cmp(&right.affordance_id));
        encoder.u64(affordances.len() as u64);
        for affordance in &affordances {
            affordance.encode_canonical(encoder);
        }
        encoder.u8(completeness_code(self.completeness));
        self.created_at.encode_canonical(encoder);
    }
}

/// Root-last handoff publication for resuming without hidden conversational state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffCapsule {
    /// Handoff identity.
    pub handoff_id: HandoffId,
    /// Mission identity.
    pub mission_id: MissionId,
    /// Source session.
    pub source_session_id: SessionId,
    /// Source principal.
    pub source_principal_id: PrincipalId,
    /// Evidence anchor.
    pub anchor: LedgerAnchor,
    /// Situation capsule root.
    pub situation_capsule_root: ContentDigest,
    /// Complete child-root set.
    pub child_roots: BTreeSet<ContentDigest>,
    /// Root of the handoff manifest and children.
    pub handoff_root: ContentDigest,
    /// Contract basis.
    pub contract_basis: ContractBasis,
    /// Creation time.
    pub created_at: TimestampNs,
    /// Expiry time.
    pub expires_at: TimestampNs,
}

impl HandoffCapsule {
    /// Materializes and seals a complete root-last handoff capsule.
    pub fn publish(
        handoff_id: HandoffId,
        mission_id: MissionId,
        source_session_id: SessionId,
        source_principal_id: PrincipalId,
        anchor: LedgerAnchor,
        situation_capsule_root: ContentDigest,
        child_roots: impl IntoIterator<Item = ContentDigest>,
        contract_basis: ContractBasis,
        created_at: TimestampNs,
        expires_at: TimestampNs,
    ) -> Result<Self, ContractError> {
        if expires_at < created_at {
            return Err(ContractError::InvertedTimeInterval);
        }
        let mut children: BTreeSet<_> = child_roots.into_iter().collect();
        children.insert(situation_capsule_root);
        if children.is_empty() {
            return Err(ContractError::IncompletePublicationGraph);
        }
        let mut capsule = Self {
            handoff_id,
            mission_id,
            source_session_id,
            source_principal_id,
            anchor,
            situation_capsule_root,
            child_roots: children,
            handoff_root: ContentDigest::sha256(b"unpublished"),
            contract_basis,
            created_at,
            expires_at,
        };
        capsule.handoff_root = capsule.computed_root();
        Ok(capsule)
    }

    /// Recomputes and verifies root and graph closure.
    pub fn verify(&self) -> Result<(), ContractError> {
        if !self.child_roots.contains(&self.situation_capsule_root) {
            return Err(ContractError::IncompletePublicationGraph);
        }
        if self.computed_root() != self.handoff_root {
            return Err(ContractError::DigestMismatch);
        }
        Ok(())
    }

    fn computed_root(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        self.handoff_id.encode_canonical(&mut encoder);
        self.mission_id.encode_canonical(&mut encoder);
        self.source_session_id.encode_canonical(&mut encoder);
        self.source_principal_id.encode_canonical(&mut encoder);
        self.anchor.encode_canonical(&mut encoder);
        encoder.digest(self.situation_capsule_root);
        encoder.u64(self.child_roots.len() as u64);
        for child in &self.child_roots {
            encoder.digest(*child);
        }
        self.contract_basis.encode_canonical(&mut encoder);
        self.created_at.encode_canonical(&mut encoder);
        self.expires_at.encode_canonical(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }
}

fn encode_sorted_digests(values: &[ContentDigest], encoder: &mut CanonicalEncoder) {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    encoder.u64(sorted.len() as u64);
    for value in sorted {
        encoder.digest(value);
    }
}

fn encode_sorted_text(values: &BTreeSet<String>, encoder: &mut CanonicalEncoder) {
    encoder.u64(values.len() as u64);
    for value in values {
        encoder.text(value);
    }
}

fn encode_text_vec(values: &[String], encoder: &mut CanonicalEncoder) {
    encoder.u64(values.len() as u64);
    for value in values {
        encoder.text(value);
    }
}

fn encode_budget(value: BudgetVector, encoder: &mut CanonicalEncoder) {
    encoder.u64(value.latency_ms);
    encoder.u64(value.tokens);
    encoder.u64(value.bytes);
    encoder.u32(value.model_calls);
    encoder.u64(value.cpu_millis);
    encoder.u64(value.network_bytes);
    encoder.u64(value.storage_operations);
    encoder.u64(canonical_f64_bits(value.privacy_exposure));
    encoder.u64(canonical_f64_bits(value.operator_attention_seconds));
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

fn provenance_code(value: ProvenanceClass) -> u8 {
    match value {
        ProvenanceClass::Observed => 1,
        ProvenanceClass::Derived => 2,
        ProvenanceClass::Predicted => 3,
        ProvenanceClass::Remembered => 4,
        ProvenanceClass::OperatorAsserted => 5,
        ProvenanceClass::VendorClaimed => 6,
        ProvenanceClass::Policy => 7,
    }
}

fn hypothesis_code(value: HypothesisDisposition) -> u8 {
    match value {
        HypothesisDisposition::Live => 1,
        HypothesisDisposition::Supported => 2,
        HypothesisDisposition::Disfavored => 3,
        HypothesisDisposition::Refuted => 4,
        HypothesisDisposition::Resolved => 5,
        HypothesisDisposition::Superseded => 6,
    }
}

fn completeness_code(value: Completeness) -> u8 {
    match value {
        Completeness::Complete => 1,
        Completeness::Bounded => 2,
        Completeness::Partial => 3,
        Completeness::Unknown => 4,
        Completeness::NotObservable => 5,
        Completeness::Unauthorized => 6,
        Completeness::Stale => 7,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basis() -> ContractBasis {
        ContractBasis::from_registry_bytes(
            b"schemas",
            b"operations",
            b"views",
            b"capabilities",
            b"errors",
            b"costs",
            "fss:0.0.1",
            Some("nightly-2026-08-31".to_owned()),
        )
    }

    #[test]
    fn handoff_requires_and_verifies_situation_root() -> Result<(), ContractError> {
        let situation_root = ContentDigest::sha256(b"situation");
        let capsule = HandoffCapsule::publish(
            HandoffId::parse("handoff:one")?,
            MissionId::parse("mission:one")?,
            SessionId::parse("session:one")?,
            PrincipalId::parse("principal:one")?,
            LedgerAnchor::genesis("site:one"),
            situation_root,
            [ContentDigest::sha256(b"case")],
            basis(),
            TimestampNs(10),
            TimestampNs(20),
        )?;
        assert!(capsule.child_roots.contains(&situation_root));
        capsule.verify()
    }
}
