#![forbid(unsafe_code)]
//! Agent mission and cognitive-control graph `G_agent` (`PROJ-AGENT-001`, `fss-x4a.23.69.11`).
//!
//! Represents mission/objective revisions, sessions/workspaces, SituationCapsules/Frames,
//! WorldEnvelopes/possible worlds, knowledge cells, investigations/hypotheses/probes, evidence
//! handles, affordances, plans/obligations/findings/work claims, episodes/learning proposals, and
//! handoffs — preserving the full 12-verb typed edge vocabulary (`basis`, `supports`,
//! `contradicts`, `invalidates`, `discriminates`, `world-safety`, `controls`, `owns`, `delegates`,
//! `supersedes`, `learns-from`, `resumes`).
//!
//! Core guarantees:
//! - Mandatory mission/workspace binding plus authority & cognition high-water marks; zero
//!   conversational-only obligations or next steps;
//! - Work claims NEVER grant effect authority, plan edges NEVER claim occurrence, and remembered
//!   episodes NEVER masquerade as current facts;
//! - Detects stale handoffs, conflicting active work claims, dropped protected worlds, invalidated
//!   plans, and computes decision-impact deltas and capability-projected recipient views across
//!   `orient -> investigate -> plan -> handoff -> resume`.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest, Generation,
    GraphAlgorithmWitness, LedgerAnchor, Plane,
};

use crate::projection::{
    AbsenceBoundary, GraphUniverse, ImmutableGraphProjection, ProjectionAuthorityScope,
    ProjectionEdgeSpec, ProjectionNodeSpec, ProjectionOrientation,
};

use super::{
    CURRENT_UNIVERSE_WIRE_VERSION, LEGACY_UNIVERSE_WIRE_VERSION, MAX_UNIVERSE_ITEMS, OpBudget,
    TypedUniverseError, UniverseMigrationReport, build_universe_witness, hash_domain_tag,
    open_wire_envelope, seal_wire_envelope, validate_clean_label,
};

/// Registered digest domain for `G_agent` projections and witnesses
/// (`SCHEMA-DOMAIN-GRAPH-G-AGENT-001`).
pub const G_AGENT_DIGEST_DOMAIN: &str = "fss.graph.g_agent_projection.v1";
/// Wire magic for durable `G_agent` fixtures (`FSSGAG01`).
pub const G_AGENT_WIRE_MAGIC: [u8; 8] = *b"FSSGAG01";
/// Registered algorithm ID emitted in `G_agent` witnesses.
pub const G_AGENT_ALGORITHM_ID: &str = "ALG-PROJ-AGENT-001";
/// Implementation generation recorded in `G_agent` witnesses.
pub const G_AGENT_IMPLEMENTATION_ID: &str = "fss-graph-algorithms:proj-agent-001:g-agent-oracle:v2";
/// Policy identity recorded in `G_agent` witnesses.
pub const G_AGENT_POLICY_ID: &str =
    "graph-policy:g-agent:mission-closure:non-conversational-obligations:v2";

/// Closed taxonomy of cognitive-control entities in `G_agent`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AgentNodeKind {
    /// Mission / ObjectiveContract revision.
    MissionRevision = 1,
    /// Agent session / workspace root.
    SessionWorkspace = 2,
    /// Anchored SituationCapsule / SituationFrame.
    SituationCapsule = 3,
    /// Factorized WorldEnvelope / protected world reference.
    WorldEnvelope = 4,
    /// Typed epistemic KnowledgeCell.
    KnowledgeCell = 5,
    /// Active InvestigationCase.
    Investigation = 6,
    /// Competing Hypothesis inside an investigation.
    Hypothesis = 7,
    /// Branch-collapsing information-gathering Probe.
    Probe = 8,
    /// Priced evidence hydration handle.
    EvidenceHandle = 9,
    /// Decomposed nondominated Affordance.
    Affordance = 10,
    /// Witnessed Plan (never claims occurrence!).
    Plan = 11,
    /// Explicit persisted Obligation (never conversational-only!).
    Obligation = 12,
    /// Evidence-linked Finding.
    Finding = 13,
    /// Coordination WorkClaim (never grants effect authority!).
    WorkClaim = 14,
    /// Historical remembered Episode (never current canonical fact!).
    Episode = 15,
    /// Learning proposal awaiting validation.
    LearningProposal = 16,
    /// Typed persisted Handoff capsule.
    Handoff = 17,
}

impl AgentNodeKind {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::MissionRevision),
            2 => Ok(Self::SessionWorkspace),
            3 => Ok(Self::SituationCapsule),
            4 => Ok(Self::WorldEnvelope),
            5 => Ok(Self::KnowledgeCell),
            6 => Ok(Self::Investigation),
            7 => Ok(Self::Hypothesis),
            8 => Ok(Self::Probe),
            9 => Ok(Self::EvidenceHandle),
            10 => Ok(Self::Affordance),
            11 => Ok(Self::Plan),
            12 => Ok(Self::Obligation),
            13 => Ok(Self::Finding),
            14 => Ok(Self::WorkClaim),
            15 => Ok(Self::Episode),
            16 => Ok(Self::LearningProposal),
            17 => Ok(Self::Handoff),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown AgentNodeKind tag {other}"
            ))),
        }
    }
}

/// Full 12-verb typed edge vocabulary in `G_agent`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AgentEdgeKind {
    /// ContractBasis / anchor basis dependency.
    Basis = 1,
    /// Evidence support edge.
    Supports = 2,
    /// Contradiction edge.
    Contradicts = 3,
    /// Invalidation edge (e.g. new evidence invalidates plan/handoff).
    Invalidates = 4,
    /// Probe discriminates between competing hypotheses.
    Discriminates = 5,
    /// World-safety protection edge preserving high-loss worlds.
    WorldSafety = 6,
    /// Control-flow relation (`mission` controls `investigation/plan`).
    Controls = 7,
    /// Ownership relation (`workspace/agent` owns `obligation/claim`).
    Owns = 8,
    /// Explicit obligation delegation (`handoff` delegates `obligation`).
    Delegates = 9,
    /// Supersession (`new_mission` supersedes `old_mission`).
    Supersedes = 10,
    /// Learning link (`proposal` learns-from `episode`).
    LearnsFrom = 11,
    /// Session resume link (`new_session` resumes `handoff`).
    Resumes = 12,
}

impl AgentEdgeKind {
    /// Stable canonical relation name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Basis => "basis",
            Self::Supports => "supports",
            Self::Contradicts => "contradicts",
            Self::Invalidates => "invalidates",
            Self::Discriminates => "discriminates",
            Self::WorldSafety => "world-safety",
            Self::Controls => "controls",
            Self::Owns => "owns",
            Self::Delegates => "delegates",
            Self::Supersedes => "supersedes",
            Self::LearnsFrom => "learns-from",
            Self::Resumes => "resumes",
        }
    }

    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::Basis),
            2 => Ok(Self::Supports),
            3 => Ok(Self::Contradicts),
            4 => Ok(Self::Invalidates),
            5 => Ok(Self::Discriminates),
            6 => Ok(Self::WorldSafety),
            7 => Ok(Self::Controls),
            8 => Ok(Self::Owns),
            9 => Ok(Self::Delegates),
            10 => Ok(Self::Supersedes),
            11 => Ok(Self::LearnsFrom),
            12 => Ok(Self::Resumes),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown AgentEdgeKind tag {other}"
            ))),
        }
    }
}

/// One typed node in `G_agent` binding mission/workspace, authority/cognition HWMs, and invariants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentControlNode {
    /// Stable unique node ID.
    pub node_id: String,
    /// Cognitive-control entity kind.
    pub kind: AgentNodeKind,
    /// Mandatory mission identifier binding this node (no orphan conversational work!).
    pub mission_id: String,
    /// Mandatory workspace identifier binding this node.
    pub workspace_id: String,
    /// Authority high-water mark sequence pinned by this node.
    pub authority_hwm: u64,
    /// Cognition high-water mark sequence pinned by this node.
    pub cognition_hwm: u64,
    /// Optional target key for `WorkClaim` conflict detection (two active claims on same target!).
    pub claim_target_id: Option<String>,
    /// True iff this node protects a high-loss world (must survive handoff!).
    pub protects_high_loss_world: bool,
    /// MUST be `false` for `WorkClaim`: work claims NEVER grant effect authority!
    pub grants_effect_authority: bool,
    /// MUST be `false` for `Plan`: plan nodes NEVER claim effect occurrence!
    pub claims_occurrence: bool,
    /// MUST be `false` for `Episode`: remembered episodes NEVER masquerade as current facts!
    pub asserts_current_fact: bool,
    /// Owning semantic plane.
    pub plane: Plane,
}

impl AgentControlNode {
    /// Validates mission/workspace binding and non-collapse cognitive-control invariants fail-closed!
    pub fn validate(&self) -> Result<(), TypedUniverseError> {
        validate_clean_label(&self.node_id, "node_id")?;
        validate_clean_label(&self.mission_id, "mission_id")?;
        validate_clean_label(&self.workspace_id, "workspace_id")?;
        if let Some(ref target) = self.claim_target_id {
            validate_clean_label(target, "claim_target_id")?;
        }
        if self.authority_hwm == 0 || self.cognition_hwm == 0 {
            return Err(TypedUniverseError::InvalidInput(format!(
                "node '{}' must bind nonzero authority_hwm and cognition_hwm",
                self.node_id
            )));
        }
        if self.grants_effect_authority {
            return Err(TypedUniverseError::AuthorityViolation(format!(
                "G_agent node '{}' cannot grant effect authority",
                self.node_id
            )));
        }
        if self.kind == AgentNodeKind::Plan && self.claims_occurrence {
            return Err(TypedUniverseError::AuthorityViolation(format!(
                "plan node '{}' cannot claim effect occurrence",
                self.node_id
            )));
        }
        if self.kind == AgentNodeKind::Episode && self.asserts_current_fact {
            return Err(TypedUniverseError::AuthorityViolation(format!(
                "remembered episode '{}' cannot masquerade as current canonical fact",
                self.node_id
            )));
        }
        Ok(())
    }

    /// Canonical SHA-256 commitment for this cognitive-control node.
    #[must_use]
    pub fn node_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        hash_domain_tag(G_AGENT_DIGEST_DOMAIN, 1, &enc.finish())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.node_id);
        enc.u8(self.kind as u8);
        enc.text(&self.mission_id);
        enc.text(&self.workspace_id);
        enc.u64(self.authority_hwm);
        enc.u64(self.cognition_hwm);
        match &self.claim_target_id {
            Some(t) => {
                enc.u8(1);
                enc.text(t);
            }
            None => enc.u8(0),
        }
        enc.u8(u8::from(self.protects_high_loss_world));
        enc.u8(u8::from(self.grants_effect_authority));
        enc.u8(u8::from(self.claims_occurrence));
        enc.u8(u8::from(self.asserts_current_fact));
        self.plane.encode_canonical(enc);
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, TypedUniverseError> {
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let node_id = dec.text().map_err(map_err)?.to_owned();
        let kind = AgentNodeKind::from_tag(dec.u8().map_err(map_err)?)?;
        let mission_id = dec.text().map_err(map_err)?.to_owned();
        let workspace_id = dec.text().map_err(map_err)?.to_owned();
        let authority_hwm = dec.u64().map_err(map_err)?;
        let cognition_hwm = dec.u64().map_err(map_err)?;
        let claim_target_id = match dec.u8().map_err(map_err)? {
            0 => None,
            1 => Some(dec.text().map_err(map_err)?.to_owned()),
            _ => {
                return Err(TypedUniverseError::MalformedWire(
                    "invalid claim_target_id flag".to_owned(),
                ));
            }
        };
        let mut read_bool = |field: &str| -> Result<bool, TypedUniverseError> {
            match dec.u8().map_err(map_err)? {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(TypedUniverseError::MalformedWire(format!(
                    "invalid {field} bool"
                ))),
            }
        };
        let protects_high_loss_world = read_bool("protects_high_loss_world")?;
        let grants_effect_authority = read_bool("grants_effect_authority")?;
        let claims_occurrence = read_bool("claims_occurrence")?;
        let asserts_current_fact = read_bool("asserts_current_fact")?;
        let plane = match dec.text().map_err(map_err)? {
            "authority" => Plane::Authority,
            "cognition" => Plane::Cognition,
            "effect" => Plane::Effect,
            other => {
                return Err(TypedUniverseError::MalformedWire(format!(
                    "unknown plane '{other}'"
                )));
            }
        };
        let node = Self {
            node_id,
            kind,
            mission_id,
            workspace_id,
            authority_hwm,
            cognition_hwm,
            claim_target_id,
            protects_high_loss_world,
            grants_effect_authority,
            claims_occurrence,
            asserts_current_fact,
            plane,
        };
        node.validate()?;
        Ok(node)
    }
}

/// One typed directed edge in `G_agent`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AgentControlEdge {
    /// Source node ID.
    pub source_id: String,
    /// Target node ID.
    pub target_id: String,
    /// Typed cognitive-control edge kind.
    pub kind: AgentEdgeKind,
}

impl AgentControlEdge {
    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.source_id);
        enc.text(&self.target_id);
        enc.u8(self.kind as u8);
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, TypedUniverseError> {
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let source_id = dec.text().map_err(map_err)?.to_owned();
        let target_id = dec.text().map_err(map_err)?.to_owned();
        let kind = AgentEdgeKind::from_tag(dec.u8().map_err(map_err)?)?;
        validate_clean_label(&source_id, "source_id")?;
        validate_clean_label(&target_id, "target_id")?;
        Ok(Self {
            source_id,
            target_id,
            kind,
        })
    }
}

/// Incremental ordered delta applied to `G_agent`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentGraphDelta {
    /// Upsert a cognitive-control node.
    UpsertNode(Box<AgentControlNode>),
    /// Remove a node and incident edges.
    RemoveNode(String),
    /// Add a typed cognitive-control edge.
    AddEdge(AgentControlEdge),
    /// Remove a typed cognitive-control edge.
    RemoveEdge(AgentControlEdge),
}

/// Certified mission closure, handoff freshness, and resume verification report over `G_agent`.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentHandoffClosureReport {
    /// Mission identifier audited.
    pub mission_id: String,
    /// True iff `orient -> investigate -> plan -> handoff -> resume` closure holds with zero stale
    /// handoffs, zero conflicting claims, zero dropped protected worlds, and zero invalidated plans.
    pub closure_intact: bool,
    /// Persisted obligations accounted for in this mission (zero conversational-only steps!).
    pub persisted_obligations: Vec<String>,
    /// Protected high-loss world nodes preserved into handoff via `WorldSafety` links.
    pub preserved_protected_worlds: Vec<String>,
    /// Protected high-loss world nodes MISSING from handoff (`closure_intact == false`!).
    pub dropped_protected_worlds: Vec<String>,
    /// Handoff nodes whose `authority_hwm < expected_authority_hwm` (stale handoff!).
    pub stale_handoff_ids: Vec<String>,
    /// Conflicting active `WorkClaim` targets (`(target_id, [claim_ids...])`).
    pub conflicting_work_claims: BTreeMap<String, Vec<String>>,
    /// Plans explicitly invalidated by `Invalidates` edges or stale HWM.
    pub invalidated_plan_ids: Vec<String>,
    /// Decision-impact delta nodes added/invalidated since `baseline_authority_hwm`.
    pub decision_impact_delta_ids: Vec<String>,
    /// Always `false`: derived cognitive-control graph NEVER becomes canonical truth or effect authority!
    pub grants_effect_authority: bool,
    /// Certified execution witness.
    pub witness: GraphAlgorithmWitness,
}

/// Anchor-pinned, capability-filtered Agent Mission & Cognitive-Control Graph (`G_agent`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentControlGraph {
    projection_id: String,
    policy_generation: Generation,
    projection: ImmutableGraphProjection,
    visible_nodes: BTreeMap<String, AgentControlNode>,
    visible_edges: BTreeSet<AgentControlEdge>,
    tombstoned_fields: Vec<String>,
    universe_digest: ContentDigest,
}

impl AgentControlGraph {
    /// Builds `G_agent` over `ImmutableGraphProjection` (`GraphUniverse::GAgent`).
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        projection_id: impl Into<String>,
        policy_generation: Generation,
        anchor: LedgerAnchor,
        history_root: ContentDigest,
        authority: &ProjectionAuthorityScope,
        nodes: Vec<AgentControlNode>,
        edges: Vec<AgentControlEdge>,
        requested_absence: AbsenceBoundary,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<Self, TypedUniverseError> {
        if is_cancelled() {
            return Err(TypedUniverseError::Cancelled);
        }
        let projection_id = projection_id.into();
        validate_clean_label(&projection_id, "projection_id")?;
        if policy_generation.0 == 0 {
            return Err(TypedUniverseError::InvalidInput(
                "policy_generation must be >= 1".to_owned(),
            ));
        }
        if nodes.len() > MAX_UNIVERSE_ITEMS || edges.len() > MAX_UNIVERSE_ITEMS * 4 {
            return Err(TypedUniverseError::InvalidInput(
                "G_agent size exceeds hard ceiling".to_owned(),
            ));
        }

        let mut raw_nodes: BTreeMap<String, AgentControlNode> = BTreeMap::new();
        for node in nodes {
            if is_cancelled() {
                return Err(TypedUniverseError::Cancelled);
            }
            node.validate()?;
            if raw_nodes.contains_key(&node.node_id) {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "duplicate G_agent node_id '{}'",
                    node.node_id
                )));
            }
            raw_nodes.insert(node.node_id.clone(), node);
        }

        let mut raw_edges: BTreeSet<AgentControlEdge> = BTreeSet::new();
        for edge in edges {
            validate_clean_label(&edge.source_id, "source_id")?;
            validate_clean_label(&edge.target_id, "target_id")?;
            if !raw_nodes.contains_key(&edge.source_id) || !raw_nodes.contains_key(&edge.target_id)
            {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "unknown G_agent edge endpoint '{}' -> '{}'",
                    edge.source_id, edge.target_id
                )));
            }
            raw_edges.insert(edge);
        }

        let proj_nodes: Vec<ProjectionNodeSpec> = raw_nodes
            .values()
            .map(|n| ProjectionNodeSpec {
                node_id: n.node_id.clone(),
                plane: n.plane,
                payload_digest: n.node_digest(),
            })
            .collect();
        let proj_edges: Vec<ProjectionEdgeSpec> = raw_edges
            .iter()
            .map(|e| ProjectionEdgeSpec {
                source_id: e.source_id.clone(),
                target_id: e.target_id.clone(),
                relation: e.kind.as_str().to_owned(),
                weight: u64::from(e.kind as u8),
            })
            .collect();

        let projection = ImmutableGraphProjection::build(
            GraphUniverse::GAgent,
            ProjectionOrientation::Directed,
            anchor,
            history_root,
            authority,
            proj_nodes,
            proj_edges,
            requested_absence,
            is_cancelled(),
        )?;

        let visible_nodes: BTreeMap<String, AgentControlNode> = raw_nodes
            .into_iter()
            .filter(|(id, _)| projection.handle_for_node_id(id).is_some())
            .collect();
        let visible_edges: BTreeSet<AgentControlEdge> = raw_edges
            .into_iter()
            .filter(|e| {
                visible_nodes.contains_key(&e.source_id) && visible_nodes.contains_key(&e.target_id)
            })
            .collect();

        let universe_digest = Self::compute_digest(
            &projection_id,
            policy_generation,
            &projection,
            &visible_nodes,
            &visible_edges,
        );
        Ok(Self {
            projection_id,
            policy_generation,
            projection,
            visible_nodes,
            visible_edges,
            tombstoned_fields: Vec::new(),
            universe_digest,
        })
    }

    /// Incrementally applies ordered `AgentGraphDelta` updates with full-rebuild parity.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_deltas(
        &self,
        new_anchor: LedgerAnchor,
        new_history_root: ContentDigest,
        expected_policy_generation: Generation,
        authority: &ProjectionAuthorityScope,
        deltas: &[AgentGraphDelta],
        requested_absence: AbsenceBoundary,
        is_cancelled: impl FnMut() -> bool,
    ) -> Result<Self, TypedUniverseError> {
        if expected_policy_generation != self.policy_generation {
            return Err(TypedUniverseError::MixedAnchorOrGeneration(
                "policy generation mismatch".to_owned(),
            ));
        }
        if new_anchor.site_lineage != self.projection.anchor().site_lineage
            || new_anchor.commit_sequence < self.projection.anchor().commit_sequence
        {
            return Err(TypedUniverseError::MixedAnchorOrGeneration(
                "delta anchor must remain on same site_lineage with monotonic sequence".to_owned(),
            ));
        }
        let mut nodes = self.visible_nodes.clone();
        let mut edges = self.visible_edges.clone();
        for delta in deltas {
            match delta {
                AgentGraphDelta::UpsertNode(n) => {
                    n.validate()?;
                    nodes.insert(n.node_id.clone(), (**n).clone());
                }
                AgentGraphDelta::RemoveNode(id) => {
                    nodes.remove(id);
                    edges.retain(|e| e.source_id != *id && e.target_id != *id);
                }
                AgentGraphDelta::AddEdge(e) => {
                    edges.insert(e.clone());
                }
                AgentGraphDelta::RemoveEdge(e) => {
                    edges.remove(e);
                }
            }
        }
        Self::build(
            self.projection_id.clone(),
            self.policy_generation,
            new_anchor,
            new_history_root,
            authority,
            nodes.into_values().collect(),
            edges.into_iter().collect(),
            requested_absence,
            is_cancelled,
        )
    }

    /// Underlying capability-filtered `ImmutableGraphProjection`.
    #[must_use]
    pub const fn projection(&self) -> &ImmutableGraphProjection {
        &self.projection
    }

    /// Canonical digest of this `G_agent` universe.
    #[must_use]
    pub const fn universe_digest(&self) -> ContentDigest {
        self.universe_digest
    }

    /// Derived `G_agent` projection NEVER grants effect authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Verifies mission/obligation closure across `orient -> investigate -> plan -> handoff -> resume`,
    /// detecting stale handoffs, conflicting work claims, dropped protected worlds, invalidated
    /// plans, and decision-impact deltas since `baseline_authority_hwm`.
    pub fn verify_handoff_closure(
        &self,
        mission_id: &str,
        expected_authority_hwm: u64,
        baseline_authority_hwm: u64,
        max_operations: u64,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<AgentHandoffClosureReport, TypedUniverseError> {
        validate_clean_label(mission_id, "mission_id")?;
        let mut budget = OpBudget::new(max_operations)?;

        let mut superseded: BTreeSet<&str> = BTreeSet::new();
        let mut explicitly_invalidated: BTreeSet<&str> = BTreeSet::new();
        let mut handoff_world_safety: BTreeSet<&str> = BTreeSet::new();
        let mut resumed_handoffs: BTreeSet<&str> = BTreeSet::new();

        for edge in &self.visible_edges {
            budget.charge(1, &mut is_cancelled)?;
            if edge.kind == AgentEdgeKind::Supersedes {
                superseded.insert(edge.target_id.as_str());
            }
        }

        for edge in &self.visible_edges {
            budget.charge(1, &mut is_cancelled)?;
            let (Some(src), Some(dst)) = (
                self.visible_nodes.get(&edge.source_id),
                self.visible_nodes.get(&edge.target_id),
            ) else {
                continue;
            };
            if src.mission_id != mission_id || dst.mission_id != mission_id {
                continue;
            }
            if superseded.contains(src.node_id.as_str())
                || superseded.contains(dst.node_id.as_str())
            {
                continue;
            }
            match edge.kind {
                AgentEdgeKind::Invalidates => {
                    explicitly_invalidated.insert(edge.target_id.as_str());
                }
                AgentEdgeKind::WorldSafety => {
                    if src.kind == AgentNodeKind::Handoff {
                        handoff_world_safety.insert(edge.target_id.as_str());
                    }
                    if dst.kind == AgentNodeKind::Handoff {
                        handoff_world_safety.insert(edge.source_id.as_str());
                    }
                }
                AgentEdgeKind::Resumes if dst.kind == AgentNodeKind::Handoff => {
                    resumed_handoffs.insert(edge.target_id.as_str());
                }
                _ => {}
            }
        }

        let mut persisted_obligations = Vec::new();
        let mut preserved_protected_worlds = Vec::new();
        let mut dropped_protected_worlds = Vec::new();
        let mut stale_handoff_ids = Vec::new();
        let mut invalidated_plan_ids = Vec::new();
        let mut decision_impact_delta_ids = Vec::new();
        let mut claims_by_target: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut saw_mission = false;
        let mut saw_workspace = false;

        for node in self.visible_nodes.values() {
            budget.charge(1, &mut is_cancelled)?;
            if node.mission_id != mission_id || superseded.contains(node.node_id.as_str()) {
                continue;
            }
            if node.authority_hwm > baseline_authority_hwm
                || explicitly_invalidated.contains(node.node_id.as_str())
            {
                decision_impact_delta_ids.push(node.node_id.clone());
            }
            match node.kind {
                AgentNodeKind::MissionRevision => saw_mission = true,
                AgentNodeKind::SessionWorkspace => saw_workspace = true,
                AgentNodeKind::Obligation => persisted_obligations.push(node.node_id.clone()),
                AgentNodeKind::Handoff => {
                    if node.authority_hwm < expected_authority_hwm {
                        stale_handoff_ids.push(node.node_id.clone());
                    }
                }
                AgentNodeKind::Plan => {
                    if explicitly_invalidated.contains(node.node_id.as_str())
                        || node.authority_hwm < expected_authority_hwm
                    {
                        invalidated_plan_ids.push(node.node_id.clone());
                    }
                }
                AgentNodeKind::WorkClaim => {
                    if let Some(ref target) = node.claim_target_id {
                        claims_by_target
                            .entry(target.clone())
                            .or_default()
                            .push(node.node_id.clone());
                    }
                }
                _ => {}
            }
            if node.protects_high_loss_world {
                if handoff_world_safety.contains(node.node_id.as_str()) {
                    preserved_protected_worlds.push(node.node_id.clone());
                } else {
                    dropped_protected_worlds.push(node.node_id.clone());
                }
            }
        }

        let conflicting_work_claims: BTreeMap<String, Vec<String>> = claims_by_target
            .into_iter()
            .filter(|(_, claims)| claims.len() > 1)
            .collect();

        let closure_intact = saw_mission
            && saw_workspace
            && stale_handoff_ids.is_empty()
            && conflicting_work_claims.is_empty()
            && dropped_protected_worlds.is_empty()
            && invalidated_plan_ids.is_empty()
            && !resumed_handoffs.is_empty();

        let mut path_enc = CanonicalEncoder::new();
        path_enc.text(mission_id);
        path_enc.u8(u8::from(closure_intact));
        path_enc.u64(stale_handoff_ids.len() as u64);
        path_enc.u64(conflicting_work_claims.len() as u64);
        path_enc.u64(dropped_protected_worlds.len() as u64);
        let decision_path_digest = hash_domain_tag(G_AGENT_DIGEST_DOMAIN, 2, &path_enc.finish());
        let mut out_enc = CanonicalEncoder::new();
        out_enc.digest(self.universe_digest);
        out_enc.digest(decision_path_digest);
        out_enc.u64(persisted_obligations.len() as u64);
        let output_digest = hash_domain_tag(G_AGENT_DIGEST_DOMAIN, 3, &out_enc.finish());

        let witness = build_universe_witness(
            G_AGENT_ALGORITHM_ID,
            G_AGENT_IMPLEMENTATION_ID,
            GraphUniverse::GAgent,
            &self.projection_id,
            self.projection.anchor(),
            self.projection.node_count(),
            self.projection.edge_count(),
            self.universe_digest,
            G_AGENT_POLICY_ID,
            budget.used(),
            ((self.visible_nodes.len() + self.visible_edges.len() + 1) * 192) as u64,
            decision_path_digest,
            output_digest,
        )?;

        Ok(AgentHandoffClosureReport {
            mission_id: mission_id.to_owned(),
            closure_intact,
            persisted_obligations,
            preserved_protected_worlds,
            dropped_protected_worlds,
            stale_handoff_ids,
            conflicting_work_claims,
            invalidated_plan_ids,
            decision_impact_delta_ids,
            grants_effect_authority: false,
            witness,
        })
    }

    /// Serializes `G_agent` into its versioned checksummed wire format (`v2`).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(CURRENT_UNIVERSE_WIRE_VERSION, false)
    }

    /// Serializes a compatible legacy `v1` fixture carrying a removed `legacy_chat_only_steps` flag.
    pub fn to_legacy_v1_fixture_bytes(
        &self,
        legacy_chat_only_steps: bool,
    ) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(LEGACY_UNIVERSE_WIRE_VERSION, legacy_chat_only_steps)
    }

    fn encode_versioned(
        &self,
        version: u32,
        legacy_chat_only_steps: bool,
    ) -> Result<Vec<u8>, TypedUniverseError> {
        let proj_bytes = self.projection.to_canonical_bytes()?;
        let mut enc = CanonicalEncoder::new();
        enc.text(&self.projection_id);
        enc.u64(self.policy_generation.0);
        enc.bytes(&proj_bytes);
        enc.u64(self.visible_nodes.len() as u64);
        for node in self.visible_nodes.values() {
            node.encode_body(&mut enc);
        }
        enc.u64(self.visible_edges.len() as u64);
        for edge in &self.visible_edges {
            edge.encode_body(&mut enc);
        }
        if version == LEGACY_UNIVERSE_WIRE_VERSION {
            enc.u8(u8::from(legacy_chat_only_steps));
        } else {
            enc.u64(self.tombstoned_fields.len() as u64);
            for t in &self.tombstoned_fields {
                enc.text(t);
            }
        }
        let payload = enc
            .finish_checked()
            .map_err(|e| TypedUniverseError::MalformedWire(e.to_string()))?;
        seal_wire_envelope(G_AGENT_WIRE_MAGIC, version, G_AGENT_DIGEST_DOMAIN, &payload)
    }

    /// Opens a `v1` (migrating deterministically with tombstones) or `v2` durable `G_agent` fixture.
    pub fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<(Self, UniverseMigrationReport), TypedUniverseError> {
        let (version, payload) =
            open_wire_envelope(bytes, G_AGENT_WIRE_MAGIC, G_AGENT_DIGEST_DOMAIN)?;
        let mut dec = CanonicalDecoder::new(payload);
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let projection_id = dec.text().map_err(map_err)?.to_owned();
        validate_clean_label(&projection_id, "projection_id")?;
        let policy_generation = Generation(dec.u64().map_err(map_err)?);
        if policy_generation.0 == 0 {
            return Err(TypedUniverseError::MalformedWire(
                "zero policy_generation".to_owned(),
            ));
        }
        let proj_bytes = dec.bytes().map_err(map_err)?;
        let projection = ImmutableGraphProjection::from_canonical_bytes(proj_bytes)?;
        if projection.universe() != GraphUniverse::GAgent {
            return Err(TypedUniverseError::MalformedWire(
                "embedded projection universe is not G_agent".to_owned(),
            ));
        }
        let n_len = usize::try_from(dec.u64().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("node count overflow".to_owned()))?;
        if n_len > MAX_UNIVERSE_ITEMS || n_len.saturating_mul(24) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "node count out of wire bounds".to_owned(),
            ));
        }
        let mut visible_nodes = BTreeMap::new();
        for _ in 0..n_len {
            let node = AgentControlNode::decode_body(&mut dec)?;
            if visible_nodes.contains_key(&node.node_id) {
                return Err(TypedUniverseError::MalformedWire(
                    "duplicate G_agent node_id".to_owned(),
                ));
            }
            let Some(handle) = projection.handle_for_node_id(&node.node_id) else {
                return Err(TypedUniverseError::MalformedWire(
                    "wire G_agent node missing from embedded projection".to_owned(),
                ));
            };
            if projection.node(handle)?.payload_digest != node.node_digest() {
                return Err(TypedUniverseError::MalformedWire(
                    "wire G_agent node digest disagrees with embedded projection".to_owned(),
                ));
            }
            visible_nodes.insert(node.node_id.clone(), node);
        }
        let e_len = usize::try_from(dec.u64().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("edge count overflow".to_owned()))?;
        if e_len > MAX_UNIVERSE_ITEMS * 4 || e_len.saturating_mul(9) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "edge count out of wire bounds".to_owned(),
            ));
        }
        let mut visible_edges = BTreeSet::new();
        for _ in 0..e_len {
            let edge = AgentControlEdge::decode_body(&mut dec)?;
            if !visible_nodes.contains_key(&edge.source_id)
                || !visible_nodes.contains_key(&edge.target_id)
            {
                return Err(TypedUniverseError::MalformedWire(
                    "wire G_agent edge references unknown node".to_owned(),
                ));
            }
            visible_edges.insert(edge);
        }
        let (migrated, tombstoned_fields) = if version == LEGACY_UNIVERSE_WIRE_VERSION {
            let _deprecated_flag = dec.u8().map_err(map_err)?;
            (
                true,
                vec![
                    "v1.legacy_chat_only_steps:tombstoned_persisted_typed_obligations_required"
                        .to_owned(),
                ],
            )
        } else {
            let t_len = usize::try_from(dec.u64().map_err(map_err)?).map_err(|_| {
                TypedUniverseError::MalformedWire("tombstone count overflow".to_owned())
            })?;
            if t_len > 32 || t_len.saturating_mul(4) > dec.remaining() {
                return Err(TypedUniverseError::MalformedWire(
                    "tombstone count exceeds bounds".to_owned(),
                ));
            }
            let mut tombs = Vec::with_capacity(t_len);
            for _ in 0..t_len {
                let t = dec.text().map_err(map_err)?.to_owned();
                validate_clean_label(&t, "tombstone")?;
                tombs.push(t);
            }
            (false, tombs)
        };
        dec.ensure_finished().map_err(map_err)?;

        let universe_digest = Self::compute_digest(
            &projection_id,
            policy_generation,
            &projection,
            &visible_nodes,
            &visible_edges,
        );
        let report = UniverseMigrationReport {
            source_version: version,
            target_version: CURRENT_UNIVERSE_WIRE_VERSION,
            migrated,
            tombstoned_fields: tombstoned_fields.clone(),
            universe_digest,
        };
        Ok((
            Self {
                projection_id,
                policy_generation,
                projection,
                visible_nodes,
                visible_edges,
                tombstoned_fields,
                universe_digest,
            },
            report,
        ))
    }

    fn compute_digest(
        projection_id: &str,
        policy_generation: Generation,
        projection: &ImmutableGraphProjection,
        visible_nodes: &BTreeMap<String, AgentControlNode>,
        visible_edges: &BTreeSet<AgentControlEdge>,
    ) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text(projection_id);
        enc.u64(policy_generation.0);
        enc.digest(projection.generation().projection_digest);
        enc.u64(visible_nodes.len() as u64);
        for node in visible_nodes.values() {
            enc.digest(node.node_digest());
        }
        enc.u64(visible_edges.len() as u64);
        for edge in visible_edges {
            edge.encode_body(&mut enc);
        }
        hash_domain_tag(G_AGENT_DIGEST_DOMAIN, 0, &enc.finish())
    }
}
