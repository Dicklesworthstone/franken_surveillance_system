#![forbid(unsafe_code)]
//! Causal evidence graph `G_evidence` (`PROJ-EVIDENCE-001`, `fss-x4a.23.69.6`).
//!
//! Represents source capsules, decoded windows, detections, tracks, geometry facts, model
//! receipts, hypothesis revisions, policy decisions, alert intents, provider receipts, operator
//! adjudications, and memories. Typed edges are strictly `derived-from`, `supports`,
//! `contradicts`, `invalidates`, `supersedes`, `observed-after`, `required-by`, and `explains`.
//!
//! Core guarantees:
//! - Knowledge state, provenance class, hypothesis disposition, and effect outcome remain
//!   orthogonal typed fields (never collapsed!);
//! - Append-only history: `Supersedes` retains superseded revisions; `Invalidates` propagates
//!   deterministically without deleting history;
//! - Recomputes alert explanations from the graph, computes minimal source explanations, shared
//!   derivation dominators, deletion reachability, and counterfactual removal proving exactly
//!   which supporting node or invalidator would flip a decision.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fss_core::{
    CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest, Generation,
    GraphAlgorithmWitness, LedgerAnchor, Plane,
};

use crate::projection::{
    AbsenceBoundary, GraphUniverse, ImmutableGraphProjection, ProjectionAuthorityScope,
    ProjectionEdgeSpec, ProjectionNodeSpec, ProjectionOrientation,
};

use super::g_world::{WorldHypothesisDisposition, WorldKnowledgeState, WorldProvenanceClass};
use super::{
    CURRENT_UNIVERSE_WIRE_VERSION, LEGACY_UNIVERSE_WIRE_VERSION, MAX_UNIVERSE_ITEMS, OpBudget,
    TypedUniverseError, UniverseMigrationReport, build_universe_witness, hash_domain_tag,
    open_wire_envelope, seal_wire_envelope, validate_clean_label,
};

/// Registered digest domain for `G_evidence` projections and witnesses
/// (`SCHEMA-DOMAIN-GRAPH-G-EVIDENCE-001`).
pub const G_EVIDENCE_DIGEST_DOMAIN: &str = "fss.graph.g_evidence_projection.v1";
/// Wire magic for durable `G_evidence` fixtures (`FSSGEV01`).
pub const G_EVIDENCE_WIRE_MAGIC: [u8; 8] = *b"FSSGEV01";
/// Registered algorithm ID emitted in `G_evidence` witnesses.
pub const G_EVIDENCE_ALGORITHM_ID: &str = "ALG-PROJ-EVIDENCE-001";
/// Implementation generation recorded in `G_evidence` witnesses.
pub const G_EVIDENCE_IMPLEMENTATION_ID: &str =
    "fss-graph-algorithms:proj-evidence-001:g-evidence-oracle:v2";
/// Policy identity recorded in `G_evidence` witnesses.
pub const G_EVIDENCE_POLICY_ID: &str =
    "graph-policy:g-evidence:append-only-supersession:counterfactual-explanation:v2";

/// Closed taxonomy of node kinds in `G_evidence`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EvidenceGraphNodeKind {
    /// Immutable source sensor capsule.
    SourceCapsule = 1,
    /// Decoded frame/audio window.
    DecodedWindow = 2,
    /// Model detection record.
    Detection = 3,
    /// Anonymous tracklet/track.
    Track = 4,
    /// Calibrated geometry/zone observation.
    GeometryFact = 5,
    /// Sealed model execution receipt.
    ModelReceipt = 6,
    /// Event hypothesis revision.
    HypothesisRevision = 7,
    /// Policy/decision card evaluation.
    PolicyDecision = 8,
    /// Prepared alert intent.
    AlertIntent = 9,
    /// External provider delivery receipt.
    ProviderReceipt = 10,
    /// Human operator adjudication.
    OperatorAdjudication = 11,
    /// Operational memory citation.
    Memory = 12,
}

impl EvidenceGraphNodeKind {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::SourceCapsule),
            2 => Ok(Self::DecodedWindow),
            3 => Ok(Self::Detection),
            4 => Ok(Self::Track),
            5 => Ok(Self::GeometryFact),
            6 => Ok(Self::ModelReceipt),
            7 => Ok(Self::HypothesisRevision),
            8 => Ok(Self::PolicyDecision),
            9 => Ok(Self::AlertIntent),
            10 => Ok(Self::ProviderReceipt),
            11 => Ok(Self::OperatorAdjudication),
            12 => Ok(Self::Memory),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown EvidenceGraphNodeKind tag {other}"
            ))),
        }
    }
}

/// Orthogonal effect outcome state (strictly separate from knowledge/provenance/disposition!).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EvidenceEffectOutcome {
    /// Not an effect node.
    NotAnEffect = 0,
    /// Prepared, not dispatched.
    Prepared = 1,
    /// Dispatched, awaiting observation.
    Dispatched = 2,
    /// Observed externally.
    Observed = 3,
    /// Verified terminal completion.
    Verified = 4,
    /// Ambiguous/indeterminate outcome.
    Indeterminate = 5,
    /// Failed/rejected effect.
    Failed = 6,
}

impl EvidenceEffectOutcome {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            0 => Ok(Self::NotAnEffect),
            1 => Ok(Self::Prepared),
            2 => Ok(Self::Dispatched),
            3 => Ok(Self::Observed),
            4 => Ok(Self::Verified),
            5 => Ok(Self::Indeterminate),
            6 => Ok(Self::Failed),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown EvidenceEffectOutcome tag {other}"
            ))),
        }
    }
}

/// Exact 8 typed directed edges in `G_evidence`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EvidenceEdgeKind {
    /// `child` was derived from `parent`.
    DerivedFrom = 1,
    /// `evidence` supports `hypothesis/decision`.
    Supports = 2,
    /// `evidence` contradicts `hypothesis/decision`.
    Contradicts = 3,
    /// `invalidator` invalidates `target` without deleting history.
    Invalidates = 4,
    /// `newer_rev` supersedes `older_rev` while retaining older history.
    Supersedes = 5,
    /// Temporal causal precedence (`later` observed after `earlier`).
    ObservedAfter = 6,
    /// Hard prerequisite (`premise` required-by `decision`).
    RequiredBy = 7,
    /// Explanation link (`evidence` explains `decision`).
    Explains = 8,
}

impl EvidenceEdgeKind {
    /// Stable canonical relation name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DerivedFrom => "derived-from",
            Self::Supports => "supports",
            Self::Contradicts => "contradicts",
            Self::Invalidates => "invalidates",
            Self::Supersedes => "supersedes",
            Self::ObservedAfter => "observed-after",
            Self::RequiredBy => "required-by",
            Self::Explains => "explains",
        }
    }

    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::DerivedFrom),
            2 => Ok(Self::Supports),
            3 => Ok(Self::Contradicts),
            4 => Ok(Self::Invalidates),
            5 => Ok(Self::Supersedes),
            6 => Ok(Self::ObservedAfter),
            7 => Ok(Self::RequiredBy),
            8 => Ok(Self::Explains),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown EvidenceEdgeKind tag {other}"
            ))),
        }
    }
}

/// One typed node in `G_evidence` keeping all 4 epistemic/effect axes strictly orthogonal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceGraphNode {
    /// Stable unique node ID.
    pub node_id: String,
    /// Typed evidence artifact kind.
    pub kind: EvidenceGraphNodeKind,
    /// Orthogonal knowledge state.
    pub knowledge_state: WorldKnowledgeState,
    /// Orthogonal provenance class.
    pub provenance_class: WorldProvenanceClass,
    /// Orthogonal hypothesis disposition.
    pub disposition: WorldHypothesisDisposition,
    /// Orthogonal effect outcome.
    pub effect_outcome: EvidenceEffectOutcome,
    /// Pinned model or calibration generation (`>= 1`).
    pub artifact_generation: Generation,
    /// Owning semantic plane.
    pub plane: Plane,
}

impl EvidenceGraphNode {
    /// Validates node invariants fail-closed.
    pub fn validate(&self) -> Result<(), TypedUniverseError> {
        validate_clean_label(&self.node_id, "node_id")?;
        if self.artifact_generation.0 == 0 {
            return Err(TypedUniverseError::InvalidInput(format!(
                "zero artifact_generation on '{}'",
                self.node_id
            )));
        }
        Ok(())
    }

    /// Canonical SHA-256 commitment for this evidence node.
    #[must_use]
    pub fn node_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        hash_domain_tag(G_EVIDENCE_DIGEST_DOMAIN, 1, &enc.finish())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.node_id);
        enc.u8(self.kind as u8);
        enc.u8(self.knowledge_state as u8);
        enc.u8(self.provenance_class as u8);
        enc.u8(self.disposition as u8);
        enc.u8(self.effect_outcome as u8);
        enc.u64(self.artifact_generation.0);
        self.plane.encode_canonical(enc);
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, TypedUniverseError> {
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let node_id = dec.text().map_err(map_err)?.to_owned();
        let kind = EvidenceGraphNodeKind::from_tag(dec.u8().map_err(map_err)?)?;
        let knowledge_state = match dec.u8().map_err(map_err)? {
            1 => WorldKnowledgeState::Certified,
            2 => WorldKnowledgeState::Observed,
            3 => WorldKnowledgeState::Hypothesized,
            4 => WorldKnowledgeState::Unknown,
            5 => WorldKnowledgeState::Conflicted,
            6 => WorldKnowledgeState::Stale,
            other => {
                return Err(TypedUniverseError::MalformedWire(format!(
                    "unknown knowledge_state tag {other}"
                )));
            }
        };
        let provenance_class = match dec.u8().map_err(map_err)? {
            1 => WorldProvenanceClass::SourceRetained,
            2 => WorldProvenanceClass::DerivedCognition,
            3 => WorldProvenanceClass::OperatorAsserted,
            4 => WorldProvenanceClass::ExternalUnverified,
            other => {
                return Err(TypedUniverseError::MalformedWire(format!(
                    "unknown provenance_class tag {other}"
                )));
            }
        };
        let disposition = match dec.u8().map_err(map_err)? {
            1 => WorldHypothesisDisposition::Supported,
            2 => WorldHypothesisDisposition::ActiveAlternative,
            3 => WorldHypothesisDisposition::Refuted,
            4 => WorldHypothesisDisposition::ProtectedHighLoss,
            other => {
                return Err(TypedUniverseError::MalformedWire(format!(
                    "unknown disposition tag {other}"
                )));
            }
        };
        let effect_outcome = EvidenceEffectOutcome::from_tag(dec.u8().map_err(map_err)?)?;
        let artifact_generation = Generation(dec.u64().map_err(map_err)?);
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
            knowledge_state,
            provenance_class,
            disposition,
            effect_outcome,
            artifact_generation,
            plane,
        };
        node.validate()?;
        Ok(node)
    }
}

/// One typed directed causal edge in `G_evidence`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EvidenceGraphEdge {
    /// Source node ID.
    pub source_id: String,
    /// Target node ID.
    pub target_id: String,
    /// Typed causal relation.
    pub kind: EvidenceEdgeKind,
}

impl EvidenceGraphEdge {
    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.source_id);
        enc.text(&self.target_id);
        enc.u8(self.kind as u8);
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, TypedUniverseError> {
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let source_id = dec.text().map_err(map_err)?.to_owned();
        let target_id = dec.text().map_err(map_err)?.to_owned();
        let kind = EvidenceEdgeKind::from_tag(dec.u8().map_err(map_err)?)?;
        validate_clean_label(&source_id, "source_id")?;
        validate_clean_label(&target_id, "target_id")?;
        Ok(Self {
            source_id,
            target_id,
            kind,
        })
    }
}

/// Append-only incremental delta for `G_evidence` (history is superseded/invalidated, never erased!).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceGraphDelta {
    /// Append a new evidence node (never deletes prior revisions!).
    AppendNode(EvidenceGraphNode),
    /// Append a new causal edge (`Supersedes`, `Invalidates`, `Supports`, `Contradicts`, etc.).
    AppendEdge(EvidenceGraphEdge),
}

/// Certified recomputed explanation & counterfactual sensitivity report for one decision node.
#[derive(Clone, Debug, PartialEq)]
pub struct CausalExplanationReport {
    /// Explained decision/alert/hypothesis node ID.
    pub target_decision_id: String,
    /// Whether the target decision remains supported (`>= 1` active un-invalidated support and zero active contradictions).
    pub decision_currently_supported: bool,
    /// Active (non-superseded, non-invalidated) supporting nodes.
    pub active_supporting_nodes: Vec<String>,
    /// Retained superseded historical revisions (preserved append-only!).
    pub superseded_history_nodes: Vec<String>,
    /// Nodes transitively invalidated via `Invalidates` + `DerivedFrom`/`Supports` propagation.
    pub invalidated_nodes: Vec<String>,
    /// Active contradicting evidence nodes targeting this decision.
    pub active_contradictions: Vec<String>,
    /// Minimal foundational `SourceCapsule` roots supporting this decision.
    pub minimal_source_roots: Vec<String>,
    /// Shared derivation dominators: removing ANY single node in this set breaks ALL active support paths!
    pub counterfactual_decision_flippers: Vec<String>,
    /// Full downstream deletion-reachability closure if any source root were deleted.
    pub deletion_impact_nodes: Vec<String>,
    /// Always `false`: explanation analysis never authorizes an effect.
    pub grants_effect_authority: bool,
    /// Certified execution witness.
    pub witness: GraphAlgorithmWitness,
}

/// Anchor-pinned, append-only Causal Evidence Graph (`G_evidence`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CausalEvidenceGraph {
    projection_id: String,
    policy_generation: Generation,
    projection: ImmutableGraphProjection,
    visible_nodes: BTreeMap<String, EvidenceGraphNode>,
    visible_edges: BTreeSet<EvidenceGraphEdge>,
    tombstoned_fields: Vec<String>,
    universe_digest: ContentDigest,
}

impl CausalEvidenceGraph {
    /// Builds `G_evidence` over `ImmutableGraphProjection` (`GraphUniverse::GEvidence`).
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        projection_id: impl Into<String>,
        policy_generation: Generation,
        anchor: LedgerAnchor,
        history_root: ContentDigest,
        authority: &ProjectionAuthorityScope,
        nodes: Vec<EvidenceGraphNode>,
        edges: Vec<EvidenceGraphEdge>,
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
                "G_evidence size exceeds hard ceiling".to_owned(),
            ));
        }

        let mut raw_nodes: BTreeMap<String, EvidenceGraphNode> = BTreeMap::new();
        for node in nodes {
            if is_cancelled() {
                return Err(TypedUniverseError::Cancelled);
            }
            node.validate()?;
            if raw_nodes.contains_key(&node.node_id) {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "duplicate G_evidence node_id '{}'",
                    node.node_id
                )));
            }
            raw_nodes.insert(node.node_id.clone(), node);
        }

        let mut raw_edges: BTreeSet<EvidenceGraphEdge> = BTreeSet::new();
        for edge in edges {
            validate_clean_label(&edge.source_id, "source_id")?;
            validate_clean_label(&edge.target_id, "target_id")?;
            if !raw_nodes.contains_key(&edge.source_id) || !raw_nodes.contains_key(&edge.target_id)
            {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "unknown G_evidence edge endpoint '{}' -> '{}'",
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
            GraphUniverse::GEvidence,
            ProjectionOrientation::Directed,
            anchor,
            history_root,
            authority,
            proj_nodes,
            proj_edges,
            requested_absence,
            is_cancelled(),
        )?;

        let visible_nodes: BTreeMap<String, EvidenceGraphNode> = raw_nodes
            .into_iter()
            .filter(|(id, _)| projection.handle_for_node_id(id).is_some())
            .collect();
        let visible_edges: BTreeSet<EvidenceGraphEdge> = raw_edges
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

    /// Incrementally appends ordered deltas (append-only: prior evidence is never deleted!) with
    /// exact full-rebuild parity.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_deltas(
        &self,
        new_anchor: LedgerAnchor,
        new_history_root: ContentDigest,
        expected_policy_generation: Generation,
        authority: &ProjectionAuthorityScope,
        deltas: &[EvidenceGraphDelta],
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
                EvidenceGraphDelta::AppendNode(n) => {
                    n.validate()?;
                    if nodes.contains_key(&n.node_id) {
                        return Err(TypedUniverseError::InvalidInput(format!(
                            "append-only G_evidence forbids mutating existing node '{}'; use Supersedes",
                            n.node_id
                        )));
                    }
                    nodes.insert(n.node_id.clone(), n.clone());
                }
                EvidenceGraphDelta::AppendEdge(e) => {
                    edges.insert(e.clone());
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

    /// Canonical digest of this `G_evidence` universe.
    #[must_use]
    pub const fn universe_digest(&self) -> ContentDigest {
        self.universe_digest
    }

    /// Derived causal evidence graph NEVER grants effect authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Recomputes an active explanation for `target_decision_id`, propagates invalidations without
    /// deleting history, extracts minimal source roots, and identifies counterfactual single-node
    /// removals that would flip the decision!
    pub fn explain_decision_and_counterfactuals(
        &self,
        target_decision_id: &str,
        stale_generation: Option<Generation>,
        max_operations: u64,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<CausalExplanationReport, TypedUniverseError> {
        validate_clean_label(target_decision_id, "target_decision_id")?;
        let mut budget = OpBudget::new(max_operations)?;
        if !self.visible_nodes.contains_key(target_decision_id) {
            return Err(TypedUniverseError::InvalidInput(format!(
                "decision node '{target_decision_id}' not present in projection"
            )));
        }

        // 1. Identify superseded nodes (`a Supersedes b` => `b` is superseded history) and seed
        //    invalidated nodes (`a Invalidates b` OR node has `stale_generation`).
        let mut superseded_set: BTreeSet<&str> = BTreeSet::new();
        let mut invalidated_set: BTreeSet<&str> = BTreeSet::new();
        let mut derived_children: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        let mut support_parents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        let mut direct_contradictions: BTreeSet<&str> = BTreeSet::new();

        for node in self.visible_nodes.values() {
            budget.charge(1, &mut is_cancelled)?;
            if stale_generation.is_some_and(|sg| node.artifact_generation == sg)
                || node.knowledge_state == WorldKnowledgeState::Stale
            {
                invalidated_set.insert(node.node_id.as_str());
            }
        }
        for edge in &self.visible_edges {
            budget.charge(1, &mut is_cancelled)?;
            match edge.kind {
                EvidenceEdgeKind::Supersedes => {
                    superseded_set.insert(edge.target_id.as_str());
                }
                EvidenceEdgeKind::Invalidates => {
                    invalidated_set.insert(edge.target_id.as_str());
                }
                EvidenceEdgeKind::DerivedFrom => {
                    // `source` derived-from `target` => invalidating/deleting `target` propagates to `source`!
                    derived_children
                        .entry(edge.target_id.as_str())
                        .or_default()
                        .push(edge.source_id.as_str());
                    support_parents
                        .entry(edge.source_id.as_str())
                        .or_default()
                        .push(edge.target_id.as_str());
                }
                EvidenceEdgeKind::Supports
                | EvidenceEdgeKind::RequiredBy
                | EvidenceEdgeKind::Explains => {
                    // `source` supports/explains `target`
                    support_parents
                        .entry(edge.target_id.as_str())
                        .or_default()
                        .push(edge.source_id.as_str());
                    derived_children
                        .entry(edge.source_id.as_str())
                        .or_default()
                        .push(edge.target_id.as_str());
                }
                EvidenceEdgeKind::Contradicts => {
                    if edge.target_id == target_decision_id {
                        direct_contradictions.insert(edge.source_id.as_str());
                    }
                }
                EvidenceEdgeKind::ObservedAfter => {}
            }
        }

        // Propagate invalidation transitively along DerivedFrom/Supports without deleting history!
        let mut inv_q: VecDeque<&str> = invalidated_set.iter().copied().collect();
        while let Some(u) = inv_q.pop_front() {
            budget.charge(1, &mut is_cancelled)?;
            if let Some(children) = derived_children.get(u) {
                for &c in children {
                    if invalidated_set.insert(c) {
                        inv_q.push_back(c);
                    }
                }
            }
        }

        // Collect active support subgraph backward from `target_decision_id`.
        let mut active_support: BTreeSet<&str> = BTreeSet::new();
        let mut minimal_roots: BTreeSet<&str> = BTreeSet::new();
        let mut back_q: VecDeque<&str> = VecDeque::new();
        back_q.push_back(target_decision_id);
        let mut back_seen: BTreeSet<&str> = BTreeSet::new();
        back_seen.insert(target_decision_id);
        while let Some(u) = back_q.pop_front() {
            budget.charge(1, &mut is_cancelled)?;
            if let Some(parents) = support_parents.get(u) {
                for &p in parents {
                    if superseded_set.contains(p) || invalidated_set.contains(p) {
                        continue;
                    }
                    active_support.insert(p);
                    if let Some(p_node) = self.visible_nodes.get(p)
                        && p_node.kind == EvidenceGraphNodeKind::SourceCapsule
                    {
                        minimal_roots.insert(p);
                    }
                    if back_seen.insert(p) {
                        back_q.push_back(p);
                    }
                }
            }
        }

        let active_contradictions: Vec<String> = direct_contradictions
            .into_iter()
            .filter(|c| !superseded_set.contains(c) && !invalidated_set.contains(c))
            .map(str::to_owned)
            .collect();

        // Check reachability from any active SourceCapsule to `target_decision_id` without a given removed node
        // (counterfactual single-node removal oracle!).
        let has_grounded_path = |removed: Option<&str>| -> bool {
            if removed == Some(target_decision_id) {
                return false;
            }
            let mut q: VecDeque<&str> = VecDeque::new();
            let mut seen: BTreeSet<&str> = BTreeSet::new();
            for &root in &minimal_roots {
                if removed == Some(root) {
                    continue;
                }
                q.push_back(root);
                seen.insert(root);
            }
            while let Some(u) = q.pop_front() {
                if u == target_decision_id {
                    return true;
                }
                if let Some(nexts) = derived_children.get(u) {
                    for &v in nexts {
                        if removed == Some(v)
                            || superseded_set.contains(v)
                            || invalidated_set.contains(v)
                        {
                            continue;
                        }
                        if seen.insert(v) {
                            q.push_back(v);
                        }
                    }
                }
            }
            false
        };

        let decision_currently_supported = has_grounded_path(None)
            && !invalidated_set.contains(target_decision_id)
            && active_contradictions.is_empty();

        let mut counterfactual_flippers = Vec::new();
        if decision_currently_supported {
            for &cand in &active_support {
                budget.charge(1, &mut is_cancelled)?;
                if !has_grounded_path(Some(cand)) {
                    counterfactual_flippers.push(cand.to_owned());
                }
            }
        }

        // Deletion reachability closure from minimal source roots.
        let mut del_impact: BTreeSet<&str> = BTreeSet::new();
        let mut del_q: VecDeque<&str> = minimal_roots.iter().copied().collect();
        while let Some(u) = del_q.pop_front() {
            budget.charge(1, &mut is_cancelled)?;
            if del_impact.insert(u)
                && let Some(children) = derived_children.get(u)
            {
                for &c in children {
                    del_q.push_back(c);
                }
            }
        }

        let active_supporting_nodes: Vec<String> =
            active_support.into_iter().map(str::to_owned).collect();
        let superseded_history_nodes: Vec<String> =
            superseded_set.into_iter().map(str::to_owned).collect();
        let invalidated_nodes: Vec<String> =
            invalidated_set.into_iter().map(str::to_owned).collect();
        let minimal_source_roots: Vec<String> =
            minimal_roots.into_iter().map(str::to_owned).collect();
        let deletion_impact_nodes: Vec<String> =
            del_impact.into_iter().map(str::to_owned).collect();

        let mut path_enc = CanonicalEncoder::new();
        path_enc.text(target_decision_id);
        path_enc.u8(u8::from(decision_currently_supported));
        for f in &counterfactual_flippers {
            path_enc.text(f);
        }
        let decision_path_digest = hash_domain_tag(G_EVIDENCE_DIGEST_DOMAIN, 2, &path_enc.finish());
        let mut out_enc = CanonicalEncoder::new();
        out_enc.digest(self.universe_digest);
        out_enc.digest(decision_path_digest);
        out_enc.u64(active_supporting_nodes.len() as u64);
        let output_digest = hash_domain_tag(G_EVIDENCE_DIGEST_DOMAIN, 3, &out_enc.finish());

        let witness = build_universe_witness(
            G_EVIDENCE_ALGORITHM_ID,
            G_EVIDENCE_IMPLEMENTATION_ID,
            GraphUniverse::GEvidence,
            &self.projection_id,
            self.projection.anchor(),
            self.projection.node_count(),
            self.projection.edge_count(),
            self.universe_digest,
            G_EVIDENCE_POLICY_ID,
            budget.used(),
            ((self.visible_nodes.len() + self.visible_edges.len() + 1) * 192) as u64,
            decision_path_digest,
            output_digest,
        )?;

        Ok(CausalExplanationReport {
            target_decision_id: target_decision_id.to_owned(),
            decision_currently_supported,
            active_supporting_nodes,
            superseded_history_nodes,
            invalidated_nodes,
            active_contradictions,
            minimal_source_roots,
            counterfactual_decision_flippers: counterfactual_flippers,
            deletion_impact_nodes,
            grants_effect_authority: false,
            witness,
        })
    }

    /// Serializes `G_evidence` into its versioned checksummed wire format (`v2`).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(CURRENT_UNIVERSE_WIRE_VERSION, false)
    }

    /// Serializes a compatible legacy `v1` fixture carrying a removed `legacy_overwrite_history` flag.
    pub fn to_legacy_v1_fixture_bytes(
        &self,
        legacy_overwrite_history: bool,
    ) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(LEGACY_UNIVERSE_WIRE_VERSION, legacy_overwrite_history)
    }

    fn encode_versioned(
        &self,
        version: u32,
        legacy_overwrite_history: bool,
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
            enc.u8(u8::from(legacy_overwrite_history));
        } else {
            enc.u64(self.tombstoned_fields.len() as u64);
            for t in &self.tombstoned_fields {
                enc.text(t);
            }
        }
        let payload = enc
            .finish_checked()
            .map_err(|e| TypedUniverseError::MalformedWire(e.to_string()))?;
        seal_wire_envelope(
            G_EVIDENCE_WIRE_MAGIC,
            version,
            G_EVIDENCE_DIGEST_DOMAIN,
            &payload,
        )
    }

    /// Opens a `v1` (migrating deterministically with tombstones) or `v2` durable `G_evidence` fixture.
    pub fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<(Self, UniverseMigrationReport), TypedUniverseError> {
        let (version, payload) =
            open_wire_envelope(bytes, G_EVIDENCE_WIRE_MAGIC, G_EVIDENCE_DIGEST_DOMAIN)?;
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
        if projection.universe() != GraphUniverse::GEvidence {
            return Err(TypedUniverseError::MalformedWire(
                "embedded projection universe is not G_evidence".to_owned(),
            ));
        }
        let n_len = usize::try_from(dec.u64().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("node count overflow".to_owned()))?;
        if n_len > MAX_UNIVERSE_ITEMS || n_len.saturating_mul(16) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "node count out of wire bounds".to_owned(),
            ));
        }
        let mut visible_nodes = BTreeMap::new();
        for _ in 0..n_len {
            let node = EvidenceGraphNode::decode_body(&mut dec)?;
            if visible_nodes.contains_key(&node.node_id) {
                return Err(TypedUniverseError::MalformedWire(
                    "duplicate G_evidence node_id".to_owned(),
                ));
            }
            let Some(handle) = projection.handle_for_node_id(&node.node_id) else {
                return Err(TypedUniverseError::MalformedWire(
                    "wire G_evidence node missing from embedded projection".to_owned(),
                ));
            };
            if projection.node(handle)?.payload_digest != node.node_digest() {
                return Err(TypedUniverseError::MalformedWire(
                    "wire G_evidence node digest disagrees with embedded projection".to_owned(),
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
            let edge = EvidenceGraphEdge::decode_body(&mut dec)?;
            if !visible_nodes.contains_key(&edge.source_id)
                || !visible_nodes.contains_key(&edge.target_id)
            {
                return Err(TypedUniverseError::MalformedWire(
                    "wire G_evidence edge references unknown node".to_owned(),
                ));
            }
            visible_edges.insert(edge);
        }
        let (migrated, tombstoned_fields) = if version == LEGACY_UNIVERSE_WIRE_VERSION {
            let _deprecated_flag = dec.u8().map_err(map_err)?;
            (
                true,
                vec![
                    "v1.legacy_overwrite_history:tombstoned_append_only_supersession_required"
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
        visible_nodes: &BTreeMap<String, EvidenceGraphNode>,
        visible_edges: &BTreeSet<EvidenceGraphEdge>,
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
        hash_domain_tag(G_EVIDENCE_DIGEST_DOMAIN, 0, &enc.finish())
    }
}
