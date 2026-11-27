#![forbid(unsafe_code)]
//! Track association hypothesis graph `G_assoc` (`PROJ-ASSOC-001`, `fss-x4a.23.69.5`).
//!
//! Represents within-camera tracklets/observations and candidate identity transitions with
//! decomposed component evidence/cost (temporal feasibility, calibrated spatial transition,
//! generation-pinned appearance, size/gait/motion, occlusion/blind-route plausibility,
//! contradictory simultaneous visibility, source quality/health, and household-routine context).
//!
//! Core guarantees:
//! - Assignments remain hypotheses (`is_person_identity == false` ALWAYS: a track ID never becomes
//!   a biometric person identity!);
//! - Mixing embeddings across distinct model generations fails closed (`MixedAnchorOrGeneration`);
//! - Simultaneous visibility at disjoint cameras/zones is flagged as a hard contradiction;
//! - Deterministic k-best association preserves competing hypotheses, ambiguity margins, and
//!   protected alternatives (e.g., person-vs-raccoon/crawling ambiguity retains BOTH hypotheses
//!   and names the cheapest discriminating probe).

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest, Generation,
    GraphAlgorithmWitness, LedgerAnchor, Plane, TimestampNs,
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

/// Registered digest domain for `G_assoc` projections and witnesses
/// (`SCHEMA-DOMAIN-GRAPH-G-ASSOC-001`).
pub const G_ASSOC_DIGEST_DOMAIN: &str = "fss.graph.g_assoc_projection.v1";
/// Wire magic for durable `G_assoc` fixtures (`FSSGAS01`).
pub const G_ASSOC_WIRE_MAGIC: [u8; 8] = *b"FSSGAS01";
/// Registered algorithm ID emitted in `G_assoc` witnesses.
pub const G_ASSOC_ALGORITHM_ID: &str = "ALG-PROJ-ASSOC-001";
/// Implementation generation recorded in `G_assoc` witnesses.
pub const G_ASSOC_IMPLEMENTATION_ID: &str = "fss-graph-algorithms:proj-assoc-001:g-assoc-oracle:v2";
/// Policy identity recorded in `G_assoc` witnesses.
pub const G_ASSOC_POLICY_ID: &str =
    "graph-policy:g-assoc:k-best-decomposed-hypotheses:no-embedding-mix:v2";

/// One within-camera anonymous tracklet observation in `G_assoc`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackletNodeSpec {
    /// Stable tracklet identifier (NEVER a person identity!).
    pub tracklet_id: String,
    /// Observing camera identifier.
    pub camera_id: String,
    /// Observed zone identifier.
    pub zone_id: String,
    /// Observation start timestamp (ns).
    pub start_ns: TimestampNs,
    /// Observation end timestamp (ns, `>= start_ns`).
    pub end_ns: TimestampNs,
    /// Pinned appearance embedding model generation (`>= 1`; mixed generations fail closed!).
    pub embedding_generation: Generation,
    /// Pinned camera geometry generation (`>= 1`).
    pub geometry_generation: Generation,
    /// Source quality/health score in basis points (`0..=10_000`).
    pub source_quality_bps: u16,
    /// Candidate class hypothesis label (`person`, `raccoon`, `crawling_person`, `resident_routine`).
    pub hypothesis_class: String,
    /// Shared camera/infrastructure failure domains.
    pub failure_domains: BTreeSet<String>,
    /// MUST be `false`: tracklets NEVER assert biometric person identity!
    pub asserts_person_identity: bool,
    /// Owning semantic plane.
    pub plane: Plane,
}

impl TrackletNodeSpec {
    /// Validates tracklet bounds and non-identity invariant fail-closed.
    pub fn validate(&self) -> Result<(), TypedUniverseError> {
        validate_clean_label(&self.tracklet_id, "tracklet_id")?;
        validate_clean_label(&self.camera_id, "camera_id")?;
        validate_clean_label(&self.zone_id, "zone_id")?;
        validate_clean_label(&self.hypothesis_class, "hypothesis_class")?;
        if self.asserts_person_identity {
            return Err(TypedUniverseError::AuthorityViolation(format!(
                "tracklet '{}' cannot convert anonymous track ID into person identity",
                self.tracklet_id
            )));
        }
        if self.end_ns.0 < self.start_ns.0
            || self.embedding_generation.0 == 0
            || self.geometry_generation.0 == 0
            || self.source_quality_bps > 10_000
        {
            return Err(TypedUniverseError::InvalidInput(format!(
                "invalid tracklet bounds on '{}'",
                self.tracklet_id
            )));
        }
        for d in &self.failure_domains {
            validate_clean_label(d, "failure_domain")?;
        }
        Ok(())
    }

    /// Canonical SHA-256 commitment for this tracklet node.
    #[must_use]
    pub fn node_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        hash_domain_tag(G_ASSOC_DIGEST_DOMAIN, 1, &enc.finish())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.tracklet_id);
        enc.text(&self.camera_id);
        enc.text(&self.zone_id);
        enc.i128(self.start_ns.0);
        enc.i128(self.end_ns.0);
        enc.u64(self.embedding_generation.0);
        enc.u64(self.geometry_generation.0);
        enc.u32(u32::from(self.source_quality_bps));
        enc.text(&self.hypothesis_class);
        enc.u64(self.failure_domains.len() as u64);
        for d in &self.failure_domains {
            enc.text(d);
        }
        enc.u8(u8::from(self.asserts_person_identity));
        self.plane.encode_canonical(enc);
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, TypedUniverseError> {
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let tracklet_id = dec.text().map_err(map_err)?.to_owned();
        let camera_id = dec.text().map_err(map_err)?.to_owned();
        let zone_id = dec.text().map_err(map_err)?.to_owned();
        let start_ns = TimestampNs(dec.i128().map_err(map_err)?);
        let end_ns = TimestampNs(dec.i128().map_err(map_err)?);
        let embedding_generation = Generation(dec.u64().map_err(map_err)?);
        let geometry_generation = Generation(dec.u64().map_err(map_err)?);
        let source_quality_bps = u16::try_from(dec.u32().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("source_quality overflow".to_owned()))?;
        let hypothesis_class = dec.text().map_err(map_err)?.to_owned();
        let d_len = usize::try_from(dec.u64().map_err(map_err)?).map_err(|_| {
            TypedUniverseError::MalformedWire("failure_domains overflow".to_owned())
        })?;
        if d_len > 64 || d_len.saturating_mul(5) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "failure_domains exceeds wire bounds".to_owned(),
            ));
        }
        let mut failure_domains = BTreeSet::new();
        for _ in 0..d_len {
            failure_domains.insert(dec.text().map_err(map_err)?.to_owned());
        }
        let asserts_person_identity = match dec.u8().map_err(map_err)? {
            0 => false,
            1 => true,
            _ => {
                return Err(TypedUniverseError::MalformedWire(
                    "invalid asserts_person_identity bool".to_owned(),
                ));
            }
        };
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
            tracklet_id,
            camera_id,
            zone_id,
            start_ns,
            end_ns,
            embedding_generation,
            geometry_generation,
            source_quality_bps,
            hypothesis_class,
            failure_domains,
            asserts_person_identity,
            plane,
        };
        node.validate()?;
        Ok(node)
    }
}

/// Decomposed 8-component association evidence/cost vector (never one opaque score!).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AssocComponentCosts {
    /// Temporal feasibility cost (lower is better).
    pub temporal_cost: u32,
    /// Calibrated spatial transition cost.
    pub spatial_cost: u32,
    /// Generation-pinned appearance similarity cost.
    pub appearance_cost: u32,
    /// Size, gait, and motion consistency cost.
    pub size_gait_motion_cost: u32,
    /// Occlusion / blind-route plausibility cost.
    pub occlusion_route_cost: u32,
    /// Source quality/health penalty.
    pub source_health_penalty: u32,
    /// Household routine contextual prior cost.
    pub household_routine_cost: u32,
}

impl AssocComponentCosts {
    /// Exact integer sum of all 7 nonnegative cost components.
    #[must_use]
    pub const fn total_cost(self) -> u64 {
        (self.temporal_cost as u64)
            + (self.spatial_cost as u64)
            + (self.appearance_cost as u64)
            + (self.size_gait_motion_cost as u64)
            + (self.occlusion_route_cost as u64)
            + (self.source_health_penalty as u64)
            + (self.household_routine_cost as u64)
    }
}

/// One candidate association hypothesis edge in `G_assoc`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AssocCandidateEdge {
    /// Stable unique hypothesis edge ID.
    pub edge_id: String,
    /// Source tracklet ID.
    pub source_id: String,
    /// Target tracklet ID.
    pub target_id: String,
    /// Hypothesis label (e.g. `same_actor_crawling_person` vs `separate_animal_raccoon`).
    pub hypothesis_label: String,
    /// Decomposed component costs.
    pub components: AssocComponentCosts,
    /// Explicit assumptions required for this association.
    pub assumptions: Vec<String>,
    /// Explicit contradictions detected (e.g. `simultaneous_disjoint_visibility`).
    pub contradictions: Vec<String>,
    /// Protected alternative flag: MUST NOT be greedily pruned during k-best ranking!
    pub protected_alternative: bool,
    /// Optional cheapest discriminating probe `(probe_id, cost_units)` that separates alternatives.
    pub discriminating_probe: Option<(String, u64)>,
}

impl AssocCandidateEdge {
    /// Validates candidate edge labels fail-closed.
    pub fn validate(&self) -> Result<(), TypedUniverseError> {
        validate_clean_label(&self.edge_id, "edge_id")?;
        validate_clean_label(&self.source_id, "source_id")?;
        validate_clean_label(&self.target_id, "target_id")?;
        validate_clean_label(&self.hypothesis_label, "hypothesis_label")?;
        for a in &self.assumptions {
            validate_clean_label(a, "assumption")?;
        }
        for c in &self.contradictions {
            validate_clean_label(c, "contradiction")?;
        }
        if let Some((ref pid, _)) = self.discriminating_probe {
            validate_clean_label(pid, "discriminating_probe")?;
        }
        Ok(())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.edge_id);
        enc.text(&self.source_id);
        enc.text(&self.target_id);
        enc.text(&self.hypothesis_label);
        enc.u32(self.components.temporal_cost);
        enc.u32(self.components.spatial_cost);
        enc.u32(self.components.appearance_cost);
        enc.u32(self.components.size_gait_motion_cost);
        enc.u32(self.components.occlusion_route_cost);
        enc.u32(self.components.source_health_penalty);
        enc.u32(self.components.household_routine_cost);
        enc.u64(self.assumptions.len() as u64);
        for a in &self.assumptions {
            enc.text(a);
        }
        enc.u64(self.contradictions.len() as u64);
        for c in &self.contradictions {
            enc.text(c);
        }
        enc.u8(u8::from(self.protected_alternative));
        match &self.discriminating_probe {
            Some((pid, cost)) => {
                enc.u8(1);
                enc.text(pid);
                enc.u64(*cost);
            }
            None => enc.u8(0),
        }
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, TypedUniverseError> {
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let edge_id = dec.text().map_err(map_err)?.to_owned();
        let source_id = dec.text().map_err(map_err)?.to_owned();
        let target_id = dec.text().map_err(map_err)?.to_owned();
        let hypothesis_label = dec.text().map_err(map_err)?.to_owned();
        let components = AssocComponentCosts {
            temporal_cost: dec.u32().map_err(map_err)?,
            spatial_cost: dec.u32().map_err(map_err)?,
            appearance_cost: dec.u32().map_err(map_err)?,
            size_gait_motion_cost: dec.u32().map_err(map_err)?,
            occlusion_route_cost: dec.u32().map_err(map_err)?,
            source_health_penalty: dec.u32().map_err(map_err)?,
            household_routine_cost: dec.u32().map_err(map_err)?,
        };
        let a_len = usize::try_from(dec.u64().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("assumptions overflow".to_owned()))?;
        if a_len > 32 || a_len.saturating_mul(5) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "assumptions exceed wire bounds".to_owned(),
            ));
        }
        let mut assumptions = Vec::with_capacity(a_len);
        for _ in 0..a_len {
            assumptions.push(dec.text().map_err(map_err)?.to_owned());
        }
        let c_len = usize::try_from(dec.u64().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("contradictions overflow".to_owned()))?;
        if c_len > 32 || c_len.saturating_mul(5) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "contradictions exceed wire bounds".to_owned(),
            ));
        }
        let mut contradictions = Vec::with_capacity(c_len);
        for _ in 0..c_len {
            contradictions.push(dec.text().map_err(map_err)?.to_owned());
        }
        let protected_alternative = match dec.u8().map_err(map_err)? {
            0 => false,
            1 => true,
            _ => {
                return Err(TypedUniverseError::MalformedWire(
                    "invalid protected_alternative bool".to_owned(),
                ));
            }
        };
        let discriminating_probe = match dec.u8().map_err(map_err)? {
            0 => None,
            1 => Some((
                dec.text().map_err(map_err)?.to_owned(),
                dec.u64().map_err(map_err)?,
            )),
            _ => {
                return Err(TypedUniverseError::MalformedWire(
                    "invalid discriminating_probe flag".to_owned(),
                ));
            }
        };
        let edge = Self {
            edge_id,
            source_id,
            target_id,
            hypothesis_label,
            components,
            assumptions,
            contradictions,
            protected_alternative,
            discriminating_probe,
        };
        edge.validate()?;
        Ok(edge)
    }
}

/// Incremental ordered delta applied to `G_assoc`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AssocDelta {
    /// Upsert a tracklet node.
    UpsertTracklet(Box<TrackletNodeSpec>),
    /// Remove a tracklet node and incident candidate edges.
    RemoveTracklet(String),
    /// Upsert a candidate association hypothesis edge.
    UpsertEdge(Box<AssocCandidateEdge>),
    /// Remove a candidate edge by `edge_id`.
    RemoveEdge(String),
}

/// One ranked candidate hypothesis returned by `G_assoc::evaluate_k_best_hypotheses`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RankedAssocHypothesis {
    /// Candidate edge ID.
    pub edge_id: String,
    /// Source and target tracklet IDs.
    pub source_id: String,
    /// Target tracklet ID.
    pub target_id: String,
    /// Human/machine hypothesis label.
    pub hypothesis_label: String,
    /// Decomposed total integer cost.
    pub total_cost: u64,
    /// Explicit shared failure domains between source & target cameras.
    pub shared_camera_failure_domains: Vec<String>,
    /// True iff simultaneous overlapping observation in disjoint zones contradicts same-actor merge!
    pub simultaneous_visibility_contradiction: bool,
    /// Protected alternative preserved regardless of rank cutoff.
    pub protected_alternative: bool,
    /// Always `false`: association hypothesis NEVER asserts biometric person identity!
    pub asserts_person_identity: bool,
}

/// Certified k-best track association result retaining alternatives, ambiguity margins, and probe.
#[derive(Clone, Debug, PartialEq)]
pub struct AssocKBestResult {
    /// Deterministic k-best hypotheses plus ALL retained protected alternatives.
    pub retained_hypotheses: Vec<RankedAssocHypothesis>,
    /// Cost gap between #2 and #1 non-contradicted hypotheses (`0` => unresolved tie!).
    pub ambiguity_margin: Option<u64>,
    /// True iff top hypotheses are tied or protected alternatives remain unresolved.
    pub unresolved_ambiguity: bool,
    /// Cheapest discriminating probe `(probe_id, cost)` across competing hypotheses, if declared.
    pub cheapest_discriminating_probe: Option<(String, u64)>,
    /// Always `false`: derived track hypotheses NEVER grant effect authority!
    pub grants_effect_authority: bool,
    /// Certified execution witness.
    pub witness: GraphAlgorithmWitness,
}

/// Anchor-pinned, capability-filtered Track Association Hypothesis Graph (`G_assoc`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackAssociationGraph {
    projection_id: String,
    policy_generation: Generation,
    projection: ImmutableGraphProjection,
    visible_nodes: BTreeMap<String, TrackletNodeSpec>,
    visible_edges: BTreeMap<String, AssocCandidateEdge>,
    tombstoned_fields: Vec<String>,
    universe_digest: ContentDigest,
}

impl TrackAssociationGraph {
    /// Builds `G_assoc`, failing closed on mixed embedding generations or identity-converting nodes!
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        projection_id: impl Into<String>,
        policy_generation: Generation,
        anchor: LedgerAnchor,
        history_root: ContentDigest,
        authority: &ProjectionAuthorityScope,
        nodes: Vec<TrackletNodeSpec>,
        edges: Vec<AssocCandidateEdge>,
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
                "G_assoc size exceeds hard ceiling".to_owned(),
            ));
        }

        let mut raw_nodes: BTreeMap<String, TrackletNodeSpec> = BTreeMap::new();
        for node in nodes {
            if is_cancelled() {
                return Err(TypedUniverseError::Cancelled);
            }
            node.validate()?;
            if raw_nodes.contains_key(&node.tracklet_id) {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "duplicate tracklet_id '{}'",
                    node.tracklet_id
                )));
            }
            raw_nodes.insert(node.tracklet_id.clone(), node);
        }

        let mut raw_edges: BTreeMap<String, AssocCandidateEdge> = BTreeMap::new();
        for edge in edges {
            edge.validate()?;
            let Some(src) = raw_nodes.get(&edge.source_id) else {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "unknown source tracklet '{}'",
                    edge.source_id
                )));
            };
            let Some(dst) = raw_nodes.get(&edge.target_id) else {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "unknown target tracklet '{}'",
                    edge.target_id
                )));
            };
            // NEVER mix embeddings across distinct model generations!
            if src.embedding_generation != dst.embedding_generation {
                return Err(TypedUniverseError::MixedAnchorOrGeneration(format!(
                    "cannot compare tracklet '{}' (emb gen {}) with '{}' (emb gen {})",
                    src.tracklet_id,
                    src.embedding_generation.0,
                    dst.tracklet_id,
                    dst.embedding_generation.0
                )));
            }
            if raw_edges.contains_key(&edge.edge_id) {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "duplicate assoc edge_id '{}'",
                    edge.edge_id
                )));
            }
            raw_edges.insert(edge.edge_id.clone(), edge);
        }

        let proj_nodes: Vec<ProjectionNodeSpec> = raw_nodes
            .values()
            .map(|n| ProjectionNodeSpec {
                node_id: n.tracklet_id.clone(),
                plane: n.plane,
                payload_digest: n.node_digest(),
            })
            .collect();
        let proj_edges: Vec<ProjectionEdgeSpec> = raw_edges
            .values()
            .map(|e| ProjectionEdgeSpec {
                source_id: e.source_id.clone(),
                target_id: e.target_id.clone(),
                relation: format!("assoc:{}", e.edge_id),
                weight: e.components.total_cost(),
            })
            .collect();

        let projection = ImmutableGraphProjection::build(
            GraphUniverse::GAssoc,
            ProjectionOrientation::Directed,
            anchor,
            history_root,
            authority,
            proj_nodes,
            proj_edges,
            requested_absence,
            is_cancelled(),
        )?;

        let visible_nodes: BTreeMap<String, TrackletNodeSpec> = raw_nodes
            .into_iter()
            .filter(|(id, _)| projection.handle_for_node_id(id).is_some())
            .collect();
        let visible_edges: BTreeMap<String, AssocCandidateEdge> = raw_edges
            .into_iter()
            .filter(|(_, e)| {
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

    /// Incrementally applies ordered `AssocDelta` updates with full-rebuild parity.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_deltas(
        &self,
        new_anchor: LedgerAnchor,
        new_history_root: ContentDigest,
        expected_policy_generation: Generation,
        authority: &ProjectionAuthorityScope,
        deltas: &[AssocDelta],
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
                AssocDelta::UpsertTracklet(n) => {
                    n.validate()?;
                    nodes.insert(n.tracklet_id.clone(), (**n).clone());
                }
                AssocDelta::RemoveTracklet(id) => {
                    nodes.remove(id);
                    edges.retain(|_, e| e.source_id != *id && e.target_id != *id);
                }
                AssocDelta::UpsertEdge(e) => {
                    e.validate()?;
                    edges.insert(e.edge_id.clone(), (**e).clone());
                }
                AssocDelta::RemoveEdge(eid) => {
                    edges.remove(eid);
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
            edges.into_values().collect(),
            requested_absence,
            is_cancelled,
        )
    }

    /// Underlying capability-filtered `ImmutableGraphProjection`.
    #[must_use]
    pub const fn projection(&self) -> &ImmutableGraphProjection {
        &self.projection
    }

    /// Canonical digest of this `G_assoc` universe.
    #[must_use]
    pub const fn universe_digest(&self) -> ContentDigest {
        self.universe_digest
    }

    /// Derived association hypotheses NEVER grant effect authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Evaluates deterministic k-best association hypotheses while retaining ALL protected
    /// alternatives, flagging simultaneous-visibility contradictions, surfacing correlated cameras,
    /// and naming the cheapest discriminating probe.
    pub fn evaluate_k_best_hypotheses(
        &self,
        k: usize,
        max_operations: u64,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<AssocKBestResult, TypedUniverseError> {
        if k == 0 {
            return Err(TypedUniverseError::InvalidInput(
                "k must be >= 1".to_owned(),
            ));
        }
        let mut budget = OpBudget::new(max_operations)?;

        let mut ranked: Vec<RankedAssocHypothesis> = Vec::with_capacity(self.visible_edges.len());
        let mut cheapest_probe: Option<(String, u64)> = None;

        for edge in self.visible_edges.values() {
            budget.charge(1, &mut is_cancelled)?;
            let (Some(src), Some(dst)) = (
                self.visible_nodes.get(&edge.source_id),
                self.visible_nodes.get(&edge.target_id),
            ) else {
                continue;
            };
            let shared_domains: Vec<String> = src
                .failure_domains
                .intersection(&dst.failure_domains)
                .cloned()
                .collect();
            let overlaps_in_time = src.start_ns.0 <= dst.end_ns.0 && dst.start_ns.0 <= src.end_ns.0;
            let simultaneous_contradiction = (overlaps_in_time && src.zone_id != dst.zone_id)
                || edge
                    .contradictions
                    .iter()
                    .any(|c| c == "simultaneous_disjoint_visibility");

            if let Some((ref pid, cost)) = edge.discriminating_probe
                && cheapest_probe
                    .as_ref()
                    .is_none_or(|(bp, bc)| (cost, pid.as_str()) < (*bc, bp.as_str()))
            {
                cheapest_probe = Some((pid.clone(), cost));
            }

            ranked.push(RankedAssocHypothesis {
                edge_id: edge.edge_id.clone(),
                source_id: edge.source_id.clone(),
                target_id: edge.target_id.clone(),
                hypothesis_label: edge.hypothesis_label.clone(),
                total_cost: edge.components.total_cost(),
                shared_camera_failure_domains: shared_domains,
                simultaneous_visibility_contradiction: simultaneous_contradiction,
                protected_alternative: edge.protected_alternative,
                asserts_person_identity: false,
            });
        }

        // Canonical CGSE tie-break: non-contradicted first, then lowest cost, then edge_id.
        ranked.sort_by(|a, b| {
            (
                a.simultaneous_visibility_contradiction,
                a.total_cost,
                a.edge_id.as_str(),
            )
                .cmp(&(
                    b.simultaneous_visibility_contradiction,
                    b.total_cost,
                    b.edge_id.as_str(),
                ))
        });

        // Retain top-k PLUS every protected alternative regardless of k cutoff!
        let mut retained_hypotheses = Vec::new();
        for (idx, hyp) in ranked.into_iter().enumerate() {
            if idx < k || hyp.protected_alternative {
                retained_hypotheses.push(hyp);
            }
        }

        let valid_costs: Vec<u64> = retained_hypotheses
            .iter()
            .filter(|h| !h.simultaneous_visibility_contradiction)
            .map(|h| h.total_cost)
            .collect();
        let ambiguity_margin = if valid_costs.len() >= 2 {
            Some(valid_costs[1].saturating_sub(valid_costs[0]))
        } else {
            None
        };
        let has_protected_competing = retained_hypotheses
            .iter()
            .filter(|h| !h.simultaneous_visibility_contradiction)
            .any(|h| h.protected_alternative);
        let unresolved_ambiguity =
            ambiguity_margin == Some(0) || (has_protected_competing && valid_costs.len() >= 2);

        let mut path_enc = CanonicalEncoder::new();
        path_enc.u64(k as u64);
        for h in &retained_hypotheses {
            path_enc.text(&h.edge_id);
            path_enc.u64(h.total_cost);
            path_enc.u8(u8::from(h.simultaneous_visibility_contradiction));
        }
        let decision_path_digest = hash_domain_tag(G_ASSOC_DIGEST_DOMAIN, 2, &path_enc.finish());
        let mut out_enc = CanonicalEncoder::new();
        out_enc.digest(self.universe_digest);
        out_enc.digest(decision_path_digest);
        out_enc.u8(u8::from(unresolved_ambiguity));
        let output_digest = hash_domain_tag(G_ASSOC_DIGEST_DOMAIN, 3, &out_enc.finish());

        let witness = build_universe_witness(
            G_ASSOC_ALGORITHM_ID,
            G_ASSOC_IMPLEMENTATION_ID,
            GraphUniverse::GAssoc,
            &self.projection_id,
            self.projection.anchor(),
            self.projection.node_count(),
            self.projection.edge_count(),
            self.universe_digest,
            G_ASSOC_POLICY_ID,
            budget.used(),
            ((self.visible_nodes.len() + self.visible_edges.len() + 1) * 192) as u64,
            decision_path_digest,
            output_digest,
        )?;

        Ok(AssocKBestResult {
            retained_hypotheses,
            ambiguity_margin,
            unresolved_ambiguity,
            cheapest_discriminating_probe: cheapest_probe,
            grants_effect_authority: false,
            witness,
        })
    }

    /// Serializes `G_assoc` into its versioned checksummed wire format (`v2`).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(CURRENT_UNIVERSE_WIRE_VERSION, false)
    }

    /// Serializes a compatible legacy `v1` fixture carrying a removed `legacy_greedy_merge` flag.
    pub fn to_legacy_v1_fixture_bytes(
        &self,
        legacy_greedy_merge: bool,
    ) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(LEGACY_UNIVERSE_WIRE_VERSION, legacy_greedy_merge)
    }

    fn encode_versioned(
        &self,
        version: u32,
        legacy_greedy_merge: bool,
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
        for edge in self.visible_edges.values() {
            edge.encode_body(&mut enc);
        }
        if version == LEGACY_UNIVERSE_WIRE_VERSION {
            enc.u8(u8::from(legacy_greedy_merge));
        } else {
            enc.u64(self.tombstoned_fields.len() as u64);
            for t in &self.tombstoned_fields {
                enc.text(t);
            }
        }
        let payload = enc
            .finish_checked()
            .map_err(|e| TypedUniverseError::MalformedWire(e.to_string()))?;
        seal_wire_envelope(G_ASSOC_WIRE_MAGIC, version, G_ASSOC_DIGEST_DOMAIN, &payload)
    }

    /// Opens a `v1` (migrating deterministically with tombstones) or `v2` durable `G_assoc` fixture.
    pub fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<(Self, UniverseMigrationReport), TypedUniverseError> {
        let (version, payload) =
            open_wire_envelope(bytes, G_ASSOC_WIRE_MAGIC, G_ASSOC_DIGEST_DOMAIN)?;
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
        if projection.universe() != GraphUniverse::GAssoc {
            return Err(TypedUniverseError::MalformedWire(
                "embedded projection universe is not G_assoc".to_owned(),
            ));
        }
        let n_len = usize::try_from(dec.u64().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("node count overflow".to_owned()))?;
        if n_len > MAX_UNIVERSE_ITEMS || n_len.saturating_mul(32) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "node count out of wire bounds".to_owned(),
            ));
        }
        let mut visible_nodes = BTreeMap::new();
        for _ in 0..n_len {
            let node = TrackletNodeSpec::decode_body(&mut dec)?;
            if visible_nodes.contains_key(&node.tracklet_id) {
                return Err(TypedUniverseError::MalformedWire(
                    "duplicate tracklet_id".to_owned(),
                ));
            }
            let Some(handle) = projection.handle_for_node_id(&node.tracklet_id) else {
                return Err(TypedUniverseError::MalformedWire(
                    "wire tracklet missing from embedded G_assoc projection".to_owned(),
                ));
            };
            if projection.node(handle)?.payload_digest != node.node_digest() {
                return Err(TypedUniverseError::MalformedWire(
                    "wire tracklet digest disagrees with embedded projection".to_owned(),
                ));
            }
            visible_nodes.insert(node.tracklet_id.clone(), node);
        }
        if visible_nodes.len() != projection.node_count() {
            return Err(TypedUniverseError::MalformedWire(
                "wire G_assoc node count disagrees with embedded projection".to_owned(),
            ));
        }
        let e_len = usize::try_from(dec.u64().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("edge count overflow".to_owned()))?;
        if e_len > MAX_UNIVERSE_ITEMS * 4 || e_len.saturating_mul(24) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "edge count out of wire bounds".to_owned(),
            ));
        }
        let mut visible_edges = BTreeMap::new();
        for _ in 0..e_len {
            let edge = AssocCandidateEdge::decode_body(&mut dec)?;
            if visible_edges.contains_key(&edge.edge_id) {
                return Err(TypedUniverseError::MalformedWire(
                    "duplicate wire G_assoc edge_id".to_owned(),
                ));
            }
            let (Some(src), Some(dst)) = (
                visible_nodes.get(&edge.source_id),
                visible_nodes.get(&edge.target_id),
            ) else {
                return Err(TypedUniverseError::MalformedWire(
                    "wire G_assoc edge references unknown tracklet".to_owned(),
                ));
            };
            if src.embedding_generation != dst.embedding_generation {
                return Err(TypedUniverseError::MixedAnchorOrGeneration(
                    "wire G_assoc edge mixes embedding generations".to_owned(),
                ));
            }
            visible_edges.insert(edge.edge_id.clone(), edge);
        }
        if visible_edges.len() != projection.edge_count() {
            return Err(TypedUniverseError::MalformedWire(
                "wire G_assoc edge count disagrees with embedded projection".to_owned(),
            ));
        }
        let (migrated, tombstoned_fields) = if version == LEGACY_UNIVERSE_WIRE_VERSION {
            let _deprecated_flag = dec.u8().map_err(map_err)?;
            (
                true,
                vec![
                    "v1.legacy_greedy_merge:tombstoned_k_best_protected_alternatives_preserved"
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
        visible_nodes: &BTreeMap<String, TrackletNodeSpec>,
        visible_edges: &BTreeMap<String, AssocCandidateEdge>,
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
        for edge in visible_edges.values() {
            edge.encode_body(&mut enc);
        }
        hash_domain_tag(G_ASSOC_DIGEST_DOMAIN, 0, &enc.finish())
    }
}
