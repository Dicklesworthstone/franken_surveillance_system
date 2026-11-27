#![forbid(unsafe_code)]
//! Possible-world and robust-control factor graph `G_world` (`PROJ-WORLD-001`, `fss-x4a.23.69.12`).
//!
//! Represents one `WorldEnvelope` as a factorized projection of certified core claims, material
//! alternatives, contradictions, assumptions, constraints, unsafe-world relations, and
//! branch-collapsing probes — WITHOUT enumerating or ranking away every complete world.
//!
//! Core guarantees:
//! - Knowledge state, provenance class, and hypothesis disposition remain strictly orthogonal
//!   typed fields (never collapsed into one score);
//! - Protected high-loss possible worlds survive model reranking, semantic compression under
//!   budget pressure, transfer, view changes, and handoff unless backed by an explicit
//!   impossibility or safe-dominance proof digest;
//! - Candidate actions are classified into `Robust`, `Conditional`, `InformationGathering`,
//!   `WaitWatch`, `Blocked`, or `Unavailable` against the exact `WorldEnvelope`;
//! - Plans bind `world_envelope_digest` and explicitly name supported and unsafe worlds, failing
//!   closed on stale envelopes or newly revealed contradictions.

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

/// Registered digest domain for `G_world` projections and witnesses
/// (`SCHEMA-DOMAIN-GRAPH-G-WORLD-001`).
pub const G_WORLD_DIGEST_DOMAIN: &str = "fss.graph.g_world_projection.v1";
/// Wire magic for durable `G_world` fixtures (`FSSGWR01`).
pub const G_WORLD_WIRE_MAGIC: [u8; 8] = *b"FSSGWR01";
/// Registered algorithm ID emitted in `G_world` witnesses.
pub const G_WORLD_ALGORITHM_ID: &str = "ALG-PROJ-WORLD-001";
/// Implementation generation recorded in `G_world` witnesses.
pub const G_WORLD_IMPLEMENTATION_ID: &str = "fss-graph-algorithms:proj-world-001:g-world-oracle:v2";
/// Policy identity recorded in `G_world` witnesses.
pub const G_WORLD_POLICY_ID: &str =
    "graph-policy:g-world:factorized-envelope:protected-high-loss-survival:v2";

/// Closed taxonomy of factor kinds inside one factorized `WorldEnvelope`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WorldFactorKind {
    /// Certified core fact shared across surviving worlds.
    CertifiedCoreClaim = 1,
    /// Material unresolved alternative world/hypothesis branch.
    MaterialAlternative = 2,
    /// Explicit contradiction between competing evidence or claims.
    Contradiction = 3,
    /// Explicit modeling/calibration/independence assumption.
    Assumption = 4,
    /// Hard safety, privacy, legal, or resource constraint.
    Constraint = 5,
    /// Relation linking a possible world to an unsafe high-loss failure mode.
    UnsafeWorldRelation = 6,
    /// Evidence-gathering probe capable of collapsing unresolved branches.
    BranchCollapsingProbe = 7,
}

impl WorldFactorKind {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::CertifiedCoreClaim),
            2 => Ok(Self::MaterialAlternative),
            3 => Ok(Self::Contradiction),
            4 => Ok(Self::Assumption),
            5 => Ok(Self::Constraint),
            6 => Ok(Self::UnsafeWorldRelation),
            7 => Ok(Self::BranchCollapsingProbe),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown WorldFactorKind tag {other}"
            ))),
        }
    }
}

/// Orthogonal epistemic knowledge state (NEVER collapsed with provenance or disposition!).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WorldKnowledgeState {
    /// Certified under complete coverage and anchor.
    Certified = 1,
    /// Observed with retained evidence but open alternatives.
    Observed = 2,
    /// Hypothesized / inferred from partial evidence.
    Hypothesized = 3,
    /// Explicitly unknown / unobservable.
    Unknown = 4,
    /// Explicitly conflicted by contradictory evidence.
    Conflicted = 5,
    /// Stale beyond validity horizon.
    Stale = 6,
}

impl WorldKnowledgeState {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::Certified),
            2 => Ok(Self::Observed),
            3 => Ok(Self::Hypothesized),
            4 => Ok(Self::Unknown),
            5 => Ok(Self::Conflicted),
            6 => Ok(Self::Stale),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown WorldKnowledgeState tag {other}"
            ))),
        }
    }
}

/// Orthogonal provenance class (NEVER collapsed with knowledge state!).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WorldProvenanceClass {
    /// Backed by immutable retained sensor evidence.
    SourceRetained = 1,
    /// Derived model/graph cognition output.
    DerivedCognition = 2,
    /// Explicit owner/operator assertion.
    OperatorAsserted = 3,
    /// Unverified external or prior-handoff claim.
    ExternalUnverified = 4,
}

impl WorldProvenanceClass {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::SourceRetained),
            2 => Ok(Self::DerivedCognition),
            3 => Ok(Self::OperatorAsserted),
            4 => Ok(Self::ExternalUnverified),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown WorldProvenanceClass tag {other}"
            ))),
        }
    }
}

/// Orthogonal hypothesis disposition (NEVER collapsed with probability or provenance!).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WorldHypothesisDisposition {
    /// Active supported hypothesis.
    Supported = 1,
    /// Active competing alternative.
    ActiveAlternative = 2,
    /// Refuted by explicit falsifying evidence.
    Refuted = 3,
    /// Protected high-loss possible world that CANNOT be ranked or compressed away without proof!
    ProtectedHighLoss = 4,
}

impl WorldHypothesisDisposition {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::Supported),
            2 => Ok(Self::ActiveAlternative),
            3 => Ok(Self::Refuted),
            4 => Ok(Self::ProtectedHighLoss),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown WorldHypothesisDisposition tag {other}"
            ))),
        }
    }
}

/// Explicit tag protecting a high-loss possible world from deletion by ranking/compression/handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedWorldSpec {
    /// Loss severity in basis points (`1..=10_000`; high-loss worlds survive low probability!).
    pub loss_severity_bps: u16,
    /// Optional cryptographic proof digest proving this world is impossible.
    pub impossibility_proof: Option<ContentDigest>,
    /// Optional cryptographic proof digest proving this world is safely dominated.
    pub safe_dominance_proof: Option<ContentDigest>,
}

impl ProtectedWorldSpec {
    /// True iff an explicit proof permits safe pruning of this high-loss world.
    #[must_use]
    pub const fn has_explicit_elimination_proof(&self) -> bool {
        self.impossibility_proof.is_some() || self.safe_dominance_proof.is_some()
    }
}

/// One typed factor node inside `G_world`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldFactorSpec {
    /// Stable unique factor/world identifier.
    pub factor_id: String,
    /// Typed factor role in the factorized `WorldEnvelope`.
    pub kind: WorldFactorKind,
    /// Orthogonal knowledge state.
    pub knowledge_state: WorldKnowledgeState,
    /// Orthogonal provenance class.
    pub provenance_class: WorldProvenanceClass,
    /// Orthogonal hypothesis disposition.
    pub disposition: WorldHypothesisDisposition,
    /// Model-estimated plausibility in parts per million (`0..=1_000_000`).
    /// Never overrides [`ProtectedWorldSpec`]!
    pub plausibility_ppm: u32,
    /// Optional high-loss protection tag (MUST be present when `disposition == ProtectedHighLoss`).
    pub protected_world: Option<ProtectedWorldSpec>,
    /// Owning semantic plane.
    pub plane: Plane,
}

impl WorldFactorSpec {
    /// Validates orthogonal field invariants fail-closed.
    pub fn validate(&self) -> Result<(), TypedUniverseError> {
        validate_clean_label(&self.factor_id, "factor_id")?;
        if self.plausibility_ppm > 1_000_000 {
            return Err(TypedUniverseError::InvalidInput(format!(
                "plausibility_ppm {} > 1_000_000 on '{}'",
                self.plausibility_ppm, self.factor_id
            )));
        }
        if self.disposition == WorldHypothesisDisposition::ProtectedHighLoss
            && self.protected_world.is_none()
        {
            return Err(TypedUniverseError::InvalidInput(format!(
                "ProtectedHighLoss factor '{}' must carry ProtectedWorldSpec",
                self.factor_id
            )));
        }
        if let Some(ref pw) = self.protected_world
            && (pw.loss_severity_bps == 0 || pw.loss_severity_bps > 10_000)
        {
            return Err(TypedUniverseError::InvalidInput(format!(
                "invalid loss_severity_bps on '{}'",
                self.factor_id
            )));
        }
        Ok(())
    }

    /// True iff this factor represents a protected high-loss world that cannot be deleted without proof.
    #[must_use]
    pub fn is_unproven_protected_world(&self) -> bool {
        self.protected_world
            .as_ref()
            .is_some_and(|pw| !pw.has_explicit_elimination_proof())
    }

    /// Canonical SHA-256 commitment for this factor.
    #[must_use]
    pub fn factor_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        hash_domain_tag(G_WORLD_DIGEST_DOMAIN, 1, &enc.finish())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.factor_id);
        enc.u8(self.kind as u8);
        enc.u8(self.knowledge_state as u8);
        enc.u8(self.provenance_class as u8);
        enc.u8(self.disposition as u8);
        enc.u32(self.plausibility_ppm);
        match &self.protected_world {
            Some(pw) => {
                enc.u8(1);
                enc.u32(u32::from(pw.loss_severity_bps));
                match pw.impossibility_proof {
                    Some(d) => {
                        enc.u8(1);
                        enc.digest(d);
                    }
                    None => enc.u8(0),
                }
                match pw.safe_dominance_proof {
                    Some(d) => {
                        enc.u8(1);
                        enc.digest(d);
                    }
                    None => enc.u8(0),
                }
            }
            None => enc.u8(0),
        }
        self.plane.encode_canonical(enc);
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, TypedUniverseError> {
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let factor_id = dec.text().map_err(map_err)?.to_owned();
        let kind = WorldFactorKind::from_tag(dec.u8().map_err(map_err)?)?;
        let knowledge_state = WorldKnowledgeState::from_tag(dec.u8().map_err(map_err)?)?;
        let provenance_class = WorldProvenanceClass::from_tag(dec.u8().map_err(map_err)?)?;
        let disposition = WorldHypothesisDisposition::from_tag(dec.u8().map_err(map_err)?)?;
        let plausibility_ppm = dec.u32().map_err(map_err)?;
        let protected_world = match dec.u8().map_err(map_err)? {
            0 => None,
            1 => {
                let loss_severity_bps =
                    u16::try_from(dec.u32().map_err(map_err)?).map_err(|_| {
                        TypedUniverseError::MalformedWire("loss_severity_bps overflow".to_owned())
                    })?;
                let impossibility_proof = match dec.u8().map_err(map_err)? {
                    0 => None,
                    1 => Some(dec.digest().map_err(map_err)?),
                    _ => {
                        return Err(TypedUniverseError::MalformedWire(
                            "invalid impossibility_proof flag".to_owned(),
                        ));
                    }
                };
                let safe_dominance_proof = match dec.u8().map_err(map_err)? {
                    0 => None,
                    1 => Some(dec.digest().map_err(map_err)?),
                    _ => {
                        return Err(TypedUniverseError::MalformedWire(
                            "invalid safe_dominance_proof flag".to_owned(),
                        ));
                    }
                };
                Some(ProtectedWorldSpec {
                    loss_severity_bps,
                    impossibility_proof,
                    safe_dominance_proof,
                })
            }
            _ => {
                return Err(TypedUniverseError::MalformedWire(
                    "invalid protected_world flag".to_owned(),
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
        let factor = Self {
            factor_id,
            kind,
            knowledge_state,
            provenance_class,
            disposition,
            plausibility_ppm,
            protected_world,
            plane,
        };
        factor.validate()?;
        Ok(factor)
    }
}

/// Directed factor relation inside `G_world`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WorldFactorEdge {
    /// Source factor ID.
    pub source_id: String,
    /// Target factor ID.
    pub target_id: String,
    /// Semantic relation label (`contradicts`, `assumes`, `constrains`, `exposes_unsafe`, `collapses_branch`).
    pub relation: String,
}

impl WorldFactorEdge {
    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.source_id);
        enc.text(&self.target_id);
        enc.text(&self.relation);
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, TypedUniverseError> {
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let source_id = dec.text().map_err(map_err)?.to_owned();
        let target_id = dec.text().map_err(map_err)?.to_owned();
        let relation = dec.text().map_err(map_err)?.to_owned();
        validate_clean_label(&source_id, "source_id")?;
        validate_clean_label(&target_id, "target_id")?;
        validate_clean_label(&relation, "relation")?;
        Ok(Self {
            source_id,
            target_id,
            relation,
        })
    }
}

/// Incremental ordered delta applied to `G_world`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorldDelta {
    /// Upsert a world factor.
    UpsertFactor(WorldFactorSpec),
    /// Attempt to remove a factor (REFUSED fail-closed if unproven protected high-loss world!).
    RemoveFactor(String),
    /// Add a directed factor edge.
    AddEdge(WorldFactorEdge),
    /// Remove a directed factor edge.
    RemoveEdge(WorldFactorEdge),
}

/// Six exact non-collapsed affordance classifications against a `WorldEnvelope`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AffordanceClass {
    /// Safe across ALL surviving supported AND protected high-loss worlds.
    Robust = 1,
    /// Safe only under specific worlds; explicitly names unsafe worlds (invalidated if unsafe world persists).
    Conditional = 2,
    /// Purely information-gathering probe that collapses competing branches without unsafe side effects.
    InformationGathering = 3,
    /// Bounded wait/watch posture while awaiting resolving evidence.
    WaitWatch = 4,
    /// Blocked by hard constraint, active safety clamp, or unresolved high-loss unsafe world.
    Blocked = 5,
    /// Required capability/sensor/oracle unavailable.
    Unavailable = 6,
}

/// Candidate action submitted for classification against `G_world`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateWorldAction {
    /// Stable unique action identifier.
    pub action_id: String,
    /// Worlds/factors where this action is supported.
    pub supported_worlds: BTreeSet<String>,
    /// Worlds/factors where executing this action would cause unsafe harm.
    pub unsafe_worlds: BTreeSet<String>,
    /// True if this action is a non-mutating information-gathering probe.
    pub is_information_gathering_probe: bool,
    /// True if this action is a bounded wait/watch posture.
    pub is_wait_watch: bool,
    /// True if required capability/sensor is currently available.
    pub capability_available: bool,
    /// True if hard policy/safety clamp blocks this action.
    pub hard_clamped: bool,
}

/// Classified affordance result against one exact `WorldEnvelope`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassifiedWorldAffordance {
    /// Action identifier.
    pub action_id: String,
    /// Exact classification (`Robust`, `Conditional`, `InformationGathering`, `WaitWatch`, `Blocked`, `Unavailable`).
    pub classification: AffordanceClass,
    /// Surviving worlds supporting this action.
    pub supported_worlds: Vec<String>,
    /// Surviving worlds (including protected high-loss worlds!) where this action is unsafe.
    pub active_unsafe_worlds: Vec<String>,
    /// Protected high-loss worlds explicitly checked against this action.
    pub checked_protected_worlds: Vec<String>,
}

/// Compressed/reranked/handoff projection of `G_world` proving protected-world survival.
#[derive(Clone, Debug, PartialEq)]
pub struct WorldHandoffProjection {
    /// Exact `WorldEnvelope` digest bound at handoff time.
    pub world_envelope_digest: ContentDigest,
    /// Retained factors (sorted by rank, ALWAYS including every unproven protected high-loss world!).
    pub retained_factors: Vec<WorldFactorSpec>,
    /// Factors dropped strictly from non-protected low-priority pool under budget pressure.
    pub dropped_non_protected_ids: Vec<String>,
    /// Explicit IDs of protected high-loss worlds forcibly preserved despite low probability/rerank!
    pub preserved_protected_worlds: Vec<String>,
    /// Always `false`: handoff projection grants zero effect authority.
    pub grants_effect_authority: bool,
    /// Certified execution witness.
    pub witness: GraphAlgorithmWitness,
}

/// Plan bound strictly to one `world_envelope_digest` naming supported and unsafe worlds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldBoundPlan {
    /// Plan identifier.
    pub plan_id: String,
    /// Bound action identifier.
    pub action_id: String,
    /// Classification at plan creation time.
    pub classification: AffordanceClass,
    /// Exact `WorldEnvelope` digest bound at plan creation time.
    pub bound_world_envelope_digest: ContentDigest,
    /// Worlds explicitly named as supported.
    pub supported_worlds: Vec<String>,
    /// Worlds explicitly named as unsafe.
    pub unsafe_worlds: Vec<String>,
    /// Always `false`: plan binding carries zero effect authority.
    pub grants_effect_authority: bool,
    /// Canonical plan binding digest.
    pub plan_digest: ContentDigest,
}

/// Outcome of revalidating a [`WorldBoundPlan`] against a current `G_world`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanRevalidationOutcome {
    /// Plan remains valid against exact unchanged envelope.
    Valid,
    /// Envelope drifted (stale digest) or new contradiction / protected unsafe world invalidated plan!
    Invalidated {
        /// Exact invalidation reasons.
        reasons: Vec<String>,
    },
}

/// Anchor-pinned, capability-filtered Possible-World & Robust-Control Factor Graph (`G_world`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldFactorGraph {
    projection_id: String,
    policy_generation: Generation,
    projection: ImmutableGraphProjection,
    visible_factors: BTreeMap<String, WorldFactorSpec>,
    visible_edges: BTreeSet<WorldFactorEdge>,
    tombstoned_fields: Vec<String>,
    world_envelope_digest: ContentDigest,
}

impl WorldFactorGraph {
    /// Builds a factorized `G_world` projection from ordered `EvidenceDeltaBatch`-derived factors.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        projection_id: impl Into<String>,
        policy_generation: Generation,
        anchor: LedgerAnchor,
        history_root: ContentDigest,
        authority: &ProjectionAuthorityScope,
        factors: Vec<WorldFactorSpec>,
        edges: Vec<WorldFactorEdge>,
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
        if factors.len() > MAX_UNIVERSE_ITEMS || edges.len() > MAX_UNIVERSE_ITEMS * 4 {
            return Err(TypedUniverseError::InvalidInput(
                "G_world size exceeds hard ceiling".to_owned(),
            ));
        }

        let mut raw_factors: BTreeMap<String, WorldFactorSpec> = BTreeMap::new();
        for factor in factors {
            if is_cancelled() {
                return Err(TypedUniverseError::Cancelled);
            }
            factor.validate()?;
            if raw_factors.contains_key(&factor.factor_id) {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "duplicate world factor_id '{}'",
                    factor.factor_id
                )));
            }
            raw_factors.insert(factor.factor_id.clone(), factor);
        }

        let mut raw_edges: BTreeSet<WorldFactorEdge> = BTreeSet::new();
        for edge in edges {
            validate_clean_label(&edge.source_id, "source_id")?;
            validate_clean_label(&edge.target_id, "target_id")?;
            validate_clean_label(&edge.relation, "relation")?;
            if !raw_factors.contains_key(&edge.source_id)
                || !raw_factors.contains_key(&edge.target_id)
            {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "unknown world edge endpoint '{}' -> '{}'",
                    edge.source_id, edge.target_id
                )));
            }
            raw_edges.insert(edge);
        }

        let proj_nodes: Vec<ProjectionNodeSpec> = raw_factors
            .values()
            .map(|f| ProjectionNodeSpec {
                node_id: f.factor_id.clone(),
                plane: f.plane,
                payload_digest: f.factor_digest(),
            })
            .collect();
        let proj_edges: Vec<ProjectionEdgeSpec> = raw_edges
            .iter()
            .map(|e| ProjectionEdgeSpec {
                source_id: e.source_id.clone(),
                target_id: e.target_id.clone(),
                relation: e.relation.clone(),
                weight: 1,
            })
            .collect();

        let projection = ImmutableGraphProjection::build(
            GraphUniverse::GWorld,
            ProjectionOrientation::Directed,
            anchor,
            history_root,
            authority,
            proj_nodes,
            proj_edges,
            requested_absence,
            is_cancelled(),
        )?;

        let visible_factors: BTreeMap<String, WorldFactorSpec> = raw_factors
            .into_iter()
            .filter(|(id, _)| projection.handle_for_node_id(id).is_some())
            .collect();
        let visible_edges: BTreeSet<WorldFactorEdge> = raw_edges
            .into_iter()
            .filter(|e| {
                visible_factors.contains_key(&e.source_id)
                    && visible_factors.contains_key(&e.target_id)
            })
            .collect();

        let world_envelope_digest = Self::compute_digest(
            &projection_id,
            policy_generation,
            &projection,
            &visible_factors,
            &visible_edges,
        );
        Ok(Self {
            projection_id,
            policy_generation,
            projection,
            visible_factors,
            visible_edges,
            tombstoned_fields: Vec::new(),
            world_envelope_digest,
        })
    }

    /// Incrementally applies ordered `WorldDelta` entries while REFUSING deletion of any
    /// unproven protected high-loss world!
    #[allow(clippy::too_many_arguments)]
    pub fn apply_deltas(
        &self,
        new_anchor: LedgerAnchor,
        new_history_root: ContentDigest,
        expected_policy_generation: Generation,
        authority: &ProjectionAuthorityScope,
        deltas: &[WorldDelta],
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
        let mut factors = self.visible_factors.clone();
        let mut edges = self.visible_edges.clone();
        for delta in deltas {
            match delta {
                WorldDelta::UpsertFactor(f) => {
                    f.validate()?;
                    // Cannot strip protection from an existing protected high-loss world without proof!
                    if let Some(prev) = factors.get(&f.factor_id)
                        && prev.is_unproven_protected_world()
                        && !f.is_unproven_protected_world()
                        && f.protected_world
                            .as_ref()
                            .is_none_or(|pw| !pw.has_explicit_elimination_proof())
                    {
                        return Err(TypedUniverseError::ProtectedWorldDeletionForbidden(
                            format!(
                                "cannot strip high-loss protection from '{}' without impossibility/dominance proof",
                                f.factor_id
                            ),
                        ));
                    }
                    factors.insert(f.factor_id.clone(), f.clone());
                }
                WorldDelta::RemoveFactor(id) => {
                    if let Some(existing) = factors.get(id)
                        && existing.is_unproven_protected_world()
                    {
                        return Err(TypedUniverseError::ProtectedWorldDeletionForbidden(
                            format!(
                                "cannot remove protected high-loss world '{id}' without impossibility/dominance proof"
                            ),
                        ));
                    }
                    factors.remove(id);
                    edges.retain(|e| e.source_id != *id && e.target_id != *id);
                }
                WorldDelta::AddEdge(e) => {
                    edges.insert(e.clone());
                }
                WorldDelta::RemoveEdge(e) => {
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
            factors.into_values().collect(),
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

    /// Exact `WorldEnvelope` commitment digest bound by plans and handoffs.
    #[must_use]
    pub const fn world_envelope_digest(&self) -> ContentDigest {
        self.world_envelope_digest
    }

    /// Visible factors in canonical order.
    #[must_use]
    pub const fn visible_factors(&self) -> &BTreeMap<String, WorldFactorSpec> {
        &self.visible_factors
    }

    /// Tombstoned legacy fields recorded during any `v1 -> v2` migration.
    #[must_use]
    pub fn tombstoned_fields(&self) -> &[String] {
        &self.tombstoned_fields
    }

    /// Derived `WorldEnvelope` cognition NEVER grants effect authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Projects a compressed/reranked handoff view capped to `max_retained_factors`.
    ///
    /// **Protected-world survival invariant:** Every unproven protected high-loss world MUST
    /// survive reranking, compression, budget pressure, transfer, and handoff. If the caller's
    /// `max_retained_factors` is smaller than the count of unproven protected high-loss worlds,
    /// this fails closed with [`TypedUniverseError::ProtectedWorldDeletionForbidden`] rather than
    /// silently dropping a protected world!
    pub fn project_compressed_handoff(
        &self,
        max_retained_factors: usize,
        rerank_overrides_ppm: &BTreeMap<String, u32>,
        max_operations: u64,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<WorldHandoffProjection, TypedUniverseError> {
        let mut budget = OpBudget::new(max_operations)?;
        let mut protected: Vec<WorldFactorSpec> = Vec::new();
        let mut non_protected: Vec<(u32, WorldFactorSpec)> = Vec::new();

        for factor in self.visible_factors.values() {
            budget.charge(1, &mut is_cancelled)?;
            if factor.is_unproven_protected_world() {
                protected.push(factor.clone());
            } else {
                let rank_score = rerank_overrides_ppm
                    .get(&factor.factor_id)
                    .copied()
                    .unwrap_or(factor.plausibility_ppm);
                non_protected.push((rank_score, factor.clone()));
            }
        }

        if max_retained_factors < protected.len() {
            return Err(TypedUniverseError::ProtectedWorldDeletionForbidden(
                format!(
                    "compression budget {max_retained_factors} cannot hide {} unproven protected high-loss worlds",
                    protected.len()
                ),
            ));
        }

        // Sort protected worlds deterministically by (descending loss severity, factor_id).
        protected.sort_by(|a, b| {
            let la = a
                .protected_world
                .as_ref()
                .map_or(0, |p| p.loss_severity_bps);
            let lb = b
                .protected_world
                .as_ref()
                .map_or(0, |p| p.loss_severity_bps);
            lb.cmp(&la).then_with(|| a.factor_id.cmp(&b.factor_id))
        });

        // Sort non-protected factors by (descending rerank score, factor_id) and fill remaining budget.
        non_protected.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| a.1.factor_id.cmp(&b.1.factor_id))
        });

        let remaining_slots = max_retained_factors - protected.len();
        let preserved_protected_worlds: Vec<String> =
            protected.iter().map(|f| f.factor_id.clone()).collect();
        let mut retained_factors = protected;
        let mut dropped_non_protected_ids = Vec::new();
        for (idx, (_, factor)) in non_protected.into_iter().enumerate() {
            budget.charge(1, &mut is_cancelled)?;
            if idx < remaining_slots {
                retained_factors.push(factor);
            } else {
                dropped_non_protected_ids.push(factor.factor_id);
            }
        }

        let mut path_enc = CanonicalEncoder::new();
        path_enc.u64(max_retained_factors as u64);
        path_enc.u64(preserved_protected_worlds.len() as u64);
        for id in &preserved_protected_worlds {
            path_enc.text(id);
        }
        let decision_path_digest = hash_domain_tag(G_WORLD_DIGEST_DOMAIN, 2, &path_enc.finish());

        let mut out_enc = CanonicalEncoder::new();
        out_enc.digest(self.world_envelope_digest);
        out_enc.u64(retained_factors.len() as u64);
        for f in &retained_factors {
            out_enc.digest(f.factor_digest());
        }
        let output_digest = hash_domain_tag(G_WORLD_DIGEST_DOMAIN, 3, &out_enc.finish());

        let witness = build_universe_witness(
            G_WORLD_ALGORITHM_ID,
            G_WORLD_IMPLEMENTATION_ID,
            GraphUniverse::GWorld,
            &self.projection_id,
            self.projection.anchor(),
            self.projection.node_count(),
            self.projection.edge_count(),
            self.world_envelope_digest,
            G_WORLD_POLICY_ID,
            budget.used(),
            ((self.visible_factors.len() + 1) * 160) as u64,
            decision_path_digest,
            output_digest,
        )?;

        Ok(WorldHandoffProjection {
            world_envelope_digest: self.world_envelope_digest,
            retained_factors,
            dropped_non_protected_ids,
            preserved_protected_worlds,
            grants_effect_authority: false,
            witness,
        })
    }

    /// Classifies candidate actions against the exact `WorldEnvelope` without hiding any active
    /// protected high-loss unsafe world!
    pub fn classify_affordances(
        &self,
        candidates: &[CandidateWorldAction],
        max_operations: u64,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<(Vec<ClassifiedWorldAffordance>, GraphAlgorithmWitness), TypedUniverseError> {
        let mut budget = OpBudget::new(max_operations)?;
        let protected_ids: Vec<String> = self
            .visible_factors
            .values()
            .filter(|f| f.is_unproven_protected_world())
            .map(|f| f.factor_id.clone())
            .collect();

        // Canonicalize candidate order & reject duplicates BEFORE hashing decision_path_digest
        // so affordance classification is 100% insertion-order-invariant (CGSE tie-break!).
        let mut sorted_candidates: Vec<&CandidateWorldAction> = candidates.iter().collect();
        sorted_candidates.sort_by(|a, b| a.action_id.cmp(&b.action_id));
        for pair in sorted_candidates.windows(2) {
            if pair[0].action_id == pair[1].action_id {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "duplicate action_id '{}'",
                    pair[0].action_id
                )));
            }
        }

        let mut results = Vec::with_capacity(sorted_candidates.len());
        let mut path_enc = CanonicalEncoder::new();
        for cand in sorted_candidates {
            budget.charge(1, &mut is_cancelled)?;
            validate_clean_label(&cand.action_id, "action_id")?;

            let active_supported: Vec<String> = cand
                .supported_worlds
                .iter()
                .filter(|id| {
                    self.visible_factors
                        .get(*id)
                        .is_some_and(|f| f.disposition != WorldHypothesisDisposition::Refuted)
                })
                .cloned()
                .collect();
            let active_unsafe: Vec<String> = cand
                .unsafe_worlds
                .iter()
                .filter(|id| {
                    self.visible_factors
                        .get(*id)
                        .is_some_and(|f| f.disposition != WorldHypothesisDisposition::Refuted)
                })
                .cloned()
                .collect();
            let hits_protected_unsafe = active_unsafe.iter().any(|id| {
                self.visible_factors
                    .get(id)
                    .is_some_and(WorldFactorSpec::is_unproven_protected_world)
            });

            let classification = if !cand.capability_available {
                AffordanceClass::Unavailable
            } else if cand.hard_clamped || hits_protected_unsafe {
                AffordanceClass::Blocked
            } else if cand.is_information_gathering_probe {
                AffordanceClass::InformationGathering
            } else if cand.is_wait_watch {
                AffordanceClass::WaitWatch
            } else if active_unsafe.is_empty() && !active_supported.is_empty() {
                AffordanceClass::Robust
            } else {
                AffordanceClass::Conditional
            };

            path_enc.text(&cand.action_id);
            path_enc.u8(classification as u8);
            results.push(ClassifiedWorldAffordance {
                action_id: cand.action_id.clone(),
                classification,
                supported_worlds: active_supported,
                active_unsafe_worlds: active_unsafe,
                checked_protected_worlds: protected_ids.clone(),
            });
        }
        results.sort_by(|a, b| a.action_id.cmp(&b.action_id));

        let decision_path_digest = hash_domain_tag(G_WORLD_DIGEST_DOMAIN, 4, &path_enc.finish());
        let mut out_enc = CanonicalEncoder::new();
        out_enc.digest(self.world_envelope_digest);
        out_enc.u64(results.len() as u64);
        for r in &results {
            out_enc.text(&r.action_id);
            out_enc.u8(r.classification as u8);
        }
        let output_digest = hash_domain_tag(G_WORLD_DIGEST_DOMAIN, 5, &out_enc.finish());
        let witness = build_universe_witness(
            G_WORLD_ALGORITHM_ID,
            G_WORLD_IMPLEMENTATION_ID,
            GraphUniverse::GWorld,
            &self.projection_id,
            self.projection.anchor(),
            self.projection.node_count(),
            self.projection.edge_count(),
            self.world_envelope_digest,
            G_WORLD_POLICY_ID,
            budget.used(),
            ((results.len() + self.visible_factors.len() + 1) * 160) as u64,
            decision_path_digest,
            output_digest,
        )?;
        Ok((results, witness))
    }

    /// Binds a plan strictly to `self.world_envelope_digest`, explicitly naming supported and
    /// unsafe worlds (refuses `Blocked` or `Unavailable` actions fail-closed!).
    pub fn bind_plan(
        &self,
        plan_id: impl Into<String>,
        affordance: &ClassifiedWorldAffordance,
    ) -> Result<WorldBoundPlan, TypedUniverseError> {
        let plan_id = plan_id.into();
        validate_clean_label(&plan_id, "plan_id")?;
        if matches!(
            affordance.classification,
            AffordanceClass::Blocked | AffordanceClass::Unavailable
        ) {
            return Err(TypedUniverseError::InvalidInput(format!(
                "cannot bind plan '{}' to {:?} affordance '{}'",
                plan_id, affordance.classification, affordance.action_id
            )));
        }
        // Verify affordance was checked against ALL currently active unproven protected worlds
        // and does not hit any active unproven protected unsafe world!
        let checked_set: BTreeSet<&str> = affordance
            .checked_protected_worlds
            .iter()
            .map(String::as_str)
            .collect();
        for factor in self.visible_factors.values() {
            if factor.is_unproven_protected_world()
                && !checked_set.contains(factor.factor_id.as_str())
            {
                return Err(TypedUniverseError::MixedAnchorOrGeneration(format!(
                    "stale affordance '{}' omitted active protected world '{}'",
                    affordance.action_id, factor.factor_id
                )));
            }
        }
        for unsafe_id in &affordance.active_unsafe_worlds {
            if self
                .visible_factors
                .get(unsafe_id)
                .is_some_and(WorldFactorSpec::is_unproven_protected_world)
            {
                return Err(TypedUniverseError::ProtectedWorldDeletionForbidden(
                    format!(
                        "cannot bind plan '{}' against active protected unsafe world '{unsafe_id}'",
                        plan_id
                    ),
                ));
            }
        }
        let mut enc = CanonicalEncoder::new();
        enc.text(&plan_id);
        enc.text(&affordance.action_id);
        enc.u8(affordance.classification as u8);
        enc.digest(self.world_envelope_digest);
        enc.u64(affordance.supported_worlds.len() as u64);
        for w in &affordance.supported_worlds {
            enc.text(w);
        }
        enc.u64(affordance.active_unsafe_worlds.len() as u64);
        for w in &affordance.active_unsafe_worlds {
            enc.text(w);
        }
        let plan_digest = hash_domain_tag(G_WORLD_DIGEST_DOMAIN, 6, &enc.finish());
        Ok(WorldBoundPlan {
            plan_id,
            action_id: affordance.action_id.clone(),
            classification: affordance.classification,
            bound_world_envelope_digest: self.world_envelope_digest,
            supported_worlds: affordance.supported_worlds.clone(),
            unsafe_worlds: affordance.active_unsafe_worlds.clone(),
            grants_effect_authority: false,
            plan_digest,
        })
    }

    /// Revalidates a [`WorldBoundPlan`] against the current `G_world`, detecting stale envelope
    /// digests, newly added contradictions, or newly exposed protected high-loss worlds!
    #[must_use]
    pub fn revalidate_plan(&self, plan: &WorldBoundPlan) -> PlanRevalidationOutcome {
        let mut reasons = Vec::new();
        if plan.bound_world_envelope_digest != self.world_envelope_digest {
            reasons.push("stale_world_envelope_digest".to_owned());
        }
        for w in &plan.supported_worlds {
            match self.visible_factors.get(w) {
                None => reasons.push(format!("supported_world_missing:{w}")),
                Some(f)
                    if matches!(
                        f.knowledge_state,
                        WorldKnowledgeState::Conflicted | WorldKnowledgeState::Stale
                    ) || f.disposition == WorldHypothesisDisposition::Refuted =>
                {
                    reasons.push(format!("supported_world_contradicted_or_refuted:{w}"));
                }
                _ => {}
            }
        }
        for w in &plan.unsafe_worlds {
            if self
                .visible_factors
                .get(w)
                .is_some_and(WorldFactorSpec::is_unproven_protected_world)
            {
                reasons.push(format!("protected_unsafe_world_active:{w}"));
            }
        }
        if reasons.is_empty() {
            PlanRevalidationOutcome::Valid
        } else {
            PlanRevalidationOutcome::Invalidated { reasons }
        }
    }

    /// Serializes `G_world` into its versioned checksummed wire format (`v2`).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(CURRENT_UNIVERSE_WIRE_VERSION, false)
    }

    /// Serializes a compatible legacy `v1` fixture carrying a removed `legacy_rank_drop_ok` flag.
    pub fn to_legacy_v1_fixture_bytes(
        &self,
        legacy_rank_drop_ok: bool,
    ) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(LEGACY_UNIVERSE_WIRE_VERSION, legacy_rank_drop_ok)
    }

    fn encode_versioned(
        &self,
        version: u32,
        legacy_rank_drop_ok: bool,
    ) -> Result<Vec<u8>, TypedUniverseError> {
        let proj_bytes = self.projection.to_canonical_bytes()?;
        let mut enc = CanonicalEncoder::new();
        enc.text(&self.projection_id);
        enc.u64(self.policy_generation.0);
        enc.bytes(&proj_bytes);
        enc.u64(self.visible_factors.len() as u64);
        for factor in self.visible_factors.values() {
            factor.encode_body(&mut enc);
        }
        enc.u64(self.visible_edges.len() as u64);
        for edge in &self.visible_edges {
            edge.encode_body(&mut enc);
        }
        if version == LEGACY_UNIVERSE_WIRE_VERSION {
            enc.u8(u8::from(legacy_rank_drop_ok));
        } else {
            enc.u64(self.tombstoned_fields.len() as u64);
            for t in &self.tombstoned_fields {
                enc.text(t);
            }
        }
        let payload = enc
            .finish_checked()
            .map_err(|e| TypedUniverseError::MalformedWire(e.to_string()))?;
        seal_wire_envelope(G_WORLD_WIRE_MAGIC, version, G_WORLD_DIGEST_DOMAIN, &payload)
    }

    /// Opens a `v1` (migrating deterministically with tombstones) or `v2` durable `G_world` fixture.
    pub fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<(Self, UniverseMigrationReport), TypedUniverseError> {
        let (version, payload) =
            open_wire_envelope(bytes, G_WORLD_WIRE_MAGIC, G_WORLD_DIGEST_DOMAIN)?;
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
        if projection.universe() != GraphUniverse::GWorld {
            return Err(TypedUniverseError::MalformedWire(
                "embedded projection universe is not G_world".to_owned(),
            ));
        }
        let f_len = usize::try_from(dec.u64().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("factor count overflow".to_owned()))?;
        if f_len > MAX_UNIVERSE_ITEMS || f_len.saturating_mul(16) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "factor count out of wire bounds".to_owned(),
            ));
        }
        let mut visible_factors = BTreeMap::new();
        for _ in 0..f_len {
            let factor = WorldFactorSpec::decode_body(&mut dec)?;
            if visible_factors.contains_key(&factor.factor_id) {
                return Err(TypedUniverseError::MalformedWire(
                    "duplicate world factor_id in wire fixture".to_owned(),
                ));
            }
            let Some(handle) = projection.handle_for_node_id(&factor.factor_id) else {
                return Err(TypedUniverseError::MalformedWire(
                    "wire world factor missing from embedded G_world projection".to_owned(),
                ));
            };
            if projection.node(handle)?.payload_digest != factor.factor_digest() {
                return Err(TypedUniverseError::MalformedWire(
                    "wire world factor digest disagrees with embedded projection".to_owned(),
                ));
            }
            visible_factors.insert(factor.factor_id.clone(), factor);
        }
        let e_len = usize::try_from(dec.u64().map_err(map_err)?)
            .map_err(|_| TypedUniverseError::MalformedWire("edge count overflow".to_owned()))?;
        if e_len > MAX_UNIVERSE_ITEMS * 4 || e_len.saturating_mul(12) > dec.remaining() {
            return Err(TypedUniverseError::MalformedWire(
                "edge count out of wire bounds".to_owned(),
            ));
        }
        let mut visible_edges = BTreeSet::new();
        for _ in 0..e_len {
            let edge = WorldFactorEdge::decode_body(&mut dec)?;
            if !visible_factors.contains_key(&edge.source_id)
                || !visible_factors.contains_key(&edge.target_id)
            {
                return Err(TypedUniverseError::MalformedWire(
                    "wire world edge references unknown factor".to_owned(),
                ));
            }
            visible_edges.insert(edge);
        }
        let (migrated, tombstoned_fields) = if version == LEGACY_UNIVERSE_WIRE_VERSION {
            let _deprecated_flag = dec.u8().map_err(map_err)?;
            (
                true,
                vec!["v1.legacy_rank_drop_ok:tombstoned_protected_worlds_must_survive".to_owned()],
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

        let world_envelope_digest = Self::compute_digest(
            &projection_id,
            policy_generation,
            &projection,
            &visible_factors,
            &visible_edges,
        );
        let report = UniverseMigrationReport {
            source_version: version,
            target_version: CURRENT_UNIVERSE_WIRE_VERSION,
            migrated,
            tombstoned_fields: tombstoned_fields.clone(),
            universe_digest: world_envelope_digest,
        };
        Ok((
            Self {
                projection_id,
                policy_generation,
                projection,
                visible_factors,
                visible_edges,
                tombstoned_fields,
                world_envelope_digest,
            },
            report,
        ))
    }

    fn compute_digest(
        projection_id: &str,
        policy_generation: Generation,
        projection: &ImmutableGraphProjection,
        visible_factors: &BTreeMap<String, WorldFactorSpec>,
        visible_edges: &BTreeSet<WorldFactorEdge>,
    ) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text(projection_id);
        enc.u64(policy_generation.0);
        enc.digest(projection.generation().projection_digest);
        enc.u64(visible_factors.len() as u64);
        for factor in visible_factors.values() {
            enc.digest(factor.factor_digest());
        }
        enc.u64(visible_edges.len() as u64);
        for edge in visible_edges {
            edge.encode_body(&mut enc);
        }
        hash_domain_tag(G_WORLD_DIGEST_DOMAIN, 0, &enc.finish())
    }
}
