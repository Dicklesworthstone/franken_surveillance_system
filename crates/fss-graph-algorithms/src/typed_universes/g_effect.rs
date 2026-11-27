#![forbid(unsafe_code)]
//! Effect and obligation graph `G_effect` (`PROJ-EFFECT-001`, `fss-x4a.23.69.7`).
//!
//! Represents prepared intents, capability grants, leases, dispatch attempts, callbacks,
//! observations, verification predicates, compensations, cleanup obligations, and non-authoritative
//! recommendation/plan edges. Typed edges are strictly `must-precede`, `owns`, `fences`,
//! `waits-for`, `compensates`, `verifies`, and `blocks` (plus explicitly non-authoritative
//! `recommends`).
//!
//! Computes exact wait-cycle/deadlock detection, acyclic critical path & slack, cancellation
//! potential, and honest completion verdicts — proving that `Dispatched`, `Observed`, `Verified`,
//! and `Indeterminate` remain strictly distinct and no cycle, stale fence, missing observation, or
//! indeterminate dispatch can ever be reported complete.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    Generation, GraphAlgorithmWitness, LedgerAnchor, Plane,
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

/// Registered digest domain for `G_effect` projections and witnesses
/// (`SCHEMA-DOMAIN-GRAPH-G-EFFECT-001`).
pub const G_EFFECT_DIGEST_DOMAIN: &str = "fss.graph.g_effect_projection.v1";
/// Wire magic for durable `G_effect` fixtures (`FSSGEF01`).
pub const G_EFFECT_WIRE_MAGIC: [u8; 8] = *b"FSSGEF01";
/// Registered algorithm ID emitted in `G_effect` witnesses.
pub const G_EFFECT_ALGORITHM_ID: &str = "ALG-PROJ-EFFECT-001";
/// Implementation generation recorded in `G_effect` witnesses.
pub const G_EFFECT_IMPLEMENTATION_ID: &str =
    "fss-graph-algorithms:proj-effect-001:g-effect-oracle:v2";
/// Policy identity recorded in `G_effect` witnesses.
pub const G_EFFECT_POLICY_ID: &str =
    "graph-policy:g-effect:directed-obligations:honest-completion:v2";

/// Closed taxonomy of node kinds in `G_effect`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EffectNodeKind {
    /// Prepared effect intent bound to an idempotency key and precondition.
    PreparedIntent = 1,
    /// Explicit scoped capability grant authorizing a commit.
    CapabilityGrant = 2,
    /// Active lease/fence protecting against stale concurrent actors.
    Lease = 3,
    /// Outbound dispatch attempt.
    DispatchAttempt = 4,
    /// Asynchronous provider callback/ACK.
    Callback = 5,
    /// External state observation proving world transition.
    Observation = 6,
    /// Verification predicate checking observed state against intent.
    VerificationPredicate = 7,
    /// Explicit compensation action on partial failure.
    Compensation = 8,
    /// Cleanup/drain obligation.
    CleanupObligation = 9,
    /// Advisory recommendation or plan (carries ZERO effect authority!).
    RecommendationPlan = 10,
}

impl EffectNodeKind {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::PreparedIntent),
            2 => Ok(Self::CapabilityGrant),
            3 => Ok(Self::Lease),
            4 => Ok(Self::DispatchAttempt),
            5 => Ok(Self::Callback),
            6 => Ok(Self::Observation),
            7 => Ok(Self::VerificationPredicate),
            8 => Ok(Self::Compensation),
            9 => Ok(Self::CleanupObligation),
            10 => Ok(Self::RecommendationPlan),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown EffectNodeKind tag {other}"
            ))),
        }
    }
}

/// Strictly non-collapsed lifecycle states of an effect/obligation node.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EffectObligationState {
    /// Prepared and revalidated, not yet dispatched (cleanly cancellable).
    Prepared = 1,
    /// Dispatched to external boundary, observation/verification not yet received!
    Dispatched = 2,
    /// Effect observed externally, verification predicate still pending!
    Observed = 3,
    /// Terminal verified completion backed by verification predicate.
    Verified = 4,
    /// Ambiguous outcome (lost ACK, timeout, split-brain); requires reconciliation!
    Indeterminate = 5,
    /// Compensated cleanly after failure.
    Compensated = 6,
    /// Cleanly drained and cancelled before dispatch.
    Cancelled = 7,
    /// Terminal failed (not yet compensated if compensation required).
    Failed = 8,
    /// Non-authoritative advisory recommendation only (never commits!).
    NonAuthoritativeRecommendation = 9,
}

impl EffectObligationState {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::Dispatched),
            3 => Ok(Self::Observed),
            4 => Ok(Self::Verified),
            5 => Ok(Self::Indeterminate),
            6 => Ok(Self::Compensated),
            7 => Ok(Self::Cancelled),
            8 => Ok(Self::Failed),
            9 => Ok(Self::NonAuthoritativeRecommendation),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown EffectObligationState tag {other}"
            ))),
        }
    }
}

/// Exact typed directed edge relations in `G_effect`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EffectEdgeKind {
    /// Ordering prerequisite (`a` must complete before `b`).
    MustPrecede = 1,
    /// Ownership relation (`owner` owns `obligation`).
    Owns = 2,
    /// Lease/fence protection (`lease` fences `intent/dispatch`).
    Fences = 3,
    /// Runtime wait dependency (`a` waits for `b`).
    WaitsFor = 4,
    /// Compensation link (`comp` compensates `failed_dispatch`).
    Compensates = 5,
    /// Verification link (`predicate/observation` verifies `dispatch`).
    Verifies = 6,
    /// Blocking dependency (`a` blocks `b`).
    Blocks = 7,
    /// Advisory recommendation edge — NEVER grants effect authority!
    Recommends = 8,
}

impl EffectEdgeKind {
    /// Stable canonical relation name in `ImmutableGraphProjection`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MustPrecede => "must-precede",
            Self::Owns => "owns",
            Self::Fences => "fences",
            Self::WaitsFor => "waits-for",
            Self::Compensates => "compensates",
            Self::Verifies => "verifies",
            Self::Blocks => "blocks",
            Self::Recommends => "recommends",
        }
    }

    /// True iff this edge kind participates in execution ordering / wait-cycle analysis.
    #[must_use]
    pub const fn is_ordering_or_wait(self) -> bool {
        matches!(self, Self::MustPrecede | Self::WaitsFor | Self::Blocks)
    }

    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::MustPrecede),
            2 => Ok(Self::Owns),
            3 => Ok(Self::Fences),
            4 => Ok(Self::WaitsFor),
            5 => Ok(Self::Compensates),
            6 => Ok(Self::Verifies),
            7 => Ok(Self::Blocks),
            8 => Ok(Self::Recommends),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown EffectEdgeKind tag {other}"
            ))),
        }
    }
}

/// One typed node in `G_effect` binding idempotency key, lease fence, anchor, owner, and state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectNodeSpec {
    /// Stable unique node identifier.
    pub node_id: String,
    /// Typed node kind.
    pub kind: EffectNodeKind,
    /// Exact idempotency key preventing duplicate effect commits.
    pub idempotency_key: String,
    /// Observed lease fence token attached to this node.
    pub lease_fence: u64,
    /// Expected active lease fence token (`lease_fence != expected_lease_fence` => stale fence!).
    pub expected_lease_fence: u64,
    /// Authority anchor bound to this node.
    pub authority_anchor: LedgerAnchor,
    /// Owning principal / actor identity.
    pub owner_principal: String,
    /// Estimated or observed execution duration in ms (for critical-path computation).
    pub duration_ms: u64,
    /// Strictly non-collapsed lifecycle state.
    pub state: EffectObligationState,
    /// Owning semantic plane (`Plane::Effect` for effects, `Plane::Cognition` for recommendations).
    pub plane: Plane,
}

impl EffectNodeSpec {
    /// Validates node invariants fail-closed.
    pub fn validate(&self) -> Result<(), TypedUniverseError> {
        validate_clean_label(&self.node_id, "node_id")?;
        validate_clean_label(&self.idempotency_key, "idempotency_key")?;
        validate_clean_label(&self.owner_principal, "owner_principal")?;
        validate_clean_label(&self.authority_anchor.site_lineage, "site_lineage")?;
        if self.kind == EffectNodeKind::RecommendationPlan
            && self.state != EffectObligationState::NonAuthoritativeRecommendation
        {
            return Err(TypedUniverseError::InvalidInput(format!(
                "recommendation node '{}' must remain NonAuthoritativeRecommendation",
                self.node_id
            )));
        }
        Ok(())
    }

    /// True iff this node carries a stale lease fence.
    #[must_use]
    pub const fn has_stale_fence(&self) -> bool {
        self.lease_fence != self.expected_lease_fence
    }

    /// Canonical SHA-256 commitment for this effect node.
    #[must_use]
    pub fn node_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        hash_domain_tag(G_EFFECT_DIGEST_DOMAIN, 1, &enc.finish())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.node_id);
        enc.u8(self.kind as u8);
        enc.text(&self.idempotency_key);
        enc.u64(self.lease_fence);
        enc.u64(self.expected_lease_fence);
        self.authority_anchor.encode_canonical(enc);
        enc.text(&self.owner_principal);
        enc.u64(self.duration_ms);
        enc.u8(self.state as u8);
        self.plane.encode_canonical(enc);
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, TypedUniverseError> {
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let node_id = dec.text().map_err(map_err)?.to_owned();
        let kind = EffectNodeKind::from_tag(dec.u8().map_err(map_err)?)?;
        let idempotency_key = dec.text().map_err(map_err)?.to_owned();
        let lease_fence = dec.u64().map_err(map_err)?;
        let expected_lease_fence = dec.u64().map_err(map_err)?;
        let authority_anchor = LedgerAnchor::decode_canonical(dec).map_err(map_err)?;
        let owner_principal = dec.text().map_err(map_err)?.to_owned();
        let duration_ms = dec.u64().map_err(map_err)?;
        let state = EffectObligationState::from_tag(dec.u8().map_err(map_err)?)?;
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
        let spec = Self {
            node_id,
            kind,
            idempotency_key,
            lease_fence,
            expected_lease_fence,
            authority_anchor,
            owner_principal,
            duration_ms,
            state,
            plane,
        };
        spec.validate()?;
        Ok(spec)
    }
}

/// One typed directed edge in `G_effect`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EffectEdgeSpec {
    /// Source node ID.
    pub source_id: String,
    /// Target node ID.
    pub target_id: String,
    /// Typed obligation edge kind.
    pub kind: EffectEdgeKind,
}

impl EffectEdgeSpec {
    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.source_id);
        enc.text(&self.target_id);
        enc.u8(self.kind as u8);
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, TypedUniverseError> {
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let source_id = dec.text().map_err(map_err)?.to_owned();
        let target_id = dec.text().map_err(map_err)?.to_owned();
        let kind = EffectEdgeKind::from_tag(dec.u8().map_err(map_err)?)?;
        validate_clean_label(&source_id, "source_id")?;
        validate_clean_label(&target_id, "target_id")?;
        Ok(Self {
            source_id,
            target_id,
            kind,
        })
    }
}

/// Incremental ordered delta applied to `G_effect`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectDelta {
    /// Upsert one effect/obligation node.
    UpsertNode(EffectNodeSpec),
    /// Remove a node (and any incident edges).
    RemoveNode(String),
    /// Add a typed obligation edge.
    AddEdge(EffectEdgeSpec),
    /// Remove a typed obligation edge.
    RemoveEdge(EffectEdgeSpec),
}

/// Honest non-collapsed completion verdict for `G_effect`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectCompletionVerdict {
    /// Every executable obligation is verified/compensated/cancelled with zero cycles, zero stale
    /// fences, zero indeterminate dispatches, and certified complete absence boundary.
    CompleteVerified,
    /// At least one wait cycle, stale fence, missing observation, unverified dispatch, or
    /// uncompensated failure blocks completion.
    IncompleteOrBlocked,
    /// At least one dispatch is `Indeterminate` (lost ACK / ambiguous boundary); reconciliation required!
    IndeterminateRequiresReconciliation,
}

/// Certified analysis of `G_effect`: cycles/deadlocks, critical path, cancellation potential,
/// and honest completion verdict backed by [`GraphAlgorithmWitness`].
#[derive(Clone, Debug, PartialEq)]
pub struct EffectObligationAnalysis {
    /// Honest non-collapsed completion verdict.
    pub verdict: EffectCompletionVerdict,
    /// Detected directed wait/deadlock cycles (each cycle is a canonically sorted SCC of size >= 2 or self-loop).
    pub deadlock_cycles: Vec<Vec<String>>,
    /// Nodes carrying stale lease fences (`lease_fence != expected_lease_fence`).
    pub stale_fence_nodes: Vec<String>,
    /// Dispatch nodes that are `Dispatched` or `Observed` without verified completion (no open-loop success!).
    pub unverified_dispatches: Vec<String>,
    /// Dispatch nodes in explicit `Indeterminate` state requiring reconciliation.
    pub indeterminate_nodes: Vec<String>,
    /// Failed nodes lacking a verified/compensated `Compensates` link.
    pub uncompensated_failures: Vec<String>,
    /// Duplicate idempotency keys shared across distinct dispatch attempts.
    pub duplicate_commit_keys: Vec<String>,
    /// Nodes cleanly cancellable via `request -> drain -> finalize` without post-dispatch reconciliation.
    pub cleanly_cancellable_nodes: Vec<String>,
    /// Critical path node IDs (present iff zero deadlock cycles exist).
    pub critical_path: Option<Vec<String>>,
    /// Total critical-path duration in ms (present iff zero deadlock cycles exist).
    pub critical_path_duration_ms: Option<u64>,
    /// Always `false`: derived graph analysis never authorizes an effect.
    pub grants_effect_authority: bool,
    /// Certified execution witness.
    pub witness: GraphAlgorithmWitness,
}

/// Anchor-pinned, capability-filtered Effect & Obligation Graph (`G_effect`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectObligationGraph {
    projection_id: String,
    policy_generation: Generation,
    projection: ImmutableGraphProjection,
    visible_nodes: BTreeMap<String, EffectNodeSpec>,
    visible_edges: BTreeSet<EffectEdgeSpec>,
    tombstoned_fields: Vec<String>,
    universe_digest: ContentDigest,
}

impl EffectObligationGraph {
    /// Builds `G_effect` from ordered `EvidenceDeltaBatch`-derived nodes and edges at one anchor.
    ///
    /// Refuses mixed site lineages, invalid node specs, and unauthorized `RecommendationPlan`
    /// edges claiming `Verifies` or `Fences` authority.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        projection_id: impl Into<String>,
        policy_generation: Generation,
        anchor: LedgerAnchor,
        history_root: ContentDigest,
        authority: &ProjectionAuthorityScope,
        nodes: Vec<EffectNodeSpec>,
        edges: Vec<EffectEdgeSpec>,
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
                "G_effect size exceeds hard ceiling".to_owned(),
            ));
        }

        let mut raw_nodes_map: BTreeMap<String, EffectNodeSpec> = BTreeMap::new();
        for node in nodes {
            if is_cancelled() {
                return Err(TypedUniverseError::Cancelled);
            }
            node.validate()?;
            if node.authority_anchor.site_lineage != anchor.site_lineage
                || node.authority_anchor.commit_sequence > anchor.commit_sequence
            {
                return Err(TypedUniverseError::MixedAnchorOrGeneration(format!(
                    "node '{}' anchor exceeds or diverges from projection anchor",
                    node.node_id
                )));
            }
            if raw_nodes_map.contains_key(&node.node_id) {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "duplicate effect node_id '{}'",
                    node.node_id
                )));
            }
            raw_nodes_map.insert(node.node_id.clone(), node);
        }

        let mut raw_edge_set: BTreeSet<EffectEdgeSpec> = BTreeSet::new();
        for edge in edges {
            validate_clean_label(&edge.source_id, "source_id")?;
            validate_clean_label(&edge.target_id, "target_id")?;
            let Some(src) = raw_nodes_map.get(&edge.source_id) else {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "unknown edge source_id '{}'",
                    edge.source_id
                )));
            };
            if !raw_nodes_map.contains_key(&edge.target_id) {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "unknown edge target_id '{}'",
                    edge.target_id
                )));
            }
            // Recommendation/plan nodes can ONLY emit non-authoritative `Recommends` edges!
            if src.kind == EffectNodeKind::RecommendationPlan
                && edge.kind != EffectEdgeKind::Recommends
            {
                return Err(TypedUniverseError::AuthorityViolation(format!(
                    "recommendation node '{}' cannot emit authoritative edge '{}'",
                    edge.source_id,
                    edge.kind.as_str()
                )));
            }
            raw_edge_set.insert(edge);
        }

        let proj_nodes: Vec<ProjectionNodeSpec> = raw_nodes_map
            .values()
            .map(|n| ProjectionNodeSpec {
                node_id: n.node_id.clone(),
                plane: n.plane,
                payload_digest: n.node_digest(),
            })
            .collect();
        let proj_edges: Vec<ProjectionEdgeSpec> = raw_edge_set
            .iter()
            .map(|e| ProjectionEdgeSpec {
                source_id: e.source_id.clone(),
                target_id: e.target_id.clone(),
                relation: e.kind.as_str().to_owned(),
                weight: u64::from(e.kind as u8),
            })
            .collect();

        let projection = ImmutableGraphProjection::build(
            GraphUniverse::GEffect,
            ProjectionOrientation::Directed,
            anchor,
            history_root,
            authority,
            proj_nodes,
            proj_edges,
            requested_absence,
            is_cancelled(),
        )?;

        let visible_nodes: BTreeMap<String, EffectNodeSpec> = raw_nodes_map
            .into_iter()
            .filter(|(id, _)| projection.handle_for_node_id(id).is_some())
            .collect();
        let visible_edges: BTreeSet<EffectEdgeSpec> = raw_edge_set
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

    /// Incrementally applies ordered deltas at `new_anchor` with full-rebuild parity.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_deltas(
        &self,
        new_anchor: LedgerAnchor,
        new_history_root: ContentDigest,
        expected_policy_generation: Generation,
        authority: &ProjectionAuthorityScope,
        deltas: &[EffectDelta],
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
                EffectDelta::UpsertNode(n) => {
                    n.validate()?;
                    nodes.insert(n.node_id.clone(), n.clone());
                }
                EffectDelta::RemoveNode(id) => {
                    nodes.remove(id);
                    edges.retain(|e| e.source_id != *id && e.target_id != *id);
                }
                EffectDelta::AddEdge(e) => {
                    edges.insert(e.clone());
                }
                EffectDelta::RemoveEdge(e) => {
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

    /// Canonical digest of this `G_effect` universe.
    #[must_use]
    pub const fn universe_digest(&self) -> ContentDigest {
        self.universe_digest
    }

    /// Tombstoned legacy fields recorded during any `v1 -> v2` migration.
    #[must_use]
    pub fn tombstoned_fields(&self) -> &[String] {
        &self.tombstoned_fields
    }

    /// Derived graph analysis NEVER grants effect authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Runs certified cycle/deadlock detection, critical-path calculation, cancellation-potential
    /// classification, and honest completion verification over `G_effect`.
    pub fn analyze_obligations(
        &self,
        max_operations: u64,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<EffectObligationAnalysis, TypedUniverseError> {
        let mut budget = OpBudget::new(max_operations)?;

        let node_ids: Vec<String> = self.visible_nodes.keys().cloned().collect();
        let mut id_to_idx: BTreeMap<&str, usize> = BTreeMap::new();
        for (idx, id) in node_ids.iter().enumerate() {
            id_to_idx.insert(id.as_str(), idx);
        }

        // Build adjacency strictly over ordering/wait edges (`must-precede`, `waits-for`, `blocks`).
        let n = node_ids.len();
        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut indegree = vec![0_usize; n];
        let mut self_loop_nodes: BTreeSet<usize> = BTreeSet::new();
        let mut verified_targets: BTreeSet<&str> = BTreeSet::new();
        let mut compensated_targets: BTreeSet<&str> = BTreeSet::new();

        for edge in &self.visible_edges {
            budget.charge(1, &mut is_cancelled)?;
            if edge.kind == EffectEdgeKind::Verifies
                && let Some(src) = self.visible_nodes.get(&edge.source_id)
                && src.state == EffectObligationState::Verified
            {
                verified_targets.insert(edge.target_id.as_str());
            } else if edge.kind == EffectEdgeKind::Compensates
                && let Some(src) = self.visible_nodes.get(&edge.source_id)
                && matches!(
                    src.state,
                    EffectObligationState::Verified | EffectObligationState::Compensated
                )
            {
                compensated_targets.insert(edge.target_id.as_str());
            }
            if edge.kind.is_ordering_or_wait()
                && let (Some(&u), Some(&v)) = (
                    id_to_idx.get(edge.source_id.as_str()),
                    id_to_idx.get(edge.target_id.as_str()),
                )
            {
                if u == v {
                    self_loop_nodes.insert(u);
                }
                adj[u].push(v);
                indegree[v] = indegree[v].saturating_add(1);
            }
        }
        for nbrs in &mut adj {
            nbrs.sort_unstable();
            nbrs.dedup();
        }
        // Recompute exact indegree after deduplicating parallel ordering/wait edges.
        indegree.fill(0);
        for nbrs in &adj {
            for &v in nbrs {
                indegree[v] = indegree[v].saturating_add(1);
            }
        }

        // Iterative Tarjan SCC for exact deterministic deadlock/wait-cycle detection.
        let deadlock_cycles = find_wait_cycles(
            &node_ids,
            &adj,
            &self_loop_nodes,
            &mut budget,
            &mut is_cancelled,
        )?;

        // Kahn topological sort & longest-path critical path when acyclic.
        let (critical_path, critical_path_duration_ms) = if deadlock_cycles.is_empty() {
            let mut ready: BTreeSet<usize> = BTreeSet::new();
            for (idx, &deg) in indegree.iter().enumerate() {
                if deg == 0 {
                    ready.insert(idx);
                }
            }
            let mut topo = Vec::with_capacity(n);
            let mut rem_deg = indegree;
            while let Some(u) = ready.pop_first() {
                budget.charge(1, &mut is_cancelled)?;
                topo.push(u);
                for &v in &adj[u] {
                    rem_deg[v] = rem_deg[v].saturating_sub(1);
                    if rem_deg[v] == 0 {
                        ready.insert(v);
                    }
                }
            }
            let is_exec: Vec<bool> = node_ids
                .iter()
                .map(|id| {
                    self.visible_nodes
                        .get(id)
                        .is_some_and(|s| s.kind != EffectNodeKind::RecommendationPlan)
                })
                .collect();
            let dur_of: Vec<u64> = node_ids
                .iter()
                .enumerate()
                .map(|(i, id)| {
                    if is_exec[i] {
                        self.visible_nodes.get(id).map_or(0, |s| s.duration_ms)
                    } else {
                        0
                    }
                })
                .collect();
            let mut best_dist = dur_of.clone();
            let mut best_hops: Vec<usize> = is_exec.iter().map(|&e| usize::from(e)).collect();
            let mut pred: Vec<Option<usize>> = vec![None; n];
            for &u in &topo {
                budget.charge(1, &mut is_cancelled)?;
                if !is_exec[u] {
                    continue;
                }
                for &v in &adj[u] {
                    if !is_exec[v] {
                        continue;
                    }
                    let cand = best_dist[u].saturating_add(dur_of[v]);
                    let cand_hops = best_hops[u].saturating_add(1);
                    if cand > best_dist[v] || (cand == best_dist[v] && cand_hops > best_hops[v]) {
                        best_dist[v] = cand;
                        best_hops[v] = cand_hops;
                        pred[v] = Some(u);
                    }
                }
            }
            if let Some((end_idx, &max_dur)) = best_dist
                .iter()
                .enumerate()
                .filter(|&(idx, _)| is_exec[idx])
                .max_by_key(|&(idx, &d)| (d, best_hops[idx], std::cmp::Reverse(idx)))
            {
                let mut path_rev = Vec::new();
                let mut cur = Some(end_idx);
                while let Some(x) = cur {
                    path_rev.push(node_ids[x].clone());
                    cur = pred[x];
                }
                path_rev.reverse();
                (Some(path_rev), Some(max_dur))
            } else {
                (Some(Vec::new()), Some(0))
            }
        } else {
            (None, None)
        };

        // Classify stale fences, unverified dispatches, indeterminate states, duplicate commits,
        // uncompensated failures, and clean cancellation potential.
        let mut stale_fence_nodes = Vec::new();
        let mut unverified_dispatches = Vec::new();
        let mut indeterminate_nodes = Vec::new();
        let mut uncompensated_failures = Vec::new();
        let mut cleanly_cancellable_nodes = Vec::new();
        let mut dispatch_key_counts: BTreeMap<&str, usize> = BTreeMap::new();

        for node in self.visible_nodes.values() {
            budget.charge(1, &mut is_cancelled)?;
            if node.kind == EffectNodeKind::RecommendationPlan {
                continue;
            }
            if node.has_stale_fence() {
                stale_fence_nodes.push(node.node_id.clone());
            }
            if node.kind == EffectNodeKind::DispatchAttempt {
                *dispatch_key_counts
                    .entry(node.idempotency_key.as_str())
                    .or_insert(0) += 1;
            }
            match node.state {
                EffectObligationState::Prepared => {
                    if !node.has_stale_fence() {
                        cleanly_cancellable_nodes.push(node.node_id.clone());
                    }
                }
                EffectObligationState::Dispatched | EffectObligationState::Observed => {
                    unverified_dispatches.push(node.node_id.clone());
                }
                EffectObligationState::Indeterminate => {
                    indeterminate_nodes.push(node.node_id.clone());
                }
                EffectObligationState::Failed => {
                    if !compensated_targets.contains(node.node_id.as_str()) {
                        uncompensated_failures.push(node.node_id.clone());
                    }
                }
                EffectObligationState::Verified => {
                    if node.kind == EffectNodeKind::DispatchAttempt
                        && !verified_targets.contains(node.node_id.as_str())
                    {
                        // A DispatchAttempt claiming Verified without a Verifies predicate/observation
                        // is an open-loop success claim and is flagged!
                        unverified_dispatches.push(node.node_id.clone());
                    }
                }
                EffectObligationState::Compensated
                | EffectObligationState::Cancelled
                | EffectObligationState::NonAuthoritativeRecommendation => {}
            }
        }

        let duplicate_commit_keys: Vec<String> = dispatch_key_counts
            .into_iter()
            .filter_map(|(k, c)| if c > 1 { Some(k.to_owned()) } else { None })
            .collect();

        let verdict = if !indeterminate_nodes.is_empty() {
            EffectCompletionVerdict::IndeterminateRequiresReconciliation
        } else if !deadlock_cycles.is_empty()
            || !stale_fence_nodes.is_empty()
            || !unverified_dispatches.is_empty()
            || !uncompensated_failures.is_empty()
            || !duplicate_commit_keys.is_empty()
            || !cleanly_cancellable_nodes.is_empty()
            || !self.projection.absence_boundary().certifies_absence()
        {
            EffectCompletionVerdict::IncompleteOrBlocked
        } else {
            EffectCompletionVerdict::CompleteVerified
        };

        let mut path_enc = CanonicalEncoder::new();
        path_enc.u8(verdict as u8);
        path_enc.u64(deadlock_cycles.len() as u64);
        for cyc in &deadlock_cycles {
            path_enc.u64(cyc.len() as u64);
            for id in cyc {
                path_enc.text(id);
            }
        }
        path_enc.u64(stale_fence_nodes.len() as u64);
        path_enc.u64(unverified_dispatches.len() as u64);
        path_enc.u64(indeterminate_nodes.len() as u64);
        let decision_path_digest = hash_domain_tag(G_EFFECT_DIGEST_DOMAIN, 2, &path_enc.finish());

        let mut out_enc = CanonicalEncoder::new();
        out_enc.digest(self.universe_digest);
        out_enc.digest(decision_path_digest);
        out_enc.u64(critical_path_duration_ms.unwrap_or(0));
        let output_digest = hash_domain_tag(G_EFFECT_DIGEST_DOMAIN, 3, &out_enc.finish());

        let witness = build_universe_witness(
            G_EFFECT_ALGORITHM_ID,
            G_EFFECT_IMPLEMENTATION_ID,
            GraphUniverse::GEffect,
            &self.projection_id,
            self.projection.anchor(),
            self.projection.node_count(),
            self.projection.edge_count(),
            self.universe_digest,
            G_EFFECT_POLICY_ID,
            budget.used(),
            ((n + self.visible_edges.len() + 1) * 160) as u64,
            decision_path_digest,
            output_digest,
        )?;

        Ok(EffectObligationAnalysis {
            verdict,
            deadlock_cycles,
            stale_fence_nodes,
            unverified_dispatches,
            indeterminate_nodes,
            uncompensated_failures,
            duplicate_commit_keys,
            cleanly_cancellable_nodes,
            critical_path,
            critical_path_duration_ms,
            grants_effect_authority: false,
            witness,
        })
    }

    /// Serializes `G_effect` into its versioned checksummed wire format (`v2`).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(CURRENT_UNIVERSE_WIRE_VERSION, false)
    }

    /// Serializes a compatible legacy `v1` fixture carrying a removed `legacy_open_loop_ok` flag.
    pub fn to_legacy_v1_fixture_bytes(
        &self,
        legacy_open_loop_ok: bool,
    ) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(LEGACY_UNIVERSE_WIRE_VERSION, legacy_open_loop_ok)
    }

    fn encode_versioned(
        &self,
        version: u32,
        legacy_open_loop_ok: bool,
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
            enc.u8(u8::from(legacy_open_loop_ok));
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
            G_EFFECT_WIRE_MAGIC,
            version,
            G_EFFECT_DIGEST_DOMAIN,
            &payload,
        )
    }

    /// Opens a `v1` (migrating deterministically with tombstones) or `v2` durable `G_effect` fixture.
    pub fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<(Self, UniverseMigrationReport), TypedUniverseError> {
        let (version, payload) =
            open_wire_envelope(bytes, G_EFFECT_WIRE_MAGIC, G_EFFECT_DIGEST_DOMAIN)?;
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
        if projection.universe() != GraphUniverse::GEffect {
            return Err(TypedUniverseError::MalformedWire(
                "embedded projection universe is not G_effect".to_owned(),
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
            let node = EffectNodeSpec::decode_body(&mut dec)?;
            if visible_nodes.contains_key(&node.node_id) {
                return Err(TypedUniverseError::MalformedWire(
                    "duplicate effect node_id in wire fixture".to_owned(),
                ));
            }
            if node.authority_anchor.site_lineage != projection.anchor().site_lineage
                || node.authority_anchor.commit_sequence > projection.anchor().commit_sequence
            {
                return Err(TypedUniverseError::MalformedWire(
                    "wire effect node anchor diverges from embedded projection".to_owned(),
                ));
            }
            let Some(handle) = projection.handle_for_node_id(&node.node_id) else {
                return Err(TypedUniverseError::MalformedWire(
                    "wire effect node missing from embedded G_effect projection".to_owned(),
                ));
            };
            if projection.node(handle)?.payload_digest != node.node_digest() {
                return Err(TypedUniverseError::MalformedWire(
                    "wire effect node digest disagrees with embedded projection".to_owned(),
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
            let edge = EffectEdgeSpec::decode_body(&mut dec)?;
            let Some(src) = visible_nodes.get(&edge.source_id) else {
                return Err(TypedUniverseError::MalformedWire(
                    "wire effect edge source missing".to_owned(),
                ));
            };
            if !visible_nodes.contains_key(&edge.target_id) {
                return Err(TypedUniverseError::MalformedWire(
                    "wire effect edge target missing".to_owned(),
                ));
            }
            if src.kind == EffectNodeKind::RecommendationPlan
                && edge.kind != EffectEdgeKind::Recommends
            {
                return Err(TypedUniverseError::AuthorityViolation(
                    "wire recommendation node cannot carry authoritative edge".to_owned(),
                ));
            }
            visible_edges.insert(edge);
        }
        let (migrated, tombstoned_fields) = if version == LEGACY_UNIVERSE_WIRE_VERSION {
            let _deprecated_flag = dec.u8().map_err(map_err)?;
            (
                true,
                vec![
                    "v1.legacy_open_loop_ok:tombstoned_closed_loop_verification_required"
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
        visible_nodes: &BTreeMap<String, EffectNodeSpec>,
        visible_edges: &BTreeSet<EffectEdgeSpec>,
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
        hash_domain_tag(G_EFFECT_DIGEST_DOMAIN, 0, &enc.finish())
    }
}

/// Iterative Tarjan SCC detecting all non-trivial strongly connected wait cycles.
fn find_wait_cycles(
    node_ids: &[String],
    adj: &[Vec<usize>],
    self_loops: &BTreeSet<usize>,
    budget: &mut OpBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<Vec<String>>, TypedUniverseError> {
    let n = node_ids.len();
    let mut index_counter = 0_u32;
    let mut indices: Vec<Option<u32>> = vec![None; n];
    let mut lowlink = vec![0_u32; n];
    let mut on_stack = vec![false; n];
    let mut tarjan_stack: Vec<usize> = Vec::new();
    let mut cycles: Vec<Vec<String>> = Vec::new();

    for start in 0..n {
        if indices[start].is_some() {
            continue;
        }
        let mut call_stack: Vec<(usize, usize)> = vec![(start, 0)];
        indices[start] = Some(index_counter);
        lowlink[start] = index_counter;
        index_counter = index_counter.saturating_add(1);
        tarjan_stack.push(start);
        on_stack[start] = true;

        while let Some((u, next_pos)) = call_stack.pop() {
            budget.charge(1, is_cancelled)?;
            if next_pos < adj[u].len() {
                let v = adj[u][next_pos];
                call_stack.push((u, next_pos + 1));
                if indices[v].is_none() {
                    indices[v] = Some(index_counter);
                    lowlink[v] = index_counter;
                    index_counter = index_counter.saturating_add(1);
                    tarjan_stack.push(v);
                    on_stack[v] = true;
                    call_stack.push((v, 0));
                } else if on_stack[v]
                    && let Some(v_idx) = indices[v]
                {
                    lowlink[u] = lowlink[u].min(v_idx);
                }
            } else {
                if let Some(&(parent, _)) = call_stack.last() {
                    lowlink[parent] = lowlink[parent].min(lowlink[u]);
                }
                if indices[u] == Some(lowlink[u]) {
                    let mut comp = Vec::new();
                    while let Some(w) = tarjan_stack.pop() {
                        on_stack[w] = false;
                        comp.push(w);
                        if w == u {
                            break;
                        }
                    }
                    if comp.len() > 1 || (comp.len() == 1 && self_loops.contains(&comp[0])) {
                        let mut names: Vec<String> =
                            comp.into_iter().map(|i| node_ids[i].clone()).collect();
                        names.sort();
                        cycles.push(names);
                    }
                }
            }
        }
    }
    cycles.sort();
    Ok(cycles)
}
