#![forbid(unsafe_code)]
//! Time-expanded transit graph `G_time` (`PROJ-TIME-001`, `fss-x4a.23.69.4`).
//!
//! Uses `(zone, time_interval)` nodes binding clock, geometry, and behavior generations plus
//! explicit clock uncertainty, and directed transit edges for physically plausible movement under
//! declared speed/behavior models.
//!
//! Clock uncertainty widens feasible arrival intervals conservatively: a path that appears feasible
//! only by pretending timestamps are exact is flagged explicitly, temporal tolerance violations
//! abstain with the exact invalidating interval, and budget exhaustion or staleness returns
//! `Unknown` — NEVER `Impossible`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

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

/// Registered digest domain for `G_time` projections and witnesses
/// (`SCHEMA-DOMAIN-GRAPH-G-TIME-001`).
pub const G_TIME_DIGEST_DOMAIN: &str = "fss.graph.g_time_projection.v1";
/// Wire magic for durable `G_time` fixtures (`FSSGTM01`).
pub const G_TIME_WIRE_MAGIC: [u8; 8] = *b"FSSGTM01";
/// Registered algorithm ID emitted in `G_time` witnesses.
pub const G_TIME_ALGORITHM_ID: &str = "ALG-PROJ-TIME-001";
/// Implementation generation recorded in `G_time` witnesses.
pub const G_TIME_IMPLEMENTATION_ID: &str = "fss-graph-algorithms:proj-time-001:g-time-oracle:v2";
/// Policy identity recorded in `G_time` witnesses.
pub const G_TIME_POLICY_ID: &str =
    "graph-policy:g-time:interval-arithmetic:conservative-clock-widening:v2";

/// Observability status of a `(zone, time_bucket)` node in `G_time`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TimeNodeObservability {
    /// Actively observed during this interval.
    Observed = 1,
    /// Physically occluded (routes may traverse unseen).
    Occluded = 2,
    /// Unobserved blind space / coverage gap.
    UnobservedSpace = 3,
    /// Camera reconnect or clock-discontinuity boundary.
    ReconnectBoundary = 4,
}

impl TimeNodeObservability {
    fn from_tag(tag: u8) -> Result<Self, TypedUniverseError> {
        match tag {
            1 => Ok(Self::Observed),
            2 => Ok(Self::Occluded),
            3 => Ok(Self::UnobservedSpace),
            4 => Ok(Self::ReconnectBoundary),
            other => Err(TypedUniverseError::MalformedWire(format!(
                "unknown TimeNodeObservability tag {other}"
            ))),
        }
    }
}

/// One `(zone, time_interval)` node in `G_time` binding clock, geometry, and behavior generations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeExpandedNodeSpec {
    /// Stable unique `(zone, bucket)` node ID.
    pub node_id: String,
    /// Spatial zone identifier.
    pub zone_id: String,
    /// Bucket/observation interval start (ns).
    pub interval_start_ns: TimestampNs,
    /// Bucket/observation interval end (ns, `>= interval_start_ns`).
    pub interval_end_ns: TimestampNs,
    /// Non-negative symmetric clock uncertainty bound (ns, widens feasible transit!).
    pub clock_uncertainty_ns: u64,
    /// Pinned clock alignment generation (`>= 1`).
    pub clock_generation: Generation,
    /// Pinned site geometry generation (`>= 1`).
    pub geometry_generation: Generation,
    /// Pinned speed/behavior model generation (`>= 1`).
    pub behavior_generation: Generation,
    /// Observability posture of this space-time bucket.
    pub observability: TimeNodeObservability,
    /// Owning semantic plane.
    pub plane: Plane,
}

impl TimeExpandedNodeSpec {
    /// Validates interval ordering and generations fail-closed.
    pub fn validate(&self) -> Result<(), TypedUniverseError> {
        validate_clean_label(&self.node_id, "node_id")?;
        validate_clean_label(&self.zone_id, "zone_id")?;
        if self.interval_end_ns.0 < self.interval_start_ns.0
            || self.clock_generation.0 == 0
            || self.geometry_generation.0 == 0
            || self.behavior_generation.0 == 0
        {
            return Err(TypedUniverseError::InvalidInput(format!(
                "invalid time-expanded node '{}'",
                self.node_id
            )));
        }
        Ok(())
    }

    /// Canonical SHA-256 commitment for this space-time node.
    #[must_use]
    pub fn node_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        hash_domain_tag(G_TIME_DIGEST_DOMAIN, 1, &enc.finish())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.node_id);
        enc.text(&self.zone_id);
        enc.i128(self.interval_start_ns.0);
        enc.i128(self.interval_end_ns.0);
        enc.u64(self.clock_uncertainty_ns);
        enc.u64(self.clock_generation.0);
        enc.u64(self.geometry_generation.0);
        enc.u64(self.behavior_generation.0);
        enc.u8(self.observability as u8);
        self.plane.encode_canonical(enc);
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, TypedUniverseError> {
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let node_id = dec.text().map_err(map_err)?.to_owned();
        let zone_id = dec.text().map_err(map_err)?.to_owned();
        let interval_start_ns = TimestampNs(dec.i128().map_err(map_err)?);
        let interval_end_ns = TimestampNs(dec.i128().map_err(map_err)?);
        let clock_uncertainty_ns = dec.u64().map_err(map_err)?;
        let clock_generation = Generation(dec.u64().map_err(map_err)?);
        let geometry_generation = Generation(dec.u64().map_err(map_err)?);
        let behavior_generation = Generation(dec.u64().map_err(map_err)?);
        let observability = TimeNodeObservability::from_tag(dec.u8().map_err(map_err)?)?;
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
            zone_id,
            interval_start_ns,
            interval_end_ns,
            clock_uncertainty_ns,
            clock_generation,
            geometry_generation,
            behavior_generation,
            observability,
            plane,
        };
        node.validate()?;
        Ok(node)
    }
}

/// Directed space-time movement edge carrying conservative transit-time interval & speed profile.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TimeTransitEdgeSpec {
    /// Stable edge ID.
    pub edge_id: String,
    /// Source `(zone, bucket)` node ID.
    pub source_id: String,
    /// Target `(zone, bucket)` node ID.
    pub target_id: String,
    /// Declared speed/behavior profile (`walk_1_4mps`, `run_5mps`, `crawl_0_5mps`, `vehicle`).
    pub behavior_model: String,
    /// Minimum physically plausible travel duration (ns).
    pub min_travel_ns: u64,
    /// Maximum physically plausible travel duration (ns, `>= min_travel_ns`).
    pub max_travel_ns: u64,
    /// Operation-specific clock/drift tolerance bound (ns).
    pub max_allowed_clock_uncertainty_ns: u64,
}

impl TimeTransitEdgeSpec {
    /// Validates transit interval bounds fail-closed.
    pub fn validate(&self) -> Result<(), TypedUniverseError> {
        validate_clean_label(&self.edge_id, "edge_id")?;
        validate_clean_label(&self.source_id, "source_id")?;
        validate_clean_label(&self.target_id, "target_id")?;
        validate_clean_label(&self.behavior_model, "behavior_model")?;
        if self.max_travel_ns < self.min_travel_ns {
            return Err(TypedUniverseError::InvalidInput(format!(
                "max_travel_ns < min_travel_ns on '{}'",
                self.edge_id
            )));
        }
        Ok(())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(&self.edge_id);
        enc.text(&self.source_id);
        enc.text(&self.target_id);
        enc.text(&self.behavior_model);
        enc.u64(self.min_travel_ns);
        enc.u64(self.max_travel_ns);
        enc.u64(self.max_allowed_clock_uncertainty_ns);
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, TypedUniverseError> {
        let map_err = |e: fss_core::ContractError| TypedUniverseError::MalformedWire(e.to_string());
        let edge_id = dec.text().map_err(map_err)?.to_owned();
        let source_id = dec.text().map_err(map_err)?.to_owned();
        let target_id = dec.text().map_err(map_err)?.to_owned();
        let behavior_model = dec.text().map_err(map_err)?.to_owned();
        let min_travel_ns = dec.u64().map_err(map_err)?;
        let max_travel_ns = dec.u64().map_err(map_err)?;
        let max_allowed_clock_uncertainty_ns = dec.u64().map_err(map_err)?;
        let edge = Self {
            edge_id,
            source_id,
            target_id,
            behavior_model,
            min_travel_ns,
            max_travel_ns,
            max_allowed_clock_uncertainty_ns,
        };
        edge.validate()?;
        Ok(edge)
    }
}

/// Incremental ordered delta applied to `G_time`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TimeDelta {
    /// Upsert a space-time node.
    UpsertNode(TimeExpandedNodeSpec),
    /// Remove a space-time node and incident edges.
    RemoveNode(String),
    /// Upsert a transit edge by `edge_id`.
    UpsertEdge(TimeTransitEdgeSpec),
    /// Remove a transit edge by `edge_id`.
    RemoveEdge(String),
}

/// Non-collapsed feasibility verdict for cross-camera/space-time transit queries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TimeFeasibilityVerdict {
    /// Conservative interval-widened transit is feasible within declared temporal tolerance.
    Feasible {
        /// Earliest possible arrival timestamp at target (ns).
        earliest_arrival_ns: TimestampNs,
        /// Latest possible arrival timestamp at target (ns).
        latest_arrival_ns: TimestampNs,
        /// Whether any intermediate hop traversed occluded or unobserved space.
        traversed_unobserved_space: bool,
        /// True if exact midpoint timestamps alone would have disagreed with interval truth.
        exact_midpoint_would_have_erred: bool,
    },
    /// Temporal tolerance exceeded (clock uncertainty or drift invalidates reliable association!).
    AbstainToleranceExceeded {
        /// Observed combined uncertainty (ns).
        observed_uncertainty_ns: u64,
        /// Configured operation-specific tolerance ceiling (ns).
        max_tolerance_ns: u64,
        /// Exact invalidating interval `[start_ns, end_ns]`.
        invalidating_interval: (TimestampNs, TimestampNs),
    },
    /// Proven infeasible under complete unredacted, current-generation coverage.
    Infeasible {
        /// Conservative arrival window `[earliest, latest]` that missed target window.
        arrival_interval: (TimestampNs, TimestampNs),
        /// Target observation window `[start, end]`.
        target_interval: (TimestampNs, TimestampNs),
    },
    /// Stale generation, budget exhaustion, reconnect boundary, or uncertified absence: NEVER `Impossible`!
    Unknown {
        /// Machine-readable reason (`budget_exhausted`, `stale_generation`, `uncertified_absence`, `reconnect_boundary`).
        reason: String,
    },
}

/// Certified space-time feasibility assessment paired with a `GraphAlgorithmWitness`.
#[derive(Clone, Debug, PartialEq)]
pub struct TimeFeasibilityAssessment {
    /// Source `(zone, bucket)` node ID.
    pub source_id: String,
    /// Target `(zone, bucket)` node ID.
    pub target_id: String,
    /// Non-collapsed verdict.
    pub verdict: TimeFeasibilityVerdict,
    /// Always `false`: derived transit analysis never grants effect authority.
    pub grants_effect_authority: bool,
    /// Certified execution witness.
    pub witness: GraphAlgorithmWitness,
}

/// Anchor-pinned, capability-filtered Time-Expanded Transit Graph (`G_time`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeExpandedTransitGraph {
    projection_id: String,
    policy_generation: Generation,
    projection: ImmutableGraphProjection,
    visible_nodes: BTreeMap<String, TimeExpandedNodeSpec>,
    visible_edges: BTreeMap<String, TimeTransitEdgeSpec>,
    tombstoned_fields: Vec<String>,
    universe_digest: ContentDigest,
}

impl TimeExpandedTransitGraph {
    /// Builds `G_time` over `ImmutableGraphProjection` (`GraphUniverse::GTime`).
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        projection_id: impl Into<String>,
        policy_generation: Generation,
        anchor: LedgerAnchor,
        history_root: ContentDigest,
        authority: &ProjectionAuthorityScope,
        nodes: Vec<TimeExpandedNodeSpec>,
        edges: Vec<TimeTransitEdgeSpec>,
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
                "G_time size exceeds hard ceiling".to_owned(),
            ));
        }

        let mut raw_nodes: BTreeMap<String, TimeExpandedNodeSpec> = BTreeMap::new();
        for node in nodes {
            if is_cancelled() {
                return Err(TypedUniverseError::Cancelled);
            }
            node.validate()?;
            if raw_nodes.contains_key(&node.node_id) {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "duplicate G_time node_id '{}'",
                    node.node_id
                )));
            }
            raw_nodes.insert(node.node_id.clone(), node);
        }

        let mut raw_edges: BTreeMap<String, TimeTransitEdgeSpec> = BTreeMap::new();
        for edge in edges {
            edge.validate()?;
            if !raw_nodes.contains_key(&edge.source_id) || !raw_nodes.contains_key(&edge.target_id)
            {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "unknown G_time edge endpoint '{}' -> '{}'",
                    edge.source_id, edge.target_id
                )));
            }
            if raw_edges.contains_key(&edge.edge_id) {
                return Err(TypedUniverseError::InvalidInput(format!(
                    "duplicate G_time edge_id '{}'",
                    edge.edge_id
                )));
            }
            raw_edges.insert(edge.edge_id.clone(), edge);
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
            .values()
            .map(|e| ProjectionEdgeSpec {
                source_id: e.source_id.clone(),
                target_id: e.target_id.clone(),
                relation: format!("{}:{}", e.behavior_model, e.edge_id),
                weight: e.min_travel_ns,
            })
            .collect();

        let projection = ImmutableGraphProjection::build(
            GraphUniverse::GTime,
            ProjectionOrientation::Directed,
            anchor,
            history_root,
            authority,
            proj_nodes,
            proj_edges,
            requested_absence,
            is_cancelled(),
        )?;

        let visible_nodes: BTreeMap<String, TimeExpandedNodeSpec> = raw_nodes
            .into_iter()
            .filter(|(id, _)| projection.handle_for_node_id(id).is_some())
            .collect();
        let visible_edges: BTreeMap<String, TimeTransitEdgeSpec> = raw_edges
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

    /// Incrementally applies ordered `TimeDelta` updates with full-rebuild parity.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_deltas(
        &self,
        new_anchor: LedgerAnchor,
        new_history_root: ContentDigest,
        expected_policy_generation: Generation,
        authority: &ProjectionAuthorityScope,
        deltas: &[TimeDelta],
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
                TimeDelta::UpsertNode(n) => {
                    n.validate()?;
                    nodes.insert(n.node_id.clone(), n.clone());
                }
                TimeDelta::RemoveNode(id) => {
                    nodes.remove(id);
                    edges.retain(|_, e| e.source_id != *id && e.target_id != *id);
                }
                TimeDelta::UpsertEdge(e) => {
                    e.validate()?;
                    edges.insert(e.edge_id.clone(), e.clone());
                }
                TimeDelta::RemoveEdge(eid) => {
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

    /// Canonical digest of this `G_time` universe.
    #[must_use]
    pub const fn universe_digest(&self) -> ContentDigest {
        self.universe_digest
    }

    /// Derived transit graph NEVER grants effect authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Evaluates conservative interval-widened same-entity transit feasibility from `source_id`
    /// to `target_id`.
    ///
    /// Budget exhaustion, stale clock/geometry/behavior generations, reconnect discontinuities, or
    /// uncertified absence return [`TimeFeasibilityVerdict::Unknown`] — NEVER `Infeasible`!
    #[allow(clippy::too_many_arguments)]
    pub fn assess_same_entity_feasibility(
        &self,
        source_id: &str,
        target_id: &str,
        expected_clock_gen: Option<Generation>,
        expected_geometry_gen: Option<Generation>,
        max_operations: u64,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<TimeFeasibilityAssessment, TypedUniverseError> {
        validate_clean_label(source_id, "source_id")?;
        validate_clean_label(target_id, "target_id")?;
        let mut budget = OpBudget::new(max_operations)?;

        let verdict = match (
            self.visible_nodes.get(source_id),
            self.visible_nodes.get(target_id),
        ) {
            (Some(src), Some(dst)) => {
                let stale = expected_clock_gen
                    .is_some_and(|g| src.clock_generation != g || dst.clock_generation != g)
                    || expected_geometry_gen.is_some_and(|g| {
                        src.geometry_generation != g || dst.geometry_generation != g
                    });
                if stale {
                    TimeFeasibilityVerdict::Unknown {
                        reason: "stale_clock_or_geometry_generation".to_owned(),
                    }
                } else if src.observability == TimeNodeObservability::ReconnectBoundary
                    || dst.observability == TimeNodeObservability::ReconnectBoundary
                {
                    TimeFeasibilityVerdict::Unknown {
                        reason: "reconnect_boundary_clock_discontinuity".to_owned(),
                    }
                } else {
                    self.run_interval_bfs(src, dst, &mut budget, &mut is_cancelled)?
                }
            }
            _ => TimeFeasibilityVerdict::Unknown {
                reason: "missing_or_redacted_endpoint".to_owned(),
            },
        };

        let mut path_enc = CanonicalEncoder::new();
        path_enc.text(source_id);
        path_enc.text(target_id);
        let verdict_tag: u8 = match &verdict {
            TimeFeasibilityVerdict::Feasible { .. } => 1,
            TimeFeasibilityVerdict::AbstainToleranceExceeded { .. } => 2,
            TimeFeasibilityVerdict::Infeasible { .. } => 3,
            TimeFeasibilityVerdict::Unknown { .. } => 4,
        };
        path_enc.u8(verdict_tag);
        let decision_path_digest = hash_domain_tag(G_TIME_DIGEST_DOMAIN, 2, &path_enc.finish());
        let mut out_enc = CanonicalEncoder::new();
        out_enc.digest(self.universe_digest);
        out_enc.digest(decision_path_digest);
        let output_digest = hash_domain_tag(G_TIME_DIGEST_DOMAIN, 3, &out_enc.finish());

        let witness = build_universe_witness(
            G_TIME_ALGORITHM_ID,
            G_TIME_IMPLEMENTATION_ID,
            GraphUniverse::GTime,
            &self.projection_id,
            self.projection.anchor(),
            self.projection.node_count(),
            self.projection.edge_count(),
            self.universe_digest,
            G_TIME_POLICY_ID,
            budget.used(),
            ((self.visible_nodes.len() + self.visible_edges.len() + 1) * 192) as u64,
            decision_path_digest,
            output_digest,
        )?;

        Ok(TimeFeasibilityAssessment {
            source_id: source_id.to_owned(),
            target_id: target_id.to_owned(),
            verdict,
            grants_effect_authority: false,
            witness,
        })
    }

    fn run_interval_bfs(
        &self,
        src: &TimeExpandedNodeSpec,
        dst: &TimeExpandedNodeSpec,
        budget: &mut OpBudget,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<TimeFeasibilityVerdict, TypedUniverseError> {
        let mut adj: BTreeMap<&str, Vec<&TimeTransitEdgeSpec>> = BTreeMap::new();
        let mut rev_adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for edge in self.visible_edges.values() {
            adj.entry(edge.source_id.as_str()).or_default().push(edge);
            rev_adj
                .entry(edge.target_id.as_str())
                .or_default()
                .push(edge.source_id.as_str());
        }

        // Prune to nodes that can topologically reach `dst` so unrelated sibling branches never
        // pollute temporal-tolerance abstentions or reconnect-boundary verdicts!
        let mut can_reach_dst: BTreeSet<&str> = BTreeSet::new();
        let mut rev_q: VecDeque<&str> = VecDeque::new();
        can_reach_dst.insert(dst.node_id.as_str());
        rev_q.push_back(dst.node_id.as_str());
        while let Some(v) = rev_q.pop_front() {
            if let Err(err) = budget.charge(1, is_cancelled) {
                return match err {
                    TypedUniverseError::BudgetExhausted { .. } => {
                        Ok(TimeFeasibilityVerdict::Unknown {
                            reason: "budget_exhausted".to_owned(),
                        })
                    }
                    other => Err(other),
                };
            }
            if let Some(preds) = rev_adj.get(v) {
                for &p in preds {
                    if can_reach_dst.insert(p) {
                        rev_q.push_back(p);
                    }
                }
            }
        }

        // Track reachable conservative arrival interval (earliest, latest, traversed_unobserved, exact_ok) per node.
        let mut queue: VecDeque<(&str, i128, i128, bool, bool)> = VecDeque::new();
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        queue.push_back((
            src.node_id.as_str(),
            src.interval_start_ns.0,
            src.interval_end_ns.0,
            matches!(
                src.observability,
                TimeNodeObservability::Occluded | TimeNodeObservability::UnobservedSpace
            ),
            true,
        ));
        seen.insert(src.node_id.as_str());

        let mut best_miss: Option<(i128, i128)> = None;
        let mut tolerance_abstain: Option<(u64, u64, (TimestampNs, TimestampNs))> = None;
        let mut saw_reconnect_boundary = false;

        while let Some((u_id, arr_min, arr_max, saw_unobs, exact_chain)) = queue.pop_front() {
            if let Err(err) = budget.charge(1, is_cancelled) {
                return match err {
                    TypedUniverseError::BudgetExhausted { .. } => {
                        Ok(TimeFeasibilityVerdict::Unknown {
                            reason: "budget_exhausted".to_owned(),
                        })
                    }
                    other => Err(other),
                };
            }
            let Some(u_node) = self.visible_nodes.get(u_id) else {
                continue;
            };
            let Some(edges) = adj.get(u_id) else {
                continue;
            };
            for &edge in edges {
                if let Err(err) = budget.charge(1, is_cancelled) {
                    return match err {
                        TypedUniverseError::BudgetExhausted { .. } => {
                            Ok(TimeFeasibilityVerdict::Unknown {
                                reason: "budget_exhausted".to_owned(),
                            })
                        }
                        other => Err(other),
                    };
                }
                let Some(v_node) = self.visible_nodes.get(&edge.target_id) else {
                    continue;
                };
                if !can_reach_dst.contains(v_node.node_id.as_str()) {
                    continue;
                }
                if v_node.observability == TimeNodeObservability::ReconnectBoundary {
                    saw_reconnect_boundary = true;
                    continue;
                }
                let combined_unc = u_node
                    .clock_uncertainty_ns
                    .saturating_add(v_node.clock_uncertainty_ns);
                let widened_min = arr_min
                    .saturating_add(i128::from(edge.min_travel_ns))
                    .saturating_sub(i128::from(combined_unc));
                let widened_max = arr_max
                    .saturating_add(i128::from(edge.max_travel_ns))
                    .saturating_add(i128::from(combined_unc));

                if combined_unc > edge.max_allowed_clock_uncertainty_ns {
                    tolerance_abstain = Some((
                        combined_unc,
                        edge.max_allowed_clock_uncertainty_ns,
                        (TimestampNs(widened_min), TimestampNs(widened_max)),
                    ));
                    continue;
                }

                // Exact-midpoint check (ignoring clock uncertainty) to detect exact-vs-interval counterexamples!
                let u_mid = arr_min.saturating_add((arr_max - arr_min) / 2);
                let v_mid = v_node
                    .interval_start_ns
                    .0
                    .saturating_add((v_node.interval_end_ns.0 - v_node.interval_start_ns.0) / 2);
                let exact_hop_ok = exact_chain
                    && v_mid >= u_mid.saturating_add(i128::from(edge.min_travel_ns))
                    && v_mid <= u_mid.saturating_add(i128::from(edge.max_travel_ns));

                let overlaps = widened_min <= v_node.interval_end_ns.0
                    && widened_max >= v_node.interval_start_ns.0;
                let next_unobs = saw_unobs
                    || matches!(
                        v_node.observability,
                        TimeNodeObservability::Occluded | TimeNodeObservability::UnobservedSpace
                    );

                if v_node.node_id == dst.node_id {
                    if overlaps {
                        return Ok(TimeFeasibilityVerdict::Feasible {
                            earliest_arrival_ns: TimestampNs(widened_min),
                            latest_arrival_ns: TimestampNs(widened_max),
                            traversed_unobserved_space: next_unobs,
                            exact_midpoint_would_have_erred: !exact_hop_ok,
                        });
                    }
                    best_miss = Some((widened_min, widened_max));
                } else if overlaps && seen.insert(v_node.node_id.as_str()) {
                    let clamped_min = widened_min.max(v_node.interval_start_ns.0);
                    let clamped_max = widened_max.min(v_node.interval_end_ns.0);
                    queue.push_back((
                        v_node.node_id.as_str(),
                        clamped_min,
                        clamped_max,
                        next_unobs,
                        exact_hop_ok,
                    ));
                }
            }
        }

        if let Some((observed, max_tol, interval)) = tolerance_abstain {
            return Ok(TimeFeasibilityVerdict::AbstainToleranceExceeded {
                observed_uncertainty_ns: observed,
                max_tolerance_ns: max_tol,
                invalidating_interval: interval,
            });
        }
        if saw_reconnect_boundary {
            return Ok(TimeFeasibilityVerdict::Unknown {
                reason: "reconnect_boundary_clock_discontinuity".to_owned(),
            });
        }
        if !self.projection.absence_boundary().certifies_absence() {
            return Ok(TimeFeasibilityVerdict::Unknown {
                reason: "uncertified_or_redacted_absence_boundary".to_owned(),
            });
        }
        if let Some((a_min, a_max)) = best_miss {
            return Ok(TimeFeasibilityVerdict::Infeasible {
                arrival_interval: (TimestampNs(a_min), TimestampNs(a_max)),
                target_interval: (dst.interval_start_ns, dst.interval_end_ns),
            });
        }
        Ok(TimeFeasibilityVerdict::Infeasible {
            arrival_interval: (src.interval_start_ns, src.interval_end_ns),
            target_interval: (dst.interval_start_ns, dst.interval_end_ns),
        })
    }

    /// Serializes `G_time` into its versioned checksummed wire format (`v2`).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(CURRENT_UNIVERSE_WIRE_VERSION, false)
    }

    /// Serializes a compatible legacy `v1` fixture carrying a removed `legacy_exact_timestamps` flag.
    pub fn to_legacy_v1_fixture_bytes(
        &self,
        legacy_exact_timestamps: bool,
    ) -> Result<Vec<u8>, TypedUniverseError> {
        self.encode_versioned(LEGACY_UNIVERSE_WIRE_VERSION, legacy_exact_timestamps)
    }

    fn encode_versioned(
        &self,
        version: u32,
        legacy_exact_timestamps: bool,
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
            enc.u8(u8::from(legacy_exact_timestamps));
        } else {
            enc.u64(self.tombstoned_fields.len() as u64);
            for t in &self.tombstoned_fields {
                enc.text(t);
            }
        }
        let payload = enc
            .finish_checked()
            .map_err(|e| TypedUniverseError::MalformedWire(e.to_string()))?;
        seal_wire_envelope(G_TIME_WIRE_MAGIC, version, G_TIME_DIGEST_DOMAIN, &payload)
    }

    /// Opens a `v1` (migrating deterministically with tombstones) or `v2` durable `G_time` fixture.
    pub fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<(Self, UniverseMigrationReport), TypedUniverseError> {
        let (version, payload) =
            open_wire_envelope(bytes, G_TIME_WIRE_MAGIC, G_TIME_DIGEST_DOMAIN)?;
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
        if projection.universe() != GraphUniverse::GTime {
            return Err(TypedUniverseError::MalformedWire(
                "embedded projection universe is not G_time".to_owned(),
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
            let node = TimeExpandedNodeSpec::decode_body(&mut dec)?;
            if visible_nodes.contains_key(&node.node_id) {
                return Err(TypedUniverseError::MalformedWire(
                    "duplicate G_time node_id".to_owned(),
                ));
            }
            let Some(handle) = projection.handle_for_node_id(&node.node_id) else {
                return Err(TypedUniverseError::MalformedWire(
                    "wire G_time node missing from embedded projection".to_owned(),
                ));
            };
            if projection.node(handle)?.payload_digest != node.node_digest() {
                return Err(TypedUniverseError::MalformedWire(
                    "wire G_time node digest disagrees with embedded projection".to_owned(),
                ));
            }
            visible_nodes.insert(node.node_id.clone(), node);
        }
        if visible_nodes.len() != projection.node_count() {
            return Err(TypedUniverseError::MalformedWire(
                "wire G_time node count disagrees with embedded projection".to_owned(),
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
            let edge = TimeTransitEdgeSpec::decode_body(&mut dec)?;
            if visible_edges.contains_key(&edge.edge_id) {
                return Err(TypedUniverseError::MalformedWire(
                    "duplicate G_time edge_id".to_owned(),
                ));
            }
            if !visible_nodes.contains_key(&edge.source_id)
                || !visible_nodes.contains_key(&edge.target_id)
            {
                return Err(TypedUniverseError::MalformedWire(
                    "wire G_time edge references unknown node".to_owned(),
                ));
            }
            visible_edges.insert(edge.edge_id.clone(), edge);
        }
        if visible_edges.len() != projection.edge_count() {
            return Err(TypedUniverseError::MalformedWire(
                "wire G_time edge count disagrees with embedded projection".to_owned(),
            ));
        }
        let (migrated, tombstoned_fields) = if version == LEGACY_UNIVERSE_WIRE_VERSION {
            let _deprecated_flag = dec.u8().map_err(map_err)?;
            (
                true,
                vec![
                    "v1.legacy_exact_timestamps:tombstoned_interval_uncertainty_required"
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
        visible_nodes: &BTreeMap<String, TimeExpandedNodeSpec>,
        visible_edges: &BTreeMap<String, TimeTransitEdgeSpec>,
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
        hash_domain_tag(G_TIME_DIGEST_DOMAIN, 0, &enc.finish())
    }
}
