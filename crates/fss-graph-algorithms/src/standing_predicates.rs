#![forbid(unsafe_code)]
//! Incremental retract/add standing predicates over DBSP `Z-set` delta streams (`FSS-163`,
//! `fss-x4a.23.13`).
//!
//! Maintains derived standing graph predicates incrementally under arbitrary additions (`+w`) and
//! retractions (`-w`) while enforcing:
//! - **Exact full-recompute equivalence (`Q(I(Delta)) == I(Delta Q)`):** every linear degree/arc
//!   predicate and bilinear 2-hop composition predicate matches full recompute from scratch at
//!   every monotonic commit sequence;
//! - **Atomic failure semantics:** stale/non-monotonic commit sequences, revoked or drifted
//!   authority scopes, privacy-redacted entity injections, negative-multiplicity violations,
//!   arithmetic overflow, budget exhaustion, or cooperative cancellation fail closed WITHOUT
//!   mutating committed engine state;
//! - **Non-authority invariant (`GRAPH-INV-004`):** standing predicate transitions (`Fired`,
//!   `Retracted`, `Sustained`, `Absent`) are derived cognition ONLY and NEVER grant effect
//!   authority (`grants_effect_authority == false`).

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use fss_core::{CanonicalEncoder, ContentDigest, LedgerAnchor, Plane};

use crate::certified::Budget;
use crate::graph::{GraphError, MAX_NODE_ID_LEN};
use crate::projection::{GraphUniverse, ProjectionAuthorityScope, ProjectionGuidance};
use crate::zset::{ZSet, ZSetDeltaBatch, ZSetGraphState, zset_equijoin, zset_incremental_equijoin};

/// Registered digest domain for standing predicate delta receipts (`SCHEMA-DOMAIN-GRAPH-STANDING-PRED-001`).
pub const STANDING_PREDICATES_RECEIPT_DOMAIN: &str = "fss.graph.standing_predicates_receipt.v1";

/// Maximum standing predicates registered in one bounded engine instance.
pub const MAX_STANDING_PREDICATES: usize = 1024;

/// Typed standing graph predicate maintained incrementally under `+w` additions and `-w` retractions.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StandingPredicateKind {
    /// Active iff `node_id` has total positive out-degree `>= min_out_degree`.
    NodeOutDegreeAtLeast {
        /// Target node identity.
        node_id: String,
        /// Threshold (`>= 1`).
        min_out_degree: u64,
    },
    /// Active iff `node_id` has total positive in-degree `>= min_in_degree`.
    NodeInDegreeAtLeast {
        /// Target node identity.
        node_id: String,
        /// Threshold (`>= 1`).
        min_in_degree: u64,
    },
    /// Active iff directed arc `(tail_id, head_id)` currently has multiplicity `> 0`.
    DirectedArcActive {
        /// Arc tail identity.
        tail_id: String,
        /// Arc head identity.
        head_id: String,
    },
    /// Active iff at least one directed 2-hop path `source_id -> mid -> target_id` exists
    /// (maintained incrementally via DBSP bilinear equijoin `Delta(E join E)`!).
    TwoHopPathExists {
        /// Path start node identity.
        source_id: String,
        /// Path end node identity.
        target_id: String,
    },
    /// Active iff the graph currently has at least `min_active_nodes` nodes with multiplicity `> 0`.
    ActiveNodeCountAtLeast {
        /// Threshold (`>= 1`).
        min_active_nodes: u64,
    },
}

/// Named standing predicate registration.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StandingPredicate {
    /// Stable unique predicate identity.
    pub predicate_id: String,
    /// Predicate semantics.
    pub kind: StandingPredicateKind,
}

/// Non-collapsed transition of one standing predicate across a delta batch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PredicateTransition {
    /// Predicate transitioned from inactive (`false`) to active (`true`).
    Fired,
    /// Predicate transitioned from active (`true`) to inactive (`false`) after retraction.
    Retracted,
    /// Predicate remained active (`true` -> `true`).
    Sustained,
    /// Predicate remained inactive (`false` -> `false`).
    Absent,
}

impl PredicateTransition {
    /// Canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fired => "fired",
            Self::Retracted => "retracted",
            Self::Sustained => "sustained",
            Self::Absent => "absent",
        }
    }
}

/// Per-predicate status row emitted in a [`StandingPredicateDeltaReceipt`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PredicateTransitionRow {
    /// Stable predicate identity.
    pub predicate_id: String,
    /// Active state immediately prior to this delta batch.
    pub previous_active: bool,
    /// Active state immediately after applying this delta batch.
    pub current_active: bool,
    /// Exact transition classification.
    pub transition: PredicateTransition,
    /// Exact non-negative integer witness count supporting `current_active` (degree, multiplicity,
    /// 2-hop witness sum, or active node count).
    pub support_count: u64,
}

/// Sealed receipt emitted for every committed retract/add standing-predicate delta batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandingPredicateDeltaReceipt {
    /// Typed graph universe pinned by the engine.
    pub universe: GraphUniverse,
    /// Authority commit sequence applied.
    pub commit_sequence: u64,
    /// Exact ledger anchor bound to this update.
    pub anchor: LedgerAnchor,
    /// Canonical digest of the committed `ZSetGraphState` after applying the batch.
    pub state_digest: ContentDigest,
    /// Domain-separated SHA-256 commitment over all predicate transitions and support counts.
    pub receipt_digest: ContentDigest,
    /// Transition rows in ascending `predicate_id` order.
    pub transitions: Vec<PredicateTransitionRow>,
    /// Dominant incremental operations charged during this batch.
    pub operations_charged: u64,
    /// Always `false`: standing predicates are derived cognition and NEVER grant effect authority!
    pub grants_effect_authority: bool,
}

/// Typed fail-closed error returned by [`StandingPredicateEngine`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StandingPredicateError {
    /// Cooperative cancellation observed before committing the delta batch.
    Cancelled,
    /// Authority scope was revoked, excluded this universe, or changed privacy epoch.
    AuthorityRevoked(String),
    /// Authority generation drifted from the engine's pinned authority generation.
    StaleAuthorityGeneration {
        /// Expected pinned generation.
        expected: u64,
        /// Supplied generation.
        observed: u64,
    },
    /// Batch commit sequence did not strictly advance past the last committed anchor sequence,
    /// or site lineage diverged.
    StaleAnchorSequence {
        /// Last committed sequence.
        last_committed: u64,
        /// Attempted sequence.
        attempted: u64,
    },
    /// Batch attempted to mutate a privacy-redacted node identity.
    RedactedEntityBlocked {
        /// Redacted node ID blocked prior to state expansion.
        node_id: String,
    },
    /// Invalid or duplicate predicate registration or bound violation.
    InvalidPredicate(String),
    /// Retraction attempted to drive a base node or arc multiplicity below zero.
    NegativeMultiplicity {
        /// Tuple description.
        tuple: String,
        /// Resulting negative multiplicity.
        multiplicity: i64,
    },
    /// Underlying graph/Z-set error (overflow or budget exhaustion).
    Graph(GraphError),
}

impl StandingPredicateError {
    /// Stable machine error identity.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Cancelled | Self::Graph(GraphError::Cancelled) => {
                "ERR-GRAPH-STANDING-PRED-CANCELLED-001"
            }
            Self::AuthorityRevoked(_) => "ERR-GRAPH-STANDING-PRED-AUTH-REVOKED-001",
            Self::StaleAuthorityGeneration { .. } => "ERR-GRAPH-STANDING-PRED-STALE-AUTH-001",
            Self::StaleAnchorSequence { .. } => "ERR-GRAPH-STANDING-PRED-STALE-ANCHOR-001",
            Self::RedactedEntityBlocked { .. } => "ERR-GRAPH-STANDING-PRED-REDACTED-001",
            Self::InvalidPredicate(_) => "ERR-GRAPH-STANDING-PRED-INVALID-001",
            Self::NegativeMultiplicity { .. } => "ERR-GRAPH-STANDING-PRED-NEGATIVE-MULT-001",
            Self::Graph(_) => "ERR-GRAPH-STANDING-PRED-GRAPH-001",
        }
    }

    /// Safe recovery guidance for this refusal.
    #[must_use]
    pub const fn guidance(&self) -> ProjectionGuidance {
        match self {
            Self::Cancelled | Self::Graph(GraphError::Cancelled) => {
                ProjectionGuidance::RetryFromPinnedAnchor
            }
            Self::AuthorityRevoked(_)
            | Self::StaleAuthorityGeneration { .. }
            | Self::RedactedEntityBlocked { .. } => ProjectionGuidance::ReauthorizeProjection,
            Self::StaleAnchorSequence { .. } => {
                ProjectionGuidance::ReacquireHandlesForCurrentGeneration
            }
            Self::InvalidPredicate(_) | Self::NegativeMultiplicity { .. } | Self::Graph(_) => {
                ProjectionGuidance::RepairInput
            }
        }
    }
}

impl fmt::Display for StandingPredicateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => write!(f, "standing predicate update cancelled cooperatively"),
            Self::AuthorityRevoked(msg) => write!(f, "authority revoked: {msg}"),
            Self::StaleAuthorityGeneration { expected, observed } => {
                write!(
                    f,
                    "stale authority generation: expected {expected}, observed {observed}"
                )
            }
            Self::StaleAnchorSequence {
                last_committed,
                attempted,
            } => write!(
                f,
                "stale or regressed commit sequence: last {last_committed}, attempted {attempted}"
            ),
            Self::RedactedEntityBlocked { node_id } => {
                write!(f, "redacted entity '{node_id}' blocked before expansion")
            }
            Self::InvalidPredicate(msg) => write!(f, "invalid standing predicate: {msg}"),
            Self::NegativeMultiplicity {
                tuple,
                multiplicity,
            } => write!(
                f,
                "retraction drove '{tuple}' multiplicity below zero ({multiplicity})"
            ),
            Self::Graph(err) => write!(f, "graph/zset error: {err}"),
        }
    }
}

impl Error for StandingPredicateError {}

impl From<GraphError> for StandingPredicateError {
    fn from(value: GraphError) -> Self {
        match value {
            GraphError::Cancelled => Self::Cancelled,
            other => Self::Graph(other),
        }
    }
}

fn plane_tag(plane: Plane) -> &'static str {
    match plane {
        Plane::Authority => "authority",
        Plane::Cognition => "cognition",
        Plane::Effect => "effect",
    }
}

fn privacy_scope_digest(authority: &ProjectionAuthorityScope) -> ContentDigest {
    let mut enc = CanonicalEncoder::new();
    enc.text(STANDING_PREDICATES_RECEIPT_DOMAIN);
    enc.tag(0x50);
    let mut planes: Vec<&str> = authority
        .allowed_planes
        .iter()
        .map(|p| plane_tag(*p))
        .collect();
    planes.sort_unstable();
    enc.u64(planes.len() as u64);
    for plane in planes {
        enc.text(plane);
    }
    enc.u64(authority.redacted_node_ids.len() as u64);
    for redacted in &authority.redacted_node_ids {
        enc.text(redacted);
    }
    ContentDigest::sha256(&enc.finish())
}

fn validate_node_id(id: &str) -> Result<(), StandingPredicateError> {
    if id.is_empty() || id.len() > MAX_NODE_ID_LEN || id.chars().any(char::is_control) {
        return Err(StandingPredicateError::InvalidPredicate(format!(
            "node identity must be 1..={MAX_NODE_ID_LEN} control-free UTF-8 bytes"
        )));
    }
    Ok(())
}

fn validate_authority(
    universe: GraphUniverse,
    pinned_auth_gen: u64,
    pinned_privacy_epoch: u64,
    pinned_privacy_scope: ContentDigest,
    authority: &ProjectionAuthorityScope,
) -> Result<(), StandingPredicateError> {
    if !authority.capability_active || !authority.privacy_active {
        return Err(StandingPredicateError::AuthorityRevoked(
            "authority or privacy projection is inactive/revoked".to_owned(),
        ));
    }
    if !authority.allowed_universes.contains(&universe) {
        return Err(StandingPredicateError::AuthorityRevoked(format!(
            "universe {} not authorized by active scope",
            universe.as_str()
        )));
    }
    if authority.authority_generation != authority.expected_authority_generation {
        return Err(StandingPredicateError::StaleAuthorityGeneration {
            expected: authority.expected_authority_generation,
            observed: authority.authority_generation,
        });
    }
    if authority.authority_generation != pinned_auth_gen {
        return Err(StandingPredicateError::StaleAuthorityGeneration {
            expected: pinned_auth_gen,
            observed: authority.authority_generation,
        });
    }
    if authority.privacy_epoch != pinned_privacy_epoch {
        return Err(StandingPredicateError::AuthorityRevoked(format!(
            "privacy epoch drifted from {pinned_privacy_epoch} to {}; rebuild engine under new privacy projection",
            authority.privacy_epoch
        )));
    }
    if privacy_scope_digest(authority) != pinned_privacy_scope {
        return Err(StandingPredicateError::AuthorityRevoked(
            "privacy redaction or plane scope drifted from engine creation basis; rebuild engine under new scope".to_owned(),
        ));
    }
    Ok(())
}

fn validate_predicate(p: &StandingPredicate) -> Result<(), StandingPredicateError> {
    if p.predicate_id.is_empty()
        || p.predicate_id.len() > 128
        || p.predicate_id.chars().any(char::is_control)
    {
        return Err(StandingPredicateError::InvalidPredicate(
            "predicate_id must be 1..=128 control-free bytes".to_owned(),
        ));
    }
    match &p.kind {
        StandingPredicateKind::NodeOutDegreeAtLeast {
            node_id,
            min_out_degree,
        } => {
            validate_node_id(node_id)?;
            if *min_out_degree == 0 {
                return Err(StandingPredicateError::InvalidPredicate(
                    "NodeOutDegreeAtLeast requires threshold >= 1".to_owned(),
                ));
            }
        }
        StandingPredicateKind::NodeInDegreeAtLeast {
            node_id,
            min_in_degree,
        } => {
            validate_node_id(node_id)?;
            if *min_in_degree == 0 {
                return Err(StandingPredicateError::InvalidPredicate(
                    "NodeInDegreeAtLeast requires threshold >= 1".to_owned(),
                ));
            }
        }
        StandingPredicateKind::DirectedArcActive { tail_id, head_id } => {
            validate_node_id(tail_id)?;
            validate_node_id(head_id)?;
        }
        StandingPredicateKind::TwoHopPathExists {
            source_id,
            target_id,
        } => {
            validate_node_id(source_id)?;
            validate_node_id(target_id)?;
        }
        StandingPredicateKind::ActiveNodeCountAtLeast { min_active_nodes } => {
            if *min_active_nodes == 0 {
                return Err(StandingPredicateError::InvalidPredicate(
                    "ActiveNodeCountAtLeast requires threshold >= 1".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

/// Incremental retract/add standing-predicate engine over DBSP `ZSetGraphState` streams (`FSS-163`).
#[derive(Clone, Debug)]
pub struct StandingPredicateEngine {
    universe: GraphUniverse,
    site_lineage: String,
    last_commit_sequence: u64,
    authority_generation: u64,
    privacy_epoch: u64,
    privacy_scope: ContentDigest,
    predicates: Vec<StandingPredicate>,
    state: ZSetGraphState,
    /// Incrementally maintained out-degree view (`node -> sum of outgoing arc weights`).
    out_degree: ZSet<String>,
    /// Incrementally maintained in-degree view (`node -> sum of incoming arc weights`).
    in_degree: ZSet<String>,
    /// Incrementally maintained bilinear 2-hop composition (`(u, mid, w) -> weight`).
    two_hop_triples: ZSet<(String, String, String)>,
    /// Incrementally maintained projected 2-hop pair counts (`(u, w) -> sum_mid weight`).
    two_hop_pairs: ZSet<(String, String)>,
    /// Last active boolean per `predicate_id`.
    active_status: BTreeMap<String, bool>,
}

impl StandingPredicateEngine {
    /// Creates an empty standing-predicate engine pinned to `universe`, `initial_anchor`, and
    /// `authority`.
    pub fn new(
        universe: GraphUniverse,
        initial_anchor: LedgerAnchor,
        authority: &ProjectionAuthorityScope,
        predicates: Vec<StandingPredicate>,
    ) -> Result<Self, StandingPredicateError> {
        if !authority.capability_active
            || !authority.privacy_active
            || !authority.allowed_universes.contains(&universe)
            || authority.allowed_planes.is_empty()
        {
            return Err(StandingPredicateError::AuthorityRevoked(format!(
                "authority scope does not authorize {} with at least one semantic plane",
                universe.as_str()
            )));
        }
        if initial_anchor.site_lineage.is_empty()
            || initial_anchor.site_lineage.len() > 128
            || initial_anchor.site_lineage.chars().any(char::is_control)
        {
            return Err(StandingPredicateError::InvalidPredicate(
                "initial anchor site_lineage must be 1..=128 control-free bytes".to_owned(),
            ));
        }
        if authority.authority_generation != authority.expected_authority_generation {
            return Err(StandingPredicateError::StaleAuthorityGeneration {
                expected: authority.expected_authority_generation,
                observed: authority.authority_generation,
            });
        }
        if predicates.len() > MAX_STANDING_PREDICATES {
            return Err(StandingPredicateError::InvalidPredicate(format!(
                "predicate count {} exceeds limit {MAX_STANDING_PREDICATES}",
                predicates.len()
            )));
        }
        let mut sorted = predicates;
        sorted.sort_by(|a, b| a.predicate_id.cmp(&b.predicate_id));
        let mut seen = BTreeSet::new();
        for p in &sorted {
            validate_predicate(p)?;
            if !seen.insert(p.predicate_id.as_str()) {
                return Err(StandingPredicateError::InvalidPredicate(format!(
                    "duplicate predicate_id '{}'",
                    p.predicate_id
                )));
            }
            // Enforce capability/privacy redaction BEFORE expanding predicates!
            for entity in predicate_referenced_entities(&p.kind) {
                if authority.redacted_node_ids.contains(entity) {
                    return Err(StandingPredicateError::RedactedEntityBlocked {
                        node_id: entity.to_owned(),
                    });
                }
            }
        }
        let active_status = sorted
            .iter()
            .map(|p| (p.predicate_id.clone(), false))
            .collect();
        Ok(Self {
            universe,
            site_lineage: initial_anchor.site_lineage,
            last_commit_sequence: initial_anchor.commit_sequence,
            authority_generation: authority.authority_generation,
            privacy_epoch: authority.privacy_epoch,
            privacy_scope: privacy_scope_digest(authority),
            predicates: sorted,
            state: ZSetGraphState::default(),
            out_degree: ZSet::new(),
            in_degree: ZSet::new(),
            two_hop_triples: ZSet::new(),
            two_hop_pairs: ZSet::new(),
            active_status,
        })
    }

    /// Current committed `ZSetGraphState`.
    #[must_use]
    pub const fn state(&self) -> &ZSetGraphState {
        &self.state
    }

    /// Last committed authority sequence.
    #[must_use]
    pub const fn last_commit_sequence(&self) -> u64 {
        self.last_commit_sequence
    }

    /// Registered predicates in canonical `predicate_id` order.
    #[must_use]
    pub fn predicates(&self) -> &[StandingPredicate] {
        &self.predicates
    }

    /// Atomically applies one retract/add [`ZSetDeltaBatch`] at `anchor`, maintaining all derived
    /// views incrementally (`Delta(L(S)) = L(Delta(S))` and bilinear `Delta(E join E)`) and
    /// emitting a sealed [`StandingPredicateDeltaReceipt`].
    ///
    /// Any validation, authority, staleness, privacy, overflow, budget, or cancellation failure
    /// leaves the engine's committed state completely unchanged.
    pub fn apply_delta_batch(
        &mut self,
        batch: &ZSetDeltaBatch,
        anchor: &LedgerAnchor,
        authority: &ProjectionAuthorityScope,
        budget: Budget,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<StandingPredicateDeltaReceipt, StandingPredicateError> {
        if is_cancelled() {
            return Err(StandingPredicateError::Cancelled);
        }
        validate_authority(
            self.universe,
            self.authority_generation,
            self.privacy_epoch,
            self.privacy_scope,
            authority,
        )?;
        if anchor.site_lineage != self.site_lineage
            || anchor.commit_sequence <= self.last_commit_sequence
            || batch.commit_sequence != anchor.commit_sequence
        {
            return Err(StandingPredicateError::StaleAnchorSequence {
                last_committed: self.last_commit_sequence,
                attempted: batch.commit_sequence,
            });
        }
        // Validate node IDs and enforce capability/privacy redaction BEFORE consolidating deltas!
        for (nid, _) in &batch.node_deltas {
            validate_node_id(nid)?;
            if authority.redacted_node_ids.contains(nid) {
                return Err(StandingPredicateError::RedactedEntityBlocked {
                    node_id: nid.clone(),
                });
            }
        }
        for ((u, v), _) in &batch.arc_deltas {
            validate_node_id(u)?;
            validate_node_id(v)?;
            if authority.redacted_node_ids.contains(u) {
                return Err(StandingPredicateError::RedactedEntityBlocked { node_id: u.clone() });
            }
            if authority.redacted_node_ids.contains(v) {
                return Err(StandingPredicateError::RedactedEntityBlocked { node_id: v.clone() });
            }
        }

        let mut ops = 0_u64;
        let charge = |ops: &mut u64| -> Result<(), StandingPredicateError> {
            if is_cancelled() {
                return Err(StandingPredicateError::Cancelled);
            }
            *ops = ops.saturating_add(1);
            if *ops > budget.max_operations {
                return Err(StandingPredicateError::Graph(GraphError::BudgetExhausted {
                    dimension: "standing_predicate_ops",
                    limit: budget.max_operations,
                }));
            }
            Ok(())
        };

        // Stage candidate state updates without mutating `self` until all checks succeed!
        let mut delta_nodes = ZSet::new();
        for (n, w) in &batch.node_deltas {
            charge(&mut ops)?;
            delta_nodes.add_weight(n.clone(), *w)?;
        }
        let mut delta_arcs = ZSet::new();
        for ((u, v), w) in &batch.arc_deltas {
            charge(&mut ops)?;
            delta_arcs.add_weight((u.clone(), v.clone()), *w)?;
        }

        let next_nodes = self.state.nodes.add(&delta_nodes)?;
        for (n, &w) in next_nodes.iter() {
            if w < 0 {
                return Err(StandingPredicateError::NegativeMultiplicity {
                    tuple: format!("node:{n}"),
                    multiplicity: w,
                });
            }
        }
        let next_arcs = self.state.arcs.add(&delta_arcs)?;
        for ((u, v), &w) in next_arcs.iter() {
            if w < 0 {
                return Err(StandingPredicateError::NegativeMultiplicity {
                    tuple: format!("arc:{u}->{v}"),
                    multiplicity: w,
                });
            }
        }

        // 1. Linear incremental degree updates: Delta(out_deg) and Delta(in_deg).
        let mut delta_out = ZSet::new();
        let mut delta_in = ZSet::new();
        for ((u, v), &w) in delta_arcs.iter() {
            charge(&mut ops)?;
            delta_out.add_weight(u.clone(), w)?;
            delta_in.add_weight(v.clone(), w)?;
        }
        let next_out_degree = self.out_degree.add(&delta_out)?;
        let next_in_degree = self.in_degree.add(&delta_in)?;

        // 2. Bilinear DBSP incremental 2-hop update:
        //    Delta(E join E) = (Delta E join E_prev) + (E_prev join Delta E) + (Delta E join Delta E).
        if is_cancelled() {
            return Err(StandingPredicateError::Cancelled);
        }
        let estimated_join_ops = (delta_arcs.len() as u64).max(1);
        if ops.saturating_add(estimated_join_ops) > budget.max_operations {
            return Err(StandingPredicateError::Graph(GraphError::BudgetExhausted {
                dimension: "standing_predicate_ops",
                limit: budget.max_operations,
            }));
        }
        let delta_two_hop = zset_incremental_equijoin(
            &self.state.arcs,
            &delta_arcs,
            &self.state.arcs,
            &delta_arcs,
        )?;
        if is_cancelled() {
            return Err(StandingPredicateError::Cancelled);
        }
        let mut delta_pairs = ZSet::new();
        for ((u, _mid, w), &mult) in delta_two_hop.iter() {
            charge(&mut ops)?;
            delta_pairs.add_weight((u.clone(), w.clone()), mult)?;
        }
        let next_two_hop_triples = self.two_hop_triples.add(&delta_two_hop)?;
        let next_two_hop_pairs = self.two_hop_pairs.add(&delta_pairs)?;

        // 3. Evaluate all registered standing predicates from the incrementally maintained views!
        let active_node_count = next_nodes.len() as u64;
        if (self.predicates.len() as u64) > budget.max_output_entries {
            return Err(StandingPredicateError::Graph(GraphError::BudgetExhausted {
                dimension: "output_entries",
                limit: budget.max_output_entries,
            }));
        }
        let mut transitions = Vec::with_capacity(self.predicates.len());
        let mut next_active = BTreeMap::new();
        for pred in &self.predicates {
            charge(&mut ops)?;
            let (current_active, support_count) = match &pred.kind {
                StandingPredicateKind::NodeOutDegreeAtLeast {
                    node_id,
                    min_out_degree,
                } => {
                    let deg = next_out_degree.weight(node_id).max(0) as u64;
                    (deg >= *min_out_degree, deg)
                }
                StandingPredicateKind::NodeInDegreeAtLeast {
                    node_id,
                    min_in_degree,
                } => {
                    let deg = next_in_degree.weight(node_id).max(0) as u64;
                    (deg >= *min_in_degree, deg)
                }
                StandingPredicateKind::DirectedArcActive { tail_id, head_id } => {
                    let mult = next_arcs.weight(&(tail_id.clone(), head_id.clone())).max(0) as u64;
                    (mult > 0, mult)
                }
                StandingPredicateKind::TwoHopPathExists {
                    source_id,
                    target_id,
                } => {
                    let cnt = next_two_hop_pairs
                        .weight(&(source_id.clone(), target_id.clone()))
                        .max(0) as u64;
                    (cnt > 0, cnt)
                }
                StandingPredicateKind::ActiveNodeCountAtLeast { min_active_nodes } => {
                    (active_node_count >= *min_active_nodes, active_node_count)
                }
            };
            let previous_active = self
                .active_status
                .get(&pred.predicate_id)
                .copied()
                .unwrap_or(false);
            let transition = match (previous_active, current_active) {
                (false, true) => PredicateTransition::Fired,
                (true, false) => PredicateTransition::Retracted,
                (true, true) => PredicateTransition::Sustained,
                (false, false) => PredicateTransition::Absent,
            };
            next_active.insert(pred.predicate_id.clone(), current_active);
            transitions.push(PredicateTransitionRow {
                predicate_id: pred.predicate_id.clone(),
                previous_active,
                current_active,
                transition,
                support_count,
            });
        }

        let next_state = ZSetGraphState {
            nodes: next_nodes,
            arcs: next_arcs,
        };
        let state_digest = next_state.digest();

        let mut enc = CanonicalEncoder::new();
        enc.text(STANDING_PREDICATES_RECEIPT_DOMAIN);
        enc.tag(0x52);
        enc.text(self.universe.as_str());
        enc.text(&anchor.site_lineage);
        enc.u64(batch.commit_sequence);
        enc.u64(self.authority_generation);
        enc.u64(self.privacy_epoch);
        enc.digest(self.privacy_scope);
        enc.digest(anchor.state_root);
        enc.digest(state_digest);
        enc.u64(transitions.len() as u64);
        for row in &transitions {
            enc.text(&row.predicate_id);
            enc.bool(row.previous_active);
            enc.bool(row.current_active);
            enc.text(row.transition.as_str());
            enc.u64(row.support_count);
        }
        let receipt_digest = ContentDigest::sha256(&enc.finish());

        // Atomic commit of staged incremental state!
        self.last_commit_sequence = batch.commit_sequence;
        self.state = next_state;
        self.out_degree = next_out_degree;
        self.in_degree = next_in_degree;
        self.two_hop_triples = next_two_hop_triples;
        self.two_hop_pairs = next_two_hop_pairs;
        self.active_status = next_active;

        Ok(StandingPredicateDeltaReceipt {
            universe: self.universe,
            commit_sequence: batch.commit_sequence,
            anchor: anchor.clone(),
            state_digest,
            receipt_digest,
            transitions,
            operations_charged: ops,
            grants_effect_authority: false,
        })
    }
}

fn predicate_referenced_entities(kind: &StandingPredicateKind) -> Vec<&str> {
    match kind {
        StandingPredicateKind::NodeOutDegreeAtLeast { node_id, .. }
        | StandingPredicateKind::NodeInDegreeAtLeast { node_id, .. } => vec![node_id.as_str()],
        StandingPredicateKind::DirectedArcActive { tail_id, head_id } => {
            vec![tail_id.as_str(), head_id.as_str()]
        }
        StandingPredicateKind::TwoHopPathExists {
            source_id,
            target_id,
        } => vec![source_id.as_str(), target_id.as_str()],
        StandingPredicateKind::ActiveNodeCountAtLeast { .. } => Vec::new(),
    }
}

/// Deterministic full-recompute reference evaluator for [`StandingPredicate`] over a raw
/// [`ZSetGraphState`]. Used as the ground-truth oracle for `FSS-163` and `FSS-164` equivalence
/// fuzzing (`incremental == full_recompute` at every commit sequence!).
pub fn evaluate_standing_predicates_full_recompute(
    state: &ZSetGraphState,
    predicates: &[StandingPredicate],
) -> Result<BTreeMap<String, (bool, u64)>, GraphError> {
    let mut out_deg: BTreeMap<&str, i64> = BTreeMap::new();
    let mut in_deg: BTreeMap<&str, i64> = BTreeMap::new();
    for ((u, v), &w) in state.arcs.iter() {
        let eo = out_deg.entry(u.as_str()).or_insert(0);
        *eo = eo
            .checked_add(w)
            .ok_or(GraphError::ArithmeticOverflow("full_out_deg"))?;
        let ei = in_deg.entry(v.as_str()).or_insert(0);
        *ei = ei
            .checked_add(w)
            .ok_or(GraphError::ArithmeticOverflow("full_in_deg"))?;
    }
    let two_hop_full = zset_equijoin(&state.arcs, &state.arcs)?;
    let mut pair_sum: BTreeMap<(&str, &str), i64> = BTreeMap::new();
    for ((u, _mid, w), &mult) in two_hop_full.iter() {
        let entry = pair_sum.entry((u.as_str(), w.as_str())).or_insert(0);
        *entry = entry
            .checked_add(mult)
            .ok_or(GraphError::ArithmeticOverflow("full_two_hop_pair"))?;
    }

    let active_nodes = state.nodes.len() as u64;
    let mut out = BTreeMap::new();
    for pred in predicates {
        let res = match &pred.kind {
            StandingPredicateKind::NodeOutDegreeAtLeast {
                node_id,
                min_out_degree,
            } => {
                let d = out_deg.get(node_id.as_str()).copied().unwrap_or(0).max(0) as u64;
                (d >= *min_out_degree, d)
            }
            StandingPredicateKind::NodeInDegreeAtLeast {
                node_id,
                min_in_degree,
            } => {
                let d = in_deg.get(node_id.as_str()).copied().unwrap_or(0).max(0) as u64;
                (d >= *min_in_degree, d)
            }
            StandingPredicateKind::DirectedArcActive { tail_id, head_id } => {
                let m = state
                    .arcs
                    .weight(&(tail_id.clone(), head_id.clone()))
                    .max(0) as u64;
                (m > 0, m)
            }
            StandingPredicateKind::TwoHopPathExists {
                source_id,
                target_id,
            } => {
                let c = pair_sum
                    .get(&(source_id.as_str(), target_id.as_str()))
                    .copied()
                    .unwrap_or(0)
                    .max(0) as u64;
                (c > 0, c)
            }
            StandingPredicateKind::ActiveNodeCountAtLeast { min_active_nodes } => {
                (active_nodes >= *min_active_nodes, active_nodes)
            }
        };
        out.insert(pred.predicate_id.clone(), res);
    }
    Ok(out)
}
