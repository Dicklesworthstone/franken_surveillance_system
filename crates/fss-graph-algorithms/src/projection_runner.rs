#![forbid(unsafe_code)]
//! Authorized projection execution boundary wiring certified graph algorithm families (`FSS-154`
//! through `FSS-160`) onto O(1) `Arc`-shared [`GraphSnapshotView`] snapshots (`FSS-151`/`FSS-152`).
//!
//! Every execution enforces BEFORE expanding graph state into any algorithm:
//! 1. Cooperative cancellation (`Cancelled` with [`SnapshotGuidance::RetryWhenReady`]);
//! 2. Active capability, privacy-epoch, and authority-generation equality via
//!    [`GraphSnapshotCatalog::acquire_view`] (`ReauthorizeSnapshot` on drift/revocation);
//! 3. Exact snapshot freshness via [`GraphSnapshotCatalog::check_freshness`] (`StaleSnapshot` with
//!    [`SnapshotGuidance::ReacquireCurrentSnapshot`] whenever the anchor, authority, privacy
//!    epoch, or projection changed);
//! 4. Non-collapsed [`AbsenceBoundary`] propagation and explicit `grants_effect_authority == false`
//!    (`GRAPH-INV-004` / `GRAPH-INV-005`).

use std::error::Error;
use std::fmt;

use fss_core::LedgerAnchor;

use crate::assignment::{
    AssignmentProblem, KBestOutput, MatchOutput, NonAssignment, k_best_assignments_with_cancel,
    optimal_assignment_with_cancel,
};
use crate::bridges::{BridgeAnalysis, GraphBudget, analyse_bridges};
use crate::certified::{Budget, CertifiedRun};
use crate::dominators::{DominanceDirection, DominanceOutput, dominators};
use crate::dynconn::{
    DynamicConnectivityLane, DynamicConnectivityOutput, EdgeUpdate,
    dynamic_connectivity_reference_with_cancel, dynamic_connectivity_with_cancel,
};
use crate::flow::{CutMode, FlowOutput, max_flow_min_cut_with_cancel};
use crate::gomory_hu::{GomoryHuOutput, gomory_hu_tree};
use crate::graph::GraphError;
use crate::interdiction::{InterdictionOutput, InterdictionQuery, interdiction};
use crate::ksp::{KspOutput, k_shortest_paths};
use crate::min_cost_flow::{MinCostFlowOutput, min_cost_flow_with_cancel};
use crate::paths::{MultiSourceOutput, ShortestPathOutput, multi_source_distances, shortest_paths};
use crate::projection::{
    AbsenceBoundary, GraphUniverse, ProjectionAuthorityScope, ProjectionGeneration,
};
use crate::scc::{SccOutput, strongly_connected_components};
use crate::set_cover::{CoverAnalysis, CoverBudget, CoverError, CoverMethod, SetCoverProblem};
use crate::snapshot_view::{
    GraphSnapshotCatalog, GraphSnapshotView, SnapshotFreshness, SnapshotGuidance,
    SnapshotInvalidationReason, SnapshotViewError,
};
use crate::steiner::{SteinerTreeOutput, steiner_tree_approximation};
use crate::submodular::{SubmodularAnalysis, SubmodularProblem};
use crate::temporal::{TemporalNetwork, TemporalOutput, temporal_reachability};
use crate::topo::{TopoOutput, topological_schedule};

/// Typed failure returned by authorized snapshot graph-algorithm execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizedRunError {
    /// Cooperative cancellation observed before or during execution.
    Cancelled,
    /// Snapshot view or authority validation failed.
    Snapshot(SnapshotViewError),
    /// Supplied snapshot view is stale/invalidated relative to the active catalog.
    StaleSnapshot(SnapshotInvalidationReason),
    /// Underlying certified graph algorithm failed closed (budget, precondition, overflow, cancel).
    Algorithm(GraphError),
    /// Underlying set-cover or submodular active-perception algorithm failed closed.
    Cover(CoverError),
}

impl AuthorizedRunError {
    /// Stable machine error identity.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Cancelled | Self::Algorithm(GraphError::Cancelled) => {
                "ERR-GRAPH-AUTHORIZED-CANCELLED-001"
            }
            Self::Snapshot(err) => err.code(),
            Self::StaleSnapshot(_) => "ERR-GRAPH-AUTHORIZED-STALE-SNAPSHOT-001",
            Self::Algorithm(_) => "ERR-GRAPH-AUTHORIZED-ALGORITHM-001",
            Self::Cover(_) => "ERR-GRAPH-AUTHORIZED-COVER-001",
        }
    }

    /// Safe operator/agent recovery guidance for this refusal.
    #[must_use]
    pub const fn guidance(&self) -> SnapshotGuidance {
        match self {
            Self::Cancelled | Self::Algorithm(GraphError::Cancelled) => {
                SnapshotGuidance::RetryWhenReady
            }
            Self::Snapshot(err) => err.guidance(),
            Self::StaleSnapshot(_) => SnapshotGuidance::ReacquireCurrentSnapshot,
            Self::Algorithm(_) | Self::Cover(_) => SnapshotGuidance::RepairSnapshotInput,
        }
    }
}

impl fmt::Display for AuthorizedRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => write!(f, "authorized graph execution cancelled cooperatively"),
            Self::Snapshot(err) => write!(f, "snapshot authorization failed: {err}"),
            Self::StaleSnapshot(reason) => write!(f, "stale snapshot view: {reason:?}"),
            Self::Algorithm(err) => write!(f, "certified algorithm failed: {err}"),
            Self::Cover(err) => write!(f, "cover/submodular algorithm failed: {err}"),
        }
    }
}

impl Error for AuthorizedRunError {}

impl From<SnapshotViewError> for AuthorizedRunError {
    fn from(value: SnapshotViewError) -> Self {
        Self::Snapshot(value)
    }
}

impl From<GraphError> for AuthorizedRunError {
    fn from(value: GraphError) -> Self {
        match value {
            GraphError::Cancelled => Self::Cancelled,
            other => Self::Algorithm(other),
        }
    }
}

impl From<CoverError> for AuthorizedRunError {
    fn from(value: CoverError) -> Self {
        match value {
            CoverError::Cancelled => Self::Cancelled,
            other => Self::Cover(other),
        }
    }
}

/// Authority-, anchor-, and absence-pinned output wrapper for every authorized snapshot execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedRunReceipt<T> {
    /// Typed graph universe executed over.
    pub universe: GraphUniverse,
    /// Exact pinned ledger anchor.
    pub anchor: LedgerAnchor,
    /// Exact cryptographic projection generation stamp.
    pub projection_generation: ProjectionGeneration,
    /// Non-collapsed absence boundary (redacted/omitted nodes never laundered into certified absence!).
    pub absence_boundary: AbsenceBoundary,
    /// Certified algorithm output / run witness.
    pub result: T,
    /// Always `false`: derived graph intelligence NEVER grants effect authority (`GRAPH-INV-004`).
    pub grants_effect_authority: bool,
}

impl<T> AuthorizedRunReceipt<T> {
    fn wrap(view: &GraphSnapshotView, result: T) -> Self {
        Self {
            universe: view.universe(),
            anchor: view.anchor().clone(),
            projection_generation: view.generation(),
            absence_boundary: view.absence_boundary().clone(),
            result,
            grants_effect_authority: false,
        }
    }

    fn wrap_with_boundary(
        view: &GraphSnapshotView,
        absence_boundary: AbsenceBoundary,
        result: T,
    ) -> Self {
        Self {
            universe: view.universe(),
            anchor: view.anchor().clone(),
            projection_generation: view.generation(),
            absence_boundary,
            result,
            grants_effect_authority: false,
        }
    }
}

/// Conservatively combines two [`AbsenceBoundary`] states across paired snapshots so an
/// uncertified or redacted view can NEVER be laundered into [`AbsenceBoundary::CertifiedComplete`].
fn combine_absence_boundaries(a: &AbsenceBoundary, b: &AbsenceBoundary) -> AbsenceBoundary {
    match (a, b) {
        (AbsenceBoundary::CertifiedComplete { .. }, AbsenceBoundary::CertifiedComplete { .. }) => {
            a.clone()
        }
        (
            AbsenceBoundary::UncertifiedOrRedacted {
                redacted_node_count: ra,
                suppressed_edge_count: sa,
                reason: reason_a,
            },
            AbsenceBoundary::UncertifiedOrRedacted {
                redacted_node_count: rb,
                suppressed_edge_count: sb,
                reason: reason_b,
            },
        ) => AbsenceBoundary::UncertifiedOrRedacted {
            redacted_node_count: ra.max(rb).to_owned(),
            suppressed_edge_count: sa.max(sb).to_owned(),
            reason: if reason_a == reason_b {
                reason_a.clone()
            } else {
                format!("{reason_a}; {reason_b}")
            },
        },
        (uncertified @ AbsenceBoundary::UncertifiedOrRedacted { .. }, _)
        | (_, uncertified @ AbsenceBoundary::UncertifiedOrRedacted { .. }) => uncertified.clone(),
    }
}

/// Verifies cooperative cancellation, active authority/privacy scope, and exact catalog freshness
/// BEFORE expanding `view` into any certified graph algorithm.
pub fn authorize_snapshot_execution(
    view: &GraphSnapshotView,
    catalog: &GraphSnapshotCatalog,
    authority: &ProjectionAuthorityScope,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), AuthorizedRunError> {
    if is_cancelled() {
        return Err(AuthorizedRunError::Cancelled);
    }
    match catalog.check_freshness(view) {
        SnapshotFreshness::Current => {}
        SnapshotFreshness::Invalidated { reason, .. } => {
            return Err(AuthorizedRunError::StaleSnapshot(reason));
        }
    }
    let active = catalog.acquire_view(view.universe(), authority, false)?;
    if active.generation() != view.generation() {
        return Err(AuthorizedRunError::StaleSnapshot(
            SnapshotInvalidationReason::ProjectionReplaced,
        ));
    }
    if is_cancelled() {
        return Err(AuthorizedRunError::Cancelled);
    }
    Ok(())
}

fn reject_redacted_id(
    id: &str,
    authority: &ProjectionAuthorityScope,
) -> Result<(), AuthorizedRunError> {
    if authority.redacted_node_ids.contains(id) {
        return Err(AuthorizedRunError::Snapshot(
            SnapshotViewError::AuthorityMismatch(format!(
                "redacted entity '{id}' blocked before graph expansion"
            )),
        ));
    }
    Ok(())
}

fn reject_redacted_set_cover(
    problem: &SetCoverProblem,
    authority: &ProjectionAuthorityScope,
) -> Result<(), AuthorizedRunError> {
    for element in problem.elements() {
        reject_redacted_id(element, authority)?;
    }
    for set in problem.sets() {
        if !problem.excluded().contains(set.id()) {
            reject_redacted_id(set.id(), authority)?;
        }
    }
    Ok(())
}

/// `FSS-154` — Runs `ALG-DYNCONN-001` (either deterministic per-state BFS reference lane or
/// optimized segment-tree rollback lane) over an authorized snapshot view.
#[allow(clippy::too_many_arguments)]
pub fn run_dynamic_connectivity_on_snapshot(
    view: &GraphSnapshotView,
    catalog: &GraphSnapshotCatalog,
    authority: &ProjectionAuthorityScope,
    unit: &str,
    relation_filter: Option<&str>,
    lane: DynamicConnectivityLane,
    batches: &[Vec<EdgeUpdate>],
    queries: &[(u32, &str, &str)],
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AuthorizedRunReceipt<CertifiedRun<DynamicConnectivityOutput>>, AuthorizedRunError> {
    authorize_snapshot_execution(view, catalog, authority, is_cancelled)?;
    for batch in batches {
        for update in batch {
            match update {
                EdgeUpdate::Insert(a, b) | EdgeUpdate::Delete(a, b) => {
                    reject_redacted_id(a, authority)?;
                    reject_redacted_id(b, authority)?;
                }
            }
        }
    }
    for &(_, a, b) in queries {
        reject_redacted_id(a, authority)?;
        reject_redacted_id(b, authority)?;
    }
    let graph = view.projection().to_weighted_graph(unit, relation_filter)?;
    let run = match lane {
        DynamicConnectivityLane::ReferencePerStateBfs => {
            dynamic_connectivity_reference_with_cancel(
                &graph,
                batches,
                queries,
                budget,
                is_cancelled,
            )?
        }
        DynamicConnectivityLane::OptimizedSegmentTreeRollback => {
            dynamic_connectivity_with_cancel(&graph, batches, queries, budget, is_cancelled)?
        }
    };
    Ok(AuthorizedRunReceipt::wrap(view, run))
}

/// `FSS-155` — Runs `ALG-BRIDGE-001` (articulation points & bridges) over an authorized snapshot view.
pub fn run_bridges_on_snapshot(
    view: &GraphSnapshotView,
    catalog: &GraphSnapshotCatalog,
    authority: &ProjectionAuthorityScope,
    root: Option<&str>,
    budget: GraphBudget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AuthorizedRunReceipt<BridgeAnalysis>, AuthorizedRunError> {
    authorize_snapshot_execution(view, catalog, authority, is_cancelled)?;
    if let Some(root_id) = root {
        reject_redacted_id(root_id, authority)?;
    }
    let simple = view.projection().to_undirected_simple_graph()?;
    let analysis = analyse_bridges(&simple, root, budget)?;
    if is_cancelled() {
        return Err(AuthorizedRunError::Cancelled);
    }
    Ok(AuthorizedRunReceipt::wrap(view, analysis))
}

/// `FSS-155` — Runs `ALG-DOM-001` (dominators / postdominators) over an authorized snapshot view.
#[allow(clippy::too_many_arguments)]
pub fn run_dominators_on_snapshot(
    view: &GraphSnapshotView,
    catalog: &GraphSnapshotCatalog,
    authority: &ProjectionAuthorityScope,
    unit: &str,
    relation_filter: Option<&str>,
    root: &str,
    direction: DominanceDirection,
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AuthorizedRunReceipt<CertifiedRun<DominanceOutput>>, AuthorizedRunError> {
    authorize_snapshot_execution(view, catalog, authority, is_cancelled)?;
    reject_redacted_id(root, authority)?;
    let graph = view.projection().to_weighted_graph(unit, relation_filter)?;
    let run = dominators(&graph, root, direction, budget)?;
    if is_cancelled() {
        return Err(AuthorizedRunError::Cancelled);
    }
    Ok(AuthorizedRunReceipt::wrap(view, run))
}

/// `FSS-156` — Runs `ALG-SP-001` (lexicographic shortest paths) over an authorized snapshot view.
#[allow(clippy::too_many_arguments)]
pub fn run_shortest_paths_on_snapshot(
    view: &GraphSnapshotView,
    catalog: &GraphSnapshotCatalog,
    authority: &ProjectionAuthorityScope,
    unit: &str,
    relation_filter: Option<&str>,
    source: &str,
    target: Option<&str>,
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AuthorizedRunReceipt<CertifiedRun<ShortestPathOutput>>, AuthorizedRunError> {
    authorize_snapshot_execution(view, catalog, authority, is_cancelled)?;
    reject_redacted_id(source, authority)?;
    if let Some(target_id) = target {
        reject_redacted_id(target_id, authority)?;
    }
    let graph = view.projection().to_weighted_graph(unit, relation_filter)?;
    let run = shortest_paths(&graph, source, target, budget)?;
    if is_cancelled() {
        return Err(AuthorizedRunError::Cancelled);
    }
    Ok(AuthorizedRunReceipt::wrap(view, run))
}

/// `FSS-156` — Runs `ALG-MSD-001` (multi-source Voronoi distances) over an authorized snapshot view.
#[allow(clippy::too_many_arguments)]
pub fn run_multi_source_distances_on_snapshot(
    view: &GraphSnapshotView,
    catalog: &GraphSnapshotCatalog,
    authority: &ProjectionAuthorityScope,
    unit: &str,
    relation_filter: Option<&str>,
    sources: &[&str],
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AuthorizedRunReceipt<CertifiedRun<MultiSourceOutput>>, AuthorizedRunError> {
    authorize_snapshot_execution(view, catalog, authority, is_cancelled)?;
    for source in sources {
        reject_redacted_id(source, authority)?;
    }
    let graph = view.projection().to_weighted_graph(unit, relation_filter)?;
    let run = multi_source_distances(&graph, sources, budget)?;
    if is_cancelled() {
        return Err(AuthorizedRunError::Cancelled);
    }
    Ok(AuthorizedRunReceipt::wrap(view, run))
}

/// `FSS-156` — Runs `ALG-KSP-001` (k-shortest diverse paths) over an authorized snapshot view.
#[allow(clippy::too_many_arguments)]
pub fn run_k_shortest_paths_on_snapshot(
    view: &GraphSnapshotView,
    catalog: &GraphSnapshotCatalog,
    authority: &ProjectionAuthorityScope,
    unit: &str,
    relation_filter: Option<&str>,
    source: &str,
    target: &str,
    k: u32,
    min_distinct_arcs: u32,
    max_enumerated: u32,
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AuthorizedRunReceipt<CertifiedRun<KspOutput>>, AuthorizedRunError> {
    authorize_snapshot_execution(view, catalog, authority, is_cancelled)?;
    reject_redacted_id(source, authority)?;
    reject_redacted_id(target, authority)?;
    let graph = view.projection().to_weighted_graph(unit, relation_filter)?;
    let run = k_shortest_paths(
        &graph,
        source,
        target,
        k,
        min_distinct_arcs,
        max_enumerated,
        budget,
    )?;
    if is_cancelled() {
        return Err(AuthorizedRunError::Cancelled);
    }
    Ok(AuthorizedRunReceipt::wrap(view, run))
}

/// `FSS-156` — Runs `ALG-TREACH-001` (temporal reachability) gated by an authorized `G_time` snapshot view.
#[allow(clippy::too_many_arguments)]
pub fn run_temporal_reachability_on_snapshot(
    view: &GraphSnapshotView,
    catalog: &GraphSnapshotCatalog,
    authority: &ProjectionAuthorityScope,
    network: &TemporalNetwork,
    source: &str,
    start: (u64, u64),
    max_intervals: u32,
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AuthorizedRunReceipt<CertifiedRun<TemporalOutput>>, AuthorizedRunError> {
    authorize_snapshot_execution(view, catalog, authority, is_cancelled)?;
    if view.universe() != GraphUniverse::GTime {
        return Err(AuthorizedRunError::Algorithm(
            GraphError::PreconditionFailed(format!(
                "temporal reachability requires G_time snapshot, got {}",
                view.universe().as_str()
            )),
        ));
    }
    reject_redacted_id(source, authority)?;
    for id in network.ids() {
        reject_redacted_id(id, authority)?;
    }
    let run = temporal_reachability(network, source, start, max_intervals, budget)?;
    if is_cancelled() {
        return Err(AuthorizedRunError::Cancelled);
    }
    Ok(AuthorizedRunReceipt::wrap(view, run))
}

/// `FSS-157` — Runs `ALG-MCF-001` (min-cost flow) over authorized cost and capacity snapshots.
#[allow(clippy::too_many_arguments)]
pub fn run_min_cost_flow_on_snapshots(
    costs_view: &GraphSnapshotView,
    capacities_view: &GraphSnapshotView,
    catalog: &GraphSnapshotCatalog,
    authority: &ProjectionAuthorityScope,
    cost_unit: &str,
    capacity_unit: &str,
    source: &str,
    sink: &str,
    demand: u64,
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AuthorizedRunReceipt<CertifiedRun<MinCostFlowOutput>>, AuthorizedRunError> {
    authorize_snapshot_execution(costs_view, catalog, authority, is_cancelled)?;
    if costs_view.generation() != capacities_view.generation() {
        authorize_snapshot_execution(capacities_view, catalog, authority, is_cancelled)?;
    }
    // GRAPH-INV-001 / GRAPH-INV-002: both views must share one pinned anchor and one typed universe.
    if costs_view.anchor() != capacities_view.anchor() {
        return Err(AuthorizedRunError::Algorithm(
            GraphError::PreconditionFailed(
                "min-cost flow cost and capacity snapshots must share the same ledger anchor"
                    .to_owned(),
            ),
        ));
    }
    if costs_view.universe() != capacities_view.universe() {
        return Err(AuthorizedRunError::Algorithm(
            GraphError::PreconditionFailed(format!(
                "min-cost flow cost ({}) and capacity ({}) snapshots must share the same universe",
                costs_view.universe().as_str(),
                capacities_view.universe().as_str()
            )),
        ));
    }
    reject_redacted_id(source, authority)?;
    reject_redacted_id(sink, authority)?;
    let costs = costs_view.projection().to_weighted_graph(cost_unit, None)?;
    let capacities = capacities_view
        .projection()
        .to_weighted_graph(capacity_unit, None)?;
    let run = min_cost_flow_with_cancel(
        &costs,
        &capacities,
        source,
        sink,
        demand,
        budget,
        is_cancelled,
    )?;
    let combined_boundary = combine_absence_boundaries(
        costs_view.absence_boundary(),
        capacities_view.absence_boundary(),
    );
    Ok(AuthorizedRunReceipt::wrap_with_boundary(
        costs_view,
        combined_boundary,
        run,
    ))
}

/// `FSS-157` — Runs `ALG-MATCH-001` (optimal weighted bipartite assignment) gated by an authorized
/// `G_assoc` snapshot view.
pub fn run_optimal_assignment_on_snapshot(
    view: &GraphSnapshotView,
    catalog: &GraphSnapshotCatalog,
    authority: &ProjectionAuthorityScope,
    problem: &AssignmentProblem,
    policy: NonAssignment,
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AuthorizedRunReceipt<CertifiedRun<MatchOutput>>, AuthorizedRunError> {
    authorize_snapshot_execution(view, catalog, authority, is_cancelled)?;
    if view.universe() != GraphUniverse::GAssoc {
        return Err(AuthorizedRunError::Algorithm(
            GraphError::PreconditionFailed(format!(
                "optimal assignment requires G_assoc snapshot, got {}",
                view.universe().as_str()
            )),
        ));
    }
    for id in problem.left().iter().chain(problem.right().iter()) {
        reject_redacted_id(id, authority)?;
    }
    let run = optimal_assignment_with_cancel(problem, policy, budget, is_cancelled)?;
    Ok(AuthorizedRunReceipt::wrap(view, run))
}

/// `FSS-157` — Runs `ALG-MULTIMATCH-001` (k-best global assignment preserving ambiguity) gated by
/// an authorized `G_assoc` snapshot view.
#[allow(clippy::too_many_arguments)]
pub fn run_k_best_assignments_on_snapshot(
    view: &GraphSnapshotView,
    catalog: &GraphSnapshotCatalog,
    authority: &ProjectionAuthorityScope,
    problem: &AssignmentProblem,
    policy: NonAssignment,
    k: u32,
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AuthorizedRunReceipt<CertifiedRun<KBestOutput>>, AuthorizedRunError> {
    authorize_snapshot_execution(view, catalog, authority, is_cancelled)?;
    if view.universe() != GraphUniverse::GAssoc {
        return Err(AuthorizedRunError::Algorithm(
            GraphError::PreconditionFailed(format!(
                "k-best assignment requires G_assoc snapshot, got {}",
                view.universe().as_str()
            )),
        ));
    }
    for id in problem.left().iter().chain(problem.right().iter()) {
        reject_redacted_id(id, authority)?;
    }
    let run = k_best_assignments_with_cancel(problem, policy, k, budget, is_cancelled)?;
    Ok(AuthorizedRunReceipt::wrap(view, run))
}

/// `FSS-158` — Runs `ALG-FLOW-001` (max-flow / min-cut) over an authorized snapshot view.
#[allow(clippy::too_many_arguments)]
pub fn run_max_flow_min_cut_on_snapshot(
    view: &GraphSnapshotView,
    catalog: &GraphSnapshotCatalog,
    authority: &ProjectionAuthorityScope,
    unit: &str,
    relation_filter: Option<&str>,
    source: &str,
    sink: &str,
    mode: CutMode,
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AuthorizedRunReceipt<CertifiedRun<FlowOutput>>, AuthorizedRunError> {
    authorize_snapshot_execution(view, catalog, authority, is_cancelled)?;
    reject_redacted_id(source, authority)?;
    reject_redacted_id(sink, authority)?;
    let graph = view.projection().to_weighted_graph(unit, relation_filter)?;
    let run = max_flow_min_cut_with_cancel(&graph, source, sink, mode, budget, is_cancelled)?;
    Ok(AuthorizedRunReceipt::wrap(view, run))
}

/// `FSS-158` — Runs `ALG-GH-001` (Gomory-Hu all-pairs min-cut tree) over an authorized snapshot view.
pub fn run_gomory_hu_on_snapshot(
    view: &GraphSnapshotView,
    catalog: &GraphSnapshotCatalog,
    authority: &ProjectionAuthorityScope,
    unit: &str,
    relation_filter: Option<&str>,
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AuthorizedRunReceipt<CertifiedRun<GomoryHuOutput>>, AuthorizedRunError> {
    authorize_snapshot_execution(view, catalog, authority, is_cancelled)?;
    let graph = view.projection().to_weighted_graph(unit, relation_filter)?;
    let run = gomory_hu_tree(&graph, budget)?;
    if is_cancelled() {
        return Err(AuthorizedRunError::Cancelled);
    }
    Ok(AuthorizedRunReceipt::wrap(view, run))
}

/// `FSS-159` — Runs `ALG-SCC-001` (strongly connected components & condensation DAG) over an
/// authorized directed snapshot view.
pub fn run_scc_on_snapshot(
    view: &GraphSnapshotView,
    catalog: &GraphSnapshotCatalog,
    authority: &ProjectionAuthorityScope,
    unit: &str,
    relation_filter: Option<&str>,
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AuthorizedRunReceipt<CertifiedRun<SccOutput>>, AuthorizedRunError> {
    authorize_snapshot_execution(view, catalog, authority, is_cancelled)?;
    let graph = view.projection().to_weighted_graph(unit, relation_filter)?;
    let run = strongly_connected_components(&graph, budget)?;
    if is_cancelled() {
        return Err(AuthorizedRunError::Cancelled);
    }
    Ok(AuthorizedRunReceipt::wrap(view, run))
}

/// `FSS-159` — Runs `ALG-TOPO-001` (lexicographic topological order, parallel frontiers, and
/// critical-path schedule) over an authorized directed acyclic snapshot view.
pub fn run_topological_schedule_on_snapshot(
    view: &GraphSnapshotView,
    catalog: &GraphSnapshotCatalog,
    authority: &ProjectionAuthorityScope,
    unit: &str,
    relation_filter: Option<&str>,
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AuthorizedRunReceipt<CertifiedRun<TopoOutput>>, AuthorizedRunError> {
    authorize_snapshot_execution(view, catalog, authority, is_cancelled)?;
    let graph = view.projection().to_weighted_graph(unit, relation_filter)?;
    let run = topological_schedule(&graph, budget)?;
    if is_cancelled() {
        return Err(AuthorizedRunError::Cancelled);
    }
    Ok(AuthorizedRunReceipt::wrap(view, run))
}

/// `FSS-160` — Runs `ALG-SETCOVER-001` gated by an authorized visibility/coverage snapshot view.
#[allow(clippy::too_many_arguments)]
pub fn run_set_cover_on_snapshot(
    view: &GraphSnapshotView,
    catalog: &GraphSnapshotCatalog,
    authority: &ProjectionAuthorityScope,
    problem: &SetCoverProblem,
    method: CoverMethod,
    budget: CoverBudget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AuthorizedRunReceipt<CoverAnalysis>, AuthorizedRunError> {
    authorize_snapshot_execution(view, catalog, authority, is_cancelled)?;
    reject_redacted_set_cover(problem, authority)?;
    let analysis = problem.solve_cancellable(method, budget, &|| is_cancelled())?;
    Ok(AuthorizedRunReceipt::wrap(view, analysis))
}

/// `FSS-160` — Runs `ALG-SUBMOD-001` gated by an authorized visibility/coverage snapshot view.
pub fn run_submodular_on_snapshot(
    view: &GraphSnapshotView,
    catalog: &GraphSnapshotCatalog,
    authority: &ProjectionAuthorityScope,
    problem: &SubmodularProblem,
    budget: CoverBudget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AuthorizedRunReceipt<SubmodularAnalysis>, AuthorizedRunError> {
    authorize_snapshot_execution(view, catalog, authority, is_cancelled)?;
    reject_redacted_set_cover(problem.support(), authority)?;
    let analysis = problem.solve_cancellable(budget, &|| is_cancelled())?;
    Ok(AuthorizedRunReceipt::wrap(view, analysis))
}

/// `FSS-160` — Runs `ALG-STEINER-001` (Steiner tree approximation) over an authorized snapshot view.
#[allow(clippy::too_many_arguments)]
pub fn run_steiner_on_snapshot(
    view: &GraphSnapshotView,
    catalog: &GraphSnapshotCatalog,
    authority: &ProjectionAuthorityScope,
    unit: &str,
    relation_filter: Option<&str>,
    terminals: &[&str],
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AuthorizedRunReceipt<CertifiedRun<SteinerTreeOutput>>, AuthorizedRunError> {
    authorize_snapshot_execution(view, catalog, authority, is_cancelled)?;
    for terminal in terminals {
        reject_redacted_id(terminal, authority)?;
    }
    let graph = view.projection().to_weighted_graph(unit, relation_filter)?;
    let run = steiner_tree_approximation(&graph, terminals, budget)?;
    if is_cancelled() {
        return Err(AuthorizedRunError::Cancelled);
    }
    Ok(AuthorizedRunReceipt::wrap(view, run))
}

/// `FSS-160` — Runs `ALG-INTERDICT-001` (network interdiction / robust placement) over an
/// authorized snapshot view.
#[allow(clippy::too_many_arguments)]
pub fn run_interdiction_on_snapshot(
    view: &GraphSnapshotView,
    catalog: &GraphSnapshotCatalog,
    authority: &ProjectionAuthorityScope,
    unit: &str,
    relation_filter: Option<&str>,
    query: &InterdictionQuery,
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AuthorizedRunReceipt<CertifiedRun<InterdictionOutput>>, AuthorizedRunError> {
    authorize_snapshot_execution(view, catalog, authority, is_cancelled)?;
    for id in query
        .entries
        .iter()
        .chain(query.targets.iter())
        .chain(query.observers.keys())
        .chain(query.costs.keys())
    {
        reject_redacted_id(id, authority)?;
    }
    for sensors in query.observers.values() {
        for sensor in sensors {
            reject_redacted_id(sensor, authority)?;
        }
    }
    let graph = view.projection().to_weighted_graph(unit, relation_filter)?;
    let run = interdiction(&graph, query, budget)?;
    if is_cancelled() {
        return Err(AuthorizedRunError::Cancelled);
    }
    Ok(AuthorizedRunReceipt::wrap(view, run))
}
