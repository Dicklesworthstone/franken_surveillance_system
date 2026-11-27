#![forbid(unsafe_code)]
//! Registered, witness-carrying graph algorithms over immutable FSS projections.
//!
//! Graph answers in FSS are derived cognition (`GRAPH-INV-004`): they pin one authority anchor
//! and one immutable projection (`GRAPH-INV-001`), make every equal-choice deterministic through a
//! registered tie-break (`GRAPH-INV-003`), and travel with a
//! [`fss_core::GraphAlgorithmWitness`] (`GRAPH-INV-008`). This crate implements the first
//! registered family end to end:
//!
//! * [`graph`]: the canonical immutable undirected simple graph (stable string identities, sorted
//!   compressed adjacency, domain-separated projection digest);
//! * [`bridges`]: `ALG-BRIDGE-001` (`articulation_points_and_bridges`), an iterative Tarjan DFS
//!   with low links, plus the exact nodes each cut vertex or bridge separates from a declared
//!   root; complexity counters are checked against the registered bound on every run and a
//!   violation fails closed;
//! * [`reference`]: the brute-force removal oracle it is certified against;
//! * [`coverage`]: the `SensorCoverageGraph` projection (evidence plane, sensors, zones) that
//!   answers "which single sensor loss leaves zone Z without any retained witness";
//! * [`coverage_timeline`]: exact certain-boundary partitions preserving handovers and gaps
//!   under one aggregate selection, graph and output budget;
//! * [`failure_domains`]: independent simultaneous-member-loss scenarios for owner-declared
//!   shared network, power, clock and host dependencies;
//! * [`registry`]: the registered identities, tie-break, policy and complexity bound.
//!
//! Nothing here reads a clock, the filesystem, or the network, and no output grants authority.

pub mod assignment;
pub mod bridges;
/// Canonical graph serialization and cryptographic hash verification (`FSS-153`, `fss-x4a.23.3`).
pub mod canonical_codec;
/// Connected dominating set and resilient observer-backbone design (`ALG-CDS-001`, `fss-x4a.23.70.8`).
pub mod cds;
pub mod centrality;
pub mod certified;
pub mod community;
/// Source-pinned anonymous tracklet handoff paths with exact implicit alternatives.
pub mod continuity;
pub mod coverage;
pub mod coverage_timeline;
/// Certified d-separation and shared-failure-domain causal independence analysis (`FSS-161`, `fss-x4a.23.11`).
pub mod d_separation;
pub mod dominators;
pub mod dynconn;
/// Active event-revision support dependencies with certified structural bottlenecks.
pub mod evidence;
/// Bounded current-head support briefs preserving ungrounded branches and historical corrections.
pub mod evidence_brief;
/// Exact historical event references with complete-lineage validation and witnessed support.
pub mod evidence_history;
/// Facility location, k-center, and p-median placement optimization (`ALG-FACILITY-001`, `fss-x4a.23.70.1`).
pub mod facility;
pub mod factorized_join;
/// Capability-projected factorized graph-relational query reference planner (`FSS-162`, `fss-x4a.23.12`).
pub mod factorized_planner;
pub mod failure_domains;
pub mod flow;
pub mod gomory_hu;
pub mod graph;
pub mod hits;
/// Native hypergraph and factor-graph reasoning (`ALG-HYPER-001`, `fss-x4a.23.70.9`).
pub mod hypergraph;
pub mod interdiction;
/// Canonical graph hashing, isomorphism, and topology-drift detection (`ALG-ISO-001`, `fss-x4a.23.70.2`).
pub mod isomorphism;
/// Exact k-core, k-truss, and robust-support decomposition (`ALG-KCORE-001`, `fss-x4a.23.70.5`).
pub mod kcore;
pub mod ksp;
/// Non-authoritative link prediction with mandatory exact verification (`ALG-LINKPRED-001`, `fss-x4a.23.70.7`).
pub mod link_pred;
pub mod min_cost_flow;
/// Exact 16-class directed MAN triadic census and routine-structure analysis (`ALG-MOTIF-001`, `fss-x4a.23.70.3`).
pub mod motif;
pub mod oracles;
pub mod paths;
/// Exact declared-layer 2D planarity and geometric consistency checks (`ALG-PLANAR-001`, `fss-x4a.23.70.6`).
pub mod planar;
pub mod ppr;
/// Immutable graph projection and generational-handle core (`FSS-151`, `fss-x4a.23.1`).
pub mod projection;
/// Authorized snapshot execution boundary wiring `FSS-154..160` onto `GraphSnapshotView`.
pub mod projection_runner;
pub mod reference;
pub mod registry;
pub mod reliability;
pub mod resilient_cover;
/// Exact budgeted placement advice over explicit movement and sensor-loss assumptions.
pub mod robust_placement;
pub mod scc;
/// Bounded unit-cost set cover with exact-small and explicitly heuristic selection.
pub mod set_cover;
/// O(1) `Arc`-shared graph snapshot views and deterministic invalidation (`FSS-152`, `fss-x4a.23.2`).
pub mod snapshot_view;
pub mod spanning;
pub mod spectral;
/// Incremental retract/add standing predicates over DBSP `Z-set` delta streams (`FSS-163`, `fss-x4a.23.13`).
pub mod standing_predicates;
pub mod steiner;
/// Exact aggregate camera-demand routing with shared capacity, failure, cost and cut proofs.
pub mod stream_capacity;
/// Bounded VF2-class labeled subgraph matching (`ALG-SUBISO-001`, `fss-x4a.23.70.4`).
pub mod subiso;
/// Budgeted positive-weight coverage with exact integer ratio ranking and explicit omissions.
pub mod submodular;
pub mod temporal;
pub mod topo;
/// Complete 12-universe typed FSS graph projection atlas (`G_phys..G_world`, `GRAPH-PROJECTION-SEMANTICS-001`).
pub mod typed_universes;
pub mod weighted;
pub mod zset;

pub use bridges::{
    BridgeAnalysis, BridgeCounters, BridgeSeparation, ComplexityBound, GraphBudget,
    VertexSeparation, analyse_bridges,
};
pub use coverage::{
    CoverageObservation, CoverageSinglePoints, SensorCoverageProjection, SensorResilience,
    ZoneResilience, ZoneState,
};
pub use graph::{GraphBuilder, GraphError, UndirectedGraph};
