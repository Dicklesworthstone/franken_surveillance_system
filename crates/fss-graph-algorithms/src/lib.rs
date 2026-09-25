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
//! * [`failure_domains`]: independent simultaneous-member-loss scenarios for owner-declared
//!   shared network, power, clock and host dependencies;
//! * [`registry`]: the registered identities, tie-break, policy and complexity bound.
//!
//! Nothing here reads a clock, the filesystem, or the network, and no output grants authority.

pub mod bridges;
pub mod coverage;
pub mod failure_domains;
pub mod graph;
pub mod reference;
pub mod registry;

pub use bridges::{
    BridgeAnalysis, BridgeCounters, BridgeSeparation, ComplexityBound, GraphBudget,
    VertexSeparation, analyse_bridges,
};
pub use coverage::{
    CoverageObservation, CoverageSinglePoints, SensorCoverageProjection, SensorResilience,
    ZoneResilience, ZoneState,
};
pub use graph::{GraphBuilder, GraphError, UndirectedGraph};
