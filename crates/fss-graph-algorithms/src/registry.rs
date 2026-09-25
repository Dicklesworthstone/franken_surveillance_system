//! Registered identities of the implemented algorithm family (`architecture/graph_algorithms.json`).
//!
//! The registry row is the contract; these constants must equal it (a test reads the machine
//! registry and compares every field that has a code counterpart).

/// Registered algorithm identity.
pub const ALGORITHM_ID: &str = "ALG-BRIDGE-001";
/// Registered algorithm name.
pub const ALGORITHM_NAME: &str = "articulation_points_and_bridges";
/// Registered tie-break rule text.
pub const TIE_BREAK_RULE: &str = "stable node and edge identity";
/// Registered complexity-witness text.
pub const COMPLEXITY_WITNESS: &str = "DFS visits and low-link updates";
/// Registered output-size witness text.
pub const OUTPUT_SIZE_WITNESS: &str = "<= |V| cut vertices and <= |E| bridge edges";
/// Registered exactness class.
pub const EXACTNESS: &str = "exact";
/// Implementation generation carried by every witness.
pub const IMPLEMENTATION_ID: &str = "fss-graph-algorithms:alg-bridge-001:iterative-tarjan:v1";
/// Canonical tie-break policy identity: nodes are indexed in ascending byte order of their stable
/// identity, edges in ascending (lower, higher) endpoint index order, DFS starts at the declared
/// root and then at every unvisited node in index order, and adjacency is scanned in ascending
/// neighbour index order. Hash iteration never decides anything.
pub const TIE_BREAK_POLICY_ID: &str = "tie:stable-node-identity-then-stable-edge-identity:v1";
/// Graph policy identity: undirected, simple (self-loops and parallel edges are refused, never
/// merged), unweighted, no numeric domain, strict input mode, with the tie-break policy above.
pub const POLICY_ID: &str = "graph-policy:undirected:simple-strict:unweighted:tie:stable-node-identity-then-stable-edge-identity:v1";
/// Complexity bound identity: `dfs_node_visits <= n`, `adjacency_scans <= 2m`,
/// `low_link_updates <= 2m + n`, `tree_edges <= n - 1`, and
/// `separation_entries <= n * (cut vertices + bridges)`.
pub const COMPLEXITY_BOUND_ID: &str = "bound:alg-bridge-001:dfs-linear:v1";

/// Projection digest domain (`SCHEMA-DOMAIN-GRAPH-PROJECTION-001`).
pub const PROJECTION_DIGEST_DOMAIN: &str = "fss.graph.projection.v1";
/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-BRIDGE-OUTPUT-001`).
pub const OUTPUT_DIGEST_DOMAIN: &str = "fss.graph.bridge_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-BRIDGE-DECISION-PATH-001`).
pub const DECISION_PATH_DIGEST_DOMAIN: &str = "fss.graph.bridge_decision_path.v1";
