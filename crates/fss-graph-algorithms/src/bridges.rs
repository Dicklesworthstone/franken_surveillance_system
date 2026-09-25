//! `ALG-BRIDGE-001` — articulation points and bridges, with root separations.
//!
//! One iterative Tarjan depth-first search with low links over the canonical
//! [`UndirectedGraph`]. The search starts at the declared root (if any) and then at every
//! unvisited node in canonical index order, scanning adjacency in ascending neighbour order, so
//! every choice follows the registered tie-break ([`TIE_BREAK_POLICY_ID`]). It reports:
//!
//! * every cut vertex (a node whose removal increases the number of connected components) and
//!   every bridge (an edge whose removal does);
//! * with a root: the nodes not connected to the root at all, and for every cut vertex other than
//!   the root and every bridge in the root's component, exactly the nodes that its failure
//!   separates from the root (the DFS subtrees of the children whose low link does not reach
//!   above it).
//!
//! The run is exact or fails closed: a declared budget that runs out is
//! [`GraphError::BudgetExhausted`] with no partial answer, and after every run the observed
//! counters are checked against the registered [`ComplexityBound`]; a violation is
//! [`GraphError::ComplexityBoundViolated`] and no output or witness is produced.

use std::collections::BTreeMap;

use fss_core::{
    CanonicalEncoder, ContentDigest, ContractError, GraphAlgorithmWitness,
    GraphAlgorithmWitnessParams, LedgerAnchor,
};

use crate::graph::{GraphError, UndirectedGraph};
use crate::registry::{
    ALGORITHM_ID, DECISION_PATH_DIGEST_DOMAIN, EXACTNESS, IMPLEMENTATION_ID, OUTPUT_DIGEST_DOMAIN,
    POLICY_ID, TIE_BREAK_POLICY_ID,
};

const UNSET: u32 = u32::MAX;

/// Observed dominant operation counts of one run.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BridgeCounters {
    /// Nodes discovered by the search.
    pub dfs_node_visits: u64,
    /// Adjacency entries scanned (each undirected edge is scanned from both ends).
    pub adjacency_scans: u64,
    /// Low-link decreases (back edges and child propagation).
    pub low_link_updates: u64,
    /// Tree edges of the search forest.
    pub tree_edges: u64,
    /// Node identities emitted across every root separation.
    pub separation_entries: u64,
}

impl BridgeCounters {
    /// The counters as the witness's `dominantOperationCounts`.
    #[must_use]
    pub fn to_map(&self) -> BTreeMap<String, u64> {
        BTreeMap::from([
            ("adjacency_scans".to_owned(), self.adjacency_scans),
            ("dfs_node_visits".to_owned(), self.dfs_node_visits),
            ("low_link_updates".to_owned(), self.low_link_updates),
            ("separation_entries".to_owned(), self.separation_entries),
            ("tree_edges".to_owned(), self.tree_edges),
        ])
    }
}

/// The registered complexity and output bound for one input size
/// ([`crate::registry::COMPLEXITY_BOUND_ID`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComplexityBound {
    /// `n`.
    pub dfs_node_visits: u64,
    /// `2m`.
    pub adjacency_scans: u64,
    /// `2m + n`.
    pub low_link_updates: u64,
    /// `n - 1` (0 for an empty graph).
    pub tree_edges: u64,
    /// `n` cut vertices.
    pub cut_vertices: u64,
    /// `m` bridges.
    pub bridges: u64,
}

impl ComplexityBound {
    /// The bound for `n` nodes and `m` edges.
    #[must_use]
    pub const fn for_size(n: u64, m: u64) -> Self {
        Self {
            dfs_node_visits: n,
            adjacency_scans: m.saturating_mul(2),
            low_link_updates: m.saturating_mul(2).saturating_add(n),
            tree_edges: n.saturating_sub(1),
            cut_vertices: n,
            bridges: m,
        }
    }

    /// Operations the registered budget measures: node visits plus adjacency scans.
    #[must_use]
    pub const fn operations(&self) -> u64 {
        self.dfs_node_visits.saturating_add(self.adjacency_scans)
    }

    /// `n * (cut vertices + bridges)`: each separation lists at most every node once.
    #[must_use]
    pub const fn separation_entries(&self, cut_vertices: u64, bridges: u64) -> u64 {
        self.dfs_node_visits
            .saturating_mul(cut_vertices.saturating_add(bridges))
    }

    /// Checks observed counters and output sizes against this bound.
    ///
    /// # Errors
    ///
    /// [`GraphError::ComplexityBoundViolated`] naming the first counter above its bound.
    pub fn check(
        &self,
        counters: &BridgeCounters,
        cut_vertices: u64,
        bridges: u64,
    ) -> Result<(), GraphError> {
        let rows = [
            (
                "dfs_node_visits",
                counters.dfs_node_visits,
                self.dfs_node_visits,
            ),
            (
                "adjacency_scans",
                counters.adjacency_scans,
                self.adjacency_scans,
            ),
            (
                "low_link_updates",
                counters.low_link_updates,
                self.low_link_updates,
            ),
            ("tree_edges", counters.tree_edges, self.tree_edges),
            ("cut_vertices", cut_vertices, self.cut_vertices),
            ("bridges", bridges, self.bridges),
            (
                "separation_entries",
                counters.separation_entries,
                self.separation_entries(cut_vertices, bridges),
            ),
        ];
        for (counter, observed, bound) in rows {
            if observed > bound {
                return Err(GraphError::ComplexityBoundViolated {
                    counter,
                    observed,
                    bound,
                });
            }
        }
        Ok(())
    }
}

/// Checks a witness's counters against the registered bound recomputed from its `n` and `m`
/// (separation entries against the loosest admissible `n * (n + m)`).
///
/// # Errors
///
/// [`GraphError::ComplexityBoundViolated`] for a counter above its bound or a missing counter;
/// [`GraphError::Inconsistent`] for a witness of another algorithm.
pub fn check_witness_bound(witness: &GraphAlgorithmWitness) -> Result<(), GraphError> {
    if witness.algorithm_id() != ALGORITHM_ID {
        return Err(GraphError::Inconsistent(format!(
            "witness of {} is not {ALGORITHM_ID}",
            witness.algorithm_id()
        )));
    }
    let (n, m) = (witness.node_count(), witness.edge_count());
    let bound = ComplexityBound::for_size(n, m);
    let counts = witness.dominant_operation_counts();
    let rows = [
        ("dfs_node_visits", bound.dfs_node_visits),
        ("adjacency_scans", bound.adjacency_scans),
        ("low_link_updates", bound.low_link_updates),
        ("tree_edges", bound.tree_edges),
        ("separation_entries", n.saturating_mul(n.saturating_add(m))),
    ];
    for (counter, limit) in rows {
        let observed = counts
            .get(counter)
            .copied()
            .ok_or_else(|| GraphError::Inconsistent(format!("witness lacks counter {counter}")))?;
        if observed > limit {
            return Err(GraphError::ComplexityBoundViolated {
                counter,
                observed,
                bound: limit,
            });
        }
    }
    Ok(())
}

/// Declared resource budget of one run; exhaustion fails closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GraphBudget {
    /// Maximum node visits plus adjacency scans.
    pub max_operations: u64,
    /// Maximum emitted identities (cut vertices, bridges, unreachable nodes, separation entries).
    pub max_output_entries: u64,
}

impl GraphBudget {
    /// The registered bound for `graph`: an exact run never exceeds it.
    #[must_use]
    pub fn registered(graph: &UndirectedGraph) -> Self {
        let (n, m) = (graph.node_count() as u64, graph.edge_count() as u64);
        let bound = ComplexityBound::for_size(n, m);
        Self {
            max_operations: bound.operations(),
            max_output_entries: n
                .saturating_add(m)
                .saturating_add(n)
                .saturating_add(bound.separation_entries(n, m)),
        }
    }
}

/// Nodes that one cut vertex's failure separates from the root.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct VertexSeparation {
    /// The cut vertex.
    pub node: String,
    /// Every node that loses its connection to the root, in ascending identity order.
    pub separated: Vec<String>,
}

/// Nodes that one bridge's failure separates from the root.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BridgeSeparation {
    /// The bridge as `(lower identity, higher identity)`.
    pub edge: (String, String),
    /// Every node that loses its connection to the root, in ascending identity order.
    pub separated: Vec<String>,
}

/// The canonical answer of `ALG-BRIDGE-001`, shared by the optimized run and the oracle.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BridgeOutput {
    /// Declared root, if any.
    pub root: Option<String>,
    /// Every cut vertex, in ascending identity order.
    pub articulation_points: Vec<String>,
    /// Every bridge as `(lower, higher)` identity, in ascending order.
    pub bridges: Vec<(String, String)>,
    /// With a root: nodes not connected to it, in ascending identity order.
    pub unreachable_from_root: Vec<String>,
    /// With a root: every cut vertex other than the root in its component, with the nodes its
    /// failure separates from the root, in ascending cut-vertex order.
    pub vertex_separations: Vec<VertexSeparation>,
    /// With a root: every bridge in its component, with the nodes its failure separates from the
    /// root, in ascending edge order.
    pub bridge_separations: Vec<BridgeSeparation>,
}

impl BridgeOutput {
    /// Identities emitted.
    #[must_use]
    pub fn entries(&self) -> u64 {
        let separated: usize = self
            .vertex_separations
            .iter()
            .map(|entry| entry.separated.len())
            .chain(
                self.bridge_separations
                    .iter()
                    .map(|entry| entry.separated.len()),
            )
            .sum();
        (self.articulation_points.len()
            + self.bridges.len()
            + self.unreachable_from_root.len()
            + separated) as u64
    }

    /// Domain-separated canonical digest of the whole answer.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        fn list(encoder: &mut CanonicalEncoder, values: &[String]) {
            encoder.u64(values.len() as u64);
            for value in values {
                encoder.text(value);
            }
        }
        let mut encoder = CanonicalEncoder::new();
        encoder.text(OUTPUT_DIGEST_DOMAIN);
        match &self.root {
            None => encoder.tag(0),
            Some(root) => {
                encoder.tag(1);
                encoder.text(root);
            }
        }
        list(&mut encoder, &self.articulation_points);
        encoder.u64(self.bridges.len() as u64);
        for (a, b) in &self.bridges {
            encoder.text(a);
            encoder.text(b);
        }
        list(&mut encoder, &self.unreachable_from_root);
        encoder.u64(self.vertex_separations.len() as u64);
        for entry in &self.vertex_separations {
            encoder.text(&entry.node);
            list(&mut encoder, &entry.separated);
        }
        encoder.u64(self.bridge_separations.len() as u64);
        for entry in &self.bridge_separations {
            encoder.text(&entry.edge.0);
            encoder.text(&entry.edge.1);
            list(&mut encoder, &entry.separated);
        }
        ContentDigest::sha256(&encoder.finish())
    }
}

/// One complete, bound-checked `ALG-BRIDGE-001` run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeAnalysis {
    /// Nodes of the input.
    pub node_count: u64,
    /// Edges of the input.
    pub edge_count: u64,
    /// Canonical input projection digest.
    pub input_digest: ContentDigest,
    /// The answer.
    pub output: BridgeOutput,
    /// Observed counters.
    pub counters: BridgeCounters,
    /// The registered bound they were checked against.
    pub bound: ComplexityBound,
    /// Operations charged against the budget (node visits plus adjacency scans).
    pub operations: u64,
    /// Identities emitted.
    pub output_entries: u64,
    /// Deterministically accounted peak working bytes (index arrays, search stack, and the
    /// largest separation under construction; the input graph is not counted).
    pub peak_working_bytes: u64,
    /// Digest of the search's decisions (start nodes and tree edges in discovery order).
    pub decision_path_digest: ContentDigest,
    /// Digest of [`Self::output`].
    pub output_digest: ContentDigest,
}

impl BridgeAnalysis {
    /// The registered witness of this run over `projection_id` pinned at `anchor`.
    ///
    /// # Errors
    ///
    /// [`ContractError::InvalidIdentifier`] when `projection_id` is empty, longer than 256
    /// bytes, or holds a control character.
    pub fn witness(
        &self,
        projection_id: &str,
        anchor: LedgerAnchor,
    ) -> Result<GraphAlgorithmWitness, ContractError> {
        GraphAlgorithmWitness::new(GraphAlgorithmWitnessParams {
            algorithm_id: ALGORITHM_ID.to_owned(),
            implementation_id: IMPLEMENTATION_ID.to_owned(),
            projection_id: projection_id.to_owned(),
            anchor,
            node_count: self.node_count,
            edge_count: self.edge_count,
            input_digest: self.input_digest,
            policy_id: POLICY_ID.to_owned(),
            dominant_operation_counts: self.counters.to_map(),
            peak_working_bytes: self.peak_working_bytes,
            budget_consumed: BTreeMap::from([
                ("operations".to_owned(), self.operations),
                ("output_entries".to_owned(), self.output_entries),
            ]),
            exactness: EXACTNESS.to_owned(),
            error_bound: None,
            stop_reason: GraphAlgorithmWitness::STOP_COMPLETED.to_owned(),
            decision_path_digest: self.decision_path_digest,
            output_digest: self.output_digest,
        })
    }
}

fn charge(operations: &mut u64, budget: &GraphBudget) -> Result<(), GraphError> {
    *operations += 1;
    if *operations > budget.max_operations {
        return Err(GraphError::BudgetExhausted {
            dimension: "operations",
            limit: budget.max_operations,
        });
    }
    Ok(())
}

/// Runs `ALG-BRIDGE-001` over `graph`, optionally rooted at node identity `root`.
///
/// # Errors
///
/// [`GraphError::UnknownNode`] for a root that is not a node; [`GraphError::BudgetExhausted`]
/// when `budget` runs out; [`GraphError::ComplexityBoundViolated`] when an observed counter
/// exceeds the registered bound. No partial answer is ever returned.
pub fn analyse_bridges(
    graph: &UndirectedGraph,
    root: Option<&str>,
    budget: GraphBudget,
) -> Result<BridgeAnalysis, GraphError> {
    let n = graph.node_count();
    let node_total = u32::try_from(n).map_err(|_| GraphError::TooLarge)?;
    let root_index = match root {
        None => None,
        Some(id) => Some(
            graph
                .index_of(id)
                .ok_or_else(|| GraphError::UnknownNode(id.to_owned()))?,
        ),
    };
    let mut disc = vec![UNSET; n];
    let mut low = vec![UNSET; n];
    let mut end = vec![0_u32; n];
    let mut parent_edge = vec![UNSET; n];
    let mut cursor = vec![0_u32; n];
    let mut is_cut = vec![false; n];
    let mut order: Vec<u32> = Vec::with_capacity(n);
    let mut bridge_edges: Vec<u32> = Vec::new();
    let mut stack: Vec<u32> = Vec::new();
    let mut max_stack = 0_usize;
    let mut counters = BridgeCounters::default();
    let mut operations = 0_u64;
    let mut time = 0_u32;
    let mut path = CanonicalEncoder::new();
    path.text(DECISION_PATH_DIGEST_DOMAIN);
    path.text(TIE_BREAK_POLICY_ID);

    for start in root_index.into_iter().chain(0..node_total) {
        if disc[start as usize] != UNSET {
            continue;
        }
        charge(&mut operations, &budget)?;
        counters.dfs_node_visits += 1;
        disc[start as usize] = time;
        low[start as usize] = time;
        time += 1;
        order.push(start);
        path.tag(0);
        path.u64(u64::from(start));
        let mut root_children = 0_u32;
        stack.push(start);
        max_stack = max_stack.max(stack.len());
        while let Some(&u) = stack.last() {
            let position = cursor[u as usize] as usize;
            if let Some(&(v, edge)) = graph.neighbours(u).get(position) {
                cursor[u as usize] += 1;
                charge(&mut operations, &budget)?;
                counters.adjacency_scans += 1;
                if edge == parent_edge[u as usize] {
                    continue;
                }
                if disc[v as usize] == UNSET {
                    charge(&mut operations, &budget)?;
                    counters.dfs_node_visits += 1;
                    counters.tree_edges += 1;
                    parent_edge[v as usize] = edge;
                    disc[v as usize] = time;
                    low[v as usize] = time;
                    time += 1;
                    order.push(v);
                    path.tag(1);
                    path.u64(u64::from(v));
                    path.u64(u64::from(edge));
                    if u == start {
                        root_children += 1;
                    }
                    stack.push(v);
                    max_stack = max_stack.max(stack.len());
                } else if disc[v as usize] < low[u as usize] {
                    low[u as usize] = disc[v as usize];
                    counters.low_link_updates += 1;
                }
            } else {
                stack.pop();
                end[u as usize] = time - 1;
                if let Some(&p) = stack.last() {
                    if low[u as usize] < low[p as usize] {
                        low[p as usize] = low[u as usize];
                        counters.low_link_updates += 1;
                    }
                    if p != start && low[u as usize] >= disc[p as usize] {
                        is_cut[p as usize] = true;
                    }
                    if low[u as usize] > disc[p as usize] {
                        bridge_edges.push(parent_edge[u as usize]);
                    }
                }
            }
        }
        if root_children >= 2 {
            is_cut[start as usize] = true;
        }
    }

    let edges = graph.edges();
    let id = |node: u32| graph.id(node).to_owned();
    let articulation_points: Vec<String> = (0..node_total)
        .filter(|&node| is_cut[node as usize])
        .map(id)
        .collect();
    bridge_edges.sort_unstable();
    let bridges: Vec<(String, String)> = bridge_edges
        .iter()
        .map(|&edge| {
            let (lo, hi) = edges[edge as usize];
            (id(lo), id(hi))
        })
        .collect();

    let mut unreachable_from_root = Vec::new();
    let mut vertex_separations = Vec::new();
    let mut bridge_separations = Vec::new();
    let mut max_separation = 0_usize;
    if let Some(root) = root_index {
        let reach_end = end[root as usize];
        let reachable = |node: u32| disc[node as usize] <= reach_end;
        unreachable_from_root = (0..node_total)
            .filter(|&node| !reachable(node))
            .map(id)
            .collect();
        // Tree children in canonical index order, from each child's parent edge.
        let mut children: Vec<Vec<u32>> = vec![Vec::new(); n];
        for child in 0..node_total {
            let edge = parent_edge[child as usize];
            if edge != UNSET {
                let (lo, hi) = edges[edge as usize];
                let parent = if lo == child { hi } else { lo };
                children[parent as usize].push(child);
            }
        }
        let subtree = |node: u32| -> &[u32] {
            &order[disc[node as usize] as usize..=end[node as usize] as usize]
        };
        for node in 0..node_total {
            if node == root || !is_cut[node as usize] || !reachable(node) {
                continue;
            }
            let mut separated: Vec<String> = Vec::new();
            for &child in &children[node as usize] {
                if low[child as usize] >= disc[node as usize] {
                    separated.extend(subtree(child).iter().map(|&member| id(member)));
                }
            }
            separated.sort_unstable();
            max_separation = max_separation.max(separated.len());
            counters.separation_entries += separated.len() as u64;
            vertex_separations.push(VertexSeparation {
                node: id(node),
                separated,
            });
        }
        for &edge in &bridge_edges {
            let (lo, hi) = edges[edge as usize];
            let child = if parent_edge[hi as usize] == edge {
                hi
            } else {
                lo
            };
            if !reachable(child) {
                continue;
            }
            let mut separated: Vec<String> =
                subtree(child).iter().map(|&member| id(member)).collect();
            separated.sort_unstable();
            max_separation = max_separation.max(separated.len());
            counters.separation_entries += separated.len() as u64;
            bridge_separations.push(BridgeSeparation {
                edge: (id(lo), id(hi)),
                separated,
            });
        }
    }

    let output = BridgeOutput {
        root: root.map(str::to_owned),
        articulation_points,
        bridges,
        unreachable_from_root,
        vertex_separations,
        bridge_separations,
    };
    let output_entries = output.entries();
    if output_entries > budget.max_output_entries {
        return Err(GraphError::BudgetExhausted {
            dimension: "output_entries",
            limit: budget.max_output_entries,
        });
    }
    let (n64, m64) = (n as u64, graph.edge_count() as u64);
    let bound = ComplexityBound::for_size(n64, m64);
    bound.check(
        &counters,
        output.articulation_points.len() as u64,
        output.bridges.len() as u64,
    )?;
    // disc, low, end, parent_edge, cursor, order (4 bytes each), is_cut (1 byte), children and
    // bridge indices (4 bytes each), the search stack, and the largest separation index list.
    let peak_working_bytes = n64 * (4 * 7 + 1)
        + 4 * bridge_edges.len() as u64
        + 4 * max_stack as u64
        + 4 * max_separation as u64;
    let output_digest = output.digest();
    Ok(BridgeAnalysis {
        node_count: n64,
        edge_count: m64,
        input_digest: graph.digest(),
        output,
        counters,
        bound,
        operations,
        output_entries,
        peak_working_bytes,
        decision_path_digest: ContentDigest::sha256(&path.finish()),
        output_digest,
    })
}
