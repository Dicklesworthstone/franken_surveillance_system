#![forbid(unsafe_code)]
//! `ALG-STEINER-001` — Steiner tree 2-approximation (Kou-Markowsky-Berman metric closure + leaf
//! pruning) over immutable undirected weighted projections.
//!
//! Connects all required terminals through optional Steiner intermediates with total weight at
//! most `2 * (1 - 1/|L|) * OPT`. Ties break by total weight then lexicographic edge identity
//! sequence (`tie:total-weight-then-lexicographic-edge-identity-sequence:v1`).

use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap};

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, checked_add, encode_ids, mul, query_digest, query_encoder,
};
use crate::graph::GraphError;
use crate::weighted::{Orientation, WeightedGraph};

/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-STEINER-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.steiner_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-STEINER-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.steiner_decision_path.v1";

/// Registered identity (`architecture/graph_algorithms.json`, `ALG-STEINER-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-STEINER-001",
    algorithm_name: "steiner_tree_approximation",
    tie_break_rule: "approximation score then stable node identity",
    complexity_witness: "shortest paths and reductions",
    output_size_witness: "<= 2 * |Terminals| <= |V| tree nodes and edges",
    exactness: "approximate",
    implementation_id: "fss-graph-algorithms:alg-steiner-001:kou-markowsky-berman-metric-closure-mst:v1",
    tie_break_policy_id: "tie:total-weight-then-lexicographic-edge-identity-sequence:v1",
    policy_id: "graph-policy:undirected:simple-strict:nonnegative-edge-weight:numeric:u64-exact:checked:unit-bound:v1:tie:total-weight-then-lexicographic-edge-identity-sequence:v1",
    complexity_bound_id: "bound:alg-steiner-001:terminals-dijkstra-plus-closure-mst:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// Registered complexity bound for `n` nodes, `m` edges, and `k` terminals.
#[must_use]
pub fn bound(n: u64, m: u64, k: u64) -> Vec<BoundRow> {
    let tk = k.max(1);
    vec![
        ("shortest_path_steps", mul(tk, add(mul(2, n), mul(4, m)))),
        ("reduction_steps", add(mul(tk, tk), mul(4, add(n, m)))),
        (OUTPUT_ENTRIES, mul(2, n)),
    ]
}

/// One undirected edge in the Steiner tree.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SteinerEdge {
    /// Lower canonical endpoint identity.
    pub u: String,
    /// Higher canonical endpoint identity.
    pub v: String,
    /// Edge weight in the projection's unit.
    pub weight: u64,
}

/// Canonical answer of `ALG-STEINER-001`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SteinerTreeOutput {
    /// Nodes included in the Steiner tree (terminals plus chosen Steiner intermediates), ascending.
    pub tree_nodes: Vec<String>,
    /// Edges of the Steiner tree, in ascending `(u, v)` order.
    pub tree_edges: Vec<SteinerEdge>,
    /// Total weight of `tree_edges`.
    pub total_weight: u64,
}

impl CertifiedOutput for SteinerTreeOutput {
    fn entries(&self) -> u64 {
        (self.tree_nodes.len() + self.tree_edges.len()) as u64
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.total_weight);
        encode_ids(encoder, &self.tree_nodes);
        encoder.u64(self.tree_edges.len() as u64);
        for edge in &self.tree_edges {
            encoder.text(&edge.u);
            encoder.text(&edge.v);
            encoder.u64(edge.weight);
        }
    }
}

fn input_digest(graph: &WeightedGraph, terminals: &[u32]) -> ContentDigest {
    let mut encoder = query_encoder(&IDENTITY, graph.digest());
    encoder.u64(terminals.len() as u64);
    for &t in terminals {
        encoder.text(graph.id(t));
    }
    query_digest(encoder)
}

struct DisjointSet {
    parent: Vec<usize>,
    size: Vec<usize>,
}

impl DisjointSet {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
            size: vec![1; n],
        }
    }

    fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            let p = self.parent[x];
            self.parent[x] = self.parent[p];
            x = p;
        }
        x
    }

    fn union(&mut self, a: usize, b: usize) -> bool {
        let mut ra = self.find(a);
        let mut rb = self.find(b);
        if ra == rb {
            return false;
        }
        if self.size[ra] < self.size[rb] || (self.size[ra] == self.size[rb] && ra > rb) {
            std::mem::swap(&mut ra, &mut rb);
        }
        self.parent[rb] = ra;
        self.size[ra] += self.size[rb];
        true
    }
}

/// Runs `ALG-STEINER-001` over an undirected `WeightedGraph`.
///
/// # Errors
///
/// Fails closed on directed graphs, unknown or duplicate terminals, disconnected terminals,
/// arithmetic overflow, or budget/bound exhaustion.
pub fn steiner_tree_approximation(
    graph: &WeightedGraph,
    terminals: &[&str],
    budget: Budget,
) -> Result<CertifiedRun<SteinerTreeOutput>, GraphError> {
    graph.require_orientation(Orientation::Undirected)?;
    let n = graph.node_count();
    let m = graph.arc_count();

    let mut term_indices: Vec<u32> = Vec::with_capacity(terminals.len());
    for &id in terminals {
        term_indices.push(
            graph
                .index_of(id)
                .ok_or_else(|| GraphError::UnknownNode(id.to_owned()))?,
        );
    }
    term_indices.sort_unstable();
    for pair in term_indices.windows(2) {
        if pair[0] == pair[1] {
            return Err(GraphError::DuplicateNode(graph.id(pair[0]).to_owned()));
        }
    }

    let k = term_indices.len();
    let digest = input_digest(graph, &term_indices);
    let mut meter = Meter::new(&IDENTITY, budget);
    let bound_rows = bound(n as u64, m as u64, k as u64);

    if k == 0 {
        return meter.finish(
            &IDENTITY,
            InputShape {
                node_count: n as u64,
                edge_count: m as u64,
                input_digest: digest,
            },
            SteinerTreeOutput::default(),
            &bound_rows,
            0,
        );
    }
    if k == 1 {
        let only = graph.id(term_indices[0]).to_owned();
        meter.tick("reduction_steps")?;
        return meter.finish(
            &IDENTITY,
            InputShape {
                node_count: n as u64,
                edge_count: m as u64,
                input_digest: digest,
            },
            SteinerTreeOutput {
                tree_nodes: vec![only],
                tree_edges: Vec::new(),
                total_weight: 0,
            },
            &bound_rows,
            64,
        );
    }

    let mut is_terminal = vec![false; n];
    for &t in &term_indices {
        is_terminal[t as usize] = true;
    }

    // Step 1: Single-source shortest paths from each terminal (except the last).
    // Store `(dist, hops, parent_node, parent_arc)` per terminal run.
    let mut closure_edges: Vec<(u64, u32, usize, usize, Vec<u32>)> = Vec::new();
    let mut dist = vec![u64::MAX; n];
    let mut hops = vec![u32::MAX; n];
    let mut parent: Vec<Option<(u32, u32)>> = vec![None; n];
    let mut settled = vec![false; n];

    for (ti_pos, &source) in term_indices.iter().enumerate() {
        dist.fill(u64::MAX);
        hops.fill(u32::MAX);
        parent.fill(None);
        settled.fill(false);

        let mut heap: BinaryHeap<Reverse<(u64, u32, u32, u32)>> = BinaryHeap::new();
        dist[source as usize] = 0;
        hops[source as usize] = 0;
        meter.tick("shortest_path_steps")?;
        heap.push(Reverse((0, 0, 0, source)));

        while let Some(Reverse((d, h, _, u))) = heap.pop() {
            meter.tick("shortest_path_steps")?;
            if settled[u as usize] {
                continue;
            }
            settled[u as usize] = true;
            for &arc_idx in graph.out_arcs(u) {
                meter.tick("shortest_path_steps")?;
                let arc = graph.arc(arc_idx);
                let v = arc.other(u);
                let nd = checked_add(d, arc.weight, "steiner_shortest_path")?;
                let nh = h.saturating_add(1);
                let better = (nd, nh, arc_idx)
                    < (
                        dist[v as usize],
                        hops[v as usize],
                        parent[v as usize].map_or(u32::MAX, |(_, pa)| pa),
                    );
                if better {
                    dist[v as usize] = nd;
                    hops[v as usize] = nh;
                    parent[v as usize] = Some((u, arc_idx));
                    meter.tick("shortest_path_steps")?;
                    heap.push(Reverse((nd, nh, arc_idx, v)));
                }
            }
        }

        for (tj_pos, &target) in term_indices.iter().enumerate().skip(ti_pos + 1) {
            if dist[target as usize] == u64::MAX {
                return Err(GraphError::PreconditionFailed(format!(
                    "terminals {} and {} are disconnected",
                    graph.id(source),
                    graph.id(target)
                )));
            }
            let mut path_arcs = Vec::new();
            let mut cur = target;
            while cur != source {
                let (prev, arc_idx) = parent[cur as usize].ok_or_else(|| {
                    GraphError::Inconsistent("missing shortest-path predecessor".to_owned())
                })?;
                path_arcs.push(arc_idx);
                cur = prev;
            }
            closure_edges.push((
                dist[target as usize],
                hops[target as usize],
                ti_pos,
                tj_pos,
                path_arcs,
            ));
        }
    }

    // Step 2: Kruskal MST on the metric closure of terminals.
    closure_edges.sort_by(|a, b| (a.0, a.1, a.2, a.3).cmp(&(b.0, b.1, b.2, b.3)));
    let mut dsu_t = DisjointSet::new(k);
    let mut candidate_arcs: BTreeSet<u32> = BTreeSet::new();
    for (w, _, ti, tj, arcs) in &closure_edges {
        meter.tick("reduction_steps")?;
        if dsu_t.union(*ti, *tj) {
            meter.decide(1, *ti as u64, *tj as u64);
            let _ = w;
            for &arc_idx in arcs {
                candidate_arcs.insert(arc_idx);
            }
        }
    }

    // Step 3: Spanning tree over the induced subgraph of `candidate_arcs`.
    let mut sorted_arcs: Vec<u32> = candidate_arcs.into_iter().collect();
    sorted_arcs.sort_by_key(|&arc_idx| (graph.arc(arc_idx).weight, arc_idx));
    let mut dsu_g = DisjointSet::new(n);
    let mut tree_arcs: Vec<u32> = Vec::new();
    for arc_idx in sorted_arcs {
        meter.tick("reduction_steps")?;
        let arc = graph.arc(arc_idx);
        if dsu_g.union(arc.tail as usize, arc.head as usize) {
            tree_arcs.push(arc_idx);
        }
    }

    // Step 4: Iteratively prune non-terminal degree-1 leaves.
    let mut active_arc = vec![true; tree_arcs.len()];
    let mut degree = vec![0_u32; n];
    for &arc_idx in &tree_arcs {
        let arc = graph.arc(arc_idx);
        degree[arc.tail as usize] += 1;
        degree[arc.head as usize] += 1;
    }
    loop {
        let mut pruned_any = false;
        for (pos, &arc_idx) in tree_arcs.iter().enumerate() {
            if !active_arc[pos] {
                continue;
            }
            let arc = graph.arc(arc_idx);
            let u = arc.tail as usize;
            let v = arc.head as usize;
            let prune_u = !is_terminal[u] && degree[u] == 1;
            let prune_v = !is_terminal[v] && degree[v] == 1;
            if prune_u || prune_v {
                meter.tick("reduction_steps")?;
                active_arc[pos] = false;
                degree[u] = degree[u].saturating_sub(1);
                degree[v] = degree[v].saturating_sub(1);
                pruned_any = true;
            }
        }
        if !pruned_any {
            break;
        }
    }

    let mut final_arcs: Vec<u32> = tree_arcs
        .into_iter()
        .zip(active_arc)
        .filter_map(|(arc_idx, keep)| keep.then_some(arc_idx))
        .collect();
    final_arcs.sort_unstable();

    let mut node_indices: BTreeSet<u32> = term_indices.iter().copied().collect();
    let mut tree_edges = Vec::with_capacity(final_arcs.len());
    let mut total_weight = 0_u64;
    for arc_idx in final_arcs {
        meter.tick("reduction_steps")?;
        let arc = graph.arc(arc_idx);
        node_indices.insert(arc.tail);
        node_indices.insert(arc.head);
        total_weight = checked_add(total_weight, arc.weight, "steiner_tree_total_weight")?;
        meter.decide(2, u64::from(arc_idx), arc.weight);
        tree_edges.push(SteinerEdge {
            u: graph.id(arc.tail).to_owned(),
            v: graph.id(arc.head).to_owned(),
            weight: arc.weight,
        });
    }
    let tree_nodes: Vec<String> = node_indices
        .into_iter()
        .map(|idx| graph.id(idx).to_owned())
        .collect();

    let working_bytes = ((n * 48) + (m * 16)) as u64;
    meter.finish(
        &IDENTITY,
        InputShape {
            node_count: n as u64,
            edge_count: m as u64,
            input_digest: digest,
        },
        SteinerTreeOutput {
            tree_nodes,
            tree_edges,
            total_weight,
        },
        &bound_rows,
        working_bytes,
    )
}
