#![forbid(unsafe_code)]
//! `ALG-CENTRAL-001` — Centrality family (Brandes shortest-path vertex & edge betweenness and
//! Wasserman-Faust closeness centrality) over immutable directed or undirected projections.
//!
//! Computes deterministic integer fixed-point (`10^9` parts-per-billion) vertex betweenness,
//! closeness, and edge betweenness scores. Equal scores break ties by ascending stable node/arc
//! identity (`tie:betweenness-ppb-descending-then-closeness-ppb-descending-then-stable-node-identity:v1`).

use std::collections::VecDeque;

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, mul, query_digest, query_encoder,
};
use crate::graph::GraphError;
use crate::weighted::{Orientation, WeightedGraph};

/// Fixed-point score scale: `1_000_000_000` parts per billion (`1.0`).
pub const SCALE_PPB: u64 = 1_000_000_000;

/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-CENTRALITY-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.centrality_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-CENTRALITY-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.centrality_decision_path.v1";

/// Registered identity (`architecture/graph_algorithms.json`, `ALG-CENTRAL-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-CENTRAL-001",
    algorithm_name: "centrality_family",
    tie_break_rule: "score then stable node identity",
    complexity_witness: "family-specific path or matrix operations",
    output_size_witness: "<= |V| vertex and <= |E| edge centrality scores",
    exactness: "exact_or_approximate_advisory",
    implementation_id: "fss-graph-algorithms:alg-central-001:brandes-shortest-path-betweenness-and-closeness-1e9:v1",
    tie_break_policy_id: "tie:betweenness-ppb-descending-then-closeness-ppb-descending-then-stable-node-identity:v1",
    policy_id: "graph-policy:directed-or-undirected:simple-strict:unweighted-shortest-paths-fixed-point-1e9:tie:betweenness-ppb-descending-then-closeness-ppb-descending-then-stable-node-identity:v1",
    complexity_bound_id: "bound:alg-central-001:brandes-n-times-n-plus-2m:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// Registered complexity bound for `n` nodes and `m` edges/arcs.
#[must_use]
pub fn bound(n: u64, m: u64) -> Vec<BoundRow> {
    vec![
        ("bfs_visits", mul(n, n)),
        ("bfs_arc_scans", mul(n, mul(2, m))),
        ("dependency_updates", mul(n, add(n, mul(2, m)))),
        (OUTPUT_ENTRIES, add(n, m)),
    ]
}

/// Vertex centrality entry (betweenness and closeness in parts per billion).
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct VertexCentrality {
    /// Stable node identity.
    pub node_id: String,
    /// Unnormalized Brandes shortest-path betweenness in parts per billion (`10^9` per unit pair).
    pub betweenness_ppb: u64,
    /// Wasserman-Faust closeness centrality in parts per billion (`0..=1_000_000_000`).
    pub closeness_ppb: u64,
}

/// Edge/arc betweenness centrality entry.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EdgeCentrality {
    /// Canonical tail (or lower endpoint) identity.
    pub tail_id: String,
    /// Canonical head (or higher endpoint) identity.
    pub head_id: String,
    /// Unnormalized Brandes shortest-path edge betweenness in parts per billion.
    pub betweenness_ppb: u64,
}

/// Canonical answer of `ALG-CENTRAL-001`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CentralityOutput {
    /// Vertices ranked by `betweenness_ppb` descending, `closeness_ppb` descending, `node_id` ascending.
    pub vertices: Vec<VertexCentrality>,
    /// Edges/arcs ranked by `betweenness_ppb` descending, `(tail_id, head_id)` ascending.
    pub edges: Vec<EdgeCentrality>,
}

impl CertifiedOutput for CentralityOutput {
    fn entries(&self) -> u64 {
        (self.vertices.len() + self.edges.len()) as u64
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.vertices.len() as u64);
        for v in &self.vertices {
            encoder.text(&v.node_id);
            encoder.u64(v.betweenness_ppb);
            encoder.u64(v.closeness_ppb);
        }
        encoder.u64(self.edges.len() as u64);
        for e in &self.edges {
            encoder.text(&e.tail_id);
            encoder.text(&e.head_id);
            encoder.u64(e.betweenness_ppb);
        }
    }
}

fn input_digest(graph: &WeightedGraph) -> ContentDigest {
    query_digest(query_encoder(&IDENTITY, graph.digest()))
}

/// Runs `ALG-CENTRAL-001` (Brandes vertex/edge betweenness and closeness centrality).
///
/// # Errors
///
/// Fails closed when `budget` or the registered complexity bound is exceeded.
pub fn centrality_family(
    graph: &WeightedGraph,
    budget: Budget,
) -> Result<CertifiedRun<CentralityOutput>, GraphError> {
    let n = graph.node_count();
    let m = graph.arc_count();
    let digest = input_digest(graph);
    let mut meter = Meter::new(&IDENTITY, budget);
    let bound_rows = bound(n as u64, m as u64);
    if n == 0 {
        return meter.finish(
            &IDENTITY,
            InputShape {
                node_count: 0,
                edge_count: 0,
                input_digest: digest,
            },
            CentralityOutput::default(),
            &bound_rows,
            0,
        );
    }

    let mut vertex_betweenness = vec![0_u128; n];
    let mut edge_betweenness = vec![0_u128; m];
    let mut closeness_ppb = vec![0_u64; n];

    let mut queue: VecDeque<u32> = VecDeque::with_capacity(n);
    let mut stack: Vec<u32> = Vec::with_capacity(n);
    let mut dist = vec![-1_i64; n];
    let mut sigma = vec![0_u128; n];
    let mut preds: Vec<Vec<(u32, u32)>> = vec![Vec::new(); n];
    let mut delta_ppb = vec![0_u128; n];

    for s in 0..n as u32 {
        queue.clear();
        stack.clear();
        dist.fill(-1);
        sigma.fill(0);
        for p in &mut preds {
            p.clear();
        }

        meter.tick("bfs_visits")?;
        dist[s as usize] = 0;
        sigma[s as usize] = 1;
        queue.push_back(s);

        while let Some(v) = queue.pop_front() {
            stack.push(v);
            let dv = dist[v as usize];
            let sv = sigma[v as usize];
            for &arc_idx in graph.out_arcs(v) {
                meter.tick("bfs_arc_scans")?;
                let arc = graph.arc(arc_idx);
                let w = match graph.orientation() {
                    Orientation::Directed => arc.head,
                    Orientation::Undirected => arc.other(v),
                };
                if dist[w as usize] < 0 {
                    meter.tick("bfs_visits")?;
                    dist[w as usize] = dv + 1;
                    queue.push_back(w);
                }
                if dist[w as usize] == dv + 1 {
                    sigma[w as usize] = sigma[w as usize].saturating_add(sv);
                    preds[w as usize].push((v, arc_idx));
                }
            }
        }

        let mut reachable = 0_u128;
        let mut total_dist = 0_u128;
        for (t, &d) in dist.iter().enumerate() {
            if t != s as usize && d > 0 {
                reachable += 1;
                total_dist += d as u128;
            }
        }
        if reachable > 0 && n > 1 && total_dist > 0 {
            let num = reachable * reachable * u128::from(SCALE_PPB);
            let den = ((n - 1) as u128) * total_dist;
            closeness_ppb[s as usize] = (num / den) as u64;
        }

        delta_ppb.fill(0);
        while let Some(w) = stack.pop() {
            meter.tick("dependency_updates")?;
            let sw = sigma[w as usize];
            let dw = delta_ppb[w as usize];
            if sw > 0 {
                for &(v, arc_idx) in &preds[w as usize] {
                    meter.tick("dependency_updates")?;
                    let sv = sigma[v as usize];
                    let contrib = (sv * (u128::from(SCALE_PPB) + dw)) / sw;
                    delta_ppb[v as usize] = delta_ppb[v as usize].saturating_add(contrib);
                    edge_betweenness[arc_idx as usize] =
                        edge_betweenness[arc_idx as usize].saturating_add(contrib);
                }
            }
            if w != s {
                vertex_betweenness[w as usize] =
                    vertex_betweenness[w as usize].saturating_add(dw);
            }
        }
    }

    if graph.orientation() == Orientation::Undirected {
        for b in &mut vertex_betweenness {
            *b /= 2;
        }
        for eb in &mut edge_betweenness {
            *eb /= 2;
        }
    }

    let mut v_order: Vec<u32> = (0..n as u32).collect();
    v_order.sort_by(|&a, &b| {
        let ba = u64::try_from(vertex_betweenness[a as usize]).unwrap_or(u64::MAX);
        let bb = u64::try_from(vertex_betweenness[b as usize]).unwrap_or(u64::MAX);
        bb.cmp(&ba)
            .then_with(|| closeness_ppb[b as usize].cmp(&closeness_ppb[a as usize]))
            .then_with(|| a.cmp(&b))
    });
    let mut vertices = Vec::with_capacity(n);
    for idx in v_order {
        let b_ppb = u64::try_from(vertex_betweenness[idx as usize]).unwrap_or(u64::MAX);
        let c_ppb = closeness_ppb[idx as usize];
        meter.decide(1, u64::from(idx), b_ppb);
        vertices.push(VertexCentrality {
            node_id: graph.id(idx).to_owned(),
            betweenness_ppb: b_ppb,
            closeness_ppb: c_ppb,
        });
    }

    let mut e_order: Vec<u32> = (0..m as u32).collect();
    e_order.sort_by(|&a, &b| {
        let ba = u64::try_from(edge_betweenness[a as usize]).unwrap_or(u64::MAX);
        let bb = u64::try_from(edge_betweenness[b as usize]).unwrap_or(u64::MAX);
        bb.cmp(&ba).then_with(|| a.cmp(&b))
    });
    let mut edges = Vec::with_capacity(m);
    for arc_idx in e_order {
        let (tail_id, head_id) = graph.arc_ids(arc_idx);
        let b_ppb = u64::try_from(edge_betweenness[arc_idx as usize]).unwrap_or(u64::MAX);
        meter.decide(2, u64::from(arc_idx), b_ppb);
        edges.push(EdgeCentrality {
            tail_id,
            head_id,
            betweenness_ppb: b_ppb,
        });
    }

    let working_bytes = ((n * 64) + (m * 24)) as u64;
    meter.finish(
        &IDENTITY,
        InputShape {
            node_count: n as u64,
            edge_count: m as u64,
            input_digest: digest,
        },
        CentralityOutput { vertices, edges },
        &bound_rows,
        working_bytes,
    )
}
