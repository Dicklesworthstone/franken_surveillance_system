#![forbid(unsafe_code)]
//! `ALG-KCORE-001` — Exact k-core, k-truss, and robust-support decomposition (`fss-x4a.23.70.5`).
//!
//! Computes BOTH exact iterative peeling `k`-core numbers (`core(v)`) AND exact iterative
//! triangle-support `k`-truss numbers (`truss(e)`, where every edge in a `k`-truss participates in
//! at least `k - 2` triangles within the truss), together with per-core distinct failure-domain
//! counts. Explicitly enforces `dense_edges_certify_independent_corroboration == false`!

use std::collections::{BTreeMap, BTreeSet};

use fss_core::CanonicalEncoder;

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, mul, query_digest, query_encoder,
};
use crate::graph::{GraphError, UndirectedGraph};

/// Projection digest domain (`SCHEMA-DOMAIN-GRAPH-KCORE-PROJECTION-001`).
pub const PROJECTION_DOMAIN: &str = "fss.graph.kcore_projection.v1";
/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-KCORE-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.kcore_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-KCORE-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.kcore_decision_path.v1";

/// Registered identity (`architecture/graph_algorithms.json`, `ALG-KCORE-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-KCORE-001",
    algorithm_name: "k_core_and_k_truss_decomposition",
    tie_break_rule: "ascending core or truss peeling order then stable node and edge identity",
    complexity_witness: "core peeling steps, triangle enumerations, and truss peeling updates",
    output_size_witness: "<= |V| core numbers plus <= |E| edge truss numbers",
    exactness: "exact",
    implementation_id: "fss-graph-algorithms:alg-kcore-001:exact-peeling-core-and-truss:v1",
    tie_break_policy_id: "tie:ascending-peel-level-then-stable-node-and-edge-id:v1",
    policy_id: "graph-policy:undirected:simple-strict:exact-kcore-and-ktruss-peeling:non-corroborating:tie:ascending-peel-level-then-stable-node-and-edge-id:v1",
    complexity_bound_id: "bound:alg-kcore-001:peeling-plus-triangle-support:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// Canonical answer of `ALG-KCORE-001`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KCoreTrussResult {
    /// Exact coreness `core(v)` per canonical node ID.
    pub core_numbers: BTreeMap<String, u64>,
    /// Exact trussness `truss(e)` (`>= 2`) per canonical undirected edge `(u, v)` (`u < v`).
    pub edge_truss_numbers: BTreeMap<(String, String), u64>,
    /// Maximum core number `max_v core(v)` (`0` on empty/edgeless graph).
    pub degeneracy: u64,
    /// Maximum truss number `max_e truss(e)` (`0` on edgeless graph).
    pub max_truss: u64,
    /// Distinct failure domains present inside the maximum-core subgraph (exposes shared-domain concentration!).
    pub max_core_distinct_failure_domains: usize,
    /// Always `false`: dense correlated edges NEVER certify independent corroboration!
    pub dense_edges_certify_independent_corroboration: bool,
    /// Always `false`: derived structural decomposition NEVER grants authority.
    pub grants_effect_authority: bool,
}

impl CertifiedOutput for KCoreTrussResult {
    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.degeneracy);
        encoder.u64(self.max_truss);
        encoder.u64(self.max_core_distinct_failure_domains as u64);
        encoder.u64(self.core_numbers.len() as u64);
        for (id, k) in &self.core_numbers {
            encoder.text(id);
            encoder.u64(*k);
        }
        encoder.u64(self.edge_truss_numbers.len() as u64);
        for ((u, v), t) in &self.edge_truss_numbers {
            encoder.text(u);
            encoder.text(v);
            encoder.u64(*t);
        }
    }

    fn entries(&self) -> u64 {
        add(
            self.core_numbers.len() as u64,
            self.edge_truss_numbers.len() as u64,
        )
    }
}

/// Registered complexity bound for `n` nodes and `m` edges.
#[must_use]
pub fn bound(n: u64, m: u64) -> Vec<BoundRow> {
    let tri_work = mul(m, add(n, 1));
    vec![
        ("core_peel_steps", add(mul(2, add(n, m)), 2)),
        ("truss_peel_steps", add(mul(2, tri_work), add(m, 2))),
        (OUTPUT_ENTRIES, add(n, m)),
    ]
}

/// Runs `ALG-KCORE-001` exact k-core and k-truss peeling decomposition on an `UndirectedGraph`.
pub fn decompose_k_core_and_truss(
    graph: &UndirectedGraph,
    node_failure_domains: &BTreeMap<String, String>,
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<CertifiedRun<KCoreTrussResult>, GraphError> {
    let n = graph.node_count();
    let m = graph.edge_count();
    let bound_rows = bound(n as u64, m as u64);
    let mut meter = Meter::new_cancellable(&IDENTITY, budget, is_cancelled);

    let mut q = query_encoder(&IDENTITY, graph.digest());
    q.u64(node_failure_domains.len() as u64);
    for (nid, dom) in node_failure_domains {
        q.text(nid);
        q.text(dom);
    }
    let input_digest = query_digest(q);

    // 1. Exact iterative k-core peeling (Batagelj-Zaversnik via canonical BTreeSet priority queue).
    let mut deg: Vec<usize> = (0..n).map(|u| graph.neighbours(u as u32).len()).collect();
    let mut alive = vec![true; n];
    let mut heap: BTreeSet<(usize, usize)> = (0..n).map(|u| (deg[u], u)).collect();
    let mut core_val = vec![0_u64; n];
    let mut cur_core = 0_u64;

    while let Some((d, u)) = heap.pop_first() {
        meter.tick("core_peel_steps")?;
        if !alive[u] {
            continue;
        }
        alive[u] = false;
        cur_core = cur_core.max(d as u64);
        core_val[u] = cur_core;
        meter.path().u64(u as u64);
        meter.path().u64(cur_core);
        for &(v_u32, _) in graph.neighbours(u as u32) {
            let v = v_u32 as usize;
            if alive[v] {
                meter.tick("core_peel_steps")?;
                heap.remove(&(deg[v], v));
                deg[v] = deg[v].saturating_sub(1);
                heap.insert((deg[v], v));
            }
        }
    }

    // 2. Exact iterative k-truss peeling (triangle support of every undirected edge).
    let mut edges: Vec<(usize, usize)> = Vec::with_capacity(m);
    let mut edge_index: BTreeMap<(usize, usize), usize> = BTreeMap::new();
    let mut adj_set: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];
    for u in 0..n {
        for &(v_u32, _) in graph.neighbours(u as u32) {
            let v = v_u32 as usize;
            if u < v {
                let idx = edges.len();
                edges.push((u, v));
                edge_index.insert((u, v), idx);
                adj_set[u].insert(v);
                adj_set[v].insert(u);
            }
        }
    }

    let mut support = vec![0_usize; edges.len()];
    for (ei, &(u, v)) in edges.iter().enumerate() {
        let (small, large) = if adj_set[u].len() <= adj_set[v].len() {
            (u, v)
        } else {
            (v, u)
        };
        for &w in &adj_set[small] {
            meter.tick("truss_peel_steps")?;
            if adj_set[large].contains(&w) {
                support[ei] += 1;
            }
        }
    }

    let mut edge_alive = vec![true; edges.len()];
    let mut e_heap: BTreeSet<(usize, usize)> =
        (0..edges.len()).map(|ei| (support[ei], ei)).collect();
    let mut truss_val = vec![2_u64; edges.len()];
    let mut cur_truss = 2_u64;

    while let Some((sup, ei)) = e_heap.pop_first() {
        meter.tick("truss_peel_steps")?;
        if !edge_alive[ei] {
            continue;
        }
        edge_alive[ei] = false;
        let (u, v) = edges[ei];
        cur_truss = cur_truss.max((sup as u64) + 2);
        truss_val[ei] = cur_truss;
        adj_set[u].remove(&v);
        adj_set[v].remove(&u);

        let (small, large) = if adj_set[u].len() <= adj_set[v].len() {
            (u, v)
        } else {
            (v, u)
        };
        let common: Vec<usize> = adj_set[small]
            .iter()
            .copied()
            .filter(|w| adj_set[large].contains(w))
            .collect();
        for w in common {
            for (a, b) in [(u.min(w), u.max(w)), (v.min(w), v.max(w))] {
                if let Some(&other_ei) = edge_index.get(&(a, b))
                    && edge_alive[other_ei]
                {
                    meter.tick("truss_peel_steps")?;
                    e_heap.remove(&(support[other_ei], other_ei));
                    support[other_ei] = support[other_ei].saturating_sub(1);
                    e_heap.insert((support[other_ei], other_ei));
                }
            }
        }
    }

    let degeneracy = core_val.iter().copied().max().unwrap_or(0);
    let max_truss = if edges.is_empty() {
        0
    } else {
        truss_val.iter().copied().max().unwrap_or(2)
    };

    let mut core_numbers = BTreeMap::new();
    let mut max_core_domains = BTreeSet::new();
    for (u, &k) in core_val.iter().enumerate() {
        let id = graph.id(u as u32).to_owned();
        if k == degeneracy
            && degeneracy > 0
            && let Some(dom) = node_failure_domains.get(&id)
        {
            max_core_domains.insert(dom.as_str());
        }
        core_numbers.insert(id, k);
    }
    let mut edge_truss_numbers = BTreeMap::new();
    for (ei, &(u, v)) in edges.iter().enumerate() {
        let mut a = graph.id(u as u32).to_owned();
        let mut b = graph.id(v as u32).to_owned();
        if a > b {
            std::mem::swap(&mut a, &mut b);
        }
        edge_truss_numbers.insert((a, b), truss_val[ei]);
    }

    let output = KCoreTrussResult {
        core_numbers,
        edge_truss_numbers,
        degeneracy,
        max_truss,
        max_core_distinct_failure_domains: max_core_domains.len(),
        dense_edges_certify_independent_corroboration: false,
        grants_effect_authority: false,
    };
    let shape = InputShape {
        node_count: n as u64,
        edge_count: m as u64,
        input_digest,
    };
    let peak_bytes = ((n + m + 1) * 128) as u64;
    meter.finish(&IDENTITY, shape, output, &bound_rows, peak_bytes)
}
