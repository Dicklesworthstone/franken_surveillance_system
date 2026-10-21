#![forbid(unsafe_code)]
//! `ALG-HITS-001` — Kleinberg HITS (Hyperlink-Induced Topic Search) hub and authority scores over
//! immutable directed weighted projections.
//!
//! Computes deterministic integer fixed-point (`10^9` parts-per-billion) L1-normalized hub and
//! authority scores. Equal scores break ties by ascending stable node identity
//! (`tie:score-ppb-descending-then-stable-node-identity-ascending:v1`).

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, mul, query_digest, query_encoder,
};
use crate::graph::GraphError;
use crate::weighted::{Orientation, WeightedGraph};

/// Fixed-point score scale: `1_000_000_000` parts per billion (`1.0`).
pub const SCALE_PPB: u64 = 1_000_000_000;
/// Maximum allowed HITS iterations.
pub const MAX_HITS_ITERATIONS: u32 = 256;

/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-HITS-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.hits_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-HITS-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.hits_decision_path.v1";

/// Registered identity (`architecture/graph_algorithms.json`, `ALG-HITS-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-HITS-001",
    algorithm_name: "hits",
    tie_break_rule: "score then stable node identity",
    complexity_witness: "sparse multiply/add operations",
    output_size_witness: "<= 2 * |V| hub and authority score entries",
    exactness: "approximate_advisory",
    implementation_id: "fss-graph-algorithms:alg-hits-001:fixed-point-hub-authority-iteration-1e9:v1",
    tie_break_policy_id: "tie:score-ppb-descending-then-stable-node-identity-ascending:v1",
    policy_id: "graph-policy:directed:simple-strict:fixed-point-1e9-hub-authority-l1:tie:score-ppb-descending-then-stable-node-identity-ascending:v1",
    complexity_bound_id: "bound:alg-hits-001:iterations-times-2m-plus-2n:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// Registered complexity bound for `n` nodes, `m` arcs, and `max_iterations` steps.
#[must_use]
pub fn bound(n: u64, m: u64, max_iterations: u32) -> Vec<BoundRow> {
    let iters = u64::from(max_iterations);
    vec![
        ("sparse_multiply_adds", mul(iters, mul(2, add(m, n)))),
        ("norm_evaluations", mul(iters, mul(2, n))),
        (OUTPUT_ENTRIES, mul(2, n)),
    ]
}

/// Parameters for one `ALG-HITS-001` invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HitsConfig {
    /// Maximum iterations (`1..=256`).
    pub max_iterations: u32,
    /// Combined L1 convergence tolerance in parts per billion.
    pub tolerance_ppb: u64,
}

impl Default for HitsConfig {
    fn default() -> Self {
        Self {
            max_iterations: 32,
            tolerance_ppb: 1_000,
        }
    }
}

/// Hub or authority score of one node.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HitsScoreEntry {
    /// Stable node identity.
    pub node_id: String,
    /// Score in parts per billion (`0..=1_000_000_000`).
    pub score_ppb: u64,
}

/// Canonical answer of `ALG-HITS-001`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HitsOutput {
    /// Hub scores ranked by `score_ppb` descending, then `node_id` ascending.
    pub hubs: Vec<HitsScoreEntry>,
    /// Authority scores ranked by `score_ppb` descending, then `node_id` ascending.
    pub authorities: Vec<HitsScoreEntry>,
    /// Number of iterations executed.
    pub iterations: u32,
    /// Final combined L1 residual in parts per billion.
    pub residual_ppb: u64,
    /// Whether `residual_ppb <= tolerance_ppb` was reached within `max_iterations`.
    pub converged: bool,
}

impl CertifiedOutput for HitsOutput {
    fn entries(&self) -> u64 {
        (self.hubs.len() + self.authorities.len()) as u64
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.iterations);
        encoder.u64(self.residual_ppb);
        encoder.bool(self.converged);
        encoder.u64(self.hubs.len() as u64);
        for entry in &self.hubs {
            encoder.text(&entry.node_id);
            encoder.u64(entry.score_ppb);
        }
        encoder.u64(self.authorities.len() as u64);
        for entry in &self.authorities {
            encoder.text(&entry.node_id);
            encoder.u64(entry.score_ppb);
        }
    }
}

fn normalize_l1(raw: &[u128], out: &mut [u64]) {
    let n = raw.len();
    if n == 0 {
        return;
    }
    let total: u128 = raw.iter().copied().sum();
    if total == 0 {
        let base = SCALE_PPB / (n as u64);
        let rem = (SCALE_PPB % (n as u64)) as usize;
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = base + u64::from(i < rem);
        }
        return;
    }
    let mut assigned = 0_u64;
    for (i, &val) in raw.iter().enumerate() {
        let share = ((val * u128::from(SCALE_PPB)) / total) as u64;
        out[i] = share;
        assigned = assigned.saturating_add(share);
    }
    let mut deficit = SCALE_PPB.saturating_sub(assigned);
    for (i, &val) in raw.iter().enumerate() {
        if deficit == 0 {
            break;
        }
        if val > 0 {
            out[i] += 1;
            deficit -= 1;
        }
    }
    for slot in out.iter_mut() {
        if deficit == 0 {
            break;
        }
        *slot += 1;
        deficit -= 1;
    }
}

fn input_digest(graph: &WeightedGraph, config: &HitsConfig) -> ContentDigest {
    let mut encoder = query_encoder(&IDENTITY, graph.digest());
    encoder.u32(config.max_iterations);
    encoder.u64(config.tolerance_ppb);
    query_digest(encoder)
}

/// Runs `ALG-HITS-001` over a directed `WeightedGraph`.
///
/// # Errors
///
/// Fails closed on undirected graphs, invalid `config`, or budget/bound exhaustion.
pub fn hits(
    graph: &WeightedGraph,
    config: &HitsConfig,
    budget: Budget,
) -> Result<CertifiedRun<HitsOutput>, GraphError> {
    graph.require_orientation(Orientation::Directed)?;
    if config.max_iterations == 0 || config.max_iterations > MAX_HITS_ITERATIONS {
        return Err(GraphError::PreconditionFailed(
            "max_iterations must be in 1..=256".to_owned(),
        ));
    }
    let n = graph.node_count();
    let m = graph.arc_count();
    let digest = input_digest(graph, config);
    let mut meter = Meter::new(&IDENTITY, budget);
    let bound_rows = bound(n as u64, m as u64, config.max_iterations);
    if n == 0 {
        return meter.finish(
            &IDENTITY,
            InputShape {
                node_count: 0,
                edge_count: 0,
                input_digest: digest,
            },
            HitsOutput::default(),
            &bound_rows,
            0,
        );
    }

    let mut hub = vec![0_u64; n];
    normalize_l1(&vec![1_u128; n], &mut hub);
    let mut auth = hub.clone();
    let mut raw_auth = vec![0_u128; n];
    let mut raw_hub = vec![0_u128; n];
    let mut next_auth = vec![0_u64; n];
    let mut next_hub = vec![0_u64; n];

    let mut iterations = 0_u32;
    let mut residual_ppb = 0_u64;
    let mut converged = false;

    for iter in 1..=config.max_iterations {
        iterations = iter;
        raw_auth.fill(0);
        raw_hub.fill(0);

        for u in 0..n as u32 {
            meter.tick("sparse_multiply_adds")?;
            let hu = u128::from(hub[u as usize]);
            for &arc_idx in graph.out_arcs(u) {
                meter.tick("sparse_multiply_adds")?;
                let arc = graph.arc(arc_idx);
                let w = u128::from(arc.weight.max(1));
                raw_auth[arc.head as usize] = raw_auth[arc.head as usize]
                    .checked_add(hu * w)
                    .ok_or(GraphError::ArithmeticOverflow("hits_raw_auth"))?;
            }
        }
        normalize_l1(&raw_auth, &mut next_auth);

        for u in 0..n as u32 {
            meter.tick("sparse_multiply_adds")?;
            for &arc_idx in graph.out_arcs(u) {
                meter.tick("sparse_multiply_adds")?;
                let arc = graph.arc(arc_idx);
                let w = u128::from(arc.weight.max(1));
                let av = u128::from(next_auth[arc.head as usize]);
                raw_hub[u as usize] = raw_hub[u as usize]
                    .checked_add(av * w)
                    .ok_or(GraphError::ArithmeticOverflow("hits_raw_hub"))?;
            }
        }
        normalize_l1(&raw_hub, &mut next_hub);

        let mut l1 = 0_u64;
        for v in 0..n {
            meter.tick_n("norm_evaluations", 2)?;
            l1 = l1
                .saturating_add(next_hub[v].abs_diff(hub[v]))
                .saturating_add(next_auth[v].abs_diff(auth[v]));
        }
        residual_ppb = l1;
        meter.decide(1, u64::from(iter), residual_ppb);
        hub.copy_from_slice(&next_hub);
        auth.copy_from_slice(&next_auth);
        if residual_ppb <= config.tolerance_ppb {
            converged = true;
            break;
        }
    }

    let mut hub_order: Vec<u32> = (0..n as u32).collect();
    hub_order.sort_by(|&a, &b| {
        hub[b as usize]
            .cmp(&hub[a as usize])
            .then_with(|| a.cmp(&b))
    });
    let mut hubs = Vec::with_capacity(n);
    for idx in hub_order {
        meter.decide(2, u64::from(idx), hub[idx as usize]);
        hubs.push(HitsScoreEntry {
            node_id: graph.id(idx).to_owned(),
            score_ppb: hub[idx as usize],
        });
    }

    let mut auth_order: Vec<u32> = (0..n as u32).collect();
    auth_order.sort_by(|&a, &b| {
        auth[b as usize]
            .cmp(&auth[a as usize])
            .then_with(|| a.cmp(&b))
    });
    let mut authorities = Vec::with_capacity(n);
    for idx in auth_order {
        meter.decide(3, u64::from(idx), auth[idx as usize]);
        authorities.push(HitsScoreEntry {
            node_id: graph.id(idx).to_owned(),
            score_ppb: auth[idx as usize],
        });
    }

    let working_bytes = (n * (8 * 4 + 16 * 2)) as u64;
    meter.finish(
        &IDENTITY,
        InputShape {
            node_count: n as u64,
            edge_count: m as u64,
            input_digest: digest,
        },
        HitsOutput {
            hubs,
            authorities,
            iterations,
            residual_ppb,
            converged,
        },
        &bound_rows,
        working_bytes,
    )
}
