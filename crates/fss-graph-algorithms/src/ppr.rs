#![forbid(unsafe_code)]
//! `ALG-PPR-001` — Personalized PageRank over immutable directed weighted projections.
//!
//! Computes deterministic integer fixed-point (`10^9` parts-per-billion) personalized stationary
//! scores via power iteration with explicit teleport probability `alpha_ppm` and dangling-node
//! redistribution to the declared seed distribution. Equal scores break ties by ascending stable
//! node identity (`tie:score-ppb-descending-then-stable-node-identity-ascending:v1`).

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, mul, query_digest, query_encoder,
};
use crate::graph::GraphError;
use crate::weighted::{Orientation, WeightedGraph};

/// Fixed-point stationary mass scale: `1_000_000_000` parts per billion (`1.0`).
pub const SCALE_PPB: u64 = 1_000_000_000;
/// Maximum allowed power-iteration steps.
pub const MAX_PPR_ITERATIONS: u32 = 256;

/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-PPR-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.ppr_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-PPR-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.ppr_decision_path.v1";

/// Registered identity (`architecture/graph_algorithms.json`, `ALG-PPR-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-PPR-001",
    algorithm_name: "personalized_pagerank",
    tie_break_rule: "score then stable node identity",
    complexity_witness: "sparse multiply/add operations",
    output_size_witness: "<= |V| stationary score entries",
    exactness: "approximate_advisory",
    implementation_id: "fss-graph-algorithms:alg-ppr-001:fixed-point-power-iteration-1e9:v1",
    tie_break_policy_id: "tie:score-ppb-descending-then-stable-node-identity-ascending:v1",
    policy_id: "graph-policy:directed:simple-strict:fixed-point-1e9-power-iteration:tie:score-ppb-descending-then-stable-node-identity-ascending:v1",
    complexity_bound_id: "bound:alg-ppr-001:power-iterations-times-n-plus-m:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// Registered complexity bound for `n` nodes, `m` arcs, and `max_iterations` steps.
#[must_use]
pub fn bound(n: u64, m: u64, max_iterations: u32) -> Vec<BoundRow> {
    let iters = u64::from(max_iterations);
    vec![
        ("sparse_multiply_adds", mul(iters, add(mul(2, n), m))),
        ("norm_evaluations", mul(iters, n)),
        (OUTPUT_ENTRIES, n),
    ]
}

/// Parameters for one `ALG-PPR-001` invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PprConfig {
    /// Teleport probability in parts per million (`1..=999_999`, e.g. `150_000` for `0.15`).
    pub alpha_ppm: u32,
    /// Maximum power iterations (`1..=256`).
    pub max_iterations: u32,
    /// L1 convergence tolerance in parts per billion.
    pub tolerance_ppb: u64,
}

impl Default for PprConfig {
    fn default() -> Self {
        Self {
            alpha_ppm: 150_000,
            max_iterations: 32,
            tolerance_ppb: 1_000,
        }
    }
}

/// Stationary score of one node.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PprScoreEntry {
    /// Stable node identity.
    pub node_id: String,
    /// Stationary score in parts per billion (`0..=1_000_000_000`).
    pub score_ppb: u64,
}

/// Canonical answer of `ALG-PPR-001`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PprOutput {
    /// Nodes ranked by `score_ppb` descending, then `node_id` ascending.
    pub scores: Vec<PprScoreEntry>,
    /// Number of power iterations executed.
    pub iterations: u32,
    /// Final L1 residual in parts per billion.
    pub residual_ppb: u64,
    /// Whether `residual_ppb <= tolerance_ppb` was reached within `max_iterations`.
    pub converged: bool,
}

impl CertifiedOutput for PprOutput {
    fn entries(&self) -> u64 {
        self.scores.len() as u64
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.iterations);
        encoder.u64(self.residual_ppb);
        encoder.bool(self.converged);
        encoder.u64(self.scores.len() as u64);
        for entry in &self.scores {
            encoder.text(&entry.node_id);
            encoder.u64(entry.score_ppb);
        }
    }
}

fn input_digest(
    graph: &WeightedGraph,
    canonical_seeds: &[(u32, u64)],
    config: &PprConfig,
) -> ContentDigest {
    let mut encoder = query_encoder(&IDENTITY, graph.digest());
    encoder.u32(config.alpha_ppm);
    encoder.u32(config.max_iterations);
    encoder.u64(config.tolerance_ppb);
    encoder.u64(canonical_seeds.len() as u64);
    for &(idx, weight) in canonical_seeds {
        encoder.text(graph.id(idx));
        encoder.u64(weight);
    }
    query_digest(encoder)
}

/// Runs `ALG-PPR-001` over a directed `WeightedGraph`.
///
/// # Errors
///
/// Fails closed on undirected graphs, invalid `config`, empty/duplicate/zero-weight/unknown seeds,
/// or budget/bound exhaustion.
pub fn personalized_pagerank(
    graph: &WeightedGraph,
    seeds: &[(&str, u64)],
    config: &PprConfig,
    budget: Budget,
) -> Result<CertifiedRun<PprOutput>, GraphError> {
    graph.require_orientation(Orientation::Directed)?;
    if config.alpha_ppm == 0 || config.alpha_ppm >= 1_000_000 {
        return Err(GraphError::PreconditionFailed(
            "alpha_ppm must be in 1..=999_999".to_owned(),
        ));
    }
    if config.max_iterations == 0 || config.max_iterations > MAX_PPR_ITERATIONS {
        return Err(GraphError::PreconditionFailed(
            "max_iterations must be in 1..=256".to_owned(),
        ));
    }
    let n = graph.node_count();
    let m = graph.arc_count();
    if n == 0 {
        if !seeds.is_empty() {
            return Err(GraphError::UnknownNode(seeds[0].0.to_owned()));
        }
        let digest = input_digest(graph, &[], config);
        let meter = Meter::new(&IDENTITY, budget);
        let bound_rows = bound(0, 0, config.max_iterations);
        return meter.finish(
            &IDENTITY,
            InputShape {
                node_count: 0,
                edge_count: 0,
                input_digest: digest,
            },
            PprOutput::default(),
            &bound_rows,
            0,
        );
    }
    if seeds.is_empty() {
        return Err(GraphError::PreconditionFailed(
            "personalized_pagerank requires at least one seed node".to_owned(),
        ));
    }

    let mut canonical_seeds: Vec<(u32, u64)> = Vec::with_capacity(seeds.len());
    let mut seed_weight_sum: u128 = 0;
    for &(id, weight) in seeds {
        if weight == 0 {
            return Err(GraphError::PreconditionFailed(format!(
                "seed {id} must have positive weight"
            )));
        }
        let idx = graph
            .index_of(id)
            .ok_or_else(|| GraphError::UnknownNode(id.to_owned()))?;
        canonical_seeds.push((idx, weight));
        seed_weight_sum = seed_weight_sum
            .checked_add(u128::from(weight))
            .ok_or(GraphError::ArithmeticOverflow("seed_weight_sum"))?;
    }
    canonical_seeds.sort_unstable_by_key(|&(idx, _)| idx);
    for pair in canonical_seeds.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(GraphError::DuplicateNode(
                graph.id(pair[0].0).to_owned(),
            ));
        }
    }

    let digest = input_digest(graph, &canonical_seeds, config);
    let mut meter = Meter::new(&IDENTITY, budget);

    let mut seed_ppb = vec![0_u64; n];
    let mut assigned: u64 = 0;
    for &(idx, weight) in &canonical_seeds {
        let share = ((u128::from(weight) * u128::from(SCALE_PPB)) / seed_weight_sum) as u64;
        seed_ppb[idx as usize] = share;
        assigned = assigned.saturating_add(share);
    }
    let mut deficit = SCALE_PPB.saturating_sub(assigned);
    for &(idx, _) in &canonical_seeds {
        if deficit == 0 {
            break;
        }
        seed_ppb[idx as usize] += 1;
        deficit -= 1;
    }

    let mut out_weight = vec![0_u128; n];
    for u in 0..n as u32 {
        let mut sum = 0_u128;
        for &arc_idx in graph.out_arcs(u) {
            let w = u128::from(graph.arc(arc_idx).weight.max(1));
            sum = sum
                .checked_add(w)
                .ok_or(GraphError::ArithmeticOverflow("out_weight"))?;
        }
        out_weight[u as usize] = sum;
    }

    let mut rank = seed_ppb.clone();
    let mut next = vec![0_u64; n];
    let mut iterations = 0_u32;
    let mut residual_ppb = 0_u64;
    let mut converged = false;
    let alpha = u128::from(config.alpha_ppm);
    let walk_ppm = 1_000_000_u128 - alpha;

    for iter in 1..=config.max_iterations {
        iterations = iter;
        next.fill(0);

        let mut dangling_mass = 0_u128;
        for u in 0..n {
            meter.tick("sparse_multiply_adds")?;
            if out_weight[u] == 0 {
                dangling_mass += u128::from(rank[u]);
            }
        }

        for v in 0..n {
            meter.tick("sparse_multiply_adds")?;
            let sv = u128::from(seed_ppb[v]);
            if sv > 0 {
                let tele = (alpha * sv) / 1_000_000;
                let dang = (walk_ppm * dangling_mass * sv) / (1_000_000 * u128::from(SCALE_PPB));
                next[v] = (tele + dang) as u64;
            }
        }

        for u in 0..n as u32 {
            let ow = out_weight[u as usize];
            if ow == 0 {
                continue;
            }
            let walk_u = (walk_ppm * u128::from(rank[u as usize])) / 1_000_000;
            for &arc_idx in graph.out_arcs(u) {
                meter.tick("sparse_multiply_adds")?;
                let arc = graph.arc(arc_idx);
                let w = u128::from(arc.weight.max(1));
                let contrib = ((walk_u * w) / ow) as u64;
                next[arc.head as usize] = next[arc.head as usize].saturating_add(contrib);
            }
        }

        let sum_next: u64 = next.iter().copied().sum();
        if sum_next < SCALE_PPB {
            let first_seed = canonical_seeds[0].0 as usize;
            next[first_seed] = next[first_seed].saturating_add(SCALE_PPB - sum_next);
        }

        let mut l1 = 0_u64;
        for v in 0..n {
            meter.tick("norm_evaluations")?;
            l1 = l1.saturating_add(next[v].abs_diff(rank[v]));
        }
        residual_ppb = l1;
        meter.decide(1, u64::from(iter), residual_ppb);
        rank.copy_from_slice(&next);
        if residual_ppb <= config.tolerance_ppb {
            converged = true;
            break;
        }
    }

    let mut order: Vec<u32> = (0..n as u32).collect();
    order.sort_by(|&a, &b| {
        rank[b as usize]
            .cmp(&rank[a as usize])
            .then_with(|| a.cmp(&b))
    });
    let mut scores = Vec::with_capacity(n);
    for idx in order {
        meter.decide(2, u64::from(idx), rank[idx as usize]);
        scores.push(PprScoreEntry {
            node_id: graph.id(idx).to_owned(),
            score_ppb: rank[idx as usize],
        });
    }

    let working_bytes = (n * (8 * 4 + 16)) as u64;
    let bound_rows = bound(n as u64, m as u64, config.max_iterations);
    meter.finish(
        &IDENTITY,
        InputShape {
            node_count: n as u64,
            edge_count: m as u64,
            input_digest: digest,
        },
        PprOutput {
            scores,
            iterations,
            residual_ppb,
            converged,
        },
        &bound_rows,
        working_bytes,
    )
}
