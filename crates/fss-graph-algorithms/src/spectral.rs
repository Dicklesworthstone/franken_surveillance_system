#![forbid(unsafe_code)]
//! `ALG-SPECTRAL-001` — Spectral change and bottleneck detection via deterministic integer
//! fixed-point deflated walk/Laplacian power iteration.
//!
//! Computes the degree-orthogonalized Fiedler/second walk eigenvector (`SCALE_PPB = 10^9`),
//! Rayleigh-quotient algebraic connectivity `lambda2_ppb`, and optional spectral drift score
//! against a reference topology. Equal magnitudes break ties by ascending stable node identity
//! (`tie:abs-eigenvector-ppb-descending-then-stable-node-identity:v1`).

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, mul, query_digest, query_encoder,
};
use crate::graph::GraphError;
use crate::weighted::WeightedGraph;

/// Fixed-point coordinate scale: `1_000_000_000` parts per billion.
pub const SCALE_PPB: i64 = 1_000_000_000;
/// Maximum allowed spectral power iterations.
pub const MAX_SPECTRAL_ITERATIONS: u32 = 256;

/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-SPECTRAL-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.spectral_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-SPECTRAL-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.spectral_decision_path.v1";

/// Registered identity (`architecture/graph_algorithms.json`, `ALG-SPECTRAL-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-SPECTRAL-001",
    algorithm_name: "spectral_change_detection",
    tie_break_rule: "eigen score then stable node identity",
    complexity_witness: "matrix-vector products and residual norms",
    output_size_witness: "<= k * |V| eigenvector entries and anomaly score",
    exactness: "approximate_advisory",
    implementation_id: "fss-graph-algorithms:alg-spectral-001:deflated-laplacian-power-iteration-1e9:v1",
    tie_break_policy_id: "tie:abs-eigenvector-ppb-descending-then-stable-node-identity:v1",
    policy_id: "graph-policy:undirected-or-symmetrized:simple-strict:normalized-walk-laplacian-fixed-point-1e9:tie:abs-eigenvector-ppb-descending-then-stable-node-identity:v1",
    complexity_bound_id: "bound:alg-spectral-001:iterations-times-n-plus-2m:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// Registered complexity bound for `n` nodes, `m` edges/arcs, and `max_iterations`.
#[must_use]
pub fn bound(n: u64, m: u64, max_iterations: u32) -> Vec<BoundRow> {
    let iters = u64::from(max_iterations);
    vec![
        ("matrix_vector_products", mul(add(iters, 1), add(n, mul(2, m)))),
        ("residual_norm_evaluations", mul(add(iters, 1), mul(2, n))),
        (OUTPUT_ENTRIES, add(n, 1)),
    ]
}

/// Parameters for one `ALG-SPECTRAL-001` invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpectralConfig {
    /// Maximum deflated power iterations (`1..=256`).
    pub max_iterations: u32,
    /// L-infinity residual convergence tolerance in parts per billion.
    pub tolerance_ppb: u64,
    /// Optional reference algebraic connectivity (`lambda2_ppb`) to measure regime drift against.
    pub reference_lambda2_ppb: Option<u64>,
}

impl Default for SpectralConfig {
    fn default() -> Self {
        Self {
            max_iterations: 32,
            tolerance_ppb: 1_000,
            reference_lambda2_ppb: None,
        }
    }
}

/// One node's Fiedler/spectral coordinate.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SpectralEntry {
    /// Stable node identity.
    pub node_id: String,
    /// Signed coordinate in parts per billion (`-1_000_000_000..=1_000_000_000`).
    pub value_ppb: i64,
}

/// Canonical answer of `ALG-SPECTRAL-001`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SpectralOutput {
    /// Fiedler vector entries ranked by `|value_ppb|` descending, then `node_id` ascending.
    pub eigenvector: Vec<SpectralEntry>,
    /// Rayleigh quotient algebraic connectivity `lambda2_ppb` (`0..=2_000_000_000`).
    pub algebraic_connectivity_ppb: u64,
    /// Spectral anomaly/change score in parts per billion.
    pub anomaly_score_ppb: u64,
    /// Iterations executed.
    pub iterations: u32,
}

impl CertifiedOutput for SpectralOutput {
    fn entries(&self) -> u64 {
        (self.eigenvector.len() + 1) as u64
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.algebraic_connectivity_ppb);
        encoder.u64(self.anomaly_score_ppb);
        encoder.u32(self.iterations);
        encoder.u64(self.eigenvector.len() as u64);
        for entry in &self.eigenvector {
            encoder.text(&entry.node_id);
            encoder.u64(entry.value_ppb as u64);
        }
    }
}

fn input_digest(graph: &WeightedGraph, config: &SpectralConfig) -> ContentDigest {
    let mut encoder = query_encoder(&IDENTITY, graph.digest());
    encoder.u32(config.max_iterations);
    encoder.u64(config.tolerance_ppb);
    match config.reference_lambda2_ppb {
        Some(ref_l2) => {
            encoder.bool(true);
            encoder.u64(ref_l2);
        }
        None => encoder.bool(false),
    }
    query_digest(encoder)
}

/// Runs `ALG-SPECTRAL-001` over `graph`.
///
/// # Errors
///
/// Fails closed on invalid `config`, arithmetic overflow, or budget/bound exhaustion.
pub fn spectral_change_detection(
    graph: &WeightedGraph,
    config: &SpectralConfig,
    budget: Budget,
) -> Result<CertifiedRun<SpectralOutput>, GraphError> {
    if config.max_iterations == 0 || config.max_iterations > MAX_SPECTRAL_ITERATIONS {
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
            SpectralOutput::default(),
            &bound_rows,
            0,
        );
    }

    let mut adj: Vec<Vec<(u32, u64)>> = vec![Vec::new(); n];
    let mut deg = vec![0_u64; n];
    for arc in graph.arcs() {
        let w = arc.weight.max(1);
        adj[arc.tail as usize].push((arc.head, w));
        adj[arc.head as usize].push((arc.tail, w));
        deg[arc.tail as usize] = deg[arc.tail as usize].saturating_add(w);
        deg[arc.head as usize] = deg[arc.head as usize].saturating_add(w);
    }
    for list in &mut adj {
        list.sort_by_key(|&(v, _)| v);
    }

    // Initialize alternating non-constant vector and deflate degree-weighted mean.
    let mut x = vec![0_i64; n];
    for (i, slot) in x.iter_mut().enumerate() {
        *slot = if i % 2 == 0 { SCALE_PPB } else { -SCALE_PPB };
    }
    let total_deg: i128 = deg.iter().map(|&d| i128::from(d.max(1))).sum();

    let deflate_and_normalize =
        |vec: &mut [i64], meter: &mut Meter| -> Result<(), GraphError> {
            let mut weighted_sum = 0_i128;
            for (i, &val) in vec.iter().enumerate() {
                meter.tick("residual_norm_evaluations")?;
                weighted_sum += i128::from(val) * i128::from(deg[i].max(1));
            }
            let mean = (weighted_sum / total_deg) as i64;
            let mut max_abs = 0_i64;
            for val in vec.iter_mut() {
                *val = val.saturating_sub(mean);
                max_abs = max_abs.max(val.saturating_abs());
            }
            if max_abs > 0 {
                // Canonical sign: first node with non-zero coordinate is positive.
                let first_sign = vec
                    .iter()
                    .copied()
                    .find(|&v| v != 0)
                    .map_or(1_i128, |v| if v > 0 { 1 } else { -1 });
                for val in vec.iter_mut() {
                    meter.tick("residual_norm_evaluations")?;
                    let scaled =
                        (i128::from(*val) * first_sign * i128::from(SCALE_PPB)) / i128::from(max_abs);
                    *val = scaled as i64;
                }
            } else {
                for _ in 0..vec.len() {
                    meter.tick("residual_norm_evaluations")?;
                }
            }
            Ok(())
        };

    deflate_and_normalize(&mut x, &mut meter)?;

    let mut next = vec![0_i64; n];
    let mut iterations = 0_u32;

    for iter in 1..=config.max_iterations {
        iterations = iter;
        for u in 0..n {
            meter.tick("matrix_vector_products")?;
            let du = i128::from(deg[u]);
            if du == 0 {
                next[u] = 0;
                continue;
            }
            let mut neighbor_sum = 0_i128;
            for &(v, w) in &adj[u] {
                meter.tick("matrix_vector_products")?;
                neighbor_sum += i128::from(w) * i128::from(x[v as usize]);
            }
            // Lazy random walk step: 0.5 * x[u] + 0.5 * (neighbor_sum / du)
            let avg = neighbor_sum / du;
            next[u] = ((i128::from(x[u]) + avg) / 2) as i64;
        }
        deflate_and_normalize(&mut next, &mut meter)?;

        let mut max_diff = 0_u64;
        for u in 0..n {
            max_diff = max_diff.max(next[u].abs_diff(x[u]));
        }
        meter.decide(1, u64::from(iter), max_diff);
        x.copy_from_slice(&next);
        if max_diff <= config.tolerance_ppb {
            break;
        }
    }

    // Rayleigh quotient of normalized Laplacian:
    // num = sum_{e=(u,v)} w_e * (x[u] - x[v])^2, den = sum_u d_u * x[u]^2.
    let mut num = 0_u128;
    for arc in graph.arcs() {
        meter.tick("matrix_vector_products")?;
        let w = u128::from(arc.weight.max(1));
        let diff = u128::from(x[arc.tail as usize].abs_diff(x[arc.head as usize]));
        num = num.saturating_add(w * diff * diff);
    }
    let mut den = 0_u128;
    for u in 0..n {
        meter.tick("matrix_vector_products")?;
        let du = u128::from(deg[u].max(1));
        let xu = u128::from(x[u].unsigned_abs());
        den = den.saturating_add(du * xu * xu);
    }
    let algebraic_connectivity_ppb = if den == 0 || m == 0 {
        0
    } else {
        ((num * u128::from(SCALE_PPB as u64)) / den).min(2_000_000_000) as u64
    };

    let anomaly_score_ppb = match config.reference_lambda2_ppb {
        Some(ref_l2) => algebraic_connectivity_ppb.abs_diff(ref_l2),
        None => (SCALE_PPB as u64).saturating_sub(algebraic_connectivity_ppb.min(SCALE_PPB as u64)),
    };

    let mut order: Vec<u32> = (0..n as u32).collect();
    order.sort_by(|&a, &b| {
        x[b as usize]
            .unsigned_abs()
            .cmp(&x[a as usize].unsigned_abs())
            .then_with(|| a.cmp(&b))
    });
    let mut eigenvector = Vec::with_capacity(n);
    for idx in order {
        meter.decide(2, u64::from(idx), x[idx as usize].unsigned_abs());
        eigenvector.push(SpectralEntry {
            node_id: graph.id(idx).to_owned(),
            value_ppb: x[idx as usize],
        });
    }

    let working_bytes = ((n * 48) + (m * 24)) as u64;
    meter.finish(
        &IDENTITY,
        InputShape {
            node_count: n as u64,
            edge_count: m as u64,
            input_digest: digest,
        },
        SpectralOutput {
            eigenvector,
            algebraic_connectivity_ppb,
            anomaly_score_ppb,
            iterations,
        },
        &bound_rows,
        working_bytes,
    )
}
