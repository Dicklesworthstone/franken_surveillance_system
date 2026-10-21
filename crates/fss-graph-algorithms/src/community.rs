#![forbid(unsafe_code)]
//! `ALG-COMM-001` — Community detection via deterministic integer modularity local moving over
//! immutable weighted projections.
//!
//! Evaluates exact integer modularity gain scaled by `(2W)^2` without floating-point arithmetic,
//! breaking ties by smallest canonical member community identity, and canonicalizes the resulting
//! partition in ascending smallest-member order
//! (`tie:modularity-gain-scaled-2m-squared-then-smallest-member-community-id:v1`).

use std::collections::BTreeMap;

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, encode_ids, mul, query_digest, query_encoder,
};
use crate::graph::GraphError;
use crate::weighted::WeightedGraph;

/// Fixed-point modularity scale: `1_000_000_000` parts per billion.
pub const SCALE_PPB: i64 = 1_000_000_000;
/// Maximum allowed local-moving passes.
pub const MAX_COMMUNITY_PASSES: u32 = 64;

/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-COMMUNITY-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.community_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-COMMUNITY-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.community_decision_path.v1";

/// Registered identity (`architecture/graph_algorithms.json`, `ALG-COMM-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-COMM-001",
    algorithm_name: "community_detection",
    tie_break_rule: "objective then canonical partition encoding",
    complexity_witness: "edge scans and moves",
    output_size_witness: "<= |V| community partition assignments",
    exactness: "approximate_advisory",
    implementation_id: "fss-graph-algorithms:alg-comm-001:deterministic-modularity-local-moving:v1",
    tie_break_policy_id: "tie:modularity-gain-scaled-2m-squared-then-smallest-member-community-id:v1",
    policy_id: "graph-policy:undirected-or-symmetrized:simple-strict:nonnegative-weight:tie:modularity-gain-scaled-2m-squared-then-smallest-member-community-id:v1",
    complexity_bound_id: "bound:alg-comm-001:passes-times-n-plus-2m-moves:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// Registered complexity bound for `n` nodes, `m` edges/arcs, and `max_passes`.
#[must_use]
pub fn bound(n: u64, m: u64, max_passes: u32) -> Vec<BoundRow> {
    let p = u64::from(max_passes);
    vec![
        ("edge_scans", mul(add(p, 1), mul(2, m))),
        ("node_moves", mul(add(p, 1), add(n, mul(2, m)))),
        (OUTPUT_ENTRIES, n),
    ]
}

/// One canonical community in the partition.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Community {
    /// Canonical community label (`0..k`, ordered by smallest member node identity).
    pub community_id: u32,
    /// Members in ascending stable node identity order.
    pub members: Vec<String>,
}

/// Canonical answer of `ALG-COMM-001`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommunityOutput {
    /// Canonical partition of the graph's nodes.
    pub communities: Vec<Community>,
    /// Modularity `Q` of the partition in parts per billion (`-1_000_000_000..=1_000_000_000`).
    pub modularity_ppb: i64,
    /// Number of local-moving passes executed.
    pub passes: u32,
}

impl CertifiedOutput for CommunityOutput {
    fn entries(&self) -> u64 {
        self.communities.iter().map(|c| c.members.len() as u64).sum()
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.modularity_ppb as u64);
        encoder.u32(self.passes);
        encoder.u64(self.communities.len() as u64);
        for c in &self.communities {
            encoder.u32(c.community_id);
            encode_ids(encoder, &c.members);
        }
    }
}

fn input_digest(graph: &WeightedGraph, max_passes: u32) -> ContentDigest {
    let mut encoder = query_encoder(&IDENTITY, graph.digest());
    encoder.u32(max_passes);
    query_digest(encoder)
}

/// Runs `ALG-COMM-001` over `graph` with at most `max_passes` local-moving sweeps.
///
/// # Errors
///
/// Fails closed on invalid `max_passes`, arithmetic overflow, or budget/bound exhaustion.
pub fn community_detection(
    graph: &WeightedGraph,
    max_passes: u32,
    budget: Budget,
) -> Result<CertifiedRun<CommunityOutput>, GraphError> {
    if max_passes == 0 || max_passes > MAX_COMMUNITY_PASSES {
        return Err(GraphError::PreconditionFailed(
            "max_passes must be in 1..=64".to_owned(),
        ));
    }
    let n = graph.node_count();
    let m = graph.arc_count();
    let digest = input_digest(graph, max_passes);
    let mut meter = Meter::new(&IDENTITY, budget);
    let bound_rows = bound(n as u64, m as u64, max_passes);

    if n == 0 {
        return meter.finish(
            &IDENTITY,
            InputShape {
                node_count: 0,
                edge_count: 0,
                input_digest: digest,
            },
            CommunityOutput::default(),
            &bound_rows,
            0,
        );
    }

    // Build symmetrized adjacency list `(neighbour, weight)`.
    let mut adj: Vec<Vec<(u32, u64)>> = vec![Vec::new(); n];
    let mut degree = vec![0_u128; n];
    let mut total_2w = 0_u128;
    for arc in graph.arcs() {
        let w = arc.weight.max(1);
        let w128 = u128::from(w);
        adj[arc.tail as usize].push((arc.head, w));
        adj[arc.head as usize].push((arc.tail, w));
        degree[arc.tail as usize] = degree[arc.tail as usize]
            .checked_add(w128)
            .ok_or(GraphError::ArithmeticOverflow("community_degree"))?;
        degree[arc.head as usize] = degree[arc.head as usize]
            .checked_add(w128)
            .ok_or(GraphError::ArithmeticOverflow("community_degree"))?;
        total_2w = total_2w
            .checked_add(2 * w128)
            .ok_or(GraphError::ArithmeticOverflow("community_total_weight"))?;
    }
    for neighbors in &mut adj {
        neighbors.sort_by_key(|&(v, _)| v);
    }

    let mut comm: Vec<u32> = (0..n as u32).collect();
    let mut sigma_tot = degree.clone();
    let mut passes = 0_u32;

    if total_2w > 0 {
        let m2 = i128::try_from(total_2w)
            .map_err(|_| GraphError::ArithmeticOverflow("community_m2"))?;
        for pass in 1..=max_passes {
            passes = pass;
            let mut moved_any = false;
            for u in 0..n as u32 {
                meter.tick("node_moves")?;
                let c_old = comm[u as usize];
                let ku = i128::try_from(degree[u as usize])
                    .map_err(|_| GraphError::ArithmeticOverflow("community_ku"))?;
                if ku == 0 {
                    continue;
                }
                let mut comm_weights: BTreeMap<u32, u128> = BTreeMap::new();
                comm_weights.insert(c_old, 0);
                for &(v, w) in &adj[u as usize] {
                    meter.tick("edge_scans")?;
                    if v != u {
                        *comm_weights.entry(comm[v as usize]).or_insert(0) += u128::from(w);
                    }
                }
                let w_old = i128::try_from(comm_weights.get(&c_old).copied().unwrap_or(0))
                    .map_err(|_| GraphError::ArithmeticOverflow("community_w_old"))?;
                let tot_old_without_u =
                    i128::try_from(sigma_tot[c_old as usize].saturating_sub(degree[u as usize]))
                        .map_err(|_| GraphError::ArithmeticOverflow("community_tot_old"))?;

                let mut best_comm = c_old;
                let mut best_gain: i128 = 0;

                for (&c_cand, &w_cand_u) in &comm_weights {
                    if c_cand == c_old {
                        continue;
                    }
                    meter.tick("node_moves")?;
                    let w_cand = i128::try_from(w_cand_u)
                        .map_err(|_| GraphError::ArithmeticOverflow("community_w_cand"))?;
                    let tot_cand = i128::try_from(sigma_tot[c_cand as usize])
                        .map_err(|_| GraphError::ArithmeticOverflow("community_tot_cand"))?;
                    // Exact integer scaled modularity delta:
                    // m2 * (w_cand - w_old) - ku * (tot_cand - tot_old_without_u)
                    let gain = m2 * (w_cand - w_old) - ku * (tot_cand - tot_old_without_u);
                    if gain > best_gain || (gain == best_gain && gain > 0 && c_cand < best_comm) {
                        best_gain = gain;
                        best_comm = c_cand;
                    }
                }

                if best_comm != c_old {
                    sigma_tot[c_old as usize] =
                        sigma_tot[c_old as usize].saturating_sub(degree[u as usize]);
                    sigma_tot[best_comm as usize] =
                        sigma_tot[best_comm as usize].saturating_add(degree[u as usize]);
                    comm[u as usize] = best_comm;
                    moved_any = true;
                    meter.decide(1, u64::from(u), u64::from(best_comm));
                }
            }
            if !moved_any {
                break;
            }
        }
    } else {
        passes = 1;
        for _ in 0..n {
            meter.tick("node_moves")?;
        }
    }

    // Group by community and canonicalize labels by smallest member index.
    let mut groups: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for (u, &c) in comm.iter().enumerate() {
        groups.entry(c).or_default().push(u as u32);
    }
    let mut sorted_groups: Vec<Vec<u32>> = groups.into_values().collect();
    sorted_groups.sort_by_key(|members| members[0]);

    let mut canonical_comm = vec![0_u32; n];
    let mut communities = Vec::with_capacity(sorted_groups.len());
    for (cid, members) in sorted_groups.iter().enumerate() {
        let cid = cid as u32;
        let mut names = Vec::with_capacity(members.len());
        for &u in members {
            canonical_comm[u as usize] = cid;
            names.push(graph.id(u).to_owned());
        }
        communities.push(Community {
            community_id: cid,
            members: names,
        });
    }

    // Compute exact modularity Q in parts per billion.
    let modularity_ppb = if total_2w == 0 {
        0
    } else {
        let mut internal_2w = 0_i128;
        for u in 0..n {
            for &(v, w) in &adj[u] {
                meter.tick("edge_scans")?;
                if canonical_comm[u] == canonical_comm[v as usize] {
                    internal_2w += i128::from(w);
                }
            }
        }
        let mut sum_sq_deg = 0_i128;
        for members in &sorted_groups {
            let tot: u128 = members.iter().map(|&u| degree[u as usize]).sum();
            let t = i128::try_from(tot)
                .map_err(|_| GraphError::ArithmeticOverflow("community_modularity"))?;
            sum_sq_deg += t * t;
        }
        let m2 = i128::try_from(total_2w)
            .map_err(|_| GraphError::ArithmeticOverflow("community_modularity"))?;
        let num = (internal_2w * m2 - sum_sq_deg) * i128::from(SCALE_PPB);
        let den = m2 * m2;
        (num / den) as i64
    };

    let working_bytes = ((n * 48) + (m * 32)) as u64;
    meter.finish(
        &IDENTITY,
        InputShape {
            node_count: n as u64,
            edge_count: m as u64,
            input_digest: digest,
        },
        CommunityOutput {
            communities,
            modularity_ppb,
            passes,
        },
        &bound_rows,
        working_bytes,
    )
}
