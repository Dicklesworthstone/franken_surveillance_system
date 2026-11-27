#![forbid(unsafe_code)]
//! `ALG-CDS-001` — Connected dominating set (CDS) and resilient observer-backbone design
//! (`fss-x4a.23.70.8`).
//!
//! Computes a connected observer/relay/control backbone where:
//! - Every non-backbone vertex is dominated by at least `min_dominators` (`>= 1`) backbone nodes;
//! - The induced backbone subgraph is connected (and optionally biconnected / free of cut-vertices
//!   when `require_biconnected_backbone == true`);
//! - Distinguishes resilient connected domination from fragile minimum spanning/Steiner trees
//!   (`mst_baseline_lacks_redundancy: true`, exposing `backbone_cut_vertices`,
//!   `min_domination_depth`, and `distinct_failure_domains`).
//!
//! Exact exhaustive minimum-cost CDS for bounded small instances (`n <= 14`), deterministic
//! connected-greedy + safe-prune approximation otherwise.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fss_core::CanonicalEncoder;

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, mul, query_digest, query_encoder,
};
use crate::graph::{GraphError, UndirectedGraph};

/// Projection digest domain (`SCHEMA-DOMAIN-GRAPH-CDS-PROJECTION-001`).
pub const PROJECTION_DOMAIN: &str = "fss.graph.cds_projection.v1";
/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-CDS-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.cds_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-CDS-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.cds_decision_path.v1";

/// Registered identity (`architecture/graph_algorithms.json`, `ALG-CDS-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-CDS-001",
    algorithm_name: "connected_dominating_set_and_resilient_backbone",
    tie_break_rule: "minimum total cost then cardinality then lexicographic backbone node tuple",
    complexity_witness: "subset connectivity checks, domination audits, and greedy augmentations",
    output_size_witness: "<= |V| backbone nodes plus cut-vertex resilience diagnostics",
    exactness: "bounded_exact_or_approximate",
    implementation_id: "fss-graph-algorithms:alg-cds-001:exact-small-and-greedy-resilient-cds:v1",
    tie_break_policy_id: "tie:min-cost-then-size-then-lexicographic-backbone-ids:v1",
    policy_id: "graph-policy:undirected:connected-dominating-backbone:explicit-k-domination-and-biconnectivity:tie:min-cost-then-size-then-lexicographic-backbone-ids:v1",
    complexity_bound_id: "bound:alg-cds-001:exact-2n-small-or-cubic-greedy-prune:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// Maximum node count for exhaustive exact minimum-cost CDS search (`2^14 = 16,384` subsets).
pub const EXACT_CDS_NODE_LIMIT: usize = 14;

/// Configuration for resilient connected dominating backbone synthesis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CdsBackboneConfig {
    /// Per-node deployment cost (`node_id -> cost >= 1`; defaults to `1` if omitted).
    pub node_costs: BTreeMap<String, u64>,
    /// Per-node failure domain label for diversity accounting.
    pub node_failure_domains: BTreeMap<String, String>,
    /// Minimum distinct backbone neighbors required for every non-backbone node (`>= 1`).
    pub min_dominators: usize,
    /// When `true`, backbone must have zero cut vertices (survives any single backbone node failure!).
    pub require_biconnected_backbone: bool,
}

/// Exact or heuristic lane executed by `ALG-CDS-001`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CdsSolverLane {
    /// Exhaustive exact minimum-cost CDS over all `2^n` subsets (`n <= 14`).
    ExactSmall,
    /// Deterministic connected-greedy expansion + safe redundant-node pruning.
    ApproximateConnectedGreedy,
}

/// Canonical answer of `ALG-CDS-001`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CdsBackboneResult {
    /// Exact or heuristic lane executed.
    pub lane: CdsSolverLane,
    /// True iff a feasible backbone satisfying connectivity, domination depth, and biconnectivity exists.
    pub feasible: bool,
    /// Selected backbone node IDs in ascending canonical order.
    pub backbone_nodes: Vec<String>,
    /// Total cost of `backbone_nodes`.
    pub total_cost: u64,
    /// Minimum domination depth achieved across non-backbone nodes (`0` if infeasible; `usize::MAX` if all nodes in backbone).
    pub achieved_min_domination_depth: usize,
    /// Cut vertices inside the induced backbone subgraph (empty => survives any single backbone node loss!).
    pub backbone_cut_vertices: Vec<String>,
    /// Distinct failure domains present across `backbone_nodes`.
    pub distinct_failure_domains: usize,
    /// Always `true`: minimum spanning / Steiner baselines remove redundancy and are NOT equivalent to resilient CDS!
    pub mst_baseline_lacks_redundancy: bool,
    /// Always `false`: derived deployment recommendation never grants effect authority.
    pub grants_effect_authority: bool,
}

impl CertifiedOutput for CdsBackboneResult {
    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self.lane {
            CdsSolverLane::ExactSmall => 1,
            CdsSolverLane::ApproximateConnectedGreedy => 2,
        });
        encoder.u8(u8::from(self.feasible));
        encoder.u64(self.total_cost);
        encoder.u64(self.achieved_min_domination_depth as u64);
        encoder.u64(self.distinct_failure_domains as u64);
        encoder.u64(self.backbone_nodes.len() as u64);
        for id in &self.backbone_nodes {
            encoder.text(id);
        }
        encoder.u64(self.backbone_cut_vertices.len() as u64);
        for id in &self.backbone_cut_vertices {
            encoder.text(id);
        }
    }

    fn entries(&self) -> u64 {
        add(
            self.backbone_nodes.len() as u64,
            self.backbone_cut_vertices.len() as u64,
        )
    }
}

/// Registered complexity bound for `n` nodes and `m` edges.
#[must_use]
pub fn bound(n: u64, m: u64) -> Vec<BoundRow> {
    let evals = if n <= EXACT_CDS_NODE_LIMIT as u64 {
        1_u64.checked_shl(n as u32).unwrap_or(u64::MAX)
    } else {
        add(mul(n, n), mul(2, n))
    };
    let per_eval = add(mul(n, n), add(mul(2, n), add(m, 2)));
    vec![
        ("subset_checks", add(evals, 4)),
        ("resilience_audits", add(mul(evals, per_eval), 8)),
        (OUTPUT_ENTRIES, mul(2, n)),
    ]
}

struct BestCdsCandidate {
    cost: u64,
    size: usize,
    picked: Vec<usize>,
    depth: usize,
    cuts: Vec<usize>,
}

fn is_induced_connected(
    graph: &UndirectedGraph,
    members: &[bool],
    count: usize,
    meter: &mut Meter<'_>,
) -> Result<bool, GraphError> {
    if count <= 1 {
        return Ok(count == 1);
    }
    let Some(start) = members.iter().position(|&b| b) else {
        return Ok(false);
    };
    let mut visited = vec![false; members.len()];
    let mut q = VecDeque::new();
    visited[start] = true;
    q.push_back(start);
    let mut seen = 0_usize;
    while let Some(u) = q.pop_front() {
        meter.tick("resilience_audits")?;
        seen += 1;
        for &(v_u32, _) in graph.neighbours(u as u32) {
            let v = v_u32 as usize;
            if members[v] && !visited[v] {
                visited[v] = true;
                q.push_back(v);
            }
        }
    }
    Ok(seen == count)
}

fn backbone_cut_vertices_indices(
    graph: &UndirectedGraph,
    members: &[bool],
    count: usize,
    meter: &mut Meter<'_>,
) -> Result<Vec<usize>, GraphError> {
    if count <= 2 {
        return Ok(Vec::new());
    }
    let mut cuts = Vec::new();
    let mut trial = members.to_vec();
    for (u, &in_b) in members.iter().enumerate() {
        if !in_b {
            continue;
        }
        trial[u] = false;
        if !is_induced_connected(graph, &trial, count - 1, meter)? {
            cuts.push(u);
        }
        trial[u] = true;
    }
    Ok(cuts)
}

fn min_domination_depth(
    graph: &UndirectedGraph,
    members: &[bool],
    meter: &mut Meter<'_>,
) -> Result<usize, GraphError> {
    let mut min_d = usize::MAX;
    for (u, &in_b) in members.iter().enumerate() {
        meter.tick("resilience_audits")?;
        if in_b {
            continue;
        }
        let dom = graph
            .neighbours(u as u32)
            .iter()
            .filter(|&&(v, _)| members[v as usize])
            .count();
        min_d = min_d.min(dom);
    }
    Ok(min_d)
}

/// Runs `ALG-CDS-001` connected dominating set & resilient observer-backbone synthesis.
pub fn compute_resilient_cds_backbone(
    graph: &UndirectedGraph,
    config: &CdsBackboneConfig,
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<CertifiedRun<CdsBackboneResult>, GraphError> {
    if config.min_dominators == 0 {
        return Err(GraphError::PreconditionFailed(
            "min_dominators must be >= 1".to_owned(),
        ));
    }
    let n = graph.node_count();
    let m = graph.edge_count();
    let bound_rows = bound(n as u64, m as u64);
    let mut meter = Meter::new_cancellable(&IDENTITY, budget, is_cancelled);

    let mut q = query_encoder(&IDENTITY, graph.digest());
    q.u64(config.min_dominators as u64);
    q.u8(u8::from(config.require_biconnected_backbone));
    q.u64(config.node_costs.len() as u64);
    for (id, c) in &config.node_costs {
        q.text(id);
        q.u64(*c);
    }
    q.u64(config.node_failure_domains.len() as u64);
    for (id, dom) in &config.node_failure_domains {
        q.text(id);
        q.text(dom);
    }
    let input_digest = query_digest(q);

    let costs: Vec<u64> = (0..n)
        .map(|u| {
            config
                .node_costs
                .get(graph.id(u as u32))
                .copied()
                .unwrap_or(1)
                .max(1)
        })
        .collect();

    let use_exact = n <= EXACT_CDS_NODE_LIMIT;
    let lane = if use_exact {
        CdsSolverLane::ExactSmall
    } else {
        CdsSolverLane::ApproximateConnectedGreedy
    };

    let mut best: Option<BestCdsCandidate> = None;

    if n > 0 && use_exact {
        let total_masks = 1_usize << n;
        let mut members = vec![false; n];
        for mask in 1..total_masks {
            meter.tick("subset_checks")?;
            let mut count = 0_usize;
            let mut cost = 0_u64;
            let mut picked = Vec::new();
            for i in 0..n {
                let bit = (mask & (1 << i)) != 0;
                members[i] = bit;
                if bit {
                    count += 1;
                    cost = cost.saturating_add(costs[i]);
                    picked.push(i);
                }
            }
            // Fast prune if already worse than best found!
            if let Some(ref b) = best
                && (cost, count, picked.as_slice()) >= (b.cost, b.size, b.picked.as_slice())
            {
                continue;
            }
            let depth = min_domination_depth(graph, &members, &mut meter)?;
            if depth < config.min_dominators {
                continue;
            }
            if !is_induced_connected(graph, &members, count, &mut meter)? {
                continue;
            }
            let cuts = backbone_cut_vertices_indices(graph, &members, count, &mut meter)?;
            if config.require_biconnected_backbone && (!cuts.is_empty() || (n >= 3 && count < 3)) {
                continue;
            }
            best = Some(BestCdsCandidate {
                cost,
                size: count,
                picked,
                depth,
                cuts,
            });
        }
    } else if n > 0 {
        // Connected-greedy construction + safe redundant-node pruning for large graphs.
        let mut members = vec![true; n];
        let mut count = n;
        let base_ok = is_induced_connected(graph, &members, count, &mut meter)?;
        if base_ok {
            // Try greedily removing highest-cost nodes that preserve domination, connectivity, and biconnectivity.
            let mut order: Vec<usize> = (0..n).collect();
            order.sort_by(|&a, &b| costs[b].cmp(&costs[a]).then_with(|| b.cmp(&a)));
            for u in order {
                if count <= 1 {
                    break;
                }
                meter.tick("subset_checks")?;
                members[u] = false;
                let depth = min_domination_depth(graph, &members, &mut meter)?;
                let conn = depth >= config.min_dominators
                    && is_induced_connected(graph, &members, count - 1, &mut meter)?;
                let biconn_ok = if conn && config.require_biconnected_backbone {
                    let cuts =
                        backbone_cut_vertices_indices(graph, &members, count - 1, &mut meter)?;
                    cuts.is_empty() && (n < 3 || count > 3)
                } else {
                    conn
                };
                if biconn_ok {
                    count -= 1;
                } else {
                    members[u] = true;
                }
            }
            let depth = min_domination_depth(graph, &members, &mut meter)?;
            let cuts = backbone_cut_vertices_indices(graph, &members, count, &mut meter)?;
            let biconn_ok =
                !config.require_biconnected_backbone || (cuts.is_empty() && (n < 3 || count >= 3));
            if depth >= config.min_dominators && biconn_ok {
                let picked: Vec<usize> = (0..n).filter(|&i| members[i]).collect();
                let cost: u64 = picked.iter().map(|&i| costs[i]).sum();
                best = Some(BestCdsCandidate {
                    cost,
                    size: count,
                    picked,
                    depth,
                    cuts,
                });
            }
        }
    }

    let output = match best {
        Some(BestCdsCandidate {
            cost: total_cost,
            picked,
            depth,
            cuts,
            ..
        }) => {
            let backbone_nodes: Vec<String> = picked
                .iter()
                .map(|&i| graph.id(i as u32).to_owned())
                .collect();
            let backbone_cut_vertices: Vec<String> = cuts
                .iter()
                .map(|&i| graph.id(i as u32).to_owned())
                .collect();
            let mut domains = BTreeSet::new();
            for id in &backbone_nodes {
                meter.path().text(id);
                if let Some(d) = config.node_failure_domains.get(id) {
                    domains.insert(d.as_str());
                }
            }
            CdsBackboneResult {
                lane,
                feasible: true,
                backbone_nodes,
                total_cost,
                achieved_min_domination_depth: depth,
                backbone_cut_vertices,
                distinct_failure_domains: domains.len(),
                mst_baseline_lacks_redundancy: true,
                grants_effect_authority: false,
            }
        }
        None => CdsBackboneResult {
            lane,
            feasible: false,
            backbone_nodes: Vec::new(),
            total_cost: 0,
            achieved_min_domination_depth: 0,
            backbone_cut_vertices: Vec::new(),
            distinct_failure_domains: 0,
            mst_baseline_lacks_redundancy: true,
            grants_effect_authority: false,
        },
    };
    let shape = InputShape {
        node_count: n as u64,
        edge_count: m as u64,
        input_digest,
    };
    let peak_bytes = ((n + m + 1) * 128) as u64;
    meter.finish(&IDENTITY, shape, output, &bound_rows, peak_bytes)
}
