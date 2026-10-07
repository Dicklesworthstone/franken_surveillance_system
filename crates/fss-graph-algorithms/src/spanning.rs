//! `ALG-MST-001` — minimum spanning forest.
//!
//! Kruskal over an undirected projection with the strict total edge order
//! `(weight, canonical edge index)`, so the forest is unique: it is the minimum spanning forest
//! of the perturbed weights `weight * (m + 1) + index`, which is also a minimum spanning forest
//! of the real weights. Edges are ordered by a counted bottom-up merge sort and joined by a
//! union-find with union by size and no path compression, so every find is at most
//! `floor(log2 n) + 1` steps and the registered bound is a hard worst case, not an amortized one.

use fss_core::CanonicalEncoder;

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, checked_add, mul, query_digest, query_encoder,
};
use crate::graph::GraphError;
use crate::weighted::{Orientation, WeightedGraph};

/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-MST-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.mst_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-MST-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.mst_decision_path.v1";

/// Registered identity (`ALG-MST-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-MST-001",
    algorithm_name: "minimum_spanning_forest",
    tie_break_rule: "weight then stable edge identity",
    complexity_witness: "sort comparisons and union/find operations",
    output_size_witness: "<= |V| - 1 tree edges",
    exactness: "exact",
    implementation_id: "fss-graph-algorithms:alg-mst-001:kruskal-merge-sort-union-by-size:v1",
    tie_break_policy_id: "tie:weight-then-canonical-edge-index:v1",
    policy_id: "graph-policy:undirected:simple-strict:edge-weight:numeric:u64-exact:checked:unit-bound:v1:tie:weight-then-canonical-edge-index:v1",
    complexity_bound_id: "bound:alg-mst-001:merge-sort-m-log-m-plus-union-by-size:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// `ceil(log2 x)` for `x >= 1` (0 for 0 and 1).
#[must_use]
pub const fn ceil_log2(x: u64) -> u64 {
    if x <= 1 {
        0
    } else {
        64 - (x - 1).leading_zeros() as u64
    }
}

/// `floor(log2 x) + 1` for `x >= 1` (1 for 0).
#[must_use]
pub const fn find_depth(x: u64) -> u64 {
    if x <= 1 {
        1
    } else {
        64 - x.leading_zeros() as u64
    }
}

/// The registered bound for `n` nodes and `m` edges.
#[must_use]
pub fn bound(n: u64, m: u64) -> Vec<BoundRow> {
    vec![
        ("sort_comparisons", mul(m, ceil_log2(m))),
        ("edge_scans", m),
        ("find_steps", mul(mul(2, m), find_depth(n))),
        ("unions", n.saturating_sub(1)),
        (OUTPUT_ENTRIES, n.saturating_sub(1)),
    ]
}

/// The canonical answer of `ALG-MST-001`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SpanningForestOutput {
    /// Forest edges `(lower, higher, weight)` in canonical edge order.
    pub edges: Vec<(String, String, u64)>,
    /// Sum of forest edge weights.
    pub total_weight: u64,
    /// Connected components of the projection (trees of the forest).
    pub components: u64,
}

impl CertifiedOutput for SpanningForestOutput {
    fn entries(&self) -> u64 {
        self.edges.len() as u64
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.edges.len() as u64);
        for (a, b, weight) in &self.edges {
            encoder.text(a);
            encoder.text(b);
            encoder.u64(*weight);
        }
        encoder.u64(self.total_weight);
        encoder.u64(self.components);
    }
}

/// Union-find with union by size and no path compression.
#[derive(Clone, Debug)]
pub(crate) struct UnionFind {
    parent: Vec<u32>,
    size: Vec<u32>,
}

impl UnionFind {
    pub(crate) fn new(n: usize) -> Self {
        Self {
            parent: (0..n as u32).collect(),
            size: vec![1; n],
        }
    }

    pub(crate) fn find(&self, mut node: u32, meter: &mut Meter) -> Result<u32, GraphError> {
        meter.tick("find_steps")?;
        while self.parent[node as usize] != node {
            meter.tick("find_steps")?;
            node = self.parent[node as usize];
        }
        Ok(node)
    }

    /// Joins two distinct roots; returns `(new root, attached root)`.
    pub(crate) fn join(&mut self, a: u32, b: u32) -> (u32, u32) {
        let (big, small) = if (self.size[a as usize], b) >= (self.size[b as usize], a) {
            (a, b)
        } else {
            (b, a)
        };
        self.parent[small as usize] = big;
        self.size[big as usize] += self.size[small as usize];
        (big, small)
    }

    /// Undoes [`Self::join`] given its result.
    pub(crate) fn split(&mut self, big: u32, small: u32) {
        self.parent[small as usize] = small;
        self.size[big as usize] -= self.size[small as usize];
    }
}

/// Bottom-up merge sort of `items` by `key`, charging one comparison each.
fn merge_sort<K: Ord + Copy>(
    items: &mut Vec<u32>,
    key: impl Fn(u32) -> K,
    meter: &mut Meter,
) -> Result<(), GraphError> {
    let len = items.len();
    let mut buffer = vec![0_u32; len];
    let mut width = 1;
    while width < len {
        let mut start = 0;
        while start < len {
            let middle = (start + width).min(len);
            let end = (start + 2 * width).min(len);
            let (mut i, mut j, mut k) = (start, middle, start);
            while i < middle && j < end {
                meter.tick("sort_comparisons")?;
                if key(items[j]) < key(items[i]) {
                    buffer[k] = items[j];
                    j += 1;
                } else {
                    buffer[k] = items[i];
                    i += 1;
                }
                k += 1;
            }
            while i < middle {
                buffer[k] = items[i];
                i += 1;
                k += 1;
            }
            while j < end {
                buffer[k] = items[j];
                j += 1;
                k += 1;
            }
            start = end;
        }
        std::mem::swap(items, &mut buffer);
        width *= 2;
    }
    Ok(())
}

/// Runs `ALG-MST-001` over an undirected projection.
///
/// # Errors
///
/// [`GraphError::PreconditionFailed`] for a directed projection, [`GraphError::ArithmeticOverflow`]
/// for a total weight outside `u64`, and the fail-closed budget and bound errors.
pub fn minimum_spanning_forest(
    graph: &WeightedGraph,
    budget: Budget,
) -> Result<CertifiedRun<SpanningForestOutput>, GraphError> {
    graph.require_orientation(Orientation::Undirected)?;
    let (n, m) = (graph.node_count(), graph.arc_count());
    let mut meter = Meter::new(&IDENTITY, budget);
    let mut order: Vec<u32> = (0..m as u32).collect();
    merge_sort(
        &mut order,
        |edge| (graph.arc(edge).weight, edge),
        &mut meter,
    )?;
    let mut sets = UnionFind::new(n);
    let mut chosen: Vec<u32> = Vec::new();
    let mut total_weight = 0_u64;
    for &edge in &order {
        meter.tick("edge_scans")?;
        let arc = graph.arc(edge);
        let (a, b) = (
            sets.find(arc.tail, &mut meter)?,
            sets.find(arc.head, &mut meter)?,
        );
        if a != b {
            meter.tick("unions")?;
            sets.join(a, b);
            meter.decide(0, u64::from(edge), arc.weight);
            total_weight = checked_add(total_weight, arc.weight, "forest weight")?;
            chosen.push(edge);
        }
    }
    chosen.sort_unstable();
    let output = SpanningForestOutput {
        edges: chosen
            .iter()
            .map(|&edge| {
                let (a, b) = graph.arc_ids(edge);
                (a, b, graph.arc(edge).weight)
            })
            .collect(),
        total_weight,
        components: (n - chosen.len()) as u64,
    };
    let (n64, m64) = (n as u64, m as u64);
    let input = query_encoder(&IDENTITY, graph.digest());
    // order and merge buffer (4 bytes per edge each), parent and size (4 bytes per node each),
    // chosen edges (4 bytes).
    let peak = add(mul(8, m64), mul(8, n64)) + 4 * chosen.len() as u64;
    meter.finish(
        &IDENTITY,
        InputShape {
            node_count: n64,
            edge_count: m64,
            input_digest: query_digest(input),
        },
        output,
        &bound(n64, m64),
        peak,
    )
}
