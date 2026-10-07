//! `ALG-GH-001` — Gomory–Hu (flow-equivalent) tree by Gusfield's algorithm.
//!
//! Over an undirected capacity projection, `n - 1` certified maximum-flow runs build a tree on
//! the same nodes whose edge `(v, parent(v))` carries the exact minimum cut value between `v` and
//! its parent. For every pair `(a, b)` the minimum cut value equals the smallest edge weight on
//! the tree path between them, so all `n (n - 1) / 2` pairwise resilience values are summarized
//! by `n - 1` numbers. The tree is the canonical Gusfield tree: nodes are processed in ascending
//! identity order, the root is the smallest identity, and each run uses the
//! [`crate::flow`] residual engine with its stable residual-edge tie-break (`(s, parent(s))`
//! is fixed once `s` is processed). The tree is flow-equivalent; this implementation does not
//! claim that every tree edge's two sides form the corresponding minimum cut.

use fss_core::CanonicalEncoder;

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, mul, query_digest, query_encoder,
};
use crate::flow::{self, Residual};
use crate::graph::GraphError;
use crate::weighted::{Orientation, WeightedGraph};

/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-GH-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.gomory_hu_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-GH-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.gomory_hu_decision_path.v1";

/// Registered identity (`ALG-GH-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-GH-001",
    algorithm_name: "gomory_hu_tree",
    tie_break_rule: "stable cut partition identity",
    complexity_witness: "max-flow invocations",
    output_size_witness: "<= |V| nodes and <= |V| - 1 tree edges",
    exactness: "exact",
    implementation_id: "fss-graph-algorithms:alg-gh-001:gusfield-flow-equivalent-edmonds-karp:v1",
    tie_break_policy_id: "tie:ascending-identity-processing-smallest-root-canonical-residual-edges:v1",
    policy_id: "graph-policy:undirected:simple-strict:edge-capacity:numeric:u64-exact:checked:unit-bound:v1:tie:ascending-identity-processing-smallest-root-canonical-residual-edges:v1",
    complexity_bound_id: "bound:alg-gh-001:n-minus-1-flow-runs:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// The registered bound for `n` nodes and `m` edges: `n - 1` flow runs, each within the
/// `ALG-FLOW-001` bound.
#[must_use]
pub fn bound(n: u64, m: u64) -> Vec<BoundRow> {
    let runs = n.saturating_sub(1);
    let per_run = flow::bound(n, m);
    let row = |name: &str| {
        per_run
            .iter()
            .find(|(counter, _)| *counter == name)
            .map_or(0, |&(_, limit)| limit)
    };
    vec![
        ("max_flow_runs", runs),
        ("augmentations", mul(runs, row("augmentations"))),
        ("residual_scans", mul(runs, row("residual_scans"))),
        ("path_steps", mul(runs, row("path_steps"))),
        ("partition_updates", mul(runs, n)),
        (OUTPUT_ENTRIES, add(n.saturating_sub(1), 0)),
    ]
}

/// The canonical answer of `ALG-GH-001`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GomoryHuOutput {
    /// The root (smallest identity), if any node exists.
    pub root: Option<String>,
    /// `(node, parent, minimum cut value)` for every non-root node, ascending by node.
    pub tree: Vec<(String, String, u64)>,
}

impl GomoryHuOutput {
    /// The minimum cut value between `a` and `b`: the smallest weight on their tree path.
    #[must_use]
    pub fn min_cut(&self, a: &str, b: &str) -> Option<u64> {
        if a == b {
            return None;
        }
        let parent_of = |node: &str| {
            self.tree
                .binary_search_by(|(member, _, _)| member.as_str().cmp(node))
                .ok()
                .map(|position| &self.tree[position])
        };
        let ancestry = |start: &str| -> Option<Vec<(String, u64)>> {
            let mut chain = vec![(start.to_owned(), u64::MAX)];
            let mut current = start.to_owned();
            while let Some((_, parent, value)) = parent_of(&current) {
                chain.push((parent.clone(), *value));
                current = parent.clone();
                if chain.len() > self.tree.len() + 1 {
                    return None;
                }
            }
            Some(chain)
        };
        let (left, right) = (ancestry(a)?, ancestry(b)?);
        if left.last().map(|(node, _)| node) != right.last().map(|(node, _)| node) {
            return None;
        }
        let meet = left
            .iter()
            .position(|(node, _)| right.iter().any(|(other, _)| other == node))?;
        let meet_node = &left[meet].0;
        let right_meet = right.iter().position(|(node, _)| node == meet_node)?;
        let edges_left = left[1..=meet].iter().map(|(_, value)| *value);
        let edges_right = right[1..=right_meet].iter().map(|(_, value)| *value);
        edges_left.chain(edges_right).min()
    }
}

impl CertifiedOutput for GomoryHuOutput {
    fn entries(&self) -> u64 {
        self.tree.len() as u64
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        match &self.root {
            None => encoder.tag(0),
            Some(root) => {
                encoder.tag(1);
                encoder.text(root);
            }
        }
        encoder.u64(self.tree.len() as u64);
        for (node, parent, value) in &self.tree {
            encoder.text(node);
            encoder.text(parent);
            encoder.u64(*value);
        }
    }
}

/// Runs `ALG-GH-001` over an undirected capacity projection.
///
/// # Errors
///
/// [`GraphError::PreconditionFailed`] for a directed projection, [`GraphError::ArithmeticOverflow`]
/// for a flow outside `u64`, and the fail-closed budget and bound errors.
pub fn gomory_hu_tree(
    graph: &WeightedGraph,
    budget: Budget,
) -> Result<CertifiedRun<GomoryHuOutput>, GraphError> {
    graph.require_orientation(Orientation::Undirected)?;
    let n = graph.node_count();
    let mut meter = Meter::new(&IDENTITY, budget);
    let mut parent = vec![0_u32; n];
    let mut value = vec![0_u64; n];
    let mut residual_edges = 0;
    for s in 1..n as u32 {
        meter.tick("max_flow_runs")?;
        let t = parent[s as usize];
        let mut residual = Residual::new(n);
        for arc in graph.arcs() {
            residual.add(arc.tail, arc.head, arc.weight);
            residual.add(arc.head, arc.tail, arc.weight);
        }
        residual_edges = residual.edges();
        let flow_value = residual.max_flow(s, t, None, &mut meter)?;
        let side = residual.reachable(s, &mut meter)?;
        value[s as usize] = flow_value;
        meter.decide(0, u64::from(s), u64::from(t));
        for i in s + 1..n as u32 {
            meter.tick("partition_updates")?;
            if side[i as usize] && parent[i as usize] == t {
                parent[i as usize] = s;
            }
        }
    }
    let output = GomoryHuOutput {
        root: (n > 0).then(|| graph.id(0).to_owned()),
        tree: (1..n as u32)
            .map(|node| {
                (
                    graph.id(node).to_owned(),
                    graph.id(parent[node as usize]).to_owned(),
                    value[node as usize],
                )
            })
            .collect(),
    };
    let (n64, m64) = (n as u64, graph.arc_count() as u64);
    let input = query_encoder(&IDENTITY, graph.digest());
    let peak = 12 * n64 + 16 * residual_edges as u64 + 9 * n64;
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
