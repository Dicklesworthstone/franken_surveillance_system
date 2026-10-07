//! `ALG-DOM-001` — dominators and post-dominators.
//!
//! Node `d` dominates `v` (from root `r`) when every directed path from `r` to `v` passes
//! through `d`; post-dominance is dominance in the reversed projection from a declared exit.
//! The dominator tree is unique, so the answer is too; the implementation is the iterative
//! Cooper–Harvey–Kennedy algorithm over the reverse postorder of a depth-first search that scans
//! arcs in ascending (neighbour, arc) order.
//!
//! Decision role: a claim, alert or completion dominated by a single sensor, gateway, verifier or
//! plan step depends on that one failure domain on every path; one supported through independent
//! paths does not. Each dominating node is reported with the exact number of nodes it dominates.
//! Nodes unreachable from the root are listed, never silently dropped.

use fss_core::CanonicalEncoder;

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, encode_ids, mul, query_digest, query_encoder,
};
use crate::graph::GraphError;
use crate::weighted::{Orientation, WeightedGraph};

/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-DOM-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.dom_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-DOM-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.dom_decision_path.v1";

/// Registered identity (`ALG-DOM-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-DOM-001",
    algorithm_name: "dominators_and_postdominators",
    tie_break_rule: "stable predecessor and node identity",
    complexity_witness: "intersections and frontier updates",
    output_size_witness: "<= |V| immediate dominator relationships",
    exactness: "exact",
    implementation_id: "fss-graph-algorithms:alg-dom-001:cooper-harvey-kennedy:v1",
    tie_break_policy_id: "tie:ascending-neighbour-then-arc-dfs-reverse-postorder:v1",
    policy_id: "graph-policy:directed:simple-strict:weights-ignored:declared-root-or-exit:tie:ascending-neighbour-then-arc-dfs-reverse-postorder:v1",
    complexity_bound_id: "bound:alg-dom-001:chk-passes-n-plus-3:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// The registered bound for `n` nodes and `m` arcs.
#[must_use]
pub fn bound(n: u64, m: u64) -> Vec<BoundRow> {
    let passes = add(n, 3);
    vec![
        ("node_visits", n),
        ("passes", passes),
        ("arc_scans", add(m, mul(passes, m))),
        ("intersect_steps", mul(mul(passes, m), mul(2, n))),
        ("tree_steps", mul(2, n)),
        (OUTPUT_ENTRIES, mul(3, n)),
    ]
}

/// Dominators from a root, or post-dominators to an exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DominanceDirection {
    /// Every path from the root to `v` passes through `d`.
    Dominators,
    /// Every path from `v` to the exit passes through `d`.
    PostDominators,
}

impl DominanceDirection {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dominators => "dominators",
            Self::PostDominators => "post_dominators",
        }
    }
}

/// The canonical answer of `ALG-DOM-001`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DominanceOutput {
    /// Direction.
    pub direction: DominanceDirection,
    /// Root (dominators) or exit (post-dominators).
    pub root: String,
    /// `(node, immediate dominator)` for every node reachable from (reaching) the root other
    /// than the root, in ascending node identity order.
    pub immediate_dominators: Vec<(String, String)>,
    /// Nodes not reachable from (not reaching) the root, ascending.
    pub unreachable: Vec<String>,
    /// `(node, number of other nodes it dominates)` for every node dominating at least one
    /// other node, ascending.
    pub dominance: Vec<(String, u64)>,
}

impl DominanceOutput {
    /// The dominator chain of `node` from the root down to `node` (inclusive), or `None` when
    /// `node` is unreachable or unknown.
    #[must_use]
    pub fn chain(&self, node: &str) -> Option<Vec<String>> {
        let mut chain = vec![node.to_owned()];
        let mut current = node.to_owned();
        while current != self.root {
            let position = self
                .immediate_dominators
                .binary_search_by(|(member, _)| member.as_str().cmp(&current))
                .ok()?;
            current = self.immediate_dominators[position].1.clone();
            chain.push(current.clone());
            if chain.len() > self.immediate_dominators.len() + 1 {
                return None;
            }
        }
        chain.reverse();
        Some(chain)
    }
}

impl CertifiedOutput for DominanceOutput {
    fn entries(&self) -> u64 {
        (self.immediate_dominators.len() + self.unreachable.len() + self.dominance.len()) as u64
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.direction.as_str());
        encoder.text(&self.root);
        encoder.u64(self.immediate_dominators.len() as u64);
        for (node, idom) in &self.immediate_dominators {
            encoder.text(node);
            encoder.text(idom);
        }
        encode_ids(encoder, &self.unreachable);
        encoder.u64(self.dominance.len() as u64);
        for (node, count) in &self.dominance {
            encoder.text(node);
            encoder.u64(*count);
        }
    }
}

const UNSET: u32 = u32::MAX;

/// Runs `ALG-DOM-001` over a directed projection from `root` (dominators) or to `root`
/// (post-dominators, the exit).
///
/// # Errors
///
/// [`GraphError::UnknownNode`] for an unknown root, [`GraphError::PreconditionFailed`] for an
/// undirected projection, and the fail-closed budget and bound errors.
pub fn dominators(
    graph: &WeightedGraph,
    root: &str,
    direction: DominanceDirection,
    budget: Budget,
) -> Result<CertifiedRun<DominanceOutput>, GraphError> {
    graph.require_orientation(Orientation::Directed)?;
    let root_index = graph.require(root)?;
    let n = graph.node_count();
    let mut meter = Meter::new(&IDENTITY, budget);
    let forward = direction == DominanceDirection::Dominators;
    let successors = |node: u32| -> Vec<u32> {
        if forward {
            graph
                .out_arcs(node)
                .iter()
                .map(|&a| graph.arc(a).head)
                .collect()
        } else {
            graph
                .in_arcs(node)
                .iter()
                .map(|&a| graph.arc(a).tail)
                .collect()
        }
    };
    let predecessors = |node: u32| -> Vec<u32> {
        if forward {
            graph
                .in_arcs(node)
                .iter()
                .map(|&a| graph.arc(a).tail)
                .collect()
        } else {
            graph
                .out_arcs(node)
                .iter()
                .map(|&a| graph.arc(a).head)
                .collect()
        }
    };

    // Depth-first postorder from the root.
    let mut postorder_number = vec![UNSET; n];
    let mut visited = vec![false; n];
    let mut postorder: Vec<u32> = Vec::new();
    let mut frames: Vec<(u32, Vec<u32>, usize)> = Vec::new();
    meter.tick("node_visits")?;
    visited[root_index as usize] = true;
    frames.push((root_index, successors(root_index), 0));
    let mut max_frames = 1_usize;
    while let Some(frame) = frames.last_mut() {
        if let Some(&next) = frame.1.get(frame.2) {
            frame.2 += 1;
            meter.tick("arc_scans")?;
            if !visited[next as usize] {
                meter.tick("node_visits")?;
                visited[next as usize] = true;
                let list = successors(next);
                frames.push((next, list, 0));
                max_frames = max_frames.max(frames.len());
            }
        } else {
            let node = frame.0;
            frames.pop();
            postorder_number[node as usize] = postorder.len() as u32;
            postorder.push(node);
        }
    }
    let reverse_postorder: Vec<u32> = postorder.iter().rev().copied().collect();

    let mut idom = vec![UNSET; n];
    idom[root_index as usize] = root_index;
    let mut changed = true;
    while changed {
        meter.tick("passes")?;
        changed = false;
        for &node in reverse_postorder.iter().skip(1) {
            let mut new_idom = UNSET;
            for pred in predecessors(node) {
                meter.tick("arc_scans")?;
                if idom[pred as usize] == UNSET {
                    continue;
                }
                if new_idom == UNSET {
                    new_idom = pred;
                    continue;
                }
                let (mut a, mut b) = (pred, new_idom);
                while a != b {
                    while postorder_number[a as usize] < postorder_number[b as usize] {
                        meter.tick("intersect_steps")?;
                        a = idom[a as usize];
                    }
                    while postorder_number[b as usize] < postorder_number[a as usize] {
                        meter.tick("intersect_steps")?;
                        b = idom[b as usize];
                    }
                }
                new_idom = a;
            }
            if new_idom != UNSET && idom[node as usize] != new_idom {
                idom[node as usize] = new_idom;
                meter.decide(0, u64::from(node), u64::from(new_idom));
                changed = true;
            }
        }
    }

    // Subtree sizes of the dominator tree (children before parents in postorder).
    let mut subtree = vec![1_u64; n];
    for &node in &postorder {
        meter.tick("tree_steps")?;
        if node != root_index {
            let parent = idom[node as usize];
            subtree[parent as usize] += subtree[node as usize];
        }
    }
    let mut immediate_dominators = Vec::new();
    let mut unreachable = Vec::new();
    let mut dominance = Vec::new();
    for node in 0..n as u32 {
        meter.tick("tree_steps")?;
        if !visited[node as usize] {
            unreachable.push(graph.id(node).to_owned());
            continue;
        }
        if node != root_index {
            immediate_dominators.push((
                graph.id(node).to_owned(),
                graph.id(idom[node as usize]).to_owned(),
            ));
        }
        if subtree[node as usize] > 1 {
            dominance.push((graph.id(node).to_owned(), subtree[node as usize] - 1));
        }
    }
    let output = DominanceOutput {
        direction,
        root: root.to_owned(),
        immediate_dominators,
        unreachable,
        dominance,
    };
    let (n64, m64) = (n as u64, graph.arc_count() as u64);
    let mut input = query_encoder(&IDENTITY, graph.digest());
    input.text(direction.as_str());
    input.text(root);
    // postorder number, idom (4 bytes), visited (1), subtree (8), postorder lists (8), frames.
    let peak = n64 * (4 + 4 + 1 + 8 + 8) + 32 * max_frames as u64 + 4 * m64;
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
