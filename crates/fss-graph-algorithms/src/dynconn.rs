//! `ALG-DYNCONN-001` — exact connectivity under a pinned sequence of edge-update batches.
//!
//! State `0` is the undirected projection itself; state `e` (for `e` in `1..=E`) is the result
//! of applying update batches `1..=e` in order. Updates are strict: inserting a present edge or
//! deleting an absent one is a precondition failure naming the batch, never silently merged.
//! For every state the run reports the exact number of connected components, and it answers
//! every connectivity query `(state, a, b)`.
//!
//! Offline method: every edge lifetime (a maximal state interval during which the edge exists)
//! is assigned to `O(log S)` nodes of a segment tree over the `S = E + 1` states; a depth-first
//! traversal applies those unions on entry and rolls them back on exit, using a union-find with
//! union by size and no path compression, so every find is at most `floor(log2 n) + 1` steps and
//! the bound is a hard worst case. Queries are canonical: `(state, lower, higher)` ascending with
//! duplicates removed; a query of a node with itself is trivially connected.

use fss_core::CanonicalEncoder;

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, mul, query_digest, query_encoder,
};
use crate::graph::GraphError;
use crate::spanning::{UnionFind, ceil_log2, find_depth};
use crate::weighted::{Orientation, WeightedGraph};

/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-DYNCONN-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.dynconn_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-DYNCONN-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.dynconn_decision_path.v1";
/// Maximum update batches of one query.
pub const MAX_BATCHES: usize = 1 << 16;

/// Registered identity (`ALG-DYNCONN-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-DYNCONN-001",
    algorithm_name: "dynamic_connectivity",
    tie_break_rule: "stable node identity then insertion order",
    complexity_witness: "union/find or dynamic-forest operations",
    output_size_witness: "<= |V| component labels",
    exactness: "exact",
    implementation_id: "fss-graph-algorithms:alg-dynconn-001:offline-segment-tree-rollback-union-find:v1",
    tie_break_policy_id: "tie:canonical-edge-then-batch-order-union-by-size-larger-root:v1",
    policy_id: "graph-policy:undirected:simple-strict:strict-insert-delete-batches:weights-ignored:tie:canonical-edge-then-batch-order-union-by-size-larger-root:v1",
    complexity_bound_id: "bound:alg-dynconn-001:segment-tree-2-log-s-per-lifetime:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// The registered bound for `n` nodes, `lifetimes` edge lifetimes, `states` states and `queries`
/// canonical queries.
#[must_use]
pub fn bound(n: u64, lifetimes: u64, states: u64, queries: u64) -> Vec<BoundRow> {
    let per_lifetime = add(mul(2, ceil_log2(states)), 2);
    let assignments = mul(lifetimes, per_lifetime);
    vec![
        ("segment_assignments", assignments),
        ("unions", assignments),
        ("rollbacks", assignments),
        (
            "find_steps",
            mul(mul(2, add(assignments, queries)), find_depth(n)),
        ),
        ("tree_visits", mul(4, states)),
        (OUTPUT_ENTRIES, add(states, queries)),
    ]
}

/// One edge update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EdgeUpdate {
    /// Insert an absent edge.
    Insert(String, String),
    /// Delete a present edge.
    Delete(String, String),
}

/// The canonical answer of `ALG-DYNCONN-001`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicConnectivityOutput {
    /// Connected components of every state `0..=E`.
    pub component_counts: Vec<u64>,
    /// `(state, lower, higher, connected)` in canonical order.
    pub answers: Vec<(u32, String, String, bool)>,
}

impl CertifiedOutput for DynamicConnectivityOutput {
    fn entries(&self) -> u64 {
        (self.component_counts.len() + self.answers.len()) as u64
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.component_counts.len() as u64);
        for &count in &self.component_counts {
            encoder.u64(count);
        }
        encoder.u64(self.answers.len() as u64);
        for (state, a, b, connected) in &self.answers {
            encoder.u32(*state);
            encoder.text(a);
            encoder.text(b);
            encoder.bool(*connected);
        }
    }
}

/// Edge lifetimes `(first state, last state, lower, higher)` of a strict update sequence.
type Lifetime = (u32, u32, u32, u32);

fn lifetimes(
    graph: &WeightedGraph,
    batches: &[Vec<EdgeUpdate>],
) -> Result<Vec<Lifetime>, GraphError> {
    let mut open: std::collections::BTreeMap<(u32, u32), u32> = graph
        .arcs()
        .iter()
        .map(|arc| ((arc.tail, arc.head), 0))
        .collect();
    let mut closed = Vec::new();
    for (position, batch) in batches.iter().enumerate() {
        let state = position as u32 + 1;
        for update in batch {
            let (a, b, insert) = match update {
                EdgeUpdate::Insert(a, b) => (a, b, true),
                EdgeUpdate::Delete(a, b) => (a, b, false),
            };
            let (x, y) = (graph.require(a)?, graph.require(b)?);
            if x == y {
                return Err(GraphError::SelfLoop(a.clone()));
            }
            let key = (x.min(y), x.max(y));
            match (insert, open.get(&key).copied()) {
                (true, None) => {
                    open.insert(key, state);
                }
                (false, Some(first)) => {
                    open.remove(&key);
                    if first < state {
                        closed.push((first, state - 1, key.0, key.1));
                    }
                }
                (true, Some(_)) => {
                    return Err(GraphError::PreconditionFailed(format!(
                        "batch {state} inserts the present edge {a} -- {b}"
                    )));
                }
                (false, None) => {
                    return Err(GraphError::PreconditionFailed(format!(
                        "batch {state} deletes the absent edge {a} -- {b}"
                    )));
                }
            }
        }
    }
    let last = batches.len() as u32;
    for ((x, y), first) in open {
        closed.push((first, last, x, y));
    }
    closed.sort_unstable();
    Ok(closed)
}

/// Runs `ALG-DYNCONN-001` over the undirected projection `graph` (state 0) and `batches`.
///
/// # Errors
///
/// [`GraphError::PreconditionFailed`] for a directed projection, an invalid update or a query
/// state outside `0..=E`; [`GraphError::UnknownNode`]; and the fail-closed budget and bound
/// errors.
pub fn dynamic_connectivity(
    graph: &WeightedGraph,
    batches: &[Vec<EdgeUpdate>],
    queries: &[(u32, &str, &str)],
    budget: Budget,
) -> Result<CertifiedRun<DynamicConnectivityOutput>, GraphError> {
    graph.require_orientation(Orientation::Undirected)?;
    if batches.len() > MAX_BATCHES {
        return Err(GraphError::TooLarge);
    }
    let n = graph.node_count();
    let states = batches.len() + 1;
    let all = lifetimes(graph, batches)?;
    let mut canonical: Vec<(u32, u32, u32)> = Vec::with_capacity(queries.len());
    for &(state, a, b) in queries {
        if state as usize >= states {
            return Err(GraphError::PreconditionFailed(format!(
                "query state {state} is outside 0..={}",
                states - 1
            )));
        }
        let (x, y) = (graph.require(a)?, graph.require(b)?);
        canonical.push((state, x.min(y), x.max(y)));
    }
    canonical.sort_unstable();
    canonical.dedup();
    let mut meter = Meter::new(&IDENTITY, budget);
    // Segment tree over states [0, states): node 1 covers everything; children 2i, 2i + 1.
    let size = states.next_power_of_two();
    let mut segments: Vec<Vec<(u32, u32)>> = vec![Vec::new(); 2 * size];
    for &(first, last, x, y) in &all {
        let (mut lo, mut hi) = (first as usize + size, last as usize + size + 1);
        while lo < hi {
            if lo & 1 == 1 {
                meter.tick("segment_assignments")?;
                segments[lo].push((x, y));
                lo += 1;
            }
            if hi & 1 == 1 {
                hi -= 1;
                meter.tick("segment_assignments")?;
                segments[hi].push((x, y));
            }
            lo /= 2;
            hi /= 2;
        }
    }
    let mut sets = UnionFind::new(n);
    let mut components = n as u64;
    let mut component_counts = vec![0_u64; states];
    let mut answers: Vec<(u32, String, String, bool)> = Vec::with_capacity(canonical.len());
    let mut next_query = 0_usize;
    // Iterative traversal: (segment node, entered?), with a rollback log per entered node.
    let mut stack: Vec<(usize, bool, usize)> = vec![(1, false, 0)];
    let mut log: Vec<(u32, u32)> = Vec::new();
    while let Some((node, entered, mark)) = stack.pop() {
        if entered {
            while log.len() > mark {
                if let Some((big, small)) = log.pop() {
                    meter.tick("rollbacks")?;
                    sets.split(big, small);
                    components += 1;
                }
            }
            continue;
        }
        meter.tick("tree_visits")?;
        let mark = log.len();
        for &(x, y) in &segments[node] {
            let (a, b) = (sets.find(x, &mut meter)?, sets.find(y, &mut meter)?);
            if a != b {
                meter.tick("unions")?;
                log.push(sets.join(a, b));
                components -= 1;
            }
        }
        stack.push((node, true, mark));
        if node >= size {
            let state = node - size;
            if state < states {
                component_counts[state] = components;
                meter.decide(0, state as u64, components);
                while next_query < canonical.len() && canonical[next_query].0 as usize == state {
                    let (_, x, y) = canonical[next_query];
                    let connected =
                        x == y || sets.find(x, &mut meter)? == sets.find(y, &mut meter)?;
                    answers.push((
                        state as u32,
                        graph.id(x).to_owned(),
                        graph.id(y).to_owned(),
                        connected,
                    ));
                    next_query += 1;
                }
            }
        } else {
            let (left_lo, right_lo) = (2 * node, 2 * node + 1);
            // Visit the left child first (pushed last).
            let covered_from = |segment: usize| {
                let mut segment = segment;
                while segment < size {
                    segment *= 2;
                }
                segment - size
            };
            if covered_from(right_lo) < states {
                stack.push((right_lo, false, 0));
            }
            stack.push((left_lo, false, 0));
        }
    }
    let output = DynamicConnectivityOutput {
        component_counts,
        answers,
    };
    let n64 = n as u64;
    let lifetimes64 = all.len() as u64;
    let mut input = query_encoder(&IDENTITY, graph.digest());
    input.u64(batches.len() as u64);
    for batch in batches {
        input.u64(batch.len() as u64);
        for update in batch {
            let (tag, a, b) = match update {
                EdgeUpdate::Insert(a, b) => (0, a, b),
                EdgeUpdate::Delete(a, b) => (1, a, b),
            };
            input.tag(tag);
            input.text(a);
            input.text(b);
        }
    }
    input.u64(canonical.len() as u64);
    for &(state, x, y) in &canonical {
        input.u32(state);
        input.text(graph.id(x));
        input.text(graph.id(y));
    }
    let peak =
        8 * n64 + 8 * lifetimes64 * (add(mul(2, ceil_log2(states as u64)), 2)) + 16 * size as u64;
    meter.finish(
        &IDENTITY,
        InputShape {
            node_count: n64,
            edge_count: graph.arc_count() as u64,
            input_digest: query_digest(input),
        },
        output,
        &bound(n64, lifetimes64, states as u64, canonical.len() as u64),
        peak,
    )
}
