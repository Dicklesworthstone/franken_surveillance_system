//! `ALG-SCC-001` — strongly connected components and their condensation.
//!
//! One iterative Tarjan search finds the components (unique for a graph); the condensation DAG
//! is then ordered by Kahn's algorithm with a min-heap keyed by each component's smallest member
//! index, so the reported component order is a topological order of the condensation that is
//! independent of the search order (`tie:smallest-member-identity-in-topological-condensation-order:v1`).
//! A component with two or more members is `cyclic` (self-loops are refused by the projection
//! policy, so a single member is never cyclic). The condensation is the safe planning
//! substrate: retry, obligation and identity cycles are collapsed explicitly, never ignored.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use fss_core::CanonicalEncoder;

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, encode_ids, mul,
};
use crate::graph::GraphError;
use crate::weighted::{Orientation, WeightedGraph};

/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-SCC-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.scc_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-SCC-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.scc_decision_path.v1";

/// Registered identity (`architecture/graph_algorithms.json`, `ALG-SCC-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-SCC-001",
    algorithm_name: "strongly_connected_components",
    tie_break_rule: "stable node identity within topological condensation order",
    complexity_witness: "edge scans and stack operations",
    output_size_witness: "<= |V| component labels and <= |E| condensation edges",
    exactness: "exact",
    implementation_id: "fss-graph-algorithms:alg-scc-001:iterative-tarjan-kahn-condensation:v1",
    tie_break_policy_id: "tie:smallest-member-identity-in-topological-condensation-order:v1",
    policy_id: "graph-policy:directed:simple-strict:weights-ignored:tie:smallest-member-identity-in-topological-condensation-order:v1",
    complexity_bound_id: "bound:alg-scc-001:tarjan-linear-plus-heap:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// The registered bound for `n` nodes and `m` arcs.
#[must_use]
pub fn bound(n: u64, m: u64) -> Vec<BoundRow> {
    vec![
        ("node_visits", n),
        ("arc_scans", mul(2, m)),
        ("stack_operations", mul(2, n)),
        ("heap_operations", mul(2, n)),
        ("condensation_arcs", m),
        (OUTPUT_ENTRIES, add(n, m)),
    ]
}

/// One strongly connected component.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Component {
    /// Position in the reported topological condensation order.
    pub label: u32,
    /// Members in ascending identity order.
    pub members: Vec<String>,
    /// Two or more members (a directed cycle exists inside).
    pub cyclic: bool,
}

/// The canonical answer of `ALG-SCC-001`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SccOutput {
    /// Components in topological condensation order (sources first).
    pub components: Vec<Component>,
    /// Condensation arcs `(from label, to label)`, ascending, without duplicates.
    pub condensation_arcs: Vec<(u32, u32)>,
}

impl SccOutput {
    /// Label of the component holding `node`.
    #[must_use]
    pub fn label_of(&self, node: &str) -> Option<u32> {
        self.components
            .iter()
            .find(|component| {
                component
                    .members
                    .binary_search_by(|member| member.as_str().cmp(node))
                    .is_ok()
            })
            .map(|component| component.label)
    }

    /// Components with a directed cycle inside.
    pub fn cyclic(&self) -> impl Iterator<Item = &Component> {
        self.components.iter().filter(|component| component.cyclic)
    }
}

impl CertifiedOutput for SccOutput {
    fn entries(&self) -> u64 {
        let members: usize = self.components.iter().map(|c| c.members.len()).sum();
        (members + self.condensation_arcs.len()) as u64
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.components.len() as u64);
        for component in &self.components {
            encoder.u32(component.label);
            encoder.bool(component.cyclic);
            encode_ids(encoder, &component.members);
        }
        encoder.u64(self.condensation_arcs.len() as u64);
        for &(from, to) in &self.condensation_arcs {
            encoder.u32(from);
            encoder.u32(to);
        }
    }
}

const UNSET: u32 = u32::MAX;

/// Runs `ALG-SCC-001` over a directed projection.
///
/// # Errors
///
/// [`GraphError::PreconditionFailed`] for an undirected projection,
/// [`GraphError::BudgetExhausted`] and [`GraphError::ComplexityBoundViolated`] fail closed.
pub fn strongly_connected_components(
    graph: &WeightedGraph,
    budget: Budget,
) -> Result<CertifiedRun<SccOutput>, GraphError> {
    graph.require_orientation(Orientation::Directed)?;
    let n = graph.node_count();
    let mut meter = Meter::new(&IDENTITY, budget);
    let mut index = vec![UNSET; n];
    let mut low = vec![UNSET; n];
    let mut on_stack = vec![false; n];
    let mut component_of = vec![UNSET; n];
    let mut scc_stack: Vec<u32> = Vec::new();
    let mut frames: Vec<(u32, usize)> = Vec::new();
    let mut counter = 0_u32;
    let mut finished = 0_u32;
    let mut max_frames = 0_usize;

    for start in 0..n as u32 {
        if index[start as usize] != UNSET {
            continue;
        }
        meter.tick("node_visits")?;
        index[start as usize] = counter;
        low[start as usize] = counter;
        counter += 1;
        meter.tick("stack_operations")?;
        scc_stack.push(start);
        on_stack[start as usize] = true;
        frames.push((start, 0));
        while let Some(&(v, cursor)) = frames.last() {
            let arcs = graph.out_arcs(v);
            if let Some(&arc) = arcs.get(cursor) {
                if let Some(frame) = frames.last_mut() {
                    frame.1 += 1;
                }
                meter.tick("arc_scans")?;
                let w = graph.arc(arc).head;
                if index[w as usize] == UNSET {
                    meter.tick("node_visits")?;
                    index[w as usize] = counter;
                    low[w as usize] = counter;
                    counter += 1;
                    meter.tick("stack_operations")?;
                    scc_stack.push(w);
                    on_stack[w as usize] = true;
                    frames.push((w, 0));
                    max_frames = max_frames.max(frames.len());
                } else if on_stack[w as usize] && index[w as usize] < low[v as usize] {
                    low[v as usize] = index[w as usize];
                }
            } else {
                frames.pop();
                if low[v as usize] == index[v as usize] {
                    while let Some(member) = scc_stack.pop() {
                        meter.tick("stack_operations")?;
                        on_stack[member as usize] = false;
                        component_of[member as usize] = finished;
                        if member == v {
                            break;
                        }
                    }
                    finished += 1;
                }
                if let Some(&(parent, _)) = frames.last()
                    && low[v as usize] < low[parent as usize]
                {
                    low[parent as usize] = low[v as usize];
                }
            }
        }
    }

    let c = finished as usize;
    let mut members: Vec<Vec<u32>> = vec![Vec::new(); c];
    for node in 0..n as u32 {
        members[component_of[node as usize] as usize].push(node);
    }
    let representative: Vec<u32> = members
        .iter()
        .map(|list| list.first().copied().unwrap_or(UNSET))
        .collect();
    let mut raw_arcs: Vec<(u32, u32)> = Vec::new();
    for arc in graph.arcs() {
        let (from, to) = (
            component_of[arc.tail as usize],
            component_of[arc.head as usize],
        );
        if from != to {
            raw_arcs.push((from, to));
        }
    }
    raw_arcs.sort_unstable();
    raw_arcs.dedup();
    let mut out: Vec<Vec<u32>> = vec![Vec::new(); c];
    let mut indegree = vec![0_u32; c];
    for &(from, to) in &raw_arcs {
        meter.tick("condensation_arcs")?;
        out[from as usize].push(to);
        indegree[to as usize] += 1;
    }
    let mut heap: BinaryHeap<Reverse<(u32, u32)>> = BinaryHeap::new();
    for component in 0..c as u32 {
        if indegree[component as usize] == 0 {
            meter.tick("heap_operations")?;
            heap.push(Reverse((representative[component as usize], component)));
        }
    }
    let mut label = vec![UNSET; c];
    let mut order: Vec<u32> = Vec::with_capacity(c);
    while let Some(Reverse((rep, component))) = heap.pop() {
        meter.tick("heap_operations")?;
        label[component as usize] = order.len() as u32;
        meter.decide(0, u64::from(rep), order.len() as u64);
        order.push(component);
        for &next in &out[component as usize] {
            meter.tick("arc_scans")?;
            indegree[next as usize] -= 1;
            if indegree[next as usize] == 0 {
                meter.tick("heap_operations")?;
                heap.push(Reverse((representative[next as usize], next)));
            }
        }
    }
    if order.len() != c {
        return Err(GraphError::Inconsistent(
            "the condensation of a graph must be acyclic".to_owned(),
        ));
    }
    let components: Vec<Component> = order
        .iter()
        .enumerate()
        .map(|(position, &component)| Component {
            label: position as u32,
            members: members[component as usize]
                .iter()
                .map(|&node| graph.id(node).to_owned())
                .collect(),
            cyclic: members[component as usize].len() >= 2,
        })
        .collect();
    let mut condensation_arcs: Vec<(u32, u32)> = raw_arcs
        .iter()
        .map(|&(from, to)| (label[from as usize], label[to as usize]))
        .collect();
    condensation_arcs.sort_unstable();
    let (n64, m64) = (n as u64, graph.arc_count() as u64);
    // index, low, component_of, label (4 bytes per node or component), on_stack (1 byte), the
    // search frames (12 bytes), the component stack and heap, and condensation arcs (8 bytes).
    let peak = n64 * 17 + 12 * max_frames as u64 + 8 * n64 + 16 * raw_arcs.len() as u64;
    meter.finish(
        &IDENTITY,
        InputShape {
            node_count: n64,
            edge_count: m64,
            input_digest: graph.digest(),
        },
        SccOutput {
            components,
            condensation_arcs,
        },
        &bound(n64, m64),
        peak,
    )
}
