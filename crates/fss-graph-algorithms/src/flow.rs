//! `ALG-FLOW-001` — maximum flow and minimum cut, over arcs or failing nodes.
//!
//! Exact Edmonds–Karp over `u64` capacities in the projection's unit. Two cut modes share one
//! residual engine and one registered identity:
//!
//! * [`CutMode::Arcs`]: arc (edge) capacities; the answer is the maximum flow value, one maximum
//!   flow, and the inclusion-minimal minimum cut (the source side is every node reachable from
//!   the source in the final residual network, which is the same for every maximum flow);
//! * [`CutMode::Nodes`]: node weights are failure costs (use `1` per node to count nodes) and
//!   arcs are unbounded; the answer is a minimum-weight set of intermediate nodes whose loss
//!   disconnects the sink from the source (Menger by node splitting), or `separable: false` when
//!   source and sink are adjacent and no node failure can separate them.
//!
//! The run certifies its own answer before returning it: flow conservation and capacity hold on
//! every arc, and the cut's capacity equals the flow value (max-flow = min-cut). A certificate
//! mismatch is `ERR-GRAPH-RESULT-INCONSISTENT-001`; nothing is returned. The tie-break is the
//! stable residual-edge identity: residual edges are created in canonical arc order (forward
//! before reverse) and every breadth-first search scans them in that order.

use std::collections::VecDeque;

use fss_core::CanonicalEncoder;

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, checked_add, encode_ids, mul, query_digest, query_encoder,
};
use crate::graph::GraphError;
use crate::weighted::{Orientation, WeightedGraph};

/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-FLOW-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.flow_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-FLOW-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.flow_decision_path.v1";

/// Registered identity (`ALG-FLOW-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-FLOW-001",
    algorithm_name: "max_flow_min_cut",
    tie_break_rule: "stable residual-edge identity",
    complexity_witness: "residual scans and augmentations",
    output_size_witness: "<= |E| edge flows and <= |V| cut partition flags",
    exactness: "exact",
    implementation_id: "fss-graph-algorithms:alg-flow-001:edmonds-karp-certified-cut:v1",
    tie_break_policy_id: "tie:canonical-arc-order-residual-edges-forward-before-reverse:v1",
    policy_id: "graph-policy:directed-or-undirected:simple-strict:arc-capacity-or-node-failure-weight:numeric:u64-exact:checked:unit-bound:v1:tie:canonical-arc-order-residual-edges-forward-before-reverse:v1",
    complexity_bound_id: "bound:alg-flow-001:edmonds-karp-vp-augmentations:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// The registered bound for `n` nodes and `m` arcs, valid for both modes and orientations:
/// at most `P = 2m + n` residual pairs over `N = 2n` residual nodes, at most `P * N + 1`
/// augmentations, `2P` residual scans per search, and `2N` path steps per augmentation.
#[must_use]
pub fn bound(n: u64, m: u64) -> Vec<BoundRow> {
    let pairs = add(mul(2, m), n);
    let nodes = mul(2, n);
    let augmentations = add(mul(pairs, nodes), 1);
    vec![
        ("augmentations", augmentations),
        ("residual_scans", mul(add(augmentations, 1), mul(2, pairs))),
        ("path_steps", mul(augmentations, mul(2, nodes))),
        ("certificate_checks", add(mul(2, m), mul(2, n))),
        (OUTPUT_ENTRIES, add(mul(2, m), mul(2, n))),
    ]
}

/// What a cut removes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CutMode {
    /// Arc capacities; minimum arc cut.
    Arcs,
    /// Node failure weights; minimum node (vertex) cut.
    Nodes,
}

impl CutMode {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Arcs => "arcs",
            Self::Nodes => "nodes",
        }
    }
}

/// A maximum flow and minimum arc cut.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArcCutOutput {
    /// Source.
    pub source: String,
    /// Sink.
    pub sink: String,
    /// Maximum flow value = minimum cut capacity.
    pub value: u64,
    /// `(tail, head, amount)` of every arc carrying flow (net direction for an undirected edge),
    /// in canonical arc order.
    pub flows: Vec<(String, String, u64)>,
    /// Inclusion-minimal source side of the minimum cut, ascending.
    pub source_side: Vec<String>,
    /// `(tail, head, capacity)` of every cut arc (an undirected edge as `(lower, higher)`), in
    /// canonical arc order.
    pub cut: Vec<(String, String, u64)>,
}

/// A minimum-weight node failure set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCutOutput {
    /// Source.
    pub source: String,
    /// Sink.
    pub sink: String,
    /// False when source and sink are adjacent: no node failure separates them.
    pub separable: bool,
    /// Total failure weight of the set (zero when inseparable).
    pub failure_weight: u64,
    /// The failing nodes, ascending (empty when inseparable).
    pub failure_set: Vec<String>,
    /// Nodes still connected to the source after the failure set is removed, ascending.
    pub source_side: Vec<String>,
}

/// The canonical answer of `ALG-FLOW-001`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowOutput {
    /// [`CutMode::Arcs`].
    Arcs(ArcCutOutput),
    /// [`CutMode::Nodes`].
    Nodes(NodeCutOutput),
}

fn encode_triples(encoder: &mut CanonicalEncoder, values: &[(String, String, u64)]) {
    encoder.u64(values.len() as u64);
    for (a, b, amount) in values {
        encoder.text(a);
        encoder.text(b);
        encoder.u64(*amount);
    }
}

impl CertifiedOutput for FlowOutput {
    fn entries(&self) -> u64 {
        match self {
            Self::Arcs(answer) => {
                (answer.flows.len() + answer.source_side.len() + answer.cut.len()) as u64
            }
            Self::Nodes(answer) => (answer.failure_set.len() + answer.source_side.len()) as u64,
        }
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::Arcs(answer) => {
                encoder.tag(0);
                encoder.text(&answer.source);
                encoder.text(&answer.sink);
                encoder.u64(answer.value);
                encode_triples(encoder, &answer.flows);
                encode_ids(encoder, &answer.source_side);
                encode_triples(encoder, &answer.cut);
            }
            Self::Nodes(answer) => {
                encoder.tag(1);
                encoder.text(&answer.source);
                encoder.text(&answer.sink);
                encoder.bool(answer.separable);
                encoder.u64(answer.failure_weight);
                encode_ids(encoder, &answer.failure_set);
                encode_ids(encoder, &answer.source_side);
            }
        }
    }
}

/// A residual network: edge `e` and its reverse `e ^ 1`.
#[derive(Clone, Debug)]
pub(crate) struct Residual {
    to: Vec<u32>,
    capacity: Vec<u64>,
    adjacency: Vec<Vec<u32>>,
}

impl Residual {
    pub(crate) fn new(nodes: usize) -> Self {
        Self {
            to: Vec::new(),
            capacity: Vec::new(),
            adjacency: vec![Vec::new(); nodes],
        }
    }

    /// Adds `u -> v` with `capacity` (and its zero reverse); returns the forward edge.
    pub(crate) fn add(&mut self, u: u32, v: u32, capacity: u64) -> u32 {
        let forward = self.to.len() as u32;
        self.to.push(v);
        self.capacity.push(capacity);
        self.adjacency[u as usize].push(forward);
        self.to.push(u);
        self.capacity.push(0);
        self.adjacency[v as usize].push(forward + 1);
        forward
    }

    /// Residual capacity of edge `edge`.
    pub(crate) fn remaining(&self, edge: u32) -> u64 {
        self.capacity[edge as usize]
    }

    /// Residual edges counted for working-byte accounting.
    pub(crate) fn edges(&self) -> usize {
        self.to.len()
    }

    /// Edmonds–Karp from `source` to `sink`, stopping once the value reaches `stop_at`.
    pub(crate) fn max_flow(
        &mut self,
        source: u32,
        sink: u32,
        stop_at: Option<u64>,
        meter: &mut Meter,
    ) -> Result<u64, GraphError> {
        let nodes = self.adjacency.len();
        let mut value = 0_u64;
        loop {
            if stop_at.is_some_and(|limit| value >= limit) {
                return Ok(value);
            }
            let mut parent_edge = vec![u32::MAX; nodes];
            let mut seen = vec![false; nodes];
            seen[source as usize] = true;
            let mut queue = VecDeque::from([source]);
            'search: while let Some(u) = queue.pop_front() {
                for &edge in &self.adjacency[u as usize] {
                    meter.tick("residual_scans")?;
                    let v = self.to[edge as usize];
                    if !seen[v as usize] && self.capacity[edge as usize] > 0 {
                        seen[v as usize] = true;
                        parent_edge[v as usize] = edge;
                        if v == sink {
                            break 'search;
                        }
                        queue.push_back(v);
                    }
                }
            }
            if !seen[sink as usize] {
                return Ok(value);
            }
            meter.tick("augmentations")?;
            let mut bottleneck = u64::MAX;
            let mut node = sink;
            while node != source {
                meter.tick("path_steps")?;
                let edge = parent_edge[node as usize];
                bottleneck = bottleneck.min(self.capacity[edge as usize]);
                node = self.to[(edge ^ 1) as usize];
            }
            let mut node = sink;
            while node != source {
                meter.tick("path_steps")?;
                let edge = parent_edge[node as usize];
                self.capacity[edge as usize] -= bottleneck;
                self.capacity[(edge ^ 1) as usize] = checked_add(
                    self.capacity[(edge ^ 1) as usize],
                    bottleneck,
                    "residual capacity",
                )?;
                node = self.to[(edge ^ 1) as usize];
            }
            meter.decide(0, u64::from(parent_edge[sink as usize]), bottleneck);
            value = checked_add(value, bottleneck, "flow value")?;
        }
    }

    /// Nodes reachable from `source` through positive residual capacity.
    pub(crate) fn reachable(
        &self,
        source: u32,
        meter: &mut Meter,
    ) -> Result<Vec<bool>, GraphError> {
        let mut seen = vec![false; self.adjacency.len()];
        seen[source as usize] = true;
        let mut queue = VecDeque::from([source]);
        while let Some(u) = queue.pop_front() {
            for &edge in &self.adjacency[u as usize] {
                meter.tick("residual_scans")?;
                let v = self.to[edge as usize];
                if !seen[v as usize] && self.capacity[edge as usize] > 0 {
                    seen[v as usize] = true;
                    queue.push_back(v);
                }
            }
        }
        Ok(seen)
    }
}

/// Runs `ALG-FLOW-001` from `source` to `sink` in `mode`.
///
/// # Errors
///
/// [`GraphError::UnknownNode`], [`GraphError::PreconditionFailed`] when source equals sink,
/// [`GraphError::ArithmeticOverflow`] for a flow or capacity sum outside `u64`,
/// [`GraphError::Inconsistent`] when the max-flow/min-cut certificate fails, and the fail-closed
/// budget and bound errors.
pub fn max_flow_min_cut(
    graph: &WeightedGraph,
    source: &str,
    sink: &str,
    mode: CutMode,
    budget: Budget,
) -> Result<CertifiedRun<FlowOutput>, GraphError> {
    let s = graph.require(source)?;
    let t = graph.require(sink)?;
    if s == t {
        return Err(GraphError::PreconditionFailed(
            "a cut needs distinct source and sink".to_owned(),
        ));
    }
    let mut meter = Meter::new(&IDENTITY, budget);
    let (output, residual_edges) = match mode {
        CutMode::Arcs => arc_cut(graph, s, t, &mut meter)?,
        CutMode::Nodes => node_cut(graph, s, t, &mut meter)?,
    };
    let (n64, m64) = (graph.node_count() as u64, graph.arc_count() as u64);
    let mut input = query_encoder(&IDENTITY, graph.digest());
    input.text(mode.as_str());
    input.text(source);
    input.text(sink);
    // to (4), capacity (8) per residual edge; adjacency (4) per edge; parent, seen, queue per
    // residual node (2n of them, 4 + 1 + 4 bytes).
    let peak = 16 * residual_edges as u64 + 2 * n64 * 9;
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

fn arc_cut(
    graph: &WeightedGraph,
    s: u32,
    t: u32,
    meter: &mut Meter,
) -> Result<(FlowOutput, usize), GraphError> {
    let n = graph.node_count();
    let mut residual = Residual::new(n);
    let mut forward: Vec<(u32, Option<u32>)> = Vec::with_capacity(graph.arc_count());
    for arc in graph.arcs() {
        let first = residual.add(arc.tail, arc.head, arc.weight);
        let second = match graph.orientation() {
            Orientation::Directed => None,
            Orientation::Undirected => Some(residual.add(arc.head, arc.tail, arc.weight)),
        };
        forward.push((first, second));
    }
    let value = residual.max_flow(s, t, None, meter)?;
    let side = residual.reachable(s, meter)?;
    if side[t as usize] {
        return Err(GraphError::Inconsistent(
            "the sink is reachable after a maximum flow".to_owned(),
        ));
    }
    let mut flows = Vec::new();
    let mut cut = Vec::new();
    let mut cut_capacity = 0_u64;
    let mut balance = vec![0_i128; n];
    for (index, arc) in graph.arcs().iter().enumerate() {
        meter.tick("certificate_checks")?;
        let (first, second) = forward[index];
        let along = arc.weight - residual.remaining(first);
        let against = second.map_or(0, |edge| arc.weight - residual.remaining(edge));
        let (tail, head, amount) = if along >= against {
            (arc.tail, arc.head, along - against)
        } else {
            (arc.head, arc.tail, against - along)
        };
        if amount > 0 {
            flows.push((graph.id(tail).to_owned(), graph.id(head).to_owned(), amount));
            balance[tail as usize] -= i128::from(amount);
            balance[head as usize] += i128::from(amount);
        }
        let crosses = match graph.orientation() {
            Orientation::Directed => side[arc.tail as usize] && !side[arc.head as usize],
            Orientation::Undirected => side[arc.tail as usize] != side[arc.head as usize],
        };
        if crosses {
            cut_capacity = checked_add(cut_capacity, arc.weight, "cut capacity")?;
            cut.push((
                graph.id(arc.tail).to_owned(),
                graph.id(arc.head).to_owned(),
                arc.weight,
            ));
        }
    }
    for node in 0..n as u32 {
        meter.tick("certificate_checks")?;
        let expected = if node == s {
            -i128::from(value)
        } else if node == t {
            i128::from(value)
        } else {
            0
        };
        if balance[node as usize] != expected {
            return Err(GraphError::Inconsistent(format!(
                "flow conservation fails at {}",
                graph.id(node)
            )));
        }
    }
    if cut_capacity != value {
        return Err(GraphError::Inconsistent(format!(
            "cut capacity {cut_capacity} differs from flow value {value}"
        )));
    }
    let source_side = (0..n as u32)
        .filter(|&node| side[node as usize])
        .map(|node| graph.id(node).to_owned())
        .collect();
    Ok((
        FlowOutput::Arcs(ArcCutOutput {
            source: graph.id(s).to_owned(),
            sink: graph.id(t).to_owned(),
            value,
            flows,
            source_side,
            cut,
        }),
        residual.edges(),
    ))
}

fn node_cut(
    graph: &WeightedGraph,
    s: u32,
    t: u32,
    meter: &mut Meter,
) -> Result<(FlowOutput, usize), GraphError> {
    let n = graph.node_count();
    let infinite = checked_add(
        graph
            .total_node_weight()
            .ok_or(GraphError::ArithmeticOverflow("total failure weight"))?,
        1,
        "total failure weight",
    )?;
    let inside = |node: u32| 2 * node;
    let outside = |node: u32| 2 * node + 1;
    let mut residual = Residual::new(2 * n);
    for node in 0..n as u32 {
        let capacity = if node == s || node == t {
            infinite
        } else {
            graph.node_weight(node)
        };
        residual.add(inside(node), outside(node), capacity);
    }
    for arc in graph.arcs() {
        residual.add(outside(arc.tail), inside(arc.head), infinite);
        if graph.orientation() == Orientation::Undirected {
            residual.add(outside(arc.head), inside(arc.tail), infinite);
        }
    }
    let value = residual.max_flow(outside(s), inside(t), Some(infinite), meter)?;
    let source_side_nodes: Vec<String>;
    let answer = if value >= infinite {
        let side = residual.reachable(outside(s), meter)?;
        source_side_nodes = (0..n as u32)
            .filter(|&node| side[outside(node) as usize])
            .map(|node| graph.id(node).to_owned())
            .collect();
        NodeCutOutput {
            source: graph.id(s).to_owned(),
            sink: graph.id(t).to_owned(),
            separable: false,
            failure_weight: 0,
            failure_set: Vec::new(),
            source_side: source_side_nodes,
        }
    } else {
        let side = residual.reachable(outside(s), meter)?;
        if side[inside(t) as usize] {
            return Err(GraphError::Inconsistent(
                "the sink is reachable after a maximum flow".to_owned(),
            ));
        }
        let mut failure_set = Vec::new();
        let mut failure_weight = 0_u64;
        for node in 0..n as u32 {
            meter.tick("certificate_checks")?;
            if side[inside(node) as usize] && !side[outside(node) as usize] {
                if node == s || node == t {
                    return Err(GraphError::Inconsistent(
                        "an unbounded terminal split arc is cut".to_owned(),
                    ));
                }
                failure_weight =
                    checked_add(failure_weight, graph.node_weight(node), "failure weight")?;
                failure_set.push(graph.id(node).to_owned());
            }
        }
        for arc in graph.arcs() {
            meter.tick("certificate_checks")?;
            let crosses = side[outside(arc.tail) as usize] && !side[inside(arc.head) as usize];
            let crosses_back = graph.orientation() == Orientation::Undirected
                && side[outside(arc.head) as usize]
                && !side[inside(arc.tail) as usize];
            if crosses || crosses_back {
                return Err(GraphError::Inconsistent(
                    "an unbounded arc crosses the node cut".to_owned(),
                ));
            }
        }
        if failure_weight != value {
            return Err(GraphError::Inconsistent(format!(
                "failure weight {failure_weight} differs from flow value {value}"
            )));
        }
        source_side_nodes = (0..n as u32)
            .filter(|&node| side[outside(node) as usize])
            .map(|node| graph.id(node).to_owned())
            .collect();
        NodeCutOutput {
            source: graph.id(s).to_owned(),
            sink: graph.id(t).to_owned(),
            separable: true,
            failure_weight,
            failure_set,
            source_side: source_side_nodes,
        }
    };
    Ok((FlowOutput::Nodes(answer), residual.edges()))
}
