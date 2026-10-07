//! `ALG-TOPO-001` — topological order, parallel frontiers and critical path.
//!
//! Activity-on-node schedule over a directed acyclic projection: every node weight is a
//! duration and every arc weight a minimum lag, both in the projection's unit. The run reports
//!
//! * the lexicographically smallest topological order by stable node identity (Kahn with a
//!   min-heap), so ties never depend on insertion or hash order;
//! * parallel frontiers (level `0` = no predecessor; otherwise one more than the deepest
//!   predecessor), each in ascending identity order;
//! * for every node its earliest and latest start and finish and its slack, against the
//!   makespan (`earliest_start(v) = max(earliest_finish(p) + lag(p, v))`);
//! * one critical path: from the smallest-identity zero-slack node starting at time zero with no
//!   tight zero-slack predecessor, repeatedly the smallest-identity zero-slack successor whose
//!   earliest start equals the current earliest finish plus the lag.
//!
//! A cyclic projection fails the precondition (`ERR-GRAPH-PRECONDITION-001`) naming the
//! smallest identity left on or behind a cycle; collapse it with `ALG-SCC-001` first. Every sum
//! is checked; an overflow is `ERR-GRAPH-NUMERIC-OVERFLOW-001`.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use fss_core::CanonicalEncoder;

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, checked_add, encode_ids, mul,
};
use crate::graph::GraphError;
use crate::weighted::{Orientation, WeightedGraph};

/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-TOPO-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.topo_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-TOPO-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.topo_decision_path.v1";

/// Registered identity (`ALG-TOPO-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-TOPO-001",
    algorithm_name: "topological_order_and_critical_path",
    tie_break_rule: "stable plan-step identity",
    complexity_witness: "in-degree updates and relaxations",
    output_size_witness: "<= |V| ordered nodes and <= |E| slack records",
    exactness: "exact",
    implementation_id: "fss-graph-algorithms:alg-topo-001:kahn-min-heap-cpm:v1",
    tie_break_policy_id: "tie:smallest-stable-identity-first:v1",
    policy_id: "graph-policy:directed:simple-strict:acyclic-required:node-duration-arc-lag:numeric:u64-exact:checked:unit-bound:v1:tie:smallest-stable-identity-first:v1",
    complexity_bound_id: "bound:alg-topo-001:kahn-linear-plus-heap:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// The registered bound for `n` nodes and `m` arcs.
#[must_use]
pub fn bound(n: u64, m: u64) -> Vec<BoundRow> {
    vec![
        ("arc_scans", mul(6, m)),
        ("heap_operations", mul(2, n)),
        ("relaxations", mul(2, m)),
        ("node_visits", mul(3, n)),
        (OUTPUT_ENTRIES, mul(4, n)),
    ]
}

/// One node's schedule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduleRow {
    /// Node identity.
    pub node: String,
    /// Duration (node weight).
    pub duration: u64,
    /// Earliest start.
    pub earliest_start: u64,
    /// Earliest finish.
    pub earliest_finish: u64,
    /// Latest start that does not delay the makespan.
    pub latest_start: u64,
    /// Latest finish that does not delay the makespan.
    pub latest_finish: u64,
    /// `latest_start - earliest_start`.
    pub slack: u64,
    /// Parallel frontier level.
    pub level: u32,
}

/// The canonical answer of `ALG-TOPO-001`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TopoOutput {
    /// Lexicographically smallest topological order.
    pub order: Vec<String>,
    /// Parallel frontiers, level by level, each ascending.
    pub frontiers: Vec<Vec<String>>,
    /// Schedule rows in ascending identity order.
    pub schedule: Vec<ScheduleRow>,
    /// Maximum earliest finish (zero for an empty projection).
    pub makespan: u64,
    /// One critical path (empty for an empty projection).
    pub critical_path: Vec<String>,
}

impl CertifiedOutput for TopoOutput {
    fn entries(&self) -> u64 {
        let frontier: usize = self.frontiers.iter().map(Vec::len).sum();
        (self.order.len() + frontier + self.schedule.len() + self.critical_path.len()) as u64
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encode_ids(encoder, &self.order);
        encoder.u64(self.frontiers.len() as u64);
        for frontier in &self.frontiers {
            encode_ids(encoder, frontier);
        }
        encoder.u64(self.schedule.len() as u64);
        for row in &self.schedule {
            encoder.text(&row.node);
            encoder.u64(row.duration);
            encoder.u64(row.earliest_start);
            encoder.u64(row.earliest_finish);
            encoder.u64(row.latest_start);
            encoder.u64(row.latest_finish);
            encoder.u64(row.slack);
            encoder.u32(row.level);
        }
        encoder.u64(self.makespan);
        encode_ids(encoder, &self.critical_path);
    }
}

/// Runs `ALG-TOPO-001` over a directed projection.
///
/// # Errors
///
/// [`GraphError::PreconditionFailed`] for an undirected or cyclic projection,
/// [`GraphError::ArithmeticOverflow`] for a schedule outside `u64`, and the fail-closed budget
/// and bound errors.
pub fn topological_schedule(
    graph: &WeightedGraph,
    budget: Budget,
) -> Result<CertifiedRun<TopoOutput>, GraphError> {
    graph.require_orientation(Orientation::Directed)?;
    let n = graph.node_count();
    let mut meter = Meter::new(&IDENTITY, budget);
    let mut indegree = vec![0_u32; n];
    for arc in graph.arcs() {
        meter.tick("arc_scans")?;
        indegree[arc.head as usize] += 1;
    }
    let mut heap: BinaryHeap<Reverse<u32>> = BinaryHeap::new();
    for node in 0..n as u32 {
        if indegree[node as usize] == 0 {
            meter.tick("heap_operations")?;
            heap.push(Reverse(node));
        }
    }
    let mut order: Vec<u32> = Vec::with_capacity(n);
    while let Some(Reverse(node)) = heap.pop() {
        meter.tick("heap_operations")?;
        meter.decide(0, u64::from(node), order.len() as u64);
        order.push(node);
        for &arc in graph.out_arcs(node) {
            meter.tick("arc_scans")?;
            let head = graph.arc(arc).head;
            indegree[head as usize] -= 1;
            if indegree[head as usize] == 0 {
                meter.tick("heap_operations")?;
                heap.push(Reverse(head));
            }
        }
    }
    if order.len() != n {
        let blocked = (0..n as u32)
            .find(|&node| indegree[node as usize] > 0)
            .map_or_else(String::new, |node| graph.id(node).to_owned());
        return Err(GraphError::PreconditionFailed(format!(
            "the projection is cyclic: {} nodes lie on or behind a cycle (first {blocked:?}); \
             condense it with ALG-SCC-001",
            n - order.len()
        )));
    }

    let mut earliest_start = vec![0_u64; n];
    let mut earliest_finish = vec![0_u64; n];
    let mut level = vec![0_u32; n];
    for &node in &order {
        meter.tick("node_visits")?;
        let mut start = 0_u64;
        let mut depth = 0_u32;
        for &arc in graph.in_arcs(node) {
            meter.tick("arc_scans")?;
            meter.tick("relaxations")?;
            let arc = graph.arc(arc);
            let ready = checked_add(
                earliest_finish[arc.tail as usize],
                arc.weight,
                "earliest start",
            )?;
            start = start.max(ready);
            depth = depth.max(level[arc.tail as usize] + 1);
        }
        earliest_start[node as usize] = start;
        earliest_finish[node as usize] =
            checked_add(start, graph.node_weight(node), "earliest finish")?;
        level[node as usize] = depth;
    }
    let makespan = earliest_finish.iter().copied().max().unwrap_or(0);
    let mut latest_finish = vec![makespan; n];
    let mut latest_start = vec![0_u64; n];
    for &node in order.iter().rev() {
        meter.tick("node_visits")?;
        let mut finish = makespan;
        for &arc in graph.out_arcs(node) {
            meter.tick("arc_scans")?;
            meter.tick("relaxations")?;
            let arc = graph.arc(arc);
            let bound = latest_start[arc.head as usize]
                .checked_sub(arc.weight)
                .ok_or_else(|| GraphError::Inconsistent("negative latest finish".to_owned()))?;
            finish = finish.min(bound);
        }
        latest_finish[node as usize] = finish;
        latest_start[node as usize] = finish
            .checked_sub(graph.node_weight(node))
            .ok_or_else(|| GraphError::Inconsistent("negative latest start".to_owned()))?;
    }
    let slack: Vec<u64> = (0..n)
        .map(|node| {
            latest_start[node]
                .checked_sub(earliest_start[node])
                .ok_or_else(|| GraphError::Inconsistent("negative slack".to_owned()))
        })
        .collect::<Result<_, _>>()?;

    let tight = |tail: u32, head: u32, lag: u64| -> bool {
        slack[tail as usize] == 0
            && slack[head as usize] == 0
            && earliest_finish[tail as usize].checked_add(lag)
                == Some(earliest_start[head as usize])
    };
    let mut critical_path: Vec<String> = Vec::new();
    let mut start_node = None;
    for node in 0..n as u32 {
        if earliest_start[node as usize] != 0 || slack[node as usize] != 0 {
            continue;
        }
        let mut has_tight_predecessor = false;
        for &arc in graph.in_arcs(node) {
            meter.tick("arc_scans")?;
            let arc = graph.arc(arc);
            if tight(arc.tail, node, arc.weight) {
                has_tight_predecessor = true;
                break;
            }
        }
        if !has_tight_predecessor {
            start_node = Some(node);
            break;
        }
    }
    if let Some(mut current) = start_node {
        loop {
            meter.tick("node_visits")?;
            critical_path.push(graph.id(current).to_owned());
            let mut next = None;
            for &arc in graph.out_arcs(current) {
                meter.tick("arc_scans")?;
                let arc = graph.arc(arc);
                if tight(current, arc.head, arc.weight) {
                    next = Some(arc.head);
                    break;
                }
            }
            match next {
                Some(head) => {
                    meter.decide(1, u64::from(current), u64::from(head));
                    current = head;
                }
                None => break,
            }
        }
    }
    if n > 0 && start_node.is_none() {
        return Err(GraphError::Inconsistent(
            "a non-empty schedule has no critical start".to_owned(),
        ));
    }

    let depth = level
        .iter()
        .copied()
        .max()
        .map_or(0, |deepest| deepest as usize + 1);
    let mut frontiers: Vec<Vec<String>> = vec![Vec::new(); if n == 0 { 0 } else { depth }];
    for node in 0..n as u32 {
        frontiers[level[node as usize] as usize].push(graph.id(node).to_owned());
    }
    let schedule = (0..n)
        .map(|node| ScheduleRow {
            node: graph.id(node as u32).to_owned(),
            duration: graph.node_weight(node as u32),
            earliest_start: earliest_start[node],
            earliest_finish: earliest_finish[node],
            latest_start: latest_start[node],
            latest_finish: latest_finish[node],
            slack: slack[node],
            level: level[node],
        })
        .collect();
    let output = TopoOutput {
        order: order
            .iter()
            .map(|&node| graph.id(node).to_owned())
            .collect(),
        frontiers,
        schedule,
        makespan,
        critical_path,
    };
    let (n64, m64) = (n as u64, graph.arc_count() as u64);
    // indegree, level (4 bytes), five u64 schedule vectors (8 bytes), order and heap (4 bytes).
    let peak = n64 * (4 + 4 + 40 + 4 + 4);
    meter.finish(
        &IDENTITY,
        InputShape {
            node_count: n64,
            edge_count: m64,
            input_digest: graph.digest(),
        },
        output,
        &bound(n64, m64),
        peak,
    )
}
