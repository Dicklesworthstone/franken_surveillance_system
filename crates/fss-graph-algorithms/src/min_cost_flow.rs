//! `ALG-MCF-001` — minimum-cost flow of a requested amount.
//!
//! Two directed projections over the same nodes and arcs carry the arc costs (one unit) and the
//! arc capacities (another unit); a mismatch in node or arc sets is a precondition failure. The
//! run sends up to `demand` units from the source to the sink at minimum total cost by successive
//! shortest augmenting paths: Dijkstra on reduced costs with node potentials (every cost is
//! non-negative, so the zero potential is feasible), heap order `(distance, node)` and strict
//! improvement in canonical residual-edge order, augmenting by the bottleneck each time.
//!
//! Before returning, the answer is certified optimal for the delivered amount: capacities and
//! conservation hold and the final residual network has no negative-cost cycle (Bellman–Ford
//! from a virtual source, `n + 1` rounds). A failed certificate is
//! `ERR-GRAPH-RESULT-INCONSISTENT-001`. When the network cannot carry the whole demand the
//! answer reports the delivered amount and the exact shortfall — never a partial success
//! presented as complete. Total cost is accumulated in 128 bits and refused if it leaves `u64`.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use fss_core::CanonicalEncoder;

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, mul, query_digest, query_encoder,
};
use crate::graph::GraphError;
use crate::weighted::{Orientation, WeightedGraph};

/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-MCF-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.mcf_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-MCF-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.mcf_decision_path.v1";

/// Registered identity (`ALG-MCF-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-MCF-001",
    algorithm_name: "min_cost_flow",
    tie_break_rule: "cost then stable assignment identity",
    complexity_witness: "augmentations and reduced-cost updates",
    output_size_witness: "<= |E| edge flow assignments",
    exactness: "exact_or_verified_candidate",
    implementation_id: "fss-graph-algorithms:alg-mcf-001:successive-shortest-path-potentials-certified:v1",
    tie_break_policy_id: "tie:distance-then-node-heap-strict-improvement-canonical-residual-edges:v1",
    policy_id: "graph-policy:directed:simple-strict:paired-cost-and-capacity-projections:numeric:u64-exact:checked:unit-bound:v1:tie:distance-then-node-heap-strict-improvement-canonical-residual-edges:v1",
    complexity_bound_id: "bound:alg-mcf-001:ssp-demand-augmentations-plus-bellman-ford-certificate:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// The registered bound for `n` nodes, `m` arcs and the requested `demand`. Successive shortest
/// paths is pseudo-polynomial: augmentations are bounded by the demand itself (each carries at
/// least one unit), so re-checking a witness needs the demand bound into its input digest.
#[must_use]
pub fn bound(n: u64, m: u64, demand: u64) -> Vec<BoundRow> {
    let runs = add(demand, 1);
    let residual = mul(2, m);
    vec![
        ("augmentations", demand),
        ("dijkstra_runs", runs),
        ("residual_scans", mul(runs, residual)),
        ("heap_operations", mul(runs, mul(2, add(residual, 1)))),
        ("path_steps", mul(demand, mul(2, n))),
        ("certificate_relaxations", mul(add(n, 1), add(residual, n))),
        (OUTPUT_ENTRIES, m),
    ]
}

/// The canonical answer of `ALG-MCF-001`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MinCostFlowOutput {
    /// Source.
    pub source: String,
    /// Sink.
    pub sink: String,
    /// Requested amount.
    pub requested: u64,
    /// Delivered amount (the maximum flow when the demand exceeds it).
    pub delivered: u64,
    /// `requested - delivered`.
    pub shortfall: u64,
    /// Exact minimum total cost of delivering `delivered`.
    pub total_cost: u64,
    /// `(tail, head, amount, unit cost)` of every arc carrying flow, canonical arc order.
    pub flows: Vec<(String, String, u64, u64)>,
}

impl CertifiedOutput for MinCostFlowOutput {
    fn entries(&self) -> u64 {
        self.flows.len() as u64
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.source);
        encoder.text(&self.sink);
        encoder.u64(self.requested);
        encoder.u64(self.delivered);
        encoder.u64(self.shortfall);
        encoder.u64(self.total_cost);
        encoder.u64(self.flows.len() as u64);
        for (tail, head, amount, cost) in &self.flows {
            encoder.text(tail);
            encoder.text(head);
            encoder.u64(*amount);
            encoder.u64(*cost);
        }
    }
}

/// Requires `costs` and `capacities` to be directed projections of the same nodes and arcs.
fn paired(costs: &WeightedGraph, capacities: &WeightedGraph) -> Result<(), GraphError> {
    costs.require_orientation(Orientation::Directed)?;
    capacities.require_orientation(Orientation::Directed)?;
    let same_arcs = costs.arc_count() == capacities.arc_count()
        && costs
            .arcs()
            .iter()
            .zip(capacities.arcs())
            .all(|(a, b)| (a.tail, a.head) == (b.tail, b.head));
    if costs.ids() != capacities.ids() || !same_arcs {
        return Err(GraphError::PreconditionFailed(
            "the cost and capacity projections must have the same nodes and arcs".to_owned(),
        ));
    }
    Ok(())
}

/// Runs `ALG-MCF-001`: up to `demand` units from `source` to `sink`.
///
/// # Errors
///
/// [`GraphError::PreconditionFailed`] for unpaired projections or equal terminals,
/// [`GraphError::UnknownNode`], [`GraphError::ArithmeticOverflow`] for a cost outside `u64`,
/// [`GraphError::Inconsistent`] when the optimality certificate fails, and the fail-closed
/// budget and bound errors.
pub fn min_cost_flow(
    costs: &WeightedGraph,
    capacities: &WeightedGraph,
    source: &str,
    sink: &str,
    demand: u64,
    budget: Budget,
) -> Result<CertifiedRun<MinCostFlowOutput>, GraphError> {
    paired(costs, capacities)?;
    let s = costs.require(source)?;
    let t = costs.require(sink)?;
    if s == t {
        return Err(GraphError::PreconditionFailed(
            "a flow needs distinct source and sink".to_owned(),
        ));
    }
    let n = costs.node_count();
    let m = costs.arc_count();
    let mut meter = Meter::new(&IDENTITY, budget);
    // Residual edge 2i is arc i forward, 2i + 1 its reverse.
    let mut to = Vec::with_capacity(2 * m);
    let mut capacity = Vec::with_capacity(2 * m);
    let mut cost: Vec<i128> = Vec::with_capacity(2 * m);
    let mut adjacency: Vec<Vec<u32>> = vec![Vec::new(); n];
    for (index, arc) in costs.arcs().iter().enumerate() {
        let forward = (2 * index) as u32;
        to.push(arc.head);
        capacity.push(capacities.arc(index as u32).weight);
        cost.push(i128::from(arc.weight));
        adjacency[arc.tail as usize].push(forward);
        to.push(arc.tail);
        capacity.push(0);
        cost.push(-i128::from(arc.weight));
        adjacency[arc.head as usize].push(forward + 1);
    }
    let from = |edge: u32| to[(edge ^ 1) as usize];
    let mut potential = vec![0_i128; n];
    let mut delivered = 0_u64;
    while delivered < demand {
        meter.tick("dijkstra_runs")?;
        let mut distance: Vec<Option<i128>> = vec![None; n];
        let mut parent_edge = vec![u32::MAX; n];
        let mut done = vec![false; n];
        let mut heap: BinaryHeap<Reverse<(i128, u32)>> = BinaryHeap::new();
        distance[s as usize] = Some(0);
        meter.tick("heap_operations")?;
        heap.push(Reverse((0, s)));
        while let Some(Reverse((d, u))) = heap.pop() {
            meter.tick("heap_operations")?;
            if done[u as usize] || distance[u as usize] != Some(d) {
                continue;
            }
            done[u as usize] = true;
            for &edge in &adjacency[u as usize] {
                meter.tick("residual_scans")?;
                if capacity[edge as usize] == 0 {
                    continue;
                }
                let v = to[edge as usize];
                let reduced = cost[edge as usize] + potential[u as usize] - potential[v as usize];
                if reduced < 0 {
                    return Err(GraphError::Inconsistent(
                        "a residual edge has negative reduced cost".to_owned(),
                    ));
                }
                let candidate = d + reduced;
                if distance[v as usize].is_none_or(|current| candidate < current) {
                    distance[v as usize] = Some(candidate);
                    parent_edge[v as usize] = edge;
                    meter.tick("heap_operations")?;
                    heap.push(Reverse((candidate, v)));
                }
            }
        }
        if distance[t as usize].is_none() {
            break;
        }
        for node in 0..n {
            if let Some(d) = distance[node] {
                potential[node] += d;
            }
        }
        meter.tick("augmentations")?;
        let mut bottleneck = demand - delivered;
        let mut node = t;
        while node != s {
            meter.tick("path_steps")?;
            let edge = parent_edge[node as usize];
            bottleneck = bottleneck.min(capacity[edge as usize]);
            node = from(edge);
        }
        let mut node = t;
        while node != s {
            meter.tick("path_steps")?;
            let edge = parent_edge[node as usize];
            capacity[edge as usize] -= bottleneck;
            capacity[(edge ^ 1) as usize] += bottleneck;
            node = from(edge);
        }
        meter.decide(0, u64::from(parent_edge[t as usize]), bottleneck);
        delivered += bottleneck;
    }

    // Certificate: capacity, conservation, and no negative cycle in the residual network.
    let mut balance = vec![0_i128; n];
    let mut flows = Vec::new();
    let mut total_cost: i128 = 0;
    for (index, arc) in costs.arcs().iter().enumerate() {
        let limit = capacities.arc(index as u32).weight;
        let amount = limit - capacity[2 * index];
        if amount != capacity[2 * index + 1] {
            return Err(GraphError::Inconsistent(
                "reverse residual differs from flow".to_owned(),
            ));
        }
        if amount > 0 {
            balance[arc.tail as usize] -= i128::from(amount);
            balance[arc.head as usize] += i128::from(amount);
            total_cost += i128::from(amount) * i128::from(arc.weight);
            flows.push((
                costs.id(arc.tail).to_owned(),
                costs.id(arc.head).to_owned(),
                amount,
                arc.weight,
            ));
        }
    }
    for node in 0..n as u32 {
        let expected = if node == s {
            -i128::from(delivered)
        } else if node == t {
            i128::from(delivered)
        } else {
            0
        };
        if balance[node as usize] != expected {
            return Err(GraphError::Inconsistent(format!(
                "flow conservation fails at {}",
                costs.id(node)
            )));
        }
    }
    let mut label = vec![0_i128; n];
    let mut relaxed = true;
    let mut rounds = 0;
    while relaxed {
        relaxed = false;
        rounds += 1;
        if rounds > n + 1 {
            return Err(GraphError::Inconsistent(
                "the residual network has a negative-cost cycle: the flow is not optimal"
                    .to_owned(),
            ));
        }
        for u in 0..n {
            meter.tick("certificate_relaxations")?;
            for &edge in &adjacency[u] {
                meter.tick("certificate_relaxations")?;
                if capacity[edge as usize] > 0 {
                    let v = to[edge as usize] as usize;
                    let candidate = label[u] + cost[edge as usize];
                    if candidate < label[v] {
                        label[v] = candidate;
                        relaxed = true;
                    }
                }
            }
        }
    }
    let total_cost =
        u64::try_from(total_cost).map_err(|_| GraphError::ArithmeticOverflow("total flow cost"))?;
    let output = MinCostFlowOutput {
        source: source.to_owned(),
        sink: sink.to_owned(),
        requested: demand,
        delivered,
        shortfall: demand - delivered,
        total_cost,
        flows,
    };
    let (n64, m64) = (n as u64, m as u64);
    let mut input = query_encoder(&IDENTITY, costs.digest());
    input.text(&capacities.digest().to_text());
    input.text(source);
    input.text(sink);
    input.u64(demand);
    let peak = 2 * m64 * (4 + 8 + 16 + 4) + n64 * (16 * 3 + 4 + 1);
    meter.finish(
        &IDENTITY,
        InputShape {
            node_count: n64,
            edge_count: m64,
            input_digest: query_digest(input),
        },
        output,
        &bound(n64, m64, demand),
        peak,
    )
}
