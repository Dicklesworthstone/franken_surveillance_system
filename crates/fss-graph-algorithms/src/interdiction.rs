//! `ALG-INTERDICT-001` — adversarial blind-spot analysis.
//!
//! Model: a movement projection over zones (`WeightedGraph`, directed or undirected; weights
//! ignored), the sensors observing each zone, a cost for an adversary to disable, dazzle or
//! cover each sensor, and declared entry and target zones. A walk from an entry to a target is
//! *unobserved* when no zone on it — entry and target included — keeps a working observer.
//!
//! The run answers the decision "how cheaply can an intruder reach the target unseen?":
//!
//! * `blind_path`: some walk is unobserved with every sensor working — an existing blind spot;
//! * `interdiction`: the minimum-cost set of sensors whose loss opens an unobserved walk, ties
//!   broken by fewer sensors, then the lexicographically smallest sensor tuple, with one witness
//!   walk (fewest zones, then lexicographically smallest);
//! * `unreachable`: no walk exists at all.
//!
//! Exactness: the minimum is exact (every subset of the at most [`MAX_EXACT_SENSORS`] relevant
//! sensors is evaluated, pruned only by cost). Beyond that the run returns an explicitly
//! *approximate* feasible interdiction — the sensors of a walk minimizing the sum of its zones'
//! observer costs — which is an upper bound on the true minimum, never presented as exact.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fss_core::CanonicalEncoder;

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, checked_add, encode_ids, mul, query_digest, query_encoder,
};
use crate::graph::GraphError;
use crate::weighted::{Orientation, WeightedGraph};

/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-INTERDICT-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.interdict_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-INTERDICT-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.interdict_decision_path.v1";
/// Largest relevant-sensor count solved exactly.
pub const MAX_EXACT_SENSORS: usize = 20;

/// Registered identity (`ALG-INTERDICT-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-INTERDICT-001",
    algorithm_name: "network_interdiction_and_robust_placement",
    tie_break_rule: "loss then canonical removal/placement set",
    complexity_witness: "cut/flow solves and branch nodes",
    output_size_witness: "<= k <= |V| + |E| interdicted elements",
    exactness: "bounded_exact_or_approximate",
    implementation_id: "fss-graph-algorithms:alg-interdict-001:exact-sensor-subset-enumeration-or-node-weighted-path-bound:v1",
    tie_break_policy_id: "tie:cost-then-cardinality-then-lexicographic-sensor-tuple:v1",
    policy_id: "graph-policy:directed-or-undirected:zones-observed-by-sensors:unobserved-walk-entry-to-target:sensor-disable-cost:numeric:u64-exact:checked:v1:tie:cost-then-cardinality-then-lexicographic-sensor-tuple:v1",
    complexity_bound_id: "bound:alg-interdict-001:2-pow-s-branch-nodes-times-linear-search:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// The registered bound for `n` zones, `m` movement arcs and `s` relevant sensors.
#[must_use]
pub fn bound(n: u64, m: u64, s: u64) -> Vec<BoundRow> {
    let exact = s <= MAX_EXACT_SENSORS as u64;
    let branches = if exact { 1_u64 << s } else { 1 };
    let searches = add(branches, 2);
    let scans = mul(2, m);
    vec![
        ("branch_nodes", branches),
        ("path_searches", searches),
        ("zone_visits", mul(searches, n)),
        ("arc_scans", mul(searches, scans)),
        ("cost_sums", mul(branches, s)),
        (OUTPUT_ENTRIES, add(n, s)),
    ]
}

/// The adversarial question over one site.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterdictionQuery {
    /// Zone → sensors observing it.
    pub observers: BTreeMap<String, BTreeSet<String>>,
    /// Sensor → disable cost (loss units; use `1` to count sensors).
    pub costs: BTreeMap<String, u64>,
    /// Entry zones.
    pub entries: BTreeSet<String>,
    /// Target zones.
    pub targets: BTreeSet<String>,
}

/// How the intruder reaches the target unseen.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InterdictionOutcome {
    /// An unobserved walk exists with every sensor working.
    BlindPath {
        /// The witness walk.
        path: Vec<String>,
    },
    /// Disabling these sensors opens an unobserved walk.
    Interdiction {
        /// Sensors, ascending.
        sensors: Vec<String>,
        /// Total disable cost.
        cost: u64,
        /// The witness walk.
        path: Vec<String>,
        /// The cost is the exact minimum (false: a feasible upper bound).
        exact: bool,
    },
    /// No walk from any entry to any target exists.
    Unreachable,
}

/// The canonical answer of `ALG-INTERDICT-001`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterdictionOutput {
    /// Relevant sensors (observing some zone), ascending.
    pub relevant_sensors: Vec<String>,
    /// The outcome.
    pub outcome: InterdictionOutcome,
}

impl CertifiedOutput for InterdictionOutput {
    fn entries(&self) -> u64 {
        let outcome = match &self.outcome {
            InterdictionOutcome::BlindPath { path } => path.len(),
            InterdictionOutcome::Interdiction { sensors, path, .. } => sensors.len() + path.len(),
            InterdictionOutcome::Unreachable => 0,
        };
        outcome as u64
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encode_ids(encoder, &self.relevant_sensors);
        match &self.outcome {
            InterdictionOutcome::BlindPath { path } => {
                encoder.tag(0);
                encode_ids(encoder, path);
            }
            InterdictionOutcome::Interdiction {
                sensors,
                cost,
                path,
                exact,
            } => {
                encoder.tag(1);
                encode_ids(encoder, sensors);
                encoder.u64(*cost);
                encode_ids(encoder, path);
                encoder.bool(*exact);
            }
            InterdictionOutcome::Unreachable => encoder.tag(2),
        }
    }
}

/// Fewest-zone, lexicographically smallest walk from an entry to a target through zones for
/// which `open` holds, as canonical node indices.
fn walk(
    graph: &WeightedGraph,
    open: &[bool],
    entries: &[u32],
    targets: &[bool],
    meter: &mut Meter,
) -> Result<Option<Vec<u32>>, GraphError> {
    meter.tick("path_searches")?;
    let n = graph.node_count();
    let mut parent = vec![u32::MAX; n];
    let mut seen = vec![false; n];
    let mut queue = VecDeque::new();
    for &entry in entries {
        if open[entry as usize] && !seen[entry as usize] {
            seen[entry as usize] = true;
            queue.push_back(entry);
        }
    }
    while let Some(node) = queue.pop_front() {
        meter.tick("zone_visits")?;
        if targets[node as usize] {
            let mut path = vec![node];
            let mut current = node;
            while parent[current as usize] != u32::MAX {
                current = parent[current as usize];
                path.push(current);
            }
            path.reverse();
            return Ok(Some(path));
        }
        for &arc in graph.out_arcs(node) {
            meter.tick("arc_scans")?;
            let next = match graph.orientation() {
                Orientation::Directed => graph.arc(arc).head,
                Orientation::Undirected => graph.arc(arc).other(node),
            };
            if open[next as usize] && !seen[next as usize] {
                seen[next as usize] = true;
                parent[next as usize] = node;
                queue.push_back(next);
            }
        }
    }
    Ok(None)
}

/// Runs `ALG-INTERDICT-001` over the movement projection `graph`.
///
/// # Errors
///
/// [`GraphError::UnknownNode`] for an entry, target or observed zone outside the projection,
/// [`GraphError::PreconditionFailed`] for empty entries/targets or a sensor without a cost,
/// [`GraphError::ArithmeticOverflow`], and the fail-closed budget and bound errors.
pub fn interdiction(
    graph: &WeightedGraph,
    query: &InterdictionQuery,
    budget: Budget,
) -> Result<CertifiedRun<InterdictionOutput>, GraphError> {
    if query.entries.is_empty() || query.targets.is_empty() {
        return Err(GraphError::PreconditionFailed(
            "interdiction needs entry and target zones".to_owned(),
        ));
    }
    let n = graph.node_count();
    let entries: Vec<u32> = query
        .entries
        .iter()
        .map(|zone| graph.require(zone))
        .collect::<Result<_, _>>()?;
    let mut targets = vec![false; n];
    for zone in &query.targets {
        targets[graph.require(zone)? as usize] = true;
    }
    let sensors: Vec<String> = query
        .observers
        .values()
        .flatten()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let index: BTreeMap<&str, usize> = sensors
        .iter()
        .enumerate()
        .map(|(i, s)| (s.as_str(), i))
        .collect();
    let mut costs = Vec::with_capacity(sensors.len());
    for sensor in &sensors {
        costs.push(*query.costs.get(sensor).ok_or_else(|| {
            GraphError::PreconditionFailed(format!("sensor {sensor} has no disable cost"))
        })?);
    }
    // Per zone: the sensors observing it as indices.
    let mut zone_sensors: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (zone, observers) in &query.observers {
        let node = graph.require(zone)?;
        zone_sensors[node as usize] = observers.iter().map(|s| index[s.as_str()]).collect();
    }
    let mut meter = Meter::new(&IDENTITY, budget);
    let ids = |path: &[u32]| {
        path.iter()
            .map(|&node| graph.id(node).to_owned())
            .collect::<Vec<_>>()
    };
    let all_open = vec![true; n];
    let outcome = if walk(graph, &all_open, &entries, &targets, &mut meter)?.is_none() {
        InterdictionOutcome::Unreachable
    } else {
        let unobserved: Vec<bool> = zone_sensors.iter().map(Vec::is_empty).collect();
        if let Some(path) = walk(graph, &unobserved, &entries, &targets, &mut meter)? {
            InterdictionOutcome::BlindPath { path: ids(&path) }
        } else if sensors.len() <= MAX_EXACT_SENSORS {
            let s = sensors.len();
            let mut best: Option<(u64, u32, Vec<usize>, Vec<u32>)> = None;
            for mask in 1_u32..(1_u32 << s) {
                meter.tick("branch_nodes")?;
                let mut cost = 0_u64;
                for (bit, &sensor_cost) in costs.iter().enumerate() {
                    if mask & (1 << bit) != 0 {
                        meter.tick("cost_sums")?;
                        cost = checked_add(cost, sensor_cost, "interdiction cost")?;
                    }
                }
                let size = mask.count_ones();
                let chosen: Vec<usize> = (0..s).filter(|bit| mask & (1 << bit) != 0).collect();
                if let Some((best_cost, best_size, best_set, _)) = &best
                    && (cost, size, &chosen) >= (*best_cost, *best_size, best_set)
                {
                    continue;
                }
                let open: Vec<bool> = zone_sensors
                    .iter()
                    .map(|observers| observers.iter().all(|&sensor| mask & (1 << sensor) != 0))
                    .collect();
                if let Some(path) = walk(graph, &open, &entries, &targets, &mut meter)? {
                    meter.decide(1, u64::from(mask), cost);
                    best = Some((cost, size, chosen, path));
                }
            }
            match best {
                Some((cost, _, chosen, path)) => InterdictionOutcome::Interdiction {
                    sensors: chosen.iter().map(|&i| sensors[i].clone()).collect(),
                    cost,
                    path: ids(&path),
                    exact: true,
                },
                None => {
                    return Err(GraphError::Inconsistent(
                        "a reachable target has no interdiction".to_owned(),
                    ));
                }
            }
        } else {
            // Feasible upper bound: a walk minimizing the sum of its zones' observer costs
            // (shared sensors counted per zone), then the exact union cost of that walk.
            meter.tick("branch_nodes")?;
            let zone_cost: Vec<u64> = zone_sensors
                .iter()
                .map(|observers| {
                    observers
                        .iter()
                        .map(|&s| costs[s])
                        .fold(0_u64, u64::saturating_add)
                })
                .collect();
            let mut best: Vec<Option<(u64, u64)>> = vec![None; n];
            let mut parent = vec![u32::MAX; n];
            let mut heap = std::collections::BinaryHeap::new();
            for &entry in &entries {
                let key = (zone_cost[entry as usize], 0_u64);
                if best[entry as usize].is_none_or(|current| key < current) {
                    best[entry as usize] = Some(key);
                    heap.push(std::cmp::Reverse((key, entry)));
                }
            }
            meter.tick("path_searches")?;
            let mut done = vec![false; n];
            let mut goal = None;
            while let Some(std::cmp::Reverse((key, node))) = heap.pop() {
                if done[node as usize] || best[node as usize] != Some(key) {
                    continue;
                }
                done[node as usize] = true;
                meter.tick("zone_visits")?;
                if targets[node as usize] {
                    goal = Some(node);
                    break;
                }
                for &arc in graph.out_arcs(node) {
                    meter.tick("arc_scans")?;
                    let next = match graph.orientation() {
                        Orientation::Directed => graph.arc(arc).head,
                        Orientation::Undirected => graph.arc(arc).other(node),
                    };
                    let candidate = (key.0.saturating_add(zone_cost[next as usize]), key.1 + 1);
                    if !done[next as usize]
                        && best[next as usize].is_none_or(|current| candidate < current)
                    {
                        best[next as usize] = Some(candidate);
                        parent[next as usize] = node;
                        heap.push(std::cmp::Reverse((candidate, next)));
                    }
                }
            }
            let goal =
                goal.ok_or_else(|| GraphError::Inconsistent("reachable target lost".to_owned()))?;
            let mut path = vec![goal];
            let mut current = goal;
            while parent[current as usize] != u32::MAX {
                current = parent[current as usize];
                path.push(current);
            }
            path.reverse();
            let chosen: BTreeSet<usize> = path
                .iter()
                .flat_map(|&node| zone_sensors[node as usize].iter().copied())
                .collect();
            let mut cost = 0_u64;
            for &sensor in &chosen {
                cost = checked_add(cost, costs[sensor], "interdiction cost")?;
            }
            InterdictionOutcome::Interdiction {
                sensors: chosen.iter().map(|&i| sensors[i].clone()).collect(),
                cost,
                path: ids(&path),
                exact: false,
            }
        }
    };
    let (n64, m64, s64) = (n as u64, graph.arc_count() as u64, sensors.len() as u64);
    let mut input = query_encoder(&IDENTITY, graph.digest());
    input.u64(query.observers.len() as u64);
    for (zone, observers) in &query.observers {
        input.text(zone);
        input.u64(observers.len() as u64);
        for sensor in observers {
            input.text(sensor);
        }
    }
    input.u64(query.costs.len() as u64);
    for (sensor, cost) in &query.costs {
        input.text(sensor);
        input.u64(*cost);
    }
    encode_ids(
        &mut input,
        &query.entries.iter().cloned().collect::<Vec<_>>(),
    );
    encode_ids(
        &mut input,
        &query.targets.iter().cloned().collect::<Vec<_>>(),
    );
    let peak = n64 * 21 + 8 * s64;
    meter.finish(
        &IDENTITY,
        InputShape {
            node_count: n64,
            edge_count: m64,
            input_digest: query_digest(input),
        },
        InterdictionOutput {
            relevant_sensors: sensors,
            outcome,
        },
        &bound(n64, m64, s64),
        peak,
    )
}
