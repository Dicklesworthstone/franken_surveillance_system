#![forbid(unsafe_code)]
//! Exact, bounded camera-placement advice for `ALG-INTERDICT-001`.
//!
//! Choose declared camera additions that maximize the minimum total sensor-disable cost
//! needed to open an unseen entry-to-target walk. Installation cost, addition count, then
//! the ascending sensor tuple break equal robustness ties. The empty addition is always
//! considered. A disconnected movement graph is reported as such, never as infinite coverage.
//!
//! This is a counterfactual over supplied, already-authorized geometry and observer facts.
//! Sensor-disable costs are owner assumptions, not probabilities or independence evidence.
//! No camera placement, acquisition, effect grant or current-coverage claim is performed.
//! Every placement and inner removal search shares one work allowance and cancellation probe.
//! Oversized, exhausted or cancelled exact work has no heuristic fallback or partial answer.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, encode_ids, mul,
};
use crate::graph::{GraphError, MAX_NODE_ID_LEN};
use crate::interdiction::{InterdictionOutcome, InterdictionQuery};
use crate::set_cover::{CoverBudget, CoverError, MAX_OUTPUT_ENTRIES, MAX_WORK_UNITS};
use crate::weighted::{Orientation, WeightedGraph};

/// Exact placement with explicit shared failures in addition to individual sensor losses.
pub mod shared_failures;

/// Maximum explicitly considered additions; larger requests are refused, not sampled.
pub const MAX_CANDIDATES: usize = 16;
/// Maximum baseline and candidate sensor identities, including zero-support sensors.
pub const MAX_TOTAL_SENSORS: usize = 20;
/// Hard movement-projection node bound.
pub const MAX_ZONES: usize = 256;
/// Hard movement-projection arc bound.
pub const MAX_ARCS: usize = 4096;
/// Complete input, including all installation and disable-cost assumptions.
pub const INPUT_DOMAIN: &str = "fss.graph.robust_placement_input.v1";
/// Complete exact answer, with the original and counterfactual witness walks.
pub const OUTPUT_DOMAIN: &str = "fss.graph.robust_placement_output.v1";
/// Deterministic exhaustive-search summary; not a retained per-branch transcript.
pub const DECISION_DOMAIN: &str = "fss.graph.robust_placement_decision_summary.v1";

/// Additive exact-placement mode; existing interdiction identities and bytes are unchanged.
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-INTERDICT-001",
    algorithm_name: "network_interdiction_and_robust_placement",
    tie_break_rule: "maximum minimum disable cost, then installation cost, cardinality and sensor tuple",
    complexity_witness: "placement branches, removal branches, path searches and adjacency scans",
    output_size_witness: "selected additions plus baseline and selected exact removal sets and witness paths",
    exactness: "bounded_exact",
    implementation_id: "fss-graph-algorithms:alg-interdict-001:exact-robust-placement:v1",
    tie_break_policy_id: "tie:maximum-minimum-disable-cost-then-install-cost-count-sensor-tuple:v1",
    policy_id: "placement-policy:exact-only:declared-observers:independent-sensor-removals:separate-u64-install-disable-costs:v1",
    complexity_bound_id: "bound:alg-interdict-001:placement-subsets-times-removal-subsets-times-linear-search:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_DOMAIN,
};

/// An owner-declared hypothetical camera. Neither identity nor geometry implies authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementCandidate {
    /// Fresh stable identity, distinct from every baseline sensor and other candidate.
    pub sensor: String,
    /// Movement zones this candidate is assumed to observe; empty support is allowed.
    pub observes: BTreeSet<String>,
    /// Assumed adversarial cost to disable this sensor, in the baseline's loss units.
    pub disable_cost: u64,
    /// Installation cost in one separately declared unit; zero is permitted.
    pub installation_cost: u64,
}

/// Exact placement objective. All supplied candidates are bound, including unaffordable ones.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementQuery {
    /// Current sensor support, loss costs, and entry/target assumptions.
    pub baseline: InterdictionQuery,
    /// Finite complete candidate catalog; order has no semantic effect.
    pub candidates: Vec<PlacementCandidate>,
    /// Unit shared by all baseline/candidate disable costs, bound independently of graph weights.
    pub disable_cost_unit: String,
    /// Unit shared by candidate installation costs and the installation budget.
    pub installation_cost_unit: String,
    /// Hard installation-cost ceiling; never compared to disable costs.
    pub installation_budget: u64,
    /// Hard count ceiling, between zero and [`MAX_CANDIDATES`].
    pub maximum_additions: usize,
}

/// A complete advisory optimum over the supplied catalog, not a physical guarantee.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementOutput {
    /// Chosen additions in ascending identity order; may be empty even with free candidates.
    pub selected_sensors: Vec<String>,
    /// Total installation cost of the chosen additions.
    pub installation_cost: u64,
    /// Exact baseline vulnerability, preserving existing blind paths and disconnection.
    pub baseline: InterdictionOutcome,
    /// Exact vulnerability after adding only the selected candidates.
    pub defended: InterdictionOutcome,
    /// Affordable subsets within the count limit whose exact vulnerability was evaluated.
    pub evaluated_placements: u64,
}

fn outcome_entries(outcome: &InterdictionOutcome) -> u64 {
    match outcome {
        InterdictionOutcome::BlindPath { path } => path.len() as u64 + 1,
        InterdictionOutcome::Interdiction { sensors, path, .. } => {
            (sensors.len() + path.len()) as u64 + 3
        }
        InterdictionOutcome::Unreachable => 1,
    }
}

fn encode_outcome(encoder: &mut CanonicalEncoder, outcome: &InterdictionOutcome) {
    match outcome {
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

impl CertifiedOutput for PlacementOutput {
    fn entries(&self) -> u64 {
        self.selected_sensors.len() as u64
            + outcome_entries(&self.baseline)
            + outcome_entries(&self.defended)
            + 2
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encode_ids(encoder, &self.selected_sensors);
        encoder.u64(self.installation_cost);
        encode_outcome(encoder, &self.baseline);
        encode_outcome(encoder, &self.defended);
        encoder.u64(self.evaluated_placements);
    }
}

/// Saturating *bounds*, never saturating semantic cost arithmetic. `s` includes all declared
/// sensor identities and `p` all candidates. Inputs outside the hard caps cannot be executed.
#[must_use]
pub fn bound(n: u64, m: u64, s: u64, p: u64) -> Vec<BoundRow> {
    let placements = if p < 64 { 1_u64 << p } else { u64::MAX };
    let removals = if s < 64 { 1_u64 << s } else { u64::MAX };
    let searches = add(1, mul(placements, add(1, removals)));
    vec![
        (
            "input_entries",
            add(add(mul(5, n), m), add(mul(n, s), add(s, p))),
        ),
        ("placement_branches", placements),
        ("inner_solves", placements),
        ("removal_branches", mul(placements, removals)),
        (
            "sensor_checks",
            mul(placements, add(p, add(s, mul(removals, s)))),
        ),
        ("path_searches", searches),
        ("entry_checks", mul(searches, n)),
        ("observer_masks", mul(placements, n)),
        ("zone_visits", mul(searches, n)),
        ("arc_scans", mul(searches, mul(2, m))),
        ("path_entries", mul(searches, n)),
        (OUTPUT_ENTRIES, add(p, add(mul(2, add(n, s)), 8))),
    ]
}

struct Work<F> {
    meter: Meter,
    cancelled: F,
}

impl<F: FnMut() -> bool> Work<F> {
    fn check(&mut self) -> Result<(), CoverError> {
        if (self.cancelled)() {
            Err(CoverError::Cancelled)
        } else {
            Ok(())
        }
    }
    fn charge(&mut self, counter: &'static str, amount: u64) -> Result<(), CoverError> {
        self.check()?;
        Ok(self.meter.tick_n(counter, amount)?)
    }
}

struct Prepared<'a> {
    graph: &'a WeightedGraph,
    sensors: Vec<String>,
    costs: Vec<u64>,
    zone_observers: Vec<u32>,
    baseline: u32,
    candidates: Vec<&'a PlacementCandidate>,
    candidate_bits: Vec<u32>,
    entries: Vec<u32>,
    targets: Vec<bool>,
    input_digest: ContentDigest,
    input_bytes: u64,
}

fn valid_id(id: &str) -> Result<(), CoverError> {
    if id.is_empty() || id.len() > MAX_NODE_ID_LEN || id.chars().any(char::is_control) {
        Err(GraphError::InvalidNodeId(id.to_owned()).into())
    } else {
        Ok(())
    }
}

fn valid_unit(unit: &str) -> bool {
    !unit.is_empty()
        && unit.len() <= crate::weighted::MAX_UNIT_LEN
        && unit
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":_-.".contains(&byte))
}

fn prepare<'a, F: FnMut() -> bool>(
    graph: &'a WeightedGraph,
    query: &'a PlacementQuery,
    work: &mut Work<F>,
) -> Result<Prepared<'a>, CoverError> {
    work.check()?;
    if !valid_unit(&query.disable_cost_unit) || !valid_unit(&query.installation_cost_unit) {
        return Err(CoverError::InvalidConstraints(
            "cost units must be bounded explicit identifiers",
        ));
    }
    if graph.node_count() > MAX_ZONES
        || graph.arc_count() > MAX_ARCS
        || query.candidates.len() > MAX_CANDIDATES
        || query.baseline.costs.len() + query.candidates.len() > MAX_TOTAL_SENSORS
        || query.baseline.observers.len() > MAX_ZONES
        || query.baseline.entries.len() > MAX_ZONES
        || query.baseline.targets.len() > MAX_ZONES
    {
        return Err(GraphError::TooLarge.into());
    }
    if query.maximum_additions > MAX_CANDIDATES {
        return Err(CoverError::InvalidConstraints(
            "addition count exceeds the hard limit",
        ));
    }
    if query.baseline.entries.is_empty() || query.baseline.targets.is_empty() {
        return Err(CoverError::InvalidConstraints(
            "placement needs explicit entry and target zones",
        ));
    }
    let mut declared = query.baseline.costs.clone();
    let mut candidates: Vec<_> = query.candidates.iter().collect();
    candidates.sort_by(|a, b| a.sensor.cmp(&b.sensor));
    for candidate in &candidates {
        if candidate.observes.len() > MAX_ZONES {
            return Err(GraphError::TooLarge.into());
        }
        valid_id(&candidate.sensor)?;
        if declared
            .insert(candidate.sensor.clone(), candidate.disable_cost)
            .is_some()
        {
            return Err(CoverError::InvalidConstraints(
                "candidate identities must be fresh and unique",
            ));
        }
    }
    let sensors: Vec<String> = declared.keys().cloned().collect();
    let mut costs = Vec::with_capacity(sensors.len());
    let mut total_cost = 0_u64;
    for (sensor, &cost) in &declared {
        valid_id(sensor)?;
        total_cost = total_cost
            .checked_add(cost)
            .ok_or(GraphError::ArithmeticOverflow("total sensor-disable cost"))?;
        costs.push(cost);
    }
    let sensor_index: BTreeMap<&str, usize> = sensors
        .iter()
        .enumerate()
        .map(|(i, s)| (s.as_str(), i))
        .collect();
    let mut baseline = 0_u32;
    for sensor in query.baseline.costs.keys() {
        baseline |= 1_u32 << sensor_index[sensor.as_str()];
    }
    let mut zone_observers = vec![0_u32; graph.node_count()];
    let mut incidences = 0_u64;
    for (zone, observers) in &query.baseline.observers {
        if observers.len() > MAX_TOTAL_SENSORS {
            return Err(GraphError::TooLarge.into());
        }
        let node = graph.require(zone)? as usize;
        for sensor in observers {
            if !query.baseline.costs.contains_key(sensor) {
                return Err(CoverError::InvalidConstraints(
                    "every baseline observer needs a disable cost",
                ));
            }
            zone_observers[node] |= 1_u32 << sensor_index[sensor.as_str()];
            incidences += 1;
        }
    }
    let mut candidate_bits = Vec::with_capacity(candidates.len());
    for candidate in &candidates {
        let bit = 1_u32 << sensor_index[candidate.sensor.as_str()];
        candidate_bits.push(bit);
        for zone in &candidate.observes {
            zone_observers[graph.require(zone)? as usize] |= bit;
            incidences += 1;
        }
    }
    let entries = query
        .baseline
        .entries
        .iter()
        .map(|id| graph.require(id))
        .collect::<Result<Vec<_>, _>>()?;
    let mut targets = vec![false; graph.node_count()];
    for target in &query.baseline.targets {
        targets[graph.require(target)? as usize] = true;
    }
    work.charge(
        "input_entries",
        (graph.node_count()
            + graph.arc_count()
            + sensors.len()
            + candidates.len()
            + query.baseline.observers.len()
            + entries.len()
            + query.baseline.targets.len()) as u64
            + incidences,
    )?;
    let mut input = CanonicalEncoder::new();
    input.text(INPUT_DOMAIN);
    input.text(IDENTITY.implementation_id);
    input.digest(graph.digest());
    input.text(&query.disable_cost_unit);
    input.text(&query.installation_cost_unit);
    input.u64(query.baseline.costs.len() as u64);
    for (sensor, cost) in &query.baseline.costs {
        input.text(sensor);
        input.u64(*cost);
    }
    input.u64(query.baseline.observers.len() as u64);
    for (zone, observers) in &query.baseline.observers {
        input.text(zone);
        encode_ids(&mut input, &observers.iter().cloned().collect::<Vec<_>>());
    }
    encode_ids(
        &mut input,
        &query.baseline.entries.iter().cloned().collect::<Vec<_>>(),
    );
    encode_ids(
        &mut input,
        &query.baseline.targets.iter().cloned().collect::<Vec<_>>(),
    );
    input.u64(candidates.len() as u64);
    for candidate in &candidates {
        input.text(&candidate.sensor);
        encode_ids(
            &mut input,
            &candidate.observes.iter().cloned().collect::<Vec<_>>(),
        );
        input.u64(candidate.disable_cost);
        input.u64(candidate.installation_cost);
    }
    input.u64(query.installation_budget);
    input.u64(query.maximum_additions as u64);
    if input.has_error() {
        return Err(GraphError::TooLarge.into());
    }
    let bytes = input.finish();
    Ok(Prepared {
        graph,
        sensors,
        costs,
        zone_observers,
        baseline,
        candidates,
        candidate_bits,
        entries,
        targets,
        input_digest: ContentDigest::sha256(&bytes),
        input_bytes: bytes.len() as u64,
    })
}

// Fewest vertices, then lexicographically smallest node tuple. Every queued node is open.
fn walk<F: FnMut() -> bool>(
    prepared: &Prepared<'_>,
    working: u32,
    work: &mut Work<F>,
) -> Result<Option<Vec<String>>, CoverError> {
    work.charge("path_searches", 1)?;
    let graph = prepared.graph;
    let mut parent = vec![u32::MAX; graph.node_count()];
    let mut seen = vec![false; graph.node_count()];
    let mut queue = VecDeque::new();
    for &entry in &prepared.entries {
        work.charge("entry_checks", 1)?;
        if prepared.zone_observers[entry as usize] & working == 0 {
            seen[entry as usize] = true;
            queue.push_back(entry);
        }
    }
    while let Some(node) = queue.pop_front() {
        work.charge("zone_visits", 1)?;
        if prepared.targets[node as usize] {
            let mut path = Vec::new();
            let mut current = node;
            loop {
                work.charge("path_entries", 1)?;
                path.push(graph.id(current).to_owned());
                let prior = parent[current as usize];
                if prior == u32::MAX {
                    break;
                }
                current = prior;
            }
            path.reverse();
            return Ok(Some(path));
        }
        for &arc in graph.out_arcs(node) {
            work.charge("arc_scans", 1)?;
            let next = match graph.orientation() {
                Orientation::Directed => graph.arc(arc).head,
                Orientation::Undirected => graph.arc(arc).other(node),
            };
            if !seen[next as usize] && prepared.zone_observers[next as usize] & working == 0 {
                seen[next as usize] = true;
                parent[next as usize] = node;
                queue.push_back(next);
            }
        }
    }
    Ok(None)
}

fn exact_loss<F: FnMut() -> bool>(
    prepared: &Prepared<'_>,
    active: u32,
    work: &mut Work<F>,
) -> Result<InterdictionOutcome, CoverError> {
    work.charge("inner_solves", 1)?;
    if let Some(path) = walk(prepared, active, work)? {
        return Ok(InterdictionOutcome::BlindPath { path });
    }
    work.charge("observer_masks", prepared.zone_observers.len() as u64)?;
    let observed = prepared
        .zone_observers
        .iter()
        .fold(0_u32, |all, mask| all | mask);
    let relevant: Vec<usize> = (0..prepared.sensors.len())
        .filter(|&bit| active & observed & (1 << bit) != 0)
        .collect();
    work.charge("sensor_checks", prepared.sensors.len() as u64)?;
    let mut best: Option<(u64, Vec<usize>, Vec<String>)> = None;
    for subset in 1_u32..(1_u32 << relevant.len()) {
        work.charge("removal_branches", 1)?;
        let mut removed = 0_u32;
        let mut cost = 0_u64;
        let mut selected = Vec::new();
        for (bit, &sensor) in relevant.iter().enumerate() {
            work.charge("sensor_checks", 1)?;
            if subset & (1 << bit) != 0 {
                removed |= 1 << sensor;
                // prepare() proved the sum of all declared sensor costs fits u64.
                cost += prepared.costs[sensor];
                selected.push(sensor);
            }
        }
        if best.as_ref().is_some_and(|(best_cost, best_set, _)| {
            (cost, selected.len(), &selected) >= (*best_cost, best_set.len(), best_set)
        }) {
            continue;
        }
        if let Some(path) = walk(prepared, active & !removed, work)? {
            best = Some((cost, selected, path));
        }
    }
    let (cost, selected, path) = best.ok_or_else(|| {
        GraphError::Inconsistent("reachable movement graph has no exact interdiction".to_owned())
    })?;
    Ok(InterdictionOutcome::Interdiction {
        sensors: selected
            .into_iter()
            .map(|index| prepared.sensors[index].clone())
            .collect(),
        cost,
        path,
        exact: true,
    })
}

fn loss(outcome: &InterdictionOutcome) -> u64 {
    match outcome {
        InterdictionOutcome::Interdiction { cost, .. } => *cost,
        InterdictionOutcome::BlindPath { .. } | InterdictionOutcome::Unreachable => 0,
    }
}

/// Select the exact best affordable additions with no cancellation source.
pub fn select_robust_placement(
    graph: &WeightedGraph,
    query: &PlacementQuery,
    budget: CoverBudget,
) -> Result<CertifiedRun<PlacementOutput>, CoverError> {
    select_robust_placement_with_cancel(graph, query, budget, || false)
}

/// Exact selection with one cooperative cancellation probe polled at each charged step.
/// The budget covers input work, every placement, every inner removal and all BFS walks.
/// Hard structural ceilings apply even to trivial or unaffordable input. Success emits both
/// baseline and selected exact witnesses; failure never emits an incumbent as an optimum.
pub fn select_robust_placement_with_cancel(
    graph: &WeightedGraph,
    query: &PlacementQuery,
    budget: CoverBudget,
    cancelled: impl FnMut() -> bool,
) -> Result<CertifiedRun<PlacementOutput>, CoverError> {
    let mut work = Work {
        meter: Meter::new(
            &IDENTITY,
            Budget::new(
                budget.max_work_units.min(MAX_WORK_UNITS),
                budget.max_output_entries.min(MAX_OUTPUT_ENTRIES),
            ),
        ),
        cancelled,
    };
    let prepared = prepare(graph, query, &mut work)?;
    // With every sensor disabled this checks only declared movement connectivity.
    let connected = walk(&prepared, 0, &mut work)?.is_some();
    let baseline = if connected {
        exact_loss(&prepared, prepared.baseline, &mut work)?
    } else {
        InterdictionOutcome::Unreachable
    };
    let mut output = PlacementOutput {
        selected_sensors: Vec::new(),
        installation_cost: 0,
        baseline: baseline.clone(),
        defended: baseline,
        evaluated_placements: 1,
    };
    work.charge("placement_branches", 1)?;
    if connected {
        for subset in 1_u32..(1_u32 << prepared.candidates.len()) {
            work.charge("placement_branches", 1)?;
            if subset.count_ones() as usize > query.maximum_additions {
                continue;
            }
            let mut remaining = query.installation_budget;
            let mut active = prepared.baseline;
            let mut selected = Vec::new();
            let mut affordable = true;
            for (bit, candidate) in prepared.candidates.iter().enumerate() {
                work.charge("sensor_checks", 1)?;
                if subset & (1 << bit) == 0 {
                    continue;
                }
                let Some(next) = remaining.checked_sub(candidate.installation_cost) else {
                    affordable = false;
                    break;
                };
                remaining = next;
                active |= prepared.candidate_bits[bit];
                selected.push(candidate.sensor.clone());
            }
            if !affordable {
                continue;
            }
            let cost = query.installation_budget - remaining;
            let defended = exact_loss(&prepared, active, &mut work)?;
            output.evaluated_placements += 1;
            if loss(&defended) > loss(&output.defended)
                || (loss(&defended) == loss(&output.defended)
                    && (cost, selected.len(), &selected)
                        < (
                            output.installation_cost,
                            output.selected_sensors.len(),
                            &output.selected_sensors,
                        ))
            {
                output.selected_sensors = selected;
                output.installation_cost = cost;
                output.defended = defended;
            }
        }
    }
    work.check()?;
    output.encode(work.meter.path());
    let operations = work.meter.operations();
    work.meter.path().u64(operations);
    let (n, m, s, p) = (
        graph.node_count() as u64,
        graph.arc_count() as u64,
        prepared.sensors.len() as u64,
        prepared.candidates.len() as u64,
    );
    let bounds = bound(n, m, s, p);
    // Conservative deterministic workspace accounting, excluding caller-owned inputs.
    let peak =
        prepared.input_bytes + (n * 4 + s * 6 + p * 4) * (MAX_NODE_ID_LEN as u64 + 32) + n * 24;
    let run = work.meter.finish(
        &IDENTITY,
        InputShape {
            node_count: n,
            edge_count: m,
            input_digest: prepared.input_digest,
        },
        output,
        &bounds,
        peak,
    )?;
    Ok(run)
}
