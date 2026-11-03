#![forbid(unsafe_code)]
//! Camera additions evaluated against shared power, network, clock or host failures.
//!
//! Every declared sensor retains its individual disable action at the existing cost. Additional
//! owner-declared actions disable all their active members together. Action costs are additive;
//! memberships are unioned, so an overlapping sensor is disabled once. Costs are declared loss
//! units, not probabilities, measured failure rates, or evidence of independent failure domains.
//!
//! For each affordable placement, the exact search finds the cheapest action set opening an
//! unobserved entry-to-target walk. The full catalog, including unselected candidates and actions,
//! is bound into the input. All searches share one cumulative budget and cancellation probe.
//! Exhaustion returns no answer. The original individual-loss API and canonical bytes are unchanged.

use std::collections::BTreeSet;

use fss_core::{CanonicalEncoder, ContentDigest};

use super::{MAX_TOTAL_SENSORS, PlacementQuery, Prepared, Work, prepare, valid_id, walk};
use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, encode_ids, mul,
};
use crate::graph::{GraphError, MAX_NODE_ID_LEN};
use crate::set_cover::{CoverBudget, CoverError, MAX_OUTPUT_ENTRIES, MAX_WORK_UNITS};
use crate::weighted::WeightedGraph;

/// Hard ceiling on declared common-dependency actions, in addition to individual sensor actions.
pub const MAX_SHARED_ACTIONS: usize = 16;
/// Canonical input binds the unchanged placement input plus every shared action.
pub const INPUT_DOMAIN: &str = "fss.graph.shared_failure_placement_input.v1";
/// Exact placement and baseline/defended action witnesses.
pub const OUTPUT_DOMAIN: &str = "fss.graph.shared_failure_placement_output.v1";
/// Deterministic exhaustive-search summary, not a retained per-branch transcript.
pub const DECISION_DOMAIN: &str = "fss.graph.shared_failure_placement_decision_summary.v1";

/// Additive shared-failure mode of the existing registered algorithm family.
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-INTERDICT-001",
    algorithm_name: "network_interdiction_and_robust_placement",
    tie_break_rule: "maximum minimum action cost, then installation cost, cardinality and sensor tuple; loss ties by action count and typed identity tuple",
    complexity_witness: "placement branches, action subsets, path searches and adjacency scans",
    output_size_witness: "selected additions plus baseline and selected action sets, affected sensors and witness paths",
    exactness: "bounded_exact",
    implementation_id: "fss-graph-algorithms:alg-interdict-001:exact-shared-failure-placement:v1",
    tie_break_policy_id: "tie:maximum-minimum-action-cost-then-install-cost-count-sensor-tuple:loss-cost-count-typed-action-tuple:v1",
    policy_id: "placement-policy:exact-only:declared-observers:individual-and-shared-actions:union-members:additive-action-costs:separate-u64-install-loss-units:v1",
    complexity_bound_id: "bound:alg-interdict-001:placement-subsets-times-action-subsets-times-linear-search:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_DOMAIN,
};

/// One owner assertion about a shared dependency. It grants no effect authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailureAction {
    /// Unique identity within the shared-action namespace, for example `power:garage`.
    pub id: String,
    /// Cost of this action in `placement.disable_cost_unit`, charged once if selected.
    pub cost: u64,
    /// Complete declared membership, including hypothetical cameras not ultimately installed.
    pub members: BTreeSet<String>,
}

/// Namespaces remain distinct even when a sensor and shared action have the same raw label.
/// Canonical ordering is individual sensors first, then shared actions, lexically within each.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ActionIdentity {
    /// Disable this individual sensor at its declared cost.
    Sensor(String),
    /// Disable all active members of this declared shared action.
    Shared(String),
}

impl ActionIdentity {
    fn encode(&self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::Sensor(id) => {
                encoder.tag(0);
                encoder.text(id);
            }
            Self::Shared(id) => {
                encoder.tag(1);
                encoder.text(id);
            }
        }
    }
}

/// All installation, movement, individual loss and shared-failure assumptions for one request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedFailureQuery {
    /// Existing placement semantics, including implicit individual sensor actions and costs.
    pub placement: PlacementQuery,
    /// Additional shared actions. Input order has no semantic effect; duplicate IDs are refused.
    pub actions: Vec<FailureAction>,
}

/// Exact vulnerability conditional on the complete declared movement and failure model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FailureOutcome {
    /// A walk is already unobserved without any failure action.
    BlindPath {
        /// Fewest vertices, then lexicographically smallest node tuple.
        path: Vec<String>,
    },
    /// The cheapest action set opening an unobserved walk.
    Interdiction {
        /// Canonical typed actions, ties by cost, then count, then this tuple.
        actions: Vec<ActionIdentity>,
        /// Union of active members disabled by these actions, in ascending identity order.
        sensors: Vec<String>,
        /// Additive action cost; shared members are not charged again individually.
        cost: u64,
        /// Fewest vertices, then lexicographically smallest node tuple.
        path: Vec<String>,
    },
    /// No entry-to-target walk exists even with all sensors disabled; no coverage claim follows.
    Unreachable,
}

impl FailureOutcome {
    fn loss(&self) -> u64 {
        match self {
            Self::Interdiction { cost, .. } => *cost,
            Self::BlindPath { .. } | Self::Unreachable => 0,
        }
    }

    fn entries(&self) -> u64 {
        match self {
            Self::BlindPath { path } => path.len() as u64 + 1,
            Self::Interdiction {
                actions,
                sensors,
                path,
                ..
            } => (actions.len() + sensors.len() + path.len()) as u64 + 3,
            Self::Unreachable => 1,
        }
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::BlindPath { path } => {
                encoder.tag(0);
                encode_ids(encoder, path);
            }
            Self::Interdiction {
                actions,
                sensors,
                cost,
                path,
            } => {
                encoder.tag(1);
                encoder.u64(actions.len() as u64);
                for action in actions {
                    action.encode(encoder);
                }
                encode_ids(encoder, sensors);
                encoder.u64(*cost);
                encode_ids(encoder, path);
            }
            Self::Unreachable => encoder.tag(2),
        }
    }
}

/// Complete advisory optimum over the supplied catalog, with its actual shared-failure witnesses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedPlacementOutput {
    /// Selected additions in ascending sensor identity order.
    pub selected_sensors: Vec<String>,
    /// Total installation cost, in the independently declared installation unit.
    pub installation_cost: u64,
    /// Exact vulnerability before installation, under the same declared failure actions.
    pub baseline: FailureOutcome,
    /// Exact vulnerability after installing only the selected additions.
    pub defended: FailureOutcome,
    /// Affordable subsets within the count limit whose exact vulnerability was evaluated.
    pub evaluated_placements: u64,
}

impl CertifiedOutput for SharedPlacementOutput {
    fn entries(&self) -> u64 {
        self.selected_sensors.len() as u64 + self.baseline.entries() + self.defended.entries() + 2
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encode_ids(encoder, &self.selected_sensors);
        encoder.u64(self.installation_cost);
        self.baseline.encode(encoder);
        self.defended.encode(encoder);
        encoder.u64(self.evaluated_placements);
    }
}

/// Saturating conservative bounds, never saturating semantic cost arithmetic.
/// `s` includes all declared sensors, `p` all candidate additions and `d` all shared actions.
#[must_use]
pub fn bound(n: u64, m: u64, s: u64, p: u64, d: u64) -> Vec<BoundRow> {
    let actions = add(s, d);
    let placements = if p < 64 { 1_u64 << p } else { u64::MAX };
    let removals = if actions < 64 {
        1_u64 << actions
    } else {
        u64::MAX
    };
    let searches = add(1, mul(placements, add(1, removals)));
    vec![
        (
            "input_entries",
            add(add(mul(5, n), m), add(mul(n, s), add(s, p))),
        ),
        ("failure_action_entries", add(s, mul(d, add(s, 1)))),
        ("placement_branches", placements),
        ("inner_solves", placements),
        ("removal_branches", mul(placements, removals)),
        ("sensor_checks", mul(placements, p)),
        (
            "action_checks",
            mul(placements, add(actions, mul(removals, actions))),
        ),
        ("loss_witness_entries", mul(placements, add(s, actions))),
        ("observer_masks", mul(placements, n)),
        ("path_searches", searches),
        ("entry_checks", mul(searches, n)),
        ("zone_visits", mul(searches, n)),
        ("arc_scans", mul(searches, mul(2, m))),
        ("path_entries", mul(searches, n)),
        (
            OUTPUT_ENTRIES,
            add(p, add(mul(2, add(n, add(s, actions))), 8)),
        ),
    ]
}

struct PreparedAction {
    identity: ActionIdentity,
    cost: u64,
    members: u32,
}

fn prepare_actions<F: FnMut() -> bool>(
    prepared: &Prepared<'_>,
    query: &SharedFailureQuery,
    work: &mut Work<F>,
) -> Result<(Vec<PreparedAction>, ContentDigest, u64), CoverError> {
    if query.actions.len() > MAX_SHARED_ACTIONS {
        return Err(GraphError::TooLarge.into());
    }
    let mut total = 0_u64;
    let mut actions = Vec::with_capacity(prepared.sensors.len() + query.actions.len());
    for (index, sensor) in prepared.sensors.iter().enumerate() {
        work.charge("failure_action_entries", 1)?;
        total = total
            .checked_add(prepared.costs[index])
            .ok_or(GraphError::ArithmeticOverflow("total failure-action cost"))?;
        actions.push(PreparedAction {
            identity: ActionIdentity::Sensor(sensor.clone()),
            cost: prepared.costs[index],
            members: 1_u32 << index,
        });
    }
    let mut shared: Vec<_> = query.actions.iter().collect();
    shared.sort_by(|a, b| a.id.cmp(&b.id));
    let mut input = CanonicalEncoder::new();
    input.text(INPUT_DOMAIN);
    input.text(IDENTITY.implementation_id);
    input.digest(prepared.input_digest);
    input.u64(shared.len() as u64);
    let mut prior: Option<&str> = None;
    for action in shared {
        work.charge("failure_action_entries", 1)?;
        valid_id(&action.id)?;
        if prior == Some(action.id.as_str()) {
            return Err(CoverError::InvalidConstraints(
                "duplicate shared failure action",
            ));
        }
        prior = Some(&action.id);
        if action.members.is_empty() {
            return Err(CoverError::InvalidConstraints(
                "shared failure action needs members",
            ));
        }
        if action.members.len() > MAX_TOTAL_SENSORS {
            return Err(GraphError::TooLarge.into());
        }
        total = total
            .checked_add(action.cost)
            .ok_or(GraphError::ArithmeticOverflow("total failure-action cost"))?;
        let mut members = 0_u32;
        input.text(&action.id);
        input.u64(action.cost);
        input.u64(action.members.len() as u64);
        for sensor in &action.members {
            work.charge("failure_action_entries", 1)?;
            valid_id(sensor)?;
            let index = prepared
                .sensors
                .binary_search(sensor)
                .map_err(|_| GraphError::UnknownNode(sensor.clone()))?;
            members |= 1_u32 << index;
            input.text(sensor);
        }
        actions.push(PreparedAction {
            identity: ActionIdentity::Shared(action.id.clone()),
            cost: action.cost,
            members,
        });
    }
    if input.has_error() {
        return Err(GraphError::TooLarge.into());
    }
    let bytes = input.finish();
    Ok((actions, ContentDigest::sha256(&bytes), bytes.len() as u64))
}

fn exact_loss<F: FnMut() -> bool>(
    prepared: &Prepared<'_>,
    actions: &[PreparedAction],
    active: u32,
    work: &mut Work<F>,
) -> Result<FailureOutcome, CoverError> {
    work.charge("inner_solves", 1)?;
    if let Some(path) = walk(prepared, active, work)? {
        return Ok(FailureOutcome::BlindPath { path });
    }
    work.charge("observer_masks", prepared.zone_observers.len() as u64)?;
    let observed = prepared
        .zone_observers
        .iter()
        .fold(0_u32, |all, mask| all | mask);
    let mut relevant = Vec::new();
    for (index, action) in actions.iter().enumerate() {
        work.charge("action_checks", 1)?;
        if action.members & active & observed != 0 {
            relevant.push(index);
        }
    }
    // At most 20 individual + 16 shared actions; the shift and all sensor masks are bounded.
    let mut best: Option<(u64, Vec<usize>, u32, Vec<String>)> = None;
    for subset in 1_u64..(1_u64 << relevant.len()) {
        work.charge("removal_branches", 1)?;
        let mut removed = 0_u32;
        let mut cost = 0_u64;
        let mut selected = Vec::new();
        for (bit, &index) in relevant.iter().enumerate() {
            work.charge("action_checks", 1)?;
            if subset & (1_u64 << bit) != 0 {
                let action = &actions[index];
                removed |= action.members & active;
                // Admission proved the sum of ALL declared action costs fits u64.
                cost += action.cost;
                selected.push(index);
            }
        }
        if best.as_ref().is_some_and(|(best_cost, best_set, _, _)| {
            (cost, selected.len(), &selected) >= (*best_cost, best_set.len(), best_set)
        }) {
            continue;
        }
        if let Some(path) = walk(prepared, active & !removed, work)? {
            best = Some((cost, selected, removed, path));
        }
    }
    let (cost, selected, removed, path) = best.ok_or_else(|| {
        GraphError::Inconsistent("reachable movement graph has no exact failure action set".into())
    })?;
    work.charge(
        "loss_witness_entries",
        (selected.len() + prepared.sensors.len()) as u64,
    )?;
    Ok(FailureOutcome::Interdiction {
        actions: selected
            .into_iter()
            .map(|i| actions[i].identity.clone())
            .collect(),
        sensors: prepared
            .sensors
            .iter()
            .enumerate()
            .filter(|(i, _)| removed & (1_u32 << i) != 0)
            .map(|(_, sensor)| sensor.clone())
            .collect(),
        cost,
        path,
    })
}

/// Exact shared-failure placement without a cancellation source.
pub fn select_robust_placement(
    graph: &WeightedGraph,
    query: &SharedFailureQuery,
    budget: CoverBudget,
) -> Result<CertifiedRun<SharedPlacementOutput>, CoverError> {
    select_robust_placement_with_cancel(graph, query, budget, || false)
}

/// Exact selection under one cumulative work/output allowance and cooperative cancellation.
///
/// An action can contain any baseline or candidate sensor. Its selected loss disables only
/// installed members. Unknown members, duplicate IDs, empty membership, invalid units, arithmetic
/// overflow, structural limits, budget exhaustion and cancellation return no partial optimum.
/// Empty `actions` is legal and has the same objective as the original individual-loss mode.
pub fn select_robust_placement_with_cancel(
    graph: &WeightedGraph,
    query: &SharedFailureQuery,
    budget: CoverBudget,
    cancelled: impl FnMut() -> bool,
) -> Result<CertifiedRun<SharedPlacementOutput>, CoverError> {
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
    work.check()?;
    if query.actions.len() > MAX_SHARED_ACTIONS {
        return Err(GraphError::TooLarge.into());
    }
    let prepared = prepare(graph, &query.placement, &mut work)?;
    let (actions, input_digest, input_bytes) = prepare_actions(&prepared, query, &mut work)?;
    let connected = walk(&prepared, 0, &mut work)?.is_some();
    let baseline = if connected {
        exact_loss(&prepared, &actions, prepared.baseline, &mut work)?
    } else {
        FailureOutcome::Unreachable
    };
    let mut output = SharedPlacementOutput {
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
            if subset.count_ones() as usize > query.placement.maximum_additions {
                continue;
            }
            let mut remaining = query.placement.installation_budget;
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
            let cost = query.placement.installation_budget - remaining;
            let defended = exact_loss(&prepared, &actions, active, &mut work)?;
            output.evaluated_placements += 1;
            if defended.loss() > output.defended.loss()
                || (defended.loss() == output.defended.loss()
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
    let (n, m, s, p, d) = (
        graph.node_count() as u64,
        graph.arc_count() as u64,
        prepared.sensors.len() as u64,
        prepared.candidates.len() as u64,
        query.actions.len() as u64,
    );
    let bounds = bound(n, m, s, p, d);
    // Conservative workspace accounting, excluding caller-owned immutable inputs.
    let peak = input_bytes
        + prepared.input_bytes
        + (n * 4 + s * 6 + p * 4 + (s + d) * 4) * (MAX_NODE_ID_LEN as u64 + 32)
        + n * 24;
    Ok(work.meter.finish(
        &IDENTITY,
        InputShape {
            node_count: n,
            edge_count: m,
            input_digest,
        },
        output,
        &bounds,
        peak,
    )?)
}
