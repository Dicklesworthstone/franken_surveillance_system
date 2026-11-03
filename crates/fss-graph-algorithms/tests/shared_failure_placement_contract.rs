#![forbid(unsafe_code)]
//! Shared-loss placement checked against an independent simple-path/set-cover oracle.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::{Rng, TestResult};
use fss_core::LedgerAnchor;
use fss_graph_algorithms::GraphError;
use fss_graph_algorithms::certified::{CertifiedOutput, check_witness};
use fss_graph_algorithms::interdiction::{InterdictionOutcome, InterdictionQuery};
use fss_graph_algorithms::robust_placement::{
    self, PlacementCandidate, PlacementQuery,
    shared_failures::{
        self, ActionIdentity, FailureAction, FailureOutcome, SharedFailureQuery,
        SharedPlacementOutput, select_robust_placement, select_robust_placement_with_cancel,
    },
};
use fss_graph_algorithms::set_cover::{
    CoverBudget, CoverError, MAX_OUTPUT_ENTRIES, MAX_WORK_UNITS,
};
use fss_graph_algorithms::weighted::{Orientation, WeightedGraph, WeightedGraphBuilder};

type OracleCut = (u64, Vec<ActionIdentity>, Vec<String>, Vec<String>);

fn ids(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|s| (*s).to_owned()).collect()
}

fn budget() -> CoverBudget {
    CoverBudget {
        max_work_units: MAX_WORK_UNITS,
        max_output_entries: MAX_OUTPUT_ENTRIES,
    }
}

fn action(id: &str, cost: u64, members: &[&str]) -> FailureAction {
    FailureAction {
        id: id.into(),
        cost,
        members: ids(members),
    }
}

fn line() -> TestResult<WeightedGraph> {
    let mut graph = WeightedGraphBuilder::directed("movement");
    graph.add_node("entry");
    graph.add_node("target");
    graph.add_arc("entry", "target", 0);
    Ok(graph.build()?)
}

fn query() -> SharedFailureQuery {
    SharedFailureQuery {
        placement: PlacementQuery {
            baseline: InterdictionQuery {
                observers: BTreeMap::from([("entry".into(), ids(&["existing"]))]),
                costs: BTreeMap::from([("existing".into(), 10)]),
                entries: ids(&["entry"]),
                targets: ids(&["target"]),
            },
            candidates: vec![
                PlacementCandidate {
                    sensor: "cheap-shared".into(),
                    observes: ids(&["entry"]),
                    disable_cost: 20,
                    installation_cost: 1,
                },
                PlacementCandidate {
                    sensor: "separate-power".into(),
                    observes: ids(&["target"]),
                    disable_cost: 10,
                    installation_cost: 2,
                },
            ],
            disable_cost_unit: "loss-points".into(),
            installation_cost_unit: "installation-points".into(),
            installation_budget: 2,
            maximum_additions: 1,
        },
        actions: vec![action("power:garage", 1, &["existing", "cheap-shared"])],
    }
}

fn loss(outcome: &FailureOutcome) -> u64 {
    match outcome {
        FailureOutcome::Interdiction { cost, .. } => *cost,
        _ => 0,
    }
}

#[test]
fn separate_power_changes_the_actual_camera_recommendation() -> TestResult {
    let graph = line()?;
    let query = query();
    let independent =
        robust_placement::select_robust_placement(&graph, &query.placement, budget())?;
    assert_eq!(independent.output.selected_sensors, ["cheap-shared"]);
    let shared = select_robust_placement(&graph, &query, budget())?;
    assert_eq!(shared.output.selected_sensors, ["separate-power"]);
    assert_eq!(shared.output.installation_cost, 2);
    assert_eq!(loss(&shared.output.baseline), 1);
    assert_eq!(
        shared.output.defended,
        FailureOutcome::Interdiction {
            actions: vec![
                ActionIdentity::Sensor("separate-power".into()),
                ActionIdentity::Shared("power:garage".into())
            ],
            sensors: vec!["existing".into(), "separate-power".into()],
            cost: 11,
            path: vec!["entry".into(), "target".into()],
        }
    );
    // An uninstalled camera may belong to a selected domain, but never appears as disabled.
    assert!(!format!("{:?}", shared.output.defended).contains("cheap-shared"));
    Ok(())
}

#[test]
fn overlapping_actions_charge_once_and_union_all_active_members() -> TestResult {
    let graph = line()?;
    let mut query = query();
    query.placement.candidates.clear();
    query.placement.baseline.costs = ["a", "b", "c", "idle"]
        .into_iter()
        .map(|s| (s.to_owned(), 10))
        .collect();
    query.placement.baseline.observers = BTreeMap::from([("entry".into(), ids(&["a", "b", "c"]))]);
    query.actions = vec![
        action("power", 3, &["a", "b", "idle"]),
        action("switch", 4, &["b", "c"]),
    ];
    let run = select_robust_placement(&graph, &query, budget())?;
    assert_eq!(
        run.output.baseline,
        FailureOutcome::Interdiction {
            actions: vec![
                ActionIdentity::Shared("power".into()),
                ActionIdentity::Shared("switch".into())
            ],
            sensors: vec!["a".into(), "b".into(), "c".into(), "idle".into()],
            cost: 7,
            path: vec!["entry".into(), "target".into()],
        }
    );
    assert_eq!(run.output.baseline, run.output.defended);
    Ok(())
}

#[test]
fn typed_action_names_and_cost_count_identity_ties_are_unambiguous() -> TestResult {
    let graph = line()?;
    let mut query = query();
    query.placement.candidates.clear();
    query.placement.baseline.costs = BTreeMap::from([("same".into(), 2)]);
    query.placement.baseline.observers = BTreeMap::from([("entry".into(), ids(&["same"]))]);
    query.actions = vec![action("same", 2, &["same"]), action("a", 2, &["same"])];
    let first = select_robust_placement(&graph, &query, budget())?;
    assert!(
        matches!(first.output.baseline, FailureOutcome::Interdiction { actions, cost: 2, .. }
        if actions == vec![ActionIdentity::Sensor("same".into())])
    );
    query.actions[0].cost = 0;
    query.actions[1].cost = 0;
    let free = select_robust_placement(&graph, &query, budget())?;
    assert!(
        matches!(free.output.baseline, FailureOutcome::Interdiction { actions, cost: 0, .. }
        if actions == vec![ActionIdentity::Shared("a".into())])
    );
    Ok(())
}

// Enumerate SIMPLE paths first. Any unobserved walk has a simple subpath. This oracle then
// solves an ordinary set-cover of each path's active observers using string sets, independently
// of the production mask-union/BFS search. All test graphs have at most five vertices.
fn paths(graph: &WeightedGraph, query: &InterdictionQuery) -> TestResult<Vec<Vec<String>>> {
    fn visit(
        graph: &WeightedGraph,
        node: u32,
        targets: &BTreeSet<String>,
        path: &mut Vec<u32>,
        result: &mut Vec<Vec<String>>,
    ) {
        if targets.contains(graph.id(node)) {
            result.push(path.iter().map(|&n| graph.id(n).to_owned()).collect());
            return;
        }
        let mut next = BTreeSet::new();
        for &arc in graph.out_arcs(node) {
            let arc = graph.arc(arc);
            next.insert(match graph.orientation() {
                Orientation::Directed => arc.head,
                Orientation::Undirected => arc.other(node),
            });
        }
        for node in next {
            if !path.contains(&node) {
                path.push(node);
                visit(graph, node, targets, path, result);
                path.pop();
            }
        }
    }
    let mut result = Vec::new();
    for entry in &query.entries {
        let node = graph.require(entry)?;
        visit(graph, node, &query.targets, &mut vec![node], &mut result);
    }
    result.sort_by(|a, b| (a.len(), a).cmp(&(b.len(), b)));
    result.dedup();
    Ok(result)
}

fn oracle_loss(
    paths: &[Vec<String>],
    query: &SharedFailureQuery,
    selected: &[String],
) -> FailureOutcome {
    let mut active = query.placement.baseline.costs.clone();
    let mut observers = query.placement.baseline.observers.clone();
    for candidate in &query.placement.candidates {
        if selected.contains(&candidate.sensor) {
            active.insert(candidate.sensor.clone(), candidate.disable_cost);
            for zone in &candidate.observes {
                observers
                    .entry(zone.clone())
                    .or_default()
                    .insert(candidate.sensor.clone());
            }
        }
    }
    let requirements: Vec<BTreeSet<String>> = paths
        .iter()
        .map(|path| {
            path.iter()
                .flat_map(|zone| observers.get(zone).into_iter().flatten().cloned())
                .collect()
        })
        .collect();
    if let Some(index) = requirements.iter().position(BTreeSet::is_empty) {
        return FailureOutcome::BlindPath {
            path: paths[index].clone(),
        };
    }
    let mut actions: Vec<(ActionIdentity, u64, BTreeSet<String>)> = active
        .iter()
        .map(|(id, &cost)| {
            (
                ActionIdentity::Sensor(id.clone()),
                cost,
                BTreeSet::from([id.clone()]),
            )
        })
        .chain(query.actions.iter().map(|action| {
            (
                ActionIdentity::Shared(action.id.clone()),
                action.cost,
                action
                    .members
                    .iter()
                    .filter(|id| active.contains_key(*id))
                    .cloned()
                    .collect(),
            )
        }))
        .collect();
    actions.sort_by(|a, b| a.0.cmp(&b.0));
    let mut best: Option<OracleCut> = None;
    for (path, required) in paths.iter().zip(requirements) {
        for subset in 0..(1_usize << actions.len()) {
            let mut covered = BTreeSet::new();
            let mut chosen = Vec::new();
            let mut cost = 0;
            for (bit, (identity, price, members)) in actions.iter().enumerate() {
                if subset & (1 << bit) != 0 {
                    covered.extend(members.iter().cloned());
                    chosen.push(identity.clone());
                    cost += price;
                }
            }
            if required.is_subset(&covered)
                && best.as_ref().is_none_or(|(c, a, _, p)| {
                    (cost, chosen.len(), &chosen, path.len(), path) < (*c, a.len(), a, p.len(), p)
                })
            {
                best = Some((cost, chosen, covered.into_iter().collect(), path.clone()));
            }
        }
    }
    match best {
        Some((cost, actions, sensors, path)) => FailureOutcome::Interdiction {
            actions,
            sensors,
            cost,
            path,
        },
        None => FailureOutcome::Unreachable,
    }
}

fn oracle(graph: &WeightedGraph, query: &SharedFailureQuery) -> TestResult<SharedPlacementOutput> {
    let paths = paths(graph, &query.placement.baseline)?;
    let baseline = oracle_loss(&paths, query, &[]);
    let mut out = SharedPlacementOutput {
        selected_sensors: Vec::new(),
        installation_cost: 0,
        baseline: baseline.clone(),
        defended: baseline,
        evaluated_placements: 1,
    };
    if paths.is_empty() {
        return Ok(out);
    }
    for subset in 1_usize..(1_usize << query.placement.candidates.len()) {
        if subset.count_ones() as usize > query.placement.maximum_additions {
            continue;
        }
        let mut cost = 0_u128;
        let mut selected = Vec::new();
        for (bit, candidate) in query.placement.candidates.iter().enumerate() {
            if subset & (1 << bit) != 0 {
                cost += u128::from(candidate.installation_cost);
                selected.push(candidate.sensor.clone());
            }
        }
        if cost > u128::from(query.placement.installation_budget) {
            continue;
        }
        selected.sort();
        let defended = oracle_loss(&paths, query, &selected);
        out.evaluated_placements += 1;
        let cost = cost as u64;
        if loss(&defended) > loss(&out.defended)
            || (loss(&defended) == loss(&out.defended)
                && (cost, selected.len(), &selected)
                    < (
                        out.installation_cost,
                        out.selected_sensors.len(),
                        &out.selected_sensors,
                    ))
        {
            out.selected_sensors = selected;
            out.installation_cost = cost;
            out.defended = defended;
        }
    }
    Ok(out)
}

#[test]
fn seeded_tiny_directed_and_undirected_instances_match_independent_path_cover_oracle() -> TestResult
{
    for seed in 0..160 {
        let mut rng = Rng(seed ^ 0x7d73_9f2a);
        let orientation = if seed % 2 == 0 {
            Orientation::Directed
        } else {
            Orientation::Undirected
        };
        let mut builder = WeightedGraphBuilder::new(orientation, "movement");
        let nodes: Vec<String> = (0..5).map(|i| format!("n{i}")).collect();
        for node in &nodes {
            builder.add_node(node);
        }
        for from in 0..5 {
            for to in 0..5 {
                if from != to
                    && (orientation == Orientation::Directed || from < to)
                    && rng.chance(330)
                {
                    builder.add_arc(&nodes[from], &nodes[to], rng.next() % 10);
                }
            }
        }
        let graph = builder.build()?;
        let mut query = query();
        query.placement.baseline.entries = ids(&["n0"]);
        if seed % 7 == 0 {
            query.placement.baseline.entries.insert("n1".into());
        }
        query.placement.baseline.targets = ids(&["n4"]);
        if seed % 11 == 0 {
            query.placement.baseline.targets.insert("n0".into());
        }
        query.placement.baseline.observers.clear();
        query.placement.baseline.costs.clear();
        query.placement.candidates.clear();
        let base = rng.below(3) + 1;
        let additions = rng.below(4);
        let mut sensors = Vec::new();
        for i in 0..base {
            let sensor = format!("old{i}");
            query
                .placement
                .baseline
                .costs
                .insert(sensor.clone(), rng.next() % 6);
            for zone in &nodes {
                if rng.chance(350) {
                    query
                        .placement
                        .baseline
                        .observers
                        .entry(zone.clone())
                        .or_default()
                        .insert(sensor.clone());
                }
            }
            sensors.push(sensor);
        }
        for i in 0..additions {
            let sensor = format!("new{i}");
            let observes = nodes.iter().filter(|_| rng.chance(400)).cloned().collect();
            query.placement.candidates.push(PlacementCandidate {
                sensor: sensor.clone(),
                observes,
                disable_cost: rng.next() % 6,
                installation_cost: rng.next() % 4,
            });
            sensors.push(sensor);
        }
        query.placement.maximum_additions = rng.below(4);
        query.placement.installation_budget = rng.next() % 6;
        query.actions.clear();
        for i in 0..(seed % 3) {
            let mut members: BTreeSet<String> = sensors
                .iter()
                .filter(|_| rng.chance(500))
                .cloned()
                .collect();
            if members.is_empty() {
                members.insert(sensors[rng.below(sensors.len())].clone());
            }
            query.actions.push(FailureAction {
                id: format!("shared{i}"),
                cost: rng.next() % 5,
                members,
            });
        }
        let actual = select_robust_placement(&graph, &query, budget())?;
        assert_eq!(actual.output, oracle(&graph, &query)?, "seed {seed}");
        let mut shuffled = query.clone();
        rng.shuffle(&mut shuffled.actions);
        rng.shuffle(&mut shuffled.placement.candidates);
        let reordered = select_robust_placement(&graph, &shuffled, budget())?;
        assert_eq!(actual, reordered, "canonical order seed {seed}");
    }
    Ok(())
}

#[test]
fn no_shared_actions_preserves_individual_objectives_and_witnesses() -> TestResult {
    let graph = line()?;
    let mut query = query();
    query.actions.clear();
    let legacy = robust_placement::select_robust_placement(&graph, &query.placement, budget())?;
    let shared = select_robust_placement(&graph, &query, budget())?;
    assert_eq!(
        legacy.output.selected_sensors,
        shared.output.selected_sensors
    );
    assert_eq!(
        legacy.output.installation_cost,
        shared.output.installation_cost
    );
    assert_eq!(
        legacy.output.evaluated_placements,
        shared.output.evaluated_placements
    );
    for (old, new) in [
        (&legacy.output.baseline, &shared.output.baseline),
        (&legacy.output.defended, &shared.output.defended),
    ] {
        match (old, new) {
            (
                InterdictionOutcome::Interdiction {
                    sensors,
                    cost,
                    path,
                    exact: true,
                },
                FailureOutcome::Interdiction {
                    actions,
                    sensors: new_sensors,
                    cost: new_cost,
                    path: new_path,
                },
            ) => {
                assert_eq!((sensors, cost, path), (new_sensors, new_cost, new_path));
                assert_eq!(
                    actions,
                    &sensors
                        .iter()
                        .cloned()
                        .map(ActionIdentity::Sensor)
                        .collect::<Vec<_>>()
                );
            }
            _ => return Err("fixture must produce exact individual losses".into()),
        }
    }
    assert_ne!(legacy.input_digest, shared.input_digest);
    assert_ne!(legacy.output_digest, shared.output_digest);
    Ok(())
}

#[test]
fn inactive_members_and_redundant_actions_still_bind_input_identity() -> TestResult {
    let graph = line()?;
    let mut query = query();
    query.placement.installation_budget = 0;
    query
        .actions
        .push(action("candidate-only", 5, &["cheap-shared"]));
    let base = select_robust_placement(&graph, &query, budget())?;
    for mutation in 0..4 {
        let mut changed = query.clone();
        match mutation {
            0 => changed.actions[1].cost += 1,
            1 => {
                changed.actions[1].members.insert("separate-power".into());
            }
            2 => changed.actions[1].id.push_str("-changed"),
            _ => changed.placement.disable_cost_unit.push_str("-changed"),
        }
        let other = select_robust_placement(&graph, &changed, budget())?;
        assert_eq!(base.output, other.output);
        assert_ne!(base.input_digest, other.input_digest);
    }
    Ok(())
}

#[test]
fn malformed_memberships_and_limits_refuse_before_any_optimum() -> TestResult {
    let graph = line()?;
    for mutation in 0..7 {
        let mut query = query();
        query.placement.maximum_additions = 0;
        match mutation {
            0 => query.actions.push(query.actions[0].clone()),
            1 => query.actions[0].members.clear(),
            2 => {
                query.actions[0].members.insert("missing".into());
            }
            3 => query.actions[0].id.clear(),
            4 => query.actions[0].id.push('\n'),
            5 => {
                query.actions = (0..=shared_failures::MAX_SHARED_ACTIONS)
                    .map(|i| action(&format!("action{i}"), 0, &["existing"]))
                    .collect()
            }
            _ => {
                query.actions[0].members = (0..=robust_placement::MAX_TOTAL_SENSORS)
                    .map(|i| format!("sensor{i}"))
                    .collect()
            }
        }
        assert!(
            select_robust_placement(&graph, &query, budget()).is_err(),
            "mutation {mutation}"
        );
    }
    Ok(())
}

#[test]
fn semantic_cost_overflow_fails_but_installation_affordability_does_not_wrap() -> TestResult {
    let graph = line()?;
    let mut query = query();
    query.placement.candidates.clear();
    query
        .placement
        .baseline
        .costs
        .insert("existing".into(), u64::MAX);
    query.actions = vec![action("power", 1, &["existing"])];
    assert!(matches!(
        select_robust_placement(&graph, &query, budget()),
        Err(CoverError::Graph(GraphError::ArithmeticOverflow(_)))
    ));
    query.actions[0].cost = 0;
    assert_eq!(
        loss(
            &select_robust_placement(&graph, &query, budget())?
                .output
                .baseline
        ),
        0
    );
    let mut query = self::query();
    query.placement.installation_budget = u64::MAX;
    query.placement.maximum_additions = 2;
    for candidate in &mut query.placement.candidates {
        candidate.installation_cost = u64::MAX;
    }
    let run = select_robust_placement(&graph, &query, budget())?;
    assert_eq!(run.output.evaluated_placements, 3);
    assert_eq!(run.output.installation_cost, u64::MAX);
    assert_eq!(run.output.selected_sensors, ["separate-power"]);
    Ok(())
}

#[test]
fn blind_zero_loss_and_disconnected_outcomes_remain_distinct() -> TestResult {
    let graph = line()?;
    let mut query = query();
    query.placement.candidates.clear();
    query.placement.baseline.observers.clear();
    let blind = select_robust_placement(&graph, &query, budget());
    // Even trivial queries validate a now-unknown candidate membership.
    assert!(blind.is_err());
    query.actions = vec![action("power", 0, &["existing"])];
    let blind = select_robust_placement(&graph, &query, budget())?;
    assert!(matches!(
        blind.output.baseline,
        FailureOutcome::BlindPath { .. }
    ));
    query
        .placement
        .baseline
        .observers
        .insert("entry".into(), ids(&["existing"]));
    let zero = select_robust_placement(&graph, &query, budget())?;
    assert!(matches!(
        zero.output.baseline,
        FailureOutcome::Interdiction { cost: 0, .. }
    ));
    let mut graph = WeightedGraphBuilder::directed("movement");
    graph.add_node("entry");
    graph.add_node("target");
    let none = select_robust_placement(&graph.build()?, &query, budget())?;
    assert_eq!(none.output.baseline, FailureOutcome::Unreachable);
    assert_eq!(none.output.defended, FailureOutcome::Unreachable);
    assert!(none.output.selected_sensors.is_empty());
    Ok(())
}

#[test]
fn cumulative_work_output_and_every_cancellation_probe_fail_without_partial_answer() -> TestResult {
    let graph = line()?;
    let mut query = query();
    query.placement.candidates.truncate(1);
    let run = select_robust_placement(&graph, &query, budget())?;
    let exact = CoverBudget {
        max_work_units: run.operations,
        max_output_entries: run.output.entries(),
    };
    assert_eq!(run, select_robust_placement(&graph, &query, exact)?);
    for max_work_units in [0, 1, run.operations - 1] {
        assert!(matches!(
            select_robust_placement(
                &graph,
                &query,
                CoverBudget {
                    max_work_units,
                    ..exact
                }
            ),
            Err(CoverError::Graph(GraphError::BudgetExhausted { .. }))
        ));
    }
    assert!(matches!(
        select_robust_placement(
            &graph,
            &query,
            CoverBudget {
                max_output_entries: exact.max_output_entries - 1,
                ..exact
            }
        ),
        Err(CoverError::Graph(GraphError::BudgetExhausted { .. }))
    ));
    let mut probes = 0;
    let successful = select_robust_placement_with_cancel(&graph, &query, budget(), || {
        probes += 1;
        false
    })?;
    assert_eq!(successful, run);
    for stop in 1..=probes {
        let mut seen = 0;
        assert!(
            matches!(
                select_robust_placement_with_cancel(&graph, &query, budget(), || {
                    seen += 1;
                    seen == stop
                }),
                Err(CoverError::Cancelled)
            ),
            "probe {stop}/{probes}"
        );
    }
    let witness = run.witness(
        "SensorCoverageGraph:shared-failure-fixture",
        LedgerAnchor::genesis("site:test"),
    )?;
    check_witness(
        &witness,
        &shared_failures::IDENTITY,
        &shared_failures::bound(2, 1, 2, 1, 1),
    )?;
    Ok(())
}

#[test]
fn shared_mode_contract_preserves_the_existing_algorithm_family_and_legacy_identity() -> TestResult
{
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../architecture/shared_failure_placement_reference.json");
    let contract = std::fs::read_to_string(path)?;
    for (field, value) in shared_failures::IDENTITY.registry_fields() {
        assert!(
            contract.contains(&format!("\"{field}\": \"{value}\"")),
            "missing {field}"
        );
    }
    for domain in [
        shared_failures::INPUT_DOMAIN,
        shared_failures::OUTPUT_DOMAIN,
        shared_failures::DECISION_DOMAIN,
    ] {
        assert!(contract.contains(domain));
    }
    assert_eq!(
        shared_failures::IDENTITY.algorithm_id,
        robust_placement::IDENTITY.algorithm_id
    );
    assert_ne!(
        shared_failures::IDENTITY.implementation_id,
        robust_placement::IDENTITY.implementation_id
    );
    assert_eq!(
        robust_placement::IDENTITY.implementation_id,
        "fss-graph-algorithms:alg-interdict-001:exact-robust-placement:v1"
    );
    Ok(())
}
