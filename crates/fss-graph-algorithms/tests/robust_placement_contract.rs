#![forbid(unsafe_code)]
//! Exact placement against exhaustive catalog enumeration and the existing interdiction owner.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::{Rng, TestResult};
use fss_core::{ContentDigest, LedgerAnchor};
use fss_graph_algorithms::GraphError;
use fss_graph_algorithms::certified::{Budget, check_witness};
use fss_graph_algorithms::interdiction::{self, InterdictionOutcome, InterdictionQuery};
use fss_graph_algorithms::robust_placement::{
    self, IDENTITY, MAX_CANDIDATES, MAX_TOTAL_SENSORS, PlacementCandidate, PlacementQuery,
    select_robust_placement, select_robust_placement_with_cancel,
};
use fss_graph_algorithms::set_cover::{
    CoverBudget, CoverError, MAX_OUTPUT_ENTRIES, MAX_WORK_UNITS,
};
use fss_graph_algorithms::weighted::{Orientation, WeightedGraph, WeightedGraphBuilder};

fn ids(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn budget() -> CoverBudget {
    CoverBudget {
        max_work_units: MAX_WORK_UNITS,
        max_output_entries: MAX_OUTPUT_ENTRIES,
    }
}

fn candidate(sensor: &str, zones: &[&str], install: u64, loss: u64) -> PlacementCandidate {
    PlacementCandidate {
        sensor: sensor.into(),
        observes: ids(zones),
        disable_cost: loss,
        installation_cost: install,
    }
}

fn graph(orientation: Orientation) -> Result<WeightedGraph, GraphError> {
    let mut graph = WeightedGraphBuilder::new(orientation, "movement");
    for node in ["entry", "left", "right", "target"] {
        graph.add_node(node);
    }
    for (from, to) in [
        ("entry", "left"),
        ("entry", "right"),
        ("left", "target"),
        ("right", "target"),
    ] {
        graph.add_arc(from, to, 0);
    }
    graph.build()
}

fn query() -> PlacementQuery {
    PlacementQuery {
        baseline: InterdictionQuery {
            observers: BTreeMap::from([
                ("left".into(), ids(&["existing-left"])),
                ("right".into(), ids(&["existing-right"])),
            ]),
            costs: BTreeMap::from([("existing-left".into(), 1), ("existing-right".into(), 4)]),
            entries: ids(&["entry"]),
            targets: ids(&["target"]),
        },
        candidates: vec![
            candidate("new-left", &["left"], 2, 5),
            candidate("new-right", &["right"], 1, 5),
            candidate("idle", &[], 0, 0),
        ],
        disable_cost_unit: "loss-points".into(),
        installation_cost_unit: "cost:usd".into(),
        installation_budget: 2,
        maximum_additions: 3,
    }
}

fn loss(outcome: &InterdictionOutcome) -> u64 {
    match outcome {
        InterdictionOutcome::Interdiction { cost, .. } => *cost,
        _ => 0,
    }
}

fn oracle_loss(
    graph: &WeightedGraph,
    query: &InterdictionQuery,
) -> TestResult<InterdictionOutcome> {
    Ok(
        interdiction::interdiction(graph, query, Budget::new(u64::MAX, u64::MAX))?
            .output
            .outcome,
    )
}

#[test]
fn placement_strengthens_the_weak_route_and_preserves_the_witness() -> TestResult {
    for orientation in [Orientation::Directed, Orientation::Undirected] {
        let graph = graph(orientation)?;
        let query = query();
        let run = select_robust_placement(&graph, &query, budget())?;
        assert_eq!(run.output.selected_sensors, vec!["new-left"]);
        assert_eq!(run.output.installation_cost, 2);
        assert_eq!(loss(&run.output.baseline), 1);
        assert_eq!(loss(&run.output.defended), 4);
        assert_eq!(run.output.baseline, oracle_loss(&graph, &query.baseline)?);
        assert_eq!(
            run.output.defended,
            InterdictionOutcome::Interdiction {
                sensors: vec!["existing-right".into()],
                cost: 4,
                path: vec!["entry".into(), "right".into(), "target".into()],
                exact: true,
            }
        );
    }
    Ok(())
}

#[test]
fn increasing_budget_admits_complementary_additions() -> TestResult {
    let graph = graph(Orientation::Directed)?;
    let mut query = query();
    query.installation_budget = 3;
    let run = select_robust_placement(&graph, &query, budget())?;
    assert_eq!(run.output.selected_sensors, vec!["new-left", "new-right"]);
    assert_eq!(loss(&run.output.defended), 6);
    query.maximum_additions = 1;
    let limited = select_robust_placement(&graph, &query, budget())?;
    assert_eq!(limited.output.selected_sensors, vec!["new-left"]);
    assert_eq!(loss(&limited.output.defended), 4);
    query.maximum_additions = 0;
    let none = select_robust_placement(&graph, &query, budget())?;
    assert!(none.output.selected_sensors.is_empty());
    assert_eq!(none.output.baseline, none.output.defended);
    Ok(())
}

#[test]
fn blind_paths_zero_cost_and_disconnection_are_distinct() -> TestResult {
    let connected = graph(Orientation::Directed)?;
    let mut query = query();
    query.baseline.observers.clear();
    query.baseline.costs.clear();
    query.candidates = vec![candidate("free", &["entry"], 0, 0)];
    let zero = select_robust_placement(&connected, &query, budget())?;
    assert!(matches!(
        zero.output.baseline,
        InterdictionOutcome::BlindPath { .. }
    ));
    assert!(zero.output.selected_sensors.is_empty());
    query.candidates[0].disable_cost = 1;
    let strengthened = select_robust_placement(&connected, &query, budget())?;
    assert_eq!(strengthened.output.selected_sensors, vec!["free"]);
    assert_eq!(loss(&strengthened.output.defended), 1);

    let mut disconnected = WeightedGraphBuilder::directed("movement");
    for node in ["entry", "left", "right", "target"] {
        disconnected.add_node(node);
    }
    let run = select_robust_placement(&disconnected.build()?, &query, budget())?;
    assert_eq!(run.output.baseline, InterdictionOutcome::Unreachable);
    assert_eq!(run.output.defended, InterdictionOutcome::Unreachable);
    assert!(run.output.selected_sensors.is_empty());
    assert_eq!(run.output.evaluated_placements, 1);
    Ok(())
}

#[test]
fn equal_robustness_ties_on_installation_then_count_then_identity() -> TestResult {
    let graph = graph(Orientation::Directed)?;
    let mut query = query();
    query.candidates = vec![
        candidate("b", &["left"], 2, 3),
        candidate("a", &["left"], 2, 3),
        candidate("expensive", &["left"], 3, 7),
        candidate("redundant", &[], 0, 0),
    ];
    query.installation_budget = 3;
    assert_eq!(
        select_robust_placement(&graph, &query, budget())?
            .output
            .selected_sensors,
        vec!["a"]
    );
    query.candidates[0].installation_cost = 1;
    assert_eq!(
        select_robust_placement(&graph, &query, budget())?
            .output
            .selected_sensors,
        vec!["b"]
    );
    Ok(())
}

#[test]
fn every_seeded_optimum_matches_exhaustive_existing_interdiction_calls() -> TestResult {
    for seed in 0..180 {
        let mut rng = Rng(seed ^ 0xcafe_713);
        let orientation = if seed % 2 == 0 {
            Orientation::Directed
        } else {
            Orientation::Undirected
        };
        let graph = graph(orientation)?;
        let mut query = query();
        query.baseline.observers.clear();
        for zone in ["entry", "left", "right", "target"] {
            let observers: BTreeSet<_> = query
                .baseline
                .costs
                .keys()
                .filter(|_| rng.chance(300))
                .cloned()
                .collect();
            query.baseline.observers.insert(zone.into(), observers);
        }
        for cost in query.baseline.costs.values_mut() {
            *cost = rng.below(7) as u64;
        }
        query.candidates = (0..4)
            .map(|index| PlacementCandidate {
                sensor: format!("candidate-{index}"),
                observes: ["entry", "left", "right", "target"]
                    .into_iter()
                    .filter(|_| rng.chance(450))
                    .map(str::to_owned)
                    .collect(),
                disable_cost: rng.below(7) as u64,
                installation_cost: rng.below(5) as u64,
            })
            .collect();
        query.installation_budget = rng.below(10) as u64;
        query.maximum_additions = rng.below(5);
        let actual = select_robust_placement(&graph, &query, budget())?;
        let baseline = oracle_loss(&graph, &query.baseline)?;
        let mut expected = (0, Vec::<String>::new(), baseline.clone());
        let mut evaluated = 0;
        for subset in 0..(1_u32 << query.candidates.len()) {
            if subset.count_ones() as usize > query.maximum_additions {
                continue;
            }
            let mut augmented = query.baseline.clone();
            let mut chosen = Vec::new();
            let mut cost = 0_u64;
            for (index, candidate) in query.candidates.iter().enumerate() {
                if subset & (1 << index) == 0 {
                    continue;
                }
                chosen.push(candidate.sensor.clone());
                cost += candidate.installation_cost;
                augmented
                    .costs
                    .insert(candidate.sensor.clone(), candidate.disable_cost);
                for zone in &candidate.observes {
                    augmented
                        .observers
                        .entry(zone.clone())
                        .or_default()
                        .insert(candidate.sensor.clone());
                }
            }
            if cost > query.installation_budget {
                continue;
            }
            evaluated += 1;
            let candidate = oracle_loss(&graph, &augmented)?;
            if loss(&candidate) > loss(&expected.2)
                || (loss(&candidate) == loss(&expected.2)
                    && (cost, chosen.len(), &chosen) < (expected.0, expected.1.len(), &expected.1))
            {
                expected = (cost, chosen, candidate);
            }
        }
        assert_eq!(actual.output.baseline, baseline, "seed {seed}");
        assert_eq!(
            (
                &actual.output.selected_sensors,
                actual.output.installation_cost,
                &actual.output.defended
            ),
            (&expected.1, expected.0, &expected.2),
            "seed {seed}"
        );
        assert_eq!(actual.output.evaluated_placements, evaluated, "seed {seed}");
        let mut reordered = query.clone();
        reordered.candidates.reverse();
        assert_eq!(
            actual,
            select_robust_placement(&graph, &reordered, budget())?,
            "seed {seed}"
        );
    }
    Ok(())
}

#[test]
fn assumptions_units_unused_candidates_and_limits_rebind_the_input() -> TestResult {
    let graph = graph(Orientation::Directed)?;
    let base = query();
    let expected = select_robust_placement(&graph, &base, budget())?;
    for variant in 0..7 {
        let mut changed = base.clone();
        match variant {
            0 => changed.disable_cost_unit = "minutes".into(),
            1 => changed.installation_cost_unit = "cost:eur".into(),
            2 => changed.installation_budget += 1,
            3 => changed.maximum_additions -= 1,
            4 => changed.candidates[2].disable_cost = 1,
            5 => changed.candidates[2].installation_cost = 1,
            _ => {
                changed
                    .baseline
                    .observers
                    .insert("target".into(), BTreeSet::new());
            }
        }
        assert_ne!(
            expected.input_digest,
            select_robust_placement(&graph, &changed, budget())?.input_digest
        );
    }
    let witness = expected.witness(
        "SensorCoverageGraph",
        LedgerAnchor::genesis("site:placement"),
    )?;
    check_witness(&witness, &IDENTITY, &robust_placement::bound(4, 4, 5, 3))?;
    assert_eq!(witness.input_digest(), expected.input_digest);
    assert_eq!(witness.output_digest(), expected.output_digest);
    assert_ne!(expected.input_digest, ContentDigest::sha256(&[]));
    Ok(())
}

#[test]
fn malformed_inconsistent_and_oversized_inputs_refuse_even_when_trivial() -> TestResult {
    let graph = graph(Orientation::Directed)?;
    for variant in 0..10 {
        let mut bad = query();
        match variant {
            0 => bad.candidates[0].sensor.clear(),
            1 => bad.candidates[0].sensor = bad.candidates[1].sensor.clone(),
            2 => bad.candidates[0].sensor = "existing-left".into(),
            3 => {
                bad.candidates[0].observes.insert("unknown-zone".into());
            }
            4 => {
                bad.baseline.costs.remove("existing-left");
            }
            5 => bad.baseline.entries.clear(),
            6 => bad.maximum_additions = MAX_CANDIDATES + 1,
            7 => bad.installation_cost_unit = "not a unit".into(),
            8 => bad.disable_cost_unit.clear(),
            _ => {
                bad.baseline.targets.insert("missing".into());
            }
        }
        assert!(
            select_robust_placement(&graph, &bad, budget()).is_err(),
            "variant {variant}"
        );
    }
    let mut bad = query();
    bad.candidates = (0..=MAX_CANDIDATES)
        .map(|i| candidate(&format!("candidate-{i}"), &[], 0, 0))
        .collect();
    bad.maximum_additions = 0;
    assert_eq!(
        select_robust_placement(&graph, &bad, budget()),
        Err(CoverError::Graph(GraphError::TooLarge))
    );
    bad.candidates.clear();
    for i in 0..MAX_TOTAL_SENSORS {
        bad.baseline.costs.insert(format!("idle-{i}"), 0);
    }
    assert_eq!(
        select_robust_placement(&graph, &bad, budget()),
        Err(CoverError::Graph(GraphError::TooLarge))
    );
    Ok(())
}

#[test]
fn overflow_refuses_disable_costs_and_cannot_wrap_installation_allowance() -> TestResult {
    let graph = graph(Orientation::Directed)?;
    let mut query = query();
    query.candidates[2].disable_cost = u64::MAX;
    assert!(matches!(
        select_robust_placement(&graph, &query, budget()),
        Err(CoverError::Graph(GraphError::ArithmeticOverflow(_)))
    ));
    query.candidates = vec![
        candidate("big", &["left"], u64::MAX, 5),
        candidate("small", &["right"], 1, 5),
    ];
    query.installation_budget = u64::MAX;
    let run = select_robust_placement(&graph, &query, budget())?;
    assert_eq!(run.output.selected_sensors, vec!["big"]);
    assert_eq!(run.output.installation_cost, u64::MAX);
    assert_eq!(run.output.evaluated_placements, 3);
    Ok(())
}

#[test]
fn one_budget_covers_every_inner_solve_and_output_no_partial_optimum() -> TestResult {
    let graph = graph(Orientation::Directed)?;
    let query = query();
    let run = select_robust_placement(&graph, &query, budget())?;
    assert_eq!(
        select_robust_placement(
            &graph,
            &query,
            CoverBudget {
                max_work_units: run.operations,
                max_output_entries: run.output_entries
            }
        )?,
        run
    );
    assert!(matches!(
        select_robust_placement(
            &graph,
            &query,
            CoverBudget {
                max_work_units: run.operations - 1,
                ..budget()
            }
        ),
        Err(CoverError::Graph(GraphError::BudgetExhausted {
            dimension: "operations",
            ..
        }))
    ));
    assert!(matches!(
        select_robust_placement(
            &graph,
            &query,
            CoverBudget {
                max_output_entries: run.output_entries - 1,
                ..budget()
            }
        ),
        Err(CoverError::Graph(GraphError::BudgetExhausted {
            dimension: "output_entries",
            ..
        }))
    ));
    let mut baseline_only = query.clone();
    baseline_only.maximum_additions = 0;
    let baseline_work = select_robust_placement(&graph, &baseline_only, budget())?.operations;
    assert!(run.operations > baseline_work);
    assert!(matches!(
        select_robust_placement(
            &graph,
            &query,
            CoverBudget {
                max_work_units: baseline_work,
                ..budget()
            }
        ),
        Err(CoverError::Graph(GraphError::BudgetExhausted { .. }))
    ));
    Ok(())
}

#[test]
fn cancellation_inside_removal_and_path_searches_never_returns_an_incumbent() -> TestResult {
    let graph = graph(Orientation::Directed)?;
    let query = query();
    let mut calls = 0;
    let run = select_robust_placement_with_cancel(&graph, &query, budget(), || {
        calls += 1;
        false
    })?;
    assert_eq!(run, select_robust_placement(&graph, &query, budget())?);
    for stop_at in [1, 2, 10, calls / 2, calls - 1, calls] {
        let mut count = 0;
        assert_eq!(
            select_robust_placement_with_cancel(&graph, &query, budget(), || {
                count += 1;
                count >= stop_at
            }),
            Err(CoverError::Cancelled),
            "cut {stop_at}/{calls}"
        );
    }
    Ok(())
}

#[test]
fn additive_mode_is_registered_without_changing_the_original_interdiction_identity() -> TestResult {
    let contract = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../architecture/robust_placement_reference.json"),
    )?;
    for (field, value) in IDENTITY.registry_fields() {
        assert!(
            contract.contains(&format!("\"{field}\": \"{value}\"")),
            "missing {field}"
        );
    }
    common::assert_registered(&interdiction::IDENTITY)?;
    for domain in [
        robust_placement::INPUT_DOMAIN,
        robust_placement::OUTPUT_DOMAIN,
        robust_placement::DECISION_DOMAIN,
    ] {
        assert!(contract.contains(domain));
    }
    Ok(())
}
