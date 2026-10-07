#![forbid(unsafe_code)]
//! Certification of `ALG-MST-001`, `ALG-GH-001`, `ALG-MCF-001`, `ALG-MATCH-001` and
//! `ALG-MULTIMATCH-001` against their brute-force oracles: exhaustive spanning-forest
//! enumeration, all-pairs subset cuts, unit-step Bellman–Ford min-cost flow, and exhaustive
//! assignment enumeration ordered by `(objective, assignment tuple)`. Metamorphic insertion
//! order, budget-one-short, tampered-witness and registry checks as for the other families.

mod common;

use common::{Rng, SEEDS, TestResult, assert_registered, certify, generate, registered};
use fss_graph_algorithms::assignment::{
    self, AssignmentProblem, AssignmentProblemBuilder, NonAssignment,
};
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::weighted::{Orientation, WeightedGraph, WeightedGraphBuilder};
use fss_graph_algorithms::{GraphError, gomory_hu, min_cost_flow, oracles, spanning};

#[test]
fn spanning_forest_equals_exhaustive_enumeration() -> TestResult {
    let mut checked = 0;
    for seed in 0..SEEDS {
        let spec = generate(seed, Orientation::Undirected, 7);
        if spec.arcs.len() > 12 {
            continue;
        }
        let graph = spec.build(None)?;
        let (n, m) = (graph.node_count() as u64, graph.arc_count() as u64);
        let bound = spanning::bound(n, m);
        let run = spanning::minimum_spanning_forest(&graph, registered(&bound))?;
        let (edges, total, components) = oracles::minimum_spanning_forest(&graph);
        let expected: Vec<(String, String, u64)> = edges
            .iter()
            .map(|&edge| {
                let (a, b) = graph.arc_ids(edge);
                (a, b, graph.arc(edge).weight)
            })
            .collect();
        assert_eq!(run.output.edges, expected, "seed {seed}");
        assert_eq!(
            (run.output.total_weight, run.output.components),
            (total, components)
        );
        let shuffled =
            spanning::minimum_spanning_forest(&spec.build(Some(seed))?, registered(&bound))?;
        assert_eq!(shuffled, run, "seed {seed}");
        if seed % 25 == 0 {
            certify(&run, &spanning::IDENTITY, &bound, |budget| {
                spanning::minimum_spanning_forest(&graph, budget)
            })?;
        }
        checked += 1;
    }
    assert!(checked > 1_000, "{checked}");
    Ok(())
}

#[test]
fn gomory_hu_tree_reproduces_every_pairwise_minimum_cut() -> TestResult {
    for seed in 0..SEEDS / 2 {
        let spec = generate(seed, Orientation::Undirected, 7);
        let graph = spec.build(None)?;
        let (n, m) = (graph.node_count() as u64, graph.arc_count() as u64);
        let bound = gomory_hu::bound(n, m);
        let run = gomory_hu::gomory_hu_tree(&graph, registered(&bound))?;
        assert_eq!(run.output.tree.len(), graph.node_count().saturating_sub(1));
        for ((a, b), value) in oracles::all_pairs_min_cut(&graph) {
            assert_eq!(
                run.output.min_cut(graph.id(a), graph.id(b)),
                Some(value),
                "seed {seed}: {} {}",
                graph.id(a),
                graph.id(b)
            );
        }
        let shuffled = gomory_hu::gomory_hu_tree(&spec.build(Some(seed))?, registered(&bound))?;
        assert_eq!(shuffled, run, "seed {seed}");
        if seed % 25 == 0 {
            certify(&run, &gomory_hu::IDENTITY, &bound, |budget| {
                gomory_hu::gomory_hu_tree(&graph, budget)
            })?;
        }
    }
    Ok(())
}

fn capacity_twin(graph: &WeightedGraph, seed: u64) -> Result<WeightedGraph, GraphError> {
    let mut rng = Rng(seed ^ 0x5eed);
    let mut builder = WeightedGraphBuilder::directed("units");
    for id in graph.ids() {
        builder.add_node(id.clone());
    }
    for arc in graph.arcs() {
        builder.add_arc(
            graph.id(arc.tail).to_owned(),
            graph.id(arc.head).to_owned(),
            rng.next() % 4,
        );
    }
    builder.build()
}

#[test]
fn min_cost_flow_equals_unit_step_bellman_ford() -> TestResult {
    for seed in 0..SEEDS {
        let spec = generate(seed, Orientation::Directed, 7);
        let costs = spec.build(None)?;
        let n = costs.node_count();
        if n < 2 {
            continue;
        }
        let capacities = capacity_twin(&costs, seed)?;
        let s = (seed as usize % n) as u32;
        let t = ((s as usize + 1 + seed as usize / 5) % n) as u32;
        if s == t {
            continue;
        }
        let demand = seed % 7;
        let (n64, m64) = (n as u64, costs.arc_count() as u64);
        let bound = min_cost_flow::bound(n64, m64, demand);
        let run = min_cost_flow::min_cost_flow(
            &costs,
            &capacities,
            costs.id(s),
            costs.id(t),
            demand,
            registered(&bound),
        )?;
        let (delivered, total) = oracles::min_cost_flow(&costs, &capacities, s, t, demand);
        assert_eq!(
            (run.output.delivered, run.output.total_cost),
            (delivered, total),
            "seed {seed}"
        );
        assert_eq!(run.output.shortfall, demand - delivered);
        let recomputed: u64 = run
            .output
            .flows
            .iter()
            .map(|(_, _, amount, cost)| amount * cost)
            .sum();
        assert_eq!(recomputed, run.output.total_cost, "seed {seed}");
        if seed % 25 == 0 {
            certify(&run, &min_cost_flow::IDENTITY, &bound, |budget| {
                min_cost_flow::min_cost_flow(
                    &costs,
                    &capacities,
                    costs.id(s),
                    costs.id(t),
                    demand,
                    budget,
                )
            })?;
        }
    }
    // Unpaired projections are refused.
    let mut a = WeightedGraphBuilder::directed("usd");
    a.add_node("x").add_node("y").add_arc("x", "y", 1);
    let mut b = WeightedGraphBuilder::directed("units");
    b.add_node("x").add_node("y").add_arc("y", "x", 1);
    let refused = min_cost_flow::min_cost_flow(
        &a.build()?,
        &b.build()?,
        "x",
        "y",
        1,
        Budget::new(1000, 1000),
    );
    assert_eq!(
        refused.err().map(|e| e.stable_id()),
        Some("ERR-GRAPH-PRECONDITION-001")
    );
    Ok(())
}

fn problem(seed: u64) -> Result<AssignmentProblem, GraphError> {
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9) ^ 0x00a5_5a00);
    let (l, r) = (rng.below(5), rng.below(5));
    let max_cost = [0, 1, 3, 20][rng.below(4)];
    let mut builder = AssignmentProblemBuilder::new("cost");
    for i in 0..l {
        builder.add_left(format!("track-{}", (i * 3) % 7));
    }
    for j in 0..r {
        builder.add_right(format!("det-{}", (j * 5) % 9));
    }
    let density = [300, 600, 1000][rng.below(3)];
    for i in 0..l {
        for j in 0..r {
            if rng.chance(density) {
                let cost = if max_cost == 0 {
                    0
                } else {
                    rng.next() % (max_cost + 1)
                };
                builder.allow(
                    format!("track-{}", (i * 3) % 7),
                    format!("det-{}", (j * 5) % 9),
                    cost,
                );
            }
        }
    }
    builder.build()
}

/// `((objective key, tuple), choice)` of one enumerated assignment.
type Ranked = ((i128, Vec<usize>), Vec<Option<u32>>);

fn policies(seed: u64) -> [NonAssignment; 3] {
    [
        NonAssignment::MaximumCardinality,
        NonAssignment::Priced {
            left: seed % 5,
            right: (seed / 5) % 4,
        },
        NonAssignment::Priced { left: 0, right: 0 },
    ]
}

fn choice_of(problem: &AssignmentProblem, assignment: &assignment::Assignment) -> Vec<Option<u32>> {
    problem
        .left()
        .iter()
        .map(|left| {
            assignment
                .pairs
                .iter()
                .find(|(l, _, _)| l == left)
                .and_then(|(_, r, _)| {
                    problem
                        .right()
                        .iter()
                        .position(|x| x == r)
                        .map(|p| p as u32)
                })
        })
        .collect()
}

#[test]
fn assignments_equal_exhaustive_enumeration_in_objective_then_tuple_order() -> TestResult {
    for seed in 0..SEEDS {
        let problem = problem(seed)?;
        let all = oracles::all_assignments(&problem);
        let n = (problem.left().len() + problem.right().len()) as u64;
        let m = problem.pairs().len() as u64;
        for policy in policies(seed) {
            let mut ranked: Vec<Ranked> = all
                .iter()
                .map(|choice| {
                    (
                        oracles::assignment_key(&problem, policy, choice),
                        choice.clone(),
                    )
                })
                .collect();
            ranked.sort();
            let bound = assignment::match_bound(n, m);
            let best = assignment::optimal_assignment(&problem, policy, registered(&bound))?;
            assert_eq!(
                choice_of(&problem, &best.output.assignment),
                ranked[0].1,
                "seed {seed} {policy:?}"
            );
            let k = 1 + (seed % 6) as u32;
            let kbound = assignment::multimatch_bound(n, m, u64::from(k));
            let kbest = assignment::k_best_assignments(&problem, policy, k, registered(&kbound))?;
            let expected: Vec<Vec<Option<u32>>> = ranked
                .iter()
                .take(k as usize)
                .map(|(_, choice)| choice.clone())
                .collect();
            let got: Vec<Vec<Option<u32>>> = kbest
                .output
                .assignments
                .iter()
                .map(|a| choice_of(&problem, a))
                .collect();
            assert_eq!(got, expected, "seed {seed} {policy:?} k {k}");
            assert_eq!(kbest.output.exhausted, ranked.len() < k as usize);
            for assignment in &kbest.output.assignments {
                assert_eq!(
                    assignment.objective,
                    assignment.matched_cost + assignment.non_assignment_cost
                );
            }
            if seed % 50 == 0 {
                certify(&best, &assignment::MATCH_IDENTITY, &bound, |budget| {
                    assignment::optimal_assignment(&problem, policy, budget)
                })?;
                certify(
                    &kbest,
                    &assignment::MULTIMATCH_IDENTITY,
                    &kbound,
                    |budget| assignment::k_best_assignments(&problem, policy, k, budget),
                )?;
            }
        }
    }
    Ok(())
}

#[test]
fn textbook_assignment_and_resilience_answers_hold() -> TestResult {
    // Two tracks, two detections: the crossing assignment is cheaper; a forbidden pair is never
    // used even when everything else is expensive.
    let mut builder = AssignmentProblemBuilder::new("neg-log-likelihood");
    builder.add_left("track-a").add_left("track-b");
    builder.add_right("det-1").add_right("det-2");
    builder
        .allow("track-a", "det-1", 9)
        .allow("track-a", "det-2", 1)
        .allow("track-b", "det-1", 2);
    let problem = builder.build()?;
    let best = assignment::optimal_assignment(
        &problem,
        NonAssignment::MaximumCardinality,
        Budget::new(1 << 30, 1 << 20),
    )?;
    assert_eq!(
        best.output.assignment.pairs,
        vec![
            ("track-a".to_owned(), "det-2".to_owned(), 1),
            ("track-b".to_owned(), "det-1".to_owned(), 2)
        ]
    );
    // With a cheap miss cost, leaving both unassigned beats any pairing.
    let priced = assignment::optimal_assignment(
        &problem,
        NonAssignment::Priced { left: 0, right: 0 },
        Budget::new(1 << 30, 1 << 20),
    )?;
    assert!(priced.output.assignment.pairs.is_empty());
    assert_eq!(priced.output.assignment.objective, 0);

    // Ring of four sensors: every pair's minimum cut is 2.
    let mut ring = WeightedGraphBuilder::undirected("links");
    for node in ["a", "b", "c", "d"] {
        ring.add_node(node);
    }
    ring.add_arc("a", "b", 1)
        .add_arc("b", "c", 1)
        .add_arc("c", "d", 1)
        .add_arc("d", "a", 1);
    let tree = gomory_hu::gomory_hu_tree(&ring.build()?, Budget::new(1 << 30, 1 << 20))?;
    assert_eq!(tree.output.min_cut("a", "c"), Some(2));
    assert_eq!(tree.output.min_cut("b", "d"), Some(2));
    Ok(())
}

#[test]
fn implemented_identities_equal_their_machine_registry_rows() -> TestResult {
    for identity in [
        &spanning::IDENTITY,
        &gomory_hu::IDENTITY,
        &min_cost_flow::IDENTITY,
        &assignment::MATCH_IDENTITY,
        &assignment::MULTIMATCH_IDENTITY,
    ] {
        assert_registered(identity)?;
    }
    Ok(())
}
