#![forbid(unsafe_code)]
//! Native reference contracts; independent set-based oracle, never a qualification claim.
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use fss_core::LedgerAnchor;
use fss_graph_algorithms::set_cover::{
    CoverBudget, CoverError, CoverMethod, CoverSet, CoverStatus, SetCoverProblem,
};
use fss_graph_algorithms::submodular::{ALGORITHM_ID, SelectionStop, SubmodularProblem};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn ids(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).to_owned()).collect()
}
fn problem(
    weights: &[(&str, u64)],
    sets: &[(&str, &[&str], u64)],
    mandatory: &[&str],
    excluded: &[&str],
    slots: usize,
    budget: u64,
) -> Result<SubmodularProblem, CoverError> {
    let elements = weights
        .iter()
        .map(|(id, _)| (*id).to_owned())
        .collect::<Vec<_>>();
    let support = sets
        .iter()
        .map(|(id, elements, _)| CoverSet::new(id, &ids(elements)))
        .collect::<Result<Vec<_>, _>>()?;
    let support =
        SetCoverProblem::new(&elements, &support, &ids(mandatory), &ids(excluded), slots)?;
    let utilities = weights
        .iter()
        .map(|(id, value)| ((*id).to_owned(), *value))
        .collect();
    let costs = sets
        .iter()
        .map(|(id, _, cost)| ((*id).to_owned(), *cost))
        .collect();
    SubmodularProblem::new(support, &utilities, &costs, budget)
}

#[test]
fn unsupported_target_does_not_discard_useful_feasible_selection() -> TestResult {
    let p = problem(
        &[("gate", 9), ("yard", 3), ("unseen", 100)],
        &[("a", &["gate"], 2), ("b", &["yard"], 1)],
        &[],
        &[],
        1,
        2,
    )?;
    let nominal = p
        .support()
        .solve(CoverMethod::ExactSmall, CoverBudget::default())?;
    assert_eq!(nominal.status(), CoverStatus::Uncoverable);
    assert!(nominal.selected().is_empty());
    let answer = p.solve(CoverBudget::default())?;
    assert_eq!(answer.selected(), ids(&["a"]));
    assert_eq!(answer.utility(), 9);
    assert_eq!(answer.total_utility(), 112);
    assert_eq!(answer.uncovered(), ids(&["unseen", "yard"]));
    assert_eq!(answer.uncoverable(), ids(&["unseen"]));
    assert_eq!(answer.stop(), SelectionStop::CardinalityLimit);
    Ok(())
}

#[test]
fn marginal_utility_is_diminishing_and_shared_targets_are_not_double_counted() -> TestResult {
    let p = problem(
        &[("x", 5), ("y", 1), ("z", 3)],
        &[("a", &["x", "y"], 1), ("b", &["x"], 1), ("c", &["z"], 1)],
        &[],
        &[],
        2,
        2,
    )?;
    let a = p.solve(CoverBudget::default())?;
    assert_eq!(a.selected(), ids(&["a", "c"]));
    assert_eq!(a.utility(), 9);
    assert_eq!(
        a.steps()
            .iter()
            .map(|step| step.marginal_utility)
            .collect::<Vec<_>>(),
        vec![6, 3]
    );
    assert_eq!(a.certificate().len(), 3);
    assert_eq!(a.stop(), SelectionStop::FullCoverage);
    Ok(())
}

#[test]
fn rational_order_near_u64_limits_uses_neither_overflow_nor_float_rounding() -> TestResult {
    let half = u64::MAX / 2;
    let p = problem(
        &[("x", half), ("y", half + 1)],
        &[("a", &["x"], u64::MAX - 1), ("b", &["y"], u64::MAX)],
        &[],
        &[],
        1,
        u64::MAX,
    )?;
    let a = p.solve(CoverBudget::default())?;
    assert_eq!(a.selected(), ids(&["b"]));
    assert_eq!(a.utility(), half + 1);
    assert_eq!(a.cost_units(), u64::MAX);
    assert_eq!(a.total_utility(), u64::MAX);
    Ok(())
}

#[test]
fn exact_ratio_ties_use_stable_identity_not_absolute_gain_or_cost() -> TestResult {
    let p = problem(
        &[("x", 2), ("y", 6)],
        &[("b", &["y"], 3), ("a", &["x"], 1)],
        &[],
        &[],
        1,
        3,
    )?;
    let a = p.solve(CoverBudget::default())?;
    assert_eq!(a.selected(), ids(&["a"]));
    assert_eq!(a.cost_units(), 1);
    Ok(())
}

#[test]
fn mandatory_empty_actions_consume_slots_and_cost_and_exclusions_never_relax() -> TestResult {
    let p = problem(
        &[("x", 7), ("y", 10)],
        &[("idle", &[], 4), ("a", &["x"], 1), ("excluded", &["y"], 1)],
        &["idle"],
        &["excluded"],
        2,
        5,
    )?;
    let a = p.solve(CoverBudget::default())?;
    assert_eq!(a.selected(), ids(&["a", "idle"]));
    assert_eq!(a.cost_units(), 5);
    assert_eq!(a.steps()[0].cumulative_cost_units, 5);
    assert_eq!(a.uncoverable(), ids(&["y"]));
    assert_eq!(a.certificate()[0].set_id, "a");
    assert!(problem(&[("x", 1)], &[("idle", &[], 4)], &["idle"], &[], 1, 3).is_err());
    Ok(())
}

#[test]
fn malformed_weight_cost_domains_and_utility_overflow_are_rejected() -> TestResult {
    assert!(problem(&[("x", u64::MAX), ("y", 1)], &[], &[], &[], 0, 0).is_err());
    assert!(problem(&[("x", 0)], &[], &[], &[], 0, 0).is_err());
    assert!(problem(&[("x", 1)], &[("a", &["x"], 0)], &[], &[], 1, 1).is_err());
    let p = problem(&[("x", 1)], &[("a", &["x"], 1)], &[], &[], 1, 1)?;
    let u = BTreeMap::from([("x".to_owned(), 1)]);
    let c = BTreeMap::from([("a".to_owned(), 1)]);
    assert!(SubmodularProblem::new(p.support().clone(), &BTreeMap::new(), &c, 1).is_err());
    assert!(
        SubmodularProblem::new(
            p.support().clone(),
            &u,
            &BTreeMap::from([("unknown".to_owned(), 1)]),
            1
        )
        .is_err()
    );
    assert!(
        SubmodularProblem::new(
            p.support().clone(),
            &BTreeMap::from([("foreign".to_owned(), 1)]),
            &c,
            1
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn zero_budget_and_empty_universe_are_complete_queries_not_absence_claims() -> TestResult {
    let p = problem(&[("x", 1)], &[("a", &["x"], u64::MAX)], &[], &[], 1, 0)?;
    let a = p.solve(CoverBudget::default())?;
    assert!(a.selected().is_empty());
    assert_eq!(a.uncovered(), ids(&["x"]));
    assert!(a.uncoverable().is_empty());
    assert_eq!(a.stop(), SelectionStop::NoAffordablePositiveGain);
    let empty = problem(&[], &[("mandatory", &[], 2)], &["mandatory"], &[], 1, 2)?;
    let a = empty.solve(CoverBudget::default())?;
    assert_eq!(a.stop(), SelectionStop::FullCoverage);
    assert_eq!(a.selected(), ids(&["mandatory"]));
    assert_eq!(a.utility(), 0);
    assert!(a.steps().is_empty());
    Ok(())
}

#[test]
fn greedy_counterexample_is_explicitly_approximate_and_never_infeasibility() -> TestResult {
    let p = problem(
        &[("x", 3), ("y", 2), ("z", 2)],
        &[("a", &["x"], 2), ("b", &["y", "z"], 3)],
        &[],
        &[],
        2,
        4,
    )?;
    let a = p.solve(CoverBudget::default())?;
    assert_eq!(a.selected(), ids(&["a"]));
    assert_eq!(a.utility(), 3); // Selecting b alone has utility 4: greedy is not optimal.
    assert_eq!(a.stop(), SelectionStop::NoAffordablePositiveGain);
    let witness = a.witness(
        "synthetic:budgeted-coverage",
        LedgerAnchor::genesis("site:test"),
    )?;
    assert_eq!(witness.algorithm_id(), ALGORITHM_ID);
    assert_eq!(witness.exactness(), "approximate");
    assert_eq!(witness.error_bound(), None);
    Ok(())
}

#[test]
fn permutations_are_identical_and_every_declared_cost_utility_and_budget_rebinds_input()
-> TestResult {
    let p = problem(
        &[("y", 3), ("x", 7)],
        &[("b", &["y"], 2), ("a", &["x"], 2)],
        &[],
        &["b"],
        2,
        2,
    )?;
    let q = problem(
        &[("x", 7), ("y", 3)],
        &[("a", &["x"], 2), ("b", &["y"], 2)],
        &[],
        &["b"],
        2,
        2,
    )?;
    assert_eq!(p, q);
    assert_eq!(
        p.solve(CoverBudget::default())?,
        q.solve(CoverBudget::default())?
    );
    for changed in [
        problem(
            &[("x", 7), ("y", 4)],
            &[("a", &["x"], 2), ("b", &["y"], 2)],
            &[],
            &["b"],
            2,
            2,
        )?,
        problem(
            &[("x", 7), ("y", 3)],
            &[("a", &["x"], 2), ("b", &["y"], 3)],
            &[],
            &["b"],
            2,
            2,
        )?,
        problem(
            &[("x", 7), ("y", 3)],
            &[("a", &["x"], 2), ("b", &["y"], 2)],
            &[],
            &["b"],
            2,
            3,
        )?,
    ] {
        assert_ne!(p.digest(), changed.digest());
    }
    Ok(())
}

#[test]
fn sixty_fourth_bit_and_largest_inventory_are_not_truncated() -> TestResult {
    let elements = (0..64).map(|i| format!("zone:{i:02}")).collect::<Vec<_>>();
    let sets = (0..1024)
        .map(|i| CoverSet::new(&format!("sensor:{i:04}"), &[elements[i % 64].clone()]))
        .collect::<Result<Vec<_>, _>>()?;
    let base = SetCoverProblem::new(&elements, &sets, &[], &[], 64)?;
    let u = elements.iter().map(|id| (id.clone(), 1)).collect();
    let c = sets.iter().map(|set| (set.id().to_owned(), 1)).collect();
    let p = SubmodularProblem::new(base, &u, &c, 64)?;
    let a = p.solve(CoverBudget::default())?;
    assert_eq!(a.utility(), 64);
    assert_eq!(a.certificate().len(), 64);
    assert_eq!(a.selected().len(), 64);
    assert_eq!(a.stop(), SelectionStop::FullCoverage);
    Ok(())
}

#[test]
fn work_output_and_cancellation_fail_closed_at_exact_boundaries() -> TestResult {
    let p = problem(
        &[("x", 1), ("y", 1)],
        &[("a", &["x"], 1), ("b", &["y"], 1)],
        &[],
        &[],
        2,
        2,
    )?;
    let a = p.solve(CoverBudget::default())?;
    let work = a.counters().work_units();
    let entries = (a.selected().len()
        + a.steps().len()
        + a.uncovered().len()
        + a.uncoverable().len()
        + 2 * a.certificate().len()) as u64;
    assert_eq!(
        p.solve(CoverBudget {
            max_work_units: work,
            max_output_entries: entries
        })?,
        a
    );
    assert!(
        p.solve(CoverBudget {
            max_work_units: work - 1,
            max_output_entries: entries
        })
        .is_err()
    );
    assert!(
        p.solve(CoverBudget {
            max_work_units: work,
            max_output_entries: entries - 1
        })
        .is_err()
    );
    assert!(matches!(
        p.solve_cancellable(CoverBudget::default(), &|| true),
        Err(CoverError::Cancelled)
    ));
    let calls = Cell::new(0_u64);
    assert!(matches!(
        p.solve_cancellable(CoverBudget::default(), &|| {
            calls.set(calls.get() + 1);
            calls.get() >= 5
        }),
        Err(CoverError::Cancelled)
    ));
    Ok(())
}

// Independent reference: string sets and cross-multiplied rational ranking; no production masks.
fn oracle(p: &SubmodularProblem) -> (Vec<String>, Vec<String>, u64, u64) {
    let support = p.support();
    let weights = support
        .elements()
        .iter()
        .cloned()
        .zip(p.utilities().iter().copied())
        .collect::<BTreeMap<_, _>>();
    let mut selected = support.mandatory().clone();
    let mut covered = BTreeSet::new();
    let mut spent = 0;
    for (index, set) in support.sets().iter().enumerate() {
        if selected.contains(set.id()) {
            covered.extend(set.elements().iter().cloned());
            spent += p.costs()[index];
        }
    }
    let mut order = Vec::new();
    while selected.len() < support.maximum_sets() {
        let mut ranked = Vec::new();
        for (i, set) in support.sets().iter().enumerate() {
            if selected.contains(set.id())
                || support.excluded().contains(set.id())
                || p.costs()[i] > p.cost_budget() - spent
            {
                continue;
            }
            let gain: u64 = set
                .elements()
                .difference(&covered)
                .map(|id| weights[id])
                .sum();
            if gain > 0 {
                ranked.push((set.id(), gain, p.costs()[i], i));
            }
        }
        ranked.sort_by(|a, b| {
            (u128::from(b.1) * u128::from(a.2))
                .cmp(&(u128::from(a.1) * u128::from(b.2)))
                .then_with(|| a.0.cmp(b.0))
        });
        let Some((id, _, cost, index)) = ranked.first() else {
            break;
        };
        order.push((*id).to_owned());
        selected.insert((*id).to_owned());
        spent += *cost;
        covered.extend(support.sets()[*index].elements().iter().cloned());
    }
    let utility = covered.iter().map(|id| weights[id]).sum();
    (selected.into_iter().collect(), order, utility, spent)
}

#[test]
fn four_thousand_seeded_problems_match_independent_set_based_policy() -> TestResult {
    let mut seed = 0x75ba_2d38_4621_09cf_u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..4000 {
        let e = (next() % 6 + 1) as usize;
        let n = (next() % 7) as usize;
        let elements = (0..e).map(|i| format!("e{i}")).collect::<Vec<_>>();
        let mut sets = Vec::new();
        let mut costs = BTreeMap::new();
        let mut mandatory = Vec::new();
        let mut excluded = Vec::new();
        let mut floor_cost = 0;
        for i in 0..n {
            let id = format!("a{i}");
            let support = elements
                .iter()
                .filter(|_| next() % 3 == 0)
                .cloned()
                .collect::<Vec<_>>();
            sets.push(CoverSet::new(&id, &support)?);
            let cost = next() % 9 + 1;
            costs.insert(id.clone(), cost);
            match next() % 6 {
                0 => {
                    mandatory.push(id);
                    floor_cost += cost;
                }
                1 => excluded.push(id),
                _ => {}
            }
        }
        let weights = elements
            .iter()
            .map(|id| (id.clone(), next() % 21 + 1))
            .collect();
        let slots = mandatory.len() + next() as usize % (n - mandatory.len() + 1);
        let base = SetCoverProblem::new(&elements, &sets, &mandatory, &excluded, slots)?;
        let p = SubmodularProblem::new(base, &weights, &costs, floor_cost + next() % 24)?;
        let answer = p.solve(CoverBudget::default())?;
        let (selected, order, utility, cost) = oracle(&p);
        assert_eq!(answer.selected(), selected);
        assert_eq!(
            answer
                .steps()
                .iter()
                .map(|step| step.action_id.clone())
                .collect::<Vec<_>>(),
            order
        );
        assert_eq!((answer.utility(), answer.cost_units()), (utility, cost));
        for row in answer.certificate() {
            assert!(answer.selected().contains(&row.set_id));
            let owner = p
                .support()
                .sets()
                .iter()
                .find(|set| set.id() == row.set_id.as_str());
            assert!(owner.is_some_and(|set| set.elements().contains(&row.element)));
        }
    }
    Ok(())
}
