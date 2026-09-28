#![forbid(unsafe_code)]
//! Public-consumer contract and independent exhaustive oracle for the FSS-160 reference slice.
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use fss_core::{ContentDigest, LedgerAnchor};
use fss_graph_algorithms::set_cover::{
    ALGORITHM_ID, CoverBudget, CoverError, CoverMethod, CoverSet, CoverStatus, MAX_ELEMENTS,
    MAX_EXACT_OPTIONAL_SETS, MAX_OUTPUT_ENTRIES, MAX_SETS, MAX_WORK_UNITS, SetCoverProblem,
};
use fss_graph_algorithms::{CoverageObservation, GraphError, SensorCoverageProjection};

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn ids(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).to_owned()).collect()
}
fn set(id: &str, elements: &[&str]) -> Result<CoverSet, CoverError> {
    CoverSet::new(id, &ids(elements))
}
fn budget() -> CoverBudget {
    CoverBudget {
        max_work_units: MAX_WORK_UNITS,
        max_output_entries: MAX_OUTPUT_ENTRIES,
    }
}
fn fixture(maximum: usize) -> Result<SetCoverProblem, CoverError> {
    // Greedy A,B,C costs three; exact B,C costs two. A greedy failure at two is NOT infeasibility.
    SetCoverProblem::new(
        &ids(&["1", "2", "3", "4", "5", "6"]),
        &[
            set("A", &["1", "2", "3", "4"])?,
            set("B", &["1", "2", "5"])?,
            set("C", &["3", "4", "6"])?,
        ],
        &[],
        &[],
        maximum,
    )
}

#[test]
fn exact_and_greedy_are_distinct_and_greedy_failure_is_not_infeasibility() -> TestResult {
    let problem = fixture(2)?;
    let exact = problem.solve(CoverMethod::ExactSmall, budget())?;
    let greedy = problem.solve(CoverMethod::Greedy, budget())?;
    assert_eq!(exact.selected(), ids(&["B", "C"]));
    assert_eq!(exact.status(), CoverStatus::Covered);
    assert_eq!(greedy.selected(), ids(&["A", "B"]));
    assert_eq!(greedy.status(), CoverStatus::HeuristicIncomplete);
    assert_eq!(greedy.uncovered(), ids(&["6"]));
    assert!(greedy.uncoverable().is_empty());
    assert_ne!(exact.output_digest(), greedy.output_digest());
    assert_eq!(
        fixture(1)?
            .solve(CoverMethod::ExactSmall, budget())?
            .status(),
        CoverStatus::InfeasibleWithinLimit
    );
    assert_eq!(
        fixture(3)?.solve(CoverMethod::Greedy, budget())?.status(),
        CoverStatus::Covered
    );
    Ok(())
}

#[test]
fn mandatory_floor_is_preserved_even_when_redundant() -> TestResult {
    let candidates = [set("a", &["x", "y"])?, set("b", &[])?];
    let p = SetCoverProblem::new(&ids(&["x", "y"]), &candidates, &ids(&["b"]), &[], 2)?;
    for method in [CoverMethod::ExactSmall, CoverMethod::Greedy] {
        let result = p.solve(method, budget())?;
        assert_eq!(result.selected(), ids(&["a", "b"]));
        assert_eq!(result.status(), CoverStatus::Covered);
    }
    assert!(
        SetCoverProblem::new(
            &ids(&["x"]),
            &[set("a", &["x"])?],
            &ids(&["a"]),
            &ids(&["a"]),
            1
        )
        .is_err()
    );
    assert!(SetCoverProblem::new(&[], &[set("a", &[])?], &ids(&["a"]), &[], 0).is_err());
    Ok(())
}

#[test]
fn exclusions_and_unseen_targets_are_not_silently_removed() -> TestResult {
    let p = SetCoverProblem::new(
        &ids(&["x", "y", "never_seen"]),
        &[set("a", &["x"])?, set("b", &["y"])?, set("idle", &[])?],
        &[],
        &ids(&["b"]),
        3,
    )?;
    for method in [CoverMethod::ExactSmall, CoverMethod::Greedy] {
        let result = p.solve(method, budget())?;
        assert_eq!(result.status(), CoverStatus::Uncoverable);
        assert_eq!(result.uncoverable(), ids(&["never_seen", "y"]));
        assert_eq!(result.uncovered(), ids(&["never_seen", "x", "y"]));
        assert!(result.selected().is_empty());
    }
    Ok(())
}

#[test]
fn canonical_ties_and_input_reordering_preserve_all_identities() -> TestResult {
    let candidates = [set("b", &["y", "x"])?, set("a", &["x", "y"])?];
    let a = SetCoverProblem::new(&ids(&["y", "x"]), &candidates, &[], &[], 2)?;
    let b = SetCoverProblem::new(
        &ids(&["x", "y"]),
        &[candidates[1].clone(), candidates[0].clone()],
        &[],
        &[],
        2,
    )?;
    assert_eq!(a, b);
    for method in [CoverMethod::ExactSmall, CoverMethod::Greedy] {
        let result = a.solve(method, budget())?;
        assert_eq!(result.selected(), ids(&["a"]));
        assert_eq!(result, b.solve(method, budget())?);
        assert_eq!(result.certificate().len(), 2);
        assert!(result.certificate().iter().all(|r| r.set_id == "a"));
    }
    Ok(())
}

#[test]
fn zero_and_full_word_universes_and_zero_selection_limit_are_total() -> TestResult {
    let empty = SetCoverProblem::new(&[], &[], &[], &[], 0)?;
    assert_eq!(
        empty.solve(CoverMethod::ExactSmall, budget())?.status(),
        CoverStatus::Covered
    );
    let universe: Vec<String> = (0..MAX_ELEMENTS).map(|n| format!("z{n:02}")).collect();
    let all = CoverSet::new("whole", &universe)?;
    let p = SetCoverProblem::new(&universe, std::slice::from_ref(&all), &[], &[], 1)?;
    for method in [CoverMethod::ExactSmall, CoverMethod::Greedy] {
        let answer = p.solve(method, budget())?;
        assert_eq!(answer.status(), CoverStatus::Covered);
        assert_eq!(answer.certificate().len(), 64);
    }
    let zero = SetCoverProblem::new(&universe, &[all], &[], &[], 0)?;
    assert_eq!(
        zero.solve(CoverMethod::ExactSmall, budget())?.status(),
        CoverStatus::InfeasibleWithinLimit
    );
    assert_eq!(
        zero.solve(CoverMethod::Greedy, budget())?.status(),
        CoverStatus::HeuristicIncomplete
    );
    Ok(())
}

#[test]
fn invalid_identities_duplicate_members_and_unknown_constraints_fail_closed() -> TestResult {
    for id in ["", "bad\nlabel", "bad\0label"] {
        assert!(set(id, &[]).is_err());
    }
    assert!(set("x", &["a", "a"]).is_err());
    let a = set("a", &["x"])?;
    assert!(
        SetCoverProblem::new(&ids(&["x", "x"]), std::slice::from_ref(&a), &[], &[], 1).is_err()
    );
    assert!(SetCoverProblem::new(&ids(&["x"]), &[a.clone(), a.clone()], &[], &[], 2).is_err());
    assert!(SetCoverProblem::new(&ids(&["y"]), std::slice::from_ref(&a), &[], &[], 1).is_err());
    assert!(
        SetCoverProblem::new(
            &ids(&["x"]),
            std::slice::from_ref(&a),
            &ids(&["unknown"]),
            &[],
            1
        )
        .is_err()
    );
    assert!(SetCoverProblem::new(&ids(&["x"]), &[a], &[], &ids(&["unknown"]), 1).is_err());
    Ok(())
}

#[test]
fn hard_limits_and_exact_size_limit_do_not_trigger_an_implicit_heuristic() -> TestResult {
    let too_many_elements = (0..=MAX_ELEMENTS)
        .map(|n| format!("e{n}"))
        .collect::<Vec<_>>();
    assert!(SetCoverProblem::new(&too_many_elements, &[], &[], &[], 1).is_err());
    assert!(SetCoverProblem::new(&[], &[], &[], &[], MAX_SETS + 1).is_err());
    let candidates = (0..=MAX_EXACT_OPTIONAL_SETS)
        .map(|n| set(&format!("s{n:03}"), &["e"]))
        .collect::<Result<Vec<_>, _>>()?;
    let p = SetCoverProblem::new(&ids(&["e"]), &candidates, &[], &[], 1)?;
    assert!(matches!(
        p.solve(CoverMethod::ExactSmall, budget()),
        Err(CoverError::Graph(GraphError::TooLarge))
    ));
    assert_eq!(
        p.solve(CoverMethod::Greedy, budget())?.status(),
        CoverStatus::Covered
    );
    Ok(())
}

#[test]
fn exact_work_boundary_and_output_allowance_are_enforced() -> TestResult {
    let p = fixture(3)?;
    for method in [CoverMethod::ExactSmall, CoverMethod::Greedy] {
        let good = p.solve(method, budget())?;
        let consumed = good.counters().work_units();
        assert_eq!(
            good,
            p.solve(
                method,
                CoverBudget {
                    max_work_units: consumed,
                    ..budget()
                }
            )?
        );
        assert!(matches!(
            p.solve(
                method,
                CoverBudget {
                    max_work_units: consumed - 1,
                    ..budget()
                }
            ),
            Err(CoverError::Graph(GraphError::BudgetExhausted {
                dimension: "work_units",
                ..
            }))
        ));
        assert!(matches!(
            p.solve(
                method,
                CoverBudget {
                    max_output_entries: 0,
                    ..budget()
                }
            ),
            Err(CoverError::Graph(GraphError::BudgetExhausted {
                dimension: "output_entries",
                ..
            }))
        ));
        let overflow_safe = CoverBudget {
            max_work_units: u64::MAX,
            max_output_entries: u64::MAX,
        };
        assert_eq!(good, p.solve(method, overflow_safe)?);
    }
    Ok(())
}

#[test]
fn cancellation_at_every_poll_never_returns_an_answer_or_changes_input() -> TestResult {
    let p = fixture(3)?;
    let original = p.clone();
    for method in [CoverMethod::ExactSmall, CoverMethod::Greedy] {
        let calls = Cell::new(0);
        let expected = p.solve_cancellable(method, budget(), &|| {
            calls.set(calls.get() + 1);
            false
        })?;
        for cancel_at in 1..=calls.get() {
            let seen = Cell::new(0);
            let result = p.solve_cancellable(method, budget(), &|| {
                seen.set(seen.get() + 1);
                seen.get() >= cancel_at
            });
            assert!(
                matches!(result, Err(CoverError::Cancelled)),
                "poll {cancel_at}"
            );
            assert_eq!(p, original);
        }
        assert_eq!(expected, p.solve(method, budget())?);
    }
    Ok(())
}

#[test]
fn witness_pins_parent_anchor_method_and_complete_disposition_digest() -> TestResult {
    let p = fixture(2)?;
    let exact = p.solve(CoverMethod::ExactSmall, budget())?;
    let greedy = p.solve(CoverMethod::Greedy, budget())?;
    let anchor = LedgerAnchor::genesis("site:cover");
    let a = exact.witness("coverage-parent:one", anchor.clone())?;
    let b = exact.witness("coverage-parent:two", anchor.clone())?;
    let g = greedy.witness("coverage-parent:one", anchor)?;
    assert_eq!(a.algorithm_id(), ALGORITHM_ID);
    assert_eq!(a.input_digest(), p.digest());
    assert_eq!(a.output_digest(), exact.output_digest());
    assert_ne!(a.digest(), b.digest());
    assert_ne!(a.digest(), g.digest());
    assert_eq!(g.exactness(), "approximate");
    assert_eq!(greedy.status(), CoverStatus::HeuristicIncomplete);
    assert_eq!(
        a.budget_consumed().get("work_units"),
        Some(&exact.counters().work_units())
    );
    Ok(())
}

#[test]
fn coverage_projection_adapter_preserves_zero_support_and_refuses_tampering() -> TestResult {
    let observations = [
        CoverageObservation {
            sensor_id: "a".into(),
            zone_scope: "zone:x".into(),
            witnesses: 2,
        },
        CoverageObservation {
            sensor_id: "b".into(),
            zone_scope: "zone:x".into(),
            witnesses: 0,
        },
    ];
    let mut projection = SensorCoverageProjection::build("site:cover", &observations)?;
    let p = SetCoverProblem::from_coverage(&projection, &ids(&["zone:x"]), &[], &[], 1)?;
    assert_eq!(p.sets().len(), 2);
    assert_eq!(
        p.solve(CoverMethod::ExactSmall, budget())?.selected(),
        ids(&["a"])
    );
    let unknown = SetCoverProblem::from_coverage(&projection, &ids(&["zone:unseen"]), &[], &[], 1)?;
    assert_eq!(
        unknown
            .solve(CoverMethod::ExactSmall, budget())?
            .uncoverable(),
        ids(&["zone:unseen"])
    );
    projection
        .witnesses
        .insert(("b".into(), "zone:x".into()), 1);
    assert!(SetCoverProblem::from_coverage(&projection, &ids(&["zone:x"]), &[], &[], 1).is_err());
    Ok(())
}

// Independent oracle: enumerate every bit mask, union BTreeSet strings, and globally compare
// all feasible selections. It shares no bitset support, combination enumerator or search order.
fn oracle(p: &SetCoverProblem) -> Option<Vec<String>> {
    let mut best: Option<Vec<String>> = None;
    for mask in 0..(1_usize << p.sets().len()) {
        let picked: BTreeSet<String> = p
            .sets()
            .iter()
            .enumerate()
            .filter(|(n, _)| mask & (1_usize << *n) != 0)
            .map(|(_, s)| s.id().to_owned())
            .collect();
        if picked.len() > p.maximum_sets()
            || !p.mandatory().is_subset(&picked)
            || !p.excluded().is_disjoint(&picked)
        {
            continue;
        }
        let covered: BTreeSet<String> = p
            .sets()
            .iter()
            .filter(|s| picked.contains(s.id()))
            .flat_map(|s| s.elements().iter().cloned())
            .collect();
        if !p.elements().iter().all(|e| covered.contains(e)) {
            continue;
        }
        let picked: Vec<String> = picked.into_iter().collect();
        if best
            .as_ref()
            .is_none_or(|old| (picked.len(), &picked) < (old.len(), old))
        {
            best = Some(picked);
        }
    }
    best
}
fn next(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(0x9e3779b97f4a7c15);
    let mut mixed = *seed;
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d049bb133111eb);
    mixed ^ (mixed >> 31)
}

#[test]
fn exact_matches_independent_oracle_on_seeded_constraints_and_reorderings() -> TestResult {
    let mut seed = 0x5e7c_0a11_u64;
    for trial in 0..1500 {
        let n = (next(&mut seed) % 9) as usize;
        let m = (next(&mut seed) % 9) as usize;
        let universe: Vec<String> = (0..m).map(|x| format!("e{x}")).collect();
        let mut sets = Vec::new();
        let mut mandatory = Vec::new();
        let mut excluded = Vec::new();
        for x in 0..n {
            let id = format!("s{x}");
            let mut members = Vec::new();
            for element in &universe {
                if next(&mut seed) & 4 != 0 {
                    members.push(element.clone());
                }
            }
            sets.push(CoverSet::new(&id, &members)?);
            match next(&mut seed) % 7 {
                0 => mandatory.push(id),
                1 => excluded.push(id),
                _ => {}
            }
        }
        let maximum =
            mandatory.len() + ((next(&mut seed) % (n + 1 - mandatory.len()) as u64) as usize);
        let p = SetCoverProblem::new(&universe, &sets, &mandatory, &excluded, maximum)?;
        let result = p.solve(CoverMethod::ExactSmall, budget())?;
        match oracle(&p) {
            Some(expected) => {
                assert_eq!(result.status(), CoverStatus::Covered, "trial {trial}");
                assert_eq!(result.selected(), expected, "trial {trial}");
            }
            None => assert!(
                matches!(
                    result.status(),
                    CoverStatus::Uncoverable | CoverStatus::InfeasibleWithinLimit
                ),
                "trial {trial}"
            ),
        }
        // Every positive certificate is an actual input edge from an actually selected set.
        let lookup: BTreeMap<&str, &CoverSet> = p.sets().iter().map(|s| (s.id(), s)).collect();
        for row in result.certificate() {
            assert!(result.selected().contains(&row.set_id));
            assert!(
                lookup[row.set_id.as_str()]
                    .elements()
                    .contains(&row.element)
            );
        }
        let mut reversed_universe = universe.clone();
        reversed_universe.reverse();
        sets.reverse();
        mandatory.reverse();
        excluded.reverse();
        let reordered =
            SetCoverProblem::new(&reversed_universe, &sets, &mandatory, &excluded, maximum)?;
        assert_eq!(p.digest(), reordered.digest());
        assert_eq!(result, reordered.solve(CoverMethod::ExactSmall, budget())?);
        let greedy = p.solve(CoverMethod::Greedy, budget())?;
        assert!(greedy.selected().len() <= maximum);
        if greedy.status() == CoverStatus::Covered {
            assert!(oracle(&p).is_some());
        }
    }
    Ok(())
}

#[test]
fn cardinality_limit_and_exclusions_are_bound_into_input_identity() -> TestResult {
    let p = fixture(3)?;
    assert_ne!(p.digest(), fixture(2)?.digest());
    let excluded = SetCoverProblem::new(p.elements(), p.sets(), &[], &ids(&["A"]), 3)?;
    assert_ne!(p.digest(), excluded.digest());
    assert_ne!(p.digest(), ContentDigest::sha256(b""));
    Ok(())
}

#[test]
fn subset_manifest_pins_the_public_generation_and_domains() {
    use fss_graph_algorithms::set_cover::{DECISION_DOMAIN, INPUT_DOMAIN, OUTPUT_DOMAIN};
    let manifest = include_str!("../../../architecture/set_cover_reference.json");
    for identity in [
        ALGORITHM_ID,
        INPUT_DOMAIN,
        OUTPUT_DOMAIN,
        DECISION_DOMAIN,
        CoverMethod::ExactSmall.implementation_id(),
        CoverMethod::Greedy.implementation_id(),
        CoverMethod::ExactSmall.policy_id(),
        CoverMethod::Greedy.policy_id(),
    ] {
        assert!(
            manifest.contains(&format!("\"{identity}\"")),
            "unregistered subset identity {identity}"
        );
    }
    assert!(manifest.contains("authored_unvalidated_reference_candidate"));
}
