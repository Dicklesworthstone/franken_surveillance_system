#![forbid(unsafe_code)]
//! Exhaustive small-matrix oracle and public admission boundaries.

use super::*;
use fss_geometry::GeometryError;
use std::sync::atomic::AtomicBool;

type Test = Result<(), ImageTrackingError>;

fn oracle(costs: &[Option<u32>], excluded: Option<(usize, usize)>) -> Option<u64> {
    let mut minimum = None;
    for first in 0..4 {
        for second in 0..4 {
            if first == second || excluded == Some((0, first)) || excluded == Some((1, second)) {
                continue;
            }
            if let (Some(a), Some(b)) = (costs[first], costs[4 + second]) {
                let cost = u64::from(a) + u64::from(b);
                minimum = Some(minimum.map_or(cost, |previous: u64| previous.min(cost)));
            }
        }
    }
    minimum
}

#[test]
fn exhaustive_rectangular_assignments_and_exclusions_match_enumeration() -> Test {
    // All 3^8 two-row matrices: zero, positive, or forbidden edges.
    for encoded in 0..6561_u32 {
        let mut remaining = encoded;
        let mut costs = [None; 8];
        for cost in &mut costs {
            *cost = match remaining % 3 {
                0 => None,
                1 => Some(0),
                _ => Some(7),
            };
            remaining /= 3;
        }
        for excluded in [None, Some((0, 0)), Some((1, 3))] {
            let result = solve(&costs, 2, 4, excluded, &mut WorkBudget::new(10_000));
            if let Some(expected) = oracle(&costs, excluded) {
                let result = result?;
                assert_eq!(
                    result.cost(),
                    expected,
                    "matrix={encoded}, excluded={excluded:?}"
                );
                assert_ne!(result.columns()[0], result.columns()[1]);
                for (row, &column) in result.columns().iter().enumerate() {
                    assert!(costs[row * 4 + column].is_some());
                    assert_ne!(excluded, Some((row, column)));
                }
            } else {
                assert!(matches!(result, Err(ImageTrackingError::InvalidInput)));
            }
        }
    }
    Ok(())
}

#[test]
fn zero_rows_and_maximum_dimensions_are_supported() -> Test {
    let empty = solve(&[], 0, 0, None, &mut WorkBudget::new(1_000))?;
    assert!(empty.columns().is_empty());
    assert_eq!(empty.cost(), 0);
    let mut costs = vec![None; 64 * 128];
    for row in 0..64 {
        costs[row * 128 + row] = Some(0);
        costs[row * 128 + 64 + row] = Some(MAX_ASSIGNMENT_COST);
    }
    let result = solve(
        &costs,
        64,
        128,
        Some((31, 31)),
        &mut WorkBudget::new(10_000_000),
    )?;
    assert_eq!(result.cost(), u64::from(MAX_ASSIGNMENT_COST));
    assert_eq!(result.columns()[31], 95);
    Ok(())
}

#[test]
fn malformed_costs_shapes_exclusions_and_infeasible_graphs_are_refused() {
    for (costs, rows, columns, excluded) in [
        (vec![Some(1)], 2, 1, None),
        (vec![Some(1)], 1, 2, None),
        (vec![Some(MAX_ASSIGNMENT_COST + 1)], 1, 1, None),
        (vec![Some(1)], 1, 1, Some((1, 0))),
        (vec![Some(1)], 1, 1, Some((0, 1))),
        (vec![None], 1, 1, None),
        (vec![Some(1)], 1, 1, Some((0, 0))),
        (vec![], usize::MAX, usize::MAX, None),
    ] {
        assert!(matches!(
            solve(
                &costs,
                rows,
                columns,
                excluded,
                &mut WorkBudget::new(100_000)
            ),
            Err(ImageTrackingError::InvalidInput)
        ));
    }
}

#[test]
fn cancellation_and_work_exhaustion_never_return_a_partial_assignment() {
    let cancelled = AtomicBool::new(true);
    assert!(matches!(
        solve(
            &[Some(1)],
            1,
            1,
            None,
            &mut WorkBudget::cancellable(100_000, &cancelled)
        ),
        Err(ImageTrackingError::Geometry(GeometryError::Cancelled))
    ));
    assert!(matches!(
        solve(&[Some(1)], 1, 1, None, &mut WorkBudget::new(1)),
        Err(ImageTrackingError::Geometry(GeometryError::BudgetExhausted))
    ));
}
