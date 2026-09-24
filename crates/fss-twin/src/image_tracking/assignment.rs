#![forbid(unsafe_code)]
//! Bounded public access to the image tracker's existing Hungarian solver.
//!
//! This is a numeric assignment, not evidence of object identity. Callers own
//! candidate gates, stable row/column ordering, miss costs and ambiguity policy.
//! The solver remains single-owned by the parent module; image tracking is unchanged.

use super::{FORBIDDEN, ImageTrackingError, MAX_COLUMNS, MAX_IMAGE_TRACKS, assign, reserve};
use fss_geometry::WorkBudget;

/// Largest finite per-edge cost accepted by the shared bounded solver.
pub const MAX_ASSIGNMENT_COST: u32 = 1_000_000_000;

/// One minimum-cost injection of rows into columns, not a uniqueness certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssignmentSolution {
    columns: Vec<usize>,
    cost: u64,
}

impl AssignmentSolution {
    /// Assigned column for every row, in the caller's original row order.
    pub fn columns(&self) -> &[usize] {
        &self.columns
    }

    /// Sum of the selected finite integer costs.
    pub fn cost(&self) -> u64 {
        self.cost
    }
}

/// Minimizes a complete row-major rectangular cost matrix using the same solver
/// as image tracking. `None` forbids an edge; no forbidden edge is ever returned.
/// At most 64 rows and 128 columns are accepted, with `rows <= columns`.
///
/// An optional excluded edge permits the caller to test global alternatives.
/// Provide distinct finite miss columns to guarantee feasibility under exclusion.
/// Invalid dimensions, costs, exclusion indices or an infeasible assignment return
/// `InvalidInput`. Cancellation, work exhaustion and allocation failure retain the
/// existing typed errors. No partial solution escapes on any error.
pub fn solve(
    costs: &[Option<u32>],
    rows: usize,
    columns: usize,
    excluded: Option<(usize, usize)>,
    budget: &mut WorkBudget<'_>,
) -> Result<AssignmentSolution, ImageTrackingError> {
    budget.charge(1)?;
    if rows > MAX_IMAGE_TRACKS
        || columns > MAX_COLUMNS
        || columns < rows
        || costs.len() != rows * columns
        || excluded.is_some_and(|(row, column)| row >= rows || column >= columns)
    {
        return Err(ImageTrackingError::InvalidInput);
    }
    budget.charge(costs.len() as u64 + rows as u64)?;
    let mut finite = reserve(costs.len())?;
    for cost in costs {
        if cost.is_some_and(|value| value > MAX_ASSIGNMENT_COST) {
            return Err(ImageTrackingError::InvalidInput);
        }
        finite.push(cost.map_or(FORBIDDEN, i64::from));
    }
    let solution = assign(&finite, rows, columns, excluded, budget)?;
    let mut selected = reserve(rows)?;
    selected.extend_from_slice(&solution.columns[..rows]);
    budget.charge(0)?;
    Ok(AssignmentSolution {
        columns: selected,
        cost: solution.cost,
    })
}

#[cfg(test)]
mod tests;
