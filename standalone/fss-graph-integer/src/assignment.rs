#![forbid(unsafe_code)]
//! Exact signed-cost perfect assignment with a checkable primal-dual certificate.
use std::vec::Vec;

/// Failure to admit or certify an assignment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssignmentError {
    /// Not a square matrix.
    Shape,
    /// Dimension or charged work exceeds caller limits.
    Budget,
    /// A signed 128-bit intermediate overflowed.
    Overflow,
    /// The primal-dual optimality witness was inconsistent.
    Certificate,
}

/// Limits for a single Hungarian solve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssignmentBudget {
    /// Largest accepted dimension.
    pub max_dimension: usize,
    /// Maximum examined edges and potential updates.
    pub max_steps: u64,
}

/// Complete optimality witness for a minimum-cost perfect assignment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssignmentWitness {
    /// Column chosen for each row.
    pub columns: Vec<usize>,
    /// Sum of chosen signed costs.
    pub objective: i128,
    /// Dual row potentials.
    pub row_dual: Vec<i128>,
    /// Dual column potentials.
    pub column_dual: Vec<i128>,
    /// Work charged, including certificate validation.
    pub steps: u64,
}

fn step(steps: &mut u64, limit: u64) -> Result<(), AssignmentError> {
    *steps = steps.checked_add(1).ok_or(AssignmentError::Overflow)?;
    if *steps > limit { Err(AssignmentError::Budget) } else { Ok(()) }
}

/// Deterministic O(n-cubed) Hungarian assignment for a complete square matrix.
///
/// All amounts are exact signed i128. Returned duals are independently checked
/// for global feasibility and equality on assigned pairs. Column-order scanning
/// gives deterministic ties, not a lexicographically minimality guarantee.
///
/// # Errors
/// Refuses malformed input, budget exhaustion, overflow or invalid certificates.
pub fn minimum_cost_assignment(
    costs: &[Vec<i128>], budget: AssignmentBudget,
) -> Result<AssignmentWitness, AssignmentError> {
    let n = costs.len();
    if n > budget.max_dimension { return Err(AssignmentError::Budget); }
    if costs.iter().any(|r| r.len() != n) { return Err(AssignmentError::Shape); }
    if n == 0 {
        return Ok(AssignmentWitness {
            columns: Vec::new(), objective: 0, row_dual: Vec::new(),
            column_dual: Vec::new(), steps: 0,
        });
    }
    let mut u = vec![0_i128; n + 1];
    let mut v = vec![0_i128; n + 1];
    let mut p = vec![0_usize; n + 1];
    let mut way = vec![0_usize; n + 1];
    let mut steps = 0_u64;
    for i in 1..=n {
        p[0] = i;
        let mut j0 = 0_usize;
        let mut slack = vec![None::<i128>; n + 1];
        let mut used = vec![false; n + 1];
        loop {
            used[j0] = true;
            let i0 = p[j0];
            let mut delta = None::<i128>;
            let mut j1 = 0_usize;
            for j in 1..=n {
                if used[j] { continue; }
                step(&mut steps, budget.max_steps)?;
                let reduced = costs[i0-1][j-1].checked_sub(u[i0])
                    .and_then(|x| x.checked_sub(v[j]))
                    .ok_or(AssignmentError::Overflow)?;
                if slack[j].is_none_or(|s| reduced < s) {
                    slack[j] = Some(reduced);
                    way[j] = j0;
                }
                let candidate = slack[j].ok_or(AssignmentError::Certificate)?;
                if delta.is_none_or(|d| candidate < d) {
                    delta = Some(candidate);
                    j1 = j;
                }
            }
            let d = delta.ok_or(AssignmentError::Certificate)?;
            for j in 0..=n {
                step(&mut steps, budget.max_steps)?;
                if used[j] {
                    u[p[j]].checked_add(d).ok_or(AssignmentError::Overflow)?;
                    v[j].checked_sub(d).ok_or(AssignmentError::Overflow)?;
                } else if let Some(s) = slack[j] {
                    s.checked_sub(d).ok_or(AssignmentError::Overflow)?;
                }
            }
            for j in 0..=n {
                if used[j] {
                    u[p[j]] += d;
                    v[j] -= d;
                } else if let Some(s) = slack[j] {
                    slack[j] = Some(s - d);
                }
            }
            j0 = j1;
            if p[j0] == 0 { break; }
        }
        loop {
            let j1 = way[j0];
            p[j0] = p[j1];
            j0 = j1;
            if j0 == 0 { break; }
        }
    }
    let mut columns = vec![usize::MAX; n];
    for j in 1..=n {
        if p[j] == 0 { return Err(AssignmentError::Certificate); }
        columns[p[j]-1] = j-1;
    }
    let mut seen = vec![false; n];
    let mut objective = 0_i128;
    for (i, &j) in columns.iter().enumerate() {
        if j >= n || seen[j] { return Err(AssignmentError::Certificate); }
        seen[j] = true;
        objective = objective.checked_add(costs[i][j]).ok_or(AssignmentError::Overflow)?;
    }
    let mut dual = 0_i128;
    for &x in u.iter().skip(1).chain(v.iter().skip(1)) {
        dual = dual.checked_add(x).ok_or(AssignmentError::Overflow)?;
    }
    if dual != objective { return Err(AssignmentError::Certificate); }
    for i in 0..n {
        for j in 0..n {
            step(&mut steps, budget.max_steps)?;
            let lower = u[i+1].checked_add(v[j+1]).ok_or(AssignmentError::Overflow)?;
            if lower > costs[i][j] || (columns[i] == j && lower != costs[i][j]) {
                return Err(AssignmentError::Certificate);
            }
        }
    }
    Ok(AssignmentWitness {
        columns, objective, row_dual: u[1..].to_vec(),
        column_dual: v[1..].to_vec(), steps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn budget() -> AssignmentBudget {
        AssignmentBudget { max_dimension: 32, max_steps: 100_000 }
    }
    #[test]
    fn signed_above_u64() {
        let large = i128::from(u64::MAX) + 1;
        let out = minimum_cost_assignment(&[vec![-large, 7], vec![3, -large]], budget()).unwrap();
        assert_eq!(out.columns, vec![0,1]);
        assert_eq!(out.objective, -2*large);
    }
    #[test]
    fn globally_optimal_not_greedy() {
        let out = minimum_cost_assignment(&[vec![2,1,3],vec![3,0,5],vec![2,2,2]], budget()).unwrap();
        assert_eq!(out.objective, 4);
    }
    #[test]
    fn malformed_bounded_and_overflow() {
        assert_eq!(minimum_cost_assignment(&[vec![1],vec![2]], budget()), Err(AssignmentError::Shape));
        assert_eq!(minimum_cost_assignment(&[vec![1]], AssignmentBudget {
            max_dimension: 1, max_steps: 0
        }), Err(AssignmentError::Budget));
        assert_eq!(minimum_cost_assignment(&[vec![i128::MAX, i128::MAX],
            vec![i128::MAX, i128::MAX]], budget()), Err(AssignmentError::Overflow));
    }
}


#[cfg(test)]
mod exhaustive_assignment_oracle {
    use super::*;
    #[test]
    fn exact_vs_permutation_oracle_for_signed_three_by_three() {
        let budget = AssignmentBudget { max_dimension: 3, max_steps: 100_000 };
        let permutations = [
            [0,1,2], [0,2,1], [1,0,2],
            [1,2,0], [2,0,1], [2,1,0]
        ];
        for seed in 0..100_i128 {
            let mut x = seed + 17;
            let mut matrix = vec![vec![0_i128; 3]; 3];
            for row in &mut matrix {
                for value in row {
                    x = (x * 37 + 11) % 101;
                    *value = x - 50;
                }
            }
            let expected = permutations.iter().map(|p| {
                (0..3).map(|i| matrix[i][p[i]]).sum::<i128>()
            }).min().unwrap();
            let got = minimum_cost_assignment(&matrix, budget).unwrap();
            assert_eq!(got.objective, expected, "seed {seed}");
            for i in 0..3 {
                for j in 0..3 {
                    assert!(got.row_dual[i] + got.column_dual[j] <= matrix[i][j]);
                }
            }
        }
    }
}
