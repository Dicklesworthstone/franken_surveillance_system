//! Dense symmetric positive-definite kernels for the reference bundle adjuster.
//!
//! Jacobi (diagonal) scaling precedes a plain row-major Cholesky factorization so
//! the relative pivot threshold is dimensionless even though the parameter vector
//! mixes radians, meters, and pixels. Every loop runs in fixed index order.

use crate::{GeometryError, WorkBudget};

/// Smallest admitted pivot of the unit-diagonal (Jacobi-scaled) matrix. A smaller
/// pivot means the reciprocal condition number of the scaled system is at or
/// below this bound, which the bundle adjuster reports as a singular system.
pub(crate) const RELATIVE_PIVOT: f64 = 1e-12;

/// Why a factorization was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FactorError {
    /// The matrix is not numerically positive definite at this (scaled) pivot.
    NotPositiveDefinite(usize),
    /// Work accounting refused the factorization.
    Budget(GeometryError),
}

/// Jacobi-scaled lower Cholesky factor of a dense symmetric matrix.
#[derive(Debug)]
pub(crate) struct Factor {
    n: usize,
    lower: Vec<f64>,
    scale: Vec<f64>,
}

pub(crate) fn cube_units(n: usize) -> u64 {
    let n = n as u64;
    n.saturating_mul(n).saturating_mul(n) / 3 + n * n + 1
}

impl Factor {
    /// Factor the row-major `n x n` matrix `a` (only symmetric input is meaningful).
    pub(crate) fn new(
        a: &[f64],
        n: usize,
        budget: &mut WorkBudget<'_>,
    ) -> Result<Self, FactorError> {
        budget.charge(cube_units(n)).map_err(FactorError::Budget)?;
        let mut scale = vec![0.0; n];
        for (i, value) in scale.iter_mut().enumerate() {
            let diagonal = a[i * n + i];
            if !diagonal.is_finite() || diagonal <= 0.0 {
                return Err(FactorError::NotPositiveDefinite(i));
            }
            *value = 1.0 / diagonal.sqrt();
        }
        let mut lower = vec![0.0; n * n];
        for j in 0..n {
            let mut pivot = a[j * n + j] * scale[j] * scale[j];
            for k in 0..j {
                pivot -= lower[j * n + k] * lower[j * n + k];
            }
            if !pivot.is_finite() || pivot <= RELATIVE_PIVOT {
                return Err(FactorError::NotPositiveDefinite(j));
            }
            let root = pivot.sqrt();
            lower[j * n + j] = root;
            for i in j + 1..n {
                let mut value = a[i * n + j] * scale[i] * scale[j];
                for k in 0..j {
                    value -= lower[i * n + k] * lower[j * n + k];
                }
                lower[i * n + j] = value / root;
            }
        }
        Ok(Self { n, lower, scale })
    }

    /// Solve `a x = rhs` for the factored matrix.
    pub(crate) fn solve(&self, rhs: &[f64]) -> Vec<f64> {
        let n = self.n;
        let mut y: Vec<f64> = rhs.iter().zip(&self.scale).map(|(r, s)| r * s).collect();
        for i in 0..n {
            let mut value = y[i];
            for k in 0..i {
                value -= self.lower[i * n + k] * y[k];
            }
            y[i] = value / self.lower[i * n + i];
        }
        for i in (0..n).rev() {
            let mut value = y[i];
            for k in i + 1..n {
                value -= self.lower[k * n + i] * y[k];
            }
            y[i] = value / self.lower[i * n + i];
        }
        for (value, s) in y.iter_mut().zip(&self.scale) {
            *value *= s;
        }
        y
    }

    /// Dense inverse, column by column, in fixed order.
    pub(crate) fn inverse(&self, budget: &mut WorkBudget<'_>) -> Result<Vec<f64>, GeometryError> {
        let n = self.n;
        budget.charge(cube_units(n).saturating_mul(3))?;
        let mut inverse = vec![0.0; n * n];
        let mut unit = vec![0.0; n];
        for column in 0..n {
            unit[column] = 1.0;
            let solved = self.solve(&unit);
            unit[column] = 0.0;
            for (row, value) in solved.into_iter().enumerate() {
                inverse[row * n + column] = value;
            }
        }
        // Symmetrize so tiny rounding asymmetries never leak into reported covariance.
        for i in 0..n {
            for j in i + 1..n {
                let mean = 0.5 * (inverse[i * n + j] + inverse[j * n + i]);
                inverse[i * n + j] = mean;
                inverse[j * n + i] = mean;
            }
        }
        Ok(inverse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solves_and_inverts_spd_and_refuses_rank_deficiency() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut budget = WorkBudget::new(1_000_000);
        let a = [4.0, 1.0, 0.5, 1.0, 3.0, 0.25, 0.5, 0.25, 2.0];
        let factor = Factor::new(&a, 3, &mut budget).map_err(|e| format!("{e:?}"))?;
        let x = factor.solve(&[1.0, 2.0, 3.0]);
        for (row, expected) in [1.0, 2.0, 3.0].iter().enumerate() {
            let product: f64 = (0..3).map(|k| a[row * 3 + k] * x[k]).sum();
            assert!((product - expected).abs() < 1e-12);
        }
        let inverse = factor.inverse(&mut budget)?;
        for i in 0..3 {
            for j in 0..3 {
                let product: f64 = (0..3).map(|k| a[i * 3 + k] * inverse[k * 3 + j]).sum();
                let expected = if i == j { 1.0 } else { 0.0 };
                assert!((product - expected).abs() < 1e-12);
            }
        }
        // Rank two: third row is the sum of the first two.
        let singular = [1.0, 0.0, 1.0, 0.0, 1.0, 1.0, 1.0, 1.0, 2.0];
        assert!(matches!(
            Factor::new(&singular, 3, &mut budget),
            Err(FactorError::NotPositiveDefinite(2))
        ));
        Ok(())
    }
}
