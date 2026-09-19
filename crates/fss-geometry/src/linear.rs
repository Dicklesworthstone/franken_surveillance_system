use crate::math::{IDENTITY, M3, V3, cross, dot, mv, norm, normalize, scale, sub};
use crate::registration::Correspondence;
use crate::{GeometryError, WorkBudget};
use crate::{PinholeIntrinsics, RigidPose};

pub(crate) struct Eigen<const N: usize> {
    pub values: [f64; N],
    pub vectors: [[f64; N]; N],
}

// Cyclic Jacobi over tiny symmetric systems. No foreign BLAS/SVD or hidden pool.
pub(crate) fn symmetric_eigen<const N: usize>(
    mut a: [[f64; N]; N],
    budget: &mut WorkBudget<'_>,
) -> Result<Eigen<N>, GeometryError> {
    let mut maximum = 0.0_f64;
    for row in &a {
        for value in row {
            if !value.is_finite() {
                return Err(GeometryError::NonFinite);
            }
            maximum = maximum.max(value.abs());
        }
    }
    if maximum <= 1e-30 {
        return Err(GeometryError::Degenerate);
    }
    let mut vectors = [[0.0; N]; N];
    for i in 0..N {
        vectors[i][i] = 1.0;
        for value in &mut a[i] {
            *value /= maximum;
        }
    }
    for _ in 0..80 {
        budget.charge((N * N) as u64)?;
        let mut off_diagonal = 0.0_f64;
        for (p, row) in a.iter().enumerate() {
            for value in &row[p + 1..] {
                off_diagonal = off_diagonal.max(value.abs());
            }
        }
        if off_diagonal <= 1e-13 {
            return Ok(Eigen {
                values: std::array::from_fn(|i| a[i][i] * maximum),
                vectors,
            });
        }
        for p in 0..N {
            for q in p + 1..N {
                budget.charge((4 * N) as u64)?;
                let apq = a[p][q];
                if apq.abs() <= 1e-15 {
                    continue;
                }
                let tau = (a[q][q] - a[p][p]) / (2.0 * apq);
                let tangent = if tau >= 0.0 {
                    1.0 / (tau + tau.hypot(1.0))
                } else {
                    -1.0 / (-tau + tau.hypot(1.0))
                };
                let cosine = 1.0 / (1.0 + tangent * tangent).sqrt();
                let sine = tangent * cosine;
                a[p][p] -= tangent * apq;
                a[q][q] += tangent * apq;
                a[p][q] = 0.0;
                a[q][p] = 0.0;
                for k in 0..N {
                    if k != p && k != q {
                        let akp = a[k][p];
                        let akq = a[k][q];
                        a[k][p] = cosine * akp - sine * akq;
                        a[p][k] = a[k][p];
                        a[k][q] = sine * akp + cosine * akq;
                        a[q][k] = a[k][q];
                    }
                    let vkp = vectors[k][p];
                    let vkq = vectors[k][q];
                    vectors[k][p] = cosine * vkp - sine * vkq;
                    vectors[k][q] = sine * vkp + cosine * vkq;
                }
            }
        }
    }
    Err(GeometryError::SolverDidNotConverge)
}

pub(crate) fn map_normalization(
    points: &[Correspondence],
    minimum_axis_ratio: f64,
    budget: &mut WorkBudget<'_>,
) -> Result<(V3, f64), GeometryError> {
    let mut center = [0.0; 3];
    for p in points {
        budget.charge(1)?;
        for (value, coordinate) in center.iter_mut().zip(p.world) {
            *value += coordinate;
        }
    }
    center = scale(center, 1.0 / points.len() as f64);
    let mut covariance = [[0.0; 3]; 3];
    for p in points {
        budget.charge(9)?;
        let d = sub(p.world, center);
        for i in 0..3 {
            for j in 0..3 {
                covariance[i][j] += d[i] * d[j];
            }
        }
    }
    let eigen = symmetric_eigen(covariance, budget)?;
    let minimum = eigen.values.into_iter().fold(f64::INFINITY, f64::min);
    let maximum = eigen.values.into_iter().fold(0.0_f64, f64::max);
    if minimum <= maximum * minimum_axis_ratio {
        return Err(GeometryError::UnsupportedGeometry);
    }
    let size =
        ((covariance[0][0] + covariance[1][1] + covariance[2][2]) / points.len() as f64).sqrt();
    if !size.is_finite() || size <= 1e-9 {
        return Err(GeometryError::Degenerate);
    }
    Ok((center, size))
}

pub(crate) fn linear_pose(
    points: &[Correspondence],
    intrinsics: PinholeIntrinsics,
    minimum_axis_ratio: f64,
    budget: &mut WorkBudget<'_>,
) -> Result<RigidPose, GeometryError> {
    let (center, size) = map_normalization(points, minimum_axis_ratio, budget)?;
    let focal = intrinsics.focal_lengths();
    let principal = intrinsics.principal_point();
    let mut normal = [[0.0; 12]; 12];
    for p in points {
        let q = scale(sub(p.world, center), 1.0 / size);
        let base = [q[0], q[1], q[2], 1.0];
        for axis in 0..2 {
            budget.charge(144)?;
            let coordinate = (p.pixel[axis] - principal[axis]) / focal[axis];
            if !coordinate.is_finite() || coordinate.abs() > 1e4 {
                return Err(GeometryError::OutOfRange);
            }
            let mut row = [0.0; 12];
            for j in 0..4 {
                row[4 * axis + j] = base[j];
                row[8 + j] = -coordinate * base[j];
            }
            for i in 0..12 {
                for j in 0..12 {
                    normal[i][j] += row[i] * row[j];
                }
            }
        }
    }
    let eigen = symmetric_eigen(normal, budget)?;
    let mut order: [usize; 12] = std::array::from_fn(|i| i);
    order.sort_by(|a, b| eigen.values[*a].total_cmp(&eigen.values[*b]).then(a.cmp(b)));
    if eigen.values[order[1]] <= eigen.values[order[11]] * 1e-10 {
        return Err(GeometryError::Degenerate);
    }
    let coefficients: [f64; 12] = std::array::from_fn(|i| eigen.vectors[i][order[0]]);
    let mut rows: M3 = std::array::from_fn(|i| std::array::from_fn(|j| coefficients[i * 4 + j]));
    let mut shift = [coefficients[3], coefficients[7], coefficients[11]];
    if dot(rows[0], cross(rows[1], rows[2])) < 0.0 {
        for row in &mut rows {
            *row = scale(*row, -1.0);
        }
        shift = scale(shift, -1.0);
    }
    let magnitude = (norm(rows[0]) + norm(rows[1]) + norm(rows[2])) / 3.0;
    if magnitude <= 1e-12 {
        return Err(GeometryError::Degenerate);
    }
    let r0 = normalize(rows[0])?;
    let r1 = normalize(sub(rows[1], scale(r0, dot(rows[1], r0))))?;
    let rotation = [r0, r1, cross(r0, r1)];
    if dot(rotation[2], rows[2]) <= 0.0 {
        return Err(GeometryError::Degenerate);
    }
    let translation = sub(scale(shift, size / magnitude), mv(rotation, center));
    RigidPose::new(rotation, translation)
}

pub(crate) fn solve_six(
    mut a: [[f64; 6]; 6],
    mut b: [f64; 6],
    budget: &mut WorkBudget<'_>,
) -> Result<[f64; 6], GeometryError> {
    budget.charge(216)?;
    let mut diagonal = [0.0; 6];
    for i in 0..6 {
        if !a[i][i].is_finite() || a[i][i] <= 0.0 {
            return Err(GeometryError::Degenerate);
        }
        diagonal[i] = a[i][i].sqrt();
    }
    for i in 0..6 {
        b[i] /= diagonal[i];
        for j in 0..6 {
            a[i][j] /= diagonal[i] * diagonal[j];
        }
    }
    for k in 0..6 {
        let mut pivot = k;
        for i in k + 1..6 {
            if a[i][k].abs() > a[pivot][k].abs() {
                pivot = i;
            }
        }
        if !a[pivot][k].is_finite() || a[pivot][k].abs() <= 1e-12 {
            return Err(GeometryError::Degenerate);
        }
        a.swap(k, pivot);
        b.swap(k, pivot);
        let row = a[k];
        let rhs = b[k];
        for i in k + 1..6 {
            let factor = a[i][k] / row[k];
            for j in k..6 {
                a[i][j] -= factor * row[j];
            }
            b[i] -= factor * rhs;
        }
    }
    let mut solution = [0.0; 6];
    for i in (0..6).rev() {
        let mut value = b[i];
        for j in i + 1..6 {
            value -= a[i][j] * solution[j];
        }
        solution[i] = value / a[i][i];
    }
    for i in 0..6 {
        solution[i] /= diagonal[i];
        if !solution[i].is_finite() {
            return Err(GeometryError::NonFinite);
        }
    }
    Ok(solution)
}

pub(crate) fn rotation_step(w: V3) -> M3 {
    let angle = norm(w);
    let (a, b) = if angle < 1e-8 {
        (1.0 - angle * angle / 6.0, 0.5 - angle * angle / 24.0)
    } else {
        (angle.sin() / angle, (1.0 - angle.cos()) / (angle * angle))
    };
    let skew = [[0.0, -w[2], w[1]], [w[2], 0.0, -w[0]], [-w[1], w[0], 0.0]];
    let squared = multiply(skew, skew);
    std::array::from_fn(|i| {
        std::array::from_fn(|j| IDENTITY[i][j] + a * skew[i][j] + b * squared[i][j])
    })
}

pub(crate) fn multiply(a: M3, b: M3) -> M3 {
    std::array::from_fn(|i| {
        std::array::from_fn(|j| a[i][0] * b[0][j] + a[i][1] * b[1][j] + a[i][2] * b[2][j])
    })
}
