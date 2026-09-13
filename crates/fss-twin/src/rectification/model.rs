#![forbid(unsafe_code)]

use super::{RectificationError, RectificationSpec};
use crate::Interval;
use fss_geometry::WorkBudget;

/// Forward distortion from a normalized positive-Z ray into the source image.
/// These are explicit model families, not arbitrary OpenCV coefficient vectors.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LensDistortion {
    /// Already pinhole, including explicit crop/resize through different intrinsics.
    Pinhole,
    /// Polynomial radial k1/k2/k3 and tangential p1/p2 (Brown-Conrady).
    BrownConrady {
        /// Coefficients of r², r⁴, r⁶ in radial scale.
        radial: [f64; 3],
        /// Tangential coefficients [p1, p2].
        tangential: [f64; 2],
    },
    /// Central fisheye: theta_d = theta*(1+k1*theta²+...+k4*theta⁸).
    /// Only rays in the front optical hemisphere are represented by this adapter.
    Fisheye {
        /// Four angular polynomial coefficients in increasing power order.
        coefficients: [f64; 4],
    },
}

impl LensDistortion {
    pub(super) fn is_pinhole(self) -> bool {
        match self {
            Self::Pinhole => true,
            Self::BrownConrady { radial, tangential } => radial == [0.0; 3] && tangential == [0.0; 2],
            Self::Fisheye { .. } => false,
        }
    }

    pub(super) fn encode(self, bytes: &mut Vec<u8>) {
        match self {
            Self::Pinhole => bytes.push(0),
            Self::BrownConrady { radial, tangential } => {
                bytes.push(1);
                for value in radial.into_iter().chain(tangential) { super::float(bytes, value); }
            }
            Self::Fisheye { coefficients } => {
                bytes.push(2);
                for value in coefficients { super::float(bytes, value); }
            }
        }
    }

    pub(super) fn validate(self, radius: f64, budget: &mut WorkBudget<'_>) -> Result<(), RectificationError> {
        let finite = |values: &[f64]| values.iter().all(|x| x.is_finite() && x.abs() <= 100.0);
        match self {
            Self::Pinhole => Ok(()),
            Self::BrownConrady { radial, tangential } => {
                if !finite(&radial) || !finite(&tangential) { return Err(RectificationError::InvalidModel); }
                // The radial Jacobian eigenvalues are f(q) and f(q)+2q*f'(q).
                // The tangential Jacobian is symmetric with spectral norm <=
                // 8*r*(|p1|+|p2|). A positive lower bound implies strict monotonicity
                // on the entire convex disk, not just at output pixel centers.
                let tangential_bound = point(8.0)?.mul(point(radius)?)?
                    .mul(point(tangential[0].abs())?.add(point(tangential[1].abs())?)?)?.upper();
                let qmax = point(radius)?.square()?.upper();
                let f = [point(1.0)?, point(radial[0])?, point(radial[1])?, point(radial[2])?];
                let g = [point(1.0)?, point(radial[0])?.mul(point(3.0)?)?,
                    point(radial[1])?.mul(point(5.0)?)?, point(radial[2])?.mul(point(7.0)?)?];
                positive_polynomial(&f, qmax, tangential_bound, budget)?;
                positive_polynomial(&g, qmax, tangential_bound, budget)
            }
            Self::Fisheye { coefficients } => {
                if !finite(&coefficients) { return Err(RectificationError::InvalidModel); }
                // Sufficient whole-front-hemisphere admission. 1.571 > pi/2 avoids
                // claiming a rigorously rounded transcendental bound from atan().
                // Some valid narrow-field models are conservatively refused.
                let qmax = point(1.571)?.square()?.upper();
                let derivative = [point(1.0)?, point(coefficients[0])?.mul(point(3.0)?)?,
                    point(coefficients[1])?.mul(point(5.0)?)?,
                    point(coefficients[2])?.mul(point(7.0)?)?, point(coefficients[3])?.mul(point(9.0)?)?];
                positive_polynomial(&derivative, qmax, 0.0, budget)
            }
        }
    }

    fn distort(self, x: f64, y: f64) -> Result<[f64; 2], RectificationError> {
        let q = x*x + y*y;
        let result = match self {
            Self::Pinhole => [x, y],
            Self::BrownConrady { radial: [k1,k2,k3], tangential: [p1,p2] } => {
                let f = 1.0 + q*(k1 + q*(k2 + q*k3));
                [x*f + 2.0*p1*x*y + p2*(q + 2.0*x*x),
                 y*f + p1*(q + 2.0*y*y) + 2.0*p2*x*y]
            }
            Self::Fisheye { coefficients: [k1,k2,k3,k4] } => {
                let r = x.hypot(y);
                if r == 0.0 { return Ok([0.0, 0.0]); }
                let theta = r.atan();
                let t = theta*theta;
                let f = (theta/r) * (1.0 + t*(k1 + t*(k2 + t*(k3 + t*k4))));
                [x*f, y*f]
            }
        };
        if result.iter().any(|v| !v.is_finite()) { return Err(RectificationError::Numeric); }
        Ok(result)
    }
}

fn point(x: f64) -> Result<Interval, RectificationError> { Ok(Interval::point(x)?) }

fn positive_polynomial(coefficients: &[Interval], maximum: f64, floor: f64,
    budget: &mut WorkBudget<'_>) -> Result<(), RectificationError> {
    // Fixed subdivision plus outward Horner bounds: sufficient, never a sampled
    // positivity test. Strict refusal also covers inconclusive interval bounds.
    for cell in 0..128 {
        budget.charge(32)?;
        let x = Interval::outward(maximum*(f64::from(cell)/128.0),
            maximum*(f64::from(cell+1)/128.0))?;
        let mut value = point(0.0)?;
        for &coefficient in coefficients.iter().rev() { value = value.mul(x)?.add(coefficient)?; }
        if value.lower() <= floor || value.lower() - floor <= 1e-7 {
            return Err(RectificationError::NonInvertibleModel);
        }
    }
    Ok(())
}

pub(super) fn source_pixel(spec: RectificationSpec, pixel: [f64; 2])
    -> Result<Option<[f64; 2]>, RectificationError> {
    if !spec.target.contains(pixel) { return Err(RectificationError::InvalidInput); }
    let [fx,fy] = spec.target.focal_lengths();
    let [cx,cy] = spec.target.principal_point();
    let x = (pixel[0]-cx)/fx;
    let y = (pixel[1]-cy)/fy;
    if !x.is_finite() || !y.is_finite() { return Err(RectificationError::Numeric); }
    if x.hypot(y) > spec.maximum_radius { return Ok(None); }
    if spec.distortion.is_pinhole() && spec.source == spec.target { return Ok(Some(pixel)); }
    let distorted = spec.distortion.distort(x,y)?;
    let [sx,sy] = spec.source.focal_lengths();
    let [ox,oy] = spec.source.principal_point();
    let result = [sx*distorted[0]+ox, sy*distorted[1]+oy];
    if result.iter().any(|v| !v.is_finite()) { return Err(RectificationError::Numeric); }
    Ok(Some(result))
}
