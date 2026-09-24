#![forbid(unsafe_code)]

use crate::TwinError;

/// Closed finite interval; arithmetic rounds outward, not to a confidence level.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Interval {
    lo: f64,
    hi: f64,
}
impl Interval {
    /// Validate ordered finite endpoints.
    pub fn new(lo: f64, hi: f64) -> Result<Self, TwinError> {
        if !lo.is_finite() || !hi.is_finite() || lo > hi {
            return Err(TwinError::Numeric);
        }
        Ok(Self { lo, hi })
    }
    /// Lower endpoint.
    pub fn lower(self) -> f64 {
        self.lo
    }
    /// Upper endpoint.
    pub fn upper(self) -> f64 {
        self.hi
    }
    /// Whether an ordinary finite value belongs to the interval.
    pub fn contains(self, value: f64) -> bool {
        value >= self.lo && value <= self.hi
    }
    /// Midpoint as a nominal representative, not an additional observation.
    pub fn midpoint(self) -> f64 {
        self.lo * 0.5 + self.hi * 0.5
    }
    pub(crate) fn point(x: f64) -> Result<Self, TwinError> {
        Self::new(x, x)
    }
    pub(crate) fn around(x: f64, error: f64) -> Result<Self, TwinError> {
        if !error.is_finite() || error < 0.0 {
            return Err(TwinError::Numeric);
        }
        Self::outward(x - error, x + error)
    }
    pub(crate) fn outward(lo: f64, hi: f64) -> Result<Self, TwinError> {
        Self::new(down(lo), up(hi))
    }
    pub(crate) fn add(self, b: Self) -> Result<Self, TwinError> {
        Self::outward(self.lo + b.lo, self.hi + b.hi)
    }
    pub(crate) fn sub(self, b: Self) -> Result<Self, TwinError> {
        Self::outward(self.lo - b.hi, self.hi - b.lo)
    }
    pub(crate) fn mul(self, b: Self) -> Result<Self, TwinError> {
        extremes([
            self.lo * b.lo,
            self.lo * b.hi,
            self.hi * b.lo,
            self.hi * b.hi,
        ])
    }
    pub(crate) fn div(self, b: Self) -> Result<Self, TwinError> {
        if b.contains(0.0) {
            return Err(TwinError::Unobservable);
        }
        extremes([
            self.lo / b.lo,
            self.lo / b.hi,
            self.hi / b.lo,
            self.hi / b.hi,
        ])
    }
    pub(crate) fn square(self) -> Result<Self, TwinError> {
        let upper = (self.lo * self.lo).max(self.hi * self.hi);
        let lower = if self.contains(0.0) {
            0.0
        } else {
            (self.lo * self.lo).min(self.hi * self.hi)
        };
        Self::new(if lower == 0.0 { 0.0 } else { down(lower) }, up(upper))
    }
    pub(crate) fn sqrt(self) -> Result<Self, TwinError> {
        if self.lo < 0.0 {
            return Err(TwinError::Numeric);
        }
        Self::new(
            if self.lo == 0.0 {
                0.0
            } else {
                down(self.lo.sqrt())
            },
            up(self.hi.sqrt()),
        )
    }
    pub(crate) fn intersect(self, b: Self) -> Option<Self> {
        let lo = self.lo.max(b.lo);
        let hi = self.hi.min(b.hi);
        (lo <= hi).then_some(Self { lo, hi })
    }
}
fn extremes(values: [f64; 4]) -> Result<Interval, TwinError> {
    if values.iter().any(|x| !x.is_finite()) {
        return Err(TwinError::Numeric);
    }
    Interval::outward(
        values.iter().copied().fold(f64::INFINITY, f64::min),
        values.iter().copied().fold(f64::NEG_INFINITY, f64::max),
    )
}
fn up(x: f64) -> f64 {
    if !x.is_finite() {
        return x;
    }
    if x == 0.0 {
        return f64::from_bits(1);
    }
    f64::from_bits(if x > 0.0 {
        x.to_bits() + 1
    } else {
        x.to_bits() - 1
    })
}
fn down(x: f64) -> f64 {
    -up(-x)
}

/// Axis-aligned position/velocity bounds in the exact declared property frame.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Bounds3(pub [Interval; 3]);
impl Bounds3 {
    /// Construct an explicit box, retaining correlations conservatively by enclosure.
    pub fn new(lower: [f64; 3], upper: [f64; 3]) -> Result<Self, TwinError> {
        Ok(Self([
            Interval::new(lower[0], upper[0])?,
            Interval::new(lower[1], upper[1])?,
            Interval::new(lower[2], upper[2])?,
        ]))
    }
    /// Nominal box centre, not proof that the centre lies on a physical surface.
    pub fn centre(self) -> [f64; 3] {
        self.0.map(Interval::midpoint)
    }
    /// Membership of a point in all coordinate intervals.
    pub fn contains(self, point: [f64; 3]) -> bool {
        (0..3).all(|i| self.0[i].contains(point[i]))
    }
}

pub(crate) type I3 = [Interval; 3];
pub(crate) fn sub(a: I3, b: I3) -> Result<I3, TwinError> {
    Ok([a[0].sub(b[0])?, a[1].sub(b[1])?, a[2].sub(b[2])?])
}
pub(crate) fn dot(a: I3, b: I3) -> Result<Interval, TwinError> {
    a[0].mul(b[0])?.add(a[1].mul(b[1])?)?.add(a[2].mul(b[2])?)
}
pub(crate) fn cross(a: I3, b: I3) -> Result<I3, TwinError> {
    Ok([
        a[1].mul(b[2])?.sub(a[2].mul(b[1])?)?,
        a[2].mul(b[0])?.sub(a[0].mul(b[2])?)?,
        a[0].mul(b[1])?.sub(a[1].mul(b[0])?)?,
    ])
}
