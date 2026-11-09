#![forbid(unsafe_code)]
//! Exact decimal-to-grid bounds and closed-rectangle predicates.
//!
//! These pure arithmetic functions know nothing about cameras, timestamps, source custody or
//! coordinate transforms. Decimal coordinates are rounded outward without binary floating
//! point or arbitrary-precision allocation. Their work is linear in at most 64 input bytes.

use std::fmt;

/// Integer subunits per explicitly declared raw coordinate unit.
pub const COORDINATE_SCALE: i64 = 1_000_000;
/// Absolute coordinate ceiling in integer subunits (one billion raw units).
pub const MAX_COORDINATE_MAGNITUDE: i64 = 1_000_000_000_000_000;
/// Longest admitted decimal/scientific coordinate spelling.
pub const MAX_DECIMAL_BYTES: usize = 64;

/// Closed outward-rounded interval containing the exact supplied decimal coordinate.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CoordinateInterval {
    /// Greatest grid coordinate not exceeding the exact value.
    pub lower: i64,
    /// Least grid coordinate not less than the exact value.
    pub upper: i64,
}
impl fmt::Debug for CoordinateInterval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CoordinateInterval([private coordinate])")
    }
}

/// Pure arithmetic refusal, never containing the supplied coordinate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeometryError {
    /// Invalid decimal syntax, rectangle order or margin.
    Invalid,
    /// Input length or exact outward interval exceeds the finite coordinate domain.
    Range,
}

/// Conservative relation of a complete closed box to a nonempty closed rectangle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RectangleRelation {
    /// Every possible expanded-box point is strictly inside the rectangle.
    Inside,
    /// One axis strictly separates the complete expanded box from the rectangle.
    Outside,
    /// Touching, intersecting or unresolved within the declared rounding/margin interval.
    Boundary,
}

/// Convert decimal/scientific text to exact floor/ceiling millionths.
///
/// All significant decimal digits are inspected, including digits rounded away by binary64.
/// Very small nonzero values remain `[0,1]` or `[-1,0]`; they never become exact zero. Exponent
/// magnitude saturates only after its effect is provably beyond this bounded grid's range.
pub fn decimal_millionths(value: &str) -> Result<CoordinateInterval, GeometryError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_DECIMAL_BYTES {
        return Err(GeometryError::Range);
    }
    let mut position = 0;
    let negative = bytes[0] == b'-';
    if matches!(bytes[0], b'+' | b'-') {
        position += 1;
    }
    let mut digits = [0_u8; MAX_DECIMAL_BYTES];
    let mut count = 0_usize;
    let mut fractional = 0_i32;
    let mut dot = false;
    while let Some(&byte) = bytes.get(position) {
        if byte.is_ascii_digit() {
            digits[count] = byte - b'0';
            count += 1;
            fractional += i32::from(dot);
        } else if byte == b'.' && !dot {
            dot = true;
        } else {
            break;
        }
        position += 1;
    }
    if count == 0 {
        return Err(GeometryError::Invalid);
    }
    let mut exponent = 0_i32;
    if matches!(bytes.get(position), Some(b'e' | b'E')) {
        position += 1;
        let exponent_negative = bytes.get(position) == Some(&b'-');
        if matches!(bytes.get(position), Some(b'+' | b'-')) {
            position += 1;
        }
        let start = position;
        while let Some(&byte) = bytes.get(position) {
            if !byte.is_ascii_digit() {
                return Err(GeometryError::Invalid);
            }
            // At most 64 significand digits and six grid digits can offset an exponent.
            // Saturation at 4096 therefore preserves every representable rounding decision.
            exponent = (exponent * 10 + i32::from(byte - b'0')).min(4096);
            position += 1;
        }
        if position == start {
            return Err(GeometryError::Invalid);
        }
        if exponent_negative {
            exponent = -exponent;
        }
    }
    if position != bytes.len() {
        return Err(GeometryError::Invalid);
    }
    let Some(first) = digits[..count].iter().position(|digit| *digit != 0) else {
        return Ok(CoordinateInterval { lower: 0, upper: 0 });
    };
    let significant = &digits[first..count];
    let point = significant.len() as i32 + exponent - fractional + 6;
    let (floor, ceil) = if point <= 0 {
        (0_i64, 1_i64)
    } else {
        if point > 16 {
            return Err(GeometryError::Range);
        }
        let point = point as usize;
        let mut floor = 0_i64;
        for index in 0..point {
            floor = floor * 10 + i64::from(significant.get(index).copied().unwrap_or(0));
        }
        let remainder = significant
            .get(point..)
            .is_some_and(|tail| tail.iter().any(|d| *d != 0));
        let ceil = floor + i64::from(remainder);
        if ceil > MAX_COORDINATE_MAGNITUDE {
            return Err(GeometryError::Range);
        }
        (floor, ceil)
    };
    Ok(if negative {
        CoordinateInterval {
            lower: -ceil,
            upper: -floor,
        }
    } else {
        CoordinateInterval {
            lower: floor,
            upper: ceil,
        }
    })
}

/// Classify the complete outward-rounded box, expanded by `margin` on every side.
///
/// A zero-area claimed box is still a closed set; no positive physical extent is inferred.
/// All touching cases are boundary-ambiguous. Neither axis is interpreted as pixels or world
/// units, and no center-point shortcut can turn an intersecting box into an inside result.
pub fn classify_rectangle(
    box_min: [i64; 2],
    box_max: [i64; 2],
    zone_min: [i64; 2],
    zone_max: [i64; 2],
    margin: u64,
) -> Result<RectangleRelation, GeometryError> {
    let admitted = |n: i64| (-MAX_COORDINATE_MAGNITUDE..=MAX_COORDINATE_MAGNITUDE).contains(&n);
    if margin > MAX_COORDINATE_MAGNITUDE as u64
        || (0..2).any(|axis| {
            !admitted(box_min[axis])
                || !admitted(box_max[axis])
                || !admitted(zone_min[axis])
                || !admitted(zone_max[axis])
                || box_min[axis] > box_max[axis]
                || zone_min[axis] >= zone_max[axis]
        })
    {
        return Err(GeometryError::Invalid);
    }
    let lower = box_min.map(|n| i128::from(n) - i128::from(margin));
    let upper = box_max.map(|n| i128::from(n) + i128::from(margin));
    if (0..2).any(|axis| {
        upper[axis] < i128::from(zone_min[axis]) || lower[axis] > i128::from(zone_max[axis])
    }) {
        return Ok(RectangleRelation::Outside);
    }
    Ok(
        if (0..2).all(|axis| {
            lower[axis] > i128::from(zone_min[axis]) && upper[axis] < i128::from(zone_max[axis])
        }) {
            RectangleRelation::Inside
        } else {
            RectangleRelation::Boundary
        },
    )
}
