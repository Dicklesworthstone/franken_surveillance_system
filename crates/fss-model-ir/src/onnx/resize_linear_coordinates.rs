#![forbid(unsafe_code)]
//! Bounded exact-coordinate planning for spatial Resize-13 linear interpolation.
//!
//! Source scales remain rational. Coefficients round directly to nearest-even
//! F32 using integer arithmetic, without a reciprocal, reconstructed scale,
//! floating coordinate, or dense interpolation matrix.

use super::resize_coordinates::{CoordinateError, PlanningError, Scale};

const MAX_COORDINATES: usize = 4096;
const MAX_PHASES: usize = 64;
type Result<T> = std::result::Result<T, CoordinateError>;
type Planned<T, E> = std::result::Result<T, PlanningError<E>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LinearCoordinates {
    HalfPixel,
    PytorchHalfPixel,
    AlignCorners,
    Asymmetric,
}

#[derive(Clone, Copy, Debug)]
struct Sample {
    lower: usize,
    upper: usize,
    weights: [f32; 2],
}

// Denominators are at most twice a source F32 scale's 24-bit significand,
// twice an admitted output size, or output_size-1. Positive coefficients
// are therefore normal; the correctly rounded quotient fits in u128.
fn unit_weight(numerator: u128, denominator: u128) -> Result<f32> {
    if denominator == 0 || denominator > 1 << 25 || numerator > denominator {
        return Err(CoordinateError::Limit);
    }
    if numerator == 0 {
        return Ok(0.0);
    }
    if numerator == denominator {
        return Ok(1.0);
    }
    let mut shift = denominator.ilog2() - numerator.ilog2();
    if numerator.checked_shl(shift).ok_or(CoordinateError::Limit)? < denominator {
        shift += 1;
    }
    let scaled = numerator.checked_shl(23 + shift).ok_or(CoordinateError::Limit)?;
    let mut significand = scaled / denominator;
    let remainder = (scaled % denominator) * 2;
    if remainder > denominator || (remainder == denominator && significand & 1 != 0) {
        significand += 1;
    }
    let mut exponent = 127_u32.checked_sub(shift).ok_or(CoordinateError::Limit)?;
    if significand == 1 << 24 {
        significand >>= 1;
        exponent += 1;
    }
    if !((1 << 23)..(1 << 24)).contains(&significand) || exponent == 0 || exponent >= 255 {
        return Err(CoordinateError::Limit);
    }
    Ok(f32::from_bits((exponent << 23) | (significand as u32 - (1 << 23))))
}

fn sample(input: usize, scale: Scale, position: usize, mode: LinearCoordinates) -> Result<Sample> {
    let (scale_numerator, scale_denominator) = scale.ratio();
    let position = position as u128;
    let (numerator, denominator) = match mode {
        LinearCoordinates::HalfPixel | LinearCoordinates::PytorchHalfPixel
            if mode == LinearCoordinates::HalfPixel || scale.output > 1 =>
        {
            let center = position
                .checked_mul(2)
                .and_then(|n| n.checked_add(1))
                .and_then(|n| n.checked_mul(scale_denominator))
                .ok_or(CoordinateError::Limit)?;
            // Negative half-pixel coordinates use the first source sample.
            (
                center.saturating_sub(scale_numerator),
                scale_numerator.checked_mul(2).ok_or(CoordinateError::Limit)?,
            )
        }
        LinearCoordinates::AlignCorners if scale.output > 1 => (
            position.checked_mul((input - 1) as u128).ok_or(CoordinateError::Limit)?,
            (scale.output - 1) as u128,
        ),
        LinearCoordinates::Asymmetric => (
            position.checked_mul(scale_denominator).ok_or(CoordinateError::Limit)?,
            scale_numerator,
        ),
        LinearCoordinates::PytorchHalfPixel | LinearCoordinates::AlignCorners => (0, 1),
        LinearCoordinates::HalfPixel => return Err(CoordinateError::Limit),
    };
    let last = (input - 1) as u128;
    if numerator >= last.checked_mul(denominator).ok_or(CoordinateError::Limit)? {
        return Ok(Sample {
            lower: input - 1,
            upper: input - 1,
            weights: [1.0, 0.0],
        });
    }
    let lower = usize::try_from(numerator / denominator).map_err(|_| CoordinateError::Limit)?;
    let remainder = numerator % denominator;
    Ok(Sample {
        lower,
        upper: lower + 1,
        weights: [
            unit_weight(denominator - remainder, denominator)?,
            unit_weight(remainder, denominator)?,
        ],
    })
}

#[derive(Debug)]
pub(super) struct Run {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) step: usize,
    pub(super) count: usize,
    pub(super) repetitions: usize,
}
impl Run {
    fn node_count(&self) -> usize {
        1 + if self.repetitions == 1 {
            0
        } else if self.count == 1 {
            1
        } else {
            3
        }
    }
}

#[derive(Debug)]
pub(super) struct Direct {
    // An empty run list is the complete identity selection.
    pub(super) runs: Vec<Run>,
    pub(super) output: usize,
}
impl Direct {
    pub(super) fn node_count(&self) -> usize {
        self.runs.iter().map(Run::node_count).sum::<usize>() + usize::from(self.runs.len() > 1)
    }
}

#[derive(Debug)]
pub(super) enum Selection {
    Direct(Direct),
    // Select residue classes, insert adjacent singleton dimensions, concatenate
    // phases and reshape to restore the original output-position order.
    Interleave {
        phases: Vec<Direct>,
        width: usize,
        tail: Option<Direct>,
    },
}
impl Selection {
    pub(super) fn node_count(&self) -> usize {
        match self {
            Self::Direct(plan) => plan.node_count(),
            Self::Interleave { phases, tail, .. } => {
                phases.iter().map(|phase| phase.node_count() + 1).sum::<usize>()
                    + 2
                    + tail.as_ref().map_or(0, |tail| tail.node_count() + 1)
            }
        }
    }
}

pub(super) struct AxisPlan {
    pub(super) output: usize,
    pub(super) lower: Selection,
    pub(super) upper: Option<Selection>,
    pub(super) weights: Vec<[f32; 2]>,
}
impl AxisPlan {
    pub(super) fn node_count(&self) -> usize {
        self.lower.node_count()
            + self.upper.as_ref().map_or(0, |upper| upper.node_count() + 3)
    }
    pub(super) fn parameter_bytes(&self) -> usize {
        self.weights.len() * 8
    }
}

fn direct<E>(
    input: usize,
    indices: &[usize],
    maximum: usize,
    charge: &mut impl FnMut(usize) -> std::result::Result<(), E>,
) -> Planned<Option<Direct>, E> {
    charge(indices.len()).map_err(PlanningError::Admission)?;
    if indices.len() == input && indices.iter().copied().eq(0..input) {
        return Ok(Some(Direct { runs: Vec::new(), output: input }));
    }
    // Equal-value runs become sample repetitions. Neighboring equal-length
    // runs with an arithmetic progression of source indices share one Slice.
    let mut groups = Vec::new();
    groups.try_reserve_exact(indices.len()).map_err(|_| CoordinateError::Limit)?;
    let mut at = 0;
    while at < indices.len() {
        let start = at;
        while at < indices.len() && indices[at] == indices[start] {
            charge(1).map_err(PlanningError::Admission)?;
            at += 1;
        }
        groups.push((indices[start], at - start));
    }
    let mut runs = Vec::new();
    let mut nodes = 0;
    let mut at = 0;
    while at < groups.len() {
        charge(1).map_err(PlanningError::Admission)?;
        let (start, repetitions) = groups[at];
        let mut count = 1;
        let mut step = 1;
        if let Some(&(next, _)) = groups.get(at + 1).filter(|next| next.1 == repetitions) {
            step = next.checked_sub(start).filter(|&n| n > 0).ok_or(CoordinateError::Limit)?;
            count = 2;
            while at + count < groups.len()
                && groups[at + count].1 == repetitions
                && groups[at + count].0 - groups[at + count - 1].0 == step
            {
                charge(1).map_err(PlanningError::Admission)?;
                count += 1;
            }
        }
        let run = Run {
            start,
            end: groups[at + count - 1].0.checked_add(1).ok_or(CoordinateError::Limit)?,
            step,
            count,
            repetitions,
        };
        nodes += run.node_count();
        if nodes + usize::from(!runs.is_empty()) > maximum {
            return Ok(None);
        }
        runs.try_reserve(1).map_err(|_| CoordinateError::Limit)?;
        runs.push(run);
        at += count;
    }
    Ok(Some(Direct { runs, output: indices.len() }))
}

fn period(input: usize, scale: Scale, mode: LinearCoordinates) -> Result<usize> {
    let (numerator, denominator) = if mode == LinearCoordinates::AlignCorners {
        (scale.output.saturating_sub(1) as u128, input.saturating_sub(1) as u128)
    } else {
        scale.ratio()
    };
    if numerator == 0 || denominator == 0 {
        return Ok(1);
    }
    let (mut a, mut b) = (numerator, denominator);
    while b != 0 {
        (a, b) = (b, a % b);
    }
    let exact = numerator / a;
    if exact <= MAX_PHASES as u128 {
        return Ok(exact as usize);
    }
    // A decimal F32 factor can lie very near a short rational period, e.g.
    // 0.6 near 3/5. This is only a planning hint: every phase below still uses
    // the already computed exact sample indices, so no coordinate is rounded
    // or approximated. Compare the final helper count before choosing it.
    let mut best = (u128::MAX, 1);
    for candidate in 1..=MAX_PHASES {
        let product = (candidate as u128).checked_mul(denominator).ok_or(CoordinateError::Limit)?;
        let nearest = product.checked_add(numerator / 2).ok_or(CoordinateError::Limit)? / numerator;
        if nearest == 0 {
            continue;
        }
        let distance = product.abs_diff(nearest.checked_mul(numerator).ok_or(CoordinateError::Limit)?);
        if distance < best.0 {
            best = (distance, candidate);
        }
    }
    Ok(best.1)
}

fn selection<E>(
    input: usize,
    indices: &[usize],
    period: usize,
    maximum: usize,
    charge: &mut impl FnMut(usize) -> std::result::Result<(), E>,
) -> Planned<Selection, E> {
    let mut best = direct(input, indices, maximum, charge)?.map(Selection::Direct);
    if (2..=MAX_PHASES).contains(&period) && period < indices.len() {
        let width = indices.len() / period;
        let prefix = width * period;
        let mut phases = Vec::new();
        phases.try_reserve_exact(period).map_err(|_| CoordinateError::Limit)?;
        let mut nodes = 2;
        for offset in 0..period {
            charge(width).map_err(PlanningError::Admission)?;
            let mut selected = Vec::new();
            selected.try_reserve_exact(width).map_err(|_| CoordinateError::Limit)?;
            selected.extend(indices[..prefix].iter().skip(offset).step_by(period).copied());
            let Some(phase) = direct(input, &selected, maximum, charge)? else {
                break;
            };
            nodes += phase.node_count() + 1;
            if nodes > maximum {
                break;
            }
            phases.push(phase);
        }
        if phases.len() == period {
            let tail = if prefix < indices.len() {
                direct(input, &indices[prefix..], maximum, charge)?
            } else {
                None
            };
            if prefix == indices.len() || tail.is_some() {
                let alternative = Selection::Interleave { phases, width, tail };
                if alternative.node_count() <= maximum
                    && best.as_ref().is_none_or(|best| alternative.node_count() < best.node_count())
                {
                    best = Some(alternative);
                }
            }
        }
    }
    best.ok_or_else(|| CoordinateError::Limit.into())
}

pub(super) fn plan_axis<E>(
    input: usize,
    scale: Scale,
    mode: LinearCoordinates,
    maximum: usize,
    mut charge: impl FnMut(usize) -> std::result::Result<(), E>,
) -> Planned<AxisPlan, E> {
    if input == 0
        || scale.output == 0
        || scale.output > MAX_COORDINATES
        || maximum == 0
        || maximum > 512
    {
        return Err(CoordinateError::Limit.into());
    }
    charge(scale.output * 4).map_err(PlanningError::Admission)?;
    let mut samples = Vec::new();
    samples.try_reserve_exact(scale.output).map_err(|_| CoordinateError::Limit)?;
    for position in 0..scale.output {
        charge(64).map_err(PlanningError::Admission)?;
        samples.push(sample(input, scale, position, mode)?);
    }
    charge(128).map_err(PlanningError::Admission)?;
    let period = period(input, scale, mode)?;
    let mut indices = Vec::new();
    indices.try_reserve_exact(scale.output).map_err(|_| CoordinateError::Limit)?;
    indices.extend(samples.iter().map(|sample| sample.lower));
    let lower = selection(input, &indices, period, maximum, &mut charge)?;
    let interpolate = samples.iter().any(|sample| sample.weights[1] != 0.0);
    let upper = if interpolate {
        indices.clear();
        indices.extend(samples.iter().map(|sample| sample.upper));
        Some(selection(input, &indices, period, maximum, &mut charge)?)
    } else {
        None
    };
    let mut weights = Vec::new();
    if interpolate {
        charge(scale.output * 2).map_err(PlanningError::Admission)?;
        weights.try_reserve_exact(scale.output).map_err(|_| CoordinateError::Limit)?;
        weights.extend(samples.into_iter().map(|sample| sample.weights));
    }
    Ok(AxisPlan { output: scale.output, lower, upper, weights })
}

#[cfg(test)]
mod tests {
    use super::unit_weight;

    #[test]
    fn coefficient_rounding_preserves_ties_to_even_and_exponent_carries() {
        let d = 1_u128 << 25;
        for (n, bits) in [
            (0, 0), (1, 0x3300_0000), (d / 2 + 1, 0x3f00_0000),
            (d / 2 + 3, 0x3f00_0002), (d - 1, 0x3f80_0000), (d, 0x3f80_0000),
        ] {
            assert_eq!(unit_weight(n, d).map(f32::to_bits), Ok(bits));
        }
    }

    #[test]
    fn coefficient_rounding_matches_independent_binary64_division_on_bounded_rationals() {
        for d in [1_u128, 2, 3, 7, 17, 31, 4095, 4096, (1 << 24) - 1, (1 << 25) - 1, 1 << 25] {
            for i in 0..=1024_u128 {
                let n = d * i / 1024;
                let expected = (n as f64 / d as f64) as f32;
                assert_eq!(unit_weight(n, d).map(f32::to_bits), Ok(expected.to_bits()), "{n}/{d}");
            }
        }
        for (n, d) in [(1, 0), (2, 1), (0, (1 << 25) + 1)] {
            assert!(unit_weight(n, d).is_err());
        }
    }
}
