#![forbid(unsafe_code)]
//! Exact, bounded Resize-13 coordinate planning, independent of graph/runtime types.
//!
//! https://onnx.ai/onnx/operators/onnx__Resize.html#resize-13
//! Importer admission is supplied as a callback so every coordinate and run keeps
//! the production cancellation/work checks, including in native standalone tests.

const MAX_FACTOR: usize = 64;
const MAX_RESAMPLE_COORDINATES: usize = 4096;
const MAX_INPUT_ELEMENTS: usize = 64 * 1024 * 1024 / 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CoordinateError {
    Limit,
    Unsupported,
}
type CoordinateResult<T> = std::result::Result<T, CoordinateError>;

#[derive(Debug, Eq, PartialEq)]
pub(super) enum PlanningError<E> {
    Coordinates(CoordinateError),
    Admission(E),
}
impl<E> From<CoordinateError> for PlanningError<E> {
    fn from(error: CoordinateError) -> Self {
        Self::Coordinates(error)
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Coordinates {
    AsymmetricFloor,
    HalfPixelRoundPreferFloor,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Scale {
    numerator: u128,
    denominator: u128,
    pub(super) output: usize,
}

impl Scale {
    /// Exact positive scale ratio, retained instead of reconstructed from the
    /// rounded output length. Shared with the bounded linear-coordinate owner.
    pub(super) fn ratio(self) -> (u128, u128) {
        (self.numerator, self.denominator)
    }

    pub(super) fn from_f32(value: f32, input: usize) -> CoordinateResult<Self> {
        if input == 0 || input > MAX_INPUT_ELEMENTS {
            return Err(CoordinateError::Limit);
        }
        if !value.is_finite() || value <= 0.0 || value > MAX_FACTOR as f32 {
            return Err(CoordinateError::Unsupported);
        }
        let bits = value.to_bits();
        let exponent = (bits >> 23) & 255;
        // Subnormal scales cannot produce one output element from any input
        // admitted by the 64 MiB tensor ceiling. Avoid a 2^149 denominator.
        if exponent == 0 {
            return Err(CoordinateError::Unsupported);
        }
        let numerator = (bits & 0x7f_ffff) | (1 << 23);
        // The maximum admitted value is 2^6, hence exponent <= 133 < 150.
        let shift = 150_u32
            .checked_sub(exponent)
            .ok_or(CoordinateError::Limit)?;
        let reduce = numerator.trailing_zeros().min(shift);
        let denominator = 1_u128
            .checked_shl(shift - reduce)
            // An unrepresentably tiny scale also has a zero output extent.
            .ok_or(CoordinateError::Unsupported)?;
        let numerator = u128::from(numerator >> reduce);
        let output = usize::try_from(
            (input as u128)
                .checked_mul(numerator)
                .ok_or(CoordinateError::Limit)?
                / denominator,
        )
        .map_err(|_| CoordinateError::Limit)?;
        if output == 0 {
            return Err(CoordinateError::Unsupported);
        }
        Ok(Self {
            numerator,
            denominator,
            output,
        })
    }

    pub(super) fn from_size(output: usize, input: usize) -> CoordinateResult<Self> {
        if input == 0 || input > MAX_INPUT_ELEMENTS {
            return Err(CoordinateError::Limit);
        }
        if output == 0
            || output
                > input
                    .checked_mul(MAX_FACTOR)
                    .ok_or(CoordinateError::Limit)?
        {
            return Err(CoordinateError::Unsupported);
        }
        Ok(Self {
            numerator: output as u128,
            denominator: input as u128,
            output,
        })
    }

    pub(super) fn integer_factor(self) -> Option<usize> {
        if self.numerator.is_multiple_of(self.denominator) {
            usize::try_from(self.numerator / self.denominator).ok()
        } else {
            None
        }
    }

    pub(super) fn index(
        self,
        position: usize,
        input: usize,
        coordinates: Coordinates,
    ) -> CoordinateResult<usize> {
        let position = position as u128;
        let selected = match coordinates {
            Coordinates::AsymmetricFloor => {
                position
                    .checked_mul(self.denominator)
                    .ok_or(CoordinateError::Limit)?
                    / self.numerator
            }
            Coordinates::HalfPixelRoundPreferFloor => {
                // Round half down of (x+1/2)/scale-1/2 is
                // ceil((2*x+1)*den/(2*num))-1 = ((2*x+1)*den-1)/(2*num).
                // The exact integer expression preserves ties and avoids
                // replacing a source scale with floor(input*scale)/input.
                let numerator = position
                    .checked_mul(2)
                    .and_then(|value| value.checked_add(1))
                    .and_then(|value| value.checked_mul(self.denominator))
                    .and_then(|value| value.checked_sub(1))
                    .ok_or(CoordinateError::Limit)?;
                numerator
                    / self
                        .numerator
                        .checked_mul(2)
                        .ok_or(CoordinateError::Limit)?
            }
        };
        usize::try_from(selected.min((input - 1) as u128)).map_err(|_| CoordinateError::Limit)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Run {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) step: usize,
    pub(super) repetitions: usize,
}

#[derive(Debug)]
pub(super) enum AxisPlan {
    Identity,
    Repeat(usize),
    Select(Vec<Run>),
}

impl AxisPlan {
    pub(super) fn node_count(&self) -> usize {
        match self {
            Self::Identity => 0,
            Self::Repeat(_) => 3,
            Self::Select(runs) => {
                runs.iter()
                    .map(|run| 1 + usize::from(run.repetitions > 1))
                    .sum::<usize>()
                    + usize::from(runs.len() > 1)
            }
        }
    }
}

pub(super) fn plan_axis<E>(
    input: usize,
    scale: Scale,
    coordinates: Coordinates,
    maximum_runs: usize,
    mut charge: impl FnMut(usize) -> std::result::Result<(), E>,
) -> std::result::Result<AxisPlan, PlanningError<E>> {
    if maximum_runs == 0 || maximum_runs > 512 {
        return Err(CoordinateError::Limit.into());
    }
    if let Some(factor) = scale.integer_factor() {
        return Ok(if factor == 1 {
            AxisPlan::Identity
        } else {
            AxisPlan::Repeat(factor)
        });
    }
    if scale.output > MAX_RESAMPLE_COORDINATES {
        return Err(CoordinateError::Limit.into());
    }
    charge(scale.output).map_err(PlanningError::Admission)?;
    let mut indices = Vec::new();
    indices
        .try_reserve_exact(scale.output)
        .map_err(|_| CoordinateError::Limit)?;
    for position in 0..scale.output {
        charge(1).map_err(PlanningError::Admission)?;
        indices.push(scale.index(position, input, coordinates)?);
    }
    // Positive-stride runs make common downsampling compact (e.g. 640 -> 320
    // needs one Slice), while constant runs repeat one selected tensor.
    let mut runs = Vec::new();
    let mut start = 0;
    while start < indices.len() {
        charge(1).map_err(PlanningError::Admission)?;
        let step = indices
            .get(start + 1)
            .map_or(0, |&next| next - indices[start]);
        let mut end = start + 1;
        while end < indices.len() && indices[end] - indices[end - 1] == step {
            charge(1).map_err(PlanningError::Admission)?;
            end += 1;
        }
        if runs.len() >= maximum_runs {
            return Err(CoordinateError::Limit.into());
        }
        runs.try_reserve(1).map_err(|_| CoordinateError::Limit)?;
        runs.push(Run {
            start: indices[start],
            end: indices[end - 1]
                .checked_add(1)
                .ok_or(CoordinateError::Limit)?,
            step: step.max(1),
            repetitions: if step == 0 { end - start } else { 1 },
        });
        start = end;
    }
    Ok(AxisPlan::Select(runs))
}
