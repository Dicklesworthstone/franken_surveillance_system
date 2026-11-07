#![forbid(unsafe_code)]
//! Exact production linear Resize planner, executable with pinned rustc --test
//! without async/runtime dependencies. Native artifact and kernel contracts live
//! in onnx_resize_execution::linear; these tests do not substitute for them.

// This test host uses only Scale/errors from the shared nearest module.
// Keep this allowance at the include boundary, not in production sources.
#[allow(dead_code)]
#[path = "../src/onnx/resize_coordinates.rs"]
mod resize_coordinates;
#[path = "../src/onnx/resize_linear_coordinates.rs"]
mod resize_linear_coordinates;

use resize_coordinates::{CoordinateError, PlanningError, Scale};
use resize_linear_coordinates::{AxisPlan, Direct, LinearCoordinates, Selection, plan_axis};

type Test = Result<(), String>;
const MODES: [LinearCoordinates; 4] = [
    LinearCoordinates::HalfPixel,
    LinearCoordinates::PytorchHalfPixel,
    LinearCoordinates::AlignCorners,
    LinearCoordinates::Asymmetric,
];

fn plan(input: usize, scale: Scale, mode: LinearCoordinates) -> Result<AxisPlan, String> {
    plan_axis(input, scale, mode, 512, |_| Ok::<_, ()>(()))
        .map_err(|error| format!("{error:?}"))
}

fn expand_direct(input: usize, plan: &Direct) -> Vec<usize> {
    if plan.runs.is_empty() {
        assert_eq!(plan.output, input);
        return (0..input).collect();
    }
    let mut indices = Vec::new();
    for run in &plan.runs {
        assert!(run.start < run.end && run.end <= input);
        assert!(run.step > 0 && run.repetitions > 0);
        let selected = (run.start..run.end).step_by(run.step).collect::<Vec<_>>();
        assert_eq!(selected.len(), run.count);
        for index in selected {
            indices.extend(std::iter::repeat_n(index, run.repetitions));
        }
    }
    assert_eq!(indices.len(), plan.output);
    indices
}

fn expand(input: usize, plan: &Selection) -> Vec<usize> {
    match plan {
        Selection::Direct(plan) => expand_direct(input, plan),
        Selection::Interleave { phases, width, tail } => {
            let phases = phases.iter().map(|p| expand_direct(input, p)).collect::<Vec<_>>();
            let mut result = Vec::new();
            for position in 0..*width {
                for phase in &phases {
                    assert_eq!(phase.len(), *width);
                    result.push(phase[position]);
                }
            }
            if let Some(tail) = tail {
                result.extend(expand_direct(input, tail));
            }
            result
        }
    }
}

fn coordinate(
    input: usize,
    output: usize,
    scale: f64,
    position: usize,
    mode: LinearCoordinates,
) -> f64 {
    let x = position as f64;
    let x = match mode {
        LinearCoordinates::HalfPixel => (x + 0.5) / scale - 0.5,
        LinearCoordinates::PytorchHalfPixel if output > 1 => (x + 0.5) / scale - 0.5,
        LinearCoordinates::AlignCorners if output > 1 => {
            x * (input - 1) as f64 / (output - 1) as f64
        }
        LinearCoordinates::Asymmetric => x / scale,
        LinearCoordinates::PytorchHalfPixel | LinearCoordinates::AlignCorners => 0.0,
    };
    // Remove only binary64 evaluation noise at exact integer boundaries. The
    // nearest distinct admitted F32-scale fixtures are much farther away.
    let x = if (x - x.round()).abs() < 1e-12 { x.round() } else { x };
    x.max(0.0).min((input - 1) as f64)
}

fn verify(input: usize, scale: Scale, original_scale: f64, mode: LinearCoordinates) -> Test {
    let planned = plan(input, scale, mode)?;
    let lower = expand(input, &planned.lower);
    let upper = planned.upper.as_ref().map(|p| expand(input, p));
    assert_eq!(lower.len(), scale.output);
    assert_eq!(planned.output, scale.output);
    assert!(planned.parameter_bytes() <= 8 * scale.output);
    assert_eq!(planned.weights.len(), if upper.is_some() { scale.output } else { 0 });
    for position in 0..scale.output {
        let x = coordinate(input, scale.output, original_scale, position, mode);
        let lo = x.floor() as usize;
        let hi = (lo + 1).min(input - 1);
        assert_eq!(lower[position], lo,
            "input={input}, output={}, scale={original_scale}, mode={mode:?}, position={position}",
            scale.output);
        let fraction = x - lo as f64;
        if let Some(upper) = &upper {
            assert_eq!(upper[position], hi);
            let weights = planned.weights[position];
            assert!((f64::from(weights[0]) - (1.0 - fraction)).abs() <= 6e-8);
            assert!((f64::from(weights[1]) - fraction).abs() <= 6e-8);
        } else {
            assert_eq!(fraction, 0.0);
        }
    }
    Ok(())
}

#[test]
fn every_small_ratio_selects_exact_neighbors_and_rounds_bounded_coefficients() -> Test {
    for input in 1..=24 {
        for output in 1..=64 {
            let scale = Scale::from_size(output, input).map_err(|e| format!("{e:?}"))?;
            for mode in MODES {
                verify(input, scale, output as f64 / input as f64, mode)?;
            }
        }
    }
    Ok(())
}

#[test]
fn source_f32_scales_adjacent_values_and_output_ratios_remain_distinct() -> Test {
    for input in [1, 2, 5, 7, 19, 32] {
        for value in [
            0.1_f32, 0.3, 0.5, 0.6, 0.75, 1.0, 1.125, 1.25,
            f32::from_bits(1.5_f32.to_bits() - 1), 1.5,
            f32::from_bits(1.5_f32.to_bits() + 1), 2.5, 3.5, 16.5, 63.5,
        ] {
            if (input as f64 * f64::from(value)).floor() < 1.0 {
                continue;
            }
            let scale = Scale::from_f32(value, input).map_err(|e| format!("{e:?}"))?;
            for mode in MODES {
                verify(input, scale, f64::from(value), mode)?;
            }
        }
    }
    let source = plan(7, Scale::from_f32(0.6, 7).map_err(|e| format!("{e:?}"))?, MODES[0])?;
    let sizes = plan(7, Scale::from_size(4, 7).map_err(|e| format!("{e:?}"))?, MODES[0])?;
    assert_ne!(
        source.weights.iter().map(|w| w.map(f32::to_bits)).collect::<Vec<_>>(),
        sizes.weights.iter().map(|w| w.map(f32::to_bits)).collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn singleton_modes_clamping_identity_and_exact_grid_sampling_are_literal() -> Test {
    let scale = Scale::from_size(1, 4).map_err(|e| format!("{e:?}"))?;
    for (mode, expected_lower, expected_upper, weights) in [
        (MODES[0], vec![1], Some(vec![2]), vec![[0.5, 0.5]]),
        (MODES[1], vec![0], None, vec![]),
        (MODES[2], vec![0], None, vec![]),
        (MODES[3], vec![0], None, vec![]),
    ] {
        let p = plan(4, scale, mode)?;
        assert_eq!(expand(4, &p.lower), expected_lower);
        assert_eq!(p.upper.as_ref().map(|p| expand(4, p)), expected_upper);
        assert_eq!(p.weights, weights);
    }
    for mode in MODES {
        for input in [1, 3, 64, 4096] {
            let p = plan(input, Scale::from_size(input, input).map_err(|e| format!("{e:?}"))?, mode)?;
            assert_eq!(p.node_count(), 0);
            assert_eq!(p.parameter_bytes(), 0);
            assert_eq!(expand(input, &p.lower), (0..input).collect::<Vec<_>>());
        }
    }
    let p = plan(8, Scale::from_size(4, 8).map_err(|e| format!("{e:?}"))?, MODES[3])?;
    assert_eq!(expand(8, &p.lower), vec![0, 2, 4, 6]);
    assert_eq!(p.node_count(), 1);
    assert!(p.weights.is_empty() && p.upper.is_none());
    Ok(())
}

#[test]
fn realistic_feature_scales_keep_small_graphs_and_linear_coefficient_storage() -> Test {
    for (input, output) in [(80, 160), (640, 480), (480, 360), (64, 4096)] {
        let scale = Scale::from_size(output, input).map_err(|e| format!("{e:?}"))?;
        let p = plan(input, scale, MODES[0])?;
        assert!(p.node_count() <= 64, "{input}->{output}: {}", p.node_count());
        assert_eq!(p.parameter_bytes(), output * 8);
        verify(input, scale, output as f64 / input as f64, MODES[0])?;
    }
    for input in [320, 640, 1280] {
        let scale = Scale::from_f32(0.6, input).map_err(|e| format!("{e:?}"))?;
        let p = plan(input, scale, MODES[0])?;
        assert!(p.node_count() <= 64, "decimal F32 scale: {}", p.node_count());
        verify(input, scale, f64::from(0.6_f32), MODES[0])?;
    }
    Ok(())
}

#[test]
fn coordinate_and_helper_limits_refuse_before_unbounded_construction() -> Test {
    let maximum = Scale::from_size(4096, 8192).map_err(|e| format!("{e:?}"))?;
    let p = plan(8192, maximum, MODES[0])?;
    assert_eq!(p.node_count(), 5);
    assert_eq!(p.parameter_bytes(), 32768);
    let excess = Scale::from_size(4097, 8194).map_err(|e| format!("{e:?}"))?;
    assert_eq!(
        plan_axis(8194, excess, MODES[0], 512, |_| Ok::<_, ()>(())).err(),
        Some(PlanningError::Coordinates(CoordinateError::Limit))
    );
    // Identity is still subject to the same explicit coordinate ceiling.
    let identity = Scale::from_size(4097, 4097).map_err(|e| format!("{e:?}"))?;
    assert_eq!(
        plan_axis(4097, identity, MODES[0], 512, |_| Ok::<_, ()>(())).err(),
        Some(PlanningError::Coordinates(CoordinateError::Limit))
    );
    for maximum in [0, 513] {
        assert_eq!(
            plan_axis(8192, maximum_scale()?, MODES[0], maximum, |_| Ok::<_, ()>(())).err(),
            Some(PlanningError::Coordinates(CoordinateError::Limit))
        );
    }
    let scale = Scale::from_size(7, 5).map_err(|e| format!("{e:?}"))?;
    assert_eq!(
        plan_axis(5, scale, MODES[0], 1, |_| Ok::<_, ()>(())).err(),
        Some(PlanningError::Coordinates(CoordinateError::Limit))
    );
    Ok(())
}

fn maximum_scale() -> Result<Scale, String> {
    Scale::from_size(4096, 8192).map_err(|e| format!("{e:?}"))
}

#[test]
fn every_planner_charge_preserves_admission_cancellation_without_a_partial_plan() -> Test {
    let scale = Scale::from_f32(1.5, 5).map_err(|e| format!("{e:?}"))?;
    let mut calls = 0;
    plan_axis(5, scale, MODES[0], 512, |_| {
        calls += 1;
        Ok::<_, usize>(())
    }).map_err(|e| format!("{e:?}"))?;
    for stop in 1..=calls {
        let mut call = 0;
        let result = plan_axis(5, scale, MODES[0], 512, |_| {
            call += 1;
            if call == stop { Err(stop) } else { Ok(()) }
        });
        assert_eq!(result.err(), Some(PlanningError::Admission(stop)));
        assert_eq!(call, stop);
    }
    Ok(())
}
