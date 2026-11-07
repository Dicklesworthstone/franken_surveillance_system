#![forbid(unsafe_code)]
//! Native tests of the unchanged production coordinate planner. This target has
//! no external dependencies and also runs directly with pinned `rustc --test`.
//! Artifact serialization and scalar execution remain in onnx_resize_execution.

#[path = "../src/onnx/resize_coordinates.rs"]
mod resize_coordinates;

use resize_coordinates::{AxisPlan, CoordinateError, Coordinates, PlanningError, Scale, plan_axis};

type Test = Result<(), String>;

fn plan(input: usize, scale: Scale, coordinates: Coordinates) -> Result<AxisPlan, String> {
    plan_axis(input, scale, coordinates, 512, |_| Ok::<_, ()>(()))
        .map_err(|error| format!("{error:?}"))
}

fn expand(input: usize, plan: &AxisPlan) -> Vec<usize> {
    match plan {
        AxisPlan::Identity => (0..input).collect(),
        AxisPlan::Repeat(factor) => (0..input)
            .flat_map(|index| std::iter::repeat_n(index, *factor))
            .collect(),
        AxisPlan::Select(runs) => {
            let mut indices = Vec::new();
            for run in runs {
                assert!(run.start < run.end && run.end <= input);
                assert!(run.step > 0 && run.repetitions > 0);
                for _ in 0..run.repetitions {
                    indices.extend((run.start..run.end).step_by(run.step));
                }
            }
            indices
        }
    }
}

#[test]
fn every_small_size_ratio_matches_an_independent_sample_center_oracle() -> Test {
    for input in 1..=24 {
        for output in 1..=64.min(input * 64) {
            let scale = Scale::from_size(output, input).map_err(|error| format!("{error:?}"))?;
            for coordinates in [Coordinates::AsymmetricFloor, Coordinates::HalfPixelRoundPreferFloor] {
                let expected: Vec<_> = (0..output).map(|x| match coordinates {
                    Coordinates::AsymmetricFloor => {
                        // Find the last source boundary at or before x, using
                        // cross products instead of division or production math.
                        (0..input).rev().find(|&i| i * output <= x * input).unwrap_or(0)
                    }
                    Coordinates::HalfPixelRoundPreferFloor => {
                        // Compare distances to all source pixel centers. The
                        // first minimum implements exact tie preference.
                        (0..input).min_by_key(|&i| {
                            ((2*i + 1) * output).abs_diff((2*x + 1) * input)
                        }).unwrap_or(0)
                    }
                }).collect();
                let planned = plan(input, scale, coordinates)?;
                assert_eq!(expand(input, &planned), expected, "input={input}, output={output}, {coordinates:?}");
                assert_eq!(scale.output, output);
            }
        }
    }
    Ok(())
}

#[test]
fn f32_scales_match_coordinate_formulas_without_replacing_the_source_scale() -> Test {
    let values = [
        0.03125_f32, 0.0625, 0.1, 0.2, 0.3, 0.5, 0.6, 0.75,
        f32::from_bits(1.0_f32.to_bits() - 1), 1.0,
        f32::from_bits(1.0_f32.to_bits() + 1), 1.125, 1.25,
        f32::from_bits(1.5_f32.to_bits() - 1), 1.5,
        f32::from_bits(1.5_f32.to_bits() + 1), 2.5, 3.5, 16.5, 63.5, 64.0,
    ];
    for input in 1..=32 {
        for value in values {
            let output = (input as f64 * f64::from(value)).floor() as usize;
            if output == 0 {
                assert_eq!(Scale::from_f32(value, input).err(), Some(CoordinateError::Unsupported));
                continue;
            }
            let scale = Scale::from_f32(value, input).map_err(|error| format!("{error:?}"))?;
            assert_eq!(scale.output, output);
            let (numerator, denominator) = scale.ratio();
            assert_eq!(numerator as f64 / denominator as f64, f64::from(value));
            for coordinates in [Coordinates::AsymmetricFloor, Coordinates::HalfPixelRoundPreferFloor] {
                let expected: Vec<_> = (0..output).map(|x| {
                    let selected = match coordinates {
                        Coordinates::AsymmetricFloor => (x as f64 / f64::from(value)).floor(),
                        Coordinates::HalfPixelRoundPreferFloor => {
                            let position = (x as f64 + 0.5) / f64::from(value) - 0.5;
                            (position - 0.5).ceil()
                        }
                    };
                    selected.max(0.0).min((input - 1) as f64) as usize
                }).collect();
                assert_eq!(expand(input, &plan(input, scale, coordinates)?), expected,
                    "input={input}, scale={value:?}, {coordinates:?}");
            }
        }
    }
    Ok(())
}

#[test]
fn literal_ties_scale_size_differences_and_adjacent_f32_values_are_exact() -> Test {
    use Coordinates::{AsymmetricFloor as A, HalfPixelRoundPreferFloor as H};
    for (input, value, coordinates, expected) in [
        (7, 0.6, A, vec![0, 1, 3, 4]),
        (7, 0.6, H, vec![0, 2, 4, 5]),
        (9, 0.25, A, vec![0, 4]),
        (9, 0.25, H, vec![1, 5]),
        (5, 1.5, H, vec![0, 0, 1, 2, 2, 3, 4]),
        (5, f32::from_bits(1.5_f32.to_bits() - 1), H, vec![0, 1, 1, 2, 3, 3, 4]),
        (5, f32::from_bits(1.5_f32.to_bits() + 1), H, vec![0, 0, 1, 2, 2, 3, 4]),
        (7, 0.5, A, vec![0, 2, 4]),
        (7, f32::from_bits(0.5_f32.to_bits() + 1), A, vec![0, 1, 3]),
        (4, 1.125, A, vec![0, 0, 1, 2]),
        (4, 1.125, H, vec![0, 1, 2, 3]),
        (4, f32::from_bits(1.0_f32.to_bits() + 1), A, vec![0, 0, 1, 2]),
        (1, 63.5, H, vec![0; 63]),
    ] {
        let scale = Scale::from_f32(value, input).map_err(|error| format!("{error:?}"))?;
        assert_eq!(expand(input, &plan(input, scale, coordinates)?), expected);
    }
    for (coordinates, expected) in [(A, vec![0, 1, 3, 5]), (H, vec![0, 2, 4, 6])] {
        let scale = Scale::from_size(4, 7).map_err(|error| format!("{error:?}"))?;
        assert_eq!(expand(7, &plan(7, scale, coordinates)?), expected);
    }
    Ok(())
}

#[test]
fn legacy_integer_factors_and_common_downsampling_keep_compact_plans() -> Test {
    for input in [1, 3, 127] {
        for factor in [1, 2, 3, 16, 64] {
            let scale = Scale::from_f32(factor as f32, input).map_err(|error| format!("{error:?}"))?;
            for coordinates in [Coordinates::AsymmetricFloor, Coordinates::HalfPixelRoundPreferFloor] {
                let planned = plan(input, scale, coordinates)?;
                assert_eq!(scale.integer_factor(), Some(factor));
                assert_eq!(planned.node_count(), if factor == 1 { 0 } else { 3 });
                assert_eq!(expand(input, &planned), (0..input).flat_map(|i| std::iter::repeat_n(i, factor)).collect::<Vec<_>>());
            }
        }
    }
    for input in [480, 640, 8192] {
        let scale = Scale::from_f32(0.5, input).map_err(|error| format!("{error:?}"))?;
        let planned = plan(input, scale, Coordinates::HalfPixelRoundPreferFloor)?;
        assert_eq!(planned.node_count(), 1);
        assert_eq!(expand(input, &planned), (0..input).step_by(2).collect::<Vec<_>>());
    }
    Ok(())
}

#[test]
fn exponent_extrema_and_coordinate_resource_limits_are_bounded() -> Test {
    let maximum_input = 16_777_216;
    for value in [0.0, -0.0, -1.0, f32::from_bits(1), f32::from_bits(0x7f_ffff),
        f32::MIN_POSITIVE, 2.0_f32.powi(-25), f32::NAN, f32::INFINITY,
        f32::NEG_INFINITY, 65.0, f32::MAX] {
        assert_eq!(Scale::from_f32(value, maximum_input).err(), Some(CoordinateError::Unsupported));
    }
    for input in [0, maximum_input + 1, usize::MAX] {
        assert_eq!(Scale::from_f32(1.0, input).err(), Some(CoordinateError::Limit));
        assert_eq!(Scale::from_size(1, input).err(), Some(CoordinateError::Limit));
    }
    assert_eq!(Scale::from_size(0, 1).err(), Some(CoordinateError::Unsupported));
    assert_eq!(Scale::from_size(65, 1).err(), Some(CoordinateError::Unsupported));
    let scale = Scale::from_f32(2.0_f32.powi(-24), maximum_input).map_err(|error| format!("{error:?}"))?;
    assert_eq!(scale.output, 1);
    assert_eq!(expand(maximum_input, &plan(maximum_input, scale, Coordinates::AsymmetricFloor)?), [0]);
    assert_eq!(expand(maximum_input, &plan(maximum_input, scale, Coordinates::HalfPixelRoundPreferFloor)?), [8_388_607]);
    let scale = Scale::from_f32(0.5, 8194).map_err(|error| format!("{error:?}"))?;
    let mut called = false;
    assert_eq!(plan_axis(8194, scale, Coordinates::AsymmetricFloor, 512, |_| {
        called = true;
        Ok::<_, ()>(())
    }).err(), Some(PlanningError::Coordinates(CoordinateError::Limit)));
    assert!(!called);
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
enum AdmissionError { Cancelled, WorkBudget }

#[test]
fn every_planning_checkpoint_propagates_cancellation_and_exact_work_limits() -> Test {
    let scale = Scale::from_f32(2.5, 15).map_err(|error| format!("{error:?}"))?;
    let mut calls = 0;
    let mut used = 0;
    let baseline = plan_axis(15, scale, Coordinates::HalfPixelRoundPreferFloor, 512, |units| {
        calls += 1;
        used += units;
        Ok::<_, AdmissionError>(())
    }).map_err(|error| format!("{error:?}"))?;
    for stop in 1..=calls {
        let mut current = 0;
        let result = plan_axis(15, scale, Coordinates::HalfPixelRoundPreferFloor, 512, |_| {
            current += 1;
            if current == stop { Err(AdmissionError::Cancelled) } else { Ok(()) }
        });
        assert_eq!(result.err(), Some(PlanningError::Admission(AdmissionError::Cancelled)));
    }
    for budget in [used - 1, used] {
        let mut current = 0;
        let result = plan_axis(15, scale, Coordinates::HalfPixelRoundPreferFloor, 512, |units| {
            current += units;
            if current > budget { Err(AdmissionError::WorkBudget) } else { Ok(()) }
        });
        if budget == used {
            assert_eq!(expand(15, &result.map_err(|error| format!("{error:?}"))?), expand(15, &baseline));
        } else {
            assert_eq!(result.err(), Some(PlanningError::Admission(AdmissionError::WorkBudget)));
        }
    }
    let AxisPlan::Select(runs) = baseline else { return Err("expected selection plan".into()) };
    assert!(plan_axis(15, scale, Coordinates::HalfPixelRoundPreferFloor, runs.len(), |_| Ok::<_, ()>(())).is_ok());
    for maximum in [0, runs.len() - 1, 513] {
        assert_eq!(plan_axis(15, scale, Coordinates::HalfPixelRoundPreferFloor, maximum, |_| Ok::<_, ()>(())).err(), Some(PlanningError::Coordinates(CoordinateError::Limit)));
    }
    Ok(())
}
