#![forbid(unsafe_code)]
//! Whole-interval validation uses genuinely held-out synthetic measurements.

use std::sync::atomic::AtomicBool;

use fss_geometry::temporal_triangulation::{
    MAX_TEMPORAL_VIEWS, TemporalTriangulationOptions as Options, TimedCalibratedView,
};
use fss_geometry::temporal_validation::{
    IntervalCalibratedView, MotionValidation, TemporalCompatibility as Compatibility,
    TemporalValidationError as Error, TemporalValidationOutcome as Outcome,
    TemporalVisibilityRefusal as Visibility, triangulate_motion_validated,
};
use fss_geometry::triangulation::CalibratedView;
use fss_geometry::{GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const EPOCH: i128 = 1_i128 << 100;
const POSITION: [f64; 3] = [0.3, 0.2, 7.0];
const VELOCITY: [f64; 3] = [2.0, -0.5, 0.25];

fn point(offset: i128) -> [f64; 3] {
    std::array::from_fn(|axis| POSITION[axis] + VELOCITY[axis] * offset as f64 * 1e-9)
}

fn view(camera: u64, center: [f64; 3], time: i128) -> Result<CalibratedView, GeometryError> {
    let pose = RigidPose::from_center(RigidPose::IDENTITY.rotation(), center)?;
    let intrinsics = PinholeIntrinsics::new(1280, 960, 640.0, 640.0, 640.0, 480.0)?;
    Ok(CalibratedView {
        camera,
        pose,
        intrinsics,
        pixel: pose.project(intrinsics, point(time))?,
        sigma_pixels: 1.0,
    })
}

fn training() -> Result<Vec<TimedCalibratedView>, GeometryError> {
    let mut result = Vec::new();
    for (index, center) in [[-2.0, 0.0, 0.0], [2.0, 1.0, 0.0], [0.0, -2.0, 0.0]]
        .into_iter()
        .enumerate()
    {
        for time in [-200_000_000_i128, -100_000_000, 0, 100_000_000, 200_000_000] {
            let offset = time + index as i128 * 7_000_000;
            result.push(TimedCalibratedView {
                view: view(index as u64 + 1, center, offset)?,
                capture_time_ns: EPOCH + offset,
            });
        }
    }
    Ok(result)
}

fn holdout(offset: i128, width: i128) -> Result<IntervalCalibratedView, GeometryError> {
    Ok(IntervalCalibratedView {
        view: view(4, [0.0; 3], offset)?,
        capture_interval_ns: [EPOCH + offset - width, EPOCH + offset + width],
    })
}

fn validate(
    holdouts: &[IntervalCalibratedView],
) -> Result<MotionValidation, Box<dyn std::error::Error>> {
    Ok(triangulate_motion_validated(
        &training()?,
        holdouts,
        Options::default(),
        &mut WorkBudget::new(4_000_000),
    )?)
}

fn compatibility(result: &MotionValidation, index: usize) -> Option<Compatibility> {
    match result.checks[index].outcome {
        Outcome::Observable { compatibility, .. } => Some(compatibility),
        Outcome::NotObservable(_) => None,
    }
}

#[test]
fn exact_held_out_measurements_support_the_nominal_fit_without_refitting() -> TestResult {
    let result = validate(&[holdout(50_000_000, 0)?])?;
    assert!(result.consistent_for_all_capture_times());
    assert_eq!(result.checks.len(), 1);
    assert_eq!(
        compatibility(&result, 0),
        Some(Compatibility::ConsistentForAllTimes)
    );
    assert_eq!(result.fit.residuals.len(), training()?.len());
    assert!(!result.fit.residuals.iter().any(|row| row.camera == 4));
    Ok(())
}

#[test]
fn midpoint_agreement_does_not_hide_uncertain_capture_time() -> TestResult {
    let exact = validate(&[holdout(0, 0)?])?;
    assert!(exact.consistent_for_all_capture_times());
    let interval = holdout(0, 150_000_000)?;
    let uncertain = validate(&[interval])?;
    assert_eq!(uncertain.fit, exact.fit);
    assert_eq!(
        uncertain.checks[0].capture_interval_ns,
        interval.capture_interval_ns
    );
    assert!(!uncertain.consistent_for_all_capture_times());
    assert_eq!(
        compatibility(&uncertain, 0),
        Some(Compatibility::TimingAmbiguous)
    );
    Ok(())
}

#[test]
fn inconsistent_holdouts_are_retained_and_cannot_move_the_fitted_trajectory() -> TestResult {
    let original = holdout(0, 50_000_000)?;
    let mut wrong = original;
    wrong.view.pixel[1] += 80.0;
    let result = validate(&[wrong])?;
    assert_eq!(result.fit, validate(&[original])?.fit);
    assert_eq!(compatibility(&result, 0), Some(Compatibility::Inconsistent));
    assert!(!result.consistent_for_all_capture_times());
    Ok(())
}

#[test]
fn widening_time_uncertainty_cannot_upgrade_a_failed_all_times_gate() -> TestResult {
    let mut narrow = holdout(0, 0)?;
    narrow.view.pixel[0] += 5.0;
    let original = validate(&[narrow])?;
    assert_eq!(
        compatibility(&original, 0),
        Some(Compatibility::Inconsistent)
    );
    for width in [1_i128, 10_000_000, 50_000_000, 150_000_000, 190_000_000] {
        let mut wider = narrow;
        wider.capture_interval_ns = [EPOCH - width, EPOCH + width];
        let result = validate(&[wider])?;
        assert!(!result.consistent_for_all_capture_times());
        assert_eq!(result.fit, original.fit);
    }
    Ok(())
}

#[test]
fn analytic_residual_range_encloses_the_continuous_projected_segment() -> TestResult {
    let mut input = holdout(20_000_000, 170_000_000)?;
    input.view.pixel[1] += 2.0;
    let result = validate(&[input])?;
    let Outcome::Observable {
        residual_bounds_pixels: [minimum, maximum],
        ..
    } = result.checks[0].outcome
    else {
        return Err("expected full observable interval".into());
    };
    for index in 0..=1000 {
        let time = input.capture_interval_ns[0]
            + (input.capture_interval_ns[1] - input.capture_interval_ns[0]) * index / 1000;
        let dt = (time - result.fit.reference_time_ns) as f64 * 1e-9;
        let world = std::array::from_fn(|axis| {
            result.fit.position[axis] + result.fit.velocity_per_second[axis] * dt
        });
        let pixel = input.view.pose.project(input.view.intrinsics, world)?;
        let residual = (pixel[0] - input.view.pixel[0]).hypot(pixel[1] - input.view.pixel[1]);
        assert!(residual >= minimum - 1e-10 && residual <= maximum + 1e-10);
    }
    // Closest point lies inside the projected segment; endpoint-only minimum is wrong.
    assert!(minimum < 3.0 && maximum > 20.0);
    Ok(())
}

#[test]
fn unobservable_intervals_are_not_clipped_into_false_support() -> TestResult {
    for (center, expected) in [
        ([0.0, 0.0, 7.0], Visibility::BehindCamera),
        ([0.0, 0.0, -1001.0], Visibility::BeyondDistance),
        ([100.0, 0.0, 0.0], Visibility::OutsideImage),
    ] {
        let mut input = holdout(0, 100_000_000)?;
        input.view.pose = RigidPose::from_center(RigidPose::IDENTITY.rotation(), center)?;
        let result = validate(&[input])?;
        assert_eq!(result.checks[0].outcome, Outcome::NotObservable(expected));
        assert!(!result.consistent_for_all_capture_times());
    }
    Ok(())
}

#[test]
fn same_camera_training_measurements_cannot_validate_their_own_fit() -> TestResult {
    let training = training()?;
    let sample = training[2];
    for width in [0_i128, 50_000_000] {
        let reused = IntervalCalibratedView {
            view: sample.view,
            capture_interval_ns: [
                sample.capture_time_ns - width,
                sample.capture_time_ns + width,
            ],
        };
        assert_eq!(
            triangulate_motion_validated(
                &training,
                &[reused],
                Options::default(),
                &mut WorkBudget::new(4_000_000)
            ),
            Err(Error::HoldoutLeak)
        );
    }
    // Different exposure from an existing camera is allowed, but not called independent hardware.
    let input = IntervalCalibratedView {
        view: view(1, [-2.0, 0.0, 0.0], 50_000_000)?,
        capture_interval_ns: [EPOCH + 49_000_000, EPOCH + 51_000_000],
    };
    assert!(validate(&[input])?.consistent_for_all_capture_times());
    Ok(())
}

#[test]
fn overlapping_holdout_intervals_from_one_camera_are_refused() -> TestResult {
    let a = holdout(0, 10_000_000)?;
    for b in [
        a,
        holdout(20_000_000, 10_000_000)?,
        holdout(5_000_000, 2_000_000)?,
    ] {
        assert_eq!(
            triangulate_motion_validated(
                &training()?,
                &[a, b],
                Options::default(),
                &mut WorkBudget::new(4_000_000)
            ),
            Err(Error::OverlappingHoldouts)
        );
    }
    assert_eq!(
        validate(&[a, holdout(50_000_000, 1_000_000)?])?
            .checks
            .len(),
        2
    );
    Ok(())
}

#[test]
fn extrapolation_is_refused_instead_of_being_hidden_by_a_small_residual() -> TestResult {
    let input = holdout(500_000_000, 0)?;
    assert_eq!(
        triangulate_motion_validated(
            &training()?,
            &[input],
            Options::default(),
            &mut WorkBudget::new(4_000_000)
        ),
        Err(Error::OutsideFitWindow)
    );
    Ok(())
}

#[test]
fn bounds_and_malformed_intervals_fail_before_the_fit() -> TestResult {
    let training = training()?;
    let input = holdout(0, 0)?;
    assert_eq!(
        triangulate_motion_validated(&training, &[], Options::default(), &mut WorkBudget::new(0)),
        Err(Error::EmptyHoldout)
    );
    let oversized = vec![input; MAX_TEMPORAL_VIEWS + 1];
    assert_eq!(
        triangulate_motion_validated(
            &training,
            &oversized,
            Options::default(),
            &mut WorkBudget::new(0)
        ),
        Err(Error::Geometry(GeometryError::LimitExceeded))
    );
    for variant in 0..6 {
        let mut malformed = input;
        match variant {
            0 => malformed.capture_interval_ns = [EPOCH + 1, EPOCH],
            1 => malformed.capture_interval_ns = [i128::MIN, i128::MAX],
            2 => malformed.view.pixel[0] = f64::NAN,
            3 => malformed.view.camera = 0,
            4 => malformed.view.sigma_pixels = 0.0,
            _ => malformed.view.pixel[1] = 960.0,
        }
        assert_eq!(
            triangulate_motion_validated(
                &training,
                &[malformed],
                Options::default(),
                &mut WorkBudget::new(256)
            ),
            Err(Error::InvalidHoldout)
        );
    }
    Ok(())
}

#[test]
fn ordering_is_exactly_deterministic_for_inputs_and_work() -> TestResult {
    let mut training = training()?;
    let mut inputs = vec![
        holdout(-50_000_000, 1_000_000)?,
        holdout(50_000_000, 1_000_000)?,
    ];
    let mut budget_a = WorkBudget::new(4_000_000);
    let a = triangulate_motion_validated(&training, &inputs, Options::default(), &mut budget_a)?;
    training.reverse();
    inputs.reverse();
    let mut budget_b = WorkBudget::new(4_000_000);
    let b = triangulate_motion_validated(&training, &inputs, Options::default(), &mut budget_b)?;
    assert_eq!(a, b);
    assert_eq!(budget_a.used(), budget_b.used());
    Ok(())
}

#[test]
fn large_epoch_offsets_preserve_interval_geometry_exactly() -> TestResult {
    let mut training = training()?;
    let mut input = holdout(0, 150_000_000)?;
    let a = triangulate_motion_validated(
        &training,
        &[input],
        Options::default(),
        &mut WorkBudget::new(4_000_000),
    )?;
    for sample in &mut training {
        sample.capture_time_ns -= EPOCH;
    }
    for time in &mut input.capture_interval_ns {
        *time -= EPOCH;
    }
    let b = triangulate_motion_validated(
        &training,
        &[input],
        Options::default(),
        &mut WorkBudget::new(4_000_000),
    )?;
    assert_eq!(a.checks[0].outcome, b.checks[0].outcome);
    assert_eq!(a.fit.position, b.fit.position);
    assert_eq!(a.fit.velocity_per_second, b.fit.velocity_per_second);
    Ok(())
}

#[test]
fn cancellation_and_late_exhaustion_never_return_a_partial_validation() -> TestResult {
    let training = training()?;
    let inputs = [
        holdout(-50_000_000, 1_000_000)?,
        holdout(50_000_000, 1_000_000)?,
    ];
    let flag = AtomicBool::new(true);
    let mut cancelled = WorkBudget::cancellable(4_000_000, &flag);
    assert_eq!(
        triangulate_motion_validated(&training, &inputs, Options::default(), &mut cancelled),
        Err(Error::Geometry(GeometryError::Cancelled))
    );
    assert_eq!(cancelled.used(), 0);
    let mut complete = WorkBudget::new(4_000_000);
    triangulate_motion_validated(&training, &inputs, Options::default(), &mut complete)?;
    let mut short = WorkBudget::new(complete.used() - 1);
    assert_eq!(
        triangulate_motion_validated(&training, &inputs, Options::default(), &mut short),
        Err(Error::Geometry(GeometryError::BudgetExhausted))
    );
    Ok(())
}

#[test]
fn mixed_checks_preserve_all_failures_without_inflating_support() -> TestResult {
    let first = holdout(-100_000_000, 0)?;
    let mut second = holdout(0, 10_000_000)?;
    second.view.pixel[0] += 50.0;
    let third = holdout(100_000_000, 50_000_000)?;
    let result = validate(&[first, second, third])?;
    assert_eq!(result.checks.len(), 3);
    assert_eq!(
        compatibility(&result, 0),
        Some(Compatibility::ConsistentForAllTimes)
    );
    assert_eq!(compatibility(&result, 1), Some(Compatibility::Inconsistent));
    assert_eq!(
        compatibility(&result, 2),
        Some(Compatibility::TimingAmbiguous)
    );
    assert!(!result.consistent_for_all_capture_times());
    Ok(())
}
