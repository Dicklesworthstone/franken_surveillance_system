#![forbid(unsafe_code)]
//! Synthetic conditional-motion contracts; these do not qualify a deployment camera or clock.

use std::sync::atomic::AtomicBool;

use fss_geometry::temporal_triangulation::{
    MAX_TEMPORAL_SPAN_NS, MAX_TEMPORAL_VIEWS, TemporalTriangulationError as Error,
    TemporalTriangulationOptions as Options, TimedCalibratedView, triangulate_motion,
};
use fss_geometry::triangulation::CalibratedView;
use fss_geometry::{GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const ROTATION: [[f64; 3]; 3] = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
const POSITION: [f64; 3] = [0.3, 0.2, 7.0];
const VELOCITY: [f64; 3] = [0.6, -0.1, 0.25];
const EPOCH: i128 = 1_i128 << 100;

fn intrinsics() -> Result<PinholeIntrinsics, GeometryError> {
    PinholeIntrinsics::new(1280, 960, 640.0, 640.0, 640.0, 480.0)
}

fn fixture(epoch: i128, velocity: [f64; 3]) -> Result<Vec<TimedCalibratedView>, GeometryError> {
    let mut observations = Vec::new();
    let centers = [[-2.0, 0.0, 0.0], [2.0, 1.0, 0.0], [0.0, -2.0, 0.0]];
    for (index, center) in centers.into_iter().enumerate() {
        let pose = RigidPose::from_center(ROTATION, center)?;
        for time in [-200_000_000_i128, -100_000_000, 0, 100_000_000, 200_000_000] {
            let offset = time + index as i128 * 7_000_000;
            let point =
                std::array::from_fn(|axis| POSITION[axis] + velocity[axis] * offset as f64 * 1e-9);
            observations.push(TimedCalibratedView {
                view: CalibratedView {
                    camera: index as u64 + 1,
                    pose,
                    intrinsics: intrinsics()?,
                    pixel: pose.project(intrinsics()?, point)?,
                    sigma_pixels: 1.0,
                },
                capture_time_ns: epoch + offset,
            });
        }
    }
    Ok(observations)
}

fn close(actual: &[f64], expected: &[f64], tolerance: f64) {
    assert_eq!(actual.len(), expected.len());
    for (actual, expected) in actual.iter().zip(expected) {
        assert!(
            (actual - expected).abs() <= tolerance,
            "{actual} != {expected}"
        );
    }
}

#[test]
fn staggered_views_recover_position_and_velocity_at_the_exact_midpoint() -> TestResult {
    let observations = fixture(EPOCH, VELOCITY)?;
    let result = triangulate_motion(
        &observations,
        Options::default(),
        &mut WorkBudget::new(1_000_000),
    )?;
    assert_eq!(result.reference_time_ns, EPOCH + 7_000_000);
    assert_eq!(
        result.observed_time_range_ns,
        [EPOCH - 200_000_000, EPOCH + 214_000_000]
    );
    let expected: [f64; 3] = std::array::from_fn(|axis| POSITION[axis] + VELOCITY[axis] * 0.007);
    close(&result.position, &expected, 1e-8);
    close(&result.velocity_per_second, &VELOCITY, 1e-8);
    assert_eq!(result.residuals.len(), observations.len());
    assert!(result.rms_reprojection_pixels < 1e-8);
    for (residual, input) in result.residuals.iter().zip(&observations) {
        assert_eq!(residual.camera, input.view.camera);
        assert_eq!(residual.capture_time_ns, input.capture_time_ns);
    }
    Ok(())
}

#[test]
fn a_large_epoch_does_not_destroy_relative_nanosecond_precision() -> TestResult {
    let origin = triangulate_motion(
        &fixture(0, VELOCITY)?,
        Options::default(),
        &mut WorkBudget::new(1_000_000),
    )?;
    let shifted = triangulate_motion(
        &fixture(EPOCH, VELOCITY)?,
        Options::default(),
        &mut WorkBudget::new(1_000_000),
    )?;
    assert_eq!(origin.position, shifted.position);
    assert_eq!(origin.velocity_per_second, shifted.velocity_per_second);
    assert_eq!(
        origin.pixel_noise_covariance,
        shifted.pixel_noise_covariance
    );
    assert_eq!(origin.reference_time_ns + EPOCH, shifted.reference_time_ns);
    Ok(())
}

#[test]
fn permutations_preserve_the_complete_result_and_work_charge() -> TestResult {
    let mut observations = fixture(EPOCH, VELOCITY)?;
    let mut first_budget = WorkBudget::new(1_000_000);
    let first = triangulate_motion(&observations, Options::default(), &mut first_budget)?;
    observations.reverse();
    let mut second_budget = WorkBudget::new(1_000_000);
    let second = triangulate_motion(&observations, Options::default(), &mut second_budget)?;
    assert_eq!(first, second);
    assert_eq!(first_budget.used(), second_budget.used());
    Ok(())
}

#[test]
fn a_stationary_feature_does_not_acquire_invented_velocity() -> TestResult {
    let result = triangulate_motion(
        &fixture(EPOCH, [0.0; 3])?,
        Options::default(),
        &mut WorkBudget::new(1_000_000),
    )?;
    close(&result.position, &POSITION, 1e-8);
    close(&result.velocity_per_second, &[0.0; 3], 1e-8);
    Ok(())
}

#[test]
fn pixel_noise_keeps_all_observations_and_symmetric_covariance() -> TestResult {
    let mut observations = fixture(EPOCH, VELOCITY)?;
    for (index, item) in observations.iter_mut().enumerate() {
        item.view.pixel[0] += (index as f64).sin() * 0.2;
        item.view.pixel[1] += (index as f64).cos() * 0.2;
    }
    let result = triangulate_motion(
        &observations,
        Options::default(),
        &mut WorkBudget::new(2_000_000),
    )?;
    assert_eq!(result.residuals.len(), observations.len());
    close(&result.velocity_per_second, &VELOCITY, 0.02);
    assert!(result.rms_reprojection_pixels < 0.3);
    for i in 0..6 {
        assert!(result.pixel_noise_covariance[i][i] > 0.0);
        for j in 0..6 {
            assert!(result.pixel_noise_covariance[i][j].is_finite());
            assert_eq!(
                result.pixel_noise_covariance[i][j],
                result.pixel_noise_covariance[j][i]
            );
        }
    }
    Ok(())
}

#[test]
fn repeated_camera_and_time_is_refused_instead_of_double_counted() -> TestResult {
    let mut observations = fixture(EPOCH, VELOCITY)?;
    observations.push(observations[0]);
    assert_eq!(
        triangulate_motion(
            &observations,
            Options::default(),
            &mut WorkBudget::new(1_000_000)
        ),
        Err(Error::DuplicateObservation)
    );
    Ok(())
}

#[test]
fn one_camera_is_not_mislabeled_multicamera_fusion() -> TestResult {
    let observations = fixture(EPOCH, VELOCITY)?;
    assert_eq!(
        triangulate_motion(
            &observations[..5],
            Options::default(),
            &mut WorkBudget::new(1_000_000)
        ),
        Err(Error::InsufficientCameras)
    );
    Ok(())
}

#[test]
fn a_missing_baseline_refuses_unobservable_depth_and_velocity() -> TestResult {
    let mut observations = fixture(EPOCH, VELOCITY)?;
    for item in &mut observations {
        item.view.pose = RigidPose::IDENTITY;
        let dt = (item.capture_time_ns - EPOCH) as f64 * 1e-9;
        let point = std::array::from_fn(|axis| POSITION[axis] + VELOCITY[axis] * dt);
        item.view.pixel = item.view.pose.project(item.view.intrinsics, point)?;
    }
    assert_eq!(
        triangulate_motion(
            &observations,
            Options::default(),
            &mut WorkBudget::new(1_000_000)
        ),
        Err(Error::UnobservableMotion)
    );
    Ok(())
}

#[test]
fn simultaneous_views_do_not_claim_velocity_observability() -> TestResult {
    let observations = fixture(EPOCH, VELOCITY)?;
    let mut simultaneous = vec![
        observations[0],
        observations[5],
        observations[10],
        observations[1],
    ];
    for (index, item) in simultaneous.iter_mut().enumerate() {
        item.view.camera = index as u64 + 1;
        item.capture_time_ns = EPOCH;
    }
    assert_eq!(
        triangulate_motion(
            &simultaneous,
            Options::default(),
            &mut WorkBudget::new(1_000_000)
        ),
        Err(Error::InvalidTimeSpan)
    );
    Ok(())
}

#[test]
fn overflow_and_unbounded_time_spans_are_refused_before_float_conversion() -> TestResult {
    let mut observations = fixture(EPOCH, VELOCITY)?;
    observations[0].capture_time_ns = i128::MIN;
    observations[1].capture_time_ns = i128::MAX;
    assert_eq!(
        triangulate_motion(
            &observations,
            Options::default(),
            &mut WorkBudget::new(1_000_000)
        ),
        Err(Error::InvalidTimeSpan)
    );
    let mut observations = fixture(EPOCH, VELOCITY)?;
    observations[0].capture_time_ns = EPOCH - MAX_TEMPORAL_SPAN_NS - 1;
    assert_eq!(
        triangulate_motion(
            &observations,
            Options::default(),
            &mut WorkBudget::new(1_000_000)
        ),
        Err(Error::InvalidTimeSpan)
    );
    Ok(())
}

#[test]
fn zero_budget_and_cancellation_return_no_partial_trajectory() -> TestResult {
    let observations = fixture(EPOCH, VELOCITY)?;
    let mut zero = WorkBudget::new(0);
    assert_eq!(
        triangulate_motion(&observations, Options::default(), &mut zero),
        Err(Error::Geometry(GeometryError::BudgetExhausted))
    );
    assert_eq!(zero.used(), 0);
    let cancelled = AtomicBool::new(true);
    let mut budget = WorkBudget::cancellable(1_000_000, &cancelled);
    assert_eq!(
        triangulate_motion(&observations, Options::default(), &mut budget),
        Err(Error::Geometry(GeometryError::Cancelled))
    );
    assert_eq!(budget.used(), 0);
    Ok(())
}

#[test]
fn exhaustion_after_initialization_still_returns_no_partial_trajectory() -> TestResult {
    let observations = fixture(EPOCH, VELOCITY)?;
    // Validation, all ray rows and one inverse fit, but no first nonlinear observation.
    let allowance = 1536 * observations.len() as u64 + 4096;
    let mut budget = WorkBudget::new(allowance);
    assert_eq!(
        triangulate_motion(&observations, Options::default(), &mut budget),
        Err(Error::Geometry(GeometryError::BudgetExhausted))
    );
    assert_eq!(budget.used(), allowance);
    Ok(())
}

#[test]
fn distance_and_speed_are_explicit_refusal_boundaries() -> TestResult {
    let observations = fixture(EPOCH, VELOCITY)?;
    let distance = Options {
        max_distance: 1.0,
        ..Options::default()
    };
    assert_eq!(
        triangulate_motion(&observations, distance, &mut WorkBudget::new(1_000_000)),
        Err(Error::NoConsensus)
    );
    let speed = Options {
        max_speed: 0.01,
        ..Options::default()
    };
    assert_eq!(
        triangulate_motion(&observations, speed, &mut WorkBudget::new(1_000_000)),
        Err(Error::SpeedLimit)
    );
    Ok(())
}

#[test]
fn an_inconsistent_association_is_not_silently_discarded() -> TestResult {
    let mut observations = fixture(EPOCH, VELOCITY)?;
    observations[7].view.pixel[0] += 80.0;
    assert!(matches!(
        triangulate_motion(
            &observations,
            Options::default(),
            &mut WorkBudget::new(4_000_000)
        ),
        Err(Error::NoConsensus | Error::NotConverged)
    ));
    Ok(())
}

#[test]
fn invalid_observations_and_options_are_refused() -> TestResult {
    let observations = fixture(EPOCH, VELOCITY)?;
    for variant in 0..5 {
        let mut invalid = observations.clone();
        match variant {
            0 => invalid[0].view.pixel[0] = f64::NAN,
            1 => invalid[0].view.pixel[0] = 1280.0,
            2 => invalid[0].view.sigma_pixels = 0.0,
            3 => invalid[0].view.sigma_pixels = f64::INFINITY,
            _ => invalid[0].view.camera = 0,
        }
        assert_eq!(
            triangulate_motion(
                &invalid,
                Options::default(),
                &mut WorkBudget::new(1_000_000)
            ),
            Err(Error::InvalidObservation)
        );
    }
    for options in [
        Options {
            max_iterations: 0,
            ..Options::default()
        },
        Options {
            max_iterations: 33,
            ..Options::default()
        },
        Options {
            max_condition_number: f64::NAN,
            ..Options::default()
        },
        Options {
            max_speed: 0.0,
            ..Options::default()
        },
    ] {
        assert_eq!(
            triangulate_motion(&observations, options, &mut WorkBudget::new(1_000_000)),
            Err(Error::InvalidOptions)
        );
    }
    Ok(())
}

#[test]
fn observation_count_bounds_apply_before_numeric_work() -> TestResult {
    let observations = fixture(EPOCH, VELOCITY)?;
    assert_eq!(
        triangulate_motion(
            &observations[..3],
            Options::default(),
            &mut WorkBudget::new(1_000_000)
        ),
        Err(Error::InsufficientObservations)
    );
    let too_many = vec![observations[0]; MAX_TEMPORAL_VIEWS + 1];
    assert_eq!(
        triangulate_motion(
            &too_many,
            Options::default(),
            &mut WorkBudget::new(1_000_000)
        ),
        Err(Error::Geometry(GeometryError::LimitExceeded))
    );
    Ok(())
}
