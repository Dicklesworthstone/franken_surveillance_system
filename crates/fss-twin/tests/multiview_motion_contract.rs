#![forbid(unsafe_code)]
//! Source-bound synthetic trajectory contracts, not field camera qualification.

mod common;

use fss_geometry::temporal_triangulation::{
    MAX_TEMPORAL_VIEWS, TemporalTriangulationError, TemporalTriangulationOptions,
    TimedCalibratedView, triangulate_motion,
};
use fss_geometry::triangulation::CalibratedView;
use fss_geometry::{GeometryBasis, GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};
use fss_twin::multiview::FusionInput;
use fss_twin::multiview_motion::{
    FusedSceneMotion, MotionFusionError as Error, MotionFusionRequest, fuse_scene_motion,
};
use fss_twin::{
    ContactObservation, ProjectionError, PropertyTwin, ScaleEvidence, TrackingCamera, TwinError,
};
use std::sync::atomic::AtomicBool;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const ROTATION: [[f64; 3]; 3] = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
const POSITION: [f64; 3] = [2.0, 2.0, 8.0];
const VELOCITY: [f64; 3] = [0.6, -0.1, 0.25];
const EPOCH: u64 = 1_000_000_000;

fn fixture(
    epoch: u64,
    position: [f64; 3],
    velocity: [f64; 3],
) -> Result<Vec<FusionInput>, Box<dyn std::error::Error>> {
    let intrinsics = PinholeIntrinsics::new(1280, 960, 640.0, 640.0, 640.0, 480.0)?;
    let centers = [[-1.0, 1.0, 0.0], [5.0, 1.0, 0.0], [2.0, -1.0, 0.0]];
    let mut inputs = Vec::new();
    for (camera_index, center) in centers.into_iter().enumerate() {
        let camera_id = camera_index as u64 + 1;
        let pose = RigidPose::from_center(ROTATION, center)?;
        let camera = TrackingCamera {
            geometry: GeometryBasis::new(1, 1)?,
            camera: camera_id,
            calibration: 9 + camera_id,
            image_domain: 19 + camera_id,
            clock: 7,
            validity: [0, u64::MAX],
            pose,
            intrinsics,
            error: None,
        };
        for (exposure, time) in [-200_000_000_i128, -100_000_000, 0, 100_000_000, 200_000_000]
            .into_iter()
            .enumerate()
        {
            let offset = time + camera_index as i128 * 7_000_000;
            let capture = u64::try_from(i128::from(epoch) + offset)?;
            let point =
                std::array::from_fn(|axis| position[axis] + velocity[axis] * offset as f64 * 1e-9);
            let pixel = pose.project(intrinsics, point)?;
            let evidence = [inputs.len() as u8 + 1; 32];
            inputs.push(FusionInput {
                camera,
                observation: ContactObservation {
                    evidence,
                    track: 100 + camera_id,
                    camera: camera_id,
                    exposure: exposure as u64 + 1,
                    image_domain: camera.image_domain,
                    clock: 7,
                    capture: [capture; 2],
                    pixel_min: pixel,
                    pixel_max: pixel,
                    visible_contact: true,
                },
                privacy_domain: 5,
                sigma_pixels: 1.0,
            });
        }
    }
    Ok(inputs)
}

fn request(epoch: u64) -> MotionFusionRequest {
    MotionFusionRequest {
        association_evidence: [33; 32],
        privacy_domain: 5,
        reference_time_ns: epoch + 50_000_000,
        max_capture_span_ns: 500_000_000,
        max_capture_uncertainty_ns: 0,
        triangulation: TemporalTriangulationOptions::default(),
    }
}

fn solve(
    twin: &PropertyTwin,
    inputs: &[FusionInput],
    request: MotionFusionRequest,
) -> Result<FusedSceneMotion, Error> {
    fuse_scene_motion(twin, inputs, request, &mut WorkBudget::new(2_000_000))
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
fn staggered_feeds_recover_motion_at_one_shared_scene_time_with_original_sources() -> TestResult {
    let twin = common::twin(&[0.0], None)?;
    let inputs = fixture(EPOCH, POSITION, VELOCITY)?;
    let result = solve(&twin, &inputs, request(EPOCH))?;
    let expected: [f64; 3] = std::array::from_fn(|axis| POSITION[axis] + VELOCITY[axis] * 0.05);
    close(&result.estimate().position, &expected, 1e-8);
    close(&result.estimate().velocity_per_second, &VELOCITY, 1e-8);
    assert_eq!(result.estimate().reference_time_ns, 1_050_000_000);
    assert_eq!(result.inputs(), inputs);
    assert_eq!(result.request(), request(EPOCH));
    assert_eq!(result.capture_hull(), [800_000_000, 1_214_000_000]);
    assert_eq!(result.clock(), 7);
    assert_eq!(result.geometry(), twin.basis());
    assert_eq!(result.twin_digest(), twin.digest());
    assert_eq!(result.source_scene_digest(), twin.source_scene_digest());
    assert_eq!(result.scale(), ScaleEvidence::Relative);
    assert_eq!(result.map_error(), None);
    assert!(
        result
            .inputs()
            .iter()
            .all(|input| input.camera.error.is_none())
    );
    assert!(result.estimate().rms_reprojection_pixels < 1e-8);
    assert_eq!(result.estimate().residuals.len(), inputs.len());
    assert_eq!(result.visibility().len(), inputs.len());
    assert!(!result.has_nominal_occlusion_conflict());
    for (row, input) in result.visibility().iter().zip(&inputs) {
        assert_eq!(row.evidence, input.observation.evidence);
        assert_eq!(row.exposure, input.observation.exposure);
        assert_eq!(row.capture, input.observation.capture);
        assert_eq!(row.nominal_capture_time_ns, input.observation.capture[0]);
        assert_eq!(row.nominal_occluded, Some(false));
    }
    Ok(())
}

#[test]
fn a_shared_scene_time_propagates_the_full_position_velocity_covariance() -> TestResult {
    let twin = common::twin(&[0.0], None)?;
    let inputs = fixture(EPOCH, POSITION, VELOCITY)?;
    let views: Vec<_> = inputs
        .iter()
        .map(|input| TimedCalibratedView {
            view: CalibratedView {
                camera: input.camera.camera,
                pose: input.camera.pose,
                intrinsics: input.camera.intrinsics,
                pixel: input.observation.pixel_min,
                sigma_pixels: input.sigma_pixels,
            },
            capture_time_ns: i128::from(input.observation.capture[0]),
        })
        .collect();
    let native = triangulate_motion(
        &views,
        request(EPOCH).triangulation,
        &mut WorkBudget::new(2_000_000),
    )?;
    let fused = solve(&twin, &inputs, request(EPOCH))?;
    let dt = (fused.estimate().reference_time_ns - native.reference_time_ns) as f64 * 1e-9;
    let transition: [[f64; 6]; 6] = std::array::from_fn(|row| {
        std::array::from_fn(|column| {
            if row == column {
                1.0
            } else if row < 3 && column == row + 3 {
                dt
            } else {
                0.0
            }
        })
    });
    for row in 0..6 {
        for column in 0..6 {
            // Independent dense multiplication of F P F^T verifies all cross terms.
            let mut expected = 0.0;
            for i in 0..6 {
                for j in 0..6 {
                    expected += transition[row][i]
                        * native.pixel_noise_covariance[i][j]
                        * transition[column][j];
                }
            }
            let actual = fused.estimate().pixel_noise_covariance[row][column];
            assert!((actual - expected).abs() < 1e-12);
            assert_eq!(actual, fused.estimate().pixel_noise_covariance[column][row]);
        }
    }
    assert_ne!(
        fused.estimate().pixel_noise_covariance[0][3],
        native.pixel_noise_covariance[0][3]
    );
    Ok(())
}

#[test]
fn capture_uncertainty_is_retained_and_cannot_be_laundered_into_pixel_covariance() -> TestResult {
    let twin = common::twin(&[0.0], Some(0.25))?;
    let mut inputs = fixture(EPOCH, POSITION, VELOCITY)?;
    let exact = solve(&twin, &inputs, request(EPOCH))?;
    for input in &mut inputs {
        let capture = input.observation.capture[0];
        input.observation.capture = [capture - 10_000_000, capture + 10_000_000];
        input.camera.error = Some(ProjectionError {
            centre: [0.2; 3],
            rotation_entry: 0.01,
            focal: [2.0; 2],
            principal: [1.0; 2],
        });
    }
    assert!(matches!(
        solve(&twin, &inputs, request(EPOCH)),
        Err(Error::CaptureWindow)
    ));
    let mut permitted = request(EPOCH);
    permitted.max_capture_uncertainty_ns = 20_000_000;
    let result = solve(&twin, &inputs, permitted)?;
    assert_eq!(result.capture_hull(), [790_000_000, 1_224_000_000]);
    assert_eq!(result.inputs(), inputs);
    assert_eq!(result.estimate(), exact.estimate());
    assert_eq!(result.map_error(), Some(0.25));
    assert_eq!(result.request().max_capture_uncertainty_ns, 20_000_000);
    permitted.max_capture_span_ns = 420_000_000;
    assert!(matches!(
        solve(&twin, &inputs, permitted),
        Err(Error::CaptureWindow)
    ));
    Ok(())
}

#[test]
fn geometry_conflicts_are_checked_at_each_exposures_own_time() -> TestResult {
    let twin = common::twin(&[4.0], None)?;
    let inputs = fixture(EPOCH, [1.0, 2.0, 8.0], [2.0, 0.0, 0.0])?;
    let result = solve(&twin, &inputs, request(EPOCH))?;
    assert!(result.has_nominal_occlusion_conflict());
    assert!(result.estimate().rms_reprojection_pixels < 1e-8);
    let camera_one: Vec<_> = result
        .visibility()
        .iter()
        .filter(|row| row.camera == 1)
        .collect();
    assert_eq!(
        camera_one.first().map(|row| row.nominal_occluded),
        Some(Some(false))
    );
    assert_eq!(
        camera_one.last().map(|row| row.nominal_occluded),
        Some(Some(true))
    );
    assert_eq!(result.inputs().len(), 15);
    assert_eq!(result.estimate().residuals.len(), 15);
    Ok(())
}

#[test]
fn input_order_does_not_change_motion_diagnostics_or_work() -> TestResult {
    let twin = common::twin(&[0.0], None)?;
    let mut inputs = fixture(EPOCH, POSITION, VELOCITY)?;
    let mut first_budget = WorkBudget::new(2_000_000);
    let first = fuse_scene_motion(&twin, &inputs, request(EPOCH), &mut first_budget)?;
    inputs.reverse();
    let mut second_budget = WorkBudget::new(2_000_000);
    let second = fuse_scene_motion(&twin, &inputs, request(EPOCH), &mut second_budget)?;
    assert_eq!(first.inputs(), second.inputs());
    assert_eq!(first.estimate(), second.estimate());
    assert_eq!(first.visibility(), second.visibility());
    assert_eq!(first.capture_hull(), second.capture_hull());
    assert_eq!(first_budget.used(), second_budget.used());
    Ok(())
}

#[test]
fn integer_epoch_translation_preserves_motion_near_u64_max() -> TestResult {
    let twin = common::twin(&[0.0], None)?;
    let shifted_epoch = u64::MAX - 300_000_000;
    let first = solve(&twin, &fixture(EPOCH, POSITION, VELOCITY)?, request(EPOCH))?;
    let shifted = solve(
        &twin,
        &fixture(shifted_epoch, POSITION, VELOCITY)?,
        request(shifted_epoch),
    )?;
    assert_eq!(first.estimate().position, shifted.estimate().position);
    assert_eq!(
        first.estimate().velocity_per_second,
        shifted.estimate().velocity_per_second
    );
    assert_eq!(
        first.estimate().pixel_noise_covariance,
        shifted.estimate().pixel_noise_covariance
    );
    assert_eq!(
        shifted.estimate().reference_time_ns,
        i128::from(shifted_epoch + 50_000_000)
    );
    Ok(())
}

#[test]
fn stationary_sources_do_not_acquire_invented_motion() -> TestResult {
    let twin = common::twin(&[0.0], None)?;
    let result = solve(&twin, &fixture(EPOCH, POSITION, [0.0; 3])?, request(EPOCH))?;
    close(&result.estimate().position, &POSITION, 1e-8);
    close(&result.estimate().velocity_per_second, &[0.0; 3], 1e-8);
    Ok(())
}

#[test]
fn duplicates_cannot_masquerade_as_independent_observations() -> TestResult {
    let twin = common::twin(&[0.0], None)?;
    let original = fixture(EPOCH, POSITION, VELOCITY)?;
    let mut inputs = original.clone();
    inputs[5].observation.evidence = inputs[0].observation.evidence;
    assert!(matches!(
        solve(&twin, &inputs, request(EPOCH)),
        Err(Error::DuplicateEvidence)
    ));
    let mut inputs = original;
    inputs[1].observation.exposure = inputs[0].observation.exposure;
    assert!(matches!(
        solve(&twin, &inputs, request(EPOCH)),
        Err(Error::DuplicateExposure)
    ));
    Ok(())
}

#[test]
fn mismatched_camera_privacy_clock_and_validity_refuse_a_scene_estimate() -> TestResult {
    let twin = common::twin(&[0.0], None)?;
    for variant in 0..8 {
        let mut inputs = fixture(EPOCH, POSITION, VELOCITY)?;
        match variant {
            0 => inputs[0].privacy_domain = 6,
            1 => {
                inputs[0].camera.clock = 8;
                inputs[0].observation.clock = 8;
            }
            2 => inputs[0].camera.validity[1] = inputs[0].observation.capture[0] - 1,
            3 => inputs[0].camera.calibration += 1,
            4 => inputs[0].camera.geometry = GeometryBasis::new(1, 2)?,
            5 => inputs[0].observation.image_domain += 1,
            6 => inputs[0].camera.pose = RigidPose::IDENTITY,
            _ => inputs[0].camera.error = Some(ProjectionError::EXACT),
        }
        let error = solve(&twin, &inputs, request(EPOCH))
            .err()
            .ok_or("incompatible source unexpectedly accepted")?;
        assert_eq!(
            error,
            if variant == 0 {
                Error::PrivacyDomain
            } else {
                Error::Basis
            }
        );
    }
    Ok(())
}

#[test]
fn invalid_contacts_noise_and_error_bounds_do_not_reach_the_solver() -> TestResult {
    let twin = common::twin(&[0.0], None)?;
    for variant in 0..8 {
        let mut inputs = fixture(EPOCH, POSITION, VELOCITY)?;
        match variant {
            0 => inputs[0].observation.visible_contact = false,
            1 => inputs[0].observation.evidence = [0; 32],
            2 => inputs[0].observation.pixel_min[0] = f64::NAN,
            3 => inputs[0].sigma_pixels = 0.0,
            4 => inputs[0].observation.pixel_max[0] -= 1.0,
            5 => inputs[0].observation.track = 0,
            6 => inputs[0].observation.exposure = 0,
            _ => {
                inputs[0].camera.error = Some(ProjectionError {
                    focal: [640.0; 2],
                    ..ProjectionError::EXACT
                })
            }
        }
        let error = solve(&twin, &inputs, request(EPOCH))
            .err()
            .ok_or("invalid source unexpectedly accepted")?;
        assert_eq!(
            error,
            if variant == 0 {
                Error::ContactUnknown
            } else {
                Error::Observation
            }
        );
    }
    Ok(())
}

#[test]
fn reference_time_must_interpolate_the_fitted_window_even_when_inside_capture_hull() -> TestResult {
    let twin = common::twin(&[0.0], None)?;
    let mut inputs = fixture(EPOCH, POSITION, VELOCITY)?;
    for input in &mut inputs {
        let time = input.observation.capture[0];
        input.observation.capture = [time - 1_000_000, time + 1_000_000];
    }
    let mut req = request(EPOCH);
    req.max_capture_uncertainty_ns = 2_000_000;
    req.reference_time_ns = 799_500_000;
    assert!(matches!(
        solve(&twin, &inputs, req),
        Err(Error::CaptureWindow)
    ));
    req.reference_time_ns = 1_214_500_000;
    assert!(matches!(
        solve(&twin, &inputs, req),
        Err(Error::CaptureWindow)
    ));
    Ok(())
}

#[test]
fn missing_cameras_and_incompatible_motion_remain_typed_refusals() -> TestResult {
    let twin = common::twin(&[0.0], None)?;
    let inputs = fixture(EPOCH, POSITION, VELOCITY)?;
    assert!(matches!(
        solve(&twin, &inputs[..3], request(EPOCH)),
        Err(Error::Triangulation(
            TemporalTriangulationError::InsufficientObservations
        ))
    ));
    assert!(matches!(
        solve(&twin, &inputs[..5], request(EPOCH)),
        Err(Error::Triangulation(
            TemporalTriangulationError::InsufficientCameras
        ))
    ));
    let mut bad = inputs;
    bad[7].observation.pixel_min[0] += 80.0;
    bad[7].observation.pixel_max[0] += 80.0;
    assert!(matches!(
        solve(&twin, &bad, request(EPOCH)),
        Err(Error::Triangulation(
            TemporalTriangulationError::NoConsensus | TemporalTriangulationError::NotConverged
        ))
    ));
    Ok(())
}

#[test]
fn malformed_request_and_hard_observation_ceiling_fail_without_partial_work() -> TestResult {
    let twin = common::twin(&[0.0], None)?;
    let inputs = fixture(EPOCH, POSITION, VELOCITY)?;
    for variant in 0..6 {
        let mut req = request(EPOCH);
        match variant {
            0 => req.association_evidence = [0; 32],
            1 => req.privacy_domain = 0,
            2 => req.max_capture_span_ns = 0,
            3 => req.max_capture_span_ns = 60_000_000_001,
            4 => req.max_capture_uncertainty_ns = req.max_capture_span_ns + 1,
            _ => req.reference_time_ns = 0,
        }
        assert!(solve(&twin, &inputs, req).is_err());
    }
    let too_many = vec![inputs[0]; MAX_TEMPORAL_VIEWS + 1];
    let mut budget = WorkBudget::new(2_000_000);
    assert!(matches!(
        fuse_scene_motion(&twin, &too_many, request(EPOCH), &mut budget),
        Err(Error::Twin(TwinError::Limit))
    ));
    assert_eq!(budget.used(), 0);
    Ok(())
}

#[test]
fn cancellation_and_budget_exhaustion_withhold_the_complete_scene_result() -> TestResult {
    let twin = common::twin(&[4.0], None)?;
    let inputs = fixture(EPOCH, POSITION, VELOCITY)?;
    let cancelled = AtomicBool::new(true);
    let mut budget = WorkBudget::cancellable(2_000_000, &cancelled);
    assert!(matches!(
        fuse_scene_motion(&twin, &inputs, request(EPOCH), &mut budget),
        Err(Error::Twin(TwinError::Geometry(GeometryError::Cancelled)))
    ));
    assert_eq!(budget.used(), 0);
    assert!(matches!(
        fuse_scene_motion(&twin, &inputs, request(EPOCH), &mut WorkBudget::new(0)),
        Err(Error::Twin(TwinError::Geometry(
            GeometryError::BudgetExhausted
        )))
    ));
    let mut measured = WorkBudget::new(2_000_000);
    let _ = fuse_scene_motion(&twin, &inputs, request(EPOCH), &mut measured)?;
    assert!(matches!(
        fuse_scene_motion(
            &twin,
            &inputs,
            request(EPOCH),
            &mut WorkBudget::new(measured.used() - 1)
        ),
        Err(Error::Twin(TwinError::Geometry(
            GeometryError::BudgetExhausted
        )))
    ));
    Ok(())
}
