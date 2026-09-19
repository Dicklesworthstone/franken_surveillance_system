#![forbid(unsafe_code)]
//! Nominal sampled geometry, not statistical detection-quality qualification.

use fss_geometry::*;
use std::sync::atomic::AtomicBool;
const SECOND: u64 = 1_000_000_000;
fn basis() -> Result<ForecastBasis, GeometryError> {
    ForecastBasis::new(GeometryBasis::new(1, 2)?, 3, 4, 5, 6)
}
fn body() -> Result<BodySamples, GeometryError> {
    BodySamples::new(
        7,
        &[
            [-0.25, -0.5, 0.0],
            [0.25, -0.5, 0.0],
            [-0.25, 0.5, 0.0],
            [0.25, 0.5, 0.0],
        ],
        &mut WorkBudget::new(100),
    )
}
fn motion(points: &[[f64; 3]], end: RouteEnd) -> Result<MotionForecast, GeometryError> {
    forecast_routes(
        basis()?,
        0,
        10 * SECOND,
        RoutePriors::new([1, 0, 0, 0], 4)?,
        &[RouteCandidate {
            id: 1,
            points,
            speed: 1.0,
            initial_pause_ns: 0,
            end,
            surface: RouteSurface::PedestrianPath,
            base_mass: 1,
            protected: true,
        }],
        &mut WorkBudget::new(1000),
    )
}
fn mesh(wall: bool) -> Result<TriangleMesh, GeometryError> {
    let vertices = if wall {
        [
            [-100.0, -100.0, 5.0],
            [0.0, -100.0, 5.0],
            [0.0, 100.0, 5.0],
            [-100.0, 100.0, 5.0],
        ]
    } else {
        [
            [-100.0, -100.0, -5.0],
            [100.0, -100.0, -5.0],
            [100.0, 100.0, -5.0],
            [-100.0, 100.0, -5.0],
        ]
    };
    TriangleMesh::from_indexed(
        basis()?.geometry(),
        &vertices,
        &[
            IndexedTriangle {
                vertices: [0, 1, 2],
                feature: 1,
                support: false,
                opaque: true,
            },
            IndexedTriangle {
                vertices: [0, 2, 3],
                feature: 1,
                support: false,
                opaque: true,
            },
        ],
        MeshLimits::default(),
        &mut WorkBudget::new(100),
    )
}
fn camera(id: u64) -> Result<HandoffCamera<'static>, GeometryError> {
    Ok(HandoffCamera {
        id,
        geometry: basis()?.geometry(),
        clock: basis()?.clock(),
        observation_generation: 8,
        image_mode: 9,
        pose: RigidPose::IDENTITY,
        intrinsics: PinholeIntrinsics::new(100, 100, 100.0, 100.0, 50.0, 50.0)?,
        availability: CameraAvailability::Ready,
        already_observing: false,
        valid: NanosecondInterval::new(0, u64::MAX)?,
        schedule: CaptureSchedule::new(SECOND, 0)?,
        latency: NanosecondInterval::new(100, 200)?,
        privacy_masks: &[],
        visible_per_mille: 1000,
        minimum_extent_px: [1.0, 1.0],
    })
}
fn options() -> HandoffOptions {
    HandoffOptions {
        max_samples_per_camera: 1000,
        endpoint_margin: 1e-6,
    }
}
fn run(
    motion: &MotionForecast,
    mesh: &TriangleMesh,
    cameras: &[HandoffCamera<'_>],
) -> Result<CameraHandoffForecast, GeometryError> {
    let body = body()?;
    predict_camera_handoffs(
        basis()?,
        motion,
        mesh,
        cameras,
        &[RouteBody {
            route: 1,
            body: &body,
        }],
        options(),
        &mut WorkBudget::new(1_000_000),
    )
}

#[test]
fn emergence_from_an_occluder_can_be_inside_the_frame() -> Result<(), GeometryError> {
    let path = motion(&[[-2.0, 0.0, 10.0], [2.0, 0.0, 10.0]], RouteEnd::Stop)?;
    let result = run(&path, &mesh(true)?, &[camera(11)?])?;
    let hit = &result.routes[0].observations[0];
    assert_eq!(hit.nominal_capture_ns, 3 * SECOND);
    assert_eq!(
        hit.availability_ns,
        NanosecondInterval::new(3 * SECOND + 100, 3 * SECOND + 200)?
    );
    assert!(hit.region.min()[0] > 0.5 && hit.region.max()[0] < 0.7);
    assert_eq!(hit.visible_samples, 4);
    assert_eq!(hit.image_mode, 9);
    assert!(result.routes[0].protected);
    Ok(())
}

#[test]
fn capture_order_is_not_pipeline_arrival_order() -> Result<(), GeometryError> {
    let path = motion(&[[-8.0, 0.0, 10.0], [8.0, 0.0, 10.0]], RouteEnd::Stop)?;
    let mut a = camera(11)?;
    a.latency = NanosecondInterval::new(10 * SECOND, 11 * SECOND)?;
    let mut b = camera(22)?;
    b.pose = RigidPose::from_center(RigidPose::IDENTITY.rotation(), [4.0, 0.0, 0.0])?;
    b.latency = NanosecondInterval::new(0, 0)?;
    let result = run(&path, &mesh(false)?, &[a, b])?;
    let observations = &result.routes[0].observations;
    assert_eq!(observations[0].nominal_capture_ns, 4 * SECOND);
    assert_eq!(observations[1].nominal_capture_ns, 8 * SECOND);
    assert!(observations[0].availability_ns.earliest() > observations[1].availability_ns.latest());
    assert_eq!(
        result.routes[0].next,
        NextCameraOutcome::Predicted {
            nominal_capture_ns: 4 * SECOND,
            cameras: vec![11]
        }
    );
    Ok(())
}

#[test]
fn simultaneous_cameras_and_input_permutation_are_preserved() -> Result<(), GeometryError> {
    let path = motion(&[[0.0, 0.0, 10.0]], RouteEnd::Stop)?;
    let scene = mesh(false)?;
    let a = camera(11)?;
    let b = camera(22)?;
    let one = run(&path, &scene, &[a, b])?;
    assert_eq!(one, run(&path, &scene, &[b, a])?);
    assert_eq!(
        one.routes[0].next,
        NextCameraOutcome::Predicted {
            nominal_capture_ns: 0,
            cameras: vec![11, 22]
        }
    );
    Ok(())
}

#[test]
fn unknown_camera_preserves_partial_hits_without_claiming_a_next_camera()
-> Result<(), GeometryError> {
    let path = motion(&[[0.0, 0.0, 10.0]], RouteEnd::Stop)?;
    let mut unknown = camera(22)?;
    unknown.availability = CameraAvailability::Unknown;
    let result = run(&path, &mesh(false)?, &[camera(11)?, unknown])?;
    assert_eq!(result.routes[0].next, NextCameraOutcome::Indeterminate);
    assert_eq!(result.routes[0].observations.len(), 1);
    assert_eq!(result.routes[0].unresolved_cameras, vec![22]);
    assert_eq!(result.total_mass, path.total_mass());
    Ok(())
}

#[test]
fn unknown_route_tail_does_not_become_negative_evidence() -> Result<(), GeometryError> {
    let path = motion(&[[100.0, 0.0, 10.0]], RouteEnd::Unknown)?;
    let result = run(&path, &mesh(false)?, &[camera(11)?])?;
    assert_eq!(result.routes[0].next, NextCameraOutcome::Indeterminate);
    assert!(result.routes[0].unmodeled_tail);
    assert!(result.routes[0].observations.is_empty());
    Ok(())
}

#[test]
fn a_first_event_before_an_unknown_tail_remains_usable() -> Result<(), GeometryError> {
    let path = motion(&[[0.0, 0.0, 10.0]], RouteEnd::Unknown)?;
    let result = run(&path, &mesh(false)?, &[camera(11)?])?;
    assert!(result.routes[0].unmodeled_tail);
    assert_eq!(
        result.routes[0].next,
        NextCameraOutcome::Predicted {
            nominal_capture_ns: 0,
            cameras: vec![11]
        }
    );
    Ok(())
}

#[test]
fn cameras_already_observing_and_unavailable_are_explicitly_excluded() -> Result<(), GeometryError>
{
    let path = motion(&[[0.0, 0.0, 10.0]], RouteEnd::Stop)?;
    let mut a = camera(11)?;
    a.already_observing = true;
    let mut b = camera(22)?;
    b.availability = CameraAvailability::Unavailable;
    let result = run(&path, &mesh(false)?, &[a, b])?;
    assert_eq!(
        result.routes[0].next,
        NextCameraOutcome::NoModeledObservation
    );
    assert_eq!(result.camera_scope.len(), 2);
    Ok(())
}

#[test]
fn sparse_sampling_does_not_claim_continuous_visibility() -> Result<(), GeometryError> {
    let path = motion(&[[-8.0, 0.0, 10.0], [8.0, 0.0, 10.0]], RouteEnd::Stop)?;
    let mut cam = camera(11)?;
    cam.schedule = CaptureSchedule::new(20 * SECOND, 0)?;
    let result = run(&path, &mesh(false)?, &[cam])?;
    assert_eq!(
        result.routes[0].next,
        NextCameraOutcome::NoModeledObservation
    );
    Ok(())
}

#[test]
fn privacy_masks_deny_regions_before_mesh_queries() -> Result<(), GeometryError> {
    let path = motion(&[[0.0, 0.0, 10.0]], RouteEnd::Stop)?;
    let masks = [ImageRect::new([0.0, 0.0], [1.0, 1.0])?];
    let cam = HandoffCamera {
        privacy_masks: &masks,
        ..camera(11)?
    };
    let result = run(&path, &mesh(true)?, &[cam])?;
    assert!(result.routes[0].observations.is_empty());
    assert_eq!(
        result.routes[0].next,
        NextCameraOutcome::NoModeledObservation
    );
    Ok(())
}

#[test]
fn expired_snapshot_is_unresolved_not_silently_reused() -> Result<(), GeometryError> {
    let path = motion(&[[0.0, 0.0, 10.0]], RouteEnd::Stop)?;
    let mut cam = camera(11)?;
    cam.valid = NanosecondInterval::new(0, SECOND)?;
    let result = run(&path, &mesh(false)?, &[cam])?;
    assert_eq!(result.routes[0].next, NextCameraOutcome::Indeterminate);
    assert_eq!(result.routes[0].unresolved_cameras, vec![11]);
    Ok(())
}

#[test]
fn wrong_clock_geometry_and_track_revision_fail_closed() -> Result<(), GeometryError> {
    let path = motion(&[[0.0, 0.0, 10.0]], RouteEnd::Stop)?;
    let scene = mesh(false)?;
    let mut cam = camera(11)?;
    cam.clock = 99;
    assert_eq!(
        run(&path, &scene, &[cam]),
        Err(GeometryError::BasisMismatch)
    );
    cam = camera(11)?;
    cam.geometry = GeometryBasis::new(2, 2)?;
    assert_eq!(
        run(&path, &scene, &[cam]),
        Err(GeometryError::BasisMismatch)
    );
    let body = body()?;
    let stale = ForecastBasis::new(basis()?.geometry(), 3, 4, 99, 6)?;
    assert_eq!(
        predict_camera_handoffs(
            stale,
            &path,
            &scene,
            &[camera(11)?],
            &[RouteBody {
                route: 1,
                body: &body
            }],
            options(),
            &mut WorkBudget::new(1000)
        ),
        Err(GeometryError::BasisMismatch)
    );
    Ok(())
}

#[test]
fn missing_body_duplicate_camera_and_duplicate_probe_fail() -> Result<(), GeometryError> {
    let path = motion(&[[0.0, 0.0, 10.0]], RouteEnd::Stop)?;
    let scene = mesh(false)?;
    assert_eq!(
        run(&path, &scene, &[camera(11)?, camera(11)?]),
        Err(GeometryError::InvalidIndex)
    );
    assert_eq!(
        predict_camera_handoffs(
            basis()?,
            &path,
            &scene,
            &[camera(11)?],
            &[],
            options(),
            &mut WorkBudget::new(1000)
        ),
        Err(GeometryError::LimitExceeded)
    );
    assert_eq!(
        BodySamples::new(1, &[[0.0; 3]; 2], &mut WorkBudget::new(100)),
        Err(GeometryError::Degenerate)
    );
    Ok(())
}

#[test]
fn sample_limits_and_cancellation_never_publish_partial_success() -> Result<(), GeometryError> {
    let path = motion(&[[100.0, 0.0, 10.0]], RouteEnd::Stop)?;
    let scene = mesh(false)?;
    let body = body()?;
    let cameras = [camera(11)?];
    let bodies = [RouteBody {
        route: 1,
        body: &body,
    }];
    assert_eq!(
        predict_camera_handoffs(
            basis()?,
            &path,
            &scene,
            &cameras,
            &bodies,
            HandoffOptions {
                max_samples_per_camera: 1,
                ..options()
            },
            &mut WorkBudget::new(1000)
        ),
        Err(GeometryError::LimitExceeded)
    );
    let cancelled = AtomicBool::new(true);
    assert_eq!(
        predict_camera_handoffs(
            basis()?,
            &path,
            &scene,
            &cameras,
            &bodies,
            options(),
            &mut WorkBudget::cancellable(1000, &cancelled)
        ),
        Err(GeometryError::Cancelled)
    );
    assert_eq!(
        predict_camera_handoffs(
            basis()?,
            &path,
            &scene,
            &cameras,
            &bodies,
            options(),
            &mut WorkBudget::new(0)
        ),
        Err(GeometryError::BudgetExhausted)
    );
    Ok(())
}

#[test]
fn capture_schedule_matches_exhaustive_integer_reference() -> Result<(), GeometryError> {
    for period in 1..32 {
        for phase in 0..period {
            let schedule = CaptureSchedule::new(period, phase)?;
            for time in 0..100 {
                let expected = (time..time + period).find(|sample| sample % period == phase);
                assert_eq!(schedule.first_at_or_after(time), expected);
            }
        }
    }
    assert_eq!(
        CaptureSchedule::new(2, 0)?.first_at_or_after(u64::MAX),
        None
    );
    assert!(CaptureSchedule::new(0, 0).is_err());
    assert!(CaptureSchedule::new(2, 2).is_err());
    Ok(())
}

#[test]
fn availability_interval_overflow_is_rejected_before_prediction() -> Result<(), GeometryError> {
    let path = motion(&[[0.0, 0.0, 10.0]], RouteEnd::Stop)?;
    let mut cam = camera(11)?;
    cam.latency = NanosecondInterval::new(u64::MAX, u64::MAX)?;
    assert_eq!(
        run(&path, &mesh(false)?, &[cam]),
        Err(GeometryError::OutOfRange)
    );
    Ok(())
}
