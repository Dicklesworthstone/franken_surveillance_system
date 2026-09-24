#![forbid(unsafe_code)]
//! Observed handoff contract contract tests.
use fss_core::ContentDigest;
use fss_geometry::{
    BodySamples, CameraAvailability, CaptureSchedule, GeometryBasis, GeometryError, HandoffCamera,
    HandoffOptions, NanosecondInterval, NextCameraOutcome, PinholeIntrinsics, RigidPose, RouteEnd,
    WorkBudget,
};
use fss_twin::observed_handoff::*;
use fss_twin::stream::{ContactTrack, TrackOptions, TrackScope};
use fss_twin::{
    ContactObservation, ImportExpectation, ImportLimits, MovementClass, NavigationProfile,
    PropertyTwin, RouteOutcome, SupportNetwork, TrackingCamera, import_twin,
};
use std::error::Error;
use std::sync::atomic::AtomicBool;

type Test = Result<(), Box<dyn Error>>;
fn budget() -> WorkBudget<'static> {
    WorkBudget::new(100_000_000)
}
fn twin() -> Result<PropertyTwin, Box<dyn Error>> {
    // Independent wire producer: two rows of three squares, with a grass shortcut.
    let mut b = vec![1; 32];
    for s in ["source-property/Z-up", "synthetic"] {
        b.extend_from_slice(&(s.len() as u16).to_le_bytes());
        b.extend_from_slice(s.as_bytes());
    }
    b.push(0);
    for f in [0.0_f64, -1.0, -1.0] {
        b.extend_from_slice(&f.to_le_bytes());
    }
    for n in [3_u32, 3, 12, 12] {
        b.extend_from_slice(&n.to_le_bytes());
    }
    for (s, k) in [("grass", 2_u8), ("path", 1), ("target", 1)] {
        b.extend_from_slice(&(s.len() as u16).to_le_bytes());
        b.extend_from_slice(s.as_bytes());
        b.push(k);
    }
    for (i, s) in ["grass", "path", "target"].iter().enumerate() {
        b.extend_from_slice(&(s.len() as u16).to_le_bytes());
        b.extend_from_slice(s.as_bytes());
        b.extend_from_slice(&(i as u32).to_le_bytes());
        b.extend_from_slice(&[1, 1]);
    }
    for y in 0..3 {
        for x in 0..4 {
            for f in [2.0 * x as f64, 2.0 * y as f64, 0.0] {
                b.extend_from_slice(&f.to_le_bytes());
            }
        }
    }
    for y in 0..2_u32 {
        for x in 0..3_u32 {
            let a = y * 4 + x;
            let object = if x == 2 {
                2
            } else if x == 1 && y == 0 {
                0
            } else {
                1
            };
            for n in [a, a + 1, a + 5, object, a, a + 5, a + 4, object] {
                b.extend_from_slice(&n.to_le_bytes());
            }
        }
    }
    let mut bytes = b"FSSTWIN1".to_vec();
    bytes.extend_from_slice(&(b.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&b);
    bytes.extend_from_slice(&ContentDigest::sha256(&bytes).bytes());
    Ok(import_twin(
        &bytes,
        ImportExpectation {
            package_sha256: ContentDigest::sha256(&bytes).bytes(),
            source_scene_sha256: [1; 32],
            basis: GeometryBasis::new(1, 1)?,
        },
        ImportLimits::default(),
        &mut budget(),
    )?)
}
fn camera(id: u64) -> Result<TrackingCamera, Box<dyn Error>> {
    let (center, k) = if id == 1 {
        (
            [2.0, 2.0, 10.0],
            PinholeIntrinsics::new(200, 200, 100.0, 100.0, 100.0, 100.0)?,
        )
    } else {
        (
            [5.0, 1.0, 5.0],
            PinholeIntrinsics::new(100, 100, 200.0, 200.0, 50.0, 50.0)?,
        )
    };
    Ok(TrackingCamera {
        geometry: GeometryBasis::new(1, 1)?,
        camera: id,
        calibration: 2,
        image_domain: 3,
        clock: 1,
        validity: [0, 100_000_000_000],
        pose: RigidPose::from_center(
            [[1.0, 0.0, 0.0], [0.0, -1.0, 0.0], [0.0, 0.0, -1.0]],
            center,
        )?,
        intrinsics: k,
        error: None,
    })
}
fn observation(id: u64, t: u64, x: f64) -> ContactObservation {
    let mut evidence = [77; 32];
    evidence[..8].copy_from_slice(&id.to_le_bytes());
    let pixel = [100.0 + 10.0 * (x - 2.0), 117.5];
    ContactObservation {
        evidence,
        track: 9,
        camera: 1,
        exposure: id,
        image_domain: 3,
        clock: 1,
        capture: [t * 1_000_000_000; 2],
        pixel_min: pixel,
        pixel_max: pixel,
        visible_contact: true,
    }
}
fn track(twin: &PropertyTwin, earlier_x: f64) -> Result<ContactTrack, Box<dyn Error>> {
    let mut b = budget();
    let mut s = ContactTrack::new(
        twin,
        TrackScope {
            track: 9,
            clock: 1,
            epoch: 7,
        },
        &[camera(1)?, camera(2)?],
        TrackOptions::default(),
        &mut b,
    )?;
    s.ingest(twin, observation(1, 1, earlier_x), None, &mut b)?;
    s.ingest(twin, observation(2, 2, 1.0), None, &mut b)?;
    Ok(s)
}
fn view(id: u64) -> Result<HandoffCamera<'static>, Box<dyn Error>> {
    let c = camera(id)?;
    Ok(HandoffCamera {
        id,
        geometry: c.geometry,
        clock: 1,
        observation_generation: 11,
        image_mode: 3,
        pose: c.pose,
        intrinsics: c.intrinsics,
        availability: CameraAvailability::Ready,
        already_observing: false,
        valid: NanosecondInterval::new(0, 100_000_000_000)?,
        schedule: CaptureSchedule::new(100_000_000, 0)?,
        latency: NanosecondInterval::new(200_000_000, 400_000_000)?,
        privacy_masks: &[],
        visible_per_mille: 1000,
        minimum_extent_px: [1.0, 1.0],
    })
}
fn body() -> Result<BodySamples, GeometryError> {
    BodySamples::new(
        8,
        &[
            [-0.1, -0.1, 0.3],
            [0.1, -0.1, 0.3],
            [-0.1, 0.1, 1.0],
            [0.1, 0.1, 1.0],
        ],
        &mut budget(),
    )
}
fn options() -> ObservedForecastOptions {
    ObservedForecastOptions {
        horizon_ns: 30_000_000_000,
        motion_generation: 4,
        max_routes: 64,
        acceleration_bound: [0.2; 3],
        handoff: HandoffOptions {
            max_samples_per_camera: 1000,
            endpoint_margin: 1e-6,
        },
    }
}
fn destination(
    body: &BodySamples,
    class: MovementClass,
) -> Result<DestinationHypothesis<'_>, Box<dyn Error>> {
    Ok(DestinationHypothesis {
        feature: 2,
        profile: NavigationProfile::new(
            class,
            0.5,
            0.0,
            if class == MovementClass::Person { 8 } else { 1 },
        )?,
        body,
        speed_multiplier: 1.0,
        initial_pause_ns: 0,
        end: RouteEnd::Stop,
    })
}

#[test]
fn observations_generate_real_routes_and_camera_handoffs_without_waypoint_inputs() -> Test {
    let twin = twin()?;
    let network = SupportNetwork::compile(&twin, 100, &mut budget())?;
    let state = track(&twin, 0.7)?;
    let body = body()?;
    let result = forecast_to_feature(
        &twin,
        &network,
        state.snapshot(2)?,
        destination(&body, MovementClass::Person)?,
        &[view(1)?, view(2)?],
        options(),
        &mut budget(),
    )?;
    assert_eq!(result.observations[0].exposure, 1);
    assert_eq!(result.observations[1].exposure, 2);
    assert_eq!(result.routes.len(), 3);
    assert_eq!(result.reachable.len(), 1);
    for r in &result.routes {
        assert!((r.nominal_speed.ok_or("speed missing")? - 0.3).abs() < 1e-9);
    }
    let preferred = &result.routes[0];
    let neutral = &result.routes[1];
    let triangles = |r: &RouteAssessment| -> Vec<u32> {
        match &r.path {
            AssessedPath::Navigation(s) => match &s.outcome {
                RouteOutcome::Found(route) => route.triangles().to_vec(),
                _ => Vec::new(),
            },
            _ => Vec::new(),
        }
    };
    assert_ne!(triangles(preferred), triangles(neutral));
    let ObservedPredictions::Modeled { motion, handoff } = &result.predictions else {
        return Err("no predictions".into());
    };
    assert_eq!(motion.priors().class_masses(), [1, 0, 0, 0]);
    assert!(
        handoff
            .camera_scope
            .iter()
            .find(|c| c.camera == 1)
            .ok_or("camera missing")?
            .already_observing
    );
    assert!(
        handoff.routes.iter().any(
            |r| matches!(&r.next,NextCameraOutcome::Predicted{cameras,..} if cameras==&vec![2])
        )
    );
    assert!(
        handoff
            .routes
            .iter()
            .find(|r| r.route == neutral.route)
            .ok_or("neutral route lost")?
            .protected
    );
    for r in &handoff.routes {
        for o in &r.observations {
            assert_eq!(
                o.availability_ns.earliest() - o.nominal_capture_ns,
                200_000_000
            );
            assert_eq!(
                o.availability_ns.latest() - o.nominal_capture_ns,
                400_000_000
            );
        }
    }
    Ok(())
}
#[test]
fn measured_speed_changes_arrival_without_changing_the_current_location() -> Test {
    let twin = twin()?;
    let network = SupportNetwork::compile(&twin, 100, &mut budget())?;
    let body = body()?;
    let mut times = Vec::new();
    for earlier in [0.7, 0.4] {
        let state = track(&twin, earlier)?;
        let result = forecast_to_feature(
            &twin,
            &network,
            state.snapshot(2)?,
            destination(&body, MovementClass::Bear)?,
            &[view(2)?],
            options(),
            &mut budget(),
        )?;
        let ObservedPredictions::Modeled { handoff, .. } = result.predictions else {
            return Err("missing predictions".into());
        };
        let first = handoff.routes[0]
            .observations
            .first()
            .ok_or("missing target view")?
            .nominal_capture_ns;
        times.push(first);
    }
    assert!(times[1] < times[0]);
    assert_eq!(times, vec![14_800_000_000, 8_400_000_000]);
    Ok(())
}
#[test]
fn animal_and_unknown_hypotheses_do_not_receive_pedestrian_preferences() -> Test {
    let twin = twin()?;
    let network = SupportNetwork::compile(&twin, 100, &mut budget())?;
    let state = track(&twin, 0.7)?;
    let body = body()?;
    for (class, masses) in [
        (MovementClass::Bear, [0, 1, 0, 0]),
        (MovementClass::Unknown, [0, 0, 0, 1]),
    ] {
        let r = forecast_to_feature(
            &twin,
            &network,
            state.snapshot(2)?,
            destination(&body, class)?,
            &[view(2)?],
            options(),
            &mut budget(),
        )?;
        assert_eq!(r.routes.len(), 2);
        assert!(
            !r.routes
                .iter()
                .any(|r| r.kind == ObservedRouteKind::WithoutPathPreference)
        );
        let ObservedPredictions::Modeled { motion, .. } = r.predictions else {
            return Err("missing forecast".into());
        };
        assert_eq!(motion.priors().class_masses(), masses);
        assert_eq!(motion.priors().person_path_multiplier(), 1);
    }
    Ok(())
}
#[test]
fn stopped_observation_does_not_invent_a_walking_speed() -> Test {
    let twin = twin()?;
    let network = SupportNetwork::compile(&twin, 100, &mut budget())?;
    let state = track(&twin, 1.0)?;
    let body = body()?;
    let r = forecast_to_feature(
        &twin,
        &network,
        state.snapshot(2)?,
        destination(&body, MovementClass::Bear)?,
        &[view(2)?],
        options(),
        &mut budget(),
    )?;
    assert!(matches!(
        r.routes[0].path,
        AssessedPath::Unresolved(UnresolvedRoute::UnusableSpeed)
    ));
    let ObservedPredictions::Modeled { motion, handoff } = r.predictions else {
        return Err("stop missing".into());
    };
    assert_eq!(motion.hypotheses().len(), 1);
    assert_eq!(motion.hypotheses()[0].id(), 2);
    assert!(matches!(
        handoff.routes[0].next,
        NextCameraOutcome::NoModeledObservation
    ));
    Ok(())
}
#[test]
fn missing_source_motion_is_not_a_no_observation_forecast() -> Test {
    let twin = twin()?;
    let network = SupportNetwork::compile(&twin, 100, &mut budget())?;
    let mut state = track(&twin, 0.7)?;
    let body = body()?;
    let mut hidden = observation(3, 3, 1.1);
    hidden.visible_contact = false;
    state.ingest(&twin, hidden, None, &mut budget())?;
    assert!(matches!(
        forecast_to_feature(
            &twin,
            &network,
            state.snapshot(3)?,
            destination(&body, MovementClass::Person)?,
            &[view(2)?],
            options(),
            &mut budget()
        ),
        Err(ObservedForecastError::MotionUnavailable)
    ));
    Ok(())
}
#[test]
fn camera_pose_substitution_and_stale_owned_forecasts_are_refused() -> Test {
    let twin = twin()?;
    let network = SupportNetwork::compile(&twin, 100, &mut budget())?;
    let mut state = track(&twin, 0.7)?;
    let body = body()?;
    let r = forecast_to_feature(
        &twin,
        &network,
        state.snapshot(2)?,
        destination(&body, MovementClass::Bear)?,
        &[view(2)?],
        options(),
        &mut budget(),
    )?;
    r.check_source_current(state.snapshot(2)?)?;
    let mut wrong = view(2)?;
    wrong.pose = camera(1)?.pose;
    assert!(matches!(
        forecast_to_feature(
            &twin,
            &network,
            state.snapshot(2)?,
            destination(&body, MovementClass::Bear)?,
            &[wrong],
            options(),
            &mut budget()
        ),
        Err(ObservedForecastError::Basis)
    ));
    state.ingest(&twin, observation(3, 3, 1.3), None, &mut budget())?;
    assert_eq!(
        r.check_source_current(state.snapshot(3)?),
        Err(ObservedForecastError::Basis)
    );
    Ok(())
}
#[test]
fn camera_validity_cannot_be_extended_by_the_forecast_request() -> Test {
    let twin = twin()?;
    let network = SupportNetwork::compile(&twin, 100, &mut budget())?;
    let body = body()?;
    let mut c2 = camera(2)?;
    c2.validity = [0, 3_000_000_000];
    let mut state = ContactTrack::new(
        &twin,
        TrackScope {
            track: 9,
            clock: 1,
            epoch: 7,
        },
        &[camera(1)?, c2],
        TrackOptions::default(),
        &mut budget(),
    )?;
    state.ingest(&twin, observation(1, 1, 0.7), None, &mut budget())?;
    state.ingest(&twin, observation(2, 2, 1.0), None, &mut budget())?;
    let r = forecast_to_feature(
        &twin,
        &network,
        state.snapshot(2)?,
        destination(&body, MovementClass::Bear)?,
        &[view(2)?],
        options(),
        &mut budget(),
    )?;
    let ObservedPredictions::Modeled { handoff, .. } = r.predictions else {
        return Err("missing forecast".into());
    };
    assert!(
        handoff
            .routes
            .iter()
            .all(|r| matches!(r.next, NextCameraOutcome::Indeterminate))
    );
    Ok(())
}
#[test]
fn complete_alternative_limits_and_cancellation_do_not_mutate_source_state() -> Test {
    let twin = twin()?;
    let network = SupportNetwork::compile(&twin, 100, &mut budget())?;
    let state = track(&twin, 0.7)?;
    let body = body()?;
    let opt = ObservedForecastOptions {
        max_routes: 2,
        ..options()
    };
    assert!(matches!(
        forecast_to_feature(
            &twin,
            &network,
            state.snapshot(2)?,
            destination(&body, MovementClass::Person)?,
            &[view(2)?],
            opt,
            &mut budget()
        ),
        Err(ObservedForecastError::Options)
    ));
    let flag = AtomicBool::new(true);
    assert!(matches!(
        forecast_to_feature(
            &twin,
            &network,
            state.snapshot(2)?,
            destination(&body, MovementClass::Person)?,
            &[view(2)?],
            options(),
            &mut WorkBudget::cancellable(100_000_000, &flag)
        ),
        Err(ObservedForecastError::Twin(fss_twin::TwinError::Geometry(
            GeometryError::Cancelled
        )))
    ));
    assert_eq!(state.revision(), 2);
    Ok(())
}
