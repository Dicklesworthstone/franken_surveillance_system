#![forbid(unsafe_code)]
//! Synthetic capture-session separation; no physical clock or source qualification.
use std::sync::atomic::AtomicBool;
use fss_geometry::{GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};
use fss_geometry::temporal_alignment::ClockAlignmentPair;
use fss_geometry::temporal_alignment::drift::ClockRateHypothesis;
use fss_geometry::temporal_alignment::drift::validation::{
    ClockProjectionRequest, ClockValidationError as Error, ClockValidationSession,
    MAX_CLOCK_VALIDATION_SESSIONS, validate_clock_sessions,
};
use fss_geometry::temporal_triangulation::{TemporalTriangulationOptions, TimedCalibratedView};
use fss_geometry::temporal_validation::IntervalCalibratedView;
use fss_geometry::triangulation::CalibratedView;

type Test = Result<(), Box<dyn std::error::Error>>;
type Session = (Vec<TimedCalibratedView>, Vec<IntervalCalibratedView>);
const EPOCH: i128 = 1_i128 << 100;
const OFFSET: i128 = 50_000_000;
const WORK: u64 = 100_000_000;
const ROTATION: [[f64; 3]; 3] = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
fn pair() -> ClockAlignmentPair {
    ClockAlignmentPair { reference_camera: 1, target_camera: 2, reference_clock: 10, target_clock: 20 }
}
fn hypotheses() -> [ClockRateHypothesis; 3] {
    [-500_000, 0, 500_000].map(|skew_ppb| ClockRateHypothesis { offset_ns: OFFSET, skew_ppb })
}
fn options() -> TemporalTriangulationOptions {
    TemporalTriangulationOptions { max_reprojection_pixels: 0.0001, ..TemporalTriangulationOptions::default() }
}
fn local(camera: u64, seconds: i128) -> i128 {
    EPOCH + seconds * 1_000_000_000 + if camera == 2 { OFFSET + seconds * 500_000 } else { 0 }
}
fn fixture(start: i128, stationary: bool) -> Result<Session, GeometryError> {
    let intrinsics = PinholeIntrinsics::new(1280, 960, 640.0, 640.0, 640.0, 480.0)?;
    let mut training = Vec::new();
    let mut validation = Vec::new();
    for camera in [1, 2] {
        let center = if camera == 1 { [-2.0, 0.0, 0.0] } else { [2.0, 1.0, 0.0] };
        let pose = RigidPose::from_center(ROTATION, center)?;
        for step in 0..5 {
            let seconds = start + step * 2;
            let t = if stationary { 0.0 } else { step as f64 * 2.0 - 4.0 };
            let point = [0.3 + 0.15 * t, 0.2 - 0.03 * t, 7.0 + 0.06 * t];
            let view = CalibratedView { camera, pose, intrinsics,
                pixel: pose.project(intrinsics, point)?, sigma_pixels: 1.0 };
            let time = local(camera, seconds);
            if step % 2 == 0 {
                training.push(TimedCalibratedView { view, capture_time_ns: time });
            } else {
                validation.push(IntervalCalibratedView { view, capture_interval_ns: [time; 2] });
            }
        }
    }
    Ok((training, validation))
}
fn session(id: u64, data: &Session) -> ClockValidationSession<'_> {
    ClockValidationSession { id, training: &data.0, validation: &data.1 }
}
fn projections() -> [ClockProjectionRequest; 2] {
    [ClockProjectionRequest { id: 2, target_interval_ns: [local(2, 16), local(2, 17)] },
     ClockProjectionRequest { id: 1, target_interval_ns: [local(2, -20), local(2, -19)] }]
}

#[test]
fn fresh_passages_validate_frozen_clock_without_narrowing_the_projection_inventory() -> Test {
    let search = fixture(-40, false)?;
    let a = fixture(-24, false)?;
    let b = fixture(-8, false)?;
    let report = validate_clock_sessions(pair(), EPOCH + OFFSET, &search.0, &search.1,
        &[session(20, &b), session(10, &a)], &hypotheses(), &projections(), options(), &mut WorkBudget::new(WORK))?;
    assert_eq!(report.sessions.iter().map(|s| s.id).collect::<Vec<_>>(), vec![10, 20]);
    assert_eq!(report.support.iter().filter(|s| s.supported_in_every_session()).map(|s| s.hypothesis.skew_ppb).collect::<Vec<_>>(), vec![500_000]);
    for projection in &report.projections {
        assert_eq!(projection.mappings.len(), 3);
        for (_, bounds) in &projection.mappings {
            assert!(projection.reference_envelope_ns[0] <= bounds[0]);
            assert!(bounds[1] <= projection.reference_envelope_ns[1]);
        }
    }
    assert_eq!(report.projections[0].containing_session_ids, vec![10]);
    assert!(report.projections[1].containing_session_ids.is_empty());
    assert_eq!(report.search.trials.len(), 3);
    assert!(report.sessions.iter().all(|s| s.scan.trials.len() == 3));
    Ok(())
}

#[test]
fn stationary_search_ambiguity_is_preserved_when_a_new_moving_passage_discriminates() -> Test {
    let search = fixture(-40, true)?;
    let held = fixture(-24, false)?;
    let report = validate_clock_sessions(pair(), EPOCH + OFFSET, &search.0, &search.1,
        &[session(1, &held)], &hypotheses(), &[], options(), &mut WorkBudget::new(WORK))?;
    assert!(report.search.trials.iter().all(|t| t.consistent_for_all_capture_times()));
    assert_eq!(report.support.iter().filter(|s| s.supported_in_every_session()).count(), 1);
    assert_eq!(report.support.len(), 3);
    Ok(())
}

#[test]
fn stationary_passages_cannot_manufacture_unique_clock_support() -> Test {
    let search = fixture(-40, true)?;
    let held = fixture(-24, true)?;
    let report = validate_clock_sessions(pair(), EPOCH + OFFSET, &search.0, &search.1,
        &[session(1, &held)], &hypotheses(), &[], options(), &mut WorkBudget::new(WORK))?;
    assert!(report.support.iter().all(|s| s.supported_in_every_session()));
    Ok(())
}

#[test]
fn reused_search_or_overlapping_sessions_are_rejected_before_they_can_validate() -> Test {
    let search = fixture(-40, false)?;
    let held = fixture(-36, false)?;
    for held in [&search, &held] {
        assert_eq!(validate_clock_sessions(pair(), EPOCH + OFFSET, &search.0, &search.1,
            &[session(1, held)], &hypotheses(), &[], options(), &mut WorkBudget::new(WORK)), Err(Error::OverlappingSessions));
    }
    Ok(())
}

#[test]
fn camera_motion_between_sessions_requires_a_new_scope() -> Test {
    let search = fixture(-40, false)?;
    let mut held = fixture(-24, false)?;
    for row in &mut held.0 { row.view.pose = RigidPose::IDENTITY; }
    for row in &mut held.1 { row.view.pose = RigidPose::IDENTITY; }
    assert_eq!(validate_clock_sessions(pair(), EPOCH + OFFSET, &search.0, &search.1,
        &[session(1, &held)], &hypotheses(), &[], options(), &mut WorkBudget::new(WORK)), Err(Error::CameraChanged));
    Ok(())
}

#[test]
fn a_clock_reset_cannot_reverse_the_order_of_capture_sessions() -> Test {
    let search = fixture(-40, false)?;
    let mut held = fixture(-24, false)?;
    for row in &mut held.0 {
        if row.view.camera == 2 { row.capture_time_ns -= 40_000_000_000; }
    }
    for row in &mut held.1 {
        if row.view.camera == 2 { row.capture_interval_ns = row.capture_interval_ns.map(|t| t - 40_000_000_000); }
    }
    assert_eq!(validate_clock_sessions(pair(), EPOCH + OFFSET, &search.0, &search.1,
        &[session(1, &held)], &hypotheses(), &[], options(), &mut WorkBudget::new(WORK)), Err(Error::ClockOrderChanged));
    Ok(())
}

#[test]
fn ordering_does_not_change_complete_results_or_work() -> Test {
    let mut search = fixture(-40, false)?;
    let mut a = fixture(-24, false)?;
    let b = fixture(-8, false)?;
    let first = validate_clock_sessions(pair(), EPOCH + OFFSET, &search.0, &search.1,
        &[session(2, &a), session(1, &b)], &hypotheses(), &projections(), options(), &mut WorkBudget::new(WORK))?;
    search.0.reverse(); search.1.reverse(); a.0.reverse(); a.1.reverse();
    let mut candidates = hypotheses(); candidates.reverse();
    let mut requests = projections(); requests.reverse();
    let second = validate_clock_sessions(pair(), EPOCH + OFFSET, &search.0, &search.1,
        &[session(1, &b), session(2, &a)], &candidates, &requests, options(), &mut WorkBudget::new(WORK))?;
    assert_eq!(first, second);
    Ok(())
}

#[test]
fn one_shared_budget_cannot_return_a_successful_prefix() -> Test {
    let search = fixture(-40, false)?;
    let held = fixture(-24, false)?;
    let run = |budget: &mut WorkBudget<'_>| validate_clock_sessions(pair(), EPOCH + OFFSET, &search.0, &search.1,
        &[session(1, &held)], &hypotheses(), &projections(), options(), budget);
    let mut measured = WorkBudget::new(WORK);
    run(&mut measured)?;
    run(&mut WorkBudget::new(measured.used()))?;
    assert!(run(&mut WorkBudget::new(measured.used() - 1)).is_err());
    let flag = AtomicBool::new(true);
    let mut cancelled = WorkBudget::cancellable(WORK, &flag);
    assert_eq!(run(&mut cancelled), Err(Error::Geometry(GeometryError::Cancelled)));
    assert_eq!(cancelled.used(), 0);
    Ok(())
}

#[test]
fn session_and_projection_inventories_are_never_deduplicated_or_truncated() -> Test {
    let search = fixture(-40, false)?;
    let held = fixture(-24, false)?;
    for sessions in [vec![], vec![session(0, &held)], vec![session(1, &held), session(1, &held)]] {
        assert_eq!(validate_clock_sessions(pair(), EPOCH + OFFSET, &search.0, &search.1,
            &sessions, &hypotheses(), &[], options(), &mut WorkBudget::new(WORK)), Err(Error::InvalidSession));
    }
    let sessions = vec![session(1, &held); MAX_CLOCK_VALIDATION_SESSIONS + 1];
    assert_eq!(validate_clock_sessions(pair(), EPOCH + OFFSET, &search.0, &search.1,
        &sessions, &hypotheses(), &[], options(), &mut WorkBudget::new(WORK)), Err(Error::Geometry(GeometryError::LimitExceeded)));
    let request = projections()[0];
    assert_eq!(validate_clock_sessions(pair(), EPOCH + OFFSET, &search.0, &search.1,
        &[session(1, &held)], &hypotheses(), &[request, request], options(), &mut WorkBudget::new(WORK)), Err(Error::InvalidProjection));
    Ok(())
}

#[test]
fn invalid_late_projection_returns_no_partial_time_envelope() -> Test {
    let search = fixture(-40, false)?;
    let held = fixture(-24, false)?;
    let requests = [projections()[0], ClockProjectionRequest { id: 99, target_interval_ns: [i128::MAX; 2] }];
    assert!(validate_clock_sessions(pair(), EPOCH + OFFSET, &search.0, &search.1,
        &[session(1, &held)], &hypotheses(), &requests, options(), &mut WorkBudget::new(WORK)).is_err());
    Ok(())
}
