#![forbid(unsafe_code)]
//! Synthetic clock hypotheses, not camera, correspondence or clock qualification.

use std::sync::atomic::AtomicBool;
use fss_geometry::{GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};
use fss_geometry::temporal_alignment::{
    ClockAlignmentError as Error, ClockAlignmentPair, MAX_CLOCK_OFFSET_HYPOTHESES,
    scan_clock_offsets,
};
use fss_geometry::temporal_triangulation::{
    TemporalTriangulationError, TemporalTriangulationOptions, TimedCalibratedView,
};
use fss_geometry::temporal_validation::{
    IntervalCalibratedView, TemporalCompatibility, TemporalValidationError,
    TemporalValidationOutcome,
};
use fss_geometry::triangulation::CalibratedView;

type Test = Result<(), Box<dyn std::error::Error>>;
const ROTATION: [[f64; 3]; 3] = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
const OFFSET: i128 = 50_000_000;
const EPOCH: i128 = 1_i128 << 100;
const WORK: u64 = 100_000_000;
fn pair() -> ClockAlignmentPair {
    ClockAlignmentPair { reference_camera: 1, target_camera: 2, reference_clock: 10, target_clock: 20 }
}
fn options() -> TemporalTriangulationOptions {
    TemporalTriangulationOptions {
        max_reprojection_pixels: 0.05,
        ..TemporalTriangulationOptions::default()
    }
}
fn observation(camera: u64, time: i128, moving: bool) -> Result<CalibratedView, GeometryError> {
    let intrinsics = PinholeIntrinsics::new(1280, 960, 640.0, 640.0, 640.0, 480.0)?;
    let center = if camera == 1 { [-2.0, 0.0, 0.0] } else { [2.0, 1.0, 0.0] };
    let pose = RigidPose::from_center(ROTATION, center)?;
    let seconds = if moving { time as f64 * 1e-9 } else { 0.0 };
    let point = [0.3 + 0.6 * seconds, 0.2 - 0.1 * seconds, 7.0 + 0.25 * seconds];
    Ok(CalibratedView {
        camera, pose, intrinsics, pixel: pose.project(intrinsics, point)?, sigma_pixels: 1.0,
    })
}
fn fixture(epoch: i128, moving: bool)
    -> Result<(Vec<TimedCalibratedView>, Vec<IntervalCalibratedView>), GeometryError>
{
    let mut training = Vec::new();
    let mut validation = Vec::new();
    for camera in [1, 2] {
        let shift = if camera == 2 { OFFSET } else { 0 };
        for time in [-200_000_000, -100_000_000, 0, 100_000_000, 200_000_000] {
            training.push(TimedCalibratedView {
                view: observation(camera, time, moving)?, capture_time_ns: epoch + time + shift,
            });
        }
        for time in [-150_000_000, 150_000_000] {
            let local = epoch + time + shift;
            validation.push(IntervalCalibratedView {
                view: observation(camera, time, moving)?, capture_interval_ns: [local, local],
            });
        }
    }
    Ok((training, validation))
}

#[test]
fn moving_feature_preserves_all_trials_and_supports_the_exact_clock_offset() -> Test {
    let (training, validation) = fixture(EPOCH, true)?;
    let scan = scan_clock_offsets(pair(), &training, &validation, &[100_000_000, 0, OFFSET],
        options(), &mut WorkBudget::new(WORK))?;
    assert_eq!(scan.pair, pair());
    assert_eq!(scan.trials.iter().map(|t| t.target_minus_reference_ns).collect::<Vec<_>>(),
        vec![0, OFFSET, 100_000_000]);
    let supported: Vec<_> = scan.trials.iter().filter(|t| t.consistent_for_all_capture_times())
        .map(|t| t.target_minus_reference_ns).collect();
    assert_eq!(supported, vec![OFFSET]);
    let result = scan.trials[1].result.as_ref().map_err(|e| *e)?;
    assert_eq!(result.checks.len(), validation.len());
    assert_eq!(result.fit.residuals.len(), training.len());
    assert!(result.fit.rms_reprojection_pixels < 1e-8);
    for (actual, expected) in result.fit.velocity_per_second.iter().zip([0.6, -0.1, 0.25]) {
        assert!((actual - expected).abs() < 1e-8);
    }
    assert!(scan.work_units > scan.trials.iter().map(|t| t.work_units).sum::<u64>());
    Ok(())
}

#[test]
fn static_features_preserve_clock_ambiguity_instead_of_picking_a_winner() -> Test {
    let (training, validation) = fixture(0, false)?;
    let scan = scan_clock_offsets(pair(), &training, &validation, &[0, OFFSET, 100_000_000],
        options(), &mut WorkBudget::new(WORK))?;
    assert_eq!(scan.trials.len(), 3);
    assert!(scan.trials.iter().all(|t| t.consistent_for_all_capture_times()));
    Ok(())
}

#[test]
fn observation_and_hypothesis_permutations_preserve_results_and_total_cost() -> Test {
    let (mut training, mut validation) = fixture(EPOCH, true)?;
    let first = scan_clock_offsets(pair(), &training, &validation, &[0, OFFSET, 100_000_000],
        options(), &mut WorkBudget::new(WORK))?;
    training.reverse();
    validation.reverse();
    let second = scan_clock_offsets(pair(), &training, &validation, &[100_000_000, OFFSET, 0],
        options(), &mut WorkBudget::new(WORK))?;
    assert_eq!(first, second);
    Ok(())
}

#[test]
fn a_large_common_epoch_does_not_destroy_small_clock_differences() -> Test {
    let (training, validation) = fixture(0, true)?;
    let origin = scan_clock_offsets(pair(), &training, &validation, &[OFFSET],
        options(), &mut WorkBudget::new(WORK))?;
    let (training, validation) = fixture(EPOCH, true)?;
    let shifted = scan_clock_offsets(pair(), &training, &validation, &[OFFSET],
        options(), &mut WorkBudget::new(WORK))?;
    let a = origin.trials[0].result.as_ref().map_err(|e| *e)?;
    let b = shifted.trials[0].result.as_ref().map_err(|e| *e)?;
    assert_eq!(a.fit.position, b.fit.position);
    assert_eq!(a.fit.velocity_per_second, b.fit.velocity_per_second);
    assert_eq!(a.fit.reference_time_ns + EPOCH, b.fit.reference_time_ns);
    assert_eq!(origin.work_units, shifted.work_units);
    Ok(())
}

#[test]
fn validation_intervals_are_shifted_whole_and_timing_ambiguity_survives() -> Test {
    let (training, mut validation) = fixture(EPOCH, true)?;
    for item in &mut validation {
        item.capture_interval_ns[0] -= 10_000_000;
        item.capture_interval_ns[1] += 10_000_000;
    }
    let scan = scan_clock_offsets(pair(), &training, &validation, &[OFFSET],
        options(), &mut WorkBudget::new(WORK))?;
    let trial = &scan.trials[0];
    assert!(!trial.consistent_for_all_capture_times());
    let result = trial.result.as_ref().map_err(|e| *e)?;
    for (check, original) in result.checks.iter().zip(&validation) {
        let offset = if check.camera == 2 { OFFSET } else { 0 };
        assert_eq!(check.capture_interval_ns,
            original.capture_interval_ns.map(|time| time - offset));
        assert!(matches!(check.outcome, TemporalValidationOutcome::Observable {
            compatibility: TemporalCompatibility::TimingAmbiguous, ..
        }));
    }
    Ok(())
}

#[test]
fn all_trials_share_one_budget_and_exhaustion_never_returns_a_prefix() -> Test {
    let (training, validation) = fixture(0, true)?;
    let mut measured = WorkBudget::new(WORK);
    scan_clock_offsets(pair(), &training, &validation, &[0, OFFSET, 100_000_000],
        options(), &mut measured)?;
    let mut exact = WorkBudget::new(measured.used());
    scan_clock_offsets(pair(), &training, &validation, &[0, OFFSET, 100_000_000],
        options(), &mut exact)?;
    let mut short = WorkBudget::new(measured.used() - 1);
    assert!(scan_clock_offsets(pair(), &training, &validation, &[0, OFFSET, 100_000_000],
        options(), &mut short).is_err());
    assert!(short.used() <= measured.used() - 1);
    Ok(())
}

#[test]
fn cancelled_scan_returns_no_inventory() -> Test {
    let (training, validation) = fixture(0, true)?;
    let flag = AtomicBool::new(true);
    let mut budget = WorkBudget::cancellable(WORK, &flag);
    assert_eq!(scan_clock_offsets(pair(), &training, &validation, &[OFFSET], options(), &mut budget),
        Err(Error::Geometry(GeometryError::Cancelled)));
    assert_eq!(budget.used(), 0);
    Ok(())
}

#[test]
fn bad_offsets_and_excess_inventory_are_not_deduplicated_or_truncated() -> Test {
    let (training, validation) = fixture(0, true)?;
    for offsets in [vec![], vec![OFFSET, OFFSET], vec![60_000_000_001], vec![i128::MIN]] {
        assert_eq!(scan_clock_offsets(pair(), &training, &validation, &offsets,
            options(), &mut WorkBudget::new(WORK)), Err(Error::InvalidOffsets));
    }
    let offsets: Vec<_> = (0..=MAX_CLOCK_OFFSET_HYPOTHESES).map(|i| i as i128).collect();
    assert_eq!(scan_clock_offsets(pair(), &training, &validation, &offsets,
        options(), &mut WorkBudget::new(WORK)), Err(Error::Geometry(GeometryError::LimitExceeded)));
    Ok(())
}

#[test]
fn camera_or_clock_scope_cannot_silently_change() -> Test {
    let (mut training, validation) = fixture(0, true)?;
    let mut bad = pair();
    bad.target_clock = bad.reference_clock;
    assert_eq!(scan_clock_offsets(bad, &training, &validation, &[OFFSET],
        options(), &mut WorkBudget::new(WORK)), Err(Error::InvalidPair));
    training[0].view.pose = RigidPose::IDENTITY;
    assert_eq!(scan_clock_offsets(pair(), &training, &validation, &[OFFSET],
        options(), &mut WorkBudget::new(WORK)), Err(Error::InvalidObservation));
    Ok(())
}

#[test]
fn fit_validation_reuse_and_duplicate_training_are_refused() -> Test {
    let (mut training, mut validation) = fixture(0, true)?;
    validation[0].capture_interval_ns = [training[0].capture_time_ns; 2];
    assert_eq!(scan_clock_offsets(pair(), &training, &validation, &[OFFSET],
        options(), &mut WorkBudget::new(WORK)), Err(Error::ReusedObservation));
    let (_, validation) = fixture(0, true)?;
    training.push(training[0]);
    assert_eq!(scan_clock_offsets(pair(), &training, &validation, &[OFFSET],
        options(), &mut WorkBudget::new(WORK)), Err(Error::ReusedObservation));
    Ok(())
}

#[test]
fn timestamp_overflow_in_a_late_hypothesis_refuses_the_whole_scan() -> Test {
    let (mut training, validation) = fixture(0, true)?;
    training[5].capture_time_ns = i128::MIN;
    assert_eq!(scan_clock_offsets(pair(), &training, &validation, &[0, OFFSET],
        options(), &mut WorkBudget::new(WORK)), Err(Error::TimestampOverflow));
    Ok(())
}

#[test]
fn weak_geometry_is_retained_as_unresolved_not_false_clock_evidence() -> Test {
    let (mut training, mut validation) = fixture(0, true)?;
    for item in &mut training {
        let time = item.capture_time_ns - if item.view.camera == 2 { OFFSET } else { 0 };
        let mut view = observation(1, time, true)?;
        view.camera = item.view.camera;
        item.view = view;
    }
    for item in &mut validation {
        let time = item.capture_interval_ns[0] - if item.view.camera == 2 { OFFSET } else { 0 };
        let mut view = observation(1, time, true)?;
        view.camera = item.view.camera;
        item.view = view;
    }
    let scan = scan_clock_offsets(pair(), &training, &validation, &[OFFSET],
        options(), &mut WorkBudget::new(WORK))?;
    assert_eq!(scan.trials.len(), 1);
    assert_eq!(scan.trials[0].result,
        Err(TemporalValidationError::Fit(TemporalTriangulationError::UnobservableMotion)));
    Ok(())
}
