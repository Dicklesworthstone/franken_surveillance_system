#![forbid(unsafe_code)]
//! Synthetic rate/offset contracts; no deployment clock or camera qualification.
use std::sync::atomic::AtomicBool;
use fss_geometry::{GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};
use fss_geometry::temporal_alignment::{ClockAlignmentPair, scan_clock_offsets};
use fss_geometry::temporal_alignment::drift::{
    ClockDriftError as Error, ClockRateHypothesis as Rate, MAX_CLOCK_SKEW_PPB, scan_clock_drift,
};
use fss_geometry::temporal_triangulation::{TemporalTriangulationOptions as Options, TimedCalibratedView};
use fss_geometry::temporal_validation::IntervalCalibratedView;
use fss_geometry::triangulation::CalibratedView;

type Test = Result<(), Box<dyn std::error::Error>>;
const OFFSET: i128 = 50_000_000;
const SKEW: i64 = 500_000;
const WORK: u64 = 100_000_000;
const EPOCH: i128 = 1_i128 << 100;
fn pair() -> ClockAlignmentPair {
    ClockAlignmentPair { reference_camera: 1, target_camera: 2, reference_clock: 10, target_clock: 20 }
}
fn options() -> Options { Options { max_reprojection_pixels: 0.001, ..Options::default() } }
fn rates() -> [Rate; 3] { [-SKEW, 0, SKEW].map(|skew_ppb| Rate { offset_ns: OFFSET, skew_ppb }) }
fn fixture(epoch: i128, skew: i64, moving: bool)
    -> Result<(Vec<TimedCalibratedView>, Vec<IntervalCalibratedView>), GeometryError>
{
    let k = PinholeIntrinsics::new(1280, 960, 640.0, 640.0, 640.0, 480.0)?;
    let mut training = Vec::new();
    let mut validation = Vec::new();
    for camera in [1, 2] {
        let center = if camera == 1 { [-2.0, 0.0, 0.0] } else { [2.0, 1.0, 0.0] };
        let pose = RigidPose::from_center([[1.0,0.0,0.0],[0.0,1.0,0.0],[0.0,0.0,1.0]], center)?;
        for (holdout, seconds) in [(false,-10), (false,-6), (false,-2), (false,2), (false,6), (false,10),
            (true,-8), (true,-4), (true,0), (true,4), (true,8)]
        {
            let reference = i128::from(seconds) * 1_000_000_000;
            let local = epoch + if camera == 1 { reference }
                else { OFFSET + reference * (1_000_000_000 + i128::from(skew)) / 1_000_000_000 };
            let t = if moving { f64::from(seconds) } else { 0.0 };
            let point = [0.3 + 0.06 * t, 0.2 - 0.01 * t, 7.0 + 0.025 * t];
            let view = CalibratedView { camera, pose, intrinsics: k, pixel: pose.project(k, point)?, sigma_pixels: 1.0 };
            if holdout { validation.push(IntervalCalibratedView { view, capture_interval_ns: [local; 2] }); }
            else { training.push(TimedCalibratedView { view, capture_time_ns: local }); }
        }
    }
    Ok((training, validation))
}

#[test]
fn exact_integer_rate_mapping_preserves_large_epochs() -> Test {
    let rate = Rate { offset_ns: OFFSET, skew_ppb: SKEW };
    for seconds in [-10_i128, -1, 0, 1, 10] {
        let target = EPOCH + OFFSET + seconds * (1_000_000_000 + i128::from(SKEW));
        let mapped = rate.map_time(EPOCH + OFFSET, target)?;
        let expected = EPOCH + seconds * 1_000_000_000;
        assert_eq!(mapped.nominal_ns, expected);
        assert_eq!(mapped.enclosure_ns, [expected; 2]);
    }
    Ok(())
}

#[test]
fn fractional_times_round_outward_on_both_sides_of_the_anchor() -> Test {
    let rate = Rate { offset_ns: 0, skew_ppb: 1_000_000 };
    assert_eq!(rate.map_time(EPOCH, EPOCH + 1)?.enclosure_ns, [EPOCH, EPOCH + 1]);
    assert_eq!(rate.map_time(EPOCH, EPOCH - 1)?.enclosure_ns, [EPOCH - 1, EPOCH]);
    assert_eq!(rate.map_time(EPOCH, EPOCH + 1)?.nominal_ns, EPOCH + 1);
    assert_eq!(rate.map_time(EPOCH, EPOCH - 1)?.nominal_ns, EPOCH - 1);
    assert_eq!(rate.map_interval(EPOCH, [EPOCH - 1, EPOCH + 1])?, [EPOCH - 1, EPOCH + 1]);
    let slow = Rate { offset_ns: 0, skew_ppb: -1_000_000 };
    assert_eq!(slow.map_interval(EPOCH, [EPOCH - 1, EPOCH + 1])?, [EPOCH - 2, EPOCH + 2]);
    Ok(())
}

#[test]
fn half_nanosecond_ties_choose_the_earlier_integer() -> Test {
    let rate = Rate { offset_ns: 0, skew_ppb: 512 };
    // 976563 * 1e9 / 1000000512 = 976562.5 exactly.
    let mapped = rate.map_time(0, 976563)?;
    assert_eq!(mapped.enclosure_ns, [976562, 976563]);
    assert_eq!(mapped.nominal_ns, 976562);
    let negative = rate.map_time(0, -976563)?;
    assert_eq!(negative.enclosure_ns, [-976563, -976562]);
    assert_eq!(negative.nominal_ns, -976563);
    Ok(())
}

#[test]
fn malformed_rates_windows_intervals_and_overflow_fail_closed() {
    let rate = Rate { offset_ns: 0, skew_ppb: 0 };
    assert_eq!(Rate { skew_ppb: MAX_CLOCK_SKEW_PPB + 1, ..rate }.map_time(0, 0), Err(Error::InvalidHypotheses));
    assert_eq!(Rate { offset_ns: i128::MIN, ..rate }.map_time(0, 0), Err(Error::InvalidHypotheses));
    assert_eq!(rate.map_time(0, 60_000_000_001), Err(Error::OutsideAnchorWindow));
    assert_eq!(rate.map_time(i128::MIN, i128::MAX), Err(Error::OutsideAnchorWindow));
    assert_eq!(Rate { offset_ns: -1, ..rate }.map_time(i128::MAX, i128::MAX), Err(Error::TimestampOverflow));
    assert_eq!(rate.map_interval(0, [1, 0]), Err(Error::InvalidInterval));
}

#[test]
fn moving_feature_distinguishes_rate_hypotheses_and_retains_the_whole_inventory() -> Test {
    let (training, validation) = fixture(EPOCH, SKEW, true)?;
    let scan = scan_clock_drift(pair(), EPOCH + OFFSET, &training, &validation, &rates(), options(), &mut WorkBudget::new(WORK))?;
    assert_eq!(scan.trials.len(), 3);
    let supported: Vec<_> = scan.trials.iter().filter(|t| t.consistent_for_all_capture_times()).map(|t| t.hypothesis).collect();
    assert_eq!(supported, vec![rates()[2]]);
    let truth = &scan.trials[2];
    assert_eq!(truth.training_mappings.len(), training.len());
    let fit = truth.result.as_ref().map_err(|e| *e)?;
    assert_eq!(fit.checks.len(), validation.len());
    assert!(fit.fit.rms_reprojection_pixels < 1e-8);
    for (actual, expected) in fit.fit.velocity_per_second.iter().zip([0.06, -0.01, 0.025]) {
        assert!((actual - expected).abs() < 1e-8);
    }
    Ok(())
}

#[test]
fn zero_rate_preserves_the_constant_offset_fit_and_validation_bytes_in_memory() -> Test {
    let (training, validation) = fixture(0, 0, true)?;
    let original = scan_clock_offsets(pair(), &training, &validation, &[OFFSET], options(), &mut WorkBudget::new(WORK))?;
    let affine = scan_clock_drift(pair(), OFFSET, &training, &validation,
        &[Rate { offset_ns: OFFSET, skew_ppb: 0 }], options(), &mut WorkBudget::new(WORK))?;
    assert_eq!(original.trials[0].result, affine.trials[0].result);
    assert!(affine.trials[0].training_mappings.iter().all(|m| m.mapped.enclosure_ns == [m.mapped.nominal_ns; 2]));
    Ok(())
}

#[test]
fn static_feature_keeps_rate_ambiguity_instead_of_selecting_a_winner() -> Test {
    let (training, validation) = fixture(0, SKEW, false)?;
    let scan = scan_clock_drift(pair(), OFFSET, &training, &validation, &rates(), options(), &mut WorkBudget::new(WORK))?;
    assert!(scan.trials.iter().all(|trial| trial.consistent_for_all_capture_times()));
    Ok(())
}

#[test]
fn input_permutations_preserve_results_and_work() -> Test {
    let (mut training, mut validation) = fixture(0, SKEW, true)?;
    let first = scan_clock_drift(pair(), OFFSET, &training, &validation, &rates(), options(), &mut WorkBudget::new(WORK))?;
    training.reverse(); validation.reverse();
    let mut reversed = rates(); reversed.reverse();
    let second = scan_clock_drift(pair(), OFFSET, &training, &validation, &reversed, options(), &mut WorkBudget::new(WORK))?;
    assert_eq!(first, second);
    Ok(())
}

#[test]
fn single_shared_budget_and_cancellation_never_return_a_successful_prefix() -> Test {
    let (training, validation) = fixture(0, SKEW, true)?;
    let mut budget = WorkBudget::new(WORK);
    scan_clock_drift(pair(), OFFSET, &training, &validation, &rates(), options(), &mut budget)?;
    scan_clock_drift(pair(), OFFSET, &training, &validation, &rates(), options(), &mut WorkBudget::new(budget.used()))?;
    assert!(scan_clock_drift(pair(), OFFSET, &training, &validation, &rates(), options(), &mut WorkBudget::new(budget.used() - 1)).is_err());
    let flag = AtomicBool::new(true);
    assert_eq!(scan_clock_drift(pair(), OFFSET, &training, &validation, &rates(), options(), &mut WorkBudget::cancellable(WORK, &flag)),
        Err(Error::Geometry(GeometryError::Cancelled)));
    Ok(())
}

#[test]
fn duplicate_inventory_and_source_clock_changes_are_not_silently_accepted() -> Test {
    let (training, validation) = fixture(0, SKEW, true)?;
    assert_eq!(scan_clock_drift(pair(), OFFSET, &training, &validation, &[rates()[0]; 2], options(), &mut WorkBudget::new(WORK)),
        Err(Error::InvalidHypotheses));
    let mut changed = pair(); changed.target_clock = changed.reference_clock;
    assert!(scan_clock_drift(changed, OFFSET, &training, &validation, &rates(), options(), &mut WorkBudget::new(WORK)).is_err());
    Ok(())
}
