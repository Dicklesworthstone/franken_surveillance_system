#![forbid(unsafe_code)]
//! Inverse enclosures must retain all clock times admitted by forward uncertainty.
use super::*;

type Test = Result<(), ReferenceError>;

fn estimate(skew_ppm: i64, uncertainty: u64, residual: u64) -> Result<ClockSyncEstimate, ReferenceError> {
    let sample = TimeSyncSample::new(1, TimestampNs(0), TimestampNs(0), uncertainty)?;
    Ok(ClockSyncEstimate {
        reference_anchor: TimestampNs(0), offset_ns: 0, skew_ppm,
        residual: SyncFitResidual { max_residual_ns: residual, mean_squared_error_ns2: 0,
            offset_variance_ns2: 0, skew_variance_ppm2: 0, sample_count: 1 },
        validity: CaptureInterval::new(TimestampNs(-1_000_000), TimestampNs(1_000_000))?,
        evidence_root: sample.digest, sample_evidence: vec![sample], generation: 1,
    })
}

fn contains(interval: CaptureInterval, point: i128) -> bool {
    interval.earliest.0 <= point && point <= interval.latest.0
}

#[test]
fn slow_sensor_uncertainty_is_scaled_before_inversion() -> Test {
    let estimate = estimate(-500_000, 10, 0)?;
    let interval = estimate.predict_reference_interval(TimestampNs(100))?;
    // 10 sensor ns correspond to 20 reference ns. Old bounds [190,210] lost both.
    assert!(contains(interval, 180));
    assert!(contains(interval, 220));
    assert_eq!(interval.earliest.0, 178); // Includes one sensor tick of skew rounding.
    assert_eq!(interval.latest.0, 222);
    Ok(())
}

#[test]
fn integer_forward_skew_rounding_is_not_lost_in_inverse_bounds() -> Test {
    let estimate = estimate(-500_000, 1, 0)?;
    let forward = estimate.predict_sensor_interval(TimestampNs(17))?;
    // 17 + trunc(-8.5) = 9. The sensor reading 10 is inside [8,10].
    assert!(contains(forward, 10));
    assert!(contains(estimate.predict_reference_interval(TimestampNs(10))?, 17));
    assert!(contains(estimate.predict_reference_interval(TimestampNs(-10))?, -17));
    Ok(())
}

#[test]
fn directed_endpoints_enclose_signed_rational_bounds() -> Test {
    for skew in [-500_000, -333_333, -1, 1, 333_333, 500_000] {
        let estimate = estimate(skew, 3, 4)?;
        let rate = 1_000_000 + i128::from(skew);
        for reading in [-101_i128, -17, -1, 0, 1, 17, 101] {
            let result = estimate.predict_reference_interval(TimestampNs(reading))?;
            let lower = (reading - 8) * 1_000_000;
            let upper = (reading + 8) * 1_000_000;
            assert!(result.earliest.0 * rate <= lower);
            assert!((result.earliest.0 + 1) * rate > lower);
            assert!(result.latest.0 * rate >= upper);
            assert!((result.latest.0 - 1) * rate < upper);
        }
    }
    Ok(())
}

#[test]
fn inverse_keeps_every_integer_time_admitted_by_forward_intervals() -> Test {
    for skew in [-500_000, -333_333, -1, 0, 1, 333_333, 500_000] {
        for uncertainty in [0, 1, 3] {
            let mut estimate = estimate(skew, uncertainty, 2)?;
            estimate.reference_anchor = TimestampNs(123);
            estimate.offset_ns = -71;
            for delta in -100..=100_i128 {
                let reference = estimate.reference_anchor.0 + delta;
                let forward = estimate.predict_sensor_interval(TimestampNs(reference))?;
                for reading in forward.earliest.0..=forward.latest.0 {
                    let inverse = estimate.predict_reference_interval(TimestampNs(reading))?;
                    assert!(contains(inverse, reference), "skew={skew}, ref={reference}, sensor={reading}");
                }
            }
        }
    }
    Ok(())
}

#[test]
fn uncertainty_sum_is_not_clamped_to_u64_before_expansion() -> Test {
    let estimate = estimate(0, u64::MAX, u64::MAX)?;
    let radius = i128::from(u64::MAX) * 2;
    for result in [estimate.predict_sensor_interval(TimestampNs(0))?,
        estimate.predict_reference_interval(TimestampNs(0))?] {
        assert_eq!(result.earliest.0, -radius);
        assert_eq!(result.latest.0, radius);
    }
    Ok(())
}

#[test]
fn zero_skew_preserves_existing_exact_intervals_and_minimum_radius() -> Test {
    for uncertainty in [0_u64, 1, 10, 100] {
        let mut estimate = estimate(0, uncertainty, 0)?;
        estimate.reference_anchor = TimestampNs(100);
        estimate.offset_ns = 31;
        let radius = i128::from(uncertainty.max(1));
        for reference in [-99_i128, 0, 17, 101] {
            let sensor = reference + 31;
            let f = estimate.predict_sensor_interval(TimestampNs(reference))?;
            let r = estimate.predict_reference_interval(TimestampNs(sensor))?;
            assert_eq!([f.earliest.0, f.latest.0], [sensor - radius, sensor + radius]);
            assert_eq!([r.earliest.0, r.latest.0], [reference - radius, reference + radius]);
        }
    }
    Ok(())
}

#[test]
fn fitted_half_rate_clock_retains_sensor_error_in_reference_domain() -> Test {
    let mut estimator = ClockOffsetSkewEstimator::new(EstimatorConfig {
        min_samples: 3, max_residual_tolerance_ns: 0, max_outlier_basis_points: 0,
        validity_horizon_ns: 1000, contradiction_tolerance_ns: 10,
    })?;
    for sequence in 1..=3 {
        let reference = i128::from(sequence) * 1000;
        estimator.add_sample(TimeSyncSample::new(sequence, TimestampNs(reference),
            TimestampNs(reference / 2), 10)?)?;
    }
    let estimate = estimator.fit()?;
    assert_eq!(estimate.skew_ppm, -500_000);
    let inverse = estimate.predict_reference_interval(TimestampNs(1000))?;
    assert!(contains(inverse, 1980));
    assert!(contains(inverse, 2020));
    Ok(())
}

#[test]
fn missing_samples_stale_time_invalid_rate_and_overflow_still_fail() -> Test {
    let mut estimate = estimate(0, 10, 0)?;
    let before = estimate.clone();
    assert!(matches!(estimate.predict_reference_interval(TimestampNs(1_000_001)),
        Err(ReferenceError::StaleEstimatePastValidity { .. })));
    assert_eq!(estimate, before);
    estimate.skew_ppm = -1_000_000;
    assert!(matches!(estimate.predict_reference_interval(TimestampNs(0)),
        Err(ReferenceError::ArithmeticOverflow)));
    estimate.skew_ppm = 0;
    estimate.reference_anchor = TimestampNs(i128::MAX - 1);
    estimate.validity = CaptureInterval::new(TimestampNs(i128::MAX - 1), TimestampNs(i128::MAX))?;
    assert!(matches!(estimate.predict_sensor_interval(TimestampNs(i128::MAX - 1)),
        Err(ReferenceError::ArithmeticOverflow)));
    assert!(matches!(estimate.predict_reference_interval(TimestampNs(i128::MAX - 1)),
        Err(ReferenceError::ArithmeticOverflow)));
    estimate.sample_evidence.clear();
    assert!(matches!(estimate.predict_reference_interval(TimestampNs(0)),
        Err(ReferenceError::InsufficientSyncSamples { .. })));
    Ok(())
}
