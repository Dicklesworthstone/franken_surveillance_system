#![forbid(unsafe_code)]
//! Outward-rounded affine clock projections, independent of estimator fitting policy.

use std::error::Error;

use fss_core::{CaptureInterval, ContentDigest, TimestampNs};
use fss_reference::{
    ClockOffsetSkewEstimator, ClockSyncEstimate, EstimatorConfig, ReferenceError,
    SyncFitResidual, TimeSyncSample,
};

type TestResult = Result<(), Box<dyn Error>>;

// A hand-built mathematical fixture, not a claim of a certified one-sample fit.
fn model(skew: i64, uncertainty: u64, residual: u64) -> Result<ClockSyncEstimate, Box<dyn Error>> {
    let sample = TimeSyncSample::new(1, TimestampNs(0), TimestampNs(37), uncertainty)?;
    Ok(ClockSyncEstimate {
        reference_anchor: TimestampNs(0),
        offset_ns: 37,
        skew_ppm: skew,
        residual: SyncFitResidual {
            max_residual_ns: residual,
            mean_squared_error_ns2: 0,
            offset_variance_ns2: 0,
            skew_variance_ppm2: 0,
            sample_count: 1,
        },
        validity: CaptureInterval::new(TimestampNs(-1_000_000_000), TimestampNs(1_000_000_000))?,
        sample_evidence: vec![sample],
        evidence_root: ContentDigest::sha256(b"clock-projection-test-only"),
        generation: 1,
    })
}

fn bounds(interval: CaptureInterval) -> (i128, i128) {
    (interval.earliest.0, interval.latest.0)
}

#[test]
fn inverse_scales_sensor_uncertainty_for_slow_and_fast_clocks() -> TestResult {
    assert_eq!(
        bounds(model(-500_000, 10, 0)?.predict_reference_interval(TimestampNs(137))?),
        (180, 220)
    );
    assert_eq!(
        bounds(model(500_000, 10, 0)?.predict_reference_interval(TimestampNs(138))?),
        (60, 74)
    );
    // Before the anchor: truncation toward zero would omit the lower endpoint.
    assert_eq!(
        bounds(model(500_000, 1, 0)?.predict_reference_interval(TimestampNs(36))?),
        (-2, 0)
    );
    Ok(())
}

#[test]
fn forward_projection_rounds_both_signed_fractional_endpoints_outward() -> TestResult {
    let positive = model(500_000, 1, 0)?;
    assert_eq!(bounds(positive.predict_sensor_interval(TimestampNs(1))?), (37, 40));
    assert_eq!(bounds(positive.predict_sensor_interval(TimestampNs(-1))?), (34, 37));
    let negative = model(-500_000, 1, 0)?;
    assert_eq!(bounds(negative.predict_sensor_interval(TimestampNs(1))?), (36, 39));
    assert_eq!(bounds(negative.predict_sensor_interval(TimestampNs(-1))?), (35, 38));
    Ok(())
}

#[test]
fn composed_uncertainty_is_not_narrowed_by_u64_saturation() -> TestResult {
    let estimate = model(0, u64::MAX, u64::MAX)?;
    let uncertainty = 2 * i128::from(u64::MAX);
    assert_eq!(
        bounds(estimate.predict_sensor_interval(TimestampNs(0))?),
        (37 - uncertainty, 37 + uncertainty)
    );
    assert_eq!(
        bounds(estimate.predict_reference_interval(TimestampNs(37))?),
        (-uncertainty, uncertainty)
    );
    Ok(())
}

#[test]
fn zero_uncertainty_retains_the_one_nanosecond_floor() -> TestResult {
    let estimate = model(0, 0, 0)?;
    assert_eq!(bounds(estimate.predict_sensor_interval(TimestampNs(0))?), (36, 38));
    assert_eq!(bounds(estimate.predict_reference_interval(TimestampNs(37))?), (-1, 1));
    Ok(())
}

#[test]
fn fractional_nominal_inverse_cannot_round_back_into_validity() -> TestResult {
    let mut estimate = model(500_000, 1, 0)?;
    estimate.validity = CaptureInterval::new(TimestampNs(0), TimestampNs(100))?;
    for sensor in [36, 188] {
        assert!(matches!(
            estimate.predict_reference_interval(TimestampNs(sensor)),
            Err(ReferenceError::StaleEstimatePastValidity { .. })
        ));
    }
    // Exact endpoints remain admitted; uncertainty is not clipped to the horizon.
    assert_eq!(bounds(estimate.predict_reference_interval(TimestampNs(37))?), (-1, 1));
    assert_eq!(bounds(estimate.predict_reference_interval(TimestampNs(187))?), (99, 101));
    Ok(())
}

#[test]
fn representable_ratios_do_not_overflow_at_the_multiplication_step() -> TestResult {
    let mut estimate = model(1_000_000, 1, 0)?;
    estimate.offset_ns = 0;
    estimate.validity = CaptureInterval::new(TimestampNs::MIN, TimestampNs::MAX)?;
    for reference in [i128::MAX / 4, i128::MIN / 4] {
        assert!(reference.checked_mul(1_000_000).is_none());
        assert_eq!(
            bounds(estimate.predict_sensor_interval(TimestampNs(reference))?),
            (2 * reference - 1, 2 * reference + 1)
        );
        let sensor = 2 * reference;
        assert_eq!(
            bounds(estimate.predict_reference_interval(TimestampNs(sensor))?),
            (reference - 1, reference + 1)
        );
    }
    Ok(())
}

#[test]
fn true_endpoint_overflow_and_nonpositive_rates_fail_closed() -> TestResult {
    let mut estimate = model(0, 1, 0)?;
    estimate.offset_ns = 0;
    estimate.validity = CaptureInterval::new(TimestampNs::MIN, TimestampNs::MAX)?;
    for endpoint in [TimestampNs::MIN, TimestampNs::MAX] {
        assert!(matches!(
            estimate.predict_sensor_interval(endpoint),
            Err(ReferenceError::ArithmeticOverflow)
        ));
        assert!(matches!(
            estimate.predict_reference_interval(endpoint),
            Err(ReferenceError::ArithmeticOverflow)
        ));
    }
    for skew in [-1_000_000, -1_000_001, i64::MIN] {
        estimate.skew_ppm = skew;
        assert!(matches!(
            estimate.predict_reference_interval(TimestampNs(0)),
            Err(ReferenceError::ArithmeticOverflow)
        ));
        assert!(matches!(
            estimate.predict_sensor_interval(TimestampNs(0)),
            Err(ReferenceError::ArithmeticOverflow)
        ));
    }
    estimate.sample_evidence.clear();
    assert!(matches!(
        estimate.predict_reference_interval(TimestampNs(0)),
        Err(ReferenceError::InsufficientSyncSamples { count: 0, .. })
    ));
    assert!(matches!(
        estimate.predict_sensor_interval(TimestampNs(0)),
        Err(ReferenceError::InsufficientSyncSamples { count: 0, .. })
    ));
    Ok(())
}

#[test]
fn projections_match_an_independent_exact_rational_oracle() -> TestResult {
    for skew in [-999_999, -500_000, -7, 0, 7, 500_000, 1_000_000] {
        for anchor in [-101, 101] {
            for offset in [-37, 37] {
                for uncertainty in [1, 3, 19] {
                    for residual in [0, 7] {
                        let mut estimate = model(skew, uncertainty, residual)?;
                        estimate.reference_anchor = TimestampNs(anchor);
                        estimate.offset_ns = offset;
                        let before = estimate.clone();
                        let u = i128::from(uncertainty) + i128::from(residual);
                        let rate = 1_000_000 + i128::from(skew);
                        for delta in [-113, -19, -1, 0, 1, 19, 113] {
                            let sensor = anchor + i128::from(offset) + delta;
                            let low_numerator = (delta - u) * 1_000_000;
                            let high_numerator = (delta + u) * 1_000_000;
                            assert_eq!(
                                bounds(estimate.predict_reference_interval(TimestampNs(sensor))?),
                                (
                                    anchor + low_numerator.div_euclid(rate),
                                    anchor - (-high_numerator).div_euclid(rate),
                                )
                            );
                            let reference = anchor + delta;
                            let numerator = delta * i128::from(skew);
                            assert_eq!(
                                bounds(estimate.predict_sensor_interval(TimestampNs(reference))?),
                                (
                                    reference + i128::from(offset)
                                        + numerator.div_euclid(1_000_000) - u,
                                    reference + i128::from(offset)
                                        - (-numerator).div_euclid(1_000_000) + u,
                                )
                            );
                        }
                        assert_eq!(estimate, before);
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn larger_measurement_and_fit_uncertainty_never_narrow_projections() -> TestResult {
    for skew in [-500_000, -7, 0, 7, 500_000] {
        for delta in [-19, 0, 19] {
            let tight = model(skew, 1, 0)?;
            for (uncertainty, residual) in [(2, 0), (1, 2), (13, 17)] {
                let wide = model(skew, uncertainty, residual)?;
                for (small, large) in [
                    (
                        tight.predict_reference_interval(TimestampNs(37 + delta))?,
                        wide.predict_reference_interval(TimestampNs(37 + delta))?,
                    ),
                    (
                        tight.predict_sensor_interval(TimestampNs(delta))?,
                        wide.predict_sensor_interval(TimestampNs(delta))?,
                    ),
                ] {
                    assert!(large.earliest <= small.earliest);
                    assert!(large.latest >= small.latest);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn fitted_slow_clock_uses_the_same_conservative_projection() -> TestResult {
    let mut estimator = ClockOffsetSkewEstimator::new(EstimatorConfig::default())?;
    for (sequence, reference, sensor) in [
        (1, 0, 37),
        (2, 1_000_000, 500_037),
        (3, 2_000_000, 1_000_037),
    ] {
        estimator.add_sample(TimeSyncSample::new(
            sequence, TimestampNs(reference), TimestampNs(sensor), 10,
        )?)?;
    }
    let estimate = estimator.fit()?;
    assert_eq!(estimate.skew_ppm, -500_000);
    assert_eq!(estimate.offset_ns, 37);
    assert_eq!(
        bounds(estimate.predict_reference_interval(TimestampNs(500_037))?),
        (999_980, 1_000_020)
    );
    Ok(())
}
