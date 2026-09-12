#![forbid(unsafe_code)]
//! Integration contract tests for deterministic clock offset/skew estimator interface (FSS-088).

use std::error::Error;

use fss_core::TimestampNs;
use fss_reference::{
    ClockOffsetSkewEstimator, ClockSyncEstimate, EstimatorConfig, EstimatorState, ReferenceError,
    TimeSyncSample, VirtualClock,
};

fn create_nominal_sample(
    seq: u64,
    ref_ns: i128,
    sensor_ns: i128,
) -> Result<TimeSyncSample, Box<dyn Error>> {
    Ok(TimeSyncSample::new(
        seq,
        TimestampNs(ref_ns),
        TimestampNs(sensor_ns),
        500, // 500 ns uncertainty
    )?)
}

#[test]
fn fault_insufficient_samples_rejected_with_typed_error() -> Result<(), Box<dyn Error>> {
    let config = EstimatorConfig {
        min_samples: 4,
        ..EstimatorConfig::default()
    };
    let mut estimator = ClockOffsetSkewEstimator::new(config);

    // 0 samples
    match estimator.fit() {
        Err(ReferenceError::InsufficientSyncSamples {
            count,
            minimum_required,
        }) => {
            assert_eq!(count, 0);
            assert_eq!(minimum_required, 4);
        }
        other => return Err(format!("expected InsufficientSyncSamples, got {other:?}").into()),
    }

    // 2 samples (< 4 required)
    estimator.add_sample(create_nominal_sample(1, 1_000_000, 1_050_000)?)?;
    estimator.add_sample(create_nominal_sample(2, 2_000_000, 2_050_000)?)?;

    match estimator.fit() {
        Err(ReferenceError::InsufficientSyncSamples {
            count,
            minimum_required,
        }) => {
            assert_eq!(count, 2);
            assert_eq!(minimum_required, 4);
        }
        other => return Err(format!("expected InsufficientSyncSamples, got {other:?}").into()),
    }

    assert_eq!(*estimator.state(), EstimatorState::Uncalibrated);
    assert!(estimator.active_estimate().is_none());
    Ok(())
}

#[test]
fn fault_non_monotonic_reference_samples_rejected() -> Result<(), Box<dyn Error>> {
    let mut estimator = ClockOffsetSkewEstimator::new(EstimatorConfig::default());
    estimator.add_sample(create_nominal_sample(1, 10_000_000, 10_050_000)?)?;

    // Backward step in reference time
    match estimator.add_sample(create_nominal_sample(2, 9_000_000, 11_050_000)?) {
        Err(ReferenceError::NonMonotonicSyncSamples { previous, current }) => {
            assert_eq!(previous, TimestampNs(10_000_000));
            assert_eq!(current, TimestampNs(9_000_000));
        }
        other => return Err(format!("expected NonMonotonicSyncSamples, got {other:?}").into()),
    }

    // Equal (zero step) in reference time
    match estimator.add_sample(create_nominal_sample(2, 10_000_000, 11_050_000)?) {
        Err(ReferenceError::NonMonotonicSyncSamples { .. }) => {}
        other => return Err(format!("expected NonMonotonicSyncSamples, got {other:?}").into()),
    }

    // Previous valid sample retained
    assert_eq!(estimator.samples().len(), 1);
    Ok(())
}

#[test]
fn fault_non_monotonic_sensor_samples_rejected() -> Result<(), Box<dyn Error>> {
    let mut estimator = ClockOffsetSkewEstimator::new(EstimatorConfig::default());
    estimator.add_sample(create_nominal_sample(1, 1_000_000, 5_000_000)?)?;

    // Reference time increases, but sensor time steps backwards
    match estimator.add_sample(create_nominal_sample(2, 2_000_000, 4_900_000)?) {
        Err(ReferenceError::NonMonotonicSyncSamples { previous, current }) => {
            assert_eq!(previous, TimestampNs(5_000_000));
            assert_eq!(current, TimestampNs(4_900_000));
        }
        other => return Err(format!("expected NonMonotonicSyncSamples, got {other:?}").into()),
    }

    assert_eq!(estimator.samples().len(), 1);
    Ok(())
}

#[test]
fn fault_outlier_dominated_fit_rejected_with_typed_error() -> Result<(), Box<dyn Error>> {
    let config = EstimatorConfig {
        min_samples: 4,
        max_residual_tolerance_ns: 1_000, // 1 microsecond tolerance
        max_outlier_basis_points: 2_000,  // max 20% outliers allowed
        ..EstimatorConfig::default()
    };
    let mut estimator = ClockOffsetSkewEstimator::new(config);

    // 5 samples where 2 of them have outlier noise exceeding 1 us tolerance
    estimator.add_sample(create_nominal_sample(1, 1_000_000, 2_000_000)?)?;
    estimator.add_sample(create_nominal_sample(2, 2_000_000, 3_050_000)?)?; // outlier (+50us)
    estimator.add_sample(create_nominal_sample(3, 3_000_000, 4_000_000)?)?;
    estimator.add_sample(create_nominal_sample(4, 4_000_000, 5_060_000)?)?; // outlier (+60us)
    estimator.add_sample(create_nominal_sample(5, 5_000_000, 6_000_000)?)?;

    match estimator.fit() {
        Err(ReferenceError::OutlierDominatedFit {
            outlier_count,
            total_samples,
            max_residual_ns,
        }) => {
            assert_eq!(total_samples, 5);
            assert!(outlier_count >= 2);
            assert!(max_residual_ns > 1_000);
        }
        other => return Err(format!("expected OutlierDominatedFit, got {other:?}").into()),
    }

    assert!(estimator.active_estimate().is_none());
    Ok(())
}

#[test]
fn fault_stale_estimate_past_validity_rejected() -> Result<(), Box<dyn Error>> {
    let config = EstimatorConfig {
        min_samples: 3,
        validity_horizon_ns: 10_000_000, // 10 ms validity horizon
        ..EstimatorConfig::default()
    };
    let mut estimator = ClockOffsetSkewEstimator::new(config);

    estimator.add_sample(create_nominal_sample(1, 1_000_000, 2_000_000)?)?;
    estimator.add_sample(create_nominal_sample(2, 2_000_000, 3_000_000)?)?;
    estimator.add_sample(create_nominal_sample(3, 3_000_000, 4_000_000)?)?;

    let estimate = estimator.fit()?;

    // Last sample at 3_000_000, horizon is 10_000_000 -> valid until 13_000_000
    assert_eq!(estimate.validity.latest, TimestampNs(13_000_000));

    // Request within validity horizon -> Success
    let valid_query = estimate.predict_sensor_interval(TimestampNs(10_000_000))?;
    assert!(valid_query.earliest.0 <= valid_query.latest.0);

    // Request beyond validity horizon -> StaleEstimatePastValidity
    match estimate.predict_sensor_interval(TimestampNs(13_000_001)) {
        Err(ReferenceError::StaleEstimatePastValidity {
            requested,
            valid_until,
        }) => {
            assert_eq!(requested, TimestampNs(13_000_001));
            assert_eq!(valid_until, TimestampNs(13_000_000));
        }
        other => return Err(format!("expected StaleEstimatePastValidity, got {other:?}").into()),
    }

    // Request before earliest sample -> StaleEstimatePastValidity
    match estimate.predict_sensor_interval(TimestampNs(999_999)) {
        Err(ReferenceError::StaleEstimatePastValidity { .. }) => {}
        other => return Err(format!("expected StaleEstimatePastValidity, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn fault_contradicted_estimate_triggers_invalidation_and_rollback() -> Result<(), Box<dyn Error>> {
    let config = EstimatorConfig {
        min_samples: 3,
        contradiction_tolerance_ns: 20_000, // 20 microseconds
        ..EstimatorConfig::default()
    };
    let mut estimator = ClockOffsetSkewEstimator::new(config);

    // Fit initial synchronized estimate: constant offset = 1_000_000 ns
    estimator.add_sample(create_nominal_sample(1, 10_000_000, 11_000_000)?)?;
    estimator.add_sample(create_nominal_sample(2, 20_000_000, 21_000_000)?)?;
    estimator.add_sample(create_nominal_sample(3, 30_000_000, 31_000_000)?)?;

    let initial_estimate = estimator.fit()?;
    assert_eq!(initial_estimate.offset_ns, 1_000_000);
    assert_eq!(initial_estimate.skew_ppm, 0);

    // Now introduce a contradictory sample where sensor offset abruptly changes to 5_000_000 ns
    let contradictory_sample = create_nominal_sample(4, 40_000_000, 45_000_000)?;
    match estimator.add_sample(contradictory_sample.clone()) {
        Err(ReferenceError::ContradictedEstimate {
            expected_offset_ns,
            observed_offset_ns,
            deviation_ns,
        }) => {
            assert_eq!(expected_offset_ns, 1_000_000);
            assert_eq!(observed_offset_ns, 5_000_000);
            assert_eq!(deviation_ns, 4_000_000);
        }
        other => return Err(format!("expected ContradictedEstimate, got {other:?}").into()),
    }

    // Estimator must transition to Invalidated state
    match estimator.state() {
        EstimatorState::Invalidated {
            prior_estimate,
            contradicting_sample: bad_sample,
            reason,
        } => {
            assert_eq!(*prior_estimate, initial_estimate);
            assert_eq!(*bad_sample, contradictory_sample);
            assert!(reason.contains("contradicted"));
        }
        other => return Err(format!("expected Invalidated state, got {other:?}").into()),
    }
    assert!(estimator.active_estimate().is_none());

    // Rollback restores the prior valid estimate
    let restored = estimator.rollback()?;
    assert_eq!(restored, Some(initial_estimate.clone()));
    assert_eq!(
        *estimator.state(),
        EstimatorState::Synchronized(initial_estimate)
    );

    Ok(())
}

#[test]
fn deterministic_bit_identical_estimates_from_virtual_clock() -> Result<(), Box<dyn Error>> {
    // Generate samples driven deterministically by a VirtualClock
    let run_estimation = |seed: u64| -> Result<ClockSyncEstimate, Box<dyn Error>> {
        let mut ref_clock = VirtualClock::new(seed, TimestampNs(1_000_000_000));
        let mut sensor_clock = VirtualClock::new(seed ^ 0xaabb, TimestampNs(1_015_000_000));
        sensor_clock.inject_skew(1_500)?; // +0.15% skew
        sensor_clock.inject_jitter(50);

        let config = EstimatorConfig {
            min_samples: 5,
            ..EstimatorConfig::default()
        };
        let mut estimator = ClockOffsetSkewEstimator::new(config);

        for seq in 1..=10 {
            let ref_t = ref_clock.now();
            let sensor_t = sensor_clock.now();
            let sample = TimeSyncSample::new(seq, ref_t, sensor_t, 250)?;
            estimator.add_sample(sample)?;

            ref_clock.advance(10_000_000)?;
            sensor_clock.advance(10_000_000)?;
        }

        let estimate = estimator.fit()?;
        Ok(estimate)
    };

    let est1 = run_estimation(0x55aa_1234_u64)?;
    let est2 = run_estimation(0x55aa_1234_u64)?;

    // Bit-identical reproducibility
    assert_eq!(est1.offset_ns, est2.offset_ns);
    assert_eq!(est1.skew_ppm, est2.skew_ppm);
    assert_eq!(est1.residual, est2.residual);
    assert_eq!(est1.validity, est2.validity);
    assert_eq!(est1.evidence_root, est2.evidence_root);
    assert_eq!(est1.sample_evidence, est2.sample_evidence);
    assert_eq!(est1, est2);

    // Different seeds produce distinct evidence and estimates
    let est_diff = run_estimation(0x9999_8888_u64)?;
    assert_ne!(est1.evidence_root, est_diff.evidence_root);

    Ok(())
}

#[test]
fn conservative_uncertainty_expansion_in_predicted_intervals() -> Result<(), Box<dyn Error>> {
    let mut estimator = ClockOffsetSkewEstimator::new(EstimatorConfig::default());
    estimator.add_sample(create_nominal_sample(1, 10_000_000, 15_000_000)?)?;
    estimator.add_sample(create_nominal_sample(2, 20_000_000, 25_000_000)?)?;
    estimator.add_sample(create_nominal_sample(3, 30_000_000, 35_000_000)?)?;

    let estimate = estimator.fit()?;

    let query_ref = TimestampNs(25_000_000);
    let interval = estimate.predict_sensor_interval(query_ref)?;

    // Nominal sensor time should be 30_000_000
    // Interval must conservatively bracket the nominal point
    assert!(interval.earliest.0 < 30_000_000);
    assert!(interval.latest.0 > 30_000_000);
    assert!(interval.latest.0 > interval.earliest.0);

    // Predict reference interval from sensor time
    let query_sensor = TimestampNs(30_000_000);
    let ref_interval = estimate.predict_reference_interval(query_sensor)?;
    assert!(ref_interval.earliest.0 < 25_000_000);
    assert!(ref_interval.latest.0 > 25_000_000);
    assert!(ref_interval.latest.0 > ref_interval.earliest.0);

    Ok(())
}

#[test]
fn end_to_end_virtual_clock_sync_workflow() -> Result<(), Box<dyn Error>> {
    // Reference camera clock (nominal, no skew)
    let mut ref_clock = VirtualClock::new(101, TimestampNs(5_000_000_000));

    // Remote camera clock with initial +25 ms offset and +2000 ppm skew
    let mut sensor_clock = VirtualClock::new(202, TimestampNs(5_025_000_000));
    sensor_clock.inject_skew(2_000)?;

    let config = EstimatorConfig {
        min_samples: 5,
        max_residual_tolerance_ns: 2_000_000,
        max_outlier_basis_points: 1_000,
        validity_horizon_ns: 30_000_000_000, // 30 seconds
        contradiction_tolerance_ns: 5_000_000,
    };
    let mut estimator = ClockOffsetSkewEstimator::new(config);

    // Collect 8 periodic synchronization samples
    for seq in 1..=8 {
        let sample = TimeSyncSample::new(seq, ref_clock.now(), sensor_clock.now(), 1_000)?;
        estimator.add_sample(sample)?;

        ref_clock.advance(100_000_000)?; // 100 ms step
        sensor_clock.advance(100_000_000)?;
    }

    let estimate = estimator.fit()?;

    // Verify fitted offset is close to initial 25 ms (+25_000_000 ns)
    assert!(estimate.offset_ns >= 24_900_000 && estimate.offset_ns <= 25_100_000);

    // Verify fitted skew is close to injected +2000 ppm
    assert!(estimate.skew_ppm >= 1_950 && estimate.skew_ppm <= 2_050);

    // Verify residual is tightly bounded
    assert!(estimate.residual.max_residual_ns < 10_000);

    // Validate a newly observed sample during the synchronized session
    let valid_next_sample = TimeSyncSample::new(9, ref_clock.now(), sensor_clock.now(), 1_000)?;
    estimate.validate_sample(&valid_next_sample, 100_000)?;

    // Extrapolate and verify sensor interval bounds the actual ground truth
    let query_ref = ref_clock.now();
    let actual_sensor = sensor_clock.now();
    let predicted_interval = estimate.predict_sensor_interval(query_ref)?;

    assert!(predicted_interval.earliest.0 <= actual_sensor.0);
    assert!(predicted_interval.latest.0 >= actual_sensor.0);

    Ok(())
}
