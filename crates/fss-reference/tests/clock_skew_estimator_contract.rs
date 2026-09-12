#![forbid(unsafe_code)]
//! Integration contract tests for deterministic clock offset/skew estimator interface (FSS-088).

use std::error::Error;

use fss_core::TimestampNs;
use fss_reference::{
    ClockOffsetSkewEstimator, ClockSyncEstimate, EstimatorConfig, EstimatorState, ReferenceError,
    SyncFitResidual, TimeSyncSample, VirtualClock,
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
    let mut estimator = ClockOffsetSkewEstimator::new(config)?;

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
    let mut estimator = ClockOffsetSkewEstimator::new(EstimatorConfig::default())?;
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
    let mut estimator = ClockOffsetSkewEstimator::new(EstimatorConfig::default())?;
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
    let mut estimator = ClockOffsetSkewEstimator::new(config)?;

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
    let mut estimator = ClockOffsetSkewEstimator::new(config)?;

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
    let mut estimator = ClockOffsetSkewEstimator::new(config)?;

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

    // Rollback restores the prior valid estimate with validity clamped before contradiction
    let Some(restored) = estimator.rollback()? else {
        return Err("prior estimate must be restored".into());
    };
    assert_eq!(restored.offset_ns, initial_estimate.offset_ns);
    assert_eq!(restored.skew_ppm, initial_estimate.skew_ppm);
    assert_eq!(
        restored.validity.earliest,
        initial_estimate.validity.earliest
    );
    assert_eq!(restored.validity.latest, TimestampNs(39_999_999));
    assert!(restored.validity.latest <= contradictory_sample.reference_time);
    assert_eq!(*estimator.state(), EstimatorState::Synchronized(restored));

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
        let mut estimator = ClockOffsetSkewEstimator::new(config)?;

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
    let mut estimator = ClockOffsetSkewEstimator::new(EstimatorConfig::default())?;
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
    let mut estimator = ClockOffsetSkewEstimator::new(config)?;

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

#[test]
fn fault_empty_evidence_rejected_in_predictions() -> Result<(), Box<dyn Error>> {
    let estimate = ClockSyncEstimate {
        reference_anchor: TimestampNs(1_000_000),
        offset_ns: 50_000,
        skew_ppm: 0,
        residual: SyncFitResidual {
            max_residual_ns: 0,
            mean_squared_error_ns2: 0,
            offset_variance_ns2: 0,
            skew_variance_ppm2: 0,
            sample_count: 0,
        },
        validity: fss_core::CaptureInterval::new(TimestampNs(1_000_000), TimestampNs(2_000_000))?,
        sample_evidence: Vec::new(),
        evidence_root: fss_core::ContentDigest::sha256(b"empty"),
        generation: 1,
    };

    let query = TimestampNs(1_500_000);
    match estimate.predict_sensor_interval(query) {
        Err(ReferenceError::InsufficientSyncSamples {
            count,
            minimum_required,
        }) => {
            assert_eq!(count, 0);
            assert_eq!(minimum_required, 1);
        }
        other => return Err(format!("expected InsufficientSyncSamples, got {other:?}").into()),
    }

    match estimate.predict_reference_interval(query) {
        Err(ReferenceError::InsufficientSyncSamples {
            count,
            minimum_required,
        }) => {
            assert_eq!(count, 0);
            assert_eq!(minimum_required, 1);
        }
        other => return Err(format!("expected InsufficientSyncSamples, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn fault_contradicting_sample_not_retained_in_samples() -> Result<(), Box<dyn Error>> {
    let config = EstimatorConfig {
        min_samples: 3,
        contradiction_tolerance_ns: 10_000,
        ..EstimatorConfig::default()
    };
    let mut estimator = ClockOffsetSkewEstimator::new(config)?;

    estimator.add_sample(create_nominal_sample(1, 10_000_000, 11_000_000)?)?;
    estimator.add_sample(create_nominal_sample(2, 20_000_000, 21_000_000)?)?;
    estimator.add_sample(create_nominal_sample(3, 30_000_000, 31_000_000)?)?;
    let _ = estimator.fit()?;

    let bad_sample = create_nominal_sample(4, 40_000_000, 61_000_000)?;
    let res = estimator.add_sample(bad_sample);
    assert!(matches!(
        res,
        Err(ReferenceError::ContradictedEstimate { .. })
    ));

    assert_eq!(estimator.samples().len(), 3);
    Ok(())
}

#[test]
fn fault_non_monotonic_sequence_rejected_with_typed_error() -> Result<(), Box<dyn Error>> {
    let mut estimator = ClockOffsetSkewEstimator::new(EstimatorConfig::default())?;
    estimator.add_sample(create_nominal_sample(5, 10_000_000, 11_000_000)?)?;

    match estimator.add_sample(create_nominal_sample(5, 20_000_000, 21_000_000)?) {
        Err(ReferenceError::NonMonotonicSyncSequence { previous, current }) => {
            assert_eq!(previous, 5);
            assert_eq!(current, 5);
        }
        other => return Err(format!("expected NonMonotonicSyncSequence, got {other:?}").into()),
    }

    match estimator.add_sample(create_nominal_sample(3, 20_000_000, 21_000_000)?) {
        Err(ReferenceError::NonMonotonicSyncSequence { previous, current }) => {
            assert_eq!(previous, 5);
            assert_eq!(current, 3);
        }
        other => return Err(format!("expected NonMonotonicSyncSequence, got {other:?}").into()),
    }

    assert_eq!(estimator.samples().len(), 1);
    Ok(())
}

#[test]
fn outliers_trimmed_from_final_linear_fit() -> Result<(), Box<dyn Error>> {
    let config = EstimatorConfig {
        min_samples: 3,
        max_residual_tolerance_ns: 2_000,
        max_outlier_basis_points: 3_000, // allow up to 30% outliers
        ..EstimatorConfig::default()
    };
    let mut estimator = ClockOffsetSkewEstimator::new(config)?;

    // 4 samples: 3 follow exact offset=1_000_000, skew=0; 1 is an outlier (+50us)
    estimator.add_sample(create_nominal_sample(1, 10_000_000, 11_000_000)?)?;
    estimator.add_sample(create_nominal_sample(2, 20_000_000, 21_050_000)?)?; // outlier
    estimator.add_sample(create_nominal_sample(3, 30_000_000, 31_000_000)?)?;
    estimator.add_sample(create_nominal_sample(4, 40_000_000, 41_000_000)?)?;

    let estimate = estimator.fit()?;

    // With outlier trimmed, fitted model is pure offset=1_000_000, skew=0
    assert_eq!(estimate.offset_ns, 1_000_000);
    assert_eq!(estimate.skew_ppm, 0);
    assert_eq!(estimate.residual.sample_count, 3);
    assert_eq!(estimate.residual.max_residual_ns, 0);
    assert_eq!(estimate.sample_evidence.len(), 3);

    Ok(())
}

#[test]
fn realistic_day_long_fit_reports_exact_variance_without_overflow() -> Result<(), Box<dyn Error>> {
    // 100 samples spanning ~23.8 h (99 steps of 864 s), ~1 ms offset, +/-100 us residuals.
    // sum_xx ~ 2.45e29 ns^2 and mse ~ 1e10 ns^2, so `mse * sum_xx` ~ 2.45e39 > u128::MAX.
    const SAMPLES: u64 = 100;
    const STEP_NS: i128 = 864_000_000_000;
    const OFFSET_NS: i128 = 1_000_000;
    const NOISE_NS: i128 = 100_000;
    const BASE_NS: i128 = 1_000_000_000;

    let mut estimator = ClockOffsetSkewEstimator::new(EstimatorConfig::default())?;
    for k in 0..SAMPLES {
        let ref_ns = BASE_NS + i128::from(k) * STEP_NS;
        let noise = if k % 2 == 0 { NOISE_NS } else { -NOISE_NS };
        estimator.add_sample(create_nominal_sample(
            k + 1,
            ref_ns,
            ref_ns + OFFSET_NS + noise,
        )?)?;
    }

    let estimate = estimator.fit()?;
    let residual = &estimate.residual;
    assert_eq!(residual.sample_count, 100);
    // The alternating noise has leverage 50 * NOISE_NS * mean(k) / sum((k - mean k)^2)
    // = 50 * 100_000 * 49.5 / 83_325 ~ 2_970 ns on the intercept; the fitted slope
    // (~ -7e-5 ppm) truncates to 0 ppm. Values below come from an independent
    // arbitrary-precision integer model of the same OLS fit.
    assert_eq!(estimate.offset_ns, 1_002_970);
    assert_eq!(estimate.skew_ppm, 0);
    assert_eq!(residual.max_residual_ns, 102_970);
    assert_eq!(residual.mean_squared_error_ns2, 10_008_820_900);

    // For x_k = k * STEP_NS (k = 0..100) the OLS offset variance is
    // mse * sum(k^2) / (n * sum(k^2) - (sum k)^2) = mse * 328_350 / 8_332_500 exactly,
    // because STEP_NS^2 cancels from numerator and denominator.
    let mse = u128::from(residual.mean_squared_error_ns2);
    let sum_xx = u128::try_from(STEP_NS * STEP_NS)? * 328_350;
    assert!(mse.checked_mul(sum_xx).is_none());
    let expected_offset_variance = u64::try_from(mse * 328_350 / 8_332_500)?;
    assert_eq!(residual.offset_variance_ns2, expected_offset_variance);
    assert_eq!(residual.offset_variance_ns2, 394_407_001);

    // Skew variance: mse * n * 1e12 / (STEP_NS^2 * 8_332_500).
    let step_sq = u128::try_from(STEP_NS * STEP_NS)?;
    let expected_skew_variance =
        u64::try_from(mse * 100 * 1_000_000_000_000 / (step_sq * 8_332_500))?;
    assert_eq!(residual.skew_variance_ppm2, expected_skew_variance);
    Ok(())
}

#[test]
fn large_tolerance_mean_squared_error_saturates_conservatively() -> Result<(), Box<dyn Error>> {
    // Residuals of ~3.3 s and ~6.7 s are inside a 10 s tolerance but their mean square
    // (~2.22e19 ns^2) exceeds u64::MAX (~1.84e19); a truncating cast would wrap it.
    let config = EstimatorConfig {
        min_samples: 3,
        max_residual_tolerance_ns: 10_000_000_000,
        ..EstimatorConfig::default()
    };
    let mut estimator = ClockOffsetSkewEstimator::new(config)?;
    let base: i128 = 1_000_000_000;
    estimator.add_sample(create_nominal_sample(1, base, base)?)?;
    estimator.add_sample(create_nominal_sample(
        2,
        base + 20_000_000_000,
        base + 30_000_000_000,
    )?)?;
    estimator.add_sample(create_nominal_sample(
        3,
        base + 40_000_000_000,
        base + 40_000_000_000,
    )?)?;

    let estimate = estimator.fit()?;
    assert_eq!(estimate.offset_ns, 3_333_333_333);
    assert_eq!(estimate.skew_ppm, 0);
    let residual = &estimate.residual;
    assert_eq!(residual.sample_count, 3);
    assert_eq!(residual.max_residual_ns, 6_666_666_667);

    // Exact mean square exceeds u64::MAX: reported as the maximum (least confident) value.
    let r_small: u128 = 3_333_333_333;
    let r_large: u128 = 6_666_666_667;
    let sum_sq = 2 * r_small * r_small + r_large * r_large;
    let exact_mse = sum_sq / 3;
    assert!(exact_mse > u128::from(u64::MAX));
    assert_eq!(residual.mean_squared_error_ns2, u64::MAX);

    // Offset variance exact value (~1.85e19) also exceeds u64::MAX: saturated.
    // sum_xx = 2e21 and denominator = 3 * 2e21 - (6e10)^2 = 2.4e21, so sum_xx / denominator
    // is exactly 5/6 (the direct `exact_mse * sum_xx` product itself overflows u128).
    let denominator: u128 = 2_400_000_000_000_000_000_000;
    assert!(exact_mse * 5 / 6 > u128::from(u64::MAX));
    assert_eq!(residual.offset_variance_ns2, u64::MAX);

    // Skew variance fits in u64 and is computed from the exact (unsaturated) mean square.
    let expected_skew_variance = u64::try_from(exact_mse * 3 * 1_000_000_000_000 / denominator)?;
    assert_eq!(residual.skew_variance_ppm2, expected_skew_variance);
    Ok(())
}

#[test]
fn estimator_config_min_samples_boundary_validated_at_construction() -> Result<(), Box<dyn Error>> {
    // Below the documented minimum of 2: rejected at construction, so `fit()` can never index
    // an empty sample set (min_samples 0 previously panicked with index out of bounds).
    for below in [0_usize, 1] {
        let config = EstimatorConfig {
            min_samples: below,
            ..EstimatorConfig::default()
        };
        match config.validate() {
            Err(ReferenceError::InvalidEstimatorConfig {
                parameter, value, ..
            }) => {
                assert_eq!(parameter, "min_samples");
                assert_eq!(value, u64::try_from(below)?);
            }
            other => return Err(format!("expected InvalidEstimatorConfig, got {other:?}").into()),
        }
        match ClockOffsetSkewEstimator::new(config) {
            Err(ReferenceError::InvalidEstimatorConfig {
                parameter, value, ..
            }) => {
                assert_eq!(parameter, "min_samples");
                assert_eq!(value, u64::try_from(below)?);
            }
            other => return Err(format!("expected InvalidEstimatorConfig, got {other:?}").into()),
        }
    }

    // Exactly 2: accepted; an empty fit is a typed error and a two-sample fit succeeds.
    let config = EstimatorConfig {
        min_samples: 2,
        ..EstimatorConfig::default()
    };
    config.validate()?;
    let mut estimator = ClockOffsetSkewEstimator::new(config)?;
    match estimator.fit() {
        Err(ReferenceError::InsufficientSyncSamples {
            count,
            minimum_required,
        }) => {
            assert_eq!(count, 0);
            assert_eq!(minimum_required, 2);
        }
        other => return Err(format!("expected InsufficientSyncSamples, got {other:?}").into()),
    }
    estimator.add_sample(create_nominal_sample(1, 10_000_000, 11_000_000)?)?;
    estimator.add_sample(create_nominal_sample(2, 20_000_000, 21_000_000)?)?;
    let estimate = estimator.fit()?;
    assert_eq!(estimate.offset_ns, 1_000_000);
    assert_eq!(estimate.skew_ppm, 0);
    assert_eq!(estimate.residual.sample_count, 2);
    Ok(())
}

#[test]
fn estimator_config_outlier_basis_points_boundary_validated_at_construction()
-> Result<(), Box<dyn Error>> {
    // Exactly 10_000 (100%): accepted.
    let config = EstimatorConfig {
        max_outlier_basis_points: 10_000,
        ..EstimatorConfig::default()
    };
    config.validate()?;
    let mut estimator = ClockOffsetSkewEstimator::new(config)?;
    estimator.add_sample(create_nominal_sample(1, 10_000_000, 11_000_000)?)?;
    estimator.add_sample(create_nominal_sample(2, 20_000_000, 21_000_000)?)?;
    estimator.add_sample(create_nominal_sample(3, 30_000_000, 31_000_000)?)?;
    assert_eq!(estimator.fit()?.offset_ns, 1_000_000);

    // 10_001 and above: rejected with a typed error.
    for above in [10_001_u16, u16::MAX] {
        let config = EstimatorConfig {
            max_outlier_basis_points: above,
            ..EstimatorConfig::default()
        };
        match config.validate() {
            Err(ReferenceError::InvalidEstimatorConfig {
                parameter, value, ..
            }) => {
                assert_eq!(parameter, "max_outlier_basis_points");
                assert_eq!(value, u64::from(above));
            }
            other => return Err(format!("expected InvalidEstimatorConfig, got {other:?}").into()),
        }
        match ClockOffsetSkewEstimator::new(config) {
            Err(ReferenceError::InvalidEstimatorConfig {
                parameter, value, ..
            }) => {
                assert_eq!(parameter, "max_outlier_basis_points");
                assert_eq!(value, u64::from(above));
            }
            other => return Err(format!("expected InvalidEstimatorConfig, got {other:?}").into()),
        }
    }

    EstimatorConfig::default().validate()?;
    Ok(())
}
