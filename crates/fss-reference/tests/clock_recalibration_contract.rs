#![forbid(unsafe_code)]
//! Invalidation cannot be bypassed by refitting accepted pre-fault samples or rolling history.

use std::error::Error;

use fss_core::TimestampNs;
use fss_reference::{
    ClockOffsetSkewEstimator, ClockSyncEstimate, EstimatorConfig, EstimatorState, ReferenceError,
    TimeSyncSample,
};

type TestResult = Result<(), Box<dyn Error>>;

fn sample(sequence: u64, reference: i128, sensor: i128) -> Result<TimeSyncSample, ReferenceError> {
    TimeSyncSample::new(sequence, TimestampNs(reference), TimestampNs(sensor), 5)
}

fn calibrated(
    horizon: u64,
) -> Result<(ClockOffsetSkewEstimator, ClockSyncEstimate), ReferenceError> {
    let mut estimator = ClockOffsetSkewEstimator::new(EstimatorConfig {
        min_samples: 3,
        max_residual_tolerance_ns: 10,
        max_outlier_basis_points: 0,
        validity_horizon_ns: horizon,
        contradiction_tolerance_ns: 100,
    })?;
    for (sequence, reference) in [(1, 10_000), (2, 20_000), (3, 30_000)] {
        estimator.add_sample(sample(sequence, reference, reference + 1_000)?)?;
    }
    let estimate = estimator.fit()?;
    Ok((estimator, estimate))
}

#[test]
fn contradicted_epoch_cannot_refit_old_samples_or_admit_more() -> TestResult {
    let (mut estimator, original) = calibrated(100_000)?;
    let witness = sample(4, 40_000, 90_000)?;
    assert!(matches!(
        estimator.add_sample(witness.clone()),
        Err(ReferenceError::ContradictedEstimate { .. })
    ));
    assert_eq!(estimator.invalidation_sample(), Some(&witness));
    let state = estimator.state().clone();
    let samples = estimator.samples().to_vec();
    for _ in 0..3 {
        assert!(matches!(
            estimator.fit(),
            Err(ReferenceError::ClockRecalibrationRequired {
                invalidated_at: TimestampNs(40_000)
            })
        ));
        // Even an observation matching the OLD model cannot clear the known contradiction.
        assert!(matches!(
            estimator.add_sample(sample(5, 50_000, 51_000)?),
            Err(ReferenceError::ClockRecalibrationRequired { .. })
        ));
        assert_eq!(estimator.state(), &state);
        assert_eq!(estimator.samples(), samples.as_slice());
        assert!(estimator.active_estimate().is_none());
    }
    assert_eq!(original.sample_evidence, samples);
    Ok(())
}

#[test]
fn rollback_never_extends_an_already_expired_horizon() -> TestResult {
    let (mut estimator, original) = calibrated(5)?;
    estimator.invalidate(sample(4, 40_000, 90_000)?, "owner observed clock reset");
    let restored = estimator
        .rollback()?
        .ok_or("expected historical interval")?;
    assert_eq!(restored.validity, original.validity);
    assert_eq!(restored.evidence_root, original.evidence_root);
    assert_eq!(restored.generation, original.generation);
    assert!(estimator.requires_recalibration());
    assert!(matches!(
        restored.predict_sensor_interval(TimestampNs(30_006)),
        Err(ReferenceError::StaleEstimatePastValidity { .. })
    ));
    assert!(matches!(
        estimator.fit(),
        Err(ReferenceError::ClockRecalibrationRequired { .. })
    ));
    Ok(())
}

#[test]
fn invalidation_before_all_valid_history_never_manufactures_a_singleton() -> TestResult {
    for boundary in [i128::MIN, -1, 9_999, 10_000] {
        let (mut estimator, _) = calibrated(100_000)?;
        let witness = sample(4, boundary, 0)?;
        estimator.invalidate(witness.clone(), "earlier invalidity discovered");
        assert!(estimator.rollback()?.is_none());
        assert!(estimator.rollback()?.is_none());
        assert_eq!(estimator.state(), &EstimatorState::Uncalibrated);
        assert!(estimator.active_estimate().is_none());
        assert_eq!(estimator.invalidation_sample(), Some(&witness));
        assert!(matches!(
            estimator.fit(),
            Err(ReferenceError::ClockRecalibrationRequired { .. })
        ));
    }
    Ok(())
}

#[test]
fn every_historical_generation_remains_clamped_through_repeated_rollback() -> TestResult {
    let (mut estimator, first) = calibrated(100_000)?;
    estimator.add_sample(sample(4, 40_000, 41_000)?)?;
    let second = estimator.fit()?;
    estimator.add_sample(sample(5, 50_000, 51_000)?)?;
    let third = estimator.fit()?;
    let witness = sample(6, 60_000, 100_000)?;
    assert!(matches!(
        estimator.add_sample(witness.clone()),
        Err(ReferenceError::ContradictedEstimate { .. })
    ));
    for original in [third, second, first] {
        let restored = estimator.rollback()?.ok_or("missing historical estimate")?;
        assert_eq!(restored.generation, original.generation);
        assert_eq!(restored.evidence_root, original.evidence_root);
        assert_eq!(restored.validity.latest, TimestampNs(59_999));
        assert!(estimator.requires_recalibration());
        assert_eq!(estimator.invalidation_sample(), Some(&witness));
        assert!(matches!(
            estimator.fit(),
            Err(ReferenceError::ClockRecalibrationRequired { .. })
        ));
    }
    assert!(estimator.rollback()?.is_none());
    assert!(matches!(
        estimator.fit(),
        Err(ReferenceError::ClockRecalibrationRequired { .. })
    ));
    Ok(())
}

#[test]
fn fresh_sensor_reset_requires_new_samples_and_preserves_the_old_epoch() -> TestResult {
    let (mut old, original) = calibrated(100_000)?;
    let witness = sample(4, 40_000, 90_000)?;
    assert!(matches!(
        old.add_sample(witness.clone()),
        Err(ReferenceError::ContradictedEstimate { .. })
    ));
    let old_state = old.state().clone();
    let first = sample(5, 50_000, 100)?; // sensor restarted below every old sensor timestamp
    let mut fresh = old.recalibrate_from(first.clone())?;
    assert!(!fresh.requires_recalibration());
    assert!(fresh.invalidation_sample().is_none());
    assert!(fresh.active_estimate().is_none());
    assert_eq!(fresh.state(), &EstimatorState::Uncalibrated);
    assert_eq!(fresh.samples(), &[first]);
    assert!(matches!(
        fresh.fit(),
        Err(ReferenceError::InsufficientSyncSamples {
            count: 1,
            minimum_required: 3
        })
    ));
    assert!(fresh.rollback()?.is_none()); // no old rollback history crosses into recovery
    fresh.add_sample(sample(6, 60_000, 10_100)?)?;
    assert!(matches!(
        fresh.fit(),
        Err(ReferenceError::InsufficientSyncSamples {
            count: 2,
            minimum_required: 3
        })
    ));
    fresh.add_sample(sample(7, 70_000, 20_100)?)?;
    let recovered = fresh.fit()?;
    assert_eq!(recovered.generation, original.generation + 1);
    assert_eq!(recovered.offset_ns, -49_900);
    assert_eq!(recovered.skew_ppm, 0);
    assert_eq!(recovered.validity.earliest, TimestampNs(50_000));
    assert_eq!(recovered.sample_evidence.as_slice(), fresh.samples());
    assert_ne!(recovered.evidence_root, original.evidence_root);
    assert_eq!(old.state(), &old_state);
    assert_eq!(old.samples(), original.sample_evidence.as_slice());
    assert_eq!(old.invalidation_sample(), Some(&witness));
    assert!(old.active_estimate().is_none());
    let recovered_time = recovered.predict_reference_interval(TimestampNs(10_100))?;
    assert_eq!(recovered_time.earliest, TimestampNs(59_995));
    assert_eq!(recovered_time.latest, TimestampNs(60_005));
    Ok(())
}

#[test]
fn repeated_invalidations_keep_earliest_history_and_latest_admission_boundaries() -> TestResult {
    let (mut estimator, _) = calibrated(100_000)?;
    estimator.invalidate(sample(100, 80_000, 0)?, "later reset");
    let earliest = sample(200, 35_000, 0)?;
    estimator.invalidate(
        earliest.clone(),
        "earlier fault found with a newer observation sequence",
    );
    assert_eq!(estimator.invalidation_sample(), Some(&earliest));
    let restored = estimator
        .rollback()?
        .ok_or("expected historical interval")?;
    assert_eq!(restored.validity.latest, TimestampNs(34_999));
    assert!(matches!(
        estimator.recalibrate_from(sample(200, 90_000, 1)?),
        Err(ReferenceError::NonMonotonicSyncSequence {
            previous: 200,
            current: 200
        })
    ));
    assert!(matches!(
        estimator.recalibrate_from(sample(201, 80_000, 1)?),
        Err(ReferenceError::NonMonotonicSyncSamples {
            previous: TimestampNs(80_000),
            ..
        })
    ));
    let next = estimator.recalibrate_from(sample(201, 90_000, 1)?)?;
    assert_eq!(next.samples().len(), 1);
    assert_eq!(estimator.invalidation_sample(), Some(&earliest));
    assert!(estimator.requires_recalibration());
    Ok(())
}

#[test]
fn fresh_sampling_rejects_stale_sequence_or_reference_without_mutation() -> TestResult {
    let (mut estimator, _) = calibrated(100_000)?;
    estimator.invalidate(sample(4, 40_000, 90_000)?, "reset");
    let before = format!("{estimator:?}");
    for (sequence, reference) in [(0, 50_000), (4, 50_000), (5, 40_000), (5, 30_000)] {
        assert!(
            estimator
                .recalibrate_from(sample(sequence, reference, 0)?)
                .is_err()
        );
        assert_eq!(format!("{estimator:?}"), before);
    }
    // Accepted pre-fault samples also bound admission after an earlier discovered fault.
    estimator.invalidate(sample(2, 9_000, 0)?, "earlier fault");
    assert!(estimator.recalibrate_from(sample(5, 20_000, 0)?).is_err());
    Ok(())
}

#[test]
fn fresh_nonadvancing_sensor_clock_invalidates_but_stale_observations_do_not() -> TestResult {
    for sensor in [0, 31_000] {
        let (mut estimator, original) = calibrated(100_000)?;
        assert!(matches!(
            estimator.add_sample(sample(3, 40_000, sensor)?),
            Err(ReferenceError::NonMonotonicSyncSequence { .. })
        ));
        assert!(matches!(
            estimator.add_sample(sample(4, 30_000, sensor)?),
            Err(ReferenceError::NonMonotonicSyncSamples { .. })
        ));
        assert!(!estimator.requires_recalibration());
        assert_eq!(estimator.active_estimate(), Some(&original));
        let witness = sample(4, 40_000, sensor)?;
        assert!(matches!(
            estimator.add_sample(witness.clone()),
            Err(ReferenceError::NonMonotonicSyncSamples { .. })
        ));
        assert!(estimator.requires_recalibration());
        assert!(estimator.active_estimate().is_none());
        assert_eq!(estimator.invalidation_sample(), Some(&witness));
        assert_eq!(estimator.samples(), original.sample_evidence.as_slice());
        assert!(matches!(
            estimator.fit(),
            Err(ReferenceError::ClockRecalibrationRequired { .. })
        ));
    }
    Ok(())
}

#[test]
fn recovery_generation_uses_the_issued_high_water_mark_not_the_rollback_target() -> TestResult {
    let (mut old, first) = calibrated(100_000)?;
    old.add_sample(sample(4, 40_000, 41_000)?)?;
    let second = old.fit()?;
    assert_eq!(old.rollback()?, Some(first));
    assert!(!old.requires_recalibration());
    let mut fresh = old.recalibrate_from(sample(5, 50_000, 0)?)?;
    fresh.add_sample(sample(6, 60_000, 10_000)?)?;
    fresh.add_sample(sample(7, 70_000, 20_000)?)?;
    let recovered = fresh.fit()?;
    assert_eq!(recovered.generation, second.generation + 1);
    assert_eq!(old.samples().len(), 4);
    Ok(())
}

#[test]
fn healthy_rollback_does_not_require_recalibration_and_cold_invalidation_is_a_noop() -> TestResult {
    let (mut estimator, first) = calibrated(100_000)?;
    estimator.add_sample(sample(4, 40_000, 41_000)?)?;
    let second = estimator.fit()?;
    assert_eq!(estimator.rollback()?, Some(first));
    assert!(!estimator.requires_recalibration());
    estimator.add_sample(sample(5, 50_000, 51_000)?)?;
    assert_eq!(estimator.fit()?.generation, second.generation + 1);
    let mut cold = ClockOffsetSkewEstimator::new(EstimatorConfig::default())?;
    cold.invalidate(sample(1, 0, 0)?, "no calibration to invalidate");
    assert!(!cold.requires_recalibration());
    assert!(cold.invalidation_sample().is_none());
    assert!(matches!(
        cold.recalibrate_from(sample(0, 0, 0)?),
        Err(ReferenceError::NonMonotonicSyncSequence {
            previous: 0,
            current: 0
        })
    ));
    Ok(())
}

#[test]
fn recalibration_refusal_has_a_typed_boundary_and_actionable_display() {
    let error = ReferenceError::ClockRecalibrationRequired {
        invalidated_at: TimestampNs(40_000),
    };
    let display = error.to_string();
    assert!(display.contains("40000ns"));
    assert!(display.contains("fresh-sample recalibration"));
    assert!(error.source().is_none());
}
