#![forbid(unsafe_code)]
//! Contract, hysteresis, source-custody protection, alert-corroboration preservation, canonical
//! round-trip, tamper refusal, clock-regression, stale-generation, and cancellation tests for
//! `FSS-121` (`fss-x4a.12.20`: registered media pressure degradation ladder).

use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, Generation, TimestampNs,
};
use fss_tensor::buffer_accounting::BufferPressureTier;
use fss_tensor::media_pressure::{
    MediaDegradationRung, MediaPressureController, MediaPressureDecisionReceipt,
    MediaPressureError, MediaPressurePolicy, MediaPressureSignals,
};

type TestResult = Result<(), Box<dyn Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn nominal_signals(gen_num: u64, ts_ns: i128) -> MediaPressureSignals {
    MediaPressureSignals {
        buffer_pressure: BufferPressureTier::Normal,
        queue_depth_bps: 1_000,
        decode_drop_rate_bps: 0,
        thermal_throttled: false,
        disk_pressure_bps: 2_000,
        active_alert_corroboration: false,
        generation: Generation(gen_num),
        observed_at_ns: TimestampNs(ts_ns),
    }
}

#[test]
fn fss_121_ordered_escalation_hysteresis_recovery_and_source_custody_protection() -> TestResult {
    let policy = MediaPressurePolicy {
        min_recovery_hold_ns: 1_000,
        ..MediaPressurePolicy::bounded_default("pipe:cam-front")
    };
    let mut ctrl = MediaPressureController::new(policy, Generation(1))?;
    assert_eq!(ctrl.current_rung(), MediaDegradationRung::Rung0Nominal);

    // 1. Nominal signals -> Rung 0, source custody protected, no gap witness required.
    let r0 = ctrl.evaluate(nominal_signals(1, 100), || false)?;
    assert_eq!(r0.effective_rung, MediaDegradationRung::Rung0Nominal);
    assert!(r0.source_custody_protected);
    assert!(!r0.coverage_gap_witness_required);

    // 2. Elevated buffer pressure -> Rung 1 (shed non-essential renditions, keep preview & analytics).
    let mut s1 = nominal_signals(1, 200);
    s1.buffer_pressure = BufferPressureTier::Elevated;
    let r1 = ctrl.evaluate(s1, || false)?;
    assert_eq!(
        r1.effective_rung,
        MediaDegradationRung::Rung1ShedNonEssentialRenditions
    );
    assert_eq!(r1.preview_stride, 1);
    assert_eq!(r1.analytics_stride, 1);
    assert!(r1.source_custody_protected);

    // 3. Critical buffer pressure + active alert corroboration -> Rung 3, corroboration protected!
    let mut s3 = nominal_signals(1, 300);
    s3.buffer_pressure = BufferPressureTier::Critical;
    s3.active_alert_corroboration = true;
    let r3 = ctrl.evaluate(s3, || false)?;
    assert_eq!(
        r3.effective_rung,
        MediaDegradationRung::Rung3ReduceAnalyticsCadence
    );
    assert_eq!(r3.preview_stride, 2);
    assert_eq!(r3.analytics_stride, 4);
    assert!(r3.alert_corroboration_protected);
    assert!(r3.source_custody_protected);

    // 4. Buffer exhausted -> Rung 4 (pause derived cognition, emit explicit coverage witness,
    //    still protect 100% of raw source custody recording!).
    let mut s4 = nominal_signals(1, 400);
    s4.buffer_pressure = BufferPressureTier::Exhausted;
    let r4 = ctrl.evaluate(s4, || false)?;
    assert_eq!(
        r4.effective_rung,
        MediaDegradationRung::Rung4PauseDerivedCognition
    );
    assert_eq!(r4.preview_stride, 0);
    assert_eq!(r4.analytics_stride, 0);
    assert!(r4.source_custody_protected);
    assert!(r4.coverage_gap_witness_required);

    // 5. Disk >= 95% -> Rung 5 emergency source backpressure with mandatory gap witness.
    let mut s5 = nominal_signals(1, 500);
    s5.disk_pressure_bps = 9_600;
    let r5 = ctrl.evaluate(s5, || false)?;
    assert_eq!(
        r5.effective_rung,
        MediaDegradationRung::Rung5EmergencySourceBackpressure
    );
    assert!(!r5.source_custody_protected);
    assert!(r5.coverage_gap_witness_required);

    // 6. Immediate recovery attempt before hysteresis hold (500 + 500 < 1000) MUST hold at Rung 5.
    let held = ctrl.evaluate(nominal_signals(1, 1_000), || false)?;
    assert_eq!(
        held.effective_rung,
        MediaDegradationRung::Rung5EmergencySourceBackpressure
    );
    assert!(held.recovery_held_by_hysteresis);

    // 7. After hold window (>= 1000ns), recovery steps down by EXACTLY ONE rung per hold window!
    let step1 = ctrl.evaluate(nominal_signals(1, 1_500), || false)?;
    assert_eq!(
        step1.effective_rung,
        MediaDegradationRung::Rung4PauseDerivedCognition
    );
    assert!(!step1.recovery_held_by_hysteresis);

    // Canonical binary round-trip + forged-contradiction tamper refusal.
    assert!(step1.verify_digest());
    let mut enc = CanonicalEncoder::new();
    step1.encode_canonical(&mut enc);
    let raw = enc.finish();
    let decoded = MediaPressureDecisionReceipt::decode_canonical(&mut CanonicalDecoder::new(&raw))?;
    assert_eq!(decoded, step1);

    // Even with recomputed digest, lying that Rung5 has source_custody_protected=true fails decode!
    let mut forged = r5.clone();
    forged.source_custody_protected = true;
    forged.receipt_digest = forged.computed_digest();
    let mut bad_enc = CanonicalEncoder::new();
    forged.encode_canonical(&mut bad_enc);
    assert!(
        MediaPressureDecisionReceipt::decode_canonical(&mut CanonicalDecoder::new(
            &bad_enc.finish()
        ))
        .is_err()
    );

    emit_caplog(
        "fss_121_ladder_escalation_and_hysteresis",
        "ordered_shedding_source_custody_protection_step_down_hysteresis_and_tamper_refusal",
        "ordered_shedding_source_custody_protection_step_down_hysteresis_and_tamper_refusal",
        "pass",
    );
    Ok(())
}

#[test]
fn fss_121_faults_clock_regression_stale_generation_and_cancellation_fail_closed() -> TestResult {
    assert_eq!(
        MediaPressureController::new(
            MediaPressurePolicy {
                queue_rung1_bps: 8_000,
                queue_rung2_bps: 7_000,
                ..MediaPressurePolicy::bounded_default("pipe:bad")
            },
            Generation(1),
        )
        .unwrap_err(),
        MediaPressureError::InvalidPolicy
    );

    let mut ctrl = MediaPressureController::new(
        MediaPressurePolicy::bounded_default("pipe:cam-a"),
        Generation(2),
    )?;
    ctrl.evaluate(nominal_signals(2, 1_000), || false)?;

    // Clock regression fails closed without mutating rung or seq.
    assert_eq!(
        ctrl.evaluate(nominal_signals(2, 999), || false)
            .unwrap_err(),
        MediaPressureError::ClockRegression {
            previous_ns: 1_000,
            observed_ns: 999,
        }
    );

    // Stale/mismatched generation fails closed.
    assert_eq!(
        ctrl.evaluate(nominal_signals(1, 2_000), || false)
            .unwrap_err(),
        MediaPressureError::StaleGeneration {
            expected: Generation(2),
            actual: Generation(1),
        }
    );

    // Out-of-range bps fails closed.
    let mut bad_bps = nominal_signals(2, 2_000);
    bad_bps.queue_depth_bps = 10_001;
    assert_eq!(
        ctrl.evaluate(bad_bps, || false).unwrap_err(),
        MediaPressureError::InvalidSignals("bps_exceeds_10000")
    );

    // Cooperative cancellation at both checkpoints leaves state completely unchanged.
    for cancel_at in [0_usize, 1] {
        let seen = AtomicUsize::new(0);
        let mut high = nominal_signals(2, 3_000);
        high.disk_pressure_bps = 9_900;
        let res = ctrl.evaluate(high, || seen.fetch_add(1, Ordering::Relaxed) >= cancel_at);
        assert_eq!(res.unwrap_err(), MediaPressureError::Cancelled);
        assert_eq!(ctrl.current_rung(), MediaDegradationRung::Rung0Nominal);
    }

    emit_caplog(
        "fss_121_faults_and_cancellation",
        "invalid_policy_clock_regression_stale_generation_and_cancellation_fail_closed",
        "invalid_policy_clock_regression_stale_generation_and_cancellation_fail_closed",
        "pass",
    );
    Ok(())
}
