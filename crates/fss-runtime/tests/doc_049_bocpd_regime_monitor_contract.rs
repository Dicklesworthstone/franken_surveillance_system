#![forbid(unsafe_code)]
//! Contract & fault suite for `DOC-049` (`fss-x4a.5.49`): bounded deterministic scalar BOCPD
//! regime monitor strictly scoped to clamped advisory workload and sensor adaptation.

use std::error::Error;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    Generation, TimestampNs,
};
use fss_runtime::bocpd_regime::{
    AdvisoryClampBounds, AdvisoryParameters, BocpdAdvisoryDisposition, BocpdAdvisoryReceipt,
    BocpdConfig, BocpdError, BocpdPrior, BocpdRegimeMonitor, MAX_BOCPD_RUN_LENGTH,
    ObservationCause, RegimeObservation, ShadowEvalOutcome,
};

type TestResult = Result<(), Box<dyn Error>>;

fn default_config() -> BocpdConfig {
    BocpdConfig {
        monitor_id: "monitor:camera-queue-regime-v1".to_owned(),
        initial_generation: Generation(1),
        prior: BocpdPrior {
            mu0: 50.0,
            kappa0: 0.1,
            alpha0: 1.5,
            beta0: 50.0,
        },
        hazard_ppm: 20_000, // 2% per-tick hazard
        max_run_length: 32,
        short_run_window: 4,
        trigger_threshold_bps: 3_500,
        hysteresis_min_steps: 2,
        cooldown_ns: 10_000,
        hypothesis_ttl_ns: 5_000,
        min_coverage_bps: 8_000,
        clamp_bounds: AdvisoryClampBounds::default(),
        baseline_params: AdvisoryParameters::default(),
    }
}

fn obs(ts: i128, value: f64, cause: ObservationCause) -> RegimeObservation {
    RegimeObservation {
        timestamp_ns: TimestampNs(ts),
        value,
        coverage_bps: 10_000,
        source_digest: ContentDigest::sha256(&ts.to_be_bytes()),
        privacy_minimized: true,
        cause,
    }
}

#[test]
fn doc_049_scalar_bocpd_detects_regime_shift_enforces_shadow_eval_activation_and_rollback()
-> TestResult {
    let cfg = default_config();
    let mut m1 = BocpdRegimeMonitor::new(cfg.clone())?;
    let mut m2 = BocpdRegimeMonitor::new(cfg)?;

    // Feed 25 steady observations around mean=10.0 -> run length grows and remains bounded.
    let mut last_steady = None;
    for i in 0..25_i128 {
        let val = 10.0 + ((i % 3) as f64 - 1.0) * 0.25;
        let o = obs(1_000 + i * 100, val, ObservationCause::Nominal);
        let h1 = m1.observe(&o, || false)?;
        let h2 = m2.observe(&o, || false)?;
        assert_eq!(h1, h2, "scalar BOCPD must be bit-deterministic across runs");
        assert!(!h1.is_event_evidence);
        assert!(m1.state_len() <= 33);
        last_steady = Some(h1);
    }
    let steady = last_steady.ok_or("missing steady hypothesis")?;
    assert!(
        steady.map_run_length >= 10,
        "steady regime should accumulate run length, got {}",
        steady.map_run_length
    );

    // Sharp regime shift from ~10.0 to ~65.0 across 3 consecutive ticks triggers BOCPD + hysteresis!
    let mut shifted_hyp = None;
    for j in 0..3_i128 {
        let o = obs(
            4_000 + j * 100,
            65.0 + (j as f64) * 0.2,
            ObservationCause::Nominal,
        );
        let h = m1.observe(&o, || false)?;
        assert!(!h.is_event_evidence);
        shifted_hyp = Some(h);
    }
    let hyp = shifted_hyp.ok_or("missing shifted hypothesis")?;
    assert!(
        hyp.change_point_prob_bps >= 3_500,
        "regime shift must raise short-run posterior, got {} bps",
        hyp.change_point_prob_bps
    );
    assert!(hyp.consecutive_triggers >= 2);
    assert!(hyp.map_run_length <= 3);

    // 1. Stage clamped proposal -> active generation stays Generation(1) until shadow eval passes!
    let next_params = AdvisoryParameters {
        inspection_depth: 4,
        batch_size: 8,
        candidate_count: 16,
        path_allocation_bps: 7_000,
        weakens_invariants: false,
    };
    let staged = m1.stage_advisory_proposal(&hyp, next_params, TimestampNs(4_300), || false)?;
    assert_eq!(m1.active_generation(), Generation(1));
    assert_eq!(staged.prior_generation, Generation(1));
    assert_eq!(staged.candidate_generation, Generation(2));

    // 2. Shadow evaluation FAILS (harmful proposal) -> rolls back & logs negative evidence!
    let rollback = m1.finalize_shadow_evaluation(
        ShadowEvalOutcome::Harmful {
            shadow_evidence_digest: ContentDigest::sha256(b"shadow:regression-latency-spike"),
            reason: "p99_latency_regressed".to_owned(),
        },
        TimestampNs(4_500),
        || false,
    )?;
    assert_eq!(
        rollback.disposition,
        BocpdAdvisoryDisposition::RolledBackNegativeEvidence
    );
    assert_eq!(rollback.active_generation, Generation(1));
    assert_eq!(m1.active_generation(), Generation(1));
    assert_eq!(m1.active_params(), AdvisoryParameters::default());
    assert_eq!(m1.negative_evidence().len(), 1);
    assert!(!rollback.grants_effect_authority);
    assert!(rollback.verify_digest());

    // Cooldown prevents immediate thrashing after rollback!
    assert_eq!(
        m1.stage_advisory_proposal(&hyp, next_params, TimestampNs(4_600), || false),
        Err(BocpdError::CooldownActive)
    );

    // During cooldown, the 65.0 regime settles across 15 steady ticks; then a second sharp shift
    // to 120.0 after cooldown passes shadow eval -> root-last activates Gen 2!
    for i in 0..15_i128 {
        let _ = m1.observe(
            &obs(
                5_000 + i * 700,
                65.0 + ((i % 3) as f64 - 1.0) * 0.25,
                ObservationCause::Nominal,
            ),
            || false,
        )?;
    }
    let mut hyp2 = None;
    for j in 0..3_i128 {
        let o = obs(16_000 + j * 100, 120.0, ObservationCause::Nominal);
        hyp2 = Some(m1.observe(&o, || false)?);
    }
    let hyp2 = hyp2.ok_or("missing second shift hypothesis")?;
    let _staged2 = m1.stage_advisory_proposal(&hyp2, next_params, TimestampNs(16_300), || false)?;
    let activated = m1.finalize_shadow_evaluation(
        ShadowEvalOutcome::Passed {
            shadow_evidence_digest: ContentDigest::sha256(b"shadow:pass-bounded-gain"),
        },
        TimestampNs(16_500),
        || false,
    )?;
    assert_eq!(
        activated.disposition,
        BocpdAdvisoryDisposition::ActivatedRootLast
    );
    assert_eq!(activated.prior_generation, Generation(1));
    assert_eq!(activated.active_generation, Generation(2));
    assert_eq!(m1.active_generation(), Generation(2));
    assert_eq!(m1.active_params(), next_params);
    assert_eq!(
        m1.prior_generation(),
        Some((Generation(1), AdvisoryParameters::default()))
    );

    // Canonical binary round-trip + tamper refusal (grants_effect_authority=true rejected!).
    let mut enc = CanonicalEncoder::new();
    activated.encode_canonical(&mut enc);
    let encoded = enc.finish();
    let decoded = BocpdAdvisoryReceipt::decode_canonical(&mut CanonicalDecoder::new(&encoded))?;
    assert_eq!(decoded, activated);

    let mut forged = activated;
    forged.grants_effect_authority = true;
    forged.receipt_digest = forged.computed_digest();
    let mut bad_enc = CanonicalEncoder::new();
    forged.encode_canonical(&mut bad_enc);
    assert!(
        BocpdAdvisoryReceipt::decode_canonical(&mut CanonicalDecoder::new(&bad_enc.finish()))
            .is_err()
    );

    println!(
        "CAPLOG {{\"step\":\"doc_049_bocpd_regime\",\"active_gen\":{},\"negative_evidence\":{},\"state_len\":{},\"verdict\":\"ok\"}}",
        m1.active_generation().0,
        m1.negative_evidence().len(),
        m1.state_len()
    );
    Ok(())
}

#[test]
fn doc_049_refuses_unmasked_nonfinite_weakening_clamps_operational_causes_and_expiry() -> TestResult
{
    let mut monitor = BocpdRegimeMonitor::new(default_config())?;

    // 1. Privacy transformation MUST precede monitoring!
    let mut unmasked = obs(1_000, 10.0, ObservationCause::Nominal);
    unmasked.privacy_minimized = false;
    assert_eq!(
        monitor.observe(&unmasked, || false),
        Err(BocpdError::PrivacyTransformRequired)
    );

    // 2. Non-finite observations (NaN / Inf) refused fail-closed.
    assert_eq!(
        monitor.observe(&obs(1_000, f64::NAN, ObservationCause::Nominal), || false),
        Err(BocpdError::InvalidObservation(
            "non_finite_or_invalid_coverage"
        ))
    );
    assert_eq!(
        monitor.observe(
            &obs(1_000, f64::INFINITY, ObservationCause::Nominal),
            || false
        ),
        Err(BocpdError::InvalidObservation(
            "non_finite_or_invalid_coverage"
        ))
    );

    // 3. Operational causes (ClockGap / SensorReconnect / ConfigChange) reset cleanly with 0 CP!
    let _ = monitor.observe(&obs(1_000, 10.0, ObservationCause::Nominal), || false)?;
    let _ = monitor.observe(&obs(1_100, 10.1, ObservationCause::Nominal), || false)?;
    let gap_hyp = monitor.observe(&obs(2_000, 999.0, ObservationCause::ClockGap), || false)?;
    assert!(gap_hyp.reset_by_operational_cause);
    assert_eq!(gap_hyp.change_point_prob_bps, 0);
    assert_eq!(monitor.state_len(), 1);
    assert!(!gap_hyp.is_event_evidence);

    // 4. Low coverage preserves baseline and refuses proposals.
    let mut low_cov = obs(2_100, 999.0, ObservationCause::Nominal);
    low_cov.coverage_bps = 2_000;
    let low_hyp = monitor.observe(&low_cov, || false)?;
    assert!(!low_hyp.sufficient_coverage);
    assert_eq!(
        monitor.stage_advisory_proposal(
            &low_hyp,
            AdvisoryParameters::default(),
            TimestampNs(2_150),
            || false
        ),
        Err(BocpdError::StaleOrUncoveredHypothesis)
    );

    // 5. Hard clamp violations & invariant-weakening attempts fail closed even with a hot shift.
    for i in 0..10_i128 {
        let _ = monitor.observe(
            &obs(3_000 + i * 100, 10.0, ObservationCause::Nominal),
            || false,
        )?;
    }
    let mut hot = None;
    for j in 0..3_i128 {
        hot = Some(monitor.observe(
            &obs(4_500 + j * 100, 80.0, ObservationCause::Nominal),
            || false,
        )?);
    }
    let hot = hot.ok_or("missing hot hypothesis")?;
    assert_eq!(
        monitor.stage_advisory_proposal(
            &hot,
            AdvisoryParameters {
                weakens_invariants: true,
                ..AdvisoryParameters::default()
            },
            TimestampNs(4_800),
            || false
        ),
        Err(BocpdError::ClampViolation(
            "advisory_cannot_weaken_invariants"
        ))
    );
    assert_eq!(
        monitor.stage_advisory_proposal(
            &hot,
            AdvisoryParameters {
                batch_size: 999, // exceeds max_batch_size=32
                ..AdvisoryParameters::default()
            },
            TimestampNs(4_800),
            || false
        ),
        Err(BocpdError::ClampViolation("outside_hard_clamp_bounds"))
    );

    // 6. Expired hypothesis refused!
    assert_eq!(
        monitor.stage_advisory_proposal(
            &hot,
            AdvisoryParameters::default(),
            TimestampNs(hot.expires_at_ns.0 + 1),
            || false
        ),
        Err(BocpdError::StaleOrUncoveredHypothesis)
    );

    // 7. Cooperative cancellation & oversized max_run_length refused cleanly.
    assert_eq!(
        monitor.observe(&obs(5_000, 10.0, ObservationCause::Nominal), || true),
        Err(BocpdError::Cancelled)
    );
    let mut bad_cfg = default_config();
    bad_cfg.max_run_length = MAX_BOCPD_RUN_LENGTH + 1;
    assert_eq!(
        BocpdRegimeMonitor::new(bad_cfg).err(),
        Some(BocpdError::InvalidConfiguration("invalid_bocpd_config"))
    );
    Ok(())
}
