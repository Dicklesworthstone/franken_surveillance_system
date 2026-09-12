#![forbid(unsafe_code)]
//! Contract test suite for operation-specific maximum tolerable time uncertainty budgets (fss-x4a.17.7 / TIME-OPERATION-TOLERANCE-001).
//!
//! Verifies:
//! - Every registered time-sensitive operation declares its tolerance, exceedance consequence, and required clock evidence
//! - Exact boundary conditions: bound, bound+1, and zero uncertainty
//! - Fail-closed typed errors (`ERR-CLOCK-UNCERTAIN-001`) with no silent pass-through or score downgrades
//! - Explicit handling of `Unknown` and `Unsynchronised` clock states
//! - Same interval accepted for loose operation and rejected for strict operation
//! - Conservative interval composition across all 9 latency/jitter sources
//! - `FORMAL-010` monotonicity: widening interval never creates stronger claims
//! - Cross-camera association with local RTP and vendor-relay profiles
//! - Strict enforcement and custom budget registration

use std::error::Error;

use fss_core::{CaptureInterval, ClockBasis, TimestampNs};
use fss_reference::{
    ClockSyncState, ERR_CLOCK_UNCERTAIN_001, ExceedanceConsequence, OperationTimeTolerance,
    RequiredClockEvidence, SourceTimeEvidence, SourceTimeEvidenceBuilder, SourceTimeEvidenceParams,
    TimeSensitiveOperation, TimeToleranceError, TimeUncertaintyBudget, UncertaintySources,
    evaluate_cross_camera_association,
};

/// Helper: constructs a clean synchronised clock state.
fn sync_clock(generation: u64, residual_ns: u64) -> ClockSyncState {
    ClockSyncState::Synchronised {
        basis: ClockBasis::HostMonotonic,
        residual_uncertainty_ns: residual_ns,
        clock_generation: generation,
    }
}

/// Helper: constructs source evidence with explicit uncertainty bounds around receive time.
fn sample_evidence(
    seq: u64,
    host_time_ns: i128,
    half_width_ns: u64,
    sync_state: ClockSyncState,
) -> Result<SourceTimeEvidence, Box<dyn Error>> {
    let host_ts = TimestampNs(host_time_ns);
    let earliest = host_ts.checked_sub_ns(i128::from(half_width_ns))?;
    let latest = host_ts.checked_add_ns(i128::from(half_width_ns))?;
    let interval = CaptureInterval::new(earliest, latest)?;

    Ok(SourceTimeEvidence::new(SourceTimeEvidenceParams {
        sequence: seq,
        has_discontinuity: false,
        device_timestamp: None,
        device_clock_basis: None,
        host_receive_time: host_ts,
        sync_state,
        uncertainty_sources: UncertaintySources::zero(),
        plausible_capture_interval: interval,
    })?)
}

/// Helper: constructs source evidence on a specific clock basis.
fn sample_evidence_with_basis(
    seq: u64,
    host_time_ns: i128,
    half_width_ns: u64,
    basis: ClockBasis,
) -> Result<SourceTimeEvidence, Box<dyn Error>> {
    let host_ts = TimestampNs(host_time_ns);
    let earliest = host_ts.checked_sub_ns(i128::from(half_width_ns))?;
    let latest = host_ts.checked_add_ns(i128::from(half_width_ns))?;
    let interval = CaptureInterval::new(earliest, latest)?;

    Ok(SourceTimeEvidence::new(SourceTimeEvidenceParams {
        sequence: seq,
        has_discontinuity: false,
        device_timestamp: None,
        device_clock_basis: Some(basis),
        host_receive_time: host_ts,
        sync_state: ClockSyncState::Synchronised {
            basis,
            residual_uncertainty_ns: 0,
            clock_generation: 1,
        },
        uncertainty_sources: UncertaintySources::zero(),
        plausible_capture_interval: interval,
    })?)
}

// ---------------------------------------------------------------------------
// 1. Registered Operations & Catalog Completeness
// ---------------------------------------------------------------------------

#[test]
fn test_all_registered_operations_name_tolerance_consequence_and_clock_evidence()
-> Result<(), Box<dyn Error>> {
    let budget = TimeUncertaintyBudget::default();

    let all_ops = [
        TimeSensitiveOperation::CrossCameraIdentityAssociation,
        TimeSensitiveOperation::GeometryDependentNegativeEvidence,
        TimeSensitiveOperation::TransitFeasibilityCheck,
        TimeSensitiveOperation::CoverageContinuityWitness,
        TimeSensitiveOperation::StereoTriangulation,
        TimeSensitiveOperation::IncidentReconstruction,
        TimeSensitiveOperation::MultiSensorFusion,
    ];

    for op in all_ops {
        let tolerance = budget.tolerance_for(op)?;
        assert_eq!(tolerance.operation, op);
        assert!(
            tolerance.max_tolerable_uncertainty_ns > 0,
            "operation {} must have positive max tolerable uncertainty",
            op.operation_id()
        );
        assert!(!op.operation_id().is_empty());
        assert_eq!(tolerance.consequence, op.default_consequence());
        assert_eq!(
            tolerance.required_clock_evidence,
            op.default_required_clock()
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 2. Exact Boundary Tests: bound, bound+1, and zero
// ---------------------------------------------------------------------------

#[test]
fn test_exact_bound_uncertainty_accepted() -> Result<(), Box<dyn Error>> {
    let budget = TimeUncertaintyBudget::default();
    let op = TimeSensitiveOperation::StereoTriangulation; // tolerance 20 ms = 20,000,000 ns, FailClosed
    let limit = op.default_max_uncertainty_ns();

    // Half-width = limit / 2 -> total uncertainty = limit
    let half_width = limit / 2;
    let evidence = sample_evidence(1, 1_000_000_000, half_width, sync_clock(1, 0))?;

    assert_eq!(evidence.uncertainty_ns(), u128::from(limit));

    let outcome = budget.enforce(op, &evidence)?;
    assert!(
        outcome.is_accepted(),
        "uncertainty at exact bound must be accepted, got: {outcome:?}"
    );

    Ok(())
}

#[test]
fn test_bound_plus_one_uncertainty_fails_closed_with_typed_error() -> Result<(), Box<dyn Error>> {
    let budget = TimeUncertaintyBudget::default();
    let op = TimeSensitiveOperation::StereoTriangulation; // 20,000,000 ns, FailClosed
    let limit = op.default_max_uncertainty_ns();

    // Construct evidence with uncertainty = limit + 1
    let host_ts = TimestampNs(1_000_000_000);
    let earliest = host_ts;
    let latest = host_ts.checked_add_ns(i128::from(limit) + 1)?;
    let interval = CaptureInterval::new(earliest, latest)?;
    let evidence = SourceTimeEvidence::new(SourceTimeEvidenceParams {
        sequence: 2,
        has_discontinuity: false,
        device_timestamp: None,
        device_clock_basis: None,
        host_receive_time: host_ts,
        sync_state: sync_clock(1, 0),
        uncertainty_sources: UncertaintySources::zero(),
        plausible_capture_interval: interval,
    })?;

    assert_eq!(evidence.uncertainty_ns(), u128::from(limit) + 1);

    let res = budget.enforce(op, &evidence);
    let Err(err) = res else {
        return Err("enforce must fail closed at bound + 1".into());
    };

    match err {
        TimeToleranceError::ClockUncertaintyExceeded {
            error_code,
            operation,
            observed_uncertainty_ns,
            max_tolerable_uncertainty_ns,
        } => {
            assert_eq!(error_code, ERR_CLOCK_UNCERTAIN_001);
            assert_eq!(operation, op);
            assert_eq!(observed_uncertainty_ns, u128::from(limit) + 1);
            assert_eq!(max_tolerable_uncertainty_ns, limit);
        }
        other => return Err(format!("expected ClockUncertaintyExceeded, got: {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_zero_uncertainty_accepted() -> Result<(), Box<dyn Error>> {
    let budget = TimeUncertaintyBudget::default();
    let op = TimeSensitiveOperation::StereoTriangulation;

    let host_ts = TimestampNs(1_000_000_000);
    let interval = CaptureInterval::new(host_ts, host_ts)?;
    let evidence = SourceTimeEvidence::new(SourceTimeEvidenceParams {
        sequence: 3,
        has_discontinuity: false,
        device_timestamp: None,
        device_clock_basis: None,
        host_receive_time: host_ts,
        sync_state: sync_clock(1, 0),
        uncertainty_sources: UncertaintySources::zero(),
        plausible_capture_interval: interval,
    })?;

    assert_eq!(evidence.uncertainty_ns(), 0);

    let outcome = budget.enforce(op, &evidence)?;
    assert!(
        outcome.is_accepted(),
        "zero uncertainty must be accepted, got: {outcome:?}"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// 3. Unknown and Unsynchronised Clock States Fail Closed
// ---------------------------------------------------------------------------

#[test]
fn test_unknown_clock_state_fails_closed_with_typed_error() -> Result<(), Box<dyn Error>> {
    let budget = TimeUncertaintyBudget::default();
    let op = TimeSensitiveOperation::CoverageContinuityWitness; // requires CertifiedSynchronised

    let unknown_state = ClockSyncState::Unknown {
        reason: "PTP daemon offline, reference clock unavailable".to_string(),
    };

    let evidence = sample_evidence(10, 1_000_000_000, 1_000_000, unknown_state)?;

    let res = budget.enforce(op, &evidence);
    let Err(err) = res else {
        return Err("unknown clock state must fail closed for operations requiring sync".into());
    };

    match err {
        TimeToleranceError::ClockStateUnknown { operation, reason } => {
            assert_eq!(operation, op);
            assert!(reason.contains("PTP daemon offline"));
        }
        other => return Err(format!("expected ClockStateUnknown, got: {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_unsynchronised_clock_state_fails_when_certified_clock_required()
-> Result<(), Box<dyn Error>> {
    let budget = TimeUncertaintyBudget::default();
    let op = TimeSensitiveOperation::CoverageContinuityWitness; // requires CertifiedSynchronised and fails closed

    let unsync_state = ClockSyncState::Unsynchronised {
        basis: ClockBasis::HostMonotonic,
        drift_bound_ns: 20_000_000,
    };

    let evidence = sample_evidence(11, 1_000_000_000, 10_000_000, unsync_state)?;

    let res = budget.enforce(op, &evidence);
    let Err(err) = res else {
        return Err(
            "unsynchronised clock must fail closed when certified clock is required".into(),
        );
    };

    match err {
        TimeToleranceError::ClockUnsynchronised {
            operation,
            basis,
            drift_bound_ns,
        } => {
            assert_eq!(operation, op);
            assert_eq!(basis, ClockBasis::HostMonotonic);
            assert_eq!(drift_bound_ns, 20_000_000);
        }
        other => return Err(format!("expected ClockUnsynchronised, got: {other:?}").into()),
    }

    // Also verify that an operation with Abstain consequence explicitly abstains
    let op_abstain = TimeSensitiveOperation::GeometryDependentNegativeEvidence;
    let outcome_abstain = budget.enforce(op_abstain, &evidence)?;
    assert!(
        outcome_abstain.is_abstained(),
        "unsynchronised clock must cause Abstain for GeometryDependentNegativeEvidence"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// 4. Differential Tolerance: Same Interval Accepted Loose, Rejected Strict
// ---------------------------------------------------------------------------

#[test]
fn test_differential_tolerance_same_interval_accepted_loose_rejected_strict()
-> Result<(), Box<dyn Error>> {
    let budget = TimeUncertaintyBudget::default();

    // 40 ms uncertainty (40,000,000 ns)
    // Stricter: StereoTriangulation has 20 ms tolerance -> MUST FAIL
    // Looser: CrossCameraIdentityAssociation has 50 ms tolerance -> MUST PASS
    // Loosest: MultiSensorFusion has 500 ms tolerance -> MUST PASS
    let evidence = sample_evidence(20, 1_000_000_000, 20_000_000, sync_clock(1, 100))?;
    assert_eq!(evidence.uncertainty_ns(), 40_000_000);

    let res_strict = budget.enforce(TimeSensitiveOperation::StereoTriangulation, &evidence);
    assert!(
        res_strict.is_err(),
        "40 ms must be rejected by 20 ms strict stereo triangulation"
    );

    let outcome_cross = budget.enforce(
        TimeSensitiveOperation::CrossCameraIdentityAssociation,
        &evidence,
    )?;
    assert!(
        outcome_cross.is_accepted(),
        "40 ms must be accepted by 50 ms cross-camera association"
    );

    let outcome_fusion = budget.enforce(TimeSensitiveOperation::MultiSensorFusion, &evidence)?;
    assert!(
        outcome_fusion.is_accepted(),
        "40 ms must be accepted by 500 ms multi-sensor fusion"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// 5. Conservative Interval Composition Across All Latency/Jitter Sources
// ---------------------------------------------------------------------------

#[test]
fn test_conservative_interval_composition_builder() -> Result<(), Box<dyn Error>> {
    let host_ts = TimestampNs(2_000_000_000);

    let mut sources = UncertaintySources::zero();
    sources.exposure_ns = 5_000_000; // 5 ms
    sources.rolling_shutter_ns = 2_000_000; // 2 ms
    sources.encoding_ns = 8_000_000; // 8 ms
    sources.buffering_ns = 15_000_000; // 15 ms
    sources.network_ns = 10_000_000; // 10 ms
    sources.vendor_relay_ns = 20_000_000; // 20 ms
    sources.decode_reorder_ns = 12_000_000; // 12 ms
    sources.clock_quantization_ns = 1_000_000; // 1 ms
    sources.offset_drift_ns = 3_000_000; // 3 ms

    let total_expected_jitter = sources.total_uncertainty_ns()?;
    assert_eq!(
        total_expected_jitter,
        (5_000_000
            + 2_000_000
            + 8_000_000
            + 15_000_000
            + 10_000_000
            + 20_000_000
            + 12_000_000
            + 1_000_000
            + 3_000_000) as u128
    );

    let evidence = SourceTimeEvidenceBuilder::new(30, host_ts)
        .uncertainty_sources(sources)
        .sync_state(sync_clock(2, 500))
        .build()?;

    // Interval must conservatively envelop the receive time shifted backward by total latency
    assert!(
        evidence.uncertainty_ns() >= total_expected_jitter,
        "interval uncertainty ({}) must conservatively cover total jitter ({})",
        evidence.uncertainty_ns(),
        total_expected_jitter
    );

    assert!(
        evidence.plausible_capture_interval.earliest <= host_ts,
        "earliest plausible capture must precede host receive time"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// 6. FORMAL-010: Interval Monotonicity & Abstention
// ---------------------------------------------------------------------------

#[test]
fn test_formal_010_monotonicity_widening_never_narrows() -> Result<(), Box<dyn Error>> {
    let host_ts = TimestampNs(1_000_000_000);
    let base_evidence = SourceTimeEvidenceBuilder::new(40, host_ts)
        .sync_state(sync_clock(1, 100))
        .build()?;

    let base_uncertainty = base_evidence.uncertainty_ns();

    // Legitimate widening by additional jitter
    let widened = base_evidence.widen_uncertainty(60_000_000)?;
    assert!(
        widened.uncertainty_ns() > base_uncertainty,
        "widen_uncertainty must strictly widen the interval"
    );

    // Over-widened evidence (60 ms > 50 ms tolerance) transitions to Abstained, never false certainty
    let budget = TimeUncertaintyBudget::default();
    let outcome = budget.enforce(
        TimeSensitiveOperation::CrossCameraIdentityAssociation,
        &widened,
    )?;
    assert!(
        !outcome.is_accepted(),
        "over-widened evidence must not be accepted"
    );
    assert!(
        outcome.is_abstained(),
        "CrossCameraIdentityAssociation must abstain on exceedance, got: {outcome:?}"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// 7. Cross-Camera Temporal Association E2E Scenarios
// ---------------------------------------------------------------------------

#[test]
fn test_cross_camera_association_consistent_and_physically_impossible() -> Result<(), Box<dyn Error>>
{
    let budget = TimeUncertaintyBudget::default();

    // Camera A detection at t = 1,000,000,000 ns (tight local RTP profile, +/- 1 ms)
    let obs_a = sample_evidence(100, 1_000_000_000, 1_000_000, sync_clock(1, 50))?;

    // Physical transit between Camera A and B: min 5.0 s (5,000,000,000 ns), max 10.0 s (10,000,000,000 ns)
    let min_transit = 5_000_000_000;
    let max_transit = 10_000_000_000;

    // Case 1: Camera B observes target at t = 7,000,000,000 ns (within feasible arrival window [6.0s, 11.0s])
    let obs_b_consistent = sample_evidence(200, 7_000_000_000, 1_000_000, sync_clock(1, 50))?;
    let decision_consistent = evaluate_cross_camera_association(
        &budget,
        &obs_a,
        &obs_b_consistent,
        min_transit,
        max_transit,
    )?;
    assert!(
        decision_consistent.is_consistent(),
        "detection at 7s transit must be temporally consistent: {decision_consistent:?}"
    );

    // Case 2: Camera B observes target at t = 2,000,000,000 ns (only 1s elapsed, impossible for min 5s transit)
    let obs_b_impossible = sample_evidence(201, 2_000_000_000, 1_000_000, sync_clock(1, 50))?;
    let decision_impossible = evaluate_cross_camera_association(
        &budget,
        &obs_a,
        &obs_b_impossible,
        min_transit,
        max_transit,
    )?;
    assert!(
        decision_impossible.is_physically_impossible(),
        "detection at 1s transit must be physically impossible: {decision_impossible:?}"
    );

    Ok(())
}

#[test]
fn test_cross_camera_association_vendor_relay_jitter_triggers_abstention()
-> Result<(), Box<dyn Error>> {
    let budget = TimeUncertaintyBudget::default();

    // Camera A has vendor cloud relay profile with large jitter (> 50 ms)
    let mut sources_a = UncertaintySources::vendor_cloud_relay_profile();
    sources_a.vendor_relay_ns = 80_000_000; // 80 ms cloud jitter

    let obs_a = SourceTimeEvidenceBuilder::new(300, TimestampNs(1_000_000_000))
        .uncertainty_sources(sources_a)
        .sync_state(sync_clock(1, 500))
        .build()?;

    let obs_b = sample_evidence(301, 7_000_000_000, 1_000_000, sync_clock(1, 50))?;

    let decision =
        evaluate_cross_camera_association(&budget, &obs_a, &obs_b, 5_000_000_000, 10_000_000_000)?;

    assert!(
        decision.is_abstained(),
        "exceeding 50 ms cross-camera tolerance must abstain, got: {decision:?}"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// 8. Strict Enforcement & Error Representation
// ---------------------------------------------------------------------------

#[test]
fn test_enforce_strict_fails_closed_on_abstain_or_degrade() -> Result<(), Box<dyn Error>> {
    let budget = TimeUncertaintyBudget::default();
    let op = TimeSensitiveOperation::CrossCameraIdentityAssociation; // default consequence is Abstain (tolerance 50 ms)

    // Uncertainty = 70 ms > tolerance 50 ms
    let evidence = sample_evidence(400, 1_000_000_000, 35_000_000, sync_clock(1, 100))?;

    // Normal enforce returns Ok(Abstained)
    let normal_outcome = budget.enforce(op, &evidence)?;
    assert!(normal_outcome.is_abstained());

    // Strict enforce must return Err(ClockUncertaintyExceeded)
    let res_strict = budget.enforce_strict(op, &evidence);
    let Err(err) = res_strict else {
        return Err(
            "enforce_strict must fail closed even when operation default is Abstain".into(),
        );
    };

    assert_eq!(err.error_code(), ERR_CLOCK_UNCERTAIN_001);
    assert!(format!("{err}").contains(ERR_CLOCK_UNCERTAIN_001));

    Ok(())
}

// ---------------------------------------------------------------------------
// 9. Custom Budget Registration & Inverted Intervals
// ---------------------------------------------------------------------------

#[test]
fn test_custom_budget_registration_and_override() -> Result<(), Box<dyn Error>> {
    let mut custom_budget = TimeUncertaintyBudget::empty();

    // Register a tightened tolerance for incident reconstruction: 20 ms instead of 250 ms, FailClosed
    let tightened = OperationTimeTolerance::new(
        TimeSensitiveOperation::IncidentReconstruction,
        20_000_000,
        ExceedanceConsequence::FailClosed,
        RequiredClockEvidence::CertifiedSynchronised,
    );
    custom_budget.register(tightened);

    // 40 ms evidence
    let evidence = sample_evidence(500, 1_000_000_000, 20_000_000, sync_clock(1, 100))?;

    let res = custom_budget.enforce(TimeSensitiveOperation::IncidentReconstruction, &evidence);
    let Err(err) = res else {
        return Err("tightened custom tolerance must fail closed at 40 ms".into());
    };

    assert_eq!(err.error_code(), ERR_CLOCK_UNCERTAIN_001);

    // Unregistered operation in empty budget returns UnregisteredOperation
    let res_unreg = custom_budget.enforce(TimeSensitiveOperation::StereoTriangulation, &evidence);
    let Err(err_unreg) = res_unreg else {
        return Err("unregistered operation must return error".into());
    };
    assert!(matches!(
        err_unreg,
        TimeToleranceError::UnregisteredOperation(TimeSensitiveOperation::StereoTriangulation)
    ));

    Ok(())
}

#[test]
fn test_inverted_transit_interval_rejected() -> Result<(), Box<dyn Error>> {
    let budget = TimeUncertaintyBudget::default();
    let obs_a = sample_evidence(600, 1_000_000_000, 1_000_000, sync_clock(1, 50))?;
    let obs_b = sample_evidence(601, 7_000_000_000, 1_000_000, sync_clock(1, 50))?;

    // Inverted transit: min (10s) > max (5s)
    let res =
        evaluate_cross_camera_association(&budget, &obs_a, &obs_b, 10_000_000_000, 5_000_000_000);
    let Err(err) = res else {
        return Err("inverted transit interval must return error".into());
    };

    assert!(matches!(err, TimeToleranceError::InvertedInterval { .. }));

    Ok(())
}

// ---------------------------------------------------------------------------
// 10. Review-627 Findings Test Coverage (F1 - F9)
// ---------------------------------------------------------------------------

// Finding 1 (CRITICAL): Degraded Observations Cannot Produce Consistent Association
#[test]
fn test_degraded_observation_cannot_produce_consistent_association() -> Result<(), Box<dyn Error>> {
    let mut budget = TimeUncertaintyBudget::empty();
    budget.register(OperationTimeTolerance::new(
        TimeSensitiveOperation::CrossCameraIdentityAssociation,
        20_000_000, // 20 ms
        ExceedanceConsequence::Degrade,
        RequiredClockEvidence::CertifiedSynchronised,
    ));
    // Obs A uncertainty = 80 ms > 20 ms (Degraded)
    let obs_a = sample_evidence(1, 1_000_000_000, 40_000_000, sync_clock(1, 0))?;
    let obs_b = sample_evidence(2, 7_000_000_000, 1_000_000, sync_clock(1, 0))?;

    let decision =
        evaluate_cross_camera_association(&budget, &obs_a, &obs_b, 5_000_000_000, 10_000_000_000)?;
    assert!(
        !decision.is_consistent(),
        "degraded camera A observation must not yield Consistent association, got {decision:?}"
    );
    assert!(
        decision.is_abstained(),
        "degraded observation must result in Abstained association decision"
    );
    Ok(())
}

// Finding 2 (CRITICAL): Cross-Camera Association Rejects Clock Basis Mismatch
#[test]
fn test_cross_camera_association_rejects_clock_basis_mismatch() -> Result<(), Box<dyn Error>> {
    let budget = TimeUncertaintyBudget::default();
    let obs_a = sample_evidence_with_basis(1, 1_000_000_000, 1_000_000, ClockBasis::HostMonotonic)?;
    let obs_b =
        sample_evidence_with_basis(2, 7_000_000_000, 1_000_000, ClockBasis::UtcDisciplined)?;

    let res =
        evaluate_cross_camera_association(&budget, &obs_a, &obs_b, 5_000_000_000, 10_000_000_000);
    assert!(
        matches!(res, Err(TimeToleranceError::ClockBasisMismatch { .. })),
        "expected ClockBasisMismatch error when associating across different clock bases, got {res:?}"
    );
    Ok(())
}

// Finding 3 (HIGH): SourceTimeEvidenceParams Rejects Interval Narrower Than Clock Drift
#[test]
fn test_params_rejects_interval_narrower_than_clock_drift() -> Result<(), Box<dyn Error>> {
    let host_ts = TimestampNs(1_000_000_000);
    let latest = host_ts.checked_add_ns(1_000)?; // 1 µs width
    let interval = CaptureInterval::new(host_ts, latest)?;
    let params = SourceTimeEvidenceParams {
        sequence: 1,
        has_discontinuity: false,
        device_timestamp: None,
        device_clock_basis: None,
        host_receive_time: host_ts,
        sync_state: ClockSyncState::Unsynchronised {
            basis: ClockBasis::HostMonotonic,
            drift_bound_ns: 50_000_000, // 50 ms drift
        },
        uncertainty_sources: UncertaintySources::zero(),
        plausible_capture_interval: interval,
    };
    let res = SourceTimeEvidence::new(params);
    assert!(
        matches!(
            res,
            Err(TimeToleranceError::NonMonotoneNarrowingAttempted { .. })
        ),
        "expected NonMonotoneNarrowingAttempted when interval is narrower than clock drift, got {res:?}"
    );
    Ok(())
}

// Finding 4 (HIGH): Boundary Point Contact Yields Indeterminate, Not Consistent
#[test]
fn test_boundary_point_contact_yields_indeterminate_not_consistent() -> Result<(), Box<dyn Error>> {
    let budget = TimeUncertaintyBudget::default();
    // Exactly touches at boundary: transit is [5s, 10s], obs_a at 1s -> arrival is [6s, 11s]
    // obs_b at exactly 6s with 0 uncertainty touches arrival at single point 6.0s
    let obs_a = sample_evidence(1, 1_000_000_000, 0, sync_clock(1, 0))?;
    let obs_b = sample_evidence(2, 6_000_000_000, 0, sync_clock(1, 0))?;
    let decision =
        evaluate_cross_camera_association(&budget, &obs_a, &obs_b, 5_000_000_000, 10_000_000_000)?;
    assert!(
        decision.is_indeterminate(),
        "exact boundary contact must yield Indeterminate, not Consistent, got {decision:?}"
    );
    Ok(())
}

// Finding 5 (HIGH): Host Receive Anchor Cannot Place Latest Capture In Future
#[test]
fn test_host_receive_anchor_cannot_place_latest_capture_in_future() -> Result<(), Box<dyn Error>> {
    let host_ts = TimestampNs(1_000_000_000);
    let sources = UncertaintySources::vendor_cloud_relay_profile();
    let evidence = SourceTimeEvidenceBuilder::new(1, host_ts)
        .uncertainty_sources(sources)
        .build()?;
    assert!(
        evidence.plausible_capture_interval.latest <= host_ts,
        "physical capture cannot occur after host receive time (latest: {}, host_ts: {})",
        evidence.plausible_capture_interval.latest,
        host_ts
    );
    Ok(())
}

// Finding 6 (HIGH): widen_uncertainty Fails Closed On Source Overflow
#[test]
fn test_widen_uncertainty_fails_on_source_overflow() -> Result<(), Box<dyn Error>> {
    let host_ts = TimestampNs(1_000_000_000);
    let mut sources = UncertaintySources::zero();
    sources.network_ns = u64::MAX - 5;
    let evidence = SourceTimeEvidenceBuilder::new(1, host_ts)
        .uncertainty_sources(sources)
        .sync_state(sync_clock(1, 0))
        .build()?;
    let res = evidence.widen_uncertainty(100);
    assert!(
        matches!(res, Err(TimeToleranceError::ArithmeticOverflow)),
        "expected ArithmeticOverflow when widening exceeds u64 source budget, got {res:?}"
    );
    Ok(())
}

// Finding 7 (MEDIUM): Bounded Monotonic Drift Rejects Excessive Drift
#[test]
fn test_bounded_monotonic_drift_rejects_excessive_drift() -> Result<(), Box<dyn Error>> {
    let budget = TimeUncertaintyBudget::default();
    let op = TimeSensitiveOperation::TransitFeasibilityCheck; // requires BoundedMonotonicDrift, tolerance 200 ms
    let unsync = ClockSyncState::Unsynchronised {
        basis: ClockBasis::HostMonotonic,
        drift_bound_ns: 800_000_000, // 800 ms drift > 200 ms tolerance
    };
    let evidence = sample_evidence(1, 1_000_000_000, 400_000_000, unsync)?;
    let res = budget.enforce(op, &evidence);
    let is_rejected = match res {
        Err(_) => true,
        Ok(outcome) => !outcome.is_accepted(),
    };
    assert!(
        is_rejected,
        "drift bound of 800 ms must not satisfy 200 ms tolerance"
    );
    Ok(())
}

// Finding 8 (MEDIUM): Error Code Registration Completeness in registries/ERRORS.md
#[test]
fn test_error_code_registration_completeness() -> Result<(), Box<dyn Error>> {
    let content = include_str!("../../../registries/ERRORS.md");

    let mut registered_ids = std::collections::BTreeSet::new();
    for line in content.lines() {
        if line.starts_with('|') {
            let cols: Vec<&str> = line.split('|').map(str::trim).collect();
            if cols.len() >= 2 {
                let token = cols[1].trim_matches('`').trim();
                if token.starts_with("ERR-") {
                    registered_ids.insert(token.to_string());
                }
            }
        }
    }

    let required_error_codes = [
        ERR_CLOCK_UNCERTAIN_001,
        "ERR-CLOCK-STATE-UNKNOWN-001",
        "ERR-CLOCK-UNSYNCHRONISED-001",
        "ERR-OPERATION-UNREGISTERED-001",
        "ERR-TIME-INTERVAL-INVERTED-001",
        "ERR-CLOCK-BASIS-MISMATCH-001",
        "ERR-ARITHMETIC-OVERFLOW-001",
        "ERR-NON-MONOTONE-NARROWING-001",
    ];

    for &code in &required_error_codes {
        assert!(
            registered_ids.contains(code),
            "Time tolerance error code '{code}' is not registered in registries/ERRORS.md"
        );
    }
    Ok(())
}

// Finding 9 (MEDIUM): Boundary Abstain/Degrade and Error Variant Tests
#[test]
fn test_boundary_conditions_for_abstain_consequence() -> Result<(), Box<dyn Error>> {
    let budget = TimeUncertaintyBudget::default();
    let op = TimeSensitiveOperation::GeometryDependentNegativeEvidence; // 100 ms, Abstain
    let limit = op.default_max_uncertainty_ns();

    // At exact bound
    let ev_at_bound = sample_evidence(1, 1_000_000_000, limit / 2, sync_clock(1, 0))?;
    let outcome_bound = budget.enforce(op, &ev_at_bound)?;
    assert!(
        outcome_bound.is_accepted(),
        "exact bound must be accepted for Abstain op"
    );

    // At bound + 1 ns
    let host_ts = TimestampNs(1_000_000_000);
    let latest = host_ts.checked_add_ns(i128::from(limit) + 1)?;
    let interval = CaptureInterval::new(host_ts, latest)?;
    let ev_bound_plus_one = SourceTimeEvidence::new(SourceTimeEvidenceParams {
        sequence: 2,
        has_discontinuity: false,
        device_timestamp: None,
        device_clock_basis: None,
        host_receive_time: host_ts,
        sync_state: sync_clock(1, 0),
        uncertainty_sources: UncertaintySources::zero(),
        plausible_capture_interval: interval,
    })?;
    let outcome_plus_one = budget.enforce(op, &ev_bound_plus_one)?;
    assert!(
        outcome_plus_one.is_abstained(),
        "bound+1 must cause Abstain"
    );
    assert!(!outcome_plus_one.is_accepted());
    Ok(())
}

#[test]
fn test_boundary_conditions_for_degrade_consequence() -> Result<(), Box<dyn Error>> {
    let budget = TimeUncertaintyBudget::default();
    let op = TimeSensitiveOperation::IncidentReconstruction; // 250 ms, Degrade
    let limit = op.default_max_uncertainty_ns();

    // At exact bound
    let ev_at_bound = sample_evidence(1, 1_000_000_000, limit / 2, sync_clock(1, 0))?;
    let outcome_bound = budget.enforce(op, &ev_at_bound)?;
    assert!(
        outcome_bound.is_accepted(),
        "exact bound must be accepted for Degrade op"
    );

    // At bound + 1 ns
    let host_ts = TimestampNs(1_000_000_000);
    let latest = host_ts.checked_add_ns(i128::from(limit) + 1)?;
    let interval = CaptureInterval::new(host_ts, latest)?;
    let ev_bound_plus_one = SourceTimeEvidence::new(SourceTimeEvidenceParams {
        sequence: 2,
        has_discontinuity: false,
        device_timestamp: None,
        device_clock_basis: None,
        host_receive_time: host_ts,
        sync_state: sync_clock(1, 0),
        uncertainty_sources: UncertaintySources::zero(),
        plausible_capture_interval: interval,
    })?;
    let outcome_plus_one = budget.enforce(op, &ev_bound_plus_one)?;
    assert!(outcome_plus_one.is_degraded(), "bound+1 must cause Degrade");
    assert!(!outcome_plus_one.is_accepted());
    Ok(())
}

#[test]
fn test_error_variants_formatting_and_codes() -> Result<(), Box<dyn Error>> {
    let err_overflow = TimeToleranceError::ArithmeticOverflow;
    assert_eq!(err_overflow.error_code(), "ERR-ARITHMETIC-OVERFLOW-001");
    assert!(format!("{err_overflow}").contains("arithmetic overflow"));

    let err_narrowing = TimeToleranceError::NonMonotoneNarrowingAttempted {
        previous_uncertainty_ns: 100,
        attempted_uncertainty_ns: 50,
    };
    assert_eq!(err_narrowing.error_code(), "ERR-NON-MONOTONE-NARROWING-001");
    assert!(format!("{err_narrowing}").contains("narrow uncertainty"));

    let err_mismatch = TimeToleranceError::ClockBasisMismatch {
        expected: ClockBasis::HostMonotonic,
        actual: ClockBasis::UtcDisciplined,
    };
    assert_eq!(err_mismatch.error_code(), "ERR-CLOCK-BASIS-MISMATCH-001");
    assert!(format!("{err_mismatch}").contains("mismatch"));

    let err_inverted = TimeToleranceError::InvertedInterval {
        earliest: TimestampNs(100),
        latest: TimestampNs(50),
    };
    assert_eq!(err_inverted.error_code(), "ERR-TIME-INTERVAL-INVERTED-001");
    assert!(format!("{err_inverted}").contains("inverted"));

    let err_unregistered =
        TimeToleranceError::UnregisteredOperation(TimeSensitiveOperation::StereoTriangulation);
    assert_eq!(
        err_unregistered.error_code(),
        "ERR-OPERATION-UNREGISTERED-001"
    );
    assert!(format!("{err_unregistered}").contains("not registered"));

    let err_unknown = TimeToleranceError::ClockStateUnknown {
        operation: TimeSensitiveOperation::StereoTriangulation,
        reason: "daemon lost".to_string(),
    };
    assert_eq!(err_unknown.error_code(), "ERR-CLOCK-STATE-UNKNOWN-001");
    assert!(format!("{err_unknown}").contains("unknown"));

    let err_unsync = TimeToleranceError::ClockUnsynchronised {
        operation: TimeSensitiveOperation::StereoTriangulation,
        basis: ClockBasis::DeviceMonotonic,
        drift_bound_ns: 1_000,
    };
    assert_eq!(err_unsync.error_code(), "ERR-CLOCK-UNSYNCHRONISED-001");
    assert!(format!("{err_unsync}").contains("unsynchronised"));

    Ok(())
}
