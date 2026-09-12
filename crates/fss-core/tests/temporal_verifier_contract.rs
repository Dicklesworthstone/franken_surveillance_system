#![forbid(unsafe_code)]
//! Integration and contract tests for temporal verifier orchestration (FSS-083).
//!
//! Enforces:
//! - Explicit 8-state typed state machine (Pending, Running, Satisfied, Violated,
//!   Indeterminate, Cancelled, StaleGeneration, BudgetExhausted)
//! - Never flatten unknown or indeterminate into pass or fail
//! - Coverage gap mid-window yields Indeterminate (never Violated or Satisfied)
//! - Missing detection during a gap is NEVER evidence of absence (INV-001, INV-007)
//! - Clock skew and interval overlap yield Indeterminate
//! - Bounded work envelope and step limits prevent unbounded retries
//! - Cancellation lifecycle: request -> drain -> finalize
//! - Fault isolation: verifier error quarantines without panics or process crashes
//! - Out-of-order and duplicate events yield Violated
//! - Deterministic execution and stable identities

use std::collections::BTreeSet;
use std::error::Error;

use fss_core::{
    AnchorPinnedEventWindow, CaptureInterval, ClockBasis, Completeness, ContentDigest,
    ContractError, CoverageContinuity, CoverageStopReason, CoverageWitness, DecisionPath,
    DurationVerifier, EventEvidence, EventHypothesis, EventId, EventKind, EventState,
    EvidenceClass, EvidenceEdgeRelation, FaultyVerifier, GapVerifier, IndeterminateReason,
    LedgerAnchor, OrderingVerifier, PredicateAbsenceVerifier, ProbabilityInterval,
    StalenessVerifier, TemporalOrchestrator, TemporalVerifierId, TimestampNs, VerificationBudget,
    VerificationRunId, VerificationState, VerifierOutcome,
};

type TestResult = Result<(), Box<dyn Error>>;

fn test_anchor() -> LedgerAnchor {
    LedgerAnchor::genesis("site:test:temporal-verifier")
}

fn make_event(
    id: &str,
    earliest_ns: i128,
    latest_ns: i128,
    kind: EventKind,
) -> Result<EventHypothesis, Box<dyn Error>> {
    let interval = CaptureInterval::new(TimestampNs(earliest_ns), TimestampNs(latest_ns))?;
    let evidence = vec![EventEvidence {
        digest: ContentDigest::sha256(format!("evidence:{id}").as_bytes()),
        class: EvidenceClass::Observed,
        failure_domain: "sensor.cam_01".to_string(),
        relation: EvidenceEdgeRelation::Supports,
        supports: true,
        capsule_digest: None,
        identity_digest: None,
    }];
    let decision_path = DecisionPath {
        policy_generation: ContentDigest::sha256(b"policy:gen-1"),
        fingerprint: ContentDigest::sha256(b"fingerprint:1"),
        abstained: false,
        abstention_reason: None,
    };
    let probability = ProbabilityInterval::new(0.5, 0.9)?;

    Ok(EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_string(),
        event_id: EventId::parse(id)?,
        revision: 1,
        supersedes: None,
        state: EventState::Witnessed,
        kind,
        interval,
        uncertainty_reason: None,
        zone_ids: vec!["zone:perimeter".to_string()],
        track_ids: vec!["track:001".to_string()],
        probability,
        evidence,
        model_receipts: vec![],
        decision_path,
    })
}

fn make_continuous_witness(anchor: &LedgerAnchor, generation: u64) -> CoverageWitness {
    let mut domain = BTreeSet::new();
    domain.insert("sensor.cam_01".to_string());
    CoverageWitness {
        anchor: anchor.clone(),
        authorized_domain: domain.clone(),
        observed_domain: domain,
        excluded_domain: BTreeSet::new(),
        continuity: CoverageContinuity::Continuous,
        completeness: Completeness::Complete,
        negative_predicate: "PerimeterBreach".to_string(),
        stop_reason: CoverageStopReason::Complete,
        authorized_generation: generation,
        observed_generation: generation,
    }
}

fn make_gapped_witness(anchor: &LedgerAnchor, generation: u64) -> CoverageWitness {
    let mut domain = BTreeSet::new();
    domain.insert("sensor.cam_01".to_string());
    CoverageWitness {
        anchor: anchor.clone(),
        authorized_domain: domain.clone(),
        observed_domain: domain,
        excluded_domain: BTreeSet::new(),
        continuity: CoverageContinuity::Gapped,
        completeness: Completeness::Partial,
        negative_predicate: "PerimeterBreach".to_string(),
        stop_reason: CoverageStopReason::SourceGap,
        authorized_generation: generation,
        observed_generation: generation,
    }
}

// ============================================================================
// Test 1: Out-of-Order Events Yields Violated
// ============================================================================

#[test]
fn test_out_of_order_events_yields_violated() -> TestResult {
    let anchor = test_anchor();
    let e1 = make_event("event:001", 2_000, 3_000, EventKind::UnknownPresence)?;
    let e2 = make_event("event:002", 1_000, 1_500, EventKind::UnknownPresence)?;

    let window_interval = CaptureInterval::new(TimestampNs(500), TimestampNs(5_000))?;
    let window = AnchorPinnedEventWindow::new(
        anchor.clone(),
        window_interval,
        vec![e1, e2],
        Some(make_continuous_witness(&anchor, 1)),
        1,
        1,
    )?;

    let mut orchestrator = TemporalOrchestrator::default();
    orchestrator.register_verifier(Box::new(OrderingVerifier::new()?))?;

    let run_id = VerificationRunId::parse("run:test:001")?;
    let report = orchestrator.execute(run_id, &window)?;

    assert!(
        report.state.is_violated(),
        "expected Violated state for out-of-order events"
    );
    let VerificationState::Violated(detail) = report.state else {
        return Err("expected Violated state".into());
    };
    assert_eq!(
        detail.violating_event_id,
        Some(EventId::parse("event:002")?)
    );
    assert!(detail.reason.contains("out of chronological order"));

    Ok(())
}

// ============================================================================
// Test 2: Clock Skew Yields Indeterminate (Never Pass or Fail)
// ============================================================================

#[test]
fn test_clock_skew_or_mismatch_yields_indeterminate() -> TestResult {
    let anchor = test_anchor();
    let e1 = make_event("event:001", 1_000, 1_500, EventKind::UnknownPresence)?;
    let e2 = make_event("event:002", 2_000, 2_500, EventKind::UnknownPresence)?;

    let window_interval = CaptureInterval::new(TimestampNs(500), TimestampNs(5_000))?;
    let window = AnchorPinnedEventWindow::new(
        anchor.clone(),
        window_interval,
        vec![e1, e2],
        Some(make_continuous_witness(&anchor, 1)),
        1,
        1,
    )?
    .with_event_clock_basis(EventId::parse("event:001")?, ClockBasis::DeviceMonotonic)
    .with_event_clock_basis(EventId::parse("event:002")?, ClockBasis::UtcDisciplined);

    let mut orchestrator = TemporalOrchestrator::default();
    orchestrator.register_verifier(Box::new(OrderingVerifier::new()?))?;

    let run_id = VerificationRunId::parse("run:test:002")?;
    let report = orchestrator.execute(run_id, &window)?;

    assert!(
        report.state.is_indeterminate(),
        "clock skew/basis mismatch must yield Indeterminate, never pass or fail"
    );
    let VerificationState::Indeterminate(detail) = report.state else {
        return Err("expected Indeterminate state".into());
    };
    assert!(matches!(
        detail.reason,
        IndeterminateReason::ClockSkew { .. }
    ));

    Ok(())
}

// ============================================================================
// Test 3: Interval Overlap Yields Indeterminate
// ============================================================================

#[test]
fn test_interval_overlap_yields_indeterminate() -> TestResult {
    let anchor = test_anchor();
    // Events have interior overlap [2_000, 2_500]
    let e1 = make_event("event:001", 1_000, 2_500, EventKind::UnknownPresence)?;
    let e2 = make_event("event:002", 2_000, 3_500, EventKind::UnknownPresence)?;

    let window_interval = CaptureInterval::new(TimestampNs(500), TimestampNs(5_000))?;
    let window = AnchorPinnedEventWindow::new(
        anchor.clone(),
        window_interval,
        vec![e1, e2],
        Some(make_continuous_witness(&anchor, 1)),
        1,
        1,
    )?;

    let mut orchestrator = TemporalOrchestrator::default();
    orchestrator.register_verifier(Box::new(OrderingVerifier::new()?))?;

    let run_id = VerificationRunId::parse("run:test:003")?;
    let report = orchestrator.execute(run_id, &window)?;

    assert!(
        report.state.is_indeterminate(),
        "interval overlap must yield Indeterminate"
    );
    let VerificationState::Indeterminate(detail) = report.state else {
        return Err("expected Indeterminate state".into());
    };
    assert!(matches!(
        detail.reason,
        IndeterminateReason::IntervalOverlap { .. }
    ));

    Ok(())
}

// ============================================================================
// Test 4: Coverage Gap Mid-Window Yields Indeterminate (Never Violated or Satisfied)
// ============================================================================

#[test]
fn test_coverage_gap_mid_window_yields_indeterminate_never_pass_fail() -> TestResult {
    let anchor = test_anchor();
    let e1 = make_event("event:001", 1_000, 1_500, EventKind::BenignRoutine)?;

    let window_interval = CaptureInterval::new(TimestampNs(500), TimestampNs(5_000))?;
    let window = AnchorPinnedEventWindow::new(
        anchor.clone(),
        window_interval,
        vec![e1],
        Some(make_gapped_witness(&anchor, 1)),
        1,
        1,
    )?;

    let mut orchestrator = TemporalOrchestrator::default();
    orchestrator.register_verifier(Box::new(GapVerifier::new()?))?;

    let run_id = VerificationRunId::parse("run:test:004")?;
    let report = orchestrator.execute(run_id, &window)?;

    assert!(
        report.state.is_indeterminate(),
        "coverage gap must yield Indeterminate, never Violated or Satisfied"
    );
    assert!(!report.state.is_satisfied());
    assert!(!report.state.is_violated());

    let VerificationState::Indeterminate(detail) = report.state else {
        return Err("expected Indeterminate state".into());
    };
    assert!(matches!(
        detail.reason,
        IndeterminateReason::CoverageGap { .. }
    ));

    Ok(())
}

// ============================================================================
// Test 5: Missing Detection During Gap is NEVER Evidence of Absence
// ============================================================================

#[test]
fn test_missing_detection_during_gap_is_indeterminate_never_evidence_of_absence() -> TestResult {
    let anchor = test_anchor();
    // Window has NO perimeter breach event detected
    let e1 = make_event("event:001", 1_000, 1_500, EventKind::BenignRoutine)?;

    let window_interval = CaptureInterval::new(TimestampNs(500), TimestampNs(5_000))?;
    // BUT coverage witness has a gap
    let window = AnchorPinnedEventWindow::new(
        anchor.clone(),
        window_interval,
        vec![e1],
        Some(make_gapped_witness(&anchor, 1)),
        1,
        1,
    )?;

    let mut orchestrator = TemporalOrchestrator::default();
    orchestrator.register_verifier(Box::new(PredicateAbsenceVerifier::new(
        EventKind::PerimeterBreach,
    )?))?;

    let run_id = VerificationRunId::parse("run:test:005")?;
    let report = orchestrator.execute(run_id, &window)?;

    // A missing detection during a gap is strictly NEVER evidence of absence!
    assert!(
        report.state.is_indeterminate(),
        "missing detection during a gap must yield Indeterminate, NEVER Satisfied absence"
    );
    assert!(!report.state.is_satisfied());

    let VerificationState::Indeterminate(detail) = report.state else {
        return Err("expected Indeterminate state".into());
    };
    assert!(matches!(
        detail.reason,
        IndeterminateReason::MissingDetectionDuringGap { .. }
    ));

    Ok(())
}

// ============================================================================
// Test 6: Stale Generation Yields StaleGeneration State
// ============================================================================

#[test]
fn test_stale_generation_yields_stale_generation_state() -> TestResult {
    let anchor = test_anchor();
    let e1 = make_event("event:001", 1_000, 1_500, EventKind::BenignRoutine)?;

    let window_interval = CaptureInterval::new(TimestampNs(500), TimestampNs(5_000))?;
    // Expected generation 5, observed generation 4 (mismatch!)
    let window = AnchorPinnedEventWindow::new(
        anchor.clone(),
        window_interval,
        vec![e1],
        Some(make_continuous_witness(&anchor, 4)),
        5,
        4,
    )?;

    let mut orchestrator = TemporalOrchestrator::default();
    orchestrator.register_verifier(Box::new(StalenessVerifier::new()?))?;

    let run_id = VerificationRunId::parse("run:test:006")?;
    let report = orchestrator.execute(run_id, &window)?;

    assert!(
        report.state.is_stale_generation(),
        "expected StaleGeneration state"
    );
    let VerificationState::StaleGeneration(detail) = report.state else {
        return Err("expected StaleGeneration state".into());
    };
    assert_eq!(detail.expected_generation, 5);
    assert_eq!(detail.observed_generation, 4);

    // Verifiers must not have executed
    assert_eq!(report.steps_consumed, 0);

    Ok(())
}

// ============================================================================
// Test 7: Budget Exhaustion Transitions Cleanly
// ============================================================================

#[test]
fn test_budget_exhaustion_transitions_cleanly() -> TestResult {
    let anchor = test_anchor();
    let e1 = make_event("event:001", 1_000, 1_500, EventKind::BenignRoutine)?;
    let e2 = make_event("event:002", 2_000, 2_500, EventKind::BenignRoutine)?;
    let e3 = make_event("event:003", 3_000, 3_500, EventKind::BenignRoutine)?;

    let window_interval = CaptureInterval::new(TimestampNs(500), TimestampNs(5_000))?;
    let window = AnchorPinnedEventWindow::new(
        anchor.clone(),
        window_interval,
        vec![e1, e2, e3],
        Some(make_continuous_witness(&anchor, 1)),
        1,
        1,
    )?;

    // Configure budget to strictly permit max 2 events
    let budget = VerificationBudget::default_budget().with_max_events(2);
    let mut orchestrator = TemporalOrchestrator::new(budget);
    orchestrator.register_verifier(Box::new(OrderingVerifier::new()?))?;

    let run_id = VerificationRunId::parse("run:test:007")?;
    let report = orchestrator.execute(run_id, &window)?;

    assert!(
        report.state.is_budget_exhausted(),
        "expected BudgetExhausted state when events exceed max_events"
    );
    let VerificationState::BudgetExhausted(detail) = report.state else {
        return Err("expected BudgetExhausted state".into());
    };
    assert_eq!(detail.dimension, "max_events");
    assert_eq!(detail.limit, 2);
    assert_eq!(detail.observed, 3);

    Ok(())
}

// ============================================================================
// Test 8: Cancellation Mid-Run Follows Request -> Drain -> Finalize
// ============================================================================

#[test]
fn test_cancellation_request_drain_finalize() -> TestResult {
    let anchor = test_anchor();
    let e1 = make_event("event:001", 1_000, 1_500, EventKind::BenignRoutine)?;

    let window_interval = CaptureInterval::new(TimestampNs(500), TimestampNs(5_000))?;
    let window = AnchorPinnedEventWindow::new(
        anchor.clone(),
        window_interval,
        vec![e1],
        Some(make_continuous_witness(&anchor, 1)),
        1,
        1,
    )?;

    let mut orchestrator = TemporalOrchestrator::default();
    orchestrator.register_verifier(Box::new(OrderingVerifier::new()?))?;
    orchestrator.register_verifier(Box::new(GapVerifier::new()?))?;
    orchestrator.register_verifier(Box::new(StalenessVerifier::new()?))?;

    // Request cancellation before execution
    orchestrator.request_cancellation("operator manual abort");
    assert!(orchestrator.is_cancellation_requested());

    let run_id = VerificationRunId::parse("run:test:008")?;
    let report = orchestrator.execute(run_id, &window)?;

    assert!(report.state.is_cancelled(), "expected Cancelled state");
    let VerificationState::Cancelled(detail) = report.state else {
        return Err("expected Cancelled state".into());
    };
    assert_eq!(detail.reason, "operator manual abort");
    assert_eq!(detail.verifiers_completed, 0);
    assert_eq!(detail.verifiers_drained, 3);

    // Cancellation request should be cleared after finalize
    assert!(!orchestrator.is_cancellation_requested());

    Ok(())
}

// ============================================================================
// Test 9: Duplicate Events Detected and Handled
// ============================================================================

#[test]
fn test_duplicate_events_detected_and_handled() -> TestResult {
    let anchor = test_anchor();
    // Two events with identical EventId
    let e1 = make_event("event:dup", 1_000, 1_500, EventKind::UnknownPresence)?;
    let e2 = make_event("event:dup", 2_000, 2_500, EventKind::UnknownPresence)?;

    let window_interval = CaptureInterval::new(TimestampNs(500), TimestampNs(5_000))?;
    let window = AnchorPinnedEventWindow::new(
        anchor.clone(),
        window_interval,
        vec![e1, e2],
        Some(make_continuous_witness(&anchor, 1)),
        1,
        1,
    )?;

    let mut orchestrator = TemporalOrchestrator::default();
    orchestrator.register_verifier(Box::new(OrderingVerifier::new()?))?;

    let run_id = VerificationRunId::parse("run:test:009")?;
    let report = orchestrator.execute(run_id, &window)?;

    assert!(
        report.state.is_violated(),
        "duplicate event ID must yield Violated"
    );
    let VerificationState::Violated(detail) = report.state else {
        return Err("expected Violated state".into());
    };
    assert_eq!(
        detail.violating_event_id,
        Some(EventId::parse("event:dup")?)
    );
    assert!(detail.reason.contains("duplicate event ID"));

    Ok(())
}

// ============================================================================
// Test 10: Verifier Error Quarantines Without Crash
// ============================================================================

#[test]
fn test_verifier_error_quarantines_without_crash() -> TestResult {
    let anchor = test_anchor();
    let e1 = make_event("event:001", 1_000, 1_500, EventKind::BenignRoutine)?;

    let window_interval = CaptureInterval::new(TimestampNs(500), TimestampNs(5_000))?;
    let window = AnchorPinnedEventWindow::new(
        anchor.clone(),
        window_interval,
        vec![e1],
        Some(make_continuous_witness(&anchor, 1)),
        1,
        1,
    )?;

    let mut orchestrator = TemporalOrchestrator::default();
    // Register a faulty verifier that returns an error
    let faulty_id = TemporalVerifierId::parse("verifier:temporal:faulty:v1")?;
    orchestrator.register_verifier(Box::new(FaultyVerifier::new(
        "verifier:temporal:faulty:v1",
        "injected sensor protocol fault",
    )?))?;

    let run_id = VerificationRunId::parse("run:test:010")?;
    let report = orchestrator.execute(run_id, &window)?;

    // Must not crash or panic; outcome must be Quarantined and state Indeterminate
    assert!(
        orchestrator.is_quarantined(&faulty_id),
        "verifier must be placed in quarantine"
    );
    assert_eq!(report.quarantined_verifiers.len(), 1);
    assert!(
        report.state.is_indeterminate(),
        "quarantine must yield Indeterminate"
    );

    let outcome = &report.outcomes[0].1;
    assert!(
        matches!(outcome, VerifierOutcome::Quarantined { .. }),
        "outcome must be Quarantined"
    );

    // Subsequent run retains quarantine without re-executing error
    let run_id2 = VerificationRunId::parse("run:test:010b")?;
    let report2 = orchestrator.execute(run_id2, &window)?;
    assert!(orchestrator.is_quarantined(&faulty_id));
    assert!(report2.state.is_indeterminate());

    // Operator can lift quarantine
    assert!(orchestrator.lift_quarantine(&faulty_id));
    assert!(!orchestrator.is_quarantined(&faulty_id));

    Ok(())
}

// ============================================================================
// Test 11: Happy Path: All Verifiers Satisfied
// ============================================================================

#[test]
fn test_happy_path_all_verifiers_satisfied() -> TestResult {
    let anchor = test_anchor();
    let e1 = make_event("event:001", 1_000, 1_500, EventKind::BenignRoutine)?;
    let e2 = make_event("event:002", 2_000, 2_500, EventKind::BenignRoutine)?;
    let e3 = make_event("event:003", 3_000, 3_500, EventKind::BenignRoutine)?;

    let window_interval = CaptureInterval::new(TimestampNs(500), TimestampNs(5_000))?;
    let window = AnchorPinnedEventWindow::new(
        anchor.clone(),
        window_interval,
        vec![e1, e2, e3],
        Some(make_continuous_witness(&anchor, 1)),
        1,
        1,
    )?;

    let mut orchestrator = TemporalOrchestrator::default();
    orchestrator.register_verifier(Box::new(OrderingVerifier::new()?))?;
    orchestrator.register_verifier(Box::new(DurationVerifier::new(Some(1_000), Some(10_000))?))?;
    orchestrator.register_verifier(Box::new(GapVerifier::new()?))?;
    orchestrator.register_verifier(Box::new(StalenessVerifier::new()?))?;
    orchestrator.register_verifier(Box::new(PredicateAbsenceVerifier::new(
        EventKind::PerimeterBreach,
    )?))?;

    let run_id = VerificationRunId::parse("run:test:011")?;
    let report = orchestrator.execute(run_id, &window)?;

    assert!(
        report.state.is_satisfied(),
        "all verifiers should be satisfied"
    );
    let VerificationState::Satisfied(detail) = report.state else {
        return Err("expected Satisfied state".into());
    };
    assert_eq!(detail.verifiers_evaluated, 5);
    assert_eq!(detail.events_evaluated, 3);

    assert_eq!(report.outcomes.len(), 5);
    for (_, outcome) in &report.outcomes {
        assert!(matches!(outcome, VerifierOutcome::Satisfied { .. }));
    }

    Ok(())
}

// ============================================================================
// Test 12: Stable Identifier Validation
// ============================================================================

#[test]
fn test_stable_id_validation() -> TestResult {
    // Valid IDs
    assert!(TemporalVerifierId::parse("verifier:ordering:v1").is_ok());
    assert!(VerificationRunId::parse("run:2026-09-12:001").is_ok());

    // Invalid IDs (empty, whitespace, illegal punctuation)
    assert!(matches!(
        TemporalVerifierId::parse(""),
        Err(ContractError::InvalidIdentifier)
    ));
    assert!(matches!(
        TemporalVerifierId::parse("verifier with space"),
        Err(ContractError::InvalidIdentifier)
    ));
    assert!(matches!(
        VerificationRunId::parse("run!invalid#"),
        Err(ContractError::InvalidIdentifier)
    ));

    Ok(())
}

// ============================================================================
// Test 13: Step Limit Budget Exhaustion
// ============================================================================

#[test]
fn test_step_limit_budget_exhaustion() -> TestResult {
    let anchor = test_anchor();
    let e1 = make_event("event:001", 1_000, 1_500, EventKind::BenignRoutine)?;
    let e2 = make_event("event:002", 2_000, 2_500, EventKind::BenignRoutine)?;

    let window_interval = CaptureInterval::new(TimestampNs(500), TimestampNs(5_000))?;
    let window = AnchorPinnedEventWindow::new(
        anchor.clone(),
        window_interval,
        vec![e1, e2],
        Some(make_continuous_witness(&anchor, 1)),
        1,
        1,
    )?;

    // Configure budget to strictly permit max 1 step
    let budget = VerificationBudget::default_budget().with_max_steps(1);
    let mut orchestrator = TemporalOrchestrator::new(budget);
    orchestrator.register_verifier(Box::new(OrderingVerifier::new()?))?;

    let run_id = VerificationRunId::parse("run:test:013")?;
    let report = orchestrator.execute(run_id, &window)?;

    assert!(
        report.state.is_budget_exhausted(),
        "expected BudgetExhausted state when steps exceed max_steps"
    );

    Ok(())
}

// ============================================================================
// Planted Defect Tests (Adversarial Review 787 Rework)
// ============================================================================

#[test]
fn test_planted_defect_out_of_order_boundary_touch_yields_violated() -> TestResult {
    let anchor = test_anchor();
    // e1 [2000, 3000] followed by e2 [1000, 2000]: inverted order, touching at boundary 2000
    let e1 = make_event("event:001", 2_000, 3_000, EventKind::BenignRoutine)?;
    let e2 = make_event("event:002", 1_000, 2_000, EventKind::BenignRoutine)?;
    let window_interval = CaptureInterval::new(TimestampNs(500), TimestampNs(5_000))?;
    let window = AnchorPinnedEventWindow::new(
        anchor.clone(),
        window_interval,
        vec![e1, e2],
        Some(make_continuous_witness(&anchor, 1)),
        1,
        1,
    )?;
    let mut orchestrator = TemporalOrchestrator::default();
    orchestrator.register_verifier(Box::new(OrderingVerifier::new()?))?;
    let report = orchestrator.execute(VerificationRunId::parse("run:test:planted01")?, &window)?;
    assert!(
        report.state.is_violated(),
        "e1 [2000, 3000] followed by e2 [1000, 2000] is out of order, got: {:?}",
        report.state
    );
    Ok(())
}

#[test]
fn test_planted_defect_empty_orchestrator_must_not_be_satisfied() -> TestResult {
    let anchor = test_anchor();
    let window = AnchorPinnedEventWindow::new(
        anchor.clone(),
        CaptureInterval::new(TimestampNs(500), TimestampNs(5_000))?,
        vec![],
        None,
        1,
        1,
    )?;
    let mut orchestrator = TemporalOrchestrator::default();
    let report = orchestrator.execute(VerificationRunId::parse("run:test:planted02")?, &window)?;
    assert!(
        !report.state.is_satisfied(),
        "Empty orchestrator must not be Satisfied, got: {:?}",
        report.state
    );
    assert!(
        report.state.is_indeterminate(),
        "Empty orchestrator must yield Indeterminate, got: {:?}",
        report.state
    );
    Ok(())
}

#[test]
fn test_planted_defect_gap_verifier_budget_exhausted_stop_reason() -> TestResult {
    let anchor = test_anchor();
    let mut witness = make_continuous_witness(&anchor, 1);
    witness.stop_reason = CoverageStopReason::BudgetExhausted;
    witness.completeness = Completeness::Partial;
    let window = AnchorPinnedEventWindow::new(
        anchor.clone(),
        CaptureInterval::new(TimestampNs(500), TimestampNs(5_000))?,
        vec![],
        Some(witness),
        1,
        1,
    )?;
    let mut orchestrator = TemporalOrchestrator::default();
    orchestrator.register_verifier(Box::new(GapVerifier::new()?))?;
    let report = orchestrator.execute(VerificationRunId::parse("run:test:planted03")?, &window)?;
    assert!(
        report.state.is_indeterminate(),
        "BudgetExhausted stop_reason must yield Indeterminate, got: {:?}",
        report.state
    );
    Ok(())
}

#[test]
fn test_planted_defect_duration_verifier_unknown_continuity() -> TestResult {
    let anchor = test_anchor();
    let mut witness = make_continuous_witness(&anchor, 1);
    witness.continuity = CoverageContinuity::Unknown;
    let window = AnchorPinnedEventWindow::new(
        anchor.clone(),
        CaptureInterval::new(TimestampNs(500), TimestampNs(5_000))?,
        vec![],
        Some(witness),
        1,
        1,
    )?;
    let mut orchestrator = TemporalOrchestrator::default();
    orchestrator.register_verifier(Box::new(DurationVerifier::new(Some(1_000), Some(10_000))?))?;
    let report = orchestrator.execute(VerificationRunId::parse("run:test:planted04")?, &window)?;
    assert!(
        report.state.is_indeterminate(),
        "Unknown coverage continuity must yield Indeterminate, got: {:?}",
        report.state
    );
    Ok(())
}
