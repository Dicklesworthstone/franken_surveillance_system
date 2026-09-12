#![forbid(unsafe_code)]
//! Comprehensive contract tests for Event Revision Lineage and State Transitions (fss-x4a.6.15 / EVENT-LIFECYCLE-001).
//!
//! Covers:
//! - Exact canonical lifecycle: Hypothesized -> Witnessed -> Corroborated -> Adjudicated -> AlertDelivered -> Resolved
//! - Alternative branches to Rejected and Indeterminate
//! - Strict state monotonicity within immutable revision lineages
//! - Planted negatives for illegal rollbacks, jumps, terminal states, and non-monotonic regressions
//! - Corroboration failure domain isolation (>= 2 distinct domains; single camera is never corroborated)
//! - Urgent single-sensor policy exception (requires explicit flag and 'single-domain/unconfirmed' label)
//! - Orthogonality of event lifecycle state and alert effect outcome
//! - Late contradiction handling with complete retention of evidentiary history
//! - Lineage replay from EvidenceDelta batches
//! - Hard bound enforcement at exact bound and bound+1

use std::error::Error;

use fss_core::event::{
    AlertEffectRecord, DecisionPath, EVENT_HYPOTHESIS_SCHEMA, EVENT_TRANSITION_TABLE,
    EventDecodeError, EventEvidence, EventHypothesis, EventKind, EventLineage, EventState,
    EventSupersedeParams, EventTransitionError, EventTransitionParams, EvidenceEdgeRelation,
    MAX_ALERT_ATTEMPTS_COUNT, MAX_ALERT_CHANNEL_LEN, MAX_ALERT_FAILURE_REASON_LEN,
    MAX_EVIDENCE_COUNT, MAX_LINEAGE_DEPTH, ProbabilityInterval, SINGLE_DOMAIN_UNCONFIRMED_LABEL,
    get_event_transition_rule, is_allowed_event_transition,
};
use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncoder, CaptureInterval, ContentDigest,
    EffectState, EventId, EvidenceClass, EvidenceDelta, ObjectId, ObligationId, OperationId, Plane,
    TimestampNs,
};

// Helper: build certain probability interval
fn certain_probability() -> ProbabilityInterval {
    ProbabilityInterval {
        lower: 1.0,
        upper: 1.0,
        calibration_generation: None,
    }
}

// Helper: build sample capture interval
fn sample_interval() -> CaptureInterval {
    CaptureInterval {
        earliest: TimestampNs(1_700_000_000_000_000_000),
        latest: TimestampNs(1_700_000_005_000_000_000),
    }
}

// Helper: build sample evidence
fn sample_evidence(domain: &str, supports: bool, tag: &str) -> EventEvidence {
    EventEvidence {
        digest: ContentDigest::sha256(format!("evidence:{domain}:{tag}").as_bytes()),
        class: EvidenceClass::Observed,
        failure_domain: domain.to_string(),
        supports,
        relation: if supports {
            EvidenceEdgeRelation::Supports
        } else {
            EvidenceEdgeRelation::Contradicts
        },
        capsule_digest: Some(ContentDigest::sha256(
            format!("capsule:{domain}:{tag}").as_bytes(),
        )),
        identity_digest: Some(ContentDigest::sha256(
            format!("identity:{domain}").as_bytes(),
        )),
    }
}

// Helper: build sample decision path
fn sample_decision_path(policy_tag: &str) -> DecisionPath {
    DecisionPath {
        policy_generation: ContentDigest::sha256(b"policy:gen:1"),
        fingerprint: ContentDigest::sha256(policy_tag.as_bytes()),
        abstained: false,
        abstention_reason: None,
    }
}

// Helper: build genesis hypothesis (revision 1)
fn sample_genesis_hypothesis(event_name: &str) -> Result<EventHypothesis, Box<dyn Error>> {
    let event_id = EventId::parse(format!("event:{event_name}"))?;
    let interval = sample_interval();
    let probability = ProbabilityInterval {
        lower: 0.5,
        upper: 0.7,
        calibration_generation: None,
    };
    let decision_path = sample_decision_path("genesis-hypothesis");

    Ok(EventHypothesis {
        schema: EVENT_HYPOTHESIS_SCHEMA.to_string(),
        event_id,
        revision: 1,
        supersedes: None,
        state: EventState::Hypothesized,
        kind: EventKind::PerimeterBreach,
        interval,
        uncertainty_reason: Some("preliminary detector trigger".to_string()),
        zone_ids: vec!["zone:perimeter-north".to_string()],
        track_ids: vec!["track:tr-001".to_string()],
        probability,
        evidence: Vec::new(),
        model_receipts: vec![ContentDigest::sha256(b"receipt:model:yolo-v1")],
        decision_path,
    })
}

// Helper: build sample transition params
fn transition_params(
    target_state: EventState,
    evidence: Vec<EventEvidence>,
    uncertainty_reason: Option<String>,
    urgent_single_sensor: bool,
) -> EventTransitionParams {
    let interval = sample_interval();
    let probability = ProbabilityInterval {
        lower: 0.8,
        upper: 0.95,
        calibration_generation: None,
    };
    let decision_path = sample_decision_path(&format!("transition-to-{:?}", target_state));

    EventTransitionParams {
        target_state,
        kind: EventKind::PerimeterBreach,
        interval,
        uncertainty_reason,
        zone_ids: vec!["zone:perimeter-north".to_string()],
        track_ids: vec!["track:tr-001".to_string()],
        probability,
        evidence,
        model_receipts: vec![ContentDigest::sha256(b"receipt:model:yolo-v1")],
        decision_path,
        urgent_single_sensor,
    }
}

#[test]
fn test_canonical_lifecycle_happy_path() -> Result<(), Box<dyn Error>> {
    let genesis = sample_genesis_hypothesis("canonical-flow-001")?;
    let mut lineage = EventLineage::new(genesis)?;

    assert_eq!(lineage.len(), 1);
    assert_eq!(lineage.current_revision(), 1);
    assert_eq!(lineage.current_state(), EventState::Hypothesized);
    assert_eq!(
        lineage.highest_canonical_state(),
        Some(EventState::Hypothesized)
    );

    // Step 1: Hypothesized -> Witnessed
    let ev1 = sample_evidence("camera:cam-north", true, "w1");
    let p1 = transition_params(EventState::Witnessed, vec![ev1.clone()], None, false);
    lineage.transition(p1)?;
    assert_eq!(lineage.len(), 2);
    assert_eq!(lineage.current_revision(), 2);
    assert_eq!(lineage.current_state(), EventState::Witnessed);
    assert_eq!(
        lineage.highest_canonical_state(),
        Some(EventState::Witnessed)
    );

    // Step 2: Witnessed -> Corroborated (requires >= 2 distinct failure domains)
    let ev2 = sample_evidence("radar:radar-north", true, "w2");
    let p2 = transition_params(
        EventState::Corroborated,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    );
    lineage.transition(p2)?;
    assert_eq!(lineage.len(), 3);
    assert_eq!(lineage.current_revision(), 3);
    assert_eq!(lineage.current_state(), EventState::Corroborated);
    assert_eq!(
        lineage.highest_canonical_state(),
        Some(EventState::Corroborated)
    );

    // Verify corroboration analysis
    let analysis = lineage.analyze_corroboration();
    assert!(analysis.is_corroborated);
    assert_eq!(analysis.distinct_failure_domains.len(), 2);
    assert_eq!(analysis.supporting_count, 2);
    assert_eq!(analysis.contradicting_count, 0);

    // Step 3: Corroborated -> Adjudicated
    let p3 = transition_params(
        EventState::Adjudicated,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    );
    lineage.transition(p3)?;
    assert_eq!(lineage.len(), 4);
    assert_eq!(lineage.current_revision(), 4);
    assert_eq!(lineage.current_state(), EventState::Adjudicated);
    assert_eq!(
        lineage.highest_canonical_state(),
        Some(EventState::Adjudicated)
    );

    // Step 4: Adjudicated -> AlertDelivered
    let ev_alert = sample_evidence("provider:sms-dispatch", true, "receipt-42");
    let p4 = transition_params(
        EventState::AlertDelivered,
        vec![ev1.clone(), ev2.clone(), ev_alert],
        None,
        false,
    );
    lineage.transition(p4)?;
    assert_eq!(lineage.len(), 5);
    assert_eq!(lineage.current_revision(), 5);
    assert_eq!(lineage.current_state(), EventState::AlertDelivered);
    assert_eq!(
        lineage.highest_canonical_state(),
        Some(EventState::AlertDelivered)
    );

    // Step 5: AlertDelivered -> Resolved
    let p5 = transition_params(EventState::Resolved, vec![ev1, ev2], None, false);
    lineage.transition(p5)?;
    assert_eq!(lineage.len(), 6);
    assert_eq!(lineage.current_revision(), 6);
    assert_eq!(lineage.current_state(), EventState::Resolved);
    assert_eq!(
        lineage.highest_canonical_state(),
        Some(EventState::Resolved)
    );
    assert!(lineage.current().state.is_terminal());

    // Verify full lineage chain integrity
    lineage.verify()?;

    // Check all supersedes links
    let history = lineage.history();
    assert!(history[0].supersedes.is_none());
    for i in 1..history.len() {
        assert_eq!(history[i].revision, (i as u64) + 1);
        assert_eq!(
            history[i].supersedes,
            Some(history[i - 1].revision_digest())
        );
    }

    Ok(())
}

#[test]
fn test_alternative_branch_hypothesized_to_rejected() -> Result<(), Box<dyn Error>> {
    let genesis = sample_genesis_hypothesis("hyp-rej-001")?;
    let mut lineage = EventLineage::new(genesis)?;

    let ev = sample_evidence("camera:cam-north", false, "benign-moth");
    let p = transition_params(
        EventState::Rejected,
        vec![ev],
        Some("confirmed insect on lens".to_string()),
        false,
    );
    lineage.transition(p)?;

    assert_eq!(lineage.current_state(), EventState::Rejected);
    assert!(lineage.current_state().is_terminal());
    lineage.verify()?;
    Ok(())
}

#[test]
fn test_alternative_branch_witnessed_to_rejected() -> Result<(), Box<dyn Error>> {
    let genesis = sample_genesis_hypothesis("wit-rej-001")?;
    let mut lineage = EventLineage::new(genesis)?;

    let ev1 = sample_evidence("camera:cam-north", true, "motion");
    let p1 = transition_params(EventState::Witnessed, vec![ev1.clone()], None, false);
    lineage.transition(p1)?;

    let ev_contra = sample_evidence("camera:cam-north", false, "refutation");
    let p2 = transition_params(
        EventState::Rejected,
        vec![ev1, ev_contra],
        Some("environmental shadow artifact".to_string()),
        false,
    );
    lineage.transition(p2)?;

    assert_eq!(lineage.current_state(), EventState::Rejected);
    assert!(lineage.current_state().is_terminal());
    assert_eq!(lineage.len(), 3);
    lineage.verify()?;
    Ok(())
}

#[test]
fn test_alternative_branch_corroborated_to_rejected() -> Result<(), Box<dyn Error>> {
    let genesis = sample_genesis_hypothesis("corr-rej-001")?;
    let mut lineage = EventLineage::new(genesis)?;

    let ev1 = sample_evidence("camera:cam-north", true, "motion");
    let p1 = transition_params(EventState::Witnessed, vec![ev1.clone()], None, false);
    lineage.transition(p1)?;

    let ev2 = sample_evidence("radar:radar-north", true, "track");
    let p2 = transition_params(
        EventState::Corroborated,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    );
    lineage.transition(p2)?;

    // Late contradiction refuting corroborated candidate
    let ev_contra = sample_evidence("rfid:badge-reader", false, "authorized-resident");
    let p3 = transition_params(
        EventState::Rejected,
        vec![ev1, ev2, ev_contra],
        Some("authorized owner entry with keycard".to_string()),
        false,
    );
    lineage.transition(p3)?;

    assert_eq!(lineage.current_state(), EventState::Rejected);
    assert!(lineage.current_state().is_terminal());
    assert_eq!(lineage.len(), 4);
    lineage.verify()?;
    Ok(())
}

#[test]
fn test_alternative_branch_adjudicated_to_rejected() -> Result<(), Box<dyn Error>> {
    let genesis = sample_genesis_hypothesis("adj-rej-001")?;
    let mut lineage = EventLineage::new(genesis)?;

    let ev1 = sample_evidence("camera:cam-north", true, "motion");
    lineage.transition(transition_params(
        EventState::Witnessed,
        vec![ev1.clone()],
        None,
        false,
    ))?;
    let ev2 = sample_evidence("radar:radar-north", true, "track");
    lineage.transition(transition_params(
        EventState::Corroborated,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    ))?;
    lineage.transition(transition_params(
        EventState::Adjudicated,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    ))?;

    // Refuted at Adjudicated stage before alert delivery
    let ev_contra = sample_evidence("dispatch:operator", false, "confirmed-drill");
    lineage.transition(transition_params(
        EventState::Rejected,
        vec![ev1, ev2, ev_contra],
        Some("scheduled security drill".to_string()),
        false,
    ))?;

    assert_eq!(lineage.current_state(), EventState::Rejected);
    assert!(lineage.current_state().is_terminal());
    lineage.verify()?;
    Ok(())
}

#[test]
fn test_alternative_branch_alert_delivered_to_rejected() -> Result<(), Box<dyn Error>> {
    let genesis = sample_genesis_hypothesis("alert-rej-001")?;
    let mut lineage = EventLineage::new(genesis)?;

    let ev1 = sample_evidence("camera:cam-north", true, "motion");
    lineage.transition(transition_params(
        EventState::Witnessed,
        vec![ev1.clone()],
        None,
        false,
    ))?;
    let ev2 = sample_evidence("radar:radar-north", true, "track");
    lineage.transition(transition_params(
        EventState::Corroborated,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    ))?;
    lineage.transition(transition_params(
        EventState::Adjudicated,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    ))?;
    let ev_alert = sample_evidence("provider:sms", true, "sms-ack");
    lineage.transition(transition_params(
        EventState::AlertDelivered,
        vec![ev1.clone(), ev2.clone(), ev_alert.clone()],
        None,
        false,
    ))?;

    // Post-delivery determination of false alarm
    let ev_contra = sample_evidence("operator:post-incident", false, "benign-delivery");
    lineage.transition(transition_params(
        EventState::Rejected,
        vec![ev1, ev2, ev_alert, ev_contra],
        Some("package delivery courier false positive".to_string()),
        false,
    ))?;

    assert_eq!(lineage.current_state(), EventState::Rejected);
    assert!(lineage.current_state().is_terminal());
    lineage.verify()?;
    Ok(())
}

#[test]
fn test_alternative_branch_indeterminate_and_forward_reconciliation() -> Result<(), Box<dyn Error>>
{
    let genesis = sample_genesis_hypothesis("indet-recon-001")?;
    let mut lineage = EventLineage::new(genesis)?;

    let ev1 = sample_evidence("camera:cam-north", true, "motion");
    lineage.transition(transition_params(
        EventState::Witnessed,
        vec![ev1.clone()],
        None,
        false,
    ))?;

    // Sensor coverage drops; event enters Indeterminate with reconciliation guidance
    let p_indet = transition_params(
        EventState::Indeterminate,
        vec![ev1.clone()],
        Some("fog obstruction; awaiting radar corroboration".to_string()),
        false,
    );
    lineage.transition(p_indet)?;
    assert_eq!(lineage.current_state(), EventState::Indeterminate);

    // Self-transition on Indeterminate updating investigation progress
    let p_indet_update = transition_params(
        EventState::Indeterminate,
        vec![ev1.clone()],
        Some("radar sweep initiated; coverage witness verified".to_string()),
        false,
    );
    lineage.transition(p_indet_update)?;
    assert_eq!(lineage.current_state(), EventState::Indeterminate);
    assert_eq!(lineage.current_revision(), 4);

    // Reconcile forward to Corroborated when radar evidence arrives
    let ev2 = sample_evidence("radar:radar-north", true, "sweep-match");
    let p_corr = transition_params(
        EventState::Corroborated,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    );
    lineage.transition(p_corr)?;
    assert_eq!(lineage.current_state(), EventState::Corroborated);

    // Continue to Adjudicated, AlertDelivered, Resolved
    lineage.transition(transition_params(
        EventState::Adjudicated,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    ))?;
    let ev_alert = sample_evidence("provider:sms", true, "sms-ack");
    lineage.transition(transition_params(
        EventState::AlertDelivered,
        vec![ev1.clone(), ev2.clone(), ev_alert],
        None,
        false,
    ))?;
    lineage.transition(transition_params(
        EventState::Resolved,
        vec![ev1, ev2],
        None,
        false,
    ))?;

    assert_eq!(lineage.current_state(), EventState::Resolved);
    lineage.verify()?;
    Ok(())
}

#[test]
fn test_planted_negative_terminal_states_immutable() -> Result<(), Box<dyn Error>> {
    // 1. Resolved is terminal
    let genesis1 = sample_genesis_hypothesis("term-res-001")?;
    let mut lineage1 = EventLineage::new(genesis1)?;
    let ev1 = sample_evidence("camera:cam-north", true, "motion");
    lineage1.transition(transition_params(
        EventState::Witnessed,
        vec![ev1.clone()],
        None,
        false,
    ))?;
    let ev2 = sample_evidence("radar:radar-north", true, "track");
    lineage1.transition(transition_params(
        EventState::Corroborated,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    ))?;
    lineage1.transition(transition_params(
        EventState::Adjudicated,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    ))?;
    lineage1.transition(transition_params(
        EventState::Resolved,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    ))?;
    assert_eq!(lineage1.current_state(), EventState::Resolved);

    let Err(err) = lineage1.transition(transition_params(
        EventState::Hypothesized,
        vec![ev1.clone()],
        None,
        false,
    )) else {
        return Err("expected TerminalStateImmutable".into());
    };
    assert_eq!(
        err,
        EventTransitionError::TerminalStateImmutable {
            state: EventState::Resolved
        }
    );

    let Err(err2) = lineage1.transition(transition_params(
        EventState::Witnessed,
        vec![ev1.clone()],
        None,
        false,
    )) else {
        return Err("expected TerminalStateImmutable".into());
    };
    assert_eq!(
        err2,
        EventTransitionError::TerminalStateImmutable {
            state: EventState::Resolved
        }
    );

    // 2. Rejected is terminal
    let genesis2 = sample_genesis_hypothesis("term-rej-001")?;
    let mut lineage2 = EventLineage::new(genesis2)?;
    lineage2.transition(transition_params(
        EventState::Rejected,
        vec![ev1.clone()],
        Some("rejected".to_string()),
        false,
    ))?;
    assert_eq!(lineage2.current_state(), EventState::Rejected);

    let Err(err3) = lineage2.transition(transition_params(
        EventState::Witnessed,
        vec![ev1],
        None,
        false,
    )) else {
        return Err("expected TerminalStateImmutable".into());
    };
    assert_eq!(
        err3,
        EventTransitionError::TerminalStateImmutable {
            state: EventState::Rejected
        }
    );

    Ok(())
}

#[test]
fn test_planted_negative_illegal_state_rollbacks() -> Result<(), Box<dyn Error>> {
    let genesis = sample_genesis_hypothesis("rollback-001")?;
    let mut lineage = EventLineage::new(genesis)?;

    let ev1 = sample_evidence("camera:cam-north", true, "motion");
    lineage.transition(transition_params(
        EventState::Witnessed,
        vec![ev1.clone()],
        None,
        false,
    ))?;

    // Rollback Witnessed -> Hypothesized
    let Err(err) = lineage.transition(transition_params(
        EventState::Hypothesized,
        vec![],
        None,
        false,
    )) else {
        return Err("expected IllegalStateTransition".into());
    };
    assert!(matches!(
        err,
        EventTransitionError::IllegalStateTransition {
            from: EventState::Witnessed,
            to: EventState::Hypothesized,
            ..
        }
    ));

    let ev2 = sample_evidence("radar:radar-north", true, "track");
    lineage.transition(transition_params(
        EventState::Corroborated,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    ))?;

    // Rollback Corroborated -> Witnessed
    let Err(err) = lineage.transition(transition_params(
        EventState::Witnessed,
        vec![ev1.clone()],
        None,
        false,
    )) else {
        return Err("expected IllegalStateTransition".into());
    };
    assert!(matches!(
        err,
        EventTransitionError::IllegalStateTransition {
            from: EventState::Corroborated,
            to: EventState::Witnessed,
            ..
        }
    ));

    lineage.transition(transition_params(
        EventState::Adjudicated,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    ))?;

    // Rollback Adjudicated -> Corroborated
    let Err(err) = lineage.transition(transition_params(
        EventState::Corroborated,
        vec![ev1.clone(), ev2],
        None,
        false,
    )) else {
        return Err("expected IllegalStateTransition".into());
    };
    assert!(matches!(
        err,
        EventTransitionError::IllegalStateTransition {
            from: EventState::Adjudicated,
            to: EventState::Corroborated,
            ..
        }
    ));

    // Rollback Adjudicated -> Witnessed
    let Err(err) = lineage.transition(transition_params(
        EventState::Witnessed,
        vec![ev1],
        None,
        false,
    )) else {
        return Err("expected IllegalStateTransition".into());
    };
    assert!(matches!(
        err,
        EventTransitionError::IllegalStateTransition {
            from: EventState::Adjudicated,
            to: EventState::Witnessed,
            ..
        }
    ));

    Ok(())
}

#[test]
fn test_planted_negative_illegal_state_jumps() -> Result<(), Box<dyn Error>> {
    let genesis = sample_genesis_hypothesis("jump-001")?;
    let mut lineage = EventLineage::new(genesis)?;
    let ev1 = sample_evidence("camera:cam-north", true, "motion");
    let ev2 = sample_evidence("radar:radar-north", true, "track");

    // Illegal jump: Hypothesized -> Corroborated
    let Err(err) = lineage.transition(transition_params(
        EventState::Corroborated,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    )) else {
        return Err("expected IllegalStateTransition".into());
    };
    assert!(matches!(
        err,
        EventTransitionError::IllegalStateTransition {
            from: EventState::Hypothesized,
            to: EventState::Corroborated,
            ..
        }
    ));

    // Illegal jump: Hypothesized -> Adjudicated
    let Err(err) = lineage.transition(transition_params(
        EventState::Adjudicated,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    )) else {
        return Err("expected IllegalStateTransition".into());
    };
    assert!(matches!(
        err,
        EventTransitionError::IllegalStateTransition {
            from: EventState::Hypothesized,
            to: EventState::Adjudicated,
            ..
        }
    ));

    // Illegal jump: Hypothesized -> AlertDelivered
    let Err(err) = lineage.transition(transition_params(
        EventState::AlertDelivered,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    )) else {
        return Err("expected IllegalStateTransition".into());
    };
    assert!(matches!(
        err,
        EventTransitionError::IllegalStateTransition {
            from: EventState::Hypothesized,
            to: EventState::AlertDelivered,
            ..
        }
    ));

    // Illegal jump: Hypothesized -> Resolved
    let Err(err) = lineage.transition(transition_params(
        EventState::Resolved,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    )) else {
        return Err("expected IllegalStateTransition".into());
    };
    assert!(matches!(
        err,
        EventTransitionError::IllegalStateTransition {
            from: EventState::Hypothesized,
            to: EventState::Resolved,
            ..
        }
    ));

    // Move to Witnessed
    lineage.transition(transition_params(
        EventState::Witnessed,
        vec![ev1.clone()],
        None,
        false,
    ))?;

    // Illegal jump: Witnessed -> AlertDelivered
    let Err(err) = lineage.transition(transition_params(
        EventState::AlertDelivered,
        vec![ev1.clone(), ev2],
        None,
        false,
    )) else {
        return Err("expected IllegalStateTransition".into());
    };
    assert!(matches!(
        err,
        EventTransitionError::IllegalStateTransition {
            from: EventState::Witnessed,
            to: EventState::AlertDelivered,
            ..
        }
    ));

    // Illegal jump: Witnessed -> Resolved
    let Err(err) = lineage.transition(transition_params(
        EventState::Resolved,
        vec![ev1],
        None,
        false,
    )) else {
        return Err("expected IllegalStateTransition".into());
    };
    assert!(matches!(
        err,
        EventTransitionError::IllegalStateTransition {
            from: EventState::Witnessed,
            to: EventState::Resolved,
            ..
        }
    ));

    Ok(())
}

#[test]
fn test_planted_negative_non_monotonic_regression_from_indeterminate() -> Result<(), Box<dyn Error>>
{
    let genesis = sample_genesis_hypothesis("mono-reg-001")?;
    let mut lineage = EventLineage::new(genesis)?;

    let ev1 = sample_evidence("camera:cam-north", true, "motion");
    lineage.transition(transition_params(
        EventState::Witnessed,
        vec![ev1.clone()],
        None,
        false,
    ))?;
    let ev2 = sample_evidence("radar:radar-north", true, "track");
    lineage.transition(transition_params(
        EventState::Corroborated,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    ))?;
    lineage.transition(transition_params(
        EventState::Adjudicated,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    ))?;
    assert_eq!(
        lineage.highest_canonical_state(),
        Some(EventState::Adjudicated)
    );

    // Branch to Indeterminate
    lineage.transition(transition_params(
        EventState::Indeterminate,
        vec![ev1.clone(), ev2.clone()],
        Some("re-evaluating risk".to_string()),
        false,
    ))?;
    assert_eq!(lineage.current_state(), EventState::Indeterminate);

    // Attempting to regress back to Witnessed (rank 2 < rank 4 of Adjudicated) must fail
    let Err(err) = lineage.transition(transition_params(
        EventState::Witnessed,
        vec![ev1.clone()],
        None,
        false,
    )) else {
        return Err("expected NonMonotonicTransition".into());
    };
    assert_eq!(
        err,
        EventTransitionError::NonMonotonicTransition {
            from: EventState::Indeterminate,
            to: EventState::Witnessed,
            highest_reached: EventState::Adjudicated,
        }
    );

    // Attempting to regress back to Corroborated (rank 3 < rank 4 of Adjudicated) must fail
    let Err(err2) = lineage.transition(transition_params(
        EventState::Corroborated,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    )) else {
        return Err("expected NonMonotonicTransition".into());
    };
    assert_eq!(
        err2,
        EventTransitionError::NonMonotonicTransition {
            from: EventState::Indeterminate,
            to: EventState::Corroborated,
            highest_reached: EventState::Adjudicated,
        }
    );

    // Reconciling to Adjudicated (rank 4 == rank 4) or forward to AlertDelivered (rank 5) is legal
    lineage.transition(transition_params(
        EventState::Adjudicated,
        vec![ev1, ev2],
        None,
        false,
    ))?;
    assert_eq!(lineage.current_state(), EventState::Adjudicated);

    Ok(())
}

#[test]
fn test_corroboration_failure_domain_requirements() -> Result<(), Box<dyn Error>> {
    let genesis = sample_genesis_hypothesis("fail-domain-001")?;
    let mut lineage = EventLineage::new(genesis)?;

    let ev1 = sample_evidence("camera:cam-north", true, "frame-1");
    lineage.transition(transition_params(
        EventState::Witnessed,
        vec![ev1.clone()],
        None,
        false,
    ))?;

    // Attempt Corroborated with two pieces of evidence from the SAME failure domain
    let ev2_same_domain = sample_evidence("camera:cam-north", true, "frame-2");
    let Err(err) = lineage.transition(transition_params(
        EventState::Corroborated,
        vec![ev1.clone(), ev2_same_domain],
        None,
        false,
    )) else {
        return Err("expected CorroborationRequired".into());
    };

    assert_eq!(
        err,
        EventTransitionError::CorroborationRequired {
            observed_domains: 1,
        }
    );

    // Positive case: two distinct failure domains
    let ev2_diff_domain = sample_evidence("radar:radar-north", true, "radar-target");
    lineage.transition(transition_params(
        EventState::Corroborated,
        vec![ev1, ev2_diff_domain],
        None,
        false,
    ))?;

    assert_eq!(lineage.current_state(), EventState::Corroborated);
    Ok(())
}

#[test]
fn test_urgent_single_sensor_policy_exception() -> Result<(), Box<dyn Error>> {
    let genesis = sample_genesis_hypothesis("urgent-001")?;
    let mut lineage = EventLineage::new(genesis)?;

    let ev1 = sample_evidence("camera:cam-north", true, "motion");
    lineage.transition(transition_params(
        EventState::Witnessed,
        vec![ev1.clone()],
        None,
        false,
    ))?;

    // Negative case 1: Witnessed -> Adjudicated with urgent_single_sensor = false fails
    let Err(err1) = lineage.transition(transition_params(
        EventState::Adjudicated,
        vec![ev1.clone()],
        Some("urgent exception attempted".to_string()),
        false,
    )) else {
        return Err("expected UrgentExceptionRequired".into());
    };
    assert_eq!(err1, EventTransitionError::UrgentExceptionRequired);

    // Negative case 2: urgent_single_sensor = true, but missing 'single-domain/unconfirmed' label
    let Err(err2) = lineage.transition(transition_params(
        EventState::Adjudicated,
        vec![ev1.clone()],
        Some("urgent perimeter alert".to_string()), // missing the required label
        true,
    )) else {
        return Err("expected Contradiction".into());
    };
    assert!(matches!(
        err2,
        EventTransitionError::Contradiction {
            field: "uncertainty_reason",
            ..
        }
    ));

    // Positive case: urgent_single_sensor = true WITH explicit label
    let label = format!("{SINGLE_DOMAIN_UNCONFIRMED_LABEL}: urgent high-severity fence breach");
    lineage.transition(transition_params(
        EventState::Adjudicated,
        vec![ev1.clone()],
        Some(label),
        true,
    ))?;

    assert_eq!(lineage.current_state(), EventState::Adjudicated);
    assert!(lineage.current().is_single_domain_unconfirmed());

    // Planted negative: urgent single-sensor policy NEVER permits calling the event 'Corroborated'
    // AGENTS.md prime directive: one camera's model score is NEVER corroborated.
    let genesis_corroborate_test = sample_genesis_hypothesis("urgent-corr-reject")?;
    let mut lineage_corr = EventLineage::new(genesis_corroborate_test)?;
    lineage_corr.transition(transition_params(
        EventState::Witnessed,
        vec![ev1.clone()],
        None,
        false,
    ))?;

    let Err(err_corr) = lineage_corr.transition(transition_params(
        EventState::Corroborated,
        vec![ev1],
        Some(format!(
            "{SINGLE_DOMAIN_UNCONFIRMED_LABEL}: attempting to call single-camera corroborated"
        )),
        true,
    )) else {
        return Err("expected CorroborationRequired".into());
    };
    assert_eq!(
        err_corr,
        EventTransitionError::CorroborationRequired {
            observed_domains: 1
        }
    );

    Ok(())
}

#[test]
fn test_planted_negative_duplicate_evidence() -> Result<(), Box<dyn Error>> {
    let genesis = sample_genesis_hypothesis("dup-ev-001")?;
    let mut lineage = EventLineage::new(genesis)?;

    let ev1 = sample_evidence("camera:cam-north", true, "motion");
    // Duplicate: exact same evidence item included twice in params.evidence
    let Err(err) = lineage.transition(transition_params(
        EventState::Witnessed,
        vec![ev1.clone(), ev1.clone()],
        None,
        false,
    )) else {
        return Err("expected DuplicateEvidence".into());
    };

    assert_eq!(
        err,
        EventTransitionError::DuplicateEvidence { digest: ev1.digest }
    );
    Ok(())
}

#[test]
fn test_orthogonality_event_state_and_alert_effect() -> Result<(), Box<dyn Error>> {
    let genesis = sample_genesis_hypothesis("ortho-001")?;
    let mut lineage = EventLineage::new(genesis)?;

    let ev1 = sample_evidence("camera:cam-north", true, "motion");
    lineage.transition(transition_params(
        EventState::Witnessed,
        vec![ev1.clone()],
        None,
        false,
    ))?;
    let ev2 = sample_evidence("radar:radar-north", true, "track");
    lineage.transition(transition_params(
        EventState::Corroborated,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    ))?;
    lineage.transition(transition_params(
        EventState::Adjudicated,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    ))?;

    // 1. Alert is prepared / committed while event is Adjudicated: event state does NOT change
    let alert_op = OperationId::parse("op:alert-dispatch-001")?;
    let alert_ob = ObligationId::parse("obligation:alert-proof-001")?;
    let attempt1 = AlertEffectRecord {
        operation_id: alert_op.clone(),
        obligation_id: alert_ob.clone(),
        event_revision: lineage.current_revision(),
        event_revision_digest: lineage.current().revision_digest(),
        effect_state: EffectState::Prepared,
        timestamp_ns: TimestampNs(1_700_000_001_000_000_000),
        channel: "sms:security-team".to_string(),
        observation_receipt: None,
        failure_reason: None,
    };
    lineage.record_alert_attempt(attempt1)?;
    assert_eq!(lineage.current_state(), EventState::Adjudicated);
    assert_eq!(lineage.alert_attempts().len(), 1);

    // 2. Lost ACK: alert effect becomes Indeterminate, but event state does NOT fabricate AlertDelivered
    let attempt2 = AlertEffectRecord {
        operation_id: alert_op.clone(),
        obligation_id: alert_ob.clone(),
        event_revision: lineage.current_revision(),
        event_revision_digest: lineage.current().revision_digest(),
        effect_state: EffectState::Indeterminate,
        timestamp_ns: TimestampNs(1_700_000_002_000_000_000),
        channel: "sms:security-team".to_string(),
        observation_receipt: None,
        failure_reason: Some("dispatch ACK timed out after 5000ms".to_string()),
    };
    lineage.record_alert_attempt(attempt2)?;
    assert_eq!(lineage.current_state(), EventState::Adjudicated);
    assert_eq!(lineage.alert_attempts().len(), 2);

    // 3. Event can branch to Indeterminate while investigating lost alert ACK
    lineage.transition(transition_params(
        EventState::Indeterminate,
        vec![ev1.clone(), ev2.clone()],
        Some("alert attempt indeterminate; reconciling provider delivery".to_string()),
        false,
    ))?;
    assert_eq!(lineage.current_state(), EventState::Indeterminate);

    // 4. Another alert attempt can be recorded even while event is Indeterminate
    let attempt3 = AlertEffectRecord {
        operation_id: OperationId::parse("op:alert-retry-002")?,
        obligation_id: alert_ob,
        event_revision: lineage.current_revision(),
        event_revision_digest: lineage.current().revision_digest(),
        effect_state: EffectState::Committed,
        timestamp_ns: TimestampNs(1_700_000_003_000_000_000),
        channel: "webhook:ops-pager".to_string(),
        observation_receipt: None,
        failure_reason: None,
    };
    lineage.record_alert_attempt(attempt3)?;
    assert_eq!(lineage.current_state(), EventState::Indeterminate);
    assert_eq!(lineage.alert_attempts().len(), 3);

    // 5. Only when observation receipt is verified does event legally transition to AlertDelivered
    let receipt_digest = ContentDigest::sha256(b"provider-observation-receipt:valid-ack");
    let ev_alert = sample_evidence("provider:webhook", true, "valid-receipt");
    lineage.transition(transition_params(
        EventState::AlertDelivered,
        vec![ev1, ev2, ev_alert],
        None,
        false,
    ))?;
    assert_eq!(lineage.current_state(), EventState::AlertDelivered);

    let attempt_verified = AlertEffectRecord {
        operation_id: alert_op,
        obligation_id: ObligationId::parse("obligation:alert-proof-001")?,
        event_revision: lineage.current_revision(),
        event_revision_digest: lineage.current().revision_digest(),
        effect_state: EffectState::Verified,
        timestamp_ns: TimestampNs(1_700_000_004_000_000_000),
        channel: "webhook:ops-pager".to_string(),
        observation_receipt: Some(receipt_digest),
        failure_reason: None,
    };
    lineage.record_alert_attempt(attempt_verified)?;
    assert_eq!(lineage.alert_attempts().len(), 4);

    lineage.verify()?;
    Ok(())
}

#[test]
fn test_chain_tamper_detection() -> Result<(), Box<dyn Error>> {
    let genesis = sample_genesis_hypothesis("tamper-001")?;

    // Tamper 1: Genesis with revision != 1 rejected
    let mut bad_genesis_rev = genesis.clone();
    bad_genesis_rev.revision = 2;
    bad_genesis_rev.supersedes = Some(ContentDigest::sha256(b"fake-prior"));
    let Err(err) = EventLineage::new(bad_genesis_rev) else {
        return Err("expected RevisionNotMonotonic".into());
    };
    assert_eq!(
        err,
        EventTransitionError::RevisionNotMonotonic {
            expected: 1,
            actual: 2
        }
    );

    // Tamper 2: Genesis with supersedes Some rejected
    let mut bad_genesis_sup = genesis.clone();
    bad_genesis_sup.supersedes = Some(ContentDigest::sha256(b"fake-prior"));
    let Err(err) = EventLineage::new(bad_genesis_sup) else {
        return Err("expected Contradiction".into());
    };
    assert!(matches!(
        err,
        EventTransitionError::Contradiction {
            field: "supersedes",
            ..
        }
    ));

    // Tamper 3: Genesis not in Hypothesized state rejected
    let mut bad_genesis_state = genesis.clone();
    bad_genesis_state.state = EventState::Corroborated;
    bad_genesis_state.evidence = vec![
        sample_evidence("cam-1", true, "1"),
        sample_evidence("cam-2", true, "2"),
    ];
    let Err(err) = EventLineage::new(bad_genesis_state) else {
        return Err("expected IllegalStateTransition".into());
    };
    assert!(matches!(
        err,
        EventTransitionError::IllegalStateTransition {
            from: EventState::Hypothesized,
            to: EventState::Corroborated,
            ..
        }
    ));

    // Tamper 4: EventId mismatch in chain
    let ev1 = sample_evidence("camera:cam-north", true, "motion");
    let p_bad_id = transition_params(EventState::Witnessed, vec![ev1], None, false);
    // Alter event_id via from_revisions
    let rev2 = genesis.supersede(fss_core::event::EventSupersedeParams {
        state: EventState::Witnessed,
        kind: EventKind::PerimeterBreach,
        interval: p_bad_id.interval,
        uncertainty_reason: None,
        zone_ids: p_bad_id.zone_ids.clone(),
        track_ids: p_bad_id.track_ids.clone(),
        probability: p_bad_id.probability,
        evidence: p_bad_id.evidence.clone(),
        model_receipts: p_bad_id.model_receipts.clone(),
        decision_path: p_bad_id.decision_path.clone(),
    })?;
    let mut rev2_tampered_id = rev2.clone();
    rev2_tampered_id.event_id = EventId::parse("event:forged-id")?;
    let Err(err) = EventLineage::from_revisions(vec![genesis.clone(), rev2_tampered_id]) else {
        return Err("expected EventIdMismatch".into());
    };
    assert!(matches!(err, EventTransitionError::EventIdMismatch { .. }));

    // Tamper 5: Fork / predecessor digest mismatch
    let mut rev2_tampered_digest = rev2;
    rev2_tampered_digest.supersedes = Some(ContentDigest::sha256(b"wrong-prior-digest"));
    let Err(err) = EventLineage::from_revisions(vec![genesis, rev2_tampered_digest]) else {
        return Err("expected DigestMismatch".into());
    };
    assert!(matches!(err, EventTransitionError::DigestMismatch { .. }));

    Ok(())
}

#[test]
fn test_bounds_at_bound_and_bound_plus_one() -> Result<(), Box<dyn Error>> {
    // 1. AlertEffectRecord channel bounds: MAX_ALERT_CHANNEL_LEN = 256
    let op = OperationId::parse("op:bound-001")?;
    let ob = ObligationId::parse("obligation:bound-001")?;
    let mut record = AlertEffectRecord {
        operation_id: op.clone(),
        obligation_id: ob.clone(),
        event_revision: 1,
        event_revision_digest: ContentDigest::sha256(b"rev1"),
        effect_state: EffectState::Prepared,
        timestamp_ns: TimestampNs(0),
        channel: "a".repeat(MAX_ALERT_CHANNEL_LEN),
        observation_receipt: None,
        failure_reason: None,
    };
    record.verify()?;

    record.channel = "a".repeat(MAX_ALERT_CHANNEL_LEN + 1);
    let Err(err) = record.verify() else {
        return Err("expected OverLimitLength".into());
    };
    assert_eq!(
        err,
        EventTransitionError::OverLimitLength {
            field: "alert_record.channel",
            limit: MAX_ALERT_CHANNEL_LEN,
            actual: MAX_ALERT_CHANNEL_LEN + 1
        }
    );

    // 2. AlertEffectRecord failure_reason bounds: MAX_ALERT_FAILURE_REASON_LEN = 512
    record.channel = "sms".to_string();
    record.failure_reason = Some("f".repeat(MAX_ALERT_FAILURE_REASON_LEN));
    record.verify()?;

    record.failure_reason = Some("f".repeat(MAX_ALERT_FAILURE_REASON_LEN + 1));
    let Err(err) = record.verify() else {
        return Err("expected OverLimitLength".into());
    };
    assert_eq!(
        err,
        EventTransitionError::OverLimitLength {
            field: "alert_record.failure_reason",
            limit: MAX_ALERT_FAILURE_REASON_LEN,
            actual: MAX_ALERT_FAILURE_REASON_LEN + 1
        }
    );

    // 3. Evidence count bounds on transition: MAX_EVIDENCE_COUNT = 256
    let genesis = sample_genesis_hypothesis("bound-ev-001")?;
    let mut lineage = EventLineage::new(genesis)?;

    let mut at_limit_evidence = Vec::with_capacity(MAX_EVIDENCE_COUNT);
    for i in 0..MAX_EVIDENCE_COUNT {
        at_limit_evidence.push(sample_evidence(
            &format!("cam-{}", i),
            true,
            &format!("w-{}", i),
        ));
    }
    assert_eq!(at_limit_evidence.len(), MAX_EVIDENCE_COUNT);
    let p_at_limit = transition_params(
        EventState::Witnessed,
        at_limit_evidence.clone(),
        None,
        false,
    );
    lineage.transition(p_at_limit)?;
    assert_eq!(lineage.current().evidence.len(), MAX_EVIDENCE_COUNT);

    // Over limit: MAX_EVIDENCE_COUNT + 1
    let mut over_limit_evidence = at_limit_evidence;
    over_limit_evidence.push(sample_evidence("cam-extra", true, "w-extra"));
    assert_eq!(over_limit_evidence.len(), MAX_EVIDENCE_COUNT + 1);
    let p_over_limit =
        transition_params(EventState::Corroborated, over_limit_evidence, None, false);
    let Err(err) = lineage.transition(p_over_limit) else {
        return Err("expected OverLimitLength".into());
    };
    assert!(matches!(
        err,
        EventTransitionError::Decode(fss_core::event::EventDecodeError::OverLimitLength {
            field: "evidence",
            limit: 256,
            actual: 257
        })
    ));

    // 4. Lineage depth bounds: MAX_LINEAGE_DEPTH = 256
    assert_eq!(MAX_LINEAGE_DEPTH, 256);
    assert_eq!(MAX_ALERT_ATTEMPTS_COUNT, 64);

    Ok(())
}

#[test]
fn test_lineage_replay_from_evidence_deltas() -> Result<(), Box<dyn Error>> {
    let genesis = sample_genesis_hypothesis("replay-event-001")?;
    let event_id = genesis.event_id.clone();
    let mut lineage = EventLineage::new(genesis)?;

    let ev1 = sample_evidence("camera:cam-north", true, "motion");
    lineage.transition(transition_params(
        EventState::Witnessed,
        vec![ev1.clone()],
        None,
        false,
    ))?;
    let ev2 = sample_evidence("radar:radar-north", true, "track");
    lineage.transition(transition_params(
        EventState::Corroborated,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    ))?;
    lineage.transition(transition_params(
        EventState::Adjudicated,
        vec![ev1.clone(), ev2.clone()],
        None,
        false,
    ))?;
    lineage.transition(transition_params(
        EventState::Resolved,
        vec![ev1, ev2],
        None,
        false,
    ))?;

    // Create EvidenceDelta records from the lineage history
    let history = lineage.history();
    let mut deltas = Vec::new();
    let mut payload_map = std::collections::BTreeMap::new();

    for rev in history {
        let payload_digest = rev.revision_digest();
        payload_map.insert(payload_digest, rev.clone());

        deltas.push(EvidenceDelta {
            delta_id: format!("delta:{}", rev.revision),
            family: "event_revision".to_string(),
            object_id: ObjectId::parse(rev.event_id.as_str())?,
            prior_generation: if rev.revision > 1 {
                Some(rev.revision - 1)
            } else {
                None
            },
            new_generation: rev.revision,
            validity: rev.interval,
            plane: Plane::Cognition,
            payload_digest,
            witness_digest: Some(rev.revision_digest()),
            operation_id: None,
        });
    }

    // Replay the lineage from deltas
    let replayed =
        EventLineage::replay_from_deltas(&event_id, &deltas, |d| payload_map.get(d).cloned())?;

    assert_eq!(replayed.len(), lineage.len());
    assert_eq!(replayed.current_revision(), lineage.current_revision());
    assert_eq!(replayed.current_state(), lineage.current_state());
    assert_eq!(
        replayed.current().revision_digest(),
        lineage.current().revision_digest()
    );
    replayed.verify()?;

    Ok(())
}

#[test]
fn test_transition_table_completeness_and_invariants() -> Result<(), Box<dyn Error>> {
    // Verify that all registered rules have consistent terminal flags and valid states
    for rule in EVENT_TRANSITION_TABLE {
        assert!(is_allowed_event_transition(rule.from, rule.to, true));
        assert_eq!(rule.terminal, rule.to.is_terminal());
        assert!(
            !rule.from.is_terminal(),
            "no transitions out of terminal states"
        );
    }

    // Direct check: cannot transition out of terminal states
    for &target in &[
        EventState::Hypothesized,
        EventState::Witnessed,
        EventState::Corroborated,
        EventState::Adjudicated,
        EventState::AlertDelivered,
        EventState::Resolved,
        EventState::Indeterminate,
        EventState::Rejected,
    ] {
        assert!(!is_allowed_event_transition(
            EventState::Resolved,
            target,
            true
        ));
        assert!(!is_allowed_event_transition(
            EventState::Rejected,
            target,
            true
        ));
    }

    // Check helper get_event_transition_rule
    let Some(rule) = get_event_transition_rule(EventState::Witnessed, EventState::Corroborated)
    else {
        return Err("rule exists".into());
    };
    assert!(!rule.requires_urgent_exception);
    assert_eq!(rule.to, EventState::Corroborated);

    let Some(urgent_rule) =
        get_event_transition_rule(EventState::Witnessed, EventState::Adjudicated)
    else {
        return Err("urgent rule exists".into());
    };
    assert!(urgent_rule.requires_urgent_exception);
    Ok(())
}

// Helper: sample alert effect record for Finding 4 tests
fn sample_alert_effect_record() -> Result<AlertEffectRecord, Box<dyn Error>> {
    let operation_id = OperationId::parse("op:alert-test-001")?;
    let obligation_id = ObligationId::parse("ob:alert-test-001")?;
    Ok(AlertEffectRecord {
        operation_id,
        obligation_id,
        event_revision: 2,
        event_revision_digest: ContentDigest::sha256(b"revision:2:digest"),
        effect_state: EffectState::Prepared,
        timestamp_ns: TimestampNs(1_700_000_002_000_000_000),
        channel: "webhook:ops-channel".to_string(),
        observation_receipt: Some(ContentDigest::sha256(b"receipt:webhook:ack")),
        failure_reason: None,
    })
}

#[test]
fn test_finding_1_indeterminate_reconciliation_cannot_bypass_corroboration_or_urgent_exception()
-> Result<(), Box<dyn Error>> {
    let genesis = sample_genesis_hypothesis("bypass-001")?;
    let mut lineage = EventLineage::new(genesis)?;
    let ev1 = sample_evidence("camera:cam1", true, "motion");

    lineage.transition(transition_params(
        EventState::Witnessed,
        vec![ev1.clone()],
        None,
        false,
    ))?;

    lineage.transition(transition_params(
        EventState::Indeterminate,
        vec![ev1.clone()],
        None,
        false,
    ))?;

    // Negative case 1: Reconciling Indeterminate -> Adjudicated with only 1 failure domain and urgent_single_sensor = false fails
    let Err(err1) = lineage.transition(transition_params(
        EventState::Adjudicated,
        vec![ev1.clone()],
        None,
        false,
    )) else {
        return Err("reconciling Indeterminate -> Adjudicated without corroboration or urgent exception must fail".into());
    };
    assert_eq!(err1, EventTransitionError::UrgentExceptionRequired);

    // Negative case 2: urgent_single_sensor = true, but missing required SINGLE_DOMAIN_UNCONFIRMED_LABEL in uncertainty_reason
    let Err(err2) = lineage.transition(transition_params(
        EventState::Adjudicated,
        vec![ev1.clone()],
        Some("unlabeled urgency".to_string()),
        true,
    )) else {
        return Err("urgent reconciliation without explicit label must fail".into());
    };
    assert!(matches!(
        err2,
        EventTransitionError::Contradiction {
            field: "uncertainty_reason",
            ..
        }
    ));

    // Positive case A: Reconciling with urgent_single_sensor = true AND explicit label succeeds
    let mut lineage_urgent = lineage.clone();
    lineage_urgent.transition(transition_params(
        EventState::Adjudicated,
        vec![ev1.clone()],
        Some(format!(
            "{SINGLE_DOMAIN_UNCONFIRMED_LABEL}: single camera urgent breach confirmation"
        )),
        true,
    ))?;
    assert_eq!(lineage_urgent.current().state, EventState::Adjudicated);

    // Positive case B: Reconciling with >= 2 independent failure domains (corroboration) succeeds without urgent exception
    let ev2 = sample_evidence("radar:rad1", true, "doppler");
    lineage.transition(transition_params(
        EventState::Adjudicated,
        vec![ev1, ev2],
        None,
        false,
    ))?;
    assert_eq!(lineage.current().state, EventState::Adjudicated);
    Ok(())
}

#[test]
fn test_finding_2_from_revisions_enforces_corroboration_and_evidence_invariants()
-> Result<(), Box<dyn Error>> {
    let genesis = sample_genesis_hypothesis("from-rev-001")?;
    let ev_single = sample_evidence("camera:cam1", true, "motion");

    let rev2 = genesis.supersede(EventSupersedeParams {
        state: EventState::Witnessed,
        kind: EventKind::PerimeterBreach,
        interval: sample_interval(),
        uncertainty_reason: None,
        zone_ids: vec!["zone:perimeter-north".into()],
        track_ids: vec!["track:tr-001".into()],
        probability: certain_probability(),
        evidence: vec![ev_single.clone()],
        model_receipts: vec![],
        decision_path: sample_decision_path("rev2"),
    })?;

    // Revision claiming Corroborated with only 1 failure domain must be rejected by from_revisions
    let rev3_single_domain = EventHypothesis {
        schema: EVENT_HYPOTHESIS_SCHEMA.to_string(),
        event_id: genesis.event_id.clone(),
        revision: 3,
        supersedes: Some(rev2.revision_digest()),
        state: EventState::Corroborated,
        kind: EventKind::PerimeterBreach,
        interval: sample_interval(),
        uncertainty_reason: None,
        zone_ids: vec!["zone:perimeter-north".into()],
        track_ids: vec!["track:tr-001".into()],
        probability: certain_probability(),
        evidence: vec![ev_single.clone()],
        model_receipts: vec![],
        decision_path: sample_decision_path("rev3-corroborated-single"),
    };

    let Err(err_corr) =
        EventLineage::from_revisions(vec![genesis.clone(), rev2.clone(), rev3_single_domain])
    else {
        return Err(
            "from_revisions must reject Corroborated revision with < 2 failure domains".into(),
        );
    };
    assert!(
        matches!(err_corr, EventTransitionError::CorroborationRequired { .. }),
        "from_revisions must return CorroborationRequired, got: {err_corr:?}"
    );

    // Revision with empty evidence in post-hypothesis state must be rejected by from_revisions
    let rev3_empty = EventHypothesis {
        schema: EVENT_HYPOTHESIS_SCHEMA.to_string(),
        event_id: genesis.event_id.clone(),
        revision: 3,
        supersedes: Some(rev2.revision_digest()),
        state: EventState::Witnessed,
        kind: EventKind::PerimeterBreach,
        interval: sample_interval(),
        uncertainty_reason: None,
        zone_ids: vec!["zone:perimeter-north".into()],
        track_ids: vec!["track:tr-001".into()],
        probability: certain_probability(),
        evidence: vec![],
        model_receipts: vec![],
        decision_path: sample_decision_path("rev3-empty"),
    };

    let Err(err_empty) = EventLineage::from_revisions(vec![genesis.clone(), rev2, rev3_empty])
    else {
        return Err(
            "from_revisions must reject post-hypothesis revision with empty evidence".into(),
        );
    };
    assert_eq!(err_empty, EventTransitionError::EvidenceRequired);

    // Lineage depth bound check in from_revisions / append_verified_revision
    let mut deep_chain = Vec::with_capacity(MAX_LINEAGE_DEPTH + 1);
    let mut prev = sample_genesis_hypothesis("deep-lineage-001")?;
    deep_chain.push(prev.clone());
    for rev_num in 2..=(MAX_LINEAGE_DEPTH as u64 + 1) {
        let tag = format!("w-{rev_num}");
        let ev = vec![sample_evidence("camera:cam1", true, &tag)];
        let curr = EventHypothesis {
            schema: EVENT_HYPOTHESIS_SCHEMA.to_string(),
            event_id: prev.event_id.clone(),
            revision: rev_num,
            supersedes: Some(prev.revision_digest()),
            state: EventState::Indeterminate,
            kind: EventKind::PerimeterBreach,
            interval: sample_interval(),
            uncertainty_reason: Some("ongoing tracking".to_string()),
            zone_ids: vec!["zone:perimeter-north".into()],
            track_ids: vec!["track:tr-001".into()],
            probability: certain_probability(),
            evidence: ev,
            model_receipts: vec![],
            decision_path: sample_decision_path("deep"),
        };
        prev = curr.clone();
        deep_chain.push(curr);
    }
    assert_eq!(deep_chain.len(), MAX_LINEAGE_DEPTH + 1);
    let Err(err_depth) = EventLineage::from_revisions(deep_chain) else {
        return Err("from_revisions must reject chain exceeding MAX_LINEAGE_DEPTH".into());
    };
    assert!(
        matches!(
            err_depth,
            EventTransitionError::OverLimitLength {
                limit: 256,
                actual: 257,
                ..
            }
        ),
        "expected OverLimitLength for depth, got: {err_depth:?}"
    );

    Ok(())
}

#[test]
fn test_finding_3_event_hypothesis_supersede_and_chain_reject_terminal_and_illegal_transitions()
-> Result<(), Box<dyn Error>> {
    let genesis = sample_genesis_hypothesis("term-001")?;
    let ev1 = sample_evidence("camera:cam1", true, "motion");

    let rejected = genesis.supersede(EventSupersedeParams {
        state: EventState::Rejected,
        kind: EventKind::PerimeterBreach,
        interval: sample_interval(),
        uncertainty_reason: Some("false alarm confirmed".into()),
        zone_ids: vec!["zone:perimeter-north".into()],
        track_ids: vec!["track:tr-001".into()],
        probability: certain_probability(),
        evidence: vec![ev1.clone()],
        model_receipts: vec![],
        decision_path: sample_decision_path("reject"),
    })?;

    // Attempting to supersede a terminal event (Rejected) back to Witnessed must fail closed
    let Err(err_resurrect) = rejected.supersede(EventSupersedeParams {
        state: EventState::Witnessed,
        kind: EventKind::PerimeterBreach,
        interval: sample_interval(),
        uncertainty_reason: None,
        zone_ids: vec!["zone:perimeter-north".into()],
        track_ids: vec!["track:tr-001".into()],
        probability: certain_probability(),
        evidence: vec![ev1.clone()],
        model_receipts: vec![],
        decision_path: sample_decision_path("resurrect"),
    }) else {
        return Err("superseding a terminal event must fail closed".into());
    };
    assert!(matches!(
        err_resurrect,
        EventDecodeError::Contradiction { field: "state", .. }
    ));

    // Attempting an illegal transition directly from Hypothesized to Resolved via supersede must fail
    let Err(err_illegal) = genesis.supersede(EventSupersedeParams {
        state: EventState::Resolved,
        kind: EventKind::PerimeterBreach,
        interval: sample_interval(),
        uncertainty_reason: None,
        zone_ids: vec!["zone:perimeter-north".into()],
        track_ids: vec!["track:tr-001".into()],
        probability: certain_probability(),
        evidence: vec![ev1.clone()],
        model_receipts: vec![],
        decision_path: sample_decision_path("illegal-jump"),
    }) else {
        return Err("illegal transition via supersede must fail".into());
    };
    assert!(matches!(
        err_illegal,
        EventDecodeError::Contradiction { field: "state", .. }
    ));

    // verify_chain must also reject a chain containing a resurrection after a terminal state
    let resurrected_rev = EventHypothesis {
        schema: EVENT_HYPOTHESIS_SCHEMA.to_string(),
        event_id: genesis.event_id.clone(),
        revision: 3,
        supersedes: Some(rejected.revision_digest()),
        state: EventState::Witnessed,
        kind: EventKind::PerimeterBreach,
        interval: sample_interval(),
        uncertainty_reason: None,
        zone_ids: vec!["zone:perimeter-north".into()],
        track_ids: vec!["track:tr-001".into()],
        probability: certain_probability(),
        evidence: vec![ev1],
        model_receipts: vec![],
        decision_path: sample_decision_path("chain-resurrect"),
    };

    let chain = vec![genesis, rejected, resurrected_rev];
    let Err(err_chain) = EventHypothesis::verify_chain(&chain) else {
        return Err("verify_chain must reject chain resurrecting terminal state".into());
    };
    assert!(matches!(
        err_chain,
        EventDecodeError::Contradiction {
            field: "chain.state",
            ..
        }
    ));

    Ok(())
}

#[test]
fn test_finding_4_alert_effect_record_canonical_domain_prefix_and_codec()
-> Result<(), Box<dyn Error>> {
    let record = sample_alert_effect_record()?;
    let bytes = record.canonical_bytes();

    let mut expected_prefix = CanonicalEncoder::new();
    expected_prefix.text("fss.canonical.v1");
    expected_prefix.text("fss.alert_effect_record.v1");
    let prefix_bytes = expected_prefix.finish();

    assert!(
        bytes.starts_with(&prefix_bytes),
        "AlertEffectRecord::canonical_bytes must be prefixed with root 'fss.canonical.v1' domain tag"
    );

    // Symmetric round-trip test via from_canonical_bytes
    let decoded = AlertEffectRecord::from_canonical_bytes(&bytes)?;
    assert_eq!(decoded, record);

    // CanonicalDecode trait test over payload without the root canonical tag
    let mut decoder = CanonicalDecoder::new(&bytes);
    let root_tag = decoder.text().map_err(|e| format!("{e:?}"))?;
    assert_eq!(root_tag, "fss.canonical.v1");
    let decoded_trait =
        AlertEffectRecord::decode_canonical(&mut decoder).map_err(|e| format!("{e:?}"))?;
    assert_eq!(decoded_trait, record);
    assert!(decoder.is_empty());

    Ok(())
}
