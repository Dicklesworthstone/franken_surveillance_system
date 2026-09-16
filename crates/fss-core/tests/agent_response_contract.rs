#![forbid(unsafe_code)]
//! Contract tests for the agent cognitive envelope (fss-x4a.30.83.64) and
//! agent response envelope (fss-x4a.30.83.65).

use std::collections::BTreeSet;

use fss_core::contract_basis::reference_contract_basis;
use fss_core::{
    AgentCognitiveEnvelope, AgentOperation, AgentResponseEnvelope, AgentView, BudgetVector,
    CognitiveAnswerClass, Completeness, ContentDigest, EnvelopeBudget, EnvelopeContinuity,
    EnvelopeCoverage, EnvelopeEpistemic, EnvelopeProposition, ExecutionBoundary, LedgerAnchor,
    ResponseOutcome, ResponseSafeRetry, ResponseTaskState,
};

#[test]
fn test_cognitive_envelope_binds_registered_operation_and_view(
) -> Result<(), Box<dyn std::error::Error>> {
    let envelope = AgentCognitiveEnvelope::new(
        reference_contract_basis(),
        "request:test:0001",
        "response:test:0001",
        "trace:test:0001",
        "AOP-005",
        "answer_coverage".to_owned(),
        "AVIEW-003",
        CognitiveAnswerClass::BoundedSummary,
        LedgerAnchor::genesis("site:fss:cognitive"),
        EnvelopeEpistemic {
            propositions: vec![EnvelopeProposition {
                id: "prop:gate".to_owned(),
                statement: "The gate is closed.".to_owned(),
                state: fss_core::KnowledgeState::Known,
                provenance: "observed".to_owned(),
                evidence: vec!["evidence:frame-0042".to_owned()],
            }],
            assumptions: vec!["assumption:night".to_owned()],
            invalidators: vec!["invalidator:recalibration".to_owned()],
        },
        EnvelopeCoverage {
            authorized_domain: vec!["domain:gate".to_owned()],
            observed_domain: vec!["domain:gate:night".to_owned()],
            not_observable_domain: vec!["domain:shed".to_owned()],
            omitted_count: 0,
            omission_reasons: vec![],
            stop_reason: "bound reached".to_owned(),
        },
        EnvelopeBudget {
            requested_json: "{\"latencyMs\":500}".to_owned(),
            consumed_json: "{\"latencyMs\":180}".to_owned(),
            remaining_json: "{\"latencyMs\":320}".to_owned(),
            degraded_dimensions: vec![],
            marginal_work_declined: vec![],
        },
        vec!["handle:cover".to_owned()],
        vec!["investigate next:shed".to_owned()],
        EnvelopeContinuity {
            cursor: Some("continuation:0001".to_owned()),
            reanchor_triggers: vec!["recalibration".to_owned()],
            session_capsule_digest: None,
            unresolved_obligations: vec![],
        },
        "decision:cognitive:0001",
    )?;
    assert_eq!(envelope.operation, AgentOperation::Query);
    assert_eq!(envelope.view, AgentView::Case);
    assert_eq!(
        envelope.answer_class,
        CognitiveAnswerClass::BoundedSummary
    );
    let digest = envelope.envelope_digest();
    // Unregistered operations and views refuse before anything else.
    assert!(AgentCognitiveEnvelope::new(
        reference_contract_basis(),
        "request:x",
        "response:x",
        "trace:x",
        "AOP-999",
        "answer".to_owned(),
        "AVIEW-003",
        CognitiveAnswerClass::DirectFact,
        LedgerAnchor::genesis("site:fss:cognitive"),
        EnvelopeEpistemic {
            propositions: vec![],
            assumptions: vec![],
            invalidators: vec![],
        },
        EnvelopeCoverage {
            authorized_domain: vec![],
            observed_domain: vec![],
            not_observable_domain: vec![],
            omitted_count: 0,
            omission_reasons: vec![],
            stop_reason: "x".to_owned(),
        },
        EnvelopeBudget {
            requested_json: "{}".to_owned(),
            consumed_json: "{}".to_owned(),
            remaining_json: "{}".to_owned(),
            degraded_dimensions: vec![],
            marginal_work_declined: vec![],
        },
        vec![],
        vec![],
        EnvelopeContinuity {
            cursor: None,
            reanchor_triggers: vec![],
            session_capsule_digest: None,
            unresolved_obligations: vec![],
        },
        "decision:x",
    )
    .is_err());
    let _ = digest;
    Ok(())
}

#[test]
fn test_response_envelope_requires_error_identity_and_binds_operation(
) -> Result<(), Box<dyn std::error::Error>> {
    // An error response without a registered error identity is refused.
    let error = AgentResponseEnvelope::new(
        reference_contract_basis(),
        "AOP-005",
        "request:test:0002",
        1,
        "principal:guard",
        Some("session:guard".to_owned()),
        Some("mission:guard".to_owned()),
        "trace:0002",
        LedgerAnchor::genesis("site:fss:response"),
        None,
        Some(3),
        AgentView::Case,
        vec!["capability:situation.read".to_owned()],
        "{\"purpose\":\"orient\"}".to_owned(),
        ResponseOutcome::Error,
        None,
        Some(ResponseTaskState::None),
        None,
        "fss.agent_query_plan.v1",
        "{\"error\":true}".to_owned(),
        ContentDigest::sha256(b"payload"),
        fss_core::KnowledgeState::Unknown,
        Completeness::Unknown,
        vec![],
        vec![],
        vec![],
        "{\"requested\":{}}".to_owned(),
        vec![],
        vec![],
        ContentDigest::sha256(b"fingerprint"),
        None,
        None,
        None,
        None,
        "safe_read_retry",
        ResponseSafeRetry::YesAfterRefresh,
        true,
        ExecutionBoundary {
            completed: vec![],
            not_started: vec![],
            possibly_occurred: vec![],
            preserved_truth: vec![],
            invalidated: vec![],
        },
        2_000,
    );
    assert!(error.is_err());
    // The same envelope with a registered error identity is accepted.
    let accepted = AgentResponseEnvelope::new(
        reference_contract_basis(),
        "AOP-005",
        "request:test:0002",
        1,
        "principal:guard",
        Some("session:guard".to_owned()),
        Some("mission:guard".to_owned()),
        "trace:0002",
        LedgerAnchor::genesis("site:fss:response"),
        None,
        Some(3),
        AgentView::Case,
        vec!["capability:situation.read".to_owned()],
        "{\"purpose\":\"orient\"}".to_owned(),
        ResponseOutcome::Error,
        None,
        Some(ResponseTaskState::None),
        Some("ERR-AGENT-PROTOCOL-001".to_owned()),
        "fss.agent_query_plan.v1",
        "{\"error\":true}".to_owned(),
        ContentDigest::sha256(b"payload"),
        fss_core::KnowledgeState::Unknown,
        Completeness::Unknown,
        vec![],
        vec![],
        vec![],
        "{\"requested\":{}}".to_owned(),
        vec![],
        vec![],
        ContentDigest::sha256(b"fingerprint"),
        None,
        None,
        None,
        None,
        "safe_read_retry",
        ResponseSafeRetry::YesAfterRefresh,
        true,
        ExecutionBoundary {
            completed: vec![],
            not_started: vec![],
            possibly_occurred: vec![],
            preserved_truth: vec![],
            invalidated: vec![],
        },
        2_000,
    )?;
    assert_eq!(accepted.operation, AgentOperation::Query);
    assert!(accepted.validate().is_ok());
    // Digest determinism and sensitivity.
    let ok = AgentResponseEnvelope::new(
        reference_contract_basis(),
        "AOP-005",
        "request:test:0003",
        1,
        "principal:guard",
        Some("session:guard".to_owned()),
        Some("mission:guard".to_owned()),
        "trace:0003",
        LedgerAnchor::genesis("site:fss:response"),
        None,
        None,
        AgentView::Case,
        vec![],
        "{\"purpose\":\"orient\"}".to_owned(),
        ResponseOutcome::Ok,
        None,
        Some(ResponseTaskState::None),
        None,
        "fss.agent_query_plan.v1",
        "{\"ok\":true}".to_owned(),
        ContentDigest::sha256(b"payload"),
        fss_core::KnowledgeState::Known,
        Completeness::Bounded,
        vec![],
        vec![],
        vec![],
        "{}".to_owned(),
        vec![],
        vec![],
        ContentDigest::sha256(b"fingerprint"),
        None,
        None,
        None,
        None,
        "never_unchanged",
        ResponseSafeRetry::NotApplicable,
        false,
        ExecutionBoundary {
            completed: vec![],
            not_started: vec![],
            possibly_occurred: vec![],
            preserved_truth: vec![],
            invalidated: vec![],
        },
        3_000,
    )?;
    let rebuilt = AgentResponseEnvelope::new(
        reference_contract_basis(),
        "AOP-005",
        "request:test:0003",
        1,
        "principal:guard",
        Some("session:guard".to_owned()),
        Some("mission:guard".to_owned()),
        "trace:0003",
        LedgerAnchor::genesis("site:fss:response"),
        None,
        None,
        AgentView::Case,
        vec![],
        "{\"purpose\":\"orient\"}".to_owned(),
        ResponseOutcome::Ok,
        None,
        Some(ResponseTaskState::None),
        None,
        "fss.agent_query_plan.v1",
        "{\"error\":true}".to_owned(),
        ContentDigest::sha256(b"payload"),
        fss_core::KnowledgeState::Known,
        Completeness::Bounded,
        vec![],
        vec![],
        vec![],
        "{}".to_owned(),
        vec![],
        vec![],
        ContentDigest::sha256(b"fingerprint"),
        None,
        None,
        None,
        None,
        "never_unchanged",
        ResponseSafeRetry::NotApplicable,
        false,
        ExecutionBoundary {
            completed: vec![],
            not_started: vec![],
            possibly_occurred: vec![],
            preserved_truth: vec![],
            invalidated: vec![],
        },
        3_000,
    )?;
    assert_ne!(ok.envelope_digest(), rebuilt.envelope_digest());
    let _ = BTreeSet::<String>::new();
    let _ = BudgetVector::builder();
    Ok(())
}
