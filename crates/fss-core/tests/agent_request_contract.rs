#![forbid(unsafe_code)]
//! Contract tests for the `fss/1` agent request envelope (fss-x4a.30.83.40).

use std::collections::BTreeSet;

use fss_core::contract_basis::reference_contract_basis;
use fss_core::{
    admit_query_read, AgentOperation, AgentRequestEnvelopeParams, AgentView, BudgetVector,
    ContentDigest, ContractBasisError, ContractError, HydrationLevel, LedgerAnchor, MissionId,
    PrincipalId, PrivacyProjection, RequestTaint, SessionId, TimestampNs,
};

fn envelope_params(operation_name: &str) -> AgentRequestEnvelopeParams {
    AgentRequestEnvelopeParams {
        contract_basis: reference_contract_basis(),
        operation_name: operation_name.to_owned(),
        request_id: "request:test:0001".to_owned(),
        principal_id: PrincipalId::parse("principal:test").unwrap_or_else(|_| unreachable!()),
        session_id: SessionId::parse("session:test").unwrap_or_else(|_| unreachable!()),
        mission_id: MissionId::parse("mission:test").unwrap_or_else(|_| unreachable!()),
        input_anchor: Some(LedgerAnchor::genesis("site:fss:request")),
        expected_workspace_revision: Some(3),
        view_id: "AVIEW-002".to_owned(),
        target_uris: vec!["fss://mission/test".to_owned()],
        payload_schema: "fss.agent_mission.v1".to_owned(),
        payload_json: "{\"revision\":1}".to_owned(),
        budget: BudgetVector::builder().latency_ms(500).build().unwrap_or_else(|_| unreachable!()),
        deadline_ns: Some(9_000),
        privacy: PrivacyProjection {
            purpose: "orient the mission".to_owned(),
            policy_generation_id: "policy:privacy:v1".to_owned(),
            allowed_domains: vec!["domain:situation".to_owned()],
            redacted_domains: vec!["domain:identity".to_owned()],
        },
        idempotency_key: None,
        continuation: None,
        expected_decision_fingerprint: None,
        max_hydration_level: HydrationLevel::H1,
        accept_compression: true,
        taint: RequestTaint {
            contains_untrusted_control_text: false,
            sources: vec![],
        },
        created_at: TimestampNs(1_000),
    }
}

#[test]
fn test_request_envelope_resolves_registered_operation(
) -> Result<(), Box<dyn std::error::Error>> {
    let envelope =
        fss_core::AgentRequestEnvelope::new(envelope_params("session.open"))?;
    assert_eq!(envelope.operation(), AgentOperation::SessionOpen);
    assert_eq!(envelope.view(), AgentView::Brief);
    assert_eq!(envelope.payload_schema(), "fss.agent_mission.v1");
    assert!(envelope.idempotency_key().is_none());
    let digest = envelope.request_digest();
    let again = fss_core::AgentRequestEnvelope::new(envelope_params("session.open"))?;
    assert_eq!(digest, again.request_digest());
    Ok(())
}

#[test]
fn test_request_envelope_payload_schema_must_match_operation_row(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut params = envelope_params("session.open");
    // AOP-001 registers fss.agent_mission.v1; anything else is refused.
    params.payload_schema = "fss.agent_query_plan.v1".to_owned();
    assert_eq!(
        fss_core::AgentRequestEnvelope::new(params),
        Err(ContractBasisError::Contract(
            ContractError::InvalidIdentifier
        ))
    );
    Ok(())
}

#[test]
fn test_request_envelope_refuses_unregistered_and_misbound_inputs(
) -> Result<(), Box<dyn std::error::Error>> {
    // Unregistered operation names fail closed through the basis boundary.
    let mut params = envelope_params("session.superopen");
    assert!(fss_core::AgentRequestEnvelope::new(params.clone()).is_err());
    // Protocol mismatch fails closed.
    params.contract_basis.semantic_protocol = "fss/2".to_owned();
    params.operation_name = "session.open".to_owned();
    assert!(fss_core::AgentRequestEnvelope::new(params).is_err());
    // Unregistered views are refused.
    let mut params = envelope_params("session.open");
    params.view_id = "AVIEW-099".to_owned();
    assert!(fss_core::AgentRequestEnvelope::new(params).is_err());
    // Non-fss targets are refused.
    let mut params = envelope_params("session.open");
    params.target_uris = vec!["https://elsewhere".to_owned()];
    assert!(fss_core::AgentRequestEnvelope::new(params).is_err());
    // Overbound target lists are refused.
    let mut params = envelope_params("session.open");
    params.target_uris = (0..257)
        .map(|index| format!("fss://target/{index}"))
        .collect();
    assert_eq!(
        fss_core::AgentRequestEnvelope::new(params),
        Err(ContractBasisError::Contract(
            ContractError::CountBoundExceeded
        ))
    );
    // Inverted deadlines are refused.
    let mut params = envelope_params("session.open");
    params.deadline_ns = Some(1_000);
    assert_eq!(
        fss_core::AgentRequestEnvelope::new(params),
        Err(ContractBasisError::Contract(
            ContractError::InvertedTimeInterval
        ))
    );
    // Empty payloads are refused.
    let mut params = envelope_params("session.open");
    params.payload_json = String::new();
    assert_eq!(
        fss_core::AgentRequestEnvelope::new(params),
        Err(ContractBasisError::Contract(ContractError::EvidenceRequired))
    );
    Ok(())
}

#[test]
fn test_effectful_requests_require_idempotency_key() -> Result<(), Box<dyn std::error::Error>> {
    // AOP-008 commit is effectful: no key, no envelope.
    let mut params = envelope_params("commit");
    params.payload_schema = "fss.agent_control_plan.v1".to_owned();
    params.payload_json = "{}".to_owned();
    params.view_id = "AVIEW-005".to_owned();
    assert_eq!(
        fss_core::AgentRequestEnvelope::new(params.clone()),
        Err(ContractBasisError::Contract(
            ContractError::InvalidEffectTransition
        ))
    );
    params.idempotency_key = Some("idem:commit:0001".to_owned());
    let envelope = fss_core::AgentRequestEnvelope::new(params)?;
    assert_eq!(envelope.operation(), AgentOperation::Commit);
    assert_eq!(envelope.idempotency_key(), Some("idem:commit:0001"));
    // A read-only query never needs the key.
    let anchor = LedgerAnchor::genesis("site:fss:request");
    let query = admit_query_read(
        &reference_contract_basis(),
        &anchor,
        "query",
        10,
        BudgetVector::builder().latency_ms(100).build()?,
    )?;
    let _ = query;
    let _ = BTreeSet::<String>::new();
    Ok(())
}

#[test]
fn test_request_envelope_digest_sensitivity() -> Result<(), Box<dyn std::error::Error>> {
    let first = fss_core::AgentRequestEnvelope::new(envelope_params("session.open"))?;
    let mut params = envelope_params("session.open");
    params.accept_compression = !params.accept_compression;
    let second = fss_core::AgentRequestEnvelope::new(params)?;
    assert_ne!(first.request_digest(), second.request_digest());
    // Digest domain separation is pinned by the schema identity.
    assert_eq!(fss_core::AgentRequestEnvelope::SCHEMA, "fss.agent_request_envelope.v1");
    let _ = ContentDigest::sha256(b"anchor");
    Ok(())
}
