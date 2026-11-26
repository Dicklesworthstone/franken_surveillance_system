#![forbid(unsafe_code)]
//! Unknown operation registries and incomplete presentation profiles cannot select legacy rows.

use fss_core::contract_basis::{
    MAX_IDENTIFIER_LEN, hydration_contract_basis, probe_contract_basis, reference_contract_basis,
    registered_operation,
};
use fss_core::{
    AgentCognitiveEnvelope, AgentOperation, AgentRequestEnvelope, AgentRequestEnvelopeParams,
    AgentResponseEnvelope, AgentView, BudgetVector, CognitiveAnswerClass, Completeness,
    ContentDigest, ContractBasis, ContractBasisError, ContractError, EnvelopeBudget,
    EnvelopeContinuity, EnvelopeCoverage, EnvelopeEpistemic, ExecutionBoundary, HydrationLevel,
    KnowledgeState, LedgerAnchor, MissionId, PrincipalId, PrivacyProjection, RequestTaint,
    ResponseOutcome, ResponseSafeRetry, SessionId, TimestampNs,
};

type Test = Result<(), Box<dyn std::error::Error>>;

fn unknown_profiles() -> Vec<ContractBasis> {
    let reference = reference_contract_basis();
    let mut unknown = reference.clone();
    unknown.operation_registry_digest = ContentDigest::sha256(b"unregistered operation semantics");
    let mut partial_probe = probe_contract_basis();
    partial_probe.schema_catalog_digest = reference.schema_catalog_digest;
    let mut partial_hydration = hydration_contract_basis();
    partial_hydration.schema_catalog_digest = reference.schema_catalog_digest;
    let mut rebound_probe = probe_contract_basis();
    rebound_probe.capability_registry_digest = ContentDigest::sha256(b"other capability rows");
    let mut rebound_hydration = hydration_contract_basis();
    rebound_hydration.cost_registry_digest = ContentDigest::sha256(b"other charging rows");
    vec![
        unknown,
        partial_probe,
        partial_hydration,
        rebound_probe,
        rebound_hydration,
    ]
}

fn malformed_bases() -> Vec<(&'static str, ContractBasis)> {
    let mut malformed = Vec::new();
    for invalid in [
        String::new(),
        "bad identity".to_owned(),
        "x".repeat(MAX_IDENTIFIER_LEN + 1),
    ] {
        let mut producer = reference_contract_basis();
        producer.producer_release_id = invalid.clone();
        malformed.push(("producer_release_id", producer));
        let mut ontology = reference_contract_basis();
        ontology.ontology_generation_id = invalid.clone();
        malformed.push(("ontology_generation_id", ontology));
        let mut nightly = reference_contract_basis();
        nightly.accepted_nightly = Some(invalid);
        malformed.push(("accepted_nightly", nightly));
    }
    malformed
}

fn request_params(
    basis: ContractBasis,
    operation: AgentOperation,
) -> Result<AgentRequestEnvelopeParams, Box<dyn std::error::Error>> {
    Ok(AgentRequestEnvelopeParams {
        contract_basis: basis,
        operation_name: operation.name().to_owned(),
        request_id: "request:basis-admission".to_owned(),
        principal_id: PrincipalId::parse("principal:test")?,
        session_id: SessionId::parse("session:test")?,
        mission_id: MissionId::parse("mission:test")?,
        input_anchor: Some(LedgerAnchor::genesis("site:fss:admission")),
        expected_workspace_revision: Some(1),
        view_id: "AVIEW-003".to_owned(),
        target_uris: vec!["fss://mission/test".to_owned()],
        payload_schema: operation.request_payload_schema().to_owned(),
        payload_json: "{}".to_owned(),
        budget: BudgetVector::builder().latency_ms(500).build()?,
        deadline_ns: Some(2_000),
        privacy: PrivacyProjection {
            purpose: "contract admission".to_owned(),
            policy_generation_id: "policy:privacy:v1".to_owned(),
            allowed_domains: vec!["domain:test".to_owned()],
            redacted_domains: vec![],
        },
        idempotency_key: operation.effectful().then(|| "idempotency:test".to_owned()),
        continuation: None,
        expected_decision_fingerprint: None,
        max_hydration_level: HydrationLevel::H1,
        accept_compression: true,
        taint: RequestTaint {
            contains_untrusted_control_text: false,
            sources: vec![],
        },
        created_at: TimestampNs(1_000),
    })
}

fn cognitive(basis: ContractBasis) -> Result<AgentCognitiveEnvelope, ContractBasisError> {
    AgentCognitiveEnvelope::new(
        basis,
        "request:basis-admission",
        "response:basis-admission",
        "trace:basis-admission",
        "query",
        "contract_admission",
        "AVIEW-003",
        CognitiveAnswerClass::BoundedSummary,
        LedgerAnchor::genesis("site:fss:admission"),
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
            stop_reason: "bounded contract fixture".to_owned(),
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
        "decision:basis-admission",
    )
}

fn response(basis: ContractBasis) -> Result<AgentResponseEnvelope, ContractBasisError> {
    AgentResponseEnvelope::new(
        basis,
        "query",
        "request:basis-admission",
        1,
        "principal:test",
        Some("session:test".to_owned()),
        Some("mission:test".to_owned()),
        "trace:basis-admission",
        LedgerAnchor::genesis("site:fss:admission"),
        None,
        Some(1),
        AgentView::Case,
        vec![],
        "{}",
        ResponseOutcome::Ok,
        None,
        None,
        None,
        AgentCognitiveEnvelope::SCHEMA,
        "{}",
        ContentDigest::sha256(b"{}"),
        KnowledgeState::Unknown,
        Completeness::Bounded,
        vec![],
        vec![],
        vec![],
        "{}",
        vec![],
        vec![],
        ContentDigest::sha256(b"admission fixture"),
        None,
        None,
        None,
        None,
        "never_unchanged",
        ResponseSafeRetry::No,
        false,
        ExecutionBoundary {
            completed: vec![],
            not_started: vec![],
            possibly_occurred: vec![],
            preserved_truth: vec![],
            invalidated: vec![],
        },
        1_000,
    )
}

#[test]
fn unknown_and_partial_profiles_cannot_fall_back_to_legacy_operations() -> Test {
    for basis in unknown_profiles() {
        for operation in AgentOperation::ALL_OPERATIONS {
            assert_eq!(operation.generation_for_basis(&basis), None);
            assert_eq!(
                registered_operation(&basis, operation.name()),
                Err(ContractBasisError::Contract(
                    ContractError::InvalidIdentifier
                )),
                "{} must not bypass its unregistered basis",
                operation.name()
            );
            assert_eq!(
                AgentRequestEnvelope::new(request_params(basis.clone(), operation)?).map(|_| ()),
                Err(ContractBasisError::Contract(
                    ContractError::InvalidIdentifier
                ))
            );
        }
        assert_eq!(
            cognitive(basis.clone()).map(|_| ()),
            Err(ContractBasisError::Contract(
                ContractError::InvalidIdentifier
            ))
        );
        assert_eq!(
            response(basis).map(|_| ()),
            Err(ContractBasisError::Contract(
                ContractError::InvalidIdentifier
            ))
        );
    }
    Ok(())
}

#[test]
fn malformed_basis_is_refused_at_every_envelope_constructor() -> Test {
    for (field, basis) in malformed_bases() {
        let expected = ContractBasisError::InvalidIdentifier { field };
        for operation in AgentOperation::ALL_OPERATIONS {
            assert_eq!(
                registered_operation(&basis, operation.name()),
                Err(expected.clone())
            );
            assert_eq!(
                AgentRequestEnvelope::new(request_params(basis.clone(), operation)?).map(|_| ()),
                Err(expected.clone())
            );
        }
        assert_eq!(cognitive(basis.clone()).map(|_| ()), Err(expected.clone()));
        assert_eq!(response(basis).map(|_| ()), Err(expected));
    }
    Ok(())
}

#[test]
fn valid_reference_probe_and_hydration_rows_remain_addressable() -> Test {
    let mut compatible_reference = reference_contract_basis();
    compatible_reference.producer_release_id = "fss:release:compatible".to_owned();
    compatible_reference.accepted_nightly = Some("nightly-2026-08-31".to_owned());
    for basis in [
        reference_contract_basis(),
        compatible_reference,
        probe_contract_basis(),
        hydration_contract_basis(),
    ] {
        for operation in AgentOperation::ALL_OPERATIONS {
            assert_eq!(registered_operation(&basis, operation.name())?, operation);
            assert_eq!(
                AgentRequestEnvelope::new(request_params(basis.clone(), operation)?)?.operation(),
                operation
            );
        }
        cognitive(basis.clone())?.validate()?;
        response(basis)?.validate()?;
    }
    Ok(())
}

#[test]
fn public_field_mutation_cannot_evade_envelope_basis_revalidation() -> Test {
    let original_cognitive = cognitive(reference_contract_basis())?;
    let original_response = response(reference_contract_basis())?;
    let mut incompatible_protocol = reference_contract_basis();
    incompatible_protocol.semantic_protocol = "fss/2".to_owned();
    for basis in unknown_profiles()
        .into_iter()
        .chain(malformed_bases().into_iter().map(|(_, basis)| basis))
        .chain([incompatible_protocol])
    {
        let mut modified_cognitive = original_cognitive.clone();
        modified_cognitive.contract_basis = basis.clone();
        assert!(modified_cognitive.validate().is_err());
        let mut modified_response = original_response.clone();
        modified_response.contract_basis = basis;
        assert_eq!(
            modified_response.validate(),
            Err(ContractError::InvalidIdentifier)
        );
    }
    original_cognitive.validate()?;
    original_response.validate()?;
    Ok(())
}
