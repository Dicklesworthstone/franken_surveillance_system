#![forbid(unsafe_code)]
//! Presentation admission changes only the explicitly selected durable metadata query profile.

use super::*;
use crate::{
    AgentResponseEnvelope, AgentView, CanonicalEncoder, Completeness, ExecutionBoundary,
    KnowledgeState, OperationMode, ResponseOutcome, ResponseSafeRetry,
};

type Test = Result<(), Box<dyn std::error::Error>>;

#[test]
fn hydration_profile_pins_schema_charging_row_and_binary_without_rewriting_reference_or_probe()
-> Test {
    let reference = reference_contract_basis();
    let reference_fixture = include_bytes!("../../../../tests/fixtures/contract_basis_v4.bin");
    assert_eq!(
        encode_canonical_binary(&reference)?.as_slice(),
        reference_fixture
    );
    let probe = probe_contract_basis();
    assert_eq!(
        encode_canonical_binary(&probe)?.as_slice(),
        include_bytes!("../../../../tests/fixtures/contract_basis_probe_v3.bin")
    );
    let schema = include_bytes!("../../../../schemas/agent_evidence_hydration.v1.json");
    let schema_digest = ContentDigest::sha256(schema);
    assert_eq!(schema_digest.to_text(), HYDRATION_RESPONSE_SCHEMA_DIGEST);
    let mut schema_pin = CanonicalEncoder::new();
    schema_pin.text("fss.agent_hydration_schema_catalog.v1");
    schema_pin.digest(reference.schema_catalog_digest);
    schema_pin.text(HYDRATION_RESPONSE_SCHEMA);
    schema_pin.digest(schema_digest);
    assert_eq!(
        ContentDigest::sha256(&schema_pin.finish_checked()?).to_text(),
        HYDRATION_SCHEMA_CATALOG_DIGEST
    );
    let mut operation_pin = CanonicalEncoder::new();
    operation_pin.text("fss.agent_hydration_operation_profile.v1");
    operation_pin.digest(reference.operation_registry_digest);
    operation_pin.text(HYDRATION_QUERY_CANONICAL_ROW);
    assert_eq!(
        ContentDigest::sha256(&operation_pin.finish_checked()?).to_text(),
        HYDRATION_OPERATION_REGISTRY_DIGEST
    );
    let hydration = hydration_contract_basis();
    let fixture =
        include_bytes!("../../../../tests/fixtures/contract_basis_event_hydration_v1.bin");
    assert_eq!(encode_canonical_binary(&hydration)?.as_slice(), fixture);
    assert_eq!(decode_canonical_binary(fixture)?, hydration);
    assert_eq!(
        ContentDigest::sha256(fixture).to_text(),
        HYDRATION_CONTRACT_BASIS_FREEZE_DIGEST
    );
    assert_eq!(
        hydration.basis_digest().to_text(),
        HYDRATION_CONTRACT_BASIS_CANONICAL_DIGEST
    );
    assert!(is_hydration_contract_basis(&hydration));
    assert!(!is_hydration_contract_basis(&reference));
    assert!(!is_hydration_contract_basis(&probe));
    assert!(negotiate_basis(&reference, &hydration).is_err());
    assert!(negotiate_basis(&hydration, &reference).is_err());
    assert_eq!(reference_contract_basis(), reference);
    assert_eq!(probe_contract_basis(), probe);
    Ok(())
}

#[test]
fn hydration_query_row_agrees_with_typed_accounting_and_retry_selectors() -> Test {
    let hydration = hydration_contract_basis();
    let reference = reference_contract_basis();
    for operation in AgentOperation::ALL_OPERATIONS {
        operation.validate_row_for_basis(&hydration)?;
        let old = operation.try_canonical_bytes()?;
        let row = operation
            .canonical_row_encoding_for_basis(&hydration)
            .ok_or("missing row")?;
        let columns: Vec<_> = row.split('|').collect();
        assert_eq!(columns.len(), 14);
        let mode = operation.mode_for_basis(&hydration).ok_or("mode missing")?;
        assert_eq!(mode.as_str(), columns[2]);
        assert_eq!(operation.effectful(), mode.affects_effect_plane());
        assert_eq!(
            operation.durable_for_basis(&hydration),
            Some(columns[10] == "1")
        );
        assert_eq!(
            columns[6].split(';').collect::<Vec<_>>(),
            operation
                .response_payload_schemas_for_basis(&hydration)
                .ok_or("schemas missing")?
        );
        assert_eq!(
            columns[12].split(';').collect::<Vec<_>>(),
            operation
                .required_capabilities_for_basis(&hydration)
                .ok_or("grants missing")?
        );
        assert_eq!(
            columns[13].split(';').collect::<Vec<_>>(),
            operation
                .retry_classes_for_basis(&hydration)
                .ok_or("retries missing")?
                .iter()
                .map(|retry| retry.as_str())
                .collect::<Vec<_>>()
        );
        if operation == AgentOperation::Query {
            assert_eq!(mode, OperationMode::CognitionWrite);
            assert_eq!(operation.durable_for_basis(&hydration), Some(true));
            assert!(!columns[13].contains("safe_read_retry"));
            assert!(columns[13].contains("reconciliation_required"));
            assert!(columns[6].contains(HYDRATION_RESPONSE_SCHEMA));
            assert_eq!(
                operation.mode_for_basis(&reference),
                Some(OperationMode::ReadCompile)
            );
            assert_eq!(operation.durable_for_basis(&reference), Some(false));
        } else {
            assert_eq!(row, operation.canonical_row_encoding());
        }
        assert_eq!(operation.try_canonical_bytes()?, old);
        assert_eq!(AgentOperation::from_canonical_bytes(&old)?, operation);
    }
    for field in 0..4 {
        let mut partial = hydration.clone();
        match field {
            0 => partial.schema_catalog_digest = reference.schema_catalog_digest,
            1 => partial.capability_registry_digest = ContentDigest::sha256(b"ungranted"),
            2 => partial.ontology_generation_id = "ontology:foreign".into(),
            _ => partial.producer_release_id = "producer:foreign".into(),
        }
        assert!(!is_hydration_contract_basis(&partial));
        assert!(
            AgentOperation::Query
                .validate_row_for_basis(&partial)
                .is_err()
        );
        assert!(AgentOperation::Query.mode_for_basis(&partial).is_none());
        assert!(AgentOperation::Query.durable_for_basis(&partial).is_none());
        assert!(
            AgentOperation::Query
                .required_capabilities_for_basis(&partial)
                .is_none()
        );
        assert!(
            AgentOperation::Query
                .retry_classes_for_basis(&partial)
                .is_none()
        );
        assert!(
            AgentOperation::Query
                .response_payload_schemas_for_basis(&partial)
                .is_none()
        );
    }
    Ok(())
}

fn response(
    basis: ContractBasis,
    operation: &str,
    schema: &str,
    recovery: &str,
    retry: ResponseSafeRetry,
) -> Result<AgentResponseEnvelope, ContractBasisError> {
    AgentResponseEnvelope::new(
        basis,
        operation,
        "request:hydration-profile",
        1,
        "principal:reader",
        Some("session:reader".into()),
        Some("mission:reader".into()),
        "trace:profile",
        LedgerAnchor::genesis("site:profile"),
        None,
        None,
        AgentView::Case,
        vec![
            "CAP-AGENT-QUERY-001".into(),
            "CAP-AGENT-EVIDENCE-HYDRATE-001".into(),
        ],
        "{}",
        ResponseOutcome::Ok,
        None,
        None,
        None,
        schema,
        "{}",
        ContentDigest::sha256(b"payload"),
        KnowledgeState::Unknown,
        Completeness::Bounded,
        vec![],
        vec![],
        vec![],
        "{}",
        vec![],
        vec![],
        ContentDigest::sha256(b"decision"),
        None,
        None,
        None,
        None,
        recovery,
        retry,
        false,
        ExecutionBoundary {
            completed: vec![],
            not_started: vec![],
            possibly_occurred: vec![],
            preserved_truth: vec![],
            invalidated: vec![],
        },
        0,
    )
}

#[test]
fn composite_and_charged_refusal_require_exact_profile_and_never_promise_free_retry() -> Test {
    for basis in [reference_contract_basis(), probe_contract_basis()] {
        assert!(
            response(
                basis,
                "query",
                HYDRATION_RESPONSE_SCHEMA,
                "never_unchanged",
                ResponseSafeRetry::No
            )
            .is_err()
        );
    }
    assert!(
        response(
            hydration_contract_basis(),
            "investigate",
            HYDRATION_RESPONSE_SCHEMA,
            "never_unchanged",
            ResponseSafeRetry::No
        )
        .is_err()
    );
    assert!(
        response(
            hydration_contract_basis(),
            "query",
            HYDRATION_RESPONSE_SCHEMA,
            "safe_read_retry",
            ResponseSafeRetry::YesAfterRefresh
        )
        .is_err()
    );
    assert!(
        response(
            hydration_contract_basis(),
            "query",
            HYDRATION_RESPONSE_SCHEMA,
            "safe_read_retry",
            ResponseSafeRetry::No
        )
        .is_err()
    );
    let accepted = response(
        hydration_contract_basis(),
        "query",
        HYDRATION_RESPONSE_SCHEMA,
        "resume_from_continuation",
        ResponseSafeRetry::No,
    )?;
    accepted.validate()?;
    let mut changed = accepted.clone();
    changed.contract_basis = reference_contract_basis();
    assert!(changed.validate().is_err());
    changed = accepted.clone();
    changed.operation = AgentOperation::Wait;
    assert!(changed.validate().is_err());
    changed = accepted.clone();
    changed.safe_retry = ResponseSafeRetry::YesAfterRefresh;
    assert!(changed.validate().is_err());
    changed = accepted;
    changed.recovery_class = "safe_read_retry".into();
    assert!(changed.validate().is_err());
    let mut refusal = response(
        hydration_contract_basis(),
        "query",
        "fss.agent_cognitive_envelope.v1",
        "reconciliation_required",
        ResponseSafeRetry::No,
    )?;
    refusal.outcome = ResponseOutcome::Refused;
    refusal.error_id = Some("ERR-AGENT-CONTEXT-INCOMPLETE-001".into());
    refusal.validate()?;
    // The ordinary frozen query retains its historical safe-read classification.
    response(
        reference_contract_basis(),
        "query",
        "fss.agent_cognitive_envelope.v1",
        "safe_read_retry",
        ResponseSafeRetry::YesAfterRefresh,
    )?
    .validate()?;
    Ok(())
}
