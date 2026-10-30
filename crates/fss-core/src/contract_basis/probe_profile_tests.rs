#![forbid(unsafe_code)]
//! Additive probe presentation must not rewrite the durable reference universe or V1 row bytes.

use super::*;
use crate::{
    AgentResponseEnvelope, AgentView, CanonicalEncoder, Completeness, ExecutionBoundary,
    KnowledgeState, ResponseOutcome, ResponseSafeRetry,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn profile_pins_actual_new_schema_and_preserves_both_binary_generations() -> TestResult {
    let old = reference_contract_basis();
    let legacy = include_bytes!("../../../../tests/fixtures/contract_basis_v2.bin");
    assert_eq!(encode_canonical_binary(&old)?.as_slice(), legacy);
    assert_eq!(
        old.basis_digest().to_text(),
        REFERENCE_CONTRACT_BASIS_CANONICAL_DIGEST
    );
    let schema = include_bytes!("../../../../schemas/agent_cognitive_envelope.v2.json");
    let schema_digest = ContentDigest::sha256(schema);
    assert_eq!(schema_digest.to_text(), PROBE_COGNITIVE_SCHEMA_DIGEST);
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_probe_schema_catalog.v1");
    encoder.digest(old.schema_catalog_digest);
    encoder.text("fss.agent_cognitive_envelope.v2");
    encoder.digest(schema_digest);
    assert_eq!(
        ContentDigest::sha256(&encoder.finish()).to_text(),
        PROBE_SCHEMA_CATALOG_DIGEST
    );
    let probe = probe_contract_basis();
    assert!(is_probe_contract_basis(&probe));
    assert!(!is_probe_contract_basis(&old));
    let fixture = include_bytes!("../../../../tests/fixtures/contract_basis_probe_v1.bin");
    assert_eq!(encode_canonical_binary(&probe)?.as_slice(), fixture);
    assert_eq!(decode_canonical_binary(fixture)?, probe);
    assert_eq!(
        ContentDigest::sha256(fixture).to_text(),
        PROBE_CONTRACT_BASIS_FREEZE_DIGEST
    );
    assert_eq!(
        probe.basis_digest().to_text(),
        PROBE_CONTRACT_BASIS_CANONICAL_DIGEST
    );
    assert!(negotiate_basis(&old, &probe).is_err());
    assert!(negotiate_basis(&probe, &old).is_err());
    assert!(!superseded_registry_digests().contains(&old.operation_registry_digest));
    let mut changed = probe.clone();
    changed.schema_catalog_digest = old.schema_catalog_digest;
    assert!(!is_probe_contract_basis(&changed));
    changed = probe.clone();
    changed.capability_registry_digest = ContentDigest::sha256(b"arbitrary grants");
    assert!(!is_probe_contract_basis(&changed));
    assert_eq!(reference_contract_basis(), old);
    Ok(())
}

#[test]
fn basis_aware_rows_add_only_investigate_v2_and_never_recode_v1() -> TestResult {
    let old = reference_contract_basis();
    let probe = probe_contract_basis();
    for operation in AgentOperation::ALL_OPERATIONS {
        let bytes = operation.try_canonical_bytes()?;
        let original = operation.canonical_row_encoding();
        assert_eq!(
            operation.generation_for_basis(&old),
            Some("gen:fss1:public-v1")
        );
        assert_eq!(
            operation.generation_for_basis(&probe),
            Some("gen:fss1:public-v2")
        );
        assert_eq!(
            operation.canonical_row_encoding_for_basis(&old),
            Some(original)
        );
        let selected = operation
            .response_payload_schemas_for_basis(&probe)
            .ok_or("profile")?;
        let row = operation
            .canonical_row_encoding_for_basis(&probe)
            .ok_or("row")?;
        let schemas = row.split('|').nth(6).ok_or("response column")?;
        assert_eq!(schemas.split(';').collect::<Vec<_>>(), selected);
        if operation == AgentOperation::Investigate {
            assert_eq!(
                selected.len(),
                operation.response_payload_schemas().len() + 1
            );
            assert_eq!(selected.last(), Some(&"fss.agent_cognitive_envelope.v2"));
            assert!(!original.contains("fss.agent_cognitive_envelope.v2"));
        } else {
            assert_eq!(selected, operation.response_payload_schemas());
            assert_eq!(row, original);
        }
        assert_eq!(AgentOperation::from_canonical_bytes(&bytes)?, operation);
        assert_eq!(operation.try_canonical_bytes()?, bytes);
    }
    let mut partial = probe.clone();
    partial.schema_catalog_digest = old.schema_catalog_digest;
    assert!(
        AgentOperation::Investigate
            .response_payload_schemas_for_basis(&partial)
            .is_none()
    );
    partial = probe;
    partial.operation_registry_digest = ContentDigest::sha256(b"unknown registry generation");
    assert!(
        AgentOperation::Investigate
            .generation_for_basis(&partial)
            .is_none()
    );
    Ok(())
}

fn response(
    basis: ContractBasis,
    operation: &str,
    schema: &str,
) -> Result<AgentResponseEnvelope, ContractBasisError> {
    AgentResponseEnvelope::new(
        basis,
        operation,
        "request:profile",
        1,
        "principal:reader",
        Some("session:reader".to_owned()),
        Some("mission:reader".to_owned()),
        "trace:profile",
        LedgerAnchor::genesis("site:profile"),
        None,
        None,
        AgentView::Case,
        vec![],
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
        "safe_read_retry",
        ResponseSafeRetry::YesAfterRefresh,
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
fn v2_outer_response_refuses_old_basis_wrong_operation_and_post_construction_mutation() -> TestResult
{
    const V2: &str = "fss.agent_cognitive_envelope.v2";
    assert!(response(reference_contract_basis(), "investigate", V2).is_err());
    assert!(response(probe_contract_basis(), "query", V2).is_err());
    let mut accepted = response(probe_contract_basis(), "investigate", V2)?;
    assert!(accepted.validate().is_ok());
    accepted.contract_basis = reference_contract_basis();
    assert!(accepted.validate().is_err());
    let legacy = response(
        reference_contract_basis(),
        "investigate",
        "fss.agent_cognitive_envelope.v1",
    )?;
    assert!(legacy.validate().is_ok());
    Ok(())
}
