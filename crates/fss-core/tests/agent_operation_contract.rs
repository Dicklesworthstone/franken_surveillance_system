#![forbid(unsafe_code)]
//! Contract tests for registered `fss/1` agent operations (AOP-001..AOP-014).
//!
//! Per `fss-x4a.30.83.17` and the machine registry `architecture/agent_operations.json`,
//! pins:
//! - registry row order, ID/name bijectivity, and the name-only parsing rule;
//! - the canonical text row encoding against the typed accessors;
//! - canonical binary round-trip and fail-closed decode on tampering;
//! - mode/effect/durability semantic invariants and the world-envelope rule;
//! - the `registered_operation` ContractBasis boundary (fail closed, typed refusal).

use fss_core::contract_basis::{
    check_basis_freshness, registered_operation, reference_contract_basis, ContractBasisError,
    ContractBasisRefusal, CANONICAL_SEMANTIC_PROTOCOL,
};
use fss_core::{AgentOperation, ContractBasis};
use fss_core::{
    classify_session_resume, BasisRegistryKind, CanonicalDecode, CanonicalEncode, CanonicalEncoder,
    ContentDigest, ContractError, LedgerAnchor, OperationMode, OperationRetryClass,
    REGISTERED_OPERATION_COUNT, ResumeInvalidation,
};

const EXPECTED_IDS: [&str; 14] = [
    "AOP-001", "AOP-002", "AOP-003", "AOP-004", "AOP-005", "AOP-006", "AOP-007", "AOP-008",
    "AOP-009", "AOP-010", "AOP-011", "AOP-012", "AOP-013", "AOP-014",
];

const EXPECTED_NAMES: [&str; 14] = [
    "session.open",
    "session.resume",
    "session.orient",
    "session.follow",
    "query",
    "investigate",
    "plan",
    "commit",
    "wait",
    "cancel",
    "explain",
    "handoff",
    "feedback",
    "doctor",
];

fn all_rows() -> Vec<AgentOperation> {
    AgentOperation::ALL_OPERATIONS.to_vec()
}

#[test]
fn test_registry_row_order_and_bijectivity() {
    let rows = all_rows();
    assert_eq!(rows.len(), REGISTERED_OPERATION_COUNT);
    assert_eq!(rows.len(), EXPECTED_IDS.len());
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(row.id(), EXPECTED_IDS[index], "row order is registry order");
        assert_eq!(row.name(), EXPECTED_NAMES[index]);
    }
    for (i, a) in rows.iter().enumerate() {
        for b in rows.iter().skip(i + 1) {
            assert_ne!(a.id(), b.id());
            assert_ne!(a.name(), b.name());
            assert_ne!(a.canonical_row_encoding(), b.canonical_row_encoding());
            assert_ne!(a.row_digest(), b.row_digest());
        }
    }
    let mut sorted = rows.clone();
    sorted.sort();
    assert_eq!(sorted, rows);
}

#[test]
fn test_id_and_name_parsing() -> Result<(), Box<dyn std::error::Error>> {
    for row in all_rows() {
        assert_eq!(AgentOperation::from_id(row.id())?, row);
        assert_eq!(AgentOperation::from_name(row.name())?, row);
        assert!(AgentOperation::from_name(row.id()).is_err());
    }
    assert!(AgentOperation::from_id("AOP-000").is_err());
    assert!(AgentOperation::from_id("AOP-015").is_err());
    assert!(AgentOperation::from_id("").is_err());
    assert!(AgentOperation::from_name("session_open").is_err());
    assert!(AgentOperation::from_name("").is_err());
    Ok(())
}

#[test]
fn test_from_str_accepts_names_only() {
    use std::str::FromStr;
    assert_eq!(
        AgentOperation::from_str("session.open"),
        Ok(AgentOperation::SessionOpen)
    );
    assert!(AgentOperation::from_str("AOP-001").is_err());
    assert!(AgentOperation::from_str("nosuchop").is_err());
}

#[test]
fn test_canonical_row_encoding_matches_accessors() -> Result<(), Box<dyn std::error::Error>> {
    for row in all_rows() {
        let fields: Vec<&str> = row.canonical_row_encoding().split('|').collect();
        assert_eq!(fields.len(), 14, "row {} must have 14 fields", row.id());
        assert_eq!(fields[0], row.id());
        assert_eq!(fields[1], row.name());
        assert_eq!(fields[2], row.mode().as_str());
        assert_eq!(fields[3], row.owner());
        assert_eq!(fields[4], row.default_view());
        assert_eq!(fields[5], row.request_payload_schema());
        let responses: Vec<&str> = fields[6].split(';').collect();
        assert_eq!(responses, row.response_payload_schemas());
        assert_eq!(fields[7], "fss.agent_request_envelope.v1");
        assert_eq!(fields[8], "fss.agent_response_envelope.v1");
        assert_eq!(fields[9], if row.effectful() { "1" } else { "0" });
        assert_eq!(fields[10], if row.durable() { "1" } else { "0" });
        assert_eq!(fields[11], row.gate());
        let capabilities: Vec<&str> = fields[12].split(';').collect();
        assert_eq!(capabilities, row.required_capabilities());
        let retries: Vec<String> = fields[13]
            .split(';')
            .map(|spelled| {
                OperationRetryClass::from_name(spelled)
                    .map(|parsed| parsed.as_str().to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let expected_retries: Vec<String> = row
            .retry_classes()
            .iter()
            .map(|r| r.as_str().to_string())
            .collect();
        assert_eq!(retries, expected_retries);
        assert!(!row.purpose().is_empty());
        assert!(!row.purpose().contains('|'));
    }
    Ok(())
}

#[test]
fn test_canonical_binary_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    for row in all_rows() {
        let mut encoder = CanonicalEncoder::new();
        row.encode_canonical(&mut encoder);
        let bytes = encoder.finish();
        let decoded = AgentOperation::from_canonical_bytes(&bytes)?;
        assert_eq!(decoded, row, "round trip must preserve {}", row.id());
        row.validate_row()?;
    }
    Ok(())
}

#[test]
fn test_decode_refuses_truncated_input() {
    for row in all_rows() {
        let mut encoder = CanonicalEncoder::new();
        row.encode_canonical(&mut encoder);
        let bytes = encoder.finish();
        for cut in [0usize, 1, bytes.len() / 2, bytes.len() - 1] {
            assert!(
                AgentOperation::from_canonical_bytes(&bytes[..cut]).is_err(),
                "truncated decode of {} must fail",
                row.id()
            );
        }
    }
}

#[test]
fn test_decode_refuses_bit_flips() {
    for row in all_rows() {
        let mut encoder = CanonicalEncoder::new();
        row.encode_canonical(&mut encoder);
        let bytes = encoder.finish();
        let mut tampered_any = false;
        for index in 0..bytes.len() {
            let mut bad = bytes.clone();
            bad[index] = bad[index].wrapping_add(1);
            if bad[index] == bytes[index] {
                continue;
            }
            tampered_any = true;
            if let Ok(decoded) = AgentOperation::from_canonical_bytes(&bad) {
                assert_ne!(
                    decoded, row,
                    "tampered byte {index} of {} must not decode to the same row",
                    row.id()
                );
            }
        }
        assert!(tampered_any);
    }
}

#[test]
fn test_decode_refuses_id_in_name_field() -> Result<(), Box<dyn std::error::Error>> {
    // Encode a row whose name field was swapped for the stable ID: the decoder
    // must refuse the relabelled row instead of silently accepting it.
    let row = AgentOperation::SessionOpen;
    let mut encoder = CanonicalEncoder::new();
    encoder.text("AOP-001");
    encoder.text("AOP-001");
    row.mode().encode_canonical(&mut encoder);
    encoder.text(row.owner());
    encoder.text(row.default_view());
    encoder.text(row.request_payload_schema());
    encoder.u32(row.response_payload_schemas().len() as u32);
    for schema in row.response_payload_schemas() {
        encoder.text(schema);
    }
    encoder.text("fss.agent_request_envelope.v1");
    encoder.text("fss.agent_response_envelope.v1");
    encoder.bool(row.effectful());
    encoder.bool(row.durable());
    encoder.text(row.gate());
    encoder.u32(row.required_capabilities().len() as u32);
    for capability in row.required_capabilities() {
        encoder.text(capability);
    }
    encoder.u32(row.retry_classes().len() as u32);
    for retry in row.retry_classes() {
        retry.encode_canonical(&mut encoder);
    }
    let bytes = encoder.finish();
    assert!(AgentOperation::from_canonical_bytes(&bytes).is_err());
    Ok(())
}

#[test]
fn test_mode_semantics() -> Result<(), Box<dyn std::error::Error>> {
    assert!(OperationMode::EffectCommit.affects_effect_plane());
    assert!(OperationMode::LifecycleEffect.affects_effect_plane());
    for mode in [
        OperationMode::SessionControl,
        OperationMode::Read,
        OperationMode::ReadWait,
        OperationMode::ReadCompile,
        OperationMode::ReadCompute,
        OperationMode::CognitionWrite,
        OperationMode::PlanPrepare,
        OperationMode::ContinuityPublish,
        OperationMode::AdvisoryWrite,
        OperationMode::DiagnosticPrepare,
    ] {
        assert!(!mode.affects_effect_plane(), "{mode} must not be effectful");
    }
    for mode in [
        OperationMode::Read,
        OperationMode::ReadWait,
        OperationMode::ReadCompile,
        OperationMode::ReadCompute,
    ] {
        assert!(mode.refines_possibility_envelope());
    }
    assert!(!OperationMode::EffectCommit.refines_possibility_envelope());
    assert!(OperationMode::EffectCommit.consumes_effect_affordances());
    assert!(!OperationMode::LifecycleEffect.consumes_effect_affordances());
    assert!(!OperationMode::Read.requires_durability());
    assert!(!OperationMode::ReadCompile.requires_durability());
    assert!(!OperationMode::ReadCompute.requires_durability());
    for mode in [
        OperationMode::SessionControl,
        OperationMode::ReadWait,
        OperationMode::CognitionWrite,
        OperationMode::PlanPrepare,
        OperationMode::EffectCommit,
        OperationMode::LifecycleEffect,
        OperationMode::ContinuityPublish,
        OperationMode::AdvisoryWrite,
        OperationMode::DiagnosticPrepare,
    ] {
        assert!(mode.requires_durability(), "{mode} must be durable");
    }
    for code in 1u8..=12 {
        let mode = OperationMode::from_code(code)?;
        assert_eq!(mode.to_code(), code);
        assert_eq!(OperationMode::from_name(mode.as_str())?, mode);
    }
    assert!(OperationMode::from_code(0).is_err());
    assert!(OperationMode::from_code(13).is_err());
    assert!(OperationMode::from_name("read-only").is_err());
    Ok(())
}

#[test]
fn test_row_invariants_across_registry() {
    let effect_rows: Vec<AgentOperation> =
        all_rows().into_iter().filter(|r| r.effectful()).collect();
    assert_eq!(
        effect_rows,
        vec![AgentOperation::Commit, AgentOperation::Cancel],
        "exactly AOP-008 and AOP-010 are effectful"
    );
    for row in all_rows() {
        assert_eq!(row.mode().affects_effect_plane(), row.effectful());
        assert_eq!(row.mode().requires_durability(), row.durable());
        assert!(row.gate().starts_with("QL-"));
        assert!(row.default_view().starts_with("AVIEW-"));
        assert!(row.owner().starts_with("fss-"));
        assert!(row.request_payload_schema().starts_with("fss."));
        for schema in row.response_payload_schemas() {
            assert!(schema.starts_with("fss."));
        }
        for capability in row.required_capabilities() {
            assert!(capability.starts_with("CAP-"));
        }
        assert!(!row.required_capabilities().is_empty());
        assert!(!row.retry_classes().is_empty());
        assert!(row.validate_row().is_ok());
    }
    let ephemeral: Vec<&str> = all_rows()
        .iter()
        .filter(|r| !r.durable())
        .map(|r| r.id())
        .collect();
    assert_eq!(ephemeral, vec!["AOP-003", "AOP-005", "AOP-011"]);
}

#[test]
fn test_row_digest_stability_and_domain_separation() {
    for row in all_rows() {
        let digest = row.row_digest();
        let reparsed = AgentOperation::from_name(row.name());
        assert_eq!(reparsed.map(|r| r.row_digest()), Ok(digest));
        assert_ne!(row.canonical_digest("fss.other.domain.v1"), digest);
    }
    for row in all_rows() {
        let encoding = row.canonical_row_encoding();
        assert!(!encoding.contains('\n'));
        assert!(!encoding.contains("\r"));
        assert_eq!(encoding.split('|').count(), 14);
    }
}

#[test]
fn test_registered_operation_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let basis = reference_contract_basis();
    assert_eq!(basis.semantic_protocol, CANONICAL_SEMANTIC_PROTOCOL);
    for row in all_rows() {
        let resolved = registered_operation(&basis, row.name())?;
        assert_eq!(resolved, row);
        assert!(resolved.validate_row().is_ok());
    }
    Ok(())
}

#[test]
fn test_registered_operation_refuses_unknown_names() -> Result<(), Box<dyn std::error::Error>> {
    let basis = reference_contract_basis();
    for bogus in ["AOP-001", "session_open", "", "session.open.extra", "COMMIT"] {
        let err = registered_operation(&basis, bogus)
            .err()
            .ok_or("expected refusal for unregistered operation name")?;
        let ContractBasisError::IncompatibleBasis { refusal } = &err else {
            return Err("expected IncompatibleBasis refusal".into());
        };
        assert_eq!(
            refusal.error_code(),
            "ERR-AGENT-PROTOCOL-001",
            "unregistered surface must map to ERR-AGENT-PROTOCOL-001"
        );
        assert!(matches!(
            refusal,
            ContractBasisRefusal::UnregisteredOperation { .. }
        ));
        assert!(refusal.remediation_guidance().contains("fss1_public_registry"));
        assert!(refusal.to_string().starts_with("unregistered operation name"));
    }
    Ok(())
}

#[test]
fn test_registered_operation_refuses_incompatible_protocol(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut basis = reference_contract_basis();
    basis.semantic_protocol = "fss/2".to_owned();
    let err = registered_operation(&basis, "session.open")
        .err()
        .ok_or("expected protocol refusal")?;
    let ContractBasisError::IncompatibleBasis { refusal } = &err else {
        return Err("expected IncompatibleBasis refusal".into());
    };
    assert!(matches!(
        refusal,
        ContractBasisRefusal::IncompatibleProtocol { .. }
    ));
    assert!(refusal.to_string().contains("incompatible protocol"));
    // Even under a bad protocol the typed error never carries operation authority.
    assert_eq!(err.error_id(), "ERR-AGENT-PROTOCOL-001");
    Ok(())
}

#[test]
fn test_registered_operation_revalidates_rows() -> Result<(), Box<dyn std::error::Error>> {
    let basis = ContractBasis {
        semantic_protocol: CANONICAL_SEMANTIC_PROTOCOL.to_owned(),
        ..reference_contract_basis()
    };
    for row in all_rows() {
        let resolved = registered_operation(&basis, row.name())?;
        assert_eq!(resolved.validate_row(), Ok(()));
    }
    Ok(())
}

#[test]
fn test_retry_class_registry_spellings() -> Result<(), Box<dyn std::error::Error>> {
    let all_spellings = [
        "never_unchanged",
        "backoff",
        "operator_action_required",
        "resume_from_continuation",
        "safe_read_retry",
        "refresh_and_retry",
        "rebase_required",
        "reconciliation_required",
    ];
    for spelling in all_spellings {
        let parsed = OperationRetryClass::from_name(spelling)?;
        assert_eq!(parsed.as_str(), spelling);
    }
    assert!(OperationRetryClass::from_name("retry_never").is_err());
    assert!(OperationRetryClass::from_name("").is_err());
    Ok(())
}

#[test]
fn test_error_code_pin_for_mode_mismatch() {
    let err = ContractError::OperationEffectModeMismatch;
    assert_eq!(err.code(), "operation_effect_mode_mismatch");
}

#[test]
fn test_resume_clean_when_root_matches_current() -> Result<(), Box<dyn std::error::Error>> {
    let basis = reference_contract_basis();
    let anchor = LedgerAnchor::genesis("site:fss:test");
    let assessment = classify_session_resume(&basis, &basis, &anchor, &anchor, &[]);
    assert!(assessment.is_clean());
    assert!(assessment.invalidations().is_empty());
    // Equal anchors are not an invalidation: nothing was missed since the root.
    Ok(())
}

#[test]
fn test_resume_enumerates_anchor_invalidations() -> Result<(), Box<dyn std::error::Error>> {
    let basis = reference_contract_basis();
    let recorded = LedgerAnchor::genesis("site:fss:test");
    let mut current = LedgerAnchor::genesis("site:fss:test");
    current.commit_sequence = recorded.commit_sequence + 7;
    // Recorded strictly older than current: expected lag, not an invalidation.
    let assessment = classify_session_resume(&basis, &basis, &recorded, &current, &[]);
    assert!(assessment.is_clean());
    // Recorded strictly newer than current: the root claims history current
    // authority does not have.
    let assessment = classify_session_resume(&basis, &basis, &current, &recorded, &[]);
    assert_eq!(
        assessment.invalidations(),
        &[ResumeInvalidation::AnchorNotStrictlyOlder]
    );
    // Lineage divergence: the recorded history is not an ancestor.
    let divergent = LedgerAnchor::genesis("site:fss:other");
    let assessment = classify_session_resume(&basis, &basis, &divergent, &recorded, &[]);
    assert_eq!(
        assessment.invalidations(),
        &[ResumeInvalidation::AnchorLineageDivergence]
    );
    Ok(())
}

#[test]
fn test_resume_enumerates_each_registry_drift() -> Result<(), Box<dyn std::error::Error>> {
    let reference = reference_contract_basis();
    let drifted: [(BasisRegistryKind, ContentDigest); 6] = [
        (BasisRegistryKind::SchemaCatalog, ContentDigest::sha256(b"other-schema")),
        (BasisRegistryKind::Operations, ContentDigest::sha256(b"other-ops")),
        (BasisRegistryKind::Views, ContentDigest::sha256(b"other-views")),
        (BasisRegistryKind::Capabilities, ContentDigest::sha256(b"other-caps")),
        (BasisRegistryKind::Errors, ContentDigest::sha256(b"other-errors")),
        (BasisRegistryKind::Costs, ContentDigest::sha256(b"other-costs")),
    ];
    for (kind, replacement) in drifted {
        let mut current = reference.clone();
        match kind {
            BasisRegistryKind::SchemaCatalog => current.schema_catalog_digest = replacement,
            BasisRegistryKind::Operations => current.operation_registry_digest = replacement,
            BasisRegistryKind::Views => current.view_registry_digest = replacement,
            BasisRegistryKind::Capabilities => current.capability_registry_digest = replacement,
            BasisRegistryKind::Errors => current.error_registry_digest = replacement,
            BasisRegistryKind::Costs => current.cost_registry_digest = replacement,
        }
        let anchor = LedgerAnchor::genesis("site:fss:test");
        let assessment = classify_session_resume(&reference, &current, &anchor, &anchor, &[]);
        assert_eq!(
            assessment.invalidations(),
            &[ResumeInvalidation::RegistryDrift { registry: kind }],
        );
        assert!(!assessment.is_clean());
    }
    Ok(())
}

#[test]
fn test_resume_classifies_tombstoned_digest_as_tombstone(
) -> Result<(), Box<dyn std::error::Error>> {
    let reference = reference_contract_basis();
    let mut current = reference.clone();
    // The current deployment moved to a new operations registry generation; the
    // generation the root pinned was tombstoned during that move.
    current.operation_registry_digest = ContentDigest::sha256(b"new-ops-generation");
    let anchor = LedgerAnchor::genesis("site:fss:test");
    let tombstones = [reference.operation_registry_digest];
    let assessment = classify_session_resume(&reference, &current, &anchor, &anchor, &tombstones);
    assert_eq!(
        assessment.invalidations(),
        &[ResumeInvalidation::TombstonedRegistryDigest {
            registry: BasisRegistryKind::Operations
        }],
        "tombstone must be the stronger, non-duplicated classification"
    );
    // A plain drift (no tombstone) enumerates the weaker classification.
    let assessment = classify_session_resume(&reference, &current, &anchor, &anchor, &[]);
    assert_eq!(
        assessment.invalidations(),
        &[ResumeInvalidation::RegistryDrift {
            registry: BasisRegistryKind::Operations
        }]
    );
    // The tombstoned root is refused outright by the request-time freshness
    // check: resume inventories what non-resume paths refuse.
    assert!(check_basis_freshness(&reference, &current, &tombstones).is_err());
    Ok(())
}

#[test]
fn test_resume_enumerates_identity_drift() -> Result<(), Box<dyn std::error::Error>> {
    let mut current = reference_contract_basis();
    current.semantic_protocol = "fss/2".to_owned();
    current.ontology_generation_id = "ontology:next:v9".to_owned();
    current.producer_release_id = "fss:release:v9".to_owned();
    let anchor = LedgerAnchor::genesis("site:fss:test");
    let assessment = classify_session_resume(&reference_contract_basis(), &current, &anchor, &anchor, &[]);
    assert_eq!(
        assessment.invalidations(),
        &[
            ResumeInvalidation::ProtocolDrift {
                recorded: "fss/1".to_owned(),
                current: "fss/2".to_owned(),
            },
            ResumeInvalidation::OntologyDrift {
                recorded: "ontology:reference:v1".to_owned(),
                current: "ontology:next:v9".to_owned(),
            },
            ResumeInvalidation::ProducerReleaseDrift {
                recorded: "fss:release:v1".to_owned(),
                current: "fss:release:v9".to_owned(),
            },
        ]
    );
    Ok(())
}

#[test]
fn test_resume_assessment_is_deterministic() -> Result<(), Box<dyn std::error::Error>> {
    let mut current = reference_contract_basis();
    current.view_registry_digest = ContentDigest::sha256(b"drifted-views");
    let recorded_anchor = LedgerAnchor::genesis("site:fss:test");
    let mut current_anchor = LedgerAnchor::genesis("site:fss:test");
    current_anchor.commit_sequence = recorded_anchor.commit_sequence + 3;
    let tombstones = [ContentDigest::sha256(b"missing")];
    let first = classify_session_resume(
        &reference_contract_basis(),
        &current,
        &recorded_anchor,
        &current_anchor,
        &tombstones,
    );
    let second = classify_session_resume(
        &reference_contract_basis(),
        &current,
        &recorded_anchor,
        &current_anchor,
        &tombstones,
    );
    assert_eq!(first, second);
    Ok(())
}
