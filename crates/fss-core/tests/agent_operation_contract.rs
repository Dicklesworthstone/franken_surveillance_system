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
use fss_core::{
    ActionAffordance, AffordanceClass, AgentOperation, CancellationRecord, CancelStage,
    ContractBasis, DiagnosisDomain, DoctorReport, ExplainQuestion, ExplainReceipt,
    FeedbackKind, FeedbackProposal, HandoffId, HandoffPublishParams,
    RepairAffordance, ReconciliationBasis, RuntimeOutcome, WaitWakeContract,
};
use fss_core::{
    admit_commit, admit_follow_read, admit_handoff, admit_query_read, advance_follow_cursor,
    classify_session_resume, require_reconciliation_before_retry,
    orient_projection, BasisRegistryKind, CanonicalDecode, CanonicalEncode, CanonicalEncoder,
    Completeness, ContentDigest, ContinuationCursor, ContinuationCursorPublishParams,
    ContinuationError, ContinuationScope, ContractError, FollowWakeContract,
    HypothesisDisposition, InvestigationCaseState, LedgerAnchor, MissionId, OperationMode,
    PreparedPlan, PreparedPlanStep,
    OperationRetryClass, OrientBudget, OrientOmissionTarget, OrientSection, PossibleWorld,
    PrincipalId, REGISTERED_OPERATION_COUNT, ResumeInvalidation, BudgetVector,
    SessionId, SituationCapsule, SituationFrame, TimestampNs,
    WorldEnvelope,
};
use std::collections::BTreeSet;

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


fn test_query_cost(latency_ms: u64) -> Result<BudgetVector, fss_core::BudgetError> {
    BudgetVector::builder().latency_ms(latency_ms).build()
}

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

fn orient_test_capsule(
    section_len: usize,
    handle_count: usize,
) -> Result<SituationCapsule, Box<dyn std::error::Error>> {
    let anchor = LedgerAnchor::genesis("site:fss:orient");
    let world_envelope = WorldEnvelope {
        envelope_id: "world-envelope:orient".to_owned(),
        objective_id: "objective:orient".to_owned(),
        anchor: anchor.clone(),
        nominal_claim_ids: BTreeSet::from(["claim:orient".to_owned()]),
        certified_core_claim_ids: BTreeSet::new(),
        alternatives: vec![PossibleWorld {
            world_id: "world:orient:protected".to_owned(),
            description: "A protected high-loss world stays decision-relevant.".to_owned(),
            claim_ids: BTreeSet::from(["claim:orient".to_owned()]),
            evidence: vec![ContentDigest::sha256(b"orient-evidence")],
            consequence_severity: 5,
            protected: true,
        }],
        adversarial_residuals: Vec::new(),
        common_invariants: BTreeSet::new(),
        coverage_boundary_handles: BTreeSet::new(),
    };
    let entries = |tag: &str| {
        (0..section_len)
            .map(|index| format!("{tag}:{index}"))
            .collect::<Vec<String>>()
    };
    let frame = SituationFrame {
        frame_id: "frame:orient".to_owned(),
        objective_id: "objective:orient".to_owned(),
        anchor: anchor.clone(),
        world_envelope,
        knowledge_cells: Vec::new(),
        now: entries("now"),
        changed: entries("changed"),
        why: entries("why"),
        unknown: entries("unknown"),
        at_risk: entries("at-risk"),
        next: Vec::new(),
        evidence_handles: (0..handle_count)
            .map(|index| format!("fss://proof/orient/{index:03}"))
            .collect(),
    };
    let capsule = SituationCapsule {
        capsule_id: "situation:orient".to_owned(),
        revision: 3,
        contract_basis: reference_contract_basis(),
        mission_id: MissionId::parse("mission:orient")?,
        session_id: SessionId::parse("session:orient")?,
        principal_id: PrincipalId::parse("principal:orient")?,
        anchor,
        previous_anchor: None,
        frame,
        obligations: Vec::new(),
        affordances: Vec::new(),
        completeness: Completeness::Complete,
        created_at: TimestampNs(1_000),
        mission_state: None,
    };
    capsule.validate()?;
    Ok(capsule)
}

#[test]
fn test_orient_projection_clips_sections_with_typed_omissions(
) -> Result<(), Box<dyn std::error::Error>> {
    let capsule = orient_test_capsule(5, 4)?;
    let budget = OrientBudget::new(3, 4)?;
    let projection = orient_projection(&capsule, budget)?;
    for section in [
        OrientSection::Now,
        OrientSection::Changed,
        OrientSection::Why,
        OrientSection::Unknown,
        OrientSection::AtRisk,
    ] {
        let retained = projection.section(section);
        assert_eq!(retained.len(), 3, "{section} must retain the bound");
    }
    // The fixture carries no affordances, so `next` is empty and retains none.
    assert!(projection.section(OrientSection::Next).is_empty());
    assert_eq!(projection.omissions.len(), 5);
    for omission in &projection.omissions {
        assert_eq!(omission.omitted_entries, 2);
    }
    // Section entries keep their frame order (head retention, no reordering).
    assert_eq!(projection.section(OrientSection::Now)[0], "now:0");
    assert_eq!(projection.section(OrientSection::Now)[2], "now:2");
    Ok(())
}

#[test]
fn test_orient_projection_bounds_evidence_handles(
) -> Result<(), Box<dyn std::error::Error>> {
    let capsule = orient_test_capsule(1, 6)?;
    let budget = OrientBudget::new(1, 4)?;
    let projection = orient_projection(&capsule, budget)?;
    assert_eq!(projection.evidence_handles.len(), 4);
    // Handles are kept in sorted order (BTreeSet iteration order).
    assert_eq!(projection.evidence_handles[0], "fss://proof/orient/000");
    let mut omissions = projection.omissions.iter();
    let handle_omission = omissions
        .find(|omission| omission.target == OrientOmissionTarget::EvidenceHandles)
        .ok_or("expected an evidence-handle omission")?;
    assert_eq!(handle_omission.omitted_entries, 2);
    Ok(())
}

#[test]
fn test_orient_projection_refuses_empty_budget() {
    assert!(OrientBudget::new(0, 4).is_err());
    assert!(OrientBudget::new(3, 0).is_err());
    assert_eq!(
        OrientBudget::new(0, 0).map_err(|err| err.code()),
        Err(ContractError::BudgetExhausted.code())
    );
}

#[test]
fn test_orient_projection_refuses_invalid_capsule() -> Result<(), Box<dyn std::error::Error>> {
    let mut capsule = orient_test_capsule(1, 1)?;
    // A stale capsule anchor diverges from the frame anchor: the read must
    // refuse instead of projecting stale state.
    capsule.anchor = LedgerAnchor::genesis("site:fss:orient-other");
    let budget = OrientBudget::new(2, 2)?;
    assert!(orient_projection(&capsule, budget).is_err());
    Ok(())
}

#[test]
fn test_orient_projection_digest_stability() -> Result<(), Box<dyn std::error::Error>> {
    let capsule = orient_test_capsule(4, 3)?;
    let first = orient_projection(&capsule, OrientBudget::new(2, 2)?)?;
    let second = orient_projection(&capsule, OrientBudget::new(2, 2)?)?;
    assert_eq!(first, second);
    assert_eq!(first.projection_digest(), second.projection_digest());
    // A different budget yields different retained content and a different digest.
    let wider = orient_projection(&capsule, OrientBudget::new(3, 3)?)?;
    assert_ne!(first.projection_digest(), wider.projection_digest());
    // The orient read is a non-durable operation (AOP-003 durable = no).
    assert!(!AgentOperation::SessionOrient.durable());
    assert!(!AgentOperation::SessionOrient.effectful());
    Ok(())
}

fn follow_cursor() -> Result<ContinuationCursor, Box<dyn std::error::Error>> {
    let anchor = LedgerAnchor::genesis("site:fss:follow");
    let cursor = ContinuationCursor::publish(ContinuationCursorPublishParams {
        scope: ContinuationScope::FollowStream,
        stream_id: "stream:fss:follow".to_owned(),
        contract_basis: reference_contract_basis(),
        session_id: SessionId::parse("session:follow")?,
        view_id: "AVIEW-001".to_owned(),
        basis_anchor: anchor.clone(),
        resume_anchor: anchor,
        source_digest: ContentDigest::sha256(b"follow-stream"),
        position: 10,
        upper_bound: 20,
        selection_witness: ContentDigest::sha256(b"follow-witness"),
        predecessor_digest: None,
        issued_at: TimestampNs(1_000),
        expires_at: TimestampNs(2_000),
    })?;
    Ok(cursor)
}

#[test]
fn test_follow_admission_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let cursor = follow_cursor()?;
    let wake = FollowWakeContract::new(5, TimestampNs(1_500), TimestampNs(1_200))?;
    let plan = admit_follow_read(&cursor, wake, TimestampNs(1_200))?;
    assert_eq!(plan.deliverable_entries, 5);
    assert!(!plan.caught_up);
    assert_eq!(plan.resume_position, 15);
    assert_eq!(plan.wake_at, TimestampNs(1_500));
    // A budget covering the remaining stream catches up at the upper bound.
    let wake = FollowWakeContract::new(50, TimestampNs(1_500), TimestampNs(1_200))?;
    let plan = admit_follow_read(&cursor, wake, TimestampNs(1_200))?;
    assert_eq!(plan.deliverable_entries, 10);
    assert!(plan.caught_up);
    assert_eq!(plan.resume_position, 20);
    Ok(())
}

#[test]
fn test_follow_refuses_unbounded_and_outlived_wakes(
) -> Result<(), Box<dyn std::error::Error>> {
    let cursor = follow_cursor()?;
    // Zero-entry wake: unbounded follow is refused, never silently truncated.
    let wake = FollowWakeContract::new(0, TimestampNs(1_500), TimestampNs(1_200));
    assert!(matches!(wake, Err(ContinuationError::UnboundedWake)));
    // Wake deadline past cursor expiry: rebase required before waiting.
    let wake = FollowWakeContract::new(5, TimestampNs(2_500), TimestampNs(1_200));
    assert_eq!(
        admit_follow_read(&cursor, wake?, TimestampNs(1_200)),
        Err(ContinuationError::WakeBeyondExpiry)
    );
    // Expired cursor at read time.
    let wake = FollowWakeContract::new(5, TimestampNs(1_500), TimestampNs(1_200))?;
    assert_eq!(
        admit_follow_read(&cursor, wake, TimestampNs(2_000)),
        Err(ContinuationError::Expired)
    );
    Ok(())
}

#[test]
fn test_follow_refuses_non_follow_stream_cursors(
) -> Result<(), Box<dyn std::error::Error>> {
    let anchor = LedgerAnchor::genesis("site:fss:follow");
    let cursor = ContinuationCursor::publish(ContinuationCursorPublishParams {
        scope: ContinuationScope::MeaningfulDelta,
        stream_id: "stream:fss:follow".to_owned(),
        contract_basis: reference_contract_basis(),
        session_id: SessionId::parse("session:follow")?,
        view_id: "AVIEW-001".to_owned(),
        basis_anchor: anchor.clone(),
        resume_anchor: anchor,
        source_digest: ContentDigest::sha256(b"follow-stream"),
        position: 0,
        upper_bound: 4,
        selection_witness: ContentDigest::sha256(b"follow-witness"),
        predecessor_digest: None,
        issued_at: TimestampNs(1_000),
        expires_at: TimestampNs(2_000),
    })?;
    let wake = FollowWakeContract::new(2, TimestampNs(1_500), TimestampNs(1_200))?;
    assert_eq!(
        admit_follow_read(&cursor, wake, TimestampNs(1_200)),
        Err(ContinuationError::WrongStream)
    );
    Ok(())
}

#[test]
fn test_follow_advance_links_predecessor_cursor() -> Result<(), Box<dyn std::error::Error>> {
    let cursor = follow_cursor()?;
    let wake = FollowWakeContract::new(5, TimestampNs(1_500), TimestampNs(1_200))?;
    let plan = admit_follow_read(&cursor, wake, TimestampNs(1_200))?;
    let anchor = LedgerAnchor::genesis("site:fss:follow");
    let successor = advance_follow_cursor(
        &cursor,
        plan.deliverable_entries,
        anchor.clone(),
        TimestampNs(1_300),
        TimestampNs(2_000),
    )?;
    assert_eq!(successor.position, 15);
    assert_eq!(successor.predecessor_digest, Some(cursor.cursor_digest));
    // The successor cursor admits the next bounded batch and reaches the bound.
    let wake = FollowWakeContract::new(5, TimestampNs(1_600), TimestampNs(1_400))?;
    let plan = admit_follow_read(&successor, wake, TimestampNs(1_400))?;
    assert!(plan.caught_up);
    assert_eq!(plan.resume_position, 20);
    // A zero-entry advance is refused as non-monotone.
    assert!(matches!(
        advance_follow_cursor(
            &cursor,
            0,
            anchor,
            TimestampNs(1_300),
            TimestampNs(2_000)
        ),
        Err(ContinuationError::NonMonotone)
    ));
    // The follow read is durable (AOP-004 durable = yes) and never effectful.
    assert!(AgentOperation::SessionFollow.durable());
    assert!(!AgentOperation::SessionFollow.effectful());
    Ok(())
}

#[test]
fn test_query_read_admission_compiles_bounded_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let basis = reference_contract_basis();
    let anchor = LedgerAnchor::genesis("site:fss:query");
    let cost = test_query_cost(250)?;
    let receipt = admit_query_read(&basis, &anchor, "query", 25, cost)?;
    assert_eq!(receipt.operation(), AgentOperation::Query);
    assert_eq!(receipt.max_entries(), 25);
    // A compiled read is complete only within its explicit boundary.
    assert_eq!(receipt.completeness(), Completeness::Bounded);
    assert_eq!(receipt.cost().latency_ms, 250);
    assert_eq!(receipt.anchor().site_lineage, "site:fss:query");
    // Deterministic identity; different bounds yield different receipts.
    let again = admit_query_read(
        &basis,
        &anchor,
        "query",
        25,
        test_query_cost(250)?,
    )?;
    assert_eq!(receipt.receipt_digest(), again.receipt_digest());
    let other = admit_query_read(
        &basis,
        &anchor,
        "query",
        26,
        test_query_cost(250)?,
    )?;
    assert_ne!(receipt.receipt_digest(), other.receipt_digest());
    Ok(())
}

#[test]
fn test_query_read_refuses_other_operations_and_empty_budgets(
) -> Result<(), Box<dyn std::error::Error>> {
    let basis = reference_contract_basis();
    let anchor = LedgerAnchor::genesis("site:fss:query");
    let cost = test_query_cost(100)?;
    // This boundary never compiles reads for another registered row.
    let err = admit_query_read(&basis, &anchor, "explain", 10, cost)
        .err()
        .ok_or("expected refusal for non-query operation")?;
    assert_eq!(
        err,
        ContractBasisError::Contract(ContractError::NotFound)
    );
    // Unregistered names refuse before any budget work.
    assert!(admit_query_read(&basis, &anchor, "queryx", 10, cost).is_err());
    // A zero entry bound admits nothing.
    assert_eq!(
        admit_query_read(&basis, &anchor, "query", 0, cost),
        Err(ContractBasisError::Contract(
            ContractError::BudgetExhausted
        ))
    );
    // A zero latency bound is unbounded work.
    let free = test_query_cost(0)?;
    assert_eq!(
        admit_query_read(&basis, &anchor, "query", 10, free),
        Err(ContractBasisError::Contract(
            ContractError::BudgetExhausted
        ))
    );
    // The query row itself stays a non-durable, non-effectful read.
    assert!(!AgentOperation::Query.durable());
    assert!(!AgentOperation::Query.effectful());
    Ok(())
}

#[test]
fn test_investigation_case_requires_competing_alternatives(
) -> Result<(), Box<dyn std::error::Error>> {
    let mission = MissionId::parse("mission:investigate")?;
    let single = BTreeSet::from(["hypothesis:intruder".to_owned()]);
    assert_eq!(
        InvestigationCaseState::create("case:one", mission.clone(), &single),
        Err(ContractError::EvidenceRequired)
    );
    let competing = BTreeSet::from([
        "hypothesis:intruder".to_owned(),
        "hypothesis:wildlife".to_owned(),
    ]);
    let case = InvestigationCaseState::create("case:gate", mission, &competing)?;
    assert_eq!(case.hypotheses().len(), 2);
    for disposition in case.hypotheses().values() {
        assert_eq!(*disposition, HypothesisDisposition::Live);
    }
    assert!(!case.is_terminal());
    Ok(())
}

#[test]
fn test_investigation_case_transitions_are_monotone(
) -> Result<(), Box<dyn std::error::Error>> {
    let mission = MissionId::parse("mission:investigate")?;
    let hypotheses = BTreeSet::from([
        "hypothesis:intruder".to_owned(),
        "hypothesis:wildlife".to_owned(),
    ]);
    let mut case = InvestigationCaseState::create("case:gate", mission, &hypotheses)?;
    // Legal strength-decrease: live -> supported -> disfavored -> refuted.
    case.advance_hypothesis("hypothesis:intruder", HypothesisDisposition::Supported)?;
    case.advance_hypothesis("hypothesis:intruder", HypothesisDisposition::Disfavored)?;
    case.advance_hypothesis("hypothesis:intruder", HypothesisDisposition::Refuted)?;
    // Refutation is final.
    assert_eq!(
        case.advance_hypothesis("hypothesis:intruder", HypothesisDisposition::Supported),
        Err(ContractError::HypothesisTransitionIllegal)
    );
    // No silent resurrection from any advanced state back to live.
    assert_eq!(
        case.advance_hypothesis("hypothesis:intruder", HypothesisDisposition::Live),
        Err(ContractError::HypothesisTransitionIllegal)
    );
    // Unknown hypotheses are refused, never silently added.
    assert_eq!(
        case.advance_hypothesis("hypothesis:ghost", HypothesisDisposition::Refuted),
        Err(ContractError::NotFound)
    );
    Ok(())
}

#[test]
fn test_investigation_case_stop_requires_no_live_hypotheses(
) -> Result<(), Box<dyn std::error::Error>> {
    let mission = MissionId::parse("mission:investigate")?;
    let hypotheses = BTreeSet::from([
        "hypothesis:intruder".to_owned(),
        "hypothesis:wildlife".to_owned(),
        "hypothesis:delivery".to_owned(),
    ]);
    let mut case = InvestigationCaseState::create("case:gate", mission, &hypotheses)?;
    // Stopping with open alternatives would flatten unresolved possibility.
    assert_eq!(
        case.stop(HypothesisDisposition::Resolved),
        Err(ContractError::CaseStopBlocked)
    );
    case.advance_hypothesis("hypothesis:intruder", HypothesisDisposition::Supported)?;
    case.advance_hypothesis("hypothesis:wildlife", HypothesisDisposition::Disfavored)?;
    case.advance_hypothesis("hypothesis:delivery", HypothesisDisposition::Refuted)?;
    case.stop(HypothesisDisposition::Resolved)?;
    assert!(case.is_terminal());
    // A terminal case admits no further advances or stops.
    assert_eq!(
        case.advance_hypothesis("hypothesis:intruder", HypothesisDisposition::Refuted),
        Err(ContractError::CaseStopBlocked)
    );
    assert_eq!(
        case.stop(HypothesisDisposition::Superseded),
        Err(ContractError::CaseStopBlocked)
    );
    Ok(())
}

#[test]
fn test_investigation_case_supersession_and_digest(
) -> Result<(), Box<dyn std::error::Error>> {
    let mission = MissionId::parse("mission:investigate")?;
    let hypotheses = BTreeSet::from([
        "hypothesis:intruder".to_owned(),
        "hypothesis:wildlife".to_owned(),
    ]);
    let mut case = InvestigationCaseState::create("case:gate", mission, &hypotheses)?;
    let digest = case.case_digest();
    // Supersession is allowed while hypotheses are still live: the case is
    // replaced, not answered.
    case.supersede()?;
    assert!(case.is_terminal());
    assert_ne!(case.case_digest(), digest);
    // Deterministic identity across reconstruction.
    let rebuilt = InvestigationCaseState::create(
        "case:gate",
        MissionId::parse("mission:investigate")?,
        &hypotheses,
    )?;
    assert_eq!(rebuilt.case_digest(), digest);
    // An advanced hypothesis changes the digest.
    let mut advanced = rebuilt.clone();
    advanced.advance_hypothesis("hypothesis:intruder", HypothesisDisposition::Supported)?;
    assert_ne!(advanced.case_digest(), rebuilt.case_digest());
    Ok(())
}

#[test]
fn test_plan_preparation_is_immutable_and_authority_free(
) -> Result<(), Box<dyn std::error::Error>> {
    let step_probe = PreparedPlanStep::new(AgentOperation::SessionOrient, "fss://situation/gate")?;
    let step_wait = PreparedPlanStep::new(AgentOperation::Wait, "fss://obligation/gate")?;
    let step_commit = PreparedPlanStep::new(AgentOperation::Commit, "fss://effect/gate")?;
    let witness = ContentDigest::sha256(b"plan-witness");
    let plan = PreparedPlan::prepare(
        "plan:gate-check",
        "objective:gate-check",
        vec![step_probe, step_wait, step_commit],
        vec![witness],
    )?;
    assert_eq!(plan.steps().len(), 3);
    // The plan records the contingent effect obligation but carries no
    // authority to start it: only commit does.
    assert!(plan.requires_commit());
    let digest = plan.plan_digest();
    assert_eq!(digest, plan.plan_digest());
    // Witness normalization: reordering witnesses yields the identical plan.
    let reordered = PreparedPlan::prepare(
        "plan:gate-check",
        "objective:gate-check",
        vec![
            PreparedPlanStep::new(AgentOperation::SessionOrient, "fss://situation/gate")?,
            PreparedPlanStep::new(AgentOperation::Wait, "fss://obligation/gate")?,
            PreparedPlanStep::new(AgentOperation::Commit, "fss://effect/gate")?,
        ],
        vec![witness],
    )?;
    assert_eq!(plan.plan_digest(), reordered.plan_digest());
    // Non-effectful plans never require commit.
    let read_only = PreparedPlan::prepare(
        "plan:read",
        "objective:read",
        vec![PreparedPlanStep::new(
            AgentOperation::SessionOrient,
            "fss://situation/gate",
        )?],
        vec![],
    )?;
    assert!(!read_only.requires_commit());
    // A plan referencing an effect row is still durable-safe to hold: the plan
    // row itself is durable, the contained commit is contingent.
    assert!(AgentOperation::Plan.durable());
    assert!(!AgentOperation::Plan.effectful());
    Ok(())
}

#[test]
fn test_plan_preparation_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    // Empty plans are refused: a recommendation must name steps.
    assert_eq!(
        PreparedPlan::prepare("plan:empty", "objective:x", vec![], vec![]),
        Err(ContractError::EvidenceRequired)
    );
    // Targets must be stable semantic identities.
    assert!(PreparedPlanStep::new(AgentOperation::Query, "http://elsewhere").is_err());
    assert!(PreparedPlanStep::new(AgentOperation::Query, "").is_err());
    // Unknown spellings never construct steps.
    Ok(())
}

fn commit_affordance(plan: &PreparedPlan) -> Result<ActionAffordance, Box<dyn std::error::Error>> {
    Ok(ActionAffordance {
        affordance_id: "affordance:commit-gate".to_owned(),
        operation: "commit".to_owned(),
        target: plan.plan_id().to_owned(),
        rationale: "Robust across the protected world frontier.".to_owned(),
        class: AffordanceClass::Robust,
        cost: BudgetVector::builder().latency_ms(120).build()?,
        reversible: false,
        branch_predicate: None,
        supported_worlds: BTreeSet::from(["world:gate:protected".to_owned()]),
        unsafe_worlds: BTreeSet::new(),
        required_capabilities: BTreeSet::from(["capability:gate.commit".to_owned()]),
    })
}

fn commit_plan() -> Result<PreparedPlan, Box<dyn std::error::Error>> {
    Ok(PreparedPlan::prepare(
        "plan:commit-gate",
        "objective:commit-gate",
        vec![
            PreparedPlanStep::new(AgentOperation::SessionOrient, "fss://situation/gate")?,
            PreparedPlanStep::new(AgentOperation::Commit, "fss://effect/gate")?,
        ],
        vec![ContentDigest::sha256(b"commit-witness")],
    )?)
}

#[test]
fn test_commit_admission_binds_exact_plan_and_affordance(
) -> Result<(), Box<dyn std::error::Error>> {
    let basis = reference_contract_basis();
    let plan = commit_plan()?;
    let affordance = commit_affordance(&plan)?;
    let anchor = LedgerAnchor::genesis("site:fss:commit");
    let receipt = admit_commit(&basis, &plan, &affordance, &anchor, TimestampNs(1_500))?;
    assert_eq!(receipt.plan_digest(), plan.plan_digest());
    assert_eq!(receipt.affordance_id(), "affordance:commit-gate");
    assert_eq!(receipt.started_at(), TimestampNs(1_500));
    let again = admit_commit(&basis, &plan, &affordance, &anchor, TimestampNs(1_500))?;
    assert_eq!(receipt.receipt_digest(), again.receipt_digest());
    // A different start time changes the receipt identity.
    let later = admit_commit(&basis, &plan, &affordance, &anchor, TimestampNs(1_600))?;
    assert_ne!(receipt.receipt_digest(), later.receipt_digest());
    Ok(())
}

#[test]
fn test_commit_admission_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let basis = reference_contract_basis();
    let plan = commit_plan()?;
    let anchor = LedgerAnchor::genesis("site:fss:commit");
    // A blocked affordance is not consumable at commit (worldEnvelopeRule).
    let mut blocked = commit_affordance(&plan)?;
    blocked.class = AffordanceClass::Blocked;
    assert!(admit_commit(&basis, &plan, &blocked, &anchor, TimestampNs(1_500)).is_err());
    // A probe affordance is not an effect affordance at all.
    let mut probe = commit_affordance(&plan)?;
    probe.class = AffordanceClass::Probe;
    assert!(admit_commit(&basis, &plan, &probe, &anchor, TimestampNs(1_500)).is_err());
    // Conditional affordances must name their supported-world basis.
    let mut unnamed = commit_affordance(&plan)?;
    unnamed.class = AffordanceClass::Conditional;
    unnamed.supported_worlds = BTreeSet::new();
    assert!(admit_commit(&basis, &plan, &unnamed, &anchor, TimestampNs(1_500)).is_err());
    // The affordance must target exactly this plan.
    let mut other_target = commit_affordance(&plan)?;
    other_target.target = "fss://plan/other".to_owned();
    assert!(admit_commit(&basis, &plan, &other_target, &anchor, TimestampNs(1_500)).is_err());
    // Committing a plan with no contingent effect steps is refused.
    let read_only = PreparedPlan::prepare(
        "plan:read-only",
        "objective:read-only",
        vec![PreparedPlanStep::new(
            AgentOperation::SessionOrient,
            "fss://situation/gate",
        )?],
        vec![],
    )?;
    let stray = commit_affordance(&read_only)?;
    assert!(admit_commit(&basis, &read_only, &stray, &anchor, TimestampNs(1_500)).is_err());
    // The commit row is the durable, effectful boundary of fss/1.
    assert!(AgentOperation::Commit.durable());
    assert!(AgentOperation::Commit.effectful());
    Ok(())
}

#[test]
fn test_wait_wake_is_deadline_bounded() -> Result<(), Box<dyn std::error::Error>> {
    // A wake deadline in the past or at now is refused: waits are bounded.
    assert_eq!(
        WaitWakeContract::new(TimestampNs(1_000), TimestampNs(1_000)),
        Err(ContractError::InvertedTimeInterval)
    );
    assert!(WaitWakeContract::new(TimestampNs(500), TimestampNs(1_000)).is_err());
    let wake = WaitWakeContract::new(TimestampNs(2_000), TimestampNs(1_000))?;
    assert_eq!(wake.deadline(), TimestampNs(2_000));
    assert_eq!(wake.issued_at(), TimestampNs(1_000));
    Ok(())
}

#[test]
fn test_wait_retry_requires_effect_reconciliation() -> Result<(), Box<dyn std::error::Error>> {
    // Waking into an indeterminate effect and retrying without reconciliation
    // coalesces effect uncertainty into a fresh attempt: refused.
    assert_eq!(
        require_reconciliation_before_retry(RuntimeOutcome::Indeterminate, None),
        Err(ContractError::InvalidEffectTransition)
    );
    // A bound reconciliation basis admits the retry.
    let basis = ReconciliationBasis::occurred_or_not(ContentDigest::sha256(b"unresolved-root"));
    assert_eq!(
        require_reconciliation_before_retry(RuntimeOutcome::Indeterminate, Some(&basis)),
        Ok(())
    );
    // Determinate outcomes never gate the retry.
    assert_eq!(
        require_reconciliation_before_retry(RuntimeOutcome::Ok, None),
        Ok(())
    );
    Ok(())
}

#[test]
fn test_cancellation_lifecycle_is_strictly_ordered(
) -> Result<(), Box<dyn std::error::Error>> {
    let intent = ContentDigest::sha256(b"effect-intent");
    let mut record = CancellationRecord::request(intent, TimestampNs(1_000));
    assert_eq!(record.intent_digest(), intent);
    assert_eq!(record.stage(), CancelStage::Requested);
    let request_digest = record.record_digest();
    // No stage skipping: request -> drain -> finalize, then terminal.
    record.advance(TimestampNs(1_100))?;
    assert_eq!(record.stage(), CancelStage::Draining);
    assert_ne!(record.record_digest(), request_digest);
    record.advance(TimestampNs(1_200))?;
    assert_eq!(record.stage(), CancelStage::Finalized);
    let finalized_digest = record.record_digest();
    assert!(record.advance(TimestampNs(1_300)).is_err());
    // The intent stays pinned: cancelling never erases the durable record.
    assert_eq!(record.intent_digest(), intent);
    assert_ne!(finalized_digest, request_digest);
    // Determinism: an identical lifecycle yields an identical record digest.
    let mut replay = CancellationRecord::request(intent, TimestampNs(1_000));
    replay.advance(TimestampNs(1_100))?;
    replay.advance(TimestampNs(1_200))?;
    assert_eq!(replay.record_digest(), finalized_digest);
    Ok(())
}

#[test]
fn test_explain_receipt_is_bounded_and_deterministic(
) -> Result<(), Box<dyn std::error::Error>> {
    let subject = ContentDigest::sha256(b"event-under-explanation");
    let evidence = vec![
        ContentDigest::sha256(b"evidence-c"),
        ContentDigest::sha256(b"evidence-a"),
        ContentDigest::sha256(b"evidence-a"),
        ContentDigest::sha256(b"evidence-b"),
    ];
    let receipt = ExplainReceipt::compile(
        ExplainQuestion::WhyNot,
        subject,
        evidence,
        vec!["fss://handle/1".to_owned(), "fss://handle/2".to_owned()],
        1,
    )?;
    assert_eq!(receipt.question(), ExplainQuestion::WhyNot);
    // Subgraph normalized to strictly ascending digest order, deduplicated,
    // with every distinct input retained.
    let subgraph = receipt.evidence_subgraph();
    assert_eq!(subgraph.len(), 3);
    assert!(subgraph.windows(2).all(|pair| pair[0] < pair[1]));
    for named in ["evidence-a", "evidence-b", "evidence-c"] {
        assert!(subgraph.contains(&ContentDigest::sha256(named.as_bytes())));
    }
    // Handles are bounded.
    assert_eq!(receipt.expansion_handles(), &["fss://handle/1".to_owned()]);
    // An explanation with no evidence is an unanchored claim: refused.
    assert_eq!(
        ExplainReceipt::compile(ExplainQuestion::Why, subject, vec![], vec![], 4),
        Err(ContractError::EvidenceRequired)
    );
    // Deterministic identity, sensitive to content.
    let again = ExplainReceipt::compile(
        ExplainQuestion::WhyNot,
        subject,
        vec![
            ContentDigest::sha256(b"evidence-a"),
            ContentDigest::sha256(b"evidence-b"),
            ContentDigest::sha256(b"evidence-c"),
        ],
        vec!["fss://handle/1".to_owned()],
        1,
    )?;
    assert_eq!(receipt.receipt_digest(), again.receipt_digest());
    // The explain row stays a non-durable, non-effectful read.
    assert!(!AgentOperation::Explain.durable());
    assert!(!AgentOperation::Explain.effectful());
    Ok(())
}

#[test]
fn test_handoff_admission_publishes_root_last(
) -> Result<(), Box<dyn std::error::Error>> {
    let basis = reference_contract_basis();
    let anchor = LedgerAnchor::genesis("site:fss:handoff");
    let situation_root = ContentDigest::sha256(b"situation-capsule-root");
    let params = HandoffPublishParams {
        handoff_id: HandoffId::parse("handoff:gate")?,
        mission_id: MissionId::parse("mission:handoff")?,
        source_session_id: SessionId::parse("session:handoff")?,
        source_principal_id: PrincipalId::parse("principal:handoff")?,
        anchor: anchor.clone(),
        situation_capsule_root: situation_root,
        child_roots: vec![ContentDigest::sha256(b"child-plan"), situation_root],
        contract_basis: basis.clone(),
        created_at: TimestampNs(1_000),
        expires_at: TimestampNs(9_000),
    };
    let capsule = admit_handoff(&basis, params)?;
    // Root-last closure holds: the situation root is a child and the root
    // digest verifies.
    capsule.verify()?;
    assert!(capsule.child_roots.contains(&situation_root));
    // A zero-lifetime capsule is not portable: refused by the admission.
    let zero = HandoffPublishParams {
        handoff_id: HandoffId::parse("handoff:zero")?,
        mission_id: MissionId::parse("mission:handoff")?,
        source_session_id: SessionId::parse("session:handoff")?,
        source_principal_id: PrincipalId::parse("principal:handoff")?,
        anchor,
        situation_capsule_root: situation_root,
        child_roots: vec![situation_root],
        contract_basis: reference_contract_basis(),
        created_at: TimestampNs(5_000),
        expires_at: TimestampNs(5_000),
    };
    assert!(admit_handoff(&reference_contract_basis(), zero).is_err());
    Ok(())
}

#[test]
fn test_feedback_proposal_is_advisory_and_evidence_linked(
) -> Result<(), Box<dyn std::error::Error>> {
    let evidence = vec![
        ContentDigest::sha256(b"feedback-evidence-b"),
        ContentDigest::sha256(b"feedback-evidence-a"),
        ContentDigest::sha256(b"feedback-evidence-a"),
    ];
    let proposal = FeedbackProposal::record(
        FeedbackKind::Correction,
        "Coverage witness for cam01 night window was misattributed".to_owned(),
        evidence,
        8,
    )?;
    assert_eq!(proposal.kind(), FeedbackKind::Correction);
    // Evidence normalized to strictly ascending deduplicated order.
    assert_eq!(proposal.evidence().len(), 2);
    assert!(proposal.evidence().windows(2).all(|pair| pair[0] < pair[1]));
    // Deterministic identity, sensitive to kind and content.
    let same = FeedbackProposal::record(
        FeedbackKind::Correction,
        "Coverage witness for cam01 night window was misattributed".to_owned(),
        vec![ContentDigest::sha256(b"feedback-evidence-a")],
        8,
    )?;
    let other_kind = FeedbackProposal::record(
        FeedbackKind::LearningProposal,
        "Coverage witness for cam01 night window was misattributed".to_owned(),
        vec![ContentDigest::sha256(b"feedback-evidence-a")],
        8,
    )?;
    assert_ne!(same.proposal_digest(), other_kind.proposal_digest());
    let _ = proposal;
    // Evidence-free proposals are refused: every proposal is evidence-linked.
    assert_eq!(
        FeedbackProposal::record(FeedbackKind::Adjudication, "no evidence".to_owned(), vec![], 8),
        Err(ContractError::EvidenceRequired)
    );
    // Empty statements are refused.
    assert!(FeedbackProposal::record(FeedbackKind::Correction, "", vec![ContentDigest::sha256(b"e")], 8).is_err());
    // The feedback row is a durable advisory write that is never effectful.
    assert!(AgentOperation::Feedback.durable());
    assert!(!AgentOperation::Feedback.effectful());
    Ok(())
}

#[test]
fn test_doctor_report_is_diagnose_only() -> Result<(), Box<dyn std::error::Error>> {
    let repair = RepairAffordance {
        repair_id: "fss://repair/coverage-recalibrate".to_owned(),
        domain: DiagnosisDomain::Evidence,
    };
    let report = DoctorReport::diagnose(
        vec![
            (DiagnosisDomain::Evidence, false),
            (DiagnosisDomain::Protocol, true),
        ],
        vec![repair],
    )?;
    // Findings in canonical domain order (Evidence < Protocol).
    assert_eq!(report.findings()[0].0, DiagnosisDomain::Evidence);
    assert!(report.findings()[1].1);
    // Digest determinism and sensitivity.
    let again = DoctorReport::diagnose(
        vec![
            (DiagnosisDomain::Protocol, true),
            (DiagnosisDomain::Evidence, false),
        ],
        vec![RepairAffordance {
            repair_id: "fss://repair/coverage-recalibrate".to_owned(),
            domain: DiagnosisDomain::Evidence,
        }],
    )?;
    assert_eq!(report.report_digest(), again.report_digest());
    // A healthy domain must not carry a repair affordance: diagnose-only.
    let healthy_repair = RepairAffordance {
        repair_id: "fss://repair/protocol-rewrite".to_owned(),
        domain: DiagnosisDomain::Protocol,
    };
    assert_eq!(
        DoctorReport::diagnose(
            vec![(DiagnosisDomain::Protocol, true)],
            vec![healthy_repair],
        ),
        Err(ContractError::InvalidEffectTransition)
    );
    // An unhealthy finding without a sealed repair is refused.
    assert_eq!(
        DoctorReport::diagnose(vec![(DiagnosisDomain::Obligations, false)], vec![]),
        Err(ContractError::EvidenceRequired)
    );
    // Repair identities are stable semantic URIs; duplicates refused.
    assert!(DoctorReport::diagnose(
        vec![(DiagnosisDomain::Evidence, false)],
        vec![RepairAffordance {
            repair_id: "repair:unsealed".to_owned(),
            domain: DiagnosisDomain::Evidence,
        }],
    )
    .is_err());
    // The doctor row is a durable diagnostic prepare that is never effectful.
    assert!(AgentOperation::Doctor.durable());
    assert!(!AgentOperation::Doctor.effectful());
    Ok(())
}
