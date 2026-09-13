#![forbid(unsafe_code)]
//! Deterministic contract tests for negative-evidence ledger and constraints (FSS-012).
//!
//! Enforces:
//! 1. Missing coverage witness / uncertified absence refusal.
//! 2. Coverage gap refusal (`CoverageContinuity::Gapped` or `Unknown`).
//! 3. Unknown format version refusal (refuse, never guess).
//! 4. Corrupt checksum and magic refusal.
//! 5. Duplicate entry identifier refusal.
//! 6. Non-canonical ordering refusal.
//! 7. Oversized input refusal.
//! 8. Tombstone consistency and revival condition enforcement.
//! 9. Seed entries (NEG-001, NEG-002, NEG-003) and golden fixture verification.
//! 10. Orthogonality of knowledge state, provenance class, and hypothesis disposition.

use std::collections::BTreeSet;
use std::error::Error;

use fss_core::acquisition::{CaptureDeviceTuple, CaptureRouteKind, Neg001ScenarioLog};
use fss_core::negative_evidence::{
    INITIAL_NEGATIVE_EVIDENCE_LEDGER_DIGEST, MAX_FAILURE_DOMAINS, MAX_NEG_TEXT_LEN,
    NEGATIVE_EVIDENCE_FORMAT_VERSION, NEGATIVE_EVIDENCE_LEDGER_MAGIC, NegativeDecision,
    NegativeEvidenceEntry, NegativeEvidenceError, NegativeEvidenceLedger, NegativeEvidenceSetup,
    initial_negative_evidence_ledger, provenance_class_as_str,
};
use fss_core::{
    Completeness, ContentDigest, CoverageContinuity, CoverageStopReason, CoverageWitness,
    DigestAlgorithm, HypothesisDisposition, KnowledgeState, LedgerAnchor, ProvenanceClass,
    Sha256Hasher, TombstoneReason,
};

fn make_valid_witness(neg_id: &str) -> CoverageWitness {
    CoverageWitness {
        anchor: LedgerAnchor::genesis("site:fss:test"),
        authorized_domain: BTreeSet::from([
            "domain:negative-evidence:architectural-constraints".to_string()
        ]),
        observed_domain: BTreeSet::from([
            "domain:negative-evidence:architectural-constraints".to_string()
        ]),
        excluded_domain: BTreeSet::new(),
        continuity: CoverageContinuity::Continuous,
        completeness: Completeness::Complete,
        negative_predicate: format!("architectural-violation-absence:{neg_id}"),
        stop_reason: CoverageStopReason::Complete,
        authorized_generation: 1,
        observed_generation: 1,
    }
}

fn make_valid_entry(neg_id: &str, decision: NegativeDecision) -> NegativeEvidenceEntry {
    NegativeEvidenceEntry {
        neg_id: neg_id.to_string(),
        date_commit: "2026-08-31 47ce055".to_string(),
        hypothesis: format!("Hypothesis for {neg_id}"),
        reasoning: format!("Reasoning for {neg_id}"),
        setup: NegativeEvidenceSetup {
            corpus: "test-corpus".to_string(),
            device_model: "test-device".to_string(),
            firmware_version: "v1.0.0".to_string(),
            platform: "linux-x86_64".to_string(),
            policy: "standards-first".to_string(),
            command: format!("cargo test -p fss-core --test {neg_id}"),
            artifact_digest: Some(ContentDigest::sha256(b"artifact-test")),
        },
        measured_result: format!("Measured result for {neg_id}"),
        decision,
        shared_failure_domains: BTreeSet::from(["domain-a".to_string(), "domain-b".to_string()]),
        revival_condition: format!("Revival condition for {neg_id}"),
        knowledge_state: KnowledgeState::Known,
        provenance_class: ProvenanceClass::Policy,
        disposition: HypothesisDisposition::Refuted,
        coverage_witness: make_valid_witness(neg_id),
        is_tombstone: false,
        tombstone_reason: None,
        proof_hash: Some(ContentDigest::sha256(b"proof-test")),
        reproduction_command: format!("cargo test -p fss-core --test {neg_id}"),
    }
}

#[test]
fn test_missing_coverage_witness_is_refused() -> Result<(), Box<dyn Error>> {
    let mut entry = make_valid_entry("NEG-010", NegativeDecision::Reject);
    // Erase negative predicate so coverage witness does not certify absence
    entry.coverage_witness.negative_predicate.clear();

    let err = entry
        .validate()
        .err()
        .ok_or("expected uncertified coverage error")?;

    match err {
        NegativeEvidenceError::UncertifiedCoverage { ref detail } => {
            assert!(
                detail.contains("does not certify absence"),
                "detail should indicate absence not certified: {detail}"
            );
            assert_eq!(err.error_id(), "ERR-NEG-UNCERTIFIED-COVERAGE-001");
        }
        other => return Err(format!("unexpected error variant: {other:?}").into()),
    }

    // Mismatched domain also fails certification
    let mut entry2 = make_valid_entry("NEG-011", NegativeDecision::Reject);
    entry2.coverage_witness.observed_domain.clear();
    let err2 = entry2
        .validate()
        .err()
        .ok_or("expected uncertified coverage error for domain mismatch")?;
    assert_eq!(err2.error_id(), "ERR-NEG-UNCERTIFIED-COVERAGE-001");

    Ok(())
}

#[test]
fn test_coverage_gap_is_refused() -> Result<(), Box<dyn Error>> {
    // 1. CoverageContinuity::Gapped must fail closed
    let mut entry_gapped = make_valid_entry("NEG-020", NegativeDecision::Reject);
    entry_gapped.coverage_witness.continuity = CoverageContinuity::Gapped;

    let err = entry_gapped
        .validate()
        .err()
        .ok_or("expected coverage gap error")?;

    match err {
        NegativeEvidenceError::CoverageGap { continuity } => {
            assert_eq!(continuity, CoverageContinuity::Gapped);
            assert_eq!(err.error_id(), "ERR-NEG-COVERAGE-GAP-001");
        }
        other => return Err(format!("unexpected error variant: {other:?}").into()),
    }

    // 2. CoverageContinuity::Unknown must also fail closed
    let mut entry_unknown = make_valid_entry("NEG-021", NegativeDecision::Reject);
    entry_unknown.coverage_witness.continuity = CoverageContinuity::Unknown;

    let err2 = entry_unknown
        .validate()
        .err()
        .ok_or("expected coverage gap error for unknown continuity")?;

    match err2 {
        NegativeEvidenceError::CoverageGap { continuity } => {
            assert_eq!(continuity, CoverageContinuity::Unknown);
            assert_eq!(err2.error_id(), "ERR-NEG-COVERAGE-GAP-001");
        }
        other => return Err(format!("unexpected error variant: {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_unknown_version_is_refused() -> Result<(), Box<dyn Error>> {
    let ledger = initial_negative_evidence_ledger()?;
    let mut bytes = ledger.encode_canonical()?;

    // Byte 8..12 is the 4-byte big-endian format version.
    // Replace it with version 2 (unknown).
    bytes[8..12].copy_from_slice(&2u32.to_be_bytes());

    // Recompute the trailing checksum for the modified payload to isolate the version check
    let payload_len = bytes.len() - 32;
    let (payload, _) = bytes.split_at(payload_len);
    let mut hasher = Sha256Hasher::new();
    hasher.update(fss_core::negative_evidence::SCHEMA_NEGATIVE_EVIDENCE_LEDGER.as_bytes());
    hasher.update(payload);
    let new_checksum = hasher.finalize()?;
    bytes[payload_len..].copy_from_slice(&new_checksum);

    let err = NegativeEvidenceLedger::decode_canonical(&bytes)
        .err()
        .ok_or("expected unknown version error")?;

    match err {
        NegativeEvidenceError::UnknownVersion { version } => {
            assert_eq!(version, 2);
            assert_eq!(err.error_id(), "ERR-NEG-UNKNOWN-VERSION-001");
        }
        other => return Err(format!("unexpected error variant: {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_corrupt_checksum_is_refused() -> Result<(), Box<dyn Error>> {
    let ledger = initial_negative_evidence_ledger()?;
    let mut bytes = ledger.encode_canonical()?;

    // Tamper with a byte in the payload
    let last_payload_byte = bytes.len() - 33;
    bytes[last_payload_byte] ^= 0x55;

    let err = NegativeEvidenceLedger::decode_canonical(&bytes)
        .err()
        .ok_or("expected corrupt checksum error")?;

    match err {
        NegativeEvidenceError::CorruptChecksum { expected, actual } => {
            assert_ne!(expected, actual);
            assert_eq!(err.error_id(), "ERR-NEG-CHECKSUM-MISMATCH-001");
        }
        other => return Err(format!("unexpected error variant: {other:?}").into()),
    }

    // Tamper with the trailer checksum directly
    let mut bytes2 = ledger.encode_canonical()?;
    let trailer_start = bytes2.len() - 10;
    bytes2[trailer_start] ^= 0xAA;

    let err2 = NegativeEvidenceLedger::decode_canonical(&bytes2)
        .err()
        .ok_or("expected corrupt checksum error for trailer tampering")?;
    assert_eq!(err2.error_id(), "ERR-NEG-CHECKSUM-MISMATCH-001");

    Ok(())
}

#[test]
fn test_corrupt_magic_is_refused() -> Result<(), Box<dyn Error>> {
    let ledger = initial_negative_evidence_ledger()?;
    let mut bytes = ledger.encode_canonical()?;

    // Tamper with magic header
    bytes[0..8].copy_from_slice(b"BADMAGIC");

    // Recompute trailer checksum so it reaches magic check
    let payload_len = bytes.len() - 32;
    let (payload, _) = bytes.split_at(payload_len);
    let mut hasher = Sha256Hasher::new();
    hasher.update(fss_core::negative_evidence::SCHEMA_NEGATIVE_EVIDENCE_LEDGER.as_bytes());
    hasher.update(payload);
    let new_checksum = hasher.finalize()?;
    bytes[payload_len..].copy_from_slice(&new_checksum);

    let err = NegativeEvidenceLedger::decode_canonical(&bytes)
        .err()
        .ok_or("expected corrupt magic error")?;

    match err {
        NegativeEvidenceError::CorruptMagic => {
            assert_eq!(err.error_id(), "ERR-NEG-CHECKSUM-MISMATCH-001");
        }
        other => return Err(format!("unexpected error variant: {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_duplicate_entry_id_is_refused() -> Result<(), Box<dyn Error>> {
    let mut ledger = NegativeEvidenceLedger::new();
    let entry1 = make_valid_entry("NEG-001", NegativeDecision::Narrow);
    let entry2 = make_valid_entry("NEG-001", NegativeDecision::Reject);

    ledger.append(entry1)?;
    let err = ledger
        .append(entry2)
        .err()
        .ok_or("expected duplicate entry id error")?;

    match err {
        NegativeEvidenceError::DuplicateEntryId { ref neg_id } => {
            assert_eq!(neg_id, "NEG-001");
            assert_eq!(err.error_id(), "ERR-NEG-DUPLICATE-ID-001");
        }
        other => return Err(format!("unexpected error variant: {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_non_canonical_order_is_refused() -> Result<(), Box<dyn Error>> {
    let mut ledger = NegativeEvidenceLedger::new();
    let entry_b = make_valid_entry("NEG-002", NegativeDecision::Reject);
    let entry_a = make_valid_entry("NEG-001", NegativeDecision::Narrow);

    ledger.append(entry_b)?;
    let err = ledger
        .append(entry_a)
        .err()
        .ok_or("expected non-canonical order error")?;

    match err {
        NegativeEvidenceError::NonCanonicalOrder {
            ref prior,
            ref current,
        } => {
            assert_eq!(prior, "NEG-002");
            assert_eq!(current, "NEG-001");
            assert_eq!(err.error_id(), "ERR-NEG-NON-CANONICAL-ORDER-001");
        }
        other => return Err(format!("unexpected error variant: {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_oversized_input_is_refused() -> Result<(), Box<dyn Error>> {
    let mut entry = make_valid_entry("NEG-050", NegativeDecision::Reject);
    // Exceed maximum text bound
    entry.hypothesis = "x".repeat(MAX_NEG_TEXT_LEN + 1);

    let err = entry
        .validate()
        .err()
        .ok_or("expected input oversized error")?;

    match err {
        NegativeEvidenceError::InputOversized { ref detail } => {
            assert!(
                detail.contains("hypothesis exceeds"),
                "detail should name hypothesis: {detail}"
            );
            assert_eq!(err.error_id(), "ERR-NEG-INPUT-OVERSIZED-001");
        }
        other => return Err(format!("unexpected error variant: {other:?}").into()),
    }

    // Exceed failure domains count
    let mut entry_domains = make_valid_entry("NEG-051", NegativeDecision::Reject);
    for i in 0..MAX_FAILURE_DOMAINS + 1 {
        entry_domains
            .shared_failure_domains
            .insert(format!("domain-{i:03}"));
    }
    let err_domains = entry_domains
        .validate()
        .err()
        .ok_or("expected input oversized error for domains")?;
    assert_eq!(err_domains.error_id(), "ERR-NEG-INPUT-OVERSIZED-001");

    Ok(())
}

#[test]
fn test_tombstone_preservation_and_rules() -> Result<(), Box<dyn Error>> {
    // 1. Tombstoned entry without tombstone_reason must fail validation
    let mut entry_invalid_tombstone = make_valid_entry("NEG-060", NegativeDecision::Reject);
    entry_invalid_tombstone.is_tombstone = true;
    entry_invalid_tombstone.tombstone_reason = None;

    let err = entry_invalid_tombstone
        .validate()
        .err()
        .ok_or("expected tombstoned entry error")?;
    assert_eq!(err.error_id(), "ERR-NEG-ENTRY-TOMBSTONED-001");

    // 2. Active entry with tombstone_reason must fail validation
    let mut entry_active_with_reason = make_valid_entry("NEG-061", NegativeDecision::Reject);
    entry_active_with_reason.is_tombstone = false;
    entry_active_with_reason.tombstone_reason = Some(TombstoneReason::Superseded);

    let err2 = entry_active_with_reason
        .validate()
        .err()
        .ok_or("expected error for active entry carrying tombstone reason")?;
    assert_eq!(err2.error_id(), "ERR-NEG-INPUT-OVERSIZED-001");

    // 3. Valid tombstoned entry passes validation and preserves reason
    let mut valid_tombstone = make_valid_entry("NEG-062", NegativeDecision::Reject);
    valid_tombstone.is_tombstone = true;
    valid_tombstone.tombstone_reason = Some(TombstoneReason::Superseded);
    assert!(valid_tombstone.validate().is_ok());

    // 4. Candidate revival requires satisfying explicit revival condition
    let ledger = initial_negative_evidence_ledger()?;
    let err3 = ledger
        .verify_revival_condition("NEG-001", false)
        .err()
        .ok_or("expected revival condition unmet error")?;

    match err3 {
        NegativeEvidenceError::RevivalConditionUnmet {
            ref neg_id,
            ref condition,
        } => {
            assert_eq!(neg_id, "NEG-001");
            assert!(
                condition.contains("official compatible SDK"),
                "revival condition should match NEG-001 doctrine: {condition}"
            );
            assert_eq!(err3.error_id(), "ERR-NEG-REVIVAL-UNMET-001");
        }
        other => return Err(format!("unexpected error variant: {other:?}").into()),
    }

    assert!(ledger.verify_revival_condition("NEG-001", true).is_ok());

    Ok(())
}

#[test]
fn test_seed_entries_and_golden_fixture() -> Result<(), Box<dyn Error>> {
    let ledger = initial_negative_evidence_ledger()?;

    // Exact initial entry count
    assert_eq!(ledger.len(), 3);

    // Exact NEG-001 doctrine
    let neg001 = ledger.get("NEG-001").ok_or("NEG-001 missing from ledger")?;
    assert_eq!(neg001.decision, NegativeDecision::Narrow);
    assert_eq!(neg001.knowledge_state, KnowledgeState::Known);
    assert_eq!(neg001.provenance_class, ProvenanceClass::Policy);
    assert_eq!(neg001.disposition, HypothesisDisposition::Refuted);
    assert!(
        neg001
            .revival_condition
            .contains("official compatible SDK/product listing")
    );
    assert!(neg001.coverage_witness.certifies_absence());

    // Exact NEG-002 doctrine
    let neg002 = ledger.get("NEG-002").ok_or("NEG-002 missing from ledger")?;
    assert_eq!(neg002.decision, NegativeDecision::Reject);
    assert_eq!(neg002.knowledge_state, KnowledgeState::Known);
    assert_eq!(neg002.provenance_class, ProvenanceClass::Policy);
    assert_eq!(neg002.disposition, HypothesisDisposition::Refuted);
    assert!(
        neg002
            .revival_condition
            .contains("Official local API/profile support")
    );
    assert!(neg002.coverage_witness.certifies_absence());

    // Exact NEG-003 doctrine
    let neg003 = ledger.get("NEG-003").ok_or("NEG-003 missing from ledger")?;
    assert_eq!(neg003.decision, NegativeDecision::Reject);
    assert_eq!(neg003.knowledge_state, KnowledgeState::Known);
    assert_eq!(neg003.provenance_class, ProvenanceClass::Policy);
    assert_eq!(neg003.disposition, HypothesisDisposition::Refuted);
    assert!(
        neg003
            .revival_condition
            .contains("candidate passes every task, license, cost")
    );
    assert!(neg003.coverage_witness.certifies_absence());

    // Canonical binary roundtrip
    let binary_bytes = ledger.encode_canonical()?;
    assert_eq!(&binary_bytes[..8], &NEGATIVE_EVIDENCE_LEDGER_MAGIC);
    let decoded = NegativeEvidenceLedger::decode_canonical(&binary_bytes)?;
    assert_eq!(decoded.len(), 3);
    assert_eq!(decoded, ledger);

    // Golden fixture file: bit-level stability assert
    let fixture_bytes = include_bytes!("../../../tests/fixtures/negative_evidence_ledger_v1.bin");
    assert_eq!(
        &binary_bytes[..],
        &fixture_bytes[..],
        "bit-level stability mismatch against golden fixture file"
    );

    // Golden fixture: compute and assert sha256 digest of binary representation
    let digest = ContentDigest::sha256(&binary_bytes);
    assert_eq!(digest.algorithm(), DigestAlgorithm::Sha256);
    assert_eq!(
        format!("{digest}"),
        INITIAL_NEGATIVE_EVIDENCE_LEDGER_DIGEST,
        "golden digest mismatch against pinned constant"
    );

    // Also assert root_digest() method matches pinned digest
    let root_dig = ledger.root_digest()?;
    assert_eq!(
        format!("{root_dig}"),
        INITIAL_NEGATIVE_EVIDENCE_LEDGER_DIGEST,
        "root_digest method mismatch against pinned constant"
    );

    // Verify format version in binary
    assert_eq!(
        u32::from_be_bytes([
            binary_bytes[8],
            binary_bytes[9],
            binary_bytes[10],
            binary_bytes[11]
        ]),
        NEGATIVE_EVIDENCE_FORMAT_VERSION
    );

    // SWARM RULE planted bypass test: any mutation to an entry MUST alter the pinned digest
    let modified_ledger = initial_negative_evidence_ledger()?;
    let mut modified_neg001 = modified_ledger
        .get("NEG-001")
        .ok_or("NEG-001 missing")?
        .clone();
    modified_neg001.hypothesis = "Subtly altered hypothesis text".to_string();
    let mut reconstructed = NegativeEvidenceLedger::new();
    reconstructed.append(modified_neg001)?;
    reconstructed.append(
        modified_ledger
            .get("NEG-002")
            .ok_or("NEG-002 missing")?
            .clone(),
    )?;
    reconstructed.append(
        modified_ledger
            .get("NEG-003")
            .ok_or("NEG-003 missing")?
            .clone(),
    )?;
    let modified_digest = reconstructed.root_digest()?;
    assert_ne!(
        format!("{modified_digest}"),
        INITIAL_NEGATIVE_EVIDENCE_LEDGER_DIGEST,
        "mutated entry must not match pinned freeze digest"
    );

    Ok(())
}

#[test]
fn test_knowledge_state_kept_orthogonal_to_provenance() -> Result<(), Box<dyn Error>> {
    // KnowledgeState, ProvenanceClass, and HypothesisDisposition must remain orthogonal
    let states = [
        KnowledgeState::Known,
        KnowledgeState::Estimated,
        KnowledgeState::Unknown,
        KnowledgeState::Conflicted,
        KnowledgeState::Stale,
        KnowledgeState::NotObservable,
        KnowledgeState::Redacted,
        KnowledgeState::Indeterminate,
        KnowledgeState::NotApplicable,
    ];
    let provenances = [
        ProvenanceClass::Observed,
        ProvenanceClass::Derived,
        ProvenanceClass::Predicted,
        ProvenanceClass::Remembered,
        ProvenanceClass::OperatorAsserted,
        ProvenanceClass::VendorClaimed,
        ProvenanceClass::Policy,
    ];
    let dispositions = [
        HypothesisDisposition::Live,
        HypothesisDisposition::Supported,
        HypothesisDisposition::Disfavored,
        HypothesisDisposition::Refuted,
        HypothesisDisposition::Resolved,
        HypothesisDisposition::Superseded,
    ];

    for &ks in &states {
        for &pc in &provenances {
            for &hd in &dispositions {
                let mut entry = make_valid_entry("NEG-099", NegativeDecision::Reject);
                entry.knowledge_state = ks;
                entry.provenance_class = pc;
                entry.disposition = hd;

                assert_eq!(entry.knowledge_state, ks);
                assert_eq!(entry.provenance_class, pc);
                assert_eq!(entry.disposition, hd);
                assert_ne!(
                    entry.knowledge_state.as_str(),
                    provenance_class_as_str(entry.provenance_class)
                );
            }
        }
    }

    Ok(())
}

#[test]
fn test_neg001_scenario_log_bridge() -> Result<(), Box<dyn Error>> {
    let witness = make_valid_witness("NEG-001");
    let log = Neg001ScenarioLog {
        schema_version: "fss.negative_evidence.scenario_log.v1",
        run_id: "run-neg001-test".to_string(),
        neg_id: "NEG-001",
        source_digest: ContentDigest::sha256(b"source"),
        registry_digest: ContentDigest::sha256(b"registry"),
        tuple: CaptureDeviceTuple {
            device_model: "DJI Flip".to_string(),
            firmware_version: "1.0.0".to_string(),
            controller_hardware: "rc-1".to_string(),
            controller_app: "app-1".to_string(),
            host_platform: "linux".to_string(),
            account_scope: "test-scope".to_string(),
        },
        route_kind: CaptureRouteKind::ProprietarySdkLiveCapture,
        authority_scope: "owner-authorized".to_string(),
        privacy_scope: "lab-isolated".to_string(),
        hypothesis_state: "rejected",
        finding_state: "unestablished_mobile_sdk",
        decision_state: "non_dependency_preserved",
        expected_readiness: fss_core::acquisition::CaptureReadinessState::Unsupported,
        observed_readiness: fss_core::acquisition::CaptureReadinessState::Unsupported,
        is_adapter_accepted: false,
        is_streaming: false,
        revival_condition_met: false,
        proof_hash: ContentDigest::sha256(b"proof-hash"),
        reproduction_command: "cargo test -p fss-core --test dji_flip_capture_route_contract"
            .to_string(),
    };

    let entry = NegativeEvidenceEntry::from_neg001_scenario_log(&log, witness)?;
    assert_eq!(entry.neg_id, "NEG-001");
    assert_eq!(entry.decision, NegativeDecision::Narrow);
    assert_eq!(entry.proof_hash, Some(log.proof_hash));
    assert!(entry.validate().is_ok());

    Ok(())
}
