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
//! 11. Seed doctrine is verbatim `docs/NEGATIVE_EVIDENCE.md` and seeds are not locally certified.
//! 12. Witness binding to the entry identifier and claimed domain.
//! 13. Decode-path canonicality (set order, entry order, duplicates, trailing bytes).
//! 14. Linked append-only supersession and evidence-backed revival.

use std::collections::BTreeSet;
use std::error::Error;

use fss_core::acquisition::{CaptureDeviceTuple, CaptureRouteKind, Neg001ScenarioLog};
use fss_core::negative_evidence::{
    EvidenceCertification, INITIAL_NEGATIVE_EVIDENCE_LEDGER_DIGEST, MAX_FAILURE_DOMAINS,
    MAX_NEG_TEXT_LEN, NEGATIVE_EVIDENCE_FORMAT_VERSION, NEGATIVE_EVIDENCE_LEDGER_MAGIC,
    NOT_LOCALLY_REPRODUCIBLE, NegativeDecision, NegativeEvidenceEntry, NegativeEvidenceError,
    NegativeEvidenceLedger, NegativeEvidenceSetup, SCHEMA_NEGATIVE_EVIDENCE_LEDGER,
    initial_negative_evidence_ledger, provenance_class_as_str,
};
use fss_core::{
    Completeness, ContentDigest, CoverageContinuity, CoverageStopReason, CoverageWitness,
    DigestAlgorithm, HypothesisDisposition, KnowledgeState, LedgerAnchor, ProvenanceClass,
    Sha256Hasher, TombstoneReason,
};

const TEST_DOMAIN: &str = "domain:negative-evidence:architectural-constraints";
const DOCTRINE: &str = include_str!("../../../docs/NEGATIVE_EVIDENCE.md");

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
        date_commit: "2026-09-12 test-fixture".to_string(),
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
        decision_text: format!("Decision text for {neg_id}"),
        shared_failure_domains: BTreeSet::from(["domain-a".to_string(), "domain-b".to_string()]),
        revival_condition: format!("Revival condition for {neg_id}"),
        knowledge_state: KnowledgeState::Known,
        provenance_class: ProvenanceClass::Policy,
        disposition: HypothesisDisposition::Refuted,
        coverage_witness: make_valid_witness(neg_id),
        claimed_domain: BTreeSet::from([TEST_DOMAIN.to_string()]),
        certification: EvidenceCertification::LocallyCertified,
        supersedes: None,
        is_tombstone: false,
        tombstone_reason: None,
        proof_hash: Some(ContentDigest::sha256(b"proof-test")),
        reproduction_command: format!("cargo test -p fss-core --test {neg_id}"),
    }
}

/// Appends the domain-separated trailing checksum to a canonical ledger payload.
fn reseal(mut payload: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut hasher = Sha256Hasher::new();
    hasher.update(SCHEMA_NEGATIVE_EVIDENCE_LEDGER.as_bytes());
    hasher.update(&payload);
    let checksum = hasher.finalize()?;
    payload.extend_from_slice(&checksum);
    Ok(payload)
}

/// Splits sealed canonical ledger bytes into their raw length-prefixed entry blocks.
fn entry_blocks(bytes: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let payload_len = bytes
        .len()
        .checked_sub(32)
        .ok_or("ledger shorter than trailer")?;
    let payload = bytes
        .get(..payload_len)
        .ok_or("ledger shorter than trailer")?;
    let mut cursor = 16;
    let mut blocks = Vec::new();
    while cursor < payload.len() {
        let len_bytes: [u8; 4] = payload
            .get(cursor..cursor + 4)
            .ok_or("truncated entry length")?
            .try_into()?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        let block = payload
            .get(cursor + 4..cursor + 4 + len)
            .ok_or("truncated entry")?;
        blocks.push(block.to_vec());
        cursor += 4 + len;
    }
    Ok(blocks)
}

/// Assembles and seals a ledger declaring `blocks.len()` entries, followed by `trailing` bytes.
fn assemble(blocks: &[Vec<u8>], trailing: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&NEGATIVE_EVIDENCE_LEDGER_MAGIC);
    payload.extend_from_slice(&NEGATIVE_EVIDENCE_FORMAT_VERSION.to_be_bytes());
    payload.extend_from_slice(&u32::try_from(blocks.len())?.to_be_bytes());
    for block in blocks {
        payload.extend_from_slice(&u32::try_from(block.len())?.to_be_bytes());
        payload.extend_from_slice(block);
    }
    payload.extend_from_slice(trailing);
    reseal(payload)
}

/// Canonical text encoding: 64-bit big-endian byte length followed by UTF-8 bytes.
fn text_encoding(value: &str) -> Vec<u8> {
    let mut encoded = (value.len() as u64).to_be_bytes().to_vec();
    encoded.extend_from_slice(value.as_bytes());
    encoded
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Extracts one field of one entry from `docs/NEGATIVE_EVIDENCE.md`, joining wrapped lines.
fn doctrine_field(neg_id: &str, label: &str) -> Result<String, Box<dyn Error>> {
    let header = format!("### {neg_id} ");
    let start = DOCTRINE
        .find(&header)
        .ok_or_else(|| format!("doctrine section {neg_id} missing"))?;
    let section = DOCTRINE.get(start..).ok_or("section slice")?;
    let end = section
        .get(header.len()..)
        .and_then(|rest| rest.find("\n### "))
        .map_or(section.len(), |i| i + header.len());
    let section = section.get(..end).ok_or("section slice")?;
    let marker = format!("- **{label}:** ");
    let pos = section
        .find(&marker)
        .ok_or_else(|| format!("doctrine field {label} of {neg_id} missing"))?;
    let rest = section.get(pos + marker.len()..).ok_or("field slice")?;
    let mut out = String::new();
    for (i, line) in rest.lines().enumerate() {
        if i == 0 {
            out.push_str(line.trim());
        } else if line.starts_with("  ") && !line.trim().is_empty() {
            out.push(' ');
            out.push_str(line.trim());
        } else {
            break;
        }
    }
    Ok(out)
}

fn revival_evidence(neg_id: &str, supersedes: &str) -> NegativeEvidenceEntry {
    let mut entry = make_valid_entry(neg_id, NegativeDecision::Revisit);
    entry.supersedes = Some(supersedes.to_string());
    entry.disposition = HypothesisDisposition::Supported;
    entry
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
    assert_eq!(err.error_id(), "ERR-NEG-VALIDATION-FAILED-001");

    // 2. Active entry with tombstone_reason must fail validation
    let mut entry_active_with_reason = make_valid_entry("NEG-061", NegativeDecision::Reject);
    entry_active_with_reason.is_tombstone = false;
    entry_active_with_reason.tombstone_reason = Some(TombstoneReason::Superseded);

    let err2 = entry_active_with_reason
        .validate()
        .err()
        .ok_or("expected error for active entry carrying tombstone reason")?;
    assert_eq!(err2.error_id(), "ERR-NEG-VALIDATION-FAILED-001");

    // 3. Valid tombstoned entry passes validation and preserves reason
    let mut valid_tombstone = make_valid_entry("NEG-062", NegativeDecision::Reject);
    valid_tombstone.is_tombstone = true;
    valid_tombstone.tombstone_reason = Some(TombstoneReason::Superseded);
    assert!(valid_tombstone.validate().is_ok());

    // 4. Candidate revival requires satisfying explicit revival condition
    let mut ledger = initial_negative_evidence_ledger()?;
    let err3 = ledger
        .verify_revival_condition("NEG-001", "NEG-004")
        .err()
        .ok_or("expected revival condition unmet error")?;

    match err3 {
        NegativeEvidenceError::RevivalConditionUnmet {
            ref neg_id,
            ref condition,
            ..
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

    ledger.append(revival_evidence("NEG-004", "NEG-001"))?;
    assert!(
        ledger
            .verify_revival_condition("NEG-001", "NEG-004")
            .is_ok()
    );

    Ok(())
}

#[test]
fn test_seed_entries_and_golden_fixture() -> Result<(), Box<dyn Error>> {
    let ledger = initial_negative_evidence_ledger()?;

    // Exact initial entry count
    assert_eq!(ledger.len(), 3);

    // Exact NEG-001 doctrine (not locally certified: the doctrine records no experiment)
    let neg001 = ledger.get("NEG-001").ok_or("NEG-001 missing from ledger")?;
    assert_eq!(neg001.decision, NegativeDecision::Narrow);
    assert_eq!(neg001.knowledge_state, KnowledgeState::Estimated);
    assert_eq!(neg001.provenance_class, ProvenanceClass::Policy);
    assert_eq!(neg001.disposition, HypothesisDisposition::Refuted);
    assert_eq!(
        neg001.revival_condition,
        "an official compatible SDK/product listing or a repeatable, owner-authorized, supportable capture surface."
    );
    assert!(!neg001.coverage_witness.certifies_absence());

    // Exact NEG-002 doctrine
    let neg002 = ledger.get("NEG-002").ok_or("NEG-002 missing from ledger")?;
    assert_eq!(neg002.decision, NegativeDecision::Reject);
    assert_eq!(neg002.knowledge_state, KnowledgeState::Estimated);
    assert_eq!(neg002.provenance_class, ProvenanceClass::Policy);
    assert_eq!(neg002.disposition, HypothesisDisposition::Refuted);
    assert_eq!(
        neg002.revival_condition,
        "official local API/profile support or a qualified owner-authorized adapter matrix."
    );
    assert!(!neg002.coverage_witness.certifies_absence());

    // Exact NEG-003 doctrine
    let neg003 = ledger.get("NEG-003").ok_or("NEG-003 missing from ledger")?;
    assert_eq!(neg003.decision, NegativeDecision::Reject);
    assert_eq!(neg003.knowledge_state, KnowledgeState::Estimated);
    assert_eq!(neg003.provenance_class, ProvenanceClass::Policy);
    assert_eq!(neg003.disposition, HypothesisDisposition::Refuted);
    assert_eq!(
        neg003.revival_condition,
        "a candidate passes every task, license, cost, privacy, and deterministic boundary against the decomposed incumbent under the same workload."
    );
    assert!(!neg003.coverage_witness.certifies_absence());

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
fn test_seed_entries_match_doctrine_document_verbatim() -> Result<(), Box<dyn Error>> {
    let ledger = initial_negative_evidence_ledger()?;
    for entry in ledger.entries() {
        let id = entry.neg_id.as_str();
        assert_eq!(entry.hypothesis, doctrine_field(id, "Hypothesis")?, "{id}");
        assert_eq!(
            entry.measured_result,
            doctrine_field(id, "Finding")?,
            "{id}"
        );
        assert_eq!(entry.decision_text, doctrine_field(id, "Decision")?, "{id}");
        assert_eq!(
            entry.revival_condition,
            doctrine_field(id, "Revival")?,
            "{id}"
        );
    }
    Ok(())
}

#[test]
fn test_seed_entries_are_truthfully_not_locally_certified() -> Result<(), Box<dyn Error>> {
    let ledger = initial_negative_evidence_ledger()?;
    for entry in ledger.entries() {
        let id = entry.neg_id.as_str();
        // Honest provenance: the doctrine document's introducing commit, no invented artifacts.
        assert_eq!(entry.date_commit, "2026-08-31 d82ac04", "{id}");
        match &entry.certification {
            EvidenceCertification::NotLocallyCertified { source } => {
                assert!(
                    source.starts_with(&format!("docs/NEGATIVE_EVIDENCE.md {id} ")),
                    "{source}"
                );
            }
            EvidenceCertification::LocallyCertified => {
                return Err(format!("{id} must not claim local certification").into());
            }
        }
        assert_eq!(entry.setup.artifact_digest, None, "{id}");
        assert_eq!(entry.proof_hash, None, "{id}");
        assert_eq!(entry.reproduction_command, NOT_LOCALLY_REPRODUCIBLE, "{id}");
        assert_eq!(entry.setup.command, NOT_LOCALLY_REPRODUCIBLE, "{id}");
        assert_eq!(
            entry.coverage_witness.continuity,
            CoverageContinuity::Unknown
        );
        assert!(entry.coverage_witness.observed_domain.is_empty());
        assert_eq!(entry.coverage_witness.observed_generation, 0);
        assert!(!entry.coverage_witness.certifies_absence());

        // Validation accepts exactly that: every non-Known knowledge state is admissible...
        for state in [
            KnowledgeState::Estimated,
            KnowledgeState::Unknown,
            KnowledgeState::Conflicted,
            KnowledgeState::Stale,
            KnowledgeState::NotObservable,
            KnowledgeState::Redacted,
            KnowledgeState::Indeterminate,
            KnowledgeState::NotApplicable,
        ] {
            let mut variant = entry.clone();
            variant.knowledge_state = state;
            assert!(variant.validate().is_ok(), "{id} {state:?}");
        }

        // ...but claiming Known or Observed without a certifying witness is refused.
        let mut known = entry.clone();
        known.knowledge_state = KnowledgeState::Known;
        assert_eq!(
            known.validate().err().map(|e| e.error_id()),
            Some("ERR-NEG-MISSING-COVERAGE-001")
        );
        let mut observed = entry.clone();
        observed.provenance_class = ProvenanceClass::Observed;
        assert_eq!(
            observed.validate().err().map(|e| e.error_id()),
            Some("ERR-NEG-MISSING-COVERAGE-001")
        );

        // An uncertified entry cannot smuggle in a witness that claims observation.
        let mut covered = entry.clone();
        covered.coverage_witness.continuity = CoverageContinuity::Continuous;
        covered.coverage_witness.completeness = Completeness::Complete;
        covered.coverage_witness.stop_reason = CoverageStopReason::Complete;
        covered.coverage_witness.observed_domain =
            covered.coverage_witness.authorized_domain.clone();
        covered.coverage_witness.authorized_generation = 1;
        covered.coverage_witness.observed_generation = 1;
        assert_eq!(
            covered.validate().err().map(|e| e.error_id()),
            Some("ERR-NEG-VALIDATION-FAILED-001")
        );

        // Relabelling a seed as locally certified fails: its witness never observed anything.
        let mut relabelled = entry.clone();
        relabelled.certification = EvidenceCertification::LocallyCertified;
        assert_eq!(
            relabelled.validate(),
            Err(NegativeEvidenceError::CoverageGap {
                continuity: CoverageContinuity::Unknown
            })
        );
    }
    Ok(())
}

#[test]
fn test_witness_must_be_bound_to_its_entry() -> Result<(), Box<dyn Error>> {
    // NEG-005 carrying a certifying witness for NEG-001 over an unrelated domain.
    let unrelated = BTreeSet::from(["domain:unrelated:thermal-camera".to_string()]);
    let mut foreign = make_valid_witness("NEG-001");
    foreign.authorized_domain = unrelated.clone();
    foreign.observed_domain = unrelated.clone();
    assert!(foreign.certifies_absence());

    let mut entry = make_valid_entry("NEG-005", NegativeDecision::Reject);
    entry.coverage_witness = foreign;
    let expected = NegativeEvidenceError::WitnessNotBound {
        neg_id: "NEG-005".to_string(),
        detail: "negative predicate 'architectural-violation-absence:NEG-001' names 'NEG-001', not this entry".to_string(),
    };
    assert_eq!(entry.validate(), Err(expected.clone()));
    assert_eq!(expected.error_id(), "ERR-NEG-UNCERTIFIED-COVERAGE-001");
    let mut ledger = initial_negative_evidence_ledger()?;
    assert_eq!(ledger.append(entry), Err(expected));

    // Predicate names the entry, but the witness covers an unrelated domain.
    let mut wrong_domain = make_valid_entry("NEG-005", NegativeDecision::Reject);
    wrong_domain.coverage_witness.authorized_domain = unrelated.clone();
    wrong_domain.coverage_witness.observed_domain = unrelated;
    assert_eq!(
        wrong_domain.validate(),
        Err(NegativeEvidenceError::WitnessNotBound {
            neg_id: "NEG-005".to_string(),
            detail: "witness domain {domain:unrelated:thermal-camera} does not match claimed domain {domain:negative-evidence:architectural-constraints}".to_string(),
        })
    );

    // A predicate naming an identifier that merely starts with this one is not bound.
    let mut prefix = make_valid_entry("NEG-005", NegativeDecision::Reject);
    prefix.coverage_witness.negative_predicate = "architectural-violation-absence:NEG-0050".into();
    assert_eq!(
        prefix.validate().err().map(|e| e.error_id()),
        Some("ERR-NEG-UNCERTIFIED-COVERAGE-001")
    );
    Ok(())
}

#[test]
fn test_decode_refuses_non_canonical_failure_domain_sets() -> Result<(), Box<dyn Error>> {
    let mut ledger = NegativeEvidenceLedger::new();
    ledger.append(make_valid_entry("NEG-010", NegativeDecision::Reject))?;
    let bytes = ledger.encode_canonical()?;
    let blocks = entry_blocks(&bytes)?;
    let block = blocks.first().ok_or("missing entry block")?;

    // Harness control: reassembling the untouched block reproduces the canonical bytes.
    assert_eq!(assemble(&blocks, &[])?, bytes);

    let a = text_encoding("domain-a");
    let b = text_encoding("domain-b");
    let pos_a = find(block, &a).ok_or("domain-a encoding not found")?;
    let pos_b = find(block, &b).ok_or("domain-b encoding not found")?;
    assert_eq!(pos_b, pos_a + a.len());

    for (case, first, second) in [
        ("[domain-b, domain-a]", &b, &a),
        ("[domain-a, domain-a]", &a, &a),
    ] {
        let mut mutated = block.clone();
        mutated[pos_a..pos_a + a.len()].copy_from_slice(first);
        mutated[pos_b..pos_b + b.len()].copy_from_slice(second);
        let err = NegativeEvidenceLedger::decode_canonical(&assemble(&[mutated], &[])?)
            .err()
            .ok_or_else(|| format!("{case} must be refused"))?;
        assert_eq!(
            err,
            NegativeEvidenceError::NonCanonicalSet {
                detail: "entry #0: set elements must be strictly increasing without duplicates"
                    .to_string()
            },
            "{case}"
        );
        assert_eq!(err.error_id(), "ERR-NEG-NON-CANONICAL-ORDER-001");
    }
    Ok(())
}

#[test]
fn test_decode_refuses_reordered_and_duplicate_entries() -> Result<(), Box<dyn Error>> {
    let bytes = initial_negative_evidence_ledger()?.encode_canonical()?;
    let blocks = entry_blocks(&bytes)?;
    assert_eq!(blocks.len(), 3);
    assert_eq!(assemble(&blocks, &[])?, bytes);

    let reordered = vec![blocks[1].clone(), blocks[0].clone(), blocks[2].clone()];
    assert_eq!(
        NegativeEvidenceLedger::decode_canonical(&assemble(&reordered, &[])?),
        Err(NegativeEvidenceError::NonCanonicalOrder {
            prior: "NEG-002".to_string(),
            current: "NEG-001".to_string(),
        })
    );

    let duplicated = vec![blocks[0].clone(), blocks[0].clone(), blocks[2].clone()];
    assert_eq!(
        NegativeEvidenceLedger::decode_canonical(&assemble(&duplicated, &[])?),
        Err(NegativeEvidenceError::DuplicateEntryId {
            neg_id: "NEG-001".to_string(),
        })
    );
    Ok(())
}

#[test]
fn test_decode_refuses_trailing_bytes() -> Result<(), Box<dyn Error>> {
    let bytes = initial_negative_evidence_ledger()?.encode_canonical()?;
    let blocks = entry_blocks(&bytes)?;

    let err = NegativeEvidenceLedger::decode_canonical(&assemble(&blocks, &[0u8])?)
        .err()
        .ok_or("trailing payload byte must be refused")?;
    assert_eq!(
        err,
        NegativeEvidenceError::TrailingBytes {
            detail: "1 unparsed trailing bytes after the last entry".to_string()
        }
    );
    assert_eq!(err.error_id(), "ERR-NEG-CHECKSUM-MISMATCH-001");

    let mut padded = blocks.clone();
    padded[2].push(0u8);
    assert_eq!(
        NegativeEvidenceLedger::decode_canonical(&assemble(&padded, &[])?),
        Err(NegativeEvidenceError::TrailingBytes {
            detail: "entry #2 has 1 unparsed trailing bytes".to_string()
        })
    );
    Ok(())
}

#[test]
fn test_tombstone_reason_must_round_trip() -> Result<(), Box<dyn Error>> {
    // Unknown(1) would encode as tag 1 and decode as Deleted: refused.
    let mut colliding = make_valid_entry("NEG-063", NegativeDecision::Reject);
    colliding.is_tombstone = true;
    colliding.tombstone_reason = Some(TombstoneReason::Unknown(1));
    assert_eq!(
        colliding.validate().err().map(|e| e.error_id()),
        Some("ERR-NEG-VALIDATION-FAILED-001")
    );
    let mut ledger = NegativeEvidenceLedger::new();
    assert!(ledger.append(colliding).is_err());

    // A forward-compatible unknown tag round-trips exactly; it is never flattened.
    let mut future = make_valid_entry("NEG-064", NegativeDecision::Reject);
    future.is_tombstone = true;
    future.tombstone_reason = Some(TombstoneReason::unknown(9)?);
    ledger.append(future.clone())?;
    let decoded = NegativeEvidenceLedger::decode_canonical(&ledger.encode_canonical()?)?;
    assert_eq!(decoded.get("NEG-064"), Some(&future));
    Ok(())
}

#[test]
fn test_error_identities_are_specific() -> Result<(), Box<dyn Error>> {
    for bad in ["BAD-070", "", "NEG-", "NEG-07x"] {
        let mut entry = make_valid_entry("NEG-070", NegativeDecision::Reject);
        entry.neg_id = bad.to_string();
        assert_eq!(
            entry.validate().err().map(|e| e.error_id()),
            Some("ERR-NEG-VALIDATION-FAILED-001"),
            "{bad:?}"
        );
    }
    let mut long = make_valid_entry("NEG-070", NegativeDecision::Reject);
    long.neg_id = format!("NEG-{}", "1".repeat(80));
    assert_eq!(
        long.validate().err().map(|e| e.error_id()),
        Some("ERR-NEG-INPUT-OVERSIZED-001")
    );
    assert_eq!(
        NegativeDecision::parse("Reject")
            .err()
            .map(|e| e.error_id()),
        Some("ERR-NEG-VALIDATION-FAILED-001")
    );
    Ok(())
}

#[test]
fn test_supersession_is_linked_and_append_only() -> Result<(), Box<dyn Error>> {
    let initial = initial_negative_evidence_ledger()?;
    let mut ledger = initial.clone();
    let mut successor = make_valid_entry("NEG-004", NegativeDecision::Revisit);
    successor.supersedes = Some("NEG-001".to_string());
    ledger.append(successor)?;

    // The superseded row is preserved unchanged (append-only) and the link survives decode.
    assert_eq!(ledger.get("NEG-001"), initial.get("NEG-001"));
    let decoded = NegativeEvidenceLedger::decode_canonical(&ledger.encode_canonical()?)?;
    assert_eq!(
        decoded.get("NEG-004").and_then(|e| e.supersedes.clone()),
        Some("NEG-001".to_string())
    );

    // A link to an earlier identifier absent from the ledger is refused.
    let mut dangling = make_valid_entry("NEG-005", NegativeDecision::Reject);
    dangling.supersedes = Some("NEG-000".to_string());
    assert!(dangling.validate().is_ok());
    assert_eq!(
        ledger.append(dangling).err().map(|e| e.error_id()),
        Some("ERR-NEG-VALIDATION-FAILED-001")
    );

    // A link to itself or to a later entry is refused.
    for target in ["NEG-006", "NEG-007"] {
        let mut forward = make_valid_entry("NEG-006", NegativeDecision::Reject);
        forward.supersedes = Some(target.to_string());
        assert_eq!(
            forward.validate().err().map(|e| e.error_id()),
            Some("ERR-NEG-VALIDATION-FAILED-001"),
            "{target}"
        );
    }
    Ok(())
}

#[test]
fn test_revival_requires_immutable_certified_evidence_row() -> Result<(), Box<dyn Error>> {
    let mut ledger = initial_negative_evidence_ledger()?;
    let unmet = |ledger: &NegativeEvidenceLedger, target: &str, evidence: &str| match ledger
        .verify_revival_condition(target, evidence)
    {
        Err(NegativeEvidenceError::RevivalConditionUnmet { reason, .. }) => Ok(reason),
        other => Err(format!("expected unmet revival, got {other:?}")),
    };

    assert_eq!(
        unmet(&ledger, "NEG-001", "NEG-004")?,
        "no immutable evidence row 'NEG-004' exists in this ledger"
    );

    ledger.append(revival_evidence("NEG-004", "NEG-002"))?;
    assert_eq!(
        unmet(&ledger, "NEG-001", "NEG-004")?,
        "evidence row 'NEG-004' does not supersede 'NEG-001'"
    );

    let mut no_proof = revival_evidence("NEG-005", "NEG-001");
    no_proof.proof_hash = None;
    ledger.append(no_proof)?;
    assert_eq!(
        unmet(&ledger, "NEG-001", "NEG-005")?,
        "evidence row 'NEG-005' carries no proof hash"
    );

    let mut still_refuted = revival_evidence("NEG-006", "NEG-001");
    still_refuted.disposition = HypothesisDisposition::Refuted;
    ledger.append(still_refuted)?;
    assert_eq!(
        unmet(&ledger, "NEG-001", "NEG-006")?,
        "evidence row 'NEG-006' records disposition 'refuted'; revival requires 'supported'"
    );

    ledger.append(revival_evidence("NEG-007", "NEG-001"))?;
    assert!(
        ledger
            .verify_revival_condition("NEG-001", "NEG-007")
            .is_ok()
    );

    // Evidence that was never locally certified cannot revive a constraint.
    let mut external = ledger.get("NEG-003").ok_or("NEG-003 missing")?.clone();
    external.neg_id = "NEG-008".to_string();
    external.supersedes = Some("NEG-001".to_string());
    external.disposition = HypothesisDisposition::Supported;
    external.coverage_witness.negative_predicate = "architectural-violation-absence:NEG-008".into();
    external.proof_hash = Some(ContentDigest::sha256(b"external-report"));
    ledger.append(external)?;
    assert_eq!(
        unmet(&ledger, "NEG-001", "NEG-008")?,
        "evidence row 'NEG-008' is not locally certified"
    );

    // Tombstone state and disposition of the target are respected.
    let mut tombstoned = make_valid_entry("NEG-009", NegativeDecision::Reject);
    tombstoned.is_tombstone = true;
    tombstoned.tombstone_reason = Some(TombstoneReason::Superseded);
    ledger.append(tombstoned)?;
    ledger.append(revival_evidence("NEG-010", "NEG-009"))?;
    assert_eq!(
        ledger.verify_revival_condition("NEG-009", "NEG-010"),
        Err(NegativeEvidenceError::EntryTombstoned {
            neg_id: "NEG-009".to_string()
        })
    );

    let mut superseded = make_valid_entry("NEG-011", NegativeDecision::Reject);
    superseded.disposition = HypothesisDisposition::Superseded;
    ledger.append(superseded)?;
    ledger.append(revival_evidence("NEG-012", "NEG-011"))?;
    assert_eq!(
        ledger
            .verify_revival_condition("NEG-011", "NEG-012")
            .err()
            .map(|e| e.error_id()),
        Some("ERR-NEG-VALIDATION-FAILED-001")
    );

    assert_eq!(
        ledger
            .verify_revival_condition("NEG-999", "NEG-007")
            .err()
            .map(|e| e.error_id()),
        Some("ERR-NEG-VALIDATION-FAILED-001")
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

    let entry = NegativeEvidenceEntry::from_neg001_scenario_log(
        &log,
        witness,
        "2026-09-12 run-neg001-test",
    )?;
    assert_eq!(entry.neg_id, "NEG-001");
    assert_eq!(entry.decision, NegativeDecision::Narrow);
    assert_eq!(entry.proof_hash, Some(log.proof_hash));
    assert!(entry.validate().is_ok());
    assert_eq!(entry.date_commit, "2026-09-12 run-neg001-test");
    assert_eq!(entry.hypothesis, doctrine_field("NEG-001", "Hypothesis")?);
    assert!(
        entry
            .measured_result
            .contains("adapter_accepted=false, streaming=false")
    );

    // A witness certifying a different entry cannot be bridged onto NEG-001.
    let foreign = make_valid_witness("NEG-002");
    assert_eq!(
        NegativeEvidenceEntry::from_neg001_scenario_log(&log, foreign, "2026-09-12 run")
            .err()
            .map(|e| e.error_id()),
        Some("ERR-NEG-UNCERTIFIED-COVERAGE-001")
    );

    Ok(())
}
