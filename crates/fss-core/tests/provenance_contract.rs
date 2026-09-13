#![forbid(unsafe_code)]
//! Integration and contract tests for ProvenanceClass and PROV-001 (observed).
//!
//! Enforces:
//! - Exact normative identity, schema spelling, meaning, and effect authorization rule for PROV-001
//! - Resolution by stable ID ("PROV-001") and schema name ("observed") with rejection of malformed IDs
//! - Canonical encoding and decoding round-trip determinism
//! - Fail-closed requirement: Observed provenance must bind source evidence anchors (ContractError::EvidenceRequired)
//! - Orthogonality: Provenance is strictly orthogonal to KnowledgeState and never collapsed into a score
//! - Effect authorization: Observed + Known authorizes irreversible effects; non-authorizing provenance
//!   classes (predicted, remembered, vendor_claimed) are rejected even with Known epistemic state.

use std::error::Error;
use std::str::FromStr;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, KnowledgeCell, KnowledgeState, KnowledgeStateBasis, LedgerAnchor,
    PrivacyGeneration, ProvenanceClass, ReconciliationBasis, RedactionMarker, RedactionReason,
    StaleBasis, TimestampNs,
};

#[test]
fn test_observed_contract_row_properties() -> Result<(), Box<dyn Error>> {
    let prov = ProvenanceClass::Observed;

    // 1. Exact normative stable ID
    assert_eq!(prov.id(), "PROV-001");

    // 2. Exact normative schema spelling
    assert_eq!(prov.as_str(), "observed");
    assert_eq!(format!("{prov}"), "observed");

    // 3. Exact normative meaning
    assert_eq!(
        prov.meaning(),
        "Directly supported by canonical sensor, device, operator, or effect evidence."
    );

    // 4. Predicate helper
    assert!(prov.is_observed());

    // 5. May authorize irreversible effect: true (when accompanied by Known state and evidence)
    assert!(prov.may_authorize_irreversible_effect());

    Ok(())
}

#[test]
fn test_observed_parse_and_resolution() -> Result<(), Box<dyn Error>> {
    // Parse from stable ID
    let from_id = ProvenanceClass::from_id("PROV-001")?;
    assert_eq!(from_id, ProvenanceClass::Observed);

    // Parse from schema name
    let from_name = ProvenanceClass::from_name("observed")?;
    assert_eq!(from_name, ProvenanceClass::Observed);

    // Parse via FromStr
    let from_str_name = ProvenanceClass::from_str("observed")?;
    assert_eq!(from_str_name, ProvenanceClass::Observed);

    let from_str_id = ProvenanceClass::from_str("PROV-001")?;
    assert_eq!(from_str_id, ProvenanceClass::Observed);

    // Rejection of unknown / malformed identities
    assert_eq!(
        ProvenanceClass::from_id("PROV-000"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ProvenanceClass::from_id("PROV-008"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ProvenanceClass::from_id(""),
        Err(ContractError::InvalidIdentifier)
    );

    assert_eq!(
        ProvenanceClass::from_name("observe"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ProvenanceClass::from_name("OBSERVED"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ProvenanceClass::from_name(""),
        Err(ContractError::InvalidIdentifier)
    );

    Ok(())
}

#[test]
fn test_observed_canonical_roundtrip() -> Result<(), Box<dyn Error>> {
    let prov = ProvenanceClass::Observed;

    let mut encoder = CanonicalEncoder::new();
    prov.encode_canonical(&mut encoder);
    let encoded_bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&encoded_bytes);
    let decoded = ProvenanceClass::decode_canonical(&mut decoder)?;

    assert_eq!(decoded, prov);
    assert_eq!(decoded.id(), "PROV-001");
    assert_eq!(decoded.as_str(), "observed");

    Ok(())
}

#[test]
fn test_observed_requires_source_evidence_anchors_fail_closed() -> Result<(), Box<dyn Error>> {
    let evidence_digest = ContentDigest::sha256(b"canonical_sensor_evidence_anchor_001");

    // 1. Observed cell with empty evidence is REFUSED
    let cell_without_evidence = KnowledgeCell {
        claim_id: "claim:door:open:001".to_string(),
        statement: "Physical contact sensor observes door open".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![], // EMPTY - violates PROV-001 contract
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };

    assert_eq!(
        cell_without_evidence.validate(),
        Err(ContractError::EvidenceRequired)
    );
    assert_eq!(
        cell_without_evidence.validated(),
        Err(ContractError::EvidenceRequired)
    );

    // 2. Observed cell with canonical source evidence is ACCEPTED
    let cell_with_evidence = KnowledgeCell {
        claim_id: "claim:door:open:001".to_string(),
        statement: "Physical contact sensor observes door open".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };

    assert!(cell_with_evidence.validate().is_ok());
    let validated = cell_with_evidence.validated()?;
    assert!(validated.is_observed());
    assert_eq!(validated.evidence.len(), 1);
    assert_eq!(validated.evidence[0], evidence_digest);

    Ok(())
}

#[test]
fn test_observed_orthogonality_across_epistemic_states() -> Result<(), Box<dyn Error>> {
    let evidence_digest = ContentDigest::sha256(b"canonical_sensor_capture_packet");

    // Helper to generate appropriate state_basis for states that require one
    let basis_for = |state: KnowledgeState| -> Result<Option<KnowledgeStateBasis>, ContractError> {
        Ok(match state {
            KnowledgeState::Redacted => Some(KnowledgeStateBasis::Redaction(RedactionMarker {
                reason: RedactionReason::PrivacyProjection,
                privacy_generation: PrivacyGeneration::parse("privacy:projection:v1")?,
            })),
            KnowledgeState::Stale => {
                let mut older = LedgerAnchor::genesis("site:provenance-test");
                older.commit_sequence = 3;
                let mut current = LedgerAnchor::genesis("site:provenance-test");
                current.commit_sequence = 5;
                Some(KnowledgeStateBasis::Stale(StaleBasis::OlderAnchor {
                    valid_at: Box::new(older),
                    current: Box::new(current),
                }))
            }
            KnowledgeState::Indeterminate => {
                Some(KnowledgeStateBasis::Reconciliation(ReconciliationBasis {
                    unresolved_outcome_root: ContentDigest::sha256(b"unresolved_attempt"),
                    branches: std::collections::BTreeSet::from([
                        fss_core::ReconciliationBranch::Occurred,
                        fss_core::ReconciliationBranch::NotOccurred,
                    ]),
                }))
            }
            _ => None,
        })
    };

    let all_states = [
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

    for state in all_states {
        let cell = KnowledgeCell {
            claim_id: format!("claim:test:{}", state.as_str()),
            statement: format!("Testing orthogonality for {}", state.as_str()),
            knowledge_state: state,
            provenance: ProvenanceClass::Observed,
            hypothesis: None,
            evidence: vec![evidence_digest],
            contradictions: vec![],
            valid_until: None,
            state_basis: basis_for(state)?,
        };

        // Validate cell
        assert!(
            cell.validate().is_ok(),
            "Validation failed for state {}",
            state.as_str()
        );

        // Provenance remains Observed regardless of epistemic state
        assert_eq!(cell.provenance, ProvenanceClass::Observed);
        assert!(cell.is_observed());
        assert_eq!(cell.provenance.id(), "PROV-001");
        assert_eq!(cell.provenance.as_str(), "observed");

        // Provenance is distinct from knowledge state
        assert_ne!(cell.provenance.as_str(), state.as_str());
    }

    Ok(())
}

#[test]
fn test_observed_cell_with_known_state_and_valid_evidence_authorizes_effect(
) -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let evidence_digest = ContentDigest::sha256(b"admissible_fire_sensor_packet");

    // Positive case: Known + Observed + Evidence + No Contradictions + Unexpired
    let valid_cell = KnowledgeCell {
        claim_id: "claim:thermal:flame:001".to_string(),
        statement: "Thermal imaging observes flame signature in zone A".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };

    assert!(valid_cell.is_irreversible_effect_premise(now));

    // Negative case 1: Empty evidence cannot authorize effect
    let mut no_evidence = valid_cell.clone();
    no_evidence.evidence.clear();
    assert!(!no_evidence.is_irreversible_effect_premise(now));

    // Negative case 2: Contradictions present cannot authorize effect
    let mut conflicted_cell = valid_cell.clone();
    conflicted_cell
        .contradictions
        .push(ContentDigest::sha256(b"conflicting_sprinkler_telemetry"));
    assert!(!conflicted_cell.is_irreversible_effect_premise(now));

    // Negative case 3: Expired validity cannot authorize effect
    let mut expired_cell = valid_cell.clone();
    expired_cell.valid_until = Some(TimestampNs(500_000_000));
    assert!(!expired_cell.is_irreversible_effect_premise(now));

    Ok(())
}

#[test]
fn test_non_authorizing_provenances_rejected_for_irreversible_effects_even_when_known(
) -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let evidence_digest = ContentDigest::sha256(b"admissible_evidence");

    // Constitutional Invariant: Predicted, Remembered, and VendorClaimed can NEVER authorize
    // irreversible effects, even when epistemic state is set to Known.
    let non_authorizing = [
        (ProvenanceClass::Predicted, "predicted"),
        (ProvenanceClass::Remembered, "remembered"),
        (ProvenanceClass::VendorClaimed, "vendor_claimed"),
    ];

    for (class, name) in non_authorizing {
        assert!(
            !class.may_authorize_irreversible_effect(),
            "Provenance class {name} must not authorize irreversible effects"
        );

        let cell = KnowledgeCell {
            claim_id: format!("claim:test:{name}"),
            statement: format!("Testing non-authorizing {name}"),
            knowledge_state: KnowledgeState::Known,
            provenance: class,
            hypothesis: None,
            evidence: vec![evidence_digest],
            contradictions: vec![],
            valid_until: Some(TimestampNs(2_000_000_000)),
            state_basis: None,
        };

        assert!(
            !cell.is_irreversible_effect_premise(now),
            "KnowledgeCell with provenance {name} must be rejected as an irreversible effect premise even when Known"
        );
    }

    Ok(())
}

#[test]
fn test_observed_cannot_authorize_effects_with_non_known_epistemic_states(
) -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let evidence_digest = ContentDigest::sha256(b"admissible_evidence");

    // Constitutional Invariant: Even though Observed provenance permits effect authorization,
    // the epistemic state MUST be Known. Non-known states strictly fail the premise gate.
    let non_known_states = [
        KnowledgeState::Estimated,
        KnowledgeState::Unknown,
        KnowledgeState::Conflicted,
        KnowledgeState::Stale,
        KnowledgeState::NotObservable,
        KnowledgeState::Redacted,
        KnowledgeState::Indeterminate,
        KnowledgeState::NotApplicable,
    ];

    for state in non_known_states {
        let cell = KnowledgeCell {
            claim_id: format!("claim:test:{}", state.as_str()),
            statement: format!("Testing non-known state {}", state.as_str()),
            knowledge_state: state,
            provenance: ProvenanceClass::Observed,
            hypothesis: None,
            evidence: vec![evidence_digest],
            contradictions: vec![],
            valid_until: Some(TimestampNs(2_000_000_000)),
            state_basis: None,
        };

        assert!(
            !cell.is_irreversible_effect_premise(now),
            "Observed cell with state {} must not authorize irreversible effect",
            state.as_str()
        );
    }

    Ok(())
}
