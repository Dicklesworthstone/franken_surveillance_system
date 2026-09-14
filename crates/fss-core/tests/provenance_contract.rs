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

use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use fss_core::{
    BeliefInterval, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder,
    ContentDigest, ContractBasis, ContractBasisRegistryBytes, ContractError, DeltaPriority,
    DerivedBelief, DerivedBeliefParams, Generation, KnowledgeCell, KnowledgeCellParams,
    KnowledgeState, KnowledgeStateBasis, LedgerAnchor, MeaningfulDelta, MeaningfulDeltaClass,
    PrivacyGeneration, ProvenanceClass, ReconciliationBasis, RedactionMarker, RedactionReason,
    SessionId, SituationFrame, StaleBasis, TimestampNs, WorldEnvelope,
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

    assert_eq!(
        ProvenanceClass::from_str("PROV-001"),
        Err(ContractError::InvalidIdentifier)
    );

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
    let empty_params = KnowledgeCellParams {
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
        KnowledgeCell::new(empty_params),
        Err(ContractError::EvidenceRequired)
    );

    // 2. Observed cell with canonical source evidence is ACCEPTED
    let cell_with_evidence = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:door:open:001".to_string(),
        statement: "Physical contact sensor observes door open".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;

    assert!(cell_with_evidence.validate().is_ok());
    let validated = cell_with_evidence.validated()?;
    assert!(validated.is_observed());
    assert_eq!(validated.evidence().len(), 1);
    assert_eq!(validated.evidence()[0], evidence_digest);

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
        let cell = KnowledgeCell::new(KnowledgeCellParams {
            claim_id: format!("claim:test:{}", state.as_str()),
            statement: format!("Testing orthogonality for {}", state.as_str()),
            knowledge_state: state,
            provenance: ProvenanceClass::Observed,
            hypothesis: None,
            evidence: vec![evidence_digest],
            contradictions: vec![],
            valid_until: None,
            state_basis: basis_for(state)?,
        })?;

        // Validate cell
        assert!(
            cell.validate().is_ok(),
            "Validation failed for state {}",
            state.as_str()
        );

        // Provenance remains Observed regardless of epistemic state
        assert_eq!(cell.provenance(), ProvenanceClass::Observed);
        assert!(cell.is_observed());
        assert_eq!(cell.provenance().id(), "PROV-001");
        assert_eq!(cell.provenance().as_str(), "observed");

        // Provenance is distinct from knowledge state
        assert_ne!(cell.provenance().as_str(), state.as_str());
    }

    Ok(())
}

#[test]
fn test_observed_cell_with_known_state_and_valid_evidence_authorizes_effect()
-> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let evidence_digest = ContentDigest::sha256(b"admissible_fire_sensor_packet");

    // Positive case: Known + Observed + Evidence + No Contradictions + Unexpired
    let valid_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:thermal:flame:001".to_string(),
        statement: "Thermal imaging observes flame signature in zone A".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;

    assert!(valid_cell.is_irreversible_effect_premise(now));

    // Negative case 1: Empty evidence cannot authorize effect
    assert_eq!(
        KnowledgeCell::new(KnowledgeCellParams {
            claim_id: "claim:thermal:flame:001".to_string(),
            statement: "Thermal imaging observes flame signature in zone A".to_string(),
            knowledge_state: KnowledgeState::Known,
            provenance: ProvenanceClass::Observed,
            hypothesis: None,
            evidence: vec![],
            contradictions: vec![],
            valid_until: Some(TimestampNs(2_000_000_000)),
            state_basis: None,
        }),
        Err(ContractError::EvidenceRequired)
    );

    // Negative case 2: Contradictions present cannot authorize effect
    let conflicted_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:thermal:flame:001".to_string(),
        statement: "Thermal imaging observes flame signature in zone A".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![ContentDigest::sha256(b"conflicting_sprinkler_telemetry")],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;
    assert!(!conflicted_cell.is_irreversible_effect_premise(now));

    // Negative case 3: Expired validity cannot authorize effect
    let expired_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:thermal:flame:001".to_string(),
        statement: "Thermal imaging observes flame signature in zone A".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(500_000_000)),
        state_basis: None,
    })?;
    assert!(!expired_cell.is_irreversible_effect_premise(now));

    Ok(())
}

#[test]
fn test_non_authorizing_provenances_rejected_for_irreversible_effects_even_when_known()
-> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let evidence_digest = ContentDigest::sha256(b"admissible_evidence");

    // Constitutional Invariant: Derived, Predicted, Remembered, and VendorClaimed can NEVER authorize
    // irreversible effects, even when epistemic state is set to Known.
    let non_authorizing = [
        (ProvenanceClass::Derived, "derived"),
        (ProvenanceClass::Predicted, "predicted"),
        (ProvenanceClass::Remembered, "remembered"),
        (ProvenanceClass::VendorClaimed, "vendor_claimed"),
    ];

    for (class, name) in non_authorizing {
        assert!(
            !class.may_authorize_irreversible_effect(),
            "Provenance class {name} must not authorize irreversible effects"
        );

        let cell_res = KnowledgeCell::new(KnowledgeCellParams {
            claim_id: format!("claim:test:{name}"),
            statement: format!("Testing non-authorizing {name}"),
            knowledge_state: KnowledgeState::Known,
            provenance: class,
            hypothesis: None,
            evidence: vec![evidence_digest],
            contradictions: vec![],
            valid_until: Some(TimestampNs(2_000_000_000)),
            state_basis: None,
        });

        if let Ok(cell) = cell_res {
            assert!(
                !cell.is_irreversible_effect_premise(now),
                "KnowledgeCell with provenance {name} must be rejected as an irreversible effect premise even when Known"
            );
        } else {
            assert_eq!(class, ProvenanceClass::Predicted);
        }
    }

    Ok(())
}

#[test]
fn test_observed_cannot_authorize_effects_with_non_known_epistemic_states()
-> Result<(), Box<dyn Error>> {
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

    let basis_for = |state: KnowledgeState| -> Result<Option<KnowledgeStateBasis>, ContractError> {
        Ok(match state {
            KnowledgeState::Redacted => Some(KnowledgeStateBasis::Redaction(RedactionMarker {
                reason: RedactionReason::PrivacyProjection,
                privacy_generation: PrivacyGeneration::parse("privacy:projection:v1")?,
            })),
            KnowledgeState::Stale => {
                Some(KnowledgeStateBasis::Stale(StaleBasis::OlderGeneration {
                    valid_at: Generation::from_u64(1),
                    current: Generation::from_u64(2),
                }))
            }
            KnowledgeState::Indeterminate => Some(KnowledgeStateBasis::Reconciliation(
                ReconciliationBasis::occurred_or_not(evidence_digest),
            )),
            _ => None,
        })
    };

    for state in non_known_states {
        let cell = KnowledgeCell::new(KnowledgeCellParams {
            claim_id: format!("claim:test:{}", state.as_str()),
            statement: format!("Testing non-known state {}", state.as_str()),
            knowledge_state: state,
            provenance: ProvenanceClass::Observed,
            hypothesis: None,
            evidence: vec![evidence_digest],
            contradictions: vec![],
            valid_until: Some(TimestampNs(2_000_000_000)),
            state_basis: basis_for(state)?,
        })?;

        assert!(
            !cell.is_irreversible_effect_premise(now),
            "Observed cell with state {} must not authorize irreversible effect",
            state.as_str()
        );
    }

    Ok(())
}

// =========================================================================
// PROV-002: derived tests
// =========================================================================

#[test]
fn test_derived_contract_row_properties() -> Result<(), Box<dyn Error>> {
    let prov = ProvenanceClass::Derived;

    // 1. Exact normative stable ID
    assert_eq!(prov.id(), "PROV-002");

    // 2. Exact normative schema spelling
    assert_eq!(prov.as_str(), "derived");
    assert_eq!(format!("{prov}"), "derived");

    // 3. Exact normative meaning
    assert_eq!(
        prov.meaning(),
        "Deterministically computed from named canonical inputs under a registered algorithm and generation."
    );

    // 4. Predicate helper
    assert!(prov.is_derived());
    assert!(!prov.is_observed());

    // 5. May authorize irreversible effect: false (derived beliefs belong to Cognition plane, never Authority plane per AGT-LAYER-004 / INV-069)
    assert!(!prov.may_authorize_irreversible_effect());

    Ok(())
}

#[test]
fn test_derived_parse_and_resolution() -> Result<(), Box<dyn Error>> {
    // Parse from stable ID
    let from_id = ProvenanceClass::from_id("PROV-002")?;
    assert_eq!(from_id, ProvenanceClass::Derived);

    // Parse from schema name
    let from_name = ProvenanceClass::from_name("derived")?;
    assert_eq!(from_name, ProvenanceClass::Derived);

    // Parse via FromStr
    let from_str_name = ProvenanceClass::from_str("derived")?;
    assert_eq!(from_str_name, ProvenanceClass::Derived);

    assert_eq!(
        ProvenanceClass::from_str("PROV-002"),
        Err(ContractError::InvalidIdentifier)
    );

    // Rejection of invalid variants
    assert_eq!(
        ProvenanceClass::from_id("PROV-0020"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ProvenanceClass::from_name("derive"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ProvenanceClass::from_name("DERIVED"),
        Err(ContractError::InvalidIdentifier)
    );

    Ok(())
}

#[test]
fn test_derived_canonical_roundtrip() -> Result<(), Box<dyn Error>> {
    let prov = ProvenanceClass::Derived;

    let mut encoder = CanonicalEncoder::new();
    prov.encode_canonical(&mut encoder);
    let encoded_bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&encoded_bytes);
    let decoded = ProvenanceClass::decode_canonical(&mut decoder)?;

    assert_eq!(decoded, prov);
    assert_eq!(decoded.id(), "PROV-002");
    assert_eq!(decoded.as_str(), "derived");

    Ok(())
}

#[test]
fn test_derived_requires_named_input_evidence_anchors_fail_closed() -> Result<(), Box<dyn Error>> {
    let input_digest = ContentDigest::sha256(b"canonical_input_telemetry_batch_001");

    // 1. Derived cell with empty evidence is REFUSED (fail closed)
    let cell_without_evidence_params = KnowledgeCellParams {
        claim_id: "claim:occupancy:zone_a".to_string(),
        statement: "Computed occupancy estimate for zone A".to_string(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![], // EMPTY - violates PROV-002 requirement to name inputs
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };

    assert_eq!(
        KnowledgeCell::new(cell_without_evidence_params),
        Err(ContractError::EvidenceRequired)
    );

    // 2. Derived cell with named canonical inputs is ACCEPTED
    let cell_with_evidence = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:occupancy:zone_a".to_string(),
        statement: "Computed occupancy estimate for zone A".to_string(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![input_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;

    assert!(cell_with_evidence.validate().is_ok());
    let validated = cell_with_evidence.validated()?;
    assert!(validated.is_derived());
    assert!(!validated.is_observed());
    assert_eq!(validated.evidence().len(), 1);
    assert_eq!(validated.evidence()[0], input_digest);

    Ok(())
}

#[test]
fn test_derived_orthogonality_across_epistemic_states() -> Result<(), Box<dyn Error>> {
    let input_digest = ContentDigest::sha256(b"canonical_algorithm_input_tensor");

    let basis_for = |state: KnowledgeState| -> Result<Option<KnowledgeStateBasis>, ContractError> {
        Ok(match state {
            KnowledgeState::Redacted => Some(KnowledgeStateBasis::Redaction(RedactionMarker {
                reason: RedactionReason::PrivacyProjection,
                privacy_generation: PrivacyGeneration::parse("privacy:projection:v1")?,
            })),
            KnowledgeState::Stale => {
                let mut older = LedgerAnchor::genesis("site:derived-ortho-test");
                older.commit_sequence = 2;
                let mut current = LedgerAnchor::genesis("site:derived-ortho-test");
                current.commit_sequence = 7;
                Some(KnowledgeStateBasis::Stale(StaleBasis::OlderAnchor {
                    valid_at: Box::new(older),
                    current: Box::new(current),
                }))
            }
            KnowledgeState::Indeterminate => {
                Some(KnowledgeStateBasis::Reconciliation(ReconciliationBasis {
                    unresolved_outcome_root: ContentDigest::sha256(
                        b"unresolved_derivation_attempt",
                    ),
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
        let cell = KnowledgeCell::new(KnowledgeCellParams {
            claim_id: format!("claim:derived:{}", state.as_str()),
            statement: format!("Testing derived orthogonality for {}", state.as_str()),
            knowledge_state: state,
            provenance: ProvenanceClass::Derived,
            hypothesis: None,
            evidence: vec![input_digest],
            contradictions: vec![],
            valid_until: None,
            state_basis: basis_for(state)?,
        })?;

        assert!(
            cell.validate().is_ok(),
            "Validation failed for derived cell in state {}",
            state.as_str()
        );

        // Provenance remains Derived regardless of epistemic state
        assert_eq!(cell.provenance(), ProvenanceClass::Derived);
        assert!(cell.is_derived());
        assert_eq!(cell.provenance().id(), "PROV-002");
        assert_eq!(cell.provenance().as_str(), "derived");

        // Epistemic state and provenance are orthogonal
        assert_ne!(cell.provenance().as_str(), state.as_str());
    }

    Ok(())
}

#[test]
fn test_derived_cell_effect_premise_evaluation() -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let input_digest = ContentDigest::sha256(b"canonical_deterministic_derivation_input");

    // Constitutional Gate: Derived beliefs belong to the Cognition plane and can NEVER
    // authorize irreversible physical effects, even when Known with inputs and no contradictions.
    let valid_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:perimeter:breach:derived".to_string(),
        statement: "Perimeter breach deterministically derived from multi-sensor fused inputs"
            .to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![input_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;

    assert_eq!(valid_cell.validate(), Ok(()));
    assert!(!valid_cell.provenance().may_authorize_irreversible_effect());
    assert!(!valid_cell.is_irreversible_effect_premise(now));

    // Negative case 1: Empty inputs cannot authorize effect
    assert_eq!(
        KnowledgeCell::new(KnowledgeCellParams {
            claim_id: "claim:perimeter:breach:derived".to_string(),
            statement: "Perimeter breach deterministically derived from multi-sensor fused inputs"
                .to_string(),
            knowledge_state: KnowledgeState::Known,
            provenance: ProvenanceClass::Derived,
            hypothesis: None,
            evidence: vec![],
            contradictions: vec![],
            valid_until: Some(TimestampNs(2_000_000_000)),
            state_basis: None,
        }),
        Err(ContractError::EvidenceRequired)
    );

    // Negative case 2: Contradictions present cannot authorize effect
    let conflicted_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:perimeter:breach:derived".to_string(),
        statement: "Perimeter breach deterministically derived from multi-sensor fused inputs"
            .to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![input_digest],
        contradictions: vec![ContentDigest::sha256(b"contradicting_fused_signal")],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;
    assert!(!conflicted_cell.is_irreversible_effect_premise(now));

    // Negative case 3: Expired validity cannot authorize effect
    let expired_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:perimeter:breach:derived".to_string(),
        statement: "Perimeter breach deterministically derived from multi-sensor fused inputs"
            .to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![input_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(500_000_000)),
        state_basis: None,
    })?;
    assert!(!expired_cell.is_irreversible_effect_premise(now));

    // Negative case 4: Estimated state cannot authorize effect
    let estimated_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:perimeter:breach:derived".to_string(),
        statement: "Perimeter breach deterministically derived from multi-sensor fused inputs"
            .to_string(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![input_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;
    assert!(!estimated_cell.is_irreversible_effect_premise(now));

    Ok(())
}

#[test]
fn test_derived_distinction_from_observed_and_predicted() -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let evidence_digest = ContentDigest::sha256(b"admissible_evidence_packet");

    let observed = ProvenanceClass::Observed;
    let derived = ProvenanceClass::Derived;
    let predicted = ProvenanceClass::Predicted;

    // Normative IDs are distinct
    assert_eq!(observed.id(), "PROV-001");
    assert_eq!(derived.id(), "PROV-002");
    assert_eq!(predicted.id(), "PROV-003");

    // Meanings represent three distinct epistemic sources
    assert_ne!(observed.meaning(), derived.meaning());
    assert_ne!(derived.meaning(), predicted.meaning());

    // Constitutional effect authorization distinction:
    // Observed may authorize irreversible effects when Known + witnessed.
    // Derived and Predicted CAN NEVER authorize irreversible effects even when Known.
    assert!(observed.may_authorize_irreversible_effect());
    assert!(!derived.may_authorize_irreversible_effect());
    assert!(!predicted.may_authorize_irreversible_effect());

    let derived_known_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:derived:known".to_string(),
        statement: "Derived proposition".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: derived,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;
    assert!(!derived_known_cell.is_irreversible_effect_premise(now));

    let predicted_known_params = KnowledgeCellParams {
        claim_id: "claim:predicted:known".to_string(),
        statement: "Predicted proposition".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: predicted,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };
    assert_eq!(
        KnowledgeCell::new(predicted_known_params),
        Err(ContractError::PredictedKnownForbidden)
    );

    Ok(())
}

#[test]
fn test_derived_belief_cognition_layer_integration() -> Result<(), Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("site:derived-belief-test");
    let belief_generation = Generation::from_u64(1);
    let receipt = ContentDigest::sha256(b"deterministic_derivation_calculation_v1");
    let input = ContentDigest::sha256(b"supporting_input_tensor_hash");

    // 1. Valid DerivedBelief construction
    let params = DerivedBeliefParams {
        belief_id: "belief:motion:fused:001".to_string(),
        anchor: anchor.clone(),
        generation: belief_generation,
        statement: "Derived fused motion belief".to_string(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Derived,
        uncertainty: BeliefInterval::from_f64(0.85, 0.85)?,
        supporting_evidence: vec![input],
        contradictions: vec![],
        derivation_receipt: receipt,
    }
    .with_computed_receipt()?;

    let belief = DerivedBelief::new(params.clone())?;
    assert_eq!(belief.provenance(), ProvenanceClass::Derived);
    assert!(belief.provenance().is_derived());
    assert_eq!(belief.provenance().id(), "PROV-002");
    assert_eq!(belief.provenance().as_str(), "derived");

    // Constitutional Hard Gate (AGENTS.md & INV-069):
    // Cognition plane cannot claim authority or authorize effects directly
    assert!(!belief.may_claim_authority());
    assert!(!belief.may_authorize_effects());

    // 2. Refuses non-Derived provenance
    let mut invalid_prov = params.clone();
    invalid_prov.provenance = ProvenanceClass::Observed;
    assert_eq!(
        DerivedBelief::new(invalid_prov),
        Err(ContractError::KnowledgeStateBasisMismatch)
    );

    // 3. Refuses Known state in DerivedBelief (cognition cannot promote to Known)
    let mut invalid_known = params.clone();
    invalid_known.knowledge_state = KnowledgeState::Known;
    assert_eq!(
        DerivedBelief::new(invalid_known),
        Err(ContractError::DerivedBeliefKnownForbidden)
    );

    // 4. Refuses empty supporting evidence
    let mut empty_evidence = params.clone();
    empty_evidence.supporting_evidence.clear();
    assert_eq!(
        DerivedBelief::new(empty_evidence),
        Err(ContractError::EvidenceRequired)
    );

    Ok(())
}

#[test]
fn test_predicted_contract_row_properties() -> Result<(), Box<dyn Error>> {
    let prov = ProvenanceClass::Predicted;

    // 1. Exact normative stable ID
    assert_eq!(prov.id(), "PROV-003");

    // 2. Exact normative schema spelling
    assert_eq!(prov.as_str(), "predicted");
    assert_eq!(format!("{prov}"), "predicted");

    // 3. Exact normative meaning
    assert_eq!(
        prov.meaning(),
        "Counterfactual or forward prediction under an explicit branch/model and assumptions."
    );

    // 4. Predicate helper methods
    assert!(prov.is_predicted());
    assert!(!prov.is_observed());
    assert!(!prov.is_derived());

    // 5. Constitutional effect authorization rule (INV-069):
    // Predictions CANNOT authorize irreversible physical effects.
    assert!(!prov.may_authorize_irreversible_effect());

    Ok(())
}

#[test]
fn test_predicted_parse_and_resolution() -> Result<(), Box<dyn Error>> {
    // Parse from stable ID
    let from_id = ProvenanceClass::from_id("PROV-003")?;
    assert_eq!(from_id, ProvenanceClass::Predicted);

    // Parse from schema name
    let from_name = ProvenanceClass::from_name("predicted")?;
    assert_eq!(from_name, ProvenanceClass::Predicted);

    // Parse via FromStr
    let from_str_name = ProvenanceClass::from_str("predicted")?;
    assert_eq!(from_str_name, ProvenanceClass::Predicted);

    assert_eq!(
        ProvenanceClass::from_str("PROV-003"),
        Err(ContractError::InvalidIdentifier)
    );

    // Rejection of invalid / malformed variants (fail closed)
    assert_eq!(
        ProvenanceClass::from_id("PROV-0030"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ProvenanceClass::from_id("PROV-3"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ProvenanceClass::from_name("predict"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ProvenanceClass::from_name("PREDICTED"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ProvenanceClass::from_name("prediction"),
        Err(ContractError::InvalidIdentifier)
    );

    Ok(())
}

#[test]
fn test_predicted_canonical_roundtrip() -> Result<(), Box<dyn Error>> {
    let prov = ProvenanceClass::Predicted;

    let mut encoder = CanonicalEncoder::new();
    prov.encode_canonical(&mut encoder);
    let encoded_bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&encoded_bytes);
    let decoded = ProvenanceClass::decode_canonical(&mut decoder)?;

    assert_eq!(decoded, prov);
    assert_eq!(decoded.id(), "PROV-003");
    assert_eq!(decoded.as_str(), "predicted");

    Ok(())
}

#[test]
fn test_predicted_orthogonality_across_epistemic_states() -> Result<(), Box<dyn Error>> {
    let assumption_digest = ContentDigest::sha256(b"counterfactual_branch_assumptions_v1");

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
                    unresolved_outcome_root: ContentDigest::sha256(b"unresolved_predicted_outcome"),
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
        let cell_params = KnowledgeCellParams {
            claim_id: format!("claim:predicted:{}", state.as_str()),
            statement: format!("Testing predicted orthogonality for {}", state.as_str()),
            knowledge_state: state,
            provenance: ProvenanceClass::Predicted,
            hypothesis: None,
            evidence: vec![assumption_digest],
            contradictions: vec![],
            valid_until: None,
            state_basis: basis_for(state)?,
        };

        if state == KnowledgeState::Known {
            assert_eq!(
                KnowledgeCell::new(cell_params),
                Err(ContractError::PredictedKnownForbidden),
                "Constitution §8.2: Predicted cell must refuse KnowledgeState::Known"
            );
            continue;
        }

        let cell = KnowledgeCell::new(cell_params)?;

        // Provenance remains Predicted regardless of epistemic state
        assert_eq!(cell.provenance(), ProvenanceClass::Predicted);
        assert!(cell.is_predicted());
        assert_eq!(cell.provenance().id(), "PROV-003");
        assert_eq!(cell.provenance().as_str(), "predicted");

        // Epistemic state and provenance are orthogonal
        assert_ne!(cell.provenance().as_str(), state.as_str());
    }

    Ok(())
}

#[test]
fn test_predicted_cannot_authorize_irreversible_effects_even_when_known()
-> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let model_input_digest = ContentDigest::sha256(b"forward_prediction_model_evidence");

    // Constitutional Hard Gate (AGENTS.md & INV-069):
    // Even if a prediction is asserted with KnowledgeState::Known,
    // has valid supporting evidence, has no contradictions, and is unexpired,
    // it MUST NEVER authorize an irreversible physical effect!
    let predicted_known_params = KnowledgeCellParams {
        claim_id: "claim:predicted:high_confidence_fire".to_string(),
        statement: "Forward model predicts 99.9% probability of structural fire propagation"
            .to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Predicted,
        hypothesis: None,
        evidence: vec![model_input_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };

    assert_eq!(
        KnowledgeCell::new(predicted_known_params),
        Err(ContractError::PredictedKnownForbidden),
        "Predicted cell claiming Known state must be refused per Constitution §8.2"
    );

    // Contrast with Observed and Derived, which DO authorize under identical conditions
    let observed_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:predicted:high_confidence_fire".to_string(),
        statement: "Forward model predicts 99.9% probability of structural fire propagation"
            .to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![model_input_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;
    assert!(observed_cell.is_irreversible_effect_premise(now));

    let derived_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:predicted:high_confidence_fire".to_string(),
        statement: "Forward model predicts 99.9% probability of structural fire propagation"
            .to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![model_input_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;
    assert!(!derived_cell.is_irreversible_effect_premise(now));

    Ok(())
}

#[test]
fn test_predicted_counterfactual_branch_and_assumptions_semantics() -> Result<(), Box<dyn Error>> {
    let branch_assumption = ContentDigest::sha256(b"counterfactual_branch:suppression_delayed_60s");
    let model_digest = ContentDigest::sha256(b"model:thermal_dispersion:generation_v2");

    // Predicted cell under explicit branch assumptions and model generation
    let counterfactual_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:counterfactual:temperature_spike".to_string(),
        statement: "Under delayed suppression branch, server room temp reaches 85C at T+60s"
            .to_string(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Predicted,
        hypothesis: None,
        evidence: vec![branch_assumption, model_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(1_500_000_000)),
        state_basis: None,
    })?;

    assert!(counterfactual_cell.validate().is_ok());
    let validated = counterfactual_cell.validated()?;
    assert!(validated.is_predicted());
    assert!(!validated.is_observed());
    assert!(!validated.is_derived());
    assert_eq!(validated.evidence().len(), 2);
    assert_eq!(validated.evidence()[0], branch_assumption);
    assert_eq!(validated.evidence()[1], model_digest);

    // Counterfactual prediction requires explicit assumptions for planning
    assert!(!validated.is_irreversible_effect_premise(TimestampNs(1_000_000_000)));

    Ok(())
}

#[test]
fn test_predicted_vlm_shortcut_prohibition() -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let vlm_embedding = ContentDigest::sha256(b"vlm:frame_inference_tensor_digest");

    // Prohibited shortcut from AGENTS.md:
    // "Letting a VLM trigger an effect directly."
    // A VLM proposition tagged as Predicted cannot satisfy effect premise
    let vlm_params = KnowledgeCellParams {
        claim_id: "claim:vlm:weapon_detection".to_string(),
        statement: "VLM inference flags weapon present in main hallway".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Predicted,
        hypothesis: None,
        evidence: vec![vlm_embedding],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };

    // Per PROV-003 and Constitution §8.2, a VLM prediction cannot claim Known
    assert_eq!(
        KnowledgeCell::new(vlm_params),
        Err(ContractError::PredictedKnownForbidden),
        "VLM prediction claiming Known state must be refused"
    );

    // Even when legitimately Estimated, VLM prediction fails closed: cannot authorize irreversible effect
    let vlm_estimated = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:vlm:weapon_detection".to_string(),
        statement: "VLM inference flags weapon present in main hallway".to_string(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Predicted,
        hypothesis: None,
        evidence: vec![vlm_embedding],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;
    assert!(vlm_estimated.validate().is_ok());
    assert!(vlm_estimated.is_predicted());
    assert!(
        !vlm_estimated.is_irreversible_effect_premise(now),
        "VLM prediction directly triggering an effect is strictly prohibited"
    );

    Ok(())
}

#[test]
fn test_predicted_distinction_from_all_other_provenance_classes() -> Result<(), Box<dyn Error>> {
    let all_provenances = [
        ProvenanceClass::Observed,
        ProvenanceClass::Derived,
        ProvenanceClass::Predicted,
        ProvenanceClass::Remembered,
        ProvenanceClass::OperatorAsserted,
        ProvenanceClass::VendorClaimed,
        ProvenanceClass::Policy,
    ];

    let predicted = ProvenanceClass::Predicted;

    for prov in all_provenances {
        if prov != predicted {
            // IDs are strictly distinct
            assert_ne!(predicted.id(), prov.id());
            // Schema names are strictly distinct
            assert_ne!(predicted.as_str(), prov.as_str());
            // Meanings are strictly distinct
            assert_ne!(predicted.meaning(), prov.meaning());
        }
    }

    // Effect authorization partition check
    let authorizing_classes: Vec<ProvenanceClass> = all_provenances
        .iter()
        .copied()
        .filter(|p| p.may_authorize_irreversible_effect())
        .collect();

    let non_authorizing_classes: Vec<ProvenanceClass> = all_provenances
        .iter()
        .copied()
        .filter(|p| !p.may_authorize_irreversible_effect())
        .collect();

    // Predicted and Derived are in the non-authorizing partition
    assert!(non_authorizing_classes.contains(&ProvenanceClass::Predicted));
    assert!(non_authorizing_classes.contains(&ProvenanceClass::Remembered));
    assert!(non_authorizing_classes.contains(&ProvenanceClass::VendorClaimed));
    assert!(non_authorizing_classes.contains(&ProvenanceClass::Derived));
    assert_eq!(non_authorizing_classes.len(), 4);

    // Observed, OperatorAsserted, Policy are in the authorizing partition
    assert!(authorizing_classes.contains(&ProvenanceClass::Observed));
    assert!(authorizing_classes.contains(&ProvenanceClass::OperatorAsserted));
    assert!(authorizing_classes.contains(&ProvenanceClass::Policy));
    assert_eq!(authorizing_classes.len(), 3);

    Ok(())
}

#[test]
fn test_remembered_contract_row_properties() -> Result<(), Box<dyn Error>> {
    let prov = ProvenanceClass::Remembered;

    // 1. Exact normative stable ID
    assert_eq!(prov.id(), "PROV-004");

    // 2. Exact normative schema spelling
    assert_eq!(prov.as_str(), "remembered");
    assert_eq!(format!("{prov}"), "remembered");

    // 3. Exact normative meaning
    assert_eq!(
        prov.meaning(),
        "Advisory operational memory or prior episode material that must be revalidated against live evidence."
    );

    // 4. Predicate helper methods
    assert!(prov.is_remembered());
    assert!(!prov.is_observed());
    assert!(!prov.is_derived());
    assert!(!prov.is_predicted());

    // 5. Constitutional effect authorization rule (INV-069):
    // Advisory memory CANNOT authorize irreversible physical effects.
    assert!(!prov.may_authorize_irreversible_effect());

    Ok(())
}

#[test]
fn test_remembered_parse_and_resolution() -> Result<(), Box<dyn Error>> {
    // Parse from stable ID
    let from_id = ProvenanceClass::from_id("PROV-004")?;
    assert_eq!(from_id, ProvenanceClass::Remembered);

    // Parse from schema name
    let from_name = ProvenanceClass::from_name("remembered")?;
    assert_eq!(from_name, ProvenanceClass::Remembered);

    // Parse via FromStr
    let from_str_name = ProvenanceClass::from_str("remembered")?;
    assert_eq!(from_str_name, ProvenanceClass::Remembered);

    assert_eq!(
        ProvenanceClass::from_str("PROV-004"),
        Err(ContractError::InvalidIdentifier)
    );

    // Rejection of invalid / malformed variants (fail closed)
    assert_eq!(
        ProvenanceClass::from_id("PROV-0040"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ProvenanceClass::from_id("PROV-4"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ProvenanceClass::from_name("remember"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ProvenanceClass::from_name("REMEMBERED"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ProvenanceClass::from_name("memory"),
        Err(ContractError::InvalidIdentifier)
    );

    Ok(())
}

#[test]
fn test_remembered_canonical_roundtrip() -> Result<(), Box<dyn Error>> {
    let prov = ProvenanceClass::Remembered;

    let mut encoder = CanonicalEncoder::new();
    prov.encode_canonical(&mut encoder);
    let encoded_bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&encoded_bytes);
    let decoded = ProvenanceClass::decode_canonical(&mut decoder)?;

    assert_eq!(decoded, prov);
    assert_eq!(decoded.id(), "PROV-004");
    assert_eq!(decoded.as_str(), "remembered");

    Ok(())
}

#[test]
fn test_remembered_orthogonality_across_epistemic_states() -> Result<(), Box<dyn Error>> {
    let memory_evidence_digest = ContentDigest::sha256(b"prior_episode_context_pack_digest");

    let basis_for = |state: KnowledgeState| -> Result<Option<KnowledgeStateBasis>, ContractError> {
        Ok(match state {
            KnowledgeState::Redacted => Some(KnowledgeStateBasis::Redaction(RedactionMarker {
                reason: RedactionReason::PrivacyProjection,
                privacy_generation: PrivacyGeneration::parse("privacy:projection:v1")?,
            })),
            KnowledgeState::Stale => {
                let mut older = LedgerAnchor::genesis("site:provenance-test");
                older.commit_sequence = 2;
                let mut current = LedgerAnchor::genesis("site:provenance-test");
                current.commit_sequence = 6;
                Some(KnowledgeStateBasis::Stale(StaleBasis::OlderAnchor {
                    valid_at: Box::new(older),
                    current: Box::new(current),
                }))
            }
            KnowledgeState::Indeterminate => {
                Some(KnowledgeStateBasis::Reconciliation(ReconciliationBasis {
                    unresolved_outcome_root: ContentDigest::sha256(
                        b"unresolved_memory_reconciliation",
                    ),
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
        let cell = KnowledgeCell::new(KnowledgeCellParams {
            claim_id: format!("claim:remembered:{}", state.as_str()),
            statement: format!("Testing remembered orthogonality for {}", state.as_str()),
            knowledge_state: state,
            provenance: ProvenanceClass::Remembered,
            hypothesis: None,
            evidence: vec![memory_evidence_digest],
            contradictions: vec![],
            valid_until: None,
            state_basis: basis_for(state)?,
        })?;

        assert!(
            cell.validate().is_ok(),
            "Validation failed for remembered cell in state {}",
            state.as_str()
        );

        // Provenance remains Remembered regardless of epistemic state
        assert_eq!(cell.provenance(), ProvenanceClass::Remembered);
        assert!(cell.is_remembered());
        assert_eq!(cell.provenance().id(), "PROV-004");
        assert_eq!(cell.provenance().as_str(), "remembered");

        // Epistemic state and provenance are strictly distinct
        assert_ne!(cell.provenance().as_str(), state.as_str());
    }

    Ok(())
}

#[test]
fn test_remembered_cannot_authorize_irreversible_effects_even_when_known()
-> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let episode_digest = ContentDigest::sha256(b"prior_shift_incident_report_packet");

    // Constitutional Hard Gate (AGENTS.md & INV-069):
    // Even if memory records a fact as Known in the prior episode,
    // has historical evidence, has no contradictions, and is unexpired,
    // it MUST NEVER authorize an irreversible physical effect without live revalidation!
    let remembered_known_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:remembered:isolation_valve_closed".to_string(),
        statement: "Prior shift episode records cooling loop valve 4 as closed".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Remembered,
        hypothesis: None,
        evidence: vec![episode_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;

    assert!(remembered_known_cell.validate().is_ok());
    assert!(remembered_known_cell.is_remembered());
    assert_eq!(
        remembered_known_cell.knowledge_state(),
        KnowledgeState::Known
    );

    // Irreversible effect premise MUST evaluate to false (fail closed)
    assert!(
        !remembered_known_cell.is_irreversible_effect_premise(now),
        "Remembered operational memory must NEVER authorize irreversible effects even when Known!"
    );

    // Contrast with Observed and Derived
    let observed_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:remembered:isolation_valve_closed".to_string(),
        statement: "Prior shift episode records cooling loop valve 4 as closed".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![episode_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;
    assert!(observed_cell.is_irreversible_effect_premise(now));

    let derived_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:remembered:isolation_valve_closed".to_string(),
        statement: "Prior shift episode records cooling loop valve 4 as closed".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![episode_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;
    assert!(!derived_cell.is_irreversible_effect_premise(now));

    Ok(())
}

#[test]
fn test_remembered_advisory_revalidation_lifecycle() -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let prior_episode_ref = ContentDigest::sha256(b"episode_archive_anchor_sequence_42");
    let live_sensor_packet = ContentDigest::sha256(b"live_telemetry_capture_sequence_99");

    // 1. Advisory operational memory: Valve state remembered from prior episode
    let advisory_memory = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:cooling:valve:004".to_string(),
        statement: "Valve 4 was verified closed in prior episode 42".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Remembered,
        hypothesis: None,
        evidence: vec![prior_episode_ref],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })?;

    assert!(advisory_memory.validate().is_ok());
    assert!(advisory_memory.is_remembered());
    // Prohibited shortcut from AGENTS.md:
    // "Treating an agent memory, prior handoff, vendor claim, or prediction as current canonical truth."
    // Memory alone cannot authorize an irreversible effect
    assert!(!advisory_memory.is_irreversible_effect_premise(now));

    // 2. Revalidation against live physical evidence (PROV-001 observed at current anchor)
    let live_revalidated = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:cooling:valve:004".to_string(),
        statement: "Live physical contact sensor confirms valve 4 is closed".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![live_sensor_packet],
        contradictions: vec![],
        valid_until: Some(TimestampNs(1_100_000_000)),
        state_basis: None,
    })?;

    assert!(live_revalidated.validate().is_ok());
    assert!(live_revalidated.is_observed());
    // Once revalidated against live observation, effect authorization succeeds
    assert!(live_revalidated.is_irreversible_effect_premise(now));

    Ok(())
}

#[test]
fn test_remembered_stale_basis_interaction() -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let historical_evidence = ContentDigest::sha256(b"historical_log_anchor_seq_10");

    let mut older = LedgerAnchor::genesis("site:facility-substation");
    older.commit_sequence = 10;
    let mut current = LedgerAnchor::genesis("site:facility-substation");
    current.commit_sequence = 25;

    // Advisory memory that is recognized as Stale due to newer ledger anchor
    let stale_memory = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:breaker:status:substation".to_string(),
        statement: "Main circuit breaker was closed at sequence 10".to_string(),
        knowledge_state: KnowledgeState::Stale,
        provenance: ProvenanceClass::Remembered,
        hypothesis: None,
        evidence: vec![historical_evidence],
        contradictions: vec![],
        valid_until: None,
        state_basis: Some(KnowledgeStateBasis::Stale(StaleBasis::OlderAnchor {
            valid_at: Box::new(older),
            current: Box::new(current),
        })),
    })?;

    assert!(stale_memory.validate().is_ok());
    let validated = stale_memory.validated()?;
    assert!(validated.is_remembered());
    assert!(validated.is_stale());

    // Both the Stale state AND the Remembered provenance independently reject effect premise
    assert!(!validated.is_irreversible_effect_premise(now));

    Ok(())
}

#[test]
fn test_remembered_distinction_from_all_other_provenance_classes() -> Result<(), Box<dyn Error>> {
    let all_provenances = [
        ProvenanceClass::Observed,
        ProvenanceClass::Derived,
        ProvenanceClass::Predicted,
        ProvenanceClass::Remembered,
        ProvenanceClass::OperatorAsserted,
        ProvenanceClass::VendorClaimed,
        ProvenanceClass::Policy,
    ];

    let remembered = ProvenanceClass::Remembered;

    for prov in all_provenances {
        if prov != remembered {
            // IDs are strictly distinct
            assert_ne!(remembered.id(), prov.id());
            // Schema names are strictly distinct
            assert_ne!(remembered.as_str(), prov.as_str());
            // Meanings are strictly distinct
            assert_ne!(remembered.meaning(), prov.meaning());
        }
    }

    // Effect authorization partition check
    let authorizing_classes: Vec<ProvenanceClass> = all_provenances
        .iter()
        .copied()
        .filter(|p| p.may_authorize_irreversible_effect())
        .collect();

    let non_authorizing_classes: Vec<ProvenanceClass> = all_provenances
        .iter()
        .copied()
        .filter(|p| !p.may_authorize_irreversible_effect())
        .collect();

    // Remembered and Derived are in the non-authorizing partition
    assert!(non_authorizing_classes.contains(&ProvenanceClass::Remembered));
    assert!(non_authorizing_classes.contains(&ProvenanceClass::Predicted));
    assert!(non_authorizing_classes.contains(&ProvenanceClass::VendorClaimed));
    assert!(non_authorizing_classes.contains(&ProvenanceClass::Derived));
    assert_eq!(non_authorizing_classes.len(), 4);

    // Authorizing partition
    assert!(authorizing_classes.contains(&ProvenanceClass::Observed));
    assert!(authorizing_classes.contains(&ProvenanceClass::OperatorAsserted));
    assert!(authorizing_classes.contains(&ProvenanceClass::Policy));
    assert_eq!(authorizing_classes.len(), 3);

    Ok(())
}

#[test]
fn test_operator_asserted_contract_row_properties() -> Result<(), Box<dyn Error>> {
    let prov = ProvenanceClass::OperatorAsserted;

    // 1. Exact normative stable ID
    assert_eq!(prov.id(), "PROV-005");

    // 2. Exact normative schema spelling
    assert_eq!(prov.as_str(), "operator_asserted");
    assert_eq!(format!("{prov}"), "operator_asserted");

    // 3. Exact normative meaning
    assert_eq!(
        prov.meaning(),
        "A human/operator assertion with identity, time, scope, and later corroboration status."
    );

    // 4. Predicate helper methods
    assert!(prov.is_operator_asserted());
    assert!(!prov.is_observed());
    assert!(!prov.is_derived());
    assert!(!prov.is_predicted());
    assert!(!prov.is_remembered());

    // 5. Constitutional effect authorization rule (INV-069):
    // Authorized human operator assertions MAY authorize irreversible effects when Known + witnessed.
    assert!(prov.may_authorize_irreversible_effect());

    Ok(())
}

#[test]
fn test_operator_asserted_parse_and_resolution() -> Result<(), Box<dyn Error>> {
    // Parse from stable ID
    let from_id = ProvenanceClass::from_id("PROV-005")?;
    assert_eq!(from_id, ProvenanceClass::OperatorAsserted);

    // Parse from schema name
    let from_name = ProvenanceClass::from_name("operator_asserted")?;
    assert_eq!(from_name, ProvenanceClass::OperatorAsserted);

    // Parse via FromStr
    let from_str_name = ProvenanceClass::from_str("operator_asserted")?;
    assert_eq!(from_str_name, ProvenanceClass::OperatorAsserted);

    assert_eq!(
        ProvenanceClass::from_str("PROV-005"),
        Err(ContractError::InvalidIdentifier)
    );

    // Rejection of invalid / malformed variants (fail closed)
    assert_eq!(
        ProvenanceClass::from_id("PROV-0050"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ProvenanceClass::from_id("PROV-5"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ProvenanceClass::from_name("operator"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ProvenanceClass::from_name("OPERATOR_ASSERTED"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ProvenanceClass::from_name("asserted"),
        Err(ContractError::InvalidIdentifier)
    );

    Ok(())
}

#[test]
fn test_operator_asserted_canonical_roundtrip() -> Result<(), Box<dyn Error>> {
    let prov = ProvenanceClass::OperatorAsserted;

    let mut encoder = CanonicalEncoder::new();
    prov.encode_canonical(&mut encoder);
    let encoded_bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&encoded_bytes);
    let decoded = ProvenanceClass::decode_canonical(&mut decoder)?;

    assert_eq!(decoded, prov);
    assert_eq!(decoded.id(), "PROV-005");
    assert_eq!(decoded.as_str(), "operator_asserted");

    Ok(())
}

#[test]
fn test_operator_asserted_orthogonality_across_epistemic_states() -> Result<(), Box<dyn Error>> {
    let operator_sig_digest = ContentDigest::sha256(b"operator_assertion_signature_token");

    let basis_for = |state: KnowledgeState| -> Result<Option<KnowledgeStateBasis>, ContractError> {
        Ok(match state {
            KnowledgeState::Redacted => Some(KnowledgeStateBasis::Redaction(RedactionMarker {
                reason: RedactionReason::PrivacyProjection,
                privacy_generation: PrivacyGeneration::parse("privacy:projection:v1")?,
            })),
            KnowledgeState::Stale => {
                let mut older = LedgerAnchor::genesis("site:provenance-test");
                older.commit_sequence = 1;
                let mut current = LedgerAnchor::genesis("site:provenance-test");
                current.commit_sequence = 8;
                Some(KnowledgeStateBasis::Stale(StaleBasis::OlderAnchor {
                    valid_at: Box::new(older),
                    current: Box::new(current),
                }))
            }
            KnowledgeState::Indeterminate => {
                Some(KnowledgeStateBasis::Reconciliation(ReconciliationBasis {
                    unresolved_outcome_root: ContentDigest::sha256(
                        b"unresolved_operator_instruction",
                    ),
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
        let cell = KnowledgeCell::new(KnowledgeCellParams {
            claim_id: format!("claim:operator:{}", state.as_str()),
            statement: format!(
                "Testing operator_asserted orthogonality for {}",
                state.as_str()
            ),
            knowledge_state: state,
            provenance: ProvenanceClass::OperatorAsserted,
            hypothesis: None,
            evidence: vec![operator_sig_digest],
            contradictions: vec![],
            valid_until: None,
            state_basis: basis_for(state)?,
        })?;

        assert!(
            cell.validate().is_ok(),
            "Validation failed for operator_asserted cell in state {}",
            state.as_str()
        );

        // Provenance remains OperatorAsserted regardless of epistemic state
        assert_eq!(cell.provenance(), ProvenanceClass::OperatorAsserted);
        assert!(cell.is_operator_asserted());
        assert_eq!(cell.provenance().id(), "PROV-005");
        assert_eq!(cell.provenance().as_str(), "operator_asserted");

        // Epistemic state and provenance are strictly distinct
        assert_ne!(cell.provenance().as_str(), state.as_str());
    }

    Ok(())
}

#[test]
fn test_operator_asserted_effect_premise_authorization_positive_and_negative()
-> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let operator_signature = ContentDigest::sha256(b"signed_operator_emergency_halt_authorization");

    // Positive case: Known + OperatorAsserted + Signed Evidence + No Contradictions + Unexpired
    let valid_operator_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:operator:emergency_halt:zone_d".to_string(),
        statement: "Operator #402 authorizes emergency power isolation for Zone D".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::OperatorAsserted,
        hypothesis: None,
        evidence: vec![operator_signature],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;

    assert!(valid_operator_cell.validate().is_ok());
    assert!(valid_operator_cell.is_operator_asserted());
    assert!(valid_operator_cell.is_irreversible_effect_premise(now));

    // Negative case 1: Missing evidence (unsigned / unanchored assertion) fails closed
    let no_evidence = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:operator:emergency_halt:zone_d".to_string(),
        statement: "Operator #402 authorizes emergency power isolation for Zone D".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::OperatorAsserted,
        hypothesis: None,
        evidence: vec![],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;
    assert!(!no_evidence.is_irreversible_effect_premise(now));

    // Negative case 2: Tentative / Estimated assertion cannot authorize irreversible effect
    let estimated_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:operator:emergency_halt:zone_d".to_string(),
        statement: "Operator #402 authorizes emergency power isolation for Zone D".to_string(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::OperatorAsserted,
        hypothesis: None,
        evidence: vec![operator_signature],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;
    assert!(!estimated_cell.is_irreversible_effect_premise(now));

    // Negative case 3: Expired operator lease / override cannot authorize effect
    let expired_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:operator:emergency_halt:zone_d".to_string(),
        statement: "Operator #402 authorizes emergency power isolation for Zone D".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::OperatorAsserted,
        hypothesis: None,
        evidence: vec![operator_signature],
        contradictions: vec![],
        valid_until: Some(TimestampNs(500_000_000)),
        state_basis: None,
    })?;
    assert!(!expired_cell.is_irreversible_effect_premise(now));

    // Negative case 4: Contradictions present invalidate authorization
    let conflicted_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:operator:emergency_halt:zone_d".to_string(),
        statement: "Operator #402 authorizes emergency power isolation for Zone D".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::OperatorAsserted,
        hypothesis: None,
        evidence: vec![operator_signature],
        contradictions: vec![ContentDigest::sha256(b"contradicting_occupancy_signal")],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;
    assert!(!conflicted_cell.is_irreversible_effect_premise(now));

    Ok(())
}

#[test]
fn test_operator_asserted_contradiction_and_corroboration_dynamics() -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let operator_claim_digest = ContentDigest::sha256(b"operator_clearance_attestation_ticket");
    let contradictory_sensor_digest =
        ContentDigest::sha256(b"radar_detects_personnel_in_hazard_zone");

    // 1. Initial operator assertion: Area is clear
    let operator_assertion = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:safety:zone_b:clearance".to_string(),
        statement: "Operator asserts Zone B is clear of all personnel".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::OperatorAsserted,
        hypothesis: None,
        evidence: vec![operator_claim_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(1_500_000_000)),
        state_basis: None,
    })?;

    assert!(operator_assertion.validate().is_ok());
    assert!(operator_assertion.is_operator_asserted());
    assert!(operator_assertion.is_irreversible_effect_premise(now));

    // 2. Later corroboration / contradiction status:
    // Physical radar detects personnel in the zone, producing a contradiction
    let contradicted_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:safety:zone_b:clearance".to_string(),
        statement: "Operator asserts Zone B is clear of all personnel".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::OperatorAsserted,
        hypothesis: None,
        evidence: vec![operator_claim_digest],
        contradictions: vec![contradictory_sensor_digest],
        valid_until: Some(TimestampNs(1_500_000_000)),
        state_basis: None,
    })?;

    // Contradiction immediately revokes effect authorization (fail closed)
    assert!(!contradicted_cell.is_irreversible_effect_premise(now));

    // 3. Epistemic state transition to Conflicted
    let conflicted_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:safety:zone_b:clearance".to_string(),
        statement: "Operator asserts Zone B is clear of all personnel".to_string(),
        knowledge_state: KnowledgeState::Conflicted,
        provenance: ProvenanceClass::OperatorAsserted,
        hypothesis: None,
        evidence: vec![operator_claim_digest],
        contradictions: vec![contradictory_sensor_digest],
        valid_until: Some(TimestampNs(1_500_000_000)),
        state_basis: None,
    })?;
    assert!(conflicted_cell.validate().is_ok());
    assert!(conflicted_cell.is_conflicted());
    assert!(conflicted_cell.is_operator_asserted());
    assert!(!conflicted_cell.is_irreversible_effect_premise(now));

    Ok(())
}

#[test]
fn test_operator_asserted_audit_identity_and_scope() -> Result<(), Box<dyn Error>> {
    let operator_cert = ContentDigest::sha256(b"x509_cert:operator:alice_wright:badge_9921");

    let cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:op:alice_wright:substation_override".to_string(),
        statement: "Operator Alice Wright (Badge #9921) asserts manual generator disconnect"
            .to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::OperatorAsserted,
        hypothesis: None,
        evidence: vec![operator_cert],
        contradictions: vec![],
        valid_until: Some(TimestampNs(3_000_000_000)),
        state_basis: None,
    })?;

    assert!(cell.validate().is_ok());
    let validated = cell.validated()?;
    assert!(validated.is_operator_asserted());
    assert_eq!(validated.provenance().id(), "PROV-005");
    assert_eq!(validated.provenance().as_str(), "operator_asserted");
    assert_eq!(format!("{}", validated.provenance()), "operator_asserted");

    Ok(())
}

#[test]
fn test_operator_asserted_distinction_from_all_other_provenance_classes()
-> Result<(), Box<dyn Error>> {
    let all_provenances = [
        ProvenanceClass::Observed,
        ProvenanceClass::Derived,
        ProvenanceClass::Predicted,
        ProvenanceClass::Remembered,
        ProvenanceClass::OperatorAsserted,
        ProvenanceClass::VendorClaimed,
        ProvenanceClass::Policy,
    ];

    let op_asserted = ProvenanceClass::OperatorAsserted;

    for prov in all_provenances {
        if prov != op_asserted {
            // IDs are strictly distinct
            assert_ne!(op_asserted.id(), prov.id());
            // Schema names are strictly distinct
            assert_ne!(op_asserted.as_str(), prov.as_str());
            // Meanings are strictly distinct
            assert_ne!(op_asserted.meaning(), prov.meaning());
        }
    }

    // Effect authorization partition check
    let authorizing_classes: Vec<ProvenanceClass> = all_provenances
        .iter()
        .copied()
        .filter(|p| p.may_authorize_irreversible_effect())
        .collect();

    let non_authorizing_classes: Vec<ProvenanceClass> = all_provenances
        .iter()
        .copied()
        .filter(|p| !p.may_authorize_irreversible_effect())
        .collect();

    // OperatorAsserted is in the authorizing partition
    assert!(authorizing_classes.contains(&ProvenanceClass::OperatorAsserted));
    assert!(authorizing_classes.contains(&ProvenanceClass::Observed));
    assert!(authorizing_classes.contains(&ProvenanceClass::Policy));
    assert_eq!(authorizing_classes.len(), 3);

    // Non-authorizing partition
    assert!(non_authorizing_classes.contains(&ProvenanceClass::Predicted));
    assert!(non_authorizing_classes.contains(&ProvenanceClass::Remembered));
    assert!(non_authorizing_classes.contains(&ProvenanceClass::VendorClaimed));
    assert!(non_authorizing_classes.contains(&ProvenanceClass::Derived));
    assert_eq!(non_authorizing_classes.len(), 4);

    Ok(())
}

#[test]
fn test_vendor_claimed_contract_row_properties() -> Result<(), Box<dyn Error>> {
    let prov = ProvenanceClass::VendorClaimed;

    // 1. Exact normative stable ID
    assert_eq!(prov.id(), "PROV-006");

    // 2. Exact normative schema spelling
    assert_eq!(prov.as_str(), "vendor_claimed");
    assert_eq!(format!("{prov}"), "vendor_claimed");

    // 3. Exact normative meaning
    assert_eq!(
        prov.meaning(),
        "Metadata or state asserted by a device/vendor boundary and not treated as independent physical truth."
    );

    // 4. Predicate helper methods
    assert!(prov.is_vendor_claimed());
    assert!(!prov.is_observed());
    assert!(!prov.is_derived());
    assert!(!prov.is_predicted());
    assert!(!prov.is_remembered());
    assert!(!prov.is_operator_asserted());

    // 5. Constitutional effect authorization rule (INV-069):
    // Vendor claims CANNOT authorize irreversible physical effects.
    assert!(!prov.may_authorize_irreversible_effect());

    Ok(())
}

#[test]
fn test_vendor_claimed_parse_and_resolution() -> Result<(), Box<dyn Error>> {
    // Parse from stable ID
    let from_id = ProvenanceClass::from_id("PROV-006")?;
    assert_eq!(from_id, ProvenanceClass::VendorClaimed);

    // Parse from schema name
    let from_name = ProvenanceClass::from_name("vendor_claimed")?;
    assert_eq!(from_name, ProvenanceClass::VendorClaimed);

    // Parse via FromStr
    let from_str_name = ProvenanceClass::from_str("vendor_claimed")?;
    assert_eq!(from_str_name, ProvenanceClass::VendorClaimed);

    assert_eq!(
        ProvenanceClass::from_str("PROV-006"),
        Err(ContractError::InvalidIdentifier)
    );

    // Rejection of invalid / malformed variants (fail closed)
    assert_eq!(
        ProvenanceClass::from_id("PROV-0060"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ProvenanceClass::from_id("PROV-6"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ProvenanceClass::from_name("vendor"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ProvenanceClass::from_name("VENDOR_CLAIMED"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ProvenanceClass::from_name("claimed"),
        Err(ContractError::InvalidIdentifier)
    );

    Ok(())
}

#[test]
fn test_vendor_claimed_canonical_roundtrip() -> Result<(), Box<dyn Error>> {
    let prov = ProvenanceClass::VendorClaimed;

    let mut encoder = CanonicalEncoder::new();
    prov.encode_canonical(&mut encoder);
    let encoded_bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&encoded_bytes);
    let decoded = ProvenanceClass::decode_canonical(&mut decoder)?;

    assert_eq!(decoded, prov);
    assert_eq!(decoded.id(), "PROV-006");
    assert_eq!(decoded.as_str(), "vendor_claimed");

    Ok(())
}

#[test]
fn test_vendor_claimed_orthogonality_across_epistemic_states() -> Result<(), Box<dyn Error>> {
    let vendor_payload_digest = ContentDigest::sha256(b"vendor_cloud_webhook_json_payload");

    let basis_for = |state: KnowledgeState| -> Result<Option<KnowledgeStateBasis>, ContractError> {
        Ok(match state {
            KnowledgeState::Redacted => Some(KnowledgeStateBasis::Redaction(RedactionMarker {
                reason: RedactionReason::PrivacyProjection,
                privacy_generation: PrivacyGeneration::parse("privacy:projection:v1")?,
            })),
            KnowledgeState::Stale => {
                let mut older = LedgerAnchor::genesis("site:provenance-test");
                older.commit_sequence = 4;
                let mut current = LedgerAnchor::genesis("site:provenance-test");
                current.commit_sequence = 9;
                Some(KnowledgeStateBasis::Stale(StaleBasis::OlderAnchor {
                    valid_at: Box::new(older),
                    current: Box::new(current),
                }))
            }
            KnowledgeState::Indeterminate => {
                Some(KnowledgeStateBasis::Reconciliation(ReconciliationBasis {
                    unresolved_outcome_root: ContentDigest::sha256(
                        b"unresolved_vendor_poll_attempt",
                    ),
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
        let cell = KnowledgeCell::new(KnowledgeCellParams {
            claim_id: format!("claim:vendor:{}", state.as_str()),
            statement: format!(
                "Testing vendor_claimed orthogonality for {}",
                state.as_str()
            ),
            knowledge_state: state,
            provenance: ProvenanceClass::VendorClaimed,
            hypothesis: None,
            evidence: vec![vendor_payload_digest],
            contradictions: vec![],
            valid_until: None,
            state_basis: basis_for(state)?,
        })?;

        assert!(
            cell.validate().is_ok(),
            "Validation failed for vendor_claimed cell in state {}",
            state.as_str()
        );

        // Provenance remains VendorClaimed regardless of epistemic state
        assert_eq!(cell.provenance(), ProvenanceClass::VendorClaimed);
        assert!(cell.is_vendor_claimed());
        assert_eq!(cell.provenance().id(), "PROV-006");
        assert_eq!(cell.provenance().as_str(), "vendor_claimed");

        // Epistemic state and provenance are strictly distinct
        assert_ne!(cell.provenance().as_str(), state.as_str());
    }

    Ok(())
}

#[test]
fn test_vendor_claimed_cannot_authorize_irreversible_effects_even_when_known()
-> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let vendor_event_digest = ContentDigest::sha256(b"vendor_cloud_motion_event_notification");

    // Constitutional Hard Gate (AGENTS.md & INV-069):
    // A vendor claim, even if received as Known truth from the vendor API,
    // has payload evidence, has no contradictions, and is unexpired,
    // MUST NEVER authorize an irreversible physical effect!
    let vendor_known_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:vendor:door_lock_status".to_string(),
        statement: "Vendor cloud API reports front entry lock bolt is fully extended".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::VendorClaimed,
        hypothesis: None,
        evidence: vec![vendor_event_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;

    assert!(vendor_known_cell.validate().is_ok());
    assert!(vendor_known_cell.is_vendor_claimed());
    assert_eq!(vendor_known_cell.knowledge_state(), KnowledgeState::Known);

    // Irreversible effect premise MUST evaluate to false (fail closed)
    assert!(
        !vendor_known_cell.is_irreversible_effect_premise(now),
        "Vendor claimed state must NEVER authorize irreversible effects even when Known!"
    );

    // Contrast with Observed and Derived
    let observed_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: vendor_known_cell.claim_id().to_string(),
        statement: vendor_known_cell.statement().to_string(),
        knowledge_state: vendor_known_cell.knowledge_state(),
        provenance: ProvenanceClass::Observed,
        hypothesis: vendor_known_cell.hypothesis(),
        evidence: vendor_known_cell.evidence().to_vec(),
        contradictions: vendor_known_cell.contradictions().to_vec(),
        valid_until: vendor_known_cell.valid_until(),
        state_basis: vendor_known_cell.state_basis().cloned(),
    })?;
    assert!(observed_cell.is_irreversible_effect_premise(now));

    let derived_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: vendor_known_cell.claim_id().to_string(),
        statement: vendor_known_cell.statement().to_string(),
        knowledge_state: vendor_known_cell.knowledge_state(),
        provenance: ProvenanceClass::Derived,
        hypothesis: vendor_known_cell.hypothesis(),
        evidence: vendor_known_cell.evidence().to_vec(),
        contradictions: vendor_known_cell.contradictions().to_vec(),
        valid_until: vendor_known_cell.valid_until(),
        state_basis: vendor_known_cell.state_basis().cloned(),
    })?;
    assert!(!derived_cell.is_irreversible_effect_premise(now));

    Ok(())
}

#[test]
fn test_vendor_claimed_prohibited_shortcut_enforcement() -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let cloud_api_response = ContentDigest::sha256(b"cloud_vendor_tamper_alert_response");

    // Prohibited shortcuts from AGENTS.md:
    // 1. "Treating an agent memory, prior handoff, vendor claim, or prediction as current canonical truth."
    // 2. "Calling one camera's model score 'corroborated'."
    // 3. "Presenting a mobile screen capture or app automation path as a stable native integration."
    let vendor_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:camera:tamper:vendor".to_string(),
        statement: "Vendor proprietary push notification claims camera 3 was tampered with"
            .to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::VendorClaimed,
        hypothesis: None,
        evidence: vec![cloud_api_response],
        contradictions: vec![],
        valid_until: Some(TimestampNs(1_500_000_000)),
        state_basis: None,
    })?;

    assert!(vendor_cell.validate().is_ok());
    assert!(vendor_cell.is_vendor_claimed());

    // Fails closed: Vendor proprietary push cannot authorize physical lockdown or alarms
    assert!(
        !vendor_cell.is_irreversible_effect_premise(now),
        "Vendor claim must not be treated as independent physical truth"
    );

    Ok(())
}

#[test]
fn test_vendor_claimed_distinction_from_observed_evidence() -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let vendor_cloud_msg = ContentDigest::sha256(b"vendor_api_door_sensor_payload");
    let physical_hardware_packet = ContentDigest::sha256(b"native_gpio_switch_continuity_packet");

    // 1. Vendor claim: Unverified vendor boundary assertion
    let vendor_claim = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:door:status:001".to_string(),
        statement: "Cloud vendor API states perimeter door is closed".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::VendorClaimed,
        hypothesis: None,
        evidence: vec![vendor_cloud_msg],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;

    // 2. Observed evidence: Direct physical sensor measurement with cryptographic custody
    let physical_observation = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:door:status:001".to_string(),
        statement: "Native GPIO reed switch circuit confirms continuity across physical door frame"
            .to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![physical_hardware_packet],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;

    // Both validate successfully
    assert!(vendor_claim.validate().is_ok());
    assert!(physical_observation.validate().is_ok());

    // Only the direct physical observation carries authority for irreversible actions
    assert!(!vendor_claim.is_irreversible_effect_premise(now));
    assert!(physical_observation.is_irreversible_effect_premise(now));

    Ok(())
}

#[test]
fn test_vendor_claimed_distinction_from_all_other_provenance_classes() -> Result<(), Box<dyn Error>>
{
    let all_provenances = [
        ProvenanceClass::Observed,
        ProvenanceClass::Derived,
        ProvenanceClass::Predicted,
        ProvenanceClass::Remembered,
        ProvenanceClass::OperatorAsserted,
        ProvenanceClass::VendorClaimed,
        ProvenanceClass::Policy,
    ];

    let vendor_claimed = ProvenanceClass::VendorClaimed;

    for prov in all_provenances {
        if prov != vendor_claimed {
            // IDs are strictly distinct
            assert_ne!(vendor_claimed.id(), prov.id());
            // Schema names are strictly distinct
            assert_ne!(vendor_claimed.as_str(), prov.as_str());
            // Meanings are strictly distinct
            assert_ne!(vendor_claimed.meaning(), prov.meaning());
        }
    }

    // Effect authorization partition check
    let non_authorizing_classes: Vec<ProvenanceClass> = all_provenances
        .iter()
        .copied()
        .filter(|p| !p.may_authorize_irreversible_effect())
        .collect();

    let authorizing_classes: Vec<ProvenanceClass> = all_provenances
        .iter()
        .copied()
        .filter(|p| p.may_authorize_irreversible_effect())
        .collect();

    // VendorClaimed and Derived are in the non-authorizing partition
    assert!(non_authorizing_classes.contains(&ProvenanceClass::VendorClaimed));
    assert!(non_authorizing_classes.contains(&ProvenanceClass::Predicted));
    assert!(non_authorizing_classes.contains(&ProvenanceClass::Remembered));
    assert!(non_authorizing_classes.contains(&ProvenanceClass::Derived));
    assert_eq!(non_authorizing_classes.len(), 4);

    // Authorizing partition
    assert!(authorizing_classes.contains(&ProvenanceClass::Observed));
    assert!(authorizing_classes.contains(&ProvenanceClass::OperatorAsserted));
    assert!(authorizing_classes.contains(&ProvenanceClass::Policy));
    assert_eq!(authorizing_classes.len(), 3);

    Ok(())
}

/// Returns the typed basis a knowledge state's registry meaning requires, if any.
fn required_state_basis(
    state: KnowledgeState,
    root: ContentDigest,
) -> Result<Option<KnowledgeStateBasis>, ContractError> {
    Ok(match state {
        KnowledgeState::Redacted => Some(KnowledgeStateBasis::Redaction(RedactionMarker {
            reason: RedactionReason::PrivacyProjection,
            privacy_generation: PrivacyGeneration::parse("privacy:projection:v1")?,
        })),
        KnowledgeState::Stale => Some(KnowledgeStateBasis::Stale(StaleBasis::OlderGeneration {
            valid_at: Generation::from_u64(1),
            current: Generation::from_u64(2),
        })),
        KnowledgeState::Indeterminate => Some(KnowledgeStateBasis::Reconciliation(
            ReconciliationBasis::occurred_or_not(root),
        )),
        KnowledgeState::Known
        | KnowledgeState::Estimated
        | KnowledgeState::Unknown
        | KnowledgeState::Conflicted
        | KnowledgeState::NotObservable
        | KnowledgeState::NotApplicable => None,
    })
}

fn evidence_less_params(
    state: KnowledgeState,
    provenance: ProvenanceClass,
    contradictions: Vec<ContentDigest>,
) -> Result<KnowledgeCellParams, ContractError> {
    Ok(KnowledgeCellParams {
        claim_id: format!(
            "claim:evidence-less:{}:{}",
            provenance.as_str(),
            state.as_str()
        ),
        statement: "Evidence-less proposition".to_string(),
        knowledge_state: state,
        provenance,
        hypothesis: None,
        evidence: vec![],
        contradictions,
        valid_until: None,
        state_basis: required_state_basis(
            state,
            ContentDigest::sha256(b"evidence_less_reconciliation_root"),
        )?,
    })
}

/// PROV-001/PROV-002 intent: an observed or derived cell that asserts present support for its
/// proposition (`known`, `estimated`, `conflicted`) must bind evidence or named inputs.
#[test]
fn test_observed_and_derived_asserting_cells_require_evidence() -> Result<(), Box<dyn Error>> {
    let contradiction = ContentDigest::sha256(b"asserting_cell_contradiction");
    for provenance in [ProvenanceClass::Observed, ProvenanceClass::Derived] {
        for state in [
            KnowledgeState::Known,
            KnowledgeState::Estimated,
            KnowledgeState::Conflicted,
        ] {
            let contradictions = if state == KnowledgeState::Conflicted {
                vec![contradiction]
            } else {
                vec![]
            };
            let params = evidence_less_params(state, provenance, contradictions)?;
            assert_eq!(
                KnowledgeCell::new(params.clone()),
                Err(ContractError::EvidenceRequired),
                "{provenance} {state} without evidence must be refused by constructor"
            );
            let anchored_params = KnowledgeCellParams {
                evidence: vec![ContentDigest::sha256(b"asserting_cell_anchor")],
                ..params
            };
            let anchored = KnowledgeCell::new(anchored_params)?;
            assert_eq!(
                anchored.validate(),
                Ok(()),
                "{provenance} {state} with evidence must be accepted"
            );
        }
    }
    Ok(())
}

/// An honest unknown (or any state asserting no present support) stays valid without evidence
/// under every provenance class: knowledge state and provenance stay orthogonal, and a cell is
/// never refused for lacking the support it reports it does not have.
#[test]
fn test_non_asserting_cells_stay_valid_without_evidence() -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let contradiction = ContentDigest::sha256(b"contradicting_root_only");
    for provenance in [
        ProvenanceClass::Observed,
        ProvenanceClass::Derived,
        ProvenanceClass::Predicted,
        ProvenanceClass::Remembered,
        ProvenanceClass::OperatorAsserted,
        ProvenanceClass::VendorClaimed,
        ProvenanceClass::Policy,
    ] {
        for state in [
            KnowledgeState::Unknown,
            KnowledgeState::Stale,
            KnowledgeState::NotObservable,
            KnowledgeState::Redacted,
            KnowledgeState::Indeterminate,
            KnowledgeState::NotApplicable,
        ] {
            let params = evidence_less_params(state, provenance, vec![])?;
            let cell = KnowledgeCell::new(params)?;
            assert_eq!(
                cell.validate(),
                Ok(()),
                "{provenance} {state} without evidence must stay valid"
            );
            assert_eq!(cell.knowledge_state(), state);
            assert_eq!(cell.provenance(), provenance);
            assert!(!cell.is_irreversible_effect_premise(now));
        }
    }

    // The physical cell for an event whose revision edges only contradict it: observed,
    // unknown, no supporting root, one contradicting root.
    let contradicted_unknown = KnowledgeCell::new(evidence_less_params(
        KnowledgeState::Unknown,
        ProvenanceClass::Observed,
        vec![contradiction],
    )?)?;
    assert!(contradicted_unknown.is_unknown());
    assert!(contradicted_unknown.is_observed());
    assert!(contradicted_unknown.evidence().is_empty());
    assert!(!contradicted_unknown.is_irreversible_effect_premise(now));
    Ok(())
}

#[test]
fn test_predicted_known_forbidden() -> Result<(), Box<dyn Error>> {
    let digest = ContentDigest::sha256(b"predicted_evidence_root_001");

    // Predicted + Known is strictly refused per PROV-003, AGENTS.md, and Constitution §8.2
    let params_predicted_known = KnowledgeCellParams {
        claim_id: "claim:future:event:001".to_string(),
        statement: "A future prediction claimed as known truth".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Predicted,
        hypothesis: None,
        evidence: vec![digest],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    };
    assert_eq!(
        KnowledgeCell::new(params_predicted_known),
        Err(ContractError::PredictedKnownForbidden)
    );

    // Predicted with Estimated is valid
    let cell_predicted_estimated = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:future:event:002".to_string(),
        statement: "A future prediction estimated with bounded model uncertainty".to_string(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Predicted,
        hypothesis: None,
        evidence: vec![digest],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })?;
    assert!(cell_predicted_estimated.validate().is_ok());

    Ok(())
}

#[test]
fn test_canonical_decode_and_from_str_strictly_refuse_ids() -> Result<(), Box<dyn Error>> {
    for prov in [
        ProvenanceClass::Observed,
        ProvenanceClass::Derived,
        ProvenanceClass::Predicted,
        ProvenanceClass::Remembered,
        ProvenanceClass::OperatorAsserted,
        ProvenanceClass::VendorClaimed,
        ProvenanceClass::Policy,
    ] {
        // Canonical decode accepts exact schema name
        let mut enc = CanonicalEncoder::new();
        enc.text(prov.as_str());
        let bytes = enc.finish();
        let mut dec = CanonicalDecoder::new(&bytes);
        assert_eq!(ProvenanceClass::decode_canonical(&mut dec)?, prov);

        // Canonical decode strictly refuses stable IDs
        let mut enc_id = CanonicalEncoder::new();
        enc_id.text(prov.id());
        let bytes_id = enc_id.finish();
        let mut dec_id = CanonicalDecoder::new(&bytes_id);
        assert_eq!(
            ProvenanceClass::decode_canonical(&mut dec_id),
            Err(ContractError::InvalidIdentifier)
        );

        // FromStr accepts exact schema name
        assert_eq!(ProvenanceClass::from_str(prov.as_str())?, prov);

        // FromStr strictly refuses stable IDs
        assert_eq!(
            ProvenanceClass::from_str(prov.id()),
            Err(ContractError::InvalidIdentifier)
        );
    }
    Ok(())
}

#[test]
fn test_may_launder_evidence_into_matrix() -> Result<(), Box<dyn Error>> {
    let classes = [
        ProvenanceClass::Observed,
        ProvenanceClass::Derived,
        ProvenanceClass::Predicted,
        ProvenanceClass::Remembered,
        ProvenanceClass::OperatorAsserted,
        ProvenanceClass::VendorClaimed,
        ProvenanceClass::Policy,
    ];

    for source in classes {
        for target in classes {
            let result = source.may_launder_evidence_into(target);
            match source {
                ProvenanceClass::Predicted => {
                    assert_eq!(
                        result,
                        target != ProvenanceClass::Predicted,
                        "Predicted into non-Predicted must constitute laundering"
                    );
                }
                ProvenanceClass::Derived => {
                    assert_eq!(
                        result,
                        target == ProvenanceClass::Observed,
                        "Derived into Observed must constitute laundering (Constitution §8.3)"
                    );
                }
                ProvenanceClass::Remembered => {
                    assert_eq!(
                        result,
                        matches!(
                            target,
                            ProvenanceClass::Observed
                                | ProvenanceClass::Derived
                                | ProvenanceClass::OperatorAsserted
                                | ProvenanceClass::Policy
                        ),
                        "Remembered laundering into authorizing/live classes must be refused"
                    );
                }
                ProvenanceClass::VendorClaimed => {
                    assert_eq!(
                        result,
                        matches!(
                            target,
                            ProvenanceClass::Observed
                                | ProvenanceClass::Derived
                                | ProvenanceClass::OperatorAsserted
                                | ProvenanceClass::Policy
                        ),
                        "VendorClaimed laundering into independent/authorizing classes must be refused"
                    );
                }
                ProvenanceClass::Observed
                | ProvenanceClass::OperatorAsserted
                | ProvenanceClass::Policy => {
                    assert!(
                        !result,
                        "{source} should not constitute laundering into {target}"
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn test_situation_frame_laundering_between_cells_rejected() -> Result<(), Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("site:test");
    let shared_digest = ContentDigest::sha256(b"shared_reused_evidence_digest_001");

    let cell_predicted = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:model:future:1".to_string(),
        statement: "Prediction from model".to_string(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Predicted,
        hypothesis: None,
        evidence: vec![shared_digest],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })?;

    let cell_observed = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:sensor:live:1".to_string(),
        statement: "Live sensor observation".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![shared_digest],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })?;

    let frame = SituationFrame {
        frame_id: "frame:001".to_string(),
        objective_id: "obj:001".to_string(),
        anchor: anchor.clone(),
        world_envelope: WorldEnvelope {
            envelope_id: "env:001".to_string(),
            objective_id: "obj:001".to_string(),
            anchor: anchor.clone(),
            nominal_claim_ids: BTreeSet::new(),
            certified_core_claim_ids: BTreeSet::new(),
            alternatives: vec![],
            adversarial_residuals: vec![],
            common_invariants: BTreeSet::new(),
            coverage_boundary_handles: BTreeSet::new(),
        },
        knowledge_cells: vec![cell_predicted.clone(), cell_observed.clone()],
        now: vec![],
        changed: vec![],
        why: vec![],
        unknown: vec![],
        at_risk: vec![],
        next: vec![],
        evidence_handles: BTreeSet::new(),
    };

    // Directional check: laundering into Observed is refused.
    assert_eq!(
        cell_observed.verify_no_evidence_laundering(&cell_predicted),
        Err(ContractError::EvidenceLaunderingDetected),
        "Directional check must refuse laundering predicted evidence into observed"
    );

    // Intra-frame: unattributable shared evidence is accepted under fss-gefi6.
    assert!(
        frame.validate().is_ok(),
        "Intra-frame unattributable shared evidence is accepted under fss-gefi6"
    );

    Ok(())
}

fn make_test_frame(cells: Vec<KnowledgeCell>) -> SituationFrame {
    let anchor = LedgerAnchor::genesis("site:test");
    SituationFrame {
        frame_id: "frame:001".to_string(),
        objective_id: "obj:001".to_string(),
        anchor: anchor.clone(),
        world_envelope: WorldEnvelope {
            envelope_id: "env:001".to_string(),
            objective_id: "obj:001".to_string(),
            anchor,
            nominal_claim_ids: BTreeSet::new(),
            certified_core_claim_ids: BTreeSet::new(),
            alternatives: vec![],
            adversarial_residuals: vec![],
            common_invariants: BTreeSet::new(),
            coverage_boundary_handles: BTreeSet::new(),
        },
        knowledge_cells: cells,
        now: vec![],
        changed: vec![],
        why: vec![],
        unknown: vec![],
        at_risk: vec![],
        next: vec![],
        evidence_handles: BTreeSet::new(),
    }
}

#[test]
fn test_derived_into_observed_directional_laundering_and_unattributable_frame()
-> Result<(), Box<dyn Error>> {
    let shared_digest = ContentDigest::sha256(b"shared_derived_to_observed_001");
    let cell_derived = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:derived:1".to_string(),
        statement: "Derived computation".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![shared_digest],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })?;
    let cell_observed = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:observed:1".to_string(),
        statement: "Observed assertion".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![shared_digest],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })?;

    // Directional check: Derived into Observed is refused (Constitution §8.3).
    assert_eq!(
        cell_observed.verify_no_evidence_laundering(&cell_derived),
        Err(ContractError::EvidenceLaunderingDetected),
        "Derived into Observed directional laundering must be refused"
    );
    // Honest derivation: Observed into Derived is accepted.
    assert!(
        cell_derived
            .verify_no_evidence_laundering(&cell_observed)
            .is_ok()
    );

    // Intra-frame unattributable shared evidence (fss-gefi6): both permutations validate.
    let frame_forward = make_test_frame(vec![cell_derived.clone(), cell_observed.clone()]);
    assert!(frame_forward.validate().is_ok());
    let frame_reverse = make_test_frame(vec![cell_observed, cell_derived]);
    assert!(frame_reverse.validate().is_ok());

    Ok(())
}

#[test]
fn test_p3_remembered_and_vendor_claimed_directional_laundering_and_unattributable_frame()
-> Result<(), Box<dyn Error>> {
    let shared_digest1 = ContentDigest::sha256(b"shared_remembered_to_policy_001");
    let cell_remembered = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:remembered:1".to_string(),
        statement: "Prior episode memory".to_string(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Remembered,
        hypothesis: None,
        evidence: vec![shared_digest1],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })?;
    let cell_policy = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:policy:1".to_string(),
        statement: "Policy rule".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Policy,
        hypothesis: None,
        evidence: vec![shared_digest1],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })?;

    // Directional check: Remembered into Policy is refused.
    assert_eq!(
        cell_policy.verify_no_evidence_laundering(&cell_remembered),
        Err(ContractError::EvidenceLaunderingDetected),
        "Remembered into Policy directional laundering must be refused"
    );
    assert!(
        cell_remembered
            .verify_no_evidence_laundering(&cell_policy)
            .is_ok()
    );

    // Intra-frame: both permutations validate under fss-gefi6.
    assert!(
        make_test_frame(vec![cell_remembered.clone(), cell_policy.clone()])
            .validate()
            .is_ok()
    );
    assert!(
        make_test_frame(vec![cell_policy, cell_remembered])
            .validate()
            .is_ok()
    );

    let shared_digest2 = ContentDigest::sha256(b"shared_vendor_to_observed_001");
    let cell_vendor = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:vendor:1".to_string(),
        statement: "Vendor claimed boundary state".to_string(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::VendorClaimed,
        hypothesis: None,
        evidence: vec![shared_digest2],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })?;
    let cell_observed = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:observed:2".to_string(),
        statement: "Observed assertion".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![shared_digest2],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })?;

    // Directional check: VendorClaimed into Observed is refused.
    assert_eq!(
        cell_observed.verify_no_evidence_laundering(&cell_vendor),
        Err(ContractError::EvidenceLaunderingDetected),
        "VendorClaimed into Observed directional laundering must be refused"
    );
    assert!(
        cell_vendor
            .verify_no_evidence_laundering(&cell_observed)
            .is_ok()
    );

    // Intra-frame: both permutations validate under fss-gefi6.
    assert!(
        make_test_frame(vec![cell_vendor.clone(), cell_observed.clone()])
            .validate()
            .is_ok()
    );
    assert!(
        make_test_frame(vec![cell_observed, cell_vendor])
            .validate()
            .is_ok()
    );

    Ok(())
}

#[test]
fn test_p2b_prediction_and_observation_directional_laundering_and_unattributable_frame()
-> Result<(), Box<dyn Error>> {
    let shared_digest = ContentDigest::sha256(b"shared_predicted_to_observed_p2b");
    let cell_predicted = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:predicted:p2b".to_string(),
        statement: "Predicted future condition".to_string(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Predicted,
        hypothesis: None,
        evidence: vec![shared_digest],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })?;
    let cell_observed = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:observed:p2b".to_string(),
        statement: "Observed assertion claiming prediction evidence".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![shared_digest],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })?;

    // Directional check: Predicted into Observed is refused.
    assert_eq!(
        cell_observed.verify_no_evidence_laundering(&cell_predicted),
        Err(ContractError::EvidenceLaunderingDetected),
        "Predicted into Observed directional laundering must be refused (P2b)"
    );
    // Honest prediction from observation: Observed into Predicted is accepted.
    assert!(
        cell_predicted
            .verify_no_evidence_laundering(&cell_observed)
            .is_ok()
    );

    // Intra-frame unattributable shared evidence (fss-gefi6): both permutations validate.
    let frame_forward = make_test_frame(vec![cell_predicted.clone(), cell_observed.clone()]);
    assert!(frame_forward.validate().is_ok());
    let frame_reverse = make_test_frame(vec![cell_observed, cell_predicted]);
    assert!(frame_reverse.validate().is_ok());

    Ok(())
}

#[test]
fn test_p4_and_p4r_normal_derivation_observed_and_derived_both_permutations_validate()
-> Result<(), Box<dyn Error>> {
    let shared_digest = ContentDigest::sha256(b"sensor_raw_telemetry_packet_p4");
    let cell_observed = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:sensor:raw:1".to_string(),
        statement: "Live sensor observation".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![shared_digest],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })?;
    let cell_derived = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:derived:rate:1".to_string(),
        statement: "Derived velocity computed from raw telemetry".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![shared_digest],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })?;

    // P4: Observed then Derived validates
    let frame_p4 = make_test_frame(vec![cell_observed.clone(), cell_derived.clone()]);
    assert!(
        frame_p4.validate().is_ok(),
        "Observed into Derived normal derivation must validate (P4)"
    );

    // P4r: Derived then Observed validates (honest derivation must not be refused by order)
    let frame_p4r = make_test_frame(vec![cell_derived, cell_observed]);
    assert!(
        frame_p4r.validate().is_ok(),
        "Derived then Observed normal derivation must validate (P4r)"
    );

    Ok(())
}

#[test]
fn test_p5_and_p5r_normal_prediction_observed_and_predicted_both_permutations_validate()
-> Result<(), Box<dyn Error>> {
    let shared_digest = ContentDigest::sha256(b"sensor_raw_telemetry_packet_p5");
    let cell_observed = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:sensor:raw:2".to_string(),
        statement: "Live sensor observation".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![shared_digest],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })?;
    let cell_predicted = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:model:future:2".to_string(),
        statement: "Prediction of future trajectory from observation".to_string(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Predicted,
        hypothesis: None,
        evidence: vec![shared_digest],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })?;

    // P5: Observed then Predicted validates
    let frame_p5 = make_test_frame(vec![cell_observed.clone(), cell_predicted.clone()]);
    assert!(
        frame_p5.validate().is_ok(),
        "Observed then Predicted normal derivation must validate (P5)"
    );

    // P5r: Predicted then Observed validates
    let frame_p5r = make_test_frame(vec![cell_predicted, cell_observed]);
    assert!(
        frame_p5r.validate().is_ok(),
        "Predicted then Observed normal derivation must validate (P5r)"
    );

    Ok(())
}

#[test]
fn test_q1_verdict_order_independent_all_pairs() -> Result<(), Box<dyn Error>> {
    let shared_digest = ContentDigest::sha256(b"shared_telemetry_q1");
    let cell_observed = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:obs:q1".to_string(),
        statement: "Observed fact".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![shared_digest],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })?;
    let cell_predicted = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:pred:q1".to_string(),
        statement: "Predicted future fact".to_string(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Predicted,
        hypothesis: None,
        evidence: vec![shared_digest],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })?;
    let cell_derived = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:der:q1".to_string(),
        statement: "Derived computation".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![shared_digest],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })?;

    // Q1: validate() verdict must not change with non-canonical cell order.
    let f1 = make_test_frame(vec![cell_predicted.clone(), cell_observed.clone()]);
    let f2 = make_test_frame(vec![cell_observed.clone(), cell_predicted.clone()]);
    assert_eq!(
        f1.validate(),
        f2.validate(),
        "Predicted vs Observed order must not change verdict"
    );

    let f3 = make_test_frame(vec![cell_derived.clone(), cell_observed.clone()]);
    let f4 = make_test_frame(vec![cell_observed, cell_derived]);
    assert_eq!(
        f3.validate(),
        f4.validate(),
        "Derived vs Observed order must not change verdict"
    );

    Ok(())
}

#[test]
fn test_q2_sorted_by_claim_id_order_independent() -> Result<(), Box<dyn Error>> {
    let shared_digest = ContentDigest::sha256(b"shared_telemetry_q2");
    // "claim:a" comes before "claim:z" lexicographically.
    let cell_a = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:a".to_string(),
        statement: "Claim A observed".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![shared_digest],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })?;
    let cell_z = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:z".to_string(),
        statement: "Claim Z predicted".to_string(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Predicted,
        hypothesis: None,
        evidence: vec![shared_digest],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })?;

    let frame_az = make_test_frame(vec![cell_a.clone(), cell_z.clone()]);
    let frame_za = make_test_frame(vec![cell_z, cell_a]);

    assert_eq!(
        frame_az.validate(),
        frame_za.validate(),
        "Frame validation must be identical regardless of claim ID ordering"
    );
    assert!(frame_az.validate().is_ok());

    Ok(())
}

/// Pin current lone-cell limitation: a single cell relabelled with an untyped evidence digest
/// cannot be detected as laundered from the digest alone without sibling or prior context.
/// Tracked for typed evidence references in follow-up bead fss-gefi6.
#[test]
fn test_lone_cell_untyped_digest_limitation_pinned_fss_gefi6() -> Result<(), Box<dyn Error>> {
    let digest = ContentDigest::sha256(b"prediction_or_derived_output_digest");
    // A single cell claiming Observed with this digest validates on its own because
    // the ContentDigest does not carry origin provenance (tracked in fss-gefi6).
    let cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:lone:001".to_string(),
        statement: "Observed statement with untyped digest".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![digest],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })?;
    assert!(
        cell.validate().is_ok(),
        "Lone cell without prior/sibling context currently validates (fss-gefi6)"
    );
    let frame = make_test_frame(vec![cell]);
    assert!(
        frame.validate().is_ok(),
        "Frame with lone relabelled cell currently validates without prior/sibling context (fss-gefi6)"
    );
    Ok(())
}

#[test]
fn test_wire_code_roundtrip() -> Result<(), Box<dyn Error>> {
    for (code, expected) in [
        (1, ProvenanceClass::Observed),
        (2, ProvenanceClass::Derived),
        (3, ProvenanceClass::Predicted),
        (4, ProvenanceClass::Remembered),
        (5, ProvenanceClass::OperatorAsserted),
        (6, ProvenanceClass::VendorClaimed),
        (7, ProvenanceClass::Policy),
    ] {
        assert_eq!(expected.to_code(), code);
        assert_eq!(ProvenanceClass::from_code(code)?, expected);
    }
    assert_eq!(
        ProvenanceClass::from_code(0),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        ProvenanceClass::from_code(8),
        Err(ContractError::InvalidIdentifier)
    );
    Ok(())
}

#[test]
fn test_fss_nozug_planted_bypass_derived_to_known_relabel_refused_as_effect_premise()
-> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let anchor = LedgerAnchor::genesis("site:derived-relabel-bypass-test");
    let belief_generation = Generation::from_u64(1);
    let receipt = ContentDigest::sha256(b"deterministic_derivation_receipt_nozug");
    let input = ContentDigest::sha256(b"input_sensor_tensor_digest_nozug");

    // Construct a valid DerivedBelief
    let params = DerivedBeliefParams {
        belief_id: "belief:track:intruder:001".to_string(),
        anchor: anchor.clone(),
        generation: belief_generation,
        statement: "Intruder detected via multi-camera fusion".to_string(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Derived,
        uncertainty: BeliefInterval::from_f64(0.95, 0.95)?,
        supporting_evidence: vec![input],
        contradictions: vec![],
        derivation_receipt: receipt,
    }
    .with_computed_receipt()?;

    let belief = DerivedBelief::new(params)?;
    let cell = belief.to_knowledge_cell(&anchor)?;

    // Baseline: Estimated + Derived is NOT an irreversible effect premise
    assert_eq!(cell.knowledge_state(), KnowledgeState::Estimated);
    assert_eq!(cell.provenance(), ProvenanceClass::Derived);
    assert!(!cell.is_irreversible_effect_premise(now));

    // Planted bypass attempt: A caller constructs a Derived+Known cell
    // attempting to turn a derived belief into an irreversible-effect premise.
    let relabelled = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: cell.claim_id().to_string(),
        statement: cell.statement().to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: cell.hypothesis(),
        evidence: cell.evidence().to_vec(),
        contradictions: cell.contradictions().to_vec(),
        valid_until: cell.valid_until(),
        state_basis: cell.state_basis().cloned(),
    })?;

    // Constitutional Hard Gate (AGT-LAYER-004, INV-069, PROV-002):
    // Derived beliefs belong strictly to the Cognition plane, never the Authority plane.
    // Even when constructed as Known with valid evidence and no contradictions,
    // ProvenanceClass::Derived::may_authorize_irreversible_effect MUST return false,
    // and is_irreversible_effect_premise MUST return false.
    assert_eq!(relabelled.knowledge_state(), KnowledgeState::Known);
    assert_eq!(relabelled.provenance(), ProvenanceClass::Derived);
    assert!(!relabelled.provenance().may_authorize_irreversible_effect());
    assert!(
        !relabelled.is_irreversible_effect_premise(now),
        "Planted bypass failed closed: Derived+Known cell MUST NOT authorize irreversible effects"
    );

    Ok(())
}

#[test]
fn test_fss_nozug_planted_bypass_hand_crafted_derived_known_cell_refused_as_effect_premise()
-> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let evidence_digest = ContentDigest::sha256(b"admissible_evidence_root_nozug");

    // Planted bypass attempt: Hand-craft a Derived + Known KnowledgeCell with valid inputs,
    // unexpired validity window, and zero contradictions.
    let hand_crafted = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:perimeter:breach:forged".to_string(),
        statement: "Perimeter breach asserted as known from derivation".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;

    // The cell passes semantic validation (Derived allows Known when evidence is present),
    // BUT effect premise evaluation MUST fail closed.
    assert_eq!(hand_crafted.validate(), Ok(()));
    assert_eq!(hand_crafted.knowledge_state(), KnowledgeState::Known);
    assert_eq!(hand_crafted.provenance(), ProvenanceClass::Derived);
    assert!(
        !hand_crafted
            .provenance()
            .may_authorize_irreversible_effect()
    );
    assert!(
        !hand_crafted.is_irreversible_effect_premise(now),
        "Hand-crafted Derived+Known cell MUST NOT authorize irreversible physical effects"
    );

    Ok(())
}

#[test]
fn test_fss_nozug_knowledge_cell_constructor_and_getters_integrity() -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let evidence_digest = ContentDigest::sha256(b"observed_source_evidence_nozug");

    // 1. Valid construction of Observed + Known cell via KnowledgeCell::new
    let observed_params = KnowledgeCellParams {
        claim_id: "claim:physical:sensor:001".to_string(),
        statement: "Motion detected by PIR sensor".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };
    let observed_cell = KnowledgeCell::new(observed_params)?;
    assert_eq!(observed_cell.claim_id(), "claim:physical:sensor:001");
    assert_eq!(observed_cell.statement(), "Motion detected by PIR sensor");
    assert_eq!(observed_cell.knowledge_state(), KnowledgeState::Known);
    assert_eq!(observed_cell.provenance(), ProvenanceClass::Observed);
    assert_eq!(observed_cell.evidence(), &[evidence_digest]);
    assert_eq!(observed_cell.contradictions(), &[]);
    assert_eq!(
        observed_cell.valid_until(),
        Some(TimestampNs(2_000_000_000))
    );
    assert_eq!(observed_cell.state_basis(), None);
    assert!(
        observed_cell
            .provenance()
            .may_authorize_irreversible_effect()
    );
    assert!(observed_cell.is_irreversible_effect_premise(now));

    // 2. Construction of Derived + Known cell via KnowledgeCell::new succeeds validation,
    // but is strictly refused as an effect premise.
    let derived_params = KnowledgeCellParams {
        claim_id: "claim:derived:model:001".to_string(),
        statement: "Classification output derived".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };
    let derived_cell = KnowledgeCell::new(derived_params)?;
    assert_eq!(derived_cell.provenance(), ProvenanceClass::Derived);
    assert!(
        !derived_cell
            .provenance()
            .may_authorize_irreversible_effect()
    );
    assert!(!derived_cell.is_irreversible_effect_premise(now));

    // 3. Construction of Predicted + Known cell via KnowledgeCell::new is refused by validation
    let predicted_params = KnowledgeCellParams {
        claim_id: "claim:predicted:future:001".to_string(),
        statement: "Future state predicted".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Predicted,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    };
    assert_eq!(
        KnowledgeCell::new(predicted_params),
        Err(ContractError::PredictedKnownForbidden)
    );

    Ok(())
}

/// Every insertion-order permutation of `0..n`.
fn permutations(n: usize) -> Vec<Vec<usize>> {
    let mut out = vec![Vec::new()];
    for next in 0..n {
        let mut grown = Vec::new();
        for prefix in &out {
            for slot in 0..=prefix.len() {
                let mut candidate = prefix.clone();
                candidate.insert(slot, next);
                grown.push(candidate);
            }
        }
        out = grown;
    }
    out
}

/// A valid cell of class `provenance` citing `evidence` (predictions are `estimated`, since a
/// prediction may never claim `known`).
fn class_cell(
    claim_id: &str,
    provenance: ProvenanceClass,
    evidence: Vec<ContentDigest>,
) -> Result<KnowledgeCell, ContractError> {
    let knowledge_state = if provenance == ProvenanceClass::Predicted {
        KnowledgeState::Estimated
    } else {
        KnowledgeState::Known
    };
    KnowledgeCell::new(KnowledgeCellParams {
        claim_id: claim_id.to_string(),
        statement: format!("{provenance} statement"),
        knowledge_state,
        provenance,
        hypothesis: None,
        evidence,
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })
}

/// Orchestrator decision (a): the frame verdict is a pure function of the SET of cells. For each
/// probe set, every ordering of the cells times every assignment of the claim ids yields one
/// verdict, and (fss-gefi6: shared evidence within a frame cannot be attributed) that verdict is
/// acceptance. Covers P2, P2b, P3, P4, P4r, P5, P5r, Q1, Q2, and sets of three to five cells.
#[test]
fn test_frame_verdict_depends_only_on_the_cell_set() -> Result<(), Box<dyn Error>> {
    use ProvenanceClass::{
        Derived, Observed, OperatorAsserted, Policy, Predicted, Remembered, VendorClaimed,
    };
    let sets: [(&str, &[ProvenanceClass]); 13] = [
        ("P2 predicted+observed", &[Predicted, Observed]),
        ("P2b relabelled observed+predicted", &[Observed, Predicted]),
        ("P3 remembered+policy", &[Remembered, Policy]),
        ("P3 vendor_claimed+observed", &[VendorClaimed, Observed]),
        (
            "P3 vendor_claimed+operator_asserted",
            &[VendorClaimed, OperatorAsserted],
        ),
        ("P4 observed+derived", &[Observed, Derived]),
        ("P4r derived+observed", &[Derived, Observed]),
        ("P5 observed+predicted", &[Observed, Predicted]),
        ("P5r predicted+observed", &[Predicted, Observed]),
        (
            "Q1 derived+observed+predicted",
            &[Derived, Observed, Predicted],
        ),
        (
            "Q2 observed(claim:a)+predicted(claim:z)",
            &[Observed, Predicted],
        ),
        (
            "T4 observed+derived+predicted+remembered",
            &[Observed, Derived, Predicted, Remembered],
        ),
        (
            "T5 observed+derived+predicted+remembered+vendor_claimed",
            &[Observed, Derived, Predicted, Remembered, VendorClaimed],
        ),
    ];
    let names = ["claim:a", "claim:m", "claim:t", "claim:x", "claim:z"];
    for (label, classes) in sets {
        let digest = ContentDigest::sha256(label.as_bytes());
        let n = classes.len();
        let mut verdicts = BTreeSet::new();
        let mut runs = 0usize;
        for naming in permutations(n) {
            let mut cells = Vec::with_capacity(n);
            for (index, class) in classes.iter().enumerate() {
                cells.push(class_cell(names[naming[index]], *class, vec![digest])?);
            }
            for order in permutations(n) {
                let ordered: Vec<KnowledgeCell> =
                    order.iter().map(|&index| cells[index].clone()).collect();
                verdicts.insert(format!("{:?}", make_test_frame(ordered).validate()));
                runs += 1;
            }
        }
        let factorial: usize = (1..=n).product();
        assert_eq!(
            runs,
            factorial * factorial,
            "{label}: not every permutation ran"
        );
        assert_eq!(
            verdicts.len(),
            1,
            "{label}: the verdict depends on order or naming: {verdicts:?}"
        );
        assert!(
            verdicts.contains("Ok(())"),
            "{label}: an unattributable set was refused: {verdicts:?}"
        );
    }
    Ok(())
}

const ALL_CLASSES: [ProvenanceClass; 7] = [
    ProvenanceClass::Observed,
    ProvenanceClass::Derived,
    ProvenanceClass::Predicted,
    ProvenanceClass::Remembered,
    ProvenanceClass::OperatorAsserted,
    ProvenanceClass::VendorClaimed,
    ProvenanceClass::Policy,
];

/// The registered `mayLaunderEvidenceInto` table (architecture/agent_contracts.json), spelled out
/// independently of `ProvenanceClass::may_launder_evidence_into`.
fn registered_launder_targets(source: ProvenanceClass) -> &'static [ProvenanceClass] {
    use ProvenanceClass::{
        Derived, Observed, OperatorAsserted, Policy, Predicted, Remembered, VendorClaimed,
    };
    match source {
        Observed | OperatorAsserted | Policy => &[],
        Derived => &[Observed],
        Predicted => &[
            Observed,
            Derived,
            Remembered,
            OperatorAsserted,
            VendorClaimed,
            Policy,
        ],
        Remembered | VendorClaimed => &[Observed, Derived, OperatorAsserted, Policy],
    }
}

/// The attributable pairwise check (the producing cell `prior` is known) refuses exactly the
/// registered pairs, for all 49 ordered class pairs, whenever any cited digest is shared, even
/// beside fresh evidence; disjoint evidence is never refused.
#[test]
fn test_pairwise_laundering_check_matches_the_registered_table() -> Result<(), Box<dyn Error>> {
    let shared = ContentDigest::sha256(b"pairwise_shared_evidence");
    let fresh = ContentDigest::sha256(b"pairwise_fresh_evidence");
    let other = ContentDigest::sha256(b"pairwise_disjoint_evidence");
    for source in ALL_CLASSES {
        for target in ALL_CLASSES {
            let registered = registered_launder_targets(source).contains(&target);
            assert_eq!(
                source.may_launder_evidence_into(target),
                registered,
                "{source}->{target}: code table differs from the registered table"
            );
            let want = if registered {
                Err(ContractError::EvidenceLaunderingDetected)
            } else {
                Ok(())
            };
            let prior = class_cell("claim:pair:source", source, vec![shared])?;
            let same = class_cell("claim:pair:target", target, vec![shared])?;
            assert_eq!(
                same.verify_no_evidence_laundering(&prior),
                want,
                "{source}->{target}: shared evidence"
            );
            let partial = class_cell("claim:pair:partial", target, vec![shared, fresh])?;
            assert_eq!(
                partial.verify_no_evidence_laundering(&prior),
                want,
                "{source}->{target}: one shared digest beside fresh evidence"
            );
            let disjoint = class_cell("claim:pair:disjoint", target, vec![other])?;
            assert_eq!(
                disjoint.verify_no_evidence_laundering(&prior),
                Ok(()),
                "{source}->{target}: disjoint evidence"
            );
        }
    }
    Ok(())
}

/// Only authorizing classes (observed, operator_asserted, policy) yield an irreversible-effect
/// premise, even as valid `known` cells with evidence; a predicted `known` cell is refused.
#[test]
fn test_only_authorizing_known_cells_are_effect_premises() -> Result<(), Box<dyn Error>> {
    let evidence = ContentDigest::sha256(b"premise_evidence");
    let now = TimestampNs(1);
    for provenance in ALL_CLASSES {
        let cell = class_cell("claim:premise", provenance, vec![evidence])?;
        let authorizing = matches!(
            provenance,
            ProvenanceClass::Observed | ProvenanceClass::OperatorAsserted | ProvenanceClass::Policy
        );
        assert_eq!(
            cell.is_irreversible_effect_premise(now),
            authorizing,
            "{provenance}"
        );
    }
    assert_eq!(
        KnowledgeCell::new(KnowledgeCellParams {
            claim_id: "claim:premise:predicted_known".to_string(),
            statement: "Predicted claim relabelled known".to_string(),
            knowledge_state: KnowledgeState::Known,
            provenance: ProvenanceClass::Predicted,
            hypothesis: None,
            evidence: vec![evidence],
            contradictions: vec![],
            valid_until: None,
            state_basis: None,
        }),
        Err(ContractError::PredictedKnownForbidden)
    );
    Ok(())
}

// fss-2nwxm: the PROV laundering refusal is enforced on production paths, not only in tests.

/// A `MaterialState` delta from `sequence` to `sequence + 1` whose changed cells are
/// `changed_cells`.
fn material_delta(
    sequence: u64,
    changed_cells: Vec<KnowledgeCell>,
) -> Result<MeaningfulDelta, Box<dyn Error>> {
    let anchor = |at: u64| {
        let mut anchor = LedgerAnchor::genesis("site:coalesce");
        anchor.commit_sequence = at;
        anchor
    };
    Ok(MeaningfulDelta {
        delta_id: format!("delta:coalesce:{sequence}"),
        contract_basis: ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
            b"schemas",
            b"operations",
            b"views",
            b"capabilities",
            b"errors",
            b"costs",
            "fss:test",
        )),
        session_id: SessionId::parse("session:coalesce")?,
        basis_frame_id: format!("frame:coalesce:{sequence}"),
        result_frame_id: format!("frame:coalesce:{}", sequence + 1),
        basis_anchor: anchor(sequence),
        result_anchor: anchor(sequence + 1),
        classes: BTreeSet::from([MeaningfulDeltaClass::MaterialState]),
        changed_cells,
        removed_claim_ids: Vec::new(),
        invalidated_assumptions: Vec::new(),
        coverage_changes: Vec::new(),
        obligation_changes: Vec::new(),
        effect_uncertainty_changes: Vec::new(),
        coalesced_count: 0,
        omitted_count: 0,
        omission_reasons: Vec::new(),
        priority: DeltaPriority::Normal,
        continuation: format!("continuation:coalesce:{sequence}"),
        selection_witness: ContentDigest::sha256(b"coalesce_selection"),
        silence_certificate: None,
    })
}

/// fss-2nwxm: `MeaningfulDelta::coalesce` supersedes an earlier changed cell with the later changed
/// cell of the same claim, so the earlier cell is its known prior. For all 49 ordered class pairs,
/// coalescing refuses exactly the registered laundering pairs with `EvidenceLaunderingDetected`
/// when a cited digest is shared, even beside fresh evidence, and accepts disjoint evidence and a
/// shared digest under another claim.
#[test]
fn test_coalesce_refuses_exactly_the_registered_superseding_relabels() -> Result<(), Box<dyn Error>>
{
    let shared = ContentDigest::sha256(b"coalesce_shared_evidence");
    let fresh = ContentDigest::sha256(b"coalesce_fresh_evidence");
    let merge = |first: &MeaningfulDelta, second: &MeaningfulDelta| {
        first.coalesce(
            second,
            "delta:coalesce:merged",
            "continuation:coalesce:merged",
            ContentDigest::sha256(b"coalesce_merged"),
        )
    };
    for source in ALL_CLASSES {
        for target in ALL_CLASSES {
            let first =
                material_delta(1, vec![class_cell("claim:coalesce", source, vec![shared])?])?;
            let relabel = material_delta(
                2,
                vec![class_cell("claim:coalesce", target, vec![shared, fresh])?],
            )?;
            if registered_launder_targets(source).contains(&target) {
                assert_eq!(
                    merge(&first, &relabel).err(),
                    Some(ContractError::EvidenceLaunderingDetected),
                    "{source}->{target}: shared evidence"
                );
            } else {
                let merged = merge(&first, &relabel)?;
                assert_eq!(
                    merged
                        .changed_cells
                        .iter()
                        .map(KnowledgeCell::provenance)
                        .collect::<Vec<_>>(),
                    vec![target],
                    "{source}->{target}: the later cell is the final state"
                );
            }
            let disjoint =
                material_delta(2, vec![class_cell("claim:coalesce", target, vec![fresh])?])?;
            assert!(
                merge(&first, &disjoint).is_ok(),
                "{source}->{target}: disjoint evidence"
            );
            let other_claim = material_delta(
                2,
                vec![class_cell("claim:coalesce:other", target, vec![shared])?],
            )?;
            assert!(
                merge(&first, &other_claim).is_ok(),
                "{source}->{target}: a shared digest under another claim"
            );
        }
    }
    Ok(())
}

/// The PROV laundering check the repository guard looks for.
const LAUNDERING_CHECK: &[u8] = b"verify_no_evidence_laundering";

/// Words that open an item after its visibility. A gated item ends at its first `;` or at the
/// close of its first braced body; any other gated target (a field, variant, match arm or
/// statement) also ends at a `,`.
const ITEM_KEYWORDS: [&str; 14] = [
    "mod",
    "fn",
    "impl",
    "trait",
    "struct",
    "enum",
    "union",
    "const",
    "static",
    "type",
    "use",
    "extern",
    "async",
    "macro_rules",
];

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte >= 0x80
}

/// Blanks `code[from..to]`, keeping newlines so line numbers survive.
fn blank(code: &mut [u8], from: usize, to: usize) {
    for byte in code.iter_mut().take(to).skip(from) {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

fn skip_ws(code: &[u8], mut at: usize) -> usize {
    while code.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }
    at
}

/// End (exclusive) of the string literal whose body starts at `body`.
fn string_end(src: &[u8], body: usize) -> usize {
    let mut at = body;
    while let Some(&byte) = src.get(at) {
        match byte {
            b'\\' => at += 2,
            b'"' => return at + 1,
            _ => at += 1,
        }
    }
    src.len()
}

/// End (exclusive) of the raw string whose `#` run starts at `start`, if one starts there.
fn raw_string_end(src: &[u8], start: usize) -> Option<usize> {
    let hashes = src
        .get(start..)?
        .iter()
        .take_while(|&&byte| byte == b'#')
        .count();
    if src.get(start + hashes) != Some(&b'"') {
        return None;
    }
    let body = start + hashes + 1;
    let mut closing = vec![b'"'];
    closing.resize(hashes + 1, b'#');
    Some(
        src.get(body..)?
            .windows(closing.len())
            .position(|window| window == closing.as_slice())
            .map_or(src.len(), |offset| body + offset + closing.len()),
    )
}

/// End (exclusive) of the character literal opening at `quote`, or `None` for a lifetime.
fn char_literal_end(src: &[u8], quote: usize) -> Option<usize> {
    let first = *src.get(quote + 1)?;
    if first == b'\\' {
        let rest = src.get(quote + 3..)?;
        return rest
            .iter()
            .position(|&byte| byte == b'\'')
            .map(|offset| quote + 4 + offset);
    }
    let width = match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    };
    (src.get(quote + 1 + width) == Some(&b'\'')).then_some(quote + 2 + width)
}

/// End (exclusive) of the (nested) block comment opening at `open`.
fn block_comment_end(src: &[u8], open: usize) -> usize {
    let mut depth = 0usize;
    let mut at = open;
    while at < src.len() {
        if src[at..].starts_with(b"/*") {
            depth += 1;
            at += 2;
        } else if src[at..].starts_with(b"*/") {
            depth -= 1;
            at += 2;
            if depth == 0 {
                return at;
            }
        } else {
            at += 1;
        }
    }
    src.len()
}

/// Returns `source` with every comment, string literal and character literal blanked at the same
/// offsets, so a comment, doc or string naming the check never reads as code.
fn mask_rust(source: &str) -> Vec<u8> {
    let src = source.as_bytes();
    let mut code = src.to_vec();
    let mut at = 0;
    while let Some(&byte) = src.get(at) {
        let next = src.get(at + 1).copied();
        let after_ident = at > 0 && is_ident_byte(src[at - 1]);
        let end = match byte {
            b'/' if next == Some(b'/') => Some(
                src[at..]
                    .iter()
                    .position(|&byte| byte == b'\n')
                    .map_or(src.len(), |offset| at + offset),
            ),
            b'/' if next == Some(b'*') => Some(block_comment_end(src, at)),
            b'"' => Some(string_end(src, at + 1)),
            b'r' if !after_ident => raw_string_end(src, at + 1),
            b'b' if !after_ident && next == Some(b'r') => raw_string_end(src, at + 2),
            b'\'' => char_literal_end(src, at),
            _ => None,
        };
        match end {
            Some(end) => {
                blank(&mut code, at, end);
                at = end;
            }
            None => at += 1,
        }
    }
    code
}

/// Parses the attribute opening at `hash`: whether it is inner, its content without whitespace,
/// and its end (exclusive).
fn attribute_at(code: &[u8], hash: usize) -> Option<(bool, String, usize)> {
    if code.get(hash) != Some(&b'#') {
        return None;
    }
    let mut at = skip_ws(code, hash + 1);
    let inner = code.get(at) == Some(&b'!');
    if inner {
        at = skip_ws(code, at + 1);
    }
    if code.get(at) != Some(&b'[') {
        return None;
    }
    let mut depth = 0usize;
    for (offset, &byte) in code.get(at..)?.iter().enumerate() {
        match byte {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    let close = at + offset;
                    let content = code[at + 1..close]
                        .iter()
                        .filter(|byte| !byte.is_ascii_whitespace())
                        .map(|&byte| char::from(byte))
                        .collect();
                    return Some((inner, content, close + 1));
                }
            }
            _ => {}
        }
    }
    None
}

fn is_test_gate(content: &str) -> bool {
    content == "cfg(test)"
        || content.starts_with("cfg(all(test,")
        || content.starts_with("cfg(all(test)")
}

/// The `"..."` literal inside `source[from..to]`.
fn literal_in(source: &str, from: usize, to: usize) -> Result<String, String> {
    let text = source.get(from..to).ok_or("attribute outside the source")?;
    let open = text.find('"').ok_or("#[path] without a literal")?;
    let body = &text[open + 1..];
    let close = body.find('"').ok_or("unterminated #[path] literal")?;
    Ok(body[..close].to_owned())
}

/// Index of the `}` closing the `{` at `open`.
fn matching_brace(code: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, &byte) in code.get(open..)?.iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + offset);
                }
            }
            _ => {}
        }
    }
    None
}

/// The identifier-like word at `from` and its end.
fn word_at(code: &[u8], from: usize) -> (String, usize) {
    let end = from
        + code.get(from..).map_or(0, |rest| {
            rest.iter().take_while(|&&byte| is_ident_byte(byte)).count()
        });
    (String::from_utf8_lossy(&code[from..end]).into_owned(), end)
}

/// End (exclusive) of the gated target starting at `start`, and the name of the out-of-line
/// module it declares, if it is one. An item ends at its first `;` or at the close of its first
/// braced body; any other target also ends at a `,`; every target ends before an unmatched
/// closing delimiter. Only `(`/`[` nesting is tracked outside braced bodies.
fn gated_target_end(code: &[u8], start: usize) -> Result<(usize, Option<String>), String> {
    let (mut word, mut after) = word_at(code, start);
    if word == "pub" {
        after = skip_ws(code, after);
        if code.get(after) == Some(&b'(') {
            after = code[after..]
                .iter()
                .position(|&byte| byte == b')')
                .map_or(code.len(), |offset| after + offset + 1);
        }
        (word, after) = word_at(code, skip_ws(code, after));
    }
    let item = ITEM_KEYWORDS.contains(&word.as_str());
    let module = (word == "mod").then(|| word_at(code, skip_ws(code, after)).0);
    let mut depth = 0usize;
    let mut at = start;
    while let Some(&byte) = code.get(at) {
        match byte {
            b'(' | b'[' => depth += 1,
            b')' | b']' | b'}' if depth == 0 => return Ok((at, None)),
            b')' | b']' => depth -= 1,
            b';' if depth == 0 => return Ok((at + 1, module)),
            b',' if depth == 0 && !item => return Ok((at + 1, None)),
            b'{' if depth == 0 => {
                return matching_brace(code, at)
                    .map(|close| (close + 1, None))
                    .ok_or_else(|| "unbalanced braces in a test-gated item".to_owned());
            }
            _ => {}
        }
        at += 1;
    }
    Err("unterminated test-gated item".to_owned())
}

/// An out-of-line module a source declares under `#[cfg(test)]`, with its `#[path]`, if any.
struct TestModule {
    name: String,
    path: Option<String>,
}

/// Blanks every `#[cfg(test)]`-gated target of the masked `code` (all of it under an inner
/// `#![cfg(test)]`) and returns the out-of-line modules declared under the gate. `source` is the
/// unmasked text at the same offsets, read only for `#[path = "..."]` literals.
fn strip_test_items(code: &mut [u8], source: &str) -> Result<Vec<TestModule>, String> {
    let mut modules = Vec::new();
    let mut at = 0;
    while at < code.len() {
        let Some((inner, content, attribute_end)) = attribute_at(code, at) else {
            at += 1;
            continue;
        };
        if !is_test_gate(&content) {
            at = attribute_end;
            continue;
        }
        if inner {
            let len = code.len();
            blank(code, 0, len);
            return Ok(modules);
        }
        let mut target = skip_ws(code, attribute_end);
        let mut path = None;
        while let Some((false, content, end)) = attribute_at(code, target) {
            if content.starts_with("path=") {
                path = Some(literal_in(source, target, end)?);
            }
            target = skip_ws(code, end);
        }
        let (end, module) = gated_target_end(code, target)?;
        if let Some(name) = module {
            modules.push(TestModule { name, path });
        }
        blank(code, at, end);
        at = end;
    }
    Ok(modules)
}

/// The 1-based lines of `code` that call the check as a method (`.check(`) or by path
/// (`::check(`).
fn laundering_call_lines(code: &[u8]) -> Vec<usize> {
    let mut lines = Vec::new();
    let mut from = 0;
    while let Some(offset) = code.get(from..).and_then(|rest| {
        rest.windows(LAUNDERING_CHECK.len())
            .position(|window| window == LAUNDERING_CHECK)
    }) {
        let at = from + offset;
        let end = at + LAUNDERING_CHECK.len();
        from = end;
        let whole_word = !code.get(end).is_some_and(|&byte| is_ident_byte(byte))
            && !(at > 0 && is_ident_byte(code[at - 1]));
        let qualified = code[..at]
            .iter()
            .rposition(|byte| !byte.is_ascii_whitespace())
            .is_some_and(|prev| {
                code[prev] == b'.' || (code[prev] == b':' && prev > 0 && code[prev - 1] == b':')
            });
        let called = code.get(skip_ws(code, end)) == Some(&b'(');
        if whole_word && qualified && called {
            lines.push(code[..at].iter().filter(|&&byte| byte == b'\n').count() + 1);
        }
    }
    lines
}

/// The production call sites (`path:line`) of the check in `sources`, source files given as
/// (repository-relative path, text) pairs. Test code never counts: `#[cfg(test)]`-gated targets
/// are blanked, and a file that an out-of-line `#[cfg(test)]` module declaration resolves to is
/// skipped with every module nested under it. A declaration that resolves to no given file is an
/// error, never a silent skip.
fn production_laundering_callers(sources: &[(PathBuf, String)]) -> Result<Vec<String>, String> {
    let known: BTreeSet<&Path> = sources.iter().map(|(path, _)| path.as_path()).collect();
    let mut scanned = Vec::new();
    let mut test_files = BTreeSet::new();
    let mut test_dirs = Vec::new();
    for (path, text) in sources {
        let mut code = mask_rust(text);
        let modules = strip_test_items(&mut code, text)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let dir = path
            .parent()
            .ok_or_else(|| format!("{}: no parent directory", path.display()))?;
        let owns_dir = matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some("lib.rs" | "main.rs" | "mod.rs")
        );
        let base = if owns_dir {
            dir.to_path_buf()
        } else {
            path.with_extension("")
        };
        for module in modules {
            let candidates = match &module.path {
                Some(explicit) => vec![dir.join(explicit)],
                None => vec![
                    base.join(format!("{}.rs", module.name)),
                    base.join(&module.name).join("mod.rs"),
                ],
            };
            let file = candidates
                .into_iter()
                .find(|candidate| known.contains(candidate.as_path()))
                .ok_or_else(|| {
                    format!(
                        "{}: test module `{}` resolves to no source file",
                        path.display(),
                        module.name
                    )
                })?;
            let nested = if file.ends_with("mod.rs") {
                file.parent().map(Path::to_path_buf)
            } else {
                Some(file.with_extension(""))
            };
            test_dirs.extend(nested);
            test_files.insert(file);
        }
        scanned.push((path, code));
    }
    let mut callers = Vec::new();
    for (path, code) in scanned {
        if test_files.contains(path) || test_dirs.iter().any(|dir| path.starts_with(dir)) {
            continue;
        }
        callers.extend(
            laundering_call_lines(&code)
                .into_iter()
                .map(|line| format!("{}:{line}", path.display())),
        );
    }
    Ok(callers)
}

/// Fails unless `sources` carries a production caller of the check; returns the call sites.
fn require_production_caller(sources: &[(PathBuf, String)]) -> Result<Vec<String>, String> {
    let callers = production_laundering_callers(sources)?;
    if callers.is_empty() {
        return Err(
            "verify_no_evidence_laundering has no production caller, so the PROV laundering \
             refusal is enforced only in tests (fss-2nwxm)"
                .to_owned(),
        );
    }
    Ok(callers)
}

/// Every `.rs` file under each workspace crate's `src`, as (repository-relative path, text).
fn workspace_sources() -> Result<Vec<(PathBuf, String)>, Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("missing crates directory")?
        .parent()
        .ok_or("missing repository root")?;
    let mut pending = Vec::new();
    for entry in std::fs::read_dir(root.join("crates"))? {
        let src = entry?.path().join("src");
        if src.is_dir() {
            pending.push(src);
        }
    }
    let mut sources = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let text = std::fs::read_to_string(&path)?;
                sources.push((path.strip_prefix(root)?.to_path_buf(), text));
            }
        }
    }
    sources.sort();
    Ok(sources)
}

/// fss-2nwxm repository guard: `KnowledgeCell::verify_no_evidence_laundering` has at least one
/// caller outside test code in the `src` tree of a workspace crate, so the PROV laundering refusal
/// is enforced on a production path and not only in tests.
#[test]
fn test_laundering_refusal_has_a_production_caller() -> Result<(), Box<dyn Error>> {
    let sources = workspace_sources()?;
    assert!(
        sources.iter().any(|(path, text)| {
            path.ends_with("crates/fss-core/src/agent.rs")
                && text.contains("pub fn verify_no_evidence_laundering(")
        }),
        "the scan did not reach the definition of the check"
    );
    require_production_caller(&sources)?;
    Ok(())
}

/// The guard's scanner on a planted crate: its one production caller is found, and removing it
/// (the planted caller removal) fails the guard. A call under `#[cfg(test)]` (inline module,
/// out-of-line module, `#[path]` module, gated function, gated file) or in a comment, doc, string
/// or raw string, and the definition itself, never count; an unresolvable test module is refused.
#[test]
fn test_laundering_guard_fails_on_a_planted_caller_removal() -> Result<(), Box<dyn Error>> {
    let lib = "#[cfg(test)]\nmod admit_tests;\n#[cfg(test)]\n#[path = \"planted_probe.rs\"]\nmod probe;\npub mod admit;\npub mod decoys;\npub mod gated;\n";
    let admit = r#"//! Planted admission path.

pub fn admit<'a>(current: &'a KnowledgeCell, prior: &KnowledgeCell) -> Result<(), ContractError> {
    current.verify_no_evidence_laundering(prior)
}

pub struct Probe {
    #[cfg(test)]
    armed: BTreeMap<u8, u8>,
    pub open: u8,
}

#[cfg(test)]
fn helper(a: &KnowledgeCell, b: &KnowledgeCell) {
    let _ = a.verify_no_evidence_laundering(b);
}

#[cfg(test)]
mod tests {
    const CLOSE: &str = "}";
    const OPEN: char = '{';
    fn check(a: &K, b: &K) {
        let _ = a.verify_no_evidence_laundering(b);
    }
}
"#;
    let decoys = r##"/// Calls `cell.verify_no_evidence_laundering(prior)`.
// cell.verify_no_evidence_laundering(prior)
/* outer /* cell.verify_no_evidence_laundering(prior) */ still a comment */
pub const TEXT: &str = "cell.verify_no_evidence_laundering(prior)";
pub const RAW: &str = r#"cell.verify_no_evidence_laundering(prior)"#;
pub fn verify_no_evidence_laundering(&self, prior: &KnowledgeCell) {}
"##;
    let gated = "#![cfg(test)]\npub fn g(a: &K, b: &K) {\n    let _ = a.verify_no_evidence_laundering(b);\n}\n";
    let test_only =
        "pub fn probe(a: &K, b: &K) {\n    let _ = a.verify_no_evidence_laundering(b);\n}\n";
    let tree = |admit_text: &str| -> Vec<(PathBuf, String)> {
        [
            ("lib.rs", lib),
            ("admit.rs", admit_text),
            ("admit_tests.rs", test_only),
            ("planted_probe.rs", test_only),
            ("decoys.rs", decoys),
            ("gated.rs", gated),
        ]
        .into_iter()
        .map(|(name, text)| (Path::new("crates/planted/src").join(name), text.to_owned()))
        .collect()
    };
    assert_eq!(
        require_production_caller(&tree(admit))?,
        vec!["crates/planted/src/admit.rs:4".to_owned()]
    );
    let removed = admit.replace("current.verify_no_evidence_laundering(prior)", "Ok(())");
    assert!(
        require_production_caller(&tree(&removed)).is_err(),
        "removing the planted caller must fail the guard"
    );
    let by_path = admit.replace(
        "current.verify_no_evidence_laundering(prior)",
        "KnowledgeCell::verify_no_evidence_laundering(current, prior)",
    );
    assert_eq!(require_production_caller(&tree(&by_path))?.len(), 1);
    let mut orphaned = tree(admit);
    orphaned.retain(|(path, _)| !path.ends_with("admit_tests.rs"));
    assert!(
        production_laundering_callers(&orphaned).is_err(),
        "an unresolvable test module must be refused"
    );
    Ok(())
}
