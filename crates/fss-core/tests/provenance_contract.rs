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
    BeliefInterval, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder,
    ContentDigest, ContractError, DerivedBelief, DerivedBeliefParams, Generation, KnowledgeCell,
    KnowledgeCellParams, KnowledgeState, KnowledgeStateBasis, LedgerAnchor, PrivacyGeneration,
    ProvenanceClass, ReconciliationBasis, RedactionMarker, RedactionReason, StaleBasis,
    TimestampNs,
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
fn test_observed_canonical_decode_rejects_stable_id_strictly_one_to_one()
-> Result<(), Box<dyn Error>> {
    // Canonical encoding is strictly one-to-one: decode_canonical accepts ONLY the schema name "observed"
    // and refuses stable IDs like "PROV-001".
    let mut encoder = CanonicalEncoder::new();
    encoder.text("PROV-001");
    let encoded_bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&encoded_bytes);
    assert_eq!(
        ProvenanceClass::decode_canonical(&mut decoder),
        Err(ContractError::InvalidIdentifier)
    );

    Ok(())
}

#[test]
fn test_knowledge_cell_canonical_encode_uses_provenance_canonical_encoding()
-> Result<(), Box<dyn Error>> {
    let evidence_digest = ContentDigest::sha256(b"canonical_sensor_evidence_anchor_001");
    let cell = KnowledgeCell {
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

    let mut encoder = CanonicalEncoder::new();
    cell.encode_canonical(&mut encoder);
    let bytes = encoder.finish();

    // Verify "observed" appears in the canonical encoding bytes
    assert!(
        bytes.windows(8).any(|window| window == b"observed"),
        "KnowledgeCell canonical encoding must encode provenance via its canonical name 'observed'"
    );

    Ok(())
}

#[test]
fn test_observed_anti_laundering_from_weaker_provenance_rejected() -> Result<(), Box<dyn Error>> {
    let predicted_evidence = ContentDigest::sha256(b"forward_prediction_model_evidence");

    let predicted_cell = KnowledgeCell {
        claim_id: "claim:fire:growth".to_string(),
        statement: "Model predicts fire expansion".to_string(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Predicted,
        hypothesis: None,
        evidence: vec![predicted_evidence],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };

    // Attempting to launder the predicted evidence into an Observed cell
    let laundered_observed_cell = KnowledgeCell {
        claim_id: "claim:fire:growth".to_string(),
        statement: "Physical observation of fire expansion".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![predicted_evidence], // SAME evidence digest from predicted!
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };

    // The anti-laundering check strictly refuses the reused evidence
    assert_eq!(
        laundered_observed_cell.verify_no_evidence_laundering(&predicted_cell),
        Err(ContractError::EvidenceLaunderingDetected)
    );

    // Fresh, distinct live observation evidence passes anti-laundering
    let live_evidence = ContentDigest::sha256(b"live_telemetry_optical_sensor_frame_99");
    let legitimate_observed_cell = KnowledgeCell {
        evidence: vec![live_evidence],
        ..laundered_observed_cell
    };
    assert!(
        legitimate_observed_cell
            .verify_no_evidence_laundering(&predicted_cell)
            .is_ok()
    );

    Ok(())
}

#[test]
fn test_provenance_class_relative_evidentiary_strength() -> Result<(), Box<dyn Error>> {
    assert!(ProvenanceClass::Observed.strength() > ProvenanceClass::Derived.strength());
    assert!(ProvenanceClass::Derived.strength() > ProvenanceClass::Predicted.strength());
    assert!(ProvenanceClass::Derived.strength() > ProvenanceClass::Remembered.strength());
    assert!(ProvenanceClass::Derived.strength() > ProvenanceClass::VendorClaimed.strength());
    assert!(ProvenanceClass::Observed.strength() > ProvenanceClass::OperatorAsserted.strength());

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
fn test_observed_cell_with_known_state_and_valid_evidence_authorizes_effect()
-> Result<(), Box<dyn Error>> {
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
fn test_non_authorizing_provenances_rejected_for_irreversible_effects_even_when_known()
-> Result<(), Box<dyn Error>> {
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

    // 5. Constitutional effect authorization rule (AGT-LAYER-004, INV-069):
    // Derived beliefs belong to the Cognition plane, never the Authority plane,
    // and CANNOT authorize irreversible physical effects.
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

    let from_str_id = ProvenanceClass::from_str("PROV-002")?;
    assert_eq!(from_str_id, ProvenanceClass::Derived);

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
    let cell_without_evidence = KnowledgeCell {
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
        cell_without_evidence.validate(),
        Err(ContractError::EvidenceRequired)
    );
    assert_eq!(
        cell_without_evidence.validated(),
        Err(ContractError::EvidenceRequired)
    );

    // 2. Derived cell with named canonical inputs is ACCEPTED
    let cell_with_evidence = KnowledgeCell {
        claim_id: "claim:occupancy:zone_a".to_string(),
        statement: "Computed occupancy estimate for zone A".to_string(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![input_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };

    assert!(cell_with_evidence.validate().is_ok());
    let validated = cell_with_evidence.validated()?;
    assert!(validated.is_derived());
    assert!(!validated.is_observed());
    assert_eq!(validated.evidence.len(), 1);
    assert_eq!(validated.evidence[0], input_digest);

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
        let cell = KnowledgeCell {
            claim_id: format!("claim:derived:{}", state.as_str()),
            statement: format!("Testing derived orthogonality for {}", state.as_str()),
            knowledge_state: state,
            provenance: ProvenanceClass::Derived,
            hypothesis: None,
            evidence: vec![input_digest],
            contradictions: vec![],
            valid_until: None,
            state_basis: basis_for(state)?,
        };

        assert!(
            cell.validate().is_ok(),
            "Validation failed for derived cell in state {}",
            state.as_str()
        );

        // Provenance remains Derived regardless of epistemic state
        assert_eq!(cell.provenance, ProvenanceClass::Derived);
        assert!(cell.is_derived());
        assert_eq!(cell.provenance.id(), "PROV-002");
        assert_eq!(cell.provenance.as_str(), "derived");

        // Epistemic state and provenance are orthogonal
        assert_ne!(cell.provenance.as_str(), state.as_str());
    }

    Ok(())
}

#[test]
fn test_derived_cell_effect_premise_evaluation() -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let input_digest = ContentDigest::sha256(b"canonical_deterministic_derivation_input");

    // Positive case: Known + Derived + Inputs + No Contradictions + Unexpired
    let valid_cell = KnowledgeCell {
        claim_id: "claim:perimeter:breach:derived".to_string(),
        statement: "Perimeter breach deterministically proved from multi-sensor fused inputs"
            .to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![input_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };

    // Constitutional gate (AGT-LAYER-004, INV-069, PROV-002):
    // Even when Known with non-empty evidence and no contradictions, Derived provenance
    // belongs to the Cognition plane and can NEVER authorize an irreversible effect premise.
    assert!(!valid_cell.is_irreversible_effect_premise(now));
    assert!(!valid_cell.provenance.may_authorize_irreversible_effect());

    // Negative case 1: Empty inputs cannot authorize effect
    let mut no_inputs = valid_cell.clone();
    no_inputs.evidence.clear();
    assert!(!no_inputs.is_irreversible_effect_premise(now));

    // Negative case 2: Contradictions present cannot authorize effect
    let mut conflicted_cell = valid_cell.clone();
    conflicted_cell
        .contradictions
        .push(ContentDigest::sha256(b"contradicting_fused_signal"));
    assert!(!conflicted_cell.is_irreversible_effect_premise(now));

    // Negative case 3: Expired validity cannot authorize effect
    let mut expired_cell = valid_cell.clone();
    expired_cell.valid_until = Some(TimestampNs(500_000_000));
    assert!(!expired_cell.is_irreversible_effect_premise(now));

    // Negative case 4: Estimated state cannot authorize effect even with Derived provenance
    let mut estimated_cell = valid_cell.clone();
    estimated_cell.knowledge_state = KnowledgeState::Estimated;
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

    // Constitutional effect authorization distinction (AGT-LAYER-004, INV-069, PROV-001..003):
    // Only Observed may authorize irreversible effects when Known + witnessed.
    // Both Derived and Predicted CAN NEVER authorize irreversible effects.
    assert!(observed.may_authorize_irreversible_effect());
    assert!(!derived.may_authorize_irreversible_effect());
    assert!(!predicted.may_authorize_irreversible_effect());

    let derived_known_cell = KnowledgeCell {
        claim_id: "claim:derived:known".to_string(),
        statement: "Derived proposition".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: derived,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };
    assert!(!derived_known_cell.is_irreversible_effect_premise(now));

    let predicted_known_cell = KnowledgeCell {
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
    assert!(!predicted_known_cell.is_irreversible_effect_premise(now));

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

    let from_str_id = ProvenanceClass::from_str("PROV-003")?;
    assert_eq!(from_str_id, ProvenanceClass::Predicted);

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
        let cell = KnowledgeCell {
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

        // Per PROV-003 and Constitution §8.2, a prediction is a counterfactual or
        // forward expectation, never current truth. It is strictly forbidden from claiming
        // the Known knowledge state.
        if state == KnowledgeState::Known {
            assert_eq!(
                cell.validate(),
                Err(ContractError::PredictedKnownForbidden),
                "PROV-003: Predicted cell must refuse KnowledgeState::Known as a prediction is never current truth"
            );
            assert_eq!(
                cell.validated(),
                Err(ContractError::PredictedKnownForbidden)
            );
            continue;
        }

        assert!(
            cell.validate().is_ok(),
            "Validation failed for predicted cell in state {}",
            state.as_str()
        );

        // Provenance remains Predicted regardless of epistemic state
        assert_eq!(cell.provenance, ProvenanceClass::Predicted);
        assert!(cell.is_predicted());
        assert_eq!(cell.provenance.id(), "PROV-003");
        assert_eq!(cell.provenance.as_str(), "predicted");

        // Epistemic state and provenance are orthogonal
        assert_ne!(cell.provenance.as_str(), state.as_str());
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
    let predicted_known_cell = KnowledgeCell {
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

    // Per PROV-003 and Constitution §8.2, a prediction is never current truth and cannot claim Known
    assert_eq!(
        predicted_known_cell.validate(),
        Err(ContractError::PredictedKnownForbidden),
        "Predicted cell claiming Known state must be refused"
    );
    assert_eq!(
        predicted_known_cell.clone().validated(),
        Err(ContractError::PredictedKnownForbidden)
    );

    // Irreversible effect premise MUST evaluate to false
    assert!(
        !predicted_known_cell.is_irreversible_effect_premise(now),
        "Predicted cell must NEVER authorize irreversible effects even when Known!"
    );

    // Anti-Laundering Hard Gate (Constitution §8.3 / AGENTS.md):
    // Relabeling the predicted evidence as Observed or Derived does NOT authorize.
    // The same evidence digest cannot be reused under a stronger provenance.
    let laundered_observed = KnowledgeCell {
        claim_id: "claim:predicted:high_confidence_fire".to_string(),
        statement: "Observed physical fire propagation".to_string(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![model_input_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };
    assert_eq!(
        laundered_observed.verify_no_evidence_laundering(&predicted_known_cell),
        Err(ContractError::EvidenceLaunderingDetected),
        "Relabeling predicted evidence to Observed must be rejected as evidence laundering"
    );

    let laundered_derived = KnowledgeCell {
        claim_id: "claim:predicted:high_confidence_fire".to_string(),
        statement: "Derived fire propagation computation".to_string(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![model_input_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };
    assert_eq!(
        laundered_derived.verify_no_evidence_laundering(&predicted_known_cell),
        Err(ContractError::EvidenceLaunderingDetected),
        "Relabeling predicted evidence to Derived must be rejected as evidence laundering"
    );

    // Legitimate estimated prediction fails closed for irreversible effects
    let predicted_estimated_cell = KnowledgeCell {
        knowledge_state: KnowledgeState::Estimated,
        ..predicted_known_cell
    };
    assert!(predicted_estimated_cell.validate().is_ok());
    assert!(!predicted_estimated_cell.is_irreversible_effect_premise(now));

    Ok(())
}

#[test]
fn test_predicted_counterfactual_branch_and_assumptions_semantics() -> Result<(), Box<dyn Error>> {
    let branch_assumption = ContentDigest::sha256(b"counterfactual_branch:suppression_delayed_60s");
    let model_digest = ContentDigest::sha256(b"model:thermal_dispersion:generation_v2");

    // Predicted cell under explicit branch assumptions and model generation
    let counterfactual_cell = KnowledgeCell {
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
    };

    assert!(counterfactual_cell.validate().is_ok());
    let validated = counterfactual_cell.validated()?;
    assert!(validated.is_predicted());
    assert!(!validated.is_observed());
    assert!(!validated.is_derived());
    assert_eq!(validated.evidence.len(), 2);
    assert_eq!(validated.evidence[0], branch_assumption);
    assert_eq!(validated.evidence[1], model_digest);

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
    let vlm_cell = KnowledgeCell {
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
        vlm_cell.validate(),
        Err(ContractError::PredictedKnownForbidden),
        "VLM prediction claiming Known state must be refused"
    );
    assert_eq!(
        vlm_cell.clone().validated(),
        Err(ContractError::PredictedKnownForbidden)
    );

    // Even when legitimately Estimated, VLM prediction fails closed: cannot authorize irreversible effect
    let vlm_estimated = KnowledgeCell {
        knowledge_state: KnowledgeState::Estimated,
        ..vlm_cell
    };
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

    // Predicted, Remembered, VendorClaimed, and Derived are in the non-authorizing partition (AGT-LAYER-004)
    assert!(non_authorizing_classes.contains(&ProvenanceClass::Predicted));
    assert!(non_authorizing_classes.contains(&ProvenanceClass::Remembered));
    assert!(non_authorizing_classes.contains(&ProvenanceClass::VendorClaimed));
    assert!(non_authorizing_classes.contains(&ProvenanceClass::Derived));
    assert_eq!(non_authorizing_classes.len(), 4);

    // Observed, OperatorAsserted, and Policy are in the authorizing partition
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

    let from_str_id = ProvenanceClass::from_str("PROV-004")?;
    assert_eq!(from_str_id, ProvenanceClass::Remembered);

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
        let cell = KnowledgeCell {
            claim_id: format!("claim:remembered:{}", state.as_str()),
            statement: format!("Testing remembered orthogonality for {}", state.as_str()),
            knowledge_state: state,
            provenance: ProvenanceClass::Remembered,
            hypothesis: None,
            evidence: vec![memory_evidence_digest],
            contradictions: vec![],
            valid_until: None,
            state_basis: basis_for(state)?,
        };

        assert!(
            cell.validate().is_ok(),
            "Validation failed for remembered cell in state {}",
            state.as_str()
        );

        // Provenance remains Remembered regardless of epistemic state
        assert_eq!(cell.provenance, ProvenanceClass::Remembered);
        assert!(cell.is_remembered());
        assert_eq!(cell.provenance.id(), "PROV-004");
        assert_eq!(cell.provenance.as_str(), "remembered");

        // Epistemic state and provenance are strictly distinct
        assert_ne!(cell.provenance.as_str(), state.as_str());
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
    let remembered_known_cell = KnowledgeCell {
        claim_id: "claim:remembered:isolation_valve_closed".to_string(),
        statement: "Prior shift episode records cooling loop valve 4 as closed".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Remembered,
        hypothesis: None,
        evidence: vec![episode_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };

    assert!(remembered_known_cell.validate().is_ok());
    assert!(remembered_known_cell.is_remembered());
    assert_eq!(remembered_known_cell.knowledge_state, KnowledgeState::Known);

    // Irreversible effect premise MUST evaluate to false (fail closed)
    assert!(
        !remembered_known_cell.is_irreversible_effect_premise(now),
        "Remembered operational memory must NEVER authorize irreversible effects even when Known!"
    );

    // Anti-Laundering Hard Gate (AGENTS.md & Constitution §8.3):
    // Relabeling a remembered cell as Observed or Derived with the same prior-episode digest
    // is confidence laundering and must NOT authorize.
    let laundered_observed = KnowledgeCell {
        statement: "Observed cooling loop valve 4 as closed".to_string(),
        provenance: ProvenanceClass::Observed,
        ..remembered_known_cell.clone()
    };
    assert_eq!(
        laundered_observed.verify_no_evidence_laundering(&remembered_known_cell),
        Err(ContractError::EvidenceLaunderingDetected),
        "Relabeling remembered evidence to Observed without fresh observation must be rejected"
    );

    let laundered_derived = KnowledgeCell {
        statement: "Derived cooling loop valve 4 as closed".to_string(),
        provenance: ProvenanceClass::Derived,
        ..remembered_known_cell.clone()
    };
    assert_eq!(
        laundered_derived.verify_no_evidence_laundering(&remembered_known_cell),
        Err(ContractError::EvidenceLaunderingDetected),
        "Relabeling remembered evidence to Derived without fresh computation must be rejected"
    );

    Ok(())
}

#[test]
fn test_remembered_advisory_revalidation_lifecycle() -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let prior_episode_ref = ContentDigest::sha256(b"episode_archive_anchor_sequence_42");
    let live_sensor_packet = ContentDigest::sha256(b"live_telemetry_capture_sequence_99");

    // 1. Advisory operational memory: Valve state remembered from prior episode
    let advisory_memory = KnowledgeCell {
        claim_id: "claim:cooling:valve:004".to_string(),
        statement: "Valve 4 was verified closed in prior episode 42".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Remembered,
        hypothesis: None,
        evidence: vec![prior_episode_ref],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    };

    assert!(advisory_memory.validate().is_ok());
    assert!(advisory_memory.is_remembered());
    // Prohibited shortcut from AGENTS.md:
    // "Treating an agent memory, prior handoff, vendor claim, or prediction as current canonical truth."
    // Memory alone cannot authorize an irreversible effect
    assert!(!advisory_memory.is_irreversible_effect_premise(now));

    // 2. Revalidation against live physical evidence (PROV-001 observed at current anchor)
    let live_revalidated = KnowledgeCell {
        claim_id: "claim:cooling:valve:004".to_string(),
        statement: "Live physical contact sensor confirms valve 4 is closed".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![live_sensor_packet],
        contradictions: vec![],
        valid_until: Some(TimestampNs(1_100_000_000)),
        state_basis: None,
    };

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
    let stale_memory = KnowledgeCell {
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
    };

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

    // Remembered, Predicted, VendorClaimed, and Derived are in the non-authorizing partition (AGT-LAYER-004)
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

    let from_str_id = ProvenanceClass::from_str("PROV-005")?;
    assert_eq!(from_str_id, ProvenanceClass::OperatorAsserted);

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
        let cell = KnowledgeCell {
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
        };

        assert!(
            cell.validate().is_ok(),
            "Validation failed for operator_asserted cell in state {}",
            state.as_str()
        );

        // Provenance remains OperatorAsserted regardless of epistemic state
        assert_eq!(cell.provenance, ProvenanceClass::OperatorAsserted);
        assert!(cell.is_operator_asserted());
        assert_eq!(cell.provenance.id(), "PROV-005");
        assert_eq!(cell.provenance.as_str(), "operator_asserted");

        // Epistemic state and provenance are strictly distinct
        assert_ne!(cell.provenance.as_str(), state.as_str());
    }

    Ok(())
}

#[test]
fn test_operator_asserted_effect_premise_authorization_positive_and_negative()
-> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let operator_signature = ContentDigest::sha256(b"signed_operator_emergency_halt_authorization");

    // Positive case: Known + OperatorAsserted + Signed Evidence + No Contradictions + Unexpired
    let valid_operator_cell = KnowledgeCell {
        claim_id: "claim:operator:emergency_halt:zone_d".to_string(),
        statement: "Operator #402 authorizes emergency power isolation for Zone D".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::OperatorAsserted,
        hypothesis: None,
        evidence: vec![operator_signature],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };

    assert!(valid_operator_cell.validate().is_ok());
    assert!(valid_operator_cell.is_operator_asserted());
    assert!(valid_operator_cell.is_irreversible_effect_premise(now));

    // Negative case 1: Missing evidence (unsigned / unanchored assertion) fails closed
    let mut no_evidence = valid_operator_cell.clone();
    no_evidence.evidence.clear();
    assert!(!no_evidence.is_irreversible_effect_premise(now));

    // Negative case 2: Tentative / Estimated assertion cannot authorize irreversible effect
    let mut estimated_cell = valid_operator_cell.clone();
    estimated_cell.knowledge_state = KnowledgeState::Estimated;
    assert!(!estimated_cell.is_irreversible_effect_premise(now));

    // Negative case 3: Expired operator lease / override cannot authorize effect
    let mut expired_cell = valid_operator_cell.clone();
    expired_cell.valid_until = Some(TimestampNs(500_000_000));
    assert!(!expired_cell.is_irreversible_effect_premise(now));

    // Negative case 4: Contradictions present invalidate authorization
    let mut conflicted_cell = valid_operator_cell.clone();
    conflicted_cell
        .contradictions
        .push(ContentDigest::sha256(b"contradicting_occupancy_signal"));
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
    let operator_assertion = KnowledgeCell {
        claim_id: "claim:safety:zone_b:clearance".to_string(),
        statement: "Operator asserts Zone B is clear of all personnel".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::OperatorAsserted,
        hypothesis: None,
        evidence: vec![operator_claim_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(1_500_000_000)),
        state_basis: None,
    };

    assert!(operator_assertion.validate().is_ok());
    assert!(operator_assertion.is_operator_asserted());
    assert!(operator_assertion.is_irreversible_effect_premise(now));

    // 2. Later corroboration / contradiction status:
    // Physical radar detects personnel in the zone, producing a contradiction
    let mut contradicted_cell = operator_assertion.clone();
    contradicted_cell
        .contradictions
        .push(contradictory_sensor_digest);

    // Contradiction immediately revokes effect authorization (fail closed)
    assert!(!contradicted_cell.is_irreversible_effect_premise(now));

    // 3. Epistemic state transition to Conflicted
    let mut conflicted_cell = contradicted_cell.clone();
    conflicted_cell.knowledge_state = KnowledgeState::Conflicted;
    assert!(conflicted_cell.validate().is_ok());
    assert!(conflicted_cell.is_conflicted());
    assert!(conflicted_cell.is_operator_asserted());
    assert!(!conflicted_cell.is_irreversible_effect_premise(now));

    Ok(())
}

#[test]
fn test_operator_asserted_audit_identity_and_scope() -> Result<(), Box<dyn Error>> {
    let operator_cert = ContentDigest::sha256(b"x509_cert:operator:alice_wright:badge_9921");

    let cell = KnowledgeCell {
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
    };

    assert!(cell.validate().is_ok());
    let validated = cell.validated()?;
    assert!(validated.is_operator_asserted());
    assert_eq!(validated.provenance.id(), "PROV-005");
    assert_eq!(validated.provenance.as_str(), "operator_asserted");
    assert_eq!(format!("{}", validated.provenance), "operator_asserted");

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

    // Non-authorizing partition (AGT-LAYER-004)
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

    let from_str_id = ProvenanceClass::from_str("PROV-006")?;
    assert_eq!(from_str_id, ProvenanceClass::VendorClaimed);

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
        let cell = KnowledgeCell {
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
        };

        assert!(
            cell.validate().is_ok(),
            "Validation failed for vendor_claimed cell in state {}",
            state.as_str()
        );

        // Provenance remains VendorClaimed regardless of epistemic state
        assert_eq!(cell.provenance, ProvenanceClass::VendorClaimed);
        assert!(cell.is_vendor_claimed());
        assert_eq!(cell.provenance.id(), "PROV-006");
        assert_eq!(cell.provenance.as_str(), "vendor_claimed");

        // Epistemic state and provenance are strictly distinct
        assert_ne!(cell.provenance.as_str(), state.as_str());
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
    let vendor_known_cell = KnowledgeCell {
        claim_id: "claim:vendor:door_lock_status".to_string(),
        statement: "Vendor cloud API reports front entry lock bolt is fully extended".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::VendorClaimed,
        hypothesis: None,
        evidence: vec![vendor_event_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };

    assert!(vendor_known_cell.validate().is_ok());
    assert!(vendor_known_cell.is_vendor_claimed());
    assert_eq!(vendor_known_cell.knowledge_state, KnowledgeState::Known);

    // Irreversible effect premise MUST evaluate to false (fail closed)
    assert!(
        !vendor_known_cell.is_irreversible_effect_premise(now),
        "Vendor claimed state must NEVER authorize irreversible effects even when Known!"
    );

    // Contrast with Observed (authorizing) and Derived (non-authorizing per AGT-LAYER-004)
    let observed_cell = KnowledgeCell {
        provenance: ProvenanceClass::Observed,
        ..vendor_known_cell.clone()
    };
    assert!(observed_cell.is_irreversible_effect_premise(now));

    let derived_cell = KnowledgeCell {
        provenance: ProvenanceClass::Derived,
        ..vendor_known_cell
    };
    // Per AGT-LAYER-004 and INV-069, Derived belongs to Cognition and CANNOT authorize effects
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
    let vendor_cell = KnowledgeCell {
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
    };

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
    let vendor_claim = KnowledgeCell {
        claim_id: "claim:door:status:001".to_string(),
        statement: "Cloud vendor API states perimeter door is closed".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::VendorClaimed,
        hypothesis: None,
        evidence: vec![vendor_cloud_msg],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };

    // 2. Observed evidence: Direct physical sensor measurement with cryptographic custody
    let physical_observation = KnowledgeCell {
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
    };

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

    // VendorClaimed, Predicted, Remembered, and Derived are in the non-authorizing partition (AGT-LAYER-004)
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

fn evidence_less_cell(
    state: KnowledgeState,
    provenance: ProvenanceClass,
    contradictions: Vec<ContentDigest>,
) -> Result<KnowledgeCell, ContractError> {
    Ok(KnowledgeCell {
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
            let cell = evidence_less_cell(state, provenance, contradictions)?;
            assert_eq!(
                cell.validate(),
                Err(ContractError::EvidenceRequired),
                "{provenance} {state} without evidence must be refused"
            );
            let anchored = KnowledgeCell {
                evidence: vec![ContentDigest::sha256(b"asserting_cell_anchor")],
                ..cell
            };
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
            let cell = evidence_less_cell(state, provenance, vec![])?;
            assert_eq!(
                cell.validate(),
                Ok(()),
                "{provenance} {state} without evidence must stay valid"
            );
            assert_eq!(cell.knowledge_state, state);
            assert_eq!(cell.provenance, provenance);
            assert!(!cell.is_irreversible_effect_premise(now));
        }
    }

    // The physical cell for an event whose revision edges only contradict it: observed,
    // unknown, no supporting root, one contradicting root.
    let contradicted_unknown = evidence_less_cell(
        KnowledgeState::Unknown,
        ProvenanceClass::Observed,
        vec![contradiction],
    )?
    .validated()?;
    assert!(contradicted_unknown.is_unknown());
    assert!(contradicted_unknown.is_observed());
    assert!(contradicted_unknown.evidence.is_empty());
    assert!(!contradicted_unknown.is_irreversible_effect_premise(now));
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
    let mut cell = belief.to_knowledge_cell(&anchor)?;

    // Baseline: Estimated + Derived is NOT an irreversible effect premise
    assert_eq!(cell.knowledge_state, KnowledgeState::Estimated);
    assert_eq!(cell.provenance, ProvenanceClass::Derived);
    assert_eq!(cell.is_irreversible_effect_premise(now), false);

    // Planted bypass attempt: A caller mutates knowledge_state to Known
    // attempting to turn a derived belief into an irreversible-effect premise.
    cell.knowledge_state = KnowledgeState::Known;

    // Constitutional Hard Gate (AGT-LAYER-004, INV-069, PROV-002):
    // Derived beliefs belong strictly to the Cognition plane, never the Authority plane.
    // Even when relabelled to Known with valid evidence and no contradictions,
    // ProvenanceClass::Derived::may_authorize_irreversible_effect MUST return false,
    // and is_irreversible_effect_premise MUST return false.
    assert_eq!(cell.knowledge_state, KnowledgeState::Known);
    assert_eq!(cell.provenance, ProvenanceClass::Derived);
    assert_eq!(cell.provenance.may_authorize_irreversible_effect(), false);
    assert_eq!(
        cell.is_irreversible_effect_premise(now),
        false,
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
    let hand_crafted = KnowledgeCell {
        claim_id: "claim:perimeter:breach:forged".to_string(),
        statement: "Perimeter breach asserted as known from derivation".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };

    // The cell passes semantic validation (Derived allows Known when evidence is present),
    // BUT effect premise evaluation MUST fail closed.
    assert_eq!(hand_crafted.validate(), Ok(()));
    assert_eq!(hand_crafted.knowledge_state, KnowledgeState::Known);
    assert_eq!(hand_crafted.provenance, ProvenanceClass::Derived);
    assert_eq!(
        hand_crafted.provenance.may_authorize_irreversible_effect(),
        false
    );
    assert_eq!(
        hand_crafted.is_irreversible_effect_premise(now),
        false,
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
    assert_eq!(
        observed_cell
            .provenance()
            .may_authorize_irreversible_effect(),
        true
    );
    assert_eq!(observed_cell.is_irreversible_effect_premise(now), true);

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
    assert_eq!(
        derived_cell
            .provenance()
            .may_authorize_irreversible_effect(),
        false
    );
    assert_eq!(derived_cell.is_irreversible_effect_premise(now), false);

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
