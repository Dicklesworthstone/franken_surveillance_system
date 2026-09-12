#![forbid(unsafe_code)]
//! Integration and contract tests for KnowledgeState (fss-x4a.30.83.2 / KSTATE-002: estimated).
//!
//! Enforces:
//! - Exact normative identity, schema spelling, and meaning for KSTATE-002 (`estimated`)
//! - Hard constitutional gate: `Estimated` may support planning, but strictly CANNOT authorize irreversible effects
//! - Explicit assumptions are strictly required for `Estimated` propositions
//! - Canonical encoding and decoding round-trip determinism
//! - Rejection of malformed, unknown, or duplicate identities with registered typed errors
//! - KnowledgeCell boundary enforcement (never permits irreversible-effect premise from estimated evidence)

use std::error::Error;
use std::str::FromStr;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, KnowledgeCell, KnowledgeState, ProvenanceClass, TimestampNs,
};

#[test]
fn test_estimated_contract_row_properties() -> Result<(), Box<dyn Error>> {
    let state = KnowledgeState::Estimated;

    // 1. Exact normative stable ID
    assert_eq!(state.id(), "KSTATE-002");

    // 2. Exact normative schema spelling
    assert_eq!(state.as_str(), "estimated");
    assert_eq!(format!("{state}"), "estimated");

    // 3. Exact normative meaning
    assert_eq!(
        state.meaning(),
        "The proposition is supported by a declared derivation or model with explicit uncertainty and operating-envelope limits."
    );

    // 4. May support planning: yes
    assert!(state.may_support_planning());
    assert_eq!(state.planning_support_description(), "yes");

    // 5. May authorize irreversible effect: no (hard constitutional gate)
    assert!(!state.may_authorize_irreversible_effect());
    assert_eq!(state.irreversible_effect_description(), "no");

    // 6. Explicit assumptions required: yes
    assert!(state.explicit_assumptions_required());

    Ok(())
}

#[test]
fn test_estimated_parse_and_resolution() -> Result<(), Box<dyn Error>> {
    // Parse from stable ID
    let from_id = KnowledgeState::from_id("KSTATE-002")?;
    assert_eq!(from_id, KnowledgeState::Estimated);

    // Parse from schema name
    let from_name = KnowledgeState::from_name("estimated")?;
    assert_eq!(from_name, KnowledgeState::Estimated);

    // Parse via FromStr
    let from_str_name = KnowledgeState::from_str("estimated")?;
    assert_eq!(from_str_name, KnowledgeState::Estimated);

    let from_str_id = KnowledgeState::from_str("KSTATE-002")?;
    assert_eq!(from_str_id, KnowledgeState::Estimated);

    // Rejection of unknown / malformed identities
    assert_eq!(
        KnowledgeState::from_id("KSTATE-000"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        KnowledgeState::from_id("KSTATE-010"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        KnowledgeState::from_id(""),
        Err(ContractError::InvalidIdentifier)
    );

    assert_eq!(
        KnowledgeState::from_name("estimate"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        KnowledgeState::from_name("ESTIMATED"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        KnowledgeState::from_name(""),
        Err(ContractError::InvalidIdentifier)
    );

    Ok(())
}

#[test]
fn test_estimated_canonical_roundtrip() -> Result<(), Box<dyn Error>> {
    let state = KnowledgeState::Estimated;

    let mut encoder = CanonicalEncoder::new();
    state.encode_canonical(&mut encoder);
    let encoded_bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&encoded_bytes);
    let decoded = KnowledgeState::decode_canonical(&mut decoder)?;

    assert_eq!(decoded, state);
    assert_eq!(decoded.id(), "KSTATE-002");
    assert_eq!(decoded.as_str(), "estimated");

    Ok(())
}

#[test]
fn test_estimated_knowledge_cell_irreversible_effect_hard_gate() -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let evidence_digest = ContentDigest::sha256(b"admissible_sensor_evidence_anchor");

    // Construct a cell with KnowledgeState::Estimated
    let cell = KnowledgeCell {
        claim_id: "claim:motion:estimated:001".to_string(),
        statement: "Estimated vehicle motion trajectory within operating-envelope limits"
            .to_string(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
    };

    // Properties on KnowledgeCell
    assert!(cell.is_estimated());
    assert!(cell.requires_explicit_assumptions());
    assert!(cell.may_support_planning());

    // Constitutional Hard Gate: Estimated CANNOT be used as an irreversible-effect premise,
    // regardless of evidence presence, lack of contradictions, or unexpired validity.
    assert!(
        !cell.is_irreversible_effect_premise(now),
        "Estimated knowledge state must NEVER authorize irreversible effects"
    );

    // Contrast with Known state: Known DOES satisfy premise requirements when evidence is present
    let known_cell = KnowledgeCell {
        claim_id: "claim:motion:known:001".to_string(),
        statement: "Established physical presence".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
    };
    assert!(known_cell.is_irreversible_effect_premise(now));

    // Changing known_cell to Estimated immediately strips irreversible effect authorization
    let mut degraded_cell = known_cell;
    degraded_cell.knowledge_state = KnowledgeState::Estimated;
    assert!(!degraded_cell.is_irreversible_effect_premise(now));

    Ok(())
}

#[test]
fn test_all_knowledge_states_universe_consistency() -> Result<(), Box<dyn Error>> {
    let all_states = [
        (
            KnowledgeState::Known,
            "KSTATE-001",
            "known",
            true,
            true,
            false,
        ),
        (
            KnowledgeState::Estimated,
            "KSTATE-002",
            "estimated",
            true,
            false,
            true,
        ),
        (
            KnowledgeState::Unknown,
            "KSTATE-003",
            "unknown",
            true,
            false,
            true,
        ),
        (
            KnowledgeState::Conflicted,
            "KSTATE-004",
            "conflicted",
            true,
            false,
            true,
        ),
        (
            KnowledgeState::Stale,
            "KSTATE-005",
            "stale",
            true,
            false,
            true,
        ),
        (
            KnowledgeState::NotObservable,
            "KSTATE-006",
            "not_observable",
            true,
            false,
            true,
        ),
        (
            KnowledgeState::Redacted,
            "KSTATE-007",
            "redacted",
            true,
            false,
            true,
        ),
        (
            KnowledgeState::Indeterminate,
            "KSTATE-008",
            "indeterminate",
            true,
            false,
            true,
        ),
        (
            KnowledgeState::NotApplicable,
            "KSTATE-009",
            "not_applicable",
            false,
            false,
            false,
        ),
    ];

    for (state, expected_id, expected_name, can_plan, can_effect, req_assump) in all_states {
        assert_eq!(state.id(), expected_id);
        assert_eq!(state.as_str(), expected_name);
        assert_eq!(state.may_support_planning(), can_plan);
        assert_eq!(state.may_authorize_irreversible_effect(), can_effect);
        assert_eq!(state.explicit_assumptions_required(), req_assump);

        // Round-trip parse by ID and name
        assert_eq!(KnowledgeState::from_id(expected_id)?, state);
        assert_eq!(KnowledgeState::from_name(expected_name)?, state);
        assert_eq!(KnowledgeState::from_str(expected_id)?, state);
        assert_eq!(KnowledgeState::from_str(expected_name)?, state);
    }

    Ok(())
}
