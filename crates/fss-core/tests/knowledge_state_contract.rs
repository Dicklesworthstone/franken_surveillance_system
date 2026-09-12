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

#[test]
fn test_unknown_contract_row_properties() -> Result<(), Box<dyn Error>> {
    let state = KnowledgeState::Unknown;

    // 1. Exact normative stable ID
    assert_eq!(state.id(), "KSTATE-003");

    // 2. Exact normative schema spelling
    assert_eq!(state.as_str(), "unknown");
    assert_eq!(format!("{state}"), "unknown");

    // 3. Exact normative meaning
    assert_eq!(
        state.meaning(),
        "The authorized evidence acquired so far does not establish the proposition."
    );

    // 4. May support planning: yes, as an explicit branch or open variable
    assert!(state.may_support_planning());
    assert_eq!(
        state.planning_support_description(),
        "yes, as an explicit branch or open variable"
    );

    // 5. May authorize irreversible effect: no (hard constitutional gate)
    assert!(!state.may_authorize_irreversible_effect());
    assert_eq!(state.irreversible_effect_description(), "no");

    // 6. Explicit assumptions required: yes
    assert!(state.explicit_assumptions_required());

    Ok(())
}

#[test]
fn test_unknown_parse_and_resolution() -> Result<(), Box<dyn Error>> {
    // Parse from stable ID
    let from_id = KnowledgeState::from_id("KSTATE-003")?;
    assert_eq!(from_id, KnowledgeState::Unknown);

    // Parse from schema name
    let from_name = KnowledgeState::from_name("unknown")?;
    assert_eq!(from_name, KnowledgeState::Unknown);

    // Parse via FromStr
    let from_str_name = KnowledgeState::from_str("unknown")?;
    assert_eq!(from_str_name, KnowledgeState::Unknown);

    let from_str_id = KnowledgeState::from_str("KSTATE-003")?;
    assert_eq!(from_str_id, KnowledgeState::Unknown);

    Ok(())
}

#[test]
fn test_unknown_canonical_roundtrip() -> Result<(), Box<dyn Error>> {
    let state = KnowledgeState::Unknown;

    let mut encoder = CanonicalEncoder::new();
    state.encode_canonical(&mut encoder);
    let encoded_bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&encoded_bytes);
    let decoded = KnowledgeState::decode_canonical(&mut decoder)?;

    assert_eq!(decoded, state);
    assert_eq!(decoded.id(), "KSTATE-003");
    assert_eq!(decoded.as_str(), "unknown");

    Ok(())
}

#[test]
fn test_unknown_knowledge_cell_explicit_branch_and_hard_gate() -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let evidence_digest = ContentDigest::sha256(b"preliminary_or_inconclusive_sensor_evidence");

    // Construct a cell with KnowledgeState::Unknown
    let cell = KnowledgeCell {
        claim_id: "claim:target:presence:001".to_string(),
        statement: "Unconfirmed target presence in zone B".to_string(),
        knowledge_state: KnowledgeState::Unknown,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
    };

    // Properties on KnowledgeCell
    assert!(cell.is_unknown());
    assert!(!cell.is_estimated());
    assert!(cell.requires_explicit_assumptions());
    assert!(cell.may_support_planning());

    // Constitutional Hard Gate: Unknown CANNOT be used as an irreversible-effect premise,
    // regardless of evidence presence, unexpired validity, or lack of contradictions.
    assert!(
        !cell.is_irreversible_effect_premise(now),
        "Unknown knowledge state must NEVER authorize irreversible effects"
    );

    // Changing state to Known satisfies premise requirements
    let mut resolved_cell = cell;
    resolved_cell.knowledge_state = KnowledgeState::Known;
    assert!(resolved_cell.is_irreversible_effect_premise(now));

    Ok(())
}

#[test]
fn test_conflicted_contract_row_properties() -> Result<(), Box<dyn Error>> {
    let state = KnowledgeState::Conflicted;

    // 1. Exact normative stable ID
    assert_eq!(state.id(), "KSTATE-004");

    // 2. Exact normative schema spelling
    assert_eq!(state.as_str(), "conflicted");
    assert_eq!(format!("{state}"), "conflicted");

    // 3. Exact normative meaning
    assert_eq!(
        state.meaning(),
        "Material admissible evidence supports incompatible propositions or generations."
    );

    // 4. May support planning: yes, only as competing branches
    assert!(state.may_support_planning());
    assert_eq!(
        state.planning_support_description(),
        "yes, only as competing branches"
    );

    // 5. May authorize irreversible effect: no (hard constitutional gate)
    assert!(!state.may_authorize_irreversible_effect());
    assert_eq!(state.irreversible_effect_description(), "no");

    // 6. Explicit assumptions required: yes
    assert!(state.explicit_assumptions_required());

    Ok(())
}

#[test]
fn test_conflicted_parse_and_resolution() -> Result<(), Box<dyn Error>> {
    // Parse from stable ID
    let from_id = KnowledgeState::from_id("KSTATE-004")?;
    assert_eq!(from_id, KnowledgeState::Conflicted);

    // Parse from schema name
    let from_name = KnowledgeState::from_name("conflicted")?;
    assert_eq!(from_name, KnowledgeState::Conflicted);

    // Parse via FromStr
    let from_str_name = KnowledgeState::from_str("conflicted")?;
    assert_eq!(from_str_name, KnowledgeState::Conflicted);

    let from_str_id = KnowledgeState::from_str("KSTATE-004")?;
    assert_eq!(from_str_id, KnowledgeState::Conflicted);

    Ok(())
}

#[test]
fn test_conflicted_canonical_roundtrip() -> Result<(), Box<dyn Error>> {
    let state = KnowledgeState::Conflicted;

    let mut encoder = CanonicalEncoder::new();
    state.encode_canonical(&mut encoder);
    let encoded_bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&encoded_bytes);
    let decoded = KnowledgeState::decode_canonical(&mut decoder)?;

    assert_eq!(decoded, state);
    assert_eq!(decoded.id(), "KSTATE-004");
    assert_eq!(decoded.as_str(), "conflicted");

    Ok(())
}

#[test]
fn test_conflicted_knowledge_cell_competing_branches_and_hard_gate() -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let evidence_a = ContentDigest::sha256(b"camera_sensor_evidence_claims_car");
    let evidence_b = ContentDigest::sha256(b"radar_sensor_evidence_claims_truck");

    // Construct a cell with KnowledgeState::Conflicted
    let cell = KnowledgeCell {
        claim_id: "claim:vehicle:classification:001".to_string(),
        statement: "Conflicting classification between camera and radar models".to_string(),
        knowledge_state: KnowledgeState::Conflicted,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![evidence_a],
        contradictions: vec![evidence_b],
        valid_until: Some(TimestampNs(2_000_000_000)),
    };

    // Properties on KnowledgeCell
    assert!(cell.is_conflicted());
    assert!(!cell.is_unknown());
    assert!(!cell.is_estimated());
    assert!(cell.requires_explicit_assumptions());
    assert!(cell.may_support_planning());

    // Constitutional Hard Gate: Conflicted CANNOT be used as an irreversible-effect premise,
    // even if contradictory evidence list were cleared or validity is current.
    assert!(
        !cell.is_irreversible_effect_premise(now),
        "Conflicted knowledge state must NEVER authorize irreversible effects"
    );

    let mut without_contradictions = cell;
    without_contradictions.contradictions.clear();
    assert!(
        !without_contradictions.is_irreversible_effect_premise(now),
        "Conflicted state cannot authorize irreversible effect even if contradictions are empty"
    );

    Ok(())
}

#[test]
fn test_stale_contract_row_properties() -> Result<(), Box<dyn Error>> {
    let state = KnowledgeState::Stale;

    // 1. Exact normative stable ID
    assert_eq!(state.id(), "KSTATE-005");

    // 2. Exact normative schema spelling
    assert_eq!(state.as_str(), "stale");
    assert_eq!(format!("{state}"), "stale");

    // 3. Exact normative meaning
    assert_eq!(
        state.meaning(),
        "The proposition was valid only at an older anchor or generation and has not been revalidated."
    );

    // 4. May support planning: yes, only as a revalidation candidate
    assert!(state.may_support_planning());
    assert_eq!(
        state.planning_support_description(),
        "yes, only as a revalidation candidate"
    );

    // 5. May authorize irreversible effect: no (hard constitutional gate)
    assert!(!state.may_authorize_irreversible_effect());
    assert_eq!(state.irreversible_effect_description(), "no");

    // 6. Explicit assumptions required: yes
    assert!(state.explicit_assumptions_required());

    Ok(())
}

#[test]
fn test_stale_parse_and_resolution() -> Result<(), Box<dyn Error>> {
    // Parse from stable ID
    let from_id = KnowledgeState::from_id("KSTATE-005")?;
    assert_eq!(from_id, KnowledgeState::Stale);

    // Parse from schema name
    let from_name = KnowledgeState::from_name("stale")?;
    assert_eq!(from_name, KnowledgeState::Stale);

    // Parse via FromStr
    let from_str_name = KnowledgeState::from_str("stale")?;
    assert_eq!(from_str_name, KnowledgeState::Stale);

    let from_str_id = KnowledgeState::from_str("KSTATE-005")?;
    assert_eq!(from_str_id, KnowledgeState::Stale);

    Ok(())
}

#[test]
fn test_stale_canonical_roundtrip() -> Result<(), Box<dyn Error>> {
    let state = KnowledgeState::Stale;

    let mut encoder = CanonicalEncoder::new();
    state.encode_canonical(&mut encoder);
    let encoded_bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&encoded_bytes);
    let decoded = KnowledgeState::decode_canonical(&mut decoder)?;

    assert_eq!(decoded, state);
    assert_eq!(decoded.id(), "KSTATE-005");
    assert_eq!(decoded.as_str(), "stale");

    Ok(())
}

#[test]
fn test_stale_knowledge_cell_revalidation_and_hard_gate() -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(2_000_000_000);
    let evidence = ContentDigest::sha256(b"historical_perimeter_clear_assertion");

    // Construct a cell with KnowledgeState::Stale
    let cell = KnowledgeCell {
        claim_id: "claim:perimeter:clear:001".to_string(),
        statement: "Perimeter clear at older anchor timestamp".to_string(),
        knowledge_state: KnowledgeState::Stale,
        provenance: ProvenanceClass::Remembered,
        hypothesis: None,
        evidence: vec![evidence],
        contradictions: vec![],
        valid_until: Some(TimestampNs(1_500_000_000)), // expired
    };

    // Properties on KnowledgeCell
    assert!(cell.is_stale());
    assert!(!cell.is_conflicted());
    assert!(!cell.is_unknown());
    assert!(!cell.is_estimated());
    assert!(cell.requires_explicit_assumptions());
    assert!(cell.may_support_planning());

    // Constitutional Hard Gate: Stale CANNOT be used as an irreversible-effect premise.
    assert!(
        !cell.is_irreversible_effect_premise(now),
        "Stale knowledge state must NEVER authorize irreversible effects"
    );

    // Even if valid_until is artificially extended, Stale knowledge_state alone strictly denies effect premise
    let mut extended_cell = cell;
    extended_cell.valid_until = Some(TimestampNs(3_000_000_000));
    assert!(
        !extended_cell.is_irreversible_effect_premise(now),
        "Stale knowledge state must NEVER authorize irreversible effects even if valid_until is in future"
    );

    Ok(())
}

#[test]
fn test_not_observable_contract_row_properties() -> Result<(), Box<dyn Error>> {
    let state = KnowledgeState::NotObservable;

    // 1. Exact normative stable ID
    assert_eq!(state.id(), "KSTATE-006");

    // 2. Exact normative schema spelling
    assert_eq!(state.as_str(), "not_observable");
    assert_eq!(format!("{state}"), "not_observable");

    // 3. Exact normative meaning
    assert_eq!(
        state.meaning(),
        "The declared sensor/authorization/model domain could not have established the proposition for the requested interval."
    );

    // 4. May support planning: yes, as a protected residual possibility
    assert!(state.may_support_planning());
    assert_eq!(
        state.planning_support_description(),
        "yes, as a protected residual possibility"
    );

    // 5. May authorize irreversible effect: no (hard constitutional gate)
    assert!(!state.may_authorize_irreversible_effect());
    assert_eq!(state.irreversible_effect_description(), "no");

    // 6. Explicit assumptions required: yes
    assert!(state.explicit_assumptions_required());

    Ok(())
}

#[test]
fn test_not_observable_parse_and_resolution() -> Result<(), Box<dyn Error>> {
    // Parse from stable ID
    let from_id = KnowledgeState::from_id("KSTATE-006")?;
    assert_eq!(from_id, KnowledgeState::NotObservable);

    // Parse from schema name
    let from_name = KnowledgeState::from_name("not_observable")?;
    assert_eq!(from_name, KnowledgeState::NotObservable);

    // Parse via FromStr
    let from_str_name = KnowledgeState::from_str("not_observable")?;
    assert_eq!(from_str_name, KnowledgeState::NotObservable);

    let from_str_id = KnowledgeState::from_str("KSTATE-006")?;
    assert_eq!(from_str_id, KnowledgeState::NotObservable);

    Ok(())
}

#[test]
fn test_not_observable_canonical_roundtrip() -> Result<(), Box<dyn Error>> {
    let state = KnowledgeState::NotObservable;

    let mut encoder = CanonicalEncoder::new();
    state.encode_canonical(&mut encoder);
    let encoded_bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&encoded_bytes);
    let decoded = KnowledgeState::decode_canonical(&mut decoder)?;

    assert_eq!(decoded, state);
    assert_eq!(decoded.id(), "KSTATE-006");
    assert_eq!(decoded.as_str(), "not_observable");

    Ok(())
}

#[test]
fn test_not_observable_knowledge_cell_protected_possibility_and_hard_gate()
-> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);

    // Construct a cell with KnowledgeState::NotObservable (e.g. sensor occluded or unpowered during interval)
    let cell = KnowledgeCell {
        claim_id: "claim:corridor:motion:001".to_string(),
        statement: "Corridor unobserved due to sensor occlusion during requested interval"
            .to_string(),
        knowledge_state: KnowledgeState::NotObservable,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
    };

    // Properties on KnowledgeCell
    assert!(cell.is_not_observable());
    assert!(!cell.is_stale());
    assert!(!cell.is_conflicted());
    assert!(!cell.is_unknown());
    assert!(!cell.is_estimated());
    assert!(cell.requires_explicit_assumptions());
    assert!(cell.may_support_planning());

    // Constitutional Hard Gate: NotObservable CANNOT be used as an irreversible-effect premise.
    assert!(
        !cell.is_irreversible_effect_premise(now),
        "NotObservable knowledge state must NEVER authorize irreversible effects"
    );

    Ok(())
}

#[test]
fn test_redacted_contract_row_properties() -> Result<(), Box<dyn Error>> {
    let state = KnowledgeState::Redacted;

    // 1. Exact normative stable ID
    assert_eq!(state.id(), "KSTATE-007");

    // 2. Exact normative schema spelling
    assert_eq!(state.as_str(), "redacted");
    assert_eq!(format!("{state}"), "redacted");

    // 3. Exact normative meaning
    assert_eq!(
        state.meaning(),
        "The proposition or its evidence exists but is intentionally withheld by the current privacy/capability projection."
    );

    // 4. May support planning: yes, only through non-leaking abstract constraints
    assert!(state.may_support_planning());
    assert_eq!(
        state.planning_support_description(),
        "yes, only through non-leaking abstract constraints"
    );

    // 5. May authorize irreversible effect: no (hard constitutional gate)
    assert!(!state.may_authorize_irreversible_effect());
    assert_eq!(state.irreversible_effect_description(), "no");

    // 6. Explicit assumptions required: yes
    assert!(state.explicit_assumptions_required());

    Ok(())
}

#[test]
fn test_redacted_parse_and_resolution() -> Result<(), Box<dyn Error>> {
    // Parse from stable ID
    let from_id = KnowledgeState::from_id("KSTATE-007")?;
    assert_eq!(from_id, KnowledgeState::Redacted);

    // Parse from schema name
    let from_name = KnowledgeState::from_name("redacted")?;
    assert_eq!(from_name, KnowledgeState::Redacted);

    // Parse via FromStr
    let from_str_name = KnowledgeState::from_str("redacted")?;
    assert_eq!(from_str_name, KnowledgeState::Redacted);

    let from_str_id = KnowledgeState::from_str("KSTATE-007")?;
    assert_eq!(from_str_id, KnowledgeState::Redacted);

    Ok(())
}

#[test]
fn test_redacted_canonical_roundtrip() -> Result<(), Box<dyn Error>> {
    let state = KnowledgeState::Redacted;

    let mut encoder = CanonicalEncoder::new();
    state.encode_canonical(&mut encoder);
    let encoded_bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&encoded_bytes);
    let decoded = KnowledgeState::decode_canonical(&mut decoder)?;

    assert_eq!(decoded, state);
    assert_eq!(decoded.id(), "KSTATE-007");
    assert_eq!(decoded.as_str(), "redacted");

    Ok(())
}

#[test]
fn test_redacted_knowledge_cell_abstract_constraints_and_hard_gate() -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let redacted_witness = ContentDigest::sha256(b"redacted_evidence_mask");

    // Construct a cell with KnowledgeState::Redacted
    let cell = KnowledgeCell {
        claim_id: "claim:resident:identity:001".to_string(),
        statement: "[REDACTED under privacy tier T2]".to_string(),
        knowledge_state: KnowledgeState::Redacted,
        provenance: ProvenanceClass::Policy,
        hypothesis: None,
        evidence: vec![redacted_witness],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
    };

    // Properties on KnowledgeCell
    assert!(cell.is_redacted());
    assert!(!cell.is_not_observable());
    assert!(!cell.is_stale());
    assert!(!cell.is_conflicted());
    assert!(!cell.is_unknown());
    assert!(!cell.is_estimated());
    assert!(cell.requires_explicit_assumptions());
    assert!(cell.may_support_planning());

    // Constitutional Hard Gate: Redacted CANNOT be used as an irreversible-effect premise,
    // even if evidence handle is present.
    assert!(
        !cell.is_irreversible_effect_premise(now),
        "Redacted knowledge state must NEVER authorize irreversible effects"
    );

    Ok(())
}

#[test]
fn test_indeterminate_contract_row_properties() -> Result<(), Box<dyn Error>> {
    let state = KnowledgeState::Indeterminate;

    // 1. Exact normative stable ID
    assert_eq!(state.id(), "KSTATE-008");

    // 2. Exact normative schema spelling
    assert_eq!(state.as_str(), "indeterminate");
    assert_eq!(format!("{state}"), "indeterminate");

    // 3. Exact normative meaning
    assert_eq!(
        state.meaning(),
        "A consequential external outcome may have occurred but is not yet proved or safely negated."
    );

    // 4. May support planning: yes, only in reconciliation branches
    assert!(state.may_support_planning());
    assert_eq!(
        state.planning_support_description(),
        "yes, only in reconciliation branches"
    );

    // 5. May authorize irreversible effect: no (hard constitutional gate)
    assert!(!state.may_authorize_irreversible_effect());
    assert_eq!(state.irreversible_effect_description(), "no");

    // 6. Explicit assumptions required: yes
    assert!(state.explicit_assumptions_required());

    Ok(())
}

#[test]
fn test_indeterminate_parse_and_resolution() -> Result<(), Box<dyn Error>> {
    // Parse from stable ID
    let from_id = KnowledgeState::from_id("KSTATE-008")?;
    assert_eq!(from_id, KnowledgeState::Indeterminate);

    // Parse from schema name
    let from_name = KnowledgeState::from_name("indeterminate")?;
    assert_eq!(from_name, KnowledgeState::Indeterminate);

    // Parse via FromStr
    let from_str_name = KnowledgeState::from_str("indeterminate")?;
    assert_eq!(from_str_name, KnowledgeState::Indeterminate);

    let from_str_id = KnowledgeState::from_str("KSTATE-008")?;
    assert_eq!(from_str_id, KnowledgeState::Indeterminate);

    Ok(())
}

#[test]
fn test_indeterminate_canonical_roundtrip() -> Result<(), Box<dyn Error>> {
    let state = KnowledgeState::Indeterminate;

    let mut encoder = CanonicalEncoder::new();
    state.encode_canonical(&mut encoder);
    let encoded_bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&encoded_bytes);
    let decoded = KnowledgeState::decode_canonical(&mut decoder)?;

    assert_eq!(decoded, state);
    assert_eq!(decoded.id(), "KSTATE-008");
    assert_eq!(decoded.as_str(), "indeterminate");

    Ok(())
}

#[test]
fn test_indeterminate_knowledge_cell_reconciliation_and_hard_gate() -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let ambiguous_receipt = ContentDigest::sha256(b"inconclusive_actuator_acknowledgement");

    // Construct a cell with KnowledgeState::Indeterminate
    let cell = KnowledgeCell {
        claim_id: "claim:gate:lock:001".to_string(),
        statement: "Gate lock command sent but physical latch closure unverified due to timeout"
            .to_string(),
        knowledge_state: KnowledgeState::Indeterminate,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![ambiguous_receipt],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
    };

    // Properties on KnowledgeCell
    assert!(cell.is_indeterminate());
    assert!(!cell.is_redacted());
    assert!(!cell.is_not_observable());
    assert!(!cell.is_stale());
    assert!(!cell.is_conflicted());
    assert!(!cell.is_unknown());
    assert!(!cell.is_estimated());
    assert!(cell.requires_explicit_assumptions());
    assert!(cell.may_support_planning());

    // Constitutional Hard Gate: Indeterminate CANNOT be used as an irreversible-effect premise.
    assert!(
        !cell.is_irreversible_effect_premise(now),
        "Indeterminate knowledge state must NEVER authorize irreversible effects"
    );

    Ok(())
}
