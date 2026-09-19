#![forbid(unsafe_code)]
//! Integration and contract tests for the KnowledgeState universe (KSTATE-001 .. KSTATE-009)
//! and the KnowledgeCell gates built on it (fss-x4a.30.83.*).
//!
//! Enforces:
//! - Exact normative identity, schema spelling, meaning, planning rule, effect rule, and
//!   assumption rule for every row of `registries/AGENT_CONTRACTS.md`
//! - Hard constitutional gate: only `known` may be an irreversible-effect premise; every other
//!   state is refused even with evidence, no contradictions, and unexpired validity
//! - Typed state bases: a state whose registry meaning names a basis is refused without it,
//!   and a basis attached to a different state is refused
//! - Privacy: a `redacted` cell never exposes its statement through `Debug` or its digest
//! - Each `is_*` predicate matches exactly one of the nine states
//! - Canonical encoding and decoding round-trip determinism
//! - Rejection of malformed or unknown identities with registered typed errors

use std::error::Error;
use std::str::FromStr;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, Generation, KnowledgeCell, KnowledgeCellParams, KnowledgeState,
    KnowledgeStateBasis, LedgerAnchor, PrivacyGeneration, ProvenanceClass,
    REDACTED_STATEMENT_MARKER, ReconciliationBasis, ReconciliationBranch, RedactionMarker,
    RedactionReason, StaleBasis, TimestampNs,
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
    let cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:motion:estimated:001".to_string(),
        statement: "Estimated vehicle motion trajectory within operating-envelope limits"
            .to_string(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;

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
    let known_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:motion:known:001".to_string(),
        statement: "Established physical presence".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;
    assert!(known_cell.is_irreversible_effect_premise(now));

    // Changing known_cell to Estimated immediately strips irreversible effect authorization
    let degraded_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: known_cell.claim_id().to_owned(),
        statement: known_cell.statement().to_owned(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: known_cell.provenance(),
        hypothesis: known_cell.hypothesis(),
        evidence: known_cell.evidence_digests(),
        contradictions: known_cell.contradictions().to_vec(),
        valid_until: known_cell.valid_until(),
        state_basis: known_cell.state_basis().cloned(),
    })?;
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
    let cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:target:presence:001".to_string(),
        statement: "Unconfirmed target presence in zone B".to_string(),
        knowledge_state: KnowledgeState::Unknown,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![evidence_digest],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;

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
    let resolved_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: cell.claim_id().to_owned(),
        statement: cell.statement().to_owned(),
        knowledge_state: KnowledgeState::Known,
        provenance: cell.provenance(),
        hypothesis: cell.hypothesis(),
        evidence: cell.evidence_digests(),
        contradictions: cell.contradictions().to_vec(),
        valid_until: cell.valid_until(),
        state_basis: cell.state_basis().cloned(),
    })?;
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
    let cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:vehicle:classification:001".to_string(),
        statement: "Conflicting classification between camera and radar models".to_string(),
        knowledge_state: KnowledgeState::Conflicted,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![evidence_a],
        contradictions: vec![evidence_b],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;

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

    let without_contradictions = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:test:conflicted:no-contra".to_string(),
        statement: "Conflicted state without contradictions".to_string(),
        knowledge_state: KnowledgeState::Conflicted,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![evidence_a],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;
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

    // Evidence present, no contradictions, and validity NOT expired; the stale state (and the
    // remembered provenance) refuse the premise.
    let cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:perimeter:clear:001".to_string(),
        statement: "Perimeter clear at older anchor".to_string(),
        knowledge_state: KnowledgeState::Stale,
        provenance: ProvenanceClass::Remembered,
        hypothesis: None,
        evidence: vec![evidence],
        contradictions: vec![],
        valid_until: Some(TimestampNs(3_000_000_000)),
        state_basis: Some(KnowledgeStateBasis::Stale(older_anchor_basis())),
    })?;

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

    // Relabeling the remembered cell as Known (basis dropped, same evidence) is laundering, not
    // revalidation: remembered provenance (PROV-004) never authorizes an irreversible effect.
    let naive_relabel = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: cell.claim_id().to_owned(),
        statement: cell.statement().to_owned(),
        knowledge_state: KnowledgeState::Known,
        provenance: cell.provenance(),
        hypothesis: cell.hypothesis(),
        evidence: cell.evidence_digests(),
        contradictions: cell.contradictions().to_vec(),
        valid_until: cell.valid_until(),
        state_basis: None,
    })?;
    assert!(!naive_relabel.is_irreversible_effect_premise(now));

    // Revalidation is a fresh observation at the current anchor: observed provenance, new live
    // evidence distinct from the remembered evidence, no stale basis, and an open validity window.
    let revalidated = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: cell.claim_id().to_owned(),
        statement: "Perimeter clear at current anchor".to_string(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Observed,
        hypothesis: cell.hypothesis(),
        evidence: vec![ContentDigest::sha256(
            b"live_perimeter_clear_capture_at_current_anchor",
        )],
        contradictions: cell.contradictions().to_vec(),
        valid_until: cell.valid_until(),
        state_basis: None,
    })?;
    assert!(revalidated.is_irreversible_effect_premise(now));

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
    let coverage_gap_witness = ContentDigest::sha256(b"corridor_sensor_occlusion_coverage_witness");

    // Non-empty evidence (the coverage witness bounding observability), no contradictions,
    // and unexpired validity, so only the knowledge state can refuse the premise.
    let cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:corridor:motion:001".to_string(),
        statement: "Corridor unobserved due to sensor occlusion during requested interval"
            .to_string(),
        knowledge_state: KnowledgeState::NotObservable,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![coverage_gap_witness],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    })?;

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

    // The identical fixture relabelled Known is a premise, so the refusal above came from the
    // knowledge state alone rather than from missing evidence or expired validity.
    let observed = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: cell.claim_id().to_owned(),
        statement: cell.statement().to_owned(),
        knowledge_state: KnowledgeState::Known,
        provenance: cell.provenance(),
        hypothesis: cell.hypothesis(),
        evidence: cell.evidence_digests(),
        contradictions: cell.contradictions().to_vec(),
        valid_until: cell.valid_until(),
        state_basis: None,
    })?;
    assert!(observed.is_irreversible_effect_premise(now));

    Ok(())
}

#[test]
fn test_not_observable_is_distinct_from_unknown() -> Result<(), Box<dyn Error>> {
    let not_observable = KnowledgeState::NotObservable;
    let unknown = KnowledgeState::Unknown;

    // Distinct registry rows.
    assert_ne!(not_observable, unknown);
    assert_ne!(not_observable.id(), unknown.id());
    assert_ne!(not_observable.as_str(), unknown.as_str());
    assert_ne!(not_observable.meaning(), unknown.meaning());
    assert_eq!(
        not_observable.planning_support_description(),
        "yes, as a protected residual possibility"
    );
    assert_eq!(
        unknown.planning_support_description(),
        "yes, as an explicit branch or open variable"
    );
    assert_eq!(KnowledgeState::from_name("not_observable")?, not_observable);
    assert_eq!(KnowledgeState::from_id("KSTATE-006")?, not_observable);

    // Distinct canonical encodings; each decodes back to itself only.
    let encode = |state: KnowledgeState| {
        let mut encoder = CanonicalEncoder::new();
        state.encode_canonical(&mut encoder);
        encoder.finish()
    };
    let not_observable_bytes = encode(not_observable);
    let unknown_bytes = encode(unknown);
    assert_ne!(not_observable_bytes, unknown_bytes);
    assert_eq!(
        KnowledgeState::decode_canonical(&mut CanonicalDecoder::new(&not_observable_bytes))?,
        not_observable
    );
    assert_eq!(
        KnowledgeState::decode_canonical(&mut CanonicalDecoder::new(&unknown_bytes))?,
        unknown
    );

    // The same claim in each state: disjoint predicates and distinct digests.
    let not_observable_cell = gate_isolating_cell(not_observable)?;
    let unknown_cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: not_observable_cell.claim_id().to_owned(),
        statement: not_observable_cell.statement().to_owned(),
        knowledge_state: unknown,
        provenance: not_observable_cell.provenance(),
        hypothesis: not_observable_cell.hypothesis(),
        evidence: not_observable_cell.evidence_digests(),
        contradictions: not_observable_cell.contradictions().to_vec(),
        valid_until: not_observable_cell.valid_until(),
        state_basis: None,
    })?;
    assert!(not_observable_cell.is_not_observable());
    assert!(!not_observable_cell.is_unknown());
    assert!(unknown_cell.is_unknown());
    assert!(!unknown_cell.is_not_observable());
    assert_ne!(
        not_observable_cell.cell_digest(),
        unknown_cell.cell_digest()
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
    let cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:resident:identity:001".to_string(),
        statement: "[REDACTED under privacy tier T2]".to_string(),
        knowledge_state: KnowledgeState::Redacted,
        provenance: ProvenanceClass::Policy,
        hypothesis: None,
        evidence: vec![redacted_witness],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: Some(KnowledgeStateBasis::Redaction(redaction_marker()?)),
    })?;

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

    // Evidence present, no contradictions, unexpired validity, and a typed reconciliation
    // basis naming the unresolved attempt with both outcome branches open.
    let cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:gate:lock:001".to_string(),
        statement: "Gate lock command sent but physical latch closure unverified due to timeout"
            .to_string(),
        knowledge_state: KnowledgeState::Indeterminate,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![ambiguous_receipt],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: Some(KnowledgeStateBasis::Reconciliation(
            ReconciliationBasis::occurred_or_not(ambiguous_receipt),
        )),
    })?;

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

    // Once reconciled to a proved outcome (Known, basis dropped) the same fixture is a
    // premise, so the refusal above came from the knowledge state alone.
    let reconciled = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: cell.claim_id().to_owned(),
        statement: cell.statement().to_owned(),
        knowledge_state: KnowledgeState::Known,
        provenance: cell.provenance(),
        hypothesis: cell.hypothesis(),
        evidence: cell.evidence_digests(),
        contradictions: cell.contradictions().to_vec(),
        valid_until: cell.valid_until(),
        state_basis: None,
    })?;
    assert!(reconciled.is_irreversible_effect_premise(now));

    Ok(())
}

#[test]
fn test_not_applicable_contract_row_properties() -> Result<(), Box<dyn Error>> {
    let state = KnowledgeState::NotApplicable;

    // 1. Exact normative stable ID
    assert_eq!(state.id(), "KSTATE-009");

    // 2. Exact normative schema spelling
    assert_eq!(state.as_str(), "not_applicable");
    assert_eq!(format!("{state}"), "not_applicable");

    // 3. Exact normative meaning
    assert_eq!(
        state.meaning(),
        "The proposition has no meaning for the named object, scope, or lifecycle state."
    );

    // 4. May support planning: no
    assert!(!state.may_support_planning());
    assert_eq!(state.planning_support_description(), "no");

    // 5. May authorize irreversible effect: no (hard constitutional gate)
    assert!(!state.may_authorize_irreversible_effect());
    assert_eq!(state.irreversible_effect_description(), "no");

    // 6. Explicit assumptions required: no
    assert!(!state.explicit_assumptions_required());

    Ok(())
}

#[test]
fn test_not_applicable_parse_and_resolution() -> Result<(), Box<dyn Error>> {
    // Parse from stable ID
    let from_id = KnowledgeState::from_id("KSTATE-009")?;
    assert_eq!(from_id, KnowledgeState::NotApplicable);

    // Parse from schema name
    let from_name = KnowledgeState::from_name("not_applicable")?;
    assert_eq!(from_name, KnowledgeState::NotApplicable);

    // Parse via FromStr
    let from_str_name = KnowledgeState::from_str("not_applicable")?;
    assert_eq!(from_str_name, KnowledgeState::NotApplicable);

    let from_str_id = KnowledgeState::from_str("KSTATE-009")?;
    assert_eq!(from_str_id, KnowledgeState::NotApplicable);

    Ok(())
}

#[test]
fn test_not_applicable_canonical_roundtrip() -> Result<(), Box<dyn Error>> {
    let state = KnowledgeState::NotApplicable;

    let mut encoder = CanonicalEncoder::new();
    state.encode_canonical(&mut encoder);
    let encoded_bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&encoded_bytes);
    let decoded = KnowledgeState::decode_canonical(&mut decoder)?;

    assert_eq!(decoded, state);
    assert_eq!(decoded.id(), "KSTATE-009");
    assert_eq!(decoded.as_str(), "not_applicable");

    Ok(())
}

#[test]
fn test_not_applicable_knowledge_cell_no_planning_and_hard_gate() -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let power_topology = ContentDigest::sha256(b"fixed_sensor_mains_power_topology_record");

    // Non-empty evidence, no contradictions, and no validity bound, so only the knowledge
    // state can refuse the premise (e.g. flight battery status on a mains-powered camera).
    let cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:camera:battery_temp:001".to_string(),
        statement: "Battery temperature proposition on mains-powered fixed sensor".to_string(),
        knowledge_state: KnowledgeState::NotApplicable,
        provenance: ProvenanceClass::Policy,
        hypothesis: None,
        evidence: vec![power_topology],
        contradictions: vec![],
        valid_until: None,
        state_basis: None,
    })?;

    // Properties on KnowledgeCell
    assert!(cell.is_not_applicable());
    assert!(!cell.is_indeterminate());
    assert!(!cell.is_redacted());
    assert!(!cell.is_not_observable());
    assert!(!cell.is_stale());
    assert!(!cell.is_conflicted());
    assert!(!cell.is_unknown());
    assert!(!cell.is_estimated());

    // Explicit assumptions: NOT required for not_applicable
    assert!(!cell.requires_explicit_assumptions());

    // Planning support: Strictly FALSE for NotApplicable (the only state with may_support_planning == false)
    assert!(!cell.may_support_planning());

    // Constitutional Hard Gate: NotApplicable CANNOT be used as an irreversible-effect premise.
    assert!(
        !cell.is_irreversible_effect_premise(now),
        "NotApplicable knowledge state must NEVER authorize irreversible effects"
    );

    // The identical fixture relabelled Known is a premise, so the refusal above came from the
    // knowledge state alone rather than from missing evidence.
    let applicable = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: cell.claim_id().to_owned(),
        statement: cell.statement().to_owned(),
        knowledge_state: KnowledgeState::Known,
        provenance: cell.provenance(),
        hypothesis: cell.hypothesis(),
        evidence: cell.evidence_digests(),
        contradictions: cell.contradictions().to_vec(),
        valid_until: cell.valid_until(),
        state_basis: None,
    })?;
    assert!(applicable.is_irreversible_effect_premise(now));

    Ok(())
}

/// Every knowledge state, in registry order.
const ALL_STATES: [KnowledgeState; 9] = [
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

/// A redaction marker naming the privacy projection that withholds a proposition.
fn redaction_marker() -> Result<RedactionMarker, ContractError> {
    Ok(RedactionMarker {
        reason: RedactionReason::PrivacyProjection,
        privacy_generation: PrivacyGeneration::parse("privacy:projection:v7")?,
    })
}

/// Returns the typed basis a valid cell in `state` must carry.
fn valid_basis_for(state: KnowledgeState) -> Result<Option<KnowledgeStateBasis>, ContractError> {
    Ok(match state {
        KnowledgeState::Redacted => Some(KnowledgeStateBasis::Redaction(redaction_marker()?)),
        KnowledgeState::Stale => Some(KnowledgeStateBasis::Stale(older_anchor_basis())),
        KnowledgeState::Indeterminate => Some(KnowledgeStateBasis::Reconciliation(
            ReconciliationBasis::occurred_or_not(ContentDigest::sha256(b"ambiguous_receipt")),
        )),
        _ => None,
    })
}

/// A valid cell with non-empty evidence, no contradictions, and unexpired validity, so the
/// knowledge state is the only field that can refuse the irreversible-effect premise.
fn gate_isolating_cell(state: KnowledgeState) -> Result<KnowledgeCell, ContractError> {
    KnowledgeCell::new(KnowledgeCellParams {
        claim_id: format!("claim:gate:{}", state.as_str()),
        statement: format!("Gate isolation fixture for {}", state.as_str()),
        knowledge_state: state,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![ContentDigest::sha256(b"admissible_gate_fixture_evidence")],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: valid_basis_for(state)?,
    })
}

/// A redacted cell whose withheld statement is `secret`.
fn redacted_cell(secret: &str, marker: RedactionMarker) -> Result<KnowledgeCell, ContractError> {
    KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:resident:presence:001".to_string(),
        statement: secret.to_string(),
        knowledge_state: KnowledgeState::Redacted,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![ContentDigest::sha256(b"redacted_presence_evidence")],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: Some(KnowledgeStateBasis::Redaction(marker)),
    })
}

#[test]
fn test_redacted_cell_debug_never_exposes_statement() -> Result<(), Box<dyn Error>> {
    let secret = "SECRET-alice-is-home";
    let cell = redacted_cell(secret, redaction_marker()?)?;

    let compact = format!("{cell:?}");
    let pretty = format!("{cell:#?}");
    assert!(!compact.contains(secret), "Debug leaked the statement");
    assert!(
        !pretty.contains(secret),
        "pretty Debug leaked the statement"
    );
    assert!(compact.contains(REDACTED_STATEMENT_MARKER));
    assert!(compact.contains("claim:resident:presence:001"));

    // Fail closed: a redacted cell that is itself invalid (no marker) is refused by constructor.
    let unmarked_params = KnowledgeCellParams {
        claim_id: "claim:resident:presence:001".to_string(),
        statement: secret.to_string(),
        knowledge_state: KnowledgeState::Redacted,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![ContentDigest::sha256(b"redacted_presence_evidence")],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };
    assert_eq!(
        KnowledgeCell::new(unmarked_params),
        Err(ContractError::RedactionMarkerRequired)
    );

    // Non-redacted cells keep their statement visible for diagnostics.
    let known = gate_isolating_cell(KnowledgeState::Known)?;
    assert!(format!("{known:?}").contains("Gate isolation fixture for known"));

    Ok(())
}

#[test]
fn test_redacted_cell_digest_is_not_a_statement_oracle() -> Result<(), Box<dyn Error>> {
    let alice = redacted_cell("SECRET-alice-is-home", redaction_marker()?)?.validated()?;
    let bob = redacted_cell("SECRET-bob-is-away", redaction_marker()?)?.validated()?;

    // Different withheld statements under the same marker hash identically.
    assert_eq!(alice.cell_digest(), bob.cell_digest());

    // The marker itself is bound into the digest.
    let capability_marker = RedactionMarker {
        reason: RedactionReason::CapabilityProjection,
        privacy_generation: PrivacyGeneration::parse("privacy:projection:v7")?,
    };
    let capability = redacted_cell("SECRET-alice-is-home", capability_marker)?.validated()?;
    assert_ne!(alice.cell_digest(), capability.cell_digest());

    // The same statement is still digest-distinct once it is no longer withheld.
    let disclosed = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: alice.claim_id().to_owned(),
        statement: alice.statement().to_owned(),
        knowledge_state: KnowledgeState::Known,
        provenance: alice.provenance(),
        hypothesis: alice.hypothesis(),
        evidence: alice.evidence_digests(),
        contradictions: alice.contradictions().to_vec(),
        valid_until: alice.valid_until(),
        state_basis: None,
    })?;
    let other_disclosed = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: bob.claim_id().to_owned(),
        statement: bob.statement().to_owned(),
        knowledge_state: KnowledgeState::Known,
        provenance: bob.provenance(),
        hypothesis: bob.hypothesis(),
        evidence: bob.evidence_digests(),
        contradictions: bob.contradictions().to_vec(),
        valid_until: bob.valid_until(),
        state_basis: None,
    })?;
    assert_ne!(disclosed.cell_digest(), other_disclosed.cell_digest());

    Ok(())
}

#[test]
fn test_redacted_cell_without_marker_is_refused() -> Result<(), Box<dyn Error>> {
    let unmarked_params = KnowledgeCellParams {
        claim_id: "claim:resident:presence:001".to_string(),
        statement: "SECRET-alice-is-home".to_string(),
        knowledge_state: KnowledgeState::Redacted,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![ContentDigest::sha256(b"redacted_presence_evidence")],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };

    assert_eq!(
        KnowledgeCell::new(unmarked_params),
        Err(ContractError::RedactionMarkerRequired)
    );
    assert_eq!(
        ContractError::RedactionMarkerRequired.code(),
        "redaction_marker_required"
    );

    Ok(())
}

#[test]
fn test_state_basis_on_a_different_state_is_refused() -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let cell = gate_isolating_cell(KnowledgeState::Known)?;
    assert!(cell.is_irreversible_effect_premise(now));

    // A Known cell carrying a redaction marker is incoherent and never a premise.
    let incoherent = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: cell.claim_id().to_owned(),
        statement: cell.statement().to_owned(),
        knowledge_state: cell.knowledge_state(),
        provenance: cell.provenance(),
        hypothesis: cell.hypothesis(),
        evidence: cell.evidence_digests(),
        contradictions: cell.contradictions().to_vec(),
        valid_until: cell.valid_until(),
        state_basis: Some(KnowledgeStateBasis::Redaction(redaction_marker()?)),
    });
    assert_eq!(incoherent, Err(ContractError::KnowledgeStateBasisMismatch));

    Ok(())
}

#[test]
fn test_every_is_predicate_across_all_knowledge_states() -> Result<(), Box<dyn Error>> {
    type Predicate = fn(&KnowledgeCell) -> bool;
    let predicates: [(&str, Predicate, KnowledgeState); 8] = [
        (
            "is_estimated",
            KnowledgeCell::is_estimated,
            KnowledgeState::Estimated,
        ),
        (
            "is_unknown",
            KnowledgeCell::is_unknown,
            KnowledgeState::Unknown,
        ),
        (
            "is_conflicted",
            KnowledgeCell::is_conflicted,
            KnowledgeState::Conflicted,
        ),
        ("is_stale", KnowledgeCell::is_stale, KnowledgeState::Stale),
        (
            "is_not_observable",
            KnowledgeCell::is_not_observable,
            KnowledgeState::NotObservable,
        ),
        (
            "is_redacted",
            KnowledgeCell::is_redacted,
            KnowledgeState::Redacted,
        ),
        (
            "is_indeterminate",
            KnowledgeCell::is_indeterminate,
            KnowledgeState::Indeterminate,
        ),
        (
            "is_not_applicable",
            KnowledgeCell::is_not_applicable,
            KnowledgeState::NotApplicable,
        ),
    ];

    // Collect every mismatch so a single run reports all widened or narrowed predicates.
    let mut mismatches = Vec::new();
    for state in ALL_STATES {
        let cell = gate_isolating_cell(state)?;
        for (name, predicate, owner) in predicates {
            let expected = state == owner;
            if predicate(&cell) != expected {
                mismatches.push(format!("{name}({}) != {expected}", state.as_str()));
            }
        }
    }
    assert_eq!(mismatches, Vec::<String>::new());

    Ok(())
}

#[test]
fn test_irreversible_effect_premise_across_all_knowledge_states() -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(1_000_000_000);
    let mut mismatches = Vec::new();
    for state in ALL_STATES {
        let cell = gate_isolating_cell(state)?;
        let expected = state == KnowledgeState::Known;
        if cell.is_irreversible_effect_premise(now) != expected {
            mismatches.push(format!("premise({}) != {expected}", state.as_str()));
        }
    }
    assert_eq!(mismatches, Vec::<String>::new());

    Ok(())
}

/// A ledger anchor on the test lineage at `commit_sequence`.
fn anchor_at(commit_sequence: u64) -> LedgerAnchor {
    let mut anchor = LedgerAnchor::genesis("site:knowledge-state");
    anchor.commit_sequence = commit_sequence;
    anchor
}

/// A stale basis naming an anchor strictly older than the current one.
fn older_anchor_basis() -> StaleBasis {
    StaleBasis::OlderAnchor {
        valid_at: Box::new(anchor_at(7)),
        current: Box::new(anchor_at(9)),
    }
}

/// A valid stale cell whose only premise blocker is its knowledge state.
fn stale_cell(basis: StaleBasis) -> Result<KnowledgeCell, ContractError> {
    KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:perimeter:clear:002".to_string(),
        statement: "Perimeter clear at an older anchor".to_string(),
        knowledge_state: KnowledgeState::Stale,
        provenance: ProvenanceClass::Remembered,
        hypothesis: None,
        evidence: vec![ContentDigest::sha256(
            b"historical_perimeter_clear_assertion",
        )],
        contradictions: vec![],
        valid_until: Some(TimestampNs(3_000_000_000)),
        state_basis: Some(KnowledgeStateBasis::Stale(basis)),
    })
}

#[test]
fn test_stale_cell_without_basis_is_refused() -> Result<(), Box<dyn Error>> {
    let params = KnowledgeCellParams {
        claim_id: "claim:perimeter:clear:002".to_string(),
        statement: "Perimeter clear at an older anchor".to_string(),
        knowledge_state: KnowledgeState::Stale,
        provenance: ProvenanceClass::Remembered,
        hypothesis: None,
        evidence: vec![ContentDigest::sha256(
            b"historical_perimeter_clear_assertion",
        )],
        contradictions: vec![],
        valid_until: Some(TimestampNs(3_000_000_000)),
        state_basis: None,
    };

    assert_eq!(
        KnowledgeCell::new(params),
        Err(ContractError::StaleBasisRequired)
    );
    assert_eq!(
        ContractError::StaleBasisRequired.code(),
        "stale_basis_required"
    );

    Ok(())
}

#[test]
fn test_stale_basis_must_name_a_strictly_older_anchor_or_generation() -> Result<(), Box<dyn Error>>
{
    // Accepted: strictly older anchor on the same lineage, strictly older generation.
    stale_cell(older_anchor_basis())?.validate()?;
    stale_cell(StaleBasis::OlderGeneration {
        valid_at: Generation::from_u64(3),
        current: Generation::from_u64(4),
    })?
    .validate()?;
    let mut older_epoch = anchor_at(50);
    older_epoch.ledger_epoch = 1;
    let mut newer_epoch = anchor_at(2);
    newer_epoch.ledger_epoch = 2;
    stale_cell(StaleBasis::OlderAnchor {
        valid_at: Box::new(older_epoch),
        current: Box::new(newer_epoch),
    })?
    .validate()?;

    // Refused: the "older" point is the current point, is newer, or is not comparable.
    let mut other_lineage = anchor_at(1);
    other_lineage.site_lineage = "site:other".to_string();
    let refused = [
        StaleBasis::OlderAnchor {
            valid_at: Box::new(anchor_at(9)),
            current: Box::new(anchor_at(9)),
        },
        StaleBasis::OlderAnchor {
            valid_at: Box::new(anchor_at(10)),
            current: Box::new(anchor_at(9)),
        },
        StaleBasis::OlderAnchor {
            valid_at: Box::new(other_lineage),
            current: Box::new(anchor_at(9)),
        },
        StaleBasis::OlderGeneration {
            valid_at: Generation::from_u64(4),
            current: Generation::from_u64(4),
        },
        StaleBasis::OlderGeneration {
            valid_at: Generation::from_u64(5),
            current: Generation::from_u64(4),
        },
    ];
    for basis in refused {
        let params = KnowledgeCellParams {
            claim_id: "claim:perimeter:clear:002".to_string(),
            statement: "Perimeter clear at an older anchor".to_string(),
            knowledge_state: KnowledgeState::Stale,
            provenance: ProvenanceClass::Remembered,
            hypothesis: None,
            evidence: vec![ContentDigest::sha256(
                b"historical_perimeter_clear_assertion",
            )],
            contradictions: vec![],
            valid_until: Some(TimestampNs(3_000_000_000)),
            state_basis: Some(KnowledgeStateBasis::Stale(basis)),
        };
        assert_eq!(
            KnowledgeCell::new(params),
            Err(ContractError::StaleBasisNotOlder)
        );
    }

    Ok(())
}

#[test]
fn test_stale_cell_cannot_pass_as_current() -> Result<(), Box<dyn Error>> {
    let now = TimestampNs(2_000_000_000);
    let stale = stale_cell(older_anchor_basis())?;
    assert!(!stale.is_irreversible_effect_premise(now));

    // Relabelling the state while keeping the stale basis does not launder it into a
    // current fact: the cell is refused and is never a premise.
    let relabelled_params = KnowledgeCellParams {
        claim_id: stale.claim_id().to_owned(),
        statement: stale.statement().to_owned(),
        knowledge_state: KnowledgeState::Known,
        provenance: stale.provenance(),
        hypothesis: stale.hypothesis(),
        evidence: stale.evidence_digests(),
        contradictions: stale.contradictions().to_vec(),
        valid_until: stale.valid_until(),
        state_basis: stale.state_basis().cloned(),
    };
    assert_eq!(
        KnowledgeCell::new(relabelled_params),
        Err(ContractError::KnowledgeStateBasisMismatch)
    );

    // The stale basis is bound into the digest, so a stale cell never shares a digest with
    // the current (revalidated) cell for the same claim.
    let revalidated = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: stale.claim_id().to_owned(),
        statement: stale.statement().to_owned(),
        knowledge_state: KnowledgeState::Known,
        provenance: stale.provenance(),
        hypothesis: stale.hypothesis(),
        evidence: stale.evidence_digests(),
        contradictions: stale.contradictions().to_vec(),
        valid_until: stale.valid_until(),
        state_basis: None,
    })?;
    assert_ne!(stale.cell_digest(), revalidated.cell_digest());

    Ok(())
}

/// A valid indeterminate cell for the unresolved attempt rooted at `root`.
fn indeterminate_cell(basis: ReconciliationBasis) -> Result<KnowledgeCell, ContractError> {
    KnowledgeCell::new(KnowledgeCellParams {
        claim_id: "claim:gate:lock:002".to_string(),
        statement: "Gate lock outcome awaits reconciliation".to_string(),
        knowledge_state: KnowledgeState::Indeterminate,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![ContentDigest::sha256(
            b"inconclusive_actuator_acknowledgement",
        )],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: Some(KnowledgeStateBasis::Reconciliation(basis)),
    })
}

#[test]
fn test_indeterminate_cell_without_reconciliation_basis_is_refused() -> Result<(), Box<dyn Error>> {
    let root = ContentDigest::sha256(b"attempt_receipt_root");
    let cell_valid = indeterminate_cell(ReconciliationBasis::occurred_or_not(root))?;
    cell_valid.validate()?;

    let params_without_basis = KnowledgeCellParams {
        claim_id: cell_valid.claim_id().to_owned(),
        statement: cell_valid.statement().to_owned(),
        knowledge_state: cell_valid.knowledge_state(),
        provenance: cell_valid.provenance(),
        hypothesis: cell_valid.hypothesis(),
        evidence: cell_valid.evidence_digests(),
        contradictions: cell_valid.contradictions().to_vec(),
        valid_until: cell_valid.valid_until(),
        state_basis: None,
    };
    assert_eq!(
        KnowledgeCell::new(params_without_basis),
        Err(ContractError::ReconciliationBasisRequired)
    );
    assert_eq!(
        ContractError::ReconciliationBasisRequired.code(),
        "reconciliation_basis_required"
    );

    // A reconciliation basis attached to a Known cell is incoherent and refused.
    let known = gate_isolating_cell(KnowledgeState::Known)?;
    let incoherent_params = KnowledgeCellParams {
        claim_id: known.claim_id().to_owned(),
        statement: known.statement().to_owned(),
        knowledge_state: known.knowledge_state(),
        provenance: known.provenance(),
        hypothesis: known.hypothesis(),
        evidence: known.evidence_digests(),
        contradictions: known.contradictions().to_vec(),
        valid_until: known.valid_until(),
        state_basis: Some(KnowledgeStateBasis::Reconciliation(
            ReconciliationBasis::occurred_or_not(root),
        )),
    };
    assert_eq!(
        KnowledgeCell::new(incoherent_params),
        Err(ContractError::KnowledgeStateBasisMismatch)
    );

    Ok(())
}

#[test]
fn test_reconciliation_basis_keeps_occurred_and_not_occurred_branches_open()
-> Result<(), Box<dyn Error>> {
    let root = ContentDigest::sha256(b"attempt_receipt_root");
    let with_branches = |branches: &[ReconciliationBranch]| ReconciliationBasis {
        unresolved_outcome_root: root,
        branches: branches.iter().copied().collect(),
    };

    // Accepted: both outcome branches open, optionally with a partial-outcome branch.
    indeterminate_cell(ReconciliationBasis::occurred_or_not(root))?.validate()?;
    indeterminate_cell(with_branches(&[
        ReconciliationBranch::Occurred,
        ReconciliationBranch::NotOccurred,
        ReconciliationBranch::PartiallyOccurred,
    ]))?
    .validate()?;

    // Refused: fewer than two branches, duplicate branches, or only one of occurred/not_occurred.
    for branches in [
        vec![],
        vec![ReconciliationBranch::Occurred],
        vec![ReconciliationBranch::NotOccurred],
        vec![ReconciliationBranch::PartiallyOccurred],
        vec![
            ReconciliationBranch::Occurred,
            ReconciliationBranch::PartiallyOccurred,
        ],
        vec![
            ReconciliationBranch::NotOccurred,
            ReconciliationBranch::PartiallyOccurred,
        ],
        vec![
            ReconciliationBranch::Occurred,
            ReconciliationBranch::Occurred,
        ],
    ] {
        let basis = with_branches(&branches);
        let params = KnowledgeCellParams {
            claim_id: "claim:gate:lock:002".to_string(),
            statement: "Gate lock outcome awaits reconciliation".to_string(),
            knowledge_state: KnowledgeState::Indeterminate,
            provenance: ProvenanceClass::Observed,
            hypothesis: None,
            evidence: vec![ContentDigest::sha256(
                b"inconclusive_actuator_acknowledgement",
            )],
            contradictions: vec![],
            valid_until: Some(TimestampNs(2_000_000_000)),
            state_basis: Some(KnowledgeStateBasis::Reconciliation(basis)),
        };
        assert_eq!(
            KnowledgeCell::new(params),
            Err(ContractError::ReconciliationBranchesIncomplete)
        );
    }

    // The unresolved attempt root is bound into the digest.
    let first = indeterminate_cell(ReconciliationBasis::occurred_or_not(root))?;
    let second = indeterminate_cell(ReconciliationBasis::occurred_or_not(ContentDigest::sha256(
        b"other_attempt_receipt_root",
    )))?;
    assert_ne!(first.cell_digest(), second.cell_digest());
    let third = indeterminate_cell(with_branches(&[
        ReconciliationBranch::Occurred,
        ReconciliationBranch::NotOccurred,
        ReconciliationBranch::PartiallyOccurred,
    ]))?;
    assert_ne!(first.cell_digest(), third.cell_digest());

    Ok(())
}

#[test]
fn test_redaction_basis_on_known_or_stale_cell_is_refused() -> Result<(), Box<dyn Error>> {
    let secret = "SECRET-misattached-redaction";
    for (knowledge_state, expected) in [
        (
            KnowledgeState::Known,
            ContractError::KnowledgeStateBasisMismatch,
        ),
        (KnowledgeState::Stale, ContractError::StaleBasisRequired),
    ] {
        let params = KnowledgeCellParams {
            claim_id: "claim:resident:presence:001".to_string(),
            statement: secret.to_string(),
            knowledge_state,
            provenance: ProvenanceClass::Observed,
            hypothesis: None,
            evidence: vec![ContentDigest::sha256(b"redacted_presence_evidence")],
            contradictions: vec![],
            valid_until: Some(TimestampNs(2_000_000_000)),
            state_basis: Some(KnowledgeStateBasis::Redaction(redaction_marker()?)),
        };

        // The combination is not a valid cell ...
        assert_eq!(KnowledgeCell::new(params), Err(expected));
    }
    Ok(())
}

/// Exact-set validation tests for every provenance x {Known with evidence, Known without evidence, Estimated without evidence}
/// per KSTATE-001 / bead fss-kdhh7.
///
/// KSTATE-001 defines known as "established by admissible evidence, with any proved terminal
/// postcondition bound as an evidence root", so Known requires non-empty evidence roots whatever
/// the provenance; admissibility is tracked by fss-gefi6.
/// Non-observed/derived claims without evidence must be Estimated (or Unknown), preserving their provenance.
#[test]
fn test_knowledge_cell_validation_exact_set_for_known_and_estimated() -> Result<(), Box<dyn Error>>
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
    let evidence_root = ContentDigest::sha256(b"admissible_evidence_root");

    for provenance in all_provenances {
        // 1. Known with evidence: valid across provenances, EXCEPT Predicted is refused per
        // AGENT_COGNITION_AND_CONTROL.md:610 (§8.2: predicted is "counterfactual or future
        // expectation, never current truth") and fss-x4a.30.83.12/PROV-003 (PredictedKnownForbidden).
        let known_ev_params = KnowledgeCellParams {
            claim_id: format!("claim:test:known_with_ev:{provenance:?}"),
            statement: "Proposition in Known state with evidence.".to_string(),
            knowledge_state: KnowledgeState::Known,
            provenance,
            hypothesis: None,
            evidence: vec![evidence_root],
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: None,
        };
        if provenance == ProvenanceClass::Predicted {
            assert_eq!(
                KnowledgeCell::new(known_ev_params),
                Err(ContractError::PredictedKnownForbidden)
            );
        } else {
            let known_with_evidence = KnowledgeCell::new(known_ev_params)?;
            assert_eq!(
                known_with_evidence.validate(),
                Ok(()),
                "Known with evidence must be valid for provenance {provenance:?}"
            );
            assert!(known_with_evidence.validated().is_ok());
        }

        // 2. Known without evidence: REFUSED with ContractError::EvidenceRequired across ALL 7 provenances!
        // Removing this rule would allow non-observed/derived provenances to validate, which violates KSTATE-001.
        let known_no_ev_params = KnowledgeCellParams {
            claim_id: format!("claim:test:known_no_ev:{provenance:?}"),
            statement: "Proposition in Known state without evidence.".to_string(),
            knowledge_state: KnowledgeState::Known,
            provenance,
            hypothesis: None,
            evidence: Vec::new(),
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: None,
        };
        let expected_known_no_ev = if provenance == ProvenanceClass::Predicted {
            ContractError::PredictedKnownForbidden
        } else {
            ContractError::EvidenceRequired
        };
        assert_eq!(
            KnowledgeCell::new(known_no_ev_params),
            Err(expected_known_no_ev),
            "Known without evidence must be refused for provenance {provenance:?}"
        );

        // 3. Estimated without evidence:
        // - Observed (PROV-001) and Derived (PROV-002) assert present support and require evidence -> Err(EvidenceRequired)
        // - Non-observed/derived (Predicted, Remembered, OperatorAsserted, VendorClaimed, Policy)
        //   without evidence are valid as Estimated, keeping their provenance orthogonal -> Ok(())
        let estimated_no_ev_params = KnowledgeCellParams {
            claim_id: format!("claim:test:estimated_no_ev:{provenance:?}"),
            statement: "Proposition in Estimated state without evidence.".to_string(),
            knowledge_state: KnowledgeState::Estimated,
            provenance,
            hypothesis: None,
            evidence: Vec::new(),
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: None,
        };
        let expected_estimated = match provenance {
            ProvenanceClass::Observed | ProvenanceClass::Derived => {
                Err(ContractError::EvidenceRequired)
            }
            ProvenanceClass::Predicted
            | ProvenanceClass::Remembered
            | ProvenanceClass::OperatorAsserted
            | ProvenanceClass::VendorClaimed
            | ProvenanceClass::Policy => Ok(()),
        };
        match expected_estimated {
            Ok(()) => {
                let cell = KnowledgeCell::new(estimated_no_ev_params)?;
                assert_eq!(cell.validate(), Ok(()));
                assert!(cell.validated().is_ok());
            }
            Err(err) => {
                assert_eq!(
                    KnowledgeCell::new(estimated_no_ev_params),
                    Err(err),
                    "Estimated without evidence mismatch for provenance {provenance:?}"
                );
            }
        }

        // 4. Estimated with evidence: valid across ALL 7 provenances.
        let estimated_with_evidence = KnowledgeCell::new(KnowledgeCellParams {
            claim_id: format!("claim:test:estimated_with_ev:{provenance:?}"),
            statement: "Proposition in Estimated state with evidence.".to_string(),
            knowledge_state: KnowledgeState::Estimated,
            provenance,
            hypothesis: None,
            evidence: vec![evidence_root],
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: None,
        })?;
        assert_eq!(
            estimated_with_evidence.validate(),
            Ok(()),
            "Estimated with evidence must be valid for provenance {provenance:?}"
        );

        // 5. Unknown without evidence: valid across ALL 7 provenances (an honest unknown never needs evidence).
        let unknown_without_evidence = KnowledgeCell::new(KnowledgeCellParams {
            claim_id: format!("claim:test:unknown_no_ev:{provenance:?}"),
            statement: "Proposition in Unknown state without evidence.".to_string(),
            knowledge_state: KnowledgeState::Unknown,
            provenance,
            hypothesis: None,
            evidence: Vec::new(),
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: None,
        })?;
        assert_eq!(
            unknown_without_evidence.validate(),
            Ok(()),
            "Unknown without evidence must be valid for provenance {provenance:?}"
        );
    }

    Ok(())
}

/// Returns the text of the `"meaning"` field in the one flat row whose `"id"` is `id`.
fn json_registry_meaning<'a>(registry: &'a str, id: &str) -> Result<&'a str, Box<dyn Error>> {
    let id_key = format!("\"id\": \"{id}\"");
    if registry.matches(id_key.as_str()).count() != 1 {
        return Err(format!("{id} must name exactly one registry row").into());
    }
    let row_start = registry
        .find(id_key.as_str())
        .ok_or("missing registry row")?;
    let row = &registry[row_start..];
    let row = &row[..row.find('}').ok_or("unterminated registry row")?];
    let key = "\"meaning\": \"";
    let start = row.find(key).ok_or("registry row lacks a meaning")? + key.len();
    let len = row[start..].find('"').ok_or("unterminated meaning")?;
    Ok(&row[start..start + len])
}

/// Returns the Meaning cell of the `registries/AGENT_CONTRACTS.md` table row for `id`.
fn markdown_registry_meaning<'a>(registry: &'a str, id: &str) -> Result<&'a str, Box<dyn Error>> {
    let prefix = format!("| `{id}` |");
    let mut rows = registry
        .lines()
        .filter(|line| line.starts_with(prefix.as_str()));
    let row = rows.next().ok_or("missing Markdown registry row")?;
    if rows.next().is_some() {
        return Err(format!("{id} must name exactly one Markdown registry row").into());
    }
    let meaning = row
        .split(" | ")
        .nth(2)
        .ok_or("Markdown row lacks a meaning cell")?;
    Ok(meaning)
}

/// `KnowledgeState::meaning()` claims to return the exact registry text, so every copy of each
/// knowledge-state meaning must equal it byte for byte: the frozen registry, the umbrella agent
/// contract, the machine-readable operating model and the human registry (fss-kdhh7). No checker
/// compared these copies, which is how KSTATE-001 kept the evidence-free "or a proved terminal
/// postcondition" wording in some of them after the registry was reconciled.
#[test]
fn knowledge_state_meaning_equals_every_registry_row_text() -> Result<(), Box<dyn Error>> {
    let json_registries = [
        (
            "architecture/knowledge_states.json",
            include_str!("../../../architecture/knowledge_states.json"),
        ),
        (
            "architecture/agent_contracts.json",
            include_str!("../../../architecture/agent_contracts.json"),
        ),
        (
            "architecture/agent_operating_model.json",
            include_str!("../../../architecture/agent_operating_model.json"),
        ),
    ];
    let markdown = include_str!("../../../registries/AGENT_CONTRACTS.md");
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
    for state in states {
        for (path, registry) in json_registries {
            assert_eq!(
                state.meaning(),
                json_registry_meaning(registry, state.id())?,
                "{} meaning differs from {path}",
                state.id()
            );
        }
        assert_eq!(
            state.meaning(),
            markdown_registry_meaning(markdown, state.id())?,
            "{} meaning differs from registries/AGENT_CONTRACTS.md",
            state.id()
        );
    }
    assert_eq!(
        KnowledgeState::Known.meaning(),
        "The proposition is established for the named anchor and validity scope by admissible evidence, with any proved terminal postcondition bound as an evidence root."
    );
    Ok(())
}
