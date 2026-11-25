#![forbid(unsafe_code)]
//! Contract, golden, immutability/supersession, and hostile-input tests for
//! `SCHEMA-AGENT-WORKSPACE-001` (`fss.agent_session_capsule.v1`, `fss-x4a.30.31`).

use fss_core::{
    AgentContractCodecError, BudgetVector, ContentDigest, ContractBasis, ContractError,
    LedgerAnchor, SESSION_CAPSULE_FORMAT_VERSION, SESSION_CAPSULE_WIRE_MAGIC, SessionCapsule,
    SessionCapsuleParams, SessionId, reference_contract_basis,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn sample_basis() -> ContractBasis {
    reference_contract_basis()
}

fn sample_capsule(revision: u64, seq: u64) -> Result<SessionCapsule, Box<dyn std::error::Error>> {
    let base = LedgerAnchor::genesis("site:workspace-schema-test");
    let mut current = base.clone();
    current.commit_sequence = seq;
    Ok(SessionCapsule::new(SessionCapsuleParams {
        session_id: SessionId::parse("session:workspace-001")?,
        revision,
        principal: "principal:owner-agent".to_owned(),
        capability_projection: vec!["capability:situation.read".to_owned()],
        objective_digest: "objective:workspace:digest0001".to_owned(),
        base_anchor: base,
        current_anchor: current,
        situation_capsule_digest: "situation:workspace:digest0001".to_owned(),
        active_hypotheses: vec!["hypothesis:intruder-north-gate".to_owned()],
        assumptions: vec!["assumption:ir-illuminator-active".to_owned()],
        unknowns: vec!["unknown:shed-interior-unobserved".to_owned()],
        not_observable_domains: vec!["domain:shed-interior".to_owned()],
        epistemic_debt: vec![
            "debt:stale-calibration".to_owned(),
            "claim:gate-01: sensor calibration older than 24h".to_owned(),
        ],
        open_obligations: vec!["obligation:reconcile-alert-42".to_owned()],
        budget_ledger: BudgetVector::builder()
            .latency_ms(250)
            .tokens(8_000)
            .bytes(32_768)
            .privacy_exposure(0.15)
            .operator_attention_seconds(1.5)
            .build()?,
        bookmarked_evidence: vec![
            ContentDigest::sha256(b"frame-north-gate-01"),
            ContentDigest::sha256(b"audio-clip-02"),
        ],
        next_actions: vec![
            "action:probe-north-gate".to_owned(),
            "action:verify-shed-door".to_owned(),
        ],
        decision_digest: "decision:workspace:digest0001".to_owned(),
    })?)
}

#[test]
fn session_capsule_v1_roundtrips_binary_json_and_enforces_immutable_supersession() -> TestResult {
    let basis = sample_basis();
    let rev1 = sample_capsule(1, 10)?;
    let invalidated_empty: Vec<String> = Vec::new();

    assert_eq!(SessionCapsule::SCHEMA, "fss.agent_session_capsule.v1");
    assert!(!rev1.grants_effect_authority());

    // 1. Canonical binary wire round-trip (`FSSAWC01` v1) + determinism.
    let w1 = rev1.to_canonical_bytes()?;
    let w2 = rev1.to_canonical_bytes()?;
    assert_eq!(w1, w2);
    assert_eq!(&w1[..8], &SESSION_CAPSULE_WIRE_MAGIC);
    assert_eq!(
        u32::from_be_bytes([w1[8], w1[9], w1[10], w1[11]]),
        SESSION_CAPSULE_FORMAT_VERSION
    );
    let from_wire = SessionCapsule::from_canonical_bytes(&w1)?;
    assert_eq!(from_wire, rev1);
    assert_eq!(from_wire.capsule_digest(), rev1.capsule_digest());

    // 2. Canonical JSON round-trip (including both bare debt IDs and `id: assumption` debt entries + invalidatedItems!).
    let invalidated = vec!["action:obsolete-probe".to_owned()];
    let json = rev1.to_canonical_json(&basis, &invalidated, "dev:ws:gen1", "stream:ws:gen1")?;
    let (from_json, decoded_basis, decoded_invalidated) = SessionCapsule::from_json(&json)?;
    assert_eq!(from_json, rev1);
    assert_eq!(decoded_basis, basis);
    assert_eq!(decoded_invalidated, invalidated);
    assert_eq!(
        from_json.to_canonical_json(
            &decoded_basis,
            &decoded_invalidated,
            "dev:ws:gen1",
            "stream:ws:gen1"
        )?,
        json
    );

    // 3. Immutable supersession + explicit stale/invalidated recording on anchor rebase!
    let mut rev2 = sample_capsule(2, 12)?;
    rev2.next_actions = vec!["action:probe-north-gate".to_owned()];
    // Silently dropping `action:verify-shed-door` across anchor rebase MUST fail closed!
    assert!(matches!(
        rev2.verify_supersedes(&rev1, &invalidated_empty),
        Err(AgentContractCodecError::CompatibilityViolation(_))
    ));
    // Recording the invalidated action explicitly succeeds!
    rev2.verify_supersedes(&rev1, &["action:verify-shed-door".to_owned()])?;

    // Reusing or lowering revision number (mutating an immutable revision) MUST fail closed!
    let mut same_rev = rev1.clone();
    same_rev.decision_digest = "decision:workspace:digest0002".to_owned();
    assert!(matches!(
        same_rev.verify_supersedes(&rev1, &invalidated_empty),
        Err(AgentContractCodecError::CompatibilityViolation(_))
    ));

    // Anchor regression across revisions MUST fail closed!
    let mut regressed_anchor = sample_capsule(3, 9)?;
    regressed_anchor.next_actions = rev1.next_actions.clone();
    assert!(matches!(
        regressed_anchor.verify_supersedes(&rev1, &invalidated_empty),
        Err(AgentContractCodecError::CompatibilityViolation(_))
    ));

    emit_caplog(
        "schema_agent_session_capsule_v1_roundtrip_and_supersession",
        "binary_json_immutability_and_rebase_invalidation_verified",
        "binary_json_immutability_and_rebase_invalidation_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn session_capsule_v1_refuses_hostile_json_debt_schema_and_wire() -> TestResult {
    let basis = sample_basis();
    let capsule = sample_capsule(1, 10)?;
    let json = capsule.to_canonical_json(&basis, &[], "dev:ws:gen1", "stream:ws:gen1")?;

    // 1. Control characters in principal fail closed!
    let mut bad_principal_params = SessionCapsuleParams {
        session_id: capsule.session_id.clone(),
        revision: 1,
        principal: "principal:\nspoof".to_owned(),
        capability_projection: vec![],
        objective_digest: capsule.objective_digest.clone(),
        base_anchor: capsule.base_anchor.clone(),
        current_anchor: capsule.current_anchor.clone(),
        situation_capsule_digest: capsule.situation_capsule_digest.clone(),
        active_hypotheses: vec![],
        assumptions: vec![],
        unknowns: vec![],
        not_observable_domains: vec![],
        epistemic_debt: vec![],
        open_obligations: vec![],
        budget_ledger: capsule.budget_ledger,
        bookmarked_evidence: vec![],
        next_actions: vec![],
        decision_digest: capsule.decision_digest.clone(),
    };
    assert_eq!(
        SessionCapsule::new(bad_principal_params.clone()),
        Err(ContractError::InvalidIdentifier)
    );
    bad_principal_params.principal = "principal:ok".to_owned();
    assert!(SessionCapsule::new(bad_principal_params).is_ok());

    // 2. Hostile JSON: unknown property, wrong root/basis/anchor schema, duplicate key, bad epistemicDebtItem, invalid optional digest!
    let unknown = json.replacen('{', "{\"extraProp\":true,", 1);
    assert!(matches!(
        SessionCapsule::from_json(&unknown),
        Err(AgentContractCodecError::MalformedPayload(_))
    ));
    let wrong_schema = json.replace(
        "fss.agent_session_capsule.v1",
        "fss.agent_session_capsule.v99",
    );
    assert!(matches!(
        SessionCapsule::from_json(&wrong_schema),
        Err(AgentContractCodecError::SchemaMismatch {
            expected: "fss.agent_session_capsule.v1",
            ..
        })
    ));
    let wrong_anchor = json.replace("fss.evidence_anchor.v1", "fss.evidence_anchor.v99");
    assert!(matches!(
        SessionCapsule::from_json(&wrong_anchor),
        Err(AgentContractCodecError::SchemaMismatch {
            expected: "fss.evidence_anchor.v1",
            ..
        })
    ));
    let dup_key = json.replacen("\"principal\":", "\"principal\":\"dup\",\"principal\":", 1);
    assert!(matches!(
        SessionCapsule::from_json(&dup_key),
        Err(AgentContractCodecError::MalformedPayload(_))
    ));
    let bad_debt = json.replace(
        "\"reviewTrigger\":",
        "\"rogueDebtField\":\"x\",\"reviewTrigger\":",
    );
    assert!(matches!(
        SessionCapsule::from_json(&bad_debt),
        Err(AgentContractCodecError::MalformedPayload(_))
    ));
    let bad_opt_digest = json.replacen('{', "{\"priorCapsuleDigest\":\"BAD_UPPER\",", 1);
    assert_eq!(
        SessionCapsule::from_json(&bad_opt_digest),
        Err(AgentContractCodecError::Contract(
            ContractError::InvalidIdentifier
        ))
    );

    // 3. Hostile binary wire: bad magic, unsupported version, truncation, checksum flip, trailing byte.
    let wire = capsule.to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        SessionCapsule::from_canonical_bytes(&bad_magic),
        Err(AgentContractCodecError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&99_u32.to_be_bytes());
    assert_eq!(
        SessionCapsule::from_canonical_bytes(&bad_ver),
        Err(AgentContractCodecError::UnsupportedVersion { version: 99 })
    );
    assert!(matches!(
        SessionCapsule::from_canonical_bytes(&wire[..wire.len() - 4]),
        Err(AgentContractCodecError::MalformedPayload(_))
    ));
    let mut bit_flip = wire.clone();
    let last = bit_flip.len() - 1;
    bit_flip[last] ^= 0x01;
    assert_eq!(
        SessionCapsule::from_canonical_bytes(&bit_flip),
        Err(AgentContractCodecError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0x99);
    assert!(matches!(
        SessionCapsule::from_canonical_bytes(&trailing),
        Err(AgentContractCodecError::MalformedPayload(_))
    ));

    emit_caplog(
        "schema_agent_session_capsule_v1_faults",
        "control_chars_hostile_json_debt_items_and_wire_failed_closed",
        "control_chars_hostile_json_debt_items_and_wire_failed_closed",
        "pass",
    );
    Ok(())
}
