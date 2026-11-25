#![forbid(unsafe_code)]
//! Contract, golden, continuity, and hostile-input tests for `SCHEMA-AGENT-SESSION-001`
//! (`fss.agent_session.v1`, `fss-x4a.30.30`).

use std::collections::BTreeSet;

use fss_core::{
    AGENT_SESSION_FORMAT_VERSION, AGENT_SESSION_WIRE_MAGIC, AgentContractCodecError, AgentSession,
    AgentSessionParams, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder,
    ContentDigest, ContractBasis, ContractError, LedgerAnchor, MAX_AGENT_SESSION_TOKEN_BUDGET,
    MissionId, PrincipalId, SessionId, reference_contract_basis,
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

fn sample_session(
    fingerprint: Option<ContentDigest>,
) -> Result<AgentSession, Box<dyn std::error::Error>> {
    let mut anchor = LedgerAnchor::genesis("site:session-schema-test");
    anchor.commit_sequence = 15;
    Ok(AgentSession::new(AgentSessionParams {
        session_id: SessionId::parse("session:schema-001")?,
        mission_id: MissionId::parse("mission:perimeter-watch")?,
        principal_id: PrincipalId::parse("principal:owner-agent")?,
        capabilities: BTreeSet::from([
            "capability:hydrate:H0".to_owned(),
            "capability:situation.read".to_owned(),
        ]),
        privacy_scope: BTreeSet::from([
            "privacy:face-redaction".to_owned(),
            "privacy:property-only".to_owned(),
        ]),
        current_anchor: anchor,
        view_id: "AVIEW-002".to_owned(),
        token_budget: 64_000,
        symbol_table_generation: 3,
        last_acknowledged_situation_fingerprint: fingerprint,
        created_at_ns: 1_700_000_000_000,
        expires_at_ns: 1_700_003_600_000,
    })?)
}

#[test]
fn agent_session_v1_roundtrips_binary_json_optional_fields_and_refresh_continuity() -> TestResult {
    let basis = sample_basis();
    let pinned = sample_session(Some(ContentDigest::sha256(b"situation-pin-15")))?;
    let unpinned = sample_session(None)?;

    assert_eq!(AgentSession::SCHEMA, "fss.agent_session.v1");
    assert!(!pinned.grants_effect_authority());
    assert!(pinned.is_active_at(1_700_000_000_000));
    assert!(!pinned.is_active_at(1_700_003_600_000));
    assert!(!pinned.is_active_at(1_699_999_999_999));

    // 1. Canonical binary wire round-trip (`FSSAGS01` v1) + determinism.
    for session in [&pinned, &unpinned] {
        let w1 = session.to_canonical_bytes()?;
        let w2 = session.to_canonical_bytes()?;
        assert_eq!(w1, w2);
        assert_eq!(&w1[..8], &AGENT_SESSION_WIRE_MAGIC);
        assert_eq!(
            u32::from_be_bytes([w1[8], w1[9], w1[10], w1[11]]),
            AGENT_SESSION_FORMAT_VERSION
        );
        let decoded = AgentSession::from_canonical_bytes(&w1)?;
        assert_eq!(decoded, *session);
        assert_eq!(decoded.session_digest(), session.session_digest());
    }

    // 2. Canonical JSON round-trip (both pinned digest and `fss-na:` unpinned sentinel!).
    for session in [&pinned, &unpinned] {
        let json = session.to_canonical_json(&basis, "dev:session:gen1", "stream:session:gen1")?;
        let (decoded, decoded_basis) = AgentSession::from_json(&json)?;
        assert_eq!(decoded, *session);
        assert_eq!(decoded_basis, basis);
        assert_eq!(
            decoded.to_canonical_json(&decoded_basis, "dev:session:gen1", "stream:session:gen1")?,
            json
        );
    }

    // 3. Optional fields (`symbols`, `continuations`, `subscriptions`, `parentHandoffId`) validated strictly.
    let base_json = pinned.to_canonical_json(&basis, "dev:session:gen1", "stream:session:gen1")?;
    let extra = format!(
        "\"continuations\":[\"cont:001\"],\"parentHandoffId\":\"handoff:prev-01\",\"subscriptions\":[\"sub:gate-events\"],\"symbols\":[{{\"alias\":\"@s1\",\"anchorFingerprint\":\"{}\",\"expiresAtNs\":1700003600000,\"invalidators\":[\"anchor_advance\"],\"objectId\":\"obj:cam-front\",\"objectRevision\":4}}],",
        ContentDigest::sha256(b"anchor-fp").to_text()
    );
    let with_opt = base_json.replacen('{', &format!("{{{extra}"), 1);
    let (parsed_opt, _) = AgentSession::from_json(&with_opt)?;
    assert_eq!(parsed_opt, pinned);

    // 4. Refresh continuity: monotone anchor + symbol generation passes; identity/anchor regression fails closed!
    let mut refreshed = pinned.clone();
    refreshed.current_anchor.commit_sequence += 1;
    refreshed.symbol_table_generation += 1;
    refreshed.verify_refresh_preserves_identity(&pinned)?;

    let mut regressed = pinned.clone();
    regressed.current_anchor.commit_sequence -= 1;
    assert!(matches!(
        regressed.verify_refresh_preserves_identity(&pinned),
        Err(AgentContractCodecError::CompatibilityViolation(_))
    ));
    let mut switched_mission = pinned.clone();
    switched_mission.mission_id = MissionId::parse("mission:hijacked")?;
    assert!(matches!(
        switched_mission.verify_refresh_preserves_identity(&pinned),
        Err(AgentContractCodecError::CompatibilityViolation(_))
    ));

    emit_caplog(
        "schema_agent_session_v1_roundtrip_and_continuity",
        "binary_json_optional_fields_and_refresh_continuity_verified",
        "binary_json_optional_fields_and_refresh_continuity_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn agent_session_v1_refuses_bounds_duplicates_hostile_json_and_wire() -> TestResult {
    let basis = sample_basis();
    let session = sample_session(None)?;
    let json = session.to_canonical_json(&basis, "dev:session:gen1", "stream:session:gen1")?;

    // 1. Over-max tokenBudget, negative createdAtNs, and malformed capability token fail closed!
    assert_eq!(
        AgentSession::new(AgentSessionParams {
            session_id: SessionId::parse("session:bad-budget")?,
            mission_id: MissionId::parse("mission:perimeter-watch")?,
            principal_id: PrincipalId::parse("principal:owner-agent")?,
            capabilities: BTreeSet::new(),
            privacy_scope: BTreeSet::new(),
            current_anchor: LedgerAnchor::genesis("site:bad"),
            view_id: "AVIEW-001".to_owned(),
            token_budget: MAX_AGENT_SESSION_TOKEN_BUDGET + 1,
            symbol_table_generation: 0,
            last_acknowledged_situation_fingerprint: None,
            created_at_ns: 0,
            expires_at_ns: 100,
        }),
        Err(ContractError::CountBoundExceeded)
    );
    assert_eq!(
        AgentSession::new(AgentSessionParams {
            session_id: SessionId::parse("session:neg-time")?,
            mission_id: MissionId::parse("mission:perimeter-watch")?,
            principal_id: PrincipalId::parse("principal:owner-agent")?,
            capabilities: BTreeSet::new(),
            privacy_scope: BTreeSet::new(),
            current_anchor: LedgerAnchor::genesis("site:bad"),
            view_id: "AVIEW-001".to_owned(),
            token_budget: 100,
            symbol_table_generation: 0,
            last_acknowledged_situation_fingerprint: None,
            created_at_ns: -1,
            expires_at_ns: 100,
        }),
        Err(ContractError::InvalidIdentifier)
    );

    // 2. Hostile JSON: unknown field, wrong root/basis/anchor schema, duplicate capability (`uniqueItems: true`), bad symbol alias!
    let unknown = json.replacen('{', "{\"rogueExtra\":1,", 1);
    assert!(matches!(
        AgentSession::from_json(&unknown),
        Err(AgentContractCodecError::MalformedPayload(_))
    ));
    let wrong_schema = json.replace("fss.agent_session.v1", "fss.agent_session.v9");
    assert!(matches!(
        AgentSession::from_json(&wrong_schema),
        Err(AgentContractCodecError::SchemaMismatch {
            expected: "fss.agent_session.v1",
            ..
        })
    ));
    let wrong_basis_schema = json.replace(
        "fss.agent_contract_basis.v1",
        "fss.agent_contract_basis.v99",
    );
    assert!(matches!(
        AgentSession::from_json(&wrong_basis_schema),
        Err(AgentContractCodecError::SchemaMismatch {
            expected: "fss.agent_contract_basis.v1",
            ..
        })
    ));
    let wrong_anchor_schema = json.replace("fss.evidence_anchor.v1", "fss.evidence_anchor.v99");
    assert!(matches!(
        AgentSession::from_json(&wrong_anchor_schema),
        Err(AgentContractCodecError::SchemaMismatch {
            expected: "fss.evidence_anchor.v1",
            ..
        })
    ));
    let dup_caps = json.replace(
        "\"capabilities\":[\"capability:hydrate:H0\",\"capability:situation.read\"]",
        "\"capabilities\":[\"capability:hydrate:H0\",\"capability:hydrate:H0\"]",
    );
    assert!(matches!(
        AgentSession::from_json(&dup_caps),
        Err(AgentContractCodecError::MalformedPayload(_))
    ));
    let bad_alias = json.replacen(
        '{',
        &format!(
            "{{\"symbols\":[{{\"alias\":\"BAD_ALIAS\",\"anchorFingerprint\":\"{}\",\"expiresAtNs\":10,\"objectId\":\"obj:1\",\"objectRevision\":0}}],",
            ContentDigest::sha256(b"fp").to_text()
        ),
        1,
    );
    assert_eq!(
        AgentSession::from_json(&bad_alias),
        Err(AgentContractCodecError::Contract(
            ContractError::InvalidIdentifier
        ))
    );

    // 3. Hostile binary wire: bad magic, unsupported version, truncation, checksum flip, trailing byte, non-canonical unsorted set!
    let wire = session.to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        AgentSession::from_canonical_bytes(&bad_magic),
        Err(AgentContractCodecError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&5_u32.to_be_bytes());
    assert_eq!(
        AgentSession::from_canonical_bytes(&bad_ver),
        Err(AgentContractCodecError::UnsupportedVersion { version: 5 })
    );
    assert!(matches!(
        AgentSession::from_canonical_bytes(&wire[..wire.len() - 4]),
        Err(AgentContractCodecError::MalformedPayload(_))
    ));
    let mut bit_flip = wire.clone();
    let last = bit_flip.len() - 1;
    bit_flip[last] ^= 0x01;
    assert_eq!(
        AgentSession::from_canonical_bytes(&bit_flip),
        Err(AgentContractCodecError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0x42);
    assert!(matches!(
        AgentSession::from_canonical_bytes(&trailing),
        Err(AgentContractCodecError::MalformedPayload(_))
    ));

    let mut enc = CanonicalEncoder::new();
    enc.text(AgentSession::SCHEMA);
    session.session_id.encode_canonical(&mut enc);
    session.mission_id.encode_canonical(&mut enc);
    session.principal_id.encode_canonical(&mut enc);
    enc.u32(2);
    enc.text("capability:z");
    enc.text("capability:a");
    enc.u32(0);
    session.current_anchor.encode_canonical(&mut enc);
    enc.text(session.view.id());
    enc.u64(session.token_budget);
    enc.u64(session.symbol_table_generation);
    enc.bool(false);
    enc.i128(session.created_at_ns);
    enc.i128(session.expires_at_ns);
    let unsorted = enc.finish_checked()?;
    let mut dec = CanonicalDecoder::new(&unsorted);
    assert_eq!(
        AgentSession::decode_canonical(&mut dec),
        Err(ContractError::NonCanonicalOrdering)
    );

    emit_caplog(
        "schema_agent_session_v1_faults",
        "bounds_unique_items_schemas_wire_and_ordering_failed_closed",
        "bounds_unique_items_schemas_wire_and_ordering_failed_closed",
        "pass",
    );
    Ok(())
}
