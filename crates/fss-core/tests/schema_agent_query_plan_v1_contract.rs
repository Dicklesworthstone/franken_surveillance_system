#![forbid(unsafe_code)]
//! Comprehensive contract, binary/JSON codec, hardening, and hostile-input tests for
//! `SCHEMA-AGENT-QUERY-001` (`fss.agent_query_plan.v1`, `fss-x4a.30.39`).

use fss_core::contract_basis::reference_contract_basis;
use fss_core::{
    AGENT_QUERY_PLAN_FORMAT_VERSION, AGENT_QUERY_PLAN_WIRE_MAGIC, AgentQueryPlan,
    AgentQueryPlanCodecError, BudgetVector, ContentDigest, ContractBasisError, ContractError,
    LedgerAnchor, MissionId, QueryCompletenessRequested, QueryInterpretation, SessionId,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn sample_plan() -> Result<AgentQueryPlan, Box<dyn std::error::Error>> {
    let basis = reference_contract_basis();
    let mut anchor = LedgerAnchor::genesis("site:fss:query-plan");
    anchor.commit_sequence = 12;
    anchor.privacy_epoch = 3;
    let budget = BudgetVector::builder()
        .latency_ms(500)
        .tokens(2_048)
        .bytes(65_536)
        .model_calls(2)
        .cpu_millis(120)
        .privacy_exposure(0.25)
        .operator_attention_seconds(5.0)
        .build()?;
    let est = BudgetVector::builder()
        .latency_ms(200)
        .tokens(1_024)
        .bytes(16_384)
        .model_calls(1)
        .cpu_millis(60)
        .privacy_exposure(0.1)
        .operator_attention_seconds(2.0)
        .build()?;
    Ok(AgentQueryPlan::compile(
        "query-plan:driveway:001",
        MissionId::parse("mission:perimeter")?,
        SessionId::parse("session:agent-01")?,
        &basis,
        "AOP-005",
        ContentDigest::sha256(b"check driveway motion last hour"),
        vec!["taint:user-text:001".to_owned()],
        anchor,
        "Inspect driveway coverage and corroborated events over the last hour.".to_owned(),
        vec!["fss://zone/driveway/cam-01".to_owned()],
        vec!["domain:coverage".to_owned(), "domain:events".to_owned()],
        vec!["CAP-AGENT-QUERY-001".to_owned()],
        vec!["privacy:face-mask:v1".to_owned()],
        QueryCompletenessRequested::CertifiedAbsence,
        budget,
        vec![
            QueryInterpretation::new(
                "interp:driveway-strict",
                "Only corroborated detections within driveway zone.".to_owned(),
                true,
                true,
                None,
            )?,
            QueryInterpretation::new(
                "interp:adjacent-street",
                "Include adjacent street approach zone.".to_owned(),
                false,
                true,
                Some("Confirm whether street zone is in authorized scope.".to_owned()),
            )?,
        ],
        "interp:driveway-strict",
        est,
        "AVIEW-003",
        1_700_000_000_000,
    )?)
}

#[test]
fn agent_query_plan_v1_canonical_binary_and_json_roundtrip() -> TestResult {
    let basis = reference_contract_basis();
    let plan = sample_plan()?;
    assert_eq!(AgentQueryPlan::SCHEMA, "fss.agent_query_plan.v1");
    assert!(!plan.grants_effect_authority());

    // 1. Canonical binary wire round-trip (`FSSAQP01` v1) + determinism check!
    let wire1 = plan.to_canonical_bytes()?;
    let wire2 = plan.to_canonical_bytes()?;
    assert_eq!(wire1, wire2);
    assert_eq!(&wire1[..8], &AGENT_QUERY_PLAN_WIRE_MAGIC);
    assert_eq!(
        u32::from_be_bytes([wire1[8], wire1[9], wire1[10], wire1[11]]),
        AGENT_QUERY_PLAN_FORMAT_VERSION
    );
    let decoded_bin = AgentQueryPlan::from_canonical_bytes(&wire1)?;
    assert_eq!(decoded_bin, plan);
    assert_eq!(decoded_bin.plan_digest(), plan.plan_digest());

    // 2. Canonical JSON round-trip conforming strictly to `schemas/agent_query_plan.v1.json`!
    let json = plan.to_canonical_json("dev:cam-01:gen1", "stream:main:gen1")?;
    let decoded_json = AgentQueryPlan::from_json_with_basis(&json, &basis)?;
    assert_eq!(decoded_json, plan);
    assert_eq!(decoded_json.plan_digest(), plan.plan_digest());
    assert_eq!(
        decoded_json.to_canonical_json("dev:cam-01:gen1", "stream:main:gen1")?,
        json
    );

    emit_caplog(
        "schema_agent_query_plan_v1_roundtrip",
        "binary_and_json_roundtrip_bit_identical",
        "binary_and_json_roundtrip_bit_identical",
        "pass",
    );
    Ok(())
}

#[test]
fn agent_query_plan_v1_refuses_duplicates_neg_time_bad_json_and_hostile_wire() -> TestResult {
    let basis = reference_contract_basis();
    let plan = sample_plan()?;
    let valid_budget = BudgetVector::builder().latency_ms(10).build()?;

    // 1. Duplicate interpretation IDs fail closed!
    let dup = AgentQueryPlan::compile(
        "query-plan:dup",
        MissionId::parse("mission:m1")?,
        SessionId::parse("session:s1")?,
        &basis,
        "AOP-005",
        ContentDigest::sha256(b"q"),
        vec![],
        LedgerAnchor::genesis("site:dup"),
        "objective".to_owned(),
        vec![],
        vec![],
        vec![],
        vec![],
        QueryCompletenessRequested::Bounded,
        valid_budget,
        vec![
            QueryInterpretation::new("interp:same", "desc 1", true, true, None)?,
            QueryInterpretation::new("interp:same", "desc 2", false, true, None)?,
        ],
        "interp:same",
        valid_budget,
        "AVIEW-003",
        10,
    );
    assert_eq!(
        dup,
        Err(ContractBasisError::Contract(
            ContractError::InvalidIdentifier
        ))
    );

    // 2. Negative createdAtNs fails closed!
    let neg_time = AgentQueryPlan::compile(
        "query-plan:neg",
        MissionId::parse("mission:m1")?,
        SessionId::parse("session:s1")?,
        &basis,
        "AOP-005",
        ContentDigest::sha256(b"q"),
        vec![],
        LedgerAnchor::genesis("site:neg"),
        "objective".to_owned(),
        vec![],
        vec![],
        vec![],
        vec![],
        QueryCompletenessRequested::Bounded,
        valid_budget,
        vec![QueryInterpretation::new(
            "interp:a", "desc", true, true, None,
        )?],
        "interp:a",
        valid_budget,
        "AVIEW-003",
        -1,
    );
    assert_eq!(
        neg_time,
        Err(ContractBasisError::Contract(
            ContractError::InvalidIdentifier
        ))
    );

    // 3. Hostile JSON inputs: unknown field, wrong schema, duplicate key, effectful operation!
    let json = plan.to_canonical_json("dev:cam-01:gen1", "stream:main:gen1")?;
    let unknown = json.replacen('{', "{\"extraSmuggled\":true,", 1);
    assert!(matches!(
        AgentQueryPlan::from_json_with_basis(&unknown, &basis),
        Err(AgentQueryPlanCodecError::MalformedPayload(_))
    ));
    let wrong_schema = json.replace("fss.agent_query_plan.v1", "fss.agent_query_plan.v9");
    assert!(matches!(
        AgentQueryPlan::from_json_with_basis(&wrong_schema, &basis),
        Err(AgentQueryPlanCodecError::SchemaMismatch { .. })
    ));
    let effectful = json.replace("\"AOP-005\"", "\"AOP-008\"");
    assert!(matches!(
        AgentQueryPlan::from_json_with_basis(&effectful, &basis),
        Err(AgentQueryPlanCodecError::Contract(_))
    ));

    // 4. Hostile binary wire inputs: bad magic, unsupported version, truncation, bit flip, trailing byte!
    let wire = plan.to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        AgentQueryPlan::from_canonical_bytes(&bad_magic),
        Err(AgentQueryPlanCodecError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&42_u32.to_be_bytes());
    assert_eq!(
        AgentQueryPlan::from_canonical_bytes(&bad_ver),
        Err(AgentQueryPlanCodecError::UnsupportedVersion { version: 42 })
    );
    assert!(matches!(
        AgentQueryPlan::from_canonical_bytes(&wire[..wire.len() - 5]),
        Err(AgentQueryPlanCodecError::MalformedPayload(_))
    ));
    let mut bit_flip = wire.clone();
    let last = bit_flip.len() - 1;
    bit_flip[last] ^= 0x01;
    assert_eq!(
        AgentQueryPlan::from_canonical_bytes(&bit_flip),
        Err(AgentQueryPlanCodecError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0x99);
    assert!(matches!(
        AgentQueryPlan::from_canonical_bytes(&trailing),
        Err(AgentQueryPlanCodecError::MalformedPayload(_))
    ));

    emit_caplog(
        "schema_agent_query_plan_v1_faults",
        "duplicates_neg_time_effect_op_json_and_wire_failed_closed",
        "duplicates_neg_time_effect_op_json_and_wire_failed_closed",
        "pass",
    );
    Ok(())
}
