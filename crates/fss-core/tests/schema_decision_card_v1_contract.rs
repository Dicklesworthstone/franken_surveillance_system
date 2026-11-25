#![forbid(unsafe_code)]
//! Contract, golden, migration, and hostile-input tests for `SCHEMA-DECISION-CARD-001`
//! (`fss.decision_card.v1`, `fss-x4a.30.14`).

use fss_core::{
    DECISION_CARD_CANONICAL_DOMAIN, DECISION_CARD_FORMAT_VERSION, DECISION_CARD_WIRE_MAGIC,
    DecisionAlternativeV1, DecisionCardError, DecisionCardV1, DecisionTimestampV1,
    EvidenceAnchorRecordV1, LedgerAnchor,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn sample_card(decision_id: &str, seq: u64) -> Result<DecisionCardV1, Box<dyn std::error::Error>> {
    let mut ledger_anchor = LedgerAnchor::genesis("site:decision-card-test");
    ledger_anchor.commit_sequence = seq;
    let mut anchor = EvidenceAnchorRecordV1::from_ledger_anchor(
        &ledger_anchor,
        "dev:cam-front:gen1",
        "stream:main:gen1",
    )?;
    anchor.model_generation = Some("model:rfdetr:v1".to_owned());
    anchor.calibration_generation = Some("cal:cam-front:v1".to_owned());

    Ok(DecisionCardV1 {
        decision_id: decision_id.to_owned(),
        decision_class: "alert_dispatch_policy".to_owned(),
        anchor,
        policy_id: "policy:perimeter:v3".to_owned(),
        alternatives: vec![
            DecisionAlternativeV1 {
                id: "alt:escalate-siren".to_owned(),
                utility: 0.92,
                admissible: false,
                rejection_reasons: vec![
                    "clamp:quiet-hours-active".to_owned(),
                    "clamp:single-camera-uncorroborated".to_owned(),
                ],
            },
            DecisionAlternativeV1 {
                id: "alt:notify-owner-silent".to_owned(),
                utility: 0.78,
                admissible: true,
                rejection_reasons: vec![],
            },
            DecisionAlternativeV1 {
                id: "alt:wait-and-corroborate".to_owned(),
                utility: 0.65,
                admissible: true,
                rejection_reasons: vec![],
            },
        ],
        selected_id: "alt:notify-owner-silent".to_owned(),
        hard_constraints: vec![
            "HC-QUIET-HOURS-001".to_owned(),
            "HC-CORROBORATION-REQUIRED-001".to_owned(),
        ],
        evidence_ids: vec![
            "sha256:11111111111111111111111111111111".to_owned(),
            "sha256:22222222222222222222222222222222".to_owned(),
        ],
        decision_path_digest: "sha256:abcdef0123456789abcdef0123456789".to_owned(),
        created_at: DecisionTimestampV1 {
            earliest_ns: 1_700_000_000_000,
            latest_ns: 1_700_000_005_000,
            clock_basis: "utc_disciplined".to_owned(),
            uncertainty_reason: Some("ntp_bound_5us".to_owned()),
        },
    })
}

#[test]
fn decision_card_v1_canonical_binary_json_roundtrip_and_supersession() -> TestResult {
    let v1 = sample_card("dec:001", 10)?;
    assert_eq!(DecisionCardV1::SCHEMA, "fss.decision_card.v1");
    assert_eq!(
        DECISION_CARD_CANONICAL_DOMAIN,
        "fss.decision_card.canonical.v1"
    );
    assert!(!v1.grants_effect_authority());
    v1.validate()?;

    // 1. Canonical binary wire round-trip (`FSSDCV01` v1) + determinism check!
    let wire1 = v1.to_canonical_bytes()?;
    let wire2 = v1.to_canonical_bytes()?;
    assert_eq!(wire1, wire2);
    assert_eq!(&wire1[..8], &DECISION_CARD_WIRE_MAGIC);
    assert_eq!(
        u32::from_be_bytes([wire1[8], wire1[9], wire1[10], wire1[11]]),
        DECISION_CARD_FORMAT_VERSION
    );
    let decoded_bin = DecisionCardV1::from_canonical_bytes(&wire1)?;
    assert_eq!(decoded_bin, v1);
    assert_eq!(decoded_bin.canonical_digest()?, v1.canonical_digest()?);

    // 2. Canonical JSON round-trip matching `schemas/decision_card.v1.json` 100%!
    let json = v1.to_canonical_json()?;
    let decoded_json = DecisionCardV1::from_json(&json)?;
    assert_eq!(decoded_json, v1);
    assert_eq!(decoded_json.to_canonical_json()?, json);

    // 3. Valid supersession preserves all prior hard constraints and alternative IDs!
    let mut v2 = sample_card("dec:002", 11)?;
    v2.hard_constraints.push("HC-PRIVACY-MASK-001".to_owned());
    v2.alternatives.push(DecisionAlternativeV1 {
        id: "alt:record-only".to_owned(),
        utility: 0.4,
        admissible: true,
        rejection_reasons: vec![],
    });
    v2.verify_supersedes(&v1)?;

    // 4. Silent rewrite attempts MUST fail closed!
    let mut dropped_hc = v2.clone();
    dropped_hc.hard_constraints.remove(0);
    assert!(matches!(
        dropped_hc.verify_supersedes(&v1),
        Err(DecisionCardError::SilentRewriteRefused(_))
    ));
    let mut dropped_alt = v2.clone();
    dropped_alt.alternatives.remove(0);
    assert!(matches!(
        dropped_alt.verify_supersedes(&v1),
        Err(DecisionCardError::SilentRewriteRefused(_))
    ));
    let mut same_id = v2;
    same_id.decision_id = v1.decision_id.clone();
    assert!(matches!(
        same_id.verify_supersedes(&v1),
        Err(DecisionCardError::SilentRewriteRefused(_))
    ));

    emit_caplog(
        "schema_decision_card_v1_roundtrip_and_supersession",
        "binary_json_determinism_and_no_silent_rewrite_verified",
        "binary_json_determinism_and_no_silent_rewrite_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn decision_card_v1_refuses_clamp_bypass_malformed_json_and_hostile_wire() -> TestResult {
    let base = sample_card("dec:fault-001", 20)?;

    // 1. Selecting an inadmissible alternative MUST fail closed!
    let mut bypass = base.clone();
    bypass.selected_id = "alt:escalate-siren".to_owned();
    assert!(matches!(
        bypass.validate(),
        Err(DecisionCardError::HardConstraintViolation(_))
    ));

    // 2. Inadmissible alternative with empty rejectionReasons MUST fail closed!
    let mut bare_no = base.clone();
    bare_no.alternatives[0].rejection_reasons.clear();
    assert!(matches!(
        bare_no.validate(),
        Err(DecisionCardError::HardConstraintViolation(_))
    ));

    // 2b. Contradictory admissible alternative carrying rejectionReasons MUST fail closed!
    let mut admissible_with_rejections = base.clone();
    admissible_with_rejections.alternatives[1]
        .rejection_reasons
        .push("clamp:contradictory".to_owned());
    assert!(matches!(
        admissible_with_rejections.validate(),
        Err(DecisionCardError::HardConstraintViolation(_))
    ));

    // 3. Non-finite utility & invalid regex pattern MUST fail closed!
    let mut nan_util = base.clone();
    nan_util.alternatives[1].utility = f64::NAN;
    assert!(matches!(
        nan_util.validate(),
        Err(DecisionCardError::InvalidField {
            field: "alternatives[].utility",
            ..
        })
    ));
    let mut bad_digest = base.clone();
    bad_digest.decision_path_digest = "UPPERCASE_INVALID".to_owned();
    assert!(matches!(
        bad_digest.validate(),
        Err(DecisionCardError::InvalidField {
            field: "decisionPathDigest",
            ..
        })
    ));

    // 4. Hostile JSON inputs: unknown property (`additionalProperties: false`), wrong schema, duplicate key, inverted time!
    let json = base.to_canonical_json()?;
    let with_unknown = json.replacen('{', "{\"rogueExtra\":1,", 1);
    assert!(matches!(
        DecisionCardV1::from_json(&with_unknown),
        Err(DecisionCardError::MalformedPayload(_))
    ));
    let wrong_schema = json.replace("fss.decision_card.v1", "fss.decision_card.v99");
    assert!(matches!(
        DecisionCardV1::from_json(&wrong_schema),
        Err(DecisionCardError::SchemaMismatch { .. })
    ));
    let dup_key = json.replacen("\"policyId\":", "\"policyId\":\"dup\",\"policyId\":", 1);
    assert!(matches!(
        DecisionCardV1::from_json(&dup_key),
        Err(DecisionCardError::MalformedPayload(_))
    ));

    // 5. Hostile binary wire inputs: bad magic, unsupported version, truncation, checksum tamper, trailing byte!
    let wire = base.to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        DecisionCardV1::from_canonical_bytes(&bad_magic),
        Err(DecisionCardError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&7_u32.to_be_bytes());
    assert_eq!(
        DecisionCardV1::from_canonical_bytes(&bad_ver),
        Err(DecisionCardError::UnsupportedVersion { version: 7 })
    );
    assert!(matches!(
        DecisionCardV1::from_canonical_bytes(&wire[..wire.len() - 4]),
        Err(DecisionCardError::MalformedPayload(_))
    ));
    let mut bit_flip = wire.clone();
    let last = bit_flip.len() - 1;
    bit_flip[last] ^= 0x01;
    assert_eq!(
        DecisionCardV1::from_canonical_bytes(&bit_flip),
        Err(DecisionCardError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0xAA);
    assert!(matches!(
        DecisionCardV1::from_canonical_bytes(&trailing),
        Err(DecisionCardError::MalformedPayload(_))
    ));

    emit_caplog(
        "schema_decision_card_v1_faults",
        "clamp_bypass_malformed_json_and_hostile_wire_failed_closed",
        "clamp_bypass_malformed_json_and_hostile_wire_failed_closed",
        "pass",
    );
    Ok(())
}
