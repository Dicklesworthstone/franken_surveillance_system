#![forbid(unsafe_code)]

use super::*;
use crate::{CaptureInterval, DecisionPath, EventEvidence, EvidenceClass, ProbabilityInterval};

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn d(value: &str) -> ContentDigest {
    ContentDigest::sha256(value.as_bytes())
}
fn signal(name: &str, kind: SignalKind, domains: &[&str]) -> FamiliaritySignal {
    FamiliaritySignal {
        evidence_digest: d(name),
        source_generation: d("source-generation"),
        kind,
        supports: true,
        failure_domains: domains.iter().map(|s| (*s).to_owned()).collect(),
        valid_from_ns: TimestampNs(0),
        expires_at_ns: TimestampNs(1_000),
        revoked: false,
        opted_in: false,
        model_receipt: None,
    }
}
fn fixture() -> Result<(EventHypothesis, FamiliarityContext), Box<dyn std::error::Error>> {
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.into(),
        event_id: EventId::parse("event:familiarity")?,
        revision: 1,
        supersedes: None,
        state: EventState::Indeterminate,
        kind: EventKind::Unclassified,
        interval: CaptureInterval::new(TimestampNs(100), TimestampNs(200))?,
        uncertainty_reason: Some("identity and activity unresolved".into()),
        zone_ids: vec!["zone:door".into()],
        track_ids: vec!["track:anonymous".into()],
        probability: ProbabilityInterval::with_calibration(0.0, 1.0, d("calibration"))?,
        evidence: vec![EventEvidence {
            digest: d("door"),
            class: EvidenceClass::Derived,
            failure_domain: "sensor:door".into(),
            supports: false,
            relation: EvidenceEdgeRelation::DerivedFrom,
            capsule_digest: Some(d("capsule")),
            identity_digest: Some(d("sensor")),
        }],
        model_receipts: vec![d("model-receipt")],
        decision_path: DecisionPath {
            policy_generation: d("policy"),
            fingerprint: d("native-decision"),
            abstained: true,
            abstention_reason: Some("unclassified candidate".into()),
        },
    };
    event.validate()?;
    let context = FamiliarityContext {
        site_lineage: "site:home".into(),
        authority_root: d("authority"),
        privacy_scope: "privacy:local".into(),
        event_id: event.event_id.clone(),
        event_revision_digest: event.revision_digest(),
        event_policy_generation: event.decision_path.policy_generation,
        coverage: AssertedCoverage::Complete,
        threat_actions: AssertedRisk::Clear,
        sensor_integrity: AssertedRisk::Clear,
        high_consequence: false,
        signals: vec![
            signal("door", SignalKind::AuthorizedDoor, &["sensor:door"]),
            signal("routine", SignalKind::Routine, &["routine:household"]),
        ],
    };
    Ok((event, context))
}
fn basis() -> FamiliarityBasis<'static> {
    FamiliarityBasis {
        site_lineage: "site:home",
        authority_root: d("authority"),
        privacy_scope: "privacy:local",
        at_ns: TimestampNs(200),
    }
}
fn assess(
    event: &EventHypothesis,
    context: &FamiliarityContext,
) -> Result<FamiliarityAssessment, FamiliarityError> {
    assess_familiarity(event, context, basis())
}

#[test]
fn familiar_activity_remains_a_hypothesis_and_event_is_unchanged() -> TestResult {
    let (event, context) = fixture()?;
    let original = event.to_canonical_json();
    let result = assess(&event, &context)?;
    assert_eq!(
        result.disposition,
        FamiliarityDisposition::PossibleFamiliarActivity
    );
    assert_eq!(result.declared_support_groups, 2);
    assert_eq!(result.valid_until_ns, Some(TimestampNs(1_000)));
    for unknown in [
        "identity_unresolved",
        "source_independence_unverified",
        "context_assertions_unverified",
        "canonical_event_unresolved",
    ] {
        assert!(result.unknowns.contains(&unknown));
    }
    assert_eq!(event.to_canonical_json(), original);
    assert_eq!(event.state, EventState::Indeterminate);
    assert!(event.decision_path.abstained);
    Ok(())
}

#[test]
fn input_permutations_preserve_decision_and_common_causes_merge_transitively() -> TestResult {
    let (event, mut context) = fixture()?;
    context.signals.push(signal(
        "bridge",
        SignalKind::OperatorConfirmation,
        &["routine:household", "sensor:door"],
    ));
    let expected = assess(&event, &context)?;
    assert_eq!(expected.declared_support_groups, 1);
    assert_eq!(
        expected.disposition,
        FamiliarityDisposition::InsufficientContext
    );
    for ordering in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let mut permuted = context.clone();
        permuted.signals = ordering
            .map(|index| context.signals[index].clone())
            .to_vec();
        for signal in &mut permuted.signals {
            signal.failure_domains.reverse();
        }
        assert_eq!(assess(&event, &permuted)?, expected);
    }
    // Expiry or revocation cannot erase a known shared cause and manufacture independence.
    context.signals[2].expires_at_ns = TimestampNs(50);
    assert_eq!(assess(&event, &context)?.declared_support_groups, 1);
    context.signals[2].revoked = true;
    let revoked_bridge = assess(&event, &context)?;
    assert_eq!(revoked_bridge.declared_support_groups, 1);
    assert_eq!(
        revoked_bridge.disposition,
        FamiliarityDisposition::InsufficientContext
    );
    Ok(())
}

#[test]
fn duplicate_sources_same_family_and_device_only_context_never_suffice() -> TestResult {
    let (event, mut context) = fixture()?;
    context.signals.push(context.signals[0].clone());
    assert!(matches!(
        assess(&event, &context),
        Err(FamiliarityError::Malformed(_))
    ));
    context.signals.pop();
    context.signals[1].kind = SignalKind::AuthorizedDoor;
    assert_eq!(
        assess(&event, &context)?.disposition,
        FamiliarityDisposition::InsufficientContext
    );
    context.signals[0].kind = SignalKind::TrustedDevice;
    context.signals[0].opted_in = true;
    context.signals[1].kind = SignalKind::Routine;
    assert_eq!(
        assess(&event, &context)?.disposition,
        FamiliarityDisposition::InsufficientContext
    );
    Ok(())
}

#[test]
fn expiry_revocation_and_uncertain_time_do_not_become_support() -> TestResult {
    let (event, context) = fixture()?;
    let mut expired_basis = basis();
    expired_basis.at_ns = TimestampNs(1_000);
    let expired = assess_familiarity(&event, &context, expired_basis)?;
    assert!(
        expired
            .signals
            .iter()
            .all(|row| row.validity == SignalValidity::Expired)
    );
    assert_eq!(
        expired.disposition,
        FamiliarityDisposition::InsufficientContext
    );
    assert_eq!(expired.valid_until_ns, None);
    let mut revoked = context.clone();
    revoked.signals[0].revoked = true;
    assert_eq!(
        assess(&event, &revoked)?.disposition,
        FamiliarityDisposition::InsufficientContext
    );
    assert!(
        assess(&event, &revoked)?
            .signals
            .iter()
            .any(|row| row.validity == SignalValidity::Revoked)
    );
    let mut too_late = context.clone();
    too_late.signals[0].valid_from_ns = TimestampNs(150);
    assert!(
        assess(&event, &too_late)?
            .signals
            .iter()
            .any(|row| row.validity == SignalValidity::OutsideEvent)
    );
    let mut future = context.clone();
    future.signals[0].valid_from_ns = TimestampNs(250);
    assert!(
        assess(&event, &future)?
            .signals
            .iter()
            .any(|row| row.validity == SignalValidity::NotYetValid)
    );
    let mut premature = basis();
    premature.at_ns = TimestampNs(199);
    assert!(matches!(
        assess_familiarity(&event, &context, premature),
        Err(FamiliarityError::Malformed(_))
    ));
    Ok(())
}

#[test]
fn device_and_appearance_require_opt_in_and_exact_event_model_receipt() -> TestResult {
    let (event, mut context) = fixture()?;
    context.signals[1].kind = SignalKind::TrustedDevice;
    assert!(
        assess(&event, &context)?
            .signals
            .iter()
            .any(|row| row.validity == SignalValidity::OptInRequired)
    );
    context.signals[1].opted_in = true;
    assert_eq!(
        assess(&event, &context)?.disposition,
        FamiliarityDisposition::PossibleFamiliarActivity
    );
    context.signals[1].kind = SignalKind::Appearance;
    context.signals[1].model_receipt = Some(d("other-generation"));
    assert!(
        assess(&event, &context)?
            .signals
            .iter()
            .any(|row| row.validity == SignalValidity::ModelMismatch)
    );
    context.signals[1].model_receipt = Some(d("model-receipt"));
    assert_eq!(
        assess(&event, &context)?.disposition,
        FamiliarityDisposition::PossibleFamiliarActivity
    );
    context.signals[1].expires_at_ns = TimestampNs(MAX_APPEARANCE_LIFETIME_NS + 1);
    assert!(matches!(
        assess(&event, &context),
        Err(FamiliarityError::Malformed(_))
    ));
    Ok(())
}

#[test]
fn high_consequence_native_threats_and_tamper_override_familiarity() -> TestResult {
    let (event, context) = fixture()?;
    for kind in [
        EventKind::CovertApproach,
        EventKind::PerimeterBreach,
        EventKind::SensorTamper,
    ] {
        let mut event = event.clone();
        event.kind = kind;
        let mut context = context.clone();
        context.event_revision_digest = event.revision_digest();
        assert_eq!(
            assess(&event, &context)?.disposition,
            FamiliarityDisposition::ThreatOverride
        );
    }
    let mut high = context.clone();
    high.high_consequence = true;
    assert_eq!(
        assess(&event, &high)?.disposition,
        FamiliarityDisposition::ThreatOverride
    );
    let mut tamper = context.clone();
    tamper.sensor_integrity = AssertedRisk::Present;
    assert_eq!(
        assess(&event, &tamper)?.disposition,
        FamiliarityDisposition::Conflicted
    );
    let mut event = event;
    event.evidence[0].relation = EvidenceEdgeRelation::SensorTamper;
    let mut context = context;
    context.event_revision_digest = event.revision_digest();
    assert_eq!(
        assess(&event, &context)?.disposition,
        FamiliarityDisposition::Conflicted
    );
    Ok(())
}

#[test]
fn expired_or_revoked_contradiction_cannot_silently_restore_benign_advice() -> TestResult {
    let (event, mut context) = fixture()?;
    let mut stolen_device = signal(
        "stolen-device",
        SignalKind::TrustedDevice,
        &["operator:incident"],
    );
    stolen_device.supports = false;
    stolen_device.expires_at_ns = TimestampNs(50);
    stolen_device.revoked = true;
    context.signals.push(stolen_device);
    let result = assess(&event, &context)?;
    assert_eq!(result.disposition, FamiliarityDisposition::Conflicted);
    assert!(result.blockers.contains(&"unresolved_contradiction"));
    assert_eq!(result.signals.len(), 3);
    Ok(())
}

#[test]
fn native_contradictions_and_unknown_or_degraded_coverage_are_preserved() -> TestResult {
    let (event, context) = fixture()?;
    let mut unknown = context.clone();
    unknown.coverage = AssertedCoverage::Unknown;
    let result = assess(&event, &unknown)?;
    assert_eq!(
        result.disposition,
        FamiliarityDisposition::InsufficientContext
    );
    assert!(result.unknowns.contains(&"coverage_unknown"));
    unknown.coverage = AssertedCoverage::Degraded;
    assert_eq!(
        assess(&event, &unknown)?.disposition,
        FamiliarityDisposition::Blocked
    );
    unknown = context.clone();
    unknown.threat_actions = AssertedRisk::Unknown;
    assert_eq!(
        assess(&event, &unknown)?.disposition,
        FamiliarityDisposition::InsufficientContext
    );
    unknown = context.clone();
    unknown.sensor_integrity = AssertedRisk::Unknown;
    assert_eq!(
        assess(&event, &unknown)?.disposition,
        FamiliarityDisposition::InsufficientContext
    );
    let mut event = event;
    event.evidence[0].relation = EvidenceEdgeRelation::Contradicts;
    let mut context = context;
    context.event_revision_digest = event.revision_digest();
    assert_eq!(
        assess(&event, &context)?.disposition,
        FamiliarityDisposition::Conflicted
    );
    Ok(())
}

#[test]
fn stale_authority_event_policy_and_cross_property_or_privacy_inputs_refuse() -> TestResult {
    let (event, context) = fixture()?;
    let mut altered = context.clone();
    altered.site_lineage = "site:another".into();
    assert_eq!(
        assess(&event, &altered),
        Err(FamiliarityError::ScopeMismatch)
    );
    altered = context.clone();
    altered.privacy_scope = "privacy:other".into();
    assert_eq!(
        assess(&event, &altered),
        Err(FamiliarityError::ScopeMismatch)
    );
    altered = context.clone();
    altered.authority_root = d("new-root");
    assert_eq!(
        assess(&event, &altered),
        Err(FamiliarityError::StaleAuthority)
    );
    altered = context.clone();
    altered.event_revision_digest = d("new-event");
    assert_eq!(assess(&event, &altered), Err(FamiliarityError::StaleEvent));
    altered = context;
    altered.event_policy_generation = d("new-policy");
    assert_eq!(assess(&event, &altered), Err(FamiliarityError::StaleEvent));
    Ok(())
}

#[test]
fn lifetimes_and_complete_input_counts_are_checked_before_evaluation() -> TestResult {
    let (event, context) = fixture()?;
    for (start, end) in [
        (0, 0),
        (1, 0),
        (i128::MIN, i128::MAX),
        (0, MAX_SIGNAL_LIFETIME_NS + 1),
    ] {
        let mut context = context.clone();
        context.signals[0].valid_from_ns = TimestampNs(start);
        context.signals[0].expires_at_ns = TimestampNs(end);
        assert!(matches!(
            assess(&event, &context),
            Err(FamiliarityError::Malformed(_))
        ));
    }
    let mut many = context.clone();
    many.signals = (0..MAX_SIGNALS + 1)
        .map(|n| signal(&n.to_string(), SignalKind::Routine, &["domain:one"]))
        .collect();
    assert!(matches!(
        assess(&event, &many),
        Err(FamiliarityError::Malformed(_))
    ));
    let mut duplicate = context;
    duplicate.signals[0]
        .failure_domains
        .push("sensor:door".into());
    assert!(matches!(
        assess(&event, &duplicate),
        Err(FamiliarityError::Malformed(_))
    ));
    Ok(())
}

fn document(context: &FamiliarityContext) -> String {
    let signals = context.signals.iter().map(|signal| format!(
        r#"{{"evidence_digest":"{}","source_generation":"{}","kind":"{}","supports":{},"failure_domains":[{}],"valid_from_ns":"{}","expires_at_ns":"{}","revoked":{},"opted_in":{},"model_receipt":{}}}"#,
        signal.evidence_digest, signal.source_generation, signal.kind.as_str(), signal.supports,
        signal.failure_domains.iter().map(|d| format!("\"{d}\"")).collect::<Vec<_>>().join(","),
        signal.valid_from_ns.0, signal.expires_at_ns.0, signal.revoked, signal.opted_in,
        signal.model_receipt.map_or_else(|| "null".into(), |d| format!("\"{d}\"")),
    )).collect::<Vec<_>>().join(",");
    format!(
        r#"{{"schema":"{}","site_lineage":"{}","authority_root":"{}","privacy_scope":"{}","event_id":"{}","event_revision_digest":"{}","event_policy_generation":"{}","coverage":"{}","threat_actions":"{}","sensor_integrity":"{}","high_consequence":{},"signals":[{}]}}"#,
        CONTEXT_SCHEMA,
        context.site_lineage,
        context.authority_root,
        context.privacy_scope,
        context.event_id.as_str(),
        context.event_revision_digest,
        context.event_policy_generation,
        context.coverage.as_str(),
        context.threat_actions.as_str(),
        context.sensor_integrity.as_str(),
        context.high_consequence,
        signals
    )
}

#[test]
fn strict_control_parser_rejects_duplicate_unknown_schema_and_malformed_fields() -> TestResult {
    let (event, context) = fixture()?;
    let valid = document(&context);
    assert_eq!(FamiliarityContext::from_json(&valid)?, context);
    assert_eq!(
        assess(&event, &FamiliarityContext::from_json(&valid)?)?,
        assess(&event, &context)?
    );
    for invalid in [
        valid.replacen("{", "{\"schema\":\"private-token\",", 1),
        valid.replacen("{", "{\"private-token\":true,", 1),
        valid.replace(CONTEXT_SCHEMA, "fss.event_familiarity_context.v999"),
        valid.replace("\"expires_at_ns\":\"1000\"", "\"expires_at_ns\":1e3"),
        valid.replace("authorized_door", "biometric_identity"),
        valid.replace("complete_asserted", "verified_complete"),
        valid.replace(&context.authority_root.to_text(), "sha256:bad"),
        format!("{valid} null"),
        " ".repeat(MAX_CONTEXT_BYTES + 1),
    ] {
        let error =
            FamiliarityContext::from_json(&invalid).expect_err("malformed context must refuse");
        assert!(!error.to_string().contains("private-token"));
    }
    Ok(())
}
