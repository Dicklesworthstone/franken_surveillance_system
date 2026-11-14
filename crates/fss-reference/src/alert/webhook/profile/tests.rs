#![forbid(unsafe_code)]
use super::*;
use fss_core::{
    CanonicalEncode, CaptureInterval, DecisionPath, EventEvidence, EventId, EventKind, EventState,
    EvidenceClass, EvidenceEdgeRelation, IdempotencyKey, OperationId, ProbabilityInterval,
    TimestampNs,
};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn digest(text: &str) -> ContentDigest {
    ContentDigest::sha256(text.as_bytes())
}
fn peer() -> Test<SocketAddr> {
    Ok("127.0.0.1:8080".parse()?)
}
fn intent() -> Test<EffectIntent> {
    Ok(EffectIntent::new(
        OperationId::parse("operation:legacy")?,
        IdempotencyKey::parse("idempotency:legacy")?,
        "alert.dispatch",
        digest("request"),
        digest("precondition"),
    )?)
}
fn edge(domain: &str, relation: EvidenceEdgeRelation) -> EventEvidence {
    EventEvidence {
        digest: digest(domain),
        class: EvidenceClass::Derived,
        failure_domain: domain.to_owned(),
        supports: relation == EvidenceEdgeRelation::Supports,
        relation,
        capsule_digest: Some(digest("capsule")),
        identity_digest: Some(digest("sensor")),
    }
}
fn event() -> Test<EventHypothesis> {
    Ok(EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(),
        event_id: EventId::parse("event:alert")?,
        revision: 1,
        supersedes: None,
        state: EventState::Corroborated,
        kind: EventKind::UnknownPresence,
        interval: CaptureInterval::new(
            TimestampNs(-9_007_199_254_740_993),
            TimestampNs(9_007_199_254_740_993),
        )?,
        uncertainty_reason: Some("declared timing uncertainty".into()),
        zone_ids: vec!["zone:east".into()],
        track_ids: vec!["track:private-not-disclosed".into()],
        probability: ProbabilityInterval::new(0.5, 0.8)?,
        evidence: vec![
            edge("domain:a", EvidenceEdgeRelation::Supports),
            edge("domain:b", EvidenceEdgeRelation::Supports),
            edge("domain:c", EvidenceEdgeRelation::Contradicts),
        ],
        model_receipts: vec![],
        decision_path: DecisionPath {
            policy_generation: digest("policy"),
            fingerprint: digest("decision"),
            abstained: false,
            abstention_reason: None,
        },
    })
}
fn encoding(event: &EventHypothesis) -> Test<Vec<u8>> {
    event.verify()?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.canonical.v1");
    encoder.text(EventHypothesis::SCHEMA);
    event.encode_canonical(&mut encoder);
    Ok(encoder.finish_checked()?)
}
fn rich(event: &EventHypothesis) -> Test<Vec<u8>> {
    let intent = intent()?;
    let bytes = encoding(event)?;
    Ok(request(
        &RequestFields {
            intent: &intent,
            event_root: digest("root"),
            event_revision_digest: event.revision_digest(),
            event_revision_encoding: &bytes,
        },
        peer()?,
        "/alerts",
        WebhookDisclosureProfile::EventMetadataV1,
    )?)
}
fn json(request: &[u8]) -> Test<fss_core::json_input::Value> {
    let text = std::str::from_utf8(request)?;
    let (head, body) = text.split_once("\r\n\r\n").ok_or("missing HTTP boundary")?;
    assert!(head.contains(&format!("Content-Length: {}", body.len())));
    assert!(!body.contains('\n'));
    assert!(!body.contains('\r'));
    Ok(fss_core::json_input::parse(body)?)
}

#[test]
fn original_route_and_entire_request_match_retained_golden_bytes() -> Test {
    let route = route_digest(
        peer()?,
        "/alerts",
        digest("plain"),
        WebhookDisclosureProfile::ReferencesV1,
        None,
    )?;
    assert_eq!(
        route.to_text(),
        "sha256:4fd3f4fe8461582869c1a05aa0376aeefe4f6b5d2b1e00c3ebf1f9d01d8d515e"
    );
    let intent = intent()?;
    let request = request(
        &RequestFields {
            intent: &intent,
            event_root: digest("root"),
            event_revision_digest: digest("revision"),
            event_revision_encoding: b"unused legacy hydration",
        },
        peer()?,
        "/alerts",
        WebhookDisclosureProfile::ReferencesV1,
    )?;
    assert_eq!(request, include_bytes!("fixtures/references-v1.http"));
    assert_eq!(
        ContentDigest::sha256(&request).to_text(),
        "sha256:360f69122c068939ea4086ed4903a4df11d1f2dc9124240186e7ca47fa02f07e"
    );
    Ok(())
}

#[test]
fn profile_and_each_separate_approval_produce_distinct_route_and_channel_identity() -> Test {
    let old = route_digest(
        peer()?,
        "/alerts",
        digest("plain"),
        WebhookDisclosureProfile::ReferencesV1,
        None,
    )?;
    let rich = route_digest(
        peer()?,
        "/alerts",
        digest("plain"),
        WebhookDisclosureProfile::EventMetadataV1,
        Some(digest("metadata")),
    )?;
    let new_approval = route_digest(
        peer()?,
        "/alerts",
        digest("plain"),
        WebhookDisclosureProfile::EventMetadataV1,
        Some(digest("metadata2")),
    )?;
    let new_plain = route_digest(
        peer()?,
        "/alerts",
        digest("plain2"),
        WebhookDisclosureProfile::EventMetadataV1,
        Some(digest("metadata")),
    )?;
    assert_eq!(
        BTreeSet::from([old, rich, new_approval, new_plain]).len(),
        4
    );
    assert_eq!(
        rich,
        route_digest(
            peer()?,
            "/alerts",
            digest("plain"),
            WebhookDisclosureProfile::EventMetadataV1,
            Some(digest("metadata"))
        )?
    );
    Ok(())
}

#[test]
fn incomplete_ambiguous_or_unknown_disclosure_selection_never_falls_back() -> Test {
    for (profile, approval) in [
        (
            WebhookDisclosureProfile::ReferencesV1,
            Some(digest("stray")),
        ),
        (WebhookDisclosureProfile::EventMetadataV1, None),
        (
            WebhookDisclosureProfile::EventMetadataV1,
            Some(ContentDigest::parse(&format!("sha256:{}", "0".repeat(64)))?),
        ),
    ] {
        assert_eq!(
            route_digest(peer()?, "/alerts", digest("plain"), profile, approval),
            Err(WebhookProfileError::Configuration)
        );
    }
    assert!(WebhookDisclosureProfile::parse("event-metadata-v2").is_err());
    assert!(WebhookDisclosureProfile::parse("").is_err());
    Ok(())
}

#[test]
fn rich_metadata_preserves_uncertainty_counterevidence_and_exact_large_declared_times() -> Test {
    let event = event()?;
    let request = rich(&event)?;
    let value = json(&request)?;
    let object = value.object().ok_or("object")?;
    assert_eq!(
        object.get("schema").and_then(|v| v.text()),
        Some(EVENT_METADATA_SCHEMA)
    );
    let retained = object
        .get("event")
        .and_then(|v| v.object())
        .ok_or("event")?;
    assert_eq!(
        retained.get("kind").and_then(|v| v.text()),
        Some("unknown_presence")
    );
    assert_eq!(
        retained.get("lifecycle").and_then(|v| v.text()),
        Some("corroborated")
    );
    let interval = retained
        .get("declared_interval_ns")
        .and_then(|v| v.object())
        .ok_or("interval")?;
    assert_eq!(
        interval.get("earliest").and_then(|v| v.text()),
        Some("-9007199254740993")
    );
    assert_eq!(
        interval.get("latest").and_then(|v| v.text()),
        Some("9007199254740993")
    );
    let counts = retained
        .get("evidence_counts")
        .and_then(|v| v.object())
        .ok_or("counts")?;
    assert_eq!(counts.get("supporting").and_then(|v| v.integer()), Some(2));
    assert_eq!(
        counts.get("contradicting").and_then(|v| v.integer()),
        Some(1)
    );
    let probability = retained
        .get("declared_probability")
        .and_then(|v| v.object())
        .ok_or("probability")?;
    assert_eq!(
        probability.get("calibration_claim").and_then(|v| v.text()),
        Some("uncalibrated")
    );
    let text = std::str::from_utf8(&request)?;
    assert!(text.contains("\"current\":\"unknown\""));
    assert!(text.contains("\"physical_truth_claim\":\"not_claimed\""));
    assert!(!text.contains("track:private-not-disclosed"));
    assert!(!text.contains("domain:a"));
    Ok(())
}

#[test]
fn declared_calibration_and_neutral_sensor_edges_are_not_promoted_to_current_health() -> Test {
    let mut event = event()?;
    event.state = EventState::Indeterminate;
    event.probability.calibration_generation = Some(digest("calibration"));
    event
        .evidence
        .push(edge("risk", EvidenceEdgeRelation::SensorTamper));
    event.evidence.push(edge(
        "restored",
        EvidenceEdgeRelation::SensorIntegrityRestoration,
    ));
    let bytes = rich(&event)?;
    let text = std::str::from_utf8(&bytes)?;
    assert!(text.contains("\"neutral\":2"));
    assert!(text.contains("\"tamper_reports\":1,\"integrity_restorations\":1"));
    assert!(text.contains("generation_declared_not_reverified"));
    assert!(text.contains("\"current\":\"unknown\""));
    Ok(())
}

#[test]
fn hostile_zone_and_uncertainty_text_round_trip_as_data_without_http_or_json_injection() -> Test {
    let mut event = event()?;
    event.zone_ids = vec!["east\"\\\r\nX-Injected: yes\u{0000}\u{2028}".into()];
    event.uncertainty_reason = Some("\"},\"verified\":true,\"x\":\"\n\u{007f}\u{2029}".into());
    let request = rich(&event)?;
    let value = json(&request)?;
    let body = value
        .object()
        .and_then(|v| v.get("event"))
        .and_then(|v| v.object())
        .ok_or("event")?;
    assert_eq!(
        body.get("zone_ids")
            .and_then(|v| v.array())
            .and_then(|v| v.first())
            .and_then(|v| v.text()),
        Some(event.zone_ids[0].as_str())
    );
    assert_eq!(
        body.get("uncertainty_reason").and_then(|v| v.text()),
        event.uncertainty_reason.as_deref()
    );
    assert!(!body.contains_key("verified"));
    Ok(())
}

#[test]
fn the_whole_escaped_request_refuses_instead_of_truncating_fields_or_discarding_counterevidence()
-> Test {
    let mut oversized = event()?;
    oversized.zone_ids = vec!["\u{0000}".repeat(64); 64];
    assert!(oversized.verify().is_ok());
    assert!(matches!(
        rich(&oversized).map_err(|error| error.downcast::<WebhookProfileError>().ok().map(|e| *e)),
        Err(Some(WebhookProfileError::Limit))
    ));
    let mut event = event()?;
    while rich(&event)?.len() < 3100 {
        event.zone_ids.push("z".repeat(64));
    }
    let bytes = encoding(&event)?;
    let intent = intent()?;
    let fields = RequestFields {
        intent: &intent,
        event_root: digest("root"),
        event_revision_digest: event.revision_digest(),
        event_revision_encoding: &bytes,
    };
    let ordinary = request(
        &fields,
        peer()?,
        "/",
        WebhookDisclosureProfile::EventMetadataV1,
    )?;
    let target = format!("/{}", "x".repeat(MAX_REQUEST_BYTES - ordinary.len()));
    assert_eq!(
        request(
            &fields,
            peer()?,
            &target,
            WebhookDisclosureProfile::EventMetadataV1
        )?
        .len(),
        MAX_REQUEST_BYTES
    );
    assert_eq!(
        request(
            &fields,
            peer()?,
            &(target + "x"),
            WebhookDisclosureProfile::EventMetadataV1
        ),
        Err(WebhookProfileError::Limit)
    );
    Ok(())
}

#[test]
fn metadata_requires_exact_valid_canonical_revision_not_only_matching_opaque_references() -> Test {
    let event = event()?;
    let mut bytes = encoding(&event)?;
    let intent = intent()?;
    let root = digest("root");
    assert_eq!(
        request(
            &RequestFields {
                intent: &intent,
                event_root: root,
                event_revision_digest: digest("other"),
                event_revision_encoding: &bytes
            },
            peer()?,
            "/alerts",
            WebhookDisclosureProfile::EventMetadataV1
        ),
        Err(WebhookProfileError::EventRevision)
    );
    bytes.push(0);
    assert_eq!(
        request(
            &RequestFields {
                intent: &intent,
                event_root: root,
                event_revision_digest: ContentDigest::sha256(&bytes),
                event_revision_encoding: &bytes
            },
            peer()?,
            "/alerts",
            WebhookDisclosureProfile::EventMetadataV1
        ),
        Err(WebhookProfileError::EventRevision)
    );
    let bytes = vec![0; MAX_METADATA_REVISION_BYTES + 1];
    assert_eq!(
        request(
            &RequestFields {
                intent: &intent,
                event_root: root,
                event_revision_digest: ContentDigest::sha256(&bytes),
                event_revision_encoding: &bytes
            },
            peer()?,
            "/alerts",
            WebhookDisclosureProfile::EventMetadataV1
        ),
        Err(WebhookProfileError::Limit)
    );
    Ok(())
}

#[test]
fn metadata_digest_algorithms_are_preserved_instead_of_relabelled() -> Test {
    let mut event = event()?;
    let declared = ContentDigest::parse(&format!("blake3:{}", "ab".repeat(32)))?;
    event.decision_path.fingerprint = declared;
    event.decision_path.policy_generation = declared;
    event.probability.calibration_generation = Some(declared);
    let value = json(&rich(&event)?)?;
    let metadata = value
        .object()
        .and_then(|v| v.get("event"))
        .and_then(|v| v.object())
        .ok_or("event")?;
    assert_eq!(
        metadata.get("decision_fingerprint").and_then(|v| v.text()),
        Some(declared.to_text().as_str())
    );
    assert_eq!(
        metadata.get("policy_generation").and_then(|v| v.text()),
        Some(declared.to_text().as_str())
    );
    assert!(!metadata.contains_key("decision_fingerprint_sha256"));
    Ok(())
}
