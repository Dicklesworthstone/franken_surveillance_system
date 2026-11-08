#![forbid(unsafe_code)]
//! Synthetic event classification and bounded, non-authoritative interpretation.

use fss_reference::unifi_direct::{
    Controller, Dispatch, Identity, MessageKind, Observation,
    events::{self, Edge, Kind},
    management,
};

#[test]
fn unknown_startup_request_is_opt_in_source_bound_and_replay_bounded()
-> Result<(), Box<dyn std::error::Error>> {
    use fss_core::{ContentDigest, json_input};
    let source = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"FutureCameraRequest","messageId":21,"responseExpected":true,"payload":{"private":"fixture"}}"#;
    let changed = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"FutureCameraRequest","messageId":21,"responseExpected":true,"payload":{}}"#;
    let correlated = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"FutureCameraRequest","messageId":22,"inResponseTo":9,"responseExpected":true}"#;
    let new_controller = || {
        Controller::new(
            Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
            1,
        )
    };
    let mut default = new_controller()?;
    assert_eq!(default.observe_event_claims(source)?, Observation::Other);
    assert!(
        default
            .prepare_event_reply(source, "2026-11-05T10:00:00.000Z")
            .is_err()
    );
    let mut controller = new_controller()?;
    assert_eq!(
        controller.observe_startup_requests(correlated)?,
        Observation::Other
    );
    assert_eq!(
        controller.observe_startup_requests(source)?,
        Observation::StartupRequest { message_id: 21 }
    );
    assert!(
        controller
            .prepare_event_reply(changed, "2026-11-05T10:00:00.000Z")
            .is_err()
    );
    let prepared = controller.prepare_event_reply(source, "2026-11-05T10:00:00.000Z")?;
    assert_eq!(prepared.kind(), MessageKind::StartupRequestReply);
    assert_eq!(
        prepared.source_digest(),
        Some(ContentDigest::sha256(source))
    );
    assert!(!format!("{prepared:?}").contains("fixture"));
    let reply = json_input::parse(std::str::from_utf8(prepared.bytes())?)?;
    let fields = reply.object().ok_or("reply object")?;
    assert_eq!(
        fields.get("functionName").and_then(|v| v.text()),
        Some("FutureCameraRequest")
    );
    assert_eq!(
        fields.get("inResponseTo").and_then(|v| v.integer()),
        Some(21)
    );
    assert_eq!(
        fields
            .get("payload")
            .and_then(|v| v.object())
            .and_then(|v| v.get("private"))
            .and_then(|v| v.text()),
        Some("fixture")
    );
    let id = prepared.id();
    controller.finish_dispatch(id, Dispatch::Written)?;
    assert!(controller.observe_startup_requests(source).is_err());
    let retired = controller.close();
    assert_eq!(retired.event_reply, None);
    assert!(!retired.event_reply_is_startup_request);

    let mut pending = new_controller()?;
    pending.observe_startup_requests(source)?;
    let retired = pending.close();
    assert_eq!(
        retired.event_reply,
        Some((21, ContentDigest::sha256(source)))
    );
    assert!(retired.event_reply_is_startup_request);

    let mut after_hello = new_controller()?;
    after_hello.observe(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_hello","messageId":7,"payload":{}}"#)?;
    assert_eq!(
        after_hello.observe_startup_requests(source)?,
        Observation::Other
    );
    assert_eq!(after_hello.close().event_reply, None);
    Ok(())
}

#[test]
fn unknown_startup_requests_stop_at_shared_reply_quota() -> Result<(), Box<dyn std::error::Error>> {
    let mut controller = Controller::new(
        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
        1,
    )?;
    for id in 1..=64 {
        let source = format!(
            r#"{{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"FutureCameraRequest","messageId":{id},"responseExpected":true}}"#
        );
        assert_eq!(
            controller.observe_startup_requests(source.as_bytes())?,
            Observation::StartupRequest { message_id: id }
        );
        let reply =
            controller.prepare_event_reply(source.as_bytes(), "2026-11-05T10:00:00.000Z")?;
        assert_eq!(reply.kind(), MessageKind::StartupRequestReply);
        let prepared_id = reply.id();
        controller.finish_dispatch(prepared_id, Dispatch::Written)?;
    }
    let overflow = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"FutureCameraRequest","messageId":65,"responseExpected":true}"#;
    assert!(controller.observe_startup_requests(overflow).is_err());
    assert_eq!(controller.close().event_reply, None);
    Ok(())
}

#[test]
fn event_reply_binds_exact_source_and_preserves_json_payload()
-> Result<(), Box<dyn std::error::Error>> {
    use fss_core::{ContentDigest, json_input};
    let source = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventSmartDetect","messageId":21,"responseExpected":true,"payload":{"label":"private\n\"value","nested":[null,true,-1.25e2,{"n":3}]}}"#;
    let changed = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventSmartDetect","messageId":21,"responseExpected":true,"payload":{}}"#;
    let mut controller = Controller::new(
        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
        1,
    )?;
    controller.observe_event_claims(source)?;
    assert!(
        controller
            .prepare_event_reply(changed, "2026-11-05T10:00:00.000Z")
            .is_err()
    );
    let prepared = controller.prepare_event_reply(source, "2026-11-05T10:00:00.000Z")?;
    assert_eq!(prepared.kind(), MessageKind::EventReply);
    assert_eq!(
        prepared.source_digest(),
        Some(ContentDigest::sha256(source))
    );
    assert!(!format!("{prepared:?}").contains("private"));
    let original = json_input::parse(std::str::from_utf8(source)?)?;
    let reply = json_input::parse(std::str::from_utf8(prepared.bytes())?)?;
    let reply = reply.object().ok_or("reply object")?;
    assert_eq!(
        reply.get("payload"),
        original.object().ok_or("source object")?.get("payload")
    );
    assert_eq!(
        reply.get("inResponseTo").and_then(|v| v.integer()),
        Some(21)
    );
    assert_eq!(
        reply.get("responseExpected").and_then(|v| v.boolean()),
        Some(false)
    );
    let conditions = management::Preconditions {
        camera: ContentDigest::sha256(b"camera"),
        peer_admission: ContentDigest::sha256(b"peer"),
        session_generation: 1,
        previous_association: None,
        previous_clock: None,
        lease_fence: 1,
    };
    let intent = management::Intent::new(prepared, conditions)?;
    assert_eq!(intent.source_digest(), Some(ContentDigest::sha256(source)));
    intent.check_message(prepared)?;
    let id = prepared.id();
    controller.finish_dispatch(id, Dispatch::NotWritten)?;
    assert_eq!(
        controller.prepared().ok_or("missing prepared reply")?.id(),
        id
    );
    controller.finish_dispatch(id, Dispatch::Written)?;
    assert!(
        controller
            .prepare_event_reply(source, "2026-11-05T10:00:00.000Z")
            .is_err()
    );
    assert!(controller.observe_event_claims(source).is_err());
    assert_eq!(controller.close().event_reply, None);
    Ok(())
}

#[test]
fn event_reply_omission_and_correlation_are_explicit() -> Result<(), Box<dyn std::error::Error>> {
    use fss_core::ContentDigest;
    let source = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventExample","messageId":22,"responseExpected":true,"payload":null}"#;
    let correlated = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventExample","messageId":23,"inResponseTo":2,"responseExpected":true}"#;
    let mut controller = Controller::new(
        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
        1,
    )?;
    controller.observe_event_claims(correlated)?;
    assert!(
        controller
            .prepare_event_reply(correlated, "2026-11-05T10:00:00.000Z")
            .is_err()
    );
    controller.observe_event_claims(source)?;
    let digest = ContentDigest::sha256(source);
    assert!(
        controller
            .omit_event_reply(ContentDigest::sha256(b"wrong"))
            .is_err()
    );
    controller.prepare_event_reply(source, "2026-11-05T10:00:00.000Z")?;
    assert!(controller.omit_event_reply(digest).is_err());
    controller.abandon_event_reply(digest)?;
    assert_eq!(controller.close().event_reply, Some((22, digest)));

    let mut omitted = Controller::new(
        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
        1,
    )?;
    omitted.observe_event_claims(source)?;
    omitted.omit_event_reply(digest)?;
    assert_eq!(omitted.close().event_reply, None);
    Ok(())
}

#[test]
fn indeterminate_event_reply_retains_obligation() -> Result<(), Box<dyn std::error::Error>> {
    let source = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventExample","messageId":22,"responseExpected":true,"payload":{}}"#;
    let mut controller = Controller::new(
        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
        1,
    )?;
    controller.observe_event_claims(source)?;
    let id = controller
        .prepare_event_reply(source, "2026-11-05T10:00:00.000Z")?
        .id();
    controller.finish_dispatch(id, Dispatch::Indeterminate)?;
    let retired = controller.close();
    assert_eq!(
        retired.previous_phase,
        fss_reference::unifi_direct::Phase::Indeterminate
    );
    assert_eq!(retired.prepared, Some((id, MessageKind::EventReply)));
    assert_eq!(
        retired.event_reply,
        Some((22, fss_core::ContentDigest::sha256(source)))
    );
    Ok(())
}

#[test]
fn smart_audio_is_classified_without_claiming_sound_or_payload_semantics()
-> Result<(), Box<dyn std::error::Error>> {
    let mut controller = Controller::new(
        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
        1,
    )?;
    let source = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventSmartAudio","messageId":4,"responseExpected":false,"payload":{}}"#;
    assert_eq!(
        controller.observe_event_claims(source)?,
        Observation::CameraEvent {
            kind: Kind::SmartAudio,
            message_id: 4,
            response_expected: false,
        }
    );
    let unknown = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventSmartAudioFuture","messageId":5,"payload":{}}"#;
    assert_eq!(
        controller.observe_event_claims(unknown)?,
        Observation::CameraEvent {
            kind: Kind::Other,
            message_id: 5,
            response_expected: false,
        }
    );
    Ok(())
}

#[test]
fn smart_audio_preserves_source_types_and_redacts_claim_values() -> Result<(), events::Error> {
    use events::{SmartAudioClaim as Claim, SmartAudioField as Field, SmartAudioPayload};
    let source=br#"{"functionName":"EventSmartAudio","payload":{"clockMonotonic":12345678901234567890,"clockStreamRate":1e3,"eventId":null,"leveldB":-43.75,"levels":true,"alrmBabyCry":"opaque-private-status","alrmBark":null,"soundLoss":"unknown-future-status","newField":{"private":"never log"}}}"#;
    let parsed = events::interpret_smart_audio_source(source)?;
    assert_eq!(parsed.payload(), SmartAudioPayload::Object);
    assert_eq!(
        parsed.get(Field::ClockMonotonic),
        &Claim::Number("12345678901234567890".into())
    );
    assert_eq!(
        parsed.get(Field::ClockStreamRate),
        &Claim::Number("1e3".into())
    );
    assert_eq!(parsed.get(Field::LevelDb), &Claim::Number("-43.75".into()));
    assert_eq!(parsed.get(Field::Levels), &Claim::Unsupported);
    assert_eq!(parsed.get(Field::EventId), &Claim::Null);
    assert_eq!(
        parsed.get(Field::AlarmBabyCry),
        &Claim::Text("opaque-private-status".into())
    );
    assert_eq!(parsed.get(Field::AlarmBark), &Claim::Null);
    assert_eq!(parsed.get(Field::AlarmSiren), &Claim::Missing);
    assert_eq!(parsed.unknown_fields(), 1);
    let debug = format!("{parsed:?}");
    assert!(!debug.contains("opaque-private-status"));
    assert!(!debug.contains("12345678901234567890"));
    Ok(())
}

#[test]
fn smart_audio_preserves_payload_absence_and_refuses_bad_envelopes() -> Result<(), events::Error> {
    use events::SmartAudioPayload;
    assert_eq!(
        events::interpret_smart_audio_source(br#"{"functionName":"EventSmartAudio"}"#)?.payload(),
        SmartAudioPayload::Missing
    );
    assert_eq!(
        events::interpret_smart_audio_source(
            br#"{"functionName":"EventSmartAudio","payload":null}"#
        )?
        .payload(),
        SmartAudioPayload::Null
    );
    assert_eq!(
        events::interpret_smart_audio_source(
            br#"{"functionName":"EventSmartMotion","payload":{}}"#
        ),
        Err(events::Error::Invalid)
    );
    assert_eq!(
        events::interpret_smart_audio_source(br#"{"functionName":"EventSmartAudio","payload":[]}"#),
        Err(events::Error::Invalid)
    );
    let oversized = format!(
        "{{\"functionName\":\"EventSmartAudio\",\"payload\":{{\"alrmBark\":\"{}\"}}}}",
        "x".repeat(129)
    );
    assert_eq!(
        events::interpret_smart_audio_source(oversized.as_bytes()),
        Err(events::Error::Limit)
    );
    Ok(())
}

#[test]
fn smart_event_is_a_camera_claim_with_explicit_reply_requirement()
-> Result<(), Box<dyn std::error::Error>> {
    let source=br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventSmartDetect","messageId":21,"responseExpected":true,"payload":{"edgeType":"enter","descriptors":[{"objectType":"person","trackerID":42,"confidenceLevel":80,"coord":[0,1,500,1000],"stationary":"false"}]}}"#;
    let mut controller = Controller::new(
        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
        1,
    )?;
    assert_eq!(
        controller.observe_event_claims(source)?,
        Observation::CameraEvent {
            kind: Kind::SmartDetect,
            message_id: 21,
            response_expected: true
        }
    );
    let parsed = events::interpret_source(source)?;
    assert_eq!(parsed.edge, Edge::Enter);
    let descriptor = &parsed.descriptors.ok_or("missing descriptors")?[0];
    assert_eq!(descriptor.object_type.as_deref(), Some("person"));
    assert_eq!(descriptor.tracker_id.as_deref(), Some("42"));
    assert_eq!(descriptor.confidence, Some(80.0));
    assert_eq!(descriptor.coordinates, Some([0.0, 1.0, 500.0, 1000.0]));
    assert_eq!(descriptor.stationary, Some(false));
    assert!(!format!("{descriptor:?}").contains("person"));
    Ok(())
}

#[test]
fn malformed_and_oversized_event_claims_are_refused() {
    assert_eq!(
        events::interpret_source(br#"{"payload":{"eventType":42}}"#),
        Err(events::Error::Invalid)
    );
    assert_eq!(
        events::interpret_source(br#"{"payload":{"descriptors":[{"coord":[0,0,1001,1]}]}}"#),
        Err(events::Error::Invalid)
    );
    let many = format!(
        "{{\"payload\":{{\"descriptors\":[{}]}}}}",
        vec!["{}"; 65].join(",")
    );
    assert_eq!(
        events::interpret_source(many.as_bytes()),
        Err(events::Error::Limit)
    );
}

#[test]
fn absent_empty_and_unknown_event_fields_are_distinct() -> Result<(), events::Error> {
    let missing = events::interpret_source(br#"{"payload":{}}"#)?;
    assert_eq!((missing.edge, missing.descriptors), (Edge::Missing, None));
    let empty = events::interpret_source(br#"{"payload":{"edgeType":"future","descriptors":[]}}"#)?;
    assert_eq!((empty.edge, empty.descriptors), (Edge::Other, Some(vec![])));
    assert_eq!(
        events::interpret_source(br#"{"payload":{"eventType":"pulse"}}"#)?.edge,
        Edge::Pulse
    );
    Ok(())
}
