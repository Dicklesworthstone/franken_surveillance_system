#![forbid(unsafe_code)]
//! Synthetic direct-UniFi management state and local-write outcome contracts.

use fss_core::json_input::{self, Value};
use fss_reference::unifi_direct::{
    AGREEMENT_DELAY_NS, AudioCodec, Controller, Dispatch, Error, Identity, MAX_MESSAGE_BYTES,
    MAX_MESSAGE_ID, MessageKind, Observation, Phase, RejectedMessage, StreamStart, TimeSyncCounts,
    TimeSyncPolicy, VideoChannel, VideoCodec,
};
use std::net::{Ipv4Addr, SocketAddrV4};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const TIME: &str = "2026-11-05T05:00:00.000Z";

#[test]
fn retirement_retains_rejected_message_kind_without_payload() -> TestResult {
    let mut c = controller(1)?;
    assert_eq!(
        c.observe(&message("ubnt_avclient_paramAgreement", 2, 1, "{}")),
        Err(Error::UnexpectedMessage)
    );
    let retired = c.close();
    assert_eq!(retired.previous_phase, Phase::AwaitHello);
    assert_eq!(retired.rejected_message, Some(RejectedMessage::Agreement));
    Ok(())
}

fn controller(first_id: u64) -> Result<Controller, Error> {
    Controller::new(
        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
        first_id,
    )
}

fn message(function: &str, id: u64, response_to: u64, payload: &str) -> Vec<u8> {
    format!("{{\"from\":\"ubnt_avclient\",\"to\":\"UniFiVideo\",\"functionName\":\"{function}\",\"messageId\":{id},\"inResponseTo\":{response_to},\"responseExpected\":false,\"payload\":{payload}}}").into_bytes()
}

fn fields(bytes: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(json_input::parse(std::str::from_utf8(bytes)?)?)
}

fn ready() -> Result<Controller, Error> {
    let mut c = controller(1)?;
    c.observe(&message("ubnt_avclient_hello", 7, 0, "{}"))?;
    c.prepare_hello(TIME)?;
    c.finish_dispatch(1, Dispatch::Written)?;
    c.prepare_agreement(TIME, AGREEMENT_DELAY_NS)?;
    c.finish_dispatch(2, Dispatch::Written)?;
    c.observe(&message("ubnt_avclient_paramAgreement", 8, 2, "{}"))?;
    Ok(c)
}

fn stream(channel: VideoChannel, audio: AudioCodec) -> Result<StreamStart, Error> {
    StreamStart::new(
        channel,
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 33), 17551),
        VideoCodec::H264,
        audio,
        "0123456789abcdef",
    )
}

#[test]
fn hello_agreement_and_time_sync_are_correlated_without_authentication_claims() -> TestResult {
    let mut c = controller(1)?;
    let reply = message("ubnt_avclient_timeSync", 40, 99, "{\"timeDelta\":0}");
    assert_eq!(c.observe(&reply)?, Observation::Other);
    assert_eq!(c.phase(), Phase::AwaitHello);
    assert_eq!(c.prepare_time_sync(123_456, TIME), Err(Error::InvalidState));
    let sync = message("ubnt_avclient_timeSync", 41, 0, "{\"timeDelta\":0}");
    assert_eq!(c.observe(&sync)?, Observation::TimeSyncRequested);
    let p = c.prepare_time_sync(123_456, TIME)?;
    assert_eq!(p.kind(), MessageKind::TimeSyncReply);
    let json = fields(p.bytes())?;
    let o = json.object().ok_or("expected object")?;
    assert_eq!(o.get("inResponseTo").and_then(Value::integer), Some(41));
    assert_eq!(
        o.get("payload")
            .and_then(Value::object)
            .and_then(|v| v.get("t1"))
            .and_then(Value::integer),
        Some(123_456)
    );
    c.finish_dispatch(1, Dispatch::Written)?;
    assert_eq!(c.phase(), Phase::AwaitHello);

    let hello = message("ubnt_avclient_hello", 42, 0, "{\"protocolVersion\":67}");
    assert_eq!(c.observe(&hello)?, Observation::Hello);
    let p = c.prepare_hello(TIME)?;
    assert_eq!(p.kind(), MessageKind::HelloReply);
    let json = fields(p.bytes())?;
    let o = json.object().ok_or("expected object")?;
    assert_eq!(o.get("inResponseTo").and_then(Value::integer), Some(42));
    assert_eq!(o.get("messageId").and_then(Value::integer), Some(2));
    assert_eq!(
        o.get("payload")
            .and_then(Value::object)
            .and_then(|v| v.get("protocolVersion"))
            .and_then(Value::integer),
        Some(67)
    );
    c.finish_dispatch(2, Dispatch::Written)?;
    assert_eq!(c.phase(), Phase::AwaitAgreementPreparation);
    assert_eq!(
        c.prepare_agreement(TIME, AGREEMENT_DELAY_NS - 1),
        Err(Error::AgreementTooEarly)
    );
    assert_eq!(c.phase(), Phase::AwaitAgreementPreparation);
    let p = c.prepare_agreement(TIME, AGREEMENT_DELAY_NS)?;
    assert_eq!(p.id(), 3);
    assert_eq!(p.kind(), MessageKind::AgreementRequest);
    let json = fields(p.bytes())?;
    let o = json.object().ok_or("expected object")?;
    assert_eq!(
        o.get("responseExpected").and_then(Value::boolean),
        Some(true)
    );
    c.finish_dispatch(3, Dispatch::Written)?;
    assert_eq!(c.phase(), Phase::AwaitAgreementReply);
    let wrong = message("ubnt_avclient_paramAgreement", 43, 2, "{}");
    assert_eq!(c.observe(&wrong), Err(Error::UnexpectedMessage));
    assert_eq!(c.phase(), Phase::AwaitAgreementReply);
    let reply = message(
        "ubnt_avclient_paramAgreement",
        44,
        3,
        "{\"authToken\":\"PRIVATE_VALUE\"}",
    );
    assert_eq!(c.observe(&reply)?, Observation::AgreementReply);
    assert_eq!(c.phase(), Phase::AgreementReplyObserved);
    assert!(!format!("{c:?}").contains("PRIVATE_VALUE"));
    Ok(())
}

#[test]
fn time_sync_counts_preserve_payload_free_correlation_observations() -> TestResult {
    let mut c = controller(1)?;
    assert_eq!(c.time_sync_counts(), TimeSyncCounts::default());
    assert_eq!(
        c.observe(&message("ubnt_avclient_timeSync", 40, 99, "{}"))?,
        Observation::Other
    );
    let expects_reply = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":41,"inResponseTo":99,"responseExpected":true}"#;
    assert_eq!(c.observe(expects_reply)?, Observation::Other);
    assert_eq!(
        c.observe(&message("ubnt_avclient_timeSync", 42, 0, "{}"))?,
        Observation::TimeSyncRequested
    );
    assert_eq!(
        c.observe(&message("ubnt_avclient_timeSync", 43, 0, "{}")),
        Err(Error::TimeSyncLimit)
    );
    assert_eq!(
        c.time_sync_counts(),
        TimeSyncCounts {
            uncorrelated: 2,
            correlated: 2,
            correlated_response_expected: 1
        }
    );
    let malformed = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":44,"inResponseTo":99,"responseExpected":"yes"}"#;
    assert_eq!(c.observe(malformed), Err(Error::InvalidEnvelope));
    assert_eq!(
        c.time_sync_counts(),
        TimeSyncCounts {
            uncorrelated: 2,
            correlated: 2,
            correlated_response_expected: 1
        }
    );
    Ok(())
}

#[test]
fn explicit_correlated_time_sync_policy_answers_only_an_explicit_request() -> TestResult {
    let mut c = Controller::new_with_time_sync_policy(
        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
        1,
        TimeSyncPolicy::ExplicitCorrelatedRequests,
    )?;
    let correlated_reply = message("ubnt_avclient_timeSync", 40, 99, "{}");
    assert_eq!(c.observe(&correlated_reply)?, Observation::Other);
    let request = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":41,"inResponseTo":99,"responseExpected":true}"#;
    assert_eq!(c.observe(request)?, Observation::TimeSyncRequested);
    assert_eq!(c.observe(request), Err(Error::TimeSyncLimit));
    let prepared = c.prepare_time_sync(123_456, TIME)?;
    let value = fields(prepared.bytes())?;
    let object = value.object().ok_or("response object")?;
    assert_eq!(
        object.get("inResponseTo").and_then(Value::integer),
        Some(41)
    );
    assert_eq!(
        object.get("responseExpected").and_then(Value::boolean),
        Some(false)
    );
    c.finish_dispatch(1, Dispatch::Written)?;
    assert_eq!(c.phase(), Phase::AwaitHello);
    let echo = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":43,"inResponseTo":1,"responseExpected":true}"#;
    assert_eq!(c.observe(echo)?, Observation::Other);
    // A correlated response to our response cannot trigger another reply.
    assert_eq!(
        c.observe(&message("ubnt_avclient_timeSync", 42, 1, "{}"))?,
        Observation::Other
    );
    assert_eq!(c.prepare_time_sync(123_456, TIME), Err(Error::InvalidState));
    assert_eq!(c.time_sync_counts().correlated_response_expected, 3);
    Ok(())
}

#[test]
fn explicit_correlated_time_sync_policy_has_a_hard_reply_bound() -> TestResult {
    let mut c = Controller::new_with_time_sync_policy(
        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
        1,
        TimeSyncPolicy::ExplicitCorrelatedRequests,
    )?;
    for id in 40..48 {
        let request = format!(
            "{{\"from\":\"ubnt_avclient\",\"to\":\"UniFiVideo\",\"functionName\":\"ubnt_avclient_timeSync\",\"messageId\":{id},\"inResponseTo\":99,\"responseExpected\":true}}"
        );
        assert_eq!(
            c.observe(request.as_bytes())?,
            Observation::TimeSyncRequested
        );
        let output_id = c.prepare_time_sync(123_456, TIME)?.id();
        c.finish_dispatch(output_id, Dispatch::Written)?;
    }
    let late_echo = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":49,"inResponseTo":8,"responseExpected":true}"#;
    assert_eq!(c.observe(late_echo)?, Observation::Other);
    let ninth = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":48,"inResponseTo":99,"responseExpected":true}"#;
    assert_eq!(c.observe(ninth), Err(Error::TimeSyncLimit));
    assert!(c.prepared().is_none());
    Ok(())
}

#[test]
fn correlated_time_sync_uncertain_write_fences_the_session() -> TestResult {
    let mut c = Controller::new_with_time_sync_policy(
        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
        1,
        TimeSyncPolicy::ExplicitCorrelatedRequests,
    )?;
    let request = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":41,"inResponseTo":99,"responseExpected":true}"#;
    assert_eq!(c.observe(request)?, Observation::TimeSyncRequested);
    let original = c.prepare_time_sync(123_456, TIME)?.bytes().to_vec();
    c.finish_dispatch(1, Dispatch::NotWritten)?;
    assert_eq!(c.prepared().ok_or("prepared reply")?.bytes(), original);
    c.finish_dispatch(1, Dispatch::Indeterminate)?;
    assert_eq!(c.phase(), Phase::Indeterminate);
    assert_eq!(c.observe(request), Err(Error::InvalidState));
    assert_eq!(
        c.finish_dispatch(1, Dispatch::Written),
        Err(Error::InvalidState)
    );
    Ok(())
}

#[test]
fn proven_unwritten_preserves_exact_bytes_and_uncertain_write_forbids_retry() -> TestResult {
    let mut c = controller(17)?;
    c.observe(&message("ubnt_avclient_hello", 42, 0, "{}"))?;
    let prepared = c.prepare_hello(TIME)?;
    let original = prepared.bytes().to_vec();
    assert_eq!(prepared.id(), 17);
    assert_eq!(
        c.finish_dispatch(18, Dispatch::Written),
        Err(Error::WrongPreparedMessage)
    );
    c.finish_dispatch(17, Dispatch::NotWritten)?;
    assert_eq!(c.prepared().ok_or("prepared lost")?.bytes(), original);
    assert_eq!(c.phase(), Phase::HelloObserved);
    c.finish_dispatch(17, Dispatch::Indeterminate)?;
    assert_eq!(c.phase(), Phase::Indeterminate);
    assert_eq!(
        c.finish_dispatch(17, Dispatch::Written),
        Err(Error::InvalidState)
    );
    assert_eq!(
        c.observe(&message("ubnt_avclient_hello", 43, 0, "{}")),
        Err(Error::InvalidState)
    );
    let retired = c.close();
    assert_eq!(retired.previous_phase, Phase::Indeterminate);
    assert_eq!(retired.prepared, Some((17, MessageKind::HelloReply)));
    assert_eq!(retired.hello_request_id, Some(42));
    assert_eq!(c.phase(), Phase::Closed);
    assert!(c.prepared().is_none());
    Ok(())
}

#[test]
fn bounded_time_sync_interleaving_does_not_advance_negotiation() -> TestResult {
    let mut c = controller(1)?;
    c.observe(&message("ubnt_avclient_timeSync", 4, 0, "{}"))?;
    assert_eq!(
        c.observe(&message("ubnt_avclient_timeSync", 5, 0, "{}")),
        Err(Error::TimeSyncLimit)
    );
    let p = c.prepare_time_sync(10, TIME)?;
    assert_eq!(p.id(), 1);
    c.observe(&message("ubnt_avclient_hello", 6, 0, "{}"))?;
    assert_eq!(c.prepare_hello(TIME), Err(Error::InvalidState));
    c.finish_dispatch(1, Dispatch::Written)?;
    assert_eq!(c.phase(), Phase::HelloObserved);
    assert_eq!(c.prepare_hello(TIME)?.id(), 2);
    Ok(())
}

#[test]
fn retiring_a_session_preserves_unresolved_agreement_and_time_sync_facts() -> TestResult {
    let mut c = controller(1)?;
    c.observe(&message("ubnt_avclient_hello", 6, 0, "{}"))?;
    c.prepare_hello(TIME)?;
    c.finish_dispatch(1, Dispatch::Written)?;
    c.prepare_agreement(TIME, AGREEMENT_DELAY_NS)?;
    c.finish_dispatch(2, Dispatch::Written)?;
    c.observe(&message("ubnt_avclient_timeSync", 7, 0, "{}"))?;
    let retired = c.close();
    assert_eq!(retired.previous_phase, Phase::AwaitAgreementReply);
    assert_eq!(retired.agreement_id, Some(2));
    assert_eq!(retired.time_sync_request_id, Some(7));
    assert_eq!(retired.hello_request_id, None);
    assert_eq!(retired.prepared, None);
    assert_eq!(c.phase(), Phase::Closed);
    Ok(())
}

#[test]
fn malformed_messages_and_unknown_events_do_not_expose_payloads_or_advance() -> TestResult {
    let mut c = controller(1)?;
    assert_eq!(
        c.observe(&vec![b'x'; MAX_MESSAGE_BYTES + 1]),
        Err(Error::InvalidJson)
    );
    assert_eq!(
        c.observe(b"{\"from\":1,\"from\":2}"),
        Err(Error::InvalidJson)
    );
    let string_id = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_hello","messageId":"7","payload":{}}"#;
    assert_eq!(c.observe(string_id), Err(Error::InvalidEnvelope));
    let unknown = message("EventSmartDetect", 8, 0, "{\"private\":\"SECRET_MARKER\"}");
    assert_eq!(c.observe(&unknown)?, Observation::Other);
    assert_eq!(c.phase(), Phase::AwaitHello);
    assert!(!format!("{c:?}").contains("SECRET_MARKER"));
    let zero = message("ubnt_avclient_hello", 0, 0, "{}");
    assert_eq!(c.observe(&zero), Err(Error::InvalidEnvelope));
    assert_eq!(c.phase(), Phase::AwaitHello);
    Ok(())
}

#[test]
fn missing_null_or_zero_hello_version_uses_the_reference_default() -> TestResult {
    for suffix in [
        "",
        ",\"payload\":null",
        ",\"payload\":{\"protocolVersion\":0}",
    ] {
        let mut c = controller(1)?;
        let input = format!(
            "{{\"from\":\"ubnt_avclient\",\"to\":\"UniFiVideo\",\"functionName\":\"ubnt_avclient_hello\",\"messageId\":7{suffix}}}"
        );
        assert_eq!(c.observe(input.as_bytes())?, Observation::Hello);
        let json = fields(c.prepare_hello(TIME)?.bytes())?;
        assert_eq!(
            json.object()
                .and_then(|o| o.get("payload"))
                .and_then(Value::object)
                .and_then(|o| o.get("protocolVersion"))
                .and_then(Value::integer),
            Some(67)
        );
    }
    Ok(())
}

#[test]
fn configuration_timestamp_and_id_exhaustion_fail_before_mutating_state() -> TestResult {
    assert!(Identity::new("FSS\"bad", "12345678-1234-4abc-9abc-123456789abc", "1").is_err());
    assert!(Identity::new("FSS", "not-a-uuid", "1").is_err());
    let mut c = controller(MAX_MESSAGE_ID)?;
    c.observe(&message("ubnt_avclient_hello", 9, 0, "{}"))?;
    assert_eq!(c.prepare_hello("bad"), Err(Error::InvalidConfiguration));
    assert!(c.prepared().is_none());
    assert_eq!(c.phase(), Phase::HelloObserved);
    assert_eq!(c.prepare_hello(TIME)?.id(), MAX_MESSAGE_ID);
    c.finish_dispatch(MAX_MESSAGE_ID, Dispatch::Written)?;
    assert_eq!(
        c.prepare_agreement(TIME, AGREEMENT_DELAY_NS),
        Err(Error::MessageIdExhausted)
    );
    assert_eq!(c.phase(), Phase::AwaitAgreementPreparation);
    assert!(c.prepared().is_none());
    Ok(())
}

#[test]
fn stream_start_targets_only_the_selected_track_and_correlates_reply() -> TestResult {
    let request = stream(VideoChannel::Video2, AudioCodec::Opus)?;
    assert!(!format!("{request:?}").contains("192.0.2.33"));
    assert!(!format!("{request:?}").contains("0123456789abcdef"));
    let mut c = ready()?;
    let prepared = c.prepare_stream_start(&request, TIME)?;
    assert_eq!(prepared.id(), 3);
    assert_eq!(
        prepared.kind(),
        MessageKind::StartStream(VideoChannel::Video2)
    );
    assert!(!format!("{prepared:?}").contains("192.0.2.33"));
    let json = fields(prepared.bytes())?;
    let root = json.object().ok_or("root")?;
    assert_eq!(
        root.get("functionName").and_then(Value::text),
        Some("ChangeVideoSettings")
    );
    assert_eq!(
        root.get("responseExpected").and_then(Value::boolean),
        Some(true)
    );
    let tracks = root
        .get("payload")
        .and_then(Value::object)
        .and_then(|p| p.get("video"))
        .and_then(Value::object)
        .ok_or("video")?;
    assert_eq!(tracks.len(), 1);
    let track = tracks
        .get("video2")
        .and_then(Value::object)
        .ok_or("track")?;
    assert_eq!(track.get("type").and_then(Value::text), Some("h264"));
    let serializer = track
        .get("avSerializer")
        .and_then(Value::object)
        .ok_or("serializer")?;
    assert_eq!(
        serializer.get("type").and_then(Value::text),
        Some("extendedFlv")
    );
    let params = serializer
        .get("parameters")
        .and_then(Value::object)
        .ok_or("params")?;
    assert_eq!(params.get("withOpus").and_then(Value::boolean), Some(true));
    assert_eq!(
        params.get("opusSampleRate").and_then(Value::integer),
        Some(48000)
    );
    assert_eq!(
        params.get("streamName").and_then(Value::text),
        Some("0123456789abcdef")
    );
    let destinations = serializer
        .get("destinations")
        .and_then(Value::array)
        .ok_or("destinations")?;
    assert_eq!(destinations.len(), 1);
    assert_eq!(
        destinations[0].text(),
        Some("tcp://192.0.2.33:17551?retryInterval=1&connectTimeout=5")
    );
    c.finish_dispatch(3, Dispatch::Written)?;
    assert_eq!(
        c.prepare_stream_start(&request, TIME),
        Err(Error::InvalidState)
    );
    assert_eq!(
        c.observe(&message("ChangeVideoSettings", 9, 2, "{}")),
        Err(Error::UnexpectedMessage)
    );
    assert_eq!(
        c.observe(&message(
            "ChangeVideoSettings",
            9,
            3,
            "{\"statusCode\":\"1\"}"
        )),
        Err(Error::InvalidEnvelope)
    );
    c.observe(&message("ubnt_avclient_timeSync", 10, 0, "{}"))?;
    c.prepare_time_sync(55, TIME)?;
    c.finish_dispatch(4, Dispatch::Written)?;
    assert_eq!(
        c.observe(&message(
            "ChangeVideoSettings",
            11,
            3,
            "{\"statusCode\":5,\"success\":false,\"secret\":\"PRIVATE\"}"
        ))?,
        Observation::StreamSettingsReply {
            request_id: 3,
            channel: VideoChannel::Video2,
            status_code: Some(5),
            success: Some(false)
        }
    );
    assert!(!format!("{c:?}").contains("PRIVATE"));
    assert_eq!(c.prepare_stream_start(&request, TIME)?.id(), 5);
    Ok(())
}

#[test]
fn stream_effect_retirement_distinguishes_unwritten_uncertain_and_awaiting_reply() -> TestResult {
    let request = stream(VideoChannel::Video1, AudioCodec::Aac)?;
    let mut c = ready()?;
    let p = c.prepare_stream_start(&request, TIME)?;
    let original = p.bytes().to_vec();
    let json = fields(&original)?;
    let params = json
        .object()
        .and_then(|o| o.get("payload"))
        .and_then(Value::object)
        .and_then(|o| o.get("video"))
        .and_then(Value::object)
        .and_then(|o| o.get("video1"))
        .and_then(Value::object)
        .and_then(|o| o.get("avSerializer"))
        .and_then(Value::object)
        .and_then(|o| o.get("parameters"))
        .and_then(Value::object)
        .ok_or("params")?;
    assert_eq!(params.get("withOpus").and_then(Value::boolean), Some(false));
    assert!(params.get("opusSampleRate").is_none());
    c.finish_dispatch(3, Dispatch::NotWritten)?;
    assert_eq!(c.prepared().ok_or("prepared")?.bytes(), original);
    c.finish_dispatch(3, Dispatch::Indeterminate)?;
    let retired = c.close();
    assert_eq!(retired.previous_phase, Phase::Indeterminate);
    assert_eq!(
        retired.prepared,
        Some((3, MessageKind::StartStream(VideoChannel::Video1)))
    );
    assert_eq!(retired.stream_request, None);

    let mut c = ready()?;
    c.prepare_stream_start(&request, TIME)?;
    c.finish_dispatch(3, Dispatch::Written)?;
    let retired = c.close();
    assert_eq!(retired.stream_request, Some((3, VideoChannel::Video1)));
    assert_eq!(retired.prepared, None);
    Ok(())
}

#[test]
fn stream_start_rejects_invalid_inputs_and_requires_completed_agreement() -> TestResult {
    let address = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 33), 17551);
    for bad in ["", "123", "0123456789ABCDEf", "0123456789abcde\""] {
        assert!(
            StreamStart::new(
                VideoChannel::Video3,
                address,
                VideoCodec::H265,
                AudioCodec::Aac,
                bad
            )
            .is_err()
        );
    }
    for bad in [
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 1),
        SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 1), 1),
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 33), 0),
    ] {
        assert!(
            StreamStart::new(
                VideoChannel::Video3,
                bad,
                VideoCodec::H265,
                AudioCodec::Aac,
                "0123456789abcdef"
            )
            .is_err()
        );
    }
    let request = stream(VideoChannel::Video3, AudioCodec::Aac)?;
    let mut c = controller(1)?;
    assert_eq!(
        c.prepare_stream_start(&request, TIME),
        Err(Error::InvalidState)
    );
    assert!(c.prepared().is_none());
    Ok(())
}

#[test]
fn hevc_request_uses_the_selected_track_and_an_empty_reply_is_not_success() -> TestResult {
    let request = StreamStart::new(
        VideoChannel::Video3,
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 44), 17552),
        VideoCodec::H265,
        AudioCodec::Aac,
        "abcdef0123456789",
    )?;
    let mut c = ready()?;
    let json = fields(c.prepare_stream_start(&request, TIME)?.bytes())?;
    let tracks = json
        .object()
        .and_then(|o| o.get("payload"))
        .and_then(Value::object)
        .and_then(|o| o.get("video"))
        .and_then(Value::object)
        .ok_or("video")?;
    assert_eq!(tracks.len(), 1);
    assert_eq!(
        tracks
            .get("video3")
            .and_then(Value::object)
            .and_then(|o| o.get("type"))
            .and_then(Value::text),
        Some("h265")
    );
    c.finish_dispatch(3, Dispatch::Written)?;
    assert_eq!(
        c.observe(&message("ChangeVideoSettings", 9, 3, "{}"))?,
        Observation::StreamSettingsReply {
            request_id: 3,
            channel: VideoChannel::Video3,
            status_code: None,
            success: None
        }
    );
    Ok(())
}

#[test]
fn stream_intent_binds_exact_request_and_owner_supplied_preconditions() -> TestResult {
    use fss_core::{ContentDigest, DigestAlgorithm};
    use fss_reference::unifi_direct::intent::{Error as IntentError, Intent, Preconditions};
    let conditions = Preconditions {
        camera: ContentDigest::sha256(b"fixture identity"),
        peer_admission: ContentDigest::sha256(b"fixture peer admission"),
        stream_generation: 9,
        previous_settings: Some(ContentDigest::sha256(b"fixture settings readback")),
        lease_fence: 12,
    };
    let mut first = ready()?;
    let request = stream(VideoChannel::Video2, AudioCodec::Aac)?;
    let prepared = first.prepare_stream_start(&request, TIME)?;
    let intent = Intent::new(prepared, conditions)?;
    assert_eq!(intent.message_id(), 3);
    assert_eq!(intent.channel(), VideoChannel::Video2);
    intent.check_message(prepared)?;
    intent.check_preconditions(conditions)?;
    assert_eq!(
        intent.check_preconditions(Preconditions {
            lease_fence: 13,
            ..conditions
        }),
        Err(IntentError::Mismatch)
    );
    assert_eq!(
        intent.request_digest(),
        ContentDigest::sha256(prepared.bytes())
    );
    let changed_conditions = Intent::new(
        prepared,
        Preconditions {
            lease_fence: 13,
            ..conditions
        },
    )?;
    assert_ne!(
        intent.precondition_digest(),
        changed_conditions.precondition_digest()
    );
    assert_eq!(intent.request_digest(), changed_conditions.request_digest());
    let unknown_old = Intent::new(
        prepared,
        Preconditions {
            previous_settings: None,
            ..conditions
        },
    )?;
    assert_ne!(
        intent.precondition_digest(),
        unknown_old.precondition_digest()
    );
    assert_eq!(
        Intent::new(
            prepared,
            Preconditions {
                camera: ContentDigest::new(DigestAlgorithm::Sha256, [0; 32]),
                ..conditions
            }
        ),
        Err(IntentError::Preconditions)
    );
    let mut second = ready()?;
    let other = stream(VideoChannel::Video3, AudioCodec::Aac)?;
    let different = second.prepare_stream_start(&other, TIME)?;
    assert_eq!(intent.check_message(different), Err(IntentError::Mismatch));
    assert!(!format!("{intent:?}").contains("0123456789abcdef"));
    let mut hello = controller(1)?;
    hello.observe(&message("ubnt_avclient_hello", 7, 0, "{}"))?;
    assert_eq!(
        Intent::new(hello.prepare_hello(TIME)?, conditions),
        Err(IntentError::WrongMessage)
    );
    Ok(())
}
