#![forbid(unsafe_code)]
//! Exact owner selection before SETUP, with no compressed metadata fallback.

use fss_reference::rtsp::client::{
    ClientCodec, ClientCommand, ClientConfig, ClientError, ClientState, RtspClientSession,
};
use fss_reference::rtsp::framed::RtspWireIntake;
use fss_reference::rtsp::selection::{SelectionError, select_onvif_metadata_description};
use fss_reference::rtsp::{RtspEvent, RtspResponse};

type Test = Result<(), Box<dyn std::error::Error>>;

fn config() -> ClientConfig {
    ClientConfig {
        presentation_uri: "rtsp://camera.local/live/".into(),
        control_root_uri: "rtsp://camera.local/live".into(),
        media_index: 1,
        channels: (4, 5),
        response_timeout_ns: 1_000_000_000,
        default_session_timeout_seconds: 60,
    }
}

fn offer(mapping: &str, extra: &str) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\n\
         m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=control:video\r\n\
         m=application 0 RTP/AVP 106 107 108\r\n\
         a=rtpmap:106 vnd.onvif.metadata+gzip/90000\r\n\
         a=rtpmap:107 {mapping}\r\n\
         a=rtpmap:108 vnd.onvif.metadata.exi.ext/90000\r\n\
         a=control:metadata\r\n{extra}"
    )
}

fn response(body: &str, fields: &str) -> Result<RtspResponse, Box<dyn std::error::Error>> {
    let wire = format!(
        "RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Type: application/sdp\r\n\
         Content-Length: {}\r\n{fields}\r\n{body}",
        body.len()
    );
    let mut intake = RtspWireIntake::new();
    intake.ingest(wire.as_bytes(), 1)?;
    let (event, _, _) = intake.poll(1)?.ok_or("missing response")?.into_parts();
    match event {
        RtspEvent::Response(value) => Ok(value),
        _ => Err("unexpected event".into()),
    }
}

#[test]
fn exact_application_ordinal_and_dynamic_payload_survive_a_mixed_offer() -> Test {
    let source = offer("VND.ONVIF.METADATA/90000", "a=rtcp-rsize\r\n");
    let parsed = select_onvif_metadata_description(source.as_bytes(), 1, 107)?;
    assert_eq!(parsed.media.len(), 2);
    assert_eq!(parsed.media[0].media_type, "video");
    assert_eq!(parsed.media[1].media_type, "application");
    assert_eq!(parsed.media[1].payload_type, 107);
    assert_eq!(
        parsed.media[1].encoding_name.as_deref(),
        Some("vnd.onvif.metadata")
    );
    assert!(parsed.media[1].rtcp_reduced_size);
    assert_eq!(parsed.media[1].control.as_deref(), Some("metadata"));
    assert!(source.contains("vnd.onvif.metadata+gzip"));
    assert!(source.contains("vnd.onvif.metadata.exi.ext"));
    Ok(())
}

#[test]
fn compressed_or_other_clock_and_channel_mappings_never_fall_back() {
    for mapping in [
        "vnd.onvif.metadata+gzip/90000",
        "vnd.onvif.metadata.exi.ext/90000",
        "vnd.onvif.metadata/8000",
        "vnd.onvif.metadata/90000/1",
        "H264/90000",
    ] {
        let source = offer(mapping, "");
        assert_eq!(
            select_onvif_metadata_description(source.as_bytes(), 1, 107),
            Err(SelectionError::Unsupported)
        );
    }
}

#[test]
fn explicit_payload_and_exact_media_are_mandatory() {
    let source = offer("vnd.onvif.metadata/90000", "");
    for payload in [0, 95, 128, 255] {
        assert_eq!(
            select_onvif_metadata_description(source.as_bytes(), 1, payload),
            Err(SelectionError::Payload)
        );
    }
    assert_eq!(
        select_onvif_metadata_description(source.as_bytes(), 1, 109),
        Err(SelectionError::Payload)
    );
    for index in [0, 2] {
        assert_eq!(
            select_onvif_metadata_description(source.as_bytes(), index, 107),
            Err(SelectionError::Media)
        );
    }
    assert_eq!(
        RtspClientSession::with_codec(config(), ClientCodec::OnvifMetadata).err(),
        Some(ClientError::Configuration)
    );
    assert_eq!(
        RtspClientSession::with_codec_and_payload_type(config(), ClientCodec::OnvifMetadata, 95)
            .err(),
        Some(ClientError::Configuration)
    );
}

#[test]
fn selected_unknown_formats_duplicates_and_transport_changes_refuse() {
    for (source, expected) in [
        (
            offer("vnd.onvif.metadata/90000", "a=fmtp:107 unknown=1\r\n"),
            SelectionError::Unsupported,
        ),
        (
            offer(
                "vnd.onvif.metadata/90000",
                "a=rtpmap:107 vnd.onvif.metadata/90000\r\n",
            ),
            SelectionError::Duplicate,
        ),
        (
            offer("vnd.onvif.metadata/90000", "a=control:other\r\n"),
            SelectionError::Duplicate,
        ),
        (
            offer("vnd.onvif.metadata/90000", "").replace("RTP/AVP 106", "RTP/SAVP 106"),
            SelectionError::Media,
        ),
        (
            offer("vnd.onvif.metadata/90000", "").replace("106 107 108", "106 107 107 108"),
            SelectionError::Duplicate,
        ),
    ] {
        assert_eq!(
            select_onvif_metadata_description(source.as_bytes(), 1, 107),
            Err(expected)
        );
    }
}

#[test]
fn negotiated_track_and_controls_remain_bound_to_the_existing_owner_scope() -> Test {
    let mut session =
        RtspClientSession::with_codec_and_payload_type(config(), ClientCodec::OnvifMetadata, 107)?;
    session.request(ClientCommand::Describe, 0)?;
    session.accept(&response(&offer("vnd.onvif.metadata/90000", ""), "")?, 1)?;
    assert_eq!(session.state(), ClientState::Described);
    assert!(session.media().is_none());
    assert!(session.hevc_media().is_none());
    assert_eq!(
        session
            .metadata_media()
            .ok_or("missing metadata")?
            .payload_type(),
        107
    );
    let setup = session.request(ClientCommand::Setup, 2)?;
    let text = std::str::from_utf8(setup.bytes())?;
    assert!(text.starts_with("SETUP rtsp://camera.local/live/metadata RTSP/1.0\r\n"));
    assert!(text.contains("interleaved=4-5"));
    Ok(())
}

#[test]
fn malicious_track_or_base_cannot_redirect_metadata_setup() -> Test {
    for (body, fields) in [
        (
            offer("vnd.onvif.metadata/90000", "").replace(
                "control:metadata",
                "control:rtsp://other.local/live/metadata",
            ),
            "",
        ),
        (
            offer("vnd.onvif.metadata/90000", "").replace("control:metadata", "control:../outside"),
            "",
        ),
        (
            offer("vnd.onvif.metadata/90000", ""),
            "Content-Base: rtsp://other.local/live/\r\n",
        ),
    ] {
        let mut session = RtspClientSession::with_codec_and_payload_type(
            config(),
            ClientCodec::OnvifMetadata,
            107,
        )?;
        session.request(ClientCommand::Describe, 0)?;
        assert_eq!(
            session.accept(&response(&body, fields)?, 1),
            Err(ClientError::UriScope)
        );
        assert_eq!(session.state(), ClientState::Failed);
        assert!(session.request(ClientCommand::Setup, 2).is_err());
    }
    Ok(())
}
