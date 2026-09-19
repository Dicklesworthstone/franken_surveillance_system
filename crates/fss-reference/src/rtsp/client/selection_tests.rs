#![forbid(unsafe_code)]
//! Negotiation regressions through the real RTSP response parser and session.

use super::*;
use crate::rtsp::{RtspEvent, RtspLimits, RtspParser};

const OFFER: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 98 96\r\na=control:trackID=1\r\na=rtpmap:98 H265/90000\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;profile-level-id=42001f;sprop-parameter-sets=Z0IAHw==,aAA=\r\n";

fn config() -> ClientConfig {
    ClientConfig {
        presentation_uri: "rtsp://camera/live/".into(),
        control_root_uri: "rtsp://camera/live/".into(),
        media_index: 0,
        channels: (0, 1),
        response_timeout_ns: SECOND,
        default_session_timeout_seconds: 60,
    }
}

fn describe(
    session: &mut RtspClientSession,
    body: &str,
) -> Result<ClientProgress, ClientError> {
    let request = session.request(ClientCommand::Describe, 0)?;
    let wire = format!(
        "RTSP/1.0 200 OK\r\nCSeq: {}\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{body}",
        request.cseq(),
        body.len(),
    );
    let mut parser = RtspParser::with_limits(RtspLimits {
        max_line_bytes: 2_048,
        max_headers: 32,
        max_body_bytes: 65_536,
        max_interleaved_bytes: 65_535,
    });
    let events = parser.feed(wire.as_bytes()).map_err(|_| ClientError::Response)?;
    for event in events {
        if let RtspEvent::Response(response) = event {
            return session.accept(&response, 1);
        }
    }
    Err(ClientError::Response)
}

#[test]
fn mixed_codec_offer_reaches_scoped_setup() -> Result<(), ClientError> {
    let mut session = RtspClientSession::new(config())?;
    assert_eq!(describe(&mut session, OFFER)?, ClientProgress::Accepted(ClientState::Described));
    let media = session.media().ok_or(ClientError::Description)?;
    assert_eq!(media.payload_type(), 96);
    assert_eq!(media.packetization_mode(), 1);
    assert_eq!(media.parameter_sets(), (&[0x67, 0x42, 0, 0x1f][..], &[0x68, 0][..]));
    let setup = session.request(ClientCommand::Setup, 2)?;
    assert!(setup.bytes().starts_with(b"SETUP rtsp://camera/live/trackID=1 RTSP/1.0\r\n"));
    assert_eq!(setup.cseq(), 2);
    Ok(())
}

#[test]
fn ambiguous_offer_requires_exact_immutable_owner_choice() -> Result<(), ClientError> {
    let offer = OFFER.replace("H265/90000", "H264/90000");
    let mut automatic = RtspClientSession::new(config())?;
    assert_eq!(describe(&mut automatic, &offer), Err(ClientError::Description));
    assert_eq!(automatic.state(), ClientState::Failed);
    assert!(automatic.media().is_none());

    let mut exact = RtspClientSession::new_with_payload_type(config(), 96)?;
    assert_eq!(describe(&mut exact, &offer)?, ClientProgress::Accepted(ClientState::Described));
    assert_eq!(exact.media().ok_or(ClientError::Description)?.payload_type(), 96);
    Ok(())
}

#[test]
fn exact_selection_never_borrows_parameters_or_changes_codec() -> Result<(), ClientError> {
    for (offer, pt) in [
        (OFFER.to_string(), 98),
        (OFFER.to_string(), 97),
        (OFFER.replace("H265/90000", "H264/90000"), 98),
    ] {
        let mut session = RtspClientSession::new_with_payload_type(config(), pt)?;
        assert_eq!(describe(&mut session, &offer), Err(ClientError::Description));
        assert_eq!(session.state(), ClientState::Failed);
        assert!(session.media().is_none());
    }
    assert!(matches!(
        RtspClientSession::new_with_payload_type(config(), 128),
        Err(ClientError::Configuration)
    ));
    Ok(())
}

#[test]
fn original_scope_profile_and_packetization_clamps_still_apply() -> Result<(), ClientError> {
    for offer in [
        OFFER.replace("profile-level-id=42001f", "profile-level-id=64001f"),
        OFFER.replace("packetization-mode=1", "packetization-mode=2"),
        OFFER.replace("H264/90000", "H264/90000/2"),
        OFFER.replace("98 96", "98 96 96"),
    ] {
        let mut session = RtspClientSession::new(config())?;
        assert_eq!(describe(&mut session, &offer), Err(ClientError::Description));
        assert!(session.media().is_none());
    }
    for uri in ["rtsp://other/live/track", "rtsp://camera/outside/track"] {
        let mut session = RtspClientSession::new(config())?;
        assert_eq!(describe(&mut session, &OFFER.replace("trackID=1", uri)), Err(ClientError::UriScope));
        assert!(session.media().is_none());
    }
    Ok(())
}

#[test]
fn choosing_video_after_audio_preserves_owner_media_index() -> Result<(), ClientError> {
    let body = OFFER.replace(
        "m=video",
        "m=audio 0 RTP/AVP 0\r\na=control:audio\r\nm=video",
    );
    let mut owner = config();
    owner.media_index = 1;
    let mut session = RtspClientSession::new(owner)?;
    describe(&mut session, &body)?;
    assert_eq!(session.media().ok_or(ClientError::Description)?.payload_type(), 96);
    Ok(())
}
