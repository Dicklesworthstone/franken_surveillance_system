#![forbid(unsafe_code)]
//! Explicit empty GET_PARAMETER liveness uses the original session/Digest owner.
//! Fixture-only, sans-I/O contracts; no camera or field compatibility is asserted.

use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};
use fss_reference::rtsp::client::authenticated::DigestClientError;
use fss_reference::rtsp::client::{
    ClientCodec, ClientCommand as C, ClientConfig, ClientError, ClientProgress, ClientState,
    RtspClientSession,
};
use fss_reference::rtsp::{RtspEvent, RtspLimits, RtspParser, RtspResponse};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SECOND: u64 = 1_000_000_000;
const URI: &str = "rtsp://camera/live/";

fn config() -> ClientConfig {
    ClientConfig {
        presentation_uri: URI.into(),
        control_root_uri: "rtsp://camera/live".into(),
        media_index: 0,
        channels: (0, 1),
        response_timeout_ns: SECOND,
        default_session_timeout_seconds: 10,
    }
}
fn response(cseq: u32, code: u16, headers: &str, body: &str) -> Test<RtspResponse> {
    let wire = format!(
        "RTSP/1.0 {code} Fixture\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len(),
    );
    let mut parser = RtspParser::with_limits(RtspLimits::default());
    let mut events = parser.feed(wire.as_bytes())?;
    if parser.buffered_bytes() != 0 || events.len() != 1 {
        return Err("fixture response framing".into());
    }
    match events.pop() {
        Some(RtspEvent::Response(response)) => Ok(response),
        _ => Err("fixture response missing".into()),
    }
}
fn credentials() -> Test<DigestCredentials<'static>> {
    Ok(DigestCredentials::new("fixture-user", "fixture-password")?)
}
fn request(session: &mut RtspClientSession, command: C, digest: bool, now: u64) -> Test<u32> {
    Ok(if digest {
        session
            .request_digest(command, &credentials()?, [0x11; 16], now)?
            .cseq()
    } else {
        session.request(command, now)?.cseq()
    })
}
fn ready(codec: ClientCodec, digest: bool) -> Test<RtspClientSession> {
    let mut session = RtspClientSession::with_codec(config(), codec)?;
    if digest {
        session.enable_digest("camera-realm", DigestPolicy::default())?;
    }
    let cseq = request(&mut session, C::Describe, digest, 0)?;
    let media = match codec {
        ClientCodec::H264 => {
            "a=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0IAHw==,aAA=\r\n"
        }
        ClientCodec::H265 => "a=rtpmap:96 H265/90000\r\n",
    };
    let body = format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\n{media}a=control:track\r\n"
    );
    session.accept(
        &response(cseq, 200, "Content-Type: application/sdp\r\n", &body)?,
        1,
    )?;
    let cseq = request(&mut session, C::Setup, digest, 2)?;
    assert_eq!(session.accept(&response(cseq, 200,
        "Session: fixture-session;timeout=10\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n", "")?, 3)?,
        ClientProgress::Accepted(ClientState::Ready));
    Ok(session)
}
fn playing(codec: ClientCodec, digest: bool) -> Test<RtspClientSession> {
    let mut session = ready(codec, digest)?;
    let cseq = request(&mut session, C::Play, digest, 4)?;
    session.accept(&response(cseq, 200, "Session: fixture-session\r\n", "")?, 5)?;
    Ok(session)
}
fn challenge(cseq: u32) -> Vec<u8> {
    format!("RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\nSession: fixture-session\r\nWWW-Authenticate: Digest realm=\"camera-realm\", nonce=\"camera-nonce\", algorithm=SHA-256, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n").into_bytes()
}

#[test]
fn both_codecs_emit_only_empty_scoped_get_parameter_and_keep_original_lifetime() -> Test {
    for codec in [ClientCodec::H264, ClientCodec::H265] {
        let mut session = playing(codec, false)?;
        let due = 4 + 5 * SECOND;
        assert_eq!(session.next_wake_ns(), Some(due));
        assert_eq!(session.tick(due)?, ClientProgress::KeepAliveDue);
        let queued = session.request(C::KeepAliveGetParameter, due)?;
        assert_eq!(queued.command(), C::KeepAliveGetParameter);
        assert_eq!(queued.bytes(), b"GET_PARAMETER rtsp://camera/live/ RTSP/1.0\r\nCSeq: 4\r\nSession: fixture-session\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(session.state(), ClientState::Playing);
        assert_eq!(
            session.accept(&response(queued.cseq(), 200, "", "")?, due + SECOND / 2)?,
            ClientProgress::Accepted(ClientState::Playing)
        );
        // The delayed ACK cannot add half a second to the conservative lifetime.
        assert_eq!(session.next_wake_ns(), Some(due + 5 * SECOND));
        assert_eq!(session.next_expiry_ns(), Some(due + 10 * SECOND));
        assert_eq!(session.codec(), codec);
    }
    Ok(())
}

#[test]
fn legacy_options_wire_is_unchanged_and_liveness_cannot_start_media() -> Test {
    for codec in [ClientCodec::H264, ClientCodec::H265] {
        let mut session = ready(codec, false)?;
        let queued = session.request(C::KeepAlive, 4)?;
        assert_eq!(
            queued.bytes(),
            b"OPTIONS rtsp://camera/live/ RTSP/1.0\r\nCSeq: 3\r\nSession: fixture-session\r\n\r\n"
        );
        session.accept(&response(queued.cseq(), 200, "", "")?, 5)?;
        let queued = session.request(C::KeepAliveGetParameter, 6)?;
        session.accept(
            &response(queued.cseq(), 200, "Session: fixture-session\r\n", "")?,
            7,
        )?;
        assert_eq!(session.state(), ClientState::Ready);
        assert_eq!(
            session.admit_channel(0, 8),
            Err(ClientError::MediaNotAdmitted)
        );
    }
    Ok(())
}

#[test]
fn idle_refusal_does_not_reserve_a_cseq_or_create_remote_session() -> Test {
    let mut session = RtspClientSession::new(config())?;
    assert!(matches!(
        session.request(C::KeepAliveGetParameter, 0),
        Err(ClientError::State)
    ));
    assert_eq!(session.next_wake_ns(), None);
    assert_eq!(session.request(C::Describe, 1)?.cseq(), 1);
    assert!(!session.cancel().remote_session_may_exist);
    Ok(())
}

#[test]
fn pending_interim_and_wrong_cseq_never_extend_request_deadline() -> Test {
    let mut session = playing(ClientCodec::H264, false)?;
    let sent = 10;
    let queued = session.request(C::KeepAliveGetParameter, sent)?;
    let deadline = sent + SECOND;
    assert_eq!(session.next_wake_ns(), Some(deadline));
    assert!(matches!(
        session.request(C::KeepAlive, sent),
        Err(ClientError::State)
    ));
    assert_eq!(
        session.accept(&response(queued.cseq() + 1, 200, "", "")?, sent + 1),
        Err(ClientError::CseqMismatch)
    );
    assert_eq!(
        session.accept(&response(queued.cseq(), 100, "", "")?, sent + 2)?,
        ClientProgress::Interim
    );
    assert_eq!(session.next_wake_ns(), Some(deadline));
    assert_eq!(session.tick(deadline), Err(ClientError::ResponseTimeout));
    assert_eq!(session.state(), ClientState::Failed);
    assert!(session.request(C::KeepAlive, deadline).is_err());
    let retired = session.cancel();
    assert_eq!(retired.pending_cseq, Some(queued.cseq()));
    assert!(retired.remote_session_may_exist);
    Ok(())
}

#[test]
fn wrong_session_and_rejected_method_never_trigger_fallback_or_hide_uncertainty() -> Test {
    for (status, headers, expected) in [
        (200, "Session: other-session\r\n", ClientError::Session),
        (405, "", ClientError::Rejected(405)),
        (501, "", ClientError::Rejected(501)),
    ] {
        let mut session = playing(ClientCodec::H265, false)?;
        let queued = session.request(C::KeepAliveGetParameter, 10)?;
        assert_eq!(
            session.accept(&response(queued.cseq(), status, headers, "")?, 11),
            Err(expected)
        );
        assert_eq!(session.state(), ClientState::Failed);
        assert_eq!(session.next_wake_ns(), None);
        assert!(session.request(C::KeepAlive, 12).is_err());
        assert_eq!(session.cancel().pending_cseq, Some(queued.cseq()));
    }
    Ok(())
}

#[test]
fn challenged_keepalive_signs_actual_method_and_preserves_its_original_deadline() -> Test {
    for codec in [ClientCodec::H264, ClientCodec::H265] {
        let mut session = playing(codec, true)?;
        let sent = 10;
        let unsigned =
            session.request_digest(C::KeepAliveGetParameter, &credentials()?, [0x11; 16], sent)?;
        let raw = challenge(unsigned.cseq());
        let answer =
            session.retry_digest_response(&raw, &credentials()?, [0x11; 16], sent + 100)?;
        assert_eq!(answer.cseq(), unsigned.cseq() + 1);
        assert_eq!(answer.command(), C::KeepAliveGetParameter);
        let wire = std::str::from_utf8(answer.bytes())?;
        assert!(wire.starts_with("GET_PARAMETER rtsp://camera/live/ RTSP/1.0\r\n"));
        assert!(wire.contains("Content-Length: 0\r\n"));
        // Independent hashlib golden: this must not be the OPTIONS A2 digest.
        assert!(wire.contains(
            "response=\"51996cbe55d14cf512ee565900e0c7c27fd1c9c626e1fef8c2a7a33476613e19\""
        ));
        assert_eq!(session.next_expiry_ns(), Some(sent + SECOND));
        let debug = format!("{answer:?}");
        assert!(!debug.contains("fixture-password"));
        assert!(!debug.contains("Authorization:"));
        session.accept(
            &response(answer.cseq(), 200, "Session: fixture-session\r\n", "")?,
            sent + 200,
        )?;
        let next = session.request_digest(
            C::KeepAliveGetParameter,
            &credentials()?,
            [0x22; 16],
            sent + 300,
        )?;
        let next_wire = std::str::from_utf8(next.bytes())?;
        assert!(next_wire.contains("nc=00000002"));
        assert!(next_wire.starts_with("GET_PARAMETER "));
        assert_eq!(session.state(), ClientState::Playing);
    }
    Ok(())
}

#[test]
fn digest_retry_cannot_change_command_or_restart_a_timed_out_request() -> Test {
    let mut session = playing(ClientCodec::H264, true)?;
    let unsigned =
        session.request_digest(C::KeepAliveGetParameter, &credentials()?, [0x11; 16], 10)?;
    assert!(matches!(
        session.request(C::KeepAliveGetParameter, 11),
        Err(ClientError::Authentication(_))
    ));
    let answer = session.retry_digest_response(
        &challenge(unsigned.cseq()),
        &credentials()?,
        [0x11; 16],
        12,
    )?;
    assert!(matches!(
        session.request_digest(C::KeepAlive, &credentials()?, [0x22; 16], 13),
        Err(DigestClientError::Session(ClientError::State))
    ));
    assert_eq!(session.tick(10 + SECOND), Err(ClientError::ResponseTimeout));
    assert!(
        session
            .retry_digest_response(
                &challenge(answer.cseq()),
                &credentials()?,
                [0x33; 16],
                10 + SECOND
            )
            .is_err()
    );
    let retired = session.cancel();
    assert_eq!(retired.pending_cseq, Some(answer.cseq()));
    assert!(retired.remote_session_may_exist);
    Ok(())
}

#[test]
fn keepalive_can_tighten_but_never_delay_expiry_by_ack_receipt_time() -> Test {
    let mut session = playing(ClientCodec::H264, false)?;
    let queued = session.request(C::KeepAliveGetParameter, 10)?;
    session.accept(
        &response(
            queued.cseq(),
            200,
            "Session: fixture-session;timeout=1\r\n",
            "",
        )?,
        SECOND / 2,
    )?;
    assert_eq!(session.next_expiry_ns(), Some(10 + SECOND));
    assert_eq!(session.tick(10 + SECOND), Err(ClientError::SessionExpired));
    assert_eq!(
        session.admit_channel(0, 10 + SECOND),
        Err(ClientError::State)
    );
    Ok(())
}
