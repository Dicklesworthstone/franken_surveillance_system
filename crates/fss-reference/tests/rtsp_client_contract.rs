#![forbid(unsafe_code)]
//! Session contracts use the existing parser, not a parallel RTSP wire grammar.

use fss_reference::rtsp::{AuthScheme, RtspEvent, RtspHeaders, RtspParser, RtspResponse};
use fss_reference::rtsp::client::{
    ClientChannel, ClientCommand as C, ClientConfig, ClientError as E,
    ClientProgress as P, ClientState as S, RtspClientSession,
};
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config() -> ClientConfig {
    ClientConfig {
        presentation_uri: "rtsp://camera.local/live/".into(),
        control_root_uri: "rtsp://camera.local/live".into(),
        media_index: 0, channels: (0, 1), response_timeout_ns: 10_000_000_000,
        default_session_timeout_seconds: 60,
    }
}
fn sdp() -> String {
    concat!("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\n",
        "m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n",
        "a=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\n",
        "a=control:trackID=0\r\n").into()
}
fn response(cseq: u32, status: u16, fields: &[(&str, &str)], body: &[u8]) -> RtspResponse {
    let mut headers = RtspHeaders::new();
    headers.insert("CSeq", cseq.to_string());
    headers.insert("Content-Length", body.len().to_string());
    for (k, v) in fields { headers.insert(*k, *v); }
    RtspResponse { version: "RTSP/1.0".into(), status_code: status, reason: "OK".into(),
        headers, body: body.to_vec(), auth_challenge: None }
}
fn described() -> Result<RtspClientSession, Box<dyn std::error::Error>> {
    let mut c = RtspClientSession::new(config())?;
    c.request(C::Describe, 0)?;
    c.accept(&response(1, 200, &[("Content-Type", "application/sdp")], sdp().as_bytes()), 1)?;
    Ok(c)
}
fn ready() -> Result<RtspClientSession, Box<dyn std::error::Error>> {
    let mut c = described()?;
    c.request(C::Setup, 2)?;
    c.accept(&response(2, 200, &[("Session", "opaque-token;timeout=60"),
        ("Transport", "RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=00000007")], &[]), 3)?;
    Ok(c)
}
fn playing() -> Result<RtspClientSession, Box<dyn std::error::Error>> {
    let mut c = ready()?;
    c.request(C::Play, 4)?;
    c.accept(&response(3, 200, &[("Session", "opaque-token")], &[]), 5)?;
    Ok(c)
}

#[test]
fn complete_negotiation_has_exact_requests_and_no_early_media() -> TestResult {
    let mut c = RtspClientSession::new(config())?;
    assert_eq!(c.admit_channel(0, 0), Err(E::MediaNotAdmitted));
    let options = c.request(C::Options, 0)?;
    assert_eq!(options.bytes(), b"OPTIONS rtsp://camera.local/live/ RTSP/1.0\r\nCSeq: 1\r\n\r\n");
    c.accept(&response(1, 200, &[], &[]), 1)?;
    assert_eq!(c.state(), S::Idle);
    let describe = c.request(C::Describe, 2)?;
    assert!(std::str::from_utf8(describe.bytes())?.contains("Accept: application/sdp\r\n"));
    c.accept(&response(2, 200, &[("Content-Type", "application/sdp")], sdp().as_bytes()), 3)?;
    let setup = c.request(C::Setup, 4)?;
    assert!(std::str::from_utf8(setup.bytes())?.starts_with("SETUP rtsp://camera.local/live/trackID=0 "));
    c.accept(&response(3, 200, &[("Session", "opaque-token;timeout=60"),
        ("Transport", "RTP/AVP/TCP;unicast;interleaved=0-1")], &[]), 5)?;
    assert_eq!(c.admit_channel(0, 5), Err(E::MediaNotAdmitted));
    c.request(C::Play, 6)?;
    assert_eq!(c.admit_channel(0, 6), Err(E::MediaNotAdmitted));
    assert_eq!(c.accept(&response(4, 200, &[("Session", "opaque-token")], &[]), 7)?, P::Accepted(S::Playing));
    assert_eq!(c.admit_channel(0, 7)?, ClientChannel::Rtp);
    assert_eq!(c.admit_channel(1, 7)?, ClientChannel::Rtcp);
    assert_eq!(c.admit_channel(2, 7), Err(E::MediaNotAdmitted));
    Ok(())
}

#[test]
fn invalid_order_and_concurrent_requests_do_not_consume_cseq() -> TestResult {
    let mut c = RtspClientSession::new(config())?;
    assert_eq!(c.request(C::Play, 0).err(), Some(E::State));
    assert_eq!(c.request(C::Describe, 0)?.cseq(), 1);
    assert_eq!(c.request(C::Describe, 0).err(), Some(E::State));
    assert_eq!(c.accept(&response(9, 200, &[], &[]), 1), Err(E::CseqMismatch));
    assert_eq!(c.next_wake_ns(), Some(10_000_000_000));
    Ok(())
}

#[test]
fn matching_response_replay_and_changed_session_are_refused() -> TestResult {
    let mut c = ready()?;
    c.request(C::Play, 4)?;
    assert_eq!(c.accept(&response(2, 200, &[("Session", "opaque-token")], &[]), 5), Err(E::CseqMismatch));
    assert_eq!(c.accept(&response(3, 200, &[("Session", "other-token")], &[]), 5), Err(E::Session));
    assert_eq!(c.state(), S::Failed);
    assert!(c.cancel().remote_session_may_exist);
    Ok(())
}

#[test]
fn timeout_is_exact_and_interim_responses_do_not_extend_it() -> TestResult {
    let mut c = RtspClientSession::new(config())?;
    c.request(C::Describe, 0)?;
    assert_eq!(c.accept(&response(1, 100, &[], &[]), 9_999_999_999)?, P::Interim);
    assert_eq!(c.tick(10_000_000_000), Err(E::ResponseTimeout));
    assert_eq!(c.request(C::Describe, 10_000_000_000).err(), Some(E::State));
    assert_eq!(c.cancel().pending_cseq, Some(1));
    Ok(())
}

#[test]
fn session_lifetime_uses_issue_time_not_delayed_ack_time() -> TestResult {
    let mut c = described()?;
    c.request(C::Setup, 2)?;
    c.accept(&response(2, 200, &[("Session", "opaque-token;timeout=2"),
        ("Transport", "RTP/AVP/TCP;unicast;interleaved=0-1")], &[]), 1_500_000_002)?;
    assert_eq!(c.tick(1_500_000_002)?, P::KeepAliveDue);
    assert_eq!(c.tick(2_000_000_002), Err(E::SessionExpired));
    Ok(())
}

#[test]
fn keepalive_is_explicit_and_does_not_drop_playing_state() -> TestResult {
    let mut c = playing()?;
    assert_eq!(c.tick(30_000_000_004)?, P::KeepAliveDue);
    let request = c.request(C::KeepAlive, 30_000_000_004)?;
    assert_eq!(request.cseq(), 4);
    assert!(request.bytes().starts_with(b"OPTIONS "));
    assert_eq!(c.admit_channel(0, 30_000_000_005)?, ClientChannel::Rtp);
    c.accept(&response(4, 200, &[], &[]), 30_000_000_006)?;
    assert_eq!(c.state(), S::Playing);
    assert_eq!(c.next_wake_ns(), Some(60_000_000_004));
    Ok(())
}

#[test]
fn teardown_and_cancel_distinguish_local_and_remote_closure() -> TestResult {
    let mut c = playing()?;
    c.request(C::Teardown, 6)?;
    assert_eq!(c.state(), S::Closing);
    assert_eq!(c.admit_channel(0, 6), Err(E::MediaNotAdmitted));
    c.accept(&response(4, 200, &[("Session", "opaque-token")], &[]), 7)?;
    assert!(!c.cancel().remote_session_may_exist);
    let mut c = described()?;
    c.request(C::Setup, 2)?;
    let receipt = c.cancel();
    assert!(receipt.remote_session_may_exist);
    assert_eq!(receipt.pending_cseq, Some(2));
    assert_eq!(c.next_wake_ns(), None);
    Ok(())
}

#[test]
fn credentials_and_redirects_never_create_authority_or_echo_input() -> TestResult {
    let mut cfg = config(); cfg.presentation_uri = "rtsp://name:secret@camera.local/live/".into();
    assert_eq!(RtspClientSession::new(cfg).err(), Some(E::UriScope));
    for status in [301, 302, 401, 407, 454, 461, 500] {
        let mut c = described()?; c.request(C::Setup, 2)?;
        let mut r = response(2, status, &[("Location", "rtsp://hostile.local/private")], &[]);
        r.auth_challenge = Some(AuthScheme::Digest);
        assert!(c.accept(&r, 3).is_err());
        assert_eq!(c.state(), S::Failed);
        assert!(!format!("{c:?}").contains("hostile"));
    }
    Ok(())
}

#[test]
fn malformed_duplicate_and_changed_transport_are_fail_closed() -> TestResult {
    for transport in [
        "RTP/AVP;unicast;client_port=5000-5001",
        "RTP/AVP/TCP;multicast;interleaved=0-1",
        "RTP/AVP/TCP;unicast;interleaved=2-3",
        "RTP/AVP/TCP;unicast;interleaved=0-1;interleaved=0-1",
        "RTP/AVP/TCP;unicast;interleaved=0-1;mode=RECORD",
        "RTP/AVP/TCP;unicast;interleaved=0-1;destination=other",
        "RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=XYZ",
        "RTP/AVP/TCP;unicast;interleaved=0-1,RTP/AVP/TCP;unicast;interleaved=0-1",
    ] {
        let mut c = described()?; c.request(C::Setup, 2)?;
        assert_eq!(c.accept(&response(2, 200, &[("Session", "opaque-token"), ("Transport", transport)], &[]), 3), Err(E::Transport));
        assert_eq!(c.state(), S::Failed);
    }
    Ok(())
}

#[test]
fn session_token_and_timeout_grammar_are_strict() -> TestResult {
    for value in ["", "token;timeout=0", "token;timeout=3601", "token;timeout=+1",
        "token;timeout=60;timeout=60", "bad token;timeout=60", "token;other=secret"] {
        let mut c = described()?; c.request(C::Setup, 2)?;
        assert_eq!(c.accept(&response(2, 200, &[("Session", value),
            ("Transport", "RTP/AVP/TCP;unicast;interleaved=0-1")], &[]), 3), Err(E::Session));
    }
    Ok(())
}

#[test]
fn media_selection_and_duplicate_sdp_attributes_are_refused() -> TestResult {
    let original = sdp();
    for body in [
        original.replace("m=video", "m=audio"), original.replace("90000", "8000"),
        original.replace("packetization-mode=1", "packetization-mode=2"),
        original.replace("RTP/AVP 96", "RTP/AVP 96 97"),
        original.replace("a=control:trackID=0", "a=control:trackID=0\r\na=control:trackID=1"),
        original.replace("packetization-mode=1", "packetization-mode=1;packetization-mode=0"),
        original.replace("a=rtpmap:96 H264/90000", "a=rtpmap:96 H264/90000\r\na=rtpmap:96 H264/90000"),
    ] {
        let mut c = RtspClientSession::new(config())?; c.request(C::Describe, 0)?;
        assert_eq!(c.accept(&response(1, 200, &[("Content-Type", "application/sdp")], body.as_bytes()), 1), Err(E::Description));
    }
    Ok(())
}

#[test]
fn control_urls_cannot_escape_the_explicit_subtree() -> TestResult {
    for control in ["rtsp://other.local/live/track", "/admin", "../admin", "//other/live",
        "rtsp://camera.local/live-secret/track", "%2e%2e/admin", "track#secret", "track%0d%0aHeader"] {
        let body = sdp().replace("trackID=0", control);
        let mut c = RtspClientSession::new(config())?; c.request(C::Describe, 0)?;
        assert_eq!(c.accept(&response(1, 200, &[("Content-Type", "application/sdp")], body.as_bytes()), 1), Err(E::UriScope));
    }
    Ok(())
}

#[test]
fn content_base_is_validated_and_relative_control_resolution_is_exact() -> TestResult {
    let mut c = RtspClientSession::new(config())?; c.request(C::Describe, 0)?;
    c.accept(&response(1, 200, &[("Content-Type", "application/sdp"),
        ("Content-Base", "rtsp://camera.local/live/nested/")], sdp().as_bytes()), 1)?;
    let request = c.request(C::Setup, 2)?;
    assert!(std::str::from_utf8(request.bytes())?.starts_with("SETUP rtsp://camera.local/live/nested/trackID=0 "));
    let mut c = RtspClientSession::new(config())?; c.request(C::Describe, 0)?;
    assert_eq!(c.accept(&response(1, 200, &[("Content-Type", "application/sdp"),
        ("Content-Base", "rtsp://other.local/live/")], sdp().as_bytes()), 1), Err(E::UriScope));
    Ok(())
}

#[test]
fn duplicate_decision_headers_and_wrong_content_length_cannot_advance() -> TestResult {
    for fields in [vec![("Session", "a"), ("Session", "b")],
        vec![("Transport", "RTP/AVP/TCP;unicast;interleaved=0-1"), ("Transport", "RTP/AVP/TCP;unicast;interleaved=0-1")]] {
        let mut c = described()?; c.request(C::Setup, 2)?;
        let mut r = response(2, 200, &[], &[]);
        if !fields.iter().any(|(k, _)| *k == "Session") { r.headers.insert("Session", "a"); }
        for (k, v) in fields { r.headers.insert(k, v); }
        assert_eq!(c.accept(&r, 3), Err(E::Response));
    }
    let mut c = described()?; c.request(C::Setup, 2)?;
    let mut r = response(2, 200, &[], &[]); r.body.push(1);
    assert_eq!(c.accept(&r, 3), Err(E::Response));
    Ok(())
}

#[test]
fn debug_redacts_urls_tokens_and_parameter_sets() -> TestResult {
    let mut c = ready()?;
    let request = c.request(C::Play, 4)?;
    for debug in [format!("{c:?}"), format!("{request:?}"), format!("{:?}", config())] {
        for secret in ["camera.local", "opaque-token", "trackID", "Z0LA"] { assert!(!debug.contains(secret)); }
    }
    assert_eq!(c.server_ssrc(), Some(7));
    Ok(())
}

#[test]
fn clock_reversal_and_deadline_overflow_are_explicit() -> TestResult {
    let mut c = playing()?;
    assert_eq!(c.tick(4), Err(E::ClockReversed));
    assert_eq!(c.state(), S::Playing);
    let mut c = RtspClientSession::new(config())?;
    assert_eq!(c.request(C::Describe, u64::MAX).err(), Some(E::Exhausted));
    assert_eq!(c.cancel().pending_cseq, None);
    Ok(())
}

#[test]
fn every_description_wire_split_reaches_the_same_negotiation() -> TestResult {
    let body = sdp();
    let wire = format!("RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    for split in 0..=wire.len() {
        let mut parser = RtspParser::new();
        let mut events = parser.feed(&wire.as_bytes()[..split])?;
        events.extend(parser.feed(&wire.as_bytes()[split..])?);
        assert_eq!(events.len(), 1);
        let mut c = RtspClientSession::new(config())?; c.request(C::Describe, 0)?;
        let RtspEvent::Response(r) = &events[0] else { return Err("expected parsed response".into()); };
        c.accept(r, 1)?;
        assert_eq!(c.state(), S::Described);
        assert_eq!(c.media().ok_or("missing media")?.payload_type(), 96);
    }
    Ok(())
}

#[test]
fn fmtp_duplicate_spelling_cannot_change_packetization_silently() -> TestResult {
    for duplicate in ["packetization-mode =0", "PACKETIZATION-MODE=0"] {
        let body = sdp().replace("packetization-mode=1", &format!("packetization-mode=1;{duplicate}"));
        let mut c = RtspClientSession::new(config())?;
        c.request(C::Describe, 0)?;
        assert_eq!(c.accept(&response(1, 200, &[("Content-Type", "application/sdp")], body.as_bytes()), 1), Err(E::Description));
    }
    Ok(())
}

#[test]
fn signaled_profile_must_match_exact_sps_profile_constraints_and_level() -> TestResult {
    for profile in ["42c00b", "42C00B", "64000b", "42c00c", "42c00", "42c0GG"] {
        let body = sdp().replace("packetization-mode=1", &format!("packetization-mode=1;profile-level-id={profile}"));
        let mut c = RtspClientSession::new(config())?;
        c.request(C::Describe, 0)?;
        let result = c.accept(&response(1, 200, &[("Content-Type", "application/sdp")], body.as_bytes()), 1);
        if matches!(profile, "42c00b" | "42C00B") {
            assert_eq!(result?, P::Accepted(S::Described));
        } else {
            assert_eq!(result, Err(E::Description));
        }
    }
    Ok(())
}
