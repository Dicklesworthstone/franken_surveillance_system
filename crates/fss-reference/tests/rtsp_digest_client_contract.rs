#![forbid(unsafe_code)]
//! RTSP Digest client challenge retries, CSeq/nonce advancement and bounded, non-extending expiry.
use fss_reference::rtsp::authentication::*;
use fss_reference::rtsp::client::authenticated::DigestClientError as E;
use fss_reference::rtsp::client::*;
use fss_reference::rtsp::{RtspEvent, RtspParser, RtspResponse};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn config() -> ClientConfig {
    ClientConfig {
        presentation_uri: "rtsp://camera.local/live/?profile=main".into(),
        control_root_uri: "rtsp://camera.local/live".into(),
        media_index: 0,
        channels: (0, 1),
        response_timeout_ns: 100,
        default_session_timeout_seconds: 60,
    }
}
fn client() -> Result<RtspClientSession, Box<dyn std::error::Error>> {
    let mut c = RtspClientSession::new(config())?;
    c.enable_digest("camera", DigestPolicy::default())?;
    Ok(c)
}
fn credentials() -> Result<DigestCredentials<'static>, AuthenticationError> {
    DigestCredentials::new("operator", "owner-password")
}
fn challenge(cseq: u32, nonce: &str, extra: &str) -> Vec<u8> {
    format!("RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\nWWW-Authenticate: Digest realm=\"camera\", nonce=\"{nonce}\", algorithm=SHA-256, qop=\"auth\"{extra}\r\nContent-Length: 0\r\n\r\n").into_bytes()
}
fn response(
    seq: u32,
    headers: &str,
    body: &str,
) -> Result<RtspResponse, Box<dyn std::error::Error>> {
    let raw = format!(
        "RTSP/1.0 200 OK\r\nCSeq: {seq}\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len()
    );
    match RtspParser::new().feed(raw.as_bytes())?.pop() {
        Some(RtspEvent::Response(r)) => Ok(r),
        _ => Err("missing response".into()),
    }
}
fn sdp() -> &'static str {
    "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\na=control:trackID=0\r\n"
}
#[test]
fn challenge_retry_then_preemptive_requests_advance_nonce_and_cseq() -> TestResult {
    let mut c = client()?;
    let creds = credentials()?;
    let first = c.request_digest(ClientCommand::Options, &creds, [1; 16], 0)?;
    assert!(!std::str::from_utf8(first.bytes())?.contains("Authorization:"));
    let retry = c.retry_digest_response(&challenge(1, "nonce-1", ""), &creds, [2; 16], 5)?;
    assert_eq!(retry.cseq(), 2);
    assert_eq!(retry.command(), ClientCommand::Options);
    let text = std::str::from_utf8(retry.bytes())?;
    assert!(
        text.starts_with("OPTIONS rtsp://camera.local/live/?profile=main RTSP/1.0\r\nCSeq: 2\r\n")
    );
    assert!(text.contains("nc=00000001"));
    assert!(!text.contains("owner-password"));
    assert_eq!(c.next_wake_ns(), Some(100));
    c.accept(&response(2, "", "")?, 6)?;
    let next = c.request_digest(ClientCommand::Describe, &creds, [3; 16], 7)?;
    assert_eq!(next.cseq(), 3);
    assert!(std::str::from_utf8(next.bytes())?.contains("nc=00000002"));
    Ok(())
}
#[test]
fn wrong_or_replayed_cseq_cannot_consume_the_pending_request() -> TestResult {
    let mut c = client()?;
    let creds = credentials()?;
    c.request_digest(ClientCommand::Options, &creds, [1; 16], 0)?;
    assert!(matches!(
        c.retry_digest_response(&challenge(9, "n", ""), &creds, [2; 16], 2),
        Err(E::Session(ClientError::CseqMismatch))
    ));
    let retry = c.retry_digest_response(&challenge(1, "n", ""), &creds, [2; 16], 3)?;
    assert_eq!(retry.cseq(), 2);
    assert!(matches!(
        c.accept(&response(1, "", "")?, 4),
        Err(ClientError::CseqMismatch)
    ));
    assert!(matches!(
        c.retry_digest_response(&challenge(1, "n", ""), &creds, [2; 16], 4),
        Err(E::Session(ClientError::CseqMismatch))
    ));
    c.accept(&response(2, "", "")?, 4)?;
    Ok(())
}
#[test]
fn stale_nonce_retries_are_bounded_without_deadline_extension() -> TestResult {
    let mut c = client()?;
    let creds = credentials()?;
    c.request_digest(ClientCommand::Options, &creds, [1; 16], 10)?;
    c.retry_digest_response(&challenge(1, "first", ""), &creds, [2; 16], 20)?;
    assert!(matches!(
        c.retry_digest_response(&challenge(2, "second", ""), &creds, [3; 16], 30),
        Err(E::Authentication(AuthenticationError::Replay))
    ));
    let stale =
        c.retry_digest_response(&challenge(2, "second", ", stale=true"), &creds, [3; 16], 30)?;
    assert_eq!(stale.cseq(), 3);
    assert_eq!(c.next_wake_ns(), Some(110));
    assert!(matches!(
        c.retry_digest_response(&challenge(3, "third", ", stale=true"), &creds, [4; 16], 40),
        Err(E::Authentication(AuthenticationError::RetryLimit))
    ));
    assert_eq!(c.tick(110), Err(ClientError::ResponseTimeout));
    assert_eq!(c.state(), ClientState::Failed);
    Ok(())
}
#[test]
fn late_matching_challenge_cannot_escape_expiry() -> TestResult {
    let mut c = client()?;
    let creds = credentials()?;
    c.request_digest(ClientCommand::Options, &creds, [1; 16], 0)?;
    assert!(matches!(
        c.retry_digest_response(&challenge(1, "n", ""), &creds, [2; 16], 100),
        Err(E::Session(ClientError::ResponseTimeout))
    ));
    assert_eq!(c.state(), ClientState::Failed);
    Ok(())
}
#[test]
fn wrong_realm_basic_proxy_and_duplicate_challenges_are_refused() -> TestResult {
    let mut c = client()?;
    let creds = credentials()?;
    c.request_digest(ClientCommand::Options, &creds, [1; 16], 0)?;
    let valid = String::from_utf8(challenge(1, "n", ""))?;
    for bad in [
        valid.replace("realm=\"camera\"", "realm=\"other\""),
        valid.replace("Digest realm", "Basic realm"),
        valid.replace("401 Unauthorized", "407 Proxy Authentication Required"),
        valid.replace(
            "Content-Length: 0",
            "WWW-Authenticate: Basic realm=\"camera\"\r\nContent-Length: 0",
        ),
    ] {
        assert!(
            c.retry_digest_response(bad.as_bytes(), &creds, [2; 16], 1)
                .is_err()
        );
    }
    assert_eq!(
        c.retry_digest_response(valid.as_bytes(), &creds, [2; 16], 2)?
            .cseq(),
        2
    );
    Ok(())
}
#[test]
fn partial_and_concatenated_responses_are_never_consumed() -> TestResult {
    let valid = challenge(1, "n", "");
    let creds = credentials()?;
    let mut c = client()?;
    c.request_digest(ClientCommand::Options, &creds, [1; 16], 0)?;
    for cut in 0..valid.len() {
        assert!(
            c.retry_digest_response(&valid[..cut], &creds, [2; 16], 1)
                .is_err()
        );
    }
    let mut suffixed = valid.clone();
    suffixed.extend_from_slice(b"$\x00\x00\x00");
    assert!(
        c.retry_digest_response(&suffixed, &creds, [2; 16], 1)
            .is_err()
    );
    assert_eq!(
        c.retry_digest_response(&valid, &creds, [2; 16], 1)?.cseq(),
        2
    );
    Ok(())
}
#[test]
fn digest_mode_cannot_silently_fall_back_or_be_reconfigured() -> TestResult {
    let mut c = client()?;
    assert!(matches!(
        c.request(ClientCommand::Describe, 0),
        Err(ClientError::Authentication(_))
    ));
    assert!(c.enable_digest("changed", DigestPolicy::default()).is_err());
    c.request_digest(ClientCommand::Options, &credentials()?, [1; 16], 0)?;
    let closed = c.cancel();
    assert_eq!(closed.pending_cseq, Some(1));
    assert!(
        c.request_digest(ClientCommand::Options, &credentials()?, [1; 16], 1)
            .is_err()
    );
    Ok(())
}
#[test]
fn retired_nonce_cannot_be_reused_by_reformatting_a_later_challenge() -> TestResult {
    let mut c = client()?;
    let creds = credentials()?;
    c.request_digest(ClientCommand::Options, &creds, [1; 16], 0)?;
    c.retry_digest_response(&challenge(1, "n1", ""), &creds, [2; 16], 1)?;
    c.retry_digest_response(&challenge(2, "n2", ", stale=true"), &creds, [3; 16], 2)?;
    c.accept(&response(3, "", "")?, 3)?;
    c.request_digest(ClientCommand::Options, &creds, [4; 16], 4)?;
    assert!(matches!(
        c.retry_digest_response(
            &challenge(4, "n1", ", opaque=\"different\", stale=true"),
            &creds,
            [5; 16],
            5
        ),
        Err(E::Authentication(AuthenticationError::Replay))
    ));
    Ok(())
}
#[test]
fn server_domain_never_changes_the_signed_request_target() -> TestResult {
    let mut c = client()?;
    let creds = credentials()?;
    c.request_digest(ClientCommand::Options, &creds, [1; 16], 0)?;
    let req = c.retry_digest_response(
        &challenge(1, "n", ", domain=\"rtsp://unrelated.example/\""),
        &creds,
        [2; 16],
        1,
    )?;
    let wire = std::str::from_utf8(req.bytes())?;
    assert!(!wire.contains("unrelated.example"));
    assert!(wire.contains("uri=\"rtsp://camera.local/live/?profile=main\""));
    Ok(())
}
#[test]
fn authenticated_describe_setup_play_and_teardown_preserve_session_lifecycle() -> TestResult {
    let mut c = client()?;
    let creds = credentials()?;
    c.request_digest(ClientCommand::Describe, &creds, [1; 16], 0)?;
    c.retry_digest_response(&challenge(1, "n", ""), &creds, [2; 16], 1)?;
    c.accept(&response(2, "Content-Type: application/sdp\r\n", sdp())?, 2)?;
    let setup = c.request_digest(ClientCommand::Setup, &creds, [3; 16], 3)?;
    assert!(
        std::str::from_utf8(setup.bytes())?
            .contains("SETUP rtsp://camera.local/live/trackID=0 RTSP/1.0")
    );
    c.accept(&response(3, "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n", "")?, 4)?;
    c.request_digest(ClientCommand::Play, &creds, [4; 16], 5)?;
    c.accept(&response(4, "Session: fixture\r\n", "")?, 6)?;
    assert_eq!(c.state(), ClientState::Playing);
    c.request_digest(ClientCommand::Teardown, &creds, [5; 16], 7)?;
    let raw = String::from_utf8(challenge(5, "fresh", ", stale=true"))?
        .replace("Content-Length: 0", "Session: fixture\r\nContent-Length: 0");
    let retry = c.retry_digest_response(raw.as_bytes(), &creds, [6; 16], 8)?;
    assert_eq!(c.state(), ClientState::Closing);
    assert_eq!(retry.cseq(), 6);
    assert!(std::str::from_utf8(retry.bytes())?.contains("Session: fixture\r\n"));
    c.accept(&response(6, "Session: fixture\r\n", "")?, 9)?;
    assert_eq!(c.state(), ClientState::Closed);
    assert!(!c.cancel().remote_session_may_exist);
    Ok(())
}
#[test]
fn debug_on_authenticated_session_and_wire_request_is_redacted() -> TestResult {
    let mut c = client()?;
    let creds = credentials()?;
    c.request_digest(ClientCommand::Options, &creds, [1; 16], 0)?;
    let req = c.retry_digest_response(&challenge(1, "private-nonce", ""), &creds, [2; 16], 1)?;
    let text = format!("{c:?} {req:?}");
    for secret in [
        "private-nonce",
        "operator",
        "owner-password",
        "Authorization:",
        "camera.local",
    ] {
        assert!(!text.contains(secret));
    }
    Ok(())
}
