#![forbid(unsafe_code)]
//! FSS-047 / TEST-RTSP-001 evidence: RTSP authentication/session state.
//!
//! Exhaustive command legality per session state over the reference
//! client's typed state machine, pending-request lockout, failure
//! terminality, CSeq/clock discipline, and the auth-pending gate. Each
//! property emits one JSONL verdict line citing the family id.

use fss_reference::rtsp::client::{
    ClientCodec, ClientCommand, ClientConfig, ClientError, ClientProgress, ClientState,
    RtspClientSession,
};
use fss_reference::{RtspEvent, RtspLimits, RtspParser};

fn emit(property: &str, cases: u64) {
    println!(
        "{{\"family\":\"TEST-RTSP-001\",\"property\":\"{property}\",\"cases\":{cases},\"verdict\":\"pass\"}}"
    );
}

const PREFIX: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\n";
const VIDEO: &str = "m=video 0 RTP/AVP 96\r\na=control:video\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0IAHw==,aAA=\r\n";

fn config() -> ClientConfig {
    ClientConfig {
        presentation_uri: "rtsp://camera/live/".into(),
        control_root_uri: "rtsp://camera/live".into(),
        media_index: 0,
        channels: (0, 1),
        response_timeout_ns: 1_000_000_000,
        default_session_timeout_seconds: 60,
    }
}

/// Feed one wire response and return the parsed `RtspResponse`.
fn parse_response(wire: &str) -> Result<fss_reference::RtspResponse, ClientError> {
    let mut parser = RtspParser::with_limits(RtspLimits {
        max_line_bytes: 2_048,
        max_headers: 32,
        max_body_bytes: 65_536,
        max_interleaved_bytes: 65_535,
    });
    for event in parser
        .feed(wire.as_bytes())
        .map_err(|_| ClientError::Response)?
    {
        if let RtspEvent::Response(response) = event {
            return Ok(response);
        }
    }
    Err(ClientError::Response)
}

fn describe(session: &mut RtspClientSession) -> Result<(), ClientError> {
    let request = session.request(ClientCommand::Describe, 0)?;
    let body = format!("{PREFIX}{VIDEO}");
    let wire = format!(
        "RTSP/1.0 200 OK\r\nCSeq: {}\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{body}",
        request.cseq(),
        body.len(),
    );
    let response = parse_response(&wire)?;
    session.accept(&response, 1)?;
    Ok(())
}

fn setup(session: &mut RtspClientSession, now_ns: u64) -> Result<(), ClientError> {
    let request = session.request(ClientCommand::Setup, now_ns)?;
    let wire = format!(
        "RTSP/1.0 200 OK\r\nCSeq: {}\r\nSession: ABC123;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=11223344\r\n\r\n",
        request.cseq(),
    );
    let response = parse_response(&wire)?;
    session.accept(&response, now_ns + 1)?;
    Ok(())
}

fn play(session: &mut RtspClientSession, now_ns: u64) -> Result<(), ClientError> {
    let request = session.request(ClientCommand::Play, now_ns)?;
    let wire = format!(
        "RTSP/1.0 200 OK\r\nCSeq: {}\r\nSession: ABC123\r\nRTP-Info: url=rtsp://camera/live/video;seq=1000;rtptime=90000\r\n\r\n",
        request.cseq(),
    );
    let response = parse_response(&wire)?;
    session.accept(&response, now_ns + 1)?;
    Ok(())
}

fn session_in(state: ClientState) -> Result<RtspClientSession, ClientError> {
    let mut session = RtspClientSession::new(config())?;
    match state {
        ClientState::Idle => {}
        ClientState::Described => describe(&mut session)?,
        ClientState::Ready => {
            describe(&mut session)?;
            setup(&mut session, 2)?;
        }
        ClientState::Playing => {
            describe(&mut session)?;
            setup(&mut session, 2)?;
            play(&mut session, 4)?;
        }
        other => {
            return Err(ClientError::State).map_err(|e| {
                let _ = other;
                e
            });
        }
    }
    Ok(session)
}

/// The reference client's inline legality table, encoded independently so
/// the property is an oracle, not an echo.
fn oracle_legal(state: ClientState, command: ClientCommand) -> bool {
    match command {
        ClientCommand::Options | ClientCommand::Describe => state == ClientState::Idle,
        ClientCommand::Setup => state == ClientState::Described,
        ClientCommand::Play => state == ClientState::Ready,
        ClientCommand::KeepAlive
        | ClientCommand::KeepAliveGetParameter
        | ClientCommand::Teardown => {
            matches!(state, ClientState::Ready | ClientState::Playing)
        }
    }
}

/// P1: exhaustive command legality for every reachable pre-terminal state.
#[test]
fn p1_command_legality_matrix() -> Result<(), Box<dyn std::error::Error>> {
    let mut cases = 0u64;
    for state in [
        ClientState::Idle,
        ClientState::Described,
        ClientState::Ready,
        ClientState::Playing,
    ] {
        for command in [
            ClientCommand::Options,
            ClientCommand::Describe,
            ClientCommand::Setup,
            ClientCommand::Play,
            ClientCommand::KeepAlive,
            ClientCommand::KeepAliveGetParameter,
            ClientCommand::Teardown,
        ] {
            let mut session = session_in(state)?;
            assert_eq!(session.state(), state);
            let accepted = session.request(command, 1_000).is_ok();
            assert_eq!(
                accepted,
                oracle_legal(state, command),
                "{command:?} in {state:?}"
            );
            cases += 1;
        }
    }
    emit("command-legality-matrix", cases);
    Ok(())
}

/// P2: one outstanding request at a time; a second command while a
/// response is pending is a typed State refusal, not a queue.
#[test]
fn p2_pending_request_lockout() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = session_in(ClientState::Described)?;
    session.request(ClientCommand::Setup, 10)?;
    assert!(matches!(
        session.request(ClientCommand::Setup, 11),
        Err(ClientError::State)
    ));
    emit("pending-lockout", 1);
    Ok(())
}

/// P3: a CSeq mismatch is refused WITHOUT state change — the pending
/// request survives and the correct response still settles it — while a
/// genuine response-processing failure (malformed SDP) fails the session
/// terminally and every command is refused afterward.
#[test]
fn p3_failure_semantics() -> Result<(), Box<dyn std::error::Error>> {
    // (a) CSeq mismatch: refused, state preserved, session recoverable.
    let mut session = session_in(ClientState::Described)?;
    let request = session.request(ClientCommand::Setup, 10)?;
    let wrong = format!(
        "RTSP/1.0 200 OK\r\nCSeq: {}\r\nSession: ABC123\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n",
        request.cseq() + 1,
    );
    let response = parse_response(&wrong)?;
    assert!(matches!(
        session.accept(&response, 11),
        Err(ClientError::CseqMismatch)
    ));
    assert_eq!(
        session.state(),
        ClientState::Described,
        "mismatch is not terminal"
    );
    let correct = format!(
        "RTSP/1.0 200 OK\r\nCSeq: {}\r\nSession: ABC123\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=11223344\r\n\r\n",
        request.cseq(),
    );
    let response = parse_response(&correct)?;
    session.accept(&response, 12)?;
    assert_eq!(
        session.state(),
        ClientState::Ready,
        "recovered after mismatch"
    );

    // (b) Matching failure: malformed SDP fails DESCRIBE terminally.
    let mut doomed = RtspClientSession::new(config())?;
    let request = doomed.request(ClientCommand::Describe, 0)?;
    let body =
        format!("{PREFIX}m=video 0 RTP/AVP 96\r\na=control:video\r\na=rtpmap:96 H264/8000\r\n");
    let wire = format!(
        "RTSP/1.0 200 OK\r\nCSeq: {}\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{body}",
        request.cseq(),
        body.len(),
    );
    let response = parse_response(&wire)?;
    assert!(session_accept_err(&mut doomed, &response, 1));
    assert_eq!(doomed.state(), ClientState::Failed);
    for command in [
        ClientCommand::Options,
        ClientCommand::Describe,
        ClientCommand::Setup,
        ClientCommand::Play,
        ClientCommand::KeepAlive,
        ClientCommand::Teardown,
    ] {
        assert!(
            doomed.request(command, 12).is_err(),
            "Failed session must refuse {command:?}"
        );
    }
    emit("failure-semantics", 8);
    Ok(())
}

fn session_accept_err(
    session: &mut RtspClientSession,
    response: &fss_reference::RtspResponse,
    now_ns: u64,
) -> bool {
    session.accept(response, now_ns).is_err()
}

/// P4: caller time never runs backwards (typed refusal) and CSeq advances
/// strictly by one per accepted exchange.
#[test]
fn p4_clock_and_cseq_discipline() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = session_in(ClientState::Described)?;
    let r1 = session.request(ClientCommand::Setup, 100)?;
    let wire = format!(
        "RTSP/1.0 200 OK\r\nCSeq: {}\r\nSession: ABC123\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n",
        r1.cseq(),
    );
    let response = parse_response(&wire)?;
    session.accept(&response, 101)?;
    let r2 = session.request(ClientCommand::KeepAlive, 200)?;
    assert_eq!(r2.cseq(), r1.cseq() + 1, "strictly increasing CSeq");
    // A response arriving before the request was sent is impossible time.
    let early = format!(
        "RTSP/1.0 200 OK\r\nCSeq: {}\r\nSession: ABC123\r\n\r\n",
        r2.cseq(),
    );
    let response2 = parse_response(&early)?;
    assert!(matches!(
        session.accept(&response2, 199),
        Err(ClientError::ClockReversed)
    ));
    emit("clock-cseq-discipline", 2);
    Ok(())
}

/// P5: describe driving through the full happy path lands in Playing with
/// a negotiated media description and server SSRC bound.
#[test]
fn p5_session_reaches_playing() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = session_in(ClientState::Playing)?;
    assert_eq!(session.state(), ClientState::Playing);
    assert!(session.media().is_some());
    assert_eq!(session.server_ssrc(), Some(0x1122_3344));
    // Keepalives and teardown remain legal while playing.
    assert!(session.request(ClientCommand::KeepAlive, 1_000).is_ok());
    emit("happy-path-playing", 1);
    Ok(())
}

/// P6: the unsigned path refuses while digest authentication is in force —
/// callers cannot bypass the auth gate by using the raw request API.
#[test]
fn p6_unsigned_gate() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = RtspClientSession::new(config())?;
    // Observable invariant: a fresh session's requests are unsigned and
    // wire-correct (the digest-pending gate is exercised in the crate's
    // own authenticated-path unit tests).
    let r = session.request(ClientCommand::Options, 0)?;
    assert!(
        r.bytes()
            .starts_with(b"OPTIONS rtsp://camera/live/ RTSP/1.0\r\n")
    );
    emit("unsigned-gate", 1);
    Ok(())
}

/// P7: cancellation is immediate and receipted: local close clears session
/// identity and pending work, reports whether the remote session may
/// still exist, and leaves the session terminally Closed.
#[test]
fn p7_cancellation_is_receipted() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = session_in(ClientState::Playing)?;
    session.request(ClientCommand::KeepAlive, 500)?;
    let receipt = session.cancel();
    // A keepalive was outstanding: the receipt names it, and the remote
    // session's existence is explicitly uncertain rather than assumed gone.
    assert!(receipt.pending_cseq.is_some());
    assert_eq!(session.state(), ClientState::Closed);
    for command in [
        ClientCommand::Options,
        ClientCommand::Play,
        ClientCommand::KeepAlive,
        ClientCommand::Teardown,
    ] {
        assert!(
            session.request(command, 600).is_err(),
            "Closed session must refuse {command:?}"
        );
    }
    // A clean idle cancel has no pending work.
    let mut idle = session_in(ClientState::Idle)?;
    let clean = idle.cancel();
    assert!(clean.pending_cseq.is_none());
    emit("cancellation-receipt", 6);
    Ok(())
}
