#![forbid(unsafe_code)]
//! Real loopback tests; no camera, external service, detached thread, or permissive public Cx.

use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::Duration;

use fss_packet::StreamKey;
use crate::rtsp::client::ClientError;
use crate::rtsp::avc_client::AvcClientError;
use crate::rtsp::tcp::{TcpDenial, TcpSecurityPolicy};
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const KEY: StreamKey = StreamKey { ingress: 71, generation: 1, ssrc: 7 };
const LEASE: u64 = 100_000_000_000;
const RESPONSE_TIMEOUT: u64 = 10_000_000_000;

struct Authority {
    binding: TcpBinding,
    revoked: Cell<bool>,
    reject_queue: Cell<bool>,
    checks: Cell<u64>,
}
impl TcpAuthority for Authority {
    fn checkpoint(&self, binding: &TcpBinding, op: TcpOperation, now: u64, until: u64) -> Result<(), TcpDenial> {
        self.checks.set(self.checks.get() + 1);
        if binding != &self.binding { return Err(TcpDenial::Unauthorized); }
        if self.revoked.get() { return Err(TcpDenial::Revoked); }
        if self.reject_queue.get() && op == TcpOperation::QueueRequest { return Err(TcpDenial::Budget); }
        if until != LEASE || now >= until { return Err(TcpDenial::Deadline); }
        Ok(())
    }
}
fn scope(peer: std::net::SocketAddr) -> TestResult<(LiveAvcConfig, Authority)> {
    let binding = TcpBinding::new(KEY, peer, "camera.local", TcpSecurityPolicy::OwnerApprovedPlaintext)?;
    let authority = Authority { binding: binding.clone(), revoked: Cell::new(false),
        reject_queue: Cell::new(false), checks: Cell::new(0) };
    let config = LiveAvcConfig {
        protocol: ClientConfig {
            presentation_uri: "rtsp://camera.local/live/".to_owned(),
            control_root_uri: "rtsp://camera.local/live".to_owned(),
            media_index: 0, channels: (0, 1), response_timeout_ns: RESPONSE_TIMEOUT,
            default_session_timeout_seconds: 60,
        },
        binding, transport: TcpLimits::default(), media: AvcReceiveLimits::default(),
        realm: "fixture-camera".to_owned(), digest_policy: DigestPolicy::default(),
        deadline_ns: LEASE, max_steps: 100_000,
    };
    Ok((config, authority))
}
fn credentials() -> TestResult<DigestCredentials<'static>> {
    Ok(DigestCredentials::new("camera-user", "camera-password")?)
}
fn response(cseq: u32, headers: &str, body: &str) -> Vec<u8> {
    format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}", body.len()).into_bytes()
}
fn challenge(cseq: u32) -> Vec<u8> {
    format!("RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\nWWW-Authenticate: Digest realm=\"fixture-camera\", nonce=\"server-nonce\", algorithm=SHA-256, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n").into_bytes()
}
fn description() -> &'static str {
    "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\na=control:trackID=0\r\n"
}
struct Fixture {
    connection: LiveAvcConnection,
    peer: TcpStream,
    authority: Authority,
}
impl Fixture {
    fn new(chunk: usize) -> TestResult<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let (mut config, authority) = scope(listener.local_addr()?)?;
        config.transport.chunk_bytes = chunk;
        let connection = LiveAvcConnection::connect(config, 0, &authority)?;
        let (peer, _) = listener.accept()?;
        peer.set_read_timeout(Some(Duration::from_secs(2)))?;
        peer.set_write_timeout(Some(Duration::from_secs(2)))?;
        peer.set_nodelay(true)?;
        Ok(Self { connection, peer, authority })
    }
    fn flush(&mut self, queued: QueuedAvcRequest, now: u64) -> TestResult<Vec<u8>> {
        for _ in 0..32_768 {
            match self.connection.poll(SocketReadiness { readable: false, writable: true }, now, &self.authority)? {
                LiveAvcStep::Write(TcpWriteStep::Sent { cseq, bytes }) => {
                    assert_eq!((cseq, bytes), (queued.cseq, queued.bytes));
                    let mut actual = vec![0; bytes];
                    self.peer.read_exact(&mut actual)?;
                    return Ok(actual);
                }
                LiveAvcStep::Write(TcpWriteStep::Advanced { .. }) | LiveAvcStep::Pending(_) => {},
                _ => return Err("unexpected output while flushing a request".into()),
            }
        }
        Err("bounded request send did not complete".into())
    }
    fn command(&mut self, command: ClientCommand, now: u64) -> TestResult<(QueuedAvcRequest, Vec<u8>)> {
        let queued = self.connection.request(command, &credentials()?, [17; 16], now, &self.authority)?;
        let bytes = self.flush(queued, now)?;
        Ok((queued, bytes))
    }
    fn receive(&mut self, bytes: &[u8], now: u64) -> TestResult<Vec<DigestAvcPoll>> {
        self.peer.write_all(bytes)?;
        let mut original = Vec::new();
        let mut events = Vec::new();
        for _ in 0..32_768 {
            match self.connection.poll(SocketReadiness { readable: true, writable: false }, now, &self.authority)? {
                LiveAvcStep::Wire(chunk) => {
                    assert_eq!(chunk.admitted_ns(), now);
                    original.extend_from_slice(chunk.expose());
                }
                LiveAvcStep::Protocol { event, transport } => {
                    let blocked = matches!(&event, DigestAvcPoll::AuthenticationRequired { .. });
                    events.push(event);
                    if transport.is_some() || blocked {
                        assert_eq!(original, bytes);
                        return Ok(events);
                    }
                }
                LiveAvcStep::Pending(wait) => {
                    if original.len() == bytes.len() && wait.wake_at_ns.is_none_or(|at| at > now) {
                        assert_eq!(original, bytes);
                        return Ok(events);
                    }
                    std::thread::yield_now();
                }
                _ => return Err("unexpected output while receiving a reply".into()),
            }
        }
        Err("bounded receive did not drain".into())
    }
}

#[test]
fn mismatched_route_is_rejected_before_connect_or_authority_access() -> TestResult {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let (mut config, authority) = scope(listener.local_addr()?)?;
    config.protocol.presentation_uri = "rtsp://other-camera/live/".to_owned();
    let error = LiveAvcConnection::connect(config, 0, &authority).err().ok_or("unexpected connection")?;
    assert_eq!(error.reason, LiveAvcError::Configuration);
    assert!(!error.connection_attempted);
    assert_eq!(authority.checks.get(), 0);
    Ok(())
}

#[test]
fn local_send_requires_readiness_and_preserves_exact_short_write_suffixes() -> TestResult {
    let mut f = Fixture::new(3)?;
    let queued = f.connection.request(ClientCommand::Describe, &credentials()?, [0; 16], 0, &f.authority)?;
    assert_eq!(f.connection.totals().ok_or("missing totals")?.sent_bytes, 0);
    assert!(matches!(f.connection.poll(SocketReadiness::default(), 0, &f.authority)?,
        LiveAvcStep::Pending(LiveAvcWait { readable: false, writable: true, .. })));
    assert_eq!(f.connection.totals().ok_or("missing totals")?.write_calls, 0);
    let bytes = f.flush(queued, 0)?;
    let text = std::str::from_utf8(&bytes)?;
    assert!(text.starts_with("DESCRIBE rtsp://camera.local/live/ RTSP/1.0\r\n"));
    assert!(!text.contains("Authorization:"));
    assert_eq!(f.connection.state(), ClientState::Idle); // no remote acknowledgement yet
    assert_eq!(f.connection.totals().ok_or("missing totals")?.sent_bytes, bytes.len() as u64);
    assert!(f.connection.cancel().is_some());
    Ok(())
}

#[test]
fn real_socket_digest_challenge_and_acknowledged_setup_play_use_existing_protocol() -> TestResult {
    let mut f = Fixture::new(7)?;
    let (request, _) = f.command(ClientCommand::Describe, 0)?;
    let events = f.receive(&challenge(request.cseq), 1)?;
    assert!(events.iter().any(|e| matches!(e, DigestAvcPoll::AuthenticationRequired { cseq: 1, .. })));
    let queued = f.connection.respond(&credentials()?, [18; 16], 2, &f.authority)?;
    let text = String::from_utf8(f.flush(queued, 2)?)?;
    assert_eq!(queued.cseq, 2);
    assert!(text.contains("Authorization: Digest "));
    assert!(text.contains("algorithm=SHA-256"));
    assert!(!text.contains("camera-password"));
    f.receive(&response(2, "Content-Type: application/sdp\r\n", description()), 3)?;
    assert_eq!(f.connection.state(), ClientState::Described);
    let (setup, _) = f.command(ClientCommand::Setup, 4)?;
    f.receive(&response(setup.cseq,
        "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n", ""), 5)?;
    assert_eq!(f.connection.state(), ClientState::Ready);
    let (play, _) = f.command(ClientCommand::Play, 6)?;
    f.receive(&response(play.cseq, "Session: fixture\r\n", ""), 7)?;
    assert_eq!(f.connection.state(), ClientState::Playing);
    let retirement = f.connection.cancel().ok_or("missing retirement")?;
    assert!(retirement.protocol.client.session.remote_session_may_exist);
    assert!(f.connection.cancel().is_none());
    Ok(())
}

#[test]
fn held_digest_challenge_prevents_socket_read_ahead_and_keeps_original_timeout() -> TestResult {
    let mut f = Fixture::new(4096)?;
    f.command(ClientCommand::Describe, 0)?;
    f.receive(&challenge(1), 1)?;
    let before = f.connection.totals().ok_or("missing totals")?.read_calls;
    f.peer.write_all(b"unadmitted next response")?;
    for now in 2..10 {
        assert!(matches!(f.connection.poll(SocketReadiness { readable: true, writable: true }, now, &f.authority)?,
            LiveAvcStep::Protocol { event: DigestAvcPoll::AuthenticationRequired { .. }, transport: None }));
    }
    assert_eq!(f.connection.totals().ok_or("missing totals")?.read_calls, before);
    let step = f.connection.poll(SocketReadiness::default(), RESPONSE_TIMEOUT, &f.authority)?;
    assert!(matches!(step, LiveAvcStep::Protocol { transport: Some(_), .. }));
    assert!(matches!(f.connection.poll(SocketReadiness::default(), RESPONSE_TIMEOUT, &f.authority)?, LiveAvcStep::Ended));
    Ok(())
}

#[test]
fn partial_request_timeout_retires_exact_prefix_without_resending() -> TestResult {
    let mut f = Fixture::new(1)?;
    f.connection.request(ClientCommand::Describe, &credentials()?, [0; 16], 0, &f.authority)?;
    assert!(matches!(f.connection.poll(SocketReadiness { readable: false, writable: true }, 0, &f.authority)?,
        LiveAvcStep::Write(TcpWriteStep::Advanced { sent: 1, .. })));
    let step = f.connection.poll(SocketReadiness::default(), RESPONSE_TIMEOUT, &f.authority)?;
    let LiveAvcStep::Protocol { event, transport: Some(transport) } = step else { return Err("missing terminal protocol event".into()); };
    assert_eq!(transport.request_sent_bytes, 1);
    assert_eq!(transport.totals.sent_bytes, 1);
    assert_eq!(transport.request.as_ref().ok_or("lost prepared request")?.cseq(), 1);
    match event {
        DigestAvcPoll::Client { event, .. } => assert!(matches!(*event,
            AvcClientPoll::Fault { reason: AvcClientError::Session(ClientError::ResponseTimeout), .. })),
        _ => return Err("expected response timeout from existing session".into()),
    }
    Ok(())
}

#[test]
fn queue_refusal_preserves_the_prepared_command_and_closes_both_owners() -> TestResult {
    let mut f = Fixture::new(4096)?;
    f.authority.reject_queue.set(true);
    let error = f.connection.request(ClientCommand::Describe, &credentials()?, [0; 16], 0, &f.authority)
        .err().ok_or("unexpected queued request")?;
    assert_eq!(error.reason, LiveAvcError::Transport(TcpError::Denied(TcpDenial::Budget)));
    let retired = error.retirement.ok_or("missing retirement")?;
    assert_eq!(retired.unqueued_request.ok_or("lost unqueued command")?.cseq(), 1);
    assert_eq!(retired.transport.totals.sent_bytes, 0);
    assert_eq!(retired.protocol.client.session.pending_cseq, Some(1));
    assert_eq!(f.connection.state(), ClientState::Closed);
    Ok(())
}

#[test]
fn revocation_cancels_even_without_socket_readiness_and_debug_never_prints_secrets() -> TestResult {
    let mut f = Fixture::new(4096)?;
    f.command(ClientCommand::Describe, 0)?;
    f.receive(&challenge(1), 1)?;
    f.connection.respond(&credentials()?, [18; 16], 2, &f.authority)?;
    f.authority.revoked.set(true);
    let error = f.connection.poll(SocketReadiness::default(), 3, &f.authority).err().ok_or("revocation ignored")?;
    assert_eq!(error.reason, LiveAvcError::Transport(TcpError::Denied(TcpDenial::Revoked)));
    let debug = format!("{error:?}");
    for secret in ["camera-user", "camera-password", "server-nonce", "camera.local", "Authorization"] {
        assert!(!debug.contains(secret));
    }
    let retired = error.retirement.ok_or("missing retired auth request")?;
    assert!(std::str::from_utf8(retired.transport.request.as_ref().ok_or("lost auth request")?.bytes())?.contains("Authorization"));
    assert_eq!(retired.transport.request_sent_bytes, 0);
    Ok(())
}

#[test]
fn work_budget_bounds_semantic_polling_and_clock_regression_is_non_mutating() -> TestResult {
    let mut f = Fixture::new(4096)?;
    f.connection.remaining_steps = 2;
    let _ = f.connection.poll(SocketReadiness::default(), 10, &f.authority)?;
    let before = f.connection.remaining_steps();
    assert_eq!(f.connection.poll(SocketReadiness::default(), 9, &f.authority).err()
        .ok_or("regressed clock accepted")?.reason, LiveAvcError::ClockReversed);
    assert_eq!(f.connection.remaining_steps(), before);
    let _ = f.connection.poll(SocketReadiness::default(), 10, &f.authority)?;
    let error = f.connection.poll(SocketReadiness::default(), 10, &f.authority).err().ok_or("unbounded polling")?;
    assert_eq!(error.reason, LiveAvcError::WorkBudget);
    let retired = error.retirement.ok_or("work exhaustion lost ownership")?;
    assert_eq!(retired.transport.totals.read_calls + retired.transport.totals.write_calls, 0);
    Ok(())
}

#[test]
fn eof_is_drained_and_remote_uncertainty_is_not_promoted_to_teardown_success() -> TestResult {
    let mut f = Fixture::new(4096)?;
    f.command(ClientCommand::Describe, 0)?;
    f.peer.shutdown(Shutdown::Write)?;
    let mut saw_eof = false;
    for _ in 0..1024 {
        match f.connection.poll(SocketReadiness { readable: true, writable: false }, 1, &f.authority)? {
            LiveAvcStep::InputEnded => saw_eof = true,
            LiveAvcStep::Protocol { transport: Some(transport), .. } => {
                assert!(saw_eof);
                assert!(transport.totals.peer_eof);
                assert!(matches!(f.connection.poll(SocketReadiness::default(), 1, &f.authority)?, LiveAvcStep::Ended));
                return Ok(());
            }
            _ => std::thread::yield_now(),
        }
    }
    Err("EOF did not reach bounded terminal drain".into())
}
