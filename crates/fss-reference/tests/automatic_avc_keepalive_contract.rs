#![forbid(unsafe_code)]
//! Native short-I/O regression: advisory keepalives cannot strand a partial frame.

use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::time::Duration;

use fss_packet::{StreamKey, avc::AvcReceiveLimits};
use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};
use fss_reference::rtsp::avc_client::{AvcClientError, AvcClientPoll};
use fss_reference::rtsp::avc_client::authenticated::{DigestAvcError, DigestAvcPoll};
use fss_reference::rtsp::client::{ClientCommand, ClientConfig, ClientError, ClientProgress, ClientState};
use fss_reference::rtsp::framed::WireIntakeError;
use fss_reference::rtsp::live_avc::{LiveAvcConfig, LiveAvcStep, SocketReadiness};
use fss_reference::rtsp::live_avc::automatic::{AutomaticAvcConnection, AutomaticAvcStep};
use fss_reference::rtsp::tcp::{TcpAuthority, TcpBinding, TcpDenial, TcpLimits, TcpOperation, TcpSecurityPolicy, TcpWriteStep};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const LEASE: u64 = 100_000_000_000;
const LOOP_BOUND: usize = 32_768;

struct Authority { binding: TcpBinding, revoked: Cell<bool> }
impl TcpAuthority for Authority {
    fn checkpoint(&self, binding: &TcpBinding, _: TcpOperation, now: u64, until: u64) -> Result<(), TcpDenial> {
        if self.revoked.get() { return Err(TcpDenial::Revoked); }
        if binding != &self.binding { return Err(TcpDenial::Unauthorized); }
        if until != LEASE || now >= until { return Err(TcpDenial::Deadline); }
        Ok(())
    }
}

struct Fixture {
    driver: AutomaticAvcConnection,
    peer: TcpStream,
    authority: Authority,
    originals: Vec<u8>,
}
impl Fixture {
    fn playing(chunk_bytes: usize, session_seconds: u32) -> Test<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let binding = TcpBinding::new(
            StreamKey { ingress: 91, generation: 1, ssrc: 7 }, listener.local_addr()?,
            "fixture.local", TcpSecurityPolicy::OwnerApprovedPlaintext,
        )?;
        let authority = Authority { binding: binding.clone(), revoked: Cell::new(false) };
        let live = LiveAvcConfig {
            protocol: ClientConfig {
                presentation_uri: "rtsp://fixture.local/live/".into(),
                control_root_uri: "rtsp://fixture.local/live".into(),
                media_index: 0, channels: (0, 1), response_timeout_ns: 10_000_000_000,
                default_session_timeout_seconds: 60,
            },
            binding, transport: TcpLimits { chunk_bytes, ..TcpLimits::default() },
            media: AvcReceiveLimits::default(), realm: "fixture-realm".into(),
            digest_policy: DigestPolicy::default(), deadline_ns: LEASE, max_steps: 200_000,
        };
        let driver = AutomaticAvcConnection::connect(live, 0, &authority)?;
        let (peer, _) = listener.accept()?;
        peer.set_read_timeout(Some(Duration::from_secs(2)))?;
        peer.set_write_timeout(Some(Duration::from_secs(2)))?;
        peer.set_nodelay(true)?;
        let mut f = Self { driver, peer, authority, originals: Vec::new() };
        let describe = f.command(0, ClientCommand::Describe)?;
        let sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\na=control:track\r\n";
        f.accept(describe, "Content-Type: application/sdp\r\n", sdp, 1, ClientState::Described)?;
        let setup = f.command(2, ClientCommand::Setup)?;
        f.accept(setup, &format!("Session: session;timeout={session_seconds}\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n"), "", 3, ClientState::Ready)?;
        let play = f.command(4, ClientCommand::Play)?;
        f.accept(play, "Session: session\r\n", "", 5, ClientState::Playing)?;
        assert!(!f.driver.needs_credentials());
        f.originals.clear();
        Ok(f)
    }
    fn poll(&mut self, readable: bool, writable: bool, now: u64) -> Test<AutomaticAvcStep> {
        // The fixture's server does not challenge. No production secret is read.
        Ok(self.driver.poll(SocketReadiness { readable, writable },
            &DigestCredentials::new("fixture-user", "fixture-password")?, [1; 16], now, &self.authority)?)
    }
    fn command(&mut self, now: u64, command: ClientCommand) -> Test<u32> {
        let AutomaticAvcStep::Queued(queued) = self.poll(false, false, now)? else {
            return Err("expected one queued command".into());
        };
        assert_eq!(queued.command, command);
        for _ in 0..LOOP_BOUND {
            match self.poll(false, true, now)? {
                AutomaticAvcStep::Live(LiveAvcStep::Write(TcpWriteStep::Sent { cseq, bytes })) => {
                    assert_eq!((cseq, bytes), (queued.cseq, queued.bytes));
                    let mut wire = vec![0; bytes];
                    self.peer.read_exact(&mut wire)?;
                    if command == ClientCommand::KeepAlive { assert!(wire.starts_with(b"OPTIONS ")); }
                    return Ok(cseq);
                }
                AutomaticAvcStep::Live(LiveAvcStep::Write(TcpWriteStep::Advanced { .. }) | LiveAvcStep::Pending(_)) => {}
                _ => return Err("unexpected command dispatch output".into()),
            }
        }
        Err("bounded command send exhausted".into())
    }
    fn accept(&mut self, cseq: u32, headers: &str, body: &str, now: u64, state: ClientState) -> Test {
        let wire = format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}", body.len()).into_bytes();
        self.peer.write_all(&wire)?;
        let before = self.originals.len();
        for _ in 0..LOOP_BOUND {
            match self.poll(true, false, now)? {
                AutomaticAvcStep::Live(LiveAvcStep::Wire(chunk)) => self.originals.extend_from_slice(chunk.expose()),
                AutomaticAvcStep::Live(LiveAvcStep::Pending(_)) => std::thread::yield_now(),
                AutomaticAvcStep::Live(LiveAvcStep::Protocol { event: DigestAvcPoll::Client { event, wire_retirement: None }, transport: None }) => {
                    if let AvcClientPoll::Control(ClientProgress::Accepted(actual)) = *event {
                        assert_eq!(actual, state);
                        assert_eq!(&self.originals[before..], wire);
                        return Ok(());
                    }
                }
                _ => return Err("unexpected control acceptance output".into()),
            }
        }
        Err("bounded control intake exhausted".into())
    }
    fn partial(&mut self, now: u64) -> Test<Vec<u8>> {
        // One standards-shaped receiver report + SDES CNAME compound on channel 1.
        let packet = [0x80, 201, 0, 1, 0, 0, 0, 7,
                      0x81, 202, 0, 2, 0, 0, 0, 7, 1, 1, b'x', 0];
        let mut wire = vec![b'$', 1, 0, 20];
        wire.extend_from_slice(&packet);
        self.peer.write_all(&wire[..9])?;
        for _ in 0..LOOP_BOUND {
            match self.poll(true, false, now)? {
                AutomaticAvcStep::Live(LiveAvcStep::Wire(chunk)) => self.originals.extend_from_slice(chunk.expose()),
                AutomaticAvcStep::Live(LiveAvcStep::Pending(_)) if self.originals.len() == 9 => {
                    assert_eq!(self.originals, wire[..9]);
                    return Ok(wire);
                }
                AutomaticAvcStep::Live(LiveAvcStep::Pending(_)) => std::thread::yield_now(),
                AutomaticAvcStep::Live(LiveAvcStep::Protocol { event: DigestAvcPoll::Client { event, .. }, .. })
                    if matches!(*event, AvcClientPoll::Pending { .. }) => {}
                _ => return Err("partial frame became a command or media event".into()),
            }
        }
        Err("bounded partial intake exhausted".into())
    }
}

#[test]
fn due_keepalive_waits_for_partial_source_then_queues_exactly_once() -> Test {
    for chunk in [1, 7, 4096] {
        let mut f = Fixture::playing(chunk, 60)?;
        let due = f.driver.next_wake_ns().ok_or("keepalive due")?;
        let wire = f.partial(due - 1)?;
        assert!(f.driver.next_wake_ns().is_some_and(|at| at > due));
        let AutomaticAvcStep::Live(LiveAvcStep::Pending(wait)) = f.poll(true, false, due)? else {
            return Err("advisory keepalive stranded partial source".into());
        };
        assert!(wait.readable);
        assert!(!wait.writable);
        assert!(wait.wake_at_ns.is_some_and(|at| at > due));
        assert!(!f.driver.needs_credentials());
        f.peer.write_all(&wire[9..])?;
        let mut source_seen = false;
        let mut due_seen = false;
        for _ in 0..LOOP_BOUND {
            match f.poll(true, false, due + 1)? {
                AutomaticAvcStep::Live(LiveAvcStep::Wire(chunk)) => f.originals.extend_from_slice(chunk.expose()),
                AutomaticAvcStep::Live(LiveAvcStep::Pending(_)) => std::thread::yield_now(),
                AutomaticAvcStep::Live(LiveAvcStep::Protocol { event: DigestAvcPoll::Client { event, wire_retirement: None }, transport: None }) => match *event {
                    AvcClientPoll::Rtcp { source, validation } => {
                        assert!(!source_seen);
                        assert_eq!(source.channel(), 1);
                        assert_eq!(source.payload(), &wire[4..]);
                        assert_eq!(validation, Ok(2));
                        source_seen = true;
                    }
                    AvcClientPoll::Control(ClientProgress::KeepAliveDue) => {
                        assert!(source_seen);
                        due_seen = true;
                        break;
                    }
                    AvcClientPoll::Pending { .. } => {}
                    _ => return Err("unexpected completed-source output".into()),
                },
                _ => return Err("unexpected completed-source step".into()),
            }
        }
        assert!(due_seen);
        assert_eq!(f.originals, wire);
        let cseq = f.command(due + 1, ClientCommand::KeepAlive)?;
        assert_eq!(cseq, 4);
        f.accept(cseq, "Session: session\r\n", "", due + 2, ClientState::Playing)?;
        assert!(!f.driver.needs_credentials());
        assert!(f.driver.next_wake_ns().is_some_and(|at| at > due + 2));
        let _retirement = f.driver.cancel().ok_or("retirement")?;
    }
    Ok(())
}

#[test]
fn partial_source_deadline_remains_hard_while_advisory_keepalive_is_deferred() -> Test {
    let mut f = Fixture::playing(7, 60)?;
    let due = f.driver.next_wake_ns().ok_or("keepalive")?;
    f.partial(due - 1)?;
    let deadline = f.driver.next_wake_ns().ok_or("partial deadline")?;
    assert!(deadline > due);
    let totals = f.driver.totals().ok_or("totals")?;
    let AutomaticAvcStep::Live(LiveAvcStep::Protocol {
        event: DigestAvcPoll::Fault { reason, retirement }, transport: Some(transport),
    }) = f.poll(false, false, deadline)? else {
        return Err("partial expiry was not terminal".into());
    };
    assert_eq!(reason, DigestAvcError::Wire(WireIntakeError::Deadline));
    assert_eq!(transport.totals, totals);
    assert!(!retirement.wire.pending.is_empty());
    assert!(f.driver.cancel().is_none());
    assert_eq!(f.driver.next_wake_ns(), None);
    Ok(())
}

#[test]
fn remote_session_expiry_still_wins_when_partial_source_has_a_later_deadline() -> Test {
    let mut f = Fixture::playing(7, 2)?;
    let due = f.driver.next_wake_ns().ok_or("keepalive")?;
    f.partial(due - 1)?;
    let deadline = f.driver.next_wake_ns().ok_or("hard deadline")?;
    assert!(deadline > due && deadline < due + 5_000_000_000);
    let AutomaticAvcStep::Live(LiveAvcStep::Protocol {
        event: DigestAvcPoll::Client { event, wire_retirement: Some(wire) }, transport: Some(_),
    }) = f.poll(false, false, deadline)? else {
        return Err("session expiry was not surfaced".into());
    };
    assert!(matches!(*event, AvcClientPoll::Fault { reason: AvcClientError::Session(ClientError::SessionExpired), .. }));
    assert!(!wire.pending.is_empty());
    assert!(f.driver.cancel().is_none());
    Ok(())
}
