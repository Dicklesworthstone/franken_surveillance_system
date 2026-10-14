#![forbid(unsafe_code)]
//! Public HEVC supervision over real bounded loopback I/O and retained source fixtures.
//! These tests do not contact cameras, infer capture time, or grant effect authority.

mod hevc_recording_support;

use std::cell::Cell;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use fss_core::ContentDigest;
use fss_packet::hevc::{HevcAssemblyLimits, HevcConfiguration, HevcConfigurationLimits};
use fss_packet::{H265Limits, ReorderLimits, StreamKey};
use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};
use fss_reference::rtsp::client::{ClientCommand, ClientConfig, ClientProgress, ClientState};
use fss_reference::rtsp::hevc_client::HevcClientPoll;
use fss_reference::rtsp::hevc_client::pictures::HevcPictureClientPoll as Event;
use fss_reference::rtsp::hevc_recording_capture::live::{
    AutomaticHevcRecordingStep as Step, LiveHevcRecordingConfig,
};
use fss_reference::rtsp::hevc_recording_capture::{
    HevcCapturePoll, HevcPictureTimingRequest, TimedHevcCapture,
};
use fss_reference::rtsp::hevc_recording_collector::HevcCollectionSeal;
use fss_reference::rtsp::live_avc::automatic::reconnect::hevc::{
    HevcTimingRefusal, SupervisedHevcRecording, SupervisedHevcRecordingError,
    SupervisedHevcRecordingStep as Supervised,
};
use fss_reference::rtsp::live_avc::automatic::reconnect::{
    ReconnectBudget, ReconnectPolicy, ReconnectRefusal, ReconnectStatus, ReconnectStop,
};
use fss_reference::rtsp::live_hevc::{
    LiveHevcConfig, LiveHevcRetirement, LiveHevcStep, QueuedHevcRequest, SocketReadiness,
};
use fss_reference::rtsp::recording::RecordingScope;
use fss_reference::rtsp::recording::hevc::{PreparedHevcRecording, verify_hevc_recording};
use fss_reference::rtsp::tcp::{
    TcpAuthority, TcpBinding, TcpDenial, TcpLimits, TcpOperation, TcpRetirement, TcpSecurityPolicy,
    TcpWriteStep,
};
use hevc_recording_support::{
    Error, PT, SSRC, configuration, nals, packet, packets, scope, timings,
};

type Test<T = ()> = Result<T, Error>;
const LEASE: u64 = 100_000_000_000;
const LOOP_BOUND: usize = 131_072;

fn policy() -> ReconnectPolicy {
    ReconnectPolicy {
        max_attempts: 3,
        initial_backoff_ns: 10,
        max_backoff_ns: 100,
        deadline_ns: LEASE,
        max_steps: 1_000_000,
    }
}

struct Authority {
    binding: TcpBinding,
    denied: Cell<Option<TcpDenial>>,
}
impl TcpAuthority for Authority {
    fn checkpoint(
        &self,
        binding: &TcpBinding,
        _: TcpOperation,
        now: u64,
        until: u64,
    ) -> Result<(), TcpDenial> {
        if let Some(denial) = self.denied.get() {
            return Err(denial);
        }
        if binding != &self.binding {
            return Err(TcpDenial::Unauthorized);
        }
        if until != LEASE || now >= until {
            return Err(TcpDenial::Deadline);
        }
        Ok(())
    }
}

fn recording_scope(generation: u64) -> Test<RecordingScope> {
    let mut value = scope()?;
    value.generation = generation;
    // These fixture values are explicitly supplied, not inferred by the supervisor.
    value.anchor = ContentDigest::sha256(format!("owner-anchor-{generation}").as_bytes());
    value.receive_clock = ContentDigest::sha256(format!("receive-clock-{generation}").as_bytes());
    Ok(value)
}

fn configs(
    peer: SocketAddr,
    chunk: usize,
    generation: u64,
) -> Test<(LiveHevcConfig, LiveHevcRecordingConfig, Authority)> {
    let key = StreamKey {
        ingress: 1,
        generation,
        ssrc: SSRC,
    };
    let binding = TcpBinding::new(
        key,
        peer,
        "fixture.local",
        TcpSecurityPolicy::OwnerApprovedPlaintext,
    )?;
    let authority = Authority {
        binding: binding.clone(),
        denied: Cell::new(None),
    };
    let live = LiveHevcConfig {
        protocol: ClientConfig {
            presentation_uri: "rtsp://fixture.local/live/".into(),
            control_root_uri: "rtsp://fixture.local/live".into(),
            media_index: 0,
            channels: (0, 1),
            response_timeout_ns: 10_000_000_000,
            default_session_timeout_seconds: 60,
        },
        binding,
        transport: TcpLimits {
            chunk_bytes: chunk,
            ..TcpLimits::default()
        },
        reorder: ReorderLimits::default(),
        reconstruction: H265Limits::default(),
        assembly: HevcAssemblyLimits::default(),
        realm: "test-realm".into(),
        digest_policy: DigestPolicy::default(),
        deadline_ns: LEASE,
        max_steps: 200_000,
    };
    let recording = LiveHevcRecordingConfig {
        scope: recording_scope(generation)?,
        payload_type: PT,
        configuration: configuration()?,
        time_scale: 90_000,
        limits: Default::default(),
    };
    Ok((live, recording, authority))
}

fn credentials() -> Test<DigestCredentials<'static>> {
    Ok(DigestCredentials::new("test-user", "test-password")?)
}
fn ready() -> SocketReadiness {
    SocketReadiness {
        readable: true,
        writable: true,
    }
}
fn sdp() -> &'static str {
    "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 98\r\na=rtpmap:98 H265/90000\r\na=control:track\r\n"
}
fn response(cseq: u32, headers: &str, body: &str) -> Vec<u8> {
    format!(
        "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len()
    )
    .into_bytes()
}
fn challenge(cseq: u32, realm: &str) -> Vec<u8> {
    format!("RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\nWWW-Authenticate: Digest realm=\"{realm}\", nonce=\"test-nonce\", algorithm=SHA-256, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n").into_bytes()
}
fn framed(packet: &[u8]) -> Test<Vec<u8>> {
    let mut out = vec![b'$', 0];
    out.extend_from_slice(&u16::try_from(packet.len())?.to_be_bytes());
    out.extend_from_slice(packet);
    Ok(out)
}
fn input() -> Test<Vec<hevc_recording_support::Packet>> {
    let mut out = packets()?;
    for (i, packet) in out.iter_mut().enumerate() {
        packet.sequence = u64::try_from(i)? + 1;
        packet.bytes[2..4].copy_from_slice(&u16::try_from(packet.sequence)?.to_be_bytes());
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stop {
    Pending,
    Timing(HevcPictureTimingRequest),
    Stopped,
    Ended,
}
#[derive(Clone, Copy)]
enum Expected {
    State(ClientState),
    Challenge,
}

struct Fixture {
    driver: SupervisedHevcRecording,
    listener: TcpListener,
    peer: TcpStream,
    authority: Authority,
    chunk: usize,
    nonce: u128,
    raw: Vec<u8>,
    events: Vec<Event>,
    windows: Vec<PreparedHevcRecording>,
    timed: Vec<TimedHevcCapture>,
    seals: Vec<HevcCollectionSeal>,
    transports: Vec<TcpRetirement>,
    connections: Vec<LiveHevcRetirement>,
    terminal: Option<HevcCapturePoll>,
}
impl Fixture {
    fn new(chunk: usize, budget_attempts: u32) -> Test<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let (live, recording, authority) = configs(listener.local_addr()?, chunk, 1)?;
        let budget =
            ReconnectBudget::for_attempts(live.transport, live.max_steps, budget_attempts)?;
        let mut driver =
            SupervisedHevcRecording::new_with_budget(live.binding.clone(), policy(), budget, 0)?;
        let attempt = driver.connect(live, recording, 0, &authority)?;
        assert_eq!(attempt.ordinal, 1);
        let (peer, _) = listener.accept()?;
        setup_peer(&peer)?;
        Ok(Self {
            driver,
            listener,
            peer,
            authority,
            chunk,
            nonce: 0,
            raw: Vec::new(),
            events: Vec::new(),
            windows: Vec::new(),
            timed: Vec::new(),
            seals: Vec::new(),
            transports: Vec::new(),
            connections: Vec::new(),
            terminal: None,
        })
    }

    fn poll(&mut self, readiness: SocketReadiness, now: u64) -> Test<Step> {
        let nonce = if self.driver.needs_credentials() {
            self.nonce = self.nonce.checked_add(1).ok_or("nonce bound")?;
            self.nonce.to_be_bytes()
        } else {
            [0; 16]
        };
        match self
            .driver
            .poll(readiness, &credentials()?, nonce, now, &self.authority)?
        {
            Supervised::Recording { key, output } => {
                assert_eq!(key, self.authority.binding.key());
                Ok(output)
            }
            _ => Err("expected current-generation native output".into()),
        }
    }

    fn command(&mut self, now: u64) -> Test<(QueuedHevcRequest, Vec<u8>)> {
        let Step::Queued(queued) = self.poll(SocketReadiness::default(), now)? else {
            return Err("missing automatic request".into());
        };
        for _ in 0..LOOP_BOUND {
            match self.poll(
                SocketReadiness {
                    readable: false,
                    writable: true,
                },
                now,
            )? {
                Step::Network(LiveHevcStep::Write(TcpWriteStep::Sent { cseq, bytes })) => {
                    assert_eq!((cseq, bytes), (queued.cseq, queued.bytes));
                    let mut wire = vec![0; bytes];
                    self.peer.read_exact(&mut wire)?;
                    return Ok((queued, wire));
                }
                Step::Network(
                    LiveHevcStep::Write(TcpWriteStep::Advanced { .. }) | LiveHevcStep::Pending(_),
                ) => {}
                _ => return Err("unexpected request dispatch output".into()),
            }
        }
        Err("bounded dispatch exhausted".into())
    }

    fn reply(&mut self, bytes: &[u8], now: u64, expected: Expected) -> Test {
        self.peer.write_all(bytes)?;
        let before = self.raw.len();
        for _ in 0..LOOP_BOUND {
            match self.poll(
                SocketReadiness {
                    readable: true,
                    writable: false,
                },
                now,
            )? {
                Step::Network(LiveHevcStep::Wire(chunk)) => {
                    self.raw.extend_from_slice(chunk.expose())
                }
                Step::Network(LiveHevcStep::Pending(_)) => std::thread::yield_now(),
                Step::ProtocolQueued { transport: None } => {}
                Step::Capture {
                    event,
                    connection: None,
                } => {
                    let HevcCapturePoll::Receiver(event) = *event else {
                        return Err("control response became a recording result".into());
                    };
                    let found = match (expected, event.as_ref()) {
                        (Expected::State(state), Event::Client { event, work: None }) => {
                            matches!(event.as_ref(), HevcClientPoll::Control {
                                progress: ClientProgress::Accepted(actual), ..
                            } if *actual == state)
                        }
                        (Expected::Challenge, Event::Client { event, work: None }) => {
                            matches!(
                                event.as_ref(),
                                HevcClientPoll::AuthenticationRequired { .. }
                            )
                        }
                        _ => false,
                    };
                    self.events.push(*event);
                    if found {
                        assert_eq!(&self.raw[before..], bytes);
                        return Ok(());
                    }
                }
                _ => return Err("unexpected control output".into()),
            }
        }
        Err("bounded control response exhausted".into())
    }

    fn negotiate(&mut self, digest: bool, start: u64) -> Test {
        let (describe, wire) = self.command(start)?;
        assert_eq!(describe.command, ClientCommand::Describe);
        assert_eq!(describe.cseq, 1);
        assert!(!std::str::from_utf8(&wire)?.contains("Authorization:"));
        let cseq = if digest {
            let raw = challenge(describe.cseq, "test-realm");
            self.reply(&raw, start + 1, Expected::Challenge)?;
            let (answer, wire) = self.command(start + 2)?;
            assert_eq!(answer.command, ClientCommand::Describe);
            assert!(answer.cseq > describe.cseq);
            assert_eq!(
                answer
                    .challenge
                    .as_ref()
                    .ok_or("challenge ownership")?
                    .expose_wire(),
                raw
            );
            assert!(std::str::from_utf8(&wire)?.contains("Authorization: Digest "));
            assert!(!std::str::from_utf8(&wire)?.contains("test-password"));
            answer.cseq
        } else {
            describe.cseq
        };
        self.reply(
            &response(cseq, "Content-Type: application/sdp\r\n", sdp()),
            start + 3,
            Expected::State(ClientState::Described),
        )?;
        let (setup, _) = self.command(start + 4)?;
        assert_eq!(setup.command, ClientCommand::Setup);
        self.reply(&response(setup.cseq,
            "Session: test-session;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n", ""),
            start + 5, Expected::State(ClientState::Ready))?;
        let (play, _) = self.command(start + 6)?;
        assert_eq!(play.command, ClientCommand::Play);
        self.reply(
            &response(play.cseq, "Session: test-session\r\n", ""),
            start + 7,
            Expected::State(ClientState::Playing),
        )?;
        assert_eq!(self.driver.state(), Some(ClientState::Playing));
        assert!(!self.driver.needs_credentials());
        Ok(())
    }

    fn playing(chunk: usize, digest: bool, budget_attempts: u32) -> Test<Self> {
        let mut f = Self::new(chunk, budget_attempts)?;
        f.negotiate(digest, 0)?;
        assert!(f.windows.is_empty());
        assert!(f.timed.is_empty());
        Ok(f)
    }

    fn drain(
        &mut self,
        now: u64,
        auto_timing: bool,
        wire_target: usize,
        want_end: bool,
    ) -> Test<Stop> {
        for _ in 0..LOOP_BOUND {
            match self.poll(ready(), now)? {
                Step::Network(LiveHevcStep::Wire(chunk)) => {
                    self.raw.extend_from_slice(chunk.expose())
                }
                Step::Network(LiveHevcStep::InputEnded) => {
                    assert!(matches!(self.driver.status(), ReconnectStatus::Active(_)));
                    assert!(
                        self.driver
                            .acknowledge_retirement(now, &self.authority)
                            .is_err()
                    );
                }
                Step::Network(LiveHevcStep::Pending(wait)) => {
                    if !want_end
                        && self.raw.len() >= wire_target
                        && wait.wake_at_ns.is_none_or(|at| at > now)
                    {
                        return Ok(Stop::Pending);
                    }
                    std::thread::yield_now();
                }
                Step::ProtocolQueued { transport } => {
                    if let Some(transport) = transport {
                        assert!(matches!(self.driver.status(), ReconnectStatus::Active(_)));
                        assert!(
                            self.driver
                                .acknowledge_retirement(now, &self.authority)
                                .is_err()
                        );
                        self.transports.push(*transport);
                    }
                }
                Step::Capture { event, connection } => {
                    if let Some(connection) = connection {
                        self.connections.push(*connection);
                    }
                    match *event {
                        HevcCapturePoll::Receiver(event) => self.events.push(*event),
                        HevcCapturePoll::TimingRequired(request) => {
                            if !auto_timing {
                                return Ok(Stop::Timing(request));
                            }
                            let timing = timings(self.timed.len() + 1)[self.timed.len()];
                            let ticket = self
                                .driver
                                .timing_ticket()
                                .ok_or("missing exact picture ticket")?;
                            assert_eq!(ticket.request(), request);
                            self.timed.push(self.driver.supply_timing_for(
                                &ticket,
                                timing,
                                now,
                                &self.authority,
                            )?);
                        }
                        HevcCapturePoll::Window(window) => {
                            // Even the last window cannot independently release the capture owner.
                            assert!(matches!(self.driver.status(), ReconnectStatus::Active(_)));
                            self.windows.push(*window);
                        }
                        HevcCapturePoll::Sealed(seal) => self.seals.push(seal),
                        event @ HevcCapturePoll::Stopped { .. } => {
                            self.terminal = Some(event);
                            return Ok(Stop::Stopped);
                        }
                        event @ HevcCapturePoll::Ended { .. } => {
                            self.terminal = Some(event);
                            return Ok(Stop::Ended);
                        }
                        _ => return Err("unexpected fixture collection pressure".into()),
                    }
                }
                _ => return Err("unexpected fixture drain output".into()),
            }
        }
        Err("bounded native drain exhausted".into())
    }

    fn feed(&mut self, bytes: &[u8], now: u64, auto_timing: bool) -> Test<Stop> {
        let wire = framed(bytes)?;
        let before = self.raw.len();
        self.peer.write_all(&wire)?;
        let result = self.drain(now, auto_timing, before + wire.len(), false)?;
        assert_eq!(&self.raw[before..], wire);
        Ok(result)
    }

    fn probation(&mut self) -> Test {
        assert_eq!(
            self.feed(&packet(0, 0, false, &nals()?[0]).bytes, 10, true)?,
            Stop::Pending
        );
        Ok(())
    }

    fn timing_wait(&mut self) -> Test<HevcPictureTimingRequest> {
        self.probation()?;
        let mut last = Stop::Pending;
        for (i, packet) in input()?[..5].iter().enumerate() {
            last = self.feed(&packet.bytes, 20 + u64::try_from(i)?, false)?;
        }
        match last {
            Stop::Timing(request) => Ok(request),
            _ => Err("missing real picture timing request".into()),
        }
    }

    fn record_and_eof(&mut self) -> Test {
        self.probation()?;
        for (i, packet) in input()?.iter().enumerate() {
            assert_eq!(
                self.feed(&packet.bytes, 20 + u64::try_from(i)?, true)?,
                Stop::Pending
            );
        }
        self.peer.shutdown(Shutdown::Write)?;
        assert_eq!(self.drain(40, true, self.raw.len(), true)?, Stop::Ended);
        assert_eq!(self.windows.len(), 2);
        assert_eq!(self.timed.len(), 4);
        assert_eq!(self.transports.len(), 1);
        assert!(self.transports[0].totals.peer_eof);
        assert!(self.connections.is_empty());
        assert!(matches!(
            self.terminal,
            Some(HevcCapturePoll::Ended { retained: Some(_) })
        ));
        let key = self.authority.binding.key();
        assert_eq!(self.driver.status(), ReconnectStatus::Retired(key));
        for window in &self.windows {
            verify_hevc_recording(
                window.manifest(),
                window.objects(),
                &recording_scope(key.generation)?,
            )?;
        }
        Ok(())
    }

    fn no_connection(&self) -> Test {
        assert_eq!(
            self.listener
                .accept()
                .err()
                .ok_or("unapproved second socket")?
                .kind(),
            ErrorKind::WouldBlock
        );
        Ok(())
    }
}

fn setup_peer(peer: &TcpStream) -> Test {
    peer.set_read_timeout(Some(Duration::from_secs(2)))?;
    peer.set_write_timeout(Some(Duration::from_secs(2)))?;
    peer.set_nodelay(true)?;
    Ok(())
}

#[test]
fn real_hevc_eof_drains_then_reconnects_with_fresh_generation_and_authentication() -> Test {
    for chunk in [1, 7, 4096] {
        for digest in [false, true] {
            let mut f = Fixture::playing(chunk, digest, 2)?;
            f.record_and_eof()?;
            let old_key = f.authority.binding.key();
            let before = f.driver.resource_budget();
            let roots: Vec<_> = f.windows.iter().map(|w| w.manifest().root()).collect();
            let (live, recording, _) = configs(f.listener.local_addr()?, chunk, 1)?;
            let failure = f
                .driver
                .connect(live, recording, 41, &f.authority)
                .err()
                .ok_or("unacknowledged retry")?;
            assert!(matches!(
                failure.reason,
                SupervisedHevcRecordingError::Supervisor(ReconnectRefusal::AwaitingRetirement)
            ));
            assert_eq!(f.driver.resource_budget(), before);
            f.no_connection()?;
            f.driver.acknowledge_retirement(100, &f.authority)?;
            assert_eq!(f.driver.resource_budget(), before);
            assert_eq!(f.driver.next_wake_ns(), Some(110));
            let (live, recording, authority) = configs(f.listener.local_addr()?, chunk, 2)?;
            let error = f
                .driver
                .connect(live, recording, 109, &authority)
                .err()
                .ok_or("early retry")?;
            assert!(matches!(
                error.reason,
                SupervisedHevcRecordingError::Supervisor(ReconnectRefusal::NotReady)
            ));
            assert_eq!(f.driver.resource_budget(), before);
            f.no_connection()?;
            let (live, recording, authority) = configs(f.listener.local_addr()?, chunk, 2)?;
            let attempt = f.driver.connect(live, recording, 110, &authority)?;
            assert_eq!(attempt.ordinal, 2);
            assert_eq!(attempt.previous, Some((old_key, 100)));
            assert_eq!(attempt.key.generation, 2);
            let (peer, _) = f.listener.accept()?;
            setup_peer(&peer)?;
            f.peer = peer;
            f.authority = authority;
            f.negotiate(digest, 110)?;
            assert_eq!(f.driver.resource_budget().admitted_attempts(), 2);
            assert_eq!(
                roots,
                f.windows
                    .iter()
                    .map(|w| w.manifest().root())
                    .collect::<Vec<_>>()
            );
            // Old footage retains its old source basis through an actual new connection.
            for window in &f.windows {
                verify_hevc_recording(window.manifest(), window.objects(), &recording_scope(1)?)?;
                assert!(
                    verify_hevc_recording(
                        window.manifest(),
                        window.objects(),
                        &recording_scope(2)?
                    )
                    .is_err()
                );
            }
            let _retirement = f.driver.cancel().ok_or("second generation retirement")?;
        }
    }
    Ok(())
}

#[test]
fn spent_whole_run_budget_refuses_second_socket_without_losing_source_windows() -> Test {
    let mut f = Fixture::playing(7, true, 1)?;
    f.record_and_eof()?;
    let before = f.driver.resource_budget();
    f.driver.acknowledge_retirement(100, &f.authority)?;
    let (live, recording, authority) = configs(f.listener.local_addr()?, f.chunk, 2)?;
    let failure = f
        .driver
        .connect(live, recording, 110, &authority)
        .err()
        .ok_or("budget refilled")?;
    assert!(matches!(
        failure.reason,
        SupervisedHevcRecordingError::Supervisor(ReconnectRefusal::Resources(_))
    ));
    assert!(failure.retirement.is_none());
    assert_eq!(f.driver.resource_budget(), before);
    f.no_connection()?;
    assert_eq!(f.windows.len(), 2);
    for window in &f.windows {
        verify_hevc_recording(window.manifest(), window.objects(), &recording_scope(1)?)?;
    }
    assert!(f.driver.cancel().is_none());
    assert_eq!(f.driver.resource_budget(), before);
    Ok(())
}

#[test]
fn first_resource_refusal_can_be_corrected_without_pinning_a_rejected_profile() -> Test {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let (mut live, recording, authority) = configs(listener.local_addr()?, 7, 1)?;
    let budget = ReconnectBudget::for_attempts(live.transport, live.max_steps, 1)?;
    let mut driver =
        SupervisedHevcRecording::new_with_budget(live.binding.clone(), policy(), budget, 0)?;
    let before = driver.resource_budget();
    live.max_steps += 1;
    live.realm = "rejected-profile-realm".into();
    let failure = driver
        .connect(live, recording, 0, &authority)
        .err()
        .ok_or("excess work admitted")?;
    assert!(matches!(
        failure.reason,
        SupervisedHevcRecordingError::Supervisor(ReconnectRefusal::Resources(_))
    ));
    assert_eq!(driver.resource_budget(), before);
    assert_eq!(
        listener
            .accept()
            .err()
            .ok_or("refusal opened socket")?
            .kind(),
        ErrorKind::WouldBlock
    );
    let (live, recording, authority) = configs(listener.local_addr()?, 7, 1)?;
    assert_eq!(driver.connect(live, recording, 1, &authority)?.ordinal, 1);
    let (_peer, _) = listener.accept()?;
    let _retired = driver.cancel().ok_or("retirement")?;
    Ok(())
}

#[test]
fn scope_and_lease_errors_never_reserve_or_connect() -> Test {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let (live, _, _) = configs(listener.local_addr()?, 7, 1)?;
    let mut driver = SupervisedHevcRecording::new(live.binding, policy(), 0)?;
    let before = driver.resource_budget();
    for mismatch in 0..3 {
        let (mut live, mut recording, authority) = configs(listener.local_addr()?, 7, 1)?;
        match mismatch {
            0 => live.deadline_ns += 1,
            1 => recording.scope.generation += 1,
            _ => live.binding = configs(listener.local_addr()?, 7, 2)?.0.binding,
        }
        let error = driver
            .connect(live, recording, 0, &authority)
            .err()
            .ok_or("invalid scope admitted")?;
        assert!(matches!(
            error.reason,
            SupervisedHevcRecordingError::Supervisor(ReconnectRefusal::Scope)
        ));
        assert_eq!(driver.resource_budget(), before);
        assert_eq!(
            listener
                .accept()
                .err()
                .ok_or("invalid scope opened socket")?
                .kind(),
            ErrorKind::WouldBlock
        );
    }
    Ok(())
}

#[test]
fn retries_pin_media_auth_and_exact_parameter_bytes_including_uninterpreted_suffixes() -> Test {
    let mut f = Fixture::playing(7, false, 3)?;
    f.record_and_eof()?;
    f.driver.acknowledge_retirement(100, &f.authority)?;
    let before = f.driver.resource_budget();
    for changed in 0..9 {
        let (mut live, mut recording, authority) = configs(f.listener.local_addr()?, f.chunk, 2)?;
        match changed {
            0 => live.realm = "different-realm".into(),
            1 => live.digest_policy.allow_legacy_md5 = true,
            2 => live.assembly.max_age_ns -= 1,
            3 => live.reorder.max_delay_ns -= 1,
            4 => recording.time_scale = 45_000,
            5 => recording.payload_type = 99,
            6 => recording.limits.max_age_ns -= 1,
            7 => recording.scope.sensor = fss_core::SensorId::parse("different-sensor")?,
            _ => {
                let original = configuration()?;
                let mut pps = original.pps().to_vec();
                pps.push(0x80);
                recording.configuration = HevcConfiguration::parse(
                    original.vps(),
                    original.sps(),
                    &pps,
                    HevcConfigurationLimits::default(),
                )?;
            }
        }
        let failure = f
            .driver
            .connect(live, recording, 110, &authority)
            .err()
            .ok_or("profile drift admitted")?;
        assert!(matches!(
            failure.reason,
            SupervisedHevcRecordingError::Supervisor(ReconnectRefusal::Scope)
        ));
        assert_eq!(f.driver.resource_budget(), before);
        f.no_connection()?;
    }
    Ok(())
}

#[test]
fn source_eob_drains_its_final_picture_then_stops_without_a_reconnect() -> Test {
    let mut f = Fixture::playing(7, false, 3)?;
    f.probation()?;
    let data = input()?;
    for (i, packet) in data[..data.len() - 1].iter().enumerate() {
        assert_eq!(
            f.feed(&packet.bytes, 20 + u64::try_from(i)?, true)?,
            Stop::Pending
        );
    }
    assert_eq!(f.timed.len(), 3);
    let original = data.last().ok_or("missing fixture EOS")?;
    let eob = packet(original.sequence, 54_000, true, &[0x4a, 1, 0x80]);
    assert_eq!(f.feed(&eob.bytes, 35, true)?, Stop::Ended);
    assert_eq!(f.timed.len(), 4); // final picture timing was not bypassed by EOB
    assert_eq!(f.windows.len(), 2);
    assert_eq!(f.transports.len(), 1);
    assert!(!f.transports[0].totals.peer_eof);
    assert_eq!(
        f.driver.status(),
        ReconnectStatus::Stopped(ReconnectStop::SourceEnded)
    );
    let budget = f.driver.resource_budget();
    assert!(f.driver.acknowledge_retirement(36, &f.authority).is_err());
    assert!(f.driver.cancel().is_none());
    assert_eq!(
        f.driver.status(),
        ReconnectStatus::Stopped(ReconnectStop::SourceEnded)
    );
    assert_eq!(f.driver.resource_budget(), budget);
    assert_eq!(f.driver.next_wake_ns(), None);
    f.no_connection()?;
    for window in &f.windows {
        verify_hevc_recording(window.manifest(), window.objects(), &recording_scope(1)?)?;
    }
    Ok(())
}

#[test]
fn marker_and_tcp_eof_preserve_an_unverified_tail_without_a_fabricated_picture() -> Test {
    let mut f = Fixture::playing(4096, false, 2)?;
    f.probation()?;
    // Parameter sets plus one IDR; no following picture prefix/AUD/EOS/EOB.
    for (i, packet) in input()?[..4].iter().enumerate() {
        assert_eq!(
            f.feed(&packet.bytes, 20 + u64::try_from(i)?, true)?,
            Stop::Pending
        );
    }
    f.peer.shutdown(Shutdown::Write)?;
    assert_eq!(f.drain(40, true, f.raw.len(), true)?, Stop::Ended);
    assert!(f.windows.is_empty());
    assert!(f.timed.is_empty());
    assert!(
        f.events
            .iter()
            .any(|event| matches!(event, Event::Ended { tail: Some(_), .. }))
    );
    assert_eq!(
        f.driver.status(),
        ReconnectStatus::Retired(f.authority.binding.key())
    );
    assert!(matches!(
        f.terminal,
        Some(HevcCapturePoll::Ended { retained: Some(_) })
    ));
    Ok(())
}

#[test]
fn wrong_generation_seal_and_bad_timing_preserve_the_real_held_picture_and_deadline() -> Test {
    let mut f = Fixture::playing(7, false, 2)?;
    let request = f.timing_wait()?;
    let ticket = f.driver.timing_ticket().ok_or("missing picture ticket")?;
    assert_eq!(ticket.request(), request);
    let wake = f.driver.next_wake_ns();
    let totals = f.driver.totals();
    let budget = f.driver.resource_budget();
    let wrong_key = StreamKey {
        generation: request.key.generation + 1,
        ..request.key
    };
    let failure = f
        .driver
        .seal(wrong_key, 25, &f.authority)
        .err()
        .ok_or("stale timing applied")?;
    assert!(failure.retirement.is_none());
    assert!(matches!(
        failure.reason,
        SupervisedHevcRecordingError::Supervisor(ReconnectRefusal::Scope)
    ));
    let failure = f
        .driver
        .seal(request.key, 24, &f.authority)
        .err()
        .ok_or("reversed clock admitted")?;
    assert!(matches!(
        failure.reason,
        SupervisedHevcRecordingError::Supervisor(ReconnectRefusal::ClockReversed)
    ));
    assert!(failure.retirement.is_none());
    let mut invalid = timings(1)[0];
    invalid.duration = 0;
    assert!(
        f.driver
            .supply_timing_for(&ticket, invalid, 26, &f.authority)
            .err()
            .ok_or("invalid timing")?
            .retirement
            .is_none()
    );
    assert_eq!(f.driver.next_wake_ns(), wake);
    f.peer.write_all(b"private-unread-test-sentinel")?;
    assert_eq!(
        f.drain(27, false, f.raw.len(), false)?,
        Stop::Timing(request)
    );
    assert_eq!(f.driver.totals(), totals);
    assert_eq!(f.driver.resource_budget(), budget);
    assert_eq!(f.driver.timing_ticket().as_ref(), Some(&ticket));
    let timed = f
        .driver
        .supply_timing_for(&ticket, timings(1)[0], 28, &f.authority)?;
    assert!(f.driver.timing_ticket().is_none());
    assert!(matches!(timed.event.as_ref(), Event::Assembly { .. }));
    let _retired = f.driver.cancel().ok_or("held source lost")?;
    Ok(())
}

#[test]
fn revocation_while_timing_is_pending_returns_all_original_work_exactly_once() -> Test {
    let mut f = Fixture::playing(7, true, 2)?;
    let request = f.timing_wait()?;
    let ticket = f.driver.timing_ticket().ok_or("missing picture ticket")?;
    assert_eq!(ticket.request(), request);
    let budget = f.driver.resource_budget();
    let totals = f.driver.totals().ok_or("totals")?;
    f.authority.denied.set(Some(TcpDenial::Revoked));
    let failure = f
        .driver
        .supply_timing_for(&ticket, timings(1)[0], 25, &f.authority)
        .err()
        .ok_or("revocation ignored")?;
    let retired = failure.retirement.ok_or("source lost on revocation")?;
    assert_eq!(
        retired
            .connection
            .ok_or("native ownership")?
            .transport
            .totals,
        totals
    );
    assert_eq!(retired.capture.collection.sources.len(), 5);
    assert!(matches!(
        retired.capture.event.as_deref(),
        Some(Event::Assembly { .. })
    ));
    assert_eq!(f.driver.resource_budget(), budget);
    assert_eq!(
        f.driver.status(),
        ReconnectStatus::Stopped(ReconnectStop::Denied(TcpDenial::Revoked))
    );
    f.authority.denied.set(None);
    assert!(f.driver.cancel().is_none());
    assert_eq!(
        f.driver.status(),
        ReconnectStatus::Stopped(ReconnectStop::Denied(TcpDenial::Revoked))
    );
    assert_eq!(f.driver.next_wake_ns(), None);
    Ok(())
}

#[test]
fn a_source_gap_is_a_permanent_refusal_not_a_transient_socket_retry() -> Test {
    let mut f = Fixture::playing(4096, false, 2)?;
    f.probation()?;
    let data = input()?;
    for (i, packet) in data[..5].iter().enumerate() {
        f.feed(&packet.bytes, 20 + u64::try_from(i)?, true)?;
    }
    f.feed(&data[6].bytes, 30, true)?;
    let now = 30 + ReorderLimits::default().max_delay_ns;
    assert_eq!(f.drain(now, true, f.raw.len(), false)?, Stop::Stopped);
    assert_eq!(
        f.driver.status(),
        ReconnectStatus::Stopped(ReconnectStop::PermanentFailure)
    );
    let Some(HevcCapturePoll::Stopped { retained, .. }) = &f.terminal else {
        return Err("missing source invalidation".into());
    };
    assert!(matches!(retained.event.as_deref(), Some(Event::Gap { .. })));
    assert_eq!(retained.collection.pictures.len(), 1);
    assert!(f.windows.is_empty());
    assert!(f.driver.acknowledge_retirement(now, &f.authority).is_err());
    f.no_connection()?;
    Ok(())
}

#[test]
fn cancel_preserves_a_sealed_but_unreturned_recording_without_publishing_or_refunding() -> Test {
    let mut f = Fixture::playing(7, false, 2)?;
    let request = f.timing_wait()?;
    let ticket = f.driver.timing_ticket().ok_or("missing picture ticket")?;
    assert_eq!(ticket.request(), request);
    let _timed = f
        .driver
        .supply_timing_for(&ticket, timings(1)[0], 25, &f.authority)?;
    let seal = f.driver.seal(request.key, 26, &f.authority)?;
    assert!(seal.window_ready);
    let before = f.driver.resource_budget();
    let (key, retired) = f.driver.cancel().ok_or("ready window lost")?;
    assert_eq!(key, request.key);
    let window = retired
        .capture
        .collection
        .ready
        .ok_or("ready window lost")?;
    verify_hevc_recording(window.manifest(), window.objects(), &recording_scope(1)?)?;
    assert!(
        retired
            .connection
            .ok_or("connection")?
            .protocol
            .client
            .session
            .remote_session_may_exist
    );
    assert!(f.windows.is_empty());
    assert!(f.driver.cancel().is_none());
    assert_eq!(f.driver.resource_budget(), before);
    assert_eq!(f.driver.next_wake_ns(), None);
    Ok(())
}

#[test]
fn revoked_backoff_cannot_be_revived_or_open_a_new_generation() -> Test {
    let mut f = Fixture::playing(4096, false, 2)?;
    f.record_and_eof()?;
    f.driver.acknowledge_retirement(100, &f.authority)?;
    let (live, recording, authority) = configs(f.listener.local_addr()?, 4096, 2)?;
    authority.denied.set(Some(TcpDenial::Revoked));
    let before = f.driver.resource_budget();
    let failure = f
        .driver
        .connect(live, recording, 110, &authority)
        .err()
        .ok_or("revoked next generation")?;
    assert!(failure.retirement.is_none());
    assert_eq!(f.driver.resource_budget(), before);
    authority.denied.set(None);
    let (live, recording, _) = configs(f.listener.local_addr()?, 4096, 2)?;
    assert!(f.driver.connect(live, recording, 111, &authority).is_err());
    assert_eq!(
        f.driver.status(),
        ReconnectStatus::Stopped(ReconnectStop::Denied(TcpDenial::Revoked))
    );
    f.no_connection()?;
    Ok(())
}

#[test]
fn retained_windows_publish_and_reopen_after_reconnect_capacity_is_exhausted() -> Test {
    use fss_object::SpoolLimits;
    use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
    use fss_reference::rtsp::recording::hevc::local::load_hevc_recording;
    use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};

    struct OwnedDirectory(std::path::PathBuf);
    impl OwnedDirectory {
        fn create() -> Test<Self> {
            let parent = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
            std::fs::create_dir_all(&parent)?;
            for index in 0..256 {
                let path = parent.join(format!(
                    "supervised-hevc-custody-{}-{index}",
                    std::process::id()
                ));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Ok(Self(path)),
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Err("exclusive fixture directory bound".into())
        }
    }
    impl Drop for OwnedDirectory {
        fn drop(&mut self) {
            // Only this fixture's successfully and exclusively created directory.
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    let mut f = Fixture::playing(7, true, 1)?;
    f.record_and_eof()?;
    f.driver.acknowledge_retirement(100, &f.authority)?;
    let (live, recording, authority) = configs(f.listener.local_addr()?, 7, 2)?;
    let failure = f
        .driver
        .connect(live, recording, 110, &authority)
        .err()
        .ok_or("budget refilled")?;
    assert!(matches!(
        failure.reason,
        SupervisedHevcRecordingError::Supervisor(ReconnectRefusal::Resources(_))
    ));
    f.no_connection()?;
    assert!(f.driver.cancel().is_none());
    drop(f.driver); // publication does not depend on a live acquisition owner

    let directory = OwnedDirectory::create()?;
    let limits = LocalPublicationLimits::new(
        32,
        64,
        32,
        128,
        SpoolLimits::new(128, 16 * 1024 * 1024, 2 * 1024 * 1024, 128),
    );
    {
        let mut publisher = LocalRootPublisher::open(&directory.0, limits)?;
        for (i, window) in f.windows.iter().enumerate() {
            let slot = SlotName::parse(&format!("supervised-hevc-{i}"))?;
            assert!(publisher.root(&slot).is_none());
            let mut job = RecordingPublication::new(
                window.publication_plan(),
                &mut publisher,
                slot,
                window.byte_len(),
                100,
            )?;
            let mut published = false;
            for now in 0..5 {
                if let RecordingProgress::Published(receipt) = job.step(now, &NeverCancel)? {
                    assert_eq!(receipt.root, window.manifest().root());
                    published = true;
                }
            }
            assert!(published);
        }
    }
    let publisher = LocalRootPublisher::open(&directory.0, limits)?;
    for (i, window) in f.windows.iter().enumerate() {
        let loaded = load_hevc_recording(
            &publisher,
            &SlotName::parse(&format!("supervised-hevc-{i}"))?,
            window.manifest().root(),
            &recording_scope(1)?,
            &NeverCancel,
        )?;
        assert_eq!(loaded.manifest(), window.manifest());
        assert_eq!(loaded.samples(), window.samples());
        assert_eq!(loaded.mappings(), window.mappings());
        assert_eq!(loaded.objects().source, window.objects().source);
        assert_eq!(
            loaded.objects().initialization,
            window.objects().initialization
        );
        assert_eq!(loaded.objects().media, window.objects().media);
        assert_eq!(loaded.objects().index, window.objects().index);
    }
    Ok(())
}

#[test]
fn a_delayed_same_generation_timing_reply_cannot_time_the_next_picture() -> Test {
    let mut f = Fixture::playing(7, true, 2)?;
    let first_request = f.timing_wait()?;
    let first = f.driver.timing_ticket().ok_or("missing first ticket")?;
    assert_eq!(first.request(), first_request);
    assert_eq!(
        f.drain(25, false, f.raw.len(), false)?,
        Stop::Timing(first_request)
    );
    assert_eq!(f.driver.timing_ticket().as_ref(), Some(&first));
    let timed = f
        .driver
        .supply_timing_for(&first, timings(1)[0], 26, &f.authority)?;
    f.timed.push(timed);
    assert!(f.driver.timing_ticket().is_none());

    let mut next_request = None;
    for (index, packet) in input()?[5..].iter().enumerate() {
        match f.feed(&packet.bytes, 30 + u64::try_from(index)?, false)? {
            Stop::Timing(request) => {
                next_request = Some(request);
                break;
            }
            Stop::Pending => {}
            _ => return Err("missing second source picture".into()),
        }
    }
    let next_request = next_request.ok_or("second timing request did not arrive")?;
    let second = f.driver.timing_ticket().ok_or("missing second ticket")?;
    assert_eq!(first.key(), second.key()); // The stream-generation fence alone is insufficient.
    assert_eq!(second.request(), next_request);
    assert_eq!(second.ordinal(), first.ordinal() + 1);
    let totals = f.driver.totals();
    let budget = f.driver.resource_budget();
    let wake = f.driver.next_wake_ns();
    // The proposed timing is valid for the second picture, so only correlation can refuse it.
    let failure = f
        .driver
        .supply_timing_for(&first, timings(2)[1], 50, &f.authority)
        .err()
        .ok_or("old picture ticket timed a different current picture")?;
    assert!(matches!(
        failure.reason,
        SupervisedHevcRecordingError::Timing(HevcTimingRefusal::StaleTicket)
    ));
    assert!(failure.retirement.is_none());
    assert_eq!(f.driver.timing_ticket().as_ref(), Some(&second));
    assert_eq!(f.driver.totals(), totals);
    assert_eq!(f.driver.resource_budget(), budget);
    assert_eq!(f.driver.next_wake_ns(), wake);
    f.timed.push(
        f.driver
            .supply_timing_for(&second, timings(2)[1], 51, &f.authority)?,
    );
    assert!(f.driver.timing_ticket().is_none());
    let repeat = f
        .driver
        .supply_timing_for(&second, timings(2)[1], 52, &f.authority)
        .err()
        .ok_or("successful ticket was reusable")?;
    assert!(matches!(
        repeat.reason,
        SupervisedHevcRecordingError::Timing(HevcTimingRefusal::StaleTicket)
    ));
    assert!(repeat.retirement.is_none());
    let _retired = f.driver.cancel().ok_or("missing exact remaining source")?;
    Ok(())
}

#[test]
fn identical_picture_metadata_from_another_owner_is_not_a_timing_ticket() -> Test {
    let mut left = Fixture::playing(7, false, 2)?;
    let mut right = Fixture::playing(7, false, 2)?;
    assert_eq!(left.timing_wait()?, right.timing_wait()?);
    let left_ticket = left.driver.timing_ticket().ok_or("missing left ticket")?;
    let right_ticket = right.driver.timing_ticket().ok_or("missing right ticket")?;
    assert_eq!(left_ticket.ordinal(), right_ticket.ordinal());
    assert_eq!(left_ticket.request(), right_ticket.request());
    assert_ne!(left_ticket, right_ticket);
    let totals = right.driver.totals();
    let wake = right.driver.next_wake_ns();
    let failure = right
        .driver
        .supply_timing_for(&left_ticket, timings(1)[0], 25, &right.authority)
        .err()
        .ok_or("another owner's ticket was admitted")?;
    assert!(matches!(
        failure.reason,
        SupervisedHevcRecordingError::Timing(HevcTimingRefusal::StaleTicket)
    ));
    assert!(failure.retirement.is_none());
    assert_eq!(right.driver.totals(), totals);
    assert_eq!(right.driver.next_wake_ns(), wake);
    assert_eq!(right.driver.timing_ticket().as_ref(), Some(&right_ticket));
    // A wrong ticket must not hide live revocation or prevent original-work retirement.
    right.authority.denied.set(Some(TcpDenial::Revoked));
    let failure = right
        .driver
        .supply_timing_for(&left_ticket, timings(1)[0], 26, &right.authority)
        .err()
        .ok_or("wrong ticket hid revoked authority")?;
    assert!(matches!(
        failure.reason,
        SupervisedHevcRecordingError::Supervisor(ReconnectRefusal::Stopped(ReconnectStop::Denied(
            TcpDenial::Revoked
        )))
    ));
    let retired = failure.retirement.ok_or("revocation lost held picture")?;
    assert!(matches!(
        retired.capture.event.as_deref(),
        Some(Event::Assembly { .. })
    ));
    assert!(right.driver.timing_ticket().is_none());
    assert!(right.driver.cancel().is_none());
    let _left = left
        .driver
        .cancel()
        .ok_or("missing left owner retirement")?;
    Ok(())
}

#[test]
fn reconnect_never_reuses_a_previous_picture_ticket_or_ordinal() -> Test {
    let mut f = Fixture::playing(7, false, 2)?;
    f.timing_wait()?;
    let old = f.driver.timing_ticket().ok_or("missing original ticket")?;
    f.timed.push(
        f.driver
            .supply_timing_for(&old, timings(1)[0], 25, &f.authority)?,
    );
    for (index, packet) in input()?[5..].iter().enumerate() {
        assert_eq!(
            f.feed(&packet.bytes, 30 + u64::try_from(index)?, true)?,
            Stop::Pending
        );
    }
    f.peer.shutdown(Shutdown::Write)?;
    assert_eq!(f.drain(50, true, f.raw.len(), true)?, Stop::Ended);
    assert!(f.driver.timing_ticket().is_none());
    f.driver.acknowledge_retirement(100, &f.authority)?;
    let (live, recording, authority) = configs(f.listener.local_addr()?, 7, 2)?;
    f.driver.connect(live, recording, 110, &authority)?;
    let (peer, _) = f.listener.accept()?;
    setup_peer(&peer)?;
    f.peer = peer;
    f.authority = authority;
    f.negotiate(false, 110)?;
    assert_eq!(
        f.feed(&packet(0, 0, false, &nals()?[0]).bytes, 120, false)?,
        Stop::Pending
    );
    let mut request = Stop::Pending;
    for (index, packet) in input()?[..5].iter().enumerate() {
        request = f.feed(&packet.bytes, 130 + u64::try_from(index)?, false)?;
    }
    assert!(matches!(request, Stop::Timing(_)));
    let new = f
        .driver
        .timing_ticket()
        .ok_or("missing new generation ticket")?;
    assert_eq!(new.key().generation, 2);
    assert!(new.ordinal() > old.ordinal());
    let budget = f.driver.resource_budget();
    let totals = f.driver.totals();
    let failure = f
        .driver
        .supply_timing_for(&old, timings(1)[0], 140, &f.authority)
        .err()
        .ok_or("old generation's timing ticket was reused")?;
    assert!(matches!(
        failure.reason,
        SupervisedHevcRecordingError::Timing(HevcTimingRefusal::StaleTicket)
    ));
    assert!(failure.retirement.is_none());
    assert_eq!(f.driver.timing_ticket().as_ref(), Some(&new));
    assert_eq!(f.driver.resource_budget(), budget);
    assert_eq!(f.driver.totals(), totals);
    let _timed = f
        .driver
        .supply_timing_for(&new, timings(1)[0], 141, &f.authority)?;
    let _retired = f.driver.cancel().ok_or("missing new generation source")?;
    assert!(f.driver.timing_ticket().is_none());
    Ok(())
}

#[test]
fn changed_sdp_payload_after_reconnect_preserves_originals_and_never_retries() -> Test {
    use fss_reference::rtsp::hevc_recording_capture::CaptureError;
    use fss_reference::rtsp::hevc_recording_capture::live::LiveHevcRecordingError;
    use fss_reference::rtsp::recording_collector::CollectorError;

    let mut f = Fixture::playing(7, false, 3)?;
    f.record_and_eof()?;
    let roots: Vec<_> = f.windows.iter().map(|w| w.manifest().root()).collect();
    f.driver.acknowledge_retirement(100, &f.authority)?;
    let (live, recording, authority) = configs(f.listener.local_addr()?, 7, 2)?;
    f.driver.connect(live, recording, 110, &authority)?;
    let (peer, _) = f.listener.accept()?;
    setup_peer(&peer)?;
    f.peer = peer;
    f.authority = authority;
    let (describe, _) = f.command(110)?;
    let sent = f
        .driver
        .totals()
        .ok_or("missing second transport")?
        .sent_bytes;
    let original = response(
        describe.cseq,
        "Content-Type: application/sdp\r\n",
        &sdp().replace("98", "99"),
    );
    f.peer.write_all(&original)?;
    let mut refusal = None;
    for _ in 0..LOOP_BOUND {
        match f
            .driver
            .poll(ready(), &credentials()?, [0; 16], 111, &f.authority)
        {
            Err(failure) => {
                refusal = Some(failure);
                break;
            }
            Ok(Supervised::Recording {
                output: Step::Network(LiveHevcStep::Wire(chunk)),
                ..
            }) => {
                f.raw.extend_from_slice(chunk.expose());
            }
            Ok(Supervised::Recording {
                output: Step::Network(LiveHevcStep::Pending(_)),
                ..
            }) => {
                std::thread::yield_now();
            }
            _ => return Err("wrong selection was delivered or scheduled SETUP".into()),
        }
    }
    let failure = refusal.ok_or("changed payload was not refused")?;
    assert!(matches!(
        failure.reason,
        SupervisedHevcRecordingError::Recording(LiveHevcRecordingError::Capture(
            CaptureError::Collection(CollectorError::StreamMismatch)
        ))
    ));
    let retired = failure
        .retirement
        .ok_or("source-bearing failure lost retirement")?;
    let Event::Client { event, work: None } =
        *retired.unoffered_event.ok_or("missing original SDP")?
    else {
        return Err("wrong source type".into());
    };
    let HevcClientPoll::Control { source, .. } = *event else {
        return Err("SDP response not retained".into());
    };
    assert_eq!(source.expose_wire(), original);
    assert_eq!(
        retired
            .connection
            .ok_or("missing native retirement")?
            .transport
            .totals
            .sent_bytes,
        sent
    );
    assert_eq!(
        f.driver.status(),
        ReconnectStatus::Stopped(ReconnectStop::PermanentFailure)
    );
    assert_eq!(f.driver.resource_budget().admitted_attempts(), 2);
    assert!(f.driver.acknowledge_retirement(112, &f.authority).is_err());
    assert_eq!(
        f.windows
            .iter()
            .map(|w| w.manifest().root())
            .collect::<Vec<_>>(),
        roots
    );
    for window in &f.windows {
        verify_hevc_recording(window.manifest(), window.objects(), &recording_scope(1)?)?;
    }
    f.no_connection()?;
    Ok(())
}

#[test]
fn legacy_synchronous_timing_keeps_its_signature_and_consumes_the_current_ticket() -> Test {
    let mut f = Fixture::playing(7, false, 2)?;
    let request = f.timing_wait()?;
    let ticket = f.driver.timing_ticket().ok_or("missing timing ticket")?;
    let mut invalid = timings(1)[0];
    invalid.duration = 0;
    let failure = f
        .driver
        .supply_timing(request.key, invalid, 25, &f.authority)
        .err()
        .ok_or("invalid legacy timing accepted")?;
    assert!(failure.retirement.is_none());
    assert_eq!(f.driver.timing_ticket().as_ref(), Some(&ticket));
    let timed = f
        .driver
        .supply_timing(request.key, timings(1)[0], 26, &f.authority)?;
    f.timed.push(timed);
    assert!(f.driver.timing_ticket().is_none());
    let totals = f.driver.totals();
    let failure = f
        .driver
        .supply_timing_for(&ticket, timings(1)[0], 27, &f.authority)
        .err()
        .ok_or("consumed compatibility ticket replayed")?;
    assert!(matches!(
        failure.reason,
        SupervisedHevcRecordingError::Timing(HevcTimingRefusal::StaleTicket)
    ));
    assert!(failure.retirement.is_none());
    assert_eq!(f.driver.totals(), totals);
    let (_, retired) = f.driver.cancel().ok_or("missing native ownership")?;
    assert_eq!(retired.capture.collection.pictures.len(), 1);
    assert!(retired.connection.is_some());
    Ok(())
}
