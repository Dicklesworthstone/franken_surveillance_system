#![forbid(unsafe_code)]
//! Local fixture-only regressions for unsent control intent and native input drainage.
//! Every socket is loopback-bound; no device discovery or external endpoint is contacted.

use std::cell::Cell;
use std::fmt;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::time::Duration;

use fss_core::{ContentDigest, SensorId, StreamId};
use fss_packet::{StreamKey, avc::AvcReceiveLimits};
use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};
use fss_reference::rtsp::avc_client::{AvcClientPoll, authenticated::DigestAvcPoll};
use fss_reference::rtsp::client::{ClientCommand, ClientConfig, ClientProgress, ClientState};
use fss_reference::rtsp::live_avc::automatic::{
    AutomaticAvcConnection, AutomaticAvcRecording, AutomaticAvcStep, AutomaticRecordingStep,
};
use fss_reference::rtsp::live_avc::recording::{
    LiveRecordingConfig, LiveRecordingError, LiveRecordingFailure, LiveRecordingStep,
};
use fss_reference::rtsp::live_avc::{
    LiveAvcConfig, LiveAvcError, LiveAvcFailure, LiveAvcStep, QueuedAvcRequest, SocketReadiness,
};
use fss_reference::rtsp::recording::RecordingScope;
use fss_reference::rtsp::recording_collector::CollectorLimits;
use fss_reference::rtsp::tcp::{
    TcpAuthority, TcpBinding, TcpDenial, TcpError, TcpLimits, TcpOperation, TcpSecurityPolicy,
    TcpTotals, TcpWriteStep,
};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const DEADLINE: u64 = 100_000_000_000;
const KEY: StreamKey = StreamKey { ingress: 71, generation: 1, ssrc: 7 };
const SDP: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\na=control:trackID=0\r\n";

struct Authority { binding: TcpBinding, revoked: Cell<bool> }
impl TcpAuthority for Authority {
    fn checkpoint(&self, binding: &TcpBinding, _: TcpOperation, now: u64, until: u64)
        -> Result<(), TcpDenial>
    {
        if binding != &self.binding { return Err(TcpDenial::Unauthorized); }
        if self.revoked.get() { return Err(TcpDenial::Revoked); }
        if until != DEADLINE || now >= until { return Err(TcpDenial::Deadline); }
        Ok(())
    }
}
#[derive(Debug)]
enum Failure { Connection(LiveAvcFailure), Recording(LiveRecordingFailure) }
impl Failure {
    fn reason(&self) -> Option<&LiveAvcError> {
        match self {
            Self::Connection(e) => Some(&e.reason),
            Self::Recording(e) => match &e.reason {
                LiveRecordingError::Network(e) => Some(e), _ => None,
            },
        }
    }
    fn retired(&self) -> bool {
        match self {
            Self::Connection(e) => e.retirement.is_some(),
            Self::Recording(e) => e.retirement.is_some(),
        }
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "fixture refusal: {self:?}") }
}
impl std::error::Error for Failure {}

#[derive(Debug)]
enum Step { Queued(QueuedAvcRequest), Live(LiveAvcStep), Recording(LiveRecordingStep) }
impl Step {
    fn live(&self) -> Option<&LiveAvcStep> {
        match self {
            Self::Live(s) => Some(s),
            Self::Recording(LiveRecordingStep::Stopped { trigger, .. }) => Some(trigger),
            _ => None,
        }
    }
    fn accepted(&self, state: ClientState) -> bool {
        matches!(self.live(), Some(LiveAvcStep::Protocol {
            event: DigestAvcPoll::Client { event, .. }, ..
        }) if matches!(event.as_ref(), AvcClientPoll::Control(ClientProgress::Accepted(s)) if *s == state))
    }
    fn terminal(&self) -> bool {
        matches!(self.live(), Some(LiveAvcStep::Protocol { transport: Some(_), .. }))
            || matches!(self, Self::Recording(LiveRecordingStep::Stopped { .. } | LiveRecordingStep::Ended))
    }
}
enum Driver { Connection(AutomaticAvcConnection), Recording(AutomaticAvcRecording) }
impl Driver {
    fn needs_credentials(&self) -> bool {
        match self { Self::Connection(d) => d.needs_credentials(), Self::Recording(d) => d.needs_credentials() }
    }
    fn next_wake_ns(&self) -> Option<u64> {
        match self { Self::Connection(d) => d.next_wake_ns(), Self::Recording(d) => d.next_wake_ns() }
    }
    fn totals(&self) -> Option<TcpTotals> {
        match self { Self::Connection(d) => d.totals(), Self::Recording(d) => d.totals() }
    }
    fn poll(&mut self, ready: SocketReadiness, now: u64, authority: &Authority)
        -> Result<Step, Failure>
    {
        let credentials = DigestCredentials::new("fixture-user", "fixture-password")
            .expect("static fixture credentials");
        match self {
            Self::Connection(d) => d.poll(ready, &credentials, [1; 16], now, authority)
                .map(|step| match step { AutomaticAvcStep::Queued(q) => Step::Queued(q), AutomaticAvcStep::Live(s) => Step::Live(s) })
                .map_err(Failure::Connection),
            Self::Recording(d) => d.poll(ready, &credentials, [1; 16], now, authority)
                .map(|step| match step {
                    AutomaticRecordingStep::Queued(q) => Step::Queued(q),
                    AutomaticRecordingStep::Recording(LiveRecordingStep::Network(s)) => Step::Live(s),
                    AutomaticRecordingStep::Recording(s) => Step::Recording(s),
                }).map_err(Failure::Recording),
        }
    }
    fn cancel(&mut self) -> bool {
        match self { Self::Connection(d) => d.cancel().is_some(), Self::Recording(d) => d.cancel().is_some() }
    }
}
struct Fixture { driver: Driver, peer: TcpStream, authority: Authority }
impl Fixture {
    fn new(recording: bool, max_steps: u64) -> Test<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let binding = TcpBinding::new(KEY, listener.local_addr()?, "camera.local",
            TcpSecurityPolicy::OwnerApprovedPlaintext)?;
        let authority = Authority { binding: binding.clone(), revoked: Cell::new(false) };
        let config = LiveAvcConfig {
            protocol: ClientConfig {
                presentation_uri: "rtsp://camera.local/live/".into(),
                control_root_uri: "rtsp://camera.local/live".into(),
                media_index: 0, channels: (0, 1), response_timeout_ns: 10_000_000_000,
                default_session_timeout_seconds: 60,
            },
            binding, transport: TcpLimits::default(), media: AvcReceiveLimits::default(),
            realm: "fixture-camera".into(), digest_policy: DigestPolicy::default(),
            deadline_ns: DEADLINE, max_steps,
        };
        let driver = if recording {
            Driver::Recording(AutomaticAvcRecording::connect(config, LiveRecordingConfig {
                scope: RecordingScope {
                    sensor: SensorId::parse("sensor:control-drain")?,
                    stream: StreamId::parse("stream:control-drain")?, generation: 1,
                    anchor: ContentDigest::sha256(b"control fixture"),
                    receive_clock: ContentDigest::sha256(b"control fixture clock"),
                }, payload_type: 96, time_scale: 90_000, limits: CollectorLimits::default(),
            }, 0, &authority)?)
        } else {
            Driver::Connection(AutomaticAvcConnection::connect(config, 0, &authority)?)
        };
        let (peer, _) = listener.accept()?;
        peer.set_read_timeout(Some(Duration::from_secs(2)))?;
        peer.set_write_timeout(Some(Duration::from_secs(2)))?;
        peer.set_nodelay(true)?;
        Ok(Self { driver, peer, authority })
    }
    fn poll(&mut self, ready: SocketReadiness, now: u64) -> Result<Step, Failure> {
        self.driver.poll(ready, now, &self.authority)
    }
    fn command(&mut self, now: u64) -> Test<QueuedAvcRequest> {
        let Step::Queued(queued) = self.poll(SocketReadiness::default(), now)? else {
            return Err("automatic command not queued".into());
        };
        for _ in 0..1024 {
            match self.poll(SocketReadiness { readable: false, writable: true }, now)? {
                Step::Live(LiveAvcStep::Write(TcpWriteStep::Sent { bytes, cseq })) => {
                    assert_eq!((cseq, bytes), (queued.cseq, queued.bytes));
                    self.peer.read_exact(&mut vec![0; bytes])?;
                    return Ok(queued);
                }
                Step::Live(LiveAvcStep::Write(_) | LiveAvcStep::Pending(_)) => {},
                _ => return Err("unexpected request dispatch output".into()),
            }
        }
        Err("request dispatch bound".into())
    }
    fn receive(&mut self, bytes: &[u8], state: ClientState, now: u64) -> Test {
        self.peer.write_all(bytes)?;
        let mut original = Vec::new();
        for _ in 0..1024 {
            let step = self.poll(SocketReadiness { readable: true, writable: false }, now)?;
            if let Some(LiveAvcStep::Wire(chunk)) = step.live() {
                original.extend_from_slice(chunk.expose());
            }
            if step.accepted(state) {
                assert_eq!(original, bytes, "fixture must preload the complete coalesced input");
                return Ok(());
            }
            if step.terminal() { return Err("reply refused before expected acceptance".into()); }
            std::thread::yield_now();
        }
        Err("reply drain bound".into())
    }
    fn blocked(&mut self, suffix: &[u8]) -> Test {
        let describe = self.command(0)?;
        let mut bytes = response(describe.cseq, "Content-Type: application/sdp\r\n", SDP);
        bytes.extend_from_slice(suffix);
        self.receive(&bytes, ClientState::Described, 1)?;
        assert!(self.driver.needs_credentials());
        let failure = self.poll(SocketReadiness::default(), 2).err().ok_or("queued over retained input")?;
        assert!(matches!(failure.reason(), Some(LiveAvcError::Protocol(
            fss_reference::rtsp::avc_client::authenticated::DigestAvcError::Backpressure))));
        assert!(!failure.retired());
        assert!(!self.driver.needs_credentials());
        if suffix == b"RTSP/1." {
            // First probe the queued partial frame. Before this native turn, its wake
            // denotes runnable parser work, not yet the fixed missing-input deadline.
            assert!(matches!(self.poll(SocketReadiness::default(), 2)?,
                Step::Live(LiveAvcStep::Pending(_))));
            assert!(!self.driver.needs_credentials());
        }
        Ok(())
    }
    fn drain_fault(&mut self, now: u64) -> Test {
        for _ in 0..1024 {
            let step = self.poll(SocketReadiness { readable: true, writable: true }, now)?;
            assert!(!matches!(step, Step::Queued(_)), "must not issue SETUP before rejecting unsolicited input");
            if step.terminal() {
                assert!(!self.driver.needs_credentials());
                assert_eq!(self.driver.next_wake_ns(), None);
                assert!(!self.driver.cancel());
                return Ok(());
            }
            std::thread::yield_now();
        }
        Err("automatic control failed to drain retained protocol fault".into())
    }
}
fn response(cseq: u32, fields: &str, body: &str) -> Vec<u8> {
    format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{fields}\r\n{body}", body.len()).into_bytes()
}

#[test]
fn both_automatic_owners_drain_coalesced_protocol_faults_without_dispatching_setup() -> Test {
    for recording in [false, true] {
        let mut f = Fixture::new(recording, 10_000)?;
        f.blocked(&response(99, "", ""))?;
        f.drain_fault(3)?;
    }
    Ok(())
}
#[test]
fn fragmented_input_waits_do_not_busy_prepare_or_refresh_the_wire_deadline() -> Test {
    for recording in [false, true] {
        let mut f = Fixture::new(recording, 10_000)?;
        let suffix = response(99, "", "");
        f.blocked(&suffix[..7])?;
        let sent = f.driver.totals().ok_or("totals missing")?.sent_bytes;
        let deadline = f.driver.next_wake_ns().ok_or("wire deadline missing")?;
        assert!(deadline > 10);
        for now in 3..10 {
            assert!(matches!(f.poll(SocketReadiness::default(), now)?, Step::Live(LiveAvcStep::Pending(_))));
            assert!(!f.driver.needs_credentials());
            assert_eq!(f.driver.next_wake_ns(), Some(deadline));
            assert_eq!(f.driver.totals().ok_or("totals missing")?.sent_bytes, sent);
        }
        f.peer.write_all(&suffix[7..])?;
        f.drain_fault(10)?;
    }
    Ok(())
}
#[test]
fn revocation_during_deferred_control_retires_source_once() -> Test {
    for recording in [false, true] {
        let mut f = Fixture::new(recording, 10_000)?;
        f.blocked(b"RTSP/1.")?;
        f.authority.revoked.set(true);
        let failure = f.poll(SocketReadiness::default(), 3).err().ok_or("revocation passed")?;
        assert_eq!(failure.reason(), Some(&LiveAvcError::Transport(TcpError::Denied(TcpDenial::Revoked))));
        assert!(failure.retired());
        assert!(!f.driver.needs_credentials());
        assert_eq!(f.driver.next_wake_ns(), None);
        assert!(!f.driver.cancel());
    }
    Ok(())
}
#[test]
fn deferred_input_still_spends_the_original_finite_work_allowance() -> Test {
    for recording in [false, true] {
        let mut f = Fixture::new(recording, 16)?;
        f.blocked(b"RTSP/1.")?;
        let mut exhausted = false;
        for _ in 0..32 {
            match f.poll(SocketReadiness::default(), 3) {
                Ok(step) => assert!(!matches!(step, Step::Queued(_))),
                Err(failure) => {
                    assert_eq!(failure.reason(), Some(&LiveAvcError::WorkBudget));
                    assert!(failure.retired());
                    exhausted = true;
                    break;
                }
            }
        }
        assert!(exhausted);
        assert!(!f.driver.cancel());
    }
    Ok(())
}
#[test]
fn reversed_clock_during_drain_preserves_input_and_scheduling() -> Test {
    for recording in [false, true] {
        let mut f = Fixture::new(recording, 10_000)?;
        f.blocked(b"RTSP/1.")?;
        let totals = f.driver.totals();
        let wake = f.driver.next_wake_ns();
        let failure = f.poll(SocketReadiness::default(), 1).err().ok_or("clock reversal passed")?;
        assert_eq!(failure.reason(), Some(&LiveAvcError::ClockReversed));
        assert!(!failure.retired());
        assert_eq!(f.driver.totals(), totals);
        assert_eq!(f.driver.next_wake_ns(), wake);
        assert!(!f.driver.needs_credentials());
        assert!(f.driver.cancel());
    }
    Ok(())
}
#[test]
fn partial_wire_expiry_terminates_without_rearming_setup_or_renewing_time() -> Test {
    for recording in [false, true] {
        let mut f = Fixture::new(recording, 10_000)?;
        f.blocked(b"RTSP/1.")?;
        let deadline = f.driver.next_wake_ns().ok_or("fixed wire deadline missing")?;
        let step = f.poll(SocketReadiness::default(), deadline)?;
        assert!(step.terminal());
        assert!(!f.driver.needs_credentials());
        assert_eq!(f.driver.next_wake_ns(), None);
        assert!(!f.driver.cancel());
    }
    Ok(())
}
#[test]
fn ordinary_accepted_negotiation_and_keepalive_still_queue_once() -> Test {
    for recording in [false, true] {
        let mut f = Fixture::new(recording, 10_000)?;
        let describe = f.command(0)?;
        f.receive(&response(describe.cseq, "Content-Type: application/sdp\r\n", SDP), ClientState::Described, 1)?;
        let setup = f.command(2)?;
        assert_eq!(setup.command, ClientCommand::Setup);
        f.receive(&response(setup.cseq,
            "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n", ""), ClientState::Ready, 3)?;
        let play = f.command(4)?;
        assert_eq!(play.command, ClientCommand::Play);
        f.receive(&response(play.cseq, "Session: fixture\r\n", ""), ClientState::Playing, 5)?;
        let due = f.driver.next_wake_ns().ok_or("keepalive missing")?;
        let _event = f.poll(SocketReadiness::default(), due)?;
        let keepalive = f.command(due)?;
        assert_eq!(keepalive.command, ClientCommand::KeepAlive);
        f.receive(&response(keepalive.cseq, "Session: fixture\r\n", ""), ClientState::Playing, due + 1)?;
        assert!(!f.driver.needs_credentials());
        assert!(f.driver.cancel());
    }
    Ok(())
}
