#![forbid(unsafe_code)]
//! Public native TCP -> automatic HEVC -> source-closed recording contracts.
//! Synthetic fixtures and owner-declared timing; not camera or detection-quality qualification.

mod hevc_recording_support;

use fss_core::ContentDigest;
use fss_object::SpoolLimits;
use fss_packet::hevc::HevcAssemblyLimits;
use fss_packet::{H265Limits, ReorderLimits, StreamKey};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};
use fss_reference::rtsp::client::{ClientCommand, ClientConfig, ClientProgress, ClientState};
use fss_reference::rtsp::hevc_client::{HevcClientPoll, pictures::HevcPictureClientPoll as Event};
use fss_reference::rtsp::hevc_recording_capture::live::{
    AutomaticHevcRecordingStep as Step, AutomaticLiveHevcRecording, LiveHevcRecordingConfig,
    LiveHevcRecordingError,
};
use fss_reference::rtsp::hevc_recording_capture::{
    CaptureError, HevcCapturePoll, HevcPictureTimingRequest, TimedHevcCapture,
};
use fss_reference::rtsp::hevc_recording_collector::HevcCollectionSeal;
use fss_reference::rtsp::live_hevc::{
    LiveHevcConfig, LiveHevcError, LiveHevcRetirement, LiveHevcStep, QueuedHevcRequest,
    SocketReadiness,
};
use fss_reference::rtsp::recording::hevc::local::load_hevc_recording;
use fss_reference::rtsp::recording::hevc::{PreparedHevcRecording, verify_hevc_recording};
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording_collector::{CollectionStop, CollectorError, CollectorLimits};
use fss_reference::rtsp::tcp::{
    TcpAuthority, TcpBinding, TcpDenial, TcpError, TcpLimits, TcpOperation, TcpRetirement,
    TcpSecurityPolicy, TcpWriteStep,
};
use hevc_recording_support::*;
use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

type Test<T = ()> = Result<T, Error>;
const LEASE: u64 = 100_000_000_000;
const KEY: StreamKey = StreamKey {
    ingress: 1,
    generation: 1,
    ssrc: SSRC,
};
static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

struct Authority {
    binding: TcpBinding,
    revoked: Cell<bool>,
    checks: Cell<u64>,
}
impl TcpAuthority for Authority {
    fn checkpoint(
        &self,
        binding: &TcpBinding,
        _: TcpOperation,
        now: u64,
        until: u64,
    ) -> Result<(), TcpDenial> {
        self.checks.set(self.checks.get() + 1);
        if binding != &self.binding {
            return Err(TcpDenial::Unauthorized);
        }
        if self.revoked.get() {
            return Err(TcpDenial::Revoked);
        }
        if until != LEASE || now >= until {
            return Err(TcpDenial::Deadline);
        }
        Ok(())
    }
}
fn configs(
    peer: std::net::SocketAddr,
    chunk: usize,
) -> Test<(LiveHevcConfig, LiveHevcRecordingConfig, Authority)> {
    let binding = TcpBinding::new(
        KEY,
        peer,
        "fixture.local",
        TcpSecurityPolicy::OwnerApprovedPlaintext,
    )?;
    let authority = Authority {
        binding: binding.clone(),
        revoked: Cell::new(false),
        checks: Cell::new(0),
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
        scope: scope()?,
        payload_type: PT,
        configuration: configuration()?,
        time_scale: 90_000,
        limits: CollectorLimits::default(),
    };
    Ok((live, recording, authority))
}
fn credentials() -> Test<DigestCredentials<'static>> {
    Ok(DigestCredentials::new("test-user", "test-password")?)
}
fn readiness() -> SocketReadiness {
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
    let mut frame = vec![b'$', 0];
    frame.extend_from_slice(&u16::try_from(packet.len())?.to_be_bytes());
    frame.extend_from_slice(packet);
    Ok(frame)
}
fn input() -> Test<Vec<Packet>> {
    let mut data = packets()?;
    for (i, p) in data.iter_mut().enumerate() {
        p.sequence = i as u64 + 1;
        p.bytes[2..4].copy_from_slice(&u16::try_from(p.sequence)?.to_be_bytes());
    }
    Ok(data)
}
fn fresh() -> Test<PathBuf> {
    let parent = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("live-hevc-recording");
    std::fs::create_dir_all(&parent)?;
    for _ in 0..256 {
        let path = parent.join(format!(
            "{}-{}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err("fixture path bound exhausted".into())
}
fn store_limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        32,
        64,
        32,
        128,
        SpoolLimits::new(128, 16 * 1024 * 1024, 2 * 1024 * 1024, 128),
    )
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
    driver: AutomaticLiveHevcRecording,
    peer: TcpStream,
    authority: Authority,
    nonce: u128,
    raw: Vec<u8>,
    events: Vec<Event>,
    windows: Vec<PreparedHevcRecording>,
    timed: Vec<TimedHevcCapture>,
    seals: Vec<HevcCollectionSeal>,
    transport: Vec<TcpRetirement>,
    connections: Vec<LiveHevcRetirement>,
    terminal: Option<HevcCapturePoll>,
}
impl Fixture {
    fn new(chunk: usize) -> Test<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let (live, recording, authority) = configs(listener.local_addr()?, chunk)?;
        let driver = AutomaticLiveHevcRecording::connect(live, recording, 0, &authority)?;
        let (peer, _) = listener.accept()?;
        peer.set_read_timeout(Some(Duration::from_secs(2)))?;
        peer.set_write_timeout(Some(Duration::from_secs(2)))?;
        peer.set_nodelay(true)?;
        Ok(Self {
            driver,
            peer,
            authority,
            nonce: 0,
            raw: Vec::new(),
            events: Vec::new(),
            windows: Vec::new(),
            timed: Vec::new(),
            seals: Vec::new(),
            transport: Vec::new(),
            connections: Vec::new(),
            terminal: None,
        })
    }
    fn poll(&mut self, ready: SocketReadiness, now: u64) -> Test<Step> {
        let nonce = if self.driver.needs_credentials() {
            self.nonce += 1;
            self.nonce.to_be_bytes()
        } else {
            [0; 16]
        };
        Ok(self
            .driver
            .poll(ready, &credentials()?, nonce, now, &self.authority)?)
    }
    fn command(&mut self, now: u64) -> Test<(QueuedHevcRequest, Vec<u8>)> {
        assert!(self.driver.needs_credentials());
        let Step::Queued(queued) = self.poll(SocketReadiness::default(), now)? else {
            return Err("automatic command not prepared".into());
        };
        for _ in 0..32_768 {
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
                _ => return Err("unexpected progress during HEVC command dispatch".into()),
            }
        }
        Err("HEVC command dispatch bound".into())
    }
    fn reply(&mut self, bytes: &[u8], now: u64, expected: Expected) -> Test {
        self.peer.write_all(bytes)?;
        let before = self.raw.len();
        for _ in 0..32_768 {
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
                        return Err("control reply became a capture failure or media claim".into());
                    };
                    let found = match (expected, event.as_ref()) {
                        (Expected::State(state), Event::Client { event, work: None }) => {
                            matches!(event.as_ref(),
                            HevcClientPoll::Control { progress: ClientProgress::Accepted(s), .. } if *s == state)
                        }
                        (Expected::Challenge, Event::Client { event, work: None }) => matches!(
                            event.as_ref(),
                            HevcClientPoll::AuthenticationRequired { .. }
                        ),
                        _ => false,
                    };
                    self.events.push(*event);
                    if found {
                        assert_eq!(&self.raw[before..], bytes);
                        return Ok(());
                    }
                }
                _ => return Err("unexpected output before matching control acceptance".into()),
            }
        }
        Err("HEVC control reply bound".into())
    }
    fn playing(chunk: usize, digest: bool) -> Test<Self> {
        let mut f = Self::new(chunk)?;
        let (describe, wire) = f.command(0)?;
        assert_eq!(describe.command, ClientCommand::Describe);
        assert!(!std::str::from_utf8(&wire)?.contains("Authorization:"));
        let cseq = if digest {
            let raw = challenge(describe.cseq, "test-realm");
            f.reply(&raw, 1, Expected::Challenge)?;
            let (answer, wire) = f.command(2)?;
            assert_eq!(answer.command, ClientCommand::Describe);
            assert!(answer.cseq > describe.cseq);
            assert_eq!(
                answer
                    .challenge
                    .as_ref()
                    .ok_or("challenge lost")?
                    .expose_wire(),
                raw
            );
            let text = std::str::from_utf8(&wire)?;
            assert!(text.contains("Authorization: Digest "));
            assert!(!text.contains("test-password"));
            answer.cseq
        } else {
            describe.cseq
        };
        f.reply(
            &response(cseq, "Content-Type: application/sdp\r\n", sdp()),
            3,
            Expected::State(ClientState::Described),
        )?;
        let (setup, _) = f.command(4)?;
        assert_eq!(setup.command, ClientCommand::Setup);
        f.reply(&response(setup.cseq,
            "Session: test-session;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n", ""),
            5, Expected::State(ClientState::Ready))?;
        let (play, _) = f.command(6)?;
        assert_eq!(play.command, ClientCommand::Play);
        f.reply(
            &response(play.cseq, "Session: test-session\r\n", ""),
            7,
            Expected::State(ClientState::Playing),
        )?;
        assert!(!f.driver.needs_credentials());
        assert!(f.windows.is_empty());
        assert!(f.timed.is_empty());
        Ok(f)
    }
    fn drain(&mut self, now: u64, automatic_timing: bool) -> Test<Stop> {
        for _ in 0..32_768 {
            match self.poll(readiness(), now)? {
                Step::Network(LiveHevcStep::Wire(chunk)) => {
                    self.raw.extend_from_slice(chunk.expose())
                }
                Step::Network(LiveHevcStep::InputEnded) => {}
                Step::Network(LiveHevcStep::Pending(wait)) => {
                    if wait.wake_at_ns.is_none_or(|at| at > now) {
                        return Ok(Stop::Pending);
                    }
                }
                Step::ProtocolQueued { transport } => {
                    if let Some(t) = transport {
                        self.transport.push(*t);
                    }
                }
                Step::Capture { event, connection } => {
                    if let Some(c) = connection {
                        self.connections.push(*c);
                    }
                    match *event {
                        HevcCapturePoll::Receiver(event) => self.events.push(*event),
                        HevcCapturePoll::TimingRequired(request) => {
                            if !automatic_timing {
                                return Ok(Stop::Timing(request));
                            }
                            let timing = timings(self.timed.len() + 1)[self.timed.len()];
                            self.timed.push(self.driver.supply_timing(
                                timing,
                                now,
                                &self.authority,
                            )?);
                        }
                        HevcCapturePoll::Window(window) => self.windows.push(*window),
                        HevcCapturePoll::Sealed(seal) => self.seals.push(seal),
                        event @ HevcCapturePoll::Stopped { .. } => {
                            self.terminal = Some(event);
                            return Ok(Stop::Stopped);
                        }
                        event @ HevcCapturePoll::Ended { .. } => {
                            self.terminal = Some(event);
                            return Ok(Stop::Ended);
                        }
                        _ => return Err("unexpected collection pressure in bounded fixture".into()),
                    }
                }
                Step::Ended => return Ok(Stop::Ended),
                _ => return Err("unexpected automatic request during media fixture".into()),
            }
        }
        Err("HEVC media progress bound".into())
    }
    fn feed(&mut self, bytes: &[u8], now: u64, automatic_timing: bool) -> Test<Stop> {
        let wire = framed(bytes)?;
        let before = self.raw.len();
        self.peer.write_all(&wire)?;
        for _ in 0..1000 {
            let stop = self.drain(now, automatic_timing)?;
            if stop != Stop::Pending || self.raw.len() - before == wire.len() {
                assert_eq!(&self.raw[before..], wire);
                return Ok(stop);
            }
            std::thread::yield_now();
        }
        Err("HEVC input delivery bound".into())
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
        let data = input()?;
        let mut last = Stop::Pending;
        for (i, packet) in data[..5].iter().enumerate() {
            last = self.feed(&packet.bytes, 20 + i as u64, false)?;
        }
        match last {
            Stop::Timing(request) => Ok(request),
            _ => Err("first real picture did not request explicit timing".into()),
        }
    }
    fn finish(&mut self) -> Test {
        self.peer.shutdown(Shutdown::Write)?;
        for _ in 0..1000 {
            match self.drain(40, true)? {
                Stop::Ended => return Ok(()),
                Stop::Pending => std::thread::yield_now(),
                _ => return Err("clean source EOF became a failure".into()),
            }
        }
        Err("HEVC EOF drain bound".into())
    }
}

#[test]
fn native_plain_and_digest_capture_publish_and_cold_replay_identically_across_chunk_sizes() -> Test
{
    let mut identities: Vec<Vec<ContentDigest>> = Vec::new();
    for chunk in [1, 7, 4096] {
        for digest in [false, true] {
            let mut f = Fixture::playing(chunk, digest)?;
            f.probation()?;
            for (i, packet) in input()?.iter().enumerate() {
                assert_eq!(f.feed(&packet.bytes, 20 + i as u64, true)?, Stop::Pending);
            }
            f.finish()?;
            assert_eq!(f.timed.len(), 4);
            assert_eq!(f.windows.len(), 2);
            assert!(matches!(
                f.terminal,
                Some(HevcCapturePoll::Ended { retained: Some(_) })
            ));
            assert_eq!(f.transport.len(), 1);
            assert!(f.transport[0].totals.peer_eof);
            assert!(f.connections.is_empty());
            assert!(matches!(f.poll(readiness(), 41)?, Step::Ended));
            assert_eq!(f.driver.next_wake_ns(), None);
            assert!(f.driver.cancel().is_none());
            let roots: Vec<_> = f.windows.iter().map(|w| w.manifest().root()).collect();
            let path = fresh()?;
            {
                let mut publisher = LocalRootPublisher::open(&path, store_limits())?;
                for (i, window) in f.windows.iter().enumerate() {
                    verify_hevc_recording(window.manifest(), window.objects(), &scope()?)?;
                    let slot = SlotName::parse(&format!("live-hevc-{i}"))?;
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
                        if let RecordingProgress::Published(receipt) =
                            job.step(now, &NeverCancel)?
                        {
                            assert_eq!(receipt.root, window.manifest().root());
                            published = true;
                        }
                    }
                    assert!(published);
                }
            }
            let publisher = LocalRootPublisher::open(&path, store_limits())?;
            for (i, original) in f.windows.iter().enumerate() {
                let loaded = load_hevc_recording(
                    &publisher,
                    &SlotName::parse(&format!("live-hevc-{i}"))?,
                    original.manifest().root(),
                    &scope()?,
                    &NeverCancel,
                )?;
                assert_eq!(loaded.manifest(), original.manifest());
                assert_eq!(loaded.samples(), original.samples());
                assert_eq!(loaded.mappings(), original.mappings());
                assert_eq!(loaded.objects().source, original.objects().source);
                assert_eq!(
                    loaded.objects().initialization,
                    original.objects().initialization
                );
                assert_eq!(loaded.objects().media, original.objects().media);
                assert_eq!(loaded.objects().index, original.objects().index);
            }
            identities.push(roots);
        }
    }
    assert!(identities.windows(2).all(|pair| pair[0] == pair[1]));
    Ok(())
}

#[test]
fn pending_timing_blocks_socket_read_ahead_and_safe_correction_keeps_its_deadline() -> Test {
    let mut f = Fixture::playing(7, false)?;
    let request = f.timing_wait()?;
    assert!(request.idr);
    assert_eq!(request.rtp_timestamp, 0);
    let wake = f.driver.next_wake_ns().ok_or("deadline")?;
    assert!(wake > 24); // queued upstream work must not busy-wake this timing wait
    let totals = f.driver.totals();
    let mut wrong = timings(1)[0];
    wrong.duration = 0;
    let failure = f
        .driver
        .supply_timing(wrong, 25, &f.authority)
        .err()
        .ok_or("invalid timing admitted")?;
    assert_eq!(
        failure.reason,
        LiveHevcRecordingError::Capture(CaptureError::Collection(CollectorError::Timeline))
    );
    assert!(failure.retirement.is_none());
    assert_eq!(f.driver.next_wake_ns(), Some(wake));
    f.peer.write_all(b"PRIVATE_UNREAD_SOURCE_SENTINEL")?;
    for now in 26..30 {
        assert_eq!(f.drain(now, false)?, Stop::Timing(request));
        assert_eq!(f.driver.totals(), totals);
        assert_eq!(f.driver.next_wake_ns(), Some(wake));
        assert!(!f.driver.needs_credentials());
    }
    let timed = f.driver.supply_timing(timings(1)[0], 30, &f.authority)?;
    assert!(matches!(timed.event.as_ref(), Event::Assembly { .. }));
    assert_eq!(f.driver.collector().retained_samples(), 1);
    assert_eq!(f.driver.totals(), totals);
    let retired = f.driver.cancel().ok_or("retirement")?;
    assert_eq!(retired.capture.collection.pictures.len(), 1);
    assert!(retired.connection.is_some());
    Ok(())
}

#[test]
fn revoked_timing_admission_returns_the_original_picture_and_packets_once() -> Test {
    let mut f = Fixture::playing(4096, true)?;
    f.timing_wait()?;
    let totals = f.driver.totals().ok_or("totals")?;
    f.authority.revoked.set(true);
    let error = f
        .driver
        .supply_timing(timings(1)[0], 25, &f.authority)
        .err()
        .ok_or("revocation ignored")?;
    assert_eq!(
        error.reason,
        LiveHevcRecordingError::Network(LiveHevcError::Transport(TcpError::Denied(
            TcpDenial::Revoked
        )))
    );
    let retired = error.retirement.ok_or("retirement")?;
    assert_eq!(
        retired.connection.ok_or("connection")?.transport.totals,
        totals
    );
    assert_eq!(retired.capture.collection.sources.len(), 5);
    assert!(retired.capture.collection.pictures.is_empty());
    assert!(matches!(
        retired.capture.event.as_deref(),
        Some(Event::Assembly { .. })
    ));
    assert!(f.driver.cancel().is_none());
    assert_eq!(f.driver.next_wake_ns(), None);
    Ok(())
}

#[test]
fn expired_picture_closes_the_socket_without_sealing_a_fake_recording() -> Test {
    let mut f = Fixture::playing(7, false)?;
    f.timing_wait()?;
    let wake = f.driver.next_wake_ns().ok_or("deadline")?;
    assert_eq!(f.drain(wake, false)?, Stop::Stopped);
    assert_eq!(f.connections.len(), 1);
    let Some(HevcCapturePoll::Stopped {
        reason, retained, ..
    }) = &f.terminal
    else {
        return Err("missing stopped capture".into());
    };
    assert_eq!(*reason, CollectionStop::Deadline);
    assert_eq!(retained.collection.sources.len(), 5);
    assert!(retained.collection.ready.is_none());
    assert!(matches!(
        retained.event.as_deref(),
        Some(Event::Assembly { .. })
    ));
    assert!(f.windows.is_empty());
    assert!(f.driver.cancel().is_none());
    assert!(matches!(f.poll(readiness(), wake)?, Step::Ended));
    Ok(())
}

#[test]
fn rtp_gap_stops_live_collection_and_keeps_its_exact_invalidation_event() -> Test {
    let mut f = Fixture::playing(4096, false)?;
    f.probation()?;
    let data = input()?;
    for (i, packet) in data[..5].iter().enumerate() {
        f.feed(&packet.bytes, 20 + i as u64, true)?;
    }
    f.feed(&data[6].bytes, 30, true)?; // sequence six is deliberately missing
    let now = 30 + ReorderLimits::default().max_delay_ns;
    assert_eq!(f.drain(now, true)?, Stop::Stopped);
    let Some(HevcCapturePoll::Stopped {
        reason, retained, ..
    }) = &f.terminal
    else {
        return Err("gap was not retained".into());
    };
    assert_eq!(*reason, CollectionStop::InputDiscontinuity);
    assert!(matches!(retained.event.as_deref(), Some(Event::Gap { .. })));
    assert_eq!(retained.collection.pictures.len(), 1);
    assert!(retained.collection.ready.is_none());
    assert_eq!(f.connections.len(), 1);
    assert!(f.windows.is_empty());
    assert!(f.driver.seal(now, &f.authority).is_err());
    assert!(f.driver.cancel().is_none());
    Ok(())
}

#[test]
fn explicit_cancel_preserves_a_prepared_window_without_publishing_it() -> Test {
    let mut f = Fixture::playing(7, false)?;
    f.probation()?;
    for (i, packet) in input()?[..5].iter().enumerate() {
        f.feed(&packet.bytes, 20 + i as u64, true)?;
    }
    let seal = f.driver.seal(25, &f.authority)?;
    assert!(seal.window_ready);
    let retired = f.driver.cancel().ok_or("retirement")?;
    let window = retired
        .capture
        .collection
        .ready
        .ok_or("prepared window lost")?;
    verify_hevc_recording(window.manifest(), window.objects(), &scope()?)?;
    assert!(
        retired
            .connection
            .ok_or("connection")?
            .protocol
            .client
            .session
            .remote_session_may_exist
    );
    assert!(f.windows.is_empty()); // no window was transferred or published by polling
    assert!(!f.driver.needs_credentials());
    assert!(f.driver.cancel().is_none());
    Ok(())
}

#[test]
fn automatic_keepalive_waits_for_the_existing_due_event_and_acknowledgement() -> Test {
    let mut f = Fixture::playing(7, true)?;
    let due = f.driver.next_wake_ns().ok_or("keepalive wake")?;
    assert!(due > 7);
    let mut due_seen = false;
    for _ in 0..16 {
        match f.poll(SocketReadiness::default(), due)? {
            Step::ProtocolQueued { transport: None } => {}
            Step::Capture {
                event,
                connection: None,
            } => {
                if let HevcCapturePoll::Receiver(source) = *event {
                    if matches!(source.as_ref(), Event::Client { event, work: None }
                        if matches!(event.as_ref(), HevcClientPoll::KeepAliveDue))
                    {
                        due_seen = true;
                        break;
                    }
                }
            }
            _ => return Err("unexpected automatic keepalive progress".into()),
        }
    }
    assert!(due_seen);
    let (queued, wire) = f.command(due)?;
    assert_eq!(queued.command, ClientCommand::KeepAlive);
    assert!(std::str::from_utf8(&wire)?.starts_with("OPTIONS "));
    f.reply(
        &response(queued.cseq, "Session: test-session\r\n", ""),
        due + 1,
        Expected::State(ClientState::Playing),
    )?;
    assert!(!f.driver.needs_credentials());
    assert!(f.windows.is_empty());
    assert!(f.timed.is_empty());
    let _retired = f.driver.cancel().ok_or("retirement")?;
    Ok(())
}

#[test]
fn invalid_recording_configuration_never_opens_a_socket() -> Test {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let (live, mut recording, authority) = configs(listener.local_addr()?, 7)?;
    recording.time_scale = 0;
    let error = AutomaticLiveHevcRecording::connect(live, recording, 0, &authority)
        .err()
        .ok_or("invalid recording connected")?;
    assert!(!error.connection_attempted);
    assert_eq!(authority.checks.get(), 0);
    Ok(())
}

#[test]
fn work_exhaustion_keeps_the_unsent_automatic_request_without_replenishing_it() -> Test {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let (mut live, recording, authority) = configs(listener.local_addr()?, 7)?;
    live.max_steps = 1;
    let mut driver = AutomaticLiveHevcRecording::connect(live, recording, 0, &authority)?;
    let (_peer, _) = listener.accept()?;
    assert!(matches!(
        driver.poll(
            SocketReadiness::default(),
            &credentials()?,
            [1; 16],
            0,
            &authority
        )?,
        Step::Queued(_)
    ));
    let error = driver
        .poll(readiness(), &credentials()?, [2; 16], 0, &authority)
        .err()
        .ok_or("work allowance replenished")?;
    assert_eq!(
        error.reason,
        LiveHevcRecordingError::Network(LiveHevcError::WorkBudget)
    );
    let retired = error.retirement.ok_or("retirement")?;
    let connection = retired.connection.ok_or("connection")?;
    assert!(connection.transport.request.is_some());
    assert_eq!(connection.transport.totals.sent_bytes, 0);
    assert_eq!(connection.transport.totals.read_calls, 0);
    assert!(driver.cancel().is_none());
    assert!(matches!(
        driver.poll(readiness(), &credentials()?, [0; 16], 1, &authority)?,
        Step::Ended
    ));
    Ok(())
}

#[test]
fn wrong_digest_realm_closes_without_dispatch_and_preserves_the_challenge() -> Test {
    let mut f = Fixture::new(7)?;
    let (describe, _) = f.command(0)?;
    let raw = challenge(describe.cseq, "unapproved-realm");
    f.reply(&raw, 1, Expected::Challenge)?;
    let sent = f.driver.totals().ok_or("totals")?.sent_bytes;
    let error = f
        .driver
        .poll(readiness(), &credentials()?, [9; 16], 2, &f.authority)
        .err()
        .ok_or("wrong realm admitted")?;
    let retired = error.retirement.ok_or("retirement")?;
    let connection = retired.connection.ok_or("connection")?;
    assert_eq!(connection.transport.totals.sent_bytes, sent);
    assert_eq!(
        connection
            .protocol
            .client
            .challenge
            .ok_or("challenge lost")?
            .expose_wire(),
        raw
    );
    assert!(retired.capture.collection.sources.is_empty());
    assert!(!f.driver.needs_credentials());
    assert_eq!(f.driver.next_wake_ns(), None);
    Ok(())
}
