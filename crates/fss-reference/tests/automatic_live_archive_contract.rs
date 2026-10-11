#![forbid(unsafe_code)]
//! Public-API loopback contracts for automatic RTSP -> protected native recording archives.
//! Synthetic media and explicit owner timing only; these are not real-camera qualification.

use fss_core::{ContentDigest, SensorId, StreamId};
use fss_object::SpoolLimits;
use fss_packet::{StreamKey, avc::AvcReceiveLimits};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, PublishCancellation, PublishCutPoint};
use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};
use fss_reference::rtsp::avc_client::{AvcClientPoll, authenticated::DigestAvcPoll};
use fss_reference::rtsp::client::{ClientCommand, ClientConfig, ClientProgress, ClientState};
use fss_reference::rtsp::live_archive::{LiveArchiveCompletion, LiveArchiveConfig, LiveArchiveError, LiveArchiveStep};
use fss_reference::rtsp::live_archive::checkpointed::{AutomaticLiveArchiveStep, AutomaticLiveAvcArchive, CheckpointedLiveArchiveStep};
use fss_reference::rtsp::live_avc::{LiveAvcConfig, LiveAvcStep, QueuedAvcRequest, SocketReadiness};
use fss_reference::rtsp::live_avc::recording::{LiveRecordingConfig, LiveRecordingStep};
use fss_reference::rtsp::recording::{MAX_RECORDING_BYTES, RecordingScope, local::load_recording};
use fss_reference::rtsp::recording_archive::{ArchiveAdmission, ArchiveError, ArchiveLimits, ArchiveNamespace, ArchiveWriteProgress};
use fss_reference::rtsp::recording_archive::checkpoint::{ArchiveWorkLimits, load_archive_work};
use fss_reference::rtsp::recording_archive::checkpoint::write_ahead::{ArchiveCheckpoint, CheckpointedArchiveProgress};
use fss_reference::rtsp::recording_capture::CapturePoll;
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_collector::{CollectorLimits, RecordingTiming};
use fss_reference::rtsp::tcp::{TcpAuthority, TcpBinding, TcpDenial, TcpLimits, TcpOperation, TcpSecurityPolicy, TcpWriteStep};
use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const LEASE: u64 = 100_000_000_000;
const PAUSE: u64 = 1_000_000_000;
const KEY: StreamKey = StreamKey { ingress: 71, generation: 1, ssrc: 7 };
static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

fn fresh() -> Test<PathBuf> {
    for _ in 0..256 {
        let path = std::env::temp_dir().join(format!("fss-auto-archive-{}-{}", std::process::id(), NEXT_PATH.fetch_add(1, Ordering::Relaxed)));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err("fixture directory allowance exhausted".into())
}
fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(128, 1024, 128, 1024, SpoolLimits::new(1024, 16 * 1024 * 1024, 2 * 1024 * 1024, 1024))
}
struct Authority { binding: TcpBinding, revoked: Cell<bool> }
impl TcpAuthority for Authority {
    fn checkpoint(&self, binding: &TcpBinding, _: TcpOperation, now: u64, until: u64) -> Result<(), TcpDenial> {
        if binding != &self.binding { return Err(TcpDenial::Unauthorized); }
        if self.revoked.get() { return Err(TcpDenial::Revoked); }
        if now >= until || until != LEASE { return Err(TcpDenial::Deadline); }
        Ok(())
    }
}
struct Cancel;
impl PublishCancellation for Cancel {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool { true }
}
fn credentials() -> Test<DigestCredentials<'static>> {
    Ok(DigestCredentials::new("fixture-user", "fixture-password")?)
}
fn description() -> &'static str {
    "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LAC9oKEbARAAEAAAMAMg8UKqA=,aM4PLIA=\r\na=control:trackID=0\r\n"
}
fn response(cseq: u32, headers: &str, body: &str) -> Vec<u8> {
    format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}", body.len()).into_bytes()
}
fn readiness() -> SocketReadiness { SocketReadiness { readable: true, writable: true } }
fn nals() -> Vec<&'static [u8]> {
    let bytes: &'static [u8] = include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264");
    let mut out = Vec::new();
    let mut start = None;
    let mut at = 0;
    while at + 3 <= bytes.len() {
        let prefix = if bytes.get(at..at + 4) == Some(&[0, 0, 0, 1]) { 4 }
            else if bytes[at..at + 3] == [0, 0, 1] { 3 } else { 0 };
        if prefix == 0 { at += 1; continue; }
        if let Some(begin) = start {
            let mut end = at;
            while end > begin && bytes[end - 1] == 0 { end -= 1; }
            if begin < end { out.push(&bytes[begin..end]); }
        }
        start = Some(at + prefix);
        at += prefix;
    }
    if let Some(begin) = start && begin < bytes.len() { out.push(&bytes[begin..]); }
    out
}
fn wire(sequence: u16, marker: bool, payload: &[u8]) -> Test<Vec<u8>> {
    let mut packet = vec![0x80, 96 | if marker { 128 } else { 0 }];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&9_000_u32.to_be_bytes());
    packet.extend_from_slice(&KEY.ssrc.to_be_bytes());
    packet.extend_from_slice(payload);
    let mut wire = vec![b'$', 0];
    wire.extend_from_slice(&u16::try_from(packet.len())?.to_be_bytes());
    wire.extend_from_slice(&packet);
    Ok(wire)
}
struct Fixture<'a> {
    driver: AutomaticLiveAvcArchive<'a>,
    peer: TcpStream,
    authority: Authority,
    namespace: ArchiveNamespace,
    nonce: u128,
}
impl<'a> Fixture<'a> {
    fn new(publisher: &'a mut LocalRootPublisher, chunk: usize) -> Test<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let binding = TcpBinding::new(KEY, listener.local_addr()?, "camera.local", TcpSecurityPolicy::OwnerApprovedPlaintext)?;
        let authority = Authority { binding: binding.clone(), revoked: Cell::new(false) };
        let live = LiveAvcConfig {
            protocol: ClientConfig {
                presentation_uri: "rtsp://camera.local/live/".into(), control_root_uri: "rtsp://camera.local/live".into(),
                media_index: 0, channels: (0, 1), response_timeout_ns: 10_000_000_000, default_session_timeout_seconds: 60,
            },
            binding, transport: TcpLimits { chunk_bytes: chunk, ..TcpLimits::default() },
            media: AvcReceiveLimits::default(), realm: "fixture-camera".into(), digest_policy: DigestPolicy::default(),
            deadline_ns: LEASE, max_steps: 100_000,
        };
        let recording = LiveRecordingConfig {
            scope: RecordingScope {
                sensor: SensorId::parse("sensor:automatic-archive")?, stream: StreamId::parse("stream:automatic-archive")?,
                generation: KEY.generation, anchor: ContentDigest::sha256(b"automatic archive anchor"),
                receive_clock: ContentDigest::sha256(b"automatic receive clock"),
            },
            payload_type: 96, time_scale: 90_000, limits: CollectorLimits::default(),
        };
        let namespace = ArchiveNamespace::new(CatalogScope {
            recording: recording.scope.clone(), decode_clock: ContentDigest::sha256(b"automatic decode clock"), time_scale: recording.time_scale,
        })?;
        let archive = LiveArchiveConfig {
            namespace: namespace.clone(), limits: ArchiveLimits { max_windows: 8, max_pages: 8, max_scan_roots: 128, windows_per_page: 2 },
            max_window_bytes: MAX_RECORDING_BYTES, max_steps: 100_000,
            publication_deadline_ns: 2 * LEASE, max_storage_pause_ns: PAUSE,
        };
        let driver = AutomaticLiveAvcArchive::connect(live, recording, archive, ArchiveWorkLimits::default(), publisher, 0, &authority, &NeverCancel)?;
        let (peer, _) = listener.accept()?;
        peer.set_read_timeout(Some(Duration::from_secs(2)))?;
        peer.set_write_timeout(Some(Duration::from_secs(2)))?;
        peer.set_nodelay(true)?;
        Ok(Self { driver, peer, authority, namespace, nonce: 0 })
    }
    fn poll(&mut self, ready: SocketReadiness, now: u64) -> Test<AutomaticLiveArchiveStep> {
        self.nonce += 1;
        Ok(self.driver.poll(ready, &credentials()?, self.nonce.to_be_bytes(), now, &self.authority, &NeverCancel)?)
    }
    fn archive_poll(&mut self, now: u64) -> Test<CheckpointedLiveArchiveStep> {
        match self.poll(readiness(), now)? {
            AutomaticLiveArchiveStep::Archive(step) => Ok(step),
            AutomaticLiveArchiveStep::Queued(_) => Err("unexpected command during protected archive work".into()),
        }
    }
    fn command(&mut self, now: u64) -> Test<(QueuedAvcRequest, Vec<u8>)> {
        let mut queued = None;
        for _ in 0..16 {
            match self.poll(SocketReadiness::default(), now)? {
                AutomaticLiveArchiveStep::Queued(request) => { queued = Some(request); break; }
                AutomaticLiveArchiveStep::Archive(CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Archive(ArchiveWriteProgress::Ready { .. }))) => {}
                _ => return Err("automatic command bypassed expected recovery boundary".into()),
            }
        }
        let queued = queued.ok_or("command not prepared")?;
        assert!(!self.driver.needs_credentials());
        for _ in 0..32_768 {
            match self.poll(SocketReadiness { readable: false, writable: true }, now)? {
                AutomaticLiveArchiveStep::Archive(CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Recording(step))) => match *step {
                    LiveRecordingStep::Network(LiveAvcStep::Write(TcpWriteStep::Sent { cseq, bytes })) => {
                        assert_eq!((cseq, bytes), (queued.cseq, queued.bytes));
                        let mut original = vec![0; bytes];
                        self.peer.read_exact(&mut original)?;
                        return Ok((queued, original));
                    }
                    LiveRecordingStep::Network(LiveAvcStep::Write(TcpWriteStep::Advanced { .. }) | LiveAvcStep::Pending(_)) => {}
                    _ => return Err("unexpected capture output during request write".into()),
                },
                _ => return Err("unexpected archive output during request write".into()),
            }
        }
        Err("bounded request write exhausted".into())
    }
    fn receive(&mut self, bytes: &[u8], now: u64) -> Test<Vec<LiveRecordingStep>> {
        self.peer.write_all(bytes)?;
        let mut originals = Vec::new();
        let mut outputs = Vec::new();
        for _ in 0..32_768 {
            let AutomaticLiveArchiveStep::Archive(CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Recording(step))) =
                self.poll(SocketReadiness { readable: true, writable: false }, now)? else {
                    return Err("unexpected automatic command or storage work before reply transfer".into());
                };
            match *step {
                LiveRecordingStep::Network(LiveAvcStep::Wire(chunk)) => {
                    assert_eq!(chunk.admitted_ns(), now);
                    originals.extend_from_slice(chunk.expose());
                }
                LiveRecordingStep::Network(LiveAvcStep::Pending(wait)) => {
                    if originals.len() == bytes.len() && wait.wake_at_ns.is_none_or(|at| at > now) {
                        assert_eq!(originals, bytes);
                        return Ok(outputs);
                    }
                    std::thread::yield_now();
                }
                other => {
                    let stop = match &other {
                        LiveRecordingStep::Network(LiveAvcStep::Protocol { event: DigestAvcPoll::AuthenticationRequired { .. }, .. }) => true,
                        LiveRecordingStep::Network(LiveAvcStep::Protocol { event: DigestAvcPoll::Client { event, .. }, .. }) => matches!(event.as_ref(), AvcClientPoll::Control(_)),
                        LiveRecordingStep::Capture { event, .. } => matches!(event.as_ref(), CapturePoll::TimingRequired(_)),
                        _ => false,
                    };
                    outputs.push(other);
                    if stop { assert_eq!(originals, bytes); return Ok(outputs); }
                }
            }
        }
        Err("bounded reply intake exhausted".into())
    }
    fn playing(publisher: &'a mut LocalRootPublisher, chunk: usize) -> Test<Self> {
        let mut f = Self::new(publisher, chunk)?;
        assert!(!f.driver.needs_credentials()); // Existing inventory must drain first.
        let (describe, _) = f.command(0)?;
        assert_eq!(describe.command, ClientCommand::Describe);
        f.receive(&response(describe.cseq, "Content-Type: application/sdp\r\n", description()), 1)?;
        let (setup, _) = f.command(2)?;
        assert_eq!(setup.command, ClientCommand::Setup);
        f.receive(&response(setup.cseq, "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n", ""), 3)?;
        let (play, _) = f.command(4)?;
        assert_eq!(play.command, ClientCommand::Play);
        f.receive(&response(play.cseq, "Session: fixture\r\n", ""), 5)?;
        assert_eq!(f.driver.state(), ClientState::Playing);
        Ok(f)
    }
    fn window(&mut self) -> Test<ArchiveAdmission> {
        let data = nals();
        let sps = data.iter().find(|n| n[0] & 31 == 7).ok_or("SPS missing")?;
        let idr = data.iter().find(|n| n[0] & 31 == 5).ok_or("IDR missing")?;
        self.receive(&wire(1, false, sps)?, 10)?;
        let outputs = self.receive(&wire(2, true, idr)?, 11)?;
        assert!(outputs.iter().any(|s| matches!(s, LiveRecordingStep::Capture { event, .. } if matches!(event.as_ref(), CapturePoll::TimingRequired(request) if request.idr))));
        let _ = self.driver.supply_timing(RecordingTiming { decode_time: 700, duration: 3_600, composition_offset: 0 }, 12, &self.authority)?;
        assert!(self.driver.seal(13, &self.authority)?);
        match self.archive_poll(13)? {
            CheckpointedLiveArchiveStep::Live(LiveArchiveStep::WindowAccepted(admission)) => Ok(admission),
            _ => Err("native window was not accepted".into()),
        }
    }
    fn pin(&mut self, now: u64) -> Test<ArchiveCheckpoint> {
        match self.archive_poll(now)? {
            CheckpointedLiveArchiveStep::Checkpoint(CheckpointedArchiveProgress::PinRequired(pin)) => Ok(pin),
            _ => Err("recovery pin not required before publication".into()),
        }
    }
    fn protect(&mut self, pin: &ArchiveCheckpoint, now: u64) -> Test {
        // The test harness owns this independent pin; no external production journal is implied.
        self.driver.acknowledge_checkpoint(pin, now, &self.authority, &NeverCancel)?;
        match self.archive_poll(now)? {
            CheckpointedLiveArchiveStep::Checkpoint(CheckpointedArchiveProgress::WorkDurable { checkpoint, receipt }) => {
                assert_eq!(checkpoint, *pin);
                assert_eq!(receipt.root, pin.root());
                Ok(())
            }
            _ => Err("source work graph did not become durable first".into()),
        }
    }
    fn finish(&mut self, now: u64) -> Test<Vec<ArchiveCheckpoint>> {
        let mut pins = Vec::new();
        for _ in 0..256 {
            match self.archive_poll(now)? {
                CheckpointedLiveArchiveStep::Checkpoint(CheckpointedArchiveProgress::PinRequired(pin)) => {
                    self.protect(&pin, now)?;
                    pins.push(pin);
                }
                CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Finished { archive, cause }) => {
                    assert_eq!(cause, LiveArchiveCompletion::OwnerStopped);
                    assert!(matches!(archive, ArchiveWriteProgress::Finished { windows: 1, pages: 1, .. }));
                    return Ok(pins);
                }
                CheckpointedLiveArchiveStep::Stopped { .. } | CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Ended) => return Err("terminal output lost or fault became EOF".into()),
                _ => {}
            }
        }
        Err("bounded final drain exhausted".into())
    }
}

#[test]
fn automatic_native_capture_retains_source_before_window_and_catalog_then_cold_replays() -> Test {
    let mut identities = Vec::new();
    for chunk in [1, 7, 4096] {
        let path = fresh()?;
        let (namespace, root, objects, pin, page_pin) = {
            let mut p = LocalRootPublisher::open(&path, limits())?;
            let mut f = Fixture::playing(&mut p, chunk)?;
            let admission = f.window()?;
            let objects = f.driver.pending().ok_or("source missing")?.children().map(|(_, digest, _)| digest);
            let pin = f.pin(14)?;
            assert!(!f.driver.needs_credentials());
            assert_eq!(f.driver.next_wake_ns(), Some(13 + PAUSE));
            let totals = f.driver.totals().ok_or("totals missing")?;
            f.peer.write_all(b"UNREAD_SOURCE_MUST_NOT_PASS_PIN_BARRIER")?;
            for _ in 0..4 {
                assert!(matches!(f.archive_poll(14)?, CheckpointedLiveArchiveStep::Checkpoint(CheckpointedArchiveProgress::PinRequired(p)) if p == pin));
            }
            assert_eq!(f.driver.totals(), Some(totals));
            assert!(f.driver.snapshot().ok_or("snapshot missing")?.windows().is_empty());
            f.protect(&pin, 14)?;
            assert_eq!(f.driver.last_durable_checkpoint(), Some(&pin));
            assert_eq!(f.driver.totals(), Some(totals));
            assert!(matches!(f.archive_poll(14)?, CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Archive(ArchiveWriteProgress::WindowDurable { ordinal: 0, .. }))));
            assert!(f.driver.finish_capture(15, &f.authority)?.is_some());
            assert!(!f.driver.needs_credentials());
            let mut pages = f.finish(15)?;
            assert_eq!(pages.len(), 1);
            assert_eq!(f.driver.snapshot().ok_or("snapshot")?.indexed_windows(), 1);
            assert_eq!(f.driver.next_wake_ns(), None);
            assert!(matches!(f.archive_poll(16)?, CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Ended)));
            (f.namespace.clone(), admission.root, objects, pin, pages.pop().ok_or("page pin")?)
        };
        let p = LocalRootPublisher::open(&path, limits())?;
        let recording = load_recording(&p, &namespace.window_slot(0)?, root, &namespace.scope().recording, &NeverCancel)?;
        assert_eq!(recording.children().map(|(_, digest, _)| digest), objects);
        let work = load_archive_work(&p, page_pin.slot(), page_pin.root(), ArchiveWorkLimits::default(), &NeverCancel)?;
        assert!(work.pending.is_none());
        assert!(work.prepared_page.is_some());
        assert_eq!(work.snapshot.windows().len(), 1);
        identities.push((root, objects, pin.root(), page_pin.root()));
    }
    assert!(identities.windows(2).all(|p| p[0] == p[1]));
    Ok(())
}

#[test]
fn automatic_digest_and_keepalive_preserve_control_acknowledgements() -> Test {
    let mut p = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::new(&mut p, 13)?;
    let (describe, _) = f.command(0)?;
    let challenge = format!("RTSP/1.0 401 Unauthorized\r\nCSeq: {}\r\nWWW-Authenticate: Digest realm=\"fixture-camera\", nonce=\"server-nonce\", algorithm=SHA-256, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n", describe.cseq);
    let outputs = f.receive(challenge.as_bytes(), 1)?;
    assert!(outputs.iter().any(|s| matches!(s, LiveRecordingStep::Network(LiveAvcStep::Protocol { event: DigestAvcPoll::AuthenticationRequired { .. }, transport: None }))));
    assert!(f.driver.needs_credentials());
    let (answer, wire) = f.command(2)?;
    assert_eq!(answer.command, ClientCommand::Describe);
    assert!(answer.cseq > describe.cseq);
    let wire = std::str::from_utf8(&wire)?;
    assert!(wire.contains("Authorization: Digest "));
    assert!(!wire.contains("fixture-password"));
    f.receive(&response(answer.cseq, "Content-Type: application/sdp\r\n", description()), 3)?;
    let (setup, _) = f.command(4)?;
    f.receive(&response(setup.cseq, "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n", ""), 5)?;
    let (play, _) = f.command(6)?;
    f.receive(&response(play.cseq, "Session: fixture\r\n", ""), 7)?;
    let due = f.driver.next_wake_ns().ok_or("keepalive wake missing")?;
    assert!(due > 7);
    assert!(matches!(f.archive_poll(due)?, CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Recording(s))
        if matches!(*s, LiveRecordingStep::Network(LiveAvcStep::Protocol { event: DigestAvcPoll::Client { event, .. }, .. })
            if matches!(*event, AvcClientPoll::Control(ClientProgress::KeepAliveDue)))));
    let (keepalive, wire) = f.command(due)?;
    assert_eq!(keepalive.command, ClientCommand::KeepAlive);
    assert!(std::str::from_utf8(&wire)?.starts_with("OPTIONS "));
    f.receive(&response(keepalive.cseq, "Session: fixture\r\n", ""), due + 1)?;
    assert_eq!(f.driver.state(), ClientState::Playing);
    let retired = f.driver.cancel().ok_or("retirement")?;
    assert!(retired.live.recording.is_some());
    assert!(f.driver.cancel().is_none());
    Ok(())
}

#[test]
fn automatic_revocation_before_setup_retires_without_an_extra_request() -> Test {
    let mut p = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::new(&mut p, 7)?;
    let (describe, _) = f.command(0)?;
    f.receive(&response(describe.cseq, "Content-Type: application/sdp\r\n", description()), 1)?;
    let sent = f.driver.totals().ok_or("totals")?.sent_bytes;
    assert!(f.driver.needs_credentials());
    f.authority.revoked.set(true);
    let error = f.driver.poll(readiness(), &credentials()?, [99; 16], 2, &f.authority, &NeverCancel).err().ok_or("revocation ignored")?;
    assert!(matches!(error.reason, LiveArchiveError::Authority(TcpDenial::Revoked)));
    let retired = error.retirement.ok_or("retirement")?;
    let connection = retired.live.recording.ok_or("recording")?.connection.ok_or("connection")?;
    assert_eq!(connection.transport.totals.sent_bytes, sent);
    assert!(!f.driver.needs_credentials());
    assert_eq!(f.driver.next_wake_ns(), None);
    assert!(matches!(f.archive_poll(3)?, CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Ended)));
    assert!(f.driver.cancel().is_none());
    Ok(())
}

#[test]
fn automatic_cancel_before_first_command_never_prepares_or_sends_it() -> Test {
    let mut p = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::new(&mut p, 4096)?;
    assert!(matches!(f.archive_poll(0)?, CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Archive(ArchiveWriteProgress::Ready { .. }))));
    assert!(f.driver.needs_credentials());
    let error = f.driver.poll(readiness(), &credentials()?, [1; 16], 0, &f.authority, &Cancel).err().ok_or("cancel ignored")?;
    assert!(matches!(error.reason, LiveArchiveError::Archive(ArchiveError::Cancelled)));
    let retired = error.retirement.ok_or("retirement")?;
    let connection = retired.live.recording.ok_or("recording")?.connection.ok_or("connection")?;
    assert_eq!(connection.transport.totals.sent_bytes, 0);
    assert!(connection.transport.request.is_none());
    assert!(f.driver.cancel().is_none());
    drop(f);
    assert_eq!(p.visible_roots().count(), 0);
    Ok(())
}

#[test]
fn automatic_interim_response_and_reversed_time_do_not_lose_or_repeat_commands() -> Test {
    let mut p = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::new(&mut p, 4096)?;
    let (describe, _) = f.command(0)?;
    f.receive(format!("RTSP/1.0 100 Continue\r\nCSeq: {}\r\nContent-Length: 0\r\n\r\n", describe.cseq).as_bytes(), 1)?;
    assert!(!f.driver.needs_credentials());
    let sent = f.driver.totals().ok_or("totals")?.sent_bytes;
    assert!(matches!(f.poll(SocketReadiness::default(), 2)?, AutomaticLiveArchiveStep::Archive(_)));
    assert_eq!(f.driver.totals().ok_or("totals")?.sent_bytes, sent);
    f.receive(&response(describe.cseq, "Content-Type: application/sdp\r\n", description()), 10)?;
    let error = f.driver.poll(readiness(), &credentials()?, [1; 16], 9, &f.authority, &NeverCancel).err().ok_or("reversed clock ignored")?;
    assert!(matches!(error.reason, LiveArchiveError::ClockReversed));
    assert!(error.retirement.is_none());
    assert!(f.driver.needs_credentials());
    assert_eq!(f.driver.next_wake_ns(), Some(10));
    assert_eq!(f.command(11)?.0.command, ClientCommand::Setup);
    let _retired = f.driver.cancel().ok_or("retirement")?;
    Ok(())
}

#[test]
fn automatic_recovered_tail_is_protected_and_indexed_before_describe() -> Test {
    let path = fresh()?;
    {
        let mut p = LocalRootPublisher::open(&path, limits())?;
        let mut f = Fixture::playing(&mut p, 7)?;
        f.window()?;
        let pin = f.pin(14)?;
        f.protect(&pin, 14)?;
        assert!(matches!(f.archive_poll(14)?, CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Archive(ArchiveWriteProgress::WindowDurable { .. }))));
        let retired = f.driver.cancel().ok_or("retirement")?;
        assert_eq!(retired.live.archive.ok_or("archive")?.snapshot.unindexed_windows().len(), 1);
    }
    let mut p = LocalRootPublisher::open(&path, limits())?;
    let mut f = Fixture::new(&mut p, 7)?;
    let mut protected = false;
    let mut ready = false;
    for _ in 0..256 {
        assert!(!f.driver.needs_credentials());
        match f.archive_poll(0)? {
            CheckpointedLiveArchiveStep::Checkpoint(CheckpointedArchiveProgress::PinRequired(pin)) => {
                assert!(matches!(f.archive_poll(0)?, CheckpointedLiveArchiveStep::Checkpoint(CheckpointedArchiveProgress::PinRequired(p)) if p == pin));
                f.protect(&pin, 0)?;
                protected = true;
            }
            CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Archive(ArchiveWriteProgress::Ready { .. })) => { ready = true; break; }
            _ => {}
        }
        let totals = f.driver.totals().ok_or("totals")?;
        assert_eq!(totals.sent_bytes, 0);
        assert_eq!(totals.read_calls, 0);
    }
    assert!(protected && ready);
    assert_eq!(f.driver.snapshot().ok_or("snapshot")?.indexed_windows(), 1);
    assert!(f.driver.needs_credentials());
    assert_eq!(f.command(0)?.0.command, ClientCommand::Describe);
    let _retired = f.driver.cancel().ok_or("retirement")?;
    Ok(())
}

#[test]
fn automatic_uncertain_checkpoint_publication_retires_originals_and_never_resumes_capture() -> Test {
    let path = fresh()?;
    let namespace = {
        let mut p = LocalRootPublisher::open(&path, limits())?;
        p.inject_crash_at(PublishCutPoint::AfterRootRename);
        let mut f = Fixture::playing(&mut p, 7)?;
        let admission = f.window()?;
        let pin = f.pin(14)?;
        f.driver.acknowledge_checkpoint(&pin, 14, &f.authority, &NeverCancel)?;
        let error = f.driver.poll(readiness(), &credentials()?, [3; 16], 14, &f.authority, &NeverCancel).err().ok_or("injected publication failure ignored")?;
        let retired = error.retirement.ok_or("retirement")?;
        assert_eq!(retired.pending_checkpoint, Some(pin));
        assert!(retired.last_durable_checkpoint.is_none());
        assert!(retired.live.recording.is_some());
        let archive = retired.live.archive.ok_or("archive")?;
        assert_eq!(archive.pending.ok_or("source lost")?.manifest().root(), admission.root);
        assert!(archive.snapshot.windows().is_empty());
        assert!(!f.driver.needs_credentials());
        assert!(matches!(f.archive_poll(15)?, CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Ended)));
        f.namespace.clone()
    };
    let p = LocalRootPublisher::open(&path, limits())?;
    assert!(p.root(&namespace.window_slot(0)?).is_none());
    assert!(p.visible_roots().count() > 0);
    Ok(())
}
