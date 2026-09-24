#![forbid(unsafe_code)]
//! Native TCP + real AVC syntax + filesystem custody before recording-window publication.
use super::*;
use crate::rtsp::datagram_archive::live::*;
use crate::rtsp::authentication::{DigestCredentials, DigestPolicy};
use crate::rtsp::avc_client::AvcClientPoll;
use crate::rtsp::avc_client::authenticated::DigestAvcPoll;
use crate::rtsp::client::{ClientCommand, ClientConfig};
use crate::rtsp::live_avc::{LiveAvcConfig, LiveAvcStep, SocketReadiness};
use crate::rtsp::live_avc::recording::{LiveRecordingConfig, LiveRecordingStep};
use crate::rtsp::recording::RecordingScope;
use crate::rtsp::recording::local::{RecordingProgress, RecordingPublication, load_recording};
use crate::rtsp::recording_capture::CapturePoll;
use crate::rtsp::recording_collector::{CollectorLimits, RecordingTiming};
use crate::rtsp::tcp::{TcpAuthority, TcpDenial, TcpLimits, TcpOperation, TcpWriteStep};
use fss_core::{SensorId, StreamId};
use fss_packet::avc::AvcReceiveLimits;
use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::time::Duration;

const LEASE: u64 = 100_000_000_000;
struct Authority { binding: TcpBinding, revoked: Cell<bool>, checks: Cell<u64> }
impl TcpAuthority for Authority {
    fn checkpoint(&self, binding: &TcpBinding, _: TcpOperation, now: u64, until: u64) -> std::result::Result<(), TcpDenial> {
        self.checks.set(self.checks.get() + 1);
        if binding != &self.binding { return Err(TcpDenial::Unauthorized); }
        if self.revoked.get() { return Err(TcpDenial::Revoked); }
        if until != LEASE || now >= until { return Err(TcpDenial::Deadline); }
        Ok(())
    }
}
fn config(peer: std::net::SocketAddr, chunk: usize) -> Test<(LiveAvcConfig, LiveRecordingConfig, DatagramScope, Authority)> {
    let mut selected = scope()?;
    selected.binding = TcpBinding::new(selected.binding.key(), peer, "camera.local", TcpSecurityPolicy::OwnerApprovedPlaintext)?;
    let authority = Authority { binding: selected.binding.clone(), revoked: Cell::new(false), checks: Cell::new(0) };
    let live = LiveAvcConfig { protocol: ClientConfig {
        presentation_uri: "rtsp://camera.local/live/".into(), control_root_uri: "rtsp://camera.local/live".into(),
        media_index: 0, channels: selected.channels, response_timeout_ns: 10_000_000_000,
        default_session_timeout_seconds: 60,
    }, binding: selected.binding.clone(), transport: TcpLimits { chunk_bytes: chunk, ..TcpLimits::default() },
        media: AvcReceiveLimits::default(), realm: "fixture-camera".into(), digest_policy: DigestPolicy::default(),
        deadline_ns: LEASE, max_steps: 100_000 };
    let recording = LiveRecordingConfig { scope: RecordingScope {
        sensor: SensorId::parse("sensor:retained-fixture")?, stream: StreamId::parse("stream:retained-fixture")?,
        generation: selected.binding.key().generation, anchor: ContentDigest::sha256(b"owner anchor"),
        receive_clock: selected.receive_clock,
    }, payload_type: 96, time_scale: 90_000, limits: CollectorLimits::default() };
    Ok((live, recording, selected, authority))
}
fn credentials() -> Test<DigestCredentials<'static>> { Ok(DigestCredentials::new("fixture-user", "fixture-password")?) }
fn response(cseq: u32, headers: &str, body: &str) -> Vec<u8> {
    format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}", body.len()).into_bytes()
}
fn description() -> &'static str {
    "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\na=control:trackID=0\r\n"
}
fn nals() -> Vec<&'static [u8]> {
    let bytes: &'static [u8] = include_bytes!("../../../../../fss-packet/tests/fixtures/avc/baseline.264");
    let mut out = Vec::new(); let mut start = None; let mut at = 0;
    while at + 3 <= bytes.len() {
        let prefix = if bytes.get(at..at + 4) == Some(&[0, 0, 0, 1]) { 4 }
            else if bytes[at..at + 3] == [0, 0, 1] { 3 } else { 0 };
        if prefix == 0 { at += 1; continue; }
        if let Some(begin) = start {
            let mut end = at; while end > begin && bytes[end - 1] == 0 { end -= 1; }
            if begin < end { out.push(&bytes[begin..end]); }
        }
        start = Some(at + prefix); at += prefix;
    }
    if let Some(begin) = start && begin < bytes.len() { out.push(&bytes[begin..]); }
    out
}
fn packet(sequence: u16, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, 96 | if marker { 128 } else { 0 }];
    bytes.extend_from_slice(&sequence.to_be_bytes()); bytes.extend_from_slice(&9000_u32.to_be_bytes());
    bytes.extend_from_slice(&7_u32.to_be_bytes()); bytes.extend_from_slice(payload); bytes
}
fn wire(channel: u8, payload: &[u8]) -> Test<Vec<u8>> {
    let mut out = vec![b'$', channel]; out.extend_from_slice(&u16::try_from(payload.len())?.to_be_bytes());
    out.extend_from_slice(payload); Ok(out)
}
fn media_source(step: &LiveRecordingStep) -> Option<&InterleavedSource> {
    let event = match step { LiveRecordingStep::Network(e) => e,
        LiveRecordingStep::Stopped { trigger, .. } => trigger.as_ref(), _ => return None };
    if let LiveAvcStep::Protocol { event: DigestAvcPoll::Client { event, .. }, .. } = event {
        match event.as_ref() { AvcClientPoll::Rtp { source, .. } | AvcClientPoll::Rtcp { source, .. }
            | AvcClientPoll::Fault { source: Some(source), .. } => Some(source), _ => None }
    } else { None }
}
struct Fixture { driver: RetainedAvcRecording, peer: TcpStream, authority: Authority, recording: RecordingScope }
impl Fixture {
    fn new(p: &mut LocalRootPublisher, chunk: usize, bounds: DatagramArchiveLimits) -> Test<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let (live, recording, scope, authority) = config(listener.local_addr()?, chunk)?;
        let saved = recording.scope.clone();
        let driver = RetainedAvcRecording::connect(live, recording, scope, bounds, p, 0, &authority, &NeverCancel, &mut work())?;
        let (peer, _) = listener.accept()?;
        peer.set_read_timeout(Some(Duration::from_secs(2)))?; peer.set_write_timeout(Some(Duration::from_secs(2)))?;
        peer.set_nodelay(true)?;
        Ok(Self { driver, peer, authority, recording: saved })
    }
    fn poll(&mut self, p: &mut LocalRootPublisher, now: u64) -> std::result::Result<RetainedRecordingStep, RetainedRecordingFailure> {
        self.driver.poll(SocketReadiness { readable: true, writable: true }, now, &self.authority, p, &NeverCancel, &mut work())
    }
    fn command(&mut self, p: &mut LocalRootPublisher, command: ClientCommand, now: u64) -> Test<u32> {
        let queued = self.driver.request(command, &credentials()?, [40 + now as u8; 16], now, &self.authority, &NeverCancel)?;
        for _ in 0..32_768 {
            let step = self.driver.poll(SocketReadiness { readable: false, writable: true }, now,
                &self.authority, p, &NeverCancel, &mut work())?;
            assert!(step.datagram.is_none());
            match step.event {
                LiveRecordingStep::Network(LiveAvcStep::Write(TcpWriteStep::Sent { cseq, bytes })) => {
                    assert_eq!((cseq, bytes), (queued.cseq, queued.bytes));
                    self.peer.read_exact(&mut vec![0; bytes])?; return Ok(cseq);
                }
                LiveRecordingStep::Network(LiveAvcStep::Write(TcpWriteStep::Advanced { .. }) | LiveAvcStep::Pending(_)) => {},
                _ => return Err("unexpected command output".into()),
            }
        }
        Err("bounded command did not complete".into())
    }
    fn receive(&mut self, p: &mut LocalRootPublisher, bytes: &[u8], now: u64) -> Test<Vec<RetainedRecordingStep>> {
        self.peer.write_all(bytes)?;
        let mut raw = 0; let mut outputs = Vec::new();
        for _ in 0..32_768 {
            let before = self.driver.totals(); let step = self.poll(p, now)?;
            if let Some(publication) = &step.datagram {
                assert_eq!(before, self.driver.totals(), "source publication must not read ahead");
                assert_eq!(p.root(&publication.local.slot).ok_or("root missing")?.state, LocalPublicationState::Durable);
                assert_eq!(ContentDigest::sha256(media_source(&step.event).ok_or("source missing")?.payload()), publication.record.payload_digest);
            }
            match &step.event {
                LiveRecordingStep::Network(LiveAvcStep::Wire(chunk)) => { raw += chunk.expose().len(); },
                LiveRecordingStep::Network(LiveAvcStep::Pending(wait)) => {
                    if raw == bytes.len() && wait.wake_at_ns.is_none_or(|at| at > now) { return Ok(outputs); }
                    std::thread::yield_now();
                }
                LiveRecordingStep::Capture { event, .. } if matches!(**event, CapturePoll::TimingRequired(_)) => {
                    outputs.push(step); return Ok(outputs);
                }
                LiveRecordingStep::Stopped { .. } => { outputs.push(step); return Ok(outputs); }
                _ => outputs.push(step),
            }
        }
        Err("bounded receive did not drain".into())
    }
    fn playing(p: &mut LocalRootPublisher, chunk: usize, bounds: DatagramArchiveLimits) -> Test<Self> {
        let mut f = Self::new(p, chunk, bounds)?;
        let seq = f.command(p, ClientCommand::Describe, 0)?;
        f.receive(p, &response(seq, "Content-Type: application/sdp\r\n", description()), 1)?;
        let seq = f.command(p, ClientCommand::Setup, 2)?;
        f.receive(p, &response(seq, "Session: private-fixture-token;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n", ""), 3)?;
        let seq = f.command(p, ClientCommand::Play, 4)?;
        f.receive(p, &response(seq, "Session: private-fixture-token\r\n", ""), 5)?;
        assert_eq!(f.driver.pin().datagrams, 0); assert_eq!(p.visible_roots().count(), 0);
        Ok(f)
    }
    fn probation(&mut self, p: &mut LocalRootPublisher) -> Test<Vec<u8>> {
        let data = nals(); let sps = data.iter().find(|n| n[0] & 31 == 7).ok_or("SPS")?;
        let bytes = packet(1, false, sps); self.receive(p, &wire(0, &bytes)?, 10)?; Ok(bytes)
    }
    fn idr(&mut self, p: &mut LocalRootPublisher) -> Test<Vec<u8>> {
        self.probation(p)?;
        let data = nals(); let idr = data.iter().find(|n| n[0] & 31 == 5).ok_or("IDR")?;
        let bytes = packet(2, true, idr); let outputs = self.receive(p, &wire(0, &bytes)?, 11)?;
        assert!(outputs.iter().any(|s| matches!(s.event.capture_event(), Some(CapturePoll::TimingRequired(_)))));
        assert_eq!(self.driver.pin().datagrams, 2); Ok(bytes)
    }
}

#[test]
fn native_datagrams_precede_timing_and_same_owner_recording_publication_for_all_chunk_sizes() -> Test {
    for chunk in [1, 7, 4096] {
        let dir = Directory::new()?; let mut p = dir.open()?;
        let mut f = Fixture::playing(&mut p, chunk, limits())?;
        let idr = f.idr(&mut p)?; let source_pin = f.driver.pin(); let scope = f.driver.scope().clone();
        let bad = f.driver.supply_timing(RecordingTiming { decode_time: 700, duration: 0, composition_offset: 0 },
            12, &f.authority, &NeverCancel).err().ok_or("bad timing accepted")?;
        assert!(bad.retirement.is_none()); assert_eq!(f.driver.pin(), source_pin);
        let _ = f.driver.supply_timing(RecordingTiming { decode_time: 700, duration: 3600, composition_offset: 0 },
            12, &f.authority, &NeverCancel)?;
        assert!(f.driver.seal(13, &f.authority, &NeverCancel)?);
        let RetainedRecordingStep { event: LiveRecordingStep::Capture { event, .. }, datagram: None } =
            f.poll(&mut p, 13)? else { return Err("sealed window missing".into()); };
        let CapturePoll::Window(window) = *event else { return Err("sealed window missing".into()); };
        assert_eq!(window.summary().decode_interval, 700..4300);
        let root = window.manifest().root(); let slot = SlotName::parse("retained-window")?;
        let mut job = RecordingPublication::new(&window, &mut p, slot.clone(), window.byte_len(), LEASE)?;
        let mut done = false;
        for _ in 0..5 { if matches!(job.step(14, &NeverCancel)?, RecordingProgress::Published(_)) { done = true; break; } }
        assert!(done); drop(job); drop(window);
        let recording_scope = f.recording.clone(); let _ = f.driver.cancel(); drop(f); drop(p);
        let p = dir.open()?;
        let archive = DatagramArchive::recover(&p, scope, limits(), Some(source_pin), &NeverCancel, &mut work())?;
        assert_eq!(archive.read(2, &p, &NeverCancel, &mut work())?.payload(), idr);
        assert_eq!(load_recording(&p, &slot, root, &recording_scope, &NeverCancel)?.summary().decode_interval, 700..4300);
    }
    Ok(())
}
#[test]
fn unsealed_fragment_survives_process_state_loss_without_becoming_a_frame_or_eof() -> Test {
    let dir = Directory::new()?; let mut p = dir.open()?; let mut f = Fixture::playing(&mut p, 7, limits())?;
    f.probation(&mut p)?;
    let bytes = packet(2, false, &[0x7c, 0x85, 0x88, 0x80]);
    let output = f.receive(&mut p, &wire(0, &bytes)?, 11)?;
    assert!(!output.iter().any(|s| matches!(s.event.capture_event(), Some(CapturePoll::Window(_) | CapturePoll::TimingRequired(_)))));
    let scope = f.driver.scope().clone(); let pin = f.driver.pin();
    assert_eq!(pin.datagrams, 2); let retired = f.driver.cancel().ok_or("retirement")?;
    assert!(retired.capture.is_some()); drop(retired); drop(f); drop(p);
    let p = dir.open()?; let a = DatagramArchive::recover(&p, scope, limits(), Some(pin), &NeverCancel, &mut work())?;
    let mut replay = DatagramReplay::new(&a, &p, pin.payload_bytes, 20, 100)?;
    assert!(matches!(replay.step(21, &NeverCancel, &mut work())?, DatagramReplayStep::Datagram(_)));
    let DatagramReplayStep::Datagram(source) = replay.step(21, &NeverCancel, &mut work())? else { return Err("fragment missing".into()); };
    assert_eq!(source.payload(), bytes);
    assert!(matches!(replay.step(21, &NeverCancel, &mut work())?, DatagramReplayStep::PrefixExhausted(_)));
    Ok(())
}
#[test]
fn repeated_rtp_and_invalid_rtcp_are_retained_without_promoting_their_admission() -> Test {
    let dir = Directory::new()?; let mut p = dir.open()?; let mut f = Fixture::playing(&mut p, 4096, limits())?;
    f.probation(&mut p)?;
    let data = nals(); let sps = data.iter().find(|n| n[0] & 31 == 7).ok_or("SPS")?;
    let duplicate = packet(2, false, sps);
    f.receive(&mut p, &wire(0, &duplicate)?, 11)?;
    f.receive(&mut p, &wire(0, &duplicate)?, 11)?;
    let invalid = f.receive(&mut p, &wire(1, b"bad")?, 12)?;
    assert!(invalid.iter().any(|s| matches!(&s.event,
        LiveRecordingStep::Network(LiveAvcStep::Protocol { event: DigestAvcPoll::Client { event, .. }, .. })
        if matches!(event.as_ref(), AvcClientPoll::Rtcp { validation: Err(_), .. }))));
    assert_eq!(f.driver.pin().datagrams, 4);
    let a = DatagramArchive::recover(&p, f.driver.scope().clone(), limits(), Some(f.driver.pin()), &NeverCancel, &mut work())?;
    assert_eq!(a.records()[1].payload_digest, a.records()[2].payload_digest);
    assert_ne!(a.records()[1].pin.head, a.records()[2].pin.head);
    assert_eq!(a.read(4, &p, &NeverCancel, &mut work())?.payload(), b"bad");
    let _ = f.driver.cancel(); Ok(())
}
#[test]
fn source_capacity_failure_returns_the_exact_withheld_datagram_and_stops_capture() -> Test {
    let dir = Directory::new()?; let mut p = dir.open()?;
    let mut f = Fixture::playing(&mut p, 4096, DatagramArchiveLimits { max_datagrams: 1, ..limits() })?;
    f.probation(&mut p)?;
    let data = nals(); let idr = data.iter().find(|n| n[0] & 31 == 5).ok_or("IDR")?;
    let bytes = packet(2, true, idr); f.peer.write_all(&wire(0, &bytes)?)?;
    for _ in 0..32768 {
        match f.poll(&mut p, 11) {
            Ok(step) => assert!(!matches!(step.event.capture_event(), Some(CapturePoll::TimingRequired(_) | CapturePoll::Window(_)))),
            Err(failure) => {
                assert!(matches!(failure.reason, RetainedRecordingError::Custody(DatagramArchiveError::Limit)));
                let r = failure.retirement.ok_or("retirement lost")?;
                assert_eq!(media_source(r.trigger.as_deref().ok_or("source trigger lost")?).ok_or("source lost")?.payload(), bytes);
                assert_eq!(r.prefix.datagrams, 1); assert!(r.capture.is_some());
                assert!(matches!(f.poll(&mut p, 12)?.event, LiveRecordingStep::Ended));
                return Ok(());
            }
        }
    }
    Err("source limit did not stop capture".into())
}
#[test]
fn lost_datagram_root_ack_preserves_candidate_and_recovers_without_recapturing() -> Test {
    let dir = Directory::new()?; let mut p = dir.open()?; let mut f = Fixture::playing(&mut p, 4096, limits())?;
    let scope = f.driver.scope().clone();
    p.inject_crash_at(PublishCutPoint::AfterRootRename);
    let data = nals(); let sps = data.iter().find(|n| n[0] & 31 == 7).ok_or("SPS")?;
    let bytes = packet(1, false, sps); f.peer.write_all(&wire(0, &bytes)?)?;
    let mut pin = None;
    for _ in 0..32768 {
        if let Err(failure) = f.poll(&mut p, 10) {
            let r = failure.retirement.ok_or("retirement")?;
            assert_eq!(r.prefix.datagrams, 0); assert!(r.publication.is_none());
            assert_eq!(media_source(r.trigger.as_deref().ok_or("trigger")?).ok_or("source")?.payload(), bytes);
            pin = r.candidate; break;
        }
    }
    let pin = pin.ok_or("candidate missing")?; assert!(p.is_poisoned()); drop(f); drop(p);
    let p = dir.open()?; let a = DatagramArchive::recover(&p, scope, limits(), Some(pin), &NeverCancel, &mut work())?;
    assert_eq!(a.pin(), pin); assert_eq!(a.read(1, &p, &NeverCancel, &mut work())?.payload(), bytes); Ok(())
}
#[test]
fn revoked_or_cancelled_owner_cannot_read_more_or_publish_another_source() -> Test {
    for revoked in [false, true] {
        let dir = Directory::new()?; let mut p = dir.open()?; let mut f = Fixture::playing(&mut p, 7, limits())?;
        f.probation(&mut p)?; let pin = f.driver.pin();
        f.authority.revoked.set(revoked);
        let cancellation: &dyn PublishCancellation = if revoked { &NeverCancel } else { &Cancel };
        let failure = f.driver.poll(SocketReadiness { readable: true, writable: true }, 11, &f.authority,
            &mut p, cancellation, &mut work()).err().ok_or("denied poll accepted")?;
        assert_eq!(failure.retirement.ok_or("retirement")?.prefix, pin);
        assert!(matches!(f.poll(&mut p, 12)?.event, LiveRecordingStep::Ended));
        assert_eq!(p.visible_roots().count(), 1);
    }
    Ok(())
}
#[test]
fn scope_mismatch_and_occupied_source_refuse_before_a_new_network_attempt() -> Test {
    let dir = Directory::new()?; let mut p = dir.open()?;
    let mut f = Fixture::playing(&mut p, 4096, limits())?; f.probation(&mut p)?;
    let peer = f.driver.scope().binding.peer(); let _ = f.driver.cancel(); drop(f);
    let (live, recording, scope, authority) = config(peer, 4096)?;
    let failure = RetainedAvcRecording::connect(live, recording, scope, limits(), &p, 20, &authority,
        &NeverCancel, &mut work()).err().ok_or("occupied connection reused")?;
    assert!(matches!(failure.reason, RetainedRecordingError::ExistingSource));
    assert!(!failure.connection_attempted); assert_eq!(authority.checks.get(), 0);
    let (live, recording, mut scope, authority) = config(peer, 4096)?; scope.receive_clock = ContentDigest::sha256(b"wrong clock");
    let failure = RetainedAvcRecording::connect(live, recording, scope, limits(), &p, 20, &authority,
        &NeverCancel, &mut work()).err().ok_or("wrong scope connected")?;
    assert!(!failure.connection_attempted); assert_eq!(authority.checks.get(), 0); Ok(())
}
#[test]
fn switching_publishers_stops_input_and_does_not_start_a_second_source_history() -> Test {
    let dir = Directory::new()?; let other = Directory::new()?;
    let mut p = dir.open()?; let mut q = other.open()?; let mut f = Fixture::playing(&mut p, 4096, limits())?;
    f.probation(&mut p)?; let pin = f.driver.pin();
    let failure = f.poll(&mut q, 11).err().ok_or("other owner accepted")?;
    assert!(matches!(failure.reason, RetainedRecordingError::Configuration));
    assert_eq!(failure.retirement.ok_or("retirement")?.prefix, pin);
    assert_eq!(q.visible_roots().count(), 0); Ok(())
}
#[test]
fn replay_clock_regression_is_safe_but_deadline_stops_the_attempt() -> Test {
    let dir = Directory::new()?; let mut p = dir.open()?; let mut a = DatagramArchive::new(scope()?, limits())?;
    add(&mut a, &mut p, 0, 0, b"source")?;
    let mut replay = DatagramReplay::new(&a, &p, 6, 10, 20)?;
    assert!(matches!(replay.step(9, &NeverCancel, &mut work()), Err(DatagramArchiveError::ClockReversed)));
    assert!(matches!(replay.step(10, &NeverCancel, &mut work())?, DatagramReplayStep::Datagram(_)));
    assert!(matches!(replay.step(20, &NeverCancel, &mut work()), Err(DatagramArchiveError::Deadline)));
    assert!(matches!(replay.step(20, &NeverCancel, &mut work()), Err(DatagramArchiveError::Stopped))); Ok(())
}

#[test]
fn post_commit_cancellation_retains_the_actual_receipt_with_the_withheld_source() -> Test {
    // The existing publisher never consults cancellation after root rename. This probe
    // becomes cancelled only after the first root exists, so it exercises the outer
    // post-I/O check without falsifying an acknowledged root or changing the publisher.
    struct CancelOnRoot(PathBuf);
    impl PublishCancellation for CancelOnRoot {
        fn cancel_requested(&self, _: PublishCutPoint) -> bool {
            std::fs::read_dir(&self.0).map_or(true, |entries| entries.take(129).any(|entry|
                entry.map_or(true, |entry| entry.path().extension().is_some_and(|e| e == "root"))))
        }
    }
    let dir = Directory::new()?; let mut p = dir.open()?;
    let mut f = Fixture::playing(&mut p, 4096, limits())?;
    let cancel = CancelOnRoot(p.root_dir().join("roots"));
    let data = nals(); let sps = data.iter().find(|n| n[0] & 31 == 7).ok_or("SPS")?;
    let bytes = packet(1, false, sps); f.peer.write_all(&wire(0, &bytes)?)?;
    for _ in 0..32768 {
        if let Err(failure) = f.driver.poll(SocketReadiness { readable: true, writable: true }, 10,
            &f.authority, &mut p, &cancel, &mut work()) {
            assert!(matches!(failure.reason, RetainedRecordingError::Custody(DatagramArchiveError::Cancelled)));
            let retired = failure.retirement.ok_or("retirement")?;
            let publication = retired.publication.as_ref().ok_or("durable receipt discarded")?;
            assert_eq!(publication.record.pin, retired.prefix);
            assert_eq!(retired.candidate, Some(retired.prefix));
            assert_eq!(publication.local.claims.local, LocalPublicationState::Durable);
            assert_eq!(media_source(retired.trigger.as_deref().ok_or("trigger")?).ok_or("source")?.payload(), bytes);
            assert!(retired.capture.is_some());
            assert_eq!(p.visible_roots().count(), 1);
            assert!(matches!(f.poll(&mut p, 11)?.event, LiveRecordingStep::Ended));
            return Ok(());
        }
    }
    Err("post-commit cancellation was not observed".into())
}

#[test]
fn terminal_bad_rtp_retains_its_original_source_without_changing_the_failure_to_eof() -> Test {
    let dir = Directory::new()?; let mut p = dir.open()?;
    let mut f = Fixture::playing(&mut p, 7, limits())?;
    let bytes = b"bad"; f.peer.write_all(&wire(0, bytes)?)?;
    for _ in 0..32768 {
        let step = f.poll(&mut p, 10)?;
        if let LiveRecordingStep::Stopped { .. } = &step.event {
            assert_eq!(media_source(&step.event).ok_or("terminal source discarded")?.payload(), bytes);
            let publication = step.datagram.as_ref().ok_or("failed RTP source not retained")?;
            assert_eq!(publication.record.payload_digest, ContentDigest::sha256(bytes));
            assert_eq!(publication.record.pin.datagrams, 1);
            assert_eq!(p.root(&publication.local.slot).ok_or("source root")?.state, LocalPublicationState::Durable);
            assert!(matches!(f.poll(&mut p, 11)?.event, LiveRecordingStep::Ended));
            return Ok(());
        }
        assert!(!matches!(step.event.capture_event(), Some(CapturePoll::Window(_) | CapturePoll::Ended { .. })));
    }
    Err("malformed RTP did not produce its terminal source receipt".into())
}
