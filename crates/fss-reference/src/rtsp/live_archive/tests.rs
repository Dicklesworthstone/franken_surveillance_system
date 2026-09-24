#![forbid(unsafe_code)]
//! Real loopback capture and actual root-last storage; no remote camera or background task.
use super::*;
use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use fss_core::{ContentDigest, SensorId, StreamId};
use fss_object::SpoolLimits;
use fss_packet::{StreamKey, avc::AvcReceiveLimits};
use fss_publication::{LocalPublicationLimits, NeverCancel};
use crate::rtsp::authentication::DigestPolicy;
use crate::rtsp::client::ClientConfig;
use crate::rtsp::live_avc::LiveAvcStep;
use crate::rtsp::recording::RecordingScope;
use crate::rtsp::recording::local::load_recording;
use crate::rtsp::recording_catalog::CatalogScope;
use crate::rtsp::recording_collector::CollectorLimits;
use crate::rtsp::tcp::{TcpLimits, TcpSecurityPolicy, TcpWriteStep};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const KEY: StreamKey = StreamKey { ingress: 71, generation: 1, ssrc: 7 };
const LEASE: u64 = 100_000_000_000;
static NEXT_PATH: AtomicU64 = AtomicU64::new(0);
fn fresh() -> Test<PathBuf> {
    for _ in 0..256 {
        let path = std::env::temp_dir().join(format!("fss-live-archive-{}-{}",
            std::process::id(), NEXT_PATH.fetch_add(1, Ordering::Relaxed)));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {},
            Err(e) => return Err(e.into()),
        }
    }
    Err("fixture directory allowance exhausted".into())
}
fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(64, 64, 64, 256,
        SpoolLimits::new(256, 16 * 1024 * 1024, 2 * 1024 * 1024, 256))
}
struct Authority { binding: TcpBinding, revoked: Cell<bool>, checks: Cell<u64> }
impl TcpAuthority for Authority {
    fn checkpoint(&self, binding: &TcpBinding, _: TcpOperation, now: u64, until: u64) -> Result<(), TcpDenial> {
        self.checks.set(self.checks.get() + 1);
        if binding != &self.binding { return Err(TcpDenial::Unauthorized); }
        if self.revoked.get() { return Err(TcpDenial::Revoked); }
        if until != LEASE || now >= until { return Err(TcpDenial::Deadline); }
        Ok(())
    }
}
fn config(peer: std::net::SocketAddr, chunk: usize, page_size: usize)
    -> Test<(LiveAvcConfig, LiveRecordingConfig, LiveArchiveConfig, Authority)> {
    let binding = TcpBinding::new(KEY, peer, "camera.local", TcpSecurityPolicy::OwnerApprovedPlaintext)?;
    let authority = Authority { binding: binding.clone(), revoked: Cell::new(false), checks: Cell::new(0) };
    let live = LiveAvcConfig { protocol: ClientConfig {
        presentation_uri: "rtsp://camera.local/live/".into(), control_root_uri: "rtsp://camera.local/live".into(),
        media_index: 0, channels: (0, 1), response_timeout_ns: 10_000_000_000,
        default_session_timeout_seconds: 60,
    }, binding, transport: TcpLimits { chunk_bytes: chunk, ..TcpLimits::default() },
        media: AvcReceiveLimits::default(), realm: "fixture-camera".into(), digest_policy: DigestPolicy::default(),
        deadline_ns: LEASE, max_steps: 100_000 };
    let recording = LiveRecordingConfig { scope: RecordingScope {
        sensor: SensorId::parse("sensor:archive-fixture")?, stream: StreamId::parse("stream:archive-fixture")?,
        generation: KEY.generation, anchor: ContentDigest::sha256(b"archive owner anchor"),
        receive_clock: ContentDigest::sha256(b"archive receive clock"),
    }, payload_type: 96, time_scale: 90_000, limits: CollectorLimits::default() };
    let archive = LiveArchiveConfig { namespace: ArchiveNamespace::new(CatalogScope {
        recording: recording.scope.clone(), decode_clock: ContentDigest::sha256(b"explicit decode clock"),
        time_scale: recording.time_scale,
    })?, limits: ArchiveLimits { max_windows: 8, max_pages: 8, max_scan_roots: 64, windows_per_page: page_size },
        max_window_bytes: MAX_RECORDING_BYTES, max_steps: 100_000,
        publication_deadline_ns: 2 * LEASE, max_storage_pause_ns: 1_000_000_000 };
    Ok((live, recording, archive, authority))
}
fn credentials() -> Test<DigestCredentials<'static>> { Ok(DigestCredentials::new("fixture-user", "fixture-password")?) }
fn response(cseq: u32, headers: &str, body: &str) -> Vec<u8> {
    format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}", body.len()).into_bytes()
}
fn description() -> &'static str {
    "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\na=control:trackID=0\r\n"
}
fn nals() -> Vec<&'static [u8]> {
    let bytes: &'static [u8] = include_bytes!("../../../../fss-packet/tests/fixtures/avc/baseline.264");
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
fn wire(sequence: u16, marker: bool, payload: &[u8]) -> Test<Vec<u8>> {
    let mut packet = vec![0x80, 96 | if marker { 128 } else { 0 }];
    packet.extend_from_slice(&sequence.to_be_bytes()); packet.extend_from_slice(&9_000_u32.to_be_bytes());
    packet.extend_from_slice(&KEY.ssrc.to_be_bytes()); packet.extend_from_slice(payload);
    let mut wire = vec![b'$', 0]; wire.extend_from_slice(&u16::try_from(packet.len())?.to_be_bytes());
    wire.extend_from_slice(&packet); Ok(wire)
}
fn timing() -> RecordingTiming { RecordingTiming { decode_time: 700, duration: 3_600, composition_offset: 0 } }
struct Fixture<'a> { driver: LiveAvcArchive<'a>, peer: TcpStream, authority: Authority, namespace: ArchiveNamespace }
impl<'a> Fixture<'a> {
    fn new(publisher: &'a mut LocalRootPublisher, chunk: usize, page_size: usize) -> Test<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let (live, recording, archive, authority) = config(listener.local_addr()?, chunk, page_size)?;
        let namespace = archive.namespace.clone();
        let driver = LiveAvcArchive::connect(live, recording, archive, publisher, 0, &authority, &NeverCancel)?;
        let (peer, _) = listener.accept()?;
        peer.set_read_timeout(Some(Duration::from_secs(2)))?; peer.set_write_timeout(Some(Duration::from_secs(2)))?;
        peer.set_nodelay(true)?;
        Ok(Self { driver, peer, authority, namespace })
    }
    fn storage(&mut self, now: u64) -> Test<Vec<ArchiveWriteProgress>> {
        let mut outputs = Vec::new();
        for _ in 0..128 {
            // Readiness cannot bypass a storage pause, even with peer bytes waiting.
            match self.driver.poll(SocketReadiness { readable: true, writable: true }, now, &self.authority, &NeverCancel)? {
                LiveArchiveStep::Archive(progress) => {
                    let done = matches!(&progress, ArchiveWriteProgress::Ready { .. });
                    outputs.push(progress); if done { return Ok(outputs); }
                }
                _ => return Err("storage driver advanced live input".into()),
            }
        }
        Err("storage did not reach readiness within its fixed bound".into())
    }
    fn command(&mut self, command: ClientCommand, now: u64) -> Test<u32> {
        let queued = self.driver.request(command, &credentials()?, [40 + now as u8; 16], now, &self.authority)?;
        for _ in 0..32_768 {
            if let LiveArchiveStep::Recording(step) = self.driver.poll(
                SocketReadiness { readable: false, writable: true }, now, &self.authority, &NeverCancel)? {
                match *step {
                    LiveRecordingStep::Network(LiveAvcStep::Write(TcpWriteStep::Sent { cseq, bytes })) => {
                        assert_eq!((cseq, bytes), (queued.cseq, queued.bytes));
                        self.peer.read_exact(&mut vec![0; bytes])?; return Ok(cseq);
                    }
                    LiveRecordingStep::Network(LiveAvcStep::Write(TcpWriteStep::Advanced { .. }) | LiveAvcStep::Pending(_)) => {},
                    _ => return Err("unexpected live output during command dispatch".into()),
                }
            } else { return Err("unexpected archive output during command dispatch".into()); }
        }
        Err("command work bound".into())
    }
    fn receive(&mut self, bytes: &[u8], now: u64) -> Test<Vec<LiveRecordingStep>> {
        self.peer.write_all(bytes)?;
        let mut originals = Vec::new(); let mut outputs = Vec::new();
        for _ in 0..32_768 {
            let LiveArchiveStep::Recording(step) = self.driver.poll(
                SocketReadiness { readable: true, writable: false }, now, &self.authority, &NeverCancel)?
                else { return Err("unexpected archive result during receive".into()); };
            match *step {
                LiveRecordingStep::Network(LiveAvcStep::Wire(chunk)) => originals.extend_from_slice(chunk.expose()),
                LiveRecordingStep::Network(LiveAvcStep::Pending(wait)) => {
                    if originals.len() == bytes.len() && wait.wake_at_ns.is_none_or(|at| at > now) {
                        assert_eq!(originals, bytes); return Ok(outputs);
                    }
                    std::thread::yield_now();
                }
                other => {
                    let stop = matches!(other.capture_event(), Some(CapturePoll::TimingRequired(_)));
                    outputs.push(other);
                    if stop { assert_eq!(originals, bytes); return Ok(outputs); }
                }
            }
        }
        Err("receive work bound".into())
    }
    fn playing(publisher: &'a mut LocalRootPublisher, chunk: usize, page_size: usize) -> Test<Self> {
        let mut f = Self::new(publisher, chunk, page_size)?; f.storage(0)?;
        let seq = f.command(ClientCommand::Describe, 0)?;
        f.receive(&response(seq, "Content-Type: application/sdp\r\n", description()), 1)?;
        let seq = f.command(ClientCommand::Setup, 2)?;
        f.receive(&response(seq, "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n", ""), 3)?;
        let seq = f.command(ClientCommand::Play, 4)?;
        f.receive(&response(seq, "Session: fixture\r\n", ""), 5)?;
        assert_eq!(f.driver.state(), ClientState::Playing); Ok(f)
    }
    fn picture(&mut self) -> Test {
        let data = nals(); let sps = data.iter().find(|n| n[0] & 31 == 7).ok_or("missing SPS")?;
        let idr = data.iter().find(|n| n[0] & 31 == 5).ok_or("missing IDR")?;
        self.receive(&wire(1, false, sps)?, 10)?;
        let outputs = self.receive(&wire(2, true, idr)?, 11)?;
        assert!(outputs.iter().any(|s| matches!(s.capture_event(),
            Some(CapturePoll::TimingRequired(request)) if request.idr)));
        Ok(())
    }
    fn window(&mut self) -> Test<ArchiveAdmission> {
        self.picture()?;
        let _ = self.driver.supply_timing(timing(), 12, &self.authority)?;
        assert!(self.driver.seal(13, &self.authority)?);
        match self.driver.poll(SocketReadiness::default(), 13, &self.authority, &NeverCancel)? {
            LiveArchiveStep::WindowAccepted(admission) => Ok(admission),
            _ => Err("window was not admitted to archive".into()),
        }
    }
}

#[test]
fn archive_scope_mismatch_refuses_before_connection_and_authority_probe() -> Test {
    let mut p = LocalRootPublisher::open(fresh()?, limits())?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let (live, mut recording, archive, authority) = config(listener.local_addr()?, 4096, 1)?;
    recording.time_scale += 1;
    let error = LiveAvcArchive::connect(live, recording, archive, &mut p, 0, &authority, &NeverCancel)
        .err().ok_or("mismatched archive connected")?;
    assert!(matches!(error.reason, LiveArchiveError::Configuration));
    assert!(!error.connection_attempted); assert_eq!(authority.checks.get(), 0);
    assert_eq!(p.visible_roots().count(), 0); Ok(())
}

#[test]
fn initial_storage_barrier_does_not_prepare_an_rtsp_command() -> Test {
    let mut p = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::new(&mut p, 7, 1)?;
    assert!(matches!(f.driver.request(ClientCommand::Describe, &credentials()?, [40; 16], 0, &f.authority),
        Err(LiveArchiveFailure { reason: LiveArchiveError::Backpressure, retirement: None })));
    assert_eq!(f.driver.totals().ok_or("totals")?.sent_bytes, 0);
    f.storage(0)?; assert_eq!(f.command(ClientCommand::Describe, 0)?, 1); Ok(())
}

#[test]
fn admission_durability_and_indexing_are_separate_and_storage_blocks_all_socket_reads() -> Test {
    let mut p = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::playing(&mut p, 7, 1)?;
    let admission = f.window()?;
    assert_eq!(f.driver.pending().ok_or("pending window")?.manifest().root(), admission.root);
    assert_eq!(f.driver.snapshot().ok_or("snapshot")?.windows().len(), 0);
    let before = f.driver.totals().ok_or("totals")?;
    f.peer.write_all(b"must remain in socket until storage is ready")?;
    let progress = f.storage(14)?;
    assert!(matches!(progress.first(), Some(ArchiveWriteProgress::WindowDurable { ordinal: 0, .. })));
    assert!(progress.iter().any(|p| matches!(p, ArchiveWriteProgress::CatalogPublished { windows: 1, .. })));
    assert_eq!(f.driver.totals().ok_or("totals")?, before);
    assert!(f.driver.pending().is_none());
    let snapshot = f.driver.snapshot().ok_or("snapshot")?;
    assert_eq!(snapshot.windows().len(), 1); assert_eq!(snapshot.indexed_windows(), 1);
    let retired = f.driver.cancel().ok_or("retirement")?;
    assert!(retired.archive.ok_or("archive retirement")?.pending.is_none());
    drop(f);
    assert_eq!(p.root(&admission.slot).ok_or("durable root")?.root, admission.root);
    Ok(())
}

#[test]
fn eof_flushes_partial_page_then_reopens_with_identical_source_and_media() -> Test {
    let mut expected = None;
    for chunk in [1, 7, 4096] {
        let path = fresh()?; let mut p = LocalRootPublisher::open(&path, limits())?;
        let mut f = Fixture::playing(&mut p, chunk, 4)?;
        let admission = f.window()?;
        let bytes = f.driver.pending().ok_or("pending")?.objects();
        let identities = (ContentDigest::sha256(bytes.source), ContentDigest::sha256(bytes.media),
            ContentDigest::sha256(bytes.index));
        f.storage(14)?;
        assert_eq!(f.driver.snapshot().ok_or("snapshot")?.indexed_windows(), 0);
        f.peer.shutdown(Shutdown::Write)?;
        let mut ended = false; let mut complete = false;
        for _ in 0..128 {
            match f.driver.poll(SocketReadiness { readable: true, writable: false }, 15, &f.authority, &NeverCancel)? {
                LiveArchiveStep::Recording(step) => {
                    if matches!(step.capture_event(), Some(CapturePoll::Ended { .. })) { ended = true; }
                }
                LiveArchiveStep::Finished { archive: ArchiveWriteProgress::Finished { windows: 1, pages: 1, .. },
                    cause: LiveArchiveCompletion::InputEnded } => { complete = true; break; }
                LiveArchiveStep::Archive(_) => {},
                _ => return Err("unexpected EOF archival disposition".into()),
            }
        }
        assert!(ended && complete);
        assert!(matches!(f.driver.poll(SocketReadiness::default(), 15, &f.authority, &NeverCancel)?, LiveArchiveStep::Ended));
        let namespace = f.namespace.clone(); drop(f); drop(p);
        let p = LocalRootPublisher::open(&path, limits())?;
        let snapshot = ArchiveSnapshot::load(&p, namespace.clone(), ArchiveLimits::default(), &NeverCancel)?;
        assert_eq!(snapshot.indexed_windows(), 1);
        let window = load_recording(&p, &admission.slot, admission.root, &namespace.scope().recording, &NeverCancel)?;
        let bytes = window.objects();
        assert_eq!(identities, (ContentDigest::sha256(bytes.source), ContentDigest::sha256(bytes.media), ContentDigest::sha256(bytes.index)));
        if let Some(prior) = expected { assert_eq!(admission.root, prior); } else { expected = Some(admission.root); }
    }
    Ok(())
}

#[test]
fn deliberate_stop_returns_untimed_source_without_claiming_a_recorded_window() -> Test {
    let mut p = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::playing(&mut p, 4096, 1)?; f.picture()?;
    let retired = f.driver.finish_capture(12, &f.authority)?.ok_or("capture retirement")?;
    assert!(retired.capture.picture.is_some()); assert!(!retired.capture.collection.pending.sources.is_empty());
    assert!(matches!(f.driver.poll(SocketReadiness::default(), 13, &f.authority, &NeverCancel)?,
        LiveArchiveStep::Finished { archive: ArchiveWriteProgress::Finished { windows: 0, pages: 0, .. },
            cause: LiveArchiveCompletion::OwnerStopped }));
    drop(f); assert_eq!(p.visible_roots().count(), 0); Ok(())
}

#[test]
fn undersized_window_allowance_returns_the_unoffered_original_and_stops_the_socket() -> Test {
    let mut p = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::playing(&mut p, 4096, 1)?; f.driver.max_window_bytes = 1;
    f.picture()?; let _ = f.driver.supply_timing(timing(), 12, &f.authority)?;
    assert!(f.driver.seal(13, &f.authority)?);
    let error = f.driver.poll(SocketReadiness::default(), 13, &f.authority, &NeverCancel).err().ok_or("overbudget admission")?;
    assert!(matches!(error.reason, LiveArchiveError::Archive(ArchiveError::Limit)));
    let retired = error.retirement.ok_or("retirement")?;
    assert!(retired.unoffered_window.is_some()); assert!(retired.recording.is_some());
    assert!(retired.archive.ok_or("archive")?.pending.is_none());
    assert!(matches!(f.driver.poll(SocketReadiness::default(), 14, &f.authority, &NeverCancel)?, LiveArchiveStep::Ended));
    drop(f); assert_eq!(p.visible_roots().count(), 0); Ok(())
}

#[test]
fn revocation_during_storage_pause_preserves_pending_window_without_publication() -> Test {
    let mut p = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::playing(&mut p, 4096, 1)?; let admission = f.window()?;
    let totals = f.driver.totals().ok_or("totals")?; f.authority.revoked.set(true);
    let error = f.driver.poll(SocketReadiness { readable: true, writable: true }, 14, &f.authority, &NeverCancel)
        .err().ok_or("revocation bypassed")?;
    assert!(matches!(error.reason, LiveArchiveError::Authority(TcpDenial::Revoked)));
    let retired = error.retirement.ok_or("retirement")?;
    assert_eq!(retired.archive.ok_or("archive")?.pending.ok_or("pending")?.manifest().root(), admission.root);
    assert_eq!(retired.recording.ok_or("capture")?.connection.ok_or("connection")?.transport.totals, totals);
    drop(f); assert!(p.root(&admission.slot).is_none()); Ok(())
}

#[test]
fn refused_flush_and_clock_regression_do_not_renew_storage_pause() -> Test {
    let mut p = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::playing(&mut p, 4096, 1)?; f.window()?;
    f.driver.max_storage_pause_ns = 5;
    let steps = f.driver.remaining_steps;
    assert!(matches!(f.driver.poll(SocketReadiness::default(), 12, &f.authority, &NeverCancel),
        Err(LiveArchiveFailure { reason: LiveArchiveError::ClockReversed, retirement: None })));
    assert_eq!(f.driver.remaining_steps, steps);
    assert!(matches!(f.driver.flush(14, &f.authority),
        Err(LiveArchiveFailure { reason: LiveArchiveError::Backpressure, retirement: None })));
    let error = f.driver.poll(SocketReadiness::default(), 18, &f.authority, &NeverCancel).err().ok_or("renewed pause")?;
    assert!(matches!(error.reason, LiveArchiveError::StoragePauseExpired));
    assert!(error.retirement.ok_or("retirement")?.archive.ok_or("archive")?.pending.is_some());
    Ok(())
}

#[test]
fn finite_driver_allowance_cannot_be_bypassed_by_no_readiness_polls() -> Test {
    let mut p = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::playing(&mut p, 4096, 1)?; f.window()?; f.driver.remaining_steps = 0;
    let error = f.driver.poll(SocketReadiness::default(), 14, &f.authority, &NeverCancel).err().ok_or("work budget bypass")?;
    assert!(matches!(error.reason, LiveArchiveError::WorkBudget));
    assert!(error.retirement.ok_or("retirement")?.archive.ok_or("archive")?.pending.is_some());
    assert!(f.driver.cancel().is_none()); Ok(())
}

mod recovery;
