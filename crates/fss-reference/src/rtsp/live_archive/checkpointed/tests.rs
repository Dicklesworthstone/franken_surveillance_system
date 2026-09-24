#![forbid(unsafe_code)]
//! Native loopback AVC -> write-ahead work -> ordinary archive -> cold source replay.
use super::*;
use crate::rtsp::authentication::DigestPolicy;
use crate::rtsp::client::ClientConfig;
use crate::rtsp::live_avc::LiveAvcStep;
use crate::rtsp::recording::RecordingScope;
use crate::rtsp::recording::local::load_recording;
use crate::rtsp::recording_archive::checkpoint::load_archive_work;
use crate::rtsp::recording_catalog::CatalogScope;
use crate::rtsp::recording_collector::CollectorLimits;
use crate::rtsp::tcp::{TcpLimits, TcpSecurityPolicy, TcpWriteStep};
use fss_core::{ContentDigest, SensorId, StreamId};
use fss_object::SpoolLimits;
use fss_packet::{StreamKey, avc::AvcReceiveLimits};
use fss_publication::{LocalPublicationLimits, NeverCancel};
use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const KEY: StreamKey = StreamKey {
    ingress: 71,
    generation: 1,
    ssrc: 7,
};
const LEASE: u64 = 100_000_000_000;
const PAUSE: u64 = 1_000_000_000;
static NEXT_PATH: AtomicU64 = AtomicU64::new(0);
fn fresh() -> Test<PathBuf> {
    for _ in 0..256 {
        let path = std::env::temp_dir().join(format!(
            "fss-checkpointed-live-{}-{}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err("fixture directory allowance exhausted".into())
}
fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        128,
        1024,
        128,
        1024,
        SpoolLimits::new(1024, 16 * 1024 * 1024, 2 * 1024 * 1024, 1024),
    )
}
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
fn config(
    peer: std::net::SocketAddr,
    chunk: usize,
) -> Test<(
    LiveAvcConfig,
    LiveRecordingConfig,
    LiveArchiveConfig,
    Authority,
)> {
    let binding = TcpBinding::new(
        KEY,
        peer,
        "camera.local",
        TcpSecurityPolicy::OwnerApprovedPlaintext,
    )?;
    let authority = Authority {
        binding: binding.clone(),
        revoked: Cell::new(false),
        checks: Cell::new(0),
    };
    let live = LiveAvcConfig {
        protocol: ClientConfig {
            presentation_uri: "rtsp://camera.local/live/".into(),
            control_root_uri: "rtsp://camera.local/live".into(),
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
        media: AvcReceiveLimits::default(),
        realm: "fixture-camera".into(),
        digest_policy: DigestPolicy::default(),
        deadline_ns: LEASE,
        max_steps: 100_000,
    };
    let recording = LiveRecordingConfig {
        scope: RecordingScope {
            sensor: SensorId::parse("sensor:checkpoint-fixture")?,
            stream: StreamId::parse("stream:checkpoint-fixture")?,
            generation: KEY.generation,
            anchor: ContentDigest::sha256(b"checkpoint live owner anchor"),
            receive_clock: ContentDigest::sha256(b"checkpoint receive clock"),
        },
        payload_type: 96,
        time_scale: 90_000,
        limits: CollectorLimits::default(),
    };
    let archive = LiveArchiveConfig {
        namespace: ArchiveNamespace::new(CatalogScope {
            recording: recording.scope.clone(),
            decode_clock: ContentDigest::sha256(b"checkpoint decode clock"),
            time_scale: recording.time_scale,
        })?,
        limits: ArchiveLimits {
            max_windows: 8,
            max_pages: 8,
            max_scan_roots: 128,
            windows_per_page: 2,
        },
        max_window_bytes: MAX_RECORDING_BYTES,
        max_steps: 100_000,
        publication_deadline_ns: 2 * LEASE,
        max_storage_pause_ns: PAUSE,
    };
    Ok((live, recording, archive, authority))
}
fn credentials() -> Test<DigestCredentials<'static>> {
    Ok(DigestCredentials::new("fixture-user", "fixture-password")?)
}
fn response(cseq: u32, headers: &str, body: &str) -> Vec<u8> {
    format!(
        "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len()
    )
    .into_bytes()
}
fn description() -> &'static str {
    "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\na=control:trackID=0\r\n"
}
fn nals() -> Vec<&'static [u8]> {
    let bytes: &'static [u8] =
        include_bytes!("../../../../../fss-packet/tests/fixtures/avc/baseline.264");
    let mut out = Vec::new();
    let mut start = None;
    let mut at = 0;
    while at + 3 <= bytes.len() {
        let prefix = if bytes.get(at..at + 4) == Some(&[0, 0, 0, 1]) {
            4
        } else if bytes[at..at + 3] == [0, 0, 1] {
            3
        } else {
            0
        };
        if prefix == 0 {
            at += 1;
            continue;
        }
        if let Some(begin) = start {
            let mut end = at;
            while end > begin && bytes[end - 1] == 0 {
                end -= 1;
            }
            if begin < end {
                out.push(&bytes[begin..end]);
            }
        }
        start = Some(at + prefix);
        at += prefix;
    }
    if let Some(begin) = start
        && begin < bytes.len()
    {
        out.push(&bytes[begin..]);
    }
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
fn timing() -> RecordingTiming {
    RecordingTiming {
        decode_time: 700,
        duration: 3_600,
        composition_offset: 0,
    }
}
fn ready() -> SocketReadiness {
    SocketReadiness {
        readable: true,
        writable: true,
    }
}
struct Fixture<'a> {
    driver: CheckpointedLiveAvcArchive<'a>,
    peer: TcpStream,
    authority: Authority,
    namespace: ArchiveNamespace,
}
impl<'a> Fixture<'a> {
    fn new(p: &'a mut LocalRootPublisher, chunk: usize, work: ArchiveWorkLimits) -> Test<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let (live, recording, archive, authority) = config(listener.local_addr()?, chunk)?;
        let namespace = archive.namespace.clone();
        let driver = CheckpointedLiveAvcArchive::connect(
            live,
            recording,
            archive,
            work,
            p,
            0,
            &authority,
            &NeverCancel,
        )?;
        let (peer, _) = listener.accept()?;
        peer.set_read_timeout(Some(Duration::from_secs(2)))?;
        peer.set_write_timeout(Some(Duration::from_secs(2)))?;
        peer.set_nodelay(true)?;
        Ok(Self {
            driver,
            peer,
            authority,
            namespace,
        })
    }
    fn poll(&mut self, now: u64) -> Test<CheckpointedLiveArchiveStep> {
        Ok(self
            .driver
            .poll(ready(), now, &self.authority, &NeverCancel)?)
    }
    fn command(&mut self, command: ClientCommand, now: u64) -> Test<u32> {
        let queued = self.driver.request(
            command,
            &credentials()?,
            [40 + now as u8; 16],
            now,
            &self.authority,
        )?;
        for _ in 0..32_768 {
            let CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Recording(step)) =
                self.driver.poll(
                    SocketReadiness {
                        readable: false,
                        writable: true,
                    },
                    now,
                    &self.authority,
                    &NeverCancel,
                )?
            else {
                return Err("unexpected storage output during command dispatch".into());
            };
            match *step {
                LiveRecordingStep::Network(LiveAvcStep::Write(TcpWriteStep::Sent {
                    cseq,
                    bytes,
                })) => {
                    assert_eq!((cseq, bytes), (queued.cseq, queued.bytes));
                    self.peer.read_exact(&mut vec![0; bytes])?;
                    return Ok(cseq);
                }
                LiveRecordingStep::Network(
                    LiveAvcStep::Write(TcpWriteStep::Advanced { .. }) | LiveAvcStep::Pending(_),
                ) => {}
                _ => return Err("unexpected live output during command dispatch".into()),
            }
        }
        Err("command work bound".into())
    }
    fn receive(&mut self, bytes: &[u8], now: u64) -> Test<Vec<LiveRecordingStep>> {
        self.peer.write_all(bytes)?;
        let mut originals = Vec::new();
        let mut outputs = Vec::new();
        for _ in 0..32_768 {
            let CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Recording(step)) =
                self.driver.poll(
                    SocketReadiness {
                        readable: true,
                        writable: false,
                    },
                    now,
                    &self.authority,
                    &NeverCancel,
                )?
            else {
                return Err("unexpected archive result during receive".into());
            };
            match *step {
                LiveRecordingStep::Network(LiveAvcStep::Wire(chunk)) => {
                    originals.extend_from_slice(chunk.expose())
                }
                LiveRecordingStep::Network(LiveAvcStep::Pending(wait)) => {
                    if originals.len() == bytes.len() && wait.wake_at_ns.is_none_or(|at| at > now) {
                        assert_eq!(originals, bytes);
                        return Ok(outputs);
                    }
                    std::thread::yield_now();
                }
                other => {
                    let stop =
                        matches!(other.capture_event(), Some(CapturePoll::TimingRequired(_)));
                    outputs.push(other);
                    if stop {
                        assert_eq!(originals, bytes);
                        return Ok(outputs);
                    }
                }
            }
        }
        Err("receive work bound".into())
    }
    fn playing(p: &'a mut LocalRootPublisher, chunk: usize) -> Test<Self> {
        let mut f = Self::new(p, chunk, ArchiveWorkLimits::default())?;
        assert!(matches!(
            f.poll(0)?,
            CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Archive(
                ArchiveWriteProgress::Ready { .. }
            ))
        ));
        let seq = f.command(ClientCommand::Describe, 0)?;
        f.receive(
            &response(seq, "Content-Type: application/sdp\r\n", description()),
            1,
        )?;
        let seq = f.command(ClientCommand::Setup, 2)?;
        f.receive(&response(seq, "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n", ""), 3)?;
        let seq = f.command(ClientCommand::Play, 4)?;
        f.receive(&response(seq, "Session: fixture\r\n", ""), 5)?;
        assert_eq!(f.driver.state(), ClientState::Playing);
        Ok(f)
    }
    fn window(&mut self) -> Test<ArchiveAdmission> {
        let data = nals();
        let sps = data.iter().find(|n| n[0] & 31 == 7).ok_or("missing SPS")?;
        let idr = data
            .iter()
            .find(|n| n[0] & 31 == 5)
            .ok_or("missing native IDR")?;
        self.receive(&wire(1, false, sps)?, 10)?;
        let outputs = self.receive(&wire(2, true, idr)?, 11)?;
        assert!(outputs.iter().any(|s| matches!(s.capture_event(),
            Some(CapturePoll::TimingRequired(request)) if request.idr)));
        let _ = self.driver.supply_timing(timing(), 12, &self.authority)?;
        assert!(self.driver.seal(13, &self.authority)?);
        match self.poll(13)? {
            CheckpointedLiveArchiveStep::Live(LiveArchiveStep::WindowAccepted(admission)) => {
                Ok(admission)
            }
            _ => Err("window not admitted".into()),
        }
    }
    fn pin(&mut self, now: u64) -> Test<ArchiveCheckpoint> {
        match self.poll(now)? {
            CheckpointedLiveArchiveStep::Checkpoint(CheckpointedArchiveProgress::PinRequired(
                pin,
            )) => Ok(pin),
            _ => Err("pin not announced before publication".into()),
        }
    }
    fn protect(&mut self, pin: &ArchiveCheckpoint, now: u64) -> Test {
        self.driver
            .acknowledge_checkpoint(pin, now, &self.authority, &NeverCancel)?;
        match self.poll(now)? {
            CheckpointedLiveArchiveStep::Checkpoint(CheckpointedArchiveProgress::WorkDurable {
                checkpoint,
                receipt,
            }) => {
                assert_eq!(checkpoint, *pin);
                assert_eq!(receipt.root, pin.root());
                Ok(())
            }
            _ => Err("whole work graph not acknowledged".into()),
        }
    }
    fn finish(&mut self, now: u64) -> Test<(Vec<ArchiveCheckpoint>, LiveArchiveCompletion)> {
        let mut pins = Vec::new();
        for _ in 0..256 {
            match self.poll(now)? {
                CheckpointedLiveArchiveStep::Checkpoint(
                    CheckpointedArchiveProgress::PinRequired(pin),
                ) => {
                    // The test harness retains the independent pin; no external journal is implied.
                    self.protect(&pin, now)?;
                    pins.push(pin);
                }
                CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Finished { archive, cause }) => {
                    assert!(matches!(
                        archive,
                        ArchiveWriteProgress::Finished {
                            windows: 1,
                            pages: 1,
                            ..
                        }
                    ));
                    return Ok((pins, cause));
                }
                CheckpointedLiveArchiveStep::Stopped { .. } => {
                    return Err("fault became finish".into());
                }
                CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Ended) => {
                    return Err("finish receipt missing".into());
                }
                _ => {}
            }
        }
        Err("bounded final archive drain did not finish".into())
    }
}

#[test]
fn native_capture_is_checkpointed_before_ordinary_archive_and_cold_replays_across_chunk_sizes()
-> Test {
    let mut identities = Vec::new();
    for chunk in [1, 7, 4096] {
        let path = fresh()?;
        let (namespace, root, objects, window_pin, page_pin) = {
            let mut p = LocalRootPublisher::open(&path, limits())?;
            let mut f = Fixture::playing(&mut p, chunk)?;
            let admission = f.window()?;
            let objects = f
                .driver
                .pending()
                .ok_or("source missing")?
                .children()
                .map(|(_, digest, _)| digest);
            let pin = f.pin(14)?;
            let calls = f.driver.totals().ok_or("totals missing")?;
            f.peer.write_all(b"PRIVATE_UNREAD_SOURCE_SENTINEL")?;
            for _ in 0..4 {
                assert!(
                    matches!(f.poll(14)?, CheckpointedLiveArchiveStep::Checkpoint(
                    CheckpointedArchiveProgress::PinRequired(p)) if p == pin)
                );
            }
            assert_eq!(f.driver.totals(), Some(calls));
            assert!(
                f.driver
                    .snapshot()
                    .ok_or("snapshot missing")?
                    .windows()
                    .is_empty()
            );
            f.protect(&pin, 14)?;
            assert_eq!(f.driver.totals(), Some(calls));
            assert!(
                f.driver
                    .snapshot()
                    .ok_or("snapshot missing")?
                    .windows()
                    .is_empty()
            );
            assert!(matches!(
                f.poll(14)?,
                CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Archive(
                    ArchiveWriteProgress::WindowDurable { ordinal: 0, .. }
                ))
            ));
            // Stop before camera input is resumed; the unread canary must not enter parsing.
            assert!(f.driver.finish_capture(15, &f.authority)?.is_some());
            let (pins, cause) = f.finish(15)?;
            assert_eq!(cause, LiveArchiveCompletion::OwnerStopped);
            assert_eq!(pins.len(), 1);
            assert_eq!(
                f.driver
                    .snapshot()
                    .ok_or("snapshot missing")?
                    .indexed_windows(),
                1
            );
            let page = pins.into_iter().next().ok_or("page pin missing")?;
            (f.namespace.clone(), admission.root, objects, pin, page)
        };
        let p = LocalRootPublisher::open(&path, limits())?;
        let recording = load_recording(
            &p,
            &namespace.window_slot(0)?,
            root,
            &namespace.scope().recording,
            &NeverCancel,
        )?;
        assert_eq!(recording.children().map(|(_, digest, _)| digest), objects);
        let work = load_archive_work(
            &p,
            page_pin.slot(),
            page_pin.root(),
            ArchiveWorkLimits::default(),
            &NeverCancel,
        )?;
        assert!(work.pending.is_none());
        assert!(work.prepared_page.is_some());
        assert_eq!(work.snapshot.windows().len(), 1);
        identities.push((root, objects, window_pin.root(), page_pin.root()));
    }
    assert!(identities.windows(2).all(|pair| pair[0] == pair[1]));
    Ok(())
}

#[test]
fn work_limits_are_rejected_before_storage_recovery_or_network_authority() -> Test {
    let mut p = LocalRootPublisher::open(fresh()?, limits())?;
    for work in [
        ArchiveWorkLimits {
            max_pending_bytes: 0,
            ..ArchiveWorkLimits::default()
        },
        ArchiveWorkLimits {
            max_new_bytes: 0,
            ..ArchiveWorkLimits::default()
        },
        ArchiveWorkLimits {
            max_graph_objects: 0,
            ..ArchiveWorkLimits::default()
        },
    ] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let (live, recording, archive, authority) = config(listener.local_addr()?, 7)?;
        let error = CheckpointedLiveAvcArchive::connect(
            live,
            recording,
            archive,
            work,
            &mut p,
            0,
            &authority,
            &NeverCancel,
        )
        .err()
        .ok_or("invalid protection connected")?;
        assert!(!error.connection_attempted);
        assert_eq!(authority.checks.get(), 0);
        assert_eq!(p.visible_roots().count(), 0);
    }
    Ok(())
}

#[test]
fn revocation_while_waiting_for_a_pin_closes_capture_and_returns_source_and_candidate_once() -> Test
{
    let mut p = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::playing(&mut p, 7)?;
    let admission = f.window()?;
    let pin = f.pin(14)?;
    f.authority.revoked.set(true);
    let error = f
        .driver
        .poll(ready(), 15, &f.authority, &NeverCancel)
        .err()
        .ok_or("revocation ignored")?;
    assert!(matches!(
        error.reason,
        LiveArchiveError::Authority(TcpDenial::Revoked)
    ));
    let retired = error.retirement.ok_or("retirement missing")?;
    assert_eq!(retired.pending_checkpoint, Some(pin));
    assert!(retired.last_durable_checkpoint.is_none());
    assert!(retired.live.recording.is_some());
    let archive = retired.live.archive.ok_or("archive retirement missing")?;
    assert_eq!(
        archive.pending.ok_or("source lost")?.manifest().root(),
        admission.root
    );
    assert!(f.driver.cancel().is_none());
    assert!(matches!(
        f.poll(15)?,
        CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Ended)
    ));
    drop(f);
    assert_eq!(p.visible_roots().count(), 0);
    Ok(())
}

#[test]
fn pin_wait_has_a_fixed_deadline_and_blocks_protocol_commands_without_resetting_the_pause() -> Test
{
    let mut p = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::playing(&mut p, 7)?;
    f.window()?;
    let pin = f.pin(14)?;
    let expires = 13 + PAUSE;
    assert_eq!(f.driver.next_wake_ns(), Some(expires));
    for now in 15..20 {
        let error = f
            .driver
            .request(
                ClientCommand::KeepAlive,
                &credentials()?,
                [90; 16],
                now,
                &f.authority,
            )
            .err()
            .ok_or("storage wait allowed a command")?;
        assert!(matches!(error.reason, LiveArchiveError::Backpressure));
        assert!(error.retirement.is_none());
        assert!(
            matches!(f.poll(now)?, CheckpointedLiveArchiveStep::Checkpoint(
            CheckpointedArchiveProgress::PinRequired(p)) if p == pin)
        );
        assert_eq!(f.driver.next_wake_ns(), Some(expires));
    }
    let error = f
        .driver
        .acknowledge_checkpoint(&pin, expires, &f.authority, &NeverCancel)
        .err()
        .ok_or("late pin acknowledgement renewed pause")?;
    assert!(matches!(
        error.reason,
        LiveArchiveError::StoragePauseExpired
    ));
    assert_eq!(
        error.retirement.ok_or("retirement")?.pending_checkpoint,
        Some(pin)
    );
    assert_eq!(f.driver.next_wake_ns(), None);
    Ok(())
}

struct Cancel;
impl PublishCancellation for Cancel {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        true
    }
}
#[test]
fn cancellation_at_the_work_barrier_never_publishes_an_ordinary_window() -> Test {
    let mut p = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::playing(&mut p, 4096)?;
    let admission = f.window()?;
    let pin = f.pin(14)?;
    f.driver
        .acknowledge_checkpoint(&pin, 14, &f.authority, &NeverCancel)?;
    let error = f
        .driver
        .poll(ready(), 14, &f.authority, &Cancel)
        .err()
        .ok_or("cancellation ignored")?;
    assert!(matches!(
        error.reason,
        LiveArchiveError::Archive(ArchiveError::Cancelled)
    ));
    let retired = error.retirement.ok_or("retirement")?;
    assert_eq!(retired.pending_checkpoint, Some(pin));
    assert!(retired.last_durable_checkpoint.is_none());
    assert_eq!(
        retired
            .live
            .archive
            .ok_or("archive")?
            .pending
            .ok_or("pending")?
            .manifest()
            .root(),
        admission.root
    );
    assert!(f.driver.cancel().is_none());
    drop(f);
    assert_eq!(p.visible_roots().count(), 0);
    Ok(())
}

#[test]
fn an_uncertain_auxiliary_root_closes_the_socket_and_retains_original_window_and_pin() -> Test {
    let path = fresh()?;
    let namespace = {
        let mut p = LocalRootPublisher::open(&path, limits())?;
        p.inject_crash_at(PublishCutPoint::AfterRootRename);
        let mut f = Fixture::playing(&mut p, 7)?;
        let admission = f.window()?;
        let pin = f.pin(14)?;
        f.driver
            .acknowledge_checkpoint(&pin, 14, &f.authority, &NeverCancel)?;
        let error = f
            .driver
            .poll(ready(), 14, &f.authority, &NeverCancel)
            .err()
            .ok_or("injected crash did not stop")?;
        let retired = error.retirement.ok_or("retirement missing")?;
        assert_eq!(retired.pending_checkpoint, Some(pin));
        assert!(retired.last_durable_checkpoint.is_none());
        assert!(retired.live.recording.is_some());
        let archive = retired.live.archive.ok_or("archive missing")?;
        assert!(archive.snapshot.windows().is_empty());
        assert_eq!(
            archive.pending.ok_or("source lost")?.manifest().root(),
            admission.root
        );
        assert!(matches!(
            f.poll(15)?,
            CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Ended)
        ));
        f.namespace.clone()
    };
    let p = LocalRootPublisher::open(&path, limits())?;
    assert!(p.root(&namespace.window_slot(0)?).is_none());
    assert!(p.visible_roots().count() > 0); // The auxiliary root committed; the whole work root did not.
    Ok(())
}

#[test]
fn recovered_tail_requires_its_page_checkpoint_before_any_new_camera_command() -> Test {
    let path = fresh()?;
    {
        let mut p = LocalRootPublisher::open(&path, limits())?;
        let mut f = Fixture::playing(&mut p, 7)?;
        f.window()?;
        let pin = f.pin(14)?;
        f.protect(&pin, 14)?;
        assert!(matches!(
            f.poll(14)?,
            CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Archive(
                ArchiveWriteProgress::WindowDurable { .. }
            ))
        ));
        let retired = f.driver.cancel().ok_or("retirement")?;
        assert_eq!(
            retired
                .live
                .archive
                .ok_or("archive")?
                .snapshot
                .unindexed_windows()
                .len(),
            1
        );
    }
    let mut p = LocalRootPublisher::open(&path, limits())?;
    let mut f = Fixture::new(&mut p, 7, ArchiveWorkLimits::default())?;
    assert!(matches!(
        f.poll(0)?,
        CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Archive(
            ArchiveWriteProgress::PageStarted { .. }
        ))
    ));
    assert!(matches!(
        f.poll(0)?,
        CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Archive(
            ArchiveWriteProgress::PageWindowVerified { .. }
        ))
    ));
    assert!(matches!(
        f.poll(0)?,
        CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Archive(
            ArchiveWriteProgress::CatalogPrepared { .. }
        ))
    ));
    let pin = f.pin(0)?;
    assert!(matches!(
        f.driver.request(
            ClientCommand::Describe,
            &credentials()?,
            [40; 16],
            0,
            &f.authority
        ),
        Err(CheckpointedLiveArchiveFailure {
            reason: LiveArchiveError::Backpressure,
            retirement: None
        })
    ));
    assert_eq!(f.driver.totals().ok_or("totals")?.sent_bytes, 0);
    assert_eq!(f.driver.totals().ok_or("totals")?.read_calls, 0);
    f.protect(&pin, 0)?;
    assert!(matches!(
        f.poll(0)?,
        CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Archive(
            ArchiveWriteProgress::CatalogIndexStaged { .. }
        ))
    ));
    assert!(matches!(
        f.poll(0)?,
        CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Archive(
            ArchiveWriteProgress::CatalogPublished { .. }
        ))
    ));
    assert!(matches!(
        f.poll(0)?,
        CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Archive(
            ArchiveWriteProgress::Ready { .. }
        ))
    ));
    assert_eq!(f.driver.snapshot().ok_or("snapshot")?.indexed_windows(), 1);
    assert_eq!(f.command(ClientCommand::Describe, 0)?, 1);
    Ok(())
}

#[test]
fn real_eof_flushes_a_protected_final_page_without_becoming_owner_stop_or_repeated_completion()
-> Test {
    let mut p = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::playing(&mut p, 4096)?;
    f.window()?;
    let pin = f.pin(14)?;
    f.protect(&pin, 14)?;
    assert!(matches!(
        f.poll(14)?,
        CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Archive(
            ArchiveWriteProgress::WindowDurable { .. }
        ))
    ));
    assert!(matches!(
        f.poll(14)?,
        CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Archive(
            ArchiveWriteProgress::Ready { .. }
        ))
    ));
    f.peer.shutdown(Shutdown::Write)?;
    let (pins, cause) = f.finish(15)?;
    assert_eq!(cause, LiveArchiveCompletion::InputEnded);
    assert_eq!(pins.len(), 1);
    assert_eq!(f.driver.snapshot().ok_or("snapshot")?.indexed_windows(), 1);
    assert!(matches!(
        f.poll(16)?,
        CheckpointedLiveArchiveStep::Live(LiveArchiveStep::Ended)
    ));
    assert_eq!(f.driver.next_wake_ns(), None);
    Ok(())
}
