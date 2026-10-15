#![forbid(unsafe_code)]
//! Loopback-only control drainage through the public protected-archive owner.

use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fss_core::{ContentDigest, SensorId, StreamId};
use fss_object::SpoolLimits;
use fss_packet::{StreamKey, avc::AvcReceiveLimits};
use fss_publication::{
    LocalPublicationLimits, LocalRootPublisher, NeverCancel, PublishCancellation, PublishCutPoint,
};
use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};
use fss_reference::rtsp::avc_client::{AvcClientPoll, authenticated::DigestAvcPoll};
use fss_reference::rtsp::client::{ClientConfig, ClientProgress, ClientState};
use fss_reference::rtsp::live_archive::{LiveArchiveConfig, LiveArchiveError, LiveArchiveStep};
use fss_reference::rtsp::live_archive::checkpointed::{
    AutomaticLiveArchiveStep as Step, AutomaticLiveAvcArchive, CheckpointedLiveArchiveStep as Progress,
};
use fss_reference::rtsp::live_avc::{LiveAvcConfig, LiveAvcStep, SocketReadiness};
use fss_reference::rtsp::live_avc::recording::{LiveRecordingConfig, LiveRecordingStep};
use fss_reference::rtsp::recording::{MAX_RECORDING_BYTES, RecordingScope};
use fss_reference::rtsp::recording_archive::{ArchiveError, ArchiveLimits, ArchiveNamespace, ArchiveWriteProgress};
use fss_reference::rtsp::recording_archive::checkpoint::ArchiveWorkLimits;
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_collector::CollectorLimits;
use fss_reference::rtsp::tcp::{
    TcpAuthority, TcpBinding, TcpDenial, TcpLimits, TcpOperation, TcpSecurityPolicy, TcpWriteStep,
};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const LEASE: u64 = 100_000_000_000;
const KEY: StreamKey = StreamKey { ingress: 71, generation: 1, ssrc: 7 };
static NEXT: AtomicU64 = AtomicU64::new(0);
const SDP: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\na=control:trackID=0\r\n";

fn publisher() -> Test<LocalRootPublisher> {
    for _ in 0..128 {
        let path = std::env::temp_dir().join(format!("fss-archive-control-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(LocalRootPublisher::open(path, LocalPublicationLimits::new(
                128, 1024, 128, 1024,
                SpoolLimits::new(1024, 16 * 1024 * 1024, 2 * 1024 * 1024, 1024),
            ))?),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {},
            Err(e) => return Err(e.into()),
        }
    }
    Err("fixture directory bound exhausted".into())
}
fn credentials() -> Test<DigestCredentials<'static>> {
    Ok(DigestCredentials::new("fixture-user", "fixture-password")?)
}
struct Authority { binding: TcpBinding, revoked: Cell<bool> }
impl TcpAuthority for Authority {
    fn checkpoint(&self, binding: &TcpBinding, _: TcpOperation, now: u64, until: u64)
        -> Result<(), TcpDenial>
    {
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
struct Fixture<'a> {
    driver: AutomaticLiveAvcArchive<'a>,
    peer: TcpStream,
    authority: Authority,
}
impl<'a> Fixture<'a> {
    fn new(p: &'a mut LocalRootPublisher) -> Test<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let binding = TcpBinding::new(KEY, listener.local_addr()?, "camera.local",
            TcpSecurityPolicy::OwnerApprovedPlaintext)?;
        let authority = Authority { binding: binding.clone(), revoked: Cell::new(false) };
        let live = LiveAvcConfig {
            protocol: ClientConfig {
                presentation_uri: "rtsp://camera.local/live/".into(),
                control_root_uri: "rtsp://camera.local/live".into(),
                media_index: 0, channels: (0, 1), response_timeout_ns: 10_000_000_000,
                default_session_timeout_seconds: 60,
            },
            binding, transport: TcpLimits::default(), media: AvcReceiveLimits::default(),
            realm: "fixture-camera".into(), digest_policy: DigestPolicy::default(),
            deadline_ns: LEASE, max_steps: 10_000,
        };
        let recording = LiveRecordingConfig {
            scope: RecordingScope {
                sensor: SensorId::parse("sensor:archive-control")?,
                stream: StreamId::parse("stream:archive-control")?, generation: 1,
                anchor: ContentDigest::sha256(b"archive control fixture anchor"),
                receive_clock: ContentDigest::sha256(b"archive control receive clock"),
            },
            payload_type: 96, time_scale: 90_000, limits: CollectorLimits::default(),
        };
        let archive = LiveArchiveConfig {
            namespace: ArchiveNamespace::new(CatalogScope {
                recording: recording.scope.clone(),
                decode_clock: ContentDigest::sha256(b"archive control decode clock"),
                time_scale: 90_000,
            })?,
            limits: ArchiveLimits { max_windows: 8, max_pages: 8, max_scan_roots: 128, windows_per_page: 2 },
            max_window_bytes: MAX_RECORDING_BYTES, max_steps: 10_000,
            publication_deadline_ns: 2 * LEASE, max_storage_pause_ns: 1_000_000_000,
        };
        let driver = AutomaticLiveAvcArchive::connect(live, recording, archive,
            ArchiveWorkLimits::default(), p, 0, &authority, &NeverCancel)?;
        let (peer, _) = listener.accept()?;
        peer.set_read_timeout(Some(Duration::from_secs(2)))?;
        peer.set_write_timeout(Some(Duration::from_secs(2)))?;
        peer.set_nodelay(true)?;
        Ok(Self { driver, peer, authority })
    }
    fn poll(&mut self, ready: bool, now: u64) -> Test<Step> {
        Ok(self.driver.poll(SocketReadiness { readable: ready, writable: ready },
            &credentials()?, [1; 16], now, &self.authority, &NeverCancel)?)
    }
    fn defer(&mut self) -> Test {
        assert!(matches!(self.poll(false, 0)?, Step::Archive(Progress::Live(
            LiveArchiveStep::Archive(ArchiveWriteProgress::Ready { .. })))));
        let Step::Queued(queued) = self.poll(false, 0)? else {
            return Err("missing initial DESCRIBE".into());
        };
        let mut sent = false;
        for _ in 0..1024 {
            if let Step::Archive(Progress::Live(LiveArchiveStep::Recording(step))) = self.poll(true, 0)?
                && let LiveRecordingStep::Network(LiveAvcStep::Write(TcpWriteStep::Sent { bytes, cseq })) = *step
            {
                assert_eq!((cseq, bytes), (queued.cseq, queued.bytes));
                self.peer.read_exact(&mut vec![0; bytes])?;
                sent = true;
                break;
            }
        }
        assert!(sent);
        let bytes = format!("RTSP/1.0 200 OK\r\nCSeq: {}\r\nContent-Length: {}\r\nContent-Type: application/sdp\r\n\r\n{SDP}RTSP/1.", queued.cseq, SDP.len()).into_bytes();
        self.peer.write_all(&bytes)?;
        let mut original = Vec::new();
        let mut accepted = false;
        for _ in 0..1024 {
            if let Step::Archive(Progress::Live(LiveArchiveStep::Recording(step))) = self.poll(true, 1)? {
                match *step {
                    LiveRecordingStep::Network(LiveAvcStep::Wire(chunk)) => original.extend_from_slice(chunk.expose()),
                    LiveRecordingStep::Network(LiveAvcStep::Protocol {
                        event: DigestAvcPoll::Client { event, .. }, ..
                    }) if matches!(event.as_ref(), AvcClientPoll::Control(ClientProgress::Accepted(ClientState::Described))) => {
                        accepted = true;
                        break;
                    }
                    _ => {},
                }
            }
            std::thread::yield_now();
        }
        assert!(accepted);
        assert_eq!(original, bytes);
        let failure = self.driver.poll(SocketReadiness::default(), &credentials()?, [1; 16],
            2, &self.authority, &NeverCancel).err().ok_or("SETUP bypassed retained wire")?;
        assert!(matches!(failure.reason, LiveArchiveError::Recording(_)));
        assert!(failure.retirement.is_none());
        assert!(!self.driver.needs_credentials());
        let step = self.poll(false, 2)?;
        assert!(matches!(step, Step::Archive(Progress::Live(LiveArchiveStep::Recording(step)))
            if matches!(step.as_ref(), LiveRecordingStep::Network(LiveAvcStep::Pending(_)))));
        assert!(!self.driver.needs_credentials());
        Ok(())
    }
}

#[test]
fn storage_ready_does_not_rearm_a_protocol_blocked_command() -> Test {
    let mut p = publisher()?;
    let mut f = Fixture::new(&mut p)?;
    f.defer()?;
    let totals = f.driver.totals();
    let deadline = f.driver.next_wake_ns().ok_or("missing wire expiry")?;
    f.driver.flush(3, &f.authority)?;
    assert!(matches!(f.poll(true, 3)?, Step::Archive(Progress::Live(
        LiveArchiveStep::Archive(ArchiveWriteProgress::Ready { .. })))));
    assert_eq!(f.driver.totals(), totals, "storage progress must perform no network I/O");
    assert!(!f.driver.needs_credentials());
    assert_eq!(f.driver.next_wake_ns(), Some(deadline));
    assert!(f.driver.pending_checkpoint().is_none());
    let retired = f.driver.cancel().ok_or("missing retirement")?;
    assert!(retired.live.recording.is_some());
    assert!(retired.live.archive.ok_or("archive retirement missing")?.pending.is_none());
    drop(f);
    assert_eq!(p.visible_roots().count(), 0);
    Ok(())
}

#[test]
fn a_completed_invalid_suffix_stops_the_archive_without_issuing_setup() -> Test {
    let mut p = publisher()?;
    let mut f = Fixture::new(&mut p)?;
    f.defer()?;
    let sent = f.driver.totals().ok_or("totals missing")?.sent_bytes;
    f.peer.write_all(b"0 200 OK\r\nCSeq: 99\r\nContent-Length: 0\r\n\r\n")?;
    let mut stopped = false;
    for _ in 0..1024 {
        let step = f.poll(true, 3)?;
        assert!(!matches!(step, Step::Queued(_)));
        if let Step::Archive(Progress::Stopped { retained, trigger }) = step {
            assert!(matches!(trigger.as_ref(), LiveRecordingStep::Stopped { .. }));
            assert!(retained.live.archive.ok_or("archive retirement missing")?.snapshot.windows().is_empty());
            stopped = true;
            break;
        }
        assert_eq!(f.driver.totals().ok_or("premature transport retirement")?.sent_bytes, sent);
        std::thread::yield_now();
    }
    assert!(stopped);
    assert!(!f.driver.needs_credentials());
    assert_eq!(f.driver.next_wake_ns(), None);
    assert!(f.driver.cancel().is_none());
    drop(f);
    assert_eq!(p.visible_roots().count(), 0);
    Ok(())
}

#[test]
fn deferred_control_preserves_revocation_and_storage_cancellation() -> Test {
    for revoke in [false, true] {
        let mut p = publisher()?;
        let mut f = Fixture::new(&mut p)?;
        f.defer()?;
        f.authority.revoked.set(revoke);
        let cancel: &dyn PublishCancellation = if revoke { &NeverCancel } else { &Cancel };
        let error = f.driver.poll(SocketReadiness::default(), &credentials()?, [1; 16],
            3, &f.authority, cancel).err().ok_or("denied archive continued")?;
        if revoke {
            assert!(matches!(error.reason, LiveArchiveError::Authority(TcpDenial::Revoked)));
        } else {
            assert!(matches!(error.reason, LiveArchiveError::Archive(ArchiveError::Cancelled)));
        }
        let retired = error.retirement.ok_or("fatal retirement missing")?;
        assert!(retired.live.recording.is_some());
        assert!(retired.live.archive.is_some());
        assert!(retired.pending_checkpoint.is_none());
        assert!(!f.driver.needs_credentials());
        assert_eq!(f.driver.next_wake_ns(), None);
        assert!(f.driver.cancel().is_none());
        drop(f);
        assert_eq!(p.visible_roots().count(), 0);
    }
    Ok(())
}
