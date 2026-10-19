#![forbid(unsafe_code)]
#![feature(tcp_linger)]
//! Actual loopback TCP resets through the public journaled AVC capture owner.
//! No synthetic error injection, external camera, subprocess or wall-clock sleep.

mod recording_support;

use fss_core::ContentDigest;
use fss_ledger::IncompleteTailPolicy;
use fss_object::SpoolLimits;
use fss_packet::{StreamKey, avc::AvcReceiveLimits};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel};
use fss_reference::rtsp::archive_pins::live::{
    JournaledLiveArchiveError, JournaledLiveArchiveStep, JournaledLiveAvcArchive,
};
use fss_reference::rtsp::archive_pins::{
    ArchivePinJournal, ArchivePinLimits, ArchivePinScope, JournaledArchiveProgress,
};
use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};
use fss_reference::rtsp::client::{ClientCommand, ClientConfig, ClientState};
use fss_reference::rtsp::live_archive::{LiveArchiveConfig, LiveArchiveError, LiveArchiveStep};
use fss_reference::rtsp::live_avc::recording::{
    LiveRecordingConfig, LiveRecordingError, LiveRecordingStep,
};
use fss_reference::rtsp::live_avc::{LiveAvcConfig, LiveAvcError, LiveAvcStep, SocketReadiness};
use fss_reference::rtsp::recording::{MAX_RECORDING_BYTES, local::load_recording};
use fss_reference::rtsp::recording_archive::checkpoint::ArchiveWorkLimits;
use fss_reference::rtsp::recording_archive::{
    ArchiveLimits, ArchiveNamespace, ArchiveWriteProgress,
};
use fss_reference::rtsp::recording_capture::CapturePoll;
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_collector::{CollectorLimits, RecordingTiming};
use fss_reference::rtsp::tcp::{
    TcpAuthority, TcpBinding, TcpDenial, TcpError, TcpLimits, TcpOperation, TcpSecurityPolicy,
    TcpWriteStep,
};
use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const LEASE: u64 = 100_000_000_000;
const START: u64 = LEASE - 1_000_000;
const KEY: StreamKey = StreamKey {
    ingress: 71,
    generation: 1,
    ssrc: 7,
};
const SDP: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\na=control:trackID=0\r\n";
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        for _ in 0..256 {
            let path = std::env::temp_dir().join(format!(
                "fss-real-read-reset-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory bound".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn storage() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        128,
        1024,
        128,
        1024,
        SpoolLimits::new(1024, 16 * 1024 * 1024, 2 * 1024 * 1024, 1024),
    )
}
fn namespace() -> Test<ArchiveNamespace> {
    Ok(ArchiveNamespace::new(CatalogScope {
        recording: recording_support::scope()?,
        decode_clock: ContentDigest::sha256(b"reset fixture decode clock"),
        time_scale: 90_000,
    })?)
}
fn pin_scope() -> Test<ArchivePinScope> {
    Ok(ArchivePinScope {
        journal_id: ContentDigest::sha256(b"reset fixture independent pins"),
        archive_namespace: namespace()?.digest(),
    })
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
        deadline: u64,
    ) -> Result<(), TcpDenial> {
        self.checks.set(self.checks.get() + 1);
        if binding != &self.binding {
            return Err(TcpDenial::Unauthorized);
        }
        if self.revoked.get() {
            return Err(TcpDenial::Revoked);
        }
        if deadline != LEASE || now >= deadline {
            return Err(TcpDenial::Deadline);
        }
        Ok(())
    }
}
struct Fixture<'a, 'p> {
    driver: JournaledLiveAvcArchive<'a, 'p>,
    peer: Option<TcpStream>,
    authority: Authority,
}
impl<'a, 'p> Fixture<'a, 'p> {
    fn new(
        publisher: &'a mut LocalRootPublisher,
        pins: &'p mut ArchivePinJournal,
        chunk: usize,
    ) -> Test<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let binding = TcpBinding::new(
            KEY,
            listener.local_addr()?,
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
                response_timeout_ns: 1_000_000_000,
                default_session_timeout_seconds: 60,
            },
            binding,
            transport: TcpLimits {
                chunk_bytes: chunk,
                ..TcpLimits::default()
            },
            media: AvcReceiveLimits::default(),
            realm: "fixture".into(),
            digest_policy: DigestPolicy::default(),
            deadline_ns: LEASE,
            max_steps: 100_000,
        };
        let recording = LiveRecordingConfig {
            scope: recording_support::scope()?,
            payload_type: 96,
            time_scale: 90_000,
            limits: CollectorLimits::default(),
        };
        let archive = LiveArchiveConfig {
            namespace: namespace()?,
            limits: ArchiveLimits {
                max_windows: 8,
                max_pages: 8,
                max_scan_roots: 128,
                windows_per_page: 4,
            },
            max_window_bytes: MAX_RECORDING_BYTES,
            max_steps: 100_000,
            publication_deadline_ns: 2 * LEASE,
            max_storage_pause_ns: 1_000_000_000,
        };
        let driver = JournaledLiveAvcArchive::connect(
            live,
            recording,
            archive,
            ArchiveWorkLimits::default(),
            publisher,
            pins,
            START,
            &authority,
            &NeverCancel,
        )?;
        let (peer, _) = listener.accept()?;
        peer.set_read_timeout(Some(Duration::from_secs(2)))?;
        peer.set_write_timeout(Some(Duration::from_secs(2)))?;
        peer.set_nodelay(true)?;
        let mut f = Self {
            driver,
            peer: Some(peer),
            authority,
        };
        assert!(matches!(
            f.poll(START)?,
            JournaledLiveArchiveStep::Live(LiveArchiveStep::Archive(
                ArchiveWriteProgress::Ready { .. }
            ))
        ));
        for (command, headers, body) in [
            (
                ClientCommand::Describe,
                "Content-Type: application/sdp\r\n",
                SDP,
            ),
            (
                ClientCommand::Setup,
                "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n",
                "",
            ),
            (ClientCommand::Play, "Session: fixture\r\n", ""),
        ] {
            let credentials = DigestCredentials::new("unused", "")?;
            let request = f.driver.request(
                command,
                &credentials,
                [0; 16],
                START,
                &f.authority,
                &NeverCancel,
            )?;
            let mut sent = false;
            for _ in 0..32_768 {
                if let JournaledLiveArchiveStep::Live(LiveArchiveStep::Recording(step)) =
                    f.poll(START)?
                    && matches!(
                        *step,
                        LiveRecordingStep::Network(LiveAvcStep::Write(TcpWriteStep::Sent { .. }))
                    )
                {
                    sent = true;
                    break;
                }
            }
            assert!(sent, "request did not finish in its work bound");
            f.peer
                .as_mut()
                .ok_or("peer")?
                .read_exact(&mut vec![0; request.bytes])?;
            let reply = format!(
                "RTSP/1.0 200 OK\r\nCSeq: {}\r\nContent-Length: {}\r\n{headers}\r\n{body}",
                request.cseq,
                body.len()
            );
            f.receive(reply.as_bytes(), false)?;
        }
        assert_eq!(f.driver.state(), ClientState::Playing);
        Ok(f)
    }
    fn poll(
        &mut self,
        now: u64,
    ) -> Result<
        JournaledLiveArchiveStep,
        fss_reference::rtsp::archive_pins::live::JournaledLiveFailure,
    > {
        self.driver.poll(
            SocketReadiness {
                readable: true,
                writable: true,
            },
            now,
            &self.authority,
            &NeverCancel,
        )
    }
    fn receive(&mut self, bytes: &[u8], picture: bool) -> Test {
        self.peer.as_mut().ok_or("peer")?.write_all(bytes)?;
        let mut received = 0;
        for _ in 0..32_768 {
            match self.poll(START)? {
                JournaledLiveArchiveStep::Live(LiveArchiveStep::Recording(step)) => match *step {
                    LiveRecordingStep::Network(LiveAvcStep::Wire(chunk)) => {
                        received += chunk.expose().len()
                    }
                    LiveRecordingStep::Capture { event, .. }
                        if matches!(*event, CapturePoll::TimingRequired(_)) =>
                    {
                        assert!(picture);
                        let _ = self.driver.supply_timing(
                            RecordingTiming {
                                decode_time: 700,
                                duration: 3600,
                                composition_offset: 0,
                            },
                            START,
                            &self.authority,
                            &NeverCancel,
                        )?;
                        return Ok(());
                    }
                    LiveRecordingStep::Network(LiveAvcStep::Pending(wait))
                        if !picture
                            && received == bytes.len()
                            && wait.wake_at_ns.is_none_or(|at| at > START) =>
                    {
                        return Ok(());
                    }
                    _ => {}
                },
                _ => return Err("unexpected archive progress before reset".into()),
            }
            std::thread::yield_now();
        }
        Err("receive work bound".into())
    }
    fn picture(&mut self, fragmented: bool) -> Test {
        let fixture = recording_support::fixture(KEY.ingress, fragmented)?;
        let mut bytes = Vec::new();
        let mut probation = fixture.packets.first().ok_or("probation")?.2.clone();
        probation[2..4].copy_from_slice(&0_u16.to_be_bytes());
        for packet in std::iter::once(&probation).chain(fixture.packets.iter().map(|p| &p.2)) {
            bytes.extend_from_slice(&[b'$', 0]);
            bytes.extend_from_slice(&u16::try_from(packet.len())?.to_be_bytes());
            bytes.extend_from_slice(packet);
        }
        self.receive(&bytes, true)
    }
    fn reset(&mut self) -> Test {
        let peer = self.peer.take().ok_or("peer")?;
        // SO_LINGER=0 produces an actual TCP RST, not a clean EOF or injected error.
        peer.set_linger(Some(Duration::ZERO))?;
        drop(peer);
        Ok(())
    }
}

#[test]
fn real_tcp_reset_preserves_the_prefix_through_both_journals_and_cold_reopening() -> Test {
    for chunk in [7, 4096] {
        for fragmented in [false, true] {
            let directory = Directory::new()?;
            let mut publisher = LocalRootPublisher::open(directory.0.join("media"), storage())?;
            let mut pins = ArchivePinJournal::create(
                directory.0.join("pins"),
                pin_scope()?,
                ArchivePinLimits::default(),
                &NeverCancel,
            )?;
            let mut f = Fixture::new(&mut publisher, &mut pins, chunk)?;
            f.picture(fragmented)?;
            f.reset()?;
            let mut admission = None;
            for _ in 0..32_768 {
                match f.poll(START)? {
                    JournaledLiveArchiveStep::Live(LiveArchiveStep::WindowAccepted(a)) => {
                        admission = Some(a);
                        break;
                    }
                    JournaledLiveArchiveStep::Live(LiveArchiveStep::Recording(step))
                        if matches!(*step, LiveRecordingStep::Network(LiveAvcStep::Pending(_))) =>
                    {
                        std::thread::yield_now()
                    }
                    _ => return Err("reset did not admit its verified prefix".into()),
                }
            }
            let admission = admission.ok_or("read reset admission work bound")?;
            let expected = f.driver.pending().ok_or("verified prefix")?;
            let source = expected.objects().source.to_vec();
            let media = expected.objects().media.to_vec();
            let mut boundaries = Vec::new();
            let mut terminal = None;
            f.authority.revoked.set(true);
            let checks = f.authority.checks.get();
            for _ in 0..64 {
                // Real source has already retired. Its expired/revoked network lease
                // cannot consume the separately authorized storage-drain allowance.
                match f.poll(LEASE + 1) {
                    Ok(JournaledLiveArchiveStep::Checkpoint(progress)) => match *progress {
                        JournaledArchiveProgress::PinPersisted { .. } => {
                            boundaries.push("candidate")
                        }
                        JournaledArchiveProgress::WorkConfirmed { .. } => {
                            boundaries.push("confirmed")
                        }
                        _ => return Err("unexpected checkpoint result".into()),
                    },
                    Ok(JournaledLiveArchiveStep::Live(LiveArchiveStep::Archive(progress))) => {
                        match progress {
                            ArchiveWriteProgress::WindowDurable { .. } => boundaries.push("window"),
                            ArchiveWriteProgress::CatalogPublished { .. } => {
                                boundaries.push("catalog")
                            }
                            ArchiveWriteProgress::Finished {
                                windows: 1,
                                pages: 1,
                                ..
                            } => boundaries.push("snapshot"),
                            _ => {}
                        }
                    }
                    Err(error) => {
                        terminal = Some(error);
                        break;
                    }
                    Ok(_) => {
                        return Err(
                            "read reset became EOF, new intake or successful capture".into()
                        );
                    }
                }
            }
            assert_eq!(
                boundaries,
                [
                    "candidate",
                    "confirmed",
                    "window",
                    "candidate",
                    "confirmed",
                    "catalog",
                    "snapshot"
                ]
            );
            assert_eq!(f.authority.checks.get(), checks);
            let error = terminal.ok_or("missing original terminal read error")?;
            assert!(
                matches!(error.reason, JournaledLiveArchiveError::Live(LiveArchiveError::Recording(ref reason)) if matches!(**reason,
                LiveRecordingError::Network(LiveAvcError::Transport(TcpError::Io { operation: TcpOperation::Read, kind: std::io::ErrorKind::ConnectionReset }))))
            );
            let retired = error.retirement.ok_or("retired ownership")?;
            let anchor = retired.journal_anchor;
            assert!(retired.pins.candidate().is_none());
            let original = retired
                .live
                .live
                .recording
                .as_ref()
                .ok_or("original source")?;
            assert!(
                !original
                    .connection
                    .as_ref()
                    .ok_or("original connection")?
                    .transport
                    .totals
                    .peer_eof
            );
            assert!(original.capture.collection.pending.pictures.is_empty());
            assert!(
                retired
                    .live
                    .live
                    .archive
                    .as_ref()
                    .ok_or("archive")?
                    .pending
                    .is_none()
            );
            assert!(f.driver.cancel().is_none());
            drop(f);
            drop(pins);
            drop(publisher);
            let publisher = LocalRootPublisher::open(directory.0.join("media"), storage())?;
            let mut pins = ArchivePinJournal::open_existing(
                directory.0.join("pins"),
                pin_scope()?,
                Some(anchor),
                ArchivePinLimits::default(),
                IncompleteTailPolicy::Reject,
                &NeverCancel,
            )?;
            pins.require_settled(&publisher, ArchiveWorkLimits::default(), &NeverCancel)?;
            let recording = load_recording(
                &publisher,
                &admission.slot,
                admission.root,
                &recording_support::scope()?,
                &NeverCancel,
            )?;
            assert_eq!(recording.objects().source, source);
            assert_eq!(recording.objects().media, media);
        }
    }
    Ok(())
}

#[test]
fn real_tcp_reset_without_a_completed_picture_never_manufactures_a_window() -> Test {
    let directory = Directory::new()?;
    let mut publisher = LocalRootPublisher::open(directory.0.join("media"), storage())?;
    let mut pins = ArchivePinJournal::create(
        directory.0.join("pins"),
        pin_scope()?,
        ArchivePinLimits::default(),
        &NeverCancel,
    )?;
    let mut f = Fixture::new(&mut publisher, &mut pins, 4096)?;
    f.reset()?;
    let mut terminal = false;
    for _ in 0..32_768 {
        match f.poll(START) {
            Err(error) => {
                let retired = error.retirement.ok_or("original retirement")?;
                let archive = retired.live.live.archive.ok_or("archive")?;
                assert!(archive.pending.is_none());
                assert!(archive.snapshot.windows().is_empty());
                assert_eq!(retired.journal_anchor.sequence, 1);
                terminal = true;
                break;
            }
            Ok(JournaledLiveArchiveStep::Live(LiveArchiveStep::Recording(step)))
                if matches!(*step, LiveRecordingStep::Network(LiveAvcStep::Pending(_))) =>
            {
                std::thread::yield_now()
            }
            _ => return Err("empty reset manufactured media or a completion claim".into()),
        }
    }
    assert!(terminal);
    drop(f);
    assert_eq!(publisher.visible_roots().count(), 0);
    Ok(())
}
