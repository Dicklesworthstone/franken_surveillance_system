#![forbid(unsafe_code)]
//! Real native TCP -> selected HEVC -> protected archive and cold original-source replay.
//! Synthetic media and an injected owner clock; no wall-clock deadline races or camera claims.

mod hevc_recording_support;

use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fss_core::ContentDigest;
use fss_object::SpoolLimits;
use fss_packet::hevc::{
    HevcAssemblyLimits, HevcBoundary, HevcConfiguration, HevcConfigurationLimits,
};
use fss_packet::{H265Limits, ReorderLimits, StreamKey};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel};
use fss_reference::rtsp::archive_pins::{
    ArchivePinLimits, ArchivePinScope, HevcArchivePinJournal, JournaledArchiveProgress,
};
use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};
use fss_reference::rtsp::client::{ClientCommand, ClientConfig, ClientProgress, ClientState};
use fss_reference::rtsp::hevc_client::{HevcClientPoll, pictures::HevcPictureClientPoll as Event};
use fss_reference::rtsp::hevc_recording_capture::live::{
    AutomaticHevcRecordingStep as RecordingStep, LiveHevcRecordingConfig,
};
use fss_reference::rtsp::hevc_recording_capture::{
    HevcCapturePoll, HevcPictureTimingRequest, TimedHevcCapture,
};
use fss_reference::rtsp::hevc_recording_collector::{HevcCollectionAdmission, HevcCollectionSeal};
use fss_reference::rtsp::live_archive::LiveArchiveCompletion;
use fss_reference::rtsp::live_hevc::{
    LiveHevcConfig, LiveHevcStep, QueuedHevcRequest, SocketReadiness,
};
use fss_reference::rtsp::live_hevc_archive::{
    JournaledLiveHevcArchive, LiveHevcArchiveConfig, LiveHevcArchiveError, LiveHevcArchiveFailure,
    LiveHevcArchiveStep as Step, SelectedHevcRecordingConfig,
};
use fss_reference::rtsp::recording::MAX_RECORDING_BYTES;
use fss_reference::rtsp::recording::hevc::local::load_hevc_recording;
use fss_reference::rtsp::recording_archive::checkpoint::{
    ArchiveWorkLimits, load_hevc_archive_work,
};
use fss_reference::rtsp::recording_archive::hevc::{HevcArchiveNamespace, HevcArchiveSnapshot};
use fss_reference::rtsp::recording_archive::{
    ArchiveAdmission, ArchiveLimits, ArchiveWriteProgress,
};
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_collector::{CollectionStop, CollectorLimits};
use fss_reference::rtsp::tcp::{
    TcpAuthority, TcpBinding, TcpDenial, TcpLimits, TcpOperation, TcpSecurityPolicy, TcpWriteStep,
};
use hevc_recording_support::*;

type Test<T = ()> = Result<T, Error>;
const LEASE: u64 = 100_000_000_000;
const START: u64 = LEASE - 1_000_000;
const KEY: StreamKey = StreamKey {
    ingress: 1,
    generation: 1,
    ssrc: SSRC,
};
static NEXT: AtomicU64 = AtomicU64::new(0);

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
fn store_limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        64,
        512,
        64,
        512,
        SpoolLimits::new(512, 64 * 1024 * 1024, 2 * 1024 * 1024, 1024),
    )
}
fn archive_limits() -> ArchiveLimits {
    ArchiveLimits {
        max_windows: 8,
        max_pages: 8,
        max_scan_roots: 256,
        windows_per_page: 2,
    }
}
fn selected() -> Test<SelectedHevcRecordingConfig> {
    Ok(SelectedHevcRecordingConfig {
        scope: scope()?,
        payload_type: PT,
        time_scale: 90_000,
        limits: CollectorLimits::default(),
        configuration_limits: HevcConfigurationLimits::default(),
    })
}
struct Stores {
    root: PathBuf,
    publisher: LocalRootPublisher,
    pins: HevcArchivePinJournal,
    namespace: HevcArchiveNamespace,
}
impl Stores {
    fn new() -> Test<Self> {
        let parent = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("live-hevc-archive");
        std::fs::create_dir_all(&parent)?;
        for _ in 0..256 {
            let path = parent.join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    let root = path.join("archive");
                    let publisher = LocalRootPublisher::open(&root, store_limits())?;
                    let namespace = HevcArchiveNamespace::new(CatalogScope {
                        recording: scope()?,
                        decode_clock: ContentDigest::sha256(b"explicit HEVC archive test clock"),
                        time_scale: 90_000,
                    })?;
                    let pins = HevcArchivePinJournal::create(
                        path.join("pins"),
                        ArchivePinScope {
                            journal_id: ContentDigest::sha256(
                                b"independent HEVC archive test journal",
                            ),
                            archive_namespace: namespace.digest(),
                        },
                        ArchivePinLimits::default(),
                        &NeverCancel,
                    )?;
                    return Ok(Self {
                        root,
                        publisher,
                        pins,
                        namespace,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("fixture directory bound".into())
    }
}
fn ready() -> SocketReadiness {
    SocketReadiness {
        readable: true,
        writable: true,
    }
}
fn response(cseq: u32, headers: &str, body: &str) -> Vec<u8> {
    format!(
        "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len()
    )
    .into_bytes()
}
fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for part in bytes.chunks(3) {
        let value = (u32::from(part[0]) << 16)
            | (u32::from(*part.get(1).unwrap_or(&0)) << 8)
            | u32::from(*part.get(2).unwrap_or(&0));
        out.push(TABLE[((value >> 18) & 63) as usize] as char);
        out.push(TABLE[((value >> 12) & 63) as usize] as char);
        out.push(if part.len() > 1 {
            TABLE[((value >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if part.len() > 2 {
            TABLE[(value & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}
fn sdp() -> Test<String> {
    let n = nals()?;
    Ok(format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 98\r\na=rtpmap:98 H265/90000\r\na=fmtp:98 sprop-vps={};sprop-sps={};sprop-pps={}\r\na=control:track\r\n",
        base64(&n[0]),
        base64(&n[1]),
        base64(&n[2])
    ))
}
fn interleaved(packet: &[u8]) -> Test<Vec<u8>> {
    let mut out = vec![b'$', 0];
    out.extend_from_slice(&u16::try_from(packet.len())?.to_be_bytes());
    out.extend_from_slice(packet);
    Ok(out)
}
fn input(count: usize) -> Test<Vec<u8>> {
    let mut wire = interleaved(&packet(0, 0, false, &nals()?[0]).bytes)?;
    for (i, mut p) in packets()?.into_iter().take(count).enumerate() {
        p.bytes[2..4].copy_from_slice(&u16::try_from(i + 1)?.to_be_bytes());
        wire.extend_from_slice(&interleaved(&p.bytes)?);
    }
    Ok(wire)
}

struct Fixture<'a> {
    driver: JournaledLiveHevcArchive<'a, 'a>,
    peer: TcpStream,
    authority: Authority,
    now: u64,
    nonce: u128,
    originals: Vec<RecordingStep>,
    timed: Vec<TimedHevcCapture>,
    seals: Vec<HevcCollectionSeal>,
}
impl<'a> Fixture<'a> {
    fn new(stores: &'a mut Stores, recording: SelectedHevcRecordingConfig) -> Test<Fixture<'a>> {
        Self::configured(stores, recording, None)
    }
    fn configured(
        stores: &'a mut Stores,
        recording: SelectedHevcRecordingConfig,
        configuration: Option<HevcConfiguration>,
    ) -> Test<Fixture<'a>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let binding = TcpBinding::new(
            KEY,
            listener.local_addr()?,
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
            transport: TcpLimits::default(),
            reorder: ReorderLimits::default(),
            reconstruction: H265Limits::default(),
            assembly: HevcAssemblyLimits::default(),
            realm: "test-realm".into(),
            digest_policy: DigestPolicy::default(),
            deadline_ns: LEASE,
            max_steps: 200_000,
        };
        let archive = LiveHevcArchiveConfig {
            namespace: stores.namespace.clone(),
            limits: archive_limits(),
            max_window_bytes: MAX_RECORDING_BYTES,
            max_steps: 200_000,
            publication_deadline_ns: LEASE + 10_000_000_000,
            max_storage_pause_ns: 5_000_000_000,
        };
        let driver = if let Some(configuration) = configuration {
            JournaledLiveHevcArchive::connect_with_configuration(
                live,
                LiveHevcRecordingConfig {
                    scope: recording.scope,
                    payload_type: recording.payload_type,
                    configuration,
                    time_scale: recording.time_scale,
                    limits: recording.limits,
                },
                archive,
                ArchiveWorkLimits::default(),
                &mut stores.publisher,
                &mut stores.pins,
                START,
                &authority,
                &NeverCancel,
            )?
        } else {
            JournaledLiveHevcArchive::connect(
                live,
                recording,
                archive,
                ArchiveWorkLimits::default(),
                &mut stores.publisher,
                &mut stores.pins,
                START,
                &authority,
                &NeverCancel,
            )?
        };
        let (peer, _) = listener.accept()?;
        peer.set_read_timeout(Some(Duration::from_secs(2)))?;
        peer.set_write_timeout(Some(Duration::from_secs(2)))?;
        peer.set_nodelay(true)?;
        let mut fixture = Fixture {
            driver,
            peer,
            authority,
            now: START,
            nonce: 0,
            originals: Vec::new(),
            timed: Vec::new(),
            seals: Vec::new(),
        };
        let Step::Archive(progress) = fixture.poll(SocketReadiness::default())? else {
            return Err("new archive must drain its initial storage state before DESCRIBE".into());
        };
        assert!(matches!(
            *progress,
            JournaledArchiveProgress::Archive(ArchiveWriteProgress::Ready {
                durable_windows: 0,
                ..
            })
        ));
        assert!(fixture.driver.needs_credentials());
        Ok(fixture)
    }
    fn tick(&mut self) -> u64 {
        self.now += 1;
        self.now
    }
    fn poll(&mut self, readiness: SocketReadiness) -> Result<Step, LiveHevcArchiveFailure> {
        let nonce = if self.driver.needs_credentials() {
            self.nonce += 1;
            self.nonce.to_be_bytes()
        } else {
            [0; 16]
        };
        let now = self.tick();
        // These fixture credentials are explicitly owned. Production obtains them from the
        // separately authorized credential-file lease only when the driver requests them.
        let credentials = DigestCredentials::new("test-user", "test-password").map_err(|_| {
            LiveHevcArchiveFailure {
                reason: LiveHevcArchiveError::Configuration,
                retirement: None,
            }
        })?;
        self.driver.poll(
            readiness,
            &credentials,
            nonce,
            now,
            &self.authority,
            &NeverCancel,
        )
    }
    fn command(&mut self) -> Test<(QueuedHevcRequest, Vec<u8>)> {
        assert!(self.driver.needs_credentials());
        let Step::Recording(step) = self.poll(SocketReadiness::default())? else {
            return Err("automatic request missing".into());
        };
        let RecordingStep::Queued(queued) = *step else {
            return Err("automatic request missing".into());
        };
        for _ in 0..32_768 {
            let Step::Recording(step) = self.poll(SocketReadiness {
                readable: false,
                writable: true,
            })?
            else {
                return Err("storage unexpectedly interrupted a queued control request".into());
            };
            if let RecordingStep::Network(LiveHevcStep::Write(TcpWriteStep::Sent { cseq, bytes })) =
                *step
            {
                assert_eq!((cseq, bytes), (queued.cseq, queued.bytes));
                let mut wire = vec![0; bytes];
                self.peer.read_exact(&mut wire)?;
                return Ok((queued, wire));
            }
            self.originals.push(*step);
        }
        Err("command dispatch bound".into())
    }
    fn reply(&mut self, bytes: &[u8], expected: ClientState) -> Test {
        self.peer.write_all(bytes)?;
        for _ in 0..32_768 {
            let Step::Recording(step) = self.poll(ready())? else {
                return Err("control response became archive work".into());
            };
            let found = match step.as_ref() {
                RecordingStep::Capture {
                    event,
                    connection: None,
                } => matches!(event.as_ref(),
                    HevcCapturePoll::Receiver(source) if matches!(source.as_ref(), Event::Client { event, work: None }
                        if matches!(event.as_ref(), HevcClientPoll::Control { progress: ClientProgress::Accepted(s), .. } if *s == expected))),
                _ => false,
            };
            self.originals.push(*step);
            if found {
                return Ok(());
            }
            std::thread::yield_now();
        }
        Err("control response bound".into())
    }
    fn play(&mut self) -> Test {
        self.play_description(&sdp()?)
    }
    fn play_description(&mut self, description: &str) -> Test {
        let (describe, wire) = self.command()?;
        assert_eq!(describe.command, ClientCommand::Describe);
        assert!(!std::str::from_utf8(&wire)?.contains("Authorization:"));
        self.reply(
            &response(
                describe.cseq,
                "Content-Type: application/sdp\r\n",
                description,
            ),
            ClientState::Described,
        )?;
        let (setup, _) = self.command()?;
        assert_eq!(setup.command, ClientCommand::Setup);
        self.reply(&response(setup.cseq, "Session: test-session;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n", ""), ClientState::Ready)?;
        let (play, _) = self.command()?;
        assert_eq!(play.command, ClientCommand::Play);
        self.reply(
            &response(play.cseq, "Session: test-session\r\n", ""),
            ClientState::Playing,
        )
    }
    fn next_timing(&mut self) -> Test<HevcPictureTimingRequest> {
        for _ in 0..32_768 {
            let Step::Recording(step) = self.poll(ready())? else {
                return Err("window or fault before expected picture".into());
            };
            if let RecordingStep::Capture {
                event,
                connection: None,
            } = step.as_ref()
                && let HevcCapturePoll::TimingRequired(request) = event.as_ref()
            {
                return Ok(*request);
            }
            self.originals.push(*step);
            std::thread::yield_now();
        }
        Err("picture progress bound".into())
    }
    fn two_picture_window(&mut self) -> Test<ArchiveAdmission> {
        self.play()?;
        // A real next VPS closes picture two; the RTP marker alone is not used as a witness.
        self.peer.write_all(&input(6)?)?;
        for i in 0..2 {
            let request = self.next_timing()?;
            assert_eq!(request.rtp_timestamp, i as u32 * 18_000);
            assert_ne!(request.boundary, HevcBoundary::EndOfInputUnverified);
            let now = self.tick();
            let timed =
                self.driver
                    .supply_timing(timings(2)[i], now, &self.authority, &NeverCancel)?;
            assert!(matches!(
                timed.admission,
                HevcCollectionAdmission::Accepted { .. }
            ));
            self.timed.push(timed);
        }
        let now = self.tick();
        let seal = self.driver.seal(now, &self.authority, &NeverCancel)?;
        assert!(seal.window_ready);
        self.seals.push(seal);
        match self.poll(SocketReadiness::default())? {
            Step::WindowAccepted(admission) => Ok(admission),
            _ => Err("sealed completed prefix was not admitted".into()),
        }
    }
}

#[test]
fn owner_stop_at_final_admission_closes_tcp_before_checkpoint_and_drains_past_live_lease() -> Test {
    let mut stores = Stores::new()?;
    let root = stores.root.clone();
    let namespace = stores.namespace.clone();
    let mut f = Fixture::new(&mut stores, selected()?)?;
    let admitted = f.two_picture_window()?;
    let pending = f.driver.pending().ok_or("pending window")?;
    assert_eq!(pending.samples().len(), 2);
    assert_eq!(pending.source_only_nals(), 1);
    let source = ContentDigest::sha256(pending.objects().source);
    assert_eq!(f.driver.snapshot().ok_or("snapshot")?.windows().len(), 0);
    assert_eq!(f.driver.journal_anchor().sequence, 1); // only genesis; no checkpoint I/O yet
    assert!(f.driver.pin_state().candidate().is_none());
    let now = f.tick();
    let retired = f
        .driver
        .finish_capture(now, &f.authority, &NeverCancel)?
        .ok_or("input retirement")?;
    assert!(
        !retired
            .connection
            .as_ref()
            .ok_or("connection retirement")?
            .transport
            .totals
            .peer_eof
    );
    assert_eq!(
        retired
            .capture
            .as_ref()
            .ok_or("collector retirement")?
            .collection
            .pictures
            .len(),
        0
    );
    assert_eq!(f.driver.state(), ClientState::Closed);
    assert!(f.driver.totals().is_none());
    assert!(!f.driver.needs_credentials());
    assert_eq!(f.peer.read(&mut [0_u8; 1])?, 0); // real TCP closure, before first protected write
    assert!(
        !f.originals
            .iter()
            .any(|s| matches!(s, RecordingStep::Network(LiveHevcStep::InputEnded)))
    );
    f.authority.revoked.set(true);
    let checks = f.authority.checks.get();
    f.now = LEASE + 1;
    let mut order = Vec::new();
    let mut finished = false;
    for _ in 0..128 {
        match f.poll(ready())? {
            Step::Archive(progress) => match *progress {
                JournaledArchiveProgress::PinPersisted { .. } => order.push("pin"),
                JournaledArchiveProgress::WorkConfirmed { .. } => order.push("work"),
                JournaledArchiveProgress::Archive(ArchiveWriteProgress::WindowDurable {
                    receipt,
                    ..
                }) => {
                    assert_eq!(receipt.root, admitted.root);
                    order.push("window");
                }
                JournaledArchiveProgress::Archive(ArchiveWriteProgress::CatalogPublished {
                    windows,
                    ..
                }) => {
                    assert_eq!(windows, 1);
                    order.push("catalog");
                }
                _ => {}
            },
            Step::Finished {
                archive:
                    ArchiveWriteProgress::Finished {
                        windows: 1,
                        pages: 1,
                        ..
                    },
                cause: LiveArchiveCompletion::OwnerStopped,
            } => {
                finished = true;
                break;
            }
            _ => return Err("drain attempted capture or lost owner-stop cause".into()),
        }
    }
    assert!(finished);
    assert_eq!(order, ["pin", "work", "window", "pin", "work", "catalog"]);
    assert_eq!(f.authority.checks.get(), checks); // storage drain never re-probed the retired TCP lease
    assert_eq!(f.driver.snapshot().ok_or("snapshot")?.indexed_windows(), 1);
    assert!(f.driver.pin_state().last_confirmed().is_some());
    assert!(f.driver.pin_state().candidate().is_none());
    drop(f);
    drop(stores);
    let publisher = LocalRootPublisher::open(&root, store_limits())?;
    let loaded = load_hevc_recording(
        &publisher,
        &admitted.slot,
        admitted.root,
        &scope()?,
        &NeverCancel,
    )?;
    assert_eq!(loaded.samples().len(), 2);
    assert_eq!(loaded.source_only_nals(), 1);
    assert_eq!(ContentDigest::sha256(loaded.objects().source), source);
    let packets = loaded.packets()?;
    assert_eq!(packets.len(), 6);
    assert_eq!(
        packets.last().ok_or("closing source witness")?.bytes,
        packet(6, 36_000, true, &nals()?[5]).bytes
    );
    let snapshot =
        HevcArchiveSnapshot::load(&publisher, namespace, archive_limits(), &NeverCancel)?;
    assert_eq!(
        (
            snapshot.windows().len(),
            snapshot.indexed_windows(),
            snapshot.pages().len()
        ),
        (1, 1, 1)
    );
    Ok(())
}

#[test]
fn eof_seal_retires_live_grant_before_final_admission_and_preserves_protected_source() -> Test {
    eof_after_final_seal(false)
}

#[test]
fn explicit_tuple_without_sdp_parameters_preserves_eof_drain_and_exact_source() -> Test {
    eof_after_final_seal(true)
}

fn eof_after_final_seal(explicit: bool) -> Test {
    let mut stores = Stores::new()?;
    let root = stores.root.clone();
    let namespace = stores.namespace.clone();
    let mut f = Fixture::configured(
        &mut stores,
        selected()?,
        explicit.then(configuration).transpose()?,
    )?;
    if explicit {
        let description = sdp()?
            .split_inclusive("\r\n")
            .filter(|line| !line.starts_with("a=fmtp:"))
            .collect::<String>();
        assert!(!description.contains("sprop-"));
        f.play_description(&description)?;
    } else {
        f.play()?;
    }
    // The following P slice really closes the IDR, but its own marker/EOF cannot close it.
    f.peer.write_all(&input(5)?)?;
    f.peer.shutdown(Shutdown::Write)?;
    let request = f.next_timing()?;
    assert_eq!(request.rtp_timestamp, 0);
    assert_ne!(request.boundary, HevcBoundary::EndOfInputUnverified);
    let now = f.tick();
    let timed = f
        .driver
        .supply_timing(timings(1)[0], now, &f.authority, &NeverCancel)?;
    assert!(matches!(
        timed.admission,
        HevcCollectionAdmission::Accepted { .. }
    ));
    f.timed.push(timed);

    let mut eof = false;
    let mut unverified = false;
    let mut sealed = false;
    for _ in 0..32_768 {
        let Step::Recording(step) = f.poll(ready())? else {
            return Err("EOF prefix was admitted before its final seal".into());
        };
        match step.as_ref() {
            RecordingStep::Network(LiveHevcStep::InputEnded) => eof = true,
            RecordingStep::Capture { event, .. } => match event.as_ref() {
                HevcCapturePoll::Receiver(source) => {
                    if let Event::Ended {
                        tail: Some(tail), ..
                    } = source.as_ref()
                        && let Some(picture) = &tail.picture
                    {
                        assert_eq!(picture.boundary(), HevcBoundary::EndOfInputUnverified);
                        assert_eq!(picture.timestamp(), 18_000);
                        unverified = true;
                    }
                }
                HevcCapturePoll::Sealed(seal) => {
                    assert!(seal.window_ready);
                    sealed = true;
                }
                HevcCapturePoll::TimingRequired(_) | HevcCapturePoll::Window(_) => {
                    return Err("EOF promoted the unverified tail into a selected picture".into());
                }
                _ => {}
            },
            _ => {}
        }
        f.originals.push(*step);
        if sealed {
            break;
        }
        std::thread::yield_now();
    }
    assert!(eof && unverified && sealed);
    assert_eq!(f.driver.state(), ClientState::Closed);
    assert!(f.driver.totals().is_none());
    assert!(!f.driver.needs_credentials());
    assert_eq!(f.peer.read(&mut [0_u8; 1])?, 0);
    assert!(f.driver.pending().is_none());
    assert!(f.driver.snapshot().ok_or("snapshot")?.windows().is_empty());
    assert_eq!(f.driver.journal_anchor().sequence, 1);
    assert_eq!(f.driver.next_wake_ns(), Some(f.now));

    // Exercise the exact formerly broken boundary: EOF is known, but WindowAccepted and
    // its first pin/work checkpoint have not happened. No clock sleeps or lease race.
    f.authority.revoked.set(true);
    let checks = f.authority.checks.get();
    f.now = LEASE + 1;
    let Step::WindowAccepted(admitted) = f.poll(SocketReadiness::default())? else {
        return Err("sealed EOF prefix did not survive live grant retirement".into());
    };
    let pending = f.driver.pending().ok_or("pending EOF window")?;
    assert_eq!(pending.samples().len(), 1);
    assert_eq!(pending.source_only_nals(), 1);
    let source = ContentDigest::sha256(pending.objects().source);
    let witness = packet(5, 18_000, true, &nals()?[4]).bytes;
    assert_eq!(f.driver.journal_anchor().sequence, 1);
    let mut order = Vec::new();
    let mut capture_ended = false;
    let mut finished = false;
    for _ in 0..128 {
        match f.poll(ready())? {
            Step::Archive(progress) => match *progress {
                JournaledArchiveProgress::PinPersisted { .. } => order.push("pin"),
                JournaledArchiveProgress::WorkConfirmed { .. } => order.push("work"),
                JournaledArchiveProgress::Archive(ArchiveWriteProgress::WindowDurable {
                    receipt,
                    ..
                }) => {
                    assert_eq!(receipt.root, admitted.root);
                    order.push("window");
                }
                JournaledArchiveProgress::Archive(ArchiveWriteProgress::CatalogPublished {
                    windows,
                    ..
                }) => {
                    assert!(capture_ended);
                    assert_eq!(windows, 1);
                    order.push("catalog");
                }
                _ => {}
            },
            Step::Recording(step) => {
                let RecordingStep::Capture {
                    event,
                    connection: None,
                } = step.as_ref()
                else {
                    return Err("EOF storage drain resumed the retired connection".into());
                };
                let HevcCapturePoll::Ended {
                    retained: Some(retained),
                } = event.as_ref()
                else {
                    return Err("EOF final capture ownership was not transferred intact".into());
                };
                assert!(!capture_ended);
                assert_eq!(order, ["pin", "work", "window"]);
                assert_eq!(retained.collection.reason, CollectionStop::EndOfInput);
                assert!(retained.collection.ready.is_none());
                assert!(retained.collection.pictures.is_empty());
                assert!(
                    retained
                        .collection
                        .sources
                        .iter()
                        .any(|p| p.bytes() == witness)
                );
                capture_ended = true;
                f.originals.push(*step);
            }
            Step::Finished {
                archive:
                    ArchiveWriteProgress::Finished {
                        windows: 1,
                        pages: 1,
                        ..
                    },
                cause: LiveArchiveCompletion::InputEnded,
            } => {
                finished = true;
                break;
            }
            _ => {
                return Err(
                    "EOF drain lost the completed prefix or actual completion cause".into(),
                );
            }
        }
    }
    assert!(capture_ended && finished);
    assert_eq!(order, ["pin", "work", "window", "pin", "work", "catalog"]);
    assert_eq!(f.authority.checks.get(), checks);
    assert!(f.driver.pin_state().candidate().is_none());
    assert!(f.driver.pin_state().last_confirmed().is_some());
    drop(f);
    drop(stores);
    let publisher = LocalRootPublisher::open(&root, store_limits())?;
    let loaded = load_hevc_recording(
        &publisher,
        &admitted.slot,
        admitted.root,
        &scope()?,
        &NeverCancel,
    )?;
    assert_eq!(loaded.samples().len(), 1);
    assert_eq!(loaded.source_only_nals(), 1);
    assert_eq!(ContentDigest::sha256(loaded.objects().source), source);
    let packets = loaded.packets()?;
    assert_eq!(packets.len(), 5);
    assert_eq!(packets.last().ok_or("closing P witness")?.bytes, witness);
    let snapshot =
        HevcArchiveSnapshot::load(&publisher, namespace, archive_limits(), &NeverCancel)?;
    assert_eq!(
        (
            snapshot.windows().len(),
            snapshot.indexed_windows(),
            snapshot.pages().len()
        ),
        (1, 1, 1)
    );
    Ok(())
}

#[test]
fn missing_ambiguous_wrong_payload_or_over_limit_sdp_refuses_before_setup() -> Test {
    for case in 0..5 {
        let mut stores = Stores::new()?;
        let mut selection = selected()?;
        let mut description = sdp()?;
        match case {
            0 => {
                description = description
                    .lines()
                    .filter(|l| !l.starts_with("a=fmtp:"))
                    .collect::<Vec<_>>()
                    .join("\r\n")
                    + "\r\n"
            }
            1 => {
                let vps = base64(&nals()?[0]);
                description = description.replace(
                    &format!("sprop-vps={vps};"),
                    &format!("sprop-vps={vps},{vps};"),
                );
            }
            2 => selection.payload_type = 97,
            3 => selection.configuration_limits.max_width = 1,
            _ => selection.payload_type = 97,
        }
        let mut f = Fixture::configured(
            &mut stores,
            selection,
            (case == 4).then(configuration).transpose()?,
        )?;
        let (describe, _) = f.command()?;
        let sent = f.driver.totals().ok_or("totals")?.sent_bytes;
        f.peer.write_all(&response(
            describe.cseq,
            "Content-Type: application/sdp\r\n",
            &description,
        ))?;
        let mut failure = None;
        for _ in 0..32_768 {
            match f.poll(ready()) {
                Err(e) => {
                    failure = Some(e);
                    break;
                }
                Ok(Step::Recording(step)) => f.originals.push(*step),
                _ => return Err("refused description advanced archive state".into()),
            }
            std::thread::yield_now();
        }
        let failure = failure.ok_or("description refusal bound")?;
        assert!(
            matches!(failure.reason, LiveHevcArchiveError::Selection),
            "case {case}"
        );
        let retired = failure.retirement.ok_or("retirement")?;
        let input = retired.recording.ok_or("input retirement")?;
        assert!(input.capture.is_none());
        assert!(input.unoffered_event.is_some());
        assert_eq!(
            input
                .connection
                .ok_or("connection")?
                .transport
                .totals
                .sent_bytes,
            sent
        );
        let archive = retired.archive.ok_or("archive retirement")?;
        assert!(archive.writer.archive.snapshot.windows().is_empty());
        assert!(archive.writer.archive.pending.is_none());
        assert_eq!(archive.journal_anchor.sequence, 1);
        assert_eq!(f.peer.read(&mut [0_u8; 1])?, 0);
        assert!(f.driver.cancel().is_none());
    }
    Ok(())
}

#[test]
fn lone_idr_with_marker_and_real_eof_keeps_unverified_tail_out_of_archive() -> Test {
    let mut stores = Stores::new()?;
    let mut f = Fixture::new(&mut stores, selected()?)?;
    f.play()?;
    f.peer.write_all(&input(4)?)?;
    f.peer.shutdown(Shutdown::Write)?;
    let mut eof = false;
    let mut unverified = false;
    let mut finished = false;
    for _ in 0..32_768 {
        match f.poll(ready())? {
            Step::Recording(step) => {
                match step.as_ref() {
                    RecordingStep::Network(LiveHevcStep::InputEnded) => eof = true,
                    RecordingStep::Capture { event, .. } => match event.as_ref() {
                        HevcCapturePoll::TimingRequired(_) | HevcCapturePoll::Window(_) => {
                            return Err("marker or EOF fabricated a complete HEVC picture".into());
                        }
                        HevcCapturePoll::Receiver(source) => {
                            if let Event::Ended {
                                tail: Some(tail), ..
                            } = source.as_ref()
                                && let Some(picture) = &tail.picture
                            {
                                assert_eq!(picture.boundary(), HevcBoundary::EndOfInputUnverified);
                                unverified = true;
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }
                f.originals.push(*step);
            }
            Step::Archive(_) => {}
            Step::Finished {
                archive:
                    ArchiveWriteProgress::Finished {
                        windows: 0,
                        pages: 0,
                        ..
                    },
                cause: LiveArchiveCompletion::InputEnded,
            } => {
                finished = true;
                break;
            }
            _ => return Err("unverified EOF tail became a recording or fault".into()),
        }
        std::thread::yield_now();
    }
    assert!(eof && unverified && finished);
    assert!(f.driver.snapshot().ok_or("snapshot")?.windows().is_empty());
    assert!(f.driver.pin_state().candidate().is_none());
    assert!(f.driver.pin_state().last_confirmed().is_none());
    Ok(())
}

#[test]
fn revocation_before_explicit_stop_keeps_the_unpublished_admitted_window() -> Test {
    let mut stores = Stores::new()?;
    let mut f = Fixture::new(&mut stores, selected()?)?;
    let admitted = f.two_picture_window()?;
    let totals = f.driver.totals().ok_or("totals")?;
    f.peer.write_all(b"UNADMITTED_SOURCE_SENTINEL")?;
    f.authority.revoked.set(true);
    let failure = f
        .poll(ready())
        .err()
        .ok_or("revocation ignored during storage pause")?;
    assert!(matches!(
        failure.reason,
        LiveHevcArchiveError::Authority(TcpDenial::Revoked)
    ));
    let retired = failure.retirement.ok_or("retirement")?;
    let input = retired.recording.ok_or("input retirement")?;
    assert_eq!(
        input.connection.ok_or("connection")?.transport.totals,
        totals
    );
    let archive = retired.archive.ok_or("archive retirement")?;
    assert_eq!(
        archive
            .writer
            .archive
            .pending
            .ok_or("pending source lost")?
            .manifest()
            .root(),
        admitted.root
    );
    assert!(archive.writer.archive.snapshot.windows().is_empty());
    assert_eq!(archive.journal_anchor.sequence, 1);
    assert!(f.driver.cancel().is_none());
    Ok(())
}

#[test]
fn capture_generated_work_recovers_cold_after_confirmation_before_window_publication() -> Test {
    let mut stores = Stores::new()?;
    let root = stores.root.clone();
    let mut f = Fixture::new(&mut stores, selected()?)?;
    let admitted = f.two_picture_window()?;
    let source = ContentDigest::sha256(f.driver.pending().ok_or("pending")?.objects().source);
    let mut confirmed = None;
    for _ in 0..16 {
        let Step::Archive(progress) = f.poll(ready())? else {
            return Err("protected work unexpectedly polled capture".into());
        };
        match *progress {
            JournaledArchiveProgress::PinPersisted { .. } => {}
            JournaledArchiveProgress::WorkConfirmed { checkpoint, .. } => {
                confirmed = Some(checkpoint);
                break;
            }
            _ => return Err("normal window publication preceded confirmed work".into()),
        }
    }
    let confirmed = confirmed.ok_or("work confirmation bound")?;
    assert!(f.driver.snapshot().ok_or("snapshot")?.windows().is_empty());
    let retired = f.driver.cancel().ok_or("retirement")?;
    assert_eq!(
        retired
            .archive
            .as_ref()
            .ok_or("archive")?
            .pins
            .last_confirmed()
            .ok_or("pin")?
            .root(),
        confirmed.root()
    );
    drop(retired); // cold proof retains only independently named work metadata
    drop(f);
    drop(stores);
    let publisher = LocalRootPublisher::open(&root, store_limits())?;
    assert!(publisher.root(&admitted.slot).is_none());
    let work = load_hevc_archive_work(
        &publisher,
        confirmed.slot(),
        confirmed.root(),
        ArchiveWorkLimits::default(),
        &NeverCancel,
    )?;
    assert!(work.snapshot.windows().is_empty());
    let pending = work.pending.ok_or("cold pending HEVC source lost")?;
    assert_eq!(pending.manifest().root(), admitted.root);
    assert_eq!(pending.samples().len(), 2);
    assert_eq!(pending.source_only_nals(), 1);
    assert_eq!(ContentDigest::sha256(pending.objects().source), source);
    Ok(())
}

#[test]
fn held_digest_challenge_is_reported_before_any_configuration_or_automatic_answer() -> Test {
    let mut stores = Stores::new()?;
    let mut f = Fixture::new(&mut stores, selected()?)?;
    let (describe, _) = f.command()?;
    let sent = f.driver.totals().ok_or("totals")?.sent_bytes;
    let challenge = format!(
        "RTSP/1.0 401 Unauthorized\r\nCSeq: {}\r\nWWW-Authenticate: Digest realm=\"test-realm\", nonce=\"fixture-nonce\", algorithm=SHA-256, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n",
        describe.cseq
    );
    f.peer.write_all(challenge.as_bytes())?;
    for _ in 0..32_768 {
        if f.driver.requires_authentication() {
            break;
        }
        let Step::Recording(step) = f.poll(ready())? else {
            return Err("challenge became archive work".into());
        };
        f.originals.push(*step);
        std::thread::yield_now();
    }
    assert!(f.driver.requires_authentication());
    assert!(f.driver.needs_credentials());
    assert_eq!(f.driver.totals().ok_or("totals")?.sent_bytes, sent);
    let retired = f
        .driver
        .cancel()
        .ok_or("retirement")?
        .recording
        .ok_or("input retirement")?;
    assert!(retired.capture.is_none());
    assert_eq!(
        retired
            .connection
            .ok_or("connection")?
            .protocol
            .client
            .challenge
            .ok_or("challenge lost")?
            .expose_wire(),
        challenge.as_bytes()
    );
    assert!(f.driver.cancel().is_none());
    Ok(())
}
