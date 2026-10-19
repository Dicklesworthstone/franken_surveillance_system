#![forbid(unsafe_code)]
//! Real loopback -> native HEVC -> two independent stores -> cold source and pixel replay.
//! Fixture observations only; not camera conformance or a coverage qualification.

mod hevc_recording_support;

use fss_codec_h265::{Decoder, DecoderLimits};
use fss_container::demux::{AvcMp4, DemuxLimits, VideoCodec};
use fss_core::ContentDigest;
use fss_object::SpoolLimits;
use fss_packet::hevc::HevcAssemblyLimits;
use fss_packet::{H265Limits, ReorderLimits, StreamKey};
use fss_publication::{
    LocalPublicationLimits, LocalPublicationState, LocalRootPublisher, NeverCancel,
    PublishCancellation, PublishCutPoint, PublishOutcome,
};
use fss_reference::rtsp::archive_pins::hevc_live::{
    JournaledLiveHevcArchive, JournaledLiveHevcArchiveStep as Step,
    LiveHevcArchiveCompletion as Completion, LiveHevcArchiveConfig, LiveHevcArchiveError,
};
use fss_reference::rtsp::archive_pins::{
    ArchivePinError, ArchivePinLimits, ArchivePinPhase, ArchivePinScope, HevcArchivePinJournal,
    JournaledArchiveProgress,
};
use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};
use fss_reference::rtsp::client::{ClientCommand, ClientConfig, ClientProgress, ClientState};
use fss_reference::rtsp::hevc_client::{HevcClientPoll, pictures::HevcPictureClientPoll as Event};
use fss_reference::rtsp::hevc_recording_capture::live::{
    AutomaticHevcRecordingStep as RecordingStep, LiveHevcRecordingConfig,
};
use fss_reference::rtsp::hevc_recording_capture::{HevcCapturePoll, TimedHevcCapture};
use fss_reference::rtsp::hevc_recording_collector::HevcCollectionSeal;
use fss_reference::rtsp::live_hevc::{
    LiveHevcConfig, LiveHevcStep, QueuedHevcRequest, SocketReadiness,
};
use fss_reference::rtsp::recording::MAX_RECORDING_BYTES;
use fss_reference::rtsp::recording::hevc::{PreparedHevcRecording, local::load_hevc_recording};
use fss_reference::rtsp::recording_archive::checkpoint::ArchiveWorkLimits;
use fss_reference::rtsp::recording_archive::hevc::{HevcArchiveNamespace, HevcArchiveSnapshot};
use fss_reference::rtsp::recording_archive::{ArchiveError, ArchiveLimits, ArchiveWriteProgress};
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_collector::{CollectionStop, CollectorLimits};
use fss_reference::rtsp::tcp::{
    TcpAuthority, TcpBinding, TcpDenial, TcpLimits, TcpOperation, TcpSecurityPolicy, TcpWriteStep,
};
use hevc_recording_support::{
    Error, PT, SSRC, configuration, nals, packet, packets, scope, timings,
};
use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

type Test<T = ()> = Result<T, Error>;
const LEASE: u64 = 100_000_000_000;
const PAUSE: u64 = 1_000_000_000;
const KEY: StreamKey = StreamKey {
    ingress: 1,
    generation: 1,
    ssrc: SSRC,
};
static NEXT: AtomicU64 = AtomicU64::new(0);

fn fresh() -> Test<PathBuf> {
    let parent = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("journaled-live-hevc-archive");
    std::fs::create_dir_all(&parent)?;
    for _ in 0..256 {
        let path = parent.join(format!(
            "{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err("fixture path allowance".into())
}
fn storage() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        128,
        1024,
        128,
        1024,
        SpoolLimits::new(1024, 64 * 1024 * 1024, 2 * 1024 * 1024, 1024),
    )
}
fn namespace() -> Test<HevcArchiveNamespace> {
    Ok(HevcArchiveNamespace::new(CatalogScope {
        recording: scope()?,
        decode_clock: ContentDigest::sha256(b"live HEVC archive decode clock"),
        time_scale: 90_000,
    })?)
}
fn pin_scope() -> Test<ArchivePinScope> {
    Ok(ArchivePinScope {
        journal_id: ContentDigest::sha256(b"live HEVC independent journal epoch"),
        archive_namespace: namespace()?.digest(),
    })
}
fn pins(path: &Path, limits: ArchivePinLimits) -> Test<HevcArchivePinJournal> {
    Ok(HevcArchivePinJournal::create(
        path.join("pins"),
        pin_scope()?,
        limits,
        &NeverCancel,
    )?)
}
fn archive_config() -> Test<LiveHevcArchiveConfig> {
    Ok(LiveHevcArchiveConfig {
        namespace: namespace()?,
        limits: ArchiveLimits {
            max_windows: 8,
            max_pages: 8,
            max_scan_roots: 128,
            windows_per_page: 2,
        },
        max_window_bytes: MAX_RECORDING_BYTES,
        max_steps: 200_000,
        publication_deadline_ns: 2 * LEASE,
        max_storage_pause_ns: PAUSE,
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
fn sdp() -> &'static str {
    "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 98\r\na=rtpmap:98 H265/90000\r\na=control:track\r\n"
}
fn framed(packet: &[u8]) -> Test<Vec<u8>> {
    let mut out = vec![b'$', 0];
    out.extend_from_slice(&u16::try_from(packet.len())?.to_be_bytes());
    out.extend_from_slice(packet);
    Ok(out)
}
fn input() -> Test<Vec<Vec<u8>>> {
    packets()?
        .into_iter()
        .enumerate()
        .map(|(i, mut p)| {
            p.bytes[2..4].copy_from_slice(&u16::try_from(i + 1)?.to_be_bytes());
            Ok(p.bytes)
        })
        .collect()
}
#[derive(Debug)]
struct ExpectedWindow {
    root: ContentDigest,
    source: Vec<u8>,
    initialization: Vec<u8>,
    media: Vec<u8>,
    index: Vec<u8>,
}
impl ExpectedWindow {
    fn copy_test_oracle(recording: &PreparedHevcRecording) -> Self {
        let objects = recording.objects();
        Self {
            root: recording.manifest().root(),
            source: objects.source.to_vec(),
            initialization: objects.initialization.to_vec(),
            media: objects.media.to_vec(),
            index: objects.index.to_vec(),
        }
    }
}
struct Fixture<'a, 'p> {
    driver: JournaledLiveHevcArchive<'a, 'p>,
    peer: TcpStream,
    authority: Authority,
    nonce: u128,
    raw: Vec<u8>,
    outputs: Vec<Step>,
    timed: Vec<TimedHevcCapture>,
    seals: Vec<HevcCollectionSeal>,
    expected: Vec<ExpectedWindow>,
}
impl<'a, 'p> Fixture<'a, 'p> {
    fn new(
        p: &'a mut LocalRootPublisher,
        pins: &'p mut HevcArchivePinJournal,
        chunk: usize,
        archive: LiveHevcArchiveConfig,
    ) -> Test<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let (live, recording, authority) = configs(listener.local_addr()?, chunk)?;
        let driver = JournaledLiveHevcArchive::connect(
            live,
            recording,
            archive,
            ArchiveWorkLimits::default(),
            p,
            pins,
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
            nonce: 0,
            raw: Vec::new(),
            outputs: Vec::new(),
            timed: Vec::new(),
            seals: Vec::new(),
            expected: Vec::new(),
        })
    }
    fn poll(&mut self, readiness: SocketReadiness, now: u64) -> Test<Step> {
        let nonce = if self.driver.needs_credentials() {
            self.nonce += 1;
            self.nonce.to_be_bytes()
        } else {
            [0; 16]
        };
        Ok(self.driver.poll(
            readiness,
            &credentials()?,
            nonce,
            now,
            &self.authority,
            &NeverCancel,
        )?)
    }
    // Retain original outputs in the caller and supply only the fixture's independently fixed DTS.
    fn retain(&mut self, step: Step, now: u64) -> Test {
        match &step {
            Step::WindowAccepted(admission) => {
                let pending = self.driver.pending().ok_or("pending source missing")?;
                assert_eq!(pending.manifest().root(), admission.root);
                assert_eq!(
                    self.driver.snapshot().ok_or("snapshot")?.windows().len(),
                    admission.ordinal
                );
                self.expected
                    .push(ExpectedWindow::copy_test_oracle(pending));
            }
            Step::Recording(recording) => match recording.as_ref() {
                RecordingStep::Network(LiveHevcStep::Wire(bytes)) => {
                    self.raw.extend_from_slice(bytes.expose())
                }
                RecordingStep::Capture { event, .. }
                    if matches!(event.as_ref(), HevcCapturePoll::TimingRequired(_)) =>
                {
                    let timing = timings(self.timed.len() + 1)[self.timed.len()];
                    self.timed.push(self.driver.supply_timing(
                        timing,
                        now,
                        &self.authority,
                        &NeverCancel,
                    )?);
                }
                _ => {}
            },
            Step::Stopped { .. } => return Err("unexpected source invalidation in fixture".into()),
            _ => {}
        }
        self.outputs.push(step);
        Ok(())
    }
    fn storage_ready(&mut self, now: u64) -> Test {
        let totals = self.driver.totals();
        for _ in 0..128 {
            let step = self.poll(ready(), now)?;
            let ready = matches!(
                &step,
                Step::Storage(JournaledArchiveProgress::Archive(
                    ArchiveWriteProgress::Ready { .. }
                ))
            );
            assert!(matches!(&step, Step::Storage(_)));
            assert_eq!(self.driver.totals(), totals);
            self.retain(step, now)?;
            if ready {
                return Ok(());
            }
        }
        Err("storage ready bound".into())
    }
    fn command(&mut self, now: u64) -> Test<(QueuedHevcRequest, Vec<u8>)> {
        assert!(self.driver.needs_credentials());
        let Step::Recording(recording) = self.poll(SocketReadiness::default(), now)? else {
            return Err("missing command".into());
        };
        let RecordingStep::Queued(queued) = *recording else {
            return Err("missing queued command".into());
        };
        for _ in 0..32_768 {
            let step = self.poll(
                SocketReadiness {
                    readable: false,
                    writable: true,
                },
                now,
            )?;
            let sent = match &step {
                Step::Recording(recording) => match recording.as_ref() {
                    RecordingStep::Network(LiveHevcStep::Write(TcpWriteStep::Sent {
                        cseq,
                        bytes,
                    })) => Some((*cseq, *bytes)),
                    RecordingStep::Network(
                        LiveHevcStep::Write(TcpWriteStep::Advanced { .. })
                        | LiveHevcStep::Pending(_),
                    ) => None,
                    _ => return Err("unexpected command progress".into()),
                },
                _ => return Err("storage resumed during command dispatch".into()),
            };
            self.retain(step, now)?;
            if let Some((cseq, bytes)) = sent {
                assert_eq!((cseq, bytes), (queued.cseq, queued.bytes));
                let mut original = vec![0; bytes];
                self.peer.read_exact(&mut original)?;
                return Ok((queued, original));
            }
        }
        Err("command send bound".into())
    }
    fn reply(&mut self, bytes: &[u8], now: u64, state: Option<ClientState>) -> Test {
        self.peer.write_all(bytes)?;
        let before = self.raw.len();
        for _ in 0..32_768 {
            let step = self.poll(
                SocketReadiness {
                    readable: true,
                    writable: false,
                },
                now,
            )?;
            let matched = match &step {
                Step::Recording(recording) => match recording.as_ref() {
                    RecordingStep::Capture {
                        event,
                        connection: None,
                    } => match event.as_ref() {
                        HevcCapturePoll::Receiver(event) => match event.as_ref() {
                            Event::Client { event, work: None } => match (state, event.as_ref()) {
                                (
                                    Some(expected),
                                    HevcClientPoll::Control {
                                        progress: ClientProgress::Accepted(actual),
                                        ..
                                    },
                                ) => expected == *actual,
                                (None, HevcClientPoll::AuthenticationRequired { .. }) => true,
                                _ => false,
                            },
                            _ => false,
                        },
                        _ => false,
                    },
                    _ => false,
                },
                _ => false,
            };
            self.retain(step, now)?;
            if matched {
                assert_eq!(&self.raw[before..], bytes);
                return Ok(());
            }
        }
        Err("control reply bound".into())
    }
    fn negotiate(&mut self, digest: bool) -> Test {
        self.storage_ready(0)?;
        let (describe, wire) = self.command(0)?;
        assert_eq!(describe.command, ClientCommand::Describe);
        assert!(!std::str::from_utf8(&wire)?.contains("Authorization:"));
        let cseq = if digest {
            let challenge = format!(
                "RTSP/1.0 401 Unauthorized\r\nCSeq: {}\r\nWWW-Authenticate: Digest realm=\"test-realm\", nonce=\"test-nonce\", algorithm=SHA-256, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n",
                describe.cseq
            );
            self.reply(challenge.as_bytes(), 1, None)?;
            let (answer, wire) = self.command(2)?;
            assert!(answer.cseq > describe.cseq);
            assert_eq!(
                answer
                    .challenge
                    .as_ref()
                    .ok_or("consumed challenge missing")?
                    .expose_wire(),
                challenge.as_bytes()
            );
            assert!(std::str::from_utf8(&wire)?.contains("Authorization: Digest "));
            assert!(!std::str::from_utf8(&wire)?.contains("test-password"));
            answer.cseq
        } else {
            describe.cseq
        };
        self.reply(
            &response(cseq, "Content-Type: application/sdp\r\n", sdp()),
            3,
            Some(ClientState::Described),
        )?;
        let (setup, _) = self.command(4)?;
        assert_eq!(setup.command, ClientCommand::Setup);
        self.reply(&response(setup.cseq, "Session: test-session;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n", ""), 5, Some(ClientState::Ready))?;
        let (play, _) = self.command(6)?;
        assert_eq!(play.command, ClientCommand::Play);
        self.reply(
            &response(play.cseq, "Session: test-session\r\n", ""),
            7,
            Some(ClientState::Playing),
        )?;
        assert_eq!(self.driver.state(), ClientState::Playing);
        assert!(self.expected.is_empty());
        assert!(self.timed.is_empty());
        self.feed(&packet(0, 0, false, &nals()?[0]).bytes, 10)?; // sequence probation
        Ok(())
    }
    fn feed(&mut self, bytes: &[u8], now: u64) -> Test {
        let wire = framed(bytes)?;
        self.peer.write_all(&wire)?;
        let before = self.raw.len();
        for _ in 0..32_768 {
            let step = self.poll(ready(), now)?;
            let idle = matches!(&step, Step::Recording(recording)
                if matches!(recording.as_ref(), RecordingStep::Network(LiveHevcStep::Pending(wait))
                    if wait.wake_at_ns.is_none_or(|at| at > now)));
            self.retain(step, now)?;
            if idle && self.raw.len() - before == wire.len() {
                assert_eq!(&self.raw[before..], wire);
                return Ok(());
            }
            if idle {
                std::thread::yield_now();
            }
        }
        Err("source drain bound".into())
    }
    fn one_window(&mut self) -> Test<ContentDigest> {
        self.negotiate(false)?;
        for (i, bytes) in input()?[..5].iter().enumerate() {
            self.feed(bytes, 20 + i as u64)?;
        }
        assert_eq!(self.timed.len(), 1);
        let seal = self.driver.seal(25, &self.authority, &NeverCancel)?;
        assert!(seal.window_ready);
        self.seals.push(seal);
        let step = self.poll(ready(), 25)?;
        let Step::WindowAccepted(admission) = &step else {
            return Err("window admission missing".into());
        };
        let root = admission.root;
        self.retain(step, 25)?;
        Ok(root)
    }
    fn finish(&mut self, now: u64) -> Test<Completion> {
        for _ in 0..32_768 {
            let step = self.poll(ready(), now)?;
            let cause = match &step {
                Step::Finished {
                    archive: ArchiveWriteProgress::Finished { .. },
                    cause,
                } => Some(*cause),
                Step::Finished { .. } | Step::Ended => return Err("invalid/repeated finish".into()),
                _ => None,
            };
            self.retain(step, now)?;
            if let Some(cause) = cause {
                return Ok(cause);
            }
            std::thread::yield_now();
        }
        Err("final archive drain bound".into())
    }
}
fn decode(recording: &PreparedHevcRecording) -> Test<usize> {
    let mut bytes = recording.objects().initialization.to_vec();
    bytes.extend_from_slice(recording.objects().media);
    let mp4 = AvcMp4::parse(&bytes, None, DemuxLimits::default())?;
    assert_eq!(mp4.codec(), VideoCodec::Hevc);
    let annex = mp4.annex_b(0, mp4.samples().len())?;
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let mut pictures = decoder.decode_annex_b(annex.bytes())?;
    pictures.extend(decoder.finish()?);
    assert!(
        pictures
            .iter()
            .all(|p| p.luma().len() == p.width() as usize * p.height() as usize)
    );
    Ok(pictures.len())
}

#[test]
fn native_plain_and_digest_streams_cold_replay_identically_after_both_journal_phases() -> Test {
    let mut identities = Vec::new();
    for chunk in [1, 7, 4096] {
        for digest in [false, true] {
            let path = fresh()?;
            let (expected, anchor, snapshot_digest) = {
                let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
                let mut pins = pins(&path, ArchivePinLimits::default())?;
                let mut f = Fixture::new(&mut p, &mut pins, chunk, archive_config()?)?;
                f.negotiate(digest)?;
                for (i, bytes) in input()?.iter().enumerate() {
                    f.feed(bytes, 20 + i as u64)?;
                }
                f.peer.shutdown(Shutdown::Write)?;
                assert_eq!(f.finish(40)?, Completion::RecordingEnded);
                assert_eq!(f.timed.len(), 4);
                assert_eq!(f.expected.len(), 2);
                let snapshot = f.driver.snapshot().ok_or("snapshot")?;
                assert_eq!(snapshot.indexed_windows(), 2);
                assert_eq!(snapshot.pages().len(), 1);
                assert_eq!(f.driver.journal_anchor().ok_or("anchor")?.sequence, 7);
                assert!(f.driver.pin_state().ok_or("pins")?.candidate().is_none());
                let phases: Vec<_> = f
                    .outputs
                    .iter()
                    .filter_map(|step| match step {
                        Step::Storage(JournaledArchiveProgress::PinPersisted {
                            receipt, ..
                        }) => Some(receipt.phase()),
                        Step::Storage(JournaledArchiveProgress::WorkConfirmed {
                            pin_receipt,
                            ..
                        }) => Some(pin_receipt.phase()),
                        _ => None,
                    })
                    .collect();
                assert_eq!(
                    phases,
                    vec![
                        ArchivePinPhase::Candidate,
                        ArchivePinPhase::Confirmed,
                        ArchivePinPhase::Candidate,
                        ArchivePinPhase::Confirmed,
                        ArchivePinPhase::Candidate,
                        ArchivePinPhase::Confirmed
                    ]
                );
                let digest = snapshot.digest()?;
                let anchor = f.driver.journal_anchor().ok_or("anchor")?;
                assert!(matches!(f.poll(ready(), 41)?, Step::Ended));
                assert_eq!(f.driver.next_wake_ns(), None);
                (f.expected, anchor, digest)
            };
            let p = LocalRootPublisher::open(path.join("media"), storage())?;
            let mut pins = HevcArchivePinJournal::open_complete(
                path.join("pins"),
                pin_scope()?,
                Some(anchor),
                ArchivePinLimits::default(),
                &NeverCancel,
            )?;
            pins.require_settled(&p, ArchiveWorkLimits::default(), &NeverCancel)?;
            let snapshot = HevcArchiveSnapshot::load(
                &p,
                namespace()?,
                archive_config()?.limits,
                &NeverCancel,
            )?;
            assert_eq!(snapshot.digest()?, snapshot_digest);
            let mut pixels = 0;
            for (entry, expected) in snapshot.windows().iter().zip(&expected) {
                assert_eq!(entry.root(), expected.root);
                let recording =
                    load_hevc_recording(&p, entry.slot(), entry.root(), &scope()?, &NeverCancel)?;
                let actual = recording.objects();
                assert_eq!(actual.source, expected.source);
                assert_eq!(actual.initialization, expected.initialization);
                assert_eq!(actual.media, expected.media);
                assert_eq!(actual.index, expected.index);
                pixels += decode(&recording)?;
            }
            assert_eq!(pixels, 4);
            identities.push((
                snapshot_digest,
                expected.iter().map(|w| w.root).collect::<Vec<_>>(),
            ));
        }
    }
    assert!(identities.windows(2).all(|pair| pair[0] == pair[1]));
    Ok(())
}

#[test]
fn publication_blocks_socket_input_and_owner_stop_drains_without_network_authority() -> Test {
    let path = fresh()?;
    let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = pins(&path, ArchivePinLimits::default())?;
    let mut f = Fixture::new(&mut p, &mut pins, 7, archive_config()?)?;
    let root = f.one_window()?;
    let totals = f.driver.totals().ok_or("totals")?;
    f.peer.write_all(b"UNREAD_SOURCE_CANARY")?;
    assert!(!f.driver.needs_credentials());
    assert!(matches!(
        f.poll(ready(), 26)?,
        Step::Storage(JournaledArchiveProgress::PinPersisted { .. })
    ));
    assert_eq!(f.driver.snapshot().ok_or("snapshot")?.windows().len(), 0);
    assert_eq!(f.driver.totals(), Some(totals));
    assert!(matches!(f.driver.seal(26, &f.authority, &NeverCancel),
        Err(e) if matches!(e.reason, LiveHevcArchiveError::Backpressure) && e.retirement.is_none()));
    assert!(matches!(
        f.poll(ready(), 26)?,
        Step::Storage(JournaledArchiveProgress::WorkConfirmed { .. })
    ));
    assert_eq!(f.driver.snapshot().ok_or("snapshot")?.windows().len(), 0);
    assert_eq!(f.driver.totals(), Some(totals));
    let retirement = f
        .driver
        .finish_capture(27, &f.authority, &NeverCancel)?
        .ok_or("input retirement")?;
    assert_eq!(
        retirement.connection.ok_or("connection")?.transport.totals,
        totals
    );
    assert!(!f.driver.needs_credentials());
    let checks = f.authority.checks.get();
    f.authority.revoked.set(true);
    assert_eq!(f.finish(27)?, Completion::OwnerStopped);
    assert_eq!(f.authority.checks.get(), checks);
    assert_eq!(
        f.driver.snapshot().ok_or("snapshot")?.windows()[0].root(),
        root
    );
    assert_eq!(f.driver.snapshot().ok_or("snapshot")?.indexed_windows(), 1);
    assert!(
        !f.raw
            .windows(b"UNREAD_SOURCE_CANARY".len())
            .any(|w| w == b"UNREAD_SOURCE_CANARY")
    );
    Ok(())
}

#[test]
fn revocation_after_candidate_retains_original_window_and_exact_pending_pin_once() -> Test {
    let path = fresh()?;
    let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = pins(&path, ArchivePinLimits::default())?;
    let mut f = Fixture::new(&mut p, &mut pins, 7, archive_config()?)?;
    let root = f.one_window()?;
    let Step::Storage(JournaledArchiveProgress::PinPersisted {
        checkpoint,
        receipt,
    }) = f.poll(ready(), 26)?
    else {
        return Err("candidate missing".into());
    };
    f.authority.revoked.set(true);
    let error = f
        .driver
        .poll(
            ready(),
            &credentials()?,
            [0; 16],
            27,
            &f.authority,
            &NeverCancel,
        )
        .err()
        .ok_or("revocation ignored")?;
    assert!(matches!(
        error.reason,
        LiveHevcArchiveError::Authority(TcpDenial::Revoked)
    ));
    let retired = error.retirement.ok_or("retirement")?;
    assert!(retired.recording.is_some());
    let archive = retired.archive.ok_or("archive")?;
    assert_eq!(archive.journal_anchor, receipt.anchor());
    assert_eq!(archive.writer.pending_checkpoint, Some(checkpoint));
    assert!(archive.writer.last_durable_checkpoint.is_none());
    assert_eq!(
        archive
            .writer
            .archive
            .pending
            .ok_or("original")?
            .manifest()
            .root(),
        root
    );
    assert!(f.driver.cancel().is_none());
    assert!(matches!(f.poll(ready(), 28)?, Step::Ended));
    drop(f);
    assert_eq!(p.visible_roots().count(), 0);
    Ok(())
}

#[test]
fn confirmed_but_unpublished_window_cold_restores_without_reopening_camera() -> Test {
    let path = fresh()?;
    let (root, anchor) = {
        let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
        let mut pins = pins(&path, ArchivePinLimits::default())?;
        let mut f = Fixture::new(&mut p, &mut pins, 4096, archive_config()?)?;
        let root = f.one_window()?;
        assert!(matches!(
            f.poll(ready(), 26)?,
            Step::Storage(JournaledArchiveProgress::PinPersisted { .. })
        ));
        assert!(matches!(
            f.poll(ready(), 26)?,
            Step::Storage(JournaledArchiveProgress::WorkConfirmed { .. })
        ));
        assert_eq!(f.driver.snapshot().ok_or("snapshot")?.windows().len(), 0);
        let retired = f.driver.cancel().ok_or("retirement")?;
        let archive = retired.archive.ok_or("archive")?;
        assert_eq!(
            archive
                .writer
                .archive
                .pending
                .ok_or("source")?
                .manifest()
                .root(),
            root
        );
        (root, archive.journal_anchor)
    };
    let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = HevcArchivePinJournal::open_complete(
        path.join("pins"),
        pin_scope()?,
        Some(anchor),
        ArchivePinLimits::default(),
        &NeverCancel,
    )?;
    assert!(
        pins.require_settled(&p, ArchiveWorkLimits::default(), &NeverCancel)
            .is_err()
    );
    let restored = pins.restore_work(&mut p, ArchiveWorkLimits::default(), 1, 100, &NeverCancel)?;
    assert_eq!((restored.durable_windows, restored.indexed_windows), (1, 0));
    assert_eq!(restored.window.ok_or("window receipt")?.root, root);
    assert!(restored.confirmation.is_none());
    let again = pins.restore_work(&mut p, ArchiveWorkLimits::default(), 1, 100, &NeverCancel)?;
    assert_eq!(
        again.window.ok_or("retry receipt")?.outcome,
        PublishOutcome::AlreadyPublished
    );
    assert_eq!(pins.anchor(), anchor);
    assert_eq!(
        decode(&load_hevc_recording(
            &p,
            &namespace()?.window_slot(0)?,
            root,
            &scope()?,
            &NeverCancel
        )?)?,
        1
    );
    // A deliberate new owner must finish the recovered page before its first DESCRIBE.
    let mut f = Fixture::new(&mut p, &mut pins, 7, archive_config()?)?;
    assert!(!f.driver.needs_credentials());
    f.storage_ready(0)?;
    assert_eq!(f.driver.totals().ok_or("totals")?.sent_bytes, 0);
    assert_eq!(f.driver.totals().ok_or("totals")?.read_calls, 0);
    assert_eq!(f.driver.snapshot().ok_or("snapshot")?.indexed_windows(), 1);
    assert_eq!(f.command(0)?.0.command, ClientCommand::Describe);
    let _retired = f.driver.cancel().ok_or("retirement")?;
    Ok(())
}

#[test]
fn confirmation_budget_failure_returns_durable_receipt_and_cold_candidate_recovery() -> Test {
    let path = fresh()?;
    let (root, anchor) = {
        let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
        let mut pins = pins(
            &path,
            ArchivePinLimits {
                max_records: 2,
                ..ArchivePinLimits::default()
            },
        )?;
        let mut f = Fixture::new(&mut p, &mut pins, 7, archive_config()?)?;
        let root = f.one_window()?;
        assert!(matches!(
            f.poll(ready(), 26)?,
            Step::Storage(JournaledArchiveProgress::PinPersisted { .. })
        ));
        let error = f
            .driver
            .poll(
                ready(),
                &credentials()?,
                [0; 16],
                26,
                &f.authority,
                &NeverCancel,
            )
            .err()
            .ok_or("confirmation limit ignored")?;
        assert!(matches!(
            error.reason,
            LiveHevcArchiveError::Storage(ArchivePinError::Limit)
        ));
        let retired = error.retirement.ok_or("retirement")?;
        assert!(retired.recording.is_some());
        let archive = retired.archive.ok_or("archive")?;
        let unrecorded = archive
            .unrecorded_confirmation
            .ok_or("durable receipt lost")?;
        assert_eq!(
            unrecorded.receipt.claims.local,
            LocalPublicationState::Durable
        );
        assert_eq!(
            archive.pins.candidate().ok_or("candidate")?.root(),
            unrecorded.checkpoint.root()
        );
        assert_eq!(
            archive
                .writer
                .archive
                .pending
                .ok_or("source")?
                .manifest()
                .root(),
            root
        );
        assert!(f.driver.cancel().is_none());
        (root, archive.journal_anchor)
    };
    let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
    // Recovery uses an explicitly enlarged metadata budget, not a hidden live retry.
    let mut pins = HevcArchivePinJournal::open_complete(
        path.join("pins"),
        pin_scope()?,
        Some(anchor),
        ArchivePinLimits::default(),
        &NeverCancel,
    )?;
    let restored = pins.restore_work(&mut p, ArchiveWorkLimits::default(), 1, 100, &NeverCancel)?;
    assert!(restored.confirmation.is_some());
    assert_eq!(restored.window.ok_or("window")?.root, root);
    assert_eq!(restored.journal_anchor.sequence, 3);
    Ok(())
}

#[test]
fn pin_damage_fences_camera_input_even_when_footage_store_is_available() -> Test {
    let path = fresh()?;
    let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = pins(&path, ArchivePinLimits::default())?;
    let mut f = Fixture::new(&mut p, &mut pins, 7, archive_config()?)?;
    f.negotiate(false)?;
    let totals = f.driver.totals().ok_or("totals")?;
    std::fs::write(path.join("pins/pins.journal"), b"damaged fixture journal")?;
    f.peer.write_all(b"UNREAD_AFTER_PIN_LOSS")?;
    let error = f
        .driver
        .poll(
            ready(),
            &credentials()?,
            [0; 16],
            11,
            &f.authority,
            &NeverCancel,
        )
        .err()
        .ok_or("pin damage ignored")?;
    assert!(matches!(error.reason, LiveHevcArchiveError::Storage(_)));
    let retired = error.retirement.ok_or("retirement")?;
    assert_eq!(
        retired
            .recording
            .ok_or("recording")?
            .connection
            .ok_or("connection")?
            .transport
            .totals,
        totals
    );
    assert!(retired.archive.is_some());
    assert!(f.driver.cancel().is_none());
    drop(f);
    assert_eq!(p.visible_roots().count(), 0);
    Ok(())
}

#[test]
fn original_pause_deadline_survives_candidate_progress_and_safe_backpressure() -> Test {
    let path = fresh()?;
    let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = pins(&path, ArchivePinLimits::default())?;
    let mut f = Fixture::new(&mut p, &mut pins, 7, archive_config()?)?;
    let root = f.one_window()?;
    assert!(matches!(
        f.poll(ready(), 26)?,
        Step::Storage(JournaledArchiveProgress::PinPersisted { .. })
    ));
    for now in 27..32 {
        let error = f
            .driver
            .flush(now, &f.authority, &NeverCancel)
            .err()
            .ok_or("flush bypassed pause")?;
        assert!(matches!(error.reason, LiveHevcArchiveError::Backpressure));
        assert!(error.retirement.is_none());
    }
    let error = f
        .driver
        .poll(
            ready(),
            &credentials()?,
            [0; 16],
            25 + PAUSE,
            &f.authority,
            &NeverCancel,
        )
        .err()
        .ok_or("pause renewed")?;
    assert!(matches!(
        error.reason,
        LiveHevcArchiveError::StoragePauseExpired
    ));
    let archive = error
        .retirement
        .ok_or("retirement")?
        .archive
        .ok_or("archive")?;
    assert!(archive.writer.last_durable_checkpoint.is_none());
    assert!(archive.pins.candidate().is_some());
    assert_eq!(
        archive
            .writer
            .archive
            .pending
            .ok_or("source")?
            .manifest()
            .root(),
        root
    );
    Ok(())
}

#[test]
fn reversed_clock_changes_neither_work_allowance_nor_pins_or_socket() -> Test {
    let path = fresh()?;
    let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = pins(&path, ArchivePinLimits::default())?;
    let mut f = Fixture::new(&mut p, &mut pins, 7, archive_config()?)?;
    f.storage_ready(10)?;
    let before = (
        f.driver.remaining_steps(),
        f.driver.journal_anchor(),
        f.driver.totals(),
        f.authority.checks.get(),
    );
    let error = f
        .driver
        .poll(
            ready(),
            &credentials()?,
            [0; 16],
            9,
            &f.authority,
            &NeverCancel,
        )
        .err()
        .ok_or("clock regression admitted")?;
    assert!(matches!(error.reason, LiveHevcArchiveError::ClockReversed));
    assert!(error.retirement.is_none());
    assert_eq!(
        before,
        (
            f.driver.remaining_steps(),
            f.driver.journal_anchor(),
            f.driver.totals(),
            f.authority.checks.get()
        )
    );
    assert_eq!(f.command(11)?.0.command, ClientCommand::Describe);
    let _retired = f.driver.cancel().ok_or("retirement")?;
    Ok(())
}

#[test]
fn rejected_window_remains_in_fatal_ownership_and_is_not_called_admitted() -> Test {
    let path = fresh()?;
    let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = pins(&path, ArchivePinLimits::default())?;
    let mut config = archive_config()?;
    config.max_window_bytes = 1;
    let mut f = Fixture::new(&mut p, &mut pins, 7, config)?;
    f.negotiate(false)?;
    for (i, bytes) in input()?[..5].iter().enumerate() {
        f.feed(bytes, 20 + i as u64)?;
    }
    f.seals.push(f.driver.seal(25, &f.authority, &NeverCancel)?);
    let error = f
        .driver
        .poll(
            ready(),
            &credentials()?,
            [0; 16],
            25,
            &f.authority,
            &NeverCancel,
        )
        .err()
        .ok_or("oversized window admitted")?;
    assert!(matches!(
        error.reason,
        LiveHevcArchiveError::Storage(ArchivePinError::Archive(ArchiveError::Limit))
    ));
    let retired = error.retirement.ok_or("retirement")?;
    let RecordingStep::Capture {
        event,
        connection: None,
    } = *retired.unreturned_step.ok_or("rejected window lost")?
    else {
        return Err("wrong original step".into());
    };
    let HevcCapturePoll::Window(window) = *event else {
        return Err("window lost".into());
    };
    assert_eq!(window.summary().samples, 1);
    let archive = retired.archive.ok_or("archive")?;
    assert!(archive.writer.archive.pending.is_none());
    assert!(archive.writer.archive.snapshot.windows().is_empty());
    assert_eq!(archive.journal_anchor.sequence, 1);
    assert!(f.driver.cancel().is_none());
    Ok(())
}

#[test]
fn source_gap_stops_capture_without_sealing_or_fabricating_archive_completion() -> Test {
    let path = fresh()?;
    let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = pins(&path, ArchivePinLimits::default())?;
    let mut f = Fixture::new(&mut p, &mut pins, 7, archive_config()?)?;
    f.negotiate(false)?;
    let data = input()?;
    for (i, bytes) in data[..5].iter().enumerate() {
        f.feed(bytes, 20 + i as u64)?;
    }
    f.feed(&data[6], 30)?; // omit sequence six
    let now = 30 + ReorderLimits::default().max_delay_ns;
    for _ in 0..128 {
        match f.poll(ready(), now)? {
            Step::Stopped { trigger, retained } => {
                let RecordingStep::Capture {
                    event,
                    connection: Some(_),
                } = *trigger
                else {
                    return Err("gap omitted socket retirement".into());
                };
                let HevcCapturePoll::Stopped {
                    reason,
                    retained: capture,
                    ..
                } = *event
                else {
                    return Err("gap lost capture work".into());
                };
                assert_eq!(reason, CollectionStop::InputDiscontinuity);
                assert!(capture.collection.ready.is_none());
                assert_eq!(capture.collection.pictures.len(), 1);
                let archive = retained.archive.ok_or("archive")?;
                assert!(archive.writer.archive.pending.is_none());
                assert!(archive.writer.archive.snapshot.windows().is_empty());
                assert!(matches!(f.poll(ready(), now)?, Step::Ended));
                assert!(f.driver.cancel().is_none());
                return Ok(());
            }
            Step::Recording(_) => {}
            _ => return Err("gap unexpectedly progressed archive".into()),
        }
    }
    Err("gap did not stop the bounded owner".into())
}

#[test]
fn invalid_cross_owner_configuration_refuses_before_recovery_or_connection() -> Test {
    for case in 0..5 {
        let path = fresh()?;
        let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
        let mut pins = pins(&path, ArchivePinLimits::default())?;
        let before = pins.anchor();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let (live, mut recording, authority) = configs(listener.local_addr()?, 7)?;
        let mut archive = archive_config()?;
        let mut work = ArchiveWorkLimits::default();
        match case {
            0 => recording.scope.generation += 1,
            1 => recording.time_scale = 48_000,
            2 => archive.max_steps = 0,
            3 => archive.max_storage_pause_ns = 0,
            _ => work.max_pending_bytes = 0,
        }
        let error = JournaledLiveHevcArchive::connect(
            live,
            recording,
            archive,
            work,
            &mut p,
            &mut pins,
            0,
            &authority,
            &NeverCancel,
        )
        .err()
        .ok_or("invalid plan connected")?;
        assert!(matches!(error.reason, LiveHevcArchiveError::Configuration));
        assert!(!error.connection_attempted);
        assert_eq!(authority.checks.get(), 0);
        assert_eq!(pins.anchor(), before);
        assert_eq!(p.visible_roots().count(), 0);
        assert_eq!(
            listener
                .accept()
                .err()
                .ok_or("unexpected accepted socket")?
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    Ok(())
}

#[test]
fn finite_outer_work_limit_retires_an_unsent_request_without_attempting_io() -> Test {
    let path = fresh()?;
    let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = pins(&path, ArchivePinLimits::default())?;
    let mut archive = archive_config()?;
    archive.max_steps = 2;
    let mut f = Fixture::new(&mut p, &mut pins, 7, archive)?;
    f.storage_ready(0)?;
    let Step::Recording(step) = f.poll(SocketReadiness::default(), 0)? else {
        return Err("command missing".into());
    };
    let RecordingStep::Queued(request) = *step else {
        return Err("request not prepared".into());
    };
    assert_eq!(f.driver.remaining_steps(), 0);
    let error = f
        .driver
        .poll(
            ready(),
            &credentials()?,
            [0; 16],
            0,
            &f.authority,
            &NeverCancel,
        )
        .err()
        .ok_or("work allowance replenished")?;
    assert!(matches!(error.reason, LiveHevcArchiveError::WorkBudget));
    let retired = error.retirement.ok_or("retirement")?;
    let transport = retired
        .recording
        .ok_or("recording")?
        .connection
        .ok_or("connection")?
        .transport;
    assert_eq!(transport.totals.sent_bytes, 0);
    assert_eq!(transport.totals.write_calls, 0);
    assert_eq!(
        transport.request.ok_or("unsent request lost")?.cseq(),
        request.cseq
    );
    assert!(f.driver.cancel().is_none());
    assert!(matches!(f.poll(ready(), 1)?, Step::Ended));
    Ok(())
}

struct Cancel;
impl PublishCancellation for Cancel {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        true
    }
}
#[test]
fn independent_storage_cancellation_still_applies_after_input_retirement() -> Test {
    let path = fresh()?;
    let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = pins(&path, ArchivePinLimits::default())?;
    let mut f = Fixture::new(&mut p, &mut pins, 7, archive_config()?)?;
    let root = f.one_window()?;
    assert!(matches!(
        f.poll(ready(), 26)?,
        Step::Storage(JournaledArchiveProgress::PinPersisted { .. })
    ));
    let _input = f
        .driver
        .finish_capture(26, &f.authority, &NeverCancel)?
        .ok_or("input ownership")?;
    let checks = f.authority.checks.get();
    f.authority.revoked.set(true);
    let error = f
        .driver
        .poll(ready(), &credentials()?, [0; 16], 27, &f.authority, &Cancel)
        .err()
        .ok_or("storage cancellation ignored")?;
    assert!(matches!(
        error.reason,
        LiveHevcArchiveError::Storage(ArchivePinError::Cancelled)
    ));
    assert_eq!(f.authority.checks.get(), checks);
    let retired = error.retirement.ok_or("retirement")?;
    assert!(retired.recording.is_none());
    let archive = retired.archive.ok_or("archive")?;
    assert_eq!(
        archive
            .writer
            .archive
            .pending
            .ok_or("source lost")?
            .manifest()
            .root(),
        root
    );
    assert!(archive.writer.pending_checkpoint.is_some());
    assert!(archive.writer.last_durable_checkpoint.is_none());
    assert!(f.driver.cancel().is_none());
    drop(f);
    assert_eq!(p.visible_roots().count(), 0);
    Ok(())
}
