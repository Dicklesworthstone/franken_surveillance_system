#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
#![feature(tcp_linger)]
//! Independent real-reset HEVC custody, bounded drain and cold-work recovery contracts.
//! Synthetic media and an injected owner clock; no wall-clock deadline races or camera claims.

mod hevc_recording_support;

use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fss_core::ContentDigest;
use fss_object::SpoolLimits;
use fss_packet::hevc::{HevcAssemblyLimits, HevcConfiguration, HevcConfigurationLimits};
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
use fss_reference::rtsp::hevc_recording_collector::HevcCollectionAdmission;
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
use fss_reference::rtsp::recording_collector::CollectorLimits;
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
        let parent = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("hevc-interruption-custody");
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

struct Fixture<'a> {
    driver: JournaledLiveHevcArchive<'a, 'a>,
    peer: TcpStream,
    authority: Authority,
    now: u64,
    nonce: u128,
    originals: Vec<RecordingStep>,
    timed: Vec<TimedHevcCapture>,
}
impl<'a> Fixture<'a> {
    fn new(stores: &'a mut Stores, recording: SelectedHevcRecordingConfig) -> Test<Fixture<'a>> {
        Self::bounded(
            stores,
            recording,
            None,
            TcpLimits::default(),
            MAX_RECORDING_BYTES,
        )
    }
    fn bounded(
        stores: &'a mut Stores,
        recording: SelectedHevcRecordingConfig,
        configuration: Option<HevcConfiguration>,
        transport: TcpLimits,
        max_window_bytes: usize,
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
            transport,
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
            max_window_bytes,
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
}

#[path = "hevc_interruption_custody_contract/cases.rs"]
mod cases;
