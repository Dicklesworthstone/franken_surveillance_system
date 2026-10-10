#![forbid(unsafe_code)]
//! Real local TCP acquisition and durable native boundary publication; no authored history roots.

use std::cell::Cell;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fss_codec_mjpeg::ComponentInterpretation;
use fss_codec_mjpeg::stream::StreamBasis;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs};
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel};
use fss_reference::http_reconnect_history::{
    DurableReconnectRecording, DurableReconnectStep, ReconnectHistoryLimits, ReconnectHistoryPin,
};
use fss_reference::ingest::CaptureHint;
use fss_reference::ingest::http_archive::{HttpArchiveLimits, HttpWireScope};
use fss_reference::ingest::http_camera::{
    HttpCameraAuthority, HttpCameraDenial, HttpCameraLimits, HttpCameraOperation, HttpCameraRoute,
    HttpCameraSecurity,
};
use fss_reference::ingest::http_history_watch::{
    HttpHistoryWatchAuthority, HttpHistoryWatchBinding, HttpHistoryWatchLimits,
    HttpHistoryWatchPlan, HttpHistoryWatchReport, process_http_history,
};
use fss_reference::ingest::http_reconnect::{HttpReconnectPolicy, HttpReconnectSlot};
use fss_reference::ingest::http_reconnect_recording::{
    HttpReconnectRecordingPlan, HttpReconnectRecordingSlot, HttpReconnectRecordingStep,
};
use fss_reference::ingest::http_recording::HttpRecordingAccess;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchTrackerConfig, WatchZone,
};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};

pub type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub const SITE: &str = "site:http-history-watch";
pub const WORK: u64 = 100_000_000_000;
const DEADLINE: u64 = 1_000_000_000_000;

pub struct Directory(pub PathBuf);
impl Directory {
    pub fn new() -> Test<Self> {
        for attempt in 0..256 {
            let path = std::env::temp_dir().join(format!(
                "fss-http-history-watch-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("owned fixture directory bound".into())
    }
    pub fn open(&self) -> Test<LocalRootPublisher> {
        Ok(LocalRootPublisher::open(
            &self.0,
            LocalPublicationLimits::new(
                1024,
                32,
                128,
                4096,
                SpoolLimits::new(4096, 16 * 1024 * 1024, 65536, 4096),
            ),
        )?)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:http-history-watch".into(),
        operation_id: OperationId::parse("operation:http-history-watch")?,
        principal: "principal:http-history-watch".into(),
        capabilities: vec![
            "ADP-REPLAY-001".into(),
            "CAP-READ-MEDIA-001".into(),
            "CAP-OBJECT-STAGE-001".into(),
            "CAP-OBJECT-PUBLISH-001".into(),
            "CAP-RETENTION-COMMIT-001".into(),
            "CAP-DELETE-PREPARE-001".into(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(512 * 1024 * 1024)
            .storage_operations(65536)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

pub struct Owner(pub bool);
impl HttpHistoryWatchAuthority for Owner {
    fn permit(&self, _: &HttpHistoryWatchPlan, destination: &ReferenceDeployment) -> bool {
        self.0 && destination.site_lineage() == SITE
    }
}
pub fn archive_limits() -> HttpArchiveLimits {
    HttpArchiveLimits {
        maximum_reads: 512,
        maximum_bytes: 1024 * 1024,
        maximum_scan_roots: 4096,
        maximum_spool_object_bytes: 65536,
    }
}
fn scope(generation: u64) -> HttpWireScope {
    HttpWireScope {
        stream: StreamBasis {
            source: [91; 32],
            generation,
        },
        receive_clock: [92; 32],
        retention_evidence: [93; 32],
    }
}

struct CameraOwner {
    peer: SocketAddr,
    now: Cell<u64>,
}
impl HttpCameraAuthority for CameraOwner {
    fn checkpoint(
        &self,
        route: &HttpCameraRoute,
        _: HttpCameraOperation,
        now: u64,
        deadline: u64,
    ) -> Result<(), HttpCameraDenial> {
        if route.peer() != self.peer || route.basis().source != [91; 32] {
            return Err(HttpCameraDenial::Unauthorized);
        }
        if now >= deadline {
            return Err(HttpCameraDenial::Deadline);
        }
        Ok(())
    }
}
impl CameraOwner {
    fn access(&self) -> HttpRecordingAccess<'_> {
        let now = self.now.get();
        self.now.set(now + 1000);
        HttpRecordingAccess {
            now_ns: now,
            camera: self,
            storage: &NeverCancel,
        }
    }
}
fn serve(listener: &TcpListener, responses: &[Vec<u8>]) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(120);
    for response in responses {
        let (mut socket, _) = loop {
            match listener.accept() {
                Ok(pair) => break pair,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => return Err(error),
            }
        };
        read_request(&mut socket)?;
        socket.write_all(response)?;
    }
    Ok(())
}
fn read_request(socket: &mut TcpStream) -> io::Result<()> {
    socket.set_read_timeout(Some(Duration::from_secs(30)))?;
    socket.set_write_timeout(Some(Duration::from_secs(30)))?;
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() >= 4096 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut byte = [0];
        socket.read_exact(&mut byte)?;
        bytes.push(byte[0]);
    }
    Ok(())
}

pub fn acquire(
    publisher: &mut LocalRootPublisher,
    responses: &[Vec<u8>],
) -> Test<ReconnectHistoryPin> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let peer = listener.local_addr()?;
    let mut slots = Vec::new();
    for index in 0..responses.len() {
        let scope = scope(index as u64 + 1);
        let mut camera = HttpCameraLimits::default();
        camera.http.wire_bytes = 1024 * 1024;
        camera.http.entity_bytes = 1024 * 1024;
        camera.frames = 256;
        camera.connect_timeout_ns = 1_000_000_000;
        slots.push(HttpReconnectRecordingSlot {
            source: HttpReconnectSlot {
                route: HttpCameraRoute::new(
                    scope.stream,
                    peer,
                    "camera.invalid",
                    "/video",
                    HttpCameraSecurity::OwnerApprovedPlaintext,
                )?,
                limits: camera,
            },
            scope,
            archive: archive_limits(),
        });
    }
    let plan = HttpReconnectRecordingPlan {
        slots,
        policy: HttpReconnectPolicy {
            initial_backoff_ns: 1000,
            maximum_backoff_ns: 2000,
            reconnect_after_complete: true,
            framing_work: WORK,
        },
        source_work: WORK,
        maximum_steps: 1_000_000,
        deadline_ns: DEADLINE,
    };
    let session = ContentDigest::sha256(b"native HTTP history-watch fixture acquisition approval");
    let mut recording = DurableReconnectRecording::new(plan, session, WORK, 0)?;
    let owner = CameraOwner {
        peer,
        now: Cell::new(0),
    };
    std::thread::scope(|threads| -> Test<ReconnectHistoryPin> {
        let server = threads.spawn(|| serve(&listener, responses));
        let acquired = (|| -> Test<ReconnectHistoryPin> {
            for _ in 0..1_000_000 {
                match recording.poll(publisher, owner.access())? {
                    DurableReconnectStep::Source(HttpReconnectRecordingStep::WirePrepared(
                        plan,
                    )) => {
                        let committed = recording.commit_wire(plan, publisher, owner.access())?;
                        if let Some(acknowledgement) = committed.acknowledgement {
                            acknowledgement?;
                        }
                    }
                    DurableReconnectStep::Source(HttpReconnectRecordingStep::FrameReady(key)) => {
                        recording.take_frame(key, publisher, owner.access())?;
                    }
                    DurableReconnectStep::BoundaryPrepared(pin) => {
                        recording.commit_boundary(pin, publisher, owner.access())?;
                    }
                    DurableReconnectStep::BoundaryDurable(pin) => {
                        drop(recording.release_boundary(pin, publisher, owner.access())?);
                    }
                    DurableReconnectStep::Source(HttpReconnectRecordingStep::Stopped) => {
                        let pin = recording.history_pin().ok_or("missing native history")?;
                        assert_eq!(pin.connections as usize, responses.len());
                        return Ok(pin);
                    }
                    DurableReconnectStep::Source(
                        HttpReconnectRecordingStep::Pending
                        | HttpReconnectRecordingStep::Waiting { .. },
                    ) => {
                        std::thread::yield_now();
                    }
                    DurableReconnectStep::Source(
                        HttpReconnectRecordingStep::Connected(_)
                        | HttpReconnectRecordingStep::Advanced,
                    ) => {}
                    _ => return Err("unexpected native history step".into()),
                }
            }
            Err("native capture step bound".into())
        })();
        drop(recording.retire());
        server.join().map_err(|_| "native server panic")??;
        acquired
    })
}

pub fn scene(frames: usize, moving_at: usize) -> Test<Vec<Vec<u8>>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let background = vec![40_u8; 96 * 48];
    let quiet = encode_jpeg(96, 48, &background, &config)?;
    let mut result = Vec::new();
    for index in 0..frames {
        if index < moving_at {
            result.push(quiet.clone());
            continue;
        }
        let mut pixels = background.clone();
        let x = 80 - ((index - moving_at) * 2).min(64);
        for y in 16..32 {
            pixels[y * 96 + x..y * 96 + x + 16].fill(220);
        }
        result.push(encode_jpeg(96, 48, &pixels, &config)?);
    }
    Ok(result)
}
pub fn response(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for jpeg in frames {
        body.extend_from_slice(
            format!(
                "--camera\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n",
                jpeg.len()
            )
            .as_bytes(),
        );
        body.extend_from_slice(jpeg);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--camera--\r\n");
    let mut wire = format!("HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=camera\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    wire.extend(body);
    wire
}

pub struct Fixture {
    pub source_dir: Directory,
    pub target_dir: Directory,
    pub source: LocalRootPublisher,
    pub target: ReferenceDeployment,
    pub cx: ReplayCx,
    pub plan: HttpHistoryWatchPlan,
    pub limits: HttpHistoryWatchLimits,
}
impl Fixture {
    pub fn new(responses: &[Vec<u8>]) -> Test<Self> {
        let source_dir = Directory::new()?;
        let target_dir = Directory::new()?;
        let mut source = source_dir.open()?;
        let history = acquire(&mut source, responses)?;
        let cx = context(&target_dir.0)?;
        let target = ReferenceDeployment::open(&target_dir.0, SITE, &cx)?;
        let bindings = (1..=history.connections)
            .map(|generation| -> Test<_> {
                Ok(HttpHistoryWatchBinding {
                    generation: u64::from(generation),
                    sensor: SensorId::parse("sensor:http-history-watch")?,
                    stream: StreamId::parse(&format!("stream:http-history-watch-{generation}"))?,
                    receive_time: TimestampNs(1_000_000_000_000),
                    capture_hint: CaptureHint::new(
                        TimestampNs(i128::from(generation) * 100_000_000_000),
                        0,
                        10.0,
                    )?,
                })
            })
            .collect::<Test<Vec<_>>>()?;
        let plan = HttpHistoryWatchPlan {
            history,
            bindings,
            interpretation: ComponentInterpretation::Grayscale,
            zones: vec![WatchZone {
                zone_id: "driveway".into(),
                x: 0,
                y: 0,
                width: 64,
                height: 48,
            }],
            detector: WatchDetectorConfig::default(),
            tracker: WatchTrackerConfig::default(),
            options: WatchOptions::default(),
            screened: false,
        };
        let limits = HttpHistoryWatchLimits {
            history: ReconnectHistoryLimits {
                archive: archive_limits(),
                maximum_reads: 2048,
                maximum_bytes: 4 * 1024 * 1024,
            },
            maximum_frames_per_generation: 200,
            maximum_bytes_per_generation: 1024 * 1024,
            ..HttpHistoryWatchLimits::default()
        };
        Ok(Self {
            source_dir,
            target_dir,
            source,
            target,
            cx,
            plan,
            limits,
        })
    }
    pub fn run(&mut self) -> Test<HttpHistoryWatchReport> {
        Ok(process_http_history(
            &self.source,
            &mut self.target,
            &self.plan,
            &self.limits,
            &Owner(true),
            &self.cx,
            &mut fss_geometry::WorkBudget::new(WORK),
            &mut fss_codec_mjpeg::DecodeBudget::new(WORK),
        )?)
    }
}
