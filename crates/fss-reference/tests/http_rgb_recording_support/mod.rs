#![forbid(unsafe_code)]
//! Actual single-thread loopback recording fixture; only its peer is test-owned.
use crate::rgb_zone_support::{Test, WORK};
use fss_codec_mjpeg::stream::StreamBasis;
use fss_object::{MAX_MANIFEST_CHILDREN, SpoolLimits};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, PublishCancellation};
use fss_reference::ingest::http_archive::HttpWireScope;
use fss_reference::ingest::http_camera::*;
use fss_reference::ingest::http_camera::rgb::HttpRgbCapture;
use fss_reference::ingest::http_recording::HttpRecordingAccess;
use fss_reference::ingest::http_replay::check::HttpCheckLimits;
use fss_reference::ingest::http_rgb_recording::*;
use fss_reference::ingest::rgb_detections::RgbDetectionContract;
use fss_reference::ingest::rgb_inference::RgbInferenceModel;
use fss_reference::ingest::rgb_tracking::{RgbZoneTracker, pipeline::RgbJpegZonePipeline};
use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, Shutdown};
use std::path::PathBuf;
use std::time::{Instant, Duration};
pub const NOW: u64 = 1_000_000;
const DEADLINE: u64 = 100_000_000_000;
pub struct Directory(pub PathBuf);
impl Directory {
    pub fn new(label: &str) -> Test<Self> {
        for attempt in 0..128 {
            let path = std::env::temp_dir().join(format!("fss-rgb-recording-{label}-{}-{attempt}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory bound".into())
    }
    pub fn open(&self) -> Test<LocalRootPublisher> {
        Ok(LocalRootPublisher::open(&self.0, LocalPublicationLimits::new(
            512, MAX_MANIFEST_CHILDREN, 512, 1024,
            SpoolLimits::new(2048, 16 * 1024 * 1024, 65536, 4096),
        ))?)
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
pub fn limits() -> HttpCheckLimits {
    let mut limits = HttpCheckLimits::default();
    limits.maximum_reads = 128;
    limits.maximum_source_bytes = 65536;
    limits.maximum_spool_object_bytes = 65536;
    limits.maximum_scan_roots = 1024;
    limits.maximum_frames = 2;
    limits.read_bytes = 257;
    limits.source_work = 100_000_000_000;
    limits.framing_work = WORK;
    limits
}
pub struct Authority {
    route: HttpCameraRoute,
    start: Instant,
    denied: Cell<Option<HttpCameraOperation>>,
}
impl Authority {
    pub fn deny(&self, operation: HttpCameraOperation) { self.denied.set(Some(operation)); }
    pub fn access<'a>(&'a self, storage: &'a dyn PublishCancellation) -> HttpRecordingAccess<'a> {
        HttpRecordingAccess { now_ns: NOW, camera: self, storage }
    }
}
impl HttpCameraAuthority for Authority {
    fn checkpoint(&self, route: &HttpCameraRoute, operation: HttpCameraOperation, now: u64, deadline: u64) -> Result<(), HttpCameraDenial> {
        if route != &self.route { return Err(HttpCameraDenial::Unauthorized); }
        if now >= deadline || self.start.elapsed().as_nanos() + u128::from(NOW) >= u128::from(deadline) { return Err(HttpCameraDenial::Deadline); }
        if self.denied.get() == Some(operation) { return Err(HttpCameraDenial::Revoked); }
        Ok(())
    }
}
pub struct Server { stream: TcpStream, request: Vec<u8>, wire: Vec<u8>, sent: bool }
impl Server {
    pub fn poll(&mut self) -> Test {
        if self.sent { return Ok(()); }
        let mut buffer = [0; 512];
        match self.stream.read(&mut buffer) {
            Ok(0) => return Err("client closed before GET".into()),
            Ok(n) => self.request.extend_from_slice(&buffer[..n]),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        if self.request.len() > 4096 { return Err("request bound".into()); }
        if self.request.ends_with(b"\r\n\r\n") {
            assert!(self.request.starts_with(b"GET /video HTTP/1.1\r\n"));
            self.stream.set_nonblocking(false)?;
            self.stream.set_write_timeout(Some(Duration::from_secs(2)))?;
            self.stream.write_all(&self.wire)?;
            self.stream.shutdown(Shutdown::Write)?;
            self.sent = true;
        }
        Ok(())
    }
}
pub fn session<'m, 't>(
    model: &'m RgbInferenceModel, head: &'m RgbDetectionContract, owner: &'t mut RgbZoneTracker,
    wire: Vec<u8>, read_bytes: usize,
) -> Test<(HttpRgbCapture<'m, 't>, Authority, Server)> {
    if wire.len() > 65536 { return Err("wire fixture bound".into()); }
    let listener = TcpListener::bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0_u16)))?;
    listener.set_nonblocking(true)?;
    let route = HttpCameraRoute::new(StreamBasis { source: [7; 32], generation: 3 }, listener.local_addr()?, "camera.invalid", "/video", HttpCameraSecurity::OwnerApprovedPlaintext)?;
    let auth = Authority { route: route.clone(), start: Instant::now(), denied: Cell::new(None) };
    let camera = HttpCamera::connect(route, HttpCameraLimits { read_bytes, connect_timeout_ns: 1_000_000_000, ..HttpCameraLimits::default() }, NOW, DEADLINE, &auth)?;
    let (stream, _) = listener.accept()?;
    stream.set_nonblocking(true)?;
    let processor = RgbJpegZonePipeline::new(model, head, owner)?;
    let capture = HttpRgbCapture::attach(camera, processor).map_err(|_| "capture attachment")?;
    Ok((capture, auth, Server { stream, request: Vec::new(), wire, sent: false }))
}
pub fn attach<'m, 't>(capture: HttpRgbCapture<'m, 't>, publisher: &LocalRootPublisher, auth: &Authority, limits: HttpCheckLimits) -> Test<HttpRgbRecording<'m, 't>> {
    let scope = HttpWireScope { stream: capture.camera().route().basis(), receive_clock: [21; 32], retention_evidence: [22; 32] };
    HttpRgbRecording::attach(capture, publisher, scope, limits, auth.access(&NeverCancel))
        .map_err(|_| "recording attachment refused".into())
}
pub fn next_barrier(recording: &mut HttpRgbRecording<'_, '_>, publisher: &mut LocalRootPublisher, auth: &Authority, server: &mut Server, commit_reads: bool) -> Test<HttpRgbRecordingStep> {
    for _ in 0..50000 {
        server.poll()?;
        match recording.poll(auth.access(&NeverCancel))? {
            HttpRgbRecordingStep::Advanced | HttpRgbRecordingStep::Pending => std::thread::yield_now(),
            HttpRgbRecordingStep::WirePrepared(plan) if commit_reads => {
                recording.commit_wire(plan, publisher, auth.access(&NeverCancel))?.acknowledgement()?;
            }
            barrier => return Ok(barrier),
        }
    }
    Err("native fixture poll bound".into())
}
