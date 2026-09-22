#![forbid(unsafe_code)]
//! Bounded single-thread loopback peer and actual neural fixture helpers.
//! Raw reads are saved in this test-owned buffer before ACK, not claimed durable.
use std::cell::Cell;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::{Duration, Instant};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget};
use fss_codec_mjpeg::stream::StreamBasis;
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_reference::ScalarExecCx;
use fss_reference::ingest::http_camera::*;
use fss_reference::ingest::http_camera::rgb::*;
use fss_reference::ingest::rgb_detections::{RgbDetectionBudget, RgbDetectionContract};
use fss_reference::ingest::rgb_inference::RgbInferenceModel;
use fss_reference::ingest::rgb_tracking::{RgbZoneTracker, RgbFrameAdmission};
use fss_reference::ingest::rgb_tracking::pipeline::RgbJpegZonePipeline;
use fss_twin::image_tracking::TrackingAvailability;
use crate::rgb_zone_support as fixture;
use fixture::{Test, WORK};
pub const NOW: u64 = 1_000_000;
const DEADLINE: u64 = 100_000_000_000;

pub struct Authority {
    route: HttpCameraRoute, started: Instant,
    deny: Cell<Option<(HttpCameraOperation, usize)>>, seen: Cell<usize>,
}
impl Authority {
    pub fn deny_on(&self, operation: HttpCameraOperation, occurrence: usize) {
        self.seen.set(0); self.deny.set(Some((operation, occurrence)));
    }
}
impl HttpCameraAuthority for Authority {
    fn checkpoint(&self, route: &HttpCameraRoute, operation: HttpCameraOperation,
        now: u64, deadline: u64) -> Result<(), HttpCameraDenial> {
        if route != &self.route { return Err(HttpCameraDenial::Unauthorized); }
        if now >= deadline || self.started.elapsed().as_nanos() + u128::from(NOW) >= u128::from(deadline) {
            return Err(HttpCameraDenial::Deadline);
        }
        if let Some((target, nth)) = self.deny.get() && operation == target {
            self.seen.set(self.seen.get() + 1);
            if self.seen.get() >= nth { return Err(HttpCameraDenial::Revoked); }
        }
        Ok(())
    }
}
pub struct Server { stream: TcpStream, response: Vec<u8>, request: Vec<u8>, sent: bool }
impl Server {
    fn poll(&mut self) -> Test {
        if self.sent { return Ok(()); }
        let mut buffer = [0_u8; 512];
        match self.stream.read(&mut buffer) {
            Ok(0) => return Err("client closed before GET".into()),
            Ok(n) => self.request.extend_from_slice(&buffer[..n]),
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        if self.request.len() > 4096 { return Err("GET fixture bound".into()); }
        if !self.request.ends_with(b"\r\n\r\n") { return Ok(()); }
        assert!(self.request.starts_with(b"GET /video HTTP/1.1\r\n"));
        let encoding = b"Accept-Encoding: identity\r\n";
        assert!(self.request.windows(encoding.len()).any(|w| w == encoding));
        self.stream.set_nonblocking(false)?;
        self.stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        self.stream.write_all(&self.response)?;
        self.stream.shutdown(Shutdown::Write)?;
        self.sent = true;
        Ok(())
    }
}
pub fn response(images: &[Vec<u8>], chunked: bool) -> Vec<u8> {
    let mut body = Vec::new();
    for image in images {
        body.extend_from_slice(format!("--fss\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n", image.len()).as_bytes());
        body.extend_from_slice(image); body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--fss--\r\n");
    let mut wire = b"HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=fss\r\n".to_vec();
    if chunked {
        wire.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
        for chunk in body.chunks(37) {
            wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            wire.extend_from_slice(chunk); wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
    } else {
        wire.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        wire.extend_from_slice(&body);
    }
    wire
}
pub fn camera(response: Vec<u8>, read_bytes: usize) -> Test<(HttpCamera, Authority, Server)> {
    // TCP handshakes complete into the listening backlog. No detached or even
    // scoped server thread is needed; both endpoints progress on this test thread.
    if response.len() > 65536 { return Err("loopback fixture wire bound".into()); }
    let listener = TcpListener::bind(([127, 0, 0, 1], 0))?;
    listener.set_nonblocking(true)?;
    let route = HttpCameraRoute::new(StreamBasis { source: [7; 32], generation: 3 },
        listener.local_addr()?, "camera.invalid", "/video", HttpCameraSecurity::OwnerApprovedPlaintext)?;
    let authority = Authority { route: route.clone(), started: Instant::now(),
        deny: Cell::new(None), seen: Cell::new(0) };
    let camera = HttpCamera::connect(route, HttpCameraLimits { read_bytes,
        connect_timeout_ns: 1_000_000_000, ..HttpCameraLimits::default() }, NOW, DEADLINE, &authority)?;
    let (stream, _) = listener.accept()?; stream.set_nonblocking(true)?;
    Ok((camera, authority, Server { stream, response, request: Vec::new(), sent: false }))
}
pub fn session<'m, 't>(model: &'m RgbInferenceModel, head: &'m RgbDetectionContract,
    owner: &'t mut RgbZoneTracker, wire: Vec<u8>, read_bytes: usize)
    -> Test<(HttpRgbCapture<'m, 't>, Authority, Server)> {
    let (camera, authority, server) = camera(wire, read_bytes)?;
    let processor = RgbJpegZonePipeline::new(model, head, owner)?;
    let capture = HttpRgbCapture::attach(camera, processor).map_err(|_| "fresh attachment refused")?;
    Ok((capture, authority, server))
}
pub fn save_wire(c: &mut HttpRgbCapture<'_, '_>, a: &Authority, receipt: HttpWireReceipt,
    saved: &mut Vec<u8>) -> Test {
    let raw = c.pending_wire().ok_or("wire lost")?;
    assert_eq!(raw.receipt(), receipt);
    assert_eq!(saved.len() as u64, receipt.range[0]);
    assert_eq!(ContentDigest::sha256(raw.bytes()).bytes(), receipt.sha256);
    saved.extend_from_slice(raw.bytes());
    c.acknowledge_wire(receipt, NOW, a)?;
    Ok(())
}
pub fn next_frame(c: &mut HttpRgbCapture<'_, '_>, a: &Authority, s: &mut Server, saved: &mut Vec<u8>) -> Test {
    let mut framing = DecodeBudget::new(WORK);
    for _ in 0..50000 {
        s.poll()?;
        match c.step(NOW, a, &mut framing)? {
            HttpRgbStep::AwaitingContext => return Ok(()),
            HttpRgbStep::Source(HttpCameraStep::WireReady(r)) => save_wire(c, a, r, saved)?,
            HttpRgbStep::Source(HttpCameraStep::Pending | HttpCameraStep::Advanced) => std::thread::yield_now(),
            _ => return Err("unexpected source phase before frame".into()),
        }
    }
    Err("native source step bound".into())
}
pub fn finish(c: &mut HttpRgbCapture<'_, '_>, a: &Authority, s: &mut Server, saved: &mut Vec<u8>) -> Test {
    let mut framing = DecodeBudget::new(WORK);
    for _ in 0..50000 {
        s.poll()?;
        match c.step(NOW, a, &mut framing)? {
            HttpRgbStep::Source(HttpCameraStep::Complete) => return Ok(()),
            HttpRgbStep::Source(HttpCameraStep::WireReady(r)) => save_wire(c, a, r, saved)?,
            HttpRgbStep::Source(HttpCameraStep::Pending | HttpCameraStep::Advanced) => std::thread::yield_now(),
            _ => return Err("unexpected unconsumed frame/result".into()),
        }
    }
    Err("native completion step bound".into())
}
pub fn context<'a>(c: &HttpRgbCapture<'_, '_>, mask: &'a [u8], n: u8,
    availability: TrackingAvailability) -> Test<HttpRgbContext<'a>> {
    let f = c.frame().ok_or("mapped frame missing")?;
    let mut source = fixture::source(f.part().bytes(), mask, n);
    source.exposure = http_rgb_exposure(f, &mut WorkBudget::new(WORK))?;
    Ok(HttpRgbContext { expected_head: f.head(), ordinal: f.part().receipt().ordinal,
        interpretation: ComponentInterpretation::YCbCr, allowed: mask,
        admission: RgbFrameAdmission::new(source, availability, ContentDigest::sha256(b"independent test capture and availability"))? })
}
pub fn analyze<'cx>(c: &mut HttpRgbCapture<'_, '_>, context: HttpRgbContext<'_>, a: &Authority,
    decoder: &mut DecodeBudget<'cx>, post: &mut RgbDetectionBudget,
    work: &mut WorkBudget<'cx>, linking: &mut WorkBudget<'cx>) -> Result<HttpRgbStep, HttpRgbError> {
    c.analyze(context, fixture::limits(), NOW, a,
        HttpRgbBudgets { decoder, projection: post, temporal: work, linking }, &ScalarExecCx::new())
}
pub fn complete(c: &mut HttpRgbCapture<'_, '_>, a: &Authority, n: u8) -> Test<HttpRgbReceipt> {
    let context = context(c, &[1; 512], n, TrackingAvailability::Available)?;
    let step = analyze(c, context, a, &mut DecodeBudget::new(WORK), &mut fixture::post(),
        &mut WorkBudget::new(WORK), &mut WorkBudget::new(WORK))?;
    match step { HttpRgbStep::ResultReady(r) => Ok(r), _ => Err("RGB computation incomplete".into()) }
}
