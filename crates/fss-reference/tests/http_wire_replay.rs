#![forbid(unsafe_code)]
//! Native TCP acquisition, actual root-last files, cold parser replay and fault cuts.
use std::cell::Cell;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits};
use fss_codec_mjpeg::http::HttpHeadIdentity;
use fss_codec_mjpeg::http_mjpeg::{HttpJpegFrame, JpegWireSpan};
use fss_codec_mjpeg::stream::StreamBasis;
use fss_geometry::WorkBudget;
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel,
    PublishCancellation, PublishCutPoint};
use fss_reference::ingest::http_archive::*;
use fss_reference::ingest::http_camera::*;
use fss_reference::ingest::http_camera::rgb::http_rgb_exposure;
use fss_reference::ingest::http_replay::*;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const JPEG: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../fss-codec-mjpeg/tests/fixtures/gray.jpg"));
const WORK: u64 = 100_000_000_000;
const NOW: u64 = 1_000_000;
const DEADLINE: u64 = 60_000_000_000;
struct Directory(PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        for attempt in 0..64 {
            let path = std::env::temp_dir().join(format!("fss-http-replay-{}-{attempt}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {},
                Err(e) => return Err(e.into()),
            }
        }
        Err("fixture directory attempts exhausted".into())
    }
    fn open(&self) -> Test<LocalRootPublisher> {
        Ok(LocalRootPublisher::open(&self.0, LocalPublicationLimits::new(1024, 16, 128, 4096,
            SpoolLimits::new(4096, 16 * 1024 * 1024, 65536, 4096)))?)
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
fn scope() -> HttpWireScope {
    HttpWireScope { stream: StreamBasis { source: [7; 32], generation: 3 },
        receive_clock: [3; 32], retention_evidence: [4; 32] }
}
fn archive_limits() -> HttpArchiveLimits {
    HttpArchiveLimits { maximum_reads: 512, maximum_bytes: 1024 * 1024,
        maximum_scan_roots: 2048, maximum_spool_object_bytes: 65536 }
}
fn work() -> WorkBudget<'static> { WorkBudget::new(WORK) }
fn framing() -> DecodeBudget<'static> { DecodeBudget::new(WORK) }
fn access<'a, 'cx>(p: &'a LocalRootPublisher, cancel: &'a dyn PublishCancellation,
    work: &'a mut WorkBudget<'cx>, framing: &'a mut DecodeBudget<'cx>) -> HttpReplayAccess<'a, 'cx> {
    HttpReplayAccess { publisher: p, cancellation: cancel, work, framing }
}
fn next(r: &mut HttpWireReplay<'_>, p: &LocalRootPublisher) -> Result<HttpReplayStep, HttpReplayError> {
    r.step(access(p, &NeverCancel, &mut work(), &mut framing()))
}
fn take(r: &mut HttpWireReplay<'_>, p: &LocalRootPublisher) -> Test<HttpJpegFrame> {
    let key = r.pending_frame().ok_or("missing held frame")?.part().receipt();
    Ok(r.take_frame(key.ordinal, key.encoded_sha256, access(p, &NeverCancel, &mut work(), &mut framing()))?)
}
fn to_frame(r: &mut HttpWireReplay<'_>, p: &LocalRootPublisher) -> Test {
    for _ in 0..100_000 {
        match next(r, p)? {
            HttpReplayStep::FrameReady => return Ok(()),
            HttpReplayStep::Complete | HttpReplayStep::PrefixExhausted => return Err("frame missing".into()),
            _ => {},
        }
    }
    Err("replay step bound".into())
}
#[derive(Debug, Eq, PartialEq)]
struct FrameKey { head: HttpHeadIdentity, ordinal: u64, exposure: [u8; 32], spans: Vec<JpegWireSpan> }
fn key(f: &HttpJpegFrame) -> Test<FrameKey> {
    assert_eq!(f.part().bytes(), JPEG);
    assert_eq!(f.decode(ComponentInterpretation::Grayscale, DecodeLimits::default(), &mut framing())?.dimensions(), [17, 13]);
    Ok(FrameKey { head: f.head(), ordinal: f.part().receipt().ordinal,
        exposure: http_rgb_exposure(f, &mut work())?, spans: f.source_spans().to_vec() })
}
struct Authority { route: HttpCameraRoute, started: Instant }
impl HttpCameraAuthority for Authority {
    fn checkpoint(&self, route: &HttpCameraRoute, _: HttpCameraOperation, now: u64, deadline: u64)
        -> Result<(), HttpCameraDenial> {
        if route != &self.route { return Err(HttpCameraDenial::Unauthorized); }
        if now >= deadline || self.started.elapsed().as_nanos() + u128::from(NOW) >= u128::from(deadline) {
            return Err(HttpCameraDenial::Deadline);
        }
        Ok(())
    }
}
struct Server { socket: TcpStream, response: Vec<u8>, request: Vec<u8>, sent: bool }
impl Server {
    fn poll(&mut self) -> Test {
        if self.sent { return Ok(()); }
        let mut bytes = [0_u8; 512];
        match self.socket.read(&mut bytes) {
            Ok(0) => return Err("client stopped before GET".into()),
            Ok(n) => self.request.extend_from_slice(&bytes[..n]),
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        if self.request.len() > 4096 { return Err("request bound".into()); }
        if !self.request.ends_with(b"\r\n\r\n") { return Ok(()); }
        assert!(self.request.starts_with(b"GET /video HTTP/1.1\r\n"));
        self.socket.set_nonblocking(false)?;
        self.socket.set_write_timeout(Some(Duration::from_secs(2)))?;
        self.socket.write_all(&self.response)?;
        self.socket.shutdown(Shutdown::Write)?;
        self.sent = true;
        Ok(())
    }
}
fn response(chunked: bool, close: bool) -> Vec<u8> {
    let mut body = Vec::new();
    for _ in 0..2 {
        body.extend_from_slice(format!("--fss\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n", JPEG.len()).as_bytes());
        body.extend_from_slice(JPEG); body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--fss--\r\n");
    let mut wire = b"HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=fss\r\n".to_vec();
    if chunked {
        wire.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
        for bytes in body.chunks(37) {
            wire.extend_from_slice(format!("{:x}\r\n", bytes.len()).as_bytes());
            wire.extend_from_slice(bytes); wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
    } else {
        if !close { wire.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes()); }
        wire.extend_from_slice(b"\r\n"); wire.extend_from_slice(&body);
    }
    wire
}
/// Capture actual opaque socket reads, not caller-constructed archive metadata.
/// Parser errors deliberately keep the already published original prefix for replay.
fn acquire(p: &mut LocalRootPublisher, wire: Vec<u8>, read_bytes: usize) -> Test<(HttpWirePin, Vec<FrameKey>)> {
    if wire.len() > 65536 { return Err("loopback response bound".into()); }
    let listener = TcpListener::bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0u16)))?;
    listener.set_nonblocking(true)?;
    let route = HttpCameraRoute::new(scope().stream, listener.local_addr()?, "camera.invalid", "/video",
        HttpCameraSecurity::OwnerApprovedPlaintext)?;
    let auth = Authority { route: route.clone(), started: Instant::now() };
    let mut c = HttpCamera::connect(route, HttpCameraLimits { read_bytes,
        connect_timeout_ns: 1_000_000_000, ..HttpCameraLimits::default() }, NOW, DEADLINE, &auth)?;
    let (socket, _) = listener.accept()?; socket.set_nonblocking(true)?;
    let mut server = Server { socket, response: wire, request: Vec::new(), sent: false };
    let mut a = HttpWireArchive::new(scope(), archive_limits())?;
    let mut frames = Vec::new(); let mut b = framing(); let mut w = work();
    for _ in 0..100_000 {
        server.poll()?;
        match c.step(NOW, &auth, &mut b) {
            Ok(HttpCameraStep::WireReady(receipt)) => {
                let plan = a.prepare(c.pending_wire().ok_or("original read lost")?, &mut w)?;
                a.publish(&plan, p, &NeverCancel, &mut w)?;
                c.acknowledge_wire(receipt, NOW, &auth)?;
            }
            Ok(HttpCameraStep::FrameReady) => {
                let receipt = c.pending_frame().ok_or("native frame lost")?.part().receipt();
                let frame = c.take_frame(receipt.ordinal, receipt.encoded_sha256, NOW, &auth)?;
                a.verify_frame(p, &frame, &NeverCancel, &mut w)?;
                frames.push(key(&frame)?);
            }
            Ok(HttpCameraStep::Complete) | Err(HttpCameraError::Http(_) | HttpCameraError::Multipart(_)
                | HttpCameraError::TrailingResponse) => return Ok((a.pin(), frames)),
            Ok(HttpCameraStep::Pending | HttpCameraStep::Advanced) => std::thread::yield_now(),
            Err(error) => return Err(error.into()),
        }
    }
    Err("native acquisition step bound".into())
}
fn load(p: &LocalRootPublisher, pin: HttpWirePin) -> Test<HttpWireArchive> {
    Ok(HttpWireArchive::load(p, scope(), pin, archive_limits(), &NeverCancel, &mut work())?)
}

#[test]
fn cold_replay_rechunks_without_changing_native_frames_or_exposure_identity() -> Test {
    for chunked in [false, true] {
        let d = Directory::new()?; let mut p = d.open()?;
        let wire = response(chunked, false);
        let (pin, native) = acquire(&mut p, wire.clone(), 257)?;
        assert_eq!(native.len(), 2); assert_eq!(pin.bytes, wire.len() as u64);
        drop(p); // All acquisition, socket and archive-index owners have gone away.
        let p = d.open()?; let a = load(&p, pin)?;
        for n in [1, 17, 257, 65536] {
            let mut r = HttpWireReplay::new(&a, pin, HttpReplayLimits { read_bytes: n, ..HttpReplayLimits::default() })?;
            let mut keys = Vec::new(); let mut finished = false;
            let mut w = work(); let mut b = framing();
            for _ in 0..100_000 {
                match r.step(access(&p, &NeverCancel, &mut w, &mut b))? {
                    HttpReplayStep::FrameReady => {
                        let before = r.position();
                        for _ in 0..3 { assert_eq!(next(&mut r, &p)?, HttpReplayStep::FrameReady); }
                        assert_eq!(r.position(), before);
                        keys.push(key(&take(&mut r, &p)?)?);
                    }
                    HttpReplayStep::Complete => { finished = true; break; }
                    HttpReplayStep::PrefixExhausted => return Err("self-delimited recording became partial".into()),
                    _ => {},
                }
            }
            assert!(finished); assert_eq!(keys, native); assert_eq!(r.pin(), pin);
            assert_eq!(r.position().parsed_bytes, pin.bytes);
            assert_eq!(r.position().transferred_frames, 2);
            assert!(r.completion().is_some());
        }
    }
    Ok(())
}
#[test]
fn archive_exhaustion_does_not_fabricate_source_eof_for_close_or_truncated_inputs() -> Test {
    let mut truncated = response(false, false); truncated.truncate(truncated.len() - 7);
    for wire in [response(false, true), truncated] {
        let d = Directory::new()?; let mut p = d.open()?;
        let (pin, _) = acquire(&mut p, wire.clone(), 257)?;
        assert_eq!(pin.bytes, wire.len() as u64); drop(p);
        let p = d.open()?; let a = load(&p, pin)?;
        let mut r = HttpWireReplay::new(&a, pin, HttpReplayLimits::default())?;
        let mut partial = false; let mut frames = 0;
        for _ in 0..100_000 {
            match next(&mut r, &p)? {
                HttpReplayStep::FrameReady => { take(&mut r, &p)?; frames += 1; }
                HttpReplayStep::PrefixExhausted => { partial = true; break; }
                HttpReplayStep::Complete => return Err("prefix was treated as socket EOF".into()),
                _ => {},
            }
        }
        assert!(partial); assert!(frames >= 1); assert!(r.completion().is_none());
        let retired = r.retire(); assert!(retired.prefix_exhausted);
        assert!(retired.complete.is_none()); assert!(retired.multipart.is_some());
    }
    Ok(())
}
#[test]
fn stale_pin_and_unaccounted_storage_are_refused_before_parsing() -> Test {
    let d = Directory::new()?; let mut p = d.open()?;
    let (pin, _) = acquire(&mut p, response(false, false), 65536)?;
    let a = load(&p, pin)?;
    assert!(matches!(HttpWireReplay::new(&a, HttpWirePin { bytes: pin.bytes - 1, ..pin }, HttpReplayLimits::default()),
        Err(HttpReplayError::Configuration)));
    let empty = HttpWireArchive::new(scope(), archive_limits())?;
    let mut r = HttpWireReplay::new(&empty, empty.pin(), HttpReplayLimits::default())?;
    assert!(matches!(next(&mut r, &p), Err(HttpReplayError::Archive(_))));
    assert_eq!(r.position(), HttpReplayPosition::default());
    Ok(())
}
struct Stop;
impl PublishCancellation for Stop { fn cancel_requested(&self, _: PublishCutPoint) -> bool { true } }
#[test]
fn authority_and_work_refusal_do_not_advance_or_poison_a_fresh_cursor() -> Test {
    let d = Directory::new()?; let mut p = d.open()?;
    let (pin, _) = acquire(&mut p, response(false, false), 65536)?; let a = load(&p, pin)?;
    let mut r = HttpWireReplay::new(&a, pin, HttpReplayLimits::default())?;
    assert_eq!(r.step(access(&p, &Stop, &mut work(), &mut framing())), Err(HttpReplayError::Cancelled));
    assert!(matches!(r.step(access(&p, &NeverCancel, &mut WorkBudget::new(0), &mut framing())), Err(HttpReplayError::Work(_))));
    assert_eq!(r.position(), HttpReplayPosition::default()); assert!(r.failure().is_none());
    assert_eq!(next(&mut r, &p)?, HttpReplayStep::PrefixVerified);
    Ok(())
}
#[test]
fn parser_budget_failure_keeps_consumed_state_and_cannot_be_retried_as_fresh_input() -> Test {
    let d = Directory::new()?; let mut p = d.open()?;
    let (pin, _) = acquire(&mut p, response(false, false), 65536)?; let a = load(&p, pin)?;
    let mut r = HttpWireReplay::new(&a, pin, HttpReplayLimits::default())?;
    assert_eq!(next(&mut r, &p)?, HttpReplayStep::PrefixVerified);
    assert!(matches!(next(&mut r, &p)?, HttpReplayStep::WireLoaded { .. }));
    let error = r.step(access(&p, &NeverCancel, &mut work(), &mut DecodeBudget::new(0))).expect_err("parse budget should fail");
    assert!(matches!(error, HttpReplayError::Http(_)));
    let position = r.position(); assert_eq!(r.failure(), Some(error));
    assert_eq!(next(&mut r, &p), Err(error)); assert_eq!(r.position(), position);
    assert!(!r.retire().wire.ok_or("raw buffer dropped on parse refusal")?.bytes.is_empty());
    Ok(())
}
#[test]
fn corrupt_originals_and_wrong_keys_do_not_release_a_complete_frame() -> Test {
    let d = Directory::new()?; let mut p = d.open()?;
    let (pin, _) = acquire(&mut p, response(false, false), 65536)?; let a = load(&p, pin)?;
    let mut r = HttpWireReplay::new(&a, pin, HttpReplayLimits::default())?; to_frame(&mut r, &p)?;
    let frame = r.pending_frame().ok_or("frame missing")?;
    let receipt = frame.part().receipt(); let span = frame.source_spans()[0];
    let before = r.position();
    assert!(matches!(r.take_frame(receipt.ordinal + 1, receipt.encoded_sha256,
        access(&p, &NeverCancel, &mut work(), &mut framing())), Err(HttpReplayError::FrameMismatch)));
    assert_eq!(r.take_frame(receipt.ordinal, receipt.encoded_sha256,
        access(&p, &Stop, &mut work(), &mut framing())).err(), Some(HttpReplayError::Cancelled));
    let (_, raw) = a.reads().find(|(_, wire)| wire.range[0] <= span.wire_range[0] && span.wire_range[0] < wire.range[1])
        .ok_or("original source run missing")?;
    let name: String = raw.sha256.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(p.root_dir().join("spool/objects").join(name), b"corrupt source")?;
    assert!(matches!(r.take_frame(receipt.ordinal, receipt.encoded_sha256,
        access(&p, &NeverCancel, &mut work(), &mut framing())), Err(HttpReplayError::Archive(_))));
    assert_eq!(r.position(), before); assert_eq!(r.pending_frame().ok_or("held frame lost")?.part().bytes(), JPEG);
    Ok(())
}
#[test]
fn frame_ceiling_preserves_partial_evidence_instead_of_reporting_completion() -> Test {
    let d = Directory::new()?; let mut p = d.open()?;
    let (pin, _) = acquire(&mut p, response(false, false), 65536)?; let a = load(&p, pin)?;
    let mut r = HttpWireReplay::new(&a, pin, HttpReplayLimits { frames: 1, ..HttpReplayLimits::default() })?;
    to_frame(&mut r, &p)?; take(&mut r, &p)?;
    assert_eq!(next(&mut r, &p), Err(HttpReplayError::FrameLimit));
    assert!(r.completion().is_none()); assert_eq!(r.position().transferred_frames, 1);
    assert_eq!(r.retire().reason, Some(HttpReplayError::FrameLimit));
    Ok(())
}
#[test]
fn trailing_response_bytes_are_rejected_even_across_replay_read_boundaries() -> Test {
    let wire = b"HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=fss\r\nContent-Length: 0\r\n\r\nX".to_vec();
    let d = Directory::new()?; let mut p = d.open()?;
    let (pin, _) = acquire(&mut p, wire.clone(), 65536)?;
    assert_eq!(pin.bytes, wire.len() as u64); let a = load(&p, pin)?;
    for read_bytes in [1, 17, 65536] {
        let mut r = HttpWireReplay::new(&a, pin, HttpReplayLimits { read_bytes, ..HttpReplayLimits::default() })?;
        let mut refused = false;
        for _ in 0..1000 {
            match next(&mut r, &p) {
                Err(HttpReplayError::TrailingResponse) => { refused = true; break; }
                Ok(HttpReplayStep::PrefixVerified | HttpReplayStep::WireLoaded { .. } | HttpReplayStep::Advanced) => {},
                other => return Err(format!("unexpected trailing-source classification: {other:?}").into()),
            }
        }
        assert!(refused); assert!(r.completion().is_none());
    }
    Ok(())
}
struct Probe { seen: Cell<usize>, stop: Option<usize> }
impl PublishCancellation for Probe {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        let n = self.seen.get() + 1; self.seen.set(n); self.stop == Some(n)
    }
}
#[test]
fn late_read_cancellation_keeps_loaded_bytes_and_resumes_without_duplicate_read() -> Test {
    let d = Directory::new()?; let mut p = d.open()?;
    let (pin, _) = acquire(&mut p, response(false, false), 65536)?; let a = load(&p, pin)?;
    let mut baseline = HttpWireReplay::new(&a, pin, HttpReplayLimits::default())?;
    next(&mut baseline, &p)?;
    let count = Probe { seen: Cell::new(0), stop: None };
    assert!(matches!(baseline.step(access(&p, &count, &mut work(), &mut framing()))?, HttpReplayStep::WireLoaded { .. }));
    let mut r = HttpWireReplay::new(&a, pin, HttpReplayLimits::default())?; next(&mut r, &p)?;
    let cancel = Probe { seen: Cell::new(0), stop: Some(count.seen.get()) };
    assert_eq!(r.step(access(&p, &cancel, &mut work(), &mut framing())), Err(HttpReplayError::Cancelled));
    let loaded = r.position().loaded_bytes;
    assert!(loaded > 0); assert!(r.pending_wire().is_some()); assert!(r.failure().is_none());
    assert_eq!(next(&mut r, &p)?, HttpReplayStep::Advanced);
    assert_eq!(r.position().loaded_bytes, loaded);
    Ok(())
}
