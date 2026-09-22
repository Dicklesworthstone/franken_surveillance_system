#![forbid(unsafe_code)]
//! Actual single-thread TCP, original-root publication, source decode and cold recovery.
use std::cell::Cell;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_object::{SpoolLimits, MAX_MANIFEST_CHILDREN};
use fss_publication::{LocalPublicationLimits, LocalPublicationState, LocalRootPublisher,
    NeverCancel, PublishCancellation, PublishCutPoint, PublishOutcome};
use fss_reference::ingest::http_archive::{HttpWireArchive, HttpArchiveLimits};
use fss_reference::ingest::http_camera::*;
use fss_reference::ingest::http_recording::*;
use fss_reference::ingest::http_replay::check::{HttpCheckDecode, HttpCheckSource};
use fss_reference::ingest::http_replay::completion::VerifiedHttpCompletion;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const JPEG: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../fss-codec-mjpeg/tests/fixtures/gray.jpg"));
const NOW: u64 = 10;
const DEADLINE: u64 = 60_000_000_000;
const WORK: u64 = 100_000_000_000;
struct Directory(PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        for n in 0..128 {
            let p = std::env::temp_dir().join(format!("fss-record-http-{}-{n}", std::process::id()));
            match std::fs::create_dir(&p) {
                Ok(()) => return Ok(Self(p)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {},
                Err(e) => return Err(e.into()),
            }
        }
        Err("fixture path capacity".into())
    }
    fn open(&self) -> Test<LocalRootPublisher> {
        Ok(LocalRootPublisher::open(&self.0, LocalPublicationLimits::new(512, MAX_MANIFEST_CHILDREN, 512, 1024,
            SpoolLimits::new(2048, 16 * 1024 * 1024, 65536, 4096)))?)
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
fn limits() -> HttpRecordingLimits {
    let mut l = HttpRecordingLimits::default();
    l.media.maximum_reads = 64; l.media.maximum_source_bytes = 65536;
    l.media.maximum_spool_object_bytes = 65536; l.media.maximum_scan_roots = 1024;
    l.media.maximum_frames = 2; l.media.read_bytes = 257;
    l.media.source_work = WORK; l.decode = HttpCheckDecode::Grayscale;
    l
}
fn source() -> HttpCheckSource {
    HttpCheckSource { source: ContentDigest::sha256(b"owned camera recording"), generation: 1,
        receive_clock: ContentDigest::sha256(b"receive clock"), retention_evidence: ContentDigest::sha256(b"retain original headers and images") }
}
struct Authority { route: HttpCameraRoute, start: Instant, deny: Cell<Option<(HttpCameraOperation, usize)>>, seen: Cell<usize> }
impl Authority {
    fn deny(&self, op: HttpCameraOperation, n: usize) { self.seen.set(0); self.deny.set(Some((op, n))); }
    fn access<'a>(&'a self, storage: &'a dyn PublishCancellation) -> HttpRecordingAccess<'a> {
        HttpRecordingAccess { now_ns: NOW, camera: self, storage }
    }
}
impl HttpCameraAuthority for Authority {
    fn checkpoint(&self, route: &HttpCameraRoute, op: HttpCameraOperation, now: u64, deadline: u64) -> Result<(), HttpCameraDenial> {
        if route != &self.route { return Err(HttpCameraDenial::Unauthorized); }
        if now >= deadline || self.start.elapsed().as_nanos() + u128::from(NOW) >= u128::from(deadline) { return Err(HttpCameraDenial::Deadline); }
        if let Some((target, nth)) = self.deny.get() && target == op {
            self.seen.set(self.seen.get() + 1);
            if self.seen.get() >= nth { return Err(HttpCameraDenial::Revoked); }
        }
        Ok(())
    }
}
struct Server { socket: TcpStream, request: Vec<u8>, wire: Vec<u8>, sent: bool }
impl Server {
    fn poll(&mut self) -> Test {
        if self.sent { return Ok(()); }
        let mut b = [0; 512];
        match self.socket.read(&mut b) {
            Ok(0) => return Err("client closed before GET".into()),
            Ok(n) => self.request.extend_from_slice(&b[..n]),
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        if self.request.len() > 4096 { return Err("GET bound".into()); }
        if self.request.ends_with(b"\r\n\r\n") {
            assert!(self.request.starts_with(b"GET /video HTTP/1.1\r\n"));
            self.socket.set_nonblocking(false)?; self.socket.set_write_timeout(Some(Duration::from_secs(2)))?;
            self.socket.write_all(&self.wire)?; self.socket.shutdown(Shutdown::Write)?; self.sent = true;
        }
        Ok(())
    }
}
fn wire(mode: u8, count: usize, image: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    for _ in 0..count {
        body.extend_from_slice(format!("--fss\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n", image.len()).as_bytes());
        body.extend_from_slice(image); body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--fss--\r\n");
    let mut result = b"HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=fss\r\n".to_vec();
    if mode == 1 {
        result.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
        for chunk in body.chunks(37) {
            result.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            result.extend_from_slice(chunk); result.extend_from_slice(b"\r\n");
        }
        result.extend_from_slice(b"0\r\n\r\n");
    } else {
        if mode == 0 { result.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes()); }
        result.extend_from_slice(b"\r\n"); result.extend_from_slice(&body);
    }
    result
}
fn connect(p: &LocalRootPublisher, bytes: Vec<u8>, limits: HttpRecordingLimits) -> Test<(HttpRecording, Authority, Server)> {
    assert!(bytes.len() < 65536);
    let listener = TcpListener::bind(std::net::SocketAddr::from(([127,0,0,1],0u16)))?; listener.set_nonblocking(true)?;
    let request = HttpRecordingRequest::new(source(), listener.local_addr()?, "camera.invalid", "/video", limits, DEADLINE)?;
    let auth = Authority { route: request.route.clone(), start: Instant::now(), deny: Cell::new(None), seen: Cell::new(0) };
    let recording = HttpRecording::connect(request, p, auth.access(&NeverCancel))?;
    let (socket, _) = listener.accept()?; socket.set_nonblocking(true)?;
    Ok((recording, auth, Server { socket, request: Vec::new(), wire: bytes, sent: false }))
}
fn next(r: &mut HttpRecording, a: &Authority, s: &mut Server) -> Test<HttpRecordingStep> {
    s.poll()?; Ok(r.poll(a.access(&NeverCancel))?)
}
fn to_wire(r: &mut HttpRecording, a: &Authority, s: &mut Server) -> Test<HttpRecordingWirePlan> {
    for _ in 0..50000 {
        match next(r,a,s)? {
            HttpRecordingStep::WirePrepared(p) => return Ok(p),
            HttpRecordingStep::Pending | HttpRecordingStep::Advanced => std::thread::yield_now(),
            _ => return Err("unexpected pre-wire state".into()),
        }
    }
    Err("wire step bound".into())
}
fn to_frame(r: &mut HttpRecording, p: &mut LocalRootPublisher, a: &Authority, s: &mut Server) -> Test<HttpRecordingFrameKey> {
    for _ in 0..50000 {
        match next(r,a,s)? {
            HttpRecordingStep::WirePrepared(plan) => { r.commit_wire(plan,p,a.access(&NeverCancel))?.acknowledgement?; }
            HttpRecordingStep::FrameReady(key) => return Ok(key),
            HttpRecordingStep::Pending | HttpRecordingStep::Advanced => std::thread::yield_now(),
            _ => return Err("unexpected pre-frame state".into()),
        }
    }
    Err("frame step bound".into())
}
#[test]
fn capture_publishes_before_parse_and_cold_recovery_verifies_all_three_framings() -> Test {
    for mode in 0..3 {
        let d = Directory::new()?; let mut p = d.open()?; let original = wire(mode,2,JPEG);
        let (mut r,a,mut s) = connect(&p,original.clone(),limits())?;
        let mut frames = 0; let mut done = None;
        for _ in 0..50000 {
            match next(&mut r,&a,&mut s)? {
                HttpRecordingStep::WirePrepared(plan) => {
                    let before = r.camera().totals(); let roots = p.visible_roots().count();
                    for _ in 0..3 { assert_eq!(r.poll(a.access(&NeverCancel))?,HttpRecordingStep::WirePrepared(plan)); }
                    assert_eq!(r.camera().totals(),before); assert_eq!(p.visible_roots().count(),roots);
                    assert!(!r.camera().pending_wire().ok_or("wire missing")?.acknowledged());
                    let receipt = r.commit_wire(plan,&mut p,a.access(&NeverCancel))?;
                    assert_eq!(receipt.publication.pin,plan.expected_pin());
                    assert_eq!(receipt.publication.local.claims.local,LocalPublicationState::Durable);
                    assert_eq!(receipt.acknowledgement,Ok(()));
                    assert!(r.camera().pending_wire().ok_or("wire missing")?.acknowledged());
                }
                HttpRecordingStep::FrameReady(key) => {
                    let before = r.camera().totals();
                    assert_eq!(r.poll(a.access(&NeverCancel))?,HttpRecordingStep::FrameReady(key));
                    assert_eq!(r.camera().totals(),before);
                    let output = r.take_frame(key,&p,a.access(&NeverCancel))?;
                    assert_eq!(output.frame.part().bytes(),JPEG);
                    assert_eq!(output.check.decoded.ok_or("decode missing")?.dimensions(),[17,13]); frames += 1;
                }
                HttpRecordingStep::CompletionPrepared(pin) => {
                    assert_eq!(frames,2); assert!(r.completion().is_none());
                    let receipt = r.commit_completion(pin,&mut p,a.access(&NeverCancel))?;
                    assert_eq!(receipt.claims.local,LocalPublicationState::Durable);
                    assert_eq!(r.poll(a.access(&NeverCancel))?,HttpRecordingStep::Complete(pin));
                    done = Some(pin); break;
                }
                HttpRecordingStep::Pending | HttpRecordingStep::Advanced => std::thread::yield_now(),
                _ => return Err("unexpected complete".into()),
            }
        }
        let completion = done.ok_or("recording not complete")?; let scope = r.scope();
        assert_eq!(r.transferred_frames(),2); let retired = r.retire(); assert_eq!(retired.complete,Some(completion));
        drop(retired); drop(p); drop(s);
        let p = d.open()?; let m = limits().media;
        let archive = HttpWireArchive::load(&p,scope,completion.wire,HttpArchiveLimits {
            maximum_reads:m.maximum_reads,maximum_bytes:m.maximum_source_bytes,maximum_scan_roots:m.maximum_scan_roots,
            maximum_spool_object_bytes:m.maximum_spool_object_bytes },&NeverCancel,&mut WorkBudget::new(WORK))?;
        assert_eq!(archive.read_range(&p,[0,completion.wire.bytes],&NeverCancel,&mut WorkBudget::new(WORK))?,original);
        let verified = VerifiedHttpCompletion::load(&p,&archive,completion,&NeverCancel,&mut WorkBudget::new(WORK))?;
        assert_eq!(verified.frames(),2); assert_eq!(verified.peer_eof(),mode==2);
    }
    Ok(())
}
#[test]
fn existing_generation_is_refused_before_a_second_connection() -> Test {
    let d=Directory::new()?; let mut p=d.open()?; let (mut r,a,mut s)=connect(&p,wire(0,2,JPEG),limits())?;
    let plan=to_wire(&mut r,&a,&mut s)?; r.commit_wire(plan,&mut p,a.access(&NeverCancel))?.acknowledgement?;
    let request=HttpRecordingRequest {route:a.route.clone(),scope:r.scope(),limits:limits(),deadline_ns:DEADLINE};
    let error=match HttpRecording::connect(request,&p,a.access(&NeverCancel)) { Ok(_)=>return Err("generation reused".into()),Err(e)=>e };
    assert!(!error.attempted); assert!(matches!(error.reason,HttpRecordingError::Archive(_)));
    Ok(())
}
#[test]
fn every_wire_publication_crash_cut_preserves_raw_input_and_exact_expected_pin() -> Test {
    for cut in [PublishCutPoint::AfterChildrenVerified,PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite,PublishCutPoint::AfterRootRename] {
        let d=Directory::new()?; let mut p=d.open()?; let (mut r,a,mut s)=connect(&p,wire(0,2,JPEG),limits())?;
        let plan=to_wire(&mut r,&a,&mut s)?; let before=r.pin();
        let bytes=r.camera().pending_wire().ok_or("raw missing")?.bytes().to_vec();
        p.inject_crash_at(cut);
        assert!(r.commit_wire(plan,&mut p,a.access(&NeverCancel)).is_err());
        assert_eq!(r.pin(),before); assert_eq!(r.pending_wire_plan(),Some(plan));
        assert_eq!(r.camera().pending_wire().ok_or("raw dropped")?.bytes(),bytes);
        assert!(!r.camera().pending_wire().ok_or("raw dropped")?.acknowledged());
        drop(p); let mut p=d.open()?;
        if cut==PublishCutPoint::AfterRootRename {
            let receipt=r.commit_wire(plan,&mut p,a.access(&NeverCancel))?;
            assert_eq!(receipt.publication.local.outcome,PublishOutcome::AlreadyPublished);
            assert_eq!(r.pin(),plan.expected_pin()); assert_eq!(receipt.acknowledgement,Ok(()));
        }
        // Earlier cuts may require explicit orphan-temp reconciliation. Never clean up here.
    }
    Ok(())
}
#[test]
fn late_camera_revocation_preserves_successful_wire_publication() -> Test {
    let d=Directory::new()?; let mut p=d.open()?; let (mut r,a,mut s)=connect(&p,wire(0,2,JPEG),limits())?;
    let plan=to_wire(&mut r,&a,&mut s)?; a.deny(HttpCameraOperation::AcknowledgeWire,1);
    let result=r.commit_wire(plan,&mut p,a.access(&NeverCancel))?;
    assert_eq!(result.publication.pin,plan.expected_pin()); assert_eq!(r.pin(),plan.expected_pin());
    assert_eq!(result.acknowledgement,Err(HttpCameraError::Denied(HttpCameraDenial::Revoked)));
    let retired=r.retire(); assert!(retired.source.wire.is_some()); assert_eq!(retired.wire_plan,Some(plan));
    Ok(())
}
struct Stop;
impl PublishCancellation for Stop { fn cancel_requested(&self,_:PublishCutPoint)->bool {true} }
#[test]
fn storage_denial_does_not_acknowledge_or_lose_the_pending_read() -> Test {
    let d=Directory::new()?; let mut p=d.open()?; let (mut r,a,mut s)=connect(&p,wire(0,2,JPEG),limits())?;
    let plan=to_wire(&mut r,&a,&mut s)?; let before=r.pin();
    assert!(matches!(r.commit_wire(plan,&mut p,a.access(&Stop)),Err(HttpRecordingError::Cancelled)));
    assert_eq!(r.pin(),before); assert_eq!(p.visible_roots().count(),0);
    r.commit_wire(plan,&mut p,a.access(&NeverCancel))?.acknowledgement?;
    Ok(())
}
#[test]
fn final_frame_release_denial_retains_decoded_pixels_and_original_frame() -> Test {
    let d=Directory::new()?; let mut p=d.open()?; let (mut r,a,mut s)=connect(&p,wire(0,2,JPEG),limits())?;
    let key=to_frame(&mut r,&mut p,&a,&mut s)?; a.deny(HttpCameraOperation::ReleaseFrame,1);
    assert!(matches!(r.take_frame(key,&p,a.access(&NeverCancel)),Err(HttpRecordingError::Source(HttpCameraError::Denied(HttpCameraDenial::Revoked)))));
    let retired=r.retire(); assert_eq!(retired.source.frame.ok_or("frame lost")?.part().bytes(),JPEG);
    assert_eq!(retired.frame_check.ok_or("accepted decode lost")?.decoded.ok_or("pixels lost")?.dimensions(),[17,13]);
    assert_eq!(retired.transferred_frames,0); Ok(())
}
#[test]
fn decode_budget_is_not_refilled_and_failed_decode_never_implies_an_empty_scene() -> Test {
    let d=Directory::new()?; let mut p=d.open()?; let mut l=limits(); l.media.decode_work=0;
    let (mut r,a,mut s)=connect(&p,wire(0,2,JPEG),l)?; let key=to_frame(&mut r,&mut p,&a,&mut s)?;
    assert!(matches!(r.take_frame(key,&p,a.access(&NeverCancel)),Err(HttpRecordingError::Decode{ordinal:1,..})));
    assert_eq!(r.transferred_frames(),0); assert!(r.pin().bytes>0); assert!(r.camera().pending_frame().is_some());
    assert!(r.completion().is_none()); assert!(r.retire().frame_error.is_some()); Ok(())
}
#[test]
fn frame_limit_leaves_a_partial_recording_without_issuing_a_terminal_root() -> Test {
    let d=Directory::new()?; let mut p=d.open()?; let mut l=limits(); l.media.maximum_frames=1;
    let (mut r,a,mut s)=connect(&p,wire(0,2,JPEG),l)?; let first=to_frame(&mut r,&mut p,&a,&mut s)?;
    r.take_frame(first,&p,a.access(&NeverCancel))?;
    let mut stopped=false;
    for _ in 0..50000 {
        s.poll()?;
        match r.poll(a.access(&NeverCancel)) {
            Ok(HttpRecordingStep::WirePrepared(plan))=>{r.commit_wire(plan,&mut p,a.access(&NeverCancel))?.acknowledgement?;}
            Ok(HttpRecordingStep::Advanced|HttpRecordingStep::Pending)=>{},
            Err(HttpRecordingError::Limit)=>{stopped=true;break;}
            other=>return Err(format!("unexpected frame-bound result: {other:?}").into()),
        }
    }
    assert!(stopped); assert_eq!(r.transferred_frames(),1); assert!(r.completion().is_none());
    assert!(r.retire().source.frame.is_some()); Ok(())
}
#[test]
fn stale_wire_and_frame_keys_cannot_release_later_input() -> Test {
    let d=Directory::new()?; let mut p=d.open()?; let (mut r,a,mut s)=connect(&p,wire(0,2,JPEG),limits())?;
    let first=to_wire(&mut r,&a,&mut s)?; r.commit_wire(first,&mut p,a.access(&NeverCancel))?.acknowledgement?;
    assert!(matches!(r.commit_wire(first,&mut p,a.access(&NeverCancel)),Err(HttpRecordingError::PlanMismatch)));
    let key=to_frame(&mut r,&mut p,&a,&mut s)?; r.take_frame(key,&p,a.access(&NeverCancel))?;
    let second=to_frame(&mut r,&mut p,&a,&mut s)?; assert_ne!(key,second);
    let counts=r.camera().totals();
    assert!(matches!(r.take_frame(key,&p,a.access(&NeverCancel)),Err(HttpRecordingError::PlanMismatch)));
    assert_eq!(r.camera().totals(),counts); r.take_frame(second,&p,a.access(&NeverCancel))?; Ok(())
}
#[test]
fn preflight_capacity_and_authority_refusals_make_no_connection() -> Test {
    let d=Directory::new()?; let p=d.open()?; let listener=TcpListener::bind(std::net::SocketAddr::from(([127,0,0,1],0u16)))?;
    listener.set_nonblocking(true)?;
    for bad in [true,false] {
        let mut l=limits(); if bad {l.media.maximum_spool_object_bytes=1024;}
        let request=HttpRecordingRequest::new(source(),listener.local_addr()?,"camera.invalid","/video",l,DEADLINE)?;
        let a=Authority {route:request.route.clone(),start:Instant::now(),deny:Cell::new(None),seen:Cell::new(0)};
        if !bad {a.deny(HttpCameraOperation::Connect,1);}
        let result=HttpRecording::connect(request,&p,a.access(&NeverCancel));
        let error=match result {Ok(_)=>return Err("preflight accepted".into()),Err(e)=>e};
        assert!(!error.attempted); assert!(matches!(listener.accept(),Err(e) if e.kind()==io::ErrorKind::WouldBlock));
    }
    Ok(())
}
