#![forbid(unsafe_code)]
//! Actual native socket EOF, root-last storage and cold replay; no fabricated end records.
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use fss_codec_mjpeg::DecodeBudget;
use fss_codec_mjpeg::http::HttpTermination;
use fss_codec_mjpeg::stream::StreamBasis;
use fss_geometry::WorkBudget;
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel,
    PublishCancellation, PublishCutPoint, PublishOutcome};
use fss_reference::ingest::http_archive::*;
use fss_reference::ingest::http_camera::*;
use fss_reference::ingest::http_camera::rgb::http_rgb_exposure;
use fss_reference::ingest::http_replay::*;
use fss_reference::ingest::http_replay::completion::*;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const JPEG: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../fss-codec-mjpeg/tests/fixtures/gray.jpg"));
const WORK: u64 = 1_000_000_000_000;
struct Directory(PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        for n in 0..128 {
            let path = std::env::temp_dir().join(format!("fss-http-end-{}-{n}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {},
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory bound".into())
    }
    fn open(&self) -> Test<LocalRootPublisher> {
        Ok(LocalRootPublisher::open(&self.0, LocalPublicationLimits::new(1024, 128, 1024, 4096,
            SpoolLimits::new(4096, 16 * 1024 * 1024, 65536, 4096)))?)
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
fn scope() -> HttpWireScope {
    HttpWireScope { stream: StreamBasis { source: [7; 32], generation: 3 },
        receive_clock: [8; 32], retention_evidence: [9; 32] }
}
fn limits() -> HttpArchiveLimits {
    HttpArchiveLimits { maximum_reads: 128, maximum_bytes: 1024 * 1024,
        maximum_scan_roots: 4096, maximum_spool_object_bytes: 65536 }
}
fn work() -> WorkBudget<'static> { WorkBudget::new(WORK) }
fn framing() -> DecodeBudget<'static> { DecodeBudget::new(WORK) }
struct Authority { route: HttpCameraRoute, clock: Instant }
impl HttpCameraAuthority for Authority {
    fn checkpoint(&self, route: &HttpCameraRoute, _: HttpCameraOperation, now: u64, deadline: u64)
        -> Result<(), HttpCameraDenial> {
        if route != &self.route { return Err(HttpCameraDenial::Unauthorized); }
        if now >= deadline || self.clock.elapsed() >= Duration::from_secs(30) { return Err(HttpCameraDenial::Deadline); }
        Ok(())
    }
}
fn response(mode: u8, final_crlf: bool) -> Vec<u8> {
    let mut body = Vec::new();
    for _ in 0..2 {
        body.extend_from_slice(format!("--fss\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n", JPEG.len()).as_bytes());
        body.extend_from_slice(JPEG); body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--fss--");
    if final_crlf { body.extend_from_slice(b"\r\n"); }
    let mut wire = b"HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=fss\r\n".to_vec();
    if mode == 1 {
        wire.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
        for bytes in body.chunks(37) {
            wire.extend_from_slice(format!("{:x}\r\n", bytes.len()).as_bytes());
            wire.extend_from_slice(bytes); wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
    } else {
        if mode == 0 { wire.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes()); }
        wire.extend_from_slice(b"\r\n"); wire.extend_from_slice(&body);
    }
    wire
}
fn capture(p: &mut LocalRootPublisher, wire: &[u8]) -> Test<(HttpCamera, HttpWireArchive, Vec<[u8; 32]>)> {
    assert!(wire.len() < 65536);
    let listener = TcpListener::bind(([127, 0, 0, 1], 0))?; listener.set_nonblocking(true)?;
    let route = HttpCameraRoute::new(scope().stream, listener.local_addr()?, "camera.invalid", "/video",
        HttpCameraSecurity::OwnerApprovedPlaintext)?;
    let auth = Authority { route: route.clone(), clock: Instant::now() };
    let mut camera = HttpCamera::connect(route, HttpCameraLimits { read_bytes: 257,
        connect_timeout_ns: 1_000_000_000, ..HttpCameraLimits::default() }, 1, 30_000_000_000, &auth)?;
    let (mut socket, _) = listener.accept()?; socket.set_nonblocking(true)?;
    let mut archive = HttpWireArchive::new(scope(), limits())?;
    assert_eq!(PreparedHttpCompletion::from_camera(&camera, &archive, &mut work()).err(), Some(HttpCompletionError::NotReady));
    let mut request = Vec::new(); let mut sent = false; let mut keys = Vec::new();
    let mut w = work(); let mut b = framing();
    for _ in 0..100_000 {
        if !sent {
            let mut buffer = [0_u8; 1024];
            match socket.read(&mut buffer) {
                Ok(n) => request.extend_from_slice(&buffer[..n]),
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {},
                Err(e) => return Err(e.into()),
            }
            assert!(request.len() < 4096);
            if request.ends_with(b"\r\n\r\n") {
                socket.set_nonblocking(false)?; socket.set_write_timeout(Some(Duration::from_secs(2)))?;
                socket.write_all(wire)?; socket.shutdown(Shutdown::Write)?; sent = true;
            }
        }
        match camera.step(2, &auth, &mut b) {
            Ok(HttpCameraStep::WireReady(receipt)) => {
                let plan = archive.prepare(camera.pending_wire().ok_or("wire lost")?, &mut w)?;
                archive.publish(&plan, p, &NeverCancel, &mut w)?;
                camera.acknowledge_wire(receipt, 2, &auth)?;
            }
            Ok(HttpCameraStep::FrameReady) => {
                assert_eq!(PreparedHttpCompletion::from_camera(&camera, &archive, &mut w).err(), Some(HttpCompletionError::NotReady));
                let r = camera.pending_frame().ok_or("frame lost")?.part().receipt();
                let f = camera.take_frame(r.ordinal, r.encoded_sha256, 2, &auth)?;
                assert_eq!(f.part().bytes(), JPEG); keys.push(http_rgb_exposure(&f, &mut w)?);
            }
            Ok(HttpCameraStep::Complete) | Err(HttpCameraError::Http(_) | HttpCameraError::Multipart(_)) => {
                assert_eq!(archive.pin().bytes, wire.len() as u64);
                return Ok((camera, archive, keys));
            }
            Ok(HttpCameraStep::Advanced | HttpCameraStep::Pending) => std::thread::yield_now(),
            Err(e) => return Err(e.into()),
        }
    }
    Err("capture step bound".into())
}
fn load(p: &LocalRootPublisher, pin: HttpWirePin) -> Test<HttpWireArchive> {
    Ok(HttpWireArchive::load(p, scope(), pin, limits(), &NeverCancel, &mut work())?)
}
fn access<'a, 'cx>(p: &'a LocalRootPublisher, cancel: &'a dyn PublishCancellation,
    w: &'a mut WorkBudget<'cx>, b: &'a mut DecodeBudget<'cx>) -> HttpReplayAccess<'a, 'cx> {
    HttpReplayAccess { publisher: p, cancellation: cancel, work: w, framing: b }
}
fn drain(r: &mut HttpWireReplay<'_>, p: &LocalRootPublisher, keys: &mut Vec<[u8; 32]>) -> Test<HttpReplayStep> {
    let mut w = work(); let mut b = framing();
    for _ in 0..100_000 {
        match r.step(access(p, &NeverCancel, &mut w, &mut b))? {
            HttpReplayStep::FrameReady => {
                let receipt = r.pending_frame().ok_or("replay frame lost")?.part().receipt();
                let f = r.take_frame(receipt.ordinal, receipt.encoded_sha256, access(p, &NeverCancel, &mut w, &mut b))?;
                assert_eq!(f.part().bytes(), JPEG); keys.push(http_rgb_exposure(&f, &mut w)?);
            }
            end @ (HttpReplayStep::Complete | HttpReplayStep::PrefixExhausted) => return Ok(end),
            _ => {},
        }
    }
    Err("replay step bound".into())
}
struct Stop;
impl PublishCancellation for Stop { fn cancel_requested(&self, _: PublishCutPoint) -> bool { true } }

#[test]
fn actual_close_eof_survives_cold_restart_without_becoming_an_archive_guess() -> Test {
    for final_crlf in [false, true] {
        let d = Directory::new()?; let mut p = d.open()?;
        let (camera, archive, live_keys) = capture(&mut p, &response(2, final_crlf))?;
        assert!(camera.totals().peer_eof);
        let plan = PreparedHttpCompletion::from_camera(&camera, &archive, &mut work())?;
        let pin = plan.pin(); assert_eq!(plan.publish(&archive, &mut p, &NeverCancel, &mut work())?.root, pin.root);
        drop(plan); drop(camera); drop(archive); drop(p);
        let p = d.open()?; let archive = load(&p, pin.wire)?;
        let proof = VerifiedHttpCompletion::load(&p, &archive, pin, &NeverCancel, &mut work())?;
        assert!(proof.peer_eof()); assert_eq!(proof.http_end().termination, HttpTermination::CloseDelimitedEof);
        for read_bytes in [1, 257, 65536] {
            let mut r = HttpWireReplay::new(&archive, pin.wire, HttpReplayLimits { read_bytes, ..HttpReplayLimits::default() })?;
            let mut keys = Vec::new(); assert_eq!(drain(&mut r, &p, &mut keys)?, HttpReplayStep::PrefixExhausted);
            assert!(r.completion().is_none());
            let step = r.finish_completed(&proof, access(&p, &NeverCancel, &mut work(), &mut framing()))?;
            assert_eq!(step, if final_crlf { HttpReplayStep::Complete } else { HttpReplayStep::FrameReady });
            assert_eq!(drain(&mut r, &p, &mut keys)?, HttpReplayStep::Complete);
            assert_eq!(keys, live_keys); assert_eq!(r.position().transferred_frames, 2);
            assert_eq!(r.finish_completed(&proof, access(&p, &NeverCancel, &mut work(), &mut framing()))?, HttpReplayStep::Complete);
        }
    }
    Ok(())
}
#[test]
fn explicit_length_and_chunk_end_records_match_replayed_native_accounting() -> Test {
    for mode in [0, 1] {
        let d = Directory::new()?; let mut p = d.open()?;
        let (camera, archive, live) = capture(&mut p, &response(mode, true))?;
        let plan = PreparedHttpCompletion::from_camera(&camera, &archive, &mut work())?;
        plan.publish(&archive, &mut p, &NeverCancel, &mut work())?;
        let proof = VerifiedHttpCompletion::load(&p, &archive, plan.pin(), &NeverCancel, &mut work())?;
        assert_eq!(proof.http_end().termination, HttpTermination::ExplicitFraming); assert!(!proof.peer_eof());
        let mut r = HttpWireReplay::new(&archive, archive.pin(), HttpReplayLimits::default())?;
        assert_eq!(r.finish_completed(&proof, access(&p, &NeverCancel, &mut work(), &mut framing())), Err(HttpCompletionError::NotReady));
        let mut keys = Vec::new(); assert_eq!(drain(&mut r, &p, &mut keys)?, HttpReplayStep::Complete);
        assert_eq!(keys, live);
        assert_eq!(r.finish_completed(&proof, access(&p, &NeverCancel, &mut work(), &mut framing()))?, HttpReplayStep::Complete);
    }
    Ok(())
}
#[test]
fn terminal_retry_and_lost_return_reuse_exact_root_and_source_closure() -> Test {
    let d = Directory::new()?; let mut p = d.open()?;
    let (camera, archive, _) = capture(&mut p, &response(2, true))?;
    let plan = PreparedHttpCompletion::from_camera(&camera, &archive, &mut work())?;
    let pin = plan.pin(); let before = p.visible_roots().count();
    assert_eq!(plan.publish(&archive, &mut p, &NeverCancel, &mut work())?.outcome, PublishOutcome::Published);
    assert_eq!(plan.publish(&archive, &mut p, &NeverCancel, &mut work())?.outcome, PublishOutcome::AlreadyPublished);
    assert_eq!(p.visible_roots().count(), before + 1); drop(p);
    let mut p = d.open()?; let a = load(&p, pin.wire)?;
    assert_eq!(VerifiedHttpCompletion::load(&p, &a, pin, &NeverCancel, &mut work())?.pin(), pin);
    assert_eq!(plan.publish(&a, &mut p, &NeverCancel, &mut work())?.outcome, PublishOutcome::AlreadyPublished);
    Ok(())
}
#[test]
fn every_publication_cut_has_honest_cold_recovery() -> Test {
    for cut in [PublishCutPoint::AfterChildrenVerified, PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite, PublishCutPoint::AfterRootRename] {
        let d = Directory::new()?; let mut p = d.open()?;
        let (c, a, _) = capture(&mut p, &response(2, true))?;
        let plan = PreparedHttpCompletion::from_camera(&c, &a, &mut work())?; let pin = plan.pin();
        p.inject_crash_at(cut);
        assert!(plan.publish(&a, &mut p, &NeverCancel, &mut work()).is_err()); assert!(p.is_poisoned());
        drop(p); let p = d.open()?; let a = load(&p, pin.wire)?;
        let loaded = VerifiedHttpCompletion::load(&p, &a, pin, &NeverCancel, &mut work());
        if cut == PublishCutPoint::AfterRootRename { assert_eq!(loaded?.pin(), pin); }
        else { assert!(loaded.is_err()); }
    }
    Ok(())
}
#[test]
fn truncated_media_cannot_mint_a_completed_capture() -> Test {
    for mode in [0, 1, 2] {
        let d = Directory::new()?; let mut p = d.open()?;
        let mut bytes = response(mode, true); bytes.truncate(bytes.len() - 12);
        let (c, a, _) = capture(&mut p, &bytes)?;
        assert!(c.failure().is_some()); assert!(c.completion().is_none());
        assert_eq!(PreparedHttpCompletion::from_camera(&c, &a, &mut work()).err(), Some(HttpCompletionError::NotReady));
    }
    Ok(())
}
#[test]
fn cancelled_or_underfunded_terminal_publication_does_not_advance_roots() -> Test {
    let d = Directory::new()?; let mut p = d.open()?;
    let (c, a, _) = capture(&mut p, &response(2, true))?;
    let plan = PreparedHttpCompletion::from_camera(&c, &a, &mut work())?; let count = p.visible_roots().count();
    assert_eq!(plan.publish(&a, &mut p, &Stop, &mut work()).err(), Some(HttpCompletionError::Cancelled));
    assert!(plan.publish(&a, &mut p, &NeverCancel, &mut WorkBudget::new(0)).is_err());
    assert_eq!(p.visible_roots().count(), count);
    assert!(p.root(&plan.pin().slot()?).is_none());
    Ok(())
}
#[test]
fn stale_completion_or_different_source_prefix_is_not_admitted() -> Test {
    let d = Directory::new()?; let mut p = d.open()?;
    let (c, a, _) = capture(&mut p, &response(2, true))?;
    let plan = PreparedHttpCompletion::from_camera(&c, &a, &mut work())?; let pin = plan.pin();
    plan.publish(&a, &mut p, &NeverCancel, &mut work())?;
    let wrong = HttpCompletionPin { wire: HttpWirePin { bytes: pin.wire.bytes - 1, ..pin.wire }, ..pin };
    assert_eq!(VerifiedHttpCompletion::load(&p, &a, wrong, &NeverCancel, &mut work()).err(), Some(HttpCompletionError::Mismatch));
    let wrong = HttpCompletionPin { root: fss_core::ContentDigest::sha256(b"not that completion"), ..pin };
    assert_eq!(VerifiedHttpCompletion::load(&p, &a, wrong, &NeverCancel, &mut work()).err(), Some(HttpCompletionError::NotDurable));
    Ok(())
}
#[test]
fn previously_verified_end_cannot_override_corrupted_originals_or_current_revocation() -> Test {
    let d = Directory::new()?; let mut p = d.open()?;
    let (c, a, _) = capture(&mut p, &response(2, true))?;
    let plan = PreparedHttpCompletion::from_camera(&c, &a, &mut work())?;
    plan.publish(&a, &mut p, &NeverCancel, &mut work())?;
    let proof = VerifiedHttpCompletion::load(&p, &a, plan.pin(), &NeverCancel, &mut work())?;
    let mut r = HttpWireReplay::new(&a, a.pin(), HttpReplayLimits::default())?;
    assert_eq!(drain(&mut r, &p, &mut Vec::new())?, HttpReplayStep::PrefixExhausted);
    let before = r.position();
    assert_eq!(r.finish_completed(&proof, access(&p, &Stop, &mut work(), &mut framing())), Err(HttpCompletionError::Cancelled));
    let (_, source) = a.reads().next().ok_or("source missing")?;
    let name: String = source.sha256.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(p.root_dir().join("spool/objects").join(name), b"corrupt original")?;
    assert!(matches!(r.finish_completed(&proof, access(&p, &NeverCancel, &mut work(), &mut framing())), Err(HttpCompletionError::Archive(_))));
    assert_eq!(r.position(), before); assert!(r.completion().is_none()); assert!(r.failure().is_none());
    Ok(())
}
#[test]
fn parser_cancellation_during_eof_finalization_latches_without_inventing_success() -> Test {
    let d = Directory::new()?; let mut p = d.open()?;
    let (c, a, _) = capture(&mut p, &response(2, false))?;
    let plan = PreparedHttpCompletion::from_camera(&c, &a, &mut work())?;
    plan.publish(&a, &mut p, &NeverCancel, &mut work())?;
    let proof = VerifiedHttpCompletion::load(&p, &a, plan.pin(), &NeverCancel, &mut work())?;
    let mut r = HttpWireReplay::new(&a, a.pin(), HttpReplayLimits::default())?;
    assert_eq!(drain(&mut r, &p, &mut Vec::new())?, HttpReplayStep::PrefixExhausted);
    assert!(matches!(r.finish_completed(&proof, access(&p, &NeverCancel, &mut work(), &mut DecodeBudget::new(0))),
        Err(HttpCompletionError::Replay(HttpReplayError::Http(_)))));
    assert!(r.failure().is_some()); assert!(r.completion().is_none());
    assert!(r.retire().multipart.is_some());
    Ok(())
}
