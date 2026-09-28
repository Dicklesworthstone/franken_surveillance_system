#![forbid(unsafe_code)]
//! Live authority loss while stdout/storage holds an already prepared original read.
use super::*;
use crate::ingest::http_camera::{
    HttpCameraAuthority, HttpCameraDenial, HttpCameraLimits, HttpCameraRoute, HttpCameraSecurity,
};
use crate::ingest::http_reconnect::{HttpReconnectOutcome, HttpReconnectStop};
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, NeverCancel, PublishCancellation};
use std::cell::Cell;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

type Test = Result<(), Box<dyn std::error::Error>>;
const DEADLINE: u64 = 10_000_000_000;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Authority {
    route: HttpCameraRoute,
    revoked: Cell<bool>,
}
impl HttpCameraAuthority for Authority {
    fn checkpoint(&self, route: &HttpCameraRoute, _: HttpCameraOperation, now: u64, deadline: u64)
        -> Result<(), HttpCameraDenial>
    {
        if route != &self.route { return Err(HttpCameraDenial::Unauthorized); }
        if self.revoked.get() { return Err(HttpCameraDenial::Revoked); }
        if now >= deadline { return Err(HttpCameraDenial::Deadline); }
        Ok(())
    }
}
struct DenyStorage;
impl PublishCancellation for DenyStorage {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool { true }
}

fn held_read_failure(deadline: bool) -> Test {
    let dir = Directory(std::env::temp_dir().join(format!("fss-prepared-revocation-{}-{}",
        std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))));
    let mut publisher = LocalRootPublisher::open(&dir.0, LocalPublicationLimits::new(
        128, 16, 128, 1024, SpoolLimits::new(1024, 16 * 1024 * 1024, 65536, 1024),
    ))?;
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let route = HttpCameraRoute::new(StreamBasis { source: [81; 32], generation: 1 },
        listener.local_addr()?, "camera.invalid", "/video", HttpCameraSecurity::OwnerApprovedPlaintext)?;
    let authority = Authority { route: route.clone(), revoked: Cell::new(false) };
    let mut limits = HttpCameraLimits::default();
    limits.http.wire_bytes = 65536;
    limits.http.entity_bytes = 65536;
    let scope = HttpWireScope { stream: route.basis(), receive_clock: [82; 32], retention_evidence: [83; 32] };
    let archive = HttpArchiveLimits { maximum_reads: 16, maximum_bytes: 65536,
        maximum_scan_roots: 1024, maximum_spool_object_bytes: 65536 };
    let mut run = HttpReconnectRecording::new(HttpReconnectRecordingPlan {
        slots: vec![HttpReconnectRecordingSlot { source: HttpReconnectSlot { route, limits }, scope, archive }],
        policy: HttpReconnectPolicy { initial_backoff_ns: 1, maximum_backoff_ns: 1,
            reconnect_after_complete: true, framing_work: 1_000_000 },
        source_work: 100_000_000, maximum_steps: 100_000, deadline_ns: DEADLINE,
    }, 0)?;
    let access = HttpRecordingAccess { now_ns: 1, camera: &authority, storage: &NeverCancel };
    let original = b"HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=fss\r\n\r\noriginal private bytes";
    std::thread::scope(|threads| -> Test {
        let server = threads.spawn(|| -> io::Result<()> {
            let start = Instant::now();
            let (mut socket, _) = loop {
                match listener.accept() {
                    Ok(accepted) => break accepted,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        if start.elapsed() > Duration::from_secs(3) { return Err(io::ErrorKind::TimedOut.into()); }
                        std::thread::yield_now();
                    }
                    Err(e) => return Err(e),
                }
            };
            socket.set_read_timeout(Some(Duration::from_secs(3)))?;
            socket.set_write_timeout(Some(Duration::from_secs(3)))?;
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte)?;
                request.push(byte[0]);
                if request.len() > 4096 { return Err(io::Error::other("fixture request limit")); }
            }
            socket.write_all(original)
        });
        let prepared = loop {
            match run.poll(&publisher, access)? {
                HttpReconnectRecordingStep::WirePrepared(plan) => break plan,
                HttpReconnectRecordingStep::Pending => std::thread::yield_now(),
                HttpReconnectRecordingStep::Connected(_) | HttpReconnectRecordingStep::Advanced => {}
                other => return Err(format!("unexpected pre-read state: {other:?}").into()),
            }
        };
        let before = run.totals();
        for _ in 0..3 {
            assert_eq!(run.poll(&publisher, access)?, HttpReconnectRecordingStep::WirePrepared(prepared));
        }
        assert_eq!(run.totals(), before, "live prepared polls must neither parse nor read");
        let now_ns = if deadline { DEADLINE } else { authority.revoked.set(true); 2 };
        let late = HttpRecordingAccess { now_ns, ..access };
        // Keep exercising the poll-first path. Direct commit now performs the same retirement
        // and storage-only drain; its no-intervening-poll cases live in http_reconnect_barriers.
        assert_eq!(run.pin().bytes, 0);
        assert_eq!(publisher.visible_roots().count(), 0);
        // Previously this returned forever without retiring the live source owner.
        assert_eq!(run.poll(&publisher, late)?, HttpReconnectRecordingStep::WirePrepared(prepared));
        assert!(run.source.camera().is_none(), "authority loss must close the live socket");
        assert!(run.handoff.is_some());
        assert_eq!(run.pending_wire_plan(), Some(prepared), "salvage must keep the original exact pin");
        let denied = HttpRecordingAccess { storage: &DenyStorage, ..late };
        assert!(matches!(run.commit_wire(prepared, &mut publisher, denied),
            Err(HttpReconnectRecordingError::Cancelled)));
        assert_eq!(run.pending_wire_plan(), Some(prepared));
        let result = run.commit_wire(prepared, &mut publisher, late)?;
        assert_eq!(result.publication.pin, prepared.expected_pin());
        assert_eq!(result.acknowledgement, None, "retired bytes cannot be acknowledged or parsed");
        let HttpReconnectRecordingStep::BoundaryReady(boundary) = run.poll(&publisher, late)? else {
            return Err("missing terminal custody boundary".into());
        };
        let reason = if deadline { HttpCameraError::Deadline }
            else { HttpCameraError::Denied(HttpCameraDenial::Revoked) };
        assert_eq!(boundary.source.outcome, HttpReconnectOutcome::SourceFailed(reason));
        assert_eq!(boundary.source.stop, Some(HttpReconnectStop::NotRetryable));
        assert_eq!(boundary.source.next_source, None);
        assert_eq!(boundary.prefix.bytes, before.received_bytes);
        let handoff = run.release_boundary(boundary, &publisher, late)?;
        assert_eq!(handoff.receipt(), boundary.source);
        assert_eq!(run.poll(&publisher, late)?, HttpReconnectRecordingStep::Stopped);
        assert_eq!(run.totals().connect_attempts, 1);
        assert_eq!(run.totals().frames, 0);
        let mut work = WorkBudget::new(100_000_000);
        let recovered = HttpWireArchive::load(&publisher, scope, boundary.prefix, archive, &NeverCancel, &mut work)?;
        let bytes = recovered.read_range(&publisher, [0, boundary.prefix.bytes], &NeverCancel, &mut work)?;
        assert_eq!(bytes, original[..bytes.len()]);
        server.join().map_err(|_| io::Error::other("fixture server panicked"))??;
        Ok(())
    })
}
#[test]
fn revoked_prepared_wire_is_retired_and_salvaged_without_acknowledgement() -> Test {
    held_read_failure(false)
}
#[test]
fn expired_prepared_wire_is_retired_and_salvaged_under_independent_storage_authority() -> Test {
    held_read_failure(true)
}
