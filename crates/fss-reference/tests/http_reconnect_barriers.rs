#![forbid(unsafe_code)]
//! Public-API loopback regressions for cancellation while a raw-read plan is held.

use std::cell::Cell;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use fss_codec_mjpeg::stream::StreamBasis;
use fss_geometry::WorkBudget;
use fss_object::SpoolLimits;
use fss_publication::{
    LocalPublicationLimits, LocalRootPublisher, NeverCancel, PublishCancellation, PublishCutPoint,
};
use fss_reference::ingest::http_archive::{HttpArchiveLimits, HttpWireArchive, HttpWireScope};
use fss_reference::ingest::http_camera::{
    HttpCameraAuthority, HttpCameraDenial, HttpCameraError, HttpCameraLimits, HttpCameraOperation,
    HttpCameraRoute, HttpCameraSecurity,
};
use fss_reference::ingest::http_reconnect::{
    HttpReconnectOutcome, HttpReconnectPolicy, HttpReconnectSlot, HttpReconnectStop,
};
use fss_reference::ingest::http_reconnect_recording::{
    HttpReconnectRecording, HttpReconnectRecordingError, HttpReconnectRecordingPlan,
    HttpReconnectRecordingSlot, HttpReconnectRecordingStep,
};
use fss_reference::ingest::http_recording::HttpRecordingAccess;

type Test = Result<(), Box<dyn std::error::Error>>;
const DEADLINE: u64 = 5_000_000_000;
const RAW: &[u8] = b"HTTP/1.1 200 OK\r\n";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "fss-reconnect-barrier-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        )))
    }
    fn open(&self) -> Result<LocalRootPublisher, Box<dyn std::error::Error>> {
        Ok(LocalRootPublisher::open(
            &self.0,
            LocalPublicationLimits::new(
                128, 16, 128, 1024,
                SpoolLimits::new(1024, 16 * 1024 * 1024, 65536, 1024),
            ),
        )?)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Authority<'a> {
    peer: SocketAddr,
    start: &'a Instant,
    revoked: Cell<bool>,
}
impl HttpCameraAuthority for Authority<'_> {
    fn checkpoint(
        &self,
        route: &HttpCameraRoute,
        _: HttpCameraOperation,
        now: u64,
        deadline: u64,
    ) -> Result<(), HttpCameraDenial> {
        if self.revoked.get() {
            return Err(HttpCameraDenial::Revoked);
        }
        if route.peer() != self.peer || ![1, 2].contains(&route.basis().generation) {
            return Err(HttpCameraDenial::Unauthorized);
        }
        if now >= deadline || self.start.elapsed().as_nanos() >= u128::from(deadline) {
            return Err(HttpCameraDenial::Deadline);
        }
        Ok(())
    }
}
struct Stop;
impl PublishCancellation for Stop {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool { true }
}

fn plan(peer: SocketAddr) -> Result<HttpReconnectRecordingPlan, HttpCameraError> {
    let mut slots = Vec::new();
    for generation in [1, 2] {
        let stream = StreamBasis { source: [81; 32], generation };
        let mut limits = HttpCameraLimits::default();
        limits.http.wire_bytes = 65536;
        limits.http.entity_bytes = 65536;
        slots.push(HttpReconnectRecordingSlot {
            source: HttpReconnectSlot {
                route: HttpCameraRoute::new(
                    stream, peer, "camera.invalid", "/video",
                    HttpCameraSecurity::OwnerApprovedPlaintext,
                )?,
                limits,
            },
            scope: HttpWireScope {
                stream, receive_clock: [82; 32], retention_evidence: [83; 32],
            },
            archive: HttpArchiveLimits {
                maximum_reads: 16, maximum_bytes: 65536,
                maximum_scan_roots: 256, maximum_spool_object_bytes: 65536,
            },
        });
    }
    Ok(HttpReconnectRecordingPlan {
        slots,
        policy: HttpReconnectPolicy {
            initial_backoff_ns: 1_000_000, maximum_backoff_ns: 4_000_000,
            reconnect_after_complete: false, framing_work: 100_000_000,
        },
        source_work: 100_000_000, maximum_steps: 100_000, deadline_ns: DEADLINE,
    })
}

fn serve(listener: &TcpListener, start: &Instant) -> io::Result<()> {
    let (mut socket, _) = loop {
        if start.elapsed() >= Duration::from_nanos(DEADLINE) {
            return Err(io::ErrorKind::TimedOut.into());
        }
        match listener.accept() {
            Ok(pair) => break pair,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::yield_now(),
            Err(e) => return Err(e),
        }
    };
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        if request.len() == 4096 { return Err(io::ErrorKind::InvalidData.into()); }
        let mut byte = [0];
        socket.read_exact(&mut byte)?;
        request.push(byte[0]);
    }
    socket.write_all(RAW)
}

// Exercise both admission surfaces independently; commit must not rely on another poll having
// observed revocation first. Source authority and drain-storage authority are intentionally split.
fn held_read_cut(poll_first: bool, expired: bool, refuse_storage: bool) -> Test {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let peer = listener.local_addr()?;
    let start = Instant::now();
    let directory = Directory::new();
    let mut publisher = directory.open()?;
    std::thread::scope(|scope| -> Test {
        let server = scope.spawn(|| serve(&listener, &start));
        let request = plan(peer)?;
        let first = request.slots[0].clone();
        let authority = Authority { peer, start: &start, revoked: Cell::new(false) };
        let mut recording = HttpReconnectRecording::new(request, 0)?;
        let wire = loop {
            let access = HttpRecordingAccess {
                now_ns: u64::try_from(start.elapsed().as_nanos())?,
                camera: &authority, storage: &NeverCancel,
            };
            if let HttpReconnectRecordingStep::WirePrepared(wire) = recording.poll(&publisher, access)? {
                break wire;
            }
            std::thread::yield_now();
        };
        let before = recording.totals();
        assert!(wire.wire().range[1] > 0);
        assert_eq!(recording.pin().bytes, 0);
        assert_eq!(publisher.visible_roots().count(), 0);
        authority.revoked.set(!expired);
        let access = HttpRecordingAccess {
            now_ns: if expired { DEADLINE } else { u64::try_from(start.elapsed().as_nanos())? },
            camera: &authority, storage: &NeverCancel,
        };
        if poll_first {
            assert_eq!(recording.poll(&publisher, access)?,
                HttpReconnectRecordingStep::WirePrepared(wire));
            assert_eq!(recording.totals().read_calls, before.read_calls);
        }
        if refuse_storage {
            let denied = HttpRecordingAccess { storage: &Stop, ..access };
            assert!(matches!(recording.commit_wire(wire, &mut publisher, denied),
                Err(HttpReconnectRecordingError::Cancelled)));
            assert_eq!(recording.pending_wire_plan(), Some(wire));
            assert_eq!(recording.pin().bytes, 0);
        }
        let published = recording.commit_wire(wire, &mut publisher, access)?;
        assert_eq!(published.acknowledgement, None, "retired input must never be parsed");
        assert_eq!(published.publication.pin, wire.expected_pin());
        let HttpReconnectRecordingStep::BoundaryReady(boundary) = recording.poll(&publisher, access)? else {
            return Err("terminal source must reach its custody boundary".into());
        };
        assert_eq!(boundary.source.outcome, HttpReconnectOutcome::SourceFailed(if expired {
            HttpCameraError::Deadline
        } else {
            HttpCameraError::Denied(HttpCameraDenial::Revoked)
        }));
        assert_eq!(boundary.source.stop, Some(HttpReconnectStop::NotRetryable));
        assert_eq!(boundary.source.next_source, None);
        assert_eq!(boundary.prefix.bytes, before.received_bytes);
        let handoff = recording.release_boundary(boundary, &publisher, access)?;
        let source = handoff.source.ok_or("missing retired source")?;
        assert_eq!(source.wire.as_ref().ok_or("missing raw read")?.parsed_bytes(), 0);
        authority.revoked.set(false); // Restoring a grant cannot revive this source or its retries.
        assert_eq!(recording.poll(&publisher, access)?, HttpReconnectRecordingStep::Stopped);
        assert_eq!(recording.totals().connect_attempts, 1);
        assert_eq!(recording.totals().frames, 0);
        drop(recording.retire());
        drop(publisher);
        let publisher = directory.open()?;
        let mut work = WorkBudget::new(100_000_000);
        let archive = HttpWireArchive::load(&publisher, first.scope, boundary.prefix,
            first.archive, &NeverCancel, &mut work)?;
        assert_eq!(archive.read_range(&publisher, [0, boundary.prefix.bytes],
            &NeverCancel, &mut work)?, RAW[..boundary.prefix.bytes as usize]);
        server.join().map_err(|_| io::Error::other("loopback fixture panicked"))??;
        Ok(())
    })
}

#[test]
fn poll_drains_revocation_while_a_wire_plan_is_held() -> Test { held_read_cut(true, false, false) }
#[test]
fn commit_drains_revocation_without_an_intervening_poll() -> Test { held_read_cut(false, false, false) }
#[test]
fn poll_drains_expired_network_lease_under_independent_storage_authority() -> Test { held_read_cut(true, true, false) }
#[test]
fn commit_drains_expired_network_lease_without_an_intervening_poll() -> Test { held_read_cut(false, true, false) }
#[test]
fn refused_drain_storage_keeps_the_same_pin_and_original_read() -> Test { held_read_cut(true, false, true) }


#[test]
fn a_generation_published_during_backoff_is_rejected_before_tcp() -> Test {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let peer = listener.local_addr()?;
    let start = Instant::now();
    let directory = Directory::new();
    let mut publisher = directory.open()?;
    std::thread::scope(|scope| -> Test {
        let server = scope.spawn(|| -> io::Result<()> {
            // One earlier generation-2 acquisition, then the target generation-1 acquisition.
            // A third connection is forbidden: generation 2 becomes occupied during backoff.
            serve(&listener, &start)?;
            serve(&listener, &start)
        });
        let authority = Authority { peer, start: &start, revoked: Cell::new(false) };
        let mut clock = 0;
        let access = |now_ns| HttpRecordingAccess {
            now_ns, camera: &authority, storage: &NeverCancel,
        };
        let mut previous = plan(peer)?;
        previous.slots.remove(0);
        let mut previous = HttpReconnectRecording::new(previous, 0)?;
        let old_wire = loop {
            clock += 1;
            if let HttpReconnectRecordingStep::WirePrepared(wire) = previous.poll(&publisher, access(clock))? {
                break wire;
            }
            std::thread::yield_now();
        };
        // Hold the actual opaque read without publishing it yet. The namespace is still empty.
        let mut request = plan(peer)?;
        request.policy.initial_backoff_ns = 1_000_000_000;
        request.policy.maximum_backoff_ns = 1_000_000_000;
        let mut target = HttpReconnectRecording::new(request, clock)?;
        let boundary = loop {
            clock += 1;
            match target.poll(&publisher, access(clock))? {
                HttpReconnectRecordingStep::WirePrepared(wire) => {
                    target.commit_wire(wire, &mut publisher, access(clock))?;
                }
                HttpReconnectRecordingStep::BoundaryReady(b) => break b,
                _ => std::thread::yield_now(),
            }
        };
        let retry_at = boundary.source.retry_at_ns.ok_or("expected a bounded retry")?;
        clock += 1;
        drop(target.release_boundary(boundary, &publisher, access(clock))?);
        clock += 1;
        let used = target.source_work_used();
        assert_eq!(target.poll(&publisher, access(clock))?,
            HttpReconnectRecordingStep::Waiting { not_before_ns: retry_at });
        assert_eq!(target.source_work_used(), used + 1, "waiting must not rescan the store");
        clock += 1;
        let old = previous.commit_wire(old_wire, &mut publisher, access(clock))?;
        assert_eq!(old.publication.wire.basis.generation, 2);
        assert!(target.poll(&publisher, access(retry_at)).is_err(),
            "the namespace changed after waiting began; it must be reverified before connection");
        assert_eq!(target.totals().connect_attempts, 1);
        assert!(matches!(listener.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
        drop(previous.retire());
        drop(target.retire());
        server.join().map_err(|_| io::Error::other("loopback fixture panicked"))??;
        Ok(())
    })
}
