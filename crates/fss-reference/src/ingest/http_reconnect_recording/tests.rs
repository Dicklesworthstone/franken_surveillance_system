#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Real loopback TCP, root-last disk publication and cold source recovery; no mock archive.
use super::*;
use crate::ingest::http_camera::{
    HttpCameraAuthority, HttpCameraDenial, HttpCameraLimits, HttpCameraRoute, HttpCameraSecurity,
};
use crate::ingest::http_reconnect::{HttpReconnectOutcome, HttpReconnectStop};
use fss_codec_mjpeg::http::HttpError;
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, NeverCancel, PublishCancellation};
use std::cell::Cell;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

type Test = Result<(), Box<dyn std::error::Error>>;
const JPEG: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../fss-codec-mjpeg/tests/fixtures/gray.jpg"
));
const DEADLINE: u64 = 5_000_000_000;
static NEXT: AtomicU64 = AtomicU64::new(1);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "fss-reconnect-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
    fn open(&self) -> Result<LocalRootPublisher, Box<dyn std::error::Error>> {
        Ok(LocalRootPublisher::open(
            &self.0,
            LocalPublicationLimits::new(
                128,
                16,
                128,
                1024,
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
fn plan(peer: SocketAddr, count: u64) -> HttpReconnectRecordingPlan {
    let slots = (1..=count)
        .map(|generation| {
            let basis = StreamBasis {
                source: [71; 32],
                generation,
            };
            let mut limits = HttpCameraLimits::default();
            limits.http.wire_bytes = 1024 * 1024;
            limits.http.entity_bytes = 1024 * 1024;
            limits.read_bytes = 4096;
            limits.frames = 8;
            HttpReconnectRecordingSlot {
                source: HttpReconnectSlot {
                    route: HttpCameraRoute::new(
                        basis,
                        peer,
                        "camera.invalid",
                        "/video",
                        HttpCameraSecurity::OwnerApprovedPlaintext,
                    )
                    .expect("fixture route"),
                    limits,
                },
                scope: HttpWireScope {
                    stream: basis,
                    receive_clock: [72; 32],
                    retention_evidence: [73; 32],
                },
                archive: HttpArchiveLimits {
                    maximum_reads: 32,
                    maximum_bytes: 1024 * 1024,
                    maximum_scan_roots: 1024,
                    maximum_spool_object_bytes: 65536,
                },
            }
        })
        .collect();
    HttpReconnectRecordingPlan {
        slots,
        policy: HttpReconnectPolicy {
            initial_backoff_ns: 1_000_000,
            maximum_backoff_ns: 4_000_000,
            reconnect_after_complete: false,
            framing_work: 1_000_000_000,
        },
        source_work: 1_000_000_000,
        maximum_steps: 100_000,
        deadline_ns: DEADLINE,
    }
}
fn response(truncated: bool) -> Vec<u8> {
    let mut body = format!(
        "--fss\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n",
        JPEG.len()
    )
    .into_bytes();
    body.extend_from_slice(JPEG);
    body.extend_from_slice(if truncated {
        b"\r\n--fss\r\n"
    } else {
        b"\r\n--fss--\r\n"
    });
    let declared = body.len() + if truncated { 100 } else { 0 };
    let mut wire = format!("HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=fss\r\nContent-Length: {declared}\r\n\r\n").into_bytes();
    wire.extend_from_slice(&body);
    wire
}
struct Authority<'a> {
    routes: Vec<HttpCameraRoute>,
    start: &'a Instant,
    ready: &'a AtomicBool,
    revoked: Cell<bool>,
    post_read_revoke: bool,
    late_ack_revoke: bool,
    reads: Cell<u32>,
    acks: Cell<u32>,
}
impl HttpCameraAuthority for Authority<'_> {
    fn checkpoint(
        &self,
        route: &HttpCameraRoute,
        op: HttpCameraOperation,
        now: u64,
        deadline: u64,
    ) -> Result<(), HttpCameraDenial> {
        if self.revoked.get() {
            return Err(HttpCameraDenial::Revoked);
        }
        if !self.routes.contains(route) {
            return Err(HttpCameraDenial::Unauthorized);
        }
        if now >= deadline || self.start.elapsed().as_nanos() >= u128::from(deadline) {
            return Err(HttpCameraDenial::Deadline);
        }
        if op == HttpCameraOperation::Read && self.post_read_revoke {
            let n = self.reads.get();
            self.reads.set(n + 1);
            if n == 0 {
                // Fixture-only synchronization: response is already written before this first read.
                while !self.ready.load(Ordering::Acquire) {
                    if self.start.elapsed() >= Duration::from_nanos(deadline) {
                        return Err(HttpCameraDenial::Deadline);
                    }
                    std::thread::yield_now();
                }
            } else {
                self.revoked.set(true);
                return Err(HttpCameraDenial::Revoked);
            }
        }
        if op == HttpCameraOperation::AcknowledgeWire && self.late_ack_revoke {
            let n = self.acks.get();
            self.acks.set(n + 1);
            if n == 1 {
                self.revoked.set(true);
                return Err(HttpCameraDenial::Revoked);
            }
        }
        Ok(())
    }
}
struct Stop;
impl PublishCancellation for Stop {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        true
    }
}
fn serve(
    listener: &TcpListener,
    responses: &[Vec<u8>],
    start: &Instant,
    ready: &AtomicBool,
) -> io::Result<Vec<Vec<u8>>> {
    let mut requests = Vec::new();
    for response in responses {
        let (mut socket, _) = loop {
            if start.elapsed() >= Duration::from_nanos(DEADLINE) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "fixture accept deadline",
                ));
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
            let mut byte = [0];
            socket.read_exact(&mut byte)?;
            request.push(byte[0]);
            if request.len() > 4096 {
                return Err(io::Error::other("fixture request bound"));
            }
        }
        requests.push(request);
        socket.write_all(response)?;
        ready.store(true, Ordering::Release);
    }
    Ok(requests)
}
fn access<'a>(auth: &'a Authority<'_>) -> HttpRecordingAccess<'a> {
    HttpRecordingAccess {
        now_ns: auth.start.elapsed().as_nanos() as u64,
        camera: auth,
        storage: &NeverCancel,
    }
}

#[test]
fn mismatched_source_or_impossible_custody_reservation_is_refused_without_io() {
    let peer = SocketAddr::from(([127, 0, 0, 1], 1));
    let mut p = plan(peer, 2);
    p.slots[1].scope.stream.generation += 1;
    assert!(matches!(
        HttpReconnectRecording::new(p, 0),
        Err(HttpReconnectRecordingError::Configuration)
    ));
    let mut p = plan(peer, 1);
    p.slots[0].archive.maximum_bytes -= 1;
    assert!(matches!(
        HttpReconnectRecording::new(p, 0),
        Err(HttpReconnectRecordingError::Configuration)
    ));
    let mut p = plan(peer, 1);
    p.maximum_steps = 0;
    assert!(HttpReconnectRecording::new(p, 0).is_err());
}

#[test]
fn storage_cancellation_and_source_work_exhaustion_precede_tcp() -> Test {
    let d = Directory::new();
    let publisher = d.open()?;
    let start = Instant::now();
    let ready = AtomicBool::new(false);
    let p = plan(SocketAddr::from(([127, 0, 0, 1], 1)), 1);
    let auth = Authority {
        routes: p.slots.iter().map(|s| s.source.route.clone()).collect(),
        start: &start,
        ready: &ready,
        revoked: Cell::new(false),
        post_read_revoke: false,
        late_ack_revoke: false,
        reads: Cell::new(0),
        acks: Cell::new(0),
    };
    let mut run = HttpReconnectRecording::new(p, 0)?;
    let denied = HttpRecordingAccess {
        storage: &Stop,
        ..access(&auth)
    };
    assert_eq!(
        run.poll(&publisher, denied),
        Err(HttpReconnectRecordingError::Cancelled)
    );
    assert_eq!(run.totals().connect_attempts, 0);
    let mut p = plan(SocketAddr::from(([127, 0, 0, 1], 1)), 1);
    p.source_work = 1;
    let mut run = HttpReconnectRecording::new(p, 0)?;
    assert!(run.poll(&publisher, access(&auth)).is_err());
    assert_eq!(run.totals().connect_attempts, 0);
    assert_eq!(publisher.visible_roots().count(), 0);
    Ok(())
}

#[test]
fn truncated_then_complete_connections_preserve_exact_durable_generations() -> Test {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let peer = listener.local_addr()?;
    let responses = vec![response(true), response(false)];
    let start = Instant::now();
    let ready = AtomicBool::new(false);
    let d = Directory::new();
    let mut publisher = d.open()?;
    std::thread::scope(|scope| -> Test {
        let server = scope.spawn(|| serve(&listener, &responses, &start, &ready));
        let p = plan(peer, 2);
        let slots = p.slots.clone();
        let auth = Authority {
            routes: slots.iter().map(|s| s.source.route.clone()).collect(),
            start: &start,
            ready: &ready,
            revoked: Cell::new(false),
            post_read_revoke: false,
            late_ack_revoke: false,
            reads: Cell::new(0),
            acks: Cell::new(0),
        };
        let mut run = HttpReconnectRecording::new(p, 0)?;
        let mut boundaries = Vec::new();
        let mut frames = Vec::new();
        let mut previous_work = 0;
        loop {
            match run.poll(&publisher, access(&auth))? {
                HttpReconnectRecordingStep::WirePrepared(wire) => {
                    let before = run.pin();
                    assert_eq!(before.bytes, wire.wire().range[0]);
                    assert_eq!(run.pending_wire_plan(), Some(wire));
                    // Merely repeating a prepared observation must not publish or acknowledge.
                    assert_eq!(
                        run.poll(&publisher, access(&auth))?,
                        HttpReconnectRecordingStep::WirePrepared(wire)
                    );
                    assert_eq!(run.pin(), before);
                    let denied = HttpRecordingAccess {
                        storage: &Stop,
                        ..access(&auth)
                    };
                    assert!(matches!(
                        run.commit_wire(wire, &mut publisher, denied),
                        Err(HttpReconnectRecordingError::Cancelled)
                    ));
                    assert_eq!(run.pin(), before);
                    assert_eq!(run.pending_wire_plan(), Some(wire));
                    let committed = run.commit_wire(wire, &mut publisher, access(&auth))?;
                    assert_eq!(committed.publication.pin, wire.expected_pin());
                    assert_eq!(committed.acknowledgement, Some(Ok(())));
                }
                HttpReconnectRecordingStep::FrameReady(key) => {
                    let frame = run.take_frame(key, &publisher, access(&auth))?;
                    assert_eq!(frame.part().bytes(), JPEG);
                    frames.push((key.head().wire.generation, key.ordinal()));
                }
                HttpReconnectRecordingStep::BoundaryReady(boundary) => {
                    assert_eq!(boundary.prefix.bytes, boundary.source.totals.received_bytes);
                    assert!(run.source_work_used() > previous_work);
                    previous_work = run.source_work_used();
                    let attempts = run.totals().connect_attempts;
                    let mut wrong = boundary;
                    wrong.prefix.bytes += 1;
                    assert!(matches!(
                        run.release_boundary(wrong, &publisher, access(&auth)),
                        Err(HttpReconnectRecordingError::PlanMismatch)
                    ));
                    let denied = HttpRecordingAccess {
                        storage: &Stop,
                        ..access(&auth)
                    };
                    assert!(matches!(
                        run.release_boundary(boundary, &publisher, denied),
                        Err(HttpReconnectRecordingError::Cancelled)
                    ));
                    assert_eq!(run.totals().connect_attempts, attempts);
                    let h = run.release_boundary(boundary, &publisher, access(&auth))?;
                    assert_eq!(h.receipt(), boundary.source);
                    boundaries.push(boundary);
                }
                HttpReconnectRecordingStep::Stopped => break,
                HttpReconnectRecordingStep::Pending
                | HttpReconnectRecordingStep::Waiting { .. } => std::thread::yield_now(),
                HttpReconnectRecordingStep::Connected(_) | HttpReconnectRecordingStep::Advanced => {
                }
            }
        }
        assert_eq!(frames, vec![(1, 1), (2, 1)]);
        assert_eq!(boundaries.len(), 2);
        assert_eq!(
            boundaries[0].source.outcome,
            HttpReconnectOutcome::SourceFailed(HttpCameraError::Http(HttpError::Truncated))
        );
        assert_eq!(
            boundaries[0].source.next_source,
            Some(slots[1].scope.stream)
        );
        assert_eq!(boundaries[1].source.outcome, HttpReconnectOutcome::Complete);
        assert_eq!(boundaries[1].source.stop, Some(HttpReconnectStop::Complete));
        assert_eq!(run.totals().connect_attempts, 2);
        assert_eq!(
            run.totals().received_bytes,
            responses.iter().map(|r| r.len() as u64).sum::<u64>()
        );
        let requests = server
            .join()
            .map_err(|_| io::Error::other("fixture server panicked"))??;
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0], requests[1],
            "new generation gets a whole fresh request, not a suffix"
        );
        drop(run.retire());
        drop(publisher);
        let publisher = d.open()?; // cold reopen: all source owners and archive indexes were lost
        for ((slot, boundary), bytes) in slots.iter().zip(&boundaries).zip(&responses) {
            let mut work = WorkBudget::new(1_000_000_000);
            let archive = HttpWireArchive::load(
                &publisher,
                slot.scope,
                boundary.prefix,
                slot.archive,
                &NeverCancel,
                &mut work,
            )?;
            assert_eq!(
                archive.read_range(
                    &publisher,
                    [0, boundary.prefix.bytes],
                    &NeverCancel,
                    &mut work
                )?,
                *bytes
            );
        }
        // Occupied generation is recovery, never permission to issue a new GET.
        let mut reused = HttpReconnectRecording::new(plan(peer, 2), 0)?;
        assert!(reused.poll(&publisher, access(&auth)).is_err());
        assert_eq!(reused.totals().connect_attempts, 0);
        Ok(())
    })
}

fn revoked_source_is_durable(post_read: bool) -> Test {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let peer = listener.local_addr()?;
    let responses = vec![response(false)];
    let start = Instant::now();
    let ready = AtomicBool::new(false);
    let d = Directory::new();
    let mut publisher = d.open()?;
    std::thread::scope(|scope| -> Test {
        let server = scope.spawn(|| serve(&listener, &responses, &start, &ready));
        let p = plan(peer, 2);
        let auth = Authority {
            routes: p.slots.iter().map(|s| s.source.route.clone()).collect(),
            start: &start,
            ready: &ready,
            revoked: Cell::new(false),
            post_read_revoke: post_read,
            late_ack_revoke: !post_read,
            reads: Cell::new(0),
            acks: Cell::new(0),
        };
        let mut run = HttpReconnectRecording::new(p, 0)?;
        let mut saw_publication = false;
        loop {
            match run.poll(&publisher, access(&auth))? {
                HttpReconnectRecordingStep::WirePrepared(wire) => {
                    let committed = run.commit_wire(wire, &mut publisher, access(&auth))?;
                    assert_eq!(committed.publication.pin, wire.expected_pin());
                    if post_read {
                        assert_eq!(
                            committed.acknowledgement, None,
                            "retired bytes must not be parsed"
                        );
                    } else {
                        assert!(matches!(
                            committed.acknowledgement,
                            Some(Err(HttpReconnectError::Source(HttpCameraError::Denied(
                                HttpCameraDenial::Revoked
                            ))))
                        ));
                    }
                    saw_publication = true;
                }
                HttpReconnectRecordingStep::BoundaryReady(boundary) => {
                    assert!(saw_publication);
                    assert!(
                        boundary.prefix.bytes > 0,
                        "post-read failure must retain actual input"
                    );
                    assert_eq!(boundary.prefix.bytes, boundary.source.totals.received_bytes);
                    assert_eq!(boundary.source.stop, Some(HttpReconnectStop::NotRetryable));
                    assert_eq!(boundary.source.next_source, None);
                    let h = run.release_boundary(boundary, &publisher, access(&auth))?;
                    assert!(h.source.expect("retired source").wire.is_some());
                }
                HttpReconnectRecordingStep::Stopped => break,
                HttpReconnectRecordingStep::FrameReady(_) => {
                    panic!("revoked source must not parse frames")
                }
                HttpReconnectRecordingStep::Pending
                | HttpReconnectRecordingStep::Waiting { .. } => std::thread::yield_now(),
                HttpReconnectRecordingStep::Connected(_) | HttpReconnectRecordingStep::Advanced => {
                }
            }
        }
        assert_eq!(
            run.totals().connect_attempts,
            1,
            "no reserved retry after revocation"
        );
        assert_eq!(run.totals().frames, 0);
        assert_eq!(
            server
                .join()
                .map_err(|_| io::Error::other("fixture server panicked"))??
                .len(),
            1
        );
        Ok(())
    })
}
#[test]
fn raw_read_survives_post_read_revocation_and_is_published_without_ack_or_retry() -> Test {
    revoked_source_is_durable(true)
}
#[test]
fn durable_publication_remains_visible_after_late_camera_ack_revocation() -> Test {
    revoked_source_is_durable(false)
}

#[test]
fn poll_budget_is_whole_recording_and_retirement_preserves_pending_keys() -> Test {
    let d = Directory::new();
    let publisher = d.open()?;
    let start = Instant::now();
    let ready = AtomicBool::new(false);
    let p = plan(SocketAddr::from(([127, 0, 0, 1], 1)), 2);
    let auth = Authority {
        routes: p.slots.iter().map(|s| s.source.route.clone()).collect(),
        start: &start,
        ready: &ready,
        revoked: Cell::new(false),
        post_read_revoke: false,
        late_ack_revoke: false,
        reads: Cell::new(0),
        acks: Cell::new(0),
    };
    let mut run = HttpReconnectRecording::new(p, 0)?;
    run.steps = run.maximum_steps;
    assert_eq!(
        run.poll(&publisher, access(&auth)),
        Err(HttpReconnectRecordingError::Limit)
    );
    assert_eq!(run.totals().connect_attempts, 0);
    let retired = run.retire();
    assert_eq!(retired.steps, 100_000);
    assert_eq!(retired.archives.len(), 2);
    assert!(retired.wire_plan.is_none());
    Ok(())
}
