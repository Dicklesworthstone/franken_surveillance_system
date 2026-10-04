#![forbid(unsafe_code)]
//! Public-API loopback regressions for cancellation while a raw-read plan is held.
//!
//! Time is explicit: every admission `now_ns` and the authority's independent live check read
//! one test-owned [`TestClock`], never wall time, so a stalled worker or a slow loopback peer
//! cannot spend the lease. Deadline refusals are forced by moving that clock. A `Pending` poll
//! never spins: the client blocks on the peer's progress signal, so injected scheduling delay
//! cannot exhaust the step budget either. Wall-clock bounds remain only as harness hang guards.

use std::cell::Cell;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

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
// Test-clock lease. Large enough that the native connect timeout (min(limit, lease left)) is a
// hang guard, not a contract, even if a worker stalls inside the kernel `connect`.
const DEADLINE: u64 = 60_000_000_000;
// Test-clock nanoseconds per admission; at most `maximum_steps` ticks can ever elapse.
const TICK: u64 = 1_000;
// Harness-only wall bound for a broken fixture; never reached while the client is live.
const HANG_GUARD: Duration = Duration::from_secs(300);
const NO_STALL: Duration = Duration::ZERO;
// Longer than the old 5 s wall-clock lease, which this peer used to exhaust.
const INJECTED_STALL: Duration = Duration::from_secs(6);
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

/// The single time source for admission and for the authority's independent live check.
#[derive(Default)]
struct TestClock(Cell<u64>);
impl TestClock {
    fn now(&self) -> u64 {
        self.0.get()
    }
    fn advance(&self, ns: u64) -> u64 {
        let next = self.0.get().saturating_add(ns);
        self.0.set(next);
        next
    }
    /// Monotone: forcing expiry can only move the live clock forward.
    fn set(&self, at: u64) {
        self.0.set(at.max(self.0.get()));
    }
}

struct Authority<'a> {
    peer: SocketAddr,
    live: &'a TestClock,
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
        if now >= deadline || self.live.now() >= deadline {
            return Err(HttpCameraDenial::Deadline);
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

fn plan(peer: SocketAddr) -> Result<HttpReconnectRecordingPlan, HttpCameraError> {
    let mut slots = Vec::new();
    for generation in [1, 2] {
        let stream = StreamBasis {
            source: [81; 32],
            generation,
        };
        let mut limits = HttpCameraLimits::default();
        limits.http.wire_bytes = 65536;
        limits.http.entity_bytes = 65536;
        // Kernel connect is real wall time: keep it a generous hang guard (validated maximum).
        limits.connect_timeout_ns = 60_000_000_000;
        slots.push(HttpReconnectRecordingSlot {
            source: HttpReconnectSlot {
                route: HttpCameraRoute::new(
                    stream,
                    peer,
                    "camera.invalid",
                    "/video",
                    HttpCameraSecurity::OwnerApprovedPlaintext,
                )?,
                limits,
            },
            scope: HttpWireScope {
                stream,
                receive_clock: [82; 32],
                retention_evidence: [83; 32],
            },
            archive: HttpArchiveLimits {
                maximum_reads: 16,
                maximum_bytes: 65536,
                maximum_scan_roots: 256,
                maximum_spool_object_bytes: 65536,
            },
        });
    }
    Ok(HttpReconnectRecordingPlan {
        slots,
        policy: HttpReconnectPolicy {
            initial_backoff_ns: 1_000_000,
            maximum_backoff_ns: 4_000_000,
            reconnect_after_complete: false,
            framing_work: 100_000_000,
        },
        source_work: 100_000_000,
        maximum_steps: 100_000,
        deadline_ns: DEADLINE,
    })
}

/// Loopback peer: optionally stalls (injected scheduling delay) before responding, then reports
/// that its response bytes were written.
struct Peer<'a> {
    stall: Duration,
    written: mpsc::Sender<()>,
    abandoned: &'a AtomicBool,
}
/// Set when the client side ends, so a peer still waiting for a connection stops.
struct Abandon<'a>(&'a AtomicBool);
impl Drop for Abandon<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Client side of a `Pending` poll. Until the peer has written the awaited response, block on
/// its progress signal: no admission, step or clock tick is spent while it stalls. Afterwards a
/// bounded backoff covers loopback delivery. Nothing here decides a deadline.
struct Readiness {
    written: mpsc::Receiver<()>,
    responses: usize,
    backoff: Duration,
}
impl Readiness {
    fn new(written: mpsc::Receiver<()>) -> Self {
        Self {
            written,
            responses: 0,
            backoff: Duration::from_millis(1),
        }
    }
    /// Wait before re-polling connection number `connection` (1-based).
    fn pending(&mut self, connection: usize) -> Test {
        if self.responses < connection {
            while self.responses < connection {
                self.written
                    .recv()
                    .map_err(|_| "loopback peer stopped before responding")?;
                self.responses += 1;
            }
            self.backoff = Duration::from_millis(1);
        } else {
            std::thread::sleep(self.backoff);
            self.backoff = (self.backoff * 2).min(Duration::from_millis(50));
        }
        Ok(())
    }
}

fn serve(listener: &TcpListener, peer: &Peer<'_>) -> io::Result<()> {
    let (mut socket, _) = loop {
        match listener.accept() {
            Ok(pair) => break pair,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if peer.abandoned.load(Ordering::Acquire) {
                    return Err(io::Error::other("client ended before connecting"));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => return Err(e),
        }
    };
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(HANG_GUARD))?;
    socket.set_write_timeout(Some(HANG_GUARD))?;
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        if request.len() == 4096 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut byte = [0];
        socket.read_exact(&mut byte)?;
        request.push(byte[0]);
    }
    std::thread::sleep(peer.stall);
    socket.write_all(RAW)?;
    // A client that already failed dropped its receiver; its own error is the report.
    let _ = peer.written.send(());
    Ok(())
}

/// How live authority ends while the raw-read plan is held.
#[derive(Clone, Copy, PartialEq)]
enum Cut {
    /// The grant is revoked at a current admission time.
    Revoked,
    /// Admission time itself reaches the lease end; the authority's live clock has not.
    AdmissionExpired,
    /// Admission time is current, but the authority's independent live clock reached the lease end.
    LiveClockExpired,
}

// Exercise both admission surfaces independently; commit must not rely on another poll having
// observed revocation first. Source authority and drain-storage authority are intentionally split.
fn held_read_cut(poll_first: bool, cut: Cut, refuse_storage: bool, stall: Duration) -> Test {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let peer = listener.local_addr()?;
    let clock = TestClock::default();
    let abandoned = AtomicBool::new(false);
    let (written, ready) = mpsc::channel();
    let mut ready = Readiness::new(ready);
    let directory = Directory::new();
    let mut publisher = directory.open()?;
    std::thread::scope(|scope| -> Test {
        let fixture = Peer {
            stall,
            written,
            abandoned: &abandoned,
        };
        let server = scope.spawn(move || serve(&listener, &fixture));
        let _abandon = Abandon(&abandoned);
        let request = plan(peer)?;
        let first = request.slots[0].clone();
        let authority = Authority {
            peer,
            live: &clock,
            revoked: Cell::new(false),
        };
        let mut recording = HttpReconnectRecording::new(request, 0)?;
        let wire = loop {
            let access = HttpRecordingAccess {
                now_ns: clock.advance(TICK),
                camera: &authority,
                storage: &NeverCancel,
            };
            match recording.poll(&publisher, access)? {
                HttpReconnectRecordingStep::WirePrepared(wire) => break wire,
                HttpReconnectRecordingStep::Pending => ready.pending(1)?,
                HttpReconnectRecordingStep::Connected(_) | HttpReconnectRecordingStep::Advanced => {
                }
                other => {
                    return Err(format!("unexpected step before the raw read: {other:?}").into());
                }
            }
        };
        let before = recording.totals();
        assert!(wire.wire().range[1] > 0);
        assert_eq!(recording.pin().bytes, 0);
        assert_eq!(publisher.visible_roots().count(), 0);
        let now_ns = match cut {
            Cut::Revoked => {
                authority.revoked.set(true);
                clock.advance(TICK)
            }
            // Forced through the controlled clock, never by waiting out real time.
            Cut::AdmissionExpired => DEADLINE,
            Cut::LiveClockExpired => {
                let admitted = clock.advance(TICK);
                clock.set(DEADLINE);
                admitted
            }
        };
        assert!(now_ns < DEADLINE || cut == Cut::AdmissionExpired);
        let access = HttpRecordingAccess {
            now_ns,
            camera: &authority,
            storage: &NeverCancel,
        };
        if poll_first {
            assert_eq!(
                recording.poll(&publisher, access)?,
                HttpReconnectRecordingStep::WirePrepared(wire)
            );
            assert_eq!(recording.totals().read_calls, before.read_calls);
        }
        if refuse_storage {
            let denied = HttpRecordingAccess {
                storage: &Stop,
                ..access
            };
            assert!(matches!(
                recording.commit_wire(wire, &mut publisher, denied),
                Err(HttpReconnectRecordingError::Cancelled)
            ));
            assert_eq!(recording.pending_wire_plan(), Some(wire));
            assert_eq!(recording.pin().bytes, 0);
        }
        let published = recording.commit_wire(wire, &mut publisher, access)?;
        assert_eq!(
            published.acknowledgement, None,
            "retired input must never be parsed"
        );
        assert_eq!(published.publication.pin, wire.expected_pin());
        let HttpReconnectRecordingStep::BoundaryReady(boundary) =
            recording.poll(&publisher, access)?
        else {
            return Err("terminal source must reach its custody boundary".into());
        };
        assert_eq!(
            boundary.source.outcome,
            HttpReconnectOutcome::SourceFailed(match cut {
                Cut::Revoked => HttpCameraError::Denied(HttpCameraDenial::Revoked),
                Cut::AdmissionExpired => HttpCameraError::Deadline,
                Cut::LiveClockExpired => HttpCameraError::Denied(HttpCameraDenial::Deadline),
            })
        );
        assert_eq!(boundary.source.stop, Some(HttpReconnectStop::NotRetryable));
        assert_eq!(boundary.source.next_source, None);
        assert_eq!(boundary.prefix.bytes, before.received_bytes);
        let handoff = recording.release_boundary(boundary, &publisher, access)?;
        let source = handoff.source.ok_or("missing retired source")?;
        assert_eq!(
            source
                .wire
                .as_ref()
                .ok_or("missing raw read")?
                .parsed_bytes(),
            0
        );
        authority.revoked.set(false); // Restoring a grant cannot revive this source or its retries.
        assert_eq!(
            recording.poll(&publisher, access)?,
            HttpReconnectRecordingStep::Stopped
        );
        assert_eq!(recording.totals().connect_attempts, 1);
        assert_eq!(recording.totals().frames, 0);
        drop(recording.retire());
        drop(publisher);
        let publisher = directory.open()?;
        let mut work = WorkBudget::new(100_000_000);
        let archive = HttpWireArchive::load(
            &publisher,
            first.scope,
            boundary.prefix,
            first.archive,
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
            RAW[..boundary.prefix.bytes as usize]
        );
        server
            .join()
            .map_err(|_| io::Error::other("loopback fixture panicked"))??;
        Ok(())
    })
}

#[test]
fn poll_drains_revocation_while_a_wire_plan_is_held() -> Test {
    held_read_cut(true, Cut::Revoked, false, NO_STALL)
}
#[test]
fn commit_drains_revocation_without_an_intervening_poll() -> Test {
    held_read_cut(false, Cut::Revoked, false, NO_STALL)
}
#[test]
fn poll_drains_expired_network_lease_under_independent_storage_authority() -> Test {
    held_read_cut(true, Cut::AdmissionExpired, false, NO_STALL)
}
#[test]
fn commit_drains_expired_network_lease_without_an_intervening_poll() -> Test {
    held_read_cut(false, Cut::AdmissionExpired, false, NO_STALL)
}
#[test]
fn refused_drain_storage_keeps_the_same_pin_and_original_read() -> Test {
    held_read_cut(true, Cut::Revoked, true, NO_STALL)
}
// The authority's own live-clock deadline refusal, forced through the controlled clock.
#[test]
fn poll_drains_an_authority_live_clock_expiry_at_a_current_admission_time() -> Test {
    held_read_cut(true, Cut::LiveClockExpired, false, NO_STALL)
}
#[test]
fn commit_drains_an_authority_live_clock_expiry_without_an_intervening_poll() -> Test {
    held_read_cut(false, Cut::LiveClockExpired, false, NO_STALL)
}
// Injected scheduling delay: the peer stalls longer than the former 5 s wall-clock lease. Under
// wall time these refused with Source(Source(Deadline)) or exhausted the step budget (Limit).
#[test]
fn a_peer_stalled_past_the_old_wall_lease_still_drains_revocation() -> Test {
    held_read_cut(true, Cut::Revoked, false, INJECTED_STALL)
}
#[test]
fn a_peer_stalled_past_the_old_wall_lease_expires_only_by_the_controlled_clock() -> Test {
    held_read_cut(false, Cut::AdmissionExpired, true, INJECTED_STALL)
}
#[test]
fn a_generation_published_during_backoff_is_rejected_before_tcp() -> Test {
    generation_published_during_backoff(NO_STALL)
}
#[test]
fn a_generation_published_during_a_stalled_backoff_is_rejected_before_tcp() -> Test {
    generation_published_during_backoff(INJECTED_STALL)
}

fn generation_published_during_backoff(stall: Duration) -> Test {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let peer = listener.local_addr()?;
    let clock = TestClock::default();
    let abandoned = AtomicBool::new(false);
    let (written, ready) = mpsc::channel();
    let mut ready = Readiness::new(ready);
    let directory = Directory::new();
    let mut publisher = directory.open()?;
    std::thread::scope(|scope| -> Test {
        let fixture = Peer {
            stall,
            written,
            abandoned: &abandoned,
        };
        let listener = &listener;
        let server = scope.spawn(move || -> io::Result<()> {
            // One earlier generation-2 acquisition, then the target generation-1 acquisition.
            // A third connection is forbidden: generation 2 becomes occupied during backoff.
            serve(listener, &fixture)?;
            serve(listener, &fixture)
        });
        let _abandon = Abandon(&abandoned);
        let authority = Authority {
            peer,
            live: &clock,
            revoked: Cell::new(false),
        };
        let access = |now_ns| HttpRecordingAccess {
            now_ns,
            camera: &authority,
            storage: &NeverCancel,
        };
        let mut previous = plan(peer)?;
        previous.slots.remove(0);
        let mut previous = HttpReconnectRecording::new(previous, 0)?;
        let old_wire = loop {
            match previous.poll(&publisher, access(clock.advance(1)))? {
                HttpReconnectRecordingStep::WirePrepared(wire) => break wire,
                HttpReconnectRecordingStep::Pending => ready.pending(1)?,
                _ => {}
            }
        };
        // Hold the actual opaque read without publishing it yet. The namespace is still empty.
        let mut request = plan(peer)?;
        request.policy.initial_backoff_ns = 1_000_000_000;
        request.policy.maximum_backoff_ns = 1_000_000_000;
        let mut target = HttpReconnectRecording::new(request, clock.now())?;
        let boundary = loop {
            let now = clock.advance(1);
            match target.poll(&publisher, access(now))? {
                HttpReconnectRecordingStep::WirePrepared(wire) => {
                    target.commit_wire(wire, &mut publisher, access(now))?;
                }
                HttpReconnectRecordingStep::BoundaryReady(b) => break b,
                HttpReconnectRecordingStep::Pending => ready.pending(2)?,
                _ => {}
            }
        };
        let retry_at = boundary
            .source
            .retry_at_ns
            .ok_or("expected a bounded retry")?;
        drop(target.release_boundary(boundary, &publisher, access(clock.advance(1)))?);
        let used = target.source_work_used();
        assert_eq!(
            target.poll(&publisher, access(clock.advance(1)))?,
            HttpReconnectRecordingStep::Waiting {
                not_before_ns: retry_at
            }
        );
        // A waiting poll costs exactly two documented units: poll admission plus the unit charged
        // before every source step (`HttpReconnectRecording::poll`: a step may open TCP, so an
        // exhausted budget must refuse first). A rescan would instead charge at least 128 per
        // visible root, and generation 1's durable roots are visible here.
        assert!(publisher.visible_roots().count() > 0);
        assert_eq!(
            target.source_work_used(),
            used + 2,
            "waiting must not rescan the store"
        );
        let old = previous.commit_wire(old_wire, &mut publisher, access(clock.advance(1)))?;
        assert_eq!(old.publication.wire.basis.generation, 2);
        clock.set(retry_at);
        assert!(
            target.poll(&publisher, access(clock.now())).is_err(),
            "the namespace changed after waiting began; it must be reverified before connection"
        );
        assert_eq!(target.totals().connect_attempts, 1);
        assert!(matches!(listener.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
        drop(previous.retire());
        drop(target.retire());
        server
            .join()
            .map_err(|_| io::Error::other("loopback fixture panicked"))??;
        Ok(())
    })
}
