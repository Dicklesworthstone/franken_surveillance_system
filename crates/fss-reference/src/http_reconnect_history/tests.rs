#![forbid(unsafe_code)]
use super::*;
use crate::ingest::http_camera::{
    HttpCameraAuthority, HttpCameraDenial, HttpCameraLimits, HttpCameraOperation, HttpCameraRoute,
    HttpCameraSecurity, HttpCameraTotals,
};
use crate::ingest::http_reconnect::{
    HttpReconnectOutcome, HttpReconnectPolicy, HttpReconnectSlot, HttpReconnectStop,
};
use crate::ingest::http_reconnect_recording::HttpReconnectRecordingSlot;
use fss_codec_mjpeg::stream::StreamBasis;
use fss_core::ContentDigest;
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, NeverCancel, PublishCancellation, PublishCutPoint};
use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

type Test = Result<(), Box<dyn std::error::Error>>;
const JPEG: &[u8] = include_bytes!("../../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
const DEADLINE: u64 = 8_000_000_000;
const WORK: u64 = 1_000_000_000;

struct Directory(PathBuf);
impl Directory {
    fn new(name: &str) -> io::Result<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-history-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::other("owned directory bound"))
    }
    fn open(&self) -> Result<LocalRootPublisher, Box<dyn std::error::Error>> {
        Ok(LocalRootPublisher::open(
            &self.0,
            LocalPublicationLimits::new(
                128,
                32,
                128,
                1024,
                SpoolLimits::new(1024, 16 * 1024 * 1024, 65536, 2048),
            ),
        )?)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn limits() -> ReconnectHistoryLimits {
    ReconnectHistoryLimits {
        archive: HttpArchiveLimits {
            maximum_reads: 16,
            maximum_bytes: 65536,
            maximum_scan_roots: 256,
            maximum_spool_object_bytes: 65536,
        },
        maximum_reads: 32,
        maximum_bytes: 131072,
    }
}
fn session() -> ContentDigest {
    ContentDigest::sha256(b"native history test acquisition approval")
}
fn scope(generation: u64) -> HttpWireScope {
    HttpWireScope {
        stream: StreamBasis {
            source: [21; 32],
            generation,
        },
        receive_clock: [22; 32],
        retention_evidence: [23; 32],
    }
}
fn plan(
    peer: SocketAddr,
    generations: &[u64],
) -> Result<HttpReconnectRecordingPlan, Box<dyn std::error::Error>> {
    let mut slots = Vec::new();
    for generation in generations {
        let scope = scope(*generation);
        let mut native = HttpCameraLimits::default();
        native.http.wire_bytes = 65536;
        native.http.entity_bytes = 65536;
        native.connect_timeout_ns = 1_000_000_000;
        native.frames = 10;
        slots.push(HttpReconnectRecordingSlot {
            source: HttpReconnectSlot {
                route: HttpCameraRoute::new(
                    scope.stream,
                    peer,
                    "camera.invalid",
                    "/stream",
                    HttpCameraSecurity::OwnerApprovedPlaintext,
                )?,
                limits: native,
            },
            scope,
            archive: limits().archive,
        });
    }
    Ok(HttpReconnectRecordingPlan {
        slots,
        policy: HttpReconnectPolicy {
            initial_backoff_ns: 1_000_000,
            maximum_backoff_ns: 2_000_000,
            reconnect_after_complete: true,
            framing_work: WORK,
        },
        source_work: WORK,
        maximum_steps: 100_000,
        deadline_ns: DEADLINE,
    })
}
struct Authority {
    peer: SocketAddr,
    start: Instant,
    deny: bool,
}
impl HttpCameraAuthority for Authority {
    fn checkpoint(
        &self,
        route: &HttpCameraRoute,
        operation: HttpCameraOperation,
        now: u64,
        deadline: u64,
    ) -> Result<(), HttpCameraDenial> {
        if self.deny && operation == HttpCameraOperation::Connect {
            return Err(HttpCameraDenial::Revoked);
        }
        if route.peer() != self.peer || route.basis().source != scope(1).stream.source {
            return Err(HttpCameraDenial::Unauthorized);
        }
        if now >= deadline || self.start.elapsed().as_nanos() >= u128::from(deadline) {
            return Err(HttpCameraDenial::Deadline);
        }
        Ok(())
    }
}
impl Authority {
    fn access<'a>(&'a self, storage: &'a dyn PublishCancellation) -> HttpRecordingAccess<'a> {
        HttpRecordingAccess {
            now_ns: self.start.elapsed().as_nanos() as u64,
            camera: self,
            storage,
        }
    }
}
struct Refuse;
impl PublishCancellation for Refuse {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        true
    }
}
fn response() -> Vec<u8> {
    let mut body = format!(
        "--camera\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n",
        JPEG.len()
    )
    .into_bytes();
    body.extend_from_slice(JPEG);
    body.extend_from_slice(b"\r\n--camera--\r\n");
    let mut bytes = format!("HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=camera\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    bytes.extend(body);
    bytes
}
fn request(socket: &mut TcpStream) -> io::Result<()> {
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
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
fn server(listener: &TcpListener, responses: &[Vec<u8>]) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let end = Instant::now() + Duration::from_secs(8);
    for response in responses {
        let (mut socket, _) = loop {
            match listener.accept() {
                Ok(pair) => break pair,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < end => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(e) => return Err(e),
            }
        };
        request(&mut socket)?;
        socket.write_all(response)?;
    }
    Ok(())
}
fn boundary(
    run: &mut DurableReconnectRecording,
    publisher: &mut LocalRootPublisher,
    auth: &Authority,
) -> Result<ReconnectHistoryPin, Box<dyn std::error::Error>> {
    for _ in 0..100_000 {
        match run.poll(publisher, auth.access(&NeverCancel))? {
            DurableReconnectStep::BoundaryPrepared(pin) => return Ok(pin),
            DurableReconnectStep::Source(HttpReconnectRecordingStep::WirePrepared(plan)) => {
                let commit = run.commit_wire(plan, publisher, auth.access(&NeverCancel))?;
                if let Some(ack) = commit.acknowledgement {
                    ack?;
                }
            }
            DurableReconnectStep::Source(HttpReconnectRecordingStep::FrameReady(key)) => {
                run.take_frame(key, publisher, auth.access(&NeverCancel))?;
            }
            DurableReconnectStep::Source(
                HttpReconnectRecordingStep::Pending | HttpReconnectRecordingStep::Waiting { .. },
            ) => std::thread::sleep(Duration::from_millis(1)),
            DurableReconnectStep::Source(
                HttpReconnectRecordingStep::Connected(_) | HttpReconnectRecordingStep::Advanced,
            ) => {}
            _ => return Err("unexpected boundary state".into()),
        }
    }
    Err("bounded polling did not reach boundary".into())
}
fn finish_history(
    publisher: &mut LocalRootPublisher,
    peer: SocketAddr,
) -> Result<ReconnectHistoryPin, Box<dyn std::error::Error>> {
    let auth = Authority {
        peer,
        start: Instant::now(),
        deny: false,
    };
    let mut run = DurableReconnectRecording::new(plan(peer, &[4, 9])?, session(), WORK, 0)?;
    for _ in 0..2 {
        let pin = boundary(&mut run, publisher, &auth)?;
        let before = run.recording().totals();
        assert!(matches!(
            run.release_boundary(pin, publisher, auth.access(&NeverCancel)),
            Err(HistoryError::NotDurable)
        ));
        assert_eq!(run.recording().totals(), before);
        let roots = publisher.visible_roots().count();
        assert!(matches!(
            run.commit_boundary(pin, publisher, auth.access(&Refuse)),
            Err(HistoryError::Cancelled)
        ));
        assert_eq!(publisher.visible_roots().count(), roots);
        let committed = run.commit_boundary(pin, publisher, auth.access(&NeverCancel))?;
        assert_eq!(committed.root, pin.root);
        assert_eq!(
            run.commit_boundary(pin, publisher, auth.access(&NeverCancel))?
                .root,
            pin.root
        );
        assert_eq!(publisher.visible_roots().count(), roots + 1);
        assert!(
            matches!(run.poll(publisher, auth.access(&NeverCancel))?, DurableReconnectStep::BoundaryDurable(p) if p == pin)
        );
        assert_eq!(
            run.recording().totals(),
            before,
            "publication never connects or parses"
        );
        drop(run.release_boundary(pin, publisher, auth.access(&NeverCancel))?);
    }
    let pin = run.history_pin().ok_or("no history")?;
    assert!(matches!(
        run.poll(publisher, auth.access(&NeverCancel))?,
        DurableReconnectStep::Source(HttpReconnectRecordingStep::Stopped)
    ));
    assert_eq!(run.recording().totals().connect_attempts, 2);
    drop(run.retire());
    Ok(pin)
}

#[test]
fn native_failure_then_completion_survive_reopen_with_all_source_and_exact_work_limits() -> Test {
    let dir = Directory::new("chain")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let peer = listener.local_addr()?;
    let truncated = b"HTTP/1.1 200 OK\r\nContent-Length: 9999\r\nContent-Type: multipart/x-mixed-replace; boundary=camera\r\n\r\n--camera\r\n".to_vec();
    let complete = response();
    let expected_bytes = (truncated.len() + complete.len()) as u64;
    let responses = [truncated, complete];
    let pin = std::thread::scope(
        |threads| -> Result<ReconnectHistoryPin, Box<dyn std::error::Error>> {
            let fixture = threads.spawn(|| server(&listener, &responses));
            let mut publisher = dir.open()?;
            let result = finish_history(&mut publisher, peer);
            fixture.join().map_err(|_| "server panic")??;
            result
        },
    )?;
    let publisher = dir.open()?;
    let mut budget = WorkBudget::new(WORK);
    let verified =
        VerifiedReconnectHistory::load(&publisher, pin, limits(), &NeverCancel, &mut budget)?;
    assert_eq!(verified.bytes(), expected_bytes);
    assert_eq!(verified.boundaries().len(), 2);
    let first = &verified.boundaries()[0];
    let last = &verified.boundaries()[1];
    assert_eq!(first.outcome(), BoundaryOutcome::SourceFailed);
    assert!(!first.diagnostic().is_empty());
    assert_eq!(first.scope().stream.generation, 4);
    assert_eq!(first.next_source(), Some(scope(9).stream));
    assert_eq!(last.outcome(), BoundaryOutcome::NativeComplete);
    assert_eq!(last.prior().map(|p| p.connections), Some(1));
    assert_eq!(last.stop(), Some(HttpReconnectStop::ConnectionsExhausted));
    let used = budget.used();
    VerifiedReconnectHistory::load(
        &publisher,
        pin,
        limits(),
        &NeverCancel,
        &mut WorkBudget::new(used),
    )?;
    assert!(
        VerifiedReconnectHistory::load(
            &publisher,
            pin,
            limits(),
            &NeverCancel,
            &mut WorkBudget::new(used - 1)
        )
        .is_err()
    );
    assert!(matches!(
        VerifiedReconnectHistory::load(
            &publisher,
            pin,
            limits(),
            &Refuse,
            &mut WorkBudget::new(WORK)
        ),
        Err(HistoryError::Cancelled)
    ));
    let mut small = limits();
    small.maximum_bytes = expected_bytes - 1;
    assert!(matches!(
        VerifiedReconnectHistory::load(
            &publisher,
            pin,
            small,
            &NeverCancel,
            &mut WorkBudget::new(WORK)
        ),
        Err(HistoryError::Limit)
    ));
    for wrong in [
        ReconnectHistoryPin {
            connections: 1,
            ..pin
        },
        ReconnectHistoryPin {
            session: ContentDigest::sha256(b"other"),
            ..pin
        },
        ReconnectHistoryPin {
            root: ContentDigest::sha256(b"other"),
            ..pin
        },
    ] {
        assert!(
            VerifiedReconnectHistory::load(
                &publisher,
                wrong,
                limits(),
                &NeverCancel,
                &mut WorkBudget::new(WORK)
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn zero_byte_denial_is_durable_and_prevents_reusing_the_session_before_tcp() -> Test {
    let dir = Directory::new("empty")?;
    let mut publisher = dir.open()?;
    let peer = "127.0.0.1:9".parse()?;
    let auth = Authority {
        peer,
        start: Instant::now(),
        deny: true,
    };
    let mut run = DurableReconnectRecording::new(plan(peer, &[1])?, session(), WORK, 0)?;
    let pin = boundary(&mut run, &mut publisher, &auth)?;
    assert_eq!(run.recording().totals().connect_attempts, 0);
    run.commit_boundary(pin, &mut publisher, auth.access(&NeverCancel))?;
    let verified = VerifiedReconnectHistory::load(
        &publisher,
        pin,
        limits(),
        &NeverCancel,
        &mut WorkBudget::new(WORK),
    )?;
    assert_eq!((verified.bytes(), verified.reads()), (0, 0));
    assert_eq!(
        verified.boundaries()[0].outcome(),
        BoundaryOutcome::ConnectFailed { attempted: false }
    );
    drop(run.retire());
    let mut again = DurableReconnectRecording::new(plan(peer, &[1])?, session(), WORK, 0)?;
    assert!(matches!(
        again.poll(&publisher, auth.access(&NeverCancel)),
        Err(HistoryError::Occupied)
    ));
    assert_eq!(again.recording().totals().connect_attempts, 0);
    Ok(())
}

#[test]
fn corrupt_published_boundary_cannot_release_its_source_or_reconnect() -> Test {
    let dir = Directory::new("corrupt")?;
    let mut publisher = dir.open()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let peer = listener.local_addr()?;
    let responses = [response()];
    std::thread::scope(|threads| -> Test {
        let fixture = threads.spawn(|| server(&listener, &responses));
        let auth = Authority {
            peer,
            start: Instant::now(),
            deny: false,
        };
        let mut run = DurableReconnectRecording::new(plan(peer, &[1, 2])?, session(), WORK, 0)?;
        let pin = boundary(&mut run, &mut publisher, &auth)?;
        run.commit_boundary(pin, &mut publisher, auth.access(&NeverCancel))?;
        let metadata = run
            .pending_boundary()
            .ok_or("boundary")?
            .observation
            .encode()?;
        // Only files inside the fixture-owned archive may be modified.
        fn corrupt(dir: &Path, wanted: &[u8]) -> io::Result<bool> {
            for item in fs::read_dir(dir)? {
                let path = item?.path();
                if path.is_dir() {
                    if corrupt(&path, wanted)? {
                        return Ok(true);
                    }
                } else if fs::read(&path).is_ok_and(|bytes| bytes == wanted) {
                    fs::write(path, b"corrupt history metadata")?;
                    return Ok(true);
                }
            }
            Ok(false)
        }
        assert!(corrupt(&dir.0, &metadata)?);
        assert!(
            run.release_boundary(pin, &publisher, auth.access(&NeverCancel))
                .is_err()
        );
        assert_eq!(run.recording().totals().connect_attempts, 1);
        let retired = run.retire();
        assert_eq!(
            retired
                .boundary
                .as_ref()
                .map(PreparedReconnectBoundary::pin),
            Some(pin)
        );
        fixture.join().map_err(|_| "server panic")??;
        Ok(())
    })
}

fn empty_record() -> Result<ArchivedReconnectBoundary, HistoryError> {
    let scope = scope(u64::MAX);
    let digest = scope.digest()?;
    ArchivedReconnectBoundary::from_native(
        session(),
        None,
        scope,
        HttpReconnectBoundary {
            prefix: crate::ingest::http_archive::HttpWirePin {
                scope: digest,
                head: digest,
                reads: 0,
                bytes: 0,
            },
            source: crate::ingest::http_reconnect::HttpReconnectReceipt {
                connection: 1,
                source: scope.stream,
                outcome: HttpReconnectOutcome::ConnectFailed {
                    reason: crate::ingest::http_camera::HttpCameraError::Deadline,
                    attempted: false,
                },
                totals: HttpCameraTotals::default(),
                admitted_ns: u64::MAX,
                next_source: None,
                retry_at_ns: None,
                stop: Some(HttpReconnectStop::Deadline),
            },
        },
    )
}
#[test]
fn record_roundtrip_preserves_u64_extremes_and_rejects_every_truncation() -> Test {
    let record = empty_record()?;
    let bytes = record.encode()?;
    assert_eq!(ArchivedReconnectBoundary::decode(&bytes)?, record);
    for end in 0..bytes.len() {
        assert!(ArchivedReconnectBoundary::decode(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(ArchivedReconnectBoundary::decode(&trailing).is_err());
    let mut version = bytes.clone();
    // Locate the version with the canonical decoder, not an assumed length-prefix encoding.
    let mut d = fss_core::CanonicalDecoder::new(&version);
    d.bytes()?;
    let offset = version.len() - d.remaining();
    version[offset..offset + 4].copy_from_slice(&[0xff; 4]);
    assert!(ArchivedReconnectBoundary::decode(&version).is_err());
    assert!(ArchivedReconnectBoundary::decode(&vec![0; 2049]).is_err());
    Ok(())
}
#[test]
fn foreign_parent_reordering_hidden_gaps_and_fabricated_completion_are_invalid() -> Test {
    for mutation in 0..9 {
        let mut record = empty_record()?;
        match mutation {
            0 => record.connection = 2,
            1 => record.prefix.bytes = 1,
            2 => record.prefix.head = ContentDigest::sha256(b"foreign"),
            3 => record.totals.sent_bytes = 1,
            4 => record.outcome = BoundaryOutcome::NativeComplete,
            5 => record.diagnostic = "bad\nmetadata".into(),
            6 => record.diagnostic = "x".repeat(513),
            7 => record.next_source = Some(scope(1).stream),
            _ => record.stop = Some(HttpReconnectStop::Complete),
        }
        assert!(record.encode().is_err(), "mutation {mutation}");
    }
    let mut first = empty_record()?;
    first.scope = scope(10);
    first.prefix.scope = first.scope.digest()?;
    first.prefix.head = first.prefix.scope;
    first.admitted_ns = 10;
    first.next_source = Some(scope(20).stream);
    first.retry_at_ns = Some(12);
    first.stop = None;
    first.validate()?;
    let prior = ReconnectHistoryPin {
        session: session(),
        root: ContentDigest::sha256(b"parent"),
        connections: 1,
    };
    let mut next = empty_record()?;
    next.scope = scope(20);
    next.prefix.scope = next.scope.digest()?;
    next.prefix.head = next.prefix.scope;
    next.connection = 2;
    next.prior = Some(prior);
    next.admitted_ns = 12;
    next.follows(&first)?;
    next.admitted_ns = 11;
    assert!(next.follows(&first).is_err());
    next.admitted_ns = 12;
    next.scope.stream.generation = 30;
    assert!(next.follows(&first).is_err());
    Ok(())
}
#[test]
fn invalid_or_unbounded_plans_refuse_before_any_custody_or_connection() -> Test {
    let peer = "127.0.0.1:9".parse()?;
    assert!(DurableReconnectRecording::new(plan(peer, &[1])?, session(), 0, 0).is_err());
    assert!(DurableReconnectRecording::new(plan(peer, &[2, 1])?, session(), WORK, 0).is_err());
    let mut too_many = plan(peer, &[1, 2])?;
    too_many.slots[0].archive.maximum_bytes = 512 * 1024 * 1024;
    assert!(DurableReconnectRecording::new(too_many, session(), WORK, 0).is_err());
    assert!(
        ReconnectHistoryPin {
            session: session(),
            root: session(),
            connections: 33
        }
        .validate()
        .is_err()
    );
    Ok(())
}
