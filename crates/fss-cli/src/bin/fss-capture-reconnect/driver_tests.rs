#![forbid(unsafe_code)]
//! Loopback driver tests. The capture owner's lease runs on a test-owned [`TestClock`], never
//! wall time, so a stalled worker or a slow peer cannot spend it; deadline refusals are forced by
//! moving that clock. Socket and fixture wall bounds remain only as hang guards.
use super::*;
use fss_core::ContentDigest;
use std::cell::Cell;
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const JPEG: &[u8] = include_bytes!("../../../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
// Harness-only wall bound for a broken fixture; never reached while the client is live.
const HANG_GUARD: Duration = Duration::from_secs(300);
pub(super) const NO_STALL: Duration = Duration::ZERO;
// Longer than both the old 5 s wall-clock lease and the old 6 s fixture accept deadline.
const INJECTED_STALL: Duration = Duration::from_secs(6);
// Test-clock nanoseconds per owner clock read.
const TICK: u64 = 1_000;

#[path = "driver_history_tests.rs"]
mod history;

struct Directory(PathBuf);
impl Directory {
    fn new(name: &str) -> Result<Self, io::Error> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-reconnect-cli-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::other("owned test directory bound"))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn options(
    root: &std::path::Path,
    peer: std::net::SocketAddr,
    generations: &str,
    after_complete: &str,
) -> Result<Options, &'static str> {
    let digest = ContentDigest::sha256(b"reconnect-cli-native-test").to_text();
    let args: Vec<OsString> = [
        "--root",
        root.to_str().ok_or("UTF-8 path")?,
        "--peer",
        &peer.to_string(),
        "--host",
        "camera.invalid",
        "--target",
        "/stream",
        "--source",
        &digest,
        "--generations",
        generations,
        "--receive-clock",
        &digest,
        "--retention-evidence",
        &digest,
        "--owner-authorized",
        "yes",
        "--plaintext",
        "yes",
        "--retain-originals",
        "yes",
        // Test-clock lease. Kernel connect is real wall time and capped by the lease left, so
        // both stay generous hang guards rather than a race against a stalled worker.
        "--timeout-ms",
        "60000",
        "--connect-timeout-ms",
        "60000",
        "--initial-backoff-ms",
        "1",
        "--maximum-backoff-ms",
        "2",
        "--after-complete",
        after_complete,
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    let mut options = Options::parse(&args)?;
    options.approve = Some(options.approval());
    Ok(options)
}
fn response() -> Vec<u8> {
    let mut body = format!(
        "--camera\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n",
        JPEG.len()
    )
    .into_bytes();
    body.extend_from_slice(JPEG);
    body.extend_from_slice(b"\r\n--camera--\r\n");
    let mut result = format!("HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=camera\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    result.extend(body);
    result
}
fn truncated() -> Vec<u8> {
    b"HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=camera\r\nContent-Length: 1000\r\n\r\n--camera\r\n".to_vec()
}

/// What the loopback peer has done, reported to the client's [`TestClock`].
enum PeerEvent {
    RequestRead,
    ResponseWritten,
}
/// Which owner wait a clock-forced lease expiry fires on.
#[derive(Clone, Copy, PartialEq)]
pub(super) enum Wait {
    /// While the peer holds a request it has read but not answered.
    Pending,
    /// While backing off before the next explicit generation.
    Backoff,
}
/// Test-owned monotone clock: the capture owner's only time source. Each read ticks by
/// [`TICK`]; a retry backoff advances it without sleeping; a `Pending` wait blocks on the peer's
/// progress instead of spending lease, steps or wall time. Wall bounds are only hang guards.
pub(super) struct TestClock {
    now: Cell<u64>,
    events: mpsc::Receiver<PeerEvent>,
    outstanding: Cell<u64>,
    backoff: Cell<Duration>,
    expire: Cell<Option<(Wait, u64)>>,
}
impl TestClock {
    pub(super) fn now(&self) -> u64 {
        self.now.get()
    }
    /// Force lease expiry: the first wait of this kind moves the clock to `at` (never back).
    pub(super) fn expire_at(&self, wait: Wait, at: u64) {
        self.expire.set(Some((wait, at)));
    }
    fn forced(&self, wait: Wait) -> bool {
        match self.expire.get() {
            Some((kind, at)) if kind == wait => {
                self.expire.set(None);
                self.now.set(at.max(self.now.get()));
                true
            }
            _ => false,
        }
    }
    fn record(&self, event: PeerEvent) {
        let outstanding = self.outstanding.get();
        self.outstanding.set(match event {
            PeerEvent::RequestRead => outstanding + 1,
            PeerEvent::ResponseWritten => outstanding.saturating_sub(1),
        });
    }
}
impl CaptureClock for TestClock {
    fn now_ns(&self) -> Option<u64> {
        let now = self.now.get().checked_add(TICK)?;
        self.now.set(now);
        Some(now)
    }
    fn await_peer(&self, _: u64) {
        while let Ok(event) = self.events.try_recv() {
            self.record(event);
        }
        if self.outstanding.get() == 0 {
            // Request or response bytes still in loopback transit: bounded backoff.
            thread::sleep(self.backoff.get());
            self.backoff
                .set((self.backoff.get() * 2).min(Duration::from_millis(50)));
            return;
        }
        if self.forced(Wait::Pending) {
            return;
        }
        // The peer holds a request: block on its response, however long it stalls.
        while self.outstanding.get() > 0 {
            match self.events.recv_timeout(HANG_GUARD) {
                Ok(event) => self.record(event),
                Err(mpsc::RecvTimeoutError::Timeout) => break,
                Err(mpsc::RecvTimeoutError::Disconnected) => self.outstanding.set(0),
            }
        }
        self.backoff.set(Duration::from_millis(1));
    }
    fn sleep(&self, ns: u64) {
        if !self.forced(Wait::Backoff) {
            self.now.set(self.now.get().saturating_add(ns));
        }
    }
}
/// A running loopback peer. Dropping or joining it tells the peer the client has ended.
pub(super) struct Fixture {
    thread: Option<thread::JoinHandle<io::Result<usize>>>,
    abandoned: Arc<AtomicBool>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.abandoned.store(true, Ordering::Release);
    }
}

fn read_request(socket: &mut TcpStream) -> io::Result<()> {
    socket.set_read_timeout(Some(HANG_GUARD))?;
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        if request.len() >= 4096 {
            return Err(io::Error::other("request bound"));
        }
        let mut byte = [0];
        if socket.read(&mut byte)? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        request.push(byte[0]);
    }
    if !request.starts_with(b"GET /stream HTTP/1.1\r\n") {
        return Err(io::Error::other("wrong request"));
    }
    Ok(())
}
/// Serve `responses` in order, each after an injected `stall` (scheduling delay) that follows the
/// complete request. No wall deadline decides anything: the peer stops only when every response
/// is written or the client has ended. Returns the peer and the client clock it reports to.
pub(super) fn serve(
    listener: TcpListener,
    responses: Vec<Vec<u8>>,
    stall: Duration,
) -> (Fixture, TestClock) {
    let (events, progress) = mpsc::channel();
    let abandoned = Arc::new(AtomicBool::new(false));
    let ended = Arc::clone(&abandoned);
    let thread = thread::spawn(move || {
        listener.set_nonblocking(true)?;
        let mut served = 0;
        for response in responses {
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        if ended.load(Ordering::Acquire) {
                            return Ok(served);
                        }
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(e) => return Err(e),
                }
            };
            socket.set_nonblocking(false)?;
            read_request(&mut socket)?;
            // A client that already ended dropped its clock; its own result is the report.
            let _ = events.send(PeerEvent::RequestRead);
            let stalled = Instant::now();
            while stalled.elapsed() < stall {
                if ended.load(Ordering::Acquire) {
                    return Ok(served);
                }
                thread::sleep(Duration::from_millis(5));
            }
            socket.set_write_timeout(Some(HANG_GUARD))?;
            socket.write_all(&response)?;
            let _ = events.send(PeerEvent::ResponseWritten);
            served += 1;
        }
        Ok(served)
    });
    let clock = TestClock {
        now: Cell::new(0),
        events: progress,
        outstanding: Cell::new(0),
        backoff: Cell::new(Duration::from_millis(1)),
        expire: Cell::new(None),
    };
    let fixture = Fixture {
        thread: Some(thread),
        abandoned,
    };
    (fixture, clock)
}
/// End the client side, then join the peer: responses written, or its I/O error.
pub(super) fn joined(mut fixture: Fixture) -> Result<usize, io::Error> {
    fixture.abandoned.store(true, Ordering::Release);
    fixture
        .thread
        .take()
        .ok_or_else(|| io::Error::other("fixture already joined"))?
        .join()
        .map_err(|_| io::Error::other("fixture thread panicked"))?
}

#[test]
fn real_truncation_is_retained_then_reacquired_in_the_next_explicit_generation() -> TestResult {
    let directory = Directory::new("truncation")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let options = options(
        &directory.0.join("archive"),
        listener.local_addr()?,
        "40,50",
        "no",
    )?;
    let (server, clock) = serve(listener, vec![truncated(), response()], NO_STALL);
    let mut out = Vec::new();
    let result = capture_with(&options, &mut out, || &clock);
    assert_eq!(joined(server)?, 2);
    assert_eq!(result, Ok(true));
    let text = String::from_utf8(out)?;
    assert!(text.contains("\"outcome\":\"source_failed\""));
    assert!(text.contains("\"generation\":\"40\""));
    assert!(text.contains("\"generation\":\"50\""));
    assert!(!text.contains("\"generation\":\"41\""));
    assert!(text.contains("\"connections_started\":2"));
    assert!(text.contains("\"frames_taken\":1"));
    assert!(text.contains("\"unpublished_received_bytes\":0"));
    assert!(text.contains("\"capture_continuity\":false"));
    let first_boundary = text
        .find("\"kind\":\"boundary_verified\"")
        .ok_or("boundary")?;
    let second_connect = text
        .rfind("\"kind\":\"connected\"")
        .ok_or("second connect")?;
    assert!(first_boundary < second_connect);
    // The same source namespace cannot be restarted even with its exact acquisition approval.
    let mut rerun = Vec::new();
    assert_eq!(capture_with(&options, &mut rerun, || &clock), Ok(false));
    assert!(String::from_utf8(rerun)?.contains("\"connect_attempts\":0"));
    Ok(())
}
#[test]
fn complete_responses_reconnect_only_when_explicitly_approved() -> TestResult {
    for (after_complete, expected) in [("no", 1), ("yes", 2)] {
        let directory = Directory::new(after_complete)?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let options = options(
            &directory.0.join("archive"),
            listener.local_addr()?,
            "1,3",
            after_complete,
        )?;
        let (server, clock) = serve(listener, vec![response(); expected], NO_STALL);
        let mut out = Vec::new();
        let result = capture_with(&options, &mut out, || &clock);
        assert_eq!(joined(server)?, expected);
        assert_eq!(result, Ok(true));
        let text = String::from_utf8(out)?;
        assert!(text.contains(&format!("\"connections_started\":{expected}")));
        assert!(text.contains(&format!("\"frames_taken\":{expected}")));
    }
    Ok(())
}
#[test]
fn http_status_denial_is_terminal_and_never_uses_the_next_reserved_slot() -> TestResult {
    let directory = Directory::new("denied")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let options = options(
        &directory.0.join("archive"),
        listener.local_addr()?,
        "4,5",
        "yes",
    )?;
    let (server, clock) = serve(
        listener,
        vec![b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n".to_vec()],
        NO_STALL,
    );
    let mut out = Vec::new();
    let result = capture_with(&options, &mut out, || &clock);
    assert_eq!(joined(server)?, 1);
    assert_eq!(result, Ok(false));
    let text = String::from_utf8(out)?;
    assert!(text.contains("\"connections_started\":1"));
    assert!(text.contains("NotRetryable"));
    assert!(text.contains("\"frames_taken\":0"));
    assert!(text.contains("\"request_satisfied\":false"));
    Ok(())
}
// Injected scheduling delay: each response is held longer than the old 5 s wall lease, and the
// second accept happens after the old 6 s fixture deadline. Under wall time this refused.
#[test]
fn a_peer_stalled_past_the_old_wall_lease_is_retained_and_reacquired_on_the_controlled_clock()
-> TestResult {
    let directory = Directory::new("stalled")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let options = options(
        &directory.0.join("archive"),
        listener.local_addr()?,
        "40,50",
        "no",
    )?;
    let (server, clock) = serve(listener, vec![truncated(), response()], INJECTED_STALL);
    let mut out = Vec::new();
    let result = capture_with(&options, &mut out, || &clock);
    assert_eq!(joined(server)?, 2);
    assert_eq!(result, Ok(true));
    let text = String::from_utf8(out)?;
    assert!(text.contains("\"outcome\":\"source_failed\""));
    assert!(text.contains("\"generation\":\"40\""));
    assert!(text.contains("\"generation\":\"50\""));
    assert!(text.contains("\"connections_started\":2"));
    assert!(text.contains("\"connect_attempts\":2"));
    assert!(text.contains("\"frames_taken\":1"));
    assert_eq!(text.matches("\"kind\":\"wire_durable\"").count(), 2);
    assert!(text.contains("\"unpublished_received_bytes\":0"));
    // The stall spent no lease: only clock reads and the bounded backoff moved it.
    assert!(clock.now() < 1_000_000_000);
    Ok(())
}
// Deadline refusal forced through the controlled clock while backing off after a truncated
// response: the durable first prefix stays, and no second generation ever connects.
#[test]
fn lease_expiry_during_backoff_is_refused_by_the_controlled_clock_before_a_second_connect()
-> TestResult {
    let directory = Directory::new("expired-backoff")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let options = options(
        &directory.0.join("archive"),
        listener.local_addr()?,
        "40,50",
        "no",
    )?;
    let (server, clock) = serve(listener.try_clone()?, vec![truncated()], NO_STALL);
    clock.expire_at(Wait::Backoff, options.timeout_ns);
    let mut out = Vec::new();
    let result = capture_with(&options, &mut out, || &clock);
    assert_eq!(joined(server)?, 1);
    assert_eq!(result, Ok(false));
    assert!(clock.now() >= options.timeout_ns);
    assert!(matches!(listener.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
    let text = String::from_utf8(out)?;
    assert!(text.contains("\"error_code\":\"ERR-CAPTURE-RECONNECT-AUTHORITY-001\""));
    assert!(text.contains("owner authority refused: Deadline"));
    assert!(text.contains("\"outcome\":\"source_failed\""));
    assert!(text.contains("\"kind\":\"wire_durable\""));
    assert!(
        !text
            .lines()
            .any(|row| row.contains("\"kind\":\"connected\"") && row.contains("\"50\""))
    );
    assert_eq!(text.matches("\"kind\":\"connected\"").count(), 1);
    assert!(text.contains("\"connect_attempts\":1"));
    assert!(text.contains("\"unpublished_received_bytes\":0"));
    assert!(text.contains("\"request_satisfied\":false"));
    Ok(())
}
// Deadline refusal forced through the controlled clock while the peer holds the request and
// never answers: nothing is claimed durable, and no further connection is attempted.
#[test]
fn lease_expiry_while_the_peer_stalls_is_refused_by_the_controlled_clock() -> TestResult {
    let directory = Directory::new("expired-stall")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let options = options(
        &directory.0.join("archive"),
        listener.local_addr()?,
        "40,50",
        "yes",
    )?;
    // The peer answers only after the client has ended, i.e. never within the capture.
    let (server, clock) = serve(listener.try_clone()?, vec![response()], HANG_GUARD);
    clock.expire_at(Wait::Pending, options.timeout_ns);
    let mut out = Vec::new();
    let result = capture_with(&options, &mut out, || &clock);
    assert_eq!(joined(server)?, 0);
    assert_eq!(result, Ok(false));
    assert!(clock.now() >= options.timeout_ns);
    assert!(matches!(listener.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
    let text = String::from_utf8(out)?;
    assert!(text.contains("\"error_code\":\"ERR-CAPTURE-RECONNECT-AUTHORITY-001\""));
    assert!(text.contains("owner authority refused: Deadline"));
    assert!(!text.contains("\"kind\":\"wire_durable\""));
    assert!(
        !text
            .lines()
            .any(|row| row.contains("\"kind\":\"connected\"") && row.contains("\"50\""))
    );
    assert!(text.contains("\"connect_attempts\":1"));
    assert!(text.contains("\"frames_taken\":0"));
    assert!(text.contains("\"request_satisfied\":false"));
    Ok(())
}
#[derive(Clone, Copy, Debug)]
enum SinkFault {
    BeforeWrite,
    PartialWrite,
    Flush,
}
struct FailingBoundary {
    bytes: Vec<u8>,
    fault: SinkFault,
    fail_next_write: bool,
    boundary_written: bool,
    failed: bool,
    calls_after_failure: usize,
}
impl FailingBoundary {
    fn new(fault: SinkFault) -> Self {
        Self {
            bytes: Vec::new(),
            fault,
            fail_next_write: false,
            boundary_written: false,
            failed: false,
            calls_after_failure: 0,
        }
    }
}
impl Write for FailingBoundary {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.failed {
            // Deliberately recover: the transcript, not a permanently broken fixture, must
            // prevent appending another object to an incomplete or unacknowledged row.
            self.calls_after_failure += 1;
        } else if self.fail_next_write {
            self.failed = true;
            return Err(io::ErrorKind::BrokenPipe.into());
        } else if bytes
            .windows(b"boundary_verified".len())
            .any(|w| w == b"boundary_verified")
        {
            match self.fault {
                SinkFault::BeforeWrite => {
                    self.failed = true;
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                SinkFault::PartialWrite => {
                    let count = bytes.len().min(16);
                    self.bytes.extend_from_slice(&bytes[..count]);
                    self.fail_next_write = true;
                    return Ok(count);
                }
                SinkFault::Flush => self.boundary_written = true,
            }
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.failed {
            self.calls_after_failure += 1;
        } else if self.boundary_written {
            self.failed = true;
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }
}
#[test]
fn output_failure_at_the_boundary_prevents_a_second_connect() -> TestResult {
    for fault in [
        SinkFault::BeforeWrite,
        SinkFault::PartialWrite,
        SinkFault::Flush,
    ] {
        let directory = Directory::new(&format!("output-{fault:?}"))?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let options = options(
            &directory.0.join("archive"),
            listener.local_addr()?,
            "7,9",
            "yes",
        )?;
        // Keep the listening socket alive so an illicit second connect cannot hide behind
        // connection refusal after the fixture has served its one allowed response.
        let (server, clock) = serve(listener.try_clone()?, vec![response()], NO_STALL);
        let mut out = FailingBoundary::new(fault);
        let result = capture_with(&options, &mut out, || &clock);
        assert_eq!(joined(server)?, 1);
        assert_eq!(result, Err("ERR-CAPTURE-RECONNECT-OUTPUT-001"));
        assert!(out.failed);
        assert_eq!(out.calls_after_failure, 0);
        assert!(matches!(listener.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
        let text = String::from_utf8(out.bytes)?;
        assert!(text.contains("\"kind\":\"wire_durable\""));
        assert_eq!(text.matches("\"kind\":\"connected\"").count(), 1);
        assert!(!text.contains("\"kind\":\"finish\""));
        if matches!(fault, SinkFault::PartialWrite) {
            assert!(!text.ends_with('\n'));
        }
    }
    Ok(())
}
#[test]
fn transcript_never_reuses_a_sink_after_write_or_flush_failure() {
    for fault in [
        SinkFault::BeforeWrite,
        SinkFault::PartialWrite,
        SinkFault::Flush,
    ] {
        let mut out = FailingBoundary::new(fault);
        let mut log = Transcript {
            out: &mut out,
            used: 0,
            maximum: RESERVE * 4,
            sequence: 0,
            io_failed: false,
        };
        assert!(log.emit("admitted", "{}".into(), false).is_ok());
        assert!(matches!(
            log.emit("boundary_verified", "{}".into(), false),
            Err(Failure::Output)
        ));
        assert!(log.io_failed);
        assert_eq!(log.sequence, 1);
        let used = log.used;
        let prefix = log.out.bytes.clone();
        for terminal in [false, true] {
            assert!(matches!(
                log.emit("finish", "{}".into(), terminal),
                Err(Failure::Output)
            ));
            assert_eq!(log.used, used);
            assert_eq!(log.sequence, 1);
            assert_eq!(log.out.bytes, prefix);
            assert_eq!(log.out.calls_after_failure, 0);
        }
    }
}
#[test]
fn stale_approval_and_failed_admission_output_create_no_archive_or_connection() -> TestResult {
    let directory = Directory::new("no-io")?;
    let root = directory.0.join("absent");
    let mut options = options(&root, "127.0.0.1:9".parse()?, "1,2", "no")?;
    options.approve = Some(ContentDigest::sha256(b"stale"));
    let mut out = Vec::new();
    assert_eq!(
        capture(&options, &mut out),
        Err("ERR-CAPTURE-RECONNECT-APPROVAL-STALE-001")
    );
    assert!(out.is_empty());
    assert!(!root.exists());
    options.approve = Some(options.approval());
    struct Closed;
    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert_eq!(
        capture(&options, &mut Closed),
        Err("ERR-CAPTURE-RECONNECT-OUTPUT-001")
    );
    assert!(!root.exists());
    Ok(())
}
#[test]
fn non_directory_or_symlinked_root_is_refused_before_the_cx_owner_or_tcp() -> TestResult {
    // The path check runs on the operator's exact path before `ReplayCx` can create or follow it.
    let directory = Directory::new("root-kind")?;
    let file = directory.0.join("file");
    fs::write(&file, b"not an archive")?;
    let target = directory.0.join("real");
    fs::create_dir(&target)?;
    let link = directory.0.join("link");
    std::os::unix::fs::symlink(&target, &link)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    for root in [&file, &link] {
        let options = options(root, listener.local_addr()?, "1,2", "no")?;
        let mut out = Vec::new();
        assert_eq!(
            capture(&options, &mut out),
            Err("ERR-CAPTURE-RECONNECT-ROOT-001")
        );
        // Only the admission row was accepted; no finish row claims anything was captured.
        assert_eq!(String::from_utf8(out)?.lines().count(), 1);
        assert!(matches!(listener.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
    }
    assert_eq!(fs::read(&file)?, b"not an archive");
    assert!(fs::symlink_metadata(&link)?.file_type().is_symlink());
    assert_eq!(fs::read_dir(&target)?.count(), 0);
    Ok(())
}
#[test]
fn transcript_keeps_a_terminal_reserve_and_finite_interrupted_writes() {
    let mut out = Vec::new();
    let mut log = Transcript {
        out: &mut out,
        used: 0,
        maximum: RESERVE * 2,
        sequence: 0,
        io_failed: false,
    };
    assert!(matches!(
        log.emit("too_large", string(&"x".repeat(RESERVE)), false),
        Err(Failure::Output)
    ));
    // Budget refusal happens before sink I/O and must not poison its terminal reserve.
    assert!(!log.io_failed);
    assert_eq!(log.used, 0);
    assert_eq!(log.sequence, 0);
    assert!(log.out.is_empty());
    assert!(log.emit("finish", "{}".into(), true).is_ok());
    assert_eq!(log.sequence, 1);
    struct Interrupted;
    impl Write for Interrupted {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::Interrupted.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert!(write_bounded(&mut Interrupted, b"x").is_err());
}

#[test]
fn transcript_latches_zero_invalid_and_exhausted_interrupted_writes() {
    struct Refusing {
        mode: usize,
        writes: usize,
        flushes: usize,
    }
    impl Write for Refusing {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            match self.mode {
                0 => Ok(0),
                1 => Ok(bytes.len() + 1),
                _ => Err(io::ErrorKind::Interrupted.into()),
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }
    for (mode, expected_writes) in [(0, 1), (1, 1), (2, 8)] {
        let mut out = Refusing {
            mode,
            writes: 0,
            flushes: 0,
        };
        let mut log = Transcript {
            out: &mut out,
            used: 0,
            maximum: RESERVE * 2,
            sequence: 0,
            io_failed: false,
        };
        assert!(matches!(
            log.emit("admitted", "{}".into(), false),
            Err(Failure::Output)
        ));
        assert!(log.io_failed);
        assert_eq!(log.out.writes, expected_writes);
        assert_eq!(log.out.flushes, 0);
        assert!(matches!(
            log.emit("finish", "{}".into(), true),
            Err(Failure::Output)
        ));
        assert_eq!(log.out.writes, expected_writes);
        assert_eq!(log.out.flushes, 0);
        assert_eq!(log.sequence, 0);
    }
}
#[test]
fn transcript_allows_short_writes_and_finite_interruptions_before_acknowledgement() {
    #[derive(Default)]
    struct InterruptedThenShort {
        bytes: Vec<u8>,
        calls: usize,
        flushes: usize,
    }
    impl Write for InterruptedThenShort {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls <= 3 {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let count = bytes.len().min(7);
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }
    let mut out = InterruptedThenShort::default();
    let mut log = Transcript {
        out: &mut out,
        used: 0,
        maximum: RESERVE * 2,
        sequence: 0,
        io_failed: false,
    };
    assert!(log.emit("admitted", "{}".into(), false).is_ok());
    assert!(log.emit("finish", "{}".into(), true).is_ok());
    assert!(!log.io_failed);
    assert_eq!(log.sequence, 2);
    assert_eq!(log.used, log.out.bytes.len());
    assert_eq!(log.out.flushes, 2);
    assert_eq!(log.out.bytes.iter().filter(|&&b| b == b'\n').count(), 2);
}

fn decode_options(
    options: &mut Options,
    privacy_root: &std::path::Path,
    work: u64,
) -> Result<(), &'static str> {
    let values = std::collections::BTreeMap::from([
        ("--decode", "grayscale"),
        ("--privacy-root", privacy_root.to_str().ok_or("path")?),
        ("--site", "site:reconnect-native-privacy"),
        ("--sensor", "sensor:front"),
    ]);
    let mut decode =
        decode::Options::parse(&values, &options.root, options.native.multipart.frame_bytes)?
            .ok_or("decode")?;
    decode.work = work;
    options.decode = Some(decode);
    options.approve = Some(options.approval());
    Ok(())
}
fn retained_privacy(root: &std::path::Path) -> TestResult {
    use fss_core::SensorId;
    use fss_reference::ReferenceDeployment;
    use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:reconnect-native-privacy".into(),
        operation_id: OperationId::parse("operation:reconnect-native-privacy")?,
        principal: "principal:test".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(8192)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"site:reconnect-native-privacy"),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, root.to_path_buf())?;
    let mut deployment = ReferenceDeployment::open(root, "site:reconnect-native-privacy", &cx)?;
    let image = fss_codec_mjpeg::decode_luma(
        JPEG,
        ContentDigest::sha256(JPEG).bytes(),
        fss_codec_mjpeg::ComponentInterpretation::Grayscale,
        fss_codec_mjpeg::DecodeLimits::default(),
        &mut fss_codec_mjpeg::DecodeBudget::new(1_000_000_000),
    )?;
    let [width, height] = image.dimensions();
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:front")?,
        [width, height],
        &[[0, 0, width, height]],
    )?;
    let approval = preview_mask(&deployment, &policy)?.approval;
    declare_mask(&mut deployment, &policy, approval, &cx)?;
    cx.drain_and_finalize();
    Ok(())
}
#[test]
fn real_reconnected_frames_use_current_mask_and_one_shared_decode_budget() -> TestResult {
    for limited in [false, true] {
        let directory = Directory::new(if limited {
            "decode-budget"
        } else {
            "decode-masked"
        })?;
        let privacy_root = directory.0.join("privacy");
        retained_privacy(&privacy_root)?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut options = options(
            &directory.0.join("archive"),
            listener.local_addr()?,
            "10,20",
            "yes",
        )?;
        let mut budget = fss_codec_mjpeg::DecodeBudget::new(1_000_000_000);
        let image = fss_codec_mjpeg::decode_luma(
            JPEG,
            ContentDigest::sha256(JPEG).bytes(),
            fss_codec_mjpeg::ComponentInterpretation::Grayscale,
            fss_codec_mjpeg::DecodeLimits::default(),
            &mut budget,
        )?;
        let one_frame = budget.used();
        let original = sha_bytes(image.receipt().luma_sha256);
        let masked = sha_bytes(ContentDigest::sha256(&vec![16; image.pixels().len()]).bytes());
        decode_options(
            &mut options,
            &privacy_root,
            if limited { one_frame } else { one_frame * 2 },
        )?;
        let (server, clock) = serve(listener, vec![response(), response()], NO_STALL);
        let mut out = Vec::new();
        let result = capture_with(&options, &mut out, || &clock);
        assert_eq!(joined(server)?, 2);
        assert_eq!(result, Ok(!limited));
        let text = String::from_utf8(out)?;
        assert!(text.contains(&masked));
        assert!(!text.contains(&original));
        assert!(text.contains("\"policy_generation\":1"));
        assert!(text.contains("\"pixels_emitted\":false"));
        assert!(text.contains("\"work_remaining\":0"));
        assert!(text.contains("\"frames_taken\":2"));
        if limited {
            assert!(text.contains("ERR-CAPTURE-RECONNECT-DECODE-001"));
            assert!(text.contains("\"frames_decoded\":1"));
            assert!(text.contains("\"pending_frame\":{\"generation\":\"20\""));
        } else {
            assert!(text.contains("\"frames_decoded\":2"));
            assert!(text.contains("\"pending_frame\":null"));
        }
    }
    Ok(())
}
#[test]
fn missing_privacy_custody_refuses_before_capture_root_or_tcp() -> TestResult {
    let directory = Directory::new("missing-privacy")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let root = directory.0.join("archive");
    let mut options = options(&root, listener.local_addr()?, "1,2", "yes")?;
    let missing = directory.0.join("absent-privacy");
    decode_options(&mut options, &missing, 1_000_000)?;
    let mut out = Vec::new();
    assert_eq!(capture(&options, &mut out), Err("ERR-CAPTURE-PRIVACY-001"));
    assert!(!root.exists());
    assert!(!missing.exists());
    assert!(out.is_empty());
    assert!(matches!(listener.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
    Ok(())
}
