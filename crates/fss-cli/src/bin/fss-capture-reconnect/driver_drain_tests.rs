#![forbid(unsafe_code)]
//! Force expiry after a real accepted read, not by racing the scheduler or the peer.
use super::*;
use super::storage_lease::StorageLease;
use super::tests::{NO_STALL, TestClock, joined, serve};
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_publication::NeverCancel;
use fss_reference::ingest::http_archive::recovery::HttpWireRecoveryState;
use std::cell::Cell;
use std::ffi::OsString;
use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const JPEG: &[u8] = include_bytes!("../../../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
const GRACE_MS: u64 = 1_000;

struct Directory(PathBuf);
impl Directory {
    fn new(name: &str) -> io::Result<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-storage-drain-{name}-{}-{attempt}",
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

fn arguments(root: &Path, peer: SocketAddr) -> Result<Vec<OsString>, &'static str> {
    let digest = ContentDigest::sha256(b"explicit-storage-drain-test").to_text();
    Ok([
        "--root", root.to_str().ok_or("UTF-8 path")?,
        "--peer", &peer.to_string(),
        "--host", "camera.invalid", "--target", "/stream",
        "--source", &digest, "--generations", "7,19",
        "--receive-clock", &digest, "--retention-evidence", &digest,
        "--owner-authorized", "yes", "--plaintext", "yes", "--retain-originals", "yes",
        "--timeout-ms", "60000", "--connect-timeout-ms", "60000",
        "--initial-backoff-ms", "1", "--maximum-backoff-ms", "2",
        "--after-complete", "yes",
    ].into_iter().map(Into::into).collect())
}
fn add(args: &mut Vec<OsString>, key: &str, value: &str) {
    args.extend([key.into(), value.into()]);
}
fn approved(root: &Path, peer: SocketAddr, grace_ms: u64, history: bool) -> Result<Options, &'static str> {
    let mut args = arguments(root, peer)?;
    add(&mut args, "--recoverable", "yes");
    add(&mut args, "--storage-drain-ms", &grace_ms.to_string());
    if history {
        add(&mut args, "--durable-history", "yes");
    }
    let mut options = Options::parse(&args)?;
    options.approve = Some(options.approval());
    Ok(options)
}
fn response() -> Vec<u8> {
    let mut body = format!(
        "--camera\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n",
        JPEG.len()
    ).into_bytes();
    body.extend_from_slice(JPEG);
    body.extend_from_slice(b"\r\n--camera--\r\n");
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=camera\r\nContent-Length: {}\r\n\r\n",
        body.len()
    ).into_bytes();
    response.extend(body);
    response
}

/// Preserve the existing fixture's peer synchronization while forcing one monotone clock jump.
struct CutClock<'a> {
    inner: &'a TestClock,
    at: Cell<Option<u64>>,
}
impl CaptureClock for CutClock<'_> {
    fn now_ns(&self) -> Option<u64> {
        self.inner.now_ns().map(|now| self.at.get().map_or(now, |at| now.max(at)))
    }
    fn await_peer(&self, bound_ns: u64) {
        self.inner.await_peer(bound_ns);
    }
    fn sleep(&self, ns: u64) {
        self.inner.sleep(ns);
    }
}
struct PreparedCut<'a> {
    jump: &'a Cell<Option<u64>>,
    at: u64,
    fail_flush: bool,
    fired: bool,
    failed: bool,
    writes_after_failure: usize,
    bytes: Vec<u8>,
}
impl Write for PreparedCut<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.failed {
            self.writes_after_failure += 1;
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        let marker = b"\"kind\":\"wire_prepared\"";
        if !self.fired && self.bytes.windows(marker.len()).any(|w| w == marker) {
            self.fired = true;
            self.jump.set(Some(self.at));
            if self.fail_flush {
                self.failed = true;
                return Err(io::ErrorKind::BrokenPipe.into());
            }
        }
        Ok(())
    }
}
fn saved_key(text: &str) -> Result<HttpWireRecoveryKey, Box<dyn std::error::Error>> {
    let row = text.lines().find(|row| row.contains("\"kind\":\"wire_prepared\""))
        .ok_or("missing prepared row")?;
    let value = row.split_once("\"recovery_key\":\"").ok_or("missing recovery key")?.1;
    Ok(HttpWireRecoveryKey::from_text(value.split_once('"').ok_or("key terminator")?.0)?)
}
fn number(row: &str, name: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let marker = format!("\"{name}\":");
    let value = row.rsplit_once(&marker).ok_or("missing numeric field")?.1;
    let end = value.find([',', '}']).ok_or("numeric terminator")?;
    Ok(value[..end].parse()?)
}

#[test]
fn zero_grace_preserves_legacy_approval_preview_and_native_reservations() -> TestResult {
    let directory = Directory::new("legacy")?;
    let base = arguments(&directory.0.join("absent"), "127.0.0.1:9".parse()?)?;
    for recoverable in [false, true] {
        for history in [false, true] {
            let mut args = base.clone();
            if recoverable { add(&mut args, "--recoverable", "yes"); }
            if history { add(&mut args, "--durable-history", "yes"); }
            let implicit = Options::parse(&args)?;
            add(&mut args, "--storage-drain-ms", "0");
            let explicit = Options::parse(&args)?;
            assert_eq!(implicit.storage_drain_ns, 0);
            assert_eq!(implicit.approval(), explicit.approval());
            assert_eq!(implicit.preview(), explicit.preview());
            assert!(!explicit.preview().contains("storage_drain"));
            assert_eq!(implicit.recording()?.reservation(), explicit.recording()?.reservation());
        }
    }
    assert!(!directory.0.join("absent").exists());
    Ok(())
}

#[test]
fn grace_requires_lossless_recovery_and_a_bounded_unsigned_millisecond_value() -> TestResult {
    let directory = Directory::new("parse")?;
    let base = arguments(&directory.0.join("absent"), "127.0.0.1:9".parse()?)?;
    let mut unkeyed = base.clone();
    add(&mut unkeyed, "--storage-drain-ms", "1");
    assert!(Options::parse(&unkeyed).is_err());
    for bad in ["-1", "1.5", "abc", "60001", "18446744073709551615"] {
        let mut args = base.clone();
        add(&mut args, "--recoverable", "yes");
        add(&mut args, "--storage-drain-ms", bad);
        assert!(Options::parse(&args).is_err(), "accepted {bad}");
    }
    for good in ["0", "1", "60000"] {
        let mut args = base.clone();
        add(&mut args, "--recoverable", "yes");
        add(&mut args, "--storage-drain-ms", good);
        assert_eq!(Options::parse(&args)?.storage_drain_ns, good.parse::<u64>()? * 1_000_000);
        add(&mut args, "--storage-drain-ms", good);
        assert!(Options::parse(&args).is_err());
    }
    Ok(())
}

#[test]
fn changing_grace_invalidates_approval_before_clock_root_or_network() -> TestResult {
    let directory = Directory::new("stale")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let root = directory.0.join("absent");
    for history in [false, true] {
        let mut options = approved(&root, listener.local_addr()?, 0, history)?;
        let original = options.approval();
        let reservation = options.recording()?.reservation();
        options.storage_drain_ns = GRACE_MS * 1_000_000;
        assert_ne!(options.approval(), original);
        assert_eq!(options.recording()?.reservation(), reservation);
        assert_eq!(options.plan()?.deadline_ns, options.timeout_ns);
        assert_eq!(options.plan()?.source_work, options.source_work);
        assert_eq!(options.plan()?.maximum_steps, options.maximum_steps);
        assert!(options.preview().contains("\"network_extended\":false"));
        let started = Cell::new(false);
        let mut output = Vec::new();
        assert_eq!(capture_with(&options, &mut output, || {
            started.set(true);
            WallClock::start()
        }), Err("ERR-CAPTURE-RECONNECT-APPROVAL-STALE-001"));
        assert!(!started.get());
        assert!(output.is_empty());
        assert!(!root.exists());
        assert!(matches!(listener.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
        let grace_approval = options.approval();
        options.storage_drain_ns += 1_000_000;
        assert_ne!(options.approval(), grace_approval);
        options.storage_drain_ns = u64::MAX;
        assert!(options.plan().is_err());
    }
    Ok(())
}

fn accepted_read_cut(grace_ms: u64, history: bool, exhaust_grace: bool, fail_flush: bool) -> TestResult {
    let directory = Directory::new("accepted")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let probe = listener.try_clone()?;
    probe.set_nonblocking(true)?;
    let options = approved(&directory.0.join("archive"), listener.local_addr()?, grace_ms, history)?;
    let (server, inner) = serve(listener, vec![response()], NO_STALL);
    let clock = CutClock { inner: &inner, at: Cell::new(None) };
    let at = options.timeout_ns + if exhaust_grace { options.storage_drain_ns } else { 0 };
    let mut out = PreparedCut {
        jump: &clock.at, at, fail_flush, fired: false, failed: false,
        writes_after_failure: 0, bytes: Vec::new(),
    };
    let result = capture_with(&options, &mut out, || &clock);
    // Always join before inspecting the result: a failed client must not orphan the peer.
    assert_eq!(joined(server)?, 1);
    assert!(out.fired, "fixture never reached an accepted original read");
    assert!(matches!(probe.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
    let text = std::str::from_utf8(&out.bytes)?;
    let key = saved_key(text)?;
    assert!(key.expected_pin().bytes > 0);
    let mut publisher = LocalRootPublisher::open(&options.root, storage_limits(&options))?;
    if fail_flush {
        assert_eq!(result, Err("ERR-CAPTURE-RECONNECT-OUTPUT-001"));
        assert_eq!(out.writes_after_failure, 0);
        assert!(!text.contains("\"kind\":\"finish\""));
        assert!(!text.contains("\"kind\":\"wire_durable\""));
        assert_eq!(publisher.visible_roots().count(), 0);
        return Ok(());
    }
    assert_eq!(result, Ok(false)); // successful salvage is not successful capture
    let finish = text.lines().find(|r| r.contains("\"kind\":\"finish\"" )).ok_or("finish")?;
    assert_eq!(number(finish, "connect_attempts")?, 1);
    assert_eq!(number(finish, "connections_started")?, 1);
    assert_eq!(number(finish, "frames_parsed")?, 0);
    assert_eq!(number(finish, "frames_taken")?, 0);
    assert!(finish.contains("\"request_satisfied\":false"));
    assert!(finish.contains("\"capture_continuity\":false"));
    if grace_ms == 0 || exhaust_grace {
        assert_eq!(number(finish, "durable_bytes")?, 0);
        assert_eq!(number(finish, "unpublished_received_bytes")?, key.expected_pin().bytes);
        assert!(!text.contains("\"kind\":\"wire_durable\""));
        assert_eq!(publisher.visible_roots().count(), 0);
    } else {
        assert_eq!(number(finish, "unpublished_received_bytes")?, 0);
        assert_eq!(number(finish, "durable_bytes")?, key.expected_pin().bytes);
        let durable = text.lines().find(|r| r.contains("\"kind\":\"wire_durable\"" )).ok_or("durable")?;
        assert!(durable.contains("\"parser_acknowledged\":null"));
        assert!(text.find("\"kind\":\"wire_prepared\"") < text.find("\"kind\":\"wire_durable\""));
        assert_eq!(key.inspect(&publisher, options.archive, &NeverCancel,
            &mut WorkBudget::new(options.source_work))?, HttpWireRecoveryState::Durable);
        let roots = publisher.visible_roots().count();
        assert_eq!(key.recover(&mut publisher, options.archive, &NeverCancel,
            &mut WorkBudget::new(options.source_work))?.pin, key.expected_pin());
        assert_eq!(publisher.visible_roots().count(), roots);
        if history {
            assert!(text.contains("\"kind\":\"history_durable\""));
            assert!(!finish.contains("\"last_durable\":null"));
        }
    }
    Ok(())
}

#[test]
fn no_opt_in_keeps_timeout_refusal_and_reports_the_unpublished_read() -> TestResult {
    accepted_read_cut(0, false, false, false)
}
#[test]
fn expired_network_read_is_retained_without_parser_ack_or_second_connection() -> TestResult {
    accepted_read_cut(GRACE_MS, false, false, false)
}
#[test]
fn expired_network_read_can_close_durable_history_under_the_same_storage_grace() -> TestResult {
    accepted_read_cut(GRACE_MS, true, false, false)
}
#[test]
fn storage_grace_expires_at_the_exact_absolute_deadline_without_refilling() -> TestResult {
    accepted_read_cut(GRACE_MS, false, true, false)
}
#[test]
fn failed_prepared_output_cannot_be_bypassed_by_storage_grace() -> TestResult {
    accepted_read_cut(GRACE_MS, true, false, true)
}

struct FixedClock {
    now: Cell<Option<u64>>,
    waits: Cell<u64>,
}
impl CaptureClock for FixedClock {
    fn now_ns(&self) -> Option<u64> { self.now.get() }
    fn await_peer(&self, _: u64) { self.waits.set(self.waits.get() + 1); }
    fn sleep(&self, _: u64) { self.waits.set(self.waits.get() + 1); }
}
fn with_owner(missing: Option<&str>, f: impl FnOnce(&Owner<'_>, &FixedClock) -> TestResult) -> TestResult {
    let directory = Directory::new("authority")?;
    let options = approved(&directory.0.join("archive"), "127.0.0.1:9".parse()?, GRACE_MS, false)?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:storage-drain-test".into(),
        operation_id: OperationId::parse("operation:storage-drain-test")?,
        principal: options.principal.clone(),
        capabilities: STORAGE_CAPS.iter().copied()
            .chain(["ADP-REPLAY-001", "CAP-ADAPTER-NET-001", "CAP-MEDIA-DECODE-001"])
            .filter(|cap| missing != Some(*cap)).map(str::to_owned).collect(),
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(1024 * 1024 * 1024)
            .storage_operations(1_000_000).build()?,
        privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
        anchor_universe: options.approval(), generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, options.root.clone())?;
    let clock = FixedClock { now: Cell::new(Some(options.timeout_ns)), waits: Cell::new(0) };
    let owner = Owner {
        cx: &cx, authority: &authority,
        routes: options.plan()?.slots.into_iter().map(|s| s.source.route).collect(),
        clock: &clock, deadline: options.timeout_ns,
    };
    let result = f(&owner, &clock);
    cx.drain_and_finalize();
    result
}

#[test]
fn grace_separates_storage_from_network_decode_and_wait_authority() -> TestResult {
    with_owner(None, |owner, clock| {
        let grace = GRACE_MS * 1_000_000;
        let lease = StorageLease::new(owner, grace).map_err(|_| "lease")?;
        let access = lease.access().map_err(|_| "storage access")?;
        assert!(!access.storage.cancel_requested(PublishCutPoint::AfterChildrenVerified));
        assert_eq!(access.camera.checkpoint(&owner.routes[0], HttpCameraOperation::AcknowledgeWire,
            access.now_ns, owner.deadline), Err(HttpCameraDenial::Deadline));
        assert_eq!(owner.decode_authority(), Err(HttpCameraDenial::Deadline));
        assert!(owner.cancel_requested(PublishCutPoint::AfterChildrenVerified));
        assert!(lease.pause(None).is_ok());
        assert!(lease.pause(Some(u64::MAX)).is_ok());
        assert_eq!(clock.waits.get(), 0);
        let ordinary = StorageLease::new(owner, 0).map_err(|_| "ordinary lease")?;
        assert!(matches!(ordinary.access(), Err(HttpCameraDenial::Deadline)));
        clock.now.set(Some(owner.deadline + grace));
        assert!(matches!(lease.access(), Err(HttpCameraDenial::Deadline)));
        assert!(lease.cancel_requested(PublishCutPoint::AfterChildrenVerified));
        assert!(matches!(lease.pause(None), Err(HttpCameraDenial::Deadline)));
        clock.now.set(None);
        assert!(matches!(lease.access(), Err(HttpCameraDenial::Deadline)));
        assert!(lease.cancel_requested(PublishCutPoint::AfterChildrenVerified));
        Ok(())
    })
}

#[test]
fn every_storage_capability_remains_required_during_grace() -> TestResult {
    for cap in STORAGE_CAPS {
        with_owner(Some(cap), |owner, _| {
            let lease = StorageLease::new(owner, GRACE_MS * 1_000_000).map_err(|_| "lease")?;
            assert!(matches!(lease.access(), Err(HttpCameraDenial::Unauthorized)));
            assert!(lease.cancel_requested(PublishCutPoint::AfterChildrenVerified));
            assert!(matches!(lease.pause(None), Err(HttpCameraDenial::Unauthorized)));
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn overflowing_or_out_of_range_storage_leases_fail_closed() -> TestResult {
    with_owner(None, |owner, _| {
        assert!(matches!(StorageLease::new(owner, 60_000_000_001), Err(HttpCameraDenial::Deadline)));
        let overflow = Owner {
            cx: owner.cx, authority: owner.authority, routes: owner.routes.clone(),
            clock: owner.clock, deadline: u64::MAX - 1,
        };
        assert!(matches!(StorageLease::new(&overflow, 2), Err(HttpCameraDenial::Deadline)));
        Ok(())
    })
}

#[test]
fn enabled_grace_preserves_successful_reacquisition_and_whole_run_bounds() -> TestResult {
    for history in [false, true] {
        let directory = Directory::new("success")?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let options = approved(&directory.0.join("archive"), listener.local_addr()?, GRACE_MS, history)?;
        let (server, clock) = serve(listener, vec![response(), response()], NO_STALL);
        let mut out = Vec::new();
        let result = capture_with(&options, &mut out, || &clock);
        assert_eq!(joined(server)?, 2);
        assert_eq!(result, Ok(true));
        let text = String::from_utf8(out)?;
        let finish = text.lines().find(|r| r.contains("\"kind\":\"finish\"" )).ok_or("finish")?;
        assert_eq!(number(finish, "connect_attempts")?, 2);
        assert_eq!(number(finish, "frames_taken")?, 2);
        assert_eq!(number(finish, "unpublished_received_bytes")?, 0);
        assert!(number(finish, "steps")? <= options.maximum_steps);
        assert!(number(finish, "source")? <= options.source_work);
        assert!(number(finish, "framing")? <= options.policy.framing_work);
        assert!(finish.contains("\"budgets_refilled\":false"));
        assert!(finish.contains("\"request_satisfied\":true"));
    }
    Ok(())
}

#[test]
fn transient_unrepresentable_wait_clock_is_not_mistaken_for_network_timeout() -> TestResult {
    struct MissingOnce {
        reads: Cell<u32>,
        deadline: u64,
    }
    impl CaptureClock for MissingOnce {
        fn now_ns(&self) -> Option<u64> {
            let read = self.reads.get();
            self.reads.set(read + 1);
            match read {
                0 => Some(self.deadline - 1),
                1 => None,
                _ => Some(self.deadline),
            }
        }
        fn await_peer(&self, _: u64) {}
        fn sleep(&self, _: u64) {}
    }
    with_owner(None, |owner, _| {
        let clock = MissingOnce { reads: Cell::new(0), deadline: owner.deadline };
        let scripted = Owner {
            cx: owner.cx, authority: owner.authority, routes: owner.routes.clone(),
            clock: &clock, deadline: owner.deadline,
        };
        let lease = StorageLease::new(&scripted, GRACE_MS * 1_000_000).map_err(|_| "lease")?;
        assert!(matches!(lease.pause(None), Err(HttpCameraDenial::Deadline)));
        assert_eq!(clock.reads.get(), 2);
        Ok(())
    })
}
