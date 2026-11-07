#![forbid(unsafe_code)]
//! Task-scoped D-Bus observation over fragmented and revoked transports.

use asupersync::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    runtime::RuntimeBuilder,
};
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_packet::dbus_handshake as wire;
use fss_reference::unifi_direct::{
    bluez_bus::{self, Admission, Error as BusError, Stage},
    bluez_monitor::{Monitor, Reason as MonitorReason, Stop as MonitorStop},
    metered::{MeteredClock, MeteredIo},
};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};
use std::{
    cell::{Cell, RefCell},
    error::Error,
    io,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
    time::Duration,
};

type TestResult = Result<(), Box<dyn Error>>;

struct Policy {
    deny: Option<Stage>,
    checks: Cell<usize>,
    revoke_adapter_watch: bool,
    adapter_watch_checks: Cell<usize>,
}
impl Admission for Policy {
    fn permits(&self, resource: &str, stage: Stage) -> bool {
        self.checks.set(self.checks.get() + 1);
        if resource == "/org/bluez/hci0" && stage == Stage::BluezWatch {
            let count = self.adapter_watch_checks.get() + 1;
            self.adapter_watch_checks.set(count);
            if self.revoke_adapter_watch && count > 1 {
                return false;
            }
        }
        matches!(resource, "fixture:system-bus" | "/org/bluez/hci0") && self.deny != Some(stage)
    }
}

struct Fixture {
    input: Vec<u8>,
    read_at: usize,
    written: Rc<RefCell<Vec<u8>>>,
    dropped: Rc<Cell<bool>>,
    pending_at_end: bool,
    deferred_stop_reply: Option<Vec<u8>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.dropped.set(true);
    }
}
impl AsyncRead for Fixture {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_at == self.input.len() {
            let stop_written = self
                .written
                .borrow()
                .windows(b"StopDiscovery".len())
                .any(|part| part == b"StopDiscovery");
            if stop_written {
                if let Some(reply) = self.deferred_stop_reply.take() {
                    self.input.extend_from_slice(&reply);
                }
            }
        }
        if self.read_at == self.input.len() {
            return if self.pending_at_end {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            };
        }
        let len = buf.remaining().min(3).min(self.input.len() - self.read_at);
        buf.put_slice(&self.input[self.read_at..self.read_at + len]);
        self.read_at += len;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Fixture {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let len = buf.len().min(3);
        self.written.borrow_mut().extend_from_slice(&buf[..len]);
        Poll::Ready(Ok(len))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn response(serial: u32, signature: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = b"l\x02\x00\x01".to_vec();
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&7_u32.to_le_bytes());
    bytes.extend_from_slice(&15_u32.to_le_bytes());
    bytes.extend_from_slice(&[5, 1, b'u', 0]);
    bytes.extend_from_slice(&serial.to_le_bytes());
    bytes.extend_from_slice(&[8, 1, b'g', 0, 1, signature, 0, 0]);
    bytes.extend_from_slice(body);
    bytes
}

fn fixture_input(owner: bool, signals: usize) -> Vec<u8> {
    let mut bytes = b"OK 00112233445566778899aabbccddeeff\r\n".to_vec();
    for serial in 1..=signals {
        bytes.extend_from_slice(b"l\x04\x00\x01\x00\x00\x00\x00");
        bytes.extend_from_slice(&(serial as u32).to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
    }
    let mut hello_body = 5_u32.to_le_bytes().to_vec();
    hello_body.extend_from_slice(b":1.42\0");
    bytes.extend_from_slice(&response(1, b's', &hello_body));
    bytes.extend_from_slice(&response(2, b'b', &u32::from(owner).to_le_bytes()));
    bytes
}

fn run_case(
    input: Vec<u8>,
    deny: Option<Stage>,
    pending: bool,
    expected: Result<(bool, usize), BusError>,
) -> TestResult {
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 64 * 1024;
    let (mut owner, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:bluez-bus".into(),
            operation_id: OperationId::parse("operation:bluez-bus")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::ObserveStatus.as_str().into(),
            ],
            deadline: Some(TimestampNs(60_000_000_000)),
            priority: 10,
            budgets: budget,
            privacy_scope: "privacy:local".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"bluez bus fixture"),
            generation: 1,
        },
        RegionId::new("region:bluez-bus")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    let written = Rc::new(RefCell::new(Vec::new()));
    let dropped = Rc::new(Cell::new(false));
    let policy = Policy {
        deny,
        checks: Cell::new(0),
        revoke_adapter_watch: false,
        adapter_watch_checks: Cell::new(0),
    };
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut owner,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:bluez-bus")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: TestResult = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                    let io = MeteredIo::with_clock(
                        Fixture {
                            input,
                            read_at: 0,
                            written: written.clone(),
                            dropped: dropped.clone(),
                            pending_at_end: pending,
                            deferred_stop_reply: None,
                        },
                        clock,
                        "fixture:system-bus",
                        8,
                    )?;
                    let observed = bluez_bus::observe(
                        cx,
                        task,
                        clock,
                        io,
                        &policy,
                        1000,
                        Duration::from_millis(30),
                    )
                    .await;
                    assert_eq!(
                        observed.map(|o| (o.bluez_name_owned, o.signals_skipped)),
                        expected
                    );
                    assert!(dropped.get());
                    assert!(policy.checks.get() > 0);
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("bus fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(59_000_000_000),
                }
            },
        )
        .await?;
        result.receipt?;
        result.output
    })?;
    if expected.is_ok() {
        let mut expected_write = wire::external_request(1000);
        expected_write.extend_from_slice(wire::BEGIN);
        expected_write.extend_from_slice(&wire::hello(1)?);
        expected_write.extend_from_slice(&wire::bluez_name_has_owner(2)?);
        assert_eq!(*written.borrow(), expected_write);
    } else if deny == Some(Stage::BluezPresence) {
        let mut expected_write = wire::external_request(1000);
        expected_write.extend_from_slice(wire::BEGIN);
        expected_write.extend_from_slice(&wire::hello(1)?);
        assert_eq!(*written.borrow(), expected_write);
    }
    Ok(())
}

#[test]
fn fragmented_replies_and_interleaved_signal_are_handled() -> TestResult {
    run_case(fixture_input(true, 1), None, false, Ok((true, 1)))
}
#[test]
fn absent_name_remains_an_observation_not_a_camera_absence_claim() -> TestResult {
    run_case(fixture_input(false, 0), None, false, Ok((false, 0)))
}
#[test]
fn policy_revocation_prevents_the_next_request() -> TestResult {
    run_case(
        fixture_input(true, 0),
        Some(Stage::BluezPresence),
        false,
        Err(BusError::Denied),
    )
}
#[test]
fn stalled_authentication_retires_owned_stream_on_deadline() -> TestResult {
    run_case(Vec::new(), None, true, Err(BusError::Interrupted))
}
#[test]
fn excessive_signals_retire_stream_without_owner_query() -> TestResult {
    run_case(fixture_input(true, 9), None, false, Err(BusError::Limit))
}

fn inventory_reply(body: &[u8]) -> Vec<u8> {
    let mut bytes = b"l\x02\x00\x01".to_vec();
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&7_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&[5, 1, b'u', 0]);
    bytes.extend_from_slice(&3_u32.to_le_bytes());
    let signature = b"a{oa{sa{sv}}}";
    bytes.extend_from_slice(&[8, 1, b'g', 0, signature.len() as u8]);
    bytes.extend_from_slice(signature);
    bytes.push(0);
    let fields = (bytes.len() - 16) as u32;
    bytes[12..16].copy_from_slice(&fields.to_le_bytes());
    while bytes.len() % 8 != 0 {
        bytes.push(0);
    }
    bytes.extend_from_slice(body);
    bytes
}

fn inventory_with_device() -> Vec<u8> {
    inventory_with_device_path("/org/bluez/hci0/dev_AA")
}

fn inventory_with_device_path(path: &str) -> Vec<u8> {
    fn pad(bytes: &mut Vec<u8>, n: usize) {
        while bytes.len() % n != 0 {
            bytes.push(0);
        }
    }
    fn string(bytes: &mut Vec<u8>, s: &str) {
        pad(bytes, 4);
        bytes.extend_from_slice(&(s.len() as u32).to_le_bytes());
        bytes.extend_from_slice(s.as_bytes());
        bytes.push(0);
    }
    fn begin(bytes: &mut Vec<u8>) -> (usize, usize) {
        pad(bytes, 4);
        let start = bytes.len();
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        pad(bytes, 8);
        (start, bytes.len())
    }
    fn end(bytes: &mut [u8], mark: (usize, usize)) {
        let len = (bytes.len() - mark.1) as u32;
        bytes[mark.0..mark.0 + 4].copy_from_slice(&len.to_le_bytes());
    }
    let mut bytes = Vec::new();
    let root = begin(&mut bytes);
    pad(&mut bytes, 8);
    string(&mut bytes, path);
    let interfaces = begin(&mut bytes);
    pad(&mut bytes, 8);
    string(&mut bytes, "org.bluez.Device1");
    let properties = begin(&mut bytes);
    pad(&mut bytes, 8);
    string(&mut bytes, "UUIDs");
    bytes.extend_from_slice(&[2, b'a', b's', 0]);
    pad(&mut bytes, 4);
    let array_at = bytes.len();
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    let array_data = bytes.len();
    string(&mut bytes, "0c430d0c-00ef-4367-bc6f-ca7c51e6b61f");
    let array_len = (bytes.len() - array_data) as u32;
    bytes[array_at..array_at + 4].copy_from_slice(&array_len.to_le_bytes());
    end(&mut bytes, properties);
    end(&mut bytes, interfaces);
    end(&mut bytes, root);
    bytes
}

fn run_inventory(
    owner_present: bool,
    deny: Option<Stage>,
    body: &[u8],
    expected: Result<(usize, usize, usize), BusError>,
) -> TestResult {
    let mut input = fixture_input(owner_present, 0);
    input.extend_from_slice(&inventory_reply(body));
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 64 * 1024;
    let (mut owner, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:bluez-inventory".into(),
            operation_id: OperationId::parse("operation:bluez-inventory")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::ObserveStatus.as_str().into(),
            ],
            deadline: Some(TimestampNs(60_000_000_000)),
            priority: 10,
            budgets: budget,
            privacy_scope: "privacy:local".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"bluez inventory fixture"),
            generation: 1,
        },
        RegionId::new("region:bluez-inventory")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    let written = Rc::new(RefCell::new(Vec::new()));
    let dropped = Rc::new(Cell::new(false));
    let policy = Policy {
        deny,
        checks: Cell::new(0),
        revoke_adapter_watch: false,
        adapter_watch_checks: Cell::new(0),
    };
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut owner,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:bluez-inventory")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: TestResult = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                    let io = MeteredIo::with_clock(
                        Fixture {
                            input,
                            read_at: 0,
                            written: written.clone(),
                            dropped: dropped.clone(),
                            pending_at_end: false,
                            deferred_stop_reply: None,
                        },
                        clock,
                        "fixture:system-bus",
                        8,
                    )?;
                    let result = bluez_bus::observe_inventory(
                        cx,
                        task,
                        clock,
                        io,
                        &policy,
                        1000,
                        Duration::from_secs(2),
                    )
                    .await;
                    assert_eq!(
                        result.map(|o| {
                            if !o.device_paths.is_empty() {
                                assert_eq!(o.device_paths, ["/org/bluez/hci0/dev_AA"]);
                                assert_eq!(o.device_claims.len(), 1);
                                assert_eq!(o.device_claims[0].path, o.device_paths[0]);
                                assert_eq!(
                                    o.device_claims[0]
                                        .claims_service("0C430D0C-00EF-4367-BC6F-CA7C51E6B61F"),
                                    Some(true)
                                );
                                assert!(!format!("{:?}", o.device_claims[0]).contains("0c430d0c"));
                                assert!(!format!("{o:?}").contains("dev_AA"));
                            }
                            (o.objects, o.adapter_paths.len(), o.device_paths.len())
                        }),
                        expected
                    );
                    assert!(dropped.get());
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("inventory fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(59_000_000_000),
                }
            },
        )
        .await?;
        result.receipt?;
        result.output
    })?;
    let mut expected_write = wire::external_request(1000);
    expected_write.extend_from_slice(wire::BEGIN);
    expected_write.extend_from_slice(&wire::hello(1)?);
    expected_write.extend_from_slice(&wire::bluez_name_has_owner(2)?);
    if owner_present && deny != Some(Stage::BluezInventory) {
        expected_write.extend_from_slice(&wire::bluez_managed_objects(3)?);
    }
    assert_eq!(*written.borrow(), expected_write);
    Ok(())
}

#[test]
fn inventory_uses_correlated_response_and_retires_stream() -> TestResult {
    run_inventory(true, None, &inventory_with_device(), Ok((1, 0, 1)))
}
#[test]
fn absent_service_or_revoked_policy_prevents_inventory_request() -> TestResult {
    run_inventory(false, None, &[0; 8], Err(BusError::BluezUnavailable))?;
    run_inventory(
        true,
        Some(Stage::BluezInventory),
        &[0; 8],
        Err(BusError::Denied),
    )
}
#[test]
fn malformed_inventory_never_returns_partial_snapshot() -> TestResult {
    run_inventory(
        true,
        None,
        &[255, 255, 255, 127, 0, 0, 0, 0],
        Err(BusError::Inventory(
            fss_packet::dbus_object_manager::Error::Invalid,
        )),
    )
}

fn watch_signal(sender: &str, member: &str) -> Vec<u8> {
    signal_with_interface(sender, "org.freedesktop.DBus.Properties", member)
}

fn signal_with_interface(sender: &str, interface: &str, member: &str) -> Vec<u8> {
    fn pad(bytes: &mut Vec<u8>, align: usize) {
        while bytes.len() % align != 0 {
            bytes.push(0);
        }
    }
    fn string(bytes: &mut Vec<u8>, value: &str) {
        pad(bytes, 4);
        bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(0);
    }
    fn field(bytes: &mut Vec<u8>, code: u8, kind: u8, value: &str) {
        pad(bytes, 8);
        bytes.extend_from_slice(&[code, 1, kind, 0]);
        string(bytes, value);
    }
    let mut body = Vec::new();
    string(&mut body, "org.bluez.Device1");
    pad(&mut body, 4);
    body.extend_from_slice(&0_u32.to_le_bytes());
    pad(&mut body, 8);
    body.extend_from_slice(&0_u32.to_le_bytes());
    let mut frame = b"l\x04\x00\x01".to_vec();
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&44_u32.to_le_bytes());
    frame.extend_from_slice(&0_u32.to_le_bytes());
    field(&mut frame, 1, b'o', "/org/bluez/hci0/dev_AA");
    field(&mut frame, 2, b's', interface);
    field(&mut frame, 3, b's', member);
    field(&mut frame, 7, b's', sender);
    pad(&mut frame, 8);
    frame.extend_from_slice(&[8, 1, b'g', 0, 6]);
    frame.extend_from_slice(b"sa{sv}as");
    // Signature length is eight bytes.
    let signature_length = frame.len() - 9;
    frame[signature_length] = 8;
    frame.push(0);
    let length = (frame.len() - 16) as u32;
    frame[12..16].copy_from_slice(&length.to_le_bytes());
    pad(&mut frame, 8);
    frame.extend_from_slice(&body);
    frame
}

fn empty_reply(serial: u32) -> Vec<u8> {
    let mut bytes = b"l\x02\x00\x01".to_vec();
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&7_u32.to_le_bytes());
    bytes.extend_from_slice(&8_u32.to_le_bytes());
    bytes.extend_from_slice(&[5, 1, b'u', 0]);
    bytes.extend_from_slice(&serial.to_le_bytes());
    bytes
}

fn watch_input(signal: Option<Vec<u8>>, second_owner: &str) -> Vec<u8> {
    fn owner_reply(serial: u32, owner: &str) -> Vec<u8> {
        let mut body = (owner.len() as u32).to_le_bytes().to_vec();
        body.extend_from_slice(owner.as_bytes());
        body.push(0);
        response(serial, b's', &body)
    }
    let mut bytes = b"OK 00112233445566778899aabbccddeeff\r\n".to_vec();
    bytes.extend_from_slice(&owner_reply(1, ":1.43"));
    bytes.extend_from_slice(&owner_reply(2, ":1.42"));
    bytes.extend_from_slice(&empty_reply(3));
    if let Some(signal) = signal {
        bytes.extend_from_slice(&signal);
    }
    bytes.extend_from_slice(&empty_reply(4));
    bytes.extend_from_slice(&empty_reply(5));
    bytes.extend_from_slice(&owner_reply(6, second_owner));
    bytes
}

fn run_watch(
    input: Vec<u8>,
    deny: Option<Stage>,
    expected: Result<(), BusError>,
    next: bool,
) -> TestResult {
    run_watch_action(
        input,
        deny,
        expected,
        if next {
            WatchAction::Next
        } else {
            WatchAction::Open
        },
    )
}

#[derive(Clone, Copy)]
enum WatchAction {
    Open,
    Next,
    Inventory { overlap: usize },
    Scan,
    ScanWait { expect_change: bool },
    ScanRevoked,
    MonitorIdle,
    MonitorProjection,
    MonitorPartial,
    MonitorOverlap,
}

fn run_watch_action(
    input: Vec<u8>,
    deny: Option<Stage>,
    expected: Result<(), BusError>,
    action: WatchAction,
) -> TestResult {
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 64 * 1024;
    let (mut owner, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:bluez-watch".into(),
            operation_id: OperationId::parse("operation:bluez-watch")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::ObserveStatus.as_str().into(),
            ],
            deadline: Some(TimestampNs(60_000_000_000)),
            priority: 10,
            budgets: budget,
            privacy_scope: "privacy:local".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"bluez watch fixture"),
            generation: 1,
        },
        RegionId::new("region:bluez-watch")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    let dropped = Rc::new(Cell::new(false));
    let policy = Policy {
        deny,
        checks: Cell::new(0),
        revoke_adapter_watch: matches!(action, WatchAction::ScanRevoked),
        adapter_watch_checks: Cell::new(0),
    };
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut owner,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:bluez-watch")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: TestResult = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                    let writes = Rc::new(RefCell::new(Vec::new()));
                    let io = MeteredIo::with_clock(
                        Fixture {
                            input,
                            read_at: 0,
                            written: writes.clone(),
                            dropped: dropped.clone(),
                            pending_at_end: true,
                            deferred_stop_reply: if matches!(
                                action,
                                WatchAction::MonitorIdle
                                    | WatchAction::MonitorProjection
                                    | WatchAction::MonitorPartial
                            ) {
                                Some(owned_empty_reply(9, ":1.42"))
                            } else if matches!(
                                action,
                                WatchAction::ScanWait {
                                    expect_change: false
                                }
                            ) {
                                Some(owned_empty_reply(8, ":1.42"))
                            } else {
                                None
                            },
                        },
                        clock,
                        "fixture:system-bus",
                        8,
                    )?;
                    let result = bluez_bus::open_watch(
                        cx,
                        task,
                        clock,
                        io,
                        &policy,
                        1000,
                        Duration::from_secs(1),
                    )
                    .await;
                    let result = match result {
                        Ok(watch) if matches!(action, WatchAction::Next) => {
                            match watch.next_change(Duration::from_millis(30)).await {
                                Ok((watch, change)) => {
                                    assert!(matches!(
                                        change.decode(watch.owner())?,
                                        fss_packet::dbus_bluez_signal::Event::Properties { .. }
                                    ));
                                    drop(watch);
                                    Ok(())
                                }
                                Err(error) => Err(error),
                            }
                        }
                        Ok(watch) if matches!(action, WatchAction::Inventory { .. }) => {
                            match watch.inventory(Duration::from_secs(1)).await {
                                Ok((watch, inventory)) => {
                                    let WatchAction::Inventory { overlap } = action else {
                                        unreachable!()
                                    };
                                    assert_eq!(inventory.overlapping_changes, overlap);
                                    assert_eq!(inventory.objects, 1);
                                    assert_eq!(inventory.device_claims.len(), 1);
                                    assert!(!format!("{inventory:?}").contains("dev_AA"));
                                    if overlap > 0 {
                                        let (watch, change) =
                                            watch.next_change(Duration::from_millis(30)).await?;
                                        assert!(matches!(
                                            change.decode(watch.owner())?,
                                            fss_packet::dbus_bluez_signal::Event::Properties { .. }
                                        ));
                                        drop(watch);
                                    } else {
                                        drop(watch);
                                    }
                                    Ok(())
                                }
                                Err(error) => Err(error),
                            }
                        }
                        Ok(watch) if matches!(action, WatchAction::Scan) => {
                            match watch
                                .start_discovery("/org/bluez/hci0", Duration::from_secs(1))
                                .await
                            {
                                Ok(scan) => match scan.stop(Duration::from_secs(1)).await {
                                    Ok(watch) => {
                                        drop(watch);
                                        Ok(())
                                    }
                                    Err(error) => Err(error),
                                },
                                Err(error) => Err(error),
                            }
                        }
                        Ok(watch)
                            if matches!(
                                action,
                                WatchAction::ScanWait { .. } | WatchAction::ScanRevoked
                            ) =>
                        {
                            match watch
                                .start_discovery("/org/bluez/hci0", Duration::from_secs(1))
                                .await
                            {
                                Ok(scan) => match scan.next_change(Duration::from_millis(30)).await
                                {
                                    Ok((scan, change)) => {
                                        let WatchAction::ScanWait { expect_change } = action else {
                                            unreachable!()
                                        };
                                        assert_eq!(change.is_some(), expect_change);
                                        if let Some(change) = change {
                                            change.decode(scan.owner())?;
                                        }
                                        match scan.stop(Duration::from_secs(1)).await {
                                            Ok(watch) => {
                                                drop(watch);
                                                Ok(())
                                            }
                                            Err(error) => Err(error),
                                        }
                                    }
                                    Err(error) => Err(error),
                                },
                                Err(error) => Err(error),
                            }
                        }
                        Ok(watch) if matches!(action, WatchAction::MonitorOverlap) => {
                            let result = Monitor::start(watch, "/org/bluez/hci0", &["0c430d0c-00ef-4367-bc6f-ca7c51e6b61f"], Duration::from_secs(1), Duration::from_millis(30), Duration::from_secs(1)).await;
                            assert!(matches!(result, Err(fss_reference::unifi_direct::bluez_monitor::StartError::Registry(fss_reference::unifi_direct::bluez_registry::Error::SnapshotOverlap))));
                            assert!(!writes.borrow().windows(b"StartDiscovery".len()).any(|part| part == b"StartDiscovery"));
                            Ok(())
                        }
                        Ok(watch)
                            if matches!(
                                action,
                                WatchAction::MonitorIdle
                                    | WatchAction::MonitorProjection
                                    | WatchAction::MonitorPartial
                            ) =>
                        {
                            let monitor = Monitor::start(
                                watch,
                                "/org/bluez/hci0",
                                &["0c430d0c-00ef-4367-bc6f-ca7c51e6b61f"],
                                Duration::from_secs(1),
                                Duration::from_millis(30),
                                Duration::from_secs(1),
                            )
                            .await?;
                            match monitor.next_change().await {
                                Ok((monitor, changed))
                                    if matches!(action, WatchAction::MonitorIdle) =>
                                {
                                    assert!(!changed);
                                    assert!(!monitor.registry().is_gapped());
                                    assert_eq!(monitor.registry().assess(0), Some(fss_reference::unifi_direct::bluez_registry::Assessment::CandidateClaim));
                                    let retired = monitor.stop().await;
                                    assert_eq!(retired.reason, MonitorReason::Stopped);
                                    assert_eq!(retired.stop, MonitorStop::Acknowledged);
                                    assert!(retired.registry.is_gapped());
                                    assert_eq!(retired.registry.assess(0), Some(fss_reference::unifi_direct::bluez_registry::Assessment::Gap));
                                    Ok(())
                                }
                                Err(retired)
                                    if matches!(action, WatchAction::MonitorProjection) =>
                                {
                                    assert!(matches!(retired.reason, MonitorReason::Projection(_)));
                                    assert_eq!(retired.stop, MonitorStop::Acknowledged);
                                    assert!(retired.registry.is_gapped());
                                    assert_eq!(retired.registry.assess(0), Some(fss_reference::unifi_direct::bluez_registry::Assessment::Gap));
                                    Ok(())
                                }
                                Err(retired) if matches!(action, WatchAction::MonitorPartial) => {
                                    assert_eq!(
                                        retired.reason,
                                        MonitorReason::Observation(BusError::DiscoveryUncertain)
                                    );
                                    assert_eq!(retired.stop, MonitorStop::Uncertain);
                                    assert!(retired.registry.is_gapped());
                                    assert_eq!(retired.registry.assess(0), Some(fss_reference::unifi_direct::bluez_registry::Assessment::Gap));
                                    Ok(())
                                }
                                _ => return Err("unexpected monitor outcome".into()),
                            }
                        }
                        Ok(watch) => {
                            drop(watch);
                            Ok(())
                        }
                        Err(error) => Err(error),
                    };
                    assert_eq!(result, expected);
                    assert!(dropped.get());
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("watch fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(59_000_000_000),
                }
            },
        )
        .await?;
        result.receipt?;
        result.output
    })
}

fn owned_inventory_reply(serial: u32, sender: &str) -> Vec<u8> {
    owned_inventory_reply_body(serial, sender, &inventory_with_device())
}

fn owned_inventory_reply_body(serial: u32, sender: &str, body: &[u8]) -> Vec<u8> {
    let mut frame = b"l\x02\x00\x01".to_vec();
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&7_u32.to_le_bytes());
    frame.extend_from_slice(&0_u32.to_le_bytes());
    frame.extend_from_slice(&[5, 1, b'u', 0]);
    frame.extend_from_slice(&serial.to_le_bytes());
    frame.extend_from_slice(&[7, 1, b's', 0]);
    frame.extend_from_slice(&(sender.len() as u32).to_le_bytes());
    frame.extend_from_slice(sender.as_bytes());
    frame.push(0);
    while frame.len() % 8 != 0 {
        frame.push(0);
    }
    let signature = b"a{oa{sa{sv}}}";
    frame.extend_from_slice(&[8, 1, b'g', 0, signature.len() as u8]);
    frame.extend_from_slice(signature);
    frame.push(0);
    let length = (frame.len() - 16) as u32;
    frame[12..16].copy_from_slice(&length.to_le_bytes());
    while frame.len() % 8 != 0 {
        frame.push(0);
    }
    frame.extend_from_slice(body);
    frame
}

fn inventory_with_adapter() -> Vec<u8> {
    fn pad(bytes: &mut Vec<u8>, n: usize) {
        while bytes.len() % n != 0 {
            bytes.push(0);
        }
    }
    fn string(bytes: &mut Vec<u8>, s: &str) {
        pad(bytes, 4);
        bytes.extend_from_slice(&(s.len() as u32).to_le_bytes());
        bytes.extend_from_slice(s.as_bytes());
        bytes.push(0);
    }
    fn begin(bytes: &mut Vec<u8>) -> (usize, usize) {
        pad(bytes, 4);
        let at = bytes.len();
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        pad(bytes, 8);
        (at, bytes.len())
    }
    fn end(bytes: &mut [u8], (at, start): (usize, usize)) {
        let len = (bytes.len() - start) as u32;
        bytes[at..at + 4].copy_from_slice(&len.to_le_bytes());
    }
    let mut body = Vec::new();
    let outer = begin(&mut body);
    pad(&mut body, 8);
    string(&mut body, "/org/bluez/hci0");
    let interfaces = begin(&mut body);
    pad(&mut body, 8);
    string(&mut body, "org.bluez.Adapter1");
    let properties = begin(&mut body);
    end(&mut body, properties);
    end(&mut body, interfaces);
    pad(&mut body, 8);
    let device = inventory_with_device_path("/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF");
    body.extend_from_slice(&device[8..]);
    end(&mut body, outer);
    body
}

#[test]
fn monitor_retirement_invalidates_claims_and_reports_cleanup() -> TestResult {
    let mut base = watch_input(None, ":1.42");
    base.extend_from_slice(&owned_inventory_reply_body(
        7,
        ":1.42",
        &inventory_with_adapter(),
    ));
    base.extend_from_slice(&owned_empty_reply(8, ":1.42"));
    run_watch_action(base.clone(), None, Ok(()), WatchAction::MonitorIdle)?;
    let mut invalid = base.clone();
    invalid.extend_from_slice(&watch_signal(":1.42", "PropertiesChanged"));
    run_watch_action(invalid, None, Ok(()), WatchAction::MonitorProjection)?;
    base.extend_from_slice(&watch_signal(":1.42", "PropertiesChanged")[..9]);
    run_watch_action(base, None, Ok(()), WatchAction::MonitorPartial)?;
    let mut overlap = watch_input(None, ":1.42");
    overlap.extend_from_slice(&watch_signal(":1.42", "PropertiesChanged"));
    overlap.extend_from_slice(&owned_inventory_reply_body(
        7,
        ":1.42",
        &inventory_with_adapter(),
    ));
    run_watch_action(overlap, None, Ok(()), WatchAction::MonitorOverlap)
}

fn owned_empty_reply(serial: u32, sender: &str) -> Vec<u8> {
    let mut frame = b"l\x02\x00\x01".to_vec();
    frame.extend_from_slice(&0_u32.to_le_bytes());
    frame.extend_from_slice(&7_u32.to_le_bytes());
    frame.extend_from_slice(&0_u32.to_le_bytes());
    frame.extend_from_slice(&[5, 1, b'u', 0]);
    frame.extend_from_slice(&serial.to_le_bytes());
    frame.extend_from_slice(&[7, 1, b's', 0]);
    frame.extend_from_slice(&(sender.len() as u32).to_le_bytes());
    frame.extend_from_slice(sender.as_bytes());
    frame.push(0);
    let length = (frame.len() - 16) as u32;
    frame[12..16].copy_from_slice(&length.to_le_bytes());
    while frame.len() % 8 != 0 {
        frame.push(0);
    }
    frame
}

#[test]
fn discovery_requires_authority_and_an_acknowledged_stop() -> TestResult {
    let mut input = watch_input(None, ":1.42");
    input.extend_from_slice(&owned_empty_reply(7, ":1.42"));
    input.extend_from_slice(&owned_empty_reply(8, ":1.42"));
    run_watch_action(input.clone(), None, Ok(()), WatchAction::Scan)?;
    run_watch_action(
        input.clone(),
        Some(Stage::BluezDiscoveryStart),
        Err(BusError::Denied),
        WatchAction::Scan,
    )?;
    run_watch_action(
        input,
        Some(Stage::BluezDiscoveryStop),
        Err(BusError::DiscoveryUncertain),
        WatchAction::Scan,
    )?;
    let mut bad = watch_input(None, ":1.42");
    bad.extend_from_slice(&owned_empty_reply(7, ":1.99"));
    run_watch_action(
        bad,
        None,
        Err(BusError::DiscoveryUncertain),
        WatchAction::Scan,
    )
}

#[test]
fn discovery_reads_changes_and_keeps_idle_session_until_stop() -> TestResult {
    let mut changed = watch_input(None, ":1.42");
    changed.extend_from_slice(&owned_empty_reply(7, ":1.42"));
    changed.extend_from_slice(&watch_signal(":1.42", "PropertiesChanged"));
    changed.extend_from_slice(&owned_empty_reply(8, ":1.42"));
    run_watch_action(
        changed,
        None,
        Ok(()),
        WatchAction::ScanWait {
            expect_change: true,
        },
    )?;
    let mut idle = watch_input(None, ":1.42");
    idle.extend_from_slice(&owned_empty_reply(7, ":1.42"));
    run_watch_action(
        idle.clone(),
        None,
        Ok(()),
        WatchAction::ScanWait {
            expect_change: false,
        },
    )?;
    idle.extend_from_slice(&watch_signal(":1.42", "PropertiesChanged")[..9]);
    run_watch_action(
        idle,
        None,
        Err(BusError::DiscoveryUncertain),
        WatchAction::ScanWait {
            expect_change: false,
        },
    )?;
    let mut revoked = watch_input(None, ":1.42");
    revoked.extend_from_slice(&owned_empty_reply(7, ":1.42"));
    revoked.extend_from_slice(&watch_signal(":1.42", "PropertiesChanged"));
    run_watch_action(
        revoked,
        None,
        Err(BusError::DiscoveryUncertain),
        WatchAction::ScanRevoked,
    )
}

#[test]
fn watch_inventory_retains_overlapping_events_and_checks_owner() -> TestResult {
    let mut input = watch_input(None, ":1.42");
    input.extend_from_slice(&watch_signal(":1.42", "PropertiesChanged"));
    input.extend_from_slice(&owned_inventory_reply(7, ":1.42"));
    run_watch_action(input, None, Ok(()), WatchAction::Inventory { overlap: 1 })?;

    let mut bad = watch_input(None, ":1.42");
    bad.extend_from_slice(&owned_inventory_reply(7, ":1.99"));
    run_watch_action(
        bad,
        None,
        Err(BusError::Protocol(wire::Error::Invalid)),
        WatchAction::Inventory { overlap: 0 },
    )?;

    let mut denied = watch_input(None, ":1.42");
    denied.extend_from_slice(&owned_inventory_reply(7, ":1.42"));
    run_watch_action(
        denied,
        Some(Stage::BluezInventory),
        Err(BusError::Denied),
        WatchAction::Inventory { overlap: 0 },
    )
}

#[test]
fn watch_preserves_interleaved_change_and_retires_connection() -> TestResult {
    run_watch(
        watch_input(Some(watch_signal(":1.42", "PropertiesChanged")), ":1.42"),
        None,
        Ok(()),
        true,
    )
}
#[test]
fn watch_rejects_wrong_sender_and_owner_epoch_change() -> TestResult {
    run_watch(
        watch_input(Some(watch_signal(":1.99", "PropertiesChanged")), ":1.42"),
        None,
        Err(BusError::Signal(
            fss_packet::dbus_bluez_signal::Error::OutsideScope,
        )),
        false,
    )?;
    run_watch(
        watch_input(None, ":1.99"),
        None,
        Err(BusError::OwnerChanged),
        false,
    )?;
    let changed = signal_with_interface(
        "org.freedesktop.DBus",
        "org.freedesktop.DBus",
        "NameOwnerChanged",
    );
    run_watch(
        watch_input(Some(changed), ":1.42"),
        None,
        Err(BusError::OwnerChanged),
        false,
    )
}
#[test]
fn watch_revocation_and_timeout_retire_owned_stream() -> TestResult {
    run_watch(
        watch_input(Some(watch_signal(":1.42", "PropertiesChanged")), ":1.42"),
        Some(Stage::BluezWatch),
        Err(BusError::Denied),
        true,
    )?;
    run_watch(
        watch_input(None, ":1.42"),
        None,
        Err(BusError::Interrupted),
        true,
    )?;
    let mut partial = watch_input(None, ":1.42");
    partial.extend_from_slice(&watch_signal(":1.42", "PropertiesChanged")[..9]);
    run_watch(partial, None, Err(BusError::Interrupted), true)
}

#[test]
fn watch_refuses_unbounded_interleaved_changes() -> TestResult {
    let mut input = watch_input(None, ":1.42");
    let reply = empty_reply(4);
    let at = input
        .windows(reply.len())
        .position(|part| part == reply)
        .ok_or("missing reply")?;
    let signal = watch_signal(":1.42", "PropertiesChanged");
    let burst = signal.repeat(33);
    input.splice(at..at, burst);
    run_watch(input, None, Err(BusError::Limit), false)
}
