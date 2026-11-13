#![forbid(unsafe_code)]
//! Task-scoped D-Bus observation over fragmented and revoked transports.

use asupersync::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    runtime::RuntimeBuilder,
};
use fss_core::{
    BudgetVector, ContentDigest, IdempotencyKey, OperationId, RegionId, RegionKind,
    RootAuthoritySpec, RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_packet::dbus_handshake as wire;
use fss_reference::unifi_direct::{
    bluez_bus::{self, Admission, Error as BusError, Stage},
    bluez_gatt_management as management,
    bluez_monitor::{Monitor, Reason as MonitorReason, Stop as MonitorStop},
    metered::{MeteredClock, MeteredIo},
};
use fss_runtime::{
    authority::AuthorityCx,
    effect::{CommitApproval, CommittedEffect, EffectCoordinator, PrepareSpec},
    effect_journal::{EffectJournalPin, EffectJournalStore, EffectPersistenceError},
    execution::{TaskCompletion, TaskSpec, run_owned_async},
    lease::LeaseRegistry,
};
use std::{
    cell::{Cell, RefCell},
    error::Error,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
    time::Duration,
};

type TestResult = Result<(), Box<dyn Error>>;
const DEVICE: &str = "/org/bluez/hci0/dev_01_23_45_67_89_AB";
const SERVICE_PATH: &str = "/org/bluez/hci0/dev_01_23_45_67_89_AB/service001";
const NOTIFY_PATH: &str = "/org/bluez/hci0/dev_01_23_45_67_89_AB/service001/char001";
const WRITE_PATH: &str = "/org/bluez/hci0/dev_01_23_45_67_89_AB/service001/char002";
const SERVICE_UUID: &str = "0c430d0c-00ef-4367-bc6f-ca7c51e6b61f";
const NOTIFY_UUID: &str = "d587c47f-ac6e-4388-a31c-e6cd380ba043";
const WRITE_UUID: &str = "9280f26c-a56f-43ea-b769-d5d732e1ac67";

// A synthetic journal for effect ownership tests. It provides no durability.
#[derive(Debug, Default)]
struct TestJournal {
    records: Vec<Vec<u8>>,
    pins: Vec<EffectJournalPin>,
}
impl EffectJournalStore for TestJournal {
    fn head(&self) -> Option<EffectJournalPin> {
        self.pins.last().copied()
    }
    fn records(&self) -> &[Vec<u8>] {
        &self.records
    }
    fn contains(&self, pin: EffectJournalPin) -> bool {
        self.pins.contains(&pin)
    }
    fn reserve_capacity(&mut self, _: usize, _: usize) -> Result<(), EffectPersistenceError> {
        Ok(())
    }
    fn append(
        &mut self,
        expected: Option<EffectJournalPin>,
        record: &[u8],
    ) -> Result<EffectJournalPin, EffectPersistenceError> {
        if expected != self.head() {
            return Err(EffectPersistenceError::PinMismatch);
        }
        let pin = EffectJournalPin {
            sequence: self.pins.len() as u64 + 1,
            root: ContentDigest::sha256(record),
        };
        self.records.push(record.to_vec());
        self.pins.push(pin);
        Ok(pin)
    }
}

struct ManagementPolicy {
    checks: Cell<usize>,
    allow: usize,
}
impl bluez_bus::GattManagementAuthority for ManagementPolicy {
    fn permits(
        &self,
        plan: &management::Plan,
        current: management::Preconditions,
        _: &CommittedEffect,
    ) -> bool {
        let count = self.checks.get() + 1;
        self.checks.set(count);
        count <= self.allow
            && plan.check_current(current).is_ok()
            && plan
                .message_bytes()
                .windows(3)
                .any(|part| part == [0x11, 0x22, 0x33])
    }
}

struct Policy {
    deny: Option<Stage>,
    checks: Cell<usize>,
    revoke_adapter_watch: bool,
    adapter_watch_checks: Cell<usize>,
    deny_device_path: bool,
    revoke_device_connect: bool,
    device_connect_checks: Cell<usize>,
    deny_notify_path: bool,
    revoke_notify_read: bool,
    notify_read_checks: Cell<usize>,
    deny_frame_read: Cell<bool>,
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
        if resource == DEVICE && stage == Stage::BluezDeviceConnect {
            let count = self.device_connect_checks.get() + 1;
            self.device_connect_checks.set(count);
            if self.deny_device_path || (self.revoke_device_connect && count > 1) {
                return false;
            }
        }
        if resource == NOTIFY_PATH && stage == Stage::BluezNotifyStart && self.deny_notify_path {
            return false;
        }
        if resource == NOTIFY_PATH && stage == Stage::BluezNotifyRead {
            if self.deny_frame_read.get() {
                return false;
            }
            let count = self.notify_read_checks.get() + 1;
            self.notify_read_checks.set(count);
            if self.revoke_notify_read && count > 4 {
                return false;
            }
        }
        matches!(
            resource,
            "fixture:system-bus" | "/org/bluez/hci0" | DEVICE | NOTIFY_PATH | WRITE_PATH
        ) && self.deny != Some(stage)
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
            let written = self.written.borrow();
            let stop_written = written
                .windows(b"StopDiscovery".len())
                .any(|part| part == b"StopDiscovery")
                || written
                    .windows(b"StopNotify".len())
                    .any(|part| part == b"StopNotify");
            drop(written);
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
        deny_device_path: false,
        revoke_device_connect: false,
        device_connect_checks: Cell::new(0),
        deny_notify_path: false,
        revoke_notify_read: false,
        notify_read_checks: Cell::new(0),
        deny_frame_read: Cell::new(false),
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
        deny_device_path: false,
        revoke_device_connect: false,
        device_connect_checks: Cell::new(0),
        deny_notify_path: false,
        revoke_notify_read: false,
        notify_read_checks: Cell::new(0),
        deny_frame_read: Cell::new(false),
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

fn gatt_value_frame(value: &[u8]) -> Vec<u8> {
    gatt_value_frame_at(NOTIFY_PATH, value)
}

fn gatt_value_frame_at(path: &str, value: &[u8]) -> Vec<u8> {
    gatt_properties_frame(path, Some(value), None)
}

fn gatt_properties_frame(path: &str, value: Option<&[u8]>, notifying: Option<bool>) -> Vec<u8> {
    fn pad(out: &mut Vec<u8>, n: usize) {
        while out.len() % n != 0 {
            out.push(0);
        }
    }
    fn text(out: &mut Vec<u8>, value: &str) {
        pad(out, 4);
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value.as_bytes());
        out.push(0);
    }
    fn field(out: &mut Vec<u8>, code: u8, kind: u8, value: &str) {
        pad(out, 8);
        out.extend_from_slice(&[code, 1, kind, 0]);
        text(out, value);
    }
    let mut body = Vec::new();
    text(&mut body, "org.bluez.GattCharacteristic1");
    pad(&mut body, 4);
    let props_at = body.len();
    body.extend_from_slice(&0_u32.to_le_bytes());
    pad(&mut body, 8);
    let props_start = body.len();
    if let Some(value) = value {
        text(&mut body, "Value");
        body.extend_from_slice(&[2, b'a', b'y', 0]);
        pad(&mut body, 4);
        body.extend_from_slice(&(value.len() as u32).to_le_bytes());
        body.extend_from_slice(value);
    }
    if let Some(notifying) = notifying {
        pad(&mut body, 8);
        text(&mut body, "Notifying");
        body.extend_from_slice(&[1, b'b', 0]);
        pad(&mut body, 4);
        body.extend_from_slice(&u32::from(notifying).to_le_bytes());
    }
    let props_len = (body.len() - props_start) as u32;
    body[props_at..props_at + 4].copy_from_slice(&props_len.to_le_bytes());
    pad(&mut body, 4);
    body.extend_from_slice(&0_u32.to_le_bytes());
    let mut frame = b"l\x04\x00\x01".to_vec();
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&44_u32.to_le_bytes());
    frame.extend_from_slice(&0_u32.to_le_bytes());
    field(&mut frame, 1, b'o', path);
    field(&mut frame, 2, b's', "org.freedesktop.DBus.Properties");
    field(&mut frame, 3, b's', "PropertiesChanged");
    field(&mut frame, 7, b's', ":1.42");
    pad(&mut frame, 8);
    frame.extend_from_slice(&[8, 1, b'g', 0, 8]);
    frame.extend_from_slice(b"sa{sv}as");
    frame.push(0);
    let header_len = (frame.len() - 16) as u32;
    frame[12..16].copy_from_slice(&header_len.to_le_bytes());
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
    DeviceLifecycle,
    DeviceCancelled,
    DeviceDisconnectCancelled,
    DeviceBadReply,
    DevicePathDenied,
    DeviceRevoked,
    Gatt,
    GattOverlap,
    GattCancelled,
    GattBadReply,
    Notify,
    NotifyRetire,
    NotifyBadPacket,
    NotifyBudget,
    NotifyDecodeBudget,
    NotifyCancelled,
    NotifyReadCancelled,
    NotifyStopCancelled,
    NotifyBadReply,
    NotifyIdle,
    NotifyStale,
    NotifyTopology,
    NotifyPathDenied,
    ManagementWrite,
    ManagementWriteCancelled,
    ManagementWriteWrongReply,
    ManagementWriteRevoked,
    ManagementWriteUnjournaled,
    ManagementWriteNotifyDenied,
    ManagementWriteNotifyRevoked,
}

fn run_watch_action(
    input: Vec<u8>,
    deny: Option<Stage>,
    expected: Result<(), BusError>,
    action: WatchAction,
) -> TestResult {
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 64 * 1024;
    budget.bytes = if matches!(action, WatchAction::NotifyDecodeBudget) {
        0
    } else if matches!(action, WatchAction::NotifyBudget) {
        u64::try_from(gatt_value_frame(&[0]).len())?
    } else {
        4096
    };
    let (mut owner, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:bluez-watch".into(),
            operation_id: OperationId::parse("operation:bluez-watch")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::ObserveStatus.as_str().into(),
                RuntimeGrant::CameraManagementPrepare.as_str().into(),
                RuntimeGrant::CameraManagementCommit.as_str().into(),
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
    let management_action = matches!(
        action,
        WatchAction::ManagementWrite
            | WatchAction::ManagementWriteCancelled
            | WatchAction::ManagementWriteWrongReply
            | WatchAction::ManagementWriteRevoked
            | WatchAction::ManagementWriteUnjournaled
            | WatchAction::ManagementWriteNotifyDenied
            | WatchAction::ManagementWriteNotifyRevoked
    );
    let mut management_effects = None;
    let mut prepared_management = None;
    let management_operation = OperationId::parse("operation:synthetic-gatt-management")?;
    if management_action {
        let mut effects = if matches!(action, WatchAction::ManagementWriteUnjournaled) {
            EffectCoordinator::new()
        } else {
            EffectCoordinator::with_journal(Box::new(TestJournal::default()))?
        };
        let mut leases = LeaseRegistry::new();
        let camera = ContentDigest::sha256(b"synthetic camera identity");
        let resource = format!("camera:{}", camera.to_text());
        let lease = leases.acquire(&resource, owner.region().as_str(), None, TimestampNs(2))?;
        let current = management::Preconditions {
            camera,
            peer_admission: ContentDigest::sha256(b"synthetic admission"),
            session_generation: 1,
            lease_fence: lease.fence,
        };
        let plan = management::Plan::new(
            10,
            ":1.42",
            DEVICE,
            WRITE_PATH,
            fss_packet::dbus_object_manager::GattWriteMode::Request,
            &[0x11, 0x22, 0x33],
            current,
        )?;
        let prepared = effects.prepare(
            &owner,
            &mut tree,
            &mut leases,
            PrepareSpec {
                operation: &management_operation,
                idempotency_key: IdempotencyKey::parse(management_operation.as_str())?,
                request_digest: plan.request_digest(),
                precondition_digest: plan.precondition_digest(),
                resource: &resource,
                fence: lease.fence,
                prepare_grant: RuntimeGrant::CameraManagementPrepare,
                commit_grant: RuntimeGrant::CameraManagementCommit,
                terminal_predicate: "independent management observation or reconciliation",
            },
            TimestampNs(3),
        )?;
        let approval = CommitApproval {
            prepared_digest: prepared.digest(),
            current_precondition_digest: plan.precondition_digest(),
        };
        let permit = effects.commit(
            &owner,
            &tree,
            &mut leases,
            prepared,
            TimestampNs(4),
            approval,
        )?;
        prepared_management = Some((plan, current, permit));
        management_effects = Some(effects);
    }
    let runtime = RuntimeBuilder::current_thread().build()?;
    let dropped = Rc::new(Cell::new(false));
    let policy = Policy {
        deny,
        checks: Cell::new(0),
        revoke_adapter_watch: matches!(action, WatchAction::ScanRevoked),
        adapter_watch_checks: Cell::new(0),
        deny_device_path: matches!(action, WatchAction::DevicePathDenied),
        revoke_device_connect: matches!(action, WatchAction::DeviceRevoked),
        device_connect_checks: Cell::new(0),
        deny_notify_path: matches!(action, WatchAction::NotifyPathDenied),
        revoke_notify_read: matches!(action, WatchAction::ManagementWriteNotifyRevoked),
        notify_read_checks: Cell::new(0),
        deny_frame_read: Cell::new(false),
    };
    let result = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut owner,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:bluez-watch")?,
                started_at: TimestampNs(if management_action { 5 } else { 2 }),
            },
            &cx,
            async |task, cx| {
                let output: TestResult = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(if management_action { 6 } else { 3 }))?;
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
                            } else if matches!(action, WatchAction::NotifyIdle) {
                                let mut replies = owned_empty_reply(10, ":1.42");
                                replies.extend_from_slice(&owned_empty_reply(11, ":1.42"));
                                Some(replies)
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
                        Ok(mut watch) if matches!(action, WatchAction::DeviceLifecycle | WatchAction::DevicePathDenied) => {
                            let unpolled = watch.connect_device(DEVICE, Duration::from_secs(1));
                            drop(unpolled);
                            assert_eq!(watch.device_link_state(), bluez_bus::DeviceLinkState::Unlinked);
                            match watch.connect_device(DEVICE, Duration::from_secs(1)).await {
                                Ok(()) => {
                                    assert_eq!(watch.device_link_state(), bluez_bus::DeviceLinkState::ConnectAcknowledged);
                                    assert_eq!(watch.device_link_path(), Some(DEVICE));
                                    assert!(matches!(watch.disconnect_device("/org/bluez/hci0/dev_01_23_45_67_89_AC", Duration::from_secs(1)).await, Err(BusError::Configuration)));
                                    let result = watch.disconnect_device(DEVICE, Duration::from_secs(1)).await;
                                    if result.is_ok() { assert_eq!(watch.device_link_state(), bluez_bus::DeviceLinkState::Unlinked); assert_eq!(watch.device_link_path(), None); }
                                    else { assert_eq!(watch.device_link_state(), bluez_bus::DeviceLinkState::ConnectAcknowledged); }
                                    drop(watch);
                                    result
                                }
                                Err(error) => {
                                    assert_eq!(watch.device_link_state(), bluez_bus::DeviceLinkState::Unlinked);
                                    drop(watch);
                                    Err(error)
                                }
                            }
                        }
                        Ok(mut watch) if matches!(action, WatchAction::DeviceBadReply | WatchAction::DeviceRevoked) => {
                            let result = watch.connect_device(DEVICE, Duration::from_secs(1)).await;
                            assert_eq!(watch.device_link_state(), bluez_bus::DeviceLinkState::Uncertain);
                            assert_eq!(watch.device_link_path(), Some(DEVICE));
                            assert!(matches!(watch.connect_device(DEVICE, Duration::from_secs(1)).await, Err(BusError::DeviceUncertain)));
                            drop(watch);
                            result
                        }
                        Ok(mut watch) if matches!(action, WatchAction::DeviceCancelled) => {
                            let mut attempt = Box::pin(watch.connect_device(DEVICE, Duration::from_secs(1)));
                            let mut polls = 0;
                            poll_fn(|cx| match attempt.as_mut().poll(cx) {
                                Poll::Pending if writes.borrow().windows(b"Connect".len()).any(|part| part == b"Connect") => Poll::Ready(()),
                                Poll::Pending => { polls += 1; assert!(polls <= 1024); cx.waker().wake_by_ref(); Poll::Pending },
                                Poll::Ready(_) => panic!("fixture unexpectedly finished before cancellation"),
                            }).await;
                            drop(attempt);
                            assert_eq!(watch.device_link_state(), bluez_bus::DeviceLinkState::Uncertain);
                            assert_eq!(watch.device_link_path(), Some(DEVICE));
                            assert!(writes.borrow().windows(b"Connect".len()).any(|part| part == b"Connect"));
                            assert!(matches!(watch.connect_device(DEVICE, Duration::from_secs(1)).await, Err(BusError::DeviceUncertain)));
                            assert!(matches!(watch.inventory(Duration::from_secs(1)).await, Err(BusError::DeviceUncertain)));
                            Ok(())
                        }
                        Ok(mut watch) if matches!(action, WatchAction::DeviceDisconnectCancelled) => {
                            watch.connect_device(DEVICE, Duration::from_secs(1)).await?;
                            let mut attempt = Box::pin(watch.disconnect_device(DEVICE, Duration::from_secs(1)));
                            let mut polls = 0;
                            poll_fn(|cx| match attempt.as_mut().poll(cx) {
                                Poll::Pending if writes.borrow().windows(b"Disconnect".len()).any(|part| part == b"Disconnect") => Poll::Ready(()),
                                Poll::Pending => { polls += 1; assert!(polls <= 1024); cx.waker().wake_by_ref(); Poll::Pending },
                                Poll::Ready(_) => panic!("fixture unexpectedly finished before cancellation"),
                            }).await;
                            drop(attempt);
                            assert_eq!(watch.device_link_state(), bluez_bus::DeviceLinkState::Uncertain);
                            assert!(writes.borrow().windows(b"Disconnect".len()).any(|part| part == b"Disconnect"));
                            assert!(matches!(watch.disconnect_device(DEVICE, Duration::from_secs(1)).await, Err(BusError::DeviceUncertain)));
                            drop(watch);
                            Ok(())
                        }
                        Ok(mut watch) if matches!(action, WatchAction::Gatt | WatchAction::GattOverlap | WatchAction::GattBadReply) => {
                            watch.connect_device(DEVICE, Duration::from_secs(1)).await?;
                            let first = watch.select_gatt(SERVICE_UUID, NOTIFY_UUID, WRITE_UUID, fss_packet::dbus_object_manager::GattWriteMode::Request, Duration::from_secs(1)).await;
                            let selected = if matches!(action, WatchAction::GattOverlap) {
                                assert!(matches!(first, Err(BusError::GattOverlap)));
                                assert_eq!(watch.device_link_state(), bluez_bus::DeviceLinkState::ConnectAcknowledged);
                                assert_eq!(watch.pending_changes(), 1);
                                let (next, change) = watch.next_change(Duration::from_secs(1)).await?;
                                change.decode(next.owner())?;
                                watch = next;
                                assert_eq!(watch.pending_changes(), 0);
                                watch.select_gatt(SERVICE_UUID, NOTIFY_UUID, WRITE_UUID, fss_packet::dbus_object_manager::GattWriteMode::Request, Duration::from_secs(1)).await
                            } else { first };
                            match selected {
                                Ok(endpoints) => {
                                    assert_eq!(endpoints.service(), SERVICE_PATH);
                                    assert_eq!(endpoints.notify(), NOTIFY_PATH);
                                    assert_eq!(endpoints.write(), WRITE_PATH);
                                    assert!(!format!("{endpoints:?}").contains("dev_01"));
                                    watch.disconnect_device(DEVICE, Duration::from_secs(1)).await?;
                                    drop(watch);
                                    Ok(())
                                }
                                Err(error) => {
                                    assert_eq!(watch.device_link_state(), if matches!(error, BusError::DeviceUncertain) { bluez_bus::DeviceLinkState::Uncertain } else { bluez_bus::DeviceLinkState::ConnectAcknowledged });
                                    drop(watch);
                                    Err(error)
                                }
                            }
                        }
                        Ok(mut watch) if matches!(action, WatchAction::GattCancelled) => {
                            watch.connect_device(DEVICE, Duration::from_secs(1)).await?;
                            let mut attempt = Box::pin(watch.select_gatt(SERVICE_UUID, NOTIFY_UUID, WRITE_UUID, fss_packet::dbus_object_manager::GattWriteMode::Request, Duration::from_secs(1)));
                            let mut polls = 0;
                            poll_fn(|cx| match attempt.as_mut().poll(cx) {
                                Poll::Pending if writes.borrow().windows(b"GetManagedObjects".len()).any(|part| part == b"GetManagedObjects") => Poll::Ready(()),
                                Poll::Pending => { polls += 1; assert!(polls <= 1024); cx.waker().wake_by_ref(); Poll::Pending },
                                Poll::Ready(_) => panic!("fixture unexpectedly finished before cancellation"),
                            }).await;
                            drop(attempt);
                            assert_eq!(watch.device_link_state(), bluez_bus::DeviceLinkState::Uncertain);
                            assert_eq!(watch.device_link_path(), Some(DEVICE));
                            assert!(matches!(watch.select_gatt(SERVICE_UUID, NOTIFY_UUID, WRITE_UUID, fss_packet::dbus_object_manager::GattWriteMode::Request, Duration::from_secs(1)).await, Err(BusError::DeviceUncertain)));
                            drop(watch);
                            Ok(())
                        }
                        Ok(mut watch) if management_action => {
                            let (plan, current, mut permit) = prepared_management.take().ok_or("missing management permit")?;
                            watch.connect_device(DEVICE, Duration::from_secs(1)).await?;
                            let endpoints = watch.select_gatt(SERVICE_UUID, NOTIFY_UUID, WRITE_UUID, fss_packet::dbus_object_manager::GattWriteMode::Request, Duration::from_secs(1)).await?;
                            watch.start_notify(&endpoints, Duration::from_secs(1)).await?;
                            assert_eq!(watch.next_gatt_serial(), 10);
                            let policy = ManagementPolicy { checks: Cell::new(0), allow: usize::MAX };
                            if matches!(action, WatchAction::ManagementWriteUnjournaled | WatchAction::ManagementWriteNotifyDenied) {
                                let refusal = watch.dispatch_gatt_management(&endpoints, &plan, current, permit, &policy, Duration::from_secs(1)).await.expect_err("missing write admission");
                                assert_eq!(refusal.reason, if matches!(action, WatchAction::ManagementWriteUnjournaled) { bluez_bus::GattManagementRefusalReason::JournalRequired } else { bluez_bus::GattManagementRefusalReason::Denied });
                                assert!(!writes.borrow().windows(b"WriteValue".len()).any(|part| part == b"WriteValue"));
                                watch.stop_notify(&endpoints, Duration::from_secs(1)).await?;
                                watch.disconnect_device(DEVICE, Duration::from_secs(1)).await?;
                                drop(watch);
                                return Ok(());
                            }
                            let before_dispatch = writes.borrow().len();
                            if matches!(action, WatchAction::ManagementWrite) {
                                let denied = watch.dispatch_gatt_management(&endpoints, &plan, current, permit, &ManagementPolicy { checks: Cell::new(0), allow: 0 }, Duration::from_secs(1)).await.expect_err("denied authority");
                                assert_eq!(denied.reason, bluez_bus::GattManagementRefusalReason::Denied);
                                permit = denied.permit;
                                let bad_current = management::Preconditions { session_generation: 2, ..current };
                                let stale = watch.dispatch_gatt_management(&endpoints, &plan, bad_current, permit, &policy, Duration::from_secs(1)).await.expect_err("stale claim");
                                assert_eq!(stale.reason, bluez_bus::GattManagementRefusalReason::Denied);
                                permit = stale.permit;
                                let different = management::Plan::new(10, ":1.42", DEVICE, WRITE_PATH, fss_packet::dbus_object_manager::GattWriteMode::Request, &[0x11, 0x22, 0x34], current)?;
                                let mismatch = watch.dispatch_gatt_management(&endpoints, &different, current, permit, &policy, Duration::from_secs(1)).await.expect_err("different request");
                                assert_eq!(mismatch.reason, bluez_bus::GattManagementRefusalReason::PermitMismatch);
                                permit = mismatch.permit;
                                assert!(!writes.borrow().windows(b"WriteValue".len()).any(|part| part == b"WriteValue"));
                            }
                            if matches!(action, WatchAction::ManagementWriteCancelled) {
                                let mut attempt = Box::pin(watch.dispatch_gatt_management(&endpoints, &plan, current, permit, &policy, Duration::from_secs(1)));
                                let mut polls = 0;
                                poll_fn(|cx| match attempt.as_mut().poll(cx) {
                                    Poll::Pending if writes.borrow().windows(b"WriteValue".len()).any(|part| part == b"WriteValue") => Poll::Ready(()),
                                    Poll::Pending => { polls += 1; assert!(polls <= 2048); cx.waker().wake_by_ref(); Poll::Pending },
                                    Poll::Ready(_) => panic!("write unexpectedly completed before cancellation"),
                                }).await;
                                drop(attempt);
                                assert_eq!(watch.notification_state(), bluez_bus::NotificationState::Uncertain);
                                assert!(matches!(watch.next_notify_change(&endpoints, Duration::from_secs(1)).await, Err(BusError::NotificationUncertain)));
                            } else {
                                let revoking = ManagementPolicy { checks: Cell::new(0), allow: 1 };
                                let authority = if matches!(action, WatchAction::ManagementWriteRevoked) { &revoking } else { &policy };
                                let outcome = watch.dispatch_gatt_management(&endpoints, &plan, current, permit, authority, Duration::from_secs(1)).await.map_err(|_| "management dispatch refused")?;
                                match outcome {
                                    bluez_bus::GattManagementWrite::Acknowledged { mut permit } if matches!(action, WatchAction::ManagementWrite) => {
                                        assert!(!permit.try_claim_dispatch());
                                        assert_eq!(watch.notification_state(), bluez_bus::NotificationState::Active);
                                        assert_eq!(watch.pending_changes(), 1);
                                        let frame = watch.next_notify_change(&endpoints, Duration::from_secs(1)).await?.ok_or("missing interleaved notification")?;
                                        frame.decode(watch.owner())?;
                                        watch.stop_notify(&endpoints, Duration::from_secs(1)).await?;
                                        watch.disconnect_device(DEVICE, Duration::from_secs(1)).await?;
                                    }
                                    bluez_bus::GattManagementWrite::Indeterminate { mut permit } if matches!(action, WatchAction::ManagementWriteWrongReply | WatchAction::ManagementWriteRevoked | WatchAction::ManagementWriteNotifyRevoked) => {
                                        assert!(!permit.try_claim_dispatch());
                                        assert_eq!(watch.notification_state(), bluez_bus::NotificationState::Uncertain);
                                        assert!(matches!(watch.next_notify_change(&endpoints, Duration::from_secs(1)).await, Err(BusError::NotificationUncertain)));
                                        if matches!(action, WatchAction::ManagementWriteRevoked) { assert!(!writes.borrow().windows(b"WriteValue".len()).any(|part| part == b"WriteValue")); }
                                        if matches!(action, WatchAction::ManagementWriteNotifyRevoked) { assert!(writes.borrow().len() > before_dispatch); }
                                    }
                                    _ => return Err("unexpected management outcome".into()),
                                }
                            }
                            drop(watch);
                            Ok(())
                        }
                        Ok(mut watch) if matches!(action, WatchAction::NotifyStale) => {
                            watch.connect_device(DEVICE, Duration::from_secs(1)).await?;
                            let endpoints = watch.select_gatt(SERVICE_UUID, NOTIFY_UUID, WRITE_UUID, fss_packet::dbus_object_manager::GattWriteMode::Request, Duration::from_secs(1)).await?;
                            let (mut watch, _change) = watch.next_change(Duration::from_secs(1)).await?;
                            assert!(matches!(watch.start_notify(&endpoints, Duration::from_secs(1)).await, Err(BusError::Configuration)));
                            assert!(!writes.borrow().windows(b"StartNotify".len()).any(|part| part == b"StartNotify"));
                            watch.disconnect_device(DEVICE, Duration::from_secs(1)).await?;
                            drop(watch);
                            Ok(())
                        }
                        Ok(mut watch) if matches!(action, WatchAction::Notify | WatchAction::NotifyRetire | WatchAction::NotifyBadPacket | WatchAction::NotifyBudget | WatchAction::NotifyDecodeBudget | WatchAction::NotifyCancelled | WatchAction::NotifyReadCancelled | WatchAction::NotifyStopCancelled | WatchAction::NotifyBadReply | WatchAction::NotifyIdle | WatchAction::NotifyPathDenied | WatchAction::NotifyTopology) => {
                            watch.connect_device(DEVICE, Duration::from_secs(1)).await?;
                            let endpoints = watch.select_gatt(SERVICE_UUID, NOTIFY_UUID, WRITE_UUID, fss_packet::dbus_object_manager::GattWriteMode::Request, Duration::from_secs(1)).await?;
                            if matches!(action, WatchAction::NotifyCancelled) {
                                let mut attempt = Box::pin(watch.start_notify(&endpoints, Duration::from_secs(1)));
                                let mut polls = 0;
                                poll_fn(|cx| match attempt.as_mut().poll(cx) {
                                    Poll::Pending if writes.borrow().windows(b"StartNotify".len()).any(|part| part == b"StartNotify") => Poll::Ready(()),
                                    Poll::Pending => { polls += 1; assert!(polls <= 1024); cx.waker().wake_by_ref(); Poll::Pending },
                                    Poll::Ready(_) => panic!("notification start unexpectedly finished before cancellation"),
                                }).await;
                                drop(attempt);
                                assert_eq!(watch.notification_state(), bluez_bus::NotificationState::Uncertain);
                                assert!(matches!(watch.start_notify(&endpoints, Duration::from_secs(1)).await, Err(BusError::NotificationUncertain)));
                                drop(watch);
                                Ok(())
                            } else {
                                let result = watch.start_notify(&endpoints, Duration::from_secs(1)).await;
                                if let Err(error) = result {
                                    assert_eq!(watch.notification_state(), if matches!(error, BusError::NotificationUncertain) { bluez_bus::NotificationState::Uncertain } else { bluez_bus::NotificationState::Inactive });
                                    drop(watch);
                                    Err(error)
                                } else if matches!(action, WatchAction::NotifyReadCancelled) {
                                    let mut attempt = Box::pin(watch.next_notify_change(&endpoints, Duration::from_secs(1)));
                                    poll_fn(|cx| match attempt.as_mut().poll(cx) {
                                        Poll::Pending => Poll::Ready(()),
                                        Poll::Ready(_) => panic!("notification read unexpectedly finished before cancellation"),
                                    }).await;
                                    drop(attempt);
                                    assert_eq!(watch.notification_state(), bluez_bus::NotificationState::Uncertain);
                                    assert!(matches!(watch.next_notify_change(&endpoints, Duration::from_secs(1)).await, Err(BusError::NotificationUncertain)));
                                    drop(watch);
                                    Ok(())
                                } else if matches!(action, WatchAction::NotifyStopCancelled) {
                                    let mut attempt = Box::pin(watch.stop_notify(&endpoints, Duration::from_secs(1)));
                                    let mut polls = 0;
                                    poll_fn(|cx| match attempt.as_mut().poll(cx) {
                                        Poll::Pending if writes.borrow().windows(b"StopNotify".len()).any(|part| part == b"StopNotify") => Poll::Ready(()),
                                        Poll::Pending => { polls += 1; assert!(polls <= 1024); cx.waker().wake_by_ref(); Poll::Pending },
                                        Poll::Ready(_) => panic!("notification stop unexpectedly finished before cancellation"),
                                    }).await;
                                    drop(attempt);
                                    assert_eq!(watch.notification_state(), bluez_bus::NotificationState::Uncertain);
                                    assert!(matches!(watch.stop_notify(&endpoints, Duration::from_secs(1)).await, Err(BusError::NotificationUncertain)));
                                    assert!(matches!(watch.disconnect_device(DEVICE, Duration::from_secs(1)).await, Err(BusError::NotificationUncertain)));
                                    drop(watch);
                                    Ok(())
                                } else if matches!(action, WatchAction::NotifyTopology) {
                                    use bluez_bus::{NotificationFrames, NotificationFramesError as FrameError, NotificationFramesStep as FrameStep};
                                    let mut frames = NotificationFrames::new(&watch, &endpoints, 128).map_err(|_| "topology framer")?;
                                    let unrelated = watch.next_notify_change(&endpoints, Duration::from_secs(1)).await?.ok_or("missing unrelated change")?;
                                    unrelated.decode(watch.owner())?;
                                    assert!(!watch.gatt_selection_stale());
                                    frames.submit(&watch, &endpoints, unrelated).map_err(|_| "unrelated submit")?;
                                    assert!(matches!(frames.next(&watch, &endpoints), Ok(FrameStep::Change(_))));
                                    let active = watch.next_notify_change(&endpoints, Duration::from_secs(1)).await?.ok_or("missing active notification status")?;
                                    active.decode(watch.owner())?;
                                    assert!(!watch.gatt_selection_stale());
                                    frames.submit(&watch, &endpoints, active).map_err(|_| "status submit")?;
                                    assert!(matches!(frames.next(&watch, &endpoints), Ok(FrameStep::Change(_))));
                                    let changed = watch.next_notify_change(&endpoints, Duration::from_secs(1)).await?.ok_or("missing selected-device change")?;
                                    changed.decode(watch.owner())?;
                                    assert!(watch.gatt_selection_stale());
                                    let refused = frames.submit(&watch, &endpoints, changed).expect_err("stale selection accepted data");
                                    assert_eq!(refused.reason, FrameError::Scope);
                                    refused.change.decode(watch.owner())?;
                                    let retired = frames.retire();
                                    assert!(retired.packet_prefix.as_bytes().is_empty());
                                    assert!(retired.pending_change.is_none() && !retired.fenced);
                                    assert!(matches!(watch.next_notify_change(&endpoints, Duration::from_secs(1)).await, Err(BusError::GattStale)));
                                    assert_eq!(watch.notification_state(), bluez_bus::NotificationState::Active);
                                    watch.stop_notify(&endpoints, Duration::from_secs(1)).await?;
                                    assert!(matches!(watch.start_notify(&endpoints, Duration::from_secs(1)).await, Err(BusError::Configuration)));
                                    watch.disconnect_device(DEVICE, Duration::from_secs(1)).await?;
                                    Ok(())
                                } else if matches!(action, WatchAction::NotifyIdle) {
                                    assert!(watch.next_notify_change(&endpoints, Duration::from_millis(30)).await?.is_none());
                                    assert_eq!(watch.notification_state(), bluez_bus::NotificationState::Active);
                                    watch.stop_notify(&endpoints, Duration::from_secs(1)).await?;
                                    watch.disconnect_device(DEVICE, Duration::from_secs(1)).await?;
                                    drop(watch);
                                    Ok(())
                                } else {
                                    assert_eq!(watch.notification_state(), bluez_bus::NotificationState::Active);
                                    assert!(matches!(watch.disconnect_device(DEVICE, Duration::from_secs(1)).await, Err(BusError::Configuration)));
                                    assert_eq!(watch.notification_state(), bluez_bus::NotificationState::Active);
                                    assert_eq!(watch.pending_changes(), 1);
                                    use bluez_bus::{NotificationFrames, NotificationFramesError as FrameError, NotificationFramesStep as FrameStep};
                                    let mut frames = NotificationFrames::new(&watch, &endpoints, 128).map_err(|_| "framer")?;
                                    let first = watch.next_notify_change(&endpoints, Duration::from_secs(1)).await?.ok_or("missing notification")?;
                                    assert!(matches!(NotificationFrames::new(&watch, &endpoints, 128), Err(FrameError::Scope)));
                                    if matches!(action, WatchAction::NotifyBudget | WatchAction::NotifyDecodeBudget) {
                                        frames.submit(&watch, &endpoints, first).map_err(|_| "budget submit")?;
                                        assert!(matches!(frames.next(&watch, &endpoints), Err(FrameError::Budget)));
                                        let retired = frames.retire();
                                        assert!(retired.packet_prefix.as_bytes().is_empty());
                                        let (_, accepted) = retired.pending_change.ok_or("original change lost")?;
                                        assert_eq!(accepted, 0);
                                        assert!(!retired.fenced);
                                        watch.stop_notify(&endpoints, Duration::from_secs(1)).await?;
                                        watch.disconnect_device(DEVICE, Duration::from_secs(1)).await?;
                                        return Ok(());
                                    }
                                    if matches!(action, WatchAction::NotifyBadPacket) {
                                        frames.submit(&watch, &endpoints, first).map_err(|_| "bad packet submit")?;
                                        assert!(matches!(frames.next(&watch, &endpoints), Err(FrameError::Framing(fss_packet::unifi_ble::FailureKind::InvalidLength))));
                                        assert!(matches!(frames.next(&watch, &endpoints), Err(FrameError::Fenced)));
                                        let retired = frames.retire();
                                        assert_eq!(retired.packet_prefix.as_bytes(), &[0, 1]);
                                        let (original, accepted) = retired.pending_change.ok_or("original change lost")?;
                                        assert_eq!(accepted, 2);
                                        assert!(matches!(original.decode(watch.owner())?, fss_packet::dbus_bluez_signal::Event::Properties { .. }));
                                        assert!(retired.fenced);
                                        watch.stop_notify(&endpoints, Duration::from_secs(1)).await?;
                                        watch.disconnect_device(DEVICE, Duration::from_secs(1)).await?;
                                        return Ok(());
                                    }
                                    if matches!(action, WatchAction::NotifyRetire) {
                                        frames.submit(&watch, &endpoints, first).map_err(|_| "partial submit")?;
                                        assert!(matches!(frames.next(&watch, &endpoints), Ok(FrameStep::Change(_))));
                                        let retired = frames.retire();
                                        assert_eq!(retired.packet_prefix.as_bytes(), &[0]);
                                        assert!(retired.pending_change.is_none() && !retired.fenced);
                                        watch.stop_notify(&endpoints, Duration::from_secs(1)).await?;
                                        watch.disconnect_device(DEVICE, Duration::from_secs(1)).await?;
                                        return Ok(());
                                    }
                                    let second = watch.next_notify_change(&endpoints, Duration::from_secs(1)).await?.ok_or("missing second notification")?;
                                    let reordered = frames.submit(&watch, &endpoints, second).expect_err("a later change cannot overtake an earlier one");
                                    assert_eq!(reordered.reason, FrameError::Sequence);
                                    frames.submit(&watch, &endpoints, first).map_err(|_| "first submit")?;
                                    let blocked = frames.submit(&watch, &endpoints, reordered.change).expect_err("pending change must apply backpressure");
                                    assert_eq!(blocked.reason, FrameError::Pending);
                                    policy.deny_frame_read.set(true);
                                    assert!(matches!(frames.next(&watch, &endpoints), Err(FrameError::Scope)));
                                    policy.deny_frame_read.set(false);
                                    let FrameStep::Change(first) = frames.next(&watch, &endpoints).map_err(|_| "first drain")? else { return Err("partial packet did not return its change".into()); };
                                    let replay = frames.submit(&watch, &endpoints, first).expect_err("a consumed change cannot be replayed");
                                    assert_eq!(replay.reason, FrameError::Scope);
                                    assert!(matches!(replay.change.decode(watch.owner())?, fss_packet::dbus_bluez_signal::Event::Properties { .. }));
                                    frames.submit(&watch, &endpoints, blocked.change).map_err(|_| "second submit")?;
                                    let FrameStep::Packet(first) = frames.next(&watch, &endpoints).map_err(|_| "first packet")? else { return Err("first packet missing".into()); };
                                    assert_eq!(first.as_bytes(), &[0, 4, 0xa5, 0x5a]);
                                    let FrameStep::Packet(second) = frames.next(&watch, &endpoints).map_err(|_| "second packet")? else { return Err("second packet missing".into()); };
                                    assert_eq!(second.as_bytes(), &[0, 3, 0x7e]);
                                    assert!(matches!(frames.next(&watch, &endpoints), Ok(FrameStep::Change(_))));
                                    assert!(matches!(frames.next(&watch, &endpoints), Ok(FrameStep::NeedChange)));
                                    watch.stop_notify(&endpoints, Duration::from_secs(1)).await?;
                                    assert!(matches!(frames.next(&watch, &endpoints), Err(FrameError::Scope)));
                                    let retired = frames.retire();
                                    assert!(retired.packet_prefix.as_bytes().is_empty());
                                    assert!(retired.pending_change.is_none() && !retired.fenced);
                                    assert_eq!(watch.notification_state(), bluez_bus::NotificationState::Inactive);
                                    watch.disconnect_device(DEVICE, Duration::from_secs(1)).await?;
                                    drop(watch);
                                    Ok(())
                                }
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
    });
    if let Some(effects) = management_effects {
        assert_eq!(
            effects
                .journal()
                .operation(&management_operation)
                .ok_or("missing effect")?
                .state,
            fss_core::EffectState::Committed
        );
    }
    result
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

fn gatt_inventory_body() -> Vec<u8> {
    struct Writer(Vec<u8>);
    impl Writer {
        fn pad(&mut self, align: usize) {
            while self.0.len() % align != 0 {
                self.0.push(0);
            }
        }
        fn string(&mut self, value: &str) {
            self.pad(4);
            self.0
                .extend_from_slice(&(value.len() as u32).to_le_bytes());
            self.0.extend_from_slice(value.as_bytes());
            self.0.push(0);
        }
        fn array(&mut self, align: usize) -> (usize, usize) {
            self.pad(4);
            let index = self.0.len();
            self.0.extend_from_slice(&0_u32.to_le_bytes());
            self.pad(align);
            (index, self.0.len())
        }
        fn finish(&mut self, (at, start): (usize, usize)) {
            let length = (self.0.len() - start) as u32;
            self.0[at..at + 4].copy_from_slice(&length.to_le_bytes());
        }
        fn property(&mut self, key: &str, signature: &[u8]) {
            self.pad(8);
            self.string(key);
            self.0.push(signature.len() as u8);
            self.0.extend_from_slice(signature);
            self.0.push(0);
        }
        fn object(&mut self, path: &str, interface: &str) -> ((usize, usize), (usize, usize)) {
            self.pad(8);
            self.string(path);
            let interfaces = self.array(8);
            self.pad(8);
            self.string(interface);
            let props = self.array(8);
            (interfaces, props)
        }
        fn finish_object(&mut self, (interfaces, props): ((usize, usize), (usize, usize))) {
            self.finish(props);
            self.finish(interfaces);
        }
    }
    let mut w = Writer(Vec::new());
    let root = w.array(8);
    let object = w.object(DEVICE, "org.bluez.Device1");
    w.property("ServicesResolved", b"b");
    w.pad(4);
    w.0.extend_from_slice(&1_u32.to_le_bytes());
    w.finish_object(object);
    let object = w.object(SERVICE_PATH, "org.bluez.GattService1");
    w.property("UUID", b"s");
    w.string(SERVICE_UUID);
    w.property("Device", b"o");
    w.string(DEVICE);
    w.finish_object(object);
    for (path, uuid, flag) in [
        (NOTIFY_PATH, NOTIFY_UUID, "notify"),
        (WRITE_PATH, WRITE_UUID, "write"),
    ] {
        let object = w.object(path, "org.bluez.GattCharacteristic1");
        w.property("UUID", b"s");
        w.string(uuid);
        w.property("Service", b"o");
        w.string(SERVICE_PATH);
        w.property("Flags", b"as");
        let flags = w.array(4);
        w.string(flag);
        w.finish(flags);
        w.finish_object(object);
    }
    w.finish(root);
    w.0
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
fn device_link_requires_admission_and_correlated_lifecycle_replies() -> TestResult {
    let mut input = watch_input(None, ":1.42");
    input.extend_from_slice(&owned_empty_reply(7, ":1.42"));
    input.extend_from_slice(&owned_empty_reply(8, ":1.42"));
    run_watch_action(input.clone(), None, Ok(()), WatchAction::DeviceLifecycle)?;
    run_watch_action(
        input.clone(),
        Some(Stage::BluezDeviceConnect),
        Err(BusError::Denied),
        WatchAction::DeviceLifecycle,
    )?;
    run_watch_action(
        input.clone(),
        None,
        Err(BusError::Denied),
        WatchAction::DevicePathDenied,
    )?;
    run_watch_action(
        watch_input(None, ":1.42"),
        None,
        Err(BusError::DeviceUncertain),
        WatchAction::DeviceRevoked,
    )?;
    run_watch_action(
        input,
        Some(Stage::BluezDeviceDisconnect),
        Err(BusError::Denied),
        WatchAction::DeviceLifecycle,
    )?;
    let mut wrong_owner = watch_input(None, ":1.42");
    wrong_owner.extend_from_slice(&owned_empty_reply(7, ":1.99"));
    run_watch_action(
        wrong_owner,
        None,
        Err(BusError::DeviceUncertain),
        WatchAction::DeviceBadReply,
    )
}

#[test]
fn cancellation_after_device_connect_submission_fences_the_watch() -> TestResult {
    run_watch_action(
        watch_input(None, ":1.42"),
        None,
        Ok(()),
        WatchAction::DeviceCancelled,
    )?;
    let mut input = watch_input(None, ":1.42");
    input.extend_from_slice(&owned_empty_reply(7, ":1.42"));
    run_watch_action(input, None, Ok(()), WatchAction::DeviceDisconnectCancelled)
}

#[test]
fn gatt_selection_is_scoped_correlated_and_preserves_overlapping_changes() -> TestResult {
    let body = gatt_inventory_body();
    let mut input = watch_input(None, ":1.42");
    input.extend_from_slice(&owned_empty_reply(7, ":1.42"));
    input.extend_from_slice(&owned_inventory_reply_body(8, ":1.42", &body));
    input.extend_from_slice(&owned_empty_reply(9, ":1.42"));
    run_watch_action(input.clone(), None, Ok(()), WatchAction::Gatt)?;
    run_watch_action(
        input,
        Some(Stage::BluezGattInventory),
        Err(BusError::Denied),
        WatchAction::Gatt,
    )?;
    let mut overlap = watch_input(None, ":1.42");
    overlap.extend_from_slice(&owned_empty_reply(7, ":1.42"));
    overlap.extend_from_slice(&watch_signal(":1.42", "PropertiesChanged"));
    overlap.extend_from_slice(&owned_inventory_reply_body(8, ":1.42", &body));
    overlap.extend_from_slice(&owned_inventory_reply_body(9, ":1.42", &body));
    overlap.extend_from_slice(&owned_empty_reply(10, ":1.42"));
    run_watch_action(overlap, None, Ok(()), WatchAction::GattOverlap)?;
    let mut wrong_owner = watch_input(None, ":1.42");
    wrong_owner.extend_from_slice(&owned_empty_reply(7, ":1.42"));
    wrong_owner.extend_from_slice(&owned_inventory_reply_body(8, ":1.99", &body));
    run_watch_action(
        wrong_owner,
        None,
        Err(BusError::DeviceUncertain),
        WatchAction::GattBadReply,
    )
}

#[test]
fn cancelled_gatt_inventory_fences_the_owned_device_watch() -> TestResult {
    let mut input = watch_input(None, ":1.42");
    input.extend_from_slice(&owned_empty_reply(7, ":1.42"));
    run_watch_action(input, None, Ok(()), WatchAction::GattCancelled)
}

#[test]
fn notification_values_reassemble_split_and_combined_ble_packets() -> TestResult {
    let mut input = watch_input(None, ":1.42");
    input.extend_from_slice(&owned_empty_reply(7, ":1.42"));
    input.extend_from_slice(&owned_inventory_reply_body(
        8,
        ":1.42",
        &gatt_inventory_body(),
    ));
    input.extend_from_slice(&gatt_value_frame(&[0]));
    input.extend_from_slice(&owned_empty_reply(9, ":1.42"));
    input.extend_from_slice(&gatt_value_frame(&[4, 0xa5, 0x5a, 0, 3, 0x7e]));
    input.extend_from_slice(&owned_empty_reply(10, ":1.42"));
    input.extend_from_slice(&owned_empty_reply(11, ":1.42"));
    run_watch_action(input.clone(), None, Ok(()), WatchAction::Notify)?;
    run_watch_action(input.clone(), None, Ok(()), WatchAction::NotifyRetire)?;
    run_watch_action(input.clone(), None, Ok(()), WatchAction::NotifyBudget)?;
    run_watch_action(input.clone(), None, Ok(()), WatchAction::NotifyDecodeBudget)?;
    run_watch_action(
        input.clone(),
        None,
        Err(BusError::Denied),
        WatchAction::NotifyPathDenied,
    )?;
    run_watch_action(
        input,
        Some(Stage::BluezNotifyStart),
        Err(BusError::Denied),
        WatchAction::Notify,
    )
}

#[test]
fn malformed_notification_preserves_original_and_fences_assembler() -> TestResult {
    let mut input = watch_input(None, ":1.42");
    input.extend_from_slice(&owned_empty_reply(7, ":1.42"));
    input.extend_from_slice(&owned_inventory_reply_body(8, ":1.42", &gatt_inventory_body()));
    input.extend_from_slice(&gatt_value_frame(&[0, 1]));
    input.extend_from_slice(&owned_empty_reply(9, ":1.42"));
    input.extend_from_slice(&owned_empty_reply(10, ":1.42"));
    input.extend_from_slice(&owned_empty_reply(11, ":1.42"));
    run_watch_action(input, None, Ok(()), WatchAction::NotifyBadPacket)
}

#[test]
fn gatt_topology_change_fences_further_reads_but_allows_session_stop() -> TestResult {
    let mut input = watch_input(None, ":1.42");
    input.extend_from_slice(&owned_empty_reply(7, ":1.42"));
    input.extend_from_slice(&owned_inventory_reply_body(
        8,
        ":1.42",
        &gatt_inventory_body(),
    ));
    input.extend_from_slice(&owned_empty_reply(9, ":1.42"));
    input.extend_from_slice(&gatt_value_frame_at(
        "/org/bluez/hci0/dev_01_23_45_67_89_AC/service001/char001",
        &[1],
    ));
    input.extend_from_slice(&gatt_properties_frame(NOTIFY_PATH, None, Some(true)));
    for change in [
        gatt_value_frame_at(WRITE_PATH, &[2]),
        gatt_properties_frame(NOTIFY_PATH, None, Some(false)),
        gatt_properties_frame(NOTIFY_PATH, Some(&[2]), Some(false)),
    ] {
        let mut case = input.clone();
        case.extend_from_slice(&change);
        case.extend_from_slice(&owned_empty_reply(10, ":1.42"));
        case.extend_from_slice(&owned_empty_reply(11, ":1.42"));
        run_watch_action(case, None, Ok(()), WatchAction::NotifyTopology)?;
    }
    Ok(())
}

#[test]
fn gatt_management_dispatch_is_bound_to_one_committed_effect() -> TestResult {
    let mut base = watch_input(None, ":1.42");
    base.extend_from_slice(&owned_empty_reply(7, ":1.42"));
    base.extend_from_slice(&owned_inventory_reply_body(
        8,
        ":1.42",
        &gatt_inventory_body(),
    ));
    base.extend_from_slice(&owned_empty_reply(9, ":1.42"));
    let mut success = base.clone();
    success.extend_from_slice(&gatt_value_frame(&[0x44]));
    success.extend_from_slice(&owned_empty_reply(10, ":1.42"));
    success.extend_from_slice(&owned_empty_reply(11, ":1.42"));
    success.extend_from_slice(&owned_empty_reply(12, ":1.42"));
    run_watch_action(success, None, Ok(()), WatchAction::ManagementWrite)?;
    run_watch_action(
        base.clone(),
        None,
        Ok(()),
        WatchAction::ManagementWriteCancelled,
    )?;
    run_watch_action(
        base.clone(),
        None,
        Ok(()),
        WatchAction::ManagementWriteRevoked,
    )?;
    let mut unjournaled = base.clone();
    unjournaled.extend_from_slice(&owned_empty_reply(10, ":1.42"));
    unjournaled.extend_from_slice(&owned_empty_reply(11, ":1.42"));
    run_watch_action(
        unjournaled,
        None,
        Ok(()),
        WatchAction::ManagementWriteUnjournaled,
    )?;
    let mut denied = base.clone();
    denied.extend_from_slice(&owned_empty_reply(10, ":1.42"));
    denied.extend_from_slice(&owned_empty_reply(11, ":1.42"));
    run_watch_action(
        denied,
        Some(Stage::BluezNotifyRead),
        Ok(()),
        WatchAction::ManagementWriteNotifyDenied,
    )?;
    run_watch_action(
        base.clone(),
        None,
        Ok(()),
        WatchAction::ManagementWriteNotifyRevoked,
    )?;
    base.extend_from_slice(&owned_empty_reply(10, ":1.99"));
    run_watch_action(base, None, Ok(()), WatchAction::ManagementWriteWrongReply)
}

#[test]
fn cancelled_notification_start_or_read_fences_the_owned_watch() -> TestResult {
    let mut input = watch_input(None, ":1.42");
    input.extend_from_slice(&owned_empty_reply(7, ":1.42"));
    input.extend_from_slice(&owned_inventory_reply_body(
        8,
        ":1.42",
        &gatt_inventory_body(),
    ));
    run_watch_action(input.clone(), None, Ok(()), WatchAction::NotifyCancelled)?;
    input.extend_from_slice(&owned_empty_reply(9, ":1.42"));
    run_watch_action(
        input.clone(),
        None,
        Ok(()),
        WatchAction::NotifyReadCancelled,
    )?;
    run_watch_action(
        input.clone(),
        None,
        Ok(()),
        WatchAction::NotifyStopCancelled,
    )?;
    run_watch_action(input, None, Ok(()), WatchAction::NotifyIdle)
}

#[test]
fn notification_start_refuses_stale_selection_and_wrong_owner() -> TestResult {
    let mut input = watch_input(None, ":1.42");
    input.extend_from_slice(&owned_empty_reply(7, ":1.42"));
    input.extend_from_slice(&owned_inventory_reply_body(
        8,
        ":1.42",
        &gatt_inventory_body(),
    ));
    let mut wrong_owner = input.clone();
    wrong_owner.extend_from_slice(&owned_empty_reply(9, ":1.99"));
    run_watch_action(
        wrong_owner,
        None,
        Err(BusError::NotificationUncertain),
        WatchAction::NotifyBadReply,
    )?;
    input.extend_from_slice(&watch_signal(":1.42", "PropertiesChanged"));
    input.extend_from_slice(&owned_empty_reply(9, ":1.42"));
    run_watch_action(input, None, Ok(()), WatchAction::NotifyStale)
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
