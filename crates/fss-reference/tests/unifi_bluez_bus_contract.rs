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
}
impl Admission for Policy {
    fn permits(&self, resource: &str, stage: Stage) -> bool {
        self.checks.set(self.checks.get() + 1);
        resource == "fixture:system-bus" && self.deny != Some(stage)
    }
}

struct Fixture {
    input: Vec<u8>,
    read_at: usize,
    written: Rc<RefCell<Vec<u8>>>,
    dropped: Rc<Cell<bool>>,
    pending_at_end: bool,
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
