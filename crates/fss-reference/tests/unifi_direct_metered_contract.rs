#![forbid(unsafe_code)]
//! Canonical admission and conservative poll-level transport accounting.

use asupersync::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    runtime::RuntimeBuilder,
};
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_reference::unifi_direct::metered::MeteredIo;
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};
use std::{
    cell::{Cell, RefCell},
    error::Error,
    io::Cursor,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};

type TestResult = Result<(), Box<dyn Error>>;

fn root(bytes: u64) -> Result<(AuthorityCx, fss_core::RegionTree), Box<dyn Error>> {
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = bytes;
    let spec = RootAuthoritySpec {
        trace_id: "trace:meter".into(),
        operation_id: OperationId::parse("operation:meter")?,
        principal: "principal:fixture".into(),
        capabilities: vec![RuntimeGrant::AdapterNet.as_str().into()],
        deadline: Some(TimestampNs(60_000_000_000)),
        priority: 10,
        budgets: budget,
        privacy_scope: "privacy:local".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"metered transport test"),
        generation: 1,
    };
    Ok(AuthorityCx::root(
        spec,
        RegionId::new("region:meter")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?)
}

struct PendingOnce {
    calls: Rc<Cell<usize>>,
}
impl AsyncRead for PendingOnce {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let count = self.calls.get() + 1;
        self.calls.set(count);
        if count == 1 {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            buf.put_slice(b"x");
            Poll::Ready(Ok(()))
        }
    }
}

struct PendingWriter {
    calls: Rc<Cell<usize>>,
    bytes: Rc<RefCell<Vec<u8>>>,
}
impl AsyncWrite for PendingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let count = self.calls.get() + 1;
        self.calls.set(count);
        if count == 1 {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            self.bytes.borrow_mut().push(bytes[0]);
            Poll::Ready(Ok(1))
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct FailRead {
    calls: Rc<Cell<usize>>,
}
impl AsyncRead for FailRead {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.calls.set(self.calls.get() + 1);
        Poll::Ready(Err(std::io::Error::other("fixture failure")))
    }
}

#[test]
fn pending_poll_reuses_reservation_but_cannot_bypass_budget() -> TestResult {
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut owner, mut tree) = root(4)?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut owner,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:meter-pending")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let calls = Rc::new(Cell::new(0));
                let output: Result<(), Box<dyn Error>> = async {
                    let mut io = MeteredIo::new(
                        PendingOnce {
                            calls: calls.clone(),
                        },
                        task,
                        cx,
                        TimestampNs(3),
                        "fixture:camera",
                        4,
                    )?;
                    let mut buffer = [0_u8; 4];
                    for _ in 0..4 {
                        assert_eq!(io.read(&mut buffer).await?, 1);
                        assert_eq!(buffer[0], b'x');
                    }
                    let error = io
                        .read(&mut buffer)
                        .await
                        .expect_err("reservation must be exhausted");
                    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
                    assert_eq!(calls.get(), 5);
                    Ok(())
                }
                .await;
                TaskCompletion {
                    output,
                    outcome: TaskOutcome::Success,
                    completed_at: TimestampNs(59_000_000_000),
                }
            },
        )
        .await?;
        result.receipt?;
        result.output
    })
}

#[test]
fn reads_and_writes_are_bounded_and_share_one_task_budget() -> TestResult {
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut owner, mut tree) = root(8)?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut owner,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:meter-io")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: Result<(), Box<dyn Error>> = async {
                    let mut io = MeteredIo::new(
                        Cursor::new(b"abcdefgh".to_vec()),
                        task,
                        cx,
                        TimestampNs(3),
                        "fixture:camera",
                        4,
                    )?;
                    let mut buffer = [0_u8; 8];
                    assert_eq!(io.read(&mut buffer).await?, 4);
                    assert_eq!(&buffer[..4], b"abcd");
                    assert_eq!(io.write(b"WXYZtoo-long").await?, 4);
                    assert_eq!(
                        io.read(&mut buffer)
                            .await
                            .expect_err("budget must be exhausted")
                            .kind(),
                        std::io::ErrorKind::PermissionDenied
                    );
                    Ok(())
                }
                .await;
                TaskCompletion {
                    output,
                    outcome: TaskOutcome::Success,
                    completed_at: TimestampNs(59_000_000_000),
                }
            },
        )
        .await?;
        result.receipt?;
        result.output
    })
}

#[test]
fn pending_and_partial_writes_consume_one_reservation_without_losing_bytes() -> TestResult {
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut owner, mut tree) = root(4)?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut owner,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:meter-write")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: Result<(), Box<dyn Error>> = async {
                    let calls = Rc::new(Cell::new(0));
                    let bytes = Rc::new(RefCell::new(Vec::new()));
                    let mut io = MeteredIo::new(
                        PendingWriter {
                            calls: calls.clone(),
                            bytes: bytes.clone(),
                        },
                        task,
                        cx,
                        TimestampNs(3),
                        "fixture:camera",
                        4,
                    )?;
                    io.write_all(b"abcd").await?;
                    assert_eq!(&*bytes.borrow(), b"abcd");
                    assert_eq!(calls.get(), 5);
                    assert_eq!(
                        io.write(b"e").await.expect_err("budget exhausted").kind(),
                        std::io::ErrorKind::PermissionDenied
                    );
                    assert_eq!(calls.get(), 5);
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("meter test failed".into())
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

#[test]
fn io_error_forfeits_unused_reservation() -> TestResult {
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut owner, mut tree) = root(4)?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut owner,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:meter-error")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: Result<(), Box<dyn Error>> = async {
                    let calls = Rc::new(Cell::new(0));
                    let mut io = MeteredIo::new(
                        FailRead {
                            calls: calls.clone(),
                        },
                        task,
                        cx,
                        TimestampNs(3),
                        "fixture:camera",
                        4,
                    )?;
                    let mut bytes = [0_u8; 4];
                    assert_eq!(
                        io.read(&mut bytes).await.expect_err("fixture error").kind(),
                        std::io::ErrorKind::Other
                    );
                    assert_eq!(
                        io.read(&mut bytes)
                            .await
                            .expect_err("reservation forfeited")
                            .kind(),
                        std::io::ErrorKind::PermissionDenied
                    );
                    assert_eq!(calls.get(), 1);
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("meter test failed".into())
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

#[test]
fn nested_meters_share_one_clock_and_charge_both_layers() -> TestResult {
    use fss_reference::unifi_direct::metered::MeteredClock;
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut owner, mut tree) = root(6)?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut owner,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:nested-meter-clock")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: TestResult = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                    let raw = MeteredIo::with_clock(
                        Cursor::new(b"abc".to_vec()),
                        clock,
                        "fixture:camera",
                        1,
                    )?;
                    let mut outer = MeteredIo::with_clock(raw, clock, "fixture:camera", 1)?;
                    let mut byte = [0_u8; 1];
                    for expected in b"abc" {
                        assert_eq!(outer.read(&mut byte).await?, 1);
                        assert_eq!(byte[0], *expected);
                    }
                    assert_eq!(
                        outer
                            .read(&mut byte)
                            .await
                            .expect_err("both layers must charge the task")
                            .kind(),
                        std::io::ErrorKind::PermissionDenied,
                    );
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("nested clock fixture failed".into())
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

#[test]
fn independently_anchored_nested_meters_refuse_clock_regression() -> TestResult {
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut owner, mut tree) = root(100)?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut owner,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:independent-meter-clocks")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: TestResult = async {
                    let inner = MeteredIo::new(
                        Cursor::new(b"x".to_vec()),
                        task,
                        cx,
                        TimestampNs(3),
                        "fixture:camera",
                        1,
                    )?;
                    // A deliberately later anchor makes the mismatch deterministic.
                    let mut outer = MeteredIo::new(
                        inner,
                        task,
                        cx,
                        TimestampNs(30_000_000_000),
                        "fixture:camera",
                        1,
                    )?;
                    let mut byte = [0_u8; 1];
                    assert_eq!(
                        outer
                            .read(&mut byte)
                            .await
                            .expect_err("inner clock must not move task time backwards")
                            .kind(),
                        std::io::ErrorKind::PermissionDenied
                    );
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("clock regression fixture failed".into())
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
