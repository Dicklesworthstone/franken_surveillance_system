#![forbid(unsafe_code)]
//! Native Asupersync execution, source bytes, and abandoned-task accounting.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::error::Error;
use std::future::{Future, poll_fn};
use std::io::Write;
use std::task::Poll;
use std::time::Duration;

use asupersync::io::AsyncReadExt;
use asupersync::net::TcpListener;
use asupersync::runtime::RuntimeBuilder;
use asupersync::time::timeout;
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::execution::{TaskCompletion, TaskSpec, run_owned_async};
use fss_runtime::grant::GrantSet;
use fss_runtime::tcp_ingress::{EndState, IngressError, Receive, TcpIngress};

type TestResult = Result<(), Box<dyn Error>>;

fn root() -> Result<(AuthorityCx, fss_core::RegionTree), Box<dyn Error>> {
    let mut budget = BudgetVector::ZERO;
    budget.bytes = 1024;
    budget.network_bytes = 1024;
    let spec = RootAuthoritySpec {
        trace_id: "trace:async-receive".into(),
        operation_id: OperationId::parse("operation:async-receive")?,
        principal: "principal:owner".into(),
        capabilities: vec![
            RuntimeGrant::AdapterNet.as_str().into(),
            RuntimeGrant::ReadMedia.as_str().into(),
        ],
        deadline: Some(TimestampNs(100)),
        priority: 10,
        budgets: budget,
        privacy_scope: "privacy:local".into(),
        retention_scope: "retention:approved".into(),
        anchor_universe: ContentDigest::sha256(b"async execution contract"),
        generation: 1,
    };
    Ok(AuthorityCx::root(
        spec,
        RegionId::new("region:async")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?)
}

fn task(name: &str) -> Result<TaskSpec, Box<dyn Error>> {
    Ok(TaskSpec {
        task_id: TaskId::new(name)?,
        started_at: TimestampNs(2),
    })
}

#[test]
fn owned_async_work_receives_real_loopback_bytes_before_task_completion() -> TestResult {
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut authority, mut tree) = root()?;
    let id = TaskId::new("task:loopback")?;
    let result = runtime.block_on(async {
        let runtime_cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            task("task:loopback")?,
            &runtime_cx,
            async |owner, cx| {
                let output: Result<Vec<u8>, String> = async {
                    cx.checkpoint().map_err(|e| e.to_string())?;
                    owner
                        .checkpoint_for(
                            RuntimeGrant::AdapterNet,
                            "fixture:loopback",
                            TimestampNs(3),
                            &BudgetVector::ZERO,
                        )
                        .map_err(|e| e.to_string())?;
                    owner
                        .checkpoint_for(
                            RuntimeGrant::ReadMedia,
                            "fixture:loopback",
                            TimestampNs(3),
                            &BudgetVector::ZERO,
                        )
                        .map_err(|e| e.to_string())?;
                    let listener = TcpListener::bind("127.0.0.1:0")
                        .await
                        .map_err(|e| e.to_string())?;
                    let address = listener.local_addr().map_err(|e| e.to_string())?;
                    let sender = std::thread::spawn(move || -> std::io::Result<()> {
                        let mut stream =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(3))?;
                        stream.write_all(b"FLV\x01source")
                    });
                    let (mut stream, _) =
                        timeout(cx.now(), Duration::from_secs(5), listener.accept())
                            .await
                            .map_err(|e| e.to_string())?
                            .map_err(|e| e.to_string())?;
                    let mut cost = BudgetVector::ZERO;
                    cost.network_bytes = 64;
                    owner
                        .checkpoint_for(
                            RuntimeGrant::AdapterNet,
                            "fixture:loopback",
                            TimestampNs(4),
                            &cost,
                        )
                        .map_err(|e| e.to_string())?;
                    let mut buffer = [0_u8; 64];
                    let mut count = 0;
                    while count < b"FLV\x01source".len() {
                        cx.checkpoint().map_err(|e| e.to_string())?;
                        let read = timeout(
                            cx.now(),
                            Duration::from_secs(5),
                            stream.read(&mut buffer[count..]),
                        )
                        .await
                        .map_err(|e| e.to_string())?
                        .map_err(|e| e.to_string())?;
                        if read == 0 {
                            return Err("early EOF".into());
                        }
                        count += read;
                    }
                    sender
                        .join()
                        .map_err(|_| "sender panicked".to_string())?
                        .map_err(|e| e.to_string())?;
                    Ok(buffer[..count].to_vec())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("loopback receive failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(5),
                }
            },
        )
        .await?;
        Ok::<_, Box<dyn Error>>(run)
    })?;
    assert_eq!(result.output?, b"FLV\x01source");
    assert_eq!(result.receipt?.task_id, id);
    assert!(tree.get(authority.region())?.active_tasks.is_empty());
    assert_eq!(authority.budget().remaining().network_bytes, 960);
    Ok(())
}

#[test]
fn dropping_parked_async_work_preserves_active_task_for_reconciliation() -> TestResult {
    struct Guard<'a>(&'a Cell<bool>);
    impl Drop for Guard<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut authority, mut tree) = root()?;
    let dropped = Cell::new(false);
    let entered = Cell::new(false);
    let id = TaskId::new("task:parked")?;
    runtime.block_on(async {
        let runtime_cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let work = run_owned_async(
            &mut authority,
            &mut tree,
            task("task:parked")?,
            &runtime_cx,
            async |owner, cx| {
                let _guard = Guard(&dropped);
                entered.set(true);
                let admitted = cx.checkpoint().is_ok()
                    && owner
                        .checkpoint(TimestampNs(3), &BudgetVector::ZERO)
                        .is_ok();
                assert!(admitted);
                std::future::pending::<()>().await;
                TaskCompletion {
                    output: (),
                    outcome: TaskOutcome::Success,
                    completed_at: TimestampNs(4),
                }
            },
        );
        assert!(
            timeout(runtime_cx.now(), Duration::from_millis(50), work)
                .await
                .is_err()
        );
        Ok::<_, Box<dyn Error>>(())
    })?;
    assert!(entered.get());
    assert!(dropped.get());
    let node = tree.get(authority.region())?;
    assert!(node.active_tasks.contains_key(&id));
    assert!(!node.completed_tasks.contains_key(&id));
    assert!(node.quiescence_proof.is_none());
    Ok(())
}

#[test]
fn tcp_ingress_retries_a_dropped_pending_read_without_losing_or_double_charging_bytes() -> TestResult
{
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut authority, mut tree) = root()?;
    let run = runtime.block_on(async {
        let runtime_cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            task("task:source")?,
            &runtime_cx,
            async |owner, cx| {
                let output: Result<(Vec<u8>, u64, EndState), String> = async {
                    owner
                        .checkpoint_for(
                            RuntimeGrant::AdapterNet,
                            "fixture:source",
                            TimestampNs(3),
                            &BudgetVector::ZERO,
                        )
                        .map_err(|e| e.to_string())?;
                    let listener = TcpListener::bind("127.0.0.1:0")
                        .await
                        .map_err(|e| e.to_string())?;
                    let address = listener.local_addr().map_err(|e| e.to_string())?;
                    let (release, wait) = std::sync::mpsc::channel::<()>();
                    let sender = std::thread::spawn(move || -> std::io::Result<()> {
                        let mut stream =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(3))?;
                        wait.recv_timeout(Duration::from_secs(4))
                            .map_err(std::io::Error::other)?;
                        stream.write_all(b"FLV!")
                    });
                    let (stream, _) = timeout(cx.now(), Duration::from_secs(5), listener.accept())
                        .await
                        .map_err(|e| e.to_string())?
                        .map_err(|e| e.to_string())?;
                    let mut source = TcpIngress::new(stream, "fixture:source", 4, 4)
                        .map_err(|e| e.to_string())?;
                    {
                        let mut read = Box::pin(source.receive(owner, cx, TimestampNs(4)));
                        let pending = poll_fn(|task| match read.as_mut().poll(task) {
                            Poll::Pending => Poll::Ready(true),
                            Poll::Ready(_) => Poll::Ready(false),
                        })
                        .await;
                        if !pending {
                            return Err("read did not park".into());
                        }
                    }
                    let after_first = owner
                        .remaining_budget()
                        .map_err(|e| e.to_string())?
                        .network_bytes;
                    // Identical public region and task labels do not confer the
                    // first owner's prepaid read capacity on a different tree.
                    let (mut other, mut other_tree) = root().map_err(|e| e.to_string())?;
                    let other_run = run_owned_async(
                        &mut other,
                        &mut other_tree,
                        task("task:source").map_err(|e| e.to_string())?,
                        cx,
                        async |other_owner, other_cx| {
                            let observed =
                                source.receive(other_owner, other_cx, TimestampNs(4)).await;
                            TaskCompletion {
                                output: observed,
                                outcome: TaskOutcome::Success,
                                completed_at: TimestampNs(5),
                            }
                        },
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                    if other_run.output != Err(IngressError::Authority) {
                        return Err("other owner reused a reserved read".into());
                    }
                    other_run.receipt.map_err(|e| e.to_string())?;
                    if other.budget().remaining().network_bytes != 1024 {
                        return Err("refused owner was charged".into());
                    }
                    release.send(()).map_err(|e| e.to_string())?;
                    let result = timeout(
                        cx.now(),
                        Duration::from_secs(5),
                        source.receive(owner, cx, TimestampNs(4)),
                    )
                    .await
                    .map_err(|e| e.to_string())?
                    .map_err(|e| e.to_string())?;
                    let Receive::Data { offset: 0, len } = result else {
                        return Err("missing source data".into());
                    };
                    if len == 0 || len > 4 {
                        return Err("invalid source length".into());
                    }
                    if source.receive(owner, cx, TimestampNs(4)).await
                        != Err(IngressError::PendingChunk)
                    {
                        return Err("pending chunk was overwritten".into());
                    }
                    if owner
                        .remaining_budget()
                        .map_err(|e| e.to_string())?
                        .network_bytes
                        != after_first
                    {
                        return Err("pending read was charged twice".into());
                    }
                    let mut output = source
                        .take_chunk()
                        .map_err(|e| e.to_string())?
                        .ok_or("missing chunk")?
                        .into_bytes();
                    while output.len() < 4 {
                        match timeout(
                            cx.now(),
                            Duration::from_secs(5),
                            source.receive(owner, cx, TimestampNs(4)),
                        )
                        .await
                        .map_err(|e| e.to_string())?
                        .map_err(|e| e.to_string())?
                        {
                            Receive::Data { offset, .. } if offset == output.len() as u64 => {
                                let chunk = source
                                    .take_chunk()
                                    .map_err(|e| e.to_string())?
                                    .ok_or("missing chunk")?;
                                output.extend_from_slice(chunk.bytes());
                            }
                            _ => return Err("unexpected source transition".into()),
                        }
                    }
                    let terminal = source
                        .receive(owner, cx, TimestampNs(4))
                        .await
                        .map_err(|e| e.to_string())?;
                    if terminal != Receive::LimitReached {
                        return Err("limit not reached".into());
                    }
                    sender
                        .join()
                        .map_err(|_| "sender panicked".to_string())?
                        .map_err(|e| e.to_string())?;
                    let retirement = source.retire();
                    if retirement.pending.is_some() || retirement.received != 4 {
                        return Err("incorrect retirement".into());
                    }
                    Ok((output, after_first, retirement.state))
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("source test failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(5),
                }
            },
        )
        .await?;
        Ok::<_, Box<dyn Error>>(run)
    })?;
    let (bytes, after_first, state) = run.output?;
    assert_eq!(bytes, b"FLV!");
    assert_eq!(after_first, 1020);
    assert_eq!(state, EndState::LimitReached);
    run.receipt?;
    Ok(())
}

#[test]
fn tcp_ingress_refuses_missing_media_grant_before_reading_or_charging() -> TestResult {
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut authority, mut tree) = root()?;
    let mut resources = BTreeSet::new();
    resources.insert("fixture:denied".to_string());
    authority.narrow_grants(GrantSet::empty().with_scope(RuntimeGrant::AdapterNet, resources))?;
    let run = runtime.block_on(async {
        let runtime_cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            task("task:denied")?,
            &runtime_cx,
            async |owner, cx| {
                let output: Result<(), String> = async {
                    owner
                        .checkpoint_for(
                            RuntimeGrant::AdapterNet,
                            "fixture:denied",
                            TimestampNs(3),
                            &BudgetVector::ZERO,
                        )
                        .map_err(|e| e.to_string())?;
                    let listener = TcpListener::bind("127.0.0.1:0")
                        .await
                        .map_err(|e| e.to_string())?;
                    let address = listener.local_addr().map_err(|e| e.to_string())?;
                    let sender = std::thread::spawn(move || -> std::io::Result<()> {
                        let mut stream =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(3))?;
                        stream.write_all(b"private source")
                    });
                    let (stream, _) = timeout(cx.now(), Duration::from_secs(5), listener.accept())
                        .await
                        .map_err(|e| e.to_string())?
                        .map_err(|e| e.to_string())?;
                    sender
                        .join()
                        .map_err(|_| "sender panicked".to_string())?
                        .map_err(|e| e.to_string())?;
                    let mut source = TcpIngress::new(stream, "fixture:denied", 32, 32)
                        .map_err(|e| e.to_string())?;
                    if source.receive(owner, cx, TimestampNs(4)).await
                        != Err(IngressError::Authority)
                    {
                        return Err("missing media grant was not refused".into());
                    }
                    let retirement = source.retire();
                    if retirement.received != 0
                        || retirement.pending.is_some()
                        || retirement.reserved_bytes != 0
                    {
                        return Err("refused source was read or reserved".into());
                    }
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("grant test failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(5),
                }
            },
        )
        .await?;
        Ok::<_, Box<dyn Error>>(run)
    })?;
    run.output?;
    run.receipt?;
    assert_eq!(authority.budget().remaining().bytes, 1024);
    assert_eq!(authority.budget().remaining().network_bytes, 1024);
    Ok(())
}

#[test]
fn tcp_ingress_retirement_returns_original_untransferred_bytes() -> TestResult {
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut authority, mut tree) = root()?;
    let run = runtime.block_on(async {
        let runtime_cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            task("task:retire")?,
            &runtime_cx,
            async |owner, cx| {
                let output: Result<(), String> = async {
                    owner
                        .checkpoint_for(
                            RuntimeGrant::AdapterNet,
                            "fixture:retire",
                            TimestampNs(3),
                            &BudgetVector::ZERO,
                        )
                        .map_err(|e| e.to_string())?;
                    let listener = TcpListener::bind("127.0.0.1:0")
                        .await
                        .map_err(|e| e.to_string())?;
                    let address = listener.local_addr().map_err(|e| e.to_string())?;
                    let sender = std::thread::spawn(move || -> std::io::Result<()> {
                        let mut stream =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(3))?;
                        stream.write_all(b"Z")
                    });
                    let (stream, _) = timeout(cx.now(), Duration::from_secs(5), listener.accept())
                        .await
                        .map_err(|e| e.to_string())?
                        .map_err(|e| e.to_string())?;
                    let mut source = TcpIngress::new(stream, "fixture:retire", 4, 8)
                        .map_err(|e| e.to_string())?;
                    let outcome = timeout(
                        cx.now(),
                        Duration::from_secs(5),
                        source.receive(owner, cx, TimestampNs(4)),
                    )
                    .await
                    .map_err(|e| e.to_string())?
                    .map_err(|e| e.to_string())?;
                    if outcome != (Receive::Data { offset: 0, len: 1 })
                        || source.pending_bytes() != Some(&b"Z"[..])
                    {
                        return Err("source byte was not retained".into());
                    }
                    sender
                        .join()
                        .map_err(|_| "sender panicked".to_string())?
                        .map_err(|e| e.to_string())?;
                    let retirement = source.retire();
                    let chunk = retirement.pending.ok_or("pending source lost")?;
                    if retirement.state != EndState::Open
                        || retirement.received != 1
                        || chunk.offset() != 0
                        || chunk.bytes() != b"Z"
                    {
                        return Err("retirement changed source bytes".into());
                    }
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("retirement test failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(5),
                }
            },
        )
        .await?;
        Ok::<_, Box<dyn Error>>(run)
    })?;
    run.output?;
    run.receipt?;
    Ok(())
}
