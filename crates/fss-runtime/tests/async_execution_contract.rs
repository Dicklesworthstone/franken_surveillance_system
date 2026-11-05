#![forbid(unsafe_code)]
//! Native Asupersync execution, source bytes, and abandoned-task accounting.

use std::cell::Cell;
use std::error::Error;
use std::io::Write;
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
