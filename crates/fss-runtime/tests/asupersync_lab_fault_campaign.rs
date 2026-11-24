#![forbid(unsafe_code)]
//! 128-seed `asupersync::lab::LabRuntime` deterministic fault campaign and native
//! `asupersync_ops` contract suite (`fss-x4a.31.5.2`).
//!
//! Covers all 4 mandatory fault workflows across 128 deterministic seeds with
//! bit-for-bit identical same-seed replay verification and emits structured JSONL
//! records (128 seeds + summary) to `target/test-logs/asupersync-lab/fault_campaign.jsonl`.

#[path = "asupersync_lab_fault_campaign/daemon_alert.rs"]
mod daemon_alert;
#[path = "asupersync_lab_fault_campaign/rtsp_tutk.rs"]
mod rtsp_tutk;

use std::error::Error;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::time::Duration;

use asupersync::io::AsyncWriteExt;
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::RuntimeBuilder;
use fss_core::{ContentDigest, OperationId, RegionId, TaskId, TaskOutcome, TimestampNs};
use fss_runtime::asupersync_ops::{
    BoundaryError, CxNetBoundary, CxTimerBoundary, PollBudget, PollStep, ScopedRegionWorker,
    ScopedWorkerError, ScopedWorkerGroup, StructuredRegionRunner, WorkerGroupBounds,
};
use fss_runtime::obligation::new_obligation;

use daemon_alert::{run_workflow_alert_tls_indeterminate, run_workflow_daemon_shutdown_race};
use rtsp_tutk::{
    TestResult, make_root, run_workflow_rtsp_teardown, run_workflow_tutk_backoff_reconnect,
};

const CAMPAIGN_SEEDS: u64 = 128;
const SEED_BASE: u64 = 0xA500_0000;

fn jsonl_log_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map_or(manifest_dir.clone(), PathBuf::from);
    repo_root
        .join("target")
        .join("test-logs")
        .join("asupersync-lab")
        .join("fault_campaign.jsonl")
}

#[test]
fn lab_runtime_128_seed_deterministic_fault_campaign_and_bit_exact_replay() -> TestResult {
    let log_path = jsonl_log_path();
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut log_file = File::create(&log_path)?;
    let mut total_steps = 0_u64;

    for idx in 0..CAMPAIGN_SEEDS {
        let seed = SEED_BASE + idx;
        let worker_count = 1 + ((seed as usize) % 4);

        let rtsp_a = run_workflow_rtsp_teardown(seed)?;
        assert_eq!(
            rtsp_a,
            run_workflow_rtsp_teardown(seed)?,
            "seed {seed}: RTSP replay diverged"
        );
        let tutk_a = run_workflow_tutk_backoff_reconnect(seed)?;
        assert_eq!(
            tutk_a,
            run_workflow_tutk_backoff_reconnect(seed)?,
            "seed {seed}: TUTK replay diverged"
        );
        let daemon_a = run_workflow_daemon_shutdown_race(seed)?;
        assert_eq!(
            daemon_a,
            run_workflow_daemon_shutdown_race(seed)?,
            "seed {seed}: daemon replay diverged"
        );
        let alert_a = run_workflow_alert_tls_indeterminate(seed)?;
        assert_eq!(
            alert_a,
            run_workflow_alert_tls_indeterminate(seed)?,
            "seed {seed}: alert replay diverged"
        );

        for run in [&rtsp_a, &tutk_a, &daemon_a, &alert_a] {
            assert!(run.quiescent, "seed {seed}: LabRuntime not quiescent");
            assert_eq!(run.active_tasks, 0, "seed {seed}: active_tasks != 0");
            assert_eq!(
                run.leaked_obligations, 0,
                "seed {seed}: leaked_obligations != 0"
            );
            assert_eq!(
                run.invariant_violations, 0,
                "seed {seed}: invariant violations"
            );
        }

        let mut combined_bytes = Vec::with_capacity(128);
        combined_bytes.extend_from_slice(&rtsp_a.trace_digest.bytes());
        combined_bytes.extend_from_slice(&tutk_a.trace_digest.bytes());
        combined_bytes.extend_from_slice(&daemon_a.trace_digest.bytes());
        combined_bytes.extend_from_slice(&alert_a.trace_digest.bytes());
        let combined = ContentDigest::sha256(&combined_bytes);
        let seed_steps = rtsp_a.steps + tutk_a.steps + daemon_a.steps + alert_a.steps;
        total_steps = total_steps.saturating_add(seed_steps);

        writeln!(
            log_file,
            "{{\"kind\":\"seed_result\",\"seed\":{seed},\"worker_count\":{worker_count},\
             \"rtsp_digest\":\"{}\",\"tutk_digest\":\"{}\",\"daemon_digest\":\"{}\",\
             \"alert_digest\":\"{}\",\"combined_trace_digest\":\"{combined}\",\
             \"replay_bit_identical\":true,\"quiescent\":true,\"active_tasks\":0,\
             \"leaked_obligations\":0,\"invariant_violations\":0,\"alert_dispatch_count\":{},\
             \"steps\":{seed_steps}}}",
            rtsp_a.trace_digest,
            tutk_a.trace_digest,
            daemon_a.trace_digest,
            alert_a.trace_digest,
            alert_a.detail_counter,
        )?;
    }

    writeln!(
        log_file,
        "{{\"kind\":\"campaign_summary\",\"seeds_executed\":{CAMPAIGN_SEEDS},\
         \"replay_bit_identical_seeds\":{CAMPAIGN_SEEDS},\"workflows_per_seed\":4,\
         \"all_quiescent\":true,\"total_active_tasks\":0,\"total_leaked_obligations\":0,\
         \"total_invariant_violations\":0,\"total_lab_steps\":{total_steps}}}"
    )?;
    log_file.flush()?;
    Ok(())
}

#[test]
fn structured_region_runner_and_cx_boundaries_native_contract() -> TestResult {
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing Asupersync runtime Cx")?;
        let (auth, tree) = make_root("op:runner:clean", "region:runner:clean", TimestampNs(1))?;
        let mut runner = StructuredRegionRunner::new(auth, tree);

        let ob1 = new_obligation(
            "ob:runner:fast",
            OperationId::parse("op:runner:fast")?,
            "fast task retired",
        )?;
        let _ = runner.spawn_task(
            &cx,
            TaskId::new("task:runner:fast")?,
            Some(ob1),
            TimestampNs(2),
            |c| async move {
                if CxTimerBoundary::sleep(&c, Duration::from_millis(2))
                    .await
                    .is_err()
                {
                    return TaskOutcome::Cancelled;
                }
                TaskOutcome::Success
            },
        )?;
        let ob2 = new_obligation(
            "ob:runner:cancel",
            OperationId::parse("op:runner:cancel")?,
            "cancellable drained",
        )?;
        let _ = runner.spawn_task(
            &cx,
            TaskId::new("task:runner:cancel")?,
            Some(ob2),
            TimestampNs(3),
            |c| async move {
                let Ok(budget) = PollBudget::new(500) else {
                    return TaskOutcome::Failed("invalid_budget".to_owned());
                };
                match CxNetBoundary::poll_until_ready(
                    &c,
                    budget,
                    Duration::from_secs(5),
                    Duration::from_millis(2),
                    |_| Ok(PollStep::<()>::Pending),
                )
                .await
                {
                    Err(BoundaryError::Cancelled) => TaskOutcome::Cancelled,
                    Ok(()) => TaskOutcome::Success,
                    Err(_) => TaskOutcome::Failed("unexpected_err".to_owned()),
                }
            },
        )?;

        let _ = CxTimerBoundary::sleep(&cx, Duration::from_millis(10)).await;
        runner.request_cancellation(TimestampNs(10))?;
        let receipt = runner
            .drain_and_finalize(&cx, Duration::from_secs(2), TimestampNs(20))
            .await?;
        assert_eq!(receipt.active_tasks, 0);
        assert_eq!(receipt.leaked_obligations, 0);
        assert_eq!(receipt.completed_tasks + receipt.cancelled_tasks, 2);

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let mut writer_handle = cx.spawn(move |c| async move {
            let mut client = TcpStream::connect(addr).await?;
            CxNetBoundary::write_all_bounded(
                &c,
                &mut client,
                b"FSS-ASYNC-FRAME",
                Duration::from_secs(2),
            )
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;
            client.flush().await
        })?;
        let (mut accepted, _) =
            CxTimerBoundary::with_timeout(&cx, Duration::from_secs(2), listener.accept()).await??;
        let mut buf = [0_u8; 15];
        CxNetBoundary::read_exact_bounded(&cx, &mut accepted, &mut buf, Duration::from_secs(2))
            .await?;
        assert_eq!(&buf, b"FSS-ASYNC-FRAME");
        assert!(writer_handle.join(&cx).await.is_ok());
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn scoped_worker_group_and_single_worker_enforce_bounds_and_zero_orphan_drain() -> TestResult {
    let bounds = WorkerGroupBounds::new(
        RegionId::new("region:test:scoped_group")?,
        "fss-test-grp",
        1,
        4,
        2,
        Duration::from_secs(2),
    )?;
    let group = ScopedWorkerGroup::new(bounds)?;
    let ran = Arc::new(AtomicUsize::new(0));
    let cancelled = Arc::new(AtomicU32::new(0));
    for _ in 0..2 {
        let ran_c = Arc::clone(&ran);
        let can_c = Arc::clone(&cancelled);
        group.spawn_worker(move |token| {
            ran_c.fetch_add(1, Ordering::AcqRel);
            if token
                .sleep_cooperative(Duration::from_secs(5), Duration::from_millis(5))
                .is_err()
            {
                can_c.fetch_add(1, Ordering::AcqRel);
            }
        })?;
    }
    assert_eq!(
        group.spawn_worker(|_| {}),
        Err(ScopedWorkerError::CapacityReached { limit: 2 })
    );
    let receipt = group.drain_and_shutdown();
    assert_eq!(receipt.active_workers, 0);
    assert!(receipt.drained_within_timeout && receipt.runtime_quiescent);
    assert_eq!(receipt.panicked_workers, 0);
    assert_eq!(receipt.total_spawned, 2);

    let single_ran = Arc::new(AtomicBool::new(false));
    let single_c = Arc::clone(&single_ran);
    let worker = ScopedRegionWorker::spawn(
        RegionId::new("region:test:single_worker")?,
        "fss-test-one",
        Duration::from_secs(2),
        move |token| {
            single_c.store(true, Ordering::Release);
            let _ = token.sleep_cooperative(Duration::from_secs(5), Duration::from_millis(5));
        },
    )?;
    let single_receipt = worker.join_and_finalize();
    assert_eq!(single_receipt.active_workers, 0);
    assert!(single_receipt.drained_within_timeout && single_receipt.runtime_quiescent);
    Ok(())
}
