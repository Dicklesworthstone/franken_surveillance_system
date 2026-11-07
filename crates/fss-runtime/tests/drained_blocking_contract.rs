#![forbid(unsafe_code)]
//! Native cancellation and ownership checks for the blocking-pool boundary.

use asupersync::{
    runtime::{RuntimeBuilder, yield_now},
    time::{sleep, timeout},
};
use fss_runtime::drained_blocking::{self, WorkOutcome};
use std::{
    future::{Future, poll_fn},
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    task::Poll,
    time::Duration,
};

type Test = Result<(), Box<dyn std::error::Error>>;

async fn wait_flag(cx: &asupersync::Cx, flag: &AtomicBool) -> Test {
    timeout(cx.now(), Duration::from_secs(5), async {
        while !flag.load(Ordering::Acquire) {
            sleep(cx.now(), Duration::from_millis(2)).await;
        }
    })
    .await
    .map_err(|_| "worker did not reach expected state")?;
    Ok(())
}

#[test]
fn cancellation_waits_for_started_closure_and_preserves_its_result() -> Test {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let entered = Arc::new(AtomicBool::new(false));
        let observed_cancel = Arc::new(AtomicBool::new(false));
        let (release_tx, release_rx) = mpsc::channel();
        let entered_worker = Arc::clone(&entered);
        let observed_worker = Arc::clone(&observed_cancel);
        let mut owner = drained_blocking::start(&cx, move |child| {
            entered_worker.store(true, Ordering::Release);
            loop {
                if child.is_cancel_requested() {
                    observed_worker.store(true, Ordering::Release);
                }
                match release_rx.recv_timeout(Duration::from_millis(2)) {
                    Ok(()) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => (),
                    Err(mpsc::RecvTimeoutError::Disconnected) => return 0,
                }
            }
            73
        })
        .map_err(|_| "worker admission failed")?;
        wait_flag(&cx, &entered).await?;
        owner.abort();
        wait_flag(&cx, &observed_cancel).await?;
        let pending = poll_fn(|context| {
            let mut wait = pin!(owner.join());
            Poll::Ready(wait.as_mut().poll(context).is_pending())
        })
        .await;
        assert!(pending, "join returned while closure was still blocked");
        release_tx.send(())?;
        let receipt = timeout(cx.now(), Duration::from_secs(5), owner.join())
            .await
            .map_err(|_| "drain timed out")?
            .ok_or("missing receipt")?;
        assert!(matches!(receipt.work, WorkOutcome::Finished(73)));
        assert!(owner.join().await.is_none());
        Ok(())
    })
}

#[test]
fn queued_cancellation_returns_unstarted_closure_after_pool_release() -> Test {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let pool = cx.blocking_pool_handle().ok_or("missing blocking pool")?;
        let occupied = Arc::new(AtomicBool::new(false));
        let occupied_worker = Arc::clone(&occupied);
        let (release_tx, release_rx) = mpsc::channel();
        let blocker = pool.spawn(move || {
            occupied_worker.store(true, Ordering::Release);
            let _ = release_rx.recv();
        });
        wait_flag(&cx, &occupied).await?;
        let executed = Arc::new(AtomicBool::new(false));
        let executed_worker = Arc::clone(&executed);
        let mut owner = drained_blocking::start(&cx, move |_| {
            executed_worker.store(true, Ordering::Release);
            17
        })
        .map_err(|_| "worker admission failed")?;
        timeout(cx.now(), Duration::from_secs(5), async {
            while pool.pending_count() == 0 {
                yield_now().await;
            }
        })
        .await
        .map_err(|_| "worker was not queued")?;
        owner.abort();
        timeout(cx.now(), Duration::from_secs(5), async {
            while !owner.cancellation_observed() {
                yield_now().await;
            }
        })
        .await
        .map_err(|_| "coordinator did not observe cancellation")?;
        let pending = poll_fn(|context| {
            let mut wait = pin!(owner.join());
            Poll::Ready(wait.as_mut().poll(context).is_pending())
        })
        .await;
        assert!(pending, "queued closure was reported released too early");
        release_tx.send(())?;
        let receipt = timeout(cx.now(), Duration::from_secs(5), owner.join())
            .await
            .map_err(|_| "drain timed out")?
            .ok_or("missing receipt")?;
        assert!(matches!(receipt.work, WorkOutcome::NotStarted(_)));
        assert!(!executed.load(Ordering::Acquire));
        assert!(blocker.is_done());
        Ok(())
    })
}

#[test]
fn panic_is_reported_only_after_closure_is_released() -> Test {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let mut owner =
            drained_blocking::start(&cx, |_| -> () { panic!("synthetic worker panic") })
                .map_err(|_| "worker admission failed")?;
        let receipt = timeout(cx.now(), Duration::from_secs(5), owner.join())
            .await
            .map_err(|_| "drain timed out")?
            .ok_or("missing receipt")?;
        assert!(matches!(receipt.work, WorkOutcome::Panicked));
        Ok(())
    })
}

#[test]
fn missing_pool_refuses_and_returns_the_original_work() -> Test {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let refusal = match drained_blocking::start(&cx, |_| 41_u32) {
            Ok(_) => return Err("operation admitted without a pool".into()),
            Err(refusal) => refusal,
        };
        assert!(matches!(
            refusal.reason,
            drained_blocking::StartFailure::NoPool
        ));
        let work = refusal.work.ok_or("unstarted closure lost")?;
        assert_eq!(work(cx.clone()), 41);
        Ok(())
    })
}
