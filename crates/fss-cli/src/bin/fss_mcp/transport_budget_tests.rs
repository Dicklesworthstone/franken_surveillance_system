#![forbid(unsafe_code)]
//! Request-region, deadline and output-reservation contracts over the real scheduler.

use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

const INIT: &str = r#"{"jsonrpc":"2.0","id":"initialize","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"budget-contract","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
const NATIVE_RESULT: &str = r#"{"native":"finished","receipt":"preserve-exactly"}"#;

fn new_server() -> Server {
    Server::new(
        "/unopened-transport-budget-fixture".into(),
        "principal:transport-budget".to_owned(),
    )
}

fn ready() -> Test<Server> {
    let mut server = new_server();
    server.enable_request_tracking();
    if !matches!(server.dispatch(INIT), Dispatch::Reply { .. }) {
        return Err("initialize did not return a protocol reply".into());
    }
    if !matches!(server.dispatch(READY), Dispatch::Ignore) {
        return Err("initialized notification did not complete".into());
    }
    Ok(server)
}

fn call(id: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"doctor"}}}}"#)
}

async fn wait_flag(cx: &Cx, flag: &AtomicBool) -> Test {
    asupersync::time::timeout(cx.now(), Duration::from_secs(5), async {
        while !flag.load(Ordering::Acquire) {
            sleep(cx.now(), POLL_INTERVAL).await;
        }
    })
    .await
    .map_err(|_| "native worker did not reach the expected boundary")?;
    Ok(())
}

async fn retire(cx: &Cx, scheduler: &mut Scheduler) -> Test {
    asupersync::time::timeout(cx.now(), Duration::from_secs(5), async {
        while scheduler.active.is_some() {
            scheduler.retire_ready().await?;
            if scheduler.active.is_some() {
                sleep(cx.now(), POLL_INTERVAL).await;
            }
        }
        Ok::<(), io::Error>(())
    })
    .await
    .map_err(|_| "native worker did not drain")??;
    Ok(())
}

fn flush_replies(replies: &mut Replies, output: &mut Vec<u8>) -> Test {
    // Vec writes and flushes always progress. The loop drains bounded frames in native slices.
    while !replies.empty() {
        replies.pump(output, OUTPUT_STALL_LIMIT)?;
    }
    Ok(())
}

struct ReleaseOnDrop(Arc<AtomicBool>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[test]
fn time_in_the_queue_consumes_the_original_deadline_without_execution() -> Test {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = Cx::current().ok_or("runtime context")?;
        let calls = Arc::new(AtomicUsize::new(0));
        let worker_calls = Arc::clone(&calls);
        let mut scheduler = Scheduler::new(Arc::new(move |_, _| {
            worker_calls.fetch_add(1, Ordering::AcqRel);
            Some((NATIVE_RESULT.to_owned(), ExitIdentity::SUCCESS))
        }));
        let next_request_limit = scheduler.request_limit;
        scheduler.request_limit = Duration::ZERO;
        let admitted = cx.now();
        let original_deadline = admitted + scheduler.request_limit;
        let mut server = ready()?;
        scheduler.accept(server.dispatch(&call("1")), admitted)?;
        assert_eq!(
            scheduler.pending.front().ok_or("queued request")?.deadline,
            original_deadline
        );
        // Changing future admission policy cannot renew an already queued request.
        scheduler.request_limit = next_request_limit;
        assert!(cx.now() >= original_deadline);
        scheduler.start_next(&cx).await?;
        assert!(scheduler.pending.is_empty());
        assert!(scheduler.active.is_none());
        assert_eq!(calls.load(Ordering::Acquire), 0);
        assert!(!scheduler.stop_admission);
        let mut output = Vec::new();
        flush_replies(&mut scheduler.replies, &mut output)?;
        let response = String::from_utf8(output)?;
        assert!(response.contains(r#""id":1"#));
        assert!(response.contains("deadline expired in the queue"));
        assert!(response.contains("native execution did not start"));
        Ok(())
    })
}

#[test]
fn active_expiry_cancels_only_its_real_region_and_keeps_the_finished_native_result() -> Test {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = Cx::current().ok_or("runtime context")?;
        let entered = Arc::new(AtomicBool::new(false));
        let observed = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let _release_on_exit = ReleaseOnDrop(Arc::clone(&release));
        let worker_entered = Arc::clone(&entered);
        let worker_observed = Arc::clone(&observed);
        let worker_release = Arc::clone(&release);
        let (identity_sender, identity_receiver) = std::sync::mpsc::sync_channel(2);
        let mut scheduler = Scheduler::new(Arc::new(move |_, child| {
            let _ = identity_sender.send((child.region_id(), child.budget().deadline));
            worker_entered.store(true, Ordering::Release);
            let started = Instant::now();
            while !worker_release.load(Ordering::Acquire)
                && started.elapsed() < Duration::from_secs(5)
            {
                if child.is_cancel_requested() {
                    worker_observed.store(true, Ordering::Release);
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Some((NATIVE_RESULT.to_owned(), ExitIdentity::SUCCESS))
        }));
        let mut server = ready()?;
        let dispatch = server.dispatch(&call("1"));
        let expected = match &dispatch {
            Dispatch::Tool { id, .. } => id.tool_result(NATIVE_RESULT, ExitIdentity::SUCCESS),
            _ => return Err("native command was not admitted".into()),
        };
        scheduler.accept(dispatch, cx.now())?;
        let deadline = scheduler.pending.front().ok_or("queued request")?.deadline;
        scheduler.start_next(&cx).await?;
        let active = scheduler.active.as_ref().ok_or("active request")?;
        let first_region = active.region.region_id();
        assert_ne!(first_region, cx.region_id());
        assert_eq!(active.deadline, deadline);
        assert_eq!(active.region.cx().budget().deadline, Some(deadline));
        wait_flag(&cx, &entered).await?;
        assert_eq!(
            identity_receiver.try_recv()?,
            (first_region, Some(deadline))
        );

        // The explicit supervisor observes the fixed deadline; no wall-clock sleep is needed.
        scheduler.expire_active(deadline)?;
        scheduler.expire_active(deadline)?;
        wait_flag(&cx, &observed).await?;
        scheduler.retire_ready().await?;
        let held = scheduler
            .active
            .as_ref()
            .ok_or("cancelled owner retired before release")?;
        assert_eq!(held.region.region_id(), first_region);
        assert!(held.stopping);
        assert!(scheduler.replies.empty());
        assert!(
            !cx.is_cancel_requested(),
            "request expiry cancelled the transport owner"
        );

        release.store(true, Ordering::Release);
        retire(&cx, &mut scheduler).await?;
        assert!(!scheduler.stop_admission);
        assert!(scheduler.terminal_failure.is_none());
        let mut output = Vec::new();
        flush_replies(&mut scheduler.replies, &mut output)?;
        assert_eq!(String::from_utf8(output)?, format!("{expected}\n"));
        assert!(cx.checkpoint().is_ok());

        // A successor gets a distinct owned region, not the cancelled region or the parent.
        scheduler.accept(server.dispatch(&call("2")), cx.now())?;
        scheduler.start_next(&cx).await?;
        let next_region = scheduler
            .active
            .as_ref()
            .ok_or("successor request")?
            .region
            .region_id();
        assert_ne!(next_region, first_region);
        assert_ne!(next_region, cx.region_id());
        retire(&cx, &mut scheduler).await?;
        assert_eq!(identity_receiver.try_recv()?.0, next_region);
        Ok(())
    })
}

#[test]
fn a_native_panic_quarantines_queued_commands_before_any_successor_runs() -> Test {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = Cx::current().ok_or("runtime context")?;
        let calls = Arc::new(AtomicUsize::new(0));
        let worker_calls = Arc::clone(&calls);
        let mut scheduler = Scheduler::new(Arc::new(move |_, _| {
            if worker_calls.fetch_add(1, Ordering::AcqRel) == 0 {
                // Inject the native unwind boundary without invoking an unrelated panic hook.
                std::panic::resume_unwind(Box::new("synthetic MCP native boundary panic"));
            }
            Some(("must not execute".to_owned(), ExitIdentity::SUCCESS))
        }));
        let mut server = ready()?;
        scheduler.accept(server.dispatch(&call("1")), cx.now())?;
        scheduler.accept(server.dispatch(&call("2")), cx.now())?;
        scheduler.start_next(&cx).await?;
        retire(&cx, &mut scheduler).await?;
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert!(scheduler.stop_admission);
        assert!(scheduler.terminal_failure.is_some());
        assert!(scheduler.pending.is_empty());
        scheduler.start_next(&cx).await?;
        assert!(scheduler.active.is_none());
        assert!(
            scheduler
                .accept(server.dispatch(&call("3")), cx.now())
                .is_err()
        );
        assert_eq!(calls.load(Ordering::Acquire), 1);
        let mut output = Vec::new();
        flush_replies(&mut scheduler.replies, &mut output)?;
        let response = String::from_utf8(output)?;
        assert!(response.contains(r#""id":1"#));
        assert!(response.contains("panicked"));
        assert!(response.contains("effects may have committed"));
        assert!(!response.contains(r#""id":2,"result"#));
        scheduler.cancel_and_drain(&cx).await?;
        assert!(cx.checkpoint().is_ok());
        Ok(())
    })
}

#[test]
fn output_pressure_does_not_renew_a_queued_request_deadline() -> Test {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = Cx::current().ok_or("runtime context")?;
        let calls = Arc::new(AtomicUsize::new(0));
        let worker_calls = Arc::clone(&calls);
        let mut scheduler = Scheduler::new(Arc::new(move |_, _| {
            worker_calls.fetch_add(1, Ordering::AcqRel);
            Some((NATIVE_RESULT.to_owned(), ExitIdentity::SUCCESS))
        }));
        // One byte beyond the control allowance prevents reserving a native result.
        let allowance = MAX_QUEUED_REPLY_BYTES - MAX_NATIVE_REPLY_BYTES;
        scheduler.replies.push("m".repeat(allowance))?;
        assert!(!scheduler.replies.capacity_for(MAX_NATIVE_REPLY_BYTES, 1));
        let next_request_limit = scheduler.request_limit;
        scheduler.request_limit = Duration::from_nanos(1);
        let mut server = ready()?;
        scheduler.accept(server.dispatch(&call("1")), cx.now())?;
        let deadline = scheduler.pending.front().ok_or("queued request")?.deadline;
        scheduler.request_limit = next_request_limit;
        scheduler.start_next(&cx).await?;
        assert!(scheduler.active.is_none());
        assert_eq!(scheduler.pending.len(), 1);
        assert_eq!(calls.load(Ordering::Acquire), 0);

        sleep(cx.now(), POLL_INTERVAL).await;
        assert!(cx.now() >= deadline);
        flush_replies(&mut scheduler.replies, &mut Vec::new())?;
        assert!(scheduler.replies.capacity_for(MAX_NATIVE_REPLY_BYTES, 1));
        assert_eq!(
            scheduler.pending.front().ok_or("queued request")?.deadline,
            deadline
        );
        scheduler.start_next(&cx).await?;
        assert!(scheduler.pending.is_empty());
        assert!(scheduler.active.is_none());
        assert_eq!(calls.load(Ordering::Acquire), 0);
        let mut output = Vec::new();
        flush_replies(&mut scheduler.replies, &mut output)?;
        let response = String::from_utf8(output)?;
        assert!(response.contains(r#""id":1"#));
        assert!(response.contains("deadline expired in the queue"));
        assert!(response.contains("native execution did not start"));
        Ok(())
    })
}

struct PartialOutput {
    allowance: usize,
    bytes: Vec<u8>,
    write_calls: usize,
    flush_calls: usize,
}

impl Write for PartialOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.write_calls += 1;
        if self.allowance == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let written = self.allowance.min(bytes.len());
        self.allowance -= written;
        self.bytes.extend_from_slice(&bytes[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_calls += 1;
        Err(io::ErrorKind::WouldBlock.into())
    }
}

#[test]
fn partial_writes_and_new_metadata_never_renew_an_unflushed_response_deadline() -> Test {
    let mut replies = Replies::default();
    let admitted = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .ok_or("monotonic fixture epoch")?;
    let key = RequestKey::Integer(1);
    replies
        .frames
        .enqueue_at("old native result".to_owned(), Some(key.clone()), admitted)?;
    let mut output = PartialOutput {
        allowance: 1,
        bytes: Vec::new(),
        write_calls: 0,
        flush_calls: 0,
    };
    replies.pump(&mut output, OUTPUT_STALL_LIMIT)?;
    assert_eq!(output.bytes.len(), 1);
    assert_eq!(replies.frames.oldest_enqueued(), Some(admitted));
    assert_eq!(replies.flush_since, Some(admitted));
    assert!(replies.flush_pending);
    assert!(replies.owns(&key));

    replies.push("new metadata".to_owned())?;
    output.allowance = usize::MAX;
    replies.pump(&mut output, OUTPUT_STALL_LIMIT)?;
    assert!(replies.frames.is_empty());
    assert_eq!(replies.flush_since, Some(admitted));
    assert!(!replies.empty(), "pending flush is still owned output");
    assert!(
        replies.owns(&key),
        "pending flush must retain the original identity"
    );
    replies.push("more metadata".to_owned())?;
    replies.pump(&mut output, OUTPUT_STALL_LIMIT)?;
    assert!(replies.frames.is_empty());
    assert_eq!(replies.flush_since, Some(admitted));

    // The explicit age/limit pair avoids waiting for the production delivery timeout.
    let calls = (output.write_calls, output.flush_calls, output.bytes.len());
    assert_eq!(
        replies
            .pump(&mut output, Duration::from_millis(500))
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert_eq!(
        (output.write_calls, output.flush_calls, output.bytes.len()),
        calls
    );
    assert!(replies.owns(&key));
    Ok(())
}
