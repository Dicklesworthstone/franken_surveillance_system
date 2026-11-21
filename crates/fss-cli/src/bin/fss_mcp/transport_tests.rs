#![forbid(unsafe_code)]
//! Native Asupersync ownership checks for the MCP scheduler and its actual framing loop.

use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

type Test = Result<(), Box<dyn std::error::Error>>;

const INIT: &str = r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"ownership-test","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

fn server() -> Server {
    Server::new(
        "/not-read-by-scheduler-test".into(),
        "principal:test".to_owned(),
    )
}

fn ready() -> Server {
    let mut server = server();
    let _ = server.handle(INIT);
    let _ = server.handle(READY);
    server
}

fn call(id: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"doctor","arguments":{{}}}}}}"#
    )
}

fn cancel(id: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","method":"notifications/cancelled","params":{{"requestId":{id}}}}}"#
    )
}

async fn wait_flag(cx: &Cx, flag: &AtomicBool) -> Test {
    asupersync::time::timeout(cx.now(), Duration::from_secs(5), async {
        while !flag.load(Ordering::Acquire) {
            sleep(cx.now(), POLL_INTERVAL).await;
        }
    })
    .await
    .map_err(|_| "native worker did not reach expected boundary")?;
    Ok(())
}

#[test]
fn active_cancel_is_exactly_scoped_and_cannot_erase_completed_native_output() -> Test {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = Cx::current().ok_or("no runtime context")?;
        let entered = Arc::new(AtomicBool::new(false));
        let observed = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let worker_entered = Arc::clone(&entered);
        let worker_observed = Arc::clone(&observed);
        let worker_release = Arc::clone(&release);
        let mut scheduler = Scheduler::new(Arc::new(move |_, child| {
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
            Some((
                r#"{"native":"committed"}"#.to_owned(),
                ExitIdentity::SUCCESS,
            ))
        }));
        let mut server = ready();
        scheduler.accept(server.dispatch(&call("9007199254740993")))?;
        scheduler.start_next(&cx)?;
        wait_flag(&cx, &entered).await?;
        // Text and integer identities cannot alias, even beyond floating-point precision.
        scheduler.accept(server.dispatch(&cancel(r#""9007199254740993""#)))?;
        sleep(cx.now(), Duration::from_millis(10)).await;
        assert!(!observed.load(Ordering::Acquire));
        scheduler.accept(server.dispatch(r#"{"jsonrpc":"2.0","id":"live","method":"ping"}"#))?;
        let mut output = Vec::new();
        scheduler.replies.pump(&mut output, OUTPUT_STALL_LIMIT)?;
        assert!(String::from_utf8(output)?.contains(r#""id":"live","result":{}"#));
        scheduler.accept(server.dispatch(&cancel("9007199254740993")))?;
        wait_flag(&cx, &observed).await?;
        scheduler.retire_ready().await?;
        assert!(
            scheduler.active.is_some(),
            "a cancellation request is not a drain receipt"
        );
        release.store(true, Ordering::Release);
        let limit = Instant::now();
        while scheduler.active.is_some() && limit.elapsed() < Duration::from_secs(5) {
            scheduler.retire_ready().await?;
            sleep(cx.now(), POLL_INTERVAL).await;
        }
        assert!(scheduler.active.is_none());
        let mut output = Vec::new();
        scheduler.replies.pump(&mut output, OUTPUT_STALL_LIMIT)?;
        let response = String::from_utf8(output)?;
        assert!(response.contains(r#""id":9007199254740993"#));
        assert!(response.contains(r#"{\"native\":\"committed\"}"#));
        assert!(response.contains(r#""isError":false"#));
        // Late cancellation is a no-op and never invokes a native application cancel operation.
        scheduler.accept(server.dispatch(&cancel("9007199254740993")))?;
        assert!(scheduler.replies.empty());
        Ok(())
    })
}

#[test]
fn queued_cancellation_duplicates_and_pressure_never_execute_refused_commands() -> Test {
    let calls = Arc::new(AtomicUsize::new(0));
    let worker_calls = Arc::clone(&calls);
    let mut scheduler = Scheduler::new(Arc::new(move |_, _| {
        worker_calls.fetch_add(1, Ordering::Relaxed);
        Some(("{}".to_owned(), ExitIdentity::SUCCESS))
    }));
    let mut server = ready();
    scheduler.accept(server.dispatch(&call("-0")))?;
    scheduler.accept(server.dispatch(&call("0")))?;
    assert_eq!(
        scheduler.pending.len(),
        1,
        "numeric ID normalization rejects duplicate -0/0"
    );
    scheduler.accept(server.dispatch(&cancel("0")))?;
    assert!(scheduler.pending.is_empty());
    for id in 1..=MAX_QUEUED_REQUESTS + 1 {
        scheduler.accept(server.dispatch(&call(&id.to_string())))?;
    }
    assert_eq!(scheduler.pending.len(), MAX_QUEUED_REQUESTS);
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let mut output = Vec::new();
    scheduler.replies.pump(&mut output, OUTPUT_STALL_LIMIT)?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("Request id is already in flight"));
    assert!(output.contains("Request cancelled before native execution"));
    assert!(output.contains("Native request queue is full"));
    Ok(())
}

#[test]
fn eof_drains_all_admitted_native_commands_in_fifo_order() -> Test {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = Cx::current().ok_or("no runtime context")?;
        let count = Arc::new(AtomicUsize::new(0));
        let worker_count = Arc::clone(&count);
        let input = format!("{INIT}\n{READY}\n{}\n{}\n", call("1"), call("2"));
        let mut output = Vec::new();
        serve_owned(
            &mut server(),
            &cx,
            &mut io::Cursor::new(input),
            &mut output,
            Arc::new(move |_, _| {
                Some((
                    worker_count.fetch_add(1, Ordering::Relaxed).to_string(),
                    ExitIdentity::SUCCESS,
                ))
            }),
            OUTPUT_STALL_LIMIT,
        )
        .await?;
        let output = String::from_utf8(output)?;
        let replies: Vec<_> = output.lines().collect();
        assert_eq!(count.load(Ordering::Relaxed), 2);
        assert_eq!(replies.len(), 3);
        assert!(replies[1].contains(r#""id":1"#) && replies[1].contains(r#""text":"0"#));
        assert!(replies[2].contains(r#""id":2"#) && replies[2].contains(r#""text":"1"#));
        Ok(())
    })
}

struct GatedInput {
    prefix: io::Cursor<Vec<u8>>,
    suffix: io::Cursor<Vec<u8>>,
    entered: Arc<AtomicBool>,
}

impl Read for GatedInput {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.prefix.position() < self.prefix.get_ref().len() as u64 {
            self.prefix.read(bytes)
        } else if self.entered.load(Ordering::Acquire) {
            self.suffix.read(bytes)
        } else {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }
}

#[test]
fn partial_frame_failure_cancels_and_drains_started_native_work_before_return() -> Test {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = Cx::current().ok_or("no runtime context")?;
        let entered = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let worker_entered = Arc::clone(&entered);
        let worker_finished = Arc::clone(&finished);
        let mut input = GatedInput {
            prefix: io::Cursor::new(format!("{INIT}\n{READY}\n{}\n", call("1")).into_bytes()),
            suffix: io::Cursor::new(b"{".to_vec()),
            entered,
        };
        let result = serve_owned(
            &mut server(),
            &cx,
            &mut input,
            &mut Vec::new(),
            Arc::new(move |_, child| {
                worker_entered.store(true, Ordering::Release);
                let started = Instant::now();
                while !child.is_cancel_requested() && started.elapsed() < Duration::from_secs(5) {
                    std::thread::sleep(POLL_INTERVAL);
                }
                worker_finished.store(child.is_cancel_requested(), Ordering::Release);
                Some(("cancelled".to_owned(), ExitIdentity::AGENT_REFUSED))
            }),
            OUTPUT_STALL_LIMIT,
        )
        .await;
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData)
        );
        assert!(
            finished.load(Ordering::Acquire),
            "transport returned before the cancelled worker drained"
        );
        Ok(())
    })
}

#[test]
fn cancelled_notifications_are_closed_and_do_not_accept_authority_or_malformed_ids() {
    let mut server = ready();
    for params in [
        r#"{"requestId":1,"root":"/other"}"#,
        r#"{"requestId":null}"#,
        r#"{"requestId":1.0}"#,
        r#"{"requestId":1,"reason":7}"#,
        r#"{"requestId":1,"_meta":false}"#,
        r#"{"reason":"missing identity"}"#,
    ] {
        let request =
            format!(r#"{{"jsonrpc":"2.0","method":"notifications/cancelled","params":{params}}}"#);
        assert!(matches!(server.dispatch(&request), Dispatch::Ignore));
    }
    assert!(matches!(server.dispatch(&cancel("1")), Dispatch::Cancel(_)));
    assert!(matches!(server.dispatch(r#"{"jsonrpc":"2.0","id":2,"method":"notifications/cancelled","params":{"requestId":1}}"#), Dispatch::Reply { .. }));
}

#[test]
fn incremental_frames_and_output_pressure_have_fixed_bounds() -> Test {
    let mut frames = Frames::default();
    let mut input = io::Cursor::new(b"{}\r\n{}\n".to_vec());
    assert!(matches!(frames.read(&mut input)?, Input::Frame(frame) if frame == b"{}"));
    assert!(matches!(frames.read(&mut input)?, Input::Frame(frame) if frame == b"{}"));
    assert!(matches!(frames.read(&mut input)?, Input::Eof));
    let mut frames = Frames::default();
    let mut input = io::Cursor::new(vec![b'x'; MAX_FRAME_BYTES + 1]);
    let error = loop {
        match frames.read(&mut input) {
            Ok(Input::Pending) => (),
            Err(error) => break error,
            _ => return Err("oversized partial frame was admitted".into()),
        }
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(frames.pending.len(), MAX_FRAME_BYTES);
    let mut replies = Replies::default();
    for _ in 0..MAX_QUEUED_REPLIES {
        replies.push("{}".to_owned())?;
    }
    assert!(replies.push("{}".to_owned()).is_err());
    struct Blocked;
    impl Write for Blocked {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert_eq!(
        replies
            .pump(&mut Blocked, Duration::ZERO)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    Ok(())
}

#[test]
fn live_identity_survives_partial_output_flush_and_retirement() -> Test {
    struct Pressure {
        bytes: Vec<u8>,
        allowance: usize,
        flush_ready: bool,
    }
    impl Write for Pressure {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.allowance == 0 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let count = bytes.len().min(self.allowance);
            self.bytes.extend_from_slice(&bytes[..count]);
            self.allowance -= count;
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.flush_ready {
                Ok(())
            } else {
                Err(io::ErrorKind::WouldBlock.into())
            }
        }
    }
    let mut scheduler = Scheduler::new(Arc::new(|_, _| None));
    let mut server = ready();
    server.enable_request_tracking();
    let key = RequestKey::Integer(41);
    scheduler.accept(server.dispatch(r#"{"jsonrpc":"2.0","id":41,"method":"ping"}"#))?;
    assert!(
        scheduler.owns(&key),
        "an immediate reply must retain its identity"
    );
    scheduler.accept(server.dispatch(&call("41")))?;
    assert!(
        scheduler.pending.is_empty(),
        "duplicate work was admitted behind an unsent reply"
    );
    let mut output = Pressure {
        bytes: Vec::new(),
        allowance: 5,
        flush_ready: false,
    };
    scheduler.replies.pump(&mut output, OUTPUT_STALL_LIMIT)?;
    assert!(scheduler.owns(&key), "partial output released its identity");
    output.allowance = IO_SLICE_BYTES;
    scheduler.replies.pump(&mut output, OUTPUT_STALL_LIMIT)?;
    assert!(
        scheduler.owns(&key),
        "unflushed output released its identity"
    );
    assert!(scheduler.replies.frames.is_empty());
    output.flush_ready = true;
    scheduler.replies.pump(&mut output, OUTPUT_STALL_LIMIT)?;
    assert!(!scheduler.owns(&key));
    let text = String::from_utf8(output.bytes)?;
    assert!(text.contains(r#""id":41,"result":{}"#));
    assert!(text.contains(r#""id":null,"error":{"code":-32600"#));
    scheduler.accept(server.dispatch(&call("41")))?;
    assert!(
        scheduler.pending.is_empty(),
        "a retired ID remains reserved for the live session"
    );
    let mut retired_refusal = Vec::new();
    scheduler.replies.pump(&mut retired_refusal, OUTPUT_STALL_LIMIT)?;
    assert!(String::from_utf8(retired_refusal)?.contains(r#""id":null,"error":{"code":-32600"#));
    Ok(())
}

#[test]
fn live_identity_is_checked_before_initialization_even_after_flush() -> Test {
    let mut server = server();
    server.enable_request_tracking();
    let mut scheduler = Scheduler::new(Arc::new(|_, _| None));
    scheduler.accept(server.dispatch(r#"{"jsonrpc":"2.0","id":0,"method":"ping"}"#))?;
    let duplicate = server.dispatch_reserved(INIT, |key| scheduler.owns(key));
    assert!(matches!(duplicate, Dispatch::Reply { id: None, text } if text.contains("-32600")));
    scheduler
        .replies
        .pump(&mut Vec::new(), OUTPUT_STALL_LIMIT)?;
    let retired = server.dispatch_reserved(INIT, |key| scheduler.owns(key));
    assert!(matches!(retired, Dispatch::Reply { id: None, text } if text.contains("-32600")));
    let initialize = server.dispatch_reserved(
        &INIT.replace(r#""id":0"#, r#""id":1"#),
        |key| scheduler.owns(key),
    );
    assert!(
        matches!(initialize, Dispatch::Reply { text, .. } if text.contains("protocolVersion") && !text.contains("Already initialized"))
    );
    Ok(())
}

#[test]
fn native_work_waits_for_its_complete_reply_reservation() -> Test {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = Cx::current().ok_or("no runtime context")?;
        let calls = Arc::new(AtomicUsize::new(0));
        let worker_calls = Arc::clone(&calls);
        let mut scheduler = Scheduler::new(Arc::new(move |_, _| {
            worker_calls.fetch_add(1, Ordering::AcqRel);
            Some(("{}".to_owned(), ExitIdentity::SUCCESS))
        }));
        let mut server = ready();
        // Exceed the non-native allowance by one complete allocated byte.
        scheduler
            .replies
            .push("x".repeat(MAX_QUEUED_REPLY_BYTES - MAX_NATIVE_REPLY_BYTES))?;
        scheduler.accept(server.dispatch(&call("1")))?;
        scheduler.start_next(&cx)?;
        let refused_before_start = scheduler.active.is_none()
            && scheduler.pending.len() == 1
            && calls.load(Ordering::Acquire) == 0;
        let mut output = Vec::new();
        while !scheduler.replies.empty() {
            scheduler.replies.pump(&mut output, OUTPUT_STALL_LIMIT)?;
        }
        scheduler.start_next(&cx)?;
        let limit = Instant::now();
        while scheduler.active.is_some() && limit.elapsed() < Duration::from_secs(5) {
            scheduler.retire_ready().await?;
            sleep(cx.now(), POLL_INTERVAL).await;
        }
        let drained = scheduler.active.is_none();
        if !drained {
            scheduler.cancel_and_drain().await;
        }
        assert!(
            refused_before_start,
            "native work ran without reserved response capacity"
        );
        assert!(drained);
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert!(
            scheduler.owns(&RequestKey::Integer(1)),
            "completed native reply lost its ID"
        );
        Ok(())
    })
}

#[test]
fn control_replies_cannot_spend_the_active_native_result_reservation() -> Test {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = Cx::current().ok_or("no runtime context")?;
        let mut scheduler = Scheduler::new(Arc::new(|_, _| {
            Some(("retained native receipt".to_owned(), ExitIdentity::SUCCESS))
        }));
        let mut server = ready();
        scheduler.accept(server.dispatch(&call("1")))?;
        scheduler.start_next(&cx)?;
        let started = scheduler.active.is_some();
        let overflow_refused = scheduler
            .reply(
                None,
                "x".repeat(MAX_QUEUED_REPLY_BYTES - MAX_NATIVE_REPLY_BYTES),
            )
            .is_err();
        let small_reply = scheduler.reply(
            None,
            server::error("null", -32600, "bounded protocol refusal"),
        );
        let limit = Instant::now();
        while scheduler.active.is_some() && limit.elapsed() < Duration::from_secs(5) {
            scheduler.retire_ready().await?;
            sleep(cx.now(), POLL_INTERVAL).await;
        }
        let drained = scheduler.active.is_none();
        if !drained {
            scheduler.cancel_and_drain().await;
        }
        assert!(
            started && overflow_refused,
            "control traffic consumed native result capacity"
        );
        small_reply?;
        assert!(drained);
        let mut output = Vec::new();
        scheduler.replies.pump(&mut output, OUTPUT_STALL_LIMIT)?;
        assert!(String::from_utf8(output)?.contains("retained native receipt"));
        Ok(())
    })
}

#[test]
fn complete_catalog_with_maximally_escaped_id_fits_beside_a_native_result() -> Test {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = Cx::current().ok_or("no runtime context")?;
        let mut scheduler = Scheduler::new(Arc::new(|_, _| {
            Some(("native result".to_owned(), ExitIdentity::SUCCESS))
        }));
        let mut server = ready();
        scheduler.accept(server.dispatch(&call("1")))?;
        scheduler.start_next(&cx)?;
        let active = scheduler.active.is_some();
        let request = format!(
            r#"{{"jsonrpc":"2.0","id":"{}","method":"tools/list"}}"#,
            r#"\u0001"#.repeat(128),
        );
        let catalog = scheduler.accept(server.dispatch(&request));
        let native_capacity_remains = scheduler.replies.capacity_for(MAX_NATIVE_REPLY_BYTES, 1);
        scheduler.cancel_and_drain().await;
        assert!(active);
        catalog?;
        assert!(
            native_capacity_remains,
            "valid catalog spent the native result reservation"
        );
        Ok(())
    })
}

#[test]
fn session_request_ceiling_seals_intake_and_drains_accepted_native_work() -> Test {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?;
    runtime.block_on(async {
        let cx = Cx::current().ok_or("no runtime context")?;
        let mut server = server();
        server.enable_request_tracking();
        let _ = server.handle(INIT);
        let _ = server.handle(READY);
        // Leave exactly two identities for native work admitted before exhaustion.
        for id in 1..server::MAX_SESSION_REQUESTS - 2 {
            let reply = server
                .handle(&format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#))
                .ok_or("missing priming reply")?;
            assert!(reply.contains(r#""result":{}"#));
        }
        let first = server::MAX_SESSION_REQUESTS - 2;
        let second = first + 1;
        let exhausted = second + 1;
        let ignored = exhausted + 1;
        let input = format!(
            "{}\n{}\n{}\n{}\n",
            call(&first.to_string()),
            call(&second.to_string()),
            call(&exhausted.to_string()),
            call(&ignored.to_string()),
        );
        let count = Arc::new(AtomicUsize::new(0));
        let worker_count = Arc::clone(&count);
        let mut output = Vec::new();
        serve_owned(
            &mut server,
            &cx,
            &mut io::Cursor::new(input),
            &mut output,
            Arc::new(move |_, _| {
                Some((
                    worker_count.fetch_add(1, Ordering::Relaxed).to_string(),
                    ExitIdentity::SUCCESS,
                ))
            }),
            OUTPUT_STALL_LIMIT,
        )
        .await?;
        let output = String::from_utf8(output)?;
        let replies: Vec<_> = output.lines().collect();
        assert_eq!(count.load(Ordering::Relaxed), 2);
        assert_eq!(replies.len(), 3);
        assert!(replies.iter().any(|reply| {
            reply.contains(&format!(r#""id":{exhausted},"error":{{"code":-32000"#))
        }));
        assert!(!output.contains(&format!(r#""id":{ignored},"#)));
        let native: Vec<_> = replies
            .iter()
            .filter(|reply| reply.contains(r#""isError":false"#))
            .collect();
        assert_eq!(native.len(), 2);
        assert!(native[0].contains(&format!(r#""id":{first},"#)));
        assert!(native[0].contains(r#""text":"0"#));
        assert!(native[1].contains(&format!(r#""id":{second},"#)));
        assert!(native[1].contains(r#""text":"1"#));
        // serve_owned does not clear the history when it enables an already tracked server.
        assert!(matches!(
            server.dispatch(&call(&first.to_string())),
            Dispatch::Reply { id: None, text } if text.contains("-32600")
        ));
        Ok(())
    })
}
