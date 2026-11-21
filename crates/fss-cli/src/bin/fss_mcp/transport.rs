#![forbid(unsafe_code)]
//! Unix stdio is nonblocking; one request-owned Asupersync pool worker executes native commands.
//! Cancellation retires a request only after its closure returns or is proved not to have run.

use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    io::{self, Read, Write},
    pin::pin,
    sync::Arc,
    task::Poll,
    time::{Duration, Instant},
};

use asupersync::{Cx, runtime::RuntimeBuilder, time::sleep};
use fss_cli::{ExitIdentity, FssCommand, RequestControl, execute_live_fss_with_control};
use fss_core::json_input::MAX_MCP_TOOL_OUTPUT_BYTES;
use fss_runtime::drained_blocking::{self, Drained, WorkOutcome};

use super::{
    json::MAX_FRAME_BYTES,
    outbox::Outbox,
    server::{self, Dispatch, RequestId, RequestKey, Server},
    stdio::Stdio,
};

const MAX_QUEUED_REQUESTS: usize = 16;
const MAX_QUEUED_REPLIES: usize = 64;
// One maximally escaped native response plus room for the full advertised catalog,
// a maximally escaped request ID and other bounded protocol/control replies.
const MAX_QUEUED_REPLY_BYTES: usize = 6 * MAX_MCP_TOOL_OUTPUT_BYTES + 256 * 1024;
const MAX_NATIVE_REPLY_BYTES: usize = 6 * MAX_MCP_TOOL_OUTPUT_BYTES + 1024;
const FRAMES_PER_TURN: usize = 8;
const IO_SLICE_BYTES: usize = 64 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(2);
const OUTPUT_STALL_LIMIT: Duration = Duration::from_secs(30);

type NativeResult = Option<(String, ExitIdentity)>;
type NativeWork = Box<dyn FnOnce(Cx) -> NativeResult + Send>;
type Executor = Arc<dyn Fn(FssCommand, &Cx) -> NativeResult + Send + Sync>;

struct Pending {
    id: RequestId,
    command: FssCommand,
}

struct Active {
    id: RequestId,
    owner: Drained<NativeWork, NativeResult>,
}

struct Scheduler {
    pending: VecDeque<Pending>,
    active: Option<Active>,
    replies: Replies,
    execute: Executor,
}

impl Scheduler {
    fn new(execute: Executor) -> Self {
        Self {
            pending: VecDeque::new(),
            active: None,
            replies: Replies::default(),
            execute,
        }
    }

    fn owns(&self, key: &RequestKey) -> bool {
        self.active
            .as_ref()
            .is_some_and(|active| &active.id.key == key)
            || self.pending.iter().any(|pending| &pending.id.key == key)
            || self.replies.owns(key)
    }

    /// Protocol replies cannot consume the capacity held for an executing native
    /// result. This avoids completing an approved effect and only then discovering
    /// that its receipt cannot enter the bounded response queue.
    fn reply(&mut self, id: Option<RequestId>, text: String) -> io::Result<()> {
        let text = text.into_boxed_str().into_string();
        let reserved = usize::from(self.active.is_some());
        if !self.replies.capacity_for(
            text.capacity()
                .saturating_add(1)
                .saturating_add(reserved * MAX_NATIVE_REPLY_BYTES),
            1 + reserved,
        ) {
            return Err(io::Error::other(
                "MCP output backlog exceeded its fixed bound",
            ));
        }
        self.replies.push_owned(text, id.map(|id| id.key))
    }

    fn duplicate(&mut self) -> io::Result<()> {
        self.reply(
            None,
            server::error("null", -32600, "Request id is already in flight"),
        )
    }

    fn accept(&mut self, request: Dispatch) -> io::Result<()> {
        match request {
            Dispatch::Ignore => Ok(()),
            Dispatch::Reply { id, text } => {
                if id.as_ref().is_some_and(|id| self.owns(&id.key)) {
                    self.duplicate()
                } else {
                    self.reply(id, text)
                }
            }
            Dispatch::Tool { id, command } => {
                if self.owns(&id.key) {
                    self.duplicate()
                } else if self.pending.len() >= MAX_QUEUED_REQUESTS {
                    let text = id.error(
                        -32003,
                        "Native request queue is full; this request was not executed",
                    );
                    self.reply(Some(id), text)
                } else {
                    self.pending.push_back(Pending { id, command });
                    Ok(())
                }
            }
            Dispatch::Cancel(id) => {
                if let Some(active) = &self.active
                    && active.id.key == id.key
                {
                    active.owner.abort();
                } else if let Some(index) = self.pending.iter().position(|p| p.id.key == id.key)
                    && let Some(pending) = self.pending.remove(index)
                {
                    let text = pending
                        .id
                        .error(-32800, "Request cancelled before native execution");
                    self.reply(Some(pending.id), text)?;
                }
                // Unknown and already-retired request IDs cannot cancel durable application work.
                Ok(())
            }
        }
    }

    fn start_next(&mut self, cx: &Cx) -> io::Result<()> {
        if self.active.is_some() || !self.replies.capacity_for(MAX_NATIVE_REPLY_BYTES, 1) {
            return Ok(());
        }
        let Some(pending) = self.pending.pop_front() else {
            return Ok(());
        };
        let execute = Arc::clone(&self.execute);
        let work: NativeWork = Box::new(move |child| execute(pending.command, &child));
        match drained_blocking::start(cx, work) {
            Ok(owner) => {
                self.active = Some(Active {
                    id: pending.id,
                    owner,
                });
                Ok(())
            }
            Err(_) => {
                let text = pending.id.error(
                    -32003,
                    "Runtime refused native execution; this request was not executed",
                );
                self.reply(Some(pending.id), text)
            }
        }
    }

    async fn retire_ready(&mut self) -> io::Result<()> {
        let Some(active) = &mut self.active else {
            return Ok(());
        };
        // `join` is explicitly retryable: a pending observation never drops the owned worker.
        let receipt = poll_fn(|context| {
            let mut joining = pin!(active.owner.join());
            Poll::Ready(match joining.as_mut().poll(context) {
                Poll::Ready(receipt) => receipt,
                Poll::Pending => None,
            })
        })
        .await;
        let Some(receipt) = receipt else {
            return Ok(());
        };
        let Some(active) = self.active.take() else {
            return Err(io::Error::other("missing native request owner"));
        };
        let response = match receipt.work {
            // A cancellation-dominant runtime result cannot erase a completed native result.
            WorkOutcome::Finished(Some((output, exit))) => active.id.tool_result(&output, exit),
            WorkOutcome::Finished(None) | WorkOutcome::NotStarted(_) => active
                .id
                .error(-32800, "Request cancelled before native execution"),
            WorkOutcome::Panicked => active.id.error(
                -32603,
                "Native request panicked; inspect retained state before retrying because effects may have committed",
            ),
            WorkOutcome::Indeterminate => active.id.error(
                -32603,
                "Native request outcome is indeterminate; inspect retained state before retrying",
            ),
        };
        let response = response.into_boxed_str().into_string();
        if response.len() + 1 > MAX_NATIVE_REPLY_BYTES {
            return Err(io::Error::other(
                "MCP native reply exceeded its reserved envelope",
            ));
        }
        self.replies.push_owned(response, Some(active.id.key))
    }

    async fn cancel_and_drain(&mut self) {
        self.pending.clear();
        self.replies.clear();
        if let Some(active) = &mut self.active {
            active.owner.abort();
            // Never advertise quiescence, exit, or release this owner while its native closure runs.
            let _ = active.owner.join().await;
        }
        self.active = None;
    }
}

struct Replies {
    frames: Outbox<RequestKey>,
    flushing_keys: Vec<RequestKey>,
    flushing_frames: usize,
    flush_pending: bool,
    last_progress: Option<Instant>,
}

impl Default for Replies {
    fn default() -> Self {
        Self {
            frames: Outbox::new(MAX_QUEUED_REPLY_BYTES, MAX_QUEUED_REPLIES),
            flushing_keys: Vec::new(),
            flushing_frames: 0,
            flush_pending: false,
            last_progress: None,
        }
    }
}

impl Replies {
    fn owns(&self, key: &RequestKey) -> bool {
        self.frames.owns(key) || self.flushing_keys.contains(key)
    }

    fn capacity_for(&self, bytes: usize, frames: usize) -> bool {
        frames
            .checked_add(self.flushing_frames)
            .is_some_and(|frames| self.frames.capacity_for(bytes, frames))
    }

    #[cfg(test)]
    fn push(&mut self, response: String) -> io::Result<()> {
        self.push_owned(response, None)
    }

    fn push_owned(&mut self, response: String, key: Option<RequestKey>) -> io::Result<()> {
        // Compact before admission, and charge the complete allocation until retirement.
        // The outbox writes LF separately so appending it cannot double this allocation.
        let response = response.into_boxed_str().into_string();
        if !self.capacity_for(response.capacity().saturating_add(1), 1) {
            return Err(io::Error::other(
                "MCP output backlog exceeded its fixed bound",
            ));
        }
        if self.empty() {
            self.last_progress = Some(Instant::now());
        }
        self.frames.enqueue(response, key)
    }

    fn empty(&self) -> bool {
        self.frames.is_empty() && !self.flush_pending
    }

    fn clear(&mut self) {
        self.frames.clear();
        self.flushing_keys.clear();
        self.flushing_frames = 0;
        self.flush_pending = false;
        self.last_progress = None;
    }

    fn pump(&mut self, output: &mut impl Write, stall_limit: Duration) -> io::Result<()> {
        let progress = self.frames.progress(output, IO_SLICE_BYTES)?;
        self.flushing_frames = self
            .flushing_frames
            .checked_add(progress.completed)
            .ok_or_else(|| io::Error::other("MCP response retirement accounting overflow"))?;
        self.flushing_keys.extend(progress.retired);
        if progress.written > 0 {
            self.flush_pending = true;
            self.last_progress = Some(Instant::now());
        }
        if self.flush_pending {
            match output.flush() {
                Ok(()) => {
                    self.flush_pending = false;
                    self.flushing_keys.clear();
                    self.flushing_frames = 0;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    ()
                }
                Err(error) => return Err(error),
            }
        }
        if !self.empty()
            && self
                .last_progress
                .is_some_and(|at| at.elapsed() >= stall_limit)
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "MCP output remained blocked",
            ));
        }
        Ok(())
    }
}

#[derive(Default)]
struct Frames {
    pending: Vec<u8>,
}

enum Input {
    Frame(Vec<u8>),
    Pending,
    Eof,
}

impl Frames {
    fn read(&mut self, input: &mut impl Read) -> io::Result<Input> {
        if let Some(frame) = self.take_frame() {
            return Ok(Input::Frame(frame));
        }
        if self.pending.len() >= MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MCP input frame exceeded its fixed bound",
            ));
        }
        let mut chunk = [0_u8; 8192];
        let capacity = chunk.len().min(MAX_FRAME_BYTES - self.pending.len());
        match input.read(&mut chunk[..capacity]) {
            Ok(0) if self.pending.is_empty() => Ok(Input::Eof),
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MCP input ended inside a frame",
            )),
            Ok(read) => {
                self.pending.extend_from_slice(&chunk[..read]);
                Ok(self.take_frame().map_or(Input::Pending, Input::Frame))
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(Input::Pending)
            }
            Err(error) => Err(error),
        }
    }

    fn take_frame(&mut self) -> Option<Vec<u8>> {
        let end = self.pending.iter().position(|byte| *byte == b'\n')?;
        let mut frame: Vec<_> = self.pending.drain(..=end).collect();
        frame.pop();
        if frame.last() == Some(&b'\r') {
            frame.pop();
        }
        Some(frame)
    }
}

async fn serve_owned(
    server: &mut Server,
    cx: &Cx,
    input: &mut impl Read,
    output: &mut impl Write,
    execute: Executor,
    stall_limit: Duration,
) -> io::Result<()> {
    let mut scheduler = Scheduler::new(execute);
    let mut frames = Frames::default();
    let mut eof = false;
    let result = async {
        loop {
            scheduler.retire_ready().await?;
            scheduler.replies.pump(output, stall_limit)?;
            if !eof {
                for _ in 0..FRAMES_PER_TURN {
                    match frames.read(input)? {
                        Input::Frame(frame) => {
                            let request = match std::str::from_utf8(&frame) {
                                Ok(text) => server.dispatch_reserved(text, |key| scheduler.owns(key)),
                                Err(_) => Dispatch::Reply {
                                    id: None,
                                    text: "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32700,\"message\":\"Invalid UTF-8\"}}".to_owned(),
                                },
                            };
                            scheduler.accept(request)?;
                            scheduler.start_next(cx)?;
                        }
                        Input::Pending => break,
                        Input::Eof => {
                            eof = true;
                            break;
                        }
                    }
                }
            }
            // EOF drains every admitted request, preserving ordinary piped-client exchanges.
            scheduler.start_next(cx)?;
            scheduler.replies.pump(output, stall_limit)?;
            if eof
                && scheduler.active.is_none()
                && scheduler.pending.is_empty()
                && scheduler.replies.empty()
            {
                return Ok(());
            }
            if cx.is_cancel_requested() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "MCP transport cancelled",
                ));
            }
            sleep(cx.now(), POLL_INTERVAL).await;
        }
    }
    .await;
    if result.is_err() {
        scheduler.cancel_and_drain().await;
    }
    result
}

pub(super) fn serve_stdio(server: &mut Server) -> io::Result<()> {
    let (mut input, mut output) = Stdio::open()?.split();
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()
        .map_err(|_| io::Error::other("MCP runtime unavailable"))?;
    runtime.block_on(async {
        let cx =
            Cx::current().ok_or_else(|| io::Error::other("MCP runtime context unavailable"))?;
        serve_owned(
            server,
            &cx,
            &mut input,
            &mut output,
            Arc::new(|command, child| {
                execute_live_fss_with_control(
                    command,
                    &RequestControl::new(&|| child.is_cancel_requested()),
                )
            }),
            OUTPUT_STALL_LIMIT,
        )
        .await
    })
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
