#![forbid(unsafe_code)]
//! Unix stdio is nonblocking; one request-owned Asupersync pool worker executes native commands.
//! Cancellation retires a request only after its closure returns or is proved not to have run.

use std::{
    collections::VecDeque,
    fs::File,
    future::{Future, poll_fn},
    io::{self, Read, Write},
    os::fd::{AsFd, OwnedFd},
    pin::pin,
    sync::Arc,
    task::Poll,
    time::{Duration, Instant},
};

use asupersync::{Cx, runtime::RuntimeBuilder, time::sleep};
use fss_cli::{ExitIdentity, FssCommand, RequestControl, execute_live_fss_with_control};
use fss_core::json_input::MAX_MCP_TOOL_OUTPUT_BYTES;
use fss_runtime::drained_blocking::{self, Drained, WorkOutcome};
use nix::fcntl::{FcntlArg, OFlag, fcntl};

use super::{
    json::MAX_FRAME_BYTES,
    server::{Dispatch, RequestId, RequestKey, Server},
};

const MAX_QUEUED_REQUESTS: usize = 16;
const MAX_QUEUED_REPLIES: usize = 64;
// One maximally escaped native response plus a bounded allowance for protocol/control replies.
const MAX_QUEUED_REPLY_BYTES: usize = 6 * MAX_MCP_TOOL_OUTPUT_BYTES + 128 * 1024;
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
    }

    fn accept(&mut self, request: Dispatch) -> io::Result<()> {
        match request {
            Dispatch::Ignore => Ok(()),
            Dispatch::Reply { id, text } => {
                if let Some(id) = id.filter(|id| self.owns(&id.key)) {
                    self.replies
                        .push(id.error(-32600, "Request id is already in flight"))
                } else {
                    self.replies.push(text)
                }
            }
            Dispatch::Tool { id, command } => {
                if self.owns(&id.key) {
                    self.replies
                        .push(id.error(-32600, "Request id is already in flight"))
                } else if self.pending.len() >= MAX_QUEUED_REQUESTS {
                    self.replies.push(id.error(
                        -32003,
                        "Native request queue is full; this request was not executed",
                    ))
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
                    self.replies.push(pending.id.error(
                        -32800,
                        "Request cancelled before native execution",
                    ))?;
                }
                // Unknown and already-retired request IDs cannot cancel durable application work.
                Ok(())
            }
        }
    }

    fn start_next(&mut self, cx: &Cx) -> io::Result<()> {
        if self.active.is_some() {
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
            Err(_) => self.replies.push(pending.id.error(
                -32003,
                "Runtime refused native execution; this request was not executed",
            )),
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
        self.replies.push(response)
    }

    async fn cancel_and_drain(&mut self) {
        self.pending.clear();
        if let Some(active) = &mut self.active {
            active.owner.abort();
            // Never advertise quiescence, exit, or release this owner while its native closure runs.
            let _ = active.owner.join().await;
        }
        self.active = None;
    }
}

#[derive(Default)]
struct Replies {
    frames: VecDeque<Vec<u8>>,
    offset: usize,
    bytes: usize,
    flush_pending: bool,
    last_progress: Option<Instant>,
}

impl Replies {
    fn push(&mut self, mut response: String) -> io::Result<()> {
        response.push('\n');
        if self.frames.len() >= MAX_QUEUED_REPLIES
            || response.len() > MAX_QUEUED_REPLY_BYTES.saturating_sub(self.bytes)
        {
            return Err(io::Error::other("MCP output backlog exceeded its fixed bound"));
        }
        if self.empty() {
            self.last_progress = Some(Instant::now());
        }
        self.bytes += response.len();
        self.frames.push_back(response.into_bytes());
        Ok(())
    }

    fn empty(&self) -> bool {
        self.frames.is_empty() && !self.flush_pending
    }

    fn pump(&mut self, output: &mut impl Write, stall_limit: Duration) -> io::Result<()> {
        let mut allowance = IO_SLICE_BYTES;
        while allowance > 0 {
            let Some(front) = self.frames.front() else {
                break;
            };
            let end = front.len().min(self.offset + allowance);
            match output.write(&front[self.offset..end]) {
                Ok(0) => {
                    return Err(io::Error::new(io::ErrorKind::WriteZero, "MCP output stopped"));
                }
                Ok(written) => {
                    self.offset += written;
                    allowance -= written;
                    self.flush_pending = true;
                    self.last_progress = Some(Instant::now());
                    if self.offset == front.len() {
                        self.bytes -= front.len();
                        self.frames.pop_front();
                        self.offset = 0;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => break,
                Err(error) => return Err(error),
            }
        }
        if self.flush_pending {
            match output.flush() {
                Ok(()) => self.flush_pending = false,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => (),
                Err(error) => return Err(error),
            }
        }
        if !self.empty()
            && self.last_progress.is_some_and(|at| at.elapsed() >= stall_limit)
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
                ) => Ok(Input::Pending),
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
                                Ok(text) => server.dispatch(text),
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

/// Duplicate the inherited endpoint without manufacturing an fd or using an unowned reader thread.
/// `fcntl` changes this open file description; restore the launcher's flags before closing the copy.
struct NonblockingFd {
    file: File,
    original: OFlag,
}

impl NonblockingFd {
    fn new(fd: OwnedFd) -> io::Result<Self> {
        let original = OFlag::from_bits_retain(fcntl(&fd, FcntlArg::F_GETFL)?);
        fcntl(&fd, FcntlArg::F_SETFL(original | OFlag::O_NONBLOCK))?;
        Ok(Self {
            file: File::from(fd),
            original,
        })
    }
}

impl Drop for NonblockingFd {
    fn drop(&mut self) {
        let _ = fcntl(&self.file, FcntlArg::F_SETFL(self.original));
    }
}

pub(super) fn serve_stdio(server: &mut Server) -> io::Result<()> {
    // Drop output before input even if the launcher supplied aliases of one open description.
    let mut input = NonblockingFd::new(io::stdin().as_fd().try_clone_to_owned()?)?;
    let mut output = NonblockingFd::new(io::stdout().as_fd().try_clone_to_owned()?)?;
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()
        .map_err(|_| io::Error::other("MCP runtime unavailable"))?;
    runtime.block_on(async {
        let cx = Cx::current().ok_or_else(|| io::Error::other("MCP runtime context unavailable"))?;
        serve_owned(
            server,
            &cx,
            &mut input.file,
            &mut output.file,
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
