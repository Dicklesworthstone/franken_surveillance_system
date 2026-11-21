#![forbid(unsafe_code)]
//! Real MCP process cancellation over the parent's retained, certified-quiet footage fixture.
//! No reader thread is detached: the test owns both pipe endpoints and polls its child to exit.

use super::*;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use std::{
    io::{self, Read},
    process::{Child, ChildStdin, ChildStdout, ExitStatus},
    time::{Duration, Instant},
};

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"native-cancel-contract","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
const RESPONSE_LIMIT: usize = 6 * fss_core::json_input::MAX_MCP_TOOL_OUTPUT_BYTES + 1024;

struct Mcp {
    child: Child,
    input: Option<ChildStdin>,
    output: Option<ChildStdout>,
    pending: Vec<u8>,
}

impl Mcp {
    fn open(root: &Path) -> TestResult<Self> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fss-mcp"))
            .arg("--root").arg(root)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn()?;
        let input = child.stdin.take();
        let output = child.stdout.take();
        let mut process = Self { child, input, output, pending: Vec::new() };
        let output = process.output.as_ref().ok_or("MCP stdout unavailable")?;
        let flags = OFlag::from_bits_retain(fcntl(output, FcntlArg::F_GETFL)?);
        fcntl(output, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
        process.send(&format!("{INIT}\n{READY}"))?;
        assert_eq!(process.response()?.get("id")?.number()?, 1);
        Ok(process)
    }

    fn send(&mut self, lines: &str) -> TestResult {
        writeln!(self.input.as_mut().ok_or("MCP stdin unavailable")?, "{lines}")?;
        Ok(())
    }

    fn response(&mut self) -> TestResult<Json> {
        let started = Instant::now();
        loop {
            if let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
                let frame: Vec<_> = self.pending.drain(..=end).collect();
                return Json::parse(std::str::from_utf8(&frame)?);
            }
            if self.pending.len() > RESPONSE_LIMIT || started.elapsed() >= Duration::from_secs(5) {
                return Err("MCP reply exceeded its byte or liveness budget".into());
            }
            let mut bytes = [0; 8192];
            match self.output.as_mut().ok_or("MCP stdout unavailable")?.read(&mut bytes) {
                Ok(0) => return Err("MCP stdout closed before its response".into()),
                Ok(read) => self.pending.extend_from_slice(&bytes[..read]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn wait_exit(&mut self) -> TestResult<ExitStatus> {
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            if started.elapsed() >= Duration::from_secs(5) {
                return Err("MCP failed to drain and exit within the native cancellation budget".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn follow(id: u64, since: &str) -> String {
    let since = fss_cli::escape_json_str(since);
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"session_follow","arguments":{{"since":"{since}","view":"brief","wait_ms":10000}}}}}}"#)
}

fn ping(id: u64) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#)
}

fn cancel(id: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","method":"notifications/cancelled","params":{{"requestId":{id}}}}}"#)
}

fn semantic(reply: &Json) -> TestResult<Json> {
    let text = reply.path(&["result", "content"])?.items()?.first()
        .ok_or("MCP content missing")?.get("text")?.text()?;
    Json::parse(text)
}

fn start_wait(process: &mut Mcp, since: &str) -> TestResult {
    process.send(&format!("{}\n{}", follow(2, since), ping(3)))?;
    let live = process.response()?;
    assert_eq!(live.get("id")?.number()?, 3, "ping must complete while the native quiet wait is active");
    assert!(live.get("result").is_ok());
    // The real native wait must observe the certified quiet prefix before cancellation, so its
    // native cancellation envelope (rather than the scheduler's unstarted refusal) is exercised.
    std::thread::sleep(Duration::from_millis(150));
    Ok(())
}

#[test]
fn ping_and_exact_request_cancellation_remain_live_during_native_quiet_wait() -> TestResult {
    let _serial = serial();
    let directory = OwnedDirectory::new("mcp-native-cancel")?;
    let (_, since) = quiet_wait_fixture(&directory)?;
    let root = directory.root();
    let before = tree_digest(&root)?;
    let mut process = Mcp::open(&root)?;
    start_wait(&mut process, &since)?;
    process.send(&format!("{}\n{}", cancel(r#""2""#), ping(4)))?;
    assert_eq!(process.response()?.get("id")?.number()?, 4, "a string ID must not cancel numeric request 2");
    let forbidden_open = |id| format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"session_open","arguments":{{"mission":"must never execute","objective":"test queued cancellation without journal writes"}}}}}}"#);
    process.send(&forbidden_open(2))?;
    let duplicate = process.response()?;
    assert_eq!(duplicate.path(&["error", "code"])?, &Json::Number("-32600".to_owned()));
    process.send(&format!("{}\n{}\n{}", forbidden_open(5), cancel("5"), cancel("2")))?;
    let replies = [process.response()?, process.response()?];
    let queued = replies.iter().find(|reply| {
        reply.get("id").and_then(Json::number).is_ok_and(|id| id == 5)
    }).ok_or("queued request cancellation response missing")?;
    assert_eq!(queued.get("id")?.number()?, 5);
    assert_eq!(queued.path(&["error", "code"])?, &Json::Number("-32800".to_owned()));
    let cancelled = replies.iter().find(|reply| {
        reply.get("id").and_then(Json::number).is_ok_and(|id| id == 2)
    }).ok_or("native request cancellation response missing")?;
    assert_eq!(cancelled.get("id")?.number()?, 2);
    assert_eq!(cancelled.path(&["result", "isError"])?, &Json::Bool(true));
    let body = semantic(&cancelled)?;
    assert_eq!(body.get("outcome")?.text()?, "cancelled");
    assert_eq!(body.get("payload")?, &Json::Null);
    assert_eq!(body.get("resnapshotRequired")?, &Json::Bool(false));
    process.send(&format!("{}\n{}", cancel("2"), ping(6)))?;
    assert_eq!(process.response()?.get("id")?.number()?, 6, "late cancellation must produce no reply or native effect");
    drop(process.input.take());
    assert!(process.wait_exit()?.success());
    assert_eq!(tree_digest(&root)?, before, "cancelled reads and unstarted session-open commands write no deployment state");
    Ok(())
}

#[test]
fn malformed_tail_drains_the_started_native_wait_before_transport_exit() -> TestResult {
    let _serial = serial();
    let directory = OwnedDirectory::new("mcp-framing-drain")?;
    let (_, since) = quiet_wait_fixture(&directory)?;
    let root = directory.root();
    let before = tree_digest(&root)?;
    let mut process = Mcp::open(&root)?;
    start_wait(&mut process, &since)?;
    process.input.as_mut().ok_or("MCP stdin unavailable")?.write_all(b"{\"jsonrpc\"")?;
    drop(process.input.take());
    assert_eq!(process.wait_exit()?.code(), Some(1));
    assert_eq!(tree_digest(&root)?, before);
    Ok(())
}

#[test]
fn broken_output_drains_native_work_even_while_the_client_keeps_stdin_open() -> TestResult {
    let _serial = serial();
    let directory = OwnedDirectory::new("mcp-output-drain")?;
    let (_, since) = quiet_wait_fixture(&directory)?;
    let root = directory.root();
    let before = tree_digest(&root)?;
    let mut process = Mcp::open(&root)?;
    start_wait(&mut process, &since)?;
    drop(process.output.take());
    process.send(&ping(4))?;
    assert!(process.wait_exit()?.success(), "broken pipe preserves the launcher exit convention");
    assert!(process.input.is_some(), "transport must not depend on a blocking stdin thread reaching EOF");
    assert_eq!(tree_digest(&root)?, before);
    Ok(())
}

#[test]
fn eof_preserves_admitted_native_results_without_implying_cancellation() -> TestResult {
    let _serial = serial();
    let directory = OwnedDirectory::new("mcp-eof-drain")?;
    let root = empty_deployment(&directory, SITE)?;
    let before = tree_digest(&root)?;
    let mut process = Mcp::open(&root)?;
    let doctor = |id| format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"doctor","arguments":{{}}}}}}"#);
    process.send(&format!("{}\n{}", doctor(2), doctor(3)))?;
    drop(process.input.take());
    for id in [2, 3] {
        let reply = process.response()?;
        assert_eq!(reply.get("id")?.number()?, id);
        assert_eq!(semantic(&reply)?.get("schema")?.text()?, "fss.doctor.v1");
    }
    assert!(process.wait_exit()?.success());
    assert_eq!(tree_digest(&root)?, before);
    Ok(())
}
