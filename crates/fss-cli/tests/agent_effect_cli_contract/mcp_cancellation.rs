#![forbid(unsafe_code)]
//! A transport cancellation stops only a real effect-receipt wait, never the prepared operation.

use super::*;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use std::{io, process::ChildStdout};

struct OwnedMcp(Child);

impl Drop for OwnedMcp {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn response(output: &mut ChildStdout, pending: &mut Vec<u8>) -> TestResult<Value> {
    let started = Instant::now();
    loop {
        if let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<_> = pending.drain(..=end).collect();
            return mcp_response::parse_response(std::str::from_utf8(&line)?);
        }
        if pending.len() > 6 * fss_core::json_input::MAX_MCP_TOOL_OUTPUT_BYTES + 1024
            || started.elapsed() >= Duration::from_secs(5)
        {
            return Err("effect-wait MCP response exceeded its byte or liveness budget".into());
        }
        let mut bytes = [0_u8; 8192];
        match output.read(&mut bytes) {
            Ok(0) => return Err("MCP exited before returning its response".into()),
            Ok(read) => pending.extend_from_slice(&bytes[..read]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) => return Err(error.into()),
        }
    }
}

#[test]
fn cancelling_mcp_wait_retains_the_real_prepared_receipt_and_does_not_cancel_its_effect()
-> TestResult {
    let (directory, event_id) = corroborated_event("mcp-request-cancel")?;
    let agent = Agent::open(&directory)?;
    let relay = Relay::spawn(None)?;
    let (code, planned) = agent.plan(&event_id, relay.address, &[])?;
    assert_eq!(code, Some(0));
    let (_, approval, _) = approvals(&planned)?;
    let operation = operation_of(&planned)?;
    let (code, _) = agent.plan(&event_id, relay.address, &["--approve", &approval])?;
    assert_eq!(code, Some(0));
    let (_, initial) = agent.run("wait", &["--operation", &operation, "--deadline-ms", "1"])?;
    assert_eq!(text(&initial, &["payload", "state"])?, "prepared");
    let journals = [
        agent.root.join("ledger/journal.fssj"),
        agent.root.join("effects/journal.fssj"),
        agent.root.join("agent/sessions/journal.fssj"),
    ];
    let before = journals
        .iter()
        .map(fs::read)
        .collect::<io::Result<Vec<_>>>()?;

    let mut child = OwnedMcp(
        Command::new(env!("CARGO_BIN_EXE_fss-mcp"))
            .arg("--root")
            .arg(&agent.root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    let mut input = child.0.stdin.take().ok_or("MCP stdin unavailable")?;
    let mut output = child.0.stdout.take().ok_or("MCP stdout unavailable")?;
    let flags = OFlag::from_bits_retain(fcntl(&output, FcntlArg::F_GETFL)?);
    fcntl(&output, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
    let mut pending = Vec::new();
    writeln!(
        input,
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"effect-wait-cancel\",\"version\":\"1\"}}}}}}"
    )?;
    writeln!(
        input,
        "{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}}"
    )?;
    assert_eq!(
        field(&response(&mut output, &mut pending)?, &["id"])?,
        &Value::Number("1".to_owned())
    );

    let operation = fss_cli::escape_json_str(&operation);
    writeln!(
        input,
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"wait","arguments":{{"operation_id":"{operation}","deadline_ms":10000}}}}}}"#
    )?;
    writeln!(
        input,
        "{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}}"
    )?;
    assert_eq!(
        field(&response(&mut output, &mut pending)?, &["id"])?,
        &Value::Number("3".to_owned())
    );
    std::thread::sleep(Duration::from_millis(150));
    writeln!(
        input,
        "{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{{\"requestId\":2}}}}"
    )?;
    writeln!(
        input,
        "{{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"ping\"}}"
    )?;
    let replies = [
        response(&mut output, &mut pending)?,
        response(&mut output, &mut pending)?,
    ];
    let ping = replies
        .iter()
        .find(|reply| field(reply, &["id"]).is_ok_and(|id| id == &Value::Number("4".to_owned())))
        .ok_or("ping response missing after cancellation")?;
    assert!(field(ping, &["result"]).is_ok());
    let cancelled = replies
        .iter()
        .find(|reply| field(reply, &["id"]).is_ok_and(|id| id == &Value::Number("2".to_owned())))
        .ok_or("cancelled wait response missing")?;
    assert_eq!(field(cancelled, &["id"])?, &Value::Number("2".to_owned()));
    assert_eq!(
        field(cancelled, &["result", "isError"])?,
        &Value::Bool(true)
    );
    let content = field(cancelled, &["result", "content"])?
        .array()
        .ok_or("MCP content")?;
    let body = parse(text(content.first().ok_or("MCP text")?, &["text"])?)?;
    assert_eq!(text(&body, &["outcome"])?, "cancelled");
    assert_eq!(text(&body, &["payload", "state"])?, "prepared");
    assert_eq!(field(&body, &["payload"])?, field(&initial, &["payload"])?);
    assert_eq!(
        texts(&body, &["proofPointers"])?,
        texts(&initial, &["proofPointers"])?
    );

    drop(input);
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if started.elapsed() >= Duration::from_secs(5) {
            return Err("MCP did not drain and exit after its cancelled wait".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert!(status.success());
    assert_eq!(
        journals
            .iter()
            .map(fs::read)
            .collect::<io::Result<Vec<_>>>()?,
        before
    );
    assert_eq!(
        relay.connections(),
        0,
        "request cancellation must never dispatch or cancel the prepared alert"
    );
    Ok(())
}
