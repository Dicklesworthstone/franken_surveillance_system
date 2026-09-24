#![forbid(unsafe_code)]
//! Synchronous, read-only MCP reference adapter. No network listener or second runtime.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, BufRead, Write};

use fss_cli::{ExitIdentity, FssCommand, escape_json_str, execute_fss_with_exit, parse_fss_args};

use super::json::{self, MAX_FRAME_BYTES, Value};

const PROTOCOL_VERSION: &str = "2025-06-18";
const MAX_TOOL_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_BUDGET_TOKENS: u64 = 4096;

const TOOLS: &str = r#"{"tools":[
{"name":"session_orient","description":"Read-only AOP-003: inspect an existing deployment through its anchor-pinned SituationCapsule. Returns the existing fss/1 AgentResponseEnvelope unchanged, including coverage gaps, uncertainty, obligations and affordances. No affordance is executed.","inputSchema":{"type":"object","properties":{"view":{"type":"string","enum":["pulse","brief","epistemic_map"]},"budget_tokens":{"type":"integer","minimum":1,"maximum":4096}},"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}},
{"name":"explain","description":"Read-only AOP-011: explain one published event, including provenance, contradictions and evidence that would change the conclusion. Returns the existing fss/1 AgentResponseEnvelope unchanged.","inputSchema":{"type":"object","properties":{"event_id":{"type":"string","minLength":1,"maxLength":128}},"required":["event_id"],"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}
]}"#;

#[derive(Clone, Copy, PartialEq)]
enum Phase { New, AwaitingInitialized, Ready }

pub(super) struct Server {
    root: OsString,
    principal: String,
    phase: Phase,
}

impl Server {
    pub(super) fn new(root: OsString, principal: String) -> Self {
        Self { root, principal, phase: Phase::New }
    }

    pub(super) fn handle(&mut self, text: &str) -> Option<String> {
        self.handle_with(text, execute_fss_with_exit)
    }

    fn handle_with(
        &mut self,
        text: &str,
        mut execute: impl FnMut(FssCommand) -> (String, ExitIdentity),
    ) -> Option<String> {
        let value = match json::parse(text) {
            Ok(value) => value,
            Err(()) => return Some(error("null", -32700, "Invalid or over-budget JSON")),
        };
        let Some(request) = value.object() else {
            return Some(error("null", -32600, "A single JSON-RPC object is required"));
        };
        if request.get("jsonrpc").and_then(Value::text) != Some("2.0") {
            return Some(error("null", -32600, "Invalid JSON-RPC version"));
        }
        let Some(method) = request.get("method").and_then(Value::text) else {
            return Some(error("null", -32600, "A method string is required"));
        };
        let id = match request.get("id") {
            None => {
                // Notifications never invoke a tool, including malformed tools/call notifications.
                if method == "notifications/initialized" && self.phase == Phase::AwaitingInitialized
                    && params(request).is_ok_and(|p| only(p, &["_meta"])) {
                    self.phase = Phase::Ready;
                }
                return None;
            }
            Some(Value::Text(id)) if id.len() <= 128 => quote(id),
            Some(Value::Number(id)) if integer_id(id) => id.clone(),
            _ => return Some(error("null", -32600, "Invalid request id")),
        };
        let p = match params(request) {
            Ok(p) => p,
            Err(()) => return Some(error(&id, -32602, "Parameters must be an object")),
        };
        let result = match method {
            "initialize" => self.initialize(p),
            "ping" if only(p, &["_meta"]) => Ok("{}".to_owned()),
            "ping" => Err((-32602, "Unexpected ping parameters")),
            _ if self.phase != Phase::Ready => Err((-32002, "Complete initialization first")),
            "tools/list" if only(p, &["_meta"]) => Ok(TOOLS.replace('\n', "")),
            "tools/list" => Err((-32602, "This complete tool list has no continuation cursor")),
            "tools/call" => self.call(p, &mut execute),
            _ => Err((-32601, "Method not found")),
        };
        Some(match result {
            Ok(result) => format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{result}}}"),
            Err((code, message)) => error(&id, code, message),
        })
    }

    fn initialize(&mut self, p: &BTreeMap<String, Value>) -> RpcResult {
        if self.phase != Phase::New { return Err((-32600, "Already initialized")); }
        if !only(p, &["protocolVersion", "capabilities", "clientInfo", "_meta"])
            || p.get("protocolVersion").and_then(Value::text).is_none_or(str::is_empty)
            || p.get("capabilities").and_then(Value::object).is_none() {
            return Err((-32602, "Expected protocolVersion, capabilities and clientInfo"));
        }
        let info = p.get("clientInfo").and_then(Value::object)
            .ok_or((-32602, "Expected clientInfo object"))?;
        if info.get("name").and_then(Value::text).is_none_or(str::is_empty)
            || info.get("version").and_then(Value::text).is_none_or(str::is_empty) {
            return Err((-32602, "Expected clientInfo name and version"));
        }
        self.phase = Phase::AwaitingInitialized;
        Ok(format!(
            "{{\"protocolVersion\":\"{PROTOCOL_VERSION}\",\"capabilities\":{{\"tools\":{{\"listChanged\":false}}}},\"serverInfo\":{{\"name\":\"fss-mcp\",\"version\":\"{}\"}},\"instructions\":\"Local read-only reference adapter, not production-qualified. The launching operator fixes the deployment root and principal audit label. Tool results retain existing FSS evidence and uncertainty semantics; they grant no effect authority. No mutation, subscriptions, remote authentication or in-flight cancellation is implemented.\"}}",
            env!("CARGO_PKG_VERSION")
        ))
    }

    fn call(
        &self,
        p: &BTreeMap<String, Value>,
        execute: &mut impl FnMut(FssCommand) -> (String, ExitIdentity),
    ) -> RpcResult {
        if !only(p, &["name", "arguments", "_meta"]) { return Err((-32602, "Unexpected tool call field")); }
        let name = p.get("name").and_then(Value::text).ok_or((-32602, "Expected tool name"))?;
        let empty = BTreeMap::new();
        let args = match p.get("arguments") {
            None => &empty,
            Some(Value::Object(args)) => args,
            _ => return Err((-32602, "Tool arguments must be an object")),
        };
        let mut argv = match name {
            "session_orient" => {
                if !only(args, &["view", "budget_tokens"]) { return Err((-32602, "Unexpected orientation argument")); }
                let mut argv = self.base_args("orient");
                if let Some(view) = args.get("view") {
                    let view = view.text().ok_or((-32602, "Expected view string"))?;
                    if !matches!(view, "pulse" | "brief" | "epistemic_map") { return Err((-32602, "Unsupported orientation view")); }
                    argv.push(format!("--view={view}").into());
                }
                if let Some(value) = args.get("budget_tokens") {
                    let n = positive_integer(value, MAX_BUDGET_TOKENS)?;
                    argv.push(format!("--budget-tokens={n}").into());
                }
                argv
            }
            "explain" => {
                if !only(args, &["event_id"]) { return Err((-32602, "Unexpected explanation argument")); }
                let event = args.get("event_id").and_then(Value::text)
                    .filter(|s| !s.is_empty() && s.len() <= 128)
                    .ok_or((-32602, "Expected event_id string of 1..128 bytes"))?;
                let mut argv = self.base_args("explain");
                // Inline values cannot be reinterpreted as flags or subcommands.
                argv.push(format!("--event-id={event}").into());
                argv
            }
            _ => return Err((-32602, "Unknown or unavailable tool")),
        };
        argv.push(format!("--principal={}", self.principal).into());
        let command = parse_fss_args(argv).map_err(|_| (-32602, "Arguments refused by the canonical CLI parser"))?;
        // A final typed clamp remains even if command parsing gains new operations.
        if !matches!(command, FssCommand::Orient(_) | FssCommand::Explain(_)) {
            return Err((-32603, "Read-only command boundary refused dispatch"));
        }
        let (output, exit) = execute(command);
        Ok(tool_result(&output, exit.code != 0))
    }

    fn base_args(&self, command: &str) -> Vec<OsString> {
        vec![command.into(), "--json".into(), "--root".into(), self.root.clone()]
    }
}

type RpcResult = Result<String, (i32, &'static str)>;

fn params(request: &BTreeMap<String, Value>) -> Result<&BTreeMap<String, Value>, ()> {
    // The static empty map avoids allocations on notification and ping paths.
    static EMPTY: BTreeMap<String, Value> = BTreeMap::new();
    match request.get("params") {
        None => Ok(&EMPTY),
        Some(Value::Object(p)) if p.get("_meta").is_none_or(|v| v.object().is_some()) => Ok(p),
        _ => Err(()),
    }
}

fn only(fields: &BTreeMap<String, Value>, names: &[&str]) -> bool {
    fields.keys().all(|key| names.contains(&key.as_str()))
}

fn positive_integer(value: &Value, maximum: u64) -> Result<u64, (i32, &'static str)> {
    let Value::Number(text) = value else { return Err((-32602, "Expected positive integer")); };
    if !text.bytes().all(|byte| byte.is_ascii_digit()) { return Err((-32602, "Expected positive integer")); }
    text.parse::<u64>().ok().filter(|n| *n > 0 && *n <= maximum)
        .ok_or((-32602, "Integer is outside the admitted budget"))
}

fn integer_id(text: &str) -> bool {
    // Never round IDs through f64. Integer spelling is preserved even beyond IEEE-754 precision.
    text.parse::<i64>().is_ok() && !text.contains(['.', 'e', 'E'])
}

fn quote(text: &str) -> String { format!("\"{}\"", escape_json_str(text)) }

fn error(id: &str, code: i32, message: &str) -> String {
    format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"error\":{{\"code\":{code},\"message\":{}}}}}", quote(message))
}

fn tool_result(output: &str, failed: bool) -> String {
    let (output, failed) = if output.len() > MAX_TOOL_OUTPUT_BYTES {
        ("FSS response exceeded the MCP byte ceiling. No response was truncated and no effect was started. Request a smaller view or page.", true)
    } else { (output, failed) };
    format!("{{\"content\":[{{\"type\":\"text\",\"text\":{}}}],\"isError\":{failed}}}", quote(output))
}

fn read_frame(reader: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if bytes.is_empty() { Ok(None) }
                else { Err(io::Error::new(io::ErrorKind::InvalidData, "unterminated MCP frame")) };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |at| at + 1);
        if take > MAX_FRAME_BYTES - bytes.len() {
            // Terminate rather than allocate or drain an unbounded attacker-controlled line.
            return Err(io::Error::new(io::ErrorKind::InvalidData, "MCP frame exceeds byte ceiling"));
        }
        bytes.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            bytes.pop();
            if bytes.last() == Some(&b'\r') { bytes.pop(); }
            return Ok(Some(bytes));
        }
    }
}

pub(super) fn serve(
    server: &mut Server,
    mut input: impl BufRead,
    mut output: impl Write,
) -> io::Result<()> {
    while let Some(frame) = read_frame(&mut input)? {
        let response = match std::str::from_utf8(&frame) {
            Ok(text) => server.handle(text),
            Err(_) => Some(error("null", -32700, "Invalid UTF-8")),
        };
        if let Some(response) = response {
            output.write_all(response.as_bytes())?;
            output.write_all(b"\n")?;
            output.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;
    const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

    fn server() -> Server { Server::new("/owner/deployment".into(), "principal:local-operator".to_owned()) }

    fn ready() -> Server {
        let mut server = server();
        assert!(server.handle(INIT).is_some_and(|r| r.contains(PROTOCOL_VERSION)));
        assert_eq!(server.handle(READY), None);
        server
    }

    #[test]
    fn lifecycle_and_discovery_match_the_registry() {
        let mut server = server();
        let list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
        assert!(server.handle(list).is_some_and(|r| r.contains("-32002")));
        assert!(server.handle(INIT).is_some_and(|r| r.contains("capabilities")));
        assert!(server.handle(list).is_some_and(|r| r.contains("-32002")));
        assert_eq!(server.handle(READY), None);
        assert!(server.handle(list).is_some_and(|r| r.contains("session_orient")));
        assert!(server.handle(INIT).is_some_and(|r| r.contains("Already initialized")));
        for name in ["session_orient", "explain"] {
            assert!(fss_cli::lookup_by_mcp_tool_name(name).is_some());
        }
        assert!(json::parse(TOOLS).is_ok());
    }

    #[test]
    fn notification_never_executes_and_mutation_tools_are_absent() {
        let mut server = ready();
        let mut calls = 0;
        for text in [
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"session_orient"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"commit"}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"session_open"}}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"session_orient","arguments":{"root":"/elsewhere"}}}"#,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"session_orient","arguments":{"principal":"principal:other"}}}"#,
        ] {
            let _ = server.handle_with(text, |_| { calls += 1; ("{}".to_owned(), ExitIdentity::SUCCESS) });
        }
        assert_eq!(calls, 0);
    }

    #[test]
    fn canonical_dispatch_and_envelope_are_not_reimplemented() {
        let mut server = ready();
        let envelope = r#"{"schema":"fss.agent_response.v1","coverage":"not_observable","effect":"indeterminate","affordances":["reconcile"]}"#;
        let response = server.handle_with(
            r#"{"jsonrpc":"2.0","id":"read-1","method":"tools/call","params":{"name":"session_orient","arguments":{"view":"pulse","budget_tokens":128}}}"#,
            |command| {
                assert!(matches!(&command, FssCommand::Orient(_)));
                if let FssCommand::Orient(args) = command {
                    assert_eq!(args.root, std::path::PathBuf::from("/owner/deployment"));
                }
                (envelope.to_owned(), ExitIdentity::SUCCESS)
            },
        );
        assert!(response.is_some_and(|r| r.contains(&quote(envelope)) && r.contains("\"isError\":false")));
    }

    #[test]
    fn ids_types_and_invalid_json_fail_closed() {
        let mut server = ready();
        for text in [
            r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":true,"method":"ping"}"#,
            r#"[]"#,
        ] { assert!(server.handle(text).is_some_and(|r| r.contains("-32600"))); }
        assert!(server.handle(r#"{"jsonrpc":"2.0","id":9007199254740993,"method":"ping"}"#)
            .is_some_and(|r| r.contains("\"id\":9007199254740993")));
        assert!(server.handle(r#"{"jsonrpc":"2.0","id":"a\"b","method":"ping"}"#)
            .is_some_and(|r| r.contains(r#""id":"a\"b""#)));
        assert!(server.handle(r#"{"id":1,"id":2}"#).is_some_and(|r| r.contains("-32700")));
    }

    #[test]
    fn invalid_budget_or_flag_injection_never_reaches_backend() {
        let mut server = ready();
        let mut calls = 0;
        for args in [r#"{"budget_tokens":0}"#, r#"{"budget_tokens":4097}"#,
            r#"{"budget_tokens":1e2}"#, r#"{"budget_tokens":"128"}"#, r#"{"view":"--root=/other"}"#] {
            let text = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"session_orient","arguments":{args}}}}}"#);
            assert!(server.handle_with(&text, |_| { calls += 1; ("{}".to_owned(), ExitIdentity::SUCCESS) })
                .is_some_and(|r| r.contains("-32602")));
        }
        assert_eq!(calls, 0);
    }

    #[test]
    fn failures_and_output_ceiling_are_explicit() {
        let mut server = ready();
        let response = server.handle_with(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"explain","arguments":{"event_id":"event:missing"}}}"#,
            |_| (r#"{"error_id":"ERR-AGENT-EVENT-NOT-FOUND-001"}"#.to_owned(), ExitIdentity::RUNTIME_FAILURE),
        );
        assert!(response.is_some_and(|r| r.contains("ERR-AGENT-EVENT-NOT-FOUND-001") && r.contains("\"isError\":true")));
        let bounded = tool_result(&"x".repeat(MAX_TOOL_OUTPUT_BYTES + 1), false);
        assert!(bounded.len() < 1024 && bounded.contains("\"isError\":true"));
    }

    #[test]
    fn framing_is_bounded_and_never_accepts_partial_requests() {
        assert!(read_frame(&mut io::Cursor::new(b"{}".to_vec())).is_err());
        assert!(read_frame(&mut io::Cursor::new(vec![b'x'; MAX_FRAME_BYTES + 1])).is_err());
        assert_eq!(read_frame(&mut io::Cursor::new(b"{}\r\n".to_vec())).ok(), Some(Some(b"{}".to_vec())));
        assert_eq!(read_frame(&mut io::Cursor::new(Vec::<u8>::new())).ok(), Some(None));
        let input = format!("{INIT}\n{READY}\n{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}}\n");
        let mut output = Vec::new();
        assert!(serve(&mut server(), io::Cursor::new(input), &mut output).is_ok());
        assert_eq!(output.iter().filter(|byte| **byte == b'\n').count(), 2);
    }
}
