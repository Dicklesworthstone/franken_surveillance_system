#![forbid(unsafe_code)]
//! Persistent interactive `fss-mcp` JSON-RPC 2.0 stdio client, pure-Rust loopback HTTP &
//! RFC 8446 TLS 1.3 HMAC webhook servers, latency percentile accounting, and manual JSON helpers.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use fss_cli::escape_json_str;
use fss_core::json_input::{Value, parse_mcp_reply};
use fss_reference::notify::ed25519::Ed25519SigningKey;
use fss_reference::notify::tls13::Tls13Stream;
use fss_reference::notify::webhook::verify_webhook_signature;
use fss_reference::notify::x509::{CertBuilderParams, build_ed25519_x509_der, encode_cert_pem};
use fss_vault::LabEntropy;

use super::TestResult;

pub const PROTOCOL_VERSION: &str = "2025-06-18";

pub const CORE_TOOL_NAMES: [&str; 14] = [
    "cancel",
    "commit",
    "doctor",
    "explain",
    "feedback",
    "handoff",
    "investigate",
    "plan",
    "query",
    "session_follow",
    "session_open",
    "session_orient",
    "session_resume",
    "wait",
];

#[derive(Clone, Debug)]
pub struct TranscriptEntry {
    pub scenario: String,
    pub client: String,
    pub rpc_id: Option<u64>,
    pub method: String,
    pub tool: Option<String>,
    pub latency_us: u64,
    pub is_error: bool,
    pub request_json: String,
    pub response_json: String,
}

#[derive(Clone, Debug, Default)]
pub struct LatencyStats {
    pub count: usize,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
}

impl LatencyStats {
    pub fn from_micros(samples_us: &[u64]) -> Self {
        if samples_us.is_empty() {
            return Self::default();
        }
        let mut sorted = samples_us.to_vec();
        sorted.sort_unstable();
        let pct = |num: usize, den: usize| -> f64 {
            let idx = ((sorted.len() - 1) * num) / den;
            sorted[idx] as f64 / 1_000.0
        };
        let max_us = *sorted.last().unwrap_or(&0);
        Self {
            count: sorted.len(),
            p50_ms: pct(50, 100),
            p95_ms: pct(95, 100),
            p99_ms: pct(99, 100),
            max_ms: max_us as f64 / 1_000.0,
        }
    }
}

pub fn quote(text: &str) -> String {
    format!("\"{}\"", escape_json_str(text))
}

pub fn json_stringify(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.clone(),
        Value::Text(t) => quote(t),
        Value::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(json_stringify)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(map) => format!(
            "{{{}}}",
            map.iter()
                .map(|(k, v)| format!("{}:{}", quote(k), json_stringify(v)))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

pub fn field<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a Value> {
    let mut cur = value;
    for key in path {
        cur = cur
            .object()
            .and_then(|o| o.get(*key))
            .ok_or_else(|| format!("missing JSON field `{key}` in path {path:?}"))?;
    }
    Ok(cur)
}

pub fn text<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a str> {
    field(value, path)?
        .text()
        .ok_or_else(|| format!("JSON field {path:?} is not a string").into())
}

pub fn bool_field(value: &Value, path: &[&str]) -> TestResult<bool> {
    field(value, path)?
        .boolean()
        .ok_or_else(|| format!("JSON field {path:?} is not a bool").into())
}

pub fn array<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a [Value]> {
    field(value, path)?
        .array()
        .ok_or_else(|| format!("JSON field {path:?} is not an array").into())
}

pub fn texts(value: &Value, path: &[&str]) -> TestResult<Vec<String>> {
    array(value, path)?
        .iter()
        .map(|item| {
            item.text()
                .map(ToOwned::to_owned)
                .ok_or_else(|| format!("non-string array item at {path:?}").into())
        })
        .collect()
}

pub fn orientation_anchor(envelope: &str) -> TestResult<String> {
    let mut rest = envelope;
    let mut offset = 0;
    while let Some(found) = rest.find("\"anchor:") {
        let start = offset + found + 1;
        let tail = &envelope[start..];
        let end = tail.find('"').ok_or("unterminated anchor token")?;
        let token = &tail[..end];
        if fss_reference::agent_follow::AnchorToken::parse(token).is_some() {
            return Ok(token.to_owned());
        }
        offset = start + end;
        rest = &envelope[offset..];
    }
    Err("orientation emitted no well-formed anchor token".into())
}

pub struct ToolReply {
    pub is_error: bool,
    pub latency_us: u64,
    pub raw_wire: String,
    pub wire: Value,
    pub body_text: String,
    pub envelope: Value,
}

impl ToolReply {
    pub fn content_blocks(&self) -> TestResult<&[Value]> {
        array(&self.wire, &["result", "content"])
    }
}

/// Transcript and per-tool latency/token summary returned when an [`McpClient`] shuts down.
pub type McpClientSummary = (
    Vec<TranscriptEntry>,
    BTreeMap<String, Vec<u64>>,
    BTreeMap<String, u64>,
);

/// Persistent interactive `fss-mcp` stdio client preserving exact per-RPC latency and transcripts.
pub struct McpClient {
    scenario: String,
    client_label: String,
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: AtomicU64,
    pub transcript: Vec<TranscriptEntry>,
    pub per_tool_us: BTreeMap<String, Vec<u64>>,
    pub per_tool_tokens: BTreeMap<String, u64>,
}

impl McpClient {
    pub fn spawn(
        scenario: &str,
        client_label: &str,
        root: &Path,
        principal: &str,
        allow_visual_hydration: bool,
        capabilities: &[&str],
    ) -> TestResult<Self> {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fss-mcp"));
        cmd.arg("--root").arg(root).args(["--principal", principal]);
        if allow_visual_hydration {
            cmd.arg("--allow-visual-hydration");
        }
        for cap in capabilities {
            cmd.args(["--grant-capability", cap]);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn()?;
        let stdin = child.stdin.take().ok_or("missing fss-mcp stdin")?;
        let stdout = BufReader::new(child.stdout.take().ok_or("missing fss-mcp stdout")?);
        let mut client = Self {
            scenario: scenario.to_owned(),
            client_label: client_label.to_owned(),
            child,
            stdin: Some(stdin),
            stdout,
            next_id: AtomicU64::new(1),
            transcript: Vec::new(),
            per_tool_us: BTreeMap::new(),
            per_tool_tokens: BTreeMap::new(),
        };
        client.initialize()?;
        Ok(client)
    }

    fn alloc_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn initialize(&mut self) -> TestResult {
        let id = self.alloc_id();
        let init_req = format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"initialize","params":{{"protocolVersion":"{PROTOCOL_VERSION}","capabilities":{{}},"clientInfo":{{"name":{},"version":"1.0"}}}}}}"#,
            quote(&self.client_label)
        );
        let (raw, reply, lat_us) = self.exchange_raw(Some(id), "initialize", None, &init_req)?;
        if text(&reply, &["result", "protocolVersion"])? != PROTOCOL_VERSION {
            return Err(format!("unexpected MCP protocolVersion: {raw}").into());
        }
        let ready = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        self.send_notification(ready)?;
        self.per_tool_us
            .entry("initialize".to_owned())
            .or_default()
            .push(lat_us);
        Ok(())
    }

    pub fn send_notification(&mut self, frame: &str) -> TestResult {
        let stdin = self.stdin.as_mut().ok_or("mcp stdin closed")?;
        writeln!(stdin, "{frame}")?;
        stdin.flush()?;
        Ok(())
    }

    pub fn tools_list(&mut self) -> TestResult<(Value, u64)> {
        let id = self.alloc_id();
        let req = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/list"}}"#);
        let (_raw, reply, lat_us) = self.exchange_raw(Some(id), "tools/list", None, &req)?;
        self.per_tool_us
            .entry("tools/list".to_owned())
            .or_default()
            .push(lat_us);
        Ok((reply, lat_us))
    }

    pub fn call_raw(
        &mut self,
        tool: &str,
        arguments_json: &str,
    ) -> TestResult<(Value, u64, String)> {
        let id = self.alloc_id();
        let req = format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":{},"arguments":{arguments_json}}}}}"#,
            quote(tool)
        );
        let (raw, reply, lat_us) = self.exchange_raw(Some(id), "tools/call", Some(tool), &req)?;
        Ok((reply, lat_us, raw))
    }

    pub fn call(&mut self, tool: &str, arguments_json: &str) -> TestResult<ToolReply> {
        let (wire, latency_us, raw_wire) = self.call_raw(tool, arguments_json)?;
        let result = field(&wire, &["result"]).map_err(|err| {
            format!("{tool} returned JSON-RPC error instead of result ({err}): {raw_wire}")
        })?;
        let is_error = result
            .object()
            .and_then(|o| o.get("isError"))
            .and_then(Value::boolean)
            .unwrap_or(false);
        let content = array(result, &["content"])?;
        let body_text = text(&content[0], &["text"])?.to_owned();
        let envelope = parse_mcp_reply(body_text.trim_end())?;
        let tok_est = (body_text.len() as u64).div_ceil(4);
        self.per_tool_us
            .entry(tool.to_owned())
            .or_default()
            .push(latency_us);
        *self.per_tool_tokens.entry(tool.to_owned()).or_insert(0) += tok_est;
        Ok(ToolReply {
            is_error,
            latency_us,
            raw_wire,
            wire,
            body_text,
            envelope,
        })
    }

    fn exchange_raw(
        &mut self,
        id: Option<u64>,
        method: &str,
        tool: Option<&str>,
        request_json: &str,
    ) -> TestResult<(String, Value, u64)> {
        let started = Instant::now();
        {
            let stdin = self.stdin.as_mut().ok_or("mcp stdin closed")?;
            writeln!(stdin, "{request_json}")?;
            stdin.flush()?;
        }
        let mut line = String::new();
        let read = self.stdout.read_line(&mut line)?;
        let latency_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        if read == 0 {
            return Err(format!("fss-mcp closed stdout prematurely on {method}/{tool:?}").into());
        }
        let trimmed = line.trim_end_matches(['\r', '\n']).to_owned();
        let parsed = parse_mcp_reply(&trimmed)?;
        let is_error = parsed.object().and_then(|o| o.get("error")).is_some()
            || parsed
                .object()
                .and_then(|o| o.get("result"))
                .and_then(Value::object)
                .and_then(|r| r.get("isError"))
                .and_then(Value::boolean)
                .unwrap_or(false);
        self.transcript.push(TranscriptEntry {
            scenario: self.scenario.clone(),
            client: self.client_label.clone(),
            rpc_id: id,
            method: method.to_owned(),
            tool: tool.map(ToOwned::to_owned),
            latency_us,
            is_error,
            request_json: request_json.to_owned(),
            response_json: trimmed.clone(),
        });
        Ok((trimmed, parsed, latency_us))
    }

    pub fn finish(mut self) -> TestResult<McpClientSummary> {
        drop(self.stdin.take());
        let status = self.child.wait()?;
        let mut stderr_buf = String::new();
        if let Some(mut err) = self.child.stderr.take() {
            let _ = err.read_to_string(&mut stderr_buf);
        }
        if !status.success() {
            return Err(format!(
                "fss-mcp client `{}` exited with {:?}: stderr={stderr_buf}",
                self.client_label,
                status.code()
            )
            .into());
        }
        if !stderr_buf.is_empty() {
            return Err(format!(
                "fss-mcp client `{}` wrote unexpected stderr: {stderr_buf}",
                self.client_label
            )
            .into());
        }
        Ok((
            std::mem::take(&mut self.transcript),
            std::mem::take(&mut self.per_tool_us),
            std::mem::take(&mut self.per_tool_tokens),
        ))
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Loopback HTTP relay used by `fss-mcp` `plan(alert)` -> `commit(dispatch)`.
/// When `reply` is `None`, closes immediately after reading the request to force `Indeterminate`.
pub struct LoopbackAlertRelay {
    pub address: SocketAddr,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

fn http_request_complete(buf: &[u8]) -> bool {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let len = String::from_utf8_lossy(&buf[..end])
        .split("\r\n")
        .find_map(|line| {
            let (k, v) = line.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    buf.len() >= end + 4 + len
}

impl LoopbackAlertRelay {
    pub fn spawn(reply: Option<&'static [u8]>) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (seen, count, halt) = (
            Arc::clone(&requests),
            Arc::clone(&connections),
            Arc::clone(&stop),
        );
        let handle = std::thread::spawn(move || {
            while !halt.load(Ordering::Acquire) {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                };
                count.fetch_add(1, Ordering::SeqCst);
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut req = Vec::new();
                let mut buf = [0_u8; 4096];
                while !http_request_complete(&req) && req.len() < 65_536 {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                if let Ok(mut guard) = seen.lock() {
                    guard.push(req);
                }
                if let Some(resp) = reply {
                    let _ = stream.write_all(resp);
                }
            }
        });
        Ok(Self {
            address,
            requests,
            connections,
            stop,
            handle: Some(handle),
        })
    }

    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    pub fn request_count(&self) -> usize {
        self.requests.lock().map(|g| g.len()).unwrap_or(0)
    }
}

impl Drop for LoopbackAlertRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Self-signed Ed25519 X.509 test PKI for pure-Rust RFC 8446 TLS 1.3 loopback webhooks.
pub struct TestPki {
    pub ca_pem: String,
    pub leaf_der: Vec<u8>,
    pub leaf_sk: Ed25519SigningKey,
}

pub fn build_test_pki(san_dns: &[&str], not_before_s: i64, not_after_s: i64, seed: u8) -> TestPki {
    let ca_sk = Ed25519SigningKey::from_seed([seed; 32]);
    let leaf_sk = Ed25519SigningKey::from_seed([seed.wrapping_add(1); 32]);
    let ca_der = build_ed25519_x509_der(
        &CertBuilderParams {
            serial: 1,
            issuer_cn: "FSS MCP E2E Root CA",
            subject_cn: "FSS MCP E2E Root CA",
            san_dns: &[],
            san_ips: &[],
            not_before_unix_s: not_before_s,
            not_after_unix_s: not_after_s,
            is_ca: true,
        },
        &ca_sk.verifying_key(),
        &ca_sk,
    );
    let leaf_der = build_ed25519_x509_der(
        &CertBuilderParams {
            serial: 2,
            issuer_cn: "FSS MCP E2E Root CA",
            subject_cn: san_dns.first().copied().unwrap_or("hooks.fss.test"),
            san_dns,
            san_ips: &[],
            not_before_unix_s: not_before_s,
            not_after_unix_s: not_after_s,
            is_ca: false,
        },
        &leaf_sk.verifying_key(),
        &ca_sk,
    );
    TestPki {
        ca_pem: encode_cert_pem(&ca_der),
        leaf_der,
        leaf_sk,
    }
}

pub struct VerifiedTlsDelivery {
    pub request_line: String,
    pub signature_header: String,
    pub idempotency_key: String,
    pub delivery_id: String,
    pub body_bytes: usize,
}

type ParsedHttpRequest = (String, Vec<(String, String)>, Vec<u8>);

fn read_http_over_tls(tls: &mut Tls13Stream<TcpStream>) -> Result<ParsedHttpRequest, String> {
    let mut raw = Vec::new();
    let mut buf = [0_u8; 4096];
    let header_end = loop {
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let n = tls
            .read_application_data(&mut buf)
            .map_err(|e| format!("TLS header read failed: {e}"))?;
        if n == 0 {
            return Err("unexpected EOF reading TLS HTTP headers".to_owned());
        }
        raw.extend_from_slice(&buf[..n]);
    };
    let head = std::str::from_utf8(&raw[..header_end - 4]).map_err(|e| e.to_string())?;
    let mut lines = head.split("\r\n");
    let req_line = lines.next().ok_or("missing HTTP request line")?.to_owned();
    let mut headers = Vec::new();
    let mut content_len = 0_usize;
    for line in lines {
        let (k, v) = line.split_once(':').ok_or("malformed HTTP header")?;
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim().to_owned();
        if key == "content-length" {
            content_len = val.parse::<usize>().map_err(|e| e.to_string())?;
        }
        headers.push((key, val));
    }
    let mut body = raw[header_end..].to_vec();
    while body.len() < content_len {
        let n = tls
            .read_application_data(&mut buf)
            .map_err(|e| format!("TLS body read failed: {e}"))?;
        if n == 0 {
            return Err("unexpected EOF reading TLS HTTP body".to_owned());
        }
        body.extend_from_slice(&buf[..n]);
    }
    body.truncate(content_len);
    Ok((req_line, headers, body))
}

fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Accepts one pure-Rust RFC 8446 TLS 1.3 connection and verifies `X-FSS-Signature-256`
/// plus `Idempotency-Key` / `X-FSS-Idempotency-Key` in constant time.
pub fn accept_and_verify_tls13_webhook(
    listener: &TcpListener,
    pki: &TestPki,
    hmac_secret: &[u8],
    expected_idempotency_key: &str,
) -> Result<VerifiedTlsDelivery, String> {
    let (sock, _) = listener.accept().map_err(|e| e.to_string())?;
    let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = sock.set_write_timeout(Some(Duration::from_secs(5)));
    let chain = vec![pki.leaf_der.clone()];
    let mut entropy = LabEntropy::from_seed([0x41; 32]);
    let mut tls = Tls13Stream::accept_server(sock, &chain, &pki.leaf_sk, &mut entropy)
        .map_err(|e| e.to_string())?;
    let (req_line, headers, body) = read_http_over_tls(&mut tls)?;
    if !req_line.starts_with("POST /alerts/ingest HTTP/1.1") {
        return Err(format!("unexpected TLS webhook request line: {req_line}"));
    }
    let ts: i64 = find_header(&headers, "x-fss-timestamp")
        .ok_or("missing X-FSS-Timestamp")?
        .parse()
        .map_err(|_| "invalid X-FSS-Timestamp")?;
    let delivery_id = find_header(&headers, "x-fss-delivery-id")
        .ok_or("missing X-FSS-Delivery-Id")?
        .to_owned();
    let sig = find_header(&headers, "x-fss-signature-256")
        .ok_or("missing X-FSS-Signature-256")?
        .to_owned();
    let idem = find_header(&headers, "x-fss-idempotency-key")
        .or_else(|| find_header(&headers, "idempotency-key"))
        .ok_or("missing Idempotency-Key / X-FSS-Idempotency-Key")?
        .to_owned();
    if idem != expected_idempotency_key {
        return Err(format!(
            "idempotency key mismatch: got `{idem}`, expected `{expected_idempotency_key}`"
        ));
    }
    if !verify_webhook_signature(hmac_secret, ts, &delivery_id, &body, &sig) {
        return Err("HMAC-SHA256 X-FSS-Signature-256 verification failed".to_owned());
    }
    let resp = "HTTP/1.1 202 Accepted\r\nContent-Length: 11\r\nX-Request-Id: tls13-wh-001\r\nConnection: close\r\n\r\n{\"ok\":true}";
    tls.write_application_data(resp.as_bytes())
        .map_err(|e| e.to_string())?;
    let _ = tls.close_notify();
    Ok(VerifiedTlsDelivery {
        request_line: req_line,
        signature_header: sig,
        idempotency_key: idem,
        delivery_id,
        body_bytes: body.len(),
    })
}
