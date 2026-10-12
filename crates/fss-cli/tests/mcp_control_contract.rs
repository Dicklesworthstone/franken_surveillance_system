#![forbid(unsafe_code)]
//! Real-process MCP alert control over synthetic retained two-camera evidence and an owned
//! loopback relay. Every effect uses the existing native owner and exact returned approvals.
//! No provider, recipient, external network service, device, or ambient document is contacted.

use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use fss_cli::agent_json::{object, string};
use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;
use fss_reference::deployment_session::plan::read_control_plan;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:mcp-control";
const IDENTITY: &str = "1,0,0,0,1,0,0,0,1";
const MIRROR: &str = "-1,0,96,0,1,0,0,0,1";

struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-mcp-control-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }
    fn root(&self) -> PathBuf {
        self.0.join("deployment")
    }
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scene(rightward: bool) -> TestResult<Vec<u8>> {
    let (width, height) = (96_u32, 48_u32);
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..14_usize {
        let mut pixels = vec![40_u8; (width * height) as usize];
        if index >= 3 {
            let left = if rightward {
                (index - 3) * 8
            } else {
                80 - (index - 3) * 8
            };
            for y in 8..24 {
                for x in left..left + 16 {
                    pixels[y * width as usize + x] = 220;
                }
            }
        }
        stream.extend(encode_jpeg(width, height, &pixels, &config)?);
    }
    Ok(stream)
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Wall-clock nanoseconds: received now, captured ten seconds earlier.
fn now_ns() -> TestResult<u128> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos())
}

fn import(
    directory: &OwnedDirectory,
    rightward: bool,
    sensor: &str,
    capture_start: u128,
) -> TestResult<String> {
    let input = directory
        .0
        .join(format!("{sensor}.mjpeg").replace(':', "-"));
    fs::write(&input, scene(rightward)?)?;
    let output = Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("import")
        .arg("--root")
        .arg(directory.root())
        .args(["--site", SITE, "--input"])
        .arg(&input)
        .args(["--sensor", sensor, "--stream", &format!("stream:{sensor}")])
        // Captured and received at wall-clock time: the evidence clock is realistic, so later
        // wall-clock effect records (a cancellation request) never jump it past a session lease.
        .args([
            "--receive-time-ns",
            &now_ns()?.to_string(),
            "--media-format",
            "mjpeg",
        ])
        .args(["--capture-start-ns", &capture_start.to_string()])
        .args(["--capture-uncertainty-ns", "1000000", "--assumed-fps", "10"])
        .output()?;
    success(&output);
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .find_map(|l| l.strip_prefix("import_identity=").map(str::to_owned))
        .ok_or("import identity missing")?)
}

fn event(root: &Path, command: &str, args: &[&str]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .arg(command)
        .arg("--root")
        .arg(root)
        .args(["--site", SITE])
        .args(args)
        .output()?)
}

fn report_field(output: &Output, key: &str) -> TestResult<String> {
    let text = String::from_utf8(output.stdout.clone())?;
    let pattern = format!("\"{key}\":");
    let start = text
        .find(&pattern)
        .ok_or_else(|| format!("missing {key} in {text}"))?
        + pattern.len();
    let rest = &text[start..];
    Ok(match rest.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next().unwrap_or_default().to_owned(),
        None => rest
            .split([',', '}', ']'])
            .next()
            .unwrap_or_default()
            .to_owned(),
    })
}

/// A deployment with one corroborated, published event; returns (directory, event id).
fn corroborated_event(name: &str) -> TestResult<(OwnedDirectory, String)> {
    let directory = OwnedDirectory::new(name)?;
    let capture_start = now_ns()? - 10_000_000_000;
    let east = format!(
        "east:{}",
        import(&directory, true, "sensor:east", capture_start)?
    );
    let west = format!(
        "west:{}",
        import(&directory, false, "sensor:west", capture_start)?
    );
    let root = directory.root();
    let corroborate = |extra: &[&str]| -> TestResult<Output> {
        let mut args = vec![
            "--camera",
            east.as_str(),
            "--camera",
            west.as_str(),
            "--ground",
            "east:1,0,0,0,1,0,0,0,1",
            "--zone",
            "door:56,0,40,48",
            "--interpretation",
            "gray",
            "--time-gate-ns",
            "250000000",
            "--distance-gate",
            "16",
        ];
        let west_ground = format!("west:{MIRROR}");
        let _ = IDENTITY;
        args.push("--ground");
        args.push(&west_ground);
        args.extend_from_slice(extra);
        event(&root, "corroborate", &args)
    };
    let prepared = corroborate(&[])?;
    success(&prepared);
    let proposal = report_field(&prepared, "proposal_digest")?;
    let published = corroborate(&["--approve", &proposal])?;
    success(&published);
    let id = report_field(&published, "event_id")?;
    Ok((directory, id))
}

/// Loopback relay: retains every complete request and answers with `reply`, or closes.
struct Relay {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

fn complete(request: &[u8]) -> bool {
    let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let length = String::from_utf8_lossy(&request[..end])
        .split("\r\n")
        .find_map(|line| line.strip_prefix("Content-Length: ").map(str::to_owned))
        .and_then(|value| value.parse::<usize>().ok());
    length.is_some_and(|length| request.len() >= end + 4 + length)
}

impl Relay {
    fn spawn(reply: Option<&'static [u8]>) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (seen, count, halt) = (requests.clone(), connections.clone(), stop.clone());
        let handle = std::thread::spawn(move || {
            while !halt.load(Ordering::SeqCst) {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                };
                count.fetch_add(1, Ordering::SeqCst);
                if stream.set_nonblocking(false).is_err()
                    || stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .is_err()
                {
                    continue;
                }
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                while !complete(&request) && request.len() < 65_536 {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&buffer[..n]),
                    }
                }
                if let Ok(mut all) = seen.lock() {
                    all.push(request);
                }
                if let Some(reply) = reply {
                    let _ = stream.write_all(reply);
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
    fn requests(&self) -> TestResult<usize> {
        Ok(self
            .requests
            .lock()
            .map_err(|_| "relay request log poisoned")?
            .len())
    }
    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn plaintext_approval() -> String {
    ContentDigest::sha256(b"owner approves the plaintext loopback relay").to_text()
}

fn run_fss(args: &[OsString]) -> TestResult<(Option<i32>, String)> {
    let output = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(args)
        .output()?;
    Ok((output.status.code(), String::from_utf8(output.stdout)?))
}

fn field<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a Value> {
    let mut current = value;
    for key in path {
        current = current
            .object()
            .and_then(|fields| fields.get(*key))
            .ok_or_else(|| format!("missing field {key}"))?;
    }
    Ok(current)
}

fn text<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a str> {
    field(value, path)?
        .text()
        .ok_or_else(|| format!("{path:?} is not a string").into())
}

fn texts(value: &Value, path: &[&str]) -> TestResult<Vec<String>> {
    field(value, path)?
        .array()
        .ok_or("not an array")?
        .iter()
        .map(|item| {
            item.text()
                .map(ToOwned::to_owned)
                .ok_or_else(|| "not a string".into())
        })
        .collect()
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn raw_payload(stdout: &str) -> TestResult<&str> {
    let start = stdout.find(",\"payload\":").ok_or("payload missing")? + ",\"payload\":".len();
    let end = stdout
        .find(",\"payloadDigest\":")
        .ok_or("payload digest missing")?;
    Ok(&stdout[start..end])
}

fn assert_conforms(schema: &str, instance: &str, scratch: &Path) -> TestResult {
    let root = repository_root();
    let file = scratch.join(format!(
        "instance-{}.json",
        ContentDigest::sha256(format!("{schema}\n{instance}").as_bytes())
            .to_text()
            .replace(':', "-")
    ));
    fs::write(&file, instance)?;
    let output = Command::new("python3")
        .arg("-B")
        .arg(root.join("scripts/json_instance_validate.py"))
        .arg(root.join("schemas").join(schema))
        .arg(&file)
        .output()?;
    fs::remove_file(&file)?;
    assert!(
        output.status.success(),
        "output does not conform to schemas/{schema}: {}{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    Ok(())
}

const PRINCIPAL: &str = "principal:mcp-control";
const STRANGER: &str = "principal:mcp-control-stranger";
const INIT: &str = r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mcp-control-contract","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

fn tool_request(name: &str, arguments: &str, notification: bool) -> String {
    let id = if notification { "" } else { r#""id":2,"# };
    format!(
        r#"{{"jsonrpc":"2.0",{id}"method":"tools/call","params":{{"name":{},"arguments":{arguments}}}}}"#,
        string(name)
    )
}

struct Reply {
    failed: bool,
    body: String,
    value: Value,
}

struct Agent {
    root: PathBuf,
    scratch: PathBuf,
    session: String,
    principal: String,
}

impl Agent {
    fn open(directory: &OwnedDirectory) -> TestResult<Self> {
        let scratch = directory.0.join("schema-instances");
        fs::create_dir(&scratch)?;
        let mut agent = Self {
            root: directory.root(),
            scratch,
            session: String::new(),
            principal: PRINCIPAL.to_owned(),
        };
        let opened = agent.call(
            "session_open",
            &object(&[
                ("mission", string("Protect the synthetic door.")),
                (
                    "objective",
                    string("Send exactly one approved loopback alert for corroborated entry."),
                ),
            ]),
            "AOP-001",
        )?;
        assert!(!opened.failed, "{}", opened.body);
        agent.session = text(&opened.value, &["sessionId"])?.to_owned();
        Ok(agent)
    }

    fn frames(&self, requests: &[String]) -> TestResult<Vec<Value>> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fss-mcp"))
            .arg("--root")
            .arg(&self.root)
            .args(["--principal", &self.principal])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut input = child.stdin.take().ok_or("MCP stdin missing")?;
        writeln!(input, "{INIT}")?;
        writeln!(input, "{READY}")?;
        for request in requests {
            assert!(request.len() < 64 * 1024);
            writeln!(input, "{request}")?;
        }
        drop(input);
        let output = child.wait_with_output()?;
        success(&output);
        assert!(
            output.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)?
            .lines()
            .map(|line| parse(line).map_err(Into::into))
            .collect()
    }

    fn call(&self, name: &str, arguments: &str, operation: &str) -> TestResult<Reply> {
        let replies = self.frames(&[tool_request(name, arguments, false)])?;
        assert_eq!(
            replies.len(),
            2,
            "initialization and exactly one tool response"
        );
        let result = field(&replies[1], &["result"])?;
        let failed = match field(result, &["isError"])? {
            Value::Bool(failed) => *failed,
            _ => return Err("MCP isError is not Boolean".into()),
        };
        let content = field(result, &["content"])?.array().ok_or("tool content")?;
        assert_eq!(content.len(), 1);
        assert_eq!(text(&content[0], &["type"])?, "text");
        let body = text(&content[0], &["text"])?.to_owned();
        assert_eq!(
            body.lines().count(),
            1,
            "one complete native semantic response"
        );
        let value = parse(body.trim_end())?;
        assert_eq!(text(&value, &["operationId"])?, operation);
        assert_eq!(text(&value, &["principalId"])?, self.principal);
        assert_eq!(
            text(&value, &["payloadDigest"])?,
            ContentDigest::sha256(raw_payload(&body)?.as_bytes()).to_text()
        );
        assert_conforms(
            "agent_response_envelope.v1.json",
            body.trim_end(),
            &self.scratch,
        )?;
        if raw_payload(&body)? != "null" {
            let schema = text(&value, &["payloadSchema"])?;
            assert_conforms(
                &format!("{}.json", schema.trim_start_matches("fss.")),
                raw_payload(&body)?,
                &self.scratch,
            )?;
        }
        Ok(Reply {
            failed,
            body,
            value,
        })
    }

    fn native(&self, command: &str, extra: &[&str]) -> TestResult<(Option<i32>, Value)> {
        let mut args: Vec<OsString> = vec![
            command.into(),
            "--json".into(),
            "--root".into(),
            self.root.as_os_str().to_owned(),
            format!("--principal={}", self.principal).into(),
        ];
        args.extend(extra.iter().map(OsString::from));
        let (code, body) = run_fss(&args)?;
        Ok((code, parse(body.trim_end())?))
    }

    fn plan_arguments(&self, event: &str, relay: SocketAddr, approve: Option<&str>) -> String {
        let mut fields = vec![
            ("intent", string("alert")),
            ("session", string(&self.session)),
            ("event_id", string(event)),
            ("relay", string(&relay.to_string())),
            ("path", string("/fss/alert")),
            ("plaintext_approval", string(&plaintext_approval())),
            ("deadline_ms", "5000".to_owned()),
        ];
        if let Some(approval) = approve {
            fields.push(("approve", string(approval)));
        }
        object(&fields)
    }

    fn plan(&self, event: &str, relay: SocketAddr, approve: Option<&str>) -> TestResult<Reply> {
        self.call(
            "plan",
            &self.plan_arguments(event, relay, approve),
            "AOP-007",
        )
    }

    fn prepare(&self, event: &str, relay: SocketAddr) -> TestResult<(String, String, String)> {
        let planned = self.plan(event, relay, None)?;
        assert!(!planned.failed, "{}", planned.body);
        let (plan, approval, _) = approvals(&planned.value)?;
        let operation = operation_of(&planned.value)?;
        let prepared = self.plan(event, relay, Some(&approval))?;
        assert!(!prepared.failed, "{}", prepared.body);
        let (_, _, dispatch) = approvals(&prepared.value)?;
        Ok((plan, operation, dispatch))
    }

    fn dispatch_arguments(plan: &str, approve: &str) -> String {
        object(&[
            ("intent", string("dispatch")),
            ("plan", string(plan)),
            ("approve", string(approve)),
        ])
    }

    fn commit(&self, plan: &str, approve: &str) -> TestResult<Reply> {
        self.call(
            "commit",
            &Self::dispatch_arguments(plan, approve),
            "AOP-008",
        )
    }

    fn cancel(&self, operation: &str, approve: Option<&str>) -> TestResult<Reply> {
        let mut fields = vec![("operation_id", string(operation))];
        if let Some(approval) = approve {
            fields.push(("approve", string(approval)));
        }
        self.call("cancel", &object(&fields), "AOP-010")
    }

    fn wait(&self, operation: &str) -> TestResult<Reply> {
        self.call(
            "wait",
            &object(&[
                ("operation_id", string(operation)),
                ("deadline_ms", "1".to_owned()),
            ]),
            "AOP-009",
        )
    }

    fn close(&self, plan: &str) -> TestResult<Reply> {
        self.call(
            "plan",
            &object(&[
                ("intent", string("close")),
                ("session", string(&self.session)),
                ("plan", string(plan)),
            ]),
            "AOP-007",
        )
    }

    fn reconcile(
        &self,
        operation: &str,
        outcome: &str,
        approve: Option<&str>,
    ) -> TestResult<Reply> {
        let mut fields = vec![
            ("intent", string("reconcile")),
            ("operation_id", string(operation)),
            ("outcome", string(outcome)),
            (
                "evidence",
                string(&ContentDigest::sha256(b"owned loopback delivery observation").to_text()),
            ),
            (
                "statement",
                string(
                    "The test owner observed the synthetic alert in the owned loopback fixture.",
                ),
            ),
        ];
        if let Some(approval) = approve {
            fields.push(("approve", string(approval)));
        }
        self.call("commit", &object(&fields), "AOP-008")
    }

    /// Remove the response pipe only after successful protocol initialization. The approved
    /// native commit still executes; its response then cannot be delivered to this client.
    fn lose_dispatch_response(&self, plan: &str, approval: &str) -> TestResult {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fss-mcp"))
            .arg("--root")
            .arg(&self.root)
            .args(["--principal", &self.principal])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut input = child.stdin.take().ok_or("MCP stdin missing")?;
        let mut output = BufReader::new(child.stdout.take().ok_or("MCP stdout missing")?);
        writeln!(input, "{INIT}")?;
        writeln!(input, "{READY}")?;
        input.flush()?;
        let mut initialized = String::new();
        assert!(output.read_line(&mut initialized)? > 0);
        assert_eq!(
            text(
                &parse(initialized.trim_end())?,
                &["result", "protocolVersion"]
            )?,
            "2025-06-18"
        );
        drop(output);
        writeln!(
            input,
            "{}",
            tool_request("commit", &Self::dispatch_arguments(plan, approval), false)
        )?;
        drop(input);
        let exited = child.wait_with_output()?;
        // The stdio owner treats BrokenPipe as a clean client disconnect. The operation's
        // durable receipt, checked below in a fresh process, is independent of that exit code.
        assert!(exited.status.success(), "{exited:?}");
        assert!(exited.stdout.is_empty());
        Ok(())
    }
}

/// Native proof-pointer positions are kept unchanged by MCP.
fn approvals(plan: &Value) -> TestResult<(String, String, String)> {
    let pointers = texts(plan, &["proofPointers"])?;
    Ok((
        text(plan, &["payload", "planId"])?.to_owned(),
        pointers.get(2).ok_or("plan approval missing")?.clone(),
        pointers.last().ok_or("dispatch proof missing")?.clone(),
    ))
}

fn operation_of(plan: &Value) -> TestResult<String> {
    let steps = field(plan, &["payload", "steps"])?.array().ok_or("steps")?;
    let prepare = steps
        .iter()
        .find(|step| text(step, &["stepId"]).is_ok_and(|id| id == "step:prepare"))
        .ok_or("prepare step")?;
    texts(prepare, &["writeWitnesses"])?
        .into_iter()
        .next()
        .ok_or_else(|| "operation witness missing".into())
}

#[test]
fn native_plan_approvals_and_receipts_are_preserved_through_mcp_and_cli() -> TestResult {
    let (directory, event) = corroborated_event("accepted")?;
    let agent = Agent::open(&directory)?;
    let relay = Relay::spawn(Some(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"))?;
    let journal = agent.root.join("effects/journal.fssj");
    let before = fs::read(&journal)?;
    let planned = agent.plan(&event, relay.address, None)?;
    assert!(!planned.failed, "{}", planned.body);
    assert_eq!(
        fs::read(&journal)?,
        before,
        "cognition alone never prepares"
    );
    assert_eq!(relay.connections(), 0);
    let (plan, approval, _) = approvals(&planned.value)?;
    let operation = operation_of(&planned.value)?;

    let (record, _, payload) = read_control_plan(&agent.root, &plan)?;
    assert_eq!(record.principal.as_str(), PRINCIPAL);
    assert_eq!(record.session_id.as_str(), agent.session);
    assert_eq!(record.operation_id, operation);
    assert_eq!(record.plan_approval.to_text(), approval);
    assert_eq!(payload, raw_payload(&planned.body)?.as_bytes());

    let (code, native) = agent.native(
        "plan",
        &[
            "--session",
            &agent.session,
            "--intent",
            "alert",
            "--event-id",
            &event,
            "--relay",
            &relay.address.to_string(),
            "--path",
            "/fss/alert",
            "--plaintext-approval",
            &plaintext_approval(),
            "--deadline-ms",
            "5000",
        ],
    )?;
    assert_eq!(code, Some(0));
    for name in [
        "payload",
        "payloadDigest",
        "decisionFingerprint",
        "requestId",
    ] {
        assert_eq!(
            field(&native, &[name])?,
            field(&planned.value, &[name])?,
            "{name}"
        );
    }
    assert_eq!(fs::read(&journal)?, before);

    let never_prepared = agent.commit(&plan, &approval)?;
    assert!(never_prepared.failed);
    assert_eq!(
        text(&never_prepared.value, &["errorId"])?,
        "ERR-OP-PRECONDITION-FAILED-001"
    );
    let prepared = agent.plan(&event, relay.address, Some(&approval))?;
    assert!(!prepared.failed, "{}", prepared.body);
    let (_, _, dispatch) = approvals(&prepared.value)?;
    assert_ne!(approval, dispatch);
    let prepared_journal = fs::read(&journal)?;
    assert_ne!(prepared_journal, before);
    assert_eq!(relay.connections(), 0);
    let wrong = agent.commit(&plan, &approval)?;
    assert!(wrong.failed);
    assert_eq!(
        text(&wrong.value, &["errorId"])?,
        "ERR-ALERT-APPROVAL-STALE-001"
    );
    assert_eq!(fs::read(&journal)?, prepared_journal);

    let stranger = Agent {
        root: agent.root.clone(),
        scratch: agent.scratch.clone(),
        session: agent.session.clone(),
        principal: STRANGER.to_owned(),
    };
    let foreign = stranger.commit(&plan, &dispatch)?;
    assert!(foreign.failed);
    assert_eq!(text(&foreign.value, &["outcome"])?, "refused");
    assert_eq!(fs::read(&journal)?, prepared_journal);
    assert_eq!(relay.connections(), 0);

    let committed = agent.commit(&plan, &dispatch)?;
    assert!(!committed.failed, "{}", committed.body);
    assert_eq!(
        text(&committed.value, &["payload", "state"])?,
        "adapter_accepted"
    );
    assert_eq!(relay.requests()?, 1);
    assert_eq!(relay.connections(), 1);
    let after = fs::read(&journal)?;
    let repeated = agent.commit(&plan, &dispatch)?;
    assert!(!repeated.failed);
    assert_eq!(
        text(&repeated.value, &["payload", "state"])?,
        "adapter_accepted"
    );
    let (code, native) = agent.native("commit", &["--plan", &plan, "--approve", &dispatch])?;
    assert_eq!(code, Some(0));
    assert_eq!(
        field(&native, &["payload"])?,
        field(&repeated.value, &["payload"])?
    );
    let waited = agent.wait(&operation)?;
    assert!(!waited.failed);
    assert_eq!(text(&waited.value, &["outcome"])?, "partial");
    assert_eq!(text(&waited.value, &["errorId"])?, "ERR-OP-TIMEOUT-001");
    assert_eq!(
        text(&waited.value, &["payload", "state"])?,
        "adapter_accepted"
    );
    assert_eq!(fs::read(&journal)?, after);
    assert_eq!(relay.connections(), 1);
    Ok(())
}

#[test]
fn lost_mcp_response_keeps_the_durable_operation_and_never_resends() -> TestResult {
    let (directory, event) = corroborated_event("lost-response")?;
    let agent = Agent::open(&directory)?;
    let relay = Relay::spawn(Some(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"))?;
    let (plan, operation, dispatch) = agent.prepare(&event, relay.address)?;
    agent.lose_dispatch_response(&plan, &dispatch)?;
    assert_eq!(relay.requests()?, 1);
    assert_eq!(relay.connections(), 1);
    let journal = agent.root.join("effects/journal.fssj");
    let durable = fs::read(&journal)?;
    let receipt = agent.wait(&operation)?;
    assert_eq!(
        text(&receipt.value, &["payload", "state"])?,
        "adapter_accepted"
    );
    let retried = agent.commit(&plan, &dispatch)?;
    assert!(!retried.failed);
    assert_eq!(
        text(&retried.value, &["payload", "state"])?,
        "adapter_accepted"
    );
    assert_eq!(fs::read(&journal)?, durable);
    assert_eq!(relay.connections(), 1);
    Ok(())
}

#[test]
fn lost_relay_ack_requires_exact_attestation_before_episode_closure() -> TestResult {
    let (directory, event) = corroborated_event("lost-ack")?;
    let agent = Agent::open(&directory)?;
    let relay = Relay::spawn(None)?;
    let (plan, operation, dispatch) = agent.prepare(&event, relay.address)?;
    let committed = agent.commit(&plan, &dispatch)?;
    assert!(committed.failed);
    assert_eq!(text(&committed.value, &["outcome"])?, "indeterminate");
    assert_eq!(
        text(&committed.value, &["errorId"])?,
        "ERR-EFFECT-INDETERMINATE-001"
    );
    assert!(!texts(&committed.value, &["executionBoundary", "possiblyOccurred"])?.is_empty());
    let journal = agent.root.join("effects/journal.fssj");
    let uncertain = fs::read(&journal)?;
    let repeated = agent.commit(&plan, &dispatch)?;
    assert!(repeated.failed);
    assert_eq!(
        text(&repeated.value, &["payload", "state"])?,
        "indeterminate"
    );
    assert_eq!(fs::read(&journal)?, uncertain);
    assert_eq!(relay.connections(), 1);
    let not_closed = agent.close(&plan)?;
    assert!(not_closed.failed);
    assert_eq!(
        text(&not_closed.value, &["recoveryClass"])?,
        "reconciliation_required"
    );

    let preview = agent.reconcile(&operation, "delivered", None)?;
    assert!(!preview.failed);
    assert_eq!(fs::read(&journal)?, uncertain);
    let approval = texts(&preview.value, &["proofPointers"])?
        .into_iter()
        .next()
        .ok_or("reconciliation approval missing")?;
    let bogus = ContentDigest::sha256(b"unapproved attestation").to_text();
    let refused = agent.reconcile(&operation, "delivered", Some(&bogus))?;
    assert!(refused.failed);
    assert_eq!(fs::read(&journal)?, uncertain);
    let reconciled = agent.reconcile(&operation, "delivered", Some(&approval))?;
    assert!(!reconciled.failed, "{}", reconciled.body);
    assert_eq!(text(&reconciled.value, &["payload", "state"])?, "verified");
    assert!(
        texts(&reconciled.value, &["degradation"])?
            .iter()
            .any(|line| line.contains("operator_asserted"))
    );
    let terminal = fs::read(&journal)?;
    let exact_retry = agent.reconcile(&operation, "delivered", Some(&approval))?;
    assert!(!exact_retry.failed);
    assert_eq!(fs::read(&journal)?, terminal);
    let contrary = agent.reconcile(&operation, "not_delivered", None)?;
    assert!(contrary.failed);
    let waited = agent.wait(&operation)?;
    assert!(!waited.failed);
    assert_eq!(text(&waited.value, &["payload", "state"])?, "verified");
    assert_eq!(relay.connections(), 1);

    let closed = agent.close(&plan)?;
    assert!(!closed.failed, "{}", closed.body);
    let pointers = texts(&closed.value, &["proofPointers"])?;
    let bytes = fss_publication::read_verified(
        agent.root.join("agent/publications"),
        ContentDigest::parse(pointers.get(1).ok_or("episode rendering proof missing")?)?,
        1 << 20,
    )?;
    let episode = String::from_utf8(bytes)?;
    assert_conforms("agent_execution_episode.v1.json", &episode, &agent.scratch)?;
    let parsed = parse(&episode)?;
    assert_eq!(text(&parsed, &["outcome", "state"])?, "succeeded");
    assert!(
        texts(&parsed, &["residualUncertainty"])?
            .iter()
            .any(|line| line.contains("operator_asserted"))
    );
    let repeated_close = agent.close(&plan)?;
    assert!(!repeated_close.failed);
    assert_eq!(
        field(&repeated_close.value, &["payload"])?,
        field(&closed.value, &["payload"])?
    );
    assert_eq!(fs::read(&journal)?, terminal);
    assert_eq!(relay.connections(), 1);
    Ok(())
}

#[test]
fn notifications_scope_overrides_and_wrong_approvals_cannot_commit_or_cancel() -> TestResult {
    let (directory, event) = corroborated_event("cancel")?;
    let agent = Agent::open(&directory)?;
    let relay = Relay::spawn(Some(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"))?;
    let (plan, operation, dispatch) = agent.prepare(&event, relay.address)?;
    let preview = agent.cancel(&operation, None)?;
    assert!(!preview.failed);
    assert_eq!(text(&preview.value, &["payload", "state"])?, "prepared");
    let approval = texts(&preview.value, &["proofPointers"])?
        .into_iter()
        .next()
        .ok_or("cancellation approval missing")?;
    let cancel = object(&[
        ("operation_id", string(&operation)),
        ("approve", string(&approval)),
    ]);
    let journal = agent.root.join("effects/journal.fssj");
    let prepared = fs::read(&journal)?;
    let rows = agent.frames(&[
        tool_request("commit", &Agent::dispatch_arguments(&plan, &dispatch), true),
        tool_request("cancel", &cancel, true),
        tool_request(
            "plan",
            &agent.plan_arguments(&event, relay.address, None),
            true,
        ),
    ])?;
    assert_eq!(
        rows.len(),
        1,
        "notifications return only the initialization response"
    );
    assert_eq!(fs::read(&journal)?, prepared);
    assert_eq!(relay.connections(), 0);

    for (key, value) in [
        ("root", "/outside/root"),
        ("principal", STRANGER),
        ("relay", "127.0.0.1:9"),
    ] {
        let forbidden = object(&[
            ("intent", string("dispatch")),
            ("plan", string(&plan)),
            ("approve", string(&dispatch)),
            (key, string(value)),
        ]);
        let responses = agent.frames(&[tool_request("commit", &forbidden, false)])?;
        assert_eq!(responses.len(), 2);
        assert_eq!(
            field(&responses[1], &["error", "code"])?.integer(),
            Some(-32602)
        );
        assert_eq!(fs::read(&journal)?, prepared);
    }
    let wrong = agent.cancel(&operation, Some(&dispatch))?;
    assert!(wrong.failed);
    assert_eq!(fs::read(&journal)?, prepared);
    let cancelled = agent.cancel(&operation, Some(&approval))?;
    assert!(!cancelled.failed);
    assert_eq!(text(&cancelled.value, &["payload", "state"])?, "cancelled");
    let stopped = fs::read(&journal)?;
    let retry = agent.cancel(&operation, Some(&approval))?;
    assert!(!retry.failed);
    assert_eq!(fs::read(&journal)?, stopped);
    let cannot_send = agent.commit(&plan, &dispatch)?;
    assert!(!cannot_send.failed);
    assert_eq!(
        text(&cannot_send.value, &["payload", "state"])?,
        "cancelled"
    );
    let closed = agent.close(&plan)?;
    assert!(!closed.failed);
    assert_eq!(fs::read(&journal)?, stopped);
    assert_eq!(relay.requests()?, 0);
    assert_eq!(relay.connections(), 0);
    Ok(())
}
