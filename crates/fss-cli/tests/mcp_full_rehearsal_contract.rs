#![forbid(unsafe_code)]
//! Full 14/14 `fss/1` MCP rehearsal contract (`fss-pyhtf` / `fss-k0idy`).
//!
//! Exercises all 14 registered `AOP-001..AOP-014` operations in one coherent end-to-end mission
//! lifecycle over `fss-mcp` stdio against a real `ReferenceDeployment`, plus byte-for-byte CLI vs
//! MCP parity for the newly exposed `explain` options (`view`, `budget_tokens`, `custody`,
//! `fusion_policy`).

use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use fss_cli::agent_json::{object, string};
use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:mcp-full-rehearsal";
const MIRROR: &str = "-1,0,96,0,1,0,0,0,1";
const PRINCIPAL: &str = "principal:mcp-rehearsal";
const INIT: &str = r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mcp-full-rehearsal","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

fn emit_log(aop: &str, tool: &str, outcome: &str) {
    println!(
        "{{\"bead\":\"fss-k0idy\",\"aop\":\"{aop}\",\"tool\":\"{tool}\",\"outcome\":\"{outcome}\",\"verdict\":\"valid\"}}"
    );
}

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        let base = std::env::temp_dir().canonicalize()?;
        for attempt in 0..100_u32 {
            let path = base.join(format!(
                "fss-mcp-rehearsal-{name}-{}-{attempt}",
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

fn import_pair(name: &str) -> TestResult<(OwnedDirectory, String, String)> {
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
    Ok((directory, east, west))
}

fn publish_corroborated_event(
    directory: &OwnedDirectory,
    east: &str,
    west: &str,
    zone: &str,
) -> TestResult<String> {
    let root = directory.root();
    let corroborate = |extra: &[&str]| -> TestResult<Output> {
        let west_ground = format!("west:{MIRROR}");
        let mut args = vec![
            "--camera",
            east,
            "--camera",
            west,
            "--ground",
            "east:1,0,0,0,1,0,0,0,1",
            "--ground",
            west_ground.as_str(),
            "--zone",
            zone,
            "--interpretation",
            "gray",
            "--time-gate-ns",
            "250000000",
            "--distance-gate",
            "16",
        ];
        args.extend_from_slice(extra);
        Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .arg("corroborate")
            .arg("--root")
            .arg(&root)
            .args(["--site", SITE])
            .args(args)
            .output()?)
    };
    let prepared = corroborate(&[])?;
    success(&prepared);
    let proposal = report_field(&prepared, "proposal_digest")?;
    let published = corroborate(&["--approve", &proposal])?;
    success(&published);
    report_field(&published, "event_id")
}


struct Relay {
    address: SocketAddr,
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
    fn spawn() -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let halt = stop.clone();
        let handle = std::thread::spawn(move || {
            while !halt.load(Ordering::SeqCst) {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                };
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                while !complete(&request) && request.len() < 65_536 {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&buffer[..n]),
                    }
                }
                let _ = stream.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n");
            }
        });
        Ok(Self {
            address,
            stop,
            handle: Some(handle),
        })
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

fn orientation_anchor(envelope: &str) -> TestResult<String> {
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

struct Reply {
    failed: bool,
    body: String,
    value: Value,
}

struct McpHarness {
    root: PathBuf,
    principal: String,
}

impl McpHarness {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            principal: PRINCIPAL.to_owned(),
        }
    }

    fn call(&self, name: &str, arguments: &str, expected_aop: Option<&str>) -> TestResult<Reply> {
        let request = format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":{},"arguments":{arguments}}}}}"#,
            string(name)
        );
        let mut child = Command::new(env!("CARGO_BIN_EXE_fss-mcp"))
            .arg("--root")
            .arg(&self.root)
            .args(["--principal", &self.principal])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut input = child.stdin.take().ok_or("MCP stdin missing")?;
        writeln!(input, "{INIT}\n{READY}\n{request}")?;
        drop(input);
        let output = child.wait_with_output()?;
        success(&output);
        assert!(output.stderr.is_empty());
        let replies: Vec<Value> = String::from_utf8(output.stdout)?
            .lines()
            .map(|line| parse(line).map_err(Into::into))
            .collect::<TestResult<Vec<Value>>>()?;
        assert_eq!(replies.len(), 2);
        let result = field(&replies[1], &["result"])?;
        let failed = match field(result, &["isError"])? {
            Value::Bool(b) => *b,
            _ => return Err("isError not bool".into()),
        };
        let content = field(result, &["content"])?.array().ok_or("content")?;
        let body = text(&content[0], &["text"])?.to_owned();
        let value = parse(body.trim_end())?;
        if let Some(aop) = expected_aop {
            assert_eq!(text(&value, &["operationId"])?, aop, "{body}");
        }
        Ok(Reply {
            failed,
            body,
            value,
        })
    }

    fn cli(&self, command: &str, extra: &[&str]) -> TestResult<String> {
        let mut args: Vec<OsString> = vec![
            command.into(),
            "--json".into(),
            "--root".into(),
            self.root.as_os_str().to_owned(),
            format!("--principal={}", self.principal).into(),
        ];
        args.extend(extra.iter().map(OsString::from));
        let output = Command::new(env!("CARGO_BIN_EXE_fss"))
            .args(args)
            .output()?;
        success(&output);
        Ok(String::from_utf8(output.stdout)?.trim_end().to_owned())
    }
}

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
fn full_14_operation_mcp_rehearsal_and_explain_parity() -> TestResult {
    let (directory, east, west) = import_pair("rehearsal")?;
    let event_id = publish_corroborated_event(&directory, &east, &west, "door:56,0,40,48")?;
    let mcp = McpHarness::new(directory.root());
    let relay = Relay::spawn()?;
    let plaintext_approval =
        ContentDigest::sha256(b"owner approves the plaintext loopback relay").to_text();

    // 1. AOP-001: session_open
    let opened = mcp.call(
        "session_open",
        &object(&[
            (
                "mission",
                string("Execute full 14-operation fss/1 MCP mission rehearsal."),
            ),
            (
                "objective",
                string("Verify every AOP-001..AOP-014 transition over fss-mcp stdio."),
            ),
            ("view", string("pulse")),
            ("budget_tokens", "20000".to_owned()),
        ]),
        Some("AOP-001"),
    )?;
    assert!(!opened.failed, "{}", opened.body);
    let session_id = text(&opened.value, &["sessionId"])?.to_owned();
    let opening_anchor = orientation_anchor(&opened.body)?;
    emit_log("AOP-001", "session_open", "ok");

    // 2. AOP-003: session_orient
    let oriented = mcp.call(
        "session_orient",
        r#"{"view":"brief","budget_tokens":1024}"#,
        Some("AOP-003"),
    )?;
    assert!(!oriented.failed, "{}", oriented.body);
    assert_eq!(
        oriented.body,
        mcp.cli("orient", &["--view=brief", "--budget-tokens=1024"])?
    );
    emit_log("AOP-003", "session_orient", "ok");

    // 3. AOP-005: query
    let queried = mcp.call(
        "query",
        &object(&[("event_id", string(&event_id)), ("max_entries", "4".to_owned())]),
        Some("AOP-005"),
    )?;
    assert!(!queried.failed, "{}", queried.body);
    assert_eq!(
        queried.body,
        mcp.cli(
            "query",
            &[&format!("--event-id={event_id}"), "--max-entries=4"]
        )?
    );
    emit_log("AOP-005", "query", "ok");

    // 4. AOP-011: explain (default + forensic + budget_tokens + custody parity)
    let explained_default = mcp.call(
        "explain",
        &object(&[("event_id", string(&event_id))]),
        Some("AOP-011"),
    )?;
    assert!(!explained_default.failed, "{}", explained_default.body);
    assert_eq!(
        explained_default.body,
        mcp.cli("explain", &[&format!("--event-id={event_id}")])?
    );

    let explained_forensic = mcp.call(
        "explain",
        &object(&[
            ("event_id", string(&event_id)),
            ("view", string("forensic")),
            ("budget_tokens", "8000".to_owned()),
            ("custody", string("yes")),
        ]),
        Some("AOP-011"),
    )?;
    assert!(!explained_forensic.failed, "{}", explained_forensic.body);
    assert_eq!(
        explained_forensic.body,
        mcp.cli(
            "explain",
            &[
                &format!("--event-id={event_id}"),
                "--view=forensic",
                "--budget-tokens=8000",
                "--custody=yes",
            ]
        )?
    );
    emit_log("AOP-011", "explain", "ok");

    // 5. AOP-006: investigate (open case + work claim + finding)
    let draft = r#"{"caseId":"case:rehearsal-door","question":"Did a corroborated person enter the east door?","decisionInformed":"Whether to dispatch an alert to the loopback relay","hypotheses":[{"hypothesisId":"h:entry","description":"Corroborated entry across east and west cameras","predictions":["east and west tracks overlap in door zone"]},{"hypothesisId":"h:artifact","description":"Synchronized lighting artifact","predictions":["no consistent ground-plane velocity"]}],"knowns":[],"unknowns":[{"statementId":"u:intent","text":"Whether the entrant is authorized"}],"discriminators":[{"discriminatorId":"d:corroboration","description":"Two-camera ground-plane overlap","separates":["h:entry","h:artifact"],"expectedOutcomes":["matched track","disjoint tracks"]}],"probes":["probe:corroborate"],"stopRules":["corroborated event published"],"decisionWindowNs":3600000000000}"#;
    let case_opened = mcp.call(
        "investigate",
        &format!(
            r#"{{"session":{},"transition":"open","draft":{draft}}}"#,
            string(&session_id)
        ),
        Some("AOP-006"),
    )?;
    assert!(!case_opened.failed, "{}", case_opened.body);
    emit_log("AOP-006", "investigate", "ok");

    // 6. AOP-013: feedback on session_1
    let support_digest = ContentDigest::sha256(b"corroborated rehearsal observation").to_text();
    let feedback_reply = mcp.call(
        "feedback",
        &format!(
            r#"{{"session":{},"target":{},"kind":"helpful","statement":"Loopback alert rehearsal completed cleanly.","supporting":[{}],"disposition":"record_only"}}"#,
            string(&session_id),
            string(&format!("event:{event_id}")),
            string(&support_digest),
        ),
        Some("AOP-013"),
    )?;
    assert!(!feedback_reply.failed, "{}", feedback_reply.body);
    assert_eq!(
        field(&feedback_reply.value, &["payload", "activePolicyMutation"])?,
        &Value::Bool(false)
    );
    emit_log("AOP-013", "feedback", "ok");

    // 7. AOP-007 + AOP-010: plan (prepare operation #1 on port 9) + cancel + close
    let plan_cancel_1 = mcp.call(
        "plan",
        &object(&[
            ("intent", string("alert")),
            ("session", string(&session_id)),
            ("event_id", string(&event_id)),
            ("relay", string("127.0.0.1:9")),
            ("path", string("/fss/cancel-rehearsal")),
            ("plaintext_approval", string(&plaintext_approval)),
            ("deadline_ms", "5000".to_owned()),
        ]),
        Some("AOP-007"),
    )?;
    assert!(!plan_cancel_1.failed, "{}", plan_cancel_1.body);
    let (cancel_plan_id, cancel_plan_approval, _) = approvals(&plan_cancel_1.value)?;
    let cancel_op_id = operation_of(&plan_cancel_1.value)?;
    let plan_cancel_prepared = mcp.call(
        "plan",
        &object(&[
            ("intent", string("alert")),
            ("session", string(&session_id)),
            ("event_id", string(&event_id)),
            ("relay", string("127.0.0.1:9")),
            ("path", string("/fss/cancel-rehearsal")),
            ("plaintext_approval", string(&plaintext_approval)),
            ("deadline_ms", "5000".to_owned()),
            ("approve", string(&cancel_plan_approval)),
        ]),
        Some("AOP-007"),
    )?;
    assert!(!plan_cancel_prepared.failed, "{}", plan_cancel_prepared.body);

    let cancel_preview = mcp.call(
        "cancel",
        &object(&[("operation_id", string(&cancel_op_id))]),
        Some("AOP-010"),
    )?;
    assert!(!cancel_preview.failed, "{}", cancel_preview.body);
    let cancel_approval = texts(&cancel_preview.value, &["proofPointers"])?
        .first()
        .ok_or("cancel approval missing")?
        .clone();
    let cancelled = mcp.call(
        "cancel",
        &object(&[
            ("operation_id", string(&cancel_op_id)),
            ("approve", string(&cancel_approval)),
        ]),
        Some("AOP-010"),
    )?;
    assert!(!cancelled.failed, "{}", cancelled.body);
    assert_eq!(text(&cancelled.value, &["payload", "state"])?, "cancelled");
    emit_log("AOP-010", "cancel", "ok");

    let closed_cancel_episode = mcp.call(
        "plan",
        &object(&[
            ("intent", string("close")),
            ("session", string(&session_id)),
            ("plan", string(&cancel_plan_id)),
        ]),
        Some("AOP-007"),
    )?;
    assert!(
        !closed_cancel_episode.failed,
        "{}",
        closed_cancel_episode.body
    );

    // Publish a second corroborated event at the new ledger head before handoff/resume
    let commit_event_id =
        publish_corroborated_event(&directory, &east, &west, "door_commit:56,0,40,48")?;

    // 8. AOP-012 + AOP-002: handoff session_1 and resume into session_2 at the advanced head
    let handed_off = mcp.call(
        "handoff",
        &object(&[
            ("session", string(&session_id)),
            (
                "note",
                string("Handoff after cancelling port-9 probe; rebase onto new effect-journal head."),
            ),
        ]),
        Some("AOP-012"),
    )?;
    assert!(!handed_off.failed, "{}", handed_off.body);
    let handoff_id = text(&handed_off.value, &["payload", "handoffId"])?.to_owned();
    emit_log("AOP-012", "handoff", "ok");

    let resumed = mcp.call(
        "session_resume",
        &object(&[("handoff", string(&handoff_id))]),
        Some("AOP-002"),
    )?;
    assert!(!resumed.failed, "{}", resumed.body);
    let resumed_session_id = text(&resumed.value, &["sessionId"])?.to_owned();
    assert_eq!(resumed_session_id, session_id);
    emit_log("AOP-002", "session_resume", "ok");

    // 9. AOP-007 + AOP-008 + AOP-009: plan + commit + wait + close on resumed_session_id
    let plan_1 = mcp.call(
        "plan",
        &object(&[
            ("intent", string("alert")),
            ("session", string(&resumed_session_id)),
            ("event_id", string(&commit_event_id)),
            ("relay", string(&relay.address.to_string())),
            ("path", string("/fss/alert")),
            ("plaintext_approval", string(&plaintext_approval)),
            ("deadline_ms", "5000".to_owned()),
        ]),
        Some("AOP-007"),
    )?;
    assert!(!plan_1.failed, "{}", plan_1.body);
    let (plan_id, plan_approval, _) = approvals(&plan_1.value)?;
    let op_id = operation_of(&plan_1.value)?;
    let plan_prepared = mcp.call(
        "plan",
        &object(&[
            ("intent", string("alert")),
            ("session", string(&resumed_session_id)),
            ("event_id", string(&commit_event_id)),
            ("relay", string(&relay.address.to_string())),
            ("path", string("/fss/alert")),
            ("plaintext_approval", string(&plaintext_approval)),
            ("deadline_ms", "5000".to_owned()),
            ("approve", string(&plan_approval)),
        ]),
        Some("AOP-007"),
    )?;
    assert!(!plan_prepared.failed, "{}", plan_prepared.body);
    let (_, _, dispatch_approval) = approvals(&plan_prepared.value)?;
    emit_log("AOP-007", "plan", "ok");

    let committed = mcp.call(
        "commit",
        &object(&[
            ("intent", string("dispatch")),
            ("plan", string(&plan_id)),
            ("approve", string(&dispatch_approval)),
        ]),
        Some("AOP-008"),
    )?;
    assert!(!committed.failed, "{}", committed.body);
    assert_eq!(
        text(&committed.value, &["payload", "state"])?,
        "adapter_accepted"
    );

    let delivery_evidence =
        ContentDigest::sha256(b"owned loopback delivery observation").to_text();
    let reconcile_preview = mcp.call(
        "commit",
        &object(&[
            ("intent", string("reconcile")),
            ("operation_id", string(&op_id)),
            ("outcome", string("delivered")),
            ("evidence", string(&delivery_evidence)),
            (
                "statement",
                string("The test owner observed the alert in the loopback fixture."),
            ),
        ]),
        Some("AOP-008"),
    )?;
    assert!(!reconcile_preview.failed, "{}", reconcile_preview.body);
    let reconcile_approval = texts(&reconcile_preview.value, &["proofPointers"])?
        .into_iter()
        .next()
        .ok_or("reconcile approval missing")?;
    let reconciled = mcp.call(
        "commit",
        &object(&[
            ("intent", string("reconcile")),
            ("operation_id", string(&op_id)),
            ("outcome", string("delivered")),
            ("evidence", string(&delivery_evidence)),
            (
                "statement",
                string("The test owner observed the alert in the loopback fixture."),
            ),
            ("approve", string(&reconcile_approval)),
        ]),
        Some("AOP-008"),
    )?;
    assert!(!reconciled.failed, "{}", reconciled.body);
    assert_eq!(text(&reconciled.value, &["payload", "state"])?, "verified");
    emit_log("AOP-008", "commit", "ok");

    let waited = mcp.call(
        "wait",
        &object(&[
            ("operation_id", string(&op_id)),
            ("deadline_ms", "50".to_owned()),
        ]),
        Some("AOP-009"),
    )?;
    assert!(!waited.failed, "{}", waited.body);
    assert_eq!(text(&waited.value, &["payload", "state"])?, "verified");
    emit_log("AOP-009", "wait", "ok");

    let closed_episode = mcp.call(
        "plan",
        &object(&[
            ("intent", string("close")),
            ("session", string(&resumed_session_id)),
            ("plan", string(&plan_id)),
        ]),
        Some("AOP-007"),
    )?;
    assert!(!closed_episode.failed, "{}", closed_episode.body);
    assert_eq!(
        text(&closed_episode.value, &["payloadSchema"])?,
        "fss.agent_control_plan.v1"
    );

    // 10. AOP-004: session_follow
    let followed = mcp.call(
        "session_follow",
        &object(&[
            ("since", string(&opening_anchor)),
            ("view", string("brief")),
            ("max_entries", "16".to_owned()),
        ]),
        Some("AOP-004"),
    )?;
    assert!(!followed.failed, "{}", followed.body);
    emit_log("AOP-004", "session_follow", "ok");

    // 11. AOP-014: doctor
    let doctored = mcp.call("doctor", "{}", None)?;
    assert_eq!(text(&doctored.value, &["schema"])?, "fss.doctor.v1");
    let checks = field(&doctored.value, &["checks"])?.array().ok_or("checks")?;
    for required_clean in [
        "deployment.layout",
        "ledger.journal",
        "effects.journal",
        "effects.obligations",
        "publication.roots",
    ] {
        let check = checks
            .iter()
            .find(|c| text(c, &["id"]).is_ok_and(|id| id == required_clean))
            .ok_or_else(|| format!("missing doctor check {required_clean}"))?;
        assert_eq!(
            text(check, &["status"])?,
            "clean",
            "doctor check {required_clean} not clean: {}",
            doctored.body
        );
    }
    emit_log("AOP-014", "doctor", "ok");

    Ok(())
}
