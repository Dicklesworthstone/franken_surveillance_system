#![forbid(unsafe_code)]
//! FSS-240: the first end-to-end agent rehearsal through the real binaries, over one deployment
//! with a corroborated event and a loopback relay:
//!
//! orient -> session open -> investigate (open, activate, claim the probe, cite, assess) ->
//! plan (rests on the case) -> approve (prepare) -> handoff -> resume -> commit (exactly one
//! dispatch) -> wait -> reconcile (owner attestation) -> close (immutable execution episode) ->
//! learn (advisory feedback citing the episode) -> conclude the case -> final handoff.
//!
//! Every answer is validated against `agent_response_envelope.v1` and its payload schema, and the
//! rehearsal retains a JSON-lines transcript (step, argv, exit, operation, outcome, error,
//! payload schema, decision fingerprint, anchor, proof pointers, degradation, next affordances,
//! consumed budget); set `FSS_REHEARSAL_TRANSCRIPT=<path>` to keep a copy. The assertions pin
//! the semantic transitions: the case, claim, plan, obligation, and episode states a cold driver
//! sees at each step, and the mission state a handoff carries.
//!
//! A second rehearsal plays scenario NS-9: the alert's acknowledgement is lost, the driver hands
//! off, and a cold driver resumes; the indeterminate effect, its open obligation, and the
//! owner-only reconcile move travel through the handoff and the resumed situation, a retried
//! commit never resends, and only the owner's attestation discharges the obligation.

use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use fss_cli::agent_json::{object, string, strings};
use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:agent-rehearsal";
const IDENTITY: &str = "1,0,0,0,1,0,0,0,1";
const MIRROR: &str = "-1,0,96,0,1,0,0,0,1";

struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-agent-rehearsal-{name}-{}-{attempt}",
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
        .args(["--receive-time-ns", &now_ns()?.to_string(), "--media-format", "mjpeg"])
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

const CASE: &str = "case:door-entry";
const STOP_RULE: &str = "one hypothesis supported by two independent sensors";

/// Runs `fss`, validates every answer, and retains the transcript.
struct Driver {
    root: PathBuf,
    scratch: PathBuf,
    transcript: Vec<String>,
}

impl Driver {
    fn run(&mut self, step: &str, argv: &[&str]) -> TestResult<(Option<i32>, Value)> {
        // The command words (`orient`, `session open`, ...) come first; options follow them.
        let words = argv
            .iter()
            .take_while(|token| !token.starts_with("--"))
            .count();
        let mut args: Vec<OsString> = argv.iter().map(OsString::from).collect();
        args.insert(words, "--json".into());
        args.insert(words + 1, "--root".into());
        args.insert(words + 2, self.root.as_os_str().to_owned());
        let (code, stdout) = run_fss(&args)?;
        assert_conforms(
            "agent_response_envelope.v1.json",
            stdout.trim_end(),
            &self.scratch,
        )?;
        let envelope = parse(stdout.trim_end())?;
        let payload = raw_payload(&stdout)?;
        if payload != "null" {
            let schema = text(&envelope, &["payloadSchema"])?;
            assert_conforms(
                &format!("{}.json", schema.trim_start_matches("fss.")),
                payload,
                &self.scratch,
            )?;
        }
        let optional = |path: &[&str]| -> String {
            text(&envelope, path).map_or_else(|_| "null".to_owned(), string)
        };
        let next: Vec<String> = field(&envelope, &["affordances"])
            .ok()
            .and_then(Value::array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        item.object()
                            .and_then(|fields| fields.get("affordanceId"))
                            .and_then(Value::text)
                            .map(ToOwned::to_owned)
                    })
                    .collect()
            })
            .unwrap_or_default();
        let consumed = field(&envelope, &["budgets", "consumed", "tokens"])
            .ok()
            .and_then(|value| match value {
                Value::Number(number) => Some(number.clone()),
                _ => None,
            })
            .unwrap_or_else(|| "null".to_owned());
        self.transcript.push(object(&[
            ("step", string(step)),
            ("argv", strings(argv)),
            (
                "exit",
                code.map_or_else(|| "null".to_owned(), |code| code.to_string()),
            ),
            ("operationId", optional(&["operationId"])),
            ("outcome", optional(&["outcome"])),
            ("errorId", optional(&["errorId"])),
            ("payloadSchema", optional(&["payloadSchema"])),
            ("decisionFingerprint", optional(&["decisionFingerprint"])),
            ("authorityRoot", optional(&["inputAnchor", "authorityRoot"])),
            (
                "proofPointers",
                strings(texts(&envelope, &["proofPointers"]).unwrap_or_default()),
            ),
            (
                "degradation",
                strings(texts(&envelope, &["degradation"]).unwrap_or_default()),
            ),
            ("nextAffordances", strings(&next)),
            ("consumedTokens", consumed),
        ]));
        Ok((code, envelope))
    }

    fn ok(&mut self, step: &str, argv: &[&str]) -> TestResult<Value> {
        let (code, envelope) = self.run(step, argv)?;
        assert_eq!(code, Some(0), "{step}: {envelope:?}");
        Ok(envelope)
    }

    fn retain(&self) -> TestResult<PathBuf> {
        let path = self.scratch.join("rehearsal.jsonl");
        let mut body = self.transcript.join("\n");
        body.push('\n');
        fs::write(&path, &body)?;
        for line in &self.transcript {
            parse(line)?;
        }
        if let Some(target) = std::env::var_os("FSS_REHEARSAL_TRANSCRIPT") {
            fs::write(target, &body)?;
        }
        Ok(path)
    }
}

fn fingerprint(envelope: &Value) -> TestResult<String> {
    Ok(text(envelope, &["decisionFingerprint"])?.to_owned())
}

fn pointers(envelope: &Value) -> TestResult<Vec<String>> {
    texts(envelope, &["proofPointers"])
}

fn propositions(envelope: &Value) -> TestResult<Vec<(String, String)>> {
    field(envelope, &["payload", "epistemic", "propositions"])?
        .array()
        .ok_or("propositions")?
        .iter()
        .map(|item| {
            Ok((
                text(item, &["id"])?.to_owned(),
                text(item, &["statement"])?.to_owned(),
            ))
        })
        .collect()
}

fn case_document() -> String {
    format!(
        r#"{{"caseId":"{CASE}","question":"Did a person enter through the door?",
"decisionInformed":"Whether to alert the owner",
"hypotheses":[{{"hypothesisId":"h:intruder","description":"A person entered through the door","predictions":["both cameras see the same ground track"]}},
{{"hypothesisId":"h:artifact","description":"A lighting or compression artifact on one camera","predictions":["only one camera sees motion"]}}],
"knowns":[],"unknowns":[{{"statementId":"u:identity","text":"Who the person is"}}],
"discriminators":[{{"discriminatorId":"d:second-camera","description":"The west camera's ground track at the same time","separates":["h:intruder","h:artifact"],"expectedOutcomes":["a matching ground track","no motion"]}}],
"probes":["probe:west-camera"],"stopRules":["{STOP_RULE}"],"decisionWindowNs":3600000000000}}"#
    )
}

#[test]
#[allow(clippy::too_many_lines)] // one rehearsal is one ordered transcript
fn orient_investigate_plan_commit_verify_learn_handoff_rehearsal() -> TestResult {
    let (directory, event_id) = corroborated_event("rehearsal")?;
    let relay = Relay::spawn(Some(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"))?;
    let scratch = directory.0.join("scratch");
    fs::create_dir_all(&scratch)?;
    let mut driver = Driver {
        root: directory.root(),
        scratch: scratch.clone(),
        transcript: Vec::new(),
    };

    // Orient cold, then open the mission.
    let oriented = driver.ok("orient", &["orient"])?;
    assert!(texts(&oriented, &["payload", "obligations"])?.is_empty());
    let explained = driver.ok("explain", &["explain", "--event-id", &event_id])?;
    let handles = field(&explained, &["payload", "evidenceHandles"])?
        .array()
        .ok_or("evidence handles")?;
    let revision = text(&handles[0], &["objectDigest"])?.to_owned();
    let manifest = text(&handles[1], &["objectDigest"])?.to_owned();
    let opened = driver.ok(
        "session-open",
        &[
            "session",
            "open",
            "--mission",
            "Protect the door.",
            "--objective",
            "Alert the owner on a corroborated entry.",
        ],
    )?;
    let session = text(&opened, &["sessionId"])?.to_owned();

    // Investigate: competing hypotheses, a claimed probe, cited and assessed evidence.
    let case_file = scratch.join("case.json");
    fs::write(&case_file, case_document())?;
    let case_path = case_file.to_string_lossy().into_owned();
    let case_step =
        |driver: &mut Driver, step: &str, transition: &str, extra: &[&str]| -> TestResult<Value> {
            let mut argv = vec![
                "investigate",
                "--session",
                session.as_str(),
                "--transition",
                transition,
            ];
            argv.extend_from_slice(extra);
            driver.ok(step, &argv)
        };
    let drafted = case_step(
        &mut driver,
        "case-open",
        "open",
        &["--case-file", &case_path],
    )?;
    let head = fingerprint(&drafted)?;
    let active = case_step(
        &mut driver,
        "case-activate",
        "activate",
        &["--case", CASE, "--expected", &head],
    )?;
    let claimed = case_step(
        &mut driver,
        "claim-probe",
        "claim",
        &["--case", CASE, "--work", "probe:probe:west-camera"],
    )?;
    let claim = propositions(&claimed)?[0].0.clone();
    let claim_head = fingerprint(&claimed)?;
    let claim_head = fingerprint(&case_step(
        &mut driver,
        "claim-activate",
        "claim-activate",
        &["--claim", &claim, "--expected", &claim_head],
    )?)?;
    let mut head = fingerprint(&active)?;
    for (step, hypothesis, evidence, side) in [
        ("cite-support", "h:intruder", revision.as_str(), "support"),
        (
            "cite-contradiction",
            "h:artifact",
            manifest.as_str(),
            "contradiction",
        ),
    ] {
        head = fingerprint(&case_step(
            &mut driver,
            step,
            "cite",
            &[
                "--case",
                CASE,
                "--expected",
                &head,
                "--hypothesis",
                hypothesis,
                "--evidence",
                evidence,
                "--side",
                side,
            ],
        )?)?;
    }
    for (step, hypothesis, disposition, evidence) in [
        (
            "assess-supported",
            "h:intruder",
            "supported",
            revision.as_str(),
        ),
        ("assess-refuted", "h:artifact", "refuted", manifest.as_str()),
    ] {
        head = fingerprint(&case_step(
            &mut driver,
            step,
            "assess",
            &[
                "--case",
                CASE,
                "--expected",
                &head,
                "--hypothesis",
                hypothesis,
                "--disposition",
                disposition,
                "--evidence",
                evidence,
            ],
        )?)?;
    }
    let completed = case_step(
        &mut driver,
        "claim-complete",
        "claim-complete",
        &[
            "--claim",
            &claim,
            "--expected",
            &claim_head,
            "--result",
            &revision,
        ],
    )?;
    assert!(propositions(&completed)?[0].1.contains(" is completed"));

    // Plan the alert on the case, then prepare it under the operator's exact approval.
    let relay_address = relay.address.to_string();
    let approval = plaintext_approval();
    let plan_args = |extra: &[&str]| -> Vec<String> {
        let mut argv: Vec<String> = [
            "plan",
            "--session",
            session.as_str(),
            "--intent",
            "alert",
            "--event-id",
            event_id.as_str(),
            "--relay",
            relay_address.as_str(),
            "--path",
            "/fss/alert",
            "--plaintext-approval",
            approval.as_str(),
            "--deadline-ms",
            "5000",
            "--case",
            CASE,
        ]
        .iter()
        .map(|item| (*item).to_owned())
        .collect();
        argv.extend(extra.iter().map(|item| (*item).to_owned()));
        argv
    };
    let planned_argv = plan_args(&[]);
    let planned = driver.ok(
        "plan",
        &planned_argv.iter().map(String::as_str).collect::<Vec<_>>(),
    )?;
    let plan_id = text(&planned, &["payload", "planId"])?.to_owned();
    let plan_approval = pointers(&planned)?[2].clone();
    let prepared_argv = plan_args(&["--approve", &plan_approval]);
    let prepared = driver.ok(
        "plan-approve",
        &prepared_argv.iter().map(String::as_str).collect::<Vec<_>>(),
    )?;
    let dispatch = pointers(&prepared)?
        .last()
        .cloned()
        .ok_or("dispatch approval")?;
    let steps = field(&planned, &["payload", "steps"])?
        .array()
        .ok_or("steps")?;
    let operation = steps
        .iter()
        .find(|step| text(step, &["stepId"]).is_ok_and(|id| id == "step:prepare"))
        .map(|step| texts(step, &["writeWitnesses"]))
        .ok_or("prepare step")??[0]
        .clone();

    // Mid-mission handoff: the prepared plan, its operation, and the open case travel with it.
    let handed = driver.ok("handoff-1", &["handoff", "--session", &session])?;
    assert_eq!(
        texts(&handed, &["payload", "activePlans"])?,
        vec![plan_id.clone()]
    );
    assert_eq!(
        texts(&handed, &["payload", "activeInvestigations"])?,
        vec![CASE.to_owned()]
    );
    assert_eq!(
        texts(&handed, &["payload", "preparedOperations"])?,
        vec![operation.clone()]
    );
    assert!(texts(&handed, &["payload", "leases"])?.is_empty());
    let handoff_id = text(&handed, &["payload", "handoffId"])?.to_owned();

    // A cold driver resumes and commits: exactly one dispatch.
    let resumed = driver.ok("resume", &["session", "resume", "--handoff", &handoff_id])?;
    // The prepare moved the head past the handoff's anchor: the resume names the new obligation
    // and the anchor-bound assumptions it invalidated, never resuming silently.
    let invalidated = texts(&resumed, &["executionBoundary", "invalidated"])?;
    assert!(
        invalidated
            .iter()
            .any(|line| line.contains("obligation added")),
        "{invalidated:#?}"
    );
    assert!(
        invalidated
            .iter()
            .any(|line| line.contains("assumption:anchor-current")),
        "{invalidated:#?}"
    );
    let committed = driver.ok(
        "commit",
        &["commit", "--plan", &plan_id, "--approve", &dispatch],
    )?;
    assert_eq!(text(&committed, &["payload", "state"])?, "adapter_accepted");
    assert_eq!(relay.connections(), 1);
    let waited = driver.ok(
        "wait",
        &["wait", "--operation", &operation, "--deadline-ms", "100"],
    )?;
    assert_eq!(text(&waited, &["payload", "state"])?, "adapter_accepted");

    // Verify: the owner attests delivery; the obligation is discharged without a resend.
    let attested = ContentDigest::sha256(b"owner's phone notification screenshot").to_text();
    let reconcile = |approve: Option<&str>| -> Vec<String> {
        let mut argv: Vec<String> = [
            "commit",
            "--reconcile",
            "delivered",
            "--operation",
            operation.as_str(),
            "--evidence",
            attested.as_str(),
            "--statement",
            "The alert reached the owner's phone.",
        ]
        .iter()
        .map(|item| (*item).to_owned())
        .collect();
        if let Some(approve) = approve {
            argv.push("--approve".to_owned());
            argv.push(approve.to_owned());
        }
        argv
    };
    let preview_argv = reconcile(None);
    let preview = driver.ok(
        "reconcile-preview",
        &preview_argv.iter().map(String::as_str).collect::<Vec<_>>(),
    )?;
    let reconcile_approval = pointers(&preview)?[0].clone();
    let verify_argv = reconcile(Some(&reconcile_approval));
    let verified = driver.ok(
        "reconcile",
        &verify_argv.iter().map(String::as_str).collect::<Vec<_>>(),
    )?;
    assert_eq!(text(&verified, &["payload", "state"])?, "verified");
    assert_eq!(relay.connections(), 1);

    // Close the plan: its immutable episode records predictions, outcome, and residuals.
    let closed = driver.ok(
        "close",
        &["plan", "--session", &session, "--close", &plan_id],
    )?;
    let episode_bytes = fss_publication::read_verified(
        directory.root().join("agent/publications"),
        ContentDigest::parse(&pointers(&closed)?[1])?,
        1 << 20,
    )?;
    let episode_text = String::from_utf8(episode_bytes)?;
    assert_conforms("agent_execution_episode.v1.json", &episode_text, &scratch)?;
    let episode = parse(&episode_text)?;
    assert_eq!(text(&episode, &["outcome", "state"])?, "succeeded");
    assert_eq!(
        texts(&episode, &["outcome", "indeterminatePredicates"])?,
        vec!["warranted".to_owned()]
    );
    let episode_digest = pointers(&closed)?[2].clone();

    // Learn: an advisory, evidence-linked proposal citing the episode; nothing activates.
    let learned = driver.ok(
        "feedback",
        &[
            "feedback", "--session", &session, "--target", &format!("plan:{plan_id}"),
            "--kind", "runbook_candidate", "--statement",
            "Corroborated two-camera door entries justified one relay alert; keep the probe-then-plan order.",
            "--supporting", &episode_digest, "--disposition", "create_learning_proposal",
        ],
    )?;
    assert_eq!(
        field(&learned, &["payload", "activePolicyMutation"])?,
        &Value::Bool(false)
    );

    // Conclude the case against its stop rule, acknowledging the residual unknown.
    let concluded = case_step(
        &mut driver,
        "case-conclude",
        "conclude",
        &[
            "--case",
            CASE,
            "--expected",
            &head,
            "--conclusion",
            "resolved",
            "--stop-rule",
            STOP_RULE,
            "--assessment",
            &revision,
            "--residual-unknowns",
            "u:identity",
        ],
    )?;
    assert_eq!(text(&concluded, &["payload", "state"])?, "resolved");

    // Final handoff: nothing active remains, and the obligation is discharged.
    let finished = driver.ok("handoff-2", &["handoff", "--session", &session])?;
    for list in [
        "activePlans",
        "activeInvestigations",
        "leases",
        "preparedOperations",
        "obligations",
        "indeterminateEffects",
    ] {
        assert!(
            texts(&finished, &["payload", list])?.is_empty(),
            "{list}: {finished:?}"
        );
    }
    assert_ne!(text(&finished, &["payload", "handoffId"])?, handoff_id);

    // The transcript is retained and every step's identity is recorded.
    let path = driver.retain()?;
    let lines = fs::read_to_string(path)?;
    assert_eq!(lines.lines().count(), driver.transcript.len());
    assert!(driver.transcript.len() >= 20);
    assert_eq!(relay.requests()?, 1);
    Ok(())
}

fn as_str(argv: &[String]) -> Vec<&str> {
    argv.iter().map(String::as_str).collect()
}

/// The affordance identities an answer lists as next moves.
fn next_moves(envelope: &Value) -> TestResult<Vec<String>> {
    Ok(field(envelope, &["affordances"])?
        .array()
        .ok_or("affordances")?
        .iter()
        .filter_map(|item| {
            item.object()
                .and_then(|fields| fields.get("affordanceId"))
                .and_then(Value::text)
                .map(ToOwned::to_owned)
        })
        .collect())
}

/// Scenario NS-9: an alert may have crossed the relay but its acknowledgement was lost; the
/// driver hands off and a cold driver resumes. The indeterminate effect, its open obligation,
/// and the reconcile affordance travel through the handoff and the resumed situation; a retried
/// commit never resends; only the owner's attestation discharges the obligation; the closed
/// episode keeps the failure and its residual uncertainty.
#[test]
#[allow(clippy::too_many_lines)] // one rehearsal is one ordered transcript
fn a_lost_acknowledgement_survives_handoff_and_resume_and_is_reconciled_never_resent() -> TestResult
{
    let (directory, event_id) = corroborated_event("lost-ack")?;
    let relay = Relay::spawn(None)?;
    let scratch = directory.0.join("scratch");
    fs::create_dir_all(&scratch)?;
    let mut driver = Driver {
        root: directory.root(),
        scratch: scratch.clone(),
        transcript: Vec::new(),
    };
    let opened = driver.ok(
        "session-open",
        &[
            "session",
            "open",
            "--mission",
            "Protect the door.",
            "--objective",
            "Alert the owner on a corroborated entry.",
        ],
    )?;
    let session = text(&opened, &["sessionId"])?.to_owned();
    let relay_address = relay.address.to_string();
    let approval = plaintext_approval();
    let plan_argv = |extra: &[&str]| -> Vec<String> {
        let mut argv: Vec<String> = [
            "plan",
            "--session",
            session.as_str(),
            "--intent",
            "alert",
            "--event-id",
            event_id.as_str(),
            "--relay",
            relay_address.as_str(),
            "--path",
            "/fss/alert",
            "--plaintext-approval",
            approval.as_str(),
            "--deadline-ms",
            "5000",
        ]
        .iter()
        .map(|item| (*item).to_owned())
        .collect();
        argv.extend(extra.iter().map(|item| (*item).to_owned()));
        argv
    };
    let planned = driver.ok("plan", &as_str(&plan_argv(&[])))?;
    let plan_id = text(&planned, &["payload", "planId"])?.to_owned();
    let plan_approval = pointers(&planned)?[2].clone();
    let prepared = driver.ok(
        "plan-approve",
        &as_str(&plan_argv(&["--approve", &plan_approval])),
    )?;
    let dispatch = pointers(&prepared)?
        .last()
        .cloned()
        .ok_or("dispatch approval")?;
    let (code, lost) = driver.run(
        "commit",
        &["commit", "--plan", &plan_id, "--approve", &dispatch],
    )?;
    assert_eq!(code, Some(1));
    assert_eq!(text(&lost, &["errorId"])?, "ERR-EFFECT-INDETERMINATE-001");
    assert_eq!(relay.connections(), 1);

    // The handoff carries the indeterminate effect and its open obligation, read live.
    let handed = driver.ok("handoff", &["handoff", "--session", &session])?;
    let effects = texts(&handed, &["payload", "indeterminateEffects"])?;
    assert_eq!(effects.len(), 1, "{handed:?}");
    let operation = effects[0].clone();
    assert_eq!(text(&lost, &["payload", "state"])?, "indeterminate");
    assert_eq!(texts(&handed, &["payload", "obligations"])?.len(), 1);
    assert!(texts(&handed, &["payload", "preparedOperations"])?.is_empty());
    assert_eq!(
        texts(&handed, &["payload", "activePlans"])?,
        vec![plan_id.clone()]
    );
    let handoff_id = text(&handed, &["payload", "handoffId"])?.to_owned();

    // A cold driver resumes: the situation names the indeterminate effect and offers
    // reconciliation, never a resend; a retried commit observes the same indeterminate state.
    let resumed = driver.ok("resume", &["session", "resume", "--handoff", &handoff_id])?;
    assert_eq!(
        texts(&resumed, &["payload", "indeterminateEffects"])?,
        vec![operation.clone()]
    );
    // Reconciliation is the owner's move: listed in the situation as blocked, never a next move
    // the agent could take itself, and never a resend.
    let listed: Vec<String> = field(&resumed, &["payload", "affordances"])?
        .array()
        .ok_or("affordances")?
        .iter()
        .filter_map(|item| {
            item.object()
                .and_then(|fields| fields.get("affordanceId"))
                .and_then(Value::text)
                .map(ToOwned::to_owned)
        })
        .collect();
    let reconcile = format!("affordance:reconcile:{operation}");
    assert!(listed.contains(&reconcile), "{listed:?}");
    assert!(!next_moves(&resumed)?.contains(&reconcile));
    let (code, retried) = driver.run(
        "commit-retry",
        &["commit", "--plan", &plan_id, "--approve", &dispatch],
    )?;
    assert_eq!(code, Some(1));
    assert_eq!(text(&retried, &["payload", "state"])?, "indeterminate");
    assert_eq!(
        relay.connections(),
        1,
        "a lost acknowledgement is never resent"
    );
    let (code, open) = driver.run(
        "close-early",
        &["plan", "--session", &session, "--close", &plan_id],
    )?;
    assert_eq!(code, Some(5));
    assert_eq!(text(&open, &["recoveryClass"])?, "reconciliation_required");

    // The owner attests the alert never arrived: the obligation fails, nothing is resent.
    let attested = ContentDigest::sha256(b"owner: no notification on any device").to_text();
    let reconcile_argv = |approve: Option<&str>| -> Vec<String> {
        let mut argv: Vec<String> = [
            "commit",
            "--reconcile",
            "not_delivered",
            "--operation",
            operation.as_str(),
            "--evidence",
            attested.as_str(),
            "--statement",
            "Nothing arrived on the owner's devices.",
        ]
        .iter()
        .map(|item| (*item).to_owned())
        .collect();
        if let Some(approve) = approve {
            argv.push("--approve".to_owned());
            argv.push(approve.to_owned());
        }
        argv
    };
    let preview = driver.ok("reconcile-preview", &as_str(&reconcile_argv(None)))?;
    let reconcile_approval = pointers(&preview)?[0].clone();
    let failed = driver.ok(
        "reconcile",
        &as_str(&reconcile_argv(Some(&reconcile_approval))),
    )?;
    assert_eq!(text(&failed, &["payload", "state"])?, "failed");
    assert_eq!(relay.connections(), 1);

    // The episode keeps the failed delivery, its competing attributions, and the residuals.
    let closed = driver.ok(
        "close",
        &["plan", "--session", &session, "--close", &plan_id],
    )?;
    let episode = parse(&String::from_utf8(fss_publication::read_verified(
        directory.root().join("agent/publications"),
        ContentDigest::parse(&pointers(&closed)?[1])?,
        1 << 20,
    )?)?)?;
    assert_eq!(text(&episode, &["outcome", "state"])?, "failed");
    assert!(texts(&episode, &["stepReceipts"])?.contains(&"step:reconcile=completed".to_owned()));
    let finished = driver.ok("handoff-final", &["handoff", "--session", &session])?;
    for list in [
        "activePlans",
        "obligations",
        "indeterminateEffects",
        "preparedOperations",
    ] {
        assert!(
            texts(&finished, &["payload", list])?.is_empty(),
            "{list}: {finished:?}"
        );
    }
    driver.retain()?;
    Ok(())
}
