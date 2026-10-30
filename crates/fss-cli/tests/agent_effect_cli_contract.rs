#![forbid(unsafe_code)]
//! Contract tests for the canonical agent effect grammar through the real `fss` binary, over a
//! deployment with one corroborated event built by `fss-file import` and `fss-event corroborate`:
//!
//! 1. `fss plan` publishes a witnessed `fss.agent_control_plan.v1` and prepares nothing; with the
//!    operator's exact plan approval it prepares; `fss commit` with the exact dispatch approval
//!    commits durably and sends exactly one request; a second commit and `fss-event alert` (which
//!    shares the operation identity) never resend; `fss wait` observes without writing;
//! 2. a relay that closes without acknowledgement leaves the operation indeterminate (exit 1,
//!    `ERR-EFFECT-INDETERMINATE-001`) and it is never resent;
//! 3. stale plan and dispatch approvals are typed refusals before any I/O, and a prepared
//!    operation can be cancelled (preview, then exact approval) so it can never be committed;
//! 4. owner-attested reconciliation discharges a dispatched alert's obligation, and `fss plan
//!    --close` then records the plan's immutable execution episode (refused while the effect is
//!    open; hydrated from the publication store and validated against its schema; returned
//!    unchanged on a second close; citing the principal's feedback as competing attribution);
//! 5. changed case revisions invalidate preview approval before preparation, and changed cases
//!    or rebased sessions invalidate prepared plans before relay I/O;
//!    a dispatch retains its exact case/session witness through the bounded network attempt,
//!    then releases ownership while cold receipt recovery never resends after witness changes.

#[path = "agent_effect_cli_contract/feedback_case.rs"]
mod feedback_case;
#[path = "agent_effect_cli_contract/learning_explain.rs"]
mod learning_explain;

#[path = "agent_effect_cli_contract/historical_health.rs"]
mod historical_health;

use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:agent-effect-cli";
const CASE: &str = "case:east-door";
const IDENTITY: &str = "1,0,0,0,1,0,0,0,1";
const MIRROR: &str = "-1,0,96,0,1,0,0,0,1";

struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-agent-effect-cli-{name}-{}-{attempt}",
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
    release_reply: Arc<AtomicBool>,
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
        Self::spawn_with_gate(reply, false)
    }

    fn spawn_with_gate(reply: Option<&'static [u8]>, gated: bool) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let release_reply = Arc::new(AtomicBool::new(!gated));
        let proceed = release_reply.clone();
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
                // Retain the complete request without acknowledging it until the test has
                // observed competing commands. Drop always interrupts this gate on failure.
                while !proceed.load(Ordering::SeqCst) && !halt.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(2));
                }
                if halt.load(Ordering::SeqCst) {
                    break;
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
            release_reply,
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
    fn release(&self) {
        self.release_reply.store(true, Ordering::SeqCst);
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

struct Agent {
    root: PathBuf,
    scratch: PathBuf,
    session: String,
}

impl Agent {
    fn open(directory: &OwnedDirectory) -> TestResult<Self> {
        Self::open_with_options(directory, &[])
    }

    fn open_with_options(directory: &OwnedDirectory, extra: &[&str]) -> TestResult<Self> {
        let root = directory.root();
        let mut args = vec![
            "session".into(),
            "open".into(),
            "--json".into(),
            "--root".into(),
            root.as_os_str().to_owned(),
            "--mission".into(),
            "Protect the door.".into(),
            "--objective".into(),
            "Alert the owner on a corroborated entry.".into(),
        ];
        args.extend(extra.iter().map(OsString::from));
        let (code, stdout) = run_fss(&args)?;
        assert_eq!(code, Some(0), "{stdout}");
        let scratch = directory.0.join("scratch");
        fs::create_dir_all(&scratch)?;
        Ok(Self {
            root,
            scratch,
            session: text(&parse(stdout.trim_end())?, &["sessionId"])?.to_owned(),
        })
    }

    fn args(&self, command: &str, extra: &[&str]) -> Vec<OsString> {
        let mut args: Vec<OsString> = vec![
            command.into(),
            "--json".into(),
            "--root".into(),
            self.root.as_os_str().to_owned(),
        ];
        args.extend(extra.iter().map(OsString::from));
        args
    }

    /// Runs one command; validates the envelope and payload; returns (exit, envelope).
    fn run(&self, command: &str, extra: &[&str]) -> TestResult<(Option<i32>, Value)> {
        let (code, stdout) = run_fss(&self.args(command, extra))?;
        self.answer(code, &stdout)
    }

    fn answer(&self, code: Option<i32>, stdout: &str) -> TestResult<(Option<i32>, Value)> {
        assert_conforms(
            "agent_response_envelope.v1.json",
            stdout.trim_end(),
            &self.scratch,
        )?;
        let envelope = parse(stdout.trim_end())?;
        let payload = raw_payload(stdout)?;
        if payload != "null" {
            let schema = text(&envelope, &["payloadSchema"])?;
            assert_conforms(
                &format!("{}.json", schema.trim_start_matches("fss.")),
                payload,
                &self.scratch,
            )?;
        }
        Ok((code, envelope))
    }

    /// The session's active plans, as the case list (a cognitive envelope) states them.
    fn active_plans(&self) -> TestResult<Vec<String>> {
        let (code, listed) = self.run(
            "investigate",
            &["--session", self.session.as_str(), "--transition", "list"],
        )?;
        assert_eq!(code, Some(0));
        field(&listed, &["payload", "epistemic", "propositions"])?
            .array()
            .ok_or("propositions")?
            .iter()
            .map(|proposition| Ok(text(proposition, &["id"])?.to_owned()))
            .filter(|id: &TestResult<String>| {
                id.as_ref().map_or(true, |id| id.starts_with("plan:"))
            })
            .collect()
    }

    fn plan(
        &self,
        event_id: &str,
        relay: SocketAddr,
        extra: &[&str],
    ) -> TestResult<(Option<i32>, Value)> {
        self.plan_with_deadline(event_id, relay, "5000", extra)
    }

    fn plan_with_deadline(
        &self,
        event_id: &str,
        relay: SocketAddr,
        deadline_ms: &str,
        extra: &[&str],
    ) -> TestResult<(Option<i32>, Value)> {
        let relay = relay.to_string();
        let approval = plaintext_approval();
        let mut args = vec![
            "--session",
            self.session.as_str(),
            "--intent",
            "alert",
            "--event-id",
            event_id,
            "--relay",
            &relay,
            "--path",
            "/fss/alert",
            "--plaintext-approval",
            &approval,
            "--deadline-ms",
            deadline_ms,
        ];
        args.extend_from_slice(extra);
        self.run("plan", &args)
    }
}

/// One `plan --close` answer: exit, envelope, and the hydrated episode (parsed and raw).
type Closed = (Option<i32>, Value, Option<(Value, String)>);

impl Agent {
    /// `plan --close`: records (or returns) the plan's immutable execution episode. Returns the
    /// exit, the envelope (whose payload is the closed control plan), and the episode rendering
    /// hydrated from the agent publication store through the second proof pointer, validated
    /// against `fss.agent_execution_episode.v1`.
    fn close(&self, plan_id: &str) -> TestResult<Closed> {
        let (code, envelope) = self.run(
            "plan",
            &["--session", self.session.as_str(), "--close", plan_id],
        )?;
        if code != Some(0) {
            return Ok((code, envelope, None));
        }
        assert_eq!(
            text(&envelope, &["payloadSchema"])?,
            "fss.agent_control_plan.v1"
        );
        assert_eq!(text(&envelope, &["payload", "planId"])?, plan_id);
        let pointer = texts(&envelope, &["proofPointers"])?[1].clone();
        let bytes = fss_publication::read_verified(
            self.root.join("agent/publications"),
            ContentDigest::parse(&pointer)?,
            1 << 20,
        )?;
        let rendering = String::from_utf8(bytes)?;
        assert_conforms("agent_execution_episode.v1.json", &rendering, &self.scratch)?;
        let episode = parse(&rendering)?;
        Ok((code, envelope, Some((episode, rendering))))
    }
}

/// The plan's approval digest (third proof pointer) and dispatch digest (last, when prepared).
fn approvals(plan: &Value) -> TestResult<(String, String, String)> {
    let pointers = texts(plan, &["proofPointers"])?;
    Ok((
        text(plan, &["payload", "planId"])?.to_owned(),
        pointers[2].clone(),
        pointers[pointers.len() - 1].clone(),
    ))
}

fn operation_of(plan: &Value) -> TestResult<String> {
    let steps = field(plan, &["payload", "steps"])?.array().ok_or("steps")?;
    let prepare = steps
        .iter()
        .find(|step| text(step, &["stepId"]).is_ok_and(|id| id == "step:prepare"))
        .ok_or("prepare step")?;
    Ok(texts(prepare, &["writeWitnesses"])?[0].clone())
}

type CapturedPipe = JoinHandle<std::io::Result<Vec<u8>>>;

/// An owned real CLI child. Every assertion/error path kills and reaps only this fixture process.
/// Both pipes are drained from spawn, independently of the bounded exit wait.
struct RunningFss {
    child: Child,
    stdout: Option<CapturedPipe>,
    stderr: Option<CapturedPipe>,
}

impl RunningFss {
    fn capture(mut pipe: impl Read + Send + 'static) -> std::io::Result<CapturedPipe> {
        std::thread::Builder::new().spawn(move || {
            let mut bytes = Vec::new();
            pipe.read_to_end(&mut bytes)?;
            Ok(bytes)
        })
    }

    fn spawn(args: &[OsString]) -> TestResult<Self> {
        let mut owned = Self {
            child: Command::new(env!("CARGO_BIN_EXE_fss"))
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?,
            stdout: None,
            stderr: None,
        };
        // Establish ownership before any fallible reader setup, so even a reader-spawn
        // failure cannot leave the CLI child or its other output reader behind.
        let stdout = owned.child.stdout.take().ok_or("commit stdout missing")?;
        owned.stdout = Some(Self::capture(stdout)?);
        let stderr = owned.child.stderr.take().ok_or("commit stderr missing")?;
        owned.stderr = Some(Self::capture(stderr)?);
        Ok(owned)
    }

    fn running(&mut self) -> TestResult<bool> {
        Ok(self.child.try_wait()?.is_none())
    }

    fn collected(reader: &mut Option<CapturedPipe>) -> TestResult<Vec<u8>> {
        Ok(reader
            .take()
            .ok_or("commit output reader missing")?
            .join()
            .map_err(|_| "commit output reader panicked")??)
    }

    fn finish(mut self) -> TestResult<Output> {
        let deadline = Instant::now() + Duration::from_secs(35);
        let status = loop {
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                return Err("the owned commit process exceeded its bounded completion wait".into());
            }
            std::thread::sleep(Duration::from_millis(2));
        };
        let stdout = Self::collected(&mut self.stdout)?;
        let stderr = Self::collected(&mut self.stderr)?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }
}

impl Drop for RunningFss {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Reaping the owned process closes its pipe writers, so readers finish even when
        // the test aborts while the relay acknowledgement is still gated.
        for reader in [self.stdout.take(), self.stderr.take()]
            .into_iter()
            .flatten()
        {
            let _ = reader.join();
        }
    }
}

impl Agent {
    fn open_case(&self) -> TestResult<Value> {
        let path = self.scratch.join("alert-case.json");
        fs::write(
            &path,
            r#"{"caseId":"case:east-door","question":"Did a person enter?",
"decisionInformed":"Prepare an owner alert",
"hypotheses":[{"hypothesisId":"h:entry","description":"Entered","predictions":["Hallway track"]},
{"hypothesisId":"h:passerby","description":"Passed","predictions":["Exterior only"]}],
"stopRules":["An independent observation distinguishes the alternatives"],
"decisionWindowNs":3600000000000}"#,
        )?;
        let (code, opened) = self.run(
            "investigate",
            &[
                "--session",
                &self.session,
                "--transition",
                "open",
                "--case-file",
                path.to_str().ok_or("case fixture path is not UTF-8")?,
            ],
        )?;
        assert_eq!(code, Some(0), "{opened:?}");
        Ok(opened)
    }

    fn cancel_case(&self, expected: &str) -> TestResult<(Option<i32>, Value)> {
        let reason = ContentDigest::sha256(b"owner withdrew the alert investigation").to_text();
        self.run(
            "investigate",
            &[
                "--session",
                &self.session,
                "--transition",
                "set-state",
                "--case",
                CASE,
                "--expected",
                expected,
                "--state",
                "cancelled",
                "--reason",
                &reason,
            ],
        )
    }

    /// Advance retained evidence without revising the alert event, then explicitly resume the
    /// same session. Both ledger and workspace anchors must move; effect history alone is not
    /// used as a stand-in for a session rebase.
    fn resume_after_new_evidence(&self, directory: &OwnedDirectory) -> TestResult<Value> {
        let (code, handed) = self.run("handoff", &["--session", &self.session])?;
        assert_eq!(code, Some(0), "{handed:?}");
        let handoff = text(&handed, &["payload", "handoffId"])?;
        import(
            directory,
            true,
            "sensor:refresh",
            now_ns()? - 10_000_000_000,
        )?;
        let (code, stdout) = run_fss(&[
            "session".into(),
            "resume".into(),
            "--json".into(),
            "--root".into(),
            self.root.as_os_str().to_owned(),
            "--handoff".into(),
            handoff.into(),
        ])?;
        let (code, resumed) = self.answer(code, &stdout)?;
        assert_eq!(code, Some(0), "{resumed:?}");
        assert_eq!(text(&resumed, &["sessionId"])?, self.session);
        assert_ne!(
            field(&resumed, &["payload", "anchor"])?,
            field(&resumed, &["payload", "previousAnchor"])?,
            "the fixture must actually rebase onto newly committed evidence"
        );
        Ok(resumed)
    }
}

#[test]
fn plan_prepare_commit_sends_exactly_once_and_shares_the_alert_identity() -> TestResult {
    let (directory, event_id) = corroborated_event("accepted")?;
    let agent = Agent::open(&directory)?;
    let relay = Relay::spawn(Some(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"))?;
    let effects = agent.root.join("effects/journal.fssj");
    let before = fs::read(&effects)?;

    let (code, planned) = agent.plan(&event_id, relay.address, &[])?;
    assert_eq!(code, Some(0));
    assert_eq!(text(&planned, &["operationId"])?, "AOP-007");
    assert_eq!(
        text(&planned, &["payloadSchema"])?,
        "fss.agent_control_plan.v1"
    );
    // Planning prepares nothing and sends nothing.
    assert_eq!(fs::read(&effects)?, before);
    assert_eq!(relay.connections(), 0);
    let (plan_id, plan_approval, _) = approvals(&planned)?;
    let operation = operation_of(&planned)?;
    // The commit step names the worlds it serves and the ones where it is a false alarm.
    let steps = field(&planned, &["payload", "steps"])?
        .array()
        .ok_or("steps")?;
    let commit = steps
        .iter()
        .find(|step| text(step, &["stepId"]).is_ok_and(|id| id == "step:commit"))
        .ok_or("commit step")?;
    assert_eq!(text(commit, &["reversibility"])?, "irreversible");
    assert!(texts(commit, &["requiredCapabilities"])?.contains(&"CAP-ALERT-COMMIT-001".to_owned()));

    // A plan cannot be committed before it is prepared.
    let (code, refused) =
        agent.run("commit", &["--plan", &plan_id, "--approve", &plan_approval])?;
    assert_eq!(code, Some(5));
    assert_eq!(
        text(&refused, &["errorId"])?,
        "ERR-OP-PRECONDITION-FAILED-001"
    );

    let (code, prepared) = agent.plan(&event_id, relay.address, &["--approve", &plan_approval])?;
    assert_eq!(code, Some(0));
    let (same_plan, _, dispatch) = approvals(&prepared)?;
    assert_eq!(same_plan, plan_id);
    assert_ne!(dispatch, plan_approval);
    assert_ne!(fs::read(&effects)?, before);
    assert_eq!(relay.connections(), 0);
    // The prepared plan is mission state, not conversation: the session's situation and its
    // handoff both carry it.
    assert_eq!(agent.active_plans()?, vec![plan_id.clone()]);
    let (code, stdout) = run_fss(&[
        "handoff".into(),
        "--json".into(),
        "--root".into(),
        agent.root.as_os_str().to_owned(),
        "--session".into(),
        agent.session.clone().into(),
    ])?;
    assert_eq!(code, Some(0), "{stdout}");
    assert_eq!(
        texts(&parse(stdout.trim_end())?, &["payload", "activePlans"])?,
        vec![plan_id.clone()]
    );

    let (code, committed) = agent.run("commit", &["--plan", &plan_id, "--approve", &dispatch])?;
    assert_eq!(code, Some(0), "{committed:?}");
    assert_eq!(text(&committed, &["outcome"])?, "ok");
    assert_eq!(text(&committed, &["payload", "state"])?, "adapter_accepted");
    assert_eq!(text(&committed, &["payload", "operationId"])?, operation);
    let runtime = texts(&committed, &["executionBoundary", "completed"])?
        .into_iter()
        .find(|line| line.starts_with("Owned alert runtime:"))
        .ok_or("commit must carry its owned runtime accounting")?;
    assert!(runtime.contains("quiescence sha256:"));
    assert!(runtime.contains("recovery_required=false"));
    assert!(
        field(&committed, &["budgets", "consumed", "networkBytes"])?
            .integer()
            .ok_or("commit network accounting")?
            > 0
    );
    assert!(
        field(&committed, &["budgets", "consumed", "storageOperations"])?
            .integer()
            .ok_or("commit storage accounting")?
            > 0
    );
    assert_eq!(relay.requests()?, 1);

    // Never resent: not by a second commit, nor by the other surface sharing the identity.
    let (code, again) = agent.run("commit", &["--plan", &plan_id, "--approve", &dispatch])?;
    assert_eq!(code, Some(0));
    assert_eq!(text(&again, &["payload", "state"])?, "adapter_accepted");
    let other_surface = event(
        &agent.root,
        "alert",
        &[
            "--event-id",
            &event_id,
            "--relay",
            &relay.address.to_string(),
            "--path",
            "/fss/alert",
            "--plaintext-approval",
            &plaintext_approval(),
            "--deadline-ms",
            "5000",
            "--approve",
            &plan_approval,
            "--dispatch",
            &dispatch,
        ],
    )?;
    success(&other_surface);
    assert_eq!(report_field(&other_surface, "stage")?, "already_dispatched");
    assert_eq!(report_field(&other_surface, "operation_id")?, operation);
    assert_eq!(relay.connections(), 1);

    // Wait observes without writing: relay acceptance is not completion.
    let journal = fs::read(&effects)?;
    let (code, waited) = agent.run("wait", &["--operation", &operation, "--deadline-ms", "150"])?;
    assert_eq!(code, Some(0));
    assert_eq!(text(&waited, &["outcome"])?, "partial");
    assert_eq!(text(&waited, &["errorId"])?, "ERR-OP-TIMEOUT-001");
    assert_eq!(fs::read(&effects)?, journal);
    Ok(())
}

#[test]
fn a_lost_acknowledgement_is_indeterminate_and_never_resent() -> TestResult {
    let (directory, event_id) = corroborated_event("lost-ack")?;
    let agent = Agent::open(&directory)?;
    let relay = Relay::spawn(None)?;
    let (_, planned) = agent.plan(&event_id, relay.address, &[])?;
    let (plan_id, plan_approval, _) = approvals(&planned)?;
    let (_, prepared) = agent.plan(&event_id, relay.address, &["--approve", &plan_approval])?;
    let (_, _, dispatch) = approvals(&prepared)?;
    let (code, committed) = agent.run("commit", &["--plan", &plan_id, "--approve", &dispatch])?;
    assert_eq!(code, Some(1));
    assert_eq!(text(&committed, &["outcome"])?, "indeterminate");
    assert_eq!(
        text(&committed, &["errorId"])?,
        "ERR-EFFECT-INDETERMINATE-001"
    );
    assert_eq!(text(&committed, &["payload", "state"])?, "indeterminate");
    assert!(
        texts(&committed, &["executionBoundary", "completed"])?
            .iter()
            .any(|line| line.starts_with("Owned alert runtime:")),
        "lost acknowledgements must retain runtime accounting"
    );
    assert!(
        !texts(&committed, &["executionBoundary", "possiblyOccurred"])?.is_empty(),
        "a lost acknowledgement must say what may have happened"
    );
    assert_eq!(relay.connections(), 1);
    let (code, again) = agent.run("commit", &["--plan", &plan_id, "--approve", &dispatch])?;
    assert_eq!(code, Some(1));
    assert_eq!(text(&again, &["payload", "state"])?, "indeterminate");
    assert_eq!(relay.connections(), 1);
    Ok(())
}

#[test]
fn post_dispatch_snapshot_failure_preserves_the_receipt_and_owned_runtime() -> TestResult {
    let (directory, event_id) = corroborated_event("dispatch-snapshot-loss")?;
    let agent = Agent::open(&directory)?;
    let relay = Relay::spawn_with_gate(
        Some(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"),
        true,
    )?;
    let (code, planned) = agent.plan_with_deadline(&event_id, relay.address, "30000", &[])?;
    assert_eq!(code, Some(0), "{planned:?}");
    let (plan_id, approval, _) = approvals(&planned)?;
    let (code, prepared) =
        agent.plan_with_deadline(&event_id, relay.address, "30000", &["--approve", &approval])?;
    assert_eq!(code, Some(0), "{prepared:?}");
    let (_, _, dispatch_approval) = approvals(&prepared)?;
    let operation = operation_of(&prepared)?;
    let mut dispatch = RunningFss::spawn(&agent.args(
        "commit",
        &["--plan", &plan_id, "--approve", &dispatch_approval],
    ))?;
    let arrival_deadline = Instant::now() + Duration::from_secs(10);
    while relay.requests()? == 0 {
        assert!(
            dispatch.running()?,
            "commit exited before the request arrived"
        );
        assert!(
            Instant::now() < arrival_deadline,
            "loopback request did not arrive"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    // Source validation and the send have completed. Temporarily remove only this fixture's
    // layout so the post-effect refresh fails, while the open journal can record acceptance.
    let layout = agent.root.join("LAYOUT");
    let retained_layout = directory.0.join("retained-layout");
    fs::rename(&layout, &retained_layout)?;
    relay.release();
    let finished = dispatch.finish();
    fs::rename(&retained_layout, &layout)?;
    let output = finished?;
    let (code, committed) =
        agent.answer(output.status.code(), std::str::from_utf8(&output.stdout)?)?;
    assert_eq!(code, Some(1), "{committed:?}");
    assert_eq!(text(&committed, &["outcome"])?, "indeterminate");
    assert_eq!(
        text(&committed, &["errorId"])?,
        "ERR-EFFECT-INDETERMINATE-001"
    );
    assert_eq!(
        text(&committed, &["recoveryClass"])?,
        "reconciliation_required"
    );
    assert_eq!(text(&committed, &["safeRetry"])?, "no");
    assert_eq!(text(&committed, &["payload", "state"])?, "adapter_accepted");
    assert_eq!(text(&committed, &["payload", "operationId"])?, operation);
    assert!(texts(&committed, &["degradation"])?.iter().any(|line| {
        line.contains("Post-dispatch snapshot unavailable") && line.contains("pre-dispatch anchor")
    }));
    let completed = texts(&committed, &["executionBoundary", "completed"])?;
    assert!(
        completed
            .iter()
            .any(|line| line.contains("receiver_accepted_202"))
    );
    assert!(completed.iter().any(|line| {
        line.starts_with("Owned alert runtime:") && line.contains("quiescence sha256:")
    }));
    assert!(
        field(&committed, &["budgets", "consumed", "networkBytes"])?
            .integer()
            .ok_or("retained dispatch network charge")?
            > 0
    );
    assert!(
        texts(&committed, &["executionBoundary", "possiblyOccurred"])?
            .iter()
            .any(|line| line.contains("retained operation state is adapter_accepted"))
    );
    assert_eq!(relay.requests()?, 1);
    let (code, again) = agent.run(
        "commit",
        &["--plan", &plan_id, "--approve", &dispatch_approval],
    )?;
    assert_eq!(code, Some(0), "{again:?}");
    assert_eq!(text(&again, &["payload", "state"])?, "adapter_accepted");
    assert_eq!(relay.connections(), 1, "recovery must never resend");
    Ok(())
}

#[test]
fn stale_approvals_refuse_before_io_and_a_cancelled_plan_is_never_committed() -> TestResult {
    let (directory, event_id) = corroborated_event("cancel")?;
    let agent = Agent::open(&directory)?;
    let relay = Relay::spawn(Some(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"))?;
    let bogus = ContentDigest::sha256(b"not the plan").to_text();
    let (code, refused) = agent.plan(&event_id, relay.address, &["--approve", &bogus])?;
    assert_eq!(code, Some(5));
    assert_eq!(
        text(&refused, &["errorId"])?,
        "ERR-ALERT-APPROVAL-STALE-001"
    );

    let (_, planned) = agent.plan(&event_id, relay.address, &[])?;
    let (plan_id, plan_approval, _) = approvals(&planned)?;
    let operation = operation_of(&planned)?;
    agent.plan(&event_id, relay.address, &["--approve", &plan_approval])?;
    let (code, refused) = agent.run("commit", &["--plan", &plan_id, "--approve", &bogus])?;
    assert_eq!(code, Some(5));
    assert_eq!(
        text(&refused, &["errorId"])?,
        "ERR-ALERT-APPROVAL-STALE-001"
    );
    assert_eq!(relay.connections(), 0);

    let (code, preview) = agent.run("cancel", &["--operation", &operation])?;
    assert_eq!(code, Some(0));
    assert_eq!(text(&preview, &["payload", "state"])?, "prepared");
    let cancel_approval = texts(&preview, &["proofPointers"])?[0].clone();
    let (code, cancelled) = agent.run(
        "cancel",
        &["--operation", &operation, "--approve", &cancel_approval],
    )?;
    assert_eq!(code, Some(0));
    assert_eq!(text(&cancelled, &["payload", "state"])?, "cancelled");

    // The prepared record is gone: the dispatch approval can no longer be current.
    let (_, replanned) = agent.plan(&event_id, relay.address, &[])?;
    assert!(
        texts(&replanned, &["executionBoundary", "completed"])?
            .iter()
            .any(|line| line.contains("already cancelled")),
        "{replanned:?}"
    );
    let (code, reported) = agent.run("commit", &["--plan", &plan_id, "--approve", &bogus])?;
    assert_eq!(code, Some(0));
    assert_eq!(text(&reported, &["payload", "state"])?, "cancelled");
    // The withdrawn plan closes as cancelled: nothing was dispatched, so its delivery prediction
    // was never tested.
    let (code, closed, episode) = agent.close(&plan_id)?;
    assert_eq!(code, Some(0), "{closed:?}");
    let (episode, _) = episode.ok_or("episode")?;
    assert_eq!(text(&episode, &["outcome", "state"])?, "cancelled");
    assert!(matches!(
        field(prediction(&episode, "prediction:delivery")?, &["error"])?,
        Value::Null
    ));
    assert!(texts(&episode, &["stepReceipts"])?.contains(&"step:commit=not_started".to_owned()));
    assert_eq!(causes(&episode)?, vec!["policy".to_owned()]);
    assert_eq!(relay.connections(), 0);
    Ok(())
}

fn reconcile(
    agent: &Agent,
    operation: &str,
    outcome: &str,
    evidence: &str,
    approve: Option<&str>,
) -> TestResult<(Option<i32>, Value)> {
    let mut args = vec![
        "--reconcile",
        outcome,
        "--operation",
        operation,
        "--evidence",
        evidence,
        "--statement",
        "The owner's phone showed the alert at 02:14.",
    ];
    if let Some(approve) = approve {
        args.push("--approve");
        args.push(approve);
    }
    agent.run("commit", &args)
}

/// Plans, prepares, and commits one alert: (plan, operation, commit exit, commit envelope).
fn dispatched(
    agent: &Agent,
    event_id: &str,
    relay: &Relay,
) -> TestResult<(String, String, Option<i32>, Value)> {
    let (_, planned) = agent.plan(event_id, relay.address, &[])?;
    let (plan_id, plan_approval, _) = approvals(&planned)?;
    let operation = operation_of(&planned)?;
    let (_, prepared) = agent.plan(event_id, relay.address, &["--approve", &plan_approval])?;
    let (_, _, dispatch) = approvals(&prepared)?;
    let (code, committed) = agent.run("commit", &["--plan", &plan_id, "--approve", &dispatch])?;
    Ok((plan_id, operation, code, committed))
}

/// The episode's attribution cause classes, in order.
fn causes(episode: &Value) -> TestResult<Vec<String>> {
    field(episode, &["attributionHypotheses"])?
        .array()
        .ok_or("attribution hypotheses")?
        .iter()
        .map(|hypothesis| Ok(text(hypothesis, &["causeClass"])?.to_owned()))
        .collect()
}

/// The episode prediction `id`.
fn prediction<'a>(episode: &'a Value, id: &str) -> TestResult<&'a Value> {
    Ok(field(episode, &["predictions"])?
        .array()
        .ok_or("predictions")?
        .iter()
        .find(|prediction| text(prediction, &["predictionId"]).is_ok_and(|found| found == id))
        .ok_or("prediction missing")?)
}

#[test]
fn an_indeterminate_alert_is_reconciled_only_by_an_approved_owner_attestation() -> TestResult {
    let (directory, event_id) = corroborated_event("reconcile-delivered")?;
    let agent = Agent::open(&directory)?;
    let relay = Relay::spawn(None)?;
    let (plan_id, operation, code, _) = dispatched(&agent, &event_id, &relay)?;
    assert_eq!(code, Some(1));
    let evidence = ContentDigest::sha256(b"screenshot of the received alert").to_text();
    // An indeterminate plan has no outcome to record: closing it needs reconciliation first.
    let (code, open, _) = agent.close(&plan_id)?;
    assert_eq!(code, Some(5), "{open:?}");
    assert_eq!(text(&open, &["errorId"])?, "ERR-OP-PRECONDITION-FAILED-001");
    assert_eq!(text(&open, &["recoveryClass"])?, "reconciliation_required");

    // A concurrent bounded wait wakes on the reconciliation.
    let root = agent.root.clone();
    let watched = operation.clone();
    let waiter = std::thread::spawn(move || {
        Command::new(env!("CARGO_BIN_EXE_fss"))
            .args(["wait", "--json", "--root"])
            .arg(&root)
            .args(["--operation", &watched, "--deadline-ms", "20000"])
            .output()
    });

    let (code, preview) = reconcile(&agent, &operation, "delivered", &evidence, None)?;
    assert_eq!(code, Some(0));
    assert_eq!(text(&preview, &["payload", "state"])?, "indeterminate");
    let approval = texts(&preview, &["proofPointers"])?[0].clone();
    let bogus = ContentDigest::sha256(b"not the approval").to_text();
    let (code, refused) = reconcile(&agent, &operation, "delivered", &evidence, Some(&bogus))?;
    assert_eq!(code, Some(5));
    assert_eq!(
        text(&refused, &["errorId"])?,
        "ERR-ALERT-APPROVAL-STALE-001"
    );

    let (code, reconciled) =
        reconcile(&agent, &operation, "delivered", &evidence, Some(&approval))?;
    assert_eq!(code, Some(0), "{reconciled:?}");
    assert_eq!(text(&reconciled, &["payload", "state"])?, "verified");
    assert!(
        texts(&reconciled, &["degradation"])?
            .iter()
            .any(|line| line.contains("operator_asserted")),
        "the provenance of the reconciliation must be explicit"
    );
    // An exact retry observes the same reconciliation; a contrary one is refused.
    let (code, again) = reconcile(&agent, &operation, "delivered", &evidence, Some(&approval))?;
    assert_eq!(code, Some(0));
    assert_eq!(text(&again, &["payload", "state"])?, "verified");
    let (code, contrary) = reconcile(&agent, &operation, "not_delivered", &evidence, None)?;
    assert_eq!(code, Some(5));
    assert_eq!(
        text(&contrary, &["errorId"])?,
        "ERR-OP-PRECONDITION-FAILED-001"
    );

    let waited = waiter.join().map_err(|_| "waiter panicked")??;
    let waited = parse(String::from_utf8(waited.stdout)?.trim_end())?;
    assert_eq!(text(&waited, &["outcome"])?, "ok");
    assert_ne!(text(&waited, &["payload", "state"])?, "indeterminate");
    // Reconciliation never contacted the relay again.
    assert_eq!(relay.connections(), 1);
    // The situation compiles over the reconciled journal and the obligation is discharged.
    let (code, oriented) = run_fss(&[
        "orient".into(),
        "--json".into(),
        "--root".into(),
        agent.root.as_os_str().to_owned(),
    ])?;
    assert_eq!(code, Some(0), "{oriented}");
    let oriented = parse(oriented.trim_end())?;
    assert!(texts(&oriented, &["payload", "obligations"])?.is_empty());
    // A reconciled plan stays active until its outcome is recorded: closing it is the next move.
    assert_eq!(agent.active_plans()?, vec![plan_id.clone()]);
    let (code, closed, episode) = agent.close(&plan_id)?;
    assert_eq!(code, Some(0), "{closed:?}");
    let (episode, first) = episode.ok_or("episode")?;
    assert_eq!(text(&episode, &["outcome", "state"])?, "succeeded");
    let delivery = prediction(&episode, "prediction:delivery")?;
    assert_eq!(text(delivery, &["observedState"])?, "verified");
    // Whether the alert was warranted is never observed by its delivery.
    let warranted = prediction(&episode, "prediction:warranted")?;
    assert!(matches!(field(warranted, &["observedState"])?, Value::Null));
    assert_eq!(
        texts(&episode, &["outcome", "indeterminatePredicates"])?,
        vec!["warranted".to_owned()]
    );
    // Residual uncertainty is stated in the envelope itself, not only behind hydration.
    for statements in [
        texts(&episode, &["residualUncertainty"])?,
        texts(&closed, &["degradation"])?,
    ] {
        assert!(
            statements
                .iter()
                .any(|line| line.contains("operator_asserted"))
        );
    }
    assert!(texts(&episode, &["stepReceipts"])?.contains(&"step:reconcile=completed".to_owned()));
    assert_eq!(causes(&episode)?, vec!["execution".to_owned()]);
    assert!(agent.active_plans()?.is_empty());
    // Episodes are immutable: closing again returns the published episode unchanged.
    let (code, again, episode) = agent.close(&plan_id)?;
    assert_eq!(code, Some(0));
    let (_, second) = episode.ok_or("episode")?;
    assert_eq!(first, second);
    assert!(
        texts(&again, &["degradation"])?
            .iter()
            .any(|line| line.contains("already closed")),
        "{again:?}"
    );
    assert_eq!(relay.connections(), 1);
    Ok(())
}

#[test]
fn a_relay_accepted_alert_attested_not_delivered_fails_its_obligation() -> TestResult {
    let (directory, event_id) = corroborated_event("reconcile-failed")?;
    let agent = Agent::open(&directory)?;
    let relay = Relay::spawn(Some(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"))?;
    let (plan_id, operation, code, committed) = dispatched(&agent, &event_id, &relay)?;
    assert_eq!(code, Some(0));
    assert_eq!(text(&committed, &["payload", "state"])?, "adapter_accepted");
    let evidence = ContentDigest::sha256(b"owner: nothing arrived on any device").to_text();
    let (_, preview) = reconcile(&agent, &operation, "not_delivered", &evidence, None)?;
    let approval = texts(&preview, &["proofPointers"])?[0].clone();
    let (code, failed) = reconcile(
        &agent,
        &operation,
        "not_delivered",
        &evidence,
        Some(&approval),
    )?;
    assert_eq!(code, Some(0));
    assert_eq!(text(&failed, &["payload", "state"])?, "failed");
    assert!(
        texts(&failed, &["degradation"])?
            .iter()
            .any(|line| line.contains("is failed")),
        "{failed:?}"
    );
    // The owner's adjudication of the event is advisory feedback; the episode cites it as one
    // more competing attribution, beside the adapter and external hypotheses.
    let (code, proposed) = agent.run(
        "feedback",
        &[
            "--session",
            agent.session.as_str(),
            "--target",
            &format!("event:{event_id}"),
            "--kind",
            "adjudication",
            "--statement",
            "The mirrored camera saw a delivery driver, not an intruder.",
            "--supporting",
            &evidence,
        ],
    )?;
    assert_eq!(code, Some(0), "{proposed:?}");
    let (code, closed, episode) = agent.close(&plan_id)?;
    assert_eq!(code, Some(0), "{closed:?}");
    let (episode, _) = episode.ok_or("episode")?;
    assert_eq!(text(&episode, &["outcome", "state"])?, "failed");
    assert_eq!(
        text(
            prediction(&episode, "prediction:delivery")?,
            &["observedState"]
        )?,
        "failed"
    );
    assert_eq!(
        causes(&episode)?,
        vec![
            "adapter".to_owned(),
            "external".to_owned(),
            "hypothesis".to_owned()
        ]
    );
    assert!(agent.active_plans()?.is_empty());
    assert_eq!(relay.connections(), 1);
    Ok(())
}

#[test]
fn a_plan_withdrawn_before_preparation_closes_and_can_never_be_prepared() -> TestResult {
    let (directory, event_id) = corroborated_event("withdraw")?;
    let agent = Agent::open(&directory)?;
    let relay = Relay::spawn(Some(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"))?;
    let (_, planned) = agent.plan(&event_id, relay.address, &[])?;
    let (plan_id, plan_approval, _) = approvals(&planned)?;
    assert_eq!(agent.active_plans()?, vec![plan_id.clone()]);

    // Closing a compiled, never-prepared plan withdraws it: an immutable episode, no effect.
    let (code, closed, episode) = agent.close(&plan_id)?;
    assert_eq!(code, Some(0), "{closed:?}");
    let (episode, _) = episode.ok_or("episode")?;
    assert_eq!(text(&episode, &["outcome", "state"])?, "cancelled");
    assert!(
        texts(&episode, &["outcome", "successPredicates"])?.contains(&"not_prepared".to_owned())
    );
    assert!(texts(&episode, &["stepReceipts"])?.contains(&"step:prepare=not_started".to_owned()));
    assert!(texts(&episode, &["effectReceipts"])?.is_empty());
    assert!(texts(&episode, &["obligations"])?.is_empty());
    assert!(matches!(
        field(prediction(&episode, "prediction:delivery")?, &["error"])?,
        Value::Null
    ));
    assert!(agent.active_plans()?.is_empty());

    // The withdrawn plan is final: its exact approval never prepares it.
    let (code, refused) = agent.plan(&event_id, relay.address, &["--approve", &plan_approval])?;
    assert_eq!(code, Some(5), "{refused:?}");
    assert_eq!(
        text(&refused, &["errorId"])?,
        "ERR-OP-PRECONDITION-FAILED-001"
    );
    assert_eq!(relay.connections(), 0);
    Ok(())
}

#[test]
fn a_changed_case_revision_refuses_exact_preview_approval_before_preparation() -> TestResult {
    let (directory, event_id) = corroborated_event("preview-case-invalidated")?;
    let agent = Agent::open(&directory)?;
    let opened = agent.open_case()?;
    let expected = text(&opened, &["decisionFingerprint"])?;
    let relay = Relay::spawn(Some(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"))?;
    let effects = agent.root.join("effects/journal.fssj");
    let journal = fs::read(&effects)?;
    let (code, planned) = agent.plan(&event_id, relay.address, &["--case", CASE])?;
    assert_eq!(code, Some(0), "{planned:?}");
    let (_, approval, _) = approvals(&planned)?;
    let operation = operation_of(&planned)?;
    assert_eq!(fs::read(&effects)?, journal);

    let (code, changed) = agent.run(
        "investigate",
        &[
            "--session",
            &agent.session,
            "--transition",
            "activate",
            "--case",
            CASE,
            "--expected",
            expected,
        ],
    )?;
    assert_eq!(code, Some(0), "{changed:?}");
    assert_ne!(text(&changed, &["decisionFingerprint"])?, expected);

    // The same event/route approval cannot publish a different case witness under the
    // existing plan identity. Detect that conflict before preparing any durable operation.
    let (code, refused) = agent.plan(
        &event_id,
        relay.address,
        &["--case", CASE, "--approve", &approval],
    )?;
    assert_eq!(code, Some(5), "{refused:?}");
    assert_eq!(
        text(&refused, &["errorId"])?,
        "ERR-OP-PRECONDITION-FAILED-001"
    );
    assert_eq!(fs::read(&effects)?, journal);
    assert_eq!(relay.connections(), 0);
    assert_eq!(relay.requests()?, 0);

    let (code, absent) = agent.run("wait", &["--operation", &operation, "--deadline-ms", "1"])?;
    assert_eq!(code, Some(5), "{absent:?}");
    assert_eq!(
        text(&absent, &["errorId"])?,
        "ERR-OP-PRECONDITION-FAILED-001"
    );
    assert_eq!(field(&absent, &["payload"])?, &Value::Null);
    assert_eq!(fs::read(&effects)?, journal);
    Ok(())
}

#[test]
fn a_changed_case_revision_invalidates_a_prepared_commit_before_relay_io() -> TestResult {
    let (directory, event_id) = corroborated_event("case-invalidated")?;
    let agent = Agent::open(&directory)?;
    let opened = agent.open_case()?;
    let expected = text(&opened, &["decisionFingerprint"])?;
    let relay = Relay::spawn(Some(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"))?;
    let (code, planned) = agent.plan(&event_id, relay.address, &["--case", CASE])?;
    assert_eq!(code, Some(0), "{planned:?}");
    let (plan_id, approval, _) = approvals(&planned)?;
    let (code, prepared) = agent.plan(
        &event_id,
        relay.address,
        &["--case", CASE, "--approve", &approval],
    )?;
    assert_eq!(code, Some(0), "{prepared:?}");
    let (prepared_id, _, dispatch) = approvals(&prepared)?;
    assert_eq!(prepared_id, plan_id);
    let operation = operation_of(&prepared)?;
    let effects = agent.root.join("effects/journal.fssj");
    let journal = fs::read(&effects)?;

    // The event, route, approval and prepared operation still match, but this exact case
    // revision no longer supports the plan. No irreversible commitment may be recorded.
    let (code, changed) = agent.cancel_case(expected)?;
    assert_eq!(code, Some(0), "{changed:?}");
    assert_ne!(text(&changed, &["decisionFingerprint"])?, expected);
    let (code, refused) = agent.run("commit", &["--plan", &plan_id, "--approve", &dispatch])?;
    assert_eq!(code, Some(5), "{refused:?}");
    assert_eq!(
        text(&refused, &["errorId"])?,
        "ERR-AGENT-AFFORDANCE-INVALIDATED-001"
    );
    assert_eq!(fs::read(&effects)?, journal);
    assert_eq!(relay.connections(), 0);
    assert_eq!(relay.requests()?, 0);
    let (code, waited) = agent.run("wait", &["--operation", &operation, "--deadline-ms", "1"])?;
    assert_eq!(code, Some(0), "{waited:?}");
    assert_eq!(text(&waited, &["payload", "state"])?, "prepared");
    assert_eq!(fs::read(&effects)?, journal);
    Ok(())
}

#[test]
fn a_rebased_session_cannot_commit_a_plan_from_its_old_anchor() -> TestResult {
    let (directory, event_id) = corroborated_event("plan-anchor-invalidated")?;
    let agent = Agent::open(&directory)?;
    let relay = Relay::spawn(Some(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"))?;
    let (code, planned) = agent.plan(&event_id, relay.address, &[])?;
    assert_eq!(code, Some(0), "{planned:?}");
    let (plan_id, approval, _) = approvals(&planned)?;
    let (code, prepared) = agent.plan(&event_id, relay.address, &["--approve", &approval])?;
    assert_eq!(code, Some(0), "{prepared:?}");
    let (_, _, dispatch) = approvals(&prepared)?;
    let operation = operation_of(&prepared)?;
    let effects = agent.root.join("effects/journal.fssj");
    let journal = fs::read(&effects)?;

    agent.resume_after_new_evidence(&directory)?;
    let (code, refused) = agent.run("commit", &["--plan", &plan_id, "--approve", &dispatch])?;
    assert_eq!(code, Some(5), "{refused:?}");
    assert_eq!(
        text(&refused, &["errorId"])?,
        "ERR-AGENT-AFFORDANCE-INVALIDATED-001"
    );
    assert_eq!(fs::read(&effects)?, journal);
    assert_eq!(relay.connections(), 0);
    assert_eq!(relay.requests()?, 0);
    let (code, waited) = agent.run("wait", &["--operation", &operation, "--deadline-ms", "1"])?;
    assert_eq!(code, Some(0), "{waited:?}");
    assert_eq!(text(&waited, &["payload", "state"])?, "prepared");
    assert_eq!(fs::read(&effects)?, journal);
    Ok(())
}

#[test]
fn dispatch_holds_its_case_and_session_witnesses_until_the_receipt_is_durable() -> TestResult {
    let (directory, event_id) = corroborated_event("dispatch-witness-ownership")?;
    let agent = Agent::open(&directory)?;
    let opened = agent.open_case()?;
    let expected = text(&opened, &["decisionFingerprint"])?;
    let relay = Relay::spawn_with_gate(
        Some(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"),
        true,
    )?;
    // Competing real CLI commands must have time to run while the explicit relay barrier is
    // held. This is still a single native attempt with a fixed, approved 30-second deadline.
    let (code, planned) =
        agent.plan_with_deadline(&event_id, relay.address, "30000", &["--case", CASE])?;
    assert_eq!(code, Some(0), "{planned:?}");
    let (plan_id, approval, _) = approvals(&planned)?;
    let (code, prepared) = agent.plan_with_deadline(
        &event_id,
        relay.address,
        "30000",
        &["--case", CASE, "--approve", &approval],
    )?;
    assert_eq!(code, Some(0), "{prepared:?}");
    let (_, _, dispatch_approval) = approvals(&prepared)?;
    let operation = operation_of(&prepared)?;
    let mut dispatch = RunningFss::spawn(&agent.args(
        "commit",
        &["--plan", &plan_id, "--approve", &dispatch_approval],
    ))?;
    let arrival_deadline = Instant::now() + Duration::from_secs(10);
    while relay.requests()? == 0 {
        assert!(
            dispatch.running()?,
            "commit exited before the loopback request arrived"
        );
        assert!(
            Instant::now() < arrival_deadline,
            "loopback request did not arrive"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    let retained = relay
        .requests
        .lock()
        .map_err(|_| "relay log poisoned")?
        .first()
        .cloned()
        .ok_or("loopback request missing")?;
    assert!(
        complete(&retained),
        "the barrier must retain a complete HTTP request"
    );
    assert!(dispatch.running()?);
    let effects = agent.root.join("effects/journal.fssj");
    let committed_journal = fs::read(&effects)?;
    let sessions = agent.root.join("agent/sessions/journal.fssj");
    let session_pin = agent.root.join("agent/sessions/ROOT");
    let held_session = fs::read(&sessions)?;
    let held_pin = fs::read(&session_pin)?;

    // Both cognition mutation and session publication must observe the same held journal,
    // while the relay has the request but has supplied no acknowledgement.
    let (code, refused) = agent.cancel_case(expected)?;
    assert_eq!(code, Some(5), "{refused:?}");
    assert_eq!(
        text(&refused, &["errorId"])?,
        "ERR-AGENT-SESSION-STORE-LOCKED-001"
    );
    let (code, handoff) = agent.run("handoff", &["--session", &agent.session])?;
    assert_eq!(code, Some(5), "{handoff:?}");
    assert_eq!(
        text(&handoff, &["errorId"])?,
        "ERR-AGENT-SESSION-STORE-LOCKED-001"
    );
    assert!(
        dispatch.running()?,
        "dispatch must still own the retained request"
    );
    assert_eq!(fs::read(&sessions)?, held_session);
    assert_eq!(fs::read(&session_pin)?, held_pin);
    assert_eq!(fs::read(&effects)?, committed_journal);

    relay.release();
    let completed = dispatch.finish()?;
    success(&completed);
    let stdout = String::from_utf8(completed.stdout)?;
    let (code, receipt) = agent.answer(completed.status.code(), &stdout)?;
    assert_eq!(code, Some(0), "{receipt:?}");
    assert_eq!(text(&receipt, &["payload", "state"])?, "adapter_accepted");
    assert_eq!(text(&receipt, &["payload", "operationId"])?, operation);
    let accepted_journal = fs::read(&effects)?;
    assert_ne!(accepted_journal, committed_journal);
    assert_eq!(relay.connections(), 1);

    // Ownership ends only after dispatch records its outcome. The exact mutation that was
    // blocked now succeeds; a fresh commit process reports its durable receipt unchanged.
    let (code, changed) = agent.cancel_case(expected)?;
    assert_eq!(code, Some(0), "{changed:?}");
    assert_ne!(text(&changed, &["decisionFingerprint"])?, expected);
    let (code, after_case) = agent.run(
        "commit",
        &["--plan", &plan_id, "--approve", &dispatch_approval],
    )?;
    assert_eq!(code, Some(0), "{after_case:?}");
    assert_eq!(
        field(&after_case, &["payload"])?,
        field(&receipt, &["payload"])?
    );
    assert_eq!(fs::read(&effects)?, accepted_journal);
    assert_eq!(relay.connections(), 1);

    // Recover again after both witnesses have changed. A receipt observation cannot become
    // permission to reuse the stale case or the old session anchor for another dispatch.
    agent.resume_after_new_evidence(&directory)?;
    let (code, after_resume) = agent.run(
        "commit",
        &["--plan", &plan_id, "--approve", &dispatch_approval],
    )?;
    assert_eq!(code, Some(0), "{after_resume:?}");
    assert_eq!(
        field(&after_resume, &["payload"])?,
        field(&receipt, &["payload"])?
    );
    assert_eq!(fs::read(&effects)?, accepted_journal);
    assert_eq!(relay.connections(), 1);
    assert_eq!(relay.requests()?, 1);
    Ok(())
}

#[test]
fn enrolled_mission_requires_terminal_episode_and_retains_handoff_proof() -> TestResult {
    let (directory, event_id) = corroborated_event("mission-cancelled")?;
    let agent = Agent::open(&directory)?;
    let open_args = [
        "session".into(),
        "open".into(),
        "--json".into(),
        "--root".into(),
        agent.root.as_os_str().to_owned(),
        "--mission".into(),
        "Protect the door.".into(),
        "--objective".into(),
        "Alert the owner on a corroborated entry.".into(),
    ];
    let (code, legacy_stdout) = run_fss(&open_args)?;
    let (code, legacy) = agent.answer(code, &legacy_stdout)?;
    assert_eq!(code, Some(0), "{legacy_stdout}");
    assert_eq!(text(&legacy, &["sessionId"])?, agent.session);
    assert_eq!(
        field(&legacy, &["payload", "missionRevision"])?,
        &Value::Number("0".to_owned())
    );
    assert_eq!(
        field(&legacy, &["payload", "decisionDeadlineNs"])?,
        &Value::Null
    );
    // No dispatch is made: a refused loopback endpoint still provides a concrete plan route.
    let relay: SocketAddr = "127.0.0.1:9".parse()?;
    let ledger_path = agent.root.join("ledger/journal.fssj");
    let effects_path = agent.root.join("effects/journal.fssj");
    let sessions_path = agent.root.join("agent/sessions/journal.fssj");
    let session_pin = agent.root.join("agent/sessions/ROOT");
    let evidence_before = fs::read(&ledger_path)?;
    let effects_before = fs::read(&effects_path)?;

    let (code, planned) = agent.plan(&event_id, relay, &[])?;
    assert_eq!(code, Some(0), "{planned:?}");
    let (plan_id, plan_approval, _) = approvals(&planned)?;
    let operation = operation_of(&planned)?;
    assert_eq!(fs::read(&effects_path)?, effects_before);
    // Exercise the complete canonical signed-128-bit deadline, without narrowing to u64,
    // floating point, or the current wall clock in the command or its handoff rendering.
    let deadline = i128::MAX.to_string();
    let bind_args = agent.args(
        "plan",
        &[
            "--session",
            &agent.session,
            "--mission-bind",
            &plan_id,
            "--mission-deadline-ns",
            &deadline,
        ],
    );
    let (code, bound_stdout) = run_fss(&bind_args)?;
    let (code, bound) = agent.answer(code, &bound_stdout)?;
    assert_eq!(code, Some(0), "{bound_stdout}");
    assert_eq!(
        text(&bound, &["payloadSchema"])?,
        "fss.agent_control_plan.v1"
    );
    assert_eq!(field(&bound, &["payload"])?, field(&planned, &["payload"])?);
    assert!(
        texts(&bound, &["degradation"])?
            .iter()
            .any(|line| line.contains(" is awaiting_evidence at ")),
        "{bound:?}"
    );
    let initial_head = texts(&bound, &["proofPointers"])?[0].clone();
    ContentDigest::parse(&initial_head)?;
    let bound_journal = fs::read(&sessions_path)?;
    let bound_pin = fs::read(&session_pin)?;
    let (code, retry_stdout) = run_fss(&bind_args)?;
    assert_eq!(code, Some(0), "{retry_stdout}");
    assert_eq!(
        retry_stdout, bound_stdout,
        "a cold exact bind retry is stable"
    );
    assert_eq!(fs::read(&sessions_path)?, bound_journal);
    assert_eq!(fs::read(&session_pin)?, bound_pin);
    assert_eq!(fs::read(&ledger_path)?, evidence_before);
    assert_eq!(fs::read(&effects_path)?, effects_before);

    // At this unchanged opening token, a fresh exact open retry returns the same admitted
    // session and immutable workspace, with the now-enrolled public mission metadata.
    let (code, oriented_stdout) = run_fss(&open_args)?;
    let (code, oriented) = agent.answer(code, &oriented_stdout)?;
    assert_eq!(code, Some(0), "{oriented_stdout}");
    assert_eq!(text(&oriented, &["sessionId"])?, agent.session);
    assert_eq!(
        field(&oriented, &["workspaceRevision"])?,
        field(&legacy, &["workspaceRevision"])?
    );
    assert_eq!(
        field(&oriented, &["payload", "missionRevision"])?,
        &Value::Number("0".to_owned())
    );
    assert_eq!(
        field(&oriented, &["payload", "decisionDeadlineNs"])?,
        &Value::Number(deadline.clone())
    );
    let summary = field(&oriented, &["payload", "contextPack", "items"])?
        .array()
        .ok_or("bound context items")?
        .iter()
        .find(|item| text(item, &["itemId"]).is_ok_and(|id| id == "context:frame:summary"))
        .ok_or("protected mission summary")?;
    assert!(text(summary, &["content"])?.contains(&format!(
        "Retained mission revision 0: awaiting_evidence at {initial_head}; current assessment"
    )));
    assert_eq!(fs::read(&sessions_path)?, bound_journal);
    assert_eq!(fs::read(&session_pin)?, bound_pin);

    // Recover an exact immutable mission head after a lost command response using only a
    // read. The public revision number alone cannot supply the next assessment's CAS digest.
    let recover_head = |expected: &str, revision: u64, freshness: &str| -> TestResult<String> {
        let before = [
            fs::read(&sessions_path)?,
            fs::read(&session_pin)?,
            fs::read(&ledger_path)?,
            fs::read(&effects_path)?,
        ];
        let (code, recovered) = agent.run("orient", &["--session", &agent.session])?;
        assert_eq!(code, Some(0), "{recovered:?}");
        assert_eq!(text(&recovered, &["operationId"])?, "AOP-003");
        assert_eq!(text(&recovered, &["sessionId"])?, agent.session);
        assert_eq!(field(&recovered, &["idempotencyKey"])?, &Value::Null);
        let head = texts(&recovered, &["proofPointers"])?[0].clone();
        assert_eq!(
            head, expected,
            "the first proof is the retained mission revision"
        );
        ContentDigest::parse(&head)?;
        assert_eq!(
            field(&recovered, &["payload", "missionRevision"])?,
            &Value::Number(revision.to_string())
        );
        assert_eq!(
            field(&recovered, &["payload", "decisionDeadlineNs"])?,
            field(&oriented, &["payload", "decisionDeadlineNs"])?
        );
        for key in [
            "objectiveId",
            "source",
            "desiredOutcome",
            "successPredicates",
            "failurePredicates",
            "stopConditions",
            "terminalProof",
        ] {
            assert_eq!(
                field(&recovered, &["payload", "objectiveContract", key])?,
                field(&oriented, &["payload", "objectiveContract", key])?,
                "recovering the current head must preserve the enrolled {key}"
            );
        }
        let summary = field(&recovered, &["payload", "contextPack", "items"])?
            .array()
            .ok_or("recovered mission context")?
            .iter()
            .find(|item| text(item, &["itemId"]).is_ok_and(|id| id == "context:frame:summary"))
            .ok_or("recovered protected mission summary")?;
        let summary = text(summary, &["content"])?;
        assert!(summary.contains("Protect the door."));
        assert!(summary.contains("Alert the owner on a corroborated entry."));
        assert!(summary.contains(expected));
        assert!(summary.contains(freshness), "{summary}");
        assert_eq!(
            [
                fs::read(&sessions_path)?,
                fs::read(&session_pin)?,
                fs::read(&ledger_path)?,
                fs::read(&effects_path)?,
            ],
            before,
            "recovering a mission head cannot write or repair agent/effect/evidence history"
        );
        Ok(head)
    };
    let recovered_initial_head = recover_head(&initial_head, 0, "current assessment")?;

    // Enrollment is cognition, so it must preserve the exact already-approved plan witness.
    // Prepare after binding rather than binding an already-prepared operation.
    let (code, prepared) = agent.plan(&event_id, relay, &["--approve", &plan_approval])?;
    assert_eq!(code, Some(0), "{prepared:?}");
    assert_eq!(text(&prepared, &["payload", "planId"])?, plan_id);
    assert_eq!(operation_of(&prepared)?, operation);
    assert_ne!(fs::read(&effects_path)?, effects_before);
    let (code, preview) = agent.run("cancel", &["--operation", &operation])?;
    assert_eq!(code, Some(0), "{preview:?}");
    assert_eq!(text(&preview, &["payload", "state"])?, "prepared");
    let cancel_approval = texts(&preview, &["proofPointers"])?[0].clone();
    let (code, cancelled) = agent.run(
        "cancel",
        &["--operation", &operation, "--approve", &cancel_approval],
    )?;
    assert_eq!(code, Some(0), "{cancelled:?}");
    assert_eq!(text(&cancelled, &["payload", "state"])?, "cancelled");
    let evidence_after_cancel = fs::read(&ledger_path)?;
    let effects_after_cancel = fs::read(&effects_path)?;

    // A cancellation receipt alone is insufficient: the enrolled plan's immutable execution
    // episode must agree before its lifecycle can become terminal.
    let (code, pending) = agent.run(
        "plan",
        &[
            "--session",
            &agent.session,
            "--mission-assess",
            &plan_id,
            "--expected-mission",
            &recovered_initial_head,
        ],
    )?;
    assert_eq!(code, Some(0), "{pending:?}");
    assert!(
        texts(&pending, &["degradation"])?
            .iter()
            .any(|line| line.contains(" is awaiting_evidence at ")),
        "{pending:?}"
    );
    let pending_head = texts(&pending, &["proofPointers"])?[0].clone();
    assert_ne!(pending_head, initial_head);
    assert_eq!(fs::read(&ledger_path)?, evidence_after_cancel);
    assert_eq!(fs::read(&effects_path)?, effects_after_cancel);

    let (code, closed, episode) = agent.close(&plan_id)?;
    assert_eq!(code, Some(0), "{closed:?}");
    let (episode, _) = episode.ok_or("cancelled execution episode missing")?;
    assert_eq!(text(&episode, &["outcome", "state"])?, "cancelled");
    let assess_args = agent.args(
        "plan",
        &[
            "--session",
            &agent.session,
            "--mission-assess",
            &plan_id,
            "--expected-mission",
            &pending_head,
        ],
    );
    let (code, terminal_stdout) = run_fss(&assess_args)?;
    let (code, terminal) = agent.answer(code, &terminal_stdout)?;
    assert_eq!(code, Some(0), "{terminal_stdout}");
    assert_eq!(
        text(&terminal, &["payloadSchema"])?,
        "fss.agent_control_plan.v1"
    );
    assert_eq!(
        field(&terminal, &["payload"])?,
        field(&planned, &["payload"])?
    );
    assert!(
        texts(&terminal, &["degradation"])?
            .iter()
            .any(|line| line.contains(" is cancelled at ")),
        "{terminal:?}"
    );
    assert!(
        texts(&terminal, &["degradation"])?
            .iter()
            .any(|line| line == "This retained mission revision is current for this projection."),
        "{terminal:?}"
    );
    let terminal_head = texts(&terminal, &["proofPointers"])?[0].clone();
    assert_ne!(terminal_head, pending_head);
    let terminal_journal = fs::read(&sessions_path)?;
    let terminal_pin = fs::read(&session_pin)?;
    let (code, retry_stdout) = run_fss(&assess_args)?;
    assert_eq!(code, Some(0), "{retry_stdout}");
    assert_eq!(
        retry_stdout, terminal_stdout,
        "the exact predecessor request must recover its already-retained terminal result"
    );
    assert_eq!(fs::read(&sessions_path)?, terminal_journal);
    assert_eq!(fs::read(&session_pin)?, terminal_pin);
    assert_eq!(fs::read(&ledger_path)?, evidence_after_cancel);
    assert_eq!(fs::read(&effects_path)?, effects_after_cancel);

    let recovered_terminal_head = recover_head(&terminal_head, 2, "current assessment")?;
    let (code, recovered_retry) = agent.run(
        "plan",
        &[
            "--session",
            &agent.session,
            "--mission-assess",
            &plan_id,
            "--expected-mission",
            &recovered_terminal_head,
        ],
    )?;
    assert_eq!(code, Some(0), "{recovered_retry:?}");
    assert_eq!(
        texts(&recovered_retry, &["proofPointers"])?[0],
        terminal_head
    );
    assert_eq!(
        field(&recovered_retry, &["payload"])?,
        field(&terminal, &["payload"])?
    );
    assert_eq!(fs::read(&sessions_path)?, terminal_journal);
    assert_eq!(fs::read(&session_pin)?, terminal_pin);
    assert_eq!(fs::read(&ledger_path)?, evidence_after_cancel);
    assert_eq!(fs::read(&effects_path)?, effects_after_cancel);

    let (code, handed) = agent.run("handoff", &["--session", &agent.session])?;
    assert_eq!(code, Some(0), "{handed:?}");
    for family in ["success", "failure", "stop"] {
        assert!(
            !texts(&handed, &["payload", "criteria", family])?.is_empty(),
            "the explicitly enrolled {family} criteria must survive handoff"
        );
    }
    assert!(
        texts(&handed, &["payload", "criteria", "stop"])?
            .iter()
            .any(|line| line.contains(&deadline)),
        "the exact i128 evidence-clock deadline must survive the public contract"
    );
    assert!(text(&handed, &["payload", "objective"])?.contains(&plan_id));
    assert!(
        texts(&handed, &["payload", "proofPointers"])?
            .iter()
            .any(|pointer| pointer.starts_with("fss://proof/sha256:")),
        "the executable criteria must retain their typed proof pointers"
    );
    assert!(
        texts(&handed, &["degradation"])?
            .iter()
            .all(|line| !line.contains("The handoff carries no success, failure, or stop criteria")),
        "an enrolled profile must not emit the legacy missing-criteria warning"
    );

    // The mission revision is a verified child of the actual root-last handoff graph, not
    // merely a digest printed in a response. It retains the exact terminal head assessed above.
    let pointers = texts(&handed, &["proofPointers"])?;
    assert!(pointers.contains(&terminal_head));
    let publication_dir = agent.root.join("agent/publications");
    let manifest =
        fss_object::ObjectManifest::from_canonical_bytes(&fss_publication::read_verified(
            &publication_dir,
            ContentDigest::parse(&pointers[1])?,
            1 << 20,
        )?)?;
    let revision_digest = ContentDigest::parse(&terminal_head)?;
    assert!(manifest.children().contains(&revision_digest));
    let retained_revision =
        fss_publication::read_verified(&publication_dir, revision_digest, 64 * 1024)?;
    assert_eq!(ContentDigest::sha256(&retained_revision), revision_digest);

    // Effects changed the opening token, so explicitly resume this same session instead of
    // opening a new identity. Its SituationCapsule exposes the retained assessed revision and
    // exact numeric deadline; lifecycle state and freshness remain protected context.
    let (code, resumed_stdout) = run_fss(&[
        "session".into(),
        "resume".into(),
        "--json".into(),
        "--root".into(),
        agent.root.as_os_str().to_owned(),
        "--handoff".into(),
        text(&handed, &["payload", "handoffId"])?.into(),
    ])?;
    let (code, resumed) = agent.answer(code, &resumed_stdout)?;
    assert_eq!(code, Some(0), "{resumed_stdout}");
    assert_eq!(text(&resumed, &["sessionId"])?, agent.session);
    assert_eq!(
        field(&resumed, &["payload", "missionRevision"])?,
        &Value::Number("2".to_owned())
    );
    assert_eq!(
        field(&resumed, &["payload", "decisionDeadlineNs"])?,
        &Value::Number(deadline)
    );
    let summary = field(&resumed, &["payload", "contextPack", "items"])?
        .array()
        .ok_or("resumed context items")?
        .iter()
        .find(|item| text(item, &["itemId"]).is_ok_and(|id| id == "context:frame:summary"))
        .ok_or("resumed protected mission summary")?;
    assert!(text(summary, &["content"])?.contains(&format!(
        "Retained mission revision 2: cancelled at {terminal_head}; current assessment"
    )));
    assert_eq!(fs::read(&ledger_path)?, evidence_after_cancel);
    assert_eq!(fs::read(&effects_path)?, effects_after_cancel);

    // New unsettled agent work changes closure without moving evidence or effect history.
    // The terminal revision remains immutable, but a ControlPlan-only response must explicitly
    // disclose that its terminal result is historical instead of implying current completion.
    agent.open_case()?;
    let journal_with_case = fs::read(&sessions_path)?;
    let pin_with_case = fs::read(&session_pin)?;
    let recovered_historical_head = recover_head(
        &terminal_head,
        2,
        "historical assessment; current lifecycle is unassessed",
    )?;
    let historical_args = agent.args(
        "plan",
        &[
            "--session",
            &agent.session,
            "--mission-assess",
            &plan_id,
            "--expected-mission",
            &recovered_historical_head,
        ],
    );
    let (code, historical_stdout) = run_fss(&historical_args)?;
    let (code, historical) = agent.answer(code, &historical_stdout)?;
    assert_eq!(code, Some(0), "{historical_stdout}");
    assert_eq!(texts(&historical, &["proofPointers"])?[0], terminal_head);
    assert_eq!(
        field(&historical, &["payload"])?,
        field(&planned, &["payload"])?
    );
    let degradation = texts(&historical, &["degradation"])?;
    assert!(
        degradation.iter().any(|line| {
            line.contains("historical retained mission revision")
                && line.contains("current mission lifecycle is unassessed")
        }),
        "{historical:?}"
    );
    assert!(degradation.iter().all(|line| {
        line != "This retained mission revision is current for this projection."
            && !line.contains("The deployment has moved beyond the session anchor.")
    }));
    assert_eq!(
        field(&historical, &["inputAnchor"])?,
        field(&resumed, &["inputAnchor"])?
    );
    let (code, retry_stdout) = run_fss(&historical_args)?;
    assert_eq!(code, Some(0), "{retry_stdout}");
    assert_eq!(retry_stdout, historical_stdout);
    assert_eq!(fs::read(&sessions_path)?, journal_with_case);
    assert_eq!(fs::read(&session_pin)?, pin_with_case);
    assert_eq!(fs::read(&ledger_path)?, evidence_after_cancel);
    assert_eq!(fs::read(&effects_path)?, effects_after_cancel);
    Ok(())
}

fn learning_quote(value: &str) -> String {
    format!("\"{}\"", fss_cli::escape_json_str(value))
}

fn learning_arguments(session: &str, plan: &str, supporting: &str, statement: &str) -> String {
    format!(
        r#"{{"session":{},"target":{},"kind":"policy_candidate","statement":{},"supporting":[{}],"disposition":"create_learning_proposal"}}"#,
        learning_quote(session),
        learning_quote(&format!("plan:{plan}")),
        learning_quote(statement),
        learning_quote(supporting),
    )
}

fn learning_args(agent: &Agent, plan: &str, supporting: &str, statement: &str) -> Vec<OsString> {
    agent.args(
        "feedback",
        &[
            "--session",
            &agent.session,
            "--target",
            &format!("plan:{plan}"),
            "--kind",
            "policy_candidate",
            "--statement",
            statement,
            "--supporting",
            supporting,
            "--disposition",
            "create_learning_proposal",
        ],
    )
}

fn learning_mcp_wire(agent: &Agent, principal: &str, arguments: &str) -> TestResult<Value> {
    learning_mcp_tool_wire(agent, principal, "feedback", arguments)
}

fn learning_mcp_tool_wire(
    agent: &Agent,
    principal: &str,
    tool: &str,
    arguments: &str,
) -> TestResult<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_fss-mcp"))
        .arg("--root")
        .arg(&agent.root)
        .arg("--principal")
        .arg(principal)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut input = child.stdin.take().ok_or("learning MCP stdin")?;
    writeln!(
        input,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2025-06-18","capabilities":{{}},"clientInfo":{{"name":"episode-learning-contract","version":"1"}}}}}}"#
    )?;
    writeln!(
        input,
        r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#
    )?;
    writeln!(
        input,
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":{},"arguments":{arguments}}}}}"#,
        learning_quote(tool)
    )?;
    drop(input);
    let output = child.wait_with_output()?;
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let mut replies = String::from_utf8(output.stdout)?
        .lines()
        .map(|line| parse(line).map_err(Into::into))
        .collect::<TestResult<Vec<Value>>>()?;
    assert_eq!(replies.len(), 2);
    assert_eq!(
        text(&replies[0], &["result", "protocolVersion"])?,
        "2025-06-18"
    );
    let reply = replies.pop().ok_or("learning MCP reply")?;
    assert_eq!(field(&reply, &["id"])?.integer(), Some(2));
    Ok(reply)
}

fn learning_mcp(
    agent: &Agent,
    principal: &str,
    arguments: &str,
    failed: bool,
) -> TestResult<String> {
    let wire = learning_mcp_wire(agent, principal, arguments)?;
    assert_eq!(field(&wire, &["result", "isError"])?, &Value::Bool(failed));
    let content = field(&wire, &["result", "content"])?
        .array()
        .ok_or("learning MCP content")?;
    assert_eq!(content.len(), 1);
    assert_eq!(text(&content[0], &["type"])?, "text");
    let body = text(&content[0], &["text"])?.to_owned();
    let (_, response) = agent.answer(None, &body)?;
    assert_eq!(text(&response, &["operationId"])?, "AOP-013");
    Ok(body)
}

fn learning_tree(
    root: &Path,
    prefixes: &[&str],
) -> TestResult<std::collections::BTreeMap<PathBuf, ContentDigest>> {
    let mut pending: Vec<PathBuf> = prefixes.iter().map(|prefix| root.join(prefix)).collect();
    let mut files = std::collections::BTreeMap::new();
    while let Some(path) = pending.pop() {
        if !path.exists() {
            continue;
        }
        if path.is_dir() {
            for entry in fs::read_dir(path)? {
                pending.push(entry?.path());
            }
        } else {
            files.insert(
                path.strip_prefix(root)?.to_path_buf(),
                ContentDigest::sha256(&fs::read(path)?),
            );
        }
    }
    Ok(files)
}

fn learning_experiences(root: &Path) -> TestResult<Vec<ContentDigest>> {
    let directory = root.join("agent/publications");
    let objects = directory.join("spool/objects");
    let mut found = Vec::new();
    if !objects.exists() {
        return Ok(found);
    }
    for entry in fs::read_dir(objects)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name.len() != 64 || !name.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        let digest = ContentDigest::parse(&format!("sha256:{name}"))?;
        let bytes = fss_publication::read_verified(&directory, digest, 1 << 20)?;
        let mut decoder = fss_core::CanonicalDecoder::new(&bytes);
        if decoder
            .text()
            .is_ok_and(|schema| schema == fss_core::ExperienceCapsule::SCHEMA)
        {
            found.push(digest);
        }
    }
    found.sort();
    Ok(found)
}

fn learning_strings(decoder: &mut fss_core::CanonicalDecoder<'_>) -> TestResult<Vec<String>> {
    let count = decoder.u32()?;
    assert!(count <= 4096);
    (0..count).map(|_| Ok(decoder.text()?.to_owned())).collect()
}

fn retained_learning_candidate(
    agent: &Agent,
    digest: ContentDigest,
) -> TestResult<fss_core::LearningProposal> {
    use fss_core::{CanonicalEncode, LearningClass, LearningProposal};

    let bytes =
        fss_publication::read_verified(agent.root.join("agent/publications"), digest, 1 << 20)?;
    let mut decoder = fss_core::CanonicalDecoder::new(&bytes);
    assert_eq!(decoder.text()?, LearningProposal::SCHEMA);
    let id = decoder.text()?.to_owned();
    assert_eq!(decoder.text()?, "policy_review_candidate");
    let episode = decoder.text()?.to_owned();
    let statement = decoder.text()?.to_owned();
    let applicability = decoder.text()?.to_owned();
    let supporting = learning_strings(&mut decoder)?;
    let contradicting = learning_strings(&mut decoder)?;
    let counterexamples = learning_strings(&mut decoder)?;
    let confidence = decoder.u32()?;
    let helpful = i64::try_from(decoder.i128()?)?;
    let harmful = i64::try_from(decoder.i128()?)?;
    let validation = learning_strings(&mut decoder)?;
    assert_eq!(decoder.text()?, "captured");
    let review = if decoder.bool()? {
        Some(decoder.i128()?)
    } else {
        None
    };
    let expiry = if decoder.bool()? {
        Some(decoder.i128()?)
    } else {
        None
    };
    let revival = learning_strings(&mut decoder)?;
    let decision = decoder.text()?.to_owned();
    decoder.ensure_finished()?;
    let candidate = LearningProposal::record(
        id,
        LearningClass::PolicyReviewCandidate,
        episode,
        statement,
        applicability,
        supporting,
        contradicting,
        counterexamples,
        confidence,
        helpful,
        harmful,
        validation,
        review,
        expiry,
        revival,
        decision,
    )?;
    assert_eq!(candidate.try_canonical_bytes()?, bytes);
    Ok(candidate)
}

/// Captured learning is protected advisory context with original custody and unknown cost;
/// discovering a record never upgrades its claim or grants effect authority.
fn assert_learning_discovery(
    envelope: &Value,
    proposal: &fss_core::LearningProposal,
    experience_id: &str,
    pointers: &[String],
) -> TestResult {
    let items = field(envelope, &["payload", "contextPack", "items"])?
        .array()
        .ok_or("protected captured-learning context")?;
    let prefix = format!("Captured learning {}", proposal.proposal_id);
    let risk = items
        .iter()
        .find(|item| {
            text(item, &["kind"]).is_ok_and(|kind| kind == "at_risk")
                && text(item, &["content"]).is_ok_and(|content| content.starts_with(&prefix))
        })
        .ok_or("captured learning missing from protected risk context")?;
    let content = text(risk, &["content"])?;
    for required in [
        proposal.proposal_id.as_str(),
        proposal.source_episode_id.as_str(),
        proposal.class.as_str(),
        experience_id,
        "state=captured",
        "evidence=single_episode",
        "confidence=0/1000000",
        "helpful=0",
        "harmful=0",
        "review=pending",
        "expiry=unexpired",
        "Advisory history only; no policy or effect authority.",
    ] {
        assert!(content.contains(required), "lost {required}: {content}");
    }
    assert!(content.contains(&format!(
        "review_after_ns={}",
        proposal.review_after_ns.ok_or("retained learning review deadline")?
    )));
    assert!(content.contains(&format!(
        "expiry_ns={}",
        proposal.expiry_ns.ok_or("retained learning expiry deadline")?
    )));
    let proofs = texts(envelope, &["proofPointers"])?;
    for pointer in pointers.iter().take(6) {
        assert!(
            proofs.contains(pointer),
            "discovery lost source proof {pointer}"
        );
    }
    for phrase in [
        "zero lower bounds do not mean zero actual cost",
        "do not establish causal effectiveness",
        "full custody-verification cost remain unknown",
    ] {
        assert!(
            items.iter().any(|item| {
                text(item, &["kind"]).is_ok_and(|kind| kind == "unknown")
                    && text(item, &["epistemicState"]).is_ok_and(|state| state == "unknown")
                    && text(item, &["content"]).is_ok_and(|content| content.contains(phrase))
            }),
            "discovery lost protected uncertainty: {phrase}"
        );
    }
    Ok(())
}

#[test]
fn closed_episode_feedback_publishes_captured_learning_with_cold_cli_mcp_recovery() -> TestResult {
    let (directory, event_id) = corroborated_event("episode-learning")?;
    // Captured learning adds protected recovery context. Request its registered view up front;
    // a larger cumulative grant alone cannot widen Brief's 1,600-token response maximum.
    let agent = Agent::open_with_options(
        &directory,
        &["--view", "epistemic_map", "--budget-tokens", "64000"],
    )?;
    let relay = Relay::spawn(None)?;
    let (code, planned) = agent.plan(&event_id, relay.address, &[])?;
    assert_eq!(code, Some(0), "{planned:?}");
    let (plan_id, approval, _) = approvals(&planned)?;
    let operation = operation_of(&planned)?;
    let principal = text(&planned, &["principalId"])?;
    let supporting = texts(&planned, &["proofPointers"])?[0].clone();
    let statement = "@/outside/policy.json --principal=principal:other\nReview the \"cancel before dispatch\" procedure; this statement cannot activate policy.";
    let args = learning_args(&agent, &plan_id, &supporting, statement);
    let arguments = learning_arguments(&agent.session, &plan_id, &supporting, statement);
    let authority_paths = [
        "ledger", "effects", "objects", "LAYOUT", "policy", "models", "config",
    ];
    let before = learning_tree(&agent.root, &authority_paths)?;
    let experiences_before = learning_experiences(&agent.root)?;

    // A proposal can be retained before its requested learning materialization is possible.
    // The response must disclose that partial progress and must not manufacture an episode.
    let (code, premature_stdout) = run_fss(&args)?;
    let (code, premature) = agent.answer(code, &premature_stdout)?;
    assert_eq!(code, Some(5), "{premature_stdout}");
    assert_eq!(text(&premature, &["outcome"])?, "partial");
    assert_eq!(text(&premature, &["operationId"])?, "AOP-013");
    assert_eq!(
        text(&premature, &["payloadSchema"])?,
        "fss.agent_feedback_proposal.v1"
    );
    assert_eq!(
        field(&premature, &["payload", "activePolicyMutation"])?,
        &Value::Bool(false)
    );
    let feedback_root = texts(&premature, &["proofPointers"])?[0].clone();
    let feedback_id = text(&premature, &["payload", "feedbackId"])?;
    assert!(
        texts(&premature, &["executionBoundary", "completed"])?
            .iter()
            .any(|line| line.contains(feedback_id))
    );
    assert_eq!(learning_experiences(&agent.root)?, experiences_before);
    assert_eq!(learning_tree(&agent.root, &authority_paths)?, before);
    let premature_mcp = learning_mcp(&agent, principal, &arguments, true)?;
    let premature_mcp = parse(&premature_mcp)?;
    assert_eq!(text(&premature_mcp, &["outcome"])?, "partial");
    assert_eq!(texts(&premature_mcp, &["proofPointers"])?[0], feedback_root);

    let (code, prepared) = agent.plan(&event_id, relay.address, &["--approve", &approval])?;
    assert_eq!(code, Some(0), "{prepared:?}");
    let (code, preview) = agent.run("cancel", &["--operation", &operation])?;
    assert_eq!(code, Some(0), "{preview:?}");
    let cancel = texts(&preview, &["proofPointers"])?[0].clone();
    let (code, cancelled) =
        agent.run("cancel", &["--operation", &operation, "--approve", &cancel])?;
    assert_eq!(code, Some(0), "{cancelled:?}");
    let (code, closed, episode) = agent.close(&plan_id)?;
    assert_eq!(code, Some(0), "{closed:?}");
    let (episode, _) = episode.ok_or("learning source episode")?;
    assert_eq!(text(&episode, &["outcome", "state"])?, "cancelled");
    let episode_rendering = ContentDigest::parse(&texts(&closed, &["proofPointers"])?[1])?;
    let authority = learning_tree(&agent.root, &authority_paths)?;

    let (code, first_stdout) = run_fss(&args)?;
    let (code, first) = agent.answer(code, &first_stdout)?;
    assert_eq!(code, Some(0), "{first_stdout}");
    assert_eq!(text(&first, &["outcome"])?, "ok");
    assert_eq!(text(&first, &["operationId"])?, "AOP-013");
    assert_eq!(
        text(&first, &["payloadSchema"])?,
        "fss.experience_capsule.v1"
    );
    assert_eq!(text(&first, &["sessionId"])?, agent.session);
    assert_eq!(
        field(&first, &["payload", "missionId"])?,
        field(&planned, &["missionId"])?
    );
    assert_eq!(
        text(&first, &["payload", "evidenceStrength"])?,
        "single_episode"
    );
    assert!(text(&first, &["payload", "outcome"])?.contains("cancelled"));
    let Value::Number(confidence) = field(&first, &["payload", "confidence"])? else {
        return Err("experience confidence is not a number".into());
    };
    assert_eq!(confidence.parse::<f64>()?, 0.0);
    assert!(texts(&first, &["payload", "operations"])?.contains(&operation));
    assert_eq!(text(&first, &["epistemicState"])?, "unknown");
    assert_eq!(text(&first, &["completeness"])?, "partial");
    let uncertainty = texts(&first, &["payload", "missingEvidence"])?;
    assert!(
        uncertainty
            .iter()
            .any(|item| item.contains("zero lower bounds do not mean zero actual cost"))
    );
    assert!(
        uncertainty
            .iter()
            .any(|item| item.contains("do not establish causal effectiveness"))
    );
    let initial = field(&first, &["payload", "initialEpistemicMap"])?
        .array()
        .ok_or("experience initial epistemic map")?;
    for identity in ["unknown:learning-cost", "unknown:learning-efficacy"] {
        let statement = initial
            .iter()
            .find(|entry| text(entry, &["statementId"]).is_ok_and(|id| id == identity))
            .ok_or("mandatory canonical experience uncertainty")?;
        assert_eq!(text(statement, &["epistemicState"])?, "unknown");
        assert!(!texts(statement, &["basis"])?.is_empty());
    }
    for dimension in [
        "latencyMs",
        "tokens",
        "bytes",
        "modelCalls",
        "cpuMillis",
        "acceleratorMillis",
        "energyMilliJoules",
        "networkBytes",
        "storageOperations",
        "privacyExposure",
        "operatorAttentionSeconds",
    ] {
        let Value::Number(lower_bound) = field(&first, &["payload", "cost", dimension])? else {
            return Err("experience cost dimension is not a number".into());
        };
        assert_eq!(lower_bound.parse::<f64>()?, 0.0);
    }
    assert!(
        field(&first, &["payload", "candidateTemplates"])?
            .array()
            .ok_or("experience candidates")?
            .iter()
            .any(|candidate| {
                text(candidate, &["kind"]).is_ok_and(|kind| kind == "policy_proposal")
                    && text(candidate, &["content"]).is_ok_and(|content| content == statement)
            })
    );

    let pointers = texts(&first, &["proofPointers"])?;
    assert!(pointers.len() >= 7);
    let learning_root = ContentDigest::parse(&pointers[0])?;
    let experience_digest = ContentDigest::parse(&pointers[1])?;
    let proposal_digest = ContentDigest::parse(&pointers[2])?;
    let episode_root = ContentDigest::parse(&pointers[3])?;
    assert_eq!(pointers[4], feedback_root);
    assert_eq!(pointers[5], supporting);
    let publication = agent.root.join("agent/publications");
    let manifest = fss_object::ObjectManifest::from_canonical_bytes(
        &fss_publication::read_verified(&publication, learning_root, 1 << 20)?,
    )?;
    assert_eq!(manifest.metadata_digest(), Some(experience_digest));
    assert!(manifest.children().contains(&proposal_digest));
    let experience = fss_publication::read_verified(&publication, experience_digest, 1 << 20)?;
    let mut decoder = fss_core::CanonicalDecoder::new(&experience);
    assert_eq!(decoder.text()?, fss_core::ExperienceCapsule::SCHEMA);
    assert_eq!(decoder.text()?, text(&first, &["payload", "experienceId"])?);
    let source = fss_object::ObjectManifest::from_canonical_bytes(
        &fss_publication::read_verified(&publication, episode_root, 1 << 20)?,
    )?;
    assert!(source.children().contains(&episode_rendering));
    let source_episode_bytes = fss_publication::read_verified(
        &publication,
        source
            .metadata_digest()
            .ok_or("retained episode metadata")?,
        1 << 20,
    )?;
    let source_episode = fss_reference::deployment_session::episode::EpisodeRecord::from_bytes(
        &source_episode_bytes,
    )?;
    assert_eq!(
        &parse(&source_episode.episode.resource_use_json)?,
        field(&episode, &["resourceUse"])?,
        "the exact source measurements remain retained while the experience discloses lower bounds"
    );
    assert!(
        manifest
            .children()
            .contains(&ContentDigest::sha256(&source_episode_bytes))
    );
    for pointer in &pointers[4..6] {
        fss_object::ObjectManifest::from_canonical_bytes(&fss_publication::read_verified(
            &publication,
            ContentDigest::parse(pointer)?,
            1 << 20,
        )?)?;
    }
    let candidate = retained_learning_candidate(&agent, proposal_digest)?;
    assert_eq!(candidate.source_episode_id, text(&episode, &["episodeId"])?);
    assert_eq!(candidate.statement, statement);
    assert!(candidate.supporting_evidence.contains(&supporting));
    assert_eq!(candidate.confidence_numerator, 0);
    assert_eq!(candidate.helpful_outcomes, 0);
    assert_eq!(candidate.harmful_outcomes, 0);
    assert!(!candidate.required_validation.is_empty());
    assert!(!candidate.applicability_json.is_empty());
    assert_eq!(
        candidate.promotion_state,
        fss_core::PromotionState::Captured
    );
    assert_eq!(learning_tree(&agent.root, &authority_paths)?, authority);
    assert_eq!(relay.connections(), 0);

    let retained = learning_tree(&agent.root, &["agent/publications"])?;
    let (code, retry_stdout) = run_fss(&args)?;
    assert_eq!(code, Some(0), "{retry_stdout}");
    assert_eq!(
        retry_stdout, first_stdout,
        "cold CLI retry must recover the exact result"
    );
    let mcp = learning_mcp(&agent, principal, &arguments, false)?;
    assert_eq!(
        mcp,
        first_stdout.trim_end(),
        "MCP and CLI share the native result"
    );
    assert_eq!(
        learning_tree(&agent.root, &["agent/publications"])?,
        retained
    );
    assert_eq!(learning_tree(&agent.root, &authority_paths)?, authority);

    // Captured artifacts bind the original admitted workspace. A benign explicit resume
    // can advance that workspace at the same evidence anchor; recovery must authenticate
    // the retained source revision instead of compiling a different binding from today's head.
    let before_inventory = learning_tree(&agent.root, &[""])?;
    let (code, before_resume) = agent.run("orient", &["--session", &agent.session])?;
    assert_eq!(code, Some(0), "{before_resume:?}");
    assert_eq!(
        text(&before_resume, &["payload", "compressionReceipt", "viewId"])?,
        "AVIEW-008"
    );
    let context_tokens = field(
        &before_resume,
        &["payload", "compressionReceipt", "actualTokens"],
    )?
    .integer()
    .ok_or("learning context token count")?;
    assert!((1..=3000).contains(&context_tokens));
    for omitted in [
        "omittedCriticalItems",
        "omittedInvalidations",
        "omittedContradictions",
    ] {
        assert_eq!(
            field(
                &before_resume,
                &[
                    "payload",
                    "compressionReceipt",
                    "criticalPreservation",
                    omitted
                ],
            )?
            .integer(),
            Some(0),
        );
    }
    assert_learning_discovery(
        &before_resume,
        &candidate,
        text(&first, &["payload", "experienceId"])?,
        &pointers,
    )?;
    assert_eq!(
        learning_tree(&agent.root, &[""])?,
        before_inventory,
        "captured-learning discovery must not mutate the deployment or session journal"
    );
    let (code, repeated_inventory) = agent.run("orient", &["--session", &agent.session])?;
    assert_eq!(code, Some(0), "{repeated_inventory:?}");
    assert_eq!(repeated_inventory, before_resume);
    assert_eq!(learning_tree(&agent.root, &[""])?, before_inventory);
    let inventory_mcp = learning_mcp_tool_wire(
        &agent,
        principal,
        "orient",
        &format!(r#"{{"session":{}}}"#, learning_quote(&agent.session)),
    )?;
    assert_eq!(
        field(&inventory_mcp, &["result", "isError"])?,
        &Value::Bool(false)
    );
    let inventory_content = field(&inventory_mcp, &["result", "content"])?
        .array()
        .ok_or("MCP captured-learning inventory")?;
    assert_eq!(inventory_content.len(), 1);
    let (_, mcp_inventory) = agent.answer(None, text(&inventory_content[0], &["text"])?)?;
    assert_eq!(
        mcp_inventory, before_resume,
        "CLI and MCP share the admitted learning inventory"
    );
    assert_eq!(learning_tree(&agent.root, &[""])?, before_inventory);
    let (code, too_small) = agent.run(
        "orient",
        &["--session", &agent.session, "--budget-tokens", "1"],
    )?;
    assert_eq!(code, Some(5), "{too_small:?}");
    assert_eq!(text(&too_small, &["outcome"])?, "refused");
    assert_eq!(
        learning_tree(&agent.root, &[""])?,
        before_inventory,
        "protected learning context must refuse an insufficient budget without mutation or truncation"
    );
    let prior_workspace = field(&before_resume, &["workspaceRevision"])?
        .integer()
        .ok_or("workspace revision before learning recovery")?;
    let (code, handed) = agent.run("handoff", &["--session", &agent.session])?;
    assert_eq!(code, Some(0), "{handed:?}");
    let handed_pointers = texts(&handed, &["proofPointers"])?;
    let handoff_manifest =
        fss_object::ObjectManifest::from_canonical_bytes(&fss_publication::read_verified(
            &publication,
            ContentDigest::parse(&handed_pointers[1])?,
            1 << 20,
        )?)?;
    assert!(handoff_manifest.children().contains(&learning_root));
    for digest in manifest.children() {
        assert!(
            handoff_manifest.children().contains(digest),
            "handoff omitted a member of the captured learning closure: {digest}"
        );
        fss_publication::read_verified(&publication, *digest, 1 << 20)?;
    }
    let (code, resumed_stdout) = run_fss(&[
        "session".into(),
        "resume".into(),
        "--json".into(),
        "--root".into(),
        agent.root.as_os_str().to_owned(),
        "--handoff".into(),
        text(&handed, &["payload", "handoffId"])?.into(),
    ])?;
    let (code, resumed) = agent.answer(code, &resumed_stdout)?;
    assert_eq!(code, Some(0), "{resumed_stdout}");
    assert_eq!(text(&resumed, &["sessionId"])?, agent.session);
    assert_learning_discovery(
        &resumed,
        &candidate,
        text(&first, &["payload", "experienceId"])?,
        &pointers,
    )?;
    assert_eq!(
        field(&resumed, &["missionId"])?,
        field(&first, &["missionId"])?
    );
    assert_eq!(
        field(&resumed, &["payload", "anchor"])?,
        field(&resumed, &["payload", "previousAnchor"])?,
        "this recovery fixture advances workspace state without moving the evidence anchor"
    );
    assert!(
        field(&resumed, &["workspaceRevision"])?
            .integer()
            .ok_or("workspace revision after learning recovery")?
            > prior_workspace,
        "the fixture must actually advance the workspace"
    );
    assert_eq!(learning_tree(&agent.root, &authority_paths)?, authority);
    let after_handoff = learning_tree(&agent.root, &["agent/publications"])?;
    let (code, recovered_stdout) = run_fss(&args)?;
    let (code, recovered) = agent.answer(code, &recovered_stdout)?;
    assert_eq!(code, Some(0), "{recovered_stdout}");
    assert_eq!(
        &texts(&recovered, &["proofPointers"])?[..6],
        &pointers[..6],
        "workspace evolution cannot replace the original learning or its source roots"
    );
    assert_eq!(
        raw_payload(&recovered_stdout)?,
        raw_payload(&first_stdout)?,
        "the captured experience and candidate meaning remain immutable"
    );
    let recovered_mcp = learning_mcp(&agent, principal, &arguments, false)?;
    assert_eq!(recovered_mcp, recovered_stdout.trim_end());
    assert_eq!(
        learning_tree(&agent.root, &["agent/publications"])?,
        after_handoff
    );
    assert_eq!(learning_tree(&agent.root, &authority_paths)?, authority);
    assert_eq!(relay.connections(), 0);

    // Retained learning never licenses a retry to recreate a lost source episode or ignore
    // corruption in its canonical candidate. Every call is a fresh process.
    for (digest, remove) in [(episode_rendering, true), (proposal_digest, false)] {
        let name = digest.to_text();
        let path = publication
            .join("spool/objects")
            .join(name.strip_prefix("sha256:").ok_or("SHA-256 custody")?);
        let original = fs::read(&path)?;
        if remove {
            fs::remove_file(&path)?;
        } else {
            let mut damaged = original.clone();
            *damaged.last_mut().ok_or("empty learning custody object")? ^= 1;
            fs::write(&path, damaged)?;
        }
        let damaged = learning_tree(&agent.root, &["agent/publications"])?;
        let before_failed_read = learning_tree(&agent.root, &[""])?;
        let (code, unreadable) = agent.run("orient", &["--session", &agent.session])?;
        assert_eq!(code, Some(5), "{unreadable:?}");
        assert_ne!(text(&unreadable, &["outcome"])?, "ok");
        assert_eq!(
            learning_tree(&agent.root, &[""])?,
            before_failed_read,
            "failed discovery must neither repair nor mutate a damaged captured source"
        );
        let (code, unhandoffable) = agent.run("handoff", &["--session", &agent.session])?;
        assert_eq!(code, Some(5), "{unhandoffable:?}");
        assert_ne!(text(&unhandoffable, &["outcome"])?, "ok");
        assert_eq!(
            learning_tree(&agent.root, &["agent/publications"])?,
            damaged
        );
        let (code, refused_stdout) = run_fss(&args)?;
        let (code, refused) = agent.answer(code, &refused_stdout)?;
        assert_eq!(code, Some(5), "{refused_stdout}");
        assert_ne!(text(&refused, &["outcome"])?, "ok");
        assert_ne!(
            text(&refused, &["payloadSchema"])?,
            "fss.experience_capsule.v1"
        );
        let refused_mcp = learning_mcp(&agent, principal, &arguments, true)?;
        assert_ne!(text(&parse(&refused_mcp)?, &["outcome"])?, "ok");
        assert_eq!(
            learning_tree(&agent.root, &["agent/publications"])?,
            damaged
        );
        assert_eq!(learning_tree(&agent.root, &authority_paths)?, authority);
        assert_eq!(relay.connections(), 0);
        fs::write(&path, original)?;
    }
    Ok(())
}

#[test]
fn learning_feedback_cannot_borrow_another_sessions_episode_or_request_activation() -> TestResult {
    let (directory, event_id) = corroborated_event("episode-learning-scope")?;
    let agent = Agent::open(&directory)?;
    let relay = Relay::spawn(None)?;
    let (code, planned) = agent.plan(&event_id, relay.address, &[])?;
    assert_eq!(code, Some(0), "{planned:?}");
    let (plan_id, approval, _) = approvals(&planned)?;
    let operation = operation_of(&planned)?;
    let principal = text(&planned, &["principalId"])?;
    let (code, prepared) = agent.plan(&event_id, relay.address, &["--approve", &approval])?;
    assert_eq!(code, Some(0), "{prepared:?}");
    let (code, preview) = agent.run("cancel", &["--operation", &operation])?;
    assert_eq!(code, Some(0), "{preview:?}");
    let cancel = texts(&preview, &["proofPointers"])?[0].clone();
    let (code, cancelled) =
        agent.run("cancel", &["--operation", &operation, "--approve", &cancel])?;
    assert_eq!(code, Some(0), "{cancelled:?}");
    let (code, closed, episode) = agent.close(&plan_id)?;
    assert_eq!(code, Some(0), "{closed:?}");
    assert!(episode.is_some());
    let supporting = texts(&closed, &["proofPointers"])?[1].clone();
    let owner_statement = "Review this retained episode under its original private session.";
    let owner_args = learning_args(&agent, &plan_id, &supporting, owner_statement);
    let (code, owned_stdout) = run_fss(&owner_args)?;
    let (code, owned) = agent.answer(code, &owned_stdout)?;
    assert_eq!(code, Some(0), "{owned_stdout}");
    let owned_pointers = texts(&owned, &["proofPointers"])?;
    let owned_experience = text(&owned, &["payload", "experienceId"])?;
    let owned_candidate =
        retained_learning_candidate(&agent, ContentDigest::parse(&owned_pointers[2])?)?;

    let (code, opened_stdout) = run_fss(&[
        "session".into(),
        "open".into(),
        "--json".into(),
        "--root".into(),
        agent.root.as_os_str().to_owned(),
        "--mission".into(),
        "Review a different mission.".into(),
        "--objective".into(),
        "Keep another session's episode outside this mission.".into(),
    ])?;
    let (code, opened) = agent.answer(code, &opened_stdout)?;
    assert_eq!(code, Some(0), "{opened_stdout}");
    let other = Agent {
        root: agent.root.clone(),
        scratch: agent.scratch.clone(),
        session: text(&opened, &["sessionId"])?.to_owned(),
    };
    assert_ne!(other.session, agent.session);
    assert_eq!(text(&opened, &["principalId"])?, principal);
    let before_foreign_read = learning_tree(&agent.root, &[""])?;
    let (code, foreign_inventory) = other.run("orient", &["--session", &other.session])?;
    assert_eq!(code, Some(0), "{foreign_inventory:?}");
    let foreign_items = field(&foreign_inventory, &["payload", "contextPack", "items"])?
        .array()
        .ok_or("foreign-session protected context")?;
    for private in [
        owned_experience,
        owned_candidate.proposal_id.as_str(),
        owner_statement,
    ] {
        assert!(
            foreign_items.iter().all(|item| {
                text(item, &["content"]).is_ok_and(|content| !content.contains(private))
            }),
            "another session exposed private captured-learning context: {private}"
        );
    }
    let foreign_proofs = texts(&foreign_inventory, &["proofPointers"])?;
    for pointer in owned_pointers.iter().take(3) {
        assert!(
            !foreign_proofs.contains(pointer),
            "another session borrowed learning custody"
        );
    }
    assert_eq!(
        learning_tree(&agent.root, &[""])?,
        before_foreign_read,
        "private scope filtering is read-only"
    );
    let statement = "Propose a policy review from the other session's cancelled alert.";
    let args = learning_args(&other, &plan_id, &supporting, statement);
    let arguments = learning_arguments(&other.session, &plan_id, &supporting, statement);
    let authority_paths = [
        "ledger", "effects", "objects", "LAYOUT", "policy", "models", "config",
    ];
    let authority = learning_tree(&agent.root, &authority_paths)?;
    let experiences = learning_experiences(&agent.root)?;
    let (code, refused_stdout) = run_fss(&args)?;
    let (code, refused) = other.answer(code, &refused_stdout)?;
    assert_eq!(code, Some(5), "{refused_stdout}");
    assert_ne!(text(&refused, &["outcome"])?, "ok");
    assert_ne!(
        text(&refused, &["payloadSchema"])?,
        "fss.experience_capsule.v1"
    );
    let refused_mcp = learning_mcp(&other, principal, &arguments, true)?;
    assert_ne!(text(&parse(&refused_mcp)?, &["outcome"])?, "ok");
    assert_eq!(learning_experiences(&agent.root)?, experiences);
    assert_eq!(learning_tree(&agent.root, &authority_paths)?, authority);

    let before = learning_tree(&agent.root, &[""])?;
    let malformed = format!(
        r#"{}, "promotionState":"promoted"}}"#,
        arguments.strip_suffix('}').ok_or("learning arguments")?
    );
    let wire = learning_mcp_wire(&other, principal, &malformed)?;
    assert_eq!(field(&wire, &["error", "code"])?.integer(), Some(-32602));
    assert_eq!(learning_tree(&agent.root, &[""])?, before);
    let foreign = learning_mcp(&other, "principal:learning-foreign", &arguments, true)?;
    assert_eq!(text(&parse(&foreign)?, &["outcome"])?, "refused");
    assert_eq!(learning_experiences(&agent.root)?, experiences);
    assert_eq!(learning_tree(&agent.root, &authority_paths)?, authority);
    assert_eq!(relay.connections(), 0);
    Ok(())
}
