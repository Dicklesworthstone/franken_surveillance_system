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
//!    unchanged on a second close; citing the principal's feedback as competing attribution).

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

use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:agent-effect-cli";
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

struct Agent {
    root: PathBuf,
    scratch: PathBuf,
    session: String,
}

impl Agent {
    fn open(directory: &OwnedDirectory) -> TestResult<Self> {
        let root = directory.root();
        let (code, stdout) = run_fss(&[
            "session".into(),
            "open".into(),
            "--json".into(),
            "--root".into(),
            root.as_os_str().to_owned(),
            "--mission".into(),
            "Protect the door.".into(),
            "--objective".into(),
            "Alert the owner on a corroborated entry.".into(),
        ])?;
        assert_eq!(code, Some(0), "{stdout}");
        let scratch = directory.0.join("scratch");
        fs::create_dir_all(&scratch)?;
        Ok(Self {
            root,
            scratch,
            session: text(&parse(stdout.trim_end())?, &["sessionId"])?.to_owned(),
        })
    }

    /// Runs one command; validates the envelope and payload; returns (exit, envelope).
    fn run(&self, command: &str, extra: &[&str]) -> TestResult<(Option<i32>, Value)> {
        let mut args: Vec<OsString> = vec![
            command.into(),
            "--json".into(),
            "--root".into(),
            self.root.as_os_str().to_owned(),
        ];
        args.extend(extra.iter().map(OsString::from));
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
            "5000",
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
