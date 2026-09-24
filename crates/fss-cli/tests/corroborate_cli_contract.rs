#![forbid(unsafe_code)]
//! End-to-end two-sensor corroboration and alert effect through the real binaries.
//!
//! `fss-file import` retains two generated MJPEG recordings from two sensors with operator
//! capture hints; `fss-event corroborate` tracks each, projects foot points through owner-supplied
//! homographies, associates ground-zone entries under explicit gates and publishes only exactly
//! approved corroborated events; `fss-event alert` prepares and then commits and sends exactly one
//! webhook to a loopback relay the test runs, each step under its own exact approval. Nothing on
//! the detect/track/associate/publish/effect path is mocked. Synthetic scenes prove the wiring and
//! the authority path, not detection quality.

use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use fss_core::ContentDigest;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const WIDTH: u32 = 96;
const HEIGHT: u32 = 48;
const FRAMES: usize = 14;
const SITE: &str = "site:corroborate-cli";
/// Receive time (10 000 s); capture hints lie before it.
const RECEIVE_NS: &str = "10000000000000";
const IDENTITY: &str = "1,0,0,0,1,0,0,0,1";
/// Camera "west" sees the same ground mirrored left-right.
const MIRROR: &str = "-1,0,96,0,1,0,0,0,1";
const DOOR: &str = "door:56,0,40,48";

struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-corroborate-cli-{name}-{}-{attempt}",
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

#[derive(Clone, Copy)]
enum Motion {
    /// A bright 16x16 square enters at the left edge from frame 3 and moves 8 px right per frame.
    Right,
    /// The mirror image: it enters at the right edge and moves left.
    Left,
    /// Nothing moves.
    Still,
}

fn scene(motion: Motion) -> TestResult<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..FRAMES {
        let mut pixels = vec![40_u8; (WIDTH * HEIGHT) as usize];
        let left = match motion {
            Motion::Right if index >= 3 => Some((index - 3) * 8),
            Motion::Left if index >= 3 => Some(80 - (index - 3) * 8),
            _ => None,
        };
        if let Some(left) = left {
            for y in 8..24 {
                for x in left..left + 16 {
                    pixels[y * WIDTH as usize + x] = 220;
                }
            }
        }
        stream.extend(encode_jpeg(WIDTH, HEIGHT, &pixels, &config)?);
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

/// Operator capture hint: start (ns) and symmetric uncertainty (ns), 10 frames per second.
#[derive(Clone, Copy)]
struct Hint {
    start_ns: u64,
    uncertainty_ns: u64,
}
const ON_TIME: Hint = Hint {
    start_ns: 1_000_000_000,
    uncertainty_ns: 1_000_000,
};

fn import(
    directory: &OwnedDirectory,
    motion: Motion,
    sensor: &str,
    hint: Option<Hint>,
) -> TestResult<String> {
    let input = directory
        .0
        .join(format!("{sensor}.mjpeg").replace(':', "-"));
    fs::write(&input, scene(motion)?)?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-file"));
    command
        .arg("import")
        .arg("--root")
        .arg(directory.root())
        .args(["--site", SITE, "--input"])
        .arg(&input)
        .args(["--sensor", sensor, "--stream", &format!("stream:{sensor}")])
        .args(["--receive-time-ns", RECEIVE_NS, "--media-format", "mjpeg"]);
    if let Some(hint) = hint {
        command
            .args(["--capture-start-ns", &hint.start_ns.to_string()])
            .args(["--capture-uncertainty-ns", &hint.uncertainty_ns.to_string()])
            .args(["--assumed-fps", "10"]);
    }
    let output = command.output()?;
    success(&output);
    fs::remove_file(input)?;
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

struct Pair {
    east: String,
    west: String,
    west_ground: &'static str,
    zone: &'static str,
    time_gate_ns: &'static str,
}

fn corroborate(root: &Path, pair: &Pair, extra: &[&str]) -> TestResult<Output> {
    let east = format!("east:{}", pair.east);
    let west = format!("west:{}", pair.west);
    let east_ground = format!("east:{IDENTITY}");
    let west_ground = format!("west:{}", pair.west_ground);
    let mut args = vec![
        "--camera",
        &east,
        "--camera",
        &west,
        "--ground",
        &east_ground,
        "--ground",
        &west_ground,
        "--zone",
        pair.zone,
        "--interpretation",
        "gray",
        "--time-gate-ns",
        pair.time_gate_ns,
        "--distance-gate",
        "16",
    ];
    args.extend_from_slice(extra);
    event(root, "corroborate", &args)
}

/// Value of the first `"key":` in a JSON report: a bare token or the quoted string body.
fn json_field(output: &Output, key: &str) -> TestResult<String> {
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

fn occurrences(output: &Output, needle: &str) -> usize {
    String::from_utf8_lossy(&output.stdout)
        .matches(needle)
        .count()
}

fn refusal(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .find_map(|line| line.strip_prefix("refusal_id=").map(str::to_owned))
        .unwrap_or_default()
}

/// A deployment with one corroborated, published event; returns (directory, event id, revision).
fn published_event(name: &str) -> TestResult<(OwnedDirectory, String, String)> {
    let directory = OwnedDirectory::new(name)?;
    let pair = Pair {
        east: import(&directory, Motion::Right, "sensor:east", Some(ON_TIME))?,
        west: import(&directory, Motion::Left, "sensor:west", Some(ON_TIME))?,
        west_ground: MIRROR,
        zone: DOOR,
        time_gate_ns: "250000000",
    };
    let root = directory.root();
    let prepared = corroborate(&root, &pair, &[])?;
    success(&prepared);
    let proposal = json_field(&prepared, "proposal_digest")?;
    let published = corroborate(&root, &pair, &["--approve", &proposal])?;
    success(&published);
    assert_eq!(json_field(&published, "status")?, "published");
    let id = json_field(&published, "event_id")?;
    let revision = json_field(&published, "event_revision_digest")?;
    Ok((directory, id, revision))
}

#[test]
fn two_sensors_entering_one_zone_yield_one_corroborated_event_and_policy_prepare_alert()
-> TestResult {
    let directory = OwnedDirectory::new("corroborated")?;
    let pair = Pair {
        east: import(&directory, Motion::Right, "sensor:east", Some(ON_TIME))?,
        west: import(&directory, Motion::Left, "sensor:west", Some(ON_TIME))?,
        west_ground: MIRROR,
        zone: DOOR,
        time_gate_ns: "250000000",
    };
    let root = directory.root();
    let prepared = corroborate(&root, &pair, &[])?;
    success(&prepared);
    assert_eq!(
        json_field(&prepared, "format")?,
        "fss.recorded_corroboration_report.v1"
    );
    assert_eq!(json_field(&prepared, "candidate_count")?, "1");
    assert_eq!(
        occurrences(&prepared, "\"disposition\":\"corroborated\""),
        2
    );
    assert_eq!(json_field(&prepared, "event_state")?, "corroborated");
    assert_eq!(json_field(&prepared, "event_kind")?, "unclassified");
    assert_eq!(json_field(&prepared, "policy_action")?, "prepare_alert");
    assert_eq!(json_field(&prepared, "alert_prepared")?, "false");
    assert_eq!(json_field(&prepared, "status")?, "prepared");
    assert_eq!(json_field(&prepared, "published_count")?, "0");
    assert_eq!(json_field(&prepared, "alert_command")?, "null");
    assert_eq!(
        json_field(&prepared, "ground_homography")?,
        "owner_supplied_not_a_calibration_certificate"
    );
    assert_ne!(
        json_field(&prepared, "failure_domain")?,
        String::new(),
        "each sensor carries its own failure domain"
    );
    assert_eq!(
        occurrences(&prepared, "\"failure_domain\":\"recorded-sensor:"),
        2
    );
    let proposal = json_field(&prepared, "proposal_digest")?;
    let command = json_field(&prepared, "publish_command")?;
    assert!(command.starts_with("fss-event corroborate --root "));
    assert!(command.ends_with(&format!("--approve {proposal}")));
    let before = json_field(&prepared, "authority_sequence")?;

    // Analysis alone writes nothing and is byte-for-byte deterministic.
    let repeated = corroborate(&root, &pair, &[])?;
    success(&repeated);
    assert_eq!(repeated.stdout, prepared.stdout);

    let published = corroborate(&root, &pair, &["--approve", &proposal])?;
    success(&published);
    assert_eq!(json_field(&published, "status")?, "published");
    assert_eq!(json_field(&published, "published_count")?, "1");
    assert_eq!(json_field(&published, "alert_prepared")?, "false");
    assert!(json_field(&published, "alert_command")?.starts_with("fss-event alert --root "));
    let after = json_field(&published, "authority_sequence")?;
    assert!(after.parse::<u64>()? > before.parse::<u64>()?);

    // Reruns recognise the exact revision and change no authority.
    let rerun = corroborate(&root, &pair, &["--approve", &proposal])?;
    success(&rerun);
    assert_eq!(json_field(&rerun, "status")?, "already_published");
    assert_eq!(json_field(&rerun, "published_count")?, "0");
    assert_eq!(json_field(&rerun, "authority_sequence")?, after);

    // Nothing was prepared in the effect journal: the alert stage still only proposes.
    let proposed = event(
        &root,
        "alert",
        &[
            "--event-id",
            &json_field(&published, "event_id")?,
            "--relay",
            "127.0.0.1:9",
            "--path",
            "/fss/alert",
            "--plaintext-approval",
            &approval(),
            "--deadline-ms",
            "2000",
        ],
    )?;
    success(&proposed);
    assert_eq!(json_field(&proposed, "stage")?, "proposed");
    assert_eq!(json_field(&proposed, "effect_state")?, "null");
    Ok(())
}

#[test]
fn an_object_seen_by_only_one_sensor_is_never_corroborated() -> TestResult {
    let directory = OwnedDirectory::new("single")?;
    let pair = Pair {
        east: import(&directory, Motion::Right, "sensor:east", Some(ON_TIME))?,
        west: import(&directory, Motion::Still, "sensor:west", Some(ON_TIME))?,
        west_ground: MIRROR,
        zone: DOOR,
        time_gate_ns: "250000000",
    };
    let output = corroborate(&directory.root(), &pair, &[])?;
    success(&output);
    assert_eq!(json_field(&output, "candidate_count")?, "0");
    assert_eq!(
        occurrences(&output, "\"disposition\":\"no_counterpart_entry\""),
        1
    );
    assert_eq!(occurrences(&output, "\"camera\":\"east\",\"zone_id\""), 1);
    assert_eq!(occurrences(&output, "\"camera\":\"west\",\"zone_id\""), 0);
    assert_eq!(occurrences(&output, "corroborated\""), 0);
    Ok(())
}

#[test]
fn distant_ground_points_late_entries_and_uncertain_clocks_do_not_associate() -> TestResult {
    // Far apart on the ground: west's homography places its object 500 units away.
    let far = OwnedDirectory::new("far")?;
    let pair = Pair {
        east: import(&far, Motion::Right, "sensor:east", Some(ON_TIME))?,
        west: import(&far, Motion::Left, "sensor:west", Some(ON_TIME))?,
        west_ground: "-1,0,596,0,1,0,0,0,1",
        zone: "yard:0,0,1000,100",
        time_gate_ns: "250000000",
    };
    let output = corroborate(&far.root(), &pair, &[])?;
    success(&output);
    assert_eq!(json_field(&output, "candidate_count")?, "0");
    assert_eq!(
        occurrences(&output, "\"disposition\":\"no_admissible_counterpart\""),
        2
    );

    // Same ground trajectory, but the west recording's clock starts one second later: the
    // capture spans overlap (so the clocks are not refused as unaligned) yet the entries fall
    // outside the time gate.
    let late = OwnedDirectory::new("late")?;
    let pair = Pair {
        east: import(&late, Motion::Right, "sensor:east", Some(ON_TIME))?,
        west: import(
            &late,
            Motion::Left,
            "sensor:west",
            Some(Hint {
                start_ns: 2_000_000_000,
                ..ON_TIME
            }),
        )?,
        west_ground: MIRROR,
        zone: DOOR,
        time_gate_ns: "250000000",
    };
    let output = corroborate(&late.root(), &pair, &[])?;
    success(&output);
    assert_eq!(json_field(&output, "candidate_count")?, "0");
    assert_eq!(
        occurrences(&output, "\"disposition\":\"no_admissible_counterpart\""),
        2
    );

    // Coincident point estimates, but +/-200 ms hints: the worst case over both intervals
    // (400 ms) exceeds the 250 ms gate, so the pair is refused as time-uncertain.
    let vague = OwnedDirectory::new("vague")?;
    let wide = Hint {
        uncertainty_ns: 200_000_000,
        ..ON_TIME
    };
    let pair = Pair {
        east: import(&vague, Motion::Right, "sensor:east", Some(wide))?,
        west: import(&vague, Motion::Left, "sensor:west", Some(wide))?,
        west_ground: MIRROR,
        zone: DOOR,
        time_gate_ns: "250000000",
    };
    let output = corroborate(&vague.root(), &pair, &[])?;
    success(&output);
    assert_eq!(json_field(&output, "candidate_count")?, "0");
    assert_eq!(
        occurrences(&output, "\"disposition\":\"time_gate_uncertain\""),
        2
    );
    Ok(())
}

fn approval() -> String {
    ContentDigest::sha256(b"owner approves the plaintext loopback relay").to_text()
}

/// Loopback relay owned by the test: accepts connections, retains every complete request, and
/// either answers with `reply` or closes without any response. Stopped and joined on drop.
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
                // Dropping the stream closes it: without a reply, the acknowledgement is lost.
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
    fn requests(&self) -> TestResult<Vec<Vec<u8>>> {
        Ok(self
            .requests
            .lock()
            .map_err(|_| "relay request log poisoned")?
            .clone())
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

fn alert(root: &Path, id: &str, relay: SocketAddr, extra: &[&str]) -> TestResult<Output> {
    let relay = relay.to_string();
    let approval = approval();
    let mut args = vec![
        "--event-id",
        id,
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
    event(root, "alert", &args)
}

#[test]
fn alert_prepares_on_approval_then_dispatches_exactly_one_request_and_never_resends() -> TestResult
{
    let (directory, id, revision) = published_event("alert-accepted")?;
    let root = directory.root();
    let relay = Relay::spawn(Some(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))?;

    let proposed = alert(&root, &id, relay.address, &[])?;
    success(&proposed);
    assert_eq!(json_field(&proposed, "stage")?, "proposed");
    assert_eq!(json_field(&proposed, "policy_action")?, "prepare_alert");
    assert_eq!(json_field(&proposed, "effect_state")?, "null");
    let plan = json_field(&proposed, "plan_digest")?;
    assert!(json_field(&proposed, "next_command")?.ends_with(&format!("--approve {plan}")));

    let prepared = alert(&root, &id, relay.address, &["--approve", &plan])?;
    success(&prepared);
    assert_eq!(json_field(&prepared, "stage")?, "prepared");
    assert_eq!(json_field(&prepared, "effect_state")?, "prepared");
    assert_eq!(json_field(&prepared, "obligation_state")?, "pending");
    assert_eq!(json_field(&prepared, "plan_digest")?, plan);
    let dispatch = json_field(&prepared, "dispatch_digest")?;
    assert!(
        json_field(&prepared, "next_command")?
            .ends_with(&format!("--approve {plan} --dispatch {dispatch}"))
    );
    assert_eq!(
        relay.connections(),
        0,
        "preparation performs no network I/O"
    );
    // Preparing again is idempotent and still sends nothing.
    let again = alert(&root, &id, relay.address, &["--approve", &plan])?;
    success(&again);
    assert_eq!(json_field(&again, "dispatch_digest")?, dispatch);
    assert_eq!(relay.connections(), 0);

    let sent = alert(
        &root,
        &id,
        relay.address,
        &["--approve", &plan, "--dispatch", &dispatch],
    )?;
    success(&sent);
    assert_eq!(json_field(&sent, "stage")?, "dispatched");
    assert_eq!(json_field(&sent, "effect_state")?, "adapter_accepted");
    assert_eq!(
        json_field(&sent, "delivery_claim")?,
        "relay_acceptance_only"
    );
    assert_eq!(json_field(&sent, "outcome")?, "receiver_accepted_200");
    assert_eq!(json_field(&sent, "obligation_state")?, "pending");
    assert_eq!(json_field(&sent, "retries")?, "0");
    let requests = relay.requests()?;
    assert_eq!(requests.len(), 1);
    assert_eq!(relay.connections(), 1);
    let request = std::str::from_utf8(&requests[0])?;
    assert!(
        request.starts_with("POST /fss/alert HTTP/1.1\r\n"),
        "{request}"
    );
    assert!(request.contains("Content-Type: application/json\r\n"));
    assert!(request.contains("Idempotency-Key: "));
    let revision_hex = revision.strip_prefix("sha256:").ok_or("revision digest")?;
    assert!(request.contains(&format!("\"event_revision_sha256\":\"{revision_hex}\"")));
    assert_eq!(
        json_field(&sent, "request_sha256")?,
        ContentDigest::sha256(&requests[0]).to_text()
    );

    // Reruns of every stage report the recorded operation and never resend.
    for extra in [
        vec!["--approve", plan.as_str(), "--dispatch", dispatch.as_str()],
        vec!["--approve", plan.as_str()],
        vec![],
    ] {
        let rerun = alert(&root, &id, relay.address, &extra)?;
        success(&rerun);
        assert_eq!(json_field(&rerun, "stage")?, "already_dispatched");
        assert_eq!(json_field(&rerun, "effect_state")?, "adapter_accepted");
        assert_eq!(json_field(&rerun, "resend")?, "false");
    }
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(relay.connections(), 1);
    assert_eq!(relay.requests()?.len(), 1);
    Ok(())
}

#[test]
fn a_relay_that_closes_without_acknowledgement_leaves_the_alert_indeterminate() -> TestResult {
    let (directory, id, _) = published_event("alert-lost-ack")?;
    let root = directory.root();
    let relay = Relay::spawn(None)?;
    let proposed = alert(&root, &id, relay.address, &[])?;
    success(&proposed);
    let plan = json_field(&proposed, "plan_digest")?;
    let prepared = alert(&root, &id, relay.address, &["--approve", &plan])?;
    success(&prepared);
    let dispatch = json_field(&prepared, "dispatch_digest")?;

    let lost = alert(
        &root,
        &id,
        relay.address,
        &["--approve", &plan, "--dispatch", &dispatch],
    )?;
    assert_eq!(lost.status.code(), Some(1));
    assert_eq!(refusal(&lost), "ERR-EFFECT-INDETERMINATE-001");
    assert_eq!(json_field(&lost, "stage")?, "dispatched");
    assert_eq!(json_field(&lost, "effect_state")?, "indeterminate");
    assert_eq!(json_field(&lost, "delivery_claim")?, "indeterminate");
    assert_eq!(json_field(&lost, "obligation_state")?, "indeterminate");
    assert_eq!(json_field(&lost, "outcome")?, "interrupted_disconnected");
    assert_eq!(relay.requests()?.len(), 1);

    let rerun = alert(
        &root,
        &id,
        relay.address,
        &["--approve", &plan, "--dispatch", &dispatch],
    )?;
    assert_eq!(rerun.status.code(), Some(1));
    assert_eq!(refusal(&rerun), "ERR-EFFECT-INDETERMINATE-001");
    assert_eq!(json_field(&rerun, "stage")?, "already_dispatched");
    assert_eq!(json_field(&rerun, "effect_state")?, "indeterminate");
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(
        relay.connections(),
        1,
        "an indeterminate alert is never resent"
    );
    Ok(())
}

#[test]
fn corroboration_refuses_one_sensor_bad_homographies_and_unaligned_clocks() -> TestResult {
    let directory = OwnedDirectory::new("refusals")?;
    let root = directory.root();
    let east = import(&directory, Motion::Right, "sensor:east", Some(ON_TIME))?;
    let west = import(&directory, Motion::Left, "sensor:west", Some(ON_TIME))?;
    let twin = import(&directory, Motion::Left, "sensor:east", Some(ON_TIME))?;
    let unknown = import(&directory, Motion::Left, "sensor:unknown-clock", None)?;
    let hour = import(
        &directory,
        Motion::Left,
        "sensor:hour-later",
        Some(Hint {
            start_ns: 3_600_000_000_000,
            ..ON_TIME
        }),
    )?;
    let with = |west: &str, west_ground: &'static str| Pair {
        east: east.clone(),
        west: west.to_owned(),
        west_ground,
        zone: DOOR,
        time_gate_ns: "250000000",
    };

    for other in [&twin, &east] {
        let same = corroborate(&root, &with(other, MIRROR), &[])?;
        assert_eq!(same.status.code(), Some(1));
        assert_eq!(refusal(&same), "ERR-CORROBORATE-SAME-SENSOR-001");
        assert!(same.stdout.is_empty());
    }
    let singular = corroborate(&root, &with(&west, "1,2,3,2,4,6,0,0,1"), &[])?;
    assert_eq!(singular.status.code(), Some(1));
    assert_eq!(refusal(&singular), "ERR-CORROBORATE-HOMOGRAPHY-INVALID-001");

    let east_camera = format!("east:{east}");
    let west_camera = format!("west:{west}");
    let east_ground = format!("east:{IDENTITY}");
    let missing = event(
        &root,
        "corroborate",
        &[
            "--camera",
            &east_camera,
            "--camera",
            &west_camera,
            "--ground",
            &east_ground,
            "--zone",
            DOOR,
            "--interpretation",
            "gray",
            "--time-gate-ns",
            "250000000",
            "--distance-gate",
            "16",
        ],
    )?;
    assert_eq!(missing.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("--ground"));
    let short = event(
        &root,
        "corroborate",
        &[
            "--camera",
            &east_camera,
            "--camera",
            &west_camera,
            "--ground",
            &east_ground,
            "--ground",
            "west:1,0,0,0,1,0",
            "--zone",
            DOOR,
            "--interpretation",
            "gray",
            "--time-gate-ns",
            "250000000",
            "--distance-gate",
            "16",
        ],
    )?;
    assert_eq!(short.status.code(), Some(2));

    let unknown_clock = corroborate(&root, &with(&unknown, MIRROR), &[])?;
    assert_eq!(unknown_clock.status.code(), Some(1));
    assert_eq!(refusal(&unknown_clock), "ERR-CORROBORATE-TIME-UNKNOWN-001");
    let unaligned = corroborate(&root, &with(&hour, MIRROR), &[])?;
    assert_eq!(unaligned.status.code(), Some(1));
    assert_eq!(refusal(&unaligned), "ERR-CORROBORATE-TIME-UNALIGNED-001");

    let stale = ContentDigest::sha256(b"not a proposal").to_text();
    let refused = corroborate(&root, &with(&west, MIRROR), &["--approve", &stale])?;
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(refusal(&refused), "ERR-CORROBORATE-APPROVAL-STALE-001");
    let still = corroborate(&root, &with(&west, MIRROR), &[])?;
    success(&still);
    assert_eq!(json_field(&still, "published_count")?, "0");
    assert_eq!(json_field(&still, "status")?, "prepared");
    Ok(())
}

#[test]
fn alert_refuses_stale_approvals_ineligible_events_and_tampered_authority() -> TestResult {
    let (directory, id, _) = published_event("alert-refusals")?;
    let root = directory.root();
    let relay = Relay::spawn(Some(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))?;
    let stale = ContentDigest::sha256(b"not the plan").to_text();

    let wrong = alert(&root, &id, relay.address, &["--approve", &stale])?;
    assert_eq!(wrong.status.code(), Some(1));
    assert_eq!(refusal(&wrong), "ERR-ALERT-APPROVAL-STALE-001");
    let early = alert(
        &root,
        &id,
        relay.address,
        &["--approve", &stale, "--dispatch", &stale],
    )?;
    assert_eq!(refusal(&early), "ERR-ALERT-APPROVAL-STALE-001");

    // A plan approved for one route is stale for another.
    let proposed = alert(&root, &id, relay.address, &[])?;
    success(&proposed);
    let plan = json_field(&proposed, "plan_digest")?;
    let relay_text = relay.address.to_string();
    let approval = approval();
    let rerouted = event(
        &root,
        "alert",
        &[
            "--event-id",
            &id,
            "--relay",
            &relay_text,
            "--path",
            "/other",
            "--plaintext-approval",
            &approval,
            "--deadline-ms",
            "5000",
            "--approve",
            &plan,
        ],
    )?;
    assert_eq!(refusal(&rerouted), "ERR-ALERT-APPROVAL-STALE-001");

    let prepared = alert(&root, &id, relay.address, &["--approve", &plan])?;
    success(&prepared);
    let bad_dispatch = alert(
        &root,
        &id,
        relay.address,
        &["--approve", &plan, "--dispatch", &stale],
    )?;
    assert_eq!(bad_dispatch.status.code(), Some(1));
    assert_eq!(refusal(&bad_dispatch), "ERR-ALERT-APPROVAL-STALE-001");
    let dispatch = json_field(&prepared, "dispatch_digest")?;
    // A dispatch approval is bound to its deadline.
    let longer = event(
        &root,
        "alert",
        &[
            "--event-id",
            &id,
            "--relay",
            &relay_text,
            "--path",
            "/fss/alert",
            "--plaintext-approval",
            &approval,
            "--deadline-ms",
            "6000",
            "--approve",
            &plan,
            "--dispatch",
            &dispatch,
        ],
    )?;
    assert_eq!(refusal(&longer), "ERR-ALERT-APPROVAL-STALE-001");

    let missing = alert(&root, "event:corroborated:absent", relay.address, &[])?;
    assert_eq!(missing.status.code(), Some(1));
    assert_eq!(refusal(&missing), "ERR-ALERT-AUTHORITY-001");

    // Tampered authority: bytes appended to the ledger journal after preparation. The deployment
    // refuses to open, so nothing is committed and nothing is sent.
    let mut ledger = fs::OpenOptions::new()
        .append(true)
        .open(root.join("ledger/journal.fssj"))?;
    ledger.write_all(b"forged authority suffix")?;
    drop(ledger);
    let tampered = alert(
        &root,
        &id,
        relay.address,
        &["--approve", &plan, "--dispatch", &dispatch],
    )?;
    assert_eq!(tampered.status.code(), Some(1));
    assert!(tampered.stdout.is_empty());
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(
        relay.connections(),
        0,
        "no request is sent on tampered authority"
    );
    Ok(())
}

#[test]
fn a_single_sensor_watch_event_is_not_alert_eligible() -> TestResult {
    let directory = OwnedDirectory::new("watch-ineligible")?;
    let root = directory.root();
    let east = import(&directory, Motion::Right, "sensor:east", Some(ON_TIME))?;
    let watch = |extra: &[&str]| -> TestResult<Output> {
        let mut args = vec![
            "--import-id",
            east.as_str(),
            "--interpretation",
            "gray",
            "--zone",
            "door:64,0,32,32",
        ];
        args.extend_from_slice(extra);
        event(&root, "watch", &args)
    };
    let prepared = watch(&[])?;
    success(&prepared);
    let proposal = json_field(&prepared, "proposal_digest")?;
    let published = watch(&["--approve", &proposal])?;
    success(&published);
    let id = json_field(&published, "event_id")?;
    let relay = Relay::spawn(Some(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))?;
    let refused = alert(&root, &id, relay.address, &[])?;
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(refusal(&refused), "ERR-ALERT-NOT-ELIGIBLE-001");
    assert_eq!(relay.connections(), 0);
    Ok(())
}
