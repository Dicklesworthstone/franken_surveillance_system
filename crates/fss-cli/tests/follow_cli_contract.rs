#![forbid(unsafe_code)]
//! Contract tests for `fss follow` (AOP-004 `session.follow`) through the real `fss` binary, over
//! deployments built with the real `fss-file import`, `fss-event watch`, `fss-event corroborate`,
//! and `fss-event alert` flows:
//!
//! 1. an orientation of an empty deployment emits an anchor token; after a watch candidate is
//!    published, following since that token returns the engine's delta naming the new unresolved
//!    event, and its basis is exactly the frame the first orientation answered with;
//! 2. following since the current anchor compares the head with itself: nothing committed changed,
//!    and the persisting coverage gap stays protected `coverage_loss` (no silence certificate
//!    without a retained CoverageWitness);
//! 3. after a corroborated event's alert is prepared, the delta carries the new obligation and
//!    the unproved effect as protected, critical classes;
//! 4. a small page budget delivers every item exactly once through exact continuations, every
//!    page carries the complete class set, and an altered or wrong-stream continuation is refused;
//! 5. unknown, foreign, ahead, and malformed anchors are typed refusals;
//! 6. every answer and refusal validates against its registered schemas
//!    (`scripts/json_instance_validate.py`), the output is deterministic, and the deployment tree
//!    digest is identical before and after every read.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::{ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const WIDTH: u32 = 96;
const HEIGHT: u32 = 48;
const FRAMES: usize = 14;
const SITE: &str = "site:follow-cli";
const OTHER_SITE: &str = "site:follow-cli-other";
const IDENTITY: &str = "1,0,0,0,1,0,0,0,1";
/// Camera "west" sees the same ground mirrored left-right.
const MIRROR: &str = "-1,0,96,0,1,0,0,0,1";

// ---------------------------------------------------------------------------------------------
// Minimal JSON reader: every assertion below goes through a full parse, so the output is also
// proven to be one well-formed JSON document.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Number(String),
    Text(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    fn parse(text: &str) -> TestResult<Self> {
        let bytes = text.as_bytes();
        let mut position = 0;
        let value = parse_value(bytes, &mut position)?;
        skip_whitespace(bytes, &mut position);
        if position != bytes.len() {
            return Err(format!("trailing bytes at {position}").into());
        }
        Ok(value)
    }

    fn get(&self, key: &str) -> TestResult<&Self> {
        match self {
            Self::Object(fields) => fields
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value)
                .ok_or_else(|| format!("missing key {key}").into()),
            _ => Err(format!("not an object when reading {key}").into()),
        }
    }

    fn path(&self, keys: &[&str]) -> TestResult<&Self> {
        let mut current = self;
        for key in keys {
            current = current.get(key)?;
        }
        Ok(current)
    }

    fn text(&self) -> TestResult<&str> {
        match self {
            Self::Text(value) => Ok(value),
            other => Err(format!("not a string: {other:?}").into()),
        }
    }

    fn items(&self) -> TestResult<&[Self]> {
        match self {
            Self::Array(items) => Ok(items),
            other => Err(format!("not an array: {other:?}").into()),
        }
    }

    fn texts(&self) -> TestResult<Vec<&str>> {
        self.items()?.iter().map(Self::text).collect()
    }

    fn number(&self) -> TestResult<u64> {
        match self {
            Self::Number(value) => Ok(value.parse()?),
            other => Err(format!("not a number: {other:?}").into()),
        }
    }
}

fn skip_whitespace(bytes: &[u8], position: &mut usize) {
    while bytes
        .get(*position)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        *position += 1;
    }
}

fn expect(bytes: &[u8], position: &mut usize, literal: &str) -> TestResult {
    if bytes[*position..].starts_with(literal.as_bytes()) {
        *position += literal.len();
        Ok(())
    } else {
        Err(format!("expected {literal} at {position}").into())
    }
}

fn parse_string(bytes: &[u8], position: &mut usize) -> TestResult<String> {
    expect(bytes, position, "\"")?;
    let mut out = String::new();
    loop {
        let byte = *bytes.get(*position).ok_or("unterminated string")?;
        *position += 1;
        match byte {
            b'"' => return Ok(out),
            b'\\' => {
                let escaped = *bytes.get(*position).ok_or("dangling escape")?;
                *position += 1;
                match escaped {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'b' => out.push('\u{8}'),
                    b'f' => out.push('\u{c}'),
                    b'u' => {
                        let hex = std::str::from_utf8(
                            bytes.get(*position..*position + 4).ok_or("short escape")?,
                        )?;
                        *position += 4;
                        out.push(
                            char::from_u32(u32::from_str_radix(hex, 16)?).ok_or("bad escape")?,
                        );
                    }
                    _ => return Err("unknown escape".into()),
                }
            }
            byte if byte < 0x20 => return Err("raw control character in string".into()),
            _ => {
                let start = *position - 1;
                let mut end = *position;
                while end < bytes.len() && bytes[end] != b'"' && bytes[end] != b'\\' {
                    end += 1;
                }
                out.push_str(std::str::from_utf8(&bytes[start..end])?);
                *position = end;
            }
        }
    }
}

fn parse_value(bytes: &[u8], position: &mut usize) -> TestResult<Json> {
    skip_whitespace(bytes, position);
    match bytes.get(*position).copied().ok_or("unexpected end")? {
        b'n' => expect(bytes, position, "null").map(|()| Json::Null),
        b't' => expect(bytes, position, "true").map(|()| Json::Bool(true)),
        b'f' => expect(bytes, position, "false").map(|()| Json::Bool(false)),
        b'"' => parse_string(bytes, position).map(Json::Text),
        b'[' => {
            *position += 1;
            let mut items = Vec::new();
            skip_whitespace(bytes, position);
            if bytes.get(*position) == Some(&b']') {
                *position += 1;
                return Ok(Json::Array(items));
            }
            loop {
                items.push(parse_value(bytes, position)?);
                skip_whitespace(bytes, position);
                match bytes.get(*position) {
                    Some(b',') => *position += 1,
                    Some(b']') => {
                        *position += 1;
                        return Ok(Json::Array(items));
                    }
                    _ => return Err("bad array".into()),
                }
            }
        }
        b'{' => {
            *position += 1;
            let mut fields: Vec<(String, Json)> = Vec::new();
            skip_whitespace(bytes, position);
            if bytes.get(*position) == Some(&b'}') {
                *position += 1;
                return Ok(Json::Object(fields));
            }
            loop {
                skip_whitespace(bytes, position);
                let key = parse_string(bytes, position)?;
                if fields.iter().any(|(seen, _)| *seen == key) {
                    return Err(format!("duplicate key {key}").into());
                }
                skip_whitespace(bytes, position);
                expect(bytes, position, ":")?;
                fields.push((key, parse_value(bytes, position)?));
                skip_whitespace(bytes, position);
                match bytes.get(*position) {
                    Some(b',') => *position += 1,
                    Some(b'}') => {
                        *position += 1;
                        return Ok(Json::Object(fields));
                    }
                    _ => return Err("bad object".into()),
                }
            }
        }
        _ => {
            let start = *position;
            while bytes
                .get(*position)
                .is_some_and(|byte| byte.is_ascii_digit() || b"-+.eE".contains(byte))
            {
                *position += 1;
            }
            if start == *position {
                return Err(format!("unexpected byte at {start}").into());
            }
            Ok(Json::Number(
                std::str::from_utf8(&bytes[start..*position])?.to_owned(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------------------------

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-follow-cli-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
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

/// Creates an empty deployment for `site` with `ReferenceDeployment::open`.
fn empty_deployment(directory: &OwnedDirectory, site: &str) -> TestResult<PathBuf> {
    let root = directory.root();
    let spec = RootAuthoritySpec {
        trace_id: "trace:follow-cli".to_owned(),
        operation_id: OperationId::parse("operation:follow-cli")?,
        principal: "operator:follow-cli".to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: fss_core::BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"follow-cli"),
        generation: 1,
    };
    let authority = ContextAuthority::new_root(spec)?;
    let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority,
        directory.0.join("cx"),
    )?);
    drop(ReferenceDeployment::open(&root, site, &cx)?);
    Ok(root)
}

#[derive(Clone, Copy)]
enum Motion {
    /// A bright 16x16 square enters at the left edge from frame 3 and moves 8 px right per frame.
    Right,
    /// The mirror image: it enters at the right edge and moves left.
    Left,
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
        if index >= 3 {
            let left = match motion {
                Motion::Right => (index - 3) * 8,
                Motion::Left => 80 - (index - 3) * 8,
            };
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

/// Value of the first `"key":` in a flat report: a bare token or the quoted string body.
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

/// Imports one generated recording into `root` with `fss-file import`; returns its identity.
/// With `capture_hint`, the recording carries an operator capture start at 1 s (10 fps, 1 ms
/// uncertainty) received at 10 000 s; without, it is received at 1 s.
fn import(
    directory: &OwnedDirectory,
    motion: Motion,
    sensor: &str,
    capture_hint: bool,
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
        .args(["--media-format", "mjpeg"]);
    if capture_hint {
        command
            .args(["--receive-time-ns", "10000000000000"])
            .args(["--capture-start-ns", "1000000000"])
            .args(["--capture-uncertainty-ns", "1000000"])
            .args(["--assumed-fps", "10"]);
    } else {
        command.args(["--receive-time-ns", "1000000000"]);
    }
    let output = command.output()?;
    success(&output);
    fs::remove_file(input)?;
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .find_map(|line| line.strip_prefix("import_identity=").map(str::to_owned))
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

/// Publishes the single watch candidate of `import_id` with `fss-event watch --approve`.
fn publish_watch_candidate(root: &Path, import_id: &str) -> TestResult<String> {
    let watch = |extra: &[&str]| -> TestResult<Output> {
        let mut args = vec![
            "--import-id",
            import_id,
            "--interpretation",
            "gray",
            "--zone",
            "door:64,0,32,32",
        ];
        args.extend_from_slice(extra);
        event(root, "watch", &args)
    };
    let prepared = watch(&[])?;
    success(&prepared);
    assert_eq!(report_field(&prepared, "candidate_count")?, "1");
    let proposal = report_field(&prepared, "proposal_digest")?;
    let published = watch(&["--approve", &proposal])?;
    success(&published);
    assert_eq!(report_field(&published, "status")?, "published");
    report_field(&published, "event_id")
}

/// Publishes one event corroborated by two sensors with `fss-event corroborate --approve`.
fn publish_corroborated_event(directory: &OwnedDirectory) -> TestResult<String> {
    let east = format!(
        "east:{}",
        import(directory, Motion::Right, "sensor:east", true)?
    );
    let west = format!(
        "west:{}",
        import(directory, Motion::Left, "sensor:west", true)?
    );
    let east_ground = format!("east:{IDENTITY}");
    let west_ground = format!("west:{MIRROR}");
    let corroborate = |extra: &[&str]| -> TestResult<Output> {
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
            "door:56,0,40,48",
            "--interpretation",
            "gray",
            "--time-gate-ns",
            "250000000",
            "--distance-gate",
            "16",
        ];
        args.extend_from_slice(extra);
        event(&directory.root(), "corroborate", &args)
    };
    let prepared = corroborate(&[])?;
    success(&prepared);
    let proposal = report_field(&prepared, "proposal_digest")?;
    let published = corroborate(&["--approve", &proposal])?;
    success(&published);
    assert_eq!(report_field(&published, "status")?, "published");
    report_field(&published, "event_id")
}

/// Proposes and then prepares (never dispatches) the webhook alert of `event_id`.
fn prepare_alert(root: &Path, event_id: &str) -> TestResult<String> {
    let approval = ContentDigest::sha256(b"owner approves the plaintext loopback relay").to_text();
    let alert = |extra: &[&str]| -> TestResult<Output> {
        let mut args = vec![
            "--event-id",
            event_id,
            "--relay",
            "127.0.0.1:9",
            "--path",
            "/fss/alert",
            "--plaintext-approval",
            &approval,
            "--deadline-ms",
            "5000",
        ];
        args.extend_from_slice(extra);
        event(root, "alert", &args)
    };
    let proposed = alert(&[])?;
    success(&proposed);
    let plan = report_field(&proposed, "plan_digest")?;
    let prepared = alert(&["--approve", &plan])?;
    success(&prepared);
    assert_eq!(report_field(&prepared, "stage")?, "prepared");
    assert_eq!(report_field(&prepared, "effect_state")?, "prepared");
    assert_eq!(report_field(&prepared, "obligation_state")?, "pending");
    Ok(plan)
}

fn run_fss(args: &[OsString]) -> TestResult<(Option<i32>, String, String)> {
    let output = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(args)
        .output()?;
    Ok((
        output.status.code(),
        String::from_utf8(output.stdout)?,
        String::from_utf8(output.stderr)?,
    ))
}

fn command_args(command: &str, root: &Path, extra: &[&str]) -> Vec<OsString> {
    let mut args = vec![
        OsString::from(command),
        OsString::from("--json"),
        OsString::from("--root"),
        root.as_os_str().to_owned(),
    ];
    args.extend(extra.iter().map(OsString::from));
    args
}

fn follow_args(root: &Path, since: &str, extra: &[&str]) -> Vec<OsString> {
    let mut args = command_args("follow", root, &["--since", since]);
    args.extend(extra.iter().map(OsString::from));
    args
}

/// Every entry under `root`: mode, size, times, inode, and content digest (the doctor proof).
fn tree_digest(root: &Path) -> TestResult<BTreeMap<PathBuf, String>> {
    let mut out = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let meta = fs::symlink_metadata(&path)?;
        let relative = path.strip_prefix(root)?.to_path_buf();
        let common = format!(
            "mode={:o} size={} mtime={}.{} ctime={}.{} ino={} nlink={}",
            meta.mode(),
            meta.size(),
            meta.mtime(),
            meta.mtime_nsec(),
            meta.ctime(),
            meta.ctime_nsec(),
            meta.ino(),
            meta.nlink()
        );
        let detail = if meta.file_type().is_dir() {
            let mut names = Vec::new();
            for entry in fs::read_dir(&path)? {
                let entry = entry?;
                names.push(entry.file_name().to_string_lossy().into_owned());
                pending.push(entry.path());
            }
            names.sort();
            format!("dir [{}]", names.join(","))
        } else if meta.file_type().is_file() {
            format!("file {}", ContentDigest::sha256(&fs::read(&path)?))
        } else {
            "special".to_owned()
        };
        out.insert(relative, format!("{common} {detail}"));
    }
    Ok(out)
}

/// The verbatim payload bytes of a rendered envelope (between `"payload":` and `"payloadDigest"`).
fn raw_payload(stdout: &str) -> TestResult<&str> {
    let start = stdout.find(",\"payload\":").ok_or("payload missing")? + ",\"payload\":".len();
    let end = stdout
        .find(",\"payloadDigest\":")
        .ok_or("payload digest missing")?;
    Ok(&stdout[start..end])
}

/// Repository root (the workspace two levels above this crate).
///
/// Prefers the `CARGO_MANIFEST_DIR` that `cargo test` sets when it runs this binary over the one
/// compiled in: a test binary reused from a shared target directory can outlive the source tree it
/// was compiled from (a per-job checkout on a build worker), and the compiled-in path then names a
/// directory that no longer exists.
fn repository_root() -> PathBuf {
    std::env::var_os("CARGO_MANIFEST_DIR")
        .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from)
        .join("../..")
}

/// Validates `instance` against `schemas/<schema>` with the repository's strict Draft 2020-12
/// validator, writing the instance under `scratch` (never under a deployment root).
fn assert_conforms(schema: &str, instance: &str, scratch: &Path, label: &str) -> TestResult {
    let root = repository_root();
    let file = scratch.join(format!(
        "instance-{}.json",
        ContentDigest::sha256(format!("{schema}\n{label}\n{instance}").as_bytes())
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
        "{label}: output does not conform to schemas/{schema}: {}{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    Ok(())
}

/// Validates one rendered envelope against `agent_response_envelope.v1` and, when it carries
/// one, its verbatim payload against `payload_schema`.
fn assert_answer_conforms(
    stdout: &str,
    payload_schema: &str,
    scratch: &Path,
    label: &str,
) -> TestResult {
    assert_conforms(
        "agent_response_envelope.v1.json",
        stdout.trim_end(),
        scratch,
        label,
    )?;
    let payload = raw_payload(stdout)?;
    if payload != "null" {
        assert_conforms(payload_schema, payload, scratch, label)?;
    }
    Ok(())
}

/// Checks the registered envelope shape of every follow answer and refusal.
fn assert_follow_envelope(stdout: &str, view_id: &str) -> TestResult<Json> {
    assert!(stdout.ends_with("}\n"), "one JSON document per line");
    let envelope = Json::parse(stdout.trim_end())?;
    assert_eq!(
        envelope.get("schema")?.text()?,
        "fss.agent_response_envelope.v1"
    );
    assert_eq!(envelope.get("operationId")?.text()?, "AOP-004");
    assert_eq!(envelope.get("effectiveViewId")?.text()?, view_id);
    assert_eq!(
        envelope.get("payloadSchema")?.text()?,
        "fss.agent_meaningful_delta.v1"
    );
    assert_eq!(
        envelope.get("effectiveCapabilities")?.texts()?,
        vec!["CAP-AGENT-SITUATION-READ-001"]
    );
    assert_eq!(
        envelope.get("outputAnchor")?,
        &Json::Null,
        "a read commits nothing"
    );
    assert_eq!(
        envelope.get("payloadDigest")?.text()?,
        ContentDigest::sha256(raw_payload(stdout)?.as_bytes()).to_text()
    );
    assert!(
        envelope
            .path(&["executionBoundary", "possiblyOccurred"])?
            .items()?
            .is_empty()
    );
    Ok(envelope)
}

/// Orients `root` in `view` and returns (the envelope, the anchor token it emits). The token is
/// the envelope's `anchor:` proof pointer; in brief, the follow affordance targets it too.
fn orient(root: &Path, view: &str) -> TestResult<(Json, String)> {
    let (code, stdout, stderr) = run_fss(&command_args("orient", root, &["--view", view]))?;
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let envelope = Json::parse(stdout.trim_end())?;
    let tokens: Vec<String> = envelope
        .get("proofPointers")?
        .texts()?
        .into_iter()
        .filter(|pointer| pointer.starts_with("anchor:"))
        .map(str::to_owned)
        .collect();
    assert_eq!(tokens.len(), 1, "exactly one anchor token: {tokens:?}");
    let token = tokens[0].clone();
    if view == "brief" {
        let follow = envelope
            .get("affordances")?
            .items()?
            .iter()
            .find(|affordance| {
                affordance
                    .get("affordanceId")
                    .and_then(Json::text)
                    .is_ok_and(|id| id == "affordance:orient:follow")
            })
            .ok_or("brief lists the follow affordance")?;
        assert_eq!(follow.get("operationId")?.text()?, "AOP-004");
        assert_eq!(follow.get("robustnessClass")?.text()?, "wait_and_watch");
        let targets = follow.get("targets")?.texts()?;
        assert_eq!(targets.len(), 1);
        assert!(
            targets[0].ends_with(&format!("/follow/{token}")),
            "{targets:?}"
        );
    }
    Ok((envelope, token))
}

/// One successful follow page: (raw stdout, parsed envelope).
fn follow_ok(
    root: &Path,
    since: &str,
    extra: &[&str],
    view_id: &str,
) -> TestResult<(String, Json)> {
    let (code, stdout, stderr) = run_fss(&follow_args(root, since, extra))?;
    assert_eq!(code, Some(0), "stdout: {stdout} stderr: {stderr}");
    let envelope = assert_follow_envelope(&stdout, view_id)?;
    assert_eq!(envelope.get("outcome")?.text()?, "ok");
    assert_eq!(envelope.get("errorId")?, &Json::Null);
    Ok((stdout, envelope))
}

/// A refused follow: asserts the exit, the error identity, the null payload, and conformance.
fn follow_refused(
    root: &Path,
    since: &str,
    extra: &[&str],
    error_id: &str,
    scratch: &Path,
) -> TestResult {
    let (code, stdout, stderr) = run_fss(&follow_args(root, since, extra))?;
    assert_eq!(code, Some(5), "stdout: {stdout} stderr: {stderr}");
    let view = if extra.contains(&"brief") {
        "AVIEW-002"
    } else {
        "AVIEW-001"
    };
    let envelope = assert_follow_envelope(&stdout, view)?;
    assert_eq!(envelope.get("outcome")?.text()?, "refused");
    assert_eq!(envelope.get("errorId")?.text()?, error_id);
    assert_eq!(envelope.get("payload")?, &Json::Null);
    assert_eq!(envelope.get("continuation")?, &Json::Null);
    assert_eq!(envelope.get("recoveryClass")?.text()?, "rebase_required");
    assert_answer_conforms(
        &stdout,
        "agent_meaningful_delta.v1.json",
        scratch,
        &format!("refusal {error_id} {extra:?}"),
    )
}

fn frame_id(orientation: &Json) -> TestResult<&str> {
    orientation
        .path(&["payload", "situationFrame", "frameId"])?
        .text()
}

fn cell_ids(payload: &Json) -> TestResult<Vec<&str>> {
    payload
        .get("changedCells")?
        .items()?
        .iter()
        .map(|cell| cell.get("cellId")?.text())
        .collect()
}

const LISTS: [&str; 5] = [
    "effectUncertaintyChanges",
    "obligationChanges",
    "invalidatedAssumptions",
    "coverageChanges",
    "removedClaimIds",
];

// ---------------------------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------------------------

/// Serializes this binary's tests. Tests open a `ReferenceDeployment` in this process, which holds
/// its native flock owner lock, and spawn real CLI processes. A child spawned by a concurrent test
/// thread inherits, until its exec closes it, every descriptor open at that instant, including
/// another test's held deployment lock; the flock then outlives its owner's drop, and that test's
/// next child or read-only inspection sees the deployment as Locked or as having an active writer.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn follow_since_an_empty_orientation_names_the_new_unresolved_event() -> TestResult {
    let _serial = serial();
    let directory = OwnedDirectory::new("new-event")?;
    let root = empty_deployment(&directory, SITE)?;
    let (empty_orientation, since) = orient(&root, "brief")?;
    assert_eq!(
        empty_orientation
            .path(&["inputAnchor", "capsuleSequence"])?
            .number()?,
        0
    );
    let import_id = import(&directory, Motion::Right, "sensor:follow-cli", false)?;
    let event_id = publish_watch_candidate(&root, &import_id)?;
    let before = tree_digest(&root)?;

    let (stdout, envelope) = follow_ok(&root, &since, &["--view", "brief"], "AVIEW-002")?;
    assert_answer_conforms(
        &stdout,
        "agent_meaningful_delta.v1.json",
        &directory.0,
        "new event",
    )?;
    let delta = envelope.get("payload")?;
    // The basis is exactly the situation the first orientation answered with.
    assert_eq!(
        delta.get("basisFrameId")?.text()?,
        frame_id(&empty_orientation)?
    );
    assert_eq!(
        delta.path(&["basisAnchor", "capsuleSequence"])?.number()?,
        0
    );
    let (head, head_token) = orient(&root, "brief")?;
    assert_eq!(delta.get("resultFrameId")?.text()?, frame_id(&head)?);
    assert_eq!(
        delta.path(&["resultAnchor", "capsuleSequence"])?.number()?,
        head.path(&["inputAnchor", "capsuleSequence"])?.number()?
    );
    assert!(
        envelope
            .get("proofPointers")?
            .texts()?
            .contains(&since.as_str())
    );
    assert!(
        envelope
            .get("proofPointers")?
            .texts()?
            .contains(&head_token.as_str())
    );
    let classes = delta.get("classes")?.texts()?;
    assert!(classes.contains(&"material_state"), "{classes:?}");
    assert!(classes.contains(&"coverage_loss"), "{classes:?}");
    assert_eq!(delta.get("priority")?.text()?, "critical");
    assert_eq!(delta.get("silenceCertificate")?, &Json::Null);
    // The new event is named, unresolved (indeterminate), by the changed event summary cell.
    let events = delta
        .get("changedCells")?
        .items()?
        .iter()
        .find(|cell| {
            cell.get("cellId")
                .and_then(Json::text)
                .is_ok_and(|id| id == "claim:deployment:events")
        })
        .ok_or("the published-event summary cell changed")?;
    let statement = events.get("value")?.text()?;
    assert!(
        statement.starts_with("1 published event: 1 indeterminate; 0 corroborated"),
        "{statement}"
    );
    assert!(statement.contains(&event_id), "{statement}");
    assert!(cell_ids(delta)?.contains(&"claim:deployment:ledger-head"));
    // A single page: nothing continues, nothing is coalesced or omitted.
    assert_eq!(envelope.get("continuation")?, &Json::Null);
    assert_eq!(envelope.get("recoveryClass")?.text()?, "safe_read_retry");
    assert_eq!(delta.get("omittedCount")?.number()?, 0);
    assert_eq!(delta.get("coalescedCount")?.number()?, 0);

    // Deterministic, and read-only.
    let (again, _) = follow_ok(&root, &since, &["--view", "brief"], "AVIEW-002")?;
    assert_eq!(again, stdout, "byte-identical follow");
    // The default view is pulse (AOP-004's registered view).
    let (pulse, pulse_envelope) = follow_ok(&root, &since, &[], "AVIEW-001")?;
    assert_answer_conforms(
        &pulse,
        "agent_meaningful_delta.v1.json",
        &directory.0,
        "new event pulse",
    )?;
    let (pulse_orientation, _) = orient(&root, "pulse")?;
    assert_eq!(
        pulse_envelope.path(&["payload", "resultFrameId"])?.text()?,
        frame_id(&pulse_orientation)?
    );
    assert_eq!(tree_digest(&root)?, before, "follow writes nothing");
    Ok(())
}

#[test]
fn follow_since_the_current_anchor_changes_nothing_but_keeps_the_coverage_gap_protected()
-> TestResult {
    let _serial = serial();
    let directory = OwnedDirectory::new("current")?;
    let root = empty_deployment(&directory, SITE)?;
    let import_id = import(&directory, Motion::Right, "sensor:follow-cli", false)?;
    publish_watch_candidate(&root, &import_id)?;
    let (orientation, since) = orient(&root, "brief")?;
    let before = tree_digest(&root)?;
    let (stdout, envelope) = follow_ok(&root, &since, &["--view", "brief"], "AVIEW-002")?;
    assert_answer_conforms(
        &stdout,
        "agent_meaningful_delta.v1.json",
        &directory.0,
        "current anchor",
    )?;
    let delta = envelope.get("payload")?;
    assert_eq!(delta.get("basisFrameId")?.text()?, frame_id(&orientation)?);
    assert_eq!(delta.get("resultFrameId")?.text()?, frame_id(&orientation)?);
    // Nothing committed changed: no changed or removed cell, no obligation, effect, or plan
    // change. The engine still reports the persisting coverage gap (no retained CoverageWitness)
    // as protected coverage loss, so no silence certificate is issued.
    assert_eq!(delta.get("classes")?.texts()?, vec!["coverage_loss"]);
    assert!(delta.get("changedCells")?.items()?.is_empty());
    for list in [
        "removedClaimIds",
        "invalidatedAssumptions",
        "obligationChanges",
        "effectUncertaintyChanges",
    ] {
        assert!(delta.get(list)?.items()?.is_empty(), "{list}");
    }
    let coverage = delta.get("coverageChanges")?.texts()?;
    assert!(
        coverage
            .iter()
            .any(|change| change.contains("remains degraded at Partial")),
        "{coverage:?}"
    );
    assert!(
        coverage
            .iter()
            .any(|change| change.contains("claim:coverage:site")),
        "{coverage:?}"
    );
    assert_eq!(delta.get("silenceCertificate")?, &Json::Null);
    assert_eq!(delta.get("priority")?.text()?, "critical");
    assert!(
        envelope
            .get("degradation")?
            .texts()?
            .iter()
            .any(|line| line.starts_with("No silence certificate:"))
    );
    assert_eq!(tree_digest(&root)?, before, "follow writes nothing");
    Ok(())
}

#[test]
fn a_prepared_alert_is_a_protected_obligation_and_effect_uncertainty_delta() -> TestResult {
    let _serial = serial();
    let directory = OwnedDirectory::new("alert")?;
    let event_id = publish_corroborated_event(&directory)?;
    let root = directory.root();
    let (orientation, since) = orient(&root, "brief")?;
    assert!(
        orientation
            .path(&["payload", "obligations"])?
            .items()?
            .is_empty()
    );
    let plan = prepare_alert(&root, &event_id)?;
    let before = tree_digest(&root)?;

    let (stdout, envelope) = follow_ok(&root, &since, &["--view", "brief"], "AVIEW-002")?;
    assert_answer_conforms(
        &stdout,
        "agent_meaningful_delta.v1.json",
        &directory.0,
        "prepared alert",
    )?;
    let delta = envelope.get("payload")?;
    assert_eq!(delta.get("basisFrameId")?.text()?, frame_id(&orientation)?);
    let classes = delta.get("classes")?.texts()?;
    for protected in ["obligation", "effect_uncertainty", "coverage_loss"] {
        assert!(classes.contains(&protected), "{protected} in {classes:?}");
    }
    assert_eq!(delta.get("priority")?.text()?, "critical");
    let (head, _) = orient(&root, "brief")?;
    let obligations = head.path(&["payload", "obligations"])?.texts()?;
    assert_eq!(
        obligations.len(),
        1,
        "one pending obligation: {obligations:?}"
    );
    assert_eq!(
        delta.get("obligationChanges")?.texts()?,
        vec![format!("obligation added: {}", obligations[0]).as_str()]
    );
    // The prepared operation has not crossed the boundary: its local-state effect cell is
    // `unknown`, and the engine reports the unproved outcome as effect uncertainty.
    let effect_cells: Vec<&Json> = delta
        .get("changedCells")?
        .items()?
        .iter()
        .filter(|cell| {
            cell.get("cellId")
                .and_then(Json::text)
                .is_ok_and(|id| id.starts_with("claim:effect:") && id.ends_with(":local-state"))
        })
        .collect();
    assert_eq!(effect_cells.len(), 1);
    assert_eq!(effect_cells[0].get("knowledgeState")?.text()?, "unknown");
    assert_eq!(effect_cells[0].get("provenanceClass")?.text()?, "observed");
    let effect_claim = effect_cells[0].get("cellId")?.text()?;
    assert_eq!(
        delta.get("effectUncertaintyChanges")?.texts()?,
        vec![
            format!("effect uncertainty remains: effect {effect_claim} is unknown without a proved outcome")
                .as_str()
        ]
    );
    // Protected classes are declared never coalesced.
    assert!(envelope.get("warnings")?.texts()?.iter().any(|line| {
        line.starts_with("Protected classes [")
            && line.contains("obligation")
            && line.contains("effect_uncertainty")
    }));
    assert!(!plan.is_empty());
    assert_eq!(tree_digest(&root)?, before, "follow writes nothing");
    Ok(())
}

#[test]
fn small_budgets_page_every_item_through_bound_continuations() -> TestResult {
    let _serial = serial();
    let directory = OwnedDirectory::new("pages")?;
    let root = directory.root();
    let (_, empty_token) = {
        let root = empty_deployment(&directory, SITE)?;
        orient(&root, "brief")?
    };
    let event_id = publish_corroborated_event(&directory)?;
    prepare_alert(&root, &event_id)?;
    let before = tree_digest(&root)?;

    let (complete_stdout, complete) = follow_ok(
        &root,
        &empty_token,
        &["--view", "brief", "--max-entries", "4096"],
        "AVIEW-002",
    )?;
    assert_answer_conforms(
        &complete_stdout,
        "agent_meaningful_delta.v1.json",
        &directory.0,
        "complete",
    )?;
    let full = complete.get("payload")?;
    let classes = full.get("classes")?.texts()?;
    let mut expected: Vec<(String, String)> = Vec::new();
    for list in LISTS {
        for text in full.get(list)?.texts()? {
            expected.push((list.to_owned(), text.to_owned()));
        }
    }
    for cell in cell_ids(full)? {
        expected.push(("changedCells".to_owned(), cell.to_owned()));
    }
    assert!(expected.len() > 6, "{expected:?}");

    let mut delivered: Vec<(String, String)> = Vec::new();
    let mut continuation: Option<String> = None;
    let mut first_token = None;
    let mut pages = 0;
    loop {
        let mut extra = vec!["--view", "brief", "--max-entries", "3"];
        if let Some(token) = &continuation {
            extra.extend(["--continuation", token.as_str()]);
        }
        let (stdout, envelope) = follow_ok(&root, &empty_token, &extra, "AVIEW-002")?;
        assert_answer_conforms(
            &stdout,
            "agent_meaningful_delta.v1.json",
            &directory.0,
            &format!("page {pages}"),
        )?;
        pages += 1;
        let page = envelope.get("payload")?;
        // Every page is the same delta and carries its complete class set.
        assert_eq!(page.get("deltaId")?, full.get("deltaId")?);
        assert_eq!(page.get("classes")?.texts()?, classes);
        assert_eq!(page.get("priority")?, full.get("priority")?);
        let mut items = 0;
        for list in LISTS {
            for text in page.get(list)?.texts()? {
                delivered.push((list.to_owned(), text.to_owned()));
                items += 1;
            }
        }
        for cell in cell_ids(page)? {
            delivered.push(("changedCells".to_owned(), cell.to_owned()));
            items += 1;
        }
        assert!(items <= 3, "a page never exceeds its budget");
        match envelope.get("continuation")? {
            Json::Null => {
                assert_eq!(envelope.get("recoveryClass")?.text()?, "safe_read_retry");
                break;
            }
            next => {
                let next = next.text()?.to_owned();
                assert_eq!(items, 3);
                assert_eq!(page.get("continuation")?.text()?, next);
                assert_eq!(
                    envelope.get("recoveryClass")?.text()?,
                    "resume_from_continuation"
                );
                first_token.get_or_insert_with(|| next.clone());
                continuation = Some(next);
            }
        }
    }
    assert!(pages > 2, "{pages} pages");
    // Every item arrives exactly once, protected items first, and nothing is truncated.
    assert_eq!(delivered, expected);
    let first_cell = delivered
        .iter()
        .position(|(list, _)| list == "changedCells")
        .unwrap_or(delivered.len());
    assert!(
        delivered[..first_cell]
            .iter()
            .any(|(list, _)| list == "obligationChanges")
    );
    assert!(
        delivered[..first_cell]
            .iter()
            .any(|(list, _)| list == "effectUncertaintyChanges")
    );

    let token = first_token.ok_or("a first continuation")?;
    // Replaying a continuation returns the same page.
    let replay = [
        "--view",
        "brief",
        "--max-entries",
        "3",
        "--continuation",
        token.as_str(),
    ];
    let (first, _) = follow_ok(&root, &empty_token, &replay, "AVIEW-002")?;
    let (second, _) = follow_ok(&root, &empty_token, &replay, "AVIEW-002")?;
    assert_eq!(first, second);
    // An altered token, or a token of another stream, is refused.
    let mut altered = token.clone();
    let last = altered.pop().ok_or("token is non-empty")?;
    altered.push(if last == '0' { '1' } else { '0' });
    let (_, head_token) = orient(&root, "brief")?;
    for (since, extra) in [
        (
            empty_token.as_str(),
            vec![
                "--view",
                "brief",
                "--max-entries",
                "3",
                "--continuation",
                altered.as_str(),
            ],
        ),
        (
            empty_token.as_str(),
            vec![
                "--view",
                "brief",
                "--max-entries",
                "2",
                "--continuation",
                token.as_str(),
            ],
        ),
        (
            head_token.as_str(),
            vec![
                "--view",
                "brief",
                "--max-entries",
                "3",
                "--continuation",
                token.as_str(),
            ],
        ),
    ] {
        follow_refused(
            &root,
            since,
            &extra,
            "ERR-AGENT-FOLLOW-CONTINUATION-001",
            &directory.0,
        )?;
    }
    assert_eq!(tree_digest(&root)?, before, "follow writes nothing");
    Ok(())
}

#[test]
fn unknown_foreign_ahead_and_malformed_anchors_are_typed_refusals() -> TestResult {
    let _serial = serial();
    let directory = OwnedDirectory::new("refusals")?;
    let root = empty_deployment(&directory, SITE)?;
    let import_id = import(&directory, Motion::Right, "sensor:follow-cli", false)?;
    publish_watch_candidate(&root, &import_id)?;
    let (_, token) = orient(&root, "brief")?;
    let other_directory = OwnedDirectory::new("refusals-other")?;
    let other = empty_deployment(&other_directory, OTHER_SITE)?;
    let (_, foreign) = orient(&other, "brief")?;
    let before = tree_digest(&root)?;

    let parts: Vec<&str> = token.split(':').collect();
    assert_eq!(parts.len(), 5, "{token}");
    let ahead = format!("anchor:{}:{}:{}:{}", parts[1], 99, parts[3], parts[4]);
    let altered = format!(
        "anchor:{}:{}:{}:{}",
        parts[1],
        parts[2],
        parts[3],
        "0".repeat(64)
    );
    let earlier = format!("anchor:{}:{}:{}:{}", parts[1], 0, parts[3], parts[4]);
    for (since, error_id) in [
        (foreign.as_str(), "ERR-AGENT-FOLLOW-ANCHOR-FOREIGN-001"),
        (ahead.as_str(), "ERR-AGENT-FOLLOW-ANCHOR-AHEAD-001"),
        (altered.as_str(), "ERR-AGENT-FOLLOW-ANCHOR-UNKNOWN-001"),
        (earlier.as_str(), "ERR-AGENT-FOLLOW-ANCHOR-UNKNOWN-001"),
    ] {
        follow_refused(&root, since, &[], error_id, &directory.0)?;
        follow_refused(&root, since, &["--view", "brief"], error_id, &directory.0)?;
    }

    let root_text = root.to_str().ok_or("temporary path is not UTF-8")?;
    for (args, error_id) in [
        (
            vec!["follow", "--json", "--root", root_text],
            "ERR-CLI-MISSING-VALUE-001",
        ),
        (
            vec![
                "follow", "--json", "--root", root_text, "--since", "commit:3",
            ],
            "ERR-CLI-MALFORMED-VALUE-001",
        ),
        (
            vec![
                "follow",
                "--json",
                "--root",
                root_text,
                "--since",
                token.as_str(),
                "--view",
                "epistemic_map",
            ],
            "ERR-CLI-MALFORMED-VALUE-001",
        ),
        (
            vec![
                "follow",
                "--json",
                "--root",
                root_text,
                "--since",
                token.as_str(),
                "--max-entries",
                "0",
            ],
            "ERR-CLI-MALFORMED-VALUE-001",
        ),
        (
            vec![
                "follow",
                "--json",
                "--root",
                root_text,
                "--since",
                token.as_str(),
                "extra",
            ],
            "ERR-CLI-TRAILING-ARGUMENT-001",
        ),
    ] {
        let os_args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let (code, stdout, stderr) = run_fss(&os_args)?;
        assert_eq!(code, Some(2), "{args:?}");
        assert_eq!(stdout, "", "no answer on an argument error: {args:?}");
        assert!(
            stderr.starts_with(&format!("fss: error[{error_id}]")),
            "{args:?}: {stderr}"
        );
    }

    let missing = directory.0.join("missing");
    let (code, stdout, _) = run_fss(&follow_args(&missing, &token, &[]))?;
    assert_eq!(code, Some(4));
    assert!(stdout.contains("\"error_id\":\"ERR-DOCTOR-NOT-A-DEPLOYMENT-001\""));
    assert!(!missing.exists(), "a refused read creates nothing");
    assert_eq!(tree_digest(&root)?, before, "refusals write nothing");
    Ok(())
}
