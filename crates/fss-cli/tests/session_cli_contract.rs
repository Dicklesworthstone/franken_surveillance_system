#![forbid(unsafe_code)]
//! Contract tests for `fss session open` (AOP-001), `fss session handoff` (AOP-012), and
//! `fss session resume` (AOP-002) through the real `fss` binary, over deployments built with the
//! real `fss-file import` and `fss-event watch --approve` flows:
//!
//! 1. open -> handoff -> resume on an unchanged deployment invalidates nothing and rebases nothing;
//! 2. open -> handoff -> a watch event is published -> resume lists the change and every
//!    invalidated assumption, and rebases the session onto the head exactly once;
//! 3. unknown sessions, unknown, tampered, and foreign handoffs, and non-deployments are typed
//!    refusals;
//! 4. an identical open, handoff, or resume is an exact, byte-identical retry;
//! 5. every answer and refusal validates against its registered schemas
//!    (`scripts/json_instance_validate.py`): the envelope, the situation capsule, the handoff
//!    capsule, and the session and workspace revision published beside the handoff;
//! 6. the authority ledger, the effect journal, and the deployment spool are byte-identical before
//!    and after every session command: only agent-plane state under `agent/` is written.
//!
//! Crash safety of the root-last handoff publication at every cut point is proven by the
//! `fss_reference::deployment_session` unit tests, which can inject the publisher's crash points.

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
const SITE: &str = "site:session-cli";
const OTHER_SITE: &str = "site:session-cli-other";
const MISSION: &str = "Keep the east door under watch overnight.";
const OBJECTIVE: &str = "Know whether anyone entered through the east door.";

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
                "fss-session-cli-{name}-{}-{attempt}",
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
        trace_id: "trace:session-cli".to_owned(),
        operation_id: OperationId::parse("operation:session-cli")?,
        principal: "operator:session-cli".to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: fss_core::BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"session-cli"),
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

/// A bright 16x16 square enters at the left edge from frame 3 and moves 8 px right per frame.
fn scene() -> TestResult<Vec<u8>> {
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
            let left = (index - 3) * 8;
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
fn import(directory: &OwnedDirectory, sensor: &str, capture_hint: bool) -> TestResult<String> {
    let input = directory
        .0
        .join(format!("{sensor}.mjpeg").replace(':', "-"));
    fs::write(&input, scene()?)?;
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
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
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

// ---------------------------------------------------------------------------------------------
// Session helpers.
// ---------------------------------------------------------------------------------------------

fn session_args(root: &Path, sub: &str, extra: &[&str]) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("session"),
        OsString::from(sub),
        OsString::from("--json"),
        OsString::from("--root"),
        root.as_os_str().to_owned(),
    ];
    args.extend(extra.iter().map(OsString::from));
    args
}

/// Every file of the authority ledger, the effect journal, the deployment spool, and `LAYOUT`
/// (mode, size, times, inode, and content digest): the state no session command may touch.
fn authority_tree(root: &Path) -> TestResult<BTreeMap<PathBuf, String>> {
    Ok(tree_digest(root)?
        .into_iter()
        .filter(|(path, _)| {
            ["ledger", "effects", "objects", "LAYOUT"]
                .iter()
                .any(|prefix| path.starts_with(prefix))
        })
        .collect())
}

/// Checks the registered envelope shape of one session answer or refusal.
fn assert_session_envelope(
    stdout: &str,
    operation_id: &str,
    payload_schema: &str,
    capability: &str,
) -> TestResult<Json> {
    assert!(stdout.ends_with("}\n"), "one JSON document per line");
    let envelope = Json::parse(stdout.trim_end())?;
    assert_eq!(
        envelope.get("schema")?.text()?,
        "fss.agent_response_envelope.v1"
    );
    assert_eq!(envelope.get("operationId")?.text()?, operation_id);
    assert_eq!(envelope.get("payloadSchema")?.text()?, payload_schema);
    assert_eq!(
        envelope.get("effectiveCapabilities")?.texts()?,
        vec![capability]
    );
    assert_eq!(
        envelope.get("outputAnchor")?,
        &Json::Null,
        "no authority is ever committed"
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

/// One successful session command: (raw stdout, parsed and schema-validated envelope).
fn session_ok(
    root: &Path,
    sub: &str,
    extra: &[&str],
    scratch: &Path,
) -> TestResult<(String, Json)> {
    let (code, stdout, stderr) = run_fss(&session_args(root, sub, extra))?;
    assert_eq!(code, Some(0), "stdout: {stdout} stderr: {stderr}");
    let (operation, schema, capability, payload_file) = match sub {
        "open" => (
            "AOP-001",
            "fss.situation_capsule.v1",
            "CAP-AGENT-SESSION-OPEN-001",
            "situation_capsule.v1.json",
        ),
        "handoff" => (
            "AOP-012",
            "fss.agent_handoff_capsule.v1",
            "CAP-AGENT-HANDOFF-WRITE-001",
            "agent_handoff_capsule.v1.json",
        ),
        _ => (
            "AOP-002",
            "fss.situation_capsule.v1",
            "CAP-AGENT-SESSION-READ-001",
            "situation_capsule.v1.json",
        ),
    };
    let envelope = assert_session_envelope(&stdout, operation, schema, capability)?;
    assert_eq!(envelope.get("outcome")?.text()?, "ok");
    assert_eq!(envelope.get("errorId")?, &Json::Null);
    assert!(
        envelope
            .get("idempotencyKey")?
            .text()?
            .starts_with("idempotency:")
    );
    envelope.get("workspaceRevision")?.number()?;
    assert_answer_conforms(&stdout, payload_file, scratch, &format!("session {sub}"))?;
    Ok((stdout, envelope))
}

/// A refused session command: asserts the exit, the error identity, the null payload, and
/// conformance.
fn session_refused(
    root: &Path,
    sub: &str,
    extra: &[&str],
    error_id: &str,
    scratch: &Path,
) -> TestResult<Json> {
    let (code, stdout, stderr) = run_fss(&session_args(root, sub, extra))?;
    assert_eq!(code, Some(5), "stdout: {stdout} stderr: {stderr}");
    let (operation, schema, capability) = match sub {
        "open" => (
            "AOP-001",
            "fss.situation_capsule.v1",
            "CAP-AGENT-SESSION-OPEN-001",
        ),
        "handoff" => (
            "AOP-012",
            "fss.agent_handoff_capsule.v1",
            "CAP-AGENT-HANDOFF-WRITE-001",
        ),
        _ => (
            "AOP-002",
            "fss.situation_capsule.v1",
            "CAP-AGENT-SESSION-READ-001",
        ),
    };
    let envelope = assert_session_envelope(&stdout, operation, schema, capability)?;
    assert_eq!(envelope.get("outcome")?.text()?, "refused");
    assert_eq!(envelope.get("errorId")?.text()?, error_id);
    assert_eq!(envelope.get("payload")?, &Json::Null);
    assert_eq!(envelope.get("sessionId")?, &Json::Null);
    assert_answer_conforms(&stdout, "situation_capsule.v1.json", scratch, error_id)?;
    Ok(envelope)
}

fn open(root: &Path, scratch: &Path) -> TestResult<(String, Json)> {
    session_ok(
        root,
        "open",
        &["--mission", MISSION, "--objective", OBJECTIVE],
        scratch,
    )
}

/// Hands `session` off and validates the session and workspace revision published beside it.
fn handoff(root: &Path, session: &str, scratch: &Path) -> TestResult<(String, Json)> {
    let (stdout, envelope) = session_ok(
        root,
        "handoff",
        &["--session", session, "--note", "night shift ends"],
        scratch,
    )?;
    let publications = root.join("agent/publications");
    let mut found = Vec::new();
    for pointer in envelope.get("proofPointers")?.texts()? {
        let Ok(digest) = ContentDigest::parse(pointer) else {
            continue;
        };
        let Ok(bytes) = fss_publication::read_verified(&publications, digest, 1 << 20) else {
            continue;
        };
        // Only the rendered public projections are JSON; the record and manifests are canonical
        // binary objects.
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        if !text.starts_with('{') {
            continue;
        }
        let document = Json::parse(&text)?;
        let schema = document.get("schema")?.text()?.to_owned();
        let file = match schema.as_str() {
            "fss.agent_session.v1" => "agent_session.v1.json",
            "fss.agent_session_capsule.v1" => "agent_session_capsule.v1.json",
            other => return Err(format!("unexpected published child {other}").into()),
        };
        assert_conforms(file, &text, scratch, &schema)?;
        assert_eq!(document.get("sessionId")?.text()?, session);
        found.push(schema);
    }
    found.sort();
    assert_eq!(
        found,
        vec!["fss.agent_session.v1", "fss.agent_session_capsule.v1"],
        "the handoff publishes the session and its workspace revision"
    );
    Ok((stdout, envelope))
}

fn payload(envelope: &Json) -> TestResult<&Json> {
    envelope.get("payload")
}

fn files_under(directory: &Path) -> TestResult<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(&path)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                out.push(entry.path());
            }
        }
    }
    out.sort();
    Ok(out)
}

fn copy_tree(from: &Path, to: &Path) -> TestResult {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------------------------

#[test]
fn open_handoff_resume_on_an_unchanged_deployment_invalidates_nothing() -> TestResult {
    let directory = OwnedDirectory::new("unchanged")?;
    let root = empty_deployment(&directory, SITE)?;
    let scratch = directory.0.clone();
    let authority = authority_tree(&root)?;

    let (_, opened) = open(&root, &scratch)?;
    let session = opened.get("sessionId")?.text()?.to_owned();
    assert!(session.starts_with("session:"));
    assert!(opened.get("missionId")?.text()?.starts_with("mission:"));
    assert_eq!(opened.get("workspaceRevision")?.number()?, 0);
    assert_eq!(opened.get("effectiveViewId")?.text()?, "AVIEW-002");
    assert_eq!(payload(&opened)?.get("sessionId")?.text()?, session);
    assert_eq!(payload(&opened)?.get("meaningfulDelta")?, &Json::Null);
    let token = opened
        .get("proofPointers")?
        .texts()?
        .into_iter()
        .find(|pointer| pointer.starts_with("anchor:"))
        .ok_or("open names its anchor token")?
        .to_owned();

    let (_, handed) = handoff(&root, &session, &scratch)?;
    assert_eq!(handed.get("effectiveViewId")?.text()?, "AVIEW-006");
    let capsule = payload(&handed)?;
    assert_eq!(capsule.get("sourceSessionId")?.text()?, session);
    assert_eq!(capsule.get("objective")?.text()?, OBJECTIVE);
    assert!(
        capsule
            .get("childRoots")?
            .texts()?
            .contains(&capsule.get("situationCapsuleRoot")?.text()?)
    );
    assert!(
        capsule
            .get("assumptions")?
            .items()?
            .iter()
            .any(|assumption| assumption
                .get("basis")
                .and_then(Json::texts)
                .is_ok_and(|basis| basis == vec![token.as_str()]))
    );
    let handoff_id = capsule.get("handoffId")?.text()?.to_owned();

    let (_, resumed) = session_ok(&root, "resume", &["--handoff", &handoff_id], &scratch)?;
    assert_eq!(resumed.get("sessionId")?.text()?, session);
    assert_eq!(resumed.get("workspaceRevision")?.number()?, 0);
    assert!(
        resumed
            .path(&["executionBoundary", "invalidated"])?
            .items()?
            .is_empty()
    );
    let situation = payload(&resumed)?;
    assert_eq!(situation.get("previousAnchor")?, situation.get("anchor")?);
    let delta = situation.get("meaningfulDelta")?;
    for list in ["invalidatedAssumptions", "changedCells", "removedClaimIds"] {
        assert!(delta.get(list)?.items()?.is_empty(), "{list}");
    }
    assert_eq!(
        authority_tree(&root)?,
        authority,
        "only agent-plane state is written"
    );
    Ok(())
}

#[test]
fn resume_after_a_watch_event_lists_the_change_and_every_invalidated_assumption() -> TestResult {
    let directory = OwnedDirectory::new("watch")?;
    let root = empty_deployment(&directory, SITE)?;
    let scratch = directory.0.clone();
    let (_, opened) = open(&root, &scratch)?;
    let session = opened.get("sessionId")?.text()?.to_owned();
    let (_, handed) = handoff(&root, &session, &scratch)?;
    let handoff_id = payload(&handed)?.get("handoffId")?.text()?.to_owned();

    let import_id = import(&directory, "sensor:east", false)?;
    let event_id = publish_watch_candidate(&root, &import_id)?;
    let authority = authority_tree(&root)?;

    let (stdout, resumed) = session_ok(&root, "resume", &["--handoff", &handoff_id], &scratch)?;
    assert_eq!(resumed.get("workspaceRevision")?.number()?, 1);
    let invalidated = resumed
        .path(&["executionBoundary", "invalidated"])?
        .texts()?;
    assert!(
        invalidated
            .iter()
            .any(|line| line.starts_with("assumption assumption:anchor-current invalidated")),
        "{invalidated:?}"
    );
    assert!(
        invalidated
            .iter()
            .any(|line| line.starts_with("claim claim:deployment:ledger-head changed")),
        "the ledger head is an invalidated anchor-bound fact: {invalidated:?}"
    );
    assert!(
        stdout.contains(&event_id),
        "the resumed situation names the new event"
    );
    let situation = payload(&resumed)?;
    assert_eq!(
        situation
            .path(&["previousAnchor", "capsuleSequence"])?
            .number()?,
        0
    );
    assert!(situation.path(&["anchor", "capsuleSequence"])?.number()? > 0);
    let delta = situation.get("meaningfulDelta")?;
    assert!(!delta.get("changedCells")?.items()?.is_empty());
    assert!(situation.get("epistemicDebt")?.items()?.iter().any(|item| {
        item.get("debtId")
            .and_then(Json::text)
            .is_ok_and(|id| id == "assumption:anchor-current")
    }));
    assert!(
        resumed
            .get("warnings")?
            .texts()?
            .iter()
            .any(|warning| warning.contains("moved since the handoff"))
    );
    assert_eq!(
        authority_tree(&root)?,
        authority,
        "resume writes no authority"
    );

    // Resuming again is an exact retry: nothing is rebased twice and the answer is identical.
    let journal = fs::read(root.join("agent/sessions/journal.fssj"))?;
    let (again, _) = session_ok(&root, "resume", &["--handoff", &handoff_id], &scratch)?;
    assert_eq!(again, stdout);
    assert_eq!(fs::read(root.join("agent/sessions/journal.fssj"))?, journal);

    // A handoff of the rebased session is sealed at the new head.
    let (_, rehanded) = handoff(&root, &session, &scratch)?;
    assert_eq!(
        payload(&rehanded)?
            .path(&["anchor", "capsuleSequence"])?
            .number()?,
        situation.path(&["anchor", "capsuleSequence"])?.number()?
    );
    Ok(())
}

#[test]
fn unknown_tampered_and_foreign_handoffs_are_typed_refusals() -> TestResult {
    let directory = OwnedDirectory::new("refusals")?;
    let root = empty_deployment(&directory, SITE)?;
    let scratch = directory.0.clone();
    let (_, opened) = open(&root, &scratch)?;
    let session = opened.get("sessionId")?.text()?.to_owned();
    let (_, handed) = handoff(&root, &session, &scratch)?;
    let handoff_id = payload(&handed)?.get("handoffId")?.text()?.to_owned();

    session_refused(
        &root,
        "handoff",
        &["--session", "session:unknown"],
        "ERR-AGENT-SESSION-NOT-FOUND-001",
        &scratch,
    )?;
    session_refused(
        &root,
        "handoff",
        &["--session", &session, "--principal", "principal:stranger"],
        "ERR-AGENT-SESSION-NOT-FOUND-001",
        &scratch,
    )?;
    session_refused(
        &root,
        "resume",
        &["--handoff", "handoff:unknown"],
        "ERR-AGENT-HANDOFF-NOT-FOUND-001",
        &scratch,
    )?;
    session_refused(
        &root,
        "resume",
        &[
            "--handoff",
            &handoff_id,
            "--principal",
            "principal:stranger",
        ],
        "ERR-AGENT-HANDOFF-INVALID-001",
        &scratch,
    )?;

    // Foreign: the handoff publication copied into another deployment.
    let other_directory = OwnedDirectory::new("refusals-foreign")?;
    let other = empty_deployment(&other_directory, OTHER_SITE)?;
    copy_tree(
        &root.join("agent/publications"),
        &other.join("agent/publications"),
    )?;
    session_refused(
        &other,
        "resume",
        &["--handoff", &handoff_id],
        "ERR-AGENT-HANDOFF-INVALID-001",
        &scratch,
    )?;

    // Tampered: one byte of the published handoff record flipped in the spool.
    let mut tampered = 0;
    for file in files_under(&root.join("agent/publications/spool"))? {
        let mut bytes = fs::read(&file)?;
        if bytes
            .windows(handoff_id.len())
            .any(|window| window == handoff_id.as_bytes())
            && !bytes.starts_with(b"{")
        {
            let last = bytes.len() - 1;
            bytes[last] ^= 0x01;
            fs::write(&file, bytes)?;
            tampered += 1;
        }
    }
    assert!(tampered > 0, "the handoff record is in the spool");
    session_refused(
        &root,
        "resume",
        &["--handoff", &handoff_id],
        "ERR-AGENT-HANDOFF-INVALID-001",
        &scratch,
    )?;

    // A root that is not a deployment is the doctor's refusal, before any session state.
    let (code, stdout, _) = run_fss(&session_args(
        &directory.0.join("missing"),
        "resume",
        &["--handoff", &handoff_id],
    ))?;
    assert_eq!(code, Some(4), "{stdout}");
    assert!(stdout.contains("ERR-DOCTOR-NOT-A-DEPLOYMENT-001"));
    assert!(!directory.0.join("missing").exists(), "nothing is created");
    Ok(())
}

#[test]
fn identical_open_and_handoff_are_byte_identical_exact_retries() -> TestResult {
    let directory = OwnedDirectory::new("idempotent")?;
    let root = empty_deployment(&directory, SITE)?;
    let scratch = directory.0.clone();
    let (first, opened) = open(&root, &scratch)?;
    let journal = fs::read(root.join("agent/sessions/journal.fssj"))?;
    let (second, _) = open(&root, &scratch)?;
    assert_eq!(second, first, "an identical open is an exact retry");
    assert_eq!(fs::read(root.join("agent/sessions/journal.fssj"))?, journal);

    // The mission may be given as a file; its contents are the mission statement.
    let mission_file = directory.0.join("mission.txt");
    fs::write(&mission_file, MISSION)?;
    let (from_file, _) = session_ok(
        &root,
        "open",
        &[
            "--mission",
            mission_file.to_str().ok_or("utf-8 path")?,
            "--objective",
            OBJECTIVE,
        ],
        &scratch,
    )?;
    assert_eq!(
        from_file, first,
        "the file's contents are the mission statement"
    );

    let session = opened.get("sessionId")?.text()?.to_owned();
    let (handed, _) = handoff(&root, &session, &scratch)?;
    let (again, _) = handoff(&root, &session, &scratch)?;
    assert_eq!(again, handed, "an identical handoff republishes nothing");
    Ok(())
}
