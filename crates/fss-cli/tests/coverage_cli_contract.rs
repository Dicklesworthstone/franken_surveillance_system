#![forbid(unsafe_code)]
//! Contract tests for retained coverage witnesses (fss-fnrgr) through the real binaries: the
//! recording is imported with `fss-file import`, analysed with `fss-event watch` /
//! `fss-event corroborate`, coverage is retained only with `--retain-coverage` and its exact
//! approval digest, and `fss orient` / `fss follow` read it back:
//!
//! 1. a quiet static scene with capture hints: the witness excludes background warm-up and
//!    confirmation latency, orient reports the zone covered and the capsule complete, and a follow
//!    since that orientation's anchor returns the engine's silence certificate bound to the
//!    retained witness;
//! 2. unknown capture time, and a source gap (capture time after it is unreliable): no witness,
//!    the zone is not_observable, the capsule partial, and no silence certificate;
//! 3. newer evidence of the same sensor makes the witness stale and it is never reused;
//! 4. a motion scene: a published candidate plus coverage whose entry frame names the event, and a
//!    follow reports the event rather than silence;
//! 5. approval gating: a preview writes nothing, a stale approval is refused before any write, a
//!    candidate approval alone retains no coverage, and a rerun never rewrites;
//! 6. corroborate retains one record per camera over the visible ground zone;
//! 7. every answer validates against its registered schema (`scripts/json_instance_validate.py`),
//!    every witness against `coverage_witness.v1`, output is deterministic, and orient/follow
//!    leave the deployment tree byte-identical;
//! 8. across a harmless successor commit (an `fss-file decode` receipt) follow still returns the
//!    engine's silence certificate (the registered `meaningfulDeltaComparison` rules), while a
//!    material successor (newer unanalysed evidence) returns protected coverage loss.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::ContentDigest;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const WIDTH: u32 = 96;
const HEIGHT: u32 = 48;
const FRAMES: usize = 14;
const SITE: &str = "site:coverage-cli";
const DOOR: &str = "door:64,0,32,32";
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

/// Re-serializes a parsed value (to validate a nested object against its own schema).
fn render(value: &Json) -> String {
    fn quote(text: &str) -> String {
        let mut out = String::from("\"");
        for ch in text.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
                c => out.push(c),
            }
        }
        out.push('"');
        out
    }
    match value {
        Json::Null => "null".to_owned(),
        Json::Bool(flag) => flag.to_string(),
        Json::Number(number) => number.clone(),
        Json::Text(text) => quote(text),
        Json::Array(items) => format!(
            "[{}]",
            items.iter().map(render).collect::<Vec<_>>().join(",")
        ),
        Json::Object(fields) => format!(
            "{{{}}}",
            fields
                .iter()
                .map(|(key, value)| format!("{}:{}", quote(key), render(value)))
                .collect::<Vec<_>>()
                .join(",")
        ),
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
                "fss-coverage-cli-{name}-{}-{attempt}",
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

#[derive(Clone, Copy)]
enum Scene {
    /// A static scene of one background level.
    Quiet(u8),
    /// A bright 16x16 square enters at the left edge from frame 3 and moves 8 px right per frame.
    Right,
    /// The mirror image: it enters at the right edge and moves left.
    Left,
}

/// Fourteen grayscale MJPEG frames; with `gap_after`, undecodable bytes follow that frame, so the
/// importer records a source gap before the next one.
fn scene(kind: Scene, gap_after: Option<usize>) -> TestResult<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..FRAMES {
        let background = match kind {
            Scene::Quiet(level) => level,
            Scene::Right | Scene::Left => 40,
        };
        let mut pixels = vec![background; (WIDTH * HEIGHT) as usize];
        let left = match kind {
            Scene::Quiet(_) => None,
            Scene::Right => (index >= 3).then(|| (index - 3) * 8),
            Scene::Left => (index >= 3).then(|| 80 - (index - 3) * 8),
        };
        if let Some(left) = left {
            for y in 8..24 {
                for x in left..left + 16 {
                    pixels[y * WIDTH as usize + x] = 220;
                }
            }
        }
        stream.extend(encode_jpeg(WIDTH, HEIGHT, &pixels, &config)?);
        if gap_after == Some(index) {
            stream.extend_from_slice(b"lost-bytes-lost-bytes-lost-bytes");
        }
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

fn refusal(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .find_map(|line| line.strip_prefix("refusal_id=").map(str::to_owned))
        .unwrap_or_default()
}

/// Imports `bytes` for `sensor`, received at 10 000 s. With `capture_start_ns` the recording
/// carries an operator capture hint (10 fps, 1 ms uncertainty); without, its capture time is
/// unknown. Returns the import identity.
fn import(
    directory: &OwnedDirectory,
    name: &str,
    bytes: &[u8],
    sensor: &str,
    capture_start_ns: Option<&str>,
) -> TestResult<String> {
    let input = directory.0.join(format!("{name}.mjpeg"));
    fs::write(&input, bytes)?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-file"));
    command
        .arg("import")
        .arg("--root")
        .arg(directory.root())
        .args(["--site", SITE, "--input"])
        .arg(&input)
        .args(["--sensor", sensor, "--stream", &format!("stream:{name}")])
        .args([
            "--media-format",
            "mjpeg",
            "--receive-time-ns",
            "10000000000000",
        ]);
    if let Some(start) = capture_start_ns {
        command
            .args(["--capture-start-ns", start])
            .args(["--capture-uncertainty-ns", "1000000"])
            .args(["--assumed-fps", "10"]);
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

fn watch(root: &Path, import_id: &str, extra: &[&str]) -> TestResult<Output> {
    let mut args = vec![
        "--import-id",
        import_id,
        "--interpretation",
        "gray",
        "--zone",
        DOOR,
    ];
    args.extend_from_slice(extra);
    event(root, "watch", &args)
}

/// A successful report, parsed.
fn report(output: &Output) -> TestResult<Json> {
    success(output);
    Json::parse(String::from_utf8(output.stdout.clone())?.trim_end())
}

fn uncovered(zone: &Json) -> TestResult<Vec<(String, u64, u64)>> {
    zone.get("uncovered")?
        .items()?
        .iter()
        .map(|gap| {
            Ok((
                gap.get("reason")?.text()?.to_owned(),
                gap.get("first_segment")?.number()?,
                gap.get("last_segment")?.number()?,
            ))
        })
        .collect()
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

/// Every entry under `root`: mode, size, times, inode, and content digest.
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

/// The verbatim payload bytes of a rendered envelope.
fn raw_payload(stdout: &str) -> TestResult<&str> {
    let start = stdout.find(",\"payload\":").ok_or("payload missing")? + ",\"payload\":".len();
    let end = stdout
        .find(",\"payloadDigest\":")
        .ok_or("payload digest missing")?;
    Ok(&stdout[start..end])
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Validates `instance` against `schemas/<schema>` with the repository's strict validator.
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

/// Every witness of a report's coverage block conforms to `coverage_witness.v1`; returns their
/// digests.
fn assert_witnesses_conform(
    coverage: &Json,
    scratch: &Path,
    label: &str,
) -> TestResult<Vec<String>> {
    let mut digests = Vec::new();
    for record in coverage.get("records")?.items()? {
        for zone in record.get("zones")?.items()? {
            for witness in zone.get("witnesses")?.items()? {
                let inner = witness.get("witness")?;
                assert_conforms("coverage_witness.v1.json", &render(inner), scratch, label)?;
                assert_eq!(
                    inner.get("completeness")?.text()?,
                    "complete_for_declared_domain"
                );
                assert_eq!(inner.get("continuity")?.text()?, "continuous");
                digests.push(inner.get("witnessDigest")?.text()?.to_owned());
            }
        }
    }
    Ok(digests)
}

/// Orients `root` (brief), checks conformance and read-only behavior, and returns
/// (stdout, envelope, anchor token).
fn orient(root: &Path, scratch: &Path, label: &str) -> TestResult<(String, Json, String)> {
    let before = tree_digest(root)?;
    let (code, stdout, stderr) = run_fss(&command_args("orient", root, &["--view", "brief"]))?;
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_answer_conforms(&stdout, "situation_capsule.v1.json", scratch, label)?;
    assert_eq!(tree_digest(root)?, before, "orient writes nothing");
    let envelope = Json::parse(stdout.trim_end())?;
    let token = envelope
        .get("proofPointers")?
        .texts()?
        .into_iter()
        .find(|pointer| pointer.starts_with("anchor:"))
        .ok_or("anchor token")?
        .to_owned();
    Ok((stdout, envelope, token))
}

/// Follows `root` since `since` (brief), checking conformance and read-only behavior.
fn follow(root: &Path, since: &str, scratch: &Path, label: &str) -> TestResult<(String, Json)> {
    let before = tree_digest(root)?;
    let (code, stdout, stderr) = run_fss(&command_args(
        "follow",
        root,
        &["--since", since, "--view", "brief"],
    ))?;
    assert_eq!(code, Some(0), "stdout: {stdout} stderr: {stderr}");
    assert_answer_conforms(&stdout, "agent_meaningful_delta.v1.json", scratch, label)?;
    assert_eq!(tree_digest(root)?, before, "follow writes nothing");
    let envelope = Json::parse(stdout.trim_end())?;
    Ok((stdout, envelope))
}

fn frame_coverage(envelope: &Json) -> TestResult<&Json> {
    envelope.path(&["payload", "situationFrame", "coverage"])
}

/// The coverage cell of the zone whose scope ends with `scope`.
fn zone_cell<'a>(envelope: &'a Json, scope: &str) -> TestResult<&'a Json> {
    for cell in envelope
        .path(&["payload", "situationFrame", "knowledgeCells"])?
        .items()?
    {
        let id = cell.get("cellId")?.text()?;
        if id.starts_with("claim:coverage:") && id.ends_with(scope) {
            return Ok(cell);
        }
    }
    Err(format!("no coverage cell for {scope}").into())
}

fn zone_cells<'a>(envelope: &'a Json, scope: &str) -> TestResult<Vec<&'a Json>> {
    let mut cells = Vec::new();
    for cell in envelope
        .path(&["payload", "situationFrame", "knowledgeCells"])?
        .items()?
    {
        let id = cell.get("cellId")?.text()?;
        if id.starts_with("claim:coverage:") && id.ends_with(scope) {
            cells.push(cell);
        }
    }
    Ok(cells)
}

fn state(cell: &Json) -> TestResult<&str> {
    cell.get("knowledgeState")?.text()
}

// ---------------------------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------------------------

#[test]
fn quiet_scene_coverage_is_approval_gated_orients_complete_and_follow_certifies_silence()
-> TestResult {
    let directory = OwnedDirectory::new("quiet")?;
    let root = directory.root();
    let id = import(
        &directory,
        "quiet",
        &scene(Scene::Quiet(40), None)?,
        "sensor:quiet",
        Some("1000000000"),
    )?;
    let (_, empty, before_token) = orient(&root, &directory.0, "before coverage")?;
    assert_eq!(empty.get("completeness")?.text()?, "partial");
    assert_eq!(
        frame_coverage(&empty)?.get("status")?.text()?,
        "uncertified"
    );

    // A preview proposes the coverage and writes nothing.
    let untouched = tree_digest(&root)?;
    let preview = report(&watch(&root, &id, &[])?)?;
    assert_eq!(tree_digest(&root)?, untouched, "a preview writes nothing");
    assert_eq!(preview.get("candidate_count")?.number()?, 0);
    let coverage = preview.get("coverage")?;
    assert_eq!(coverage.get("coverage_status")?.text()?, "proposed");
    assert_eq!(coverage.get("witness_count")?.number()?, 1);
    assert_eq!(
        coverage.get("absence_certified_for_witness_domains")?,
        &Json::Bool(false)
    );
    let record = &coverage.get("records")?.items()?[0];
    assert_eq!(record.get("sensor_id")?.text()?, "sensor:quiet");
    assert_eq!(
        record.get("capture_time_label")?.text()?,
        "operator_assumption"
    );
    let zone = &record.get("zones")?.items()?[0];
    assert_eq!(zone.get("scope")?.text()?, "zone:door");
    let witness = &zone.get("witnesses")?.items()?[0];
    // Background warm-up (frames 0..3) and confirmation latency (frames 12..13) are excluded
    // explicitly; the certain bounds run from the latest capture of frame 4 to the earliest
    // capture of frame 11.
    assert_eq!(witness.get("first_segment")?.number()?, 4);
    assert_eq!(witness.get("last_segment")?.number()?, 11);
    assert_eq!(
        render(witness.get("covered_ns")?),
        "[1401000000,2099000000]"
    );
    assert_eq!(
        uncovered(zone)?,
        vec![
            ("background_warmup".to_owned(), 0, 3),
            ("confirmation_latency".to_owned(), 12, 13)
        ]
    );
    let digests = assert_witnesses_conform(coverage, &directory.0, "quiet witness")?;
    assert_eq!(digests.len(), 1);
    let approval = coverage.get("approval_digest")?.text()?.to_owned();
    assert!(
        coverage
            .get("retain_command")?
            .text()?
            .ends_with(&format!("--retain-coverage {approval}"))
    );
    let sequence = preview.get("authority_sequence")?.number()?;

    // A stale approval is refused before any write.
    let stale = ContentDigest::sha256(b"not this coverage").to_text();
    let refused = watch(&root, &id, &["--retain-coverage", &stale])?;
    assert!(!refused.status.success());
    assert_eq!(refusal(&refused), "ERR-COVERAGE-APPROVAL-STALE-001");
    assert!(refused.stdout.is_empty());
    assert_eq!(
        tree_digest(&root)?,
        untouched,
        "a refused approval writes nothing"
    );

    // The exact approval retains it once; reruns never rewrite.
    let retained = report(&watch(&root, &id, &["--retain-coverage", &approval])?)?;
    assert_eq!(
        retained.path(&["coverage", "coverage_status"])?.text()?,
        "retained"
    );
    assert_eq!(
        retained.path(&["coverage", "absence_certified_for_witness_domains"])?,
        &Json::Bool(true)
    );
    let after = retained.get("authority_sequence")?.number()?;
    assert!(after > sequence);
    let written = tree_digest(&root)?;
    let rerun = report(&watch(&root, &id, &["--retain-coverage", &approval])?)?;
    assert_eq!(
        rerun.path(&["coverage", "coverage_status"])?.text()?,
        "already_retained"
    );
    assert_eq!(rerun.path(&["coverage", "retain_command"])?, &Json::Null);
    assert_eq!(rerun.get("authority_sequence")?.number()?, after);
    assert_eq!(
        tree_digest(&root)?,
        written,
        "an exact rerun writes nothing"
    );

    // Orient: the zone is covered and the capsule complete for its declared domain.
    let (stdout, oriented, token) = orient(&root, &directory.0, "covered")?;
    assert_eq!(oriented.get("completeness")?.text()?, "complete");
    let frame = frame_coverage(&oriented)?;
    assert_eq!(frame.get("status")?.text()?, "complete_for_declared_domain");
    assert_eq!(frame.get("witnessIds")?.texts()?, vec![digests[0].as_str()]);
    assert_eq!(frame.get("absenceClaimsCertified")?, &Json::Bool(true));
    assert_eq!(state(zone_cell(&oriented, ":zone:door")?)?, "known");
    assert_eq!(state(zone_cell(&oriented, ":site")?)?, "known");
    let (again, _, _) = orient(&root, &directory.0, "covered again")?;
    assert_eq!(again, stdout, "byte-identical orientation");

    // Follow since that orientation: the engine certifies silence, bound to the witness.
    let (followed, delta) = follow(&root, &token, &directory.0, "silence")?;
    let payload = delta.get("payload")?;
    assert_eq!(
        payload.get("classes")?.texts()?,
        vec!["no_meaningful_change"]
    );
    assert_eq!(payload.get("priority")?.text()?, "low");
    let certificate = payload.get("silenceCertificate")?;
    assert_ne!(certificate, &Json::Null);
    let domain = certificate.get("authorizedDomain")?.texts()?;
    assert!(
        domain.contains(&format!("fss://coverage/{}", digests[0]).as_str()),
        "{domain:?}"
    );
    let (followed_again, _) = follow(&root, &token, &directory.0, "silence again")?;
    assert_eq!(followed_again, followed, "byte-identical follow");

    // Since the anchor before retention, coverage recovered: that is a change, not silence.
    let (_, recovered) = follow(&root, &before_token, &directory.0, "recovery")?;
    let payload = recovered.get("payload")?;
    assert_eq!(payload.get("silenceCertificate")?, &Json::Null);
    assert!(
        payload
            .get("classes")?
            .texts()?
            .contains(&"coverage_recovery")
    );
    Ok(())
}

#[test]
fn unknown_capture_time_yields_no_witness_and_no_silence() -> TestResult {
    let directory = OwnedDirectory::new("unknown")?;
    let root = directory.root();
    let id = import(
        &directory,
        "unknown",
        &scene(Scene::Quiet(40), None)?,
        "sensor:unknown",
        None,
    )?;
    let preview = report(&watch(&root, &id, &[])?)?;
    let coverage = preview.get("coverage")?;
    assert_eq!(coverage.get("witness_count")?.number()?, 0);
    let zone = &coverage.path(&["records"])?.items()?[0]
        .get("zones")?
        .items()?[0];
    assert!(zone.get("witnesses")?.items()?.is_empty());
    assert_eq!(
        uncovered(zone)?,
        vec![("capture_time_unknown".to_owned(), 0, 13)]
    );
    let approval = coverage.get("approval_digest")?.text()?.to_owned();
    report(&watch(&root, &id, &["--retain-coverage", &approval])?)?;

    let (_, oriented, token) = orient(&root, &directory.0, "unknown time")?;
    assert_eq!(oriented.get("completeness")?.text()?, "partial");
    let frame = frame_coverage(&oriented)?;
    assert_eq!(frame.get("status")?.text()?, "not_observable");
    assert!(frame.get("witnessIds")?.items()?.is_empty());
    assert_eq!(frame.get("absenceClaimsCertified")?, &Json::Bool(false));
    assert!(
        frame
            .get("gaps")?
            .texts()?
            .iter()
            .any(|gap| gap.contains("capture_time_unknown"))
    );
    assert_eq!(
        state(zone_cell(&oriented, ":zone:door")?)?,
        "not_observable"
    );
    let (_, delta) = follow(&root, &token, &directory.0, "unknown time follow")?;
    let payload = delta.get("payload")?;
    assert_eq!(payload.get("silenceCertificate")?, &Json::Null);
    assert!(payload.get("classes")?.texts()?.contains(&"coverage_loss"));
    Ok(())
}

#[test]
fn a_source_gap_splits_coverage_and_leaves_the_zone_not_observable() -> TestResult {
    let directory = OwnedDirectory::new("gap")?;
    let root = directory.root();
    let id = import(
        &directory,
        "gap",
        &scene(Scene::Quiet(40), Some(7))?,
        "sensor:gap",
        Some("1000000000"),
    )?;
    // The whole range crosses the gap: refused, nothing bridged.
    let across = watch(&root, &id, &[])?;
    assert!(!across.status.success());
    assert_eq!(refusal(&across), "ERR-WATCH-SOURCE-GAP-001");

    // Before the gap: one witness; the rest of the import was never analysed, so it is stale.
    let first = report(&watch(
        &root,
        &id,
        &["--first-segment", "0", "--segment-count", "8"],
    )?)?;
    let coverage = first.get("coverage")?;
    assert_eq!(coverage.get("witness_count")?.number()?, 1);
    let approval = coverage.get("approval_digest")?.text()?.to_owned();
    report(&watch(
        &root,
        &id,
        &[
            "--first-segment",
            "0",
            "--segment-count",
            "8",
            "--retain-coverage",
            &approval,
        ],
    )?)?;
    let (_, oriented, _) = orient(&root, &directory.0, "before the gap")?;
    assert_eq!(state(zone_cell(&oriented, ":zone:door")?)?, "stale");
    assert_eq!(oriented.get("completeness")?.text()?, "partial");

    // After the gap the frame index no longer predicts capture time: no witness.
    let second = report(&watch(
        &root,
        &id,
        &["--first-segment", "8", "--segment-count", "6"],
    )?)?;
    let coverage = second.get("coverage")?;
    assert_eq!(coverage.get("witness_count")?.number()?, 0);
    let zone = &coverage.get("records")?.items()?[0].get("zones")?.items()?[0];
    assert_eq!(
        uncovered(zone)?,
        vec![("capture_time_unreliable_after_gap".to_owned(), 8, 13)]
    );
    let approval = coverage.get("approval_digest")?.text()?.to_owned();
    report(&watch(
        &root,
        &id,
        &[
            "--first-segment",
            "8",
            "--segment-count",
            "6",
            "--retain-coverage",
            &approval,
        ],
    )?)?;
    let (_, oriented, token) = orient(&root, &directory.0, "after the gap")?;
    assert_eq!(oriented.get("completeness")?.text()?, "partial");
    assert_eq!(
        state(zone_cell(&oriented, ":zone:door")?)?,
        "not_observable"
    );
    let frame = frame_coverage(&oriented)?;
    assert_eq!(frame.get("status")?.text()?, "not_observable");
    assert!(
        frame
            .get("gaps")?
            .texts()?
            .iter()
            .any(|gap| gap.contains("capture_time_unreliable_after_gap"))
    );
    let (_, delta) = follow(&root, &token, &directory.0, "gap follow")?;
    assert_eq!(delta.path(&["payload", "silenceCertificate"])?, &Json::Null);
    Ok(())
}

#[test]
fn newer_evidence_makes_a_witness_stale_and_it_is_never_reused() -> TestResult {
    let directory = OwnedDirectory::new("stale")?;
    let root = directory.root();
    let first = import(
        &directory,
        "first",
        &scene(Scene::Quiet(40), None)?,
        "sensor:stale",
        Some("1000000000"),
    )?;
    let preview = report(&watch(&root, &first, &[])?)?;
    let approval = preview
        .path(&["coverage", "approval_digest"])?
        .text()?
        .to_owned();
    let digests = assert_witnesses_conform(preview.get("coverage")?, &directory.0, "stale")?;
    report(&watch(&root, &first, &["--retain-coverage", &approval])?)?;
    let (_, covered, token) = orient(&root, &directory.0, "fresh")?;
    assert_eq!(covered.get("completeness")?.text()?, "complete");

    // New evidence of the same sensor, captured later and not analysed.
    let second = import(
        &directory,
        "second",
        &scene(Scene::Quiet(60), None)?,
        "sensor:stale",
        Some("3000000000"),
    )?;
    let (_, stale, _) = orient(&root, &directory.0, "stale")?;
    assert_eq!(stale.get("completeness")?.text()?, "partial");
    let cell = zone_cell(&stale, ":zone:door")?;
    assert_eq!(state(cell)?, "stale");
    let frame = frame_coverage(&stale)?;
    assert!(frame.get("witnessIds")?.items()?.is_empty());
    assert!(
        !stale
            .path(&["payload", "situationFrame", "worldEnvelope"])
            .map(render)?
            .contains(&digests[0]),
        "a stale witness bounds nothing"
    );
    let (_, delta) = follow(&root, &token, &directory.0, "stale follow")?;
    let payload = delta.get("payload")?;
    assert_eq!(payload.get("silenceCertificate")?, &Json::Null);
    assert!(payload.get("classes")?.texts()?.contains(&"coverage_loss"));

    // Covering the new recording does not bridge the unanalysed interval between the two.
    let preview = report(&watch(&root, &second, &[])?)?;
    let approval = preview
        .path(&["coverage", "approval_digest"])?
        .text()?
        .to_owned();
    report(&watch(&root, &second, &["--retain-coverage", &approval])?)?;
    let (_, split, _) = orient(&root, &directory.0, "split")?;
    assert_eq!(state(zone_cell(&split, ":zone:door")?)?, "not_observable");
    assert!(
        frame_coverage(&split)?
            .get("gaps")?
            .texts()?
            .iter()
            .any(|gap| gap.contains("not observable between 2099000000 ns and 3401000000 ns"))
    );
    Ok(())
}

#[test]
fn a_motion_scene_keeps_its_event_and_follow_reports_it_not_silence() -> TestResult {
    let directory = OwnedDirectory::new("motion")?;
    let root = directory.root();
    let id = import(
        &directory,
        "motion",
        &scene(Scene::Right, None)?,
        "sensor:motion",
        Some("1000000000"),
    )?;
    let (_, _, before) = orient(&root, &directory.0, "before motion")?;
    let preview = report(&watch(&root, &id, &[])?)?;
    assert_eq!(preview.get("candidate_count")?.number()?, 1);
    let candidate = &preview.get("candidates")?.items()?[0];
    let event_id = candidate.get("event_id")?.text()?.to_owned();
    let proposal = candidate.get("proposal_digest")?.text()?.to_owned();
    let zone = &preview.path(&["coverage", "records"])?.items()?[0]
        .get("zones")?
        .items()?[0];
    let entries: Vec<&Json> = zone
        .get("uncovered")?
        .items()?
        .iter()
        .filter(|gap| {
            gap.get("reason")
                .and_then(Json::text)
                .is_ok_and(|r| r == "zone_entry")
        })
        .collect();
    assert_eq!(entries.len(), 1, "the entry frame is its own interval");
    assert_eq!(entries[0].get("event_id")?.text()?, event_id);
    assert_eq!(
        entries[0].get("candidate_id")?.text()?,
        candidate.get("candidate_id")?.text()?
    );
    assert_eq!(
        entries[0].get("first_segment")?.number()?,
        candidate.get("entry_segment")?.number()?
    );
    assert_witnesses_conform(preview.get("coverage")?, &directory.0, "motion")?;

    // Approving the candidate alone retains no coverage.
    let published = report(&watch(&root, &id, &["--approve", &proposal])?)?;
    assert_eq!(
        published.path(&["candidates"])?.items()?[0]
            .get("status")?
            .text()?,
        "published"
    );
    assert_eq!(
        published.path(&["coverage", "coverage_status"])?.text()?,
        "proposed"
    );
    let approval = published
        .path(&["coverage", "approval_digest"])?
        .text()?
        .to_owned();
    let retained = report(&watch(&root, &id, &["--retain-coverage", &approval])?)?;
    assert_eq!(
        retained.path(&["coverage", "coverage_status"])?.text()?,
        "retained"
    );

    let (_, oriented, token) = orient(&root, &directory.0, "motion covered")?;
    let gaps = frame_coverage(&oriented)?.get("gaps")?.texts()?;
    assert!(
        gaps.iter()
            .any(|gap| gap.contains(&format!("(event {event_id} published)"))),
        "{gaps:?}"
    );
    // The event is reported, never folded into silence.
    let (_, delta) = follow(&root, &before, &directory.0, "motion follow")?;
    let payload = delta.get("payload")?;
    assert_eq!(payload.get("silenceCertificate")?, &Json::Null);
    assert!(payload.get("classes")?.texts()?.contains(&"material_state"));
    let events = payload
        .get("changedCells")?
        .items()?
        .iter()
        .find(|cell| {
            cell.get("cellId")
                .and_then(Json::text)
                .is_ok_and(|id| id == "claim:deployment:events")
        })
        .ok_or("the event summary changed")?;
    assert!(events.get("value")?.text()?.contains(&event_id));
    // At the head nothing changed: silence over the covered zone is certified, while the
    // published event stays in the situation (silence is "no change", never "no event").
    let (_, current) = follow(&root, &token, &directory.0, "motion current")?;
    let certificate = current.path(&["payload", "silenceCertificate"])?;
    assert_ne!(certificate, &Json::Null);
    assert!(
        certificate
            .get("authorizedDomain")?
            .texts()?
            .iter()
            .any(|domain| domain.starts_with("fss://coverage/sha256:"))
    );
    let summary = oriented
        .path(&["payload", "situationFrame", "knowledgeCells"])?
        .items()?
        .iter()
        .find(|cell| {
            cell.get("cellId")
                .and_then(Json::text)
                .is_ok_and(|id| id == "claim:deployment:events")
        })
        .ok_or("the head names the event")?;
    assert!(summary.get("value")?.text()?.contains(&event_id));
    Ok(())
}

#[test]
fn corroborate_retains_one_record_per_camera_over_the_visible_ground_zone() -> TestResult {
    let directory = OwnedDirectory::new("corroborate")?;
    let root = directory.root();
    let east = format!(
        "east:{}",
        import(
            &directory,
            "east",
            &scene(Scene::Right, None)?,
            "sensor:east",
            Some("1000000000")
        )?
    );
    let west = format!(
        "west:{}",
        import(
            &directory,
            "west",
            &scene(Scene::Left, None)?,
            "sensor:west",
            Some("1000000000")
        )?
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
        event(&root, "corroborate", &args)
    };
    let untouched = tree_digest(&root)?;
    let preview = report(&corroborate(&[])?)?;
    assert_eq!(tree_digest(&root)?, untouched, "a preview writes nothing");
    let coverage = preview.get("coverage")?;
    assert_eq!(coverage.get("coverage_status")?.text()?, "proposed");
    let records = coverage.get("records")?.items()?;
    assert_eq!(records.len(), 2);
    for (record, sensor) in records.iter().zip(["sensor:east", "sensor:west"]) {
        assert_eq!(record.get("source")?.text()?, "corroborate");
        assert_eq!(record.get("sensor_id")?.text()?, sensor);
        let zone = &record.get("zones")?.items()?[0];
        assert_eq!(zone.get("scope")?.text()?, "ground-zone:door");
        // The ground zone's image preimage lies inside the frame for both owner homographies.
        assert!(
            uncovered(zone)?
                .iter()
                .all(|(reason, _, _)| reason != "zone_outside_frame")
        );
    }
    assert_witnesses_conform(coverage, &directory.0, "corroborate")?;
    let approval = coverage.get("approval_digest")?.text()?.to_owned();
    let stale = ContentDigest::sha256(b"not these records").to_text();
    let refused = corroborate(&["--retain-coverage", &stale])?;
    assert!(!refused.status.success());
    assert_eq!(refusal(&refused), "ERR-COVERAGE-APPROVAL-STALE-001");
    assert_eq!(tree_digest(&root)?, untouched);
    let retained = report(&corroborate(&["--retain-coverage", &approval])?)?;
    assert_eq!(
        retained.path(&["coverage", "coverage_status"])?.text()?,
        "retained"
    );
    let rerun = report(&corroborate(&["--retain-coverage", &approval])?)?;
    assert_eq!(
        rerun.path(&["coverage", "coverage_status"])?.text()?,
        "already_retained"
    );
    let (_, oriented, _) = orient(&root, &directory.0, "corroborate coverage")?;
    assert_eq!(zone_cells(&oriented, ":ground-zone:door")?.len(), 2);
    Ok(())
}

/// Decodes one retained segment with `fss-file decode`: the derived decode receipt commits one
/// authority batch that retains no source evidence, coverage, event, or effect. Returns the
/// authority sequence it committed at.
fn decode_segment(root: &Path, import_id: &str) -> TestResult<u64> {
    let output = Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("decode")
        .arg("--root")
        .arg(root)
        .args(["--site", SITE])
        .args([
            "--import-id",
            import_id,
            "--segment",
            "5",
            "--interpretation",
            "gray",
        ])
        .output()?;
    success(&output);
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .find_map(|line| line.strip_prefix("decode_authority_sequence="))
        .ok_or("decode authority sequence missing")?
        .parse()?)
}

#[test]
fn a_harmless_successor_commit_keeps_certified_silence_and_a_material_one_does_not() -> TestResult {
    let directory = OwnedDirectory::new("harmless")?;
    let root = directory.root();
    let id = import(
        &directory,
        "harmless",
        &scene(Scene::Quiet(40), None)?,
        "sensor:harmless",
        Some("1000000000"),
    )?;
    let preview = report(&watch(&root, &id, &[])?)?;
    let coverage = preview.get("coverage")?;
    let digests = assert_witnesses_conform(coverage, &directory.0, "harmless witness")?;
    assert_eq!(digests.len(), 1);
    let approval = coverage.get("approval_digest")?.text()?.to_owned();
    report(&watch(&root, &id, &["--retain-coverage", &approval])?)?;
    let (_, oriented, token) = orient(&root, &directory.0, "harmless covered")?;
    assert_eq!(oriented.get("completeness")?.text()?, "complete");
    let covered_at = oriented
        .path(&["inputAnchor", "capsuleSequence"])?
        .number()?;

    // A harmless successor commit: the ledger head advances, nothing decision-relevant changes.
    let decoded_at = decode_segment(&root, &id)?;
    assert!(decoded_at > covered_at, "{decoded_at} > {covered_at}");
    let (_, head, head_token) = orient(&root, &directory.0, "harmless head")?;
    assert_ne!(head_token, token, "the anchor advanced");
    assert_eq!(head.get("completeness")?.text()?, "complete");
    assert_eq!(
        head.path(&["inputAnchor", "capsuleSequence"])?.number()?,
        decoded_at
    );

    // Follow across the advance: the engine certifies silence, bound to the retained witness.
    let (followed, delta) = follow(&root, &token, &directory.0, "harmless silence")?;
    let payload = delta.get("payload")?;
    assert_eq!(
        payload
            .path(&["basisAnchor", "capsuleSequence"])?
            .number()?,
        covered_at
    );
    assert_eq!(
        payload
            .path(&["resultAnchor", "capsuleSequence"])?
            .number()?,
        decoded_at
    );
    assert_eq!(
        payload.get("classes")?.texts()?,
        vec!["no_meaningful_change"]
    );
    assert_eq!(payload.get("priority")?.text()?, "low");
    assert!(payload.get("changedCells")?.items()?.is_empty());
    let certificate = payload.get("silenceCertificate")?;
    assert_ne!(certificate, &Json::Null);
    let domain = certificate.get("authorizedDomain")?.texts()?;
    assert!(
        domain.contains(&format!("fss://coverage/{}", digests[0]).as_str()),
        "{domain:?}"
    );
    let (again, _) = follow(&root, &token, &directory.0, "harmless silence again")?;
    assert_eq!(again, followed, "byte-identical follow");

    // A material successor: newer evidence of the same sensor, not analysed, makes the witness
    // stale, and the same follow now reports protected coverage loss instead of silence.
    import(
        &directory,
        "harmless-later",
        &scene(Scene::Quiet(60), None)?,
        "sensor:harmless",
        Some("3000000000"),
    )?;
    let (_, material) = follow(&root, &token, &directory.0, "material")?;
    let payload = material.get("payload")?;
    assert_eq!(payload.get("silenceCertificate")?, &Json::Null);
    let classes = payload.get("classes")?.texts()?;
    assert!(classes.contains(&"coverage_loss"), "{classes:?}");
    assert!(!classes.contains(&"no_meaningful_change"), "{classes:?}");
    let (_, stale, _) = orient(&root, &directory.0, "material head")?;
    assert_eq!(state(zone_cell(&stale, ":zone:door")?)?, "stale");
    Ok(())
}
