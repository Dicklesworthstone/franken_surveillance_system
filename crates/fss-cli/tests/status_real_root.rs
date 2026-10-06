#![forbid(unsafe_code)]
//! `fss status --json --root <dir>` through the real `fss` binary over real deployment roots
//! (fss-2h5zq.60):
//!
//! 1. without `--root` the legacy document is byte-identical;
//! 2. roots produced by `fss-lab run` (quiet, intrusion), by `fss-file import` of an MJPEG and an
//!    Annex-B recording, and by `fss-file import --media-format rtpplay` report exactly what they
//!    committed: sensors, streams, capsule counts, clock bases, continuity knowledge, imports,
//!    events, obligations and the capabilities they exercised;
//! 3. every read is read-only: the tree digest of the root (mode, size, times, inode, content)
//!    is identical before and after, and a second read is byte-identical;
//! 4. a readiness guard runs on every document: no device acquisition, live streaming or
//!    real-provider alert readiness under any key or value, and file sources never claim
//!    continuity;
//! 5. a missing, empty, corrupt or over-budget root is a typed refusal that prints no inventory;
//! 6. a file import cancelled before its manifest batch is listed under `degraded[]` and its
//!    capsules are excluded from every count until the import completes;
//! 7. a root whose writer lock is held reports `possibly_stale` until the writer drops.
//!
//! Each case prints one `CAPLOG` record after its assertions passed. Directories are allocated
//! under the cargo target tmpdir and never removed.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::{
    BudgetVector, CanonicalDecode, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
    SensorCapsule, SensorId, StreamId, TimestampNs,
};
use fss_reference::ingest::file_adapter::STAGE_COMMIT_MANIFEST;
use fss_reference::{
    ADP_FILE_ROW_ID, ADP_REPLAY_ROW_ID, FileIngestAdapter, FileIngestError, FileIngestLimits,
    FileIngestRequest, ReferenceDeployment, ReplayCx, ReplayIoAuthority,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:status-real-root";
/// Committed rtpdump fixtures (tests/fixtures/media/rtp), SSRC 0x11223344, payload type 96.
const RTP_BINDING: [&str; 10] = [
    "--media-format",
    "rtpplay",
    "--rtp-generation",
    "1",
    "--rtp-ssrc",
    "287454020",
    "--rtp-payload-type",
    "96",
    "--rtp-mode",
    "non-interleaved",
];

// ---------------------------------------------------------------------------------------------
// Minimal JSON reader: every assertion goes through a full parse, so each document is also
// proven to be one well-formed JSON value with no duplicate keys.
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

    fn has(&self, key: &str) -> bool {
        matches!(self, Self::Object(fields) if fields.iter().any(|(name, _)| name == key))
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

    fn boolean(&self) -> TestResult<bool> {
        match self {
            Self::Bool(value) => Ok(*value),
            other => Err(format!("not a boolean: {other:?}").into()),
        }
    }

    /// The element of an array of objects whose `key` equals `value`.
    fn find(&self, key: &str, value: &str) -> TestResult<&Self> {
        for item in self.items()? {
            if item.get(key)?.text()? == value {
                return Ok(item);
            }
        }
        Err(format!("no element with {key} = {value}").into())
    }

    /// Every (key, value) pair of every object, recursively.
    fn walk<'a>(&'a self, out: &mut Vec<(Option<&'a str>, &'a Self)>) {
        match self {
            Self::Object(fields) => {
                for (key, value) in fields {
                    out.push((Some(key), value));
                    value.walk(out);
                }
            }
            Self::Array(items) => {
                for item in items {
                    out.push((None, item));
                    item.walk(out);
                }
            }
            _ => {}
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
// Fixtures and helpers.
// ---------------------------------------------------------------------------------------------

/// A fresh directory under the cargo target tmpdir; never removed.
fn directory(label: &str) -> TestResult<PathBuf> {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
    fs::create_dir_all(base)?;
    for attempt in 0..1000_u32 {
        let path = base.join(format!(
            "status-real-root-{label}-{}-{attempt}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err("test directory capacity".into())
}

fn media_fixture(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/media")
        .join(relative)
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn line_field(output: &Output, name: &str) -> TestResult<String> {
    let text = std::str::from_utf8(&output.stdout)?;
    let prefix = format!("{name}=");
    text.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map(str::to_owned)
        .ok_or_else(|| format!("missing output field {name}").into())
}

/// Runs `fss status` with `args`; returns (exit code, stdout, stderr).
fn fss(args: &[&str]) -> TestResult<(i32, String, String)> {
    let output = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(args)
        .output()?;
    Ok((
        output.status.code().ok_or("killed by a signal")?,
        String::from_utf8(output.stdout)?,
        String::from_utf8(output.stderr)?,
    ))
}

fn status_args<'a>(root: &'a Path, extra: &[&'a str]) -> TestResult<Vec<&'a str>> {
    let mut args = vec![
        "status",
        "--json",
        "--root",
        root.to_str().ok_or("utf-8 root")?,
    ];
    args.extend_from_slice(extra);
    Ok(args)
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

fn copy_tree(from: &Path, to: &Path) -> TestResult {
    fs::create_dir(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

fn caplog(step: &str, observed: &str) {
    println!(
        "CAPLOG {{\"bead\":\"fss-2h5zq.60\",\"step\":\"{step}\",\"verdict\":\"pass\",\"observed\":\"{observed}\"}}"
    );
}

/// The status document of `root`, read twice: the read is read-only (identical tree digest)
/// and deterministic (identical bytes). Every document passes the readiness guard.
fn read_status(root: &Path) -> TestResult<(Json, String)> {
    let before = tree_digest(root)?;
    let (code, stdout, stderr) = fss(&status_args(root, &[])?)?;
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    assert!(stderr.is_empty(), "stderr={stderr}");
    let (_, again, _) = fss(&status_args(root, &[])?)?;
    assert_eq!(stdout, again, "two reads of one root are byte-identical");
    assert_eq!(before, tree_digest(root)?, "status wrote under the root");
    let document = Json::parse(stdout.trim_end())?;
    readiness_guard(&document)?;
    assert_eq!(document.get("schema")?.text()?, "fss.status.v1");
    assert_eq!(document.get("deployment")?.text()?, "inspected_read_only");
    assert!(document.get("read_only")?.boolean()?);
    assert_eq!(
        document.path(&["bounds", "complete"])?,
        &Json::Bool(true),
        "a printed inventory is always complete"
    );
    Ok((document, stdout))
}

/// No field of a status document may imply readiness the reference does not have.
fn readiness_guard(document: &Json) -> TestResult {
    const READINESS_KEYS: [&str; 8] = [
        "implemented",
        "available",
        "qualified",
        "ready",
        "online",
        "connected",
        "acquiring",
        "streaming",
    ];
    const READINESS_VALUES: [&str; 7] = [
        "implemented",
        "available",
        "online",
        "connected",
        "acquiring",
        "streaming",
        "live",
    ];
    const UNSUPPORTED: [&str; 5] = [
        "device_acquisition",
        "live_streaming",
        "real_provider_alerts",
        "uvc",
        "rtsp",
    ];
    let mut pairs = Vec::new();
    document.walk(&mut pairs);
    for (key, value) in pairs {
        if let Some(key) = key {
            assert!(!READINESS_KEYS.contains(&key), "readiness key {key}");
        }
        if let Json::Text(text) = value {
            assert!(
                !READINESS_VALUES.contains(&text.as_str()),
                "readiness value {text} under {key:?}"
            );
            if key == Some("capability") || key == Some("kind") {
                for word in UNSUPPORTED {
                    assert!(!text.contains(word), "{key:?} = {text}");
                }
            }
            if key == Some("capability") {
                for word in ["live", "device", "acquisition", "provider"] {
                    assert!(!text.contains(word), "capability {text}");
                }
            }
        }
    }
    if document.has("readiness") {
        for key in [
            "device_acquisition",
            "live_streaming",
            "real_provider_alerts",
        ] {
            assert_eq!(
                document.path(&["readiness", key])?.text()?,
                "not_claimed",
                "{key}"
            );
        }
        assert_eq!(
            document
                .path(&["readiness", "release_qualification"])?
                .text()?,
            "not_qualified"
        );
    }
    if document.has("sensors") {
        for sensor in document.get("sensors")?.items()? {
            for stream in sensor.get("streams")?.items()? {
                let continuity = stream.get("continuity")?;
                assert_eq!(continuity.get("live")?.text()?, "not_claimed");
                assert_eq!(continuity.get("scope")?.text()?, "committed_history_only");
                let bases = stream.path(&["capture_interval", "clock_bases"])?.texts()?;
                if bases.contains(&"estimated") {
                    assert_ne!(
                        continuity.get("knowledge")?.text()?,
                        "verified",
                        "an estimated clock never verifies continuity"
                    );
                    assert_eq!(
                        stream
                            .path(&["capture_interval", "capture_time_class"])?
                            .text()?,
                        "estimated_not_capture_truth"
                    );
                }
            }
        }
    }
    Ok(())
}

fn capabilities(document: &Json) -> TestResult<Vec<&str>> {
    document
        .get("capabilities_exercised")?
        .items()?
        .iter()
        .map(|item| item.get("capability")?.text())
        .collect()
}

fn degraded_kinds(document: &Json) -> TestResult<Vec<&str>> {
    document
        .get("degraded")?
        .items()?
        .iter()
        .map(|item| item.get("kind")?.text())
        .collect()
}

fn only_stream(document: &Json) -> TestResult<(&str, &Json)> {
    let sensors = document.get("sensors")?.items()?;
    assert_eq!(sensors.len(), 1, "exactly one sensor");
    let streams = sensors[0].get("streams")?.items()?;
    assert_eq!(streams.len(), 1, "exactly one stream");
    Ok((sensors[0].get("sensor_id")?.text()?, &streams[0]))
}

fn import(root: &Path, input: &Path, sensor: &str, extra: &[&str]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("import")
        .arg("--root")
        .arg(root)
        .args(["--site", SITE, "--input"])
        .arg(input)
        .args([
            "--sensor",
            sensor,
            "--stream",
            "stream:status-main",
            "--receive-time-ns",
            "2000000000",
        ])
        .args(extra)
        .output()?)
}

fn context(scratch: &Path, label: &str) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: format!("trace:status-real-root-{label}"),
        operation_id: OperationId::parse(format!("operation:status-real-root-{label}"))?,
        principal: format!("operator:status-real-root-{label}"),
        capabilities: vec![ADP_FILE_ROW_ID.to_owned(), ADP_REPLAY_ROW_ID.to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_owned(),
        retention_scope: "retention:ephemeral".to_owned(),
        anchor_universe: ContentDigest::sha256(b"status-real-root"),
        generation: 1,
    })?;
    let directory = scratch.join(format!("cx-{label}"));
    fs::create_dir_all(&directory)?;
    Ok(ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority, directory,
    )?))
}

fn hex_of(digest: &ContentDigest) -> String {
    let text = digest.to_text();
    text.split_once(':')
        .map_or(text.clone(), |(_, hex)| hex.to_owned())
}

// ---------------------------------------------------------------------------------------------
// Cases.
// ---------------------------------------------------------------------------------------------

/// Without `--root` the document is the legacy one, byte for byte, and passes the guard.
#[test]
fn legacy_status_without_root_is_unchanged() -> TestResult {
    let (code, stdout, stderr) = fss(&["status", "--json"])?;
    assert_eq!(code, 0);
    assert!(stderr.is_empty());
    assert_eq!(
        stdout,
        format!(
            "{{\"schema\":\"fss.status.v1\",\"version\":\"{}\",\"phase\":\"reference_implementation_unqualified\",\"deployment\":\"not_specified\",\"sensors\":[],\"events\":[],\"degraded\":[\"no_deployment_root_inspected\",\"not_release_qualified\"]}}\n",
            env!("CARGO_PKG_VERSION")
        )
    );
    readiness_guard(&Json::parse(stdout.trim_end())?)?;
    // The grammar stays exact: --json is required, and the bound needs a root.
    assert_eq!(fss(&["status"])?.0, 2);
    assert_eq!(fss(&["status", "--json", "extra"])?.0, 2);
    assert_eq!(
        fss(&["status", "--json", "--max-journal-bytes", "4096"])?.0,
        2
    );
    caplog("legacy_unchanged", "exit=0 legacy_bytes_identical");
    Ok(())
}

/// Lab roots: virtual cameras publish their capsules under roots, not as `sensor_capsule`
/// ledger objects, so the ledger inventory lists no sensors and status says so instead of
/// inventing them. `quiet` retains a continuous source coverage witness: its sources are listed
/// under `coverage_witness_sources` (never counted as retained capsules) with the degradation
/// that they have no ledgered capsules, and its one event is rejected. Neither root claims
/// liveness, a file source or a file import.
#[test]
fn lab_scenario_roots_report_their_committed_inventory() -> TestResult {
    let dir = directory("lab")?;
    let mut observed = Vec::new();
    for scenario in ["quiet", "intrusion"] {
        let root = dir.join(scenario);
        let ran = Command::new(env!("CARGO_BIN_EXE_fss-lab"))
            .args(["run", scenario, "--root"])
            .arg(&root)
            .output()?;
        success(&ran);
        let (document, stdout) = read_status(&root)?;
        println!("STATUS {scenario} {}", stdout.trim_end());
        assert_eq!(
            document.path(&["anchor", "site_lineage"])?.text()?,
            "site:lab"
        );
        assert!(document.path(&["anchor", "commit_sequence"])?.number()? > 0);
        assert!(document.path(&["anchor", "ledger_present"])?.boolean()?);
        assert!(document.get("sensors")?.items()?.is_empty(), "{scenario}");
        assert_eq!(document.path(&["capsules", "retained"])?.number()?, 0);
        assert_eq!(
            document
                .path(&["imports", "file_imports_completed"])?
                .number()?,
            0
        );
        let events = document.path(&["events", "count"])?.number()?;
        assert!(events >= 1, "{scenario}");
        let exercised = capabilities(&document)?;
        assert!(exercised.contains(&"reference_event_publication"));
        assert!(!exercised.contains(&"reference_file_import"));
        assert!(!exercised.contains(&"source_custody_capsules"));
        let kinds = degraded_kinds(&document)?;
        assert!(!kinds.contains(&"no_live_continuity"), "{scenario}");
        let sources = document.get("coverage_witness_sources")?.items()?;
        if scenario == "quiet" {
            assert_eq!(
                document
                    .path(&["events", "by_state", "rejected"])?
                    .number()?,
                1
            );
            assert!(exercised.contains(&"retained_coverage_witnesses"));
            assert!(!sources.is_empty(), "quiet retains a coverage witness");
            for source in sources {
                assert_eq!(source.get("witness_continuity")?.text()?, "continuous");
                assert_eq!(source.get("scope")?.text()?, "committed_history_only");
                assert!(source.get("frames")?.number()? > 0);
            }
            assert_eq!(
                document
                    .get("degraded")?
                    .find("kind", "coverage_sources_without_ledgered_capsules")?
                    .get("count")?
                    .number()?,
                u64::try_from(sources.len())?
            );
        } else {
            assert!(sources.is_empty(), "intrusion retains no coverage witness");
            assert!(exercised.contains(&"durable_effect_journal"));
            assert!(document.path(&["effects", "operations"])?.number()? >= 1);
        }
        observed.push(format!(
            "{scenario}:events={events} coverage_sources={}",
            sources.len()
        ));
    }
    caplog("lab_roots", &observed.join(" "));
    Ok(())
}

/// MJPEG and Annex-B file imports: one estimated-clock stream whose continuity is not
/// observable, a completed import with its manifest root, and the no_live_continuity
/// degradation.
#[test]
fn file_import_roots_report_a_file_source_without_live_continuity() -> TestResult {
    let dir = directory("file")?;
    let mut observed = Vec::new();
    for (format, fixture) in [
        ("mjpeg", "mjpeg/mjpeg_clean_3frames.mjpeg"),
        ("annexb", "h264/clean.264"),
    ] {
        let root = dir.join(format);
        let sensor = format!("sensor:status-{format}");
        let imported = import(
            &root,
            &media_fixture(fixture),
            &sensor,
            &["--media-format", format],
        )?;
        success(&imported);
        let segments: u64 = line_field(&imported, "segment_count")?.parse()?;
        assert!(segments > 0);
        let (document, stdout) = read_status(&root)?;
        println!("STATUS {format} {}", stdout.trim_end());
        assert_eq!(document.path(&["anchor", "site_lineage"])?.text()?, SITE);
        let (sensor_id, stream) = only_stream(&document)?;
        assert_eq!(sensor_id, sensor);
        assert_eq!(stream.get("stream_id")?.text()?, "stream:status-main");
        assert_eq!(stream.get("capsules")?.number()?, segments);
        assert_eq!(
            stream.path(&["capture_interval", "clock_bases"])?.texts()?,
            ["estimated"]
        );
        assert_eq!(
            stream.path(&["continuity", "knowledge"])?.text()?,
            "not_observable_file_source"
        );
        assert_eq!(
            stream
                .path(&["continuity", "witnessed_continuous"])?
                .number()?,
            0
        );
        assert_eq!(
            document.path(&["capsules", "retained"])?.number()?,
            segments
        );
        assert_eq!(
            document
                .path(&["capsules", "excluded_incomplete_import"])?
                .number()?,
            0
        );
        assert_eq!(
            document
                .path(&["imports", "file_imports_completed"])?
                .number()?,
            1
        );
        assert_eq!(
            document
                .path(&["imports", "file_imports_incomplete"])?
                .number()?,
            0
        );
        assert!(
            document
                .path(&["imports", "last_import_manifest_root"])?
                .text()?
                .starts_with("sha256:")
        );
        assert_eq!(document.path(&["events", "count"])?.number()?, 0);
        assert_eq!(document.path(&["obligations", "count"])?.number()?, 0);
        let exercised = capabilities(&document)?;
        for capability in ["reference_file_import", "source_custody_capsules"] {
            assert!(exercised.contains(&capability), "{format}: {capability}");
        }
        assert!(!exercised.contains(&"reference_event_publication"));
        let no_live = document
            .get("degraded")?
            .find("kind", "no_live_continuity")?;
        assert_eq!(no_live.get("count")?.number()?, 1);
        assert_eq!(
            document.path(&["situation", "knowledge"])?.text()?,
            "not_observable"
        );
        assert_eq!(
            document.path(&["situation", "last_handoff_digest"])?,
            &Json::Null
        );
        observed.push(format!(
            "{format}:capsules={segments} continuity=not_observable_file_source"
        ));
    }
    caplog("file_import_roots", &observed.join(" "));
    Ok(())
}

/// A recorded RTP session: five access-unit capsules, the file-entry gap recorded, no file
/// import lifecycle object, and the recorded RTP import capability.
#[test]
fn rtpplay_import_root_reports_recorded_gaps_and_its_own_import_family() -> TestResult {
    let dir = directory("rtpplay")?;
    let root = dir.join("deployment");
    let imported = import(
        &root,
        &media_fixture("rtp/clean.rtp"),
        "sensor:status-rtp",
        &RTP_BINDING,
    )?;
    success(&imported);
    assert_eq!(line_field(&imported, "capsule_count")?, "5");
    assert_eq!(line_field(&imported, "gap_before_capsules")?, "1");
    let (document, stdout) = read_status(&root)?;
    println!("STATUS rtpplay {}", stdout.trim_end());
    let (sensor, stream) = only_stream(&document)?;
    assert_eq!(sensor, "sensor:status-rtp");
    assert_eq!(stream.get("capsules")?.number()?, 5);
    assert_eq!(stream.get("recorded_gaps")?.number()?, 1);
    assert_eq!(
        stream.path(&["capture_interval", "clock_bases"])?.texts()?,
        ["estimated"]
    );
    assert_eq!(
        stream.path(&["continuity", "knowledge"])?.text()?,
        "not_observable_file_source"
    );
    assert_eq!(
        document
            .path(&["imports", "rtpdump_import_records"])?
            .number()?,
        1
    );
    assert_eq!(
        document
            .path(&["imports", "file_imports_completed"])?
            .number()?,
        0
    );
    let exercised = capabilities(&document)?;
    assert!(exercised.contains(&"recorded_rtp_session_import"));
    assert!(!exercised.contains(&"reference_file_import"));
    let kinds = degraded_kinds(&document)?;
    assert!(kinds.contains(&"no_live_continuity"));
    assert_eq!(
        document
            .get("degraded")?
            .find("kind", "recorded_gaps")?
            .get("count")?
            .number()?,
        1
    );
    caplog(
        "rtpplay_root",
        "capsules=5 recorded_gaps=1 continuity=not_observable_file_source",
    );
    Ok(())
}

fn assert_refusal(args: &[&str], code: i32, error_id: &str) -> TestResult<Json> {
    let (exit, stdout, stderr) = fss(args)?;
    assert_eq!(exit, code, "stdout={stdout} stderr={stderr}");
    let document = Json::parse(stdout.trim_end())?;
    assert_eq!(document.get("schema")?.text()?, "fss.cli_diagnostic.v1");
    assert_eq!(document.get("command")?.text()?, "status");
    assert_eq!(document.get("error_id")?.text()?, error_id);
    assert_eq!(document.get("exit_code")?.number()?, u64::try_from(code)?);
    assert!(!document.get("effect_started")?.boolean()?);
    for key in ["sensors", "capsules", "imports", "events", "anchor"] {
        assert!(!document.has(key), "a refusal prints no inventory ({key})");
    }
    Ok(document)
}

/// Missing, empty, corrupt and over-budget roots are typed refusals, and none writes.
#[test]
fn refusals_are_typed_print_no_inventory_and_write_nothing() -> TestResult {
    let dir = directory("refusals")?;
    let missing = dir.join("missing");
    assert_refusal(
        &status_args(&missing, &[])?,
        4,
        "ERR-DOCTOR-NOT-A-DEPLOYMENT-001",
    )?;
    assert!(!missing.exists(), "status never creates the root");
    let empty = dir.join("empty");
    fs::create_dir(&empty)?;
    let before = tree_digest(&empty)?;
    assert_refusal(
        &status_args(&empty, &[])?,
        4,
        "ERR-DOCTOR-NOT-A-DEPLOYMENT-001",
    )?;
    assert_eq!(before, tree_digest(&empty)?);

    let root = dir.join("clean");
    success(&import(
        &root,
        &media_fixture("mjpeg/mjpeg_clean_3frames.mjpeg"),
        "sensor:status-refusal",
        &["--media-format", "mjpeg"],
    )?);
    let before = tree_digest(&root)?;
    let over = assert_refusal(
        &status_args(&root, &["--max-journal-bytes", "64"])?,
        7,
        "ERR-STATUS-OVER-BUDGET-001",
    )?;
    assert_eq!(over.get("exit_id")?.text()?, "EXIT-STATUS-REFUSED-007");
    assert!(!over.get("partial_totals")?.boolean()?);
    assert!(!over.get("retryable")?.boolean()?);
    assert_eq!(before, tree_digest(&root)?);

    // Corrupt one retained capsule metadata object of a copy: one flipped payload byte.
    let corrupt = dir.join("corrupt");
    copy_tree(&root, &corrupt)?;
    let spool = corrupt.join("objects/spool/objects");
    let mut flipped = 0;
    for entry in fs::read_dir(&spool)? {
        let path = entry?.path();
        let mut bytes = fs::read(&path)?;
        let header = fss_object::SPOOL_OBJECT_HEADER_LEN;
        if bytes.len() > header && SensorCapsule::from_canonical_bytes(&bytes[header..]).is_ok() {
            let last = bytes.len() - 1;
            bytes[last] ^= 0x01;
            let mut permissions = fs::metadata(&path)?.permissions();
            permissions.set_mode(permissions.mode() | 0o200);
            fs::set_permissions(&path, permissions)?;
            fs::write(&path, &bytes)?;
            flipped += 1;
            break;
        }
    }
    assert_eq!(flipped, 1, "one capsule object corrupted");
    let before = tree_digest(&corrupt)?;
    let refused = assert_refusal(&status_args(&corrupt, &[])?, 7, "ERR-STATUS-CORRUPT-001")?;
    assert_eq!(
        refused.get("recovery_class")?.text()?,
        "operator_action_required"
    );
    assert_eq!(before, tree_digest(&corrupt)?);
    caplog(
        "refusals",
        "missing=4 empty=4 over_budget=7:ERR-STATUS-OVER-BUDGET-001 corrupt=7:ERR-STATUS-CORRUPT-001",
    );
    Ok(())
}

/// An import cancelled before its manifest batch (two capsule deltas per batch) is listed as
/// incomplete and its committed capsules count nowhere; after the same import completes, they
/// are counted and the degradation is gone.
#[test]
fn incomplete_import_is_listed_and_excluded_until_it_completes() -> TestResult {
    let dir = directory("incomplete")?;
    let root = dir.join("deployment");
    let input = media_fixture("mjpeg/mjpeg_clean_3frames.mjpeg");
    let request = FileIngestRequest::new(
        input,
        SensorId::parse("sensor:status-incomplete")?,
        StreamId::parse("stream:status-main")?,
    )
    .with_limits(FileIngestLimits {
        max_batch_deltas: 2,
        ..FileIngestLimits::standard()
    })
    .with_receive_time(TimestampNs(2_000_000_000));
    {
        let cx = context(&dir, "open")?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let cancelled = context(&dir, "cancel")?;
        cancelled.set_cancel_at_checkpoint(STAGE_COMMIT_MANIFEST);
        match FileIngestAdapter::ingest(request.clone(), &cancelled, &mut deployment) {
            Err(FileIngestError::CancellationRequested { stage }) => {
                assert_eq!(stage, STAGE_COMMIT_MANIFEST);
            }
            other => return Err(format!("expected a cancelled import, got {other:?}").into()),
        }
    }
    let (document, stdout) = read_status(&root)?;
    println!("STATUS incomplete {}", stdout.trim_end());
    assert!(document.get("sensors")?.items()?.is_empty());
    assert_eq!(document.path(&["capsules", "retained"])?.number()?, 0);
    let excluded = document
        .path(&["capsules", "excluded_incomplete_import"])?
        .number()?;
    assert!(excluded > 0, "the cancelled import committed capsules");
    assert_eq!(
        document
            .path(&["capsules", "historical_objects"])?
            .number()?,
        excluded
    );
    assert_eq!(
        document
            .path(&["imports", "file_imports_completed"])?
            .number()?,
        0
    );
    assert_eq!(
        document
            .path(&["imports", "file_imports_incomplete"])?
            .number()?,
        1
    );
    let incomplete = document
        .get("degraded")?
        .find("kind", "incomplete_import")?
        .get("subject")?
        .text()?
        .to_owned();
    assert!(incomplete.starts_with("object:file-import:"));

    let receipt = {
        let cx = context(&dir, "reopen")?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        FileIngestAdapter::ingest(request, &context(&dir, "resume")?, &mut deployment)?
    };
    assert_eq!(
        incomplete,
        format!("object:file-import:{}", hex_of(&receipt.import_identity))
    );
    let (document, _) = read_status(&root)?;
    let (_, stream) = only_stream(&document)?;
    assert_eq!(stream.get("capsules")?.number()?, excluded);
    assert_eq!(
        document.path(&["capsules", "retained"])?.number()?,
        excluded
    );
    assert_eq!(
        document
            .path(&["capsules", "excluded_incomplete_import"])?
            .number()?,
        0
    );
    assert_eq!(
        document
            .path(&["imports", "file_imports_completed"])?
            .number()?,
        1
    );
    assert!(!degraded_kinds(&document)?.contains(&"incomplete_import"));
    caplog(
        "incomplete_import",
        &format!("excluded={excluded} then_counted={excluded}"),
    );
    Ok(())
}

/// While a writer holds the deployment locks the report is possibly stale; after it drops, the
/// lock table shows no writer.
#[test]
fn held_writer_marks_the_report_possibly_stale_until_it_drops() -> TestResult {
    let dir = directory("held")?;
    let root = dir.join("deployment");
    success(&import(
        &root,
        &media_fixture("mjpeg/mjpeg_clean_3frames.mjpeg"),
        "sensor:status-held",
        &["--media-format", "mjpeg"],
    )?);
    {
        let cx = context(&dir, "writer")?;
        let _writer = ReferenceDeployment::open(&root, SITE, &cx)?;
        let (code, stdout, stderr) = fss(&status_args(&root, &[])?)?;
        assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
        let document = Json::parse(stdout.trim_end())?;
        readiness_guard(&document)?;
        assert_eq!(document.path(&["writer", "state_before"])?.text()?, "held");
        assert_eq!(document.path(&["writer", "state_after"])?.text()?, "held");
        assert!(document.path(&["writer", "possibly_stale"])?.boolean()?);
        assert!(degraded_kinds(&document)?.contains(&"possibly_stale"));
    }
    let (document, _) = read_status(&root)?;
    assert_eq!(
        document.path(&["writer", "state_before"])?.text()?,
        "not_observed"
    );
    assert!(!document.path(&["writer", "possibly_stale"])?.boolean()?);
    assert!(!degraded_kinds(&document)?.contains(&"possibly_stale"));
    caplog("held_writer", "held=possibly_stale dropped=not_observed");
    Ok(())
}
