#![forbid(unsafe_code)]
//! Contract tests for `fss-event graph single-points` (`ALG-BRIDGE-001`, fss-w96u7) over a
//! deployment built through the real binaries: recordings are imported with `fss-file import`,
//! analysed with `fss-event watch`, and their coverage is retained only with the exact
//! `--retain-coverage` approval. The graph command then reads the committed head:
//!
//! 1. before any coverage is retained the projection is the evidence plane alone and no zone,
//!    sensor, cut vertex or bridge is claimed;
//! 2. with three sensors, a zone two sensors witnessed has no single point of failure, a zone one
//!    sensor witnessed names that sensor, a zone outside every frame is `not_observable`, and a
//!    sensor whose zones nobody else witnessed has a bridge uplink;
//! 3. the witness validates against `schemas/graph_algorithm_witness.v1.json`, pins the
//!    committed anchor, and its counters equal the exact `n` visits and `2m` scans;
//! 4. the command writes nothing (tree digest unchanged) and is byte-deterministic;
//! 5. malformed arguments and a foreign site are refused without output.

use std::collections::BTreeMap;
use std::error::Error;
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
const SITE: &str = "site:graph-cli";

// ---------------------------------------------------------------------------------------------
// Minimal strict JSON reader.
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
        skip(bytes, &mut position);
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
        keys.iter().try_fold(self, |current, key| current.get(key))
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

fn skip(bytes: &[u8], position: &mut usize) {
    while bytes.get(*position).is_some_and(u8::is_ascii_whitespace) {
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
    let mut out = Vec::new();
    loop {
        let byte = *bytes.get(*position).ok_or("unterminated string")?;
        *position += 1;
        match byte {
            b'"' => return Ok(String::from_utf8(out)?),
            b'\\' => {
                let escaped = *bytes.get(*position).ok_or("dangling escape")?;
                *position += 1;
                match escaped {
                    b'"' | b'\\' | b'/' => out.push(escaped),
                    b'n' => out.push(b'\n'),
                    b't' => out.push(b'\t'),
                    b'r' => out.push(b'\r'),
                    _ => return Err("unsupported escape".into()),
                }
            }
            byte if byte < 0x20 => return Err("raw control character".into()),
            byte => out.push(byte),
        }
    }
}

fn parse_value(bytes: &[u8], position: &mut usize) -> TestResult<Json> {
    skip(bytes, position);
    match bytes.get(*position).copied().ok_or("unexpected end")? {
        b'n' => expect(bytes, position, "null").map(|()| Json::Null),
        b't' => expect(bytes, position, "true").map(|()| Json::Bool(true)),
        b'f' => expect(bytes, position, "false").map(|()| Json::Bool(false)),
        b'"' => parse_string(bytes, position).map(Json::Text),
        b'[' => {
            *position += 1;
            let mut items = Vec::new();
            skip(bytes, position);
            if bytes.get(*position) == Some(&b']') {
                *position += 1;
                return Ok(Json::Array(items));
            }
            loop {
                items.push(parse_value(bytes, position)?);
                skip(bytes, position);
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
            skip(bytes, position);
            if bytes.get(*position) == Some(&b'}') {
                *position += 1;
                return Ok(Json::Object(fields));
            }
            loop {
                skip(bytes, position);
                let key = parse_string(bytes, position)?;
                if fields.iter().any(|(name, _)| *name == key) {
                    return Err(format!("duplicate key {key}").into());
                }
                skip(bytes, position);
                expect(bytes, position, ":")?;
                fields.push((key, parse_value(bytes, position)?));
                skip(bytes, position);
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

/// The raw text of top-level member `key` of a one-line JSON object (for schema validation of
/// the exact emitted bytes).
fn raw_member<'a>(text: &'a str, key: &str) -> TestResult<&'a str> {
    let marker = format!("\"{key}\":");
    let start = text.find(&marker).ok_or("member missing")? + marker.len();
    let bytes = text.as_bytes();
    let mut depth = 0_i32;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, &byte) in bytes[start..].iter().enumerate() {
        if in_string {
            match byte {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(&text[start..=start + offset]);
                }
            }
            _ => {}
        }
    }
    Err("unterminated member".into())
}

// ---------------------------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------------------------

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-graph-cli-{name}-{}-{attempt}",
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

/// Fourteen frames of one static grayscale level.
fn quiet_scene(level: u8) -> TestResult<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let pixels = vec![level; (WIDTH * HEIGHT) as usize];
    let mut stream = Vec::new();
    for _ in 0..FRAMES {
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

/// Imports a quiet recording for `sensor` with an operator capture hint; returns its identity.
fn import(directory: &OwnedDirectory, name: &str, sensor: &str, level: u8) -> TestResult<String> {
    let input = directory.0.join(format!("{name}.mjpeg"));
    fs::write(&input, quiet_scene(level)?)?;
    let output = Command::new(env!("CARGO_BIN_EXE_fss-file"))
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
        ])
        .args(["--capture-start-ns", "1000000000"])
        .args(["--capture-uncertainty-ns", "1000000"])
        .args(["--assumed-fps", "10"])
        .output()?;
    success(&output);
    fs::remove_file(input)?;
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .find_map(|line| line.strip_prefix("import_identity=").map(str::to_owned))
        .ok_or("import identity missing")?)
}

fn watch(root: &Path, import_id: &str, zones: &[&str], extra: &[&str]) -> TestResult<Json> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-event"));
    command.arg("watch").arg("--root").arg(root).args([
        "--site",
        SITE,
        "--import-id",
        import_id,
        "--interpretation",
        "gray",
    ]);
    for zone in zones {
        command.args(["--zone", zone]);
    }
    let output = command.args(extra).output()?;
    success(&output);
    Json::parse(String::from_utf8(output.stdout)?.trim_end())
}

/// Watches and retains the proposed coverage with its exact approval.
fn retain(root: &Path, import_id: &str, zones: &[&str]) -> TestResult {
    let preview = watch(root, import_id, zones, &[])?;
    let approval = preview
        .path(&["coverage", "approval_digest"])?
        .text()?
        .to_owned();
    let retained = watch(root, import_id, zones, &["--retain-coverage", &approval])?;
    assert_eq!(
        retained.path(&["coverage", "coverage_status"])?.text()?,
        "retained"
    );
    Ok(())
}

fn graph(args: &[&std::ffi::OsStr]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .arg("graph")
        .args(args)
        .output()?)
}

fn single_points(root: &Path, site: &str) -> TestResult<Output> {
    graph(&[
        "single-points".as_ref(),
        "--root".as_ref(),
        root.as_os_str(),
        "--site".as_ref(),
        site.as_ref(),
    ])
}

/// Every entry under `root`: mode, size, mtime, inode, and content digest.
fn tree_digest(root: &Path) -> TestResult<BTreeMap<PathBuf, String>> {
    let mut out = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let meta = fs::symlink_metadata(&path)?;
        let detail = if meta.file_type().is_dir() {
            let mut names = Vec::new();
            for entry in fs::read_dir(&path)? {
                let entry = entry?;
                names.push(entry.file_name().to_string_lossy().into_owned());
                pending.push(entry.path());
            }
            names.sort();
            format!("dir [{}]", names.join(","))
        } else {
            format!("file {}", ContentDigest::sha256(&fs::read(&path)?))
        };
        out.insert(
            path.strip_prefix(root)?.to_path_buf(),
            format!(
                "mode={:o} size={} mtime={}.{} ino={} {detail}",
                meta.mode(),
                meta.size(),
                meta.mtime(),
                meta.mtime_nsec(),
                meta.ino()
            ),
        );
    }
    Ok(out)
}

fn assert_conforms(schema: &str, instance: &str, scratch: &Path) -> TestResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let file = scratch.join("witness-instance.json");
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

struct ZoneRow<'a> {
    scope: &'a str,
    state: &'a str,
    observers: Vec<&'a str>,
    single_points: Vec<&'a str>,
}

fn zone_rows(report: &Json) -> TestResult<Vec<ZoneRow<'_>>> {
    report
        .get("zones")?
        .items()?
        .iter()
        .map(|zone| {
            Ok(ZoneRow {
                scope: zone.get("scope")?.text()?,
                state: zone.get("state")?.text()?,
                observers: zone.get("observers")?.texts()?,
                single_points: zone.get("single_points_of_failure")?.texts()?,
            })
        })
        .collect()
}

#[test]
fn single_points_of_retained_coverage_are_certified_read_only_and_deterministic() -> TestResult {
    let directory = OwnedDirectory::new("mesh")?;
    let root = directory.root();
    let north = import(&directory, "north", "sensor:north", 40)?;

    // 1. Nothing retained yet: only the evidence plane.
    let empty = single_points(&root, SITE)?;
    success(&empty);
    let empty = Json::parse(String::from_utf8(empty.stdout)?.trim_end())?;
    assert_eq!(empty.path(&["projection", "node_count"])?.number()?, 1);
    assert_eq!(
        empty
            .path(&["projection", "retained_coverage_records"])?
            .number()?,
        0
    );
    assert!(empty.get("zones")?.items()?.is_empty());
    assert!(
        empty
            .path(&["algorithm", "articulation_points"])?
            .items()?
            .is_empty()
    );

    // 2. Three sensors through the real watch flow.
    let south = import(&directory, "south", "sensor:south", 60)?;
    let east = import(&directory, "east", "sensor:east", 80)?;
    retain(&root, &north, &["door:64,0,32,32", "gate:0,0,32,32"])?;
    retain(&root, &south, &["door:64,0,32,32", "attic:80,32,32,32"])?;
    retain(&root, &east, &["shed:16,8,32,32"])?;

    let before = tree_digest(&root)?;
    let first = single_points(&root, SITE)?;
    success(&first);
    let second = single_points(&root, SITE)?;
    success(&second);
    assert_eq!(first.stdout, second.stdout, "byte-deterministic");
    assert_eq!(tree_digest(&root)?, before, "the command writes nothing");
    let text = String::from_utf8(first.stdout)?;
    let report = Json::parse(text.trim_end())?;
    assert_eq!(
        report.get("format")?.text()?,
        "fss.coverage_single_points.v1"
    );
    assert_eq!(
        report
            .path(&["projection", "retained_coverage_records"])?
            .number()?,
        3
    );

    let zones = zone_rows(&report)?;
    let scopes: Vec<&str> = zones.iter().map(|zone| zone.scope).collect();
    assert_eq!(
        scopes,
        ["zone:attic", "zone:door", "zone:gate", "zone:shed"]
    );
    assert_eq!(
        (zones[0].state, zones[0].observers.len()),
        ("not_observable", 0)
    );
    assert_eq!(zones[1].state, "multiple_observers");
    assert_eq!(zones[1].observers, ["sensor:north", "sensor:south"]);
    assert!(zones[1].single_points.is_empty());
    assert_eq!(zones[2].state, "single_observer");
    assert_eq!(zones[2].single_points, ["sensor:north"]);
    assert_eq!(zones[3].single_points, ["sensor:east"]);

    let sensors: Vec<(&str, Vec<&str>, &Json)> = report
        .get("sensors")?
        .items()?
        .iter()
        .map(|sensor| {
            Ok((
                sensor.get("sensor_id")?.text()?,
                sensor.get("sole_observer_of")?.texts()?,
                sensor.get("uplink_is_bridge")?,
            ))
        })
        .collect::<TestResult<_>>()?;
    assert_eq!(
        sensors,
        vec![
            ("sensor:east", vec!["zone:shed"], &Json::Bool(true)),
            ("sensor:north", vec!["zone:gate"], &Json::Bool(false)),
            ("sensor:south", vec![], &Json::Bool(false)),
        ]
    );
    assert_eq!(
        report
            .path(&["algorithm", "articulation_points"])?
            .texts()?,
        [
            "plane/site:graph-cli",
            "sensor/sensor:east",
            "sensor/sensor:north"
        ]
    );
    assert_eq!(
        report
            .path(&["algorithm", "unreachable_from_root"])?
            .texts()?,
        ["zone/zone:attic"]
    );

    // 3. The witness conforms, pins the committed anchor, and carries exact counters.
    let witness = report.get("witness")?;
    assert_eq!(witness.get("algorithmId")?.text()?, "ALG-BRIDGE-001");
    assert_eq!(witness.get("stopReason")?.text()?, "completed");
    assert_eq!(witness.get("exactness")?.text()?, "exact");
    assert_eq!(witness.get("errorBound")?, &Json::Null);
    let (n, m) = (
        witness.get("nodeCount")?.number()?,
        witness.get("edgeCount")?.number()?,
    );
    // plane + 3 sensors + 4 zones; 3 uplinks + 4 witnessed (sensor, zone) pairs.
    assert_eq!((n, m), (8, 7));
    let counts = witness.get("dominantOperationCounts")?;
    assert_eq!(counts.get("dfs_node_visits")?.number()?, n);
    assert_eq!(counts.get("adjacency_scans")?.number()?, 2 * m);
    assert!(
        counts.get("low_link_updates")?.number()?
            <= report
                .path(&["algorithm", "complexity_bound", "low_link_updates"])?
                .number()?
    );
    assert_eq!(witness.path(&["anchor", "deploymentId"])?.text()?, SITE);
    assert_eq!(
        witness.get("inputDigest")?.text()?,
        report.path(&["projection", "input_digest"])?.text()?
    );
    assert_conforms(
        "graph_algorithm_witness.v1.json",
        raw_member(text.trim_end(), "witness")?,
        &directory.0,
    )?;

    // 5. Refusals.
    let foreign = single_points(&root, "site:elsewhere")?;
    assert!(!foreign.status.success());
    assert!(foreign.stdout.is_empty());
    let unknown = graph(&["cuts".as_ref()])?;
    assert!(!unknown.status.success());
    assert!(String::from_utf8(unknown.stderr)?.contains("ERR-CLI-MALFORMED-VALUE-001"));
    let missing = graph(&[
        "single-points".as_ref(),
        "--root".as_ref(),
        root.as_os_str(),
    ])?;
    assert!(!missing.status.success());
    let absent = single_points(&directory.0.join("absent"), SITE)?;
    assert!(!absent.status.success());
    assert!(absent.stdout.is_empty());
    Ok(())
}
