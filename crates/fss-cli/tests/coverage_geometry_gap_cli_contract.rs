#![forbid(unsafe_code)]
//! Contract tests, through the real binaries, for geometric ground-zone coverage
//! (fss-2h5zq.53) and decode refusals as coverage gaps (fss-fnrgr follow-up):
//!
//! 1. `fss-event corroborate` with owner calibrated poses and an owner scene mesh (an fss-twin
//!    package): a ground zone fully in view is covered with its recorded visible fraction and a
//!    mesh-checked occlusion model; behind an opaque mesh wall the zone is `not_observable` with
//!    reason `occluded`, orient says so and follow certifies no silence;
//! 2. without a mesh the claim is frustum-only: `occlusion_unknown` in the visibility block,
//!    "frustum-only" in every witness predicate, and orient's declared domain and zone cell say
//!    so; a zone outside the frustum is `outside_frustum` with no witness;
//! 3. `fss-event watch --tolerate-decode-refusals` over a corrupt MJPEG frame gives one
//!    `decode_refused` interval with its error id and no track bridging; without the flag the
//!    run refuses exactly as before; a retained record split by the gap is not observable in
//!    orient and follow certifies no silence over it;
//! 4. an H.264 stream with a corrupted P slice resumes at the next IDR, every segment between is
//!    refused and uncovered, and the output is deterministic;
//! 5. a mesh whose digest does not match and a pose that disagrees with its homography are typed
//!    refusals; every answer and witness conforms to its registered schema.

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

const SITE: &str = "site:coverage-geometry-cli";
const H264: &[u8] =
    include_bytes!("../../fss-codec-h264/tests/fixtures/decode/p_qcif_ref3_p4x4.h264");
/// East sees the ground from 10 units above (48, 24): `x = u`, `y = 48 - v`.
const EAST_GROUND: &str = "east:1,0,0,0,-1,48,0,0,1";
/// West is rotated half a turn about the vertical: `x = 96 - u`, `y = v`.
const WEST_GROUND: &str = "west:-1,0,96,0,1,0,0,0,1";
/// The calibrated poses those homographies describe (W,H,fx,fy,cx,cy,R row-major,t = -R*centre).
const EAST_POSE: &str = "east:96,48,10,10,48,24,1,0,0,0,-1,0,0,0,-1,-48,24,10";
const WEST_POSE: &str = "west:96,48,10,10,48,24,-1,0,0,0,1,0,0,0,-1,48,-24,10";

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
                "fss-coverage-geometry-cli-{name}-{}-{attempt}",
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
    Quiet,
    Right,
    Left,
}

/// Fourteen 96x48 grayscale MJPEG frames. `Right`/`Left`: a bright 16x16 square moves 8 px per
/// frame from frame 3. With `corrupt`, that frame's SOF0 names quantization table 4, which the
/// canonical codec refuses as malformed.
fn scene(kind: Scene, corrupt: Option<usize>) -> TestResult<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..14_usize {
        let mut pixels = vec![40_u8; 96 * 48];
        let left = match kind {
            Scene::Quiet => None,
            Scene::Right => (index >= 3).then(|| (index - 3) * 8),
            Scene::Left => (index >= 3).then(|| 80 - (index - 3) * 8),
        };
        if let Some(left) = left {
            for y in 8..24 {
                for x in left..left + 16 {
                    pixels[y * 96 + x] = 220;
                }
            }
        }
        let mut frame = encode_jpeg(96, 48, &pixels, &config)?;
        if corrupt == Some(index) {
            let sof = frame
                .windows(2)
                .position(|pair| pair == [0xFF, 0xC0])
                .ok_or("no SOF0 marker")?;
            frame[sof + 12] = 4;
        }
        stream.extend(frame);
    }
    Ok(stream)
}

/// Two copies of `p_qcif_ref3_p4x4` (IDR at segments 0 and 12) with the P slice of segment 3
/// truncated to 20 bytes.
fn corrupted_h264() -> TestResult<Vec<u8>> {
    let mut starts = Vec::new();
    let mut from = 0;
    while let Some(offset) = H264[from..].windows(3).position(|w| w == [0, 0, 1]) {
        starts.push(from + offset + 3);
        from += offset + 3;
    }
    let slice = *starts.get(6).ok_or("fixture NAL layout")?;
    let next = *starts.get(7).ok_or("fixture NAL layout")?;
    if H264[slice] & 0x1f != 1 {
        return Err("expected a non-IDR slice".into());
    }
    let resume = if H264[next - 4] == 0 {
        next - 4
    } else {
        next - 3
    };
    let mut stream = H264[..slice + 20].to_vec();
    stream.extend_from_slice(&H264[resume..]);
    stream.extend_from_slice(H264);
    Ok(stream)
}

fn text(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
}

/// An fss-twin `FSSTWIN1` package (source scene digest `01..01`): an opaque ground plane at
/// z = 0 and, optionally, an opaque wall in the plane x = 52 (z 0..20) that stands between both
/// cameras (10 units above (48, 24)) and every ground point with x > 52.
fn twin_package(wall: bool) -> Vec<u8> {
    let mut body = vec![1_u8; 32];
    text(&mut body, "test/Z-up");
    text(&mut body, "synthetic");
    body.push(0);
    for value in [0.0_f64, -1.0, -1.0] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    let mut vertices: Vec<[f64; 3]> = vec![
        [-100.0, -100.0, 0.0],
        [200.0, -100.0, 0.0],
        [200.0, 200.0, 0.0],
        [-100.0, 200.0, 0.0],
    ];
    let mut triangles: Vec<[u32; 4]> = vec![[0, 1, 2, 0], [0, 2, 3, 0]];
    let objects: u32 = if wall { 2 } else { 1 };
    if wall {
        vertices.extend([
            [52.0, -10.0, 0.0],
            [52.0, 60.0, 0.0],
            [52.0, 60.0, 20.0],
            [52.0, -10.0, 20.0],
        ]);
        triangles.extend([[4, 5, 6, 1], [4, 6, 7, 1]]);
    }
    for count in [
        objects,
        objects,
        vertices.len() as u32,
        triangles.len() as u32,
    ] {
        body.extend_from_slice(&count.to_le_bytes());
    }
    text(&mut body, "ground");
    body.push(1);
    if wall {
        text(&mut body, "wall");
        body.push(5);
    }
    text(&mut body, "ground");
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(&[1, 1]);
    if wall {
        text(&mut body, "wall");
        body.extend_from_slice(&1_u32.to_le_bytes());
        body.extend_from_slice(&[0, 1]);
    }
    for vertex in &vertices {
        for value in vertex {
            body.extend_from_slice(&value.to_le_bytes());
        }
    }
    for triangle in &triangles {
        for value in triangle {
            body.extend_from_slice(&value.to_le_bytes());
        }
    }
    let mut package = b"FSSTWIN1".to_vec();
    package.extend_from_slice(&(body.len() as u64).to_le_bytes());
    package.extend_from_slice(&body);
    let trailer = ContentDigest::sha256(&package).bytes();
    package.extend_from_slice(&trailer);
    package
}

fn source_scene() -> String {
    format!("sha256:{}", "01".repeat(32))
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

/// Imports `bytes` for `sensor` with an operator capture hint (10 fps from 1 s, 1 ms
/// uncertainty). Returns the import identity.
fn import(
    directory: &OwnedDirectory,
    name: &str,
    bytes: &[u8],
    format: &str,
    sensor: &str,
) -> TestResult<String> {
    let input = directory.0.join(format!("{name}.media"));
    fs::write(&input, bytes)?;
    let output = Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("import")
        .arg("--root")
        .arg(directory.root())
        .args(["--site", SITE, "--input"])
        .arg(&input)
        .args(["--sensor", sensor, "--stream", &format!("stream:{name}")])
        .args([
            "--media-format",
            format,
            "--receive-time-ns",
            "10000000000000",
            "--capture-start-ns",
            "1000000000",
            "--capture-uncertainty-ns",
            "1000000",
            "--assumed-fps",
            "10",
        ])
        .output()?;
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

fn watch(
    root: &Path,
    import_id: &str,
    zone: &str,
    interpretation: &str,
    extra: &[&str],
) -> TestResult<Output> {
    let mut args = vec![
        "--import-id",
        import_id,
        "--interpretation",
        interpretation,
        "--zone",
        zone,
    ];
    args.extend_from_slice(extra);
    event(root, "watch", &args)
}

/// Two recordings of distinct sensors: quiet scenes (no entry interrupts coverage), or one moving
/// square seen mirrored (east: `Right`, west: `Left`).
fn recordings(directory: &OwnedDirectory, moving: bool) -> TestResult<[String; 2]> {
    let (east, west) = if moving {
        (Scene::Right, Scene::Left)
    } else {
        (Scene::Quiet, Scene::Quiet)
    };
    Ok([
        format!(
            "east:{}",
            import(
                directory,
                "east",
                &scene(east, None)?,
                "mjpeg",
                "sensor:east"
            )?
        ),
        format!(
            "west:{}",
            import(
                directory,
                "west",
                &scene(west, None)?,
                "mjpeg",
                "sensor:west"
            )?
        ),
    ])
}

fn corroborate(root: &Path, cameras: &[String; 2], extra: &[&str]) -> TestResult<Output> {
    let mut args = vec![
        "--camera",
        &cameras[0],
        "--camera",
        &cameras[1],
        "--ground",
        EAST_GROUND,
        "--ground",
        WEST_GROUND,
        "--zone",
        "door:56,0,40,48",
        "--zone",
        "far:200,0,40,48",
        "--interpretation",
        "gray",
        "--time-gate-ns",
        "250000000",
        "--distance-gate",
        "16",
    ];
    args.extend_from_slice(extra);
    event(root, "corroborate", &args)
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

/// The zone `id` of every record of a report's coverage block.
fn zones<'a>(report: &'a Json, id: &str) -> TestResult<Vec<&'a Json>> {
    let mut found = Vec::new();
    for record in report.path(&["coverage", "records"])?.items()? {
        for zone in record.get("zones")?.items()? {
            if zone.get("zone_id")?.text()? == id {
                found.push(zone);
            }
        }
    }
    Ok(found)
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

/// Every entry under `root`: mode, size, mtime, inode and content digest.
fn tree_digest(root: &Path) -> TestResult<BTreeMap<PathBuf, String>> {
    let mut out = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let meta = fs::symlink_metadata(&path)?;
        let relative = path.strip_prefix(root)?.to_path_buf();
        let common = format!(
            "mode={:o} size={} mtime={}.{} ino={}",
            meta.mode(),
            meta.size(),
            meta.mtime(),
            meta.mtime_nsec(),
            meta.ino()
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
        } else {
            format!("file {}", ContentDigest::sha256(&fs::read(&path)?))
        };
        out.insert(relative, format!("{common} {detail}"));
    }
    Ok(out)
}

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
/// negative predicates.
fn witness_predicates(coverage: &Json, scratch: &Path, label: &str) -> TestResult<Vec<String>> {
    let mut predicates = Vec::new();
    for record in coverage.get("records")?.items()? {
        for zone in record.get("zones")?.items()? {
            for witness in zone.get("witnesses")?.items()? {
                let inner = witness.get("witness")?;
                assert_conforms("coverage_witness.v1.json", &render(inner), scratch, label)?;
                predicates.push(inner.get("negativePredicate")?.text()?.to_owned());
            }
        }
    }
    Ok(predicates)
}

/// Orients `root` (brief) read-only and schema-checked; returns (envelope, anchor token).
fn orient(root: &Path, scratch: &Path, label: &str) -> TestResult<(Json, String)> {
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
    Ok((envelope, token))
}

/// Follows `root` since `since` (brief), read-only and schema-checked.
fn follow(root: &Path, since: &str, scratch: &Path, label: &str) -> TestResult<Json> {
    let before = tree_digest(root)?;
    let (code, stdout, stderr) = run_fss(&command_args(
        "follow",
        root,
        &["--since", since, "--view", "brief"],
    ))?;
    assert_eq!(code, Some(0), "stdout: {stdout} stderr: {stderr}");
    assert_answer_conforms(&stdout, "agent_meaningful_delta.v1.json", scratch, label)?;
    assert_eq!(tree_digest(root)?, before, "follow writes nothing");
    Json::parse(stdout.trim_end())
}

fn frame_coverage(envelope: &Json) -> TestResult<&Json> {
    envelope.path(&["payload", "situationFrame", "coverage"])
}

/// The coverage cells whose claim ends with `scope` (one per sensor).
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

/// Retains `report`'s coverage by rerunning `rerun` with its exact approval.
fn retain(proposal: &Json, rerun: impl Fn(&[&str]) -> TestResult<Output>) -> TestResult {
    let approval = proposal
        .path(&["coverage", "approval_digest"])?
        .text()?
        .to_owned();
    let retained = report(&rerun(&["--retain-coverage", &approval])?)?;
    assert_eq!(
        retained.path(&["coverage", "coverage_status"])?.text()?,
        "retained"
    );
    Ok(())
}

/// No silence certificate: the orientation's coverage gap persists as protected coverage loss.
fn assert_no_silence(root: &Path, scratch: &Path, label: &str) -> TestResult {
    let (_, token) = orient(root, scratch, label)?;
    let delta = follow(root, &token, scratch, label)?;
    let payload = delta.get("payload")?;
    assert_eq!(payload.get("silenceCertificate")?, &Json::Null, "{label}");
    assert!(
        payload.get("classes")?.texts()?.contains(&"coverage_loss"),
        "{label}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Geometric ground-zone coverage.
// ---------------------------------------------------------------------------------------------

#[test]
fn without_a_mesh_ground_coverage_is_frustum_only_and_a_zone_outside_the_frustum_is_not_observable()
-> TestResult {
    let directory = OwnedDirectory::new("frustum")?;
    let root = directory.root();
    let cameras = recordings(&directory, false)?;
    let preview = report(&corroborate(&root, &cameras, &[])?)?;
    let doors = zones(&preview, "door")?;
    assert_eq!(doors.len(), 2);
    for door in doors {
        let visibility = door.get("visibility")?;
        assert_eq!(visibility.get("camera_model")?.text()?, "owner_homography");
        assert_eq!(visibility.get("sampling")?.text()?, "grid-cell-centers:8x8");
        assert_eq!(visibility.get("samples")?.number()?, 64);
        assert_eq!(visibility.get("visible")?.number()?, 64);
        assert_eq!(visibility.get("visible_fraction_ppm")?.number()?, 1_000_000);
        assert_eq!(visibility.get("threshold_ppm")?.number()?, 1_000_000);
        assert_eq!(visibility.get("state")?.text()?, "observable");
        assert_eq!(visibility.get("occlusion")?.text()?, "occlusion_unknown");
        assert_eq!(
            visibility.get("occlusion_unknown_reason")?.text()?,
            "no_scene_mesh"
        );
        assert_eq!(visibility.get("claim")?.text()?, "frustum_only");
        assert!(door.get("witness_count")?.number()? > 0);
    }
    for far in zones(&preview, "far")? {
        let visibility = far.get("visibility")?;
        assert_eq!(visibility.get("state")?.text()?, "not_observable");
        assert_eq!(visibility.get("cause")?.text()?, "outside_frustum");
        assert_eq!(visibility.get("outside_frustum")?.number()?, 64);
        assert_eq!(far.get("witness_count")?.number()?, 0);
        let gaps = uncovered(far)?;
        assert_eq!(gaps, vec![("outside_frustum".to_owned(), 0, 13)]);
    }
    let predicates = witness_predicates(preview.get("coverage")?, &directory.0, "frustum")?;
    assert!(!predicates.is_empty());
    for predicate in &predicates {
        assert!(predicate.contains("frustum-only"), "{predicate}");
        assert!(predicate.contains("occlusion_unknown"), "{predicate}");
        assert!(predicate.contains("64 of 64 ground samples"), "{predicate}");
    }
    // Deterministic, then retained with the exact approval.
    let again = report(&corroborate(&root, &cameras, &[])?)?;
    assert_eq!(again, preview);
    retain(&preview, |extra| corroborate(&root, &cameras, extra))?;

    let (oriented, _) = orient(&root, &directory.0, "frustum orient")?;
    let frame = frame_coverage(&oriented)?;
    let domains = frame.get("domains")?.texts()?;
    assert!(
        domains
            .iter()
            .any(|domain| domain.contains("ground-zone:door")
                && domain.contains("(frustum-only: occlusion_unknown)")),
        "{domains:?}"
    );
    let gaps = frame.get("gaps")?.texts()?;
    assert!(
        gaps.iter().any(|gap| gap.contains("covered frustum-only")),
        "{gaps:?}"
    );
    assert!(
        gaps.iter()
            .any(|gap| gap.contains("not covered (outside_frustum")),
        "{gaps:?}"
    );
    for cell in zone_cells(&oriented, ":ground-zone:door")? {
        assert_eq!(cell.get("knowledgeState")?.text()?, "known");
        assert!(cell.get("value")?.text()?.contains("frustum-only"));
    }
    let far_cells = zone_cells(&oriented, ":ground-zone:far")?;
    assert_eq!(far_cells.len(), 2);
    for cell in far_cells {
        assert_eq!(cell.get("knowledgeState")?.text()?, "not_observable");
    }
    assert_no_silence(&root, &directory.0, "frustum follow")
}

#[test]
fn with_poses_and_a_scene_mesh_the_zone_in_view_is_covered_and_behind_a_wall_it_is_occluded()
-> TestResult {
    for wall in [false, true] {
        let directory = OwnedDirectory::new(if wall { "walled" } else { "open" })?;
        let root = directory.root();
        let cameras = recordings(&directory, false)?;
        let package = twin_package(wall);
        let mesh = directory.0.join("scene.fsstwin");
        fs::write(&mesh, &package)?;
        let mesh_path = mesh.to_str().ok_or("UTF-8 path")?.to_owned();
        let mesh_digest = ContentDigest::sha256(&package).to_text();
        let source = source_scene();
        let geometry = [
            "--pose",
            EAST_POSE,
            "--pose",
            WEST_POSE,
            "--scene-mesh",
            &mesh_path,
            "--scene-mesh-digest",
            &mesh_digest,
            "--scene-source-digest",
            &source,
        ];
        let run = |extra: &[&str]| -> TestResult<Output> {
            let mut args = geometry.to_vec();
            args.extend_from_slice(extra);
            corroborate(&root, &cameras, &args)
        };
        let preview = report(&run(&[])?)?;
        assert_eq!(preview.get("candidate_count")?.number()?, 0);
        let doors = zones(&preview, "door")?;
        assert_eq!(doors.len(), 2);
        for door in &doors {
            let visibility = door.get("visibility")?;
            assert_eq!(visibility.get("camera_model")?.text()?, "calibrated_pose");
            assert_eq!(visibility.get("occlusion")?.text()?, "mesh_checked");
            assert_eq!(visibility.get("scene_mesh_digest")?.text()?, mesh_digest);
            assert_eq!(visibility.get("occlusion_unknown_reason")?, &Json::Null);
            assert_eq!(
                visibility.get("claim")?.text()?,
                "frustum_and_mesh_occlusion"
            );
            if wall {
                assert_eq!(visibility.get("visible")?.number()?, 0);
                assert_eq!(visibility.get("occluded")?.number()?, 64);
                assert_eq!(visibility.get("state")?.text()?, "not_observable");
                assert_eq!(visibility.get("cause")?.text()?, "occluded");
                assert_eq!(door.get("witness_count")?.number()?, 0);
                assert_eq!(uncovered(door)?, vec![("occluded".to_owned(), 0, 13)]);
            } else {
                assert_eq!(visibility.get("visible")?.number()?, 64);
                assert_eq!(visibility.get("visible_fraction_ppm")?.number()?, 1_000_000);
                assert_eq!(visibility.get("state")?.text()?, "observable");
                assert_eq!(visibility.get("cause")?, &Json::Null);
                assert!(door.get("witness_count")?.number()? > 0);
            }
        }
        for predicate in witness_predicates(preview.get("coverage")?, &directory.0, "mesh")? {
            if predicate.contains("ground-zone:door") {
                assert!(
                    predicate.contains("occlusion checked against owner scene mesh"),
                    "{predicate}"
                );
                assert!(!predicate.contains("frustum-only"), "{predicate}");
            }
        }
        retain(&preview, run)?;
        let (oriented, _) = orient(&root, &directory.0, "mesh orient")?;
        let door_cells = zone_cells(&oriented, ":ground-zone:door")?;
        assert_eq!(door_cells.len(), 2);
        for cell in door_cells {
            let state = cell.get("knowledgeState")?.text()?;
            if wall {
                assert_eq!(state, "not_observable");
                assert!(cell.get("value")?.text()?.contains("occluded"));
            } else {
                assert_eq!(state, "known");
                assert!(!cell.get("value")?.text()?.contains("frustum-only"));
            }
        }
        if wall {
            let gaps = frame_coverage(&oriented)?.get("gaps")?.texts()?;
            assert!(
                gaps.iter()
                    .any(|gap| gap.contains("ground-zone:door")
                        && gap.contains("not covered (occluded")),
                "{gaps:?}"
            );
            assert_no_silence(&root, &directory.0, "walled follow")?;
        }
    }
    Ok(())
}

#[test]
fn a_mismatched_mesh_digest_and_a_disagreeing_pose_are_typed_refusals() -> TestResult {
    let directory = OwnedDirectory::new("geometry-refusals")?;
    let root = directory.root();
    let cameras = recordings(&directory, true)?;
    let package = twin_package(true);
    let mesh = directory.0.join("scene.fsstwin");
    fs::write(&mesh, &package)?;
    let mesh_path = mesh.to_str().ok_or("UTF-8 path")?.to_owned();
    let other = ContentDigest::sha256(b"another package").to_text();
    let source = source_scene();
    let untouched = tree_digest(&root)?;
    let mismatch = corroborate(
        &root,
        &cameras,
        &[
            "--pose",
            EAST_POSE,
            "--scene-mesh",
            &mesh_path,
            "--scene-mesh-digest",
            &other,
            "--scene-source-digest",
            &source,
        ],
    )?;
    assert!(!mismatch.status.success());
    assert_eq!(refusal(&mismatch), "ERR-CORROBORATE-VISIBILITY-001");
    assert!(mismatch.stdout.is_empty());
    // East with west's calibration: the pose and the east homography disagree.
    let swapped = format!("east:{}", WEST_POSE.trim_start_matches("west:"));
    let disagreeing = corroborate(&root, &cameras, &["--pose", &swapped])?;
    assert!(!disagreeing.status.success());
    assert_eq!(refusal(&disagreeing), "ERR-CORROBORATE-POSE-INVALID-001");
    let unknown = corroborate(
        &root,
        &cameras,
        &[
            "--pose",
            "north:96,48,10,10,48,24,1,0,0,0,-1,0,0,0,-1,-48,24,10",
        ],
    )?;
    assert!(!unknown.status.success());
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("--pose names no --camera"));
    assert_eq!(tree_digest(&root)?, untouched, "refusals write nothing");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Decode refusals as coverage gaps.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_corrupt_mjpeg_frame_is_a_decode_refused_gap_only_when_tolerated_and_never_certified_silent()
-> TestResult {
    let directory = OwnedDirectory::new("mjpeg-gap")?;
    let root = directory.root();
    let id = import(
        &directory,
        "quiet",
        &scene(Scene::Quiet, Some(9))?,
        "mjpeg",
        "sensor:quiet",
    )?;
    let door = "door:64,0,32,32";
    // Default: today's refusal, nothing printed, nothing written.
    let untouched = tree_digest(&root)?;
    let strict = watch(&root, &id, door, "gray", &[])?;
    assert!(!strict.status.success());
    assert_eq!(refusal(&strict), "ERR-DECODE-001");
    assert!(strict.stdout.is_empty());
    assert_eq!(tree_digest(&root)?, untouched);

    let flag = ["--tolerate-decode-refusals"];
    let preview = report(&watch(&root, &id, door, "gray", &flag)?)?;
    assert_eq!(preview.get("frames_decoded")?.number()?, 13);
    let refusals = preview.get("decode_refusals")?.items()?;
    assert_eq!(refusals.len(), 1);
    assert_eq!(refusals[0].get("first_segment")?.number()?, 9);
    assert_eq!(refusals[0].get("last_segment")?.number()?, 9);
    assert_eq!(refusals[0].get("error_id")?.text()?, "ERR-DECODE-001");
    let zone = &zones(&preview, "door")?[0];
    assert_eq!(
        uncovered(zone)?,
        vec![
            ("background_warmup".to_owned(), 0, 3),
            ("confirmation_latency".to_owned(), 7, 8),
            ("decode_refused".to_owned(), 9, 9),
            ("confirmation_latency".to_owned(), 12, 13),
        ]
    );
    let refused = zone
        .get("uncovered")?
        .items()?
        .iter()
        .find(|gap| {
            gap.get("reason")
                .and_then(Json::text)
                .is_ok_and(|r| r == "decode_refused")
        })
        .ok_or("decode_refused interval")?;
    assert_eq!(refused.get("error_id")?.text()?, "ERR-DECODE-001");
    let spans: Vec<(u64, u64)> = zone
        .get("witnesses")?
        .items()?
        .iter()
        .map(|w| {
            Ok((
                w.get("first_segment")?.number()?,
                w.get("last_segment")?.number()?,
            ))
        })
        .collect::<TestResult<_>>()?;
    assert_eq!(
        spans,
        [(4, 6), (10, 11)],
        "no witness spans the refused frame"
    );
    witness_predicates(preview.get("coverage")?, &directory.0, "mjpeg gap")?;
    let command = preview.path(&["coverage", "retain_command"])?.text()?;
    assert!(
        command.contains("--tolerate-decode-refusals"),
        "the rerun reproduces the tolerant analysis: {command}"
    );
    let again = watch(&root, &id, door, "gray", &flag)?;
    assert_eq!(report(&again)?, preview, "deterministic");
    assert_eq!(tree_digest(&root)?, untouched, "a preview writes nothing");

    retain(&preview, |extra| {
        let mut args = flag.to_vec();
        args.extend_from_slice(extra);
        watch(&root, &id, door, "gray", &args)
    })?;
    let (oriented, _) = orient(&root, &directory.0, "gap orient")?;
    let cells = zone_cells(&oriented, ":zone:door")?;
    assert_eq!(cells.len(), 1);
    assert_eq!(cells[0].get("knowledgeState")?.text()?, "not_observable");
    let gaps = frame_coverage(&oriented)?.get("gaps")?.texts()?;
    assert!(
        gaps.iter()
            .any(|gap| gap.contains("not covered (decode_refused ERR-DECODE-001)")),
        "{gaps:?}"
    );
    assert!(
        gaps.iter()
            .any(|gap| gap.contains("not observable between")),
        "{gaps:?}"
    );
    assert_no_silence(&root, &directory.0, "gap follow")
}

#[test]
fn a_moving_object_is_never_tracked_across_a_refused_frame() -> TestResult {
    let directory = OwnedDirectory::new("mjpeg-bridge")?;
    let root = directory.root();
    let id = import(
        &directory,
        "moving",
        &scene(Scene::Right, Some(6))?,
        "mjpeg",
        "sensor:moving",
    )?;
    let preview = report(&watch(
        &root,
        &id,
        "door:64,0,32,32",
        "gray",
        &["--tolerate-decode-refusals"],
    )?)?;
    assert_eq!(preview.get("candidate_count")?.number()?, 1);
    let candidate = &preview.get("candidates")?.items()?[0];
    let range = candidate.get("frame_range")?.items()?;
    assert!(range[0].number()? > 6, "the track starts after the gap");
    for evidence in candidate.get("evidence")?.items()? {
        assert!(evidence.get("segment")?.number()? > 6);
    }
    let zone = &zones(&preview, "door")?[0];
    let refused: Vec<(String, u64, u64)> = uncovered(zone)?
        .into_iter()
        .filter(|(reason, _, _)| reason == "decode_refused")
        .collect();
    assert_eq!(refused, vec![("decode_refused".to_owned(), 6, 6)]);
    for witness in zone.get("witnesses")?.items()? {
        let (first, last) = (
            witness.get("first_segment")?.number()?,
            witness.get("last_segment")?.number()?,
        );
        assert!(last < 6 || first > 6);
    }
    Ok(())
}

#[test]
fn an_h264_stream_with_a_corrupted_p_slice_resumes_at_the_next_idr() -> TestResult {
    let directory = OwnedDirectory::new("h264-gap")?;
    let root = directory.root();
    let id = import(
        &directory,
        "avc",
        &corrupted_h264()?,
        "annexb",
        "sensor:avc",
    )?;
    let scene_zone = "scene:0,0,176,144";
    let strict = watch(&root, &id, scene_zone, "ycbcr", &[])?;
    assert!(!strict.status.success());
    assert_eq!(refusal(&strict), "ERR-DECODE-BOUNDS-001");
    let flag = ["--tolerate-decode-refusals"];
    let first = watch(&root, &id, scene_zone, "ycbcr", &flag)?;
    let preview = report(&first)?;
    assert_eq!(preview.get("frames_decoded")?.number()?, 15);
    let refusals = preview.get("decode_refusals")?.items()?;
    assert_eq!(refusals.len(), 1);
    assert_eq!(refusals[0].get("first_segment")?.number()?, 3);
    assert_eq!(refusals[0].get("last_segment")?.number()?, 11);
    assert_eq!(
        refusals[0].get("error_id")?.text()?,
        "ERR-DECODE-BOUNDS-001"
    );
    let zone = &zones(&preview, "scene")?[0];
    assert!(
        uncovered(zone)?.contains(&("decode_refused".to_owned(), 3, 11)),
        "{:?}",
        uncovered(zone)?
    );
    for witness in zone.get("witnesses")?.items()? {
        assert!(witness.get("first_segment")?.number()? >= 12);
    }
    let second = watch(&root, &id, scene_zone, "ycbcr", &flag)?;
    assert_eq!(second.stdout, first.stdout, "deterministic");
    Ok(())
}
