#![forbid(unsafe_code)]
//! Contract tests for owner-declared privacy masks (fss-bgqkd, GOAL-009) through the real
//! binaries: `fss-event privacy-mask declare` previews and, only with its exact approval, retains
//! a per-sensor mask policy; every retained decode (`fss-file decode` for JPEG, H.264 and H.265,
//! `fss-event watch`) then fills the masked pixels before any consumer, binds the policy into its
//! receipts and lineage, reports masked zones as not observable, and refuses unmasked access.
//!
//! 1. declaration: a preview writes nothing; a wrong or stale approval is refused before any
//!    write; the exact approval retains one generation; a rerun writes nothing;
//! 2. motion entirely inside a masked rectangle yields no candidate (the same scene without the
//!    mask yields one); a zone inside or partly inside the mask carries no witness
//!    (`privacy_masked`) while an unmasked zone keeps its witness; lineages never share a
//!    pipeline generation or coverage identity; orient reports the masked zone not_observable;
//! 3. the decoded PGM holds the fill inside the mask, byte-checked, and the source bytes outside;
//!    receipts differ with and without the policy; the pre-mask decode and raw extract are refused;
//! 4. the same holds on the H.264 and H.265 range decode paths, and an H.265 watch;
//! 5. a candidate outside the mask names the applied transform and publishes;
//! 6. every analysis is byte-for-byte deterministic.

use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::ContentDigest;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// 176x144 `testsrc2` scene, one IDR then eleven P pictures.
const H264: &[u8] =
    include_bytes!("../../fss-codec-h264/tests/fixtures/decode/p_qcif_ref3_p4x4.h264");
/// 96x48 libx265 encode of the moving-square scene (see the fixture README).
const HEVC: &[u8] =
    include_bytes!("../../fss-reference/tests/fixtures/hevc_ingest/watch_96x48_moving.h265");

const WIDTH: u32 = 96;
const HEIGHT: u32 = 48;
const FRAMES: usize = 14;
const SITE: &str = "site:privacy-mask-cli";
const DOOR: &str = "door:64,0,32,32";
/// Covers the whole band the square moves through (rows 8..24) and the door zone.
const BAND: &str = "0,0,96,32";

// ---------------------------------------------------------------------------------------------
// Minimal JSON reader: assertions go through a full parse.
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
// Fixtures and process helpers.
// ---------------------------------------------------------------------------------------------

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-privacy-mask-cli-{name}-{}-{attempt}",
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

/// Fourteen grayscale MJPEG frames on a dark background; with `moving`, a bright 16x16 square
/// enters at the left edge from frame 3 and moves 8 px right per frame through rows 8..24.
fn scene(moving: bool) -> TestResult<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..FRAMES {
        let mut pixels = vec![40_u8; (WIDTH * HEIGHT) as usize];
        if moving && index >= 3 {
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

fn refusal(output: &Output) -> String {
    assert!(!output.status.success(), "expected a refusal");
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .find_map(|line| line.strip_prefix("refusal_id=").map(str::to_owned))
        .unwrap_or_default()
}

/// Imports `bytes` for `sensor` (with an operator capture hint: 10 fps from 1 s).
fn import(
    directory: &OwnedDirectory,
    name: &str,
    bytes: &[u8],
    sensor: &str,
    format: &str,
) -> TestResult<String> {
    let input = directory.0.join(format!("{name}.bin"));
    fs::write(&input, bytes)?;
    let output = Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("import")
        .arg("--root")
        .arg(directory.root())
        .args(["--site", SITE, "--input"])
        .arg(&input)
        .args(["--sensor", sensor, "--stream", &format!("stream:{name}")])
        .args(["--media-format", format])
        .args(["--receive-time-ns", "10000000000000"])
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

fn event(root: &Path, args: &[&str]) -> TestResult<Output> {
    let (command, rest) = args.split_first().ok_or("empty event command")?;
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .arg(command)
        .args(rest.iter().take_while(|a| !a.starts_with("--")))
        .arg("--root")
        .arg(root)
        .args(["--site", SITE])
        .args(rest.iter().skip_while(|a| !a.starts_with("--")))
        .output()?)
}

fn mask(root: &Path, operation: &str, sensor: &str, extra: &[&str]) -> TestResult<Output> {
    let mut args = vec!["privacy-mask", operation, "--sensor", sensor];
    args.extend_from_slice(extra);
    event(root, &args)
}

fn report(output: &Output) -> TestResult<Json> {
    success(output);
    Json::parse(String::from_utf8(output.stdout.clone())?.trim_end())
}

/// Previews `rectangles` for `sensor`, then retains it with the previewed approval.
fn declare(root: &Path, sensor: &str, resolution: &str, rectangles: &[&str]) -> TestResult<Json> {
    let mut extra = vec!["--resolution", resolution];
    for rectangle in rectangles {
        extra.extend_from_slice(&["--rect", rectangle]);
    }
    let preview = report(&mask(root, "declare", sensor, &extra)?)?;
    assert_eq!(preview.get("status")?.text()?, "proposed");
    let approval = preview.get("approval_digest")?.text()?.to_owned();
    extra.extend_from_slice(&["--approve", &approval]);
    let retained = report(&mask(root, "declare", sensor, &extra)?)?;
    assert_eq!(retained.get("status")?.text()?, "retained");
    Ok(retained)
}

fn watch(root: &Path, import_id: &str, interpretation: &str, extra: &[&str]) -> TestResult<Output> {
    let mut args = vec![
        "watch",
        "--import-id",
        import_id,
        "--interpretation",
        interpretation,
    ];
    args.extend_from_slice(extra);
    event(root, &args)
}

fn file(root: &Path, action: &str, args: &[&str], output: Option<&Path>) -> TestResult<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-file"));
    command
        .arg(action)
        .arg("--root")
        .arg(root)
        .args(["--site", SITE])
        .args(args);
    if let Some(path) = output {
        command.arg("--output").arg(path);
    }
    Ok(command.output()?)
}

fn values(output: &Output, name: &str) -> TestResult<Vec<String>> {
    let prefix = format!("{name}=");
    Ok(String::from_utf8(output.stdout.clone())?
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix).map(str::to_owned))
        .collect())
}

fn field(output: &Output, name: &str) -> TestResult<String> {
    values(output, name)?
        .into_iter()
        .next()
        .ok_or_else(|| format!("missing field {name}").into())
}

/// Splits a (multi-image) binary PGM into its images' pixel planes.
fn pgm_images(bytes: &[u8], width: usize, height: usize) -> TestResult<Vec<Vec<u8>>> {
    let header = format!("P5\n{width} {height}\n255\n").into_bytes();
    let mut images = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let body = rest
            .strip_prefix(header.as_slice())
            .ok_or("unexpected PGM header")?;
        let (image, tail) = body.split_at_checked(width * height).ok_or("short PGM")?;
        images.push(image.to_vec());
        rest = tail;
    }
    Ok(images)
}

/// Asserts that every pixel inside `rect` is the fill and every pixel outside equals `source`.
fn assert_masked(masked: &[u8], source: &[u8], width: usize, rect: [usize; 4], label: &str) {
    let [x0, y0, w, h] = rect;
    assert_eq!(masked.len(), source.len(), "{label}");
    for (index, (value, original)) in masked.iter().zip(source).enumerate() {
        let (x, y) = (index % width, index / width);
        if (x0..x0 + w).contains(&x) && (y0..y0 + h).contains(&y) {
            assert_eq!(*value, 16, "{label}: masked pixel ({x},{y})");
        } else {
            assert_eq!(value, original, "{label}: unmasked pixel ({x},{y})");
        }
    }
    assert!(
        (0..w * h).any(|i| source[(y0 + i / w) * width + x0 + i % w] != 16),
        "{label}: the source must differ from the fill inside the mask"
    );
}

fn zone<'a>(record: &'a Json, zone_id: &str) -> TestResult<&'a Json> {
    record
        .get("zones")?
        .items()?
        .iter()
        .find(|zone| zone.get("zone_id").and_then(Json::text).ok() == Some(zone_id))
        .ok_or_else(|| format!("no zone {zone_id}").into())
}

fn reasons(zone: &Json) -> TestResult<Vec<(String, u64, u64)>> {
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

fn orient(root: &Path) -> TestResult<Json> {
    let output = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args([
            OsString::from("orient"),
            OsString::from("--json"),
            OsString::from("--root"),
            root.as_os_str().to_owned(),
            OsString::from("--view"),
            OsString::from("brief"),
        ])
        .output()?;
    success(&output);
    Json::parse(String::from_utf8(output.stdout)?.trim_end())
}

fn zone_state<'a>(envelope: &'a Json, scope: &str) -> TestResult<&'a str> {
    for cell in envelope
        .path(&["payload", "situationFrame", "knowledgeCells"])?
        .items()?
    {
        let id = cell.get("cellId")?.text()?;
        if id.starts_with("claim:coverage:") && id.ends_with(scope) {
            return cell.get("knowledgeState")?.text();
        }
    }
    Err(format!("no coverage cell for {scope}").into())
}

// ---------------------------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------------------------

#[test]
fn declaration_requires_the_exact_current_approval_and_reruns_write_nothing() -> TestResult {
    let directory = OwnedDirectory::new("declare")?;
    let root = directory.root();
    import(
        &directory,
        "quiet",
        &scene(false)?,
        "sensor:declare",
        "mjpeg",
    )?;
    let sensor = "sensor:declare";

    let shown = report(&mask(&root, "show", sensor, &[])?)?;
    assert_eq!(
        shown.path(&["privacy_mask", "binding"])?.text()?,
        "no_policy_declared"
    );
    assert_eq!(
        shown.path(&["privacy_mask", "applied_redaction_transform"])?,
        &Json::Null
    );
    let sequence = shown.get("authority_sequence")?.number()?;

    let spec = ["--resolution", "96x48", "--rect", BAND];
    let first = mask(&root, "declare", sensor, &spec)?;
    let preview = report(&first)?;
    assert_eq!(preview.get("status")?.text()?, "proposed");
    assert_eq!(preview.get("authority_sequence")?.number()?, sequence);
    assert_eq!(
        preview.get("applied_redaction_transform")?.text()?,
        "transform:bounding_box_redact"
    );
    assert_eq!(preview.get("unmasked_access")?.text()?, "refused");
    let approval = preview.get("approval_digest")?.text()?.to_owned();
    assert!(
        preview
            .get("approve_command")?
            .text()?
            .ends_with(&format!("--approve {approval}"))
    );
    let again = mask(&root, "declare", sensor, &spec)?;
    assert_eq!(again.stdout, first.stdout, "a preview is deterministic");

    // A wrong approval is refused before any write.
    let wrong = ContentDigest::sha256(b"not this mask").to_text();
    let mut refused_args = spec.to_vec();
    refused_args.extend_from_slice(&["--approve", &wrong]);
    let refused = mask(&root, "declare", sensor, &refused_args)?;
    assert_eq!(refusal(&refused), "ERR-PRIVACY-MASK-APPROVAL-STALE-001");
    assert!(refused.stdout.is_empty());
    let unchanged = report(&mask(&root, "show", sensor, &[])?)?;
    assert_eq!(unchanged.get("authority_sequence")?.number()?, sequence);

    // The exact approval retains generation 1; an exact rerun writes nothing.
    let mut approve = spec.to_vec();
    approve.extend_from_slice(&["--approve", &approval]);
    let retained = report(&mask(&root, "declare", sensor, &approve)?)?;
    assert_eq!(retained.get("status")?.text()?, "retained");
    assert_eq!(retained.get("generation")?.number()?, 1);
    assert_eq!(retained.get("approve_command")?, &Json::Null);
    let after = retained.get("authority_sequence")?.number()?;
    assert!(after > sequence);
    let rerun = report(&mask(&root, "declare", sensor, &approve)?)?;
    assert_eq!(rerun.get("status")?.text()?, "already_current");
    assert_eq!(rerun.get("authority_sequence")?.number()?, after);
    let current = report(&mask(&root, "show", sensor, &[])?)?;
    assert_eq!(
        current.path(&["privacy_mask", "binding"])?.text()?,
        "sensor_policy"
    );
    assert_eq!(
        current.path(&["privacy_mask", "policy_digest"])?.text()?,
        retained.get("policy_digest")?.text()?
    );

    // An approval previewed against generation 1 is stale once generation 2 exists.
    let stale_spec = ["--resolution", "96x48", "--rect", "0,0,48,48"];
    let stale = report(&mask(&root, "declare", sensor, &stale_spec)?)?;
    let stale_approval = stale.get("approval_digest")?.text()?.to_owned();
    let second = declare(&root, sensor, "96x48", &["0,0,96,16"])?;
    assert_eq!(second.get("generation")?.number()?, 2);
    assert_eq!(
        second.get("replaces")?.text()?,
        retained.get("policy_digest")?.text()?
    );
    let mut stale_args = stale_spec.to_vec();
    stale_args.extend_from_slice(&["--approve", &stale_approval]);
    let refused = mask(&root, "declare", sensor, &stale_args)?;
    assert_eq!(refusal(&refused), "ERR-PRIVACY-MASK-APPROVAL-STALE-001");

    // A rectangle outside the declared resolution is not a policy.
    let invalid = mask(
        &root,
        "declare",
        sensor,
        &["--resolution", "96x48", "--rect", "90,0,16,16"],
    )?;
    assert_eq!(refusal(&invalid), "ERR-PRIVACY-MASK-POLICY-001");
    Ok(())
}

#[test]
fn motion_inside_a_mask_yields_no_candidate_and_masked_zones_are_not_observable() -> TestResult {
    let directory = OwnedDirectory::new("watch")?;
    let root = directory.root();
    let sensor = "sensor:watch";
    let id = import(&directory, "moving", &scene(true)?, sensor, "mjpeg")?;
    // door: inside the mask; edge: straddles its lower border; yard: outside it.
    let zones = [
        "--zone",
        DOOR,
        "--zone",
        "edge:80,24,16,16",
        "--zone",
        "yard:0,36,96,12",
    ];

    let unmasked = report(&watch(&root, &id, "gray", &zones)?)?;
    assert_eq!(unmasked.get("candidate_count")?.number()?, 1);
    // Without a policy the report is unchanged (pinned by `watch_report_golden`).
    assert!(unmasked.get("privacy_mask").is_err());
    let unmasked_record = &unmasked.path(&["coverage", "records"])?.items()?[0];
    let yard_before = zone(unmasked_record, "yard")?;
    assert!(!yard_before.get("witnesses")?.items()?.is_empty());

    declare(&root, sensor, "96x48", &[BAND])?;
    let masked_output = watch(&root, &id, "gray", &zones)?;
    let masked = report(&masked_output)?;
    // The mask is applied before the foreground model: no box, no track, no candidate.
    assert_eq!(masked.get("candidate_count")?.number()?, 0);
    assert_eq!(masked.get("foreground_boxes")?.number()?, 0);
    assert_eq!(
        masked.path(&["privacy_mask", "binding"])?.text()?,
        "sensor_policy"
    );
    assert_eq!(
        masked
            .path(&["privacy_mask", "applied_redaction_transform"])?
            .text()?,
        "transform:bounding_box_redact"
    );
    assert_ne!(
        masked.get("plan_digest")?.text()?,
        unmasked.get("plan_digest")?.text()?
    );
    let repeated = watch(&root, &id, "gray", &zones)?;
    assert_eq!(repeated.stdout, masked_output.stdout, "deterministic");

    let coverage = masked.get("coverage")?;
    let record = &coverage.get("records")?.items()?[0];
    assert_ne!(
        record.get("identity")?.text()?,
        unmasked_record.get("identity")?.text()?
    );
    for zone_id in ["door", "edge"] {
        let masked_zone = zone(record, zone_id)?;
        assert!(
            masked_zone.get("witnesses")?.items()?.is_empty(),
            "{zone_id}: a masked zone carries no witness"
        );
        assert_eq!(
            reasons(masked_zone)?,
            vec![("privacy_masked".to_owned(), 0, 13)],
            "{zone_id}"
        );
    }
    // Every zone's pipeline generation binds the mask generation, so nothing is reused.
    for zone_id in ["door", "edge", "yard"] {
        assert_ne!(
            zone(record, zone_id)?.get("pipeline_generation")?.text()?,
            zone(unmasked_record, zone_id)?
                .get("pipeline_generation")?
                .text()?,
            "{zone_id}"
        );
    }
    let yard = zone(record, "yard")?;
    assert!(
        !yard.get("witnesses")?.items()?.is_empty(),
        "unmasked zone keeps coverage"
    );

    // Retain the masked lineage; orient reports the masked zones not_observable.
    let approval = coverage.get("approval_digest")?.text()?.to_owned();
    let mut retain = zones.to_vec();
    retain.extend_from_slice(&["--retain-coverage", &approval]);
    let retained = report(&watch(&root, &id, "gray", &retain)?)?;
    assert_eq!(
        retained.path(&["coverage", "coverage_status"])?.text()?,
        "retained"
    );
    let oriented = orient(&root)?;
    assert_eq!(zone_state(&oriented, ":zone:door")?, "not_observable");
    assert_eq!(zone_state(&oriented, ":zone:edge")?, "not_observable");
    assert_eq!(zone_state(&oriented, ":zone:yard")?, "known");
    let gaps = oriented
        .path(&["payload", "situationFrame", "coverage", "gaps"])?
        .texts()?;
    assert!(
        gaps.iter().any(|gap| gap.contains("privacy_masked")),
        "{gaps:?}"
    );
    Ok(())
}

#[test]
fn decoded_pgm_carries_the_fill_and_receipts_bind_the_policy() -> TestResult {
    let directory = OwnedDirectory::new("pgm")?;
    let root = directory.root();
    let sensor = "sensor:pgm";
    let id = import(&directory, "moving", &scene(true)?, sensor, "mjpeg")?;
    let decode_args = [
        "--import-id",
        &id,
        "--segment",
        "6",
        "--interpretation",
        "gray",
    ];
    let before_path = directory.0.join("before.pgm");
    let before = file(&root, "decode", &decode_args, Some(&before_path))?;
    success(&before);
    assert_eq!(
        field(&before, "privacy_mask_binding")?,
        "no_policy_declared"
    );
    assert_eq!(field(&before, "applied_redaction_transform")?, "none");
    let extracted = file(
        &root,
        "extract",
        &["--import-id", &id, "--segment", "6"],
        Some(&directory.0.join("raw-before.jpg")),
    )?;
    success(&extracted);

    let retained = declare(&root, sensor, "96x48", &["8,8,16,16"])?;
    let policy = retained.get("policy_digest")?.text()?.to_owned();

    // The pre-mask lineage and raw source export are unmasked access: refused.
    let reopened = file(&root, "read-decoded", &decode_args, None)?;
    assert_eq!(
        refusal(&reopened),
        "ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001"
    );
    let raw = file(
        &root,
        "extract",
        &["--import-id", &id, "--segment", "6"],
        Some(&directory.0.join("raw-after.jpg")),
    )?;
    assert_eq!(refusal(&raw), "ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001");
    assert!(!directory.0.join("raw-after.jpg").exists());

    let after_path = directory.0.join("after.pgm");
    let after = file(&root, "decode", &decode_args, Some(&after_path))?;
    success(&after);
    assert_eq!(field(&after, "privacy_mask_binding")?, "sensor_policy");
    assert_eq!(field(&after, "privacy_mask_policy")?, policy);
    assert_eq!(
        field(&after, "applied_redaction_transform")?,
        "transform:bounding_box_redact"
    );
    for name in [
        "decode_identity",
        "decode_receipt_digest",
        "luma_sha256",
        "privacy_mask_binding_digest",
    ] {
        assert_ne!(field(&after, name)?, field(&before, name)?, "{name}");
    }
    let source = pgm_images(&fs::read(&before_path)?, 96, 48)?;
    let masked = pgm_images(&fs::read(&after_path)?, 96, 48)?;
    assert_eq!((source.len(), masked.len()), (1, 1));
    assert_masked(&masked[0], &source[0], 96, [8, 8, 16, 16], "jpeg");

    // The masked lineage reopens and replays; the receipt is stable.
    let read = file(&root, "read-decoded", &decode_args, None)?;
    success(&read);
    assert_eq!(
        field(&read, "decode_receipt_digest")?,
        field(&after, "decode_receipt_digest")?
    );
    let verified = file(&root, "verify-decoded", &decode_args, None)?;
    success(&verified);
    assert_eq!(field(&verified, "replay_verified")?, "true");

    // A policy for another stream resolution never lets pixels through unmasked.
    let other = import(&directory, "other", &scene(false)?, "sensor:other", "mjpeg")?;
    declare(&root, "sensor:other", "64x48", &["0,0,8,8"])?;
    let mismatch = file(
        &root,
        "decode",
        &[
            "--import-id",
            &other,
            "--segment",
            "0",
            "--interpretation",
            "gray",
        ],
        Some(&directory.0.join("mismatch.pgm")),
    )?;
    assert_eq!(refusal(&mismatch), "ERR-PRIVACY-MASK-RESOLUTION-001");
    assert!(!directory.0.join("mismatch.pgm").exists());
    Ok(())
}

/// Decodes `count` frames from segment 0 of a video import with and without a mask and checks
/// every frame; returns the masked receipts' digests.
fn video_masking(
    name: &str,
    bytes: &[u8],
    format: &str,
    dims: [usize; 2],
    rect: [usize; 4],
) -> TestResult<()> {
    let directory = OwnedDirectory::new(name)?;
    let root = directory.root();
    let sensor = format!("sensor:{name}");
    let id = import(&directory, name, bytes, &sensor, format)?;
    let args = [
        "--import-id",
        &id,
        "--segment",
        "0",
        "--segment-count",
        "3",
        "--interpretation",
        "ycbcr",
    ];
    let before_path = directory.0.join("before.pgm");
    let before = file(&root, "decode", &args, Some(&before_path))?;
    success(&before);
    assert_eq!(
        field(&before, "privacy_mask_binding")?,
        "no_policy_declared"
    );
    let [x, y, w, h] = rect;
    declare(
        &root,
        &sensor,
        &format!("{}x{}", dims[0], dims[1]),
        &[&format!("{x},{y},{w},{h}")],
    )?;
    let after_path = directory.0.join("after.pgm");
    let after = file(&root, "decode", &args, Some(&after_path))?;
    success(&after);
    assert_eq!(field(&after, "privacy_mask_binding")?, "sensor_policy");
    let source = pgm_images(&fs::read(&before_path)?, dims[0], dims[1])?;
    let masked = pgm_images(&fs::read(&after_path)?, dims[0], dims[1])?;
    assert_eq!(source.len(), 3, "{name}");
    assert_eq!(masked.len(), 3, "{name}");
    for (index, (masked, source)) in masked.iter().zip(&source).enumerate() {
        assert_masked(
            masked,
            source,
            dims[0],
            rect,
            &format!("{name} frame {index}"),
        );
    }
    for name in [
        "frame_receipt_digest",
        "frame_luma_sha256",
        "frame_i420_sha256",
    ] {
        let old = values(&before, name)?;
        let new = values(&after, name)?;
        assert_eq!(old.len(), 3);
        assert!(
            old.iter().zip(&new).all(|(a, b)| a != b),
            "{name}: {old:?} {new:?}"
        );
    }
    let repeated = file(&root, "decode", &args, None)?;
    success(&repeated);
    assert_eq!(
        values(&repeated, "frame_receipt_digest")?,
        values(&after, "frame_receipt_digest")?,
        "deterministic"
    );
    Ok(())
}

#[test]
fn masks_apply_equally_on_the_h264_and_h265_decode_paths() -> TestResult {
    video_masking("h264", H264, "annexb", [176, 144], [16, 16, 64, 32])?;
    video_masking("hevc", HEVC, "hevc", [96, 48], [64, 0, 32, 32])?;

    // The H.265 watch: the same moving square, masked, yields no candidate.
    let directory = OwnedDirectory::new("hevc-watch")?;
    let root = directory.root();
    let id = import(&directory, "hevc", HEVC, "sensor:hevc-watch", "hevc")?;
    let unmasked = report(&watch(&root, &id, "ycbcr", &["--zone", DOOR])?)?;
    assert_eq!(unmasked.get("candidate_count")?.number()?, 1);
    declare(&root, "sensor:hevc-watch", "96x48", &[BAND])?;
    let masked = report(&watch(&root, &id, "ycbcr", &["--zone", DOOR])?)?;
    assert_eq!(masked.get("candidate_count")?.number()?, 0);
    assert_eq!(
        masked.path(&["privacy_mask", "binding"])?.text()?,
        "sensor_policy"
    );
    Ok(())
}

#[test]
fn a_candidate_outside_the_mask_names_the_transform_and_publishes() -> TestResult {
    let directory = OwnedDirectory::new("publish")?;
    let root = directory.root();
    let sensor = "sensor:publish";
    let id = import(&directory, "moving", &scene(true)?, sensor, "mjpeg")?;
    declare(&root, sensor, "96x48", &["0,40,96,8"])?;
    let prepared = report(&watch(&root, &id, "gray", &["--zone", DOOR])?)?;
    assert_eq!(prepared.get("candidate_count")?.number()?, 1);
    let candidate = &prepared.get("candidates")?.items()?[0];
    assert_eq!(
        candidate
            .path(&["privacy_transform", "applied_redaction_transform"])?
            .text()?,
        "transform:bounding_box_redact"
    );
    assert_eq!(
        candidate
            .path(&["privacy_transform", "policy_digest"])?
            .text()?,
        prepared.path(&["privacy_mask", "policy_digest"])?.text()?
    );
    let proposal = candidate.get("proposal_digest")?.text()?.to_owned();
    let published = report(&watch(
        &root,
        &id,
        "gray",
        &["--zone", DOOR, "--approve", &proposal],
    )?)?;
    assert_eq!(published.get("published_count")?.number()?, 1);
    orient(&root)?;
    Ok(())
}

/// 64x48 4:2:0 colour bars on which the verified YOLOX-Nano package proposes detections.
const COLORBARS: &[u8] =
    include_bytes!("../../../tests/fixtures/media/jpeg/rgb_64x48_colorbars_420.jpg");
const PACKAGE_SHA256: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";

fn package_detect(root: &Path, id: &str) -> TestResult<Json> {
    let output = Command::new(env!("CARGO_BIN_EXE_fss-infer"))
        .arg("package-detect")
        .arg("--root")
        .arg(root)
        .args([
            "--site",
            SITE,
            "--import-id",
            id,
            "--first-segment",
            "0",
            "--frames",
            "1",
            "--interpretation",
            "ycbcr",
            "--package-digest",
            PACKAGE_SHA256,
        ])
        .arg("--package")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models/yolox-nano/yolox_nano.fmpk"))
        .output()?;
    report(&output)
}

#[test]
fn the_detector_package_sees_only_masked_rgb() -> TestResult {
    let directory = OwnedDirectory::new("package")?;
    let root = directory.root();
    let sensor = "sensor:package";
    let id = import(&directory, "bars", COLORBARS, sensor, "mjpeg")?;
    let unmasked = package_detect(&root, &id)?;
    assert_eq!(
        unmasked.path(&["privacy_mask", "binding"])?.text()?,
        "no_policy_declared"
    );
    let frame = &unmasked.get("frames")?.items()?[0];
    assert!(!frame.get("detections")?.items()?.is_empty());

    declare(&root, sensor, "64x48", &["0,0,64,48"])?;
    let masked = package_detect(&root, &id)?;
    assert_eq!(
        masked.path(&["privacy_mask", "binding"])?.text()?,
        "sensor_policy"
    );
    let masked_frame = &masked.get("frames")?.items()?[0];
    assert_eq!(masked_frame.get("color")?.text()?, "jpeg_rgb");
    // Every pixel is masked: no detection may touch a masked pixel, so none survives.
    assert!(masked_frame.get("detections")?.items()?.is_empty());
    for name in ["input_digest", "inference_identity"] {
        assert_ne!(
            masked_frame.get(name)?.text()?,
            frame.get(name)?.text()?,
            "{name}"
        );
    }
    Ok(())
}
