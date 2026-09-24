#![forbid(unsafe_code)]
//! End-to-end model-free pipeline through the real binaries: `fss-file import` retains a
//! recording, `fss-event watch` decodes it, runs foreground detection, Kalman tracking and the
//! zone gate, and publishes only exactly approved candidates. Synthetic scenes prove the wiring
//! and authority path, not detection quality.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::ContentDigest;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

/// 176x144 `testsrc2` scene, one IDR then eleven P pictures.
const H264: &[u8] =
    include_bytes!("../../fss-codec-h264/tests/fixtures/decode/p_qcif_ref3_p4x4.h264");

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const WIDTH: u32 = 96;
const HEIGHT: u32 = 48;
const FRAMES: usize = 14;

struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-watch-cli-{name}-{}-{attempt}",
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
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Dark background; from frame 3 a bright 16x16 block-aligned square enters at the left
/// edge and moves 8 px right per frame along the top band. `moving == false` is static.
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

fn import(name: &str, bytes: &[u8], format: &str) -> TestResult<(OwnedDirectory, PathBuf, String)> {
    let directory = OwnedDirectory::new(name)?;
    let root = directory.0.join("deployment");
    let input = directory.0.join("recording.bin");
    fs::write(&input, bytes)?;
    let output = Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("import")
        .arg("--root")
        .arg(&root)
        .args(["--site", "site:watch-cli", "--input"])
        .arg(&input)
        .args([
            "--sensor",
            "sensor:watch-cli",
            "--stream",
            "stream:watch-cli",
            "--receive-time-ns",
            "1000000000",
            "--media-format",
            format,
        ])
        .output()?;
    success(&output);
    let id = String::from_utf8(output.stdout)?
        .lines()
        .find_map(|l| l.strip_prefix("import_identity=").map(str::to_owned))
        .ok_or("import identity missing")?;
    fs::remove_file(input)?;
    Ok((directory, root, id))
}

fn watch(
    root: &Path,
    id: &str,
    interpretation: &str,
    zone: &str,
    extra: &[&str],
) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .arg("watch")
        .arg("--root")
        .arg(root)
        .args([
            "--site",
            "site:watch-cli",
            "--import-id",
            id,
            "--interpretation",
            interpretation,
            "--zone",
            zone,
        ])
        .args(extra)
        .output()?)
}

/// Value of the first `"key":` in the JSON report: a bare number or the quoted string body.
fn json_field(output: &Output, key: &str) -> TestResult<String> {
    let text = String::from_utf8(output.stdout.clone())?;
    let pattern = format!("\"{key}\":");
    let start = text
        .find(&pattern)
        .ok_or_else(|| format!("missing {key}"))?
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

fn refusal(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .find_map(|line| line.strip_prefix("refusal_id=").map(str::to_owned))
        .unwrap_or_default()
}

#[test]
fn moving_object_entering_zone_yields_one_candidate_and_reruns_never_duplicate() -> TestResult {
    let (directory, root, id) = import("enter", &scene(true)?, "mjpeg")?;
    let door = "door:64,0,32,32";
    let prepared = watch(&root, &id, "gray", door, &[])?;
    success(&prepared);
    assert_eq!(
        json_field(&prepared, "format")?,
        "fss.recorded_watch_report.v1"
    );
    assert_eq!(json_field(&prepared, "frames_decoded")?, "14");
    assert_eq!(json_field(&prepared, "candidate_count")?, "1");
    assert_eq!(json_field(&prepared, "zone_id")?, "door");
    assert_eq!(json_field(&prepared, "status")?, "prepared");
    assert_eq!(json_field(&prepared, "event_kind")?, "unclassified");
    assert_eq!(json_field(&prepared, "event_state")?, "indeterminate");
    assert_eq!(json_field(&prepared, "published_count")?, "0");
    assert_eq!(json_field(&prepared, "corroborated")?, "false");
    assert_eq!(json_field(&prepared, "alert_authorized")?, "false");
    let proposal = json_field(&prepared, "proposal_digest")?;
    let command = json_field(&prepared, "publish_command")?;
    assert!(command.starts_with("fss-event watch --root "));
    assert!(command.ends_with(&format!("--approve {proposal}")));
    let sequence = json_field(&prepared, "authority_sequence")?;

    // Analysis alone writes nothing and is byte-for-byte deterministic.
    let report_path = directory.0.join("watch.json");
    let report_arg = report_path.to_str().ok_or("temporary path is not UTF-8")?;
    let repeated = watch(&root, &id, "gray", door, &["--report-out", report_arg])?;
    success(&repeated);
    assert_eq!(repeated.stdout, prepared.stdout);
    assert_eq!(fs::read(&report_path)?, prepared.stdout);

    let published = watch(&root, &id, "gray", door, &["--approve", &proposal])?;
    success(&published);
    assert_eq!(json_field(&published, "status")?, "published");
    assert_eq!(json_field(&published, "published_count")?, "1");
    let after = json_field(&published, "authority_sequence")?;
    assert!(after.parse::<u64>()? > sequence.parse::<u64>()?);

    // Rerunning the exact approval recognises the event and changes no authority.
    let rerun = watch(&root, &id, "gray", door, &["--approve", &proposal])?;
    success(&rerun);
    assert_eq!(json_field(&rerun, "status")?, "already_published");
    assert_eq!(json_field(&rerun, "published_count")?, "0");
    assert_eq!(json_field(&rerun, "already_published_count")?, "1");
    assert_eq!(json_field(&rerun, "authority_sequence")?, after);
    assert_eq!(json_field(&rerun, "proposal_digest")?, proposal);
    assert_eq!(json_field(&rerun, "publish_command")?, "null");
    let plain = watch(&root, &id, "gray", door, &[])?;
    success(&plain);
    assert_eq!(json_field(&plain, "status")?, "already_published");
    assert_eq!(json_field(&plain, "authority_sequence")?, after);
    Ok(())
}

#[test]
fn motion_outside_all_zones_and_a_static_scene_yield_no_candidates() -> TestResult {
    let (_moving_dir, moving_root, moving) = import("outside", &scene(true)?, "mjpeg")?;
    let outside = watch(&moving_root, &moving, "gray", "yard:0,36,96,12", &[])?;
    success(&outside);
    assert_eq!(json_field(&outside, "candidate_count")?, "0");
    assert_ne!(json_field(&outside, "foreground_boxes")?, "0");
    assert_ne!(json_field(&outside, "confirmed_tracks")?, "0");

    let (_quiet_dir, quiet_root, quiet) = import("static", &scene(false)?, "mjpeg")?;
    let still = watch(&quiet_root, &quiet, "gray", "door:64,0,32,32", &[])?;
    success(&still);
    assert_eq!(json_field(&still, "candidate_count")?, "0");
    assert_eq!(json_field(&still, "foreground_boxes")?, "0");
    Ok(())
}

#[test]
fn h264_recording_runs_through_the_same_pipeline_deterministically() -> TestResult {
    let (_directory, root, id) = import("h264", H264, "annexb")?;
    let first = watch(&root, &id, "ycbcr", "scene:0,0,176,144", &[])?;
    success(&first);
    assert_eq!(json_field(&first, "media_format")?, "annexb");
    assert_eq!(json_field(&first, "frames_decoded")?, "12");
    assert_eq!(json_field(&first, "width")?, "176");
    assert_eq!(json_field(&first, "height")?, "144");
    assert_eq!(json_field(&first, "published_count")?, "0");
    let second = watch(&root, &id, "ycbcr", "scene:0,0,176,144", &[])?;
    success(&second);
    assert_eq!(second.stdout, first.stdout);
    // H.264 ranges must start at an IDR access unit.
    let predicted = watch(
        &root,
        &id,
        "ycbcr",
        "scene:0,0,176,144",
        &["--first-segment", "1"],
    )?;
    assert!(!predicted.status.success());
    assert_eq!(refusal(&predicted), "ERR-DECODE-H264-RANGE-NOT-IDR-001");
    Ok(())
}

#[test]
fn unknown_import_corrupt_source_and_stale_approval_are_typed_refusals() -> TestResult {
    let (_directory, root, id) = import("refusals", &scene(true)?, "mjpeg")?;
    let unknown = ContentDigest::sha256(b"never imported").to_text();
    let missing = watch(&root, &unknown, "gray", "door:64,0,32,32", &[])?;
    assert!(!missing.status.success());
    assert_eq!(refusal(&missing), "ERR-DECODE-SOURCE-UNAVAILABLE-001");

    let stale = ContentDigest::sha256(b"not a proposal").to_text();
    let refused = watch(
        &root,
        &id,
        "gray",
        "door:64,0,32,32",
        &["--approve", &stale],
    )?;
    assert!(!refused.status.success());
    assert_eq!(refusal(&refused), "ERR-WATCH-APPROVAL-STALE-001");

    let wrong = watch(&root, &id, "ycbcr", "door:64,0,32,32", &[])?;
    assert!(!wrong.status.success());
    assert!(refusal(&wrong).starts_with("ERR-DECODE-"));

    // Truncate the last H.264 slice: custody retains the damaged bytes, decode refuses them.
    let last_nal = H264
        .windows(3)
        .rposition(|w| w == [0, 0, 1])
        .ok_or("fixture has no start code")?;
    let truncated = &H264[..last_nal + (H264.len() - last_nal) / 2];
    let (_corrupt_dir, corrupt_root, corrupt) = import("corrupt", truncated, "annexb")?;
    let damaged = watch(&corrupt_root, &corrupt, "ycbcr", "scene:0,0,176,144", &[])?;
    assert!(!damaged.status.success());
    assert!(
        refusal(&damaged).starts_with("ERR-DECODE-"),
        "{}",
        String::from_utf8_lossy(&damaged.stderr)
    );
    assert!(damaged.stdout.is_empty());
    Ok(())
}
