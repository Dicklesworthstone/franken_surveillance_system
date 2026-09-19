#![forbid(unsafe_code)]
//! Cross-process recorded-source -> canonical decode -> retained output -> pixel-change workflow.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use fss_core::ContentDigest;
use fss_reference::ingest::recorded_decode::RecordedDecodeReceipt;

const JPEG: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
type TestResult<T = ()> = Result<T, Box<dyn Error>>;
struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!("fss-media-cli-{name}-{}-{attempt}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {},
                Err(e) => return Err(e.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }
}
impl Drop for OwnedDirectory { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }

fn command(root: &Path, action: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-file"));
    command.arg(action).arg("--root").arg(root).args(["--site", "site:media-cli"]);
    command
}
fn success(output: &Output) {
    assert!(output.status.success(), "stdout={} stderr={}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}
fn field(output: &Output, name: &str) -> TestResult<String> {
    let prefix = format!("{name}=");
    String::from_utf8(output.stdout.clone())?.lines().find_map(|line| line.strip_prefix(&prefix).map(str::to_owned))
        .ok_or_else(|| std::io::Error::other(format!("missing field {name}")).into())
}
fn imported(name: &str) -> TestResult<(OwnedDirectory, PathBuf, String)> {
    let directory = OwnedDirectory::new(name)?;
    let root = directory.0.join("deployment");
    let input = directory.0.join("recording.mjpeg");
    fs::write(&input, [JPEG, JPEG].concat())?;
    let output = command(&root, "import").arg("--input").arg(&input).args([
        "--sensor", "sensor:media-cli", "--stream", "stream:media-cli", "--receive-time-ns", "1000000000",
    ]).output()?;
    success(&output);
    let id = field(&output, "import_identity")?;
    fs::remove_file(input)?;
    Ok((directory, root, id))
}
fn frame_command(root: &Path, action: &str, id: &str) -> Command {
    let mut command = command(root, action);
    command.args(["--import-id", id, "--segment", "1", "--interpretation", "gray"]);
    command
}
fn motion_command(root: &Path, id: &str, report: &Path, comparisons: &str) -> Command {
    let mut command = command(root, "motion");
    command.args(["--import-id", id, "--start-segment", "0", "--frame-count", "2",
        "--interpretation", "gray", "--pixel-delta", "1", "--minimum-changed-pixels", "1",
        "--max-comparisons", comparisons]).arg("--report-out").arg(report);
    command
}

#[test]
fn decode_reopen_export_and_verify_run_in_separate_processes() -> TestResult {
    let (directory, root, id) = imported("restart")?;
    let output_path = directory.0.join("first.pgm");
    let receipt_path = directory.0.join("decode.receipt");
    let decoded = frame_command(&root, "decode", &id).arg("--output").arg(&output_path)
        .arg("--receipt-out").arg(&receipt_path).output()?;
    success(&decoded);
    assert_eq!(field(&decoded, "decode_complete")?, "true");
    assert_eq!(field(&decoded, "clock_basis")?, "estimated");
    assert_eq!(field(&decoded, "capture_earliest_ns")?, "0");
    assert_eq!(field(&decoded, "capture_latest_ns")?, "1000000000");
    assert_eq!(field(&decoded, "absence_certifiable")?, "false");
    let receipt = RecordedDecodeReceipt::decode(&fs::read(&receipt_path)?, ContentDigest::parse(field(&decoded, "decode_receipt_digest")?)?)?;
    assert_eq!(receipt.identity().to_text(), field(&decoded, "decode_identity")?);
    assert!(fs::read(&output_path)?.starts_with(b"P5\n"));
    let restored_path = directory.0.join("restored.pgm");
    let restored = frame_command(&root, "read-decoded", &id).arg("--output").arg(&restored_path).output()?;
    success(&restored);
    assert_eq!(field(&restored, "this_request_decode_work_units")?, "0");
    assert_eq!(field(&restored, "decode_root")?, field(&decoded, "decode_root")?);
    assert_eq!(fs::read(&restored_path)?, fs::read(&output_path)?);
    let replay = frame_command(&root, "verify-decoded", &id).output()?;
    success(&replay); assert_eq!(field(&replay, "replay_verified")?, "true");
    let retry = frame_command(&root, "decode", &id).output()?;
    success(&retry);
    assert_eq!(field(&retry, "decode_authority_sequence")?, field(&decoded, "decode_authority_sequence")?);
    assert_eq!(field(&retry, "decode_receipt_digest")?, field(&decoded, "decode_receipt_digest")?);
    Ok(())
}

#[test]
fn motion_scan_retains_each_frame_and_distinguishes_baseline_from_zero_change() -> TestResult {
    let (directory, root, id) = imported("motion")?;
    let report_path = directory.0.join("motion.json");
    let result = motion_command(&root, &id, &report_path, "100000000").output()?;
    success(&result);
    assert_eq!(field(&result, "motion_complete")?, "true");
    assert_eq!(field(&result, "motion_observations")?, "2");
    let report = fs::read_to_string(&report_path)?;
    assert!(report.contains("\"complete\":true"));
    assert!(report.contains("\"no_predecessor\""));
    assert!(report.contains("\"comparison\":null"));
    assert!(report.contains("\"changed_pixels\":0"));
    assert!(report.contains("\"candidate\":false"));
    assert!(report.contains("\"absence_certifiable\":false"));
    assert_eq!(ContentDigest::sha256(report.as_bytes()).to_text(), field(&result, "motion_report_sha256")?);
    success(&frame_command(&root, "read-decoded", &id).output()?);
    Ok(())
}

#[test]
fn comparison_pressure_produces_explicit_partial_report_and_replayable_frames() -> TestResult {
    let (directory, root, id) = imported("pressure")?;
    let partial_path = directory.0.join("partial.json");
    let partial = motion_command(&root, &id, &partial_path, "0").output()?;
    assert!(!partial.status.success());
    assert_eq!(field(&partial, "motion_complete")?, "false");
    assert_eq!(field(&partial, "motion_next_segment")?, "1");
    let report = fs::read_to_string(&partial_path)?;
    assert!(report.contains("\"complete\":false"));
    assert!(report.contains("\"resume_start_segment\":0"));
    // Decoding the second frame completed before the comparison was refused.
    success(&frame_command(&root, "read-decoded", &id).output()?);
    let completed_path = directory.0.join("completed.json");
    success(&motion_command(&root, &id, &completed_path, "100000000").output()?);
    assert!(fs::read_to_string(completed_path)?.contains("\"complete\":true"));
    Ok(())
}

#[test]
fn decode_refusals_do_not_overwrite_exports_or_invent_completed_pixels() -> TestResult {
    let (directory, root, id) = imported("refusal")?;
    let absent = frame_command(&root, "read-decoded", &id).output()?;
    assert!(!absent.status.success());
    let refused = frame_command(&root, "decode", &id).args(["--work-units", "0"]).output()?;
    assert!(!refused.status.success());
    assert!(!frame_command(&root, "read-decoded", &id).output()?.status.success());
    success(&frame_command(&root, "decode", &id).output()?);
    let existing = directory.0.join("existing.pgm"); fs::write(&existing, b"operator-owned")?;
    assert!(!frame_command(&root, "read-decoded", &id).arg("--output").arg(&existing).output()?.status.success());
    assert_eq!(fs::read(existing)?, b"operator-owned");
    let inside = root.join("not-a-derived-object.pgm");
    assert!(!frame_command(&root, "read-decoded", &id).arg("--output").arg(&inside).output()?.status.success());
    assert!(!inside.exists());
    Ok(())
}
