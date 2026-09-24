#![forbid(unsafe_code)]
//! Cross-process `fss-infer package-detect` (fss-q4ngj): `fss-file import` retains a JPEG, then the
//! verified YOLOX-Nano package runs over it and prints the package detection report. A tampered
//! package is refused before any inference. Proves wiring, not detection quality.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const JPEG: &[u8] =
    include_bytes!("../../../tests/fixtures/media/jpeg/rgb_64x48_colorbars_420.jpg");
const PACKAGE_SHA256: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";

struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-package-cli-{name}-{}-{attempt}",
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

fn package_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models/yolox-nano/yolox_nano.fmpk")
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn import(directory: &OwnedDirectory) -> TestResult<(PathBuf, String)> {
    let root = directory.0.join("deployment");
    let input = directory.0.join("camera.jpg");
    fs::write(&input, JPEG)?;
    let output = Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("import")
        .arg("--root")
        .arg(&root)
        .args(["--site", "site:package-cli"])
        .arg("--input")
        .arg(&input)
        .args([
            "--sensor",
            "sensor:package-cli",
            "--stream",
            "stream:package-cli",
            "--receive-time-ns",
            "1000000000",
        ])
        .output()?;
    success(&output);
    let id = String::from_utf8(output.stdout)?
        .lines()
        .find_map(|l| l.strip_prefix("import_identity=").map(str::to_owned))
        .ok_or("import_identity missing")?;
    Ok((root, id))
}

fn detect(root: &Path, id: &str, package: &Path, report: Option<&Path>) -> TestResult<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-infer"));
    command
        .arg("package-detect")
        .arg("--root")
        .arg(root)
        .args([
            "--site",
            "site:package-cli",
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
        .arg(package);
    if let Some(report) = report {
        command.arg("--report-out").arg(report);
    }
    Ok(command.output()?)
}

#[test]
fn verified_package_detects_over_a_retained_import() -> TestResult {
    let directory = OwnedDirectory::new("detect")?;
    let (root, id) = import(&directory)?;
    let report = directory.0.join("report.json");
    let output = detect(&root, &id, &package_path(), Some(&report))?;
    success(&output);
    let json = String::from_utf8(output.stdout)?;
    assert_eq!(fs::read_to_string(&report)?, json);
    for needle in [
        "{\"schema\":\"fss.package_detection_report.v1\"",
        "\"media_format\":\"mjpeg\"",
        "\"color\":\"jpeg_rgb\"",
        "\"complete\":true",
        "\"model_outputs\":\"uncalibrated\"",
        "\"absence_certifiable\":false",
        "\"effects_authorized\":false",
    ] {
        assert!(json.contains(needle), "{needle} missing from {json}");
    }
    // The laboratory oracle's package-threshold detections for this JPEG are three `tie` rows.
    assert_eq!(json.matches("\"label\":\"tie\"").count(), 3, "{json}");
    Ok(())
}

#[test]
fn tampered_package_is_refused_before_inference() -> TestResult {
    let directory = OwnedDirectory::new("tamper")?;
    let (root, id) = import(&directory)?;
    let mut bytes = fs::read(package_path())?;
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x80;
    let tampered = directory.0.join("tampered.fmpk");
    fs::write(&tampered, bytes)?;
    let output = detect(&root, &id, &tampered, None)?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)?.starts_with("ERR-MODEL-PACKAGE-DIGEST-001"));
    Ok(())
}
