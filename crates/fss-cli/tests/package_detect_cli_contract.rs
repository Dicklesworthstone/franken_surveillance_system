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
    detect_with(root, id, package, report, &[])
}

fn detect_with(
    root: &Path,
    id: &str,
    package: &Path,
    report: Option<&Path>,
    extra: &[&str],
) -> TestResult<Output> {
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
    command.args(extra);
    Ok(command.output()?)
}

/// Text of the first JSON string value following `"key":"`.
fn field(json: &str, key: &str) -> Option<String> {
    let rest = json.split(&format!("\"{key}\":\"")).nth(1)?;
    rest.split('"').next().map(str::to_owned)
}

/// Every frame's complete detection array text.
fn detections(json: &str) -> Vec<String> {
    json.split("\"detections\":[")
        .skip(1)
        .map(|rest| rest.split("]}").next().unwrap_or_default().to_owned())
        .collect()
}

#[test]
fn kernel_selection_is_explicit_and_bound_into_the_report() -> TestResult {
    let directory = OwnedDirectory::new("kernels")?;
    let (root, id) = import(&directory)?;
    let optimized = detect_with(
        &root,
        &id,
        &package_path(),
        None,
        &["--kernels", "optimized-cpu"],
    )?;
    success(&optimized);
    let default = detect(&root, &id, &package_path(), None)?;
    success(&default);
    let scalar = detect_with(
        &root,
        &id,
        &package_path(),
        None,
        &["--kernels", "scalar-reference"],
    )?;
    success(&scalar);
    let (optimized, default, scalar) = (
        String::from_utf8(optimized.stdout)?,
        String::from_utf8(default.stdout)?,
        String::from_utf8(scalar.stdout)?,
    );
    // The optimized executor is the default; the selection is part of the model identity.
    assert_eq!(optimized, default);
    assert!(field(&scalar, "model_digest").is_some());
    assert_ne!(
        field(&optimized, "model_digest"),
        field(&scalar, "model_digest")
    );
    assert_ne!(
        field(&optimized, "inference_identity"),
        field(&scalar, "inference_identity")
    );
    // Bit-identical outputs, identical post-NMS detections.
    assert_eq!(
        field(&optimized, "output_digest"),
        field(&scalar, "output_digest")
    );
    assert_eq!(detections(&optimized), detections(&scalar));
    assert_eq!(scalar.matches("\"label\":\"tie\"").count(), 3, "{scalar}");
    let refused = detect_with(&root, &id, &package_path(), None, &["--kernels", "fastest"])?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    Ok(())
}

#[test]
fn thread_count_is_explicit_and_never_changes_the_report() -> TestResult {
    let directory = OwnedDirectory::new("threads")?;
    let (root, id) = import(&directory)?;
    let one = detect_with(&root, &id, &package_path(), None, &["--threads", "1"])?;
    success(&one);
    let four = detect_with(&root, &id, &package_path(), None, &["--threads", "4"])?;
    success(&four);
    let auto = detect_with(&root, &id, &package_path(), None, &["--threads", "auto"])?;
    success(&auto);
    let default = detect(&root, &id, &package_path(), None)?;
    success(&default);
    // Bit-identical execution: the report bytes (every digest and detection) do not move.
    assert_eq!(one.stdout, four.stdout);
    assert_eq!(one.stdout, auto.stdout);
    assert_eq!(one.stdout, default.stdout);
    for refused in ["0", "65", "many"] {
        let output = detect_with(&root, &id, &package_path(), None, &["--threads", refused])?;
        assert!(!output.status.success(), "--threads {refused}");
        assert!(output.stdout.is_empty(), "--threads {refused}");
    }
    Ok(())
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
