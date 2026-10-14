#![forbid(unsafe_code)]
//! Real-process retained RTP neural detection with verified package and private report.
#[path = "../../fss-reference/tests/rtpdump_support/mod.rs"]
mod rtpdump_support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::{ContentDigest, SensorId, StreamId, TimestampNs};
use fss_reference::ReferenceDeployment;
use fss_reference::ingest::rtpdump::import::{
    RtpImportLimits, RtpImportScope, prepare_rtp_import, publish_rtp_import,
};
use rtpdump_support::{Error, TestResult, config_for, cx, real_dump};

const PACKAGE: &[u8] = include_bytes!("../../../models/yolox-nano/yolox_nano.fmpk");
const PACKAGE_SHA: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";
const SITE: &str = "site:rtp-detection-cli";

fn directory(label: &str) -> Result<PathBuf, Error> {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(base)?;
    for attempt in 0..1000 {
        let path = base.join(format!(
            "rtp-detection-cli-{label}-{}-{attempt}",
            std::process::id()
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err("fixture directory bound".into())
}

fn setup(label: &str, damaged: bool) -> Result<(PathBuf, PathBuf, ContentDigest, PathBuf), Error> {
    let dir = directory(label)?;
    let root = dir.join("deployment");
    let package = dir.join("detector.fmpk");
    std::fs::write(&package, PACKAGE)?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&root, SITE, &cx)?;
    let mut bytes = real_dump(true);
    if damaged {
        bytes.extend_from_slice(&[0, 10, 0]);
    }
    let source = publish_rtp_import(
        prepare_rtp_import(
            &bytes,
            RtpImportScope {
                sensor: SensorId::parse("sensor:rtp-detection-cli")?,
                stream: StreamId::parse("stream:rtp-detection-cli")?,
                receive_time: TimestampNs(1_000_000_000),
            },
            config_for(7),
            RtpImportLimits::default(),
            &cx,
        )?,
        &cx,
        &mut dep,
    )?
    .root();
    Ok((dir, root, source, package))
}

fn command(root: &Path, source: ContentDigest, package: &Path, report: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-decode-rtp"));
    command
        .args(["detect", "--root"])
        .arg(root)
        .args(["--site", SITE, "--source-root"])
        .arg(source.to_string())
        .args(["--custody", "current", "--package"])
        .arg(package)
        .args(["--package-sha256", PACKAGE_SHA, "--report-out"])
        .arg(report);
    command
}

fn success(output: Output) -> Result<String, Error> {
    if !output.status.success() {
        return Err(format!(
            "detection child failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn field<'a>(text: &'a str, key: &str) -> Result<&'a str, Error> {
    text.lines()
        .find_map(|line| line.strip_prefix(key))
        .ok_or_else(|| format!("missing report field {key}").into())
}

#[test]
fn cold_detection_report_is_deterministic_private_and_read_only() -> TestResult {
    let (dir, root, source, package) = setup("cold", false)?;
    let cx = cx()?;
    let deployment = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    let anchor = deployment.current_anchor().clone();
    drop(deployment);

    let first = dir.join("detect-a.jsonl");
    let stdout = success(command(&root, source, &package, &first).output()?)?;
    assert_eq!(field(&stdout, "detection_complete=")?, "true");
    assert_eq!(field(&stdout, "detection_report_complete=")?, "true");
    assert_eq!(field(&stdout, "detection_frames=")?, "4");
    assert_eq!(field(&stdout, "calibrated_probability=")?, "false");
    assert_eq!(field(&stdout, "absence_certifiable=")?, "false");
    assert_eq!(
        field(&stdout, "detection_report_sha256=")?,
        ContentDigest::sha256(&std::fs::read(&first)?).to_string()
    );
    let report = std::fs::read_to_string(&first)?;
    assert!(report.lines().next().is_some_and(|line| line.contains("\"type\":\"header\"")));
    assert!(report.contains("\"type\":\"frame\""));
    assert!(report.lines().last().is_some_and(|line| {
        line.contains("\"type\":\"summary\"") && line.contains("\"complete\":true")
    }));

    let second = dir.join("detect-b.jsonl");
    success(command(&root, source, &package, &second).output()?)?;
    assert_eq!(std::fs::read(&first)?, std::fs::read(&second)?);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&first)?.permissions().mode() & 0o777, 0o600);
    }
    let reopened = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    assert_eq!(reopened.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn package_tamper_unsafe_path_and_incomplete_source_never_certify_detection() -> TestResult {
    let (dir, root, source, package) = setup("refuse", false)?;
    let existing = dir.join("existing.jsonl");
    std::fs::write(&existing, b"keep")?;
    assert!(!command(&root, source, &package, &existing).output()?.status.success());
    assert_eq!(std::fs::read(&existing)?, b"keep");

    let inside = root.join("forbidden.jsonl");
    assert!(!command(&root, source, &package, &inside).output()?.status.success());
    assert!(!inside.exists());

    let mut tampered = PACKAGE.to_vec();
    tampered[tampered.len() / 2] ^= 1;
    let bad_package = dir.join("tampered.fmpk");
    std::fs::write(&bad_package, tampered)?;
    let bad_report = dir.join("tampered.jsonl");
    assert!(
        !command(&root, source, &bad_package, &bad_report)
            .output()?
            .status
            .success()
    );
    assert!(!bad_report.exists());

    let (tail_dir, tail_root, tail_source, tail_package) = setup("tail", true)?;
    let tail_report = tail_dir.join("tail.jsonl");
    let output = command(&tail_root, tail_source, &tail_package, &tail_report).output()?;
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("detection_complete=false"));
    assert!(!stdout.contains("detection_report_sha256="));
    if tail_report.exists() {
        let report = std::fs::read_to_string(tail_report)?;
        assert!(!report.lines().any(|line| {
            line.contains("\"type\":\"summary\"") && line.contains("\"complete\":true")
        }));
    }
    Ok(())
}
