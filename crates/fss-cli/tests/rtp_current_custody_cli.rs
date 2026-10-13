#![forbid(unsafe_code)]
//! The actual retained decode command preserves snapshot output and admits current custody.
#[path = "../../fss-reference/tests/rtpdump_support/mod.rs"]
mod rtpdump_support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::{ContentDigest, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::rtpdump::import::{
    RtpImportLimits, RtpImportScope, prepare_rtp_import, publish_rtp_import,
};
use fss_reference::ReferenceDeployment;
use rtpdump_support::{Error, TestResult, config_for, cx, real_dump};

fn directory(label: &str) -> Result<PathBuf, Error> {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(base)?;
    for index in 0..1000 {
        let path = base.join(format!("rtp-custody-cli-{label}-{}-{index}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err("temporary directory bound".into())
}

fn command(root: &Path, source: ContentDigest, output: &Path, extra: &[&str]) -> Result<Output, Error> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-decode-rtp"))
        .args(["decode", "--root"])
        .arg(root)
        .args(["--site", "site:current-custody-cli", "--source-root"])
        .arg(source.to_string())
        .arg("--output")
        .arg(output)
        .args(extra)
        .output()?)
}

#[test]
fn current_mode_preserves_native_pixels_and_read_only_cold_operation() -> TestResult {
    let dir = directory("cold")?;
    let root = dir.join("deployment");
    std::fs::create_dir(&root)?;
    let cx = cx()?;
    let mut deployment = ReferenceDeployment::open(&root, "site:current-custody-cli", &cx)?;
    let scope = RtpImportScope {
        sensor: SensorId::parse("sensor:current-custody-cli")?,
        stream: StreamId::parse("stream:current-custody-cli")?,
        receive_time: TimestampNs(1_000_000_000),
    };
    let original = real_dump(true);
    let plan = prepare_rtp_import(
        &original,
        scope,
        config_for(7),
        RtpImportLimits::default(),
        &cx,
    )?;
    let source = publish_rtp_import(plan, &cx, &mut deployment)?.root();
    let anchor = deployment.current_anchor().clone();
    drop(deployment);
    drop(original);

    let snapshot_path = dir.join("snapshot.pgm");
    let current_path = dir.join("current.pgm");
    let snapshot = command(&root, source, &snapshot_path, &[])?;
    assert!(snapshot.status.success(), "{}", String::from_utf8_lossy(&snapshot.stderr));
    let current = command(
        &root,
        source,
        &current_path,
        &["--custody", "current", "--max-custody-read-bytes", "134217728"],
    )?;
    assert!(current.status.success(), "{}", String::from_utf8_lossy(&current.stderr));
    let snapshot_text = String::from_utf8(snapshot.stdout)?;
    let current_text = String::from_utf8(current.stdout)?;
    assert!(!snapshot_text.contains("custody_mode="));
    assert!(current_text.contains("custody_mode=current"));
    assert!(current_text.contains("decode_complete=true"));
    assert!(current_text.contains("export_complete=true"));
    assert!(current_text.contains("absence_certifiable=false"));
    assert!(current_text.contains("capture_time_class=unknown"));
    let reads: u64 = current_text
        .lines()
        .find_map(|line| line.strip_prefix("custody_read_bytes="))
        .ok_or("missing read accounting")?
        .parse()?;
    assert!(reads > 0 && reads <= 128 * 1024 * 1024);
    let frames = |text: &str| -> Vec<String> {
        text.lines()
            .filter(|line| line.starts_with("frame_luma_sha256="))
            .map(str::to_owned)
            .collect()
    };
    assert_eq!(frames(&snapshot_text).len(), 4);
    assert_eq!(frames(&snapshot_text), frames(&current_text));
    assert_eq!(std::fs::read(snapshot_path)?, std::fs::read(current_path)?);
    let reopened = ReferenceDeployment::reopen(&root, "site:current-custody-cli", &cx)?;
    assert_eq!(reopened.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn malformed_custody_options_refuse_before_deployment_or_output_creation() -> TestResult {
    let dir = directory("refuse")?;
    let root = dir.join("missing-deployment");
    let output = dir.join("must-not-exist.pgm");
    for extra in [
        vec!["--custody", "latest"],
        vec!["--max-custody-read-bytes", "134217728"],
        vec!["--custody", "current", "--max-custody-read-bytes", "1"],
        vec!["--custody", "current", "--max-custody-read-bytes", "2147483649"],
    ] {
        let result = command(&root, ContentDigest::sha256(b"unused root"), &output, &extra)?;
        assert_eq!(result.status.code(), Some(2));
        assert!(!root.exists());
        assert!(!output.exists());
        assert!(result.stdout.is_empty());
    }
    Ok(())
}
