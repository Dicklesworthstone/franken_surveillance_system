#![forbid(unsafe_code)]
//! Real native report generation followed by read-only cold source reproduction.
#[path = "../../fss-reference/tests/rtpdump_support/mod.rs"]
mod rtpdump_support;
use fss_core::{ContentDigest, SensorId, StreamId, TimestampNs};
use fss_reference::ReferenceDeployment;
use fss_reference::ingest::rtpdump::import::{
    RtpImportLimits, RtpImportScope, prepare_rtp_import, publish_rtp_import,
};
use rtpdump_support::{Error, TestResult, config_for, cx, real_dump};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const PACKAGE: &[u8] = include_bytes!("../../../models/yolox-nano/yolox_nano.fmpk");
const PACKAGE_SHA: &str = "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";
const SITE: &str = "site:rtp-verify-report-cli";
struct Fixture {
    dir: PathBuf,
    root: PathBuf,
    source: ContentDigest,
    package: PathBuf,
}
impl Fixture {
    fn new(label: &str, partial: bool) -> Result<Self, Error> {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
        std::fs::create_dir_all(base)?;
        for i in 0..1000 {
            let dir = base.join(format!(
                "rtp-report-verify-{label}-{}-{i}",
                std::process::id()
            ));
            match std::fs::create_dir(&dir) {
                Ok(()) => {
                    let root = dir.join("deployment");
                    let package = dir.join("package.fmpk");
                    std::fs::write(&package, PACKAGE)?;
                    let cx = cx()?;
                    let mut dep = ReferenceDeployment::open(&root, SITE, &cx)?;
                    let mut bytes = real_dump(true);
                    if partial {
                        bytes.extend_from_slice(&[0, 10, 0]);
                    }
                    let plan = prepare_rtp_import(
                        &bytes,
                        RtpImportScope {
                            sensor: SensorId::parse("sensor:verify-report")?,
                            stream: StreamId::parse("stream:verify-report")?,
                            receive_time: TimestampNs(1_000_000_000),
                        },
                        config_for(7),
                        RtpImportLimits::default(),
                        &cx,
                    )?;
                    let source = publish_rtp_import(plan, &cx, &mut dep)?.root();
                    return Ok(Self {
                        dir,
                        root,
                        source,
                        package,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("fixture directory ceiling".into())
    }
    fn command(&self, mode: &str) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_fss-decode-rtp"));
        c.args([mode, "--root"])
            .arg(&self.root)
            .args(["--site", SITE, "--source-root"])
            .arg(self.source.to_string())
            .args(["--custody", "current", "--package"])
            .arg(&self.package)
            .args(["--package-sha256", PACKAGE_SHA]);
        if matches!(mode, "track" | "verify-tracks") {
            c.args(["--class-index", "0"]);
        }
        c
    }
    fn verify(&self, mode: &str, path: &Path, expected: ContentDigest) -> Command {
        let mut c = self.command(mode);
        c.arg("--report-in")
            .arg(path)
            .arg("--report-sha256")
            .arg(expected.to_string());
        c
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
fn success(o: Output) -> Result<String, Error> {
    if !o.status.success() {
        return Err(format!(
            "command failed: {}\n{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(o.stdout)?)
}
fn field<'a>(text: &'a str, key: &str) -> Result<&'a str, Error> {
    text.lines()
        .find_map(|l| l.strip_prefix(key))
        .ok_or_else(|| format!("missing {key}").into())
}
fn mode_pairs() -> [(&'static str, &'static str, &'static str); 2] {
    [
        ("detect", "verify-detections", "detection"),
        ("track", "verify-tracks", "tracking"),
    ]
}
#[test]
fn cold_native_reports_verify_without_writes_or_export_success_claims() -> TestResult {
    let f = Fixture::new("cold", false)?;
    let cx = cx()?;
    let dep = ReferenceDeployment::reopen(&f.root, SITE, &cx)?;
    let before = dep.current_anchor().clone();
    drop(dep);
    for (export, verify, prefix) in mode_pairs() {
        let path = f.dir.join(format!("{export}.jsonl"));
        let stdout = success(f.command(export).arg("--report-out").arg(&path).output()?)?;
        let expected: ContentDigest =
            field(&stdout, &format!("{prefix}_report_sha256="))?.parse()?;
        let bytes = std::fs::read(&path)?;
        assert_eq!(expected, ContentDigest::sha256(&bytes));
        let entries = std::fs::read_dir(&f.dir)?.count();
        let stdout = success(f.verify(verify, &path, expected).output()?)?;
        assert!(stdout.contains(&format!("{prefix}_report_verified=true")));
        assert!(!stdout.contains("report_complete=true"));
        assert_eq!(
            field(&stdout, "verified_report_sha256=")?,
            expected.to_string()
        );
        assert_eq!(std::fs::read(&path)?, bytes);
        assert_eq!(std::fs::read_dir(&f.dir)?.count(), entries);
    }
    let dep = ReferenceDeployment::reopen(&f.root, SITE, &cx)?;
    assert_eq!(dep.current_anchor(), &before);
    Ok(())
}
#[test]
fn tampered_rehashed_truncated_appended_and_wrong_expected_reports_refuse() -> TestResult {
    let f = Fixture::new("tamper", false)?;
    for (export, verify, prefix) in mode_pairs() {
        let path = f.dir.join(format!("{export}.jsonl"));
        success(f.command(export).arg("--report-out").arg(&path).output()?)?;
        let original = std::fs::read(&path)?;
        let mut changed = original.clone();
        let middle = changed.len() / 2;
        changed[middle] ^= 1;
        let mut suffix = original.clone();
        suffix.push(b'\n');
        for bytes in [changed, suffix, original[..original.len() - 1].to_vec()] {
            std::fs::write(&path, &bytes)?;
            let o = f
                .verify(verify, &path, ContentDigest::sha256(&bytes))
                .output()?;
            assert!(!o.status.success());
            assert!(
                !String::from_utf8(o.stdout)?.contains(&format!("{prefix}_report_verified=true"))
            );
            assert_eq!(std::fs::read(&path)?, bytes);
        }
        std::fs::write(&path, &original)?;
        let changed_option = if export == "track" {
            ["--track-min-hits", "3"]
        } else {
            ["--minimum-score-ppm", "1000000"]
        };
        assert!(
            !f.verify(verify, &path, ContentDigest::sha256(&original))
                .args(changed_option)
                .output()?
                .status
                .success()
        );
        assert!(
            !f.verify(verify, &path, ContentDigest::sha256(b"unrelated"))
                .output()?
                .status
                .success()
        );
        assert!(
            !f.verify(verify, &path, ContentDigest::sha256(&original))
                .args(["--max-dimension", "1024"])
                .output()?
                .status
                .success()
        );
    }
    Ok(())
}
#[test]
fn verification_rejects_output_flags_and_oversized_input_before_native_work() -> TestResult {
    let f = Fixture::new("bounds", false)?;
    let path = f.dir.join("input.jsonl");
    std::fs::write(&path, b"untrusted report")?;
    let expected = ContentDigest::sha256(b"untrusted report");
    for (_, verify, _) in mode_pairs() {
        let output = f.dir.join("must-not-exist");
        for flag in ["--report-out", "--output", "--receipt-out"] {
            let o = f
                .verify(verify, &path, expected)
                .arg(flag)
                .arg(&output)
                .output()?;
            assert_eq!(o.status.code(), Some(2));
            assert!(!output.exists());
        }
        let o = f
            .verify(verify, &path, expected)
            .args(["--max-report-bytes", "1"])
            .output()?;
        assert!(!o.status.success());
        assert_eq!(std::fs::read(&path)?, b"untrusted report");
    }
    Ok(())
}
#[test]
fn partial_native_reports_cannot_verify_even_when_exactly_reproduced() -> TestResult {
    let f = Fixture::new("partial", true)?;
    for (export, verify, prefix) in mode_pairs() {
        let path = f.dir.join(format!("{export}.jsonl"));
        assert!(
            !f.command(export)
                .arg("--report-out")
                .arg(&path)
                .output()?
                .status
                .success()
        );
        let bytes = std::fs::read(&path)?;
        let o = f
            .verify(verify, &path, ContentDigest::sha256(&bytes))
            .output()?;
        assert!(!o.status.success());
        assert!(String::from_utf8(o.stdout)?.contains(&format!("{prefix}_report_verified=false")));
    }
    Ok(())
}

#[test]
fn current_privacy_invalidates_old_reports_without_rewriting_them() -> TestResult {
    use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
    let f = Fixture::new("privacy", false)?;
    let mut reports = Vec::new();
    for (export, verify, prefix) in mode_pairs() {
        let path = f.dir.join(format!("{export}.jsonl"));
        success(f.command(export).arg("--report-out").arg(&path).output()?)?;
        let bytes = std::fs::read(&path)?;
        reports.push((verify, prefix, path, bytes));
    }
    let cx = cx()?;
    let mut dep = ReferenceDeployment::reopen(&f.root, SITE, &cx)?;
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:verify-report")?,
        [1, 1],
        &[[0, 0, 1, 1]],
    )?;
    let approval = preview_mask(&dep, &policy)?.approval;
    declare_mask(&mut dep, &policy, approval, &cx)?;
    let anchor = dep.current_anchor().clone();
    drop(dep);
    for (verify, prefix, path, bytes) in reports {
        let result = f
            .verify(verify, &path, ContentDigest::sha256(&bytes))
            .output()?;
        assert!(!result.status.success());
        assert!(
            String::from_utf8(result.stdout)?.contains(&format!("{prefix}_report_verified=false"))
        );
        assert_eq!(std::fs::read(path)?, bytes);
    }
    assert_eq!(
        ReferenceDeployment::reopen(&f.root, SITE, &cx)?.current_anchor(),
        &anchor
    );
    Ok(())
}

#[test]
fn missing_originals_cannot_verify_previously_exported_reports() -> TestResult {
    use fss_reference::ingest::rtpdump::recovery::{RtpRecoveryPolicy, inspect_rtp_import};
    let f = Fixture::new("lost-source", false)?;
    let mut reports = Vec::new();
    for (export, verify, prefix) in mode_pairs() {
        let path = f.dir.join(format!("{export}.jsonl"));
        success(f.command(export).arg("--report-out").arg(&path).output()?)?;
        let bytes = std::fs::read(&path)?;
        reports.push((verify, prefix, path, bytes));
    }
    let cx = cx()?;
    let dep = ReferenceDeployment::reopen(&f.root, SITE, &cx)?;
    let retained = inspect_rtp_import(f.source, 1, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let chunk = *retained
        .report()
        .chunk_digests()
        .first()
        .ok_or("source chunk")?;
    std::fs::remove_file(dep.publisher().spool().object_path(chunk))?;
    drop(retained);
    drop(dep);
    for (verify, prefix, path, bytes) in reports {
        let result = f
            .verify(verify, &path, ContentDigest::sha256(&bytes))
            .output()?;
        assert!(!result.status.success());
        assert!(
            String::from_utf8(result.stdout)?.contains(&format!("{prefix}_report_verified=false"))
        );
        assert_eq!(std::fs::read(path)?, bytes);
    }
    Ok(())
}
