#![forbid(unsafe_code)]
//! Real operator processes: receipt export, cold native verification and fail-closed files.
#[path = "../../fss-reference/tests/rtpdump_support/mod.rs"]
mod rtpdump_support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::{ContentDigest, SensorId, StreamId, TimestampNs};
use fss_reference::ReferenceDeployment;
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::rtpdump::import::{
    RtpImportLimits, RtpImportScope, prepare_rtp_import, publish_rtp_import,
};
use rtpdump_support::{Error, TestResult, config_for, cx, real_dump};

const SITE: &str = "site:rtp-receipts-cli";
fn directory(label: &str) -> Result<PathBuf, Error> {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(base)?;
    for i in 0..1000 {
        let path = base.join(format!(
            "rtp-receipts-cli-{label}-{}-{i}",
            std::process::id()
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err("scratch directory bound".into())
}
fn setup(label: &str, tail: bool) -> Result<(PathBuf, PathBuf, ContentDigest), Error> {
    let dir = directory(label)?;
    let root = dir.join("deployment");
    std::fs::create_dir(&root)?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::open(&root, SITE, &cx)?;
    let mut bytes = real_dump(true);
    if tail {
        bytes.extend_from_slice(&[0, 20, 0]);
    }
    let scope = RtpImportScope {
        sensor: SensorId::parse("sensor:rtp-receipts-cli")?,
        stream: StreamId::parse("stream:rtp-receipts-cli")?,
        receive_time: TimestampNs(1_000_000_000),
    };
    let source = publish_rtp_import(
        prepare_rtp_import(
            &bytes,
            scope,
            config_for(7),
            RtpImportLimits::default(),
            &cx,
        )?,
        &cx,
        &mut dep,
    )?
    .root();
    Ok((dir, root, source))
}
fn command(root: &Path, source: ContentDigest, mode: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-decode-rtp"));
    command
        .args([mode, "--root"])
        .arg(root)
        .args(["--site", SITE, "--source-root"])
        .arg(source.to_string())
        .args(["--custody", "current"]);
    command
}
fn success(result: Output) -> Result<String, Error> {
    if !result.status.success() {
        return Err(format!(
            "command failed: {}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(result.stdout)?)
}
fn field<'a>(text: &'a str, key: &str) -> Result<&'a str, Error> {
    text.lines()
        .find_map(|line| line.strip_prefix(key))
        .ok_or_else(|| format!("missing {key}").into())
}
fn export(root: &Path, source: ContentDigest, receipt: &Path) -> Result<String, Error> {
    success(
        command(root, source, "receipts")
            .arg("--receipts-out")
            .arg(receipt)
            .output()?,
    )
}
fn verify(
    root: &Path,
    source: ContentDigest,
    path: &Path,
    digest: ContentDigest,
) -> Result<Output, Error> {
    Ok(command(root, source, "verify-receipts")
        .arg("--receipts-in")
        .arg(path)
        .arg("--receipts-sha256")
        .arg(digest.to_string())
        .output()?)
}

#[test]
fn cold_export_and_verification_preserve_pixels_and_deployment_authority() -> TestResult {
    let (dir, root, source) = setup("cold", false)?;
    let cx = cx()?;
    let dep = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    let anchor = dep.current_anchor().clone();
    drop(dep);
    let receipts = dir.join("frames.receipts");
    let pixels = dir.join("frames.pgm");
    let snapshot = dir.join("snapshot.pgm");
    let exported = success(
        command(&root, source, "receipts")
            .arg("--receipts-out")
            .arg(&receipts)
            .arg("--output")
            .arg(&pixels)
            .output()?,
    )?;
    assert!(exported.contains("receipts_complete=true"));
    assert!(exported.contains("export_complete=true"));
    assert!(exported.contains("decode_complete=true"));
    assert!(exported.contains("absence_certifiable=false"));
    let digest: ContentDigest = field(&exported, "receipts_sha256=")?.parse()?;
    let bytes = std::fs::read(&receipts)?;
    assert_eq!(ContentDigest::sha256(&bytes), digest);
    assert_eq!(field(&exported, "frames_decoded=")?, "4");
    let verified = success(verify(&root, source, &receipts, digest)?)?;
    assert!(verified.contains("receipts_verified=true"));
    assert!(!verified.contains("export_complete=true"));
    assert_eq!(
        field(&verified, "receipt_recipe=")?,
        field(&exported, "receipt_recipe=")?
    );
    success(
        command(&root, source, "decode")
            .arg("--output")
            .arg(&snapshot)
            .output()?,
    )?;
    assert_eq!(std::fs::read(pixels)?, std::fs::read(snapshot)?);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&receipts)?.permissions().mode() & 0o777,
            0o600
        );
    }
    let reopened = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    assert_eq!(reopened.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn tampered_rehashed_truncated_and_extra_receipts_cannot_verify() -> TestResult {
    let (dir, root, source) = setup("tamper", false)?;
    let path = dir.join("receipts");
    let exported = export(&root, source, &path)?;
    let digest: ContentDigest = field(&exported, "receipts_sha256=")?.parse()?;
    let bytes = std::fs::read(&path)?;
    let mut changed = bytes.clone();
    let last = changed.len() / 2;
    changed[last] ^= 1;
    let mut extra = bytes.clone();
    extra.push(0);
    for bad in [changed, extra, bytes[..bytes.len() - 1].to_vec()] {
        std::fs::write(&path, &bad)?;
        for expected in [digest, ContentDigest::sha256(&bad)] {
            let result = verify(&root, source, &path, expected)?;
            assert!(!result.status.success());
            let text = String::from_utf8(result.stdout)?;
            assert!(text.contains("receipts_verified=false"));
            assert!(!text.contains("receipts_verified=true"));
        }
    }
    std::fs::write(&path, &bytes)?;
    let changed_recipe = command(&root, source, "verify-receipts")
        .arg("--receipts-in")
        .arg(&path)
        .arg("--receipts-sha256")
        .arg(digest.to_string())
        .args(["--max-dimension", "1024"])
        .output()?;
    assert!(!changed_recipe.status.success());
    Ok(())
}

#[test]
fn limits_and_incomplete_source_never_certify_a_partial_export() -> TestResult {
    let (dir, root, source) = setup("limits", false)?;
    let path = dir.join("receipt");
    let pixels = dir.join("pixels.pgm");
    let result = command(&root, source, "receipts")
        .arg("--receipts-out")
        .arg(&path)
        .arg("--output")
        .arg(&pixels)
        .args(["--max-receipts-bytes", "1"])
        .output()?;
    assert!(!result.status.success());
    assert!(!path.exists() && !pixels.exists());
    let (dir, root, source) = setup("tail", true)?;
    let path = dir.join("partial");
    let result = command(&root, source, "receipts")
        .arg("--receipts-out")
        .arg(&path)
        .output()?;
    assert!(!result.status.success());
    let text = String::from_utf8(result.stdout)?;
    assert!(text.contains("receipts_complete=false"));
    assert!(!text.contains("receipts_complete=true"));
    assert!(text.contains("decode_complete=false"));
    assert!(path.exists());
    let digest = ContentDigest::sha256(&std::fs::read(&path)?);
    assert!(!verify(&root, source, &path, digest)?.status.success());
    Ok(())
}

#[test]
fn output_collisions_existing_files_and_deployment_paths_refuse_without_overwrite() -> TestResult {
    let (dir, root, source) = setup("paths", false)?;
    let existing = dir.join("existing");
    std::fs::write(&existing, b"keep these bytes")?;
    let result = command(&root, source, "receipts")
        .arg("--receipts-out")
        .arg(&existing)
        .output()?;
    assert!(!result.status.success());
    assert_eq!(std::fs::read(&existing)?, b"keep these bytes");
    let inside = root.join("receipt");
    assert!(
        !command(&root, source, "receipts")
            .arg("--receipts-out")
            .arg(&inside)
            .output()?
            .status
            .success()
    );
    assert!(!inside.exists());
    let same = dir.join("same");
    assert!(
        !command(&root, source, "receipts")
            .arg("--receipts-out")
            .arg(&same)
            .arg("--output")
            .arg(&same)
            .output()?
            .status
            .success()
    );
    assert!(!same.exists());
    #[cfg(unix)]
    {
        let link = dir.join("link");
        std::os::unix::fs::symlink(&existing, &link)?;
        assert!(
            !command(&root, source, "receipts")
                .arg("--receipts-out")
                .arg(&link)
                .output()?
                .status
                .success()
        );
        assert!(
            !verify(
                &root,
                source,
                &link,
                ContentDigest::sha256(b"keep these bytes")
            )?
            .status
            .success()
        );
        assert_eq!(std::fs::read(existing)?, b"keep these bytes");
    }
    Ok(())
}

#[test]
fn current_privacy_policy_changes_native_verification_and_exported_planes() -> TestResult {
    let (dir, root, source) = setup("mask", false)?;
    let receipts = dir.join("before.receipts");
    let before = export(&root, source, &receipts)?;
    let before_digest = field(&before, "receipts_sha256=")?.parse()?;
    let cx = cx()?;
    let mut dep = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    // Fixture dimensions are learned from the same native retained decoder, never guessed.
    let retained = fss_reference::ingest::rtpdump::recovery::inspect_rtp_import(
        source,
        3,
        Default::default(),
        &cx,
        &dep,
    )?;
    let params = retained
        .h264_parameters(&cx)?
        .unique_pair()
        .ok_or("parameters")?;
    let mut decoder = retained.decode_h264(
        fss_reference::ingest::rtpdump::recovery::decode::RetainedRtpDecodeRequest::new(params),
        &dep,
        &cx,
    )?;
    let mut dimensions = None;
    for _ in 0..10000 {
        if let fss_reference::ingest::rtpdump::recovery::decode::RetainedRtpDecodeStep::Frame(f) =
            decoder.step(&dep, &cx)?
        {
            dimensions = Some(f.dimensions());
            break;
        }
    }
    let dimensions = dimensions.ok_or("first native frame")?;
    drop(decoder);
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:rtp-receipts-cli")?,
        dimensions,
        &[[0, 0, dimensions[0], dimensions[1]]],
    )?;
    let approval = preview_mask(&dep, &policy)?.approval;
    declare_mask(&mut dep, &policy, approval, &cx)?;
    drop(dep);
    assert!(
        !verify(&root, source, &receipts, before_digest)?
            .status
            .success()
    );
    let masked = dir.join("after.pgm");
    let new_receipts = dir.join("after.receipts");
    let after = success(
        command(&root, source, "receipts")
            .arg("--receipts-out")
            .arg(new_receipts)
            .arg("--output")
            .arg(&masked)
            .output()?,
    )?;
    assert_ne!(
        field(&before, "receipts_sha256=")?,
        field(&after, "receipts_sha256=")?
    );
    let header = format!("P5\n{} {}\n255\n", dimensions[0], dimensions[1]).into_bytes();
    let mut expected = Vec::new();
    for _ in 0..4 {
        expected.extend_from_slice(&header);
        expected.extend(std::iter::repeat_n(
            16,
            (dimensions[0] * dimensions[1]) as usize,
        ));
    }
    assert_eq!(std::fs::read(masked)?, expected);
    Ok(())
}

#[test]
fn malformed_receipt_requests_refuse_before_any_filesystem_effect() -> TestResult {
    let dir = directory("parse")?;
    let root = dir.join("missing");
    let destination = dir.join("output");
    for extra in [
        vec!["--max-receipt-bytes", "0"],
        vec!["--max-receipts-bytes", "268435457"],
        vec!["--receipts-sha256", "not-for-export"],
    ] {
        let result = command(&root, ContentDigest::sha256(b"none"), "receipts")
            .arg("--receipts-out")
            .arg(&destination)
            .args(extra)
            .output()?;
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        assert!(!root.exists() && !destination.exists());
    }
    Ok(())
}
