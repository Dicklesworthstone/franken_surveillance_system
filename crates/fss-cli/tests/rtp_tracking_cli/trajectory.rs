#![forbid(unsafe_code)]
//! Separate processes over real retained RTP and the existing verified neural package.
use super::*;
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::rtpdump::recovery::{RtpRecoveryPolicy, inspect_rtp_import};
use fss_reference::ingest::rtpdump::recovery::decode::{RetainedRtpDecodeRequest, RetainedRtpDecodeStep};

fn native(mode: &str, root: &Path, source: ContentDigest, package: &Path, class: usize) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-decode-rtp"));
    command.args([mode, "--root"]).arg(root)
        .args(["--site", SITE, "--source-root"]).arg(source.to_string())
        .args(["--custody", "current", "--package"]).arg(package)
        .args(["--package-sha256", PACKAGE_SHA, "--class-index"]).arg(class.to_string());
    command
}
fn export(root: &Path, source: ContentDigest, package: &Path, saved: &Path) -> Command {
    let mut command = native("track-stream", root, source, package, 0);
    command.arg("--tracks-out").arg(saved);
    command
}
fn verify(root: &Path, source: ContentDigest, package: &Path, saved: &Path, digest: ContentDigest) -> Command {
    let mut command = native("verify-tracks", root, source, package, 0);
    command.arg("--tracks-in").arg(saved).arg("--tracks-sha256").arg(digest.to_string());
    command
}
fn failed(output: Output, marker: &str) -> TestResult {
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(!stdout.contains(&format!("{marker}=true")));
    assert!(!stdout.contains("tracks_sha256="));
    Ok(())
}

#[test]
fn trajectory_roundtrip_is_cold_deterministic_private_and_read_only() -> TestResult {
    let (dir, root, source, package) = setup("trajectory-cold", false)?;
    let cx = cx()?;
    let dep = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    let before = dep.current_anchor().clone();
    drop(dep);
    let first = dir.join("first.tracks");
    let stdout = success(export(&root, source, &package, &first).output()?)?;
    assert_eq!(field(&stdout, "tracks_export_complete=")?, "true");
    assert_eq!(field(&stdout, "tracking_complete=")?, "true");
    assert_eq!(field(&stdout, "identity_authority=")?, "false");
    let bytes = std::fs::read(&first)?;
    let digest = ContentDigest::sha256(&bytes);
    assert_eq!(field(&stdout, "tracks_sha256=")?, digest.to_string());
    assert_eq!(field(&stdout, "tracks_bytes=")?.parse::<usize>()?, bytes.len());
    let second = dir.join("second.tracks");
    success(export(&root, source, &package, &second).output()?)?;
    assert_eq!(bytes, std::fs::read(second)?);
    let verified = success(verify(&root, source, &package, &first, digest).output()?)?;
    assert_eq!(field(&verified, "tracks_verified=")?, "true");
    assert_eq!(field(&verified, "tracks_sha256=")?, digest.to_string());
    assert_eq!(field(&verified, "last_track_frame=")?, field(&stdout, "last_track_frame=")?);
    assert!(!verified.contains("tracks_export_complete=true"));
    assert_eq!(bytes, std::fs::read(&first)?);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&first)?.permissions().mode() & 0o777, 0o600);
    }
    let dep = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    assert_eq!(dep.current_anchor(), &before);
    Ok(())
}

#[test]
fn recomputed_checksums_do_not_verify_changed_truncated_or_extended_trajectories() -> TestResult {
    let (dir, root, source, package) = setup("trajectory-tamper", false)?;
    let path = dir.join("original.tracks");
    success(export(&root, source, &package, &path).output()?)?;
    let bytes = std::fs::read(&path)?;
    let mut changed = bytes.clone();
    changed[0] ^= 1;
    let mut trailing = bytes.clone();
    trailing.push(0);
    for (i, value) in [changed, bytes[..12].to_vec(), trailing].into_iter().enumerate() {
        let candidate = dir.join(format!("tampered-{i}.tracks"));
        std::fs::write(&candidate, &value)?;
        failed(verify(&root, source, &package, &candidate, ContentDigest::sha256(&value)).output()?, "tracks_verified")?;
        assert_eq!(std::fs::read(&candidate)?, value);
    }
    failed(verify(&root, source, &package, &path, ContentDigest::sha256(b"wrong independent digest")).output()?, "tracks_verified")?;
    Ok(())
}

#[test]
fn native_policy_and_outer_admission_changes_cannot_reuse_a_saved_transcript() -> TestResult {
    let (dir, root, source, package) = setup("trajectory-policy", false)?;
    let saved = dir.join("original.tracks");
    success(export(&root, source, &package, &saved).output()?)?;
    let digest = ContentDigest::sha256(&std::fs::read(&saved)?);
    for (key, value) in [("--track-min-hits", "3"), ("--max-track-records", "1000003"), ("--completion", "diagnostic")] {
        failed(verify(&root, source, &package, &saved, digest).args([key, value]).output()?, "tracks_verified")?;
    }
    let mut changed_class = native("verify-tracks", &root, source, &package, 1);
    failed(changed_class.arg("--tracks-in").arg(&saved).arg("--tracks-sha256").arg(digest.to_string()).output()?, "tracks_verified")?;
    Ok(())
}

#[test]
fn unsafe_destinations_and_verification_outputs_are_rejected_without_replacement() -> TestResult {
    let (dir, root, source, package) = setup("trajectory-path", false)?;
    let existing = dir.join("keep.tracks");
    std::fs::write(&existing, b"preserve existing bytes")?;
    failed(export(&root, source, &package, &existing).output()?, "tracks_export_complete")?;
    assert_eq!(std::fs::read(&existing)?, b"preserve existing bytes");
    let inside = root.join("forbidden.tracks");
    failed(export(&root, source, &package, &inside).output()?, "tracks_export_complete")?;
    assert!(!inside.exists());
    let unwanted = dir.join("never-created.tracks");
    for option in ["--tracks-out", "--report-out", "--output"] {
        let output = verify(&root, source, &package, &existing, ContentDigest::sha256(b"unused"))
            .arg(option).arg(&unwanted).output()?;
        assert_eq!(output.status.code(), Some(2));
        assert!(!unwanted.exists());
    }
    let directory_input = dir.join("not-a-file");
    std::fs::create_dir(&directory_input)?;
    failed(verify(&root, source, &package, &directory_input, ContentDigest::sha256(b"unused")).output()?, "tracks_verified")?;
    #[cfg(unix)]
    {
        let link = dir.join("saved-symlink");
        std::os::unix::fs::symlink(&existing, &link)?;
        failed(verify(&root, source, &package, &link, ContentDigest::sha256(b"unused")).output()?, "tracks_verified")?;
    }
    Ok(())
}

#[test]
fn missing_original_custody_cannot_be_replaced_by_a_saved_trajectory() -> TestResult {
    let (dir, root, source, package) = setup("trajectory-custody", false)?;
    let path = dir.join("saved.tracks");
    success(export(&root, source, &package, &path).output()?)?;
    let saved = std::fs::read(&path)?;
    let cx = cx()?;
    let dep = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    let retained = inspect_rtp_import(source, 1, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let chunk = *retained.report().chunk_digests().first().ok_or("source chunk")?;
    std::fs::remove_file(dep.publisher().spool().object_path(chunk))?;
    drop(dep);
    failed(verify(&root, source, &package, &path, ContentDigest::sha256(&saved)).output()?, "tracks_verified")?;
    assert_eq!(std::fs::read(path)?, saved);
    Ok(())
}

#[test]
fn fresh_valid_privacy_changes_prevent_verification_of_old_unmasked_trajectories() -> TestResult {
    let (dir, root, source, package) = setup("trajectory-privacy", false)?;
    let path = dir.join("unmasked.tracks");
    success(export(&root, source, &package, &path).output()?)?;
    let digest = ContentDigest::sha256(&std::fs::read(&path)?);
    let cx = cx()?;
    let mut dep = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    let retained = inspect_rtp_import(source, 1, RtpRecoveryPolicy::default(), &cx, &dep)?;
    let parameters = retained.h264_parameters(&cx)?.unique_pair().ok_or("source parameters")?;
    let dimensions = {
        let mut decoder = retained.decode_h264(RetainedRtpDecodeRequest::new(parameters), &dep, &cx)?;
        let mut dimensions = None;
        for _ in 0..20_000 {
            match decoder.step(&dep, &cx)? {
                RetainedRtpDecodeStep::Frame(frame) => { dimensions = Some(frame.dimensions()); break; }
                RetainedRtpDecodeStep::Ended(_) => break,
                _ => {}
            }
        }
        dimensions.ok_or("native dimensions")?
    };
    let mask = PrivacyMaskPolicy::new(SensorId::parse("sensor:rtp-tracking-cli")?, dimensions,
        &[[0, 0, dimensions[0], dimensions[1]]])?;
    let approval = preview_mask(&dep, &mask)?.approval;
    declare_mask(&mut dep, &mask, approval, &cx)?;
    drop(dep);
    failed(verify(&root, source, &package, &path, digest).output()?, "tracks_verified")?;
    let masked = dir.join("masked.tracks");
    let stdout = success(export(&root, source, &package, &masked).output()?)?;
    let masked_digest = ContentDigest::sha256(&std::fs::read(&masked)?);
    assert_ne!(masked_digest, digest);
    assert_eq!(field(&stdout, "tracking_complete=")?, "true");
    success(verify(&root, source, &package, &masked, masked_digest).output()?)?;
    Ok(())
}

#[test]
fn diagnostic_transcripts_preserve_source_incompleteness_but_not_analysis_failures() -> TestResult {
    let (dir, root, source, package) = setup("trajectory-diagnostic", true)?;
    let strict = dir.join("strict.tracks");
    failed(export(&root, source, &package, &strict).output()?, "tracks_export_complete")?;
    let diagnostic = dir.join("diagnostic.tracks");
    let stdout = success(export(&root, source, &package, &diagnostic).args(["--completion", "diagnostic"]).output()?)?;
    assert_eq!(field(&stdout, "tracking_complete=")?, "false");
    assert_eq!(field(&stdout, "tracks_export_complete=")?, "true");
    let digest = ContentDigest::sha256(&std::fs::read(&diagnostic)?);
    let checked = success(verify(&root, source, &package, &diagnostic, digest).args(["--completion", "diagnostic"]).output()?)?;
    assert_eq!(field(&checked, "tracking_complete=")?, "false");
    assert_eq!(field(&checked, "tracks_verified=")?, "true");
    failed(verify(&root, source, &package, &diagnostic, digest).output()?, "tracks_verified")?;
    let limited = dir.join("limited.tracks");
    failed(export(&root, source, &package, &limited)
        .args(["--completion", "diagnostic", "--max-track-frames", "1"]).output()?, "tracks_export_complete")?;
    Ok(())
}

#[test]
fn output_record_and_native_tracking_limits_never_publish_a_success_digest() -> TestResult {
    let (dir, root, source, package) = setup("trajectory-bounds", false)?;
    for (i, (key, value)) in [
        ("--max-tracks-bytes", "1"), ("--max-track-record-bytes", "1"),
        ("--max-track-records", "3"), ("--max-track-frames", "1"),
    ].into_iter().enumerate() {
        let path = dir.join(format!("limited-{i}.tracks"));
        failed(export(&root, source, &package, &path).args([key, value]).output()?, "tracks_export_complete")?;
    }
    Ok(())
}
