#![forbid(unsafe_code)]
//! Real subprocesses and the committed neural package over cold original RTP custody.

use super::*;

fn cascade(root: &Path, source: ContentDigest, package: &Path, report: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fss-decode-rtp"));
    cmd.args(["cascade", "--root"]).arg(root)
        .args(["--site", SITE, "--source-root"]).arg(source.to_text())
        .args(["--custody", "current", "--package"]).arg(package)
        .args(["--package-sha256", PACKAGE_SHA, "--report-out"]).arg(report)
        .args(["--pixel-delta", "255", "--minimum-changed-pixels", "4194304",
            "--sentinel-stride", "2"]);
    cmd
}
fn count(report: &str, kind: &str) -> usize {
    let tag = format!("\"type\":\"{kind}\"");
    report.lines().filter(|row| row.contains(&tag)).count()
}

#[test]
fn quiet_cascade_is_complete_without_claiming_exhaustive_inference_and_replays_exactly() -> TestResult {
    let (dir, root, source, package) = setup("cascade-quiet", false)?;
    let cx = cx()?;
    let dep = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    let anchor = dep.current_anchor().clone();
    drop(dep);
    let first = dir.join("cascade-a.jsonl");
    let out = success(cascade(&root, source, &package, &first).output()?)?;
    assert_eq!(field(&out, "sampling_complete=")?, "true");
    assert_eq!(field(&out, "cascade_report_complete=")?, "true");
    assert_eq!(field(&out, "all_frames_inferred=")?, "false");
    assert_eq!(field(&out, "sampling_frames=")?, "4");
    assert_eq!(field(&out, "sampling_selected=")?, "2");
    assert_eq!(field(&out, "sampling_skipped=")?, "2");
    assert_eq!(field(&out, "detection_frames=")?, "2");
    assert!(!out.contains("detection_complete=true"));
    let report = std::fs::read_to_string(&first)?;
    assert_eq!(count(&report, "sampling"), 4);
    assert_eq!(count(&report, "frame"), 2);
    let skipped: Vec<_> = report.lines().filter(|r| r.contains("\"model_executed\":false")).collect();
    assert_eq!(skipped.len(), 2);
    assert!(skipped.iter().all(|r| r.contains("\"frame_receipt\":\"sha256:")
        && r.contains("\"decision_hex\":\"") && r.contains("\"detection_sha256\":null")));
    assert!(report.lines().last().is_some_and(|r| r.contains("\"sampling_complete\":true")
        && r.contains("\"all_frames_inferred\":false")));
    assert_eq!(field(&out, "cascade_report_sha256=")?, ContentDigest::sha256(report.as_bytes()).to_text());
    let second = dir.join("cascade-b.jsonl");
    success(cascade(&root, source, &package, &second).output()?)?;
    assert_eq!(std::fs::read(&first)?, std::fs::read(&second)?);
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&first)?.permissions().mode() & 0o777, 0o600);
    }
    let exhaustive = dir.join("ordinary-detection.jsonl");
    let ordinary = success(command(&root, source, &package, &exhaustive).output()?)?;
    assert_eq!(field(&ordinary, "detection_frames=")?, "4");
    assert_eq!(field(&ordinary, "detection_complete=")?, "true");
    assert_eq!(count(&std::fs::read_to_string(exhaustive)?, "sampling"), 0);
    let dep = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    assert_eq!(dep.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn comparison_exhaustion_infers_or_refuses_but_never_skips_the_required_floor() -> TestResult {
    let (dir, root, source, package) = setup("cascade-floor", false)?;
    let report = dir.join("floor.jsonl");
    let out = success(cascade(&root, source, &package, &report)
        .args(["--max-comparisons", "0"]).output()?)?;
    assert_eq!(field(&out, "all_frames_inferred=")?, "true");
    assert_eq!(field(&out, "sampling_skipped=")?, "0");
    assert_eq!(field(&out, "detection_frames=")?, "4");
    let text = std::fs::read_to_string(&report)?;
    assert_eq!(text.lines().filter(|r| r.contains("\"comparison_unavailable\":\"work_budget\"")).count(), 3);
    let limited = dir.join("limited.jsonl");
    let out = cascade(&root, source, &package, &limited)
        .args(["--max-comparisons", "0", "--max-inference-frames", "2"]).output()?;
    assert!(!out.status.success());
    let stdout = String::from_utf8(out.stdout)?;
    assert!(stdout.contains("sampling_complete=false"));
    assert!(!stdout.contains("cascade_report_sha256="));
    let text = std::fs::read_to_string(limited)?;
    assert!(!text.contains("\"sampling_complete\":true"));
    assert_eq!(count(&text, "sampling"), 2);
    assert_eq!(count(&text, "frame"), 2);
    Ok(())
}

#[test]
fn mandatory_frames_are_included_and_missing_positions_do_not_get_fabricated() -> TestResult {
    let (dir, root, source, package) = setup("cascade-required", false)?;
    let basis = ContentDigest::sha256(b"operator-evidence-selection").to_text();
    let report = dir.join("required.jsonl");
    let out = success(cascade(&root, source, &package, &report)
        .args(["--required-frames", &format!("3={basis}")]).output()?)?;
    assert_eq!(field(&out, "detection_frames=")?, "3");
    assert_eq!(field(&out, "sampling_skipped=")?, "1");
    assert_eq!(field(&out, "unobserved_required_frames=")?, "0");
    let text = std::fs::read_to_string(report)?;
    assert!(text.lines().any(|r| r.contains("\"type\":\"sampling\"")
        && r.contains("\"output_index\":3") && r.contains("\"model_executed\":true")
        && r.contains(&format!("\"required_basis\":\"{basis}\""))));
    let missing = dir.join("missing.jsonl");
    let output = cascade(&root, source, &package, &missing)
        .args(["--required-frames", &format!("100={basis}")]).output()?;
    assert!(!output.status.success());
    let out = String::from_utf8(output.stdout)?;
    assert_eq!(field(&out, "unobserved_required_frames=")?, "1");
    assert!(out.contains("sampling_complete=false"));
    assert!(!std::fs::read_to_string(missing)?.contains("\"sampling_complete\":true"));
    Ok(())
}

#[test]
fn sampling_preserves_malformed_source_progress_and_refuses_unsafe_report_paths() -> TestResult {
    let (dir, root, source, package) = setup("cascade-tail", true)?;
    let report = dir.join("tail.jsonl");
    let out = cascade(&root, source, &package, &report).output()?;
    assert!(!out.status.success());
    let text = std::fs::read_to_string(report)?;
    assert!(count(&text, "source_progress") > 0);
    assert!(!text.contains("\"sampling_complete\":true"));
    let existing = dir.join("keep.jsonl");
    std::fs::write(&existing, b"keep-original")?;
    assert!(!cascade(&root, source, &package, &existing).output()?.status.success());
    assert_eq!(std::fs::read(existing)?, b"keep-original");
    let inside = root.join("forbidden.jsonl");
    assert!(!cascade(&root, source, &package, &inside).output()?.status.success());
    assert!(!inside.exists());
    Ok(())
}

#[test]
fn invalid_sampling_and_wrong_package_fail_before_report_creation() -> TestResult {
    let (dir, root, source, package) = setup("cascade-admission", false)?;
    for (index, extra) in [
        vec!["--post-activity-frames", "257"], vec!["--max-baseline-bytes", "4194305"],
        vec!["--max-inference-frames", "0"], vec!["--sentinel-stride", "3"],
        vec!["--custody", "snapshot"], vec!["--output", "forbidden.pgm"],
    ].into_iter().enumerate() {
        let report = dir.join(format!("invalid-{index}.jsonl"));
        assert!(!cascade(&root, source, &package, &report).args(extra).output()?.status.success());
        assert!(!report.exists());
    }
    let bad_package = dir.join("wrong-package.fmpk");
    let mut bad = PACKAGE.to_vec();
    let at = bad.len() / 2;
    bad[at] ^= 1;
    std::fs::write(&bad_package, bad)?;
    let report = dir.join("wrong-package.jsonl");
    assert!(!cascade(&root, source, &bad_package, &report).output()?.status.success());
    assert!(!report.exists());
    Ok(())
}
