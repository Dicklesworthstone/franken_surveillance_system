#![forbid(unsafe_code)]
//! Executable native-custody workflow. The shared fixture executes the real numeric package.

#[path = "../../fss-reference/tests/package_evaluation_support/mod.rs"]
mod support;

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use fss_core::ContentDigest;
use support::{Directory, Fixture, PRINCIPAL, SITE, STREAM, Test};

fn command(root: &Path, report: ContentDigest, labels: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-evaluate"));
    command
        .arg("retained-package")
        .arg("--root")
        .arg(root)
        .arg("--site")
        .arg(SITE)
        .arg("--principal")
        .arg(PRINCIPAL)
        .arg("--package-report")
        .arg(report.to_string())
        .arg("--labels")
        .arg(labels)
        .args([
            "--label",
            "numeric-a",
            "--clip-id",
            "clip",
            "--clip-origin-ns",
            "1000000000",
            "--stream-id",
            STREAM,
            "--clock-basis",
            "estimated",
            "--confirmation-hits",
            "2",
            "--maximum-missed-frames",
            "1",
            "--minimum-iou-ppm",
            "0",
            "--max-false-alerts",
            "0",
            "--per-observed-ns",
            "1000000000",
        ]);
    command
}

fn write_labels(directory: &Path, positive: bool) -> Test<std::path::PathBuf> {
    let path = directory.join("labels.tsv");
    let truth = if positive {
        "truth\ttruth\tclip\tnumeric-a\t-\t100000000\t100000000\n"
    } else {
        ""
    };
    fs::write(
        &path,
        format!("fss-evaluation-labels.v1\nclip\tclip\t200000000\n{truth}"),
    )?;
    Ok(path)
}

fn refused(output: &Output) -> Test {
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error = std::str::from_utf8(&output.stderr)?;
    assert_eq!(error.lines().count(), 1);
    assert!(error.contains("\"schema\":\"fss.evaluation.cli_error.v1\""));
    assert!(error.contains("\"effect_started\":false"));
    Ok(())
}

#[test]
fn native_retained_output_produces_repeatable_bound_scores_and_preserves_journals() -> Test {
    let fixture = Fixture::new("cli-positive", [160, 160, 192], Some(0))?;
    let labels = write_labels(&fixture.directory.0, true)?;
    let label_bytes = fs::read(&labels)?;
    let before = fixture.journals()?;
    let first = command(&fixture.root, fixture.report, &labels).output()?;
    let second = command(&fixture.root, fixture.report, &labels).output()?;
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(first.stdout, second.stdout);
    assert!(first.stderr.is_empty());
    let result = std::str::from_utf8(&first.stdout)?;
    assert_eq!(result.lines().count(), 1);
    for field in [
        "\"schema\":\"fss.retained_package_evaluation.v1\"",
        "\"evaluation\":{\"schema\":\"fss.evaluation.cli.v1\"",
        "\"coverage_basis\":\"caller_declared\"",
        "\"source_verification_passes\":2",
        "\"threshold_activated\":false",
        "\"model_inference_executed\":false",
        "\"external_effects_reconciled\":false",
        "\"true_positives\":1",
        "\"detect_ns\":\"100000000\"",
        "\"observed_ns\":\"200000000\"",
        "\"observation_index\":1",
        "\"privacy_epoch\":",
        "\"result_digest\":",
        "\"projection_digest\":",
    ] {
        assert!(result.contains(field), "missing {field}");
    }
    assert!(!result.contains("source.mjpeg"));
    assert_eq!(fixture.journals()?, before);
    assert_eq!(fs::read(labels)?, label_bytes);
    Ok(())
}

#[test]
fn negative_native_clip_still_has_observed_time_without_manual_candidate_rows() -> Test {
    let fixture = Fixture::new("cli-negative", [0, 0, 0], Some(0))?;
    let labels = write_labels(&fixture.directory.0, false)?;
    let result = command(&fixture.root, fixture.report, &labels).output()?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let json = std::str::from_utf8(&result.stdout)?;
    assert!(json.contains("\"tracks\":[]"));
    assert!(json.contains("\"candidates\":0"));
    assert!(json.contains("\"observed_ns\":\"200000000\""));
    Ok(())
}

#[test]
fn wrong_scope_source_damage_and_budget_exhaustion_leave_stdout_empty() -> Test {
    let fixture = Fixture::new("cli-refusal", [160, 160, 192], Some(0))?;
    let labels = write_labels(&fixture.directory.0, true)?;
    let before = fixture.journals()?;
    for extra in [
        ["--model-generation", "fabricated"],
        ["--maximum-source-bytes", "1"],
        ["--track", "manual-selection"],
    ] {
        refused(
            &command(&fixture.root, fixture.report, &labels)
                .args(extra)
                .output()?,
        )?;
    }
    let original = fs::read(&fixture.chunk)?;
    let mut corrupt = original.clone();
    *corrupt.last_mut().ok_or("source object")? ^= 1;
    fs::write(&fixture.chunk, &corrupt)?;
    refused(&command(&fixture.root, fixture.report, &labels).output()?)?;
    assert_eq!(fs::read(&fixture.chunk)?, corrupt);
    assert_eq!(fixture.journals()?, before);
    Ok(())
}

#[test]
fn missing_roots_are_not_created_and_subcommand_help_does_no_io() -> Test {
    let directory = Directory::new("cli-missing")?;
    let root = directory.0.join("not-created");
    let labels = write_labels(&directory.0, false)?;
    refused(&command(&root, ContentDigest::sha256(b"missing"), &labels).output()?)?;
    assert!(!root.exists());
    let output = Command::new(env!("CARGO_BIN_EXE_fss-evaluate"))
        .args(["retained-package", "--help"])
        .output()?;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(std::str::from_utf8(&output.stdout)?.contains("First confirmation"));
    assert!(!root.exists());
    Ok(())
}
