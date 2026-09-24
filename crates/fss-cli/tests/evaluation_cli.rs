#![forbid(unsafe_code)]
//! Executable-level tests for the read-only event-evaluation adapter.

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn Error>>;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/evaluation/cli-smoke")
        .join(name)
}

fn command(labels: &str, candidates: &str, maximum: &str, period: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-evaluate"));
    command
        .arg("--labels")
        .arg(fixture(labels))
        .arg("--candidates")
        .arg(fixture(candidates))
        .args([
            "--pipeline-generation",
            "synthetic-pipeline",
            "--model-generation",
            "synthetic-model",
            "--policy-generation",
            "synthetic-policy",
            "--max-false-alerts",
            maximum,
            "--per-observed-ns",
            period,
        ]);
    command
}

fn assert_refusal(output: &Output, code: &str) -> TestResult {
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let diagnostic = std::str::from_utf8(&output.stderr)?;
    assert!(diagnostic.starts_with('{'));
    assert!(diagnostic.ends_with("}\n"));
    assert_eq!(diagnostic.lines().count(), 1);
    assert!(diagnostic.contains("\"schema\":\"fss.evaluation.cli_error.v1\""));
    assert!(diagnostic.contains(&format!("\"code\":\"{code}\"")));
    assert!(diagnostic.contains("\"effect_started\":false"));
    Ok(())
}

#[test]
fn executable_preserves_budget_coverage_and_event_outcomes() -> TestResult {
    let output = command("labels.tsv", "candidates.tsv", "0", "1000").output()?;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let report = std::str::from_utf8(&output.stdout)?;
    assert!(report.starts_with('{'));
    assert!(report.ends_with("}\n"));
    assert_eq!(report.lines().count(), 1);
    for expected in [
        "\"schema\":\"fss.evaluation.cli.v1\"",
        "\"coverage_basis\":\"caller_declared\"",
        "\"derived_only\":true",
        "\"threshold_activated\":false",
        "\"observable_truth_events\":1",
        "\"not_observable_truth_events\":1",
        "\"candidates_inside_not_observable\":1",
        "\"observed_ns\":\"900\"",
        "\"auprc\":{\"state\":\"defined\",\"ppm\":1000000}",
        "\"precision\":{\"state\":\"defined\",\"numerator\":1,\"denominator\":2}",
        "\"operating_point\":{\"state\":\"within_budget\",\"point\":{\"threshold_ppm\":900000,\"true_positives\":1,\"false_positives\":0",
        "\"event_id\":\"hidden\",\"disposition\":{\"state\":\"not_observable\"",
        "\"candidate_id\":\"fp\",\"disposition\":{\"state\":\"false_positive\"}",
        "\"candidate_id\":\"gap\",\"disposition\":{\"state\":\"inside_not_observable\"}",
        "\"time_to_detect_ns\":\"10\"",
        "\"label_set_digest\":",
        "\"candidate_set_digest\":",
        "\"report_digest\":",
    ] {
        assert!(
            report.contains(expected),
            "missing report field: {expected}"
        );
    }
    Ok(())
}

#[test]
fn repeated_execution_is_deterministic_and_preserves_input_bytes() -> TestResult {
    let labels_before = fs::read(fixture("labels.tsv"))?;
    let candidates_before = fs::read(fixture("candidates.tsv"))?;
    let first = command("labels.tsv", "candidates.tsv", "0", "1000").output()?;
    let second = command("labels.tsv", "candidates.tsv", "0", "1000").output()?;
    assert!(first.status.success());
    assert!(second.status.success());
    assert!(first.stderr.is_empty());
    assert!(second.stderr.is_empty());
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(labels_before, fs::read(fixture("labels.tsv"))?);
    assert_eq!(candidates_before, fs::read(fixture("candidates.tsv"))?);
    Ok(())
}

#[test]
fn an_entirely_unobservable_clip_has_no_operating_point() -> TestResult {
    let output = command("all-gap-labels.tsv", "candidates.tsv", "0", "1000").output()?;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let report = std::str::from_utf8(&output.stdout)?;
    for expected in [
        "\"observed_ns\":\"0\"",
        "\"observable_truth_events\":0",
        "\"not_observable_truth_events\":1",
        "\"candidates_inside_not_observable\":3",
        "\"auprc\":{\"state\":\"undefined\",\"reason\":\"no_observable_truth_events\"}",
        "\"operating_point\":{\"state\":\"no_observed_time\"}",
    ] {
        assert!(report.contains(expected), "missing gap state: {expected}");
    }
    assert!(!report.contains("\"state\":\"within_budget\""));
    Ok(())
}

#[test]
fn invalid_budget_and_numeric_inputs_do_not_emit_reports() -> TestResult {
    for (maximum, period, code) in [
        ("0", "0", "evaluation.invalid_budget"),
        ("-1", "1000", "evaluation.cli.invalid_integer"),
        (
            "0",
            "18446744073709551616",
            "evaluation.cli.invalid_integer",
        ),
        ("1.5", "1000", "evaluation.cli.invalid_integer"),
    ] {
        let output = command("labels.tsv", "candidates.tsv", maximum, period).output()?;
        assert_refusal(&output, code)?;
    }
    Ok(())
}

#[test]
fn dangling_clip_and_missing_file_are_typed_refusals() -> TestResult {
    let dangling = command("labels.tsv", "unknown-clip-candidates.tsv", "0", "1000").output()?;
    assert_refusal(&dangling, "evaluation.unknown_clip")?;
    assert!(!fixture("deliberately-absent.tsv").exists());
    let missing = command("deliberately-absent.tsv", "candidates.tsv", "0", "1000").output()?;
    assert_refusal(&missing, "evaluation.cli.input_io")?;
    // Diagnostics do not echo local paths or untrusted source rows.
    assert!(!std::str::from_utf8(&missing.stderr)?.contains("deliberately-absent"));
    Ok(())
}

#[test]
fn help_is_available_without_opening_inputs() -> TestResult {
    let output = Command::new(env!("CARGO_BIN_EXE_fss-evaluate"))
        .arg("--help")
        .output()?;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = std::str::from_utf8(&output.stdout)?;
    assert!(help.contains("fss-evaluation-labels.v1"));
    assert!(help.contains("caller declarations"));
    Ok(())
}
