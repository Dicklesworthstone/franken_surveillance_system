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
fn fixed_threshold_preserves_over_budget_and_empty_prefix_results() -> TestResult {
    for (labels, threshold, counts, budget, precision, latency) in [
        (
            "labels.tsv",
            "500000",
            (1, 1, 0),
            "over_budget",
            "defined",
            true,
        ),
        (
            "labels.tsv",
            "500001",
            (1, 0, 0),
            "within_budget",
            "defined",
            true,
        ),
        (
            "labels.tsv",
            "1000000",
            (0, 0, 1),
            "within_budget",
            "undefined",
            false,
        ),
        (
            "all-gap-labels.tsv",
            "0",
            (0, 0, 0),
            "no_observed_time",
            "undefined",
            false,
        ),
    ] {
        let output = command(labels, "candidates.tsv", "0", "1000")
            .args(["--fixed-threshold-ppm", threshold])
            .output()?;
        assert!(output.status.success());
        let json = std::str::from_utf8(&output.stdout)?;
        let (_, fixed) = json
            .split_once("\"fixed_operating_point\":")
            .ok_or("missing fixed result")?;
        let (tp, fp, missed) = counts;
        for expected in [
            format!("\"threshold_ppm\":{threshold},"),
            format!("\"true_positives\":{tp},"),
            format!("\"false_positives\":{fp},"),
            format!("\"false_negatives\":{missed},"),
            format!("\"budget_state\":\"{budget}\""),
            format!("\"precision\":{{\"state\":\"{precision}\""),
            "\"digest\":\"sha256:".to_owned(),
        ] {
            assert!(fixed.contains(&expected), "{expected} missing from {fixed}");
        }
        assert_eq!(fixed.contains("\"min_ns\":\"10\""), latency);
    }
    let invalid = command("labels.tsv", "candidates.tsv", "0", "1000")
        .args(["--fixed-threshold-ppm", "1000001"])
        .output()?;
    assert_refusal(&invalid, "evaluation.invalid_threshold")
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

fn class_json<'a>(json: &'a str, class: &str) -> Result<&'a str, Box<dyn Error>> {
    let class_marker = format!("\"class\":\"{class}\"");
    Ok(json
        .split(&class_marker)
        .nth(1)
        .ok_or("missing class")?
        .split("\"class\":")
        .next()
        .ok_or("missing class body")?)
}

#[test]
fn class_breakdown_scores_one_fixed_threshold_without_losing_negative_exposure() -> TestResult {
    let output = command("class-labels.tsv", "class-candidates.tsv", "1", "1000")
        .args([
            "--fixed-threshold-ppm",
            "800000",
            "--class-breakdown",
            "zero,vehicle",
        ])
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let json = std::str::from_utf8(&output.stdout)?;
    let breakdown = json
        .split("\"class_breakdown\":")
        .nth(1)
        .ok_or("class breakdown")?;
    for field in [
        "\"schema\":\"fss.evaluation.class_breakdown.v1\"",
        "\"threshold_ppm\":800000",
        "\"threshold_selection\":\"caller_fixed\"",
        "\"denominator_basis\":\"all_observed_clip_time\"",
        "\"observed_ns\":\"1900\"",
        "\"declared_classes\":[\"vehicle\",\"zero\"]",
        "\"report_digest\":\"sha256:",
        "\"digest\":\"sha256:",
    ] {
        assert!(breakdown.contains(field), "missing {field}");
    }
    let person = class_json(breakdown, "person")?;
    assert!(person.contains("\"auprc\":{\"state\":\"defined\",\"ppm\":833333}"));
    assert!(person.contains("\"fixed_operating_point\":{\"true_positives\":1,\"false_positives\":1,\"false_negatives\":1"));
    assert!(person.contains("\"budget_state\":\"within_budget\""));
    let vehicle = class_json(breakdown, "vehicle")?;
    assert!(vehicle.contains("\"fixed_operating_point\":{\"true_positives\":0,\"false_positives\":1,\"false_negatives\":1"));
    let zero = class_json(breakdown, "zero")?;
    assert!(zero.contains("\"observable_truth_events\":0"));
    assert!(
        zero.contains(
            "\"auprc\":{\"state\":\"undefined\",\"reason\":\"no_observable_truth_events\"}"
        )
    );
    let missed = class_json(breakdown, "missed-only")?;
    assert!(missed.contains("\"fixed_operating_point\":{\"true_positives\":0,\"false_positives\":0,\"false_negatives\":1"));
    let orphan = class_json(breakdown, "orphan")?;
    assert!(orphan.contains("\"false_positives\":1"));
    assert!(orphan.contains(
        "\"recall\":{\"state\":\"undefined\",\"reason\":\"no_observable_truth_events\"}"
    ));
    Ok(())
}

#[test]
fn optional_class_breakdown_preserves_the_complete_original_pooled_json() -> TestResult {
    let pooled = command("labels.tsv", "candidates.tsv", "0", "1000")
        .args(["--fixed-threshold-ppm", "800000"])
        .output()?;
    let first = command("labels.tsv", "candidates.tsv", "0", "1000")
        .args([
            "--fixed-threshold-ppm",
            "800000",
            "--class-breakdown",
            "all",
        ])
        .output()?;
    let second = command("labels.tsv", "candidates.tsv", "0", "1000")
        .args([
            "--fixed-threshold-ppm",
            "800000",
            "--class-breakdown",
            "all",
        ])
        .output()?;
    assert!(pooled.status.success());
    assert!(first.status.success());
    assert!(second.status.success());
    assert_eq!(first.stdout, second.stdout);
    let pooled = std::str::from_utf8(&pooled.stdout)?.trim_end();
    let complete = std::str::from_utf8(&first.stdout)?;
    assert_eq!(
        complete
            .split(",\"class_breakdown\":")
            .next()
            .ok_or("pooled prefix")?,
        pooled.strip_suffix('}').ok_or("pooled object")?
    );
    Ok(())
}

#[test]
fn class_breakdown_requires_fixed_threshold_and_refuses_invalid_inventory() -> TestResult {
    for (extras, code) in [
        (
            vec!["--class-breakdown", "all"],
            "evaluation.cli.class_breakdown_requires_fixed_threshold",
        ),
        (
            vec![
                "--fixed-threshold-ppm",
                "800000",
                "--class-breakdown",
                "person,person",
            ],
            "evaluation.duplicate_id",
        ),
        (
            vec![
                "--fixed-threshold-ppm",
                "800000",
                "--class-breakdown",
                "person,,vehicle",
            ],
            "evaluation.invalid_text",
        ),
        (
            vec![
                "--fixed-threshold-ppm",
                "800000",
                "--class-breakdown",
                "bad class",
            ],
            "evaluation.invalid_text",
        ),
    ] {
        let output = command("labels.tsv", "candidates.tsv", "0", "1000")
            .args(extras)
            .output()?;
        assert_refusal(&output, code)?;
    }
    let too_many = (0..257)
        .map(|index| format!("class-{index}"))
        .collect::<Vec<_>>()
        .join(",");
    assert_refusal(
        &command("labels.tsv", "candidates.tsv", "0", "1000")
            .args([
                "--fixed-threshold-ppm",
                "800000",
                "--class-breakdown",
                &too_many,
            ])
            .output()?,
        "evaluation.limit_exceeded",
    )?;
    Ok(())
}

#[test]
fn heldout_cli_binds_the_threshold_and_refuses_calibration_on_holdout() -> TestResult {
    let holdout = || {
        let mut evaluate = command("labels.tsv", "candidates.tsv", "0", "1000");
        evaluate.arg("--holdout-manifest").arg(fixture("holdout.tsv"));
        evaluate
    };
    let output = holdout().args(["--fixed-threshold-ppm", "800000"]).output()?;
    assert!(output.status.success(), "{}", std::str::from_utf8(&output.stderr)?);
    let json = std::str::from_utf8(&output.stdout)?;
    assert!(json.contains("\"schema\":\"fss.evaluation.holdout.v1\""));
    assert!(json.contains("\"membership_basis\":\"caller_declared\""));
    assert!(json.contains("\"training_clips\":1,\"calibration_clips\":1,\"holdout_clips\":1"));
    assert!(json.contains("\"manifest_digest\":\"sha256:"));
    assert_refusal(&holdout().output()?, "evaluation.holdout.options")?;
    assert_refusal(
        &holdout().args(["--fixed-threshold-ppm", "0"]).output()?,
        "evaluation.holdout.threshold",
    )?;
    assert_refusal(
        &holdout().args(["--fixed-threshold-ppm", "800000", "--conformal-alpha-ppm", "100000"]).output()?,
        "evaluation.holdout.options",
    )
}
