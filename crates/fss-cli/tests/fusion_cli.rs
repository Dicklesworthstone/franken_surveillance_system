#![forbid(unsafe_code)]
//! Executable-level tests for `fss-fuse` and `fss-evaluate --calibration-bins`: labelled
//! outcomes become a digest-bound score calibration, the calibration feeds a fusion query, and
//! tampered or missing calibrations, malformed queries and invalid policies are typed refusals.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn scratch(name: &str) -> TestResult<PathBuf> {
    let dir = std::env::temp_dir().join(format!("fss-fuse-cli-{}-{name}", std::process::id()));
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// 300 true events, each detected with a high score, and 700 false alarms with lower scores.
fn write_evaluation_inputs(dir: &Path) -> TestResult<(PathBuf, PathBuf)> {
    let mut labels = String::from("fss-evaluation-labels.v1\nclip\tc\t5000000000000\n");
    let mut candidates = String::from("fss-evaluation-candidates.v1\n");
    for index in 0..300_u64 {
        let start = index * 10_000_000_000;
        labels.push_str(&format!(
            "truth\te{index}\tc\tperson\t-\t{start}\t{}\n",
            start + 1_000_000_000
        ));
        let score = 700_000 + (index * 4_999) % 300_000;
        candidates.push_str(&format!(
            "candidate\ttp{index}\tc\tperson\t-\t{}\t{score}\n",
            start + 100
        ));
    }
    for index in 0..700_u64 {
        let at = 3_100_000_000_000 + index * 2_000_000_000;
        let score = (index * 6_007) % 820_000;
        candidates.push_str(&format!(
            "candidate\tfp{index}\tc\tperson\t-\t{at}\t{score}\n"
        ));
    }
    let (labels_path, candidates_path) = (dir.join("labels.tsv"), dir.join("candidates.tsv"));
    fs::write(&labels_path, labels)?;
    fs::write(&candidates_path, candidates)?;
    Ok((labels_path, candidates_path))
}

fn evaluate(dir: &Path) -> TestResult<PathBuf> {
    let (labels, candidates) = write_evaluation_inputs(dir)?;
    let output = Command::new(env!("CARGO_BIN_EXE_fss-evaluate"))
        .arg("--labels")
        .arg(&labels)
        .arg("--candidates")
        .arg(&candidates)
        .args([
            "--pipeline-generation",
            "synthetic-pipeline",
            "--model-generation",
            "synthetic-model",
            "--policy-generation",
            "synthetic-policy",
            "--max-false-alerts",
            "10",
            "--per-observed-ns",
            "86400000000000",
            "--calibration-bins",
            "0,400000,700000,850000,950000",
            "--calibration-generation",
            "synthetic-detector:cam-a:day:v1",
        ])
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8(output.stdout)?;
    assert!(report.contains("\"score_calibration\":{\"schema\":\"fss.score_calibration.v1\""));
    assert!(report.contains("\"generation\":\"synthetic-detector:cam-a:day:v1\""));
    let path = dir.join("evaluation.json");
    fs::write(&path, report)?;
    Ok(path)
}

fn query(score_a: u32, score_b: u32, coverage: &str) -> String {
    format!(
        r#"{{
  "schema": "fss.fusion_query.v1",
  "hypothesis": "event:night-1",
  "kind": "unknown_presence",
  "prior": "calibration",
  "coverage": {coverage},
  "looks": 1,
  "now_ns": "1000000000000",
  "severity": {{"expected_harm": 10000, "false_alert_cost": 200, "delay_cost_per_second": 5, "reversible": false}},
  "policy": {{
    "generation": "policy:unknown-presence:v1",
    "alert_threshold": 1000, "retain_threshold": -500, "reject_threshold": -2000,
    "min_independent_support": 2, "urgent_single_domain_threshold": null,
    "max_wait_ns": "30000000000", "look_penalty_per_doubling": 301,
    "operator_confirmation_available": true
  }},
  "evidence": [
    {{"id": "cam-a/cand-1", "sensor": "cam-a", "failure_domains": ["sensor:cam-a"], "observability": "observed", "calibration": {{"score_ppm": {score_a}}}}},
    {{"id": "cam-b/cand-7", "sensor": "cam-b", "failure_domains": ["sensor:cam-b"], "observability": "observed", "calibration": {{"score_ppm": {score_b}}}}},
    {{"id": "vlm/phrase", "sensor": "cam-b", "failure_domains": ["sensor:cam-b", "model:vlm"], "observability": "observed", "calibration": {{"uncalibrated": "a VLM phrase has no numeric authority"}}}}
  ]
}}"#
    )
}

fn fuse(dir: &Path, query_text: &str, calibration: Option<&Path>) -> TestResult<Output> {
    let path = dir.join("query.json");
    fs::write(&path, query_text)?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-fuse"));
    command.arg("--query").arg(&path);
    if let Some(calibration) = calibration {
        command.arg("--calibration").arg(calibration);
    }
    Ok(command.output()?)
}

fn assert_refusal(output: &Output, code: &str) {
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(output.stdout.is_empty());
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert!(
        diagnostic.contains("\"schema\":\"fss.fusion.cli_error.v1\""),
        "{diagnostic}"
    );
    assert!(
        diagnostic.contains(&format!("\"code\":\"{code}\"")),
        "{diagnostic}"
    );
    assert!(diagnostic.contains("\"effect_started\":false"));
}

#[test]
fn calibrated_scores_from_two_cameras_alert_and_weak_ones_do_not() -> TestResult {
    let dir = scratch("decide")?;
    let calibration = evaluate(&dir)?;
    let output = fuse(
        &dir,
        &query(980_000, 970_000, r#"{"state": "complete"}"#),
        Some(&calibration),
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let outcome = String::from_utf8(output.stdout)?;
    assert!(outcome.contains("\"schema\":\"fss.fusion_outcome.v1\""));
    assert!(
        outcome.contains("\"decision\":{\"kind\":\"alert\"}"),
        "{outcome}"
    );
    assert!(outcome.contains("\"uncalibrated\":[\"vlm/phrase\"]"));
    assert!(outcome.contains("\"effect_authority\":false"));
    assert!(outcome.contains("\"score_calibration_digest\":\"sha256:"));

    let weak = fuse(
        &dir,
        &query(500_000, 450_000, r#"{"state": "complete"}"#),
        Some(&calibration),
    )?;
    let weak = String::from_utf8(weak.stdout)?;
    assert!(
        !weak.contains("\"decision\":{\"kind\":\"alert\"}"),
        "{weak}"
    );

    // A gap turns strong evidence into an alert with degraded coverage, never a plain alert.
    let gapped = fuse(
        &dir,
        &query(
            980_000,
            970_000,
            r#"{"state": "gap", "reason": "cam-c dark"}"#,
        ),
        Some(&calibration),
    )?;
    assert!(
        String::from_utf8(gapped.stdout)?
            .contains("\"decision\":{\"kind\":\"alert_degraded_coverage\"}")
    );
    fs::remove_dir_all(&dir)?;
    Ok(())
}

#[test]
fn tampered_missing_or_malformed_inputs_are_refused() -> TestResult {
    let dir = scratch("refuse")?;
    let calibration = evaluate(&dir)?;
    // A score without a calibration.
    assert_refusal(
        &fuse(
            &dir,
            &query(980_000, 970_000, r#"{"state": "complete"}"#),
            None,
        )?,
        "fusion.cli.calibration_required",
    );
    // A tampered count no longer reproduces the digest.
    let text = fs::read_to_string(&calibration)?;
    let tampered = text.replacen("\"true_positives\":0", "\"true_positives\":9", 1);
    assert_ne!(
        tampered, text,
        "the fixture must contain an empty bin to tamper"
    );
    let tampered_path = dir.join("tampered.json");
    fs::write(&tampered_path, tampered)?;
    assert_refusal(
        &fuse(
            &dir,
            &query(980_000, 970_000, r#"{"state": "complete"}"#),
            Some(&tampered_path),
        )?,
        "fusion.cli.calibration_digest_mismatch",
    );
    // An inconsistent policy.
    let bad_policy = query(980_000, 970_000, r#"{"state": "complete"}"#)
        .replace("\"retain_threshold\": -500", "\"retain_threshold\": 5000");
    assert_refusal(
        &fuse(&dir, &bad_policy, Some(&calibration))?,
        "ERR-FUSION-POLICY-INVALID-001",
    );
    // Wrong schema and unknown coverage state.
    assert_refusal(
        &fuse(&dir, "{\"schema\": \"other\"}", Some(&calibration))?,
        "fusion.cli.query_schema",
    );
    assert_refusal(
        &fuse(
            &dir,
            &query(1, 2, r#"{"state": "maybe"}"#),
            Some(&calibration),
        )?,
        "fusion.cli.coverage_state",
    );
    fs::remove_dir_all(&dir)?;
    Ok(())
}

#[test]
fn transit_reachability_turns_reachable_observers_into_bounded_waits() -> TestResult {
    let dir = scratch("transit")?;
    let calibration = evaluate(&dir)?;
    // One strong camera at the driveway; the porch camera can see the entity 4-8 s later; the
    // garden gate only opens after the 30 s wait horizon, so the garden camera is never waited
    // for.
    let now: u64 = 1_000_000_000_000;
    let document = format!(
        r#"{{
  "schema": "fss.fusion_query.v1",
  "hypothesis": "event:driveway-1",
  "kind": "unknown_presence",
  "prior": "calibration",
  "coverage": {{"state": "complete"}},
  "looks": 1,
  "now_ns": "{now}",
  "severity": {{"expected_harm": 10000, "false_alert_cost": 200, "delay_cost_per_second": 5, "reversible": false}},
  "policy": {{
    "generation": "policy:unknown-presence:v1",
    "alert_threshold": 1000, "retain_threshold": -500, "reject_threshold": -2000,
    "min_independent_support": 2, "urgent_single_domain_threshold": null,
    "max_wait_ns": "30000000000", "look_penalty_per_doubling": 301,
    "operator_confirmation_available": false
  }},
  "evidence": [
    {{"id": "cam-a/cand-1", "sensor": "cam-a", "failure_domains": ["sensor:cam-a"], "observability": "observed", "calibration": {{"score_ppm": 980000}}}}
  ],
  "transit": {{
    "origin": {{"zone": "driveway", "earliest_ns": "{origin_lo}", "latest_ns": "{now}"}},
    "zones": [
      {{"id": "driveway", "max_wait_ns": "0"}},
      {{"id": "porch", "max_wait_ns": "0"}},
      {{"id": "garden", "max_wait_ns": "0"}}
    ],
    "transits": [
      {{"from": "driveway", "to": "porch", "open_ns": "0", "close_ns": "{far}", "min_travel_ns": "5000000000", "max_travel_ns": "8000000000"}},
      {{"from": "driveway", "to": "garden", "open_ns": "{gate}", "close_ns": "{far}", "min_travel_ns": "1000000000", "max_travel_ns": "2000000000"}}
    ],
    "observers": [
      {{"zone": "porch", "sensor": "cam-b", "failure_domains": ["sensor:cam-b"], "positive": [1200, 1600], "negative": [-1500, -1000]}},
      {{"zone": "garden", "sensor": "cam-c", "failure_domains": ["sensor:cam-c"], "positive": [1200, 1600], "negative": [-1500, -1000]}}
    ]
  }}
}}"#,
        origin_lo = now - 1_000_000_000,
        far = now + 3_600_000_000_000,
        gate = now + 60_000_000_000,
    );
    let output = fuse(&dir, &document, Some(&calibration))?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let outcome = String::from_utf8(output.stdout)?;
    let porch_start = now + 4_000_000_000;
    let porch_end = now + 8_000_000_000;
    assert!(
        outcome.contains(&format!(
            "\"decision\":{{\"kind\":\"wait_for_corroboration\",\"opportunity\":\"transit:cam-b:porch\",\"deadline_ns\":\"{porch_end}\""
        )),
        "{outcome}"
    );
    assert!(outcome.contains(&format!(
        "\"opportunity_window_ns\":[\"{porch_start}\",\"{porch_end}\"]"
    )));
    assert!(outcome.contains("\"zone\":\"garden\",\"sensor\":\"cam-c\",\"reachability\":\"temporally_infeasible\",\"presence_ns\":[],\"opportunity_window_ns\":null"));
    assert!(outcome.contains("\"algorithm\":\"ALG-TREACH-001\""));
    // An unknown observer zone is a typed refusal.
    let bad = document.replace(
        "\"zone\": \"garden\", \"sensor\"",
        "\"zone\": \"attic\", \"sensor\"",
    );
    assert_refusal(
        &fuse(&dir, &bad, Some(&calibration))?,
        "ERR-GRAPH-INPUT-INVALID-001",
    );
    fs::remove_dir_all(&dir)?;
    Ok(())
}
