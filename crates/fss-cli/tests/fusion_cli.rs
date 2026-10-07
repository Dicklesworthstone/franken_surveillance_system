#![forbid(unsafe_code)]
//! Executable-level tests for `fss-fuse` and `fss-evaluate --calibration-bins`: labelled
//! outcomes become a digest-bound score calibration, the calibration feeds a fusion query, and
//! tampered or missing calibrations, malformed queries and invalid policies are typed refusals.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_cli::escape_json_str;
use fss_cli::json_input::{Value, parse};

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
    evaluate_as(dir, "synthetic-detector:cam-a:day:v1", "evaluation")
}

fn evaluate_as(dir: &Path, generation: &str, name: &str) -> TestResult<PathBuf> {
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
            generation,
        ])
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8(output.stdout)?;
    assert!(report.contains("\"score_calibration\":{\"schema\":\"fss.score_calibration.v1\""));
    assert!(report.contains(&format!("\"generation\":\"{generation}\"")));
    let path = dir.join(format!("{name}.json"));
    fs::write(&path, report)?;
    Ok(path)
}

fn query(score_a: u32, score_b: u32, coverage: &str) -> String {
    format!(
        r#"{{
  "schema": "fss.fusion_query.v2",
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

fn calibration_binding(path: &Path) -> TestResult<String> {
    let document = parse(&fs::read_to_string(path)?)?;
    let calibration = document
        .object()
        .and_then(|object| object.get("score_calibration"))
        .and_then(Value::object)
        .ok_or("missing score calibration")?;
    let generation = calibration
        .get("generation")
        .and_then(Value::text)
        .ok_or("missing calibration generation")?;
    let digest = calibration
        .get("digest")
        .and_then(Value::text)
        .ok_or("missing calibration digest")?;
    Ok(format!(
        "\"generation\": \"{}\", \"digest\": \"{}\"",
        escape_json_str(generation),
        escape_json_str(digest)
    ))
}

fn bind_scores(query_text: &str, calibration: &Path) -> TestResult<String> {
    Ok(query_text.replace(
        r#"{"score_ppm": "#,
        &format!("{{{}, \"score_ppm\": ", calibration_binding(calibration)?),
    ))
}

fn fuse(dir: &Path, query_text: &str, calibration: Option<&Path>) -> TestResult<Output> {
    match calibration {
        Some(calibration) => {
            fuse_many(dir, &bind_scores(query_text, calibration)?, &[calibration])
        }
        None => fuse_many(dir, query_text, &[]),
    }
}

fn fuse_many(dir: &Path, query_text: &str, calibrations: &[&Path]) -> TestResult<Output> {
    let path = dir.join("query.json");
    fs::write(&path, query_text)?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-fuse"));
    command.arg("--query").arg(&path);
    for calibration in calibrations {
        command.arg("--calibration").arg(calibration);
    }
    Ok(command.output()?)
}

fn output_text(output: Output) -> TestResult<String> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

fn json_text_field(document: &str, key: &str) -> TestResult<String> {
    Ok(parse(document)?
        .object()
        .and_then(|object| object.get(key))
        .and_then(Value::text)
        .ok_or("missing text field")?
        .to_owned())
}

fn independently_bound_query(a: &Path, b: &Path, coverage: &str) -> TestResult<String> {
    let a = calibration_binding(a)?;
    let b = calibration_binding(b)?;
    Ok(query(980_000, 970_000, coverage)
        .replace(
            "\"prior\": \"calibration\"",
            &format!("\"prior\": {{{a}}}"),
        )
        .replace(
            "{\"score_ppm\": 980000}",
            &format!("{{\"score_ppm\": 980000, {a}}}"),
        )
        .replace(
            "{\"score_ppm\": 970000}",
            &format!("{{\"score_ppm\": 970000, {b}}}"),
        ))
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
fn one_score_calibration_cannot_independently_corroborate_itself() -> TestResult {
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
        outcome.contains("\"decision\":{\"kind\":\"request_operator_confirmation\"}"),
        "{outcome}"
    );
    assert!(outcome.contains("\"supporting_clusters\":1"), "{outcome}");
    assert!(outcome.contains("calibration:sha256:"), "{outcome}");
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

    // Gapped coverage cannot turn repeated use of one calibration into independent support.
    let gapped = fuse(
        &dir,
        &query(
            980_000,
            970_000,
            r#"{"state": "gap", "reason": "cam-c dark"}"#,
        ),
        Some(&calibration),
    )?;
    let gapped = output_text(gapped)?;
    assert!(!gapped.contains("\"decision\":{\"kind\":\"alert"), "{gapped}");
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
    // for. The false-alert cost makes this bounded wait decision-relevant after delay cost.
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
  "severity": {{"expected_harm": 10000, "false_alert_cost": 1000, "delay_cost_per_second": 5, "reversible": false}},
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

#[test]
fn distinct_calibrations_are_selected_by_identity_not_argument_order() -> TestResult {
    let dir = scratch("multiple-calibrations")?;
    let a = evaluate_as(&dir, "detector-a:cam-a:day:v1", "calibration-a")?;
    let b = evaluate_as(&dir, "independent-detector-b:cam-b:day:v1", "calibration-b")?;
    let document = independently_bound_query(&a, &b, r#"{"state": "complete"}"#)?;
    let first = output_text(fuse_many(&dir, &document, &[&a, &b])?)?;
    let reversed = output_text(fuse_many(&dir, &document, &[&b, &a])?)?;
    assert_eq!(first, reversed, "argument order must not select a calibration");
    assert!(first.contains("\"decision\":{\"kind\":\"alert\"}"), "{first}");
    assert!(first.contains("\"supporting_clusters\":2"), "{first}");
    assert!(first.contains("\"score_calibration_digest\":null"), "{first}");
    assert!(first.contains("\"score_calibrations\":["), "{first}");
    assert!(first.contains("\"prior_calibration\":{\"generation\":\"detector-a:cam-a:day:v1\""));

    let gapped = independently_bound_query(
        &a,
        &b,
        r#"{"state": "gap", "reason": "cam-c dark"}"#,
    )?;
    let gapped = output_text(fuse_many(&dir, &gapped, &[&a, &b])?)?;
    assert!(
        gapped.contains("\"decision\":{\"kind\":\"alert_degraded_coverage\"}"),
        "{gapped}"
    );
    let ambiguous_prior = document.replace(
        &format!("\"prior\": {{{}}}", calibration_binding(&a)?),
        "\"prior\": \"calibration\"",
    );
    assert_refusal(
        &fuse_many(&dir, &ambiguous_prior, &[&a, &b])?,
        "fusion.cli.prior_ambiguous",
    );
    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn scores_require_exact_unambiguous_calibration_bindings() -> TestResult {
    let dir = scratch("binding-refusals")?;
    let calibration = evaluate(&dir)?;
    let raw = query(980_000, 970_000, r#"{"state": "complete"}"#);
    let legacy = raw.replace("fss.fusion_query.v2", "fss.fusion_query.v1");
    for document in [&raw, &legacy] {
        assert_refusal(
            &fuse_many(&dir, document, &[&calibration])?,
            "fusion.cli.calibration_binding_required",
        );
    }
    let bound = bind_scores(&raw, &calibration)?;
    let wrong_generation = bound.replace(
        "synthetic-detector:cam-a:day:v1",
        "unrelated-detector:night:v7",
    );
    assert_refusal(
        &fuse_many(&dir, &wrong_generation, &[&calibration])?,
        "fusion.cli.calibration_generation_mismatch",
    );
    let wrong_digest = bound.replace("sha256:", "sha256:00");
    assert_refusal(
        &fuse_many(&dir, &wrong_digest, &[&calibration])?,
        "fusion.cli.calibration_unknown",
    );
    let ambiguous_mode = bound.replace(
        "\"score_ppm\": 980000",
        "\"score_ppm\": 980000, \"uncalibrated\": \"ambiguous\"",
    );
    assert_refusal(
        &fuse_many(&dir, &ambiguous_mode, &[&calibration])?,
        "fusion.cli.calibration_mode",
    );
    let out_of_range = bound.replace("\"score_ppm\": 980000", "\"score_ppm\": 1000001");
    assert_refusal(
        &fuse_many(&dir, &out_of_range, &[&calibration])?,
        "fusion.cli.score_out_of_range",
    );
    assert_refusal(
        &fuse_many(&dir, &bound, &[&calibration, &calibration])?,
        "fusion.cli.calibration_duplicate",
    );
    let without_prior = bound.replace("\"prior\": \"calibration\"", "\"prior\": [0, 0]");
    assert_refusal(
        &fuse_many(&dir, &without_prior, &[])?,
        "fusion.cli.calibration_required",
    );
    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn one_calibration_generation_cannot_name_conflicting_contents() -> TestResult {
    let dir = scratch("generation-conflict")?;
    let a = evaluate(&dir)?;
    let conflicting = fss_fusion::ScoreCalibration::from_counts(
        "synthetic-detector:cam-a:day:v1",
        &[0],
        &[(100, 100)],
    )?;
    let b = dir.join("conflicting.json");
    fs::write(
        &b,
        format!(
            r#"{{"schema":"fss.score_calibration.v1","generation":"{}","digest":"{}","bins":[{{"lo_ppm":0,"true_positives":100,"false_positives":100}}]}}"#,
            conflicting.generation,
            conflicting.digest.to_text(),
        ),
    )?;
    let document = query(980_000, 970_000, r#"{"state": "complete"}"#);
    assert_refusal(
        &fuse_many(&dir, &document, &[&a, &b])?,
        "fusion.cli.calibration_generation_conflict",
    );
    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn exact_prior_identity_and_raw_scores_remain_digest_bound() -> TestResult {
    let dir = scratch("input-provenance")?;
    // Same labelled counts give identical numerical priors; generation identity still matters.
    let a = evaluate_as(&dir, "detector-a:cam-a:day:v1", "calibration-a")?;
    let b = evaluate_as(&dir, "independent-detector-b:cam-b:day:v1", "calibration-b")?;
    let document = independently_bound_query(&a, &b, r#"{"state": "complete"}"#)?;
    let first = output_text(fuse_many(&dir, &document, &[&a, &b])?)?;
    let other_prior = document.replace(
        &format!("\"prior\": {{{}}}", calibration_binding(&a)?),
        &format!("\"prior\": {{{}}}", calibration_binding(&b)?),
    );
    assert_ne!(document, other_prior);
    let other = output_text(fuse_many(&dir, &other_prior, &[&a, &b])?)?;
    assert_eq!(
        json_text_field(&first, "query_digest")?,
        json_text_field(&other, "query_digest")?,
    );
    assert_eq!(
        json_text_field(&first, "decision_digest")?,
        json_text_field(&other, "decision_digest")?,
    );
    assert_ne!(
        json_text_field(&first, "input_binding_digest")?,
        json_text_field(&other, "input_binding_digest")?,
    );
    assert!(other.contains(
        "\"prior_calibration\":{\"generation\":\"independent-detector-b:cam-b:day:v1\""
    ));

    // These two raw values land in the same bin and must still be distinguishable in provenance.
    let within_bin = document.replace("\"score_ppm\": 980000", "\"score_ppm\": 980001");
    let changed_score = output_text(fuse_many(&dir, &within_bin, &[&a, &b])?)?;
    assert_eq!(
        json_text_field(&first, "query_digest")?,
        json_text_field(&changed_score, "query_digest")?,
    );
    assert_ne!(
        json_text_field(&first, "input_binding_digest")?,
        json_text_field(&changed_score, "input_binding_digest")?,
    );
    assert!(changed_score.contains("\"evidence_id\":\"cam-a/cand-1\",\"score_ppm\":980001"));
    assert!(changed_score.contains("\"effect_authority\":false"));
    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn explicit_llrs_remain_readable_and_conflicting_stdin_is_refused() -> TestResult {
    let dir = scratch("explicit-llrs")?;
    let document = query(980_000, 970_000, r#"{"state": "complete"}"#)
        .replace("fss.fusion_query.v2", "fss.fusion_query.v1")
        .replace("\"prior\": \"calibration\"", "\"prior\": [0, 0]")
        .replace(
            "{\"score_ppm\": 980000}",
            "{\"generation\": \"asserted-a:v1\", \"llr\": [1200, 1600]}",
        )
        .replace(
            "{\"score_ppm\": 970000}",
            "{\"generation\": \"asserted-b:v1\", \"llr\": [1200, 1600]}",
        );
    let outcome = output_text(fuse_many(&dir, &document, &[])?)?;
    assert!(outcome.contains("\"decision\":{\"kind\":\"alert\"}"), "{outcome}");
    assert!(outcome.contains("\"prior_calibration\":null"), "{outcome}");
    assert!(outcome.contains("\"score_calibration_bindings\":[]"), "{outcome}");
    let conflict = Command::new(env!("CARGO_BIN_EXE_fss-fuse"))
        .args(["--query", "-", "--calibration", "-"])
        .output()?;
    assert_refusal(&conflict, "fusion.cli.stdin_conflict");
    fs::remove_dir_all(dir)?;
    Ok(())
}
