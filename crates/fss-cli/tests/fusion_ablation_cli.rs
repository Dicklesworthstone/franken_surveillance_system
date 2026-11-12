#![forbid(unsafe_code)]
//! Real command regressions for source-loss explanations and their replay/provenance boundary.

use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use fss_cli::json_input::{Value, parse};
use fss_cli::json_output::string;
use fss_fusion::ScoreCalibration;

type Test<T = ()> = Result<T, Box<dyn Error>>;

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Test<Self> {
        for index in 0..100 {
            let path =
                std::env::temp_dir().join(format!("fss-ablation-{}-{index}", std::process::id(),));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("scratch names exhausted".into())
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn invoke(query: &str, options: &[&str]) -> Test<Output> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_fss-fuse"))
        .args(["--query", "-"])
        .args(options)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut input) = child.stdin.take() {
        // Argument refusal can exit before consuming stdin. Preserve that real-process refusal.
        if let Err(error) = input.write_all(query.as_bytes()) {
            if error.kind() != std::io::ErrorKind::BrokenPipe {
                return Err(error.into());
            }
        }
    }
    Ok(child.wait_with_output()?)
}
fn accepted(output: Output) -> Test<Value> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    Ok(parse(std::str::from_utf8(&output.stdout)?)?)
}
fn field<'a>(v: &'a Value, key: &str) -> Test<&'a Value> {
    v.object()
        .and_then(|o| o.get(key))
        .ok_or_else(|| format!("missing {key}").into())
}
fn text<'a>(v: &'a Value, key: &str) -> Test<&'a str> {
    field(v, key)?
        .text()
        .ok_or_else(|| format!("non-text {key}").into())
}
fn encode(v: &Value) -> String {
    match v {
        Value::Null => "null".to_owned(),
        Value::Bool(v) => v.to_string(),
        Value::Number(v) => v.clone(),
        Value::Text(v) => string(v),
        Value::Array(rows) => format!(
            "[{}]",
            rows.iter().map(encode).collect::<Vec<_>>().join(",")
        ),
        Value::Object(rows) => format!(
            "{{{}}}",
            rows.iter()
                .map(|(k, v)| format!("{}:{}", string(k), encode(v)))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}
fn item(id: &str, sensor: &str, domains: &str, calibration: &str) -> String {
    format!(
        r#"{{"id":{id},"sensor":{sensor},"failure_domains":{domains},
        "observability":"observed","calibration":{calibration}}}"#,
        id = string(id),
        sensor = string(sensor)
    )
}
fn direct(lo: i64, hi: i64) -> String {
    format!(r#"{{"generation":"manual:v1","llr":[{lo},{hi}]}}"#)
}
fn query(evidence: &[String], opportunities: &str, probes: &str) -> String {
    format!(
        r#"{{"schema":"fss.fusion_query.v2","hypothesis":"event:entry",
        "kind":"unknown_presence","prior":[0,0],"looks":1,"now_ns":"20",
        "coverage":{{"state":"complete"}},
        "severity":{{"expected_harm":"10000","false_alert_cost":"200",
        "delay_cost_per_second":"1","reversible":false}},
        "policy":{{"generation":"policy:v1","alert_threshold":1000,"retain_threshold":0,
        "reject_threshold":-2000,"min_independent_support":2,"urgent_single_domain_threshold":null,
        "max_wait_ns":"100","look_penalty_per_doubling":301,"operator_confirmation_available":false}},
        "evidence":[{}],"opportunities":{opportunities},"probes":{probes}}}"#,
        evidence.join(",")
    )
}

#[test]
fn source_loss_reclusters_and_both_complete_queries_replay_through_the_ordinary_command() -> Test {
    let original = query(
        &[
            item("a", "camera-a", r#"["power:a"]"#, &direct(600, 900)),
            item(
                "bridge",
                "camera-bridge",
                r#"["power:a","power:b"]"#,
                &direct(-100, 400),
            ),
            item("b", "camera-b", r#"["power:b"]"#, &direct(700, 1000)),
        ],
        "[]",
        "[]",
    );
    let ordinary = accepted(invoke(&original, &[])?)?;
    assert_eq!(text(&ordinary, "schema")?, "fss.fusion_outcome.v1");
    assert!(ordinary.object().unwrap().get("ablation").is_none());
    let report = accepted(invoke(&original, &["--without-sensor", "camera-bridge"])?)?;
    assert_eq!(text(&report, "schema")?, "fss.fusion_ablation_report.v1");
    assert_eq!(
        field(&report, "native_source_verified")?,
        &Value::Bool(false)
    );
    let ablation = field(&report, "ablation")?;
    assert_eq!(
        field(ablation, "unavailable_evidence")?,
        &Value::Array(vec![Value::Text("bridge".into())])
    );
    let baseline = field(ablation, "baseline")?;
    let projected = field(ablation, "counterfactual")?;
    assert_eq!(
        field(field(projected, "outcome")?, "posterior_log_odds_millibans")?,
        &parse("[1300,1900]")?
    );
    assert_eq!(
        text(field(field(projected, "outcome")?, "decision")?, "kind")?,
        "alert_degraded_coverage"
    );
    assert_eq!(
        field(field(projected, "query")?, "evidence")?
            .array()
            .unwrap()
            .len(),
        3
    );
    for side in [baseline, projected] {
        let replay = accepted(invoke(&encode(field(side, "query")?), &[])?)?;
        assert_eq!(
            text(&replay, "query_digest")?,
            text(field(side, "outcome")?, "query_digest")?
        );
        assert_eq!(
            text(&replay, "decision_digest")?,
            text(field(side, "outcome")?, "decision_digest")?
        );
    }
    assert_eq!(
        text(&ordinary, "decision_digest")?,
        text(field(baseline, "outcome")?, "decision_digest")?
    );
    let a = accepted(invoke(
        &original,
        &[
            "--without-sensor",
            "camera-bridge",
            "--without-domain",
            "power:a",
        ],
    )?)?;
    let b = accepted(invoke(
        &original,
        &[
            "--without-domain",
            "power:a",
            "--without-sensor",
            "camera-bridge",
        ],
    )?)?;
    assert_eq!(a, b, "selector order changed the simultaneous explanation");
    Ok(())
}

#[test]
fn future_choices_from_a_failed_sensor_are_removed_and_the_baseline_choices_replay() -> Test {
    let original = query(
        &[item("a", "camera-a", r#"["model:a"]"#, &direct(500, 700))],
        r#"[{"id":"arrival-b","sensor":"camera-b","failure_domains":["model:b"],
            "window_start_ns":"30","window_end_ns":"50","positive":[900,900],"negative":[-900,-900]}]"#,
        r#"[{"id":"resample-b","kind":"camera_sample","failure_domains":["sensor:camera-b"],
            "cost":"1","latency_ns":"1","positive":[900,900],"negative":[-900,-900]}]"#,
    );
    let report = accepted(invoke(&original, &["--without-sensor", "camera-b"])?)?;
    let ablation = field(&report, "ablation")?;
    let baseline = field(ablation, "baseline")?;
    let projected = field(ablation, "counterfactual")?;
    assert_eq!(
        text(field(field(baseline, "outcome")?, "decision")?, "kind")?,
        "wait_for_corroboration"
    );
    assert_eq!(
        text(field(field(projected, "outcome")?, "decision")?, "kind")?,
        "hold_indeterminate"
    );
    assert_eq!(
        field(ablation, "removed_opportunities")?,
        &parse(r#"["arrival-b"]"#)?
    );
    assert_eq!(
        field(ablation, "removed_probes")?,
        &parse(r#"["resample-b"]"#)?
    );
    let replay = accepted(invoke(&encode(field(baseline, "query")?), &[])?)?;
    assert_eq!(
        text(&replay, "decision_digest")?,
        text(field(baseline, "outcome")?, "decision_digest")?
    );
    assert_eq!(
        field(field(projected, "query")?, "opportunities")?,
        &parse("[]")?
    );
    assert_eq!(field(field(projected, "query")?, "probes")?, &parse("[]")?);
    Ok(())
}

#[test]
fn calibration_inputs_survive_projection_and_a_different_raw_score_changes_the_outer_receipt()
-> Test {
    let scratch = Scratch::new()?;
    let calibration =
        ScoreCalibration::from_counts("camera-mode:v1", &[0, 500000], &[(100, 9900), (9900, 100)])?;
    let artifact = format!(
        r#"{{"schema":"fss.score_calibration.v1","generation":"camera-mode:v1",
        "digest":"{}","bins":[{{"lo_ppm":0,"true_positives":100,"false_positives":9900}},
        {{"lo_ppm":500000,"true_positives":9900,"false_positives":100}}]}}"#,
        calibration.digest
    );
    let path = scratch.0.join("calibration.json");
    fs::write(&path, &artifact)?;
    let path_text = path.to_str().ok_or("non-unicode scratch")?;
    let binding = |score| {
        format!(
            r#"{{"generation":"camera-mode:v1","digest":"{}","score_ppm":{score}}}"#,
            calibration.digest
        )
    };
    let request = |score| {
        query(
            &[
                item("a", "camera-a", "[]", &binding(score)),
                item("b", "camera-b", "[]", &binding(900000)),
            ],
            "[]",
            "[]",
        )
        .replace(
            r#""prior":[0,0]"#,
            &format!(
                r#""prior":{{"generation":"camera-mode:v1","digest":"{}"}}"#,
                calibration.digest
            ),
        )
    };
    let first = accepted(invoke(
        &request(750000),
        &["--calibration", path_text, "--without-sensor", "camera-b"],
    )?)?;
    let second = accepted(invoke(
        &request(750001),
        &["--calibration", path_text, "--without-sensor", "camera-b"],
    )?)?;
    assert_eq!(
        text(field(&first, "ablation")?, "ablation_digest")?,
        text(field(&second, "ablation")?, "ablation_digest")?,
        "scores inside one bin should share numerical query"
    );
    assert_ne!(
        text(&first, "report_digest")?,
        text(&second, "report_digest")?
    );
    let provenance = field(&first, "calibration_provenance")?;
    assert_eq!(
        field(provenance, "score_calibration_bindings")?
            .array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        text(field(provenance, "prior_calibration")?, "digest")?,
        calibration.digest.to_text()
    );
    assert_ne!(
        text(provenance, "baseline_input_binding_digest")?,
        text(provenance, "counterfactual_input_binding_digest")?
    );
    assert_eq!(fs::read_to_string(path)?, artifact);
    assert_eq!(
        fs::read_dir(&scratch.0)?.count(),
        1,
        "read-only explanation created a file"
    );
    Ok(())
}

#[test]
fn malformed_unmatched_duplicate_excessive_and_sequence_selectors_refuse_without_output() -> Test {
    let original = query(
        &[item("a", "camera-a", "[]", &direct(500, 700))],
        "[]",
        "[]",
    );
    let excess: Vec<&str> = std::iter::repeat_n(["--without-sensor", "camera-a"], 17)
        .flatten()
        .collect();
    for options in [
        vec!["--without-sensor", "missing"],
        vec!["--without-sensor", ""],
        vec![
            "--without-sensor",
            "camera-a",
            "--without-sensor",
            "camera-a",
        ],
        vec!["--without-sensor", "camera-a", "--without-domain", "absent"],
        excess,
        vec!["--without-sensor"],
    ] {
        let output = invoke(&original, &options)?;
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let error = parse(std::str::from_utf8(&output.stderr)?)?;
        assert_eq!(text(&error, "schema")?, "fss.fusion.cli_error.v1");
        assert_eq!(field(&error, "effect_started")?, &Value::Bool(false));
    }
    let scratch = Scratch::new()?;
    let checkpoint = scratch.0.join("must-not-exist.checkpoint");
    let output = Command::new(env!("CARGO_BIN_EXE_fss-fuse"))
        .args(["--sequence", "does-not-exist.json", "--checkpoint-out"])
        .arg(&checkpoint)
        .args(["--without-sensor", "camera-a"])
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!checkpoint.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("fusion.cli.sequence_invalid"));
    Ok(())
}
