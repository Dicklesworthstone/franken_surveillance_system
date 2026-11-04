#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::panic)]
//! Restart, exact-input and publication regression tests for the executable's real adapter.

use std::sync::atomic::{AtomicU64, Ordering};

use fss_cli::json_input::parse;

use super::*;

fn good<T>(result: Result<T>) -> T {
    result.unwrap_or_else(|error| panic!("{}: {}", error.code, error.detail))
}

fn code<T>(result: Result<T>) -> String {
    match result {
        Ok(_) => panic!("expected refusal"),
        Err(error) => error.code,
    }
}

fn json(value: &str) -> Value {
    parse(value).unwrap_or_else(|error| panic!("{error}"))
}

fn source(label: &str) -> String {
    ContentDigest::sha256(label.as_bytes()).to_text()
}

fn request_text(steps: &[String], limit: usize) -> String {
    format!(
        r#"{{"schema":"fss.fusion_sequence.v1","hypothesis":"event:entry",
        "config":{{"alert_threshold_mban":1000,"floor_mban":-10000,
        "ceiling_mban":10000,"min_independent_clusters":2}},
        "source_limit":{limit},"steps":[{}]}}"#,
        steps.join(",")
    )
}

fn request(steps: &[String], limit: usize) -> Value {
    json(&request_text(steps, limit))
}

fn observation(
    alias: &str,
    sensor: &str,
    source: Option<&str>,
    calibration: &str,
    now: u64,
    observability: &str,
) -> String {
    format!(
        r#"{{"kind":"observe","query":{{"schema":"fss.fusion_query.v2",
        "hypothesis":"event:entry","kind":"unknown_presence","prior":[-1000,-1000],
        "coverage":{{"state":"complete"}},"looks":1,"now_ns":"{now}",
        "severity":{{"expected_harm":10000,"false_alert_cost":200,
        "delay_cost_per_second":5,"reversible":false}},
        "policy":{{"generation":"policy:v1","alert_threshold":1000,
        "retain_threshold":-500,"reject_threshold":-2000,"min_independent_support":2,
        "urgent_single_domain_threshold":null,"max_wait_ns":"30000000000",
        "look_penalty_per_doubling":301,"operator_confirmation_available":true}},
        "evidence":[{{"id":{},"sensor":{},"failure_domains":[{}],
        "observability":{observability},"calibration":{calibration}}}]}},"sources":{{{}:{}}}}}"#,
        text(alias),
        text(sensor),
        text(&format!("sensor:{sensor}")),
        text(alias),
        source.map_or_else(|| "null".to_owned(), text)
    )
}

fn direct(alias: &str, sensor: &str, source: &str, now: u64) -> String {
    observation(
        alias,
        sensor,
        Some(source),
        r#"{"generation":"manual:v1","llr":[600,600]}"#,
        now,
        r#""observed""#,
    )
}

fn operator_reset() -> String {
    r#"{"kind":"reset","reason":{"kind":"operator_reset","reason":"new regime"}}"#.to_owned()
}

fn restored(bytes: &[u8]) -> State {
    good(State::restore(bytes, ContentDigest::sha256(bytes)))
}

fn report_field<'a>(report: &'a Value, key: &str) -> &'a Value {
    report
        .object()
        .and_then(|map| map.get(key))
        .unwrap_or_else(|| panic!("missing {key}"))
}

#[test]
fn split_restart_produces_identical_checkpoint_and_both_transcript_heads() {
    let a = source("a");
    let b = source("b");
    let steps = vec![
        direct("a", "cam-a", &a, 1),
        direct("retry", "cam-a", &a, 2),
        operator_reset(),
        direct("b", "cam-b", &b, 3),
        direct("a-again", "cam-a", &a, 4),
    ];
    let (full_report, full_bytes) = good(execute(
        &request(&steps, 4),
        &Calibrations::new(),
        None,
        None,
    ));
    let (_, prefix) = good(execute(
        &request(&steps[..2], 4),
        &Calibrations::new(),
        None,
        None,
    ));
    let (resumed_report, resumed_bytes) = good(execute(
        &request(&steps[2..], 4),
        &Calibrations::new(),
        Some(restored(&prefix)),
        Some(ContentDigest::sha256(&prefix)),
    ));
    assert_eq!(full_bytes, resumed_bytes);
    let full = json(&full_report);
    let resumed = json(&resumed_report);
    assert_eq!(
        report_field(&full, "sequence_transcript_digest"),
        report_field(&resumed, "sequence_transcript_digest")
    );
    assert_eq!(
        report_field(&full, "steps").array().expect("steps")[2..],
        *report_field(&resumed, "steps").array().expect("steps")
    );
    assert_eq!(restored(&resumed_bytes).process.sources_seen(), 2);
    assert_eq!(
        restored(&resumed_bytes)
            .process
            .accumulator()
            .accumulated_llr(),
        LlrInterval::point(600).expect("point")
    );
}

#[test]
fn renamed_retry_after_restart_contributes_no_numeric_evidence() {
    let a = source("a");
    let (_, prefix) = good(execute(
        &request(&[direct("old", "cam-a", &a, 1)], 2),
        &Calibrations::new(),
        None,
        None,
    ));
    let (report, bytes) = good(execute(
        &request(&[direct("new", "cam-a", &a, 2)], 2),
        &Calibrations::new(),
        Some(restored(&prefix)),
        Some(ContentDigest::sha256(&prefix)),
    ));
    let state = restored(&bytes);
    assert_eq!(state.process.sources_seen(), 1);
    assert_eq!(
        state.process.accumulator().accumulated_llr(),
        LlrInterval::point(600).expect("point")
    );
    assert!(report.contains("\"disposition\":\"already_admitted\""));
    assert!(report.contains("\"step_delta_millibans\":[0,0]"));
}

#[test]
fn same_bin_raw_score_change_is_refused_after_restart() {
    let calibration =
        ScoreCalibration::from_counts("cal:v1", &[0, 500_000], &[(10, 900), (900, 10)])
            .expect("calibration");
    let raw = |score| {
        format!(
            r#"{{"generation":"cal:v1","digest":{},"score_ppm":{score}}}"#,
            text(&calibration.digest.to_text())
        )
    };
    let a = source("raw-score");
    assert_eq!(
        calibration.calibrate(700_000),
        calibration.calibrate(700_001)
    );
    let first = observation(
        "first",
        "cam-a",
        Some(&a),
        &raw(700_000),
        1,
        r#""observed""#,
    );
    let changed = observation(
        "changed",
        "cam-a",
        Some(&a),
        &raw(700_001),
        2,
        r#""observed""#,
    );
    let mut calibrations = Calibrations::new();
    calibrations.insert(calibration.digest.to_text(), calibration);
    let (_, bytes) = good(execute(&request(&[first], 2), &calibrations, None, None));
    assert_eq!(
        code(execute(
            &request(&[changed], 2),
            &calibrations,
            Some(restored(&bytes)),
            Some(ContentDigest::sha256(&bytes))
        )),
        "ERR-FUSION-SOURCE-CONFLICT-001"
    );
}

#[test]
fn reset_and_restart_do_not_refund_signed_source_capacity() {
    let a = source("signed");
    let negative = observation(
        "negative",
        "cam-a",
        Some(&a),
        r#"{"generation":"manual:v1","llr":[-500,-500]}"#,
        1,
        r#""observed""#,
    );
    let (_, bytes) = good(execute(
        &request(&[negative, operator_reset()], 1),
        &Calibrations::new(),
        None,
        None,
    ));
    let state = restored(&bytes);
    assert_eq!(state.process.sources_seen(), 1);
    assert_eq!(
        state.process.accumulator().accumulated_llr(),
        LlrInterval::point(0).expect("point")
    );
    assert!(
        execute(
            &request(&[direct("b", "cam-b", &source("b"), 2)], 1),
            &Calibrations::new(),
            Some(state),
            Some(ContentDigest::sha256(&bytes))
        )
        .is_err()
    );
}

#[test]
fn genesis_and_nonnumeric_missing_sources_roundtrip_without_consuming_capacity() {
    let (_, empty) = good(execute(&request(&[], 1), &Calibrations::new(), None, None));
    let (_, same) = good(execute(
        &request(&[], 1),
        &Calibrations::new(),
        Some(restored(&empty)),
        Some(ContentDigest::sha256(&empty)),
    ));
    assert_eq!(empty, same);
    let missing = observation(
        "missing",
        "cam-a",
        None,
        r#"{"uncalibrated":"no numeric claim"}"#,
        1,
        r#"{"not_observable":"occluded"}"#,
    );
    let (_, bytes) = good(execute(
        &request(&[missing], 1),
        &Calibrations::new(),
        Some(restored(&same)),
        Some(ContentDigest::sha256(&same)),
    ));
    assert_eq!(restored(&bytes).process.sources_seen(), 0);
    assert_eq!(restored(&bytes).last_observation_ns, Some(1));
}

#[test]
fn changed_configuration_and_backwards_time_refuse_continuation() {
    let (_, bytes) = good(execute(
        &request(&[direct("a", "cam-a", &source("a"), 10)], 2),
        &Calibrations::new(),
        None,
        None,
    ));
    for changed in [
        request_text(&[], 2).replace("event:entry", "event:other"),
        request_text(&[], 2).replace("\"floor_mban\":-10000", "\"floor_mban\":0"),
        request_text(&[], 3),
    ] {
        assert_eq!(
            code(execute(
                &json(&changed),
                &Calibrations::new(),
                Some(restored(&bytes)),
                Some(ContentDigest::sha256(&bytes))
            )),
            "fusion.cli.checkpoint_configuration"
        );
    }
    assert!(
        execute(
            &request(&[direct("b", "cam-b", &source("b"), 9)], 2),
            &Calibrations::new(),
            Some(restored(&bytes)),
            Some(ContentDigest::sha256(&bytes))
        )
        .is_err()
    );
}

#[test]
fn digest_truncation_trailing_bytes_and_inventory_mismatch_refuse() {
    let (_, bytes) = good(execute(
        &request(&[direct("a", "cam-a", &source("a"), 1)], 2),
        &Calibrations::new(),
        None,
        None,
    ));
    assert_eq!(
        code(State::restore(&bytes, ContentDigest::sha256(b"wrong"))),
        "fusion.cli.checkpoint_identity"
    );
    for cut in [0, 8, bytes.len() / 2, bytes.len() - 1] {
        let truncated = &bytes[..cut];
        assert!(State::restore(truncated, ContentDigest::sha256(truncated)).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(State::restore(&extra, ContentDigest::sha256(&extra)).is_err());
    let mut mismatched = restored(&bytes);
    mismatched.raw_seen.clear();
    assert!(mismatched.checkpoint().is_err());
    // A changed raw inventory key with a recomputed outer hash must still match the core keys.
    let mut mismatch = bytes.clone();
    let source_start = mismatch.len() - 66;
    mismatch[source_start + 1] ^= 1;
    assert!(State::restore(&mismatch, ContentDigest::sha256(&mismatch)).is_err());
}

#[test]
fn unknown_fields_missing_bindings_and_step_overflow_refuse() {
    let step = direct("a", "cam-a", &source("a"), 1);
    let bad = step.replace(&format!("\"a\":{}", text(&source("a"))), "\"a\":null");
    assert!(execute(&request(&[bad], 2), &Calibrations::new(), None, None).is_err());
    let mut unknown = request(&[step], 2);
    if let Value::Object(fields) = &mut unknown {
        fields.insert("ignored".to_owned(), Value::Bool(true));
    }
    assert!(execute(&unknown, &Calibrations::new(), None, None).is_err());
    assert!(
        execute(
            &request(&vec![operator_reset(); MAX_STEPS + 1], 2),
            &Calibrations::new(),
            None,
            None
        )
        .is_err()
    );
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "fss-fusion-sequence-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("isolated test directory");
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn args(input: &Path, output: &Path) -> Vec<OsString> {
    vec![
        "--sequence".into(),
        input.as_os_str().into(),
        "--checkpoint-out".into(),
        output.as_os_str().into(),
    ]
}

#[test]
fn failed_later_transition_publishes_no_prefix_and_preserves_previous_checkpoint() {
    let dir = Scratch::new();
    let a = source("a");
    let (_, prior) = good(execute(
        &request(&[direct("a", "cam-a", &a, 1)], 3),
        &Calibrations::new(),
        None,
        None,
    ));
    let prior_path = dir.0.join("previous.bin");
    fs::write(&prior_path, &prior).expect("prior");
    let input = dir.0.join("steps.json");
    let output = dir.0.join("next.bin");
    let conflict = direct("reinterpret", "cam-a", &a, 3).replace("[600,600]", "[700,700]");
    fs::write(
        &input,
        request_text(&[direct("b", "cam-b", &source("b"), 2), conflict], 3),
    )
    .expect("steps");
    let mut arguments = args(&input, &output);
    arguments.extend([
        OsString::from("--checkpoint-in"),
        prior_path.as_os_str().into(),
        OsString::from("--checkpoint-digest"),
        ContentDigest::sha256(&prior).to_text().into(),
    ]);
    assert!(run(arguments).is_err());
    assert!(!output.exists());
    assert_eq!(fs::read(&prior_path).expect("unchanged prior"), prior);
}

#[test]
fn complete_command_writes_digest_pinned_checkpoint_and_never_overwrites() {
    let dir = Scratch::new();
    let input = dir.0.join("steps.json");
    let output = dir.0.join("state.bin");
    fs::write(
        &input,
        request_text(&[direct("a", "cam-a", &source("a"), 1)], 2),
    )
    .expect("input");
    let report = json(&good(run(args(&input, &output))));
    let bytes = fs::read(&output).expect("published checkpoint");
    let expected = good(sha(report_field(&report, "checkpoint_digest")
        .text()
        .expect("digest")));
    assert_eq!(
        good(read_checkpoint(&output, expected))
            .process
            .sources_seen(),
        1
    );
    assert_eq!(
        report_field(&report, "effect_authority"),
        &Value::Bool(false)
    );
    assert_eq!(
        code(run(args(&input, &output))),
        "fusion.cli.checkpoint_publication"
    );
    assert_eq!(fs::read(output).expect("still same checkpoint"), bytes);
}

#[test]
fn resume_needs_independent_pin_and_checkpoint_cannot_be_symlink() {
    assert!(
        run(vec![
            "--sequence".into(),
            "-".into(),
            "--checkpoint-out".into(),
            "new.bin".into(),
            "--checkpoint-in".into(),
            "old.bin".into()
        ])
        .is_err()
    );
    #[cfg(unix)]
    {
        let dir = Scratch::new();
        let (_, bytes) = good(execute(&request(&[], 1), &Calibrations::new(), None, None));
        let target = dir.0.join("real.bin");
        let link = dir.0.join("link.bin");
        fs::write(&target, &bytes).expect("checkpoint");
        std::os::unix::fs::symlink(&target, &link).expect("link");
        assert!(read_checkpoint(&link, ContentDigest::sha256(&bytes)).is_err());
    }
}
