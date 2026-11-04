#![forbid(unsafe_code)]
//! Real-process restart and failed-publication regressions for source-once fusion checkpoints.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_cli::json_input::{Value, parse};
use fss_cli::json_output::string;
use fss_core::ContentDigest;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> TestResult<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-fusion-sequence-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("temporary directory capacity exhausted".into())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn observation(alias: &str, sensor: &str, source: &str, now: u64, llr: i32) -> String {
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
        "evidence":[{{"id":{alias},"sensor":{sensor},"failure_domains":[{domain}],
        "observability":"observed","calibration":{{"generation":"manual:v1",
        "llr":[{llr},{llr}]}}}}]}},"sources":{{{alias}:{source}}}}}"#,
        alias = string(alias),
        sensor = string(sensor),
        domain = string(&format!("sensor:{sensor}")),
        source = string(source),
    )
}

fn invoke(
    dir: &Path,
    name: &str,
    steps: &[String],
    prior: Option<(&Path, &str)>,
) -> TestResult<(Output, PathBuf)> {
    let input = dir.join(format!("{name}.json"));
    let checkpoint = dir.join(format!("{name}.checkpoint"));
    fs::write(
        &input,
        format!(
            r#"{{"schema":"fss.fusion_sequence.v1","hypothesis":"event:entry",
            "config":{{"alert_threshold_mban":1000,"floor_mban":-10000,
            "ceiling_mban":10000,"min_independent_clusters":2}},
            "source_limit":2,"steps":[{}]}}"#,
            steps.join(",")
        ),
    )?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-fuse"));
    command
        .arg("--sequence")
        .arg(input)
        .arg("--checkpoint-out")
        .arg(&checkpoint);
    if let Some((path, digest)) = prior {
        command
            .arg("--checkpoint-in")
            .arg(path)
            .arg("--checkpoint-digest")
            .arg(digest);
    }
    Ok((command.output()?, checkpoint))
}

fn field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    value
        .object()
        .and_then(|object| object.get(key))
        .ok_or_else(|| format!("missing JSON field {key}").into())
}

fn text_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a str> {
    field(value, key)?
        .text()
        .ok_or_else(|| format!("JSON field {key} is not text").into())
}

fn accepted(output: Output, checkpoint: &Path) -> TestResult<Value> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let report = parse(std::str::from_utf8(&output.stdout)?)?;
    assert_eq!(
        text_field(&report, "schema")?,
        "fss.fusion_sequence_report.v1"
    );
    assert_eq!(field(&report, "effect_authority")?, &Value::Bool(false));
    assert_eq!(
        text_field(&report, "checkpoint_digest")?,
        ContentDigest::sha256(&fs::read(checkpoint)?).to_text()
    );
    Ok(report)
}

fn refused(output: Output, checkpoint: &Path, expected: &str) -> TestResult {
    assert_eq!(output.status.code(), Some(2));
    assert!(
        output.stdout.is_empty(),
        "refusal published a success report"
    );
    let diagnostic = parse(std::str::from_utf8(&output.stderr)?)?;
    assert_eq!(text_field(&diagnostic, "code")?, expected);
    assert_eq!(field(&diagnostic, "effect_started")?, &Value::Bool(false));
    assert!(
        !checkpoint.exists(),
        "refusal published a checkpoint prefix"
    );
    Ok(())
}

#[test]
fn separate_process_resume_matches_uninterrupted_duplicate_reset_sequence() -> TestResult {
    let dir = Scratch::new("restart")?;
    let a = ContentDigest::sha256(b"source:a").to_text();
    let b = ContentDigest::sha256(b"source:b").to_text();
    let initial = vec![observation("a", "cam-a", &a, 1, 600)];
    let continuation = vec![
        observation("renamed", "cam-a", &a, 2, 600),
        r#"{"kind":"reset","reason":{"kind":"operator_reset","reason":"new regime"}}"#.to_owned(),
        observation("b", "cam-b", &b, 3, 600),
    ];
    let (output, first_path) = invoke(&dir.0, "first", &initial, None)?;
    let first = accepted(output, &first_path)?;
    let first_bytes = fs::read(&first_path)?;
    let pin = text_field(&first, "checkpoint_digest")?;
    let (output, resumed_path) =
        invoke(&dir.0, "resumed", &continuation, Some((&first_path, pin)))?;
    let resumed = accepted(output, &resumed_path)?;
    let all: Vec<_> = initial.into_iter().chain(continuation).collect();
    let (output, uninterrupted_path) = invoke(&dir.0, "uninterrupted", &all, None)?;
    let uninterrupted = accepted(output, &uninterrupted_path)?;

    assert_eq!(fs::read(&first_path)?, first_bytes);
    assert_eq!(fs::read(resumed_path)?, fs::read(uninterrupted_path)?);
    assert_eq!(text_field(&resumed, "previous_checkpoint_digest")?, pin);
    assert_eq!(field(&resumed, "sources_seen")?.integer(), Some(2));
    assert_eq!(
        field(&resumed, "sequence_transcript_digest")?,
        field(&uninterrupted, "sequence_transcript_digest")?
    );
    let steps = field(&resumed, "steps")?.array().ok_or("steps array")?;
    let retry = steps.first().ok_or("missing retry step")?;
    let receipt = field(retry, "source_receipt")?;
    let admissions = field(receipt, "admissions")?.array().ok_or("admissions")?;
    assert_eq!(
        text_field(admissions.first().ok_or("retry admission")?, "disposition")?,
        "already_admitted"
    );
    let delta = field(retry, "step_delta_millibans")?
        .array()
        .ok_or("step delta")?;
    assert_eq!(delta.len(), 2);
    assert!(delta.iter().all(|bound| bound.integer() == Some(0)));
    Ok(())
}

#[test]
fn failed_batch_and_malformed_pin_preserve_the_previous_checkpoint() -> TestResult {
    let dir = Scratch::new("refusal")?;
    let a = ContentDigest::sha256(b"source:a").to_text();
    let b = ContentDigest::sha256(b"source:b").to_text();
    let (output, prior_path) = invoke(
        &dir.0,
        "prior",
        &[observation("a", "cam-a", &a, 1, 600)],
        None,
    )?;
    let prior = accepted(output, &prior_path)?;
    let original = fs::read(&prior_path)?;
    let pin = text_field(&prior, "checkpoint_digest")?;
    let steps = [
        observation("b", "cam-b", &b, 2, 600),
        observation("changed", "cam-a", &a, 3, 700),
    ];
    let (output, path) = invoke(&dir.0, "conflict", &steps, Some((&prior_path, pin)))?;
    refused(output, &path, "ERR-FUSION-SOURCE-CONFLICT-001")?;
    assert_eq!(fs::read(&prior_path)?, original);

    let (output, path) = invoke(
        &dir.0,
        "bad-pin",
        &[],
        Some((&prior_path, "sha256:not-a-digest")),
    )?;
    refused(output, &path, "fusion.cli.sequence_invalid")?;
    assert_eq!(fs::read(prior_path)?, original);
    Ok(())
}
