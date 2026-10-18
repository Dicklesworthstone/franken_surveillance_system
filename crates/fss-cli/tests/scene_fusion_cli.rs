#![forbid(unsafe_code)]
//! Invoke the built command over immutable synthetic known-rig files.

#[path = "../src/bin/fss-scene-fuse/fixtures.rs"]
mod fixtures;
use fixtures::{Fixture, POSITION, TestResult, VELOCITY, field, replace};
use fss_cli::json_input::{Value, parse};
use std::process::{Command, Output};

fn run(f: &Fixture, write_report: bool) -> TestResult<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-scene-fuse"));
    command
        .arg("--twin")
        .arg(&f.twin)
        .arg("--rig")
        .arg(&f.rig)
        .arg("--observations")
        .arg(&f.query);
    if write_report {
        command.arg("--report-out").arg(&f.report);
    }
    Ok(command.output()?)
}
fn real(value: &Value) -> TestResult<f64> {
    match value {
        Value::Number(n) => Ok(n.parse()?),
        _ => Err("expected numeric estimate".into()),
    }
}

#[test]
fn executable_unifies_three_staggered_feeds_and_reproduces_report_exactly() -> TestResult {
    let f = Fixture::new(false, &["infer_linear"])?;
    let output = run(&f, true)?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, std::fs::read(&f.report)?);
    let value = parse(std::str::from_utf8(&output.stdout)?)?;
    let estimate = field(&value, &["report", "hypotheses", "0", "estimate"])?;
    for (key, expected) in [("position", POSITION), ("velocity_per_second", VELOCITY)] {
        for (value, expected) in field(estimate, &[key])?
            .array()
            .ok_or("estimate array")?
            .iter()
            .zip(expected)
        {
            assert!((real(value)? - expected).abs() < 1e-8);
        }
    }
    assert_eq!(
        field(estimate, &["views"])?
            .array()
            .ok_or("view array")?
            .len(),
        6
    );
    assert_eq!(output.stdout, run(&f, false)?.stdout);
    assert_eq!(run(&f, true)?.status.code(), Some(2));
    assert_eq!(output.stdout, std::fs::read(&f.report)?);
    Ok(())
}

#[test]
fn executable_retains_duplicate_source_refusal_and_successful_companion() -> TestResult {
    let f = Fixture::new(false, &["infer_linear", "static"])?;
    let mut query = f.read_query()?;
    let original = field(
        &query,
        &["hypotheses", "0", "observations", "0", "evidence_digest"],
    )?
    .clone();
    replace(
        &mut query,
        &["hypotheses", "0", "observations", "1", "evidence_digest"],
        original,
    )?;
    f.write_query(&query)?;
    let output = run(&f, false)?;
    assert_eq!(output.status.code(), Some(3));
    let value = parse(std::str::from_utf8(&output.stdout)?)?;
    assert_eq!(
        field(&value, &["report", "hypotheses", "0", "estimate", "reason"])?.text(),
        Some("duplicate_source_evidence")
    );
    assert_eq!(
        field(&value, &["report", "hypotheses", "1", "outcome"])?.text(),
        Some("solved")
    );
    assert_eq!(
        field(&value, &["report", "counts", "total"])?.integer(),
        Some(2)
    );
    Ok(())
}
