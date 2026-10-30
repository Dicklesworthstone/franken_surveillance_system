#![forbid(unsafe_code)]
//! Real command boundary over explicitly synthetic, source-labelled geometry.
use std::path::PathBuf;
use std::process::Command;
use fss_core::ContentDigest;
use fss_cli::json_input::{parse, Value};
type Test = Result<(), Box<dyn std::error::Error>>;
fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/clock-alignment/moving_feature.json")
}
fn command() -> Result<Command, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(fixture())?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-clock-align"));
    command.arg("--input").arg(fixture()).arg("--input-digest").arg(ContentDigest::sha256(&bytes).to_text());
    Ok(command)
}
#[test]
fn native_command_emits_complete_pinned_scan() -> Test {
    let output = command()?.output()?;
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    let value = parse(std::str::from_utf8(&output.stdout)?)?;
    let report = value.object().and_then(|v| v.get("report")).and_then(Value::object).ok_or("report")?;
    assert_eq!(report.get("hypothesis_count").and_then(Value::integer), Some(3));
    assert_eq!(report.get("hypotheses_complete").and_then(Value::boolean), Some(true));
    assert_eq!(report.get("clock_activated").and_then(Value::boolean), Some(false));
    Ok(())
}
#[test]
fn insufficient_work_is_nonzero_without_a_successful_prefix() -> Test {
    let output = command()?.args(["--work-units", "1"]).output()?;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    parse(std::str::from_utf8(&output.stderr)?)?;
    Ok(())
}
#[test]
fn wrong_independent_digest_refuses_before_analysis() -> Test {
    let output = Command::new(env!("CARGO_BIN_EXE_fss-clock-align"))
        .arg("--input").arg(fixture()).arg("--input-digest")
        .arg(ContentDigest::sha256(b"not the selected input").to_text()).output()?;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    Ok(())
}
