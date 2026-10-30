#![forbid(unsafe_code)]
//! Real process boundary for affine clock hypotheses, never device qualification.
use std::path::PathBuf;
use std::process::Command;
use fss_core::ContentDigest;
use fss_cli::json_input::{parse, Value};
type Test = Result<(), Box<dyn std::error::Error>>;
fn command() -> Result<Command, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/clock-alignment/drifting_feature.json");
    let pin = ContentDigest::sha256(&std::fs::read(&path)?).to_text();
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-clock-align"));
    command.arg("--input").arg(path).arg("--input-digest").arg(pin);
    Ok(command)
}
#[test]
fn rate_query_uses_the_existing_command_and_preserves_every_trial() -> Test {
    let output = command()?.output()?;
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    let response = parse(std::str::from_utf8(&output.stdout)?)?;
    let report = response.object().and_then(|v| v.get("report")).and_then(Value::object).ok_or("report")?;
    assert_eq!(report.get("schema").and_then(Value::text), Some("fss.clock_drift_report.v1"));
    assert_eq!(report.get("hypothesis_count").and_then(Value::integer), Some(3));
    assert_eq!(report.get("all_times_supported_count").and_then(Value::integer), Some(1));
    assert_eq!(report.get("hypotheses_complete").and_then(Value::boolean), Some(true));
    assert_eq!(report.get("clock_activated").and_then(Value::boolean), Some(false));
    assert_eq!(report.get("independent_clock_validation").and_then(Value::boolean), Some(false));
    Ok(())
}
#[test]
fn work_exhaustion_has_no_successful_json_prefix() -> Test {
    let output = command()?.args(["--work-units", "1"]).output()?;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    parse(std::str::from_utf8(&output.stderr)?)?;
    Ok(())
}
#[test]
fn help_describes_both_input_profiles_without_touching_a_source() -> Test {
    let output = Command::new(env!("CARGO_BIN_EXE_fss-clock-align")).arg("--help").output()?;
    assert_eq!(output.status.code(), Some(0));
    let help = std::str::from_utf8(&output.stdout)?;
    assert!(help.contains("fss.clock_alignment_query.v1"));
    assert!(help.contains("fss.clock_drift_query.v1"));
    Ok(())
}
