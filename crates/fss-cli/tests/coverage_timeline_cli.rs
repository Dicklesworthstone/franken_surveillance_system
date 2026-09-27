#![forbid(unsafe_code)]
//! Process-boundary contracts for the read-only timeline command.

use std::error::Error;
use std::process::Command;

#[test]
fn timeline_help_is_available_without_a_deployment() -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["graph", "timeline", "--help"])
        .output()?;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout)?;
    assert!(help.contains("fss-event graph timeline"));
    assert!(help.contains("--during START_NS:END_NS"));
    assert!(help.contains("NOT a sensor-failure or no-activity determination"));
    assert!(help.contains("Budgets include all segments and shared scenarios"));
    Ok(())
}

#[test]
fn invalid_timeline_requests_fail_before_reading_and_emit_no_json() -> Result<(), Box<dyn Error>> {
    let cases: &[&[&str]] = &[
        &[],
        &["--during", "2:1"],
        &["--during", "1:2:3"],
        &["--during", "0:1", "--during", "2:3"],
        &["--during", "0:1", "--failure-domain", "power:x=a,a"],
    ];
    for extra in cases {
        let output = Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .args(["graph", "timeline", "--root", "not-opened", "--site", "site:test"])
            .args(*extra)
            .output()?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr)?;
        assert!(error.contains("timeline --help"), "{error}");
        assert!(!error.contains("deployment read failed"), "{error}");
    }
    Ok(())
}

#[test]
fn existing_single_points_help_still_works_and_discovers_timeline() -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["graph", "single-points", "--help"])
        .output()?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    assert!(help.contains("WHOLE window"));
    assert!(help.contains("fss-event graph timeline --help"));
    Ok(())
}
