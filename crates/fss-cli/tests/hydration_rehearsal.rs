#![forbid(unsafe_code)]

use std::error::Error;
use std::process::{Command, Output};

fn run(args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_fss-hydration-rehearsal"))
        .args(args)
        .output()
}

#[test]
fn catalog_scenarios_are_deterministic_and_flag_compatible() -> Result<(), Box<dyn Error>> {
    for (scenario, outcome, level) in [
        ("success", "ok", Some("H2")),
        ("budget-fallback", "ok", Some("H1")),
        ("privacy-denied", "denied", None),
        ("expired", "typed_unavailable", None),
        ("h4-denied", "denied", None),
        ("h4-qualified", "ok", Some("H4")),
    ] {
        let first = run(&["--scenario", scenario])?;
        let second = run(&[scenario])?;
        assert!(first.status.success(), "{scenario}: {:?}", first.stderr);
        assert!(second.status.success(), "{scenario}: {:?}", second.stderr);
        assert!(first.stderr.is_empty());
        assert!(second.stderr.is_empty());
        assert_eq!(first.stdout, second.stdout);
        let transcript = String::from_utf8(first.stdout)?;
        assert_eq!(transcript.lines().count(), 1);
        assert!(transcript.contains("\"schema\":\"fss.hydration_rehearsal.v1\""));
        assert!(transcript.contains(&format!("\"outcome\":\"{outcome}\"")));
        assert!(transcript.contains(&format!("\"scenario\":\"{scenario}\"")));
        if let Some(level) = level {
            assert!(transcript.contains(&format!("\"deliveredLevel\":\"{level}\"")));
        } else {
            assert!(transcript.contains("\"artifactDigest\":null"));
            assert!(transcript.contains("\"continuationDigest\":null"));
        }
    }
    Ok(())
}

#[test]
fn downgrade_and_denial_remain_explicit() -> Result<(), Box<dyn Error>> {
    let output = run(&["budget-fallback"])?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("\"requestedLevel\":\"H3\""));
    assert!(text.contains("\"completeness\":\"partial\""));
    for (scenario, code) in [
        ("privacy-denied", "hydration_privacy_denied"),
        ("h4-denied", "hydration_laboratory_grant_required"),
    ] {
        let output = run(&[scenario])?;
        assert!(output.status.success());
        assert!(String::from_utf8(output.stdout)?.contains(code));
    }
    Ok(())
}

#[test]
fn all_preserves_canonical_scenario_order() -> Result<(), Box<dyn Error>> {
    let output = run(&["all"])?;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let transcript = String::from_utf8(output.stdout)?;
    let lines: Vec<_> = transcript.lines().collect();
    assert_eq!(lines.len(), 6);
    for (line, scenario) in lines.iter().zip([
        "success", "budget-fallback", "privacy-denied", "expired", "h4-denied", "h4-qualified",
    ]) {
        assert!(line.contains(&format!("\"scenario\":\"{scenario}\"")));
    }
    Ok(())
}

#[test]
fn invalid_arguments_fail_without_partial_stdout() -> Result<(), Box<dyn Error>> {
    for args in [
        vec!["not-a-scenario"],
        vec!["--scenario"],
        vec!["--scenario", "success", "extra"],
        vec!["success", "extra"],
    ] {
        let output = run(&args)?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
    Ok(())
}
