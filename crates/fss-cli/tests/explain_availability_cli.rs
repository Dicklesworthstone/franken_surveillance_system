#![forbid(unsafe_code)]
//! Real event publication -> checked AOP-011 support availability, without new authority.

#[path = "../src/custody_review/fixture.rs"]
mod fixture;

use std::fs;
use std::process::{Command, Output};

use fixture::{Fixture, TestResult, inventory};
use fss_cli::json_input::{self, Value};
use fss_core::ContentDigest;
use fss_reference::agent_orient::{OrientLimits, read_deployment};

fn run(f: &Fixture, options: &[&str]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(["explain", "--json", "--root"]).arg(&f.root)
        .args(["--event-id", fixture::EVENT]).args(options).output()?)
}
fn field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    value.object().and_then(|object| object.get(key)).ok_or_else(|| format!("missing {key}").into())
}
fn path<'a>(mut value: &'a Value, keys: &[&str]) -> TestResult<&'a Value> {
    for key in keys { value = field(value, key)?; }
    Ok(value)
}
fn json(output: &Output) -> TestResult<Value> {
    Ok(json_input::parse(std::str::from_utf8(&output.stdout)?)?)
}
fn successful(output: &Output) -> TestResult<Value> {
    assert!(output.status.success(), "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    json(output)
}
fn propositions(value: &Value) -> TestResult<&[Value]> {
    path(value, &["payload", "epistemic", "propositions"])?.array().ok_or_else(|| "propositions".into())
}
fn statement<'a>(value: &'a Value, prefix: &str, suffix: &str) -> TestResult<&'a str> {
    let row = propositions(value)?.iter().find(|row| {
        field(row, "id").ok().and_then(Value::text).is_some_and(|id| id.starts_with(prefix) && id.ends_with(suffix))
    }).ok_or("missing proposition")?;
    field(row, "statement")?.text().ok_or_else(|| "statement".into())
}
fn available(value: &Value, state: &str) -> TestResult {
    assert!(statement(value, "claim:event-support:", ":availability")?
        .starts_with(&format!("Declared support availability: {state}.")));
    Ok(())
}
fn originals(value: &Value) -> TestResult<Vec<Value>> {
    Ok(propositions(value)?.iter().filter(|row| {
        field(row, "id").ok().and_then(Value::text).is_some_and(|id| {
            !id.starts_with("claim:event-support:") && !id.starts_with("claim:event-custody:")
        })
    }).cloned().collect())
}
fn still_original(f: &Fixture, original: &Value, checked: &Value) -> TestResult {
    assert_eq!(originals(original)?, originals(checked)?);
    assert_eq!(field(original, "epistemicState")?, field(checked, "epistemicState")?);
    assert_eq!(field(original, "affordances")?, field(checked, "affordances")?);
    assert_eq!(path(original, &["payload", "evidenceHandles"])?, path(checked, &["payload", "evidenceHandles"])?);
    let snapshot = read_deployment(&f.root, &OrientLimits::default())?;
    assert_eq!(snapshot.event(&f.event.event_id).ok_or("event")?.event, f.event);
    assert!(snapshot.operations.is_empty());
    Ok(())
}

#[test]
fn verified_reference_paths_use_standard_envelopes_and_default_stays_unchecked() -> TestResult {
    let f = Fixture::new("availability-process-intact")?;
    let before = inventory(&f.root)?;
    let plain_output = run(&f, &[])?;
    let plain = successful(&plain_output)?;
    assert_eq!(plain_output.stdout, run(&f, &["--custody", "no"])?.stdout);
    assert!(statement(&plain, "claim:event-support:", ":availability").is_err());
    let output = run(&f, &["--custody", "yes"])?;
    let checked = successful(&output)?;
    available(&checked, "verified_reference_path")?;
    assert_eq!(field(&checked, "schema")?.text(), Some("fss.agent_response_envelope.v1"));
    assert_eq!(field(&checked, "operationId")?.text(), Some("AOP-011"));
    assert_eq!(path(&checked, &["payload", "schema"])?.text(), Some("fss.agent_cognitive_envelope.v1"));
    assert_eq!(field(&checked, "decisionFingerprint")?, path(&checked, &["payload", "decisionDigest"])?);
    for dimension in ["requested", "consumed", "remaining"] {
        assert_eq!(path(&checked, &["budgets", dimension])?, path(&checked, &["payload", "budget", dimension])?);
    }
    assert!(path(&checked, &["budgets", "consumed", "tokens"])?.integer().ok_or("tokens")? <= 1800);
    let text = std::str::from_utf8(&output.stdout)?;
    assert!(text.contains("shared remaining="));
    assert!(!text.contains(std::str::from_utf8(fixture::SOURCE)?));
    assert!(!text.contains(std::str::from_utf8(fixture::COUNTER)?));
    still_original(&f, &plain, &checked)?;
    assert_eq!(output.stdout, run(&f, &["--custody=yes"])?.stdout);
    assert_eq!(inventory(&f.root)?, before);
    Ok(())
}

#[test]
fn loss_of_the_only_support_changes_the_path_result_not_event_truth() -> TestResult {
    let f = Fixture::new("availability-process-loss")?;
    let plain = successful(&run(&f, &[])?)?;
    let healthy = successful(&run(&f, &["--custody", "yes"])?)?;
    let before_anchor = read_deployment(&f.root, &OrientLimits::default())?.anchor;
    fs::remove_file(f.object_path(f.source))?;
    let before = inventory(&f.root)?;
    let checked = successful(&run(&f, &["--custody", "yes"])?)?;
    available(&checked, "no_unblocked_reference_path")?;
    assert!(statement(&checked, "claim:event-custody:", &format!(":fault:{}", f.source))?.contains("object is missing"));
    assert_ne!(field(&healthy, "decisionFingerprint")?, field(&checked, "decisionFingerprint")?);
    assert_eq!(field(&healthy, "requestId")?, field(&checked, "requestId")?);
    assert_eq!(read_deployment(&f.root, &OrientLimits::default())?.anchor, before_anchor);
    still_original(&f, &plain, &checked)?;
    assert_eq!(inventory(&f.root)?, before);
    Ok(())
}

#[test]
fn surviving_support_does_not_erase_corrupt_counterevidence() -> TestResult {
    let f = Fixture::new("availability-process-counter")?;
    let plain = successful(&run(&f, &[])?)?;
    let healthy = successful(&run(&f, &["--custody", "yes"])?)?;
    fs::write(f.object_path(f.counter), b"corrupt private counterevidence")?;
    let output = run(&f, &["--custody", "yes"])?;
    let checked = successful(&output)?;
    available(&checked, "verified_reference_path")?;
    assert!(statement(&checked, "claim:event-custody:", &format!(":fault:{}", f.counter))?.contains("object is corrupt"));
    assert!(statement(&checked, "claim:event-custody:", ":publication-closure")?.contains("all_verified=false"));
    assert_ne!(field(&healthy, "decisionFingerprint")?, field(&checked, "decisionFingerprint")?);
    assert!(!std::str::from_utf8(&output.stdout)?.contains("corrupt private counterevidence"));
    still_original(&f, &plain, &checked)?;
    Ok(())
}

#[test]
fn undiscovered_descendants_are_unchecked_or_completely_refused_never_verified() -> TestResult {
    let f = Fixture::new("availability-process-descendants")?;
    fs::remove_file(f.object_path(f.provenance))?;
    let output = run(&f, &["--custody", "yes"])?;
    let value = json(&output)?;
    if output.status.success() {
        available(&value, "unchecked_reference_path")?;
        assert!(statement(&value, "claim:event-custody:", ":publication-closure")?.contains("manifest_expansion_complete=false"));
        assert!(statement(&value, "claim:event-custody:", ":unexamined-references").is_ok());
    } else {
        // Registered complete-context refusal is allowed, but never an unrelated runtime failure.
        assert_eq!(field(&value, "outcome")?.text(), Some("refused"));
        assert_eq!(field(&value, "errorId")?.text(), Some(fss_cli::ERR_AGENT_CONTEXT_INCOMPLETE));
        assert_eq!(field(&value, "operationId")?.text(), Some("AOP-011"));
        assert_eq!(field(&value, "payload")?, &Value::Null);
    }
    assert!(ContentDigest::parse(field(&value, "decisionFingerprint")?.text().ok_or("decision")?).is_ok());
    Ok(())
}
