#![forbid(unsafe_code)]
//! Real event publication -> standard AOP-011 with explicitly requested custody verification.

#[path = "../src/custody_review/fixture.rs"]
mod fixture;

use std::fs;
use std::process::{Command, Output};

use fixture::{Fixture, TestResult, inventory};
use fss_cli::json_input::{self, Value};
use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, PrincipalId};
use fss_reference::agent_orient::{OrientLimits, read_deployment};

fn run(f: &Fixture, extra: &[&str]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(["explain", "--json", "--root"]).arg(&f.root)
        .args(["--event-id", fixture::EVENT]).args(extra).output()?)
}
fn field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    value.object().and_then(|fields| fields.get(key)).ok_or_else(|| format!("missing {key}").into())
}
fn path<'a>(mut value: &'a Value, keys: &[&str]) -> TestResult<&'a Value> {
    for key in keys { value = field(value, key)?; }
    Ok(value)
}
fn json(output: &Output) -> TestResult<Value> {
    Ok(json_input::parse(std::str::from_utf8(&output.stdout)?)?)
}
fn success(output: &Output) {
    assert!(output.status.success(), "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}
fn propositions(value: &Value) -> TestResult<&[Value]> {
    path(value, &["payload", "epistemic", "propositions"])?.array().ok_or_else(|| "propositions".into())
}
fn custody_proposition<'a>(value: &'a Value, suffix: &str) -> TestResult<&'a Value> {
    propositions(value)?.iter().find(|p| {
        field(p, "id").ok().and_then(Value::text)
            .is_some_and(|id| id.starts_with("claim:event-custody:") && id.ends_with(suffix))
    }).ok_or_else(|| format!("missing custody {suffix}").into())
}
fn originals(value: &Value) -> TestResult<Vec<Value>> {
    Ok(propositions(value)?.iter().filter(|p| {
        field(p, "id").ok().and_then(Value::text)
            .is_some_and(|id| !id.starts_with("claim:event-support:") && !id.starts_with("claim:event-custody:"))
    }).cloned().collect())
}

#[test]
fn omitted_and_explicitly_disabled_custody_keep_the_original_request_and_response() -> TestResult {
    let f = Fixture::new("default-process")?;
    let plain = run(&f, &[])?;
    success(&plain);
    assert_eq!(plain.stdout, run(&f, &["--custody", "no"])?.stdout);
    let snapshot = read_deployment(&f.root, &OrientLimits::default())?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.cli.explain.request.v1");
    encoder.text(fixture::EVENT);
    PrincipalId::parse(fss_cli::orient_cmd::DEFAULT_PRINCIPAL)?.encode_canonical(&mut encoder);
    snapshot.anchor.encode_canonical(&mut encoder);
    let digest = ContentDigest::sha256(&encoder.finish()).to_text();
    assert_eq!(field(&json(&plain)?, "requestId")?.text(),
        Some(format!("request:explain:{}", digest.trim_start_matches("sha256:")).as_str()));
    assert!(!String::from_utf8(plain.stdout)?.contains("claim:event-custody:"));
    Ok(())
}

#[test]
fn checked_response_keeps_the_universal_contract_worlds_and_physical_judgment() -> TestResult {
    let f = Fixture::new("intact-process")?;
    let before = inventory(&f.root)?;
    let plain_output = run(&f, &[])?;
    success(&plain_output);
    let plain = json(&plain_output)?;
    let checked_output = run(&f, &["--custody", "yes"])?;
    success(&checked_output);
    let checked = json(&checked_output)?;
    assert_eq!(field(&checked, "schema")?.text(), Some("fss.agent_response_envelope.v1"));
    assert_eq!(field(&checked, "operationId")?.text(), Some("AOP-011"));
    assert_eq!(path(&checked, &["payload", "schema"])?.text(), Some("fss.agent_cognitive_envelope.v1"));
    assert_eq!(field(&checked, "epistemicState")?, field(&plain, "epistemicState")?);
    assert_eq!(originals(&checked)?, originals(&plain)?);
    assert_eq!(field(&checked, "affordances")?, field(&plain, "affordances")?);
    assert_eq!(path(&checked, &["payload", "evidenceHandles"])?, path(&plain, &["payload", "evidenceHandles"])?);
    assert_ne!(field(&checked, "requestId")?, field(&plain, "requestId")?);
    assert_ne!(field(&checked, "decisionFingerprint")?, field(&plain, "decisionFingerprint")?);
    assert_eq!(field(&checked, "decisionFingerprint")?, path(&checked, &["payload", "decisionDigest"])?);
    for dimension in ["requested", "consumed", "remaining"] {
        assert_eq!(path(&checked, &["budgets", dimension])?, path(&checked, &["payload", "budget", dimension])?);
    }
    let tokens = path(&checked, &["budgets", "consumed", "tokens"])?.integer().ok_or("tokens")?;
    assert!(tokens <= 1800);
    assert!(tokens > path(&plain, &["budgets", "consumed", "tokens"])?.integer().ok_or("plain tokens")?);
    assert!(field(custody_proposition(&checked, ":publication-closure")?, "statement")?.text()
        .ok_or("statement")?.contains("all_verified=true"));
    let text = std::str::from_utf8(&checked_output.stdout)?;
    assert!(!text.contains(std::str::from_utf8(fixture::SOURCE)?));
    assert!(!text.contains(std::str::from_utf8(fixture::COUNTER)?));
    assert!(!text.contains("custody verification and full graph expansion in the agent payload were not requested"));
    assert_eq!(checked_output.stdout, run(&f, &["--custody=yes"])?.stdout);
    assert_eq!(read_deployment(&f.root, &OrientLimits::default())?.event(&f.event.event_id).ok_or("event")?.event, f.event);
    assert_eq!(inventory(&f.root)?, before);
    Ok(())
}

#[test]
fn a_missing_source_is_reported_without_changing_the_stored_event() -> TestResult {
    let f = Fixture::new("missing-process")?;
    let healthy = run(&f, &["--custody", "yes"])?;
    success(&healthy);
    fs::remove_file(f.object_path(f.source))?;
    let missing = run(&f, &["--custody", "yes"])?;
    success(&missing); // Explanation succeeded; it explicitly reports custody failure.
    let value = json(&missing)?;
    let fault = custody_proposition(&value, &format!(":fault:{}", f.source))?;
    assert!(field(fault, "statement")?.text().ok_or("statement")?.contains("object is missing"));
    assert_ne!(field(&value, "decisionFingerprint")?, field(&json(&healthy)?, "decisionFingerprint")?);
    assert_eq!(read_deployment(&f.root, &OrientLimits::default())?.event(&f.event.event_id).ok_or("event")?.event, f.event);
    Ok(())
}

#[test]
fn counterevidence_corruption_remains_an_individual_custody_fault() -> TestResult {
    let f = Fixture::new("counter-process")?;
    fs::write(f.object_path(f.counter), b"damaged private counterevidence")?;
    let output = run(&f, &["--custody", "yes"])?;
    success(&output);
    let value = json(&output)?;
    let fault = custody_proposition(&value, &format!(":fault:{}", f.counter))?;
    assert!(field(fault, "statement")?.text().ok_or("statement")?.contains("object is corrupt"));
    assert!(!std::str::from_utf8(&output.stdout)?.contains("damaged private counterevidence"));
    Ok(())
}

#[test]
fn a_missing_provenance_manifest_does_not_certify_undiscovered_references() -> TestResult {
    let f = Fixture::new("provenance-process")?;
    fs::remove_file(f.object_path(f.provenance))?;
    let output = run(&f, &["--custody", "yes"])?;
    // Complete context must be returned or explicitly refused; it may not become unchecked success.
    let value = json(&output)?;
    if output.status.success() {
        let unknown = custody_proposition(&value, ":unexamined-references")?;
        assert_eq!(field(unknown, "state")?.text(), Some("unknown"));
        let identities = field(unknown, "evidence")?.array().ok_or("identities")?;
        for digest in [f.source, f.counter] {
            assert!(identities.iter().any(|id| id.text() == Some(digest.to_text().as_str())));
        }
    } else {
        assert_eq!(field(&value, "outcome")?.text(), Some("refused"));
        assert_eq!(field(&value, "payload")?, &Value::Null);
        assert_eq!(field(&value, "operationId")?.text(), Some("AOP-011"));
        assert_eq!(field(&value, "errorId")?.text(), Some(fss_cli::ERR_AGENT_CONTEXT_INCOMPLETE));
    }
    Ok(())
}

#[test]
fn too_many_faults_refuse_instead_of_falling_back_to_a_structural_only_answer() -> TestResult {
    let f = Fixture::with_extra("overflow-process", 33)?;
    for digest in &f.extras { fs::remove_file(f.object_path(*digest))?; }
    let output = run(&f, &["--custody", "yes"])?;
    assert!(!output.status.success());
    let value = json(&output)?;
    assert_eq!(field(&value, "operationId")?.text(), Some("AOP-011"));
    assert_eq!(field(&value, "outcome")?.text(), Some("refused"));
    assert_eq!(field(&value, "errorId")?.text(), Some(fss_cli::ERR_AGENT_CONTEXT_INCOMPLETE));
    assert_eq!(field(&value, "payload")?, &Value::Null);
    Ok(())
}

#[test]
fn invalid_or_duplicate_custody_options_are_refused_before_deployment_io() -> TestResult {
    for (extra, expected) in [
        (vec!["--custody", "true"], fss_cli::ERR_CLI_MALFORMED_VALUE),
        (vec!["--custody", "yes", "--custody", "no"], fss_cli::ERR_CLI_DUPLICATE_OPTION),
        (vec!["--custody"], fss_cli::ERR_CLI_MISSING_VALUE),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_fss"))
            .args(["explain", "--json", "--root", "/never-open-this-root", "--event-id", fixture::EVENT])
            .args(extra).output()?;
        assert!(!output.status.success());
        let diagnostic = format!("{}{}", String::from_utf8(output.stdout)?, String::from_utf8(output.stderr)?);
        assert!(diagnostic.contains(expected), "{diagnostic}");
        assert!(!diagnostic.contains("ERR-DOCTOR-NOT-A-DEPLOYMENT"));
    }
    Ok(())
}
