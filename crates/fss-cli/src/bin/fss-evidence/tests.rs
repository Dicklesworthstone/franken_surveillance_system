#![forbid(unsafe_code)]
//! Operator grammar, record preservation, budget refusals and exact anchor pins.

use super::*;
use fss_core::{
    CaptureInterval, DecisionPath, EventEvidence, EventId, EventKind, EventState,
    EvidenceClass, EvidenceEdgeRelation, ProbabilityInterval, TimestampNs,
};

type TestResult = Result<(), String>;

fn args(extra: &[&str]) -> Vec<OsString> {
    ["analyze", "--root", "/unused/private-root", "--site", "site:test"]
        .into_iter().chain(extra.iter().copied()).map(OsString::from).collect()
}

fn request() -> Result<Request, String> {
    parse(&args(&[])).map_err(|e| format!("{e:?}"))?
        .ok_or_else(|| "fixture unexpectedly requested help".to_owned())
}

fn facts() -> ReadFacts {
    ReadFacts {
        site: "site:test".to_owned(),
        anchor: LedgerAnchor::genesis("site:test"),
        ledger_root: ContentDigest::sha256(b"reference ledger"),
        ledger_tail_uncommitted: false,
        effect_tail_uncommitted: false,
        files_read: 3,
        bytes_read: 123,
    }
}

fn event() -> Result<EventHypothesis, String> {
    let policy = ContentDigest::sha256(b"reference policy");
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(),
        event_id: EventId::parse("event:operator-test").map_err(|e| e.to_string())?,
        revision: 1,
        supersedes: None,
        state: EventState::Hypothesized,
        kind: EventKind::Unclassified,
        interval: CaptureInterval::point(TimestampNs(42)),
        uncertainty_reason: Some("unconfirmed \"reference\"\nnot an observation".to_owned()),
        zone_ids: vec!["zone:reference".to_owned()],
        track_ids: vec![],
        probability: ProbabilityInterval {
            lower: 0.0,
            upper: 1.0,
            calibration_generation: None,
        },
        evidence: vec![EventEvidence {
            digest: ContentDigest::sha256(b"retained counterevidence"),
            class: EvidenceClass::Observed,
            failure_domain: "sensor:reference".to_owned(),
            supports: false,
            relation: EvidenceEdgeRelation::Contradicts,
            capsule_digest: None,
            identity_digest: Some(ContentDigest::sha256(b"identity")),
        }],
        model_receipts: vec![ContentDigest::sha256(b"receipt reference")],
        decision_path: DecisionPath {
            policy_generation: policy,
            fingerprint: policy,
            abstained: true,
            abstention_reason: Some("reference diagnostic only".to_owned()),
        },
    };
    event.verify().map_err(|e| e.to_string())?;
    Ok(event)
}

fn report(request: &Request, facts: &ReadFacts, events: &[EventHypothesis]) -> Result<String, String> {
    report_for_records(request, facts, events, &|| false).map_err(|e| format!("{e:?}"))
}

#[test]
fn parser_requires_explicit_site_root_and_unambiguous_grammar() -> TestResult {
    assert_eq!(request()?.site, "site:test");
    for input in [
        vec![], vec!["analyze"], vec!["analyze", "--root", "/unused"],
        vec!["analyze", "--site", "site:test"], vec!["other"],
        vec!["analyze", "--root=/unused", "--site", "site:test"],
    ] {
        let input = input.into_iter().map(OsString::from).collect::<Vec<_>>();
        assert!(parse(&input).is_err());
    }
    Ok(())
}

#[test]
fn invalid_options_duplicates_and_bounds_are_refused() {
    for extra in [
        vec!["--site", "site:test"], vec!["--unknown", "private"],
        vec!["--max-operations", "0"], vec!["--max-operations", "50000001"],
        vec!["--max-operations", "18446744073709551616"],
        vec!["--max-output-entries", "65537"], vec!["--timeout-ms", "0"],
        vec!["--max-report-bytes", "1023"], vec!["--max-report-bytes", "2097153"],
        vec!["--max-operations", "+2"], vec!["--expected-witness", "not-a-digest"],
        vec!["--max-operations", "--site"],
    ] {
        assert!(parse(&args(&extra)).is_err(), "case {extra:?}");
    }
}

#[test]
fn help_and_argument_bounds_do_not_open_any_deployment() {
    assert!(matches!(parse(&["--help".into()]), Ok(None)));
    assert!(matches!(parse(&["analyze".into(), "--help".into()]), Ok(None)));
    assert!(parse(&["--help".into(), "--root".into(), "/unused".into()]).is_err());
    assert!(parse(&vec!["x".into(); MAX_ARGS + 1]).is_err());
    let mut values = args(&[]);
    values[2] = "x".repeat(MAX_ARG_BYTES + 1).into();
    assert!(parse(&values).is_err());
}

#[cfg(unix)]
#[test]
fn native_root_bytes_are_preserved_but_site_must_be_utf8() {
    use std::os::unix::ffi::OsStringExt;
    let mut values = args(&[]);
    values[2] = OsString::from_vec(b"/unused/\xff".to_vec());
    assert!(parse(&values).is_ok());
    values[4] = OsString::from_vec(b"site:\xff".to_vec());
    assert!(parse(&values).is_err());
}

#[test]
fn cancellation_precedes_filesystem_access() -> TestResult {
    assert!(matches!(execute(&request()?, &|| true), Err(CommandError::Stopped)));
    Ok(())
}

#[test]
fn complete_canonical_record_counterevidence_and_warnings_survive_rendering() -> TestResult {
    let original = event()?;
    let bytes = original.to_versioned_bytes().map_err(|e| e.to_string())?;
    let result = report(&request()?, &facts(), std::slice::from_ref(&original))?;
    assert!(result.contains(&format!("\"record\":{}", original.to_canonical_json())));
    assert!(result.contains("no_declared_support"));
    assert!(result.contains("\"contradictions\":1"));
    assert!(result.contains("derived_cognition_no_effect_authority"));
    assert!(result.contains("not custody, independent corroboration, truth, absence"));
    assert!(result.contains("\"source_bytes_read\":123"));
    assert!(!result.contains("/unused/private-root"));
    assert_eq!(bytes, original.to_versioned_bytes().map_err(|e| e.to_string())?);
    assert_eq!(result, report(&request()?, &facts(), &[original])?);
    Ok(())
}

#[test]
fn exact_report_budget_succeeds_and_one_byte_less_refuses() -> TestResult {
    let events = vec![event()?];
    let mut request = request()?;
    let baseline = report(&request, &facts(), &events)?;
    request.report_limit = baseline.len();
    assert_eq!(baseline, report(&request, &facts(), &events)?);
    request.report_limit -= 1;
    assert!(matches!(report_for_records(&request, &facts(), &events, &|| false),
        Err(CommandError::OutputBound)));
    Ok(())
}

#[test]
fn witness_pin_accepts_exact_replay_and_refuses_changed_anchor_or_record() -> TestResult {
    let events = vec![event()?];
    let facts = facts();
    let mut request = request()?;
    let projection = EvidenceClaimProjection::build(&events, EvidenceProjectionLimits::default())
        .map_err(|e| e.to_string())?;
    request.expected = Some(projection.analyze(facts.anchor.clone(), request.budget)
        .map_err(|e| e.to_string())?.witness.digest());
    assert!(report(&request, &facts, &events).is_ok());
    let mut changed_facts = facts.clone();
    changed_facts.site = "site:other".to_owned();
    changed_facts.anchor = LedgerAnchor::genesis("site:other");
    let mut moved_request = request.clone();
    moved_request.site = changed_facts.site.clone();
    assert!(matches!(report_for_records(&moved_request, &changed_facts, &events, &|| false),
        Err(CommandError::StaleWitness)));
    let mut changed = events;
    changed[0].uncertainty_reason = Some("changed uncertainty".to_owned());
    assert!(matches!(report_for_records(&request, &facts, &changed, &|| false),
        Err(CommandError::StaleWitness)));
    Ok(())
}

#[test]
fn wrong_site_and_algorithm_budget_exhaustion_have_no_report() -> TestResult {
    let mut wrong = facts();
    wrong.site = "site:other".to_owned();
    assert!(matches!(report_for_records(&request()?, &wrong, &[], &|| false),
        Err(CommandError::SiteMismatch)));
    let mut request = request()?;
    request.budget = Budget::new(0, 0);
    assert!(matches!(report_for_records(&request, &facts(), &[event()?], &|| false),
        Err(CommandError::Projection(_))));
    Ok(())
}

#[test]
fn uncommitted_tails_stay_visible_but_are_not_event_inputs() -> TestResult {
    let mut facts = facts();
    facts.ledger_tail_uncommitted = true;
    facts.effect_tail_uncommitted = true;
    let report = report(&request()?, &facts, &[])?;
    assert!(report.contains("\"records\":[]"));
    assert!(report.contains("\"ledger_tail_uncommitted\":true"));
    assert!(report.contains("\"effect_tail_uncommitted\":true"));
    assert!(report.contains("latest_retained_revision_of_every_event"));
    Ok(())
}

#[test]
fn cancellation_after_analysis_still_suppresses_the_complete_report() -> TestResult {
    use std::cell::Cell;
    let calls = Cell::new(0);
    let check = || { calls.set(calls.get() + 1); calls.get() >= 3 };
    assert!(matches!(report_for_records(&request()?, &facts(), &[event()?], &check),
        Err(CommandError::Stopped)));
    Ok(())
}

#[test]
fn array_bounds_include_delimiters_and_do_not_truncate_rows() {
    assert_eq!(bounded_array(["123".to_owned()].into_iter(), 5).ok(), Some("[123]".to_owned()));
    assert!(bounded_array(["123".to_owned()].into_iter(), 4).is_err());
    assert!(bounded_array(["1".to_owned(), "2".to_owned()].into_iter(), 4).is_err());
}

struct Interrupted;
impl Write for Interrupted {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> { Err(io::ErrorKind::Interrupted.into()) }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

struct ShortWrites(Vec<u8>);
impl Write for ShortWrites {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = bytes.len().min(2);
        self.0.extend_from_slice(&bytes[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

#[test]
fn interrupted_output_is_bounded_and_short_writes_preserve_exact_bytes() -> TestResult {
    assert!(emit(&mut Interrupted, b"report").is_err());
    let mut writer = ShortWrites(Vec::new());
    emit(&mut writer, b"complete report\n").map_err(|e| e.to_string())?;
    assert_eq!(writer.0, b"complete report\n");
    Ok(())
}
