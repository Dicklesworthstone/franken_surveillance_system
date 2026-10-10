#![forbid(unsafe_code)]
//! Operator history/impact grammar, projection and output failure contracts.

use super::*;
use fss_core::{
    CaptureInterval, DecisionPath, EventEvidence, EventId, EventKind, EventState, EvidenceClass,
    EvidenceEdgeRelation, ProbabilityInterval, TimestampNs,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn args(command: &str, extra: &[&str]) -> Vec<OsString> {
    [command, "--root", "/fss-history-test-no-deployment", "--site", "site:history-test"]
        .into_iter().chain(extra.iter().copied()).map(OsString::from).collect()
}

fn request(command: &str, extra: &[&str]) -> TestResult<HistoryRequest> {
    Ok(parse_history(&args(command, extra)).map_err(|e| format!("{e:?}"))?
        .ok_or("fixture unexpectedly requested help")?)
}

fn support(digest: ContentDigest) -> EventEvidence {
    EventEvidence {
        digest, class: EvidenceClass::Observed, failure_domain: "sensor:fixture".to_owned(),
        supports: true, relation: EvidenceEdgeRelation::Supports,
        capsule_digest: None, identity_digest: None,
    }
}

fn event(id: &str, evidence: Vec<EventEvidence>) -> TestResult<EventHypothesis> {
    let policy = ContentDigest::sha256(b"fixture policy");
    Ok(EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(), event_id: EventId::parse(id)?,
        revision: 1, supersedes: None, state: EventState::Hypothesized,
        kind: EventKind::Unclassified,
        interval: CaptureInterval::new(TimestampNs(0), TimestampNs(1))?,
        uncertainty_reason: Some("unclassified synthetic history".to_owned()),
        zone_ids: vec![], track_ids: vec![],
        probability: ProbabilityInterval { lower: 0.0, upper: 1.0, calibration_generation: None },
        evidence, model_receipts: vec![],
        decision_path: DecisionPath {
            policy_generation: policy, fingerprint: policy, abstained: true,
            abstention_reason: Some("not adjudicated".to_owned()),
        },
    })
}

fn fixture() -> TestResult<(Vec<Vec<EventHypothesis>>, ReadFacts)> {
    let old = event("event:a", vec![])?;
    let mut new = old.clone();
    new.revision = 2;
    new.supersedes = Some(old.revision_digest());
    new.state = EventState::Indeterminate;
    new.evidence = vec![support(ContentDigest::sha256(b"new source"))];
    let dependent = event("event:b", vec![support(old.revision_digest())])?;
    let facts = ReadFacts {
        site: "site:history-test".to_owned(), anchor: LedgerAnchor::genesis("site:history-test"),
        ledger_root: ContentDigest::sha256(b"fixture ledger"), ledger_tail_uncommitted: true,
        effect_tail_uncommitted: false, files_read: 7, bytes_read: 1234,
    };
    Ok((vec![vec![old, new], vec![dependent]], facts))
}

fn report(request: &HistoryRequest, facts: &ReadFacts, chains: &[Vec<EventHypothesis>]) -> TestResult<String> {
    let lineages: Vec<_> = chains.iter().map(Vec::as_slice).collect();
    Ok(report_history(request, facts, &lineages, &|| false).map_err(|e| format!("{e:?}"))?)
}

#[test]
fn grammar_requires_exact_artifact_only_for_impact() -> TestResult {
    let digest = ContentDigest::sha256(b"artifact").to_text();
    assert!(request("analyze-history", &[]).is_ok());
    assert!(request("impact", &["--artifact", &digest]).is_ok());
    assert!(request("impact", &[]).is_err());
    assert!(request("analyze-history", &["--artifact", &digest]).is_err());
    assert!(request("impact", &["--artifact", &digest, "--artifact", &digest]).is_err());
    assert!(request("impact", &["--artifact", "invalid"]).is_err());
    assert!(request("analyze-history", &["--unknown", "value"]).is_err());
    assert!(request("analyze-history", &["--site", "site:duplicate"]).is_err());
    Ok(())
}

#[test]
fn help_and_all_option_bounds_are_checked_before_io() -> TestResult {
    assert!(run(&["analyze-history".into(), "--help".into()]).map_err(|e| format!("{e:?}"))?.contains("expand exact historical event references"));
    assert!(run(&["impact".into(), "--help".into()]).is_ok());
    assert!(run(&["impact".into(), "--help".into(), "--root".into(), "unused".into()]).is_err());
    assert!(parse_history(&vec!["impact".into(); MAX_ARGS + 1]).is_err());
    let mut oversized = args("analyze-history", &[]);
    oversized[2] = "x".repeat(MAX_ARG_BYTES + 1).into();
    assert!(parse_history(&oversized).is_err());
    for pair in [["--max-operations", "0"], ["--max-output-entries", "0"], ["--max-report-bytes", "1023"], ["--timeout-ms", "0"]] {
        assert!(request("analyze-history", &pair).is_err());
    }
    let digest = ContentDigest::sha256(b"pin").to_text();
    assert!(request("impact", &[
        "--artifact", &digest, "--expected-witness", &digest, "--max-operations", "1",
        "--max-output-entries", "1", "--max-report-bytes", "1024", "--timeout-ms", "1",
    ]).is_ok());
    Ok(())
}

#[test]
fn report_retains_old_records_and_current_heads_without_redirecting() -> TestResult {
    let (chains, facts) = fixture()?;
    let text = report(&request("analyze-history", &[])?, &facts, &chains)?;
    for record in chains.iter().flatten() { assert!(text.contains(&record.to_canonical_json())); }
    assert!(text.contains("\"is_current_head\":false"));
    assert!(text.contains("\"catalogue_revisions_validated\":3"));
    assert!(text.contains("\"expanded_revision_count\":3"));
    assert!(text.contains("\"ledger_tail_uncommitted\":true"));
    assert!(text.contains("\"positive_path_from_query_root\":false"));
    assert!(text.contains("derived_cognition_no_effect_authority"));
    assert!(text.ends_with('\n'));
    assert_eq!(text, report(&request("analyze-history", &[])?, &facts, &chains)?);
    Ok(())
}

#[test]
fn impact_uses_the_requested_revision_not_its_successor() -> TestResult {
    let (chains, facts) = fixture()?;
    let artifact = chains[0][0].revision_digest().to_text();
    let text = report(&request("impact", &["--artifact", &artifact])?, &facts, &chains)?;
    assert!(text.contains("artifact_positive_support_impact"));
    assert!(text.contains(&format!("\"query_root\":{}", string(&object_node(chains[0][0].revision_digest())))));
    let expected_heads = array(&[object(&[
        ("event_id", string(chains[1][0].event_id.as_str())),
        ("revision_digest", string(&chains[1][0].revision_digest().to_text())),
    ])]);
    assert!(text.contains(&format!("\"heads_reachable_from_query_root\":{expected_heads}")));
    assert!(text.contains(&chains[0][1].to_canonical_json()));
    assert!(text.contains("reachable does not mean indispensable"));
    Ok(())
}

#[test]
fn exact_witness_pin_is_mode_and_artifact_bound() -> TestResult {
    let (chains, facts) = fixture()?;
    let lineages: Vec<_> = chains.iter().map(Vec::as_slice).collect();
    let projection = EvidenceHistoryProjection::build(&lineages, HistoryLimits::default())?;
    let mut req = request("analyze-history", &[])?;
    let proof = projection.analyze(facts.anchor.clone(), req.base.budget)?.witness;
    req.base.expected = Some(proof.digest());
    assert!(report(&req, &facts, &chains).is_ok());
    req.artifact = Some(chains[0][0].revision_digest());
    assert!(matches!(report_history(&req, &facts, &lineages, &|| false), Err(CommandError::StaleWitness)));
    let impact = projection.support_impact(chains[0][0].revision_digest(), facts.anchor.clone(), req.base.budget)?;
    req.base.expected = Some(impact.witness.digest());
    assert!(report(&req, &facts, &chains).is_ok());
    Ok(())
}

#[test]
fn byte_budget_is_exact_and_no_record_or_warning_is_dropped() -> TestResult {
    let (chains, facts) = fixture()?;
    let mut req = request("analyze-history", &[])?;
    let original = report(&req, &facts, &chains)?;
    req.base.report_limit = original.len();
    assert_eq!(report(&req, &facts, &chains)?, original);
    req.base.report_limit -= 1;
    let lineages: Vec<_> = chains.iter().map(Vec::as_slice).collect();
    assert!(matches!(report_history(&req, &facts, &lineages, &|| false), Err(CommandError::OutputBound)));
    Ok(())
}

#[test]
fn cancellation_and_missing_source_never_create_a_deployment() -> TestResult {
    let req = request("analyze-history", &[])?;
    assert!(!req.base.root.exists());
    assert!(matches!(execute_history(&req, &|| true), Err(CommandError::Stopped)));
    assert!(matches!(execute_history(&req, &|| false), Err(CommandError::Source)));
    assert!(!req.base.root.exists());
    Ok(())
}

#[test]
fn wrong_site_broken_history_and_algorithm_exhaustion_refuse_reports() -> TestResult {
    let (mut chains, mut facts) = fixture()?;
    let req = request("analyze-history", &[])?;
    facts.site = "site:wrong".to_owned();
    assert!(report(&req, &facts, &chains).is_err());
    facts.site = req.base.site.clone();
    let mut small = req.clone();
    small.base.budget = Budget::new(1, 1);
    assert!(report(&small, &facts, &chains).is_err());
    chains[0][1].supersedes = Some(ContentDigest::sha256(b"forged predecessor"));
    assert!(report(&req, &facts, &chains).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn native_root_paths_survive_but_artifact_values_require_utf8() {
    use std::os::unix::ffi::OsStringExt;
    let mut values = args("analyze-history", &[]);
    values[2] = OsString::from_vec(b"/unused/\xff".to_vec());
    assert!(parse_history(&values).is_ok());
    values[0] = "impact".into();
    values.extend([OsString::from("--artifact"), OsString::from_vec(b"sha256:\xff".to_vec())]);
    assert!(parse_history(&values).is_err());
}
