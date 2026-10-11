#![forbid(unsafe_code)]
//! Exact availability-conditioned support, with an independent record-level oracle.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    CaptureInterval, ContentDigest, DecisionPath, EventEvidence, EventHypothesis, EventId,
    EventKind, EventState, EvidenceClass, EvidenceEdgeRelation, LedgerAnchor,
    ProbabilityInterval, TimestampNs,
};
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::evidence_brief::availability::{
    AvailabilityObservation, AvailableSupport, EvidenceAvailabilityAnalysis,
    MAX_AVAILABILITY_OBSERVATIONS, ObjectAvailability, POSSIBLE_PROJECTION_ID,
    VERIFIED_PROJECTION_ID, analyze_current_availability,
};
use fss_graph_algorithms::evidence_history::{EvidenceHistoryProjection, HistoryLimits};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const BUDGET: Budget = Budget::new(2_000_000, 65_536);

fn digest(text: &str) -> ContentDigest { ContentDigest::sha256(text.as_bytes()) }
fn edge(source: ContentDigest, relation: EvidenceEdgeRelation) -> EventEvidence {
    EventEvidence {
        digest: source, class: EvidenceClass::Observed, failure_domain: "sensor:fixture".to_owned(),
        supports: relation.required_supports_flag(), relation, capsule_digest: None, identity_digest: None,
    }
}
fn event(id: &str, sources: &[ContentDigest]) -> TestResult<EventHypothesis> {
    let policy = digest("uncalibrated fixture policy");
    let record = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(), event_id: EventId::parse(id)?,
        revision: 1, supersedes: None, state: EventState::Hypothesized, kind: EventKind::Unclassified,
        interval: CaptureInterval::new(TimestampNs(0), TimestampNs(1))?,
        uncertainty_reason: Some("synthetic paths; no physical truth asserted".to_owned()),
        zone_ids: vec![], track_ids: vec![],
        probability: ProbabilityInterval { lower: 0.0, upper: 1.0, calibration_generation: None },
        evidence: sources.iter().map(|source| edge(*source, EvidenceEdgeRelation::Supports)).collect(),
        model_receipts: vec![],
        decision_path: DecisionPath {
            policy_generation: policy, fingerprint: policy, abstained: true,
            abstention_reason: Some("structural analysis only".to_owned()),
        },
    };
    record.verify()?;
    Ok(record)
}
fn build(lineages: &[Vec<EventHypothesis>]) -> TestResult<EvidenceHistoryProjection> {
    let refs: Vec<_> = lineages.iter().map(Vec::as_slice).collect();
    Ok(EvidenceHistoryProjection::build(&refs, HistoryLimits::default())?)
}
fn observe(digest: ContentDigest, availability: ObjectAvailability) -> AvailabilityObservation {
    AvailabilityObservation { digest, availability }
}
fn analyze(p: &EvidenceHistoryProjection, obs: &[AvailabilityObservation]) -> TestResult<EvidenceAvailabilityAnalysis> {
    Ok(analyze_current_availability(p, "event:target", obs, LedgerAnchor::genesis("site:availability"), BUDGET)?)
}

#[test]
fn unchecked_verified_and_unavailable_sources_are_distinct() -> TestResult {
    let source = digest("source");
    let p = build(&[vec![event("event:target", &[source])?]])?;
    let unknown = analyze(&p, &[])?;
    let verified = analyze(&p, &[observe(source, ObjectAvailability::Verified)])?;
    let unavailable = analyze(&p, &[observe(source, ObjectAvailability::Unavailable)])?;
    assert_eq!(unknown.support, AvailableSupport::UncheckedReferencePath);
    assert_eq!(verified.support, AvailableSupport::VerifiedReferencePath);
    assert_eq!(unavailable.support, AvailableSupport::NoUnblockedReferencePath);
    assert_eq!(unknown.unchecked_frontier_references, 1);
    assert_eq!(unavailable.unchecked_frontier_references, 0);
    assert_eq!(unknown.possible_witness.digest(), verified.possible_witness.digest());
    assert_ne!(unknown.verified_witness.digest(), verified.verified_witness.digest());
    assert_ne!(unknown.possible_witness.digest(), unavailable.possible_witness.digest());
    assert_eq!(verified.possible_witness.projection_id(), POSSIBLE_PROJECTION_ID);
    assert_eq!(verified.verified_witness.projection_id(), VERIFIED_PROJECTION_ID);
    Ok(())
}

#[test]
fn simultaneous_losses_exhaust_alternatives_without_rewriting_the_event() -> TestResult {
    let a = digest("source-a");
    let b = digest("source-b");
    let target = event("event:target", &[a, b])?;
    let original = target.to_versioned_bytes()?;
    let p = build(&[vec![target]])?;
    assert_eq!(analyze(&p, &[observe(a, ObjectAvailability::Unavailable), observe(b, ObjectAvailability::Verified)])?.support,
        AvailableSupport::VerifiedReferencePath);
    assert_eq!(analyze(&p, &[observe(a, ObjectAvailability::Unavailable)])?.support,
        AvailableSupport::UncheckedReferencePath);
    assert_eq!(analyze(&p, &[observe(a, ObjectAvailability::Unavailable), observe(b, ObjectAvailability::Unavailable)])?.support,
        AvailableSupport::NoUnblockedReferencePath);
    assert_eq!(p.records()[0].to_versioned_bytes()?, original);
    Ok(())
}

#[test]
fn one_shared_source_blocks_both_transitive_branches() -> TestResult {
    let source = digest("shared recording");
    let a = event("event:a", &[source])?;
    let mut b = event("event:b", &[source])?;
    b.evidence[0].failure_domain = "different-label-not-independent".to_owned();
    let target = event("event:target", &[a.revision_digest(), b.revision_digest()])?;
    let p = build(&[vec![a], vec![b], vec![target]])?;
    assert_eq!(analyze(&p, &[observe(source, ObjectAvailability::Unavailable)])?.support,
        AvailableSupport::NoUnblockedReferencePath);
    assert_eq!(analyze(&p, &[observe(source, ObjectAvailability::Verified)])?.support,
        AvailableSupport::VerifiedReferencePath);
    Ok(())
}

#[test]
fn unchecked_or_unavailable_intermediate_revisions_restrict_paths() -> TestResult {
    let source = digest("source");
    let a = event("event:a", &[source])?;
    let target = event("event:target", &[a.revision_digest()])?;
    let revision = a.revision_digest();
    let p = build(&[vec![a], vec![target]])?;
    let verified = observe(source, ObjectAvailability::Verified);
    assert_eq!(analyze(&p, &[verified, observe(revision, ObjectAvailability::Unchecked)])?.support,
        AvailableSupport::UncheckedReferencePath);
    assert_eq!(analyze(&p, &[verified, observe(revision, ObjectAvailability::Unavailable)])?.support,
        AvailableSupport::NoUnblockedReferencePath);
    Ok(())
}

#[test]
fn verified_unsupported_metadata_is_never_promoted_to_a_frontier() -> TestResult {
    let old = event("event:a", &[])?;
    let target = event("event:target", &[old.revision_digest()])?;
    let obs = [observe(old.revision_digest(), ObjectAvailability::Verified)];
    let p = build(&[vec![old], vec![target]])?;
    assert_eq!(analyze(&p, &obs)?.support, AvailableSupport::NoUnblockedReferencePath);
    let no_support = build(&[vec![event("event:target", &[])?]])?;
    assert_eq!(analyze(&no_support, &[])?.support, AvailableSupport::NoDeclaredSupport);
    Ok(())
}

#[test]
fn newer_evidence_does_not_redirect_historical_support() -> TestResult {
    let old_source = digest("old source");
    let new_source = digest("new source");
    let old = event("event:a", &[old_source])?;
    let mut new = old.clone();
    new.revision = 2;
    new.supersedes = Some(old.revision_digest());
    new.state = EventState::Indeterminate;
    new.evidence = vec![edge(new_source, EvidenceEdgeRelation::Supports)];
    let target = event("event:target", &[old.revision_digest()])?;
    let p = build(&[vec![old, new], vec![target]])?;
    assert_eq!(analyze(&p, &[observe(old_source, ObjectAvailability::Unavailable), observe(new_source, ObjectAvailability::Verified)])?.support,
        AvailableSupport::NoUnblockedReferencePath);
    Ok(())
}

#[test]
fn counterevidence_and_unmapped_faults_are_not_positive_support() -> TestResult {
    let source = digest("source");
    let counter = digest("counterevidence");
    let mut target = event("event:target", &[source])?;
    target.evidence.push(edge(counter, EvidenceEdgeRelation::Contradicts));
    let p = build(&[vec![target]])?;
    let clean = analyze(&p, &[observe(source, ObjectAvailability::Verified)])?;
    let faults = analyze(&p, &[observe(source, ObjectAvailability::Verified),
        observe(counter, ObjectAvailability::Unavailable), observe(digest("opaque manifest"), ObjectAvailability::Unavailable)])?;
    assert_eq!(faults.support, AvailableSupport::VerifiedReferencePath);
    assert_eq!(faults.mapped_observations, 1);
    assert_eq!(faults.outside_graph_observations, 2);
    assert_eq!(clean.possible_witness, faults.possible_witness);
    assert_eq!(clean.verified_witness, faults.verified_witness);
    Ok(())
}

#[test]
fn input_order_is_irrelevant_but_duplicate_or_oversized_observations_fail() -> TestResult {
    let a = digest("a");
    let b = digest("b");
    let p = build(&[vec![event("event:target", &[a, b])?]])?;
    let a = observe(a, ObjectAvailability::Verified);
    let b = observe(b, ObjectAvailability::Unchecked);
    assert_eq!(analyze(&p, &[a, b])?, analyze(&p, &[b, a])?);
    assert!(analyze(&p, &[a, a]).is_err());
    assert!(analyze(&p, &[a, observe(a.digest, ObjectAvailability::Unavailable)]).is_err());
    assert!(analyze(&p, &vec![a; MAX_AVAILABILITY_OBSERVATIONS + 1]).is_err());
    assert!(analyze_current_availability(&p, "event:unknown", &[], LedgerAnchor::genesis("site:availability"), BUDGET).is_err());
    Ok(())
}

#[test]
fn both_runs_share_exact_operation_and_output_allowances() -> TestResult {
    let source = digest("source");
    let p = build(&[vec![event("event:target", &[source])?]])?;
    let obs = [observe(source, ObjectAvailability::Verified)];
    let baseline = analyze(&p, &obs)?;
    let run = |budget| analyze_current_availability(&p, "event:target", &obs,
        LedgerAnchor::genesis("site:availability"), budget);
    assert_eq!(run(Budget::new(baseline.graph_operations, baseline.graph_output_entries))?, baseline);
    assert!(run(Budget::new(baseline.graph_operations - 1, baseline.graph_output_entries)).is_err());
    assert!(run(Budget::new(baseline.graph_operations, baseline.graph_output_entries - 1)).is_err());
    assert!(run(Budget::new(0, 0)).is_err());
    Ok(())
}

#[test]
fn witnesses_bind_the_authority_anchor() -> TestResult {
    let p = build(&[vec![event("event:target", &[digest("source")])?]])?;
    let first = analyze(&p, &[])?;
    let second = analyze_current_availability(&p, "event:target", &[],
        LedgerAnchor::genesis("site:another"), BUDGET)?;
    assert_ne!(first.possible_witness.digest(), second.possible_witness.digest());
    assert_ne!(first.verified_witness.digest(), second.verified_witness.digest());
    Ok(())
}

// Record-level least fixed point, not a traversal of either production graph.
fn oracle(p: &EvidenceHistoryProjection, target: ContentDigest, obs: &[AvailabilityObservation], strict: bool) -> bool {
    let records: BTreeMap<_, _> = p.records().iter().map(|r| (r.revision_digest(), r)).collect();
    let states: BTreeMap<_, _> = obs.iter().map(|o| (o.digest, o.availability)).collect();
    let allowed = |d: ContentDigest, default: ObjectAvailability| {
        let state = states.get(&d).copied().unwrap_or(default);
        state != ObjectAvailability::Unavailable && (!strict || state == ObjectAvailability::Verified)
    };
    let mut reachable = BTreeSet::new();
    for record in records.values() {
        for edge in record.evidence.iter().filter(|edge| edge.counts_as_support()) {
            if !records.contains_key(&edge.digest) && allowed(edge.digest, ObjectAvailability::Unchecked) {
                reachable.insert(edge.digest);
            }
        }
    }
    loop {
        let old_len = reachable.len();
        for (digest, record) in &records {
            if allowed(*digest, ObjectAvailability::Verified)
                && record.evidence.iter().any(|e| e.counts_as_support() && reachable.contains(&e.digest)) {
                reachable.insert(*digest);
            }
        }
        if old_len == reachable.len() { break; }
    }
    reachable.contains(&target)
}

#[test]
fn seeded_histories_match_independent_fixed_point_and_verified_paths_are_a_subset() -> TestResult {
    let mut seed = 0x42_5f_5353_u64;
    let mut random = || { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; seed };
    for _ in 0..256 {
        let sources: Vec<_> = (0..4).map(|n| digest(&format!("source:{n}"))).collect();
        let mut candidates = sources.clone();
        let mut lineages = Vec::new();
        for n in 0..6 {
            let selected: Vec<_> = candidates.iter().filter(|_| random() % 4 == 0).copied().collect();
            let mut record = event(&format!("event:{n}"), &selected)?;
            record.evidence.push(edge(sources[(random() % 4) as usize], EvidenceEdgeRelation::Contradicts));
            candidates.push(record.revision_digest());
            lineages.push(vec![record]);
        }
        let p = build(&lineages)?;
        let obs: Vec<_> = candidates.iter().filter_map(|d| match random() % 4 {
            0 => None,
            1 => Some(observe(*d, ObjectAvailability::Verified)),
            2 => Some(observe(*d, ObjectAvailability::Unchecked)),
            _ => Some(observe(*d, ObjectAvailability::Unavailable)),
        }).collect();
        for (id, target) in p.heads() {
            let output = analyze_current_availability(&p, id, &obs,
                LedgerAnchor::genesis("site:availability"), BUDGET)?;
            let possible = oracle(&p, *target, &obs, false);
            let verified = oracle(&p, *target, &obs, true);
            assert!(!verified || possible);
            let record = p.records().iter().find(|r| r.revision_digest() == *target).ok_or("missing record")?;
            let expected = if !record.evidence.iter().any(|e| e.counts_as_support()) {
                AvailableSupport::NoDeclaredSupport
            } else if verified { AvailableSupport::VerifiedReferencePath }
            else if possible { AvailableSupport::UncheckedReferencePath }
            else { AvailableSupport::NoUnblockedReferencePath };
            assert_eq!(output.support, expected);
        }
    }
    Ok(())
}
