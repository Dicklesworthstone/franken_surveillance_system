#![forbid(unsafe_code)]
//! Historical support references, complete-lineage validation and fail-closed bounds.

mod common;

use common::{Rng, TestResult, anchor};
use fss_core::{
    CaptureInterval, ContentDigest, DecisionPath, EventEvidence, EventHypothesis, EventId,
    EventKind, EventState, EvidenceClass, EvidenceEdgeRelation, ProbabilityInterval, TimestampNs,
};
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::dominators::{self, DominanceDirection};
use fss_graph_algorithms::evidence::{
    EvidenceClaimProjection, EvidenceProjectionLimits, FRONTIER_ROOT, SupportReachability,
    object_node, support_node,
};
use fss_graph_algorithms::evidence_history::{
    EvidenceHistoryProjection, HistoryLimits, MAX_REVISIONS, PROJECTION_ID,
};
use fss_graph_algorithms::oracles;

fn edge(digest: ContentDigest, relation: EvidenceEdgeRelation) -> EventEvidence {
    EventEvidence {
        digest, class: EvidenceClass::Observed, failure_domain: "sensor:fixture".to_owned(),
        supports: relation.required_supports_flag(), relation, capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"fixture identity")),
    }
}

fn event(id: &str, evidence: Vec<EventEvidence>) -> TestResult<EventHypothesis> {
    let policy = ContentDigest::sha256(b"synthetic uncalibrated policy");
    let record = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(), event_id: EventId::parse(id)?,
        revision: 1, supersedes: None, state: EventState::Hypothesized,
        kind: EventKind::Unclassified,
        interval: CaptureInterval::new(TimestampNs(0), TimestampNs(1))?,
        uncertainty_reason: Some("synthetic; no custody or truth asserted".to_owned()),
        zone_ids: vec![], track_ids: vec![],
        probability: ProbabilityInterval { lower: 0.0, upper: 1.0, calibration_generation: None },
        evidence, model_receipts: vec![],
        decision_path: DecisionPath {
            policy_generation: policy, fingerprint: policy, abstained: true,
            abstention_reason: Some("structural test only".to_owned()),
        },
    };
    record.verify()?;
    Ok(record)
}

fn successor(previous: &EventHypothesis, source: ContentDigest) -> TestResult<EventHypothesis> {
    let mut record = previous.clone();
    record.revision += 1;
    record.supersedes = Some(previous.revision_digest());
    record.state = EventState::Indeterminate;
    record.evidence = vec![edge(source, EvidenceEdgeRelation::Supports)];
    record.verify()?;
    Ok(record)
}

fn build(lineages: &[Vec<EventHypothesis>]) -> TestResult<EvidenceHistoryProjection> {
    let refs: Vec<_> = lineages.iter().map(Vec::as_slice).collect();
    Ok(EvidenceHistoryProjection::build(&refs, HistoryLimits::default())?)
}

fn budget(projection: &EvidenceHistoryProjection) -> Budget {
    Budget::registered(&dominators::bound(
        projection.graph().node_count() as u64, projection.graph().arc_count() as u64,
    ))
}

#[test]
fn unsupported_old_claim_is_expanded_not_promoted_to_a_source() -> TestResult {
    let old = event("event:a", vec![])?;
    let new = successor(&old, ContentDigest::sha256(b"later observation"))?;
    let dependent = event("event:b", vec![edge(old.revision_digest(), EvidenceEdgeRelation::Supports)])?;
    let active = EvidenceClaimProjection::build(
        &[new.clone(), dependent.clone()], EvidenceProjectionLimits::default(),
    )?;
    assert!(active.unexpanded_support().contains(&old.revision_digest()));
    let projection = build(&[vec![old.clone(), new.clone()], vec![dependent]])?;
    let analysis = projection.analyze(anchor(), budget(&projection))?;
    assert_eq!(projection.records().len(), 3);
    assert_eq!(projection.heads().get("event:a"), Some(&new.revision_digest()));
    assert!(!projection.unexpanded_support().contains(&old.revision_digest()));
    assert_eq!(analysis.claims[0].reachability, SupportReachability::NoDeclaredSupport);
    assert_eq!(analysis.claims[2].reachability, SupportReachability::Unrooted);
    assert_eq!(analysis.witness.projection_id(), PROJECTION_ID);
    Ok(())
}

#[test]
fn two_historical_branches_expose_the_same_recording_bottleneck() -> TestResult {
    let source = ContentDigest::sha256(b"one recording");
    let a = event("event:a", vec![edge(source, EvidenceEdgeRelation::Supports)])?;
    let mut b = event("event:b", vec![edge(source, EvidenceEdgeRelation::Supports)])?;
    b.evidence[0].failure_domain = "nominally-different-label".to_owned();
    let a2 = successor(&a, ContentDigest::sha256(b"new a"))?;
    let b2 = successor(&b, ContentDigest::sha256(b"new b"))?;
    let target = event("event:target", vec![
        edge(a.revision_digest(), EvidenceEdgeRelation::Supports),
        edge(b.revision_digest(), EvidenceEdgeRelation::Supports),
    ])?;
    let projection = build(&[vec![a, a2], vec![b, b2], vec![target.clone()]])?;
    let result = projection.analyze(anchor(), budget(&projection))?;
    assert!(result.run.output.immediate_dominators.contains(&(
        object_node(target.revision_digest()), object_node(source),
    )));
    Ok(())
}

#[test]
fn supersession_is_not_a_positive_edge_or_a_redirect() -> TestResult {
    let original = ContentDigest::sha256(b"original support");
    let later = ContentDigest::sha256(b"later support");
    let old = event("event:a", vec![edge(original, EvidenceEdgeRelation::Supports)])?;
    let new = successor(&old, later)?;
    let dependent = event("event:b", vec![edge(old.revision_digest(), EvidenceEdgeRelation::Supports)])?;
    let projection = build(&[vec![old.clone(), new.clone()], vec![dependent.clone()]])?;
    let result = projection.analyze(anchor(), budget(&projection))?;
    let chain = result.run.output.chain(&object_node(dependent.revision_digest())).ok_or("unrooted fixture")?;
    assert!(chain.contains(&object_node(old.revision_digest())));
    assert!(chain.contains(&object_node(original)));
    assert!(!chain.contains(&object_node(new.revision_digest())));
    assert!(!chain.contains(&object_node(later)));
    let old_index = projection.graph().require(&object_node(old.revision_digest()))?;
    let new_index = projection.graph().require(&object_node(new.revision_digest()))?;
    assert!(!projection.graph().arcs().iter().any(|arc| arc.tail == old_index && arc.head == new_index));
    Ok(())
}

#[test]
fn historical_counterevidence_is_expanded_but_not_traversed_as_support() -> TestResult {
    let old = event("event:a", vec![])?;
    let new = successor(&old, ContentDigest::sha256(b"new evidence"))?;
    let target = event("event:b", vec![edge(old.revision_digest(), EvidenceEdgeRelation::Contradicts)])?;
    let bytes = target.to_versioned_bytes()?;
    let projection = build(&[vec![old.clone(), new], vec![target.clone()]])?;
    assert!(projection.records().contains(&old));
    assert_eq!(projection.records()[2].to_versioned_bytes()?, bytes);
    assert!(projection.graph().index_of(&support_node(target.revision_digest(), 0)).is_none());
    let analysis = projection.analyze(anchor(), budget(&projection))?;
    assert_eq!(analysis.claims[2].contradictions, 1);
    assert_eq!(analysis.claims[2].supports, 0);
    assert_eq!(analysis.claims[2].reachability, SupportReachability::NoDeclaredSupport);
    Ok(())
}

#[test]
fn unreferenced_ancestors_are_validated_without_bulk_expansion() -> TestResult {
    let old = event("event:a", vec![])?;
    let new = successor(&old, ContentDigest::sha256(b"new source"))?;
    let projection = build(&[vec![old.clone(), new.clone()]])?;
    assert_eq!(projection.catalogue_revisions(), 2);
    assert_eq!(projection.records(), std::slice::from_ref(&new));
    assert_eq!(projection.catalogue_bytes(), old.to_versioned_bytes()?.len() + new.to_versioned_bytes()?.len());
    assert!(projection.graph().index_of(&object_node(old.revision_digest())).is_none());
    let mut invalid_old = old;
    invalid_old.probability.lower = f64::NAN;
    assert!(build(&[vec![invalid_old, new]]).is_err());
    Ok(())
}

#[test]
fn broken_partial_forked_reordered_and_duplicate_lineages_fail_closed() -> TestResult {
    let old = event("event:a", vec![])?;
    let new = successor(&old, ContentDigest::sha256(b"new"))?;
    let last = successor(&new, ContentDigest::sha256(b"last"))?;
    let mut fork = new.clone();
    fork.supersedes = Some(ContentDigest::sha256(b"fabricated predecessor"));
    for lineages in [
        vec![vec![]], vec![vec![new.clone()]], vec![vec![old.clone(), last]],
        vec![vec![new.clone(), old.clone()]], vec![vec![old.clone(), fork]],
        vec![vec![old.clone()], vec![old.clone(), new]],
    ] {
        assert!(build(&lineages).is_err());
    }
    Ok(())
}

#[test]
fn invalid_unused_terminal_successor_is_not_hidden_by_selection() -> TestResult {
    let mut old = event("event:a", vec![edge(ContentDigest::sha256(b"counter"), EvidenceEdgeRelation::Contradicts)])?;
    old.state = EventState::Rejected;
    let new = successor(&old, ContentDigest::sha256(b"later"))?;
    assert!(build(&[vec![old, new]]).is_err());
    Ok(())
}

#[test]
fn exact_catalogue_limits_and_each_one_short_are_enforced() -> TestResult {
    let old = event("event:a", vec![edge(ContentDigest::sha256(b"source"), EvidenceEdgeRelation::Supports)])?;
    let new = successor(&old, ContentDigest::sha256(b"later"))?;
    let chain = vec![old, new];
    let bytes = chain.iter().try_fold(0_usize, |n, r| -> TestResult<usize> { Ok(n + r.to_versioned_bytes()?.len()) })?;
    let exact = HistoryLimits { max_lineages: 1, max_revisions: 2, max_evidence_edges: 2, max_canonical_bytes: bytes };
    let projection = EvidenceHistoryProjection::build(&[&chain], exact)?;
    assert_eq!(projection.catalogue_edges(), 2);
    for limits in [
        HistoryLimits { max_lineages: 0, ..exact },
        HistoryLimits { max_revisions: 1, ..exact },
        HistoryLimits { max_evidence_edges: 1, ..exact },
        HistoryLimits { max_canonical_bytes: bytes - 1, ..exact },
    ] {
        assert!(EvidenceHistoryProjection::build(&[&chain], limits).is_err());
    }
    assert!(EvidenceHistoryProjection::build(&[], HistoryLimits { max_revisions: MAX_REVISIONS + 1, ..exact }).is_err());
    Ok(())
}

#[test]
fn budgets_and_projection_policy_are_part_of_the_exact_contract() -> TestResult {
    let record = event("event:a", vec![edge(ContentDigest::sha256(b"source"), EvidenceEdgeRelation::Supports)])?;
    let projection = build(&[vec![record.clone()]])?;
    let result = projection.analyze(anchor(), budget(&projection))?;
    assert!(projection.analyze(anchor(), Budget::new(result.run.operations - 1, u64::MAX)).is_err());
    assert!(projection.analyze(anchor(), Budget::new(u64::MAX, result.run.output_entries - 1)).is_err());
    let active = EvidenceClaimProjection::build(&[record], EvidenceProjectionLimits::default())?;
    assert_ne!(active.graph().digest(), projection.graph().digest());
    assert_eq!(active.graph().ids(), projection.graph().ids());
    let other = projection.analyze(fss_core::LedgerAnchor::genesis("site:other"), budget(&projection))?;
    assert_eq!(result.run, other.run);
    assert_ne!(result.witness.digest(), other.witness.digest());
    Ok(())
}

#[test]
fn empty_catalogue_is_explicit_and_never_an_absence_proof() -> TestResult {
    let projection = build(&[])?;
    let result = projection.analyze(anchor(), budget(&projection))?;
    assert!(projection.records().is_empty());
    assert!(projection.heads().is_empty());
    assert!(result.claims.is_empty());
    assert_eq!(projection.graph().node_count(), 1);
    Ok(())
}

#[test]
fn seeded_histories_match_independent_removal_and_permutation_oracles() -> TestResult {
    for seed in 0..256 {
        let mut rng = Rng(seed);
        let mut lineages: Vec<Vec<EventHypothesis>> = Vec::new();
        let mut prior = Vec::new();
        for i in 0..1 + rng.below(6) {
            let mut evidence = Vec::new();
            let mut seen = std::collections::BTreeSet::new();
            for j in 0..rng.below(4) {
                let digest = if !prior.is_empty() && rng.chance(600) {
                    prior[rng.below(prior.len())]
                } else {
                    ContentDigest::sha256(&j.to_be_bytes())
                };
                if !seen.insert(digest) { continue; }
                let relation = if rng.chance(250) { EvidenceEdgeRelation::Contradicts } else { EvidenceEdgeRelation::Supports };
                evidence.push(edge(digest, relation));
            }
            let first = event(&format!("event:s{seed}-{i}"), evidence)?;
            let mut second = successor(&first, ContentDigest::sha256(b"later source"))?;
            second.evidence.extend(first.evidence.iter().cloned());
            prior.push(first.revision_digest());
            prior.push(second.revision_digest());
            lineages.push(vec![first, second]);
        }
        let projection = build(&lineages)?;
        let result = projection.analyze(anchor(), budget(&projection))?;
        assert_eq!(result.run.output, oracles::dominators(
            projection.graph(), projection.graph().require(FRONTIER_ROOT)?, DominanceDirection::Dominators,
        ), "seed {seed}");
        rng.shuffle(&mut lineages);
        let shuffled = build(&lineages)?;
        assert_eq!(projection, shuffled, "seed {seed}");
        assert_eq!(result, shuffled.analyze(anchor(), budget(&shuffled))?, "seed {seed}");
    }
    Ok(())
}

#[test]
fn artifact_impact_reaches_current_dependents_through_old_revisions_only() -> TestResult {
    let source = ContentDigest::sha256(b"old source");
    let old = event("event:a", vec![edge(source, EvidenceEdgeRelation::Supports)])?;
    let new = successor(&old, ContentDigest::sha256(b"unrelated new support"))?;
    let target = event("event:b", vec![edge(old.revision_digest(), EvidenceEdgeRelation::Supports)])?;
    let counter = event("event:c", vec![edge(source, EvidenceEdgeRelation::Contradicts)])?;
    let projection = build(&[vec![old.clone(), new], vec![target.clone()], vec![counter]])?;
    let impact = projection.support_impact(source, anchor(), budget(&projection))?;
    assert_eq!(impact.affected_heads, vec![(target.event_id.to_string(), target.revision_digest())]);
    assert_eq!(impact.run.output.root, object_node(source));
    let historical = projection.support_impact(old.revision_digest(), anchor(), budget(&projection))?;
    assert_eq!(impact.affected_heads, historical.affected_heads);
    assert_ne!(impact.run.input_digest, historical.run.input_digest);
    assert_ne!(impact.witness.digest(), historical.witness.digest());
    Ok(())
}

#[test]
fn impact_is_possible_dependency_not_indispensability() -> TestResult {
    let a = ContentDigest::sha256(b"alternative a");
    let b = ContentDigest::sha256(b"alternative b");
    let record = event("event:a", vec![edge(a, EvidenceEdgeRelation::Supports), edge(b, EvidenceEdgeRelation::Supports)])?;
    let projection = build(&[vec![record.clone()]])?;
    let global = projection.analyze(anchor(), budget(&projection))?;
    assert_eq!(global.claims[0].immediate_dominator.as_deref(), Some(FRONTIER_ROOT));
    let impact = projection.support_impact(a, anchor(), budget(&projection))?;
    assert_eq!(impact.affected_heads, vec![(record.event_id.to_string(), record.revision_digest())]);
    assert!(projection.support_impact(a, anchor(), Budget::new(impact.run.operations - 1, u64::MAX)).is_err());
    assert!(projection.support_impact(a, anchor(), Budget::new(u64::MAX, impact.run.output_entries - 1)).is_err());
    assert!(projection.support_impact(ContentDigest::sha256(b"unknown"), anchor(), budget(&projection)).is_err());
    Ok(())
}

#[test]
fn a_current_revision_is_its_own_zero_length_impact_root() -> TestResult {
    let record = event("event:a", vec![])?;
    let projection = build(&[vec![record.clone()]])?;
    let global = projection.analyze(anchor(), budget(&projection))?;
    assert_eq!(global.claims[0].reachability, SupportReachability::NoDeclaredSupport);
    let impact = projection.support_impact(record.revision_digest(), anchor(), budget(&projection))?;
    assert_eq!(impact.affected_heads, vec![(record.event_id.to_string(), record.revision_digest())]);
    // Impact is not an assertion that an unsupported event became grounded or true.
    Ok(())
}
