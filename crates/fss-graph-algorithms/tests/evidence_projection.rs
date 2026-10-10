#![forbid(unsafe_code)]
//! Active event records -> support incidence -> certified dominators.

mod common;

use common::{Rng, TestResult, anchor};
use fss_core::{
    CaptureInterval, ContentDigest, DecisionPath, EventEvidence, EventHypothesis, EventId,
    EventKind, EventState, EvidenceClass, EvidenceEdgeRelation, LedgerAnchor, ProbabilityInterval,
    TimestampNs,
};
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::dominators::{self, DominanceDirection};
use fss_graph_algorithms::evidence::{
    EvidenceClaimProjection, EvidenceProjectionError, EvidenceProjectionLimits, FRONTIER_ROOT,
    MAX_EVENTS, SupportReachability, object_node,
};
use fss_graph_algorithms::{GraphError, oracles};

fn edge(digest: ContentDigest, relation: EvidenceEdgeRelation) -> EventEvidence {
    EventEvidence {
        digest,
        class: EvidenceClass::Observed,
        failure_domain: "sensor:reference-only".to_owned(),
        supports: relation.required_supports_flag(),
        relation,
        capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"declared identity")),
    }
}

fn event(name: &str, evidence: Vec<EventEvidence>) -> TestResult<EventHypothesis> {
    let digest = ContentDigest::sha256(b"test policy, not calibrated");
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(),
        event_id: EventId::parse(name)?,
        revision: 1,
        supersedes: None,
        state: EventState::Hypothesized,
        kind: EventKind::Unclassified,
        interval: CaptureInterval::new(TimestampNs(0), TimestampNs(1))?,
        uncertainty_reason: Some("synthetic reference, no source custody asserted".to_owned()),
        zone_ids: vec![],
        track_ids: vec![],
        probability: ProbabilityInterval {
            lower: 0.0,
            upper: 1.0,
            calibration_generation: None,
        },
        evidence,
        model_receipts: vec![],
        decision_path: DecisionPath {
            policy_generation: digest,
            fingerprint: digest,
            abstained: true,
            abstention_reason: Some("not an adjudication".to_owned()),
        },
    };
    event.verify()?;
    Ok(event)
}

fn build(events: &[EventHypothesis]) -> TestResult<EvidenceClaimProjection> {
    Ok(EvidenceClaimProjection::build(events, EvidenceProjectionLimits::default())?)
}

fn budget(projection: &EvidenceClaimProjection) -> Budget {
    Budget::registered(&dominators::bound(
        projection.graph().node_count() as u64,
        projection.graph().arc_count() as u64,
    ))
}

#[test]
fn a_shared_artifact_dominates_two_nominally_distinct_branches() -> TestResult {
    let source = ContentDigest::sha256(b"one recording");
    let a = event("event:a", vec![edge(source, EvidenceEdgeRelation::Supports)])?;
    let mut b = event("event:b", vec![edge(source, EvidenceEdgeRelation::Supports)])?;
    b.evidence[0].failure_domain = "different-label-not-independent".to_owned();
    let c = event("event:c", vec![
        edge(a.revision_digest(), EvidenceEdgeRelation::Supports),
        edge(b.revision_digest(), EvidenceEdgeRelation::Supports),
    ])?;
    let target = object_node(c.revision_digest());
    let projection = build(&[a, b, c])?;
    let result = projection.analyze(anchor(), budget(&projection))?;
    assert_eq!(projection.unexpanded_support(), &[source]);
    assert!(result.run.output.immediate_dominators.contains(&(target, object_node(source))));
    assert_eq!(result.claims[2].supports, 2); // Edges, NOT independent sources.
    assert_eq!(result.claims[2].immediate_dominator, Some(object_node(source)));
    Ok(())
}

#[test]
fn alternate_objects_remove_the_shared_artifact_bottleneck() -> TestResult {
    let a = ContentDigest::sha256(b"source a");
    let b = ContentDigest::sha256(b"source b");
    let event = event("event:alternatives", vec![
        edge(a, EvidenceEdgeRelation::Supports),
        edge(b, EvidenceEdgeRelation::Supports),
    ])?;
    let projection = build(&[event])?;
    let result = projection.analyze(anchor(), budget(&projection))?;
    assert_eq!(projection.unexpanded_support().len(), 2);
    assert_eq!(result.claims[0].immediate_dominator.as_deref(), Some(FRONTIER_ROOT));
    // This establishes path diversity only, not sensor or failure-domain independence.
    Ok(())
}

#[test]
fn all_nine_non_support_relations_are_retained_but_never_traversed() -> TestResult {
    let relations = [
        EvidenceEdgeRelation::DerivedFrom, EvidenceEdgeRelation::Contradicts,
        EvidenceEdgeRelation::Invalidates, EvidenceEdgeRelation::Supersedes,
        EvidenceEdgeRelation::ObservedAfter, EvidenceEdgeRelation::RequiredBy,
        EvidenceEdgeRelation::Explains, EvidenceEdgeRelation::SensorTamper,
        EvidenceEdgeRelation::SensorIntegrityRestoration,
    ];
    let evidence = relations.iter().enumerate().map(|(i, relation)| {
        edge(ContentDigest::sha256(&i.to_be_bytes()), *relation)
    }).collect();
    let original = event("event:counterevidence", evidence)?;
    let bytes = original.to_versioned_bytes()?;
    let projection = build(&[original])?;
    let result = projection.analyze(anchor(), budget(&projection))?;
    assert_eq!(projection.graph().arc_count(), 0);
    assert_eq!(projection.unexpanded_evidence().len(), 9);
    assert!(projection.unexpanded_support().is_empty());
    assert_eq!(result.claims[0].reachability, SupportReachability::NoDeclaredSupport);
    assert_eq!((result.claims[0].contradictions, result.claims[0].neutral), (1, 8));
    assert_eq!(projection.events()[0].to_versioned_bytes()?, bytes);
    Ok(())
}

#[test]
fn a_support_reference_to_an_ungrounded_claim_remains_unrooted() -> TestResult {
    let ungrounded = event("event:a", vec![])?;
    let dependent = event("event:b", vec![edge(
        ungrounded.revision_digest(), EvidenceEdgeRelation::Supports,
    )])?;
    let projection = build(&[ungrounded, dependent])?;
    let result = projection.analyze(anchor(), budget(&projection))?;
    assert_eq!(result.claims[0].reachability, SupportReachability::NoDeclaredSupport);
    assert_eq!(result.claims[1].reachability, SupportReachability::Unrooted);
    assert!(projection.unexpanded_support().is_empty());
    assert!(result.claims.iter().all(|claim| claim.immediate_dominator.is_none()));
    Ok(())
}

#[test]
fn historical_reference_is_not_redirected_to_a_new_revision() -> TestResult {
    let old = event("event:a", vec![])?;
    let mut new = old.clone();
    new.revision = 2;
    new.supersedes = Some(old.revision_digest());
    new.state = EventState::Indeterminate;
    new.evidence.push(edge(ContentDigest::sha256(b"later contradiction"), EvidenceEdgeRelation::Contradicts));
    let dependent = event("event:b", vec![edge(old.revision_digest(), EvidenceEdgeRelation::Supports)])?;
    let projection = build(&[new, dependent])?;
    assert_eq!(projection.unexpanded_support(), &[old.revision_digest()]);
    assert_eq!(projection.events()[0].revision, 2);
    let result = projection.analyze(anchor(), budget(&projection))?;
    assert_eq!(result.claims[0].reachability, SupportReachability::NoDeclaredSupport);
    assert_eq!(result.claims[1].reachability, SupportReachability::RootedInUnexpandedReference);
    Ok(())
}

#[test]
fn counterevidence_attribution_and_uncertainty_bind_the_input() -> TestResult {
    let original = event("event:a", vec![edge(ContentDigest::sha256(b"counter"), EvidenceEdgeRelation::Contradicts)])?;
    let base = build(std::slice::from_ref(&original))?;
    let mut changed = original.clone();
    changed.evidence[0].failure_domain = "different declaration".to_owned();
    assert_ne!(base.graph().digest(), build(&[changed])?.graph().digest());
    let mut changed = original;
    changed.uncertainty_reason = Some("different uncertainty".to_owned());
    assert_ne!(base.graph().digest(), build(&[changed])?.graph().digest());
    Ok(())
}

#[test]
fn duplicate_events_and_malformed_support_flags_fail_closed() -> TestResult {
    let valid = event("event:a", vec![edge(ContentDigest::sha256(b"source"), EvidenceEdgeRelation::Supports)])?;
    assert!(build(&[valid.clone(), valid.clone()]).is_err());
    let mut invalid = valid;
    invalid.evidence[0].supports = false;
    assert!(matches!(
        EvidenceClaimProjection::build(&[invalid], EvidenceProjectionLimits::default()),
        Err(EvidenceProjectionError::Event(_))
    ));
    Ok(())
}

#[test]
fn compiler_and_algorithm_budget_boundaries_have_no_partial_success() -> TestResult {
    let event = event("event:a", vec![edge(ContentDigest::sha256(b"source"), EvidenceEdgeRelation::Supports)])?;
    let bytes = event.to_versioned_bytes()?.len();
    let exact = EvidenceProjectionLimits { max_events: 1, max_evidence_edges: 1, max_canonical_bytes: bytes };
    let projection = EvidenceClaimProjection::build(std::slice::from_ref(&event), exact)?;
    assert_eq!(projection.canonical_bytes(), bytes);
    assert_eq!(projection.evidence_edges(), 1);
    for limits in [
        EvidenceProjectionLimits { max_events: 0, ..exact },
        EvidenceProjectionLimits { max_evidence_edges: 0, ..exact },
        EvidenceProjectionLimits { max_canonical_bytes: bytes - 1, ..exact },
    ] {
        assert!(matches!(
            EvidenceClaimProjection::build(std::slice::from_ref(&event), limits),
            Err(EvidenceProjectionError::Graph(GraphError::BudgetExhausted { .. }))
        ));
    }
    assert!(EvidenceClaimProjection::build(&[], EvidenceProjectionLimits { max_events: MAX_EVENTS + 1, ..exact }).is_err());
    let result = projection.analyze(anchor(), budget(&projection))?;
    assert!(projection.analyze(anchor(), Budget::new(result.run.operations - 1, u64::MAX)).is_err());
    assert!(projection.analyze(anchor(), Budget::new(u64::MAX, result.run.output_entries - 1)).is_err());
    let other_anchor = LedgerAnchor::genesis("site:other-snapshot");
    let other = projection.analyze(other_anchor.clone(), budget(&projection))?;
    assert_eq!(result.run, other.run);
    assert_eq!(other.witness.anchor(), &other_anchor);
    assert_ne!(result.witness, other.witness);
    Ok(())
}

#[test]
fn empty_input_is_explicitly_empty_not_an_absence_certificate() -> TestResult {
    let projection = build(&[])?;
    let result = projection.analyze(anchor(), budget(&projection))?;
    assert!(result.claims.is_empty());
    assert!(projection.events().is_empty());
    assert_eq!(projection.graph().node_count(), 1); // Only the synthetic root.
    Ok(())
}

#[test]
fn seeded_record_projections_match_independent_removal_and_permutation_oracles() -> TestResult {
    for seed in 0..512 {
        let mut rng = Rng(seed);
        let mut events: Vec<EventHypothesis> = Vec::new();
        for i in 0..1 + rng.below(8) {
            let mut evidence = Vec::new();
            for j in 0..rng.below(4) {
                let source = if !events.is_empty() && rng.chance(500) {
                    events[rng.below(events.len())].revision_digest()
                } else {
                    ContentDigest::sha256(&j.to_be_bytes())
                };
                evidence.push(edge(source, EvidenceEdgeRelation::Supports));
            }
            if rng.chance(500) {
                evidence.push(edge(ContentDigest::sha256(b"retained counter"), EvidenceEdgeRelation::Contradicts));
            }
            events.push(event(&format!("event:seed-{seed}-{i}"), evidence)?);
        }
        let projection = build(&events)?;
        let result = projection.analyze(anchor(), budget(&projection))?;
        assert_eq!(result.run.output, oracles::dominators(
            projection.graph(), projection.graph().require(FRONTIER_ROOT)?, DominanceDirection::Dominators,
        ));
        rng.shuffle(&mut events);
        let reordered = build(&events)?;
        assert_eq!(projection, reordered, "seed {seed}");
        assert_eq!(result, reordered.analyze(anchor(), budget(&reordered))?, "seed {seed}");
    }
    Ok(())
}
