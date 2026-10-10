#![forbid(unsafe_code)]
//! Current-head briefs: common bottlenecks, ungrounded alternatives and old support.

mod common;

use std::collections::BTreeSet;

use common::{Rng, TestResult, anchor};
use fss_core::{CaptureInterval, ContentDigest, DecisionPath, EventEvidence, EventHypothesis,
    EventId, EventKind, EventState, EvidenceClass, EvidenceEdgeRelation, ProbabilityInterval,
    TimestampNs};
use fss_graph_algorithms::GraphError;
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::evidence::{EvidenceProjectionError, FRONTIER_ROOT,
    SupportReachability, object_node};
use fss_graph_algorithms::evidence_brief::{MAX_BRIEF_ENTRIES, explain_current_support};
use fss_graph_algorithms::evidence_history::{EvidenceHistoryProjection, HistoryLimits};
use fss_graph_algorithms::weighted::WeightedGraph;

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

fn corrected(old: &EventHypothesis) -> TestResult<EventHypothesis> {
    let mut next = old.clone();
    next.revision += 1;
    next.supersedes = Some(old.revision_digest());
    next.state = EventState::Indeterminate;
    next.evidence = vec![edge(ContentDigest::sha256(b"later counterevidence"),
        EvidenceEdgeRelation::Contradicts)];
    next.verify()?;
    Ok(next)
}

fn build(lineages: &[Vec<EventHypothesis>]) -> TestResult<EvidenceHistoryProjection> {
    let lineages: Vec<_> = lineages.iter().map(Vec::as_slice).collect();
    Ok(EvidenceHistoryProjection::build(&lineages, HistoryLimits::default())?)
}

fn ample() -> Budget { Budget::new(u64::MAX, u64::MAX) }

#[test]
fn one_recording_remains_a_bottleneck_across_two_nominal_domains() -> TestResult {
    let source = ContentDigest::sha256(b"one recording");
    let a = event("event:a", vec![edge(source, EvidenceEdgeRelation::Supports)])?;
    let mut b = event("event:b", vec![edge(source, EvidenceEdgeRelation::Supports)])?;
    b.evidence[0].failure_domain = "different-domain-label".to_owned();
    let target = event("event:target", vec![
        edge(a.revision_digest(), EvidenceEdgeRelation::Supports),
        edge(b.revision_digest(), EvidenceEdgeRelation::Supports),
    ])?;
    let projection = build(&[vec![a], vec![b], vec![target]])?;
    let brief = explain_current_support(&projection, "event:target", anchor(), ample(), 2)?;
    assert_eq!(brief.direct_support_edges, 2);
    assert_eq!(brief.unexpanded_support, vec![source]);
    assert_eq!(brief.bottleneck_objects, vec![source]);
    assert!(brief.unsupported_revisions.is_empty());
    assert_eq!(brief.brief_entries, 2);
    Ok(())
}

#[test]
fn a_rooted_alternative_does_not_hide_the_unsupported_branch() -> TestResult {
    let old = event("event:a", vec![])?;
    let target = event("event:target", vec![
        edge(old.revision_digest(), EvidenceEdgeRelation::Supports),
        edge(ContentDigest::sha256(b"other support"), EvidenceEdgeRelation::Supports),
    ])?;
    let projection = build(&[vec![old.clone()], vec![target]])?;
    let brief = explain_current_support(&projection, "event:target", anchor(), ample(), 16)?;
    assert_eq!(brief.reachability, SupportReachability::RootedInUnexpandedReference);
    assert_eq!(brief.unsupported_revisions.len(), 1);
    assert_eq!(brief.unsupported_revisions[0].digest, old.revision_digest());
    assert_eq!(brief.unexpanded_support.len(), 1);
    Ok(())
}

#[test]
fn superseded_support_keeps_the_adverse_current_revision_separate() -> TestResult {
    let source = ContentDigest::sha256(b"old recording");
    let old = event("event:a", vec![edge(source, EvidenceEdgeRelation::Supports)])?;
    let current = corrected(&old)?;
    let target = event("event:target", vec![edge(old.revision_digest(), EvidenceEdgeRelation::Supports)])?;
    let projection = build(&[vec![old.clone(), current.clone()], vec![target]])?;
    let brief = explain_current_support(&projection, "event:target", anchor(), ample(), 16)?;
    assert_eq!(brief.bottleneck_objects, vec![source, old.revision_digest()]);
    assert_eq!(brief.superseded_support.len(), 1);
    let correction = &brief.superseded_support[0];
    assert_eq!(correction.referenced.digest, old.revision_digest());
    assert_eq!(correction.current.digest, current.revision_digest());
    assert_eq!(correction.current.state, EventState::Indeterminate);
    assert_eq!(brief.unexpanded_support, vec![source]);
    assert_eq!(brief.brief_entries, 5); // one source, two bottlenecks, a two-revision pair
    Ok(())
}

#[test]
fn transitive_old_support_is_visible_even_when_it_is_not_indispensable() -> TestResult {
    let old = event("event:a", vec![edge(ContentDigest::sha256(b"a"), EvidenceEdgeRelation::Supports)])?;
    let current = corrected(&old)?;
    let b = event("event:b", vec![edge(old.revision_digest(), EvidenceEdgeRelation::Supports)])?;
    let target = event("event:target", vec![
        edge(b.revision_digest(), EvidenceEdgeRelation::Supports),
        edge(ContentDigest::sha256(b"independent-looking alternative"), EvidenceEdgeRelation::Supports),
    ])?;
    let projection = build(&[vec![old.clone(), current], vec![b], vec![target]])?;
    let brief = explain_current_support(&projection, "event:target", anchor(), ample(), 16)?;
    assert!(brief.bottleneck_objects.is_empty());
    assert_eq!(brief.unexpanded_support.len(), 2);
    assert_eq!(brief.superseded_support[0].referenced.digest, old.revision_digest());
    Ok(())
}

#[test]
fn no_path_does_not_masquerade_as_redundancy_or_absence() -> TestResult {
    let unsupported = event("event:a", vec![])?;
    let target = event("event:target", vec![edge(unsupported.revision_digest(), EvidenceEdgeRelation::Supports)])?;
    let projection = build(&[vec![unsupported], vec![target]])?;
    let brief = explain_current_support(&projection, "event:target", anchor(), ample(), 16)?;
    assert_eq!(brief.reachability, SupportReachability::Unrooted);
    assert!(brief.bottleneck_objects.is_empty());
    assert!(brief.unexpanded_support.is_empty());
    assert_eq!(brief.unsupported_revisions.len(), 1);
    let root_brief = explain_current_support(&projection, "event:a", anchor(), ample(), 16)?;
    assert_eq!(root_brief.reachability, SupportReachability::NoDeclaredSupport);
    assert_eq!(root_brief.unsupported_revisions[0], root_brief.target);
    Ok(())
}

#[test]
fn counterevidence_and_tamper_are_counted_not_traversed() -> TestResult {
    let source = ContentDigest::sha256(b"counter or tamper");
    let target = event("event:target", vec![
        edge(source, EvidenceEdgeRelation::Contradicts),
        edge(source, EvidenceEdgeRelation::SensorTamper),
        edge(source, EvidenceEdgeRelation::RequiredBy),
    ])?;
    let bytes = target.to_versioned_bytes()?;
    let projection = build(&[vec![target]])?;
    let brief = explain_current_support(&projection, "event:target", anchor(), ample(), 16)?;
    assert_eq!((brief.direct_support_edges, brief.direct_contradictions, brief.direct_other_relations), (0, 1, 2));
    assert!(brief.unexpanded_support.is_empty());
    assert_eq!(projection.records()[0].to_versioned_bytes()?, bytes);
    Ok(())
}

#[test]
fn two_algorithm_runs_share_operations_and_output_allowances() -> TestResult {
    let target = event("event:target", vec![edge(ContentDigest::sha256(b"source"), EvidenceEdgeRelation::Supports)])?;
    let projection = build(&[vec![target]])?;
    let result = explain_current_support(&projection, "event:target", anchor(), ample(), 16)?;
    let exact = Budget::new(result.graph_operations, result.graph_output_entries);
    assert_eq!(result, explain_current_support(&projection, "event:target", anchor(), exact, result.brief_entries)?);
    for budget in [
        Budget::new(result.graph_operations - 1, result.graph_output_entries),
        Budget::new(result.graph_operations, result.graph_output_entries - 1),
    ] {
        assert!(matches!(explain_current_support(&projection, "event:target", anchor(), budget, 16),
            Err(EvidenceProjectionError::Graph(GraphError::BudgetExhausted { .. }))));
    }
    assert_ne!(result.rooted_witness.input_digest(), result.ancestry_witness.input_digest());
    assert_eq!(result.receipt.subject(), result.target.digest);
    assert!(result.receipt.evidence_subgraph().contains(&result.rooted_witness.digest()));
    assert!(result.receipt.evidence_subgraph().contains(&result.ancestry_witness.digest()));
    Ok(())
}

#[test]
fn complete_brief_admission_never_slices_a_dependency_or_correction_pair() -> TestResult {
    let old = event("event:a", vec![edge(ContentDigest::sha256(b"source"), EvidenceEdgeRelation::Supports)])?;
    let current = corrected(&old)?;
    let target = event("event:target", vec![edge(old.revision_digest(), EvidenceEdgeRelation::Supports)])?;
    let projection = build(&[vec![old, current], vec![target]])?;
    let result = explain_current_support(&projection, "event:target", anchor(), ample(), 16)?;
    for limit in 0..result.brief_entries {
        assert!(matches!(explain_current_support(&projection, "event:target", anchor(), ample(), limit),
            Err(EvidenceProjectionError::Graph(GraphError::BudgetExhausted {
                dimension: "evidence_brief_entries", ..
            }))));
    }
    assert!(explain_current_support(&projection, "event:target", anchor(), ample(), MAX_BRIEF_ENTRIES + 1).is_err());
    Ok(())
}

#[test]
fn unknown_heads_fail_and_receipts_bind_the_exact_target_and_anchor() -> TestResult {
    let source = ContentDigest::sha256(b"shared");
    let a = event("event:a", vec![edge(source, EvidenceEdgeRelation::Supports)])?;
    let b = event("event:b", vec![edge(source, EvidenceEdgeRelation::Supports)])?;
    let projection = build(&[vec![a], vec![b]])?;
    assert!(explain_current_support(&projection, "event:missing", anchor(), ample(), 16).is_err());
    let a = explain_current_support(&projection, "event:a", anchor(), ample(), 16)?;
    let b = explain_current_support(&projection, "event:b", anchor(), ample(), 16)?;
    assert_ne!(a.receipt.receipt_digest(), b.receipt.receipt_digest());
    let changed_anchor = fss_core::LedgerAnchor::genesis("site:other");
    let changed = explain_current_support(&projection, "event:a", changed_anchor, ample(), 16)?;
    assert_ne!(a.receipt.receipt_digest(), changed.receipt.receipt_digest());
    Ok(())
}

// Independent repeated arc-scan traversal, intentionally not the production DFS/idom algorithm.
fn reachable(graph: &WeightedGraph, root: u32, removed: Option<u32>, reverse: bool) -> BTreeSet<u32> {
    let mut seen = BTreeSet::new();
    if removed == Some(root) { return seen; }
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if !seen.insert(node) { continue; }
        for arc in graph.arcs() {
            let (from, to) = if reverse { (arc.head, arc.tail) } else { (arc.tail, arc.head) };
            if from == node && removed != Some(to) && !seen.contains(&to) { pending.push(to); }
        }
    }
    seen
}

#[test]
fn seeded_briefs_match_removal_and_reverse_reachability_oracles() -> TestResult {
    for seed in 0..256 {
        let mut rng = Rng(seed);
        let mut lineages: Vec<Vec<EventHypothesis>> = Vec::new();
        for i in 0..2 + rng.below(6) {
            let mut evidence = Vec::new();
            for j in 0..rng.below(4) {
                let digest = if !lineages.is_empty() && rng.chance(600) {
                    lineages[rng.below(lineages.len())][0].revision_digest()
                } else { ContentDigest::sha256(&j.to_be_bytes()) };
                evidence.push(edge(digest, EvidenceEdgeRelation::Supports));
            }
            let first = event(&format!("event:{i}"), evidence)?;
            let mut lineage = vec![first];
            if rng.chance(500) { lineage.push(corrected(&lineage[0])?); }
            lineages.push(lineage);
        }
        let projection = build(&lineages)?;
        for (id, digest) in projection.heads() {
            let result = explain_current_support(&projection, id, anchor(), ample(), MAX_BRIEF_ENTRIES)?;
            let graph = projection.graph();
            let target = graph.require(&object_node(*digest))?;
            let frontier = graph.require(FRONTIER_ROOT)?;
            let ancestors = reachable(graph, target, None, true);
            let rooted = reachable(graph, frontier, None, false).contains(&target);
            let expected: BTreeSet<_> = (0..graph.node_count() as u32).filter(|&node| {
                node != target && rooted && graph.id(node).starts_with("object:")
                    && !reachable(graph, frontier, Some(node), false).contains(&target)
            }).map(|node| ContentDigest::parse(&graph.id(node)[7..])).collect::<Result<_, _>>()?;
            assert_eq!(result.bottleneck_objects.iter().copied().collect::<BTreeSet<_>>(), expected, "seed {seed}");
            let frontier_refs: Vec<_> = projection.unexpanded_support().iter().copied().filter(|d| {
                graph.index_of(&object_node(*d)).is_some_and(|index| ancestors.contains(&index))
            }).collect();
            assert_eq!(result.unexpanded_support, frontier_refs);
            let unsupported: Vec<_> = projection.records().iter().filter(|record| {
                graph.index_of(&object_node(record.revision_digest())).is_some_and(|index| ancestors.contains(&index))
                    && !record.evidence.iter().any(|edge| edge.counts_as_support())
            }).map(EventHypothesis::revision_digest).collect();
            assert_eq!(result.unsupported_revisions.iter().map(|r| r.digest).collect::<Vec<_>>(), unsupported);
        }
        rng.shuffle(&mut lineages);
        assert_eq!(projection, build(&lineages)?, "lineage permutation {seed}");
    }
    Ok(())
}
