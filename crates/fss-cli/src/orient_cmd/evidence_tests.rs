#![forbid(unsafe_code)]
//! Deterministic H1 projection tests; these do not substitute for the binary integration test.

use super::*;
use fss_core::{
    CaptureInterval, DecisionPath, EventEvidence, EventHypothesis, EventId, EventKind,
    EventState, EvidenceClass, EvidenceEdgeRelation, LedgerAnchor, ProbabilityInterval,
    TimestampNs,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn edge(digest: ContentDigest, relation: EvidenceEdgeRelation) -> EventEvidence {
    EventEvidence {
        digest, class: EvidenceClass::Observed, failure_domain: "sensor:fixture".to_owned(),
        supports: relation.required_supports_flag(), relation, capsule_digest: None,
        identity_digest: Some(ContentDigest::sha256(b"identity fixture")),
    }
}

fn event(id: &str, evidence: Vec<EventEvidence>) -> TestResult<EventHypothesis> {
    let policy = ContentDigest::sha256(b"uncalibrated fixture policy");
    let record = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(), event_id: EventId::parse(id)?,
        revision: 1, supersedes: None, state: EventState::Hypothesized,
        kind: EventKind::Unclassified,
        interval: CaptureInterval::new(TimestampNs(0), TimestampNs(1))?,
        uncertainty_reason: Some("synthetic reference only".to_owned()),
        zone_ids: Vec::new(), track_ids: Vec::new(),
        probability: ProbabilityInterval { lower: 0.0, upper: 1.0, calibration_generation: None },
        evidence, model_receipts: Vec::new(),
        decision_path: DecisionPath {
            policy_generation: policy, fingerprint: policy, abstained: true,
            abstention_reason: Some("not an adjudication".to_owned()),
        },
    };
    record.verify()?;
    Ok(record)
}

fn brief(lineages: &[Vec<EventHypothesis>]) -> TestResult<EvidenceSupportBrief> {
    let slices: Vec<_> = lineages.iter().map(Vec::as_slice).collect();
    let graph = EvidenceHistoryProjection::build(&slices, HistoryLimits::default())?;
    Ok(explain_current_support(&graph, "event:target", LedgerAnchor::genesis("site:test"),
        GRAPH_BUDGET, MAX_BRIEF_ENTRIES)? )
}

fn review(propositions: Vec<EnvelopeProposition>) -> TestResult<SupportReview> {
    let digest = ContentDigest::sha256(b"test subject");
    Ok(SupportReview {
        propositions,
        assumptions: vec![SCOPE.to_owned()], invalidators: vec![INVALIDATOR.to_owned()],
        warnings: vec![PROOF_SCOPE.to_owned()], proof_pointers: Vec::new(),
        receipt: ExplainReceipt::compile(ExplainQuestion::Why, digest, vec![digest], Vec::new(), 0)?,
        requested: BudgetVector::ZERO, consumed: BudgetVector::ZERO,
        cost_statement: "Test accounting fixture; no real storage read.".to_owned(),
    })
}

#[test]
fn shared_recording_is_exposed_without_independence_or_truth_upgrade() -> TestResult {
    let source = ContentDigest::sha256(b"one recording");
    let a = event("event:a", vec![edge(source, EvidenceEdgeRelation::Supports)])?;
    let b = event("event:b", vec![edge(source, EvidenceEdgeRelation::Supports)])?;
    let target = event("event:target", vec![edge(a.revision_digest(), EvidenceEdgeRelation::Supports),
        edge(b.revision_digest(), EvidenceEdgeRelation::Supports)])?;
    let rows = propositions(&brief(&[vec![a], vec![b], vec![target]])?);
    let bottleneck = rows.iter().find(|row| row.id.ends_with(":bottlenecks")).ok_or("bottleneck missing")?;
    assert_eq!(bottleneck.evidence, vec![source.to_text()]);
    assert!(bottleneck.statement.contains("not an automatic event retraction"));
    let custody = rows.iter().find(|row| row.id.ends_with(":custody-and-independence")).ok_or("unknown missing")?;
    assert_eq!(custody.state, KnowledgeState::Unknown);
    assert!(rows.iter().all(|row| !row.id.ends_with(":unknown-presence")));
    Ok(())
}

#[test]
fn unsupported_alternative_and_adverse_current_head_are_both_preserved() -> TestResult {
    let old = event("event:a", Vec::new())?;
    let mut current = old.clone();
    current.revision = 2;
    current.supersedes = Some(old.revision_digest());
    current.state = EventState::Indeterminate;
    current.evidence.push(edge(ContentDigest::sha256(b"contradiction"), EvidenceEdgeRelation::Contradicts));
    let target = event("event:target", vec![edge(old.revision_digest(), EvidenceEdgeRelation::Supports),
        edge(ContentDigest::sha256(b"rooted alternative"), EvidenceEdgeRelation::Supports)])?;
    let rows = propositions(&brief(&[vec![old.clone(), current.clone()], vec![target]])?);
    assert!(rows.iter().any(|row| row.id.contains(":unsupported:") && row.evidence.contains(&old.revision_digest().to_text())));
    let correction = rows.iter().find(|row| row.id.contains(":superseded:")).ok_or("correction missing")?;
    assert!(correction.statement.contains("revision 2 (indeterminate)"));
    assert!(correction.evidence.contains(&old.revision_digest().to_text()));
    assert!(correction.evidence.contains(&current.revision_digest().to_text()));
    assert_eq!(correction.state, KnowledgeState::Known); // Known recorded correction, not known presence.
    Ok(())
}

#[test]
fn non_support_edges_never_enter_a_source_list_and_unrooted_is_not_redundant() -> TestResult {
    let counter = ContentDigest::sha256(b"counterevidence");
    let target = event("event:target", vec![edge(counter, EvidenceEdgeRelation::Contradicts),
        edge(counter, EvidenceEdgeRelation::SensorTamper)])?;
    let rows = propositions(&brief(&[vec![target]])?);
    assert!(!rows.iter().any(|row| row.id.ends_with(":unexpanded-references")));
    assert!(rows.iter().any(|row| row.statement.contains("NOT evidence of redundancy")));
    assert!(rows.iter().any(|row| row.statement.contains("0 Supports, 1 Contradicts, 1 other")));
    Ok(())
}

#[test]
fn semantic_budget_accepts_exact_boundary_and_rejects_one_short_without_mutation() -> TestResult {
    let target = event("event:target", Vec::new())?;
    let mut review = review(propositions(&brief(&[vec![target]])?))?;
    let extra = (semantic_bytes(&review)? as u64).div_ceil(4);
    let maximum = u64::from(AgentView::DecisionDiff.maximum_tokens());
    assert!(extra < maximum);
    review.consumed.tokens = maximum - extra + 1;
    let original = review.consumed;
    assert!(matches!(price(&mut review), Err(EvidenceProjectionError::Graph(GraphError::BudgetExhausted {
        dimension: "agent_explain_semantic_tokens", ..
    }))));
    assert_eq!(review.consumed, original);
    review.consumed.tokens -= 1;
    price(&mut review)?;
    assert_eq!(review.requested.tokens, maximum);
    assert_eq!(review.consumed.tokens, maximum);
    assert_eq!(budget(&review).remaining_json, agent_json::remaining(&review.requested, &review.consumed));
    assert!(!budget(&review).degraded_dimensions.is_empty());
    Ok(())
}

#[test]
fn oversized_semantic_fields_refuse_the_whole_review_without_dropping_rows() -> TestResult {
    let target = ContentDigest::sha256(b"subject");
    let rows = vec![proposition(target, "large", "x".repeat(MAX_SEMANTIC_BYTES + 1),
        KnowledgeState::Unknown, Vec::new())];
    let mut review = review(rows.clone())?;
    assert!(price(&mut review).is_err());
    assert_eq!(review.propositions, rows);
    assert_eq!(review.consumed, BudgetVector::ZERO);
    Ok(())
}

#[test]
fn propositions_are_stable_under_lineage_permutation_and_fit_envelope_field_bounds() -> TestResult {
    let source = ContentDigest::sha256(b"source");
    let a = event("event:a", vec![edge(source, EvidenceEdgeRelation::Supports)])?;
    let target = event("event:target", vec![edge(a.revision_digest(), EvidenceEdgeRelation::Supports)])?;
    let mut histories = vec![vec![a], vec![target]];
    let first = propositions(&brief(&histories)?);
    histories.reverse();
    assert_eq!(first, propositions(&brief(&histories)?));
    let mut ids = std::collections::BTreeSet::new();
    for row in &first {
        assert!(ids.insert(&row.id));
        assert!(row.id.len() <= 256);
        assert!(row.statement.len() <= 16_384);
        assert!(row.evidence.len() <= 256);
        assert!(row.evidence.iter().all(|digest| ContentDigest::parse(digest).is_ok()));
    }
    Ok(())
}
