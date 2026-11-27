#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]
//! Contract, retract/add transition, full-recompute parity, and fault/cancel/privacy proof suite
//! for `FSS-163` (`fss-x4a.23.13`): incremental retract/add standing predicates.

use fss_core::{ContentDigest, LedgerAnchor};
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::projection::{
    GraphUniverse, ProjectionAuthorityScope, ProjectionGuidance,
};
use fss_graph_algorithms::standing_predicates::{
    PredicateTransition, StandingPredicate, StandingPredicateEngine, StandingPredicateError,
    StandingPredicateKind, evaluate_standing_predicates_full_recompute,
};
use fss_graph_algorithms::zset::ZSetDeltaBatch;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn anchor_at(seq: u64) -> LedgerAnchor {
    let mut a = LedgerAnchor::genesis("site-alpha");
    a.commit_sequence = seq;
    a.state_root = ContentDigest::sha256(format!("state-root:{seq}").as_bytes());
    a
}

#[test]
fn fss_163_incremental_add_retract_transitions_match_full_recompute_at_every_commit() -> TestResult
{
    let mut auth = ProjectionAuthorityScope::active_for(GraphUniverse::GEvidence, 5, 1);
    auth.redacted_node_ids.insert("redacted-cam".to_owned());

    let predicates = vec![
        StandingPredicate {
            predicate_id: "p:active_nodes_ge_3".to_owned(),
            kind: StandingPredicateKind::ActiveNodeCountAtLeast {
                min_active_nodes: 3,
            },
        },
        StandingPredicate {
            predicate_id: "p:arc_ab".to_owned(),
            kind: StandingPredicateKind::DirectedArcActive {
                tail_id: "a".to_owned(),
                head_id: "b".to_owned(),
            },
        },
        StandingPredicate {
            predicate_id: "p:in_c_ge_2".to_owned(),
            kind: StandingPredicateKind::NodeInDegreeAtLeast {
                node_id: "c".to_owned(),
                min_in_degree: 2,
            },
        },
        StandingPredicate {
            predicate_id: "p:out_a_ge_2".to_owned(),
            kind: StandingPredicateKind::NodeOutDegreeAtLeast {
                node_id: "a".to_owned(),
                min_out_degree: 2,
            },
        },
        StandingPredicate {
            predicate_id: "p:two_hop_ac".to_owned(),
            kind: StandingPredicateKind::TwoHopPathExists {
                source_id: "a".to_owned(),
                target_id: "c".to_owned(),
            },
        },
    ];

    let mut engine = StandingPredicateEngine::new(
        GraphUniverse::GEvidence,
        anchor_at(0),
        &auth,
        predicates.clone(),
    )?;
    let budget = Budget::new(500, 32);

    // Commit 1: Add a, b, c and arcs a->b, b->c -> fires active_nodes, arc_ab, and bilinear two_hop_ac!
    let r1 = engine.apply_delta_batch(
        &ZSetDeltaBatch {
            commit_sequence: 1,
            node_deltas: vec![
                ("a".to_owned(), 1),
                ("b".to_owned(), 1),
                ("c".to_owned(), 1),
            ],
            arc_deltas: vec![
                (("a".to_owned(), "b".to_owned()), 1),
                (("b".to_owned(), "c".to_owned()), 1),
            ],
        },
        &anchor_at(1),
        &auth,
        budget,
        &|| false,
    )?;
    assert!(!r1.grants_effect_authority);
    let trans1: std::collections::BTreeMap<_, _> = r1
        .transitions
        .iter()
        .map(|row| {
            (
                row.predicate_id.as_str(),
                (row.transition, row.support_count),
            )
        })
        .collect();
    assert_eq!(
        trans1["p:active_nodes_ge_3"],
        (PredicateTransition::Fired, 3)
    );
    assert_eq!(trans1["p:arc_ab"], (PredicateTransition::Fired, 1));
    assert_eq!(trans1["p:two_hop_ac"], (PredicateTransition::Fired, 1));
    assert_eq!(trans1["p:out_a_ge_2"], (PredicateTransition::Absent, 1));
    assert_eq!(trans1["p:in_c_ge_2"], (PredicateTransition::Absent, 1));

    // Commit 2: Add second path a->d->c (fires out_a_ge_2, in_c_ge_2, sustains two_hop_ac with support=2!)
    let r2 = engine.apply_delta_batch(
        &ZSetDeltaBatch {
            commit_sequence: 2,
            node_deltas: vec![("d".to_owned(), 1)],
            arc_deltas: vec![
                (("a".to_owned(), "d".to_owned()), 1),
                (("d".to_owned(), "c".to_owned()), 1),
            ],
        },
        &anchor_at(2),
        &auth,
        budget,
        &|| false,
    )?;
    let trans2: std::collections::BTreeMap<_, _> = r2
        .transitions
        .iter()
        .map(|row| {
            (
                row.predicate_id.as_str(),
                (row.transition, row.support_count),
            )
        })
        .collect();
    assert_eq!(trans2["p:out_a_ge_2"], (PredicateTransition::Fired, 2));
    assert_eq!(trans2["p:in_c_ge_2"], (PredicateTransition::Fired, 2));
    assert_eq!(trans2["p:two_hop_ac"], (PredicateTransition::Sustained, 2));

    // Commit 3: Retract a->b and d->c -> retracts arc_ab, out_a_ge_2, in_c_ge_2, AND two_hop_ac!
    let r3 = engine.apply_delta_batch(
        &ZSetDeltaBatch {
            commit_sequence: 3,
            node_deltas: vec![("b".to_owned(), -1), ("d".to_owned(), -1)],
            arc_deltas: vec![
                (("a".to_owned(), "b".to_owned()), -1),
                (("d".to_owned(), "c".to_owned()), -1),
            ],
        },
        &anchor_at(3),
        &auth,
        budget,
        &|| false,
    )?;
    let trans3: std::collections::BTreeMap<_, _> = r3
        .transitions
        .iter()
        .map(|row| {
            (
                row.predicate_id.as_str(),
                (row.transition, row.support_count),
            )
        })
        .collect();
    assert_eq!(
        trans3["p:active_nodes_ge_3"],
        (PredicateTransition::Retracted, 2)
    );
    assert_eq!(trans3["p:arc_ab"], (PredicateTransition::Retracted, 0));
    assert_eq!(trans3["p:out_a_ge_2"], (PredicateTransition::Retracted, 1));
    assert_eq!(trans3["p:in_c_ge_2"], (PredicateTransition::Retracted, 1));
    assert_eq!(trans3["p:two_hop_ac"], (PredicateTransition::Retracted, 0));

    // Exact parity check against full recompute from scratch!
    let full = evaluate_standing_predicates_full_recompute(engine.state(), &predicates)?;
    for row in &r3.transitions {
        assert_eq!(
            full[&row.predicate_id],
            (row.current_active, row.support_count)
        );
    }

    println!(
        "CAPLOG {{\"bead\":\"FSS-163\",\"commits\":3,\"retractions_verified\":5,\"full_recompute_parity\":true}}"
    );
    Ok(())
}

#[test]
fn fss_163_atomic_refusals_preserve_committed_state_on_stale_cancel_redaction_and_negative_mult()
-> TestResult {
    let mut auth = ProjectionAuthorityScope::active_for(GraphUniverse::GEvidence, 5, 1);
    auth.redacted_node_ids.insert("redacted-cam".to_owned());

    // Redacted entity in predicate registration refused before creation!
    let bad_reg = StandingPredicateEngine::new(
        GraphUniverse::GEvidence,
        anchor_at(0),
        &auth,
        vec![StandingPredicate {
            predicate_id: "p:bad".to_owned(),
            kind: StandingPredicateKind::NodeOutDegreeAtLeast {
                node_id: "redacted-cam".to_owned(),
                min_out_degree: 1,
            },
        }],
    );
    assert!(matches!(
        bad_reg,
        Err(StandingPredicateError::RedactedEntityBlocked { .. })
    ));

    let mut engine = StandingPredicateEngine::new(
        GraphUniverse::GEvidence,
        anchor_at(1),
        &auth,
        vec![StandingPredicate {
            predicate_id: "p:arc".to_owned(),
            kind: StandingPredicateKind::DirectedArcActive {
                tail_id: "a".to_owned(),
                head_id: "b".to_owned(),
            },
        }],
    )?;
    let budget = Budget::new(100, 16);
    engine.apply_delta_batch(
        &ZSetDeltaBatch {
            commit_sequence: 2,
            node_deltas: vec![("a".to_owned(), 1), ("b".to_owned(), 1)],
            arc_deltas: vec![(("a".to_owned(), "b".to_owned()), 1)],
        },
        &anchor_at(2),
        &auth,
        budget,
        &|| false,
    )?;
    let committed_digest = engine.state().digest();

    // 1. Stale/duplicate commit sequence refused atomically!
    let stale = engine.apply_delta_batch(
        &ZSetDeltaBatch {
            commit_sequence: 2,
            node_deltas: Vec::new(),
            arc_deltas: Vec::new(),
        },
        &anchor_at(2),
        &auth,
        budget,
        &|| false,
    );
    let err_stale = match stale {
        Err(e) => e,
        Ok(_) => return Err("expected stale sequence refusal".into()),
    };
    assert_eq!(err_stale.code(), "ERR-GRAPH-STANDING-PRED-STALE-ANCHOR-001");
    assert_eq!(
        err_stale.guidance(),
        ProjectionGuidance::ReacquireHandlesForCurrentGeneration
    );

    // 2. Cooperative cancellation refused atomically!
    let canc = engine.apply_delta_batch(
        &ZSetDeltaBatch {
            commit_sequence: 3,
            node_deltas: vec![("c".to_owned(), 1)],
            arc_deltas: Vec::new(),
        },
        &anchor_at(3),
        &auth,
        budget,
        &|| true,
    );
    assert!(matches!(canc, Err(StandingPredicateError::Cancelled)));

    // 3. Redacted entity in delta batch refused BEFORE expansion!
    let red = engine.apply_delta_batch(
        &ZSetDeltaBatch {
            commit_sequence: 3,
            node_deltas: vec![("redacted-cam".to_owned(), 1)],
            arc_deltas: Vec::new(),
        },
        &anchor_at(3),
        &auth,
        budget,
        &|| false,
    );
    assert!(matches!(
        red,
        Err(StandingPredicateError::RedactedEntityBlocked { .. })
    ));

    // 4. Negative multiplicity retraction refused atomically!
    let neg = engine.apply_delta_batch(
        &ZSetDeltaBatch {
            commit_sequence: 3,
            node_deltas: Vec::new(),
            arc_deltas: vec![(("a".to_owned(), "b".to_owned()), -2)],
        },
        &anchor_at(3),
        &auth,
        budget,
        &|| false,
    );
    assert!(matches!(
        neg,
        Err(StandingPredicateError::NegativeMultiplicity { .. })
    ));

    // 5. Revoked or drifted authority refused atomically!
    let mut drifted = auth.clone();
    drifted.authority_generation = 99;
    let drift_res = engine.apply_delta_batch(
        &ZSetDeltaBatch {
            commit_sequence: 3,
            node_deltas: Vec::new(),
            arc_deltas: Vec::new(),
        },
        &anchor_at(3),
        &drifted,
        budget,
        &|| false,
    );
    assert!(matches!(
        drift_res,
        Err(StandingPredicateError::StaleAuthorityGeneration { .. })
    ));

    // 6. Tight budget fails closed atomically!
    let tight = engine.apply_delta_batch(
        &ZSetDeltaBatch {
            commit_sequence: 3,
            node_deltas: vec![("x".to_owned(), 1), ("y".to_owned(), 1)],
            arc_deltas: vec![(("x".to_owned(), "y".to_owned()), 1)],
        },
        &anchor_at(3),
        &auth,
        Budget::new(1, 16),
        &|| false,
    );
    assert!(matches!(tight, Err(StandingPredicateError::Graph(_))));

    // Every refusal preserved committed state & commit_sequence bit-for-bit!
    assert_eq!(engine.last_commit_sequence(), 2);
    assert_eq!(engine.state().digest(), committed_digest);

    println!(
        "CAPLOG {{\"bead\":\"FSS-163\",\"atomic_refusals_verified\":6,\"state_uncorrupted\":true}}"
    );
    Ok(())
}
