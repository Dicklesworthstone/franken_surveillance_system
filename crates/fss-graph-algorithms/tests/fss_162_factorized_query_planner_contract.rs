#![forbid(unsafe_code)]
//! Contract & fault tests for `FSS-162` (`fss-x4a.23.12`): capability-projected factorized
//! graph-relational query reference planner, differential equivalence against brute-force
//! relational oracle, predicate-order invariance, and absence-boundary honesty.

use fss_core::{ContentDigest, LedgerAnchor, Plane};
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::factorized_planner::{
    FACTORIZED_PLAN_MAGIC, FACTORIZED_PLAN_VERSION, FactorizedQueryPlanReceipt,
    FactorizedQueryPlanner, GRAPH_FACTORIZED_QUERY_PLAN_DOMAIN, GraphRelationalQuery, PlannerError,
    RelationPredicate,
};
use fss_graph_algorithms::projection::{
    AbsenceBoundary, GraphUniverse, ImmutableGraphProjection, ProjectionAuthorityScope,
    ProjectionEdgeSpec, ProjectionNodeSpec, ProjectionOrientation,
};
use fss_graph_algorithms::snapshot_view::GraphSnapshotCatalog;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn d(label: &str) -> ContentDigest {
    ContentDigest::sha256(label.as_bytes())
}

fn anchor(seq: u64) -> LedgerAnchor {
    let mut a = LedgerAnchor::genesis("site-fss-162");
    a.commit_sequence = seq;
    a.state_root = d(&format!("state-162-{seq}"));
    a
}

fn node(id: &str, plane: Plane) -> ProjectionNodeSpec {
    ProjectionNodeSpec {
        node_id: id.to_owned(),
        plane,
        payload_digest: d(id),
    }
}

fn edge(src: &str, dst: &str, rel: &str, weight: u64) -> ProjectionEdgeSpec {
    ProjectionEdgeSpec {
        source_id: src.to_owned(),
        target_id: dst.to_owned(),
        relation: rel.to_owned(),
        weight,
    }
}

#[test]
fn factorized_planner_matches_reference_oracle_is_order_invariant_and_honors_redaction()
-> TestResult {
    // Build a directed sensor-zone-event graph containing two triangles:
    //   (cam-1 -> zone-a -> evt-1) with cam-1 -> evt-1
    //   (cam-2 -> zone-secret -> evt-2) with cam-2 -> evt-2
    let raw_nodes = vec![
        node("cam-1", Plane::Authority),
        node("cam-2", Plane::Authority),
        node("zone-a", Plane::Authority),
        node("zone-secret", Plane::Authority),
        node("evt-1", Plane::Cognition),
        node("evt-2", Plane::Cognition),
    ];
    let raw_edges = vec![
        edge("cam-1", "zone-a", "covers", 10),
        edge("zone-a", "evt-1", "contains", 20),
        edge("cam-1", "evt-1", "witnessed", 30),
        edge("cam-2", "zone-secret", "covers", 10),
        edge("zone-secret", "evt-2", "contains", 20),
        edge("cam-2", "evt-2", "witnessed", 30),
    ];

    let full_scope = ProjectionAuthorityScope::active_for(GraphUniverse::GEvidence, 1, 1);
    let full_proj = ImmutableGraphProjection::build(
        GraphUniverse::GEvidence,
        ProjectionOrientation::Directed,
        anchor(7),
        d("hist-7"),
        &full_scope,
        raw_nodes.clone(),
        raw_edges.clone(),
        AbsenceBoundary::CertifiedComplete {
            coverage_witness_digest: d("cov-7"),
        },
        false,
    )?;

    // Publish into FSS-152 GraphSnapshotCatalog and query through its O(1) Arc handle!
    let mut catalog = GraphSnapshotCatalog::new();
    let _ = catalog.publish(full_proj, &full_scope, false)?;
    let view = catalog.acquire_view(GraphUniverse::GEvidence, &full_scope, false)?;

    let preds_a = vec![
        RelationPredicate {
            predicate_name: "p_covers".to_owned(),
            left_var: "cam".to_owned(),
            right_var: "zone".to_owned(),
            relation_filter: Some("covers".to_owned()),
            min_weight: 1,
            max_weight: 50,
        },
        RelationPredicate {
            predicate_name: "p_contains".to_owned(),
            left_var: "zone".to_owned(),
            right_var: "evt".to_owned(),
            relation_filter: Some("contains".to_owned()),
            min_weight: 1,
            max_weight: 50,
        },
        RelationPredicate {
            predicate_name: "p_witnessed".to_owned(),
            left_var: "cam".to_owned(),
            right_var: "evt".to_owned(),
            relation_filter: Some("witnessed".to_owned()),
            min_weight: 1,
            max_weight: 50,
        },
    ];
    let mut preds_b = preds_a.clone();
    preds_b.reverse();

    let q_a = GraphRelationalQuery {
        query_id: "q:triangle-corroboration".to_owned(),
        variables: vec!["cam".to_owned(), "zone".to_owned(), "evt".to_owned()],
        predicates: preds_a,
    };
    let q_b = GraphRelationalQuery {
        query_id: "q:triangle-corroboration".to_owned(),
        variables: vec!["cam".to_owned(), "zone".to_owned(), "evt".to_owned()],
        predicates: preds_b,
    };

    let budget = Budget::new(50_000, 1_000);
    let exec_a = FactorizedQueryPlanner::plan_and_execute(view.projection(), &q_a, budget, false)?;
    let exec_b = FactorizedQueryPlanner::plan_and_execute(view.projection(), &q_b, budget, false)?;
    let oracle_tuples =
        FactorizedQueryPlanner::execute_reference_oracle(view.projection(), &q_a, 1_000, false)?;

    // 1. Permutation invariance & exact differential equivalence against brute-force oracle!
    assert_eq!(exec_a.plan.plan_digest, exec_b.plan.plan_digest);
    assert_eq!(exec_a.receipt, exec_b.receipt);
    assert_eq!(exec_a.canonical_tuples, oracle_tuples);
    assert_eq!(exec_a.canonical_tuples.len(), 2);
    assert!(exec_a.receipt.certifies_absence());
    assert_eq!(
        GRAPH_FACTORIZED_QUERY_PLAN_DOMAIN,
        "fss.graph.factorized_query_plan.v1"
    );

    // 2. Capability/redaction projection BEFORE search expansion: redact `zone-secret` and
    //    verify zero leaked tuples AND non-inflated `certifies_absence() == false`!
    let mut restricted_scope = ProjectionAuthorityScope::active_for(GraphUniverse::GEvidence, 1, 1);
    restricted_scope
        .redacted_node_ids
        .insert("zone-secret".to_owned());
    let restricted_proj = ImmutableGraphProjection::build(
        GraphUniverse::GEvidence,
        ProjectionOrientation::Directed,
        anchor(7),
        d("hist-7"),
        &restricted_scope,
        raw_nodes,
        raw_edges,
        AbsenceBoundary::CertifiedComplete {
            coverage_witness_digest: d("cov-7"),
        },
        false,
    )?;
    let exec_redacted =
        FactorizedQueryPlanner::plan_and_execute(&restricted_proj, &q_a, budget, false)?;
    let oracle_redacted =
        FactorizedQueryPlanner::execute_reference_oracle(&restricted_proj, &q_a, 1_000, false)?;
    assert_eq!(exec_redacted.canonical_tuples, oracle_redacted);
    assert_eq!(
        exec_redacted.canonical_tuples,
        vec![vec![
            "cam-1".to_owned(),
            "zone-a".to_owned(),
            "evt-1".to_owned()
        ]]
    );
    assert!(
        !exec_redacted.receipt.certifies_absence(),
        "redacted projection MUST NOT claim certified absence"
    );

    // Binary wire codec round-trip (`FSSFQP01` v1).
    let wire = exec_a.receipt.to_canonical_bytes()?;
    assert_eq!(&wire[..8], &FACTORIZED_PLAN_MAGIC);
    assert_eq!(
        u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]),
        FACTORIZED_PLAN_VERSION
    );
    assert_eq!(
        FactorizedQueryPlanReceipt::from_canonical_bytes(&wire)?,
        exec_a.receipt
    );

    emit_caplog(
        "fss162_planner_diff_oracle_invariance_and_redaction",
        "factorized_planner_matches_oracle_order_invariant_and_honors_redaction",
        "factorized_planner_matches_oracle_order_invariant_and_honors_redaction",
        "pass",
    );
    Ok(())
}

#[test]
fn factorized_planner_refuses_invalid_queries_cancel_and_hostile_wire() -> TestResult {
    let scope = ProjectionAuthorityScope::active_for(GraphUniverse::GPhys, 1, 1);
    let proj = ImmutableGraphProjection::build(
        GraphUniverse::GPhys,
        ProjectionOrientation::Undirected,
        anchor(1),
        d("hist-1"),
        &scope,
        vec![node("a", Plane::Authority), node("b", Plane::Authority)],
        vec![edge("a", "b", "link", 5)],
        AbsenceBoundary::CertifiedComplete {
            coverage_witness_digest: d("cov-1"),
        },
        false,
    )?;

    let valid_q = GraphRelationalQuery {
        query_id: "q:edge".to_owned(),
        variables: vec!["x".to_owned(), "y".to_owned()],
        predicates: vec![RelationPredicate {
            predicate_name: "p1".to_owned(),
            left_var: "x".to_owned(),
            right_var: "y".to_owned(),
            relation_filter: None,
            min_weight: 0,
            max_weight: 10,
        }],
    };

    // 1. Cooperative cancellation fails closed cleanly.
    assert_eq!(
        FactorizedQueryPlanner::plan(&proj, &valid_q, true),
        Err(PlannerError::Cancelled)
    );

    // 2. Self-variable predicate & inverted weight bounds fail closed!
    let bad_self = GraphRelationalQuery {
        query_id: "q:bad-self".to_owned(),
        variables: vec!["x".to_owned()],
        predicates: vec![RelationPredicate {
            predicate_name: "self".to_owned(),
            left_var: "x".to_owned(),
            right_var: "x".to_owned(),
            relation_filter: None,
            min_weight: 0,
            max_weight: 10,
        }],
    };
    assert!(matches!(
        FactorizedQueryPlanner::plan(&proj, &bad_self, false),
        Err(PlannerError::InvalidInput(_))
    ));

    let bad_weights = GraphRelationalQuery {
        query_id: "q:bad-w".to_owned(),
        variables: vec!["x".to_owned(), "y".to_owned()],
        predicates: vec![RelationPredicate {
            predicate_name: "inv".to_owned(),
            left_var: "x".to_owned(),
            right_var: "y".to_owned(),
            relation_filter: None,
            min_weight: 100,
            max_weight: 10,
        }],
    };
    assert!(matches!(
        FactorizedQueryPlanner::plan(&proj, &bad_weights, false),
        Err(PlannerError::InvalidInput(_))
    ));

    // 3. Empty incident predicate tightens domain cardinality to 0 (intersection semantics)
    //    and yields empty result matching oracle!
    let empty_pred_q = GraphRelationalQuery {
        query_id: "q:empty-band".to_owned(),
        variables: vec!["x".to_owned(), "y".to_owned()],
        predicates: vec![
            RelationPredicate {
                predicate_name: "p_dup".to_owned(),
                left_var: "x".to_owned(),
                right_var: "y".to_owned(),
                relation_filter: None,
                min_weight: 0,
                max_weight: 10,
            },
            RelationPredicate {
                predicate_name: "p_dup".to_owned(),
                left_var: "x".to_owned(),
                right_var: "y".to_owned(),
                relation_filter: Some("nonexistent".to_owned()),
                min_weight: 0,
                max_weight: 10,
            },
        ],
    };
    let mut empty_pred_q_rev = empty_pred_q.clone();
    empty_pred_q_rev.predicates.reverse();
    let empty_a = FactorizedQueryPlanner::plan_and_execute(
        &proj,
        &empty_pred_q,
        Budget::new(5_000, 100),
        false,
    )?;
    let empty_b = FactorizedQueryPlanner::plan_and_execute(
        &proj,
        &empty_pred_q_rev,
        Budget::new(5_000, 100),
        false,
    )?;
    assert_eq!(empty_a.plan.plan_digest, empty_b.plan.plan_digest);
    assert_eq!(empty_a.plan.estimated_cardinalities, vec![0, 0]);
    assert!(empty_a.canonical_tuples.is_empty());

    // 4. Hostile wire decoding on `FSSFQP01` (including unregistered graph universe!).
    let exec =
        FactorizedQueryPlanner::plan_and_execute(&proj, &valid_q, Budget::new(5_000, 100), false)?;
    let mut bogus_universe = exec.receipt.clone();
    bogus_universe.universe = "G_bogus".to_owned();
    bogus_universe.receipt_digest = bogus_universe.compute_digest()?;
    assert!(matches!(
        bogus_universe.verify_self(),
        Err(PlannerError::MalformedWire(_))
    ));
    let wire = exec.receipt.to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        FactorizedQueryPlanReceipt::from_canonical_bytes(&bad_magic),
        Err(PlannerError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&3_u32.to_be_bytes());
    assert_eq!(
        FactorizedQueryPlanReceipt::from_canonical_bytes(&bad_ver),
        Err(PlannerError::UnsupportedVersion { version: 3 })
    );
    assert!(matches!(
        FactorizedQueryPlanReceipt::from_canonical_bytes(&wire[..wire.len() - 4]),
        Err(PlannerError::MalformedWire(_))
    ));
    let mut bit_flip = wire.clone();
    let last = bit_flip.len() - 1;
    bit_flip[last] ^= 0x01;
    assert_eq!(
        FactorizedQueryPlanReceipt::from_canonical_bytes(&bit_flip),
        Err(PlannerError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0xFF);
    assert!(matches!(
        FactorizedQueryPlanReceipt::from_canonical_bytes(&trailing),
        Err(PlannerError::MalformedWire(_))
    ));

    emit_caplog(
        "fss162_faults_validation_cancel_and_wire",
        "invalid_queries_cancel_and_hostile_wire_failed_closed",
        "invalid_queries_cancel_and_hostile_wire_failed_closed",
        "pass",
    );
    Ok(())
}
