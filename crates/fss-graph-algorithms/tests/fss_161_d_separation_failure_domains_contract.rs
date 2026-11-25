#![forbid(unsafe_code)]
//! Contract, differential oracle, shared-failure-domain corroboration, capability/privacy
//! redaction, fault, budget, cancellation, and wire tests for `FSS-161` (`fss-x4a.23.11`).

use fss_core::{ContentDigest, LedgerAnchor, Plane};
use fss_graph_algorithms::d_separation::{
    ActiveTripleKind, CausalDag, CorroborationIndependenceStatus, D_SEPARATION_WIRE_MAGIC,
    D_SEPARATION_WIRE_VERSION, DSeparationBudget, DSeparationError, DSeparationReceipt,
    DSeparationVerdict, GRAPH_CAUSAL_DAG_DOMAIN, GRAPH_D_SEPARATION_RECEIPT_DOMAIN,
};
use fss_graph_algorithms::failure_domains::{FailureDomain, FailureDomainKind};
use fss_graph_algorithms::projection::{
    AbsenceBoundary, GraphUniverse, ProjectionAuthorityScope, ProjectionEdgeSpec, ProjectionError,
    ProjectionNodeSpec,
};
use fss_graph_algorithms::{CoverageObservation, SensorCoverageProjection};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn anchor(seq: u64) -> LedgerAnchor {
    let mut a = LedgerAnchor::genesis("site:fss-161-dsep");
    a.commit_sequence = seq;
    a.state_root = ContentDigest::sha256(format!("state:{seq}").as_bytes());
    a
}

fn node(id: &str) -> ProjectionNodeSpec {
    ProjectionNodeSpec {
        node_id: id.to_owned(),
        plane: Plane::Cognition,
        payload_digest: ContentDigest::sha256(id.as_bytes()),
    }
}

fn edge(src: &str, dst: &str) -> ProjectionEdgeSpec {
    ProjectionEdgeSpec {
        source_id: src.to_owned(),
        target_id: dst.to_owned(),
        relation: "causes".to_owned(),
        weight: 1,
    }
}

fn vec_s(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

fn certified_absence() -> AbsenceBoundary {
    AbsenceBoundary::CertifiedComplete {
        coverage_witness_digest: ContentDigest::sha256(b"cov-fss-161"),
    }
}

#[test]
fn bayes_ball_matches_moralized_ancestral_oracle_across_structures_and_seeded_dags() -> TestResult {
    assert_eq!(GRAPH_CAUSAL_DAG_DOMAIN, "fss.graph.causal_dag.v1");
    assert_eq!(
        GRAPH_D_SEPARATION_RECEIPT_DOMAIN,
        "fss.graph.d_separation_receipt.v1"
    );

    let auth = ProjectionAuthorityScope::active_for(GraphUniverse::GEvidence, 1, 1);
    let hroot = ContentDigest::sha256(b"hist-161");

    // 1. Canonical M-bias + Collider-Descendant DAG:
    //    u1 -> x, u1 -> m, u2 -> m, u2 -> y, m -> d, x -> z_chain -> y
    //    Without z_chain (pure M-bias + collider descendant): u1 -> x, u1 -> m, u2 -> m, u2 -> y, m -> d
    let nodes = vec![
        node("u1"),
        node("u2"),
        node("x"),
        node("m"),
        node("y"),
        node("d"),
    ];
    let edges = vec![
        edge("u1", "x"),
        edge("u1", "m"),
        edge("u2", "m"),
        edge("u2", "y"),
        edge("m", "d"),
    ];
    let dag = CausalDag::build(
        GraphUniverse::GEvidence,
        anchor(10),
        hroot,
        &auth,
        nodes.clone(),
        edges.clone(),
        certified_absence(),
        false,
    )?;

    // Insertion-order invariance: reversed inputs yield bit-identical dag_digest!
    let mut rev_nodes = nodes;
    rev_nodes.reverse();
    let mut rev_edges = edges;
    rev_edges.reverse();
    let dag_rev = CausalDag::build(
        GraphUniverse::GEvidence,
        anchor(10),
        hroot,
        &auth,
        rev_nodes,
        rev_edges,
        certified_absence(),
        false,
    )?;
    assert_eq!(dag.dag_digest(), dag_rev.dag_digest());

    // M-bias unconditioned: x ⊥ y | {} is TRUE (collider m blocks path!).
    let r_empty = dag.evaluate_d_separation(
        "q:mbias:empty",
        &vec_s(&["x"]),
        &vec_s(&["y"]),
        &vec_s(&[]),
        DSeparationBudget::ceiling(),
        false,
    )?;
    assert!(!r_empty.grants_effect_authority());
    assert_eq!(r_empty.verdict, DSeparationVerdict::CertifiedDSeparated);
    assert!(r_empty.active_path.is_none());
    assert!(dag.oracle_d_separation_moralized_ancestral(&vec_s(&["x"]), &vec_s(&["y"]), &[])?);

    // M-bias conditioned on collider m: OPENS path x <- u1 -> m <- u2 -> y!
    let r_collider = dag.evaluate_d_separation(
        "q:mbias:collider",
        &vec_s(&["x"]),
        &vec_s(&["y"]),
        &vec_s(&["m"]),
        DSeparationBudget::ceiling(),
        false,
    )?;
    assert_eq!(r_collider.verdict, DSeparationVerdict::DConnected);
    let path = r_collider
        .active_path
        .as_ref()
        .ok_or("expected active path")?;
    assert_eq!(
        path.triples.iter().map(|t| t.kind).collect::<Vec<_>>(),
        vec![
            ActiveTripleKind::Fork,
            ActiveTripleKind::ColliderActivated,
            ActiveTripleKind::Fork,
        ]
    );
    assert!(!dag.oracle_d_separation_moralized_ancestral(
        &vec_s(&["x"]),
        &vec_s(&["y"]),
        &vec_s(&["m"]),
    )?);

    // M-bias conditioned on DESCENDANT d of collider m: STILL opens path (explaining away)!
    let r_desc = dag.evaluate_d_separation(
        "q:mbias:descendant",
        &vec_s(&["x"]),
        &vec_s(&["y"]),
        &vec_s(&["d"]),
        DSeparationBudget::ceiling(),
        false,
    )?;
    assert_eq!(r_desc.verdict, DSeparationVerdict::DConnected);
    assert!(!dag.oracle_d_separation_moralized_ancestral(
        &vec_s(&["x"]),
        &vec_s(&["y"]),
        &vec_s(&["d"]),
    )?);

    // Conditioning on BOTH d AND u1 blocks the fork at u1 -> CertifiedDSeparated again!
    let r_reblocked = dag.evaluate_d_separation(
        "q:mbias:reblocked",
        &vec_s(&["x"]),
        &vec_s(&["y"]),
        &vec_s(&["d", "u1"]),
        DSeparationBudget::ceiling(),
        false,
    )?;
    assert_eq!(r_reblocked.verdict, DSeparationVerdict::CertifiedDSeparated);
    assert!(dag.oracle_d_separation_moralized_ancestral(
        &vec_s(&["x"]),
        &vec_s(&["y"]),
        &vec_s(&["d", "u1"]),
    )?);

    // 2. Differential oracle campaign across 240 deterministic seeded random DAGs (n = 6..=10).
    let mut rng_state: u64 = 0x5EED_0161_CAFE_BABEu64;
    let mut next_u64 = || -> u64 {
        rng_state = rng_state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        rng_state
    };

    let mut total_queries = 0_usize;
    let mut separated_count = 0_usize;
    let mut connected_count = 0_usize;

    for graph_idx in 0..80_usize {
        let n = 6 + (graph_idx % 5); // 6..=10 nodes, edges only i -> j for i < j (guaranteed DAG!)
        let mut r_nodes = Vec::with_capacity(n);
        for i in 0..n {
            r_nodes.push(node(&format!("n{i}")));
        }
        let mut r_edges = Vec::new();
        for i in 0..n {
            for j in (i + 1)..n {
                if (next_u64() % 100) < 35 {
                    r_edges.push(edge(&format!("n{i}"), &format!("n{j}")));
                }
            }
        }
        let g = CausalDag::build(
            GraphUniverse::GEvidence,
            anchor(100 + graph_idx as u64),
            hroot,
            &auth,
            r_nodes,
            r_edges,
            certified_absence(),
            false,
        )?;

        // Run 3 diverse disjoint (X, Y, Z) queries per random DAG = 240 queries!
        for q in 0..3_usize {
            let mut perm: Vec<usize> = (0..n).collect();
            for k in (1..n).rev() {
                let swap_idx = (next_u64() as usize) % (k + 1);
                perm.swap(k, swap_idx);
            }
            let x_len = 1 + ((next_u64() as usize) % 2);
            let y_len = 1 + ((next_u64() as usize) % 2);
            let max_z = n.saturating_sub(x_len + y_len);
            let z_len = if max_z == 0 {
                0
            } else {
                (next_u64() as usize) % (max_z + 1)
            };
            let x: Vec<String> = perm[0..x_len].iter().map(|i| format!("n{i}")).collect();
            let y: Vec<String> = perm[x_len..x_len + y_len]
                .iter()
                .map(|i| format!("n{i}"))
                .collect();
            let z: Vec<String> = perm[x_len + y_len..x_len + y_len + z_len]
                .iter()
                .map(|i| format!("n{i}"))
                .collect();

            let receipt = g.evaluate_d_separation(
                &format!("q:rand:{graph_idx}:{q}"),
                &x,
                &y,
                &z,
                DSeparationBudget::ceiling(),
                false,
            )?;
            let oracle = g.oracle_d_separation_moralized_ancestral(&x, &y, &z)?;
            assert_eq!(
                receipt.verdict.is_d_separated_on_projection(),
                oracle,
                "Bayes-Ball disagreed with moralized-ancestral oracle on graph {graph_idx} query {q}"
            );
            total_queries += 1;
            if oracle {
                separated_count += 1;
                assert_eq!(receipt.verdict, DSeparationVerdict::CertifiedDSeparated);
            } else {
                connected_count += 1;
                assert_eq!(receipt.verdict, DSeparationVerdict::DConnected);
                assert!(receipt.active_path.is_some());
            }
        }
    }
    assert_eq!(total_queries, 240);
    assert!(separated_count > 20 && connected_count > 20);

    emit_caplog(
        "fss_161_differential_bayes_ball_vs_moralized_oracle",
        "240_seeded_dags_and_mbias_100pct_equivalent",
        "240_seeded_dags_and_mbias_100pct_equivalent",
        "pass",
    );
    Ok(())
}

#[test]
fn shared_failure_domains_refute_corroboration_and_redaction_downgrades_certification() -> TestResult
{
    // Three cameras observing zone "rear":
    // - cam-a and cam-b share PoE switch `network/poe-sw-1` (confounded!)
    // - cam-c is on an independent breaker & switch (`power/ups-2`, `network/uplink-2`)
    let coverage = SensorCoverageProjection::build(
        "site:fss-161-corrob",
        &[
            CoverageObservation {
                sensor_id: "cam-a".to_owned(),
                zone_scope: "rear".to_owned(),
                witnesses: 4,
            },
            CoverageObservation {
                sensor_id: "cam-b".to_owned(),
                zone_scope: "rear".to_owned(),
                witnesses: 4,
            },
            CoverageObservation {
                sensor_id: "cam-c".to_owned(),
                zone_scope: "rear".to_owned(),
                witnesses: 4,
            },
        ],
    )?;
    let domains = vec![
        FailureDomain::new(
            FailureDomainKind::Network,
            "poe-sw-1",
            &vec_s(&["cam-a", "cam-b"]),
        )?,
        FailureDomain::new(FailureDomainKind::Power, "ups-2", &vec_s(&["cam-c"]))?,
        FailureDomain::new(FailureDomainKind::Network, "uplink-2", &vec_s(&["cam-c"]))?,
    ];

    let auth = ProjectionAuthorityScope::active_for(GraphUniverse::GSensor, 1, 1);
    let hroot = ContentDigest::sha256(b"hist-corrob");
    let dag = CausalDag::from_failure_domains(
        &coverage,
        &domains,
        anchor(20),
        hroot,
        &auth,
        certified_absence(),
        false,
    )?;

    // 1. {cam-a, cam-b} CANNOT corroborate independently because of shared fork `failure/network/poe-sw-1`!
    let report_ab = dag.assess_corroboration_independence(
        "corrob:ab",
        &vec_s(&["sensor/cam-a", "sensor/cam-b"]),
        &[],
        DSeparationBudget::ceiling(),
        false,
    )?;
    assert!(!report_ab.grants_effect_authority());
    assert_eq!(
        report_ab.status,
        CorroborationIndependenceStatus::ConfoundedBySharedDomains
    );
    assert_eq!(
        report_ab.pair_findings[0].shared_fork_causes,
        vec!["failure/network/poe-sw-1".to_owned()]
    );

    // 2. {cam-a, cam-c} ARE CertifiedDSeparated given {} (disjoint failure domains; zone/rear is an unconditioned collider)!
    let report_ac = dag.assess_corroboration_independence(
        "corrob:ac",
        &vec_s(&["sensor/cam-a", "sensor/cam-c"]),
        &[],
        DSeparationBudget::ceiling(),
        false,
    )?;
    assert_eq!(
        report_ac.status,
        CorroborationIndependenceStatus::IndependentOnCertifiedProjection
    );
    assert_eq!(
        report_ac.pair_findings[0].receipt.verdict,
        DSeparationVerdict::CertifiedDSeparated
    );

    // 3. Conditioning on the shared observed zone `zone/rear` (collider!) activates explaining-away between cam-a and cam-c!
    let report_ac_collider = dag.assess_corroboration_independence(
        "corrob:ac:zone",
        &vec_s(&["sensor/cam-a", "sensor/cam-c"]),
        &vec_s(&["zone/rear"]),
        DSeparationBudget::ceiling(),
        false,
    )?;
    assert_eq!(
        report_ac_collider.status,
        CorroborationIndependenceStatus::ConfoundedBySharedDomains
    );

    // 4. Privacy/capability redaction of `failure/network/poe-sw-1` BEFORE expansion:
    //    cam-a and cam-b appear disconnected on the partial view, MUST downgrade to
    //    `DSeparatedOnPartialView` / `UncertifiedPartialView` — NEVER `CertifiedDSeparated`!
    let mut redacted_auth = auth.clone();
    redacted_auth
        .redacted_node_ids
        .insert("failure/network/poe-sw-1".to_owned());
    let redacted_dag = CausalDag::from_failure_domains(
        &coverage,
        &domains,
        anchor(20),
        hroot,
        &redacted_auth,
        certified_absence(),
        false,
    )?;
    assert!(!redacted_dag.absence_boundary().certifies_absence());
    let report_redacted = redacted_dag.assess_corroboration_independence(
        "corrob:ab:redacted",
        &vec_s(&["sensor/cam-a", "sensor/cam-b"]),
        &[],
        DSeparationBudget::ceiling(),
        false,
    )?;
    assert_eq!(
        report_redacted.status,
        CorroborationIndependenceStatus::UncertifiedPartialView
    );
    assert_eq!(
        report_redacted.pair_findings[0].receipt.verdict,
        DSeparationVerdict::DSeparatedOnPartialView
    );

    emit_caplog(
        "fss_161_failure_domain_corroboration_and_redaction",
        "shared_domain_confounded_disjoint_certified_redacted_partial_verified",
        "shared_domain_confounded_disjoint_certified_redacted_partial_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn cycles_authority_budget_cancellation_and_hostile_wire_fail_closed() -> TestResult {
    let auth = ProjectionAuthorityScope::active_for(GraphUniverse::GEvidence, 2, 1);
    let hroot = ContentDigest::sha256(b"hist-faults");

    // 1. Cycle refusal (`a -> b -> c -> a`) fails closed with CycleDetected!
    let cyclic = CausalDag::build(
        GraphUniverse::GEvidence,
        anchor(30),
        hroot,
        &auth,
        vec![node("a"), node("b"), node("c")],
        vec![edge("a", "b"), edge("b", "c"), edge("c", "a")],
        certified_absence(),
        false,
    );
    assert!(matches!(
        cyclic,
        Err(DSeparationError::CycleDetected { .. })
    ));

    // 2. Authority/universe/stale-generation refusal BEFORE expansion!
    let mut bad_auth = auth.clone();
    bad_auth.authority_generation = 99;
    assert!(matches!(
        CausalDag::build(
            GraphUniverse::GEvidence,
            anchor(30),
            hroot,
            &bad_auth,
            vec![node("a"), node("b")],
            vec![edge("a", "b")],
            certified_absence(),
            false,
        ),
        Err(DSeparationError::Projection(
            ProjectionError::StaleAuthorityGeneration { .. }
        ))
    ));

    // 3. Valid DAG for query faults: overlapping sets, budget exhaustion, cancellation, wire tamper.
    let dag = CausalDag::build(
        GraphUniverse::GEvidence,
        anchor(31),
        hroot,
        &auth,
        vec![node("x"), node("m"), node("y")],
        vec![edge("x", "m"), edge("m", "y")],
        certified_absence(),
        false,
    )?;

    // Overlapping X and Y fails closed!
    assert!(matches!(
        dag.evaluate_d_separation(
            "q:overlap",
            &vec_s(&["x", "m"]),
            &vec_s(&["m", "y"]),
            &[],
            DSeparationBudget::ceiling(),
            false,
        ),
        Err(DSeparationError::InvalidInput(_))
    ));

    // Budget one short (limit = 1) fails closed!
    assert!(matches!(
        dag.evaluate_d_separation(
            "q:budget",
            &vec_s(&["x"]),
            &vec_s(&["y"]),
            &[],
            DSeparationBudget::new(1),
            false,
        ),
        Err(DSeparationError::BudgetExhausted { .. })
    ));

    // Cooperative cancellation fails closed!
    assert_eq!(
        dag.evaluate_d_separation(
            "q:cancel",
            &vec_s(&["x"]),
            &vec_s(&["y"]),
            &[],
            DSeparationBudget::ceiling(),
            true,
        ),
        Err(DSeparationError::Cancelled)
    );

    // Wire round-trip determinism + hostile bytes (`FSSDSE01` v1).
    let receipt = dag.evaluate_d_separation(
        "q:wire",
        &vec_s(&["x"]),
        &vec_s(&["y"]),
        &[],
        DSeparationBudget::ceiling(),
        false,
    )?;
    let w1 = receipt.to_canonical_bytes()?;
    let w2 = receipt.to_canonical_bytes()?;
    assert_eq!(w1, w2);
    assert_eq!(&w1[..8], &D_SEPARATION_WIRE_MAGIC);
    assert_eq!(
        u32::from_be_bytes([w1[8], w1[9], w1[10], w1[11]]),
        D_SEPARATION_WIRE_VERSION
    );
    assert_eq!(DSeparationReceipt::from_canonical_bytes(&w1)?, receipt);

    let mut bad_magic = w1.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        DSeparationReceipt::from_canonical_bytes(&bad_magic),
        Err(DSeparationError::InvalidMagic)
    );
    let mut bad_ver = w1.clone();
    bad_ver[8..12].copy_from_slice(&9_u32.to_be_bytes());
    assert_eq!(
        DSeparationReceipt::from_canonical_bytes(&bad_ver),
        Err(DSeparationError::UnsupportedVersion { version: 9 })
    );
    assert!(matches!(
        DSeparationReceipt::from_canonical_bytes(&w1[..w1.len() - 4]),
        Err(DSeparationError::MalformedWire(_))
    ));
    let mut flipped = w1.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    assert_eq!(
        DSeparationReceipt::from_canonical_bytes(&flipped),
        Err(DSeparationError::ChecksumMismatch)
    );
    let mut trailing = w1;
    trailing.push(0xAA);
    assert!(matches!(
        DSeparationReceipt::from_canonical_bytes(&trailing),
        Err(DSeparationError::MalformedWire(_))
    ));

    emit_caplog(
        "fss_161_faults_cycles_budget_cancel_wire",
        "cycle_authority_overlap_budget_cancel_and_wire_failed_closed",
        "cycle_authority_overlap_budget_cancel_and_wire_failed_closed",
        "pass",
    );
    Ok(())
}
