#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]
//! Certification, differential-oracle, adversarial-fault, and non-authority proof suite for all
//! 9 prose-mandated graph algorithm families closing `GRAPH-ALGORITHM-SEMANTIC-GAPS-001`
//! (`fss-x4a.23.70` / `fss-x4a.23.70.1..9`):
//! - `ALG-FACILITY-001` (`facility.rs`)
//! - `ALG-ISO-001`      (`isomorphism.rs`)
//! - `ALG-MOTIF-001`    (`motif.rs`)
//! - `ALG-SUBISO-001`   (`subiso.rs`)
//! - `ALG-KCORE-001`    (`kcore.rs`)
//! - `ALG-PLANAR-001`   (`planar.rs`)
//! - `ALG-LINKPRED-001` (`link_pred.rs`)
//! - `ALG-CDS-001`      (`cds.rs`)
//! - `ALG-HYPER-001`    (`hypergraph.rs`)

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::{Rng, TestResult, assert_registered, certify, registered};
use fss_core::Generation;
use fss_graph_algorithms::cds::{
    self, CdsBackboneConfig, CdsSolverLane, compute_resilient_cds_backbone,
};
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::facility::{
    self, DemandPoint, FacilityCandidate, FacilityObjective, FacilityProblem, FacilitySolverLane,
    solve_facility_placement,
};
use fss_graph_algorithms::graph::{GraphBuilder, GraphError};
use fss_graph_algorithms::hypergraph::{
    self, HyperFactorSpec, HypergraphMode, NativeHypergraph, analyze_native_hypergraph,
};
use fss_graph_algorithms::isomorphism::{
    self, IsomorphismVerdict, LabeledMultigraph, compare_and_verify_isomorphism,
};
use fss_graph_algorithms::kcore::{self, decompose_k_core_and_truss};
use fss_graph_algorithms::link_pred::{
    self, LinkVerificationStatus, LinkVerifierContext, predict_and_verify_links,
};
use fss_graph_algorithms::motif::{self, classify_man_triad, triadic_census_and_motifs};
use fss_graph_algorithms::planar::{
    self, DeclaredLayerSpec, PlanarityVerdict, check_declared_layer_planarity,
};
use fss_graph_algorithms::subiso::{
    self, SubgraphMatchMode, SubgraphMatchVerdict, match_subgraph_bounded,
};
use fss_graph_algorithms::weighted::WeightedGraphBuilder;

#[test]
fn all_9_gap_algorithm_families_match_machine_registry_rows() -> TestResult {
    assert_registered(&facility::IDENTITY)?;
    assert_registered(&isomorphism::IDENTITY)?;
    assert_registered(&motif::IDENTITY)?;
    assert_registered(&subiso::IDENTITY)?;
    assert_registered(&kcore::IDENTITY)?;
    assert_registered(&planar::IDENTITY)?;
    assert_registered(&link_pred::IDENTITY)?;
    assert_registered(&cds::IDENTITY)?;
    assert_registered(&hypergraph::IDENTITY)?;
    println!(
        "CAPLOG {{\"epic\":\"GRAPH-ALGORITHM-SEMANTIC-GAPS-001\",\"registered_gap_families\":9,\"status\":\"exact_match\"}}"
    );
    Ok(())
}

#[test]
fn alg_facility_001_distinct_objectives_capacity_privacy_domains_and_oracle() -> TestResult {
    // Construct an instance where FacilityLocation, KCenter, and PMedian pick DISTINCT optima!
    // - f:cheap-edge: opening=1, dist(d1)=0, dist(d2)=8, dist(d3)=8 -> FL=1+16=17, KC=8, PM=16 (with d weights 10,1,1: PM=0+8+8=16, FL=17)
    // - f:center-mid: opening=50, dist(d1)=4, dist(d2)=4, dist(d3)=4 -> KC=4 (best KCenter!), PM=40+4+4=48, FL=98
    // - f:heavy-hub:  opening=30, dist(d1)=0, dist(d2)=5, dist(d3)=5 -> PM=10 (best PMedian!), FL=40, KC=5
    // - f:private:    privacy_excluded=true, dist=0 everywhere (MUST NEVER be chosen!)
    let candidates = vec![
        FacilityCandidate {
            facility_id: "f:cheap-edge".to_owned(),
            opening_cost: 1,
            capacity: 100,
            failure_domain: "pwr:a".to_owned(),
            privacy_excluded: false,
        },
        FacilityCandidate {
            facility_id: "f:center-mid".to_owned(),
            opening_cost: 50,
            capacity: 100,
            failure_domain: "pwr:b".to_owned(),
            privacy_excluded: false,
        },
        FacilityCandidate {
            facility_id: "f:heavy-hub".to_owned(),
            opening_cost: 30,
            capacity: 100,
            failure_domain: "pwr:c".to_owned(),
            privacy_excluded: false,
        },
        FacilityCandidate {
            facility_id: "f:private-bedroom".to_owned(),
            opening_cost: 0,
            capacity: 100,
            failure_domain: "pwr:d".to_owned(),
            privacy_excluded: true,
        },
    ];
    let demands = vec![
        DemandPoint {
            demand_id: "d:entry".to_owned(),
            weight: 10,
        },
        DemandPoint {
            demand_id: "d:yard-w".to_owned(),
            weight: 1,
        },
        DemandPoint {
            demand_id: "d:yard-e".to_owned(),
            weight: 1,
        },
    ];
    let mut distances = BTreeMap::new();
    for (f, ds) in [
        ("f:cheap-edge", [0_u64, 8, 8]),
        ("f:center-mid", [4, 4, 4]),
        ("f:heavy-hub", [0, 5, 5]),
        ("f:private-bedroom", [0, 0, 0]),
    ] {
        distances.insert((f.to_owned(), "d:entry".to_owned()), ds[0]);
        distances.insert((f.to_owned(), "d:yard-w".to_owned()), ds[1]);
        distances.insert((f.to_owned(), "d:yard-e".to_owned()), ds[2]);
    }

    let mk = |obj: FacilityObjective, k: usize, min_dom: usize| FacilityProblem {
        objective: obj,
        max_facilities: k,
        min_distinct_failure_domains: min_dom,
        candidates: candidates.clone(),
        demands: demands.clone(),
        distances: distances.clone(),
    };

    let b1 = facility::bound(3, 3, 1);
    let fl = solve_facility_placement(
        &mk(FacilityObjective::FacilityLocation, 1, 1),
        registered(&b1),
        &|| false,
    )?;
    let kc = solve_facility_placement(
        &mk(FacilityObjective::KCenter, 1, 1),
        registered(&b1),
        &|| false,
    )?;
    let pm = solve_facility_placement(
        &mk(FacilityObjective::PMedian, 1, 1),
        registered(&b1),
        &|| false,
    )?;

    assert_eq!(fl.output.lane, FacilitySolverLane::ExactSmall);
    assert_eq!(
        fl.output.selected_facilities,
        vec!["f:cheap-edge".to_owned()]
    );
    assert_eq!(fl.output.objective_value, 17);
    assert_eq!(
        kc.output.selected_facilities,
        vec!["f:center-mid".to_owned()]
    );
    assert_eq!(kc.output.objective_value, 4);
    assert_eq!(
        pm.output.selected_facilities,
        vec!["f:heavy-hub".to_owned()]
    );
    assert_eq!(pm.output.objective_value, 10);
    assert!(!fl.output.grants_effect_authority);
    certify(&fl, &facility::IDENTITY, &b1, |short| {
        solve_facility_placement(
            &mk(FacilityObjective::FacilityLocation, 1, 1),
            short,
            &|| false,
        )
    })?;

    // Diversity constraint requiring 2 distinct failure domains forces selecting 2 facilities; k=1 becomes infeasible!
    let inf = solve_facility_placement(
        &mk(FacilityObjective::KCenter, 1, 2),
        registered(&b1),
        &|| false,
    )?;
    assert!(!inf.output.feasible);
    let b2 = facility::bound(3, 3, 2);
    let div2 = solve_facility_placement(
        &mk(FacilityObjective::KCenter, 2, 2),
        registered(&b2),
        &|| false,
    )?;
    assert!(div2.output.feasible);
    assert_eq!(div2.output.distinct_failure_domains, 2);

    // Cooperative cancellation fails closed!
    assert!(matches!(
        solve_facility_placement(
            &mk(FacilityObjective::PMedian, 1, 1),
            registered(&b1),
            &|| true
        ),
        Err(GraphError::Cancelled)
    ));

    // Large instance (> 16 candidates) engages labeled ApproximateGreedySwap lane with regret bound!
    let mut big_cands = Vec::new();
    let mut big_dists = BTreeMap::new();
    for i in 0..18 {
        let fid = format!("f:{i:02}");
        big_cands.push(FacilityCandidate {
            facility_id: fid.clone(),
            opening_cost: 5 + (i as u64),
            capacity: 50,
            failure_domain: format!("pwr:{}", i % 3),
            privacy_excluded: false,
        });
        for d in &demands {
            big_dists.insert((fid.clone(), d.demand_id.clone()), 2 + ((i as u64) % 7));
        }
    }
    let big_prob = FacilityProblem {
        objective: FacilityObjective::PMedian,
        max_facilities: 2,
        min_distinct_failure_domains: 2,
        candidates: big_cands.clone(),
        demands: demands.clone(),
        distances: big_dists.clone(),
    };
    let b_big = facility::bound(18, 3, 2);
    let big_run = solve_facility_placement(&big_prob, registered(&b_big), &|| false)?;
    assert_eq!(
        big_run.output.lane,
        FacilitySolverLane::ApproximateGreedySwap
    );
    assert!(big_run.output.feasible);
    assert!(big_run.output.distinct_failure_domains >= 2);

    // Capacitated multi-facility large instance where NO single facility can serve total demand (12 > 10):
    // greedy ramp-up MUST still add a 2nd facility across a distinct failure domain to become feasible!
    let cap_cands: Vec<FacilityCandidate> = big_cands
        .into_iter()
        .map(|mut c| {
            c.capacity = 10;
            c
        })
        .collect();
    let cap_prob = FacilityProblem {
        objective: FacilityObjective::PMedian,
        max_facilities: 2,
        min_distinct_failure_domains: 2,
        candidates: cap_cands,
        demands,
        distances: big_dists,
    };
    let cap_run = solve_facility_placement(&cap_prob, registered(&b_big), &|| false)?;
    assert_eq!(
        cap_run.output.lane,
        FacilitySolverLane::ApproximateGreedySwap
    );
    assert!(cap_run.output.feasible);
    assert_eq!(cap_run.output.selected_facilities.len(), 2);
    assert_eq!(cap_run.output.distinct_failure_domains, 2);

    println!(
        "CAPLOG {{\"alg\":\"ALG-FACILITY-001\",\"fl\":\"{}\",\"kc\":\"{}\",\"pm\":\"{}\",\"large_lane_regret\":{}}}",
        fl.output.selected_facilities[0],
        kc.output.selected_facilities[0],
        pm.output.selected_facilities[0],
        big_run.output.regret_upper_bound
    );
    Ok(())
}

#[test]
fn alg_iso_001_wl_candidate_vs_exact_iso_multiedge_and_probe_cap() -> TestResult {
    // 1. Isomorphic labeled directed multigraphs (relabeled & reordered edges!) -> Isomorphic with exact bijection!
    let mut g1 = LabeledMultigraph {
        nodes: BTreeMap::from([
            ("a".to_owned(), "Cam".to_owned()),
            ("b".to_owned(), "Zone".to_owned()),
            ("c".to_owned(), "Switch".to_owned()),
        ]),
        edges: vec![
            ("a".to_owned(), "b".to_owned(), "covers".to_owned()),
            ("a".to_owned(), "b".to_owned(), "covers".to_owned()), // multiedge!
            ("a".to_owned(), "c".to_owned(), "poe".to_owned()),
        ],
    };
    let g2 = LabeledMultigraph {
        nodes: BTreeMap::from([
            ("z1".to_owned(), "Switch".to_owned()),
            ("z2".to_owned(), "Cam".to_owned()),
            ("z3".to_owned(), "Zone".to_owned()),
        ]),
        edges: vec![
            ("z2".to_owned(), "z1".to_owned(), "poe".to_owned()),
            ("z2".to_owned(), "z3".to_owned(), "covers".to_owned()),
            ("z2".to_owned(), "z3".to_owned(), "covers".to_owned()),
        ],
    };
    let b = isomorphism::bound(3, 3, 3, 100);
    let iso = compare_and_verify_isomorphism(&g1, &g2, 3, 100, registered(&b), &|| false)?;
    assert!(iso.output.wl_candidate_match);
    assert!(!iso.output.hash_proves_identity);
    assert!(!iso.output.grants_effect_authority);
    assert!(iso.output.drifted_node_labels.is_empty());
    match &iso.output.verdict {
        IsomorphismVerdict::Isomorphic { bijection } => {
            assert_eq!(bijection.get("a").map(String::as_str), Some("z2"));
            assert_eq!(bijection.get("b").map(String::as_str), Some("z3"));
            assert_eq!(bijection.get("c").map(String::as_str), Some("z1"));
        }
        other => return Err(format!("expected Isomorphic, got {other:?}").into()),
    }
    certify(&iso, &isomorphism::IDENTITY, &b, |short| {
        compare_and_verify_isomorphism(&g1, &g2, 3, 100, short, &|| false)
    })?;

    // 2. Classic 1-WL indistinguishable pair: two disjoint directed 3-cycles (C3 + C3) vs one directed 6-cycle (C6)!
    //    WL fingerprints MATCH (wl_candidate_match == true), hash_proves_identity == false,
    //    exact verifier proves NonIsomorphic — and probe_cap=1 returns UnknownBudgetExhausted (NEVER NonIsomorphic)!
    let mut c3_c3_nodes = BTreeMap::new();
    let mut c6_nodes = BTreeMap::new();
    for i in 0..6 {
        c3_c3_nodes.insert(format!("u{i}"), "N".to_owned());
        c6_nodes.insert(format!("v{i}"), "N".to_owned());
    }
    let c3_c3 = LabeledMultigraph {
        nodes: c3_c3_nodes,
        edges: vec![
            ("u0".to_owned(), "u1".to_owned(), "e".to_owned()),
            ("u1".to_owned(), "u2".to_owned(), "e".to_owned()),
            ("u2".to_owned(), "u0".to_owned(), "e".to_owned()),
            ("u3".to_owned(), "u4".to_owned(), "e".to_owned()),
            ("u4".to_owned(), "u5".to_owned(), "e".to_owned()),
            ("u5".to_owned(), "u3".to_owned(), "e".to_owned()),
        ],
    };
    let c6 = LabeledMultigraph {
        nodes: c6_nodes,
        edges: vec![
            ("v0".to_owned(), "v1".to_owned(), "e".to_owned()),
            ("v1".to_owned(), "v2".to_owned(), "e".to_owned()),
            ("v2".to_owned(), "v3".to_owned(), "e".to_owned()),
            ("v3".to_owned(), "v4".to_owned(), "e".to_owned()),
            ("v4".to_owned(), "v5".to_owned(), "e".to_owned()),
            ("v5".to_owned(), "v0".to_owned(), "e".to_owned()),
        ],
    };
    let b6 = isomorphism::bound(6, 6, 4, 2_000);
    let exact_refute =
        compare_and_verify_isomorphism(&c3_c3, &c6, 4, 2_000, registered(&b6), &|| false)?;
    assert!(exact_refute.output.wl_candidate_match);
    assert!(!exact_refute.output.hash_proves_identity);
    assert!(matches!(
        exact_refute.output.verdict,
        IsomorphismVerdict::NonIsomorphic { .. }
    ));

    let b6_tiny = isomorphism::bound(6, 6, 4, 2);
    let capped =
        compare_and_verify_isomorphism(&c3_c3, &c6, 4, 2, registered(&b6_tiny), &|| false)?;
    assert!(matches!(
        capped.output.verdict,
        IsomorphismVerdict::UnknownBudgetExhausted { .. }
    ));

    // 3. Topology drift reports changed node labels.
    g1.nodes.insert("d".to_owned(), "Door".to_owned());
    let b_drift = isomorphism::bound(4, 3, 2, 50);
    let drift = compare_and_verify_isomorphism(&g1, &g2, 2, 50, registered(&b_drift), &|| false)?;
    assert_eq!(drift.output.drifted_node_labels, vec!["Door".to_owned()]);

    println!(
        "CAPLOG {{\"alg\":\"ALG-ISO-001\",\"wl_collision_caught\":true,\"probe_cap_unknown\":true}}"
    );
    Ok(())
}

#[test]
fn alg_motif_001_exact_16_man_classes_oracle_and_non_whitelisting() -> TestResult {
    // Exhaustively check ALL 64 directed 3-node graphs: every 1 of the 16 MAN classes MUST appear,
    // and permuting the 3 vertices MUST yield the identical MAN class!
    let mut seen_classes = BTreeSet::new();
    let perms = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    for mask in 0_u8..64 {
        let bits = |i: usize, j: usize| -> bool {
            let idx = match (i, j) {
                (0, 1) => 0,
                (1, 0) => 1,
                (0, 2) => 2,
                (2, 0) => 3,
                (1, 2) => 4,
                (2, 1) => 5,
                _ => return false,
            };
            (mask & (1 << idx)) != 0
        };
        let base_cls = classify_man_triad(
            bits(0, 1),
            bits(1, 0),
            bits(0, 2),
            bits(2, 0),
            bits(1, 2),
            bits(2, 1),
        );
        seen_classes.insert(base_cls);
        for p in perms {
            let p_cls = classify_man_triad(
                bits(p[0], p[1]),
                bits(p[1], p[0]),
                bits(p[0], p[2]),
                bits(p[2], p[0]),
                bits(p[1], p[2]),
                bits(p[2], p[1]),
            );
            assert_eq!(base_cls, p_cls, "MAN class must be permutation-invariant");
        }
    }
    assert_eq!(seen_classes.len(), 16);

    // Run full triadic census on a 6-node directed graph with known 030C + 030T + 300 motifs.
    let mut wb = WeightedGraphBuilder::directed("unit");
    for i in 0..6 {
        wb.add_node(format!("n{i}"));
    }
    // 030C cycle on (n0, n1, n2)
    wb.add_arc("n0", "n1", 1)
        .add_arc("n1", "n2", 1)
        .add_arc("n2", "n0", 1);
    // 300 clique on (n3, n4, n5)
    for (u, v) in [
        ("n3", "n4"),
        ("n4", "n3"),
        ("n4", "n5"),
        ("n5", "n4"),
        ("n3", "n5"),
        ("n5", "n3"),
    ] {
        wb.add_arc(u, v, 1);
    }
    let g = wb.build()?;
    let b = motif::bound(6);
    let run = triadic_census_and_motifs(&g, registered(&b), &|| false)?;
    let total: u64 = run.output.man_counts.values().sum();
    assert_eq!(total, 20); // C(6, 3) = 20
    assert_eq!(run.output.man_counts.get("030C"), Some(&1));
    assert_eq!(run.output.man_counts.get("300"), Some(&1));
    assert!(!run.output.whitelists_behavior);
    assert!(!run.output.establishes_corroboration);
    assert!(!run.output.grants_effect_authority);
    certify(&run, &motif::IDENTITY, &b, |short| {
        triadic_census_and_motifs(&g, short, &|| false)
    })?;

    println!(
        "CAPLOG {{\"alg\":\"ALG-MOTIF-001\",\"man_classes_verified\":16,\"triads_counted\":{}}}",
        total
    );
    Ok(())
}

#[test]
fn alg_subiso_001_induced_vs_monomorphic_oracle_and_noncompletion_unknown() -> TestResult {
    // Pattern: P0(Cam) -> P1(Zone) -> P2(Door) (no direct edge P0 -> P2!)
    let pattern = LabeledMultigraph {
        nodes: BTreeMap::from([
            ("p0".to_owned(), "Cam".to_owned()),
            ("p1".to_owned(), "Zone".to_owned()),
            ("p2".to_owned(), "Door".to_owned()),
        ]),
        edges: vec![
            ("p0".to_owned(), "p1".to_owned(), "sees".to_owned()),
            ("p1".to_owned(), "p2".to_owned(), "leads".to_owned()),
        ],
    };
    // Target has TWO chains:
    // - (c1 -> z1 -> d1) WITH extra chord (c1 -> d1): monomorphic match YES, induced match NO!
    // - (c2 -> z2 -> d2) WITHOUT chord: BOTH monomorphic and induced match YES!
    let target = LabeledMultigraph {
        nodes: BTreeMap::from([
            ("c1".to_owned(), "Cam".to_owned()),
            ("z1".to_owned(), "Zone".to_owned()),
            ("d1".to_owned(), "Door".to_owned()),
            ("c2".to_owned(), "Cam".to_owned()),
            ("z2".to_owned(), "Zone".to_owned()),
            ("d2".to_owned(), "Door".to_owned()),
        ]),
        edges: vec![
            ("c1".to_owned(), "z1".to_owned(), "sees".to_owned()),
            ("z1".to_owned(), "d1".to_owned(), "leads".to_owned()),
            ("c1".to_owned(), "d1".to_owned(), "chord".to_owned()),
            ("c2".to_owned(), "z2".to_owned(), "sees".to_owned()),
            ("z2".to_owned(), "d2".to_owned(), "leads".to_owned()),
        ],
    };

    let b = subiso::bound(500, 10);
    let mono = match_subgraph_bounded(
        &pattern,
        &target,
        SubgraphMatchMode::Monomorphic,
        10,
        500,
        registered(&b),
        &|| false,
    )?;
    assert_eq!(mono.output.verdict, SubgraphMatchVerdict::Complete);
    assert_eq!(mono.output.matches.len(), 2);
    assert!(!mono.output.grants_effect_authority);

    let ind = match_subgraph_bounded(
        &pattern,
        &target,
        SubgraphMatchMode::Induced,
        10,
        500,
        registered(&b),
        &|| false,
    )?;
    assert_eq!(ind.output.verdict, SubgraphMatchVerdict::Complete);
    assert_eq!(ind.output.matches.len(), 1);
    assert_eq!(
        ind.output.matches[0].get("p0").map(String::as_str),
        Some("c2")
    );
    certify(&ind, &subiso::IDENTITY, &b, |short| {
        match_subgraph_bounded(
            &pattern,
            &target,
            SubgraphMatchMode::Induced,
            10,
            500,
            short,
            &|| false,
        )
    })?;

    // Noncompletion (probe cap = 2 OR match cap = 1) MUST return UnknownBounded, NEVER Complete/NoMatch!
    let b_cap = subiso::bound(2, 10);
    let probe_capped = match_subgraph_bounded(
        &pattern,
        &target,
        SubgraphMatchMode::Monomorphic,
        10,
        2,
        registered(&b_cap),
        &|| false,
    )?;
    assert!(matches!(
        probe_capped.output.verdict,
        SubgraphMatchVerdict::UnknownBounded { ref reason } if reason == "probe_cap_reached"
    ));

    let b_mcap = subiso::bound(500, 1);
    let match_capped = match_subgraph_bounded(
        &pattern,
        &target,
        SubgraphMatchMode::Monomorphic,
        1,
        500,
        registered(&b_mcap),
        &|| false,
    )?;
    assert!(matches!(
        match_capped.output.verdict,
        SubgraphMatchVerdict::UnknownBounded { ref reason } if reason == "match_cap_reached"
    ));

    println!(
        "CAPLOG {{\"alg\":\"ALG-SUBISO-001\",\"mono_matches\":2,\"induced_matches\":1,\"noncompletion_unknown\":true}}"
    );
    Ok(())
}

#[test]
fn alg_kcore_001_exact_core_and_truss_peeling_oracle_and_shared_domain() -> TestResult {
    // K4 clique (a,b,c,d: core=3, truss=4) + bridge (d-e: core=1, truss=2) + triangle (e,f,g: core=2, truss=3) + leaf (g-h: core=1, truss=2).
    let mut gb = GraphBuilder::new();
    for id in ["a", "b", "c", "d", "e", "f", "g", "h"] {
        gb.add_node(id);
    }
    for (u, v) in [
        ("a", "b"),
        ("a", "c"),
        ("a", "d"),
        ("b", "c"),
        ("b", "d"),
        ("c", "d"),
        ("d", "e"),
        ("e", "f"),
        ("f", "g"),
        ("e", "g"),
        ("g", "h"),
    ] {
        gb.add_edge(u, v);
    }
    let g = gb.build()?;
    // All 4 K4 nodes share ONE failure domain (`sw:single-poe`) -> exposes shared-domain concentration!
    let doms: BTreeMap<String, String> = [
        ("a", "sw:single-poe"),
        ("b", "sw:single-poe"),
        ("c", "sw:single-poe"),
        ("d", "sw:single-poe"),
        ("e", "sw:other"),
        ("f", "sw:other"),
        ("g", "sw:other"),
        ("h", "sw:other"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect();

    let b = kcore::bound(g.node_count() as u64, g.edge_count() as u64);
    let run = decompose_k_core_and_truss(&g, &doms, registered(&b), &|| false)?;
    assert_eq!(run.output.degeneracy, 3);
    assert_eq!(run.output.max_truss, 4);
    assert_eq!(run.output.max_core_distinct_failure_domains, 1);
    assert!(!run.output.dense_edges_certify_independent_corroboration);
    assert!(!run.output.grants_effect_authority);
    assert_eq!(run.output.core_numbers.get("a"), Some(&3));
    assert_eq!(run.output.core_numbers.get("e"), Some(&2));
    assert_eq!(run.output.core_numbers.get("h"), Some(&1));
    assert_eq!(
        run.output
            .edge_truss_numbers
            .get(&("a".to_owned(), "b".to_owned())),
        Some(&4)
    );
    assert_eq!(
        run.output
            .edge_truss_numbers
            .get(&("d".to_owned(), "e".to_owned())),
        Some(&2)
    );
    assert_eq!(
        run.output
            .edge_truss_numbers
            .get(&("e".to_owned(), "f".to_owned())),
        Some(&3)
    );
    certify(&run, &kcore::IDENTITY, &b, |short| {
        decompose_k_core_and_truss(&g, &doms, short, &|| false)
    })?;

    // Differential check against direct definition oracle on 40 seeded random graphs!
    for seed in 1..=40_u64 {
        let mut rng = Rng(seed * 7919);
        let n = 4 + rng.below(6);
        let mut rb = GraphBuilder::new();
        for i in 0..n {
            rb.add_node(format!("v{i}"));
        }
        let mut adj = vec![BTreeSet::new(); n];
        for i in 0..n {
            for j in (i + 1)..n {
                if rng.below(100) < 55 {
                    rb.add_edge(format!("v{i}"), format!("v{j}"));
                    adj[i].insert(j);
                    adj[j].insert(i);
                }
            }
        }
        let rg = rb.build()?;
        let r_bound = kcore::bound(rg.node_count() as u64, rg.edge_count() as u64);
        let r_run =
            decompose_k_core_and_truss(&rg, &BTreeMap::new(), registered(&r_bound), &|| false)?;
        // Oracle check: for every k=1..=degeneracy, induced subgraph on {v | core(v) >= k} has min degree >= k!
        for k in 1..=r_run.output.degeneracy {
            let sub: BTreeSet<usize> = (0..n)
                .filter(|&u| r_run.output.core_numbers[rg.id(u as u32)] >= k)
                .collect();
            for &u in &sub {
                let deg_in = adj[u].iter().filter(|v| sub.contains(v)).count() as u64;
                assert!(deg_in >= k, "k-core invariant failed at seed={seed}, k={k}");
            }
        }
    }

    println!(
        "CAPLOG {{\"alg\":\"ALG-KCORE-001\",\"degeneracy\":3,\"max_truss\":4,\"seeded_oracle_graphs\":40}}"
    );
    Ok(())
}

#[test]
fn alg_planar_001_exact_dmp_planar_and_nonplanar_families_plus_layer_guards() -> TestResult {
    let layer = DeclaredLayerSpec {
        declared_layer_id: "ground_walkways_2d".to_owned(),
        geometry_generation: Generation(4),
        ignored_crossings_overpasses: vec!["overpass:deck-stairs".to_owned()],
    };

    // 1. Planar: 3D Cube Q3 (8 vertices, 12 edges -> 6 faces: V-E+F = 8-12+6 = 2!)
    let mut cube_b = GraphBuilder::new();
    for i in 0..8 {
        cube_b.add_node(format!("q{i}"));
    }
    for (u, v) in [
        (0, 1),
        (1, 2),
        (2, 3),
        (3, 0),
        (4, 5),
        (5, 6),
        (6, 7),
        (7, 4),
        (0, 4),
        (1, 5),
        (2, 6),
        (3, 7),
    ] {
        cube_b.add_edge(format!("q{u}"), format!("q{v}"));
    }
    let cube = cube_b.build()?;
    let b_cube = planar::bound(cube.node_count() as u64, cube.edge_count() as u64);
    let r_cube = check_declared_layer_planarity(&cube, &layer, registered(&b_cube), &|| false)?;
    assert!(!r_cube.output.replaces_metric_calibration);
    assert!(!r_cube.output.implies_global_3d_planarity);
    assert!(!r_cube.output.grants_effect_authority);
    assert_eq!(r_cube.output.geometry_generation, Generation(4));
    match &r_cube.output.verdict {
        PlanarityVerdict::Planar { face_cycles } => assert_eq!(face_cycles.len(), 6),
        other => return Err(format!("cube Q3 must be planar, got {other:?}").into()),
    }
    certify(&r_cube, &planar::IDENTITY, &b_cube, |short| {
        check_declared_layer_planarity(&cube, &layer, short, &|| false)
    })?;

    // 2. Nonplanar K5 (Euler bound m=10 > 3*5-6=9)
    let mut k5_b = GraphBuilder::new();
    for i in 0..5 {
        k5_b.add_node(format!("k{i}"));
    }
    for i in 0..5 {
        for j in (i + 1)..5 {
            k5_b.add_edge(format!("k{i}"), format!("k{j}"));
        }
    }
    let k5 = k5_b.build()?;
    let b_k5 = planar::bound(5, 10);
    let r_k5 = check_declared_layer_planarity(&k5, &layer, registered(&b_k5), &|| false)?;
    assert!(matches!(
        r_k5.output.verdict,
        PlanarityVerdict::NonPlanar { .. }
    ));

    // 3. Nonplanar K_{3,3} subdivided on 2 edges (n=8, m=11 <= 3*8-6=18 AND <= 2*8-4=12!)
    //    Euler bounds DO NOT catch this — forces real DMP conflict obstruction detection!
    let mut sub_k33 = GraphBuilder::new();
    for id in ["l0", "l1", "l2", "r0", "r1", "r2", "s0", "s1"] {
        sub_k33.add_node(id);
    }
    for (u, v) in [
        ("l0", "s0"),
        ("s0", "r0"),
        ("l0", "r1"),
        ("l0", "r2"),
        ("l1", "r0"),
        ("l1", "s1"),
        ("s1", "r1"),
        ("l1", "r2"),
        ("l2", "r0"),
        ("l2", "r1"),
        ("l2", "r2"),
    ] {
        sub_k33.add_edge(u, v);
    }
    let sk33 = sub_k33.build()?;
    let b_sk = planar::bound(sk33.node_count() as u64, sk33.edge_count() as u64);
    let r_sk = check_declared_layer_planarity(&sk33, &layer, registered(&b_sk), &|| false)?;
    assert!(matches!(
        r_sk.output.verdict,
        PlanarityVerdict::NonPlanar { ref obstruction_kind, .. }
            if obstruction_kind == "dmp_conflicting_fragment_k5_or_k33_obstruction"
    ));

    // 4. Nonplanar Petersen graph (n=10, m=15, girth 5 -> m <= 2*10-4=16 -> ALSO forces DMP!)
    let mut pet_b = GraphBuilder::new();
    for i in 0..10 {
        pet_b.add_node(format!("p{i}"));
    }
    for i in 0..5 {
        pet_b.add_edge(format!("p{i}"), format!("p{}", (i + 1) % 5));
        pet_b.add_edge(format!("p{i}"), format!("p{}", i + 5));
        pet_b.add_edge(format!("p{}", i + 5), format!("p{}", ((i + 2) % 5) + 5));
    }
    let pet = pet_b.build()?;
    let b_pet = planar::bound(10, 15);
    let r_pet = check_declared_layer_planarity(&pet, &layer, registered(&b_pet), &|| false)?;
    assert!(matches!(
        r_pet.output.verdict,
        PlanarityVerdict::NonPlanar { .. }
    ));

    println!(
        "CAPLOG {{\"alg\":\"ALG-PLANAR-001\",\"cube_faces\":6,\"k5_nonplanar\":true,\"sub_k33_dmp_caught\":true,\"petersen_dmp_caught\":true}}"
    );
    Ok(())
}

#[test]
fn alg_linkpred_001_advisory_scoring_and_mandatory_exact_verifier_gates() -> TestResult {
    // Hub h connected to a, b, c, d -> pairs (a,b), (a,c), (a,d), (b,c), (b,d), (c,d) all share common neighbor h!
    let mut gb = GraphBuilder::new();
    for id in ["h", "a", "b", "c", "d"] {
        gb.add_node(id);
    }
    for id in ["a", "b", "c", "d"] {
        gb.add_edge("h", id);
    }
    let g = gb.build()?;

    // Configure exact verifier gates:
    // - (a, b): passes ALL 4 gates -> AdmittedAdvisoryCandidate!
    // - (a, c): contradicted -> RejectedByVerifier (`hard_contradiction_present`)!
    // - (a, d): d lacks evidence backing -> RejectedByVerifier (`missing_source_evidence_backing`)!
    // - (b, c): NOT in temporally_geometrically_feasible_pairs -> RejectedByVerifier!
    let ctx = LinkVerifierContext {
        model_generation: Generation(5),
        evidence_backed_nodes: ["h", "a", "b", "c"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        temporally_geometrically_feasible_pairs: [
            ("a".to_owned(), "b".to_owned()),
            ("a".to_owned(), "c".to_owned()),
            ("a".to_owned(), "d".to_owned()),
        ]
        .into_iter()
        .collect(),
        capability_visible_nodes: ["h", "a", "b", "c", "d"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        contradicted_pairs: [("a".to_owned(), "c".to_owned())].into_iter().collect(),
        max_suggestions: 10,
    };

    let b = link_pred::bound(g.node_count() as u64, 10);
    let run = predict_and_verify_links(&g, &ctx, registered(&b), &|| false)?;
    assert!(!run.output.creates_canonical_edge);
    assert!(!run.output.creates_identity);
    assert!(!run.output.establishes_corroboration);
    assert!(!run.output.grants_effect_authority);
    assert_eq!(run.output.admitted_advisory_candidates.len(), 1);
    assert_eq!(run.output.admitted_advisory_candidates[0].left_id, "a");
    assert_eq!(run.output.admitted_advisory_candidates[0].right_id, "b");
    assert_eq!(
        run.output.admitted_advisory_candidates[0].status,
        LinkVerificationStatus::AdmittedAdvisoryCandidate
    );
    assert!(run.output.rejected_candidates.iter().any(|s| {
        s.left_id == "a"
            && s.right_id == "c"
            && matches!(
                s.status,
                LinkVerificationStatus::RejectedByVerifier { ref reasons }
                    if reasons.contains(&"hard_contradiction_present".to_owned())
            )
    }));
    certify(&run, &link_pred::IDENTITY, &b, |short| {
        predict_and_verify_links(&g, &ctx, short, &|| false)
    })?;

    println!(
        "CAPLOG {{\"alg\":\"ALG-LINKPRED-001\",\"admitted\":{},\"rejected\":{}}}",
        run.output.admitted_advisory_candidates.len(),
        run.output.rejected_candidates.len()
    );
    Ok(())
}

#[test]
fn alg_cds_001_exact_cds_vs_biconnected_resilient_backbone_and_oracle() -> TestResult {
    // 4-cycle (b0-b1-b2-b3-b0) plus leaf sensor s0 attached to BOTH b0 and b1, and leaf s1 attached to BOTH b2 and b3!
    // - 1-dominated non-biconnected CDS: {b0, b3} (size 2, connected!) dominates all 6 nodes!
    // - 2-dominated biconnected resilient backbone: {b0, b1, b2, b3} (size 4, zero cut vertices, every leaf has >= 2 dominators!)
    let mut gb = GraphBuilder::new();
    for id in ["b0", "b1", "b2", "b3", "s0", "s1"] {
        gb.add_node(id);
    }
    for (u, v) in [
        ("b0", "b1"),
        ("b1", "b2"),
        ("b2", "b3"),
        ("b3", "b0"),
        ("s0", "b0"),
        ("s0", "b1"),
        ("s1", "b2"),
        ("s1", "b3"),
    ] {
        gb.add_edge(u, v);
    }
    let g = gb.build()?;
    let b = cds::bound(g.node_count() as u64, g.edge_count() as u64);

    let doms: BTreeMap<String, String> = [
        ("b0", "pwr:1"),
        ("b1", "pwr:2"),
        ("b2", "pwr:3"),
        ("b3", "pwr:4"),
        ("s0", "pwr:1"),
        ("s1", "pwr:3"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect();

    let cfg_min = CdsBackboneConfig {
        node_costs: BTreeMap::new(),
        node_failure_domains: doms.clone(),
        min_dominators: 1,
        require_biconnected_backbone: false,
    };
    let r_min = compute_resilient_cds_backbone(&g, &cfg_min, registered(&b), &|| false)?;
    assert_eq!(r_min.output.lane, CdsSolverLane::ExactSmall);
    assert!(r_min.output.feasible);
    assert_eq!(r_min.output.backbone_nodes.len(), 2);
    assert!(r_min.output.mst_baseline_lacks_redundancy);
    assert!(!r_min.output.grants_effect_authority);
    certify(&r_min, &cds::IDENTITY, &b, |short| {
        compute_resilient_cds_backbone(&g, &cfg_min, short, &|| false)
    })?;

    let cfg_res = CdsBackboneConfig {
        node_costs: BTreeMap::new(),
        node_failure_domains: doms,
        min_dominators: 2,
        require_biconnected_backbone: true,
    };
    let r_res = compute_resilient_cds_backbone(&g, &cfg_res, registered(&b), &|| false)?;
    assert!(r_res.output.feasible);
    assert_eq!(
        r_res.output.backbone_nodes,
        vec!["b0", "b1", "b2", "b3"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
    assert!(r_res.output.backbone_cut_vertices.is_empty());
    assert_eq!(r_res.output.achieved_min_domination_depth, 2);
    assert_eq!(r_res.output.distinct_failure_domains, 4);

    // Large graph (n=16 > EXACT_CDS_NODE_LIMIT) engages ApproximateConnectedGreedy lane cleanly!
    let mut big_b = GraphBuilder::new();
    for i in 0..16 {
        big_b.add_node(format!("n{i:02}"));
    }
    for i in 0..16 {
        big_b.add_edge(format!("n{i:02}"), format!("n{:02}", (i + 1) % 16));
        big_b.add_edge(format!("n{i:02}"), format!("n{:02}", (i + 2) % 16));
    }
    let big_g = big_b.build()?;
    let b_big = cds::bound(big_g.node_count() as u64, big_g.edge_count() as u64);
    let r_big = compute_resilient_cds_backbone(&big_g, &cfg_min, registered(&b_big), &|| false)?;
    assert_eq!(r_big.output.lane, CdsSolverLane::ApproximateConnectedGreedy);
    assert!(r_big.output.feasible);

    println!(
        "CAPLOG {{\"alg\":\"ALG-CDS-001\",\"min_cds_size\":2,\"resilient_biconn_size\":4,\"large_greedy_size\":{}}}",
        r_big.output.backbone_nodes.len()
    );
    Ok(())
}

#[test]
fn alg_hyper_001_native_s_walk_hitting_set_and_pairwise_distortion() -> TestResult {
    // 3 multi-entity factors:
    // - f:vis-1 (arity 3): cam:1, cell:driveway, occluder:hedge
    // - f:vis-2 (arity 3): cam:1, cell:driveway, cam:2  (shares 2 entities with f:vis-1 -> 2-adjacent!)
    // - f:manifest-3 (arity 3): cam:2, chunk:a, chunk:b (shares only 1 entity cam:2 with f:vis-2!)
    let hg = NativeHypergraph {
        mode: HypergraphMode::NativeHypergraph,
        factors: vec![
            HyperFactorSpec {
                factor_id: "f:vis-1".to_owned(),
                members: [
                    ("cam:1", "observer"),
                    ("cell:driveway", "target"),
                    ("occ:hedge", "occluder"),
                ]
                .into_iter()
                .map(|(e, r)| (e.to_owned(), r.to_owned()))
                .collect(),
                uncertainty_bps: 300,
                provenance: "visibility_factor".to_owned(),
            },
            HyperFactorSpec {
                factor_id: "f:vis-2".to_owned(),
                members: [
                    ("cam:1", "observer"),
                    ("cell:driveway", "target"),
                    ("cam:2", "corroborator"),
                ]
                .into_iter()
                .map(|(e, r)| (e.to_owned(), r.to_owned()))
                .collect(),
                uncertainty_bps: 250,
                provenance: "corroboration_factor".to_owned(),
            },
            HyperFactorSpec {
                factor_id: "f:manifest-3".to_owned(),
                members: [
                    ("cam:2", "source"),
                    ("chunk:a", "payload"),
                    ("chunk:b", "parity"),
                ]
                .into_iter()
                .map(|(e, r)| (e.to_owned(), r.to_owned()))
                .collect(),
                uncertainty_bps: 0,
                provenance: "archive_manifest".to_owned(),
            },
        ],
    };

    let b = hypergraph::bound(6, 3);
    // s = 1: all 3 hyperedges form 1 component; minimum hitting set has size 2 (e.g., cam:1 + cam:2)!
    let r1 = analyze_native_hypergraph(&hg, 1, registered(&b), &|| false)?;
    assert_eq!(r1.output.mode, HypergraphMode::NativeHypergraph);
    assert_eq!(r1.output.max_arity_preserved, 3);
    assert!(r1.output.pairwise_expansion_distorts_semantics);
    assert!(!r1.output.grants_effect_authority);
    assert_eq!(r1.output.s_components.len(), 1);
    assert!(r1.output.hitting_set_exact);
    assert_eq!(r1.output.minimal_hitting_set.len(), 2);
    certify(&r1, &hypergraph::IDENTITY, &b, |short| {
        analyze_native_hypergraph(&hg, 1, short, &|| false)
    })?;

    // s = 2: f:vis-1 and f:vis-2 share 2 entities (connected), while f:manifest-3 splits off cleanly!
    let r2 = analyze_native_hypergraph(&hg, 2, registered(&b), &|| false)?;
    assert_eq!(r2.output.s_components.len(), 2);
    assert!(
        r2.output
            .s_components
            .contains(&vec!["f:vis-1".to_owned(), "f:vis-2".to_owned()])
    );
    assert!(
        r2.output
            .s_components
            .contains(&vec!["f:manifest-3".to_owned()])
    );

    // BipartiteFactorProjection mode preserves exact same s-components and hitting set while declaring mode!
    let mut hg_bip = hg;
    hg_bip.mode = HypergraphMode::BipartiteFactorProjection;
    let rbip = analyze_native_hypergraph(&hg_bip, 2, registered(&b), &|| false)?;
    assert_eq!(rbip.output.mode, HypergraphMode::BipartiteFactorProjection);
    assert_eq!(rbip.output.s_components, r2.output.s_components);
    assert_eq!(
        rbip.output.minimal_hitting_set,
        r2.output.minimal_hitting_set
    );

    // Budget=0 fails closed!
    assert!(matches!(
        analyze_native_hypergraph(&hg_bip, 1, Budget::new(0, 0), &|| false),
        Err(GraphError::BudgetExhausted { .. })
    ));

    println!(
        "CAPLOG {{\"alg\":\"ALG-HYPER-001\",\"max_arity\":3,\"s1_comps\":1,\"s2_comps\":2,\"exact_hitting_set\":2}}"
    );
    Ok(())
}
