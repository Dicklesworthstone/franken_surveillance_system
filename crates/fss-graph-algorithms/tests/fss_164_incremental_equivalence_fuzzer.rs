#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]
//! Deterministic seeded full-recompute versus incremental graph equivalence fuzzer (`FSS-164`,
//! `fss-x4a.23.14`).
//!
//! Exercises randomized multi-step add/retract/mutate/reorder/duplicate sequences across ALL FOUR
//! incremental graph engines in FSS and asserts byte-for-byte digest and semantic equivalence
//! against independent full-recompute baselines at EVERY step:
//! 1. `ALG-DYNCONN-001` (`OptimizedSegmentTreeRollback` vs `ReferencePerStateBfs` across 80 seeds);
//! 2. `ALG-ZSET-001` + `StandingPredicateEngine` (incremental retract/add DBSP linear + bilinear
//!    2-hop standing predicates vs full recompute from scratch across 80 multi-commit seeds);
//! 3. `H_vis` (`HVisProjection::apply_deltas` vs full `HVisProjection::build` across 40 seeds);
//! 4. `G_phys` (`GPhysProjection::apply_deltas` vs full `GPhysProjection::build` across 40 seeds).

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::{Rng, TestResult, registered};
use fss_core::{ContentDigest, Generation, LedgerAnchor, Plane, TimestampNs};
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::dynconn::{
    self, EdgeUpdate, dynamic_connectivity_reference_with_cancel, dynamic_connectivity_with_cancel,
};
use fss_graph_algorithms::projection::{AbsenceBoundary, GraphUniverse, ProjectionAuthorityScope};
use fss_graph_algorithms::standing_predicates::{
    StandingPredicate, StandingPredicateEngine, StandingPredicateKind,
    evaluate_standing_predicates_full_recompute,
};
use fss_graph_algorithms::typed_universes::g_phys::{
    PhysicalAccessState, PhysicalDelta, PhysicalEdgeSpec, PhysicalNodeKind, PhysicalNodeSpec,
    PhysicalTopologyGraph, TraversalBehaviorMode,
};
use fss_graph_algorithms::typed_universes::h_vis::{
    CodecQualityState, IlluminationWeather, LensHealthState, OccluderState, PoseFovStatus,
    SensorHealthPosture, VisibilityDelta, VisibilityFactor, VisibilityHypergraph,
};
use fss_graph_algorithms::weighted::WeightedGraphBuilder;
use fss_graph_algorithms::zset::ZSetDeltaBatch;

fn anchor_at(seq: u64) -> LedgerAnchor {
    let mut a = LedgerAnchor::genesis("site-fuzz");
    a.commit_sequence = seq;
    a.state_root = ContentDigest::sha256(format!("fuzz-root:{seq}").as_bytes());
    a
}

fn history_at(seq: u64) -> ContentDigest {
    ContentDigest::sha256(format!("fuzz-hist:{seq}").as_bytes())
}

fn complete_absence(tag: &str) -> AbsenceBoundary {
    AbsenceBoundary::CertifiedComplete {
        coverage_witness_digest: ContentDigest::sha256(tag.as_bytes()),
    }
}

#[test]
fn fss_164_fuzz_dynconn_optimized_vs_reference_bfs_across_80_seeds() -> TestResult {
    let mut total_batches = 0_u64;
    let mut total_queries = 0_u64;
    for seed in 0..80_u64 {
        let mut rng = Rng(seed ^ 0x4459_4e43_4f4e_4e01);
        let n = 2 + rng.below(9); // 2..=10 nodes
        let mut wb = WeightedGraphBuilder::undirected("hops");
        for i in 0..n {
            wb.add_node(format!("n{i}"));
        }
        let mut present: BTreeSet<(usize, usize)> = BTreeSet::new();
        for u in 0..n {
            for v in (u + 1)..n {
                if rng.chance(300) {
                    present.insert((u, v));
                    wb.add_arc(format!("n{u}"), format!("n{v}"), 1);
                }
            }
        }
        let graph = wb.build()?;

        let num_batches = 3 + rng.below(10);
        let mut batches: Vec<Vec<EdgeUpdate>> = Vec::with_capacity(num_batches);
        let mut max_edges = present.len() as u64;
        let mut lifetime_upper = present.len() as u64;
        for _ in 0..num_batches {
            let ops = 1 + rng.below(4);
            let mut batch = Vec::new();
            for _ in 0..ops {
                let u = rng.below(n);
                let v = rng.below(n);
                if u == v {
                    continue;
                }
                let key = (u.min(v), u.max(v));
                if present.contains(&key) {
                    present.remove(&key);
                    batch.push(EdgeUpdate::Delete(
                        format!("n{}", key.0),
                        format!("n{}", key.1),
                    ));
                } else {
                    present.insert(key);
                    lifetime_upper += 1;
                    batch.push(EdgeUpdate::Insert(
                        format!("n{}", key.0),
                        format!("n{}", key.1),
                    ));
                }
            }
            max_edges = max_edges.max(present.len() as u64);
            batches.push(batch);
        }

        let states = batches.len() + 1;
        let q_count = 4 + rng.below(10);
        let mut query_owned: Vec<(u32, String, String)> = Vec::with_capacity(q_count);
        for _ in 0..q_count {
            let st = rng.below(states) as u32;
            let a = rng.below(n);
            let b = rng.below(n);
            query_owned.push((st, format!("n{a}"), format!("n{b}")));
        }
        let query_refs: Vec<(u32, &str, &str)> = query_owned
            .iter()
            .map(|(st, a, b)| (*st, a.as_str(), b.as_str()))
            .collect();

        let opt_b = dynconn::bound(
            n as u64,
            lifetime_upper.max(1),
            states as u64,
            q_count as u64,
        );
        let ref_b =
            dynconn::reference_bound(n as u64, max_edges.max(1), states as u64, q_count as u64);

        let opt = dynamic_connectivity_with_cancel(
            &graph,
            &batches,
            &query_refs,
            registered(&opt_b),
            &|| false,
        )?;
        let reference = dynamic_connectivity_reference_with_cancel(
            &graph,
            &batches,
            &query_refs,
            registered(&ref_b),
            &|| false,
        )?;

        assert_eq!(
            opt.output, reference.output,
            "FSS-164 dynconn output mismatch on seed={seed}"
        );
        assert_eq!(
            opt.output_digest, reference.output_digest,
            "FSS-164 dynconn digest mismatch on seed={seed}"
        );
        total_batches += batches.len() as u64;
        total_queries += query_refs.len() as u64;
    }

    println!(
        "CAPLOG {{\"bead\":\"FSS-164\",\"engine\":\"ALG-DYNCONN-001\",\"seeds\":80,\"batches\":{total_batches},\"queries\":{total_queries},\"divergences\":0}}"
    );
    Ok(())
}

#[test]
fn fss_164_fuzz_standing_predicates_retract_add_vs_full_recompute_across_80_seeds() -> TestResult {
    let auth = ProjectionAuthorityScope::active_for(GraphUniverse::GEvidence, 11, 1);
    let mut total_commits = 0_u64;
    for seed in 0..80_u64 {
        let mut rng = Rng(seed ^ 0x5a53_4554_5052_4544);
        let n = 4 + rng.below(5); // 4..=8 nodes
        let predicates = vec![
            StandingPredicate {
                predicate_id: "p:active_ge_3".to_owned(),
                kind: StandingPredicateKind::ActiveNodeCountAtLeast {
                    min_active_nodes: 3,
                },
            },
            StandingPredicate {
                predicate_id: "p:arc_01".to_owned(),
                kind: StandingPredicateKind::DirectedArcActive {
                    tail_id: "n0".to_owned(),
                    head_id: "n1".to_owned(),
                },
            },
            StandingPredicate {
                predicate_id: "p:in_2_ge_2".to_owned(),
                kind: StandingPredicateKind::NodeInDegreeAtLeast {
                    node_id: "n2".to_owned(),
                    min_in_degree: 2,
                },
            },
            StandingPredicate {
                predicate_id: "p:out_0_ge_2".to_owned(),
                kind: StandingPredicateKind::NodeOutDegreeAtLeast {
                    node_id: "n0".to_owned(),
                    min_out_degree: 2,
                },
            },
            StandingPredicate {
                predicate_id: "p:two_hop_02".to_owned(),
                kind: StandingPredicateKind::TwoHopPathExists {
                    source_id: "n0".to_owned(),
                    target_id: "n2".to_owned(),
                },
            },
            StandingPredicate {
                predicate_id: "p:two_hop_13".to_owned(),
                kind: StandingPredicateKind::TwoHopPathExists {
                    source_id: "n1".to_owned(),
                    target_id: "n3".to_owned(),
                },
            },
        ];

        let mut engine = StandingPredicateEngine::new(
            GraphUniverse::GEvidence,
            anchor_at(0),
            &auth,
            predicates.clone(),
        )?;
        let mut node_mults: BTreeMap<usize, i64> = BTreeMap::new();
        let mut arc_mults: BTreeMap<(usize, usize), i64> = BTreeMap::new();
        let steps = 5 + rng.below(10);

        for step in 1..=steps {
            let mut node_deltas = Vec::new();
            let mut arc_deltas = Vec::new();

            // Mix additions, duplicate coalesced updates, and valid retractions!
            for _ in 0..(1 + rng.below(4)) {
                let u = rng.below(n);
                let cur = node_mults.get(&u).copied().unwrap_or(0);
                let delta = if cur > 0 && rng.chance(450) { -1 } else { 1 };
                *node_mults.entry(u).or_insert(0) += delta;
                node_deltas.push((format!("n{u}"), delta));
            }
            for _ in 0..(1 + rng.below(5)) {
                let u = rng.below(n);
                let v = rng.below(n);
                if u == v {
                    continue;
                }
                let cur = arc_mults.get(&(u, v)).copied().unwrap_or(0);
                let delta = if cur > 0 && rng.chance(450) { -1 } else { 1 };
                *arc_mults.entry((u, v)).or_insert(0) += delta;
                arc_deltas.push(((format!("n{u}"), format!("n{v}")), delta));
            }
            // Inject an explicit self-canceling pair (+1, -1) inside the same batch to stress consolidation!
            if rng.chance(400) {
                arc_deltas.push((("n0".to_owned(), "n1".to_owned()), 1));
                arc_deltas.push((("n0".to_owned(), "n1".to_owned()), -1));
            }

            let batch = ZSetDeltaBatch {
                commit_sequence: step as u64,
                node_deltas,
                arc_deltas,
            };
            let receipt = engine.apply_delta_batch(
                &batch,
                &anchor_at(step as u64),
                &auth,
                Budget::new(10_000, 64),
                &|| false,
            )?;

            // Independent full-recompute oracle at EVERY commit!
            let oracle = evaluate_standing_predicates_full_recompute(engine.state(), &predicates)?;
            for row in &receipt.transitions {
                let expected = oracle[&row.predicate_id];
                assert_eq!(
                    (row.current_active, row.support_count),
                    expected,
                    "FSS-164 standing predicate divergence on seed={seed} step={step} pred={}",
                    row.predicate_id
                );
            }
            total_commits += 1;
        }
    }

    println!(
        "CAPLOG {{\"bead\":\"FSS-164\",\"engine\":\"ALG-ZSET-001+STANDING-PREDICATES\",\"seeds\":80,\"commits\":{total_commits},\"divergences\":0}}"
    );
    Ok(())
}

#[test]
fn fss_164_fuzz_h_vis_and_g_phys_incremental_deltas_vs_full_rebuild_across_40_seeds() -> TestResult
{
    // 1. H_vis incremental apply_deltas vs full HVisProjection::build across 40 seeds!
    let auth_vis = ProjectionAuthorityScope::active_for(GraphUniverse::HVis, 12, 1);
    let mut hvis_steps = 0_u64;
    for seed in 0..40_u64 {
        let mut rng = Rng(seed ^ 0x4856_4953_4655_5a5a);
        let mk_factor =
            |fid: usize, cam: usize, cell: usize, prob: u16, degraded: bool| VisibilityFactor {
                factor_id: format!("vf:{fid}"),
                camera_id: format!("cam:{cam}"),
                camera_generation: Generation(1),
                calibration_generation: Generation(2),
                target_cell_id: format!("cell:{cell}"),
                target_class: "person".to_owned(),
                environment_regime: "yard_day".to_owned(),
                sensor_health: if degraded {
                    SensorHealthPosture::Degraded
                } else {
                    SensorHealthPosture::Nominal
                },
                pose_fov: PoseFovStatus::InFrustumVerified,
                occluder_state: OccluderState::Clear,
                illumination_weather: IlluminationWeather::DayClear,
                lens_health: LensHealthState::Clean,
                target_height_cm: 170,
                target_direction: "north".to_owned(),
                codec_quality: CodecQualityState::High,
                detector_model_generation: Generation(3),
                detector_profile_id: "det-v3".to_owned(),
                detector_degraded: degraded,
                detection_probability_bps: prob,
                uncertainty_bps: 500,
                valid_from_ns: TimestampNs(100),
                valid_until_ns: TimestampNs(10_000),
                failure_domains: BTreeSet::from([format!("pwr:{}", cam % 2)]),
                plane: Plane::Cognition,
            };

        let mut truth: BTreeMap<String, VisibilityFactor> = BTreeMap::new();
        for fid in 0..4 {
            let f = mk_factor(fid, fid % 2, fid % 3, 8500, false);
            truth.insert(f.factor_id.clone(), f);
        }
        let mut inc = VisibilityHypergraph::build(
            format!("hvis-fuzz-{seed}"),
            Generation(1),
            anchor_at(1),
            history_at(1),
            &auth_vis,
            truth.values().cloned().collect(),
            complete_absence("hvis:1"),
            || false,
        )?;

        for step in 2..=6_u64 {
            let mut deltas = Vec::new();
            for _ in 0..(1 + rng.below(3)) {
                let fid = rng.below(6);
                let key = format!("vf:{fid}");
                if truth.contains_key(&key) && rng.chance(400) {
                    truth.remove(&key);
                    deltas.push(VisibilityDelta::RemoveFactor(key));
                } else {
                    let f = mk_factor(
                        fid,
                        rng.below(3),
                        rng.below(3),
                        4000 + (rng.next() % 5000) as u16,
                        rng.chance(300),
                    );
                    truth.insert(f.factor_id.clone(), f.clone());
                    deltas.push(VisibilityDelta::UpsertFactor(Box::new(f)));
                }
            }
            inc = inc.apply_deltas(
                anchor_at(step),
                history_at(step),
                Generation(1),
                &auth_vis,
                &deltas,
                complete_absence(&format!("hvis:{step}")),
                || false,
            )?;
            let mut full_factors: Vec<VisibilityFactor> = truth.values().cloned().collect();
            rng.shuffle(&mut full_factors);
            let full = VisibilityHypergraph::build(
                format!("hvis-fuzz-{seed}"),
                Generation(1),
                anchor_at(step),
                history_at(step),
                &auth_vis,
                full_factors,
                complete_absence(&format!("hvis:{step}")),
                || false,
            )?;
            assert_eq!(
                inc.universe_digest(),
                full.universe_digest(),
                "FSS-164 H_vis digest divergence on seed={seed} step={step}"
            );
            assert_eq!(
                inc.to_canonical_bytes()?,
                full.to_canonical_bytes()?,
                "FSS-164 H_vis wire bytes divergence on seed={seed} step={step}"
            );
            hvis_steps += 1;
        }
    }

    // 2. G_phys incremental apply_deltas vs full GPhysProjection::build across 40 seeds!
    let auth_phys = ProjectionAuthorityScope::active_for(GraphUniverse::GPhys, 12, 1);
    let mut gphys_steps = 0_u64;
    for seed in 0..40_u64 {
        let mut rng = Rng(seed ^ 0x4750_4859_5346_555a);
        let mk_node = |id: usize| PhysicalNodeSpec {
            node_id: format!("pn:{id}"),
            kind: if id.is_multiple_of(2) {
                PhysicalNodeKind::Walkway
            } else {
                PhysicalNodeKind::Door
            },
            survey_generation: Generation(1),
            survey_valid_until_ns: TimestampNs(10_000),
            plane: Plane::Cognition,
        };
        let mk_edge =
            |eid: usize, s: usize, t: usize, stealth: bool, locked: bool| PhysicalEdgeSpec {
                edge_id: format!("pe:{eid}"),
                source_id: format!("pn:{s}"),
                target_id: format!("pn:{t}"),
                mode: if stealth {
                    TraversalBehaviorMode::CrawlUnderObstacle
                } else {
                    TraversalBehaviorMode::OrdinaryWalk
                },
                width_cm: 90,
                slope_permille: 0,
                visibility_bps: if stealth { 1500 } else { 8000 },
                access_state: if locked {
                    PhysicalAccessState::LockedOrClosed
                } else {
                    PhysicalAccessState::Open
                },
                min_transit_ms: 1000 + (eid as u64) * 100,
                max_transit_ms: 2000 + (eid as u64) * 100,
                uncertainty_ms: 250,
                survey_generation: Generation(1),
                valid_until_ns: TimestampNs(10_000),
            };

        let mut truth_nodes: BTreeMap<String, PhysicalNodeSpec> = BTreeMap::new();
        let mut truth_edges: BTreeMap<String, PhysicalEdgeSpec> = BTreeMap::new();
        for id in 0..5 {
            let n = mk_node(id);
            truth_nodes.insert(n.node_id.clone(), n);
        }
        for eid in 0..4 {
            let e = mk_edge(eid, eid, eid + 1, eid % 2 == 1, false);
            truth_edges.insert(e.edge_id.clone(), e);
        }

        let mut inc = PhysicalTopologyGraph::build(
            format!("gphys-fuzz-{seed}"),
            Generation(1),
            anchor_at(1),
            history_at(1),
            &auth_phys,
            truth_nodes.values().cloned().collect(),
            truth_edges.values().cloned().collect(),
            complete_absence("gphys:1"),
            || false,
        )?;

        for step in 2..=6_u64 {
            let mut deltas = Vec::new();
            for _ in 0..(1 + rng.below(3)) {
                let eid = rng.below(8);
                let ekey = format!("pe:{eid}");
                if truth_edges.contains_key(&ekey) && rng.chance(400) {
                    truth_edges.remove(&ekey);
                    deltas.push(PhysicalDelta::RemoveEdge(ekey));
                } else {
                    let s = rng.below(5);
                    let mut t = rng.below(5);
                    if t == s {
                        t = (s + 1) % 5;
                    }
                    let e = mk_edge(eid, s, t, rng.chance(500), rng.chance(300));
                    truth_edges.insert(e.edge_id.clone(), e.clone());
                    deltas.push(PhysicalDelta::UpsertEdge(Box::new(e)));
                }
            }
            inc = inc.apply_deltas(
                anchor_at(step),
                history_at(step),
                Generation(1),
                &auth_phys,
                &deltas,
                complete_absence(&format!("gphys:{step}")),
                || false,
            )?;
            let mut full_nodes: Vec<PhysicalNodeSpec> = truth_nodes.values().cloned().collect();
            let mut full_edges: Vec<PhysicalEdgeSpec> = truth_edges.values().cloned().collect();
            rng.shuffle(&mut full_nodes);
            rng.shuffle(&mut full_edges);
            let full = PhysicalTopologyGraph::build(
                format!("gphys-fuzz-{seed}"),
                Generation(1),
                anchor_at(step),
                history_at(step),
                &auth_phys,
                full_nodes,
                full_edges,
                complete_absence(&format!("gphys:{step}")),
                || false,
            )?;
            assert_eq!(
                inc.universe_digest(),
                full.universe_digest(),
                "FSS-164 G_phys digest divergence on seed={seed} step={step}"
            );
            assert_eq!(
                inc.to_canonical_bytes()?,
                full.to_canonical_bytes()?,
                "FSS-164 G_phys wire bytes divergence on seed={seed} step={step}"
            );
            gphys_steps += 1;
        }
    }

    println!(
        "CAPLOG {{\"bead\":\"FSS-164\",\"engines\":[\"H_vis\",\"G_phys\"],\"seeds\":40,\"hvis_steps\":{hvis_steps},\"gphys_steps\":{gphys_steps},\"divergences\":0}}"
    );
    Ok(())
}
