#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]
//! Authorized projection contract, differential-lane, fault/cancel/stale-anchor, and non-authority
//! proof suite for `FSS-154` through `FSS-160` (`fss-x4a.23.4`..`fss-x4a.23.10`):
//! - `FSS-154`: Dynamic connectivity reference (`ReferencePerStateBfs`) vs optimized
//!   (`OptimizedSegmentTreeRollback`) lanes + cooperative cancellation + strict batch errors;
//! - `FSS-155`: Articulation/bridge (`ALG-BRIDGE-001`) + dominator/postdominator (`ALG-DOM-001`);
//! - `FSS-156`: Shortest path, multi-source distance, k-shortest diverse paths, & temporal reachability;
//! - `FSS-157`: Weighted bipartite matching, k-best assignment (preserving ambiguity), & min-cost flow;
//! - `FSS-158`: Max-flow / min-cut & Gomory-Hu cut hierarchy;
//! - `FSS-159`: SCC + condensation DAG + lexicographic topological schedule / critical path;
//! - `FSS-160`: Set-cover, submodular selection, Steiner tree, & network interdiction.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::{TestResult, registered};
use fss_core::{ContentDigest, LedgerAnchor, Plane};
use fss_graph_algorithms::assignment::{self, AssignmentProblemBuilder, NonAssignment};
use fss_graph_algorithms::bridges::GraphBudget;
use fss_graph_algorithms::dominators::{self, DominanceDirection};
use fss_graph_algorithms::dynconn::{self, DynamicConnectivityLane, EdgeUpdate};
use fss_graph_algorithms::flow::{self, CutMode, FlowOutput};
use fss_graph_algorithms::gomory_hu;
use fss_graph_algorithms::graph::GraphError;
use fss_graph_algorithms::interdiction::{self, InterdictionOutcome, InterdictionQuery};
use fss_graph_algorithms::ksp;
use fss_graph_algorithms::min_cost_flow;
use fss_graph_algorithms::paths;
use fss_graph_algorithms::projection::{
    AbsenceBoundary, GraphUniverse, ImmutableGraphProjection, ProjectionAuthorityScope,
    ProjectionEdgeSpec, ProjectionNodeSpec, ProjectionOrientation,
};
use fss_graph_algorithms::projection_runner::{
    AuthorizedRunError, run_bridges_on_snapshot, run_dominators_on_snapshot,
    run_dynamic_connectivity_on_snapshot, run_gomory_hu_on_snapshot, run_interdiction_on_snapshot,
    run_k_best_assignments_on_snapshot, run_k_shortest_paths_on_snapshot,
    run_max_flow_min_cut_on_snapshot, run_min_cost_flow_on_snapshots,
    run_multi_source_distances_on_snapshot, run_optimal_assignment_on_snapshot,
    run_scc_on_snapshot, run_set_cover_on_snapshot, run_shortest_paths_on_snapshot,
    run_steiner_on_snapshot, run_submodular_on_snapshot, run_temporal_reachability_on_snapshot,
    run_topological_schedule_on_snapshot,
};
use fss_graph_algorithms::scc;
use fss_graph_algorithms::set_cover::{CoverBudget, CoverMethod, CoverSet, SetCoverProblem};
use fss_graph_algorithms::snapshot_view::{GraphSnapshotCatalog, SnapshotGuidance};
use fss_graph_algorithms::steiner;
use fss_graph_algorithms::submodular::SubmodularProblem;
use fss_graph_algorithms::temporal::{self, TemporalNetworkBuilder, Transit};
use fss_graph_algorithms::topo;
use fss_graph_algorithms::weighted::Orientation;

fn anchor_at(seq: u64) -> LedgerAnchor {
    let mut a = LedgerAnchor::genesis("site-alpha");
    a.commit_sequence = seq;
    a.state_root = ContentDigest::sha256(format!("state-root:{seq}").as_bytes());
    a
}

fn history_at(seq: u64) -> ContentDigest {
    ContentDigest::sha256(format!("history:{seq}").as_bytes())
}

fn node(id: &str) -> ProjectionNodeSpec {
    ProjectionNodeSpec {
        node_id: id.to_owned(),
        plane: Plane::Cognition,
        payload_digest: ContentDigest::sha256(id.as_bytes()),
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

fn complete_absence(tag: &str) -> AbsenceBoundary {
    AbsenceBoundary::CertifiedComplete {
        coverage_witness_digest: ContentDigest::sha256(tag.as_bytes()),
    }
}

#[test]
fn fss_154_dynamic_connectivity_reference_vs_optimized_cancel_and_stale_snapshot() -> TestResult {
    let auth = ProjectionAuthorityScope::active_for(GraphUniverse::GSensor, 4, 1);
    let proj = ImmutableGraphProjection::build(
        GraphUniverse::GSensor,
        ProjectionOrientation::Undirected,
        anchor_at(10),
        history_at(10),
        &auth,
        vec![node("n0"), node("n1"), node("n2"), node("n3"), node("n4")],
        vec![
            edge("n0", "n1", "link", 1),
            edge("n1", "n2", "link", 1),
            edge("n3", "n4", "link", 1),
        ],
        complete_absence("cov:10"),
        false,
    )?;
    let mut catalog = GraphSnapshotCatalog::new();
    catalog.publish(proj, &auth, false)?;
    let view = catalog.acquire_view(GraphUniverse::GSensor, &auth, false)?;

    let batches = vec![
        vec![EdgeUpdate::Insert("n2".to_owned(), "n3".to_owned())],
        vec![EdgeUpdate::Delete("n1".to_owned(), "n2".to_owned())],
        vec![
            EdgeUpdate::Insert("n0".to_owned(), "n4".to_owned()),
            EdgeUpdate::Insert("n1".to_owned(), "n2".to_owned()),
        ],
    ];
    let queries = [
        (0, "n0", "n4"),
        (1, "n0", "n4"),
        (2, "n0", "n4"),
        (3, "n0", "n4"),
        (2, "n2", "n4"),
    ];
    let opt_b = dynconn::bound(5, 6, 4, 5);
    let ref_b = dynconn::reference_bound(5, 5, 4, 5);

    let opt = run_dynamic_connectivity_on_snapshot(
        &view,
        &catalog,
        &auth,
        "hops",
        None,
        DynamicConnectivityLane::OptimizedSegmentTreeRollback,
        &batches,
        &queries,
        registered(&opt_b),
        &|| false,
    )?;
    let reference = run_dynamic_connectivity_on_snapshot(
        &view,
        &catalog,
        &auth,
        "hops",
        None,
        DynamicConnectivityLane::ReferencePerStateBfs,
        &batches,
        &queries,
        registered(&ref_b),
        &|| false,
    )?;

    // Exact semantic & digest equivalence between reference BFS and optimized segment-tree lanes!
    assert_eq!(opt.result.output, reference.result.output);
    assert_eq!(opt.result.output_digest, reference.result.output_digest);
    assert_eq!(opt.result.output.component_counts, vec![2, 1, 2, 1]);
    assert!(!opt.grants_effect_authority);
    assert!(opt.absence_boundary.certifies_absence());

    // Cooperative cancellation fails closed with actionable retry guidance!
    let cancelled = run_dynamic_connectivity_on_snapshot(
        &view,
        &catalog,
        &auth,
        "hops",
        None,
        DynamicConnectivityLane::OptimizedSegmentTreeRollback,
        &batches,
        &queries,
        registered(&opt_b),
        &|| true,
    );
    let err = match cancelled {
        Err(e) => e,
        Ok(_) => return Err("expected cancellation failure".into()),
    };
    assert_eq!(err.code(), "ERR-GRAPH-AUTHORIZED-CANCELLED-001");
    assert_eq!(err.guidance(), SnapshotGuidance::RetryWhenReady);

    // Revoked authority fails closed BEFORE graph expansion!
    let mut revoked_auth = auth.clone();
    revoked_auth.capability_active = false;
    let rev = run_dynamic_connectivity_on_snapshot(
        &view,
        &catalog,
        &revoked_auth,
        "hops",
        None,
        DynamicConnectivityLane::ReferencePerStateBfs,
        &batches,
        &queries,
        registered(&ref_b),
        &|| false,
    );
    assert!(matches!(rev, Err(AuthorizedRunError::Snapshot(_))));

    // Stale snapshot (after catalog advances to anchor 11) fails closed with ReacquireCurrentSnapshot!
    let proj2 = ImmutableGraphProjection::build(
        GraphUniverse::GSensor,
        ProjectionOrientation::Undirected,
        anchor_at(11),
        history_at(11),
        &auth,
        vec![node("n0"), node("n1")],
        vec![edge("n0", "n1", "link", 1)],
        complete_absence("cov:11"),
        false,
    )?;
    catalog.publish(proj2, &auth, false)?;
    let stale = run_dynamic_connectivity_on_snapshot(
        &view,
        &catalog,
        &auth,
        "hops",
        None,
        DynamicConnectivityLane::OptimizedSegmentTreeRollback,
        &batches,
        &queries,
        registered(&opt_b),
        &|| false,
    );
    let stale_err = match stale {
        Err(e) => e,
        Ok(_) => return Err("expected stale snapshot refusal".into()),
    };
    assert_eq!(stale_err.code(), "ERR-GRAPH-AUTHORIZED-STALE-SNAPSHOT-001");
    assert_eq!(
        stale_err.guidance(),
        SnapshotGuidance::ReacquireCurrentSnapshot
    );

    println!(
        "CAPLOG {{\"bead\":\"FSS-154\",\"lanes\":[\"reference_bfs\",\"segment_tree_rollback\"],\"digest_match\":true,\"states\":4}}"
    );
    Ok(())
}

#[test]
fn fss_155_bridges_and_dominators_authorized_execution_and_privacy_absence() -> TestResult {
    // 1. Undirected bridge analysis with privacy redaction -> AbsenceBoundary downgraded honestly!
    let mut auth_u = ProjectionAuthorityScope::active_for(GraphUniverse::GPhys, 2, 1);
    auth_u.redacted_node_ids.insert("secret-vault".to_owned());
    let proj_u = ImmutableGraphProjection::build(
        GraphUniverse::GPhys,
        ProjectionOrientation::Undirected,
        anchor_at(20),
        history_at(20),
        &auth_u,
        vec![
            node("a"),
            node("b"),
            node("c"),
            node("d"),
            node("secret-vault"),
        ],
        vec![
            edge("a", "b", "walk", 1),
            edge("b", "c", "walk", 1),
            edge("c", "d", "walk", 1),
            edge("d", "secret-vault", "walk", 1),
        ],
        complete_absence("cov:20"),
        false,
    )?;
    let mut catalog = GraphSnapshotCatalog::new();
    catalog.publish(proj_u, &auth_u, false)?;
    let view_u = catalog.acquire_view(GraphUniverse::GPhys, &auth_u, false)?;

    let br_budget = GraphBudget::registered(&view_u.projection().to_undirected_simple_graph()?);
    let br = run_bridges_on_snapshot(&view_u, &catalog, &auth_u, Some("a"), br_budget, &|| false)?;
    assert!(!br.grants_effect_authority);
    // Redacted node MUST downgrade AbsenceBoundary (never claiming CertifiedComplete!).
    assert!(!br.absence_boundary.certifies_absence());
    assert_eq!(br.result.output.bridges.len(), 3);
    assert_eq!(br.result.output.articulation_points.len(), 2);

    // 2. Directed dominators & postdominators over G_evidence!
    let auth_d = ProjectionAuthorityScope::active_for(GraphUniverse::GEvidence, 2, 1);
    let proj_d = ImmutableGraphProjection::build(
        GraphUniverse::GEvidence,
        ProjectionOrientation::Directed,
        anchor_at(21),
        history_at(21),
        &auth_d,
        vec![
            node("root"),
            node("gate"),
            node("left"),
            node("right"),
            node("sink"),
        ],
        vec![
            edge("root", "gate", "supports", 1),
            edge("gate", "left", "supports", 1),
            edge("gate", "right", "supports", 1),
            edge("left", "sink", "supports", 1),
            edge("right", "sink", "supports", 1),
        ],
        complete_absence("cov:21"),
        false,
    )?;
    catalog.publish(proj_d, &auth_d, false)?;
    let view_d = catalog.acquire_view(GraphUniverse::GEvidence, &auth_d, false)?;
    let dom_b = dominators::bound(5, 5);
    let dom = run_dominators_on_snapshot(
        &view_d,
        &catalog,
        &auth_d,
        "hops",
        None,
        "root",
        DominanceDirection::Dominators,
        registered(&dom_b),
        &|| false,
    )?;
    assert!(!dom.grants_effect_authority);
    let sink_idom = dom
        .result
        .output
        .immediate_dominators
        .iter()
        .find(|(n, _)| n == "sink")
        .map(|(_, d)| d.as_str());
    assert_eq!(sink_idom, Some("gate"));

    println!(
        "CAPLOG {{\"bead\":\"FSS-155\",\"bridges\":{},\"sink_idom\":\"gate\",\"redacted_absence_preserved\":true}}",
        br.result.output.bridges.len()
    );
    Ok(())
}

#[test]
fn fss_156_shortest_multi_source_ksp_and_temporal_reachability() -> TestResult {
    let auth_p = ProjectionAuthorityScope::active_for(GraphUniverse::GPhys, 3, 1);
    let proj_p = ImmutableGraphProjection::build(
        GraphUniverse::GPhys,
        ProjectionOrientation::Directed,
        anchor_at(30),
        history_at(30),
        &auth_p,
        vec![node("entry"), node("hall"), node("yard"), node("door")],
        vec![
            edge("entry", "hall", "transit", 2),
            edge("hall", "door", "transit", 2),
            edge("entry", "yard", "transit", 3),
            edge("yard", "door", "transit", 3),
        ],
        complete_absence("cov:30"),
        false,
    )?;
    let mut catalog = GraphSnapshotCatalog::new();
    catalog.publish(proj_p, &auth_p, false)?;
    let view_p = catalog.acquire_view(GraphUniverse::GPhys, &auth_p, false)?;

    let sp_b = paths::sp_bound(Orientation::Directed, 4, 4);
    let sp = run_shortest_paths_on_snapshot(
        &view_p,
        &catalog,
        &auth_p,
        "seconds",
        None,
        "entry",
        Some("door"),
        registered(&sp_b),
        &|| false,
    )?;
    assert_eq!(sp.result.output.distance("door"), Some(4));

    let msd_b = paths::msd_bound(Orientation::Directed, 4, 4);
    let msd = run_multi_source_distances_on_snapshot(
        &view_p,
        &catalog,
        &auth_p,
        "seconds",
        None,
        &["entry", "yard"],
        registered(&msd_b),
        &|| false,
    )?;
    let door_msd = msd
        .result
        .output
        .reachable
        .iter()
        .find(|r| r.node == "door")
        .map(|r| r.distance);
    assert_eq!(door_msd, Some(3));

    let ksp_b = ksp::bound(Orientation::Directed, 4, 4, 2, 8);
    let ks = run_k_shortest_paths_on_snapshot(
        &view_p,
        &catalog,
        &auth_p,
        "seconds",
        None,
        "entry",
        "door",
        2,
        1,
        8,
        registered(&ksp_b),
        &|| false,
    )?;
    assert_eq!(ks.result.output.paths.len(), 2);
    assert_eq!(ks.result.output.paths[0].cost, 4);
    assert_eq!(ks.result.output.paths[1].cost, 6);

    // Temporal reachability gated by G_time snapshot (wrong universe refused!).
    let mut tb = TemporalNetworkBuilder::new("seconds", 20);
    tb.add_node("entry", 5).add_node("door", 5);
    tb.add_transit(
        "entry",
        "door",
        Transit {
            open: 0,
            close: 10,
            min_travel: 3,
            max_travel: 5,
        },
    );
    let net = tb.build()?;
    let tr_b = temporal::bound(2, 1, 20, 8);

    // Refuses G_phys snapshot for temporal reachability (universe is semantic — GRAPH-INV-002!).
    let wrong_u = run_temporal_reachability_on_snapshot(
        &view_p,
        &catalog,
        &auth_p,
        &net,
        "entry",
        (0, 2),
        8,
        registered(&tr_b),
        &|| false,
    );
    assert!(matches!(
        wrong_u,
        Err(AuthorizedRunError::Algorithm(
            GraphError::PreconditionFailed(_)
        ))
    ));

    let auth_t = ProjectionAuthorityScope::active_for(GraphUniverse::GTime, 3, 1);
    let proj_t = ImmutableGraphProjection::build(
        GraphUniverse::GTime,
        ProjectionOrientation::Directed,
        anchor_at(31),
        history_at(31),
        &auth_t,
        vec![node("entry"), node("door")],
        vec![edge("entry", "door", "transit", 3)],
        complete_absence("cov:31"),
        false,
    )?;
    catalog.publish(proj_t, &auth_t, false)?;
    let view_t = catalog.acquire_view(GraphUniverse::GTime, &auth_t, false)?;
    let tr = run_temporal_reachability_on_snapshot(
        &view_t,
        &catalog,
        &auth_t,
        &net,
        "entry",
        (0, 2),
        8,
        registered(&tr_b),
        &|| false,
    )?;
    assert!(!tr.grants_effect_authority);
    assert!(tr.result.output.row("door").is_some());

    println!(
        "CAPLOG {{\"bead\":\"FSS-156\",\"sp_cost\":4,\"ksp_paths\":{},\"temporal_ok\":true}}",
        ks.result.output.paths.len()
    );
    Ok(())
}

#[test]
fn fss_157_matching_k_best_ambiguity_and_min_cost_flow() -> TestResult {
    let auth = ProjectionAuthorityScope::active_for(GraphUniverse::GAssoc, 5, 1);
    let proj_costs = ImmutableGraphProjection::build(
        GraphUniverse::GAssoc,
        ProjectionOrientation::Directed,
        anchor_at(40),
        history_at(40),
        &auth,
        vec![node("s"), node("a"), node("b"), node("t")],
        vec![
            edge("s", "a", "flow", 1),
            edge("a", "t", "flow", 2),
            edge("s", "b", "flow", 4),
            edge("b", "t", "flow", 1),
        ],
        complete_absence("cov:40"),
        false,
    )?;
    let mut catalog = GraphSnapshotCatalog::new();
    catalog.publish(proj_costs, &auth, false)?;
    let view_costs = catalog.acquire_view(GraphUniverse::GAssoc, &auth, false)?;

    let mcf_b = min_cost_flow::bound(4, 4, 1);
    let mcf = run_min_cost_flow_on_snapshots(
        &view_costs,
        &view_costs,
        &catalog,
        &auth,
        "cost",
        "cap",
        "s",
        "t",
        1,
        registered(&mcf_b),
        &|| false,
    )?;
    assert_eq!(mcf.result.output.total_cost, 3);
    assert!(!mcf.grants_effect_authority);

    // K-best assignment preserves near-tied hypotheses explicitly!
    let mut ab = AssignmentProblemBuilder::new("score");
    ab.add_left("trk-1").add_left("trk-2");
    ab.add_right("det-a").add_right("det-b");
    ab.allow("trk-1", "det-a", 10)
        .allow("trk-1", "det-b", 11)
        .allow("trk-2", "det-a", 11)
        .allow("trk-2", "det-b", 10);
    let prob = ab.build()?;
    let m_b = assignment::match_bound(4, 4);
    let best1 = run_optimal_assignment_on_snapshot(
        &view_costs,
        &catalog,
        &auth,
        &prob,
        NonAssignment::MaximumCardinality,
        registered(&m_b),
        &|| false,
    )?;
    assert_eq!(best1.result.output.assignment.objective, 20);

    let kb_b = assignment::multimatch_bound(4, 4, 2);
    let kbest = run_k_best_assignments_on_snapshot(
        &view_costs,
        &catalog,
        &auth,
        &prob,
        NonAssignment::MaximumCardinality,
        2,
        registered(&kb_b),
        &|| false,
    )?;
    assert_eq!(kbest.result.output.assignments.len(), 2);
    assert_eq!(kbest.result.output.assignments[0].objective, 20);
    assert_eq!(kbest.result.output.assignments[1].objective, 22);

    println!(
        "CAPLOG {{\"bead\":\"FSS-157\",\"mcf_cost\":3,\"kbest_solutions\":2,\"ambiguity_preserved\":true}}"
    );
    Ok(())
}

#[test]
fn fss_158_max_flow_min_cut_and_gomory_hu_tree() -> TestResult {
    let auth = ProjectionAuthorityScope::active_for(GraphUniverse::GSensor, 6, 1);
    let proj = ImmutableGraphProjection::build(
        GraphUniverse::GSensor,
        ProjectionOrientation::Undirected,
        anchor_at(50),
        history_at(50),
        &auth,
        vec![node("src"), node("mid1"), node("mid2"), node("dst")],
        vec![
            edge("src", "mid1", "uplink", 5),
            edge("src", "mid2", "uplink", 3),
            edge("mid1", "dst", "uplink", 2),
            edge("mid2", "dst", "uplink", 4),
        ],
        complete_absence("cov:50"),
        false,
    )?;
    let mut catalog = GraphSnapshotCatalog::new();
    catalog.publish(proj, &auth, false)?;
    let view = catalog.acquire_view(GraphUniverse::GSensor, &auth, false)?;

    let fl_b = flow::bound(4, 4);
    let fl = run_max_flow_min_cut_on_snapshot(
        &view,
        &catalog,
        &auth,
        "mbps",
        None,
        "src",
        "dst",
        CutMode::Arcs,
        registered(&fl_b),
        &|| false,
    )?;
    match &fl.result.output {
        FlowOutput::Arcs(arc_cut) => assert_eq!(arc_cut.value, 5),
        other => return Err(format!("expected Arcs flow cut, got {other:?}").into()),
    }
    assert!(!fl.grants_effect_authority);

    let gh_b = gomory_hu::bound(4, 4);
    let gh = run_gomory_hu_on_snapshot(
        &view,
        &catalog,
        &auth,
        "mbps",
        None,
        registered(&gh_b),
        &|| false,
    )?;
    assert_eq!(gh.result.output.min_cut("src", "dst"), Some(5));

    println!("CAPLOG {{\"bead\":\"FSS-158\",\"max_flow\":5,\"gomory_hu_src_dst_cut\":5}}");
    Ok(())
}

#[test]
fn fss_159_scc_condensation_and_topological_critical_path() -> TestResult {
    // 1. Cyclic graph -> SCC exposes explicit cyclic component, Topo refuses cleanly!
    let auth = ProjectionAuthorityScope::active_for(GraphUniverse::GEffect, 7, 1);
    let cyclic = ImmutableGraphProjection::build(
        GraphUniverse::GEffect,
        ProjectionOrientation::Directed,
        anchor_at(60),
        history_at(60),
        &auth,
        vec![node("a"), node("b"), node("c")],
        vec![
            edge("a", "b", "dep", 1),
            edge("b", "a", "dep", 1),
            edge("b", "c", "dep", 1),
        ],
        complete_absence("cov:60"),
        false,
    )?;
    let mut catalog = GraphSnapshotCatalog::new();
    catalog.publish(cyclic, &auth, false)?;
    let view_cyc = catalog.acquire_view(GraphUniverse::GEffect, &auth, false)?;

    let scc_b = scc::bound(3, 3);
    let scc_run = run_scc_on_snapshot(
        &view_cyc,
        &catalog,
        &auth,
        "ms",
        None,
        registered(&scc_b),
        &|| false,
    )?;
    assert_eq!(scc_run.result.output.cyclic().count(), 1);
    assert_eq!(scc_run.result.output.condensation_arcs.len(), 1);

    let topo_b = topo::bound(3, 3);
    let cyc_refused = run_topological_schedule_on_snapshot(
        &view_cyc,
        &catalog,
        &auth,
        "ms",
        None,
        registered(&topo_b),
        &|| false,
    );
    assert!(matches!(
        cyc_refused,
        Err(AuthorizedRunError::Algorithm(
            GraphError::PreconditionFailed(_)
        ))
    ));

    // 2. Acyclic DAG -> exact topological order, frontiers, and critical-path makespan!
    let dag = ImmutableGraphProjection::build(
        GraphUniverse::GEffect,
        ProjectionOrientation::Directed,
        anchor_at(61),
        history_at(61),
        &auth,
        vec![node("prepare"), node("verify"), node("commit")],
        vec![
            edge("prepare", "verify", "dep", 5),
            edge("verify", "commit", "dep", 7),
        ],
        complete_absence("cov:61"),
        false,
    )?;
    catalog.publish(dag, &auth, false)?;
    let view_dag = catalog.acquire_view(GraphUniverse::GEffect, &auth, false)?;
    let dag_run = run_topological_schedule_on_snapshot(
        &view_dag,
        &catalog,
        &auth,
        "ms",
        None,
        registered(&topo_b),
        &|| false,
    )?;
    assert_eq!(
        dag_run.result.output.order,
        vec![
            "prepare".to_owned(),
            "verify".to_owned(),
            "commit".to_owned()
        ]
    );
    assert_eq!(dag_run.result.output.makespan, 12);
    assert!(!dag_run.grants_effect_authority);

    println!("CAPLOG {{\"bead\":\"FSS-159\",\"cyclic_sccs\":1,\"dag_makespan\":12}}");
    Ok(())
}

#[test]
fn fss_160_set_cover_submodular_steiner_and_interdiction() -> TestResult {
    let auth = ProjectionAuthorityScope::active_for(GraphUniverse::GPhys, 8, 1);
    let proj = ImmutableGraphProjection::build(
        GraphUniverse::GPhys,
        ProjectionOrientation::Undirected,
        anchor_at(70),
        history_at(70),
        &auth,
        vec![node("entry"), node("corridor"), node("yard"), node("vault")],
        vec![
            edge("entry", "corridor", "walk", 2),
            edge("corridor", "vault", "walk", 2),
            edge("entry", "yard", "walk", 3),
            edge("yard", "vault", "walk", 3),
        ],
        complete_absence("cov:70"),
        false,
    )?;
    let mut catalog = GraphSnapshotCatalog::new();
    catalog.publish(proj, &auth, false)?;
    let view = catalog.acquire_view(GraphUniverse::GPhys, &auth, false)?;

    // 1. Set cover with mandatory & privacy-excluded cameras!
    let sets = vec![
        CoverSet::new("cam-a", &["z1".to_owned(), "z2".to_owned()])?,
        CoverSet::new("cam-b", &["z2".to_owned(), "z3".to_owned()])?,
        CoverSet::new(
            "cam-private",
            &["z1".to_owned(), "z2".to_owned(), "z3".to_owned()],
        )?,
    ];
    let sc_prob = SetCoverProblem::new(
        &["z1".to_owned(), "z2".to_owned(), "z3".to_owned()],
        &sets,
        &[],
        &["cam-private".to_owned()],
        2,
    )?;
    let sc = run_set_cover_on_snapshot(
        &view,
        &catalog,
        &auth,
        &sc_prob,
        CoverMethod::ExactSmall,
        CoverBudget::default(),
        &|| false,
    )?;
    assert!(sc.result.uncovered().is_empty());
    assert!(!sc.result.selected().contains(&"cam-private".to_owned()));
    assert!(!sc.grants_effect_authority);

    // 2. Submodular active-perception selection under cost ceiling!
    let sub_prob = SubmodularProblem::new(
        sc_prob,
        &BTreeMap::from([
            ("z1".to_owned(), 10_u64),
            ("z2".to_owned(), 8),
            ("z3".to_owned(), 6),
        ]),
        &BTreeMap::from([
            ("cam-a".to_owned(), 4_u64),
            ("cam-b".to_owned(), 4),
            ("cam-private".to_owned(), 1),
        ]),
        4,
    )?;
    let sub = run_submodular_on_snapshot(
        &view,
        &catalog,
        &auth,
        &sub_prob,
        CoverBudget::default(),
        &|| false,
    )?;
    assert_eq!(sub.result.selected(), &["cam-a".to_owned()]);

    // 3. Steiner tree over G_phys terminals!
    let st_b = steiner::bound(4, 4, 2);
    let st = run_steiner_on_snapshot(
        &view,
        &catalog,
        &auth,
        "meters",
        None,
        &["entry", "vault"],
        registered(&st_b),
        &|| false,
    )?;
    assert_eq!(st.result.output.total_weight, 4);

    // 4. Interdiction query (minimum sensor disable cost opening a blind walk entry -> vault)!
    let iq = InterdictionQuery {
        observers: BTreeMap::from([
            ("corridor".to_owned(), BTreeSet::from(["cam-a".to_owned()])),
            ("yard".to_owned(), BTreeSet::from(["cam-b".to_owned()])),
        ]),
        costs: BTreeMap::from([("cam-a".to_owned(), 1_u64), ("cam-b".to_owned(), 2)]),
        entries: BTreeSet::from(["entry".to_owned()]),
        targets: BTreeSet::from(["vault".to_owned()]),
    };
    let int_b = interdiction::bound(4, 4, 2);
    let inter = run_interdiction_on_snapshot(
        &view,
        &catalog,
        &auth,
        "meters",
        None,
        &iq,
        registered(&int_b),
        &|| false,
    )?;
    assert!(!inter.grants_effect_authority);
    let disabled_count = match &inter.result.output.outcome {
        InterdictionOutcome::Interdiction {
            sensors,
            cost,
            exact,
            ..
        } => {
            assert_eq!(*cost, 1);
            assert!(*exact);
            assert_eq!(sensors, &vec!["cam-a".to_owned()]);
            sensors.len()
        }
        other => return Err(format!("expected Interdiction outcome, got {other:?}").into()),
    };

    println!(
        "CAPLOG {{\"bead\":\"FSS-160\",\"set_cover_selected\":{},\"submodular_selected\":{},\"steiner_weight\":4,\"interdiction_disabled\":{disabled_count}}}",
        sc.result.selected().len(),
        sub.result.selected().len()
    );
    Ok(())
}

#[test]
fn fresh_eyes_side_input_privacy_universe_single_anchor_and_early_cancel_guards() -> TestResult {
    // 1. Side-input privacy redaction MUST fail closed with AuthorityMismatch BEFORE expansion!
    let mut auth_assoc = ProjectionAuthorityScope::active_for(GraphUniverse::GAssoc, 9, 1);
    auth_assoc
        .redacted_node_ids
        .insert("redacted-trk".to_owned());
    let proj_assoc = ImmutableGraphProjection::build(
        GraphUniverse::GAssoc,
        ProjectionOrientation::Directed,
        anchor_at(80),
        history_at(80),
        &auth_assoc,
        vec![node("trk-1"), node("det-1"), node("redacted-trk")],
        vec![edge("trk-1", "det-1", "match", 1)],
        complete_absence("cov:80"),
        false,
    )?;
    let mut catalog = GraphSnapshotCatalog::new();
    catalog.publish(proj_assoc, &auth_assoc, false)?;
    let view_assoc = catalog.acquire_view(GraphUniverse::GAssoc, &auth_assoc, false)?;

    let mut ab_red = AssignmentProblemBuilder::new("score");
    ab_red
        .add_left("redacted-trk")
        .add_right("det-1")
        .allow("redacted-trk", "det-1", 5);
    let prob_red = ab_red.build()?;
    let m_b = assignment::match_bound(2, 1);
    let red_match = run_optimal_assignment_on_snapshot(
        &view_assoc,
        &catalog,
        &auth_assoc,
        &prob_red,
        NonAssignment::MaximumCardinality,
        registered(&m_b),
        &|| false,
    );
    assert!(matches!(
        red_match,
        Err(AuthorizedRunError::Snapshot(
            fss_graph_algorithms::snapshot_view::SnapshotViewError::AuthorityMismatch(_)
        ))
    ));
    let kb_b = assignment::multimatch_bound(2, 1, 1);
    let red_kbest = run_k_best_assignments_on_snapshot(
        &view_assoc,
        &catalog,
        &auth_assoc,
        &prob_red,
        NonAssignment::MaximumCardinality,
        1,
        registered(&kb_b),
        &|| false,
    );
    assert!(matches!(
        red_kbest,
        Err(AuthorizedRunError::Snapshot(
            fss_graph_algorithms::snapshot_view::SnapshotViewError::AuthorityMismatch(_)
        ))
    ));

    // 2. Wrong universe (G_phys instead of G_assoc) refused on assignment & k-best assignment!
    let mut auth_phys = ProjectionAuthorityScope::active_for(GraphUniverse::GPhys, 9, 1);
    auth_phys.redacted_node_ids.insert("secret-zone".to_owned());
    let proj_phys = ImmutableGraphProjection::build(
        GraphUniverse::GPhys,
        ProjectionOrientation::Undirected,
        anchor_at(81),
        history_at(81),
        &auth_phys,
        vec![node("entry"), node("vault"), node("secret-zone")],
        vec![edge("entry", "vault", "walk", 2)],
        complete_absence("cov:81"),
        false,
    )?;
    catalog.publish(proj_phys, &auth_phys, false)?;
    let view_phys = catalog.acquire_view(GraphUniverse::GPhys, &auth_phys, false)?;

    let mut ab_ok = AssignmentProblemBuilder::new("score");
    ab_ok
        .add_left("trk-1")
        .add_right("det-1")
        .allow("trk-1", "det-1", 5);
    let prob_ok = ab_ok.build()?;
    assert!(matches!(
        run_optimal_assignment_on_snapshot(
            &view_phys,
            &catalog,
            &auth_phys,
            &prob_ok,
            NonAssignment::MaximumCardinality,
            registered(&m_b),
            &|| false,
        ),
        Err(AuthorizedRunError::Algorithm(
            GraphError::PreconditionFailed(_)
        ))
    ));
    assert!(matches!(
        run_k_best_assignments_on_snapshot(
            &view_phys,
            &catalog,
            &auth_phys,
            &prob_ok,
            NonAssignment::MaximumCardinality,
            1,
            registered(&kb_b),
            &|| false,
        ),
        Err(AuthorizedRunError::Algorithm(
            GraphError::PreconditionFailed(_)
        ))
    ));

    // 3. Redacted entity in set-cover, submodular, interdiction, temporal, and dynconn side inputs refused!
    let sc_red = SetCoverProblem::new(
        &["secret-zone".to_owned()],
        &[CoverSet::new("cam-a", &["secret-zone".to_owned()])?],
        &[],
        &[],
        1,
    )?;
    assert!(matches!(
        run_set_cover_on_snapshot(
            &view_phys,
            &catalog,
            &auth_phys,
            &sc_red,
            CoverMethod::ExactSmall,
            CoverBudget::default(),
            &|| false,
        ),
        Err(AuthorizedRunError::Snapshot(
            fss_graph_algorithms::snapshot_view::SnapshotViewError::AuthorityMismatch(_)
        ))
    ));
    let sub_red = SubmodularProblem::new(
        sc_red,
        &BTreeMap::from([("secret-zone".to_owned(), 5_u64)]),
        &BTreeMap::from([("cam-a".to_owned(), 2_u64)]),
        5,
    )?;
    assert!(matches!(
        run_submodular_on_snapshot(
            &view_phys,
            &catalog,
            &auth_phys,
            &sub_red,
            CoverBudget::default(),
            &|| false,
        ),
        Err(AuthorizedRunError::Snapshot(
            fss_graph_algorithms::snapshot_view::SnapshotViewError::AuthorityMismatch(_)
        ))
    ));
    let iq_red = InterdictionQuery {
        observers: BTreeMap::from([(
            "secret-zone".to_owned(),
            BTreeSet::from(["cam-a".to_owned()]),
        )]),
        costs: BTreeMap::from([("cam-a".to_owned(), 1_u64)]),
        entries: BTreeSet::from(["entry".to_owned()]),
        targets: BTreeSet::from(["vault".to_owned()]),
    };
    let int_b = interdiction::bound(2, 1, 1);
    assert!(matches!(
        run_interdiction_on_snapshot(
            &view_phys,
            &catalog,
            &auth_phys,
            "meters",
            None,
            &iq_red,
            registered(&int_b),
            &|| false,
        ),
        Err(AuthorizedRunError::Snapshot(
            fss_graph_algorithms::snapshot_view::SnapshotViewError::AuthorityMismatch(_)
        ))
    ));
    let dyn_b = dynconn::bound(2, 1, 2, 1);
    assert!(matches!(
        run_dynamic_connectivity_on_snapshot(
            &view_phys,
            &catalog,
            &auth_phys,
            "hops",
            None,
            DynamicConnectivityLane::ReferencePerStateBfs,
            &[vec![EdgeUpdate::Insert(
                "entry".to_owned(),
                "secret-zone".to_owned()
            )]],
            &[(0, "entry", "vault")],
            registered(&dyn_b),
            &|| false,
        ),
        Err(AuthorizedRunError::Snapshot(
            fss_graph_algorithms::snapshot_view::SnapshotViewError::AuthorityMismatch(_)
        ))
    ));

    // 4. Temporal network containing a redacted node refused BEFORE temporal_reachability!
    let mut auth_t = ProjectionAuthorityScope::active_for(GraphUniverse::GTime, 9, 1);
    auth_t.redacted_node_ids.insert("secret-zone".to_owned());
    let proj_t = ImmutableGraphProjection::build(
        GraphUniverse::GTime,
        ProjectionOrientation::Directed,
        anchor_at(82),
        history_at(82),
        &auth_t,
        vec![node("entry"), node("vault"), node("secret-zone")],
        vec![edge("entry", "vault", "transit", 1)],
        complete_absence("cov:82"),
        false,
    )?;
    catalog.publish(proj_t, &auth_t, false)?;
    let view_t = catalog.acquire_view(GraphUniverse::GTime, &auth_t, false)?;
    let mut tb_red = TemporalNetworkBuilder::new("seconds", 10);
    tb_red.add_node("entry", 2).add_node("secret-zone", 2);
    let net_red = tb_red.build()?;
    let tr_b = temporal::bound(2, 0, 10, 4);
    assert!(matches!(
        run_temporal_reachability_on_snapshot(
            &view_t,
            &catalog,
            &auth_t,
            &net_red,
            "entry",
            (0, 1),
            4,
            registered(&tr_b),
            &|| false,
        ),
        Err(AuthorizedRunError::Snapshot(
            fss_graph_algorithms::snapshot_view::SnapshotViewError::AuthorityMismatch(_)
        ))
    ));

    // 5. Cross-anchor AND cross-universe min-cost flow refused (GRAPH-INV-001 / GRAPH-INV-002)!
    let mut auth_both = ProjectionAuthorityScope::active_for(GraphUniverse::GAssoc, 9, 1);
    auth_both.allowed_universes.insert(GraphUniverse::GTime);
    let mut mcf_catalog = GraphSnapshotCatalog::new();
    let p_mcf_a = ImmutableGraphProjection::build(
        GraphUniverse::GAssoc,
        ProjectionOrientation::Directed,
        anchor_at(83),
        history_at(83),
        &auth_both,
        vec![node("entry"), node("vault")],
        vec![edge("entry", "vault", "flow", 1)],
        complete_absence("cov:83"),
        false,
    )?;
    let p_mcf_b_diff_anchor = ImmutableGraphProjection::build(
        GraphUniverse::GTime,
        ProjectionOrientation::Directed,
        anchor_at(84),
        history_at(84),
        &auth_both,
        vec![node("entry"), node("vault")],
        vec![edge("entry", "vault", "flow", 1)],
        complete_absence("cov:84"),
        false,
    )?;
    mcf_catalog.publish(p_mcf_a, &auth_both, false)?;
    mcf_catalog.publish(p_mcf_b_diff_anchor, &auth_both, false)?;
    let v_mcf_a = mcf_catalog.acquire_view(GraphUniverse::GAssoc, &auth_both, false)?;
    let v_mcf_diff_anchor = mcf_catalog.acquire_view(GraphUniverse::GTime, &auth_both, false)?;
    let mcf_b = min_cost_flow::bound(2, 1, 1);
    assert!(matches!(
        run_min_cost_flow_on_snapshots(
            &v_mcf_a,
            &v_mcf_diff_anchor,
            &mcf_catalog,
            &auth_both,
            "cost",
            "cap",
            "entry",
            "vault",
            1,
            registered(&mcf_b),
            &|| false,
        ),
        Err(AuthorizedRunError::Algorithm(
            GraphError::PreconditionFailed(msg)
        )) if msg.contains("same ledger anchor")
    ));
    let p_mcf_a_84 = ImmutableGraphProjection::build(
        GraphUniverse::GAssoc,
        ProjectionOrientation::Directed,
        anchor_at(84),
        history_at(84),
        &auth_both,
        vec![node("entry"), node("vault")],
        vec![edge("entry", "vault", "flow", 1)],
        complete_absence("cov:84"),
        false,
    )?;
    mcf_catalog.publish(p_mcf_a_84, &auth_both, false)?;
    let v_mcf_a_84 = mcf_catalog.acquire_view(GraphUniverse::GAssoc, &auth_both, false)?;
    assert!(matches!(
        run_min_cost_flow_on_snapshots(
            &v_mcf_a_84,
            &v_mcf_diff_anchor,
            &mcf_catalog,
            &auth_both,
            "cost",
            "cap",
            "entry",
            "vault",
            1,
            registered(&mcf_b),
            &|| false,
        ),
        Err(AuthorizedRunError::Algorithm(
            GraphError::PreconditionFailed(msg)
        )) if msg.contains("same universe")
    ));

    // 6. Early cooperative cancellation fires BEFORE lifetimes() in both dynconn lanes!
    let wg = view_phys.projection().to_weighted_graph("hops", None)?;
    let invalid_batches = vec![vec![EdgeUpdate::Delete(
        "nonexistent".to_owned(),
        "entry".to_owned(),
    )]];
    assert_eq!(
        dynconn::dynamic_connectivity_with_cancel(
            &wg,
            &invalid_batches,
            &[],
            registered(&dyn_b),
            &|| true,
        ),
        Err(GraphError::Cancelled)
    );
    assert_eq!(
        dynconn::dynamic_connectivity_reference_with_cancel(
            &wg,
            &invalid_batches,
            &[],
            registered(&dyn_b),
            &|| true,
        ),
        Err(GraphError::Cancelled)
    );

    // 7. Min-cost flow MUST NOT launder an uncertified/redacted capacity snapshot into CertifiedComplete!
    let mut auth_mcf_red = ProjectionAuthorityScope::active_for(GraphUniverse::GAssoc, 10, 1);
    auth_mcf_red
        .redacted_node_ids
        .insert("hidden-cap".to_owned());
    let mut mcf_cat_a = GraphSnapshotCatalog::new();
    let p_cost_clean = ImmutableGraphProjection::build(
        GraphUniverse::GAssoc,
        ProjectionOrientation::Directed,
        anchor_at(85),
        history_at(85),
        &auth_mcf_red,
        vec![node("s"), node("t")],
        vec![edge("s", "t", "flow", 2)],
        complete_absence("cov:85-cost"),
        false,
    )?;
    let p_cap_redacted = ImmutableGraphProjection::build(
        GraphUniverse::GAssoc,
        ProjectionOrientation::Directed,
        anchor_at(85),
        history_at(85),
        &auth_mcf_red,
        vec![node("s"), node("t"), node("hidden-cap")],
        vec![
            edge("s", "t", "flow", 3),
            edge("s", "hidden-cap", "flow", 1),
        ],
        complete_absence("cov:85-cap"),
        false,
    )?;
    assert!(p_cost_clean.absence_boundary().certifies_absence());
    assert!(!p_cap_redacted.absence_boundary().certifies_absence());
    mcf_cat_a.publish(p_cost_clean, &auth_mcf_red, false)?;
    let v_cost_clean = mcf_cat_a.acquire_view(GraphUniverse::GAssoc, &auth_mcf_red, false)?;
    // Re-publish capacity projection at same anchor/universe in a paired catalog? Wait:
    // authorize_snapshot_execution requires both views current in the same catalog, OR same view.
    // Publish p_cap_redacted in mcf_cat_a and test redacted-cost + redacted-cap preservation:
    mcf_cat_a.publish(p_cap_redacted, &auth_mcf_red, false)?;
    let v_cap_red = mcf_cat_a.acquire_view(GraphUniverse::GAssoc, &auth_mcf_red, false)?;
    // Verify stale v_cost_clean is rejected against v_cap_red, and valid v_cap_red preserves uncertified boundary!
    assert!(matches!(
        run_min_cost_flow_on_snapshots(
            &v_cost_clean,
            &v_cap_red,
            &mcf_cat_a,
            &auth_mcf_red,
            "cost",
            "cap",
            "s",
            "t",
            1,
            registered(&mcf_b),
            &|| false,
        ),
        Err(AuthorizedRunError::StaleSnapshot(_))
    ));
    let mcf_red_receipt = run_min_cost_flow_on_snapshots(
        &v_cap_red,
        &v_cap_red,
        &mcf_cat_a,
        &auth_mcf_red,
        "cost",
        "cap",
        "s",
        "t",
        1,
        registered(&mcf_b),
        &|| false,
    )?;
    assert!(!mcf_red_receipt.absence_boundary.certifies_absence());
    assert!(!mcf_red_receipt.grants_effect_authority);
    Ok(())
}
