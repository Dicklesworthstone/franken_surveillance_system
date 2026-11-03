#![forbid(unsafe_code)]
//! Independent tiny edge-subset/path-cover oracle, conservative time and complete provenance.

mod common;

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use common::{Rng, TestResult};
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm, LedgerAnchor};
use fss_graph_algorithms::GraphError;
use fss_graph_algorithms::assignment::{self, AssignmentProblemBuilder, NonAssignment};
use fss_graph_algorithms::certified::{Budget, CertifiedOutput, CertifiedRun, check_witness};
use fss_graph_algorithms::continuity::{
    self, ContinuityOutput, ContinuityQuery, PathCover, RejectionReason, Scope, Tracklet,
    TrackletSupport, Transition,
};

fn pin(text: &str) -> ContentDigest {
    ContentDigest::sha256(text.as_bytes())
}
fn budget() -> Budget {
    Budget::new(continuity::MAX_WORK_UNITS, continuity::MAX_OUTPUT_ENTRIES)
}

fn tracklet(id: &str, camera: &str, start: [i64; 2], end: [i64; 2]) -> Tracklet {
    Tracklet {
        id: id.into(),
        camera: camera.into(),
        camera_generation: pin(&format!("camera:{camera}")),
        calibration: pin(&format!("calibration:{camera}")),
        model: pin("model"),
        evidence: vec![
            pin(&format!("evidence:{id}:1")),
            pin(&format!("evidence:{id}:2")),
        ],
        start,
        end,
        support: TrackletSupport::Declared,
    }
}

fn transition(from: &str, to: &str, transit: [u64; 2], cost: u64) -> Transition {
    Transition {
        from: from.into(),
        to: to.into(),
        transit,
        cost,
        basis: pin(&format!("transit:{from}:{to}")),
    }
}

fn query() -> ContinuityQuery {
    ContinuityQuery {
        scope: Scope {
            property: "home".into(),
            session: "visit-1".into(),
            privacy_policy: pin("owner-local-policy"),
            generation: pin("generation"),
            clock: pin("clock"),
        },
        time_unit: "milliseconds".into(),
        cost_unit: "declared-cost".into(),
        birth_cost: 7,
        end_cost: 3,
        k: 8,
        tracklets: vec![
            tracklet("a", "entry", [0, 1], [3, 4]),
            tracklet("b", "walkway", [10, 11], [13, 14]),
            tracklet("c", "porch", [20, 21], [23, 24]),
        ],
        transitions: vec![
            transition("a", "b", [6, 8], 1),
            transition("b", "c", [6, 8], 2),
            transition("a", "c", [16, 18], 4),
        ],
    }
}

type OracleEdge = (usize, usize, u64);
type OracleAssignment = (u64, Vec<usize>);

/// Independently enumerates endpoint choices, then every subset of admitted physical edges.
/// No assignment builder, Hungarian/Murty solve or production gate function is used.
fn exhaustive(query: &ContinuityQuery) -> (Vec<OracleEdge>, Vec<OracleAssignment>) {
    let mut tracklets: Vec<&Tracklet> = query.tracklets.iter().collect();
    tracklets.sort_by_key(|item| &item.id);
    let positions: BTreeMap<&str, usize> = tracklets
        .iter()
        .enumerate()
        .map(|(i, t)| (t.id.as_str(), i))
        .collect();
    let n = tracklets.len();
    let mut edges = Vec::new();
    for item in &query.transitions {
        let (a, b) = (positions[item.from.as_str()], positions[item.to.as_str()]);
        let (from, to) = (tracklets[a], tracklets[b]);
        let compatible = from.support == TrackletSupport::Declared
            && to.support == TrackletSupport::Declared
            && from.model == to.model
            && (from.camera != to.camera
                || (from.camera_generation == to.camera_generation
                    && from.calibration == to.calibration));
        let mut all_times_fit = true;
        for departure in from.end {
            for arrival in to.start {
                let duration = i128::from(arrival) - i128::from(departure);
                all_times_fit &= duration > 0
                    && duration >= i128::from(item.transit[0])
                    && duration <= i128::from(item.transit[1]);
            }
        }
        if compatible && all_times_fit {
            edges.push((a, b, item.cost));
        }
    }
    edges.sort_unstable();
    assert!(edges.len() <= 15, "oracle must remain exhaustive and tiny");
    let mut assignments = Vec::new();
    for mask in 0..(1_usize << edges.len()) {
        let mut next = vec![n; n];
        let mut incoming = vec![false; n];
        let mut legal = true;
        let mut link_cost = 0;
        let mut count = 0;
        for (i, &(a, b, cost)) in edges.iter().enumerate() {
            if mask & (1 << i) == 0 {
                continue;
            }
            if next[a] != n || incoming[b] {
                legal = false;
                break;
            }
            next[a] = b;
            incoming[b] = true;
            link_cost += cost;
            count += 1;
        }
        if !legal {
            continue;
        }
        // Check acyclicity independently, rather than assuming the gate's DAG claim.
        for start in 0..n {
            let mut at = start;
            let mut seen = BTreeSet::new();
            while at != n {
                if !seen.insert(at) {
                    legal = false;
                    break;
                }
                at = next[at];
            }
        }
        if legal {
            assignments.push((
                link_cost + (n - count) as u64 * (query.birth_cost + query.end_cost),
                next,
            ));
        }
    }
    assignments.sort_unstable();
    (edges, assignments)
}

fn cover_tuple(cover: &PathCover, members: &[String]) -> Vec<usize> {
    let n = members.len();
    let positions: BTreeMap<&str, usize> = members
        .iter()
        .enumerate()
        .map(|(i, id)| (id.as_str(), i))
        .collect();
    let mut tuple = vec![n; n];
    let mut flattened: Vec<&String> = cover.paths.iter().flatten().collect();
    flattened.sort();
    assert_eq!(
        flattened,
        members.iter().collect::<Vec<_>>(),
        "every tracklet occurs exactly once"
    );
    let mut path_links = Vec::new();
    for path in &cover.paths {
        assert!(!path.is_empty());
        for pair in path.windows(2) {
            path_links.push((&pair[0], &pair[1]));
        }
    }
    path_links.sort_unstable();
    assert_eq!(
        path_links,
        cover
            .links
            .iter()
            .map(|edge| (&edge.from, &edge.to))
            .collect::<Vec<_>>()
    );
    for edge in &cover.links {
        tuple[positions[edge.from.as_str()]] = positions[edge.to.as_str()];
    }
    let starts: Vec<String> = cover
        .paths
        .iter()
        .filter_map(|path| path.first().cloned())
        .collect();
    let mut ends: Vec<String> = cover
        .paths
        .iter()
        .filter_map(|path| path.last().cloned())
        .collect();
    ends.sort();
    assert_eq!(starts, cover.starts);
    assert_eq!(ends, cover.ends);
    assert_eq!(
        cover.total_cost,
        cover.link_cost + cover.birth_cost + cover.end_cost
    );
    tuple
}

fn check(query: &ContinuityQuery, run: &CertifiedRun<ContinuityOutput>) {
    let output = &run.output;
    let n = query.tracklets.len();
    let (edges, expected) = exhaustive(query);
    assert_eq!(output.transitions.len(), n * (n - 1));
    assert_eq!(
        output
            .transitions
            .iter()
            .filter(|row| row.declared.is_some())
            .count(),
        query.transitions.len()
    );
    assert!(
        output
            .transitions
            .iter()
            .all(|row| row.admitted == row.reasons.is_empty())
    );
    let members = &output.family.members;
    let mapped_edges: Vec<_> = edges
        .iter()
        .map(|&(a, b, cost)| (members[a].clone(), members[b].clone(), cost))
        .collect();
    assert_eq!(
        mapped_edges,
        output
            .family
            .edges
            .iter()
            .map(|edge| (edge.from.clone(), edge.to.clone(), edge.cost))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        output.family.all_singletons.total_cost,
        n as u64 * (query.birth_cost + query.end_cost)
    );
    assert_eq!(
        cover_tuple(&output.family.all_singletons, members),
        vec![n; n]
    );
    let actual: Vec<_> = output
        .alternatives
        .iter()
        .map(|cover| (cover.total_cost, cover_tuple(cover, members)))
        .collect();
    assert_eq!(
        actual,
        expected
            .iter()
            .take(query.k as usize)
            .cloned()
            .collect::<Vec<_>>()
    );
    assert_eq!(
        output.displayed_prefix_complete,
        expected.len() < query.k as usize
    );
    assert_eq!(
        output.matching.output.exhausted,
        output.displayed_prefix_complete
    );
    assert_eq!(
        output.matching.output.assignments.len(),
        output.alternatives.len()
    );
    assert_eq!(
        run.counters["assignment_operations"],
        output.matching.operations
    );
    assert_eq!(run.operations, run.counters.values().sum::<u64>());
    assert_eq!(run.output_entries, output.entries());
}

fn tiny_query(seed: u64) -> ContinuityQuery {
    let mut rng = Rng(seed ^ 0x8fa2_91e3);
    let n = 2 + rng.below(4);
    let mut query = query();
    query.birth_cost = rng.below(5) as u64;
    query.end_cost = rng.below(5) as u64;
    query.k = [1, 2, 3, 7, 32][rng.below(5)];
    query.tracklets = (0..n)
        .map(|i| {
            let t = i as i64 * 10;
            let mut item = tracklet(
                &format!("t{}", (i * 7 + 2) % 11),
                &format!("camera{}", i % 3),
                [t, t + rng.below(3) as i64],
                [t + 3, t + 5],
            );
            if rng.chance(60) {
                item.support = TrackletSupport::Missing;
                item.evidence.clear();
            }
            item
        })
        .collect();
    query.transitions.clear();
    for a in 0..n {
        for b in 0..n {
            if a == b || !rng.chance(800) {
                continue;
            }
            let transit = if rng.chance(700) { [0, 100] } else { [8, 10] };
            query.transitions.push(transition(
                &query.tracklets[a].id,
                &query.tracklets[b].id,
                transit,
                rng.below(7) as u64,
            ));
        }
    }
    query
}

#[test]
fn seeded_edge_subset_oracle_proves_ordered_prefix_and_full_implicit_family() -> TestResult {
    let mut branching = 0;
    let mut truncated = 0;
    for seed in 0..256 {
        let query = tiny_query(seed);
        let run = continuity::plan(&query, budget())?;
        check(&query, &run);
        branching += usize::from(run.output.family.edges.len() > 2);
        truncated += usize::from(!run.output.displayed_prefix_complete);
        let mut permuted = query.clone();
        let mut rng = Rng(seed + 42);
        rng.shuffle(&mut permuted.tracklets);
        rng.shuffle(&mut permuted.transitions);
        for item in &mut permuted.tracklets {
            rng.shuffle(&mut item.evidence);
        }
        assert_eq!(
            continuity::plan(&permuted, budget())?,
            run,
            "permutation seed {seed}"
        );
    }
    assert!(branching > 50 && truncated > 50);
    Ok(())
}

#[test]
fn three_camera_path_preserves_every_member_and_explicit_no_handoff_alternative() -> TestResult {
    let query = query();
    let run = continuity::plan(&query, budget())?;
    check(&query, &run);
    assert_eq!(run.output.alternatives[0].paths, vec![vec!["a", "b", "c"]]);
    assert_eq!(run.output.alternatives[0].link_cost, 3);
    assert_eq!(run.output.alternatives[0].total_cost, 13);
    assert_eq!(
        run.output.family.all_singletons.paths,
        vec![vec!["a"], vec!["b"], vec!["c"]]
    );
    assert_eq!(run.output.family.all_singletons.total_cost, 30);
    Ok(())
}

#[test]
fn birth_end_prices_allow_split_paths_and_zero_cost_ties_use_assignment_order() -> TestResult {
    let mut query = query();
    query.birth_cost = 0;
    query.end_cost = 0;
    query.k = 32;
    let run = continuity::plan(&query, budget())?;
    assert!(run.output.alternatives[0].links.is_empty());
    check(&query, &run);
    for item in &mut query.transitions {
        item.cost = 0;
    }
    let tied = continuity::plan(&query, budget())?;
    check(&query, &tied);
    assert_eq!(tied.output.alternatives[0].paths, vec![vec!["a", "b", "c"]]);
    assert!(
        tied.output
            .alternatives
            .iter()
            .all(|cover| cover.total_cost == 0)
    );
    Ok(())
}

#[test]
fn exact_requested_count_does_not_claim_proven_exhaustion() -> TestResult {
    let mut query = query();
    query.tracklets.truncate(1);
    query.transitions.clear();
    query.k = 1;
    let prefix = continuity::plan(&query, budget())?;
    assert_eq!(prefix.output.alternatives.len(), 1);
    assert!(!prefix.output.displayed_prefix_complete);
    assert_eq!(
        prefix.output.family.all_singletons,
        prefix.output.alternatives[0]
    );
    query.k = 2;
    let complete = continuity::plan(&query, budget())?;
    assert_eq!(complete.output.alternatives.len(), 1);
    assert!(complete.output.displayed_prefix_complete);
    Ok(())
}

#[test]
fn widening_capture_uncertainty_can_only_remove_admitted_handoffs() -> TestResult {
    for seed in 0..96 {
        let mut query = tiny_query(seed);
        let original = continuity::plan(&query, budget())?;
        let edges: BTreeSet<_> = original
            .output
            .family
            .edges
            .iter()
            .map(|edge| (&edge.from, &edge.to))
            .collect();
        for item in &mut query.tracklets {
            item.start[0] -= 4;
            item.start[1] += 4;
            item.end[0] -= 4;
            item.end[1] += 4;
        }
        let wider = continuity::plan(&query, budget())?;
        assert!(
            wider
                .output
                .family
                .edges
                .iter()
                .all(|edge| edges.contains(&(&edge.from, &edge.to)))
        );
        check(&query, &wider);
    }
    Ok(())
}

#[test]
fn pairwise_possible_transit_is_insufficient_and_full_interval_bounds_are_inclusive() -> TestResult
{
    let mut query = query();
    query.tracklets = vec![
        tracklet("a", "one", [0, 0], [0, 0]),
        tracklet("b", "two", [1, 10], [1, 10]),
        tracklet("c", "three", [11, 11], [11, 11]),
    ];
    query.transitions = vec![
        transition("a", "b", [1, 2], 0),
        transition("b", "c", [1, 2], 0),
    ];
    let possible_only = continuity::plan(&query, budget())?;
    assert!(possible_only.output.family.edges.is_empty());
    for row in possible_only
        .output
        .transitions
        .iter()
        .filter(|row| row.declared.is_some())
    {
        assert!(row.reasons.contains(&RejectionReason::TransitNotRobust));
    }
    query.transitions[0].transit = [1, 10];
    query.transitions[1].transit = [1, 10];
    let robust = continuity::plan(&query, budget())?;
    assert_eq!(robust.output.family.edges.len(), 2);
    assert_eq!(
        robust.output.alternatives[0].paths,
        vec![vec!["a", "b", "c"]]
    );
    check(&query, &robust);
    Ok(())
}

#[test]
fn simultaneous_or_overlapping_exposures_are_retained_without_handoff() -> TestResult {
    let mut query = query();
    query.tracklets[1].start = [4, 6];
    query.transitions[0].transit = [0, 20];
    let run = continuity::plan(&query, budget())?;
    let row = run
        .output
        .transitions
        .iter()
        .find(|row| row.from == "a" && row.to == "b")
        .ok_or("pair missing")?;
    assert!(row.reasons.contains(&RejectionReason::NotStrictlyForward));
    assert!(!row.admitted);
    assert_eq!(run.output.tracklets.len(), 3);
    check(&query, &run);
    Ok(())
}

#[test]
fn unavailable_support_never_removes_members_or_becomes_negative_evidence() -> TestResult {
    for support in [
        TrackletSupport::Missing,
        TrackletSupport::Invalidated,
        TrackletSupport::Redacted,
    ] {
        let mut query = query();
        query.tracklets[1].support = support;
        query.tracklets[1].evidence.clear();
        let run = continuity::plan(&query, budget())?;
        check(&query, &run);
        assert_eq!(run.output.tracklets[1].support, support);
        assert!(
            run.output
                .alternatives
                .iter()
                .all(|cover| cover.paths.contains(&vec!["b".into()]))
        );
        assert_eq!(run.output.family.edges.len(), 1);
        for row in run.output.transitions.iter().filter(|row| row.from == "b") {
            assert!(row.reasons.contains(&RejectionReason::SourceUnavailable));
        }
        for row in run.output.transitions.iter().filter(|row| row.to == "b") {
            assert!(row.reasons.contains(&RejectionReason::TargetUnavailable));
        }
    }
    Ok(())
}

#[test]
fn model_and_same_camera_generations_are_never_silently_mixed() -> TestResult {
    let mut query = query();
    query.tracklets[1].model = pin("different-model");
    let changed_model = continuity::plan(&query, budget())?;
    assert!(
        changed_model
            .output
            .transitions
            .iter()
            .filter(|row| row.from == "b" || row.to == "b")
            .all(|row| row
                .reasons
                .contains(&RejectionReason::ModelGenerationMismatch))
    );
    query.tracklets[1].model = query.tracklets[0].model;
    query.tracklets[1].camera = query.tracklets[0].camera.clone();
    let changed_camera = continuity::plan(&query, budget())?;
    let row = changed_camera
        .output
        .transitions
        .iter()
        .find(|row| row.from == "a" && row.to == "b")
        .ok_or("pair missing")?;
    assert!(
        row.reasons
            .contains(&RejectionReason::CameraGenerationMismatch)
    );
    assert!(row.reasons.contains(&RejectionReason::CalibrationMismatch));
    query.tracklets[1].camera_generation = query.tracklets[0].camera_generation;
    query.tracklets[1].calibration = query.tracklets[0].calibration;
    let same_generation = continuity::plan(&query, budget())?;
    assert_eq!(same_generation.output.family.edges.len(), 3);
    check(&query, &same_generation);
    Ok(())
}

#[test]
fn source_scope_generation_privacy_clock_cost_and_rejected_assumptions_are_digest_bound()
-> TestResult {
    let mut query = query();
    query.transitions.push(transition("c", "a", [0, 50], 9));
    let original = continuity::plan(&query, budget())?;
    let mut variants = Vec::new();
    macro_rules! change {
        ($target:expr, $value:expr) => {{
            let mut changed = query.clone();
            ($target)(&mut changed, $value);
            variants.push(changed);
        }};
    }
    change!(
        |q: &mut ContinuityQuery, v| q.scope.property = v,
        "other-property".into()
    );
    change!(
        |q: &mut ContinuityQuery, v| q.scope.session = v,
        "other-session".into()
    );
    change!(
        |q: &mut ContinuityQuery, v| q.scope.privacy_policy = v,
        pin("other-privacy")
    );
    change!(
        |q: &mut ContinuityQuery, v| q.scope.generation = v,
        pin("other-generation")
    );
    change!(
        |q: &mut ContinuityQuery, v| q.scope.clock = v,
        pin("other-clock")
    );
    change!(
        |q: &mut ContinuityQuery, v| q.tracklets[0].camera_generation = v,
        pin("other-camera-generation")
    );
    change!(
        |q: &mut ContinuityQuery, v| q.tracklets[0].calibration = v,
        pin("other-calibration")
    );
    change!(
        |q: &mut ContinuityQuery, v| q.tracklets[0].model = v,
        pin("other-model")
    );
    change!(
        |q: &mut ContinuityQuery, v| q.tracklets[0].evidence[0] = v,
        pin("other-evidence")
    );
    change!(|q: &mut ContinuityQuery, v| q.tracklets[0].start[0] = v, -1);
    change!(|q: &mut ContinuityQuery, v| q.tracklets[0].end[0] = v, 2);
    change!(
        |q: &mut ContinuityQuery, v| q.tracklets[0].support = v,
        TrackletSupport::Invalidated
    );
    change!(|q: &mut ContinuityQuery, v| q.transitions[3].cost = v, 10);
    change!(
        |q: &mut ContinuityQuery, v| q.transitions[3].basis = v,
        pin("changed-rejected-basis")
    );
    change!(
        |q: &mut ContinuityQuery, v| q.transitions[3].transit = v,
        [0, 99]
    );
    change!(
        |q: &mut ContinuityQuery, v| q.cost_unit = v,
        "other-cost-unit".into()
    );
    change!(
        |q: &mut ContinuityQuery, v| q.time_unit = v,
        "other-time-unit".into()
    );
    change!(|q: &mut ContinuityQuery, v| q.birth_cost = v, 6);
    change!(|q: &mut ContinuityQuery, v| q.end_cost = v, 4);
    change!(|q: &mut ContinuityQuery, v| q.k = v, 2);
    for variant in variants {
        let run = continuity::plan(&variant, budget())?;
        assert_ne!(run.input_digest, original.input_digest);
        assert_ne!(run.output_digest, original.output_digest);
        assert_ne!(run.decision_path_digest, original.decision_path_digest);
    }
    Ok(())
}

#[test]
fn signed_time_extremes_use_exact_wide_subtraction() -> TestResult {
    let mut query = query();
    query.tracklets = vec![
        tracklet("a", "one", [i64::MIN; 2], [i64::MIN; 2]),
        tracklet("b", "two", [i64::MAX; 2], [i64::MAX; 2]),
    ];
    query.transitions = vec![
        transition("a", "b", [u64::MAX; 2], 0),
        transition("b", "a", [0, u64::MAX], 0),
    ];
    let run = continuity::plan(&query, budget())?;
    assert_eq!(run.output.family.edges.len(), 1);
    assert_eq!(run.output.transitions[0].gap, [i128::from(u64::MAX); 2]);
    assert_eq!(run.output.transitions[1].gap, [-i128::from(u64::MAX); 2]);
    check(&query, &run);
    Ok(())
}

#[test]
fn singleton_and_materialized_assignment_cost_overflow_fail_closed() -> TestResult {
    let mut query = query();
    query.birth_cost = u64::MAX;
    assert!(matches!(
        continuity::plan(&query, budget()),
        Err(GraphError::ArithmeticOverflow(_))
    ));
    query.tracklets.truncate(1);
    query.transitions.clear();
    query.end_cost = 0;
    let exact = continuity::plan(&query, budget())?;
    assert_eq!(exact.output.family.all_singletons.total_cost, u64::MAX);
    query = self::query();
    query.birth_cost = 0;
    query.end_cost = 0;
    query.transitions[0].cost = u64::MAX;
    query.transitions[1].cost = 1;
    query.k = 32;
    assert!(matches!(
        continuity::plan(&query, budget()),
        Err(GraphError::ArithmeticOverflow(_))
    ));
    Ok(())
}

#[test]
fn exact_shared_operation_and_output_allowances_include_the_full_child_proof() -> TestResult {
    let query = query();
    let run = continuity::plan(&query, budget())?;
    assert_eq!(
        continuity::plan(&query, Budget::new(run.operations, run.output_entries))?,
        run
    );
    assert!(matches!(
        continuity::plan(&query, Budget::new(run.operations - 1, run.output_entries)),
        Err(GraphError::BudgetExhausted { .. })
    ));
    assert!(matches!(
        continuity::plan(&query, Budget::new(run.operations, run.output_entries - 1)),
        Err(GraphError::BudgetExhausted {
            dimension: "output_entries",
            ..
        })
    ));
    assert!(run.output_entries > run.output.matching.output_entries);
    assert!(run.operations > run.output.matching.operations);
    for bad in [
        Budget::new(0, 1),
        Budget::new(1, 0),
        Budget::new(continuity::MAX_WORK_UNITS + 1, 1),
        Budget::new(1, continuity::MAX_OUTPUT_ENTRIES + 1),
    ] {
        assert!(matches!(
            continuity::plan(&query, bad),
            Err(GraphError::PreconditionFailed(_))
        ));
    }
    Ok(())
}

#[test]
fn every_cancellation_checkpoint_returns_no_prefix_or_witness() -> TestResult {
    let mut query = query();
    query.tracklets.truncate(2);
    query.transitions.truncate(1);
    query.k = 3;
    let calls = Cell::new(0_usize);
    let complete = continuity::plan_with_cancel(&query, budget(), &|| {
        calls.set(calls.get() + 1);
        false
    })?;
    let checkpoints = calls.get();
    assert!(checkpoints > 100);
    assert_eq!(complete, continuity::plan(&query, budget())?);
    for stop in 1..=checkpoints {
        calls.set(0);
        assert_eq!(
            continuity::plan_with_cancel(&query, budget(), &|| {
                calls.set(calls.get() + 1);
                calls.get() >= stop
            }),
            Err(GraphError::Cancelled),
            "stop={stop}/{checkpoints}"
        );
    }
    Ok(())
}

#[test]
fn cancellable_assignment_wrappers_preserve_every_legacy_success_field() -> TestResult {
    for seed in 0..64 {
        let mut rng = Rng(seed);
        let mut builder = AssignmentProblemBuilder::new("cost");
        for i in 0..3 {
            builder.add_left(format!("l{i}")).add_right(format!("r{i}"));
        }
        for i in 0..3 {
            for j in 0..3 {
                if rng.chance(700) {
                    builder.allow(format!("l{i}"), format!("r{j}"), rng.below(7) as u64);
                }
            }
        }
        let problem = builder.build()?;
        for policy in [
            NonAssignment::MaximumCardinality,
            NonAssignment::Priced {
                left: seed % 3,
                right: seed % 5,
            },
        ] {
            assert_eq!(
                assignment::optimal_assignment(&problem, policy, budget())?,
                assignment::optimal_assignment_with_cancel(&problem, policy, budget(), &|| false)?
            );
            assert_eq!(
                assignment::k_best_assignments(&problem, policy, 9, budget())?,
                assignment::k_best_assignments_with_cancel(&problem, policy, 9, budget(), &|| {
                    false
                })?
            );
            assert_eq!(
                assignment::optimal_assignment_with_cancel(&problem, policy, budget(), &|| true),
                Err(GraphError::Cancelled)
            );
            assert_eq!(
                assignment::k_best_assignments_with_cancel(&problem, policy, 9, budget(), &|| true),
                Err(GraphError::Cancelled)
            );
        }
    }
    Ok(())
}

#[test]
fn malformed_oversized_and_ambiguous_declarations_are_rejected_without_partial_results() {
    let original = query();
    let mut variants = Vec::new();
    macro_rules! bad {
        ($edit:expr) => {{
            let mut q = original.clone();
            ($edit)(&mut q);
            variants.push(q);
        }};
    }
    bad!(|q: &mut ContinuityQuery| q.k = 0);
    bad!(|q: &mut ContinuityQuery| q.k = continuity::MAX_K + 1);
    bad!(|q: &mut ContinuityQuery| q.tracklets.clear());
    bad!(|q: &mut ContinuityQuery| q.tracklets =
        vec![q.tracklets[0].clone(); continuity::MAX_TRACKLETS + 1]);
    bad!(|q: &mut ContinuityQuery| q.transitions =
        vec![q.transitions[0].clone(); continuity::MAX_TRANSITIONS + 1]);
    bad!(|q: &mut ContinuityQuery| q.tracklets.push(q.tracklets[0].clone()));
    bad!(|q: &mut ContinuityQuery| q.transitions.push(q.transitions[0].clone()));
    bad!(|q: &mut ContinuityQuery| q.transitions[0].to = "unknown".into());
    bad!(|q: &mut ContinuityQuery| q.transitions[0].to = q.transitions[0].from.clone());
    bad!(|q: &mut ContinuityQuery| q.transitions[0].transit = [5, 4]);
    bad!(|q: &mut ContinuityQuery| q.tracklets[0].evidence.clear());
    bad!(|q: &mut ContinuityQuery| {
        let source = q.tracklets[0].evidence[0];
        q.tracklets[0].evidence.push(source);
    });
    bad!(|q: &mut ContinuityQuery| q.tracklets[0].evidence =
        vec![pin("source"); continuity::MAX_EVIDENCE + 1]);
    bad!(|q: &mut ContinuityQuery| q.tracklets[0].start = [2, 1]);
    bad!(|q: &mut ContinuityQuery| q.tracklets[0].end = [5, 4]);
    bad!(|q: &mut ContinuityQuery| q.tracklets[0].start = [8, 9]);
    bad!(|q: &mut ContinuityQuery| q.scope.privacy_policy =
        ContentDigest::new(DigestAlgorithm::Sha256, [0; 32]));
    bad!(|q: &mut ContinuityQuery| q.tracklets[0].evidence[0] = pin("source").with_laboratory(true));
    bad!(|q: &mut ContinuityQuery| q.transitions[0].basis = pin("basis").with_laboratory(true));
    bad!(|q: &mut ContinuityQuery| q.scope.property = "other/property".into());
    bad!(|q: &mut ContinuityQuery| q.scope.session.clear());
    bad!(|q: &mut ContinuityQuery| q.tracklets[0].id = "non-ascii-\u{03c0}".into());
    bad!(|q: &mut ContinuityQuery| q.tracklets[0].camera = "a".repeat(continuity::MAX_ID_BYTES + 1));
    bad!(|q: &mut ContinuityQuery| q.time_unit = "unit with spaces".into());
    bad!(|q: &mut ContinuityQuery| q.cost_unit = "a".repeat(continuity::MAX_UNIT_BYTES + 1));
    for (i, bad) in variants.into_iter().enumerate() {
        assert!(
            matches!(
                continuity::plan(&bad, budget()),
                Err(GraphError::PreconditionFailed(_)
                    | GraphError::UnknownNode(_)
                    | GraphError::SelfLoop(_)
                    | GraphError::TooLarge)
            ),
            "case {i}"
        );
    }
}

#[test]
fn maximum_tracklet_inventory_retains_all_pair_dispositions_with_a_tiny_prefix() -> TestResult {
    let mut query = query();
    query.tracklets = (0..continuity::MAX_TRACKLETS)
        .map(|i| {
            tracklet(
                &format!("t{i:02}"),
                "camera",
                [i as i64 * 3; 2],
                [i as i64 * 3 + 1; 2],
            )
        })
        .collect();
    query.transitions.clear();
    query.k = 1;
    let run = continuity::plan(&query, budget())?;
    assert_eq!(run.output.transitions.len(), continuity::MAX_TRANSITIONS);
    assert_eq!(
        run.output.alternatives[0].paths.len(),
        continuity::MAX_TRACKLETS
    );
    assert!(run.output.family.edges.is_empty());
    let witness = run.witness(
        "SpatioTemporalTrackGraph@declared:all-isolated",
        LedgerAnchor::genesis("continuity-test"),
    )?;
    check_witness(
        &witness,
        &continuity::IDENTITY,
        &continuity::bound(run.node_count, run.edge_count, 1),
    )?;
    for from in &query.tracklets {
        for to in &query.tracklets {
            if from.id != to.id {
                query
                    .transitions
                    .push(transition(&from.id, &to.id, [0, 100], 0));
            }
        }
    }
    let dense = continuity::plan(&query, budget())?;
    assert_eq!(dense.output.transitions.len(), continuity::MAX_TRANSITIONS);
    assert_eq!(
        dense.output.family.edges.len(),
        continuity::MAX_TRANSITIONS / 2
    );
    assert_eq!(dense.output.alternatives[0].paths.len(), 1);
    assert_eq!(
        dense.output.alternatives[0].paths[0].len(),
        continuity::MAX_TRACKLETS
    );
    Ok(())
}

#[test]
fn composition_and_child_witnesses_bind_complete_outputs_and_registered_mode() -> TestResult {
    let query = query();
    let run = continuity::plan(&query, budget())?;
    let anchor = LedgerAnchor::genesis("continuity-test");
    let witness = run.witness("SpatioTemporalTrackGraph@declared:case", anchor.clone())?;
    let bounds = continuity::bound(run.node_count, run.edge_count, u64::from(query.k));
    check_witness(&witness, &continuity::IDENTITY, &bounds)?;
    let matching = &run.output.matching;
    check_witness(
        &matching.witness("SpatioTemporalTrackGraph@declared:case/assignment", anchor)?,
        &assignment::MULTIMATCH_IDENTITY,
        &assignment::multimatch_bound(matching.node_count, matching.edge_count, u64::from(query.k)),
    )?;
    let mut changed = run.output.clone();
    changed.matching.operations += 1;
    let mut encoder = CanonicalEncoder::new();
    encoder.text(continuity::OUTPUT_DOMAIN);
    changed.encode(&mut encoder);
    assert_ne!(ContentDigest::sha256(&encoder.finish()), run.output_digest);
    let mode = include_str!("../../../architecture/continuity_reference.json");
    for (field, value) in continuity::IDENTITY.registry_fields() {
        assert!(
            mode.contains(&format!("\"{field}\": \"{value}\"")),
            "mode missing {field}"
        );
    }
    let domains = include_str!("../../../registries/DIGEST_DOMAINS.md");
    for domain in [
        continuity::INPUT_DOMAIN,
        continuity::OUTPUT_DOMAIN,
        continuity::DECISION_DOMAIN,
    ] {
        assert!(domains.contains(domain));
    }
    Ok(())
}
