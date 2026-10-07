#![forbid(unsafe_code)]
//! Certification of `ALG-SCC-001`, `ALG-TOPO-001`, `ALG-DOM-001`, `ALG-SP-001`, `ALG-MSD-001`
//! and `ALG-FLOW-001` against their brute-force oracles.
//!
//! 1. Differential: thousands of seeded directed and undirected weighted graphs (random
//!    `G(n, p)`, DAGs, cycles, cliques, stars, paths, layered graphs, disjoint unions, empty and
//!    single-node graphs, zero weights) must produce exactly the oracle's answer; flows are
//!    checked for capacity, conservation and value instead (they are not unique).
//! 2. Metamorphic: insertion order never changes the answer, decision path, input digest, or
//!    witness digest.
//! 3. Bounds: every run's counters lie within the registered bound, a budget one operation short
//!    fails closed with no answer, and a tampered witness is refused.
//! 4. Registry: every implemented identity equals its machine registry row.

mod common;

use std::collections::BTreeSet;

use common::{SEEDS, TestResult, assert_registered, certify, generate, registered};
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::dominators::{self, DominanceDirection};
use fss_graph_algorithms::flow::{self, CutMode, FlowOutput};
use fss_graph_algorithms::paths;
use fss_graph_algorithms::weighted::{Orientation, WeightedGraphBuilder};
use fss_graph_algorithms::{GraphError, oracles, scc, topo};

#[test]
fn scc_equals_mutual_reachability_oracle() -> TestResult {
    for seed in 0..SEEDS {
        let spec = generate(seed, Orientation::Directed, 9);
        let graph = spec.build(None)?;
        let (n, m) = (graph.node_count() as u64, graph.arc_count() as u64);
        let bound = scc::bound(n, m);
        let run = scc::strongly_connected_components(&graph, registered(&bound))?;
        assert_eq!(run.output, oracles::scc(&graph), "seed {seed}");
        let shuffled =
            scc::strongly_connected_components(&spec.build(Some(seed))?, registered(&bound))?;
        assert_eq!(
            shuffled, run,
            "seed {seed}: insertion order reached the answer"
        );
        if seed % 25 == 0 {
            certify(&run, &scc::IDENTITY, &bound, |budget| {
                scc::strongly_connected_components(&graph, budget)
            })?;
        }
    }
    Ok(())
}

#[test]
fn topo_equals_selection_and_relaxation_oracle() -> TestResult {
    let mut acyclic = 0;
    for seed in 0..SEEDS {
        let spec = generate(seed, Orientation::Directed, 9);
        let graph = spec.build(None)?;
        let (n, m) = (graph.node_count() as u64, graph.arc_count() as u64);
        let bound = topo::bound(n, m);
        let certified = topo::topological_schedule(&graph, registered(&bound));
        match oracles::topo(&graph) {
            Err(_) => assert!(
                matches!(certified, Err(GraphError::PreconditionFailed(_))),
                "seed {seed}: a cyclic graph must fail the precondition"
            ),
            Ok(expected) => {
                acyclic += 1;
                let run = certified?;
                assert_eq!(run.output, expected, "seed {seed}");
                let shuffled =
                    topo::topological_schedule(&spec.build(Some(seed))?, registered(&bound))?;
                assert_eq!(shuffled, run, "seed {seed}");
                if seed % 25 == 0 {
                    certify(&run, &topo::IDENTITY, &bound, |budget| {
                        topo::topological_schedule(&graph, budget)
                    })?;
                }
            }
        }
    }
    assert!(
        acyclic > SEEDS / 4,
        "the corpus must exercise many DAGs ({acyclic})"
    );
    Ok(())
}

#[test]
fn dominators_equal_removal_oracle_in_both_directions() -> TestResult {
    for seed in 0..SEEDS {
        let spec = generate(seed, Orientation::Directed, 9);
        let graph = spec.build(None)?;
        if graph.node_count() == 0 {
            continue;
        }
        let root = (seed as usize % graph.node_count()) as u32;
        let root_id = graph.id(root).to_owned();
        let (n, m) = (graph.node_count() as u64, graph.arc_count() as u64);
        let bound = dominators::bound(n, m);
        for direction in [
            DominanceDirection::Dominators,
            DominanceDirection::PostDominators,
        ] {
            let run = dominators::dominators(&graph, &root_id, direction, registered(&bound))?;
            assert_eq!(
                run.output,
                oracles::dominators(&graph, root, direction),
                "seed {seed} {direction:?}"
            );
            let shuffled = dominators::dominators(
                &spec.build(Some(seed))?,
                &root_id,
                direction,
                registered(&bound),
            )?;
            assert_eq!(shuffled, run, "seed {seed}");
            for (node, _) in &run.output.immediate_dominators {
                let chain = run
                    .output
                    .chain(node)
                    .ok_or("reachable node without a chain")?;
                assert_eq!(chain.first(), Some(&root_id));
                assert_eq!(chain.last(), Some(node));
            }
            if seed % 25 == 0 {
                certify(&run, &dominators::IDENTITY, &bound, |budget| {
                    dominators::dominators(&graph, &root_id, direction, budget)
                })?;
            }
        }
    }
    Ok(())
}

#[test]
fn shortest_and_multi_source_paths_equal_bellman_ford() -> TestResult {
    for seed in 0..SEEDS {
        for orientation in [Orientation::Directed, Orientation::Undirected] {
            let spec = generate(seed, orientation, 9);
            let graph = spec.build(None)?;
            let n = graph.node_count();
            if n == 0 {
                continue;
            }
            let (n64, m64) = (n as u64, graph.arc_count() as u64);
            let source = (seed as usize % n) as u32;
            let target = ((seed as usize / 7) % n) as u32;
            let bound = paths::sp_bound(orientation, n64, m64);
            let run = paths::shortest_paths(
                &graph,
                graph.id(source),
                Some(graph.id(target)),
                registered(&bound),
            )?;
            assert_eq!(
                run.output,
                oracles::shortest_paths(&graph, source, Some(target)),
                "seed {seed} {orientation}"
            );
            let shuffled = paths::shortest_paths(
                &spec.build(Some(seed))?,
                graph.id(source),
                Some(graph.id(target)),
                registered(&bound),
            )?;
            assert_eq!(shuffled, run, "seed {seed} {orientation}");

            let mut sources: Vec<u32> = (0..n as u32)
                .filter(|v| (seed >> (v % 8)) & 1 == 1)
                .collect();
            if sources.is_empty() {
                sources.push(source);
            }
            let ids: Vec<&str> = sources.iter().map(|&s| graph.id(s)).collect();
            let msd_bound = paths::msd_bound(orientation, n64, m64);
            let msd = paths::multi_source_distances(&graph, &ids, registered(&msd_bound))?;
            assert_eq!(
                msd.output,
                oracles::multi_source(&graph, &sources),
                "seed {seed}"
            );
            if seed % 25 == 0 {
                certify(&run, &paths::SP_IDENTITY, &bound, |budget| {
                    paths::shortest_paths(&graph, graph.id(source), Some(graph.id(target)), budget)
                })?;
                certify(&msd, &paths::MSD_IDENTITY, &msd_bound, |budget| {
                    paths::multi_source_distances(&graph, &ids, budget)
                })?;
            }
        }
    }
    Ok(())
}

#[test]
fn flow_cuts_equal_subset_enumeration() -> TestResult {
    for seed in 0..SEEDS {
        for orientation in [Orientation::Directed, Orientation::Undirected] {
            let spec = generate(seed, orientation, 8);
            let graph = spec.build(None)?;
            let n = graph.node_count();
            if n < 2 {
                continue;
            }
            let s = (seed as usize % n) as u32;
            let t = ((seed as usize / 3 + 1 + s as usize) % n) as u32;
            if s == t {
                continue;
            }
            let (n64, m64) = (n as u64, graph.arc_count() as u64);
            let bound = flow::bound(n64, m64);
            let run = flow::max_flow_min_cut(
                &graph,
                graph.id(s),
                graph.id(t),
                CutMode::Arcs,
                registered(&bound),
            )?;
            let FlowOutput::Arcs(answer) = &run.output else {
                return Err("arc mode answered nodes".into());
            };
            let expected = oracles::min_arc_cut(&graph, s, t);
            assert_eq!(answer.value, expected.value, "seed {seed} {orientation}");
            assert_eq!(
                answer.source_side, expected.source_side,
                "seed {seed} {orientation}"
            );
            assert_eq!(answer.cut, expected.cut, "seed {seed} {orientation}");
            for (tail, head, amount) in &answer.flows {
                let (a, b) = (graph.require(tail)?, graph.require(head)?);
                let arc = graph.find_arc(a, b).ok_or("flow on a missing arc")?;
                assert!(*amount <= graph.arc(arc).weight, "seed {seed}: capacity");
            }
            let balance = oracles::balances(&answer.flows);
            for (node, value) in &balance {
                let expected = if node == graph.id(s) {
                    -i128::from(answer.value)
                } else if node == graph.id(t) {
                    i128::from(answer.value)
                } else {
                    0
                };
                assert_eq!(*value, expected, "seed {seed}: conservation at {node}");
            }
            let shuffled = flow::max_flow_min_cut(
                &spec.build(Some(seed))?,
                graph.id(s),
                graph.id(t),
                CutMode::Arcs,
                registered(&bound),
            )?;
            assert_eq!(shuffled.output_digest, run.output_digest, "seed {seed}");

            let nodes = flow::max_flow_min_cut(
                &graph,
                graph.id(s),
                graph.id(t),
                CutMode::Nodes,
                registered(&bound),
            )?;
            let FlowOutput::Nodes(cut) = &nodes.output else {
                return Err("node mode answered arcs".into());
            };
            match oracles::min_node_cut_weight(&graph, s, t) {
                None => assert!(
                    !cut.separable,
                    "seed {seed}: adjacent terminals are inseparable"
                ),
                Some(weight) => {
                    assert!(cut.separable, "seed {seed}");
                    assert_eq!(cut.failure_weight, weight, "seed {seed} {orientation}");
                    let removed: BTreeSet<u32> = cut
                        .failure_set
                        .iter()
                        .map(|id| graph.require(id))
                        .collect::<Result<_, _>>()?;
                    assert!(
                        !oracles::connected_without(&graph, s, t, &removed),
                        "seed {seed}"
                    );
                }
            }
            if seed % 25 == 0 {
                certify(&run, &flow::IDENTITY, &bound, |budget| {
                    flow::max_flow_min_cut(&graph, graph.id(s), graph.id(t), CutMode::Arcs, budget)
                })?;
                certify(&nodes, &flow::IDENTITY, &bound, |budget| {
                    flow::max_flow_min_cut(&graph, graph.id(s), graph.id(t), CutMode::Nodes, budget)
                })?;
            }
        }
    }
    Ok(())
}

#[test]
fn textbook_answers_hold() -> TestResult {
    // A plan: fetch (3) -> verify (2) -> commit (1); fetch -> index (1) -> commit. Critical
    // path fetch, verify, commit; makespan 6; index has slack 1.
    let mut plan = WeightedGraphBuilder::directed("ms");
    plan.add_weighted_node("fetch", 3)
        .add_weighted_node("verify", 2)
        .add_weighted_node("index", 1)
        .add_weighted_node("commit", 1);
    plan.add_arc("fetch", "verify", 0)
        .add_arc("verify", "commit", 0)
        .add_arc("fetch", "index", 0)
        .add_arc("index", "commit", 0);
    let plan = plan.build()?;
    let schedule = topo::topological_schedule(&plan, Budget::registered(&topo::bound(4, 4)))?;
    assert_eq!(schedule.output.makespan, 6);
    assert_eq!(schedule.output.critical_path, ["fetch", "verify", "commit"]);
    assert_eq!(
        schedule.output.order,
        ["fetch", "index", "verify", "commit"]
    );
    let index = schedule
        .output
        .schedule
        .iter()
        .find(|row| row.node == "index")
        .ok_or("index row")?;
    assert_eq!((index.earliest_start, index.slack), (3, 1));

    // Two sensors feed one gateway feeding the recorder; the gateway dominates the recorder
    // and is the single-node failure set.
    let mut mesh = WeightedGraphBuilder::directed("failures");
    for node in ["cam-a", "cam-b", "gateway", "recorder", "site"] {
        mesh.add_weighted_node(node, 1);
    }
    mesh.add_arc("site", "cam-a", 0)
        .add_arc("site", "cam-b", 0)
        .add_arc("cam-a", "gateway", 0)
        .add_arc("cam-b", "gateway", 0)
        .add_arc("gateway", "recorder", 0);
    let mesh = mesh.build()?;
    let dom = dominators::dominators(
        &mesh,
        "site",
        DominanceDirection::Dominators,
        Budget::registered(&dominators::bound(5, 5)),
    )?;
    assert_eq!(
        dom.output.chain("recorder"),
        Some(vec!["site".into(), "gateway".into(), "recorder".into()])
    );
    let cut = flow::max_flow_min_cut(
        &mesh,
        "site",
        "recorder",
        CutMode::Nodes,
        Budget::registered(&flow::bound(5, 5)),
    )?;
    let FlowOutput::Nodes(cut) = cut.output else {
        return Err("node mode".into());
    };
    assert_eq!(
        (cut.failure_weight, cut.failure_set),
        (1, vec!["gateway".to_owned()])
    );

    // A cyclic plan is refused with the precondition error, never ordered.
    let mut cyclic = WeightedGraphBuilder::directed("ms");
    cyclic
        .add_node("a")
        .add_node("b")
        .add_arc("a", "b", 0)
        .add_arc("b", "a", 0);
    let refused = topo::topological_schedule(&cyclic.build()?, Budget::new(1000, 1000));
    assert_eq!(
        refused.err().map(|e| e.stable_id()),
        Some("ERR-GRAPH-PRECONDITION-001")
    );

    // Overflowing distances are typed, never wrapped.
    let mut long = WeightedGraphBuilder::directed("ns");
    long.add_node("a").add_node("b").add_node("c");
    long.add_arc("a", "b", u64::MAX).add_arc("b", "c", 1);
    let overflow = paths::shortest_paths(&long.build()?, "a", None, Budget::new(1000, 1000));
    assert_eq!(
        overflow.err().map(|e| e.stable_id()),
        Some("ERR-GRAPH-NUMERIC-OVERFLOW-001")
    );
    Ok(())
}

#[test]
fn implemented_identities_equal_their_machine_registry_rows() -> TestResult {
    for identity in [
        &scc::IDENTITY,
        &topo::IDENTITY,
        &dominators::IDENTITY,
        &paths::SP_IDENTITY,
        &paths::MSD_IDENTITY,
        &flow::IDENTITY,
    ] {
        assert_registered(identity)?;
    }
    Ok(())
}
