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

use std::collections::BTreeSet;
use std::error::Error;

use fss_core::{GraphAlgorithmWitness, GraphAlgorithmWitnessParams, LedgerAnchor};
use fss_graph_algorithms::certified::{AlgorithmIdentity, Budget, CertifiedRun, check_witness};
use fss_graph_algorithms::dominators::{self, DominanceDirection};
use fss_graph_algorithms::flow::{self, CutMode, FlowOutput};
use fss_graph_algorithms::paths;
use fss_graph_algorithms::weighted::{Orientation, WeightedGraph, WeightedGraphBuilder};
use fss_graph_algorithms::{GraphError, oracles, scc, topo};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SEEDS: u64 = 2_500;

/// SplitMix64: deterministic, platform independent.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next() % bound as u64) as usize
        }
    }

    fn chance(&mut self, per_mille: u64) -> bool {
        self.next() % 1000 < per_mille
    }

    fn shuffle<T>(&mut self, values: &mut [T]) {
        for index in (1..values.len()).rev() {
            let other = self.below(index + 1);
            values.swap(index, other);
        }
    }
}

#[derive(Clone, Debug)]
struct Spec {
    orientation: Orientation,
    nodes: Vec<(String, u64)>,
    arcs: Vec<(usize, usize, u64)>,
}

impl Spec {
    fn build(&self, shuffle: Option<u64>) -> Result<WeightedGraph, GraphError> {
        let mut nodes = self.nodes.clone();
        let mut arcs = self.arcs.clone();
        if let Some(seed) = shuffle {
            let mut rng = Rng(seed);
            rng.shuffle(&mut nodes);
            rng.shuffle(&mut arcs);
        }
        let mut builder = WeightedGraphBuilder::new(self.orientation, "test-unit");
        for (id, weight) in &nodes {
            builder.add_weighted_node(id.clone(), *weight);
        }
        for &(a, b, weight) in &arcs {
            let (a, b) = if shuffle.is_some() && self.orientation == Orientation::Undirected {
                (b, a)
            } else {
                (a, b)
            };
            builder.add_arc(self.nodes[a].0.clone(), self.nodes[b].0.clone(), weight);
        }
        builder.build()
    }
}

/// Node identities whose byte order differs from creation order, to catch index/identity slips.
fn node_id(index: usize) -> String {
    format!("n{}-{}", (index * 7) % 10, index)
}

fn generate(seed: u64, orientation: Orientation, max_nodes: usize) -> Spec {
    let mut rng = Rng(seed.wrapping_mul(0x2545_f491_4f6c_dd1d) ^ 0xdead_beef);
    let n = rng.below(max_nodes + 1);
    let max_weight = [0, 1, 3, 9, 100][rng.below(5)] as u64;
    let weight = |rng: &mut Rng| {
        if max_weight == 0 {
            0
        } else {
            rng.next() % (max_weight + 1)
        }
    };
    let nodes: Vec<(String, u64)> = (0..n).map(|i| (node_id(i), weight(&mut rng))).collect();
    let mut pairs: BTreeSet<(usize, usize)> = BTreeSet::new();
    let family = rng.below(9);
    let push = |pairs: &mut BTreeSet<(usize, usize)>, a: usize, b: usize| {
        if a != b {
            let key = if orientation == Orientation::Undirected {
                (a.min(b), a.max(b))
            } else {
                (a, b)
            };
            pairs.insert(key);
        }
    };
    match family {
        0 => {
            let p = [100, 250, 450, 700][rng.below(4)];
            for a in 0..n {
                for b in 0..n {
                    if rng.chance(p) {
                        push(&mut pairs, a, b);
                    }
                }
            }
        }
        1 => {
            // DAG: arcs only forward along a random permutation.
            let mut perm: Vec<usize> = (0..n).collect();
            rng.shuffle(&mut perm);
            for i in 0..n {
                for j in i + 1..n {
                    if rng.chance(400) {
                        push(&mut pairs, perm[i], perm[j]);
                    }
                }
            }
        }
        2 => {
            for i in 0..n {
                push(&mut pairs, i, (i + 1) % n.max(1));
            }
        }
        3 => {
            for a in 0..n {
                for b in 0..n {
                    push(&mut pairs, a, b);
                }
            }
        }
        4 => {
            for i in 1..n {
                if rng.chance(500) {
                    push(&mut pairs, 0, i);
                } else {
                    push(&mut pairs, i, 0);
                }
            }
        }
        5 => {
            for i in 1..n {
                push(&mut pairs, i - 1, i);
            }
        }
        6 => {
            // Layered with skip arcs (plan-like).
            for i in 0..n {
                for j in i + 1..n.min(i + 3) {
                    push(&mut pairs, i, j);
                }
            }
        }
        7 => {
            // Two cycles joined by one arc, plus a disjoint tail.
            let half = n / 2;
            for i in 0..half {
                push(&mut pairs, i, (i + 1) % half.max(1));
            }
            for i in half..n {
                let next = if i + 1 < n { i + 1 } else { half };
                push(&mut pairs, i, next);
            }
            if half > 0 && n > half {
                push(&mut pairs, 0, half);
            }
        }
        _ => {}
    }
    let arcs = pairs
        .into_iter()
        .map(|(a, b)| (a, b, weight(&mut rng)))
        .collect();
    Spec {
        orientation,
        nodes,
        arcs,
    }
}

fn anchor() -> LedgerAnchor {
    LedgerAnchor::genesis("site:graph-certification")
}

/// Bound, witness re-check, tamper refusal and the budget-one-short refusal for one run.
fn certify<O, F>(
    run: &CertifiedRun<O>,
    identity: &AlgorithmIdentity,
    bound: &[(&'static str, u64)],
    rerun: F,
) -> TestResult
where
    F: Fn(Budget) -> Result<CertifiedRun<O>, GraphError>,
{
    let witness = run.witness("projection:certification", anchor())?;
    check_witness(&witness, identity, bound)?;
    assert_eq!(witness.output_digest(), run.output_digest);
    if run.operations > 0 {
        let short = rerun(Budget::new(run.operations - 1, u64::MAX));
        assert!(
            matches!(
                short,
                Err(GraphError::BudgetExhausted {
                    dimension: "operations",
                    ..
                })
            ),
            "{}: a budget one short must fail closed: {:?}",
            identity.algorithm_id,
            short.err()
        );
    }
    if run.output_entries > 0 {
        let short = rerun(Budget::new(u64::MAX, run.output_entries - 1));
        assert!(
            matches!(
                short,
                Err(GraphError::BudgetExhausted {
                    dimension: "output_entries",
                    ..
                })
            ),
            "{}: an output budget one short must fail closed",
            identity.algorithm_id
        );
    }
    // Tamper: inflate the first counter far above any bound.
    let mut counts = witness.dominant_operation_counts().clone();
    if let Some((_, value)) = counts.iter_mut().next() {
        *value = u64::MAX;
    }
    let tampered = GraphAlgorithmWitness::new(GraphAlgorithmWitnessParams {
        algorithm_id: witness.algorithm_id().to_owned(),
        implementation_id: witness.implementation_id().to_owned(),
        projection_id: witness.projection_id().to_owned(),
        anchor: witness.anchor().clone(),
        node_count: witness.node_count(),
        edge_count: witness.edge_count(),
        input_digest: witness.input_digest(),
        policy_id: witness.policy_id().to_owned(),
        dominant_operation_counts: counts,
        peak_working_bytes: witness.peak_working_bytes(),
        budget_consumed: witness.budget_consumed().clone(),
        exactness: witness.exactness().to_owned(),
        error_bound: None,
        stop_reason: witness.stop_reason().to_owned(),
        decision_path_digest: witness.decision_path_digest(),
        output_digest: witness.output_digest(),
    })?;
    assert!(check_witness(&tampered, identity, bound).is_err());
    Ok(())
}

fn registered(budget_rows: &[(&'static str, u64)]) -> Budget {
    Budget::registered(budget_rows)
}

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

fn registry_row(algorithm_id: &str) -> TestResult<String> {
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../architecture/graph_algorithms.json"),
    )?;
    let start = text
        .find(&format!("\"id\": \"{algorithm_id}\""))
        .ok_or("algorithm row missing from the registry")?;
    let rest = &text[start..];
    let end = rest.find('}').ok_or("unterminated registry row")?;
    Ok(rest[..end].to_owned())
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
        let row = registry_row(identity.algorithm_id)?;
        for (field, value) in identity.registry_fields() {
            assert!(
                row.contains(&format!("\"{field}\": \"{value}\"")),
                "{} registry row lacks {field} = {value}",
                identity.algorithm_id
            );
        }
    }
    Ok(())
}
