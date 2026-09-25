#![forbid(unsafe_code)]
//! Certification of `ALG-BRIDGE-001` against the brute-force removal oracle.
//!
//! 1. Differential: thousands of seeded graphs from a deterministic generator (random `G(n, p)`,
//!    random trees, paths, cycles, stars, cliques, barbells, lollipops, grids, disjoint unions,
//!    and plane/sensor/zone coverage shapes), each with and without a root, must produce exactly
//!    the oracle's cut vertices, bridges, unreachable set and root separations.
//! 2. Metamorphic: node and edge insertion order and edge orientation never change anything
//!    (answer, decision path, witness digest); relabelling by a bijection maps the answer through
//!    the bijection.
//! 3. Bounds: every run's counters lie within the registered bound (checked in the runtime path
//!    and again here from the witness), exact counters equal `n` visits and `2m` scans, a budget
//!    one short fails closed, and a tampered witness is refused.
//! 4. Registry: the implemented identities equal the machine registry row.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use fss_core::{ContentDigest, GraphAlgorithmWitness, GraphAlgorithmWitnessParams, LedgerAnchor};
use fss_graph_algorithms::bridges::{BridgeOutput, check_witness_bound};
use fss_graph_algorithms::reference::reference_bridges;
use fss_graph_algorithms::registry;
use fss_graph_algorithms::{
    GraphBudget, GraphBuilder, GraphError, UndirectedGraph, analyse_bridges,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const CORPUS_SEEDS: u64 = 4_000;

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

/// A generated graph: node identities and undirected edges by identity.
#[derive(Clone, Debug)]
struct Spec {
    nodes: Vec<String>,
    edges: Vec<(String, String)>,
}

impl Spec {
    fn numbered(n: usize, edges: &[(usize, usize)]) -> Self {
        let name = |index: usize| format!("n{index:03}");
        let mut unique = BTreeSet::new();
        let mut kept = Vec::new();
        for &(a, b) in edges {
            if a != b && unique.insert((a.min(b), a.max(b))) {
                kept.push((name(a), name(b)));
            }
        }
        Self {
            nodes: (0..n).map(name).collect(),
            edges: kept,
        }
    }

    fn build(&self) -> Result<UndirectedGraph, GraphError> {
        let mut builder = GraphBuilder::new();
        for node in &self.nodes {
            builder.add_node(node.clone());
        }
        for (a, b) in &self.edges {
            builder.add_edge(a.clone(), b.clone());
        }
        builder.build()
    }
}

fn clique(offset: usize, size: usize, edges: &mut Vec<(usize, usize)>) {
    for a in 0..size {
        for b in a + 1..size {
            edges.push((offset + a, offset + b));
        }
    }
}

fn generate(seed: u64) -> Spec {
    let mut rng = Rng(seed.wrapping_mul(0xa076_1d64_78bd_642f) ^ 0x5eed);
    let family = seed % 11;
    let mut edges = Vec::new();
    let n;
    match family {
        0 | 1 => {
            n = rng.below(25);
            let density = [30, 80, 150, 300, 600][rng.below(5)];
            for a in 0..n {
                for b in a + 1..n {
                    if rng.chance(density) {
                        edges.push((a, b));
                    }
                }
            }
        }
        2 => {
            n = 1 + rng.below(30);
            for child in 1..n {
                edges.push((rng.below(child), child));
            }
            for _ in 0..rng.below(3) {
                edges.push((rng.below(n), rng.below(n)));
            }
        }
        3 => {
            n = 1 + rng.below(20);
            for index in 1..n {
                edges.push((index - 1, index));
            }
            if rng.chance(500) && n > 2 {
                edges.push((n - 1, 0));
            }
        }
        4 => {
            n = 1 + rng.below(20);
            for leaf in 1..n {
                edges.push((0, leaf));
            }
            if n > 3 && rng.chance(500) {
                edges.push((1, 2));
            }
        }
        5 => {
            n = 1 + rng.below(10);
            clique(0, n, &mut edges);
        }
        6 => {
            // Barbell: two cliques joined by a path.
            let size = 3 + rng.below(4);
            let bar = rng.below(4);
            n = 2 * size + bar;
            clique(0, size, &mut edges);
            clique(size + bar, size, &mut edges);
            let mut previous = size - 1;
            for index in size..size + bar {
                edges.push((previous, index));
                previous = index;
            }
            edges.push((previous, size + bar));
        }
        7 => {
            // Lollipop: a clique with a tail.
            let size = 3 + rng.below(5);
            let tail = 1 + rng.below(6);
            n = size + tail;
            clique(0, size, &mut edges);
            for index in size..n {
                edges.push((index - 1, index));
            }
        }
        8 => {
            let (rows, columns) = (1 + rng.below(5), 1 + rng.below(5));
            n = rows * columns;
            for row in 0..rows {
                for column in 0..columns {
                    let node = row * columns + column;
                    if column + 1 < columns && !rng.chance(150) {
                        edges.push((node, node + 1));
                    }
                    if row + 1 < rows && !rng.chance(150) {
                        edges.push((node, node + columns));
                    }
                }
            }
        }
        9 => {
            // Disjoint union of two random sparse graphs plus isolated nodes.
            let (left, right) = (1 + rng.below(10), 1 + rng.below(10));
            n = left + right + rng.below(3);
            for (offset, size) in [(0, left), (left, right)] {
                for a in 0..size {
                    for b in a + 1..size {
                        if rng.chance(250) {
                            edges.push((offset + a, offset + b));
                        }
                    }
                }
            }
        }
        _ => {
            // Coverage shape: node 0 is the plane, then sensors, then zones.
            let sensors = 1 + rng.below(6);
            let zones = 1 + rng.below(8);
            n = 1 + sensors + zones;
            for sensor in 1..=sensors {
                edges.push((0, sensor));
                for zone in 0..zones {
                    if rng.chance(300) {
                        edges.push((sensor, 1 + sensors + zone));
                    }
                }
            }
        }
    }
    Spec::numbered(n, &edges)
}

fn root_for(spec: &Spec, seed: u64) -> Option<String> {
    if spec.nodes.is_empty() || seed % 4 == 3 {
        return None;
    }
    let mut rng = Rng(seed ^ 0x0000_0000_0000_beef);
    if seed % 11 == 10 {
        return Some(spec.nodes[0].clone());
    }
    Some(spec.nodes[rng.below(spec.nodes.len())].clone())
}

fn anchor() -> LedgerAnchor {
    LedgerAnchor::genesis("site:graph-certification")
}

#[test]
fn optimized_run_equals_the_removal_oracle_on_the_seeded_corpus() -> TestResult {
    let mut checked = 0_u64;
    let mut nontrivial = 0_u64;
    let mut with_separations = 0_u64;
    for seed in 0..CORPUS_SEEDS {
        let spec = generate(seed);
        let graph = spec.build()?;
        let root = root_for(&spec, seed);
        let analysis = analyse_bridges(&graph, root.as_deref(), GraphBudget::registered(&graph))?;
        let oracle = reference_bridges(&graph, root.as_deref())?;
        assert_eq!(analysis.output, oracle, "seed {seed}: {spec:?}");
        assert_eq!(analysis.output_digest, oracle.digest());
        // Exact counters: every node is visited once and every edge scanned from both ends.
        assert_eq!(analysis.counters.dfs_node_visits, graph.node_count() as u64);
        assert_eq!(
            analysis.counters.adjacency_scans,
            2 * graph.edge_count() as u64
        );
        let witness = analysis.witness("SensorCoverageGraph@certification", anchor())?;
        check_witness_bound(&witness)?;
        assert_eq!(witness.output_digest(), oracle.digest());
        assert_eq!(witness.input_digest(), graph.digest());
        checked += 1;
        if !oracle.articulation_points.is_empty() || !oracle.bridges.is_empty() {
            nontrivial += 1;
        }
        if !oracle.vertex_separations.is_empty() {
            with_separations += 1;
        }
    }
    assert_eq!(checked, CORPUS_SEEDS);
    // The corpus exercises the interesting cases, not only trivially 2-connected graphs.
    assert!(nontrivial > CORPUS_SEEDS / 2, "nontrivial {nontrivial}");
    assert!(
        with_separations > CORPUS_SEEDS / 4,
        "separations {with_separations}"
    );
    Ok(())
}

#[test]
fn insertion_order_and_orientation_never_change_the_answer_or_witness() -> TestResult {
    for seed in 0..600 {
        let spec = generate(seed);
        let root = root_for(&spec, seed);
        let graph = spec.build()?;
        let baseline = analyse_bridges(&graph, root.as_deref(), GraphBudget::registered(&graph))?;
        let mut rng = Rng(seed ^ 0x0123_4567);
        let mut shuffled = spec.clone();
        rng.shuffle(&mut shuffled.nodes);
        rng.shuffle(&mut shuffled.edges);
        for edge in &mut shuffled.edges {
            if rng.chance(500) {
                std::mem::swap(&mut edge.0, &mut edge.1);
            }
        }
        let permuted = shuffled.build()?;
        assert_eq!(permuted, graph);
        let run = analyse_bridges(
            &permuted,
            root.as_deref(),
            GraphBudget::registered(&permuted),
        )?;
        assert_eq!(run, baseline, "seed {seed}");
        assert_eq!(
            run.witness("p", anchor())?.digest(),
            baseline.witness("p", anchor())?.digest()
        );
    }
    Ok(())
}

fn map_output(
    output: &BridgeOutput,
    mapping: &BTreeMap<String, String>,
) -> TestResult<BridgeOutput> {
    let name = |id: &String| -> TestResult<String> {
        Ok(mapping.get(id).ok_or("unmapped identity")?.clone())
    };
    let names = |ids: &[String]| -> TestResult<Vec<String>> {
        let mut out = ids.iter().map(name).collect::<TestResult<Vec<_>>>()?;
        out.sort_unstable();
        Ok(out)
    };
    let pair = |(a, b): &(String, String)| -> TestResult<(String, String)> {
        let (a, b) = (name(a)?, name(b)?);
        Ok(if a <= b { (a, b) } else { (b, a) })
    };
    let mut bridges = output
        .bridges
        .iter()
        .map(pair)
        .collect::<TestResult<Vec<_>>>()?;
    bridges.sort_unstable();
    let mut vertex_separations = output
        .vertex_separations
        .iter()
        .map(|entry| {
            Ok(fss_graph_algorithms::VertexSeparation {
                node: name(&entry.node)?,
                separated: names(&entry.separated)?,
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    vertex_separations.sort_unstable();
    let mut bridge_separations = output
        .bridge_separations
        .iter()
        .map(|entry| {
            Ok(fss_graph_algorithms::BridgeSeparation {
                edge: pair(&entry.edge)?,
                separated: names(&entry.separated)?,
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    bridge_separations.sort_unstable();
    Ok(BridgeOutput {
        root: output.root.as_ref().map(name).transpose()?,
        articulation_points: names(&output.articulation_points)?,
        bridges,
        unreachable_from_root: names(&output.unreachable_from_root)?,
        vertex_separations,
        bridge_separations,
    })
}

#[test]
fn relabelling_maps_the_answer_through_the_bijection() -> TestResult {
    for seed in 0..600 {
        let spec = generate(seed);
        let root = root_for(&spec, seed);
        let graph = spec.build()?;
        let baseline = analyse_bridges(&graph, root.as_deref(), GraphBudget::registered(&graph))?;
        // A bijection onto fresh identities whose canonical order differs from the original.
        let mut rng = Rng(seed ^ 0x00ab_cdef);
        let mut targets: Vec<usize> = (0..spec.nodes.len()).collect();
        rng.shuffle(&mut targets);
        let forward: BTreeMap<String, String> = spec
            .nodes
            .iter()
            .zip(&targets)
            .map(|(old, new)| (old.clone(), format!("relabelled-{new:04}-{}", old.len())))
            .collect();
        let backward: BTreeMap<String, String> = forward
            .iter()
            .map(|(a, b)| (b.clone(), a.clone()))
            .collect();
        let relabelled = Spec {
            nodes: spec.nodes.iter().map(|id| forward[id].clone()).collect(),
            edges: spec
                .edges
                .iter()
                .map(|(a, b)| (forward[a].clone(), forward[b].clone()))
                .collect(),
        };
        let relabelled_graph = relabelled.build()?;
        let relabelled_root = root.as_ref().map(|id| forward[id].clone());
        let run = analyse_bridges(
            &relabelled_graph,
            relabelled_root.as_deref(),
            GraphBudget::registered(&relabelled_graph),
        )?;
        assert_eq!(
            map_output(&run.output, &backward)?,
            baseline.output,
            "seed {seed}"
        );
        // Order-independent counters are invariant; all counters stay within the bound.
        assert_eq!(
            run.counters.dfs_node_visits,
            baseline.counters.dfs_node_visits
        );
        assert_eq!(
            run.counters.adjacency_scans,
            baseline.counters.adjacency_scans
        );
        assert_eq!(run.counters.tree_edges, baseline.counters.tree_edges);
        assert_eq!(
            run.counters.separation_entries,
            baseline.counters.separation_entries
        );
        check_witness_bound(&run.witness("p", anchor())?)?;
    }
    Ok(())
}

fn named(n: usize, edges: &[(usize, usize)]) -> TestResult<UndirectedGraph> {
    Ok(Spec::numbered(n, edges).build()?)
}

fn ids(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn adversarial_families_have_their_textbook_answers() -> TestResult {
    let budget = |graph: &UndirectedGraph| GraphBudget::registered(graph);
    // Path n0-n1-n2-n3: inner nodes cut, every edge a bridge.
    let path = named(4, &[(0, 1), (1, 2), (2, 3)])?;
    let answer = analyse_bridges(&path, Some("n000"), budget(&path))?;
    assert_eq!(answer.output.articulation_points, ids(&["n001", "n002"]));
    assert_eq!(answer.output.bridges.len(), 3);
    assert_eq!(
        answer.output.vertex_separations[0].separated,
        ids(&["n002", "n003"])
    );
    // Cycle: 2-connected.
    let cycle = named(5, &[(0, 1), (1, 2), (2, 3), (3, 4), (4, 0)])?;
    let answer = analyse_bridges(&cycle, None, budget(&cycle))?;
    assert!(answer.output.articulation_points.is_empty() && answer.output.bridges.is_empty());
    // Star: the centre is the only cut vertex, each spoke a bridge.
    let star = named(5, &[(0, 1), (0, 2), (0, 3), (0, 4)])?;
    let answer = analyse_bridges(&star, Some("n001"), budget(&star))?;
    assert_eq!(answer.output.articulation_points, ids(&["n000"]));
    assert_eq!(answer.output.bridges.len(), 4);
    assert_eq!(
        answer.output.vertex_separations[0].separated,
        ids(&["n002", "n003", "n004"])
    );
    // Empty and singleton graphs.
    let empty = named(0, &[])?;
    let answer = analyse_bridges(&empty, None, budget(&empty))?;
    assert_eq!(answer.output, BridgeOutput::default());
    let single = named(1, &[])?;
    let answer = analyse_bridges(&single, Some("n000"), budget(&single))?;
    assert!(answer.output.articulation_points.is_empty());
    // An unknown root is refused.
    assert_eq!(
        analyse_bridges(&single, Some("missing"), budget(&single))
            .err()
            .map(|error| error.stable_id()),
        Some("ERR-GRAPH-INPUT-INVALID-001")
    );
    Ok(())
}

#[test]
fn budgets_fail_closed_and_tampered_witnesses_are_refused() -> TestResult {
    let graph = named(6, &[(0, 1), (1, 2), (2, 0), (2, 3), (3, 4), (4, 5)])?;
    let registered = GraphBudget::registered(&graph);
    let short = GraphBudget {
        max_operations: registered.max_operations - 1,
        ..registered
    };
    assert_eq!(
        analyse_bridges(&graph, Some("n000"), short)
            .err()
            .map(|error| error.stable_id()),
        Some("ERR-GRAPH-BUDGET-EXHAUSTED-001")
    );
    let tiny = GraphBudget {
        max_output_entries: 1,
        ..registered
    };
    assert!(matches!(
        analyse_bridges(&graph, Some("n000"), tiny),
        Err(GraphError::BudgetExhausted {
            dimension: "output_entries",
            ..
        })
    ));
    let honest = analyse_bridges(&graph, Some("n000"), registered)?.witness("p", anchor())?;
    check_witness_bound(&honest)?;
    let mut counts = honest.dominant_operation_counts().clone();
    counts.insert(
        "adjacency_scans".to_owned(),
        2 * graph.edge_count() as u64 + 1,
    );
    let tampered = GraphAlgorithmWitness::new(GraphAlgorithmWitnessParams {
        algorithm_id: honest.algorithm_id().to_owned(),
        implementation_id: honest.implementation_id().to_owned(),
        projection_id: honest.projection_id().to_owned(),
        anchor: honest.anchor().clone(),
        node_count: honest.node_count(),
        edge_count: honest.edge_count(),
        input_digest: honest.input_digest(),
        policy_id: honest.policy_id().to_owned(),
        dominant_operation_counts: counts,
        peak_working_bytes: honest.peak_working_bytes(),
        budget_consumed: honest.budget_consumed().clone(),
        exactness: honest.exactness().to_owned(),
        error_bound: honest.error_bound(),
        stop_reason: honest.stop_reason().to_owned(),
        decision_path_digest: honest.decision_path_digest(),
        output_digest: honest.output_digest(),
    })?;
    assert_ne!(tampered.digest(), honest.digest());
    assert_eq!(
        check_witness_bound(&tampered)
            .err()
            .map(|error| error.stable_id()),
        Some("ERR-GRAPH-COMPLEXITY-BOUND-001")
    );
    assert_ne!(honest.output_digest(), ContentDigest::sha256(b""));
    Ok(())
}

fn registry_row() -> TestResult<String> {
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../architecture/graph_algorithms.json"),
    )?;
    let start = text
        .find(&format!("\"id\": \"{}\"", registry::ALGORITHM_ID))
        .ok_or("algorithm row missing from the registry")?;
    let rest = &text[start..];
    let end = rest.find('}').ok_or("unterminated registry row")?;
    Ok(rest[..end].to_owned())
}

#[test]
fn implemented_identities_equal_the_machine_registry_row() -> TestResult {
    let row = registry_row()?;
    for (field, value) in [
        ("name", registry::ALGORITHM_NAME),
        ("owner", "fss-graph-algorithms"),
        ("tieBreak", registry::TIE_BREAK_RULE),
        ("complexityWitness", registry::COMPLEXITY_WITNESS),
        ("outputSizeWitness", registry::OUTPUT_SIZE_WITNESS),
        ("exactness", registry::EXACTNESS),
        ("implementationId", registry::IMPLEMENTATION_ID),
        ("tieBreakPolicyId", registry::TIE_BREAK_POLICY_ID),
        ("policyId", registry::POLICY_ID),
        ("complexityBoundId", registry::COMPLEXITY_BOUND_ID),
    ] {
        assert!(
            row.contains(&format!("\"{field}\": \"{value}\"")),
            "registry row lacks {field} = {value}: {row}"
        );
    }
    assert!(row.contains("\"SensorCoverageGraph\""));
    assert!(row.contains("\"status\": \"implemented\""));
    Ok(())
}
