#![forbid(unsafe_code)]
//! Certification of `ALG-KSP-001`, `ALG-TREACH-001` and `ALG-DYNCONN-001` against exhaustive
//! oracles: every loopless path in `(cost, hops, sequence)` order with the same diversity and
//! cap rule; integer-time presence fixpoints over small horizons; and per-state BFS component
//! counts. Metamorphic insertion order, budget-one-short, tampered-witness and registry checks.

mod common;

use common::{Rng, SEEDS, TestResult, assert_registered, certify, generate, registered};
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::dynconn::{self, EdgeUpdate};
use fss_graph_algorithms::ksp;
use fss_graph_algorithms::temporal::{
    self, Reachability, TemporalNetwork, TemporalNetworkBuilder, Transit,
};
use fss_graph_algorithms::weighted::{Orientation, WeightedGraphBuilder};
use fss_graph_algorithms::{GraphError, oracles};

#[test]
fn k_shortest_paths_equal_exhaustive_enumeration() -> TestResult {
    let mut nontrivial = 0;
    for seed in 0..SEEDS {
        for orientation in [Orientation::Directed, Orientation::Undirected] {
            let spec = generate(seed, orientation, 7);
            let graph = spec.build(None)?;
            let n = graph.node_count();
            if n < 2 {
                continue;
            }
            let s = (seed as usize % n) as u32;
            let t = ((s as usize + 1 + seed as usize / 3) % n) as u32;
            if s == t {
                continue;
            }
            let k = 1 + (seed % 5) as u32;
            let diversity = (seed % 3) as u32;
            let cap = k + (seed % 7) as u32;
            let (n64, m64) = (n as u64, graph.arc_count() as u64);
            let bound = ksp::bound(orientation, n64, m64, u64::from(k), u64::from(cap));
            let run = ksp::k_shortest_paths(
                &graph,
                graph.id(s),
                graph.id(t),
                k,
                diversity,
                cap,
                registered(&bound),
            )?;
            let (paths, enumerated, rejected, stop) =
                oracles::k_shortest(&graph, s, t, k, diversity, cap);
            let expected: Vec<(u64, u64, Vec<String>)> = paths
                .iter()
                .map(|(cost, hops, nodes)| {
                    (
                        *cost,
                        *hops,
                        nodes.iter().map(|&v| graph.id(v).to_owned()).collect(),
                    )
                })
                .collect();
            let got: Vec<(u64, u64, Vec<String>)> = run
                .output
                .paths
                .iter()
                .map(|path| (path.cost, path.hops, path.nodes.clone()))
                .collect();
            assert_eq!(
                got, expected,
                "seed {seed} {orientation} k {k} d {diversity} cap {cap}"
            );
            assert_eq!(
                (
                    run.output.enumerated,
                    run.output.rejected_for_diversity,
                    run.output.stop.as_str()
                ),
                (enumerated, rejected, stop),
                "seed {seed} {orientation}"
            );
            if run.output.paths.len() > 1 {
                nontrivial += 1;
            }
            let shuffled = ksp::k_shortest_paths(
                &spec.build(Some(seed))?,
                graph.id(s),
                graph.id(t),
                k,
                diversity,
                cap,
                registered(&bound),
            )?;
            assert_eq!(shuffled, run, "seed {seed}");
            if seed % 25 == 0 {
                certify(&run, &ksp::IDENTITY, &bound, |budget| {
                    ksp::k_shortest_paths(
                        &graph,
                        graph.id(s),
                        graph.id(t),
                        k,
                        diversity,
                        cap,
                        budget,
                    )
                })?;
            }
        }
    }
    assert!(nontrivial > 500, "{nontrivial}");
    Ok(())
}

fn seeded_network(seed: u64, shuffle: bool) -> Result<(TemporalNetwork, u32), GraphError> {
    let mut rng = Rng(seed.wrapping_mul(0x51_7cc1_b727_220a) ^ 0x7e57);
    let n = 1 + rng.below(6);
    let horizon = 4 + rng.below(28) as u64;
    let mut nodes: Vec<(String, u64)> = (0..n)
        .map(|i| {
            let wait = match rng.below(4) {
                0 => 0,
                1 => rng.next() % 3,
                2 => rng.next() % 10,
                _ => u64::MAX,
            };
            (format!("zone-{}", (i * 5) % 7), wait)
        })
        .collect();
    let mut arcs = Vec::new();
    for a in 0..n {
        for b in 0..n {
            if a != b && rng.chance(350) {
                let open = rng.next() % (horizon + 2);
                let close = open + rng.next() % (horizon + 2);
                let min_travel = rng.next() % 6;
                let max_travel = min_travel + rng.next() % 6;
                arcs.push((
                    a,
                    b,
                    Transit {
                        open,
                        close,
                        min_travel,
                        max_travel,
                    },
                ));
            }
        }
    }
    let source = rng.below(n);
    let mut order: Vec<usize> = (0..n).collect();
    if shuffle {
        let mut shuffler = Rng(seed);
        shuffler.shuffle(&mut nodes);
        shuffler.shuffle(&mut arcs);
        shuffler.shuffle(&mut order);
    }
    let names: Vec<String> = (0..n).map(|i| format!("zone-{}", (i * 5) % 7)).collect();
    let mut builder = TemporalNetworkBuilder::new("s", horizon);
    for (id, wait) in &nodes {
        builder.add_node(id.clone(), *wait);
    }
    for &(a, b, transit) in &arcs {
        builder.add_transit(names[a].clone(), names[b].clone(), transit);
    }
    let built = builder.build()?;
    let index = built.index_of(&names[source]).ok_or(GraphError::TooLarge)?;
    Ok((built, index))
}

#[test]
fn temporal_reachability_equals_integer_time_fixpoint() -> TestResult {
    let mut infeasible = 0;
    for seed in 0..SEEDS * 2 {
        let (network, source) = seeded_network(seed, false)?;
        let mut rng = Rng(seed ^ 0x51a7);
        let a = rng.next() % (network.horizon() + 3);
        let start = (a, a + rng.next() % 4);
        let (n64, m64) = (network.ids().len() as u64, network.transits().len() as u64);
        let cap = 64;
        let bound = temporal::bound(n64, m64, network.horizon(), cap);
        let source_id = network.ids()[source as usize].clone();
        let run = temporal::temporal_reachability(
            &network,
            &source_id,
            start,
            cap as u32,
            registered(&bound),
        )?;
        let expected = oracles::temporal_presence(&network, source, start);
        for (node, row) in run.output.rows.iter().enumerate() {
            let mut points = vec![false; network.horizon() as usize + 1];
            for &(lo, hi) in &row.presence {
                for time in lo..=hi {
                    assert!(!points[time as usize], "seed {seed}: overlapping intervals");
                    points[time as usize] = true;
                }
            }
            assert_eq!(
                points, expected[node],
                "seed {seed}: presence at {}",
                row.node
            );
            for pair in row.presence.windows(2) {
                assert!(
                    pair[0].1 + 1 < pair[1].0,
                    "seed {seed}: intervals must be disjoint and non-adjacent"
                );
            }
            if row.reachability == Reachability::TemporallyInfeasible {
                infeasible += 1;
            }
        }
        let (shuffled, _) = seeded_network(seed, true)?;
        let again = temporal::temporal_reachability(
            &shuffled,
            &source_id,
            start,
            cap as u32,
            registered(&bound),
        )?;
        assert_eq!(again, run, "seed {seed}");
        if seed % 50 == 0 {
            certify(&run, &temporal::IDENTITY, &bound, |budget| {
                temporal::temporal_reachability(&network, &source_id, start, cap as u32, budget)
            })?;
        }
    }
    assert!(
        infeasible > 50,
        "the corpus must exercise temporally infeasible paths ({infeasible})"
    );
    Ok(())
}

#[test]
fn temporal_textbook_cases_and_refusals() -> TestResult {
    // Two camera zones joined by a 5..8 s walk that may only start while a gate is open.
    let mut builder = TemporalNetworkBuilder::new("s", 100);
    builder
        .add_node("driveway", 0)
        .add_node("porch", 0)
        .add_node("garden", 0);
    builder.add_transit(
        "driveway",
        "porch",
        Transit {
            open: 10,
            close: 12,
            min_travel: 5,
            max_travel: 8,
        },
    );
    builder.add_transit(
        "garden",
        "porch",
        Transit {
            open: 0,
            close: 100,
            min_travel: 1,
            max_travel: 1,
        },
    );
    let network = builder.build()?;
    let bound = temporal::bound(3, 2, 100, 8);
    let early =
        temporal::temporal_reachability(&network, "driveway", (0, 3), 8, registered(&bound))?;
    let porch = early.output.row("porch").ok_or("porch row")?;
    assert_eq!(porch.reachability, Reachability::TemporallyInfeasible);
    assert_eq!(
        early.output.row("garden").ok_or("garden")?.reachability,
        Reachability::NoPath
    );
    let late =
        temporal::temporal_reachability(&network, "driveway", (9, 11), 8, registered(&bound))?;
    assert_eq!(
        late.output.row("porch").ok_or("porch")?.presence,
        vec![(15, 19)]
    );
    // A tiny interval cap fails closed instead of truncating.
    let mut ring = TemporalNetworkBuilder::new("s", 60);
    ring.add_node("a", 0).add_node("b", 0);
    ring.add_transit(
        "a",
        "b",
        Transit {
            open: 0,
            close: 60,
            min_travel: 3,
            max_travel: 3,
        },
    );
    ring.add_transit(
        "b",
        "a",
        Transit {
            open: 0,
            close: 60,
            min_travel: 4,
            max_travel: 4,
        },
    );
    let refused = temporal::temporal_reachability(
        &ring.build()?,
        "a",
        (0, 0),
        2,
        Budget::new(1 << 30, 1 << 20),
    );
    assert!(matches!(
        refused,
        Err(GraphError::BudgetExhausted {
            dimension: "intervals",
            ..
        })
    ));
    let mut inverted = TemporalNetworkBuilder::new("s", 10);
    inverted.add_node("a", 0).add_node("b", 0);
    inverted.add_transit(
        "a",
        "b",
        Transit {
            open: 5,
            close: 4,
            min_travel: 0,
            max_travel: 0,
        },
    );
    assert_eq!(
        inverted.build().err().map(|e| e.stable_id()),
        Some("ERR-GRAPH-PRECONDITION-001")
    );
    Ok(())
}

#[test]
fn dynamic_connectivity_equals_per_state_recomputation() -> TestResult {
    for seed in 0..SEEDS {
        let spec = generate(seed, Orientation::Undirected, 8);
        let graph = spec.build(None)?;
        let n = graph.node_count();
        if n == 0 {
            continue;
        }
        let mut rng = Rng(seed ^ 0xd1c0);
        let mut present: std::collections::BTreeSet<(u32, u32)> = graph
            .arcs()
            .iter()
            .map(|arc| (arc.tail, arc.head))
            .collect();
        let mut batches = Vec::new();
        for _ in 0..rng.below(7) {
            let mut batch = Vec::new();
            for _ in 0..rng.below(4) {
                let (a, b) = (rng.below(n) as u32, rng.below(n) as u32);
                if a == b {
                    continue;
                }
                let key = (a.min(b), a.max(b));
                let (x, y) = (graph.id(a).to_owned(), graph.id(b).to_owned());
                if present.remove(&key) {
                    batch.push(EdgeUpdate::Delete(x, y));
                } else {
                    present.insert(key);
                    batch.push(EdgeUpdate::Insert(x, y));
                }
            }
            batches.push(batch);
        }
        let states = oracles::connectivity_states(&graph, &batches);
        let mut queries: Vec<(u32, String, String)> = Vec::new();
        for _ in 0..rng.below(10) {
            let state = rng.below(batches.len() + 1) as u32;
            queries.push((
                state,
                graph.id(rng.below(n) as u32).to_owned(),
                graph.id(rng.below(n) as u32).to_owned(),
            ));
        }
        let query_refs: Vec<(u32, &str, &str)> = queries
            .iter()
            .map(|(s, a, b)| (*s, a.as_str(), b.as_str()))
            .collect();
        let mut canonical: Vec<(u32, u32, u32)> = query_refs
            .iter()
            .map(|&(s, a, b)| {
                let (x, y) = (
                    graph.index_of(a).unwrap_or(0),
                    graph.index_of(b).unwrap_or(0),
                );
                (s, x.min(y), x.max(y))
            })
            .collect();
        canonical.sort_unstable();
        canonical.dedup();
        let lifetimes = 64;
        let bound = dynconn::bound(
            n as u64,
            lifetimes,
            batches.len() as u64 + 1,
            canonical.len() as u64,
        );
        let run = dynconn::dynamic_connectivity(&graph, &batches, &query_refs, registered(&bound))?;
        let counts: Vec<u64> = states.iter().map(|(count, _)| *count).collect();
        assert_eq!(run.output.component_counts, counts, "seed {seed}");
        let expected: Vec<(u32, String, String, bool)> = canonical
            .iter()
            .map(|&(s, x, y)| {
                let labels = &states[s as usize].1;
                (
                    s,
                    graph.id(x).to_owned(),
                    graph.id(y).to_owned(),
                    labels[x as usize] == labels[y as usize],
                )
            })
            .collect();
        assert_eq!(run.output.answers, expected, "seed {seed}");
    }
    // Strict updates.
    let mut builder = WeightedGraphBuilder::undirected("links");
    builder.add_node("a").add_node("b").add_arc("a", "b", 1);
    let graph = builder.build()?;
    let insert_present = dynconn::dynamic_connectivity(
        &graph,
        &[vec![EdgeUpdate::Insert("a".into(), "b".into())]],
        &[],
        Budget::new(1000, 1000),
    );
    assert_eq!(
        insert_present.err().map(|e| e.stable_id()),
        Some("ERR-GRAPH-PRECONDITION-001")
    );
    let delete_then = dynconn::dynamic_connectivity(
        &graph,
        &[vec![EdgeUpdate::Delete("a".into(), "b".into())]],
        &[(0, "a", "b"), (1, "b", "a")],
        Budget::new(1000, 1000),
    )?;
    assert_eq!(delete_then.output.component_counts, vec![1, 2]);
    assert_eq!(
        delete_then.output.answers,
        vec![
            (0, "a".to_owned(), "b".to_owned(), true),
            (1, "a".to_owned(), "b".to_owned(), false)
        ]
    );
    certify(
        &delete_then,
        &dynconn::IDENTITY,
        &dynconn::bound(2, 1, 2, 2),
        |budget| {
            dynconn::dynamic_connectivity(
                &graph,
                &[vec![EdgeUpdate::Delete("a".into(), "b".into())]],
                &[(0, "a", "b"), (1, "b", "a")],
                budget,
            )
        },
    )?;
    Ok(())
}

#[test]
fn implemented_identities_equal_their_machine_registry_rows() -> TestResult {
    for identity in [&ksp::IDENTITY, &temporal::IDENTITY, &dynconn::IDENTITY] {
        assert_registered(identity)?;
    }
    Ok(())
}
