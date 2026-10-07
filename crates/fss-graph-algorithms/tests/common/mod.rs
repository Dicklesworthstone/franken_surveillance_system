//! Shared seeded generator and certification helpers of the graph certification tests.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::error::Error;

use fss_core::{GraphAlgorithmWitness, GraphAlgorithmWitnessParams, LedgerAnchor};
use fss_graph_algorithms::GraphError;
use fss_graph_algorithms::certified::{AlgorithmIdentity, Budget, CertifiedRun, check_witness};
use fss_graph_algorithms::weighted::{Orientation, WeightedGraph, WeightedGraphBuilder};

pub type TestResult<T = ()> = Result<T, Box<dyn Error>>;

pub const SEEDS: u64 = 2_500;

/// SplitMix64: deterministic, platform independent.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next() % bound as u64) as usize
        }
    }

    pub fn chance(&mut self, per_mille: u64) -> bool {
        self.next() % 1000 < per_mille
    }

    pub fn shuffle<T>(&mut self, values: &mut [T]) {
        for index in (1..values.len()).rev() {
            let other = self.below(index + 1);
            values.swap(index, other);
        }
    }
}

#[derive(Clone, Debug)]
pub struct Spec {
    pub orientation: Orientation,
    pub nodes: Vec<(String, u64)>,
    pub arcs: Vec<(usize, usize, u64)>,
}

impl Spec {
    pub fn build(&self, shuffle: Option<u64>) -> Result<WeightedGraph, GraphError> {
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
pub fn node_id(index: usize) -> String {
    format!("n{}-{}", (index * 7) % 10, index)
}

pub fn generate(seed: u64, orientation: Orientation, max_nodes: usize) -> Spec {
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

pub fn anchor() -> LedgerAnchor {
    LedgerAnchor::genesis("site:graph-certification")
}

/// Bound, witness re-check, tamper refusal and the budget-one-short refusal for one run.
pub fn certify<O, F>(
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

pub fn registered(budget_rows: &[(&'static str, u64)]) -> Budget {
    Budget::registered(budget_rows)
}

pub fn registry_row(algorithm_id: &str) -> TestResult<String> {
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

/// Asserts every identity field equals its machine registry row.
pub fn assert_registered(identity: &AlgorithmIdentity) -> TestResult {
    let row = registry_row(identity.algorithm_id)?;
    for (field, value) in identity.registry_fields() {
        assert!(
            row.contains(&format!("\"{field}\": \"{value}\"")),
            "{} registry row lacks {field} = {value}",
            identity.algorithm_id
        );
    }
    Ok(())
}
