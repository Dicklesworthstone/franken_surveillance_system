#![forbid(unsafe_code)]
//! `ALG-FACTOR-001` — Factorized free join (worst-case optimal Leapfrog Triejoin) over multiway
//! relational and graph pattern projections.
//!
//! Intersects sorted relation slices level-by-level in canonical variable order, starting from
//! the smallest extension slice at each binding prefix, and emits a compressed factorized trie
//! without materializing explosive intermediate Cartesian products
//! (`tie:lexicographic-variable-order-then-ascending-key-tuple:v1`).

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, mul, query_digest, query_encoder,
};
use crate::graph::GraphError;
use crate::weighted::{Orientation, WeightedGraph};

/// Projection digest domain (`SCHEMA-DOMAIN-GRAPH-FACTOR-PROJECTION-001`).
pub const PROJECTION_DOMAIN: &str = "fss.graph.factor_projection.v1";
/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-FACTOR-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.factor_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-FACTOR-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.factor_decision_path.v1";

/// Registered identity (`architecture/graph_algorithms.json`, `ALG-FACTOR-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-FACTOR-001",
    algorithm_name: "factorized_free_join",
    tie_break_rule: "lexicographic stable relation key",
    complexity_witness: "iterator seeks, intersections, and emitted factors",
    output_size_witness: "<= |V| * |Relations| factor nodes and edges",
    exactness: "exact",
    implementation_id: "fss-graph-algorithms:alg-factor-001:leapfrog-triejoin-factorized-trie:v1",
    tie_break_policy_id: "tie:lexicographic-variable-order-then-ascending-key-tuple:v1",
    policy_id: "graph-policy:multiway-relational-pattern:sorted-deduplicated-relations:leapfrog-intersection:tie:lexicographic-variable-order-then-ascending-key-tuple:v1",
    complexity_bound_id: "bound:alg-factor-001:seeks-plus-intersections-plus-emitted-factors:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// Registered complexity bound for domain size `v`, total relation tuples `m`, and `r` relations.
#[must_use]
pub fn bound(v: u64, m: u64, r: u64) -> Vec<BoundRow> {
    let rels = r.max(1);
    let max_factors = mul(v, rels);
    vec![
        ("iterator_seeks", add(mul(rels, add(v, m)), max_factors)),
        ("set_intersections", add(mul(rels, mul(v, v)), max_factors)),
        ("emitted_factors", max_factors),
        (OUTPUT_ENTRIES, max_factors),
    ]
}

/// One binary relation constraining `(left_var, right_var)` with `left_var < right_var`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PatternRelation {
    /// Relation name.
    pub name: String,
    /// Index of the earlier variable (`0..variables.len()`).
    pub left_var: usize,
    /// Index of the later variable (`left_var + 1..variables.len()`).
    pub right_var: usize,
    /// Sorted, deduplicated `(left_value, right_value)` pairs.
    pub pairs: Vec<(String, String)>,
}

/// Canonical multiway relational join problem.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactorJoinProblem {
    /// Query variables in elimination order.
    pub variables: Vec<String>,
    /// Sorted domain of admissible values.
    pub domain: Vec<String>,
    /// Binary relations constraining pairs of variables.
    pub relations: Vec<PatternRelation>,
}

impl FactorJoinProblem {
    /// Builds a pattern join problem over `graph` where each pattern edge `(u_var, v_var)`
    /// binds the graph's arcs (or both directions if undirected).
    ///
    /// # Errors
    ///
    /// Fails closed if `variables` is empty, `pattern_edges` is empty, or any variable index is
    /// out of range or `left_var >= right_var`.
    pub fn from_graph_pattern(
        graph: &WeightedGraph,
        variables: Vec<String>,
        pattern_edges: &[(&str, usize, usize)],
    ) -> Result<Self, GraphError> {
        if variables.is_empty() || variables.len() > 8 {
            return Err(GraphError::PreconditionFailed(
                "variables must have 1..=8 entries".to_owned(),
            ));
        }
        if pattern_edges.is_empty() {
            return Err(GraphError::PreconditionFailed(
                "pattern_edges must not be empty".to_owned(),
            ));
        }
        let domain: Vec<String> = graph.ids().to_vec();
        let mut pairs: Vec<(String, String)> = Vec::new();
        for arc in graph.arcs() {
            let u = graph.id(arc.tail).to_owned();
            let v = graph.id(arc.head).to_owned();
            pairs.push((u.clone(), v.clone()));
            if graph.orientation() == Orientation::Undirected {
                pairs.push((v, u));
            }
        }
        pairs.sort();
        pairs.dedup();

        let mut relations = Vec::with_capacity(pattern_edges.len());
        for &(name, left_var, right_var) in pattern_edges {
            if left_var >= right_var || right_var >= variables.len() {
                return Err(GraphError::PreconditionFailed(
                    "pattern edge requires left_var < right_var < variables.len()".to_owned(),
                ));
            }
            relations.push(PatternRelation {
                name: name.to_owned(),
                left_var,
                right_var,
                pairs: pairs.clone(),
            });
        }
        Ok(Self {
            variables,
            domain,
            relations,
        })
    }

    /// Domain-separated canonical digest of the join problem.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(PROJECTION_DOMAIN);
        encoder.u64(self.variables.len() as u64);
        for var in &self.variables {
            encoder.text(var);
        }
        encoder.u64(self.domain.len() as u64);
        for val in &self.domain {
            encoder.text(val);
        }
        encoder.u64(self.relations.len() as u64);
        for rel in &self.relations {
            encoder.text(&rel.name);
            encoder.u64(rel.left_var as u64);
            encoder.u64(rel.right_var as u64);
            encoder.u64(rel.pairs.len() as u64);
            for (a, b) in &rel.pairs {
                encoder.text(a);
                encoder.text(b);
            }
        }
        ContentDigest::sha256(&encoder.finish())
    }
}

/// One node in the compressed factorized output trie.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FactorNode {
    /// Variable depth (`0..variables.len()`).
    pub depth: u32,
    /// Index of parent factor node at `depth - 1` (`None` at `depth == 0`).
    pub parent: Option<u32>,
    /// Bound value from `domain`.
    pub value: String,
}

/// Canonical answer of `ALG-FACTOR-001`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FactorJoinOutput {
    /// Compressed factorized trie nodes.
    pub factors: Vec<FactorNode>,
    /// Number of complete variable bindings represented by the trie leaves.
    pub complete_bindings: u64,
    /// Whether factor emission stopped at the `|V| * |Relations|` output cap.
    pub capped: bool,
}

impl FactorJoinOutput {
    /// Reconstructs the complete joined tuples in lexicographic order from the factorized trie.
    #[must_use]
    pub fn materialize_tuples(&self, arity: usize) -> Vec<Vec<String>> {
        if arity == 0 || self.factors.is_empty() {
            return Vec::new();
        }
        let target_depth = (arity - 1) as u32;
        let mut out = Vec::new();
        for (idx, factor) in self.factors.iter().enumerate() {
            if factor.depth == target_depth {
                let mut tuple = vec![String::new(); arity];
                let mut cur = Some(idx as u32);
                while let Some(c) = cur {
                    let node = &self.factors[c as usize];
                    tuple[node.depth as usize] = node.value.clone();
                    cur = node.parent;
                }
                out.push(tuple);
            }
        }
        out
    }
}

impl CertifiedOutput for FactorJoinOutput {
    fn entries(&self) -> u64 {
        self.factors.len() as u64
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.complete_bindings);
        encoder.bool(self.capped);
        encoder.u64(self.factors.len() as u64);
        for factor in &self.factors {
            encoder.u32(factor.depth);
            match factor.parent {
                Some(p) => {
                    encoder.bool(true);
                    encoder.u32(p);
                }
                None => encoder.bool(false),
            }
            encoder.text(&factor.value);
        }
    }
}

/// Intersects sorted slices using leapfrog binary-search seeks, starting from the shortest slice.
fn leapfrog_intersect(
    slices: &[&[u32]],
    meter: &mut Meter,
) -> Result<Vec<u32>, GraphError> {
    if slices.is_empty() {
        return Ok(Vec::new());
    }
    let mut ordered: Vec<&[u32]> = slices.to_vec();
    ordered.sort_by_key(|s| s.len());
    if ordered[0].is_empty() {
        return Ok(Vec::new());
    }
    if ordered.len() == 1 {
        meter.tick("iterator_seeks")?;
        return Ok(ordered[0].to_vec());
    }
    let mut result = Vec::new();
    let first = ordered[0];
    let rest = &ordered[1..];
    'candidate: for &val in first {
        meter.tick("set_intersections")?;
        for slice in rest {
            meter.tick("iterator_seeks")?;
            if slice.binary_search(&val).is_err() {
                continue 'candidate;
            }
        }
        result.push(val);
    }
    Ok(result)
}

/// Runs `ALG-FACTOR-001` over `problem`.
///
/// # Errors
///
/// Fails closed on invalid relations or budget/bound exhaustion.
pub fn factorized_free_join(
    problem: &FactorJoinProblem,
    budget: Budget,
) -> Result<CertifiedRun<FactorJoinOutput>, GraphError> {
    let v_count = problem.domain.len();
    let r_count = problem.relations.len();
    let m_count: usize = problem.relations.iter().map(|r| r.pairs.len()).sum();
    let input_digest = query_digest(query_encoder(&IDENTITY, problem.digest()));
    let mut meter = Meter::new(&IDENTITY, budget);
    let bound_rows = bound(v_count as u64, m_count as u64, r_count as u64);

    if v_count == 0 || problem.variables.is_empty() || r_count == 0 {
        return meter.finish(
            &IDENTITY,
            InputShape {
                node_count: v_count as u64,
                edge_count: m_count as u64,
                input_digest,
            },
            FactorJoinOutput::default(),
            &bound_rows,
            0,
        );
    }

    let mut val_to_idx: BTreeMap<&str, u32> = BTreeMap::new();
    for (idx, val) in problem.domain.iter().enumerate() {
        val_to_idx.insert(val.as_str(), idx as u32);
    }

    // Build indexed adjacency `left_val -> sorted Vec<right_val>` and `left_domain` per relation.
    struct IndexedRel {
        left_var: usize,
        right_var: usize,
        left_keys: Vec<u32>,
        adj: BTreeMap<u32, Vec<u32>>,
    }
    let mut indexed_rels = Vec::with_capacity(r_count);
    for rel in &problem.relations {
        let mut adj: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        let mut left_set: BTreeSet<u32> = BTreeSet::new();
        for (a, b) in &rel.pairs {
            meter.tick("iterator_seeks")?;
            if let (Some(&ia), Some(&ib)) = (val_to_idx.get(a.as_str()), val_to_idx.get(b.as_str()))
            {
                left_set.insert(ia);
                adj.entry(ia).or_default().push(ib);
            }
        }
        for list in adj.values_mut() {
            list.sort_unstable();
            list.dedup();
        }
        indexed_rels.push(IndexedRel {
            left_var: rel.left_var,
            right_var: rel.right_var,
            left_keys: left_set.into_iter().collect(),
            adj,
        });
    }

    let arity = problem.variables.len();
    let max_factors = (v_count * r_count.max(1)) as u64;
    let all_domain: Vec<u32> = (0..v_count as u32).collect();
    let empty_vec: Vec<u32> = Vec::new();

    // Level 0 candidate slices: all relations with `left_var == 0`.
    let mut level0_slices: Vec<&[u32]> = Vec::new();
    for rel in &indexed_rels {
        if rel.left_var == 0 {
            level0_slices.push(&rel.left_keys);
        }
    }
    if level0_slices.is_empty() {
        level0_slices.push(&all_domain);
    }
    let level0_vals = leapfrog_intersect(&level0_slices, &mut meter)?;

    let mut factors: Vec<FactorNode> = Vec::new();
    // Active frontier at current depth: `(factor_index, binding_prefix_indices)`
    let mut frontier: Vec<(u32, Vec<u32>)> = Vec::new();
    let mut capped = false;

    for val in level0_vals {
        if factors.len() as u64 >= max_factors {
            capped = true;
            break;
        }
        meter.tick("emitted_factors")?;
        let f_idx = factors.len() as u32;
        meter.decide(1, 0, u64::from(val));
        factors.push(FactorNode {
            depth: 0,
            parent: None,
            value: problem.domain[val as usize].clone(),
        });
        frontier.push((f_idx, vec![val]));
    }

    for depth in 1..arity {
        if frontier.is_empty() || capped {
            break;
        }
        let mut next_frontier: Vec<(u32, Vec<u32>)> = Vec::new();
        for (parent_factor, prefix) in &frontier {
            let mut slices: Vec<&[u32]> = Vec::new();
            for rel in &indexed_rels {
                if rel.right_var == depth {
                    let bound_left = prefix[rel.left_var];
                    match rel.adj.get(&bound_left) {
                        Some(ext) => slices.push(ext.as_slice()),
                        None => slices.push(empty_vec.as_slice()),
                    }
                } else if rel.left_var == depth {
                    slices.push(&rel.left_keys);
                }
            }
            if slices.is_empty() {
                slices.push(&all_domain);
            }
            let candidates = leapfrog_intersect(&slices, &mut meter)?;
            for val in candidates {
                if factors.len() as u64 >= max_factors {
                    capped = true;
                    break;
                }
                meter.tick("emitted_factors")?;
                let f_idx = factors.len() as u32;
                meter.decide(1, depth as u64, u64::from(val));
                factors.push(FactorNode {
                    depth: depth as u32,
                    parent: Some(*parent_factor),
                    value: problem.domain[val as usize].clone(),
                });
                let mut next_prefix = prefix.clone();
                next_prefix.push(val);
                next_frontier.push((f_idx, next_prefix));
            }
            if capped {
                break;
            }
        }
        frontier = next_frontier;
    }

    let complete_bindings = if arity == 1 {
        factors.iter().filter(|f| f.depth == 0).count() as u64
    } else {
        frontier.len() as u64
    };

    let working_bytes = ((v_count + m_count + factors.len()) * 32) as u64;
    meter.finish(
        &IDENTITY,
        InputShape {
            node_count: v_count as u64,
            edge_count: m_count as u64,
            input_digest,
        },
        FactorJoinOutput {
            factors,
            complete_bindings,
            capped,
        },
        &bound_rows,
        working_bytes,
    )
}
