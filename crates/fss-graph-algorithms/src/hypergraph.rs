#![forbid(unsafe_code)]
//! `ALG-HYPER-001` — Native hypergraph and factor-graph reasoning (`fss-x4a.23.70.9`).
//!
//! Preserves multi-entity relations (`arity >= 2`) with explicit typed `(entity_id, role)`
//! incidences, uncertainty, provenance, and failure domains rather than lossily collapsing them
//! into pairwise cliques!
//!
//! Explicitly declares whether execution operated in [`HypergraphMode::NativeHypergraph`] or
//! [`HypergraphMode::BipartiteFactorProjection`], detects when pairwise expansion distorts
//! semantics (`pairwise_expansion_distorts_semantics`: e.g., a 3-way factor vs three pairwise
//! edges creating phantom triangles!), computes exact native `s`-connected components (`s >= 1`),
//! and computes an exact minimum hitting set (factor cover) for bounded small hypergraphs.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, mul, query_digest, query_encoder,
};
use crate::graph::GraphError;

/// Projection digest domain (`SCHEMA-DOMAIN-GRAPH-HYPER-PROJECTION-001`).
pub const PROJECTION_DOMAIN: &str = "fss.graph.hyper_projection.v1";
/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-HYPER-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.hyper_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-HYPER-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.hyper_decision_path.v1";

/// Registered identity (`architecture/graph_algorithms.json`, `ALG-HYPER-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-HYPER-001",
    algorithm_name: "native_hypergraph_and_factor_reasoning",
    tie_break_rule: "canonical hyperedge identity then sorted member role and entity identity",
    complexity_witness: "hyperedge incidence overlaps, s-walk traversals, and hitting-set checks",
    output_size_witness: "<= |E_H| s-components plus <= |V| minimal hitting-set entities",
    exactness: "exact",
    implementation_id: "fss-graph-algorithms:alg-hyper-001:native-s-walk-and-hitting-set:v1",
    tie_break_policy_id: "tie:canonical-hyperedge-id-then-sorted-member-role-entity:v1",
    policy_id: "graph-policy:native-hypergraph:arity-role-uncertainty-provenance-preserved:tie:canonical-hyperedge-id-then-sorted-member-role-entity:v1",
    complexity_bound_id: "bound:alg-hyper-001:native-incidence-overlap-plus-bounded-hitting-set:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// Operating representation explicitly recorded on every output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HypergraphMode {
    /// Native multi-entity hypergraph / factor representation.
    NativeHypergraph,
    /// Lossless incidence bipartite factor projection (`entity <-> factor_node`, retaining arity & roles).
    BipartiteFactorProjection,
}

/// One typed multi-entity hyperedge / factor preserving arity, roles, uncertainty, and provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HyperFactorSpec {
    /// Stable unique factor / hyperedge identifier.
    pub factor_id: String,
    /// Multi-entity incidences `(entity_id, role_label)` (`len >= 2`).
    pub members: BTreeSet<(String, String)>,
    /// Factor uncertainty in basis points (`0..=10_000`).
    pub uncertainty_bps: u16,
    /// Explicit provenance tag (`source_manifest`, `multi_sensor_factor`, `policy_quorum`).
    pub provenance: String,
}

/// Canonical native hypergraph input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHypergraph {
    /// Operating mode recorded in the output.
    pub mode: HypergraphMode,
    /// Multi-entity factors.
    pub factors: Vec<HyperFactorSpec>,
}

impl NativeHypergraph {
    /// Validates factor arities, labels, and computes a canonical insertion-order-invariant digest.
    pub fn projection_digest(&self) -> Result<ContentDigest, GraphError> {
        let mut sorted = self.factors.clone();
        sorted.sort_by(|a, b| a.factor_id.cmp(&b.factor_id));
        for pair in sorted.windows(2) {
            if pair[0].factor_id == pair[1].factor_id {
                return Err(GraphError::PreconditionFailed(
                    "duplicate factor_id".to_owned(),
                ));
            }
        }
        let mut enc = CanonicalEncoder::new();
        enc.text(PROJECTION_DOMAIN);
        enc.u8(match self.mode {
            HypergraphMode::NativeHypergraph => 1,
            HypergraphMode::BipartiteFactorProjection => 2,
        });
        enc.u64(sorted.len() as u64);
        for f in &sorted {
            if f.factor_id.is_empty()
                || f.provenance.is_empty()
                || f.members.len() < 2
                || f.uncertainty_bps > 10_000
            {
                return Err(GraphError::PreconditionFailed(
                    "invalid hyperfactor: requires non-empty id/provenance, arity >= 2, uncertainty <= 10000"
                        .to_owned(),
                ));
            }
            enc.text(&f.factor_id);
            enc.u32(u32::from(f.uncertainty_bps));
            enc.text(&f.provenance);
            enc.u64(f.members.len() as u64);
            for (ent, role) in &f.members {
                if ent.is_empty() || role.is_empty() {
                    return Err(GraphError::PreconditionFailed(
                        "empty member entity or role".to_owned(),
                    ));
                }
                enc.text(ent);
                enc.text(role);
            }
        }
        Ok(ContentDigest::sha256(&enc.finish()))
    }
}

/// Canonical answer of `ALG-HYPER-001`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HypergraphReasoningResult {
    /// Recorded operating mode (`NativeHypergraph` or `BipartiteFactorProjection`).
    pub mode: HypergraphMode,
    /// Overlap width `s` used for native `s`-walk connectivity (`>= 1`).
    pub s_overlap: usize,
    /// Native `s`-connected components of hyperedges (each component sorted by `factor_id`).
    pub s_components: Vec<Vec<String>>,
    /// Minimum hitting set of entities intersecting every hyperedge (exact for `|V| <= 16`, greedy otherwise).
    pub minimal_hitting_set: Vec<String>,
    /// True iff `minimal_hitting_set` is certified exact minimum cardinality.
    pub hitting_set_exact: bool,
    /// Maximum factor arity preserved across all hyperedges.
    pub max_arity_preserved: usize,
    /// True iff any `>= 3`-ary factor or role-typed incidence would lose semantics under pairwise clique expansion!
    pub pairwise_expansion_distorts_semantics: bool,
    /// Always `false`: derived hypergraph reasoning never grants effect authority.
    pub grants_effect_authority: bool,
}

impl CertifiedOutput for HypergraphReasoningResult {
    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self.mode {
            HypergraphMode::NativeHypergraph => 1,
            HypergraphMode::BipartiteFactorProjection => 2,
        });
        encoder.u64(self.s_overlap as u64);
        encoder.u64(self.max_arity_preserved as u64);
        encoder.u8(u8::from(self.pairwise_expansion_distorts_semantics));
        encoder.u8(u8::from(self.hitting_set_exact));
        encoder.u64(self.s_components.len() as u64);
        for comp in &self.s_components {
            encoder.u64(comp.len() as u64);
            for fid in comp {
                encoder.text(fid);
            }
        }
        encoder.u64(self.minimal_hitting_set.len() as u64);
        for ent in &self.minimal_hitting_set {
            encoder.text(ent);
        }
    }

    fn entries(&self) -> u64 {
        add(
            self.s_components.len() as u64,
            self.minimal_hitting_set.len() as u64,
        )
    }
}

/// Exact hitting-set entity ceiling (`2^16 = 65,536` subsets).
pub const EXACT_HITTING_SET_LIMIT: usize = 16;

/// Registered complexity bound for `entities` entities and `factors` hyperedges.
#[must_use]
pub fn bound(entities: u64, factors: u64) -> Vec<BoundRow> {
    let overlap_work = mul(factors, mul(factors, add(entities, 1)));
    let hit_work = if entities <= EXACT_HITTING_SET_LIMIT as u64 {
        1_u64.checked_shl(entities as u32).unwrap_or(u64::MAX)
    } else {
        mul(entities, add(factors, 1))
    };
    vec![
        ("incidence_overlaps", add(overlap_work, 4)),
        ("hitting_set_checks", add(hit_work, 4)),
        (OUTPUT_ENTRIES, add(factors, entities)),
    ]
}

/// Runs `ALG-HYPER-001` native `s`-connectivity, pairwise-distortion audit, and hitting-set solver.
pub fn analyze_native_hypergraph(
    hg: &NativeHypergraph,
    s_overlap: usize,
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<CertifiedRun<HypergraphReasoningResult>, GraphError> {
    if s_overlap == 0 {
        return Err(GraphError::PreconditionFailed(
            "s_overlap must be >= 1".to_owned(),
        ));
    }
    let proj_digest = hg.projection_digest()?;
    let mut factors = hg.factors.clone();
    factors.sort_by(|a, b| a.factor_id.cmp(&b.factor_id));

    let mut entity_set = BTreeSet::new();
    let mut factor_entities: Vec<BTreeSet<String>> = Vec::with_capacity(factors.len());
    let mut max_arity_preserved = 0_usize;
    let mut has_distinct_roles = false;
    for f in &factors {
        max_arity_preserved = max_arity_preserved.max(f.members.len());
        let mut ents = BTreeSet::new();
        let mut roles = BTreeSet::new();
        for (e, r) in &f.members {
            entity_set.insert(e.clone());
            ents.insert(e.clone());
            roles.insert(r.as_str());
        }
        if roles.len() > 1 {
            has_distinct_roles = true;
        }
        factor_entities.push(ents);
    }
    let entities: Vec<String> = entity_set.into_iter().collect();
    let entity_idx: BTreeMap<&str, usize> = entities
        .iter()
        .enumerate()
        .map(|(i, e)| (e.as_str(), i))
        .collect();

    let bound_rows = bound(entities.len() as u64, factors.len() as u64);
    let mut meter = Meter::new_cancellable(&IDENTITY, budget, is_cancelled);

    let mut q = query_encoder(&IDENTITY, proj_digest);
    q.u64(s_overlap as u64);
    let input_digest = query_digest(q);

    // 1. Native s-line-graph adjacency (two hyperedges are s-adjacent iff they share >= s entities!).
    let f_len = factors.len();
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); f_len];
    for i in 0..f_len {
        for j in (i + 1)..f_len {
            meter.tick("incidence_overlaps")?;
            let shared = factor_entities[i].intersection(&factor_entities[j]).count();
            if shared >= s_overlap {
                adj[i].push(j);
                adj[j].push(i);
            }
        }
    }

    let mut seen = vec![false; f_len];
    let mut s_components = Vec::new();
    for start in 0..f_len {
        if seen[start] {
            continue;
        }
        let mut comp = Vec::new();
        let mut q_bfs = VecDeque::new();
        seen[start] = true;
        q_bfs.push_back(start);
        while let Some(u) = q_bfs.pop_front() {
            meter.tick("incidence_overlaps")?;
            comp.push(factors[u].factor_id.clone());
            for &v in &adj[u] {
                if !seen[v] {
                    seen[v] = true;
                    q_bfs.push_back(v);
                }
            }
        }
        comp.sort();
        s_components.push(comp);
    }
    s_components.sort();

    // 2. Minimum hitting set (cover every hyperedge with minimum entities).
    let factor_masks: Vec<Vec<usize>> = factor_entities
        .iter()
        .map(|es| es.iter().map(|e| entity_idx[e.as_str()]).collect())
        .collect();
    let (minimal_hitting_set, hitting_set_exact) = if factors.is_empty() {
        (Vec::new(), true)
    } else if entities.len() <= EXACT_HITTING_SET_LIMIT {
        let mut best_pick: Option<Vec<usize>> = None;
        let total_masks = 1_usize << entities.len();
        for mask in 1..total_masks {
            meter.tick("hitting_set_checks")?;
            let bits = mask.count_ones() as usize;
            if best_pick.as_ref().is_some_and(|b| bits > b.len()) {
                continue;
            }
            let hits_all = factor_masks
                .iter()
                .all(|f| f.iter().any(|&ei| (mask & (1 << ei)) != 0));
            if hits_all {
                let pick: Vec<usize> = (0..entities.len())
                    .filter(|&i| (mask & (1 << i)) != 0)
                    .collect();
                if best_pick
                    .as_ref()
                    .is_none_or(|b| (pick.len(), pick.as_slice()) < (b.len(), b.as_slice()))
                {
                    best_pick = Some(pick);
                }
            }
        }
        let picked = best_pick
            .unwrap_or_default()
            .into_iter()
            .map(|i| entities[i].clone())
            .collect();
        (picked, true)
    } else {
        // Deterministic greedy hitting set for large entity universes.
        let mut uncovered: BTreeSet<usize> = (0..f_len).collect();
        let mut chosen = Vec::new();
        while !uncovered.is_empty() {
            let mut best_e: Option<(usize, usize)> = None;
            for ei in 0..entities.len() {
                meter.tick("hitting_set_checks")?;
                let gain = uncovered
                    .iter()
                    .filter(|&&fi| factor_masks[fi].contains(&ei))
                    .count();
                if gain > 0 && best_e.is_none_or(|(bg, bi)| (gain > bg) || (gain == bg && ei < bi))
                {
                    best_e = Some((gain, ei));
                }
            }
            let Some((_, ei)) = best_e else {
                break;
            };
            chosen.push(entities[ei].clone());
            uncovered.retain(|&fi| !factor_masks[fi].contains(&ei));
        }
        chosen.sort();
        (chosen, false)
    };

    for comp in &s_components {
        for fid in comp {
            meter.path().text(fid);
        }
    }
    for ent in &minimal_hitting_set {
        meter.path().text(ent);
    }

    let pairwise_expansion_distorts_semantics = max_arity_preserved >= 3 || has_distinct_roles;
    let output = HypergraphReasoningResult {
        mode: hg.mode,
        s_overlap,
        s_components,
        minimal_hitting_set,
        hitting_set_exact,
        max_arity_preserved,
        pairwise_expansion_distorts_semantics,
        grants_effect_authority: false,
    };
    let shape = InputShape {
        node_count: entities.len() as u64,
        edge_count: factors.len() as u64,
        input_digest,
    };
    let peak_bytes = ((entities.len() + factors.len() + 1) * 192) as u64;
    meter.finish(&IDENTITY, shape, output, &bound_rows, peak_bytes)
}
