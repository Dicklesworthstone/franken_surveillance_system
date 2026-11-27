#![forbid(unsafe_code)]
//! `ALG-SUBISO-001` — Bounded VF2-class labeled subgraph matching (`fss-x4a.23.70.4`).
//!
//! Compares labeled directed pattern graphs against target incident, route, scene, or adapter
//! graphs with hard pattern-size, match-count, and probe-budget ceilings plus cooperative
//! cancellation checkpoints.
//!
//! Critical honesty invariant: noncompletion (probe budget exhausted or match cap truncated search)
//! returns [`SubgraphMatchVerdict::UnknownBounded`] — **NEVER** `NoMatch`!

use std::collections::{BTreeMap, BTreeSet};

use fss_core::CanonicalEncoder;

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, query_digest, query_encoder,
};
use crate::graph::GraphError;
use crate::isomorphism::LabeledMultigraph;

/// Projection digest domain (`SCHEMA-DOMAIN-GRAPH-SUBISO-PROJECTION-001`).
pub const PROJECTION_DOMAIN: &str = "fss.graph.subiso_projection.v1";
/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-SUBISO-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.subiso_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-SUBISO-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.subiso_decision_path.v1";

/// Registered identity (`architecture/graph_algorithms.json`, `ALG-SUBISO-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-SUBISO-001",
    algorithm_name: "bounded_vf2_subgraph_matching",
    tie_break_rule: "lexicographic target-node mapping tuple over canonical pattern order",
    complexity_witness: "VF2 feasibility probes and candidate degree prunings",
    output_size_witness: "<= max_matches bounded pattern-to-target embeddings",
    exactness: "bounded_exact",
    implementation_id: "fss-graph-algorithms:alg-subiso-001:bounded-vf2-induced-and-monomorphic:v1",
    tie_break_policy_id: "tie:lexicographic-target-mapping-over-sorted-pattern-ids:v1",
    policy_id: "graph-policy:labeled-directed-subgraph:bounded-vf2:noncompletion-is-unknown:tie:lexicographic-target-mapping-over-sorted-pattern-ids:v1",
    complexity_bound_id: "bound:alg-subiso-001:bounded-vf2-probes-and-match-cap:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// Hard ceiling on pattern node count to prevent unguarded adversarial blowup.
pub const MAX_PATTERN_NODES: usize = 32;

/// Subgraph match semantics (`Induced` vs `Monomorphic`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubgraphMatchMode {
    /// Every pattern edge must match target edges AND non-edges in pattern must be absent in target.
    Induced,
    /// Every pattern edge must be present in target with at least equal multiplicity (extra target edges allowed).
    Monomorphic,
}

/// Non-collapsed subgraph matching verdict: noncompletion is NEVER `NoMatch`!
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubgraphMatchVerdict {
    /// Search exhausted the entire search space cleanly (empty `matches` => genuine no-match).
    Complete,
    /// Hard probe cap or `max_matches` ceiling stopped search early: absence is NOT proven!
    UnknownBounded {
        /// Machine stop reason (`probe_cap_reached` or `match_cap_reached`).
        reason: String,
    },
}

/// Canonical answer of `ALG-SUBISO-001`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubgraphMatchResult {
    /// Non-collapsed completeness verdict.
    pub verdict: SubgraphMatchVerdict,
    /// Found embeddings (`pattern_node_id -> target_node_id`), sorted lexicographically.
    pub matches: Vec<BTreeMap<String, String>>,
    /// Probes consumed by VF2 backtracking.
    pub probes_used: u64,
    /// Always `false`: pattern matching never grants authority or establishes canonical truth.
    pub grants_effect_authority: bool,
}

impl CertifiedOutput for SubgraphMatchResult {
    fn encode(&self, encoder: &mut CanonicalEncoder) {
        match &self.verdict {
            SubgraphMatchVerdict::Complete => encoder.u8(1),
            SubgraphMatchVerdict::UnknownBounded { reason } => {
                encoder.u8(2);
                encoder.text(reason);
            }
        }
        encoder.u64(self.probes_used);
        encoder.u64(self.matches.len() as u64);
        for m in &self.matches {
            encoder.u64(m.len() as u64);
            for (k, v) in m {
                encoder.text(k);
                encoder.text(v);
            }
        }
    }

    fn entries(&self) -> u64 {
        self.matches.len() as u64
    }
}

/// Registered complexity bound for `max_probes` and `max_matches`.
#[must_use]
pub fn bound(max_probes: u64, max_matches: u64) -> Vec<BoundRow> {
    vec![
        ("vf2_probes", add(max_probes, 1)),
        (OUTPUT_ENTRIES, max_matches),
    ]
}

fn edge_counts<'a>(
    g: &'a LabeledMultigraph,
) -> BTreeMap<(&'a str, &'a str), BTreeMap<&'a str, usize>> {
    let mut map: BTreeMap<(&'a str, &'a str), BTreeMap<&'a str, usize>> = BTreeMap::new();
    for (s, t, l) in &g.edges {
        *map.entry((s.as_str(), t.as_str()))
            .or_default()
            .entry(l.as_str())
            .or_insert(0) += 1;
    }
    map
}

fn degrees<'a>(g: &'a LabeledMultigraph) -> BTreeMap<&'a str, (usize, usize)> {
    let mut deg: BTreeMap<&'a str, (usize, usize)> = g
        .nodes
        .keys()
        .map(|k| (k.as_str(), (0_usize, 0_usize)))
        .collect();
    for (s, t, _) in &g.edges {
        if let Some(e) = deg.get_mut(s.as_str()) {
            e.0 += 1;
        }
        if let Some(e) = deg.get_mut(t.as_str()) {
            e.1 += 1;
        }
    }
    deg
}

fn edges_compatible(
    pat: Option<&BTreeMap<&str, usize>>,
    tgt: Option<&BTreeMap<&str, usize>>,
    mode: SubgraphMatchMode,
) -> bool {
    match mode {
        SubgraphMatchMode::Induced => pat == tgt,
        SubgraphMatchMode::Monomorphic => match pat {
            None => true,
            Some(pm) => {
                let Some(tm) = tgt else {
                    return false;
                };
                pm.iter()
                    .all(|(lbl, &cnt)| tm.get(lbl).copied().unwrap_or(0) >= cnt)
            }
        },
    }
}

/// Runs `ALG-SUBISO-001` bounded VF2-class labeled subgraph matching of `pattern` in `target`.
#[allow(clippy::too_many_arguments)]
pub fn match_subgraph_bounded(
    pattern: &LabeledMultigraph,
    target: &LabeledMultigraph,
    mode: SubgraphMatchMode,
    max_matches: usize,
    max_probes: u64,
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<CertifiedRun<SubgraphMatchResult>, GraphError> {
    if pattern.nodes.is_empty()
        || pattern.nodes.len() > MAX_PATTERN_NODES
        || max_matches == 0
        || max_probes == 0
    {
        return Err(GraphError::PreconditionFailed(
            "invalid pattern size, max_matches, or max_probes".to_owned(),
        ));
    }
    let pd = pattern.projection_digest()?;
    let td = target.projection_digest()?;
    let bound_rows = bound(max_probes, max_matches as u64);
    let mut meter = Meter::new_cancellable(&IDENTITY, budget, is_cancelled);

    let mut q = query_encoder(&IDENTITY, pd);
    q.digest(td);
    q.u8(match mode {
        SubgraphMatchMode::Induced => 1,
        SubgraphMatchMode::Monomorphic => 2,
    });
    q.u64(max_matches as u64);
    q.u64(max_probes);
    let input_digest = query_digest(q);

    let p_deg = degrees(pattern);
    let t_deg = degrees(target);
    let p_edges = edge_counts(pattern);
    let t_edges = edge_counts(target);

    // Canonical pattern order (sorted node IDs) with degree+label pre-filtering of target candidates.
    let pat_order: Vec<&str> = pattern.nodes.keys().map(String::as_str).collect();
    let mut candidates: Vec<Vec<&str>> = Vec::with_capacity(pat_order.len());
    for &pu in &pat_order {
        let p_lbl = &pattern.nodes[pu];
        let (p_out, p_in) = p_deg[pu];
        let cands: Vec<&str> = target
            .nodes
            .iter()
            .filter(|(tid, t_lbl)| {
                *t_lbl == p_lbl && {
                    let (t_out, t_in) = t_deg[tid.as_str()];
                    t_out >= p_out && t_in >= p_in
                }
            })
            .map(|(tid, _)| tid.as_str())
            .collect();
        candidates.push(cands);
    }

    let mut matches: Vec<BTreeMap<String, String>> = Vec::new();
    let mut current: Vec<(&str, &str)> = Vec::with_capacity(pat_order.len());
    let mut used: BTreeSet<&str> = BTreeSet::new();
    let mut probes = 0_u64;
    let mut stop_reason: Option<&'static str> = None;

    vf2_search(
        0,
        &pat_order,
        &candidates,
        &p_edges,
        &t_edges,
        mode,
        max_matches,
        max_probes,
        &mut current,
        &mut used,
        &mut matches,
        &mut probes,
        &mut stop_reason,
        &mut meter,
    )?;

    for m in &matches {
        for (k, v) in m {
            meter.path().text(k);
            meter.path().text(v);
        }
    }
    let verdict = match stop_reason {
        None => SubgraphMatchVerdict::Complete,
        Some(reason) => SubgraphMatchVerdict::UnknownBounded {
            reason: reason.to_owned(),
        },
    };
    let output = SubgraphMatchResult {
        verdict,
        matches,
        probes_used: probes,
        grants_effect_authority: false,
    };
    let shape = InputShape {
        node_count: (pattern.nodes.len() + target.nodes.len()) as u64,
        edge_count: (pattern.edges.len() + target.edges.len()) as u64,
        input_digest,
    };
    let peak_bytes = ((pattern.nodes.len() + target.nodes.len() + 1) * 192) as u64;
    meter.finish(&IDENTITY, shape, output, &bound_rows, peak_bytes)
}

#[allow(clippy::too_many_arguments)]
fn vf2_search<'a>(
    depth: usize,
    pat_order: &[&'a str],
    candidates: &[Vec<&'a str>],
    p_edges: &BTreeMap<(&'a str, &'a str), BTreeMap<&'a str, usize>>,
    t_edges: &BTreeMap<(&'a str, &'a str), BTreeMap<&'a str, usize>>,
    mode: SubgraphMatchMode,
    max_matches: usize,
    max_probes: u64,
    current: &mut Vec<(&'a str, &'a str)>,
    used: &mut BTreeSet<&'a str>,
    matches: &mut Vec<BTreeMap<String, String>>,
    probes: &mut u64,
    stop_reason: &mut Option<&'static str>,
    meter: &mut Meter<'_>,
) -> Result<(), GraphError> {
    if stop_reason.is_some() {
        return Ok(());
    }
    if depth == pat_order.len() {
        if matches.len() >= max_matches {
            *stop_reason = Some("match_cap_reached");
            return Ok(());
        }
        let emb: BTreeMap<String, String> = current
            .iter()
            .map(|&(p, t)| (p.to_owned(), t.to_owned()))
            .collect();
        matches.push(emb);
        return Ok(());
    }
    let pu = pat_order[depth];
    for &tv in &candidates[depth] {
        if used.contains(tv) {
            continue;
        }
        if *probes >= max_probes {
            *stop_reason = Some("probe_cap_reached");
            return Ok(());
        }
        *probes += 1;
        meter.tick("vf2_probes")?;

        if !edges_compatible(p_edges.get(&(pu, pu)), t_edges.get(&(tv, tv)), mode) {
            continue;
        }
        let mut ok = true;
        for &(mpu, mtv) in current.iter() {
            if !edges_compatible(p_edges.get(&(pu, mpu)), t_edges.get(&(tv, mtv)), mode)
                || !edges_compatible(p_edges.get(&(mpu, pu)), t_edges.get(&(mtv, tv)), mode)
            {
                ok = false;
                break;
            }
        }
        if !ok {
            continue;
        }
        current.push((pu, tv));
        used.insert(tv);
        vf2_search(
            depth + 1,
            pat_order,
            candidates,
            p_edges,
            t_edges,
            mode,
            max_matches,
            max_probes,
            current,
            used,
            matches,
            probes,
            stop_reason,
            meter,
        )?;
        used.remove(tv);
        current.pop();
        if stop_reason.is_some() {
            return Ok(());
        }
    }
    Ok(())
}
