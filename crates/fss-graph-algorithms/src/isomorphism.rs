#![forbid(unsafe_code)]
//! `ALG-ISO-001` — Canonical graph hashing, isomorphism, and topology-drift detection
//! (`fss-x4a.23.70.2`).
//!
//! Preserves node labels, edge labels, direction, and multiedges. Provides:
//! - Deterministic `k`-round Weisfeiler-Lehman (WL) color-refinement fingerprints & topology-drift
//!   summaries explicitly marked `hash_proves_identity: false` (candidate relation ONLY!);
//! - Bounded exact backtracking isomorphism verification (`verify_exact_isomorphism`) returning
//!   [`IsomorphismVerdict::Isomorphic`], [`IsomorphismVerdict::NonIsomorphic`], or
//!   [`IsomorphismVerdict::UnknownBudgetExhausted`] (NEVER mistaking budget exhaustion for
//!   non-isomorphism!).

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, mul, query_digest, query_encoder,
};
use crate::graph::GraphError;

/// Projection digest domain (`SCHEMA-DOMAIN-GRAPH-ISO-PROJECTION-001`).
pub const PROJECTION_DOMAIN: &str = "fss.graph.iso_projection.v1";
/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-ISO-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.iso_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-ISO-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.iso_decision_path.v1";

/// Registered identity (`architecture/graph_algorithms.json`, `ALG-ISO-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-ISO-001",
    algorithm_name: "canonical_graph_hashing_and_isomorphism",
    tie_break_rule: "canonical node color class then lexicographic stable identity",
    complexity_witness: "WL refinement rounds, color hashes, and backtracking probes",
    output_size_witness: "<= |V| node color hashes plus exact bijection or refutation",
    exactness: "bounded_exact_with_candidate_hash",
    implementation_id: "fss-graph-algorithms:alg-iso-001:labeled-directed-wl-and-exact-iso:v1",
    tie_break_policy_id: "tie:canonical-wl-color-class-then-lexicographic-node-id:v1",
    policy_id: "graph-policy:labeled-directed-multigraph:wl-candidate-hash-plus-bounded-exact-iso:tie:canonical-wl-color-class-then-lexicographic-node-id:v1",
    complexity_bound_id: "bound:alg-iso-001:wl-linear-plus-bounded-backtrack-probes:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// Labeled directed multigraph input preserving labels, direction, and edge multiplicity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LabeledMultigraph {
    /// Map from stable `node_id` to semantic node label (e.g., `"Camera"`, `"Zone"`).
    pub nodes: BTreeMap<String, String>,
    /// Directed labeled edges `(source_id, target_id, edge_label)` (multiedges preserved!).
    pub edges: Vec<(String, String, String)>,
}

impl LabeledMultigraph {
    /// Validates endpoints and computes a canonical insertion-order-invariant projection digest.
    pub fn projection_digest(&self) -> Result<ContentDigest, GraphError> {
        for (id, label) in &self.nodes {
            if id.is_empty() || label.is_empty() {
                return Err(GraphError::PreconditionFailed(
                    "empty node id or label".to_owned(),
                ));
            }
        }
        let mut sorted_edges = self.edges.clone();
        sorted_edges.sort();
        for (s, t, l) in &sorted_edges {
            if l.is_empty() || !self.nodes.contains_key(s) || !self.nodes.contains_key(t) {
                return Err(GraphError::PreconditionFailed(
                    "edge has empty label or unknown endpoint".to_owned(),
                ));
            }
        }
        let mut enc = CanonicalEncoder::new();
        enc.text(PROJECTION_DOMAIN);
        enc.u64(self.nodes.len() as u64);
        for (id, label) in &self.nodes {
            enc.text(id);
            enc.text(label);
        }
        enc.u64(sorted_edges.len() as u64);
        for (s, t, l) in &sorted_edges {
            enc.text(s);
            enc.text(t);
            enc.text(l);
        }
        Ok(ContentDigest::sha256(&enc.finish()))
    }
}

/// Exact isomorphism / topology-drift verdict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IsomorphismVerdict {
    /// Proven isomorphic by explicit label- and multiedge-preserving bijection (`left_id -> right_id`).
    Isomorphic {
        /// Exact sorted bijection mapping every left node to its paired right node.
        bijection: BTreeMap<String, String>,
    },
    /// Proven non-isomorphic with explicit refutation reason.
    NonIsomorphic {
        /// Concrete structural or WL-color mismatch reason.
        reason: String,
    },
    /// Backtracking probe cap reached before proof; NEVER claimed non-isomorphic!
    UnknownBudgetExhausted {
        /// Probes consumed before stop.
        probes_used: u64,
    },
}

/// Canonical answer of `ALG-ISO-001`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IsomorphismReport {
    /// WL candidate fingerprint of the left graph.
    pub left_wl_fingerprint: ContentDigest,
    /// WL candidate fingerprint of the right graph.
    pub right_wl_fingerprint: ContentDigest,
    /// True iff WL candidate fingerprints agree (necessary, NOT sufficient for identity!).
    pub wl_candidate_match: bool,
    /// Always `false`: hash equality alone NEVER proves graph identity!
    pub hash_proves_identity: bool,
    /// Exact bounded isomorphism verdict.
    pub verdict: IsomorphismVerdict,
    /// Labels present in left/right whose multiplicity changed (topology drift summary).
    pub drifted_node_labels: Vec<String>,
    /// Always `false`: derived graph comparison never grants authority.
    pub grants_effect_authority: bool,
}

impl CertifiedOutput for IsomorphismReport {
    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.digest(self.left_wl_fingerprint);
        encoder.digest(self.right_wl_fingerprint);
        encoder.u8(u8::from(self.wl_candidate_match));
        match &self.verdict {
            IsomorphismVerdict::Isomorphic { bijection } => {
                encoder.u8(1);
                encoder.u64(bijection.len() as u64);
                for (k, v) in bijection {
                    encoder.text(k);
                    encoder.text(v);
                }
            }
            IsomorphismVerdict::NonIsomorphic { reason } => {
                encoder.u8(2);
                encoder.text(reason);
            }
            IsomorphismVerdict::UnknownBudgetExhausted { probes_used } => {
                encoder.u8(3);
                encoder.u64(*probes_used);
            }
        }
        encoder.u64(self.drifted_node_labels.len() as u64);
        for d in &self.drifted_node_labels {
            encoder.text(d);
        }
    }

    fn entries(&self) -> u64 {
        let map_len = match &self.verdict {
            IsomorphismVerdict::Isomorphic { bijection } => bijection.len() as u64,
            _ => 1,
        };
        add(map_len, self.drifted_node_labels.len() as u64)
    }
}

/// Registered complexity bound for `n` nodes, `m` edges, `wl_rounds`, and `max_backtrack_probes`.
#[must_use]
pub fn bound(n: u64, m: u64, wl_rounds: u64, max_backtrack_probes: u64) -> Vec<BoundRow> {
    // Each graph ticks once per node at init plus (n + out_edges + in_edges) = n + 2*m per WL round.
    let per_graph_wl = add(n, mul(wl_rounds, add(n, mul(2, m))));
    let wl_work = mul(2, per_graph_wl);
    vec![
        ("wl_refinements", add(wl_work, 4)),
        ("backtrack_probes", add(max_backtrack_probes, 1)),
        (OUTPUT_ENTRIES, add(mul(2, n), 4)),
    ]
}

fn compute_wl_colors(
    g: &LabeledMultigraph,
    rounds: usize,
    meter: &mut Meter<'_>,
) -> Result<(ContentDigest, BTreeMap<String, ContentDigest>), GraphError> {
    let mut out_adj: BTreeMap<&str, Vec<(&str, &str)>> = BTreeMap::new();
    let mut in_adj: BTreeMap<&str, Vec<(&str, &str)>> = BTreeMap::new();
    for (s, t, l) in &g.edges {
        out_adj
            .entry(s.as_str())
            .or_default()
            .push((l.as_str(), t.as_str()));
        in_adj
            .entry(t.as_str())
            .or_default()
            .push((l.as_str(), s.as_str()));
    }

    let mut colors: BTreeMap<String, ContentDigest> = BTreeMap::new();
    for (id, label) in &g.nodes {
        meter.tick("wl_refinements")?;
        let mut enc = CanonicalEncoder::new();
        enc.text("wl:init");
        enc.text(label);
        colors.insert(id.clone(), ContentDigest::sha256(&enc.finish()));
    }

    for round in 0..rounds {
        let mut next_colors = BTreeMap::new();
        for (id, cur) in &colors {
            meter.tick("wl_refinements")?;
            let mut out_sig: Vec<(&str, [u8; 32])> = Vec::new();
            if let Some(edges) = out_adj.get(id.as_str()) {
                for &(elabel, nbr) in edges {
                    meter.tick("wl_refinements")?;
                    if let Some(c) = colors.get(nbr) {
                        out_sig.push((elabel, c.bytes()));
                    }
                }
            }
            out_sig.sort();
            let mut in_sig: Vec<(&str, [u8; 32])> = Vec::new();
            if let Some(edges) = in_adj.get(id.as_str()) {
                for &(elabel, nbr) in edges {
                    meter.tick("wl_refinements")?;
                    if let Some(c) = colors.get(nbr) {
                        in_sig.push((elabel, c.bytes()));
                    }
                }
            }
            in_sig.sort();
            let mut enc = CanonicalEncoder::new();
            enc.text("wl:step");
            enc.u64(round as u64);
            enc.digest(*cur);
            enc.u64(out_sig.len() as u64);
            for (el, cb) in out_sig {
                enc.text(el);
                enc.bytes(&cb);
            }
            enc.u64(in_sig.len() as u64);
            for (el, cb) in in_sig {
                enc.text(el);
                enc.bytes(&cb);
            }
            next_colors.insert(id.clone(), ContentDigest::sha256(&enc.finish()));
        }
        colors = next_colors;
    }

    let mut multiset: Vec<[u8; 32]> = colors.values().map(|c| c.bytes()).collect();
    multiset.sort();
    let mut fenc = CanonicalEncoder::new();
    fenc.text("wl:graph_fingerprint");
    fenc.u64(multiset.len() as u64);
    for b in multiset {
        fenc.bytes(&b);
    }
    Ok((ContentDigest::sha256(&fenc.finish()), colors))
}

fn edge_multiset_map(g: &LabeledMultigraph) -> BTreeMap<(&str, &str), BTreeMap<&str, usize>> {
    let mut map: BTreeMap<(&str, &str), BTreeMap<&str, usize>> = BTreeMap::new();
    for (s, t, l) in &g.edges {
        *map.entry((s.as_str(), t.as_str()))
            .or_default()
            .entry(l.as_str())
            .or_insert(0) += 1;
    }
    map
}

/// Runs `ALG-ISO-001` comparing `left` and `right` via WL hashing + bounded exact isomorphism.
pub fn compare_and_verify_isomorphism(
    left: &LabeledMultigraph,
    right: &LabeledMultigraph,
    wl_rounds: usize,
    max_backtrack_probes: u64,
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<CertifiedRun<IsomorphismReport>, GraphError> {
    if max_backtrack_probes == 0 {
        return Err(GraphError::PreconditionFailed(
            "max_backtrack_probes must be >= 1".to_owned(),
        ));
    }
    let ld = left.projection_digest()?;
    let rd = right.projection_digest()?;
    let n = left.nodes.len().max(right.nodes.len()) as u64;
    let m = left.edges.len().max(right.edges.len()) as u64;
    let bound_rows = bound(n, m, wl_rounds as u64, max_backtrack_probes);
    let mut meter = Meter::new_cancellable(&IDENTITY, budget, is_cancelled);

    let mut q = query_encoder(&IDENTITY, ld);
    q.digest(rd);
    q.u64(wl_rounds as u64);
    q.u64(max_backtrack_probes);
    let input_digest = query_digest(q);

    // Label drift histogram.
    let mut l_hist: BTreeMap<&str, usize> = BTreeMap::new();
    let mut r_hist: BTreeMap<&str, usize> = BTreeMap::new();
    for lbl in left.nodes.values() {
        *l_hist.entry(lbl.as_str()).or_insert(0) += 1;
    }
    for lbl in right.nodes.values() {
        *r_hist.entry(lbl.as_str()).or_insert(0) += 1;
    }
    let mut all_labels: BTreeSet<&str> = BTreeSet::new();
    all_labels.extend(l_hist.keys().copied());
    all_labels.extend(r_hist.keys().copied());
    let drifted_node_labels: Vec<String> = all_labels
        .into_iter()
        .filter(|lbl| l_hist.get(lbl) != r_hist.get(lbl))
        .map(str::to_owned)
        .collect();

    let (left_fp, left_colors) = compute_wl_colors(left, wl_rounds, &mut meter)?;
    let (right_fp, right_colors) = compute_wl_colors(right, wl_rounds, &mut meter)?;
    let wl_candidate_match = left_fp == right_fp;

    let verdict = if left.nodes.len() != right.nodes.len() {
        IsomorphismVerdict::NonIsomorphic {
            reason: "node_count_mismatch".to_owned(),
        }
    } else if left.edges.len() != right.edges.len() {
        IsomorphismVerdict::NonIsomorphic {
            reason: "edge_count_mismatch".to_owned(),
        }
    } else if !wl_candidate_match {
        IsomorphismVerdict::NonIsomorphic {
            reason: "wl_color_histogram_mismatch".to_owned(),
        }
    } else {
        // Exact bounded backtracking isomorphism preserving labels, direction, and multiedges!
        let mut right_by_color: BTreeMap<[u8; 32], Vec<&str>> = BTreeMap::new();
        for (rid, col) in &right_colors {
            right_by_color
                .entry(col.bytes())
                .or_default()
                .push(rid.as_str());
        }
        // Order left nodes by smallest candidate color class first, then canonical node_id.
        let mut left_order: Vec<&str> = left.nodes.keys().map(String::as_str).collect();
        left_order.sort_by(|&a, &b| {
            let ca = right_by_color
                .get(&left_colors[a].bytes())
                .map_or(0, Vec::len);
            let cb = right_by_color
                .get(&left_colors[b].bytes())
                .map_or(0, Vec::len);
            (ca, a).cmp(&(cb, b))
        });

        let l_edges = edge_multiset_map(left);
        let r_edges = edge_multiset_map(right);
        let mut mapping: Vec<(&str, &str)> = Vec::with_capacity(left_order.len());
        let mut used_right: BTreeSet<&str> = BTreeSet::new();
        let mut probes = 0_u64;
        let mut hit_probe_cap = false;

        let found = backtrack_iso(
            0,
            &left_order,
            &left.nodes,
            &right.nodes,
            &left_colors,
            &right_by_color,
            &l_edges,
            &r_edges,
            &mut mapping,
            &mut used_right,
            &mut probes,
            max_backtrack_probes,
            &mut hit_probe_cap,
            &mut meter,
        )?;

        if found {
            let bijection: BTreeMap<String, String> = mapping
                .into_iter()
                .map(|(l, r)| (l.to_owned(), r.to_owned()))
                .collect();
            for (l, r) in &bijection {
                meter.path().text(l);
                meter.path().text(r);
            }
            IsomorphismVerdict::Isomorphic { bijection }
        } else if hit_probe_cap {
            IsomorphismVerdict::UnknownBudgetExhausted {
                probes_used: probes,
            }
        } else {
            IsomorphismVerdict::NonIsomorphic {
                reason: "no_structure_preserving_bijection".to_owned(),
            }
        }
    };

    let report = IsomorphismReport {
        left_wl_fingerprint: left_fp,
        right_wl_fingerprint: right_fp,
        wl_candidate_match,
        hash_proves_identity: false,
        verdict,
        drifted_node_labels,
        grants_effect_authority: false,
    };
    let shape = InputShape {
        node_count: (left.nodes.len() + right.nodes.len()) as u64,
        edge_count: (left.edges.len() + right.edges.len()) as u64,
        input_digest,
    };
    let peak_bytes = ((left.nodes.len() + right.nodes.len() + 1) * 192) as u64;
    meter.finish(&IDENTITY, shape, report, &bound_rows, peak_bytes)
}

#[allow(clippy::too_many_arguments)]
fn backtrack_iso<'a>(
    depth: usize,
    left_order: &[&'a str],
    left_nodes: &BTreeMap<String, String>,
    right_nodes: &BTreeMap<String, String>,
    left_colors: &BTreeMap<String, ContentDigest>,
    right_by_color: &BTreeMap<[u8; 32], Vec<&'a str>>,
    l_edges: &BTreeMap<(&'a str, &'a str), BTreeMap<&'a str, usize>>,
    r_edges: &BTreeMap<(&'a str, &'a str), BTreeMap<&'a str, usize>>,
    mapping: &mut Vec<(&'a str, &'a str)>,
    used_right: &mut BTreeSet<&'a str>,
    probes: &mut u64,
    max_probes: u64,
    hit_probe_cap: &mut bool,
    meter: &mut Meter<'_>,
) -> Result<bool, GraphError> {
    if depth == left_order.len() {
        return Ok(true);
    }
    let u = left_order[depth];
    let Some(cands) = right_by_color.get(&left_colors[u].bytes()) else {
        return Ok(false);
    };
    for &v in cands {
        if used_right.contains(v) {
            continue;
        }
        if *probes >= max_probes {
            *hit_probe_cap = true;
            return Ok(false);
        }
        *probes += 1;
        meter.tick("backtrack_probes")?;

        // Explicitly verify node label equality (never relying solely on WL hash collision resistance)
        // plus self-loop multiset and all incident directed multiedges against already-mapped vertices.
        if left_nodes.get(u) != right_nodes.get(v) || l_edges.get(&(u, u)) != r_edges.get(&(v, v)) {
            continue;
        }
        let mut consistent = true;
        for &(mu, mv) in mapping.iter() {
            if l_edges.get(&(u, mu)) != r_edges.get(&(v, mv))
                || l_edges.get(&(mu, u)) != r_edges.get(&(mv, v))
            {
                consistent = false;
                break;
            }
        }
        if !consistent {
            continue;
        }
        mapping.push((u, v));
        used_right.insert(v);
        if backtrack_iso(
            depth + 1,
            left_order,
            left_nodes,
            right_nodes,
            left_colors,
            right_by_color,
            l_edges,
            r_edges,
            mapping,
            used_right,
            probes,
            max_probes,
            hit_probe_cap,
            meter,
        )? {
            return Ok(true);
        }
        used_right.remove(v);
        mapping.pop();
        if *hit_probe_cap {
            return Ok(false);
        }
    }
    Ok(false)
}
