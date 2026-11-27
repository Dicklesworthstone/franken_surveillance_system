#![forbid(unsafe_code)]
//! `ALG-LINKPRED-001` — Non-authoritative link prediction with exact verification
//! (`fss-x4a.23.70.7`).
//!
//! Scores non-adjacent candidate node pairs using a generation-pinned deterministic integer
//! structural scorer (scaled Common Neighbors + Jaccard ppm), then pipes EVERY candidate through a
//! mandatory **exact verifier** checking:
//! 1. source evidence presence;
//! 2. temporal and geometric feasibility;
//! 3. capability visibility (both endpoints visible and generation-compatible);
//! 4. hard contradiction absence (`contradicted_pairs`).
//!
//! Enforces strict non-authority invariants: `creates_canonical_edge == false`,
//! `creates_identity == false`, `establishes_corroboration == false`, and
//! `grants_effect_authority == false`.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{CanonicalEncoder, Generation};

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, mul, query_digest, query_encoder,
};
use crate::graph::{GraphError, UndirectedGraph};

/// Projection digest domain (`SCHEMA-DOMAIN-GRAPH-LINKPRED-PROJECTION-001`).
pub const PROJECTION_DOMAIN: &str = "fss.graph.linkpred_projection.v1";
/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-LINKPRED-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.linkpred_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-LINKPRED-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.linkpred_decision_path.v1";

/// Registered identity (`architecture/graph_algorithms.json`, `ALG-LINKPRED-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-LINKPRED-001",
    algorithm_name: "non_authoritative_link_prediction_with_verifier",
    tie_break_rule: "descending exact score then lexicographic endpoint identity pair",
    complexity_witness: "candidate pair scorings and exact verifier checks",
    output_size_witness: "<= max_suggestions verified advisory candidates",
    exactness: "approximate_advisory_with_exact_verification",
    implementation_id: "fss-graph-algorithms:alg-linkpred-001:jaccard-cn-plus-exact-verifier:v1",
    tie_break_policy_id: "tie:descending-jaccard-cn-score-then-lexicographic-pair:v1",
    policy_id: "graph-policy:undirected:non-authoritative-link-prediction:mandatory-exact-verifier:tie:descending-jaccard-cn-score-then-lexicographic-pair:v1",
    complexity_bound_id: "bound:alg-linkpred-001:pair-scan-plus-exact-verifier:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// Exact verification ruleset every link-prediction suggestion MUST pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkVerifierContext {
    /// Pinned candidate-model generation (`>= 1`).
    pub model_generation: Generation,
    /// Nodes with verified backing source evidence (nodes outside this set fail verification!).
    pub evidence_backed_nodes: BTreeSet<String>,
    /// Pairs allowed by temporal & geometric feasibility (`(min_id, max_id)`).
    pub temporally_geometrically_feasible_pairs: BTreeSet<(String, String)>,
    /// Nodes visible under the caller's capability projection.
    pub capability_visible_nodes: BTreeSet<String>,
    /// Pairs with explicit hard contradictions (e.g. simultaneous disjoint visibility!).
    pub contradicted_pairs: BTreeSet<(String, String)>,
    /// Maximum ranked advisory suggestions to emit (`>= 1`).
    pub max_suggestions: usize,
}

/// Exact verifier disposition for one predicted candidate link.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinkVerificationStatus {
    /// Passed ALL 4 exact verifier gates; remains advisory-only (NEVER canonical truth!).
    AdmittedAdvisoryCandidate,
    /// Refused by the exact verifier with explicit machine reasons.
    RejectedByVerifier {
        /// Exact verification gates that rejected this candidate.
        reasons: Vec<String>,
    },
}

/// One scored & verified candidate link proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedLinkSuggestion {
    /// Canonical lower endpoint ID.
    pub left_id: String,
    /// Canonical upper endpoint ID.
    pub right_id: String,
    /// Common-neighbor overlap count.
    pub common_neighbors: u64,
    /// Exact integer Jaccard similarity in parts-per-million (`0..=1_000_000`).
    pub jaccard_ppm: u64,
    /// Exact verifier disposition.
    pub status: LinkVerificationStatus,
}

/// Canonical answer of `ALG-LINKPRED-001`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkPredictionResult {
    /// Pinned candidate model generation.
    pub model_generation: Generation,
    /// Ranked candidates that passed ALL exact verifier gates.
    pub admitted_advisory_candidates: Vec<VerifiedLinkSuggestion>,
    /// Ranked candidates explicitly rejected by the exact verifier (kept auditable!).
    pub rejected_candidates: Vec<VerifiedLinkSuggestion>,
    /// Always `false`: prediction NEVER creates canonical edges!
    pub creates_canonical_edge: bool,
    /// Always `false`: prediction NEVER creates identity!
    pub creates_identity: bool,
    /// Always `false`: prediction NEVER establishes corroboration!
    pub establishes_corroboration: bool,
    /// Always `false`: prediction NEVER grants effect authority!
    pub grants_effect_authority: bool,
}

impl CertifiedOutput for LinkPredictionResult {
    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.model_generation.0);
        for list in [
            &self.admitted_advisory_candidates,
            &self.rejected_candidates,
        ] {
            encoder.u64(list.len() as u64);
            for s in list {
                encoder.text(&s.left_id);
                encoder.text(&s.right_id);
                encoder.u64(s.common_neighbors);
                encoder.u64(s.jaccard_ppm);
                match &s.status {
                    LinkVerificationStatus::AdmittedAdvisoryCandidate => encoder.u8(1),
                    LinkVerificationStatus::RejectedByVerifier { reasons } => {
                        encoder.u8(2);
                        encoder.u64(reasons.len() as u64);
                        for r in reasons {
                            encoder.text(r);
                        }
                    }
                }
            }
        }
    }

    fn entries(&self) -> u64 {
        add(
            self.admitted_advisory_candidates.len() as u64,
            self.rejected_candidates.len() as u64,
        )
    }
}

/// Registered complexity bound for `n` nodes and `max_suggestions`.
#[must_use]
pub fn bound(n: u64, max_suggestions: u64) -> Vec<BoundRow> {
    let pairs = n.saturating_mul(n.saturating_sub(1)) / 2;
    vec![
        ("pair_scorings", add(mul(pairs, add(n, 1)), 2)),
        ("verifier_checks", add(pairs, 2)),
        (OUTPUT_ENTRIES, mul(2, max_suggestions)),
    ]
}

fn canonical_pair(a: &str, b: &str) -> (String, String) {
    if a <= b {
        (a.to_owned(), b.to_owned())
    } else {
        (b.to_owned(), a.to_owned())
    }
}

/// Runs `ALG-LINKPRED-001` non-authoritative scoring followed by mandatory exact verification.
pub fn predict_and_verify_links(
    graph: &UndirectedGraph,
    ctx: &LinkVerifierContext,
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<CertifiedRun<LinkPredictionResult>, GraphError> {
    if ctx.model_generation.0 == 0 || ctx.max_suggestions == 0 {
        return Err(GraphError::PreconditionFailed(
            "model_generation and max_suggestions must be >= 1".to_owned(),
        ));
    }
    let n = graph.node_count();
    let m = graph.edge_count();
    let bound_rows = bound(n as u64, ctx.max_suggestions as u64);
    let mut meter = Meter::new_cancellable(&IDENTITY, budget, is_cancelled);

    let norm_feasible: BTreeSet<(String, String)> = ctx
        .temporally_geometrically_feasible_pairs
        .iter()
        .map(|(a, b)| canonical_pair(a, b))
        .collect();
    let norm_contradicted: BTreeSet<(String, String)> = ctx
        .contradicted_pairs
        .iter()
        .map(|(a, b)| canonical_pair(a, b))
        .collect();

    let mut q = query_encoder(&IDENTITY, graph.digest());
    q.u64(ctx.model_generation.0);
    q.u64(ctx.max_suggestions as u64);
    q.u64(ctx.evidence_backed_nodes.len() as u64);
    for id in &ctx.evidence_backed_nodes {
        q.text(id);
    }
    q.u64(ctx.capability_visible_nodes.len() as u64);
    for id in &ctx.capability_visible_nodes {
        q.text(id);
    }
    q.u64(norm_feasible.len() as u64);
    for (a, b) in &norm_feasible {
        q.text(a);
        q.text(b);
    }
    q.u64(norm_contradicted.len() as u64);
    for (a, b) in &norm_contradicted {
        q.text(a);
        q.text(b);
    }
    let input_digest = query_digest(q);

    // Precompute neighbor sets for exact integer Jaccard & Common Neighbors.
    let adj_sets: Vec<BTreeSet<usize>> = (0..n)
        .map(|u| {
            graph
                .neighbours(u as u32)
                .iter()
                .map(|&(v, _)| v as usize)
                .collect()
        })
        .collect();

    let mut scored: Vec<(u64, u64, String, String)> = Vec::new();
    for u in 0..n {
        for v in (u + 1)..n {
            meter.tick("pair_scorings")?;
            if adj_sets[u].contains(&v) {
                continue;
            }
            let mut cn = 0_u64;
            for &w in &adj_sets[u] {
                meter.tick("pair_scorings")?;
                if adj_sets[v].contains(&w) {
                    cn += 1;
                }
            }
            if cn == 0 {
                continue;
            }
            let union_sz = (adj_sets[u].len() + adj_sets[v].len()) as u64 - cn;
            let jaccard_ppm = cn.saturating_mul(1_000_000) / union_sz.max(1);
            let (lid, rid) = canonical_pair(graph.id(u as u32), graph.id(v as u32));
            scored.push((jaccard_ppm, cn, lid, rid));
        }
    }

    // Canonical order: descending jaccard_ppm, descending cn, ascending (left_id, right_id).
    scored.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| a.2.cmp(&b.2))
            .then_with(|| a.3.cmp(&b.3))
    });

    // Mandatory exact verifier gate on EVERY candidate!
    let mut admitted = Vec::new();
    let mut rejected = Vec::new();
    let mut seen_rank: BTreeMap<(String, String), ()> = BTreeMap::new();

    for (jaccard_ppm, common_neighbors, left_id, right_id) in scored {
        if admitted.len() >= ctx.max_suggestions && rejected.len() >= ctx.max_suggestions {
            break;
        }
        meter.tick("verifier_checks")?;
        let pair = (left_id.clone(), right_id.clone());
        if seen_rank.insert(pair.clone(), ()).is_some() {
            continue;
        }
        let mut reasons = Vec::new();
        if !ctx.capability_visible_nodes.contains(&left_id)
            || !ctx.capability_visible_nodes.contains(&right_id)
        {
            reasons.push("endpoint_not_capability_visible".to_owned());
        }
        if !ctx.evidence_backed_nodes.contains(&left_id)
            || !ctx.evidence_backed_nodes.contains(&right_id)
        {
            reasons.push("missing_source_evidence_backing".to_owned());
        }
        if !norm_feasible.contains(&pair) {
            reasons.push("temporal_or_geometric_constraint_failed".to_owned());
        }
        if norm_contradicted.contains(&pair) {
            reasons.push("hard_contradiction_present".to_owned());
        }

        if reasons.is_empty() {
            if admitted.len() < ctx.max_suggestions {
                meter.path().text(&left_id);
                meter.path().text(&right_id);
                meter.path().u8(1);
                admitted.push(VerifiedLinkSuggestion {
                    left_id,
                    right_id,
                    common_neighbors,
                    jaccard_ppm,
                    status: LinkVerificationStatus::AdmittedAdvisoryCandidate,
                });
            }
        } else if rejected.len() < ctx.max_suggestions {
            meter.path().text(&left_id);
            meter.path().text(&right_id);
            meter.path().u8(0);
            rejected.push(VerifiedLinkSuggestion {
                left_id,
                right_id,
                common_neighbors,
                jaccard_ppm,
                status: LinkVerificationStatus::RejectedByVerifier { reasons },
            });
        }
    }

    let output = LinkPredictionResult {
        model_generation: ctx.model_generation,
        admitted_advisory_candidates: admitted,
        rejected_candidates: rejected,
        creates_canonical_edge: false,
        creates_identity: false,
        establishes_corroboration: false,
        grants_effect_authority: false,
    };
    let shape = InputShape {
        node_count: n as u64,
        edge_count: m as u64,
        input_digest,
    };
    let peak_bytes = ((n + m + 1) * 128) as u64;
    meter.finish(&IDENTITY, shape, output, &bound_rows, peak_bytes)
}
