#![forbid(unsafe_code)]
//! `ALG-MOTIF-001` — Motif, triadic-census, and routine-structure analysis (`fss-x4a.23.70.3`).
//!
//! Computes the exact 16-class directed MAN triadic census (`003`..`300`) plus recurring typed
//! routine-motif candidates over a bounded directed projection. Explicitly enforces that motif or
//! routine density NEVER whitelists behavior, establishes corroboration, or grants/suppresses
//! effects (`whitelists_behavior == false`, `establishes_corroboration == false`,
//! `grants_effect_authority == false`).

use std::collections::{BTreeMap, BTreeSet};

use fss_core::CanonicalEncoder;

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, query_digest, query_encoder,
};
use crate::graph::GraphError;
use crate::weighted::{Orientation, WeightedGraph};

/// Projection digest domain (`SCHEMA-DOMAIN-GRAPH-MOTIF-PROJECTION-001`).
pub const PROJECTION_DOMAIN: &str = "fss.graph.motif_projection.v1";
/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-MOTIF-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.motif_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-MOTIF-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.motif_decision_path.v1";

/// Registered identity (`architecture/graph_algorithms.json`, `ALG-MOTIF-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-MOTIF-001",
    algorithm_name: "motif_and_triadic_census",
    tie_break_rule: "canonical triad MAN class then lexicographic node triple",
    complexity_witness: "triad classifications and routine candidate aggregations",
    output_size_witness: "<= 16 MAN triad classes plus bounded routine candidates",
    exactness: "exact_or_bounded_advisory",
    implementation_id: "fss-graph-algorithms:alg-motif-001:exact-man-triad-census:v1",
    tie_break_policy_id: "tie:canonical-man-class-then-lexicographic-node-triple:v1",
    policy_id: "graph-policy:directed:man-16-triadic-census:non-whitelisting-advisory:tie:canonical-man-class-then-lexicographic-node-triple:v1",
    complexity_bound_id: "bound:alg-motif-001:cubic-bounded-triad-scan:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// Canonical 16 directed MAN triad isomorphism classes.
pub const MAN_TRIAD_CLASSES: [&str; 16] = [
    "003", "012", "102", "021D", "021U", "021C", "111D", "111U", "030T", "030C", "201", "120D",
    "120U", "120C", "210", "300",
];

/// Advisory routine-motif candidate surfaced for evidence-linked curation (NEVER whitelisting!).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutineMotifCandidate {
    /// Canonical MAN triad class (`030T`, `030C`, `300`, etc.).
    pub man_class: String,
    /// Exact count of observed instances in this projection.
    pub instance_count: u64,
    /// Bounded sample witness triples (`<= 8` canonical sorted `(u, v, w)` tuples).
    pub sample_triples: Vec<(String, String, String)>,
}

/// Canonical answer of `ALG-MOTIF-001`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriadicCensusResult {
    /// Complete 16-class MAN triadic census (sum equals `C(n, 3)`!).
    pub man_counts: BTreeMap<String, u64>,
    /// Non-empty closed/connected motif candidates (`030T`, `030C`, `120*`, `210`, `300`) for memory curation.
    pub routine_candidates: Vec<RoutineMotifCandidate>,
    /// Always `false`: motif frequency NEVER whitelists behavior!
    pub whitelists_behavior: bool,
    /// Always `false`: motif density NEVER establishes independent corroboration!
    pub establishes_corroboration: bool,
    /// Always `false`: advisory motif analysis NEVER grants or suppresses effects!
    pub grants_effect_authority: bool,
}

impl CertifiedOutput for TriadicCensusResult {
    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.man_counts.len() as u64);
        for (cls, cnt) in &self.man_counts {
            encoder.text(cls);
            encoder.u64(*cnt);
        }
        encoder.u64(self.routine_candidates.len() as u64);
        for rc in &self.routine_candidates {
            encoder.text(&rc.man_class);
            encoder.u64(rc.instance_count);
            encoder.u64(rc.sample_triples.len() as u64);
            for (a, b, c) in &rc.sample_triples {
                encoder.text(a);
                encoder.text(b);
                encoder.text(c);
            }
        }
    }

    fn entries(&self) -> u64 {
        add(
            self.man_counts.len() as u64,
            self.routine_candidates.len() as u64,
        )
    }
}

/// Registered complexity bound for `n` nodes.
#[must_use]
pub fn bound(n: u64) -> Vec<BoundRow> {
    let triples = if n >= 3 {
        n.saturating_mul(n - 1).saturating_mul(n - 2) / 6
    } else {
        0
    };
    vec![
        ("triad_classifications", add(triples, 1)),
        (OUTPUT_ENTRIES, 32),
    ]
}

/// Classifies an ordered triple `(a, b, c)` into its exact directed MAN triad class (`003..300`).
#[must_use]
pub fn classify_man_triad(
    ab: bool,
    ba: bool,
    ac: bool,
    ca: bool,
    bc: bool,
    cb: bool,
) -> &'static str {
    let mut mutual = 0_u8;
    let mut asym = 0_u8;
    for (xy, yx) in [(ab, ba), (ac, ca), (bc, cb)] {
        if xy && yx {
            mutual += 1;
        } else if xy || yx {
            asym += 1;
        }
    }
    let out_deg = [
        u8::from(ab) + u8::from(ac),
        u8::from(ba) + u8::from(bc),
        u8::from(ca) + u8::from(cb),
    ];
    let in_deg = [
        u8::from(ba) + u8::from(ca),
        u8::from(ab) + u8::from(cb),
        u8::from(ac) + u8::from(bc),
    ];
    match (mutual, asym) {
        (0, 0) => "003",
        (0, 1) => "012",
        (1, 0) => "102",
        (0, 2) => {
            if out_deg.contains(&2) {
                "021D"
            } else if in_deg.contains(&2) {
                "021U"
            } else {
                "021C"
            }
        }
        (1, 1) => {
            // Find the single asymmetric arc; check whether it enters or leaves the mutual dyad.
            // In MAN convention: 111D has the non-mutual vertex having out-degree 1 (pointing INTO dyad -> dyad vertex has in=2, out=1);
            // 111U has the non-mutual vertex having in-degree 1 (pointed TO from dyad -> dyad vertex has out=2, in=1).
            if in_deg.contains(&2) { "111D" } else { "111U" }
        }
        (0, 3) => {
            if out_deg == [1, 1, 1] && in_deg == [1, 1, 1] {
                "030C"
            } else {
                "030T"
            }
        }
        (2, 0) => "201",
        (1, 2) => {
            // 120D: one node has out=2, in=0; 120U: one node has in=2, out=0; 120C: cyclic asymmetric + mutual.
            if (0..3).any(|i| out_deg[i] == 2 && in_deg[i] == 0) {
                "120D"
            } else if (0..3).any(|i| in_deg[i] == 2 && out_deg[i] == 0) {
                "120U"
            } else {
                "120C"
            }
        }
        (2, 1) => "210",
        (3, 0) => "300",
        _ => "003",
    }
}

/// Runs `ALG-MOTIF-001` exact 16-class MAN triadic census over a directed `WeightedGraph`.
pub fn triadic_census_and_motifs(
    graph: &WeightedGraph,
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<CertifiedRun<TriadicCensusResult>, GraphError> {
    if graph.orientation() != Orientation::Directed {
        return Err(GraphError::PreconditionFailed(
            "ALG-MOTIF-001 requires a directed projection".to_owned(),
        ));
    }
    let n = graph.node_count();
    let bound_rows = bound(n as u64);
    let mut meter = Meter::new_cancellable(&IDENTITY, budget, is_cancelled);

    let q = query_encoder(&IDENTITY, graph.digest());
    let input_digest = query_digest(q);

    let mut adj: BTreeSet<(usize, usize)> = BTreeSet::new();
    for arc in graph.arcs() {
        adj.insert((arc.tail as usize, arc.head as usize));
    }

    let mut man_counts: BTreeMap<String, u64> = MAN_TRIAD_CLASSES
        .iter()
        .map(|&c| (c.to_owned(), 0_u64))
        .collect();
    let mut samples: BTreeMap<&'static str, Vec<(String, String, String)>> = BTreeMap::new();

    for i in 0..n {
        for j in (i + 1)..n {
            for k in (j + 1)..n {
                meter.tick("triad_classifications")?;
                let cls = classify_man_triad(
                    adj.contains(&(i, j)),
                    adj.contains(&(j, i)),
                    adj.contains(&(i, k)),
                    adj.contains(&(k, i)),
                    adj.contains(&(j, k)),
                    adj.contains(&(k, j)),
                );
                *man_counts.entry(cls.to_owned()).or_insert(0) += 1;
                if matches!(
                    cls,
                    "030T" | "030C" | "120D" | "120U" | "120C" | "210" | "300"
                ) {
                    let entry = samples.entry(cls).or_default();
                    if entry.len() < 8 {
                        entry.push((
                            graph.id(i as u32).to_owned(),
                            graph.id(j as u32).to_owned(),
                            graph.id(k as u32).to_owned(),
                        ));
                    }
                }
            }
        }
    }

    let mut routine_candidates = Vec::new();
    for (cls, sample_triples) in samples {
        let count = man_counts.get(cls).copied().unwrap_or(0);
        meter.path().text(cls);
        meter.path().u64(count);
        routine_candidates.push(RoutineMotifCandidate {
            man_class: cls.to_owned(),
            instance_count: count,
            sample_triples,
        });
    }

    let output = TriadicCensusResult {
        man_counts,
        routine_candidates,
        whitelists_behavior: false,
        establishes_corroboration: false,
        grants_effect_authority: false,
    };
    let shape = InputShape {
        node_count: n as u64,
        edge_count: graph.arc_count() as u64,
        input_digest,
    };
    let peak_bytes = ((n + graph.arc_count() + 1) * 128) as u64;
    meter.finish(&IDENTITY, shape, output, &bound_rows, peak_bytes)
}
