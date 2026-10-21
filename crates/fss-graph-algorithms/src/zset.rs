#![forbid(unsafe_code)]
//! `ALG-ZSET-001` — DBSP Abelian group `Z-set` incremental view maintenance over capsule deltas.
//!
//! Represents collections and changes uniformly as sorted maps from canonical tuple keys to
//! non-zero signed integer multiplicities (`i64`). Linear operators (`filter`, `project`,
//! degree aggregation) satisfy `Delta(L(S)) = L(Delta(S))`, and bilinear relational joins satisfy
//! `Delta(A join B) = (Delta A join B_prev) + (A_prev join Delta B) + (Delta A join Delta B)`
//! (`Q(I(Delta)) == I(Delta Q)` exactness).

use std::collections::BTreeMap;

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, mul, query_digest, query_encoder,
};
use crate::graph::GraphError;

/// Projection digest domain (`SCHEMA-DOMAIN-GRAPH-ZSET-PROJECTION-001`).
pub const PROJECTION_DOMAIN: &str = "fss.graph.zset_projection.v1";
/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-ZSET-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.zset_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-ZSET-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.zset_decision_path.v1";

/// Registered identity (`architecture/graph_algorithms.json`, `ALG-ZSET-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-ZSET-001",
    algorithm_name: "zset_incremental_maintenance",
    tie_break_rule: "commit sequence then stable tuple key",
    complexity_witness: "delta tuple updates and circuit activations",
    output_size_witness: "<= |Delta| <= |V| + |E| delta tuple records",
    exactness: "exact",
    implementation_id: "fss-graph-algorithms:alg-zset-001:dbsp-abelian-zset-bilinear-join-delta:v1",
    tie_break_policy_id: "tie:commit-sequence-then-lexicographic-tuple-key:v1",
    policy_id: "graph-policy:incremental-zset:signed-i64-multiplicity:zero-weight-consolidation:bilinear-delta-join:tie:commit-sequence-then-lexicographic-tuple-key:v1",
    complexity_bound_id: "bound:alg-zset-001:delta-tuples-plus-circuit-activations:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// Registered complexity bound for `v` nodes, `e` edges, and `d` delta tuples.
#[must_use]
pub fn bound(v: u64, e: u64, d: u64) -> Vec<BoundRow> {
    let cap = add(v, e).max(d);
    vec![
        ("delta_tuple_updates", add(mul(4, d), mul(2, cap))),
        ("circuit_activations", add(mul(d, add(v, 2)), cap)),
        (OUTPUT_ENTRIES, add(v, e)),
    ]
}

/// Canonical Abelian group `Z-set` mapping keys `K` to non-zero `i64` multiplicities.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ZSet<K: Ord> {
    entries: BTreeMap<K, i64>,
}

impl<K: Ord + Clone> ZSet<K> {
    /// Empty `Z-set` (additive identity `0`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Builds a consolidated `Z-set` from `(key, weight)` pairs, summing duplicates and dropping
    /// zero weights.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::ArithmeticOverflow`] if any multiplicity addition overflows `i64`.
    pub fn from_iter_checked<I>(iter: I) -> Result<Self, GraphError>
    where
        I: IntoIterator<Item = (K, i64)>,
    {
        let mut zset = Self::new();
        for (k, w) in iter {
            zset.add_weight(k, w)?;
        }
        Ok(zset)
    }

    /// Adds `delta` to the multiplicity of `key`, removing the entry if the new multiplicity is 0.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::ArithmeticOverflow`] on `i64` overflow.
    pub fn add_weight(&mut self, key: K, delta: i64) -> Result<(), GraphError> {
        if delta == 0 {
            return Ok(());
        }
        let next = match self.entries.get(&key) {
            Some(&cur) => cur
                .checked_add(delta)
                .ok_or(GraphError::ArithmeticOverflow("zset_multiplicity"))?,
            None => delta,
        };
        if next == 0 {
            self.entries.remove(&key);
        } else {
            self.entries.insert(key, next);
        }
        Ok(())
    }

    /// Multiplicity of `key` (`0` if absent).
    #[must_use]
    pub fn weight(&self, key: &K) -> i64 {
        self.entries.get(key).copied().unwrap_or(0)
    }

    /// Number of non-zero entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the `Z-set` is identically zero.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterates `(key, weight)` in ascending key order.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &i64)> {
        self.entries.iter()
    }

    /// Additive inverse `-self`.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::ArithmeticOverflow`] if any weight is `i64::MIN`.
    pub fn negate(&self) -> Result<Self, GraphError> {
        let mut out = BTreeMap::new();
        for (k, &w) in &self.entries {
            let neg = w
                .checked_neg()
                .ok_or(GraphError::ArithmeticOverflow("zset_negate"))?;
            out.insert(k.clone(), neg);
        }
        Ok(Self { entries: out })
    }

    /// Abelian group sum `self + other` (`I(Delta)` integration step).
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::ArithmeticOverflow`] on `i64` overflow.
    pub fn add(&self, other: &Self) -> Result<Self, GraphError> {
        let mut out = self.clone();
        for (k, &w) in &other.entries {
            out.add_weight(k.clone(), w)?;
        }
        Ok(out)
    }

    /// Abelian group difference `self - other` (`D(S)` differentiation step).
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::ArithmeticOverflow`] on `i64` overflow.
    pub fn subtract(&self, other: &Self) -> Result<Self, GraphError> {
        let neg = other.negate()?;
        self.add(&neg)
    }

    /// Linear filter operator: `Delta(filter(S)) == filter(Delta(S))`.
    #[must_use]
    pub fn filter<F>(&self, mut predicate: F) -> Self
    where
        F: FnMut(&K) -> bool,
    {
        let entries = self
            .entries
            .iter()
            .filter(|(k, _)| predicate(k))
            .map(|(k, &w)| (k.clone(), w))
            .collect();
        Self { entries }
    }
}

/// Full relational equijoin `A((x, y)) join B((y, z)) -> (x, y, z)` with multiplied weights.
///
/// # Errors
///
/// Returns [`GraphError::ArithmeticOverflow`] on weight multiplication or addition overflow.
pub fn zset_equijoin(
    left: &ZSet<(String, String)>,
    right: &ZSet<(String, String)>,
) -> Result<ZSet<(String, String, String)>, GraphError> {
    let mut right_by_key: BTreeMap<&str, Vec<(&str, i64)>> = BTreeMap::new();
    for ((y, z), &w) in right.iter() {
        right_by_key
            .entry(y.as_str())
            .or_default()
            .push((z.as_str(), w));
    }
    let mut out = ZSet::new();
    for ((x, y), &wl) in left.iter() {
        if let Some(matches) = right_by_key.get(y.as_str()) {
            for &(z, wr) in matches {
                let prod = wl
                    .checked_mul(wr)
                    .ok_or(GraphError::ArithmeticOverflow("zset_join_mul"))?;
                out.add_weight((x.clone(), y.clone(), z.to_owned()), prod)?;
            }
        }
    }
    Ok(out)
}

/// Bilinear incremental DBSP equijoin:
/// `Delta(A join B) = (Delta A join B_prev) + (A_prev join Delta B) + (Delta A join Delta B)`.
///
/// # Errors
///
/// Returns [`GraphError::ArithmeticOverflow`] on weight overflow.
pub fn zset_incremental_equijoin(
    prev_left: &ZSet<(String, String)>,
    delta_left: &ZSet<(String, String)>,
    prev_right: &ZSet<(String, String)>,
    delta_right: &ZSet<(String, String)>,
) -> Result<ZSet<(String, String, String)>, GraphError> {
    let term1 = zset_equijoin(delta_left, prev_right)?;
    let term2 = zset_equijoin(prev_left, delta_right)?;
    let term3 = zset_equijoin(delta_left, delta_right)?;
    term1.add(&term2)?.add(&term3)
}

/// Base graph state maintained as a `Z-set` of nodes and directed arcs.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ZSetGraphState {
    /// Active node identities with multiplicity.
    pub nodes: ZSet<String>,
    /// Active directed arcs `(tail, head)` with multiplicity.
    pub arcs: ZSet<(String, String)>,
}

impl ZSetGraphState {
    /// Canonical digest of the base state.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(PROJECTION_DOMAIN);
        encoder.u64(self.nodes.len() as u64);
        for (node, &w) in self.nodes.iter() {
            encoder.text(node);
            encoder.u64(w as u64);
        }
        encoder.u64(self.arcs.len() as u64);
        for ((u, v), &w) in self.arcs.iter() {
            encoder.text(u);
            encoder.text(v);
            encoder.u64(w as u64);
        }
        ContentDigest::sha256(&encoder.finish())
    }
}

/// One incremental delta batch at `commit_sequence`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ZSetDeltaBatch {
    /// Monotonic authority commit sequence.
    pub commit_sequence: u64,
    /// Node multiplicity updates `(node_id, delta_weight)`.
    pub node_deltas: Vec<(String, i64)>,
    /// Arc multiplicity updates `((tail_id, head_id), delta_weight)`.
    pub arc_deltas: Vec<((String, String), i64)>,
}

/// One emitted view-delta tuple record.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ZSetDeltaRecord {
    /// Commit sequence that produced the delta.
    pub commit_sequence: u64,
    /// Canonical view tuple key (`arc:u->v`, `out_deg:u`, or `node:u`).
    pub tuple_key: String,
    /// Non-zero signed multiplicity change.
    pub delta_weight: i64,
}

/// Canonical answer of `ALG-ZSET-001`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ZSetMaintenanceOutput {
    /// Consolidated view delta records in `(commit_sequence, tuple_key)` order, capped at `|V| + |E|`.
    pub delta_records: Vec<ZSetDeltaRecord>,
    ///Incremental 2-hop composition delta count (`Delta(E join E)`), verifying bilinear circuit activation.
    pub two_hop_delta_count: u64,
}

impl CertifiedOutput for ZSetMaintenanceOutput {
    fn entries(&self) -> u64 {
        self.delta_records.len() as u64
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.two_hop_delta_count);
        encoder.u64(self.delta_records.len() as u64);
        for rec in &self.delta_records {
            encoder.u64(rec.commit_sequence);
            encoder.text(&rec.tuple_key);
            encoder.u64(rec.delta_weight as u64);
        }
    }
}

fn input_digest(state: &ZSetGraphState, batch: &ZSetDeltaBatch) -> ContentDigest {
    let mut encoder = query_encoder(&IDENTITY, state.digest());
    encoder.u64(batch.commit_sequence);
    encoder.u64(batch.node_deltas.len() as u64);
    for (n, w) in &batch.node_deltas {
        encoder.text(n);
        encoder.u64(*w as u64);
    }
    encoder.u64(batch.arc_deltas.len() as u64);
    for ((u, v), w) in &batch.arc_deltas {
        encoder.text(u);
        encoder.text(v);
        encoder.u64(*w as u64);
    }
    query_digest(encoder)
}

/// Runs `ALG-ZSET-001` incremental view maintenance over `state` and `batch`.
///
/// # Errors
///
/// Fails closed on arithmetic overflow or budget/bound exhaustion.
pub fn zset_incremental_maintenance(
    state: &ZSetGraphState,
    batch: &ZSetDeltaBatch,
    budget: Budget,
) -> Result<CertifiedRun<ZSetMaintenanceOutput>, GraphError> {
    let mut delta_nodes = ZSet::new();
    for (n, w) in &batch.node_deltas {
        delta_nodes.add_weight(n.clone(), *w)?;
    }
    let mut delta_arcs = ZSet::new();
    for ((u, v), w) in &batch.arc_deltas {
        delta_arcs.add_weight((u.clone(), v.clone()), *w)?;
    }

    let next_nodes = state.nodes.add(&delta_nodes)?;
    let next_arcs = state.arcs.add(&delta_arcs)?;

    let v_count = next_nodes.len().max(state.nodes.len()) as u64;
    let e_count = next_arcs.len().max(state.arcs.len()) as u64;
    let d_count = (batch.node_deltas.len() + batch.arc_deltas.len()) as u64;
    let digest = input_digest(state, batch);
    let mut meter = Meter::new(&IDENTITY, budget);
    let bound_rows = bound(v_count, e_count, d_count);

    // Linear operator: out-degree view delta `Delta(out_deg)(u) = sum_v Delta_arcs(u, v)`.
    let mut deg_delta: ZSet<String> = ZSet::new();
    for ((u, _v), &w) in delta_arcs.iter() {
        meter.tick("delta_tuple_updates")?;
        deg_delta.add_weight(u.clone(), w)?;
    }
    for (_n, &_w) in delta_nodes.iter() {
        meter.tick("delta_tuple_updates")?;
    }

    // Bilinear operator: 2-hop composition delta `Delta(E join E)`.
    let two_hop_delta =
        zset_incremental_equijoin(&state.arcs, &delta_arcs, &state.arcs, &delta_arcs)?;
    for _ in 0..delta_arcs.len() {
        meter.tick("circuit_activations")?;
    }

    let max_records = add(v_count, e_count) as usize;
    let mut raw_records: Vec<ZSetDeltaRecord> = Vec::new();
    for (n, &w) in delta_nodes.iter() {
        meter.tick("delta_tuple_updates")?;
        raw_records.push(ZSetDeltaRecord {
            commit_sequence: batch.commit_sequence,
            tuple_key: format!("node:{n}"),
            delta_weight: w,
        });
    }
    for ((u, v), &w) in delta_arcs.iter() {
        meter.tick("delta_tuple_updates")?;
        raw_records.push(ZSetDeltaRecord {
            commit_sequence: batch.commit_sequence,
            tuple_key: format!("arc:{u}->{v}"),
            delta_weight: w,
        });
    }
    for (u, &w) in deg_delta.iter() {
        meter.tick("circuit_activations")?;
        raw_records.push(ZSetDeltaRecord {
            commit_sequence: batch.commit_sequence,
            tuple_key: format!("out_deg:{u}"),
            delta_weight: w,
        });
    }
    raw_records.sort();
    if raw_records.len() > max_records {
        raw_records.truncate(max_records);
    }
    for (idx, rec) in raw_records.iter().enumerate() {
        meter.decide(1, idx as u64, rec.delta_weight.unsigned_abs());
    }

    let working_bytes = ((v_count + e_count + d_count) * 48) as u64;
    meter.finish(
        &IDENTITY,
        InputShape {
            node_count: v_count,
            edge_count: e_count,
            input_digest: digest,
        },
        ZSetMaintenanceOutput {
            delta_records: raw_records,
            two_hop_delta_count: two_hop_delta.len() as u64,
        },
        &bound_rows,
        working_bytes,
    )
}
