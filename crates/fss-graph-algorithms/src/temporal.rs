//! `ALG-TREACH-001` — temporal reachability under interval time and transit constraints.
//!
//! A [`TemporalNetwork`] is a directed movement projection (zones, portals, camera views) in one
//! integer time unit with a horizon `H`. Every node declares how long an entity may linger there
//! (`max_wait`, `u64::MAX` for unbounded); every arc declares the window in which a traversal may
//! *start* (`open..=close`) and the travel-time bounds (`min_travel..=max_travel`). Given the
//! uncertain capture interval at which an entity was at the source, the run computes, for every
//! node, the exact set of integer times at which the entity could be present there — the least
//! fixpoint of
//!
//! `presence(v) = linger(v, start if v = source  ∪  ⋃ (presence(u) ∩ window(u, v)) ⊕ travel(u, v))`
//!
//! clipped to `0..=H`, as sorted disjoint inclusive intervals. Nothing is approximated: interval
//! endpoints are exact integers and every sum is checked. Each node is classified
//! `reachable`, `temporally_infeasible` (a path exists but no timing composes — the invalidation
//! reason for an association that geometry alone would allow) or `no_path`.
//!
//! The fixpoint is a worklist over ascending node identity; a per-node interval cap
//! (`max_intervals`) and the operation budget fail closed — never a truncated set presented as
//! exact.

use std::collections::{BTreeSet, VecDeque};

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, mul, query_digest, query_encoder,
};
use crate::graph::{GraphError, MAX_GRAPH_EDGES, MAX_GRAPH_NODES, MAX_NODE_ID_LEN};

/// Temporal projection digest domain (`SCHEMA-DOMAIN-GRAPH-TEMPORAL-PROJECTION-001`).
pub const TEMPORAL_PROJECTION_DOMAIN: &str = "fss.graph.temporal_projection.v1";
/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-TREACH-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.treach_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-TREACH-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.treach_decision_path.v1";
/// Maximum intervals one presence set may hold.
pub const MAX_INTERVALS: u32 = 1 << 16;

/// Registered identity (`ALG-TREACH-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-TREACH-001",
    algorithm_name: "temporal_reachability",
    tie_break_rule: "earliest feasible interval then stable path identity",
    complexity_witness: "interval compositions and dominance prunes",
    output_size_witness: "<= |V| reached nodes and <= |E| valid intervals",
    exactness: "exact",
    implementation_id: "fss-graph-algorithms:alg-treach-001:integer-interval-least-fixpoint-worklist:v1",
    tie_break_policy_id: "tie:ascending-node-identity-worklist-sorted-disjoint-intervals:v1",
    policy_id: "graph-policy:directed:simple-strict:departure-window-travel-bounds-node-linger:integer-time:checked:horizon-clipped:v1:tie:ascending-node-identity-worklist-sorted-disjoint-intervals:v1",
    complexity_bound_id: "bound:alg-treach-001:n-times-horizon-node-updates:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// The registered bound for `n` nodes, `m` arcs, horizon `h` and interval cap `cap`: every node
/// update adds at least one integer time point, so there are at most `n (h + 1) + n` updates.
#[must_use]
pub fn bound(n: u64, m: u64, horizon: u64, cap: u64) -> Vec<BoundRow> {
    let updates = add(mul(n, add(horizon, 1)), n);
    vec![
        ("node_updates", updates),
        ("arc_propagations", mul(updates, add(m, 1))),
        (
            "interval_compositions",
            mul(mul(updates, add(m, 1)), add(cap, 1)),
        ),
        (
            "dominance_prunes",
            mul(mul(updates, add(m, 1)), mul(2, add(cap, 1))),
        ),
        ("reachability_scans", add(m, n)),
        (OUTPUT_ENTRIES, mul(n, add(cap, 1))),
    ]
}

/// Traversal constraints of one arc.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Transit {
    /// Earliest start of a traversal.
    pub open: u64,
    /// Latest start of a traversal.
    pub close: u64,
    /// Minimum travel time.
    pub min_travel: u64,
    /// Maximum travel time.
    pub max_travel: u64,
}

/// Collects one temporal network in any order.
#[derive(Clone, Debug)]
pub struct TemporalNetworkBuilder {
    unit: String,
    horizon: u64,
    nodes: Vec<(String, u64)>,
    arcs: Vec<(String, String, Transit)>,
}

impl TemporalNetworkBuilder {
    /// An empty network in `unit` with horizon `horizon`.
    #[must_use]
    pub fn new(unit: impl Into<String>, horizon: u64) -> Self {
        Self {
            unit: unit.into(),
            horizon,
            nodes: Vec::new(),
            arcs: Vec::new(),
        }
    }

    /// Adds a node where an entity may linger up to `max_wait`.
    pub fn add_node(&mut self, id: impl Into<String>, max_wait: u64) -> &mut Self {
        self.nodes.push((id.into(), max_wait));
        self
    }

    /// Adds a transit `tail -> head`.
    pub fn add_transit(
        &mut self,
        tail: impl Into<String>,
        head: impl Into<String>,
        transit: Transit,
    ) -> &mut Self {
        self.arcs.push((tail.into(), head.into(), transit));
        self
    }

    /// Validates and canonicalizes.
    ///
    /// # Errors
    ///
    /// [`GraphError`] input variants (identities, unit, size, self-loop, parallel transit,
    /// unknown endpoint), and [`GraphError::PreconditionFailed`] for an inverted window or
    /// travel bound.
    pub fn build(self) -> Result<TemporalNetwork, GraphError> {
        if self.unit.is_empty()
            || self.unit.len() > 64
            || !self
                .unit
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b":_-.".contains(&byte))
        {
            return Err(GraphError::InvalidNodeId(format!("unit:{}", self.unit)));
        }
        if self.nodes.len() > MAX_GRAPH_NODES || self.arcs.len() > MAX_GRAPH_EDGES {
            return Err(GraphError::TooLarge);
        }
        let mut nodes = self.nodes;
        nodes.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        for (id, _) in &nodes {
            if id.is_empty() || id.len() > MAX_NODE_ID_LEN || id.chars().any(char::is_control) {
                return Err(GraphError::InvalidNodeId(id.clone()));
            }
        }
        for pair in nodes.windows(2) {
            if pair[0].0 == pair[1].0 {
                return Err(GraphError::DuplicateNode(pair[0].0.clone()));
            }
        }
        let (ids, waits): (Vec<String>, Vec<u64>) = nodes.into_iter().unzip();
        let index = |id: &str| {
            ids.binary_search_by(|probe| probe.as_str().cmp(id))
                .map(|position| position as u32)
                .map_err(|_| GraphError::UnknownNode(id.to_owned()))
        };
        let mut arcs = Vec::with_capacity(self.arcs.len());
        for (tail, head, transit) in &self.arcs {
            let (t, h) = (index(tail)?, index(head)?);
            if t == h {
                return Err(GraphError::SelfLoop(tail.clone()));
            }
            if transit.open > transit.close || transit.min_travel > transit.max_travel {
                return Err(GraphError::PreconditionFailed(format!(
                    "transit {tail} -> {head} has an inverted window or travel bound"
                )));
            }
            arcs.push((t, h, *transit));
        }
        arcs.sort_unstable();
        for pair in arcs.windows(2) {
            if (pair[0].0, pair[0].1) == (pair[1].0, pair[1].1) {
                return Err(GraphError::ParallelEdge(
                    ids[pair[0].0 as usize].clone(),
                    ids[pair[0].1 as usize].clone(),
                ));
            }
        }
        let mut out: Vec<Vec<u32>> = vec![Vec::new(); ids.len()];
        for (position, &(t, _, _)) in arcs.iter().enumerate() {
            out[t as usize].push(position as u32);
        }
        Ok(TemporalNetwork {
            unit: self.unit,
            horizon: self.horizon,
            ids,
            waits,
            arcs,
            out,
        })
    }
}

/// An immutable canonical temporal movement network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemporalNetwork {
    unit: String,
    horizon: u64,
    ids: Vec<String>,
    waits: Vec<u64>,
    arcs: Vec<(u32, u32, Transit)>,
    out: Vec<Vec<u32>>,
}

impl TemporalNetwork {
    /// Node identities in canonical order.
    #[must_use]
    pub fn ids(&self) -> &[String] {
        &self.ids
    }

    /// Lingering bound of canonical node `node`.
    #[must_use]
    pub fn max_wait(&self, node: u32) -> u64 {
        self.waits[node as usize]
    }

    /// Transits `(tail, head, constraints)` in canonical order.
    #[must_use]
    pub fn transits(&self) -> &[(u32, u32, Transit)] {
        &self.arcs
    }

    /// Horizon.
    #[must_use]
    pub const fn horizon(&self) -> u64 {
        self.horizon
    }

    /// Canonical index of `id`.
    #[must_use]
    pub fn index_of(&self, id: &str) -> Option<u32> {
        self.ids
            .binary_search_by(|probe| probe.as_str().cmp(id))
            .ok()
            .map(|position| position as u32)
    }

    /// Domain-separated canonical digest.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(TEMPORAL_PROJECTION_DOMAIN);
        encoder.text(&self.unit);
        encoder.u64(self.horizon);
        encoder.u64(self.ids.len() as u64);
        for (id, wait) in self.ids.iter().zip(&self.waits) {
            encoder.text(id);
            encoder.u64(*wait);
        }
        encoder.u64(self.arcs.len() as u64);
        for &(t, h, transit) in &self.arcs {
            encoder.u32(t);
            encoder.u32(h);
            encoder.u64(transit.open);
            encoder.u64(transit.close);
            encoder.u64(transit.min_travel);
            encoder.u64(transit.max_travel);
        }
        ContentDigest::sha256(&encoder.finish())
    }
}

/// Classification of one node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reachability {
    /// Some time within the horizon admits presence.
    Reachable,
    /// A path exists but no timing composes within the horizon.
    TemporallyInfeasible,
    /// No path from the source at all.
    NoPath,
}

impl Reachability {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::TemporallyInfeasible => "temporally_infeasible",
            Self::NoPath => "no_path",
        }
    }
}

/// One node of the answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresenceRow {
    /// Node identity.
    pub node: String,
    /// Classification.
    pub reachability: Reachability,
    /// Sorted disjoint inclusive presence intervals.
    pub presence: Vec<(u64, u64)>,
}

/// The canonical answer of `ALG-TREACH-001`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemporalOutput {
    /// Source.
    pub source: String,
    /// Capture interval at the source.
    pub start: (u64, u64),
    /// Horizon.
    pub horizon: u64,
    /// Every node in ascending identity order.
    pub rows: Vec<PresenceRow>,
}

impl TemporalOutput {
    /// The row of `node`.
    #[must_use]
    pub fn row(&self, node: &str) -> Option<&PresenceRow> {
        self.rows
            .binary_search_by(|row| row.node.as_str().cmp(node))
            .ok()
            .map(|position| &self.rows[position])
    }
}

impl CertifiedOutput for TemporalOutput {
    fn entries(&self) -> u64 {
        self.rows.iter().map(|row| row.presence.len() as u64).sum()
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.source);
        encoder.u64(self.start.0);
        encoder.u64(self.start.1);
        encoder.u64(self.horizon);
        encoder.u64(self.rows.len() as u64);
        for row in &self.rows {
            encoder.text(&row.node);
            encoder.text(row.reachability.as_str());
            encoder.u64(row.presence.len() as u64);
            for &(lo, hi) in &row.presence {
                encoder.u64(lo);
                encoder.u64(hi);
            }
        }
    }
}

/// Merges sorted-or-not inclusive integer intervals into sorted disjoint ones (adjacent
/// integers merge).
fn normalize(
    mut intervals: Vec<(u64, u64)>,
    meter: &mut Meter,
) -> Result<Vec<(u64, u64)>, GraphError> {
    intervals.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(intervals.len());
    for (lo, hi) in intervals {
        meter.tick("dominance_prunes")?;
        match merged.last_mut() {
            Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
            _ => merged.push((lo, hi)),
        }
    }
    Ok(merged)
}

/// Each interval extended by lingering `wait`, clipped to the horizon.
fn linger(intervals: &[(u64, u64)], wait: u64, horizon: u64) -> Vec<(u64, u64)> {
    intervals
        .iter()
        .map(|&(lo, hi)| (lo, hi.saturating_add(wait).min(horizon)))
        .collect()
}

/// Runs `ALG-TREACH-001` from `source` present during `start = (earliest, latest)`.
///
/// # Errors
///
/// [`GraphError::UnknownNode`], [`GraphError::PreconditionFailed`] for an inverted start interval
/// or an interval cap outside `1..=MAX_INTERVALS`, [`GraphError::BudgetExhausted`] (including
/// the `intervals` dimension) and [`GraphError::ComplexityBoundViolated`].
pub fn temporal_reachability(
    network: &TemporalNetwork,
    source: &str,
    start: (u64, u64),
    max_intervals: u32,
    budget: Budget,
) -> Result<CertifiedRun<TemporalOutput>, GraphError> {
    let s = network
        .index_of(source)
        .ok_or_else(|| GraphError::UnknownNode(source.to_owned()))?;
    if start.0 > start.1 {
        return Err(GraphError::PreconditionFailed(
            "inverted start interval".to_owned(),
        ));
    }
    if max_intervals == 0 || max_intervals > MAX_INTERVALS {
        return Err(GraphError::PreconditionFailed(format!(
            "max_intervals must be within 1..={MAX_INTERVALS}"
        )));
    }
    let n = network.ids.len();
    let horizon = network.horizon;
    let mut meter = Meter::new(&IDENTITY, budget);
    let mut presence: Vec<Vec<(u64, u64)>> = vec![Vec::new(); n];
    if start.0 <= horizon {
        let clipped = vec![(start.0, start.1.min(horizon))];
        presence[s as usize] = normalize(
            linger(&clipped, network.waits[s as usize], horizon),
            &mut meter,
        )?;
    }
    let mut queue: BTreeSet<u32> = BTreeSet::new();
    if !presence[s as usize].is_empty() {
        meter.tick("node_updates")?;
        queue.insert(s);
    }
    while let Some(u) = queue.pop_first() {
        meter.decide(0, u64::from(u), presence[u as usize].len() as u64);
        for &arc_index in &network.out[u as usize] {
            meter.tick("arc_propagations")?;
            let (_, v, transit) = network.arcs[arc_index as usize];
            let mut arrivals: Vec<(u64, u64)> = Vec::new();
            for &(lo, hi) in &presence[u as usize] {
                meter.tick("interval_compositions")?;
                let (depart_lo, depart_hi) = (lo.max(transit.open), hi.min(transit.close));
                if depart_lo > depart_hi {
                    continue;
                }
                let arrive_lo = depart_lo.saturating_add(transit.min_travel);
                if arrive_lo > horizon {
                    continue;
                }
                let arrive_hi = depart_hi.saturating_add(transit.max_travel).min(horizon);
                arrivals.push((arrive_lo, arrive_hi));
            }
            if arrivals.is_empty() {
                continue;
            }
            let reached = linger(&arrivals, network.waits[v as usize], horizon);
            let mut union = presence[v as usize].clone();
            union.extend(reached);
            let union = normalize(union, &mut meter)?;
            if union != presence[v as usize] {
                if union.len() > max_intervals as usize {
                    return Err(GraphError::BudgetExhausted {
                        dimension: "intervals",
                        limit: u64::from(max_intervals),
                    });
                }
                meter.tick("node_updates")?;
                presence[v as usize] = union;
                queue.insert(v);
            }
        }
    }
    // Structural reachability, ignoring time.
    let mut structural = vec![false; n];
    structural[s as usize] = true;
    let mut frontier = VecDeque::from([s]);
    meter.tick("reachability_scans")?;
    while let Some(u) = frontier.pop_front() {
        for &arc_index in &network.out[u as usize] {
            meter.tick("reachability_scans")?;
            let v = network.arcs[arc_index as usize].1;
            if !structural[v as usize] {
                structural[v as usize] = true;
                frontier.push_back(v);
            }
        }
    }
    let rows = (0..n)
        .map(|node| PresenceRow {
            node: network.ids[node].clone(),
            reachability: if !presence[node].is_empty() {
                Reachability::Reachable
            } else if structural[node] {
                Reachability::TemporallyInfeasible
            } else {
                Reachability::NoPath
            },
            presence: presence[node].clone(),
        })
        .collect();
    let output = TemporalOutput {
        source: source.to_owned(),
        start,
        horizon,
        rows,
    };
    let (n64, m64) = (n as u64, network.arcs.len() as u64);
    let mut input = query_encoder(&IDENTITY, network.digest());
    input.text(source);
    input.u64(start.0);
    input.u64(start.1);
    input.u32(max_intervals);
    let stored: u64 = presence.iter().map(|set| set.len() as u64).sum();
    let peak = 16 * stored + 16 * u64::from(max_intervals) + 6 * n64;
    meter.finish(
        &IDENTITY,
        InputShape {
            node_count: n64,
            edge_count: m64,
            input_digest: query_digest(input),
        },
        output,
        &bound(n64, m64, horizon, u64::from(max_intervals)),
        peak,
    )
}
