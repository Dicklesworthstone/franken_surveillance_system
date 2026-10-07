//! `ALG-SP-001` (shortest path) and `ALG-MSD-001` (multi-source distance).
//!
//! Both run one Dijkstra over exact `u64` arc lengths in the projection's unit, directed or
//! undirected, with a lexicographic key so that every tie is decided by a registered rule and
//! never by heap or insertion order:
//!
//! * `ALG-SP-001` keys `(distance, hops)`: among shortest paths, fewest arcs. The parent of `v`
//!   is the tail of the smallest-index arc `u -> v` with `key(u) + (w, 1) = key(v)`, which makes
//!   the shortest-path tree unique and acyclic even with zero-length arcs;
//! * `ALG-MSD-001` keys `(distance, source identity, hops)`: every node's nearest source, ties
//!   between equally near sources broken by the smallest source identity.
//!
//! Weights of different meaning cannot mix: the unit is bound into the projection digest. An
//! overflowing distance is `ERR-GRAPH-NUMERIC-OVERFLOW-001`; unreachable nodes are listed.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use fss_core::CanonicalEncoder;

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, checked_add, encode_ids, mul, query_digest, query_encoder,
};
use crate::graph::GraphError;
use crate::weighted::{Orientation, WeightedGraph};

/// `ALG-SP-001` output digest domain (`SCHEMA-DOMAIN-GRAPH-SP-OUTPUT-001`).
pub const SP_OUTPUT_DOMAIN: &str = "fss.graph.sp_output.v1";
/// `ALG-SP-001` decision-path domain (`SCHEMA-DOMAIN-GRAPH-SP-DECISION-PATH-001`).
pub const SP_DECISION_PATH_DOMAIN: &str = "fss.graph.sp_decision_path.v1";
/// `ALG-MSD-001` output digest domain (`SCHEMA-DOMAIN-GRAPH-MSD-OUTPUT-001`).
pub const MSD_OUTPUT_DOMAIN: &str = "fss.graph.msd_output.v1";
/// `ALG-MSD-001` decision-path domain (`SCHEMA-DOMAIN-GRAPH-MSD-DECISION-PATH-001`).
pub const MSD_DECISION_PATH_DOMAIN: &str = "fss.graph.msd_decision_path.v1";

/// Registered identity (`ALG-SP-001`).
pub static SP_IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-SP-001",
    algorithm_name: "shortest_path",
    tie_break_rule: "cost then stable edge/path identity",
    complexity_witness: "heap pushes, pops, and relaxations",
    output_size_witness: "<= |V| path nodes and <= |V| - 1 edges",
    exactness: "exact",
    implementation_id: "fss-graph-algorithms:alg-sp-001:lexicographic-dijkstra:v1",
    tie_break_policy_id: "tie:distance-then-hops-then-smallest-parent-arc:v1",
    policy_id: "graph-policy:directed-or-undirected:simple-strict:nonnegative-arc-length:numeric:u64-exact:checked:unit-bound:v1:tie:distance-then-hops-then-smallest-parent-arc:v1",
    complexity_bound_id: "bound:alg-sp-001:dijkstra-binary-heap:v1",
    output_domain: SP_OUTPUT_DOMAIN,
    decision_path_domain: SP_DECISION_PATH_DOMAIN,
};

/// Registered identity (`ALG-MSD-001`).
pub static MSD_IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-MSD-001",
    algorithm_name: "multi_source_distance",
    tie_break_rule: "distance then source identity",
    complexity_witness: "heap operations and relaxations",
    output_size_witness: "<= |V| distance-source records",
    exactness: "exact",
    implementation_id: "fss-graph-algorithms:alg-msd-001:multi-source-lexicographic-dijkstra:v1",
    tie_break_policy_id: "tie:distance-then-smallest-source-identity-then-hops:v1",
    policy_id: "graph-policy:directed-or-undirected:simple-strict:nonnegative-arc-length:numeric:u64-exact:checked:unit-bound:v1:tie:distance-then-smallest-source-identity-then-hops:v1",
    complexity_bound_id: "bound:alg-msd-001:dijkstra-binary-heap:v1",
    output_domain: MSD_OUTPUT_DOMAIN,
    decision_path_domain: MSD_DECISION_PATH_DOMAIN,
};

/// Adjacency entries one Dijkstra may scan: `m` directed, `2m` undirected.
#[must_use]
pub fn scan_entries(orientation: Orientation, m: u64) -> u64 {
    match orientation {
        Orientation::Directed => m,
        Orientation::Undirected => mul(2, m),
    }
}

/// The registered `ALG-SP-001` bound for `n` nodes and `m` arcs.
#[must_use]
pub fn sp_bound(orientation: Orientation, n: u64, m: u64) -> Vec<BoundRow> {
    let r = scan_entries(orientation, m);
    vec![
        ("node_settles", n),
        ("relaxations", r),
        ("heap_pushes", add(r, 1)),
        ("heap_pops", add(r, 1)),
        ("parent_scans", r),
        (OUTPUT_ENTRIES, mul(3, n)),
    ]
}

/// The registered `ALG-MSD-001` bound for `n` nodes and `m` arcs.
#[must_use]
pub fn msd_bound(orientation: Orientation, n: u64, m: u64) -> Vec<BoundRow> {
    let r = scan_entries(orientation, m);
    vec![
        ("node_settles", n),
        ("relaxations", r),
        ("heap_pushes", add(r, n)),
        ("heap_pops", add(r, n)),
        (OUTPUT_ENTRIES, mul(2, n)),
    ]
}

/// One reachable node of a shortest-path answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistanceRow {
    /// Node identity.
    pub node: String,
    /// Exact shortest distance.
    pub distance: u64,
    /// Fewest arcs among shortest paths.
    pub hops: u64,
    /// Parent on the canonical shortest-path tree (`None` for the source).
    pub parent: Option<String>,
}

/// The canonical answer of `ALG-SP-001`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShortestPathOutput {
    /// Source identity.
    pub source: String,
    /// Every reachable node in ascending identity order.
    pub reachable: Vec<DistanceRow>,
    /// Every unreachable node, ascending.
    pub unreachable: Vec<String>,
    /// With a target: the canonical path from the source (inclusive), or `None` if unreachable.
    pub target: Option<(String, Option<Vec<String>>)>,
}

impl ShortestPathOutput {
    /// The exact distance to `node`, if reachable.
    #[must_use]
    pub fn distance(&self, node: &str) -> Option<u64> {
        self.reachable
            .binary_search_by(|row| row.node.as_str().cmp(node))
            .ok()
            .map(|position| self.reachable[position].distance)
    }
}

impl CertifiedOutput for ShortestPathOutput {
    fn entries(&self) -> u64 {
        let path = self
            .target
            .as_ref()
            .and_then(|(_, path)| path.as_ref())
            .map_or(0, Vec::len);
        (self.reachable.len() + self.unreachable.len() + path) as u64
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.source);
        encoder.u64(self.reachable.len() as u64);
        for row in &self.reachable {
            encoder.text(&row.node);
            encoder.u64(row.distance);
            encoder.u64(row.hops);
            match &row.parent {
                None => encoder.tag(0),
                Some(parent) => {
                    encoder.tag(1);
                    encoder.text(parent);
                }
            }
        }
        encode_ids(encoder, &self.unreachable);
        match &self.target {
            None => encoder.tag(0),
            Some((target, path)) => {
                encoder.tag(1);
                encoder.text(target);
                match path {
                    None => encoder.tag(0),
                    Some(path) => {
                        encoder.tag(1);
                        encode_ids(encoder, path);
                    }
                }
            }
        }
    }
}

/// One reachable node of a multi-source answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NearestRow {
    /// Node identity.
    pub node: String,
    /// Its nearest source (smallest identity among equally near sources).
    pub source: String,
    /// Exact distance from that source.
    pub distance: u64,
    /// Fewest arcs among shortest paths from that source.
    pub hops: u64,
}

/// The canonical answer of `ALG-MSD-001`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiSourceOutput {
    /// Sources, ascending.
    pub sources: Vec<String>,
    /// Every reachable node, ascending.
    pub reachable: Vec<NearestRow>,
    /// Nodes no source reaches, ascending.
    pub unreachable: Vec<String>,
}

impl CertifiedOutput for MultiSourceOutput {
    fn entries(&self) -> u64 {
        (self.reachable.len() + self.unreachable.len()) as u64
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encode_ids(encoder, &self.sources);
        encoder.u64(self.reachable.len() as u64);
        for row in &self.reachable {
            encoder.text(&row.node);
            encoder.text(&row.source);
            encoder.u64(row.distance);
            encoder.u64(row.hops);
        }
        encode_ids(encoder, &self.unreachable);
    }
}

/// `(distance, source rank, hops)`.
type Key = (u64, u32, u64);

/// Settled keys of one lexicographic Dijkstra; `None` for unreachable nodes.
pub(crate) fn lexicographic_dijkstra(
    graph: &WeightedGraph,
    sources: &[u32],
    meter: &mut Meter,
) -> Result<Vec<Option<Key>>, GraphError> {
    let n = graph.node_count();
    let mut best: Vec<Option<Key>> = vec![None; n];
    let mut settled = vec![false; n];
    let mut heap: BinaryHeap<Reverse<(Key, u32)>> = BinaryHeap::new();
    for (rank, &source) in sources.iter().enumerate() {
        let key = (0, rank as u32, 0);
        if best[source as usize].is_none_or(|current| key < current) {
            best[source as usize] = Some(key);
            meter.tick("heap_pushes")?;
            heap.push(Reverse((key, source)));
        }
    }
    while let Some(Reverse((key, node))) = heap.pop() {
        meter.tick("heap_pops")?;
        if settled[node as usize] || best[node as usize] != Some(key) {
            continue;
        }
        settled[node as usize] = true;
        meter.tick("node_settles")?;
        meter.decide(0, u64::from(node), key.0);
        for &arc_index in graph.out_arcs(node) {
            meter.tick("relaxations")?;
            let arc = graph.arc(arc_index);
            let next = match graph.orientation() {
                Orientation::Directed => arc.head,
                Orientation::Undirected => arc.other(node),
            };
            if settled[next as usize] {
                continue;
            }
            let candidate = (
                checked_add(key.0, arc.weight, "path distance")?,
                key.1,
                key.2 + 1,
            );
            if best[next as usize].is_none_or(|current| candidate < current) {
                best[next as usize] = Some(candidate);
                meter.tick("heap_pushes")?;
                heap.push(Reverse((candidate, next)));
            }
        }
    }
    Ok(best)
}

/// Runs `ALG-SP-001` from `source`, optionally reporting the canonical path to `target`.
///
/// # Errors
///
/// [`GraphError::UnknownNode`] for an unknown source or target, [`GraphError::ArithmeticOverflow`]
/// for a distance outside `u64`, and the fail-closed budget and bound errors.
pub fn shortest_paths(
    graph: &WeightedGraph,
    source: &str,
    target: Option<&str>,
    budget: Budget,
) -> Result<CertifiedRun<ShortestPathOutput>, GraphError> {
    let source_index = graph.require(source)?;
    let target_index = target.map(|id| graph.require(id)).transpose()?;
    let n = graph.node_count();
    let mut meter = Meter::new(&SP_IDENTITY, budget);
    let keys = lexicographic_dijkstra(graph, &[source_index], &mut meter)?;
    let mut parent = vec![None::<u32>; n];
    for node in 0..n as u32 {
        let Some(key) = keys[node as usize] else {
            continue;
        };
        if node == source_index {
            continue;
        }
        let mut chosen: Option<(u32, u32)> = None;
        for &arc_index in graph.in_arcs(node) {
            meter.tick("parent_scans")?;
            let arc = graph.arc(arc_index);
            let tail = match graph.orientation() {
                Orientation::Directed => arc.tail,
                Orientation::Undirected => arc.other(node),
            };
            let Some(tail_key) = keys[tail as usize] else {
                continue;
            };
            if tail_key.0.checked_add(arc.weight) == Some(key.0)
                && tail_key.2 + 1 == key.2
                && chosen.is_none_or(|(best_arc, _)| arc_index < best_arc)
            {
                chosen = Some((arc_index, tail));
            }
        }
        let (_, tail) = chosen.ok_or_else(|| {
            GraphError::Inconsistent(format!("{} has no tight parent", graph.id(node)))
        })?;
        parent[node as usize] = Some(tail);
    }
    let mut reachable = Vec::new();
    let mut unreachable = Vec::new();
    for node in 0..n as u32 {
        match keys[node as usize] {
            Some((distance, _, hops)) => reachable.push(DistanceRow {
                node: graph.id(node).to_owned(),
                distance,
                hops,
                parent: parent[node as usize].map(|tail| graph.id(tail).to_owned()),
            }),
            None => unreachable.push(graph.id(node).to_owned()),
        }
    }
    let target_answer = target_index.map(|goal| {
        let path = keys[goal as usize].map(|_| {
            let mut path = vec![goal];
            let mut current = goal;
            while let Some(tail) = parent[current as usize] {
                path.push(tail);
                current = tail;
            }
            path.reverse();
            path.iter().map(|&node| graph.id(node).to_owned()).collect()
        });
        (graph.id(goal).to_owned(), path)
    });
    let output = ShortestPathOutput {
        source: source.to_owned(),
        reachable,
        unreachable,
        target: target_answer,
    };
    let (n64, m64) = (n as u64, graph.arc_count() as u64);
    let mut input = query_encoder(&SP_IDENTITY, graph.digest());
    input.text(source);
    match target {
        None => input.tag(0),
        Some(target) => {
            input.tag(1);
            input.text(target);
        }
    }
    let r = scan_entries(graph.orientation(), m64);
    // keys (24 bytes), settled (1), parent (8) per node, and at most r + 1 heap entries (28).
    let peak = n64 * 33 + 28 * add(r, 1);
    meter.finish(
        &SP_IDENTITY,
        InputShape {
            node_count: n64,
            edge_count: m64,
            input_digest: query_digest(input),
        },
        output,
        &sp_bound(graph.orientation(), n64, m64),
        peak,
    )
}

/// Runs `ALG-MSD-001` from every node of `sources`.
///
/// # Errors
///
/// [`GraphError::PreconditionFailed`] for an empty or duplicated source list,
/// [`GraphError::UnknownNode`] for an unknown source, [`GraphError::ArithmeticOverflow`], and the
/// fail-closed budget and bound errors.
pub fn multi_source_distances(
    graph: &WeightedGraph,
    sources: &[&str],
    budget: Budget,
) -> Result<CertifiedRun<MultiSourceOutput>, GraphError> {
    if sources.is_empty() {
        return Err(GraphError::PreconditionFailed(
            "multi-source distance needs at least one source".to_owned(),
        ));
    }
    let mut indices: Vec<u32> = sources
        .iter()
        .map(|id| graph.require(id))
        .collect::<Result<_, _>>()?;
    indices.sort_unstable();
    if indices.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(GraphError::PreconditionFailed(
            "multi-source distance sources must be distinct".to_owned(),
        ));
    }
    let n = graph.node_count();
    let mut meter = Meter::new(&MSD_IDENTITY, budget);
    let keys = lexicographic_dijkstra(graph, &indices, &mut meter)?;
    let mut reachable = Vec::new();
    let mut unreachable = Vec::new();
    for node in 0..n as u32 {
        match keys[node as usize] {
            Some((distance, rank, hops)) => reachable.push(NearestRow {
                node: graph.id(node).to_owned(),
                source: graph.id(indices[rank as usize]).to_owned(),
                distance,
                hops,
            }),
            None => unreachable.push(graph.id(node).to_owned()),
        }
    }
    let source_ids: Vec<String> = indices
        .iter()
        .map(|&node| graph.id(node).to_owned())
        .collect();
    let mut input = query_encoder(&MSD_IDENTITY, graph.digest());
    encode_ids(&mut input, &source_ids);
    let output = MultiSourceOutput {
        sources: source_ids,
        reachable,
        unreachable,
    };
    let (n64, m64) = (n as u64, graph.arc_count() as u64);
    let r = scan_entries(graph.orientation(), m64);
    let peak = n64 * 25 + 28 * add(r, n64);
    meter.finish(
        &MSD_IDENTITY,
        InputShape {
            node_count: n64,
            edge_count: m64,
            input_digest: query_digest(input),
        },
        output,
        &msd_bound(graph.orientation(), n64, m64),
        peak,
    )
}
