//! Canonical immutable weighted graph projection (directed or undirected).
//!
//! The substrate of every weighted or directed registered algorithm. Like [`crate::graph`],
//! nodes carry stable external string identities and are indexed in ascending byte order of
//! those identities, so insertion order never reaches an algorithm and two builders fed the same
//! sets produce byte-identical graphs and the same [`WeightedGraph::digest`].
//!
//! Numeric policy (`numeric:u64-exact:checked:unit-bound:v1`): every node and arc weight is an
//! unsigned 64-bit integer in one declared unit (for example `ns`, `bytes`, `frames`,
//! `capacity:sensor-paths`, `cost:micro-usd`). There are no floats, no NaN, no infinities and no
//! negative weights; every sum an algorithm forms is checked and an overflow is a typed failure,
//! never a wrapped or saturated answer. Two projections in different units never compare equal
//! and their digests differ, so weights of different meaning cannot be mixed silently.
//!
//! Structural policy: simple and strict. A self-loop, a parallel arc (same tail and head; for an
//! undirected graph either orientation), an unknown endpoint, a duplicate node or an invalid
//! identity is refused, never merged or repaired. Directed graphs index arcs in ascending
//! `(tail, head)` order; undirected graphs store each edge once as `(lower, higher)`.

use std::fmt;

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::graph::{GraphError, MAX_GRAPH_EDGES, MAX_GRAPH_NODES, MAX_NODE_ID_LEN};

/// Weighted projection digest domain (`SCHEMA-DOMAIN-GRAPH-WEIGHTED-PROJECTION-001`).
pub const WEIGHTED_PROJECTION_DIGEST_DOMAIN: &str = "fss.graph.weighted_projection.v1";
/// Numeric policy identity shared by every weighted algorithm.
pub const NUMERIC_POLICY_ID: &str = "numeric:u64-exact:checked:unit-bound:v1";
/// Maximum byte length of the declared weight unit.
pub const MAX_UNIT_LEN: usize = 64;

/// Whether arcs are ordered pairs or unordered edges.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Orientation {
    /// Arcs `tail -> head`.
    Directed,
    /// Edges `{lower, higher}` traversable both ways.
    Undirected,
}

impl Orientation {
    /// Stable spelling used in policy identities and canonical bytes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Directed => "directed",
            Self::Undirected => "undirected",
        }
    }
}

impl fmt::Display for Orientation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One canonical arc (or undirected edge with `tail < head`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Arc {
    /// Canonical index of the tail (the lower endpoint of an undirected edge).
    pub tail: u32,
    /// Canonical index of the head (the higher endpoint of an undirected edge).
    pub head: u32,
    /// Weight in the graph's declared unit.
    pub weight: u64,
}

impl Arc {
    /// The endpoint opposite `node` (for an undirected traversal).
    #[must_use]
    pub const fn other(&self, node: u32) -> u32 {
        if self.tail == node {
            self.head
        } else {
            self.tail
        }
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_NODE_ID_LEN && !id.chars().any(char::is_control)
}

fn valid_unit(unit: &str) -> bool {
    !unit.is_empty()
        && unit.len() <= MAX_UNIT_LEN
        && unit
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":_-.".contains(&byte))
}

/// Collects weighted nodes and arcs in any order; [`WeightedGraphBuilder::build`] canonicalizes.
#[derive(Clone, Debug)]
pub struct WeightedGraphBuilder {
    orientation: Orientation,
    unit: String,
    nodes: Vec<(String, u64)>,
    arcs: Vec<(String, String, u64)>,
}

impl WeightedGraphBuilder {
    /// An empty builder for `orientation` with every weight in `unit`.
    #[must_use]
    pub fn new(orientation: Orientation, unit: impl Into<String>) -> Self {
        Self {
            orientation,
            unit: unit.into(),
            nodes: Vec::new(),
            arcs: Vec::new(),
        }
    }

    /// A directed builder.
    #[must_use]
    pub fn directed(unit: impl Into<String>) -> Self {
        Self::new(Orientation::Directed, unit)
    }

    /// An undirected builder.
    #[must_use]
    pub fn undirected(unit: impl Into<String>) -> Self {
        Self::new(Orientation::Undirected, unit)
    }

    /// Adds one node with weight zero.
    pub fn add_node(&mut self, id: impl Into<String>) -> &mut Self {
        self.nodes.push((id.into(), 0));
        self
    }

    /// Adds one node with a weight (a duration, capacity or cost in the declared unit).
    pub fn add_weighted_node(&mut self, id: impl Into<String>, weight: u64) -> &mut Self {
        self.nodes.push((id.into(), weight));
        self
    }

    /// Adds one arc `tail -> head` (an undirected edge for an undirected builder).
    pub fn add_arc(
        &mut self,
        tail: impl Into<String>,
        head: impl Into<String>,
        weight: u64,
    ) -> &mut Self {
        self.arcs.push((tail.into(), head.into(), weight));
        self
    }

    /// Validates and canonicalizes the graph.
    ///
    /// # Errors
    ///
    /// Every [`GraphError`] input variant; [`GraphError::InvalidNodeId`] also names an invalid
    /// unit (prefixed `unit:`). The first failure in canonical order is reported.
    pub fn build(self) -> Result<WeightedGraph, GraphError> {
        if !valid_unit(&self.unit) {
            return Err(GraphError::InvalidNodeId(format!("unit:{}", self.unit)));
        }
        if self.nodes.len() > MAX_GRAPH_NODES || self.arcs.len() > MAX_GRAPH_EDGES {
            return Err(GraphError::TooLarge);
        }
        let mut nodes = self.nodes;
        nodes.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        for (id, _) in &nodes {
            if !valid_id(id) {
                return Err(GraphError::InvalidNodeId(id.clone()));
            }
        }
        for pair in nodes.windows(2) {
            if pair[0].0 == pair[1].0 {
                return Err(GraphError::DuplicateNode(pair[0].0.clone()));
            }
        }
        let (ids, node_weights): (Vec<String>, Vec<u64>) = nodes.into_iter().unzip();
        let index = |id: &str| -> Result<u32, GraphError> {
            ids.binary_search_by(|probe| probe.as_str().cmp(id))
                .map_err(|_| GraphError::UnknownNode(id.to_owned()))
                .and_then(|position| u32::try_from(position).map_err(|_| GraphError::TooLarge))
        };
        let mut arcs = Vec::with_capacity(self.arcs.len());
        for (tail, head, weight) in &self.arcs {
            let (t, h) = (index(tail)?, index(head)?);
            if t == h {
                return Err(GraphError::SelfLoop(tail.clone()));
            }
            let (t, h) = match self.orientation {
                Orientation::Directed => (t, h),
                Orientation::Undirected => (t.min(h), t.max(h)),
            };
            arcs.push(Arc {
                tail: t,
                head: h,
                weight: *weight,
            });
        }
        arcs.sort_unstable();
        for pair in arcs.windows(2) {
            if (pair[0].tail, pair[0].head) == (pair[1].tail, pair[1].head) {
                return Err(GraphError::ParallelEdge(
                    ids[pair[0].tail as usize].clone(),
                    ids[pair[0].head as usize].clone(),
                ));
            }
        }
        let n = ids.len();
        let (out_offsets, out_adj) = adjacency(n, &arcs, self.orientation, true);
        let (in_offsets, in_adj) = adjacency(n, &arcs, self.orientation, false);
        Ok(WeightedGraph {
            orientation: self.orientation,
            unit: self.unit,
            ids,
            node_weights,
            arcs,
            out_offsets,
            out_adj,
            in_offsets,
            in_adj,
        })
    }
}

/// Compressed adjacency of arc indices, each node's list sorted by (neighbour, arc index).
fn adjacency(
    n: usize,
    arcs: &[Arc],
    orientation: Orientation,
    outgoing: bool,
) -> (Vec<u32>, Vec<u32>) {
    let mut lists: Vec<Vec<(u32, u32)>> = vec![Vec::new(); n];
    for (position, arc) in arcs.iter().enumerate() {
        let position = position as u32;
        match orientation {
            Orientation::Directed => {
                if outgoing {
                    lists[arc.tail as usize].push((arc.head, position));
                } else {
                    lists[arc.head as usize].push((arc.tail, position));
                }
            }
            Orientation::Undirected => {
                lists[arc.tail as usize].push((arc.head, position));
                lists[arc.head as usize].push((arc.tail, position));
            }
        }
    }
    let mut offsets = Vec::with_capacity(n + 1);
    let mut flat = Vec::new();
    offsets.push(0_u32);
    for mut list in lists {
        list.sort_unstable();
        flat.extend(list.into_iter().map(|(_, arc)| arc));
        offsets.push(flat.len() as u32);
    }
    (offsets, flat)
}

/// An immutable canonical weighted graph projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WeightedGraph {
    orientation: Orientation,
    unit: String,
    ids: Vec<String>,
    node_weights: Vec<u64>,
    arcs: Vec<Arc>,
    out_offsets: Vec<u32>,
    out_adj: Vec<u32>,
    in_offsets: Vec<u32>,
    in_adj: Vec<u32>,
}

impl WeightedGraph {
    /// Directed or undirected.
    #[must_use]
    pub const fn orientation(&self) -> Orientation {
        self.orientation
    }

    /// The declared weight unit.
    #[must_use]
    pub fn unit(&self) -> &str {
        &self.unit
    }

    /// Nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.ids.len()
    }

    /// Arcs (edges).
    #[must_use]
    pub fn arc_count(&self) -> usize {
        self.arcs.len()
    }

    /// Stable identity of canonical node `node`.
    #[must_use]
    pub fn id(&self, node: u32) -> &str {
        &self.ids[node as usize]
    }

    /// Every node identity in canonical index order.
    #[must_use]
    pub fn ids(&self) -> &[String] {
        &self.ids
    }

    /// Canonical index of `id`, if present.
    #[must_use]
    pub fn index_of(&self, id: &str) -> Option<u32> {
        self.ids
            .binary_search_by(|probe| probe.as_str().cmp(id))
            .ok()
            .and_then(|position| u32::try_from(position).ok())
    }

    /// Canonical index of `id`.
    ///
    /// # Errors
    ///
    /// [`GraphError::UnknownNode`] when absent.
    pub fn require(&self, id: &str) -> Result<u32, GraphError> {
        self.index_of(id)
            .ok_or_else(|| GraphError::UnknownNode(id.to_owned()))
    }

    /// Weight of canonical node `node`.
    #[must_use]
    pub fn node_weight(&self, node: u32) -> u64 {
        self.node_weights[node as usize]
    }

    /// Every arc in canonical arc-index order.
    #[must_use]
    pub fn arcs(&self) -> &[Arc] {
        &self.arcs
    }

    /// Arc `arc`.
    #[must_use]
    pub fn arc(&self, arc: u32) -> Arc {
        self.arcs[arc as usize]
    }

    /// Indices of arcs leaving `node` (every incident edge when undirected), sorted by
    /// (neighbour, arc index).
    #[must_use]
    pub fn out_arcs(&self, node: u32) -> &[u32] {
        let node = node as usize;
        &self.out_adj[self.out_offsets[node] as usize..self.out_offsets[node + 1] as usize]
    }

    /// Indices of arcs entering `node` (every incident edge when undirected), sorted by
    /// (neighbour, arc index).
    #[must_use]
    pub fn in_arcs(&self, node: u32) -> &[u32] {
        let node = node as usize;
        &self.in_adj[self.in_offsets[node] as usize..self.in_offsets[node + 1] as usize]
    }

    /// Canonical index of the arc `tail -> head` (either orientation when undirected).
    #[must_use]
    pub fn find_arc(&self, tail: u32, head: u32) -> Option<u32> {
        let (t, h) = match self.orientation {
            Orientation::Directed => (tail, head),
            Orientation::Undirected => (tail.min(head), tail.max(head)),
        };
        self.arcs
            .binary_search_by(|arc| (arc.tail, arc.head).cmp(&(t, h)))
            .ok()
            .map(|position| position as u32)
    }

    /// Identity pair of arc `arc`.
    #[must_use]
    pub fn arc_ids(&self, arc: u32) -> (String, String) {
        let arc = self.arcs[arc as usize];
        (self.id(arc.tail).to_owned(), self.id(arc.head).to_owned())
    }

    /// Sum of every arc weight, or `None` on overflow.
    #[must_use]
    pub fn total_arc_weight(&self) -> Option<u64> {
        self.arcs
            .iter()
            .try_fold(0_u64, |sum, arc| sum.checked_add(arc.weight))
    }

    /// Sum of every node weight, or `None` on overflow.
    #[must_use]
    pub fn total_node_weight(&self) -> Option<u64> {
        self.node_weights
            .iter()
            .try_fold(0_u64, |sum, &weight| sum.checked_add(weight))
    }

    /// Requires `orientation`.
    ///
    /// # Errors
    ///
    /// [`GraphError::PreconditionFailed`] naming the required orientation.
    pub fn require_orientation(&self, orientation: Orientation) -> Result<(), GraphError> {
        if self.orientation == orientation {
            Ok(())
        } else {
            Err(GraphError::PreconditionFailed(format!(
                "the algorithm requires a {orientation} projection, not {}",
                self.orientation
            )))
        }
    }

    /// The same graph with every arc reversed (identity for an undirected graph).
    #[must_use]
    pub fn reversed(&self) -> Self {
        if self.orientation == Orientation::Undirected {
            return self.clone();
        }
        let mut builder = WeightedGraphBuilder::directed(self.unit.clone());
        for (id, &weight) in self.ids.iter().zip(&self.node_weights) {
            builder.add_weighted_node(id.clone(), weight);
        }
        for arc in &self.arcs {
            builder.add_arc(
                self.id(arc.head).to_owned(),
                self.id(arc.tail).to_owned(),
                arc.weight,
            );
        }
        // Reversal of a valid simple directed graph is a valid simple directed graph.
        builder.build().unwrap_or_else(|_| self.clone())
    }

    /// Domain-separated canonical digest of orientation, unit, numeric policy, nodes with their
    /// weights, and arcs with theirs.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(WEIGHTED_PROJECTION_DIGEST_DOMAIN);
        encoder.text(self.orientation.as_str());
        encoder.text(&self.unit);
        encoder.text(NUMERIC_POLICY_ID);
        encoder.u64(self.ids.len() as u64);
        for (id, &weight) in self.ids.iter().zip(&self.node_weights) {
            encoder.text(id);
            encoder.u64(weight);
        }
        encoder.u64(self.arcs.len() as u64);
        for arc in &self.arcs {
            encoder.u64(u64::from(arc.tail));
            encoder.u64(u64::from(arc.head));
            encoder.u64(arc.weight);
        }
        ContentDigest::sha256(&encoder.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insertion_order_never_reaches_the_canonical_graph() -> Result<(), GraphError> {
        let mut first = WeightedGraphBuilder::directed("ns");
        first.add_node("c").add_node("a").add_weighted_node("b", 7);
        first
            .add_arc("a", "b", 3)
            .add_arc("c", "b", 1)
            .add_arc("b", "a", 2);
        let mut second = WeightedGraphBuilder::directed("ns");
        second.add_weighted_node("b", 7).add_node("c").add_node("a");
        second
            .add_arc("b", "a", 2)
            .add_arc("c", "b", 1)
            .add_arc("a", "b", 3);
        let (first, second) = (first.build()?, second.build()?);
        assert_eq!(first, second);
        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.ids(), ["a", "b", "c"]);
        assert_eq!(first.out_arcs(1), [1]);
        assert_eq!(first.in_arcs(1), [0, 2]);
        assert_eq!(first.find_arc(2, 1), Some(2));
        assert_eq!(first.find_arc(1, 2), None);
        Ok(())
    }

    #[test]
    fn unit_and_orientation_are_bound_into_the_digest() -> Result<(), GraphError> {
        let build = |orientation, unit: &str| {
            let mut builder = WeightedGraphBuilder::new(orientation, unit);
            builder.add_node("a").add_node("b").add_arc("a", "b", 1);
            builder.build()
        };
        let base = build(Orientation::Directed, "ns")?.digest();
        assert_ne!(base, build(Orientation::Directed, "bytes")?.digest());
        assert_ne!(base, build(Orientation::Undirected, "ns")?.digest());
        Ok(())
    }

    #[test]
    fn strict_input_is_refused_not_repaired() {
        type Case<'a> = (Orientation, &'a str, Vec<&'a str>, Vec<(&'a str, &'a str)>);
        let cases: Vec<Case<'_>> = vec![
            (Orientation::Directed, "ns", vec!["a", "a"], vec![]),
            (Orientation::Directed, "", vec!["a"], vec![]),
            (Orientation::Directed, "n s", vec!["a"], vec![]),
            (Orientation::Directed, "ns", vec!["a"], vec![("a", "a")]),
            (Orientation::Directed, "ns", vec!["a"], vec![("a", "z")]),
            (
                Orientation::Directed,
                "ns",
                vec!["a", "b"],
                vec![("a", "b"), ("a", "b")],
            ),
            (
                Orientation::Undirected,
                "ns",
                vec!["a", "b"],
                vec![("a", "b"), ("b", "a")],
            ),
        ];
        for (orientation, unit, nodes, arcs) in cases {
            let mut builder = WeightedGraphBuilder::new(orientation, unit);
            for node in nodes {
                builder.add_node(node);
            }
            for (tail, head) in arcs {
                builder.add_arc(tail, head, 1);
            }
            let result = builder.build();
            assert_eq!(
                result.as_ref().err().map(GraphError::stable_id),
                Some("ERR-GRAPH-INPUT-INVALID-001"),
                "{result:?}"
            );
        }
        let mut antiparallel = WeightedGraphBuilder::directed("ns");
        antiparallel
            .add_node("a")
            .add_node("b")
            .add_arc("a", "b", 1)
            .add_arc("b", "a", 1);
        assert!(antiparallel.build().is_ok());
    }
}
