//! Canonical immutable undirected simple graph.
//!
//! Nodes carry stable external string identities and are indexed in ascending byte order of those
//! identities; edges are indexed in ascending `(lower, higher)` endpoint index order. Insertion
//! order therefore never reaches an algorithm: two builders fed the same node and edge sets in any
//! order produce byte-identical graphs and the same [`UndirectedGraph::digest`]. Input is strict:
//! an empty, oversized, or control-character identity, a duplicate node, an unknown endpoint, a
//! self-loop, or a parallel edge is refused, never repaired.

use std::fmt;

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::registry::PROJECTION_DIGEST_DOMAIN;

/// Maximum nodes of one projection.
pub const MAX_GRAPH_NODES: usize = 1 << 16;
/// Maximum edges of one projection.
pub const MAX_GRAPH_EDGES: usize = 1 << 20;
/// Maximum byte length of one node identity.
pub const MAX_NODE_ID_LEN: usize = 512;

/// A typed graph input, budget, bound, or consistency failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GraphError {
    /// A node identity is empty, longer than [`MAX_NODE_ID_LEN`], or holds a control character.
    InvalidNodeId(String),
    /// The same node identity was added twice.
    DuplicateNode(String),
    /// An edge or root names a node that was not added.
    UnknownNode(String),
    /// An edge joins a node to itself (the policy is simple).
    SelfLoop(String),
    /// The same undirected edge was added twice (the policy is simple).
    ParallelEdge(String, String),
    /// More than [`MAX_GRAPH_NODES`] nodes or [`MAX_GRAPH_EDGES`] edges.
    TooLarge,
    /// A declared budget dimension ran out before the exact answer was complete.
    BudgetExhausted {
        /// Budget dimension.
        dimension: &'static str,
        /// Declared limit.
        limit: u64,
    },
    /// An observed counter exceeded the registered complexity or output bound.
    ComplexityBoundViolated {
        /// Counter name.
        counter: &'static str,
        /// Observed value.
        observed: u64,
        /// Registered bound for this input.
        bound: u64,
    },
    /// A derived projection answer disagrees with its structural invariant.
    Inconsistent(String),
}

impl GraphError {
    /// Registered stable error identity (`registries/ERRORS.md`).
    #[must_use]
    pub const fn stable_id(&self) -> &'static str {
        match self {
            Self::InvalidNodeId(_)
            | Self::DuplicateNode(_)
            | Self::UnknownNode(_)
            | Self::SelfLoop(_)
            | Self::ParallelEdge(_, _)
            | Self::TooLarge => "ERR-GRAPH-INPUT-INVALID-001",
            Self::BudgetExhausted { .. } => "ERR-GRAPH-BUDGET-EXHAUSTED-001",
            Self::ComplexityBoundViolated { .. } => "ERR-GRAPH-COMPLEXITY-BOUND-001",
            Self::Inconsistent(_) => "ERR-GRAPH-RESULT-INCONSISTENT-001",
        }
    }
}

impl fmt::Display for GraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNodeId(id) => write!(formatter, "invalid node identity {id:?}"),
            Self::DuplicateNode(id) => write!(formatter, "duplicate node {id:?}"),
            Self::UnknownNode(id) => write!(formatter, "unknown node {id:?}"),
            Self::SelfLoop(id) => write!(formatter, "self-loop at {id:?}"),
            Self::ParallelEdge(a, b) => write!(formatter, "parallel edge {a:?} -- {b:?}"),
            Self::TooLarge => formatter.write_str("graph exceeds the node or edge limit"),
            Self::BudgetExhausted { dimension, limit } => {
                write!(formatter, "budget {dimension} exhausted at {limit}")
            }
            Self::ComplexityBoundViolated {
                counter,
                observed,
                bound,
            } => write!(
                formatter,
                "counter {counter} observed {observed} above its registered bound {bound}"
            ),
            Self::Inconsistent(reason) => write!(formatter, "inconsistent result: {reason}"),
        }
    }
}

impl std::error::Error for GraphError {}

fn valid_node_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_NODE_ID_LEN && !id.chars().any(char::is_control)
}

/// Collects nodes and edges in any order; [`GraphBuilder::build`] canonicalizes.
#[derive(Clone, Debug, Default)]
pub struct GraphBuilder {
    nodes: Vec<String>,
    edges: Vec<(String, String)>,
}

impl GraphBuilder {
    /// An empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one node identity.
    pub fn add_node(&mut self, id: impl Into<String>) -> &mut Self {
        self.nodes.push(id.into());
        self
    }

    /// Adds one undirected edge between two node identities.
    pub fn add_edge(&mut self, a: impl Into<String>, b: impl Into<String>) -> &mut Self {
        self.edges.push((a.into(), b.into()));
        self
    }

    /// Validates and canonicalizes the graph.
    ///
    /// # Errors
    ///
    /// Any [`GraphError`] input variant; the first failure in canonical order is reported.
    pub fn build(self) -> Result<UndirectedGraph, GraphError> {
        if self.nodes.len() > MAX_GRAPH_NODES || self.edges.len() > MAX_GRAPH_EDGES {
            return Err(GraphError::TooLarge);
        }
        let mut ids = self.nodes;
        ids.sort_unstable();
        for id in &ids {
            if !valid_node_id(id) {
                return Err(GraphError::InvalidNodeId(id.clone()));
            }
        }
        for pair in ids.windows(2) {
            if pair[0] == pair[1] {
                return Err(GraphError::DuplicateNode(pair[0].clone()));
            }
        }
        let index = |id: &str| -> Result<u32, GraphError> {
            ids.binary_search_by(|probe| probe.as_str().cmp(id))
                .map_err(|_| GraphError::UnknownNode(id.to_owned()))
                .and_then(|position| u32::try_from(position).map_err(|_| GraphError::TooLarge))
        };
        let mut edges = Vec::with_capacity(self.edges.len());
        for (a, b) in &self.edges {
            let (x, y) = (index(a)?, index(b)?);
            if x == y {
                return Err(GraphError::SelfLoop(a.clone()));
            }
            edges.push((x.min(y), x.max(y)));
        }
        edges.sort_unstable();
        for pair in edges.windows(2) {
            if pair[0] == pair[1] {
                let (lo, hi) = pair[0];
                return Err(GraphError::ParallelEdge(
                    ids[lo as usize].clone(),
                    ids[hi as usize].clone(),
                ));
            }
        }
        let n = ids.len();
        let mut degree = vec![0_u32; n + 1];
        for &(lo, hi) in &edges {
            degree[lo as usize + 1] += 1;
            degree[hi as usize + 1] += 1;
        }
        let mut running = 0_u32;
        for slot in &mut degree {
            running += *slot;
            *slot = running;
        }
        let offsets = degree;
        let mut fill: Vec<u32> = offsets[..n].to_vec();
        let mut adjacency = vec![(0_u32, 0_u32); edges.len() * 2];
        for (edge, &(lo, hi)) in edges.iter().enumerate() {
            let edge = u32::try_from(edge).map_err(|_| GraphError::TooLarge)?;
            adjacency[fill[lo as usize] as usize] = (hi, edge);
            fill[lo as usize] += 1;
            adjacency[fill[hi as usize] as usize] = (lo, edge);
            fill[hi as usize] += 1;
        }
        for window in offsets.windows(2) {
            adjacency[window[0] as usize..window[1] as usize].sort_unstable();
        }
        Ok(UndirectedGraph {
            ids,
            edges,
            offsets,
            adjacency,
        })
    }
}

/// An immutable canonical undirected simple graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UndirectedGraph {
    ids: Vec<String>,
    edges: Vec<(u32, u32)>,
    offsets: Vec<u32>,
    adjacency: Vec<(u32, u32)>,
}

impl UndirectedGraph {
    /// Nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.ids.len()
    }

    /// Edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Stable identity of the node at canonical index `node`.
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

    /// Every edge `(lower, higher)` in canonical edge-index order.
    #[must_use]
    pub fn edges(&self) -> &[(u32, u32)] {
        &self.edges
    }

    /// `(neighbour, edge index)` of `node` in ascending neighbour order.
    #[must_use]
    pub fn neighbours(&self, node: u32) -> &[(u32, u32)] {
        let node = node as usize;
        &self.adjacency[self.offsets[node] as usize..self.offsets[node + 1] as usize]
    }

    /// Domain-separated canonical digest of the node identities and edges.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(PROJECTION_DIGEST_DOMAIN);
        encoder.u64(self.ids.len() as u64);
        for id in &self.ids {
            encoder.text(id);
        }
        encoder.u64(self.edges.len() as u64);
        for &(lo, hi) in &self.edges {
            encoder.u64(u64::from(lo));
            encoder.u64(u64::from(hi));
        }
        ContentDigest::sha256(&encoder.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insertion_order_never_reaches_the_canonical_graph() -> Result<(), GraphError> {
        let mut first = GraphBuilder::new();
        first.add_node("c").add_node("a").add_node("b");
        first.add_edge("a", "b").add_edge("c", "b");
        let mut second = GraphBuilder::new();
        second.add_node("b").add_node("c").add_node("a");
        second.add_edge("b", "c").add_edge("b", "a");
        let (first, second) = (first.build()?, second.build()?);
        assert_eq!(first, second);
        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.ids(), ["a", "b", "c"]);
        assert_eq!(first.edges(), [(0, 1), (1, 2)]);
        assert_eq!(first.neighbours(1), [(0, 0), (2, 1)]);
        Ok(())
    }

    #[test]
    fn strict_input_is_refused_not_repaired() {
        type Case<'a> = (Vec<&'a str>, Vec<(&'a str, &'a str)>, &'a str);
        let cases: Vec<Case<'_>> = vec![
            (vec!["a", "a"], vec![], "ERR-GRAPH-INPUT-INVALID-001"),
            (vec![""], vec![], "ERR-GRAPH-INPUT-INVALID-001"),
            (vec!["a\n"], vec![], "ERR-GRAPH-INPUT-INVALID-001"),
            (vec!["a"], vec![("a", "a")], "ERR-GRAPH-INPUT-INVALID-001"),
            (vec!["a"], vec![("a", "z")], "ERR-GRAPH-INPUT-INVALID-001"),
            (
                vec!["a", "b"],
                vec![("a", "b"), ("b", "a")],
                "ERR-GRAPH-INPUT-INVALID-001",
            ),
        ];
        for (nodes, edges, expected) in cases {
            let mut builder = GraphBuilder::new();
            for node in nodes {
                builder.add_node(node);
            }
            for (a, b) in edges {
                builder.add_edge(a, b);
            }
            let result = builder.build();
            assert_eq!(
                result.as_ref().err().map(GraphError::stable_id),
                Some(expected),
                "{result:?}"
            );
        }
    }
}
