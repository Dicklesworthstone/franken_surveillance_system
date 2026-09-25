//! Brute-force removal oracle for `ALG-BRIDGE-001`.
//!
//! Straight from the definitions, sharing nothing with the optimized search but the canonical
//! edge list: a node is a cut vertex when deleting it increases the number of connected
//! components, an edge is a bridge when deleting it does, and a failure separates from the root
//! exactly the nodes reachable before it and unreachable after it (the failed node itself
//! excluded). `O(n * (n + m))`; meant for certification corpora, never a decision path.

use std::collections::VecDeque;

use crate::bridges::{BridgeOutput, BridgeSeparation, VertexSeparation};
use crate::graph::{GraphError, UndirectedGraph};

struct Oracle<'a> {
    graph: &'a UndirectedGraph,
    adjacency: Vec<Vec<(usize, usize)>>,
}

impl Oracle<'_> {
    /// Reachability from `from` with one node and/or one edge deleted.
    fn reach(&self, from: usize, skip_node: Option<usize>, skip_edge: Option<usize>) -> Vec<bool> {
        let mut seen = vec![false; self.adjacency.len()];
        if skip_node == Some(from) {
            return seen;
        }
        seen[from] = true;
        let mut queue = VecDeque::from([from]);
        while let Some(node) = queue.pop_front() {
            for &(next, edge) in &self.adjacency[node] {
                if Some(edge) == skip_edge || Some(next) == skip_node || seen[next] {
                    continue;
                }
                seen[next] = true;
                queue.push_back(next);
            }
        }
        seen
    }

    fn components(&self, skip_node: Option<usize>, skip_edge: Option<usize>) -> usize {
        let mut assigned = vec![false; self.adjacency.len()];
        let mut count = 0;
        for start in 0..self.adjacency.len() {
            if assigned[start] || Some(start) == skip_node {
                continue;
            }
            count += 1;
            for (node, reached) in self.reach(start, skip_node, skip_edge).iter().enumerate() {
                if *reached {
                    assigned[node] = true;
                }
            }
        }
        count
    }

    fn ids(&self, members: impl Iterator<Item = usize>) -> Vec<String> {
        let mut ids: Vec<String> = members
            .filter_map(|node| u32::try_from(node).ok())
            .map(|node| self.graph.id(node).to_owned())
            .collect();
        ids.sort_unstable();
        ids
    }
}

/// The exact `ALG-BRIDGE-001` answer by exhaustive deletion.
///
/// # Errors
///
/// [`GraphError::UnknownNode`] for a root that is not a node.
pub fn reference_bridges(
    graph: &UndirectedGraph,
    root: Option<&str>,
) -> Result<BridgeOutput, GraphError> {
    let n = graph.node_count();
    let mut adjacency = vec![Vec::new(); n];
    for (edge, &(a, b)) in graph.edges().iter().enumerate() {
        adjacency[a as usize].push((b as usize, edge));
        adjacency[b as usize].push((a as usize, edge));
    }
    let oracle = Oracle { graph, adjacency };
    let base = oracle.components(None, None);
    let articulation_points =
        oracle.ids((0..n).filter(|&node| oracle.components(Some(node), None) > base));
    let bridge_indices: Vec<usize> = (0..graph.edge_count())
        .filter(|&edge| oracle.components(None, Some(edge)) > base)
        .collect();
    let endpoints = |edge: usize| {
        let (a, b) = graph.edges()[edge];
        let (a, b) = (graph.id(a).to_owned(), graph.id(b).to_owned());
        if a <= b { (a, b) } else { (b, a) }
    };
    let mut bridges: Vec<(String, String)> =
        bridge_indices.iter().map(|&edge| endpoints(edge)).collect();
    bridges.sort_unstable();

    let mut output = BridgeOutput {
        root: root.map(str::to_owned),
        articulation_points,
        bridges,
        ..BridgeOutput::default()
    };
    let Some(root_id) = root else {
        return Ok(output);
    };
    let root_node = graph
        .index_of(root_id)
        .ok_or_else(|| GraphError::UnknownNode(root_id.to_owned()))? as usize;
    let before = oracle.reach(root_node, None, None);
    output.unreachable_from_root = oracle.ids((0..n).filter(|&node| !before[node]));
    let lost = |after: &[bool], failed: Option<usize>| {
        oracle.ids((0..n).filter(|&node| before[node] && !after[node] && Some(node) != failed))
    };
    for (node, &reached) in before.iter().enumerate() {
        if node == root_node || !reached {
            continue;
        }
        let separated = lost(&oracle.reach(root_node, Some(node), None), Some(node));
        if !separated.is_empty() {
            output.vertex_separations.push(VertexSeparation {
                node: oracle.ids(std::iter::once(node)).concat(),
                separated,
            });
        }
    }
    output.vertex_separations.sort_unstable();
    for &edge in &bridge_indices {
        let separated = lost(&oracle.reach(root_node, None, Some(edge)), None);
        if !separated.is_empty() {
            output.bridge_separations.push(BridgeSeparation {
                edge: endpoints(edge),
                separated,
            });
        }
    }
    output.bridge_separations.sort_unstable();
    Ok(output)
}
