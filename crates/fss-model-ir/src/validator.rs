//! Comprehensive graph validator for Model IR v1.

use alloc::collections::{BTreeMap, BTreeSet};

use crate::error::ModelIrError;
use crate::graph::{ModelIrGraph, ModelIrVersion};
use crate::node::GraphNode;
use crate::port::TensorPort;
use crate::shape_inference::infer_operator_outputs;

/// Static validator enforcing topological, type, shape, generation, and IR constraints.
pub struct GraphValidator;

impl GraphValidator {
    /// Validates a `ModelIrGraph` against all Model IR v1 rules.
    ///
    /// # Checks Performed
    /// 1. IR version compatibility (`ModelIrVersion::V1`).
    /// 2. Non-empty graph structure (at least one node and one output).
    /// 3. Valid graph identifier.
    /// 4. Model generation uniformity on declared inputs and outputs.
    /// 5. Node ID uniqueness.
    /// 6. Tensor output name uniqueness (no multiple producers or collisions with inputs).
    /// 7. Dangling tensor inputs (all node inputs must be declared or produced).
    /// 8. Dangling graph outputs (all outputs must be declared or produced).
    /// 9. Cycle detection and topological ordering (graph must be a strict DAG).
    /// 10. Node operator validation, port counts, and dtype/shape inference.
    /// 11. Conformance of declared outputs against inferred output types and shapes.
    ///
    /// # Errors
    /// Returns a typed [`ModelIrError`] detailing the exact violation.
    pub fn validate(graph: &ModelIrGraph) -> Result<(), ModelIrError> {
        // 1. IR version compatibility
        if graph.version() != ModelIrVersion::V1 {
            return Err(ModelIrError::VersionMismatch {
                expected: ModelIrVersion::V1.as_u32(),
                actual: graph.version().as_u32(),
            });
        }

        // 2. Non-empty graph
        if graph.nodes().is_empty() || graph.outputs().is_empty() {
            return Err(ModelIrError::EmptyGraph);
        }

        // 3. Valid graph ID
        if graph.id().trim().is_empty() {
            return Err(ModelIrError::InvalidAttribute {
                node_id: "graph".to_string(),
                attr_name: "id".to_string(),
                reason: "graph ID cannot be empty".to_string(),
            });
        }

        // 4. Model generation uniformity
        for input in graph.inputs() {
            if input.generation() != graph.generation() {
                return Err(ModelIrError::GenerationMismatch {
                    expected: graph.generation(),
                    actual: input.generation(),
                    tensor_name: input.name().to_string(),
                });
            }
        }
        for output in graph.outputs() {
            if output.generation() != graph.generation() {
                return Err(ModelIrError::GenerationMismatch {
                    expected: graph.generation(),
                    actual: output.generation(),
                    tensor_name: output.name().to_string(),
                });
            }
        }

        // 5. Node ID uniqueness
        let mut seen_node_ids = BTreeSet::new();
        for node in graph.nodes() {
            if !seen_node_ids.insert(node.id()) {
                return Err(ModelIrError::DuplicateNodeId {
                    node_id: node.id().to_string(),
                });
            }
        }

        // 6. Output tensor uniqueness and collision detection
        let mut tensor_producers: BTreeMap<&str, &str> = BTreeMap::new();
        for input in graph.inputs() {
            if tensor_producers
                .insert(input.name(), "graph_input")
                .is_some()
            {
                return Err(ModelIrError::DuplicateTensorOutput {
                    tensor_name: input.name().to_string(),
                    first_node: "graph_input".to_string(),
                    second_node: "graph_input".to_string(),
                });
            }
        }

        for node in graph.nodes() {
            if node.outputs().is_empty() {
                return Err(ModelIrError::InvalidPortCount {
                    node_id: node.id().to_string(),
                    op_id: node.op().stable_id(),
                    expected: "at least 1 output",
                    actual: 0,
                });
            }
            for out_name in node.outputs() {
                if let Some(&first_producer) = tensor_producers.get(out_name.as_str()) {
                    return Err(ModelIrError::DuplicateTensorOutput {
                        tensor_name: out_name.clone(),
                        first_node: first_producer.to_string(),
                        second_node: node.id().to_string(),
                    });
                }
                tensor_producers.insert(out_name.as_str(), node.id());
            }
        }

        // 7. Dangling inputs on nodes
        for node in graph.nodes() {
            for in_name in node.inputs() {
                if !tensor_producers.contains_key(in_name.as_str()) {
                    return Err(ModelIrError::DanglingInput {
                        node_id: node.id().to_string(),
                        tensor_name: in_name.clone(),
                    });
                }
            }
        }

        // 8. Dangling graph outputs
        for out_port in graph.outputs() {
            if !tensor_producers.contains_key(out_port.name()) {
                return Err(ModelIrError::DanglingOutput {
                    tensor_name: out_port.name().to_string(),
                });
            }
        }

        // 9. Cycle detection and topological sort
        let topo_nodes = Self::topological_sort(graph, &tensor_producers)?;

        // 10. Type and shape inference along topological order
        let mut env: BTreeMap<String, TensorPort> = BTreeMap::new();
        for input in graph.inputs() {
            env.insert(input.name().to_string(), input.clone());
        }

        for node in topo_nodes {
            let mut input_ports = Vec::with_capacity(node.inputs().len());
            for in_name in node.inputs() {
                let port = env
                    .get(in_name)
                    .ok_or_else(|| ModelIrError::DanglingInput {
                        node_id: node.id().to_string(),
                        tensor_name: in_name.clone(),
                    })?;
                input_ports.push(port);
            }

            let output_ports = infer_operator_outputs(
                node.id(),
                node.op(),
                &input_ports,
                node.outputs(),
                node.attributes(),
                graph.generation(),
            )?;

            for out_port in output_ports {
                env.insert(out_port.name().to_string(), out_port);
            }
        }

        // 11. Conformance of declared outputs against inferred ports
        for out_decl in graph.outputs() {
            let inferred =
                env.get(out_decl.name())
                    .ok_or_else(|| ModelIrError::DanglingOutput {
                        tensor_name: out_decl.name().to_string(),
                    })?;

            if inferred.dtype() != out_decl.dtype() {
                return Err(ModelIrError::DTypeMismatch {
                    node_id: "output".to_string(),
                    op_id: "GRAPH-OUTPUT",
                    expected: out_decl.dtype(),
                    actual: inferred.dtype(),
                    tensor_name: out_decl.name().to_string(),
                });
            }

            if inferred.shape() != out_decl.shape() {
                return Err(ModelIrError::ShapeMismatch {
                    node_id: "output".to_string(),
                    op_id: "GRAPH-OUTPUT",
                    reason: format!(
                        "declared output shape {} for '{}' does not match inferred shape {}",
                        out_decl.shape(),
                        out_decl.name(),
                        inferred.shape()
                    ),
                });
            }

            if inferred.generation() != out_decl.generation() {
                return Err(ModelIrError::GenerationMismatch {
                    expected: out_decl.generation(),
                    actual: inferred.generation(),
                    tensor_name: out_decl.name().to_string(),
                });
            }
        }

        Ok(())
    }

    /// Computes a deterministic topological ordering of the computation nodes.
    ///
    /// # Errors
    /// Returns [`ModelIrError::CycleDetected`] if a cycle is encountered.
    pub fn topological_sort<'a>(
        graph: &'a ModelIrGraph,
        producer_map: &BTreeMap<&str, &'a str>,
    ) -> Result<Vec<&'a GraphNode>, ModelIrError> {
        // Detect cycles via DFS with cycle path reconstruction
        let mut state: BTreeMap<&'a str, u8> = BTreeMap::new(); // 0: unvisited, 1: visiting, 2: visited
        let mut path: Vec<&'a str> = Vec::new();
        let mut node_map: BTreeMap<&'a str, &'a GraphNode> = BTreeMap::new();
        for node in graph.nodes() {
            node_map.insert(node.id(), node);
        }

        // Node -> list of predecessor node IDs (dependencies)
        let mut deps: BTreeMap<&'a str, Vec<&'a str>> = BTreeMap::new();
        for node in graph.nodes() {
            let mut node_deps = Vec::new();
            for in_name in node.inputs() {
                if let Some(&producer_id) = producer_map.get(in_name.as_str())
                    && producer_id != "graph_input"
                    && !node_deps.contains(&producer_id)
                {
                    node_deps.push(producer_id);
                }
            }
            node_deps.sort_unstable();
            deps.insert(node.id(), node_deps);
        }

        for node in graph.nodes() {
            if *state.get(node.id()).unwrap_or(&0) == 0 {
                Self::dfs_cycle_check(node.id(), &deps, &mut state, &mut path)?;
            }
        }

        // If acyclic, compute topological order using Kahn's algorithm
        // In-degree = count of predecessor nodes
        let mut in_degrees: BTreeMap<&'a str, usize> = BTreeMap::new();
        let mut dependents: BTreeMap<&'a str, Vec<&'a str>> = BTreeMap::new();

        for node in graph.nodes() {
            in_degrees.insert(node.id(), 0);
            dependents.insert(node.id(), Vec::new());
        }

        for (consumer_id, dep_list) in &deps {
            in_degrees.insert(*consumer_id, dep_list.len());
            for dep_id in dep_list {
                if let Some(consumer_list) = dependents.get_mut(dep_id) {
                    consumer_list.push(*consumer_id);
                }
            }
        }

        // Nodes with 0 in-degree ready to execute
        let mut ready: BTreeSet<&'a str> = BTreeSet::new();
        for (node_id, &deg) in &in_degrees {
            if deg == 0 {
                ready.insert(*node_id);
            }
        }

        let mut topo_order = Vec::with_capacity(graph.nodes().len());
        while let Some(&next_id) = ready.iter().next() {
            ready.remove(next_id);
            if let Some(&node) = node_map.get(next_id) {
                topo_order.push(node);
            }

            if let Some(consumers) = dependents.get(next_id) {
                for consumer_id in consumers {
                    if let Some(deg) = in_degrees.get_mut(consumer_id) {
                        *deg = deg.saturating_sub(1);
                        if *deg == 0 {
                            ready.insert(*consumer_id);
                        }
                    }
                }
            }
        }

        if topo_order.len() != graph.nodes().len() {
            return Err(ModelIrError::CycleDetected {
                node_id: "graph".to_string(),
                cycle_path: vec!["unresolved cyclic dependency".to_string()],
            });
        }

        Ok(topo_order)
    }

    fn dfs_cycle_check<'a>(
        current_id: &'a str,
        deps: &BTreeMap<&'a str, Vec<&'a str>>,
        state: &mut BTreeMap<&'a str, u8>,
        path: &mut Vec<&'a str>,
    ) -> Result<(), ModelIrError> {
        state.insert(current_id, 1);
        path.push(current_id);

        if let Some(predecessors) = deps.get(current_id) {
            for &pred_id in predecessors {
                let pred_state = *state.get(pred_id).unwrap_or(&0);
                if pred_state == 1 {
                    // Back-edge found: pred_id is already on path
                    let cycle_start = path.iter().position(|&x| x == pred_id).unwrap_or(0);
                    let mut cycle_path: Vec<String> = path[cycle_start..]
                        .iter()
                        .map(|s| (*s).to_string())
                        .collect();
                    cycle_path.push(pred_id.to_string());
                    return Err(ModelIrError::CycleDetected {
                        node_id: pred_id.to_string(),
                        cycle_path,
                    });
                }
                if pred_state == 0 {
                    Self::dfs_cycle_check(pred_id, deps, state, path)?;
                }
            }
        }

        path.pop();
        state.insert(current_id, 2);
        Ok(())
    }
}
