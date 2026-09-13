//! Frozen Model IR v1 computation graph definition.

use core::fmt;

use fss_core::{ContentDigest, Generation};

use crate::canonical::compute_model_ir_digest;
use crate::error::ModelIrError;
use crate::node::GraphNode;
use crate::port::TensorPort;
use crate::validator::GraphValidator;

/// Pinned, frozen specification version for Model IR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ModelIrVersion {
    /// Version 1 of the Model Operator IR.
    V1,
    /// Unsupported or future Model Operator IR version.
    Unsupported(u32),
}

impl ModelIrVersion {
    /// Returns the numerical version tag.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::V1 => 1,
            Self::Unsupported(v) => v,
        }
    }

    /// Resolves a `ModelIrVersion` from a numerical version tag.
    ///
    /// # Errors
    /// Returns [`ModelIrError::VersionMismatch`] if the version is not supported.
    pub fn from_u32(version: u32) -> Result<Self, ModelIrError> {
        match version {
            1 => Ok(Self::V1),
            other => Err(ModelIrError::VersionMismatch {
                expected: 1,
                actual: other,
            }),
        }
    }

    /// Constructs an explicit unsupported version tag for compatibility validation.
    ///
    /// # Errors
    /// Returns [`ModelIrError::InvalidAttribute`] if `version == 1`.
    pub fn unsupported(version: u32) -> Result<Self, ModelIrError> {
        if version == 1 {
            return Err(ModelIrError::InvalidAttribute {
                node_id: "version".to_string(),
                attr_name: "version".to_string(),
                reason: "version 1 is supported (V1) and cannot be constructed as unsupported"
                    .to_string(),
            });
        }
        Ok(Self::Unsupported(version))
    }

    /// Returns `true` if this version is supported by the v1 runtime.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::V1)
    }
}

impl fmt::Display for ModelIrVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1 => write!(f, "v1"),
            Self::Unsupported(v) => write!(f, "unsupported_v{v}"),
        }
    }
}

/// A complete, self-contained Model IR computation graph.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelIrGraph {
    id: String,
    version: ModelIrVersion,
    generation: Generation,
    inputs: Vec<TensorPort>,
    outputs: Vec<TensorPort>,
    nodes: Vec<GraphNode>,
}

impl ModelIrGraph {
    /// Constructs a new `ModelIrGraph` without performing full topological validation.
    ///
    /// Call [`validate`](Self::validate) or [`new_validated`](Self::new_validated)
    /// to run the comprehensive validation suite.
    ///
    /// # Errors
    /// Returns [`ModelIrError::InvalidAttribute`] if `id` is empty.
    pub fn new(
        id: impl Into<String>,
        version: ModelIrVersion,
        generation: Generation,
        inputs: Vec<TensorPort>,
        outputs: Vec<TensorPort>,
        nodes: Vec<GraphNode>,
    ) -> Result<Self, ModelIrError> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(ModelIrError::InvalidAttribute {
                node_id: "graph".to_string(),
                attr_name: "id".to_string(),
                reason: "graph ID cannot be empty".to_string(),
            });
        }
        Ok(Self {
            id,
            version,
            generation,
            inputs,
            outputs,
            nodes,
        })
    }

    /// Constructs a new `ModelIrGraph` and immediately validates all topological and semantic constraints.
    ///
    /// # Errors
    /// Returns any [`ModelIrError`] emitted by [`GraphValidator::validate`].
    pub fn new_validated(
        id: impl Into<String>,
        version: ModelIrVersion,
        generation: Generation,
        inputs: Vec<TensorPort>,
        outputs: Vec<TensorPort>,
        nodes: Vec<GraphNode>,
    ) -> Result<Self, ModelIrError> {
        let graph = Self::new(id, version, generation, inputs, outputs, nodes)?;
        GraphValidator::validate(&graph)?;
        Ok(graph)
    }

    /// Returns a new builder for constructing a `ModelIrGraph`.
    #[must_use]
    pub fn builder(id: impl Into<String>, generation: Generation) -> ModelIrGraphBuilder {
        ModelIrGraphBuilder::new(id, generation)
    }

    /// Returns the unique graph identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the Model IR version of this graph.
    #[must_use]
    pub fn version(&self) -> ModelIrVersion {
        self.version
    }

    /// Returns the model generation this graph belongs to.
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.generation
    }

    /// Returns the declared input tensor ports.
    #[must_use]
    pub fn inputs(&self) -> &[TensorPort] {
        &self.inputs
    }

    /// Returns the declared output tensor ports.
    #[must_use]
    pub fn outputs(&self) -> &[TensorPort] {
        &self.outputs
    }

    /// Returns the computation nodes of the graph.
    #[must_use]
    pub fn nodes(&self) -> &[GraphNode] {
        &self.nodes
    }

    /// Returns the number of computation nodes in the graph.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the number of inputs to the graph.
    #[must_use]
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    /// Returns the number of outputs from the graph.
    #[must_use]
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }

    /// Looks up a computation node by its unique identifier.
    #[must_use]
    pub fn find_node(&self, id: &str) -> Option<&GraphNode> {
        self.nodes.iter().find(|n| n.id() == id)
    }

    /// Looks up an input tensor port by name.
    #[must_use]
    pub fn find_input(&self, name: &str) -> Option<&TensorPort> {
        self.inputs.iter().find(|p| p.name() == name)
    }

    /// Looks up an output tensor port by name.
    #[must_use]
    pub fn find_output(&self, name: &str) -> Option<&TensorPort> {
        self.outputs.iter().find(|p| p.name() == name)
    }

    /// Validates the graph topology, operator admissions, dtype and shape compatibility,
    /// cycle freedom, and generation isolation.
    ///
    /// # Errors
    /// Returns [`ModelIrError`] on any validation failure.
    pub fn validate(&self) -> Result<(), ModelIrError> {
        GraphValidator::validate(self)
    }

    /// Computes the deterministic canonical content digest for this graph under `fss.model_ir.v1`.
    ///
    /// # Errors
    /// Returns [`ModelIrError`] if digest computation encounters arithmetic overflow.
    pub fn content_digest(&self) -> Result<ContentDigest, ModelIrError> {
        self.validate()?;
        compute_model_ir_digest(self)
    }
}

/// Builder for constructing [`ModelIrGraph`] instances.
#[derive(Debug, Clone)]
pub struct ModelIrGraphBuilder {
    id: String,
    version: ModelIrVersion,
    generation: Generation,
    inputs: Vec<TensorPort>,
    outputs: Vec<TensorPort>,
    nodes: Vec<GraphNode>,
}

impl ModelIrGraphBuilder {
    /// Creates a new builder with the given ID and model generation.
    #[must_use]
    pub fn new(id: impl Into<String>, generation: Generation) -> Self {
        Self {
            id: id.into(),
            version: ModelIrVersion::V1,
            generation,
            inputs: Vec::new(),
            outputs: Vec::new(),
            nodes: Vec::new(),
        }
    }

    /// Sets the IR version (defaults to V1).
    #[must_use]
    pub fn version(mut self, version: ModelIrVersion) -> Self {
        self.version = version;
        self
    }

    /// Adds a declared input tensor port.
    #[must_use]
    pub fn add_input(mut self, port: TensorPort) -> Self {
        self.inputs.push(port);
        self
    }

    /// Adds multiple declared input tensor ports.
    #[must_use]
    pub fn with_inputs(mut self, ports: impl IntoIterator<Item = TensorPort>) -> Self {
        self.inputs.extend(ports);
        self
    }

    /// Adds a declared output tensor port.
    #[must_use]
    pub fn add_output(mut self, port: TensorPort) -> Self {
        self.outputs.push(port);
        self
    }

    /// Adds multiple declared output tensor ports.
    #[must_use]
    pub fn with_outputs(mut self, ports: impl IntoIterator<Item = TensorPort>) -> Self {
        self.outputs.extend(ports);
        self
    }

    /// Adds a computation node to the graph.
    #[must_use]
    pub fn add_node(mut self, node: GraphNode) -> Self {
        self.nodes.push(node);
        self
    }

    /// Adds multiple computation nodes to the graph.
    #[must_use]
    pub fn with_nodes(mut self, nodes: impl IntoIterator<Item = GraphNode>) -> Self {
        self.nodes.extend(nodes);
        self
    }

    /// Constructs the graph without performing full topological validation.
    ///
    /// # Errors
    /// Returns [`ModelIrError::InvalidAttribute`] if `id` is empty.
    pub fn build(self) -> Result<ModelIrGraph, ModelIrError> {
        ModelIrGraph::new(
            self.id,
            self.version,
            self.generation,
            self.inputs,
            self.outputs,
            self.nodes,
        )
    }

    /// Constructs the graph and executes full validation.
    ///
    /// # Errors
    /// Returns any [`ModelIrError`] emitted by [`GraphValidator::validate`].
    pub fn build_and_validate(self) -> Result<ModelIrGraph, ModelIrError> {
        let graph = self.build()?;
        GraphValidator::validate(&graph)?;
        Ok(graph)
    }
}
