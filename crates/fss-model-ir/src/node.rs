//! Operator computation node within a Model IR graph.

use core::fmt;

use crate::attribute::{AttrValue, AttributeMap};
use crate::error::ModelIrError;
use crate::op::OpCode;

/// A node in the computation graph representing an invocation of an operator.
#[derive(Debug, Clone, PartialEq)]
pub struct GraphNode {
    id: String,
    op: OpCode,
    name: String,
    inputs: Vec<String>,
    outputs: Vec<String>,
    attributes: AttributeMap,
}

impl GraphNode {
    /// Constructs a new validated `GraphNode`.
    ///
    /// # Errors
    /// Returns [`ModelIrError::InvalidAttribute`] if `id` or `name` is empty.
    pub fn new(
        id: impl Into<String>,
        op: OpCode,
        name: impl Into<String>,
        inputs: Vec<String>,
        outputs: Vec<String>,
        attributes: AttributeMap,
    ) -> Result<Self, ModelIrError> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(ModelIrError::InvalidAttribute {
                node_id: "node".to_string(),
                attr_name: "id".to_string(),
                reason: "node ID cannot be empty".to_string(),
            });
        }
        let name = name.into();
        if name.trim().is_empty() {
            return Err(ModelIrError::InvalidAttribute {
                node_id: id.clone(),
                attr_name: "name".to_string(),
                reason: "node name cannot be empty".to_string(),
            });
        }
        Ok(Self {
            id,
            op,
            name,
            inputs,
            outputs,
            attributes,
        })
    }

    /// Returns the unique node identifier within the graph.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the operator code executed by this node.
    #[must_use]
    pub fn op(&self) -> OpCode {
        self.op
    }

    /// Returns the descriptive name of this node.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the input tensor names consumed by this node.
    #[must_use]
    pub fn inputs(&self) -> &[String] {
        &self.inputs
    }

    /// Returns the output tensor names produced by this node.
    #[must_use]
    pub fn outputs(&self) -> &[String] {
        &self.outputs
    }

    /// Returns the attributes map of this node.
    #[must_use]
    pub fn attributes(&self) -> &AttributeMap {
        &self.attributes
    }

    /// Looks up an attribute by name.
    #[must_use]
    pub fn get_attr(&self, name: &str) -> Option<&AttrValue> {
        self.attributes.get(name)
    }
}

impl fmt::Display for GraphNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Node[id={}, op={}, name={}, in=[{}], out=[{}]]",
            self.id,
            self.op,
            self.name,
            self.inputs.join(", "),
            self.outputs.join(", ")
        )
    }
}
