//! Typed errors for the model operator IR runtime.

use core::fmt;

use fss_core::Generation;
use fss_tensor::{DType, TensorError};

/// Comprehensive typed errors emitted by model IR graph construction, validation, and inference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelIrError {
    /// A cycle was detected in the model IR computation graph.
    CycleDetected {
        /// Node ID where the cycle was detected.
        node_id: String,
        /// Path of node IDs forming the cycle.
        cycle_path: Vec<String>,
    },
    /// A node references an input tensor that is neither a graph input nor produced by any node.
    DanglingInput {
        /// Node ID attempting to consume the tensor.
        node_id: String,
        /// Name of the missing tensor.
        tensor_name: String,
    },
    /// A declared graph output tensor is never produced by any node or graph input.
    DanglingOutput {
        /// Name of the missing output tensor.
        tensor_name: String,
    },
    /// Two nodes in the same graph declare identical node identifiers.
    DuplicateNodeId {
        /// Duplicated node identifier.
        node_id: String,
    },
    /// Multiple nodes claim to produce the same output tensor name.
    DuplicateTensorOutput {
        /// Duplicated tensor name.
        tensor_name: String,
        /// First producer node.
        first_node: String,
        /// Second producer node.
        second_node: String,
    },
    /// A tensor data type does not match the expected type for an operator.
    DTypeMismatch {
        /// Node where mismatch occurred.
        node_id: String,
        /// Stable operator ID.
        op_id: &'static str,
        /// Expected data type.
        expected: DType,
        /// Actual data type provided.
        actual: DType,
        /// Name of the offending tensor.
        tensor_name: String,
    },
    /// Tensor dimensions or shapes are incompatible with operator semantics.
    ShapeMismatch {
        /// Node where mismatch occurred.
        node_id: String,
        /// Stable operator ID.
        op_id: &'static str,
        /// Specific reason for shape incompatibility.
        reason: String,
    },
    /// Tensor rank does not match the operator requirement.
    RankMismatch {
        /// Node where mismatch occurred.
        node_id: String,
        /// Stable operator ID.
        op_id: &'static str,
        /// Expected rank.
        expected_rank: usize,
        /// Actual rank provided.
        actual_rank: usize,
        /// Name of the offending tensor.
        tensor_name: String,
    },
    /// An unknown or unadmitted operator identifier was encountered.
    UnknownOperator {
        /// Unknown operator string.
        op_id: String,
    },
    /// The IR version of the graph is incompatible with the expected version.
    VersionMismatch {
        /// Expected IR version.
        expected: u32,
        /// Actual IR version.
        actual: u32,
    },
    /// Tensors from distinct model generations were illegally mixed in the same graph.
    GenerationMismatch {
        /// Expected baseline generation.
        expected: Generation,
        /// Divergent generation found.
        actual: Generation,
        /// Name of the tensor carrying divergent generation.
        tensor_name: String,
    },
    /// Arithmetic overflow occurred during shape, stride, or dimension computation.
    ArithmeticOverflow {
        /// Description of the operation that overflowed.
        operation: &'static str,
    },
    /// An attribute value provided to a node is invalid or out of acceptable range.
    InvalidAttribute {
        /// Node ID owning the attribute.
        node_id: String,
        /// Name of the attribute.
        attr_name: String,
        /// Reason the value was rejected.
        reason: String,
    },
    /// A required operator attribute was missing from the node specification.
    MissingAttribute {
        /// Node ID lacking the attribute.
        node_id: String,
        /// Name of the missing attribute.
        attr_name: String,
    },
    /// Node has an invalid number of inputs or outputs for the operator.
    InvalidPortCount {
        /// Node ID.
        node_id: String,
        /// Stable operator ID.
        op_id: &'static str,
        /// Expected port count description.
        expected: &'static str,
        /// Actual number of ports provided.
        actual: usize,
    },
    /// Graph contains no nodes or no executable paths.
    EmptyGraph,
    /// Underlying tensor core error.
    TensorError(TensorError),
    /// Core infrastructure error.
    CoreError(fss_core::ContractError),
}

impl fmt::Display for ModelIrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CycleDetected {
                node_id,
                cycle_path,
            } => {
                write!(
                    f,
                    "cycle detected at node '{node_id}' along path: {}",
                    cycle_path.join(" -> ")
                )
            }
            Self::DanglingInput {
                node_id,
                tensor_name,
            } => {
                write!(
                    f,
                    "node '{node_id}' references nonexistent input tensor '{tensor_name}'"
                )
            }
            Self::DanglingOutput { tensor_name } => {
                write!(
                    f,
                    "graph output tensor '{tensor_name}' is not produced by any node or graph input"
                )
            }
            Self::DuplicateNodeId { node_id } => {
                write!(f, "duplicate node ID '{node_id}' in model graph")
            }
            Self::DuplicateTensorOutput {
                tensor_name,
                first_node,
                second_node,
            } => {
                write!(
                    f,
                    "tensor '{tensor_name}' output claimed by multiple nodes: '{first_node}' and '{second_node}'"
                )
            }
            Self::DTypeMismatch {
                node_id,
                op_id,
                expected,
                actual,
                tensor_name,
            } => {
                write!(
                    f,
                    "dtype mismatch at node '{node_id}' ({op_id}) on tensor '{tensor_name}': expected {expected}, got {actual}"
                )
            }
            Self::ShapeMismatch {
                node_id,
                op_id,
                reason,
            } => {
                write!(f, "shape mismatch at node '{node_id}' ({op_id}): {reason}")
            }
            Self::RankMismatch {
                node_id,
                op_id,
                expected_rank,
                actual_rank,
                tensor_name,
            } => {
                write!(
                    f,
                    "rank mismatch at node '{node_id}' ({op_id}) on tensor '{tensor_name}': expected {expected_rank}, got {actual_rank}"
                )
            }
            Self::UnknownOperator { op_id } => {
                write!(
                    f,
                    "unknown operator identifier '{op_id}'; operator set is closed and frozen"
                )
            }
            Self::VersionMismatch { expected, actual } => {
                write!(
                    f,
                    "model IR version mismatch: expected v{expected}, got v{actual}"
                )
            }
            Self::GenerationMismatch {
                expected,
                actual,
                tensor_name,
            } => {
                write!(
                    f,
                    "tensor generation mismatch on '{tensor_name}': graph generation is {}, tensor is {}",
                    expected.get(),
                    actual.get()
                )
            }
            Self::ArithmeticOverflow { operation } => {
                write!(f, "arithmetic overflow during {operation}")
            }
            Self::InvalidAttribute {
                node_id,
                attr_name,
                reason,
            } => {
                write!(
                    f,
                    "invalid attribute '{attr_name}' on node '{node_id}': {reason}"
                )
            }
            Self::MissingAttribute { node_id, attr_name } => {
                write!(
                    f,
                    "missing required attribute '{attr_name}' on node '{node_id}'"
                )
            }
            Self::InvalidPortCount {
                node_id,
                op_id,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "invalid port count for node '{node_id}' ({op_id}): expected {expected}, got {actual}"
                )
            }
            Self::EmptyGraph => {
                write!(
                    f,
                    "model IR graph must contain at least one node and one output"
                )
            }
            Self::TensorError(err) => write!(f, "tensor error: {err}"),
            Self::CoreError(err) => write!(f, "core error: {err}"),
        }
    }
}

impl std::error::Error for ModelIrError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TensorError(err) => Some(err),
            Self::CoreError(err) => Some(err),
            _ => None,
        }
    }
}

impl From<TensorError> for ModelIrError {
    fn from(err: TensorError) -> Self {
        Self::TensorError(err)
    }
}

impl From<fss_core::ContractError> for ModelIrError {
    fn from(err: fss_core::ContractError) -> Self {
        Self::CoreError(err)
    }
}
