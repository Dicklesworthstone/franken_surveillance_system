//! Closed, versioned operator set with stable operator identifiers.

use core::fmt;

use crate::error::ModelIrError;

/// Stable, closed set of first-party model operators for Model IR v1.
///
/// Every operator has a canonical `OP-...-001` identifier that is never renumbered.
/// The set is closed; unadmitted operators must be rejected by the graph validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OpCode {
    /// Elementwise addition: A + B (OP-ADD-001).
    Add,
    /// Elementwise subtraction: A - B (OP-SUB-001).
    Sub,
    /// Elementwise multiplication: A * B (OP-MUL-001).
    Mul,
    /// Elementwise division: A / B (OP-DIV-001).
    Div,
    /// Rectified linear unit activation (OP-RELU-001).
    Relu,
    /// Gaussian error linear unit activation (OP-GELU-001).
    Gelu,
    /// Sigmoid linear unit / Swish activation (OP-SILU-001).
    Silu,
    /// Logistic sigmoid activation (OP-SIGMOID-001).
    Sigmoid,
    /// Hyperbolic tangent activation (OP-TANH-001).
    Tanh,
    /// Matrix multiplication / batched GEMM (OP-MATMUL-001).
    MatMul,
    /// Tensor view reshaping with element-count preservation (OP-RESHAPE-001).
    Reshape,
    /// Axis permutation (OP-TRANSPOSE-001).
    Transpose,
    /// Removal of dimensions of size 1 (OP-SQUEEZE-001).
    Squeeze,
    /// Insertion of dimensions of size 1 (OP-UNSQUEEZE-001).
    Unsqueeze,
    /// Concatenation of tensors along a specified axis (OP-CONCAT-001).
    Concat,
    /// Sub-tensor slicing along specified axes (OP-SLICE-001).
    Slice,
    /// Layer normalization with mean and variance scaling (OP-LAYERNORM-001).
    LayerNorm,
    /// Root mean square normalization (OP-RMSNORM-001).
    RMSNorm,
    /// Softmax normalized exponential over a specified axis (OP-SOFTMAX-001).
    Softmax,
    /// 2D spatial convolution (OP-CONV2D-001).
    Conv2d,
    /// 2D spatial maximum pooling (OP-MAXPOOL2D-001).
    MaxPool2d,
    /// Lookup table embedding (OP-EMBEDDING-001).
    Embedding,
}

impl OpCode {
    /// Returns the stable, normative identifier for this operator.
    #[must_use]
    pub const fn stable_id(&self) -> &'static str {
        match self {
            Self::Add => "OP-ADD-001",
            Self::Sub => "OP-SUB-001",
            Self::Mul => "OP-MUL-001",
            Self::Div => "OP-DIV-001",
            Self::Relu => "OP-RELU-001",
            Self::Gelu => "OP-GELU-001",
            Self::Silu => "OP-SILU-001",
            Self::Sigmoid => "OP-SIGMOID-001",
            Self::Tanh => "OP-TANH-001",
            Self::MatMul => "OP-MATMUL-001",
            Self::Reshape => "OP-RESHAPE-001",
            Self::Transpose => "OP-TRANSPOSE-001",
            Self::Squeeze => "OP-SQUEEZE-001",
            Self::Unsqueeze => "OP-UNSQUEEZE-001",
            Self::Concat => "OP-CONCAT-001",
            Self::Slice => "OP-SLICE-001",
            Self::LayerNorm => "OP-LAYERNORM-001",
            Self::RMSNorm => "OP-RMSNORM-001",
            Self::Softmax => "OP-SOFTMAX-001",
            Self::Conv2d => "OP-CONV2D-001",
            Self::MaxPool2d => "OP-MAXPOOL2D-001",
            Self::Embedding => "OP-EMBEDDING-001",
        }
    }

    /// Returns the canonical human-readable name of this operator.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Sub => "sub",
            Self::Mul => "mul",
            Self::Div => "div",
            Self::Relu => "relu",
            Self::Gelu => "gelu",
            Self::Silu => "silu",
            Self::Sigmoid => "sigmoid",
            Self::Tanh => "tanh",
            Self::MatMul => "matmul",
            Self::Reshape => "reshape",
            Self::Transpose => "transpose",
            Self::Squeeze => "squeeze",
            Self::Unsqueeze => "unsqueeze",
            Self::Concat => "concat",
            Self::Slice => "slice",
            Self::LayerNorm => "layer_norm",
            Self::RMSNorm => "rms_norm",
            Self::Softmax => "softmax",
            Self::Conv2d => "conv2d",
            Self::MaxPool2d => "max_pool2d",
            Self::Embedding => "embedding",
        }
    }

    /// Resolves an `OpCode` from its stable `OP-...-001` identifier.
    ///
    /// # Errors
    /// Returns [`ModelIrError::UnknownOperator`] if the identifier is not recognized.
    pub fn from_stable_id(id: &str) -> Result<Self, ModelIrError> {
        match id {
            "OP-ADD-001" => Ok(Self::Add),
            "OP-SUB-001" => Ok(Self::Sub),
            "OP-MUL-001" => Ok(Self::Mul),
            "OP-DIV-001" => Ok(Self::Div),
            "OP-RELU-001" => Ok(Self::Relu),
            "OP-GELU-001" => Ok(Self::Gelu),
            "OP-SILU-001" => Ok(Self::Silu),
            "OP-SIGMOID-001" => Ok(Self::Sigmoid),
            "OP-TANH-001" => Ok(Self::Tanh),
            "OP-MATMUL-001" => Ok(Self::MatMul),
            "OP-RESHAPE-001" => Ok(Self::Reshape),
            "OP-TRANSPOSE-001" => Ok(Self::Transpose),
            "OP-SQUEEZE-001" => Ok(Self::Squeeze),
            "OP-UNSQUEEZE-001" => Ok(Self::Unsqueeze),
            "OP-CONCAT-001" => Ok(Self::Concat),
            "OP-SLICE-001" => Ok(Self::Slice),
            "OP-LAYERNORM-001" => Ok(Self::LayerNorm),
            "OP-RMSNORM-001" => Ok(Self::RMSNorm),
            "OP-SOFTMAX-001" => Ok(Self::Softmax),
            "OP-CONV2D-001" => Ok(Self::Conv2d),
            "OP-MAXPOOL2D-001" => Ok(Self::MaxPool2d),
            "OP-EMBEDDING-001" => Ok(Self::Embedding),
            other => Err(ModelIrError::UnknownOperator {
                op_id: other.to_string(),
            }),
        }
    }

    /// Resolves an `OpCode` from its canonical name.
    ///
    /// # Errors
    /// Returns [`ModelIrError::UnknownOperator`] if the name is not recognized.
    pub fn from_name(name: &str) -> Result<Self, ModelIrError> {
        match name {
            "add" => Ok(Self::Add),
            "sub" => Ok(Self::Sub),
            "mul" => Ok(Self::Mul),
            "div" => Ok(Self::Div),
            "relu" => Ok(Self::Relu),
            "gelu" => Ok(Self::Gelu),
            "silu" => Ok(Self::Silu),
            "sigmoid" => Ok(Self::Sigmoid),
            "tanh" => Ok(Self::Tanh),
            "matmul" => Ok(Self::MatMul),
            "reshape" => Ok(Self::Reshape),
            "transpose" => Ok(Self::Transpose),
            "squeeze" => Ok(Self::Squeeze),
            "unsqueeze" => Ok(Self::Unsqueeze),
            "concat" => Ok(Self::Concat),
            "slice" => Ok(Self::Slice),
            "layer_norm" => Ok(Self::LayerNorm),
            "rms_norm" => Ok(Self::RMSNorm),
            "softmax" => Ok(Self::Softmax),
            "conv2d" => Ok(Self::Conv2d),
            "max_pool2d" => Ok(Self::MaxPool2d),
            "embedding" => Ok(Self::Embedding),
            other => Err(ModelIrError::UnknownOperator {
                op_id: other.to_string(),
            }),
        }
    }

    /// Returns an immutable slice of all closed operators admitted in Model IR v1.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Add,
            Self::Sub,
            Self::Mul,
            Self::Div,
            Self::Relu,
            Self::Gelu,
            Self::Silu,
            Self::Sigmoid,
            Self::Tanh,
            Self::MatMul,
            Self::Reshape,
            Self::Transpose,
            Self::Squeeze,
            Self::Unsqueeze,
            Self::Concat,
            Self::Slice,
            Self::LayerNorm,
            Self::RMSNorm,
            Self::Softmax,
            Self::Conv2d,
            Self::MaxPool2d,
            Self::Embedding,
        ]
    }

    /// Returns `true` if `identifier` matches a known stable op ID or canonical name.
    #[must_use]
    pub fn is_admitted(identifier: &str) -> bool {
        Self::from_stable_id(identifier).is_ok() || Self::from_name(identifier).is_ok()
    }
}

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.name(), self.stable_id())
    }
}
