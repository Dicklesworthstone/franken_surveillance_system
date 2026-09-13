//! Closed, versioned operator set with stable operator identifiers and pinned attribute schemas.

use core::fmt;

use fss_core::{ContentDigest, DigestAlgorithm, Sha256Hasher};

use crate::error::ModelIrError;

/// Domain tag for canonical operator table freeze digest computation.
pub const OPERATOR_TABLE_DIGEST_DOMAIN: &[u8] = b"fss.model_ir.operator_table.v1\0";

/// Pinned canonical freeze digest covering all 22 operators and their attribute schemas.
///
/// Any modification to operator IDs, names, or attribute schemas alters this digest
/// and requires an explicit IR generation bump.
pub const OPERATOR_TABLE_FREEZE_DIGEST: &str =
    "sha256:1ec9e87669ff631aacb26ba6b23a38db7280e6e05595e75cf06b56f03fd59bf0";

/// Stable baseline operator identifiers for Model IR v1.
///
/// Identifiers must remain immutable, monotonic, and match normative registrations.
pub const OPERATOR_BASELINE_IDS: &[&str] = &[
    "OP-ADD-001",
    "OP-SUB-001",
    "OP-MUL-001",
    "OP-DIV-001",
    "OP-RELU-001",
    "OP-GELU-001",
    "OP-SILU-001",
    "OP-SIGMOID-001",
    "OP-TANH-001",
    "OP-MATMUL-001",
    "OP-RESHAPE-001",
    "OP-TRANSPOSE-001",
    "OP-SQUEEZE-001",
    "OP-UNSQUEEZE-001",
    "OP-CONCAT-001",
    "OP-SLICE-001",
    "OP-LAYERNORM-001",
    "OP-RMSNORM-001",
    "OP-SOFTMAX-001",
    "OP-CONV2D-001",
    "OP-MAXPOOL2D-001",
    "OP-EMBEDDING-001",
];

/// Tombstoned operator identifiers that must never be resurrected or reused.
pub const OPERATOR_TOMBSTONES: &[&str] = &[];

/// Normative metadata specification for a closed first-party model operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorSpec {
    /// Associated enumeration opcode.
    pub opcode: OpCode,
    /// Normative stable identifier (`OP-...-001`).
    pub stable_id: &'static str,
    /// Canonical human-readable name.
    pub name: &'static str,
    /// Strictly admitted attribute names (empty slice means operator rejects all attributes).
    pub allowed_attributes: &'static [&'static str],
}

/// Normative table of all 22 operators in Model IR v1 with their admitted attribute schemas.
pub const OPERATOR_SPECS: &[OperatorSpec] = &[
    OperatorSpec {
        opcode: OpCode::Add,
        stable_id: "OP-ADD-001",
        name: "add",
        allowed_attributes: &[],
    },
    OperatorSpec {
        opcode: OpCode::Sub,
        stable_id: "OP-SUB-001",
        name: "sub",
        allowed_attributes: &[],
    },
    OperatorSpec {
        opcode: OpCode::Mul,
        stable_id: "OP-MUL-001",
        name: "mul",
        allowed_attributes: &[],
    },
    OperatorSpec {
        opcode: OpCode::Div,
        stable_id: "OP-DIV-001",
        name: "div",
        allowed_attributes: &[],
    },
    OperatorSpec {
        opcode: OpCode::Relu,
        stable_id: "OP-RELU-001",
        name: "relu",
        allowed_attributes: &[],
    },
    OperatorSpec {
        opcode: OpCode::Gelu,
        stable_id: "OP-GELU-001",
        name: "gelu",
        allowed_attributes: &["approximate"],
    },
    OperatorSpec {
        opcode: OpCode::Silu,
        stable_id: "OP-SILU-001",
        name: "silu",
        allowed_attributes: &[],
    },
    OperatorSpec {
        opcode: OpCode::Sigmoid,
        stable_id: "OP-SIGMOID-001",
        name: "sigmoid",
        allowed_attributes: &[],
    },
    OperatorSpec {
        opcode: OpCode::Tanh,
        stable_id: "OP-TANH-001",
        name: "tanh",
        allowed_attributes: &[],
    },
    OperatorSpec {
        opcode: OpCode::MatMul,
        stable_id: "OP-MATMUL-001",
        name: "matmul",
        allowed_attributes: &[],
    },
    OperatorSpec {
        opcode: OpCode::Reshape,
        stable_id: "OP-RESHAPE-001",
        name: "reshape",
        allowed_attributes: &["allowzero", "shape"],
    },
    OperatorSpec {
        opcode: OpCode::Transpose,
        stable_id: "OP-TRANSPOSE-001",
        name: "transpose",
        allowed_attributes: &["permutation"],
    },
    OperatorSpec {
        opcode: OpCode::Squeeze,
        stable_id: "OP-SQUEEZE-001",
        name: "squeeze",
        allowed_attributes: &["axes"],
    },
    OperatorSpec {
        opcode: OpCode::Unsqueeze,
        stable_id: "OP-UNSQUEEZE-001",
        name: "unsqueeze",
        allowed_attributes: &["axes"],
    },
    OperatorSpec {
        opcode: OpCode::Concat,
        stable_id: "OP-CONCAT-001",
        name: "concat",
        allowed_attributes: &["axis"],
    },
    OperatorSpec {
        opcode: OpCode::Slice,
        stable_id: "OP-SLICE-001",
        name: "slice",
        allowed_attributes: &["axes", "ends", "starts", "steps"],
    },
    OperatorSpec {
        opcode: OpCode::LayerNorm,
        stable_id: "OP-LAYERNORM-001",
        name: "layer_norm",
        allowed_attributes: &[
            "bias",
            "elementwise_affine",
            "epsilon",
            "normalized_shape",
            "scale",
        ],
    },
    OperatorSpec {
        opcode: OpCode::RMSNorm,
        stable_id: "OP-RMSNORM-001",
        name: "rms_norm",
        allowed_attributes: &["elementwise_affine", "epsilon", "normalized_shape", "scale"],
    },
    OperatorSpec {
        opcode: OpCode::Softmax,
        stable_id: "OP-SOFTMAX-001",
        name: "softmax",
        allowed_attributes: &["axis"],
    },
    OperatorSpec {
        opcode: OpCode::Conv2d,
        stable_id: "OP-CONV2D-001",
        name: "conv2d",
        allowed_attributes: &["dilations", "groups", "padding", "strides"],
    },
    OperatorSpec {
        opcode: OpCode::MaxPool2d,
        stable_id: "OP-MAXPOOL2D-001",
        name: "max_pool2d",
        allowed_attributes: &["ceil_mode", "kernel_size", "padding", "strides"],
    },
    OperatorSpec {
        opcode: OpCode::Embedding,
        stable_id: "OP-EMBEDDING-001",
        name: "embedding",
        allowed_attributes: &["dtype", "embedding_dim", "num_embeddings", "padding_idx"],
    },
];

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
    /// Returns the normative specification record for this operator.
    #[must_use]
    pub const fn spec(&self) -> &'static OperatorSpec {
        let idx = *self as usize;
        &OPERATOR_SPECS[idx]
    }

    /// Returns the stable, normative identifier for this operator.
    #[must_use]
    pub const fn stable_id(&self) -> &'static str {
        self.spec().stable_id
    }

    /// Returns the canonical human-readable name of this operator.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.spec().name
    }

    /// Returns the strictly admitted attribute names for this operator.
    #[must_use]
    pub const fn allowed_attributes(&self) -> &'static [&'static str] {
        self.spec().allowed_attributes
    }

    /// Resolves an `OpCode` from its stable `OP-...-001` identifier.
    ///
    /// # Errors
    /// Returns [`ModelIrError::UnknownOperator`] if the identifier is not recognized.
    pub fn from_stable_id(id: &str) -> Result<Self, ModelIrError> {
        for spec in OPERATOR_SPECS {
            if spec.stable_id == id {
                return Ok(spec.opcode);
            }
        }
        Err(ModelIrError::UnknownOperator {
            op_id: id.to_string(),
        })
    }

    /// Resolves an `OpCode` from its canonical name.
    ///
    /// # Errors
    /// Returns [`ModelIrError::UnknownOperator`] if the name is not recognized.
    pub fn from_name(name: &str) -> Result<Self, ModelIrError> {
        for spec in OPERATOR_SPECS {
            if spec.name == name {
                return Ok(spec.opcode);
            }
        }
        Err(ModelIrError::UnknownOperator {
            op_id: name.to_string(),
        })
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

/// Computes the canonical SHA-256 freeze digest over the operator table and attribute schemas.
///
/// # Errors
/// Returns [`ModelIrError::ArithmeticOverflow`] if hasher exceeds message length bounds.
pub fn compute_operator_table_digest() -> Result<ContentDigest, ModelIrError> {
    let mut buf = Vec::new();
    buf.extend_from_slice(OPERATOR_TABLE_DIGEST_DOMAIN);
    buf.extend_from_slice(&(OPERATOR_SPECS.len() as u32).to_be_bytes());
    for spec in OPERATOR_SPECS {
        buf.extend_from_slice(&(spec.stable_id.len() as u32).to_be_bytes());
        buf.extend_from_slice(spec.stable_id.as_bytes());
        buf.extend_from_slice(&(spec.name.len() as u32).to_be_bytes());
        buf.extend_from_slice(spec.name.as_bytes());
        buf.extend_from_slice(&(spec.allowed_attributes.len() as u32).to_be_bytes());
        for &attr in spec.allowed_attributes {
            buf.extend_from_slice(&(attr.len() as u32).to_be_bytes());
            buf.extend_from_slice(attr.as_bytes());
        }
    }
    let mut hasher = Sha256Hasher::new();
    hasher.update(&buf);
    let digest_bytes = hasher
        .finalize()
        .map_err(|_| ModelIrError::ArithmeticOverflow {
            operation: "operator table freeze digest calculation",
        })?;
    Ok(ContentDigest::new(DigestAlgorithm::Sha256, digest_bytes))
}

/// Verifies that the live operator table matches the pinned freeze digest.
///
/// # Errors
/// Returns [`ModelIrError::InvalidAttribute`] if the digest has diverged.
pub fn verify_operator_table_frozen() -> Result<(), ModelIrError> {
    let computed = compute_operator_table_digest()?;
    if computed.to_string() != OPERATOR_TABLE_FREEZE_DIGEST {
        return Err(ModelIrError::InvalidAttribute {
            node_id: "operator_table".to_string(),
            attr_name: "freeze_digest".to_string(),
            reason: format!(
                "operator table freeze digest diverged: expected {OPERATOR_TABLE_FREEZE_DIGEST}, got {computed}"
            ),
        });
    }
    Ok(())
}

/// Verifies that all operators match the baseline identifiers and no tombstones are resurrected.
///
/// # Errors
/// Returns [`ModelIrError::UnknownOperator`] or [`ModelIrError::InvalidAttribute`] on baseline violation.
pub fn verify_operator_baseline() -> Result<(), ModelIrError> {
    if OPERATOR_SPECS.len() != OPERATOR_BASELINE_IDS.len() {
        return Err(ModelIrError::InvalidAttribute {
            node_id: "operator_table".to_string(),
            attr_name: "baseline_count".to_string(),
            reason: format!(
                "operator count {} != baseline count {}",
                OPERATOR_SPECS.len(),
                OPERATOR_BASELINE_IDS.len()
            ),
        });
    }

    for (spec, &expected_id) in OPERATOR_SPECS.iter().zip(OPERATOR_BASELINE_IDS.iter()) {
        if spec.stable_id != expected_id {
            return Err(ModelIrError::InvalidAttribute {
                node_id: "operator_table".to_string(),
                attr_name: "stable_id".to_string(),
                reason: format!(
                    "operator id mismatch: expected {expected_id}, found {}",
                    spec.stable_id
                ),
            });
        }
        for &tombstone in OPERATOR_TOMBSTONES {
            if spec.stable_id == tombstone {
                return Err(ModelIrError::InvalidAttribute {
                    node_id: "operator_table".to_string(),
                    attr_name: "tombstone".to_string(),
                    reason: format!("tombstoned operator id {} resurrected", spec.stable_id),
                });
            }
        }
    }
    Ok(())
}
